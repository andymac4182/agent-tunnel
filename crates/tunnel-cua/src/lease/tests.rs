use super::*;

fn target() -> TargetSession {
    TargetSession::new("console:1")
}

const A: SessionId = SessionId::new(1);
const B: SessionId = SessionId::new(2);
const R0: GrantRevision = GrantRevision::new(0);
const R1: GrantRevision = GrantRevision::new(1);

/// **The refusal, with a holder that genuinely holds.**
///
/// The trap the scoping document names is *a lease refusal where no lease was
/// ever held*. So the first leg is not the refusal: it is `check` succeeding
/// for A, which is the same call every input operation makes. Only then is B
/// refused, and the third leg shows B is refused *by the lease* rather than by
/// being unable to hold one at all.
#[test]
fn a_second_session_is_refused_only_while_the_first_genuinely_holds_the_lease() {
    let mut leases = InputLeases::new();
    let target = target();

    // Leg 1: nobody holds it, and an operation is refused for that reason.
    assert_eq!(leases.check(&target, A, R0), Err(LeaseRefusal::NotHeld));

    // Leg 2: A takes it, and A's operations pass the very check B will fail.
    let grant = leases.acquire(&target, A, R0).expect("the target is free");
    assert_eq!(leases.check(&target, A, R0), Ok(grant.lease()));
    assert_eq!(leases.holder(&target), Some(A));

    // Leg 3: B is refused, both at acquisition and at use.
    assert_eq!(
        leases.acquire(&target, B, R0).map(|_| ()),
        Err(LeaseRefusal::HeldByAnotherSession)
    );
    assert_eq!(
        leases.check(&target, B, R0),
        Err(LeaseRefusal::HeldByAnotherSession)
    );
    // And A still holds it: a refused acquisition changed nothing.
    assert_eq!(leases.holder(&target), Some(A));

    // Leg 4 -- the non-vacuity control. B is refused *by the lease*, not by
    // being B. Once A releases, B takes it and passes the same check.
    leases.release(&grant).expect("A holds it");
    assert_eq!(leases.holder(&target), None);
    let b_grant = leases.acquire(&target, B, R0).expect("the target is free");
    assert_eq!(leases.check(&target, B, R0), Ok(b_grant.lease()));
    assert_ne!(
        b_grant.lease(),
        grant.lease(),
        "a new holding gets a new identifier"
    );
}

/// Two targets are independent: the lease is per target OS session, not one
/// global mutex over the device.
#[test]
fn leases_on_different_targets_do_not_interfere() {
    let mut leases = InputLeases::new();
    let first = TargetSession::new("console:1");
    let second = TargetSession::new("console:2");

    leases.acquire(&first, A, R0).unwrap();
    leases.acquire(&second, B, R0).unwrap();
    assert_eq!(leases.holder(&first), Some(A));
    assert_eq!(leases.holder(&second), Some(B));
    assert_eq!(leases.len(), 2);
}

/// Re-acquiring is idempotent, so a session that asks twice does not deadlock
/// itself or mint a second holding that the first release would orphan.
#[test]
fn reacquiring_returns_the_same_holding_and_a_single_release_ends_it() {
    let mut leases = InputLeases::new();
    let target = target();

    let first = leases.acquire(&target, A, R0).unwrap();
    let again = leases.acquire(&target, A, R0).unwrap();
    assert_eq!(first.lease(), again.lease());
    assert_eq!(again.grant_revision(), R0);
    assert_eq!(leases.len(), 1);

    leases.release(&first).unwrap();
    assert!(leases.is_empty());
    // And the second grant is now stale, so releasing it again is refused
    // rather than dropping whatever came next.
    assert_eq!(leases.release(&again), Err(LeaseRefusal::NotHeld));
}

/// Releasing somebody else's lease, or a superseded holding of your own, is
/// refused. Both would otherwise be a way to take input away from an agent
/// mid-gesture.
#[test]
fn a_release_must_name_the_holding_it_owns() {
    let mut leases = InputLeases::new();
    let target = target();

    let a_grant = leases.acquire(&target, A, R0).unwrap();
    // B forges a grant for A's target. The type does not prevent building one;
    // the registry refuses it.
    let forged = LeaseGrant {
        target: target.clone(),
        session: B,
        lease: a_grant.lease(),
        grant_revision: R0,
    };
    assert_eq!(
        leases.release(&forged),
        Err(LeaseRefusal::HeldByAnotherSession)
    );

    // A releases, B takes it, and A's old grant names a holding that is gone.
    leases.release(&a_grant).unwrap();
    leases.acquire(&target, B, R0).unwrap();
    assert_eq!(
        leases.release(&a_grant),
        Err(LeaseRefusal::HeldByAnotherSession)
    );
    assert_eq!(leases.holder(&target), Some(B), "B still has it");
}

/// **Releasing a superseded holding of your own is refused too**, and the
/// session check cannot catch this one.
///
/// A takes the lease, releases it, and takes it again. The first grant now
/// names a holding that has been replaced. The holder is still A, so the
/// session comparison passes — the only thing standing between this and A
/// silently dropping its own *current* lease is the lease-identifier check.
///
/// This leg exists because the guard harness found the rule green without it:
/// every other release test was decided by the session comparison first, so
/// deleting the identifier check changed nothing that was measured. A rule
/// nothing can break is not a guard, and this is the case that breaks it.
#[test]
fn releasing_a_superseded_holding_of_your_own_does_not_drop_the_current_one() {
    let mut leases = InputLeases::new();
    let target = target();

    let first = leases.acquire(&target, A, R0).unwrap();
    leases.release(&first).unwrap();
    let second = leases.acquire(&target, A, R0).unwrap();
    assert_ne!(first.lease(), second.lease());

    assert_eq!(
        leases.release(&first),
        Err(LeaseRefusal::NotTheHolder),
        "the first holding is gone; releasing it must not touch the second"
    );
    assert_eq!(
        leases.holder(&target),
        Some(A),
        "A's current lease survived the stale release"
    );
    assert_eq!(leases.check(&target, A, R0), Ok(second.lease()));
    // Non-vacuity: the current grant does release it.
    leases.release(&second).unwrap();
    assert!(leases.is_empty());
}

/// **M3-16, part one: a revoked holder cannot use the lease.**
///
/// `check` is given the revision the device believes the grant carries. When
/// that has moved past the one the lease was taken under, the operation is
/// refused. Nothing is dispatched.
#[test]
fn a_superseded_grant_revision_refuses_the_holder_at_the_point_of_use() {
    let mut leases = InputLeases::new();
    let target = target();

    let grant = leases.acquire(&target, A, R0).unwrap();
    assert_eq!(leases.check(&target, A, R0), Ok(grant.lease()));
    assert_eq!(
        leases.check(&target, A, R1),
        Err(LeaseRefusal::GrantRevoked)
    );
    // A revision *behind* the recorded one is not a revocation -- it is a
    // stale reading, and refusing on it would be the wrong direction.
    assert_eq!(leases.check(&target, A, R0), Ok(grant.lease()));

    // **This leg used to assert the defect.** It re-acquired at R1, took the
    // `Ok`, and concluded that the refusal above was recoverable -- which is
    // precisely the laundering `acquire` now refuses. See
    // `a_revoked_holder_cannot_re_acquire_its_own_lease_to_clear_the_refusal`.
    assert_eq!(
        leases.acquire(&target, A, R1).map(|_| ()),
        Err(LeaseRefusal::GrantRevoked)
    );
    assert_eq!(
        leases.check(&target, A, R1),
        Err(LeaseRefusal::GrantRevoked),
        "and the refusal still stands afterwards"
    );
}

/// **M3-16, part two: refusing the holder does not free the target.**
///
/// This is the half that is *not* closed, asserted so that the row and the
/// code say the same thing. `check` refusing leaves the entry in place, so a
/// second agent is still blocked; only `reconcile_grant` frees it, and nothing
/// in this repository calls that.
#[test]
fn a_revoked_lease_still_blocks_another_session_until_it_is_reconciled() {
    let mut leases = InputLeases::new();
    let target = target();

    leases.acquire(&target, A, R0).unwrap();
    assert_eq!(
        leases.check(&target, A, R1),
        Err(LeaseRefusal::GrantRevoked),
        "A is refused"
    );
    assert_eq!(
        leases.acquire(&target, B, R1).map(|_| ()),
        Err(LeaseRefusal::HeldByAnotherSession),
        "and B is still blocked by a lease nobody may use"
    );

    let freed = leases.reconcile_grant(A, R1);
    assert_eq!(freed, vec![target.clone()]);
    assert_eq!(leases.holder(&target), None);
    // Now B can take it, which is what makes the reconcile the mechanism
    // rather than a bookkeeping call.
    let b_grant = leases.acquire(&target, B, R1).unwrap();
    assert_eq!(leases.check(&target, B, R1), Ok(b_grant.lease()));
}

/// Reconciling a revision that has not moved frees nothing. Without this the
/// test above would pass for a `reconcile_grant` that simply dropped every
/// lease it was handed.
#[test]
fn reconciling_an_unchanged_revision_frees_nothing() {
    let mut leases = InputLeases::new();
    let target = target();
    leases.acquire(&target, A, R1).unwrap();

    assert!(leases.reconcile_grant(A, R1).is_empty());
    assert!(
        leases.reconcile_grant(B, GrantRevision::new(9)).is_empty(),
        "another session's revision says nothing about A's lease"
    );
    assert_eq!(leases.holder(&target), Some(A));
}

/// A session ending drops what it held, and nothing else.
#[test]
fn releasing_a_session_drops_only_its_own_leases() {
    let mut leases = InputLeases::new();
    let first = TargetSession::new("console:1");
    let second = TargetSession::new("console:2");
    leases.acquire(&first, A, R0).unwrap();
    leases.acquire(&second, B, R0).unwrap();

    assert_eq!(leases.release_all_for_session(A), vec![first.clone()]);
    assert_eq!(leases.holder(&first), None);
    assert_eq!(leases.holder(&second), Some(B));
}

/// **The hole review found, and the rule that closes it.**
///
/// `acquire` used to write the supplied revision into an existing holding. So
/// a holder that `check` had just refused with `GrantRevoked` could simply
/// acquire again at the advanced revision, have it recorded, and pass `check`
/// — and `reconcile_grant` at that revision would then free nothing, because
/// the recorded revision was no longer behind. **One call defeated both halves
/// of the M3-16 story**, and re-acquiring is the obvious client response to a
/// refusal. The old tests stopped before the re-acquire, so nothing measured
/// it; this is that measurement.
#[test]
fn a_revoked_holder_cannot_re_acquire_its_own_lease_to_clear_the_refusal() {
    let mut leases = InputLeases::new();
    let target = target();

    let grant = leases.acquire(&target, A, R0).unwrap();
    assert_eq!(grant.grant_revision(), R0, "the holding records R0");
    assert_eq!(
        leases.check(&target, A, R1),
        Err(LeaseRefusal::GrantRevoked),
        "the holder is refused at the point of use"
    );

    // The move that used to launder the revocation.
    assert_eq!(
        leases.acquire(&target, A, R1).map(|_| ()),
        Err(LeaseRefusal::GrantRevoked),
        "re-acquiring must not raise the recorded revision"
    );

    // Both halves still hold afterwards: the holder is still refused, and the
    // reconcile still has something to free.
    assert_eq!(
        leases.check(&target, A, R1),
        Err(LeaseRefusal::GrantRevoked)
    );
    assert_eq!(leases.reconcile_grant(A, R1), vec![target.clone()]);
    assert_eq!(leases.holder(&target), None);

    // **The control that keeps this from being a lockout.** A legitimately
    // re-granted consumer releases and acquires afresh, which mints a new
    // holding at the new revision and passes `check`.
    let mut leases = InputLeases::new();
    let grant = leases.acquire(&target, A, R0).unwrap();
    assert_eq!(grant.grant_revision(), R0);
    leases.release(&grant).unwrap();
    let regranted = leases.acquire(&target, A, R1).unwrap();
    assert_eq!(regranted.grant_revision(), R1);
    assert_eq!(leases.check(&target, A, R1), Ok(regranted.lease()));
    assert_ne!(regranted.lease(), grant.lease(), "a fresh holding");
}

/// A revision at or below the recorded one is a **stale reading**, not a
/// revocation: accepted, and it changes nothing. Without this leg the rule
/// above would be indistinguishable from "re-acquiring is always refused".
#[test]
fn re_acquiring_at_a_stale_revision_is_accepted_and_changes_nothing() {
    let mut leases = InputLeases::new();
    let target = target();

    let first = leases.acquire(&target, A, R1).unwrap();
    let again = leases
        .acquire(&target, A, R0)
        .expect("a stale reading is not a revocation");
    assert_eq!(again.lease(), first.lease());
    assert_eq!(
        again.grant_revision(),
        R1,
        "the recorded revision is the holding's, not the caller's"
    );
    // And the recorded revision really did not drop: reconciling at R1 frees
    // nothing, which it would not if the holding had been lowered to R0.
    assert!(leases.reconcile_grant(A, R1).is_empty());
    assert_eq!(leases.check(&target, A, R1), Ok(first.lease()));
}
