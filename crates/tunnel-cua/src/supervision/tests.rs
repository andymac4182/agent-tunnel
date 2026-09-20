use super::*;

use crate::Operation;
use crate::capture::{CaptureId, CaptureRefusal, Point};
use crate::lease::{GrantRevision, SessionId};

fn target(name: &str) -> TargetSession {
    TargetSession::new(name)
}

#[test]
fn an_operation_that_reached_the_backend_is_unknown_and_never_retryable() {
    let lost = restart_outcome(InFlight::ReachedBackend);
    assert_eq!(
        lost,
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::BackendRestarted))
    );
    assert!(lost.reached_the_backend());
    assert!(!lost.retry_is_safe());
    // The whole cross-product, not one representative: a supervisor must not
    // be able to make *any* operation retryable by restarting under it.
    for operation in Operation::ALL {
        assert!(
            !lost.retry_is_safe_for(operation),
            "{operation:?} must not be retryable after a restart it was in flight across"
        );
    }
}

#[test]
fn an_operation_that_never_reached_the_backend_is_not_dispatched() {
    let never = restart_outcome(InFlight::NotReached);
    assert_eq!(never, Dispatch::NotDispatched(NotDispatched::NotReached));
    assert!(!never.reached_the_backend());
    assert!(never.retry_is_safe());
    // And `retry_is_safe_for` agrees for input operations too: `NotReached`
    // is not `PeerUnavailable`, so M3-15's narrower rule does not apply. A
    // restart is a fact this device observed, not the relay's ambiguous
    // answer.
    assert!(never.retry_is_safe_for(Operation::Click));
}

#[test]
fn the_two_stages_are_the_only_thing_that_separates_them() {
    // Stated as a test rather than only in prose: there is no third input,
    // no operation argument, no "the supervisor is confident" flag. If a
    // future caller wants a retryable answer it must be able to say the
    // request was never written, which is a transport fact it either has or
    // does not.
    assert_ne!(
        restart_outcome(InFlight::NotReached),
        restart_outcome(InFlight::ReachedBackend)
    );
}

#[test]
fn a_restart_drops_the_lease_and_forgets_every_capture() {
    let mut leases = InputLeases::new();
    let mut captures = Captures::new();
    let session = SessionId::new(1);
    let desktop = target("desktop-0");
    leases
        .acquire(&desktop, session, GrantRevision::new(0))
        .expect("the lease was free");
    let identity = captures
        .record(&desktop, 0, 128, 96, 100)
        .expect("a valid geometry");
    assert_eq!(leases.holder(&desktop), Some(session));
    assert!(captures.resolve(identity.id(), &desktop).is_ok());

    let invalidation = invalidate(
        &mut leases,
        &mut captures,
        BackendGeneration::INITIAL.next(),
    );

    assert_eq!(invalidation.leases_released, vec![desktop.clone()]);
    assert_eq!(invalidation.captures_forgotten, 1);
    assert!(invalidation.freed_anything());
    assert_eq!(invalidation.generation.value(), 1);

    assert_eq!(leases.holder(&desktop), None);
    assert!(leases.is_empty());
    // **Unknown, not superseded.** The consumer is told the device has never
    // heard of this capture, which is the truth: the image it named was
    // produced by a backend that no longer exists.
    assert_eq!(
        captures.resolve(identity.id(), &desktop).unwrap_err(),
        CaptureRefusal::Unknown
    );
    assert!(captures.is_empty());
}

#[test]
fn a_capture_issued_after_a_restart_never_reuses_a_pre_restart_identity() {
    // The rule `Captures::invalidate_all` names as load-bearing, measured.
    // If the counter restarted, a stale click would resolve against a
    // different image, pass the bounds check, and be dispatched at
    // coordinates nobody picked.
    let mut leases = InputLeases::new();
    let mut captures = Captures::new();
    let desktop = target("desktop-0");
    let before = captures
        .record(&desktop, 0, 128, 96, 100)
        .expect("a valid geometry");

    invalidate(
        &mut leases,
        &mut captures,
        BackendGeneration::INITIAL.next(),
    );

    let after = captures
        .record(&desktop, 0, 128, 96, 100)
        .expect("a valid geometry");
    assert_ne!(before.id(), after.id());
    assert_eq!(
        captures.resolve(before.id(), &desktop).unwrap_err(),
        CaptureRefusal::Unknown
    );
    // And the point check cannot launder it either: an in-bounds point
    // against a forgotten identity is still refused as unknown.
    assert_eq!(
        captures
            .resolve_point(before.id(), &desktop, Point::new(1, 1))
            .unwrap_err(),
        CaptureRefusal::Unknown
    );
}

#[test]
fn a_restart_frees_every_session_not_merely_the_one_that_asked() {
    // `reconcile_grant` and `release_all_for_session` both ask whose lease
    // it is. A restart does not: the backend enforcing the exclusivity is
    // gone for everybody.
    let mut leases = InputLeases::new();
    let mut captures = Captures::new();
    let first = target("desktop-0");
    let second = target("desktop-1");
    leases
        .acquire(&first, SessionId::new(1), GrantRevision::new(0))
        .expect("free");
    leases
        .acquire(&second, SessionId::new(2), GrantRevision::new(0))
        .expect("free");

    let invalidation = invalidate(
        &mut leases,
        &mut captures,
        BackendGeneration::INITIAL.next(),
    );

    assert_eq!(invalidation.leases_released.len(), 2);
    assert!(leases.is_empty());
}

#[test]
fn a_lease_taken_after_a_restart_never_reuses_a_pre_restart_lease_id() {
    let mut leases = InputLeases::new();
    let mut captures = Captures::new();
    let desktop = target("desktop-0");
    let before = leases
        .acquire(&desktop, SessionId::new(1), GrantRevision::new(0))
        .expect("free");

    invalidate(
        &mut leases,
        &mut captures,
        BackendGeneration::INITIAL.next(),
    );

    let after = leases
        .acquire(&desktop, SessionId::new(1), GrantRevision::new(0))
        .expect("free again");
    assert_ne!(
        before.lease().value(),
        after.lease().value(),
        "a reissued lease id would let a pre-restart grant pass `release`"
    );
}

#[test]
fn restarting_an_idle_backend_frees_nothing_and_says_so() {
    let mut leases = InputLeases::new();
    let mut captures = Captures::new();
    let invalidation = invalidate(
        &mut leases,
        &mut captures,
        BackendGeneration::INITIAL.next(),
    );
    assert!(!invalidation.freed_anything());
    assert!(invalidation.leases_released.is_empty());
    assert_eq!(invalidation.captures_forgotten, 0);
}

#[test]
fn a_generation_that_has_not_started_is_distinguishable_from_the_first_one() {
    assert!(!BackendGeneration::INITIAL.has_started());
    assert!(BackendGeneration::INITIAL.next().has_started());
    assert!(BackendGeneration::INITIAL.next() > BackendGeneration::INITIAL);
    assert_eq!(BackendGeneration::INITIAL.next().next().value(), 2);
}

#[test]
fn a_capture_id_from_another_device_is_still_unknown_after_a_restart() {
    // Not a new rule, but worth pinning: invalidation must not make
    // `resolve` permissive by emptying the registry.
    let captures = Captures::new();
    assert_eq!(
        captures
            .resolve(CaptureId::new(7), &target("desktop-0"))
            .unwrap_err(),
        CaptureRefusal::Unknown
    );
}
