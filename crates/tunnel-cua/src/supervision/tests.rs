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
    // **And it still declares the residue.** "Nothing was held" is a fact
    // about this device's registries; it is not a witness to the desktop. See
    // `a_restart_that_freed_nothing_still_declares_what_it_cannot_see`.
    assert_eq!(invalidation.residue(), RESTART_RESIDUE);
}

// -------------------------------------------- what a restart cannot see (C09)

/// The whole map, both directions, with the partition pinned by absolute
/// count rather than by anything derived from the map under test.
///
/// An emptied `Operation::ALL` would make a "for every operation" loop
/// vacuously true; the three `assert_eq!`s on literal counts are what stop
/// that, and the first of them is the positive control for the other two.
#[test]
fn every_operation_declares_what_an_interruption_of_it_can_leave_unobserved() {
    assert_eq!(
        Operation::ALL.len(),
        12,
        "the operation table this partition is measured over"
    );

    let mut declares_something = Vec::new();
    let mut declares_nothing = Vec::new();
    for operation in Operation::ALL {
        if interruption_residue(operation).is_empty() {
            declares_nothing.push(operation);
        } else {
            declares_something.push(operation);
        }
    }

    assert_eq!(
        declares_nothing,
        vec![
            Operation::Describe,
            Operation::Capture,
            Operation::ScreenInfo,
            Operation::CursorPosition,
            Operation::Move,
        ],
        "the four reads synthesise no input at all, and `move`'s entire \
         effect is a pointer position `cursor_position` reports"
    );
    assert_eq!(declares_nothing.len(), 5);
    assert_eq!(
        declares_something,
        vec![
            Operation::Click,
            Operation::DoubleClick,
            Operation::Drag,
            Operation::Scroll,
            Operation::TypeText,
            Operation::PressKey,
            Operation::Hotkey,
        ]
    );
    assert_eq!(declares_something.len(), 7);

    // A read that manufactured a residue would make the declaration
    // meaningless, so this direction is asserted as hard as the other.
    for operation in Operation::READ_ONLY {
        assert_eq!(
            interruption_residue(operation),
            DesktopResidue::NONE,
            "{} synthesises no input",
            operation.name()
        );
    }
}

/// The kinds are not interchangeable, and collapsing any two would lose the
/// distinction a consumer acts on.
#[test]
fn a_held_button_and_a_held_key_are_different_declarations() {
    let button = interruption_residue(Operation::Click);
    assert!(button.pointer_button_may_be_down());
    assert!(!button.key_may_be_held());
    assert!(!button.effect_may_be_partial());

    let key = interruption_residue(Operation::PressKey);
    assert!(key.key_may_be_held());
    assert!(!key.pointer_button_may_be_down());
    assert_eq!(interruption_residue(Operation::Hotkey), key);

    assert_ne!(button, key);

    // A drag is the only operation carrying both kinds: it presses, travels
    // and releases, so it can end with the button down *and* half done.
    let drag = interruption_residue(Operation::Drag);
    assert!(drag.pointer_button_may_be_down());
    assert!(drag.effect_may_be_partial());
    assert!(!drag.key_may_be_held());

    // Partial delivery without anything left asserted.
    for operation in [Operation::Scroll, Operation::TypeText] {
        let residue = interruption_residue(operation);
        assert_eq!(residue, DesktopResidue::PARTIAL_EFFECT);
        assert!(!residue.pointer_button_may_be_down());
        assert!(!residue.key_may_be_held());
    }
}

/// The restart declaration is the fold over the input operations, and carries
/// every kind any of them can leave.
#[test]
fn a_restart_declares_every_kind_an_input_operation_can_leave() {
    let folded = Operation::INPUT
        .into_iter()
        .map(interruption_residue)
        .fold(DesktopResidue::NONE, DesktopResidue::union);
    assert_eq!(RESTART_RESIDUE, folded);
    assert_eq!(Operation::INPUT.len(), 8, "the set the fold ran over");

    assert!(RESTART_RESIDUE.pointer_button_may_be_down());
    assert!(RESTART_RESIDUE.key_may_be_held());
    assert!(RESTART_RESIDUE.effect_may_be_partial());
    assert!(!RESTART_RESIDUE.is_empty());
}

/// **The positive control for every assertion above.**
///
/// `DesktopResidue` can express "nothing", and five of the twelve operations
/// and an un-restarted `Invalidation` do express it — so a restart declaring
/// all three kinds is a decision this code made, not a constant of the type
/// that could not have come out otherwise.
#[test]
fn the_residue_type_can_express_nothing_which_is_what_makes_the_rest_a_choice() {
    assert!(DesktopResidue::NONE.is_empty());
    assert!(DesktopResidue::default().is_empty());
    assert_eq!(DesktopResidue::default(), DesktopResidue::NONE);
    assert!(interruption_residue(Operation::Move).is_empty());
    assert!(interruption_residue(Operation::Capture).is_empty());

    // A `Default` invalidation is "no restart happened", not "a restart
    // happened and the desktop is clean". Nothing produces the second.
    assert!(Invalidation::default().residue().is_empty());

    assert!(
        !DesktopResidue::NONE
            .union(DesktopResidue::KEY_HELD)
            .is_empty()
    );
    assert_eq!(
        DesktopResidue::NONE.union(DesktopResidue::NONE),
        DesktopResidue::NONE
    );
}

/// A restart that freed nothing declares exactly as much as one that freed
/// everything.
///
/// The device's registries are not a witness to the desktop: a lease released
/// just before the kill empties them and says nothing about what the backend
/// was part-way through, and the agent who inherits a held button holds no
/// lease at the moment of the restart at all.
#[test]
fn a_restart_that_freed_nothing_still_declares_what_it_cannot_see() {
    let mut idle_leases = InputLeases::new();
    let mut idle_captures = Captures::new();
    let idle = invalidate(
        &mut idle_leases,
        &mut idle_captures,
        BackendGeneration::INITIAL.next(),
    );

    let mut busy_leases = InputLeases::new();
    let mut busy_captures = Captures::new();
    let target = target("desktop-0");
    busy_leases
        .acquire(&target, SessionId::new(1), GrantRevision::new(0))
        .expect("the target is free");
    busy_captures
        .record(&target, 0, 128, 96, 100)
        .expect("geometry");
    let busy = invalidate(
        &mut busy_leases,
        &mut busy_captures,
        BackendGeneration::INITIAL.next(),
    );

    // The positive control: these two invalidations really are different, so
    // the equality below is not two copies of the same empty answer.
    assert!(!idle.freed_anything());
    assert!(busy.freed_anything());
    assert_eq!(busy.leases_released, vec![target]);
    assert_eq!(busy.captures_forgotten, 1);

    assert_eq!(idle.residue(), busy.residue());
    assert_eq!(idle.residue(), RESTART_RESIDUE);
}

#[test]
fn an_invalidation_is_stamped_with_the_generation_that_died() {
    // **The assertion whose absence let a wrong doc line survive review.**
    // `invalidate` stamps what it is handed and advances nothing, and a
    // supervisor hands it the generation it is leaving, because it stops
    // before it starts. So the number here is the backend that just died --
    // which is also the one the dropped leases and captures were minted
    // against.
    let mut leases = InputLeases::new();
    let mut captures = Captures::new();
    let dying = BackendGeneration::INITIAL.next();
    let invalidation = invalidate(&mut leases, &mut captures, dying);
    assert_eq!(invalidation.generation, dying);
    assert_eq!(
        invalidation.generation.value(),
        1,
        "the generation that died, not the 2 the device goes on to"
    );
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

// ------------------------------------------------------- restart attribution

/// Every `UnknownReason` the transport layer can conclude on its own, so the
/// attribution cases below are a cross-product rather than one representative.
const TRANSPORT_UNKNOWNS: [UnknownReason; 8] = [
    UnknownReason::Truncated,
    UnknownReason::FramingAbsent,
    UnknownReason::Unparseable,
    UnknownReason::SuccessAbsent,
    UnknownReason::TransportLost,
    UnknownReason::BackendRestarted,
    UnknownReason::DeadlineExpired,
    UnknownReason::UnexpectedStatus { status: 500 },
];

/// Answers that must survive attribution untouched, each with why.
fn answers_attribution_must_not_rewrite() -> Vec<Dispatch> {
    use crate::lease::LeaseRefusal;
    use crate::outcome::{FailureCode, InputRefusal};
    vec![
        // A backend answered definitively on a connection that lived long
        // enough to deliver it.
        Dispatch::Dispatched(Completion::Ok(serde_json::json!({}))),
        Dispatch::Dispatched(Completion::Failed {
            code: FailureCode::BackendReported,
        }),
        Dispatch::Dispatched(Completion::Failed {
            code: FailureCode::PermissionDenied,
        }),
        // Each of these names a more specific cause than "a restart happened".
        Dispatch::NotDispatched(NotDispatched::BackendRejected { status: 400 }),
        Dispatch::NotDispatched(NotDispatched::BackendUnavailable),
        Dispatch::NotDispatched(NotDispatched::NotPermitted),
        Dispatch::NotDispatched(NotDispatched::EndpointRefused),
        Dispatch::NotDispatched(NotDispatched::PeerUnavailable),
        Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Lease(
            LeaseRefusal::NotHeld,
        ))),
    ]
}

#[test]
fn an_undisturbed_exchange_keeps_the_transports_own_answer() {
    // **The control that makes every other case in this file mean something.**
    // If attribution rewrote an untouched exchange, the tests below could not
    // tell "the epoch changed" from "attribution always rewrites".
    let epoch = LifecycleEpoch::new(7);
    for reason in TRANSPORT_UNKNOWNS {
        let transport = Dispatch::Dispatched(Completion::Unknown(reason));
        assert_eq!(
            attribute_restart(epoch, epoch, transport.clone()),
            transport,
            "an equal epoch must change nothing, including for {reason:?}"
        );
    }
    for answer in answers_attribution_must_not_rewrite() {
        assert_eq!(
            attribute_restart(epoch, epoch, answer.clone()),
            answer,
            "an equal epoch must change nothing, including for {answer:?}"
        );
    }
}

#[test]
fn a_disturbed_exchange_that_reached_the_backend_is_named_a_restart() {
    // The row M5-C10 exists for: the named reason, not merely the arm.
    let before = LifecycleEpoch::INITIAL;
    let after = before.next();
    for reason in TRANSPORT_UNKNOWNS {
        let attributed = attribute_restart(
            before,
            after,
            Dispatch::Dispatched(Completion::Unknown(reason)),
        );
        assert_eq!(
            attributed,
            Dispatch::Dispatched(Completion::Unknown(UnknownReason::BackendRestarted)),
            "an unknown outcome across a supervisor disturbance is a restart, \
             whatever the transport called it; {reason:?} was not re-attributed"
        );
    }
}

#[test]
fn a_disturbed_exchange_that_never_reached_the_backend_stays_retryable() {
    // The other half of the stage mapping. A request that was never written
    // is retryable whether or not the supervisor restarted anything, and
    // `restart_outcome` is what says so -- this is not a pass-through.
    let before = LifecycleEpoch::INITIAL;
    let after = before.next();
    let attributed = attribute_restart(
        before,
        after,
        Dispatch::NotDispatched(NotDispatched::NotReached),
    );
    assert_eq!(
        attributed,
        Dispatch::NotDispatched(NotDispatched::NotReached)
    );
    assert!(attributed.retry_is_safe_for(Operation::Click));
}

#[test]
fn a_disturbed_exchange_keeps_every_definitive_answer_it_was_given() {
    // Attribution must not destroy information. An `Ok` rewritten to
    // `Unknown` because something restarted afterwards would be strictly
    // worse than not attributing at all.
    let before = LifecycleEpoch::INITIAL;
    let after = before.next();
    for answer in answers_attribution_must_not_rewrite() {
        assert_eq!(
            attribute_restart(before, after, answer.clone()),
            answer,
            "a definitive answer must survive a restart that happened around \
             it: {answer:?}"
        );
    }
}

#[test]
fn attribution_never_changes_what_a_retry_is_allowed_to_do() {
    // **The rule M5-C10's acceptance names: attribution must not widen
    // retryability.** Measured over every `UnknownReason`, plus representative
    // answers from the arms attribution must leave alone, crossed with every
    // operation in both epoch relations -- rather than argued from the shape
    // of the match.
    //
    // **Not an exhaustive enumeration of `Dispatch`, and does not claim to
    // be.** The schema, operation, lease and capture refusals,
    // `AnsweredLocally`, and `Failed { Unsupported }` are absent; every one of
    // them reaches `_ => transport` and is returned untouched, so none can
    // affect retryability. What the 432 pins is that the set actually measured
    // did not shrink.
    let before = LifecycleEpoch::INITIAL;
    let mut inputs: Vec<Dispatch> = TRANSPORT_UNKNOWNS
        .into_iter()
        .map(|reason| Dispatch::Dispatched(Completion::Unknown(reason)))
        .collect();
    inputs.push(Dispatch::NotDispatched(NotDispatched::NotReached));
    inputs.extend(answers_attribution_must_not_rewrite());

    let mut checked = 0usize;
    for after in [before, before.next()] {
        for transport in &inputs {
            let attributed = attribute_restart(before, after, transport.clone());
            assert_eq!(
                attributed.retry_is_safe(),
                transport.retry_is_safe(),
                "attribution changed blanket retryability of {transport:?}"
            );
            for operation in Operation::ALL {
                assert_eq!(
                    attributed.retry_is_safe_for(operation),
                    transport.retry_is_safe_for(operation),
                    "attribution changed retryability of {transport:?} for \
                     {operation:?}"
                );
                checked += 1;
            }
        }
    }
    // **A literal, because the obvious form of this assertion cannot fail.**
    // This first read `assert_eq!(checked, 2 * inputs.len() * Operation::ALL
    // .len())`, which is exactly the thing it was written to prevent: empty
    // `inputs` and both sides go to zero together, so the check agrees with
    // itself over a loop that never ran. 432 is 18 transport answers x 12
    // operations x 2 epoch relations, and it is written out so that dropping
    // an input, an operation or the undisturbed arm fails here rather than
    // quietly shrinking the cross-product.
    assert_eq!(
        checked,
        432,
        "the cross-product did not run in full: {} inputs x {} operations x 2",
        inputs.len(),
        Operation::ALL.len()
    );
}
