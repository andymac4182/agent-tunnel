//! Deterministic regressions for the owner's bounded admission hold across a
//! data-rotation freeze (task row M3-15; owner decision 2026-09-25).
//!
//! Each scenario drives the real actor handlers through [`FreezeFixture`]:
//! a new OPEN that lands between QUIESCE and COMMITTED is held, never
//! refused as a fault, and leaves the hold exactly once with an explicit
//! outcome. The hold deadline is passed as an explicit instant, so nothing
//! here waits on the wall clock.
//!
//! **Witnesses.** Before the hold existed the relay answered every one of
//! these OPENs synchronously with `RelayError::OwnerNotReady`, so each test
//! below that asserts "held" (an empty receiver) is red on that code, and the
//! bound, cap, cancellation, abort, recovery, session-loss and shutdown tests
//! additionally assert counters that did not exist.

use std::time::{Duration as StdDuration, Instant};

use tokio::sync::oneshot;
use tunnel_protocol::rotation::RotationPhase;

use super::super::freeze_hold::{self, MAX_HELD_PER_DEVICE, MAX_HOLD};
use super::{FreezeFixture, STREAM_ID};
use crate::actor::{ConsumerStreamRegistration, RelayError};
use crate::runtime::RotationFreezeHoldSnapshot;

type Admission = oneshot::Receiver<Result<ConsumerStreamRegistration, RelayError>>;

impl FreezeFixture {
    /// One new consumer stream OPEN through the real admission path.
    fn open(&mut self) -> Admission {
        let (response, receiver) = oneshot::channel();
        self.actor.open_echo_stream(
            self.consumer.clone(),
            self.device_id,
            self.service_id,
            self.grant.clone(),
            self.consumer_expires_at,
            response,
        );
        receiver
    }

    fn hold(&self) -> RotationFreezeHoldSnapshot {
        self.actor.freeze_hold.snapshot()
    }

    /// OPENs the relay queued since the last call, counting those drained by
    /// the phase helpers.
    fn opens_sent(&mut self) -> usize {
        let _ = self.drain_control();
        std::mem::take(&mut self.opens_drained)
    }

    /// QUIESCE through COMMITTED, asserting that nothing held was dispatched
    /// before COMMITTED.
    async fn commit_rotation(&mut self) {
        assert!(self.complete_barrier().is_empty());
        self.connector_frozen(0).await;
        self.connector_drained().await;
        assert_eq!(self.phase(), RotationPhase::Committing);
        self.connector_committed().await;
    }
}

fn assert_waiting(receiver: &mut Admission, label: &str) {
    match receiver.try_recv() {
        Err(oneshot::error::TryRecvError::Empty) => {}
        Ok(Ok(registration)) => panic!(
            "{label}: an OPEN during a freeze must be held, but stream {} was admitted",
            registration.stream_id
        ),
        Ok(Err(error)) => panic!("{label}: an OPEN during a freeze must be held, got {error}"),
        Err(oneshot::error::TryRecvError::Closed) => {
            panic!("{label}: the held OPEN was dropped without an answer")
        }
    }
}

fn admitted(receiver: &mut Admission, label: &str) -> u64 {
    match receiver.try_recv() {
        Ok(Ok(registration)) => registration.stream_id,
        Ok(Err(error)) => panic!("{label}: expected admission, got {error}"),
        Err(error) => panic!("{label}: expected an answer, got {error:?}"),
    }
}

fn refused(receiver: &mut Admission, label: &str) -> RelayError {
    match receiver.try_recv() {
        Ok(Err(error)) => error,
        Ok(Ok(registration)) => panic!(
            "{label}: expected a refusal, got admitted stream {}",
            registration.stream_id
        ),
        Err(error) => panic!("{label}: expected an answer, got {error:?}"),
    }
}

/// Every held OPEN leaves the hold through exactly one counter.
fn assert_partition(hold: RotationFreezeHoldSnapshot) {
    assert_eq!(
        hold.held,
        hold.currently_held
            + hold.released_on_commit
            + hold.released_on_abort
            + hold.refused_after_bound
            + hold.cancelled
            + hold.released_on_session_loss,
        "every held OPEN leaves the hold exactly once: {hold:?}"
    );
}

#[test]
fn hold_bound_is_derived_from_the_handshake_budget_and_the_waiting_deadlines() {
    let operation = StdDuration::from_secs(30);
    // The relay default handshake budget (10 s) is capped at 1.5 s.
    assert_eq!(freeze_hold::hold_bound(10_000, operation, None), MAX_HOLD);
    assert_eq!(MAX_HOLD, StdDuration::from_millis(1_500));
    // A tighter negotiated handshake budget wins.
    assert_eq!(
        freeze_hold::hold_bound(1_000, operation, None),
        StdDuration::from_secs(1)
    );
    // Half the operation timeout, so the ingress admission deadline cannot
    // fire first and turn `not_dispatched` into `unknown`.
    assert_eq!(
        freeze_hold::hold_bound(10_000, StdDuration::from_secs(2), None),
        StdDuration::from_secs(1)
    );
    // Half the peer idle timeout on a cluster relay, for the ingress's wait
    // on the owner's response head.
    assert_eq!(
        freeze_hold::hold_bound(10_000, operation, Some(StdDuration::from_secs(2))),
        StdDuration::from_secs(1)
    );
    assert_eq!(
        freeze_hold::hold_bound(10_000, operation, Some(StdDuration::from_secs(60))),
        MAX_HOLD
    );
    assert_eq!(freeze_hold::per_device_cap(64), MAX_HELD_PER_DEVICE);
    assert_eq!(freeze_hold::per_device_cap(3), 3);
    assert_eq!(freeze_hold::per_device_cap(0), 1);
}

#[tokio::test]
async fn an_open_during_a_freeze_is_admitted_after_commit() {
    let mut fixture = FreezeFixture::new("hold-commit", false);
    fixture.quiesce();

    let mut receiver = fixture.open();
    assert_waiting(&mut receiver, "quiescing");
    assert_eq!(
        fixture.opens_sent(),
        0,
        "a held OPEN never reaches the device during the freeze"
    );
    assert_eq!(fixture.session().streams.len(), 1);
    assert_eq!(fixture.hold().currently_held, 1);

    // The roster fixed at QUIESCE is untouched by the held OPEN.
    assert!(fixture.complete_barrier().is_empty());
    assert_eq!(
        fixture
            .relay_fence()
            .entries
            .iter()
            .map(|entry| entry.stream_id)
            .collect::<Vec<_>>(),
        vec![STREAM_ID]
    );
    fixture.connector_frozen(0).await;
    assert_waiting(&mut receiver, "draining");
    fixture.connector_drained().await;
    assert_waiting(&mut receiver, "committing");
    assert_eq!(fixture.opens_sent(), 0);
    fixture.connector_committed().await;

    // COMMITTED admits it, with no consumer-visible error.
    assert_eq!(admitted(&mut receiver, "after commit"), STREAM_ID + 1);
    assert_eq!(fixture.opens_sent(), 1, "exactly one OPEN, after COMMITTED");
    assert_eq!(fixture.session().streams.len(), 2);
    let hold = fixture.hold();
    assert_eq!(hold.held, 1);
    assert_eq!(hold.released_on_commit, 1);
    assert_eq!(hold.admitted_after_hold, 1);
    assert_eq!(hold.currently_held, 0);
    assert_eq!(hold.refused_after_bound, 0);
    assert_partition(hold);
}

#[tokio::test]
async fn an_open_held_past_the_bound_is_refused_with_rotation_freeze() {
    let mut fixture = FreezeFixture::new("hold-bound", false);
    fixture.quiesce();
    let mut receiver = fixture.open();
    assert_waiting(&mut receiver, "held");

    // Inside the bound nothing changes.
    fixture
        .actor
        .service_held_opens(Instant::now() + MAX_HOLD / 2);
    assert_waiting(&mut receiver, "inside the bound");

    // Past the bound the freeze is still on, so the answer is the distinct
    // scheduled-freeze refusal, not the owner-not-ready fault refusal.
    fixture
        .actor
        .service_held_opens(Instant::now() + MAX_HOLD + StdDuration::from_millis(1));
    assert!(matches!(
        refused(&mut receiver, "past the bound"),
        RelayError::RotationFreeze
    ));
    let hold = fixture.hold();
    assert_eq!(hold.refused_after_bound, 1);
    assert_eq!(hold.currently_held, 0);
    assert!(hold.max_hold_wait_ms >= MAX_HOLD.as_millis() as u64);
    assert_partition(hold);

    // The refused OPEN is never dispatched later.
    fixture.commit_rotation().await;
    assert_eq!(fixture.opens_sent(), 0);
    assert_eq!(fixture.hold().admitted_after_hold, 0);
}

#[tokio::test]
async fn the_hold_cap_is_enforced_per_device() {
    let mut fixture = FreezeFixture::new("hold-cap", false);
    let cap = freeze_hold::per_device_cap(fixture.actor.options.limits.max_streams_per_device);
    assert_eq!(cap, MAX_HELD_PER_DEVICE);
    fixture.quiesce();

    let mut held: Vec<Admission> = (0..cap).map(|_| fixture.open()).collect();
    for (index, receiver) in held.iter_mut().enumerate() {
        assert_waiting(receiver, &format!("held {index}"));
    }
    let mut over = fixture.open();
    assert!(
        matches!(
            refused(&mut over, "over the cap"),
            RelayError::RotationFreeze
        ),
        "an OPEN over the cap is refused at once with the scheduled-freeze reason"
    );
    let hold = fixture.hold();
    assert_eq!(hold.held, cap as u64);
    assert_eq!(hold.currently_held, cap as u64);
    assert_eq!(hold.refused_hold_full, 1);

    fixture.commit_rotation().await;
    let mut stream_ids: Vec<u64> = held
        .iter_mut()
        .enumerate()
        .map(|(index, receiver)| admitted(receiver, &format!("held {index}")))
        .collect();
    let arrival_order = stream_ids.clone();
    stream_ids.sort_unstable();
    assert_eq!(arrival_order, stream_ids, "held OPENs are admitted FIFO");
    assert_eq!(fixture.opens_sent(), cap);
    let hold = fixture.hold();
    assert_eq!(hold.admitted_after_hold, cap as u64);
    assert_partition(hold);
}

#[tokio::test]
async fn a_consumer_cancelling_during_the_hold_dispatches_nothing() {
    let mut fixture = FreezeFixture::new("hold-cancel", false);
    fixture.quiesce();
    let receiver = fixture.open();
    let mut sibling = fixture.open();
    drop(receiver);

    fixture.commit_rotation().await;
    assert_eq!(admitted(&mut sibling, "sibling"), STREAM_ID + 1);
    assert_eq!(
        fixture.opens_sent(),
        1,
        "only the sibling's OPEN reaches the device"
    );
    let hold = fixture.hold();
    assert_eq!(hold.cancelled, 1);
    assert_eq!(hold.admitted_after_hold, 1);
    assert_partition(hold);
}

#[tokio::test]
async fn an_abort_during_the_hold_admits_on_the_resumed_old_carrier() {
    let mut fixture = FreezeFixture::new("hold-abort", false);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    let mut receiver = fixture.open();
    let abort_message_id = fixture.abort_by_candidate_loss().await;
    // Still frozen while the abort completes.
    assert_waiting(&mut receiver, "aborting");
    let mut during_abort = fixture.open();
    assert_waiting(&mut during_abort, "opened while aborting");
    assert_eq!(fixture.opens_sent(), 0);

    fixture.connector_aborted(&abort_message_id).await;
    assert_eq!(admitted(&mut receiver, "after abort"), STREAM_ID + 1);
    assert_eq!(admitted(&mut during_abort, "after abort"), STREAM_ID + 2);
    assert_eq!(fixture.opens_sent(), 2);
    let hold = fixture.hold();
    assert_eq!(hold.released_on_abort, 2);
    assert_eq!(hold.released_on_commit, 0);
    assert_eq!(hold.admitted_after_hold, 2);
    assert_partition(hold);
}

#[tokio::test]
async fn recovery_during_the_hold_releases_with_the_fault_refusal() {
    let mut fixture = FreezeFixture::new("hold-recovery", false);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(0).await;
    let mut receiver = fixture.open();
    assert_waiting(&mut receiver, "draining");

    fixture
        .actor
        .disconnect_data(fixture.old_carrier.clone())
        .await;
    assert_eq!(fixture.phase(), RotationPhase::Recovering);
    // The actor settles held OPENs after every command.
    fixture.actor.service_held_opens(Instant::now());
    assert!(
        matches!(
            refused(&mut receiver, "recovery"),
            RelayError::OwnerNotReady
        ),
        "recovery is a fault state: the held OPEN gets the existing fault refusal"
    );
    assert_eq!(fixture.opens_sent(), 0);
    let hold = fixture.hold();
    assert_eq!(hold.released_on_abort, 1);
    assert_eq!(hold.admitted_after_hold, 0);
    assert_partition(hold);

    // A new OPEN during recovery is not held: the fault refusal is unchanged.
    let mut late = fixture.open();
    assert!(matches!(
        refused(&mut late, "opened during recovery"),
        RelayError::OwnerNotReady
    ));
    assert_eq!(fixture.hold().held, 1);
}

#[tokio::test]
async fn session_loss_during_the_hold_releases_with_the_fault_refusal() {
    let mut fixture = FreezeFixture::new("hold-session-loss", false);
    fixture.quiesce();
    let mut receiver = fixture.open();
    assert_waiting(&mut receiver, "held");

    let key = fixture.key.clone();
    fixture
        .actor
        .close_session(&key, super::super::CONTROL_CLOSED_REASON)
        .await;
    assert!(
        matches!(
            refused(&mut receiver, "session loss"),
            RelayError::OwnerNotReady
        ),
        "a held OPEN was never dispatched, so session loss answers not_dispatched"
    );
    let hold = fixture.actor.freeze_hold.snapshot();
    assert_eq!(hold.released_on_session_loss, 1);
    assert_partition(hold);
}

#[tokio::test]
async fn relay_shutdown_during_the_hold_releases_every_held_open() {
    let mut fixture = FreezeFixture::new("hold-shutdown", false);
    fixture.quiesce();
    let mut first = fixture.open();
    let mut second = fixture.open();

    fixture.actor.close_all().await;
    for (label, receiver) in [("first", &mut first), ("second", &mut second)] {
        assert!(matches!(
            refused(receiver, label),
            RelayError::OwnerNotReady
        ));
    }
    let hold = fixture.actor.freeze_hold.snapshot();
    assert_eq!(hold.released_on_session_loss, 2);
    assert_eq!(hold.currently_held, 0);
    assert_partition(hold);
}

#[tokio::test]
async fn owner_not_ready_fault_states_are_still_refused_at_once() {
    // No active carrier: a fault state, never held.
    let mut fixture = FreezeFixture::new("hold-fault", false);
    fixture
        .actor
        .sessions
        .get_mut(&fixture.key.scope())
        .expect("fixture session")
        .active_carrier = None;
    let mut receiver = fixture.open();
    assert!(matches!(
        refused(&mut receiver, "no active carrier"),
        RelayError::OwnerNotReady
    ));
    assert_eq!(fixture.hold(), RotationFreezeHoldSnapshot::default());
}
