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

use std::time::Duration as StdDuration;

use tokio::time::Instant;

use tokio::sync::{mpsc, oneshot};
use tunnel_protocol::rotation::RotationPhase;

use super::super::freeze_hold::{
    self, HeldKind, HeldOpen, MAX_HELD_PER_DEVICE, MAX_HELD_PER_TENANT, MAX_HELD_TOTAL, MAX_HOLD,
};
use super::super::{Command, DeviceScope, DispatchRequest, EchoOutcome};
use super::{FreezeFixture, Observed, STREAM_ID, drain_data, sequenced};
use crate::actor::{ConsumerStreamRegistration, RelayError};
use crate::runtime::RotationFreezeHoldSnapshot;
use tunnel_protocol::{ControlMessage, FrameKind};

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
            + hold.released_on_recovery
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
    assert_eq!(freeze_hold::hold_bound(10_000, &[operation]), MAX_HOLD);
    assert_eq!(MAX_HOLD, StdDuration::from_millis(1_500));
    // A tighter negotiated handshake budget wins.
    assert_eq!(
        freeze_hold::hold_bound(1_000, &[operation]),
        StdDuration::from_secs(1)
    );
    // Half the operation timeout, so the ingress admission deadline cannot
    // fire first and turn `not_dispatched` into `unknown`.
    assert_eq!(
        freeze_hold::hold_bound(10_000, &[StdDuration::from_secs(2)]),
        StdDuration::from_secs(1)
    );
    // Half the peer idle timeout on a cluster relay, for the ingress's wait
    // on the owner's response head.
    assert_eq!(
        freeze_hold::hold_bound(10_000, &[operation, StdDuration::from_secs(2)]),
        StdDuration::from_secs(1)
    );
    assert_eq!(
        freeze_hold::hold_bound(10_000, &[operation, StdDuration::from_secs(60)]),
        MAX_HOLD
    );
    // Half the filesystem client's handshake budget (the descriptor's
    // `requestTimeoutSeconds`), for an fs upgrade.
    assert_eq!(
        freeze_hold::hold_bound(10_000, &[operation, StdDuration::from_secs(2)]),
        StdDuration::from_secs(1)
    );
    let fs_budget =
        StdDuration::from_secs(tunnel_fs_provider::default_limits().request_timeout_seconds());
    assert!(freeze_hold::hold_bound(10_000, &[operation, fs_budget]) <= fs_budget / 2);
    assert_eq!(freeze_hold::per_device_cap(64), MAX_HELD_PER_DEVICE);
    assert_eq!(freeze_hold::per_device_cap(3), 3);
    assert_eq!(freeze_hold::per_device_cap(0), 1);
}

#[tokio::test]
async fn an_open_during_a_freeze_is_admitted_after_commit() {
    let mut fixture = FreezeFixture::new("hold-commit", false);
    fixture.quiesce();
    // A record written while the writer is frozen, held for the new carrier.
    let _frozen = fixture.write(b"frozen-before-commit");

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
    // Order: the frozen record was flushed onto the new carrier, in sequence,
    // before the held OPEN was admitted.
    assert_eq!(
        sequenced(&drain_data(&mut fixture.candidate_rx)),
        vec![(FrameKind::Data, 1, fixture.attempt.new_generation)]
    );
    assert_eq!(
        fixture.hold().released_with_deferred_writes,
        0,
        "the held OPEN was released only after the frozen writes were flushed"
    );
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
    let _frozen = fixture.write(b"frozen-before-abort");
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
    // Order: the frozen record resumed on the old carrier, in sequence, before
    // the held OPENs were admitted.
    let old = drain_data(&mut fixture.old_rx);
    assert_eq!(
        sequenced(&old),
        vec![(FrameKind::Data, 1, fixture.attempt.old_generation)]
    );
    assert!(!old.iter().any(|item| matches!(item, Observed::Close)));
    let hold = fixture.hold();
    assert_eq!(hold.released_with_deferred_writes, 0);
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
    assert_eq!(hold.released_on_recovery, 1);
    assert_eq!(hold.released_on_abort, 0);
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

// ---- the unary echo -------------------------------------------------------

impl FreezeFixture {
    /// One finite unary echo through the real dispatch path.
    async fn echo(&mut self, body: &[u8]) -> oneshot::Receiver<EchoOutcome> {
        let (response, receiver) = oneshot::channel();
        self.actor
            .dispatch_echo(DispatchRequest {
                consumer: self.consumer.clone(),
                device_id: self.device_id,
                service_id: self.service_id,
                grant: self.grant.clone(),
                body: body.to_vec(),
                consumer_expires_at: self.consumer_expires_at,
                response,
            })
            .await;
        receiver
    }

    /// Every unary echo OPEN the relay queued since the last drain.
    fn echo_opens(&mut self) -> Vec<u64> {
        self.drain_control()
            .into_iter()
            .filter_map(|message| match message {
                ControlMessage::Open(open) if open.operation == "echo" => Some(open.stream_id),
                _ => None,
            })
            .collect()
    }
}

fn echo_waiting(receiver: &mut oneshot::Receiver<EchoOutcome>, label: &str) {
    assert!(
        matches!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "{label}: the unary echo must be held, not answered"
    );
}

#[tokio::test]
async fn a_unary_echo_during_a_freeze_is_held_then_dispatched_after_commit() {
    let mut fixture = FreezeFixture::new("hold-echo-commit", false);
    fixture.quiesce();
    let mut receiver = fixture.echo(b"held-echo").await;
    echo_waiting(&mut receiver, "quiescing");
    assert!(
        fixture.echo_opens().is_empty(),
        "nothing reaches the device"
    );
    assert!(fixture.session().pending.is_empty(), "not in the roster");
    assert_eq!(fixture.hold().currently_held, 1);

    // Before the hold, a unary echo in a freeze was refused at once
    // (`RESOURCE_EXHAUSTED`); now it is dispatched after COMMITTED.
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(0).await;
    fixture.connector_drained().await;
    echo_waiting(&mut receiver, "committing");
    let before_commit = fixture.echo_opens();
    assert!(before_commit.is_empty());
    // `connector_committed` drains control itself, so the OPEN is observed
    // through the pending table and the counters.
    fixture.connector_committed().await;
    echo_waiting(&mut receiver, "dispatched, awaiting the device's answer");
    assert_eq!(fixture.session().pending.len(), 1, "dispatched once");
    let hold = fixture.hold();
    assert_eq!(hold.released_on_commit, 1);
    assert_eq!(hold.admitted_after_hold, 1);
    assert_partition(hold);
}

#[tokio::test]
async fn a_unary_echo_held_past_the_bound_is_refused_with_rotation_freeze() {
    let mut fixture = FreezeFixture::new("hold-echo-bound", false);
    fixture.quiesce();
    let mut receiver = fixture.echo(b"held-echo").await;
    echo_waiting(&mut receiver, "held");
    fixture
        .actor
        .service_held_opens(Instant::now() + MAX_HOLD + StdDuration::from_millis(1));
    match receiver.try_recv() {
        Ok(EchoOutcome::Failure { code, execution }) => {
            assert_eq!(code, "ROTATION_FREEZE");
            assert_eq!(execution, "not_dispatched");
        }
        other => panic!("expected the rotation-freeze refusal, got {other:?}"),
    }
    fixture.commit_rotation().await;
    assert!(fixture.session().pending.is_empty(), "never dispatched");
    assert_eq!(fixture.hold().refused_after_bound, 1);
}

#[tokio::test]
async fn a_unary_echo_cancelled_during_the_hold_dispatches_nothing() {
    let mut fixture = FreezeFixture::new("hold-echo-cancel", false);
    fixture.quiesce();
    let receiver = fixture.echo(b"held-echo").await;
    drop(receiver);
    fixture.commit_rotation().await;
    assert!(
        fixture.session().pending.is_empty(),
        "no echo was dispatched"
    );
    let hold = fixture.hold();
    assert_eq!(hold.cancelled, 1);
    assert_eq!(hold.admitted_after_hold, 0);
    assert_partition(hold);
}

// ---- successor session, caps and the real run loop -------------------------

#[tokio::test]
async fn a_successor_session_never_inherits_a_held_open() {
    let mut fixture = FreezeFixture::new("hold-successor", false);
    fixture.quiesce();
    let mut receiver = fixture.open();
    assert_waiting(&mut receiver, "held");

    // The same device reconnects: a successor session with a new key, not
    // frozen, takes the scope without the predecessor having been closed
    // through `close_session`.
    {
        let session = fixture
            .actor
            .sessions
            .get_mut(&fixture.key.scope())
            .expect("fixture session");
        session.key.session_id = "hold-successor-next".to_owned();
        session.rotation = None;
    }
    fixture.actor.service_held_opens(Instant::now());
    assert!(
        matches!(
            refused(&mut receiver, "successor"),
            RelayError::OwnerNotReady
        ),
        "a held OPEN belongs to its session and is refused, not admitted on the successor"
    );
    assert_eq!(fixture.opens_sent(), 0);
    let hold = fixture.hold();
    assert_eq!(hold.released_on_session_loss, 1);
    assert_eq!(hold.admitted_after_hold, 0);
}

/// A held unary echo for an arbitrary scope, for the pure cap tests.
fn synthetic_held(
    fixture: &FreezeFixture,
    receivers: &mut Vec<oneshot::Receiver<EchoOutcome>>,
) -> HeldOpen {
    let (response, receiver) = oneshot::channel();
    receivers.push(receiver);
    let now = Instant::now();
    HeldOpen {
        key: fixture.key.clone(),
        kind: HeldKind::Echo(DispatchRequest {
            consumer: fixture.consumer.clone(),
            device_id: fixture.device_id,
            service_id: fixture.service_id,
            grant: fixture.grant.clone(),
            body: Vec::new(),
            consumer_expires_at: fixture.consumer_expires_at,
            response,
        }),
        held_at: now,
        deadline: now + MAX_HOLD,
    }
}

fn scope(tenant: u128, device: u128) -> DeviceScope {
    DeviceScope {
        tenant_id: uuid::Uuid::from_u128(tenant),
        device_id: uuid::Uuid::from_u128(device),
    }
}

#[tokio::test]
async fn the_hold_cap_is_enforced_per_tenant() {
    let fixture = FreezeFixture::new("hold-tenant-cap", false);
    let mut hold = freeze_hold::FreezeHold::default();
    let mut receivers = Vec::new();
    let devices = MAX_HELD_PER_TENANT / MAX_HELD_PER_DEVICE;
    for device in 0..devices {
        for _ in 0..MAX_HELD_PER_DEVICE {
            assert!(
                hold.try_hold(
                    scope(1, device as u128),
                    synthetic_held(&fixture, &mut receivers),
                    MAX_HELD_PER_DEVICE,
                )
                .is_none()
            );
        }
    }
    // The tenant is full although this device has held nothing.
    assert!(
        hold.try_hold(
            scope(1, 999),
            synthetic_held(&fixture, &mut receivers),
            MAX_HELD_PER_DEVICE
        )
        .is_some(),
        "a tenant's {MAX_HELD_PER_TENANT} held requests fill its cap"
    );
    // Another tenant is unaffected.
    assert!(
        hold.try_hold(
            scope(2, 0),
            synthetic_held(&fixture, &mut receivers),
            MAX_HELD_PER_DEVICE
        )
        .is_none()
    );
    let snapshot = hold.snapshot();
    assert_eq!(snapshot.held, MAX_HELD_PER_TENANT as u64 + 1);
    assert_eq!(snapshot.refused_hold_full, 1);
}

#[tokio::test]
async fn the_hold_cap_is_enforced_per_relay() {
    let fixture = FreezeFixture::new("hold-relay-cap", false);
    let mut hold = freeze_hold::FreezeHold::default();
    let mut receivers = Vec::new();
    // One request per tenant, so neither the device nor the tenant cap binds.
    for tenant in 0..MAX_HELD_TOTAL {
        assert!(
            hold.try_hold(
                scope(10_000 + tenant as u128, 1),
                synthetic_held(&fixture, &mut receivers),
                MAX_HELD_PER_DEVICE,
            )
            .is_none()
        );
    }
    assert!(
        hold.try_hold(
            scope(99_999, 1),
            synthetic_held(&fixture, &mut receivers),
            MAX_HELD_PER_DEVICE
        )
        .is_some(),
        "the relay holds at most {MAX_HELD_TOTAL} requests"
    );
    let snapshot = hold.snapshot();
    assert_eq!(snapshot.currently_held, MAX_HELD_TOTAL as u64);
    assert_eq!(snapshot.refused_hold_full, 1);
}

/// The real actor loop answers a held OPEN at its deadline with no further
/// command: only the `sleep_until_hold_deadline` branch can wake it.
#[tokio::test(start_paused = true)]
async fn the_run_loop_refuses_a_held_open_at_its_deadline_without_a_command() {
    let mut fixture = FreezeFixture::new("hold-run-loop", false);
    fixture.quiesce();
    let receiver = fixture.open();
    let commands: mpsc::Sender<Command> = fixture.actor.command_tx.clone();
    let FreezeFixture {
        actor, control_rx, ..
    } = fixture;
    let started = Instant::now();
    let running = tokio::spawn(actor.run());
    let answer = tokio::time::timeout(MAX_HOLD * 4, receiver)
        .await
        .expect("the run loop answers the held OPEN on its own")
        .expect("the held OPEN is answered, not dropped");
    assert!(matches!(answer, Err(RelayError::RotationFreeze)));
    assert!(Instant::now() - started >= MAX_HOLD, "not before the bound");
    let (response, snapshot) = oneshot::channel();
    commands
        .send(Command::Snapshot { response })
        .await
        .expect("the actor is still running");
    let snapshot = snapshot.await.expect("snapshot");
    assert_eq!(snapshot.rotation_freeze_hold.refused_after_bound, 1);
    running.abort();
    drop(control_rx);
}
