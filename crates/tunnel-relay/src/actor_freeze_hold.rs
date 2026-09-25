//! The owner's bounded admission hold across a data-rotation freeze (task row
//! M3-15; docs/protocol.md, "Quiesce admission").
//!
//! From `ROTATE_QUIESCE` until the connector's `ROTATE_COMMITTED`, or until
//! the attempt ends without a commit, the owner may not add a stream to the
//! immutable roster it fixed at QUIESCE. Refusing a new OPEN there made every
//! scheduled rotation visible to consumers as a `503`, which rmcp and most
//! HTTP clients do not retry. Instead the owner now **holds** that OPEN and
//! runs ordinary admission for it once the freeze ends.
//!
//! The hold is bounded three ways, and none of them is a new unbounded queue:
//!
//! - **Time.** [`hold_bound`]: at most [`MAX_HOLD`] (1.5 s), never more than
//!   the session's negotiated rotation handshake budget, and never more than
//!   half the relay's operation timeout, so the ingress's own admission
//!   deadline cannot fire first and turn a certain `not_dispatched` into an
//!   ambiguous `unknown`.
//! - **Count per device.** [`per_device_cap`]: at most
//!   [`MAX_HELD_PER_DEVICE`], and never more than the device's stream limit.
//! - **Count per relay.** [`MAX_HELD_TOTAL`] across every device.
//!
//! A held OPEN carries no request bytes: its body is still with the consumer
//! (or the ingress, behind HTTP/3 flow control), so a count bound is also the
//! byte bound. Nothing is sent to the device while an OPEN is held, so the
//! two-socket steady state and the QUIESCE roster are untouched.
//!
//! Every held OPEN leaves the hold exactly once, with an explicit outcome:
//!
//! | End of hold | Outcome |
//! | --- | --- |
//! | attempt committed | ordinary admission on the new carrier |
//! | attempt aborted, old carrier resumed | ordinary admission on the old carrier |
//! | attempt entered recovery | ordinary admission, which refuses with the existing owner-not-ready fault refusal |
//! | freeze outlasted the bound | `ROTATION_FREEZE`, `not_dispatched`, retryable |
//! | consumer went away | dropped; no OPEN ever reached the device |
//! | device session ended, or relay shutdown | owner-not-ready fault refusal, `not_dispatched` |
//!
//! When the cap is already full a new OPEN is refused with `ROTATION_FREEZE`
//! at once. That refusal and the bound refusal are the only places the
//! distinct scheduled-freeze reason is spoken; the fault refusals keep their
//! existing body.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use tunnel_catalog::{AuthenticatedConsumer, GrantSnapshot};
use tunnel_protocol::rotation::RotationPhase;
use uuid::Uuid;

use super::{DeviceScope, DeviceSession, RelayActor, RelayError, SessionKey, StreamAdmissionReply};
use crate::runtime::RotationFreezeHoldSnapshot;

/// The longest the owner holds a new OPEN across one rotation freeze.
///
/// **Why 1.5 s.** A healthy freeze is three control round trips —
/// QUIESCE→FROZEN, FROZEN→DRAINED, COMMIT→COMMITTED — plus flushing bytes
/// already queued below the fences, which is bounded by the per-stream credit
/// window. The candidate's mTLS dial and attachment happen **before**
/// QUIESCE, under the handshake budget, so they are not part of the freeze.
/// 1.5 s covers those three round trips at 500 ms each, which is a poor
/// intercontinental or mobile path, and still answers a consumer well inside
/// ordinary HTTP client patience. The M3 gates negotiate a 2 s handshake
/// budget, and [`hold_bound`] never exceeds the negotiated budget, so on the
/// relay's 10 s default the figure is 1.5 s and on a policy tighter than
/// 1.5 s it is that policy's budget. A freeze longer than this is not the
/// scheduled case the hold exists for; the consumer is told so explicitly
/// and may retry.
pub(super) const MAX_HOLD: Duration = Duration::from_millis(1_500);

/// The most OPENs one device may have held at once.
///
/// An MCP consumer usually has one POST and one standalone GET in flight; a
/// burst of concurrent tool calls in the tens of milliseconds a healthy
/// freeze lasts fits in eight. Beyond that the consumer gets an immediate,
/// explicit, retryable refusal rather than joining a queue.
pub(super) const MAX_HELD_PER_DEVICE: usize = 8;

/// The most OPENs the relay holds across every device.
pub(super) const MAX_HELD_TOTAL: usize = 256;

/// The retry hint carried by a `ROTATION_FREEZE` refusal. It is the existing
/// owner-not-ready hint, so the `Retry-After` header and `retry_after_ms`
/// stay derived from one number.
pub(crate) const ROTATION_FREEZE_RETRY_AFTER_MS: u64 =
    crate::peer_runtime::OWNER_NOT_READY_RETRY_AFTER_MS;

/// The hold bound for one session: [`MAX_HOLD`], capped by the negotiated
/// handshake budget, by half the relay's operation timeout and, on a
/// cluster relay, by half the peer idle timeout.
///
/// The last two keep the hold strictly inside every deadline that waits on
/// it. The ingress wraps admission in the operation timeout, and a forwarded
/// request's ingress waits for the owner's response head under the peer idle
/// timeout; either firing first would turn a certain `not_dispatched` answer
/// into an ambiguous one. Halving leaves the other half for the round trip.
pub(super) fn hold_bound(
    handshake_timeout_ms: u64,
    operation_timeout: Duration,
    peer_idle_timeout: Option<Duration>,
) -> Duration {
    let bound = MAX_HOLD
        .min(Duration::from_millis(handshake_timeout_ms))
        .min(operation_timeout / 2);
    peer_idle_timeout.map_or(bound, |idle| bound.min(idle / 2))
}

/// The per-device hold cap: [`MAX_HELD_PER_DEVICE`], never more than the
/// device's stream limit, and at least one.
pub(super) fn per_device_cap(max_streams_per_device: usize) -> usize {
    MAX_HELD_PER_DEVICE.min(max_streams_per_device).max(1)
}

/// True from QUIESCE until COMMITTED, or until the attempt's abort completes:
/// the scheduled freeze the hold covers. `Recovering` also freezes admission
/// but is a fault state, not a scheduled freeze, so it is excluded and keeps
/// its existing refusal.
pub(super) fn attempt_frozen(session: &DeviceSession) -> bool {
    session.rotation.as_ref().is_some_and(|rotation| {
        matches!(
            rotation.state.phase(),
            RotationPhase::Quiescing
                | RotationPhase::Draining
                | RotationPhase::Committing
                | RotationPhase::Aborting
        )
    })
}

/// Everything ordinary admission needs, retained while the OPEN is held.
pub(super) struct HeldOpen {
    pub(super) key: SessionKey,
    pub(super) consumer: AuthenticatedConsumer,
    pub(super) device_id: Uuid,
    pub(super) service_id: Uuid,
    pub(super) grant: GrantSnapshot,
    pub(super) consumer_expires_at: DateTime<Utc>,
    pub(super) request_id: Option<String>,
    pub(super) response: StreamAdmissionReply,
    pub(super) held_at: Instant,
    pub(super) deadline: Instant,
}

/// The relay-wide hold: one FIFO per device and the counters.
#[derive(Default)]
pub(super) struct FreezeHold {
    queues: HashMap<DeviceScope, VecDeque<HeldOpen>>,
    total: usize,
    counters: RotationFreezeHoldSnapshot,
}

impl FreezeHold {
    pub(super) fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// The earliest deadline of any held OPEN.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.queues
            .values()
            .flat_map(|queue| queue.iter().map(|held| held.deadline))
            .min()
    }

    pub(super) fn snapshot(&self) -> RotationFreezeHoldSnapshot {
        RotationFreezeHoldSnapshot {
            currently_held: self.total as u64,
            ..self.counters
        }
    }

    /// Drop held OPENs whose consumer has gone. Nothing was dispatched for
    /// them, so dropping is the whole outcome.
    fn sweep_cancelled(&mut self, scope: &DeviceScope) {
        let Some(queue) = self.queues.get_mut(scope) else {
            return;
        };
        let before = queue.len();
        queue.retain(|held| !held.response.is_closed());
        let removed = before - queue.len();
        self.total -= removed;
        self.counters.cancelled += removed as u64;
        if queue.is_empty() {
            self.queues.remove(scope);
        }
    }

    /// Admit `held` into the hold, or hand it back when a cap is full.
    pub(super) fn try_hold(
        &mut self,
        scope: DeviceScope,
        held: HeldOpen,
        per_device_cap: usize,
    ) -> Option<HeldOpen> {
        self.sweep_cancelled(&scope);
        let device_held = self.queues.get(&scope).map_or(0, VecDeque::len);
        if device_held >= per_device_cap || self.total >= MAX_HELD_TOTAL {
            self.counters.refused_hold_full += 1;
            return Some(held);
        }
        self.queues.entry(scope).or_default().push_back(held);
        self.total += 1;
        self.counters.held += 1;
        None
    }

    fn take(&mut self, scope: &DeviceScope) -> VecDeque<HeldOpen> {
        let queue = self.queues.remove(scope).unwrap_or_default();
        self.total -= queue.len();
        queue
    }

    fn restore(&mut self, scope: DeviceScope, queue: VecDeque<HeldOpen>) {
        if queue.is_empty() {
            return;
        }
        self.total += queue.len();
        self.queues.insert(scope, queue);
    }

    fn record_wait(&mut self, held: &HeldOpen, now: Instant) {
        let waited = now.saturating_duration_since(held.held_at).as_millis();
        let waited = u64::try_from(waited).unwrap_or(u64::MAX);
        self.counters.max_hold_wait_ms = self.counters.max_hold_wait_ms.max(waited);
    }
}

/// Resolve at the earliest hold deadline; never when nothing is held.
pub(super) async fn sleep_until_hold_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,
        None => std::future::pending().await,
    }
}

/// Why a held OPEN left the hold for re-admission.
#[derive(Clone, Copy)]
enum Release {
    Commit,
    Abort,
}

/// What ordinary admission did with one OPEN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Admission {
    Admitted,
    Refused,
    Held,
}

impl RelayActor {
    /// Service every device with held OPENs. Called after every actor command,
    /// on the maintenance tick and when the earliest hold deadline passes.
    pub(super) fn service_held_opens(&mut self, now: Instant) {
        if self.freeze_hold.is_empty() {
            return;
        }
        let scopes: Vec<DeviceScope> = self.freeze_hold.queues.keys().cloned().collect();
        for scope in scopes {
            self.service_held_scope(&scope, now);
        }
    }

    /// Settle the held OPENs of one device against its current session.
    pub(super) fn service_held_scope(&mut self, scope: &DeviceScope, now: Instant) {
        self.freeze_hold.sweep_cancelled(scope);
        let queue = self.freeze_hold.take(scope);
        if queue.is_empty() {
            return;
        }
        let mut keep = VecDeque::with_capacity(queue.len());
        let mut readmit = Vec::new();
        for held in queue {
            let session = self
                .sessions
                .get(scope)
                .filter(|session| session.key == held.key);
            match session {
                None => {
                    // The device session ended (or was replaced) while the
                    // OPEN was held. Nothing reached the device: the existing
                    // owner-not-ready refusal is exact, `not_dispatched`.
                    self.freeze_hold.record_wait(&held, now);
                    self.freeze_hold.counters.released_on_session_loss += 1;
                    let _ = held.response.send(Err(RelayError::OwnerNotReady));
                }
                Some(session) if attempt_frozen(session) => {
                    if now >= held.deadline {
                        self.freeze_hold.record_wait(&held, now);
                        self.freeze_hold.counters.refused_after_bound += 1;
                        let _ = held.response.send(Err(RelayError::RotationFreeze));
                    } else {
                        keep.push_back(held);
                    }
                }
                Some(session) => {
                    // The attempt's freeze is over. `Retiring` is reached only
                    // through COMMITTED; any other phase here means the
                    // attempt ended without one (a completed abort, or
                    // recovery).
                    let release =
                        if session.rotation.as_ref().is_some_and(|rotation| {
                            rotation.state.phase() == RotationPhase::Retiring
                        }) {
                            Release::Commit
                        } else {
                            Release::Abort
                        };
                    readmit.push((held, release));
                }
            }
        }
        self.freeze_hold.restore(scope.clone(), keep);
        for (held, release) in readmit {
            self.freeze_hold.record_wait(&held, now);
            match release {
                Release::Commit => self.freeze_hold.counters.released_on_commit += 1,
                Release::Abort => self.freeze_hold.counters.released_on_abort += 1,
            }
            let admission = self.admit_consumer_stream(
                held.consumer,
                held.device_id,
                held.service_id,
                held.grant,
                held.consumer_expires_at,
                held.request_id,
                held.response,
                false,
            );
            if admission == Admission::Admitted {
                self.freeze_hold.counters.admitted_after_hold += 1;
            }
        }
    }

    /// Answer every remaining held OPEN at relay shutdown. Sessions are
    /// closed first, so each one is a session loss.
    pub(super) fn release_held_opens_at_shutdown(&mut self) {
        let scopes: Vec<DeviceScope> = self.freeze_hold.queues.keys().cloned().collect();
        let now = Instant::now();
        for scope in scopes {
            for held in self.freeze_hold.take(&scope) {
                if held.response.is_closed() {
                    self.freeze_hold.counters.cancelled += 1;
                    continue;
                }
                self.freeze_hold.record_wait(&held, now);
                self.freeze_hold.counters.released_on_session_loss += 1;
                let _ = held.response.send(Err(RelayError::OwnerNotReady));
            }
        }
    }
}
