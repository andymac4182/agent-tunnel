//! The owner's bounded admission hold across a data-rotation freeze (task row
//! M3-15; docs/protocol.md, "Quiesce admission").
//!
//! From `ROTATE_QUIESCE` until the connector's `ROTATE_COMMITTED`, or until
//! the attempt ends without a commit, the owner may not add a stream to the
//! immutable roster it fixed at QUIESCE. Refusing a new request there made
//! every scheduled rotation visible to consumers as a `503`, which rmcp and
//! most HTTP clients do not retry. Instead the owner now **holds** it and runs
//! ordinary admission for it once the freeze ends. Two kinds are held: a
//! consumer stream OPEN (the echo stream, `http-forward/1` and the filesystem
//! upgrade) and a finite unary echo, which carries its request body.
//!
//! The hold is bounded, and none of the bounds is a new unbounded queue:
//!
//! - **Time.** [`hold_bound`]: at most [`MAX_HOLD`] (1.5 s), never more than
//!   the session's negotiated rotation handshake budget, and never more than
//!   half of any deadline that waits on the held request: the relay's
//!   operation timeout, a cluster's peer idle timeout and, for the filesystem
//!   upgrade, the client's handshake budget (the descriptor's
//!   `requestTimeoutSeconds`). None of them can fire first and turn a certain
//!   `not_dispatched` into an ambiguous `unknown`.
//! - **Count per device.** [`per_device_cap`]: at most
//!   [`MAX_HELD_PER_DEVICE`] (8), never more than the device's stream limit.
//! - **Count per tenant.** [`MAX_HELD_PER_TENANT`] (64) across that tenant's
//!   devices, so one tenant cannot take the whole relay's hold.
//! - **Count per relay.** [`MAX_HELD_TOTAL`] (256) across every tenant.
//! - **Bytes.** A held stream OPEN carries no request bytes: its body is still
//!   with the consumer (or the ingress, behind HTTP/3 flow control). A held
//!   unary echo carries its body, at most the relay's `max_body_bytes`
//!   (64 KiB, the configuration ceiling). So the held bytes are at most
//!   8 × 64 KiB = 512 KiB per device, 64 × 64 KiB = 4 MiB per tenant and
//!   256 × 64 KiB = 16 MiB per relay.
//!
//! Nothing is sent to the device while a request is held, so the two-socket
//! steady state and the QUIESCE roster are untouched.
//!
//! Every held request leaves the hold exactly once, with an explicit outcome:
//!
//! | End of hold | Stream OPEN | Unary echo |
//! | --- | --- | --- |
//! | attempt committed | ordinary admission on the new carrier | ordinary dispatch |
//! | attempt aborted, old carrier resumed | ordinary admission on the old carrier | ordinary dispatch |
//! | attempt entered recovery | owner-not-ready fault refusal | `RESOURCE_EXHAUSTED`, the echo's existing freeze answer |
//! | freeze outlasted the bound | `ROTATION_FREEZE` | `ROTATION_FREEZE` |
//! | consumer went away | dropped; nothing reached the device | dropped |
//! | session ended or replaced, or relay shutdown | owner-not-ready fault refusal | `DEVICE_OFFLINE` |
//!
//! Every refusal above is `not_dispatched`. When a cap is already full a new
//! request is refused with `ROTATION_FREEZE` at once. That refusal and the
//! bound refusal are the only places the distinct scheduled-freeze reason is
//! spoken; the fault refusals keep their existing bodies.

use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

// The hold's clock is tokio's, so a paused-time test drives the real deadline.
use tokio::time::Instant;

use chrono::{DateTime, Utc};
use tunnel_catalog::{AuthenticatedConsumer, GrantSnapshot};
use tunnel_protocol::rotation::RotationPhase;
use uuid::Uuid;

use super::{
    DeviceScope, DeviceSession, DispatchRequest, EchoOutcome, RelayActor, RelayError, SessionKey,
    StreamAdmissionReply,
};
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

/// The most requests one tenant may have held at once, across its devices.
pub(super) const MAX_HELD_PER_TENANT: usize = 64;

/// The most requests the relay holds across every tenant.
pub(super) const MAX_HELD_TOTAL: usize = 256;

/// The retry hint carried by a `ROTATION_FREEZE` refusal. It is the existing
/// owner-not-ready hint, so the `Retry-After` header and `retry_after_ms`
/// stay derived from one number.
pub(crate) const ROTATION_FREEZE_RETRY_AFTER_MS: u64 =
    crate::peer_runtime::OWNER_NOT_READY_RETRY_AFTER_MS;

/// The hold bound for one request: [`MAX_HOLD`], capped by the negotiated
/// handshake budget and by half of every deadline in `waiting_deadlines`.
///
/// The waiting deadlines are the ones that would otherwise fire first on a
/// held request: the relay's operation timeout (the ingress wraps admission
/// in it), a cluster's peer idle timeout (a forwarded request's ingress waits
/// for the owner's response head under it) and, for the filesystem upgrade,
/// the client's handshake budget. Either firing first would turn a certain
/// `not_dispatched` answer into an ambiguous one. Halving leaves the other
/// half for the round trip.
pub(super) fn hold_bound(handshake_timeout_ms: u64, waiting_deadlines: &[Duration]) -> Duration {
    waiting_deadlines.iter().fold(
        MAX_HOLD.min(Duration::from_millis(handshake_timeout_ms)),
        |bound, deadline| bound.min(*deadline / 2),
    )
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

/// What was held, with everything ordinary admission needs.
pub(super) enum HeldKind {
    /// A consumer stream OPEN: the echo stream, `http-forward/1` or the
    /// filesystem upgrade. No request bytes.
    Stream {
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: DateTime<Utc>,
        request_id: Option<String>,
        response: StreamAdmissionReply,
    },
    /// A finite unary echo, with its body (at most `max_body_bytes`).
    Echo(DispatchRequest),
}

/// One held request.
pub(super) struct HeldOpen {
    pub(super) key: SessionKey,
    pub(super) kind: HeldKind,
    pub(super) held_at: Instant,
    pub(super) deadline: Instant,
}

/// Why a held request is refused without being admitted.
#[derive(Clone, Copy)]
enum HoldRefusal {
    /// The freeze outlasted the bound, or the hold was full.
    RotationFreeze,
    /// The device session ended or was replaced.
    SessionLost,
}

impl HeldOpen {
    fn is_closed(&self) -> bool {
        match &self.kind {
            HeldKind::Stream { response, .. } => response.is_closed(),
            HeldKind::Echo(request) => request.response.is_closed(),
        }
    }

    /// Answer the consumer with an explicit `not_dispatched` refusal.
    fn refuse(self, refusal: HoldRefusal) {
        match self.kind {
            HeldKind::Stream { response, .. } => {
                let _ = response.send(Err(match refusal {
                    HoldRefusal::RotationFreeze => RelayError::RotationFreeze,
                    HoldRefusal::SessionLost => RelayError::OwnerNotReady,
                }));
            }
            HeldKind::Echo(request) => {
                let _ = request.response.send(EchoOutcome::Failure {
                    code: match refusal {
                        HoldRefusal::RotationFreeze => ROTATION_FREEZE_ECHO_CODE,
                        HoldRefusal::SessionLost => "DEVICE_OFFLINE",
                    },
                    execution: "not_dispatched",
                });
            }
        }
    }
}

/// The unary echo's failure code for the scheduled-freeze refusal; the echo
/// route maps it to the same consumer body as the stream refusal.
pub(crate) const ROTATION_FREEZE_ECHO_CODE: &str = "ROTATION_FREEZE";

/// The relay-wide hold: one FIFO per device and the counters.
#[derive(Default)]
pub(super) struct FreezeHold {
    queues: HashMap<DeviceScope, VecDeque<HeldOpen>>,
    tenants: HashMap<Uuid, usize>,
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
        queue.retain(|held| !held.is_closed());
        let removed = before - queue.len();
        let empty = queue.is_empty();
        self.forget(scope, removed);
        self.counters.cancelled += removed as u64;
        if empty {
            self.queues.remove(scope);
        }
    }

    /// Account `count` requests of `scope` as having left the hold.
    fn forget(&mut self, scope: &DeviceScope, count: usize) {
        self.total -= count;
        if let Some(tenant) = self.tenants.get_mut(&scope.tenant_id) {
            *tenant -= count;
            if *tenant == 0 {
                self.tenants.remove(&scope.tenant_id);
            }
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
        let tenant_held = self.tenants.get(&scope.tenant_id).copied().unwrap_or(0);
        if device_held >= per_device_cap
            || tenant_held >= MAX_HELD_PER_TENANT
            || self.total >= MAX_HELD_TOTAL
        {
            self.counters.refused_hold_full += 1;
            return Some(held);
        }
        *self.tenants.entry(scope.tenant_id).or_default() += 1;
        self.queues.entry(scope).or_default().push_back(held);
        self.total += 1;
        self.counters.held += 1;
        None
    }

    fn take(&mut self, scope: &DeviceScope) -> VecDeque<HeldOpen> {
        let queue = self.queues.remove(scope).unwrap_or_default();
        self.forget(scope, queue.len());
        queue
    }

    fn restore(&mut self, scope: DeviceScope, queue: VecDeque<HeldOpen>) {
        if queue.is_empty() {
            return;
        }
        self.total += queue.len();
        *self.tenants.entry(scope.tenant_id).or_default() += queue.len();
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
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Why a held OPEN left the hold for re-admission.
#[derive(Clone, Copy)]
enum Release {
    Commit,
    Abort,
    Recovery,
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
                    // request was held. Nothing reached the device, so the
                    // answer is the existing `not_dispatched` fault refusal;
                    // a successor session never inherits a held request.
                    self.freeze_hold.record_wait(&held, now);
                    self.freeze_hold.counters.released_on_session_loss += 1;
                    held.refuse(HoldRefusal::SessionLost);
                }
                Some(session) if attempt_frozen(session) => {
                    if now >= held.deadline {
                        self.freeze_hold.record_wait(&held, now);
                        self.freeze_hold.counters.refused_after_bound += 1;
                        held.refuse(HoldRefusal::RotationFreeze);
                    } else {
                        keep.push_back(held);
                    }
                }
                Some(session) => {
                    // The attempt's freeze is over. `Retiring` is reached only
                    // through COMMITTED and `Recovering` only through a fault;
                    // `Active` here means the abort completed.
                    let release = match session.rotation.as_ref().map(|r| r.state.phase()) {
                        Some(RotationPhase::Retiring) => Release::Commit,
                        Some(RotationPhase::Recovering) => Release::Recovery,
                        _ => Release::Abort,
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
                Release::Recovery => self.freeze_hold.counters.released_on_recovery += 1,
            }
            // Order: every caller settles the hold after the writer's frozen
            // DATA/FIN/RESET were flushed, so on the data carrier nothing
            // admitted from the hold is sequenced ahead of them.  The held
            // OPEN itself travels on the control socket, which has no order
            // relative to the data carrier.  This counts a release that found
            // deferred writes still queued on the session (frozen or
            // credit-parked).
            if !matches!(release, Release::Recovery)
                && self.sessions.get(scope).is_some_and(|session| {
                    session.streams.values().any(|stream| {
                        !stream.pending_records.is_empty() || stream.pending_terminal.is_some()
                    })
                })
            {
                self.freeze_hold.counters.released_with_deferred_writes += 1;
            }
            let admission = match held.kind {
                HeldKind::Stream {
                    consumer,
                    device_id,
                    service_id,
                    grant,
                    consumer_expires_at,
                    request_id,
                    response,
                } => self.admit_consumer_stream(
                    consumer,
                    device_id,
                    service_id,
                    grant,
                    consumer_expires_at,
                    request_id,
                    response,
                    false,
                ),
                HeldKind::Echo(request) => self.admit_unary_echo(request, false),
            };
            if admission == Admission::Admitted {
                self.freeze_hold.counters.admitted_after_hold += 1;
            }
        }
    }

    /// Answer every remaining held request at relay shutdown. Sessions are
    /// closed first, so each one is a session loss.
    pub(super) fn release_held_opens_at_shutdown(&mut self) {
        let scopes: Vec<DeviceScope> = self.freeze_hold.queues.keys().cloned().collect();
        let now = Instant::now();
        for scope in scopes {
            for held in self.freeze_hold.take(&scope) {
                if held.is_closed() {
                    self.freeze_hold.counters.cancelled += 1;
                    continue;
                }
                self.freeze_hold.record_wait(&held, now);
                self.freeze_hold.counters.released_on_session_loss += 1;
                held.refuse(HoldRefusal::SessionLost);
            }
        }
    }

    /// Put `held` in the hold for `session`'s current attempt, or refuse it
    /// with `ROTATION_FREEZE` when a cap is full. `fs_handshake` is the
    /// filesystem client's handshake budget, for a filesystem upgrade.
    pub(super) fn hold_request(
        &mut self,
        scope: DeviceScope,
        session_key: SessionKey,
        handshake_timeout_ms: u64,
        kind: HeldKind,
        fs_handshake: Option<Duration>,
    ) -> Admission {
        let now = Instant::now();
        let mut waiting = vec![self.options.limits.operation_timeout];
        if let Some(cluster) = self.options.cluster.as_ref() {
            waiting.push(Duration::from_secs(cluster.peer_idle_timeout_seconds));
        }
        waiting.extend(fs_handshake);
        let held = HeldOpen {
            key: session_key,
            kind,
            held_at: now,
            deadline: now + hold_bound(handshake_timeout_ms, &waiting),
        };
        let cap = per_device_cap(self.options.limits.max_streams_per_device);
        match self.freeze_hold.try_hold(scope, held, cap) {
            None => Admission::Held,
            Some(refused) => {
                refused.refuse(HoldRefusal::RotationFreeze);
                Admission::Refused
            }
        }
    }
}
