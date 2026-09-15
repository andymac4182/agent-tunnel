//! The one-shot gate-4 fixture hold for the owner's peer relay.
//!
//! Implementation gate 4 must rotate a stream while its owner→device record
//! stream stops at a named position: inside a BODY record's eight-byte
//! header, inside a BODY payload, or after END but before the outer FIN.
//! An armed [`HttpRelayHold`] makes the owner's peer relay stop its next
//! actor write at that position until the fixture releases it; the rotation,
//! sequencing, carriers and device are unchanged and real.
//!
//! This implementation lives only in the harness (gate 5).  `tunnel-relay`
//! defines the [`HttpRelayInterposer`] hook and ships no implementation, so
//! no relay artifact can honour a hold; the harness attaches this one through
//! `HttpForwardExports::with_fixture_interposer`.  An unarmed hold is a
//! pass-through, and a hold releases itself after [`HOLD_CEILING`] so a
//! fixture that forgets to release cannot wedge a stream forever.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tunnel_relay::{HttpRelayHoldPoint, HttpRelayInterposer};

/// The longest a held write waits before releasing itself.
pub const HOLD_CEILING: Duration = Duration::from_secs(30);

const IDLE: u8 = 0;
const ARMED: u8 = 1;
const HELD: u8 = 2;
const RELEASED: u8 = 3;

#[derive(Debug)]
struct State {
    phase: AtomicU8,
    point: AtomicU8,
    header_bytes: AtomicU8,
    hits: AtomicU64,
    reached: Notify,
    release: Notify,
}

/// A one-shot hold shared between a fixture and the owner relay.
#[derive(Clone, Debug)]
pub struct HttpRelayHold {
    state: Arc<State>,
}

impl Default for HttpRelayHold {
    fn default() -> Self {
        Self {
            state: Arc::new(State {
                phase: AtomicU8::new(IDLE),
                point: AtomicU8::new(0),
                header_bytes: AtomicU8::new(0),
                hits: AtomicU64::new(0),
                reached: Notify::new(),
                release: Notify::new(),
            }),
        }
    }
}

const fn point_code(point: HttpRelayHoldPoint) -> u8 {
    match point {
        HttpRelayHoldPoint::InsideBodyHeader { .. } => 1,
        HttpRelayHoldPoint::InsideBodyPayload => 2,
        HttpRelayHoldPoint::BeforeRequestFin => 3,
    }
}

impl HttpRelayHold {
    /// Arm the hold for the next stream reaching `point`.  Returns `false`
    /// unless the hold is idle (a previous use was released), so a stale arm
    /// cannot be mistaken for a new one.
    pub fn arm(&self, point: HttpRelayHoldPoint) -> bool {
        if let HttpRelayHoldPoint::InsideBodyHeader { bytes } = point
            && !(1..=7).contains(&bytes)
        {
            return false;
        }
        let from = self.state.phase.load(Ordering::Acquire);
        if from != IDLE && from != RELEASED {
            return false;
        }
        if self
            .state
            .phase
            .compare_exchange(from, ARMED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.state.point.store(point_code(point), Ordering::Release);
        if let HttpRelayHoldPoint::InsideBodyHeader { bytes } = point {
            self.state.header_bytes.store(bytes, Ordering::Release);
        }
        true
    }

    /// Wait until an armed hold is holding a write.
    pub async fn reached(&self) {
        loop {
            let notified = self.state.reached.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.phase.load(Ordering::Acquire) == HELD {
                return;
            }
            notified.await;
        }
    }

    /// Whether a write is held right now.
    #[must_use]
    pub fn is_held(&self) -> bool {
        self.state.phase.load(Ordering::Acquire) == HELD
    }

    /// Release the held write (or disarm an unused hold).
    pub fn release(&self) {
        self.state.phase.store(RELEASED, Ordering::Release);
        self.state.release.notify_waiters();
    }

    /// How many writes this hold has held.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.state.hits.load(Ordering::Acquire)
    }

    fn current_point(&self) -> Option<HttpRelayHoldPoint> {
        if self.state.phase.load(Ordering::Acquire) != ARMED {
            return None;
        }
        match self.state.point.load(Ordering::Acquire) {
            1 => Some(HttpRelayHoldPoint::InsideBodyHeader {
                bytes: self.state.header_bytes.load(Ordering::Acquire),
            }),
            2 => Some(HttpRelayHoldPoint::InsideBodyPayload),
            3 => Some(HttpRelayHoldPoint::BeforeRequestFin),
            _ => None,
        }
    }

    async fn hold(&self, point: HttpRelayHoldPoint) {
        if self.current_point() != Some(point) {
            return;
        }
        if self
            .state
            .phase
            .compare_exchange(ARMED, HELD, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.state.hits.fetch_add(1, Ordering::AcqRel);
        let released = self.state.release.notified();
        tokio::pin!(released);
        released.as_mut().enable();
        self.state.reached.notify_waiters();
        if self.state.phase.load(Ordering::Acquire) == HELD {
            let _ = tokio::time::timeout(HOLD_CEILING, released).await;
        }
        let _ =
            self.state
                .phase
                .compare_exchange(HELD, RELEASED, Ordering::AcqRel, Ordering::Acquire);
    }
}

impl HttpRelayInterposer for HttpRelayHold {
    fn armed_point(&self) -> Option<HttpRelayHoldPoint> {
        self.current_point()
    }

    fn hold_at(&self, point: HttpRelayHoldPoint) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(self.hold(point))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_hold_is_one_shot_point_specific_and_released_by_the_fixture() {
        let hold = HttpRelayHold::default();
        // Unarmed: pass-through.
        hold.hold_at(HttpRelayHoldPoint::BeforeRequestFin).await;
        assert!(!hold.arm(HttpRelayHoldPoint::InsideBodyHeader { bytes: 8 }));
        assert!(hold.arm(HttpRelayHoldPoint::BeforeRequestFin));
        assert!(!hold.arm(HttpRelayHoldPoint::InsideBodyPayload), "one shot");
        // A different point passes through.
        hold.hold_at(HttpRelayHoldPoint::InsideBodyPayload).await;
        let held = {
            let hold = hold.clone();
            tokio::spawn(async move { hold.hold_at(HttpRelayHoldPoint::BeforeRequestFin).await })
        };
        hold.reached().await;
        assert!(hold.is_held());
        assert!(!held.is_finished());
        hold.release();
        held.await.expect("join");
        assert_eq!(hold.hits(), 1);
        assert!(hold.arm(HttpRelayHoldPoint::InsideBodyPayload), "rearmed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_forgotten_hold_releases_itself_at_the_ceiling() {
        let hold = HttpRelayHold::default();
        assert!(hold.arm(HttpRelayHoldPoint::InsideBodyPayload));
        let started = tokio::time::Instant::now();
        hold.hold_at(HttpRelayHoldPoint::InsideBodyPayload).await;
        assert_eq!(started.elapsed(), HOLD_CEILING);
        assert!(!hold.is_held());
    }
}
