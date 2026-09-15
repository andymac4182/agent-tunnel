//! The per-peer aggregate bound on `http-forward/1` peer-hop bytes (review
//! finding D of implementation gate 3).
//!
//! Each hop stream has its own credited window of
//! [`PEER_HOP_WINDOW_BYTES`](super::PEER_HOP_WINDOW_BYTES).  docs/cluster.md
//! also bounds one peer connection to 8 MiB across all its streams and both
//! directions, so N saturated HTTP streams to one peer must not each receive
//! an independent window.  One [`HopAggregate`] per remote peer (keyed by
//! its node identity) therefore holds two counters shared by every HTTP hop
//! stream this relay runs with that peer:
//!
//! * **send**: encoded bytes this relay has sent and the peer has not yet
//!   reported consumed.  A writer waits (never fails) when its next chunk
//!   would take the aggregate above [`HOP_AGGREGATE_BYTES`];
//! * **receive**: encoded bytes received from that peer and still queued
//!   here.  A compliant peer can never exceed the bound, because its own
//!   send aggregate for this relay bounds it; a violation closes the stream.
//!
//! With half the connection ceiling per direction, both directions together
//! stay within 8 MiB.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;
use tunnel_cluster::peer_frame::CONNECTION_BYTE_BUDGET;

/// The aggregate bound per direction per peer, in encoded hop bytes.
pub const HOP_AGGREGATE_BYTES: usize = CONNECTION_BYTE_BUDGET / 2;

#[derive(Debug, Default)]
struct Counters {
    sent_in_flight: u64,
    received_queued: u64,
    send_high_water: u64,
    receive_high_water: u64,
}

/// The shared counters for one remote peer.
#[derive(Debug)]
pub(crate) struct HopAggregate {
    counters: Mutex<Counters>,
    changed: Notify,
    limit: u64,
}

impl HopAggregate {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            counters: Mutex::new(Counters::default()),
            changed: Notify::new(),
            limit: limit as u64,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Counters> {
        self.counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Wait until `cost` more in-flight bytes fit, then charge them.
    /// Resolves `false` if `stopped` resolves first; nothing is charged then.
    pub(crate) async fn acquire_send(
        &self,
        cost: u64,
        stopped: impl std::future::Future<Output = ()>,
    ) -> bool {
        tokio::pin!(stopped);
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut counters = self.lock();
                // A single chunk larger than the whole bound still proceeds
                // once nothing else is in flight, so no stream can wedge.
                if counters.sent_in_flight == 0
                    || counters.sent_in_flight.saturating_add(cost) <= self.limit
                {
                    counters.sent_in_flight = counters.sent_in_flight.saturating_add(cost);
                    counters.send_high_water =
                        counters.send_high_water.max(counters.sent_in_flight);
                    return true;
                }
            }
            tokio::select! {
                () = &mut stopped => return false,
                () = notified => {}
            }
        }
    }

    /// The peer consumed (or the stream released) `bytes` in-flight bytes.
    pub(crate) fn release_send(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        {
            let mut counters = self.lock();
            counters.sent_in_flight = counters.sent_in_flight.saturating_sub(bytes);
        }
        self.changed.notify_waiters();
    }

    /// Charge received bytes.  Returns `false` (charging nothing) when the
    /// peer exceeded the aggregate it must respect.
    pub(crate) fn charge_receive(&self, bytes: u64) -> bool {
        let mut counters = self.lock();
        let Some(next) = counters.received_queued.checked_add(bytes) else {
            return false;
        };
        if next > self.limit {
            return false;
        }
        counters.received_queued = next;
        counters.receive_high_water = counters.receive_high_water.max(next);
        true
    }

    pub(crate) fn release_receive(&self, bytes: u64) {
        let mut counters = self.lock();
        counters.received_queued = counters.received_queued.saturating_sub(bytes);
    }

    /// `(send high water, receive high water)` in encoded bytes.
    pub(crate) fn high_water(&self) -> (usize, usize) {
        let counters = self.lock();
        (
            usize::try_from(counters.send_high_water).unwrap_or(usize::MAX),
            usize::try_from(counters.receive_high_water).unwrap_or(usize::MAX),
        )
    }

    #[cfg(test)]
    pub(crate) fn current(&self) -> (u64, u64) {
        let counters = self.lock();
        (counters.sent_in_flight, counters.received_queued)
    }
}

/// The aggregates of one relay, keyed by remote peer node identity.
#[derive(Clone, Debug, Default)]
pub(crate) struct HopAggregates {
    inner: Arc<Mutex<HashMap<String, Arc<HopAggregate>>>>,
}

impl HopAggregates {
    /// The shared aggregate for `peer_node`.  Idle entries are evicted
    /// before the bounded map grows past the peer destination bound.
    pub(crate) fn for_peer(&self, peer_node: &str) -> Arc<HopAggregate> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(aggregate) = map.get(peer_node) {
            return Arc::clone(aggregate);
        }
        if map.len() >= tunnel_transport::DEFAULT_PEER_DESTINATIONS {
            map.retain(|_, aggregate| Arc::strong_count(aggregate) > 1);
        }
        let aggregate = HopAggregate::new(HOP_AGGREGATE_BYTES);
        map.insert(peer_node.to_owned(), Arc::clone(&aggregate));
        aggregate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_sender_waits_for_the_shared_bound_and_resumes_on_release() {
        let aggregate = HopAggregate::new(100);
        assert!(aggregate.acquire_send(60, std::future::pending()).await);
        assert!(aggregate.acquire_send(40, std::future::pending()).await);
        let waiter = {
            let aggregate = Arc::clone(&aggregate);
            tokio::spawn(async move { aggregate.acquire_send(10, std::future::pending()).await })
        };
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert!(!waiter.is_finished(), "the bound is shared and full");
        aggregate.release_send(20);
        assert!(waiter.await.expect("join"));
        assert_eq!(aggregate.current().0, 90);
        // A stopped waiter charges nothing.
        assert!(!aggregate.acquire_send(50, async {}).await);
        assert_eq!(aggregate.current().0, 90);
        assert_eq!(aggregate.high_water().0, 100);
    }

    #[test]
    fn a_receiver_refuses_bytes_beyond_the_bound_without_charging() {
        let aggregate = HopAggregate::new(100);
        assert!(aggregate.charge_receive(100));
        assert!(!aggregate.charge_receive(1));
        aggregate.release_receive(30);
        assert!(aggregate.charge_receive(30));
        assert_eq!(aggregate.current().1, 100);
    }

    #[test]
    fn aggregates_are_per_peer_and_shared_by_its_streams() {
        let aggregates = HopAggregates::default();
        let first = aggregates.for_peer("relay-a");
        let second = aggregates.for_peer("relay-a");
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &aggregates.for_peer("relay-b")));
    }
}
