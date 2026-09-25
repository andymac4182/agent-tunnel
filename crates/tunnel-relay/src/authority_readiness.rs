//! Readiness of a single relay's Redis authority (task row M6-C67).
//!
//! A relay without `[cluster]` has no membership readiness, so before M6-C67
//! its `/readyz` answered `200` once it was serving -- also while every
//! request failed closed with `AUTHORIZATION_UNAVAILABLE` because Redis was
//! down, restarted under a run nothing re-attested, or came back empty.
//!
//! One background task checks the authority with
//! [`tunnel_catalog::Catalog::check_authority`] every [`PROBE_INTERVAL`],
//! each check bounded by [`PROBE_DEADLINE`], and publishes the outcome as a
//! deadline.  `/readyz` only reads that deadline, so a probe never reaches
//! Redis and a burst of probes adds no Redis traffic.  The state fails
//! closed three ways: a failed check withdraws readiness at once, a check
//! that exceeds its deadline counts as failed, and a task that stopped (a
//! panic, cancellation) lets the deadline lapse within [`READY_FOR`].
//!
//! Recovery is the check succeeding again.  The check runs on the catalog's
//! ordinary lane, so after a Redis restart it is the same reconnect that
//! re-binds a run the namespace allows (M6-C65) or refuses one it does not
//! (`run_changed`, `unbound`, `continuity`, `persistence`): a refused
//! namespace stays not ready until an operator re-attests it, and a relay
//! whose continuity witness re-bound it is ready again without anyone.
//!
//! The state carries no payload, identifier or error text: only a deadline
//! and, on transitions, one log line with the fixed failure class of
//! [`CatalogConnectionFailure`] (or `timeout`).

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;
use tunnel_catalog::{CatalogConnectionFailure, SharedCatalog};

/// How often the authority is checked.
pub(crate) const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// The bound on one check: the lane's own verification deadline (2 s) plus
/// its reply deadline (2 s), and one second of margin.  A check still
/// pending at this bound counts as failed.
pub(crate) const PROBE_DEADLINE: Duration = Duration::from_secs(5);

/// How long one successful check keeps the relay ready.  It covers the next
/// check's interval and deadline, so a healthy authority never flaps, and it
/// is the longest a stopped probe task can leave a stale `ready`.
pub(crate) const READY_FOR: Duration = PROBE_INTERVAL
    .saturating_add(PROBE_DEADLINE)
    .saturating_add(Duration::from_secs(1));

/// The published authority state of one single relay.
pub(crate) struct AuthorityReadiness {
    origin: Instant,
    /// Milliseconds since `origin` until which the relay is ready; `0` is
    /// never ready.
    ready_until_ms: AtomicU64,
}

impl AuthorityReadiness {
    /// A relay starts ready: `serve` verified the authority (connection,
    /// incarnation and run) just before it listened, and the first check
    /// runs at once.
    fn new() -> Self {
        let readiness = Self {
            origin: Instant::now(),
            ready_until_ms: AtomicU64::new(0),
        };
        readiness.mark_ready();
        readiness
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn mark_ready(&self) {
        let until = self
            .now_ms()
            .saturating_add(u64::try_from(READY_FOR.as_millis()).unwrap_or(u64::MAX));
        self.ready_until_ms.store(until, Ordering::Release);
    }

    fn mark_unready(&self) {
        self.ready_until_ms.store(0, Ordering::Release);
    }

    /// Whether the last check succeeded recently enough.  Reads one atomic.
    pub(crate) fn is_ready(&self) -> bool {
        self.now_ms() < self.ready_until_ms.load(Ordering::Acquire)
    }

    /// Start the check loop for `catalog`; it stops when `cancel` fires.
    pub(crate) fn spawn(catalog: SharedCatalog, cancel: CancellationToken) -> Arc<Self> {
        let readiness = Arc::new(Self::new());
        let state = readiness.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = check_loop(catalog, state) => {}
            }
        });
        readiness
    }
}

/// One bounded check; `Err` carries only the fixed failure class.
async fn check_once(catalog: &SharedCatalog) -> Result<(), &'static str> {
    match tokio::time::timeout(PROBE_DEADLINE, catalog.check_authority()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(CatalogConnectionFailure::classify(&error).as_str()),
        Err(_) => Err("timeout"),
    }
}

async fn check_loop(catalog: SharedCatalog, state: Arc<AuthorityReadiness>) {
    let mut ticker = tokio::time::interval(PROBE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failing: Option<&'static str> = None;
    loop {
        ticker.tick().await;
        match check_once(&catalog).await {
            Ok(()) => {
                state.mark_ready();
                if failing.take().is_some() {
                    tracing::info!("relay Redis authority available; readiness restored");
                }
            }
            Err(class) => {
                state.mark_unready();
                if failing != Some(class) {
                    tracing::warn!(class, "relay Redis authority unavailable; not ready");
                    failing = Some(class);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "authority_readiness_tests.rs"]
mod tests;
