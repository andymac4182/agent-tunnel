//! Bounded diagnostics for public consumer response writes.
//!
//! The relay records only a saturating timeout count and a small recent-event
//! window at exact public response-write callsites.  No socket error, payload,
//! URL, path, token, or caller-provided text is stored.

use std::{
    collections::VecDeque,
    future::Future,
    sync::{Arc, Mutex},
};

use serde::Serialize;
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

/// The outcome of one bounded public response write.
///
/// A timeout is distinct from a completed write, an authorization expiry,
/// and a transport error. Callers must not treat any outcome except `Sent`
/// as delivery success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConsumerWriteOutcome {
    Sent,
    TimedOut,
    Expired,
    Failed,
}

impl ConsumerWriteOutcome {
    #[must_use]
    pub(crate) const fn is_sent(self) -> bool {
        matches!(self, Self::Sent)
    }

    #[must_use]
    pub(crate) const fn is_timed_out(self) -> bool {
        matches!(self, Self::TimedOut)
    }
}

/// Classify one socket write against an already-created absolute deadline.
///
/// The future's error is deliberately discarded: the diagnostic boundary
/// needs only the typed distinction between completion, timeout, and failure,
/// and must not retain or expose transport text.
pub(crate) async fn send_until<F, T, E>(send: F, deadline: Instant) -> ConsumerWriteOutcome
where
    F: Future<Output = Result<T, E>>,
{
    match timeout_at(deadline, send).await {
        Ok(Ok(_)) => ConsumerWriteOutcome::Sent,
        Ok(Err(_)) => ConsumerWriteOutcome::Failed,
        Err(_) => ConsumerWriteOutcome::TimedOut,
    }
}

/// Classify a public response write against both its physical write bound and
/// the consumer authorization lifetime. Authorization expiry wins ties and
/// never contributes to the physical writer-timeout diagnostic.
pub(crate) async fn send_until_or_expired<F, T, E>(
    send: F,
    send_deadline: Instant,
    expiry_deadline: Instant,
) -> ConsumerWriteOutcome
where
    F: Future<Output = Result<T, E>>,
{
    if expiry_deadline <= Instant::now() {
        return ConsumerWriteOutcome::Expired;
    }
    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(expiry_deadline) => ConsumerWriteOutcome::Expired,
        outcome = send_until(send, send_deadline) => outcome,
    }
}

/// The public ingress class that observed a response-write timeout.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerIngressKind {
    Local,
    Forwarded,
}

/// Safe correlation scope for one public consumer response write.
///
/// Device and service UUIDs are authorization-scope identifiers already used
/// by relay diagnostics.  The ingress kind distinguishes an owner-local
/// response from a response written while forwarding from another relay.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct ConsumerWriteScope {
    pub device_id: Uuid,
    pub service_id: Uuid,
    pub ingress: ConsumerIngressKind,
}

impl ConsumerWriteScope {
    #[must_use]
    pub(crate) const fn new(
        device_id: Uuid,
        service_id: Uuid,
        ingress: ConsumerIngressKind,
    ) -> Self {
        Self {
            device_id,
            service_id,
            ingress,
        }
    }
}

/// One redacted timeout event retained in the bounded recent window.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct ConsumerWriteTimeoutSnapshot {
    /// Saturating monotonic occurrence number for this relay process.
    pub sequence: u64,
    pub scope: ConsumerWriteScope,
}

/// Redacted diagnostics returned to the typed relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ConsumerWriteDiagnosticSnapshot {
    /// Saturating monotonic count of timed-out public response writes.
    pub timeout_count: u64,
    /// At most this module's fixed recent-event bound is retained.
    pub recent_timeouts: Vec<ConsumerWriteTimeoutSnapshot>,
}

const MAX_RECENT_TIMEOUTS: usize = 8;

#[derive(Default)]
struct ConsumerWriteDiagnosticState {
    timeout_count: u64,
    recent_timeouts: VecDeque<ConsumerWriteTimeoutSnapshot>,
}

/// Cloneable, bounded state for response-write timeout diagnostics.
#[derive(Clone, Default)]
pub(crate) struct ConsumerWriteDiagnostics {
    state: Arc<Mutex<ConsumerWriteDiagnosticState>>,
}

impl ConsumerWriteDiagnostics {
    /// Record a timeout without retaining any transport error or message
    /// content.  The count and event window are updated under one lock so a
    /// snapshot cannot pair a count with a different scope.
    pub(crate) fn record_timeout(&self, scope: ConsumerWriteScope) -> ConsumerWriteTimeoutSnapshot {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.timeout_count = state.timeout_count.saturating_add(1);
        let event = ConsumerWriteTimeoutSnapshot {
            sequence: state.timeout_count,
            scope,
        };
        if state.recent_timeouts.len() == MAX_RECENT_TIMEOUTS {
            let _ = state.recent_timeouts.pop_front();
        }
        state.recent_timeouts.push_back(event);
        event
    }

    /// Return the bounded redacted view used by a relay's typed snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> ConsumerWriteDiagnosticSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ConsumerWriteDiagnosticSnapshot {
            timeout_count: state.timeout_count,
            recent_timeouts: state.recent_timeouts.iter().copied().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::time::{Duration, Instant, sleep};

    use super::{ConsumerWriteOutcome, send_until_or_expired};

    #[tokio::test]
    async fn expired_write_does_not_poll_send_future() {
        let polled = Arc::new(AtomicBool::new(false));
        let send_polled = polled.clone();
        let outcome = send_until_or_expired(
            async move {
                send_polled.store(true, Ordering::SeqCst);
                Ok::<(), ()>(())
            },
            Instant::now() + Duration::from_secs(1),
            Instant::now() - Duration::from_millis(1),
        )
        .await;

        assert_eq!(outcome, ConsumerWriteOutcome::Expired);
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn authorization_expiry_precedes_a_pending_physical_write_timeout() {
        let start = Instant::now();
        let outcome = send_until_or_expired(
            async {
                sleep(Duration::from_millis(50)).await;
                Ok::<(), ()>(())
            },
            start + Duration::from_secs(1),
            start + Duration::from_millis(5),
        )
        .await;

        assert_eq!(outcome, ConsumerWriteOutcome::Expired);
        assert!(!outcome.is_timed_out());
    }

    #[tokio::test]
    async fn physical_write_deadline_remains_a_timeout_before_expiry() {
        let start = Instant::now();
        let outcome = send_until_or_expired(
            std::future::pending::<Result<(), ()>>(),
            start + Duration::from_millis(5),
            start + Duration::from_secs(1),
        )
        .await;

        assert_eq!(outcome, ConsumerWriteOutcome::TimedOut);
        assert_ne!(outcome, ConsumerWriteOutcome::Expired);
    }
}
