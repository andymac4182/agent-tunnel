//! Bounded, payload-free diagnostics for `http-forward/1` exchanges.
//!
//! Each hop an exchange crosses on this relay records its queue high-water
//! marks when the hop ends: the owner actor's per-stream receive buffer and
//! credit-parked bytes, the peer HTTP/3 stream's credited in-flight bytes
//! and receive queue, and the ingress bridge's handoff and body queues.
//! Records contain identifiers, byte counts and closed-vocabulary labels
//! only; never header values, paths, bodies or credentials.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::Serialize;

/// The most recent records retained per kind.
pub const MAX_HTTP_FORWARD_RECORDS: usize = 64;

/// One owner-actor logical stream carrying an HTTP exchange.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpOwnerStreamRecord {
    pub stream_id: u64,
    pub operation_id: String,
    /// Peer request identity when the consumer arrived through another relay.
    pub request_id: Option<String>,
    /// Largest number of device→owner DATA bytes held for the reader, charged
    /// to the session budget and bounded by the owner's advertised credit.
    pub receive_buffer_high_water: usize,
    /// The owner's advertised per-stream receive window.
    pub receive_window: usize,
    /// Largest number of owner→device bytes parked for send credit.
    pub parked_bytes_high_water: usize,
    /// Largest number of sent-but-unacknowledged bytes retained for replay.
    pub replay_bytes_high_water: usize,
    /// Owner→device DATA payload bytes emitted.
    pub sent_bytes: u64,
    /// Device→owner DATA payload bytes delivered to the reader.
    pub delivered_bytes: u64,
    /// `fin`, `reset` or `closed`: how the owner released the stream.
    pub release: &'static str,
    /// The RESET reason code emitted or received, when any.
    pub reset_reason: Option<u16>,
}

/// One bridge or peer-hop exchange endpoint on this relay.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpExchangeRecord {
    /// `ingress_local`, `ingress_remote` or `owner_peer`.
    pub role: &'static str,
    pub request_id: Option<String>,
    pub stream_id: Option<u64>,
    /// Bridge→carrier request handoff high-water bytes (ingress roles).
    pub request_handoff_high_water: usize,
    /// Carrier→bridge response handoff high-water bytes (ingress roles).
    pub response_handoff_high_water: usize,
    /// Queued public response body high-water bytes (ingress roles).
    pub response_body_high_water: usize,
    /// Largest credited in-flight bytes this relay had sent on the peer
    /// HTTP/3 stream but the peer had not yet consumed.
    pub peer_send_in_flight_high_water: usize,
    /// Largest number of peer DATA bytes received and queued here but not
    /// yet consumed by the next hop.
    pub peer_receive_queue_high_water: usize,
    /// The peer hop's per-direction credit window, when a peer hop exists.
    pub peer_window: usize,
    /// Terminal labels: `complete`, `aborted` or `pending`.
    pub request_outcome: &'static str,
    pub response_outcome: &'static str,
    /// The first sanitized `HTTP_*` code, when any.  The owner relays
    /// records without decoding them, so an `owner_peer` record never has one.
    pub error_code: Option<&'static str>,
    /// `not_dispatched`, `dispatched` or `unknown` (always `unknown` for an
    /// `owner_peer` record, which holds no dispatch knowledge).
    pub execution: &'static str,
}

/// The retained diagnostic snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpForwardDiagnosticSnapshot {
    pub owner_streams: Vec<HttpOwnerStreamRecord>,
    pub exchanges: Vec<HttpExchangeRecord>,
    pub owner_streams_recorded: u64,
    pub exchanges_recorded: u64,
}

#[derive(Debug, Default)]
struct Inner {
    owner_streams: VecDeque<HttpOwnerStreamRecord>,
    exchanges: VecDeque<HttpExchangeRecord>,
    owner_streams_recorded: u64,
    exchanges_recorded: u64,
}

/// Shared bounded recorder.  The lock guards plain data and is never held
/// across an await.
#[derive(Clone, Debug, Default)]
pub struct HttpForwardDiagnostics {
    inner: Arc<Mutex<Inner>>,
}

impl HttpForwardDiagnostics {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn record_owner_stream(&self, record: HttpOwnerStreamRecord) {
        let mut inner = self.lock();
        if inner.owner_streams.len() >= MAX_HTTP_FORWARD_RECORDS {
            inner.owner_streams.pop_front();
        }
        inner.owner_streams.push_back(record);
        inner.owner_streams_recorded = inner.owner_streams_recorded.saturating_add(1);
    }

    pub fn record_exchange(&self, record: HttpExchangeRecord) {
        let mut inner = self.lock();
        if inner.exchanges.len() >= MAX_HTTP_FORWARD_RECORDS {
            inner.exchanges.pop_front();
        }
        inner.exchanges.push_back(record);
        inner.exchanges_recorded = inner.exchanges_recorded.saturating_add(1);
    }

    #[must_use]
    pub fn snapshot(&self) -> HttpForwardDiagnosticSnapshot {
        let inner = self.lock();
        HttpForwardDiagnosticSnapshot {
            owner_streams: inner.owner_streams.iter().cloned().collect(),
            exchanges: inner.exchanges.iter().cloned().collect(),
            owner_streams_recorded: inner.owner_streams_recorded,
            exchanges_recorded: inner.exchanges_recorded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_bounded_and_counted() {
        let diagnostics = HttpForwardDiagnostics::default();
        for index in 0..(MAX_HTTP_FORWARD_RECORDS + 3) {
            diagnostics.record_exchange(HttpExchangeRecord {
                role: "ingress_local",
                stream_id: Some(index as u64),
                ..HttpExchangeRecord::default()
            });
            diagnostics.record_owner_stream(HttpOwnerStreamRecord {
                stream_id: index as u64,
                ..HttpOwnerStreamRecord::default()
            });
        }
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.exchanges.len(), MAX_HTTP_FORWARD_RECORDS);
        assert_eq!(snapshot.owner_streams.len(), MAX_HTTP_FORWARD_RECORDS);
        assert_eq!(
            snapshot.exchanges_recorded,
            (MAX_HTTP_FORWARD_RECORDS + 3) as u64
        );
        assert_eq!(snapshot.exchanges[0].stream_id, Some(3));
    }
}
