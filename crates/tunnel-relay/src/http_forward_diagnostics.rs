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
use tunnel_http_forward::{RecordPosition, TrackerSnapshot};

/// The most recent records retained per kind.
pub const MAX_HTTP_FORWARD_RECORDS: usize = 64;

/// A payload-free record-grammar position of one direction: counters of the
/// record headers seen and where the byte stream stops.  Nothing here is
/// derived from a payload octet.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpRecordPosition {
    pub heads: u32,
    pub bodies: u64,
    pub ends: u32,
    pub body_bytes: u64,
    pub total_bytes: u64,
    /// `boundary`, `partial_header`, `partial_head` or `partial_body`.
    pub position: &'static str,
    /// Bytes of the unfinished header or payload that arrived.
    pub partial_received: u32,
    /// The unfinished payload's declared length (zero inside a header).
    pub partial_total: u32,
    pub invalid: bool,
}

impl From<TrackerSnapshot> for HttpRecordPosition {
    fn from(snapshot: TrackerSnapshot) -> Self {
        let (partial_received, partial_total) = match snapshot.position {
            RecordPosition::Boundary => (0, 0),
            RecordPosition::Header { received } => (u32::from(received), 0),
            RecordPosition::Payload {
                received, total, ..
            } => (received, total),
        };
        Self {
            heads: snapshot.heads,
            bodies: snapshot.bodies,
            ends: snapshot.ends,
            body_bytes: snapshot.body_bytes,
            total_bytes: snapshot.total_bytes,
            position: snapshot.position.label(),
            partial_received,
            partial_total,
            invalid: snapshot.invalid,
        }
    }
}

/// The owner's view of one HTTP stream at a completed scheduled rotation.
///
/// The record positions and parked/buffered bytes are captured when the
/// owner froze its writer at QUIESCE (so the request position is exactly
/// what was sequenced below the relay fence); the fences and acknowledgement
/// cursors are the attempt's drain proof, read when the attempt completed.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpRotationObservation {
    pub stream_id: u64,
    pub operation_id: String,
    pub request_id: Option<String>,
    /// The session's completed-rotation count including this attempt.
    pub rotation: u64,
    pub rotation_id: String,
    pub old_generation: u64,
    pub new_generation: u64,
    /// Owner→device bytes sequenced before the freeze.
    pub request: HttpRecordPosition,
    /// The owner's FIN was sequenced before the freeze.
    pub request_fin_sequenced: bool,
    /// Device→owner bytes received before the freeze.
    pub response: HttpRecordPosition,
    pub response_fin_received: bool,
    /// Owner→device bytes held unsequenced (credit, replay or the freeze).
    pub parked_bytes: usize,
    /// Device→owner bytes held for the reader: credit withheld by the owner.
    pub receive_buffered_bytes: usize,
    /// `fin` or `reset` when a terminal waited behind the freeze.
    pub deferred_terminal: Option<&'static str>,
    /// The owner's `last_emitted` when it froze.
    pub frozen_last_emitted: u64,
    pub relay_fence: Option<u64>,
    pub connector_fence: Option<u64>,
    pub relay_acknowledged: Option<u64>,
    pub connector_acknowledged: Option<u64>,
}

/// The live owner view of one HTTP stream in a relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RelayHttpStreamSnapshot {
    /// Owner→device bytes sequenced so far.
    pub request: HttpRecordPosition,
    pub request_fin_sequenced: bool,
    /// Device→owner bytes received in order so far.
    pub response: HttpRecordPosition,
    pub response_fin_received: bool,
    /// Owner→device bytes waiting unsequenced (credit, replay or freeze).
    pub parked_bytes: usize,
    /// Device→owner bytes waiting for the reader.
    pub receive_buffered_bytes: usize,
    /// Cumulative owner→device send credit and bytes sent.
    pub send_credit: u64,
    pub sent_bytes: u64,
    /// `fin` or `reset` while a terminal waits behind parked data or a
    /// freeze.
    pub deferred_terminal: Option<&'static str>,
    pub local_reset: Option<u16>,
    pub peer_reset: Option<u16>,
    pub cancel_sent: bool,
    pub reset_sequence: Option<u64>,
    pub reset_generation: Option<u64>,
    pub reset_deferred_by_freeze: bool,
    /// The owner's writer is frozen for rotation or recovery.
    pub frozen: bool,
}

/// The owner published `STREAM_FORGET` for an HTTP stream and removed it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpForgetRecord {
    pub stream_id: u64,
    pub operation_id: String,
    pub request_id: Option<String>,
}

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
    /// Final owner→device (sequenced) and device→owner (received) record
    /// positions.
    pub request: HttpRecordPosition,
    pub response: HttpRecordPosition,
    /// The owner's own RESET: its sequence, the generation of the carrier it
    /// was queued on, and whether a rotation freeze deferred it.
    pub reset_sequence: Option<u64>,
    pub reset_generation: Option<u64>,
    pub reset_deferred_by_freeze: bool,
    /// The owner sent a scoped control `CANCEL` for this stream.
    pub cancel_sent: bool,
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
    /// The first sanitized `HTTP_*` code, when any.  An `owner_peer` record
    /// carries one only when the owner's own record validation or progress
    /// budget failed the exchange.
    pub error_code: Option<&'static str>,
    /// `not_dispatched`, `dispatched` or `unknown`.  An `owner_peer` record
    /// holds no dispatch knowledge beyond its own validation.
    pub execution: &'static str,
    /// The transport progress budget that expired at this endpoint, when
    /// one did: `first_head`, `record`, `credit_stall` or `fin_after_end`.
    pub progress_expired: Option<&'static str>,
}

/// The retained diagnostic snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpForwardDiagnosticSnapshot {
    pub owner_streams: Vec<HttpOwnerStreamRecord>,
    pub exchanges: Vec<HttpExchangeRecord>,
    pub rotations: Vec<HttpRotationObservation>,
    pub forgotten: Vec<HttpForgetRecord>,
    pub owner_streams_recorded: u64,
    pub exchanges_recorded: u64,
    pub rotations_recorded: u64,
    pub forgotten_recorded: u64,
    /// Public requests refused by head normalization before any owner
    /// route, peer stream or tunnel stream was opened.
    pub ingress_rejected_before_admission: u64,
    /// Highest HTTP peer-hop bytes this relay had in flight to (sent) and
    /// queued from (received) any one peer across all its streams, and the
    /// per-direction aggregate bound.
    pub hop_aggregate_send_high_water: usize,
    pub hop_aggregate_receive_high_water: usize,
    pub hop_aggregate_limit: usize,
}

#[derive(Debug, Default)]
struct Inner {
    owner_streams: VecDeque<HttpOwnerStreamRecord>,
    exchanges: VecDeque<HttpExchangeRecord>,
    rotations: VecDeque<HttpRotationObservation>,
    forgotten: VecDeque<HttpForgetRecord>,
    owner_streams_recorded: u64,
    exchanges_recorded: u64,
    rotations_recorded: u64,
    forgotten_recorded: u64,
    ingress_rejected_before_admission: u64,
    hop_aggregate_send_high_water: usize,
    hop_aggregate_receive_high_water: usize,
}

fn push_bounded<T>(queue: &mut VecDeque<T>, value: T) {
    if queue.len() >= MAX_HTTP_FORWARD_RECORDS {
        queue.pop_front();
    }
    queue.push_back(value);
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

    pub fn record_rotation(&self, record: HttpRotationObservation) {
        let mut inner = self.lock();
        push_bounded(&mut inner.rotations, record);
        inner.rotations_recorded = inner.rotations_recorded.saturating_add(1);
    }

    pub fn record_forget(&self, record: HttpForgetRecord) {
        let mut inner = self.lock();
        push_bounded(&mut inner.forgotten, record);
        inner.forgotten_recorded = inner.forgotten_recorded.saturating_add(1);
    }

    pub fn record_ingress_rejection(&self) {
        let mut inner = self.lock();
        inner.ingress_rejected_before_admission =
            inner.ingress_rejected_before_admission.saturating_add(1);
    }

    pub fn note_hop_aggregate(&self, send: usize, receive: usize) {
        let mut inner = self.lock();
        inner.hop_aggregate_send_high_water = inner.hop_aggregate_send_high_water.max(send);
        inner.hop_aggregate_receive_high_water =
            inner.hop_aggregate_receive_high_water.max(receive);
    }

    #[must_use]
    pub fn snapshot(&self) -> HttpForwardDiagnosticSnapshot {
        let inner = self.lock();
        HttpForwardDiagnosticSnapshot {
            owner_streams: inner.owner_streams.iter().cloned().collect(),
            exchanges: inner.exchanges.iter().cloned().collect(),
            rotations: inner.rotations.iter().cloned().collect(),
            forgotten: inner.forgotten.iter().cloned().collect(),
            owner_streams_recorded: inner.owner_streams_recorded,
            exchanges_recorded: inner.exchanges_recorded,
            rotations_recorded: inner.rotations_recorded,
            forgotten_recorded: inner.forgotten_recorded,
            ingress_rejected_before_admission: inner.ingress_rejected_before_admission,
            hop_aggregate_send_high_water: inner.hop_aggregate_send_high_water,
            hop_aggregate_receive_high_water: inner.hop_aggregate_receive_high_water,
            hop_aggregate_limit: crate::http::forward::HOP_AGGREGATE_BYTES,
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
