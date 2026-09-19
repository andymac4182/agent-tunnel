//! Bounded, payload-free diagnostics for `http-forward/1` exchanges.
//!
//! Each hop an exchange crosses on this relay records its queue high-water
//! marks when the hop ends: the owner actor's per-stream receive buffer and
//! credit-parked bytes, the peer HTTP/3 stream's credited in-flight bytes
//! and receive queue, and the ingress bridge's handoff and body queues.
//! Records contain identifiers, byte counts and closed-vocabulary labels
//! only; never header values, paths, bodies or credentials.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use serde::Serialize;
use tunnel_http_forward::{RecordPosition, TrackerSnapshot};

/// The most recent records retained per kind.
pub const MAX_HTTP_FORWARD_RECORDS: usize = 64;

/// One peer hop's send and receive byte counts **as they stood at a single
/// instant**.
///
/// The peer hop's two published high-water figures are independent all-time
/// `max` latches, so both reading high is equally consistent with two
/// disjoint bursts (task row M8-C22).  This pair is the answer to that: it is
/// only ever written from one of the hop's two mutation points, each of which
/// already holds one of the two figures under its own lock and reads the
/// other from a live atomic, so the two numbers are a reading of the same
/// moment rather than two readings joined afterwards.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HopBytePair {
    /// Credited bytes sent on the peer stream and not yet consumed by the
    /// peer.
    pub send_bytes: usize,
    /// Peer DATA bytes received here and not yet consumed by the next hop.
    pub receive_bytes: usize,
}

impl HopBytePair {
    /// The smaller of the two directions.  A coincident latch is ordered by
    /// this, because it is what a claim of *both* directions loaded rests on:
    /// a pair is better attested than another exactly when the weaker of its
    /// two halves is larger.
    #[must_use]
    pub const fn smaller(self) -> usize {
        if self.send_bytes < self.receive_bytes {
            self.send_bytes
        } else {
            self.receive_bytes
        }
    }
}

/// A peer hop's live byte pair, plus the best-attested coincident instant it
/// has reached.
///
/// Held behind an `Arc` by the hop itself and by a weak entry in
/// [`HttpForwardDiagnostics`], so the live pair is readable on the forwarding
/// snapshot for as long as the hop exists and disappears with it.  Without
/// the live half, any assertion about the hop is post-hoc: a stalled response
/// direction terminates only at the export's 30 s output-credit budget, so an
/// observation window shorter than the exchange sees no record at all.
#[derive(Debug, Default)]
pub struct HopLivePair {
    send_bytes: AtomicUsize,
    receive_bytes: AtomicUsize,
    /// Leaf lock.  Acquired while a caller holds the hop's credit or queue
    /// lock, and never acquires either, so the two orders cannot cycle.
    coincident: Mutex<HopBytePair>,
}

impl HopLivePair {
    /// Record the send direction's current level, reading the receive
    /// direction as it stands at this instant.
    pub fn note_send(&self, send_bytes: usize) {
        self.send_bytes.store(send_bytes, Ordering::Relaxed);
        let receive_bytes = self.receive_bytes.load(Ordering::Relaxed);
        self.latch(HopBytePair {
            send_bytes,
            receive_bytes,
        });
    }

    /// Record the receive direction's current level, reading the send
    /// direction as it stands at this instant.
    pub fn note_receive(&self, receive_bytes: usize) {
        self.receive_bytes.store(receive_bytes, Ordering::Relaxed);
        let send_bytes = self.send_bytes.load(Ordering::Relaxed);
        self.latch(HopBytePair {
            send_bytes,
            receive_bytes,
        });
    }

    fn latch(&self, candidate: HopBytePair) {
        if candidate.smaller() == 0 {
            return;
        }
        let mut held = self
            .coincident
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if candidate.smaller() > held.smaller() {
            *held = candidate;
        }
    }

    /// The pair as it stands now.
    #[must_use]
    pub fn live(&self) -> HopBytePair {
        HopBytePair {
            send_bytes: self.send_bytes.load(Ordering::Relaxed),
            receive_bytes: self.receive_bytes.load(Ordering::Relaxed),
        }
    }

    /// The pair at the instant the smaller of the two was largest.
    #[must_use]
    pub fn coincident(&self) -> HopBytePair {
        *self
            .coincident
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One peer hop that is still open, sampled from the forwarding snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpLiveHopRecord {
    /// `ingress_remote` or `owner_peer`.
    pub role: &'static str,
    pub request_id: Option<String>,
    pub stream_id: Option<u64>,
    /// The hop's send/receive bytes as of this snapshot pass.
    pub live: HopBytePair,
    /// The best-attested coincident pair this hop has reached so far.
    pub coincident: HopBytePair,
    /// The hop's per-direction credit window.
    pub window: usize,
}

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
/// cursors are the attempt's drain proof, read at its commit decision.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpRotationObservation {
    pub stream_id: u64,
    pub operation_id: String,
    pub request_id: Option<String>,
    /// The completed-rotation count this attempt reaches when it completes.
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
    /// The send/receive pair **at one instant**: the moment the smaller of
    /// the hop's two directions was largest.  The two fields above are
    /// independent all-time latches and cannot show simultaneity; this one
    /// can, because it is written as a pair from a single mutation point
    /// (task row M8-C22).
    pub peer_coincident: HopBytePair,
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
    /// Every peer hop still open on this relay, with its live send/receive
    /// pair and its coincident latch.  An observation window shorter than an
    /// exchange sees the hop here; `exchanges` above only gains the hop once
    /// it has terminated.
    pub live_peer_hops: Vec<HttpLiveHopRecord>,
}

/// A registered live hop.  The diagnostics hold only a weak reference, so a
/// hop deregisters itself by being dropped and no teardown path can leak one.
#[derive(Debug)]
struct LiveHopEntry {
    role: &'static str,
    request_id: Option<String>,
    stream_id: Option<u64>,
    window: usize,
    pair: Weak<HopLivePair>,
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
    live_hops: Vec<LiveHopEntry>,
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

    /// Publish one open peer hop's live pair on the snapshot.
    ///
    /// The entry holds a weak reference: when the hop's shared state is
    /// dropped the entry stops resolving and the next snapshot pass removes
    /// it, so there is no deregistration path to forget.
    pub fn register_live_hop(
        &self,
        role: &'static str,
        request_id: Option<String>,
        stream_id: Option<u64>,
        window: usize,
        pair: &Arc<HopLivePair>,
    ) {
        let mut inner = self.lock();
        inner
            .live_hops
            .retain(|entry| entry.pair.strong_count() > 0);
        inner.live_hops.push(LiveHopEntry {
            role,
            request_id,
            stream_id,
            window,
            pair: Arc::downgrade(pair),
        });
    }

    pub fn note_hop_aggregate(&self, send: usize, receive: usize) {
        let mut inner = self.lock();
        inner.hop_aggregate_send_high_water = inner.hop_aggregate_send_high_water.max(send);
        inner.hop_aggregate_receive_high_water =
            inner.hop_aggregate_receive_high_water.max(receive);
    }

    #[must_use]
    pub fn snapshot(&self) -> HttpForwardDiagnosticSnapshot {
        let mut inner = self.lock();
        inner
            .live_hops
            .retain(|entry| entry.pair.strong_count() > 0);
        let live_peer_hops = inner
            .live_hops
            .iter()
            .filter_map(|entry| {
                let pair = entry.pair.upgrade()?;
                Some(HttpLiveHopRecord {
                    role: entry.role,
                    request_id: entry.request_id.clone(),
                    stream_id: entry.stream_id,
                    live: pair.live(),
                    coincident: pair.coincident(),
                    window: entry.window,
                })
            })
            .collect();
        HttpForwardDiagnosticSnapshot {
            live_peer_hops,
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

    /// The property the two independent `max` latches do not have: two
    /// disjoint bursts must not produce a pair, because at no instant were
    /// both directions loaded (task row M8-C22).
    #[test]
    fn disjoint_bursts_latch_no_coincident_pair() {
        let pair = HopLivePair::default();
        // Burst one: the send direction fills and drains, receive idle.
        pair.note_send(190_000);
        pair.note_send(0);
        // Burst two: the receive direction fills and drains, send idle.
        pair.note_receive(190_000);
        pair.note_receive(0);
        assert_eq!(pair.coincident(), HopBytePair::default());
        assert_eq!(pair.coincident().smaller(), 0);
    }

    /// The pair is the instant the *smaller* half is largest, not the two
    /// directions' separate maxima joined afterwards.
    #[test]
    fn coincident_pair_keeps_the_best_attested_instant() {
        let pair = HopLivePair::default();
        // An instant with a large send and a tiny receive.
        pair.note_send(190_000);
        pair.note_receive(10);
        assert_eq!(
            pair.coincident(),
            HopBytePair {
                send_bytes: 190_000,
                receive_bytes: 10,
            }
        );
        // A better-attested instant: both halves substantial.  The smaller
        // half rises from 10 to 40_000, so this one replaces it.
        pair.note_receive(40_000);
        assert_eq!(
            pair.coincident(),
            HopBytePair {
                send_bytes: 190_000,
                receive_bytes: 40_000,
            }
        );
        // The send direction drains.  A fall never latches, and the live
        // reading follows it down while the latch stands.
        pair.note_send(0);
        assert_eq!(
            pair.live(),
            HopBytePair {
                send_bytes: 0,
                receive_bytes: 40_000,
            }
        );
        assert_eq!(pair.coincident().smaller(), 40_000);
        // A larger single direction with a smaller partner does not displace
        // it: 190_000/40_000 is better attested than 200_000/20.
        pair.note_send(200_000);
        pair.note_receive(20);
        assert_eq!(pair.coincident().smaller(), 40_000);
    }

    /// A live hop is published while it exists and disappears with it, so a
    /// window shorter than the exchange can see the hop and a finished one
    /// leaves no stale entry.
    #[test]
    fn live_hops_are_published_then_reaped() {
        let diagnostics = HttpForwardDiagnostics::default();
        let pair = Arc::new(HopLivePair::default());
        pair.note_send(120);
        pair.note_receive(340);
        diagnostics.register_live_hop(
            "owner_peer",
            Some("r-1".to_owned()),
            Some(7),
            196_608,
            &pair,
        );
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.live_peer_hops.len(), 1);
        let hop = &snapshot.live_peer_hops[0];
        assert_eq!(hop.role, "owner_peer");
        assert_eq!(hop.stream_id, Some(7));
        assert_eq!(hop.window, 196_608);
        assert_eq!(hop.live.send_bytes, 120);
        assert_eq!(hop.live.receive_bytes, 340);
        assert_eq!(hop.coincident.smaller(), 120);
        drop(pair);
        assert!(diagnostics.snapshot().live_peer_hops.is_empty());
    }
}
