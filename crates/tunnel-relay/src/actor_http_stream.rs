//! Owner-actor support for `http-forward/1` logical streams (implementation
//! gates 3 and 4 of docs/http-forwarding.md).
//!
//! An HTTP stream reuses the M2 stream admission, authorization challenge,
//! sequence, replay, rotation-freeze and FORGET machinery of the consumer
//! echo stream.  It differs in these ways:
//!
//! * DATA carries raw `http-forward/1` record bytes: no length prefix, and a
//!   write resolves when its chunk is sequenced (or parks for send credit or
//!   replay capacity), not when a response record arrives.
//! * The directions are independent half-closes.  A connector FIN only ends
//!   the response direction; the owner neither marks the stream terminal nor
//!   answers it with its own FIN.  The owner's FIN is an explicit request.
//! * Received DATA stays in a per-stream buffer charged to the session
//!   budget until the reader takes it.  WINDOW_UPDATE is issued only then,
//!   so the connector can never have more unread bytes queued here than the
//!   owner's advertised window.
//! * A connector RESET is also published out of band (with whether it
//!   followed the connector's FIN), and a matching `RESULT_STATUS` detail is
//!   retained for the reader.  A close that cannot prove both directions
//!   finished emits `RESET(CANCELLED)`, never a FIN, so truncation can never
//!   look like completion.
//! * Gate 4: the owner follows the record framing of what it sequenced and
//!   what it received (headers only, never payload), publishes its rotation
//!   freeze to the exchange tasks so their progress budgets pause, captures
//!   each HTTP stream's record position when it freezes for a scheduled
//!   rotation, and sends a scoped control `CANCEL` when a local
//!   `RESET(CANCELLED)` has to wait behind that freeze.

use tokio::sync::watch;
use tunnel_http_bridge::{PauseController, PauseSignal};
use tunnel_http_forward::{RecordTracker, TrackerSnapshot};
use tunnel_protocol::{ResultDetail, reset_reason};

use super::*;
use crate::http_forward_diagnostics::{
    HttpForgetRecord, HttpOwnerStreamRecord, HttpRecordPosition, HttpRotationObservation,
    RelayHttpStreamSnapshot,
};

/// The OPEN operation name for an HTTP forwarding stream.
pub(crate) const HTTP_FORWARD_STREAM_OPERATION: &str = "http_forward";

/// The OPEN operation name for a filesystem 9P stream.
///
/// A separate name from `http_forward` although the two share every byte of the
/// carrier machinery: the OPEN names the adapter the connector will run, and a
/// 9P stream announced as an HTTP one would be a lie the connector's own
/// allowlist could not check.
pub(crate) const FS_STREAM_OPERATION: &str = "fs_9p";

/// A connector RESET observed by the owner, ahead of ordered delivery.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct HttpPeerReset {
    pub(crate) reason: u16,
    /// The connector's FIN preceded this RESET in sequence order.
    pub(crate) after_fin: bool,
}

/// Why the **owner actor** tore a stream down, for an ingress that has to
/// name a reason to its consumer.
///
/// This is deliberately **not** a general mirror of `close_session`'s reason
/// string.  A session is torn down for roughly thirty distinct reasons —
/// relay shutdown, an authority outage, an owner fence, a rotation or
/// recovery failure, a queue that refused a frame, a device framing fault —
/// and almost none of them mean "the device went away".  Reporting them all
/// as one thing is how a close code becomes a lie.
///
/// So only the causes an ingress can state **accurately** are carried, and
/// every other reason publishes nothing and keeps whatever close it already
/// had.  A new variant belongs here only with evidence for the claim it
/// would let an ingress make.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum StreamTeardownCause {
    /// The **device's own transport ended**.  The relay is healthy and the
    /// device it was proxying to is not, which is the one thing an ingress may
    /// report as a backend that went away.
    ///
    /// Two teardowns qualify, and they are the two halves of a single event: a
    /// connector that stops closes both of its sockets, and whichever loss the
    /// relay notices first decides the reason.  Control first is
    /// `CONTROL_CLOSED`, from `disconnect_control`.  Data first is a frame
    /// that fails to queue, which tears the session down as
    /// `REVERSE_CHANNEL_UNAVAILABLE` — but **only** with the carrier's sender
    /// actually closed.  That same reason used to be how a queue budget
    /// refusal arrived too, and a budget refusal is the relay declining to
    /// buffer while the device is fine; since M4-37 a backpressure refusal of
    /// a flow-control frame closes as `FLOW_CONTROL_UNDELIVERABLE` instead, and
    /// the sender check is kept as defence in depth.  M4-35 measured the race
    /// at 7 red in 24 gate-9 runs on the measuring host.
    DeviceGone,
}

/// One ordered read result.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum HttpRead {
    Data(Vec<u8>),
    Fin,
    Reset(u16),
    /// The stream is gone or was released locally.
    Closed,
}

/// What the actor does with one read request, decided from stream state
/// alone.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReadStep {
    /// Answer immediately.
    Reply(HttpRead),
    /// Deliver this chunk; its bytes are now owed as receive credit.
    Chunk(Vec<u8>),
    /// Nothing to deliver yet: park the reader.
    Park,
}

/// The owner's record position and holdings when it froze its writer for a
/// scheduled rotation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct HttpFreezeCapture {
    pub(crate) request: TrackerSnapshot,
    pub(crate) request_fin_sequenced: bool,
    pub(crate) response: TrackerSnapshot,
    pub(crate) response_fin_received: bool,
    pub(crate) parked_bytes: usize,
    pub(crate) receive_buffered: usize,
    pub(crate) deferred_terminal: Option<&'static str>,
    pub(crate) frozen_last_emitted: u64,
}

/// Per-stream HTTP state on the owner.
pub(crate) struct HttpStreamState {
    chunks: VecDeque<Vec<u8>>,
    buffered: usize,
    buffered_high_water: usize,
    parked_high_water: usize,
    replay_high_water: usize,
    delivered_bytes: u64,
    /// Receive credit released by reads but not yet advertised because the
    /// data queue refused the WINDOW_UPDATE.
    credit_owed: u64,
    reader: Option<oneshot::Sender<HttpRead>>,
    peer_fin: bool,
    fin_delivered: bool,
    peer_reset: Option<u16>,
    local_fin: bool,
    local_reset: Option<u16>,
    reset_tx: watch::Sender<Option<HttpPeerReset>>,
    /// Why the owner actor tore this stream down, when it is a cause an
    /// ingress may accurately report.  See [`StreamTeardownCause`].
    terminal_tx: watch::Sender<Option<StreamTeardownCause>>,
    status_tx: watch::Sender<Option<ResultDetail>>,
    freeze_tx: PauseController,
    recorded: bool,
    /// Framing of the owner→device bytes actually sequenced.
    request_tracker: RecordTracker,
    /// Framing of the device→owner bytes received in order.
    response_tracker: RecordTracker,
    request_fin_sequenced: bool,
    reset_sequence: Option<(u64, u64)>,
    reset_deferred_by_freeze: bool,
    cancel_sent: bool,
    freeze_capture: Option<HttpFreezeCapture>,
}

/// The watchers an HTTP ingress task receives with its registration.
pub(crate) struct HttpStreamWatchers {
    pub(crate) peer_reset: watch::Receiver<Option<HttpPeerReset>>,
    /// Why the owner actor tore this stream down, when it is a cause an
    /// ingress may accurately report.
    pub(crate) terminal: watch::Receiver<Option<StreamTeardownCause>>,
    pub(crate) result_status: watch::Receiver<Option<ResultDetail>>,
    /// Paused while this owner's writer is frozen for rotation or recovery.
    pub(crate) freeze: PauseSignal,
}

/// The registration an HTTP ingress task receives.
pub(crate) struct HttpStreamRegistration {
    pub(crate) base: ConsumerStreamRegistration,
    pub(crate) peer_reset: watch::Receiver<Option<HttpPeerReset>>,
    /// Why the owner actor tore this stream down, when it is a cause an
    /// ingress may accurately report.
    pub(crate) terminal: watch::Receiver<Option<StreamTeardownCause>>,
    pub(crate) result_status: watch::Receiver<Option<ResultDetail>>,
    pub(crate) freeze: PauseSignal,
}

/// What `reset_http_stream` did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct HttpResetOutcome {
    /// The RESET was queued, deferred in order, or already present.
    pub(crate) accepted: bool,
}

/// Actor-wide HTTP bookkeeping done between commands.
#[derive(Debug, Default)]
pub(crate) struct HttpMaintenance {
    /// Sessions whose required HTTP `CANCEL` could not be queued, collected
    /// where the send was refused and fenced after the command.
    pub(crate) cancel_undeliverable: Vec<SessionKey>,
    /// How many sessions had their HTTP streams visited to re-publish a
    /// freeze transition (a local counter for regression tests).
    pub(crate) freeze_stream_scans: u64,
}

impl HttpStreamState {
    pub(crate) fn new(frozen: bool) -> (Self, HttpStreamWatchers) {
        let (reset_tx, reset_rx) = watch::channel(None);
        let (terminal_tx, terminal_rx) = watch::channel(None);
        let (status_tx, status_rx) = watch::channel(None);
        let freeze_tx = PauseController::new(frozen);
        let freeze_rx = freeze_tx.signal();
        (
            Self {
                chunks: VecDeque::new(),
                buffered: 0,
                buffered_high_water: 0,
                parked_high_water: 0,
                replay_high_water: 0,
                delivered_bytes: 0,
                credit_owed: 0,
                reader: None,
                peer_fin: false,
                fin_delivered: false,
                peer_reset: None,
                local_fin: false,
                local_reset: None,
                reset_tx,
                terminal_tx,
                status_tx,
                freeze_tx,
                recorded: false,
                request_tracker: RecordTracker::new(),
                response_tracker: RecordTracker::new(),
                request_fin_sequenced: false,
                reset_sequence: None,
                reset_deferred_by_freeze: false,
                cancel_sent: false,
                freeze_capture: None,
            },
            HttpStreamWatchers {
                peer_reset: reset_rx,
                terminal: terminal_rx,
                result_status: status_rx,
                freeze: freeze_rx,
            },
        )
    }

    pub(crate) const fn local_terminal(&self) -> bool {
        self.local_fin || self.local_reset.is_some()
    }

    pub(crate) fn mark_local_reset(&mut self, reason: u16) {
        self.local_reset.get_or_insert(reason);
    }

    pub(crate) fn note_parked(&mut self, parked_bytes: usize) {
        self.parked_high_water = self.parked_high_water.max(parked_bytes);
    }

    pub(crate) fn note_replay(&mut self, replay_bytes: usize) {
        self.replay_high_water = self.replay_high_water.max(replay_bytes);
    }

    /// Follow the framing of a chunk that was just sequenced toward the
    /// device.  Only record headers are inspected.
    pub(crate) fn observe_sequenced(&mut self, chunk: &[u8]) {
        self.request_tracker.observe(chunk);
    }

    /// The owner's terminal frame was sequenced on `generation`.
    pub(crate) fn note_terminal_sequenced(
        &mut self,
        terminal: Terminal,
        sequence: u64,
        generation: u64,
    ) {
        match terminal {
            Terminal::Fin => self.request_fin_sequenced = true,
            Terminal::Reset(_) => {
                self.reset_sequence.get_or_insert((sequence, generation));
            }
        }
    }

    /// A RESET was deferred behind the rotation freeze.
    pub(crate) fn note_reset_deferred(&mut self) {
        self.reset_deferred_by_freeze = true;
    }

    /// Whether a local cancellation still needs the device to learn of it
    /// out of band: the device has neither finished nor reset its direction
    /// and no CANCEL was sent yet.
    pub(crate) const fn cancel_needed(&self) -> bool {
        !self.cancel_sent && !self.peer_fin && self.peer_reset.is_none()
    }

    pub(crate) fn note_cancel(&mut self) {
        self.cancel_sent = true;
    }

    /// Publish this owner's writer-freeze state to the exchange task.
    pub(crate) fn publish_freeze(&self, frozen: bool) {
        self.freeze_tx.set(frozen);
    }

    /// Capture the record position at a scheduled rotation freeze.
    pub(crate) fn capture_freeze(
        &mut self,
        parked_bytes: usize,
        pending_terminal: Option<Terminal>,
        last_emitted: u64,
    ) {
        self.freeze_capture = Some(HttpFreezeCapture {
            request: self.request_tracker.snapshot(),
            request_fin_sequenced: self.request_fin_sequenced,
            response: self.response_tracker.snapshot(),
            response_fin_received: self.peer_fin,
            parked_bytes,
            receive_buffered: self.buffered,
            deferred_terminal: terminal_label(pending_terminal),
            frozen_last_emitted: last_emitted,
        });
    }

    pub(crate) fn take_freeze_capture(&mut self) -> Option<HttpFreezeCapture> {
        self.freeze_capture.take()
    }

    /// Whether a close can end this stream with FIN only: the owner already
    /// sent its terminal and the connector finished or reset its direction.
    pub(crate) fn completed(&self) -> bool {
        self.local_terminal() && (self.peer_fin || self.peer_reset.is_some())
    }

    /// Accept one ordered connector DATA payload.  Returns `false` when it
    /// would exceed the advertised window, which the sequence state already
    /// forbids, so a violation is a protocol error.
    pub(crate) fn accept_data(&mut self, payload: &[u8], window: usize) -> bool {
        if payload.is_empty() {
            return true;
        }
        let Some(buffered) = self.buffered.checked_add(payload.len()) else {
            return false;
        };
        if buffered > window {
            return false;
        }
        self.response_tracker.observe(payload);
        self.buffered = buffered;
        self.buffered_high_water = self.buffered_high_water.max(buffered);
        self.chunks.push_back(payload.to_vec());
        self.wake_reader();
        true
    }

    fn wake_reader(&mut self) {
        // Data is served on the next explicit read so the credit release and
        // WINDOW_UPDATE happen on the actor's read path; a parked reader is
        // only woken here and immediately re-reads.
        if let Some(reader) = self.reader.take() {
            let _ = reader.send(HttpRead::Data(Vec::new()));
        }
    }

    pub(crate) fn accept_fin(&mut self) {
        self.peer_fin = true;
        self.wake_reader();
    }

    /// Publish why the owner actor is tearing this stream down, so an ingress
    /// that must name a reason to its consumer can name the right one.
    ///
    /// **Must be called before the stream's `closed` token is cancelled.**
    /// That ordering is the same invariant M4-25 established for the
    /// authorization reset: an ingress woken by the cancellation reads this
    /// slot on its way out, so publishing afterwards would race the reader and
    /// silently degrade the close it produces.
    ///
    /// The first cause wins, matching [`Self::accept_reset`]: a connector
    /// RESET that already explained the stream keeps its explanation.
    pub(crate) fn publish_terminal_cause(&self, cause: StreamTeardownCause) {
        self.terminal_tx.send_if_modified(|slot| {
            if slot.is_some() {
                return false;
            }
            *slot = Some(cause);
            true
        });
    }

    /// Accept the connector RESET: undelivered bytes are discarded (their
    /// charge is returned by the caller) and the reader learns of it.
    pub(crate) fn accept_reset(&mut self, reason: u16) -> usize {
        if self.peer_reset.is_none() {
            self.peer_reset = Some(reason);
            let after_fin = self.peer_fin;
            self.reset_tx
                .send_replace(Some(HttpPeerReset { reason, after_fin }));
        }
        let discarded = self.buffered;
        self.chunks.clear();
        self.buffered = 0;
        if let Some(reader) = self.reader.take() {
            let _ = reader.send(HttpRead::Reset(reason));
        }
        discarded
    }

    pub(crate) fn accept_status(&self, detail: ResultDetail) {
        self.status_tx.send_if_modified(|current| {
            if current.is_some() {
                return false;
            }
            *current = Some(detail);
            true
        });
    }

    /// Decide one read.  A delivered chunk moves its bytes from the buffer
    /// to the owed receive credit; the caller advertises that credit and
    /// calls [`Self::settle_credit`] once the WINDOW_UPDATE is queued.
    pub(crate) fn next_read(&mut self, stream_terminal: bool) -> ReadStep {
        if let Some(reason) = self.peer_reset {
            return ReadStep::Reply(HttpRead::Reset(reason));
        }
        if self.local_reset.is_some() {
            return ReadStep::Reply(HttpRead::Closed);
        }
        if let Some(chunk) = self.chunks.pop_front() {
            let len = chunk.len();
            self.buffered = self.buffered.saturating_sub(len);
            self.delivered_bytes = self.delivered_bytes.saturating_add(len as u64);
            self.credit_owed = self.credit_owed.saturating_add(len as u64);
            return ReadStep::Chunk(chunk);
        }
        if self.peer_fin && !self.fin_delivered {
            self.fin_delivered = true;
            return ReadStep::Reply(HttpRead::Fin);
        }
        if stream_terminal {
            return ReadStep::Reply(HttpRead::Closed);
        }
        ReadStep::Park
    }

    /// Park a reader; a reader it replaces learns the stream closed.
    pub(crate) fn park_reader(&mut self, reader: oneshot::Sender<HttpRead>) {
        if let Some(previous) = self.reader.replace(reader) {
            let _ = previous.send(HttpRead::Closed);
        }
    }

    pub(crate) const fn credit_owed(&self) -> u64 {
        self.credit_owed
    }

    pub(crate) fn settle_credit(&mut self) {
        self.credit_owed = 0;
    }

    #[cfg(test)]
    pub(crate) const fn buffered(&self) -> usize {
        self.buffered
    }

    /// Release everything held for the reader.  Returns the discarded bytes
    /// whose budget charge the caller must return.
    pub(crate) fn release(&mut self) -> usize {
        let discarded = self.buffered;
        self.chunks.clear();
        self.buffered = 0;
        if let Some(reader) = self.reader.take() {
            let _ = reader.send(HttpRead::Closed);
        }
        discarded
    }

    fn live_snapshot(
        &self,
        parked_bytes: usize,
        pending_terminal: Option<Terminal>,
        send_credit: u64,
        sent_bytes: u64,
        frozen: bool,
    ) -> RelayHttpStreamSnapshot {
        RelayHttpStreamSnapshot {
            request: HttpRecordPosition::from(self.request_tracker.snapshot()),
            request_fin_sequenced: self.request_fin_sequenced,
            response: HttpRecordPosition::from(self.response_tracker.snapshot()),
            response_fin_received: self.peer_fin,
            parked_bytes,
            receive_buffered_bytes: self.buffered,
            send_credit,
            sent_bytes,
            deferred_terminal: terminal_label(pending_terminal),
            local_reset: self.local_reset,
            peer_reset: self.peer_reset,
            cancel_sent: self.cancel_sent,
            reset_sequence: self.reset_sequence.map(|(sequence, _)| sequence),
            reset_generation: self.reset_sequence.map(|(_, generation)| generation),
            reset_deferred_by_freeze: self.reset_deferred_by_freeze,
            frozen,
        }
    }
}

const fn terminal_label(terminal: Option<Terminal>) -> Option<&'static str> {
    match terminal {
        Some(Terminal::Fin) => Some("fin"),
        Some(Terminal::Reset(_)) => Some("reset"),
        None => None,
    }
}

impl RelayActor {
    /// Take the next ordered read for an HTTP stream, or park the reader.
    pub(super) fn read_http_stream(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        operation_id: &str,
        response: oneshot::Sender<HttpRead>,
    ) {
        let Some(session) = self.session_mut(key) else {
            let _ = response.send(HttpRead::Closed);
            return;
        };
        let data_tx = session.data_tx.clone();
        let queue_budget = session.queue_budget.clone();
        let generation = session.generation;
        let epoch = session.key.epoch;
        let Some(stream) = session.streams.get_mut(&stream_id) else {
            let _ = response.send(HttpRead::Closed);
            return;
        };
        if stream.operation_id != operation_id {
            let _ = response.send(HttpRead::Closed);
            return;
        }
        let terminal = stream.terminal;
        let Some(http) = stream.http.as_mut() else {
            let _ = response.send(HttpRead::Closed);
            return;
        };
        match http.next_read(terminal) {
            ReadStep::Reply(read) => {
                let _ = response.send(read);
            }
            ReadStep::Park => http.park_reader(response),
            ReadStep::Chunk(chunk) => {
                let len = chunk.len();
                release_m2_bytes(&queue_budget, stream, len);
                stream.receive_bytes = stream.receive_bytes.saturating_add(len);
                // Advertise the released credit.  The update is applied to
                // the sequence only once it is queued, so a refused queue
                // slot -- or no active carrier at all -- keeps the debt
                // instead of recording credit the connector never learns
                // about.  `redrive_owed_http_credit` pays that debt when a
                // carrier is writable again (M4-29).
                if let Some(data_tx) = data_tx {
                    Self::advertise_owed_http_credit(
                        stream,
                        stream_id,
                        &data_tx,
                        &queue_budget,
                        epoch,
                        generation,
                    );
                }
                let _ = response.send(HttpRead::Data(chunk));
            }
        }
    }

    /// Queue one WINDOW_UPDATE carrying every byte of receive credit this
    /// stream's reads have released and not yet advertised.  Returns whether
    /// nothing is owed any more.
    ///
    /// The debt is settled only once the update is queued; the sequence's
    /// advertised credit moves in the same step, so a refusal leaves both the
    /// debt and the credit exactly as they were.
    fn advertise_owed_http_credit(
        stream: &mut M2Stream,
        stream_id: u64,
        data_tx: &mpsc::Sender<DataOutbound>,
        queue_budget: &QueueBudget,
        epoch: u64,
        generation: u64,
    ) -> bool {
        let Some(owed) = stream.http.as_ref().map(HttpStreamState::credit_owed) else {
            return true;
        };
        if owed == 0 {
            return true;
        }
        let current = stream
            .sequence
            .direction(Direction::ConnectorToRelay)
            .receive_credit();
        let Some(limit) = current.checked_add(owed) else {
            return false;
        };
        let update = Frame::window_update(epoch, generation, stream_id, limit);
        let mut candidate = stream.sequence.clone();
        if candidate
            .send_frame(Direction::RelayToConnector, &update)
            .is_ok()
            && let Ok(encoded) = update.encode()
            && queue_flow_control(data_tx, queue_budget, encoded).is_ok()
        {
            stream.sequence = candidate;
            if let Some(http) = stream.http.as_mut() {
                http.settle_credit();
            }
            return true;
        }
        false
    }

    /// Pay receive credit that a read released while it could not be
    /// advertised (task row M4-29).
    ///
    /// A consumer read is the only event that advertises released credit, so
    /// a read taken while the session had **no active data carrier** — the
    /// window between a failed data socket and its retained recovery's
    /// activation — or while the data queue refused the update left a debt
    /// that nothing else would ever pay.  The connector then parks its next
    /// write for want of exactly that credit, the consumer waits for the reply
    /// that write carries, and no further read happens: a deadlock with every
    /// cursor quiesced. Measured, not inferred: in `verify-m4-fs-data-recovery`
    /// the held `Rread` was read with no carrier, 65,541 bytes stayed owed at
    /// activation, and the connector parked a 65,536-byte `Rread` five bytes
    /// short of its credit.
    ///
    /// Called when a carrier becomes the active writer and from the actor
    /// tick; a no-op without an active carrier or with nothing owed.
    pub(super) fn redrive_owed_http_credit(&mut self, key: &SessionKey) {
        let Some(session) = self.session_mut(key) else {
            return;
        };
        let Some(data_tx) = session.data_tx.clone() else {
            return;
        };
        let queue_budget = session.queue_budget.clone();
        let generation = session.generation;
        let epoch = session.key.epoch;
        for (&stream_id, stream) in &mut session.streams {
            if stream.terminal
                || stream
                    .http
                    .as_ref()
                    .is_none_or(|http| http.credit_owed() == 0)
            {
                continue;
            }
            if !Self::advertise_owed_http_credit(
                stream,
                stream_id,
                &data_tx,
                &queue_budget,
                epoch,
                generation,
            ) {
                // The queue refused: keep the remaining debts for the next
                // tick rather than spending more refusals on this one.
                break;
            }
        }
    }

    /// Queue the owner's FIN after every sequenced or parked DATA chunk.
    pub(super) fn finish_http_stream(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        operation_id: &str,
    ) -> bool {
        let queued = {
            let Some(session) = self.session_mut(key) else {
                return false;
            };
            let frozen = Self::rotation_frozen(session);
            let Some(stream) = session.streams.get_mut(&stream_id) else {
                return false;
            };
            if stream.operation_id != operation_id || stream.terminal || stream.open_pending {
                return false;
            }
            let Some(http) = stream.http.as_mut() else {
                return false;
            };
            if http.local_terminal() {
                return false;
            }
            http.local_fin = true;
            if frozen || !stream.pending_records.is_empty() {
                stream.pending_terminal.get_or_insert(Terminal::Fin);
                return true;
            }
            let queued =
                Self::queue_stream_terminal_frame_mode(session, stream_id, Terminal::Fin, true);
            if !queued && let Some(stream) = session.streams.get_mut(&stream_id) {
                stream.terminal_fin_failure = true;
            }
            queued
        };
        if !queued {
            self.arm_terminal_fin_failure_deadline(key);
        }
        queued
    }

    /// Queue a scoped control `CANCEL` for an HTTP stream whose local
    /// cancellation cannot reach the device in order yet.  Returns whether
    /// it entered the bounded control queue.
    pub(super) fn send_http_cancel(session: &mut DeviceSession, stream_id: u64) -> bool {
        let Some(stream) = session.streams.get(&stream_id) else {
            return true;
        };
        let Ok(message) = wire::encode_control_message(&wire::cancel(
            &session.key.session_id,
            session.key.epoch,
            stream_id,
            &stream.operation_id,
        )) else {
            return false;
        };
        let delivered = queue_control(&session.control_tx, &session.queue_budget, message).is_ok();
        if let Some(http) = session
            .streams
            .get_mut(&stream_id)
            .and_then(|stream| stream.http.as_mut())
        {
            http.note_cancel();
        }
        delivered
    }

    /// Send the scoped `CANCEL` a local cancellation needs, when it needs
    /// one, and remember the session for fencing if it could not be queued.
    pub(super) fn cancel_http_if_needed(&mut self, key: &SessionKey, stream_id: u64, reason: u16) {
        let undeliverable = self.session_mut(key).is_some_and(|session| {
            let needed = reason == reset_reason::CANCELLED
                && session
                    .streams
                    .get(&stream_id)
                    .and_then(|stream| stream.http.as_ref())
                    .is_some_and(HttpStreamState::cancel_needed);
            needed && !Self::send_http_cancel(session, stream_id)
        });
        if undeliverable {
            self.http_maintenance.cancel_undeliverable.push(key.clone());
        }
    }

    /// Reset an HTTP stream with a registered reason code.  Parked chunks
    /// were never sequenced and are dropped; the RESET follows everything
    /// already emitted, including an earlier FIN.  A cancellation deferred
    /// behind the rotation freeze is also sent as a control `CANCEL`, so the
    /// device stops promptly while the RESET keeps its sequence position.
    pub(super) fn reset_http_stream(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        operation_id: &str,
        reason: u16,
    ) -> HttpResetOutcome {
        let reason = if reset_reason::is_registered(reason) {
            reason
        } else {
            reset_reason::ADAPTER_FAILURE
        };
        let mut outcome = HttpResetOutcome::default();
        let queued = {
            let Some(session) = self.session_mut(key) else {
                return outcome;
            };
            let frozen = Self::rotation_frozen(session);
            let queue_budget = session.queue_budget.clone();
            let Some(stream) = session.streams.get_mut(&stream_id) else {
                return outcome;
            };
            if stream.operation_id != operation_id || stream.terminal || stream.open_pending {
                return outcome;
            }
            let Some(http) = stream.http.as_mut() else {
                return outcome;
            };
            outcome.accepted = true;
            if http.local_reset.is_some() {
                return outcome;
            }
            http.local_reset = Some(reason);
            let discarded = http.release();
            release_m2_bytes(&queue_budget, stream, discarded);
            let parked = stream.pending_record_bytes;
            stream.pending_record_bytes = 0;
            for (_, waiter) in stream.pending_records.drain(..) {
                let _ = waiter.send(Err(EchoOutcome::Failure {
                    code: "STREAM_RESET",
                    execution: "unknown",
                }));
            }
            release_m2_bytes(&queue_budget, stream, parked);
            let sent_terminal = stream
                .sequence
                .direction(Direction::RelayToConnector)
                .send_terminal();
            if matches!(sent_terminal, Some(Terminal::Reset(_))) {
                return outcome;
            }
            if frozen {
                // A FIN that was only pending was never sequenced, so the
                // RESET replaces it.
                stream.pending_terminal = Some(Terminal::Reset(reason));
                if let Some(http) = stream.http.as_mut() {
                    http.note_reset_deferred();
                }
                true
            } else {
                stream.pending_terminal = None;
                let queued = Self::queue_stream_terminal_frame_mode(
                    session,
                    stream_id,
                    Terminal::Reset(reason),
                    true,
                );
                if !queued && let Some(stream) = session.streams.get_mut(&stream_id) {
                    // Keep the RESET for an ordered retry (every tick while
                    // the failure deadline runs, and on ACK/WINDOW_UPDATE):
                    // a refused writer queue must not strand the device.
                    stream.pending_terminal = Some(Terminal::Reset(reason));
                    stream.terminal_fin_failure = true;
                }
                queued
            }
        };
        if !queued {
            self.arm_terminal_fin_failure_deadline(key);
        }
        // The device must learn of a cancellation that is not on the wire
        // yet — deferred behind a freeze or refused by the writer queue — so
        // it is also sent out of band.
        let deferred = self
            .session_for(key)
            .and_then(|session| session.streams.get(&stream_id))
            .is_some_and(|stream| stream.pending_terminal.is_some());
        if deferred {
            self.cancel_http_if_needed(key, stream_id, reason);
        }
        outcome
    }

    /// Retry the ordered terminals a refused writer queue left pending on a
    /// session whose terminal-failure deadline is running.
    pub(super) fn retry_failed_terminals(&mut self, key: &SessionKey) {
        let stream_ids = self
            .session_for(key)
            .filter(|session| session.terminal_fin_failure_deadline.is_some())
            .map(|session| {
                let mut ids = session
                    .streams
                    .iter()
                    .filter(|(_, stream)| {
                        stream.terminal_fin_failure && stream.pending_terminal.is_some()
                    })
                    .map(|(stream_id, _)| *stream_id)
                    .collect::<Vec<_>>();
                ids.sort_unstable();
                ids
            })
            .unwrap_or_default();
        for stream_id in stream_ids {
            self.flush_pending_terminal(key, stream_id);
        }
    }

    /// Retain the connector's bounded `RESULT_STATUS` detail for the exact
    /// stream and operation.  A status for a forgotten or non-HTTP stream is
    /// a late, bounded message and is ignored.
    pub(super) fn accept_http_result_status(
        &mut self,
        key: &SessionKey,
        status: &tunnel_protocol::ResultStatus,
    ) {
        let Some(session) = self.session_mut(key) else {
            return;
        };
        let Some(stream) = session.streams.get_mut(&status.stream_id) else {
            return;
        };
        if stream.operation_id != status.operation_id {
            return;
        }
        if let (Some(http), Some(detail)) = (stream.http.as_ref(), status.detail.clone()) {
            http.accept_status(detail);
        }
    }

    /// Re-publish one session's writer-freeze state to its HTTP exchange
    /// tasks when, and only when, it changed since the last publication.
    /// Returns whether the session's streams were visited.
    pub(super) fn refresh_session_http_freeze(session: &mut DeviceSession) -> bool {
        let frozen = Self::rotation_frozen(session);
        if frozen == session.http_freeze_published {
            return false;
        }
        session.http_freeze_published = frozen;
        for stream in session.streams.values_mut() {
            if let Some(http) = stream.http.as_ref() {
                http.publish_freeze(frozen);
            }
        }
        true
    }

    /// After one command: re-publish the writer-freeze state of the sessions
    /// that command could have changed (streams are visited only on an actual
    /// freeze transition), and fence any session whose required HTTP
    /// cancellation could not be queued.  Per-frame traffic names its
    /// session, so this is O(1) for it rather than O(devices × streams).
    pub(super) async fn after_command_http_maintenance(&mut self, scope: HttpMaintenanceScope) {
        let visited = match scope {
            HttpMaintenanceScope::None => 0,
            HttpMaintenanceScope::Session(scope) => {
                self.sessions.get_mut(&scope).map_or(0, |session| {
                    usize::from(Self::refresh_session_http_freeze(session))
                })
            }
            HttpMaintenanceScope::All => self
                .sessions
                .values_mut()
                .map(|session| usize::from(Self::refresh_session_http_freeze(session)))
                .sum(),
        };
        self.http_maintenance.freeze_stream_scans = self
            .http_maintenance
            .freeze_stream_scans
            .saturating_add(visited as u64);
        if self.http_maintenance.cancel_undeliverable.is_empty() {
            return;
        }
        let mut undeliverable = std::mem::take(&mut self.http_maintenance.cancel_undeliverable);
        undeliverable.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        undeliverable.dedup();
        for key in undeliverable {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = "http_cancel_undeliverable",
                "HTTP CANCEL could not enter the control queue; fencing the session"
            );
            self.close_session(&key, CANCEL_UNDELIVERABLE).await;
        }
    }

    /// Capture each HTTP stream's record position as the owner freezes its
    /// writer at QUIESCE.
    pub(super) fn capture_http_freeze(session: &mut DeviceSession) {
        for stream in session.streams.values_mut() {
            let last_emitted = stream
                .sequence
                .direction(Direction::RelayToConnector)
                .last_emitted();
            let parked = stream.pending_record_bytes;
            let pending_terminal = stream.pending_terminal;
            if let Some(http) = stream.http.as_mut() {
                http.capture_freeze(parked, pending_terminal, last_emitted);
            }
        }
    }

    /// Turn the captured positions into rotation observations at the
    /// commit decision, adding the fences and acknowledgement cursors.
    pub(super) fn record_http_rotation_observations(
        session: &mut DeviceSession,
        completed: Option<&RelayRotationSnapshot>,
        rotation: u64,
        diagnostics: &HttpForwardDiagnostics,
    ) {
        let find = |pairs: Option<&Vec<(u64, u64)>>, stream_id: u64| {
            pairs.and_then(|pairs| {
                pairs
                    .iter()
                    .find(|(id, _)| *id == stream_id)
                    .map(|(_, value)| *value)
            })
        };
        let attempt = completed.and_then(|snapshot| snapshot.attempt.clone());
        for (stream_id, stream) in &mut session.streams {
            let Some(capture) = stream
                .http
                .as_mut()
                .and_then(HttpStreamState::take_freeze_capture)
            else {
                continue;
            };
            diagnostics.record_rotation(HttpRotationObservation {
                stream_id: *stream_id,
                operation_id: stream.operation_id.clone(),
                request_id: stream.request_id.clone(),
                rotation,
                rotation_id: attempt
                    .as_ref()
                    .map(|attempt| attempt.rotation_id.clone())
                    .unwrap_or_default(),
                old_generation: attempt.as_ref().map_or(0, |attempt| attempt.old_generation),
                new_generation: attempt.as_ref().map_or(0, |attempt| attempt.new_generation),
                request: HttpRecordPosition::from(capture.request),
                request_fin_sequenced: capture.request_fin_sequenced,
                response: HttpRecordPosition::from(capture.response),
                response_fin_received: capture.response_fin_received,
                parked_bytes: capture.parked_bytes,
                receive_buffered_bytes: capture.receive_buffered,
                deferred_terminal: capture.deferred_terminal,
                frozen_last_emitted: capture.frozen_last_emitted,
                relay_fence: find(
                    completed.map(|snapshot| &snapshot.relay_fence_sequences),
                    *stream_id,
                ),
                connector_fence: find(
                    completed.map(|snapshot| &snapshot.connector_fence_sequences),
                    *stream_id,
                ),
                relay_acknowledged: find(
                    completed.map(|snapshot| &snapshot.relay_ack_sequences),
                    *stream_id,
                ),
                connector_acknowledged: find(
                    completed.map(|snapshot| &snapshot.connector_ack_sequences),
                    *stream_id,
                ),
            });
        }
    }

    /// Record that the owner published `STREAM_FORGET` for an HTTP stream.
    pub(super) fn record_http_forget(stream: &M2Stream, diagnostics: &HttpForwardDiagnostics) {
        if stream.http.is_some() {
            diagnostics.record_forget(HttpForgetRecord {
                stream_id: stream.sequence.stream_id(),
                operation_id: stream.operation_id.clone(),
                request_id: stream.request_id.clone(),
            });
        }
    }

    /// The live, payload-free HTTP view of one stream for the snapshot.
    pub(super) fn http_stream_snapshot(
        stream: &M2Stream,
        frozen: bool,
    ) -> Option<RelayHttpStreamSnapshot> {
        let http = stream.http.as_ref()?;
        let send = stream.sequence.direction(Direction::RelayToConnector);
        Some(http.live_snapshot(
            stream.pending_record_bytes,
            stream.pending_terminal,
            send.send_credit(),
            send.sent_bytes(),
            frozen,
        ))
    }

    /// Record the owner stream's bounded high-water marks once, when the
    /// stream is released.
    pub(super) fn record_http_owner_stream(
        stream: &mut M2Stream,
        diagnostics: &HttpForwardDiagnostics,
    ) {
        let snapshot = stream.sequence.snapshot();
        let sent = snapshot.direction(Direction::RelayToConnector);
        let Some(http) = stream.http.as_mut() else {
            return;
        };
        if http.recorded {
            return;
        }
        http.recorded = true;
        let (release, reset_reason) = match (http.local_reset, http.peer_reset) {
            (Some(reason), _) | (None, Some(reason)) => ("reset", Some(reason)),
            (None, None) if http.local_fin && http.peer_fin => ("fin", None),
            _ => ("closed", None),
        };
        diagnostics.record_owner_stream(HttpOwnerStreamRecord {
            stream_id: stream.sequence.stream_id(),
            operation_id: stream.operation_id.clone(),
            request_id: stream.request_id.clone(),
            receive_buffer_high_water: http.buffered_high_water,
            receive_window: wire::M2_INITIAL_WINDOW_BYTES,
            parked_bytes_high_water: http.parked_high_water,
            replay_bytes_high_water: http.replay_high_water,
            sent_bytes: sent.sent_bytes,
            delivered_bytes: http.delivered_bytes,
            release,
            reset_reason,
            request: HttpRecordPosition::from(http.request_tracker.snapshot()),
            response: HttpRecordPosition::from(http.response_tracker.snapshot()),
            reset_sequence: http.reset_sequence.map(|(sequence, _)| sequence),
            reset_generation: http.reset_sequence.map(|(_, generation)| generation),
            reset_deferred_by_freeze: http.reset_deferred_by_freeze,
            cancel_sent: http.cancel_sent,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_http_forward::{END_RECORD, RecordKind, RecordPosition, encode_body};

    const WINDOW: usize = 131_072;

    fn state() -> (HttpStreamState, HttpStreamWatchers) {
        HttpStreamState::new(false)
    }

    #[test]
    fn received_data_is_bounded_by_the_window_and_owes_credit_only_when_read() {
        let (mut http, _) = state();
        assert!(http.accept_data(&[1; 100_000], WINDOW));
        assert!(http.accept_data(&[2; 31_072], WINDOW));
        // One byte above the advertised window is a protocol violation and
        // is not buffered.
        assert!(!http.accept_data(&[3; 1], WINDOW));
        assert_eq!(http.buffered(), WINDOW);
        assert_eq!(http.credit_owed(), 0, "receipt never releases credit");
        let ReadStep::Chunk(chunk) = http.next_read(false) else {
            panic!("expected a chunk");
        };
        assert_eq!(chunk.len(), 100_000);
        assert_eq!(http.buffered(), 31_072);
        assert_eq!(http.credit_owed(), 100_000);
        // A refused WINDOW_UPDATE keeps the debt; the next read adds to it.
        let ReadStep::Chunk(_) = http.next_read(false) else {
            panic!("expected a chunk");
        };
        assert_eq!(http.credit_owed(), WINDOW as u64);
        http.settle_credit();
        assert_eq!(http.credit_owed(), 0);
        assert_eq!(http.next_read(false), ReadStep::Park);
    }

    #[test]
    fn response_fin_is_a_half_close_delivered_after_buffered_bytes() {
        let (mut http, _) = state();
        let (reader, mut parked) = oneshot::channel();
        http.park_reader(reader);
        assert!(http.accept_data(b"abc", WINDOW));
        assert_eq!(parked.try_recv(), Ok(HttpRead::Data(Vec::new())), "woken");
        http.accept_fin();
        assert!(!http.completed(), "the owner has not finished its side");
        assert!(matches!(http.next_read(false), ReadStep::Chunk(_)));
        assert_eq!(http.next_read(false), ReadStep::Reply(HttpRead::Fin));
        // FIN is delivered once; a released stream then reads as closed.
        assert_eq!(http.next_read(false), ReadStep::Park);
        assert_eq!(http.next_read(true), ReadStep::Reply(HttpRead::Closed));
        http.local_fin = true;
        assert!(http.completed());
    }

    #[test]
    fn reset_after_fin_is_published_with_its_order_and_discards_unread_bytes() {
        let (mut http, watchers) = state();
        assert!(http.accept_data(&[9; 500], WINDOW));
        http.accept_fin();
        assert_eq!(http.accept_reset(reset_reason::CANCELLED), 500);
        assert_eq!(
            *watchers.peer_reset.borrow(),
            Some(HttpPeerReset {
                reason: reset_reason::CANCELLED,
                after_fin: true
            })
        );
        // A second RESET keeps the first observation.
        assert_eq!(http.accept_reset(reset_reason::ADAPTER_FAILURE), 0);
        assert_eq!(
            watchers.peer_reset.borrow().map(|reset| reset.reason),
            Some(reset_reason::CANCELLED)
        );
        assert_eq!(
            http.next_read(false),
            ReadStep::Reply(HttpRead::Reset(reset_reason::CANCELLED))
        );
        assert!(!http.cancel_needed(), "the device already reset");
    }

    #[test]
    fn a_parked_reader_learns_of_reset_and_release_exactly_once() {
        let (mut http, _) = state();
        let (first, mut first_rx) = oneshot::channel();
        http.park_reader(first);
        let (second, mut second_rx) = oneshot::channel();
        http.park_reader(second);
        assert_eq!(first_rx.try_recv(), Ok(HttpRead::Closed), "replaced");
        assert_eq!(http.accept_reset(reset_reason::ADAPTER_FAILURE), 0);
        assert_eq!(
            second_rx.try_recv(),
            Ok(HttpRead::Reset(reset_reason::ADAPTER_FAILURE))
        );
        let (mut http, _) = state();
        assert!(http.accept_data(&[1; 10], WINDOW));
        let (reader, mut reader_rx) = oneshot::channel();
        http.park_reader(reader);
        // Terminal discard: release returns the charge of unread bytes.
        assert_eq!(http.release(), 10);
        assert_eq!(reader_rx.try_recv(), Ok(HttpRead::Closed));
        assert_eq!(http.release(), 0);
    }

    #[test]
    fn a_local_reset_closes_reads_and_status_keeps_the_first_detail() {
        let (mut http, watchers) = state();
        http.mark_local_reset(reset_reason::CANCELLED);
        http.mark_local_reset(reset_reason::ADAPTER_FAILURE);
        assert_eq!(http.local_reset, Some(reset_reason::CANCELLED));
        assert_eq!(http.next_read(false), ReadStep::Reply(HttpRead::Closed));
        http.accept_status(ResultDetail {
            code: "HTTP_CANCELLED".into(),
            execution: "dispatched".into(),
        });
        http.accept_status(ResultDetail {
            code: "HTTP_BODY_LIMIT".into(),
            execution: "unknown".into(),
        });
        assert_eq!(
            watchers
                .result_status
                .borrow()
                .as_ref()
                .map(|detail| detail.code.as_str()),
            Some("HTTP_CANCELLED")
        );
    }

    #[test]
    fn freeze_publication_and_capture_record_the_exact_position() {
        let (mut http, watchers) = HttpStreamState::new(false);
        let mut request = Vec::new();
        let head = tunnel_http_forward::RecordHeader::new(RecordKind::RequestHead, 2)
            .expect("head")
            .encode();
        request.extend_from_slice(&head);
        request.extend_from_slice(b"{}");
        encode_body(&[5; 40], &mut request);
        // Sequenced: HEAD plus the BODY header and 10 payload bytes.
        http.observe_sequenced(&request[..10 + 8 + 10]);
        assert!(http.accept_data(&END_RECORD[..3], WINDOW));
        http.publish_freeze(true);
        assert!(watchers.freeze.is_paused());
        http.capture_freeze(30, Some(Terminal::Reset(reset_reason::CANCELLED)), 7);
        let capture = http.take_freeze_capture().expect("captured");
        assert_eq!(capture.request.heads, 1);
        assert_eq!(capture.request.bodies, 1);
        assert_eq!(
            capture.request.position,
            RecordPosition::Payload {
                kind: RecordKind::Body,
                received: 10,
                total: 40
            }
        );
        assert_eq!(
            capture.response.position,
            RecordPosition::Header { received: 3 }
        );
        assert_eq!(capture.parked_bytes, 30);
        assert_eq!(capture.receive_buffered, 3);
        assert_eq!(capture.deferred_terminal, Some("reset"));
        assert_eq!(capture.frozen_last_emitted, 7);
        assert!(http.take_freeze_capture().is_none(), "taken once");
        http.publish_freeze(false);
        assert!(!watchers.freeze.is_paused());
    }

    #[test]
    fn deferred_terminal_bookkeeping_and_cancel_are_one_shot() {
        let (mut http, _) = state();
        assert!(http.cancel_needed());
        http.note_reset_deferred();
        http.note_cancel();
        assert!(!http.cancel_needed(), "at most one CANCEL per stream");
        http.note_terminal_sequenced(Terminal::Fin, 4, 1);
        http.note_terminal_sequenced(Terminal::Reset(reset_reason::CANCELLED), 5, 2);
        http.note_terminal_sequenced(Terminal::Reset(reset_reason::CANCELLED), 6, 3);
        let snapshot = http.live_snapshot(0, None, 0, 0, false);
        assert!(snapshot.request_fin_sequenced);
        assert_eq!(snapshot.reset_sequence, Some(5));
        assert_eq!(snapshot.reset_generation, Some(2));
        assert!(snapshot.reset_deferred_by_freeze);
        assert!(snapshot.cancel_sent);
        // A device that already finished needs no cancellation.
        let (mut finished, _) = state();
        finished.accept_fin();
        assert!(!finished.cancel_needed());
    }
}
