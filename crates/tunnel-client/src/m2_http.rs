//! Connector-actor support for `http-forward/1` streams.
//!
//! The actor stays the only owner of each stream's sequence, credit and
//! authorization state; the exchange task (see [`crate::http_forward`]) only
//! asks it to read, write, finish or reset.
//!
//! * Received DATA is buffered per stream (charged to the retained budget)
//!   and released to the reader one chunk at a time.  Its WINDOW_UPDATE is
//!   issued only then, so unread bytes never exceed the advertised window.
//! * The request FIN half-closes only the request direction: the connector
//!   answers with its own FIN only when the handler's response completes.
//! * A write that does not fit the stream's send credit or replay capacity
//!   (or arrives while writes are frozen for rotation) parks in the actor and
//!   is retried when an ACK or WINDOW_UPDATE arrives, instead of failing the
//!   session.
//! * A local RESET first sends bounded `RESULT_STATUS` detail on the control
//!   socket, then queues the RESET (which may follow the connector's FIN).
//! * Gate 4: the actor publishes its writer freeze to the exchange task so
//!   the bridge's progress budgets pause for it, follows the record framing
//!   of the received request (headers only) for the device record log, and
//!   turns an owner's control `CANCEL` into a prompt out-of-band cancellation
//!   whose ordered RESET and `RESULT_STATUS` the bridge then emits.

use tunnel_http_bridge::{
    HANDOFF_CAPACITY, PauseController, QueueStats, RecordTracker, ResetNotifier, SignaledReset,
    channel, detail_from_reason, pump_inbound, pump_outbound, reset_signal_pair, serve_paused,
};
use tunnel_protocol::{ResultDetail, ResultStatus};

use super::*;
use crate::http_forward::{
    DeviceHttpExchangeRecord, DeviceRead, DeviceReader, DeviceWriter, HttpActorRequest, HttpExport,
};

/// The OPEN operation name for an HTTP forwarding stream.
pub(super) const HTTP_FORWARD_OPERATION: &str = "http_forward";

/// The OPEN operation name for a filesystem 9P stream (M4 gate 4).
///
/// It must match the relay's `FS_STREAM_OPERATION` exactly: the connector's
/// own allowlist check is what makes an OPEN naming an adapter this device
/// does not serve a refusal rather than a surprise.
pub(super) const FS_STREAM_OPERATION: &str = "fs_9p";

/// Per-stream HTTP state held by the connector actor.
pub(super) struct DeviceHttpState {
    chunks: VecDeque<Vec<u8>>,
    buffered: usize,
    buffered_high_water: usize,
    fin_ready: bool,
    fin_delivered: bool,
    peer_reset: Option<u16>,
    reader: Option<oneshot::Sender<DeviceRead>>,
    notifier: ResetNotifier,
    parked: Option<(Vec<u8>, oneshot::Sender<bool>)>,
    parked_high_water: usize,
    finish_after_parked: Option<oneshot::Sender<bool>>,
    receive_window: u64,
    /// This connector's writer freeze, observed by the bridge's clocks.
    freeze: PauseController,
    /// Framing of the owner→device bytes received in order.
    request_tracker: RecordTracker,
    pub(super) cancel_received: bool,
    task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for DeviceHttpState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceHttpState")
            .field("buffered", &self.buffered)
            .field("fin_ready", &self.fin_ready)
            .field("peer_reset", &self.peer_reset)
            .field("parked", &self.parked.as_ref().map(|(data, _)| data.len()))
            .finish_non_exhaustive()
    }
}

impl Drop for DeviceHttpState {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// What the actor does with one read request, decided from stream state.
#[derive(Debug)]
pub(super) enum DeviceReadStep {
    Reply(DeviceRead),
    /// Deliver this chunk; the caller releases its receive credit.
    Chunk(Vec<u8>),
    Park,
}

/// The capacity facts one parked-write decision depends on.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct WriteRoom {
    pub(super) writes_frozen: bool,
    pub(super) pending_output: bool,
    pub(super) sent_bytes: u64,
    pub(super) send_credit: u64,
    pub(super) replay_bytes: usize,
    pub(super) max_replay_bytes: usize,
    pub(super) replay_frames: usize,
    pub(super) max_replay_frames: usize,
    pub(super) retained_capacity: bool,
}

impl WriteRoom {
    /// Whether one chunk of `len` bytes can be sequenced now: writes are not
    /// frozen for rotation, nothing for this stream waits ahead of it, and it
    /// fits the send credit, the replay bytes and frames, and the retained
    /// budget.
    pub(super) fn fits(&self, len: usize) -> bool {
        let frames = len.div_ceil(MAX_PAYLOAD_LEN).max(1);
        !self.writes_frozen
            && !self.pending_output
            && self
                .sent_bytes
                .checked_add(len as u64)
                .is_some_and(|sent| sent <= self.send_credit)
            && self
                .replay_bytes
                .checked_add(len)
                .is_some_and(|bytes| bytes <= self.max_replay_bytes)
            && self
                .replay_frames
                .checked_add(frames)
                .is_some_and(|count| count <= self.max_replay_frames)
            && self.retained_capacity
    }
}

impl DeviceHttpState {
    pub(super) fn new(
        notifier: ResetNotifier,
        receive_window: u64,
        freeze: PauseController,
        task: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            chunks: VecDeque::new(),
            buffered: 0,
            buffered_high_water: 0,
            fin_ready: false,
            fin_delivered: false,
            peer_reset: None,
            reader: None,
            notifier,
            parked: None,
            parked_high_water: 0,
            finish_after_parked: None,
            receive_window,
            freeze,
            request_tracker: RecordTracker::new(),
            cancel_received: false,
            task,
        }
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.buffered
            .saturating_add(self.parked.as_ref().map_or(0, |(data, _)| data.len()))
    }

    fn wake_reader(&mut self) {
        if let Some(reader) = self.reader.take() {
            // An empty chunk only wakes the reader, which re-reads.
            let _ = reader.send(DeviceRead::Data(Vec::new()));
        }
    }

    /// Accept a peer or local RESET: unread bytes are dropped, the reader
    /// learns of it, and a stalled handler is signalled out of band.
    fn abort(&mut self, reason: u16, after_fin: bool) {
        if self.peer_reset.is_none() {
            self.peer_reset = Some(reason);
            self.notifier.notify(SignaledReset {
                detail: detail_from_reason(reason),
                after_fin,
            });
        }
        self.chunks.clear();
        self.buffered = 0;
        if let Some(reader) = self.reader.take() {
            let _ = reader.send(DeviceRead::Reset(reason));
        }
        if let Some((_, reply)) = self.parked.take() {
            let _ = reply.send(false);
        }
        if let Some(reply) = self.finish_after_parked.take() {
            let _ = reply.send(false);
        }
    }

    /// Accept one ordered request payload for the reader.
    fn accept_payload(&mut self, payload: Vec<u8>) {
        if payload.is_empty() || self.peer_reset.is_some() {
            return;
        }
        self.request_tracker.observe(&payload);
        self.buffered = self.buffered.saturating_add(payload.len());
        self.buffered_high_water = self.buffered_high_water.max(self.buffered);
        self.chunks.push_back(payload);
        self.wake_reader();
    }

    /// The request FIN: delivered after every buffered chunk.
    fn accept_fin(&mut self) {
        self.fin_ready = true;
        self.wake_reader();
    }

    /// Decide one read (authorization checks are the actor's).
    fn next_read(&mut self) -> DeviceReadStep {
        if let Some(reason) = self.peer_reset {
            return DeviceReadStep::Reply(DeviceRead::Reset(reason));
        }
        if let Some(chunk) = self.chunks.pop_front() {
            self.buffered = self.buffered.saturating_sub(chunk.len());
            return DeviceReadStep::Chunk(chunk);
        }
        if self.fin_ready && !self.fin_delivered {
            self.fin_delivered = true;
            return DeviceReadStep::Reply(DeviceRead::Fin);
        }
        DeviceReadStep::Park
    }

    fn park_reader(&mut self, reply: oneshot::Sender<DeviceRead>) {
        if let Some(previous) = self.reader.replace(reply) {
            let _ = previous.send(DeviceRead::Closed);
        }
    }

    /// Whether a new write may be accepted at all: nothing is parked ahead
    /// of it and the stream was not reset.
    const fn accepts_write(&self) -> bool {
        self.parked.is_none() && self.finish_after_parked.is_none() && self.peer_reset.is_none()
    }

    fn park_write(&mut self, data: Vec<u8>, reply: oneshot::Sender<bool>) {
        self.parked_high_water = self.parked_high_water.max(data.len());
        self.parked = Some((data, reply));
    }

    fn parked_len(&self) -> Option<usize> {
        self.parked.as_ref().map(|(data, _)| data.len())
    }

    fn take_parked(&mut self) -> Option<(Vec<u8>, oneshot::Sender<bool>)> {
        self.parked.take()
    }

    /// Defer a FIN behind the parked write.  Returns the reply back when no
    /// write is parked, so the caller emits the FIN now.
    fn defer_finish(&mut self, reply: oneshot::Sender<bool>) -> Option<oneshot::Sender<bool>> {
        if self.parked.is_some() {
            self.finish_after_parked = Some(reply);
            None
        } else {
            Some(reply)
        }
    }

    fn take_deferred_finish(&mut self) -> Option<oneshot::Sender<bool>> {
        self.finish_after_parked.take()
    }

    /// Publish this connector's writer-freeze state to the exchange task.
    pub(super) fn publish_freeze(&self, frozen: bool) {
        self.freeze.set(frozen);
    }
}

impl M2Stream {
    pub(super) fn is_http(&self) -> bool {
        self.http.is_some()
    }

    /// An HTTP exchange whose response FIN is sequenced and whose request
    /// FIN was received in order has nothing left to authorize: no request
    /// byte can follow, and the handler's response is complete.  Expiring
    /// its authorization would only emit a RESET after the FIN while the
    /// owner, having seen both terminals, is already reclaiming the stream —
    /// a RESET the owner never acknowledges, so the connector could never
    /// prove the owner's STREAM_FORGET.  `response_fin_deferred` reports a
    /// response FIN already retained for the carrier behind a writer freeze
    /// or a full queue: it follows every response byte in order, so the
    /// exchange is settled just the same.
    pub(super) fn http_exchange_settled(&self, response_fin_deferred: bool) -> bool {
        if !self.is_http() || !(self.output_fin || response_fin_deferred) || self.output_reset {
            return false;
        }
        let received = self.sequence.direction(Direction::RelayToConnector);
        matches!(
            received.receive_terminal(),
            Some(tunnel_protocol::Terminal::Fin)
        ) && received.receive_terminal_sequence() == Some(received.recv_contiguous())
    }
}

impl M2Actor {
    /// Whether this HTTP exchange is settled (see
    /// [`M2Stream::http_exchange_settled`]), counting a response FIN that is
    /// retained for the carrier but not yet sequenced.
    pub(super) fn http_stream_settled(&self, stream_id: u64) -> bool {
        let fin_deferred = self
            .pending_outputs
            .iter()
            .any(|output| output.stream_id == stream_id && output.kind == FrameKind::Fin);
        self.streams
            .get(&stream_id)
            .is_some_and(|stream| stream.http_exchange_settled(fin_deferred))
    }

    /// Build the HTTP state for an admitted stream and start its exchange
    /// task.  The handler is only invoked after a validated request head,
    /// which can only arrive after the stream's authorization is confirmed.
    pub(super) fn start_http_exchange(
        &self,
        stream_id: u64,
        service_id: &str,
        export: HttpExport,
        receive_window: u64,
    ) -> DeviceHttpState {
        let (notifier, signal) = reset_signal_pair();
        let (request_tx, request_rx, request_handoff) = channel(HANDOFF_CAPACITY);
        let (response_tx, response_rx, response_handoff) = channel(HANDOFF_CAPACITY);
        let sink = self.http_requests.clone();
        let reader = DeviceReader {
            sink: sink.clone(),
            stream_id,
            signal,
            pending: None,
        };
        let writer = DeviceWriter {
            sink: sink.clone(),
            stream_id,
        };
        let body_stats: Arc<std::sync::Mutex<Option<Arc<QueueStats>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let slot = Arc::clone(&body_stats);
        let handler = Arc::clone(&export.handler);
        let service_id = service_id.to_owned();
        let deadline = Duration::from_millis(self.config.limits.operation_timeout_ms);
        let config = export
            .config
            .with_deadline(export.config.deadline().min(deadline))
            .unwrap_or(export.config);
        let profile = export.profile;
        let freeze = PauseController::new(self.writes_frozen);
        let pause = freeze.signal();
        let task = tokio::spawn(async move {
            let serving = serve_paused(
                profile,
                config,
                request_rx,
                response_tx,
                pause,
                move |request| {
                    *slot
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(request.body().stats());
                    handler.call(request)
                },
            );
            let (report, _, _) = tokio::join!(
                serving,
                pump_outbound(response_rx, writer),
                pump_inbound(reader, request_tx),
            );
            let request_body_high_water = body_stats
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map_or(0, |stats| stats.high_water());
            let record = DeviceHttpExchangeRecord {
                stream_id,
                service_id,
                request_handoff_high_water: request_handoff.high_water(),
                response_handoff_high_water: response_handoff.high_water(),
                request_body_high_water,
                report: Some(report),
                ..DeviceHttpExchangeRecord::default()
            };
            let _ = sink.send(HttpActorRequest::Done { record }).await;
        });
        DeviceHttpState::new(notifier, receive_window, freeze, Some(task))
    }

    /// Build the state for an admitted filesystem stream and start its 9P
    /// exchange task.
    ///
    /// Deliberately the **same** carrier state as an HTTP exchange: the
    /// connector's buffering, credit release, parked writes, independent
    /// half-closes and terminal handling are properties of a raw bidirectional
    /// logical stream, not of HTTP, and duplicating them for 9P would mean two
    /// implementations of the rules `docs/protocol.md` states once. What differs
    /// is only the task: `tunnel_fs_provider` replaces the HTTP bridge.
    pub(super) fn start_fs_exchange(
        &self,
        stream_id: u64,
        export: crate::fs_export::FsExport,
        grant: tunnel_fs_core::CapabilitySet,
        authority: std::sync::Arc<crate::fs_export::StreamAuthority>,
        receive_window: u64,
    ) -> DeviceHttpState {
        let (notifier, signal) = reset_signal_pair();
        let (request_tx, request_rx, _request_handoff) = channel(HANDOFF_CAPACITY);
        let (response_tx, response_rx, _response_handoff) = channel(HANDOFF_CAPACITY);
        let sink = self.http_requests.clone();
        let reader = DeviceReader {
            sink: sink.clone(),
            stream_id,
            signal,
            pending: None,
        };
        let writer = DeviceWriter {
            sink: sink.clone(),
            stream_id,
        };
        let freeze = PauseController::new(self.writes_frozen);
        let task = tokio::spawn(async move {
            let (report, _, _) = tokio::join!(
                crate::fs_export::serve(export, grant, authority, request_rx, response_tx),
                pump_outbound(response_rx, writer),
                pump_inbound(reader, request_tx),
            );
            // The exchange record is shaped for HTTP heads and has nothing to
            // hold for a 9P stream — **except the report**, which is the only
            // path the provider's mutation ledger has to the actor and so to a
            // status snapshot. An earlier round of this gate discarded it here,
            // which left the whole outcome ledger recorded nowhere a running
            // binary could read.
            let record = DeviceHttpExchangeRecord {
                stream_id,
                fs: Some(Box::new(report)),
                ..DeviceHttpExchangeRecord::default()
            };
            let _ = sink.send(HttpActorRequest::Done { record }).await;
        });
        DeviceHttpState::new(notifier, receive_window, freeze, Some(task))
    }

    /// Publish the writer freeze to every HTTP exchange; called after each
    /// actor event, so a progress clock pauses for exactly the freeze.
    pub(super) fn publish_http_freeze(&self) {
        for stream in self.streams.values() {
            if let Some(http) = stream.http.as_ref() {
                http.publish_freeze(self.writes_frozen);
            }
        }
    }

    pub(super) async fn handle_http_request(
        &mut self,
        request: HttpActorRequest,
    ) -> Result<(), ClientError> {
        match request {
            HttpActorRequest::Read { stream_id, reply } => self.http_read(stream_id, reply).await,
            HttpActorRequest::Write {
                stream_id,
                data,
                reply,
            } => self.http_write(stream_id, data, reply).await,
            HttpActorRequest::Finish { stream_id, reply } => {
                self.http_finish(stream_id, reply).await
            }
            HttpActorRequest::Reset {
                stream_id,
                reason,
                outcome,
                code,
                execution,
                reply,
            } => {
                self.http_reset(stream_id, reason, outcome, code, execution)
                    .await?;
                let _ = reply.send(true);
                Ok(())
            }
            HttpActorRequest::Done { mut record } => {
                if let Some(http) = self
                    .streams
                    .get(&record.stream_id)
                    .and_then(|stream| stream.http.as_ref())
                {
                    record.receive_buffer_high_water = http.buffered_high_water;
                    record.parked_bytes_high_water = http.parked_high_water;
                    record.receive_window = http.receive_window;
                    let request = http.request_tracker.snapshot();
                    record.request_heads = request.heads;
                    record.request_bodies = request.bodies;
                    record.request_ends = request.ends;
                    record.request_body_bytes = request.body_bytes;
                    record.request_fin_received = http.fin_ready;
                    record.request_framing_invalid = request.invalid;
                    record.cancel_received = http.cancel_received;
                }
                if let Some(fs) = record.fs.as_ref() {
                    // Folded into the session total here and nowhere else, so
                    // the ledger is published in every status snapshot from
                    // this point on. Counters only; nothing here can carry a
                    // path, a name or a byte of content.
                    self.fs_counters.absorb(&fs.stats);
                    self.publish_status();
                }
                self.http_handlers.diagnostics().record(record);
                Ok(())
            }
        }
    }

    async fn http_read(
        &mut self,
        stream_id: u64,
        reply: oneshot::Sender<DeviceRead>,
    ) -> Result<(), ClientError> {
        let active_key = self.active.key.clone();
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            let _ = reply.send(DeviceRead::Closed);
            return Ok(());
        };
        let expired = stream.auth.confirmed
            && stream
                .auth
                .deadline
                .min(stream.auth.operation_deadline)
                .expired();
        let invalidated = stream.auth.invalidated;
        let input_reset = stream.input_reset;
        let Some(http) = stream.http.as_mut() else {
            let _ = reply.send(DeviceRead::Closed);
            return Ok(());
        };
        if let Some(reason) = http.peer_reset {
            let _ = reply.send(DeviceRead::Reset(reason));
            return Ok(());
        }
        if expired {
            // Authorization is checked before every chunk reaches the
            // handler; an expired stream is reset, never read further.
            let _ = reply.send(DeviceRead::Closed);
            return self.expire_stream(stream_id).await;
        }
        if invalidated || input_reset {
            let _ = reply.send(DeviceRead::Reset(M2_RESET_PROTOCOL));
            return Ok(());
        }
        match http.next_read() {
            DeviceReadStep::Reply(read) => {
                let _ = reply.send(read);
            }
            DeviceReadStep::Park => http.park_reader(reply),
            DeviceReadStep::Chunk(chunk) => {
                let len = chunk.len();
                let _ = reply.send(DeviceRead::Data(chunk));
                self.defer_window_update(&active_key, stream_id, len)?;
                self.flush_pending_carrier_controls_for_key(&active_key)?;
                self.publish_status();
            }
        }
        Ok(())
    }

    /// The room one HTTP chunk has now.
    fn http_write_room(&self, stream_id: u64, len: usize) -> Option<WriteRoom> {
        let stream = self.streams.get(&stream_id)?;
        let direction = stream.sequence.direction(Direction::ConnectorToRelay);
        let limits = direction.limits();
        Some(WriteRoom {
            writes_frozen: self.writes_frozen,
            pending_output: has_pending_output_for_stream(&self.pending_outputs, stream_id),
            sent_bytes: direction.sent_bytes(),
            send_credit: direction.send_credit(),
            replay_bytes: direction.replay_bytes(),
            max_replay_bytes: limits.max_replay_bytes,
            replay_frames: direction.replay_len(),
            max_replay_frames: limits.max_replay_frames,
            retained_capacity: self.ensure_bulk_retained_capacity(len).is_ok(),
        })
    }

    fn http_write_fits(&self, stream_id: u64, len: usize) -> bool {
        self.http_write_room(stream_id, len)
            .is_some_and(|room| room.fits(len))
    }

    async fn http_write(
        &mut self,
        stream_id: u64,
        data: Vec<u8>,
        reply: oneshot::Sender<bool>,
    ) -> Result<(), ClientError> {
        let writable = self.streams.get(&stream_id).is_some_and(|stream| {
            stream
                .http
                .as_ref()
                .is_some_and(DeviceHttpState::accepts_write)
                && !stream.output_fin
                && !stream.output_reset
                && !stream.reset_queued
        });
        if !writable {
            let _ = reply.send(false);
            return Ok(());
        }
        if self.http_write_fits(stream_id, data.len()) {
            self.emit_payload(stream_id, data).await?;
            let _ = reply.send(true);
            return Ok(());
        }
        if let Some(http) = self
            .streams
            .get_mut(&stream_id)
            .and_then(|stream| stream.http.as_mut())
        {
            http.park_write(data, reply);
        }
        self.publish_status();
        Ok(())
    }

    /// Retry a parked write (and a FIN waiting behind it) after credit, ACK
    /// or a writer thaw may have made room.
    pub(super) async fn retry_http_parked(&mut self, stream_id: u64) -> Result<(), ClientError> {
        let Some(len) = self
            .streams
            .get(&stream_id)
            .and_then(|stream| stream.http.as_ref())
            .and_then(DeviceHttpState::parked_len)
        else {
            return Ok(());
        };
        if !self.http_write_fits(stream_id, len) {
            return Ok(());
        }
        let Some((data, reply)) = self
            .streams
            .get_mut(&stream_id)
            .and_then(|stream| stream.http.as_mut())
            .and_then(DeviceHttpState::take_parked)
        else {
            return Ok(());
        };
        self.emit_payload(stream_id, data).await?;
        let _ = reply.send(true);
        let finish = self
            .streams
            .get_mut(&stream_id)
            .and_then(|stream| stream.http.as_mut())
            .and_then(DeviceHttpState::take_deferred_finish);
        if let Some(reply) = finish {
            self.http_emit_fin(stream_id).await?;
            let _ = reply.send(true);
        }
        Ok(())
    }

    /// Retry every parked HTTP write; called from the actor tick.
    pub(super) async fn retry_all_http_parked(&mut self) -> Result<(), ClientError> {
        let parked = self
            .streams
            .iter()
            .filter(|(_, stream)| {
                stream
                    .http
                    .as_ref()
                    .is_some_and(|http| http.parked.is_some())
            })
            .map(|(stream_id, _)| *stream_id)
            .collect::<Vec<_>>();
        for stream_id in parked {
            self.retry_http_parked(stream_id).await?;
        }
        Ok(())
    }

    async fn http_emit_fin(&mut self, stream_id: u64) -> Result<(), ClientError> {
        self.emit_or_defer(PendingOutput {
            stream_id,
            kind: FrameKind::Fin,
            payload: Vec::new(),
            reset_reason: None,
        })
        .await
    }

    async fn http_finish(
        &mut self,
        stream_id: u64,
        reply: oneshot::Sender<bool>,
    ) -> Result<(), ClientError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            let _ = reply.send(false);
            return Ok(());
        };
        if stream.output_fin || stream.output_reset || stream.reset_queued {
            let _ = reply.send(false);
            return Ok(());
        }
        let Some(http) = stream.http.as_mut() else {
            let _ = reply.send(false);
            return Ok(());
        };
        let Some(reply) = http.defer_finish(reply) else {
            return Ok(());
        };
        self.http_emit_fin(stream_id).await?;
        let _ = reply.send(true);
        Ok(())
    }

    async fn http_reset(
        &mut self,
        stream_id: u64,
        reason: u16,
        outcome: &'static str,
        code: &'static str,
        execution: &'static str,
    ) -> Result<(), ClientError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        let operation_id = stream.operation_id.clone();
        let after_fin = stream.input_fin;
        if let Some(http) = stream.http.as_mut() {
            http.abort(reason, after_fin);
        }
        if stream.output_reset || stream.reset_queued {
            return Ok(());
        }
        // RESULT_STATUS first, on the control socket, so the owner can
        // correlate the detail with the RESET that follows on data.
        let status = ControlMessage::ResultStatus(ResultStatus::new(
            message_id(),
            self.session.session_id.clone(),
            self.session.epoch,
            stream_id,
            operation_id,
            outcome,
            Some(ResultDetail {
                code: code.to_owned(),
                execution: execution.to_owned(),
            }),
        ));
        self.send_critical_control(status, None)?;
        self.emit_or_defer(PendingOutput {
            stream_id,
            kind: FrameKind::Reset,
            payload: Vec::new(),
            reset_reason: Some(reason),
        })
        .await
    }

    /// An owner control `CANCEL` for an HTTP stream: stop the handler at
    /// once, out of band.  The bridge then emits the stream's ordered RESET
    /// with its `RESULT_STATUS` (dispatch knowledge included) through
    /// [`Self::http_reset`].  Returns `true` when the exchange task already
    /// ended, so the caller must emit the RESET itself.
    pub(super) fn http_cancel(&mut self, stream_id: u64) -> bool {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return false;
        };
        let after_fin = stream.input_fin;
        let Some(http) = stream.http.as_mut() else {
            return false;
        };
        http.cancel_received = true;
        http.abort(tunnel_protocol::reset_reason::CANCELLED, after_fin);
        http.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Deliver post-authorization request DATA to the HTTP reader.
    pub(super) fn http_dispatch_payload(&mut self, stream_id: u64, payload: Vec<u8>) {
        if let Some(http) = self
            .streams
            .get_mut(&stream_id)
            .and_then(|stream| stream.http.as_mut())
        {
            http.accept_payload(payload);
        }
    }

    /// The request FIN half-closes only the request direction.
    pub(super) fn http_dispatch_fin(&mut self, stream_id: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.input_fin = true;
            if let Some(http) = stream.http.as_mut() {
                http.accept_fin();
            }
        }
    }

    /// Record a peer or local RESET on an HTTP stream.
    pub(super) fn http_abort(&mut self, stream_id: u64, reason: u16) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let after_fin = stream.input_fin
                || stream
                    .pending
                    .iter()
                    .any(|input| matches!(input, BufferedInput::Fin));
            if let Some(http) = stream.http.as_mut() {
                http.abort(reason, after_fin);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_http_bridge::ResetSignal;
    use tunnel_protocol::reset_reason;

    fn state() -> (DeviceHttpState, ResetSignal, ()) {
        let (notifier, signal) = reset_signal_pair();
        let freeze = PauseController::new(false);
        (
            DeviceHttpState::new(notifier, 131_072, freeze, None),
            signal,
            (),
        )
    }

    fn room() -> WriteRoom {
        WriteRoom {
            writes_frozen: false,
            pending_output: false,
            sent_bytes: 0,
            send_credit: 131_072,
            replay_bytes: 0,
            max_replay_bytes: 131_072,
            replay_frames: 0,
            max_replay_frames: 4,
            retained_capacity: true,
        }
    }

    #[test]
    fn a_write_parks_for_freeze_ordering_credit_replay_and_budget() {
        assert!(room().fits(65_536));
        assert!(room().fits(131_072));
        let cases: [(&str, WriteRoom, usize); 6] = [
            (
                "frozen for rotation",
                WriteRoom {
                    writes_frozen: true,
                    ..room()
                },
                1,
            ),
            (
                "an output for this stream waits ahead",
                WriteRoom {
                    pending_output: true,
                    ..room()
                },
                1,
            ),
            (
                "send credit",
                WriteRoom {
                    sent_bytes: 131_000,
                    ..room()
                },
                73,
            ),
            (
                "replay bytes",
                WriteRoom {
                    replay_bytes: 131_000,
                    ..room()
                },
                73,
            ),
            (
                "replay frames",
                WriteRoom {
                    replay_frames: 4,
                    ..room()
                },
                1,
            ),
            (
                "retained budget",
                WriteRoom {
                    retained_capacity: false,
                    ..room()
                },
                1,
            ),
        ];
        for (name, room, len) in cases {
            assert!(!room.fits(len), "{name} must park the write");
        }
        // A thaw alone makes the frozen write fit again.
        assert!(
            WriteRoom {
                writes_frozen: false,
                ..room()
            }
            .fits(1)
        );
    }

    #[test]
    fn the_request_fin_is_a_half_close_delivered_after_buffered_chunks() {
        let (mut http, _, _) = state();
        let (reader, mut woken) = oneshot::channel();
        http.park_reader(reader);
        http.accept_payload(b"head".to_vec());
        assert!(matches!(woken.try_recv(), Ok(DeviceRead::Data(data)) if data.is_empty()));
        http.accept_fin();
        assert!(matches!(http.next_read(), DeviceReadStep::Chunk(chunk) if chunk == b"head"));
        assert!(matches!(
            http.next_read(),
            DeviceReadStep::Reply(DeviceRead::Fin)
        ));
        assert!(matches!(http.next_read(), DeviceReadStep::Park));
        // The response direction is untouched: a write is still accepted.
        assert!(http.accepts_write());
    }

    #[test]
    fn a_reset_after_fin_is_signalled_in_order_and_discards_unread_bytes() {
        let (mut http, signal, _) = state();
        http.accept_payload(vec![1; 300]);
        http.accept_fin();
        let (reader, mut reset) = oneshot::channel();
        http.park_reader(reader);
        // Parked reader is woken, then the reset arrives.
        let _ = reset.try_recv();
        let (reader, mut reset) = oneshot::channel();
        http.park_reader(reader);
        http.abort(reset_reason::CANCELLED, true);
        assert!(matches!(
            reset.try_recv(),
            Ok(DeviceRead::Reset(reset_reason::CANCELLED))
        ));
        assert_eq!(http.retained_bytes(), 0, "terminal discard releases bytes");
        assert!(matches!(
            http.next_read(),
            DeviceReadStep::Reply(DeviceRead::Reset(reset_reason::CANCELLED))
        ));
        // A second RESET keeps the first signal.
        http.abort(reset_reason::ADAPTER_FAILURE, false);
        let mut signal = signal;
        let observed = futures_util::FutureExt::now_or_never(signal.wait()).expect("signalled");
        assert!(observed.after_fin);
        assert_eq!(observed.detail.code.as_str(), "HTTP_CANCELLED");
        // No later payload is buffered after the reset.
        http.accept_payload(vec![2; 10]);
        assert_eq!(http.retained_bytes(), 0);
    }

    #[test]
    fn a_fin_waits_behind_a_parked_write_and_a_reset_fails_both() {
        let (mut http, _, _) = state();
        let (write, mut write_rx) = oneshot::channel();
        http.park_write(vec![9; 1_000], write);
        assert!(!http.accepts_write(), "one parked write at a time");
        assert_eq!(http.retained_bytes(), 1_000);
        let (finish, mut finish_rx) = oneshot::channel();
        assert!(http.defer_finish(finish).is_none(), "FIN deferred");
        // The retry path takes the write, then the deferred FIN, in order.
        let (data, reply) = http.take_parked().expect("parked");
        assert_eq!(data.len(), 1_000);
        let _ = reply.send(true);
        assert!(matches!(write_rx.try_recv(), Ok(true)));
        let reply = http.take_deferred_finish().expect("deferred finish");
        let _ = reply.send(true);
        assert!(matches!(finish_rx.try_recv(), Ok(true)));
        // With nothing parked a FIN is emitted at once.
        let (finish, _) = oneshot::channel();
        assert!(http.defer_finish(finish).is_some());
        // A reset fails a parked write and a deferred FIN.
        let (mut http, _, _) = state();
        let (write, mut write_rx) = oneshot::channel();
        http.park_write(vec![1; 10], write);
        let (finish, mut finish_rx) = oneshot::channel();
        assert!(http.defer_finish(finish).is_none());
        http.abort(reset_reason::ADAPTER_FAILURE, false);
        assert!(matches!(write_rx.try_recv(), Ok(false)));
        assert!(matches!(finish_rx.try_recv(), Ok(false)));
        assert!(!http.accepts_write());
    }

    #[test]
    fn the_request_record_log_counts_heads_bodies_and_end_without_payload() {
        let (mut http, _, _) = state();
        let head = [0x01, 0, 0, 0, 0, 0, 0, 2, b'{', b'}'];
        http.accept_payload(head[..5].to_vec());
        http.accept_payload(head[5..].to_vec());
        http.accept_payload(vec![0x03, 0, 0, 0, 0, 0, 0, 3, 7, 7, 7]);
        http.accept_payload(vec![0x04, 0, 0, 0, 0, 0, 0, 0]);
        let snapshot = http.request_tracker.snapshot();
        assert_eq!((snapshot.heads, snapshot.bodies, snapshot.ends), (1, 1, 1));
        assert_eq!(snapshot.body_bytes, 3);
    }

    #[test]
    fn the_freeze_is_published_to_the_exchange_clock() {
        let (notifier, _) = reset_signal_pair();
        let freeze = PauseController::new(false);
        let signal = freeze.signal();
        let http = DeviceHttpState::new(notifier, 1, freeze, None);
        http.publish_freeze(true);
        assert!(signal.is_paused());
        http.publish_freeze(false);
        assert!(!signal.is_paused());
    }

    fn http_stream(state: Option<DeviceHttpState>) -> M2Stream {
        let started = Instant::now();
        let deadline = DualDeadline::new(started, SystemTime::now(), Duration::from_secs(1))
            .expect("test deadline");
        M2Stream {
            export: crate::ExportConfig::default(),
            operation_id: "operation".to_owned(),
            service_id: "service".to_owned(),
            operation: HTTP_FORWARD_OPERATION.to_owned(),
            auth: AuthContext {
                challenge_id: "challenge".to_owned(),
                nonce: "nonce".to_owned(),
                permission_digest: "permission".to_owned(),
                grant_revision: 1,
                deadline,
                operation_deadline: deadline,
                confirmed: true,
                refresh_in_flight: false,
                invalidated: false,
            },
            sequence: StreamState::new(1, 1024).expect("test sequence"),
            pending: VecDeque::new(),
            pending_bytes: 0,
            record_buffer: Vec::new(),
            record_expected: None,
            input_fin: false,
            input_reset: false,
            output_fin: false,
            output_reset: false,
            reset_queued: false,
            http: state,
            fs_authority: None,
        }
    }

    #[test]
    fn only_an_exchange_with_both_fins_is_settled_for_authorization() {
        let (http, _, ()) = state();
        let mut stream = http_stream(Some(http));
        assert!(!stream.http_exchange_settled(false), "nothing ended yet");
        let fin = Frame::fin(1, 1, 1, 1, 0);
        stream
            .sequence
            .receive_frame(Direction::RelayToConnector, &fin)
            .expect("request FIN");
        assert!(
            !stream.http_exchange_settled(false),
            "the response is still running and its writes need authorization"
        );
        assert!(
            stream.http_exchange_settled(true),
            "a response FIN retained behind a freeze settles the exchange too"
        );
        stream.output_fin = true;
        assert!(stream.http_exchange_settled(false));
        let mut upload = http_stream(Some(state().0));
        upload.output_fin = true;
        assert!(
            !upload.http_exchange_settled(false),
            "the request FIN has not arrived: request bytes may still need authorization"
        );
        stream.output_reset = true;
        assert!(
            !stream.http_exchange_settled(false),
            "a reset exchange is not settled"
        );

        let mut echo = http_stream(None);
        echo.output_fin = true;
        echo.sequence
            .receive_frame(Direction::RelayToConnector, &fin)
            .expect("request FIN");
        assert!(!echo.http_exchange_settled(false), "only HTTP streams");
    }
}
