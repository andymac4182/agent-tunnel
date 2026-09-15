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

use tunnel_http_bridge::{
    HANDOFF_CAPACITY, QueueStats, ResetNotifier, SignaledReset, channel, detail_from_reason,
    pump_inbound, pump_outbound, reset_signal_pair, serve,
};
use tunnel_protocol::{ResultDetail, ResultStatus};

use super::*;
use crate::http_forward::{
    DeviceHttpExchangeRecord, DeviceRead, DeviceReader, DeviceWriter, HttpActorRequest, HttpExport,
};

/// The OPEN operation name for an HTTP forwarding stream.
pub(super) const HTTP_FORWARD_OPERATION: &str = "http_forward";

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

impl DeviceHttpState {
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
}

impl M2Stream {
    pub(super) fn is_http(&self) -> bool {
        self.http.is_some()
    }
}

impl M2Actor {
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
        let task = tokio::spawn(async move {
            let serving = serve(profile, config, request_rx, response_tx, move |request| {
                *slot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(request.body().stats());
                handler.call(request)
            });
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
        DeviceHttpState {
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
            task: Some(task),
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
        if let Some(chunk) = http.chunks.pop_front() {
            let len = chunk.len();
            http.buffered = http.buffered.saturating_sub(len);
            let _ = reply.send(DeviceRead::Data(chunk));
            self.defer_window_update(&active_key, stream_id, len)?;
            self.flush_pending_carrier_controls_for_key(&active_key)?;
            self.publish_status();
            return Ok(());
        }
        if http.fin_ready && !http.fin_delivered {
            http.fin_delivered = true;
            let _ = reply.send(DeviceRead::Fin);
            return Ok(());
        }
        if let Some(previous) = http.reader.replace(reply) {
            let _ = previous.send(DeviceRead::Closed);
        }
        Ok(())
    }

    /// Whether one HTTP chunk can be sequenced now without exceeding the
    /// stream's send credit, replay capacity or the retained budget.
    fn http_write_fits(&self, stream_id: u64, len: usize) -> bool {
        let Some(stream) = self.streams.get(&stream_id) else {
            return false;
        };
        if self.writes_frozen || has_pending_output_for_stream(&self.pending_outputs, stream_id) {
            return false;
        }
        let direction = stream.sequence.direction(Direction::ConnectorToRelay);
        let limits = direction.limits();
        let frames = len.div_ceil(MAX_PAYLOAD_LEN).max(1);
        direction
            .sent_bytes()
            .checked_add(len as u64)
            .is_some_and(|sent| sent <= direction.send_credit())
            && direction
                .replay_bytes()
                .checked_add(len)
                .is_some_and(|bytes| bytes <= limits.max_replay_bytes)
            && direction
                .replay_len()
                .checked_add(frames)
                .is_some_and(|count| count <= limits.max_replay_frames)
            && self.ensure_bulk_retained_capacity(len).is_ok()
    }

    async fn http_write(
        &mut self,
        stream_id: u64,
        data: Vec<u8>,
        reply: oneshot::Sender<bool>,
    ) -> Result<(), ClientError> {
        let writable = self.streams.get(&stream_id).is_some_and(|stream| {
            stream.http.as_ref().is_some_and(|http| {
                http.parked.is_none()
                    && http.finish_after_parked.is_none()
                    && http.peer_reset.is_none()
            }) && !stream.output_fin
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
            http.parked_high_water = http.parked_high_water.max(data.len());
            http.parked = Some((data, reply));
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
            .and_then(|http| http.parked.as_ref())
            .map(|(data, _)| data.len())
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
            .and_then(|http| http.parked.take())
        else {
            return Ok(());
        };
        self.emit_payload(stream_id, data).await?;
        let _ = reply.send(true);
        let finish = self
            .streams
            .get_mut(&stream_id)
            .and_then(|stream| stream.http.as_mut())
            .and_then(|http| http.finish_after_parked.take());
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
        if http.parked.is_some() {
            http.finish_after_parked = Some(reply);
            return Ok(());
        }
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

    /// Deliver post-authorization request DATA to the HTTP reader.
    pub(super) fn http_dispatch_payload(&mut self, stream_id: u64, payload: Vec<u8>) {
        if let Some(http) = self
            .streams
            .get_mut(&stream_id)
            .and_then(|stream| stream.http.as_mut())
        {
            if payload.is_empty() || http.peer_reset.is_some() {
                return;
            }
            http.buffered = http.buffered.saturating_add(payload.len());
            http.buffered_high_water = http.buffered_high_water.max(http.buffered);
            http.chunks.push_back(payload);
            http.wake_reader();
        }
    }

    /// The request FIN half-closes only the request direction.
    pub(super) fn http_dispatch_fin(&mut self, stream_id: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.input_fin = true;
            if let Some(http) = stream.http.as_mut() {
                http.fin_ready = true;
                http.wake_reader();
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
