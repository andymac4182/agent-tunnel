//! Owner-actor support for `http-forward/1` logical streams (implementation
//! gate 3 of docs/http-forwarding.md).
//!
//! An HTTP stream reuses the M2 stream admission, authorization challenge,
//! sequence, replay, rotation-freeze and FORGET machinery of the consumer
//! echo stream.  It differs in four ways:
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

use tokio::sync::watch;
use tunnel_protocol::{ResultDetail, reset_reason};

use super::*;
use crate::http_forward_diagnostics::HttpOwnerStreamRecord;

/// The OPEN operation name for an HTTP forwarding stream.
pub(crate) const HTTP_FORWARD_STREAM_OPERATION: &str = "http_forward";

/// A connector RESET observed by the owner, ahead of ordered delivery.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct HttpPeerReset {
    pub(crate) reason: u16,
    /// The connector's FIN preceded this RESET in sequence order.
    pub(crate) after_fin: bool,
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
    status_tx: watch::Sender<Option<ResultDetail>>,
    recorded: bool,
}

/// The registration an HTTP ingress task receives.
pub(crate) struct HttpStreamRegistration {
    pub(crate) base: ConsumerStreamRegistration,
    pub(crate) peer_reset: watch::Receiver<Option<HttpPeerReset>>,
    pub(crate) result_status: watch::Receiver<Option<ResultDetail>>,
}

impl HttpStreamState {
    pub(crate) fn new() -> (
        Self,
        watch::Receiver<Option<HttpPeerReset>>,
        watch::Receiver<Option<ResultDetail>>,
    ) {
        let (reset_tx, reset_rx) = watch::channel(None);
        let (status_tx, status_rx) = watch::channel(None);
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
                status_tx,
                recorded: false,
            },
            reset_rx,
            status_rx,
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
        self.buffered = buffered;
        self.buffered_high_water = self.buffered_high_water.max(buffered);
        self.chunks.push_back(payload.to_vec());
        if let Some(reader) = self.reader.take() {
            self.serve_parked(reader);
        }
        true
    }

    fn serve_parked(&mut self, reader: oneshot::Sender<HttpRead>) {
        // Data is served on the next explicit read so the credit release and
        // WINDOW_UPDATE happen on the actor's read path; a parked reader is
        // only woken here and immediately re-reads.
        let _ = reader.send(HttpRead::Data(Vec::new()));
    }

    pub(crate) fn accept_fin(&mut self) {
        self.peer_fin = true;
        if let Some(reader) = self.reader.take() {
            self.serve_parked(reader);
        }
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
        let Some(http) = stream.http.as_mut() else {
            let _ = response.send(HttpRead::Closed);
            return;
        };
        if let Some(reason) = http.peer_reset {
            let _ = response.send(HttpRead::Reset(reason));
            return;
        }
        if http.local_reset.is_some() {
            let _ = response.send(HttpRead::Closed);
            return;
        }
        if let Some(chunk) = http.chunks.pop_front() {
            let len = chunk.len();
            http.buffered = http.buffered.saturating_sub(len);
            http.delivered_bytes = http.delivered_bytes.saturating_add(len as u64);
            http.credit_owed = http.credit_owed.saturating_add(len as u64);
            let owed = http.credit_owed;
            release_m2_bytes(&queue_budget, stream, len);
            stream.receive_bytes = stream.receive_bytes.saturating_add(len);
            // Advertise the released credit.  The update is applied to the
            // sequence only once it is queued, so a refused queue slot keeps
            // the debt for the next read instead of recording credit the
            // connector never learns about.
            if let Some(data_tx) = data_tx {
                let current = stream
                    .sequence
                    .direction(Direction::ConnectorToRelay)
                    .receive_credit();
                if let Some(limit) = current.checked_add(owed) {
                    let update = Frame::window_update(epoch, generation, stream_id, limit);
                    let mut candidate = stream.sequence.clone();
                    if candidate
                        .send_frame(Direction::RelayToConnector, &update)
                        .is_ok()
                        && let Ok(encoded) = update.encode()
                        && queue_data(&data_tx, &queue_budget, encoded).is_ok()
                    {
                        stream.sequence = candidate;
                        if let Some(http) = stream.http.as_mut() {
                            http.credit_owed = 0;
                        }
                    }
                }
            }
            let _ = response.send(HttpRead::Data(chunk));
            return;
        }
        if http.peer_fin && !http.fin_delivered {
            http.fin_delivered = true;
            let _ = response.send(HttpRead::Fin);
            return;
        }
        if stream.terminal {
            let _ = response.send(HttpRead::Closed);
            return;
        }
        if let Some(previous) = http.reader.replace(response) {
            let _ = previous.send(HttpRead::Closed);
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

    /// Reset an HTTP stream with a registered reason code.  Parked chunks
    /// were never sequenced and are dropped; the RESET follows everything
    /// already emitted, including an earlier FIN.
    pub(super) fn reset_http_stream(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        operation_id: &str,
        reason: u16,
    ) -> bool {
        let reason = if reset_reason::is_registered(reason) {
            reason
        } else {
            reset_reason::ADAPTER_FAILURE
        };
        let queued = {
            let Some(session) = self.session_mut(key) else {
                return false;
            };
            let frozen = Self::rotation_frozen(session);
            let queue_budget = session.queue_budget.clone();
            let Some(stream) = session.streams.get_mut(&stream_id) else {
                return false;
            };
            if stream.operation_id != operation_id || stream.terminal || stream.open_pending {
                return false;
            }
            let Some(http) = stream.http.as_mut() else {
                return false;
            };
            if http.local_reset.is_some() {
                return true;
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
                return true;
            }
            if frozen {
                // A FIN that was only pending was never sequenced, so the
                // RESET replaces it.
                stream.pending_terminal = Some(Terminal::Reset(reason));
                return true;
            }
            stream.pending_terminal = None;
            let queued = Self::queue_stream_terminal_frame_mode(
                session,
                stream_id,
                Terminal::Reset(reason),
                true,
            );
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
        });
    }
}
