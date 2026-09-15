//! `http-forward/1` over the real relay path (implementation gate 3 of
//! docs/http-forwarding.md).
//!
//! ```text
//! consumer ─HTTP─▶ ingress Axum route ─bridge `forward`─▶ handoff
//!     ─▶ peer HTTP/3 hop (credited) ─▶ owner handoff ─▶ owner actor stream
//!     ─▶ device data WebSocket ─▶ connector `serve` ─▶ in-process handler
//! ```
//!
//! * The public route verifies the consumer's bearer token and grant for the
//!   `http-forward` export exactly as the echo routes do, then removes
//!   `authorization` and `cookie` before the head is normalized.  Every
//!   other credential, forwarded-identity or `x-agent-tunnel-*` field still
//!   fails closed in the codec.  The raw token reaches only the owner, inside
//!   the authenticated peer envelope, for independent verification.
//! * An owner-local ingress drives the owner actor stream directly
//!   ([`ActorWriter`] / [`ActorReader`]).  A non-owner ingress opens the
//!   existing `/internal/v1/streams` peer route with the HTTP grant scope and
//!   carries tunnel DATA/FIN/RESET inside `ConsumerChunk` records.  That hop
//!   has its own byte and record credit ([`PEER_HOP_WINDOW_BYTES`],
//!   [`PEER_HOP_WINDOW_RECORDS`]): a sender never has more encoded bytes in
//!   flight than the receiver has consumed plus the window, and each side
//!   reads continuously, so CREDIT and RESET are never stuck behind a slow
//!   body.
//! * The owner relays the peer hop and its actor stream through two
//!   handoffs.  It assigns every tunnel sequence and applies credit, and it
//!   re-validates both record directions against its own copy of the export
//!   profile before forwarding a chunk ([`owner_relay`]); the ingress and the
//!   device validate independently.
//! * Gate 4: a public request whose head fails normalization is refused
//!   before any route, peer stream or tunnel stream is opened; the owner
//!   relays its rotation freeze to the ingress over the hop (`PAUSE`), so
//!   both bridge adapters' progress budgets pause for exactly that freeze;
//!   and every HTTP hop to one peer shares a per-direction aggregate byte
//!   bound ([`aggregate`]).
//! * A RESET carries the protocol's registered reason code.  The device's
//!   bounded `RESULT_STATUS` detail is correlated on the owner and carried to
//!   the ingress in the peer RESET record, so the ingress gateway status and
//!   execution knowledge match the device's authoritative record.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;

use bytes::Bytes;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tunnel_http_bridge::{
    BridgeConfig, CarrierClosed, CarrierEvent, CarrierReader, CarrierWriter, ExchangeReport,
    Execution, HANDOFF_CAPACITY, OutboundEnd, Outcome, PauseController, PauseSignal, Profile,
    QueueStats, ResetDetail, ResetNotifier, ResetSignal, SignaledReset, channel,
    detail_from_reason, detail_from_status, forward_paused, pump_inbound, pump_outbound,
    rejection_response, reset_reason_for, reset_signal_pair,
};
use tunnel_http_forward::HttpErrorCode;
use tunnel_protocol::{ResultDetail, reset_reason};

use super::*;
use crate::actor::{HttpPeerReset, HttpRead, HttpStreamRegistration};
use crate::http_forward_diagnostics::{HttpExchangeRecord, HttpForwardDiagnostics};

mod aggregate;
mod hold;
mod owner_relay;

pub use aggregate::HOP_AGGREGATE_BYTES;
pub(crate) use aggregate::{HopAggregate, HopAggregates};
pub use hold::{HttpRelayHoldPoint, HttpRelayInterposer};
use owner_relay::{OwnerRequestWriter, OwnerResponseWriter, OwnerVerdict};

/// The peer hop's per-direction window, in encoded record bytes: three
/// maximum records, inside the 256 KiB per-stream peer budget.
pub const PEER_HOP_WINDOW_BYTES: usize = 196_608;
/// The peer hop's per-direction window, in records.
pub const PEER_HOP_WINDOW_RECORDS: usize = 64;
/// How long a reader waits for the device's `RESULT_STATUS` after its RESET
/// arrived first on the other socket.
const RESULT_STATUS_GRACE: Duration = Duration::from_millis(500);
/// How long the other direction may keep draining after one direction of a
/// relayed exchange reset or lost its carrier.
const RELAY_TERMINAL_GRACE: Duration = Duration::from_secs(2);
/// The eight-byte peer record prefix charged with each hop record.
const PEER_PREFIX_LEN: usize = 8;
const MAX_HOP_DATA: usize = MAX_CONSUMER_PEER_BODY - 1;

const TAG_DATA: u8 = 1;
const TAG_FIN: u8 = 2;
const TAG_RESET: u8 = 3;
const TAG_CREDIT: u8 = 4;
const TAG_PAUSE: u8 = 5;

/// One `http-forward/1` application profile a relay can serve: the
/// profile's policies and the bridge limits.
#[derive(Clone)]
pub struct HttpForwardExport {
    pub profile: Arc<Profile>,
    pub config: BridgeConfig,
    /// Set only when selected from [`HttpForwardExports`] that carry a
    /// fixture interposer.
    interposer: Option<Arc<dyn HttpRelayInterposer>>,
}

impl HttpForwardExport {
    #[must_use]
    pub fn new(profile: Arc<Profile>, config: BridgeConfig) -> Self {
        Self {
            profile,
            config,
            interposer: None,
        }
    }

    /// Whether a fixture interposer is attached (test evidence only).
    #[must_use]
    pub fn has_interposer(&self) -> bool {
        self.interposer.is_some()
    }
}

impl core::fmt::Debug for HttpForwardExport {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HttpForwardExport")
            .field("config", &self.config)
            .field("interposer", &self.interposer.is_some())
            .finish_non_exhaustive()
    }
}

/// The catalog service capability naming a service's `http-forward/1`
/// profile: `{"http_forward_profile": "mcp-2026-07-28"}`.  The capability is
/// part of the Redis service record, written by the operator's catalog
/// provisioning, never by a consumer.
pub const HTTP_FORWARD_PROFILE_CAPABILITY: &str = "http_forward_profile";

/// The longest profile identifier.
pub const MAX_PROFILE_ID_LEN: usize = 64;

/// The profiles a relay serves, keyed by profile identifier (gate 5).
///
/// Every public request and every owner-side peer stream selects its profile
/// from the resolved catalog service record's
/// [`HTTP_FORWARD_PROFILE_CAPABILITY`].  A service without the capability,
/// or naming a profile this relay does not serve, is refused as not found
/// before its head is normalized, a route is resolved or any stream opens.
#[derive(Clone, Default)]
pub struct HttpForwardExports {
    exports: std::collections::BTreeMap<String, HttpForwardExport>,
    interposer: Option<Arc<dyn HttpRelayInterposer>>,
}

impl core::fmt::Debug for HttpForwardExports {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HttpForwardExports")
            .field("profiles", &self.exports.keys().collect::<Vec<_>>())
            .field("interposer", &self.interposer.is_some())
            .finish()
    }
}

impl HttpForwardExports {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve `export` for services whose capability names `id`.
    ///
    /// # Errors
    /// An identifier that is empty, longer than [`MAX_PROFILE_ID_LEN`], not
    /// lowercase ASCII letters, digits, `-`, `.` or `_`, or already present.
    pub fn with_profile(
        mut self,
        id: impl Into<String>,
        export: HttpForwardExport,
    ) -> Result<Self, &'static str> {
        let id = id.into();
        if id.is_empty()
            || id.len() > MAX_PROFILE_ID_LEN
            || !id.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'.' | b'_')
            })
        {
            return Err(
                "http-forward profile identifiers are 1..=64 lowercase letters, digits, '-', '.' or '_'",
            );
        }
        if self.exports.contains_key(&id) {
            return Err("an http-forward profile is configured twice");
        }
        self.exports.insert(id, export);
        Ok(self)
    }

    /// Attach a fixture interposer to the owner relay of every profile.
    /// Test infrastructure only: no implementation exists in this crate and
    /// the `serve` binary never calls this.
    #[doc(hidden)]
    #[must_use]
    pub fn with_fixture_interposer(mut self, interposer: Arc<dyn HttpRelayInterposer>) -> Self {
        self.interposer = Some(interposer);
        self
    }

    /// Whether any profile is served.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exports.is_empty()
    }

    /// The served profile identifiers.
    pub fn profile_ids(&self) -> impl Iterator<Item = &str> {
        self.exports.keys().map(String::as_str)
    }

    /// Whether a fixture interposer is attached.
    #[must_use]
    pub fn has_fixture_interposer(&self) -> bool {
        self.interposer.is_some()
    }

    /// The export selected by a service record's capabilities.
    #[must_use]
    pub fn select(&self, capabilities: &serde_json::Value) -> Option<HttpForwardExport> {
        let id = capabilities
            .get(HTTP_FORWARD_PROFILE_CAPABILITY)?
            .as_str()?;
        let mut export = self.exports.get(id)?.clone();
        export.interposer = self.interposer.clone();
        Some(export)
    }
}

// ---------------------------------------------------------------------------
// Owner actor carriers.

/// Writes DATA/FIN/RESET to the owner actor's logical stream.
pub(crate) struct ActorWriter {
    handle: RelayHandle,
    key: SessionKey,
    stream_id: u64,
    operation_id: String,
}

impl CarrierWriter for ActorWriter {
    fn data(&mut self, data: Bytes) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        let handle = self.handle.clone();
        let key = self.key.clone();
        let stream_id = self.stream_id;
        let operation_id = self.operation_id.clone();
        async move {
            handle
                .write_http_stream(key, stream_id, operation_id, data.to_vec())
                .await
                .map_err(|error| {
                    tracing::debug!(error = ?error, phase = "http_forward_actor_write");
                    CarrierClosed
                })
        }
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        let handle = self.handle.clone();
        let key = self.key.clone();
        let stream_id = self.stream_id;
        let operation_id = self.operation_id.clone();
        async move {
            if handle
                .finish_http_stream(key, stream_id, operation_id)
                .await
            {
                Ok(())
            } else {
                Err(CarrierClosed)
            }
        }
    }

    fn reset(&mut self, detail: ResetDetail) -> impl Future<Output = ()> + Send {
        let handle = self.handle.clone();
        let key = self.key.clone();
        let stream_id = self.stream_id;
        let operation_id = self.operation_id.clone();
        async move {
            let _ = handle
                .reset_http_stream(key, stream_id, operation_id, reset_reason_for(detail))
                .await;
        }
    }
}

/// Reads the owner actor's logical stream.
pub(crate) struct ActorReader {
    handle: RelayHandle,
    key: SessionKey,
    stream_id: u64,
    operation_id: String,
    status: watch::Receiver<Option<ResultDetail>>,
    signal: ResetSignal,
    pending: Option<tokio::sync::oneshot::Receiver<HttpRead>>,
    pending_reset: Option<u16>,
}

async fn detail_with_status(
    reason: u16,
    status: &mut watch::Receiver<Option<ResultDetail>>,
) -> ResetDetail {
    let current = status.borrow().clone();
    let detail = match current {
        Some(detail) => Some(detail),
        None => tokio::time::timeout(RESULT_STATUS_GRACE, status.wait_for(Option::is_some))
            .await
            .ok()
            .and_then(Result::ok)
            .and_then(|value| value.clone()),
    };
    detail
        .and_then(|detail| detail_from_status(&detail.code, &detail.execution))
        .unwrap_or_else(|| detail_from_reason(reason))
}

impl CarrierReader for ActorReader {
    /// Cancel-safe: an outstanding actor read and a RESET still waiting for
    /// its `RESULT_STATUS` are kept across calls, so a pump that drops this
    /// future (to watch another event) never loses a chunk the actor has
    /// already released.
    #[allow(clippy::manual_async_fn)]
    fn next(&mut self) -> impl Future<Output = CarrierEvent> + Send {
        async move {
            loop {
                if let Some(reason) = self.pending_reset {
                    let detail = detail_with_status(reason, &mut self.status).await;
                    self.pending_reset = None;
                    return CarrierEvent::Reset(detail);
                }
                if self.pending.is_none() {
                    match self
                        .handle
                        .begin_read_http_stream(
                            self.key.clone(),
                            self.stream_id,
                            self.operation_id.clone(),
                        )
                        .await
                    {
                        Some(receiver) => self.pending = Some(receiver),
                        None => return CarrierEvent::Closed,
                    }
                }
                let Some(receiver) = self.pending.as_mut() else {
                    return CarrierEvent::Closed;
                };
                let read = receiver.await.unwrap_or(HttpRead::Closed);
                self.pending = None;
                match read {
                    // An empty chunk only wakes a parked reader.
                    HttpRead::Data(data) if data.is_empty() => {}
                    HttpRead::Data(data) => return CarrierEvent::Data(Bytes::from(data)),
                    HttpRead::Fin => return CarrierEvent::Fin,
                    HttpRead::Reset(reason) => self.pending_reset = Some(reason),
                    HttpRead::Closed => return CarrierEvent::Closed,
                }
            }
        }
    }

    fn reset_signal(&self) -> ResetSignal {
        self.signal.clone()
    }
}

/// Build both carriers for an admitted HTTP stream plus the task that turns
/// the actor's out-of-band RESET observation into the bridge signal.
pub(crate) fn actor_carriers(
    handle: &RelayHandle,
    registration: HttpStreamRegistration,
) -> (ActorWriter, ActorReader, JoinHandle<()>, PauseSignal) {
    let HttpStreamRegistration {
        base,
        mut peer_reset,
        result_status,
        freeze,
    } = registration;
    let (notifier, signal) = reset_signal_pair();
    let closed = base.closed.clone();
    let mut status = result_status.clone();
    let task = tokio::spawn(async move {
        let peer: HttpPeerReset = tokio::select! {
            () = closed.cancelled() => return,
            observed = peer_reset.wait_for(Option::is_some) => match observed {
                Ok(value) => match *value {
                    Some(peer) => peer,
                    None => return,
                },
                Err(_) => return,
            },
        };
        let detail = detail_with_status(peer.reason, &mut status).await;
        notifier.notify(SignaledReset {
            detail,
            after_fin: peer.after_fin,
        });
    });
    (
        ActorWriter {
            handle: handle.clone(),
            key: base.key.clone(),
            stream_id: base.stream_id,
            operation_id: base.operation_id.clone(),
        },
        ActorReader {
            handle: handle.clone(),
            key: base.key,
            stream_id: base.stream_id,
            operation_id: base.operation_id,
            status: result_status,
            signal,
            pending: None,
            pending_reset: None,
        },
        task,
        freeze,
    )
}

// ---------------------------------------------------------------------------
// Peer HTTP/3 hop.

#[derive(Clone, Debug, Eq, PartialEq)]
enum HopRecord {
    Data(Bytes),
    Fin,
    Reset(ResetDetail),
    Credit {
        bytes: u64,
        records: u64,
    },
    /// The sending relay's recorded rotation freeze started (`true`) or
    /// ended.  It carries no credit and consumes no window.
    Pause(bool),
}

const EXECUTIONS: [Execution; 3] = [
    Execution::NotDispatched,
    Execution::Dispatched,
    Execution::Unknown,
];

fn encode_hop(record: &HopRecord) -> Vec<u8> {
    match record {
        HopRecord::Data(data) => {
            let mut body = Vec::with_capacity(1 + data.len());
            body.push(TAG_DATA);
            body.extend_from_slice(data);
            body
        }
        HopRecord::Fin => vec![TAG_FIN],
        HopRecord::Reset(detail) => {
            let code = HttpErrorCode::ALL
                .iter()
                .position(|code| *code == detail.code)
                .unwrap_or(0);
            let execution = EXECUTIONS
                .iter()
                .position(|execution| *execution == detail.execution)
                .unwrap_or(2);
            let mut body = vec![TAG_RESET];
            body.extend_from_slice(&reset_reason_for(*detail).to_be_bytes());
            body.push(u8::try_from(code).unwrap_or(0));
            body.push(u8::try_from(execution).unwrap_or(2));
            body
        }
        HopRecord::Credit { bytes, records } => {
            let mut body = vec![TAG_CREDIT];
            body.extend_from_slice(&bytes.to_be_bytes());
            body.extend_from_slice(&records.to_be_bytes());
            body
        }
        HopRecord::Pause(paused) => vec![TAG_PAUSE, u8::from(*paused)],
    }
}

fn decode_hop(body: &[u8]) -> Option<HopRecord> {
    let (&tag, rest) = body.split_first()?;
    match tag {
        TAG_DATA if !rest.is_empty() && rest.len() <= MAX_HOP_DATA => {
            Some(HopRecord::Data(Bytes::copy_from_slice(rest)))
        }
        TAG_FIN if rest.is_empty() => Some(HopRecord::Fin),
        TAG_RESET if rest.len() == 4 => {
            let reason = u16::from_be_bytes([rest[0], rest[1]]);
            let code = *HttpErrorCode::ALL.get(usize::from(rest[2]))?;
            let execution = *EXECUTIONS.get(usize::from(rest[3]))?;
            let detail = ResetDetail { code, execution };
            // The reason must be registered and agree with the detail, so the
            // numeric code stays the protocol's shared registry value.
            (reset_reason::is_registered(reason) && reason == reset_reason_for(detail))
                .then_some(HopRecord::Reset(detail))
        }
        TAG_CREDIT if rest.len() == 16 => {
            let bytes = u64::from_be_bytes(rest[..8].try_into().ok()?);
            let records = u64::from_be_bytes(rest[8..].try_into().ok()?);
            Some(HopRecord::Credit { bytes, records })
        }
        TAG_PAUSE if rest.len() == 1 && rest[0] <= 1 => Some(HopRecord::Pause(rest[0] == 1)),
        _ => None,
    }
}

fn hop_cost(payload: usize) -> u64 {
    (PEER_PREFIX_LEN + 1 + payload) as u64
}

/// One direction of a peer hop's send half, abstracting the ingress
/// (`PeerExchangeSend`) and owner (`InboundPeerSend`) request streams.
pub(crate) trait PeerSendHalf: Send + 'static {
    fn send_record<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> impl Future<Output = Result<(), PeerRuntimeError>> + Send + 'a;
    fn finish(&mut self) -> impl Future<Output = Result<(), PeerRuntimeError>> + Send + '_;
    fn cancel(&mut self);
}

/// One direction of a peer hop's receive half.
pub(crate) trait PeerRecvHalf: Send + 'static {
    fn recv_record(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> impl Future<Output = Result<Option<PeerRecord>, PeerRuntimeError>> + Send + '_;
    fn cancel(&mut self);
}

impl PeerSendHalf for PeerExchangeSend {
    fn send_record<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> impl Future<Output = Result<(), PeerRuntimeError>> + Send + 'a {
        self.send_message(PeerRecordKind::ConsumerChunk, body)
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), PeerRuntimeError>> + Send + '_ {
        PeerExchangeSend::finish(self)
    }

    fn cancel(&mut self) {
        PeerExchangeSend::cancel(self);
    }
}

impl PeerRecvHalf for PeerExchangeRecv {
    fn recv_record(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> impl Future<Output = Result<Option<PeerRecord>, PeerRuntimeError>> + Send + '_ {
        self.recv_message_until(deadline)
    }

    fn cancel(&mut self) {
        PeerExchangeRecv::cancel(self);
    }
}

impl PeerSendHalf for crate::peer_runtime::InboundPeerSend {
    fn send_record<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> impl Future<Output = Result<(), PeerRuntimeError>> + Send + 'a {
        self.send_message(PeerRecordKind::ConsumerChunk, body)
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), PeerRuntimeError>> + Send + '_ {
        crate::peer_runtime::InboundPeerSend::finish(self)
    }

    fn cancel(&mut self) {
        crate::peer_runtime::InboundPeerSend::cancel(self);
    }
}

impl PeerRecvHalf for crate::peer_runtime::InboundPeerRecv {
    fn recv_record(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> impl Future<Output = Result<Option<PeerRecord>, PeerRuntimeError>> + Send + '_ {
        self.recv_message_until(deadline)
    }

    fn cancel(&mut self) {
        crate::peer_runtime::InboundPeerRecv::cancel(self);
    }
}

#[derive(Debug, Default)]
struct CreditState {
    sent_bytes: u64,
    sent_records: u64,
    peer_consumed_bytes: u64,
    peer_consumed_records: u64,
    in_flight_high_water: usize,
    closed: bool,
}

#[derive(Debug, Default)]
struct QueueState {
    events: VecDeque<CarrierEvent>,
    queued_bytes: usize,
    queued_records: usize,
    high_water: usize,
    consumed_bytes: u64,
    consumed_records: u64,
}

/// State shared by one peer hop's writer, reader and tasks.
struct HopShared {
    credit: Mutex<CreditState>,
    credit_changed: Notify,
    queue: Mutex<QueueState>,
    queue_changed: Notify,
    consumed_tx: watch::Sender<(u64, u64)>,
    peer_terminal: CancellationToken,
    stop: CancellationToken,
    /// The bounds this stream shares with every HTTP hop to the same peer.
    aggregate: Arc<HopAggregate>,
    /// The peer relay's recorded rotation freeze, as it reported it.
    peer_pause: PauseController,
}

impl Drop for HopShared {
    /// Return whatever this stream still holds of the peer aggregate: bytes
    /// sent but never reported consumed, and bytes received but never read.
    fn drop(&mut self) {
        let credit = self
            .credit
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let in_flight = credit.sent_bytes.saturating_sub(credit.peer_consumed_bytes);
        self.aggregate.release_send(in_flight);
        let queue = self
            .queue
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let queued: u64 = queue
            .events
            .iter()
            .map(|event| match event {
                CarrierEvent::Data(data) => hop_cost(data.len()),
                _ => 0,
            })
            .sum();
        self.aggregate.release_receive(queued);
    }
}

impl HopShared {
    fn credit(&self) -> MutexGuard<'_, CreditState> {
        self.credit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn queue(&self) -> MutexGuard<'_, QueueState> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn close_credit(&self) {
        self.credit().closed = true;
        self.credit_changed.notify_waiters();
    }

    /// Resolves once the hop can no longer carry writes.
    async fn closed_or_stopped(&self) {
        loop {
            let notified = self.credit_changed.notified();
            let mut notified = pin!(notified);
            notified.as_mut().enable();
            if self.credit().closed || self.stop.is_cancelled() {
                return;
            }
            tokio::select! {
                () = self.stop.cancelled() => return,
                () = notified => {}
            }
        }
    }

    fn push(&self, event: CarrierEvent) {
        {
            let mut queue = self.queue();
            if let CarrierEvent::Data(data) = &event {
                queue.queued_bytes = queue.queued_bytes.saturating_add(data.len());
                queue.queued_records = queue.queued_records.saturating_add(1);
                queue.high_water = queue.high_water.max(queue.queued_bytes);
            }
            queue.events.push_back(event);
        }
        self.queue_changed.notify_one();
    }
}

enum HopCommand {
    Record(Vec<u8>),
    Fin,
    Reset(ResetDetail),
    Pause(bool),
}

/// The credited send side of a peer hop.
pub(crate) struct PeerHopWriter {
    shared: Arc<HopShared>,
    commands: mpsc::Sender<HopCommand>,
}

/// Relays this relay's freeze state to the peer over one hop.
pub(crate) struct HopPauser {
    commands: mpsc::Sender<HopCommand>,
}

impl HopPauser {
    /// Forward every change of `freeze` until the hop's writer is gone.
    pub(crate) async fn relay(self, mut freeze: PauseSignal) {
        let mut reported = false;
        loop {
            let paused = freeze.is_paused();
            if paused != reported {
                if self.commands.send(HopCommand::Pause(paused)).await.is_err() {
                    return;
                }
                reported = paused;
            }
            tokio::select! {
                () = freeze.changed() => {}
                () = self.commands.closed() => return,
            }
        }
    }
}

impl PeerHopWriter {
    pub(crate) fn pauser(&self) -> HopPauser {
        HopPauser {
            commands: self.commands.clone(),
        }
    }
}

impl CarrierWriter for PeerHopWriter {
    fn data(&mut self, data: Bytes) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        let shared = Arc::clone(&self.shared);
        let commands = self.commands.clone();
        async move {
            let mut pieces = Vec::new();
            let mut rest = data;
            while !rest.is_empty() {
                pieces.push(rest.split_to(rest.len().min(MAX_HOP_DATA)));
            }
            let cost: u64 = pieces.iter().map(|piece| hop_cost(piece.len())).sum();
            let records = pieces.len() as u64;
            loop {
                let notified = shared.credit_changed.notified();
                let mut notified = pin!(notified);
                notified.as_mut().enable();
                {
                    let credit = shared.credit();
                    if credit.closed {
                        return Err(CarrierClosed);
                    }
                    let in_flight = credit.sent_bytes.saturating_sub(credit.peer_consumed_bytes);
                    let in_flight_records = credit
                        .sent_records
                        .saturating_sub(credit.peer_consumed_records);
                    if in_flight.saturating_add(cost) <= PEER_HOP_WINDOW_BYTES as u64
                        && in_flight_records.saturating_add(records)
                            <= PEER_HOP_WINDOW_RECORDS as u64
                    {
                        break;
                    }
                }
                tokio::select! {
                    () = shared.stop.cancelled() => return Err(CarrierClosed),
                    () = notified => {}
                }
            }
            // Reserve every slot before charging or sending, so a dropped
            // write sends nothing and a chunk is never split.
            let permits = commands
                .reserve_many(pieces.len())
                .await
                .map_err(|_| CarrierClosed)?;
            // The per-peer aggregate is shared by every HTTP hop to this
            // peer.  Only this writer adds to this stream's in-flight bytes,
            // so the per-stream window cannot close again while it waits.
            // The aggregate charge and the credit charge below happen with no
            // await between them, so a dropped write leaks neither.
            if !shared
                .aggregate
                .acquire_send(cost, shared.closed_or_stopped())
                .await
            {
                return Err(CarrierClosed);
            }
            {
                let mut credit = shared.credit();
                credit.sent_bytes = credit.sent_bytes.saturating_add(cost);
                credit.sent_records = credit.sent_records.saturating_add(records);
                let in_flight = credit.sent_bytes.saturating_sub(credit.peer_consumed_bytes);
                credit.in_flight_high_water = credit
                    .in_flight_high_water
                    .max(usize::try_from(in_flight).unwrap_or(usize::MAX));
            }
            for (permit, piece) in permits.zip(pieces) {
                permit.send(HopCommand::Record(encode_hop(&HopRecord::Data(piece))));
            }
            Ok(())
        }
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        let commands = self.commands.clone();
        async move {
            commands
                .send(HopCommand::Fin)
                .await
                .map_err(|_| CarrierClosed)
        }
    }

    fn reset(&mut self, detail: ResetDetail) -> impl Future<Output = ()> + Send {
        let commands = self.commands.clone();
        async move {
            let _ = commands.send(HopCommand::Reset(detail)).await;
        }
    }
}

/// The credited receive side of a peer hop.
pub(crate) struct PeerHopReader {
    shared: Arc<HopShared>,
    signal: ResetSignal,
}

impl CarrierReader for PeerHopReader {
    fn next(&mut self) -> impl Future<Output = CarrierEvent> + Send {
        let shared = Arc::clone(&self.shared);
        async move {
            loop {
                let notified = shared.queue_changed.notified();
                let mut notified = pin!(notified);
                notified.as_mut().enable();
                let popped = {
                    let mut queue = shared.queue();
                    let event = queue.events.pop_front();
                    if let Some(CarrierEvent::Data(data)) = &event {
                        shared.aggregate.release_receive(hop_cost(data.len()));
                        queue.queued_bytes = queue.queued_bytes.saturating_sub(data.len());
                        queue.queued_records = queue.queued_records.saturating_sub(1);
                        queue.consumed_bytes =
                            queue.consumed_bytes.saturating_add(hop_cost(data.len()));
                        queue.consumed_records = queue.consumed_records.saturating_add(1);
                        let consumed = (queue.consumed_bytes, queue.consumed_records);
                        shared.consumed_tx.send_replace(consumed);
                    }
                    event
                };
                if let Some(event) = popped {
                    return event;
                }
                notified.await;
            }
        }
    }

    fn reset_signal(&self) -> ResetSignal {
        self.signal.clone()
    }
}

/// Bounded hop statistics and task control.
pub(crate) struct PeerHop {
    shared: Arc<HopShared>,
    writer_task: JoinHandle<()>,
    reader_task: JoinHandle<()>,
}

impl PeerHop {
    fn send_in_flight_high_water(&self) -> usize {
        self.shared.credit().in_flight_high_water
    }

    /// The peer relay's recorded freeze as it reported it on this hop.
    pub(crate) fn peer_pause_signal(&self) -> PauseSignal {
        self.shared.peer_pause.signal()
    }

    fn aggregate_high_water(&self) -> (usize, usize) {
        self.shared.aggregate.high_water()
    }

    fn receive_queue_high_water(&self) -> usize {
        self.shared.queue().high_water
    }

    /// Let the writer flush its terminal record, then stop both tasks.
    async fn finish(self, grace: Duration) {
        let Self {
            shared,
            writer_task,
            reader_task,
        } = self;
        let mut writer_task = writer_task;
        if tokio::time::timeout(grace, &mut writer_task).await.is_err() {
            writer_task.abort();
        }
        shared.stop.cancel();
        let _ = reader_task.await;
    }
}

/// Start one credited peer hop over an established request stream.
pub(crate) fn spawn_peer_hop<S: PeerSendHalf, R: PeerRecvHalf>(
    mut send: S,
    mut recv: R,
    deadline: tokio::time::Instant,
    aggregate: Arc<HopAggregate>,
) -> (PeerHopWriter, PeerHopReader, PeerHop) {
    let (consumed_tx, mut consumed_rx) = watch::channel((0u64, 0u64));
    let shared = Arc::new(HopShared {
        credit: Mutex::new(CreditState::default()),
        credit_changed: Notify::new(),
        queue: Mutex::new(QueueState::default()),
        queue_changed: Notify::new(),
        consumed_tx,
        peer_terminal: CancellationToken::new(),
        stop: CancellationToken::new(),
        aggregate,
        peer_pause: PauseController::new(false),
    });
    let (notifier, signal): (ResetNotifier, ResetSignal) = reset_signal_pair();
    let (commands, mut command_rx) = mpsc::channel::<HopCommand>(4);

    let writer_shared = Arc::clone(&shared);
    let writer_task = tokio::spawn(async move {
        let shared = writer_shared;
        let mut fin_sent = false;
        let mut reset_sent = false;
        let mut commands_closed = false;
        let mut failed = false;
        loop {
            // A RESET ends both directions.  After FIN the writer stays open
            // for a later RESET until the local endpoint releases it, and
            // until the peer's own terminal ends the need for CREDIT.
            if reset_sent || (fin_sent && commands_closed && shared.peer_terminal.is_cancelled()) {
                break;
            }
            enum Step {
                Command(Option<HopCommand>),
                Credit,
                PeerTerminal,
                Stop,
            }
            let step = tokio::select! {
                biased;
                () = shared.stop.cancelled() => Step::Stop,
                command = command_rx.recv(), if !commands_closed => Step::Command(command),
                changed = consumed_rx.changed(), if !shared.peer_terminal.is_cancelled() => {
                    if changed.is_err() { Step::Stop } else { Step::Credit }
                }
                () = shared.peer_terminal.cancelled(), if commands_closed => Step::PeerTerminal,
            };
            let body = match step {
                Step::Stop => break,
                Step::PeerTerminal => continue,
                Step::Credit => {
                    let (bytes, records) = *consumed_rx.borrow_and_update();
                    encode_hop(&HopRecord::Credit { bytes, records })
                }
                Step::Command(None) => {
                    commands_closed = true;
                    if fin_sent {
                        continue;
                    }
                    // The local endpoint dropped the writer before FIN or
                    // RESET: the direction is abandoned, never completed.
                    reset_sent = true;
                    encode_hop(&HopRecord::Reset(ResetDetail {
                        code: HttpErrorCode::StreamInterrupted,
                        execution: Execution::Unknown,
                    }))
                }
                // DATA after FIN is impossible from the bridge; drop it
                // rather than violate the peer's directional grammar.
                Step::Command(Some(HopCommand::Record(_))) if fin_sent => continue,
                Step::Command(Some(HopCommand::Record(body))) => body,
                Step::Command(Some(HopCommand::Fin)) if fin_sent => continue,
                Step::Command(Some(HopCommand::Fin)) => {
                    fin_sent = true;
                    encode_hop(&HopRecord::Fin)
                }
                Step::Command(Some(HopCommand::Reset(detail))) => {
                    reset_sent = true;
                    encode_hop(&HopRecord::Reset(detail))
                }
                Step::Command(Some(HopCommand::Pause(paused))) => {
                    encode_hop(&HopRecord::Pause(paused))
                }
            };
            let sent = tokio::select! {
                biased;
                () = shared.stop.cancelled() => break,
                sent = send.send_record(&body) => sent,
            };
            if let Err(error) = &sent {
                tracing::debug!(error = %error, phase = "http_forward_peer_hop_send");
                failed = true;
                break;
            }
        }
        shared.close_credit();
        let local_terminal = fin_sent || reset_sent;
        if failed || !local_terminal {
            send.cancel();
        } else {
            let _ = tokio::time::timeout(Duration::from_secs(5), send.finish()).await;
        }
    });

    let reader_shared = Arc::clone(&shared);
    let reader_task = tokio::spawn(async move {
        let shared = reader_shared;
        let mut fin_seen = false;
        loop {
            let received = tokio::select! {
                biased;
                () = shared.stop.cancelled() => break,
                received = recv.recv_record(deadline) => received,
            };
            let record = match received {
                Ok(Some(record)) if record.kind() == PeerRecordKind::ConsumerChunk => record,
                other => {
                    tracing::debug!(
                        kind = ?other.as_ref().ok().map(|record| record.as_ref().map(PeerRecord::kind)),
                        failed = other.is_err(),
                        phase = "http_forward_peer_hop_receive_end"
                    );
                    if !shared.peer_terminal.is_cancelled() {
                        shared.push(CarrierEvent::Closed);
                    }
                    break;
                }
            };
            let Some(decoded) = decode_hop(record.body()) else {
                shared.push(CarrierEvent::Closed);
                break;
            };
            drop(record);
            match decoded {
                HopRecord::Data(data) => {
                    if fin_seen || shared.peer_terminal.is_cancelled() {
                        shared.push(CarrierEvent::Closed);
                        break;
                    }
                    // The sender may not exceed the window this side has
                    // granted; a violation is a protocol failure, not a
                    // reason to queue more.
                    let over = {
                        let queue = shared.queue();
                        queue.queued_bytes.saturating_add(data.len()) > PEER_HOP_WINDOW_BYTES
                            || queue.queued_records >= PEER_HOP_WINDOW_RECORDS
                    };
                    if over {
                        tracing::debug!(phase = "http_forward_peer_hop_window_violation");
                        shared.push(CarrierEvent::Closed);
                        break;
                    }
                    // The same peer's HTTP hops together may not exceed the
                    // aggregate its own sender bound respects.
                    if !shared.aggregate.charge_receive(hop_cost(data.len())) {
                        tracing::debug!(phase = "http_forward_peer_hop_aggregate_violation");
                        shared.push(CarrierEvent::Closed);
                        break;
                    }
                    shared.push(CarrierEvent::Data(data));
                }
                HopRecord::Fin => {
                    fin_seen = true;
                    shared.peer_terminal.cancel();
                    shared.push(CarrierEvent::Fin);
                }
                HopRecord::Reset(detail) => {
                    notifier.notify(SignaledReset {
                        detail,
                        after_fin: fin_seen,
                    });
                    shared.peer_terminal.cancel();
                    shared.push(CarrierEvent::Reset(detail));
                    break;
                }
                HopRecord::Credit { bytes, records } => {
                    let released = {
                        let mut credit = shared.credit();
                        // Consumption can never exceed what was sent.
                        let bytes = bytes.min(credit.sent_bytes);
                        let released = bytes.saturating_sub(credit.peer_consumed_bytes);
                        credit.peer_consumed_bytes = credit.peer_consumed_bytes.max(bytes);
                        credit.peer_consumed_records = credit.peer_consumed_records.max(records);
                        released
                    };
                    shared.aggregate.release_send(released);
                    shared.credit_changed.notify_waiters();
                }
                HopRecord::Pause(paused) => shared.peer_pause.set(paused),
            }
        }
        shared.peer_terminal.cancel();
        shared.close_credit();
        recv.cancel();
    });

    (
        PeerHopWriter {
            shared: Arc::clone(&shared),
            commands,
        },
        PeerHopReader {
            shared: Arc::clone(&shared),
            signal,
        },
        PeerHop {
            shared,
            writer_task,
            reader_task,
        },
    )
}

// ---------------------------------------------------------------------------
// Public ingress route.

fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Complete => "complete",
        Outcome::Aborted => "aborted",
        Outcome::Pending => "pending",
    }
}

/// The raw path after `/v1/devices/{device}/services/{service}/http`, taken
/// from the undecoded request target so the codec sees exactly what the
/// consumer sent.
fn export_path(uri: &http::Uri) -> Option<String> {
    let path = uri.path();
    let mut segments = path.splitn(7, '/');
    let (Some(""), Some("v1"), Some("devices"), Some(_), Some("services"), Some(_), Some(rest)) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return None;
    };
    let rest = rest.strip_prefix("http")?;
    rest.starts_with('/').then(|| rest.to_owned())
}

/// Remove the public-layer credentials after verification.  The token
/// profile verifies `authorization`; `cookie` is never an accepted
/// credential here, so it is removed without being honored.  Any other
/// credential or internal field is left for the codec to reject.
fn strip_public_credentials(headers: &mut http::HeaderMap) {
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::COOKIE);
}

fn gateway_error(status: StatusCode, code: &'static str, execution: &'static str) -> Response {
    error_response(status, code, "http forwarding is unavailable", execution)
}

/// `ANY /v1/devices/{device}/services/{service}/http/{*path}`.
pub(crate) async fn http_forward_route(
    State(state): State<HttpState>,
    Path((device, service, _path)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    if let Some(response) = cluster_unready_response(&state) {
        return response;
    }
    let Some(exports) = state.http_forward.clone() else {
        return error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "not found",
            "not_dispatched",
        );
    };
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return admission_limit_response(ADMISSION_LIMIT_RETRY_AFTER_MS);
    };
    let (Some(catalog), Some(oidc)) = (state.catalog.as_ref(), state.oidc.as_ref()) else {
        return gateway_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "not_dispatched",
        );
    };
    let headers = request.headers();
    let validated = match oidc
        .authenticate_for_scope(
            &**catalog,
            bearer(headers),
            None,
            crate::HTTP_FORWARD_OPERATION,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => return consumer_authentication_response(&error),
    };
    let bearer_token = forwarded_bearer_token(headers).to_owned();
    let Ok(device_id) = parse_uuid(&device) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "not found",
            "not_dispatched",
        );
    };
    let (service_id, mut grant, capabilities) = match service_and_grant_of_type(
        &state,
        &validated.consumer,
        device_id,
        &service,
        crate::HTTP_FORWARD_SERVICE_TYPE,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let now = Utc::now();
    if !grant.permissions.allows(crate::HTTP_FORWARD_OPERATION)
        || grant.valid_until <= now
        || validated.expires_at <= now
    {
        return error_response(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "http export is not authorized",
            "not_dispatched",
        );
    }
    grant.valid_until = grant.valid_until.min(validated.expires_at);
    // Gate 5: the authorized service's catalog record selects the profile.
    // A service naming no profile this relay serves is not an HTTP export
    // here; nothing is normalized, routed or opened for it.
    let Some(export) = exports.select(&capabilities) else {
        state
            .handle
            .http_forward_diagnostics()
            .record_ingress_rejection();
        return error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "not found",
            "not_dispatched",
        );
    };
    let Some(scope_permit) = state
        .scoped_admission
        .try_acquire(OwnerScope::new(grant.tenant_id, device_id))
    else {
        return admission_limit_response(ADMISSION_LIMIT_RETRY_AFTER_MS);
    };

    // Verified: remove the public credentials and map the public target onto
    // the export's own path before anything is normalized or forwarded.
    let (mut parts, body) = request.into_parts();
    let Some(path) = export_path(&parts.uri) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "not found",
            "not_dispatched",
        );
    };
    let target = match parts.uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    let Ok(uri) = http::Uri::try_from(target) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "HTTP_INVALID_HEAD",
            "invalid request target",
            "not_dispatched",
        );
    };
    parts.uri = uri;
    strip_public_credentials(&mut parts.headers);
    // A head the bridge would refuse is refused here, before any owner
    // route, peer stream or tunnel stream exists: a malformed or forbidden
    // head must not amplify into peer→owner→device admission work.
    if let Err(error) = tunnel_http_bridge::normalize::request_head(&parts, &export.profile.request)
    {
        state
            .handle
            .http_forward_diagnostics()
            .record_ingress_rejection();
        return rejection_response(error).map(axum::body::Body::new);
    }
    let request = http::Request::from_parts(parts, body);

    // The exchange never outlives the consumer's verified token.
    let token_remaining = (validated.expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    let config = if token_remaining < export.config.deadline() {
        match export.config.with_deadline(token_remaining) {
            Ok(config) => config,
            Err(_) => {
                return error_response(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "credential expired",
                    "not_dispatched",
                );
            }
        }
    } else {
        export.config
    };
    let exchange_deadline = tokio::time::Instant::now() + config.discard_bound();
    let diagnostics = state.handle.http_forward_diagnostics().clone();

    let route = match state.peer.clone() {
        Some(peer) => match peer
            .resolve(OwnerScope::new(grant.tenant_id, device_id), Utc::now())
            .await
        {
            Ok(route) => Some((peer, route)),
            Err(error) => return peer_failure_response(error),
        },
        None => None,
    };

    let (to_device_tx, to_device_rx, request_handoff) = channel(HANDOFF_CAPACITY);
    let (from_device_tx, from_device_rx, response_handoff) = channel(HANDOFF_CAPACITY);

    match route {
        Some((peer, route @ OwnerRoute::Remote { .. })) => {
            let request_id = Uuid::new_v4().to_string();
            let fault = PeerFaultObserver::new(
                PeerFaultRole::Ingress,
                PeerFaultContext::for_owner(
                    route.owner_token(),
                    Some(service_id),
                    Some(request_id.clone()),
                ),
            );
            let admission = match timeout(
                state.limits.operation_timeout,
                open_remote_http_admission(
                    &peer,
                    &route,
                    service_id,
                    &bearer_token,
                    request_id.clone(),
                    fault.diagnostic(),
                ),
            )
            .await
            {
                Ok(Ok(admission)) => admission,
                Ok(Err(error)) => {
                    state.handle.record_peer_fault(&fault, &error);
                    return peer_failure_response(error);
                }
                Err(_) => {
                    state.handle.record_peer_fault_tuple(
                        &fault,
                        fault.stage(),
                        PeerFaultCause::Deadline,
                    );
                    return peer_failure_response(PeerRuntimeError::Closed);
                }
            };
            fault.mark(PeerOpenDiagnosticStage::Body);
            let (_, send, recv) = admission.into_parts();
            let aggregate = state
                .handle
                .http_hop_aggregates()
                .for_peer(&route.owner_token().node_id);
            let (hop_writer, hop_reader, hop) =
                spawn_peer_hop(send, recv, exchange_deadline, aggregate);
            let owner_freeze = hop.peer_pause_signal();
            let outbound = tokio::spawn(pump_outbound(to_device_rx, hop_writer));
            let inbound = tokio::spawn(pump_inbound(hop_reader, from_device_tx));
            let (response, exchange) = forward_paused(
                request,
                export.profile,
                config,
                to_device_tx,
                from_device_rx,
                owner_freeze,
            )
            .await;
            let body_stats = response.body().stats();
            tokio::spawn(async move {
                let _permits = (permit, scope_permit);
                let (report, _, _) = tokio::join!(exchange.report(), outbound, inbound);
                hop_finish_and_record(
                    hop,
                    diagnostics,
                    "ingress_remote",
                    Some(request_id),
                    None,
                    &request_handoff,
                    &response_handoff,
                    &body_stats,
                    report,
                )
                .await;
            });
            response.map(axum::body::Body::new)
        }
        _ => {
            let registration = match timeout(
                state.limits.operation_timeout,
                state.handle.open_http_stream(
                    validated.consumer,
                    device_id,
                    service_id,
                    grant,
                    validated.expires_at,
                    None,
                ),
            )
            .await
            {
                Ok(Ok(registration)) => registration,
                Ok(Err(error)) => return local_consumer_admission_response(error),
                Err(_) => {
                    return gateway_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "REVERSE_CHANNEL_INTERRUPTED",
                        "unknown",
                    );
                }
            };
            let key = registration.base.key.clone();
            let stream_id = registration.base.stream_id;
            let operation_id = registration.base.operation_id.clone();
            let mut cleanup =
                state
                    .handle
                    .echo_cleanup_guard(key.clone(), stream_id, operation_id.clone(), None);
            let (writer, reader, signal_task, freeze) = actor_carriers(&state.handle, registration);
            let outbound = tokio::spawn(pump_outbound(to_device_rx, writer));
            let inbound = tokio::spawn(pump_inbound(reader, from_device_tx));
            let (response, exchange) = forward_paused(
                request,
                export.profile,
                config,
                to_device_tx,
                from_device_rx,
                freeze,
            )
            .await;
            let body_stats = response.body().stats();
            let handle = state.handle.clone();
            tokio::spawn(async move {
                let _permits = (permit, scope_permit);
                let (report, _, _) = tokio::join!(exchange.report(), outbound, inbound);
                signal_task.abort();
                if matches!(
                    timeout(
                        Duration::from_secs(5),
                        handle.close_echo_stream_with_cause(key, stream_id, operation_id, None),
                    )
                    .await,
                    Ok(true)
                ) {
                    cleanup.disarm();
                }
                record_exchange(
                    &diagnostics,
                    "ingress_local",
                    None,
                    Some(stream_id),
                    &request_handoff,
                    &response_handoff,
                    &body_stats,
                    None,
                    report,
                );
            });
            response.map(axum::body::Body::new)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn hop_finish_and_record(
    hop: PeerHop,
    diagnostics: HttpForwardDiagnostics,
    role: &'static str,
    request_id: Option<String>,
    stream_id: Option<u64>,
    request_handoff: &QueueStats,
    response_handoff: &QueueStats,
    body: &QueueStats,
    report: ExchangeReport,
) {
    let send_high_water = hop.send_in_flight_high_water();
    let receive_high_water = hop.receive_queue_high_water();
    let (aggregate_send, aggregate_receive) = hop.aggregate_high_water();
    diagnostics.note_hop_aggregate(aggregate_send, aggregate_receive);
    hop.finish(RELAY_TERMINAL_GRACE).await;
    record_exchange(
        &diagnostics,
        role,
        request_id,
        stream_id,
        request_handoff,
        response_handoff,
        body,
        Some((send_high_water, receive_high_water)),
        report,
    );
}

#[allow(clippy::too_many_arguments)]
fn record_exchange(
    diagnostics: &HttpForwardDiagnostics,
    role: &'static str,
    request_id: Option<String>,
    stream_id: Option<u64>,
    request_handoff: &QueueStats,
    response_handoff: &QueueStats,
    body: &QueueStats,
    peer: Option<(usize, usize)>,
    report: ExchangeReport,
) {
    diagnostics.record_exchange(HttpExchangeRecord {
        role,
        request_id,
        stream_id,
        request_handoff_high_water: request_handoff.high_water(),
        response_handoff_high_water: response_handoff.high_water(),
        response_body_high_water: body.high_water(),
        peer_send_in_flight_high_water: peer.map_or(0, |(send, _)| send),
        peer_receive_queue_high_water: peer.map_or(0, |(_, receive)| receive),
        peer_window: if peer.is_some() {
            PEER_HOP_WINDOW_BYTES
        } else {
            0
        },
        request_outcome: outcome_label(report.request),
        response_outcome: outcome_label(report.response),
        error_code: report.error.map(HttpErrorCode::as_str),
        execution: report.execution.as_str(),
        progress_expired: report
            .progress_expired
            .map(tunnel_http_bridge::ProgressKind::as_str),
    });
}

async fn open_remote_http_admission(
    peer: &PeerRuntime,
    route: &OwnerRoute,
    service_id: Uuid,
    bearer_token: &str,
    request_id: String,
    diagnostic: &PeerOpenDiagnostic,
) -> Result<RemoteConsumerAdmission, PeerRuntimeError> {
    let destination = Destination::new(route.owner_token().clone(), service_id);
    let bearer = forwarded_consumer_bearer(bearer_token, route.owner_token().clone())?;
    let envelope = RequestEnvelope::new(
        InternalRoute::ConsumerStreams,
        request_id.clone(),
        peer.source().clone(),
        destination,
        20_000,
        None,
        InternalRequest::ConsumerStreams(tunnel_cluster::envelope::ConsumerStreamsRequest {
            stream_id: request_id.clone(),
            required_scope: crate::HTTP_FORWARD_OPERATION.to_owned(),
            bearer,
            bytes: Vec::new(),
        }),
    );
    let exchange = peer
        .open_with_diagnostics(route, envelope, diagnostic)
        .await?;
    let (send, recv) = exchange.split();
    let mut admission = RemoteConsumerAdmission::new(request_id, send, recv);
    diagnostic.mark(PeerOpenDiagnosticStage::Head);
    admission.accept_response().await?;
    Ok(admission)
}

// ---------------------------------------------------------------------------
// Owner side of a forwarded HTTP exchange.

/// Wraps a writer so the relay can observe that FIN was accepted.
struct FinObserved<W> {
    inner: W,
    finished: watch::Sender<bool>,
}

impl<W: CarrierWriter> CarrierWriter for FinObserved<W> {
    fn data(&mut self, data: Bytes) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        self.inner.data(data)
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        let finished = self.finished.clone();
        let finish = self.inner.finish();
        async move {
            let result = finish.await;
            if result.is_ok() {
                finished.send_replace(true);
            }
            result
        }
    }

    fn reset(&mut self, detail: ResetDetail) -> impl Future<Output = ()> + Send {
        self.inner.reset(detail)
    }
}

async fn both_finished(mut up: watch::Receiver<bool>, mut down: watch::Receiver<bool>) {
    let _ = up.wait_for(|finished| *finished).await;
    let _ = down.wait_for(|finished| *finished).await;
}

/// Relay one forwarded HTTP exchange between the peer hop and the owner
/// actor.  The owner admits the stream itself (after re-authenticating the
/// forwarded token and re-authorizing the grant), remains the only authority
/// for its tunnel sequences, and re-validates both record directions against
/// its own copy of the export profile.  An owner without an export profile
/// cannot validate and refuses the stream before admitting it.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn handle_peer_http_stream(
    request: InboundPeerRequest,
    handle: RelayHandle,
    consumer: tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Uuid,
    grant: tunnel_catalog::GrantSnapshot,
    consumer_expires_at: chrono::DateTime<Utc>,
    fault: &PeerFaultObserver,
    export: Option<HttpForwardExport>,
) -> Result<(), PeerRuntimeError> {
    let Some(export) = export else {
        tracing::debug!(phase = "http_forward_owner_without_profile");
        return Err(PeerRuntimeError::Closed);
    };
    let request_id = request.envelope().request_id.clone();
    let source_node = request.envelope().source.node_id.clone();
    let admission_context = request.admission_cancellation_context();
    let registration = match handle
        .open_http_stream(
            consumer,
            device_id,
            service_id,
            grant,
            consumer_expires_at,
            Some(request_id.clone()),
        )
        .await
    {
        Ok(registration) => registration,
        Err(RelayError::OwnerNotReady) => {
            handle.record_peer_fault_tuple(
                fault,
                PeerOpenDiagnosticStage::Owner,
                PeerFaultCause::OwnerNotReady,
            );
            return request.reject_owner_not_ready().await;
        }
        Err(RelayError::StreamLimit) => {
            handle.record_peer_fault_tuple(
                fault,
                PeerOpenDiagnosticStage::Owner,
                PeerFaultCause::Capacity,
            );
            return request.reject_stream_limit().await;
        }
        Err(_) => return Err(PeerRuntimeError::Closed),
    };
    let key = registration.base.key.clone();
    let stream_id = registration.base.stream_id;
    let operation_id = registration.base.operation_id.clone();
    let mut cleanup = handle.echo_cleanup_guard(
        key.clone(),
        stream_id,
        operation_id.clone(),
        admission_context.clone(),
    );
    let (mut send, recv) = request.split();
    if let Err(error) = send.respond(StatusCode::OK).await {
        let _ = handle
            .close_echo_stream_with_cause(key, stream_id, operation_id, None)
            .await;
        cleanup.disarm();
        return Err(error);
    }
    fault.mark(PeerOpenDiagnosticStage::Body);
    let token_remaining = (consumer_expires_at - Utc::now())
        .to_std()
        .unwrap_or_default()
        .min(tunnel_http_bridge::MAX_DEADLINE);
    let deadline = tokio::time::Instant::now() + token_remaining;
    let aggregate = handle.http_hop_aggregates().for_peer(&source_node);
    let (hop_writer, hop_reader, hop) = spawn_peer_hop(send, recv, deadline, aggregate);
    let (actor_writer, actor_reader, signal_task, freeze) = actor_carriers(&handle, registration);
    // The ingress's progress clocks pause for exactly this owner's freeze.
    let pause_task = tokio::spawn(hop_writer.pauser().relay(freeze));
    let (up_finished_tx, up_finished) = watch::channel(false);
    let (down_finished_tx, down_finished) = watch::channel(false);
    let (up_tx, up_rx, up_stats) = channel(HANDOFF_CAPACITY);
    let (down_tx, down_rx, down_stats) = channel(HANDOFF_CAPACITY);
    let verdict = Arc::new(OwnerVerdict::default());
    let (method_tx, method_rx) = watch::channel(None);
    let request_writer = OwnerRequestWriter::new(
        actor_writer,
        export.profile.request.clone(),
        method_tx,
        export.interposer.clone(),
        Arc::clone(&verdict),
        down_tx.clone(),
    );
    let response_writer = OwnerResponseWriter::new(
        hop_writer,
        export.profile.response.clone(),
        method_rx,
        Arc::clone(&verdict),
        up_tx.clone(),
    );
    let up_in = tokio::spawn(pump_inbound(hop_reader, up_tx));
    let up_out = tokio::spawn(pump_outbound(
        up_rx,
        FinObserved {
            inner: request_writer,
            finished: up_finished_tx,
        },
    ));
    let down_in = tokio::spawn(pump_inbound(actor_reader, down_tx));
    let down_out = tokio::spawn(pump_outbound(
        down_rx,
        FinObserved {
            inner: response_writer,
            finished: down_finished_tx,
        },
    ));
    let admission_cancelled = async {
        match admission_context {
            Some(admission) => admission.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    };
    let mut up_out = up_out;
    let mut down_out = down_out;
    let (mut up_end, mut down_end) = (None::<OutboundEnd>, None::<OutboundEnd>);
    tokio::select! {
        () = both_finished(up_finished, down_finished) => {}
        () = tokio::time::sleep_until(deadline) => {}
        () = admission_cancelled => {}
        end = &mut up_out => {
            up_end = end.ok();
            let _ = tokio::time::timeout(RELAY_TERMINAL_GRACE, &mut down_out).await.map(|end| down_end = end.ok());
        }
        end = &mut down_out => {
            down_end = end.ok();
            let _ = tokio::time::timeout(RELAY_TERMINAL_GRACE, &mut up_out).await.map(|end| up_end = end.ok());
        }
    }
    for task in [&up_out, &down_out] {
        task.abort();
    }
    up_in.abort();
    down_in.abort();
    signal_task.abort();
    pause_task.abort();
    let _ = pause_task.await;
    let send_high_water = hop.send_in_flight_high_water();
    let receive_high_water = hop.receive_queue_high_water();
    let (aggregate_send, aggregate_receive) = hop.aggregate_high_water();
    handle
        .http_forward_diagnostics()
        .note_hop_aggregate(aggregate_send, aggregate_receive);
    let closed = timeout(
        Duration::from_secs(5),
        handle.close_echo_stream_with_cause(key, stream_id, operation_id, None),
    )
    .await;
    if matches!(closed, Ok(true)) {
        cleanup.disarm();
    }
    hop.finish(RELAY_TERMINAL_GRACE).await;
    let aborted = |end: Option<OutboundEnd>| match end {
        Some(OutboundEnd::Finished) | None => Outcome::Complete,
        Some(_) => Outcome::Aborted,
    };
    let verdict = verdict.get();
    handle
        .http_forward_diagnostics()
        .record_exchange(HttpExchangeRecord {
            role: "owner_peer",
            request_id: Some(request_id),
            stream_id: Some(stream_id),
            request_handoff_high_water: up_stats.high_water(),
            response_handoff_high_water: down_stats.high_water(),
            response_body_high_water: 0,
            peer_send_in_flight_high_water: send_high_water,
            peer_receive_queue_high_water: receive_high_water,
            peer_window: PEER_HOP_WINDOW_BYTES,
            request_outcome: outcome_label(aborted(up_end)),
            response_outcome: outcome_label(aborted(down_end)),
            error_code: verdict.map(|detail| detail.code.as_str()),
            execution: verdict
                .map_or(Execution::Unknown, |detail| detail.execution)
                .as_str(),
            progress_expired: None,
        });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_cluster::peer_frame::StreamBudget;

    fn export() -> HttpForwardExport {
        let profile = tunnel_mcp::McpProfile::V2026_07_28
            .policies(tunnel_mcp::McpLimits::default())
            .unwrap();
        HttpForwardExport::new(Arc::new(profile), BridgeConfig::default())
    }

    /// Gate 5: a service selects its profile only through the catalog
    /// capability, and anything unlisted selects nothing.
    #[test]
    fn profiles_are_selected_only_by_a_listed_catalog_capability() {
        let exports = HttpForwardExports::new()
            .with_profile("mcp-2026-07-28", export())
            .unwrap();
        assert!(
            exports
                .select(&serde_json::json!({"http_forward_profile": "mcp-2026-07-28"}))
                .is_some()
        );
        for capabilities in [
            serde_json::json!({}),
            serde_json::json!({"operations": ["http:invoke"]}),
            serde_json::json!({"http_forward_profile": "mcp-2025-11-25"}),
            serde_json::json!({"http_forward_profile": "MCP-2026-07-28"}),
            serde_json::json!({"http_forward_profile": ["mcp-2026-07-28"]}),
            serde_json::json!({"http_forward_profile": null}),
            serde_json::json!("mcp-2026-07-28"),
        ] {
            assert!(exports.select(&capabilities).is_none(), "{capabilities}");
        }
        assert!(
            HttpForwardExports::new()
                .select(&serde_json::json!({"http_forward_profile": "mcp-2026-07-28"}))
                .is_none()
        );
        for id in ["", "MCP", "mcp 2026", "a/b", &"x".repeat(65)] {
            assert!(
                HttpForwardExports::new()
                    .with_profile(id, export())
                    .is_err(),
                "{id}"
            );
        }
        assert!(
            exports
                .clone()
                .with_profile("mcp-2026-07-28", export())
                .is_err()
        );
    }

    /// Review item 6 (resolved in gate 5): no interposer implementation
    /// exists in this crate, so exports carry none unless a caller attaches
    /// one explicitly, and the fixture hold is not a cargo feature that
    /// workspace feature unification could enable.
    #[test]
    fn exports_carry_no_interposer_unless_a_fixture_attaches_one() {
        let exports = HttpForwardExports::new()
            .with_profile("mcp-2026-07-28", export())
            .unwrap();
        assert!(!exports.has_fixture_interposer());
        let selected = exports
            .select(&serde_json::json!({"http_forward_profile": "mcp-2026-07-28"}))
            .unwrap();
        assert!(!selected.has_interposer());
        let manifest = include_str!("../../Cargo.toml");
        assert!(!manifest.contains("test-fixtures"), "the feature is gone");
    }

    /// An in-memory peer request direction.  The "network" is unbounded:
    /// only the hop credit and the per-peer aggregate may bound it.
    struct FakeSend {
        tx: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[allow(clippy::manual_async_fn)]
    impl PeerSendHalf for FakeSend {
        fn send_record<'a>(
            &'a mut self,
            body: &'a [u8],
        ) -> impl Future<Output = Result<(), PeerRuntimeError>> + Send + 'a {
            let sent = self.tx.send(body.to_vec());
            async move { sent.map_err(|_| PeerRuntimeError::Closed) }
        }

        fn finish(&mut self) -> impl Future<Output = Result<(), PeerRuntimeError>> + Send + '_ {
            async { Ok(()) }
        }

        fn cancel(&mut self) {}
    }

    struct FakeRecv {
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
        budget: StreamBudget,
    }

    #[allow(clippy::manual_async_fn)]
    impl PeerRecvHalf for FakeRecv {
        fn recv_record(
            &mut self,
            _deadline: tokio::time::Instant,
        ) -> impl Future<Output = Result<Option<PeerRecord>, PeerRuntimeError>> + Send + '_
        {
            async move {
                match self.rx.recv().await {
                    Some(body) => Ok(Some(
                        self.budget
                            .record_from_slice(PeerRecordKind::ConsumerChunk, &body)?,
                    )),
                    None => Ok(None),
                }
            }
        }

        fn cancel(&mut self) {}
    }

    struct HopPair {
        receiver_reader: PeerHopReader,
        _sender: PeerHop,
        _receiver: PeerHop,
        _sender_reader: PeerHopReader,
        _receiver_writer: PeerHopWriter,
    }

    fn hop_pair(
        send_aggregate: &Arc<HopAggregate>,
        receive_aggregate: &Arc<HopAggregate>,
    ) -> (PeerHopWriter, HopPair) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3_600);
        let (forward_tx, forward_rx) = mpsc::unbounded_channel();
        let (back_tx, back_rx) = mpsc::unbounded_channel();
        let connection = tunnel_cluster::peer_frame::ConnectionBudget::new();
        let (sender_writer, sender_reader, sender) = spawn_peer_hop(
            FakeSend { tx: forward_tx },
            FakeRecv {
                rx: back_rx,
                budget: connection.open_stream().expect("stream"),
            },
            deadline,
            Arc::clone(send_aggregate),
        );
        let (receiver_writer, receiver_reader, receiver) = spawn_peer_hop(
            FakeSend { tx: back_tx },
            FakeRecv {
                rx: forward_rx,
                budget: connection.open_stream().expect("stream"),
            },
            deadline,
            Arc::clone(receive_aggregate),
        );
        (
            sender_writer,
            HopPair {
                receiver_reader,
                _sender: sender,
                _receiver: receiver,
                _sender_reader: sender_reader,
                _receiver_writer: receiver_writer,
            },
        )
    }

    const STREAMS: usize = 40;
    const CHUNKS: usize = 8;
    const CHUNK: usize = 65_528;

    /// Saturate `STREAMS` hops to one peer whose receivers do not read, and
    /// return the peak in-flight and queued aggregate bytes.
    async fn saturate(limit: usize) -> (u64, u64, Vec<HopPair>, Vec<JoinHandle<bool>>) {
        let send_aggregate = HopAggregate::new(limit);
        let receive_aggregate = HopAggregate::new(limit);
        let mut pairs = Vec::new();
        let mut writers = Vec::new();
        for _ in 0..STREAMS {
            let (mut writer, pair) = hop_pair(&send_aggregate, &receive_aggregate);
            writers.push(tokio::spawn(async move {
                for _ in 0..CHUNKS {
                    if writer.data(Bytes::from(vec![7u8; CHUNK])).await.is_err() {
                        return false;
                    }
                }
                writer.finish().await.is_ok()
            }));
            pairs.push(pair);
        }
        // Virtual time: every task is blocked on credit once this elapses.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let (sent, _) = send_aggregate.current();
        let (_, queued) = receive_aggregate.current();
        (sent, queued, pairs, writers)
    }

    #[tokio::test(start_paused = true)]
    async fn many_saturated_http_hops_to_one_peer_share_one_connection_bound() {
        let window = PEER_HOP_WINDOW_BYTES as u64;
        // Red: without the shared bound every stream fills its own window,
        // which on one connection exceeds the per-direction share of the
        // 8 MiB ceiling.
        let (unbounded_sent, _, pairs, writers) = saturate(usize::MAX / 4).await;
        assert!(
            unbounded_sent > HOP_AGGREGATE_BYTES as u64,
            "control run must exceed the aggregate: {unbounded_sent}"
        );
        for writer in writers {
            writer.abort();
        }
        drop(pairs);

        // Green: the shared bound holds for the sender and the receiver.
        let (sent, queued, pairs, writers) = saturate(HOP_AGGREGATE_BYTES).await;
        assert!(sent <= HOP_AGGREGATE_BYTES as u64, "sent {sent}");
        assert!(queued <= HOP_AGGREGATE_BYTES as u64, "queued {queued}");
        assert!(
            sent + window > HOP_AGGREGATE_BYTES as u64,
            "the bound was reached, not met vacuously: {sent}"
        );
        // Draining every receiver lets every blocked writer finish: the
        // bound is backpressure, not failure.
        let mut readers = Vec::new();
        for pair in pairs {
            readers.push(tokio::spawn(async move {
                // Move the whole pair: dropping its other halves would reset
                // the stream.
                let mut pair = pair;
                let mut bytes = 0usize;
                loop {
                    match pair.receiver_reader.next().await {
                        CarrierEvent::Data(data) => bytes += data.len(),
                        CarrierEvent::Fin => return bytes,
                        other => panic!("unexpected hop event {other:?}"),
                    }
                }
            }));
        }
        for writer in writers {
            assert!(writer.await.expect("join"), "every write completed");
        }
        for reader in readers {
            assert_eq!(reader.await.expect("join"), CHUNKS * CHUNK);
        }
    }

    #[test]
    fn hop_records_round_trip_and_reject_mutations() {
        for record in [
            HopRecord::Data(Bytes::from_static(b"synthetic")),
            HopRecord::Fin,
            HopRecord::Reset(ResetDetail {
                code: HttpErrorCode::Cancelled,
                execution: Execution::Dispatched,
            }),
            HopRecord::Reset(ResetDetail {
                code: HttpErrorCode::DeadlineExceeded,
                execution: Execution::NotDispatched,
            }),
            HopRecord::Credit {
                bytes: 196_608,
                records: 3,
            },
        ] {
            assert_eq!(decode_hop(&encode_hop(&record)), Some(record));
        }
        assert_eq!(decode_hop(&[]), None);
        assert_eq!(decode_hop(&[TAG_DATA]), None);
        assert_eq!(decode_hop(&[TAG_FIN, 0]), None);
        assert_eq!(decode_hop(&[9]), None);
        // An unregistered reason, or one that disagrees with the detail, is
        // not a private extension: it is rejected.
        let mut reset = encode_hop(&HopRecord::Reset(ResetDetail {
            code: HttpErrorCode::Cancelled,
            execution: Execution::Unknown,
        }));
        reset[1..3].copy_from_slice(&reset_reason::ADAPTER_FAILURE.to_be_bytes());
        assert_eq!(decode_hop(&reset), None);
        reset[1..3].copy_from_slice(&9_999u16.to_be_bytes());
        assert_eq!(decode_hop(&reset), None);
        let oversized = vec![TAG_DATA; MAX_CONSUMER_PEER_BODY + 1];
        assert_eq!(decode_hop(&oversized), None);
    }

    #[test]
    fn export_path_uses_the_raw_target_after_the_http_segment() {
        let uri = http::Uri::from_static("/v1/devices/d/services/s/http/upload?x=1");
        assert_eq!(export_path(&uri).as_deref(), Some("/upload"));
        let encoded = http::Uri::from_static("/v1/devices/d/services/s/http/a%2Fb");
        assert_eq!(export_path(&encoded).as_deref(), Some("/a%2Fb"));
        let other = http::Uri::from_static("/v1/devices/d/services/s/httpx/upload");
        assert_eq!(export_path(&other), None);
    }

    #[test]
    fn only_verified_public_credentials_are_stripped() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer t"));
        headers.insert(header::COOKIE, HeaderValue::from_static("session=s"));
        headers.insert("proxy-authorization", HeaderValue::from_static("Basic x"));
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        strip_public_credentials(&mut headers);
        assert!(!headers.contains_key(header::AUTHORIZATION));
        assert!(!headers.contains_key(header::COOKIE));
        // Left for the codec to reject rather than silently laundered.
        assert!(headers.contains_key("proxy-authorization"));
        assert!(headers.contains_key("content-type"));
    }
}
