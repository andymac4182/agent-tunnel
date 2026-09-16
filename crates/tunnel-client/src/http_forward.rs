//! Device-side `http-forward/1` exports (implementation gate 3 of
//! docs/http-forwarding.md).
//!
//! A connector serves an HTTP export by calling an in-process
//! [`HttpHandler`]: no local listener, address or socket is involved.  The
//! export must be both allowlisted in the runtime configuration (`type =
//! "http-forward"`) and registered with a handler through
//! [`crate::connect_with_http_handlers`]; the relay's OPEN cannot select
//! anything else.
//!
//! Each admitted stream runs the gate-2 bridge [`tunnel_http_bridge::serve`]
//! over two handoffs.  [`DeviceWriter`] and [`DeviceReader`] carry the
//! handoff frames to the connector actor, which keeps the logical stream's
//! sequence, credit and authorization state authoritative: received DATA is
//! released to the reader (and its WINDOW_UPDATE issued) only when the
//! handler side takes it, and a write waits in the actor for send credit.
//! A local RESET sends bounded `RESULT_STATUS` detail on the control socket
//! before the RESET is queued on the data socket.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use tokio::sync::{mpsc, oneshot};
use tunnel_http_bridge::{
    BridgeConfig, CarrierClosed, CarrierEvent, CarrierReader, CarrierWriter, ChannelBody,
    ExchangeReport, Profile, ResetDetail, ResetSignal, reset_reason_for, result_outcome,
};

/// A handler response body.
pub type HttpBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
/// A handler's future.
pub type HttpHandlerFuture =
    Pin<Box<dyn Future<Output = Result<Response<HttpBody>, HttpHandlerError>> + Send>>;

/// A handler failure.  It carries no message: the peer only ever learns a
/// sanitized code.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct HttpHandlerError;

impl std::fmt::Display for HttpHandlerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("http handler failed")
    }
}

impl std::error::Error for HttpHandlerError {}

/// An in-process HTTP handler for one export.
pub trait HttpHandler: Send + Sync + 'static {
    fn call(&self, request: Request<ChannelBody>) -> HttpHandlerFuture;
}

impl<F> HttpHandler for F
where
    F: Fn(Request<ChannelBody>) -> HttpHandlerFuture + Send + Sync + 'static,
{
    fn call(&self, request: Request<ChannelBody>) -> HttpHandlerFuture {
        self(request)
    }
}

/// One registered export: its profile, bridge limits and handler.
#[derive(Clone)]
pub struct HttpExport {
    pub profile: Arc<Profile>,
    pub config: BridgeConfig,
    pub handler: Arc<dyn HttpHandler>,
}

impl std::fmt::Debug for HttpExport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpExport")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The most recent device exchange records retained.
pub const MAX_DEVICE_HTTP_RECORDS: usize = 64;

/// Payload-free queue high-water marks for one device-side exchange.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceHttpExchangeRecord {
    pub stream_id: u64,
    pub service_id: String,
    /// Owner→device bytes buffered in the connector actor for the reader.
    pub receive_buffer_high_water: usize,
    /// The stream's advertised receive window.
    pub receive_window: u64,
    /// Device→owner bytes parked in the actor for send credit.
    pub parked_bytes_high_water: usize,
    /// Carrier→bridge request handoff.
    pub request_handoff_high_water: usize,
    /// Bridge→carrier response handoff.
    pub response_handoff_high_water: usize,
    /// The handler's request body queue.
    pub request_body_high_water: usize,
    pub report: Option<ExchangeReport>,
    /// The device record log: request record headers the connector actor
    /// received in order (after sequence deduplication), BODY octets, and
    /// whether the ordered request FIN arrived.  Payload-free.
    pub request_heads: u32,
    pub request_bodies: u64,
    pub request_ends: u32,
    pub request_body_bytes: u64,
    pub request_fin_received: bool,
    pub request_framing_invalid: bool,
    /// The owner sent a control `CANCEL` for this stream.
    pub cancel_received: bool,
}

/// Shared bounded device diagnostics.
#[derive(Clone, Debug, Default)]
pub struct DeviceHttpDiagnostics {
    records: Arc<Mutex<VecDeque<DeviceHttpExchangeRecord>>>,
}

impl DeviceHttpDiagnostics {
    pub(crate) fn record(&self, record: DeviceHttpExchangeRecord) {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if records.len() >= MAX_DEVICE_HTTP_RECORDS {
            records.pop_front();
        }
        records.push_back(record);
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<DeviceHttpExchangeRecord> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }
}

/// Read access to the payload-free counters of registered MCP exports.
#[derive(Clone, Debug, Default)]
pub struct McpExportDiagnostics {
    exports: BTreeMap<String, tunnel_mcp_export::McpExport>,
}

impl McpExportDiagnostics {
    /// The counters of the export registered for `service_id`.
    #[must_use]
    pub fn get(&self, service_id: &str) -> Option<tunnel_mcp_export::ExportDiagnostics> {
        self.exports
            .get(service_id)
            .map(tunnel_mcp_export::McpExport::diagnostics)
    }
}

/// The handler registry passed to [`crate::connect_with_http_handlers`].
#[derive(Clone, Debug, Default)]
pub struct HttpHandlers {
    exports: BTreeMap<String, HttpExport>,
    diagnostics: DeviceHttpDiagnostics,
    /// The registered MCP exports, kept only for their payload-free counters.
    mcp: BTreeMap<String, tunnel_mcp_export::McpExport>,
}

/// Ending the registry ends the protocol sessions it served.
///
/// A registered MCP export is also held by [`McpExportDiagnostics`], so the
/// export's own `Drop` cannot be relied on to run when the connector stops.
/// This is the connector's explicit teardown: every MCP export ends its open
/// protocol sessions and kills each session child's process group, so a
/// session nobody ended cannot outlive the device session it was served on
/// (M3-04).
impl Drop for HttpHandlers {
    fn drop(&mut self) {
        for export in self.mcp.values() {
            export.shutdown();
        }
    }
}

impl HttpHandlers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the handler for the export whose catalog service identifier
    /// is `service_id`.
    #[must_use]
    pub fn with_export(mut self, service_id: impl Into<String>, export: HttpExport) -> Self {
        self.exports.insert(service_id.into(), export);
        self
    }

    pub(crate) fn export(&self, service_id: &str) -> Option<&HttpExport> {
        self.exports.get(service_id)
    }

    /// Whether a handler is registered for `service_id`.
    #[must_use]
    pub fn contains(&self, service_id: &str) -> bool {
        self.exports.contains_key(service_id)
    }

    /// Register every `[exports.<service>.mcp]` export of a validated
    /// runtime configuration (M3-02).  Each export carries its selected MCP
    /// profile's `http-forward/1` policies, so the device validates heads
    /// against exactly the allowlist the relay enforces, and every request is
    /// buffered and validated before the stdio child or fixed local server is
    /// invoked.  A Streamable HTTP export reads its bearer token file here.
    ///
    /// # Errors
    /// The first export configuration rule violated.
    pub fn with_mcp_exports(
        mut self,
        config: &crate::RuntimeConfig,
    ) -> Result<Self, tunnel_mcp_export::McpConfigError> {
        for (service_id, export) in &config.exports {
            let Some(mcp) = &export.mcp else { continue };
            if export.kind != crate::ExportKind::HttpForward {
                return Err(tunnel_mcp_export::McpConfigError(
                    "an mcp table is only valid on an http-forward export",
                ));
            }
            let mcp_export = tunnel_mcp_export::McpExport::from_config(mcp)?;
            let profile = mcp_export.profile_policies().map_err(|_| {
                tunnel_mcp_export::McpConfigError("the pinned MCP profile tables are inconsistent")
            })?;
            self.mcp.insert(service_id.clone(), mcp_export.clone());
            let handler_export = mcp_export.clone();
            let handler = move |request: Request<ChannelBody>| -> HttpHandlerFuture {
                let export = handler_export.clone();
                Box::pin(async move { export.handle(request).await.map_err(|_| HttpHandlerError) })
            };
            self.exports.insert(
                service_id.clone(),
                HttpExport {
                    profile: Arc::new(profile),
                    config: BridgeConfig::default(),
                    handler: Arc::new(handler),
                },
            );
        }
        Ok(self)
    }

    /// A shareable view of every registered MCP export's payload-free
    /// counters (children, sessions, interruptions, cancellation
    /// notifications; never arguments, environment or bodies).  It stays
    /// valid after the handlers move into
    /// [`crate::connect_with_http_handlers`].
    #[must_use]
    pub fn mcp_diagnostics_source(&self) -> McpExportDiagnostics {
        McpExportDiagnostics {
            exports: self.mcp.clone(),
        }
    }

    /// The bounded device-side exchange records.
    #[must_use]
    pub fn diagnostics(&self) -> DeviceHttpDiagnostics {
        self.diagnostics.clone()
    }
}

/// One ordered read from the connector actor.
#[derive(Debug)]
pub(crate) enum DeviceRead {
    Data(Vec<u8>),
    Fin,
    Reset(u16),
    Closed,
}

/// Requests an exchange task sends to the connector actor.
#[derive(Debug)]
pub(crate) enum HttpActorRequest {
    Read {
        stream_id: u64,
        reply: oneshot::Sender<DeviceRead>,
    },
    Write {
        stream_id: u64,
        data: Vec<u8>,
        reply: oneshot::Sender<bool>,
    },
    Finish {
        stream_id: u64,
        reply: oneshot::Sender<bool>,
    },
    Reset {
        stream_id: u64,
        reason: u16,
        outcome: &'static str,
        code: &'static str,
        execution: &'static str,
        reply: oneshot::Sender<bool>,
    },
    Done {
        record: DeviceHttpExchangeRecord,
    },
}

/// A sink for actor requests (the actor's bounded event channel).
pub(crate) trait ActorSink: Clone + Send + Sync + 'static {
    fn send(&self, request: HttpActorRequest) -> impl Future<Output = bool> + Send;
}

impl ActorSink for mpsc::Sender<HttpActorRequest> {
    fn send(&self, request: HttpActorRequest) -> impl Future<Output = bool> + Send {
        let sender = self.clone();
        async move { sender.send(request).await.is_ok() }
    }
}

/// Writes the bridge's response direction to the connector actor.
pub(crate) struct DeviceWriter<S> {
    pub(crate) sink: S,
    pub(crate) stream_id: u64,
}

impl<S: ActorSink> CarrierWriter for DeviceWriter<S> {
    fn data(&mut self, data: Bytes) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        let sink = self.sink.clone();
        let stream_id = self.stream_id;
        async move {
            let (reply, receiver) = oneshot::channel();
            if !sink
                .send(HttpActorRequest::Write {
                    stream_id,
                    data: data.to_vec(),
                    reply,
                })
                .await
            {
                return Err(CarrierClosed);
            }
            match receiver.await {
                Ok(true) => Ok(()),
                _ => Err(CarrierClosed),
            }
        }
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        let sink = self.sink.clone();
        let stream_id = self.stream_id;
        async move {
            let (reply, receiver) = oneshot::channel();
            if !sink
                .send(HttpActorRequest::Finish { stream_id, reply })
                .await
            {
                return Err(CarrierClosed);
            }
            match receiver.await {
                Ok(true) => Ok(()),
                _ => Err(CarrierClosed),
            }
        }
    }

    fn reset(&mut self, detail: ResetDetail) -> impl Future<Output = ()> + Send {
        let sink = self.sink.clone();
        let stream_id = self.stream_id;
        async move {
            let (reply, receiver) = oneshot::channel();
            if sink
                .send(HttpActorRequest::Reset {
                    stream_id,
                    reason: reset_reason_for(detail),
                    outcome: result_outcome(detail),
                    code: detail.code.as_str(),
                    execution: detail.execution.as_str(),
                    reply,
                })
                .await
            {
                let _ = receiver.await;
            }
        }
    }
}

/// Reads the bridge's request direction from the connector actor.
/// Cancel-safe: an outstanding read survives a dropped `next` future.
pub(crate) struct DeviceReader<S> {
    pub(crate) sink: S,
    pub(crate) stream_id: u64,
    pub(crate) signal: ResetSignal,
    pub(crate) pending: Option<oneshot::Receiver<DeviceRead>>,
}

impl<S: ActorSink> CarrierReader for DeviceReader<S> {
    #[allow(clippy::manual_async_fn)]
    fn next(&mut self) -> impl Future<Output = CarrierEvent> + Send {
        async move {
            loop {
                if self.pending.is_none() {
                    let (reply, receiver) = oneshot::channel();
                    if !self
                        .sink
                        .send(HttpActorRequest::Read {
                            stream_id: self.stream_id,
                            reply,
                        })
                        .await
                    {
                        return CarrierEvent::Closed;
                    }
                    self.pending = Some(receiver);
                }
                let Some(receiver) = self.pending.as_mut() else {
                    return CarrierEvent::Closed;
                };
                let read = receiver.await.unwrap_or(DeviceRead::Closed);
                self.pending = None;
                match read {
                    DeviceRead::Data(data) if data.is_empty() => {}
                    DeviceRead::Data(data) => return CarrierEvent::Data(Bytes::from(data)),
                    DeviceRead::Fin => return CarrierEvent::Fin,
                    DeviceRead::Reset(reason) => {
                        return CarrierEvent::Reset(tunnel_http_bridge::detail_from_reason(reason));
                    }
                    DeviceRead::Closed => return CarrierEvent::Closed,
                }
            }
        }
    }

    fn reset_signal(&self) -> ResetSignal {
        self.signal.clone()
    }
}
