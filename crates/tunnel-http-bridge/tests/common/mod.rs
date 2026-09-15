//! Synthetic fixtures: a test profile allowlist, controllable bodies, an
//! in-process owner/device pair joined by bounded channels, and frame taps.
//!
//! The profile below is a test fixture only.  The enumerated per-profile
//! ACP/MCP allowlists are implementation-gate-5 work.
#![allow(dead_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use http_body::{Body, Frame as BodyFrame, SizeHint};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tunnel_http_bridge::{
    BodyError, BridgeConfig, ChannelBody, ExchangeHandle, ExchangeReport, Frame, FrameReceiver,
    FrameSender, Profile, QueueStats, channel, forward, serve,
};
use tunnel_http_forward::{
    HttpVersion, Method, Occurrence, RecordDecoder, RecordEvent, RecordKind, RequestPolicy,
    ResponsePolicy,
};

pub const REQUEST_LIMIT: u64 = 1024 * 1024;
pub const RESPONSE_LIMIT: u64 = 64 * 1024 * 1024;
/// Default DATA credit per direction, matching the 256 KiB per-stream
/// starting budget in cluster.md.
pub const STREAM_CREDIT: usize = 256 * 1024;

pub fn profile() -> Arc<Profile> {
    let mut request = RequestPolicy::new(REQUEST_LIMIT).unwrap();
    for (method, path) in [
        (Method::Post, "/upload"),
        (Method::Post, "/echo"),
        (Method::Get, "/events"),
        (Method::Head, "/events"),
        (Method::Get, "/status"),
    ] {
        request.allow_route(method, path).unwrap();
    }
    request.allow_http_version(HttpVersion::Http11);
    request.allow_http_version(HttpVersion::Http2);
    request.query.allow("code", Occurrence::Singleton).unwrap();
    for name in ["content-type", "content-encoding", "x-case"] {
        request.headers.allow(name, Occurrence::Singleton).unwrap();
    }
    request
        .headers
        .allow("accept", Occurrence::Repeatable)
        .unwrap();

    let mut response = ResponsePolicy::new(RESPONSE_LIMIT).unwrap();
    for name in ["content-type", "content-encoding", "etag", "x-case"] {
        response.headers.allow(name, Occurrence::Singleton).unwrap();
    }
    response
        .headers
        .allow("cache-control", Occurrence::Repeatable)
        .unwrap();
    Arc::new(Profile { request, response })
}

/// A synthetic error with no content.
#[derive(Debug)]
pub struct TestError;

impl std::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("synthetic body failure")
    }
}

impl std::error::Error for TestError {}

pub type BodyTx = mpsc::Sender<Result<BodyFrame<Bytes>, TestError>>;

/// A body driven frame by frame by the test.
pub struct TestBody {
    rx: mpsc::Receiver<Result<BodyFrame<Bytes>, TestError>>,
    exact: Option<u64>,
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = TestError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<BodyFrame<Bytes>, TestError>>> {
        self.rx.poll_recv(cx)
    }

    fn size_hint(&self) -> SizeHint {
        self.exact
            .map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

pub fn test_body(capacity: usize) -> (BodyTx, TestBody) {
    let (tx, rx) = mpsc::channel(capacity);
    (tx, TestBody { rx, exact: None })
}

/// A finished body of the given frames.
pub fn frames_body(
    frames: Vec<Result<BodyFrame<Bytes>, TestError>>,
    exact: Option<u64>,
) -> TestBody {
    let (tx, rx) = mpsc::channel(frames.len().max(1));
    for frame in frames {
        tx.try_send(frame).unwrap();
    }
    TestBody { rx, exact }
}

pub fn data(bytes: &[u8]) -> Result<BodyFrame<Bytes>, TestError> {
    Ok(BodyFrame::data(Bytes::copy_from_slice(bytes)))
}

pub fn trailers(name: &'static str, value: &'static str) -> Result<BodyFrame<Bytes>, TestError> {
    let mut map = HeaderMap::new();
    map.insert(name, http::HeaderValue::from_static(value));
    Ok(BodyFrame::trailers(map))
}

pub fn empty_body() -> TestBody {
    frames_body(Vec::new(), None)
}

pub fn full(bytes: &[u8]) -> TestBody {
    frames_body(vec![data(bytes)], Some(bytes.len() as u64))
}

/// Poll `value` every 50 ms until it is unchanged for three consecutive
/// polls, within the overall test bound, and return the stable value.
pub async fn wait_until_stable<T: PartialEq + Copy>(value: impl Fn() -> T) -> T {
    within(async {
        let mut last = value();
        let mut stable = 0;
        while stable < 3 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let now = value();
            if now == last {
                stable += 1;
            } else {
                stable = 0;
                last = now;
            }
        }
        last
    })
    .await
}

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("step finished within the test bound")
}

/// Collect a body, returning its bytes or its first error.
pub async fn collect<B>(body: B) -> Result<Vec<u8>, B::Error>
where
    B: Body<Data = Bytes>,
{
    let mut body = std::pin::pin!(body);
    let mut out = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
        if let Ok(chunk) = frame?.into_data() {
            out.extend_from_slice(&chunk);
        }
    }
    Ok(out)
}

pub async fn next_chunk(body: &mut ChannelBody) -> Option<Result<Bytes, BodyError>> {
    loop {
        let frame = std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await?;
        match frame {
            Ok(frame) => {
                if let Ok(chunk) = frame.into_data() {
                    return Some(Ok(chunk));
                }
            }
            Err(error) => return Some(Err(error)),
        }
    }
}

/// Both directions of one logical stream.
pub struct Link {
    pub to_device: FrameSender,
    pub device_rx: FrameReceiver,
    pub to_owner: FrameSender,
    pub owner_rx: FrameReceiver,
    pub request_stats: Arc<QueueStats>,
    pub response_stats: Arc<QueueStats>,
}

pub fn link(credit: usize) -> Link {
    let (to_device, device_rx, request_stats) = channel(credit);
    let (to_owner, owner_rx, response_stats) = channel(credit);
    Link {
        to_device,
        device_rx,
        to_owner,
        owner_rx,
        request_stats,
        response_stats,
    }
}

pub fn request<B>(method: &str, uri: &str, headers: &[(&str, &str)], body: B) -> Request<B> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(body).unwrap()
}

pub struct Running {
    pub response: Response<ChannelBody>,
    pub handle: ExchangeHandle,
    pub device: JoinHandle<ExchangeReport>,
}

/// Run the owner and device adapters in process over `link`.
pub async fn exchange<RB, H, F, B, E>(
    request: Request<RB>,
    link: Link,
    config: BridgeConfig,
    handler: H,
) -> Running
where
    RB: Body<Data = Bytes> + Send + 'static,
    H: FnOnce(Request<ChannelBody>) -> F + Send + 'static,
    F: Future<Output = Result<Response<B>, E>> + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    E: Send + 'static,
{
    exchange_with(request, link, config, config, profile(), handler).await
}

/// As [`exchange`], with separate device configuration and profile.
pub async fn exchange_with<RB, H, F, B, E>(
    request: Request<RB>,
    link: Link,
    owner_config: BridgeConfig,
    device_config: BridgeConfig,
    device_profile: Arc<Profile>,
    handler: H,
) -> Running
where
    RB: Body<Data = Bytes> + Send + 'static,
    H: FnOnce(Request<ChannelBody>) -> F + Send + 'static,
    F: Future<Output = Result<Response<B>, E>> + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    E: Send + 'static,
{
    let Link {
        to_device,
        device_rx,
        to_owner,
        owner_rx,
        ..
    } = link;
    let device = tokio::spawn(serve(
        device_profile,
        device_config,
        device_rx,
        to_owner,
        handler,
    ));
    let (response, handle) = within(forward(
        request,
        profile(),
        owner_config,
        to_device,
        owner_rx,
    ))
    .await;
    Running {
        response,
        handle,
        device,
    }
}

/// Everything a tap observed on one direction.
#[derive(Debug, Default)]
pub struct TapLog {
    pub bytes: Vec<u8>,
    pub fin: bool,
    pub reset: Option<tunnel_http_bridge::ResetDetail>,
    pub closed_without_terminal: bool,
}

impl TapLog {
    pub fn record_kinds(&self) -> Vec<RecordKind> {
        record_kinds(&self.bytes)
    }
}

/// Total BODY payload bytes in a record stream.
pub fn body_bytes(bytes: &[u8]) -> usize {
    let mut decoder = RecordDecoder::new();
    let mut input = bytes;
    let mut total = 0;
    while let Ok(Some(event)) = decoder.decode(&mut input) {
        if let RecordEvent::Body { data, .. } = event {
            total += data.len();
        }
    }
    total
}

pub fn record_kinds(bytes: &[u8]) -> Vec<RecordKind> {
    let mut decoder = RecordDecoder::new();
    let mut input = bytes;
    let mut kinds = Vec::new();
    while let Ok(Some(event)) = decoder.decode(&mut input) {
        if let RecordEvent::Header(header) = event {
            kinds.push(header.kind());
        }
    }
    kinds
}

/// Forward frames from `rx` to a fresh bounded direction, recording them and
/// re-cutting DATA at the given absolute byte offsets.
pub fn tap(
    rx: FrameReceiver,
    credit: usize,
    cuts: Vec<usize>,
) -> (FrameReceiver, Arc<Mutex<TapLog>>) {
    tap_with_reset_delay(rx, credit, cuts, Duration::ZERO)
}

/// As [`tap`], but a RESET is held for `reset_delay` before it is forwarded:
/// a slow carrier for the terminal frame.
pub fn tap_with_reset_delay(
    mut rx: FrameReceiver,
    credit: usize,
    cuts: Vec<usize>,
    reset_delay: Duration,
) -> (FrameReceiver, Arc<Mutex<TapLog>>) {
    let (out, out_rx, _) = channel(credit);
    let log = Arc::new(Mutex::new(TapLog::default()));
    let task_log = Arc::clone(&log);
    tokio::spawn(async move {
        let mut signal = rx.reset_signal();
        let mut offset = 0usize;
        loop {
            let Some(frame) = rx.recv().await else {
                let mut log = task_log.lock().unwrap();
                if !log.fin && log.reset.is_none() {
                    log.closed_without_terminal = true;
                }
                return;
            };
            match frame {
                Frame::Data(mut bytes) => {
                    task_log.lock().unwrap().bytes.extend_from_slice(&bytes);
                    let end = offset + bytes.len();
                    let mut pieces = Vec::new();
                    for &cut in cuts.iter().filter(|cut| **cut > offset && **cut < end) {
                        let consumed = end - bytes.len();
                        pieces.push(bytes.split_to(cut - consumed));
                    }
                    pieces.push(bytes);
                    offset = end;
                    for piece in pieces {
                        // In-order delivery first; the early-reset signal
                        // only matters while the next hop is stalled.
                        tokio::select! {
                            biased;
                            sent = out.send_data(piece) => if sent.is_err() { return },
                            // Only a RESET sent before the source's FIN: a
                            // FIN-then-RESET is forwarded in order, FIN first.
                            detail = signal.wait_before_fin() => {
                                task_log.lock().unwrap().reset = Some(detail);
                                tokio::time::sleep(reset_delay).await;
                                out.reset(detail);
                                return;
                            }
                        }
                    }
                }
                Frame::Fin => {
                    task_log.lock().unwrap().fin = true;
                    let _ = out.finish();
                }
                Frame::Reset(detail) => {
                    task_log.lock().unwrap().reset = Some(detail);
                    tokio::time::sleep(reset_delay).await;
                    out.reset(detail);
                    return;
                }
            }
        }
    });
    (out_rx, log)
}
