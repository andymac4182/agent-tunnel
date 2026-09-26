//! Bounded request collection, local responses and streaming response bodies.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::sync::mpsc;
use tunnel_mcp::message::{McpRejection, codes};

/// A boxed error carrying no payload.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// The response body every export returns.
pub type ExportBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// A payload-free body failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamFailure {
    /// The cumulative response limit was exceeded.
    Limit,
    /// The backend or child ended the stream before the final message.
    Interrupted,
}

impl std::fmt::Display for StreamFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "mcp export stream failed: {self:?}")
    }
}

impl std::error::Error for StreamFailure {}

/// Why a request body could not be collected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectError {
    TooLarge,
    Interrupted,
}

/// Collect a complete request body of at most `limit` bytes.
///
/// # Errors
/// [`CollectError::TooLarge`] as soon as the limit is exceeded (or a known
/// length already exceeds it); [`CollectError::Interrupted`] on a body error.
pub async fn collect_limited<B>(body: B, limit: u64) -> Result<Bytes, CollectError>
where
    B: Body<Data = Bytes>,
{
    if body.size_hint().lower() > limit {
        return Err(CollectError::TooLarge);
    }
    let mut body = std::pin::pin!(body);
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| CollectError::Interrupted)?;
        if let Ok(data) = frame.into_data() {
            if (out.len() as u64).saturating_add(data.len() as u64) > limit {
                return Err(CollectError::TooLarge);
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(out))
}

fn full(bytes: Bytes) -> ExportBody {
    http_body_util::Full::new(bytes)
        .map_err(|never| match never {})
        .boxed()
}

/// An empty body.
#[must_use]
pub fn empty() -> ExportBody {
    full(Bytes::new())
}

/// A complete `application/json` response.
#[must_use]
pub fn json_response(status: StatusCode, body: Bytes) -> Response<ExportBody> {
    let mut response = Response::new(full(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// A local rejection as a JSON-RPC error response.
#[must_use]
pub fn rejection(rejection: &McpRejection) -> Response<ExportBody> {
    let status = StatusCode::from_u16(rejection.status).unwrap_or(StatusCode::BAD_REQUEST);
    json_response(status, Bytes::from(rejection.body()))
}

/// A sanitized local failure with a fixed message.
#[must_use]
pub fn local_error(
    status: StatusCode,
    message: &'static str,
    id: Option<serde_json::Value>,
) -> Response<ExportBody> {
    rejection(&McpRejection {
        status: status.as_u16(),
        code: codes::INTERNAL_ERROR,
        message,
        id,
        supported: None,
    })
}

/// The `retryAfterMs` hint of a capacity refusal.  A slot frees when a
/// request completes, a legacy session is deleted or reaches its idle
/// expiry, or a child exits, so this is a backoff hint rather than a promise.
pub const CAPACITY_RETRY_AFTER_MS: u64 = 1_000;

/// The documented refusal of an export at its capacity bound (task row
/// M6-C145): `503`, JSON-RPC [`codes::CAPACITY_EXHAUSTED`], and `error.data`
/// of `{"retryable": true, "retryAfterMs": ..., "execution":
/// "not_dispatched"}`.  Nothing was started for the request, so a client may
/// retry it after the hint whatever its method.
///
/// It is not an internal error: before task row M6-C145 this answer was
/// `-32603`, which the M6-03 soak (M6-C122) recorded as a failure a client
/// cannot tell from a server bug.  The relay forwards response bodies but not
/// a `Retry-After` header (the MCP profiles do not allowlist it), so the hint
/// travels in the body.
#[must_use]
pub fn capacity_refusal(
    message: &'static str,
    id: Option<serde_json::Value>,
) -> Response<ExportBody> {
    let mut body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": codes::CAPACITY_EXHAUSTED,
            "message": message,
            "data": {
                "retryable": true,
                "retryAfterMs": CAPACITY_RETRY_AFTER_MS,
                "execution": "not_dispatched",
            },
        },
    });
    if let Some(id) = id {
        body["id"] = id;
    }
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default()),
    )
}

/// A bodyless response (202 Accepted, 204 No Content).
#[must_use]
pub fn no_body(status: StatusCode) -> Response<ExportBody> {
    let mut response = Response::new(empty());
    *response.status_mut() = status;
    response
}

/// Headers of an SSE response.
pub fn sse_head(response: &mut Response<ExportBody>) {
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    headers.insert(
        http::HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
}

/// Frame one compact JSON-RPC message as an SSE `data` event.  The compact
/// form never contains a line break.
#[must_use]
pub fn sse_event(compact: &[u8]) -> Bytes {
    let mut event = Vec::with_capacity(compact.len() + 8);
    event.extend_from_slice(b"data: ");
    event.extend_from_slice(compact);
    event.extend_from_slice(b"\n\n");
    Bytes::from(event)
}

/// Streaming response bodies are fed through this bounded queue.
pub const STREAM_QUEUE: usize = 8;

/// The sending half of a [`ChannelResponseBody`].
#[derive(Debug)]
pub struct StreamSender {
    tx: mpsc::Sender<Result<Bytes, StreamFailure>>,
}

impl StreamSender {
    /// Send bytes, waiting for queue room.  `Err` when the body was dropped.
    pub async fn send(&self, bytes: Bytes) -> Result<(), ()> {
        self.tx.send(Ok(bytes)).await.map_err(|_| ())
    }

    /// Fail the body (never a clean end).
    pub async fn fail(&self, failure: StreamFailure) {
        let _ = self.tx.send(Err(failure)).await;
    }

    /// Resolves once the receiving body was dropped (the consumer went away
    /// or the exchange was reset).
    pub async fn closed(&self) {
        self.tx.closed().await;
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// A response body fed by a bounded queue, failing once its cumulative
/// limit is exceeded.
#[derive(Debug)]
pub struct ChannelResponseBody {
    rx: mpsc::Receiver<Result<Bytes, StreamFailure>>,
    limit: u64,
    sent: u64,
    failed: bool,
    bytes: Arc<AtomicU64>,
}

impl ChannelResponseBody {
    /// A body limited to `limit` cumulative bytes, and its sender.
    #[must_use]
    pub fn channel(limit: u64, bytes: Arc<AtomicU64>) -> (StreamSender, Self) {
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        (
            StreamSender { tx },
            Self {
                rx,
                limit,
                sent: 0,
                failed: false,
                bytes,
            },
        )
    }
}

impl Body for ChannelResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(failure))) => {
                self.failed = true;
                Poll::Ready(Some(Err(Box::new(failure))))
            }
            Poll::Ready(Some(Ok(bytes))) => {
                let sent = self.sent.saturating_add(bytes.len() as u64);
                if sent > self.limit {
                    self.failed = true;
                    self.rx.close();
                    return Poll::Ready(Some(Err(Box::new(StreamFailure::Limit))));
                }
                self.sent = sent;
                self.bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn collection_stops_at_the_limit_and_accepts_exactly_the_limit() {
        let body = http_body_util::Full::new(Bytes::from_static(b"12345"));
        assert_eq!(collect_limited(body, 5).await.unwrap(), &b"12345"[..]);
        let body = http_body_util::Full::new(Bytes::from_static(b"123456"));
        assert_eq!(collect_limited(body, 5).await, Err(CollectError::TooLarge));
    }

    #[tokio::test]
    async fn a_streaming_body_fails_when_its_cumulative_limit_is_exceeded() {
        let counter = Arc::new(AtomicU64::new(0));
        let (tx, mut body) = ChannelResponseBody::channel(10, Arc::clone(&counter));
        tokio::spawn(async move {
            tx.send(Bytes::from_static(b"123456")).await.unwrap();
            tx.send(Bytes::from_static(b"7890")).await.unwrap();
            let _ = tx.send(Bytes::from_static(b"x")).await;
        });
        let mut body = Pin::new(&mut body);
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            &b"123456"[..]
        );
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            &b"7890"[..]
        );
        assert!(body.frame().await.unwrap().is_err());
        assert!(body.frame().await.is_none());
        assert_eq!(counter.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn sse_events_are_single_data_lines() {
        assert_eq!(sse_event(br#"{"a":1}"#), &b"data: {\"a\":1}\n\n"[..]);
    }
}
