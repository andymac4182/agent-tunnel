//! A bounded streaming HTTP body fed by a pump.
//!
//! The body ends cleanly only when the pump calls [`BodySender::finish`],
//! which it does after the direction's END and FIN.  A dropped sender or a
//! [`BodySender::fail`] yields an error frame, so truncation can never look
//! like a successful end.

use core::fmt;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tunnel_http_forward::HttpErrorCode;

/// A body stream error.  It carries only the sanitized code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BodyError {
    code: HttpErrorCode,
}

impl BodyError {
    #[must_use]
    pub const fn code(&self) -> HttpErrorCode {
        self.code
    }
}

impl fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "http-forward body failed: {}", self.code)
    }
}

impl std::error::Error for BodyError {}

#[derive(Clone, Copy, Debug)]
enum Terminal {
    End,
    Error(HttpErrorCode),
}

#[derive(Debug, Default)]
struct Shared {
    terminal: OnceLock<Terminal>,
}

/// The pump's half.
#[derive(Debug)]
pub struct BodySender {
    tx: mpsc::Sender<Bytes>,
    shared: Arc<Shared>,
}

/// The receiver dropped the body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyClosed;

impl BodySender {
    /// Deliver one chunk, waiting for queue capacity.
    ///
    /// # Errors
    /// [`BodyClosed`] when the body was dropped.
    pub async fn send(&self, data: Bytes) -> Result<(), BodyClosed> {
        self.tx.send(data).await.map_err(|_| BodyClosed)
    }

    /// End the body successfully after already queued chunks.
    pub fn finish(self) {
        let _ = self.shared.terminal.set(Terminal::End);
    }

    /// Fail the body; the error is visible on the next poll.
    pub fn fail(self, code: HttpErrorCode) {
        let _ = self.shared.terminal.set(Terminal::Error(code));
    }
}

/// A streaming body backed by a bounded queue.
#[derive(Debug)]
pub struct ChannelBody {
    rx: Option<mpsc::Receiver<Bytes>>,
    shared: Arc<Shared>,
    length: Option<u64>,
    done: bool,
    on_drop: Option<CancellationToken>,
}

impl ChannelBody {
    /// A body of `queue` chunks.  `length` is the checked exact length, if
    /// declared.  `on_drop` is cancelled if the body is dropped before the
    /// pump ends or fails it.
    #[must_use]
    pub fn channel(
        queue: usize,
        length: Option<u64>,
        on_drop: Option<CancellationToken>,
    ) -> (BodySender, Self) {
        let (tx, rx) = mpsc::channel(queue.max(1));
        let shared = Arc::new(Shared::default());
        let sender = BodySender {
            tx,
            shared: Arc::clone(&shared),
        };
        let body = Self {
            rx: Some(rx),
            shared,
            length,
            done: false,
            on_drop,
        };
        (sender, body)
    }

    /// A complete body of known bytes.
    #[must_use]
    pub fn full(data: Bytes) -> Self {
        let length = data.len() as u64;
        let (sender, body) = Self::channel(1, Some(length), None);
        if !data.is_empty() {
            // A fresh one-slot queue always has room.
            let _ = sender.tx.try_send(data);
        }
        sender.finish();
        body
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        if this.done {
            return Poll::Ready(None);
        }
        // Chunks queued before a failure were received in order and are
        // delivered first; the queue is bounded, so the error follows
        // promptly.  `fail` drops the sender, which closes the queue.
        let Some(rx) = this.rx.as_mut() else {
            this.done = true;
            return Poll::Ready(None);
        };
        match rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(data)) => Poll::Ready(Some(Ok(Frame::data(data)))),
            Poll::Ready(None) => {
                this.done = true;
                match this.shared.terminal.get() {
                    Some(Terminal::End) => Poll::Ready(None),
                    Some(Terminal::Error(code)) => {
                        Poll::Ready(Some(Err(BodyError { code: *code })))
                    }
                    None => Poll::Ready(Some(Err(BodyError {
                        code: HttpErrorCode::StreamInterrupted,
                    }))),
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        self.length
            .map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

impl Drop for ChannelBody {
    fn drop(&mut self) {
        if self.shared.terminal.get().is_none()
            && let Some(token) = &self.on_drop
        {
            token.cancel();
        }
    }
}
