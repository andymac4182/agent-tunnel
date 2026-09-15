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

use crate::stream::QueueStats;

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
    stats: Arc<QueueStats>,
}

/// The pump's half.
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
        let len = data.len();
        // Charged before the send so the reader never releases bytes that
        // were not yet counted.
        self.shared.stats.add(len);
        self.tx.send(data).await.map_err(|_| {
            self.shared.stats.sub(len);
            BodyClosed
        })
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

impl fmt::Debug for BodySender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BodySender")
            .field(
                "queued_chunks",
                &(self.tx.max_capacity() - self.tx.capacity()),
            )
            .finish()
    }
}

/// A streaming body backed by a bounded queue.  `Debug` prints no bytes.
pub struct ChannelBody {
    rx: Option<mpsc::Receiver<Bytes>>,
    shared: Arc<Shared>,
    length: Option<u64>,
    done: bool,
    /// Octets handed to the reader so far.
    delivered: u64,
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
            delivered: 0,
            on_drop,
        };
        (sender, body)
    }

    /// Byte accounting for chunks queued between the pump and this body's
    /// reader: the current occupancy and its high-water mark.
    #[must_use]
    pub fn stats(&self) -> Arc<QueueStats> {
        Arc::clone(&self.shared.stats)
    }

    /// A complete body of known bytes.
    #[must_use]
    pub fn full(data: Bytes) -> Self {
        let length = data.len() as u64;
        let (sender, body) = Self::channel(1, Some(length), None);
        if !data.is_empty() {
            // A fresh one-slot queue always has room.
            sender.shared.stats.add(data.len());
            let _ = sender.tx.try_send(data);
        }
        sender.finish();
        body
    }
}

impl fmt::Debug for ChannelBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelBody")
            .field(
                "queued_chunks",
                &self.rx.as_ref().map_or(0, mpsc::Receiver::len),
            )
            .field("length", &self.length)
            .field("done", &self.done)
            .finish()
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
            Poll::Ready(Some(data)) => {
                this.shared.stats.sub(data.len());
                this.delivered = this.delivered.saturating_add(data.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
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
    /// Dropping an unfinished body cancels the exchange, except when the
    /// reader already took every octet of a declared length: an HTTP server
    /// stops polling at the declared length, before END and FIN arrive, and
    /// that is not the consumer going away.  The exchange then completes (or
    /// fails) on its own END and FIN, which the owner's response pump bounds
    /// with the FIN-after-END budget from the last declared byte.
    fn drop(&mut self) {
        let fully_delivered = self.length == Some(self.delivered);
        if self.shared.terminal.get().is_none()
            && !fully_delivered
            && let Some(token) = &self.on_drop
        {
            token.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn dropping_a_fully_delivered_declared_body_is_not_a_cancellation() {
        let token = CancellationToken::new();
        let (sender, mut body) = ChannelBody::channel(2, Some(3), Some(token.clone()));
        sender.send(Bytes::from_static(b"abc")).await.expect("send");
        let frame = body.frame().await.expect("frame").expect("data");
        assert_eq!(frame.into_data().expect("data").as_ref(), b"abc");
        // The server stops at the declared length before END and FIN.
        drop(body);
        assert!(!token.is_cancelled());
        drop(sender);

        let token = CancellationToken::new();
        let (sender, mut body) = ChannelBody::channel(2, Some(6), Some(token.clone()));
        sender.send(Bytes::from_static(b"abc")).await.expect("send");
        let _ = body.frame().await;
        drop(body);
        assert!(token.is_cancelled(), "a short read is a consumer departure");
        drop(sender);

        let token = CancellationToken::new();
        let (_sender, body) = ChannelBody::channel(2, None, Some(token.clone()));
        drop(body);
        assert!(token.is_cancelled(), "an unknown length ends only at FIN");
    }
}
