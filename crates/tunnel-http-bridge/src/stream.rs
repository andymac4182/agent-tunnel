//! A bounded in-process stand-in for one direction of a logical tunnel
//! stream.
//!
//! DATA is charged byte-for-byte against a credit semaphore that is released
//! only when the receiver takes the frame, so a sender cannot outrun its
//! receiver.  FIN and RESET are ordered behind earlier DATA but use two
//! reserved queue slots, so exhausted byte credit can never block them.  Any
//! RESET also raises an out-of-band [`ResetSignal`], standing in for scoped
//! control cancellation: a receiver stalled on its own downstream can stop
//! work before the queued RESET reaches it, even when the RESET is queued
//! behind an earlier FIN.

use core::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};

use crate::status::ResetDetail;

/// One ordered item of the stream.  `Debug` prints DATA lengths only.
#[derive(Clone, Eq, PartialEq)]
pub enum Frame {
    Data(Bytes),
    Fin,
    Reset(ResetDetail),
}

impl fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(data) => formatter
                .debug_struct("Data")
                .field("payload_len", &data.len())
                .finish(),
            Self::Fin => formatter.write_str("Fin"),
            Self::Reset(detail) => formatter.debug_tuple("Reset").field(detail).finish(),
        }
    }
}

/// What the peer's RESET signal carries.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SignaledReset {
    pub detail: ResetDetail,
    /// The peer had already queued FIN for this direction, so every earlier
    /// DATA frame of the direction is complete.
    pub after_fin: bool,
}

/// Byte accounting for the queue, for tests and diagnostics.
#[derive(Debug, Default)]
pub struct QueueStats {
    queued: AtomicUsize,
    high_water: AtomicUsize,
}

impl QueueStats {
    /// DATA bytes currently queued.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::SeqCst)
    }

    /// The largest number of DATA bytes ever queued at once.
    #[must_use]
    pub fn high_water(&self) -> usize {
        self.high_water.load(Ordering::SeqCst)
    }

    fn add(&self, len: usize) {
        let now = self.queued.fetch_add(len, Ordering::SeqCst) + len;
        self.high_water.fetch_max(now, Ordering::SeqCst);
    }

    fn sub(&self, len: usize) {
        self.queued.fetch_sub(len, Ordering::SeqCst);
    }
}

struct Envelope {
    frame: Option<Frame>,
    len: usize,
    stats: Arc<QueueStats>,
    _credit: Option<OwnedSemaphorePermit>,
}

impl Drop for Envelope {
    fn drop(&mut self) {
        self.stats.sub(self.len);
    }
}

const OPEN: u8 = 0;
const FIN: u8 = 1;
const RESET: u8 = 2;

struct SenderState {
    state: AtomicU8,
    signal: watch::Sender<Option<SignaledReset>>,
}

/// Why a send did not happen.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SendError {
    /// The receiver is gone (carrier failure).
    Closed,
    /// This direction already sent FIN or RESET.
    Terminated,
}

/// The sending half.  Clones share one direction state, so FIN and RESET are
/// each emitted at most once however many tasks hold a clone.
#[derive(Clone)]
pub struct FrameSender {
    tx: mpsc::Sender<Envelope>,
    credit: Arc<Semaphore>,
    capacity: usize,
    state: Arc<SenderState>,
    stats: Arc<QueueStats>,
}

impl FrameSender {
    /// Queue DATA, waiting for byte credit.  Data larger than the credit
    /// capacity is split; splits carry no meaning to the record decoder.
    ///
    /// # Errors
    /// [`SendError::Terminated`] after FIN or RESET, or
    /// [`SendError::Closed`] when the receiver is gone.
    pub async fn send_data(&self, mut data: Bytes) -> Result<(), SendError> {
        while !data.is_empty() {
            if self.state.state.load(Ordering::SeqCst) != OPEN {
                return Err(SendError::Terminated);
            }
            let take = data.len().min(self.capacity);
            let chunk = data.split_to(take);
            // `capacity` is clamped to u32 at construction.
            let permits = u32::try_from(take).map_err(|_| SendError::Closed)?;
            let credit = Arc::clone(&self.credit)
                .acquire_many_owned(permits)
                .await
                .map_err(|_| SendError::Closed)?;
            if self.state.state.load(Ordering::SeqCst) != OPEN {
                return Err(SendError::Terminated);
            }
            self.stats.add(take);
            let envelope = Envelope {
                frame: Some(Frame::Data(chunk)),
                len: take,
                stats: Arc::clone(&self.stats),
                _credit: Some(credit),
            };
            // Never waits: every queued DATA holds at least one byte permit,
            // and the channel has `capacity + 2` slots.
            self.tx
                .send(envelope)
                .await
                .map_err(|_| SendError::Closed)?;
        }
        Ok(())
    }

    /// Queue the ordered FIN.
    ///
    /// # Errors
    /// [`SendError::Terminated`] if FIN or RESET was already sent, or
    /// [`SendError::Closed`] when the receiver is gone.
    pub fn finish(&self) -> Result<(), SendError> {
        if self
            .state
            .state
            .compare_exchange(OPEN, FIN, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SendError::Terminated);
        }
        self.tx
            .try_send(self.envelope(Frame::Fin))
            .map_err(|_| SendError::Closed)
    }

    /// Queue RESET at most once, using reserved capacity.  Returns whether
    /// this call emitted it.
    pub fn reset(&self, detail: ResetDetail) -> bool {
        let previous = self.state.state.swap(RESET, Ordering::SeqCst);
        if previous == RESET {
            return false;
        }
        // Every emitted RESET is signalled.  A RESET queued behind FIN still
        // cancels a receiver that is stalled and cannot reach the queue.
        self.state.signal.send_replace(Some(SignaledReset {
            detail,
            after_fin: previous == FIN,
        }));
        // A closed receiver needs no RESET; a full queue is impossible
        // because two slots are reserved for FIN and RESET.
        let _ = self.tx.try_send(self.envelope(Frame::Reset(detail)));
        true
    }

    /// True when the receiver is gone.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Whether this direction has queued FIN (and not since RESET).  For
    /// diagnostics and tests.
    #[must_use]
    pub fn fin_sent(&self) -> bool {
        self.state.state.load(Ordering::SeqCst) == FIN
    }

    /// DATA credit capacity: a send no larger than this is one queue item,
    /// so it is either wholly queued or not queued at all.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    fn envelope(&self, frame: Frame) -> Envelope {
        Envelope {
            frame: Some(frame),
            len: 0,
            stats: Arc::clone(&self.stats),
            _credit: None,
        }
    }
}

/// The receiving half.
pub struct FrameReceiver {
    rx: mpsc::Receiver<Envelope>,
    signal: watch::Receiver<Option<SignaledReset>>,
    terminated: bool,
}

impl FrameReceiver {
    /// The next ordered frame.  `None` means the sender is gone without FIN
    /// or RESET (a carrier failure), or a RESET was already returned.
    pub async fn recv(&mut self) -> Option<Frame> {
        if self.terminated {
            return None;
        }
        let mut envelope = self.rx.recv().await?;
        let frame = envelope.frame.take()?;
        drop(envelope);
        if matches!(frame, Frame::Reset(_)) {
            self.terminated = true;
        }
        Some(frame)
    }

    /// Terminal discard after a local failure: consume in-flight peer frames
    /// without delivering them until the peer's own FIN, RESET or carrier
    /// loss, so the peer learns of the reset in order instead of seeing its
    /// receiver vanish.
    pub async fn discard_until_terminal(&mut self) {
        while let Some(frame) = self.recv().await {
            if !matches!(frame, Frame::Data(_)) {
                return;
            }
        }
    }

    /// A handle that resolves when the peer emits RESET.
    #[must_use]
    pub fn reset_signal(&self) -> ResetSignal {
        ResetSignal {
            rx: self.signal.clone(),
        }
    }
}

/// Resolves once the peer has queued a RESET.
#[derive(Clone)]
pub struct ResetSignal {
    rx: watch::Receiver<Option<SignaledReset>>,
}

impl ResetSignal {
    /// Wait for any peer RESET, including one queued after FIN.  Pends
    /// forever if none arrives.
    pub async fn wait(&mut self) -> SignaledReset {
        if let Ok(value) = self.rx.wait_for(Option::is_some).await
            && let Some(reset) = *value
        {
            return reset;
        }
        std::future::pending().await
    }

    /// Wait for a peer RESET queued before its FIN.  A receiver delivering a
    /// direction the peer already finished uses this, so a later RESET never
    /// truncates bytes the peer completed; it sees that RESET in order.
    pub async fn wait_before_fin(&mut self) -> ResetDetail {
        if let Ok(value) = self
            .rx
            .wait_for(|reset| reset.is_some_and(|reset| !reset.after_fin))
            .await
            && let Some(reset) = *value
        {
            return reset.detail;
        }
        std::future::pending().await
    }
}

/// Build one bounded direction with `capacity_bytes` of DATA credit
/// (clamped to 1..=u32::MAX).
#[must_use]
pub fn channel(capacity_bytes: usize) -> (FrameSender, FrameReceiver, Arc<QueueStats>) {
    let capacity = capacity_bytes.clamp(1, u32::MAX as usize);
    let (tx, rx) = mpsc::channel(capacity + 2);
    let (signal_tx, signal_rx) = watch::channel(None);
    let stats = Arc::new(QueueStats::default());
    let sender = FrameSender {
        tx,
        credit: Arc::new(Semaphore::new(capacity)),
        capacity,
        state: Arc::new(SenderState {
            state: AtomicU8::new(OPEN),
            signal: signal_tx,
        }),
        stats: Arc::clone(&stats),
    };
    let receiver = FrameReceiver {
        rx,
        signal: signal_rx,
        terminated: false,
    };
    (sender, receiver, stats)
}
