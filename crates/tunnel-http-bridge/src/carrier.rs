//! Carrying one exchange over a real logical tunnel stream (implementation
//! gate 3).
//!
//! [`owner::forward`](crate::owner::forward) and
//! [`device::serve`](crate::device::serve) are unchanged from gate 2: they
//! still talk to a bounded [`stream::channel`](crate::stream::channel).  A
//! real carrier (the relay's owner actor, a peer HTTP/3 request stream, or
//! the connector's device actor) implements [`CarrierWriter`] and
//! [`CarrierReader`], and [`pump_outbound`] / [`pump_inbound`] move frames
//! between that carrier and the channel.  The channel is then a *handoff*
//! of at most [`HANDOFF_CAPACITY`] bytes: one DATA frame.  Every hop keeps
//! its own credit authoritative; a pump holds at most one frame outside the
//! handoff.
//!
//! Resets cross the boundary with the protocol's shared numeric reason code
//! ([`reset_reason_for`]) plus bounded `RESULT_STATUS` detail
//! ([`result_outcome`], [`detail_from_status`]); there is no private numeric
//! extension to RESET.

use std::future::Future;

use bytes::Bytes;
use tunnel_http_forward::HttpErrorCode;
use tunnel_protocol::reset_reason;

use crate::status::{Execution, ResetDetail};
use crate::stream::{Frame, FrameReceiver, FrameSender, ResetSignal, SignaledReset};

/// The handoff capacity between a carrier pump and the bridge: one maximum
/// DATA payload, so a record head always fits one queue item.
pub const HANDOFF_CAPACITY: usize = 64 * 1024;

/// The carrier is gone (socket, peer stream, or actor registration lost).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CarrierClosed;

/// One ordered event read from a carrier.
#[derive(Clone, Eq, PartialEq)]
pub enum CarrierEvent {
    Data(Bytes),
    Fin,
    Reset(ResetDetail),
    /// The carrier ended without FIN or RESET.
    Closed,
}

impl core::fmt::Debug for CarrierEvent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Data(data) => formatter
                .debug_struct("Data")
                .field("payload_len", &data.len())
                .finish(),
            Self::Fin => formatter.write_str("Fin"),
            Self::Reset(detail) => formatter.debug_tuple("Reset").field(detail).finish(),
            Self::Closed => formatter.write_str("Closed"),
        }
    }
}

/// The sending half of a real carrier.
pub trait CarrierWriter: Send + 'static {
    /// Send DATA in order, resolving once the carrier accepted the whole
    /// chunk under its own credit.  The pump drops this future when the
    /// bridge resets before FIN; the writer must then still accept
    /// [`CarrierWriter::reset`] and must never emit a partial chunk.
    fn data(&mut self, data: Bytes) -> impl Future<Output = Result<(), CarrierClosed>> + Send;

    /// Send FIN after every accepted DATA chunk.
    fn finish(&mut self) -> impl Future<Output = Result<(), CarrierClosed>> + Send;

    /// Send RESET (at most once) after every accepted DATA chunk.
    fn reset(&mut self, detail: ResetDetail) -> impl Future<Output = ()> + Send;
}

/// The receiving half of a real carrier.
pub trait CarrierReader: Send + 'static {
    /// The next ordered event.
    fn next(&mut self) -> impl Future<Output = CarrierEvent> + Send;

    /// A signal that resolves as soon as the carrier knows of a peer RESET,
    /// possibly before its ordered delivery (standing in for scoped control
    /// cancellation).  A carrier with no such knowledge returns a signal that
    /// never resolves.
    fn reset_signal(&self) -> ResetSignal;
}

/// The protocol RESET reason code for a bridge failure.  Cancellation has
/// its own code; every other HTTP forwarding failure is an adapter failure
/// whose detail travels in `RESULT_STATUS`.
#[must_use]
pub const fn reset_reason_for(detail: ResetDetail) -> u16 {
    match detail.code {
        HttpErrorCode::Cancelled => reset_reason::CANCELLED,
        _ => reset_reason::ADAPTER_FAILURE,
    }
}

/// The `RESULT_STATUS` outcome for a bridge failure: `cancelled`, or
/// `outcome_unknown` when the emitter cannot prove whether the handler ran,
/// otherwise `failed`.
#[must_use]
pub const fn result_outcome(detail: ResetDetail) -> &'static str {
    match (detail.code, detail.execution) {
        (HttpErrorCode::Cancelled, _) => "cancelled",
        (_, Execution::Unknown) => "outcome_unknown",
        _ => "failed",
    }
}

/// Rebuild the bridge detail from bounded `RESULT_STATUS` detail tokens.
/// Unknown tokens are rejected rather than guessed.
#[must_use]
pub fn detail_from_status(code: &str, execution: &str) -> Option<ResetDetail> {
    Some(ResetDetail {
        code: HttpErrorCode::parse(code)?,
        execution: Execution::parse(execution)?,
    })
}

/// The detail a receiver can infer from a RESET reason code alone, when no
/// matching `RESULT_STATUS` is available.  Execution is always `unknown`:
/// only the emitter's status can prove more.
#[must_use]
pub const fn detail_from_reason(reason: u16) -> ResetDetail {
    ResetDetail {
        code: if reason == reset_reason::CANCELLED {
            HttpErrorCode::Cancelled
        } else {
            HttpErrorCode::StreamInterrupted
        },
        execution: Execution::Unknown,
    }
}

/// How an outbound pump ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OutboundEnd {
    /// FIN was sent and the bridge released the direction.
    Finished,
    /// RESET was sent.
    Reset(ResetDetail),
    /// The bridge dropped the direction before FIN; RESET was sent.
    Abandoned,
    /// The carrier failed.
    CarrierClosed,
}

enum Step {
    Frame(Option<Frame>),
    ResetBeforeFin(ResetDetail),
}

enum Write {
    Done(Result<(), CarrierClosed>),
    ResetBeforeFin(ResetDetail),
}

/// Move the bridge's outbound frames onto a carrier until the direction is
/// terminal.  A RESET the bridge raises before its FIN preempts an
/// outstanding DATA write, so exhausted carrier credit cannot delay it; a
/// RESET after FIN is sent in order, so a completed direction is never
/// truncated.
pub async fn pump_outbound<W: CarrierWriter>(
    mut from_bridge: FrameReceiver,
    mut writer: W,
) -> OutboundEnd {
    let mut signal = from_bridge.reset_signal();
    let mut fin_sent = false;
    loop {
        let step = if fin_sent {
            Step::Frame(from_bridge.recv().await)
        } else {
            tokio::select! {
                biased;
                detail = signal.wait_before_fin() => Step::ResetBeforeFin(detail),
                frame = from_bridge.recv() => Step::Frame(frame),
            }
        };
        let frame = match step {
            Step::ResetBeforeFin(detail) => {
                writer.reset(detail).await;
                return OutboundEnd::Reset(detail);
            }
            Step::Frame(frame) => frame,
        };
        match frame {
            None if fin_sent => return OutboundEnd::Finished,
            None => {
                writer
                    .reset(ResetDetail {
                        code: HttpErrorCode::StreamInterrupted,
                        execution: Execution::Unknown,
                    })
                    .await;
                return OutboundEnd::Abandoned;
            }
            Some(Frame::Data(data)) => {
                let write = {
                    let pending = writer.data(data);
                    tokio::pin!(pending);
                    tokio::select! {
                        biased;
                        detail = signal.wait_before_fin() => Write::ResetBeforeFin(detail),
                        result = &mut pending => Write::Done(result),
                    }
                };
                match write {
                    Write::Done(Ok(())) => {}
                    Write::Done(Err(CarrierClosed)) => return OutboundEnd::CarrierClosed,
                    Write::ResetBeforeFin(detail) => {
                        writer.reset(detail).await;
                        return OutboundEnd::Reset(detail);
                    }
                }
            }
            Some(Frame::Fin) => {
                if writer.finish().await.is_err() {
                    return OutboundEnd::CarrierClosed;
                }
                fin_sent = true;
            }
            Some(Frame::Reset(detail)) => {
                writer.reset(detail).await;
                return OutboundEnd::Reset(detail);
            }
        }
    }
}

/// How an inbound pump ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InboundEnd {
    /// The peer's FIN was delivered and the bridge released the direction.
    Finished,
    /// The peer's RESET was delivered.
    Reset(ResetDetail),
    /// The carrier ended without FIN or RESET.
    CarrierClosed,
    /// The bridge stopped reading.
    BridgeClosed,
}

enum Delivery {
    Sent(bool),
    Ahead(CarrierEvent),
    Signal(SignaledReset),
}

/// Move a carrier's ordered events into the bridge.  While one DATA chunk
/// waits for handoff credit, the pump reads at most one further event
/// ahead, and it also watches the carrier's out-of-band RESET signal, so a
/// peer RESET reaches a stalled bridge promptly.  A RESET known to follow
/// the peer's FIN only raises the bridge's signal; the ordered DATA, FIN and
/// RESET are still delivered in sequence.
pub async fn pump_inbound<R: CarrierReader>(mut reader: R, to_bridge: FrameSender) -> InboundEnd {
    let mut signal = reader.reset_signal();
    let mut signalled = false;
    let mut fin_seen = false;
    let mut ahead: Option<CarrierEvent> = None;
    loop {
        let event = if let Some(event) = ahead.take() {
            event
        } else if signalled {
            tokio::select! {
                biased;
                () = to_bridge.closed() => return InboundEnd::BridgeClosed,
                event = reader.next() => event,
            }
        } else {
            tokio::select! {
                biased;
                () = to_bridge.closed() => return InboundEnd::BridgeClosed,
                reset = signal.wait() => {
                    signalled = true;
                    if reset.after_fin {
                        to_bridge.signal_reset(reset);
                        continue;
                    }
                    to_bridge.reset(reset.detail);
                    return InboundEnd::Reset(reset.detail);
                }
                event = reader.next() => event,
            }
        };
        match event {
            CarrierEvent::Data(data) => {
                let mut delivered = false;
                {
                    let send = to_bridge.send_data(data);
                    tokio::pin!(send);
                    while !delivered {
                        let outcome = tokio::select! {
                            biased;
                            result = &mut send => Delivery::Sent(result.is_ok()),
                            reset = signal.wait(), if !signalled => Delivery::Signal(reset),
                            event = reader.next(), if ahead.is_none() => Delivery::Ahead(event),
                        };
                        match outcome {
                            Delivery::Sent(true) => delivered = true,
                            Delivery::Sent(false) => return InboundEnd::BridgeClosed,
                            Delivery::Signal(reset) => {
                                signalled = true;
                                if !reset.after_fin {
                                    to_bridge.reset(reset.detail);
                                    return InboundEnd::Reset(reset.detail);
                                }
                                to_bridge.signal_reset(reset);
                            }
                            Delivery::Ahead(CarrierEvent::Reset(detail)) if !fin_seen => {
                                to_bridge.reset(detail);
                                return InboundEnd::Reset(detail);
                            }
                            Delivery::Ahead(event) => {
                                if event == CarrierEvent::Fin {
                                    fin_seen = true;
                                }
                                ahead = Some(event);
                            }
                        }
                    }
                }
            }
            CarrierEvent::Fin => {
                fin_seen = true;
                if to_bridge.finish().is_err() {
                    return InboundEnd::BridgeClosed;
                }
            }
            CarrierEvent::Reset(detail) => {
                to_bridge.reset(detail);
                return InboundEnd::Reset(detail);
            }
            CarrierEvent::Closed => {
                // Dropping the only sender without FIN or RESET is a carrier
                // failure to the bridge.
                return if fin_seen {
                    InboundEnd::Finished
                } else {
                    InboundEnd::CarrierClosed
                };
            }
        }
    }
}
