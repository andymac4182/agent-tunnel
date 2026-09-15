//! Streaming a local HTTP body into BODY records under byte credit.

use std::pin::Pin;

use bytes::Bytes;
use http_body::Body;
use tunnel_http_forward::{
    END_RECORD, HttpErrorCode, MAX_BODY_PAYLOAD_LEN, RecordHeader, RecordKind,
};

use crate::exchange::Exchange;
use crate::stream::SendError;

/// Why a pump stopped early.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PumpError {
    /// The exchange was already stopped by another failure.
    Stopped,
    /// The local body was invalid or failed.
    Source(HttpErrorCode),
    /// The outbound stream is gone.
    Sink(HttpErrorCode),
}

/// Queue bytes on the exchange's outbound direction, abandoning the wait as
/// soon as the exchange stops.
pub(crate) async fn send(exchange: &Exchange, data: Bytes) -> Result<(), PumpError> {
    tokio::select! {
        biased;
        () = exchange.stop.cancelled() => Err(PumpError::Stopped),
        result = exchange.peer.send_data(data) => match result {
            Ok(()) => Ok(()),
            Err(SendError::Terminated) => Err(PumpError::Stopped),
            Err(SendError::Closed) => Err(PumpError::Sink(HttpErrorCode::StreamInterrupted)),
        },
    }
}

/// Encode `data` as consecutive BODY records without copying the payload.
async fn send_body_records(exchange: &Exchange, data: Bytes) -> Result<(), PumpError> {
    let mut rest = data;
    while !rest.is_empty() {
        let payload = rest.split_to(rest.len().min(MAX_BODY_PAYLOAD_LEN));
        // Invariant: 1..=MAX_BODY_PAYLOAD_LEN bytes is always a valid BODY.
        let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let header = RecordHeader::new(RecordKind::Body, len)
            .map_err(|_| PumpError::Source(HttpErrorCode::BadRecord))?;
        send(exchange, Bytes::copy_from_slice(&header.encode())).await?;
        send(exchange, payload).await?;
    }
    Ok(())
}

/// Pump a local body to END and FIN.  One body frame is held at a time, and
/// the next is polled only after the previous one fit the outbound credit.
/// The declared length is checked on every chunk (long) and at the end
/// (short); discovered non-empty trailers fail the direction.
pub(crate) async fn pump_body<B>(
    exchange: &Exchange,
    mut body: Pin<&mut B>,
    declared: Option<u64>,
    limit: u64,
) -> Result<(), PumpError>
where
    B: Body<Data = Bytes>,
{
    let mut sent = 0u64;
    loop {
        let next = tokio::select! {
            biased;
            () = exchange.stop.cancelled() => return Err(PumpError::Stopped),
            next = next_frame(body.as_mut()) => next,
        };
        let frame = match next {
            None => break,
            Some(Err(_)) => return Err(PumpError::Source(HttpErrorCode::StreamInterrupted)),
            Some(Ok(frame)) => frame,
        };
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(frame) => {
                if frame
                    .trailers_ref()
                    .is_some_and(|trailers| !trailers.is_empty())
                {
                    return Err(PumpError::Source(HttpErrorCode::UnsupportedFeature));
                }
                continue;
            }
        };
        if data.is_empty() {
            continue;
        }
        let total = sent
            .checked_add(data.len() as u64)
            .ok_or(PumpError::Source(HttpErrorCode::BodyLimit))?;
        if declared.is_some_and(|declared| total > declared) {
            return Err(PumpError::Source(HttpErrorCode::LengthMismatch));
        }
        if total > limit {
            return Err(PumpError::Source(HttpErrorCode::BodyLimit));
        }
        sent = total;
        send_body_records(exchange, data).await?;
    }
    if declared.is_some_and(|declared| declared != sent) {
        return Err(PumpError::Source(HttpErrorCode::LengthMismatch));
    }
    send(exchange, Bytes::from_static(&END_RECORD)).await?;
    exchange.peer.finish().map_err(|error| match error {
        SendError::Terminated => PumpError::Stopped,
        SendError::Closed => PumpError::Sink(HttpErrorCode::StreamInterrupted),
    })
}

/// Poll one frame, discarding the error value so no body error type (and no
/// message it might carry) is held or reported.
pub(crate) async fn next_frame<B>(
    mut body: Pin<&mut B>,
) -> Option<Result<http_body::Frame<Bytes>, ()>>
where
    B: Body<Data = Bytes>,
{
    std::future::poll_fn(|cx| {
        body.as_mut()
            .poll_frame(cx)
            .map(|frame| frame.map(|result| result.map_err(drop)))
    })
    .await
}
