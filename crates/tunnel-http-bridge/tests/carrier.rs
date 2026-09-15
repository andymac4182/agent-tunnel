//! Carrier pumps (implementation gate 3): the gate-2 bridge running over a
//! separate carrier through bounded handoffs, with the RESET ordering rules a
//! real carrier must keep.

use std::time::Duration;

use bytes::Bytes;
use tunnel_http_bridge::{
    CarrierClosed, CarrierEvent, CarrierReader, CarrierWriter, Execution, Frame, FrameReceiver,
    FrameSender, HANDOFF_CAPACITY, InboundEnd, OutboundEnd, ResetDetail, ResetSignal, channel,
    detail_from_reason, detail_from_status, pump_inbound, pump_outbound, reset_reason_for,
    result_outcome,
};
use tunnel_http_forward::HttpErrorCode;
use tunnel_protocol::reset_reason;

/// A fake carrier built from the stand-in channel, so its credit can be
/// exhausted deterministically.
struct ChannelWriter(FrameSender);

impl CarrierWriter for ChannelWriter {
    fn data(
        &mut self,
        data: Bytes,
    ) -> impl std::future::Future<Output = Result<(), CarrierClosed>> + Send {
        let sender = self.0.clone();
        async move { sender.send_data(data).await.map_err(|_| CarrierClosed) }
    }

    fn finish(&mut self) -> impl std::future::Future<Output = Result<(), CarrierClosed>> + Send {
        let result = self.0.finish().map_err(|_| CarrierClosed);
        async move { result }
    }

    fn reset(&mut self, detail: ResetDetail) -> impl std::future::Future<Output = ()> + Send {
        self.0.reset(detail);
        async {}
    }
}

struct ChannelReader(FrameReceiver);

impl CarrierReader for ChannelReader {
    #[allow(clippy::manual_async_fn)]
    fn next(&mut self) -> impl std::future::Future<Output = CarrierEvent> + Send {
        async move {
            match self.0.recv().await {
                Some(Frame::Data(data)) => CarrierEvent::Data(data),
                Some(Frame::Fin) => CarrierEvent::Fin,
                Some(Frame::Reset(detail)) => CarrierEvent::Reset(detail),
                None => CarrierEvent::Closed,
            }
        }
    }

    fn reset_signal(&self) -> ResetSignal {
        self.0.reset_signal()
    }
}

const CANCELLED: ResetDetail = ResetDetail {
    code: HttpErrorCode::Cancelled,
    execution: Execution::Unknown,
};

#[tokio::test]
async fn bytes_cross_two_handoffs_and_a_carrier_in_order() {
    let (bridge_tx, bridge_rx, _) = channel(HANDOFF_CAPACITY);
    let (carrier_tx, carrier_rx, _) = channel(1024);
    let (peer_tx, mut peer_rx, peer_stats) = channel(HANDOFF_CAPACITY);
    let outbound = tokio::spawn(pump_outbound(bridge_rx, ChannelWriter(carrier_tx)));
    let inbound = tokio::spawn(pump_inbound(ChannelReader(carrier_rx), peer_tx));
    let payload: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
    // More than every bounded queue on the path holds, so the writer must
    // run concurrently with the reader.
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        for chunk in sent.chunks(10_000) {
            bridge_tx
                .send_data(Bytes::copy_from_slice(chunk))
                .await
                .unwrap();
        }
        bridge_tx.finish().unwrap();
    });
    let mut received = Vec::new();
    loop {
        match peer_rx.recv().await {
            Some(Frame::Data(data)) => received.extend_from_slice(&data),
            Some(Frame::Fin) => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(received, payload);
    writer.await.unwrap();
    assert!(peer_stats.high_water() <= HANDOFF_CAPACITY);
    drop(peer_rx);
    assert_eq!(outbound.await.unwrap(), OutboundEnd::Finished);
    assert!(matches!(
        inbound.await.unwrap(),
        InboundEnd::Finished | InboundEnd::BridgeClosed
    ));
}

#[tokio::test]
async fn reset_before_fin_preempts_a_write_stalled_on_carrier_credit() {
    let (bridge_tx, bridge_rx, _) = channel(HANDOFF_CAPACITY);
    // A carrier with 16 bytes of credit that nobody reads.
    let (carrier_tx, mut carrier_rx, _) = channel(16);
    let outbound = tokio::spawn(pump_outbound(bridge_rx, ChannelWriter(carrier_tx)));
    bridge_tx
        .send_data(Bytes::from_static(&[7; 64]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!outbound.is_finished(), "the write is stalled on credit");
    assert!(bridge_tx.reset(CANCELLED));
    let end = tokio::time::timeout(Duration::from_secs(1), outbound)
        .await
        .expect("RESET must not wait for carrier credit")
        .unwrap();
    assert_eq!(end, OutboundEnd::Reset(CANCELLED));
    // The carrier saw only whole chunks it had credit for, then RESET.
    let mut data = 0;
    loop {
        match carrier_rx.recv().await {
            Some(Frame::Data(chunk)) => data += chunk.len(),
            Some(Frame::Reset(detail)) => {
                assert_eq!(detail, CANCELLED);
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(data <= 16);
}

#[tokio::test]
async fn reset_after_fin_is_sent_in_order_and_never_truncates() {
    let (bridge_tx, bridge_rx, _) = channel(HANDOFF_CAPACITY);
    let (carrier_tx, mut carrier_rx, _) = channel(HANDOFF_CAPACITY);
    let outbound = tokio::spawn(pump_outbound(bridge_rx, ChannelWriter(carrier_tx)));
    bridge_tx
        .send_data(Bytes::from_static(b"complete"))
        .await
        .unwrap();
    bridge_tx.finish().unwrap();
    bridge_tx.reset(CANCELLED);
    assert_eq!(
        carrier_rx.recv().await,
        Some(Frame::Data(Bytes::from_static(b"complete")))
    );
    assert_eq!(carrier_rx.recv().await, Some(Frame::Fin));
    assert_eq!(carrier_rx.recv().await, Some(Frame::Reset(CANCELLED)));
    assert_eq!(outbound.await.unwrap(), OutboundEnd::Reset(CANCELLED));
}

#[tokio::test]
async fn abandoned_direction_is_reset_never_finished() {
    let (bridge_tx, bridge_rx, _) = channel(HANDOFF_CAPACITY);
    let (carrier_tx, mut carrier_rx, _) = channel(HANDOFF_CAPACITY);
    let outbound = tokio::spawn(pump_outbound(bridge_rx, ChannelWriter(carrier_tx)));
    bridge_tx
        .send_data(Bytes::from_static(b"part"))
        .await
        .unwrap();
    drop(bridge_tx);
    assert_eq!(outbound.await.unwrap(), OutboundEnd::Abandoned);
    assert!(matches!(carrier_rx.recv().await, Some(Frame::Data(_))));
    assert!(matches!(carrier_rx.recv().await, Some(Frame::Reset(_))));
}

#[tokio::test]
async fn peer_reset_reaches_a_bridge_stalled_on_handoff_credit() {
    let (carrier_tx, carrier_rx, _) = channel(HANDOFF_CAPACITY);
    // A one-byte handoff the bridge never reads.
    let (bridge_tx, bridge_rx, _) = channel(1);
    let mut signal = bridge_rx.reset_signal();
    let inbound = tokio::spawn(pump_inbound(ChannelReader(carrier_rx), bridge_tx));
    carrier_tx
        .send_data(Bytes::from_static(b"first"))
        .await
        .unwrap();
    carrier_tx
        .send_data(Bytes::from_static(b"second"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    carrier_tx.reset(CANCELLED);
    let reset = tokio::time::timeout(Duration::from_secs(1), signal.wait())
        .await
        .expect("the stalled bridge learns of the RESET");
    assert_eq!(reset.detail, CANCELLED);
    assert!(!reset.after_fin);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), inbound)
            .await
            .unwrap()
            .unwrap(),
        InboundEnd::Reset(CANCELLED)
    );
}

#[tokio::test]
async fn peer_reset_after_fin_only_signals_and_keeps_ordered_delivery() {
    let (carrier_tx, carrier_rx, _) = channel(HANDOFF_CAPACITY);
    let (bridge_tx, mut bridge_rx, _) = channel(4);
    let mut signal = bridge_rx.reset_signal();
    let inbound = tokio::spawn(pump_inbound(ChannelReader(carrier_rx), bridge_tx));
    carrier_tx
        .send_data(Bytes::from_static(b"12345678"))
        .await
        .unwrap();
    carrier_tx.finish().unwrap();
    carrier_tx.reset(CANCELLED);
    let reset = tokio::time::timeout(Duration::from_secs(1), signal.wait())
        .await
        .unwrap();
    assert!(reset.after_fin);
    let mut data = Vec::new();
    loop {
        match bridge_rx.recv().await {
            Some(Frame::Data(chunk)) => data.extend_from_slice(&chunk),
            Some(Frame::Fin) => break,
            other => panic!("ordered delivery lost: {other:?}"),
        }
    }
    assert_eq!(data, b"12345678");
    assert_eq!(bridge_rx.recv().await, Some(Frame::Reset(CANCELLED)));
    assert_eq!(inbound.await.unwrap(), InboundEnd::Reset(CANCELLED));
}

#[test]
fn reset_mapping_uses_the_shared_registry_and_bounded_status() {
    assert_eq!(reset_reason_for(CANCELLED), reset_reason::CANCELLED);
    for code in HttpErrorCode::ALL {
        let detail = ResetDetail {
            code,
            execution: Execution::Dispatched,
        };
        let reason = reset_reason_for(detail);
        assert!(reset_reason::is_registered(reason));
        assert_eq!(
            reason == reset_reason::CANCELLED,
            code == HttpErrorCode::Cancelled
        );
        assert_eq!(
            detail_from_status(code.as_str(), Execution::Dispatched.as_str()),
            Some(detail)
        );
    }
    assert_eq!(result_outcome(CANCELLED), "cancelled");
    assert_eq!(
        result_outcome(ResetDetail {
            code: HttpErrorCode::DeadlineExceeded,
            execution: Execution::Unknown,
        }),
        "outcome_unknown"
    );
    assert_eq!(
        result_outcome(ResetDetail {
            code: HttpErrorCode::InvalidHead,
            execution: Execution::NotDispatched,
        }),
        "failed"
    );
    assert_eq!(detail_from_status("HTTP_NOPE", "unknown"), None);
    assert_eq!(detail_from_status("HTTP_CANCELLED", "maybe"), None);
    assert_eq!(
        detail_from_reason(reset_reason::CANCELLED).code,
        HttpErrorCode::Cancelled
    );
    assert_eq!(
        detail_from_reason(reset_reason::ADAPTER_FAILURE),
        ResetDetail {
            code: HttpErrorCode::StreamInterrupted,
            execution: Execution::Unknown,
        }
    );
}
