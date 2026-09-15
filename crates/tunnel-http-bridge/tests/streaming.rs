//! Concurrency, half-close, SSE byte exactness, backpressure, cancellation
//! and deadlines through the owner and device adapters.

mod common;

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use common::*;
use http::{Request, Response, StatusCode};
use http_body::{Body, Frame as BodyFrame};
use tokio::sync::oneshot;
use tunnel_http_bridge::{
    BridgeConfig, ChannelBody, Execution, GatewayError, HandlerCancellation, Outcome, forward,
    serve,
};
use tunnel_http_forward::{HttpErrorCode, RecordKind};

/// Echo the request body into a streaming response as it arrives.
async fn echo_handler(request: Request<ChannelBody>) -> Result<Response<TestBody>, TestError> {
    let (tx, body) = test_body(4);
    tokio::spawn(async move {
        let mut upload = request.into_body();
        while let Some(chunk) = next_chunk(&mut upload).await {
            let frame = chunk.map(BodyFrame::data).map_err(|_| TestError);
            if tx.send(frame).await.is_err() {
                return;
            }
        }
    });
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .body(body)
        .unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_response_arrives_and_streams_while_the_upload_is_still_open() {
    let (upload, body) = test_body(4);
    upload.send(data(b"part-1;")).await.unwrap();
    let mut running = exchange(
        request(
            "POST",
            "/echo",
            &[("content-type", "application/octet-stream")],
            body,
        ),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        echo_handler,
    )
    .await;
    // `upload` is still open: the response head and first echoed bytes must
    // not wait for the request END.
    assert_eq!(running.response.status(), StatusCode::OK);
    assert!(running.response.headers().get("content-length").is_none());
    let body = running.response.body_mut();
    assert_eq!(within(next_chunk(body)).await.unwrap().unwrap(), "part-1;");
    upload.send(data(b"part-2;")).await.unwrap();
    assert_eq!(within(next_chunk(body)).await.unwrap().unwrap(), "part-2;");
    drop(upload);
    let rest = within(collect(running.response.into_body())).await.unwrap();
    assert!(rest.is_empty());
    let owner = within(running.handle.report()).await;
    let device = within(running.device).await.unwrap();
    for report in [owner, device] {
        assert_eq!(report.request, Outcome::Complete);
        assert_eq!(report.response, Outcome::Complete);
        assert_eq!(report.execution, Execution::Dispatched);
        assert_eq!(report.error, None);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_half_close_ends_only_the_request_and_the_response_keeps_streaming() {
    let (upload, body) = test_body(4);
    let (gate_tx, gate_rx) = oneshot::channel::<()>();
    let link = link(STREAM_CREDIT);
    let Link {
        to_device,
        device_rx,
        to_owner,
        owner_rx,
        ..
    } = link;
    let (device_rx, request_log) = tap(device_rx, STREAM_CREDIT, Vec::new());
    let (owner_rx, response_log) = tap(owner_rx, STREAM_CREDIT, Vec::new());
    let device = tokio::spawn(serve(
        profile(),
        BridgeConfig::default(),
        device_rx,
        to_owner,
        move |request: Request<ChannelBody>| async move {
            let (tx, body) = test_body(4);
            tokio::spawn(async move {
                // A clean end of the request body happens only after END+FIN.
                let upload = collect(request.into_body())
                    .await
                    .expect("clean request end");
                let line = format!("upload-complete:{}\n", upload.len());
                tx.send(data(line.as_bytes())).await.unwrap();
                gate_rx.await.unwrap();
                for index in 0..3 {
                    let line = format!("after-half-close:{index}\n");
                    tx.send(data(line.as_bytes())).await.unwrap();
                }
            });
            Ok::<_, TestError>(
                Response::builder()
                    .status(200)
                    .header("content-type", "text/event-stream")
                    .body(body)
                    .unwrap(),
            )
        },
    ));
    let (mut response, handle) = within(forward(
        request("POST", "/upload", &[], body),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    upload.send(data(b"synthetic-upload")).await.unwrap();
    drop(upload);
    let body = response.body_mut();
    assert_eq!(
        within(next_chunk(body)).await.unwrap().unwrap(),
        "upload-complete:16\n"
    );
    {
        let request = request_log.lock().unwrap();
        assert!(request.fin, "request FIN was forwarded");
        assert!(request.reset.is_none());
        assert_eq!(
            request.record_kinds(),
            [RecordKind::RequestHead, RecordKind::Body, RecordKind::End]
        );
        let response = response_log.lock().unwrap();
        assert!(
            !response.fin && response.reset.is_none(),
            "response still open"
        );
    }
    gate_tx.send(()).unwrap();
    let rest = within(collect(response.into_body())).await.unwrap();
    assert_eq!(
        rest,
        b"after-half-close:0\nafter-half-close:1\nafter-half-close:2\n"
    );
    let owner = within(handle.report()).await;
    let device = within(device).await.unwrap();
    assert_eq!(owner.error, None);
    assert_eq!(device.error, None);
    assert_eq!(device.request, Outcome::Complete);
    assert_eq!(device.response, Outcome::Complete);
    let response = response_log.lock().unwrap();
    assert!(response.fin && response.reset.is_none());
    assert_eq!(response.record_kinds().last(), Some(&RecordKind::End));
}

const SSE: &[u8] = b"data: caf\xc3\xa9\n\nid: 7\r\ndata: {\"a\":1}\r\n\r\n: keep\n\ndata: \xf0\x9f\x8e\x89\rdata: x\r\r";

async fn sse_exchange(chunks: Vec<Vec<u8>>, cuts: Vec<usize>) -> Vec<u8> {
    let Link {
        to_device,
        device_rx,
        to_owner,
        owner_rx,
        ..
    } = link(STREAM_CREDIT);
    let (owner_rx, _log) = tap(owner_rx, STREAM_CREDIT, cuts);
    let device = tokio::spawn(serve(
        profile(),
        BridgeConfig::default(),
        device_rx,
        to_owner,
        move |_request: Request<ChannelBody>| async move {
            let frames = chunks.iter().map(|chunk| data(chunk)).collect();
            Ok::<_, TestError>(
                Response::builder()
                    .status(200)
                    .header("content-type", "text/event-stream")
                    .header("cache-control", "no-store")
                    .body(frames_body(frames, None))
                    .unwrap(),
            )
        },
    ));
    let (response, handle) = within(forward(
        request(
            "GET",
            "/events",
            &[("accept", "text/event-stream")],
            empty_body(),
        ),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = within(collect(response.into_body())).await.unwrap();
    assert_eq!(within(handle.report()).await.error, None);
    assert_eq!(within(device).await.unwrap().error, None);
    bytes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sse_body_split_by_the_handler_at_every_pair_of_offsets_is_byte_exact() {
    // Covers splits inside `\n`, `\r\n`, `\r`, blank-line delimiters and
    // two- and four-byte UTF-8 sequences.
    for first in 0..=SSE.len() {
        for second in first..=SSE.len() {
            let chunks = vec![
                SSE[..first].to_vec(),
                SSE[first..second].to_vec(),
                SSE[second..].to_vec(),
            ];
            let got = sse_exchange(chunks, Vec::new()).await;
            assert_eq!(got, SSE, "handler split at {first},{second}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sse_record_stream_cut_at_every_transport_offset_is_byte_exact() {
    // First learn the record stream length for a single-chunk body.
    let mut total = 0;
    {
        let Link {
            to_device,
            device_rx,
            to_owner,
            owner_rx,
            ..
        } = link(STREAM_CREDIT);
        let (owner_rx, log) = tap(owner_rx, STREAM_CREDIT, Vec::new());
        tokio::spawn(serve(
            profile(),
            BridgeConfig::default(),
            device_rx,
            to_owner,
            |_request: Request<ChannelBody>| async move {
                Ok::<_, TestError>(
                    Response::builder()
                        .status(200)
                        .header("content-type", "text/event-stream")
                        .header("cache-control", "no-store")
                        .body(frames_body(vec![data(SSE)], None))
                        .unwrap(),
                )
            },
        ));
        let (response, _handle) = within(forward(
            request("GET", "/events", &[], empty_body()),
            profile(),
            BridgeConfig::default(),
            to_device,
            owner_rx,
        ))
        .await;
        within(collect(response.into_body())).await.unwrap();
        total += log.lock().unwrap().bytes.len();
    }
    assert!(total > SSE.len());
    for cut in 1..total {
        let got = sse_exchange(vec![SSE.to_vec()], vec![cut]).await;
        assert_eq!(got, SSE, "transport cut at {cut}");
    }
    // And every byte in its own DATA frame at once.
    let got = sse_exchange(vec![SSE.to_vec()], (1..total).collect()).await;
    assert_eq!(got, SSE);
}

/// A lazily produced body that counts bytes handed out.
struct CountingBody {
    produced: Arc<AtomicU64>,
    chunk: usize,
    remaining: u64,
    dropped: Arc<AtomicBool>,
}

impl Body for CountingBody {
    type Data = Bytes;
    type Error = TestError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<BodyFrame<Bytes>, TestError>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let len = (self.chunk as u64).min(self.remaining);
        self.remaining -= len;
        self.produced.fetch_add(len, Ordering::SeqCst);
        Poll::Ready(Some(Ok(BodyFrame::data(Bytes::from(vec![
            b'x';
            len as usize
        ])))))
    }
}

impl Drop for CountingBody {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_consumer_bounds_bytes_produced_by_the_handler_and_queued() {
    const CREDIT: usize = 64 * 1024;
    const CHUNK: usize = 4096;
    let produced = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let link = link(CREDIT);
    let response_stats = Arc::clone(&link.response_stats);
    let handler_produced = Arc::clone(&produced);
    let handler_dropped = Arc::clone(&dropped);
    let mut running = exchange(
        request("GET", "/events", &[], empty_body()),
        link,
        BridgeConfig::default(),
        move |_request: Request<ChannelBody>| async move {
            Ok::<_, TestError>(
                Response::builder()
                    .status(200)
                    .body(CountingBody {
                        produced: handler_produced,
                        chunk: CHUNK,
                        remaining: 32 * 1024 * 1024,
                        dropped: handler_dropped,
                    })
                    .unwrap(),
            )
        },
    )
    .await;
    let body = running.response.body_mut();
    within(next_chunk(body)).await.unwrap().unwrap();
    // Stall the consumer long enough for any unbounded buffering to show.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let stalled = produced.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        produced.load(Ordering::SeqCst),
        stalled,
        "production stopped"
    );
    // One handler chunk in hand, the stream credit, one DATA frame in the
    // owner pump, the body queue (4 chunks), and the chunk the consumer took.
    let bound = (CHUNK + CREDIT + CREDIT + 4 * CHUNK + CHUNK) as u64;
    assert!(
        stalled <= bound,
        "produced {stalled} bytes while stalled; bound {bound}"
    );
    assert!(response_stats.high_water() <= CREDIT);
    assert!(response_stats.high_water() > 0);
    // Reading resumes production.
    for _ in 0..64 {
        within(next_chunk(body)).await.unwrap().unwrap();
    }
    assert!(produced.load(Ordering::SeqCst) > stalled);
    drop(running.response);
    let device = within(running.device).await.unwrap();
    assert_eq!(device.response, Outcome::Aborted);
    assert_eq!(device.error, Some(HttpErrorCode::Cancelled));
    assert!(dropped.load(Ordering::SeqCst), "handler body was dropped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_handler_bounds_bytes_read_from_the_consumer_upload() {
    const CREDIT: usize = 64 * 1024;
    const CHUNK: usize = 4096;
    let produced = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let upload = CountingBody {
        produced: Arc::clone(&produced),
        chunk: CHUNK,
        remaining: 900 * 1024,
        dropped: Arc::clone(&dropped),
    };
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let link = link(CREDIT);
    let request_stats = Arc::clone(&link.request_stats);
    let running = tokio::spawn(async move {
        exchange(
            request("POST", "/upload", &[], upload),
            link,
            BridgeConfig::default(),
            move |request: Request<ChannelBody>| async move {
                release_rx.await.unwrap();
                let upload = collect(request.into_body()).await.unwrap();
                Ok::<_, TestError>(
                    Response::builder()
                        .status(200)
                        .body(ChannelBody::full(Bytes::from(upload.len().to_string())))
                        .unwrap(),
                )
            },
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let stalled = produced.load(Ordering::SeqCst);
    // Owner: one chunk in hand plus stream credit.  Device: one DATA frame in
    // its pump plus the request body queue.
    let bound = (CHUNK + CREDIT + CREDIT + 4 * CHUNK) as u64;
    assert!(
        stalled <= bound,
        "read {stalled} upload bytes while the handler stalled; bound {bound}"
    );
    assert!(request_stats.high_water() <= CREDIT);
    release_tx.send(()).unwrap();
    let running = within(running).await.unwrap();
    let body = within(collect(running.response.into_body())).await.unwrap();
    assert_eq!(body, (900 * 1024).to_string().as_bytes());
    assert_eq!(within(running.device).await.unwrap().error, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_drop_mid_body_resets_both_directions_and_the_handler_observes_it() {
    let producer_closed = Arc::new(AtomicBool::new(false));
    let token_cancelled = Arc::new(AtomicBool::new(false));
    let (closed, cancelled) = (Arc::clone(&producer_closed), Arc::clone(&token_cancelled));
    let Link {
        to_device,
        device_rx,
        to_owner,
        owner_rx,
        ..
    } = link(STREAM_CREDIT);
    let (device_rx, request_log) = tap(device_rx, STREAM_CREDIT, Vec::new());
    let (owner_rx, response_log) = tap(owner_rx, STREAM_CREDIT, Vec::new());
    let device = tokio::spawn(serve(
        profile(),
        BridgeConfig::default(),
        device_rx,
        to_owner,
        move |request: Request<ChannelBody>| async move {
            let token = request
                .extensions()
                .get::<HandlerCancellation>()
                .unwrap()
                .0
                .clone();
            tokio::spawn(async move {
                token.cancelled().await;
                cancelled.store(true, Ordering::SeqCst);
            });
            let (tx, body) = test_body(1);
            tokio::spawn(async move {
                for index in 0..2 {
                    let event = format!("data: {index}\n\n");
                    tx.send(data(event.as_bytes())).await.unwrap();
                }
                // Then stay idle, as an SSE stream between events does: the
                // owner pump is waiting on the device, not writing a body.
                tx.closed().await;
                closed.store(true, Ordering::SeqCst);
            });
            Ok::<_, TestError>(Response::builder().status(200).body(body).unwrap())
        },
    ));
    let (mut response, handle) = within(forward(
        request("GET", "/events", &[], empty_body()),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    for _ in 0..2 {
        within(next_chunk(response.body_mut()))
            .await
            .unwrap()
            .unwrap();
    }
    drop(response);
    let owner = within(handle.report()).await;
    let device = within(device).await.unwrap();
    assert_eq!(owner.response, Outcome::Aborted);
    assert_eq!(owner.error, Some(HttpErrorCode::Cancelled));
    assert_eq!(
        device.request,
        Outcome::Complete,
        "the GET had already ended"
    );
    assert_eq!(device.response, Outcome::Aborted);
    assert_eq!(device.error, Some(HttpErrorCode::Cancelled));
    assert_eq!(device.execution, Execution::Dispatched);
    within(async {
        while !(producer_closed.load(Ordering::SeqCst) && token_cancelled.load(Ordering::SeqCst)) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let request = request_log.lock().unwrap();
    assert_eq!(
        request.record_kinds(),
        [RecordKind::RequestHead, RecordKind::End]
    );
    assert!(request.fin);
    assert_eq!(
        request.reset.map(|detail| detail.code),
        Some(HttpErrorCode::Cancelled)
    );
    let response = response_log.lock().unwrap();
    assert!(!response.fin);
    assert!(response.reset.is_some(), "response direction reset");
    assert!(
        !response.record_kinds().contains(&RecordKind::End),
        "no fabricated END"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_the_forward_future_cancels_a_handler_that_is_not_reading_its_upload() {
    let handler_dropped = Arc::new(AtomicBool::new(false));
    let token_cancelled = Arc::new(AtomicBool::new(false));
    let (dropped, cancelled) = (Arc::clone(&handler_dropped), Arc::clone(&token_cancelled));
    let (started_tx, started_rx) = oneshot::channel();
    let Link {
        to_device,
        device_rx,
        to_owner,
        owner_rx,
        ..
    } = link(STREAM_CREDIT);
    let device = tokio::spawn(serve(
        profile(),
        BridgeConfig::default(),
        device_rx,
        to_owner,
        move |request: Request<ChannelBody>| async move {
            struct Guard(Arc<AtomicBool>);
            impl Drop for Guard {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _guard = Guard(dropped);
            let token = request
                .extensions()
                .get::<HandlerCancellation>()
                .unwrap()
                .0
                .clone();
            tokio::spawn(async move {
                token.cancelled().await;
                cancelled.store(true, Ordering::SeqCst);
            });
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
            Ok::<_, TestError>(Response::new(empty_body()))
        },
    ));
    let produced = Arc::new(AtomicU64::new(0));
    // Larger than the stream credit plus the device body queue, so the
    // device's request pump stalls on a handler that never reads.
    let upload = CountingBody {
        produced: Arc::clone(&produced),
        chunk: 4096,
        remaining: 900 * 1024,
        dropped: Arc::new(AtomicBool::new(false)),
    };
    let mut forwarding = Box::pin(forward(
        request("POST", "/upload", &[], upload),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ));
    tokio::select! {
        _ = &mut forwarding => panic!("no response head is ever produced"),
        started = started_rx => started.unwrap(),
    }
    let stalled = within(async {
        let mut last = u64::MAX;
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let now = produced.load(Ordering::SeqCst);
            if now == last {
                return now;
            }
            last = now;
        }
    })
    .await;
    assert!(stalled < 900 * 1024, "the upload is stalled, not finished");
    drop(forwarding);
    let device = within(device).await.unwrap();
    assert_eq!(device.error, Some(HttpErrorCode::Cancelled));
    assert_eq!(device.execution, Execution::Dispatched);
    assert!(
        handler_dropped.load(Ordering::SeqCst),
        "handler future dropped"
    );
    within(async {
        while !token_cancelled.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadline_before_headers_is_a_504_with_unknown_execution() {
    let owner_config = BridgeConfig {
        deadline: Some(Duration::from_millis(150)),
        ..BridgeConfig::default()
    };
    let running = exchange_with(
        request("GET", "/events", &[], empty_body()),
        link(STREAM_CREDIT),
        owner_config,
        BridgeConfig::default(),
        profile(),
        |_request: Request<ChannelBody>| async move {
            std::future::pending::<()>().await;
            Ok::<_, TestError>(Response::new(empty_body()))
        },
    )
    .await;
    assert_eq!(running.response.status(), StatusCode::GATEWAY_TIMEOUT);
    let error = running.response.extensions().get::<GatewayError>().copied();
    assert_eq!(
        error,
        Some(GatewayError {
            code: HttpErrorCode::DeadlineExceeded,
            execution: Execution::Unknown,
        })
    );
    let body = within(collect(running.response.into_body())).await.unwrap();
    assert_eq!(
        body,
        br#"{"error":{"code":"HTTP_DEADLINE_EXCEEDED","execution":"unknown"}}"#
    );
    let device = within(running.device).await.unwrap();
    assert_eq!(device.error, Some(HttpErrorCode::DeadlineExceeded));
    assert_eq!(device.execution, Execution::Dispatched);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadline_after_headers_errors_the_body_instead_of_ending_it() {
    let owner_config = BridgeConfig {
        deadline: Some(Duration::from_millis(200)),
        ..BridgeConfig::default()
    };
    let (tx, body) = test_body(1);
    let running = exchange_with(
        request("GET", "/events", &[], empty_body()),
        link(STREAM_CREDIT),
        owner_config,
        BridgeConfig::default(),
        profile(),
        move |_request: Request<ChannelBody>| async move {
            tx.send(data(b"data: first\n\n")).await.unwrap();
            tokio::spawn(async move {
                std::future::pending::<()>().await;
                drop(tx);
            });
            Ok::<_, TestError>(Response::builder().status(200).body(body).unwrap())
        },
    )
    .await;
    assert_eq!(running.response.status(), StatusCode::OK);
    let error = within(collect(running.response.into_body()))
        .await
        .unwrap_err();
    assert_eq!(error.code(), HttpErrorCode::DeadlineExceeded);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_completed_response_survives_a_later_upload_failure() {
    let (upload, body) = test_body(4);
    upload.send(data(b"unread upload")).await.unwrap();
    let mut running = exchange(
        request("POST", "/upload", &[], body),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        |request: Request<ChannelBody>| async move {
            // Answer without reading the upload; the device discards it.
            drop(request);
            Ok::<_, TestError>(Response::new(frames_body(
                vec![data(b"early and complete")],
                None,
            )))
        },
    )
    .await;
    let mut complete = Vec::new();
    while let Some(chunk) = within(next_chunk(running.response.body_mut())).await {
        complete.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(complete, b"early and complete");
    // Wait until the owner has seen the response FIN before failing the upload.
    within(async {
        while !http_body::Body::is_end_stream(running.response.body()) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    upload.send(Err(TestError)).await.unwrap();
    let owner = within(running.handle.report()).await;
    assert_eq!(owner.response, Outcome::Complete, "response stays complete");
    assert_eq!(owner.request, Outcome::Aborted);
    assert_eq!(owner.error, Some(HttpErrorCode::StreamInterrupted));
    let device = within(running.device).await.unwrap();
    assert_eq!(device.response, Outcome::Complete);
    assert_eq!(device.request, Outcome::Aborted);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streaming_upload_over_the_body_limit_is_413_from_the_owner() {
    let produced = Arc::new(AtomicU64::new(0));
    let upload = CountingBody {
        produced: Arc::clone(&produced),
        chunk: 4096,
        remaining: REQUEST_LIMIT + 1,
        dropped: Arc::new(AtomicBool::new(false)),
    };
    let running = exchange(
        request("POST", "/upload", &[], upload),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        |request: Request<ChannelBody>| async move {
            collect(request.into_body()).await.map_err(|_| TestError)?;
            Ok::<_, TestError>(Response::new(empty_body()))
        },
    )
    .await;
    assert_eq!(running.response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        running.response.extensions().get::<GatewayError>().copied(),
        Some(GatewayError {
            code: HttpErrorCode::BodyLimit,
            execution: Execution::Unknown,
        })
    );
    let device = within(running.device).await.unwrap();
    assert_eq!(device.error, Some(HttpErrorCode::BodyLimit));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_keeps_accounting_peer_frames_until_the_device_learns_of_the_reset() {
    const CREDIT: usize = 64 * 1024;
    let Link {
        to_device,
        device_rx,
        to_owner,
        owner_rx,
        ..
    } = link(CREDIT);
    // The owner's RESET travels slowly; the device's response writes are
    // stalled on credit the whole time.
    let (device_rx, _log) =
        tap_with_reset_delay(device_rx, CREDIT, Vec::new(), Duration::from_millis(150));
    let device = tokio::spawn(serve(
        profile(),
        BridgeConfig::default(),
        device_rx,
        to_owner,
        |_request: Request<ChannelBody>| async move {
            // A paced producer, so discarded bytes stay far below the
            // response body limit while the RESET is in flight.
            let (tx, body) = test_body(1);
            tokio::spawn(async move {
                while tx.send(data(&[b'x'; 4096])).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            });
            Ok::<_, TestError>(Response::builder().status(200).body(body).unwrap())
        },
    ));
    let (mut response, handle) = within(forward(
        request("GET", "/events", &[], empty_body()),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    within(next_chunk(response.body_mut()))
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(response);
    let device = within(device).await.unwrap();
    assert_eq!(
        device.error,
        Some(HttpErrorCode::Cancelled),
        "the device saw the ordered RESET, not a carrier failure"
    );
    assert_eq!(
        within(handle.report()).await.error,
        Some(HttpErrorCode::Cancelled)
    );
}
