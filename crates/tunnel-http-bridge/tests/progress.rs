//! Transport progress budgets wired into both adapters (implementation
//! gate 4, review finding A).  Every test runs on Tokio's paused clock, so
//! elapsed times are exact and no test sleeps for real.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::BodyExt;
use tokio::time::Instant;
use tunnel_http_bridge::{
    BridgeConfig, ChannelBody, ExchangeReport, Execution, Frame, FrameReceiver, FrameSender,
    PauseController, PauseSignal, ProgressBudgets, ProgressKind, channel, forward_paused,
    serve_paused,
};
use tunnel_http_forward::{
    END_RECORD, HeaderField, HttpErrorCode, HttpVersion, Method, RequestHead, ResponseHead,
    encode_body, encode_request_head, encode_response_head,
};

use common::{STREAM_CREDIT, TestError, profile};

const QUEUE_ONE: usize = 1;

fn config() -> BridgeConfig {
    let progress = ProgressBudgets::default()
        .with_first_head(Duration::from_secs(10))
        .and_then(|budgets| budgets.with_record(Duration::from_secs(10)))
        .and_then(|budgets| budgets.with_credit_stall(Duration::from_secs(30)))
        .and_then(|budgets| budgets.with_fin_after_end(Duration::from_secs(10)))
        .expect("budgets");
    BridgeConfig::default()
        .with_deadline(Duration::from_secs(3_600))
        .and_then(|config| config.with_body_queue(QUEUE_ONE))
        .expect("config")
        .with_progress(progress)
}

fn request_head_record() -> Vec<u8> {
    let head = RequestHead {
        method: Method::Post,
        path: "/upload".into(),
        query: String::new(),
        http_version: HttpVersion::Http11,
        headers: vec![HeaderField::new("content-type", "application/octet-stream")],
        body_length: None,
    };
    let mut out = Vec::new();
    encode_request_head(&head, &profile().request, &mut out).expect("head");
    out
}

fn body_record(len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    encode_body(&vec![7u8; len], &mut out);
    out
}

struct Device {
    to_device: FrameSender,
    from_device: FrameReceiver,
    task: tokio::task::JoinHandle<ExchangeReport>,
}

/// A device serving a handler that never reads its request body until
/// `release` is notified, then drains it and answers 200.
fn device(pause: PauseSignal, release: Arc<tokio::sync::Notify>) -> Device {
    let (to_device, from_owner, _) = channel(STREAM_CREDIT);
    let (to_owner, from_device, _) = channel(STREAM_CREDIT);
    let task = tokio::spawn(serve_paused(
        profile(),
        config(),
        from_owner,
        to_owner,
        pause,
        move |request: Request<ChannelBody>| async move {
            release.notified().await;
            let _ = request.into_body().collect().await;
            Ok::<_, TestError>(Response::new(common::empty_body()))
        },
    ));
    Device {
        to_device,
        from_device,
        task,
    }
}

/// Wait for the device's RESET (returning when it arrived relative to
/// `started`), then close the owner side so terminal discard ends, and
/// return the device's report.
async fn reset_then_report(mut device: Device, started: Instant) -> (Duration, ExchangeReport) {
    let code = loop {
        match device.from_device.recv().await {
            Some(Frame::Reset(detail)) => break detail.code,
            Some(_) => {}
            None => panic!("the device dropped its sender without RESET"),
        }
    };
    let at = started.elapsed();
    assert_eq!(code, HttpErrorCode::DeadlineExceeded);
    drop(device.to_device);
    let report = device.task.await.expect("join");
    (at, report)
}

#[tokio::test(start_paused = true)]
async fn a_missing_request_head_expires_the_first_head_budget_before_dispatch() {
    let release = Arc::new(tokio::sync::Notify::new());
    let started = Instant::now();
    let device = device(PauseSignal::never(), release);
    let (at, report) = reset_then_report(device, started).await;
    assert_eq!(at, Duration::from_secs(10));
    assert_eq!(report.error, Some(HttpErrorCode::DeadlineExceeded));
    assert_eq!(report.progress_expired, Some(ProgressKind::FirstHead));
    assert_eq!(report.execution, Execution::NotDispatched);
}

#[tokio::test(start_paused = true)]
async fn trickled_bytes_of_one_record_do_not_restart_the_record_budget() {
    let release = Arc::new(tokio::sync::Notify::new());
    let device = device(PauseSignal::never(), release);
    device
        .to_device
        .send_data(Bytes::from(request_head_record()))
        .await
        .expect("head");
    let record = body_record(64);
    let started = Instant::now();
    // One byte every three seconds: each arrival is progress on the wire,
    // but the same record stays partial.
    let trickle = {
        let sender = device.to_device.clone();
        tokio::spawn(async move {
            for byte in record {
                tokio::time::sleep(Duration::from_secs(3)).await;
                if sender.send_data(Bytes::from(vec![byte])).await.is_err() {
                    return;
                }
            }
        })
    };
    let reset = tokio::spawn(reset_then_report(device, started));
    let (at, report) = reset.await.expect("join");
    trickle.abort();
    // The record's first byte arrived at 3 s; its budget ran out 10 s later.
    assert_eq!(at, Duration::from_secs(13));
    assert_eq!(report.progress_expired, Some(ProgressKind::Record));
    assert_eq!(report.error, Some(HttpErrorCode::DeadlineExceeded));
    assert_eq!(report.execution, Execution::Dispatched);
}

#[tokio::test(start_paused = true)]
async fn a_recorded_freeze_pauses_the_record_budget() {
    let release = Arc::new(tokio::sync::Notify::new());
    let freeze = PauseController::new(false);
    let device = device(freeze.signal(), release);
    let mut head = request_head_record();
    let record = body_record(64);
    head.extend_from_slice(&record[..20]);
    device
        .to_device
        .send_data(Bytes::from(head))
        .await
        .expect("partial");
    let started = Instant::now();
    let reset = tokio::spawn(reset_then_report(device, started));
    tokio::time::sleep(Duration::from_secs(4)).await;
    freeze.set(true);
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert!(
        !reset.is_finished(),
        "a freeze stops the partial-record clock"
    );
    freeze.set(false);
    let (at, report) = reset.await.expect("join");
    assert_eq!(at, Duration::from_secs(130));
    assert_eq!(report.progress_expired, Some(ProgressKind::Record));
}

#[tokio::test(start_paused = true)]
async fn time_blocked_on_an_unread_handler_body_is_withheld_credit_not_a_stall() {
    let release = Arc::new(tokio::sync::Notify::new());
    let device = device(PauseSignal::never(), Arc::clone(&release));
    let mut bytes = request_head_record();
    // Two complete records fill the one-chunk body queue and block the
    // decoder; the third is only partly sent.
    bytes.extend_from_slice(&body_record(100));
    bytes.extend_from_slice(&body_record(100));
    let third = body_record(100);
    bytes.extend_from_slice(&third[..50]);
    device
        .to_device
        .send_data(Bytes::from(bytes))
        .await
        .expect("send");
    let started = Instant::now();
    let reset = tokio::spawn(reset_then_report(device, started));
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert!(
        !reset.is_finished(),
        "a handler that withholds credit keeps the budget stopped"
    );
    release.notify_one();
    // The handler drains; the rest of the third record never comes.
    let (at, report) = reset.await.expect("join");
    assert_eq!(at, Duration::from_secs(310));
    assert_eq!(report.progress_expired, Some(ProgressKind::Record));
}

#[tokio::test(start_paused = true)]
async fn fin_must_follow_end_within_its_budget() {
    let release = Arc::new(tokio::sync::Notify::new());
    release.notify_one();
    let device = device(PauseSignal::never(), release);
    let mut bytes = request_head_record();
    bytes.extend_from_slice(&body_record(10));
    bytes.extend_from_slice(&END_RECORD);
    device
        .to_device
        .send_data(Bytes::from(bytes))
        .await
        .expect("send");
    let started = Instant::now();
    let (at, report) = reset_then_report(device, started).await;
    assert_eq!(at, Duration::from_secs(10));
    assert_eq!(report.progress_expired, Some(ProgressKind::FinAfterEnd));
    // END alone never completed the request.
    assert_ne!(report.request, tunnel_http_bridge::Outcome::Complete);
}

#[tokio::test(start_paused = true)]
async fn an_output_credit_stall_fails_the_ingress_with_a_504_and_a_freeze_pauses_it() {
    let freeze = PauseController::new(false);
    // A device side that never reads: the small handoff fills at once.
    let (to_device, _from_owner_unread, _) = channel(64);
    let (to_owner, from_device, _) = channel(STREAM_CREDIT);
    let (tx, body) = common::test_body(4);
    let request = Request::builder()
        .method("POST")
        .uri("/upload")
        .header("content-type", "application/octet-stream")
        .body(body)
        .expect("request");
    let started = Instant::now();
    let pause = freeze.signal();
    let exchange = tokio::spawn(async move {
        forward_paused(request, profile(), config(), to_device, from_device, pause).await
    });
    tx.send(common::data(&[1; 1024])).await.expect("chunk");
    tokio::time::sleep(Duration::from_secs(20)).await;
    freeze.set(true);
    tokio::time::sleep(Duration::from_secs(60)).await;
    freeze.set(false);
    let (response, handle) = exchange.await.expect("join");
    // 30 s of stall plus the 60 s freeze.
    assert_eq!(started.elapsed(), Duration::from_secs(90));
    assert_eq!(response.status(), 504);
    drop(to_owner);
    let report = handle.report().await;
    assert_eq!(report.progress_expired, Some(ProgressKind::CreditStall));
    assert_eq!(report.error, Some(HttpErrorCode::DeadlineExceeded));
}

#[tokio::test(start_paused = true)]
async fn a_partial_response_record_expires_at_the_ingress_after_headers() {
    let (to_device, mut from_owner, _) = channel(STREAM_CREDIT);
    let (to_owner, from_device, _) = channel(STREAM_CREDIT);
    let request = Request::builder()
        .method("GET")
        .uri("/status")
        .body(common::empty_body())
        .expect("request");
    let exchange = tokio::spawn(async move {
        forward_paused(
            request,
            profile(),
            config(),
            to_device,
            from_device,
            PauseSignal::never(),
        )
        .await
    });
    // Drain the request.
    loop {
        if matches!(from_owner.recv().await, Some(Frame::Fin) | None) {
            break;
        }
    }
    let head = ResponseHead {
        status: 200,
        headers: vec![HeaderField::new("content-type", "text/event-stream")],
        body_length: None,
    };
    let mut bytes = Vec::new();
    encode_response_head(&head, &profile().response, Method::Get, &mut bytes).expect("head");
    let record = body_record(40);
    bytes.extend_from_slice(&record[..30]);
    to_owner.send_data(Bytes::from(bytes)).await.expect("send");
    let started = Instant::now();
    let (response, handle) = exchange.await.expect("join");
    assert_eq!(response.status(), 200);
    let collected = response.into_body().collect().await;
    assert!(collected.is_err(), "a truncated record never ends the body");
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    drop(to_owner);
    let report = handle.report().await;
    assert_eq!(report.progress_expired, Some(ProgressKind::Record));
}
