//! Zero-body rules, exact lengths, trailers, content encoding, header
//! normalization and handler failures, enforced at both adapters.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use common::*;
use http::{Request, Response, StatusCode};
use tunnel_http_bridge::{
    BridgeConfig, ChannelBody, Execution, Frame, FrameReceiver, GatewayError, Outcome, Profile,
    ResetDetail, forward,
};
use tunnel_http_forward::{
    END_RECORD, HttpErrorCode, RecordKind, RequestPolicy, encode_body, encode_record,
};

fn gateway(response: &Response<ChannelBody>) -> Option<GatewayError> {
    response.extensions().get::<GatewayError>().copied()
}

fn expect_gateway(
    response: &Response<ChannelBody>,
    status: StatusCode,
    code: HttpErrorCode,
    execution: Execution,
) {
    assert_eq!(response.status(), status);
    assert_eq!(gateway(response), Some(GatewayError { code, execution }));
}

/// A handler that must never run.
fn forbidden_handler(
    invoked: Arc<AtomicBool>,
) -> impl FnOnce(Request<ChannelBody>) -> std::future::Ready<Result<Response<TestBody>, TestError>>
+ Send
+ 'static {
    move |_request| {
        invoked.store(true, Ordering::SeqCst);
        std::future::ready(Ok(Response::new(empty_body())))
    }
}

/// Forward a request that the ingress must reject: the device side sees no
/// frame at all, only the sender being dropped.
async fn rejected_at_ingress(request: Request<TestBody>) -> Response<ChannelBody> {
    let Link {
        to_device,
        mut device_rx,
        owner_rx,
        ..
    } = link(STREAM_CREDIT);
    let (response, handle) = within(forward(
        request,
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    assert_eq!(
        within(device_rx.recv()).await,
        None,
        "nothing reached the device"
    );
    let report = within(handle.report()).await;
    assert_eq!(report.execution, Execution::NotDispatched);
    response
}

// ----- ingress normalization before dispatch ---------------------------------

#[tokio::test]
async fn duplicate_or_conflicting_content_length_is_rejected_before_dispatch() {
    let cases: [&[(&str, &str)]; 5] = [
        &[("content-length", "5"), ("content-length", "5")],
        &[("content-length", "5"), ("content-length", "6")],
        &[("content-length", "5, 5")],
        &[("content-length", "-5")],
        &[("content-length", "5"), ("transfer-encoding", "chunked")],
    ];
    for headers in cases {
        let response =
            rejected_at_ingress(request("POST", "/upload", headers, full(b"hello"))).await;
        expect_gateway(
            &response,
            StatusCode::BAD_REQUEST,
            HttpErrorCode::InvalidHead,
            Execution::NotDispatched,
        );
    }
}

#[tokio::test]
async fn unsupported_framing_and_features_are_rejected_before_dispatch() {
    let cases: [(&str, &[(&str, &str)]); 6] = [
        ("POST", &[("transfer-encoding", "gzip, chunked")]),
        ("POST", &[("trailer", "x-checksum")]),
        ("POST", &[("content-encoding", "gzip")]),
        (
            "POST",
            &[("content-encoding", "identity"), ("content-encoding", "br")],
        ),
        (
            "POST",
            &[("connection", "x-case"), ("x-case", "hop-by-hop")],
        ),
        ("CONNECT", &[]),
    ];
    for (method, headers) in cases {
        let response = rejected_at_ingress(request(method, "/upload", headers, empty_body())).await;
        expect_gateway(
            &response,
            StatusCode::NOT_IMPLEMENTED,
            HttpErrorCode::UnsupportedFeature,
            Execution::NotDispatched,
        );
    }
}

#[tokio::test]
async fn unknown_or_credential_headers_fail_instead_of_being_stripped() {
    for headers in [
        &[("x-unlisted", "1")][..],
        &[("authorization", "Bearer synthetic")][..],
        &[("cookie", "synthetic=1")][..],
    ] {
        let response = rejected_at_ingress(request("POST", "/upload", headers, empty_body())).await;
        expect_gateway(
            &response,
            StatusCode::BAD_REQUEST,
            HttpErrorCode::InvalidHead,
            Execution::NotDispatched,
        );
    }
}

#[tokio::test]
async fn declared_length_above_the_limit_is_413_before_dispatch() {
    let length = (REQUEST_LIMIT + 1).to_string();
    let response = rejected_at_ingress(request(
        "POST",
        "/upload",
        &[("content-length", &length)],
        empty_body(),
    ))
    .await;
    expect_gateway(
        &response,
        StatusCode::PAYLOAD_TOO_LARGE,
        HttpErrorCode::BodyLimit,
        Execution::NotDispatched,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingress_consumes_only_transport_fields_and_trims_boundary_whitespace() {
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let running = exchange(
        request(
            "POST",
            "http://synthetic.invalid/upload?code=1",
            &[
                ("host", "synthetic.invalid"),
                ("connection", "keep-alive"),
                ("expect", "100-continue"),
                ("transfer-encoding", "chunked"),
                ("content-encoding", "identity"),
                ("x-case", " \tpadded value\t "),
                ("accept", "text/plain"),
                ("accept", "application/json"),
            ],
            frames_body(vec![data(b"abc"), data(b"de")], None),
        ),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        move |request: Request<ChannelBody>| async move {
            let headers: Vec<(String, String)> = request
                .headers()
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
                .collect();
            let uri = request.uri().to_string();
            let hint = http_body::Body::size_hint(request.body()).exact();
            let body = collect(request.into_body()).await.unwrap();
            seen_tx.send((uri, headers, hint, body)).unwrap();
            Ok::<_, TestError>(Response::new(empty_body()))
        },
    )
    .await;
    assert_eq!(running.response.status(), StatusCode::OK);
    let (uri, headers, hint, body) = within(seen_rx).await.unwrap();
    assert_eq!(uri, "/upload?code=1");
    let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
    assert!(!names.contains(&"host"));
    assert!(!names.contains(&"transfer-encoding"));
    assert!(!names.contains(&"expect"));
    assert!(!names.contains(&"connection"));
    assert!(headers.contains(&("x-case".into(), "padded value".into())));
    assert!(headers.contains(&("content-encoding".into(), "identity".into())));
    assert_eq!(
        headers.iter().filter(|(name, _)| name == "accept").count(),
        2,
        "repeated fields are kept separate"
    );
    assert_eq!(hint, None, "chunked upload has no declared length");
    assert_eq!(body, b"abcde");
}

// ----- exact request Content-Length through the owner pump -------------------

/// Upload `first`, wait until the handler runs, then upload `rest` and end.
/// Returns the exchange and what the handler's body read saw, or `None` if
/// the exchange's RESET cancelled the handler before its read returned.
async fn upload_with_length(
    declared: &str,
    first: &[u8],
    rest: &[u8],
) -> (Running, Option<Result<Vec<u8>, HttpErrorCode>>) {
    let (hint_tx, hint_rx) = tokio::sync::oneshot::channel();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (upload, body) = test_body(4);
    upload.send(data(first)).await.unwrap();
    let running = tokio::spawn(exchange(
        request("POST", "/upload", &[("content-length", declared)], body),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        move |request: Request<ChannelBody>| async move {
            hint_tx
                .send(http_body::Body::size_hint(request.body()).exact())
                .unwrap();
            let body = collect(request.into_body())
                .await
                .map_err(|error| error.code());
            let failed = body.is_err();
            seen_tx.send(body).unwrap();
            if failed {
                return Err(TestError);
            }
            Ok(Response::new(empty_body()))
        },
    ));
    let hint = within(hint_rx).await.unwrap();
    assert_eq!(hint, Some(declared.parse().unwrap()));
    if !rest.is_empty() {
        upload.send(data(rest)).await.unwrap();
    }
    drop(upload);
    let seen = within(seen_rx).await.ok();
    (within(running).await.unwrap(), seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_content_length_must_match_the_bytes_exactly() {
    let (running, seen) = upload_with_length("5", b"hel", b"lo").await;
    assert_eq!(seen, Some(Ok(b"hello".to_vec())));
    assert_eq!(running.response.status(), StatusCode::OK);
    assert_eq!(within(running.device).await.unwrap().error, None);

    for rest in [&b""[..], &b"lo!"[..]] {
        let (running, seen) = upload_with_length("5", b"hel", rest).await;
        // The handler either sees the body fail or is cancelled by the RESET
        // first (the device aborts the handler task); it never sees an end.
        if let Some(seen) = seen {
            assert_eq!(
                seen,
                Err(HttpErrorCode::LengthMismatch),
                "the handler saw the body fail, not end"
            );
        }
        expect_gateway(
            &running.response,
            StatusCode::BAD_REQUEST,
            HttpErrorCode::LengthMismatch,
            Execution::Unknown,
        );
        let device = within(running.device).await.unwrap();
        assert_eq!(device.request, Outcome::Aborted);
        assert_eq!(device.error, Some(HttpErrorCode::LengthMismatch));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovered_request_trailers_fail_the_upload_but_empty_trailers_do_not() {
    let running = exchange(
        request(
            "POST",
            "/upload",
            &[],
            frames_body(
                vec![data(b"abc"), trailers("x-checksum", "synthetic")],
                None,
            ),
        ),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        |request: Request<ChannelBody>| async move {
            collect(request.into_body()).await.map_err(|_| TestError)?;
            Ok::<_, TestError>(Response::new(empty_body()))
        },
    )
    .await;
    expect_gateway(
        &running.response,
        StatusCode::NOT_IMPLEMENTED,
        HttpErrorCode::UnsupportedFeature,
        Execution::Unknown,
    );
    let device = within(running.device).await.unwrap();
    assert_eq!(device.error, Some(HttpErrorCode::UnsupportedFeature));

    let empty = Ok(http_body::Frame::trailers(http::HeaderMap::new()));
    let running = exchange(
        request(
            "POST",
            "/upload",
            &[],
            frames_body(vec![data(b"abc"), empty], None),
        ),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        |request: Request<ChannelBody>| async move {
            let body = collect(request.into_body()).await.map_err(|_| TestError)?;
            Ok::<_, TestError>(Response::new(full(&body)))
        },
    )
    .await;
    assert_eq!(running.response.status(), StatusCode::OK);
    assert_eq!(
        within(collect(running.response.into_body())).await.unwrap(),
        b"abc"
    );
}

// ----- device-side request enforcement (raw owner) ---------------------------

/// Send raw request records to a device and return its RESET, if any.  When
/// `wait_for_dispatch` is set, `rest` is sent only after the handler runs.
async fn raw_request(
    head: Vec<u8>,
    rest: Vec<u8>,
    wait_for_dispatch: bool,
    invoked: Arc<AtomicBool>,
) -> (Option<ResetDetail>, Outcome) {
    let Link {
        to_device,
        device_rx,
        to_owner,
        mut owner_rx,
        ..
    } = link(STREAM_CREDIT);
    let handler_invoked = Arc::clone(&invoked);
    let device = tokio::spawn(tunnel_http_bridge::serve(
        profile(),
        BridgeConfig::default(),
        device_rx,
        to_owner,
        move |request: Request<ChannelBody>| async move {
            handler_invoked.store(true, Ordering::SeqCst);
            collect(request.into_body()).await.map_err(|_| TestError)?;
            Ok::<_, TestError>(Response::new(empty_body()))
        },
    ));
    to_device.send_data(Bytes::from(head)).await.unwrap();
    if wait_for_dispatch {
        within(async {
            while !invoked.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await;
    }
    if !rest.is_empty() {
        to_device.send_data(Bytes::from(rest)).await.unwrap();
    }
    let _ = to_device.finish();
    let reset = within(first_terminal(&mut owner_rx)).await;
    drop(to_device);
    let report = within(device).await.unwrap();
    (reset, report.request)
}

async fn first_terminal(rx: &mut FrameReceiver) -> Option<ResetDetail> {
    while let Some(frame) = rx.recv().await {
        match frame {
            Frame::Reset(detail) => return Some(detail),
            Frame::Fin => return None,
            Frame::Data(_) => {}
        }
    }
    None
}

fn request_head_record(json: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_record(RecordKind::RequestHead, json.as_bytes(), &mut out).unwrap();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_rejects_a_body_that_disagrees_with_body_length() {
    let head = r#"{"method":"POST","path":"/upload","query":"","http_version":"2","headers":[],"body_length":"5"}"#;
    for body in [&b"hel"[..], &b"hello!"[..]] {
        let mut rest = Vec::new();
        encode_body(body, &mut rest);
        rest.extend_from_slice(&END_RECORD);
        let invoked = Arc::new(AtomicBool::new(false));
        let (reset, request) =
            raw_request(request_head_record(head), rest, true, Arc::clone(&invoked)).await;
        assert_eq!(
            reset,
            Some(ResetDetail {
                code: HttpErrorCode::LengthMismatch,
                execution: Execution::Dispatched,
            })
        );
        assert_eq!(request, Outcome::Aborted);
        assert!(invoked.load(Ordering::SeqCst), "valid head was dispatched");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_rejects_an_invalid_head_without_dispatching() {
    // Content-Length inside the head array is forbidden framing.
    let head = r#"{"method":"POST","path":"/upload","query":"","http_version":"2","headers":[["content-length","5"]],"body_length":"5"}"#;
    let invoked = Arc::new(AtomicBool::new(false));
    let (reset, _) = raw_request(
        request_head_record(head),
        END_RECORD.to_vec(),
        false,
        Arc::clone(&invoked),
    )
    .await;
    assert_eq!(
        reset,
        Some(ResetDetail {
            code: HttpErrorCode::InvalidHead,
            execution: Execution::NotDispatched,
        })
    );
    assert!(!invoked.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_policy_rejection_is_a_502_with_the_devices_not_dispatched_record() {
    let invoked = Arc::new(AtomicBool::new(false));
    let owner = profile();
    let mut request_policy = RequestPolicy::new(REQUEST_LIMIT).unwrap();
    request_policy.allow_http_version(tunnel_http_forward::HttpVersion::Http11);
    let device_profile = Arc::new(Profile {
        request: request_policy,
        response: owner.response.clone(),
    });
    let running = exchange_with(
        request("GET", "/events", &[], empty_body()),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        BridgeConfig::default(),
        device_profile,
        forbidden_handler(Arc::clone(&invoked)),
    )
    .await;
    expect_gateway(
        &running.response,
        StatusCode::BAD_GATEWAY,
        HttpErrorCode::InvalidHead,
        Execution::NotDispatched,
    );
    assert!(!invoked.load(Ordering::SeqCst));
}

// ----- handler responses -----------------------------------------------------

async fn respond<B>(method: &str, uri: &str, response: Response<B>) -> Running
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
{
    exchange(
        request(method, uri, &[], empty_body()),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        move |_request: Request<ChannelBody>| async move { Ok::<_, TestError>(response) },
    )
    .await
}

fn with_status(status: u16, headers: &[(&str, &str)], body: TestBody) -> Response<TestBody> {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(body).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_body_responses_forward_without_body_or_length() {
    for (method, status) in [("HEAD", 200), ("GET", 204), ("GET", 205), ("GET", 304)] {
        let uri = if method == "HEAD" {
            "/events"
        } else {
            "/status"
        };
        let running = respond(
            method,
            uri,
            with_status(status, &[("etag", "\"synthetic\"")], empty_body()),
        )
        .await;
        assert_eq!(running.response.status().as_u16(), status);
        assert!(running.response.headers().get("content-length").is_none());
        assert_eq!(running.response.headers()["etag"], "\"synthetic\"");
        let body = within(collect(running.response.into_body())).await.unwrap();
        assert!(body.is_empty());
        let device = within(running.device).await.unwrap();
        assert_eq!(device.error, None, "{method} {status}");
        assert_eq!(device.response, Outcome::Complete);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handler_body_or_length_on_a_zero_body_response_is_rejected_before_headers() {
    for (method, status) in [("HEAD", 200), ("GET", 204), ("GET", 205), ("GET", 304)] {
        let uri = if method == "HEAD" {
            "/events"
        } else {
            "/status"
        };
        let mut cases = vec![
            // Streaming data with no size hint: found by draining.
            with_status(status, &[], frames_body(vec![data(b"x")], None)),
            // A known non-zero size.
            with_status(status, &[], full(b"abc")),
        ];
        if status == 204 || status == 205 {
            // No content exists, so a non-zero length is contradictory.
            cases.push(with_status(
                status,
                &[("content-length", "12")],
                empty_body(),
            ));
        }
        for response in cases {
            let running = respond(method, uri, response).await;
            expect_gateway(
                &running.response,
                StatusCode::BAD_GATEWAY,
                HttpErrorCode::LengthMismatch,
                Execution::Dispatched,
            );
        }
    }
}

/// A fake device that answers with raw response records.
async fn raw_response(method: &str, uri: &str, records: Vec<u8>) -> Response<ChannelBody> {
    let Link {
        to_device,
        mut device_rx,
        to_owner,
        owner_rx,
        ..
    } = link(STREAM_CREDIT);
    tokio::spawn(async move {
        while let Some(frame) = device_rx.recv().await {
            if frame == Frame::Fin {
                break;
            }
        }
        to_owner.send_data(Bytes::from(records)).await.unwrap();
        let _ = to_owner.finish();
        // Keep the request direction open until the owner is done.
        device_rx.discard_until_terminal().await;
    });
    let (response, _handle) = within(forward(
        request(method, uri, &[], empty_body()),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    response
}

fn response_head_record(json: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_record(RecordKind::ResponseHead, json.as_bytes(), &mut out).unwrap();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_enforces_zero_body_rules_on_device_responses() {
    for (method, uri, status) in [
        ("HEAD", "/events", 200),
        ("GET", "/status", 204),
        ("GET", "/status", 205),
        ("GET", "/status", 304),
    ] {
        // A non-zero body_length is an invalid head: nothing is committed.
        let mut records = response_head_record(&format!(
            r#"{{"status":{status},"headers":[],"body_length":"5"}}"#
        ));
        encode_body(b"hello", &mut records);
        records.extend_from_slice(&END_RECORD);
        let response = raw_response(method, uri, records).await;
        expect_gateway(
            &response,
            StatusCode::BAD_GATEWAY,
            HttpErrorCode::InvalidHead,
            Execution::Unknown,
        );

        // A zero head followed by BODY: headers commit, then the body errors.
        let mut records = response_head_record(&format!(
            r#"{{"status":{status},"headers":[],"body_length":"0"}}"#
        ));
        encode_body(b"x", &mut records);
        records.extend_from_slice(&END_RECORD);
        let response = raw_response(method, uri, records).await;
        assert_eq!(response.status().as_u16(), status);
        let error = within(collect(response.into_body())).await.unwrap_err();
        assert_eq!(error.code(), HttpErrorCode::LengthMismatch);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_rejects_device_bodies_that_disagree_with_body_length() {
    for body in [&b"hel"[..], &b"hello!"[..]] {
        let mut records = response_head_record(r#"{"status":200,"headers":[],"body_length":"5"}"#);
        encode_body(body, &mut records);
        records.extend_from_slice(&END_RECORD);
        let response = raw_response("GET", "/events", records).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-length"], "5");
        let error = within(collect(response.into_body())).await.unwrap_err();
        assert_eq!(error.code(), HttpErrorCode::LengthMismatch);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handler_content_length_is_carried_and_checked_exactly() {
    let running = respond(
        "GET",
        "/events",
        with_status(
            200,
            &[("content-length", "5")],
            frames_body(vec![data(b"he"), data(b"llo")], None),
        ),
    )
    .await;
    assert_eq!(running.response.headers()["content-length"], "5");
    assert_eq!(
        within(collect(running.response.into_body())).await.unwrap(),
        b"hello"
    );

    for chunks in [vec![data(b"hel")], vec![data(b"hel"), data(b"lo!")]] {
        let Link {
            to_device,
            device_rx,
            to_owner,
            owner_rx,
            ..
        } = link(STREAM_CREDIT);
        let (owner_rx, log) = tap(owner_rx, STREAM_CREDIT, Vec::new());
        let device = tokio::spawn(tunnel_http_bridge::serve(
            profile(),
            BridgeConfig::default(),
            device_rx,
            to_owner,
            move |_request: Request<ChannelBody>| async move {
                Ok::<_, TestError>(with_status(
                    200,
                    &[("content-length", "5")],
                    frames_body(chunks, None),
                ))
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
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "headers already committed"
        );
        let error = within(collect(response.into_body())).await.unwrap_err();
        assert_eq!(error.code(), HttpErrorCode::LengthMismatch);
        let device = within(device).await.unwrap();
        assert_eq!(device.response, Outcome::Aborted);
        assert_eq!(device.error, Some(HttpErrorCode::LengthMismatch));
        let log = log.lock().unwrap();
        assert!(
            !log.record_kinds().contains(&RecordKind::End),
            "no fabricated END"
        );
        assert!(!log.fin);
        assert!(log.reset.is_some());
        assert!(
            body_bytes(&log.bytes) <= 5,
            "never more than declared on the wire"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_handler_framing_is_rejected_before_headers() {
    let cases = [
        (
            with_status(
                200,
                &[("content-length", "3"), ("content-length", "3")],
                full(b"abc"),
            ),
            HttpErrorCode::InvalidHead,
        ),
        (
            with_status(200, &[("content-length", "4")], full(b"abc")),
            HttpErrorCode::LengthMismatch,
        ),
        (
            with_status(200, &[("trailer", "x-checksum")], empty_body()),
            HttpErrorCode::UnsupportedFeature,
        ),
        (
            with_status(200, &[("content-encoding", "gzip")], full(b"abc")),
            HttpErrorCode::UnsupportedFeature,
        ),
        (
            with_status(200, &[("transfer-encoding", "chunked")], empty_body()),
            HttpErrorCode::UnsupportedFeature,
        ),
        (
            with_status(200, &[("set-cookie", "synthetic=1")], empty_body()),
            HttpErrorCode::InvalidHead,
        ),
        (
            with_status(200, &[("x-unlisted", "1")], empty_body()),
            HttpErrorCode::InvalidHead,
        ),
        (
            with_status(101, &[], empty_body()),
            HttpErrorCode::InvalidHead,
        ),
    ];
    for (response, code) in cases {
        let running = respond("GET", "/events", response).await;
        expect_gateway(
            &running.response,
            StatusCode::BAD_GATEWAY,
            code,
            Execution::Dispatched,
        );
        let device = within(running.device).await.unwrap();
        assert_eq!(device.error, Some(code));
    }
    // Identity is accepted where the profile allows the field.
    let running = respond(
        "GET",
        "/events",
        with_status(200, &[("content-encoding", "identity")], full(b"abc")),
    )
    .await;
    assert_eq!(running.response.headers()["content-encoding"], "identity");
    assert_eq!(
        within(collect(running.response.into_body())).await.unwrap(),
        b"abc"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovered_response_trailers_error_the_body_after_headers() {
    let Link {
        to_device,
        device_rx,
        to_owner,
        owner_rx,
        ..
    } = link(STREAM_CREDIT);
    let (owner_rx, log) = tap(owner_rx, STREAM_CREDIT, Vec::new());
    tokio::spawn(tunnel_http_bridge::serve(
        profile(),
        BridgeConfig::default(),
        device_rx,
        to_owner,
        |_request: Request<ChannelBody>| async move {
            Ok::<_, TestError>(with_status(
                200,
                &[],
                frames_body(
                    vec![data(b"data: 1\n\n"), trailers("x-checksum", "synthetic")],
                    None,
                ),
            ))
        },
    ));
    let (response, handle) = within(forward(
        request("GET", "/events", &[], empty_body()),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let error = within(collect(response.into_body())).await.unwrap_err();
    assert_eq!(error.code(), HttpErrorCode::UnsupportedFeature);
    assert_eq!(within(handle.report()).await.response, Outcome::Aborted);
    let log = log.lock().unwrap();
    assert!(!log.record_kinds().contains(&RecordKind::End));
    assert_eq!(
        log.reset.map(|detail| detail.code),
        Some(HttpErrorCode::UnsupportedFeature)
    );
}

// ----- handler failures ------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handler_panic_or_error_before_headers_is_a_502_marked_dispatched() {
    let running = exchange(
        request("GET", "/events", &[], empty_body()),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        |_request: Request<ChannelBody>| async move {
            if std::hint::black_box(true) {
                panic!("synthetic handler panic");
            }
            Ok::<_, TestError>(Response::new(empty_body()))
        },
    )
    .await;
    expect_gateway(
        &running.response,
        StatusCode::BAD_GATEWAY,
        HttpErrorCode::StreamInterrupted,
        Execution::Dispatched,
    );
    let body = within(collect(running.response.into_body())).await.unwrap();
    assert!(
        !String::from_utf8(body)
            .unwrap()
            .contains("synthetic handler panic")
    );

    let running = exchange(
        request("GET", "/events", &[], empty_body()),
        link(STREAM_CREDIT),
        BridgeConfig::default(),
        |_request: Request<ChannelBody>| async move { Err::<Response<TestBody>, _>(TestError) },
    )
    .await;
    expect_gateway(
        &running.response,
        StatusCode::BAD_GATEWAY,
        HttpErrorCode::StreamInterrupted,
        Execution::Dispatched,
    );
    let owner = within(running.handle.report()).await;
    let device = within(running.device).await.unwrap();
    assert_eq!(owner.execution, Execution::Dispatched);
    assert_eq!(device.execution, Execution::Dispatched);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handler_body_error_after_headers_errors_the_stream_without_end() {
    let Link {
        to_device,
        device_rx,
        to_owner,
        owner_rx,
        ..
    } = link(STREAM_CREDIT);
    let (owner_rx, log) = tap(owner_rx, STREAM_CREDIT, Vec::new());
    let device = tokio::spawn(tunnel_http_bridge::serve(
        profile(),
        BridgeConfig::default(),
        device_rx,
        to_owner,
        |_request: Request<ChannelBody>| async move {
            Ok::<_, TestError>(with_status(
                200,
                &[("content-type", "text/event-stream")],
                frames_body(vec![data(b"data: partial\n\n"), Err(TestError)], None),
            ))
        },
    ));
    let (response, handle) = within(forward(
        request("GET", "/events", &[], empty_body()),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(gateway(&response).is_none());
    let mut body = response.into_body();
    assert_eq!(
        within(next_chunk(&mut body)).await.unwrap().unwrap(),
        "data: partial\n\n"
    );
    let error = within(next_chunk(&mut body)).await.unwrap().unwrap_err();
    assert_eq!(error.code(), HttpErrorCode::StreamInterrupted);
    assert!(within(next_chunk(&mut body)).await.is_none());
    let owner = within(handle.report()).await;
    assert_eq!(owner.response, Outcome::Aborted);
    assert_eq!(owner.execution, Execution::Dispatched);
    let device = within(device).await.unwrap();
    assert_eq!(device.response, Outcome::Aborted);
    let log = log.lock().unwrap();
    assert_eq!(
        log.record_kinds(),
        [RecordKind::ResponseHead, RecordKind::Body]
    );
    assert!(!log.fin);
    assert!(log.reset.is_some());
}

#[test]
fn normalization_names_the_specific_rejection() {
    use tunnel_http_bridge::NormalizeError;
    use tunnel_http_bridge::normalize::request_head;
    use tunnel_http_forward::{CodecError, HeaderRule};
    let policy = profile().request.clone();
    type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], NormalizeError);
    let cases: [Case<'_>; 10] = [
        (
            "POST",
            &[("trailer", "x-checksum")],
            NormalizeError::DeclaredTrailers,
        ),
        (
            "POST",
            &[("content-length", "1"), ("transfer-encoding", "chunked")],
            NormalizeError::TransferEncodingWithContentLength,
        ),
        (
            "POST",
            &[("content-length", "1"), ("content-length", "1")],
            NormalizeError::DuplicateContentLength,
        ),
        (
            "POST",
            &[("content-length", "1 1")],
            NormalizeError::InvalidContentLength,
        ),
        (
            "POST",
            &[("transfer-encoding", "chunked, gzip")],
            NormalizeError::UnsupportedTransferEncoding,
        ),
        (
            "POST",
            &[("content-encoding", "gzip")],
            NormalizeError::UnsupportedContentEncoding,
        ),
        (
            "POST",
            &[("connection", "upgrade")],
            NormalizeError::UnsupportedConnectionOption,
        ),
        (
            "POST",
            &[("expect", "nothing")],
            NormalizeError::UnsupportedExpectation,
        ),
        (
            "POST",
            &[("expect", "103-checkpoint")],
            NormalizeError::UnsupportedExpectation,
        ),
        (
            "POST",
            &[("x-unlisted", "1")],
            NormalizeError::Codec(CodecError::InvalidHeader(HeaderRule::NotAllowed)),
        ),
    ];
    for (method, headers, expected) in cases {
        let (parts, ()) = request(method, "/upload", headers, ()).into_parts();
        assert_eq!(request_head(&parts, &policy).unwrap_err(), expected);
    }
    let mut parts = request("POST", "/upload", &[("transfer-encoding", "chunked")], ())
        .into_parts()
        .0;
    parts.version = http::Version::HTTP_2;
    assert_eq!(
        request_head(&parts, &policy).unwrap_err(),
        NormalizeError::UnsupportedTransferEncoding,
        "chunked framing does not exist in HTTP/2"
    );
    for field in ["connection", "keep-alive", "proxy-connection"] {
        let value = if field == "connection" {
            "keep-alive"
        } else {
            "1"
        };
        let mut parts = request("POST", "/upload", &[(field, value)], ())
            .into_parts()
            .0;
        parts.version = http::Version::HTTP_2;
        assert_eq!(
            request_head(&parts, &policy).unwrap_err(),
            NormalizeError::ConnectionSpecificField,
            "RFC 9113 section 8.2.2: {field}"
        );
    }
}

// A paused clock on the current-thread runtime: the timer below fires only
// once every task is parked, so "nothing arrived" is observed at quiescence
// rather than after a wall-clock guess.
#[tokio::test(start_paused = true)]
async fn device_does_not_end_the_request_body_at_end_without_fin() {
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let Link {
        to_device,
        device_rx,
        to_owner,
        mut owner_rx,
        ..
    } = link(STREAM_CREDIT);
    let device = tokio::spawn(tunnel_http_bridge::serve(
        profile(),
        BridgeConfig::default(),
        device_rx,
        to_owner,
        move |request: Request<ChannelBody>| async move {
            // The RESET aborts this handler future, as designed, possibly
            // before it is polled again to see the failed body.  The body is
            // therefore read, and its outcome reported, by a task the abort
            // does not reach; the outcome is then the bridge's alone.
            let body = request.into_body();
            let reader = tokio::spawn(async move {
                let outcome = collect(body).await.map_err(|error| error.code());
                result_tx.send(outcome).unwrap();
            });
            let _ = reader.await;
            Ok::<_, TestError>(Response::new(empty_body()))
        },
    ));
    let mut records = request_head_record(
        r#"{"method":"POST","path":"/upload","query":"","http_version":"2","headers":[],"body_length":"5"}"#,
    );
    encode_body(b"hello", &mut records);
    records.extend_from_slice(&END_RECORD);
    to_device.send_data(Bytes::from(records)).await.unwrap();
    // END arrived, FIN did not: once the bridge and the reader are idle, the
    // read must still be pending.
    let mut result_rx = result_rx;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), &mut result_rx)
            .await
            .is_err(),
        "the body did not end before FIN"
    );
    to_device.reset(ResetDetail {
        code: HttpErrorCode::StreamInterrupted,
        execution: Execution::Unknown,
    });
    assert_eq!(
        within(result_rx).await.unwrap(),
        Err(HttpErrorCode::StreamInterrupted),
        "END followed by RESET is a failed body, never a successful one"
    );
    let reset = within(first_terminal(&mut owner_rx)).await;
    assert!(reset.is_some());
    assert_eq!(within(device).await.unwrap().request, Outcome::Aborted);
}

#[tokio::test(start_paused = true)]
async fn owner_does_not_end_the_response_body_at_end_without_fin() {
    let Link {
        to_device,
        mut device_rx,
        to_owner,
        owner_rx,
        ..
    } = link(STREAM_CREDIT);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        while let Some(frame) = device_rx.recv().await {
            if frame == Frame::Fin {
                break;
            }
        }
        let mut records = response_head_record(r#"{"status":200,"headers":[],"body_length":"5"}"#);
        encode_body(b"hello", &mut records);
        records.extend_from_slice(&END_RECORD);
        to_owner.send_data(Bytes::from(records)).await.unwrap();
        release_rx.await.unwrap();
        to_owner.reset(ResetDetail {
            code: HttpErrorCode::StreamInterrupted,
            execution: Execution::Dispatched,
        });
        device_rx.discard_until_terminal().await;
    });
    let (response, handle) = within(forward(
        request("GET", "/events", &[], empty_body()),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    let mut body = response.into_body();
    assert_eq!(
        within(next_chunk(&mut body)).await.unwrap().unwrap(),
        "hello"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), next_chunk(&mut body))
            .await
            .is_err(),
        "the body did not end before FIN"
    );
    release_tx.send(()).unwrap();
    let error = within(next_chunk(&mut body)).await.unwrap().unwrap_err();
    assert_eq!(error.code(), HttpErrorCode::StreamInterrupted);
    assert_eq!(within(handle.report()).await.response, Outcome::Aborted);
}

#[tokio::test]
async fn unsupported_expectation_is_417_before_dispatch() {
    let response = rejected_at_ingress(request(
        "POST",
        "/upload",
        &[("expect", "103-checkpoint")],
        empty_body(),
    ))
    .await;
    expect_gateway(
        &response,
        StatusCode::EXPECTATION_FAILED,
        HttpErrorCode::UnsupportedFeature,
        Execution::NotDispatched,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn representation_content_length_on_head_and_304_is_dropped_not_rejected() {
    for (method, uri, status, length) in [
        ("HEAD", "/events", 200, "1234"),
        ("GET", "/status", 304, "1234"),
        ("GET", "/status", 204, "0"),
        ("GET", "/status", 205, "0"),
    ] {
        let running = respond(
            method,
            uri,
            with_status(status, &[("content-length", length)], empty_body()),
        )
        .await;
        assert_eq!(
            running.response.status().as_u16(),
            status,
            "{method} {status}"
        );
        assert!(gateway(&running.response).is_none());
        assert!(
            running.response.headers().get("content-length").is_none(),
            "no representation length is forwarded"
        );
        assert!(
            within(collect(running.response.into_body()))
                .await
                .unwrap()
                .is_empty()
        );
        let device = within(running.device).await.unwrap();
        assert_eq!(device.error, None);
        assert_eq!(device.response, Outcome::Complete);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_gone_before_the_head_is_queued_is_503_not_dispatched() {
    let Link {
        to_device,
        device_rx,
        owner_rx,
        ..
    } = link(STREAM_CREDIT);
    drop(device_rx);
    let (response, handle) = within(forward(
        request("GET", "/events", &[], empty_body()),
        profile(),
        BridgeConfig::default(),
        to_device,
        owner_rx,
    ))
    .await;
    expect_gateway(
        &response,
        StatusCode::SERVICE_UNAVAILABLE,
        HttpErrorCode::StreamInterrupted,
        Execution::NotDispatched,
    );
    assert_eq!(
        within(handle.report()).await.execution,
        Execution::NotDispatched
    );
}

#[tokio::test]
async fn debug_output_never_contains_payload_or_header_values() {
    use tunnel_http_bridge::normalize::{request_head, response_head};
    const SENTINEL: &str = "SENTINEL-payload-7f3a";
    let frame = Frame::Data(Bytes::from(format!("data: {SENTINEL}\n\n")));
    let body = ChannelBody::full(Bytes::from(SENTINEL));
    let (parts, ()) = request("POST", "/upload", &[("x-case", SENTINEL)], ()).into_parts();
    let ingress = request_head(&parts, &profile().request).unwrap();
    assert!(String::from_utf8_lossy(&ingress.record).contains(SENTINEL));
    let (parts, ()) = Response::builder()
        .status(200)
        .header("x-case", SENTINEL)
        .body(())
        .unwrap()
        .into_parts();
    let handler = response_head(
        &parts,
        None,
        tunnel_http_forward::Method::Get,
        &profile().response,
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&handler.record).contains(SENTINEL));
    let (sender, channel_body) = ChannelBody::channel(1, None, None);
    sender.send(Bytes::from(SENTINEL)).await.unwrap();
    for rendered in [
        format!("{frame:?}"),
        format!("{body:?}"),
        format!("{ingress:?}"),
        format!("{handler:?}"),
        format!("{channel_body:?}"),
        format!("{sender:?}"),
    ] {
        assert!(!rendered.contains(SENTINEL), "{rendered}");
        assert!(!rendered.contains("SENTINEL"), "{rendered}");
    }
    assert_eq!(format!("{frame:?}"), "Data { payload_len: 29 }");
}
