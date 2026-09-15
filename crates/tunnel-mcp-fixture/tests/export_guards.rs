#![cfg(unix)]
//! Raw-HTTP guard tests of both export kinds through the in-process
//! http-forward/1 bridge: allowlists before dispatch, buffered validation,
//! body limits, ID preservation with concurrent identical IDs, child output
//! bounds, stderr, sessions, and hostile fixed backends.

mod common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use common::{body_bytes, exchange, http_export, stdio_export, within};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tunnel_mcp_fixture::STDERR_MARKER;

const CURRENT: &str = "mcp-2026-07-28";
const LEGACY: &str = "mcp-2025-11-25";

fn post(headers: &[(&str, &str)], body: impl Into<Bytes>) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.test");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Full::new(body.into())).expect("request")
}

fn current_call(
    id: &str,
    tool: &str,
    arguments: &str,
    extra_meta: &str,
) -> (Vec<(&'static str, String)>, String) {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{{"name":"raw","version":"1"}},"io.modelcontextprotocol/clientCapabilities":{{}}{extra_meta}}}}}}}"#
    );
    let headers = vec![
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
        ("mcp-protocol-version", "2026-07-28".to_owned()),
        ("mcp-method", "tools/call".to_owned()),
        ("mcp-name", tool.to_owned()),
    ];
    (headers, body)
}

fn as_refs<'a>(headers: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("json body")
}

/// Every `data:` payload of an SSE body, or the whole JSON body.
fn messages(bytes: &[u8]) -> Vec<serde_json::Value> {
    let text = std::str::from_utf8(bytes).expect("utf-8");
    if text.trim_start().starts_with('{') {
        return vec![json(bytes)];
    }
    text.split("\n\n")
        .filter_map(|event| event.strip_prefix("data: "))
        .map(|data| serde_json::from_str(data).expect("event json"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlisted_routes_headers_and_versions_never_reach_the_child() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(CURRENT, workspace.path(), 4);
    let (headers, body) = current_call("1", "echo", "{}", "");
    // A neighbouring header is refused by the codec before dispatch.
    let mut with_origin = as_refs(&headers);
    with_origin.push(("origin", "https://hostile.example"));
    let response = within(exchange(&export, post(&with_origin, body.clone()))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let gateway = json(&body_bytes(response).await.expect("body"));
    assert_eq!(gateway["error"]["code"], "HTTP_INVALID_HEAD");
    assert_eq!(gateway["error"]["execution"], "not_dispatched");
    // Legacy-only mechanisms are unlisted in the 2026 profile.
    for (name, value) in [("mcp-session-id", "abc"), ("last-event-id", "1")] {
        let mut extra = as_refs(&headers);
        extra.push((name, value));
        let response = within(exchange(&export, post(&extra, body.clone()))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
    }
    // GET and DELETE have no meaning in the 2026 profile: 405, no child.
    for method in ["GET", "DELETE"] {
        let request = Request::builder()
            .method(method)
            .uri("/mcp")
            .header("host", "gateway.test")
            .header("accept", "text/event-stream")
            .body(Full::new(Bytes::new()))
            .expect("request");
        let response = within(exchange(&export, request)).await;
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}"
        );
    }
    // Buffered validation: a header/body mismatch is a local -32020.
    let mut mismatch = headers.clone();
    mismatch.retain(|(name, _)| *name != "mcp-name");
    mismatch.push(("mcp-name", "other".to_owned()));
    let response = within(exchange(&export, post(&as_refs(&mismatch), body.clone()))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = json(&body_bytes(response).await.expect("body"));
    assert_eq!(error["error"]["code"], -32020);
    assert_eq!(error["id"], 1);
    // An unsupported protocol version lists the supported one.
    let mut version = headers.clone();
    version.retain(|(name, _)| *name != "mcp-protocol-version");
    version.push(("mcp-protocol-version", "2025-11-25".to_owned()));
    let response = within(exchange(&export, post(&as_refs(&version), body.clone()))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = json(&body_bytes(response).await.expect("body"));
    assert_eq!(error["error"]["code"], -32022);
    assert_eq!(
        error["error"]["data"]["supported"],
        serde_json::json!(["2026-07-28"])
    );
    // A client notification has no per-request child to reach: 202, no
    // body, dropped.
    let notification =
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#;
    let response = within(exchange(
        &export,
        post(
            &[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "notifications/cancelled"),
            ],
            notification,
        ),
    ))
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(body_bytes(response).await.expect("body").is_empty());
    assert_eq!(export.diagnostics().notifications_dropped, 1);
    // A body over the request limit is refused before dispatch.
    let (headers, _) = current_call("2", "echo", "{}", "");
    let oversized = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"echo","arguments":{{"pad":"{}"}}}}}}"#,
        "p".repeat(70_000)
    );
    let response = within(exchange(&export, post(&as_refs(&headers), oversized))).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    assert_eq!(
        export.diagnostics().children_spawned,
        0,
        "no child ever ran"
    );
    assert!(!workspace.path().join("invocations.log").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_identical_request_ids_are_isolated_and_preserved_exactly() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(CURRENT, workspace.path(), 8);
    let mut tasks = Vec::new();
    for index in 0..4u64 {
        let export = export.clone();
        tasks.push(tokio::spawn(async move {
            let token = format!(r#","progressToken":"token-{index}""#);
            let (headers, body) =
                current_call("9007199254740993", "progress", r#"{"steps":3}"#, &token);
            let response = within(exchange(&export, post(&as_refs(&headers), body))).await;
            assert_eq!(response.status(), StatusCode::OK);
            (index, body_bytes(response).await.expect("body"))
        }));
    }
    for task in tasks {
        let (index, bytes) = task.await.expect("join");
        let text = std::str::from_utf8(&bytes).expect("utf-8");
        assert!(text.contains(r#""id":9007199254740993"#), "exact large id");
        let events = messages(&bytes);
        let progress: Vec<_> = events
            .iter()
            .filter(|event| event["method"] == "notifications/progress")
            .collect();
        assert_eq!(progress.len(), 3, "{text}");
        for event in progress {
            assert_eq!(event["params"]["progressToken"], format!("token-{index}"));
        }
        let last = events.last().expect("final");
        assert!(last["result"].is_object());
    }
    // A string ID with escapes round-trips.
    let (headers, body) = current_call(r#""id-ü-\"q\"""#, "echo", "{}", "");
    let response = within(exchange(&export, post(&as_refs(&headers), body))).await;
    let bytes = body_bytes(response).await.expect("body");
    assert_eq!(
        messages(&bytes).last().expect("final")["id"],
        "id-\u{fc}-\"q\""
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn child_output_limits_stderr_and_child_process_limits_hold() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(CURRENT, workspace.path(), 1);
    // A result line above the 1 MiB message limit kills the child and
    // interrupts the exchange rather than truncating it.
    let (headers, body) = current_call("1", "big", r#"{"bytes":2000000}"#, "");
    let response = within(exchange(&export, post(&as_refs(&headers), body))).await;
    let status = response.status();
    let outcome = body_bytes(response).await;
    assert!(
        status == StatusCode::BAD_GATEWAY || outcome.is_err(),
        "never a successful truncated result: {status}"
    );
    let diagnostics = export.diagnostics();
    assert_eq!(diagnostics.child_invalid_output, 1, "{diagnostics:?}");
    // 4 MiB of stderr is drained, counted and never forwarded.
    let (headers, body) = current_call("2", "stderr_flood", r#"{"bytes":4194304}"#, "");
    let response = within(exchange(&export, post(&as_refs(&headers), body))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = body_bytes(response).await.expect("body");
    assert!(bytes.len() < 4096 && !bytes.windows(8).any(|window| window == b"eeeeeeee"));
    for _ in 0..200 {
        if export.diagnostics().child_stderr_bytes >= 4_194_304 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(export.diagnostics().child_stderr_bytes >= 4_194_304);
    // With one child slot busy, a second request is refused, not queued.
    let busy = export.clone();
    let (headers, body) = current_call("3", "sleep", r#"{"label":"busy"}"#, "");
    let sleeper = tokio::spawn(async move {
        let response = exchange(&busy, post(&as_refs(&headers), body)).await;
        // Hold the response so the child keeps its slot until dropped.
        tokio::time::sleep(Duration::from_millis(800)).await;
        drop(response);
    });
    for _ in 0..200 {
        if common::count_lines(&workspace.path().join("invocations.log"), "sleep") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (headers, body) = current_call("4", "echo", "{}", "");
    let response = within(exchange(&export, post(&as_refs(&headers), body))).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    sleeper.abort();
    let _ = sleeper.await;
    for _ in 0..400 {
        if export.diagnostics().children_running == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(export.diagnostics().children_running, 0, "children reaped");
    let _ = STDERR_MARKER;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_sessions_require_ids_and_end_on_delete() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(LEGACY, workspace.path(), 2);
    let base = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
    ];
    let init = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}"#;
    let response = within(exchange(&export, post(&base, init))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .expect("session")
        .to_owned();
    assert_eq!(session.len(), 32);
    let _ = body_bytes(response).await;
    let with_session = |extra: &[(&'static str, &'static str)]| {
        let mut headers: Vec<(&str, String)> =
            base.iter().map(|(n, v)| (*n, (*v).to_owned())).collect();
        headers.push(("mcp-protocol-version", "2025-11-25".to_owned()));
        headers.push(("mcp-session-id", session.clone()));
        for (name, value) in extra {
            headers.push((name, (*value).to_owned()));
        }
        headers
    };
    let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    // Without a session: 400.  Unknown session: 404.
    let mut no_session: Vec<(&str, &str)> = base.to_vec();
    no_session.push(("mcp-protocol-version", "2025-11-25"));
    let response = within(exchange(&export, post(&no_session, list))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let mut unknown = no_session.clone();
    unknown.push(("mcp-session-id", "00000000000000000000000000000000"));
    let response = within(exchange(&export, post(&unknown, list))).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // initialized notification: 202 with no body.
    let initialized = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let headers = with_session(&[]);
    let refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let response = within(exchange(&export, post(&refs, initialized))).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(body_bytes(response).await.expect("body").is_empty());
    let response = within(exchange(&export, post(&refs, list))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let listed = messages(&body_bytes(response).await.expect("body"));
    assert_eq!(listed.last().expect("final")["id"], 1);
    // One standalone GET stream per session.
    let get = |headers: &[(&str, String)]| {
        let mut builder = Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("host", "gateway.test");
        for (name, value) in headers {
            if *name != "content-type" {
                builder = builder.header(*name, value.as_str());
            }
        }
        builder
            .header("accept", "text/event-stream")
            .body(Full::new(Bytes::new()))
            .expect("get")
    };
    let get_headers: Vec<(&str, String)> = headers
        .iter()
        .filter(|(name, _)| *name != "accept")
        .cloned()
        .collect();
    let first = within(exchange(&export, get(&get_headers))).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = within(exchange(&export, get(&get_headers))).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    drop(first);
    // DELETE ends the session and kills its child.
    let mut delete = Request::builder()
        .method("DELETE")
        .uri("/mcp")
        .header("host", "gateway.test");
    for (name, value) in &headers {
        if *name == "mcp-session-id" || *name == "mcp-protocol-version" {
            delete = delete.header(*name, value.as_str());
        }
    }
    let response = within(exchange(
        &export,
        delete.body(Full::new(Bytes::new())).expect("delete"),
    ))
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = within(exchange(&export, post(&refs, list))).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    for _ in 0..200 {
        if export.diagnostics().children_running == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(export.diagnostics().children_running, 0);
}

type Recorded = Arc<Mutex<Vec<HashMap<String, String>>>>;

/// A hostile fixed backend answering every request with `response`.
async fn hostile_backend(response: fn() -> Response<Full<Bytes>>) -> (String, Recorded) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let recorded: Recorded = Arc::default();
    let seen = Arc::clone(&recorded);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let seen = Arc::clone(&seen);
                    async move {
                        seen.lock().expect("lock").push(
                            request
                                .headers()
                                .iter()
                                .map(|(name, value)| {
                                    (name.to_string(), value.to_str().unwrap_or("").to_owned())
                                })
                                .collect(),
                        );
                        Ok::<_, Infallible>(response())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{address}/private/mcp"), recorded)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_http_backends_cannot_redirect_challenge_encode_or_leak_headers() {
    let dir = tempfile::tempdir().expect("dir");
    let token = dir.path().join("backend.token");
    std::fs::write(&token, "synthetic-backend-token\n").expect("token");
    let (headers, body) = current_call("5", "echo", "{}", "");

    type Case = (fn() -> Response<Full<Bytes>>, StatusCode);
    let cases: [Case; 4] = [
        (
            || {
                Response::builder()
                    .status(302)
                    .header("location", "http://169.254.169.254/latest")
                    .body(Full::new(Bytes::new()))
                    .expect("redirect")
            },
            StatusCode::BAD_GATEWAY,
        ),
        (
            || {
                Response::builder()
                    .status(401)
                    .header("www-authenticate", "Bearer realm=\"private-backend\"")
                    .body(Full::new(Bytes::from_static(b"private challenge")))
                    .expect("challenge")
            },
            StatusCode::BAD_GATEWAY,
        ),
        (
            || {
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .header("content-encoding", "gzip")
                    .body(Full::new(Bytes::from_static(b"\x1f\x8b")))
                    .expect("gzip")
            },
            StatusCode::BAD_GATEWAY,
        ),
        (
            || {
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .header("set-cookie", "backend=private")
                    .header("www-authenticate", "Bearer realm=\"private\"")
                    .header("server", "private-backend/1.0")
                    .header("x-private-address", "10.1.2.3")
                    .body(Full::new(Bytes::from_static(
                        br#"{"jsonrpc":"2.0","id":5,"result":{"content":[]}}"#,
                    )))
                    .expect("ok")
            },
            StatusCode::OK,
        ),
    ];
    for (index, (respond, expected)) in cases.into_iter().enumerate() {
        let (url, recorded) = hostile_backend(respond).await;
        let export = http_export(CURRENT, &url, Some(&token));
        let response = within(exchange(&export, post(&as_refs(&headers), body.clone()))).await;
        assert_eq!(response.status(), expected, "case {index}");
        let response_headers = response.headers().clone();
        let bytes = body_bytes(response).await.expect("body");
        for forbidden in [
            "location",
            "www-authenticate",
            "set-cookie",
            "server",
            "x-private-address",
            "content-encoding",
        ] {
            assert!(
                response_headers.get(forbidden).is_none(),
                "case {index}: {forbidden}"
            );
        }
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("private") && !text.contains("169.254"),
            "case {index}: {text}"
        );
        let seen = recorded.lock().expect("lock").clone();
        assert_eq!(
            seen.len(),
            1,
            "case {index}: exactly one backend request, no redirect follow"
        );
        let request = &seen[0];
        assert_eq!(request["authorization"], "Bearer synthetic-backend-token");
        assert_eq!(request["accept-encoding"], "identity");
        assert!(request["host"].starts_with("127.0.0.1:"), "fixed Host");
        assert_eq!(request["mcp-name"], "echo");
        assert!(!request.contains_key("origin"));
        assert!(!request.values().any(|value| value.contains("gateway.test")));
    }

    // A closed port is a pre-dispatch 502 JSON-RPC error.
    let closed = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}/mcp", closed.local_addr().expect("address"));
    drop(closed);
    let export = http_export(CURRENT, &url, None);
    let response = within(exchange(&export, post(&as_refs(&headers), body.clone()))).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let error = json(&body_bytes(response).await.expect("body"));
    assert_eq!(error["error"]["code"], -32603);
    assert_eq!(export.diagnostics().dispatched, 0);
}
