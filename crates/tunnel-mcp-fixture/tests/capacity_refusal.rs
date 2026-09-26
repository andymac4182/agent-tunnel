#![cfg(unix)]
//! Task row M6-C145 (the M6-C122 soak defect): a stdio export at its
//! `max_children` bound refuses the next session or request with a
//! documented, retryable capacity refusal -- `503`, JSON-RPC code
//! `-32050`, `error.data` carrying `retryable`, `retryAfterMs` and
//! `execution = "not_dispatched"` -- and never with `-32603` (internal
//! error), which is what the soak's MCP load steps saw from 8 concurrent
//! sessions on one device.
//!
//! Deterministic: the table is filled with exactly `max_children` sessions
//! opened concurrently, so no timing decides which request is refused.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{body_bytes, count_lines, exchange, stdio_export, within};
use http::{Request, StatusCode};
use http_body_util::Full;
use tunnel_mcp_export::McpExport;

const LEGACY: &str = "mcp-2025-11-25";
const CURRENT: &str = "mcp-2026-07-28";
const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"capacity","version":"1"}}}"#;
/// The soak's concurrency: eight sessions, the default `max_children`.
const SESSIONS: usize = 8;

fn request(method: &str, headers: &[(&str, String)], body: &str) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method(method)
        .uri("/mcp")
        .header("host", "gateway.test");
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    builder
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("request")
}

fn legacy_headers(session: Option<&str>) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
        ("mcp-protocol-version", "2025-11-25".to_owned()),
    ];
    if let Some(session) = session {
        headers.push(("mcp-session-id", session.to_owned()));
    }
    headers
}

async fn initialize(export: &McpExport) -> (StatusCode, Option<String>, serde_json::Value) {
    let response = within(exchange(
        export,
        request("POST", &legacy_headers(None), INIT),
    ))
    .await;
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .map(|value| value.to_str().expect("session").to_owned());
    let bytes = body_bytes(response).await.expect("body");
    let body = parse(&bytes);
    (status, session, body)
}

/// The JSON-RPC body of a JSON or single-event SSE response.
fn parse(bytes: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(bytes);
    let json = text
        .lines()
        .find_map(|line| line.strip_prefix("data:"))
        .unwrap_or(&text)
        .trim();
    serde_json::from_str(json).unwrap_or(serde_json::Value::Null)
}

/// The documented capacity refusal, and never the internal-error code.
fn assert_capacity_refusal(status: StatusCode, body: &serde_json::Value, id: u64) {
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let error = &body["error"];
    assert_ne!(error["code"], -32603, "never an internal error: {body}");
    assert_eq!(
        error["code"],
        tunnel_mcp::message::codes::CAPACITY_EXHAUSTED,
        "{body}"
    );
    assert_eq!(error["code"], -32050, "the documented value: {body}");
    assert_eq!(error["data"]["retryable"], true, "{body}");
    assert_eq!(error["data"]["execution"], "not_dispatched", "{body}");
    assert!(
        error["data"]["retryAfterMs"]
            .as_u64()
            .is_some_and(|ms| ms > 0),
        "{body}"
    );
    assert_eq!(body["id"], id, "the refusal answers the request: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_concurrent_sessions_fill_the_table_and_the_ninth_is_a_retryable_refusal() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(LEGACY, workspace.path(), SESSIONS);

    // Eight sessions opened at once: every one is admitted.
    let opened = futures_join(&export, SESSIONS).await;
    let mut sessions = Vec::new();
    for (status, session, body) in opened {
        assert_eq!(status, StatusCode::OK, "{body}");
        sessions.push(session.expect("an admitted initialize names its session"));
    }
    assert_eq!(export.diagnostics().children_running, SESSIONS as u64);

    // The ninth is refused, typed and retryable, before any child starts.
    let (status, session, body) = initialize(&export).await;
    assert!(session.is_none(), "a refused initialize opens no session");
    assert_capacity_refusal(status, &body, 0);
    assert_eq!(export.diagnostics().children_running, SESSIONS as u64);

    // The refusal is honest about retrying: once a session ends, the same
    // request is admitted.
    let mut delete = legacy_headers(Some(&sessions[0]));
    delete.retain(|(name, _)| *name != "accept" && *name != "content-type");
    let response = within(exchange(&export, request("DELETE", &delete, ""))).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let mut admitted = false;
    for _ in 0..200 {
        let (status, session, _) = initialize(&export).await;
        if status == StatusCode::OK && session.is_some() {
            admitted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(admitted, "a retry after a session ended is admitted");
}

async fn futures_join(
    export: &McpExport,
    count: usize,
) -> Vec<(StatusCode, Option<String>, serde_json::Value)> {
    let tasks: Vec<_> = (0..count)
        .map(|_| {
            let export = export.clone();
            tokio::spawn(async move { initialize(&export).await })
        })
        .collect();
    let mut out = Vec::with_capacity(count);
    for task in tasks {
        out.push(task.await.expect("initialize task"));
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_2026_request_past_the_child_limit_is_the_same_retryable_refusal() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(CURRENT, workspace.path(), 1);
    let call = |id: u64, tool: &str| {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{{"name":"capacity","version":"1"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
        );
        let headers = vec![
            ("content-type", "application/json".to_owned()),
            ("accept", "application/json, text/event-stream".to_owned()),
            ("mcp-protocol-version", "2026-07-28".to_owned()),
            ("mcp-method", "tools/call".to_owned()),
            ("mcp-name", tool.to_owned()),
        ];
        request("POST", &headers, &body)
    };
    // One sleeping request holds the only child slot.
    let busy = export.clone();
    let sleeper = tokio::spawn({
        let request = call(1, "sleep");
        async move {
            let response = exchange(&busy, request).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(response);
        }
    });
    for _ in 0..400 {
        if count_lines(&workspace.path().join("invocations.log"), "sleep") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(export.diagnostics().children_running, 1);
    let response = within(exchange(&export, call(2, "echo"))).await;
    let status = response.status();
    let body = parse(&body_bytes(response).await.expect("body"));
    assert_capacity_refusal(status, &body, 2);
    sleeper.abort();
    let _ = sleeper.await;
}

/// Review of #187: the Streamable HTTP export's session table
/// (`http_backend.rs`) refuses a new `initialize` once one principal holds
/// `MAX_SESSIONS_PER_BINDING` sessions, before the backend is dialled.  That
/// refusal is the same documented `-32050`; the request's ID is not parsed
/// there, so the body carries `"id": null` as JSON-RPC requires of an error
/// whose request ID is unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_http_session_table_is_the_same_retryable_refusal_with_a_null_id() {
    let markers = tempfile::tempdir().expect("markers");
    let (url, shutdown) = common::rmcp_http_backend(true, markers.path()).await;
    let export = common::http_export(LEGACY, &url, None);
    let share = tunnel_mcp_export::http_backend::MAX_SESSIONS_PER_BINDING;
    for index in 0..share {
        let (status, session, body) = initialize(&export).await;
        assert_eq!(status, StatusCode::OK, "session {index}: {body}");
        assert!(session.is_some(), "session {index}");
    }
    let dispatched = export.diagnostics().dispatched;
    let response = within(exchange(
        &export,
        request("POST", &legacy_headers(None), INIT),
    ))
    .await;
    let status = response.status();
    let body = parse(&body_bytes(response).await.expect("body"));
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let error = &body["error"];
    assert_ne!(error["code"], -32603, "never an internal error: {body}");
    assert_eq!(error["code"], -32050, "{body}");
    assert_eq!(error["data"]["retryable"], true, "{body}");
    assert_eq!(error["data"]["execution"], "not_dispatched", "{body}");
    assert!(
        body.as_object()
            .is_some_and(|object| object.contains_key("id"))
            && body["id"].is_null(),
        "an unknown request ID is sent as null, not omitted: {body}"
    );
    assert_eq!(
        export.diagnostics().dispatched,
        dispatched,
        "refused before the backend is dialled"
    );
    shutdown.cancel();
}
