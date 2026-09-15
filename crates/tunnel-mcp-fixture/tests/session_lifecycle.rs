#![cfg(unix)]
//! Stdio export lifecycle guards (review round 1): legacy session idle
//! expiry, a stalled consumer confined to its own stream, duplicate in-flight
//! progress tokens, and process-group cleanup of wrapper descendants.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use common::{body_bytes, count_lines, exchange, fixture_binary, stdio_export_with, within};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use tunnel_http_bridge::ChannelBody;

const LEGACY: &str = "mcp-2025-11-25";
const CURRENT: &str = "mcp-2026-07-28";
const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}"#;

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

fn build<B>(method: &str, headers: &[(&'static str, String)], body: B) -> Request<B> {
    let mut builder = Request::builder()
        .method(method)
        .uri("/mcp")
        .header("host", "gateway.test");
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    builder.body(body).expect("request")
}

fn post(headers: &[(&'static str, String)], body: &str) -> Request<Full<Bytes>> {
    build("POST", headers, Full::new(Bytes::from(body.to_owned())))
}

async fn open_session(export: &tunnel_mcp_export::McpExport) -> String {
    let response = within(exchange(export, post(&legacy_headers(None), INIT))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .expect("session")
        .to_owned();
    let _ = body_bytes(response).await;
    session
}

fn tools_list(id: u64) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list"}}"#)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_legacy_session_expires_even_with_an_open_get_stream() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(
        LEGACY,
        workspace.path(),
        1,
        &fixture_binary(),
        "session_idle_seconds = 1\n",
    );
    let session = open_session(&export).await;
    let mut get_headers = legacy_headers(Some(&session));
    get_headers.retain(|(name, _)| *name != "accept" && *name != "content-type");
    get_headers.push(("accept", "text/event-stream".to_owned()));
    let stream = within(exchange(
        &export,
        build("GET", &get_headers, Full::new(Bytes::new())),
    ))
    .await;
    assert_eq!(stream.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    // The session ended: its stream is interrupted, its child is gone and
    // its only slot is free for a new session.
    assert!(body_bytes(stream).await.is_err(), "open GET interrupted");
    let response = within(exchange(
        &export,
        post(&legacy_headers(Some(&session)), &tools_list(1)),
    ))
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let diagnostics = export.diagnostics();
    assert_eq!(diagnostics.sessions_expired, 1, "{diagnostics:?}");
    for _ in 0..200 {
        if export.diagnostics().children_running == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(export.diagnostics().children_running, 0);
    let _replacement = open_session(&export).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activity_keeps_a_legacy_session_alive() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(
        LEGACY,
        workspace.path(),
        1,
        &fixture_binary(),
        "session_idle_seconds = 3\n",
    );
    let session = open_session(&export).await;
    // Five 1 s gaps outlast the 3 s idle limit, with 2 s of margin per
    // exchange for a loaded host.
    for id in 1..=5u64 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let response = within(exchange(
            &export,
            post(&legacy_headers(Some(&session)), &tools_list(id)),
        ))
        .await;
        assert_eq!(response.status(), StatusCode::OK, "request {id}");
        let _ = body_bytes(response).await;
    }
    assert_eq!(export.diagnostics().sessions_expired, 0);
}

fn direct(headers: &[(&'static str, String)], body: &str) -> Request<ChannelBody> {
    build(
        "POST",
        headers,
        ChannelBody::full(Bytes::from(body.to_owned())),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_consumer_interrupts_only_its_own_stream() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(LEGACY, workspace.path(), 1, &fixture_binary(), "");
    let session = open_session(&export).await;
    let headers = legacy_headers(Some(&session));
    // A progress stream whose consumer never reads: served directly by the
    // export so no bridge buffer absorbs the backlog.
    let stalled = within(export.handle(direct(
        &headers,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"progress","arguments":{"steps":100},"_meta":{"progressToken":"stalled"}}}"#,
    )))
    .await
    .expect("stalled stream head");
    assert_eq!(stalled.status(), StatusCode::OK);
    let log = workspace.path().join("invocations.log");
    for _ in 0..400 {
        if count_lines(&log, "progress") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    // Another request on the same session still completes promptly.
    let echo = tokio::time::timeout(
        Duration::from_secs(5),
        export.handle(direct(
            &headers,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
        )),
    )
    .await
    .expect("the session pump is not blocked by the stalled stream")
    .expect("echo");
    assert_eq!(echo.status(), StatusCode::OK);
    let bytes = tokio::time::timeout(Duration::from_secs(5), echo.into_body().collect())
        .await
        .expect("echo body")
        .expect("echo body ok")
        .to_bytes();
    assert!(String::from_utf8_lossy(&bytes).contains(r#""id":2"#));
    assert!(export.diagnostics().stalled_streams >= 1);
    // The stalled stream itself is interrupted, not completed.
    let collected = tokio::time::timeout(Duration::from_secs(5), stalled.into_body().collect())
        .await
        .expect("stalled body ends");
    assert!(collected.is_err(), "the stalled stream is interrupted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_duplicate_in_flight_progress_token_is_rejected() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(LEGACY, workspace.path(), 1, &fixture_binary(), "");
    let session = open_session(&export).await;
    let headers = legacy_headers(Some(&session));
    let sleep = |id: u64, token: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"sleep","arguments":{{"label":"t{id}"}},"_meta":{{"progressToken":"{token}"}}}}}}"#
        )
    };
    let first_export = export.clone();
    let first_headers = headers.clone();
    let first_body = sleep(1, "shared");
    let first = tokio::spawn(async move {
        let response = exchange(&first_export, post(&first_headers, &first_body)).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(response);
    });
    let log = workspace.path().join("invocations.log");
    for _ in 0..400 {
        if count_lines(&log, "sleep") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let response = within(exchange(&export, post(&headers, &sleep(2, "shared")))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_bytes(response).await.expect("body");
    assert!(String::from_utf8_lossy(&body).contains("progress token"));
    assert_eq!(count_lines(&log, "sleep"), 1, "the duplicate never ran");
    first.abort();
}

fn wrapper_script(dir: &Path) -> PathBuf {
    let script = dir.join("wrapper.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n/bin/sleep 300 &\necho $! > grandchild.pid\nexec \"{}\" \"$@\"\n",
            fixture_binary().display()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    script
}

fn alive(pid: &str) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

async fn grandchild_is_reaped(workspace: &Path) {
    let mut pid = String::new();
    for _ in 0..200 {
        pid = std::fs::read_to_string(workspace.join("grandchild.pid"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !pid.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!pid.is_empty(), "the wrapper started a grandchild");
    for _ in 0..500 {
        if !alive(&pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Clean up before failing so a red run leaks nothing.
    let _ = std::process::Command::new("/bin/kill")
        .args(["-9", &pid])
        .status();
    panic!("grandchild {pid} outlived its process group");
}

fn current_call(id: u64, tool: &str) -> (Vec<(&'static str, String)>, String) {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}}}}"#
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrapper_descendants_die_with_a_completed_request() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let export = stdio_export_with(CURRENT, workspace.path(), 2, &script, "");
    let (headers, body) = current_call(1, "echo");
    let response = within(exchange(&export, post(&headers, &body))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = body_bytes(response).await;
    grandchild_is_reaped(workspace.path()).await;
    assert!(export.diagnostics().child_group_kills >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrapper_descendants_die_when_the_server_crashes() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let export = stdio_export_with(CURRENT, workspace.path(), 2, &script, "");
    let (headers, body) = current_call(1, "crash");
    let response = within(exchange(&export, post(&headers, &body))).await;
    let _ = body_bytes(response).await;
    grandchild_is_reaped(workspace.path()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrapper_descendants_die_when_a_legacy_session_is_deleted() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let export = stdio_export_with(LEGACY, workspace.path(), 2, &script, "");
    let session = open_session(&export).await;
    let mut delete_headers = legacy_headers(Some(&session));
    delete_headers.retain(|(name, _)| *name != "accept" && *name != "content-type");
    let response = within(exchange(
        &export,
        build("DELETE", &delete_headers, Full::new(Bytes::new())),
    ))
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    grandchild_is_reaped(workspace.path()).await;
}
