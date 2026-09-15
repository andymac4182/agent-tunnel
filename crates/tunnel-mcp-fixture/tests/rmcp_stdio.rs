#![cfg(unix)]
//! The official rmcp client (3.4.0) against the stdio export through the
//! in-process http-forward/1 bridge, for both pinned profiles.

mod common;

use std::time::Duration;

use common::{connect, count_lines, gateway, stdio_export, wait_for_file, within};
use rmcp::model::{CallToolRequestParams, ClientRequest, Request, RequestMetaObject};
use rmcp::service::PeerRequestOptions;
use tunnel_mcp_fixture::{IMAGE_PNG_BASE64, STDERR_MARKER};

fn arguments(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().cloned().expect("object")
}

fn text_of(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .find_map(|block| block.as_text().map(|text| text.text.clone()))
        .expect("text block")
}

async fn discovery_echo_meta_progress_and_bytes(profile: &str, legacy: bool) {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(profile, workspace.path(), 8);
    let gateway = gateway(export.clone(), workspace.path());
    let (client, handler) = connect(&gateway, legacy).await;

    let tools = within(client.list_all_tools()).await.expect("tools/list");
    let names: Vec<_> = tools.iter().map(|tool| tool.name.to_string()).collect();
    assert!(names.contains(&"echo".to_owned()) && names.contains(&"sleep".to_owned()));

    // _meta and arguments reach the server exactly.
    let mut meta = RequestMetaObject::new();
    meta.insert(
        "io.agent-tunnel.test/marker".to_owned(),
        serde_json::json!({"nested": [1, "two", 3.5], "unicode": "caf\u{e9}"}),
    );
    let mut params = CallToolRequestParams::new("echo")
        .with_arguments(arguments(serde_json::json!({"a": 1, "b": "x"})));
    params.meta = Some(meta);
    let echoed = within(client.call_tool(params)).await.expect("echo");
    let seen: serde_json::Value = serde_json::from_str(&text_of(&echoed)).expect("echo json");
    assert_eq!(seen["arguments"], serde_json::json!({"a": 1, "b": "x"}));
    assert_eq!(
        seen["meta"]["io.agent-tunnel.test/marker"],
        serde_json::json!({"nested": [1, "two", 3.5], "unicode": "caf\u{e9}"})
    );
    if !legacy {
        assert_eq!(
            seen["meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
    }
    assert!(echoed.content.iter().any(|block| {
        block
            .as_image()
            .is_some_and(|image| image.data == IMAGE_PNG_BASE64)
    }));

    // Progress notifications for this request arrive before its result.
    let handle = within(
        client.send_cancellable_request(
            ClientRequest::CallToolRequest(Request::new(
                CallToolRequestParams::new("progress")
                    .with_arguments(arguments(serde_json::json!({"steps": 4}))),
            )),
            PeerRequestOptions::no_options(),
        ),
    )
    .await
    .expect("progress request");
    within(handle.await_response())
        .await
        .expect("progress result");
    let progress = handler.progress.lock().expect("lock").clone();
    assert_eq!(progress, vec![1.0, 2.0, 3.0, 4.0], "{profile}");

    // A 300 KiB result is byte-exact.
    let big = within(
        client.call_tool(
            CallToolRequestParams::new("big")
                .with_arguments(arguments(serde_json::json!({"bytes": 300_000}))),
        ),
    )
    .await
    .expect("big");
    let text = text_of(&big);
    assert_eq!(text.len(), 300_000);
    assert!(text.bytes().all(|byte| byte == b'b'));

    let diagnostics = export.diagnostics();
    if legacy {
        assert_eq!(diagnostics.children_spawned, 1, "one child per session");
    } else {
        assert!(diagnostics.children_spawned >= 4, "one child per request");
    }
    let _ = within(client.cancel()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_profile_discovery_echo_meta_progress_and_bytes() {
    discovery_echo_meta_progress_and_bytes("mcp-2026-07-28", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_profile_initialize_echo_meta_progress_and_bytes() {
    discovery_echo_meta_progress_and_bytes("mcp-2025-11-25", true).await;
}

async fn cancellation_reaches_the_child(profile: &str, legacy: bool) {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(profile, workspace.path(), 8);
    let gateway = gateway(export.clone(), workspace.path());
    let (client, _) = connect(&gateway, legacy).await;
    let handle = within(
        client.send_cancellable_request(
            ClientRequest::CallToolRequest(Request::new(
                CallToolRequestParams::new("sleep")
                    .with_arguments(arguments(serde_json::json!({"label": "c1"}))),
            )),
            PeerRequestOptions::no_options(),
        ),
    )
    .await
    .expect("sleep request");
    let log = workspace.path().join("invocations.log");
    for _ in 0..400 {
        if count_lines(&log, "sleep") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(count_lines(&log, "sleep"), 1, "sleep started");
    within(handle.cancel(Some("test cancel".to_owned())))
        .await
        .expect("cancel");
    assert!(
        wait_for_file(&workspace.path().join("cancelled-c1")).await,
        "{profile}: the child observed notifications/cancelled"
    );
    let diagnostics = export.diagnostics();
    if !legacy {
        // 2026: the bridge wrote notifications/cancelled itself when the
        // response stream closed, then reaped the per-request child.
        assert_eq!(diagnostics.cancel_notifications_sent, 1);
        for _ in 0..200 {
            if export.diagnostics().children_running == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(export.diagnostics().children_running, 0);
    } else {
        // 2025: the client's own notifications/cancelled was forwarded.
        assert_eq!(diagnostics.cancel_notifications_sent, 0);
    }
    assert_eq!(count_lines(&log, "sleep"), 1, "never re-invoked");
    let _ = within(client.cancel()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_profile_stream_close_cancels_the_child_request() {
    cancellation_reaches_the_child("mcp-2026-07-28", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_profile_forwards_notifications_cancelled() {
    cancellation_reaches_the_child("mcp-2025-11-25", true).await;
}

async fn crash_is_interrupted_not_replayed_or_leaked(profile: &str, legacy: bool) {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(profile, workspace.path(), 8);
    let gateway = gateway(export.clone(), workspace.path());
    let (client, _) = connect(&gateway, legacy).await;
    let crashed = within(client.call_tool(CallToolRequestParams::new("crash"))).await;
    let error = crashed.expect_err("a crashed child is not a result");
    assert!(!format!("{error:?}").contains(STDERR_MARKER));
    assert!(!format!("{error}").contains(STDERR_MARKER));
    // Later calls work (a fresh child; for 2025 the client re-initializes
    // after 404) and the crashing call is never replayed.
    let echoed = within(client.call_tool(CallToolRequestParams::new("echo"))).await;
    if echoed.is_err() {
        // The rmcp legacy client may surface the ended session once before
        // recovering; the next call must succeed.
        within(client.call_tool(CallToolRequestParams::new("echo")))
            .await
            .expect("echo after crash");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log = workspace.path().join("invocations.log");
    assert_eq!(
        count_lines(&log, "crash"),
        1,
        "{profile}: crash ran exactly once"
    );
    let diagnostics = export.diagnostics();
    assert!(diagnostics.interrupted >= 1, "{diagnostics:?}");
    assert!(
        diagnostics.child_stderr_bytes >= STDERR_MARKER.len() as u64,
        "stderr drained and counted: {diagnostics:?}"
    );
    if legacy {
        assert!(diagnostics.sessions_ended >= 1);
    }
    let _ = within(client.cancel()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_profile_child_crash_is_a_scoped_interruption() {
    crash_is_interrupted_not_replayed_or_leaked("mcp-2026-07-28", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_profile_child_crash_ends_the_session_without_replay() {
    crash_is_interrupted_not_replayed_or_leaked("mcp-2025-11-25", true).await;
}
