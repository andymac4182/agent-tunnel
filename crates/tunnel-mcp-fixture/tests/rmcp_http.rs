#![cfg(unix)]
//! The official rmcp client against the Streamable HTTP export, which
//! forwards to the official rmcp Streamable HTTP server on a fixed loopback
//! port, through the in-process http-forward/1 bridge.

mod common;

use std::time::Duration;

use common::{connect, count_lines, gateway, http_export, rmcp_http_backend, wait_for_file, within};
use rmcp::model::{CallToolRequestParams, ClientRequest, Request, RequestMetaObject};
use rmcp::service::PeerRequestOptions;

fn arguments(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().cloned().expect("object")
}

async fn http_export_round_trip(profile: &str, legacy: bool) {
    let dir = tempfile::tempdir().expect("dir");
    let (url, shutdown) = rmcp_http_backend(legacy, dir.path()).await;
    let export = http_export(profile, &url, None);
    let gateway = gateway(export.clone(), dir.path());
    let (client, handler) = connect(&gateway, legacy).await;

    let tools = within(client.list_all_tools()).await.expect("tools/list");
    assert!(tools.iter().any(|tool| tool.name == "progress"));

    let mut meta = RequestMetaObject::new();
    meta.insert(
        "io.agent-tunnel.test/marker".to_owned(),
        serde_json::json!({"k": [true, null, 7]}),
    );
    let mut params =
        CallToolRequestParams::new("echo").with_arguments(arguments(serde_json::json!({"z": 26})));
    params.meta = Some(meta);
    let echoed = within(client.call_tool(params)).await.expect("echo");
    let text = echoed
        .content
        .iter()
        .find_map(|block| block.as_text().map(|text| text.text.clone()))
        .expect("text");
    let seen: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(seen["arguments"], serde_json::json!({"z": 26}));
    assert_eq!(
        seen["meta"]["io.agent-tunnel.test/marker"],
        serde_json::json!({"k": [true, null, 7]})
    );

    let handle = within(client.send_cancellable_request(
        ClientRequest::CallToolRequest(Request::new(
            CallToolRequestParams::new("progress")
                .with_arguments(arguments(serde_json::json!({"steps": 3}))),
        )),
        PeerRequestOptions::no_options(),
    ))
    .await
    .expect("progress");
    within(handle.await_response()).await.expect("progress result");
    assert_eq!(
        handler.progress.lock().expect("lock").clone(),
        vec![1.0, 2.0, 3.0]
    );

    // Cancellation: 2026 closes the request's response stream (the export
    // drops the backend connection); 2025 POSTs notifications/cancelled.
    let handle = within(client.send_cancellable_request(
        ClientRequest::CallToolRequest(Request::new(
            CallToolRequestParams::new("sleep")
                .with_arguments(arguments(serde_json::json!({"label": "h1"}))),
        )),
        PeerRequestOptions::no_options(),
    ))
    .await
    .expect("sleep");
    let log = dir.path().join("invocations.log");
    for _ in 0..400 {
        if count_lines(&log, "sleep") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    within(handle.cancel(Some("test".to_owned())))
        .await
        .expect("cancel");
    assert!(
        wait_for_file(&dir.path().join("cancelled-h1")).await,
        "{profile}: the backend observed cancellation"
    );
    assert_eq!(count_lines(&log, "sleep"), 1);
    let diagnostics = export.diagnostics();
    assert_eq!(diagnostics.children_spawned, 0);
    assert!(diagnostics.dispatched >= 4, "{diagnostics:?}");
    let _ = within(client.cancel()).await;
    shutdown.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_profile_http_export_round_trip_and_cancellation() {
    http_export_round_trip("mcp-2026-07-28", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_profile_http_export_round_trip_and_cancellation() {
    http_export_round_trip("mcp-2025-11-25", true).await;
}
