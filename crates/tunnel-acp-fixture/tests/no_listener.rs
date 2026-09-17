#![cfg(unix)]
//! **No inbound device listener exists**, measured on the process's own socket
//! table (M8 chunk 3; M8-02's "no inbound desktop listener").
//!
//! `tunnel_http_bridge::serve` takes no address, so there is no call whose
//! absence could be asserted.  `docs/acp.md` asks for the stronger thing — that
//! nothing is listening — and that is a property of the process, so it is read
//! from the process.
//!
//! This test lives in its own binary and runs one test, so no concurrent test
//! opens a socket underneath it.
//!
//! Two checks, and each is honest about what it covers:
//!
//! 1. **No listening socket exists** while a complete ACP conversation runs.
//!    `lsof` is asked for this process's listening TCP and UDP sockets; a
//!    positive control binds a real loopback listener first and proves the
//!    detector sees one.
//! 2. **The socket count does not rise** across the conversation, which also
//!    catches a Unix-domain listener that check 1 would not classify.  The
//!    baseline is taken **after** a warm-up conversation has completed, because
//!    the Tokio runtime's own signal plumbing — which `tokio::process` requires
//!    to reap a child — creates a socket pair of its own the first time a
//!    process is spawned.  That pair is the runtime's, not an export's, and
//!    counting it as a listener would be wrong in the other direction.
//!
//! What this does **not** show: anything about the tunnel, a relay, or a
//! device's real sockets.  `docs/http-forwarding.md`'s gate-3 device tests own
//! that; this is the gate-2 in-process path.

mod common;

use std::net::TcpListener;
use std::os::unix::fs::FileTypeExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use common::{acp_export, exchange, sse_payloads, within};
use http::{Request, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use tunnel_acp::headers;
use tunnel_acp_export::AcpExport;
use tunnel_http_bridge::{ChannelBody, Profile};

fn open_sockets() -> usize {
    (0..4096)
        .filter(|fd| {
            std::fs::metadata(format!("/dev/fd/{fd}"))
                .is_ok_and(|metadata| metadata.file_type().is_socket())
        })
        .count()
}

/// This process's listening sockets, as the operating system reports them.
fn listening_sockets() -> Vec<String> {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("lsof")
        .args(["-a", "-p", &pid, "-i", "-P", "-n"])
        .output()
        .expect("lsof is available on this host");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains("(LISTEN)"))
        .map(ToOwned::to_owned)
        .collect()
}

fn empty() -> Full<Bytes> {
    Full::new(Bytes::new())
}

fn json_body(value: &Value) -> Full<Bytes> {
    Full::new(Bytes::from(serde_json::to_vec(value).expect("json")))
}

/// Run a whole v1 conversation through the in-process bridge, recording the
/// socket count observed from **inside** the handler's exchange.
async fn conversation(
    export: &AcpExport,
    profile: &Arc<Profile>,
    workspace: &std::path::Path,
    during: &AtomicUsize,
) {
    let request = Request::builder()
        .method("POST")
        .uri("/acp")
        .version(Version::HTTP_2)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {"protocolVersion": 1, "clientCapabilities": {}},
        })))
        .expect("request");
    let response = exchange(export, Arc::clone(profile), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let connection = response
        .headers()
        .get(headers::ACP_CONNECTION_ID)
        .and_then(|value| value.to_str().ok())
        .expect("a connection id")
        .to_owned();
    drop(response);

    let stream = exchange(
        export,
        Arc::clone(profile),
        Request::builder()
            .method("GET")
            .uri("/acp")
            .version(Version::HTTP_2)
            .header("accept", "text/event-stream")
            .header(headers::ACP_CONNECTION_ID, &connection)
            .body(empty())
            .expect("request"),
    )
    .await;
    assert_eq!(stream.status(), StatusCode::OK);

    let request = Request::builder()
        .method("POST")
        .uri("/acp")
        .version(Version::HTTP_2)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header(headers::ACP_CONNECTION_ID, &connection)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "new-1",
            "method": "session/new",
            "params": {"cwd": workspace.to_string_lossy(), "mcpServers": []},
        })))
        .expect("request");
    assert_eq!(
        exchange(export, Arc::clone(profile), request)
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    let mut connection_body = std::pin::pin!(stream.into_body());
    let session = within(read_session_id(&mut connection_body)).await;
    let session_stream = exchange(
        export,
        Arc::clone(profile),
        Request::builder()
            .method("GET")
            .uri("/acp")
            .version(Version::HTTP_2)
            .header("accept", "text/event-stream")
            .header(headers::ACP_CONNECTION_ID, &connection)
            .header(headers::ACP_SESSION_ID, &session)
            .body(empty())
            .expect("request"),
    )
    .await;
    assert_eq!(session_stream.status(), StatusCode::OK);

    let request = Request::builder()
        .method("POST")
        .uri("/acp")
        .version(Version::HTTP_2)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header(headers::ACP_CONNECTION_ID, &connection)
        .header(headers::ACP_SESSION_ID, &session)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "prompt-1",
            "method": "session/prompt",
            "params": {"sessionId": session, "prompt": [{"type": "text", "text": "ok"}]},
        })))
        .expect("request");
    assert_eq!(
        exchange(export, Arc::clone(profile), request)
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    // The child is running and the streams are open: this is the moment a
    // listener would exist if one existed at all.
    during.store(open_sockets(), Ordering::SeqCst);
    assert!(
        listening_sockets().is_empty(),
        "a socket was listening while the ACP export served a turn: {:?}",
        listening_sockets()
    );

    // The stream stays established across the DELETE below: the body is
    // borrowed, not consumed.
    let mut session_body = std::pin::pin!(session_stream.into_body());
    let stop = within(read_stop_reason(&mut session_body)).await;
    assert_eq!(stop, "end_turn", "the turn completed, read off the wire");

    let request = Request::builder()
        .method("DELETE")
        .uri("/acp")
        .version(Version::HTTP_2)
        .header(headers::ACP_CONNECTION_ID, &connection)
        .body(empty())
        .expect("request");
    assert_eq!(
        exchange(export, Arc::clone(profile), request)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_acp_export_serves_a_whole_conversation_with_nothing_listening() {
    // The detector is not vacuous: a real listener is seen.
    assert!(listening_sockets().is_empty(), "the process starts clean");
    let control = TcpListener::bind("127.0.0.1:0").expect("a control listener");
    assert_eq!(
        listening_sockets().len(),
        1,
        "the detector sees a listening socket"
    );
    drop(control);
    assert!(listening_sockets().is_empty());

    let workspace = tempfile::tempdir().expect("workspace");
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let during = AtomicUsize::new(usize::MAX);

    // Warm-up: the first spawned child makes the Tokio runtime build its
    // signal plumbing, which is a socket pair of the runtime's own.  Counting
    // that against the export would be measuring Tokio.
    conversation(&export, &profile, workspace.path(), &during).await;
    let baseline = open_sockets();

    conversation(&export, &profile, workspace.path(), &during).await;
    assert_eq!(
        during.load(Ordering::SeqCst),
        baseline,
        "no socket was opened while the export served an ACP turn"
    );
    assert_eq!(open_sockets(), baseline, "and none was left behind");
    assert!(listening_sockets().is_empty(), "and nothing is listening");

    export.shutdown();
}

/// As [`read_stop_reason`], the body is borrowed so the connection stream
/// stays established for the rest of the conversation.
async fn read_session_id(body: &mut std::pin::Pin<&mut ChannelBody>) -> String {
    read_until(body, |value| {
        value
            .pointer("/result/sessionId")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
    .await
}

/// Read a stream's stop reason **without letting the body go**.
///
/// The body is borrowed rather than consumed, so the caller keeps the stream
/// established. Under `docs/acp.md`'s subscriber-loss policy — implemented in
/// M8 chunk 4 — dropping an established required stream terminates its whole
/// ACP transport, so a helper that consumed the response here would end the
/// connection and the DELETE that follows would be answered 404 rather than
/// 202. That is the correct behaviour and this is the helper adapting to it.
async fn read_stop_reason(body: &mut std::pin::Pin<&mut ChannelBody>) -> String {
    read_until(body, |value| {
        value
            .pointer("/result/stopReason")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
    .await
}

async fn read_until(
    body: &mut std::pin::Pin<&mut ChannelBody>,
    pick: impl Fn(&Value) -> Option<String>,
) -> String {
    let mut buffer = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        if let Ok(data) = frame.into_data() {
            buffer.extend_from_slice(&data);
        }
        for payload in sse_payloads(&buffer) {
            if let Ok(value) = serde_json::from_slice::<Value>(&payload)
                && let Some(found) = pick(&value)
            {
                return found;
            }
        }
    }
    panic!("the stream ended before the message arrived");
}
