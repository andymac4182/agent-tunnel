#![cfg(unix)]
//! The ACP HTTP/SSE bridge, driven by raw HTTP through the gate-2
//! `forward`/`serve` path (M8 chunk 3).
//!
//! These tests hold the rules the pinned client never exercises because it is
//! well behaved: a batch, a session header that disagrees with the body, a
//! second subscriber, a prompt before its subscriber is ready, and the
//! subscription deadlines.  The conversation the **official client** drives is
//! in `pinned_client.rs`; this file is the profile's refusals.
//!
//! **No assertion about a prompt, a session or a permission terminates on an
//! HTTP status.**  Where a status appears it is the bridge's own refusal —
//! nothing was dispatched to an agent, so there is no later message to anchor
//! to — and each of those also asserts that nothing reached the agent.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{acp_export, acp_export_with, body_text, exchange, sse_payloads, within};
use http::{Request, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use tunnel_acp::headers;
use tunnel_acp_export::AcpExport;
use tunnel_http_bridge::{ChannelBody, Profile};

fn empty() -> Full<Bytes> {
    Full::new(Bytes::new())
}

fn post() -> http::request::Builder {
    Request::builder()
        .method("POST")
        .uri("/acp")
        .version(Version::HTTP_2)
        .header("content-type", "application/json")
        .header("accept", "application/json")
}

fn get() -> http::request::Builder {
    Request::builder()
        .method("GET")
        .uri("/acp")
        .version(Version::HTTP_2)
        .header("accept", "text/event-stream")
}

/// Drive one exchange against the export, **bounded**.
///
/// The bound is not decoration.  `exchange` awaits a response that a broken
/// export may never produce, and an unbounded wait here turns a guard-deletion
/// case from evidence into a hang: a mutation that stops `initialize` ever
/// resolving made every test that opens a connection wait forever, so the
/// case's `cargo test` hit the harness's 600 s ceiling and was reported
/// `NOT EVIDENCE (timed out)` rather than `RED` (task row M8-C13).  A bounded
/// wait makes the same mutation fail by name, which is what the case is for.
async fn send(
    export: &AcpExport,
    profile: &Arc<Profile>,
    request: Request<Full<Bytes>>,
) -> http::Response<ChannelBody> {
    within(exchange(export, Arc::clone(profile), request)).await
}

fn json_body(value: &Value) -> Full<Bytes> {
    Full::new(Bytes::from(serde_json::to_vec(value).expect("json")))
}

/// Open a connection and return its identifier.
async fn initialize(export: &AcpExport, profile: &Arc<Profile>) -> String {
    let request = post()
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {"protocolVersion": 1, "clientCapabilities": {}},
        })))
        .expect("request");
    let response = send(export, profile, request).await;
    assert_eq!(response.status(), StatusCode::OK, "initialize answers 200");
    let id = response
        .headers()
        .get(headers::ACP_CONNECTION_ID)
        .and_then(|value| value.to_str().ok())
        .expect("initialize returns Acp-Connection-Id")
        .to_owned();
    let body: Value = serde_json::from_str(&body_text(response).await).expect("json body");
    assert_eq!(body["id"], json!("init-1"));
    assert_eq!(body["result"]["protocolVersion"], json!(1));
    id
}

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("workspace")
}

// --------------------------------------------------------------- the batch

/// M8-C02.  The RFD answers a batch with **501**; the pinned SDK preserves
/// batches instead.  The pinned client never originates one, so this is the
/// reachable half of the disagreement: a host that POSTs an array.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_posted_batch_is_refused_with_501_and_never_reaches_an_agent() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let before = export.diagnostics();

    let batch = Bytes::from_static(
        br#"[{"jsonrpc":"2.0","id":1,"method":"session/new","params":{}},{"jsonrpc":"2.0","id":2,"method":"session/new","params":{}}]"#,
    );
    let request = Request::builder()
        .method("POST")
        .uri("/acp")
        .version(Version::HTTP_2)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header(headers::ACP_CONNECTION_ID, &connection)
        .body(Full::new(batch))
        .expect("request");
    let response = send(&export, &profile, request).await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_IMPLEMENTED,
        "a batch is refused with the RFD's own 501"
    );
    let body: Value = serde_json::from_str(&body_text(response).await).expect("json body");
    assert_eq!(
        body["error"]["code"],
        json!(tunnel_acp::message::codes::BATCH_NOT_SUPPORTED),
        "refused for being a batch, by its own code"
    );
    let after = export.diagnostics();
    assert_eq!(after.batches_refused, before.batches_refused + 1);
    // The 501 is not the claim: nothing was dispatched.  No session exists.
    assert_eq!(after.sessions_opened, before.sessions_opened);
    export.shutdown();
}

/// The device half of M8-C02: **the SSE stream never carries a batch**, proved
/// with a child that deliberately emits one.
///
/// That is the row's written acceptance, and it is not the same thing as
/// answering 501 mid-stream — the 501 is the RFD's answer to a *POST*, which
/// `a_posted_batch_is_refused_with_501_and_never_reaches_an_agent` holds. An
/// SSE response's status is written when the stream opens, so a refusal
/// discovered afterwards can only break the stream; what has to be shown is
/// that it *is* refused, by its own rule, and that the stream ends rather than
/// silently continuing.
///
/// The fixture's `batch` directive makes the agent write a JSON-RPC array on
/// its stdout. The supervisor refuses it by `AcpRule::BatchNotSupported` and
/// kills the child — chunk 2's rule, re-observed here through the HTTP path —
/// and `docs/acp.md`'s "a child crash closes the transport and invalidates
/// live sessions" is what carries that to the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sse_stream_never_carries_a_batch_and_the_refusal_ends_the_transport() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;

    let stream = send(&export, &profile, get_connection(&connection)).await;
    assert_eq!(stream.status(), StatusCode::OK);
    let session = open_session(&export, &profile, &connection, workspace.path(), stream).await;

    let session_stream = send(&export, &profile, get_session(&connection, &session.id)).await;
    assert_eq!(
        session_stream.status(),
        StatusCode::OK,
        "the session stream opened with 200 before any batch was written"
    );
    let request = post()
        .header(headers::ACP_CONNECTION_ID, &connection)
        .header(headers::ACP_SESSION_ID, &session.id)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "prompt-1",
            "method": "session/prompt",
            "params": {"sessionId": session.id, "prompt": [{"type": "text", "text": "batch"}]},
        })))
        .expect("request");
    let accepted = send(&export, &profile, request).await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    // The stream ends without ever delivering the batch, and without a status
    // to carry the refusal: the head was already on the wire.
    // ------------------------------------------------- what actually happened
    //
    // Three separate observations, because "the batch did not arrive" alone
    // would also be true of a stream that simply went quiet.
    let (payloads, ending) = within(collect_stream(session_stream)).await;
    assert!(
        !payloads.iter().any(|payload| payload.starts_with(b"[")),
        "the SSE stream never carries a batch: {payloads:?}"
    );
    // 1. The **rule**: the supervisor refused the line for being a batch, by
    //    its own `AcpRule`, and killed the child for it. The counter is the
    //    child's own, folded into the export when the connection ended, so it
    //    outlives the connection that carried it.
    let mut diagnostics = export.diagnostics();
    for _ in 0..400 {
        if diagnostics.connections_ended_by_child == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        diagnostics = export.diagnostics();
    }
    assert_eq!(
        diagnostics.child_batch_output, 1,
        "refused for being a batch, by its own rule: {diagnostics:?}"
    );
    assert_eq!(diagnostics.child_invalid_output, 1, "{diagnostics:?}");
    // 2. The **transport**: `docs/acp.md` says a child crash closes the
    //    transport and invalidates live sessions, so the connection is gone
    //    rather than left in the map with a dead child behind it.
    assert_eq!(diagnostics.connections_ended_by_child, 1);
    assert_eq!(diagnostics.live_connections, 0);
    let late = send(&export, &profile, get_connection(&connection)).await;
    assert_eq!(late.status(), StatusCode::NOT_FOUND);
    // 3. The **stream's ending**: errored, not quiet and not a clean end. A
    //    broken ACP stream must not look like an orderly one, and a test that
    //    accepted a read timeout here would pass whether or not anything ended.
    assert_eq!(
        ending,
        Ending::Errored,
        "the stream broke; it did not go quiet or end cleanly"
    );
    export.shutdown();
}

// -------------------------------------------------------- identity headers

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_header_that_disagrees_with_the_body_is_refused_with_400() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let stream = send(&export, &profile, get_connection(&connection)).await;
    let session = open_session(&export, &profile, &connection, workspace.path(), stream).await;
    let before = export.diagnostics();

    let request = post()
        .header(headers::ACP_CONNECTION_ID, &connection)
        .header(headers::ACP_SESSION_ID, "session-not-this-one")
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "prompt-1",
            "method": "session/prompt",
            "params": {"sessionId": session.id, "prompt": [{"type": "text", "text": "ok"}]},
        })))
        .expect("request");
    let response = send(&export, &profile, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_str(&body_text(response).await).expect("json body");
    assert_eq!(
        body["error"]["code"],
        json!(tunnel_acp::message::codes::HEADER_MISMATCH)
    );
    // Refused before dispatch: no prompt was ever started.
    assert_eq!(
        export.diagnostics().prompts_accepted,
        before.prompts_accepted
    );
    export.shutdown();
}

/// `docs/acp.md`: `cwd` "must match the service's allowed workspace; the host
/// cannot select arbitrary paths", and consumer-supplied `mcpServers` are
/// rejected while nonempty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_cannot_choose_a_workspace_or_attach_mcp_servers() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let _stream = send(&export, &profile, get_connection(&connection)).await;

    for params in [
        json!({"cwd": "/etc", "mcpServers": []}),
        json!({"cwd": workspace.path().to_string_lossy(), "mcpServers": [{"name": "x", "command": "/bin/sh"}]}),
    ] {
        let request = post()
            .header(headers::ACP_CONNECTION_ID, &connection)
            .body(json_body(&json!({
                "jsonrpc": "2.0",
                "id": "new-1",
                "method": "session/new",
                "params": params,
            })))
            .expect("request");
        let response = send(&export, &profile, request).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "refused before anything reached the agent: {params}"
        );
    }
    // And no session was opened by either attempt.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(export.diagnostics().sessions_opened, 0);
    export.shutdown();
}

// ------------------------------------------------------------ subscribers

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_connection_subscriber_is_refused_409_and_the_first_keeps_the_stream() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;

    let first = send(&export, &profile, get_connection(&connection)).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = send(&export, &profile, get_connection(&connection)).await;
    assert_eq!(
        second.status(),
        StatusCode::CONFLICT,
        "a second subscriber is refused, never silently fanned out"
    );
    assert_eq!(export.diagnostics().subscribers_refused, 1);

    // The refusal did not take the first subscriber's stream away: it still
    // receives the session/new result.
    let session = open_session(&export, &profile, &connection, workspace.path(), first).await;
    assert!(!session.id.is_empty());
    export.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_session_subscriber_is_refused_409() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let stream = send(&export, &profile, get_connection(&connection)).await;
    let session = open_session(&export, &profile, &connection, workspace.path(), stream).await;

    let first = send(&export, &profile, get_session(&connection, &session.id)).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = send(&export, &profile, get_session(&connection, &session.id)).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    assert_eq!(export.diagnostics().subscribers_refused, 1);
    export.shutdown();
}

/// **A lost *established* required SSE stream terminates the whole ACP
/// transport**, and each of `docs/acp.md`'s five consequences is asserted
/// separately (M8 chunk 4).
///
/// `docs/acp.md`: "Once an established required SSE stream breaks, terminate
/// that ACP transport connection in v0: refuse new prompts, resolve pending
/// permissions as cancelled, request cancellation of active turns, close
/// streams, and clean up the child. A reconnect must initialize anew."
///
/// **This replaces a chunk-3 test that asserted the opposite**, and the
/// replacement is a behaviour change rather than a correction of a mistake.
/// `dropping_one_session_stream_leaves_the_others_delivering` held that one
/// lost subscriber closed one stream and left the connection running. That was
/// a deliberate stopgap: the behaviour it replaced — the first failed send
/// silently ending the router, so every other stream went quiet and every
/// prompt hung until DELETE — was worse than either policy, and chunk 3 said in
/// terms that the narrow fix "is not the documented policy". It now is.
///
/// A second session is opened so the test can show the *other* stream closing
/// too, which is the half that distinguishes "terminate the transport" from
/// "close the stream that broke".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_established_session_stream_terminates_the_whole_transport() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let stream = send(&export, &profile, get_connection(&connection)).await;

    let first = open_session(&export, &profile, &connection, workspace.path(), stream).await;
    let first_stream = send(&export, &profile, get_session(&connection, &first.id)).await;
    assert_eq!(first_stream.status(), StatusCode::OK);
    let first_held = HeldStream::hold(first_stream);

    let second_id = within(second_session(
        &export,
        &profile,
        &connection,
        workspace.path(),
    ))
    .await;
    let second_stream = send(&export, &profile, get_session(&connection, &second_id)).await;
    assert_eq!(second_stream.status(), StatusCode::OK);

    // The child is read from the process table **before** the break, so the
    // cleanup consequence is checked against a process that really existed.
    let pids = export.child_pids();
    assert_eq!(pids.len(), 1, "one child per connection");
    let child = pids[0];
    assert!(common::is_alive(child), "the child is running");

    // Ask for a permission and wait for it to be outstanding, so there is a
    // pending callback for the break to resolve.
    let request = post()
        .header(headers::ACP_CONNECTION_ID, &connection)
        .header(headers::ACP_SESSION_ID, &first.id)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "prompt-permission",
            "method": "session/prompt",
            "params": {"sessionId": first.id, "prompt": [{"type": "text", "text": "permission"}]},
        })))
        .expect("request");
    assert_eq!(
        send(&export, &profile, request).await.status(),
        StatusCode::ACCEPTED
    );
    // The permission request is observed **on the wire**, not inferred from the
    // 202 above: `docs/acp.md`'s 202 means accepted by the bridge and no more.
    let method = within(first_held.wait_for_pointer("/method")).await;
    assert_eq!(method, "session/request_permission");

    // The consumer goes away on the first session's established stream.
    first_held.break_now();

    // The whole transport ends.
    let mut diagnostics = export.diagnostics();
    for _ in 0..400 {
        if diagnostics.connections_ended_by_subscriber_loss == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        diagnostics = export.diagnostics();
    }

    // (i) the transport terminated, by the subscriber-loss rule and not by
    // some other ending.
    assert_eq!(
        diagnostics.connections_ended_by_subscriber_loss, 1,
        "{diagnostics:?}"
    );
    assert_eq!(
        diagnostics.connections_ended_by_child, 0,
        "the child did not end this; the lost subscriber did: {diagnostics:?}"
    );
    assert_eq!(diagnostics.live_connections, 0, "{diagnostics:?}");

    // (ii) pending permissions resolved cancelled, never approved.
    assert_eq!(
        diagnostics.permissions_cancelled_by_loss, 1,
        "the outstanding permission was cancelled: {diagnostics:?}"
    );
    assert_eq!(
        diagnostics.permissions_answered, 0,
        "nothing was approved: {diagnostics:?}"
    );

    // (iii) new prompts are refused.
    let request = post()
        .header(headers::ACP_CONNECTION_ID, &connection)
        .header(headers::ACP_SESSION_ID, &second_id)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "prompt-after",
            "method": "session/prompt",
            "params": {"sessionId": second_id, "prompt": [{"type": "text", "text": "ok"}]},
        })))
        .expect("request");
    assert_eq!(
        send(&export, &profile, request).await.status(),
        StatusCode::NOT_FOUND,
        "a prompt on a terminated transport is refused"
    );

    // (iv) the other stream closed, and it **errored** rather than ending
    // cleanly: a broken ACP stream must not look like an orderly one.
    let (_payloads, ending) = within(collect_stream(second_stream)).await;
    assert_eq!(
        ending,
        Ending::Errored,
        "the surviving session's stream errored, rather than ending cleanly"
    );

    // (v) a reconnect must initialize anew: the old connection is gone.
    assert_eq!(
        send(&export, &profile, get_connection(&connection))
            .await
            .status(),
        StatusCode::NOT_FOUND,
        "the old connection cannot be reattached to"
    );
    let fresh = initialize(&export, &profile).await;
    assert_ne!(fresh, connection, "a reconnect is a new connection");

    // (vi) the child was cleaned up, read from the process table rather than
    // from a counter.
    for _ in 0..200 {
        if !common::is_alive(child) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !common::is_alive(child),
        "the terminated connection's child is gone from the process table"
    );
    export.shutdown();
}

/// The **connection** stream is a required stream too, and breaking it has the
/// same consequence as breaking a session stream (M8 chunk 4).
///
/// `docs/acp.md` names "an established required SSE stream" without
/// distinguishing them, and this profile has two kinds. Breaking each one
/// independently is what shows the rule is about the stream being required
/// rather than about which handler happened to notice. Here the session stream
/// stays perfectly healthy and the connection stream is the one that goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_established_connection_stream_terminates_the_whole_transport() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let stream = send(&export, &profile, get_connection(&connection)).await;
    let session = open_session(&export, &profile, &connection, workspace.path(), stream).await;

    let session_stream = send(&export, &profile, get_session(&connection, &session.id)).await;
    assert_eq!(session_stream.status(), StatusCode::OK);

    let pids = export.child_pids();
    assert_eq!(pids.len(), 1);
    let child = pids[0];
    assert!(common::is_alive(child));

    // The connection GET goes away; the session GET is untouched.
    session.connection_stream.break_now();

    let mut diagnostics = export.diagnostics();
    for _ in 0..400 {
        if diagnostics.connections_ended_by_subscriber_loss == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        diagnostics = export.diagnostics();
    }
    assert_eq!(
        diagnostics.connections_ended_by_subscriber_loss, 1,
        "breaking the connection stream ends the transport: {diagnostics:?}"
    );
    assert_eq!(diagnostics.live_connections, 0, "{diagnostics:?}");

    // The healthy session stream is closed with it, and errors rather than
    // ending cleanly.
    let (_payloads, ending) = within(collect_stream(session_stream)).await;
    assert_eq!(ending, Ending::Errored);

    // A reconnect must initialize anew.
    assert_eq!(
        send(&export, &profile, get_connection(&connection))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    for _ in 0..200 {
        if !common::is_alive(child) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(!common::is_alive(child), "the child is gone");
    export.shutdown();
}

/// **The output-credit stall is bounded, measured, and the event is never
/// dropped and continued past** (M8 chunk 4).
///
/// `docs/acp.md`'s limits table: "Output credit stall | 30 seconds, then
/// cancel/close; never drop an event and continue." The second clause is the
/// one with teeth: this profile has no `Last-Event-ID` replay, so a bridge that
/// skipped a message it could not deliver would leave a hole the consumer could
/// never learn about. So a stall ends the connection instead.
///
/// The bound is **shortened** here so the stall can be reached cheaply, exactly
/// as chunk 2 and chunk 3 shortened the permission and subscription deadlines,
/// and the elapsed time is read from the export's own measurement rather than
/// from the constant it was configured with. The documented 30 seconds is
/// asserted separately, as a default, by
/// `the_documented_output_stall_default_is_thirty_seconds`.
///
/// The subscriber here **takes its queue and never reads the body**, which is a
/// stalled consumer rather than a lost one: the distinction matters, because a
/// lost consumer is the subscriber-loss rule and would end the connection for a
/// different reason and with a different counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn output_credit_stalls_are_bounded_and_the_event_is_never_skipped() {
    let workspace = workspace();
    let export = acp_export_with(workspace.path(), "[deadlines]\noutput_stall_ms = 400\n");
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let stream = send(&export, &profile, get_connection(&connection)).await;
    let session = open_session(&export, &profile, &connection, workspace.path(), stream).await;

    // Subscribe **directly against the export**, then deliberately never poll
    // the body.
    //
    // Directly, because the bound under test is the export's own. The gate-2
    // `forward`/`serve` carrier in `exchange` has credit-based flow control of
    // its own, and it drains the export's body into that credit whether or not
    // the consumer is reading — so a stalled consumer behind it stalls the
    // *carrier*, some tens of kilobytes later, and the export never sees
    // backpressure at all. Going through it here would measure the wrong
    // bound and would have passed while proving nothing. The whole chain is
    // exercised over the real three-relay path by the `verify-m8-acp-real-path`
    // gate; this test is about this queue.
    let stalled = export
        .handle(
            get_session(&connection, &session.id)
                .map(|_| tunnel_http_bridge::ChannelBody::full(Bytes::new())),
        )
        .await
        .expect("the session GET is answered");
    assert_eq!(stalled.status(), StatusCode::OK);

    let request = post()
        .header(headers::ACP_CONNECTION_ID, &connection)
        .header(headers::ACP_SESSION_ID, &session.id)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "prompt-flood",
            "method": "session/prompt",
            "params": {"sessionId": session.id, "prompt": [{"type": "text", "text": "updates:512"}]},
        })))
        .expect("request");
    assert_eq!(
        send(&export, &profile, request).await.status(),
        StatusCode::ACCEPTED
    );

    let mut diagnostics = export.diagnostics();
    for _ in 0..400 {
        if diagnostics.output_stalls == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        diagnostics = export.diagnostics();
    }
    assert_eq!(
        diagnostics.output_stalls, 1,
        "the stall bound was reached: {diagnostics:?}"
    );

    // **Observed elapsing**, not a constant read back: the measurement the
    // dispatcher recorded must exceed the bound it was running against.
    assert_eq!(diagnostics.last_stall_bound_us, 400_000, "{diagnostics:?}");
    assert!(
        diagnostics.last_stall_elapsed_us > diagnostics.last_stall_bound_us,
        "the stall was measured and exceeded its bound: {diagnostics:?}"
    );

    // The connection ended rather than the message being skipped.
    assert_eq!(diagnostics.live_connections, 0, "{diagnostics:?}");
    assert_eq!(
        diagnostics.messages_dropped_on_closed_stream, 0,
        "nothing was dropped and continued past: {diagnostics:?}"
    );
    export.shutdown();
}

/// The number `docs/acp.md` publishes, asserted as the shipped default.
///
/// A shortened bound proves the mechanism; it does not prove the value the
/// document promises. This is the other half, and it is a configuration
/// assertion rather than an observation — which is why it is a separate test
/// with a name that says so, and not a line inside the measured one.
#[test]
fn the_documented_output_stall_default_is_thirty_seconds() {
    assert_eq!(
        tunnel_acp_export::DEFAULT_OUTPUT_STALL_MS,
        30_000,
        "docs/acp.md's limits table says 30 seconds"
    );
    assert_eq!(
        tunnel_acp_export::OUTPUT_STALL_DEADLINE,
        Duration::from_secs(30)
    );
}

// ------------------------------------------------------------- deadlines

/// The subscription deadline is **observed and elapsed**, at a shortened
/// bound, exactly as chunk 2 measured the permission deadline.
///
/// The deadline the profile ships is 10 seconds; the run below at that real
/// value is `the_documented_ten_second_deadline_is_the_one_that_elapses`.
/// This one shortens it so the mechanism can be measured cheaply, and reads
/// the elapsed time the watchdog recorded rather than the constant it was
/// configured with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_whose_subscriber_never_arrives_is_ended_after_its_measured_deadline() {
    let workspace = workspace();
    let export = acp_export_with(
        workspace.path(),
        "[deadlines]\nsubscribe_ms = 200\npermission_ms = 60000\n",
    );
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let started = Instant::now();
    let connection = initialize(&export, &profile).await;
    let pid = export.child_pids().first().copied().expect("a child");

    let mut diagnostics = export.diagnostics();
    for _ in 0..600 {
        if diagnostics.connection_subscribe_expired == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        diagnostics = export.diagnostics();
    }
    assert_eq!(
        diagnostics.connection_subscribe_expired, 1,
        "the connection GET never arrived and the window closed"
    );
    assert_eq!(diagnostics.last_expiry_bound_us, 200_000);
    assert!(
        diagnostics.last_expiry_elapsed_us > diagnostics.last_expiry_bound_us,
        "the bound must be exceeded, not merely reached: {diagnostics:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "and the test's own wall clock agrees"
    );
    assert_eq!(diagnostics.live_connections, 0);

    // A connection that expired is gone: a later GET finds nothing.
    let late = send(&export, &profile, get_connection(&connection)).await;
    assert_eq!(late.status(), StatusCode::NOT_FOUND);
    // And the child it owned is gone with it, read from the process table.
    for _ in 0..200 {
        if !common::is_alive(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !common::is_alive(pid),
        "the expired connection's child is gone"
    );
    export.shutdown();
}

/// The **documented** 10-second bound, run at its real value.
///
/// This test takes eleven seconds on purpose.  A shortened bound proves the
/// mechanism; it does not prove the number `docs/acp.md` publishes, and a
/// constant asserted against itself proves nothing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_documented_ten_second_deadline_is_the_one_that_elapses() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let started = Instant::now();
    let _connection = initialize(&export, &profile).await;

    let mut diagnostics = export.diagnostics();
    for _ in 0..1200 {
        if diagnostics.connection_subscribe_expired == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        diagnostics = export.diagnostics();
    }
    let elapsed = started.elapsed();
    assert_eq!(diagnostics.connection_subscribe_expired, 1);
    assert_eq!(
        diagnostics.last_expiry_bound_us, 10_000_000,
        "the default bound is the documented ten seconds"
    );
    assert!(
        diagnostics.last_expiry_elapsed_us > 10_000_000,
        "{diagnostics:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(10),
        "the wall clock waited the whole ten seconds: {elapsed:?}"
    );
    export.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_whose_subscriber_never_arrives_closes_its_window() {
    let workspace = workspace();
    // **1500 ms, not 300.** The bound applies to the *connection* GET as well
    // as the session GET, and 300 ms is the wall time between `initialize`
    // returning and this test getting round to sending the connection GET on a
    // loaded machine. When that window closed first the connection ended, the
    // session's window never expired, and this test failed for a reason that
    // had nothing to do with what it measures. It surfaced as a test reddening
    // at random across a whole guard-deletion suite, which is how it was
    // found. The deadline is still observed and still elapses; only the
    // fragility is gone.
    //
    // **1500 ms was not enough either.** Running all five ACP guard suites back
    // to back keeps this machine compiling and running the workspace for half
    // an hour, and the connection GET still missed a 1500 ms window under it.
    // 5000 ms is chosen against that load rather than against an idle machine.
    // The underlying coupling — one configuration value bounding two different
    // windows — is what M8-C12 records as not fixed.
    let export = acp_export_with(workspace.path(), "[deadlines]\nsubscribe_ms = 5000\n");
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let stream = send(&export, &profile, get_connection(&connection)).await;
    let session = open_session(&export, &profile, &connection, workspace.path(), stream).await;

    let mut diagnostics = export.diagnostics();
    for _ in 0..1500 {
        if diagnostics.session_subscribe_expired == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        diagnostics = export.diagnostics();
    }
    assert_eq!(
        diagnostics.connection_subscribe_expired, 0,
        "the connection's own window must not be what closed: {diagnostics:?}"
    );
    assert_eq!(diagnostics.session_subscribe_expired, 1);
    assert!(
        diagnostics.last_expiry_elapsed_us > diagnostics.last_expiry_bound_us,
        "{diagnostics:?}"
    );
    // The window is closed, not reopened: a late session GET is refused by the
    // same mechanism that refuses a second subscriber.
    let late = send(&export, &profile, get_session(&connection, &session.id)).await;
    assert_eq!(late.status(), StatusCode::CONFLICT);
    export.shutdown();
}

/// `docs/acp.md`: "reject session prompts until that subscriber is ready".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prompt_before_its_session_subscriber_is_refused_and_nothing_is_dispatched() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let stream = send(&export, &profile, get_connection(&connection)).await;
    let session = open_session(&export, &profile, &connection, workspace.path(), stream).await;

    let request = post()
        .header(headers::ACP_CONNECTION_ID, &connection)
        .header(headers::ACP_SESSION_ID, &session.id)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "prompt-1",
            "method": "session/prompt",
            "params": {"sessionId": session.id, "prompt": [{"type": "text", "text": "ok"}]},
        })))
        .expect("request");
    let response = send(&export, &profile, request).await;
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "the session has no subscriber yet"
    );
    let diagnostics = export.diagnostics();
    assert_eq!(diagnostics.prompts_refused_not_ready, 1);
    assert_eq!(
        diagnostics.prompts_accepted, 0,
        "nothing was dispatched to the agent"
    );

    // And the same prompt succeeds once the subscriber is there — so the
    // refusal was the readiness rule and not something else.
    let session_stream = send(&export, &profile, get_session(&connection, &session.id)).await;
    assert_eq!(session_stream.status(), StatusCode::OK);
    let request = post()
        .header(headers::ACP_CONNECTION_ID, &connection)
        .header(headers::ACP_SESSION_ID, &session.id)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "prompt-1",
            "method": "session/prompt",
            "params": {"sessionId": session.id, "prompt": [{"type": "text", "text": "ok"}]},
        })))
        .expect("request");
    let accepted = send(&export, &profile, request).await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    // 202 is not the claim.  The turn is over when the wire says so.
    let (payloads, _ending) = within(collect_stream(session_stream)).await;
    let stop = payloads
        .iter()
        .filter_map(|payload| serde_json::from_slice::<Value>(payload).ok())
        .find_map(|value| {
            value
                .pointer("/result/stopReason")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    assert_eq!(stop.as_deref(), Some("end_turn"));
    export.shutdown();
}

// ------------------------------------------------------- byte-exact events

/// The SSE encoding, byte for byte, taken off the transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_sse_event_is_exactly_data_space_message_newline_newline() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let stream = send(&export, &profile, get_connection(&connection)).await;

    let request = post()
        .header(headers::ACP_CONNECTION_ID, &connection)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "new-1",
            "method": "session/new",
            "params": {"cwd": workspace.path().to_string_lossy(), "mcpServers": []},
        })))
        .expect("request");
    assert_eq!(
        send(&export, &profile, request).await.status(),
        StatusCode::ACCEPTED
    );

    let (raw, _ending) = within(collect_raw(stream)).await;
    let payloads = sse_payloads(&raw);
    assert!(
        !payloads.is_empty(),
        "the connection stream carried the result"
    );
    // Byte for byte: the concatenation of the framed payloads is the stream.
    let mut rebuilt = Vec::new();
    for payload in &payloads {
        rebuilt.extend_from_slice(b"data: ");
        rebuilt.extend_from_slice(payload);
        rebuilt.extend_from_slice(b"\n\n");
    }
    assert_eq!(
        rebuilt, raw,
        "the stream is exactly `data: <compact>\\n\\n` events and nothing else"
    );
    for payload in &payloads {
        assert!(
            !payload.contains(&b'\n'),
            "a compact ACP message has no line break in it"
        );
        let value: Value = serde_json::from_slice(payload).expect("each event is one JSON message");
        assert_eq!(value["jsonrpc"], json!("2.0"));
    }
    export.shutdown();
}

/// M8-C05.  Session-scoped responses carry no `Acp-Session-Id`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_scoped_stream_answers_with_no_session_header() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let stream = send(&export, &profile, get_connection(&connection)).await;
    let session = open_session(&export, &profile, &connection, workspace.path(), stream).await;

    let session_stream = send(&export, &profile, get_session(&connection, &session.id)).await;
    assert_eq!(session_stream.status(), StatusCode::OK);
    assert!(
        session_stream
            .headers()
            .get(headers::ACP_SESSION_ID)
            .is_none(),
        "the pinned SDK's server sets this header here; this profile follows the RFD and does not"
    );
    assert_eq!(
        session_stream
            .headers()
            .get(headers::ACP_CONNECTION_ID)
            .and_then(|value| value.to_str().ok()),
        Some(connection.as_str()),
        "the connection header is the one identity a response carries"
    );
    assert_eq!(
        session_stream
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    export.shutdown();
}

// ------------------------------------------------------------- deletion

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_answers_202_and_the_child_is_gone_from_the_process_table() {
    let workspace = workspace();
    let export = acp_export(workspace.path());
    let profile = Arc::new(export.profile_policies().expect("profile"));
    let connection = initialize(&export, &profile).await;
    let pid = export.child_pids().first().copied().expect("a child");
    assert!(common::is_alive(pid));

    let request = Request::builder()
        .method("DELETE")
        .uri("/acp")
        .version(Version::HTTP_2)
        .header(headers::ACP_CONNECTION_ID, &connection)
        .body(empty())
        .expect("request");
    let response = send(&export, &profile, request).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // 202 is "accepted by the bridge".  Whether the child is gone is read from
    // the process table, not from the status.
    for _ in 0..200 {
        if !common::is_alive(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !common::is_alive(pid),
        "the child's life ended with its connection"
    );
    assert_eq!(export.diagnostics().live_connections, 0);
    // A second DELETE finds nothing rather than tearing something down twice.
    let request = Request::builder()
        .method("DELETE")
        .uri("/acp")
        .version(Version::HTTP_2)
        .header(headers::ACP_CONNECTION_ID, &connection)
        .body(empty())
        .expect("request");
    assert_eq!(
        send(&export, &profile, request).await.status(),
        StatusCode::NOT_FOUND
    );
    export.shutdown();
}

// ------------------------------------------------------------- helpers

struct Session {
    id: String,
    /// The connection GET, held open.  A `Session` that dropped it would
    /// terminate its own transport: see [`HeldStream`].
    connection_stream: HeldStream,
}

fn get_connection(connection: &str) -> Request<Full<Bytes>> {
    get()
        .header(headers::ACP_CONNECTION_ID, connection)
        .body(empty())
        .expect("request")
}

fn get_session(connection: &str, session: &str) -> Request<Full<Bytes>> {
    get()
        .header(headers::ACP_CONNECTION_ID, connection)
        .header(headers::ACP_SESSION_ID, session)
        .body(empty())
        .expect("request")
}

/// POST a second `session/new` and wait for the export to report it.
///
/// The connection stream's single subscriber was consumed reading the first
/// session's result, so this one is identified from the export's own session
/// count plus the fixture's deterministic naming (`session-1`, `session-2`).
async fn second_session(
    export: &AcpExport,
    profile: &Arc<Profile>,
    connection: &str,
    workspace: &std::path::Path,
) -> String {
    let request = post()
        .header(headers::ACP_CONNECTION_ID, connection)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "new-2",
            "method": "session/new",
            "params": {"cwd": workspace.to_string_lossy(), "mcpServers": []},
        })))
        .expect("request");
    assert_eq!(
        send(export, profile, request).await.status(),
        StatusCode::ACCEPTED
    );
    for _ in 0..400 {
        if export.diagnostics().sessions_opened == 2 {
            return "session-2".to_owned();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the second session was never opened");
}

/// POST `session/new` and read its result **off the connection stream**,
/// which is where the RFD puts it.
async fn open_session(
    export: &AcpExport,
    profile: &Arc<Profile>,
    connection: &str,
    workspace: &std::path::Path,
    stream: http::Response<ChannelBody>,
) -> Session {
    let request = post()
        .header(headers::ACP_CONNECTION_ID, connection)
        .body(json_body(&json!({
            "jsonrpc": "2.0",
            "id": "new-1",
            "method": "session/new",
            "params": {"cwd": workspace.to_string_lossy(), "mcpServers": []},
        })))
        .expect("request");
    let accepted = send(export, profile, request).await;
    assert_eq!(
        accepted.status(),
        StatusCode::ACCEPTED,
        "session/new answers 202; the result travels on the connection GET"
    );
    let held = HeldStream::hold(stream);
    let id = within(held.wait_for_session_id()).await;
    Session {
        id,
        connection_stream: held,
    }
}

/// A subscribed SSE stream held open, draining in the background, for the rest
/// of a test.
///
/// **Holding is now load-bearing.** Under `docs/acp.md`'s subscriber-loss
/// policy an established stream whose body is dropped terminates its whole ACP
/// transport, so a test that reads one event and lets the response go has
/// destroyed the connection it was building. Parking the body in a drain task
/// keeps the stream established until a test asks for a break with
/// [`HeldStream::break_now`], which is the only place a break should come from.
struct HeldStream {
    payloads: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl HeldStream {
    fn hold(response: http::Response<ChannelBody>) -> Self {
        let payloads = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let sink = Arc::clone(&payloads);
        let task = tokio::spawn(async move {
            let mut body = std::pin::pin!(response.into_body());
            let mut buffer = Vec::new();
            let mut taken = 0usize;
            while let Some(frame) = body.frame().await {
                let Ok(frame) = frame else { return };
                if let Ok(data) = frame.into_data() {
                    buffer.extend_from_slice(&data);
                }
                let all = sse_payloads(&buffer);
                if all.len() > taken {
                    let mut guard = sink
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.extend_from_slice(&all[taken..]);
                    taken = all.len();
                }
            }
        });
        Self { payloads, task }
    }

    /// Break this established stream the way a consumer going away breaks it:
    /// the drain task is aborted, which drops the response body.
    fn break_now(&self) {
        self.task.abort();
    }

    fn seen(&self) -> Vec<Vec<u8>> {
        self.payloads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Wait for a payload whose JSON pointer resolves to a string.
    async fn wait_for_pointer(&self, pointer: &str) -> String {
        loop {
            for payload in self.seen() {
                if let Ok(value) = serde_json::from_slice::<Value>(&payload)
                    && let Some(found) = value.pointer(pointer).and_then(Value::as_str)
                {
                    return found.to_owned();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_session_id(&self) -> String {
        self.wait_for_pointer("/result/sessionId").await
    }
}

/// How a stream stopped producing.
///
/// **The three are not interchangeable**, and conflating them is how a test
/// can claim a stream "broke" when it simply went quiet: a broken ACP stream
/// errors its body, an orderly one ends, and a live one that has nothing to
/// say does neither. `Quiet` is a *timeout in the test*, not an observation
/// about the stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ending {
    /// The body yielded an error: this is what a broken stream looks like.
    Errored,
    /// The body ended cleanly.
    Eof,
    /// Neither happened within the read window.
    Quiet,
}

/// Read a stream until it ends and return its `data:` payloads in arrival
/// order, with the way it stopped.
async fn collect_stream(response: http::Response<ChannelBody>) -> (Vec<Vec<u8>>, Ending) {
    let (raw, ending) = collect_raw(response).await;
    (sse_payloads(&raw), ending)
}

async fn collect_raw(response: http::Response<ChannelBody>) -> (Vec<u8>, Ending) {
    let mut body = std::pin::pin!(response.into_body());
    let mut buffer = Vec::new();
    // A live stream stays open for the life of its connection, so a read window
    // bounds the wait -- but which of the three endings happened is reported
    // rather than flattened.
    loop {
        match tokio::time::timeout(Duration::from_millis(2500), body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    buffer.extend_from_slice(&data);
                }
            }
            Ok(Some(Err(_))) => return (buffer, Ending::Errored),
            Ok(None) => return (buffer, Ending::Eof),
            Err(_) => return (buffer, Ending::Quiet),
        }
    }
}
