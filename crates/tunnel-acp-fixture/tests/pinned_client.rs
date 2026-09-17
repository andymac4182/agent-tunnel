#![cfg(unix)]
//! A complete v1 ACP conversation driven by the **official pinned client**
//! through the gate-2 `forward`/`serve` bridge (M8 chunk 3).
//!
//! The client is `agent-client-protocol` / `agent-client-protocol-http`
//! `=2.1.0` — the same artifacts `tunnel-acp` pins for the profile tables, so
//! this is the first thing in this repository that is interoperability
//! evidence rather than a table asserting itself.  It speaks cleartext HTTP/2
//! with prior knowledge to a loopback gateway, because the pinned profile
//! accepts HTTP/2 only.
//!
//! **What is measured here, and where.**
//!
//! * Everything about the conversation — the `session/new` result, the update
//!   chunks, the permission request, the `stopReason` — is read from messages
//!   the client actually received, never from an HTTP status.  Nearly every
//!   POST on this binding answers 202, which `docs/acp.md` says means "accepted
//!   by the bridge" and nothing more.
//! * **Wire order is taken at the transport**, from the gateway's own tap, not
//!   from the order the client's handlers ran.  M3-03 recorded rmcp delivering
//!   log sequence 4 before 3 while the wire was intact; a handler-order
//!   assertion would be measuring the SDK's concurrency, not this bridge's
//!   ordering.  The handler's record is compared as a **multiset** only, which
//!   is all it can honestly prove.
//!
//! **There is no principal here.**  The in-process bridge has no relay ingress
//! in front of it, so every request carries no `tunnel-principal-binding` at
//! all — the M3-01/M3-02 precedent exactly.  Nothing in this file is evidence
//! about principals, tenants, rotation, peers or isolation.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::schema::v1::{
    ContentBlock, InitializeRequest, NewSessionRequest, PromptRequest, RequestPermissionOutcome,
    RequestPermissionRequest, RequestPermissionResponse, SelectedPermissionOutcome,
    SessionNotification, StopReason, TextContent,
};
use agent_client_protocol::{Agent, ConnectionTo};
use agent_client_protocol_http::HttpClient;
use common::{acp_export, gateway, http2_client, order_digest, sse_payloads, within};
use serde_json::Value;

/// Everything the client's own handlers saw, in the order they ran.
///
/// Deliberately named for what it is.  Handler order is **not** wire order,
/// and this record is only ever compared as a multiset.
#[derive(Clone, Debug, Default)]
struct HandlerRecord {
    updates: Arc<Mutex<Vec<String>>>,
    permissions: Arc<Mutex<Vec<String>>>,
}

fn update_text(notification: &SessionNotification) -> String {
    serde_json::to_value(&notification.update)
        .ok()
        .and_then(|value| {
            value
                .pointer("/content/text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pinned_client_completes_a_v1_conversation_with_a_permission_callback() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = acp_export(workspace.path());
    let gateway = gateway(export.clone());
    let endpoint = gateway.endpoint();
    let record = HandlerRecord::default();

    let updates = Arc::clone(&record.updates);
    let permissions = Arc::clone(&record.permissions);
    let cwd = workspace.path().to_path_buf();
    let outcome: Arc<Mutex<Option<StopReason>>> = Arc::new(Mutex::new(None));
    let seen_stop = Arc::clone(&outcome);

    let client = HttpClient::with_endpoint_and_client(&endpoint, http2_client())
        .expect("the pinned client accepts the gateway endpoint");

    within(
        agent_client_protocol::Client
            .builder()
            .on_receive_notification(
                async move |notification: SessionNotification, _context| {
                    updates
                        .lock()
                        .expect("lock")
                        .push(update_text(&notification));
                    Ok(())
                },
                agent_client_protocol::on_receive_notification!(),
            )
            .on_receive_request(
                async move |request: RequestPermissionRequest, responder, _connection| {
                    // The host answers on the same endpoint with both identity
                    // headers; the SDK does that POST itself.
                    let option = request
                        .options
                        .iter()
                        .find(|option| {
                            option.option_id.0.as_ref() == tunnel_acp_fixture::PERMIT_OPTION
                        })
                        .map(|option| option.option_id.clone())
                        .expect("the agent offered the permit option");
                    permissions
                        .lock()
                        .expect("lock")
                        .push(option.0.as_ref().to_owned());
                    responder.respond(RequestPermissionResponse::new(
                        RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(option)),
                    ))
                },
                agent_client_protocol::on_receive_request!(),
            )
            .connect_with(client, move |connection: ConnectionTo<Agent>| async move {
                let initialized = connection
                    .send_request(InitializeRequest::new(ProtocolVersion::V1))
                    .block_task()
                    .await?;
                assert_eq!(initialized.protocol_version, ProtocolVersion::V1);

                let session = connection
                    .send_request(NewSessionRequest::new(cwd))
                    .block_task()
                    .await?;

                // `permission` makes the agent ask once, wait for the answer,
                // record what it actually received in the workspace, and stop
                // with the matching reason.
                let prompt = connection
                    .send_request(PromptRequest::new(
                        session.session_id.clone(),
                        vec![ContentBlock::Text(TextContent::new(
                            "permission".to_owned(),
                        ))],
                    ))
                    .block_task()
                    .await?;
                *seen_stop.lock().expect("lock") = Some(prompt.stop_reason);
                Ok(())
            }),
    )
    .await
    .expect("the pinned client completed the conversation");

    // ------------------------------------------------ what the wire carried
    //
    // `stopReason` is read from the message the client received, which the
    // bridge put on the session GET.  No status says a turn finished.
    assert_eq!(
        *outcome.lock().expect("lock"),
        Some(StopReason::EndTurn),
        "the turn ended with end_turn, read off the wire"
    );

    // The agent wrote what it *received* into its workspace, so this is the
    // agent's own record of the permission outcome rather than the bridge's
    // belief about what it forwarded.
    let marker = workspace
        .path()
        .join(tunnel_acp_fixture::PERMISSION_OUTCOME_FILE);
    assert!(
        common::wait_for_file(&marker).await,
        "the agent recorded an outcome"
    );
    assert_eq!(
        std::fs::read_to_string(&marker).expect("marker"),
        format!("selected:{}", tunnel_acp_fixture::PERMIT_OPTION),
        "the agent received the host's selection, not a cancellation"
    );

    // The client's handlers saw one permission and the agent's chunks.  This
    // is a multiset claim on purpose: handler order is the SDK's business.
    assert_eq!(
        record.permissions.lock().expect("lock").len(),
        1,
        "exactly one permission reached the host"
    );
    let mut handler_updates = record.updates.lock().expect("lock").clone();
    handler_updates.sort();
    assert!(
        handler_updates
            .iter()
            .any(|text| text.starts_with("permission-outcome:selected:")),
        "the handler saw the agent's outcome chunk: {handler_updates:?}"
    );

    // ---------------------------------------------- wire order, at the tap
    let session_streams: Vec<Vec<u8>> = gateway
        .wire
        .bytes("GET ")
        .into_iter()
        .filter(|bytes| !bytes.is_empty())
        .collect();
    assert!(
        !session_streams.is_empty(),
        "the gateway recorded the SSE streams: {:?}",
        gateway.wire.labels()
    );
    for raw in &session_streams {
        let payloads = sse_payloads(raw);
        // Byte for byte, at the transport: every event is one `data:` line.
        let mut rebuilt = Vec::new();
        for payload in &payloads {
            rebuilt.extend_from_slice(b"data: ");
            rebuilt.extend_from_slice(payload);
            rebuilt.extend_from_slice(b"\n\n");
        }
        assert_eq!(
            &rebuilt, raw,
            "the stream is exactly the events and nothing else"
        );
    }

    // The session stream is the one carrying the prompt result.  Its order is
    // fixed by a digest over arrival order: the permission request precedes
    // the outcome chunk, which precedes the result.
    let session_stream = session_streams
        .iter()
        .map(|raw| sse_payloads(raw))
        .find(|payloads| {
            payloads.iter().any(|payload| {
                serde_json::from_slice::<Value>(payload)
                    .ok()
                    .and_then(|value| value.pointer("/result/stopReason").cloned())
                    .is_some()
            })
        })
        .expect("a session stream carried the prompt result");
    let methods: Vec<String> = session_stream
        .iter()
        .filter_map(|payload| serde_json::from_slice::<Value>(payload).ok())
        .map(|value| {
            value
                .get("method")
                .and_then(Value::as_str)
                .map_or_else(|| "<result>".to_owned(), ToOwned::to_owned)
        })
        .collect();
    assert_eq!(
        methods,
        vec![
            "session/request_permission".to_owned(),
            "session/update".to_owned(),
            "<result>".to_owned(),
        ],
        "the session stream's wire order: the callback, then the chunk that \
         reports its outcome, then the turn's result"
    );
    // A digest over arrival order, so a future reordering changes the value
    // rather than passing a multiset comparison.
    assert_ne!(
        order_digest(&session_stream),
        order_digest(&{
            let mut reversed = session_stream.clone();
            reversed.reverse();
            reversed
        }),
        "the digest is order sensitive"
    );

    export.shutdown();
}

/// The same client, without a permission: the plain `initialize` →
/// `session/new` → `session/prompt` → `end_turn` → DELETE path.
///
/// The DELETE is the pinned client's own: `HttpTransportLifecycle::drop`
/// sends it when the transport ends.  Its effect is read from the process
/// table, not from the 202 it received.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pinned_clients_own_delete_ends_the_child() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = acp_export(workspace.path());
    let gateway = gateway(export.clone());
    let endpoint = gateway.endpoint();
    let cwd = workspace.path().to_path_buf();
    let pids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&pids);
    let live = export.clone();

    let client = HttpClient::with_endpoint_and_client(&endpoint, http2_client()).expect("endpoint");
    within(
        agent_client_protocol::Client
            .builder()
            .on_receive_notification(
                async move |_notification: SessionNotification, _context| Ok(()),
                agent_client_protocol::on_receive_notification!(),
            )
            .connect_with(client, move |connection: ConnectionTo<Agent>| async move {
                connection
                    .send_request(InitializeRequest::new(ProtocolVersion::V1))
                    .block_task()
                    .await?;
                *observed.lock().expect("lock") = live.child_pids();
                let session = connection
                    .send_request(NewSessionRequest::new(cwd))
                    .block_task()
                    .await?;
                let prompt = connection
                    .send_request(PromptRequest::new(
                        session.session_id.clone(),
                        vec![ContentBlock::Text(TextContent::new("ok".to_owned()))],
                    ))
                    .block_task()
                    .await?;
                assert_eq!(prompt.stop_reason, StopReason::EndTurn);
                Ok(())
            }),
    )
    .await
    .expect("conversation");

    let pid = pids
        .lock()
        .expect("lock")
        .first()
        .copied()
        .expect("a child");
    for _ in 0..400 {
        if !common::is_alive(pid) && export.diagnostics().live_connections == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !common::is_alive(pid),
        "the client's DELETE ended the connection's child; read from the process table"
    );
    assert_eq!(export.diagnostics().live_connections, 0);
    export.shutdown();
}
