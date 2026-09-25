#![forbid(unsafe_code)]
//! The ACP demo consumer: the **official pinned ACP client** running one
//! session through a relay (`docs/demo/acp.md`).
//!
//! It is `agent-client-protocol` / `agent-client-protocol-http` `=2.1.0`, the
//! same artifacts `tunnel-acp` pins, speaking HTTP/2 over TLS to a relay's
//! consumer listener with a bearer token.  Nothing here talks to the device:
//! every byte goes consumer → relay → device data WebSocket → the device's ACP
//! export → the agent's stdio, and back.
//!
//! One session, four steps, each printed as one `demo:` line:
//!
//! 1. `initialize` and `session/new` in the configured workspace;
//! 2. a prompt whose streaming `session/update` chunks are printed as they
//!    arrive, ending `end_turn`;
//! 3. a prompt that asks for **permission**; the client's callback selects the
//!    allow option, and the agent reports the outcome it received;
//! 4. a prompt that asks for permission and is **cancelled** instead of
//!    answered: `session/cancel` resolves the pending callback `cancelled` and
//!    the turn ends `cancelled`.
//!
//! The expected agent is `tunnel-acp-fixture agent`, the repository's
//! synthetic agent: its prompts are directives (`updates:<n>`, `permission`),
//! not natural language.  Against another agent the prompts would mean
//! nothing in particular, and this client says so rather than guessing.
//!
//! The access token is read from a file, never from argv or the environment
//! of a shell history, and is never printed.
//!
//! ```text
//! acp-demo-client --url https://localhost:8443/v1/devices/<device>/services/<service>/http/acp \
//!     --ca server-ca.pem --token-file token.jwt --cwd /abs/path/to/the/export/workspace
//! ```
//!
//! Exit status: 0 when every step observed what it expects, 1 when a step
//! observed something else (the line says which), 2 for a usage error.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::schema::v1::{
    CancelNotification, ContentBlock, InitializeRequest, NewSessionRequest, PromptRequest,
    RequestPermissionOutcome, RequestPermissionRequest, RequestPermissionResponse,
    SelectedPermissionOutcome, SessionNotification, StopReason, TextContent,
};
use agent_client_protocol::{Agent, ConnectionTo};
use agent_client_protocol_http::HttpClient;
use serde_json::Value;
use tokio::sync::mpsc;

/// The whole session must finish inside this, so a stuck relay is a named
/// failure rather than a hang.
const SESSION_DEADLINE: Duration = Duration::from_secs(60);

struct Arguments {
    url: String,
    ca: PathBuf,
    token_file: PathBuf,
    cwd: PathBuf,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: acp-demo-client --url <https://…/http/acp> --ca <server-ca.pem> \
         --token-file <file> --cwd <export workspace>"
    );
    ExitCode::from(2)
}

fn parse() -> Option<Arguments> {
    let mut url = None;
    let mut ca = None;
    let mut token_file = None;
    let mut cwd = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let value = arguments.next()?;
        match flag.as_str() {
            "--url" => url = Some(value),
            "--ca" => ca = Some(PathBuf::from(value)),
            "--token-file" => token_file = Some(PathBuf::from(value)),
            "--cwd" => cwd = Some(PathBuf::from(value)),
            _ => return None,
        }
    }
    Some(Arguments {
        url: url?,
        ca: ca?,
        token_file: token_file?,
        cwd: cwd?,
    })
}

/// The text of an `agent_message_chunk`, or the update's kind otherwise.
fn update_text(notification: &SessionNotification) -> String {
    let value = serde_json::to_value(&notification.update).unwrap_or(Value::Null);
    value
        .pointer("/content/text")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            value
                .get("sessionUpdate")
                .and_then(Value::as_str)
                .map(|kind| format!("<{kind}>"))
        })
        .unwrap_or_else(|| "<update>".to_owned())
}

fn spelling(stop: StopReason) -> String {
    serde_json::to_value(stop)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "<unknown>".to_owned())
}

/// What the permission callback should do with the next request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OnPermission {
    Allow,
    /// Leave it unanswered and tell the session task, which cancels the turn.
    HoldForCancel,
}

fn http_client(arguments: &Arguments) -> Result<reqwest::Client, String> {
    let ca = std::fs::read(&arguments.ca)
        .map_err(|error| format!("reading --ca {}: {error}", arguments.ca.display()))?;
    let certificate = reqwest::Certificate::from_pem(&ca)
        .map_err(|error| format!("--ca is not a PEM certificate: {error}"))?;
    let token = std::fs::read_to_string(&arguments.token_file)
        .map_err(|error| format!("reading --token-file: {error}"))?;
    let mut bearer = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.trim()))
        .map_err(|_| "the token file does not hold a header-safe token".to_owned())?;
    bearer.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, bearer);
    reqwest::Client::builder()
        // `acp-http-v1` is HTTP/2 only; the relay answers HTTP/1.1 with 501.
        .http2_prior_knowledge()
        .tls_certs_only([certificate])
        .default_headers(headers)
        .build()
        .map_err(|error| format!("building the HTTP client: {error}"))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let Some(arguments) = parse() else {
        return usage();
    };
    let http = match http_client(&arguments) {
        Ok(http) => http,
        Err(error) => {
            eprintln!("demo: FAILED setup: {error}");
            return ExitCode::from(1);
        }
    };
    let client = match HttpClient::with_endpoint_and_client(&arguments.url, http) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("demo: FAILED setup: the endpoint is not a URL: {error}");
            return ExitCode::from(2);
        }
    };

    let mode = Arc::new(Mutex::new(OnPermission::Allow));
    let callback_mode = Arc::clone(&mode);
    let (held_tx, mut held_rx) = mpsc::unbounded_channel::<()>();
    let failures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let failed = Arc::clone(&failures);
    let cwd = arguments.cwd.clone();

    let session = agent_client_protocol::Client
        .builder()
        .on_receive_notification(
            async move |notification: SessionNotification, _context| {
                println!("demo: update {}", update_text(&notification));
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .on_receive_request(
            async move |request: RequestPermissionRequest, responder, _connection| {
                let offered: Vec<String> = request
                    .options
                    .iter()
                    .map(|option| option.option_id.0.as_ref().to_owned())
                    .collect();
                let title = serde_json::to_value(&request.tool_call)
                    .ok()
                    .and_then(|value| value.get("title").and_then(Value::as_str).map(ToOwned::to_owned))
                    .unwrap_or_default();
                println!("demo: permission requested \"{title}\" options={offered:?}");
                let mode = *callback_mode.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                match mode {
                    OnPermission::Allow => {
                        // The allow option, chosen by kind rather than by name
                        // so the demo does not depend on the fixture's ids.
                        let Some(option) = request
                            .options
                            .iter()
                            .find(|option| {
                                serde_json::to_value(&option.kind)
                                    .ok()
                                    .and_then(|kind| kind.as_str().map(|kind| kind.starts_with("allow")))
                                    .unwrap_or(false)
                            })
                            .map(|option| option.option_id.clone())
                        else {
                            println!("demo: the agent offered no allow option; cancelling");
                            return responder.respond(RequestPermissionResponse::new(
                                RequestPermissionOutcome::Cancelled,
                            ));
                        };
                        println!("demo: permission answered selected={}", option.0.as_ref());
                        responder.respond(RequestPermissionResponse::new(
                            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(option)),
                        ))
                    }
                    OnPermission::HoldForCancel => {
                        // Not answered: the session task cancels the turn, and
                        // `session/cancel` is what resolves this callback.
                        // Dropping an individual responder sends nothing.
                        drop(responder);
                        let _ = held_tx.send(());
                        Ok(())
                    }
                }
            },
            agent_client_protocol::on_receive_request!(),
        )
        .connect_with(client, move |connection: ConnectionTo<Agent>| async move {
            let expect = |step: &str, ok: bool, detail: String| {
                if ok {
                    println!("demo: ok {step} {detail}");
                } else {
                    println!("demo: FAILED {step} {detail}");
                    failed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(step.to_owned());
                }
            };

            // 1. initialize and a session in the export's workspace.
            let initialized = connection
                .send_request(InitializeRequest::new(ProtocolVersion::V1))
                .block_task()
                .await?;
            expect(
                "initialize",
                initialized.protocol_version == ProtocolVersion::V1,
                format!("protocol={:?}", initialized.protocol_version),
            );
            let session = connection
                .send_request(NewSessionRequest::new(cwd))
                .block_task()
                .await?;
            let id = session.session_id.clone();
            println!("demo: ok session/new session={}", id.0.as_ref());

            // 2. streaming updates.
            let streamed = connection
                .send_request(PromptRequest::new(
                    id.clone(),
                    vec![ContentBlock::Text(TextContent::new("updates:5".to_owned()))],
                ))
                .block_task()
                .await?;
            expect(
                "prompt-streaming",
                streamed.stop_reason == StopReason::EndTurn,
                format!("stopReason={}", spelling(streamed.stop_reason)),
            );

            // 3. a permission callback, answered.
            let allowed = connection
                .send_request(PromptRequest::new(
                    id.clone(),
                    vec![ContentBlock::Text(TextContent::new("permission".to_owned()))],
                ))
                .block_task()
                .await?;
            expect(
                "prompt-permission",
                allowed.stop_reason == StopReason::EndTurn,
                format!("stopReason={}", spelling(allowed.stop_reason)),
            );

            // 4. the same callback, left pending and cancelled.
            *mode.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                OnPermission::HoldForCancel;
            let pending = connection.send_request(PromptRequest::new(
                id.clone(),
                vec![ContentBlock::Text(TextContent::new("permission".to_owned()))],
            ));
            if held_rx.recv().await.is_none() {
                expect("prompt-cancel", false, "no permission callback arrived".to_owned());
                return Ok(());
            }
            println!("demo: sending session/cancel");
            connection.send_notification(CancelNotification::new(id.clone()))?;
            let cancelled = pending.block_task().await?;
            expect(
                "prompt-cancel",
                cancelled.stop_reason == StopReason::Cancelled,
                format!("stopReason={}", spelling(cancelled.stop_reason)),
            );
            Ok(())
        });

    match tokio::time::timeout(SESSION_DEADLINE, session).await {
        Err(_) => {
            println!("demo: FAILED the session did not finish within {SESSION_DEADLINE:?}");
            ExitCode::from(1)
        }
        Ok(Err(error)) => {
            println!("demo: FAILED the ACP connection ended with an error: {error}");
            ExitCode::from(1)
        }
        Ok(Ok(())) => {
            let failures = failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if failures.is_empty() {
                println!("demo: PASS initialize, session, streaming, permission and cancel through the relay");
                ExitCode::SUCCESS
            } else {
                println!("demo: FAILED steps={failures:?}");
                ExitCode::from(1)
            }
        }
    }
}
