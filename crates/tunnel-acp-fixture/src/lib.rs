#![forbid(unsafe_code)]
//! A deterministic synthetic ACP v1 stdio agent (task row M8-02's fixture).
//!
//! **No model, no credentials, no network, synthetic effects only.** The agent
//! never calls out, never reads a file outside its working directory and never
//! runs a command a message gave it. Its "effects" are marker files in the
//! workspace it was started in.
//!
//! It speaks the newline-delimited ACP v1 JSON-RPC that `docs/acp.md` records,
//! hand-written rather than produced by the pinned SDK's server: its job is to
//! emit lines a real agent library would refuse to produce, and running the
//! SDK here would read as interoperability evidence this chunk does not have.
//!
//! # Directives
//!
//! A `session/prompt` whose first text block is one of these makes the agent
//! do the named pathological thing. Anything else is answered `end_turn`.
//!
//! | Directive | What the agent does |
//! | --- | --- |
//! | `ok` | one `session/update`, then `stopReason: end_turn` |
//! | `permission` | `session/request_permission`, wait for the answer, record the outcome it received, then finish with the matching stop reason |
//! | `permission:<n>` | the same, but `n` requests at once, so the pending-callback bound is reachable from one turn |
//! | `oversized:<bytes>` | one stdout line of `<bytes>` filler with no newline in it |
//! | `malformed` | one stdout line that is not JSON |
//! | `batch` | one stdout line that is a JSON-RPC **array** (M8-C02) |
//! | `stderr-flood:<bytes>` | write `<bytes>` to stderr, then finish |
//! | `detach:<file>` | start a descendant that calls `setsid` and survives its process group, then finish |
//! | `exit:<code>` | finish the turn, then exit by itself — the one end of life that runs none of the supervisor's kill path |
//! | `silent` | never answer the prompt |
//! | `updates:<n>` | emit `n` `session/update` chunks as fast as it can, then finish — enough of them fills a stream's bounded queue, so an unread subscriber stalls output credit |
//! | `effect-crash:<name>` | append one line to the workspace's own side-effect ledger, flush it to disk, then **die without answering the prompt** |
//! | `effect:<name>` | append one line to that same ledger, then finish `end_turn` — the non-crashing sibling, so a turn that must survive can still record a durable effect |
//! | `effect-permission:<name>` | record one effect, then behave as `permission`: the turn stays open on a pending callback and the effect is already on disk |
//!
//! The echoed permission outcome is what makes a timeout observable **on the
//! wire**: the supervisor's belief about what it sent is not evidence that the
//! agent received a cancellation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, mpsc, oneshot};

/// The argv verb that runs the agent on stdio.
pub const AGENT_MODE: &str = "agent";
/// The argv verb that runs a descendant which deliberately leaves its process
/// group. It takes a pid file path.
pub const DETACHED_MODE: &str = "detached";
/// The longest a detached descendant lives on its own, so a failed run leaks
/// nothing for more than this.
pub const DETACHED_LIFETIME_SECONDS: u64 = 300;

/// The option the fixture offers, and the one the supervisor may select.
pub const PERMIT_OPTION: &str = "permit-one";
/// The option the fixture offers for a refusal.
pub const REJECT_OPTION: &str = "reject-one";

/// The marker the agent writes in its workspace recording the permission
/// outcome it actually received, as `<outcome>:<optionId>`. A supervisor's
/// belief about what it sent is not evidence that the agent received it.
pub const PERMISSION_OUTCOME_FILE: &str = "permission-outcome.txt";

/// Written next to the pid file: `ok` when `setsid` succeeded, `err` when it
/// did not. A test must not assume the escape happened.
pub const SETSID_MARKER: &str = "setsid";

/// The agent's own append-only record of the synthetic side effects it has
/// performed, one name per line, in its workspace.
///
/// **This is the ledger a test must read after a fault, and the reason it
/// exists is that the alternative is not evidence.** A harness counter that
/// increments where the harness *believes* it dispatched proves only what the
/// harness believed; it cannot distinguish "the effect happened once" from
/// "the effect happened twice and one attempt was not recorded", which is the
/// exact question a replay test asks. This file is written by the agent
/// process, at the moment the effect happens, and survives the process dying
/// immediately afterwards.
pub const SIDE_EFFECT_LEDGER: &str = "side-effects.log";

type Waiters = Arc<Mutex<HashMap<String, oneshot::Sender<Value>>>>;

/// Run the synthetic agent on stdin/stdout until stdin closes.
pub async fn run_agent() {
    let (out, mut outbox) = mpsc::channel::<String>(64);
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(line) = outbox.recv().await {
            if stdout.write_all(line.as_bytes()).await.is_err()
                || stdout.write_all(b"\n").await.is_err()
                || stdout.flush().await.is_err()
            {
                return;
            }
        }
    });
    // A raw sink for the lines that must NOT go through JSON serialization:
    // an oversized run of filler and a line that is not JSON at all.
    let waiters: Waiters = Arc::new(Mutex::new(HashMap::new()));
    let mut sessions = 0u64;

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let method = message.get("method").and_then(Value::as_str);
        let id = message.get("id").cloned();
        match method {
            Some("initialize") => {
                if let Some(id) = id {
                    let _ = out
                        .send(
                            json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {"protocolVersion": 1, "agentCapabilities": {}},
                            })
                            .to_string(),
                        )
                        .await;
                }
            }
            Some("session/new") => {
                sessions += 1;
                let session = format!("session-{sessions}");
                if let Some(id) = id {
                    let _ = out
                        .send(
                            json!({"jsonrpc": "2.0", "id": id, "result": {"sessionId": session}})
                                .to_string(),
                        )
                        .await;
                }
            }
            Some("session/prompt") => {
                let Some(id) = id else { continue };
                let session = message
                    .pointer("/params/sessionId")
                    .and_then(Value::as_str)
                    .unwrap_or("session-1")
                    .to_owned();
                let directive = message
                    .pointer("/params/prompt/0/text")
                    .and_then(Value::as_str)
                    .unwrap_or("ok")
                    .to_owned();
                // A task of its own, so the read loop keeps routing the
                // permission answer that this prompt is waiting for.
                tokio::spawn(run_directive(
                    directive,
                    session,
                    id,
                    out.clone(),
                    Arc::clone(&waiters),
                ));
            }
            Some("session/cancel") => {}
            // A response: route it to whoever is waiting for that id.
            None => {
                let Some(key) = message.get("id").map(id_key) else {
                    continue;
                };
                if let Some(sender) = waiters.lock().await.remove(&key) {
                    let _ = sender.send(message);
                }
            }
            Some(_) => {}
        }
    }
    drop(out);
    let _ = writer.await;
}

fn id_key(id: &Value) -> String {
    // Keeps the JSON type, so a string "1" and a number 1 are different keys --
    // the same rule the supervisor applies.
    match id {
        Value::String(text) => format!("s:{text}"),
        other => format!("n:{other}"),
    }
}

async fn run_directive(
    directive: String,
    session: String,
    id: Value,
    out: mpsc::Sender<String>,
    waiters: Waiters,
) {
    let (verb, argument) = match directive.split_once(':') {
        Some((verb, argument)) => (verb, Some(argument.to_owned())),
        None => (directive.as_str(), None),
    };
    match verb {
        // `permission` asks once; `permission:<n>` asks `n` times at once, so
        // the pending-callback bound is reachable from a single session and a
        // single turn.
        // `effect-permission:<name>` is `permission` with one durable side
        // effect recorded first, for a turn that must be held open across a
        // carrier drain and then shown to have run its effect exactly once.
        "permission" | "effect-permission" => {
            let count = if verb == "effect-permission" {
                record_side_effect(&argument.clone().unwrap_or_else(|| "effect".to_owned()));
                1
            } else {
                argument
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(1)
                    .max(1)
            };
            let mut waiting = Vec::with_capacity(count);
            for index in 0..count {
                let permission_id = format!("permission-{session}-{index}");
                let (sender, receiver) = oneshot::channel();
                waiters
                    .lock()
                    .await
                    .insert(format!("s:{permission_id}"), sender);
                let _ = out
                    .send(
                        json!({
                            "jsonrpc": "2.0",
                            "id": permission_id,
                            "method": "session/request_permission",
                            "params": {
                                "sessionId": session,
                                "toolCall": {"toolCallId": format!("tool-{index}"), "title": "Read the synthetic fixture listing"},
                                "options": [
                                    {"optionId": PERMIT_OPTION, "name": "Allow once", "kind": "allow_once"},
                                    {"optionId": REJECT_OPTION, "name": "Reject once", "kind": "reject_once"},
                                ],
                            },
                        })
                        .to_string(),
                    )
                    .await;
                waiting.push(receiver);
            }
            let mut outcome = "none".to_owned();
            let mut selected = String::new();
            for receiver in waiting {
                let answer = receiver.await.ok();
                // Echo what actually arrived. This is the wire evidence that a
                // timeout reached the agent as a cancellation, rather than the
                // supervisor's own belief about what it sent.
                outcome = answer
                    .as_ref()
                    .and_then(|value| value.pointer("/result/outcome/outcome"))
                    .and_then(Value::as_str)
                    .unwrap_or("none")
                    .to_owned();
                selected = answer
                    .as_ref()
                    .and_then(|value| value.pointer("/result/outcome/optionId"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
            }
            if count == 1 {
                // A synthetic effect in the workspace, so a test reads what the
                // agent *received* rather than what the supervisor believes it
                // sent. Written atomically.
                let temporary = std::path::Path::new(PERMISSION_OUTCOME_FILE).with_extension("tmp");
                if std::fs::write(&temporary, format!("{outcome}:{selected}")).is_ok() {
                    let _ = std::fs::rename(&temporary, PERMISSION_OUTCOME_FILE);
                }
            }
            update(
                &out,
                &session,
                &format!("permission-outcome:{outcome}:{selected}"),
            )
            .await;
            let stop = match (outcome.as_str(), selected.as_str()) {
                ("cancelled", _) => "cancelled",
                ("selected", REJECT_OPTION) => "refusal",
                _ => "end_turn",
            };
            finish(&out, &id, stop).await;
        }
        "oversized" => {
            let bytes = argument
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(2 << 20);
            // No newline anywhere inside, so a reader that reassembled first
            // would buffer all of it.
            let _ = out.send("A".repeat(bytes)).await;
            finish(&out, &id, "end_turn").await;
        }
        "malformed" => {
            let _ = out.send("{\"jsonrpc\":\"2.0\",".to_owned()).await;
            finish(&out, &id, "end_turn").await;
        }
        "batch" => {
            // A JSON-RPC batch frame (M8-C02): the pinned SDK preserves these,
            // the pinned RFD revision answers 501, and this profile refuses.
            let _ = out
                .send(
                    json!([
                        {"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": session, "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "one"}}}},
                        {"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": session, "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "two"}}}},
                    ])
                    .to_string(),
                )
                .await;
            finish(&out, &id, "end_turn").await;
        }
        "stderr-flood" => {
            let bytes = argument
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(4 << 20);
            let mut stderr = tokio::io::stderr();
            let chunk = vec![b'E'; 4096];
            let mut written = 0usize;
            while written < bytes {
                let take = chunk.len().min(bytes - written);
                if stderr.write_all(&chunk[..take]).await.is_err() {
                    break;
                }
                written += take;
            }
            let _ = stderr.flush().await;
            update(&out, &session, &format!("stderr-bytes:{written}")).await;
            finish(&out, &id, "end_turn").await;
        }
        "detach" => {
            let file = argument.unwrap_or_else(|| "detached.pid".to_owned());
            let started = spawn_detached(Path::new(&file));
            update(&out, &session, &format!("detached:{started}")).await;
            finish(&out, &id, "end_turn").await;
        }
        // The child ending by itself, which is the one end of life that runs
        // none of the supervisor's kill path: no cancellation, no `start_kill`,
        // only the post-wait group signal. The M8-C07 review found that half
        // untested end to end.
        "exit" => {
            let code = argument
                .and_then(|value| value.parse::<i32>().ok())
                .unwrap_or(0);
            finish(&out, &id, "end_turn").await;
            // Let the writer task flush the line before the process goes.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            std::process::exit(code);
        }
        // Enough updates to overrun a stream's bounded queue. A subscriber
        // that took its queue but never reads the body then stalls output
        // credit, which is the bound `docs/acp.md` puts at 30 seconds.
        "updates" => {
            let count = argument
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(64);
            for index in 0..count {
                update(&out, &session, &format!("chunk-{index}")).await;
            }
            finish(&out, &id, "end_turn").await;
        }
        // A synthetic side effect recorded on disk, then a crash before the
        // turn can be answered. The consumer is left with a dispatched request
        // and no result, which is `outcome_unknown`; the ledger is how a test
        // learns the effect happened exactly once.
        "effect-crash" => {
            let name = argument.unwrap_or_else(|| "effect".to_owned());
            record_side_effect(&name);
            // `abort` rather than `exit`: no destructor runs, no buffered
            // stdout is flushed, and the turn is never answered. That is the
            // crash this directive is for, and it is why the ledger is
            // flushed to disk *before* this line rather than at exit.
            std::process::abort();
        }
        // The same durable record as `effect-crash`, without the crash.
        //
        // It exists because "no repeated side effects across a rotation"
        // cannot otherwise be read from the **agent's own** ledger: every
        // other ledger-writing directive kills the agent, so a turn that must
        // survive three rotations and then finish had no way to record that it
        // ran exactly once.  Counting SSE messages instead would measure the
        // stream rather than the effect.
        "effect" => {
            let name = argument.unwrap_or_else(|| "effect".to_owned());
            record_side_effect(&name);
            update(&out, &session, "synthetic effect recorded").await;
            finish(&out, &id, "end_turn").await;
        }
        "silent" => {}
        _ => {
            update(&out, &session, "synthetic listing").await;
            finish(&out, &id, "end_turn").await;
        }
    }
}

/// Append one synthetic side effect to the workspace ledger and flush it.
///
/// Opened for append and `sync_all`ed before returning, so the record is on
/// disk before the caller crashes. An effect that is not durable by the time
/// the process dies would make an exactly-once claim unfalsifiable.
fn record_side_effect(name: &str) {
    use std::io::Write as _;

    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(SIDE_EFFECT_LEDGER)
    else {
        return;
    };
    if writeln!(file, "{name}").is_ok() {
        let _ = file.sync_all();
    }
}

async fn update(out: &mpsc::Sender<String>, session: &str, text: &str) {
    let _ = out
        .send(
            json!({
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": session,
                    "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": {"type": "text", "text": text},
                    },
                },
            })
            .to_string(),
        )
        .await;
}

async fn finish(out: &mpsc::Sender<String>, id: &Value, stop: &str) {
    let _ = out
        .send(json!({"jsonrpc": "2.0", "id": id, "result": {"stopReason": stop}}).to_string())
        .await;
}

/// Start the descendant that deliberately leaves this process group.
fn spawn_detached(pid_file: &Path) -> bool {
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
    std::process::Command::new(executable)
        .arg(DETACHED_MODE)
        .arg(pid_file)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// Run as a descendant that escapes its process group.
///
/// `setsid` puts this process in a brand new session and process group, which
/// is exactly the hole `docs/tasks.md` M3-09 records: a group `SIGKILL` aimed
/// at the supervised child's group can no longer reach it. Whether the escape
/// succeeded is written next to the pid, so a test reports what happened
/// rather than assuming it.
pub async fn run_detached(pid_file: &Path) {
    #[cfg(unix)]
    let escaped = rustix::process::setsid().is_ok();
    #[cfg(not(unix))]
    let escaped = false;

    let marker = marker_file(pid_file);
    let _ = std::fs::write(&marker, if escaped { "ok" } else { "err" });
    // Publish the pid atomically so a reader never sees a half-written file.
    let temporary = pid_file.with_extension("tmp");
    if std::fs::write(&temporary, std::process::id().to_string()).is_ok() {
        let _ = std::fs::rename(&temporary, pid_file);
    }
    tokio::time::sleep(std::time::Duration::from_secs(DETACHED_LIFETIME_SECONDS)).await;
}

/// Where [`run_detached`] records whether `setsid` succeeded.
#[must_use]
pub fn marker_file(pid_file: &Path) -> PathBuf {
    pid_file.with_extension(SETSID_MARKER)
}
