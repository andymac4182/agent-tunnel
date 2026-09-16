#![forbid(unsafe_code)]
//! A deterministic synthetic MCP server built with the pinned official Rust
//! SDK (rmcp 3.4.0).  It touches nothing but an optional marker directory
//! the test owns.
//!
//! Tools:
//!
//! * `echo` — returns one text block holding `{"arguments", "meta"}` as the
//!   server received them (so `_meta` preservation is observable) plus a
//!   fixed synthetic image block;
//! * `progress` — sends `steps` progress notifications with the request's
//!   progress token, then returns `done`;
//! * `sleep` — waits until the request is cancelled and records
//!   `cancelled-<label>` in the marker directory (or gives up after 60 s);
//!   with `descendant`, it first starts a synthetic descendant process in its
//!   own process group (see [`DESCENDANT_MODE`]);
//! * `crash` — writes a synthetic marker to stderr and exits with status 3;
//!   with `label`, it first sends one progress notification and waits for
//!   the test's release marker, so the crash lands mid-stream;
//! * `stderr_flood` — writes `bytes` synthetic bytes to stderr and returns;
//! * `big` — returns a text block of `bytes` synthetic bytes;
//! * `log` — sends `count` `notifications/message` log notifications whose
//!   data is [`log_data`], then returns `logged-<count>`;
//! * `stream` — sends `events` progress notifications whose messages are
//!   [`stream_event_message`], pausing after each index listed in `gates`
//!   until the test releases it, then returns [`stream_result`];
//! * `gate` — waits for the test's release marker, then returns
//!   `released-<label>`.
//!
//! Every call appends `<tool>` to `invocations.log` in the marker directory,
//! so a test can prove a tool ran exactly once.  `initialize`,
//! `server/discover` and `tools/list` append their method to
//! `discovery.log`.
//!
//! **Release markers.**  A tool that waits writes `waiting-<name>` and polls
//! for `release-<name>` (bounded by [`RELEASE_WAIT`]).  `tools/list` waits
//! the same way under the name `discovery` when the test created
//! `hold-discovery`, and consumes that request marker so only one listing is
//! held.  The markers are the only coupling between a test and a server
//! process; the waiting server polls, the test never sleeps on them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, DiscoverResult,
    Implementation, InitializeRequestParams, InitializeResult, ListToolsResult,
    PaginatedRequestParams, ProgressNotificationParam, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use tokio::io::AsyncWriteExt;

/// The synthetic stderr marker `crash` writes.  Tests assert it never
/// reaches a consumer.
pub const STDERR_MARKER: &str = "SYNTHETIC-FIXTURE-STDERR-MARKER";
/// A 1x1 transparent PNG, base64.
pub const IMAGE_PNG_BASE64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
/// The binary's first argument that runs a synthetic descendant: it writes
/// its process ID to the path given as the second argument and then waits,
/// bounded by [`DESCENDANT_LIFETIME`], without leaving its process group.
pub const DESCENDANT_MODE: &str = "descendant";
/// The longest a synthetic descendant lives on its own.
pub const DESCENDANT_LIFETIME: Duration = Duration::from_secs(180);
/// The longest a server waits for a release marker.
pub const RELEASE_WAIT: Duration = Duration::from_secs(120);
/// How often a waiting server looks for its release marker.
const RELEASE_POLL: Duration = Duration::from_millis(10);
/// The `tools/list` hold request marker.
pub const HOLD_DISCOVERY: &str = "hold-discovery";
/// The release name of a held `tools/list`.
pub const DISCOVERY_RELEASE: &str = "discovery";

/// The message of `stream` event `index` for `label`: a fixed prefix and
/// `bytes` deterministic synthetic ASCII characters.
#[must_use]
pub fn stream_event_message(label: &str, index: u64, bytes: usize) -> String {
    let mut message = format!("{label}:{index}:");
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ index.wrapping_mul(0x0100_0000_01B3);
    for _ in 0..bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let offset = u8::try_from(state % 62).unwrap_or(0);
        message.push(char::from(match offset {
            0..=9 => b'0' + offset,
            10..=35 => b'a' + offset - 10,
            _ => b'A' + offset - 36,
        }));
    }
    message
}

/// The text `stream` returns once every event was sent.
#[must_use]
pub fn stream_result(label: &str, events: u64, bytes: usize) -> String {
    format!("stream-done:{label}:{events}:{bytes}")
}

/// The data of log notification `index` for `label`.
#[must_use]
pub fn log_data(label: &str, index: u64) -> serde_json::Value {
    serde_json::json!({"label": label, "seq": index, "synthetic": true})
}

/// The file name a waiting server writes.
#[must_use]
pub fn waiting_marker(name: &str) -> String {
    format!("waiting-{name}")
}

/// The file name that releases a waiting server.
#[must_use]
pub fn release_marker(name: &str) -> String {
    format!("release-{name}")
}

/// The pid file a `descendant` label writes.
#[must_use]
pub fn descendant_pid_file(label: &str) -> String {
    format!("descendant-{label}.pid")
}

/// The fixture server.
#[derive(Clone, Debug, Default)]
pub struct FixtureServer {
    marker_dir: Option<Arc<PathBuf>>,
}

impl FixtureServer {
    #[must_use]
    pub fn new(marker_dir: Option<PathBuf>) -> Self {
        Self {
            marker_dir: marker_dir.map(Arc::new),
        }
    }

    async fn record(&self, name: &str, line: &str) {
        let Some(dir) = &self.marker_dir else { return };
        if let Ok(mut file) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))
            .await
        {
            let _ = file.write_all(format!("{line}\n").as_bytes()).await;
            let _ = file.flush().await;
        }
    }

    /// Write `waiting-<name>` and wait for `release-<name>`.  Returns whether
    /// the release arrived.  Without a marker directory nothing waits.
    async fn wait_release(&self, name: &str) -> bool {
        let Some(dir) = &self.marker_dir else {
            return true;
        };
        let _ = tokio::fs::write(dir.join(waiting_marker(name)), b"waiting").await;
        let release = dir.join(release_marker(name));
        let deadline = tokio::time::Instant::now() + RELEASE_WAIT;
        while tokio::time::Instant::now() < deadline {
            if tokio::fs::try_exists(&release).await.unwrap_or(false) {
                return true;
            }
            tokio::time::sleep(RELEASE_POLL).await;
        }
        false
    }

    /// Consume the `tools/list` hold request, if the test created one.
    async fn take_discovery_hold(&self) -> bool {
        let Some(dir) = &self.marker_dir else {
            return false;
        };
        // A rename is atomic, so exactly one listing claims the hold.
        tokio::fs::rename(dir.join(HOLD_DISCOVERY), dir.join("hold-discovery-claimed"))
            .await
            .is_ok()
    }

    fn spawn_descendant(&self, label: &str) {
        let Some(dir) = &self.marker_dir else { return };
        let Ok(executable) = std::env::current_exe() else {
            return;
        };
        // Same process group as this server: only a group kill reaches it.
        let spawned = std::process::Command::new(executable)
            .arg(DESCENDANT_MODE)
            .arg(dir.join(descendant_pid_file(label)))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = spawned {
            // Reap it whenever it ends, so it never lingers as a zombie.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}

/// Run a synthetic descendant: publish the pid atomically, then wait.
pub async fn run_descendant(pid_file: &Path) {
    let temporary = pid_file.with_extension("tmp");
    if tokio::fs::write(&temporary, std::process::id().to_string())
        .await
        .is_ok()
    {
        let _ = tokio::fs::rename(&temporary, pid_file).await;
    }
    tokio::time::sleep(DESCENDANT_LIFETIME).await;
}

fn schema(properties: serde_json::Value) -> Arc<serde_json::Map<String, serde_json::Value>> {
    let serde_json::Value::Object(map) = serde_json::json!({
        "type": "object",
        "properties": properties,
    }) else {
        unreachable!("literal object")
    };
    Arc::new(map)
}

fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "echo",
            "Echo arguments and _meta",
            schema(serde_json::json!({})),
        ),
        Tool::new(
            "progress",
            "Send progress notifications",
            schema(serde_json::json!({"steps": {"type": "integer"}})),
        ),
        Tool::new(
            "sleep",
            "Wait until cancelled",
            schema(serde_json::json!({
                "label": {"type": "string"},
                "descendant": {"type": "boolean"},
            })),
        ),
        Tool::new(
            "crash",
            "Exit the process",
            schema(serde_json::json!({
                "label": {"type": "string"},
                "descendant": {"type": "boolean"},
            })),
        ),
        Tool::new(
            "stderr_flood",
            "Write synthetic stderr",
            schema(serde_json::json!({"bytes": {"type": "integer"}})),
        ),
        Tool::new(
            "big",
            "Return a large text block",
            schema(serde_json::json!({"bytes": {"type": "integer"}})),
        ),
        Tool::new(
            "log",
            "Send log notifications",
            schema(serde_json::json!({
                "label": {"type": "string"},
                "count": {"type": "integer"},
            })),
        ),
        Tool::new(
            "stream",
            "Stream gated progress events",
            schema(serde_json::json!({
                "label": {"type": "string"},
                "events": {"type": "integer"},
                "bytes": {"type": "integer"},
                "gates": {"type": "array", "items": {"type": "integer"}},
            })),
        ),
        Tool::new(
            "gate",
            "Wait for a release marker",
            schema(serde_json::json!({"label": {"type": "string"}})),
        ),
    ]
}

fn argument_u64(request: &CallToolRequestParams, name: &str, default: u64) -> u64 {
    request
        .arguments
        .as_ref()
        .and_then(|arguments| arguments.get(name))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(default)
}

fn argument_bool(request: &CallToolRequestParams, name: &str) -> bool {
    request
        .arguments
        .as_ref()
        .and_then(|arguments| arguments.get(name))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// A label argument reduced to ASCII letters and digits (it names files).
fn argument_label(request: &CallToolRequestParams) -> Option<String> {
    request
        .arguments
        .as_ref()
        .and_then(|arguments| arguments.get("label"))
        .and_then(serde_json::Value::as_str)
        .map(|label| {
            label
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .take(64)
                .collect::<String>()
        })
        .filter(|label| !label.is_empty())
}

impl ServerHandler for FixtureServer {
    // Logging is deprecated by SEP-2577 but still part of both pinned
    // profiles; the gate exercises `notifications/message` deliberately.
    #[allow(deprecated)]
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_logging()
                .build(),
        )
        .with_server_info(Implementation::new("tunnel-mcp-fixture", "0.1.0"))
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        self.record("discovery.log", "initialize").await;
        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }

    async fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        self.record("discovery.log", "server/discover").await;
        Ok(DiscoverResult::from_server_info(
            self.supported_protocol_versions().into_owned(),
            self.get_info(),
        ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.record("discovery.log", "tools/list").await;
        if self.take_discovery_hold().await && !self.wait_release(DISCOVERY_RELEASE).await {
            return Err(ErrorData::internal_error("discovery hold expired", None));
        }
        Ok(ListToolsResult::with_all_items(tools()))
    }

    #[allow(clippy::too_many_lines)]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.record("invocations.log", &request.name).await;
        match request.name.as_ref() {
            "echo" => {
                let text = serde_json::json!({
                    "arguments": request.arguments,
                    "meta": context.meta,
                })
                .to_string();
                Ok(CallToolResult::success(vec![
                    ContentBlock::text(text),
                    ContentBlock::image(IMAGE_PNG_BASE64, "image/png"),
                ])
                .into())
            }
            "progress" => {
                let steps = argument_u64(&request, "steps", 3).min(100);
                if let Some(token) = context.meta.get_progress_token() {
                    for step in 0..steps {
                        #[allow(clippy::cast_precision_loss)]
                        let _ = context
                            .peer
                            .notify_progress(
                                ProgressNotificationParam::new(token.clone(), (step + 1) as f64)
                                    .with_total(steps as f64),
                            )
                            .await;
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
                Ok(CallToolResult::success(vec![ContentBlock::text("done")]).into())
            }
            "sleep" => {
                let label = argument_label(&request).unwrap_or_else(|| "default".to_owned());
                if argument_bool(&request, "descendant") {
                    self.spawn_descendant(&label);
                }
                tokio::select! {
                    () = context.ct.cancelled() => {
                        self.record(&format!("cancelled-{label}"), "cancelled").await;
                        Ok(CallToolResult::success(vec![ContentBlock::text("cancelled")]).into())
                    }
                    () = tokio::time::sleep(Duration::from_secs(60)) => {
                        Ok(CallToolResult::success(vec![ContentBlock::text("slept")]).into())
                    }
                }
            }
            "crash" => {
                if let Some(label) = argument_label(&request) {
                    if argument_bool(&request, "descendant") {
                        self.spawn_descendant(&label);
                    }
                    if let Some(token) = context.meta.get_progress_token() {
                        let _ = context
                            .peer
                            .notify_progress(
                                ProgressNotificationParam::new(token.clone(), 1.0)
                                    .with_message(format!("before-crash:{label}")),
                            )
                            .await;
                    }
                    let _ = self.wait_release(&format!("crash{label}")).await;
                }
                let mut stderr = tokio::io::stderr();
                let _ = stderr.write_all(STDERR_MARKER.as_bytes()).await;
                let _ = stderr.flush().await;
                std::process::exit(3);
            }
            "stderr_flood" => {
                let bytes = argument_u64(&request, "bytes", 1 << 20).min(64 << 20);
                let chunk = vec![b'e'; 64 * 1024];
                let mut stderr = tokio::io::stderr();
                let mut written = 0u64;
                while written < bytes {
                    let take = usize::try_from((bytes - written).min(chunk.len() as u64))
                        .unwrap_or(chunk.len());
                    if stderr.write_all(&chunk[..take]).await.is_err() {
                        break;
                    }
                    written += take as u64;
                }
                let _ = stderr.flush().await;
                Ok(CallToolResult::success(vec![ContentBlock::text("flooded")]).into())
            }
            "big" => {
                let bytes = usize::try_from(argument_u64(&request, "bytes", 1024).min(64 << 20))
                    .unwrap_or(1024);
                Ok(CallToolResult::success(vec![ContentBlock::text("b".repeat(bytes))]).into())
            }
            "log" => {
                let label = argument_label(&request).unwrap_or_else(|| "default".to_owned());
                let count = argument_u64(&request, "count", 3).min(100);
                for index in 0..count {
                    #[allow(deprecated)]
                    let _ = context
                        .peer
                        .notify_logging_message(
                            rmcp::model::LoggingMessageNotificationParam::new(
                                rmcp::model::LoggingLevel::Info,
                                log_data(&label, index),
                            )
                            .with_logger("tunnel-mcp-fixture"),
                        )
                        .await;
                }
                Ok(
                    CallToolResult::success(vec![ContentBlock::text(format!("logged-{count}"))])
                        .into(),
                )
            }
            "stream" => {
                let label = argument_label(&request).unwrap_or_else(|| "default".to_owned());
                let events = argument_u64(&request, "events", 8).min(4096);
                let bytes = usize::try_from(argument_u64(&request, "bytes", 64).min(64 * 1024))
                    .unwrap_or(64);
                let gates = request
                    .arguments
                    .as_ref()
                    .and_then(|arguments| arguments.get("gates"))
                    .and_then(serde_json::Value::as_array)
                    .map(|gates| {
                        gates
                            .iter()
                            .filter_map(serde_json::Value::as_u64)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let Some(token) = context.meta.get_progress_token() else {
                    return Err(ErrorData::invalid_params(
                        "stream needs a progress token",
                        None,
                    ));
                };
                for index in 0..events {
                    #[allow(clippy::cast_precision_loss)]
                    let sent = context
                        .peer
                        .notify_progress(
                            ProgressNotificationParam::new(token.clone(), (index + 1) as f64)
                                .with_total(events as f64)
                                .with_message(stream_event_message(&label, index, bytes)),
                        )
                        .await;
                    if sent.is_err() {
                        return Err(ErrorData::internal_error("stream peer closed", None));
                    }
                    if gates.contains(&index)
                        && !self.wait_release(&format!("stream{label}g{index}")).await
                    {
                        return Err(ErrorData::internal_error("stream gate expired", None));
                    }
                }
                Ok(
                    CallToolResult::success(vec![ContentBlock::text(stream_result(
                        &label, events, bytes,
                    ))])
                    .into(),
                )
            }
            "gate" => {
                let label = argument_label(&request).unwrap_or_else(|| "default".to_owned());
                if !self.wait_release(&format!("gate{label}")).await {
                    return Err(ErrorData::internal_error("gate expired", None));
                }
                Ok(
                    CallToolResult::success(vec![ContentBlock::text(format!("released-{label}"))])
                        .into(),
                )
            }
            _ => Err(ErrorData::invalid_params("unknown tool", None)),
        }
    }
}

/// Serve the fixture with the official rmcp Streamable HTTP server on
/// `listener` until `shutdown`.  `legacy_sessions` selects rmcp's
/// 2025-11-25 session mode; otherwise requests are served statelessly.
pub async fn serve_http(
    listener: tokio::net::TcpListener,
    legacy_sessions: bool,
    marker_dir: PathBuf,
    shutdown: tokio_util::sync::CancellationToken,
) {
    use hyper_util::rt::TokioIo;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
    let server = FixtureServer::new(Some(marker_dir));
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(legacy_sessions)
        .with_sse_keep_alive(None)
        .with_cancellation_token(shutdown.child_token());
    let service: StreamableHttpService<FixtureServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(LocalSessionManager::default()),
            config,
        );
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            // A per-connection accept error (a peer that vanished, a
            // momentary descriptor limit) is not the end of the listener.
            Err(error) => {
                eprintln!("tunnel-mcp-fixture: accept failed: {}", error.kind());
                continue;
            }
        };
        let service = hyper_util::service::TowerToHyperService::new(service.clone());
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
