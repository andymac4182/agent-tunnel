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
//! * `crash` — writes a synthetic marker to stderr and exits with status 3;
//! * `stderr_flood` — writes `bytes` synthetic bytes to stderr and returns;
//! * `big` — returns a text block of `bytes` synthetic bytes.
//!
//! Every call appends `<tool>` to `invocations.log` in the marker directory,
//! so a test can prove a tool ran exactly once.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ProgressNotificationParam, ServerCapabilities,
    ServerConfig, Tool,
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
            schema(serde_json::json!({"label": {"type": "string"}})),
        ),
        Tool::new("crash", "Exit the process", schema(serde_json::json!({}))),
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

impl ServerHandler for FixtureServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("tunnel-mcp-fixture", "0.1.0"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(tools()))
    }

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
                let label = request
                    .arguments
                    .as_ref()
                    .and_then(|arguments| arguments.get("label"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("default")
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .collect::<String>();
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
            _ => Err(ErrorData::invalid_params("unknown tool", None)),
        }
    }
}
