//! Shared in-process plumbing: the official rmcp client talks HTTP over a
//! Unix socket to a test gateway, which runs the gate-2 bridge `forward`
//! against `serve` and an MCP export.  No TCP listener is involved except
//! the loopback MCP backend of the Streamable HTTP export.

#![allow(dead_code)]

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rmcp::model::{ProgressNotificationParam, ProtocolVersion};
use rmcp::service::{NotificationContext, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, UnixSocketHttpClient};
use rmcp::{ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient};
use tokio::net::{TcpListener, UnixListener};
use tokio_util::sync::CancellationToken;
use tunnel_http_bridge::{BridgeConfig, ChannelBody, Profile, channel, forward, serve};
use tunnel_mcp_export::{McpExport, McpExportConfig};

pub const TIMEOUT: Duration = Duration::from_secs(30);
pub const URI: &str = "http://mcp.gateway.test/mcp";

pub async fn within<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("step timed out")
}

pub fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tunnel-mcp-fixture"))
}

pub fn stdio_export(profile: &str, workspace: &Path, max_children: usize) -> McpExport {
    stdio_export_with(profile, workspace, max_children, &fixture_binary(), "")
}

/// A stdio export with an explicit command (for example a wrapper script)
/// and extra `[backend]` lines.
pub fn stdio_export_with(
    profile: &str,
    workspace: &Path,
    max_children: usize,
    command: &Path,
    extra_backend: &str,
) -> McpExport {
    let text = format!(
        "profile = \"{profile}\"\n[backend]\nkind = \"stdio\"\ncommand = \"{}\"\nargs = [\"stdio\"]\nworkspace = \"{}\"\nmax_children = {max_children}\n{extra_backend}[limits]\nrequest_body_bytes = 65536\njson_response_bytes = 1048576\nsse_response_bytes = 4194304\n",
        command.display(),
        workspace.display(),
    );
    let config: McpExportConfig = toml_config(&text);
    McpExport::from_config(&config).expect("valid stdio export")
}

pub fn http_export(profile: &str, url: &str, token_file: Option<&Path>) -> McpExport {
    let mut text = format!(
        "profile = \"{profile}\"\n[backend]\nkind = \"streamable-http\"\nurl = \"{url}\"\n"
    );
    if let Some(path) = token_file {
        text.push_str(&format!("bearer_token_file = \"{}\"\n", path.display()));
    }
    text.push_str("[limits]\nrequest_body_bytes = 65536\njson_response_bytes = 1048576\nsse_response_bytes = 4194304\n");
    McpExport::from_config(&toml_config(&text)).expect("valid http export")
}

fn toml_config(text: &str) -> McpExportConfig {
    toml::from_str(text).expect("export config")
}

/// Forward one request through the in-process bridge to `export`.
pub async fn exchange<B>(export: &McpExport, request: Request<B>) -> Response<ChannelBody>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
{
    let profile = Arc::new(export.profile_policies().expect("profile"));
    exchange_with_profile(export, profile, request).await
}

pub async fn exchange_with_profile<B>(
    export: &McpExport,
    profile: Arc<Profile>,
    request: Request<B>,
) -> Response<ChannelBody>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
{
    let (to_device, from_owner, _) = channel(1 << 17);
    let (to_owner, from_device, _) = channel(1 << 17);
    let device_export = export.clone();
    tokio::spawn(serve(
        Arc::clone(&profile),
        BridgeConfig::default(),
        from_owner,
        to_owner,
        move |request: Request<ChannelBody>| async move { device_export.handle(request).await },
    ));
    let (response, _handle) = forward(
        request,
        profile,
        BridgeConfig::default(),
        to_device,
        from_device,
    )
    .await;
    response
}

pub struct Gateway {
    pub socket: PathBuf,
    shutdown: CancellationToken,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Serve the bridge on a Unix socket in `dir`.
pub fn gateway(export: McpExport, dir: &Path) -> Gateway {
    let socket = dir.join("gateway.sock");
    let listener = UnixListener::bind(&socket).expect("bind unix socket");
    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    let profile = Arc::new(export.profile_policies().expect("profile"));
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = stop.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else { return };
            let export = export.clone();
            let profile = Arc::clone(&profile);
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let export = export.clone();
                    let profile = Arc::clone(&profile);
                    async move {
                        Ok::<_, Infallible>(exchange_with_profile(&export, profile, request).await)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Gateway { socket, shutdown }
}

/// An rmcp client that records progress notifications.
#[derive(Clone, Debug, Default)]
pub struct RecordingClient {
    pub progress: Arc<Mutex<Vec<f64>>>,
    pub protocol: Option<ProtocolVersion>,
}

impl ClientHandler for RecordingClient {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        let mut info = rmcp::model::ClientConfig::default();
        if let Some(protocol) = &self.protocol {
            info = info.with_protocol_version(protocol.clone());
        }
        info
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.progress
            .lock()
            .expect("progress lock")
            .push(params.progress);
    }
}

pub async fn connect(
    gateway: &Gateway,
    legacy: bool,
) -> (RunningService<RoleClient, RecordingClient>, RecordingClient) {
    let http = UnixSocketHttpClient::new(gateway.socket.to_str().expect("utf-8 path"), URI);
    let transport = StreamableHttpClientTransport::with_client(
        http,
        StreamableHttpClientTransportConfig::with_uri(URI),
    );
    let (handler, lifecycle) = if legacy {
        (
            RecordingClient {
                protocol: Some(ProtocolVersion::V_2025_11_25),
                ..RecordingClient::default()
            },
            ClientLifecycleMode::Initialize,
        )
    } else {
        (
            RecordingClient::default(),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
    };
    let running = within(handler.clone().serve_with_lifecycle(transport, lifecycle))
        .await
        .expect("client lifecycle");
    (running, handler)
}

/// Serve the fixture with the official rmcp Streamable HTTP server on a
/// loopback port.  Returns the URL.
pub async fn rmcp_http_backend(
    legacy_sessions: bool,
    marker_dir: &Path,
) -> (String, CancellationToken) {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let shutdown = CancellationToken::new();
    let server = tunnel_mcp_fixture::FixtureServer::new(Some(marker_dir.to_owned()));
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(legacy_sessions)
        .with_sse_keep_alive(Some(Duration::from_millis(200)))
        .with_cancellation_token(shutdown.child_token());
    let service: StreamableHttpService<tunnel_mcp_fixture::FixtureServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(LocalSessionManager::default()),
            config,
        );
    let stop = shutdown.clone();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = stop.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else { return };
            let service = hyper_util::service::TowerToHyperService::new(service.clone());
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{address}/mcp"), shutdown)
}

pub async fn body_bytes(response: Response<ChannelBody>) -> Result<Bytes, ()> {
    within(response.into_body().collect())
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|_| ())
}

pub async fn wait_for_file(path: &Path) -> bool {
    for _ in 0..600 {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

pub fn count_lines(path: &Path, needle: &str) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == needle)
        .count()
}
