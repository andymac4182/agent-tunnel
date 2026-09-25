//! `tunnel-test-harness mcp-demo-client`: the MCP demo's cloud-side client
//! (docs/demo/mcp.md).
//!
//! It is the pinned official Rust MCP SDK (rmcp 3.4.0) talking to a relay's
//! public MCP route, exactly as a hosted agent would: HTTPS to the consumer
//! listener with a bearer token, nothing else.  rmcp has no TLS client
//! without `reqwest`, which the workspace does not pin, so a byte-copying TLS
//! sidecar on a private Unix socket carries rmcp's own Unix-socket HTTP
//! client to the relay (the same arrangement as `verify-m3-mcp-cloud-client`).
//!
//! Before any MCP traffic it performs the discovery a standard MCP client
//! performs on its first `401` (task row M3-11): it reads the
//! `WWW-Authenticate` challenge, follows its `resource_metadata` URL, and
//! prints the protected-resource metadata.  The token is read from the
//! `AGENTUPLINK_TOKEN` environment variable and is never printed.
//!
//! Every line it prints starts with `mcp-demo:` and carries identifiers,
//! counts and synthetic fixture values only.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rmcp::{
    ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient,
    model::{
        CallToolRequestParams, ClientConfig, ContentBlock, GetPromptRequestParams,
        ProgressNotificationParam, ProtocolVersion, ReadResourceRequestParams, ResourceContents,
        ResourceUpdatedNotificationParam, SubscribeRequestParams, SubscriptionFilter,
    },
    service::NotificationContext,
    transport::{
        StreamableHttpClientTransport, UnixSocketHttpClient,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::{HarnessError, Result};

/// The bound on every single step.
const STEP: Duration = Duration::from_secs(30);
/// The environment variable holding the consumer's bearer token.
pub const TOKEN_ENV: &str = "AGENTUPLINK_TOKEN";

/// Parsed `mcp-demo-client` arguments.
#[derive(Debug)]
pub struct DemoArgs {
    /// `https://host:port/v1/devices/<device>/services/<service>/http/mcp`.
    pub url: String,
    /// PEM file of the CA that issued the relay's consumer certificate.
    pub ca: PathBuf,
    /// `2025-11-25` (default) or `2026-07-28`.
    pub profile: String,
}

impl DemoArgs {
    /// Parse `--url URL --ca PEM [--profile P]`.
    ///
    /// # Errors
    /// A missing or unknown flag, or an unknown profile.
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut url = None;
        let mut ca = None;
        let mut profile = "2025-11-25".to_owned();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            let value = iter
                .next()
                .ok_or_else(|| HarnessError::InvalidInput(format!("{flag} needs a value")))?;
            match flag.as_str() {
                "--url" => url = Some(value.clone()),
                "--ca" => ca = Some(PathBuf::from(value)),
                "--profile" => profile.clone_from(value),
                _ => {
                    return Err(HarnessError::InvalidInput(format!(
                        "mcp-demo-client: unknown flag {flag}"
                    )));
                }
            }
        }
        if profile != "2025-11-25" && profile != "2026-07-28" {
            return Err(HarnessError::InvalidInput(
                "mcp-demo-client: --profile is 2025-11-25 or 2026-07-28".into(),
            ));
        }
        Ok(Self {
            url: url.ok_or_else(|| HarnessError::InvalidInput("--url is required".into()))?,
            ca: ca.ok_or_else(|| HarnessError::InvalidInput("--ca is required".into()))?,
            profile,
        })
    }
}

/// `https://host:port/path` split into its parts.
struct Target {
    host: String,
    port: u16,
    path: String,
}

fn split_url(url: &str) -> Result<Target> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| HarnessError::InvalidInput("--url must be https://".into()))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_owned(),
            port.parse()
                .map_err(|_| HarnessError::InvalidInput("--url port".into()))?,
        ),
        None => (authority.to_owned(), 443),
    };
    Ok(Target {
        host,
        port,
        path: format!("/{path}"),
    })
}

fn tls_connector(ca: &Path) -> Result<TlsConnector> {
    let pem = std::fs::read(ca).map_err(HarnessError::Io)?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
        let certificate: CertificateDer<'static> = certificate.map_err(HarnessError::Io)?;
        roots
            .add(certificate)
            .map_err(|error| HarnessError::Http(format!("CA: {error}")))?;
    }
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .map_err(|error| HarnessError::Http(format!("TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// One HTTPS request with no MCP client involved: the discovery a client does
/// before it has a token.  Returns status, `WWW-Authenticate` and body.
async fn plain_request(
    connector: &TlsConnector,
    target: &Target,
    method: &str,
    path: &str,
) -> Result<(u16, Option<String>, Vec<u8>)> {
    let tcp = tokio::net::TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(HarnessError::Io)?;
    let name = ServerName::try_from(target.host.clone())
        .map_err(|_| HarnessError::InvalidInput("--url host".into()))?;
    let tls = connector
        .connect(name, tcp)
        .await
        .map_err(HarnessError::Io)?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|error| HarnessError::Http(error.to_string()))?;
    tokio::spawn(connection);
    let body = if method == "POST" {
        br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec()
    } else {
        Vec::new()
    };
    let mut builder = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("{}:{}", target.host, target.port));
    if method == "POST" {
        builder = builder
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|error| HarnessError::Http(error.to_string()))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| HarnessError::Http(error.to_string()))?;
    let status = response.status().as_u16();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|error| HarnessError::Http(error.to_string()))?
        .to_bytes()
        .to_vec();
    Ok((status, challenge, body))
}

/// The quoted value of `name="..."` in a `WWW-Authenticate` challenge.
fn challenge_param(challenge: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = challenge.find(&needle)? + needle.len();
    let end = challenge[start..].find('"')?;
    Some(challenge[start..start + end].to_owned())
}

/// A byte-copying TLS sidecar: rmcp's Unix-socket HTTP client in, TLS to the
/// relay out.
struct Sidecar {
    socket: PathBuf,
    shutdown: CancellationToken,
    _directory: tempfile::TempDir,
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl Sidecar {
    fn start(connector: TlsConnector, host: String, port: u16) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("mcpdemo")
            .tempdir()
            .map_err(HarnessError::Io)?;
        let socket = directory.path().join("s.sock");
        let listener = tokio::net::UnixListener::bind(&socket).map_err(HarnessError::Io)?;
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = stop.cancelled() => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((local, _)) = accepted else { return };
                let connector = connector.clone();
                let stop = stop.clone();
                let host = host.clone();
                tokio::spawn(async move {
                    let Ok(tcp) = tokio::net::TcpStream::connect((host.as_str(), port)).await
                    else {
                        return;
                    };
                    let Ok(name) = ServerName::try_from(host) else {
                        return;
                    };
                    let Ok(remote) = connector.connect(name, tcp).await else {
                        return;
                    };
                    let (mut local_read, mut local_write) = tokio::io::split(local);
                    let (mut remote_read, mut remote_write) = tokio::io::split(remote);
                    tokio::select! {
                        _ = tokio::io::copy(&mut local_read, &mut remote_write) => {}
                        _ = tokio::io::copy(&mut remote_read, &mut local_write) => {}
                        () = stop.cancelled() => {}
                    }
                });
            }
        });
        Ok(Self {
            socket,
            shutdown,
            _directory: directory,
        })
    }
}

/// What the demo client's handler saw arrive from the server.
#[derive(Default)]
struct Seen {
    progress: Mutex<Vec<f64>>,
    updated: Mutex<Vec<String>>,
    logs: Mutex<u64>,
    changed: tokio::sync::Notify,
}

#[derive(Clone)]
struct DemoHandler {
    seen: Arc<Seen>,
    protocol: ProtocolVersion,
}

impl ClientHandler for DemoHandler {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default().with_protocol_version(self.protocol.clone())
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        if let Ok(mut progress) = self.seen.progress.lock() {
            progress.push(params.progress);
        }
        self.seen.changed.notify_waiters();
    }

    async fn on_resource_updated(
        &self,
        params: ResourceUpdatedNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        if let Ok(mut updated) = self.seen.updated.lock() {
            updated.push(params.uri);
        }
        self.seen.changed.notify_waiters();
    }

    #[allow(deprecated)]
    async fn on_logging_message(
        &self,
        _params: rmcp::model::LoggingMessageNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        if let Ok(mut logs) = self.seen.logs.lock() {
            *logs += 1;
        }
        self.seen.changed.notify_waiters();
    }
}

impl Seen {
    async fn wait(&self, ready: impl Fn(&Self) -> bool) -> bool {
        timeout(STEP, async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if ready(self) {
                    return;
                }
                changed.await;
            }
        })
        .await
        .is_ok()
    }
}

fn step_error(step: &str, error: impl std::fmt::Display) -> HarnessError {
    HarnessError::Http(format!("mcp-demo: step={step} failed: {error}"))
}

async fn bounded<T, E: std::fmt::Display>(
    step: &str,
    future: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    timeout(STEP, future)
        .await
        .map_err(|_| step_error(step, "timed out"))?
        .map_err(|error| step_error(step, error))
}

fn text_of(content: &[ContentBlock]) -> String {
    content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect::<Vec<_>>()
        .join("")
}

/// Run the demo.  Prints one line per step and a final `mcp-demo: ok` line.
///
/// # Errors
/// Any step that fails, with the step named.
#[allow(clippy::too_many_lines)]
pub async fn run(args: DemoArgs) -> Result<()> {
    let token = std::env::var(TOKEN_ENV).map_err(|_| {
        HarnessError::InvalidInput(format!("{TOKEN_ENV} must hold the consumer's bearer token"))
    })?;
    let target = split_url(&args.url)?;
    let connector = tls_connector(&args.ca)?;

    // 1. Discovery, as a client does before it has a token (M3-11).
    let (status, challenge, _) = plain_request(&connector, &target, "POST", &target.path).await?;
    let challenge = challenge.ok_or_else(|| {
        step_error(
            "discovery",
            format!("unauthenticated POST answered {status} with no WWW-Authenticate"),
        )
    })?;
    println!("mcp-demo: step=unauthenticated status={status} challenge={challenge}");
    let metadata_url = challenge_param(&challenge, "resource_metadata")
        .ok_or_else(|| step_error("discovery", "challenge names no resource_metadata"))?;
    let metadata_target = split_url(&metadata_url)?;
    let (status, _, body) =
        plain_request(&connector, &metadata_target, "GET", &metadata_target.path).await?;
    let metadata: serde_json::Value =
        serde_json::from_slice(&body).map_err(|error| step_error("resource-metadata", error))?;
    if status != 200 || metadata["resource"] != serde_json::Value::String(args.url.clone()) {
        return Err(step_error(
            "resource-metadata",
            format!("status {status}, resource {}", metadata["resource"]),
        ));
    }
    println!(
        "mcp-demo: step=resource-metadata status=200 resource={} authorization_servers={} scopes_supported={}",
        metadata["resource"], metadata["authorization_servers"], metadata["scopes_supported"]
    );

    // 2. The real MCP client, with the token.
    let sidecar = Sidecar::start(connector, target.host.clone(), target.port)?;
    let socket = sidecar
        .socket
        .to_str()
        .ok_or_else(|| HarnessError::InvalidInput("sidecar socket path".into()))?
        .to_owned();
    let legacy = args.profile == "2025-11-25";
    let config = StreamableHttpClientTransportConfig::with_uri(args.url.clone()).auth_header(token);
    let transport = StreamableHttpClientTransport::with_client(
        UnixSocketHttpClient::new(&socket, &args.url),
        config,
    );
    let seen = Arc::new(Seen::default());
    let handler = DemoHandler {
        seen: Arc::clone(&seen),
        protocol: if legacy {
            ProtocolVersion::V_2025_11_25
        } else {
            ProtocolVersion::V_2026_07_28
        },
    };
    let lifecycle = if legacy {
        ClientLifecycleMode::Initialize
    } else {
        ClientLifecycleMode::Discover {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        }
    };
    let client = bounded(
        "initialize",
        handler.serve_with_lifecycle(transport, lifecycle),
    )
    .await?;
    let server = client
        .peer_info()
        .and_then(|info| info.server_info.as_ref().map(|server| server.name.clone()))
        .unwrap_or_default();
    println!(
        "mcp-demo: step={} ok profile={} server={server}",
        if legacy {
            "initialize"
        } else {
            "server/discover"
        },
        args.profile
    );

    let tools = bounded("tools/list", client.list_all_tools()).await?;
    let names: Vec<String> = tools.iter().map(|tool| tool.name.to_string()).collect();
    println!(
        "mcp-demo: step=tools/list count={} names={}",
        names.len(),
        names.join(",")
    );

    let mut arguments = serde_json::Map::new();
    arguments.insert("greeting".into(), "hello from the demo".into());
    let echoed = bounded(
        "tools/call echo",
        client.call_tool(CallToolRequestParams::new("echo").with_arguments(arguments)),
    )
    .await?;
    let images = echoed
        .content
        .iter()
        .filter(|block| block.as_image().is_some())
        .count();
    let echoed_text = text_of(&echoed.content);
    if !echoed_text.contains("hello from the demo") {
        return Err(step_error(
            "tools/call echo",
            "arguments did not round-trip",
        ));
    }
    println!("mcp-demo: step=tools/call name=echo text={echoed_text} images={images}");

    let resources = bounded("resources/list", client.list_all_resources()).await?;
    let uris: Vec<String> = resources
        .iter()
        .map(|resource| resource.uri.clone())
        .collect();
    println!(
        "mcp-demo: step=resources/list count={} uris={}",
        uris.len(),
        uris.join(",")
    );
    for uri in [
        tunnel_mcp_fixture::RESOURCE_TEXT_URI,
        tunnel_mcp_fixture::RESOURCE_BLOB_URI,
    ] {
        let read = bounded(
            "resources/read",
            client.read_resource(ReadResourceRequestParams::new(uri)),
        )
        .await?;
        for contents in &read.contents {
            match contents {
                ResourceContents::TextResourceContents { text, .. } => {
                    if text != tunnel_mcp_fixture::RESOURCE_TEXT {
                        return Err(step_error("resources/read", "text resource differs"));
                    }
                    println!("mcp-demo: step=resources/read uri={uri} text={text:?}");
                }
                ResourceContents::BlobResourceContents { blob, .. } => {
                    if blob != tunnel_mcp_fixture::IMAGE_PNG_BASE64 {
                        return Err(step_error("resources/read", "blob resource differs"));
                    }
                    println!(
                        "mcp-demo: step=resources/read uri={uri} blob_base64_bytes={}",
                        blob.len()
                    );
                }
                _ => return Err(step_error("resources/read", "unexpected content kind")),
            }
        }
    }

    let prompts = bounded("prompts/list", client.list_all_prompts()).await?;
    println!(
        "mcp-demo: step=prompts/list count={} names={}",
        prompts.len(),
        prompts
            .iter()
            .map(|prompt| prompt.name.clone())
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut prompt_arguments = serde_json::Map::new();
    prompt_arguments.insert("name".into(), "Ada".into());
    let prompt = bounded(
        "prompts/get",
        client.get_prompt(
            GetPromptRequestParams::new(tunnel_mcp_fixture::PROMPT_NAME)
                .with_arguments(prompt_arguments),
        ),
    )
    .await?;
    let rendered: Vec<String> = prompt
        .messages
        .iter()
        .filter_map(|message| message.content.as_text().map(|text| text.text.clone()))
        .collect();
    if rendered != [tunnel_mcp_fixture::prompt_text("Ada")] {
        return Err(step_error("prompts/get", "rendered prompt differs"));
    }
    println!("mcp-demo: step=prompts/get name=greet messages={rendered:?}");

    // Subscriptions: 2025-11-25 `resources/subscribe`, answered on the
    // session's standalone GET stream; 2026-07-28 `subscriptions/listen`,
    // answered on the listen request's own stream.
    let uri = tunnel_mcp_fixture::RESOURCE_TEXT_URI;
    if legacy {
        #[allow(deprecated)]
        bounded(
            "resources/subscribe",
            client.subscribe(SubscribeRequestParams::new(uri)),
        )
        .await?;
        let mut touch = serde_json::Map::new();
        touch.insert("uri".into(), uri.into());
        let touched = bounded(
            "tools/call touch",
            client.call_tool(CallToolRequestParams::new("touch").with_arguments(touch)),
        )
        .await?;
        let arrived = seen
            .wait(|seen| {
                seen.updated
                    .lock()
                    .is_ok_and(|updated| updated.iter().any(|value| value == uri))
            })
            .await;
        if !arrived {
            return Err(step_error(
                "resources/subscribe",
                "no notifications/resources/updated arrived",
            ));
        }
        println!(
            "mcp-demo: step=resources/subscribe uri={uri} touch={:?} notifications/resources/updated=received",
            text_of(&touched.content)
        );
    } else {
        let mut subscription = bounded(
            "subscriptions/listen",
            client.listen(
                SubscriptionFilter::builder()
                    .resource_subscription(uri)
                    .build(),
            ),
        )
        .await?;
        let notification = bounded("subscriptions/listen next", subscription.next()).await?;
        let received = matches!(
            notification,
            Some(rmcp::model::ServerNotification::ResourceUpdatedNotification(ref updated))
                if updated.params.uri == uri
        );
        if !received {
            return Err(step_error(
                "subscriptions/listen",
                "no notifications/resources/updated arrived",
            ));
        }
        println!(
            "mcp-demo: step=subscriptions/listen uri={uri} notifications/resources/updated=received"
        );
    }

    let mut progress = serde_json::Map::new();
    progress.insert("steps".into(), 3.into());
    bounded(
        "tools/call progress",
        client.call_tool(CallToolRequestParams::new("progress").with_arguments(progress)),
    )
    .await?;
    let mut log = serde_json::Map::new();
    log.insert("label".into(), "demo".into());
    log.insert("count".into(), 2.into());
    bounded(
        "tools/call log",
        client.call_tool(CallToolRequestParams::new("log").with_arguments(log)),
    )
    .await?;
    let logs_arrived = seen
        .wait(|seen| seen.logs.lock().is_ok_and(|logs| *logs >= 2))
        .await;
    println!(
        "mcp-demo: step=notifications logs_received={} progress_received={}",
        seen.logs.lock().map_or(0, |logs| *logs),
        seen.progress.lock().map_or(0, |progress| progress.len())
    );
    if !logs_arrived {
        return Err(step_error(
            "notifications",
            "log notifications did not arrive",
        ));
    }

    bounded("close", async {
        client
            .cancel()
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    })
    .await?;
    drop(sidecar);
    println!(
        "mcp-demo: ok profile={} tools={} resources={} prompts={}",
        args.profile,
        names.len(),
        uris.len(),
        prompts.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_parameters_are_read_from_quoted_values() {
        let challenge = r#"Bearer resource_metadata="https://relay.test/.well-known/oauth-protected-resource/v1/x", scope="http:invoke""#;
        assert_eq!(
            challenge_param(challenge, "resource_metadata").as_deref(),
            Some("https://relay.test/.well-known/oauth-protected-resource/v1/x")
        );
        assert_eq!(
            challenge_param(challenge, "scope").as_deref(),
            Some("http:invoke")
        );
        assert_eq!(challenge_param(challenge, "error"), None);
    }

    #[test]
    fn urls_split_into_host_port_and_path() {
        let target = split_url("https://localhost:8443/v1/devices/a/services/b/http/mcp")
            .expect("valid URL");
        assert_eq!(target.host, "localhost");
        assert_eq!(target.port, 8443);
        assert_eq!(target.path, "/v1/devices/a/services/b/http/mcp");
        assert!(split_url("http://localhost/").is_err());
    }
}
