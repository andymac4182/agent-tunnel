//! Operator configuration of one MCP export, embedded in the device runtime
//! configuration as `[exports.<service>.mcp]`.
//!
//! ```toml
//! [exports.00000000-0000-4000-8000-000000000001]
//! type = "http-forward"
//!
//! [exports.00000000-0000-4000-8000-000000000001.mcp]
//! profile = "mcp-2026-07-28"
//!
//! [exports.00000000-0000-4000-8000-000000000001.mcp.backend]
//! kind = "stdio"
//! command = "/opt/mcp/bin/server"
//! args = ["--read-only"]
//! workspace = "/srv/mcp-workspace"
//! inherit_env = ["LANG"]
//! env = { SERVER_MODE = "synthetic" }
//! ```
//!
//! A Streamable HTTP backend is a fixed loopback IP literal URL:
//!
//! ```toml
//! [exports.<service>.mcp.backend]
//! kind = "streamable-http"
//! url = "http://127.0.0.1:8931/mcp"
//! bearer_token_file = "/etc/agent-tunnel/mcp-backend.token"
//! ```
//!
//! Nothing here is selectable by a consumer: the relay's OPEN names only the
//! export, and every executable, argument, environment value, working
//! directory, address and credential comes from this file.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tunnel_mcp::{McpLimits, McpProfile};

/// The most arguments a stdio command may have.
pub const MAX_ARGS: usize = 64;
/// The longest argument or environment value, in bytes.
pub const MAX_ARG_LEN: usize = 4096;
/// The most explicit plus inherited environment variables.
pub const MAX_ENV: usize = 64;
/// The default and maximum concurrent child processes of one stdio export.
pub const DEFAULT_MAX_CHILDREN: usize = 8;
pub const MAX_CHILDREN: usize = 64;

/// One MCP export.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpExportConfig {
    /// `mcp-2026-07-28` or `mcp-2025-11-25`.
    pub profile: String,
    pub backend: McpBackendConfig,
    #[serde(default)]
    pub limits: McpLimitsConfig,
}

/// Where the export's MCP server lives.  `Debug` prints no argument or
/// environment values, which may carry operator secrets.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum McpBackendConfig {
    /// A supervised child process speaking MCP over stdio.
    #[serde(rename = "stdio")]
    Stdio {
        /// Absolute path of the executable.  It is executed directly, never
        /// through a shell.
        command: PathBuf,
        #[serde(default)]
        args: Vec<String>,
        /// Explicit environment values.  The child environment is cleared
        /// first.
        #[serde(default)]
        env: BTreeMap<String, String>,
        /// Names copied from the connector's own environment when set.
        #[serde(default)]
        inherit_env: Vec<String>,
        /// Absolute working directory.
        workspace: PathBuf,
        /// Concurrent child processes (per-request children for the 2026
        /// profile, sessions for the 2025 profile).
        #[serde(default = "default_max_children")]
        max_children: usize,
        /// Legacy (2025-11-25) session idle deadline in seconds (default
        /// 600, 1..=86400).  Ignored by the 2026 profile.
        #[serde(default = "default_session_idle_seconds")]
        session_idle_seconds: u64,
    },
    /// A fixed local Streamable HTTP server.
    #[serde(rename = "streamable-http")]
    StreamableHttp {
        /// `http://<loopback IP literal>:<port><path>`.
        url: String,
        /// Absolute path of a file holding a bearer token inserted as the
        /// backend `Authorization` header.
        #[serde(default)]
        bearer_token_file: Option<PathBuf>,
        /// How long the device remembers which principal a backend-issued
        /// legacy (2025-11-25) session belongs to after that session's last
        /// use (default 600, 1..=86400).  The backend owns the session; this
        /// bounds the device's own table, so a client that vanishes without
        /// a DELETE cannot hold a slot for ever.  Ignored by the 2026
        /// profile, which has no sessions.
        #[serde(default = "default_session_idle_seconds")]
        session_idle_seconds: u64,
    },
}

impl std::fmt::Debug for McpBackendConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdio {
                args,
                env,
                inherit_env,
                max_children,
                ..
            } => formatter
                .debug_struct("Stdio")
                .field("args", &args.len())
                .field("env_names", &env.keys().collect::<Vec<_>>())
                .field("inherit_env", inherit_env)
                .field("max_children", max_children)
                .finish_non_exhaustive(),
            Self::StreamableHttp {
                bearer_token_file,
                session_idle_seconds,
                ..
            } => formatter
                .debug_struct("StreamableHttp")
                .field("credential", &bearer_token_file.is_some())
                .field("session_idle_seconds", session_idle_seconds)
                .finish_non_exhaustive(),
        }
    }
}

/// The default legacy session idle deadline (10 minutes).
pub const DEFAULT_SESSION_IDLE_SECONDS: u64 = 600;
/// The ceiling on the legacy session idle deadline (24 hours).
pub const MAX_SESSION_IDLE_SECONDS: u64 = 86_400;

const fn default_session_idle_seconds() -> u64 {
    DEFAULT_SESSION_IDLE_SECONDS
}

const fn default_max_children() -> usize {
    DEFAULT_MAX_CHILDREN
}

/// Optional overrides of the profile's finite body limits.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpLimitsConfig {
    pub request_body_bytes: Option<u64>,
    pub json_response_bytes: Option<u64>,
    pub sse_response_bytes: Option<u64>,
}

/// A rejected MCP export configuration.  Messages are fixed strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpConfigError(pub &'static str);

impl std::fmt::Display for McpConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for McpConfigError {}

impl std::fmt::Debug for StdioBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StdioBackend")
            .field("args", &self.args.len())
            .field("env_names", &self.env.keys().collect::<Vec<_>>())
            .field("max_children", &self.max_children)
            .finish_non_exhaustive()
    }
}

/// A validated stdio backend.  `Debug` prints no argument or environment
/// values.
#[derive(Clone, Eq, PartialEq)]
pub struct StdioBackend {
    pub command: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub inherit_env: Vec<String>,
    pub workspace: PathBuf,
    pub max_children: usize,
    pub session_idle: std::time::Duration,
}

/// A validated fixed HTTP backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpBackend {
    pub address: SocketAddr,
    /// The `Host` value sent to the backend.
    pub authority: String,
    /// The backend's MCP endpoint path.
    pub path: String,
    pub bearer_token_file: Option<PathBuf>,
    /// How long a backend-issued legacy session's principal binding is
    /// remembered after its last use.
    pub session_idle: std::time::Duration,
}

/// A validated export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatedBackend {
    Stdio(StdioBackend),
    Http(HttpBackend),
}

/// A validated export configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedExport {
    pub profile: McpProfile,
    pub limits: McpLimits,
    pub backend: ValidatedBackend,
}

fn env_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn text_ok(value: &str) -> bool {
    value.len() <= MAX_ARG_LEN && !value.contains('\0')
}

fn absolute(path: &Path) -> bool {
    path.is_absolute() && !path.as_os_str().is_empty() && path.to_str().is_some_and(text_ok)
}

impl McpExportConfig {
    /// Validate the configuration without touching the filesystem.
    ///
    /// # Errors
    /// The first violated rule.
    pub fn validate(&self) -> Result<ValidatedExport, McpConfigError> {
        let profile = McpProfile::parse_id(&self.profile).ok_or(McpConfigError(
            "mcp.profile must be mcp-2026-07-28 or mcp-2025-11-25",
        ))?;
        let defaults = McpLimits::default();
        let limits = McpLimits::new(
            self.limits
                .request_body_bytes
                .unwrap_or(defaults.request_body()),
            self.limits
                .json_response_bytes
                .unwrap_or(defaults.json_response_body()),
            self.limits
                .sse_response_bytes
                .unwrap_or(defaults.sse_response_body()),
        )
        .map_err(|_| {
            McpConfigError(
                "mcp.limits must be non-zero, within their ceilings, with json_response_bytes <= sse_response_bytes",
            )
        })?;
        let backend = match &self.backend {
            McpBackendConfig::Stdio {
                command,
                args,
                env,
                inherit_env,
                workspace,
                max_children,
                session_idle_seconds,
            } => {
                if !absolute(command) {
                    return Err(McpConfigError(
                        "mcp.backend.command must be an absolute path",
                    ));
                }
                if !absolute(workspace) {
                    return Err(McpConfigError(
                        "mcp.backend.workspace must be an absolute path",
                    ));
                }
                if args.len() > MAX_ARGS || !args.iter().all(|arg| text_ok(arg)) {
                    return Err(McpConfigError(
                        "mcp.backend.args must be at most 64 values of at most 4096 bytes without NUL",
                    ));
                }
                if env.len() + inherit_env.len() > MAX_ENV
                    || !env
                        .iter()
                        .all(|(name, value)| env_name_ok(name) && text_ok(value))
                    || !inherit_env.iter().all(|name| env_name_ok(name))
                    || inherit_env.iter().any(|name| env.contains_key(name))
                {
                    return Err(McpConfigError(
                        "mcp.backend environment names must be distinct uppercase identifiers (at most 64) with values without NUL",
                    ));
                }
                if *session_idle_seconds == 0 || *session_idle_seconds > MAX_SESSION_IDLE_SECONDS {
                    return Err(McpConfigError(
                        "mcp.backend.session_idle_seconds must be between 1 and 86400",
                    ));
                }
                if *max_children == 0 || *max_children > MAX_CHILDREN {
                    return Err(McpConfigError(
                        "mcp.backend.max_children must be between 1 and 64",
                    ));
                }
                ValidatedBackend::Stdio(StdioBackend {
                    command: command.clone(),
                    args: args.clone(),
                    env: env.clone(),
                    inherit_env: inherit_env.clone(),
                    workspace: workspace.clone(),
                    max_children: *max_children,
                    session_idle: std::time::Duration::from_secs(*session_idle_seconds),
                })
            }
            McpBackendConfig::StreamableHttp {
                url,
                bearer_token_file,
                session_idle_seconds,
            } => {
                let backend = parse_backend_url(url)?;
                if let Some(path) = bearer_token_file
                    && !absolute(path)
                {
                    return Err(McpConfigError(
                        "mcp.backend.bearer_token_file must be an absolute path",
                    ));
                }
                if *session_idle_seconds == 0 || *session_idle_seconds > MAX_SESSION_IDLE_SECONDS {
                    return Err(McpConfigError(
                        "mcp.backend.session_idle_seconds must be between 1 and 86400",
                    ));
                }
                ValidatedBackend::Http(HttpBackend {
                    bearer_token_file: bearer_token_file.clone(),
                    session_idle: std::time::Duration::from_secs(*session_idle_seconds),
                    ..backend
                })
            }
        };
        Ok(ValidatedExport {
            profile,
            limits,
            backend,
        })
    }
}

fn parse_backend_url(text: &str) -> Result<HttpBackend, McpConfigError> {
    const RULE: &str = "mcp.backend.url must be http://<loopback IP literal>:<port>/<canonical path> without credentials, query or fragment";
    let url = url::Url::parse(text).map_err(|_| McpConfigError(RULE))?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(McpConfigError(RULE));
    }
    let ip: IpAddr = match url.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        _ => return Err(McpConfigError(RULE)),
    };
    if !ip.is_loopback() {
        return Err(McpConfigError(RULE));
    }
    let port = url.port_or_known_default().ok_or(McpConfigError(RULE))?;
    let path = url.path();
    if tunnel_http_bridge_path_ok(path).is_err() {
        return Err(McpConfigError(RULE));
    }
    let authority = match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };
    Ok(HttpBackend {
        address: SocketAddr::new(ip, port),
        authority,
        path: path.to_owned(),
        bearer_token_file: None,
        // Replaced by the validated configuration value; the URL parser has
        // no opinion about it.
        session_idle: std::time::Duration::from_secs(DEFAULT_SESSION_IDLE_SECONDS),
    })
}

fn tunnel_http_bridge_path_ok(path: &str) -> Result<(), ()> {
    // The codec's canonical export-path rule, plus: the backend endpoint is
    // never the bare root.
    if path == "/" {
        return Err(());
    }
    tunnel_http_forward::validate_path(path).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse with every quoted absolute Unix path made absolute on this host:
    /// `"/opt/x"` becomes `"C:/opt/x"` on Windows, where `/opt/x` has no drive
    /// and is rightly refused as not absolute.
    fn parse(text: &str) -> Result<ValidatedExport, String> {
        let text = if cfg!(windows) {
            text.replace("\"/", "\"C:/")
        } else {
            text.to_owned()
        };
        let config: McpExportConfig = toml::from_str(&text).map_err(|error| error.to_string())?;
        config.validate().map_err(|error| error.to_string())
    }

    const STDIO: &str = r#"
profile = "mcp-2026-07-28"
[backend]
kind = "stdio"
command = "/opt/mcp/server"
args = ["--mode", "synthetic"]
workspace = "/srv/ws"
inherit_env = ["LANG"]
env = { SERVER_MODE = "synthetic" }
"#;

    #[test]
    fn valid_stdio_and_http_exports_parse() {
        let stdio = parse(STDIO).unwrap();
        assert_eq!(stdio.profile, McpProfile::V2026_07_28);
        let ValidatedBackend::Stdio(backend) = stdio.backend else {
            panic!("stdio");
        };
        assert_eq!(backend.max_children, DEFAULT_MAX_CHILDREN);
        let http = parse(
            r#"
profile = "mcp-2025-11-25"
[backend]
kind = "streamable-http"
url = "http://127.0.0.1:8931/v1/mcp"
bearer_token_file = "/etc/token"
[limits]
request_body_bytes = 4096
"#,
        )
        .unwrap();
        assert_eq!(http.profile, McpProfile::V2025_11_25);
        assert_eq!(http.limits.request_body(), 4096);
        let ValidatedBackend::Http(backend) = http.backend else {
            panic!("http");
        };
        assert_eq!(backend.authority, "127.0.0.1:8931");
        assert_eq!(backend.path, "/v1/mcp");
        // The session table's idle deadline defaults like the stdio one.
        assert_eq!(
            backend.session_idle,
            std::time::Duration::from_secs(DEFAULT_SESSION_IDLE_SECONDS)
        );
        let explicit = parse(
            r#"
profile = "mcp-2025-11-25"
[backend]
kind = "streamable-http"
url = "http://127.0.0.1:8931/v1/mcp"
session_idle_seconds = 30
"#,
        )
        .unwrap();
        let ValidatedBackend::Http(backend) = explicit.backend else {
            panic!("http");
        };
        assert_eq!(backend.session_idle, std::time::Duration::from_secs(30));
        let v6 = parse(
            r#"
profile = "mcp-2026-07-28"
[backend]
kind = "streamable-http"
url = "http://[::1]:9/mcp"
"#,
        )
        .unwrap();
        let ValidatedBackend::Http(backend) = v6.backend else {
            panic!("http");
        };
        assert_eq!(backend.authority, "[::1]:9");
    }

    #[test]
    fn invalid_exports_are_rejected() {
        let http = |url: &str| {
            format!(
                "profile = \"mcp-2026-07-28\"\n[backend]\nkind = \"streamable-http\"\nurl = \"{url}\"\n"
            )
        };
        for url in [
            "https://127.0.0.1:1/mcp",
            "http://localhost:1/mcp",
            "http://10.0.0.1:1/mcp",
            "http://0.0.0.0:1/mcp",
            "http://example.invalid:1/mcp",
            "http://user:pw@127.0.0.1:1/mcp",
            "http://127.0.0.1:1/mcp?x=1",
            "http://127.0.0.1:1/mcp#f",
            "http://127.0.0.1:1/",
            "http://127.0.0.1:1/a//b",
            "http://127.0.0.1:1/a/%41",
            "unix:///tmp/socket",
        ] {
            assert!(parse(&http(url)).is_err(), "{url}");
        }
        for seconds in ["0", "86401"] {
            let text = format!(
                "profile = \"mcp-2025-11-25\"\n[backend]\nkind = \"streamable-http\"\nurl = \"http://127.0.0.1:1/mcp\"\nsession_idle_seconds = {seconds}\n"
            );
            assert!(parse(&text).is_err(), "{seconds}");
        }
        let replace = |from: &str, to: &str| STDIO.replace(from, to);
        for text in [
            replace("mcp-2026-07-28", "mcp-2025-06-18"),
            replace("/opt/mcp/server", "server"),
            replace("/opt/mcp/server", "sh -c 'x'"),
            replace("/srv/ws", "relative/ws"),
            replace("SERVER_MODE", "server_mode"),
            replace("\"LANG\"", "\"SERVER_MODE\""),
            replace("kind = \"stdio\"", "kind = \"shell\""),
            format!("{STDIO}max_children = 0\n"),
            format!("{STDIO}max_children = 65\n"),
            format!("{STDIO}session_idle_seconds = 0\n"),
            format!("{STDIO}session_idle_seconds = 86401\n"),
            format!("{STDIO}shell = true\n"),
            STDIO.replace(
                "profile = \"mcp-2026-07-28\"",
                "profile = \"mcp-2026-07-28\"\nunknown = 1",
            ),
            format!("{STDIO}[limits]\njson_response_bytes = 99999999999\n"),
        ] {
            assert!(parse(&text).is_err(), "{text}");
        }
    }
}
