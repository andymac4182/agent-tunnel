//! Configuration owned by the runnable M1 client.
//!
//! `tunnel_core::ClientConfig` is retained for the bootstrap `check-config`
//! compatibility command.  A live connector uses [`RuntimeConfig`] instead:
//! it contains the endpoint and credential references that are required to
//! establish both mutually authenticated WebSockets.  The validated rotation
//! policy is carried for the pending M2 runtime integration; this module does
//! not itself schedule or perform data-socket handover.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
};
use tunnel_core::{ConfigError as CoreConfigError, RotationConfig};
use url::Url;

const MAX_DEVICE_ID_LEN: usize = 128;
const MAX_EXPORT_NAME_LEN: usize = 128;
const DEFAULT_MAX_STREAMS: usize = 64;
const DEFAULT_QUEUE_FRAMES: usize = 128;
const DEFAULT_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_GRANT_TIMEOUT_MS: u64 = 5_000;
const MAX_GRANT_TIMEOUT_MS: u64 = 5_000;

/// Runtime configuration for one foreground connector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeConfig {
    /// Stable local device/connector label.  The relay binds its authoritative
    /// identity to the client certificate, not this label.
    pub device_id: String,
    /// Relay device WebSocket endpoint.  M1 accepts only `wss://` URLs.
    pub relay_url: String,
    /// Local client certificate and private key plus the relay trust bundle.
    pub credentials: CredentialConfig,
    /// Named local exports.  M1 supports the synthetic `echo` export only.
    pub exports: BTreeMap<String, ExportConfig>,
    /// Hard local resource limits.
    pub limits: LimitsConfig,
    /// Validated M2 data-socket rotation policy.  The connector runtime does
    /// not consume this policy until rotation is integrated.
    pub rotation: RotationConfig,
}

impl<'de> Deserialize<'de> for RuntimeConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawRuntimeConfig::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

impl RuntimeConfig {
    /// Parse and validate TOML without touching the filesystem.
    pub fn parse(input: &str) -> Result<Self, RuntimeConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    /// Load and validate a runtime configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let input = fs::read_to_string(path)?;
        Self::parse(&input)
    }

    /// Validate the semantic configuration contract.
    pub fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.device_id.is_empty()
            || self.device_id.len() > MAX_DEVICE_ID_LEN
            || !self
                .device_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(RuntimeConfigError::Invalid(
                "device_id must contain 1 to 128 ASCII letters, digits, dots, hyphens, or underscores",
            ));
        }

        let url = Url::parse(&self.relay_url)
            .map_err(|_| RuntimeConfigError::Invalid("relay_url must be a valid URL"))?;
        if url.scheme() != "wss" {
            return Err(RuntimeConfigError::Invalid(
                "relay_url must use wss://; insecure WebSockets are not supported",
            ));
        }
        if url.host_str().is_none() {
            return Err(RuntimeConfigError::Invalid(
                "relay_url must contain a DNS host",
            ));
        }
        if url.username() != "" || url.password().is_some() {
            return Err(RuntimeConfigError::Invalid(
                "relay_url must not contain credentials",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(RuntimeConfigError::Invalid(
                "relay_url must not contain a query or fragment",
            ));
        }
        if !url.path().ends_with("/control") {
            return Err(RuntimeConfigError::Invalid(
                "relay_url must be the explicit control endpoint ending in /control",
            ));
        }

        self.credentials.validate()?;
        self.limits.validate()?;
        self.rotation
            .validate()
            .map_err(RuntimeConfigError::Rotation)?;
        if self.exports.is_empty() {
            return Err(RuntimeConfigError::Invalid(
                "at least one local export must be configured",
            ));
        }
        for (name, export) in &self.exports {
            if name.is_empty()
                || name.len() > MAX_EXPORT_NAME_LEN
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(RuntimeConfigError::Invalid(
                    "export names must contain 1 to 128 ASCII letters, digits, dots, hyphens, or underscores",
                ));
            }
            if export.kind == ExportKind::HttpForward && export.device_canary.is_some() {
                return Err(RuntimeConfigError::Invalid(
                    "an http-forward export has no device_canary",
                ));
            }
            if let Some(mcp) = &export.mcp {
                if export.kind != ExportKind::HttpForward {
                    return Err(RuntimeConfigError::Invalid(
                        "an mcp table is only valid on an http-forward export",
                    ));
                }
                mcp.validate()
                    .map_err(|error| RuntimeConfigError::Invalid(error.0))?;
            }
            if let Some(canary) = &export.device_canary
                && canary.len() > 256
            {
                return Err(RuntimeConfigError::Invalid(
                    "echo device_canary must be at most 256 bytes",
                ));
            }
        }
        Ok(())
    }

    /// Resolve relative credential paths against the directory containing the
    /// configuration file.  Absolute paths are preserved.
    #[must_use]
    pub fn resolve_relative_to(&self, base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        let mut resolved = self.clone();
        resolved.credentials = self.credentials.resolve_relative_to(base);
        resolved
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        let mut exports = BTreeMap::new();
        exports.insert("echo".to_owned(), ExportConfig::default());
        Self {
            device_id: "my-device".to_owned(),
            relay_url: "wss://relay.example.invalid/v1/tunnel/control".to_owned(),
            credentials: CredentialConfig::default(),
            exports,
            limits: LimitsConfig::default(),
            rotation: RotationConfig::default(),
        }
    }
}

/// Paths used to construct the client TLS identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    #[serde(alias = "certificate", alias = "cert", alias = "client_cert")]
    pub client_certificate: PathBuf,
    #[serde(alias = "private_key", alias = "key", alias = "client_key")]
    pub client_key: PathBuf,
    #[serde(alias = "ca", alias = "server_ca")]
    pub server_ca: PathBuf,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            client_certificate: PathBuf::from("device-cert.pem"),
            client_key: PathBuf::from("device-key.pem"),
            server_ca: PathBuf::from("server-ca.pem"),
        }
    }
}

impl CredentialConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        for (label, path) in [
            ("client certificate", &self.client_certificate),
            ("client private key", &self.client_key),
            ("server CA", &self.server_ca),
        ] {
            if path.as_os_str().is_empty() {
                return Err(RuntimeConfigError::Invalid(match label {
                    "client certificate" => "client certificate path must not be empty",
                    "client private key" => "client private key path must not be empty",
                    _ => "server CA path must not be empty",
                }));
            }
        }
        if self.client_certificate == self.client_key || self.client_certificate == self.server_ca {
            return Err(RuntimeConfigError::Invalid(
                "credential paths must refer to separate files",
            ));
        }
        Ok(())
    }

    fn resolve_relative_to(&self, base: &Path) -> Self {
        let resolve = |path: &Path| {
            if path.is_absolute() {
                path.to_owned()
            } else {
                base.join(path)
            }
        };
        Self {
            client_certificate: resolve(&self.client_certificate),
            client_key: resolve(&self.client_key),
            server_ca: resolve(&self.server_ca),
        }
    }
}

/// The only local service exposed by M1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExportConfig {
    #[serde(rename = "type", alias = "kind")]
    pub kind: ExportKind,
    /// Optional synthetic response marker.  It is returned by the relay's
    /// test adapter and never treated as a credential or executable path.
    pub device_canary: Option<String>,
    /// An MCP export served by the connector itself (M3-02): only valid on
    /// an `http-forward` export.  See `tunnel_mcp_export::config`.
    pub mcp: Option<tunnel_mcp_export::McpExportConfig>,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            kind: ExportKind::Echo,
            device_canary: None,
            mcp: None,
        }
    }
}

/// Local export kind supported by the M1 client.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportKind {
    Echo,
    /// An `http-forward/1` export.  It is admitted only when an in-process
    /// handler is registered for the same service identifier; the M1 profile
    /// never admits it.
    #[serde(rename = "http-forward")]
    HttpForward,
}

/// Resource limits enforced before work enters a client queue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_streams: usize,
    pub max_queue_frames: usize,
    pub max_queue_bytes: usize,
    pub grant_timeout_ms: u64,
    pub operation_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_streams: DEFAULT_MAX_STREAMS,
            max_queue_frames: DEFAULT_QUEUE_FRAMES,
            max_queue_bytes: DEFAULT_QUEUE_BYTES,
            grant_timeout_ms: DEFAULT_GRANT_TIMEOUT_MS,
            operation_timeout_ms: 30_000,
        }
    }
}

impl LimitsConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.max_streams == 0 || self.max_streams > DEFAULT_MAX_STREAMS {
            return Err(RuntimeConfigError::Invalid(
                "limits.max_streams must be between 1 and 64",
            ));
        }
        if self.max_queue_frames == 0 || self.max_queue_frames > 1_024 {
            return Err(RuntimeConfigError::Invalid(
                "limits.max_queue_frames must be between 1 and 1024",
            ));
        }
        if self.max_queue_bytes < 256 * 1024 || self.max_queue_bytes > 8 * 1024 * 1024 {
            return Err(RuntimeConfigError::Invalid(
                "limits.max_queue_bytes must be between 262144 and 8388608",
            ));
        }
        if self.grant_timeout_ms == 0 || self.grant_timeout_ms > MAX_GRANT_TIMEOUT_MS {
            return Err(RuntimeConfigError::Invalid(
                "limits.grant_timeout_ms must be between 1 and 5000",
            ));
        }
        if self.operation_timeout_ms == 0 || self.operation_timeout_ms > 300_000 {
            return Err(RuntimeConfigError::Invalid(
                "limits.operation_timeout_ms must be between 1 and 300000",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeConfig {
    device_id: String,
    #[serde(default, alias = "endpoint", alias = "relay_endpoint")]
    relay_url: Option<String>,
    #[serde(default)]
    credentials: Option<RawCredentialConfig>,
    #[serde(
        default,
        alias = "client_certificate",
        alias = "certificate",
        alias = "cert"
    )]
    client_cert: Option<PathBuf>,
    #[serde(default, alias = "client_key", alias = "private_key", alias = "key")]
    private_key: Option<PathBuf>,
    #[serde(default, alias = "server_ca", alias = "ca")]
    trust_bundle: Option<PathBuf>,
    #[serde(default)]
    exports: Option<BTreeMap<String, ExportConfig>>,
    #[serde(default)]
    limits: LimitsConfig,
    #[serde(default)]
    rotation: RotationConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredentialConfig {
    #[serde(alias = "certificate", alias = "cert", alias = "client_cert")]
    client_certificate: Option<PathBuf>,
    #[serde(alias = "private_key", alias = "key", alias = "client_key")]
    client_key: Option<PathBuf>,
    #[serde(alias = "ca", alias = "server_ca")]
    server_ca: Option<PathBuf>,
}

impl TryFrom<RawRuntimeConfig> for RuntimeConfig {
    type Error = RuntimeConfigError;

    fn try_from(raw: RawRuntimeConfig) -> Result<Self, Self::Error> {
        let credentials = raw.credentials.unwrap_or(RawCredentialConfig {
            client_certificate: None,
            client_key: None,
            server_ca: None,
        });
        let choose_path =
            |flat: Option<PathBuf>, nested: Option<PathBuf>, label: &'static str| match (
                flat, nested,
            ) {
                (Some(flat), Some(nested)) if flat != nested => {
                    Err(RuntimeConfigError::Invalid(label))
                }
                (Some(flat), _) | (_, Some(flat)) => Ok(flat),
                (None, None) => Err(RuntimeConfigError::Invalid(label)),
            };
        let relay_url = raw
            .relay_url
            .ok_or(RuntimeConfigError::Invalid("relay_url is required"))?;
        let credentials = CredentialConfig {
            client_certificate: choose_path(
                raw.client_cert,
                credentials.client_certificate,
                "client certificate path is required",
            )?,
            client_key: choose_path(
                raw.private_key,
                credentials.client_key,
                "client private key path is required",
            )?,
            server_ca: choose_path(
                raw.trust_bundle,
                credentials.server_ca,
                "server CA path is required",
            )?,
        };
        let exports = raw.exports.unwrap_or_else(|| {
            let mut map = BTreeMap::new();
            map.insert("echo".to_owned(), ExportConfig::default());
            map
        });
        Ok(Self {
            device_id: raw.device_id,
            relay_url,
            credentials,
            exports,
            limits: raw.limits,
            rotation: raw.rotation,
        })
    }
}

/// Errors produced while parsing or validating a runtime configuration.
#[derive(Debug)]
pub enum RuntimeConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Rotation(CoreConfigError),
    Invalid(&'static str),
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "could not read runtime configuration: {error}"),
            Self::Parse(error) => write!(formatter, "invalid TOML configuration: {error}"),
            Self::Rotation(error) => write!(formatter, "invalid rotation policy: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl Error for RuntimeConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::Rotation(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl From<std::io::Error> for RuntimeConfigError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<toml::de::Error> for RuntimeConfigError {
    fn from(error: toml::de::Error) -> Self {
        Self::Parse(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_toml() -> &'static str {
        r#"
device_id = "fixture-one"
relay_url = "wss://relay.example.test/v1/tunnel/control"
client_cert = "client.pem"
private_key = "client-key.pem"
server_ca = "ca.pem"

[exports.echo]
type = "echo"
device_canary = "fixture-one"
"#
    }

    #[test]
    fn parses_flat_fixture_configuration() {
        let config = RuntimeConfig::parse(valid_toml()).expect("valid runtime configuration");
        assert_eq!(config.device_id, "fixture-one");
        assert_eq!(
            config.exports["echo"].device_canary.as_deref(),
            Some("fixture-one")
        );
    }

    #[test]
    fn parses_nested_credential_configuration() {
        let config = RuntimeConfig::parse(
            r#"
device_id = "fixture-one"
endpoint = "wss://relay.example.test/v1/tunnel/control"
[credentials]
certificate = "client.pem"
key = "client-key.pem"
ca = "ca.pem"
"#,
        )
        .expect("valid nested configuration");
        assert_eq!(
            config.credentials.client_certificate,
            PathBuf::from("client.pem")
        );
        assert!(config.exports.contains_key("echo"));
    }

    #[test]
    fn rejects_plaintext_urls_and_non_echo_exports() {
        for input in [
            valid_toml().replace("wss://", "ws://"),
            valid_toml().replace("type = \"echo\"", "type = \"mcp\""),
        ] {
            assert!(
                RuntimeConfig::parse(&input).is_err(),
                "accepted invalid input"
            );
        }
    }

    #[test]
    fn m1_configuration_uses_default_rotation_policy() {
        let config = RuntimeConfig::parse(valid_toml()).expect("valid runtime configuration");
        assert_eq!(config.rotation, RotationConfig::default());
    }

    #[test]
    fn accepts_partial_rotation_overrides() {
        let input = format!(
            "{}\n[rotation]\ninterval_seconds = 600\noverlap_seconds = 45",
            valid_toml()
        );
        let config = RuntimeConfig::parse(&input).expect("valid rotation override");
        assert_eq!(config.rotation.interval_seconds, 600);
        assert_eq!(config.rotation.handshake_timeout_seconds, 10);
        assert_eq!(config.rotation.overlap_seconds, 45);
    }

    #[test]
    fn rejects_invalid_rotation_timing() {
        for timing in [
            "interval_seconds = 0",
            "interval_seconds = 86401",
            "handshake_timeout_seconds = 0",
            "handshake_timeout_seconds = 301",
            "overlap_seconds = 0",
            "overlap_seconds = 3601",
            "handshake_timeout_seconds = 30",
            "interval_seconds = 30",
        ] {
            let input = format!("{}\n[rotation]\n{timing}", valid_toml());
            assert!(RuntimeConfig::parse(&input).is_err(), "accepted {timing}");
        }
        let input = format!("{}\n[rotation]\ninterval_seconds = 0", valid_toml());
        let error = RuntimeConfig::parse(&input).expect_err("invalid rotation interval");
        assert!(error.to_string().contains("rotation.interval_seconds"));
    }

    #[test]
    fn rejects_unknown_rotation_keys() {
        for input in [
            format!("{}\nrotation_seconds = 10", valid_toml()),
            format!("{}\n[rotation]\ninterval_second = 300", valid_toml()),
        ] {
            assert!(
                RuntimeConfig::parse(&input).is_err(),
                "accepted unknown key"
            );
        }
    }

    #[test]
    fn accepts_uuid_named_echo_export() {
        let input = valid_toml().replace(
            "[exports.echo]",
            "[exports.11111111-1111-4111-8111-111111111111]",
        );
        let config = RuntimeConfig::parse(&input).expect("UUID-named export");
        assert!(
            config
                .exports
                .contains_key("11111111-1111-4111-8111-111111111111")
        );
    }

    #[test]
    fn queue_budget_leaves_headroom_for_maximum_echo_response() {
        let mut config = RuntimeConfig::default();
        config.limits.max_queue_bytes = 256 * 1024 - 1;
        assert!(config.validate().is_err());
        config.limits.max_queue_bytes = 256 * 1024;
        assert!(config.validate().is_ok());
    }

    const MCP_EXPORT: &str = r#"
[exports.22222222-2222-4222-8222-222222222222]
type = "http-forward"

[exports.22222222-2222-4222-8222-222222222222.mcp]
profile = "mcp-2026-07-28"

[exports.22222222-2222-4222-8222-222222222222.mcp.backend]
kind = "stdio"
command = "/opt/synthetic/mcp-server"
args = ["stdio"]
workspace = "/srv/synthetic-workspace"
env = { SYNTHETIC_SECRET = "synthetic-env-value" }
"#;

    #[test]
    fn mcp_exports_parse_validate_and_register_handlers() {
        let input = valid_toml().replace(
            "[exports.echo]\ntype = \"echo\"\ndevice_canary = \"fixture-one\"\n",
            MCP_EXPORT,
        );
        let config = RuntimeConfig::parse(&input).expect("mcp export");
        let export = &config.exports["22222222-2222-4222-8222-222222222222"];
        assert_eq!(export.kind, ExportKind::HttpForward);
        assert!(export.mcp.is_some());
        // Debug never prints environment values.
        assert!(!format!("{config:?}").contains("synthetic-env-value"));
        let handlers = crate::http_forward::HttpHandlers::new()
            .with_mcp_exports(&config)
            .expect("handlers");
        assert!(handlers.contains("22222222-2222-4222-8222-222222222222"));

        // An mcp table on an echo export, an unknown profile, a relative
        // command and a non-loopback backend are configuration errors.
        for broken in [
            input.replace("type = \"http-forward\"", "type = \"echo\""),
            input.replace("mcp-2026-07-28", "mcp-2024-11-05"),
            input.replace("/opt/synthetic/mcp-server", "mcp-server"),
            input.replace(
                "kind = \"stdio\"\ncommand = \"/opt/synthetic/mcp-server\"\nargs = [\"stdio\"]\nworkspace = \"/srv/synthetic-workspace\"\nenv = { SYNTHETIC_SECRET = \"synthetic-env-value\" }",
                "kind = \"streamable-http\"\nurl = \"http://192.0.2.10:8080/mcp\"",
            ),
            input.replace("args = [\"stdio\"]", "args = [\"stdio\"]\nshell = \"/bin/sh\""),
        ] {
            assert!(RuntimeConfig::parse(&broken).is_err(), "{broken}");
        }
    }
}
