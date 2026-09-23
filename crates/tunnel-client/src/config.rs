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
/// Why an fs export is refused off Unix; the same words
/// `tunnel_fs_host::unsupported_host_reason` uses.
pub const FS_EXPORT_UNSUPPORTED_ON_THIS_HOST: &str =
    "filesystem exports are unsupported on this host";
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
    /// `tunnel-client connect`'s reconnect policy (M6-C23).  Only the CLI's
    /// supervisor loop reads it; the library's `connect` makes one attempt.
    pub reconnect: ReconnectConfig,
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
        self.reconnect.validate()?;
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
            if let Some(acp) = &export.acp {
                if export.kind != ExportKind::HttpForward {
                    return Err(RuntimeConfigError::Invalid(
                        "an acp table is only valid on an http-forward export",
                    ));
                }
                if export.mcp.is_some() {
                    // One handler is registered per service identifier, so two
                    // application tables on one export would silently mean
                    // "whichever `with_*_exports` ran last".  Refusing is the
                    // only answer that cannot depend on registration order.
                    return Err(RuntimeConfigError::Invalid(
                        "an export carries either an mcp table or an acp table, never both",
                    ));
                }
                acp.validate()
                    .map_err(|error| RuntimeConfigError::Invalid(error.0))?;
            }
            match (export.kind, export.fs.as_ref()) {
                (ExportKind::Fs, None) => {
                    return Err(RuntimeConfigError::Invalid(
                        "an fs export requires an [exports.<service>.fs] table naming its root",
                    ));
                }
                (kind, Some(_)) if kind != ExportKind::Fs => {
                    return Err(RuntimeConfigError::Invalid(
                        "an fs table is only valid on an fs export",
                    ));
                }
                (ExportKind::Fs, Some(fs)) => {
                    // Gate 2 declares filesystem exports unsupported off Unix
                    // (`tunnel_fs_host::unsupported_host_reason`). Refused
                    // here, at `config check` and at startup, so a configured
                    // export is a named error rather than one that silently
                    // answers every session `root_unavailable`.
                    if cfg!(not(unix)) {
                        return Err(RuntimeConfigError::Invalid(
                            FS_EXPORT_UNSUPPORTED_ON_THIS_HOST,
                        ));
                    }
                    if fs.root.as_os_str().is_empty() {
                        return Err(RuntimeConfigError::Invalid(
                            "an fs export must name a root directory",
                        ));
                    }
                    if fs.capabilities.is_empty() {
                        // Default deny: an export granting nothing admits no
                        // session at all, rather than one that can do nothing.
                        return Err(RuntimeConfigError::Invalid(
                            "an fs export must name at least one capability",
                        ));
                    }
                    for capability in &fs.capabilities {
                        if tunnel_fs_core::Capability::parse(capability).is_none() {
                            return Err(RuntimeConfigError::Invalid(
                                "fs capabilities are read, write, list and delete",
                            ));
                        }
                    }
                }
                _ => {}
            }
            if export.kind == ExportKind::Fs && export.device_canary.is_some() {
                return Err(RuntimeConfigError::Invalid(
                    "an fs export has no device_canary",
                ));
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
            reconnect: ReconnectConfig::default(),
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
    /// An ACP export served by the connector itself (M8 chunk 3): only valid
    /// on an `http-forward` export, and never alongside an `mcp` table on the
    /// same export.  See `tunnel_acp_export::config`.
    pub acp: Option<tunnel_acp_export::AcpExportConfig>,
    /// A filesystem export served by the connector itself (M4 gate 4): only
    /// valid on an `fs` export, and required on one.  The root is operator
    /// configuration and is the one path this profile opens by name.
    pub fs: Option<FsExportSettings>,
}

/// The operator configuration of one filesystem export.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FsExportSettings {
    /// The host directory the export is rooted at.
    pub root: PathBuf,
    /// The capabilities this device will serve **at most**.
    ///
    /// The session's effective grant is this intersected with what the relay's
    /// OPEN named, so a relay can only ever narrow it. Default deny: an export
    /// that names nothing admits no session, which is gate 1's own rule.
    pub capabilities: Vec<String>,
    /// The optional provider features this export implements.
    ///
    /// The descriptor's own `features` spellings — `atomicRename`,
    /// `exclusiveCreate`, `symlinks`, `hardLinks` and the rest. **Default
    /// none**, which is the contract's own default: every feature is opt-in,
    /// and `hardLinks` in particular switches off the `st_nlink` write refusal,
    /// so an export that enabled one by omission would be wider than the
    /// operator asked for. A name this build does not know is ignored rather
    /// than refused, which can only ever fail to turn something on.
    pub features: Vec<String>,
}

impl Default for FsExportSettings {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            capabilities: Vec::new(),
            features: Vec::new(),
        }
    }
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            kind: ExportKind::Echo,
            device_canary: None,
            mcp: None,
            acp: None,
            fs: None,
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
    /// A filesystem export serving 9P2000.L over one logical stream (M4 gate
    /// 4).  It is admitted only when an `[exports.<service>.fs]` table names a
    /// root this connector can open; the M1 profile never admits it.
    #[serde(rename = "fs")]
    Fs,
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

/// Smallest `reconnect.initial_delay_ms`: below this a retry loop against a
/// relay that refuses at once is a busy loop in all but name.
pub const MIN_RECONNECT_DELAY_MS: u64 = 100;
/// Largest `reconnect.max_delay_ms` (5 minutes): a device may not stay away
/// from a relay that came back for longer than this after its last attempt.
pub const MAX_RECONNECT_DELAY_MS: u64 = 300_000;

/// How `tunnel-client connect` reconnects after a retryable end of session
/// (task row M6-C23).  The defaults are the documented policy in
/// docs/runtime.md ("Reconnecting"): first delay about 1 s, doubling, capped
/// at 60 s, jittered, and no attempt limit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReconnectConfig {
    /// `false` makes `connect` exit on the first end of session, as it did
    /// before M6-C23, for a supervisor that prefers to own restarts.  The
    /// `--no-reconnect` flag sets it for one run.
    pub enabled: bool,
    /// Upper bound of the first delay; the n-th consecutive failed attempt's
    /// bound is `initial_delay_ms * 2^(n-1)`, capped at `max_delay_ms`.
    pub initial_delay_ms: u64,
    /// Cap on every delay.
    pub max_delay_ms: u64,
    /// Consecutive failed attempts after which `connect` gives up and exits
    /// with the last attempt's cause; `0` means no limit.  The count resets
    /// when a session has stayed ready for `max_delay_ms`.
    pub max_attempts: u32,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_delay_ms: 1_000,
            max_delay_ms: 60_000,
            max_attempts: 0,
        }
    }
}

impl ReconnectConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.initial_delay_ms < MIN_RECONNECT_DELAY_MS
            || self.initial_delay_ms > MAX_RECONNECT_DELAY_MS
        {
            return Err(RuntimeConfigError::Invalid(
                "reconnect.initial_delay_ms must be between 100 and 300000",
            ));
        }
        if self.max_delay_ms < self.initial_delay_ms || self.max_delay_ms > MAX_RECONNECT_DELAY_MS {
            return Err(RuntimeConfigError::Invalid(
                "reconnect.max_delay_ms must be between reconnect.initial_delay_ms and 300000",
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
    #[serde(default)]
    reconnect: ReconnectConfig,
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
            reconnect: raw.reconnect,
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

    /// An fs export is valid configuration on a Unix host and a named refusal
    /// everywhere else. Both halves run somewhere in CI: the Unix half on the
    /// Linux and macOS jobs, the refusal on the Windows job, so the Windows
    /// connector cannot quietly accept an export it will never serve.
    #[test]
    fn an_fs_export_is_refused_by_name_where_filesystem_exports_are_unsupported() {
        let result = RuntimeConfig::parse(
            r#"
device_id = "fixture-one"
relay_url = "wss://relay.example.test/v1/tunnel/control"
client_cert = "client.pem"
private_key = "client-key.pem"
server_ca = "ca.pem"

[exports.files]
type = "fs"

[exports.files.fs]
root = "/srv/export"
capabilities = ["read", "list"]
"#,
        );
        if cfg!(unix) {
            result.expect("an fs export is valid configuration on a Unix host");
        } else {
            let error = result.expect_err("an fs export must be refused off Unix");
            assert!(
                error
                    .to_string()
                    .contains(FS_EXPORT_UNSUPPORTED_ON_THIS_HOST),
                "{error}"
            );
        }
    }

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
    fn reconnect_defaults_and_bounds() {
        let config = RuntimeConfig::parse(valid_toml()).expect("valid default");
        assert_eq!(config.reconnect, ReconnectConfig::default());
        assert!(config.reconnect.enabled);
        let input = format!(
            "{}\n[reconnect]\nenabled = false\ninitial_delay_ms = 200\nmax_delay_ms = 400\nmax_attempts = 3",
            valid_toml()
        );
        let config = RuntimeConfig::parse(&input).expect("valid reconnect override");
        assert!(!config.reconnect.enabled);
        assert_eq!(config.reconnect.initial_delay_ms, 200);
        assert_eq!(config.reconnect.max_delay_ms, 400);
        assert_eq!(config.reconnect.max_attempts, 3);
        for bad in [
            "initial_delay_ms = 99",
            "initial_delay_ms = 300001",
            "initial_delay_ms = 2000\nmax_delay_ms = 1000",
            "max_delay_ms = 300001",
            "jitter = 0",
        ] {
            let input = format!("{}\n[reconnect]\n{bad}", valid_toml());
            assert!(
                RuntimeConfig::parse(&input).is_err(),
                "{bad} must be refused"
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

    /// The same configuration with every quoted absolute Unix path made
    /// absolute on this host: `"/opt/x"` becomes `"C:/opt/x"` on Windows, where
    /// `/opt/x` has no drive and is rightly refused as not absolute.
    fn host(text: &str) -> String {
        if cfg!(windows) {
            text.replace("\"/", "\"C:/")
        } else {
            text.to_owned()
        }
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
        let input = host(&valid_toml().replace(
            "[exports.echo]\ntype = \"echo\"\ndevice_canary = \"fixture-one\"\n",
            MCP_EXPORT,
        ));
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
        let counters = handlers
            .mcp_diagnostics_source()
            .get("22222222-2222-4222-8222-222222222222")
            .expect("mcp export counters");
        assert_eq!(counters.children_spawned, 0);
        assert!(handlers.mcp_diagnostics_source().get("echo").is_none());

        // An mcp table on an echo export, an unknown profile, a relative
        // command and a non-loopback backend are configuration errors.
        for broken in [
            input.replace("type = \"http-forward\"", "type = \"echo\""),
            input.replace("mcp-2026-07-28", "mcp-2024-11-05"),
            input.replace("/opt/synthetic/mcp-server", "mcp-server"),
            input.replace(
                &host("kind = \"stdio\"\ncommand = \"/opt/synthetic/mcp-server\"\nargs = [\"stdio\"]\nworkspace = \"/srv/synthetic-workspace\"\nenv = { SYNTHETIC_SECRET = \"synthetic-env-value\" }"),
                "kind = \"streamable-http\"\nurl = \"http://192.0.2.10:8080/mcp\"",
            ),
            input.replace("args = [\"stdio\"]", "args = [\"stdio\"]\nshell = \"/bin/sh\""),
        ] {
            assert!(RuntimeConfig::parse(&broken).is_err(), "{broken}");
        }
    }

    const ACP_EXPORT: &str = "[exports.33333333-3333-4333-8333-333333333333]\ntype = \"http-forward\"\n\n[exports.33333333-3333-4333-8333-333333333333.acp]\nprofile = \"acp-http-v1\"\n\n[exports.33333333-3333-4333-8333-333333333333.acp.agent]\ncommand = \"/opt/synthetic/acp-agent\"\nargs = [\"agent\"]\nworkspace = \"/srv/synthetic-workspace\"\n";

    #[test]
    fn acp_exports_parse_validate_and_register_handlers() {
        let input = host(&valid_toml().replace(
            "[exports.echo]\ntype = \"echo\"\ndevice_canary = \"fixture-one\"\n",
            ACP_EXPORT,
        ));
        let config = RuntimeConfig::parse(&input).expect("acp export");
        let export = &config.exports["33333333-3333-4333-8333-333333333333"];
        assert_eq!(export.kind, ExportKind::HttpForward);
        assert!(export.acp.is_some());

        // Registration is what the binary does; a table that parsed and was
        // never registered would be an export the operator configured and the
        // connector silently refused at OPEN.
        let handlers = crate::http_forward::HttpHandlers::new()
            .with_mcp_exports(&config)
            .expect("mcp handlers")
            .with_acp_exports(&config)
            .expect("acp handlers");
        assert!(handlers.contains("33333333-3333-4333-8333-333333333333"));
        let counters = handlers
            .acp_diagnostics_source()
            .get("33333333-3333-4333-8333-333333333333")
            .expect("acp export counters");
        assert_eq!(counters.connections_opened, 0);
        assert!(handlers.acp_diagnostics_source().get("echo").is_none());
        // No child is started by registration alone: `initialize` starts one.
        assert!(
            handlers
                .acp_diagnostics_source()
                .child_pids("33333333-3333-4333-8333-333333333333")
                .is_empty()
        );

        // An acp table on an echo export, an unknown profile and a relative
        // command are configuration errors.
        for broken in [
            input.replace("type = \"http-forward\"", "type = \"echo\""),
            input.replace("acp-http-v1", "acp-http-v2"),
            input.replace("/opt/synthetic/acp-agent", "acp-agent"),
            input.replace("/srv/synthetic-workspace", "synthetic-workspace"),
        ] {
            assert!(RuntimeConfig::parse(&broken).is_err(), "{broken}");
        }
    }

    /// One handler is registered per service identifier, so two application
    /// tables on one export would mean "whichever `with_*_exports` ran last".
    #[test]
    fn an_export_carries_an_mcp_table_or_an_acp_table_and_never_both() {
        let both = valid_toml()
            .replace(
                "[exports.echo]\ntype = \"echo\"\ndevice_canary = \"fixture-one\"\n",
                MCP_EXPORT,
            )
            .replace(
                "[exports.22222222-2222-4222-8222-222222222222.mcp]\nprofile = \"mcp-2026-07-28\"\n",
                "[exports.22222222-2222-4222-8222-222222222222.acp]\nprofile = \"acp-http-v1\"\n\n[exports.22222222-2222-4222-8222-222222222222.acp.agent]\ncommand = \"/opt/synthetic/acp-agent\"\nargs = [\"agent\"]\nworkspace = \"/srv/synthetic-workspace\"\n\n[exports.22222222-2222-4222-8222-222222222222.mcp]\nprofile = \"mcp-2026-07-28\"\n",
            );
        // Not vacuous: the edit really did put both tables on one export.
        assert!(both.contains(".acp]") && both.contains(".mcp]"), "{both}");
        let both = host(&both);
        let error = RuntimeConfig::parse(&both).expect_err("both tables are refused");
        assert!(
            format!("{error}").contains("never both"),
            "refused for the wrong reason: {error}"
        );
    }
}
