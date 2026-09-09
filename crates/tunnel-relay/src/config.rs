use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::OidcVerifier;
use tunnel_core::{ConfigError as CoreConfigError, RotationConfig};

/// Runtime limits enforced before a request or WebSocket message allocates
/// payload storage.  These are hard upper bounds for the M1 profile.
#[derive(Clone, Debug)]
pub struct RelayLimits {
    pub max_body_bytes: usize,
    pub max_control_bytes: usize,
    pub max_streams_per_device: usize,
    pub max_pending_operations: usize,
    pub max_devices: usize,
    pub max_devices_per_user: usize,
    pub max_queue_messages: usize,
    pub max_queue_bytes: usize,
    pub operation_timeout: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
            max_control_bytes: 32 * 1024,
            max_streams_per_device: 64,
            max_pending_operations: 64,
            max_devices: 1_024,
            max_devices_per_user: 16,
            max_queue_messages: 128,
            max_queue_bytes: 4 * 1024 * 1024,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

impl RelayLimits {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_body_bytes == 0 || self.max_body_bytes > 64 * 1024 {
            return Err(ConfigError::Invalid("max_body_bytes must be 1..=65536"));
        }
        if self.max_control_bytes == 0 || self.max_control_bytes > 32 * 1024 {
            return Err(ConfigError::Invalid("max_control_bytes must be 1..=32768"));
        }
        if self.max_streams_per_device == 0 || self.max_streams_per_device > 64 {
            return Err(ConfigError::Invalid(
                "max_streams_per_device must be 1..=64",
            ));
        }
        if self.max_pending_operations == 0 || self.max_pending_operations > 64 {
            return Err(ConfigError::Invalid(
                "max_pending_operations must be 1..=64",
            ));
        }
        if self.max_devices == 0 || self.max_devices > 1_000_000 {
            return Err(ConfigError::Invalid("max_devices must be 1..=1000000"));
        }
        if self.max_devices_per_user == 0 || self.max_devices_per_user > 64 {
            return Err(ConfigError::Invalid("max_devices_per_user must be 1..=64"));
        }
        if self.max_queue_messages == 0 || self.max_queue_messages > 1_024 {
            return Err(ConfigError::Invalid("max_queue_messages must be 1..=1024"));
        }
        if self.max_queue_bytes < 256 * 1024 || self.max_queue_bytes > 64 * 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "max_queue_bytes must be 256KiB..=64MiB",
            ));
        }
        if self.operation_timeout.is_zero() || self.operation_timeout > Duration::from_secs(300) {
            return Err(ConfigError::Invalid(
                "operation_timeout must be 1..=300 seconds",
            ));
        }
        Ok(())
    }
}

/// Options supplied by an embedding application or test harness.
///
/// Listener creation and TLS configuration stay outside this crate.  The
/// transport crate owns certificate verification and injects its typed
/// identity.  `start` accepts already-bound listeners so a harness can use
/// ephemeral ports without a second configuration path.
#[derive(Clone)]
pub struct RelayOptions {
    pub node_id: String,
    pub boot_id: String,
    pub deployment_incarnation: String,
    pub limits: RelayLimits,
    pub oidc: Arc<OidcVerifier>,
    pub challenge_interval: Duration,
    pub owner_lease: Duration,
    pub rotation: RotationConfig,
    pub shutdown: CancellationToken,
}

impl RelayOptions {
    pub fn new(oidc: Arc<OidcVerifier>) -> Self {
        Self {
            node_id: "relay-local".into(),
            boot_id: uuid::Uuid::new_v4().to_string(),
            deployment_incarnation: "m1-local".into(),
            limits: RelayLimits::default(),
            oidc,
            challenge_interval: Duration::from_secs(2),
            owner_lease: Duration::from_secs(30),
            rotation: RotationConfig::default(),
            shutdown: CancellationToken::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.node_id.is_empty() || self.node_id.len() > 128 {
            return Err(ConfigError::Invalid("node_id must contain 1..=128 bytes"));
        }
        if self.boot_id.is_empty() || self.boot_id.len() > 128 {
            return Err(ConfigError::Invalid("boot_id must contain 1..=128 bytes"));
        }
        if self.deployment_incarnation.is_empty() || self.deployment_incarnation.len() > 128 {
            return Err(ConfigError::Invalid(
                "deployment_incarnation must contain 1..=128 bytes",
            ));
        }
        if self.challenge_interval.is_zero() || self.challenge_interval > Duration::from_secs(5) {
            return Err(ConfigError::Invalid(
                "challenge_interval must be <= 5 seconds",
            ));
        }
        if self.owner_lease < Duration::from_secs(6) || self.owner_lease > Duration::from_secs(30) {
            return Err(ConfigError::Invalid("owner_lease must be 6..=30 seconds"));
        }
        self.limits.validate()?;
        self.rotation.validate().map_err(ConfigError::Rotation)
    }
}

/// The on-disk `serve` configuration.  Secret material is referenced by path;
/// it is never accepted inline in TOML or command arguments.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeConfig {
    #[serde(default = "default_consumer_bind")]
    pub consumer_bind: SocketAddr,
    #[serde(default = "default_device_bind")]
    pub device_bind: SocketAddr,
    pub oidc_issuer: String,
    pub oidc_audience: Vec<String>,
    pub oidc_jwks_path: PathBuf,
    pub redis_url: String,
    pub redis_namespace: String,
    pub device_tls_cert_chain: PathBuf,
    pub device_tls_private_key: PathBuf,
    pub device_tls_client_ca: PathBuf,
    pub consumer_tls_cert_chain: PathBuf,
    pub consumer_tls_private_key: PathBuf,
    #[serde(default)]
    pub consumer_tls_client_ca: Option<PathBuf>,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub boot_id: String,
    #[serde(default)]
    pub deployment_incarnation: String,
    #[serde(default = "default_max_devices_per_user")]
    pub max_devices_per_user: usize,
    #[serde(default = "default_max_queue_bytes")]
    pub max_queue_bytes: usize,
    #[serde(default)]
    pub rotation: RotationConfig,
}

impl ServeConfig {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Toml)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.oidc_issuer.trim().is_empty()
            || self.oidc_audience.is_empty()
            || self.redis_url.trim().is_empty()
            || self.redis_namespace.trim().is_empty()
            || self.deployment_incarnation.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "oidc issuer, audience, Redis settings, and deployment incarnation are required",
            ));
        }
        if self.redis_namespace.len() > 128 {
            return Err(ConfigError::Invalid(
                "redis_namespace must be at most 128 bytes",
            ));
        }
        if self.oidc_jwks_path.as_os_str().is_empty()
            || self.device_tls_cert_chain.as_os_str().is_empty()
            || self.device_tls_private_key.as_os_str().is_empty()
            || self.device_tls_client_ca.as_os_str().is_empty()
            || self.consumer_tls_cert_chain.as_os_str().is_empty()
            || self.consumer_tls_private_key.as_os_str().is_empty()
        {
            return Err(ConfigError::Invalid("TLS and OIDC paths must not be empty"));
        }
        if self.max_devices_per_user == 0 || self.max_devices_per_user > 64 {
            return Err(ConfigError::Invalid("max_devices_per_user must be 1..=64"));
        }
        if self.max_queue_bytes < 256 * 1024 || self.max_queue_bytes > 64 * 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "max_queue_bytes must be 256KiB..=64MiB",
            ));
        }
        self.rotation.validate().map_err(ConfigError::Rotation)?;
        Ok(())
    }

    /// Start both listener roles after the caller has constructed the durable
    /// catalog and OIDC verifier.  This helper is intentionally separate from
    /// `check-config`; no command silently starts networking while checking a
    /// file.
    pub async fn start(
        &self,
        options: RelayOptions,
        catalog: tunnel_catalog::SharedCatalog,
        consumer_listener: TcpListener,
        device_listener: TcpListener,
        consumer_tls: Arc<rustls::ServerConfig>,
        device_tls: Arc<rustls::ServerConfig>,
    ) -> Result<crate::RunningRelay, crate::RelayError> {
        let mut options = options;
        if !self.node_id.is_empty() {
            options.node_id = self.node_id.clone();
        }
        if !self.boot_id.is_empty() {
            options.boot_id = self.boot_id.clone();
        }
        if !self.deployment_incarnation.is_empty() {
            options.deployment_incarnation = self.deployment_incarnation.clone();
        }
        options.limits.max_devices_per_user = self.max_devices_per_user;
        options.limits.max_queue_bytes = self.max_queue_bytes;
        options.rotation = self.rotation.clone();
        crate::Relay::start(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
        )
        .await
    }
}

fn default_consumer_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8443))
}

fn default_device_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9443))
}

fn default_max_devices_per_user() -> usize {
    16
}

fn default_max_queue_bytes() -> usize {
    4 * 1024 * 1024
}

#[derive(Debug)]
pub enum ConfigError {
    Toml(toml::de::Error),
    Rotation(CoreConfigError),
    Invalid(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Toml(error) => write!(formatter, "invalid relay TOML: {error}"),
            Self::Rotation(error) => write!(formatter, "invalid rotation policy: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Toml(error) => Some(error),
            Self::Rotation(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey};
    use tunnel_catalog::{ApprovedJwk, OidcConfig, OidcVerifier};

    fn oidc() -> Arc<OidcVerifier> {
        let key = ApprovedJwk::from_decoding_key(
            "test",
            Algorithm::RS256,
            DecodingKey::from_secret(b"test-only-key"),
        )
        .expect("test key");
        let config = OidcConfig::new(
            "https://issuer.example.test/",
            ["agent-tunnel".to_owned()],
            vec![key],
        )
        .expect("test OIDC config");
        Arc::new(OidcVerifier::new(config).expect("test OIDC verifier"))
    }

    fn valid_toml() -> &'static str {
        r#"
oidc_issuer = "https://issuer.example.test/"
oidc_audience = ["agent-tunnel"]
oidc_jwks_path = "oidc-jwks.json"
redis_url = "redis://127.0.0.1:6379/0"
redis_namespace = "agent-tunnel/test"
deployment_incarnation = "test-incarnation"
device_tls_cert_chain = "device-cert.pem"
device_tls_private_key = "device-key.pem"
device_tls_client_ca = "device-ca.pem"
consumer_tls_cert_chain = "consumer-cert.pem"
consumer_tls_private_key = "consumer-key.pem"
"#
    }

    #[test]
    fn serve_defaults_to_shared_rotation_policy() {
        let config = ServeConfig::parse(valid_toml()).expect("valid serve configuration");
        assert_eq!(config.rotation, RotationConfig::default());
    }

    #[test]
    fn relay_options_default_to_and_validate_shared_rotation_policy() {
        let options = RelayOptions::new(oidc());
        assert_eq!(options.rotation, RotationConfig::default());
        options.validate().expect("default relay options");

        let mut invalid = options;
        invalid.rotation.interval_seconds = 0;
        let error = invalid.validate().expect_err("invalid rotation interval");
        assert!(error.to_string().contains("rotation.interval_seconds"));
    }

    #[test]
    fn serve_accepts_partial_rotation_override() {
        let input = format!(
            "{}\n[rotation]\ninterval_seconds = 600\nhandshake_timeout_seconds = 15",
            valid_toml()
        );
        let config = ServeConfig::parse(&input).expect("valid rotation override");
        assert_eq!(config.rotation.interval_seconds, 600);
        assert_eq!(config.rotation.handshake_timeout_seconds, 15);
        assert_eq!(config.rotation.overlap_seconds, 30);
    }

    #[test]
    fn serve_rejects_invalid_rotation_timing() {
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
            assert!(ServeConfig::parse(&input).is_err(), "accepted {timing}");
        }
    }

    #[test]
    fn serve_rejects_unknown_rotation_keys() {
        for input in [
            format!("{}\nrotation_seconds = 10", valid_toml()),
            format!("{}\n[rotation]\ninterval_second = 300", valid_toml()),
        ] {
            assert!(ServeConfig::parse(&input).is_err(), "accepted unknown key");
        }
    }
}
