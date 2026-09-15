use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{OidcVerifier, validate_redis_namespace};
use tunnel_core::{ConfigError as CoreConfigError, RotationConfig};

use crate::redis_connection::RedisTlsMaterialPaths;

/// Default per-owner consumer admission bound.  It equals the default
/// `max_streams_per_device`, because one device must be able to use the whole
/// per-device stream allowance it is documented to have; a lower per-owner
/// bound makes that allowance unreachable through a single relay.  Fairness
/// still holds by default because the relay-global `max_pending_operations`
/// default is twice this value, so one owner scope can never take more than
/// half of a relay's concurrent ingress.  A deployment with many tenants per
/// relay can lower it deliberately.
pub const DEFAULT_MAX_PENDING_OPERATIONS_PER_OWNER: usize = 64;
/// Hard ceiling for the per-owner consumer admission bound.  It matches the
/// relay-global ceiling so the configuration cannot advertise a per-owner
/// allowance the process bound could never grant.
pub const MAX_PENDING_OPERATIONS_PER_OWNER_CEILING: usize = 128;

/// Runtime limits enforced before a request or WebSocket message allocates
/// payload storage.  These are hard upper bounds for the M1 profile.
#[derive(Clone, Debug)]
pub struct RelayLimits {
    pub max_body_bytes: usize,
    pub max_control_bytes: usize,
    pub max_streams_per_device: usize,
    /// Relay-global consumer ingress admission permits.  This is a process
    /// bound: it is not tenant-scoped and must not be the only admission
    /// bound, or one tenant's in-flight operations refuse every other
    /// tenant's public request.
    pub max_pending_operations: usize,
    /// Consumer admission permits one `(tenant_id, device_id)` owner scope may
    /// hold at once.  Layered *under* `max_pending_operations`: the global cap
    /// still bounds the process, and the effective per-owner bound is
    /// `min(max_pending_operations_per_owner, max_pending_operations)` because
    /// the global permit is always reserved first.  The default keeps three
    /// quarters of the relay-global permits available to one owner scope, so a
    /// single owner retains headroom for its documented
    /// `max_streams_per_device` allowance spread across a cluster's non-owner
    /// ingress relays, while at least a quarter of relay ingress capacity can
    /// never be consumed by one tenant/device.  Deployments serving many
    /// concurrent tenants should lower it.
    pub max_pending_operations_per_owner: usize,
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
            max_pending_operations: 128,
            max_pending_operations_per_owner: DEFAULT_MAX_PENDING_OPERATIONS_PER_OWNER,
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
        if self.max_pending_operations == 0 || self.max_pending_operations > 128 {
            return Err(ConfigError::Invalid(
                "max_pending_operations must be 1..=128",
            ));
        }
        if self.max_pending_operations_per_owner == 0
            || self.max_pending_operations_per_owner > MAX_PENDING_OPERATIONS_PER_OWNER_CEILING
        {
            return Err(ConfigError::Invalid(
                "max_pending_operations_per_owner must be 1..=128",
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
    /// Optional M7 configuration.  The relay runtime does not consume this
    /// field yet; keeping it on the typed options lets the M7 transport wire
    /// it in without adding a second configuration path.
    pub cluster: Option<ClusterConfig>,
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
            cluster: None,
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
        self.rotation.validate().map_err(ConfigError::Rotation)?;
        if let Some(cluster) = &self.cluster {
            cluster.validate()?;
            if let Some(cluster_node_id) = &cluster.node_id
                && cluster_node_id != &self.node_id
            {
                return Err(ConfigError::Invalid(
                    "cluster.node_id must match the relay node_id",
                ));
            }
        }
        Ok(())
    }
}

/// Operator-provisioned constraints for signed private peer endpoints.
///
/// The membership publisher signs the endpoint advertised by a relay.  This
/// local policy is the independently trusted constraint used when that record
/// is checked.  An empty host list means that only private IP literals are
/// accepted; the default policy therefore does not trust private DNS by
/// accident.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PrivateEndpointPolicyConfig {
    #[serde(alias = "hosts")]
    pub allowed_hosts: Vec<String>,
    #[serde(alias = "server_names")]
    pub allowed_server_names: Vec<String>,
    #[serde(alias = "ports")]
    pub allowed_ports: Vec<u16>,
    pub require_private_ip: bool,
}

impl Default for PrivateEndpointPolicyConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_server_names: Vec::new(),
            allowed_ports: vec![8443],
            require_private_ip: true,
        }
    }
}

impl PrivateEndpointPolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.allowed_hosts.len() > MAX_CLUSTER_AUTHORIZED_NODES
            || self.allowed_server_names.len() > MAX_CLUSTER_AUTHORIZED_NODES
        {
            return Err(ConfigError::Invalid(
                "cluster endpoint policy allowlists must contain at most 32 entries",
            ));
        }
        if self.allowed_ports.is_empty() || self.allowed_ports.len() > MAX_CLUSTER_AUTHORIZED_NODES
        {
            return Err(ConfigError::Invalid(
                "cluster endpoint policy must contain 1..=32 ports",
            ));
        }

        let mut ports = BTreeSet::new();
        for port in &self.allowed_ports {
            if *port == 0 || !ports.insert(*port) {
                return Err(ConfigError::Invalid(
                    "cluster endpoint policy ports must be unique and nonzero",
                ));
            }
        }

        let mut hosts = BTreeSet::new();
        for host in &self.allowed_hosts {
            if !validate_endpoint_host(host)
                || host != &host.to_ascii_lowercase()
                || !hosts.insert(host)
            {
                return Err(ConfigError::Invalid(
                    "cluster endpoint policy hosts must be unique, valid, and lower-case",
                ));
            }
        }

        let mut server_names = BTreeSet::new();
        for server_name in &self.allowed_server_names {
            if !validate_server_name(server_name)
                || server_name != &server_name.to_ascii_lowercase()
                || !server_names.insert(server_name)
            {
                return Err(ConfigError::Invalid(
                    "cluster endpoint policy server names must be unique, valid, and lower-case",
                ));
            }
        }

        if self.allowed_hosts.is_empty() && !self.require_private_ip {
            return Err(ConfigError::Invalid(
                "cluster endpoint policy without hosts must require private IP literals",
            ));
        }
        Ok(())
    }
}

/// Optional M7 relay-cluster configuration.
///
/// The executable consumes this boundary to construct the private QUIC/H3
/// listener and signed membership runtime.  All key and trust material is
/// referenced by path so this configuration never contains private
/// membership-signing or CA key material.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfig {
    pub deployment_id: String,
    #[serde(alias = "peer_udp_bind", alias = "private_peer_bind")]
    pub peer_bind: SocketAddr,
    #[serde(alias = "peer_cert_chain", alias = "peer_certificate")]
    pub peer_tls_cert_chain: PathBuf,
    #[serde(alias = "peer_private_key", alias = "peer_key")]
    pub peer_tls_private_key: PathBuf,
    #[serde(alias = "peer_client_ca", alias = "peer_ca")]
    pub peer_tls_client_ca: PathBuf,

    /// At least one operator-installed public-key or trust-bundle path is
    /// required.  Both may be supplied during a signer rotation overlap.
    #[serde(
        default,
        alias = "membership_signer_public_key",
        alias = "membership_public_key_path"
    )]
    pub membership_signer_public_key_path: Option<PathBuf>,
    /// Identifier paired with the raw/hex public key at
    /// `membership_signer_public_key_path`.  A trust document containing
    /// named keys does not need this field.
    #[serde(
        default,
        alias = "membership_signer_public_key_id",
        alias = "membership_publisher_key_id"
    )]
    pub membership_signer_key_id: Option<String>,
    #[serde(
        default,
        alias = "membership_signer_trust_bundle",
        alias = "membership_signer_trust_bundle_path",
        alias = "membership_trust_bundle_path"
    )]
    pub membership_signer_trust_path: Option<PathBuf>,

    #[serde(alias = "checkpoint_authority_url")]
    pub checkpoint_authority_endpoint: String,
    #[serde(
        alias = "checkpoint_authority_trust_bundle",
        alias = "checkpoint_authority_trust_bundle_path"
    )]
    pub checkpoint_authority_trust_path: PathBuf,

    /// Required local high-water fence file.  The relay opens this path in
    /// persisted cluster mode and never silently creates an empty state.
    #[serde(
        alias = "membership_state_path",
        alias = "membership_version_state_file"
    )]
    pub membership_version_state_path: PathBuf,

    #[serde(
        default,
        alias = "private_endpoint_policy",
        alias = "signed_endpoint_policy"
    )]
    pub endpoint_policy: PrivateEndpointPolicyConfig,

    /// When present, the cluster section repeats the top-level node identity
    /// and is checked against it.  Omitting it uses the existing `node_id`
    /// field, avoiding a breaking change to M1/M2 configuration.
    #[serde(default, alias = "node_identity")]
    pub node_id: Option<String>,

    /// Bounds from the M7 membership and peer contracts.  They are exposed as
    /// seconds so the TOML representation stays simple and deterministic.
    #[serde(default = "default_membership_record_lifetime_seconds")]
    pub membership_record_lifetime_seconds: u64,
    #[serde(
        default = "default_membership_refresh_seconds",
        alias = "membership_refresh_interval_seconds"
    )]
    pub membership_refresh_seconds: u64,
    #[serde(
        default = "default_membership_reconcile_seconds",
        alias = "membership_revalidation_seconds"
    )]
    pub membership_reconcile_seconds: u64,
    #[serde(default = "default_peer_idle_timeout_seconds")]
    pub peer_idle_timeout_seconds: u64,
    #[serde(default = "default_peer_drain_timeout_seconds")]
    pub peer_drain_timeout_seconds: u64,
    #[serde(
        default = "default_checkpoint_timeout_seconds",
        alias = "checkpoint_request_timeout_seconds"
    )]
    pub checkpoint_timeout_seconds: u64,
    #[serde(default = "default_cluster_clock_skew_seconds")]
    pub max_clock_skew_seconds: u64,
}

impl ClusterConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_cluster_identifier(&self.deployment_id, "cluster.deployment_id")?;
        if self.peer_bind.port() == 0 {
            return Err(ConfigError::Invalid(
                "cluster.peer_bind must use a nonzero UDP port",
            ));
        }
        validate_config_path(&self.peer_tls_cert_chain, "cluster.peer_tls_cert_chain")?;
        validate_config_path(&self.peer_tls_private_key, "cluster.peer_tls_private_key")?;
        validate_config_path(&self.peer_tls_client_ca, "cluster.peer_tls_client_ca")?;

        if self
            .membership_signer_public_key_path
            .as_ref()
            .is_none_or(|path| path.as_os_str().is_empty())
            && self
                .membership_signer_trust_path
                .as_ref()
                .is_none_or(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::Invalid(
                "cluster requires a membership signer public-key or trust-bundle path",
            ));
        }
        if let Some(path) = &self.membership_signer_public_key_path {
            validate_config_path(path, "cluster.membership_signer_public_key_path")?;
            if self.membership_signer_trust_path.is_none()
                && self
                    .membership_signer_key_id
                    .as_deref()
                    .is_none_or(str::is_empty)
            {
                return Err(ConfigError::Invalid(
                    "cluster.membership_signer_key_id is required with a direct public-key path",
                ));
            }
        } else if self.membership_signer_key_id.is_some() {
            return Err(ConfigError::Invalid(
                "cluster.membership_signer_key_id requires a direct public-key path",
            ));
        }
        if let Some(key_id) = &self.membership_signer_key_id {
            validate_cluster_identifier(key_id, "cluster.membership_signer_key_id")?;
        }
        if let Some(path) = &self.membership_signer_trust_path {
            validate_config_path(path, "cluster.membership_signer_trust_path")?;
        }

        validate_https_endpoint(&self.checkpoint_authority_endpoint)?;
        validate_config_path(
            &self.checkpoint_authority_trust_path,
            "cluster.checkpoint_authority_trust_path",
        )?;
        validate_config_path(
            &self.membership_version_state_path,
            "cluster.membership_version_state_path",
        )?;
        self.endpoint_policy.validate()?;

        if let Some(node_id) = &self.node_id {
            validate_cluster_identifier(node_id, "cluster.node_id")?;
        }

        bounded_cluster_seconds(
            self.membership_record_lifetime_seconds,
            1,
            MAX_CLUSTER_RECORD_LIFETIME_SECONDS,
            "cluster.membership_record_lifetime_seconds must be 1..=60",
        )?;
        bounded_cluster_seconds(
            self.membership_refresh_seconds,
            1,
            MAX_CLUSTER_REFRESH_SECONDS,
            "cluster.membership_refresh_seconds must be 1..=20",
        )?;
        bounded_cluster_seconds(
            self.membership_reconcile_seconds,
            1,
            MAX_CLUSTER_RECONCILE_SECONDS,
            "cluster.membership_reconcile_seconds must be 1..=5",
        )?;
        bounded_cluster_seconds(
            self.peer_idle_timeout_seconds,
            1,
            MAX_CLUSTER_IDLE_TIMEOUT_SECONDS,
            "cluster.peer_idle_timeout_seconds must be 1..=60",
        )?;
        bounded_cluster_seconds(
            self.peer_drain_timeout_seconds,
            1,
            MAX_CLUSTER_DRAIN_SECONDS,
            "cluster.peer_drain_timeout_seconds must be 1..=30",
        )?;
        bounded_cluster_seconds(
            self.checkpoint_timeout_seconds,
            1,
            MAX_CLUSTER_CHECKPOINT_TIMEOUT_SECONDS,
            "cluster.checkpoint_timeout_seconds must be 1..=2",
        )?;
        if self.max_clock_skew_seconds > MAX_CLUSTER_CLOCK_SKEW_SECONDS {
            return Err(ConfigError::Invalid(
                "cluster.max_clock_skew_seconds must be 0..=1",
            ));
        }
        if self.membership_refresh_seconds > self.membership_record_lifetime_seconds {
            return Err(ConfigError::Invalid(
                "cluster.membership_refresh_seconds must not exceed the record lifetime",
            ));
        }
        Ok(())
    }

    fn validate_for_serve(
        &self,
        node_id: &str,
        boot_id: &str,
        redis_namespace: &str,
        deployment_incarnation: &str,
    ) -> Result<(), ConfigError> {
        self.validate()?;
        if node_id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "cluster mode requires a top-level node_id",
            ));
        }
        if let Some(cluster_node_id) = &self.node_id
            && cluster_node_id != node_id
        {
            return Err(ConfigError::Invalid(
                "cluster.node_id must match the relay node_id",
            ));
        }
        if !boot_id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "cluster mode requires a fresh process boot_id; remove the configured legacy boot_id",
            ));
        }
        if redis_namespace.trim().is_empty() || deployment_incarnation.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "cluster mode requires the existing Redis namespace and deployment incarnation",
            ));
        }
        Ok(())
    }
}

/// Optional operator-controlled recovery inputs.
///
/// Recovery deliberately has its own control-file paths and may select a
/// separately provisioned Redis TLS profile.  The authority identity and
/// candidate incarnation default to the checked serving configuration; an
/// explicit recovery override is available for an operator preparing a
/// replacement incarnation without changing the ordinary `serve` profile.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConfig {
    /// Durable approval-version fence used only by `recovery-initialize` and
    /// `recover`.
    pub fence_path: PathBuf,
    /// Owner-provisioned public recovery-key document.
    pub trusted_keys_path: PathBuf,
    /// Optional recovery-only Redis authority URL.  When absent, the checked
    /// top-level `redis_url` is used.
    #[serde(default)]
    pub redis_url: Option<String>,
    /// Optional recovery-only candidate deployment incarnation.  When absent,
    /// the checked top-level `deployment_incarnation` is used.
    #[serde(default)]
    pub deployment_incarnation: Option<String>,
    /// Optional recovery-only Redis TLS material.  Each absent field falls
    /// back to the corresponding checked top-level serving field.
    #[serde(default)]
    pub redis_tls_root_ca_path: Option<PathBuf>,
    #[serde(default)]
    pub redis_tls_client_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub redis_tls_client_key_path: Option<PathBuf>,
}

impl std::fmt::Debug for RecoveryConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryConfig")
            .field("fence_path", &"<redacted>")
            .field("trusted_keys_path", &"<redacted>")
            .field("has_redis_url", &self.redis_url.is_some())
            .field("deployment_incarnation", &self.deployment_incarnation)
            .field(
                "has_redis_tls_root_ca_path",
                &self.redis_tls_root_ca_path.is_some(),
            )
            .field(
                "has_redis_tls_client_cert_path",
                &self.redis_tls_client_cert_path.is_some(),
            )
            .field(
                "has_redis_tls_client_key_path",
                &self.redis_tls_client_key_path.is_some(),
            )
            .finish()
    }
}

impl RecoveryConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_config_path(&self.fence_path, "recovery.fence_path")?;
        validate_config_path(&self.trusted_keys_path, "recovery.trusted_keys_path")?;
        if let Some(redis_url) = &self.redis_url {
            validate_redis_endpoint(redis_url)?;
        }
        if let Some(incarnation) = &self.deployment_incarnation {
            validate_cluster_identifier(incarnation, "recovery.deployment_incarnation")?;
        }
        let tls_material = RedisTlsMaterialPaths {
            root_ca_path: self.redis_tls_root_ca_path.clone(),
            client_cert_path: self.redis_tls_client_cert_path.clone(),
            client_key_path: self.redis_tls_client_key_path.clone(),
        };
        tls_material
            .validate_shape()
            .map_err(ConfigError::Invalid)?;
        if tls_material.is_configured()
            && self
                .redis_url
                .as_deref()
                .is_some_and(|url| !url.starts_with("rediss://"))
        {
            return Err(ConfigError::Invalid(
                "recovery Redis TLS material requires a rediss:// URL",
            ));
        }
        Ok(())
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
    #[serde(default)]
    pub redis_tls_root_ca_path: Option<PathBuf>,
    #[serde(default)]
    pub redis_tls_client_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub redis_tls_client_key_path: Option<PathBuf>,
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
    /// Per-`(tenant, device)` consumer admission permits, layered under the
    /// relay-global bound.  Absence keeps the documented default so existing
    /// M1/M2 configuration files stay valid.
    #[serde(default = "default_max_pending_operations_per_owner")]
    pub max_pending_operations_per_owner: usize,
    #[serde(default = "default_max_queue_bytes")]
    pub max_queue_bytes: usize,
    #[serde(default)]
    pub rotation: RotationConfig,
    /// M7 is opt-in.  Absence preserves the existing M1/M2 configuration
    /// shape and behavior.
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,
    /// Recovery is opt-in and is never opened by ordinary `serve`.
    #[serde(default)]
    pub recovery: Option<RecoveryConfig>,
    /// Gate 5: the `http-forward/1` application profiles this relay serves.
    /// Absent, the public HTTP route answers 404 as before.
    #[serde(default)]
    pub http_forward: Option<HttpForwardServeConfig>,
}

/// The `[http_forward]` table: the pinned application profiles a relay
/// serves and their finite limits.  Only profiles pinned in code can be
/// named; a catalog service selects one through its
/// `http_forward_profile` capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpForwardServeConfig {
    /// For example `["mcp-2026-07-28", "mcp-2025-11-25"]`.
    pub profiles: Vec<String>,
    /// Cumulative request body limit (default 1 MiB, at most 16 MiB).
    #[serde(default)]
    pub request_body_bytes: Option<u64>,
    /// Cumulative response body limit, the SSE limit (default 64 MiB, at
    /// most 1 GiB).
    #[serde(default)]
    pub response_body_bytes: Option<u64>,
    /// Absolute exchange deadline in seconds (default 300, at most 86400).
    #[serde(default)]
    pub deadline_seconds: Option<u64>,
}

impl HttpForwardServeConfig {
    /// Build the relay's profile set.
    ///
    /// # Errors
    /// No profile, an unpinned or repeated profile, or limits outside their
    /// bounds.
    pub fn exports(&self) -> Result<crate::HttpForwardExports, ConfigError> {
        if self.profiles.is_empty() {
            return Err(ConfigError::Invalid(
                "http_forward.profiles must name at least one profile",
            ));
        }
        let defaults = tunnel_mcp::McpLimits::default();
        let response = self
            .response_body_bytes
            .unwrap_or(defaults.sse_response_body());
        let limits = tunnel_mcp::McpLimits::new(
            self.request_body_bytes.unwrap_or(defaults.request_body()),
            response.min(defaults.json_response_body()),
            response,
        )
        .map_err(|_| {
            ConfigError::Invalid(
                "http_forward body limits must be 1..=16MiB (request) and 1..=1GiB (response)",
            )
        })?;
        let mut bridge = tunnel_http_bridge::BridgeConfig::default();
        if let Some(seconds) = self.deadline_seconds {
            bridge = bridge
                .with_deadline(Duration::from_secs(seconds))
                .map_err(|_| {
                    ConfigError::Invalid("http_forward.deadline_seconds must be 1..=86400")
                })?;
        }
        let mut exports = crate::HttpForwardExports::new();
        for id in &self.profiles {
            let profile = tunnel_mcp::McpProfile::parse_id(id).ok_or(ConfigError::Invalid(
                "http_forward.profiles may name only mcp-2026-07-28 and mcp-2025-11-25",
            ))?;
            let policies = profile
                .policies(limits)
                .map_err(|_| ConfigError::Invalid("pinned http_forward profile is inconsistent"))?;
            exports = exports
                .with_profile(
                    profile.id(),
                    crate::HttpForwardExport::new(Arc::new(policies), bridge),
                )
                .map_err(|_| ConfigError::Invalid("http_forward.profiles repeats a profile"))?;
        }
        Ok(exports)
    }
}

impl ServeConfig {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)
            .map_err(|error| ConfigError::Toml(toml_error_summary(&error, input)))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.oidc_issuer.trim().is_empty()
            || self.oidc_audience.is_empty()
            || self.redis_namespace.trim().is_empty()
            || self.deployment_incarnation.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "oidc issuer, audience, Redis settings, and deployment incarnation are required",
            ));
        }
        let redis_tls_material = RedisTlsMaterialPaths {
            root_ca_path: self.redis_tls_root_ca_path.clone(),
            client_cert_path: self.redis_tls_client_cert_path.clone(),
            client_key_path: self.redis_tls_client_key_path.clone(),
        };
        redis_tls_material
            .validate_shape()
            .map_err(ConfigError::Invalid)?;
        if redis_tls_material.is_configured() && !self.redis_url.starts_with("rediss://") {
            return Err(ConfigError::Invalid(
                "Redis TLS material requires a rediss:// URL",
            ));
        }
        validate_redis_endpoint(&self.redis_url)?;
        if self.redis_namespace.len() > 128 {
            return Err(ConfigError::Invalid(
                "redis_namespace must be at most 128 bytes",
            ));
        }
        // The Redis authority owns this rule and previously applied it only
        // once `connect` ran, after `serve` had already read JWKS material and
        // was about to bind both listeners.  Applying it here means an
        // unusable namespace fails configuration validation instead of startup,
        // and the read-only dry run reaches the same verdict with no network.
        validate_redis_namespace(&self.redis_namespace).map_err(|_| {
            ConfigError::Invalid(
                "redis_namespace must contain 1..=96 ASCII letters, digits, dots, hyphens, or underscores",
            )
        })?;
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
        if self.max_pending_operations_per_owner == 0
            || self.max_pending_operations_per_owner > MAX_PENDING_OPERATIONS_PER_OWNER_CEILING
        {
            return Err(ConfigError::Invalid(
                "max_pending_operations_per_owner must be 1..=128",
            ));
        }
        if self.max_queue_bytes < 256 * 1024 || self.max_queue_bytes > 64 * 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "max_queue_bytes must be 256KiB..=64MiB",
            ));
        }
        self.rotation.validate().map_err(ConfigError::Rotation)?;
        if let Some(cluster) = &self.cluster {
            cluster.validate_for_serve(
                &self.node_id,
                &self.boot_id,
                &self.redis_namespace,
                &self.deployment_incarnation,
            )?;
        }
        if let Some(recovery) = &self.recovery {
            recovery.validate()?;
            let selected_tls = RedisTlsMaterialPaths {
                root_ca_path: recovery
                    .redis_tls_root_ca_path
                    .clone()
                    .or_else(|| self.redis_tls_root_ca_path.clone()),
                client_cert_path: recovery
                    .redis_tls_client_cert_path
                    .clone()
                    .or_else(|| self.redis_tls_client_cert_path.clone()),
                client_key_path: recovery
                    .redis_tls_client_key_path
                    .clone()
                    .or_else(|| self.redis_tls_client_key_path.clone()),
            };
            selected_tls
                .validate_shape()
                .map_err(ConfigError::Invalid)?;
            let selected_url = recovery.redis_url.as_deref().unwrap_or(&self.redis_url);
            if selected_tls.is_configured() && !selected_url.starts_with("rediss://") {
                return Err(ConfigError::Invalid(
                    "recovery Redis TLS material requires a rediss:// URL",
                ));
            }
            validate_redis_endpoint(selected_url)?;
        }
        if let Some(http_forward) = &self.http_forward {
            http_forward.exports()?;
        }
        Ok(())
    }

    /// The listener options `serve` uses: default socket options plus the
    /// configured `http-forward/1` profiles.  No fixture interposer can be
    /// expressed in configuration.
    ///
    /// # Errors
    /// An invalid `[http_forward]` table.
    pub fn listener_options(&self) -> Result<crate::ListenerSocketOptions, ConfigError> {
        Ok(crate::ListenerSocketOptions {
            http_forward: self
                .http_forward
                .as_ref()
                .map(HttpForwardServeConfig::exports)
                .transpose()?,
            ..crate::ListenerSocketOptions::default()
        })
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
        if self.cluster.is_some() {
            return Err(crate::RelayError::Config(
                "cluster configuration requires ServeConfig::start_with_peer after membership bootstrap"
                    .to_owned(),
            ));
        }
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
        options.limits.max_pending_operations_per_owner = self.max_pending_operations_per_owner;
        options.limits.max_queue_bytes = self.max_queue_bytes;
        options.rotation = self.rotation.clone();
        let listener_options = self
            .listener_options()
            .map_err(|error| crate::RelayError::Config(error.to_string()))?;
        crate::Relay::start_with_listener_options(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
            listener_options,
        )
        .await
    }

    /// Start a cluster-configured relay after the caller has completed the
    /// external checkpoint/membership bootstrap and constructed the private
    /// peer transport. Keeping those trust-boundary inputs explicit prevents
    /// Redis or a config file from silently enrolling a relay.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_peer(
        &self,
        options: RelayOptions,
        catalog: tunnel_catalog::SharedCatalog,
        consumer_listener: TcpListener,
        device_listener: TcpListener,
        consumer_tls: Arc<rustls::ServerConfig>,
        device_tls: Arc<rustls::ServerConfig>,
        peer: crate::PeerListenerConfig,
        peer_runtime: Arc<crate::PeerRuntime>,
    ) -> Result<crate::RunningRelay, crate::RelayError> {
        self.start_with_peer_and_listener_options(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
            peer,
            peer_runtime,
            self.listener_options()
                .map_err(|error| crate::RelayError::Config(error.to_string()))?,
        )
        .await
    }

    /// Start a cluster-configured relay with explicit accepted public
    /// listener socket options.  The normal [`Self::start_with_peer`] path
    /// leaves operating-system socket defaults unchanged.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_peer_and_listener_options(
        &self,
        options: RelayOptions,
        catalog: tunnel_catalog::SharedCatalog,
        consumer_listener: TcpListener,
        device_listener: TcpListener,
        consumer_tls: Arc<rustls::ServerConfig>,
        device_tls: Arc<rustls::ServerConfig>,
        peer: crate::PeerListenerConfig,
        peer_runtime: Arc<crate::PeerRuntime>,
        listener_options: crate::ListenerSocketOptions,
    ) -> Result<crate::RunningRelay, crate::RelayError> {
        let mut listener_options = listener_options;
        if listener_options.http_forward.is_none() {
            listener_options.http_forward = self
                .listener_options()
                .map_err(|error| crate::RelayError::Config(error.to_string()))?
                .http_forward;
        }
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
        options.limits.max_pending_operations_per_owner = self.max_pending_operations_per_owner;
        options.limits.max_queue_bytes = self.max_queue_bytes;
        options.rotation = self.rotation.clone();
        options.cluster = self.cluster.clone();
        crate::Relay::start_with_peer_and_listener_options(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
            peer,
            peer_runtime,
            listener_options,
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

fn default_max_pending_operations_per_owner() -> usize {
    DEFAULT_MAX_PENDING_OPERATIONS_PER_OWNER
}

fn default_max_queue_bytes() -> usize {
    4 * 1024 * 1024
}

const MAX_CLUSTER_AUTHORIZED_NODES: usize = 32;
const MAX_CLUSTER_RECORD_LIFETIME_SECONDS: u64 = 60;
const MAX_CLUSTER_REFRESH_SECONDS: u64 = 20;
const MAX_CLUSTER_RECONCILE_SECONDS: u64 = 5;
const MAX_CLUSTER_IDLE_TIMEOUT_SECONDS: u64 = 60;
const MAX_CLUSTER_DRAIN_SECONDS: u64 = 30;
const MAX_CLUSTER_CHECKPOINT_TIMEOUT_SECONDS: u64 = 2;
const MAX_CLUSTER_CLOCK_SKEW_SECONDS: u64 = 1;

fn default_membership_record_lifetime_seconds() -> u64 {
    MAX_CLUSTER_RECORD_LIFETIME_SECONDS
}

fn default_membership_refresh_seconds() -> u64 {
    MAX_CLUSTER_REFRESH_SECONDS
}

fn default_membership_reconcile_seconds() -> u64 {
    MAX_CLUSTER_RECONCILE_SECONDS
}

fn default_peer_idle_timeout_seconds() -> u64 {
    MAX_CLUSTER_IDLE_TIMEOUT_SECONDS
}

fn default_peer_drain_timeout_seconds() -> u64 {
    MAX_CLUSTER_DRAIN_SECONDS
}

fn default_checkpoint_timeout_seconds() -> u64 {
    MAX_CLUSTER_CHECKPOINT_TIMEOUT_SECONDS
}

fn default_cluster_clock_skew_seconds() -> u64 {
    MAX_CLUSTER_CLOCK_SKEW_SECONDS
}

fn bounded_cluster_seconds(
    value: u64,
    minimum: u64,
    maximum: u64,
    message: &'static str,
) -> Result<(), ConfigError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigError::Invalid(message));
    }
    Ok(())
}

fn validate_cluster_identifier(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ConfigError::Invalid(field));
    }
    Ok(())
}

fn validate_config_path(path: &Path, field: &'static str) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::Invalid(field));
    }
    Ok(())
}

fn validate_https_endpoint(endpoint: &str) -> Result<(), ConfigError> {
    if endpoint.is_empty()
        || endpoint.len() > 2_048
        || endpoint
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ConfigError::Invalid(
            "cluster.checkpoint_authority_endpoint must be a bounded HTTPS URL",
        ));
    }
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return Err(ConfigError::Invalid(
            "cluster.checkpoint_authority_endpoint must use https://",
        ));
    };
    if rest.is_empty() || rest.contains('?') || rest.contains('#') {
        return Err(ConfigError::Invalid(
            "cluster.checkpoint_authority_endpoint must contain an authority without query or fragment",
        ));
    }

    let authority_end = rest.find(['/', '?', '#']);
    let authority_end = authority_end.unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return Err(ConfigError::Invalid(
            "cluster.checkpoint_authority_endpoint must not contain credentials",
        ));
    }

    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(end) = bracketed.find(']') else {
            return Err(ConfigError::Invalid(
                "cluster.checkpoint_authority_endpoint has an invalid IPv6 host",
            ));
        };
        let host = &bracketed[..end];
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(ConfigError::Invalid(
                "cluster.checkpoint_authority_endpoint has an invalid IPv6 host",
            ));
        }
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            443
        } else {
            let Some(port) = suffix.strip_prefix(':') else {
                return Err(ConfigError::Invalid(
                    "cluster.checkpoint_authority_endpoint has an invalid port",
                ));
            };
            parse_nonzero_port(port)?
        };
        (host, port)
    } else {
        if authority.matches(':').count() > 1 {
            return Err(ConfigError::Invalid(
                "cluster.checkpoint_authority_endpoint must bracket an IPv6 host",
            ));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, parse_nonzero_port(port)?),
            None => (authority, 443),
        };
        if !validate_endpoint_host(host) {
            return Err(ConfigError::Invalid(
                "cluster.checkpoint_authority_endpoint has an invalid host",
            ));
        }
        (host, port)
    };

    let _ = (host, port);
    Ok(())
}

/// Validate the Redis endpoint at the serving boundary.
///
/// The catalog crate also has a low-level constructor used by the disposable
/// local Redis harness.  Keeping that constructor transport-agnostic lets the
/// harness use an ephemeral plaintext Redis process without making plaintext a
/// supported relay deployment profile.  `ServeConfig` is the production
/// boundary, so a relay can only start when Redis TLS is selected explicitly.
fn validate_redis_endpoint(endpoint: &str) -> Result<(), ConfigError> {
    if endpoint.is_empty()
        || endpoint.len() > 2_048
        || endpoint
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ConfigError::Invalid(
            "redis_url must be a bounded rediss:// URL",
        ));
    }
    let Some(authority) = endpoint.strip_prefix("rediss://") else {
        return Err(ConfigError::Invalid(
            "redis_url must use rediss://; plaintext redis:// is only supported by the disposable local test harness, not relay serve",
        ));
    };
    if authority.is_empty() || authority.contains('#') {
        return Err(ConfigError::Invalid(
            "redis_url must be a bounded rediss:// URL with an authority",
        ));
    }
    Ok(())
}

fn parse_nonzero_port(value: &str) -> Result<u16, ConfigError> {
    let port = value.parse::<u16>().map_err(|_| {
        ConfigError::Invalid("cluster endpoint ports must be decimal values in 1..=65535")
    })?;
    if port == 0 {
        return Err(ConfigError::Invalid(
            "cluster endpoint ports must be decimal values in 1..=65535",
        ));
    }
    Ok(port)
}

fn validate_endpoint_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 255
        || host.contains('%')
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric()
                    || (byte == b'-' && index > 0 && index + 1 < label.len())
            })
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
    })
}

fn validate_server_name(server_name: &str) -> bool {
    validate_endpoint_host(server_name)
}

#[derive(Debug)]
pub enum ConfigError {
    Toml(TomlErrorSummary),
    Rotation(CoreConfigError),
    Invalid(&'static str),
}

/// A redacted TOML failure suitable for operator diagnostics.
///
/// `toml::de::Error` retains the complete input and its `Display` output
/// includes the source line.  Relay configuration can contain credentials or
/// private paths, so the executable keeps only a bounded category, an
/// allow-listed field name when one is available, and a byte-derived location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TomlErrorSummary {
    category: &'static str,
    field: Option<String>,
    line: Option<usize>,
    column: Option<usize>,
}

fn toml_error_summary(error: &toml::de::Error, input: &str) -> TomlErrorSummary {
    let message = error.message();
    let (category, field) = if let Some(field) = extract_toml_field(message, "unknown field") {
        ("unknown field", Some(field))
    } else if let Some(field) = extract_toml_field(message, "missing field") {
        ("missing field", Some(field))
    } else if let Some(field) = extract_toml_field(message, "duplicate field") {
        ("duplicate field", Some(field))
    } else if message.starts_with("invalid type") {
        ("invalid type", None)
    } else if message.starts_with("invalid value") {
        ("invalid value", None)
    } else if message.starts_with("invalid length") {
        ("invalid length", None)
    } else {
        ("syntax or deserialization error", None)
    };
    let (line, column) = error
        .span()
        .map(|span| toml_error_location(input, span.start))
        .unwrap_or((None, None));
    TomlErrorSummary {
        category,
        field,
        line,
        column,
    }
}

fn extract_toml_field(message: &str, prefix: &str) -> Option<String> {
    let rest = message.strip_prefix(prefix)?.trim_start();
    let quote = rest.as_bytes().first().copied()?;
    if !matches!(quote, b'`' | b'\'') {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find(char::from(quote))?;
    let field = &rest[..end];
    if field.is_empty()
        || field.len() > 128
        || !field
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return None;
    }
    Some(field.to_owned())
}

fn toml_error_location(input: &str, offset: usize) -> (Option<usize>, Option<usize>) {
    let bytes = input.as_bytes();
    let offset = offset.min(bytes.len());
    let prefix = &bytes[..offset];
    let line = prefix.iter().filter(|byte| **byte == b'\n').count() + 1;
    let column = prefix
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(offset, |newline| offset.saturating_sub(newline + 1))
        + 1;
    (Some(line), Some(column))
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Toml(error) => {
                write!(formatter, "invalid relay TOML: {}", error.category)?;
                if let Some(field) = &error.field {
                    write!(formatter, " `{field}`")?;
                }
                if let (Some(line), Some(column)) = (error.line, error.column) {
                    write!(formatter, " at line {line}, column {column}")?;
                }
                Ok(())
            }
            Self::Rotation(error) => write!(formatter, "invalid rotation policy: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Toml(_) => None,
            Self::Rotation(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_catalog::{ApprovedJwk, OidcConfig, OidcVerifier};

    fn oidc() -> Arc<OidcVerifier> {
        // A placeholder Ed25519 public key: these tests never validate a
        // token, and an HMAC secret can no longer be approved as an RSA key.
        let key = ApprovedJwk::from_ed25519_der("test", &[0_u8; 32]).expect("test key");
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
redis_url = "rediss://redis.example.test:6379/0"
redis_namespace = "agent-tunnel-test"
deployment_incarnation = "test-incarnation"
device_tls_cert_chain = "device-cert.pem"
device_tls_private_key = "device-key.pem"
device_tls_client_ca = "device-ca.pem"
consumer_tls_cert_chain = "consumer-cert.pem"
consumer_tls_private_key = "consumer-key.pem"
"#
    }

    fn valid_cluster_toml() -> String {
        format!(
            "{}\nnode_id = \"relay-a\"\n\n[cluster]\ndeployment_id = \"deployment-a\"\npeer_bind = \"127.0.0.1:8443\"\npeer_tls_cert_chain = \"peer-cert.pem\"\npeer_tls_private_key = \"peer-key.pem\"\npeer_tls_client_ca = \"peer-ca.pem\"\nmembership_signer_public_key_path = \"membership-signer.pub\"\nmembership_signer_trust_path = \"membership-trust.pem\"\ncheckpoint_authority_endpoint = \"https://checkpoint.example.test/v1/checkpoint\"\ncheckpoint_authority_trust_path = \"checkpoint-ca.pem\"\nmembership_version_state_path = \"state/membership-version-state.json\"\n\n[cluster.endpoint_policy]\nallowed_ports = [8443]\nrequire_private_ip = true\n",
            valid_toml()
        )
    }

    #[test]
    fn http_forward_profiles_are_pinned_configured_and_otherwise_absent() {
        let config = ServeConfig::parse(valid_toml()).expect("valid");
        assert!(config.http_forward.is_none());
        assert!(config.listener_options().unwrap().http_forward.is_none());
        let configured = format!(
            "{}\n[http_forward]\nprofiles = [\"mcp-2026-07-28\", \"mcp-2025-11-25\"]\nrequest_body_bytes = 65536\ndeadline_seconds = 60\n",
            valid_toml()
        );
        let config = ServeConfig::parse(&configured).expect("http_forward parses");
        let options = config.listener_options().unwrap();
        let exports = options.http_forward.expect("exports");
        assert_eq!(
            exports.profile_ids().collect::<Vec<_>>(),
            vec!["mcp-2025-11-25", "mcp-2026-07-28"]
        );
        assert!(
            !exports.has_fixture_interposer(),
            "configuration cannot attach a hold"
        );
        let selected = exports
            .select(&serde_json::json!({"http_forward_profile": "mcp-2026-07-28"}))
            .expect("selected");
        assert_eq!(selected.profile.request.body_limit(), 65_536);
        assert_eq!(selected.config.deadline(), Duration::from_secs(60));
        for broken in [
            "[http_forward]\nprofiles = []\n",
            "[http_forward]\nprofiles = [\"mcp-2024-11-05\"]\n",
            "[http_forward]\nprofiles = [\"fixture\"]\n",
            "[http_forward]\nprofiles = [\"mcp-2026-07-28\", \"mcp-2026-07-28\"]\n",
            "[http_forward]\nprofiles = [\"mcp-2026-07-28\"]\nrequest_body_bytes = 0\n",
            "[http_forward]\nprofiles = [\"mcp-2026-07-28\"]\nresponse_body_bytes = 2000000000\n",
            "[http_forward]\nprofiles = [\"mcp-2026-07-28\"]\ndeadline_seconds = 0\n",
            "[http_forward]\nprofiles = [\"mcp-2026-07-28\"]\nfixture_hold = true\n",
        ] {
            let input = format!("{}\n{broken}", valid_toml());
            assert!(ServeConfig::parse(&input).is_err(), "{broken}");
        }
    }

    #[test]
    fn per_owner_admission_bound_defaults_below_the_relay_global_bound() {
        let limits = RelayLimits::default();
        limits.validate().expect("default limits validate");
        assert_eq!(
            limits.max_pending_operations_per_owner,
            DEFAULT_MAX_PENDING_OPERATIONS_PER_OWNER
        );
        assert!(
            limits.max_pending_operations_per_owner < limits.max_pending_operations,
            "the per-owner bound must leave relay-global capacity for other tenants"
        );
        assert!(
            limits.max_pending_operations_per_owner <= MAX_PENDING_OPERATIONS_PER_OWNER_CEILING,
            "the per-owner bound must respect its hard ceiling"
        );
    }

    #[test]
    fn default_limits_keep_the_per_device_stream_allowance_reachable() {
        // A single device holding one in-flight operation per stream needs as
        // many per-owner admission permits as its stream allowance; the
        // defaults shipped 48 permits against 64 streams, so the configured
        // saturation workload refused an authorized consumer with 429.
        let limits = RelayLimits::default();
        assert!(
            limits.max_pending_operations_per_owner >= limits.max_streams_per_device,
            "default per-owner admission bound {} must not sit below the default stream allowance {}",
            limits.max_pending_operations_per_owner,
            limits.max_streams_per_device
        );
        assert!(
            limits.max_pending_operations >= limits.max_pending_operations_per_owner,
            "the relay-global bound must be able to grant the per-owner bound"
        );
    }

    #[test]
    fn per_owner_admission_bound_rejects_zero_and_above_the_ceiling() {
        let limits = |max_pending_operations_per_owner| RelayLimits {
            max_pending_operations_per_owner,
            ..RelayLimits::default()
        };
        for invalid in [0, MAX_PENDING_OPERATIONS_PER_OWNER_CEILING + 1] {
            let error = limits(invalid)
                .validate()
                .expect_err("accepted an out-of-range per-owner admission bound");
            assert_eq!(
                error.to_string(),
                "max_pending_operations_per_owner must be 1..=128"
            );
        }
        for valid in [
            RelayLimits::default().max_streams_per_device,
            MAX_PENDING_OPERATIONS_PER_OWNER_CEILING,
        ] {
            limits(valid)
                .validate()
                .expect("in-range per-owner bound validates");
        }
        // A deployment may deliberately choose a lower per-owner bound as
        // backpressure; only the defaults must keep the documented per-device
        // stream allowance reachable, which the test below pins.
        limits(1)
            .validate()
            .expect("a deliberate lower bound validates");
    }

    #[test]
    fn serve_config_defaults_and_validates_the_per_owner_admission_bound() {
        let config = ServeConfig::parse(valid_toml()).expect("valid serve configuration");
        assert_eq!(
            config.max_pending_operations_per_owner,
            DEFAULT_MAX_PENDING_OPERATIONS_PER_OWNER
        );
        let configured = format!("{}max_pending_operations_per_owner = 96\n", valid_toml());
        let config = ServeConfig::parse(&configured).expect("explicit per-owner bound parses");
        assert_eq!(config.max_pending_operations_per_owner, 96);
        for invalid in ["0", "129"] {
            let input = format!(
                "{}max_pending_operations_per_owner = {invalid}\n",
                valid_toml()
            );
            let error = ServeConfig::parse(&input)
                .expect_err("accepted an out-of-range per-owner admission bound");
            assert_eq!(
                error.to_string(),
                "max_pending_operations_per_owner must be 1..=128"
            );
        }
    }

    #[test]
    fn serve_defaults_to_shared_rotation_policy() {
        let config = ServeConfig::parse(valid_toml()).expect("valid serve configuration");
        assert_eq!(config.rotation, RotationConfig::default());
    }

    /// The original M7-C35 breakage: the serving parser accepted a namespace
    /// the Redis authority refuses, so `serve` read JWKS material and bound
    /// both listeners before failing at `connect`.
    #[test]
    fn serve_rejects_a_namespace_the_redis_authority_refuses() {
        for rejected in [
            // The namespace `examples/m1-relay.toml` actually shipped.
            "agent-tunnel/m1".to_owned(),
            "agent:tunnel".to_owned(),
            "agent*tunnel".to_owned(),
            "agent tunnel".to_owned(),
            "n".repeat(tunnel_catalog::MAX_REDIS_NAMESPACE_BYTES + 1),
        ] {
            let input = namespace_toml(&rejected);
            let error = match ServeConfig::parse(&input) {
                Ok(_) => panic!("namespace {rejected:?} must be rejected before serve binds"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("redis_namespace"),
                "the failure for {rejected:?} must name the field: {error}"
            );
        }

        // The corrected example namespace and the other key-safe characters
        // must still parse, so the rule cannot be satisfied by rejecting
        // everything.
        for accepted in ["agent-tunnel-m1", "agent_tunnel.m1", "AgentTunnel0"] {
            ServeConfig::parse(&namespace_toml(accepted))
                .unwrap_or_else(|error| panic!("namespace {accepted:?} must parse: {error}"));
        }
    }

    fn namespace_toml(namespace: &str) -> String {
        valid_toml().replace(
            "redis_namespace = \"agent-tunnel-test\"",
            &format!("redis_namespace = \"{namespace}\""),
        )
    }

    #[test]
    fn serve_requires_tls_for_redis_authority() {
        let input = valid_toml().replace(
            "rediss://redis.example.test:6379/0",
            "redis://127.0.0.1:6379/0",
        );
        let error = ServeConfig::parse(&input).expect_err("accepted plaintext Redis URL");
        assert!(error.to_string().contains("must use rediss://"));
        assert!(error.to_string().contains("disposable local test harness"));
    }

    #[test]
    fn serve_rejects_partial_redis_tls_client_identity_paths() {
        let input = format!(
            "{}\nredis_tls_client_cert_path = \"client-cert.pem\"",
            valid_toml()
        );
        let error =
            ServeConfig::parse(&input).expect_err("accepted a partial Redis client identity");
        assert!(
            error
                .to_string()
                .contains("Redis client certificate and private key must be supplied together")
        );
    }

    #[test]
    fn serve_rejects_plaintext_with_redis_tls_material_at_config_check() {
        let input = format!(
            "{}\nredis_tls_root_ca_path = \"missing-ca.pem\"",
            valid_toml().replace(
                "rediss://redis.example.test:6379/0",
                "redis://127.0.0.1:6379/0",
            )
        );
        let error = ServeConfig::parse(&input)
            .expect_err("accepted plaintext Redis with configured TLS material");
        assert!(
            error
                .to_string()
                .contains("Redis TLS material requires a rediss:// URL")
        );
    }

    #[test]
    fn serve_rejects_malformed_tls_redis_urls() {
        for redis_url in [
            "rediss://",
            "rediss://redis.example.test#fragment",
            "rediss://redis.example.test\n",
        ] {
            let input = valid_toml().replace("rediss://redis.example.test:6379/0", redis_url);
            assert!(
                ServeConfig::parse(&input).is_err(),
                "accepted malformed Redis URL {redis_url:?}"
            );
        }
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

    #[test]
    fn serve_rejects_unsupported_database_url_fields_as_unknown_toml_fields() {
        for field in ["sqlite_url", "database_url", "postgres_url"] {
            let input = format!("{}\n{field} = \"unsupported\"", valid_toml());
            let error = ServeConfig::parse(&input)
                .expect_err("accepted an unsupported database URL configuration field");
            let message = error.to_string();
            assert!(
                message.contains("unknown field"),
                "{field} did not fail as an unknown TOML field: {message}"
            );
            assert!(
                message.contains(field),
                "{field} was not named in its unknown-field error: {message}"
            );
        }
    }

    #[test]
    fn serve_toml_errors_redact_source_lines_and_values() {
        let secret = "startup-config-secret-value";
        let inputs = [
            format!("{}\nunknown_startup_field = \"{secret}\"", valid_toml()),
            format!("oidc_issuer = \"{secret}\n"),
        ];
        for input in inputs {
            let error = ServeConfig::parse(&input).expect_err("accepted malformed TOML");
            let message = error.to_string();
            assert!(
                message.starts_with("invalid relay TOML:"),
                "missing stable TOML category: {message}"
            );
            assert!(
                message.contains("line ") && message.contains("column "),
                "missing bounded TOML location: {message}"
            );
            assert!(
                !message.contains(secret),
                "TOML diagnostic leaked the source value: {message}"
            );
            assert!(
                !message.contains("|"),
                "TOML diagnostic retained a source-line rendering: {message}"
            );
        }
    }

    #[test]
    fn legacy_configuration_remains_cluster_free_and_accepts_boot_id() {
        let config = ServeConfig::parse(&format!(
            "{}\nboot_id = \"legacy-configured-boot\"",
            valid_toml()
        ))
        .expect("legacy M1/M2 configuration");
        assert!(config.cluster.is_none());
        assert_eq!(config.boot_id, "legacy-configured-boot");
    }

    #[test]
    fn cluster_configuration_uses_documented_defaults() {
        let config = ServeConfig::parse(&valid_cluster_toml()).expect("valid cluster config");
        let cluster = config.cluster.expect("cluster config");
        assert_eq!(
            cluster.membership_version_state_path,
            PathBuf::from("state/membership-version-state.json")
        );
        assert_eq!(cluster.membership_record_lifetime_seconds, 60);
        assert_eq!(cluster.membership_refresh_seconds, 20);
        assert_eq!(cluster.membership_reconcile_seconds, 5);
        assert_eq!(cluster.peer_idle_timeout_seconds, 60);
        assert_eq!(cluster.peer_drain_timeout_seconds, 30);
        assert_eq!(cluster.checkpoint_timeout_seconds, 2);
        assert_eq!(cluster.max_clock_skew_seconds, 1);
    }

    #[test]
    fn cluster_requires_membership_version_state_path() {
        let input = valid_cluster_toml()
            .lines()
            .filter(|line| !line.starts_with("membership_version_state_path"))
            .collect::<Vec<_>>()
            .join("\n");
        let error = ServeConfig::parse(&input).expect_err("missing membership state path");
        assert!(error.to_string().contains("membership_version_state_path"));
    }

    #[test]
    fn cluster_requires_operator_installed_membership_trust() {
        let input = valid_cluster_toml()
            .lines()
            .filter(|line| {
                !line.starts_with("membership_signer_public_key_path")
                    && !line.starts_with("membership_signer_trust_path")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let error = ServeConfig::parse(&input).expect_err("missing membership trust");
        assert!(
            error
                .to_string()
                .contains("membership signer public-key or trust-bundle path")
        );
    }

    #[test]
    fn direct_membership_public_key_requires_an_explicit_key_id() {
        let input = valid_cluster_toml()
            .lines()
            .filter(|line| !line.starts_with("membership_signer_trust_path"))
            .collect::<Vec<_>>()
            .join("\n");
        let error = ServeConfig::parse(&input).expect_err("accepted an unnamed direct key");
        assert!(error.to_string().contains("membership_signer_key_id"));

        let input = input.replace(
            "[cluster]\n",
            "[cluster]\nmembership_signer_key_id = \"publisher-1\"\n",
        );
        ServeConfig::parse(&input).expect("accepted a named direct key");
    }

    #[test]
    fn cluster_requires_https_checkpoint_authority() {
        let input = valid_cluster_toml().replace(
            "https://checkpoint.example.test/v1/checkpoint",
            "http://checkpoint.example.test/v1/checkpoint",
        );
        let error = ServeConfig::parse(&input).expect_err("accepted insecure checkpoint endpoint");
        assert!(error.to_string().contains("must use https://"));
    }

    #[test]
    fn cluster_rejects_reused_legacy_boot_id() {
        let input = valid_cluster_toml().replace(
            "node_id = \"relay-a\"",
            "node_id = \"relay-a\"\nboot_id = \"reused-boot\"",
        );
        let error = ServeConfig::parse(&input).expect_err("accepted a configured cluster boot id");
        assert!(error.to_string().contains("fresh process boot_id"));
    }

    #[test]
    fn cluster_rejects_unknown_insecure_transport_keys() {
        let input = format!("{}\ntls_skip_verify = true", valid_cluster_toml());
        assert!(
            ServeConfig::parse(&input).is_err(),
            "accepted TLS skip flag"
        );

        let input = format!("{}\n[cluster]\nh2_fallback = true", valid_cluster_toml());
        assert!(
            ServeConfig::parse(&input).is_err(),
            "accepted HTTP/2 fallback"
        );
    }

    #[test]
    fn cluster_rejects_node_identity_mismatch_and_invalid_policy() {
        let input = valid_cluster_toml().replace(
            "checkpoint_authority_trust_path = \"checkpoint-ca.pem\"",
            "checkpoint_authority_trust_path = \"checkpoint-ca.pem\"\nnode_id = \"relay-b\"",
        );
        let error = ServeConfig::parse(&input).expect_err("accepted a mismatched node identity");
        assert!(error.to_string().contains("cluster.node_id must match"));

        let input = valid_cluster_toml().replace("allowed_ports = [8443]", "allowed_ports = [0]");
        let error = ServeConfig::parse(&input).expect_err("accepted zero endpoint port");
        assert!(error.to_string().contains("unique and nonzero"));
    }
}
