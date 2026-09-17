//! Operator configuration of one ACP export, embedded in the device runtime
//! configuration as `[exports.<service>.acp]` (M8 chunk 3).
//!
//! ```toml
//! [exports.00000000-0000-4000-8000-000000000001]
//! type = "http-forward"
//!
//! [exports.00000000-0000-4000-8000-000000000001.acp]
//! profile = "acp-http-v1"
//!
//! [exports.00000000-0000-4000-8000-000000000001.acp.agent]
//! command = "/opt/acp/bin/agent"
//! args = ["agent"]
//! workspace = "/srv/acp-workspace"
//! inherit_env = ["LANG"]
//! env = { AGENT_MODE = "synthetic" }
//! ```
//!
//! Nothing here is selectable by a consumer.  `docs/acp.md`: "Host HTTP input
//! cannot install agents, select an executable, add arguments, inject
//! environment, or switch workspaces."  The relay's OPEN names only the
//! export; every other field comes from this file.
//!
//! The shape follows `tunnel_mcp_export::config` deliberately, so an operator
//! who has written one of these has written the other.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tunnel_acp::{AcpLimits, AcpProfile};

/// The most arguments the agent command may have.
pub const MAX_ARGS: usize = 64;
/// The longest argument or environment value, in bytes.
pub const MAX_ARG_LEN: usize = 4096;
/// The most explicit plus inherited environment variables.
pub const MAX_ENV: usize = 64;

/// `docs/acp.md`: "Require the connection GET within 10 seconds of
/// initialization and a session GET within 10 seconds of its creation."
pub const DEFAULT_SUBSCRIBE_DEADLINE_MS: u64 = 10_000;
/// The ceiling on that deadline.  There is no unlimited value.
pub const MAX_SUBSCRIBE_DEADLINE_MS: u64 = 600_000;
/// `docs/acp.md`: 60 seconds, then cancel the prompt and the pending
/// permission.
pub const DEFAULT_PERMISSION_TIMEOUT_MS: u64 = 60_000;
/// The ceiling on the permission deadline.
pub const MAX_PERMISSION_TIMEOUT_MS: u64 = 3_600_000;
/// `docs/acp.md`: 8 sessions per ACP connection.
pub const DEFAULT_SESSION_LIMIT: usize = tunnel_acp::lifecycle::MAX_SESSIONS_PER_CONNECTION;
/// `docs/acp.md`: 1 MiB, rejected before unbounded reassembly.
pub const DEFAULT_MESSAGE_LIMIT: u64 = 1 << 20;
/// The stderr diagnostic sink's cap.
pub const DEFAULT_STDERR_CAP: u64 = 1 << 20;

/// One ACP export.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpExportConfig {
    /// `acp-http-v1`.  The only pinned profile (M8-01).
    pub profile: String,
    pub agent: AcpAgentConfig,
    #[serde(default)]
    pub limits: AcpLimitsConfig,
    #[serde(default)]
    pub deadlines: AcpDeadlinesConfig,
}

/// The fixed local ACP agent.  `Debug` prints no argument or environment
/// value: those may carry operator secrets.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpAgentConfig {
    /// Absolute path of the executable.  Executed directly, never through a
    /// shell.
    pub command: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    /// Absolute working directory, and the only `cwd` a session may name.
    pub workspace: PathBuf,
    /// Names copied from the connector's own environment when set.
    #[serde(default)]
    pub inherit_env: Vec<String>,
    /// Explicit environment values.  The child environment is cleared first.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl std::fmt::Debug for AcpAgentConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcpAgentConfig")
            .field("args", &self.args.len())
            .field("env_names", &self.env.keys().collect::<Vec<_>>())
            .field("inherit_env", &self.inherit_env)
            .finish_non_exhaustive()
    }
}

/// Optional overrides of the profile's finite body limits.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpLimitsConfig {
    pub request_body_bytes: Option<u64>,
    pub json_response_bytes: Option<u64>,
    pub sse_response_bytes: Option<u64>,
}

/// Optional overrides of the documented deadlines.  Each is finite and
/// bounded; tests shorten them so a deadline can actually elapse.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpDeadlinesConfig {
    /// How long a connection GET has after `initialize`, and a session GET
    /// after `session/new`.
    pub subscribe_ms: Option<u64>,
    /// How long a `session/request_permission` may stay outstanding.
    pub permission_ms: Option<u64>,
}

/// A rejected ACP export configuration.  Messages are fixed strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcpConfigError(pub &'static str);

impl std::fmt::Display for AcpConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for AcpConfigError {}

/// A validated export configuration.
#[derive(Clone, Debug)]
pub struct ValidatedAcp {
    pub profile: AcpProfile,
    pub limits: AcpLimits,
    pub child: crate::child::ChildConfig,
    pub workspace: PathBuf,
    pub subscribe_deadline: Duration,
    pub permission_timeout: Duration,
    pub session_limit: usize,
}

fn absolute(path: &Path) -> bool {
    path.is_absolute() && !path.components().any(|c| c.as_os_str() == "..")
}

impl AcpExportConfig {
    /// Validate every rule this export has.
    ///
    /// # Errors
    /// The first rule violated.
    pub fn validate(&self) -> Result<ValidatedAcp, AcpConfigError> {
        let profile = AcpProfile::parse_id(&self.profile)
            .ok_or(AcpConfigError("acp.profile must be a pinned ACP profile"))?;
        let defaults = AcpLimits::default();
        let limits = AcpLimits::new(
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
        .map_err(|_| AcpConfigError("acp.limits are outside their finite bounds"))?;

        let agent = &self.agent;
        if !absolute(&agent.command) {
            return Err(AcpConfigError(
                "acp.agent.command must be an absolute path with no parent components",
            ));
        }
        if !absolute(&agent.workspace) {
            return Err(AcpConfigError(
                "acp.agent.workspace must be an absolute path with no parent components",
            ));
        }
        if agent.args.len() > MAX_ARGS {
            return Err(AcpConfigError("acp.agent.args has too many entries"));
        }
        if agent.args.iter().any(|arg| arg.len() > MAX_ARG_LEN) {
            return Err(AcpConfigError("an acp.agent argument is too long"));
        }
        if agent.env.len().saturating_add(agent.inherit_env.len()) > MAX_ENV {
            return Err(AcpConfigError("acp.agent has too many environment names"));
        }
        if agent
            .env
            .iter()
            .any(|(name, value)| name.is_empty() || value.len() > MAX_ARG_LEN)
            || agent.inherit_env.iter().any(String::is_empty)
        {
            return Err(AcpConfigError("an acp.agent environment entry is invalid"));
        }

        let subscribe_ms = self
            .deadlines
            .subscribe_ms
            .unwrap_or(DEFAULT_SUBSCRIBE_DEADLINE_MS);
        if subscribe_ms == 0 || subscribe_ms > MAX_SUBSCRIBE_DEADLINE_MS {
            return Err(AcpConfigError(
                "acp.deadlines.subscribe_ms must be 1..=600000",
            ));
        }
        let permission_ms = self
            .deadlines
            .permission_ms
            .unwrap_or(DEFAULT_PERMISSION_TIMEOUT_MS);
        if permission_ms == 0 || permission_ms > MAX_PERMISSION_TIMEOUT_MS {
            return Err(AcpConfigError(
                "acp.deadlines.permission_ms must be 1..=3600000",
            ));
        }

        Ok(ValidatedAcp {
            profile,
            limits,
            child: crate::child::ChildConfig {
                command: agent.command.clone(),
                args: agent.args.clone(),
                workspace: agent.workspace.clone(),
                inherit_env: agent.inherit_env.clone(),
                env: agent.env.clone(),
                message_limit: limits.request_body(),
                stderr_cap: DEFAULT_STDERR_CAP,
            },
            workspace: agent.workspace.clone(),
            subscribe_deadline: Duration::from_millis(subscribe_ms),
            permission_timeout: Duration::from_millis(permission_ms),
            session_limit: DEFAULT_SESSION_LIMIT,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> String {
        concat!(
            "profile = \"acp-http-v1\"\n",
            "[agent]\n",
            "command = \"/opt/acp/bin/agent\"\n",
            "args = [\"agent\"]\n",
            "workspace = \"/srv/acp-workspace\"\n",
        )
        .to_owned()
    }

    #[test]
    fn a_valid_export_validates_and_keeps_the_documented_defaults() {
        let config: AcpExportConfig = toml::from_str(&valid()).expect("parses");
        let validated = config.validate().expect("valid");
        assert_eq!(validated.profile, AcpProfile::HttpV1);
        // The documented bound, read back from the validated value rather than
        // asserted against the constant it came from.
        assert_eq!(validated.subscribe_deadline, Duration::from_secs(10));
        assert_eq!(validated.permission_timeout, Duration::from_secs(60));
        assert_eq!(validated.session_limit, 8);
    }

    #[test]
    fn every_rejected_shape_is_rejected() {
        for broken in [
            valid().replace("acp-http-v1", "acp-http-v2"),
            valid().replace("/opt/acp/bin/agent", "agent"),
            valid().replace("/srv/acp-workspace", "workspace"),
            valid().replace("/opt/acp/bin/agent", "/opt/../etc/agent"),
            format!("{}[deadlines]\nsubscribe_ms = 0\n", valid()),
            format!("{}[deadlines]\npermission_ms = 0\n", valid()),
            format!("{}[deadlines]\nsubscribe_ms = 600001\n", valid()),
            format!("{}[limits]\nrequest_body_bytes = 0\n", valid()),
        ] {
            let parsed: Result<AcpExportConfig, _> = toml::from_str(&broken);
            let rejected = match parsed {
                Err(_) => true,
                Ok(config) => config.validate().is_err(),
            };
            assert!(
                rejected,
                "accepted a configuration it must refuse:\n{broken}"
            );
        }
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let text = format!("{}surprise = true\n", valid());
        assert!(toml::from_str::<AcpExportConfig>(&text).is_err());
    }

    #[test]
    fn debug_prints_no_argument_or_environment_value() {
        let text = format!(
            "{}env = {{ SECRET_VALUE = \"synthetic-secret\" }}\n",
            valid()
        );
        let config: AcpExportConfig = toml::from_str(&text).expect("parses");
        let printed = format!("{:?}", config.agent);
        assert!(printed.contains("SECRET_VALUE"), "{printed}");
        assert!(!printed.contains("synthetic-secret"), "{printed}");
        assert!(!printed.contains("agent\""), "{printed}");
    }
}
