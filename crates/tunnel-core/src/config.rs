//! Strict TOML parsing and bounded configuration values.

use serde::Deserialize;
use std::{error::Error, fmt};

/// Rotation policy. All durations are whole seconds.
///
/// `overlap_seconds` bounds coexistence from opening a replacement data socket,
/// including its handshake. An abort before commit closes the replacement;
/// after commit the old socket must close within this budget. It is not an
/// additional drain period after the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RotationConfig {
    /// Target age of a data socket before replacement; 1..=86,400 seconds.
    pub interval_seconds: u64,
    /// Replacement handshake deadline; 1..=300 seconds, less than overlap.
    pub handshake_timeout_seconds: u64,
    /// Total replacement overlap; 1..=3,600 seconds, less than the interval.
    pub overlap_seconds: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 300,
            handshake_timeout_seconds: 10,
            overlap_seconds: 30,
        }
    }
}

impl RotationConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        bounded(
            self.interval_seconds,
            86_400,
            "rotation.interval_seconds must be between 1 and 86400",
        )?;
        bounded(
            self.handshake_timeout_seconds,
            300,
            "rotation.handshake_timeout_seconds must be between 1 and 300",
        )?;
        bounded(
            self.overlap_seconds,
            3_600,
            "rotation.overlap_seconds must be between 1 and 3600",
        )?;
        if self.handshake_timeout_seconds >= self.overlap_seconds {
            return Err(ConfigError::Invalid(
                "rotation.handshake_timeout_seconds must be less than rotation.overlap_seconds",
            ));
        }
        if self.overlap_seconds >= self.interval_seconds {
            return Err(ConfigError::Invalid(
                "rotation.overlap_seconds must be less than rotation.interval_seconds",
            ));
        }
        Ok(())
    }
}

/// Local device configuration. Identity registration and authentication are
/// future work: `device_id` is a label, not a credential or authorization claim.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientConfig {
    pub device_id: String,
    pub rotation: RotationConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            device_id: "my-device".into(),
            rotation: RotationConfig::default(),
        }
    }
}

impl ClientConfig {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.device_id.is_empty()
            || self.device_id.len() > 128
            || !self
                .device_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ConfigError::Invalid(
                "device_id must contain 1 to 128 ASCII letters, digits, dots, hyphens, or underscores",
            ));
        }
        self.rotation.validate()
    }
}

/// Relay capacity policy. These limits are validated but are not enforced by a
/// server yet. Authentication must determine a device's user, not device input.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayConfig {
    pub max_connected_clients: u64,
    pub max_clients_per_user: u64,
    pub rotation: RotationConfig,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_connected_clients: 1_024,
            max_clients_per_user: 16,
            rotation: RotationConfig::default(),
        }
    }
}

impl RelayConfig {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        bounded(
            self.max_connected_clients,
            1_000_000,
            "max_connected_clients must be between 1 and 1000000",
        )?;
        bounded(
            self.max_clients_per_user,
            10_000,
            "max_clients_per_user must be between 1 and 10000",
        )?;
        if self.max_clients_per_user > self.max_connected_clients {
            return Err(ConfigError::Invalid(
                "max_clients_per_user must not exceed max_connected_clients",
            ));
        }
        self.rotation.validate()
    }
}

fn bounded(value: u64, maximum: u64, message: &'static str) -> Result<(), ConfigError> {
    if value == 0 || value > maximum {
        Err(ConfigError::Invalid(message))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Parse(toml::de::Error),
    Invalid(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "invalid TOML configuration: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(error: toml::de::Error) -> Self {
        Self::Parse(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_configuration_uses_five_minute_rotation() {
        let client = ClientConfig::parse("").unwrap();
        let relay = RelayConfig::parse("").unwrap();
        assert_eq!(client.rotation.interval_seconds, 300);
        assert_eq!(client.rotation.handshake_timeout_seconds, 10);
        assert_eq!(client.rotation.overlap_seconds, 30);
        assert_eq!(client.rotation, relay.rotation);
        assert_eq!(relay.max_clients_per_user, 16);
        assert_eq!(relay.max_connected_clients, 1_024);
    }

    #[test]
    fn supports_partial_rotation_overrides() {
        let config = ClientConfig::parse("[rotation]\ninterval_seconds = 600").unwrap();
        assert_eq!(config.rotation.interval_seconds, 600);
        assert_eq!(config.rotation.handshake_timeout_seconds, 10);
        assert_eq!(config.rotation.overlap_seconds, 30);
    }

    #[test]
    fn rejects_invalid_timing_and_overflow_inputs() {
        for input in [
            "interval_seconds = 0",
            "interval_seconds = -1",
            "interval_seconds = 86401",
            "interval_seconds = 9223372036854775807",
            "interval_seconds = 18446744073709551616",
            "interval_seconds = 1.5",
            "handshake_timeout_seconds = 0",
            "handshake_timeout_seconds = 301",
            "overlap_seconds = 0",
            "overlap_seconds = 3601",
            "handshake_timeout_seconds = 30",
            "handshake_timeout_seconds = 31",
            "interval_seconds = 30",
            "interval_seconds = 29",
        ] {
            assert!(
                ClientConfig::parse(&format!("[rotation]\n{input}")).is_err(),
                "accepted {input}"
            );
        }
    }

    #[test]
    fn accepts_valid_boundary_timings() {
        for input in [
            "interval_seconds = 3\nhandshake_timeout_seconds = 1\noverlap_seconds = 2",
            "interval_seconds = 86400\nhandshake_timeout_seconds = 300\noverlap_seconds = 3600",
        ] {
            ClientConfig::parse(&format!("[rotation]\n{input}")).unwrap();
        }
    }

    #[test]
    fn catches_unknown_keys_and_invalid_toml() {
        for input in [
            "rotation_seconds = 300",
            "[rotation]\ninterval_second = 300",
            "device_id = 'one'\ndevice_id = 'two'",
            "[rotation",
        ] {
            assert!(ClientConfig::parse(input).is_err(), "accepted {input}");
        }
        assert!(RelayConfig::parse("max_client_per_user = 16").is_err());
    }

    #[test]
    fn rejects_invalid_device_labels() {
        for label in ["", "../private/data", "my device", "🦀"] {
            let config = ClientConfig {
                device_id: label.into(),
                ..ClientConfig::default()
            };
            assert!(config.validate().is_err(), "accepted {label}");
        }
        let config = ClientConfig {
            device_id: "a".repeat(129),
            ..ClientConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_excessive_and_inconsistent_capacity_limits() {
        for input in [
            "max_connected_clients = 0",
            "max_connected_clients = -1",
            "max_connected_clients = 1000001",
            "max_clients_per_user = 0",
            "max_clients_per_user = 10001",
            "max_clients_per_user = 1025",
            "max_connected_clients = 18446744073709551616",
        ] {
            assert!(RelayConfig::parse(input).is_err(), "accepted {input}");
        }
        RelayConfig::parse("max_connected_clients = 1\nmax_clients_per_user = 1").unwrap();
    }

    #[test]
    fn checked_in_examples_remain_valid() {
        ClientConfig::parse(include_str!("../../../examples/client.toml")).unwrap();
        RelayConfig::parse(include_str!("../../../examples/relay.toml")).unwrap();
    }
}
