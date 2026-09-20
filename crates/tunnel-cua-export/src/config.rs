//! How a supervised backend is described, and what is refused before one is
//! started.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// The longest the supervisor waits for a freshly started backend to publish
/// its loopback address.
///
/// Finite, with no unlimited value: a supervisor that waited forever for a
/// backend that will never bind is a supervisor that never reports a fault.
pub const DEFAULT_STARTUP: Duration = Duration::from_secs(20);

/// Ceiling on the configurable startup wait.
pub const MAX_STARTUP: Duration = Duration::from_secs(120);

/// How often the supervisor looks for the address file.
pub const ADDRESS_POLL: Duration = Duration::from_millis(10);

/// One supervised `computer.v1` backend process.
///
/// **The address is read from the backend, never configured.** The backend
/// binds an ephemeral loopback port and publishes it; the supervisor reads it
/// back and puts it through [`tunnel_cua::endpoint::BackendEndpoint`], which
/// refuses anything that is not loopback. Configuring the address instead
/// would mean the supervisor believed a number rather than observing one, and
/// the loopback policy would be enforced against configuration rather than
/// against the process that is actually listening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendProcess {
    /// The executable. Never a shell string: nothing here goes through a
    /// shell, so nothing here can be made to interpret a metacharacter.
    pub command: PathBuf,
    /// Arguments, passed as a vector rather than split from a line.
    pub args: Vec<String>,
    /// The environment set explicitly. The child's environment is **cleared**
    /// first, so nothing leaks in that was not named.
    pub env: BTreeMap<String, String>,
    /// Names copied from this process's environment, if present.
    pub inherit_env: Vec<String>,
    /// The child's working directory.
    pub workspace: PathBuf,
    /// Where the backend publishes the loopback address it bound.
    ///
    /// **Removed by the supervisor before every start.** A stale file from the
    /// previous generation would otherwise be read as the new backend's
    /// address, and the supervisor would hand out a port belonging to a
    /// process it had just killed — or, worse, to whatever bound that port
    /// next.
    pub address_file: PathBuf,
    /// How long to wait for that address before calling the start a failure.
    pub startup: Duration,
}

/// Why a [`BackendProcess`] was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// The executable path is empty.
    NoCommand,
    /// The address file path is empty, or is the workspace itself.
    NoAddressFile,
    /// The startup wait is zero or above [`MAX_STARTUP`].
    StartupOutOfRange,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::NoCommand => "a supervised backend needs an executable",
            Self::NoAddressFile => "a supervised backend needs a distinct address file path",
            Self::StartupOutOfRange => "the startup wait must be non-zero and within its ceiling",
        })
    }
}

impl std::error::Error for ConfigError {}

impl BackendProcess {
    /// Build a validated configuration.
    ///
    /// # Errors
    /// [`ConfigError`] for an empty command, a missing or non-distinct
    /// address file, or a startup wait outside its range.
    pub fn new(
        command: PathBuf,
        args: Vec<String>,
        workspace: PathBuf,
        address_file: PathBuf,
    ) -> Result<Self, ConfigError> {
        if command.as_os_str().is_empty() {
            return Err(ConfigError::NoCommand);
        }
        if address_file.as_os_str().is_empty() || address_file == workspace {
            return Err(ConfigError::NoAddressFile);
        }
        Ok(Self {
            command,
            args,
            env: BTreeMap::new(),
            inherit_env: Vec::new(),
            workspace,
            address_file,
            startup: DEFAULT_STARTUP,
        })
    }

    /// Set the startup wait.
    ///
    /// # Errors
    /// [`ConfigError::StartupOutOfRange`] for zero or above [`MAX_STARTUP`].
    pub fn with_startup(mut self, startup: Duration) -> Result<Self, ConfigError> {
        if startup.is_zero() || startup > MAX_STARTUP {
            return Err(ConfigError::StartupOutOfRange);
        }
        self.startup = startup;
        Ok(self)
    }

    /// Name an environment variable to copy from this process, if set.
    #[must_use]
    pub fn inheriting(mut self, name: &str) -> Self {
        self.inherit_env.push(name.to_owned());
        self
    }

    /// Set an environment variable explicitly.
    #[must_use]
    pub fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_owned(), value.to_owned());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> BackendProcess {
        BackendProcess::new(
            PathBuf::from("/usr/bin/true"),
            Vec::new(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp/address"),
        )
        .expect("valid")
    }

    #[test]
    fn an_empty_command_is_refused() {
        assert_eq!(
            BackendProcess::new(
                PathBuf::new(),
                Vec::new(),
                PathBuf::from("/tmp"),
                PathBuf::from("/tmp/address"),
            ),
            Err(ConfigError::NoCommand)
        );
    }

    #[test]
    fn an_address_file_equal_to_the_workspace_is_refused() {
        // A supervisor that removed this path before every start would be
        // removing the workspace.
        assert_eq!(
            BackendProcess::new(
                PathBuf::from("/usr/bin/true"),
                Vec::new(),
                PathBuf::from("/tmp"),
                PathBuf::from("/tmp"),
            ),
            Err(ConfigError::NoAddressFile)
        );
    }

    #[test]
    fn the_startup_wait_is_bounded_in_both_directions() {
        assert_eq!(
            valid().with_startup(Duration::ZERO),
            Err(ConfigError::StartupOutOfRange)
        );
        assert_eq!(
            valid().with_startup(MAX_STARTUP + Duration::from_secs(1)),
            Err(ConfigError::StartupOutOfRange)
        );
        assert!(valid().with_startup(MAX_STARTUP).is_ok());
    }

    #[test]
    fn a_fresh_configuration_inherits_nothing_and_sets_nothing() {
        // The environment is cleared at spawn, so an empty default here is
        // the difference between "nothing" and "whatever the device had".
        let process = valid();
        assert!(process.env.is_empty());
        assert!(process.inherit_env.is_empty());
        assert_eq!(process.startup, DEFAULT_STARTUP);
    }
}
