//! Configuration contracts for the proposed tunnel.
//!
//! The planned transport has one control WebSocket and one data WebSocket in
//! steady state. Replacing the data socket can briefly add one socket. This
//! crate validates configuration only; it does not establish any connections.

pub mod config;

pub use config::{ClientConfig, ConfigError, RelayConfig, RotationConfig};

/// One persistent control connection plus one active data connection.
pub const STEADY_STATE_WEBSOCKETS: usize = 2;

/// The control connection, old data connection, and replacement data connection.
pub const MAX_WEBSOCKETS_DURING_ROTATION: usize = 3;
