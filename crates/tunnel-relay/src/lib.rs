//! The M1 relay runtime.
//!
//! The relay owns one bounded actor for all live device sessions.  Axum
//! handlers authenticate and validate requests, then send typed commands to
//! that actor; handlers never mutate socket or epoch state themselves.  The
//! device listener is intended to be run through `tunnel-transport`, which
//! performs mandatory mTLS and injects the verified [`tunnel_transport::TlsIdentity`]
//! extension before the WebSocket upgrade.

#![deny(unsafe_code)]

mod actor;
mod config;
mod http;
mod runtime;
mod wire;

pub use actor::{Relay, RelayError, RelayHandle, RunningRelay};
pub use config::{RelayLimits, RelayOptions, ServeConfig};
pub use http::{consumer_router, device_router, router};
pub use runtime::{RelayCarrierSnapshot, RelaySessionSnapshot, RelaySnapshot, RelayStreamSnapshot};
pub use wire::{MAX_BODY_BYTES, MAX_CONTROL_BYTES};

/// Protocol major supported by this relay.
pub const PROTOCOL_MAJOR: u8 = 1;
/// The one M1 application export.  Later adapters add their own negotiated
/// feature names; the relay never accepts an executable or URL from a peer.
pub const ECHO_SERVICE_TYPE: &str = "echo";
/// The fixed operation name used by the echo grant.
pub const ECHO_OPERATION: &str = "echo:invoke";
