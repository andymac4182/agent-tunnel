//! Reusable real-resource fixtures and acceptance checks for Agent Tunnel.
//! The acceptance command exercises the production relay, catalog and client
//! through authenticated sockets using isolated synthetic test identities.

#![forbid(unsafe_code)]

pub mod acceptance;
pub mod admission;
pub mod peer;
pub mod redis_restart;

mod database;
mod error;
mod fixture;
mod harness;
mod oidc;
mod pki;
mod process;
mod proxy;

pub use database::{RedisLease, RedisLeaseOptions};
pub use error::{HarnessError, Result};
pub use fixture::{
    ConsumerFixture, DeviceFixture, FixtureTopology, PrincipalFixture, TenantFixture,
};
pub use harness::{Harness, HarnessOptions, RunningHarness};
pub use oidc::{OidcClaims, OidcFixture, OidcTokenOptions};
pub use pki::{
    CertificateAuthority, CertificateMaterial, CertificateProfile, CertificateRole, FixturePki,
    Validity,
};
pub use process::{ManagedProcess, ProcessSpec};
pub use proxy::{
    Direction, FaultAction, FaultRule, FaultScript, ProxyConfig, ProxyHandle, ProxyStats, TcpProxy,
};

/// The maximum authorization snapshot age required by the M1 design.
pub const AUTHORIZATION_SNAPSHOT_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(5);

/// The five device fixture identities used by the M1 multi-tenant gate.
pub const M1_DEVICE_COUNT: usize = 5;
