//! Reusable real-resource fixtures and acceptance checks for Agent Tunnel.
//! The acceptance command exercises the production relay, catalog and client
//! through authenticated sockets using isolated synthetic test identities.

#![forbid(unsafe_code)]
// Unix-only by declaration: see `src/entry.rs`.
#![cfg(unix)]

pub mod acceptance;
pub mod admission;
mod c11_capture;
pub mod cluster_acceptance;
pub mod cluster_fixture;
pub mod cluster_transport;
/// The gate-4 owner-relay fixture hold (harness only, gate 5).
pub mod http_relay_hold;
pub mod m2_acceptance;
pub mod mcp_demo_client;
pub mod peer;
pub mod peer_fragmentation;
pub mod peer_frames;
pub mod production_cluster;
pub mod redis_lane_restart;
pub mod redis_restart;
pub mod redis_tls;

/// The catalog profile identifier of the synthetic gate-3/4 `http-forward`
/// fixture service.  It is not an application profile a production relay
/// can be configured to serve.
pub const FIXTURE_HTTP_FORWARD_PROFILE: &str = "fixture-http-forward";

pub use production_cluster::{
    LateResponseEvidence, PublicAbandonedUpgradeEvidence, validate_late_response_evidence,
    validate_public_abandoned_upgrade_evidence, verify_public_abandoned_upgrade,
    verify_side_effect_late,
};

mod database;
mod error;
mod fanout_proxy;
mod fixture;
mod harness;
mod oidc;
mod pki;
mod process;
mod proxy;

pub use cluster_fixture::ClusterFixture;
pub use database::{RedisLease, RedisLeaseOptions};
pub use error::{HarnessError, Result};
pub use fanout_proxy::{
    FanoutConnection, FanoutProxy, FanoutProxyConfig, FanoutProxyDiagnostics, FanoutProxyHandle,
    FanoutRouteFault, FanoutRouteFlow, TcpFanoutProxy, TcpFanoutProxyConfig, TcpFanoutProxyHandle,
};
pub use fixture::{
    ConsumerFixture, DeviceFixture, FixtureTopology, PrincipalFixture, SharedFixtureIdentity,
    TenantFixture,
};
pub use harness::{Harness, HarnessOptions, MCP_GATE_SERVICES, McpServiceFixture, RunningHarness};
pub use oidc::{OidcClaims, OidcFixture, OidcTokenOptions};
pub use pki::{
    CertificateAuthority, CertificateMaterial, CertificateProfile, CertificateRole, FixturePki,
    Validity,
};
pub use process::{ManagedProcess, ProcessSpec};
pub use proxy::{
    ConnectionId, Direction, FaultAction, FaultRule, FaultScript, ProxyConfig, ProxyConnection,
    ProxyDiagnostics, ProxyHandle, ProxyStats, TcpProxy,
};

/// Return the process status used by acceptance-command entrypoints.
///
/// Keeping this pure status mapping in the shared harness crate lets the
/// validator regression tests exercise the exact boundary used by the binary
/// without launching an external Redis/relay fixture.  The command still
/// owns printing its bounded, payload-free diagnostic.
#[doc(hidden)]
pub fn acceptance_command_exit_code<T>(
    result: &std::result::Result<T, HarnessError>,
) -> std::process::ExitCode {
    match result {
        Ok(_) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}

/// The maximum authorization snapshot age required by the M1 design.
pub const AUTHORIZATION_SNAPSHOT_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(5);

/// The five device fixture identities used by the M1 multi-tenant gate.
pub const M1_DEVICE_COUNT: usize = 5;

#[cfg(test)]
pub(crate) mod acceptance_test_support {
    use super::{HarnessError, acceptance_command_exit_code};

    const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;

    /// Assert the same nonzero status and redaction boundary used by the CLI
    /// for a deliberately incomplete evidence value.
    pub(crate) fn assert_rejected<T>(
        result: std::result::Result<T, HarnessError>,
        expected_field: &str,
    ) {
        let diagnostic = assert_failed(result);
        assert!(
            diagnostic.contains(expected_field),
            "{expected_field} missing from bounded diagnostic: {diagnostic}"
        );
    }

    pub(crate) fn assert_failed<T>(result: std::result::Result<T, HarnessError>) -> String {
        let diagnostic = result
            .as_ref()
            .err()
            .expect("incomplete evidence unexpectedly passed")
            .to_string();
        assert_eq!(
            acceptance_command_exit_code(&result),
            std::process::ExitCode::FAILURE,
            "an incomplete mandatory gate must reach the nonzero CLI path"
        );
        assert!(
            diagnostic.len() <= MAX_DIAGNOSTIC_BYTES,
            "acceptance diagnostic exceeded its bound: {} bytes",
            diagnostic.len()
        );
        for secret in ["fixture-secret-token", "private-key-pem", "bearer-token"] {
            assert!(
                !diagnostic.contains(secret),
                "acceptance diagnostic leaked a secret marker: {secret}"
            );
        }
        diagnostic
    }
}
