//! Unit tests that need no child process.
//!
//! The supervisor's behaviour against a real child is in
//! `tunnel-acp-fixture/tests`, because only the crate that defines the fixture
//! binary gets `CARGO_BIN_EXE_*`.

use std::path::PathBuf;

use tunnel_acp::lifecycle::{MAX_PENDING_PER_DIRECTION, MAX_SESSIONS_PER_CONNECTION};

use crate::child::ChildConfig;
use crate::supervisor::{ConnectionScope, SupervisorConfig};

fn scope() -> ConnectionScope {
    ConnectionScope {
        tenant: "tenant-a".to_owned(),
        principal: "principal-a".to_owned(),
        device: "device-a".to_owned(),
        service: "service-a".to_owned(),
        connection: "connection-a".to_owned(),
    }
}

fn child() -> ChildConfig {
    ChildConfig {
        command: PathBuf::from("/nonexistent/agent"),
        args: Vec::new(),
        workspace: PathBuf::from("/"),
        inherit_env: Vec::new(),
        env: std::collections::BTreeMap::new(),
        message_limit: 1 << 20,
        stderr_cap: 1 << 16,
    }
}

#[test]
fn the_default_bounds_are_the_documented_ones() {
    let config = SupervisorConfig::new(child(), scope());
    assert_eq!(config.session_limit, MAX_SESSIONS_PER_CONNECTION);
    assert_eq!(config.pending_limit, MAX_PENDING_PER_DIRECTION);
    // docs/acp.md's bounds table: permission response 60 seconds.
    assert_eq!(config.permission_timeout.as_secs(), 60);
}

#[test]
fn a_child_that_cannot_be_started_fails_rather_than_being_retried() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let config = SupervisorConfig::new(child(), scope());
        let started = crate::Supervisor::start(config);
        assert!(started.is_err(), "the executable does not exist");
    });
}

#[test]
fn the_id_scope_carries_the_direction() {
    let scope = scope();
    let host = scope.id_scope(tunnel_acp::lifecycle::Direction::HostToAgent);
    let agent = scope.id_scope(tunnel_acp::lifecycle::Direction::AgentToHost);
    assert_ne!(host, agent);
    assert_eq!(host.reversed(), agent);
}
