//! The M8-01 pin: which published artifacts this crate is compiled against,
//! and the assertions that keep that true.
//!
//! **This module proves that the pin is the pin. It proves nothing about
//! interoperability.** No ACP client has been run against anything in this
//! repository; compiling against a crate is not running against it.
//!
//! Three things are asserted rather than asserted-in-a-comment:
//!
//! 1. The versions and checksums below are the ones `Cargo.lock` records.  The
//!    integration test `tests/pin.rs` reads the workspace lockfile and
//!    compares it, so a `cargo update` that moved either crate turns a test
//!    red instead of leaving a stale sentence in a document.
//! 2. `unstable_mcp_over_acp` is off in the **built artifact**.  The schema's
//!    method-name table gains `mcp/connect`, `mcp/message` and
//!    `mcp/disconnect` members when that feature is on, and
//!    [`enabled_client_method_keys`] reads the compiled table back through
//!    serde.  Turning the feature on anywhere in the workspace unifies it into
//!    this build and turns that test red.
//! 3. `unstable_protocol_v2` is off.  It has a second, stronger guard: the
//!    schema deliberately removes `ProtocolVersion::LATEST` when that feature
//!    is enabled, so [`LATEST_PROTOCOL_VERSION`] below does not compile at
//!    all if anything in the workspace turns it on.  A compile failure is not
//!    a red test, so `tests/pin.rs` also scans every workspace manifest for
//!    the two feature names, which is a red test.

use agent_client_protocol::schema::ProtocolVersion;

/// The pinned core SDK crate.
pub const CORE_CRATE: &str = "agent-client-protocol";
/// Exact version; the manifest requires `=2.1.0`.
pub const CORE_VERSION: &str = "2.1.0";
/// `Cargo.lock` checksum, equal to the crates.io index `cksum` and to the
/// SHA-256 of the downloaded `.crate` archive.
pub const CORE_CHECKSUM: &str = "6395d81d91fd2ee93f48ea31cfc511356e75b9061ca0389cefd0308507cc11ba";

/// The pinned HTTP/WebSocket transport crate.
pub const HTTP_CRATE: &str = "agent-client-protocol-http";
pub const HTTP_VERSION: &str = "2.1.0";
pub const HTTP_CHECKSUM: &str = "5f0d39290be11146183166d4d077013b94a204516c9ecbbb058a234c28c5babc";

/// The wire-format schema crate.  It is not named in this crate's manifest:
/// the core SDK requires it as `=1.7.0`, and it is the crate the normative v1
/// method names and the `StopReason` vocabulary actually live in, so it is
/// pinned here too and checked in the lockfile.
pub const SCHEMA_CRATE: &str = "agent-client-protocol-schema";
pub const SCHEMA_VERSION: &str = "1.7.0";
pub const SCHEMA_CHECKSUM: &str =
    "ca98360c7bb8cc97d7acd49e2a8a851c3f7bee6b2f0535036d8ab86b5fcd223d";

/// The upstream commit both 2.1.0 crates were published from, read from the
/// `.cargo_vcs_info.json` inside each published `.crate` archive.
pub const SDK_VCS_COMMIT: &str = "726c5030bfaa88cfdac2fb1f71a63abb331ce586";
/// The upstream commit `agent-client-protocol-schema` 1.7.0 was published
/// from, from its own `.cargo_vcs_info.json`.
pub const SCHEMA_VCS_COMMIT: &str = "272bf799f35a258c6a4107a0410ed361e83683d3";
/// `github.com/agentclientprotocol/rust-sdk`.
pub const SDK_REPOSITORY: &str = "https://github.com/agentclientprotocol/rust-sdk";

/// The immutable commit of the upstream transport RFD this profile's HTTP
/// shape was taken from, in `agentclientprotocol/agent-client-protocol`, path
/// `docs/rfds/streamable-http-websocket-transport.mdx`.
///
/// Its revision history's **last** entry is 2026-07-02.  `docs/acp.md`
/// originally pinned "revision 2026-05-04, the last listed revision", which
/// was already two revisions stale; `docs/sources.md` records the
/// reconciliation and the one place the pinned SDK and this revision of the
/// RFD disagree.
pub const TRANSPORT_RFD_COMMIT: &str = "ccff4e7d2e431880225804a8c136c2ccfcb313d0";
/// The last revision listed in the RFD's own revision history at that commit.
pub const TRANSPORT_RFD_REVISION: &str = "2026-07-02";
/// The revision `docs/acp.md` named before this chunk reconciled it.
pub const TRANSPORT_RFD_REVISION_PREVIOUSLY_CLAIMED: &str = "2026-05-04";

/// The two draft features this export must never be built with.
pub const REFUSED_FEATURES: [&str; 2] = ["unstable_protocol_v2", "unstable_mcp_over_acp"];

/// The schema's latest **stable** protocol version.
///
/// This constant is load-bearing at compile time.  `ProtocolVersion::LATEST`
/// exists in the pinned schema only under `#[cfg(not(feature =
/// "unstable_protocol_v2"))]` — upstream removes it when the draft is enabled
/// so that callers must choose `V1` or `V2` explicitly.  If anything in this
/// workspace turns that feature on, cargo's feature unification reaches this
/// crate and this line stops compiling.
pub const LATEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::LATEST;

/// The same fact as a `const` assertion, so it is checked even if the constant
/// above were only referenced from a test that someone deleted.
const _: () = assert!(LATEST_PROTOCOL_VERSION.as_u16() == crate::PROTOCOL_VERSION_V1);

/// The member names of the compiled `ClientMethodNames` table.
///
/// This reads the **built artifact** rather than a list written here: the
/// struct's `mcp_connect`, `mcp_message` and `mcp_disconnect` members exist
/// only under `unstable_mcp_over_acp`, so their absence here is an observation
/// that the feature is off in this build, not an assumption.
#[must_use]
pub fn enabled_client_method_keys() -> Vec<String> {
    keys_of(&agent_client_protocol::schema::v1::CLIENT_METHOD_NAMES)
}

/// The member names of the compiled `AgentMethodNames` table, for the same
/// reason: `mcp_message`, the `providers_*` set, `session_fork` and the `nes_*`
/// set are each behind their own unstable feature.
#[must_use]
pub fn enabled_agent_method_keys() -> Vec<String> {
    keys_of(&agent_client_protocol::schema::v1::AGENT_METHOD_NAMES)
}

fn keys_of<T: serde::Serialize>(value: &T) -> Vec<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| match value {
            serde_json::Value::Object(map) => Some(map.keys().cloned().collect()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Whether the compiled schema exposes MCP-over-ACP methods.
///
/// Must be `false`.  `docs/acp.md` puts MCP-over-ACP outside the first ACP
/// milestone, and upstream gates it behind a feature, so "outside the
/// milestone" means *not enabled* rather than *not mentioned*.
#[must_use]
pub fn mcp_over_acp_enabled() -> bool {
    enabled_client_method_keys()
        .iter()
        .any(|key| key.starts_with("mcp_"))
        || enabled_agent_method_keys()
            .iter()
            .any(|key| key.starts_with("mcp_"))
}

#[cfg(test)]
#[path = "pin_tests.rs"]
mod tests;
