//! Assertions about the **built artifact**: which optional parts of the
//! pinned SDK this crate is compiled with.
//!
//! The lockfile and manifest checks live in `tests/pin.rs`, which can read the
//! workspace from disk.

use super::*;

/// `unstable_mcp_over_acp` is off, observed rather than assumed.
///
/// The schema's method-name tables gain `mcp_connect`, `mcp_message` and
/// `mcp_disconnect` members when the feature is on.  This reads the compiled
/// tables back through serde, so enabling the feature anywhere in the
/// workspace unifies it into this build and fails here.
#[test]
fn mcp_over_acp_is_not_enabled_in_this_build() {
    let client = enabled_client_method_keys();
    let agent = enabled_agent_method_keys();
    assert!(
        !client.is_empty(),
        "the client method table did not serialize"
    );
    assert!(
        !agent.is_empty(),
        "the agent method table did not serialize"
    );

    for key in ["mcp_connect", "mcp_message", "mcp_disconnect"] {
        assert!(!client.contains(&key.to_owned()), "client table has {key}");
        assert!(!agent.contains(&key.to_owned()), "agent table has {key}");
    }
    assert!(!mcp_over_acp_enabled());

    // The check is not vacuous: the stable members it would sit beside are
    // present, so an empty or renamed table would not pass silently.
    for key in ["session_request_permission", "session_update"] {
        assert!(client.contains(&key.to_owned()), "client table lacks {key}");
    }
    for key in ["initialize", "session_new", "session_prompt"] {
        assert!(agent.contains(&key.to_owned()), "agent table lacks {key}");
    }
}

/// Other unstable surfaces are off too.  They are not this milestone's
/// concern, but a build that enabled `unstable` wholesale would quietly widen
/// the method set the profile is validated against.
#[test]
fn no_unstable_method_surface_is_enabled_in_this_build() {
    let agent = enabled_agent_method_keys();
    for key in [
        "providers_list",
        "providers_set",
        "providers_disable",
        "session_fork",
        "nes_start",
        "nes_suggest",
        "nes_accept",
        "nes_reject",
        "nes_close",
    ] {
        assert!(!agent.contains(&key.to_owned()), "agent table has {key}");
    }
}

/// `unstable_protocol_v2` is off.
///
/// The compiled schema exposes `ProtocolVersion::LATEST` only when the draft
/// is **not** enabled — upstream removes the shorthand so that callers must
/// pick `V1` or `V2` explicitly — so referencing it is the strongest available
/// witness.  If the feature were turned on anywhere in this workspace, `pin.rs`
/// would not compile at all.
///
/// A compile failure is not a red test, which is why `tests/pin.rs` also scans
/// every workspace manifest for the feature name.  This test records the
/// value the constant carries.
#[test]
fn the_latest_stable_protocol_version_is_v1() {
    assert_eq!(LATEST_PROTOCOL_VERSION.as_u16(), 1);
    assert_eq!(LATEST_PROTOCOL_VERSION.as_u16(), crate::PROTOCOL_VERSION_V1);
    assert_eq!(
        LATEST_PROTOCOL_VERSION,
        agent_client_protocol::schema::ProtocolVersion::V1
    );
}

#[test]
fn the_recorded_pin_names_the_two_published_crates_and_their_commits() {
    assert_eq!(CORE_CRATE, "agent-client-protocol");
    assert_eq!(HTTP_CRATE, "agent-client-protocol-http");
    assert_eq!(SCHEMA_CRATE, "agent-client-protocol-schema");
    assert_eq!(CORE_VERSION, "2.1.0");
    assert_eq!(HTTP_VERSION, "2.1.0");
    assert_eq!(SCHEMA_VERSION, "1.7.0");
    // Both 2.1.0 crates were published from one commit of one repository.
    assert_eq!(SDK_VCS_COMMIT.len(), 40);
    assert_eq!(SCHEMA_VCS_COMMIT.len(), 40);
    assert_ne!(SDK_VCS_COMMIT, SCHEMA_VCS_COMMIT);
    for checksum in [CORE_CHECKSUM, HTTP_CHECKSUM, SCHEMA_CHECKSUM] {
        assert_eq!(checksum.len(), 64);
        assert!(
            checksum
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }
    assert_eq!(
        REFUSED_FEATURES,
        ["unstable_protocol_v2", "unstable_mcp_over_acp"]
    );
}

/// The RFD revision this profile was taken from is **not** the one
/// `docs/acp.md` claimed before this chunk.  Recording both keeps the
/// correction from being quietly forgotten.
#[test]
fn the_transport_rfd_revision_is_the_reconciled_one() {
    assert_eq!(TRANSPORT_RFD_REVISION, "2026-07-02");
    assert_eq!(TRANSPORT_RFD_REVISION_PREVIOUSLY_CLAIMED, "2026-05-04");
    assert_ne!(
        TRANSPORT_RFD_REVISION,
        TRANSPORT_RFD_REVISION_PREVIOUSLY_CLAIMED
    );
    assert_eq!(TRANSPORT_RFD_COMMIT.len(), 40);
}
