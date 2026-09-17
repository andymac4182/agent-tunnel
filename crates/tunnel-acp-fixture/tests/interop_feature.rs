//! The interop driver stays out of the default build graph (M8-C04, M8-C09).
//!
//! `pin.rs` in `tunnel-acp` reads the lockfile so the record of *what* is
//! pinned cannot drift from the artifact. This reads this crate's manifest for
//! the same reason, about a different property: **whether** the pinned HTTP
//! client is in the build at all by default.
//!
//! The lockfile cannot answer that — an optional dependency is locked whether
//! or not any build enables it — so the manifest is the thing to read. A future
//! edit that makes these unconditional, or that puts `interop` in `default`,
//! turns this red instead of quietly putting a second `rustls` crypto provider
//! and an `aws-lc-sys` C build back into every binary in the workspace.

use std::path::Path;

fn manifest() -> toml::Value {
    let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("this crate's manifest is readable");
    toml::from_str(&text).expect("the manifest is TOML")
}

/// The dependencies that carry the pinned ACP client, and the exact versions
/// they are pinned at.
const INTEROP_DEPENDENCIES: [(&str, &str); 3] = [
    ("agent-client-protocol", "=2.1.0"),
    ("agent-client-protocol-http", "=2.1.0"),
    // Not an ACP crate: it is the transport `agent-client-protocol-http`'s
    // `client` feature requires, and the one that carries `rustls/aws-lc-rs`.
    ("reqwest", "0.13"),
];

#[test]
fn the_pinned_client_is_optional_and_not_in_the_default_feature_set() {
    let manifest = manifest();
    let features = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .expect("this crate declares features");
    let default = features
        .get("default")
        .and_then(toml::Value::as_array)
        .expect("a default feature list");
    assert!(
        default.is_empty(),
        "the default feature set must be empty; found {default:?}"
    );
    let interop: Vec<&str> = features
        .get("interop")
        .and_then(toml::Value::as_array)
        .expect("an interop feature")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();

    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .expect("this crate has dependencies");
    for (name, version) in INTEROP_DEPENDENCIES {
        let entry = dependencies
            .get(name)
            .unwrap_or_else(|| panic!("{name} is a dependency of this crate"));
        assert_eq!(
            entry.get("optional").and_then(toml::Value::as_bool),
            Some(true),
            "{name} must be optional, or it is in every build"
        );
        assert_eq!(
            entry.get("version").and_then(toml::Value::as_str),
            Some(version),
            "{name} version"
        );
        assert!(
            interop.contains(&format!("dep:{name}").as_str()),
            "{name} must be enabled by the interop feature and nothing else; interop is {interop:?}"
        );
    }

    // Not vacuous: the same manifest really does name the ACP HTTP client.
    assert!(dependencies.contains_key("agent-client-protocol-http"));
}

/// The test file this feature gates is gated, and says so.
#[test]
fn the_interop_test_is_behind_the_feature_it_needs() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("pinned_client.rs"),
    )
    .expect("the interop test is readable");
    assert!(
        source.starts_with("#![cfg(all(unix, feature = \"interop\"))]"),
        "pinned_client.rs must be gated on the feature that supplies its client"
    );
}
