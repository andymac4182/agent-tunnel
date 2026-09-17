//! The pin, checked against the files that actually decide it.
//!
//! `src/pin.rs` records what was pinned.  These tests read the workspace's own
//! `Cargo.lock` and manifests and compare, so the record cannot drift from the
//! artifact: a `cargo update` that moved either SDK crate, or a manifest that
//! turned on one of the two refused draft features, turns a test red instead
//! of leaving a stale sentence in a document.
//!
//! What this does **not** show: that the pinned crates work, or that anything
//! in this repository interoperates with an ACP client.  It shows only that
//! the artifact in the lockfile is the artifact that was named.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use tunnel_acp::pin;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root is two levels above this crate")
}

/// One `[[package]]` entry of `Cargo.lock`.
struct LockEntry {
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

fn lock_entries(name: &str) -> Vec<LockEntry> {
    let text = std::fs::read_to_string(workspace_root().join("Cargo.lock"))
        .expect("the workspace lockfile is readable");
    let document: toml::Value = toml::from_str(&text).expect("Cargo.lock is TOML");
    document
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("Cargo.lock has a package array")
        .iter()
        .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some(name))
        .map(|package| LockEntry {
            version: package["version"].as_str().unwrap_or_default().to_owned(),
            source: package
                .get("source")
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
            checksum: package
                .get("checksum")
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
        })
        .collect()
}

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[test]
fn each_pinned_crate_is_in_the_lockfile_exactly_once_at_its_recorded_checksum() {
    for (name, version, checksum) in [
        (pin::CORE_CRATE, pin::CORE_VERSION, pin::CORE_CHECKSUM),
        (pin::HTTP_CRATE, pin::HTTP_VERSION, pin::HTTP_CHECKSUM),
        (pin::SCHEMA_CRATE, pin::SCHEMA_VERSION, pin::SCHEMA_CHECKSUM),
    ] {
        let entries = lock_entries(name);
        assert_eq!(
            entries.len(),
            1,
            "{name} appears {} times in Cargo.lock; a pin means one artifact",
            entries.len()
        );
        let entry = &entries[0];
        assert_eq!(entry.version, version, "{name} version");
        assert_eq!(
            entry.source.as_deref(),
            Some(CRATES_IO),
            "{name} must come from crates.io, not a git or path override"
        );
        assert_eq!(entry.checksum.as_deref(), Some(checksum), "{name} checksum");
    }
}

/// The lockfile check above would also pass if the manifest asked for a range
/// that happened to resolve here.  The pin is exact, so the manifest must say
/// so.
#[test]
fn the_manifest_requires_the_exact_versions_with_no_default_features() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("this crate's manifest is readable");
    let document: toml::Value = toml::from_str(&manifest).expect("the manifest is TOML");
    let dependencies = document
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .expect("the manifest has dependencies");

    for (name, version) in [
        (pin::CORE_CRATE, pin::CORE_VERSION),
        (pin::HTTP_CRATE, pin::HTTP_VERSION),
    ] {
        let entry = dependencies
            .get(name)
            .unwrap_or_else(|| panic!("{name} is a dependency of this crate"));
        assert_eq!(
            entry.get("version").and_then(toml::Value::as_str),
            Some(format!("={version}").as_str()),
            "{name} must be required exactly"
        );
        assert_eq!(
            entry.get("default-features").and_then(toml::Value::as_bool),
            Some(false),
            "{name} must not take default features"
        );
        assert!(
            entry.get("features").is_none(),
            "{name} must enable no features at all"
        );
    }
}

fn workspace_manifests() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut manifests = vec![root.join("Cargo.toml")];
    let crates = std::fs::read_dir(root.join("crates")).expect("crates/ is readable");
    for entry in crates {
        let path = entry.expect("a readable directory entry").path();
        let manifest = path.join("Cargo.toml");
        if manifest.is_file() {
            manifests.push(manifest);
        }
    }
    manifests.sort();
    manifests
}

/// Neither draft feature is enabled by any manifest in this workspace.
///
/// This is the **red test** behind the claim.  `src/pin.rs` also refuses to
/// compile if `unstable_protocol_v2` is on, because the schema removes
/// `ProtocolVersion::LATEST` in that configuration — but a build failure is
/// not a red test, and the guard-deletion suite would not be able to measure
/// it.  This scan is measurable: add either name to any manifest and this
/// fails.
#[test]
fn no_workspace_manifest_enables_a_refused_draft_feature() {
    let manifests = workspace_manifests();
    assert!(
        manifests.len() > 5,
        "expected to scan the whole workspace, found {}",
        manifests.len()
    );
    let mut offenders = BTreeSet::new();
    for manifest in &manifests {
        let text = std::fs::read_to_string(manifest).expect("a readable manifest");
        for feature in pin::REFUSED_FEATURES {
            if text.contains(feature) {
                offenders.insert(format!("{}: {feature}", manifest.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a workspace manifest enables a refused ACP draft feature: {offenders:?}"
    );

    // Not vacuous: the scan really is reading this crate's manifest, which
    // names the crate the features would be enabled on.
    let this = manifests
        .iter()
        .find(|path| path.ends_with("tunnel-acp/Cargo.toml"))
        .expect("this crate's manifest is among those scanned");
    let text = std::fs::read_to_string(this).unwrap();
    assert!(text.contains(pin::CORE_CRATE));
}
