//! **Proof 3 of the four: the default feature set links nothing capable of
//! synthesising input or capturing a screen.**
//!
//! `<scratchpad>/m5-scoping-and-decisions.md` and `AGENTS.md` both put Lane A
//! under one rule: no dependency capable of synthesising input or capturing a
//! screen in the default feature set, "that is what makes *the host was not
//! touched* checkable by `cargo tree` rather than by reading code."
//!
//! Reading code does not scale and does not survive a refactor. Reading the
//! dependency graph does: a crate that cannot move a mouse cannot be made to
//! move one by a future edit to a file nobody re-reviews.
//!
//! # What this proves, and what it does not
//!
//! It proves that **no crate on the denylist appears anywhere in this
//! workspace's `Cargo.lock`**, that no such crate is in the transitive closure
//! of either M5 crate, and that the two M5 crates declare only dependencies
//! from a small explicit allowlist. Those are real, mechanical properties.
//!
//! It does **not** prove that no code anywhere could ever touch a host: a
//! process can shell out, and `std` can open a device node. What it removes is
//! the *easy* way, which is also the only way anything in this repository has
//! ever proposed to do it — a crate that wraps the OS automation APIs. The
//! other three proofs cover the rest, and none of the four is sufficient
//! alone.
//!
//! # The gap this test has, stated rather than hidden
//!
//! **`windows-sys` is already in this workspace's lockfile**, reached from
//! `tokio`/`mio`/`socket2` and gated in their manifests behind
//! `cfg(windows)`. `Cargo.lock` records the union of every target's
//! dependencies and carries no `cfg` information, so a lockfile scan **cannot
//! distinguish a Win32 binding that is compiled from one that is gated away**.
//! Putting `windows-sys` on the denylist would therefore turn this test red on
//! a fact that has nothing to do with CUA, and deleting the check to make it
//! green would be exactly the cue-word deletion `AGENTS.md` forbids.
//!
//! So the denylist below covers the macOS and Linux capture and event-posting
//! surfaces — which are genuinely absent, and one of which (`core-graphics`)
//! is the surface that matters on the host these chunks run on — and the Win32
//! surface is covered instead by
//! [`the_two_m5_crates_declare_only_allowlisted_dependencies`], which is a
//! stronger check over a smaller scope. The residual hole — a *transitive*
//! Win32 input dependency on a Windows build — is recorded as task row
//! **M5-C04** rather than claimed closed. It is not reachable today, because
//! no M5 crate depends on anything that could introduce one, but this test is
//! not what shows that.
//!
//! This does not run `cargo tree`. A test that shelled out to cargo inside a
//! cargo test run is fragile and slow; the lockfile is the same information
//! and is what `cargo tree` reads. `tunnel-acp/tests/pin.rs` scans the
//! lockfile for the same kind of reason.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root is two levels above this crate")
}

fn lock_package_names() -> BTreeSet<String> {
    let text = std::fs::read_to_string(workspace_root().join("Cargo.lock"))
        .expect("the workspace lockfile is readable");
    let document: toml::Value = toml::from_str(&text).expect("Cargo.lock is TOML");
    document
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("Cargo.lock has a package array")
        .iter()
        .filter_map(|package| package.get("name").and_then(toml::Value::as_str))
        .map(str::to_owned)
        .collect()
}

/// Crates that can synthesise keyboard or pointer input, capture a screen, or
/// reach the OS automation APIs that do either.
///
/// Three groups, kept separate so a future reader can tell why each name is
/// here rather than trusting one long list:
///
/// * **Input synthesis**: they exist to press keys and move pointers.
/// * **Screen capture**: they exist to read a framebuffer or a window.
/// * **The OS API surfaces** underneath both. These are the interesting ones,
///   because a crate could reach them without advertising automation in its
///   name — `core-graphics` is how a macOS capture is actually taken, and
///   `windows`/`winapi` expose `SendInput`.
///
/// A name arriving in the lockfile through some transitive path is exactly
/// what this test is for. If a legitimate dependency ever needs one, that is a
/// decision with a task row, not a line quietly deleted from this list.
const DENIED: &[(&str, &str)] = &[
    // Input synthesis.
    ("enigo", "input synthesis"),
    ("rdev", "input synthesis and global hooks"),
    ("autopilot", "input synthesis and screen capture"),
    ("inputbot", "input synthesis"),
    ("mouse-rs", "pointer synthesis"),
    ("device_query", "global input state"),
    ("multiinput", "raw input devices"),
    ("uinput", "kernel input device creation"),
    ("evdev", "kernel input devices"),
    // Screen capture.
    ("xcap", "screen and window capture"),
    ("screenshots", "screen capture"),
    ("scrap", "screen capture"),
    ("captrs", "screen capture"),
    ("dxgcap", "desktop duplication capture"),
    ("libwayshot", "wayland screen capture"),
    // The OS API surfaces underneath both.
    ("core-graphics", "macOS Quartz: capture and event posting"),
    ("core-graphics-types", "macOS Quartz types"),
    ("cocoa", "macOS AppKit"),
    ("objc", "Objective-C runtime bridge"),
    ("objc2", "Objective-C runtime bridge (objc2 generation)"),
    ("objc2-app-kit", "macOS AppKit"),
    // How a *modern* macOS capture is actually taken. The first review of this
    // chunk pointed out that `core-graphics` and `objc2-app-kit` no longer
    // cover the path on their own: `CGDisplayCreateImage` is deprecated, and
    // current crates reach ScreenCaptureKit or the objc2 Core Graphics
    // bindings directly. A denylist that named only the old path would have
    // been a denylist with a hole in exactly the direction it exists to cover.
    (
        "objc2-core-graphics",
        "macOS Quartz through objc2: capture and event posting",
    ),
    ("objc2-screen-capture-kit", "macOS ScreenCaptureKit"),
    ("screencapturekit", "macOS ScreenCaptureKit"),
    (
        "core-graphics-helmer-fork",
        "a maintained fork of the macOS Quartz bindings",
    ),
    ("x11", "X11 client"),
    ("x11rb", "X11 client"),
    ("xcb", "X11 client"),
    ("wayland-client", "Wayland client"),
    // `winapi` is not here, and neither is `windows-sys`: see the module
    // documentation. They are not absent from this workspace, they are gated
    // behind `cfg(windows)` in crates the lockfile cannot express a `cfg` for,
    // and M5-C04 records the residue.
];

/// The Win32 binding crates this scan deliberately cannot cover, and the row
/// that owns the gap.
///
/// Named as data so the limitation is discoverable from the test rather than
/// only from a comment, and so a future reader who does close the gap has the
/// list to work from.
const WIN32_NOT_COVERED: &[&str] = &["winapi", "windows", "windows-sys"];

/// The row that owns [`WIN32_NOT_COVERED`].
const WIN32_GAP_ROW: &str = "M5-C04";

/// **The proof.** No crate capable of input synthesis or screen capture is
/// anywhere in this workspace's dependency graph.
#[test]
fn no_crate_capable_of_input_or_capture_is_in_the_workspace_lockfile() {
    let packages = lock_package_names();
    let offenders: Vec<String> = DENIED
        .iter()
        .filter(|(name, _)| packages.contains(*name))
        .map(|(name, why)| format!("{name} ({why})"))
        .collect();
    assert!(
        offenders.is_empty(),
        "Lane A must link nothing capable of input synthesis or screen capture, \
         and the workspace lockfile now contains: {offenders:?}. \
         This is not a lint to silence: adding one of these is a decision that \
         needs a task row and a safety argument, per AGENTS.md."
    );
}

/// Read the lockfile's dependency edges: package name -> its dependencies'
/// names.
///
/// `Cargo.lock` entries list dependencies as `"name"` or `"name version"`, so
/// the first whitespace-separated word is the name.
fn lock_edges() -> std::collections::BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(workspace_root().join("Cargo.lock"))
        .expect("the workspace lockfile is readable");
    let document: toml::Value = toml::from_str(&text).expect("Cargo.lock is TOML");
    let mut edges: std::collections::BTreeMap<String, BTreeSet<String>> = Default::default();
    for package in document
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("Cargo.lock has a package array")
    {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let dependencies: BTreeSet<String> = package
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(toml::Value::as_str)
                    .filter_map(|entry| entry.split_whitespace().next())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        edges
            .entry(name.to_owned())
            .or_default()
            .extend(dependencies);
    }
    edges
}

/// Everything reachable from `root` through the lockfile's edges.
///
/// This is what `cargo tree -p <root>` shows, minus target filtering — which
/// makes it an **over**-approximation, and over-approximating is the safe
/// direction for a check that is looking for something forbidden.
fn closure(root: &str) -> BTreeSet<String> {
    let edges = lock_edges();
    let mut seen = BTreeSet::new();
    let mut queue = vec![root.to_owned()];
    while let Some(name) = queue.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if let Some(dependencies) = edges.get(&name) {
            queue.extend(dependencies.iter().cloned());
        }
    }
    seen
}

/// The same denylist, narrowed to what either M5 crate can actually reach.
///
/// Stronger than the workspace-wide scan for the scope that matters: a crate
/// arriving anywhere in the workspace is a warning, and a crate arriving in
/// *this* closure is the defect itself.
#[test]
fn neither_m5_crate_can_reach_a_crate_capable_of_input_or_capture() {
    for root in ["tunnel-cua", "tunnel-cua-fixture"] {
        let reachable = closure(root);
        assert!(
            reachable.contains(root),
            "{root} is not in the lockfile; the closure is reading nothing"
        );
        let offenders: Vec<&str> = DENIED
            .iter()
            .filter(|(name, _)| reachable.contains(*name))
            .map(|(name, _)| *name)
            .collect();
        assert!(
            offenders.is_empty(),
            "{root} can reach {offenders:?}, which is capable of input synthesis or screen capture"
        );
    }
    // Non-vacuity: the closure really does traverse edges rather than
    // returning its root. `tunnel-cua` reaches the codec it instantiates, and
    // the fixture reaches `tunnel-cua`.
    assert!(closure("tunnel-cua").contains("tunnel-http-forward"));
    assert!(closure("tunnel-cua-fixture").contains("tunnel-cua"));
    assert!(closure("tunnel-cua-fixture").contains("serde_json"));
    // A control that the closure is not merely returning everything: a crate
    // this workspace does use, but that neither M5 crate can reach.
    assert!(
        !closure("tunnel-cua").contains("agent-client-protocol"),
        "tunnel-cua must not reach the pinned ACP SDK; that edge is what json.rs avoids"
    );
    // `tunnel-cua` does no I/O itself, but it *does* reach `tokio`
    // transitively, through `tunnel-http-bridge`, whose `Profile` type it
    // instantiates. Recorded rather than asserted away: "pure" here means this
    // crate opens nothing, not that nothing below it could.
    assert!(closure("tunnel-cua").contains("tokio"));
    assert!(
        !manifest_dependency_names(
            &workspace_root()
                .join("crates")
                .join("tunnel-cua")
                .join("Cargo.toml")
        )
        .contains("tokio"),
        "tunnel-cua must not declare an async runtime of its own"
    );
}

/// The gap is real, and this test says so out loud so it cannot be forgotten.
///
/// It asserts the state of the world that *makes* the gap exist — `windows-sys`
/// present in the lockfile through a `cfg(windows)` edge — so that if the
/// world ever changes the assertion changes with it, and the row it names has
/// to be revisited rather than quietly outliving its reason.
#[test]
fn the_win32_binding_gap_is_recorded_rather_than_silently_excluded() {
    let packages = lock_package_names();
    assert!(
        WIN32_NOT_COVERED
            .iter()
            .any(|name| packages.contains(*name)),
        "a Win32 binding crate is no longer in the lockfile, so {WIN32_GAP_ROW}'s \
         premise has changed: revisit the row and consider denylisting {WIN32_NOT_COVERED:?}"
    );
    // None of them is on the denylist, which is the deliberate exclusion this
    // test documents.
    for name in WIN32_NOT_COVERED {
        assert!(
            !DENIED.iter().any(|(denied, _)| denied == name),
            "{name} is both denylisted and recorded as not covered; pick one"
        );
    }
    // The row that owns the gap is a real row in `docs/tasks.md`.
    let tasks = std::fs::read_to_string(workspace_root().join("docs").join("tasks.md"))
        .expect("docs/tasks.md is readable");
    assert!(
        tasks.contains(WIN32_GAP_ROW),
        "{WIN32_GAP_ROW} must exist in docs/tasks.md; a gap with no row is a gap nobody owns"
    );
}

/// The scan is not vacuous: it really is reading this workspace's lockfile,
/// and that lockfile really does contain the crates this workspace uses.
///
/// Without this, an empty or unreadable lockfile — or a `DENIED` list someone
/// emptied — would report a clean bill of health.
#[test]
fn the_denylist_scan_is_reading_a_real_populated_lockfile() {
    let packages = lock_package_names();
    assert!(
        packages.len() > 50,
        "expected a populated lockfile, found {} packages",
        packages.len()
    );
    for expected in ["tunnel-cua", "tunnel-http-forward", "serde_json", "tokio"] {
        assert!(
            packages.contains(expected),
            "{expected} should be in the lockfile; the scan is not reading what it thinks"
        );
    }
    assert!(
        DENIED.len() >= 24,
        "the denylist was truncated to {} entries",
        DENIED.len()
    );
    // And a control: a name that is genuinely absent reads as absent, so
    // `contains` is answering rather than always saying yes.
    assert!(!packages.contains("this-crate-does-not-exist"));
}

fn manifest_dependency_names(manifest: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(manifest).expect("a readable manifest");
    let document: toml::Value = toml::from_str(&text).expect("the manifest is TOML");
    let mut names = BTreeSet::new();
    for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(entries) = document.get(table).and_then(toml::Value::as_table) {
            names.extend(entries.keys().cloned());
        }
    }
    // Target-specific tables too, which is where a platform automation crate
    // would most naturally hide.
    if let Some(targets) = document.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(entries) = target.get(table).and_then(toml::Value::as_table) {
                    names.extend(entries.keys().cloned());
                }
            }
        }
    }
    names
}

/// Every direct dependency of the two M5 crates, named.
///
/// A denylist answers "none of the known-bad crates". This answers the
/// stronger question for the two crates that would host the defect: "only
/// these, and nothing else". A new dependency on either crate turns this red
/// and has to be argued for rather than merged in passing.
const M5_ALLOWED_DEPENDENCIES: &[&str] = &[
    // tunnel-cua
    "serde",
    "serde_json",
    "toml",
    "tunnel-http-bridge",
    "tunnel-http-forward",
    // tunnel-cua-fixture
    "tokio",
    "tunnel-cua",
];

#[test]
fn the_two_m5_crates_declare_only_allowlisted_dependencies() {
    let root = workspace_root();
    let manifests = [
        root.join("crates").join("tunnel-cua").join("Cargo.toml"),
        root.join("crates")
            .join("tunnel-cua-fixture")
            .join("Cargo.toml"),
    ];
    for manifest in &manifests {
        assert!(manifest.is_file(), "{} is missing", manifest.display());
        let names = manifest_dependency_names(manifest);
        assert!(
            !names.is_empty(),
            "{} declares no dependencies at all; the scan is reading the wrong file",
            manifest.display()
        );
        for name in &names {
            assert!(
                M5_ALLOWED_DEPENDENCIES.contains(&name.as_str()),
                "{} declares {name}, which is not on the M5 allowlist. \
                 Adding a dependency to an M5 crate is a safety decision, not a build detail.",
                manifest.display()
            );
        }
    }
}

/// Neither M5 crate declares a feature that could turn one of these on later.
///
/// Lane B — the real backend on a dedicated VM — is deliberately **not**
/// implemented in this chunk, and this test is what keeps a future Lane B
/// feature from being added to these crates without anyone noticing. When Lane
/// B does arrive it will need this test changed, deliberately, with an
/// argument.
#[test]
fn neither_m5_crate_declares_any_optional_feature_yet() {
    let root = workspace_root();
    for crate_name in ["tunnel-cua", "tunnel-cua-fixture"] {
        let manifest = root.join("crates").join(crate_name).join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest).expect("a readable manifest");
        let document: toml::Value = toml::from_str(&text).expect("the manifest is TOML");
        let features = document
            .get("features")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let non_default: Vec<&String> = features.keys().filter(|key| *key != "default").collect();
        assert!(
            non_default.is_empty(),
            "{crate_name} declares the features {non_default:?}; \
             a Lane A crate has no feature to turn on, and Lane B is not this chunk"
        );
    }
}
