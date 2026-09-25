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
//! of any M5 crate, and that the M5 crates declare only dependencies from a
//! small explicit allowlist. Those are real, mechanical properties.
//!
//! Chunk 4 added a third crate, `tunnel-cua-export`, which owns processes.
//! **That widens the scope of this file rather than escaping it**: a crate
//! that can spawn a child is exactly where a real automation dependency would
//! be most tempting, so it gets its own budget below, and the budget
//! deliberately contains no HTTP client -- the health probe is a trait the
//! caller implements, so Lane A's rule that the fixture is the only backend
//! stays checkable from the manifest.
//!
//! It does **not** prove that no code anywhere could ever touch a host: a
//! process can shell out, and `std` can open a device node. What it removes is
//! the *easy* way, which is also the only way anything in this repository has
//! ever proposed to do it — a crate that wraps the OS automation APIs. The
//! other three proofs cover the rest, and none of the four is sufficient
//! alone.
//!
//! # The Win32 surface, and why the lockfile alone cannot cover it
//!
//! **`windows-sys` is already in this workspace's lockfile**, reached from
//! `tokio`/`mio`/`socket2` and gated in their manifests behind
//! `cfg(windows)`. `Cargo.lock` records the union of every target's
//! dependencies and carries no `cfg` information, so a lockfile scan **cannot
//! distinguish a Win32 binding that is compiled from one that is gated away**.
//! Putting `windows-sys` on the name denylist would therefore turn this test
//! red on a fact that has nothing to do with CUA, and deleting the check to
//! make it green would be exactly the cue-word deletion `AGENTS.md` forbids.
//!
//! **Task row M5-C04 recorded that gap, and the per-target walk below closes
//! it at the level the lockfile could not reach.** `windows-sys` as a crate is
//! harmless: its input and capture surface is **feature-gated**
//! (`Win32_UI_Input_KeyboardAndMouse` is where `SendInput` lives,
//! `Win32_Graphics_Gdi` is `BitBlt`, and so on). So instead of denying the
//! crate by name, [`no_m5_crate_reaches_a_win32_input_or_capture_surface_on_any_target`]
//! asks cargo for the resolve graph **with each target's `cfg` filters
//! applied** (`cargo metadata --filter-platform <triple>`, which needs no
//! toolchain for that target and no network), walks it from the M5 crates,
//! and denies the input/capture **features** of the Win32 binding crates
//! wherever they are reached, plus every name on [`DENIED`], per target. A
//! transitive dependency introduced on a Windows build is exactly what that
//! walk sees and the lockfile did not.
//!
//! **What it still does not see**, and this is parity with the other
//! platforms rather than a Windows-specific hole: a crate that declares its
//! own `extern "system"` imports from `user32.dll` — or uses `windows-link`'s
//! raw-dylib macro — without enabling a binding crate's feature. The same is
//! true on macOS of a crate that hand-writes `extern` declarations against
//! Quartz instead of depending on `core-graphics`. That is the "a process can
//! do FFI" limit stated above; the other three proofs cover it.
//!
//! **This file now runs `cargo` for that one test**, and it is written to be
//! reliable rather than avoided: `--offline --locked`, the same `cargo` binary
//! running the test (`$CARGO`), and a failure that names what to run
//! (`cargo fetch --locked`) instead of a skip. The rest of the file still
//! reads the lockfile directly, as `tunnel-acp/tests/pin.rs` does.

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
    // Windows-only input and capture wrappers. Genuinely absent from the
    // lockfile, so they can be denied by name like the rest.
    ("winput", "Win32 input synthesis"),
    ("windows-capture", "Windows.Graphics.Capture screen capture"),
    ("win-screenshot", "Win32 screen capture"),
    // `winapi`, `windows` and `windows-sys` are not here: see the module
    // documentation. They are not absent from this workspace, they are gated
    // behind `cfg(windows)` in crates the lockfile cannot express a `cfg` for.
    // Their input/capture surface is denied at the **feature** level, per
    // target, by `WIN32_DENIED_FEATURES`.
];

/// The Win32 binding crates that are **not** denied by name in the lockfile
/// scan, because the lockfile cannot say whether they are compiled.
///
/// Each one must have an entry in [`WIN32_DENIED_FEATURES`]; that is what
/// makes the exclusion a narrowing to the feature level rather than a hole,
/// and `the_win32_bindings_are_denied_by_feature_rather_than_silently_excluded`
/// holds the two lists together.
const WIN32_BINDINGS_NOT_NAME_DENIED: &[&str] = &["winapi", "windows", "windows-sys"];

/// The row that recorded the gap and records how it was closed.
const WIN32_GAP_ROW: &str = "M5-C04";

/// The input and capture surface of each Win32 binding crate, as the
/// **features** that gate it.
///
/// A feature matches if it equals an entry or extends it with `_` (so
/// `Win32_UI_Input` also denies `Win32_UI_Input_KeyboardAndMouse`, where
/// `SendInput` lives). `windows` and `windows-sys` share the Win32 naming;
/// `windows` adds the WinRT namespaces. `winapi` names features by header.
const WIN32_DENIED_FEATURES: &[(&str, &[&str])] = &[
    (
        "windows-sys",
        &[
            // SendInput, keyboard/pointer state, raw input.
            "Win32_UI_Input",
            // SetWindowsHookEx, SendMessage/PostMessage, window enumeration.
            "Win32_UI_WindowsAndMessaging",
            // UI Automation: drives controls without synthesising input.
            "Win32_UI_Accessibility",
            // GetDC/BitBlt: the classic screen capture.
            "Win32_Graphics_Gdi",
            // IDXGIOutputDuplication: desktop duplication capture.
            "Win32_Graphics_Dxgi",
            // Windows.Graphics.Capture interop.
            "Win32_System_WinRT_Graphics_Capture",
        ],
    ),
    (
        "windows",
        &[
            "Win32_UI_Input",
            "Win32_UI_WindowsAndMessaging",
            "Win32_UI_Accessibility",
            "Win32_Graphics_Gdi",
            "Win32_Graphics_Dxgi",
            "Win32_System_WinRT_Graphics_Capture",
            // WinRT: Windows.Graphics.Capture and Windows.UI.Input (whose
            // Preview.Injection namespace is InputInjector).
            "Graphics_Capture",
            "UI_Input",
        ],
    ),
    (
        "winapi",
        &[
            "winuser",
            "wingdi",
            "dxgi",
            "dxgi1_2",
            "dxgi1_3",
            "dxgi1_4",
            "dxgi1_5",
            "dxgi1_6",
            "uiautomationclient",
            "uiautomationcore",
            "uiautomationcoreapi",
        ],
    ),
];

/// Whether `feature` of `crate_name` opens an input or capture surface.
fn denied_win32_feature(crate_name: &str, feature: &str) -> bool {
    WIN32_DENIED_FEATURES
        .iter()
        .filter(|(name, _)| *name == crate_name)
        .flat_map(|(_, features)| features.iter())
        .any(|denied| {
            feature == *denied
                || feature
                    .strip_prefix(denied)
                    .is_some_and(|rest| rest.starts_with('_'))
        })
}

/// The targets the per-target walk evaluates.
///
/// Both Windows ABIs and both Windows architectures, because their `cfg`
/// graphs differ (`windows-sys`'s import-library crates are per target), plus
/// the Linux and Apple hosts so the same denylist is applied with *their*
/// `cfg` filters rather than the lockfile's union.
const TARGETS: &[&str] = &[
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-pc-windows-gnu",
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
];

const M5_CRATES: &[&str] = &["tunnel-cua", "tunnel-cua-export", "tunnel-cua-fixture"];

/// `cargo metadata` for one target, with that target's `cfg` filters applied
/// to the resolve graph.
///
/// `--offline --locked`: this must never touch the network or rewrite the
/// lockfile. It needs every package's sources in the local registry cache,
/// including the Windows-only ones a non-Windows build never downloads, so a
/// fresh machine needs `cargo fetch --locked` first. That failure is reported
/// as a failure with that instruction, **not** as a skip: a check that passes
/// when it could not run is the thing this file exists to avoid.
fn cargo_metadata(target: &str) -> serde_json::Value {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--filter-platform",
            target,
            "--manifest-path",
        ])
        .arg(workspace_root().join("Cargo.toml"))
        .output()
        .expect("cargo can be run from a test");
    assert!(
        output.status.success(),
        "cargo metadata --filter-platform {target} failed ({}); if the error is a missing \
         package, run `cargo fetch --locked` so the Windows-only sources are cached:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata emits JSON")
}

/// One package the M5 crates reach on one target: its name and the features
/// the resolver enabled on it for that target.
struct Reached {
    name: String,
    version: String,
    features: BTreeSet<String>,
}

/// Walk the target-filtered resolve graph from the M5 crates.
///
/// Normal and build edges are followed everywhere; dev edges only from the M5
/// crates themselves, because their tests run on a Lane A host and nothing
/// else's do here. Features are the workspace-unified set for the target,
/// which is a **superset** of what building only the M5 crates would enable —
/// the safe direction for a denylist, with a measured cost: a crate *outside*
/// the M5 closure that enables `Win32_UI_Input` on the same `windows-sys`
/// version also turns the check red (M5-C04 records that control). In a
/// workspace built as one, that is the same compiled `windows-sys` the M5
/// binaries link, so it is worth a look rather than a false alarm.
fn m5_reach(metadata: &serde_json::Value) -> Vec<Reached> {
    let packages = metadata["packages"].as_array().expect("a package list");
    let package = |id: &str| {
        packages
            .iter()
            .find(|package| package["id"] == id)
            .unwrap_or_else(|| panic!("{id} is in the resolve but not the package list"))
    };
    let nodes: std::collections::BTreeMap<&str, &serde_json::Value> = metadata["resolve"]["nodes"]
        .as_array()
        .expect("a resolve graph")
        .iter()
        .map(|node| (node["id"].as_str().expect("a node id"), node))
        .collect();
    let roots: Vec<&str> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter(|id| M5_CRATES.contains(&package(id)["name"].as_str().unwrap_or_default()))
        .collect();
    assert_eq!(
        roots.len(),
        M5_CRATES.len(),
        "every M5 crate is a workspace member of the resolve"
    );
    let mut seen = BTreeSet::new();
    let mut queue = roots.clone();
    while let Some(id) = queue.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = nodes
            .get(id)
            .unwrap_or_else(|| panic!("{id} has no resolve node"));
        for dependency in node["deps"].as_array().expect("a dependency list") {
            let non_dev = dependency["dep_kinds"]
                .as_array()
                .expect("dependency kinds")
                .iter()
                .any(|kind| kind["kind"] != "dev");
            if non_dev || roots.contains(&id) {
                queue.push(dependency["pkg"].as_str().expect("a package id"));
            }
        }
    }
    seen.into_iter()
        .map(|id| {
            let package = package(id);
            Reached {
                name: package["name"].as_str().unwrap_or_default().to_owned(),
                version: package["version"].as_str().unwrap_or_default().to_owned(),
                features: nodes[id]["features"]
                    .as_array()
                    .expect("a feature list")
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            }
        })
        .collect()
}

/// **M5-C04's closure.** On every target, with that target's `cfg` filters
/// applied, nothing the M5 crates reach is a denied crate or enables a Win32
/// input or capture feature.
///
/// The controls are in the same test so they cannot be skipped separately:
/// the walk visits a non-trivial number of nodes on every target, it reaches
/// `windows-sys` **on the Windows targets** with its real features read (so
/// the feature check is looking at a populated set on the crate it exists
/// for), and it does **not** reach `windows-sys` on the others even though the
/// lockfile contains it — which is the `cfg` filtering the lockfile scan
/// could not do.
#[test]
fn no_m5_crate_reaches_a_win32_input_or_capture_surface_on_any_target() {
    let lockfile = lock_package_names();
    assert!(
        lockfile.contains("windows-sys"),
        "the cfg control below needs windows-sys in the lockfile"
    );
    for target in TARGETS {
        let reached = m5_reach(&cargo_metadata(target));
        let windows_sys: Vec<&Reached> = reached
            .iter()
            .filter(|package| package.name == "windows-sys")
            .collect();
        let bindings: Vec<String> = reached
            .iter()
            .filter(|package| WIN32_BINDINGS_NOT_NAME_DENIED.contains(&package.name.as_str()))
            .map(|package| {
                format!(
                    "{}@{} ({} features)",
                    package.name,
                    package.version,
                    package.features.len()
                )
            })
            .collect();
        eprintln!(
            "{target}: walked {} packages from {M5_CRATES:?}; Win32 bindings reached: {bindings:?}",
            reached.len()
        );
        assert!(
            reached.len() > 30,
            "{target}: the walk visited only {} packages; it is reading nothing",
            reached.len()
        );
        for root in M5_CRATES {
            assert!(
                reached.iter().any(|package| package.name == *root),
                "{target}: {root} is not in its own walk"
            );
        }

        let named: Vec<String> = reached
            .iter()
            .filter(|package| DENIED.iter().any(|(name, _)| *name == package.name))
            .map(|package| format!("{}@{}", package.name, package.version))
            .collect();
        assert!(
            named.is_empty(),
            "{target}: the M5 crates reach {named:?}, which is capable of input or capture"
        );
        let features: Vec<String> = reached
            .iter()
            .flat_map(|package| {
                package
                    .features
                    .iter()
                    .filter(|feature| denied_win32_feature(&package.name, feature))
                    .map(move |feature| format!("{}@{}/{feature}", package.name, package.version))
            })
            .collect();
        assert!(
            features.is_empty(),
            "{target}: the M5 crates reach a Win32 input or capture surface through {features:?}. \
             A binding crate is harmless; these features are not. Features are unified across \
             the workspace, so the crate that enabled one may be outside the M5 closure: find it \
             with `cargo tree --target {target} -e features -i <crate>`. Either way this needs a \
             task row and a safety argument, per AGENTS.md, not an edit to WIN32_DENIED_FEATURES."
        );

        if target.contains("-windows-") {
            assert!(
                !windows_sys.is_empty(),
                "{target}: windows-sys is not reached, so the feature check saw nothing on the \
                 crate it exists for"
            );
            assert!(
                windows_sys
                    .iter()
                    .any(|package| package.features.contains("Win32_Foundation")),
                "{target}: windows-sys is reached with no Win32_Foundation feature; the \
                 feature list is not being read"
            );
        } else {
            assert!(
                windows_sys.is_empty(),
                "{target}: windows-sys is reached on a non-Windows target, so the cfg filter \
                 was not applied"
            );
        }
    }
}

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

/// The same denylist, narrowed to what any M5 crate can actually reach.
///
/// Stronger than the workspace-wide scan for the scope that matters: a crate
/// arriving anywhere in the workspace is a warning, and a crate arriving in
/// *this* closure is the defect itself.
#[test]
fn no_m5_crate_can_reach_a_crate_capable_of_input_or_capture() {
    for root in ["tunnel-cua", "tunnel-cua-export", "tunnel-cua-fixture"] {
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

/// The Win32 bindings are excluded from the **name** denylist only because
/// they are denied at the **feature** level, and this test holds the two
/// together so the exclusion cannot outlive its cover.
///
/// It asserts that a Win32 binding crate is **present in the lockfile at all**
/// (the reason a name denial is impossible), that every excluded binding has a
/// feature denial in [`WIN32_DENIED_FEATURES`], and that the feature matcher
/// answers both ways.
///
/// **What it does not assert.** It does not check that any edge is
/// `cfg(windows)`-gated; `Cargo.lock` cannot say. That question is answered by
/// [`no_m5_crate_reaches_a_win32_input_or_capture_surface_on_any_target`],
/// which reads cargo's per-target resolve graph instead. Before M5-C04 closed,
/// this test was the whole of the Win32 story and an ungated Win32 dependency
/// would have satisfied it; it is now the bookkeeping half.
#[test]
fn the_win32_bindings_are_denied_by_feature_rather_than_silently_excluded() {
    let packages = lock_package_names();
    assert!(
        WIN32_BINDINGS_NOT_NAME_DENIED
            .iter()
            .any(|name| packages.contains(*name)),
        "a Win32 binding crate is no longer in the lockfile, so {WIN32_GAP_ROW}'s \
         premise has changed: consider denylisting {WIN32_BINDINGS_NOT_NAME_DENIED:?} by name"
    );
    for name in WIN32_BINDINGS_NOT_NAME_DENIED {
        // Not on the name denylist, which is the deliberate exclusion ...
        assert!(
            !DENIED.iter().any(|(denied, _)| denied == name),
            "{name} is both denylisted by name and excluded; pick one"
        );
        // ... and covered at the feature level instead, which is what makes
        // the exclusion a narrowing rather than a hole.
        assert!(
            WIN32_DENIED_FEATURES
                .iter()
                .any(|(crate_name, features)| crate_name == name && !features.is_empty()),
            "{name} is excluded from the name denylist with no feature denial to cover it"
        );
    }
    // The matcher answers both ways: the exact feature, a sub-feature, a
    // sibling that merely shares a prefix without the `_` boundary, a feature
    // every Windows build enables, and the right feature on the wrong crate.
    assert!(denied_win32_feature("windows-sys", "Win32_UI_Input"));
    assert!(denied_win32_feature(
        "windows-sys",
        "Win32_UI_Input_KeyboardAndMouse"
    ));
    assert!(denied_win32_feature(
        "windows",
        "UI_Input_Preview_Injection"
    ));
    assert!(denied_win32_feature("winapi", "winuser"));
    assert!(!denied_win32_feature("windows-sys", "Win32_UI_InputX"));
    assert!(!denied_win32_feature("windows-sys", "Win32_Foundation"));
    assert!(!denied_win32_feature("tokio", "Win32_UI_Input"));
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

/// Every direct dependency of the two M5 crates, **per crate**.
///
/// A denylist answers "none of the known-bad crates". This answers the
/// stronger question for the two crates that would host the defect: "only
/// these, and nothing else". A new dependency on either crate turns this red
/// and has to be argued for rather than merged in passing.
///
/// **Per crate rather than a flat union, corrected after review.** The earlier
/// version was one list checked against both manifests, so `tunnel-cua-fixture`
/// could have gained `tunnel-http-bridge` — or `tunnel-cua` an async runtime —
/// without the test noticing, because the name was allowed *somewhere*. The
/// pure crate and the fixture have deliberately different budgets, and a check
/// that cannot tell them apart is not checking the thing it claims.
const M5_ALLOWED_DEPENDENCIES: &[(&str, &[&str])] = &[
    (
        // Pure: no async runtime, no I/O, no sockets.
        "tunnel-cua",
        &[
            "serde",
            "serde_json",
            "toml",
            "tunnel-http-bridge",
            "tunnel-http-forward",
        ],
    ),
    (
        // The supervisor owns processes and a clock. `rustix` is the safe
        // process-group signalling every export in this workspace uses, and
        // `tunnel-deadman` is the parent-death sentinel. **No HTTP client**:
        // the health probe is a trait the caller implements, so this crate
        // cannot be pointed at a backend at all. `serde_json` is a
        // dev-dependency only -- a probe payload in a test -- because the
        // production path reads a typed `Dispatch`, never a body.
        "tunnel-cua-export",
        &[
            "rustix",
            "serde_json",
            "tempfile",
            "tokio",
            "tunnel-cua",
            "tunnel-deadman",
        ],
    ),
    (
        // The fixture binds a loopback socket, so it gets a runtime -- and
        // nothing else. In particular **not** `tunnel-http-bridge`.
        "tunnel-cua-fixture",
        &[
            "rustix",
            "serde_json",
            "tempfile",
            "tokio",
            "tunnel-cua",
            "tunnel-cua-export",
            "tunnel-deadman",
        ],
    ),
];

#[test]
fn the_m5_crates_declare_only_allowlisted_dependencies() {
    let root = workspace_root();
    for (crate_name, allowed) in M5_ALLOWED_DEPENDENCIES {
        let manifest = root.join("crates").join(crate_name).join("Cargo.toml");
        assert!(manifest.is_file(), "{} is missing", manifest.display());
        let names = manifest_dependency_names(&manifest);
        assert!(
            !names.is_empty(),
            "{crate_name} declares no dependencies at all; the scan is reading the wrong file"
        );
        for name in &names {
            assert!(
                allowed.contains(&name.as_str()),
                "{crate_name} declares {name}, which is not on *its own* M5 allowlist. \
                 Adding a dependency to an M5 crate is a safety decision, not a build detail."
            );
        }
    }

    // A tripwire against re-flattening the const, **not** a demonstration of
    // non-vacuity: both sides are literals written here, so this can only fail
    // if someone merges the two budgets back into one. The discrimination that
    // actually bites is the manifest loop above, which reads each crate's real
    // declarations -- under the old flat union the fixture could have taken
    // `tunnel-http-bridge` unnoticed, and now it cannot.
    let pure = M5_ALLOWED_DEPENDENCIES[0].1;
    let export = M5_ALLOWED_DEPENDENCIES[1].1;
    let fixture = M5_ALLOWED_DEPENDENCIES[2].1;
    assert!(pure.contains(&"tunnel-http-bridge") && !fixture.contains(&"tunnel-http-bridge"));
    assert!(fixture.contains(&"tokio") && !pure.contains(&"tokio"));
    // The supervisor gets the sentinel and the pure crate does not; the pure
    // crate gets the codec and the supervisor does not. Three budgets, not one.
    assert!(export.contains(&"tunnel-deadman") && !pure.contains(&"tunnel-deadman"));
    assert!(!export.contains(&"tunnel-http-bridge"));
}

/// Neither M5 crate declares a feature that could turn one of these on later.
///
/// Lane B — the real backend on a dedicated VM — is deliberately **not**
/// implemented in this chunk, and this test is what keeps a future Lane B
/// feature from being added to these crates without anyone noticing. When Lane
/// B does arrive it will need this test changed, deliberately, with an
/// argument.
#[test]
fn no_m5_crate_declares_any_optional_feature_yet() {
    let root = workspace_root();
    for crate_name in ["tunnel-cua", "tunnel-cua-export", "tunnel-cua-fixture"] {
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
