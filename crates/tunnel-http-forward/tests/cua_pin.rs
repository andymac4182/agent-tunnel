//! The CUA pin, checked against the documents that actually decide it.
//!
//! `src/cua_pin.rs` records what was pinned. These tests read the real
//! `docs/sources.md` and `docs/integrations.md` and compare, so the record
//! cannot drift from the artifact: deleting a digest, repointing the release
//! commit, or quietly widening the command allowlist turns a test red instead
//! of leaving a stale sentence in a document.
//!
//! What this does **not** show: that the pinned server works, that it was ever
//! started, or that anything in this repository has spoken to a `/cmd`
//! endpoint. It shows only that the artifact named in the document is the
//! artifact named in the code, and that both are the one that was hashed.
//!
//! The re-fetch-and-re-hash half of the pin rule is `scripts/m5-cua-refetch.sh`,
//! which downloads both files again and compares them to the constants here.
//! It is not run from a unit test on purpose: a test that reaches the network
//! is a test that goes red when PyPI is slow, and the verification pass is
//! where re-fetching belongs.

use std::path::{Path, PathBuf};

use tunnel_http_forward::cua_pin;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the workspace root is two levels above this crate")
}

fn read_doc(name: &str) -> String {
    let path = workspace_root().join("docs").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn sources_md_records_every_digest_this_pin_claims() {
    let sources = read_doc("sources.md");
    for (what, digest) in [
        ("the wheel", cua_pin::WHEEL_SHA256),
        ("the sdist", cua_pin::SDIST_SHA256),
        ("main.py", cua_pin::MAIN_PY_SHA256),
        // The parameter half of the pin. Recorded separately because it is a
        // separate file answering a separate question -- M5-C06.
        ("handlers/base.py", cua_pin::BASE_PY_SHA256),
    ] {
        assert!(
            sources.contains(digest),
            "docs/sources.md no longer records the SHA-256 of {what} ({digest}). \
             A pin that is only in code is a pin the verification pass cannot re-check."
        );
    }
}

/// The parameter pin is only a pin because something re-derives it from the
/// artifact. If that wiring is removed, `COMMAND_PARAMETERS` degrades to a
/// table agreeing with itself — which is the exact shape M5-C06 was filed
/// about, one level up. So the wiring is asserted rather than assumed.
#[test]
fn the_refetch_script_still_re_derives_the_parameter_pin() {
    let root = workspace_root();
    let refetch = std::fs::read_to_string(root.join("scripts").join("m5-cua-refetch.sh"))
        .expect("scripts/m5-cua-refetch.sh");

    assert!(
        refetch.contains("m5-cua-param-parity.py"),
        "the refetch script no longer invokes the parameter-parity check, so \
         COMMAND_PARAMETERS is no longer compared against upstream by anything"
    );
    assert!(
        refetch.contains(cua_pin::BASE_PY_SHA256),
        "the refetch script no longer re-hashes handlers/base.py, so the file \
         the parameter table is read from is unpinned"
    );
    assert!(
        root.join("scripts")
            .join("m5-cua-param-parity.py")
            .is_file(),
        "scripts/m5-cua-param-parity.py is missing"
    );

    // Positive control: this test reads the real script, and these two lines
    // have been in it since M5-01. Without them the three assertions above
    // would pass identically against an empty string.
    assert!(refetch.contains(cua_pin::MAIN_PY_SHA256));
    assert!(refetch.contains(cua_pin::WHEEL_SHA256));
}

#[test]
fn sources_md_records_the_release_commit_the_version_and_the_python_requirement() {
    let sources = read_doc("sources.md");
    for needle in [
        cua_pin::RELEASE_COMMIT,
        cua_pin::VERSION,
        cua_pin::DISTRIBUTION,
        cua_pin::REQUIRES_PYTHON,
    ] {
        assert!(
            sources.contains(needle),
            "docs/sources.md no longer records {needle}"
        );
    }
}

/// The reconciliation is the correction this pin carries, so losing it is a
/// regression in its own right.
#[test]
fn sources_md_still_records_the_divergence_from_the_inspected_tree() {
    let sources = read_doc("sources.md");
    assert!(
        sources.contains(cua_pin::INSPECTED_COMMIT),
        "docs/sources.md no longer names the inspected development commit, so the \
         reconciliation between it and the released artifact has been lost"
    );
    assert!(
        sources.contains(cua_pin::INSPECTED_VERSION),
        "docs/sources.md no longer records that the inspected commit declares {}, \
         which is the whole reason it is not the pin",
        cua_pin::INSPECTED_VERSION
    );
    // The reconciliation originally claimed the two trees differed only in
    // `pyproject.toml`. That was false — `handlers/cua_driver.py` differs too,
    // and it is a file this pin cites. Losing that sentence would restore the
    // overclaim, so it is asserted rather than trusted to survive editing.
    assert!(
        sources.contains("cua_driver.py"),
        "docs/sources.md no longer records that handlers/cua_driver.py differs \
         between the inspected and released commits"
    );
    assert!(
        sources.contains("desktop_capture_authorized"),
        "docs/sources.md no longer records what that difference actually changes"
    );
}

/// `/ws` being deferred is a decision with a reason, not an omission.
#[test]
fn the_websocket_deferral_is_recorded_as_a_decision() {
    let sources = read_doc("sources.md");
    assert!(
        sources.contains(cua_pin::WEBSOCKET_DEFERRAL_RECORDED_AS),
        "docs/sources.md no longer says {:?}, so the deferred surface reads as \
         an omission rather than a choice",
        cua_pin::WEBSOCKET_DEFERRAL_RECORDED_AS
    );
}

/// Both of these are load-bearing for any adapter that parses a `/cmd`
/// response, and both were confirmed against the released sdist. If the
/// documents stop saying so, an adapter author will reach for a JSON body
/// parser and a status-code check, and both will be wrong.
#[test]
fn the_two_downstream_critical_properties_are_still_written_down() {
    let integrations = read_doc("integrations.md");
    assert!(
        integrations.contains(cua_pin::CMD_MEDIA_TYPE),
        "docs/integrations.md no longer names the {} media type of /cmd",
        cua_pin::CMD_MEDIA_TYPE
    );
    assert!(
        integrations.contains("success:false") || integrations.contains("success: false"),
        "docs/integrations.md no longer warns that a successful HTTP status can \
         carry a failed command result"
    );
    // These two assertions must compare the constants against the *document*,
    // not against literals retyped here. An earlier version checked
    // `SUCCESS_FALSE_UNDER_200_EVIDENCE.contains("StreamingResponse")` and
    // `PRE_DISPATCH_ERROR_STATUSES == [400, 401]`, which could only fail if
    // someone edited the constant in the same commit — `assert!(CONST)` with
    // the lint sidestepped syntactically rather than answered.
    assert!(
        integrations.contains("StreamingResponse")
            || integrations.contains("after the response has begun"),
        "docs/integrations.md no longer records *why* a 200 can carry a failure, \
         so {} is a claim with nothing behind it",
        cua_pin::SUCCESS_FALSE_UNDER_200_EVIDENCE
    );
    assert!(
        integrations.contains("HTTPException"),
        "docs/integrations.md no longer records that pre-dispatch failures bypass \
         the data: framing"
    );
    for status in cua_pin::PRE_DISPATCH_ERROR_STATUSES {
        assert!(
            integrations.contains(&status.to_string()),
            "docs/integrations.md no longer names the pre-dispatch status {status}"
        );
    }
}

/// Every allowlisted command must appear in the operation table that claims to
/// map to it. This is what stops the code allowlist and the document's table
/// from drifting apart in either direction.
#[test]
fn every_allowlisted_command_appears_in_the_operation_table() {
    let integrations = read_doc("integrations.md");
    let table: String = integrations
        .lines()
        .filter(|line| line.starts_with('|'))
        .collect::<Vec<_>>()
        .join("\n");

    // Non-vacuity: if the table ever stops being found, the per-command
    // assertions below would all pass against an empty haystack.
    assert!(
        table.contains("Computer Server command"),
        "the computer.v1 operation table is no longer in docs/integrations.md"
    );

    for command in cua_pin::ALLOWED_COMMANDS {
        assert!(
            table.contains(*command),
            "{command} is allowlisted in code but absent from the operation table \
             in docs/integrations.md"
        );
    }
}

/// The withdrawal is a decision, not a note. A future chunk that reintroduces
/// a `cua-driver` profile should have to delete this test deliberately.
#[test]
fn the_driver_is_recorded_as_an_extra_of_the_pinned_server_not_a_separate_profile() {
    let sources = read_doc("sources.md");
    assert!(
        sources.contains(cua_pin::DRIVER_EXTRA_REQUIREMENT),
        "docs/sources.md no longer records the driver extra as {}",
        cua_pin::DRIVER_EXTRA_REQUIREMENT
    );
    assert!(
        !cua_pin::DRIVER_EXTRA_REQUIREMENT.contains("0.24.0"),
        "the extra's range excludes the 0.24.0 the withdrawn premise quoted"
    );
}

/// The re-fetch script is the executable half of the pin rule, so its absence
/// is a failure of the pin and not merely a missing file.
#[test]
fn the_refetch_script_exists_and_names_both_digests() {
    let path = workspace_root().join("scripts").join("m5-cua-refetch.sh");
    let script = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    for digest in [cua_pin::WHEEL_SHA256, cua_pin::SDIST_SHA256] {
        assert!(
            script.contains(digest),
            "scripts/m5-cua-refetch.sh does not compare against {digest}, so running \
             it would prove less than it claims"
        );
    }
}

/// **M5-C13: the scroll sign convention is pinned and written down.** Three
/// pinned handlers state that positive `y` scrolls up; the constant names each
/// file and phrase, and `docs/integrations.md` must say so to a consumer,
/// because the adapter passes `dy` through unchanged.
#[test]
fn the_scroll_sign_convention_is_pinned_and_recorded_for_consumers() {
    let files: Vec<&str> = cua_pin::SCROLL_SIGN_CONVENTION
        .iter()
        .map(|(file, _)| *file)
        .collect();
    assert_eq!(
        files,
        [
            "handlers/macos.py",
            "handlers/windows.py",
            "handlers/vnc.py",
            "handlers/linux.py",
            "handlers/cua_driver.py",
        ],
        "the three handlers that state a convention and the two that fix it in code"
    );
    for (file, phrase) in cua_pin::SCROLL_SIGN_CONVENTION {
        assert!(
            phrase.to_ascii_lowercase().contains("up"),
            "{file}: the recorded phrase must be the one that states the direction"
        );
    }
    let integrations = read_doc("integrations.md");
    assert!(
        integrations.contains("**positive `dy` scrolls up**"),
        "docs/integrations.md no longer tells a consumer which way `dy` scrolls"
    );
    assert!(
        integrations.contains("cua_pin::SCROLL_SIGN_CONVENTION"),
        "docs/integrations.md no longer points at the pinned evidence"
    );
}
