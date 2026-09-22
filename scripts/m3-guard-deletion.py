#!/usr/bin/env python3
"""Defeat one process-containment guard at a time, run the tests it should
protect, and restore it.

This is the red-then-green evidence behind M3-09.  Two suites live here:

* `m3c09` — `crates/tunnel-deadman` and the stdio export's child supervision
  in `crates/tunnel-mcp-export`, witnessed by the process-table measurements
  in `crates/tunnel-mcp-fixture/tests/process_residue.rs`: the sentinel firing
  on a bare end of file, the sentinel being armed at all, the stand-down on
  the orderly path, and the fixture's own honesty about whether it really
  detached.
* `m3c09-deadman` — the resolution rule that decides whether an installation
  is watched at all, witnessed by `tunnel-deadman`'s own unit tests.

**One rule of M3-09 is deliberately not here**, and is recorded in that row's
"Not covered" list instead: the *ordering* of the stand-down against the group
kill.  Hoisting the stand-down above the kill leaves every test in both suites
green — measured by doing it, not inferred — and the reason is not the obvious
one — on a hoist the sentinel does not
fire early, it **does not fire at all**.  `watch` returns `EXIT_STOOD_DOWN` on
the stand-down token without calling `kill_group`, so in both orderings the
group is killed by the supervisor's own `kill_group` and the sentinel exits
stood-down either way; the `deadman_stood_down` counter reads that exit status,
so it increments in both.

What the ordering really guards is a **crash window**: the hoist leaves the
group alive and unwatched between the two calls, so a `SIGKILL` of the device
inside it leaks the group.  It is microseconds wide and cannot be hit
deterministically without widening it — and widening it is an **addition**,
which a deletion case may not make.  Hence no case, rather than a case that
would pass either way and look like coverage.

**The fourth case is not like the others and is the point of having it.**  It
defeats the *fixture*, not the product: it makes the escaping descendant fail
to escape.  Every containment measurement in `process_residue.rs` is built on
a descendant that genuinely left the process group, and a fixture that quietly
stopped detaching would turn those measurements into a test of nothing while
leaving them green.  The case proves the tests refuse that fixture instead of
reporting it as containment.

It follows `scripts/acp-guard-deletion.py`, `scripts/fs-guard-deletion.py` and
`scripts/m5-guard-deletion.py`, **including their refusals, none of which may
be removed**:

1. `run_tests` will not call a failed build a red test.  A deleted guard can
   leave the crate unbuildable, and counting that as evidence would credit the
   guard for a failure that says nothing about behaviour.
2. A case whose `old` text is **not unique** in its file is refused outright
   rather than applied to the first match.  `str.replace(old, new, 1)` edits
   whichever match comes first, so an ambiguous case would defeat some *other*
   guard and report a red for it under the wrong name.
3. A run that *timed out* returns `NOT EVIDENCE (timed out)`, not `RED (hung)`:
   a timed-out run names no failing test.

The classification of those outcomes is **not in this file**.  It lives in
`scripts/guard_outcomes.py`, shared with the other harnesses, and it is an
**allow list**: everything that is not a usable outcome fails closed.

Usage:

    python3 scripts/m3-guard-deletion.py            # every case
    python3 scripts/m3-guard-deletion.py --list
    python3 scripts/m3-guard-deletion.py --case sentinel
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_outcomes import AppliedCase  # noqa: E402
from guard_outcomes import check_anchors as shared_check_anchors  # noqa: E402
from guard_outcomes import install_interrupt_restore  # noqa: E402
from guard_outcomes import refuse_resident_mutation  # noqa: E402
from guard_outcomes import unusable as unusable_outcomes  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEADMAN = REPO / "crates" / "tunnel-deadman"
EXPORT = REPO / "crates" / "tunnel-mcp-export"
FIXTURE = REPO / "crates" / "tunnel-mcp-fixture"

CLIENT = REPO / "crates" / "tunnel-client"

DEADMAN_LIB = DEADMAN / "src" / "lib.rs"
CHILD = EXPORT / "src" / "child.rs"
FIXTURE_LIB = FIXTURE / "src" / "lib.rs"
DOCTOR = CLIENT / "src" / "doctor.rs"

# Only the containment measurements: the rest of this fixture crate's suite is
# the M3-02 end-to-end work and says nothing about these guards.  --no-fail-fast
# so every red test is named.
CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-mcp-fixture",
    "--test",
    "process_residue",
    "--locked",
    "--no-fail-fast",
]

#: **A fourth refusal, and this suite is the reason it exists (task row
#: M3-19).**  The tests here do not merely link the code under test: they
#: `exec` two *binaries*, `tunnel-mcp-fixture` and `tunnel-deadman`, and read
#: the process table for what those binaries did.  `cargo test --test
#: process_residue` selects test targets, and it builds **no binary belonging
#: to another package at all** — so a case that edits `crates/tunnel-deadman`
#: is run against whatever sentinel executable happened to be lying in the
#: target directory.
#:
#: That was measured, not assumed.  The first run of this suite reported the
#: sentinel's group kill as `still green` — a guard that is the entire
#: mechanism, defeated, with nothing going red — because the deleted code was
#: never rebuilt and the binary on disk still had it.  A harness that silently
#: tests a stale artifact is worse than no harness: it reports "this guard is
#: not load-bearing" about a guard that is.
#:
#: So every case builds these binaries first, and a build failure here is a
#: build failure for the case.  **This step may not be removed to make the
#: suite faster.**
CARGO_BUILD_BINARIES = [
    "cargo",
    "build",
    "--locked",
    "-p",
    "tunnel-deadman",
    "-p",
    "tunnel-mcp-fixture",
    "--bins",
]

# An edit is (file, exact text to remove or replace, replacement).
Edit = tuple[Path, str, str]


@dataclass(frozen=True)
class Case:
    """One defeated guard, and the test that must notice.

    **`expected_red` is why this is a class rather than the 3-tuple this file
    used to carry**, and the mechanism is lifted from
    `scripts/m0-guard-exit-codes.py` rather than reinvented.  Without it a
    case is classified `RED` on *any* named failing test, so a case can be
    green-lit by a failure that has nothing to do with the rule it claims to
    prove -- and a tally of such cases reads exactly like a tally of real
    ones.  That is the M5-C11 defect class applied to the evidence itself: the
    run's success and its measuring nothing look identical.

    Every value case therefore names the test(s) that must be among the
    failures.  If they are not, the outcome is `RED (wrong witness)`, which is
    absent from `guard_outcomes.USABLE_OUTCOMES` and fails the run.  A value
    case with no declared witness is refused before anything is edited.

    `expect_build_failure` cases declare none: a build failure names no test,
    and requiring one would be incoherent.
    """

    name: str
    edits: list[Edit]
    expected_red: frozenset[str] = frozenset()
    expect_build_failure: bool = False


CASES: list[Case] = [
    # ------------------------------------------- the sentinel fires on EOF
    Case(
        # The whole mechanism.  Without this line the sentinel still starts,
        # still watches and still exits — and the group it was watching
        # outlives the supervisor exactly as it did before this chunk.  This
        # case is also the red half of M3-09's red-then-green: with it applied,
        # the measured leak is the one the row records.
        "a bare end of file makes the sentinel kill the watched process group",
        [(DEADMAN_LIB, "    kill_group(leader);\n    EXIT_FIRED", "    EXIT_FIRED")],
        # The rule is that the sentinel signals the group when the supervisor
        # dies unexpectedly, so the witness is the measurement of exactly
        # that: a SIGKILLed supervisor whose child's group is gone afterwards.
        frozenset({"a_sigkilled_supervisor_still_kills_the_group"}),
    ),
    Case(
        # Arming at spawn.  A sentinel armed late — or not at all — leaves a
        # window in which a device crash orphans the group.
        "every stdio child is watched by a parent-death sentinel",
        [
            (
                CHILD,
                "    let deadman = group.and_then(tunnel_deadman::Deadman::arm);",
                "    let deadman: Option<tunnel_deadman::Deadman> = None;",
            )
        ],
        # An unarmed supervisor leaks the group on a SIGKILL: the same
        # measurement, reached because the sentinel that would have fired was
        # never spawned at all.
        frozenset({"a_sigkilled_supervisor_still_kills_the_group"}),
    ),
    Case(
        # The orderly path.  Dropping the handle instead of standing the
        # sentinel down still closes the pipe, but with **no token**, so the
        # sentinel reads a bare end of file and fires — a redundant group
        # `SIGKILL` sent after the supervisor has already killed and reaped
        # that group, which is the one moment at which the id may genuinely
        # have been freed.  (This is the token-failure path the deadman
        # module's docs name; it is not an argument about the *ordering* of
        # the stand-down, which guards a crash window instead.)  The counter
        # is how a test sees the difference between "stood down" and "fired
        # and nobody noticed".
        "an orderly end stands the sentinel down rather than letting it fire",
        [
            (
                CHILD,
                "            if tokio::task::spawn_blocking(move || deadman.stand_down())\n                .await\n                .unwrap_or(false)\n            {\n                supervisor_counters\n                    .deadman_stood_down\n                    .fetch_add(1, Ordering::Relaxed);\n            }",
                "            drop(deadman);",
            )
        ],
        # The `deadman_stood_down` counter distinguishes "stood down" from
        # "fired and nobody noticed", and exactly one test reads it.
        frozenset({"an_orderly_shutdown_stands_the_sentinel_down_instead_of_firing_it"}),
    ),
    # ------------------------------------ the fixture's honesty about itself
    Case(
        # Not a product guard: a fixture guard.  If the descendant stops
        # actually leaving the process group, the plain group kill reaches it
        # and every containment claim in `process_residue.rs` becomes a
        # measurement of nothing — while staying green.  The escape marker and
        # the assertion on it are what stop that, so defeating the escape must
        # redden the measurements rather than quietly weaken them.
        "a descendant that failed to detach is refused, not measured",
        [
            (
                FIXTURE_LIB,
                "        DetachRoute::Setsid => rustix::process::setsid().is_ok(),",
                "        DetachRoute::Setsid => false,",
            )
        ],
        # The escape marker's own assertion: a descendant that did not detach
        # must be refused rather than measured as containment.
        frozenset({"a_setsid_descendant_escapes_the_group_kill"}),
    ),
]


@dataclass
class Suite:
    name: str
    crates: list[Path]
    cargo_test: list[str]
    cases: list[Case] = field(default_factory=list)
    cwd: Path = REPO


#: A second suite, for the rules whose witnesses are `tunnel-deadman`'s own
#: unit tests rather than the process-table measurements.  It is separate
#: because a single `cargo test --test process_residue` names a target that
#: only the fixture crate has, and **this suite edits only a package its own
#: invocation rebuilds** — the rule M3-19 exists to state.
DEADMAN_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-deadman",
    "--locked",
    "--no-fail-fast",
]

DEADMAN_CASES: list[Case] = [
    Case(
        # The rule that makes a missing sentinel *detectable*.  Without it, a
        # configured path that names nothing resolves to a path anyway; `arm`
        # then fails at spawn instead of at resolution, and `availability` —
        # which the device's doctor reports and which starts no process —
        # would tell an operator the installation is watched when it is not.
        # A packaging slip would then be invisible in the one place built to
        # show it.
        #
        # **Re-anchored at M6-C08.**  The guard used to read `return
        # path.is_file().then_some(path);`; the explicit branch now delegates
        # to `classify`, and taking the path on trust is spelt as returning
        # `Usable` without classifying it.  The rule is unchanged.
        "a configured sentinel path that names no file resolves to no sentinel",
        [
            (
                DEADMAN_LIB,
                "        return classify(PathBuf::from(explicit));",
                "        return Resolution::Usable(PathBuf::from(explicit));",
            )
        ],
        frozenset({"tests::an_explicit_path_to_a_non_file_resolves_to_no_sentinel"}),
    ),
    # ------------------------------------------------------------- M6-C08
    Case(
        # **The defect the row measured.**  Without the mode test, a
        # zero-byte 0644 file named `tunnel-deadman` resolves as usable and
        # `doctor` reports `PROCESS_CONTAINMENT_SENTINEL_PRESENT` for an
        # installation that contains nothing.  Note the edit keeps the
        # regular-file half, so this case defeats the execute-bit rule
        # *alone* and cannot be credited to the other one.
        "a file of the sentinel's name with no execute bit is not a sentinel",
        [
            (
                DEADMAN_LIB,
                "        .is_ok_and(|metadata| metadata.is_file() "
                "&& metadata.permissions().mode() & 0o111 != 0)",
                "        .is_ok_and(|metadata| metadata.is_file())",
            )
        ],
        frozenset({"tests::a_zero_byte_decoy_wearing_the_sentinels_name_is_not_a_sentinel"}),
    ),
    Case(
        # The other half, defeated on its own for the same reason.  A
        # directory carries execute bits meaning "searchable", so the mode
        # test alone accepts a directory named `tunnel-deadman`.  The old
        # `is_file()` rule got this right by accident; it has to keep getting
        # it right on purpose.
        "a directory carrying execute bits is not a sentinel",
        [
            (
                DEADMAN_LIB,
                "        .is_ok_and(|metadata| metadata.is_file() "
                "&& metadata.permissions().mode() & 0o111 != 0)",
                "        .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)",
            )
        ],
        frozenset({"tests::a_directory_wearing_the_sentinels_name_is_not_a_sentinel"}),
    ),
    Case(
        # The distinct status itself.  Folding "a file is there and cannot be
        # run" back into "nothing is there" restores a report that is true
        # about containment and useless as advice: the operator is told to
        # install a `tunnel-deadman` they are looking straight at.
        "a file that is present and unusable is not reported as nothing being there",
        [
            (
                DEADMAN_LIB,
                "    } else {\n        Resolution::Unusable(path)\n    }\n}",
                "    } else {\n        Resolution::Absent\n    }\n}",
            )
        ],
        frozenset(
            {
                "tests::a_file_that_is_there_and_unusable_is_reported_apart_from_"
                "nothing_being_there"
            }
        ),
    ),
    Case(
        # Returning on the first unusable candidate is what the old rule did
        # -- it returned on the first `is_file()` -- and it would let a decoy
        # in `deps` hide the real sentinel one directory up, turning every
        # containment measurement in `process_residue.rs` into a measurement
        # of nothing while they stayed green.
        "an unusable candidate does not shadow a usable one further along the search",
        [
            (
                DEADMAN_LIB,
                "            Resolution::Unusable(path) => rejected = rejected.or(Some(path)),",
                "            Resolution::Unusable(path) => return Resolution::Unusable(path),",
            )
        ],
        frozenset({"tests::a_decoy_in_deps_does_not_shadow_the_real_sentinel_above_it"}),
    ),
    Case(
        # An explicit `TUNNEL_DEADMAN_BIN` that names an unusable file must
        # not fall back to the search.  A fallback would resolve to some
        # *other* file and report success -- the shape of M6-C08 itself, one
        # level up: a configuration mistake reported as a working
        # installation.
        "an explicit sentinel path that is unusable does not fall back to the search",
        [
            (
                DEADMAN_LIB,
                "        return classify(PathBuf::from(explicit));",
                "        let explicit = classify(PathBuf::from(explicit));\n"
                "        if let Resolution::Usable(_) = explicit {\n"
                "            return explicit;\n"
                "        }",
            )
        ],
        frozenset({"tests::an_explicit_unusable_path_does_not_fall_back_to_the_search"}),
    ),
]

#: The doctor's own mapping, in its own suite because it lives in a different
#: package and M3-19's rule is that a suite may only edit packages its own
#: `cargo test` invocation rebuilds.
DOCTOR_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-client",
    "--locked",
    "--no-fail-fast",
    "doctor::",
]

DOCTOR_CASES: list[Case] = [
    Case(
        # The product rule and the surface that reports it are separate
        # guards, and only this one is about what an operator reads.  The
        # resolution rule could be perfect and this mapping could still fold
        # the two degraded states together, which is the state M6-C08 asked
        # not to be left in.
        "an unusable sentinel is reported with its own doctor code",
        [
            (
                DOCTOR,
                '            code: "PROCESS_CONTAINMENT_SENTINEL_UNUSABLE",',
                '            code: "PROCESS_CONTAINMENT_SENTINEL_MISSING",',
            )
        ],
        frozenset(
            {
                "doctor::tests::a_missing_parent_death_sentinel_is_reported_and_"
                "does_not_fail_the_doctor"
            }
        ),
    ),
]

SUITES: list[Suite] = [
    Suite("m3c09", [DEADMAN, EXPORT, FIXTURE], CARGO_TEST, CASES),
    Suite("m3c09-deadman", [DEADMAN], DEADMAN_TEST, DEADMAN_CASES),
    Suite("m6c08-doctor", [CLIENT], DOCTOR_TEST, DOCTOR_CASES),
]

#: Cases whose green result is itself the measurement.  Empty today, and kept
#: so a future case that needs one has the mechanism rather than inventing it.
EXPECT_GREEN: set[str] = set()


def cargo_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    env.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")
    env.setdefault("CARGO_INCREMENTAL", "0")
    return env


def run_tests(suite: Suite) -> tuple[str, list[str]]:
    """Run one suite's tests and classify the outcome.

    A build that did not compile is **never** reported as a red test.

    The binaries the tests `exec` are rebuilt first; see
    [`CARGO_BUILD_BINARIES`] for why a stale one is a silent false green.
    """
    try:
        built = subprocess.run(
            CARGO_BUILD_BINARIES,
            cwd=suite.cwd,
            env=cargo_env(),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return "NOT EVIDENCE (timed out)", []
    if built.returncode != 0:
        return "BUILD FAILED", []
    try:
        done = subprocess.run(
            suite.cargo_test,
            cwd=suite.cwd,
            env=cargo_env(),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return "NOT EVIDENCE (timed out)", []
    combined = done.stdout + done.stderr
    if "error[" in combined or "error: could not compile" in combined:
        return "BUILD FAILED", []
    failures = sorted(
        {
            line.strip().removeprefix("test ").removesuffix(" ... FAILED")
            for line in done.stdout.splitlines()
            if line.strip().endswith("... FAILED")
        }
    )
    if done.returncode == 0:
        return "still green", []
    if not failures:
        return "NOT EVIDENCE (no named failure)", []
    return "RED", failures


# **The `git checkout --` restore that used to live here is gone (M5-C07).**
# It was replaced by `guard_outcomes.AppliedCase`, which writes back the exact
# bytes it recorded before mutating.  Deleted rather than left unused on
# purpose: it checked out whole crate directories, so any other uncommitted
# work under them was discarded with the mutation -- the M4-32 mechanism -- and
# a dead helper spelling exactly that is an invitation to call it again.  It is
# not a rule being removed to go green: no case reaches it any more, and the
# tree-cleanliness contract it served is now held by `AppliedCase.restore` plus
# the journal that `refuse_resident_mutation` reads.


def sweep_residue() -> None:
    """Kill anything this suite's fixtures left behind.

    Unlike every other guard-deletion harness in this repository, the cases
    here deliberately defeat process cleanup, and a case that goes red is
    *precisely* a case where something survived.  The fixture's own pid guards
    handle the ordinary path, but a build failure or a timeout can leave a
    descendant with a 180-second lifetime running on a developer's machine.
    Nothing else in this file may assume it was tidy.
    """
    for mode in ("detached", "descendant", "wrapper", "supervise", "daemonize"):
        subprocess.run(
            ["/usr/bin/pkill", "-9", "-f", f"tunnel-mcp-fixture {mode}"],
            capture_output=True,
            check=False,
        )
    subprocess.run(
        ["/usr/bin/pkill", "-9", "-f", "tunnel-deadman "],
        capture_output=True,
        check=False,
    )


def require_clean_tree(suites: list[Suite]) -> None:
    for suite in suites:
        for crate in suite.crates:
            relative = str(crate.relative_to(REPO))
            changed = subprocess.run(
                ["git", "status", "--porcelain", "--", relative],
                cwd=REPO,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if changed:
                sys.exit(
                    "m3-guard-deletion: refusing to run with uncommitted changes "
                    f"under {relative}; a case applied on top of them could not "
                    "be told apart from them, and the run would report a guard "
                    "as load-bearing on the strength of somebody else's edit. "
                    "Each case is restored by writing back the exact bytes it "
                    "recorded (M5-C07), so these changes would survive a run -- "
                    "but the evidence would not be trustworthy."
                )


def check_anchors(selected: list[tuple[Suite, Case]]) -> int:
    """Resolve every selected case's guard text, and stop (M4-27).

    The resolution, the STALLED/AMBIGUOUS split and the empty-selection
    refusal all live in `scripts/guard_outcomes.py`, shared with the other
    three harnesses; this only drops the per-case `expect_build_failure` flag,
    which an anchor check has no use for.
    """
    return shared_check_anchors(
        "m3-guard-deletion",
        ((suite.name, case.name, case.edits) for suite, case in selected),
    )


def require_declared_witnesses(selected: list[tuple[Suite, Case]]) -> None:
    """Refuse a value case that names no test, before anything is edited.

    Without this the `expected_red` mechanism is opt-in, and a case added with
    the field omitted silently falls back to the "any red will do" behaviour
    it exists to reject -- the mechanism's own version of the defect it
    guards.  Lifted from `scripts/m0-guard-exit-codes.py` along with the
    mechanism, because the refusal is the half that makes it hold.
    """
    problems = [
        f"[{suite.name}] {case.name}"
        for suite, case in selected
        if not case.expect_build_failure and not case.expected_red
    ] + [
        f"[{suite.name}] {case.name} (compiler refusal may not declare a witness)"
        for suite, case in selected
        if case.expect_build_failure and case.expected_red
    ]
    if problems:
        sys.exit(
            "m3-guard-deletion: every value case must name the test(s) that "
            "must redden, and a compiler-refusal case must name none; a case "
            "classified RED by an unrelated failure is not evidence for the "
            "rule it claims. Offending case(s): " + ", ".join(problems)
        )


def main() -> int:
    # M5-C07: make `SIGTERM`/`SIGHUP` raise, so the per-case `AppliedCase`
    # context manager restores on the way out instead of being skipped.
    install_interrupt_restore()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print case names and exit")
    parser.add_argument(
        "--check-anchors",
        action="store_true",
        help=(
            "check every case's guard text without building anything, and exit "
            "non-zero if any anchor is missing or ambiguous"
        ),
    )
    parser.add_argument("--case", help="run only cases whose name contains this text")
    parser.add_argument("--suite", help="run only this suite (m3c09, m3c09-deadman)")
    arguments = parser.parse_args()

    suites = SUITES
    if arguments.suite:
        suites = [suite for suite in SUITES if suite.name == arguments.suite]
        if not suites:
            sys.exit(f"m3-guard-deletion: no suite named {arguments.suite!r}")
    selected = [
        (suite, case)
        for suite in suites
        for case in suite.cases
        if not arguments.case or arguments.case in case.name
    ]
    if arguments.list:
        for suite, case in selected:
            witnesses = ", ".join(sorted(case.expected_red)) or "(compiler refusal)"
            print(f"{suite.name}: {case.name} -> {witnesses}")
        return 0
    if arguments.check_anchors:
        return check_anchors(selected)
    if not selected:
        sys.exit(f"m3-guard-deletion: no case matches {arguments.case!r}")

    # **M5-C07, before anything is edited.**  `require_clean_tree`
    # below refuses on a dirty tree, which already stops a second run
    # stacking on a resident mutation -- but it can only say
    # "something is uncommitted", about a tree the operator may
    # believe they dirtied themselves.  This names the harness, suite,
    # case and files a previous interrupted run left mutated, because
    # a resident mutation is a guard deleted from the product and not
    # a tidying job.  Placed *after* the `--check-anchors` dispatch so
    # read-only mode stays a pure anchor check (M4-34, M4-36).
    refuse_resident_mutation("m3-guard-deletion", REPO)
    require_declared_witnesses(selected)
    require_clean_tree(suites)

    # **Preflight (M4-27).**  Resolve every selected case's anchors before any
    # case executes, and fail closed listing *all* mismatches at once.  The
    # per-case refusal in the loop below already fails the run and names
    # itself, so this changes no outcome and no count -- it moves an existing
    # refusal from the end of a multi-hour run to its first second.
    if check_anchors(selected) != 0:
        return 1

    results: list[tuple[str, str, str, list[str]]] = []
    for suite, case in selected:
        name = case.name
        # **M5-C07.**  The apply/test/restore cycle runs inside a context
        # manager, so the restore happens on *every* way out of this block --
        # a refusal, an exception, a `KeyboardInterrupt`, or the `SystemExit`
        # that `install_interrupt_restore` turns a `SIGTERM` into.  It
        # restores the exact recorded original bytes rather than running `git
        # checkout --` over the crate, which would discard any other
        # uncommitted work under that path (M4-32).  This harness is the one
        # M4-36 bypassed into running its whole destructive suite under
        # `--check-anchors`, so an interrupted case here is not hypothetical.
        #
        # The residue sweep is in a `finally` for the same reason the restore
        # is in a context manager: this suite's cases deliberately defeat
        # process cleanup, so an *interrupted* case is exactly the one whose
        # fixtures are most likely to have outlived it.  Leaving the sweep
        # after the `with` block meant an interrupt skipped it -- the tree
        # stayed clean, but descendants with a 180-second lifetime were left
        # running on the developer's machine.  It is inside the `try` so it
        # also runs after the restore rather than racing it.
        try:
            with AppliedCase("m3-guard-deletion", REPO, suite.name, name) as applied:
                problem = applied.apply_all(case.edits)
                if problem is not None:
                    results.append((suite.name, name, f"COULD NOT APPLY: {problem}", []))
                    print(f"[{suite.name}] {name}: {problem}", flush=True)
                    continue
                outcome, failures = run_tests(suite)
        finally:
            sweep_residue()
        if name in EXPECT_GREEN:
            outcome = (
                "DOCUMENTED GREEN"
                if outcome == "still green"
                else f"EXPECTED A DOCUMENTED GREEN, GOT: {outcome}"
            )
        elif case.expect_build_failure:
            outcome = (
                "REFUSED BY COMPILER"
                if outcome == "BUILD FAILED"
                else f"EXPECTED A COMPILER REFUSAL, GOT: {outcome}"
            )
        elif outcome == "BUILD FAILED":
            outcome = "BUILD FAILED (not evidence)"
        elif outcome == "RED":
            # **The witness check.**  `RED` means *something* failed; it does
            # not mean the rule this case names was the thing that noticed.
            # An outcome spelt this way is absent from
            # `guard_outcomes.USABLE_OUTCOMES`, so it fails the run rather
            # than being counted as evidence for a rule it did not test.
            missing = sorted(case.expected_red - set(failures))
            if missing:
                outcome = (
                    "RED (wrong witness): expected "
                    + ", ".join(missing)
                    + " to redden, got "
                    + (", ".join(failures) if failures else "nothing")
                )
        results.append((suite.name, name, outcome, failures))
        print(
            f"[{suite.name}] {name}: {outcome} {failures if failures else ''}".rstrip(),
            flush=True,
        )

    print("\n=== summary ===")
    for suite_name, name, outcome, failures in results:
        detail = f" -> {', '.join(failures)}" if failures else ""
        print(f"- [{suite_name}] {name}: {outcome}{detail}")
    for suite in suites:
        rows = [row for row in results if row[0] == suite.name]
        if not rows:
            continue
        red = sum(1 for row in rows if row[2] == "RED")
        compiler = sum(1 for row in rows if row[2] == "REFUSED BY COMPILER")
        documented = sum(1 for row in rows if row[2] == "DOCUMENTED GREEN")
        measurable = len(rows) - compiler - documented
        print(f"\n{suite.name}: {red} of {measurable} defeated guards turned a test red")
        if documented:
            print(
                f"{suite.name}: {documented} guard(s) reported separately as a documented green"
            )
        if compiler:
            print(
                f"{suite.name}: {compiler} further guard(s) are enforced by the "
                "compiler and are reported separately, never counted as a red test"
            )

    unusable = unusable_outcomes(
        (suite_name, name, outcome) for suite_name, name, outcome, _ in results
    )
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
