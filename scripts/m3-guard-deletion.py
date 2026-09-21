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
from guard_outcomes import check_anchors as shared_check_anchors  # noqa: E402
from guard_outcomes import unusable as unusable_outcomes  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEADMAN = REPO / "crates" / "tunnel-deadman"
EXPORT = REPO / "crates" / "tunnel-mcp-export"
FIXTURE = REPO / "crates" / "tunnel-mcp-fixture"

DEADMAN_LIB = DEADMAN / "src" / "lib.rs"
CHILD = EXPORT / "src" / "child.rs"
FIXTURE_LIB = FIXTURE / "src" / "lib.rs"

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

CASES: list[tuple[str, list[Edit], bool]] = [
    # ------------------------------------------- the sentinel fires on EOF
    (
        # The whole mechanism.  Without this line the sentinel still starts,
        # still watches and still exits — and the group it was watching
        # outlives the supervisor exactly as it did before this chunk.  This
        # case is also the red half of M3-09's red-then-green: with it applied,
        # the measured leak is the one the row records.
        "a bare end of file makes the sentinel kill the watched process group",
        [(DEADMAN_LIB, "    kill_group(leader);\n    EXIT_FIRED", "    EXIT_FIRED")],
        False,
    ),
    (
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
        False,
    ),
    (
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
        False,
    ),
    # ------------------------------------ the fixture's honesty about itself
    (
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
        False,
    ),
]


@dataclass
class Suite:
    name: str
    crates: list[Path]
    cargo_test: list[str]
    cases: list[tuple[str, list[Edit], bool]] = field(default_factory=list)
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

DEADMAN_CASES: list[tuple[str, list[Edit], bool]] = [
    (
        # The rule that makes a missing sentinel *detectable*.  Without it, a
        # configured path that names nothing resolves to a path anyway; `arm`
        # then fails at spawn instead of at resolution, and `availability` —
        # which the device's doctor reports and which starts no process —
        # would tell an operator the installation is watched when it is not.
        # A packaging slip would then be invisible in the one place built to
        # show it.
        "a configured sentinel path that names no file resolves to no sentinel",
        [
            (
                DEADMAN_LIB,
                "        return path.is_file().then_some(path);",
                "        return Some(path);",
            )
        ],
        False,
    ),
]

SUITES: list[Suite] = [
    Suite("m3c09", [DEADMAN, EXPORT, FIXTURE], CARGO_TEST, CASES),
    Suite("m3c09-deadman", [DEADMAN], DEADMAN_TEST, DEADMAN_CASES),
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


def restore(suite: Suite) -> None:
    subprocess.run(
        ["git", "checkout", "--"]
        + [str(crate.relative_to(REPO)) for crate in suite.crates],
        cwd=REPO,
        check=True,
    )


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
                    f"under {relative}; each case is restored by checking the "
                    "crate out again, which would discard them."
                )


def check_anchors(selected: list[tuple[Suite, str, list[Edit], bool]]) -> int:
    """Resolve every selected case's guard text, and stop (M4-27).

    The resolution, the STALLED/AMBIGUOUS split and the empty-selection
    refusal all live in `scripts/guard_outcomes.py`, shared with the other
    three harnesses; this only drops the per-case `expect_build_failure` flag,
    which an anchor check has no use for.
    """
    return shared_check_anchors(
        "m3-guard-deletion",
        ((suite.name, name, edits) for suite, name, edits, _ in selected),
    )


def main() -> int:
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
        (suite, name, edits, expect_build_failure)
        for suite in suites
        for name, edits, expect_build_failure in suite.cases
        if not arguments.case or arguments.case in name
    ]
    if arguments.list:
        for suite, name, _, _ in selected:
            print(f"{suite.name}: {name}")
        return 0
    if arguments.check_anchors:
        return check_anchors(selected)
    if not selected:
        sys.exit(f"m3-guard-deletion: no case matches {arguments.case!r}")

    require_clean_tree(suites)

    # **Preflight (M4-27).**  Resolve every selected case's anchors before any
    # case executes, and fail closed listing *all* mismatches at once.  The
    # per-case refusal in the loop below already fails the run and names
    # itself, so this changes no outcome and no count -- it moves an existing
    # refusal from the end of a multi-hour run to its first second.
    if check_anchors(selected) != 0:
        return 1

    results: list[tuple[str, str, str, list[str]]] = []
    for suite, name, edits, expect_build_failure in selected:
        problem = None
        for path, old, new in edits:
            text = path.read_text()
            occurrences = text.count(old)
            if occurrences == 0:
                problem = "guard text not found"
                break
            if occurrences > 1:
                problem = f"guard text is ambiguous: {occurrences} occurrences"
                break
            path.write_text(text.replace(old, new, 1))
        if problem is not None:
            restore(suite)
            results.append((suite.name, name, f"COULD NOT APPLY: {problem}", []))
            print(f"[{suite.name}] {name}: {problem}", flush=True)
            continue
        outcome, failures = run_tests(suite)
        restore(suite)
        sweep_residue()
        if name in EXPECT_GREEN:
            outcome = (
                "DOCUMENTED GREEN"
                if outcome == "still green"
                else f"EXPECTED A DOCUMENTED GREEN, GOT: {outcome}"
            )
        elif expect_build_failure:
            outcome = (
                "REFUSED BY COMPILER"
                if outcome == "BUILD FAILED"
                else f"EXPECTED A COMPILER REFUSAL, GOT: {outcome}"
            )
        elif outcome == "BUILD FAILED":
            outcome = "BUILD FAILED (not evidence)"
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
