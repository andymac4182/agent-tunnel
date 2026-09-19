#!/usr/bin/env python3
"""Defeat one process-containment guard at a time, run the tests it should
protect, and restore it.

This is the red-then-green evidence behind M3-09.  One suite lives here:

* `m3c09` — `crates/tunnel-deadman` and the stdio export's child supervision
  in `crates/tunnel-mcp-export`: the sentinel firing on a bare end of file,
  the sentinel being armed at all, the stand-down on the orderly path, and the
  fixture's own honesty about whether it really detached.

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
        # sentinel down still closes the pipe, so the sentinel fires a group
        # signal at an id whose group has already been reaped and may since
        # have been reissued.  The counter is how a test sees the difference
        # between "stood down" and "fired and nobody noticed".
        "an orderly end stands the sentinel down rather than letting it fire",
        [
            (
                CHILD,
                "            let _ = tokio::task::spawn_blocking(move || deadman.stand_down()).await;",
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


SUITES: list[Suite] = [Suite("m3c09", [DEADMAN, EXPORT, FIXTURE], CARGO_TEST, CASES)]

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
    """
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print case names and exit")
    parser.add_argument("--case", help="run only cases whose name contains this text")
    parser.add_argument("--suite", help="run only this suite (m3c09)")
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
    if not selected:
        sys.exit(f"m3-guard-deletion: no case matches {arguments.case!r}")

    require_clean_tree(suites)

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
