#!/usr/bin/env python3
"""Defeat one operator-surface guard at a time, run the tests it should
protect, and restore it.

This is the red-then-green evidence behind M0-03's exit-code vocabulary.
The guards live in `crates/tunnel-client/src/main.rs` and are witnessed by
that binary's unit tests plus the real-process fixtures in
`crates/tunnel-client/tests/exit_codes_cli.rs`.

**What the row is about.** `CliError::exit_code` used to match `&'static str`
with a `_ => 1` arm.  Six live causes had no entry in that table, so they
exited `1`, "unexpected internal failure" -- including `OWNER_BUSY` (another
connector already holds the device) and `CANCELLED` (the session was
interrupted).  Those need different operator actions and the process's exit
status, the first thing a supervisor or a tester reads, said the same thing
about all of them.  The fix replaces the string table with a closed `Cause`
enum matched exhaustively.

**Two kinds of case live here, and the distinction is the point.**

* Cases marked `expect_build_failure` are the *totality* rule.  Removing an
  arm from `Cause::exit_code`, `Cause::code` or `Cause::from_client` makes
  the match non-exhaustive, and the crate does not compile.  These are
  reported as `REFUSED BY COMPILER` and are **never counted as a red test**:
  a build failure names no behaviour, and counting it as one would credit the
  guard for a failure that says nothing.  They are still worth running,
  because a `_` arm reintroduced anywhere would turn the refusal into a
  silent green -- which is the original defect returning.
* Every other case edits a *value* the compiler cannot check -- which number
  a cause maps to, which string it publishes, whether a transport detail is
  appended to a message -- and must turn a named test red.

**One rule is deliberately not here.**  Exit `6` (`OUTCOME_UNKNOWN`) is
documented in `docs/runtime.md` and has no producer in this binary, so there
is nothing to defeat.  A case for it would have to add the producer first,
and an addition is not a deletion: it would measure the case's own code.
The gap is named in `docs/runtime.md` and in M0-03 instead of being faked
here.

It follows `scripts/m3-guard-deletion.py`, `scripts/acp-guard-deletion.py`,
`scripts/fs-guard-deletion.py` and `scripts/m5-guard-deletion.py`,
**including their refusals, none of which may be removed**:

1. `run_tests` will not call a failed build a red test.
2. A case whose `old` text is not unique in its file is refused outright
   rather than applied to the first match.
3. A run that timed out returns `NOT EVIDENCE (timed out)`, not `RED (hung)`.

The classification of those outcomes lives in `scripts/guard_outcomes.py`,
shared with the other harnesses, and is an allow list: everything that is not
a usable outcome fails closed.

Usage:

    python3 scripts/m0-guard-exit-codes.py            # every case
    python3 scripts/m0-guard-exit-codes.py --list
    python3 scripts/m0-guard-exit-codes.py --check-anchors
    python3 scripts/m0-guard-exit-codes.py --case owner
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
CLIENT = REPO / "crates" / "tunnel-client"

MAIN = CLIENT / "src" / "main.rs"
LIB = CLIENT / "src" / "lib.rs"

#: The whole client suite.  It is seconds long, and the guards here are
#: witnessed by both the binary's unit tests and the process fixtures, which
#: are separate test targets: naming one target would silently drop the other
#: half of the evidence.  `--no-fail-fast` so every red test is named.
CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-client",
    "--locked",
    "--no-fail-fast",
]

#: The fixtures in `exit_codes_cli.rs` `exec` the built `tunnel-client`
#: binary, so the binary must be rebuilt before each case.  `cargo test -p`
#: does build this package's own binaries for its integration tests, so this
#: is belt and braces rather than the M3-19 situation -- but it is cheap, and
#: the failure it prevents (a case reported as `still green` because the
#: measurement ran against a stale executable) is the one that makes a
#: harness worse than no harness.
CARGO_BUILD_BINARIES = [
    "cargo",
    "build",
    "--locked",
    "-p",
    "tunnel-client",
    "--bins",
]

# An edit is (file, exact text to remove or replace, replacement).
Edit = tuple[Path, str, str]

CASES: list[tuple[str, list[Edit], bool]] = [
    # ------------------------------------------- the distinctions themselves
    (
        # The headline case.  This *is* the old behaviour: before this row,
        # `OWNER_BUSY` fell through `_ => 1`.  A tester who started a second
        # connector saw "unexpected internal failure" and had no way to learn
        # that the answer was to stop the first one.
        "a held owner slot is not reported as an internal failure",
        [
            (
                MAIN,
                "            Self::OwnerBusy | Self::ResourceExhausted => 7,",
                "            Self::OwnerBusy | Self::ResourceExhausted => 1,",
            )
        ],
        False,
    ),
    (
        # Also the old behaviour.  An interrupted session is the single most
        # common non-success outcome a foreground `connect` has, and it was
        # indistinguishable from a crash.
        "an interrupted session is not reported as an internal failure",
        [(MAIN, "            Self::Cancelled => 130,", "            Self::Cancelled => 1,")],
        False,
    ),
    (
        # A stale authorization is an authorization decision, not a bug.  The
        # documented meaning of `3` is "untrusted credentials / authorization
        # denied"; putting this at `1` tells an operator to file a defect
        # report instead of re-authorizing.
        "a stale authorization is reported as an authorization failure",
        [
            (
                MAIN,
                "            Self::CredentialError | Self::AuthorizationStale => 3,",
                "            Self::CredentialError => 3,\n            Self::AuthorizationStale => 1,",
            )
        ],
        False,
    ),
    (
        # The one non-doctor status any fixture in this repository can reach
        # on a real process.  Defeating it is what proves
        # `a_refused_relay_connection_exits_four_and_names_the_transport` can
        # redden **for the reason it names** rather than merely being green:
        # the `ExitCode::from` plumbing between `Cause::exit_code` and the
        # caller's `$?` has no other witness.
        "the chosen exit code reaches the process exit status",
        [
            (
                MAIN,
                "            Self::TransportError | Self::SessionClosed => 4,",
                "            Self::TransportError | Self::SessionClosed => 1,",
            )
        ],
        False,
    ),
    # ------------------------------------------------ the published vocabulary
    (
        # The exit code is what a script reads; the code string is what a
        # human and a log search read.  They are separate surfaces and both
        # have to be pinned, or a mapping can be "fixed" in one and left
        # wrong in the other.
        "the published diagnostic code is not interchangeable with another",
        [
            (
                MAIN,
                '            Self::OwnerBusy => "OWNER_BUSY",',
                '            Self::OwnerBusy => "SUPERVISOR_FAILED",',
            )
        ],
        False,
    ),
    # -------------------------------------------------------- the redaction
    (
        # **Redaction is the hard constraint on these surfaces.**  An error
        # message's whole job is to describe internal state, so it is exactly
        # where a backend error escapes.
        #
        # **This case applies two edits, and the reason is a measurement.**
        # It was first written with only the second edit -- appending `detail`
        # to the generic transport arm -- and the run reported `RED` against
        # an unrelated `m2_runtime` rotation test while the redaction fixture
        # it was written for **stayed green**.  A case that reddens something
        # other than the rule it names is not evidence for that rule, so the
        # first edit was found by probing rather than assumed: `sanitize_error`
        # discards the underlying error at construction, so with it intact the
        # appended `detail` is the constant `"transport failure"` and nothing
        # leaks.  The redaction here is genuinely two independent layers, and
        # only defeating both puts `IO error: Connection refused (os error 61)`
        # in front of an operator.
        #
        # It must redden `assert_transport_message_is_bounded`, which is the
        # assertion in that fixture that can redden at all.  The endpoint and
        # path entries in `assert_redacted` cannot: this error path does not
        # produce them even fully unredacted, and the fixture says so rather
        # than letting them read as coverage.
        "a transport failure does not print the underlying backend error",
        [
            (
                LIB,
                '    let _ = error;\n    "transport failure".to_owned()',
                "    error.to_owned()",
            ),
            (
                LIB,
                '            Self::Transport { scope, .. } => format!("{scope} failed"),',
                '            Self::Transport { scope, detail } => format!("{scope} failed: {detail}"),',
            ),
        ],
        False,
    ),
    # ------------------------------------------------ the shared vocabulary
    (
        # The cross-crate rule, and the one this row got wrong before a
        # reviewer would have.  `CLI_DIAGNOSTIC_EXIT_CODES` is what the
        # production-cluster chaos gate classifies a connector's
        # pre-readiness exit against.  A cause mapped to a status outside it
        # is classified `Unclassified`, which blocks release -- and until
        # this row the gate held its *own copy* of the list, so the drift
        # was invisible on both sides.  Mapping to an unpublished status
        # must fail in the connector's own tests, not at a release gate
        # hours later.
        "an exit status outside the published vocabulary is refused",
        [
            (
                MAIN,
                "            Self::OwnerBusy | Self::ResourceExhausted => 7,",
                "            Self::OwnerBusy | Self::ResourceExhausted => 9,",
            )
        ],
        False,
    ),
    # ------------------------------------------------- totality, by compiler
    (
        # The rule that replaced the string table.  Removing an arm leaves
        # the match non-exhaustive and the crate does not build.  Reported
        # separately and never counted as a red test.
        "every cause must state an exit code or the crate does not compile",
        [
            (
                MAIN,
                "            Self::DeadlineExceeded => 5,\n",
                "",
            )
        ],
        True,
    ),
    (
        # The same rule for the classification of connector errors.  A new
        # `ClientError` variant cannot reach the CLI unclassified.
        "every connector error must be classified or the crate does not compile",
        [
            (
                MAIN,
                "            ClientError::OwnerBusy => Self::OwnerBusy,\n",
                "",
            )
        ],
        True,
    ),
]


@dataclass
class Suite:
    name: str
    crates: list[Path]
    cargo_test: list[str]
    cases: list[tuple[str, list[Edit], bool]] = field(default_factory=list)
    cwd: Path = REPO


#: A second suite, for the rule whose witness lives in the production-cluster
#: harness rather than in the connector.  It is separate because it names a
#: different package: `cargo test -p tunnel-client` builds no test target of
#: `tunnel-test-harness`, so a case edited into the classifier would be run
#: against nothing at all and reported as `still green` -- the M3-19 failure.
HARNESS = REPO / "crates" / "tunnel-test-harness"
CHAOS = HARNESS / "src" / "production_cluster" / "chaos.rs"

HARNESS_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "--no-fail-fast",
    "production_cluster::chaos::tests::a_pre_readiness",
]

HARNESS_CASES: list[tuple[str, list[Edit], bool]] = [
    (
        # The other half of the cross-crate rule.  A classifier that accepts
        # every status classifies a signal death and a spurious success as
        # interruptions, which is worse than the drift it replaced: the gate
        # would report a clean run through exactly the failures it exists to
        # catch.  The `Some(9)` and `Some(-1)` assertions are what stop it.
        "the exit classifier does not accept every status",
        [
            (
                CHAOS,
                "            if u8::try_from(code)\n                .is_ok_and(|code| tunnel_client::CLI_DIAGNOSTIC_EXIT_CODES.contains(&code)) =>",
                "            if u8::try_from(code).is_ok_and(|_| true) =>",
            )
        ],
        False,
    ),
]

SUITES: list[Suite] = [
    Suite("m0c03-exit-codes", [CLIENT], CARGO_TEST, CASES),
    Suite("m0c03-classifier", [HARNESS], HARNESS_TEST, HARNESS_CASES),
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
    """
    try:
        built = subprocess.run(
            CARGO_BUILD_BINARIES,
            cwd=suite.cwd,
            env=cargo_env(),
            capture_output=True,
            text=True,
            timeout=900,
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
            timeout=900,
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
                    "m0-guard-exit-codes: refusing to run with uncommitted changes "
                    f"under {relative}; a case applied on top of them could not "
                    "be told apart from them, and the run would report a guard "
                    "as load-bearing on the strength of somebody else's edit. "
                    "Each case is restored by writing back the exact bytes it "
                    "recorded (M5-C07), so these changes would survive a run -- "
                    "but the evidence would not be trustworthy."
                )


def check_anchors(selected: list[tuple[Suite, str, list[Edit], bool]]) -> int:
    """Resolve every selected case's guard text, and stop (M4-27)."""
    return shared_check_anchors(
        "m0-guard-exit-codes",
        ((suite.name, name, edits) for suite, name, edits, _ in selected),
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
    parser.add_argument("--suite", help="run only this suite (m0c03-exit-codes, m0c03-classifier)")
    arguments = parser.parse_args()

    suites = SUITES
    if arguments.suite:
        suites = [suite for suite in SUITES if suite.name == arguments.suite]
        if not suites:
            sys.exit(f"m0-guard-exit-codes: no suite named {arguments.suite!r}")
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
        sys.exit(f"m0-guard-exit-codes: no case matches {arguments.case!r}")

    # M5-C07, before anything is edited: name the harness, suite, case and
    # files a previous interrupted run left mutated.  Placed after the
    # `--check-anchors` dispatch so read-only mode stays a pure anchor check
    # (M4-34, M4-36).
    refuse_resident_mutation("m0-guard-exit-codes", REPO)
    require_clean_tree(suites)

    # Preflight (M4-27): resolve every selected case's anchors before any
    # case executes, and fail closed listing all mismatches at once.
    if check_anchors(selected) != 0:
        return 1

    results: list[tuple[str, str, str, list[str]]] = []
    for suite, name, edits, expect_build_failure in selected:
        with AppliedCase("m0-guard-exit-codes", REPO, suite.name, name) as applied:
            problem = applied.apply_all(edits)
            if problem is not None:
                results.append((suite.name, name, f"COULD NOT APPLY: {problem}", []))
                print(f"[{suite.name}] {name}: {problem}", flush=True)
                continue
            outcome, failures = run_tests(suite)
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
