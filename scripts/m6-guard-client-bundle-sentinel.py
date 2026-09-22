#!/usr/bin/env python3
"""Red-then-green evidence for one rule: **a bundle that contains
`tunnel-client` contains a working `tunnel-deadman` beside it.**

This is M6-C06's evidence.  The rule itself lives in
`scripts/client-bundle-sentinel.sh`, shared by every script that assembles a
directory of tunnel binaries, and the reason it is shared as an *assertion*
rather than as a binary list is in that file's header: the three assemblers
legitimately carry different binaries, and what they must agree on is
narrower than any of their lists.

**Two suites, and the split is the honest part.**

* `assembler` runs `scripts/m7-local-artifact-verify.sh` for real, against
  binaries the caller has already built, and is where a *code* edit to an
  assembler is required to be caught.  That script is the cheap one to run
  because it does not build anything.
* `rule` runs the shared assertion directly against constructed directories.
  These are probes of the rule, **not** coverage of any assembler, and are
  reported separately for that reason.  They exist because three of the
  rule's four witnesses are unreachable through `m7-local-artifact-verify.sh`
  -- its `resolve_input_path` (called by `validate_binary`) rejects a
  missing, symlinked or non-executable input at its own three `die` lines
  before the shared rule ever sees the staged directory -- and a witness no
  case can reach is the defect recorded as instance fourteen of
  `docs/tasks.md` row M5-C11.  Naming them here, in a suite that says what it
  is, is the alternative to letting them look exercised.

  **Measured, because the Fable review read this claim as false** -- it read
  `validate_binary` alone, which only checks `file -b` for Mach-O, and
  concluded a non-executable input would reach the rule.  Passing a 0644
  copy of the real `tunnel-deadman` as `--deadman-bin` answers
  `m7-local-artifact-verify: binary is not executable: ...`, so the claim
  holds and the reachability argument above stands.  The function that makes
  it is now named here, so the next reader can check it in one hop instead of
  two.

**`scripts/m7-local-source-parity-build.sh` is not run here, and that is a
stated gap rather than a silent one.**  Its assembly step is behind a full
`cargo build --locked --workspace --bins` of an immutable source copy, so a
case costs minutes and a run costs tens of them.  Its `copy_binary
tunnel-deadman` line is anchored by `--check-anchors` (so a rename or a
reflow is caught in seconds), and the red-then-green for it was measured once
by hand and recorded on the M6-C06 row rather than being asserted here from
memory.

**What makes a green here evidence.**  The shared assertion prints a line
naming the directory it verified and the probe exit it got, and the green
control below requires that line.  Without it a pass and a call that never
ran would look identical -- which is the defect this harness's own subject
had in its first draft (instance seventeen of M5-C11), and the standing rule
from `docs/testing.md`.

Usage:

    python3 scripts/m6-guard-client-bundle-sentinel.py \\
        --client-bin target/debug/tunnel-client
    python3 scripts/m6-guard-client-bundle-sentinel.py --list
    python3 scripts/m6-guard-client-bundle-sentinel.py --check-anchors
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_outcomes import AppliedCase  # noqa: E402
from guard_outcomes import check_anchors as shared_check_anchors  # noqa: E402
from guard_outcomes import install_interrupt_restore  # noqa: E402
from guard_outcomes import refuse_resident_mutation  # noqa: E402
from guard_outcomes import unusable as unusable_outcomes  # noqa: E402

HARNESS = "m6-guard-client-bundle-sentinel"
REPO = Path(__file__).resolve().parent.parent
RULE = REPO / "scripts" / "client-bundle-sentinel.sh"
VERIFY = REPO / "scripts" / "m7-local-artifact-verify.sh"
PARITY = REPO / "scripts" / "m7-local-source-parity-build.sh"

#: The success line the shared assertion prints.  Required by the green
#: control, so that control fails if the call is removed rather than passing
#: because nothing objected.
RAN_MARKER = "answered the no-argument probe with exit 2"

WITNESS = re.compile(r"\[witness=([a-z0-9-]+)\]")

Edit = tuple[Path, str, str]


@dataclass(frozen=True)
class Case:
    """One defeated assembler, or one defective sentinel, and its witness.

    `edits` mutates a product body -- an assembler script.  `plant` mutates
    the *inputs* instead, the way `scripts/m6-release-artifact.py`'s controls
    mutate a bundle: it is handed the staging directory and returns the
    `--deadman-bin` path to pass, or `None` to pass none.  A case uses one or
    the other, never both, so the thing being measured is never ambiguous.

    `expected_witness` is mandatory for a red case.  A run that fails for a
    different reason is `RED (wrong witness)`, which is not a usable outcome:
    the rule declares four distinct witnesses precisely because the fixes
    differ, and a case satisfied by any failure would let three of them rot.
    """

    name: str
    expected_witness: str | None = None
    edits: list[Edit] = field(default_factory=list)
    plant: str | None = None
    expect_green: bool = False


# --------------------------------------------------------------- the runner


def run_verify(client: Path, staging: Path, deadman: Path | None) -> tuple[int, str]:
    """Run the observer script over one prepared input set."""
    command = [
        "/bin/sh",
        str(VERIFY),
        "--client-bin",
        str(client),
        "--output-dir",
        str(staging / "out"),
        # Stated explicitly rather than inferred.  `infer_profile` matches on
        # `*/target/debug/*`, and an agent-scoped `CARGO_TARGET_DIR` is not
        # named `target`, so inference would refuse before any case could
        # measure anything -- which is how this argument was found.
        "--profile",
        "debug",
    ]
    if deadman is not None:
        command += ["--deadman-bin", str(deadman)]
    completed = subprocess.run(
        command, cwd=str(REPO), capture_output=True, text=True, timeout=300, check=False
    )
    return completed.returncode, completed.stdout + completed.stderr


def run_rule(bundle: Path) -> tuple[int, str]:
    """Run the shared assertion alone against one constructed directory."""
    script = (
        f". {RULE!s}\n"
        f'assert_client_sentinel_beside "{bundle}" guard-probe\n'
        'echo "guard-probe: returned 0"\n'
    )
    completed = subprocess.run(
        ["/bin/sh", "-c", script],
        cwd="/",
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return completed.returncode, completed.stdout + completed.stderr


def classify(case: Case, status: int, output: str) -> str:
    """Map one run onto the shared outcome vocabulary, failing closed."""
    if case.expect_green:
        if status != 0:
            return f"EXPECTED A DOCUMENTED GREEN, GOT exit {status}"
        if RAN_MARKER not in output:
            # The whole point of the control.  A zero exit with no success
            # line means the assertion did not run, which is exactly what a
            # deleted call looks like.
            return (
                "EXPECTED A DOCUMENTED GREEN, GOT a pass with no evidence the "
                "assertion ran (no success line)"
            )
        return "DOCUMENTED GREEN"
    if status == 0:
        return "still green with its mechanism defeated"
    found = WITNESS.search(output)
    witness = found.group(1) if found else None
    if witness is None:
        return f"RED (wrong witness): expected {case.expected_witness}, got no witness"
    if witness != case.expected_witness:
        return f"RED (wrong witness): expected {case.expected_witness}, got {witness}"
    return "RED"


# ---------------------------------------------------------------- the cases

#: Code edits to an assembler.  Only `sentinel-missing` is reachable this
#: way in `m7-local-artifact-verify.sh`: its `validate_binary` rejects a
#: missing, non-executable or symlinked `--deadman-bin` before the shared
#: assertion ever sees the staged directory.
ASSEMBLER_CASES: list[Case] = [
    Case(
        # The defect itself, one script over.  `m7-local-source-parity-
        # build.sh` omitted `tunnel-deadman` from its copy list; this is the
        # same omission in the sibling that consumes its output, and the
        # sibling could not inherit the producer's fix because it takes each
        # binary as its own flag.
        "an assembled bundle without the sentinel is refused",
        expected_witness="sentinel-missing",
        edits=[
            (
                VERIFY,
                'copy_binary tunnel-deadman "$deadman_path" "$deadman_file_type"\n',
                "",
            )
        ],
    ),
    Case(
        # The rule is about the *assembled* directory, not about the inputs.
        # Copying the sentinel somewhere other than beside the client passes
        # every input check and still ships a client that cannot resolve it,
        # because `sentinel_path()` looks beside `current_exe()`.
        "a sentinel copied somewhere other than beside the client is refused",
        expected_witness="sentinel-missing",
        edits=[
            (
                VERIFY,
                'copy_binary tunnel-deadman "$deadman_path" "$deadman_file_type"',
                'mkdir -p "$bin_dir/elsewhere"\n'
                '    cp -p "$deadman_path" "$bin_dir/elsewhere/tunnel-deadman"',
            )
        ],
    ),
    Case(
        # Nothing is defeated.  This must pass *and* say it checked, which is
        # the difference between a control and a green line.
        "an unmodified assembly reports that it verified the sentinel",
        expect_green=True,
    ),
]

#: Input mutations, probing the rule directly.  These say nothing about any
#: assembler's coverage and are reported under their own suite name.
RULE_CASES: list[Case] = [
    Case(
        "a bundle with no sentinel at all is refused",
        expected_witness="sentinel-missing",
        plant="absent",
    ),
    Case(
        # The decoy.  `tunnel_deadman::resolve_sentinel` accepts any
        # `is_file()`, so a file of the right name makes `availability()`
        # answer `Armable` while every arming attempt fails.  Executing it is
        # the only thing that tells the two apart, and this case is what
        # proves the probe is doing that rather than checking a mode bit.
        "a decoy of the sentinel's name that is not the sentinel is refused",
        expected_witness="sentinel-not-the-sentinel",
        plant="decoy",
    ),
    Case(
        "a sentinel that is not executable is refused",
        expected_witness="sentinel-not-executable",
        plant="not-executable",
    ),
    Case(
        "a sentinel that is a symlink is refused",
        expected_witness="sentinel-not-a-regular-file",
        plant="symlink",
    ),
    Case(
        # Instance seventeen of M5-C11, as a case.  The first draft of the
        # rule returned 0 for a directory with no client in it, so pointing
        # the check at the wrong path -- the likeliest way to defeat it --
        # was indistinguishable from a pass.
        "the rule cannot be satisfied by being pointed at nothing",
        expected_witness="bundle-dir-missing",
        plant="no-such-directory",
    ),
    Case(
        "an intact bundle reports what it verified",
        expect_green=True,
        plant="intact",
    ),
]


@dataclass
class Suite:
    name: str
    cases: list[Case]


SUITES: list[Suite] = [
    Suite("m6c06-assembler", ASSEMBLER_CASES),
    Suite("m6c06-rule", RULE_CASES),
]


# ------------------------------------------------------------ input staging


def stage_rule_bundle(staging: Path, client: Path, deadman: Path, plant: str) -> Path:
    """Build one bundle directory for a `rule` case."""
    if plant == "no-such-directory":
        return staging / "absent-directory"
    bundle = staging / "bin"
    bundle.mkdir(parents=True)
    shutil.copy2(client, bundle / "tunnel-client")
    target = bundle / "tunnel-deadman"
    if plant == "absent":
        return bundle
    if plant == "intact":
        shutil.copy2(deadman, target)
        return bundle
    if plant == "decoy":
        # A real, executable file that is emphatically not the sentinel: a
        # shell script exiting 0, where tunnel-deadman exits 2 for a wrong
        # argument list.  A zero-byte file would be caught by the mode check
        # first and would measure that instead of the probe.
        #
        # `shutil.copy`, not `copy2`, and a written script rather than a
        # copy of a system binary: `/bin/echo` carries macOS file flags that
        # `copystat` cannot reproduce into a temporary directory, so copying
        # it raises before the case can measure anything.
        target.write_text("#!/bin/sh\nexit 0\n")
        target.chmod(0o755)
        return bundle
    if plant == "not-executable":
        shutil.copy2(deadman, target)
        target.chmod(0o644)
        return bundle
    if plant == "symlink":
        target.symlink_to(deadman)
        return bundle
    raise AssertionError(f"unknown plant {plant!r}")


# ------------------------------------------------------------------ the run


def check_anchors(selected: list[tuple[Suite, Case]]) -> int:
    """Resolve every selected case's guard text, and stop (M4-27).

    The parity build's own copy line is anchored here even though no case
    runs that script, so a rename or a reflow of the line this row added is
    caught in a second rather than at the next release.
    """
    extra: list[str] = []
    anchor = "copy_binary tunnel-deadman\n"
    occurrences = PARITY.read_text().count(anchor)
    if occurrences != 1:
        extra.append(
            f"[m6c06-parity] the parity build's sentinel copy resolves to "
            f"{occurrences} occurrences of {anchor!r} in "
            f"{PARITY.relative_to(REPO)}, not 1"
        )
    return shared_check_anchors(
        HARNESS,
        ((suite.name, case.name, case.edits) for suite, case in selected),
        extra,
    )


def require_clean_tree(suites: list[Suite]) -> None:
    """Refuse to run over somebody else's uncommitted edit to the scripts.

    The same rule the other harnesses hold over their crates, held here over
    the two files a case may edit: a case applied on top of an uncommitted
    change cannot be told apart from it, and the run would report the rule as
    load-bearing on the strength of an edit it did not make.
    """
    del suites  # every suite in this harness edits the same two scripts
    for path in (VERIFY, RULE, PARITY):
        relative = str(path.relative_to(REPO))
        changed = subprocess.run(
            ["git", "status", "--porcelain", "--", relative],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if changed:
            sys.exit(
                f"{HARNESS}: refusing to run with uncommitted changes to "
                f"{relative}; a case applied on top of them could not be told "
                "apart from them, and the run would report the rule as "
                "load-bearing on the strength of somebody else's edit."
            )


def require_declared_witnesses(selected: list[tuple[Suite, Case]]) -> None:
    """Refuse a red case that names no witness, before anything is edited."""
    problems = [
        f"[{suite.name}] {case.name}"
        for suite, case in selected
        if not case.expect_green and not case.expected_witness
    ] + [
        f"[{suite.name}] {case.name} (a green control may not declare a witness)"
        for suite, case in selected
        if case.expect_green and case.expected_witness
    ] + [
        f"[{suite.name}] {case.name} (a case may not both edit code and plant inputs)"
        for suite, case in selected
        if case.edits and case.plant
    ]
    if problems:
        sys.exit(
            f"{HARNESS}: every red case must name the witness it expects, a "
            "green control must name none, and no case may both edit an "
            "assembler and plant inputs. Offending case(s): "
            + ", ".join(problems)
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-bin", help="a built tunnel-client")
    parser.add_argument("--deadman-bin", help="a built tunnel-deadman")
    parser.add_argument("--case", help="substring of a case name")
    parser.add_argument("--suite", help="one suite name")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--check-anchors", action="store_true")
    arguments = parser.parse_args()

    install_interrupt_restore()

    suites = SUITES
    if arguments.suite:
        suites = [suite for suite in suites if suite.name == arguments.suite]
        if not suites:
            sys.exit(f"{HARNESS}: no suite named {arguments.suite!r}")
    selected = [
        (suite, case)
        for suite in suites
        for case in suite.cases
        if not arguments.case or arguments.case in case.name
    ]
    if arguments.list:
        for suite, case in selected:
            witness = case.expected_witness or "(green control)"
            print(f"{suite.name}: {case.name} -> {witness}")
        return 0
    if arguments.check_anchors:
        return check_anchors(selected)
    if not selected:
        sys.exit(f"{HARNESS}: no case matches {arguments.case!r}")

    if not arguments.client_bin:
        sys.exit(
            f"{HARNESS}: --client-bin is required; this harness runs real "
            "assemblies and does not build anything itself"
        )
    client = Path(arguments.client_bin)
    if not client.is_absolute():
        client = REPO / client
    deadman = (
        Path(arguments.deadman_bin)
        if arguments.deadman_bin
        else client.parent / "tunnel-deadman"
    )
    for binary in (client, deadman):
        if not binary.is_file():
            sys.exit(f"{HARNESS}: not a file: {binary}")

    refuse_resident_mutation(HARNESS, REPO)
    require_declared_witnesses(selected)
    require_clean_tree(suites)
    if check_anchors(selected) != 0:
        return 1

    results: list[tuple[str, str, str]] = []
    for suite, case in selected:
        with tempfile.TemporaryDirectory() as raw:
            staging = Path(raw)
            if suite.name == "m6c06-rule":
                bundle = stage_rule_bundle(staging, client, deadman, case.plant or "intact")
                status, output = run_rule(bundle)
                outcome = classify(case, status, output)
            else:
                with AppliedCase(HARNESS, REPO, suite.name, case.name) as applied:
                    problem = applied.apply_all(case.edits)
                    if problem is not None:
                        results.append((suite.name, case.name, f"COULD NOT APPLY: {problem}"))
                        print(f"[{suite.name}] {case.name}: {problem}", flush=True)
                        continue
                    status, output = run_verify(client, staging, deadman)
                outcome = classify(case, status, output)
        results.append((suite.name, case.name, outcome))
        print(f"[{suite.name}] {case.name}: {outcome}", flush=True)

    print()
    problems = unusable_outcomes((suite, name, outcome) for suite, name, outcome in results)
    red = sum(1 for _, _, outcome in results if outcome == "RED")
    green = sum(1 for _, _, outcome in results if outcome == "DOCUMENTED GREEN")
    print(
        f"{HARNESS}: {len(results)} case(s): {red} red with the declared "
        f"witness, {green} documented green"
    )
    if problems:
        for problem in problems:
            print(f"{HARNESS}: {problem}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
