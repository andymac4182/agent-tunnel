#!/usr/bin/env python3
"""Tests for the shared guard-deletion outcome classifier.

The allowlist in `guard_outcomes.py` is the whole defence against the class of
defect recorded as M8-C06 and M8-C08: an outcome spelling nobody classified
used to vanish from every tally and let the run exit 0.  An allowlist can still
fail the same way if it quietly grows, so the three cases that matter are
pinned here.

    python3 scripts/test_guard_outcomes.py
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from guard_outcomes import (  # noqa: E402
    USABLE_OUTCOMES,
    AppliedCase,
    check_anchors,
    is_usable,
    mutation_journal,
    recover_mutations,
    refuse_resident_mutation,
    unusable,
)


def check(condition: bool, message: str) -> None:
    if not condition:
        sys.exit(f"test_guard_outcomes: {message}")


def main() -> int:
    # The three usable outcomes, and nothing else.
    check(is_usable("RED"), "RED must be usable")
    check(is_usable("REFUSED BY COMPILER"), "a compiler refusal must be usable")
    check(is_usable("DOCUMENTED GREEN"), "a documented green must be usable")
    check(
        USABLE_OUTCOMES == {"RED", "REFUSED BY COMPILER", "DOCUMENTED GREEN"},
        "the allowlist grew: a new usable outcome needs its own case here, and "
        "a task row saying why a non-red result counts as evidence",
    )

    # A guard that was defeated with nothing going red is NOT evidence.  This
    # is the spelling that was open in both harnesses after M8-C06 (M8-C08).
    check(not is_usable("still green"), "still green must not be usable")

    # An expectation that did not hold is not evidence either, in both
    # directions: a guard that should have refused to compile and did not, and
    # a documented green that actually went red.
    check(
        not is_usable("EXPECTED A COMPILER REFUSAL, GOT: RED"),
        "a missed compiler refusal must not be usable",
    )
    check(
        not is_usable("EXPECTED A DOCUMENTED GREEN, GOT: RED"),
        "a documented green that went red must not be usable: the rule became "
        "load-bearing and the comment explaining the green is now wrong",
    )

    # Anything nobody has ever classified fails closed, which is the property
    # the old deny-list-of-prefixes did not have.
    check(not is_usable("SOMETHING NOBODY HAS WRITTEN YET"), "must fail closed")
    check(not is_usable(""), "an empty outcome must fail closed")

    # The listing names the case and explains the spellings that understate
    # themselves.
    rows = [
        ("gate4", "a load-bearing guard", "RED"),
        ("gate4", "a documented green", "DOCUMENTED GREEN"),
        ("gate4", "a guard that is not load-bearing", "still green"),
    ]
    listed = unusable(rows)
    check(len(listed) == 1, f"exactly one unusable row, got {listed}")
    check("a guard that is not load-bearing" in listed[0], "the case is named")
    check("NOTHING went red" in listed[0], "the green is explained, not just echoed")

    every_module_filter_is_anchored()
    the_preflight_refuses_a_stalled_anchor()
    the_preflight_refuses_an_ambiguous_anchor()
    the_preflight_refuses_an_empty_selection()
    the_preflight_accepts_an_anchor_that_resolves_once()
    the_preflight_lists_every_mismatch_not_just_the_first()
    a_harness_local_problem_still_fails_the_preflight()
    every_guard_anchor_resolves_to_exactly_one_occurrence()

    # M5-C07, behavioural first and source-text last.
    an_interrupted_case_restores_the_tree_on_the_way_out()
    a_sigterm_mid_case_restores_the_tree()
    a_sigkilled_run_leaves_a_journal_that_names_the_case()
    every_harness_mutates_through_the_interrupt_safe_context()

    print("test_guard_outcomes: PASS")
    return 0


def run_preflight(selection, extra_problems=()) -> tuple[int, str]:
    """`check_anchors` over a synthetic selection, with its output captured."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = check_anchors("test-harness", selection, extra_problems)
    return code, out.getvalue()


@contextlib.contextmanager
def anchor_file(body: str):
    """A throwaway file to resolve a synthetic anchor against.

    Synthetic only: the preflight fixtures must never depend on the repository's
    real guard text, or they would go red whenever a guard is legitimately
    rewritten and stop testing the preflight at all.
    """
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "guarded.rs"
        path.write_text(body)
        yield path


def the_preflight_refuses_a_stalled_anchor() -> None:
    """Zero matches is STALLED, and it fails the run (M4-27).

    This is the direction the harness could not previously hold: it was
    checked by hand in `m4c32` and nothing stopped it from rotting back.
    """
    with anchor_file("fn keep() {}\n") as path:
        code, output = run_preflight(
            [("suite1", "a guard whose anchor a formatter rewrapped",
              [(path, "fn gone()", "")])]
        )
    check(code == 1, f"a stalled anchor must fail the run, got exit {code}")
    check("STALLED: guard text not found" in output,
          f"a stalled anchor must be named STALLED, got {output!r}")
    check("a guard whose anchor a formatter rewrapped" in output,
          f"the stalled case must be named, got {output!r}")


def the_preflight_refuses_an_ambiguous_anchor() -> None:
    """More than one match is AMBIGUOUS, and it fails the run (M4-27).

    `str.replace(old, new, 1)` edits the FIRST match, so an ambiguous anchor
    measures some other guard and reports a red for it under this case's name.
    The count matters as well as the refusal: "2 occurrences" is what tells
    the reader the anchor is shared rather than missing.
    """
    with anchor_file("let x = 1;\nlet x = 1;\n") as path:
        code, output = run_preflight(
            [("suite1", "a guard whose text is not unique",
              [(path, "let x = 1;", "")])]
        )
    check(code == 1, f"an ambiguous anchor must fail the run, got exit {code}")
    check("AMBIGUOUS: 2 occurrences" in output,
          f"an ambiguous anchor must be named with its count, got {output!r}")


def the_preflight_refuses_an_empty_selection() -> None:
    """A selection of nothing must refuse, not report a clean sweep (M4-27).

    `--check-anchors --case no-such-case` used to print "checked 0 anchors ...
    every anchor resolves" and exit 0.  A check that passes because it measured
    nothing proves less than it claims, which is the one defect this whole file
    exists to refuse -- so it is pinned here rather than trusted to stay fixed.
    """
    code, output = run_preflight([])
    check(code == 1, f"an empty selection must refuse, got exit {code}")
    check("not evidence" in output,
          f"the refusal must say why it refused, got {output!r}")
    check("every anchor resolves" not in output,
          f"an empty selection must never claim a clean sweep, got {output!r}")


def the_preflight_accepts_an_anchor_that_resolves_once() -> None:
    """The green direction, so the three refusals above are not vacuous.

    Without this a `check_anchors` that returned 1 unconditionally would pass
    every refusal fixture, and they would prove nothing about the preflight.
    """
    with anchor_file("let x = 1;\n") as path:
        code, output = run_preflight(
            [("suite1", "a guard that resolves", [(path, "let x = 1;", "")])]
        )
    check(code == 0, f"a unique anchor must pass, got exit {code}: {output!r}")
    check("checked 1 anchors" in output,
          f"the pass must say how much it checked, got {output!r}")


def the_preflight_lists_every_mismatch_not_just_the_first() -> None:
    """All mismatches at once, which is the entire point of a preflight.

    One `cargo fmt` rewraps several anchors together -- the m5c2 and m5c3
    shape.  A preflight that stopped at the first would still cost one full
    run per stalled anchor, which is the cost this row exists to remove, so
    "reports all of them" is a rule and not an implementation detail.
    """
    with anchor_file("fn keep() {}\nlet x = 1;\nlet x = 1;\n") as path:
        code, output = run_preflight(
            [
                ("suite1", "stalled one", [(path, "fn gone()", "")]),
                ("suite1", "stalled two", [(path, "fn also_gone()", "")]),
                ("suite2", "ambiguous one", [(path, "let x = 1;", "")]),
            ]
        )
    check(code == 1, f"mismatches must fail the run, got exit {code}")
    for name in ("stalled one", "stalled two", "ambiguous one"):
        check(name in output, f"{name!r} must be listed, got {output!r}")
    check("3 anchor problem(s)" in output,
          f"all three mismatches must be counted, got {output!r}")
    check("across 2 suite(s)" in output,
          f"both suites must be reported, got {output!r}")


#: Raised 8 -> 9 by gate 14 (`production_cluster::fs_rename_restart::`).  This
#: is the anti-vacuity floor for the anchoring scan -- what stops that rule
#: passing when it has matched *nothing* -- and not itself what covers gate 14,
#: since `every_module_filter_is_anchored` already inspects gate 14's filter
#: along with the rest.
EXPECTED_MODULE_FILTERS = 9

#: The floor each harness's `--check-anchors` must clear, so a run that
#: selected almost nothing cannot pass as a clean sweep.  Measured on
#: `m4c33-guard-preflight` off `154ac5d`: fs 427 anchors / 13 suites,
#: acp 148 / 7, m5 82 / 3, m3 5 / 2.  These are floors, not equalities --
#: adding a guard case must not break this file -- but a drop means either a
#: deleted case, which belongs in a task row, or a selection that stopped
#: selecting, which is the vacuity trap.
#:
#: **Re-measured on `m4c35-trename-restart`, and the fs floor had gone slack.**
#: The 427 above was already stale at `a8b30a1`, which really carries **431**
#: across 13 suites: four cases were added after that measurement without this
#: floor or the M4-06 row's roll-up following them.  A floor four short of the
#: truth still passes, which is exactly how it stops being a floor -- so it is
#: re-measured here rather than incremented, to what gate 14's tip actually
#: reports: **485 across 14 suites**.
#:
#: It was briefly set to 486 and this file caught it: gate 14 removed one
#: guard case after that reading, and the floor -- being an *at least* -- is
#: the one figure in this repository that fails loudly when it is set above
#: the truth rather than below it.  That is the whole point of it, and the
#: correction was taken by re-running `--check-anchors`, not by subtracting
#: one.
EXPECTED_GUARD_ANCHORS = {
    "fs-guard-deletion.py": 485,
    "acp-guard-deletion.py": 148,
    # Measured at the m5c8 tip: 100 anchors across 7 suites. The floor stood
    # at 82 and had gone stale across three chunks, so it no longer noticed a
    # suite dropping out.
    "m5-guard-deletion.py": 100,
    "m3-guard-deletion.py": 5,
    # **Two harnesses that were never in this registry at all**, added by the
    # m6c3 worker (M6-C06/M6-C07).  Absence here is quieter than a stale
    # floor: every rule this file holds over a guard harness -- the
    # `--check-anchors` short circuit, `AppliedCase`, `install_interrupt_
    # restore`, `refuse_resident_mutation`, the banned rewrite spellings --
    # was simply not applied to them.  Measured at `38d857b`:
    # m0 13 anchors across 2 suites, m6 2 across 2.
    #
    # m6's two is small because most of its cases plant inputs rather than
    # edit code, and that is the honest figure: a floor set to the number of
    # *cases* would pass while the anchored ones rotted.
    "m0-guard-exit-codes.py": 13,
    "m6-guard-client-bundle-sentinel.py": 2,
}


def every_module_filter_is_anchored() -> None:
    """Every `production_cluster::<module>` test filter must end in `::`.

    Without the anchor a filter is a **prefix** of any module whose name
    extends it, and cargo's filter is a substring match -- so that suite
    silently selects another gate's cases and measures rules that are not its
    own.  That happened: `production_cluster::fs_rotation` began selecting
    gate 12's six cases the moment `fs_rotation_write` existed.

    Fixing the one collision would leave the class open, because the next
    module named as an extension of an existing one re-creates it in silence.
    This is the rule, held where it cannot rot back.
    """
    script = (Path(__file__).resolve().parent / "fs-guard-deletion.py").read_text()
    seen = [line.strip() for line in script.splitlines() if '"production_cluster::' in line]
    unanchored = [line for line in seen if not line.endswith('::",')]
    check(
        not unanchored,
        "these module filters are prefixes and will capture another gate's "
        f"cases: {unanchored}",
    )
    # Without this the check passes vacuously: it matches on one literal
    # spelling, so reformatting the filters -- single quotes, a line break --
    # makes `seen` empty and `unanchored` empty with it, and a de-anchored
    # filter sails through.  A guard that cannot tell "all anchored" from
    # "found nothing to look at" is the shape this file exists to refuse.
    check(
        len(seen) >= EXPECTED_MODULE_FILTERS,
        f"expected at least {EXPECTED_MODULE_FILTERS} module filters to "
        f"inspect, found {len(seen)} -- the scan matched nothing, so its "
        "silence is not evidence",
    )


def a_harness_local_problem_still_fails_the_preflight() -> None:
    """`extra_problems` must count and fail, not merely print.

    **This is the one seam the M4-27 refactor created, and it was unpinned.**
    Moving the preflight into `guard_outcomes.py` left `fs-guard-deletion.py`'s
    own glued-case-name rule on the far side of a module boundary, passed in as
    `extra_problems`.  Deleting that loop outright leaves every other fixture in
    this file green and `--check-anchors` reporting 427/13 exactly as before,
    because no glued name exists in the tree for the real run to catch -- so the
    rule would fail open with nothing to say so.  A refactor's new seam is
    precisely where a fixture is owed.

    The selection here resolves cleanly, so the only thing that can fail the run
    is the extra problem, and the counted total must include it.
    """
    with anchor_file("let x = 1;\n") as path:
        code, output = run_preflight(
            [("suite1", "a case whose anchor is fine", [(path, "let x = 1;", "")])],
            ["glued case name: line 12: 'refuses' + 'anambiguous'..."],
        )
    check(code == 1, f"a harness-local problem must fail the run, got exit {code}")
    check("glued case name" in output, f"the problem must be named, got {output!r}")
    check(
        "1 anchor problem(s)" in output,
        f"the harness-local problem must be counted, not merely printed, got "
        f"{output!r}",
    )
    check(
        "every anchor resolves" not in output,
        f"a run with a harness-local problem must not claim a clean sweep, got "
        f"{output!r}",
    )


def the_flag_short_circuits_before_anything_is_edited(script: Path) -> None:
    """`--check-anchors` must return before the harness touches the tree.

    **Found by red-testing this file, and anticipated by nobody (M4-34).**
    Deleting only the two dispatch lines from a harness -- leaving the argparse
    flag in place, which is exactly what a careless edit does -- makes
    `--check-anchors` a *silently ignored* flag: argparse still accepts it, so
    the harness falls straight through into `require_clean_tree` and the
    deletion loop and runs the entire multi-hour destructive suite.  It does
    not fail; it does the most expensive and most dangerous possible thing.

    That is not hypothetical: it happened here, from inside this test file,
    which then had to be killed mid-case and left a defeated guard in
    `crates/tunnel-cua/src/outcome.rs` because the kill pre-empted `restore()`
    -- the M4-32 shape, reached through a unit test rather than a concurrent
    edit.

    So the dispatch is pinned in the source, and pinned *before* the subprocess
    runs: if this check fails, no subprocess is started and nothing is edited.
    Order is the rule, not merely presence -- a dispatch placed after
    `require_clean_tree` would still edit the tree first.
    """
    text = script.read_text()
    dispatch = "if arguments.check_anchors:"
    check(
        dispatch in text,
        f"{script.name} no longer dispatches on --check-anchors, so the flag "
        "would be silently ignored and the full destructive suite would run",
    )
    check(
        "return check_anchors(selected)" in text,
        f"{script.name} accepts --check-anchors but does not return the "
        "preflight's exit code",
    )
    guard = "require_clean_tree(suites)"
    check(
        guard in text and text.index(dispatch) < text.index(guard),
        f"{script.name} dispatches --check-anchors only after it has begun "
        "editing the tree; the flag must short-circuit first",
    )


def every_guard_anchor_resolves_to_exactly_one_occurrence() -> None:
    """Hold `fs-guard-deletion.py --check-anchors` as a standing rule.

    The deletion loop already refuses an anchor that matches zero times or
    more than once -- but only for the cases a given invocation selects, and
    only after paying a `cargo test` for each.  So the same defect the
    ambiguity refusal closes for a *selected* case stayed open for an
    unselected one: a guard whose anchor had rotted in a suite nobody happened
    to run was invisible until someone ran it, and the full script does not
    fit in one session.  `--check-anchors` resolves every anchor in every
    suite against the tree and builds nothing, so it can run here every time.

    It also refuses a case name that two adjacent string literals joined
    without a space -- display-only, but it makes the suite's output stop
    matching the rule the gate prints when it fails, and a name is not a
    dictionary word, so nothing downstream of the join can detect it.

    **All four harnesses, not just `fs-` (M4-27).**  The preflight was landed
    in `fs-guard-deletion.py` alone, and holding only that one here would be a
    standing rule that covers a quarter of what it appears to: `m5-`, `acp-`
    and `m3-` could lose the flag entirely and this file would stay green.
    """
    directory = Path(__file__).resolve().parent
    for script_name, floor in sorted(EXPECTED_GUARD_ANCHORS.items()):
        script = directory / script_name
        check(script.exists(), f"{script_name} is missing")
        the_flag_short_circuits_before_anything_is_edited(script)
        result = subprocess.run(
            [sys.executable, str(script), "--check-anchors"],
            capture_output=True,
            text=True,
            check=False,
            # **This bounds duration, NOT damage, and must not be read as a
            # second line of defence.**  `subprocess.run(timeout=)` kills the
            # child, and killing a deletion harness mid-case pre-empts its
            # `restore()` -- which is exactly the damage M4-34 describes, not a
            # defence against it.  If a run ever reaches this timeout the tree
            # has already been edited and may be left with a guard defeated in
            # it.  The static check above is the only thing preventing that;
            # this merely stops a unit test hanging for hours afterwards.
            timeout=300,
        )
        check(
            result.returncode == 0,
            f"{script_name} --check-anchors failed:\n"
            f"{result.stdout}{result.stderr}",
        )
        # The same vacuity trap as the filter scan above: a `--check-anchors`
        # that silently selected nothing would exit 0 and prove nothing, so
        # require the run to say how much it actually looked at.
        check(
            "checked " in result.stdout and " anchors across " in result.stdout,
            f"{script_name} --check-anchors did not report how many anchors it "
            f"checked, so its exit code is not evidence: {result.stdout!r}",
        )
        checked = int(result.stdout.split("checked ", 1)[1].split(" anchors", 1)[0])
        check(
            checked >= floor,
            f"{script_name}: expected at least {floor} anchors to be checked, "
            f"found {checked} -- the scan selected almost nothing, so its "
            "silence is not evidence",
        )


# --------------------------------------------------------------------------
# Interrupt-safe mutation (task row M5-C07)
# --------------------------------------------------------------------------

ORIGINAL = "fn guard() -> bool {\n    real_check()\n}\n"
MUTATED = "fn guard() -> bool {\n    true\n}\n"


@contextlib.contextmanager
def scratch_repo():
    """A throwaway `repo` holding one product file, for the cases below.

    Deliberately **not** this repository: the whole subject here is a harness
    that mutates a tree, and M4-32's instance was a guard suite editing a tree
    somebody else was working in.  A test of that must not do it.
    """
    with tempfile.TemporaryDirectory() as directory:
        repo = Path(directory)
        product = repo / "guard.rs"
        product.write_text(ORIGINAL)
        yield repo, product


def an_interrupted_case_restores_the_tree_on_the_way_out() -> None:
    """A `KeyboardInterrupt` mid-case must still restore (M5-C07).

    This is the row's own incident, twice over: a run killed between the edit
    and the restore left the mutation in the working tree, and the next
    `git add -A` committed a defeated guard under a `docs:` subject.

    **The positive control is in the same case and is the load-bearing half.**
    "The file matches the original afterwards" is satisfied just as well by a
    mutation that never happened, so this asserts *inside* the `with` block
    that the file really was mutated and the journal really existed.  Without
    that, a broken `apply` would make this case pass.
    """
    with scratch_repo() as (repo, product):
        journal = mutation_journal(repo)
        try:
            with AppliedCase("test", repo, "suite", "case") as applied:
                problem = applied.apply(product, "real_check()", "true")
                check(problem is None, f"the edit should apply, got {problem!r}")
                # Positive control: the mutation is real and journalled.
                check(
                    product.read_text() == MUTATED,
                    "the guard was NOT actually mutated, so a clean tree "
                    "afterwards would prove nothing",
                )
                check(journal.exists(), "a journal must exist while a case is applied")
                raise KeyboardInterrupt("as a long chain being interrupted does")
        except KeyboardInterrupt:
            pass
        check(
            product.read_text() == ORIGINAL,
            "an interrupted case left the mutation resident in the product",
        )
        check(
            not journal.exists(),
            "the journal must be gone once the restore has completed",
        )


def a_sigterm_mid_case_restores_the_tree() -> None:
    """`SIGTERM` must reach the restore, not bypass it (M5-C07).

    `SIGINT` already raises, but the default `SIGTERM` disposition terminates
    without unwinding, so every `finally` in the program would be skipped --
    which is how M4-34's `subprocess.run(timeout=)` left a mutation in
    `crates/tunnel-cua/src/outcome.rs`.  This runs a real child, signals it for
    real, and reads the tree afterwards, because the `signal.signal` call that
    makes it work is exactly the kind of thing a source-text check cannot
    verify.
    """
    with scratch_repo() as (repo, product):
        child_source = repo / "child.py"
        child_source.write_text(
            "import sys, time\n"
            f"sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})\n"
            "from guard_outcomes import AppliedCase, install_interrupt_restore\n"
            "from pathlib import Path\n"
            "install_interrupt_restore()\n"
            f"repo = Path({str(repo)!r})\n"
            "try:\n"
            "    with AppliedCase('test', repo, 'suite', 'case') as applied:\n"
            "        applied.apply(repo / 'guard.rs', 'real_check()', 'true')\n"
            "        print('APPLIED', flush=True)\n"
            "        time.sleep(30)\n"
            "except BaseException:\n"
            "    pass\n"
        )
        child = subprocess.Popen(
            [sys.executable, str(child_source)],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            # Wait for the mutation to be on disk before signalling, so this
            # cannot accidentally signal a process that had not edited
            # anything -- which would make the case pass vacuously.
            assert child.stdout is not None
            check(
                child.stdout.readline().strip() == "APPLIED",
                "the child did not report applying its edit",
            )
            check(
                product.read_text() == MUTATED,
                "the child's mutation is not on disk, so signalling it would "
                "prove nothing",
            )
            child.terminate()
            child.wait(timeout=30)
        finally:
            if child.poll() is None:  # pragma: no cover - defensive
                child.kill()
                child.wait(timeout=10)
        check(
            product.read_text() == ORIGINAL,
            "a SIGTERM mid-case left the mutation resident: the signal "
            "bypassed the restore",
        )
        check(
            not mutation_journal(repo).exists(),
            "a SIGTERM mid-case left the journal behind",
        )


def a_sigkilled_run_leaves_a_journal_that_names_the_case() -> None:
    """The layer for the signal that cannot be handled at all (M5-C07).

    `SIGKILL` runs nothing, so no `finally` and no handler can help -- the
    mutation *is* resident afterwards.  What must not happen is the next run
    starting on top of it, or the tree merely looking clean.  The journal is
    the evidence, and `refuse_resident_mutation` is what reads it.

    Paired with its positive control: the refusal must **not** fire when no
    journal exists, or it would be an unconditional refusal that proves
    nothing by firing.
    """
    with scratch_repo() as (repo, product):
        # No journal: the refusal must return quietly.  Without this the case
        # below cannot distinguish "refused because a journal exists" from
        # "refuses always".
        refuse_resident_mutation("test-harness", repo)

        # Now simulate the kill: apply, and never restore.
        applied = AppliedCase("m5-guard-deletion", repo, "m5c4", "a named case")
        problem = applied.apply(product, "real_check()", "true")
        check(problem is None, f"the edit should apply, got {problem!r}")
        check(product.read_text() == MUTATED, "the mutation must be resident")

        journal = mutation_journal(repo)
        check(journal.exists(), "a SIGKILL must leave the journal behind")

        try:
            refuse_resident_mutation("m5-guard-deletion", repo)
        except SystemExit as refusal:
            message = str(refusal)
        else:  # pragma: no cover - the refusal is the point
            sys.exit(
                "test_guard_outcomes: a resident mutation did NOT stop the "
                "next run, which is the whole defect of M5-C07"
            )
        for expected in ("m5c4", "a named case", "guard.rs", "M5-C07"):
            check(
                expected in message,
                f"the refusal must name {expected!r} rather than only saying "
                f"the tree is dirty; got: {message}",
            )

        # And the recorded original is recoverable byte for byte.
        check(recover_mutations(repo) == 0, "recovery should succeed")
        check(
            product.read_text() == ORIGINAL,
            "recovery must restore the exact original bytes",
        )
        check(not journal.exists(), "recovery must remove the journal")


def every_harness_mutates_through_the_interrupt_safe_context() -> None:
    """All four harnesses, or the fix covers a quarter of what it appears to.

    M5-C07 names the same pattern in `acp-`, `fs-`, `m3-` and `m5-`, so this
    holds every one of them to it.

    **This is a source-text check, which M4-36 records as the weakest kind of
    guard**: it sees spelling, not reachability, and it cannot see a harness
    that imports `AppliedCase` and then mutates around it.  It is here for the
    thing the behavioural cases above cannot cover -- a *fifth* harness, or a
    regression in one of the three this chunk did not exercise end to end --
    and not as the primary defence.  The bare `write_text`/`git checkout`
    refusals below are what make it more than a presence check: they fail if
    the old path comes back alongside the new one.
    """
    directory = Path(__file__).resolve().parent
    for script_name in sorted(EXPECTED_GUARD_ANCHORS):
        source = (directory / script_name).read_text()
        for required in (
            "from guard_outcomes import AppliedCase",
            "install_interrupt_restore()",
            "refuse_resident_mutation(",
            "with AppliedCase(",
        ):
            check(
                required in source,
                f"{script_name} does not use {required!r}: an interrupted run "
                "can leave a guard deleted from the product (M5-C07)",
            )
        # The two spellings whose return would reinstate the defect.
        check(
            "path.write_text(text.replace(" not in source,
            f"{script_name} mutates a file outside AppliedCase, so an "
            "interrupt can leave that edit resident (M5-C07)",
        )
        check(
            '["git", "checkout", "--"]' not in source,
            f"{script_name} restores with `git checkout --`, which discards "
            "every other uncommitted change under the crate (M4-32)",
        )


if __name__ == "__main__":
    sys.exit(main())
