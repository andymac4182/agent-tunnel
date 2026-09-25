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
    WITNESS_DEBT_FILE,
    AppliedCase,
    WitnessDebt,
    NoWriteCapability,
    WriteAttempted,
    check_anchors,
    classify_outcome,
    is_usable,
    mutation_journal,
    read_only_entry,
    recover_mutations,
    refuse_resident_mutation,
    require_declared_witnesses,
    require_git_index,
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
    every_mutation_harness_is_registered()
    every_guard_anchor_resolves_to_exactly_one_occurrence()

    # M5-C07, behavioural first and source-text last.
    an_interrupted_case_restores_the_tree_on_the_way_out()
    a_sigterm_mid_case_restores_the_tree()
    a_sigkilled_run_leaves_a_journal_that_names_the_case()
    every_harness_mutates_through_the_interrupt_safe_context()

    # M4-36: read-only mode is a capability, not two lines' position.
    the_read_only_entry_holds_no_write_capability()
    a_deletion_loop_reachable_from_read_only_mode_is_refused()
    a_lost_check_anchors_dispatch_cannot_delete_anything()
    an_unbalanced_exit_cannot_disable_the_write_barrier()

    # M4-23 / M4-24: a red must be the case's own red.
    a_red_from_a_foreign_test_is_not_credited()
    an_undeclared_case_is_refused_before_anything_is_edited()
    a_case_owed_a_witness_is_still_counted_and_never_silent()
    the_witness_debt_ledger_matches_the_tree_and_is_pinned()

    # M4-26: a lost git index must stop the run, not go unreported.
    a_checkout_without_a_git_index_is_refused()

    # M4-30 / M4-32: the tree or history changing under a case is refused.
    an_untouched_case_in_a_git_repo_restores_without_refusal()
    a_foreign_edit_during_a_case_is_not_overwritten()
    a_commit_during_a_case_is_refused()
    a_staged_mutation_is_refused()
    a_partial_add_of_a_multi_edit_is_refused()
    a_flagged_foreign_edit_survives_the_next_run_and_recovery()
    a_crashed_case_with_a_foreign_edit_is_not_recovered()
    a_crashed_case_whose_head_moved_is_not_recovered()
    a_crashed_case_with_a_staged_mutation_is_not_recovered()

    # The harness code between the shared module and the source-text
    # checks, which nothing here used to execute.
    every_harness_main_runs_to_its_summary()

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
    check("STALLED: guard text not found" in output and "AMBIGUOUS" not in output,
          f"a stalled anchor must be named STALLED and only STALLED, got {output!r}")
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
    check("AMBIGUOUS: 2 occurrences" in output and "STALLED" not in output,
          f"an ambiguous anchor must be named with its count, and not as "
          f"STALLED, got {output!r}")


def the_preflight_refuses_an_empty_selection() -> None:
    """A selection of nothing must refuse, not report a clean sweep (M4-27).

    `--check-anchors --case no-such-case` used to print "checked 0 anchors ...
    every anchor resolves" and exit 0.  A check that passes because it measured
    nothing proves less than it claims, which is the one defect this whole file
    exists to refuse -- so it is pinned here rather than trusted to stay fixed.
    """
    code, output = run_preflight([])
    check(code == 1, f"an empty selection must refuse, got exit {code}")
    # **The empty-selection refusal's own text (M4-43).**  "not evidence"
    # alone is generic enough for any refusal to say; this names the branch.
    check("selected no cases" in output and "anchor problem(s)" not in output,
          f"the refusal must be the empty-selection one and say why it refused, "
          f"got {output!r}")
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
    # Was 148. **149** after M5-C16 added the `m8c7` case that defeats
    # `availability()`. Re-measured, not incremented: 150 first, which fails
    # naming acp ("found 149"), then 149.
    "acp-guard-deletion.py": 149,
    # Measured at the m5c8 tip: 100 anchors across 7 suites. The floor stood
    # at 82 and had gone stale across three chunks, so it no longer noticed a
    # suite dropping out.
    #
    # **110** on `m5-code`, measured: the `m5c9` suite (10 cases, one anchor
    # each) took `--check-anchors` from 100 to 110 across 8 suites, and a floor
    # left at 100 would have passed with the whole suite deleted (Opus review
    # of `fc920f8`). Re-measured, not incremented: 111 first, which fails
    # naming m5 ("found 110"), then 110.
    "m5-guard-deletion.py": 110,
    # Was 5. Measured at the m6c4 tip: 12 anchors across 3 suites -- the seven
    # M6-C08 resolution rules and the `m6c08-doctor` suite for the surface
    # that reports them. (11 before the Fable review, which added the
    # access-versus-mode-bit rule as a case of its own.)
    #
    # Was 12. Re-measured on `m3c1-suite-stability` after merging PR #81:
    # **15 anchors across 4 suites**, the three added being the
    # `m3c25-resign-pin-wait` cases (M3-25 / M7-C89). Taken from what
    # `--check-anchors` reports, not by adding three, and shown live by
    # setting it to 16 first and watching this file fail.
    #
    # Then **17**, after the Fable review of `3cf2c1e` added two cases that
    # witness the pin wait's *application* (its call site and its bound), not
    # only its decision. Re-measured the same way: 18 first, which fails
    # naming m3, then 17, which passes.
    #
    # Then **18**, for the `m7c89-readiness-pins` suite's one case (M7-C89:
    # readiness read against the transport pin set). Re-measured the same
    # way: 19 first, which fails naming m3 ("found 18"), then 18.
    #
    # Then **24**, for the `m7c92-unary-echo` suite's six cases (M7-C92: the
    # finite echo's owner STREAM_FORGET; M7-C93: its rotation fence).
    # Re-measured the same way: 25 first, which fails naming m3, then 24.
    #
    # Then **25**, for review F1's late-ACK-below-the-watermark case.
    # Re-measured the same way: 26 first, which fails naming m3, then 25.
    #
    # Then **26**, for the `m7c97-retiring-admission` suite's one case.
    # Re-measured the same way: 27 first, which fails naming m3, then 26.
    #
    # Then **27**, for review S2's carrier-loss case in the same suite.
    # Re-measured the same way: 28 first, which fails naming m3, then 27.
    #
    # Then **34**, measured by the M5-C16 worker: `--check-anchors` reported
    # 34 across 11 suites with the new `m3c09` availability case, so the floor
    # had been lagging six behind the truth before that case was added (not
    # attributed here to the suites that landed without raising it). Re-measured the same way:
    # 35 first, which fails naming m3 ("found 34"), then 34.
    #
    # Then **60**, measured on branch `m7-connector`: `--check-anchors`
    # reported 51 across 12 suites after merging `origin/main` (the floor had
    # lagged 17 behind), and 60 across 14 once the `m7-connector-relay` and
    # `m7-connector-client` suites added their nine cases (M7-C84, M7-C94,
    # M7-C95, M7-C98, M7-C109, M7-C110).  Re-measured the same way: 61 first,
    # which fails naming m3, then 60.
    "m3-guard-deletion.py": 60,
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
    #
    # m0 raised 13 -> **44** after merging #140, re-measured rather than
    # carried: `--check-anchors` reports 44 across 3 suites, and 45 fails
    # naming m0. The floor had gone slack by 31 without anyone noticing.
    "m0-guard-exit-codes.py": 44,
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
        "return read_only_entry(" in text,
        f"{script.name} accepts --check-anchors but does not dispatch into "
        "the shared read-only entry point, so read-only mode would be a "
        "branch in main() rather than a path without write capability "
        "(M4-36)",
    )
    guard = "require_clean_tree(suites)"
    check(
        guard in text and text.index(dispatch) < text.index(guard),
        f"{script.name} dispatches --check-anchors only after it has begun "
        "editing the tree; the flag must short-circuit first",
    )


#: The two files that use `AppliedCase` without being mutation harnesses: the
#: module that defines it, and this file, which tests it.  Named rather than
#: pattern-matched, and their continued existence is asserted below, so a
#: rename cannot silently widen the harness set to include them -- or, worse,
#: narrow it by making the discovery below match nothing at all.
NOT_HARNESSES = {"guard_outcomes.py", "test_guard_outcomes.py"}


def every_mutation_harness_is_registered() -> None:
    """Discover mutation harnesses, and refuse an unregistered one.

    **The class behind an instance this file already had.**  Every rule below
    -- the `--check-anchors` short circuit, `AppliedCase`, the interrupt
    restore, the resident-mutation refusal, the banned rewrite spellings, the
    anchor floor -- is applied only to the harnesses named in
    `EXPECTED_GUARD_ANCHORS`.  Nothing checked that the names were *all* of
    them.  `m0-guard-exit-codes.py` was created and went unregistered, so for
    the hours it existed this file held none of its rules over it and said
    nothing; `m6-guard-client-bundle-sentinel.py` would have been the second.
    Both were caught by a person noticing, which is not a mechanism.

    **Discovery is behavioural, not by filename.**  A glob such as
    `*-guard-*.py` happens to match the six harnesses today and is evaded by
    the next sensible name -- `m7-evidence-guard.py` already misses it, and a
    harness called `m9_guard.py` would too.  What actually makes a file a
    mutation harness is that it edits product bodies through `AppliedCase`,
    so that is what is matched.

    **It refuses; it does not auto-register.**  Adding a discovered harness to
    the floor dictionary with a default of 0 would satisfy this check while
    reinstating the vacuity it exists to prevent: a floor of 0 passes over a
    harness that selected nothing.  A new harness has to be measured and
    written down by the person adding it, and until then this file is red.
    """
    directory = Path(__file__).resolve().parent
    for name in sorted(NOT_HARNESSES):
        check(
            (directory / name).exists(),
            f"{name} is named as a non-harness but does not exist; the "
            "discovery below would silently change shape",
        )
    discovered = {
        path.name
        for path in sorted(directory.glob("*.py"))
        if path.name not in NOT_HARNESSES
        and "from guard_outcomes import AppliedCase" in path.read_text()
    }
    check(
        bool(discovered),
        "no mutation harness was discovered at all; the detection above has "
        "stopped matching and every rule in this file is now held over nothing",
    )
    unregistered = sorted(discovered - set(EXPECTED_GUARD_ANCHORS))
    check(
        not unregistered,
        "mutation harness(es) not in EXPECTED_GUARD_ANCHORS, so none of this "
        f"file's rules are held over them: {unregistered}. Run each with "
        "--check-anchors and record the measured figure; do not default it to "
        "0, which passes over a harness that selected nothing.",
    )
    stale = sorted(set(EXPECTED_GUARD_ANCHORS) - discovered)
    check(
        not stale,
        "EXPECTED_GUARD_ANCHORS names harness(es) that no longer use "
        f"AppliedCase, or no longer exist: {stale}",
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


# --------------------------------------------------------------------------
# M4-36: read-only is a capability, not a spelling
# --------------------------------------------------------------------------


def the_read_only_entry_holds_no_write_capability() -> None:
    """Every primitive a guard run mutates with must raise inside the entry.

    **This is the check the source-text one could not express.**  M4-36 built
    the bypass and measured it: nesting the `--check-anchors` dispatch under
    the preceding `if arguments.list:` block leaves it present, correctly
    ordered and unreachable, and `m3-guard-deletion.py --check-anchors` then
    ran the whole destructive suite to completion in 76.8 s and exited 0 while
    the static check reported PASS.  Ordering and spelling were both correct;
    reachability was not, and nothing could see it.

    So this asserts the substance instead: inside the read-only scope, a write
    is not possible.

    **Defeating it.**  Delete any one line from `NoWriteCapability.__enter__`
    and the assertion for that primitive alone fails, with the write having
    succeeded and the temporary file left holding "mutated". Each primitive is
    checked separately, so a barrier that covered `Path.write_text` but not
    `os.replace` fails on the `os.replace` case and cannot be credited by its
    sibling -- which is the M4-23 defect, and this control must not reproduce
    it while proving it.
    """
    import os

    directory = Path(tempfile.mkdtemp())
    product = directory / "product.rs"

    # **Each attempt names the primitive whose refusal must have fired.**
    # `Path.write_text` calls `Path.open(mode="w")` internally, so an
    # assertion that merely required *something* to raise would be satisfied
    # by the `Path.open` barrier when the `Path.write_text` one had been
    # removed -- a control reddening for its sibling's reason, which is the
    # M4-23 defect reproduced inside the fixture built to prove it. Found by
    # defeating this check: deleting the `Path.write_text` line from
    # `NoWriteCapability.__enter__` left the whole file passing. So the
    # refusal's own message is matched.
    attempts = {
        "Path.write_text": (lambda: product.write_text("mutated"), "Path.write_text"),
        "Path.open(w)": (lambda: product.open("w"), "with mode 'w'"),
        "Path.unlink": (lambda: product.unlink(), "Path.unlink"),
        "os.replace": (lambda: os.replace(product, directory / "moved.rs"), "os.replace"),
        "subprocess.run": (
            lambda: subprocess.run(["git", "checkout", "--", "."]),
            "subprocess.run",
        ),
    }
    for name, (attempt, expected_reason) in attempts.items():
        product.write_text("ORIGINAL")
        reason = ""
        try:
            with NoWriteCapability():
                attempt()
        except WriteAttempted as refusal:
            reason = str(refusal)
        check(
            reason != "",
            f"a read-only guard-harness entry point was able to call {name}: "
            "read-only mode must be a path with no write capability, or a "
            "bypassed dispatch runs the destructive suite and exits 0 (M4-36)",
        )
        check(
            expected_reason in reason,
            f"{name} was refused, but not by its own barrier: expected the "
            f"refusal to name {expected_reason!r}, got {reason!r}. A control "
            "that reddens for a sibling's reason proves nothing about the "
            "rule it names (M4-23).",
        )
        check(
            product.exists() and product.read_text() == "ORIGINAL",
            f"{name} changed the tree from inside a read-only scope",
        )
        # The scope must also *end*: a barrier that leaked would break every
        # later test in this file rather than failing here.
        product.write_text("restored")
        check(product.read_text() == "restored", f"{name} left the barrier installed")


def a_deletion_loop_reachable_from_read_only_mode_is_refused() -> None:
    """The bypass M4-36 built, reduced to its load-bearing step.

    The bypass's harm is not that a dispatch was nested -- it is that the
    *deletion loop* then ran.  So this makes exactly that reachable **from
    `read_only_entry` itself**, by giving the entry an anchor resolver that
    applies a real case through the real `AppliedCase`, which is what a
    bypassed dispatch does on its first case.

    It must raise, and the product file must be untouched.  Before this fix it
    would have mutated the file and carried on to the next case -- for 427
    anchors on `fs-guard-deletion`, editing the tree throughout.

    **Defeating it.**  Drop the `NoWriteCapability` scope from
    `read_only_entry` and the case is applied: the file reads empty and the
    assertion below fails naming the mutation, rather than passing because
    something else raised.
    """
    import guard_outcomes

    directory = Path(tempfile.mkdtemp())
    product = directory / "provider.rs"
    ORIGINAL = "if queued.flushed { return; }\n"
    product.write_text(ORIGINAL)

    def deletion_loop(_harness, _selected, _extra=()):
        with AppliedCase("test-harness", directory, "gate4", "a case") as applied:
            applied.apply_all([(product, "if queued.flushed { return; }", "")])
        return 0

    saved = guard_outcomes.check_anchors
    guard_outcomes.check_anchors = deletion_loop
    raised = None
    try:
        read_only_entry("test-harness", [("gate4", "a case", [])])
    except WriteAttempted as refusal:
        raised = str(refusal)
    finally:
        guard_outcomes.check_anchors = saved

    check(
        raised is not None,
        "the deletion loop ran from inside the read-only entry point without "
        "raising: a successful destructive run then looks exactly like a "
        "successful read-only one (M4-36)",
    )
    # **Which barrier fired is part of the claim (M4-43).**  This used to
    # accept any `WriteAttempted`, so a refusal from `subprocess.run` or
    # `os.replace` would have satisfied an assertion about the deletion loop's
    # file write. `AppliedCase.apply` writes with `Path.write_text`, so that
    # is the refusal this must see.
    check(
        "Path.write_text" in raised,
        "the deletion loop was refused from inside the read-only entry, but "
        f"not by the barrier on the write it makes; got {raised!r}",
    )
    check(
        product.read_text() == ORIGINAL,
        "a case was applied to the product from inside read-only mode",
    )


# --------------------------------------------------------------------------
# M4-23 / M4-24: a red must be the case's own red
# --------------------------------------------------------------------------


def a_red_from_a_foreign_test_is_not_credited() -> None:
    """The defect itself, as a classification.

    M4-23's instance: `[gate4] release a descriptor only for its own
    generation` was credited a red naming three `m7_startup.rs` tests about
    membership state and a checkpoint, which have nothing to do with a
    descriptor cache keyed by fid generation. Clean-tree controls passed 6 of
    6, and the case's own deletion applied by hand passed 6 of 6.

    **Defeating it.**  Hand `classify_outcome` the witness the case declares
    instead of the foreign name and it returns plain `RED`, which is usable --
    so this control distinguishes the two, rather than reddening on anything.
    """
    foreign = classify_outcome(
        "RED",
        ["serve_rejects_corrupt_membership_state_through_the_binary"],
        documented_green=False,
        expect_build_failure=False,
        expected_red=frozenset({"a_stale_generation_is_refused"}),
        owed_witness=False,
    )
    check(
        not is_usable(foreign),
        f"a red naming only a foreign test was credited as evidence: {foreign!r}",
    )
    check(
        "wrong witness" in foreign and "a_stale_generation_is_refused" in foreign,
        f"the refusal must name the witness that did not redden, got {foreign!r}",
    )

    own = classify_outcome(
        "RED",
        ["a_stale_generation_is_refused"],
        documented_green=False,
        expect_build_failure=False,
        expected_red=frozenset({"a_stale_generation_is_refused"}),
        owed_witness=False,
    )
    check(
        own == "RED" and is_usable(own),
        f"a red naming the case's own witness must be credited, got {own!r}",
    )

    # A witness among several unrelated failures is still the case's own red:
    # the rule is that the declared test reddened, not that nothing else did.
    mixed = classify_outcome(
        "RED",
        ["a_flake_elsewhere", "a_stale_generation_is_refused"],
        documented_green=False,
        expect_build_failure=False,
        expected_red=frozenset({"a_stale_generation_is_refused"}),
        owed_witness=False,
    )
    check(mixed == "RED", f"a witness alongside a flake must still count, got {mixed!r}")


def an_undeclared_case_is_refused_before_anything_is_edited() -> None:
    """The refusal that makes the mechanism more than opt-in.

    **Defeating it.**  Give the case a witness, or name it in the debt ledger,
    and the refusal does not fire -- so this fails for the absence of a
    declaration specifically, and not because any call to it exits.
    """
    empty = WitnessDebt(())

    def refuse(cases, debt=empty) -> str:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                require_declared_witnesses("test-harness", cases, debt)
        except SystemExit as stop:
            return str(stop)
        return ""

    # **Each refusal is matched by its own suffix, and its siblings' are
    # required absent (M4-43).**  The three share one `sys.exit` and one
    # preamble, so a substring of the preamble -- or of the case name --
    # would be satisfied by whichever sibling fired.
    suffixes = {
        "missing": "[gate4] a case (names no witness)",
        "contradictory": "[gate4] a case (compiler refusal may not name a witness)",
        "stale": "[gate4] a case (declares a witness but is still in the debt ledger)",
    }

    def only(text: str, kind: str) -> bool:
        return suffixes[kind] in text and all(
            suffixes[other] not in text for other in suffixes if other != kind
        )

    undeclared = refuse([("gate4", "a case", False, frozenset())])
    check(
        only(undeclared, "missing"),
        f"an undeclared value case must be refused by name, got {undeclared!r}",
    )

    declared = refuse([("gate4", "a case", False, frozenset({"its_own_test"}))])
    check(declared == "", f"a declared case must not be refused, got {declared!r}")

    owed = refuse(
        [("gate4", "a case", False, frozenset())],
        WitnessDebt([("gate4", "a case")]),
    )
    check(owed == "", f"a case in the debt ledger must not be refused, got {owed!r}")

    # A compiler refusal names no test, and must not be made to.
    contradictory = refuse([("gate4", "a case", True, frozenset({"a_test"}))])
    check(
        only(contradictory, "contradictory"),
        f"a compiler-refusal case with a witness must be refused, got {contradictory!r}",
    )

    # A case cannot both declare a witness and still be owed one, or the
    # ledger would silently outlive the fix it tracks.
    stale = refuse(
        [("gate4", "a case", False, frozenset({"its_own_test"}))],
        WitnessDebt([("gate4", "a case")]),
    )
    check(
        only(stale, "stale"),
        f"a case in both the table and the ledger must be refused, got {stale!r}",
    )


def a_case_owed_a_witness_is_still_counted_and_never_silent() -> None:
    """The ledger is a debt, not an exemption.

    An owed case keeps the old unattributed classification -- it has to, or
    every harness would refuse to run -- so the protection against the ledger
    quietly becoming permanent is that its size is pinned below and can only
    shrink.
    """
    owed = classify_outcome(
        "RED",
        ["something_unrelated"],
        documented_green=False,
        expect_build_failure=False,
        expected_red=frozenset(),
        owed_witness=True,
    )
    check(owed == "RED", f"an owed case keeps its classification, got {owed!r}")


def the_witness_debt_ledger_matches_the_tree_and_is_pinned() -> None:
    """The M4-24 figure, asserted rather than printed.

    The ledger must name exactly the value cases that declare no witness --
    no more, so a case cannot be exempted by being added to it, and no fewer,
    so a harness cannot be made to refuse to run by a stale entry.

    `PINNED_WITNESS_DEBT` is the measured reach of M4-23: 691 of the 745 guard
    cases across the five harnesses were credited for a failure named after no
    test in the repository. It may go **down** as cases are given measured
    witnesses, and a rise fails this check.

    **What this does not check, stated because an earlier version of M4-23's
    row claimed it did (found on review).**  "May only shrink" holds. "A
    shrink means a witness was earned" does **not**. A case leaves the owed
    set by gaining a `WITNESSES` entry, but equally by being added to
    `EXPECT_GREEN`, by being given `expect_build_failure`, or by being
    deleted -- and this check cannot tell those apart. Measured: appending one
    name to `fs-guard-deletion`'s `EXPECT_GREEN` struck **five** cases at once,
    because that name recurs in five suites, and the only response was
    `the witness debt fell from 691 to 686`.

    The real protection is narrower and worth stating exactly. A **guessed**
    `WITNESSES` entry fails closed at the next full run: the named test does
    not redden, the case is classified `RED (wrong witness)`, and the run
    exits non-zero. Reclassifying to `EXPECT_GREEN` fails closed only if the
    guard is genuinely load-bearing, in which case the run reports
    `EXPECTED A DOCUMENTED GREEN, GOT: RED`. So a wrong witness is caught by
    running; a wrong exemption is caught only sometimes. The departure route
    is therefore reported below rather than assumed.
    """
    import importlib.util
    import json

    #: Measured 2026-09-23 by driving each harness's own shipped classifier:
    #: 691.  Lowered by M4-42 only as whole suites earned measured witnesses
    #: (every drop is a `WITNESSES` entry, not a reclassification):
    #: m5-guard-deletion's 100 -> 591; fs-guard-deletion's gate2, gate3,
    #: gate4, gate5 and gate9-epoch-change (160) -> 431; acp-guard-deletion's
    #: seven suites less three unwitnessable cases (141) -> 290;
    #: fs-guard-deletion's gate7, gate8, gate10 and gate11 (127) -> 163;
    #: its gate6-adapters, gate6-e2e, gate12, gate13 and gate14 (160) -> 3.
    #: The 3 left are acp cases that no run could witness (M4-42).
    #: `m5-code` (#140) independently struck `[m5c7] the scroll deltas may
    #: be dropped for constants` (renamed from "...for the cursor point"
    #: after M5-C13) with a measured witness; M4-42 had already witnessed
    #: it under the old name, so the merged figure stays 3.
    PINNED_WITNESS_DEBT = 3

    directory = Path(__file__).resolve().parent
    ledger = json.loads(WITNESS_DEBT_FILE.read_text())

    def describe(case) -> tuple[str, bool, bool, frozenset[str]]:
        """`(name, documented green, compiler refusal, declared witnesses)`.

        The harnesses carry three case shapes -- a 2-tuple, a 3-tuple with an
        `expect_build_failure` flag, and two different dataclasses -- and an
        unrecognised one must fail here rather than be silently scored as
        owing nothing, which would exempt a whole harness by accident.
        """
        if isinstance(case, tuple):
            return (case[0], False, bool(len(case) > 2 and case[2]), frozenset())
        name = getattr(case, "name", None)
        check(name is not None, f"unrecognised case shape: {case!r}")
        witness = getattr(case, "expected_red", None)
        if witness is None:
            # The `m6` harness spells a single witness as `expected_witness`.
            single = getattr(case, "expected_witness", None)
            witness = frozenset({single}) if single else frozenset()
        return (
            name,
            bool(getattr(case, "expect_green", False)),
            bool(getattr(case, "expect_build_failure", False)),
            frozenset(witness),
        )

    total = 0
    declared_witnesses = 0
    for script_name in sorted(EXPECTED_GUARD_ANCHORS):
        module_name = script_name.removesuffix(".py")
        spec = importlib.util.spec_from_file_location(
            module_name.replace("-", "_") + "_ledger", directory / script_name
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        expect_green = set(getattr(module, "EXPECT_GREEN", ()))
        declared = getattr(module, "WITNESSES", {})
        owed = set()
        for suite in module.SUITES:
            for case in suite.cases:
                name, green, build_failure, witness = describe(case)
                if name in expect_green or green or build_failure or witness:
                    continue
                if (suite.name, name) in declared:
                    continue
                owed.add((suite.name, name))
        recorded = {(suite, name) for suite, name in ledger.get(module_name, [])}
        check(
            owed == recorded,
            f"{script_name}: the witness-debt ledger does not match the tree. "
            f"Missing from the ledger: {sorted(owed - recorded)}. Stale in the "
            f"ledger: {sorted(recorded - owed)}. A case given a measured "
            "witness must be struck from the ledger in the same change.",
        )
        # The harness's own `DEBT` is what its run-summary figure is computed
        # from, so pin that object rather than only the file it came from: a
        # harness that loaded the wrong entry would print a smaller number of
        # unattributed reds than it actually had.
        harness_debt = getattr(module, "DEBT", None)
        if harness_debt is not None:
            check(
                len(harness_debt) == len(recorded),
                f"{script_name}: the harness loaded {len(harness_debt)} debt "
                f"entries but the ledger records {len(recorded)}, so the "
                "'unattributed red(s)' figure it prints understates the "
                "cases it credited without attribution (M4-23)",
            )
        total += len(recorded)
        declared_witnesses += len(declared)

    check(
        total <= PINNED_WITNESS_DEBT,
        f"the witness debt grew from {PINNED_WITNESS_DEBT} to {total}: a new "
        "guard case must declare the test its guard owns (task row M4-23). "
        "This figure may only go down.",
    )
    check(
        total == PINNED_WITNESS_DEBT,
        f"the witness debt fell from {PINNED_WITNESS_DEBT} to {total}, which "
        f"is the intended direction. {declared_witnesses} case(s) across all "
        "harnesses now carry a WITNESSES entry; if that number did not rise "
        f"by {PINNED_WITNESS_DEBT - total}, the debt fell by reclassification "
        "(EXPECT_GREEN, expect_build_failure, or deletion) rather than by a "
        "witness being earned, and this check cannot tell those apart. "
        "Lower the pin in this file and record the new figure in task row "
        "M4-23, re-derived rather than adjusted, saying which route it took.",
    )


# --------------------------------------------------------------------------
# M4-26: a harness that lost its git index must not report anything
# --------------------------------------------------------------------------


def a_checkout_without_a_git_index_is_refused() -> None:
    """The blindness M4-26 records, refused instead of run.

    With no index, `git status --porcelain -- <path>` reports tracked files as
    untracked and `git diff -- crates/` -- the check M5-C07 prescribes before
    every commit -- reports **clean**, because a file carrying a resident
    mutation reads as untracked and there is nothing to compare against. So
    the prescribed check reports clean precisely when the thing it exists to
    catch has happened.

    **Defeating it.**  The same repository with its index intact must not be
    refused, so this fails for the missing index specifically. Both halves are
    asserted, and the middle assertion reproduces the blindness itself: it
    shows `git diff` reporting clean over a file that holds a mutation, which
    is the reason a refusal is the only usable answer.
    """
    directory = Path(tempfile.mkdtemp())
    run = lambda *args: subprocess.run(  # noqa: E731
        ["git", *args], cwd=directory, capture_output=True, text=True, check=True
    )
    run("init", "-q")
    run("config", "user.email", "t@example.invalid")
    run("config", "user.name", "t")
    product = directory / "provider.rs"
    product.write_text("if queued.flushed { return; }\n")
    run("add", "-A")
    run("commit", "-qm", "initial")

    # With an index, the check passes: the refusal is about the index and not
    # about this being a temporary directory.
    require_git_index("test-harness", directory)

    # A resident mutation, of the kind an interrupted case leaves.
    product.write_text("")

    # The index goes, exactly as a kill during git's rename over it does.
    (directory / ".git" / "index").unlink()

    # The blindness, reproduced: the prescribed check reports clean over a
    # file that is holding a deleted guard right now.
    diff = subprocess.run(
        ["git", "diff", "--", "."], cwd=directory, capture_output=True, text=True
    ).stdout.strip()
    check(
        diff == "",
        "this fixture no longer reproduces M4-26: `git diff` reported a change "
        f"over a lost index, so the refusal below is guarding nothing. Got {diff!r}",
    )

    refused = ""
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            require_git_index("test-harness", directory)
    except SystemExit as stop:
        refused = str(stop)
    check(
        "no usable git index" in refused,
        "a harness with no git index must refuse rather than run blind, with "
        f"every check that would notice reporting clean (M4-26). Got {refused!r}",
    )
    check(
        "git read-tree HEAD" in refused,
        f"the refusal must say how to recover, got {refused!r}",
    )


# --------------------------------------------------------------------------
# M4-30 / M4-32: a case whose tree or history changed underneath it
# --------------------------------------------------------------------------


@contextlib.contextmanager
def scratch_git_repo():
    """A throwaway git repository holding one committed product file."""
    with tempfile.TemporaryDirectory() as directory:
        repo = Path(directory)

        def git(*args: str) -> str:
            return subprocess.run(
                ["git", *args], cwd=repo, capture_output=True, text=True, check=True
            ).stdout.strip()

        git("init", "-q")
        git("config", "user.email", "t@example.invalid")
        git("config", "user.name", "t")
        (repo / "guard.rs").write_text(ORIGINAL)
        (repo / "other.rs").write_text(ORIGINAL)
        git("add", "-A")
        git("commit", "-qm", "initial")
        yield repo, git


def _exit_refusal(body) -> str:
    """Run `body(applied)` inside an `AppliedCase`; return its exit refusal."""
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            body()
    except SystemExit as stop:
        return str(stop)
    return ""


def an_untouched_case_in_a_git_repo_restores_without_refusal() -> None:
    """The positive control for the three refusals below.

    Without it an `AppliedCase` that refused on every exit in a git work tree
    would satisfy all three, and prove nothing about what they name.  It also
    asserts HEAD was read, so the HEAD check below is known to have run rather
    than to have been skipped as "not a git repository".
    """
    with scratch_git_repo() as (repo, git):
        seen = {}

        def body() -> None:
            with AppliedCase("test-harness", repo, "suite", "case") as applied:
                check(applied.apply(repo / "guard.rs", "real_check()", "true") is None,
                      "the edit should apply")
                seen["head"] = applied.head
        refusal = _exit_refusal(body)
        check(refusal == "", f"an untouched case must restore quietly, got {refusal!r}")
        check(
            seen["head"] == git("rev-parse", "HEAD"),
            f"the case must record the HEAD it began on, got {seen['head']!r}; "
            "without it the HEAD check is skipped, not passed",
        )
        check((repo / "guard.rs").read_text() == ORIGINAL, "the case must be restored")
        check(not mutation_journal(repo).exists(), "the journal must be gone")


def a_foreign_edit_during_a_case_is_not_overwritten() -> None:
    """M4-32: an edit made mid-case is refused over, never erased.

    The restore used to write the recorded original back unconditionally, so
    an editor save or a `cargo fmt` landing on a mutated file during the
    case's test run was silently erased and the run exited 0.  Now the restore
    sees the file no longer holds the bytes the case wrote, leaves it alone,
    keeps it in the journal, restores the case's other file, and refuses.

    **Defeating it.**  Restore unconditionally again and the foreign line is
    gone and no refusal is raised: both assertions below fail.
    """
    with scratch_git_repo() as (repo, _git):
        guard, other = repo / "guard.rs", repo / "other.rs"

        def body() -> None:
            with AppliedCase("test-harness", repo, "m4c32", "a raced case") as applied:
                applied.apply_all([(guard, "real_check()", "true"),
                                   (other, "real_check()", "true")])
                # Somebody else edits one mutated file mid-case.
                guard.write_text(MUTATED + "// a foreign edit\n")
        refusal = _exit_refusal(body)
        check(
            "guard.rs was edited by something else" in refusal
            and "M4-32" in refusal
            and "HEAD moved" not in refusal,
            f"a foreign edit to a mutated file must be refused by name, got {refusal!r}",
        )
        check(
            guard.read_text() == MUTATED + "// a foreign edit\n",
            "the foreign edit was erased by the restore (M4-32)",
        )
        check(other.read_text() == ORIGINAL, "the case's other file must still be restored")
        journal = mutation_journal(repo)
        check(journal.exists() and "guard.rs" in journal.read_text()
              and "other.rs" not in journal.read_text(),
              "the journal must keep exactly the file that was not restored")


def a_commit_during_a_case_is_refused() -> None:
    """M4-30: a commit taken mid-case promotes the defeated guard.

    Afterwards `git status` is clean -- truthfully -- because HEAD itself
    holds the mutation.  The restore must refuse, and say that HEAD's blob of
    the file IS the defeated text.

    **Defeating it.**  Drop the HEAD comparison from `restore` and the run
    ends quietly with the defeated guard in history: the refusal is empty.
    """
    with scratch_git_repo() as (repo, git):
        guard = repo / "guard.rs"

        def body() -> None:
            with AppliedCase("test-harness", repo, "m4c30", "a committed case") as applied:
                applied.apply(guard, "real_check()", "true")
                git("add", "guard.rs")
                git("commit", "-qm", "docs: an unrelated commit taken mid-run")
        refusal = _exit_refusal(body)
        check(
            "HEAD moved" in refusal
            and "guard.rs IS the defeated text" in refusal
            and "M4-30" in refusal
            and "never --amend" in refusal
            and "edited by something else" not in refusal,
            f"a commit taken mid-case must be refused, naming the promoted file, got {refusal!r}",
        )
        check(
            git("show", "HEAD:guard.rs") + "\n" == MUTATED,
            "the fixture must really have promoted the mutation into HEAD",
        )


def a_staged_mutation_is_refused() -> None:
    """M4-30's precursor: a `git add` mid-case stages the defeated text.

    The working tree is restored, so `git diff` shows the restore as an
    unstaged change and the next `git commit` would promote the mutation.

    **Defeating it.**  Drop the index comparison and this returns quietly.
    """
    with scratch_git_repo() as (repo, git):
        guard = repo / "guard.rs"

        def body() -> None:
            with AppliedCase("test-harness", repo, "m4c30", "a staged case") as applied:
                applied.apply(guard, "real_check()", "true")
                git("add", "guard.rs")
        refusal = _exit_refusal(body)
        check(
            "index stages the defeated text of guard.rs" in refusal
            and "HEAD moved" not in refusal,
            f"a staged mutation must be refused by name, got {refusal!r}",
        )
        check(guard.read_text() == ORIGINAL, "the working tree must still be restored")


TWO_GUARDS = "fn a() -> bool {\n    check_a()\n}\nfn b() -> bool {\n    check_b()\n}\n"


def a_partial_add_of_a_multi_edit_is_refused() -> None:
    """M4-30: `git add -p` staging part of a mutation is a change of index.

    The index-holds-the-whole-mutation check cannot see a partial stage: the
    index then holds text that is neither the original nor the mutation.  The
    case compares the index blob at its start with the one at its end.

    **Defeating it.**  Drop the start/end comparison and this returns quietly
    with half the defeated guard staged.
    """
    with scratch_git_repo() as (repo, git):
        guard = repo / "guard.rs"
        guard.write_text(TWO_GUARDS)
        git("add", "guard.rs")
        git("commit", "-qm", "two guards")

        def body() -> None:
            with AppliedCase("test-harness", repo, "m4c30", "a two-edit case") as applied:
                applied.apply_all([(guard, "check_a()", "true"), (guard, "check_b()", "true")])
                whole = guard.read_text()
                # What `git add -p` accepting only the first hunk stages.
                guard.write_text(TWO_GUARDS.replace("check_a()", "true"))
                git("add", "guard.rs")
                guard.write_text(whole)
        refusal = _exit_refusal(body)
        check(
            "the index entry for guard.rs changed" in refusal
            and "git add -p" in refusal
            and "index stages the defeated text" not in refusal,
            f"a partially staged mutation must be refused as such, got {refusal!r}",
        )


def _recover(repo: Path) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = recover_mutations(repo)
    return code, out.getvalue()


def _startup_refusal(repo: Path) -> str:
    try:
        refuse_resident_mutation("test-harness", repo)
    except SystemExit as stop:
        return str(stop)
    return ""


def a_flagged_foreign_edit_survives_the_next_run_and_recovery() -> None:
    """M4-32, one step later: the refusal and the recovery must not undo it.

    Review reproduced it: the live restore kept the foreign-edited file in
    the journal, the next run's refusal then recommended
    `--recover-mutations` without mentioning the edit, and recovery wrote the
    original back unconditionally -- erasing the edit the restore had
    refused to touch.

    **Defeating it.**  Make `recover_mutations` write back unconditionally
    again and the foreign line is gone and the exit code is 0.
    """
    with scratch_git_repo() as (repo, _git):
        guard = repo / "guard.rs"

        def body() -> None:
            with AppliedCase("test-harness", repo, "m4c32", "a raced case") as applied:
                applied.apply(guard, "real_check()", "true")
                guard.write_text(MUTATED + "// a foreign edit\n")
        _exit_refusal(body)
        startup = _startup_refusal(repo)
        check(
            "FOREIGN EDIT is present" in startup
            and "flagged by the live restore" in startup
            and "--recover-mutations will REFUSE" in startup
            and "Recover with:" not in startup,
            f"the next run's refusal must say a foreign edit is present and "
            f"must not recommend recovery, got {startup!r}",
        )
        code, said = _recover(repo)
        check(
            code == 1 and "REFUSING" in said and "guard.rs: a FOREIGN EDIT" in said,
            f"recovery must refuse a flagged file by name, got {code} {said!r}",
        )
        check(
            guard.read_text() == MUTATED + "// a foreign edit\n",
            "recovery erased the foreign edit the live restore kept (M4-32)",
        )
        check(mutation_journal(repo).exists(), "a refused recovery must keep the journal")
        # The flag is load-bearing on its own: an editor's undo can put the
        # file back to exactly the mutated text, and a content check alone
        # would then call recovery safe over an edit nobody reconciled.
        guard.write_text(MUTATED)
        code, said = _recover(repo)
        check(
            code == 1 and "flagged by the live restore" in said,
            f"a file the live restore flagged must stay refused even when it "
            f"holds the mutation again, got {code} {said!r}",
        )


def _crash(repo: Path, edits) -> None:
    """Apply a case and never restore it: what a `SIGKILL` leaves."""
    applied = AppliedCase("m5-guard-deletion", repo, "m5c4", "a killed case")
    check(applied.apply_all(edits) is None, "the crash fixture's edit should apply")


def a_crashed_case_with_a_foreign_edit_is_not_recovered() -> None:
    """A `SIGKILL`ed case: no live restore ran, so nothing was flagged.

    Recovery must still see that the file holds neither recorded text.
    """
    with scratch_git_repo() as (repo, _git):
        guard = repo / "guard.rs"
        _crash(repo, [(guard, "real_check()", "true")])
        guard.write_text(MUTATED + "// edited after the kill\n")
        code, said = _recover(repo)
        check(
            code == 1 and "guard.rs: a FOREIGN EDIT" in said
            and "flagged by the live restore" not in said,
            f"an unflagged foreign edit must still refuse recovery, got {code} {said!r}",
        )
        check(guard.read_text() == MUTATED + "// edited after the kill\n",
              "recovery erased an edit made after the kill")


def a_crashed_case_whose_head_moved_is_not_recovered() -> None:
    """M4-30 on the crash path: a commit after the kill may carry the mutation.

    Restoring the worktree then leaves the defeated guard in HEAD with a
    clean-looking tree, so recovery refuses and says why.
    """
    with scratch_git_repo() as (repo, git):
        guard = repo / "guard.rs"
        _crash(repo, [(guard, "real_check()", "true")])
        git("add", "guard.rs")
        git("commit", "-qm", "docs: a commit taken over a resident mutation")
        code, said = _recover(repo)
        check(
            code == 1 and "HEAD moved" in said and "never --amend" in said,
            f"recovery after HEAD moved must refuse, got {code} {said!r}",
        )
        check(guard.read_text() == MUTATED, "a refused recovery must write nothing")
        check("HEAD moved" in _startup_refusal(repo),
              "the startup refusal must name the moved HEAD too")


def a_crashed_case_with_a_staged_mutation_is_not_recovered() -> None:
    """M4-30 on the crash path: the index holds the mutation after the kill."""
    with scratch_git_repo() as (repo, git):
        guard = repo / "guard.rs"
        _crash(repo, [(guard, "real_check()", "true")])
        git("add", "guard.rs")
        code, said = _recover(repo)
        check(
            code == 1 and "guard.rs: the index entry changed" in said
            and "HEAD moved" not in said,
            f"recovery over a staged mutation must refuse, got {code} {said!r}",
        )
        check(guard.read_text() == MUTATED, "a refused recovery must write nothing")


def every_harness_main_runs_to_its_summary() -> None:
    """Run each harness's `main()` end to end, with only the slow parts stubbed.

    **The gap this closes was found the hard way, in this chunk.**  Adding the
    unattributed-red summary line introduced a `NameError` in
    `acp-guard-deletion` (no `HARNESS` binding) and a wrong label in
    `fs-guard-deletion` (`HARNESS` there is a *crate path*, so the line would
    have printed a directory). Every check in this file passed anyway, because
    nothing here had ever executed a harness's `main()`: the tests covered the
    shared module and the harnesses' source text, and the code between them
    ran only during a multi-hour destructive run.

    So this runs the real `main()` of every registered harness with
    `AppliedCase`, `require_clean_tree`, `refuse_resident_mutation` and
    `run_tests` stubbed -- nothing is edited and no `cargo` is started -- and
    requires it to reach its summary. A crash anywhere on that path fails
    here, in seconds, instead of at the end of a run measured in hours.

    **Defeating it.**  Reintroduce the bare `{HARNESS}` in `acp-`'s summary
    and this fails with the `NameError`; the source-text checks above do not.
    """
    import importlib.util

    directory = Path(__file__).resolve().parent
    for script_name in sorted(EXPECTED_GUARD_ANCHORS):
        module_name = script_name.removesuffix(".py")
        spec = importlib.util.spec_from_file_location(
            module_name.replace("-", "_") + "_smoke", directory / script_name
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        class NoOpApplied:
            def __init__(self, *_a, **_k) -> None:
                pass

            def __enter__(self):
                return self

            def apply_all(self, _edits):
                return None

            def __exit__(self, *_e):
                return False

        module.AppliedCase = NoOpApplied
        module.require_clean_tree = lambda *_a, **_k: None
        module.refuse_resident_mutation = lambda *_a, **_k: None
        module.check_anchors = lambda *_a, **_k: 0
        if hasattr(module, "sweep_residue"):
            module.sweep_residue = lambda *_a, **_k: None
        # Every case's own witness, so the run reaches the summary rather than
        # stopping on a wrong-witness refusal. The witness check itself is
        # covered by `a_red_from_a_foreign_test_is_not_credited`.
        witnesses = getattr(module, "WITNESSES", {})

        def run_tests(suite, _module=module, _witnesses=witnesses):
            names = sorted({w for group in _witnesses.values() for w in group})
            for case in suite.cases:
                declared = getattr(case, "expected_red", None)
                if declared:
                    names.extend(declared)
            return ("RED", sorted(set(names)) or ["an_unattributed_failure"])

        if hasattr(module, "run_tests"):
            module.run_tests = run_tests

        argv = sys.argv
        sys.argv = [module_name]
        captured = io.StringIO()
        failure = None
        refusal = None
        try:
            with contextlib.redirect_stdout(captured):
                module.main()
        except SystemExit as stop:
            refusal = str(stop.code) if stop.code not in (None, 0) else None
        except Exception as problem:  # noqa: BLE001 - reported, not swallowed
            failure = problem
        finally:
            sys.argv = argv

        check(
            failure is None,
            f"{script_name}: main() raised {failure!r} on a path no test in "
            "this file had ever executed. A harness that crashes in its "
            "summary does so after the whole destructive run has completed.",
        )
        output = captured.getvalue()
        reached = "=== summary ===" in output or "case(s):" in output
        # **The escape clause is narrowed to one message, and review is why
        # (M4-43).**  It used to accept any refusal whose text contained the
        # harness's own name -- and every `sys.exit` in every harness prefixes
        # its name, so *any* pre-summary refusal satisfied it. With `DEBT`
        # emptied so `require_witnesses` refuses before the loop, the clause
        # returned True and every attribution check below was skipped: this
        # test exists because a crash in the summary was invisible, and a
        # harness refusing before its summary was equally invisible to it.
        # Only `m6-guard-client-bundle-sentinel` may legitimately stop early,
        # because it runs real assemblies and has no binary here, and only
        # for that reason.
        excused = (
            script_name == "m6-guard-client-bundle-sentinel.py"
            and refusal is not None
            and "--client-bin is required" in refusal
        )
        check(
            reached or excused,
            f"{script_name}: main() neither reached its summary nor refused "
            f"for the one excused reason; stdout {output[-200:]!r}, "
            f"refusal {refusal!r}",
        )
        if not reached:
            continue
        if getattr(module, "DEBT", None) and len(module.DEBT):
            check(
                "red(s) were attributed to the test the case declares" in output,
                f"{script_name} owes {len(module.DEBT)} witnesses but does not "
                "report how many of its reds were credited without attribution, "
                "so the debt is silent again (M4-23)",
            )
            check(
                module_name in output.split("red(s) were attributed")[0].rsplit("\n", 1)[-1],
                f"{script_name}: the attribution summary does not name the "
                "harness it belongs to",
            )


def _plant_nested_dispatch(source: str) -> str | None:
    """The M4-36 bypass, applied to a harness's source.

    Moves the whole `if arguments.check_anchors:` block inside the preceding
    `if arguments.list:` block, after its `return 0`.  The dispatch is then
    **present**, **correctly ordered** relative to `require_clean_tree`, and
    **unreachable** -- which is what makes every source-text check pass while
    `main()` falls straight through to the deletion loop.
    """
    lines = source.splitlines(keepends=True)

    def block_at(index: int) -> int:
        """The line after the `if` block starting at `index`."""
        end = index + 1
        while end < len(lines) and (
            not lines[end].strip() or lines[end].startswith("        ")
        ):
            end += 1
        return end

    # There are two `if arguments.check_anchors:` blocks: the capability drop
    # at argument-parse time and the dispatch itself.  Only the **dispatch**
    # moves -- the capability drop stays exactly where it is, so this fixture
    # asserts that the drop is what saves the run when the dispatch is lost.
    # Moving the drop instead would delete the fix and test nothing.
    dispatch = None
    listing = None
    for index, line in enumerate(lines):
        if line.rstrip() == "    if arguments.check_anchors:":
            end = block_at(index)
            if any("return read_only_entry(" in row for row in lines[index:end]):
                dispatch = (index, end)
        elif line.rstrip() == "    if arguments.list:":
            listing = block_at(index)
    if dispatch is None or listing is None or listing > dispatch[0]:
        return None

    start, end = dispatch
    nested = [
        "    " + row if row.strip() else row for row in lines[start:end]
    ]
    remaining = lines[:start] + lines[end:]
    return "".join(remaining[:listing] + nested + remaining[listing:])


def _restore_write_capability() -> None:
    """Undo a `forbid_writes_for_this_process` this file provoked.

    That call is deliberately irreversible in a harness process, which has no
    later work that may write. This file *does*, so the fixtures below reset
    the barrier explicitly rather than leaving every later test running
    without write capability -- which would make them pass or fail for a
    reason that has nothing to do with what they assert.
    """
    import guard_outcomes

    guard_outcomes.NoWriteCapability.release_all()


def a_lost_check_anchors_dispatch_cannot_delete_anything() -> None:
    """The bypass M4-36 actually records, reproduced against every harness.

    **This replaces a fixture that tested the wrong scenario, and the
    correction came from independent review.**  The earlier fixture made the
    deletion loop reachable *from inside* `read_only_entry` and watched the
    barrier there refuse it. That is not what happened in the 76.8 s incident:
    there the dispatch was never reached at all, so no barrier inside it could
    fire. Driven against the then-current tree, the nested-dispatch bypass ran
    all **12** of `m3-guard-deletion`'s cases through the deletion loop with
    `read_only_entry` entered **zero** times and every shipped check passing.
    A barrier bolted onto a branch protects nothing when the branch is what
    was lost.

    So the property asserted here is the one that survives losing the
    dispatch: `--check-anchors` drops write capability at argument-parse time,
    so a harness that falls through to the deletion loop raises on its first
    mutation. The probe writes to a temporary file rather than a crate, so a
    regression fails this test instead of editing the product.

    **Defeating it.**  Remove the `forbid_writes_for_this_process()` call from
    a harness's `main()` and that harness fails here, having completed cases
    under a flag that must not edit anything. Removing the call from all six
    fails on the first.
    """
    import importlib.util

    directory = Path(__file__).resolve().parent
    unexercised: list[str] = []
    not_reached: list[str] = []
    for script_name in sorted(EXPECTED_GUARD_ANCHORS):
        original = (directory / script_name).read_text()
        bypassed = _plant_nested_dispatch(original)
        if bypassed is None:
            # Named and failed below, never silently skipped: a harness whose
            # shape this fixture cannot recognise is exactly a harness whose
            # capability drop may have moved out of reach.
            unexercised.append(script_name)
            continue

        module_name = script_name.removesuffix(".py")
        spec = importlib.util.spec_from_file_location(
            module_name.replace("-", "_") + "_bypassed", directory / script_name
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        # Executed with `__file__` pointing at the real script, so the
        # harness's own REPO-relative constants still resolve.
        exec(compile(bypassed, str(directory / script_name), "exec"), module.__dict__)

        scratch = Path(tempfile.mkdtemp()) / "product.rs"
        tally = {"attempted": 0, "completed": 0}

        class Probe:
            """The deletion loop's first write, aimed somewhere harmless.

            `attempted` counts cases that reached the mutation; `completed`
            counts those whose write actually landed. The difference is the
            whole property: the loop may be *reached* when the dispatch is
            lost, but no mutation may *succeed*.
            """

            def __init__(self, *_a, **_k) -> None:
                pass

            def __enter__(self):
                return self

            def apply_all(self, _edits):
                tally["attempted"] += 1
                scratch.write_text("a guard deleted under --check-anchors")
                tally["completed"] += 1
                return None

            def __exit__(self, *_e):
                return False

        module.AppliedCase = Probe
        module.require_clean_tree = lambda *_a, **_k: None
        module.refuse_resident_mutation = lambda *_a, **_k: None
        module.require_git_index = lambda *_a, **_k: None
        module.check_anchors = lambda *_a, **_k: 0
        if hasattr(module, "sweep_residue"):
            module.sweep_residue = lambda *_a, **_k: None
        if hasattr(module, "run_tests"):
            module.run_tests = lambda *_a, **_k: ("RED", ["anything"])

        argv = sys.argv
        sys.argv = [module_name, "--check-anchors"]
        refused = None
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                module.main()
        except WriteAttempted as stop:
            refused = str(stop)
        except SystemExit:
            pass
        except Exception:  # noqa: BLE001 - a crash is not a refusal; asserted below
            pass
        finally:
            sys.argv = argv
            _restore_write_capability()

        check(
            not scratch.exists() and tally["completed"] == 0,
            f"{script_name}: a --check-anchors run whose dispatch was nested "
            f"out of reach completed {tally['completed']} mutation(s). "
            "Read-only mode must be a capability taken away at parse time, "
            "not a branch a lost dispatch can skip (M4-36).",
        )
        if not tally["attempted"]:
            not_reached.append(script_name)
        else:
            # It reached the deletion loop, so what stopped it must be the
            # missing capability and not some unrelated refusal -- a control
            # that reddens for a sibling's reason proves nothing (M4-43).
            # `Probe.apply_all` writes with `Path.write_text`, so that is the
            # barrier that must have fired; "write capability" alone is in
            # every `refuse(...)` message and names no primitive.
            check(
                refused is not None and "called Path.write_text" in refused,
                f"{script_name}: the deletion loop was reached under "
                "--check-anchors and something other than the write barrier "
                f"stopped it; refusal was {refused!r}",
            )

    # **Exact, not a floor, and review is why (M4-43).**  This used to require
    # `exercised >= 5` and `reached >= 4` -- one below the populations of 6
    # and 5 -- so exactly one harness could drop out of either set and the
    # fixture still passed. Review planted an `m3` with **both** `if
    # arguments.check_anchors:` blocks nested under `if arguments.list:`, the
    # capability drop as well as the dispatch. The planter matches the
    # dispatch at indent 4, so it returned None, the harness was skipped, and
    # the fixture reported PASS while that harness's `--check-anchors` landed
    # 12 mutations. An excluded set that is never measured is the defect this
    # file keeps finding in itself.
    check(
        not unexercised,
        "the nested-dispatch bypass could not be planted in "
        f"{', '.join(unexercised)}, so those harness(es) were never measured. "
        "Their `--check-anchors` dispatch or capability drop is no longer at "
        "the top level of main(), which is the shape of the very bypass this "
        "fixture exists to catch (M4-36).",
    )
    # Exactly one harness may stop before the deletion loop, and it is named:
    # `m6-guard-client-bundle-sentinel` refuses without a built
    # `--client-bin`, so the loop is unreachable for it here. Any other
    # harness failing to reach the loop means this fixture proved nothing
    # about the barrier for it.
    check(
        not_reached == ["m6-guard-client-bundle-sentinel.py"],
        "the harnesses that did not reach the deletion loop under the bypass "
        f"were {not_reached}; exactly one is excused, "
        "m6-guard-client-bundle-sentinel.py (no --client-bin). Any other "
        "harness here was not tested against the write barrier.",
    )


def an_unbalanced_exit_cannot_disable_the_write_barrier() -> None:
    """The barrier must survive an `__exit__` with no matching `__enter__`.

    **Found on review, measured before it was fixed.**  `__exit__` used to
    decrement the nesting depth unconditionally, so `__enter__(); __exit__();
    __exit__()` left `_depth == -1`. The next `__enter__` then saw a non-zero
    depth, took itself to be nested inside a barrier that did not exist, and
    installed nothing -- so `forbid_writes_for_this_process()` returned with
    the process still able to write. Nothing shipped calls `__exit__`
    unbalanced, but a `finally` after a failed `__enter__` would.

    Two shapes are checked, each for its own reason: a stray second exit on
    the same instance (the depth must not go negative, and a later barrier
    must install), and an exit on a never-entered instance while another
    holds the barrier (it must not lift it). Each asserts the refusal names
    `Path.write_text`, so neither is satisfied by a sibling barrier (M4-43).

    **Defeating it.**  Restore the unconditional decrement in `__exit__` and
    the first shape fails with the write landing.
    """
    import guard_outcomes

    target = Path(tempfile.mkdtemp()) / "product.rs"

    def write_is_refused() -> str | None:
        try:
            target.write_text("mutated")
        except WriteAttempted as refusal:
            return str(refusal)
        return None

    try:
        stray = NoWriteCapability()
        stray.__enter__()
        stray.__exit__()
        stray.__exit__()
        check(
            NoWriteCapability._depth == 0,
            "an unmatched __exit__ drove the write barrier's depth to "
            f"{NoWriteCapability._depth}; below zero, the next barrier "
            "believes it is nested and installs nothing",
        )
        guard_outcomes.forbid_writes_for_this_process()
        refused = write_is_refused()
        check(
            refused is not None and "Path.write_text" in refused,
            "after a stray __exit__, forbid_writes_for_this_process() left "
            f"the process able to write (refusal {refused!r}): --check-anchors "
            "would then be read-only in name only (M4-36)",
        )

        never_entered = NoWriteCapability()
        never_entered.__exit__()
        refused = write_is_refused()
        check(
            refused is not None and "Path.write_text" in refused,
            "an __exit__ on a never-entered barrier lifted the barrier another "
            f"instance holds (refusal {refused!r})",
        )
    finally:
        _restore_write_capability()
    check(
        not target.exists(),
        "a write landed while the barrier was supposed to be held",
    )


if __name__ == "__main__":
    sys.exit(main())
