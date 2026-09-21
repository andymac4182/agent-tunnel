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
    check_anchors,
    is_usable,
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
    every_guard_anchor_resolves_to_exactly_one_occurrence()

    print("test_guard_outcomes: PASS")
    return 0


def run_preflight(selection) -> tuple[int, str]:
    """`check_anchors` over a synthetic selection, with its output captured."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = check_anchors("test-harness", selection)
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


EXPECTED_MODULE_FILTERS = 8

#: The floor each harness's `--check-anchors` must clear, so a run that
#: selected almost nothing cannot pass as a clean sweep.  Measured on
#: `m4c33-guard-preflight` off `154ac5d`: fs 427 anchors / 13 suites,
#: acp 148 / 7, m5 82 / 3, m3 5 / 2.  These are floors, not equalities --
#: adding a guard case must not break this file -- but a drop means either a
#: deleted case, which belongs in a task row, or a selection that stopped
#: selecting, which is the vacuity trap.
EXPECTED_GUARD_ANCHORS = {
    "fs-guard-deletion.py": 427,
    "acp-guard-deletion.py": 148,
    "m5-guard-deletion.py": 82,
    "m3-guard-deletion.py": 5,
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
            # Defence in depth behind the static check above: a `--check-anchors`
            # that ever reaches the deletion loop must not be allowed to run for
            # hours from inside a unit test.
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


if __name__ == "__main__":
    sys.exit(main())
