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

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from guard_outcomes import USABLE_OUTCOMES, is_usable, unusable  # noqa: E402


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
    every_guard_anchor_resolves_to_exactly_one_occurrence()

    print("test_guard_outcomes: PASS")
    return 0


EXPECTED_MODULE_FILTERS = 8
EXPECTED_GUARD_ANCHORS = 426


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
    """
    script = Path(__file__).resolve().parent / "fs-guard-deletion.py"
    result = subprocess.run(
        [sys.executable, str(script), "--check-anchors"],
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        result.returncode == 0,
        "fs-guard-deletion --check-anchors failed:\n"
        f"{result.stdout}{result.stderr}",
    )
    # The same vacuity trap as the filter scan above: a `--check-anchors` that
    # silently selected nothing would exit 0 and prove nothing, so require the
    # run to say how much it actually looked at.
    check(
        "checked " in result.stdout and " anchors across " in result.stdout,
        "--check-anchors did not report how many anchors it checked, so its "
        f"exit code is not evidence: {result.stdout!r}",
    )
    checked = int(result.stdout.split("checked ", 1)[1].split(" anchors", 1)[0])
    check(
        checked >= EXPECTED_GUARD_ANCHORS,
        f"expected at least {EXPECTED_GUARD_ANCHORS} anchors to be checked, "
        f"found {checked} -- the scan selected almost nothing, so its silence "
        "is not evidence",
    )


if __name__ == "__main__":
    sys.exit(main())
