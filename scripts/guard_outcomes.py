"""One outcome classifier for every guard-deletion harness in this repository.

**Why this file exists (task row M8-C08).**  Each harness used to carry its own
copy of the rule, written as a list of *unusable* prefixes:

* `scripts/acp-guard-deletion.py` matched ``BUILD``, ``COULD``, ``EXPECTED``,
  ``NOT``;
* `scripts/fs-guard-deletion.py` matched ``BUILD``, ``COULD``, ``MODULE``,
  ``NO TEST`` — a different list, for the same job.

A deny list of prefixes **fails open**: any outcome nobody remembered to add is
counted as neither red (the red tally matches the exact string ``RED``) nor
unusable, so it vanishes from both tallies and the run still exits 0.  That has
now happened four times in this repository, most recently with ``RED (hung)``
(M8-C06) and with ``still green``, which is present in *both* harnesses today
and means the exact opposite of a usable result: the guard was defeated and
**nothing went red**, so the guard is not load-bearing.

So the rule is inverted here and shared.  A guard-deletion run has exactly two
usable outcomes; every other spelling, present or future, fails closed and is
listed by name.  Adding a new outcome to a harness now requires no change here
at all — which is the point, because the changes that were required are the
ones that were forgotten.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

#: The only outcomes that count as a usable result.
#:
#: ``RED`` — the guard was defeated and a named test went red, which is the
#: evidence a guard-deletion suite exists to produce.
#:
#: ``REFUSED BY COMPILER`` — the guard is enforced by the type system or a
#: feature gate, so defeating it does not build.  A stronger guarantee than a
#: red test, reported separately and never counted in a red tally.
#: ``DOCUMENTED GREEN`` — the suite argues, in the case's own comment, why
#: nothing can go red: the rule is defence in depth behind a guard that refuses
#: first, so the green result *is* the measurement.  Reported separately and
#: never counted in a red total.  A case marked this way that actually goes red
#: becomes ``EXPECTED A DOCUMENTED GREEN, GOT: ...``, which is not usable —
#: the rule became load-bearing and the comment explaining the green is wrong.
#: This is distinct from a **stale** case, which nobody can explain and which
#: must stay unusable (see task row M4-18).
USABLE_OUTCOMES = frozenset({"RED", "REFUSED BY COMPILER", "DOCUMENTED GREEN"})

#: Spellings worth explaining when they are listed, because the bare status
#: reads as harmless.
EXPLANATIONS = {
    "still green": "still green — the guard was defeated and NOTHING went red, so it is not load-bearing",
}


def is_usable(outcome: str) -> bool:
    """Whether `outcome` is a result a suite may report as evidence."""
    return outcome in USABLE_OUTCOMES


def describe(outcome: str) -> str:
    """The outcome, expanded where the bare spelling understates it."""
    return EXPLANATIONS.get(outcome, outcome)


def unusable(results: Iterable[tuple[str, str, str]]) -> list[str]:
    """Every `(suite, case, outcome)` whose outcome is not usable.

    Returns display strings.  A non-empty list must make the harness exit
    non-zero: that is the whole contract, and the reason this is not a deny
    list.
    """
    return [
        f"[{suite}] {case}: {describe(outcome)}"
        for suite, case, outcome in results
        if not is_usable(outcome)
    ]


#: A selected case, reduced to the only three things a preflight needs:
#: ``(suite name, case name, edits)``, where each edit is ``(path, old, new)``.
#: The four harnesses carry different per-case payloads -- `fs-` selects
#: 3-tuples, `m5-`, `acp-` and `m3-` select 4-tuples with an
#: ``expect_build_failure`` flag -- so each normalises to this on the way in
#: rather than this module learning all four selection shapes.
Selection = tuple[str, str, Sequence[tuple[Path, str, str]]]


def check_anchors(
    harness: str,
    selected: Iterable[Selection],
    extra_problems: Iterable[str] = (),
) -> int:
    """Resolve every selected case's guard text against the tree, and stop.

    **Why this is here rather than copied into each harness (task row M4-27).**
    The per-case refusal inside every deletion loop already fails the run and
    names the case -- but only for the cases a given invocation selects, and
    only after paying a `cargo test` per case, so a formatter pass that rewraps
    several anchors at once is not reported until the run walks to each one,
    and a full run is measured in hours.  This moves that existing refusal from
    hour three to second one.  It changes no outcome and no count.

    The row that asks for it says why it is shared: "the preflight belongs in
    the shared shape all four harnesses use, so a mistake in it blocks every
    M3, M4, M5 and M8 guard run at once".  Four copies would be four places for
    the next fix to be applied to three of -- which is the same rot the
    allowlist above exists to refuse, and the reason `USABLE_OUTCOMES` is not
    copied four times either.

    Returns 0 when every anchor resolves to exactly one occurrence, and 1
    otherwise, having listed **all** mismatches rather than stopping at the
    first -- one formatter pass rewraps several anchors, and reporting them one
    run at a time is the cost this exists to remove.
    """
    # An empty selection must refuse rather than report a clean sweep of
    # nothing.  `--check-anchors --case no-such-case` used to print "checked 0
    # anchors ... every anchor resolves" and exit 0: a check that can pass
    # because it measured nothing proves less than it claims, and it is owed by
    # a flag whose entire job is to be trusted when it says nothing is wrong.
    selected = list(selected)
    if not selected:
        print(
            f"{harness}: --check-anchors selected no cases, so it checked "
            "nothing; a clean result over an empty selection is not evidence",
            flush=True,
        )
        return 1

    problems = 0
    checked = 0
    for suite_name, case_name, edits in selected:
        for path, old, _ in edits:
            checked += 1
            occurrences = path.read_text().count(old)
            if occurrences != 1:
                problems += 1
                kind = (
                    "STALLED: guard text not found"
                    if occurrences == 0
                    else f"AMBIGUOUS: {occurrences} occurrences"
                )
                print(f"[{suite_name}] {case_name}: {kind} in {path}", flush=True)
    for problem in extra_problems:
        problems += 1
        print(f"{harness}: {problem}", flush=True)
    print(
        f"{harness}: checked {checked} anchors across "
        f"{len({suite_name for suite_name, _, _ in selected})} suite(s)",
        flush=True,
    )
    if problems:
        print(f"{harness}: {problems} anchor problem(s)", flush=True)
        return 1
    print(f"{harness}: every anchor resolves to exactly one occurrence", flush=True)
    return 0
