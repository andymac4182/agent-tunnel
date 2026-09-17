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

from collections.abc import Iterable

#: The only outcomes that count as a usable result.
#:
#: ``RED`` — the guard was defeated and a named test went red, which is the
#: evidence a guard-deletion suite exists to produce.
#:
#: ``REFUSED BY COMPILER`` — the guard is enforced by the type system or a
#: feature gate, so defeating it does not build.  A stronger guarantee than a
#: red test, reported separately and never counted in a red tally.
USABLE_OUTCOMES = frozenset({"RED", "REFUSED BY COMPILER"})

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
