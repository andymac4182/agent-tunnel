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

import json
import os
import signal
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from types import TracebackType

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


# --------------------------------------------------------------------------
# Interrupt-safe mutation (task row M5-C07)
# --------------------------------------------------------------------------
#
# Every guard-deletion harness defeats one guard at a time by editing the
# crate in place and restoring it *after* the test run.  Killed between those
# two steps -- which is exactly what an interrupted multi-hour chain does --
# the mutation is **left in the working tree**, and the next `git add -A`
# commits it.  That happened twice within an hour on 2026-09-20, both times
# landing a defeated guard in a commit whose subject said `docs:`, and once
# more from inside `scripts/test_guard_outcomes.py` (M4-34), whose 120 s kill
# pre-empted a harness's `restore()` and left a mutation in
# `crates/tunnel-cua/src/outcome.rs`.
#
# This is the shared half of the remedy, and it has three layers because no
# single one covers every way a process dies:
#
# 1. `AppliedCase` is a context manager, so a `KeyboardInterrupt`, a
#    `SystemExit` or any exception still restores on the way out.  This is the
#    `try/finally` the row asks for, written once rather than four times.
# 2. `install_interrupt_restore` makes `SIGTERM` and `SIGHUP` raise, so those
#    reach layer 1 instead of bypassing it.  `SIGINT` already raises
#    `KeyboardInterrupt`; `SIGKILL` cannot be handled at all, which is why
#    there is a layer 3.
# 3. A **journal file** is written before the first byte of a case is mutated
#    and removed only after the restore completes.  A `SIGKILL` leaves it
#    behind holding the original text of every file it touched, so
#    `refuse_resident_mutation` can *name* the suite, the case and the files
#    rather than the tree merely looking clean -- and the originals are
#    recoverable byte for byte.
#
# **Why the restore writes recorded bytes rather than running `git checkout
# --`.**  `git checkout --` over a crate discards *everything* uncommitted
# under that path, not only the line the case mutated -- the mechanism of
# M4-32, where a legitimate edit made during a completing run is silently
# erased, and of a loss this session where a `git checkout --` meant to revert
# one mutation destroyed all of an agent's uncommitted work.  Writing back the
# exact recorded original touches only the files the case itself mutated.
# That narrows M4-32; it does not close it, because a `cargo fmt` run against
# a mutated tree still reflows anchors, so the discipline that row states --
# nothing may touch the worktree while a suite runs -- still stands.

#: Name of the journal a harness stamps while a case's edits are applied.
MUTATION_JOURNAL_NAME = ".guard-mutation-journal.json"


def mutation_journal(repo: Path) -> Path:
    """Where the in-flight-mutation journal lives for `repo`."""
    return repo / MUTATION_JOURNAL_NAME


def refuse_resident_mutation(harness: str, repo: Path) -> None:
    """Refuse to start when a previous run left a mutation applied.

    The existing `require_clean_tree` check in each harness refuses on a dirty
    tree, which already catches the common case -- but it can only say
    "something is uncommitted here", and it says it about a tree somebody may
    reasonably believe they dirtied themselves.  This says *which* harness,
    *which* suite and *which* case was in flight, and which files hold a
    defeated guard right now, because a resident mutation is not a dirty tree
    to be tidied: it is a guard deleted from the product.
    """
    journal = mutation_journal(repo)
    try:
        record = json.loads(journal.read_text())
    except FileNotFoundError:
        return
    except (OSError, ValueError) as problem:
        sys.exit(
            f"{harness}: a mutation journal exists at {journal} but could not "
            f"be read ({problem}). A previous guard run was interrupted while a "
            "guard was deleted from the product; do not trust this tree. "
            "Compare it against HEAD blob by blob before doing anything else."
        )
    files = record.get("files", [])
    listing = "\n".join(f"    {entry.get('path')}" for entry in files)
    sys.exit(
        f"{harness}: refusing to run -- a previous guard-deletion run was "
        f"interrupted while a case was applied, so a defeated guard may be "
        f"resident in the product right now (task row M5-C07).\n"
        f"  harness: {record.get('harness')}\n"
        f"  suite:   {record.get('suite')}\n"
        f"  case:    {record.get('case')}\n"
        f"  pid:     {record.get('pid')}\n"
        f"  files holding a mutation:\n{listing}\n"
        "  Recover with: python3 scripts/guard_outcomes.py --recover-mutations\n"
        "  which writes back the original text this journal recorded, then "
        "removes it. Do NOT simply delete the journal: that discards the only "
        "record of what was mutated."
    )


def recover_mutations(repo: Path) -> int:
    """Write back every original the journal recorded, then remove it.

    Separate from `refuse_resident_mutation` on purpose: the refusal must not
    repair anything silently.  An interrupted run is a fact worth a human
    reading it, and a harness that quietly fixed the tree and carried on would
    make the incident invisible -- which is the whole complaint of M5-C07.

    **It writes the recorded originals back without checking that each file
    still holds the mutation**, so an edit made to one of those files *after*
    the interrupted run would be clobbered.  That is accepted rather than
    guarded: the refusal this answers says in terms not to trust the tree, so
    "read the refusal, then edit the named files, then recover" is not a
    sequence anybody is being invited into.  A caller who has already edited
    those files should revert from `HEAD` and delete the journal by hand.
    """
    journal = mutation_journal(repo)
    try:
        record = json.loads(journal.read_text())
    except FileNotFoundError:
        print(f"no mutation journal at {journal}; nothing to recover", flush=True)
        return 0
    restored = 0
    for entry in record.get("files", []):
        path = repo / entry["path"]
        path.write_text(entry["original"])
        print(f"restored {entry['path']}", flush=True)
        restored += 1
    journal.unlink()
    print(
        f"recovered {restored} file(s) from the [{record.get('suite')}] "
        f"{record.get('case')} mutation and removed the journal",
        flush=True,
    )
    return 0


def install_interrupt_restore() -> None:
    """Make `SIGTERM`/`SIGHUP` raise, so a context manager's exit still runs.

    Python turns `SIGINT` into `KeyboardInterrupt` already, but the default
    `SIGTERM` disposition terminates the process without unwinding -- so a
    `kill`, a hangup from a supervising shell, or a test harness's
    `subprocess.run(timeout=)` would skip every `finally` in the program.  That
    is the M4-34 incident exactly.

    **`SIGHUP` is installed unconditionally, which overrides an inherited
    `SIG_IGN`.**  So a run launched under `nohup` -- which ignores `SIGHUP`
    precisely so it survives a lost terminal -- will now exit on hangup
    instead of continuing.  That is deliberate and is the safe direction for
    *this* program: exiting runs the restore, whereas surviving a hangup with
    a mutation applied and nobody watching is the M5-C07 incident with a
    longer fuse.  Nothing in this repository `nohup`s a guard suite, and the
    note is here so the next reader does not have to re-derive why a
    backgrounded run died cleanly.
    """

    def raise_on_signal(number: int, _frame: object) -> None:
        raise SystemExit(f"interrupted by signal {signal.Signals(number).name}")

    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, raise_on_signal)


class AppliedCase:
    """One case's edits, applied so that no exit path can leave them resident.

    Used as a context manager around the apply/test/restore cycle::

        with AppliedCase(harness, repo, suite.name, name) as applied:
            problem = applied.apply_all(edits)
            if problem is None:
                outcome = run_tests(suite)

    The restore happens on the way out of the `with` block **whatever** takes
    us out of it -- a normal return, a refusal, an exception, a
    `KeyboardInterrupt`, or the `SystemExit` that `install_interrupt_restore`
    turns `SIGTERM` into.
    """

    def __init__(self, harness: str, repo: Path, suite: str, case: str) -> None:
        self.harness = harness
        self.repo = repo
        self.suite = suite
        self.case = case
        #: `(path, original text)` for every file mutated so far, in order.
        self.originals: list[tuple[Path, str]] = []

    def __enter__(self) -> AppliedCase:
        return self

    def _write_journal(self) -> None:
        """Write the journal **atomically**.

        This is rewritten on every `apply`, and a multi-edit case rewrites it
        with the earlier files' originals already in it -- `acp-` has a
        two-edit case and `fs-` an eight-edit one.  A bare truncate-then-write
        `SIGKILL`ed between the truncate and the write would leave an *empty*
        journal and lose the originals recorded for the earlier edits: the
        refusal would still fire, so the tree would not be trusted, but
        "recoverable byte for byte" would be false in exactly the window this
        class exists to cover.  `os.replace` is atomic within a filesystem, so
        the journal on disk is always either the previous complete record or
        the new one.  A `SIGKILL` during the temporary write leaves the older
        complete journal in place and the not-yet-mutated file unmutated,
        which is the safe direction.
        """
        journal = mutation_journal(self.repo)
        payload = json.dumps(
            {
                "harness": self.harness,
                "suite": self.suite,
                "case": self.case,
                "pid": os.getpid(),
                "files": [
                    {
                        "path": str(path.relative_to(self.repo)),
                        "original": original,
                    }
                    for path, original in self.originals
                ],
            },
            indent=2,
        )
        temporary = journal.with_name(journal.name + ".tmp")
        temporary.write_text(payload)
        os.replace(temporary, journal)

    def apply(self, path: Path, old: str, new: str) -> str | None:
        """Record the original and mutate, or return why it could not.

        The original is journalled **before** the file is written, so a kill
        between the two leaves a journal naming a file that turns out to be
        unmutated -- which is recoverable and honest.  The other order would
        leave a mutated file no journal mentions, which is the defect.

        Both occurrence refusals are load-bearing and were carried here from
        the four copies this replaces.  Zero occurrences means the guard text
        no longer exists, so the case is stale and measures nothing.  More than
        one means `str.replace(old, new, 1)` would silently edit the **first**
        match, so a case whose text is not unique measures some other guard --
        and reports a red for it under this case's name.
        """
        text = path.read_text()
        occurrences = text.count(old)
        if occurrences == 0:
            return "guard text not found"
        if occurrences > 1:
            return f"guard text is ambiguous: {occurrences} occurrences"
        self.originals.append((path, text))
        self._write_journal()
        path.write_text(text.replace(old, new, 1))
        return None

    def apply_all(self, edits: Iterable[tuple[Path, str, str]]) -> str | None:
        """Apply every edit, stopping at the first that cannot be applied."""
        for path, old, new in edits:
            problem = self.apply(path, old, new)
            if problem is not None:
                return problem
        return None

    def restore(self) -> None:
        """Write back every recorded original, then drop the journal."""
        while self.originals:
            path, original = self.originals.pop()
            path.write_text(original)
        journal = mutation_journal(self.repo)
        journal.unlink(missing_ok=True)
        # A `SIGKILL` during an atomic journal write can leave the temporary
        # behind. Harmless -- `os.replace` never ran, so the journal proper is
        # the older complete record -- but it should not accumulate.
        journal.with_name(journal.name + ".tmp").unlink(missing_ok=True)

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> bool:
        self.restore()
        # Never suppress: an interrupt must still stop the run, and a refusal
        # must still be reported.  This only guarantees the tree is clean
        # first.
        return False



# --------------------------------------------------------------------------
# Witness attribution (task rows M4-23, M4-24)
# --------------------------------------------------------------------------
#
# `run_tests` in every harness returns `RED` on `returncode != 0` and collects
# every `FAILED` line, with no attribution to the guard that was deleted.  So
# a case is credited whenever *anything* in the suite's surface goes red --
# `fs-guard-deletion`'s gate4 command alone spans four crates' entire test
# surface -- and a case can pass while the test it exists for never ran, never
# failed, or failed for an unrelated reason.
#
# **The reach was measured before this was written (M4-24), and it is not
# positional.**  Driving each harness's own shipped classifier with a failure
# named after no test in the repository, **691 of 745** guard cases were
# credited for it: `fs` 447 of 475, `m5` 100 of 100, `acp` 144 of 146, and
# `m3` and `m0` 0 of 12 each.  The two that refuse are the two that already
# carried `expected_red`.  So the answer M4-24 asks for -- any case, or only
# one position? -- is **neither of the two rivals it names**: every value case
# in every harness lacking this mechanism is exposed, and position has nothing
# to do with it.  The 54 that refuse do so because they are `EXPECT_GREEN`
# (29) or a compiler refusal (1), which fail closed on any red at all, or
# because they already declare a witness (24).
#
# The figure is `691` and not the `657` an earlier pass reported.  That pass
# recovered each case's outcome by regex-splitting the harness's own log
# lines, and 34 case names contain ": ", so a non-greedy split moved part of
# the name into the outcome and scored those cases as refused.  Re-derived by
# reading the `(suite, case, outcome)` triples the harness hands to
# `unusable_outcomes`, it agrees to the case with an independent count of
# value cases taken straight from the shipped case lists.
#
# The remedy is the one `m0-guard-exit-codes` and `m3-guard-deletion` already
# ship, lifted here so there is one copy rather than five: a case names the
# test that must redden, and a red without it is `RED (wrong witness)`, which
# is absent from `USABLE_OUTCOMES` and fails the run.


class WitnessDebt:
    """Cases that predate the witness requirement, pinned so they can only shrink.

    **Why this exists rather than 657 invented witnesses.**  A witness is the
    test that reddens when *this* guard is deleted.  That is a measurement --
    one `cargo test` per case, hours per harness -- and it cannot be read off
    the case's text.  Writing a plausible-looking test name next to each case
    would produce a harness that checks 657 guesses and reports them as
    attribution, which is the M4-23 defect with a longer stride: the run's
    success and its measuring nothing would still look identical, and would
    now additionally *claim* to have been attributed.

    So the undeclared cases are named, counted and frozen instead.  A case in
    the ledger keeps the old "any red will do" classification and is reported
    as such; a case **not** in the ledger and not declaring a witness is
    refused before anything is edited.  New cases therefore cannot join the
    debt, and a case given a real witness must be struck from the ledger,
    so the figure this pins is monotonically decreasing by construction.
    """

    def __init__(self, undeclared: Iterable[tuple[str, str]]) -> None:
        #: `(suite, case)` for every case still classified without attribution.
        self.undeclared = frozenset(undeclared)

    def owes(self, suite: str, case: str) -> bool:
        return (suite, case) in self.undeclared

    def __len__(self) -> int:
        return len(self.undeclared)



#: Where the pinned ledger of cases that predate the witness requirement lives.
WITNESS_DEBT_FILE = Path(__file__).resolve().parent / "guard_witness_debt.json"


def load_witness_debt(harness: str) -> WitnessDebt:
    """The pinned ledger for `harness`, or an empty one if it owes nothing.

    Read from a single JSON file rather than inlined into each harness so the
    total is countable in one place and a test can assert it never grows.  A
    harness with no entry owes nothing, which is the state every harness is
    meant to reach.
    """
    try:
        ledger = json.loads(WITNESS_DEBT_FILE.read_text())
    except FileNotFoundError:
        return WitnessDebt(())
    return WitnessDebt(
        (suite, case) for suite, case in ledger.get(harness, [])
    )


def require_declared_witnesses(
    harness: str,
    cases: Iterable[tuple[str, str, bool, frozenset[str]]],
    debt: WitnessDebt,
) -> None:
    """Refuse, before anything is edited, a case that names no test it owns.

    `cases` is `(suite, case, expect_build_failure, expected_red)`.

    Without this the mechanism is opt-in, and a case added with the field
    omitted falls back silently to the behaviour it exists to reject -- the
    mechanism's own version of the defect it guards.  A compiler-refusal case
    declares none: a build failure names no test, and requiring one would be
    incoherent.
    """
    missing: list[str] = []
    contradictory: list[str] = []
    stale_debt: list[str] = []
    for suite, case, expect_build_failure, expected_red in cases:
        if expect_build_failure and expected_red:
            contradictory.append(f"[{suite}] {case}")
        elif expect_build_failure:
            continue
        elif expected_red and debt.owes(suite, case):
            # A case cannot both declare a witness and be owed one.  Left
            # unchecked the ledger would silently outlive the fix it tracks.
            stale_debt.append(f"[{suite}] {case}")
        elif not expected_red and not debt.owes(suite, case):
            missing.append(f"[{suite}] {case}")
    problems = (
        [f"{entry} (names no witness)" for entry in missing]
        + [f"{entry} (compiler refusal may not name a witness)" for entry in contradictory]
        + [f"{entry} (declares a witness but is still in the debt ledger)" for entry in stale_debt]
    )
    if problems:
        sys.exit(
            f"{harness}: every value case must name the test(s) that must "
            "redden when its guard is deleted. A case classified RED by an "
            "unrelated failure is not evidence for the rule it claims (task "
            "row M4-23). Offending case(s): " + ", ".join(problems)
        )


def classify_outcome(
    outcome: str,
    failures: Sequence[str],
    *,
    documented_green: bool,
    expect_build_failure: bool,
    expected_red: frozenset[str],
    owed_witness: bool,
) -> str:
    """The one classification rule, shared by all five harnesses.

    This was five near-identical inline blocks in five `main()` functions.
    The witness check existed in two of them, which is precisely how M4-23
    came to be true of the other three: a rule copied five times is a rule
    fixed in two.
    """
    if documented_green:
        return (
            "DOCUMENTED GREEN"
            if outcome == "still green"
            else f"EXPECTED A DOCUMENTED GREEN, GOT: {outcome}"
        )
    if expect_build_failure:
        return (
            "REFUSED BY COMPILER"
            if outcome == "BUILD FAILED"
            else f"EXPECTED A COMPILER REFUSAL, GOT: {outcome}"
        )
    if outcome == "BUILD FAILED":
        return "BUILD FAILED (not evidence)"
    if outcome != "RED":
        return outcome
    if owed_witness:
        # Unattributed by declaration, not by accident.  Still counted, so the
        # ledger is a debt and not a silent exemption -- `UNATTRIBUTED` is
        # printed beside it and the ledger's size is asserted elsewhere.
        return "RED"
    missing = sorted(expected_red - set(failures))
    if missing:
        # `RED` means *something* failed; it does not mean the rule this case
        # names was what noticed.  This spelling is absent from
        # `USABLE_OUTCOMES`, so it fails the run rather than being counted as
        # evidence for a rule it did not test.
        return (
            "RED (wrong witness): expected "
            + ", ".join(missing)
            + " to redden, got "
            + (", ".join(failures) if failures else "nothing")
        )
    return "RED"


# --------------------------------------------------------------------------
# The git index a harness needs in order to see anything (task row M4-26)
# --------------------------------------------------------------------------


def require_git_index(harness: str, repo: Path) -> None:
    """Refuse to run, or to believe a completed run, without a git index.

    Git writes `index.lock` and renames it over `index`, so a process killed
    in that window loses the index outright -- and a guard harness under
    concurrent-build memory pressure is the widest such window in this
    repository.  With no index every check that would notice goes blind in the
    same direction at once: `git status --porcelain -- <path>` reports tracked
    files as untracked, and `git diff -- crates/` -- the check M5-C07
    prescribes before every commit -- reports **clean**, because a file
    carrying a resident mutation reads as untracked and `git diff` has nothing
    to compare against.

    So the prescribed check reports clean precisely when the thing it exists
    to catch has happened.  This refuses instead, and it is called both before
    a run and after it: the loss that matters happens *mid-run*, so a check
    only at the start would certify an index that was gone by the end.

    `AppliedCase.restore` writes back recorded bytes rather than running `git
    checkout --`, so a lost index no longer stops the restore itself -- that
    half of M4-26 was closed by M5-C07.  What remains is that nothing
    *verifies* the index survived, and a count from a run whose index state
    was not confirmed is not a measurement.
    """
    done = subprocess.run(
        ["git", "ls-files"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    tracked = len(done.stdout.splitlines()) if done.returncode == 0 else 0
    if tracked == 0:
        sys.exit(
            f"{harness}: refusing to trust this run -- `git ls-files` in "
            f"{repo} lists {tracked} tracked file(s), so this checkout has no "
            "usable git index (task row M4-26). Every check that would notice "
            "a resident mutation reports clean in this state: `git status "
            "--porcelain` calls tracked files untracked and `git diff -- "
            "crates/` compares against nothing.\n"
            "  Recover with: git read-tree HEAD\n"
            "  then re-run this harness from the start. Do not report any "
            "figure from a run that saw this message: a count from a run "
            "whose index state was not confirmed is not a measurement."
        )


# --------------------------------------------------------------------------
# A read-only entry with no write capability (task row M4-36)
# --------------------------------------------------------------------------
#
# `--check-anchors` used to be read-only by virtue of *where its two lines sat*
# in `main()`.  M4-34 pinned that with a source-text assertion -- the dispatch
# must be spelt this way and must appear before `require_clean_tree` -- and
# M4-36 records what such a check cannot see.  Nesting the dispatch under the
# preceding `if arguments.list:` block leaves it present, correctly ordered and
# unreachable; `m3-guard-deletion.py --check-anchors` then ran the entire
# destructive suite to completion in 76.8 s, deleting and restoring all five
# guards, and exited 0, while `test_guard_outcomes.py` reported PASS.  Nothing
# anywhere reported a problem, because a successful destructive run looks
# exactly like a successful read-only one.
#
# The substance of the property is "this invocation must not be able to write",
# and that is expressible directly rather than as a claim about two lines'
# position: enter a scope in which the write primitives raise, resolve the
# anchors, and leave.  A deletion loop that becomes reachable from this entry
# does not run to completion and exit 0 -- it raises on its first mutation and
# names itself.  That is the part the source-text check could not express, and
# it is what `test_guard_outcomes.py` now fixtures.


class WriteAttempted(RuntimeError):
    """A read-only entry point tried to modify something."""


class NoWriteCapability:
    """A scope in which the primitives a guard run mutates with all raise.

    Public because it is what `test_guard_outcomes.py` exercises directly:
    the property M4-36 asks for is behavioural, so the fixture has to be able
    to enter the same scope `read_only_entry` enters and attempt each write.

    This covers the ways every harness in this repository changes the tree:
    `Path.write_text` (`AppliedCase.apply` and `restore`), `Path.open` in any
    writing mode, `os.replace` (the journal), `Path.unlink` (the journal
    again), and `subprocess.run` (`cargo`, and any `git` that could write).

    It is a capability barrier and not a sandbox: code that reached for
    `os.write` on a raw descriptor would get through.  Nothing here does, and
    the point is not to contain an adversary -- it is that the read-only entry
    cannot *accidentally* acquire a write path, which is the failure M4-36
    describes.  The fixture that proves it works does so by making the
    deletion loop reachable and watching this raise.
    """

    def __enter__(self) -> NoWriteCapability:
        import subprocess as _subprocess

        self._saved = {
            "write_text": Path.write_text,
            "open": Path.open,
            "unlink": Path.unlink,
            "replace": os.replace,
            "run": _subprocess.run,
        }
        self._subprocess = _subprocess

        def refuse(what: str):
            def refused(*_args, **_kwargs):
                raise WriteAttempted(
                    f"a read-only guard-harness entry point called {what}; "
                    "read-only mode is a path without write capability (task "
                    "row M4-36), so this is a bypassed dispatch and not a "
                    "slow run"
                )

            return refused

        def guarded_open(self_path, mode="r", *args, **kwargs):
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                raise WriteAttempted(
                    f"a read-only guard-harness entry point opened "
                    f"{self_path} with mode {mode!r} (task row M4-36)"
                )
            return self._saved["open"](self_path, mode, *args, **kwargs)

        Path.write_text = refuse("Path.write_text")
        Path.unlink = refuse("Path.unlink")
        Path.open = guarded_open
        os.replace = refuse("os.replace")
        self._subprocess.run = refuse("subprocess.run")
        return self

    def __exit__(self, *_exc: object) -> bool:
        Path.write_text = self._saved["write_text"]
        Path.open = self._saved["open"]
        Path.unlink = self._saved["unlink"]
        os.replace = self._saved["replace"]
        self._subprocess.run = self._saved["run"]
        return False


def read_only_entry(
    harness: str,
    selected: Iterable[Selection],
    extra_problems: Iterable[str] = (),
) -> int:
    """Resolve every selected case's anchors, unable to write anything.

    The read-only entry point M4-36 asks for.  All five harnesses dispatch
    `--check-anchors` into this rather than calling `check_anchors` directly,
    so read-only-ness is a property of the call graph -- this function holds
    no write capability and neither does anything it calls -- instead of a
    property of two lines' position in a `main()`.
    """
    selected = list(selected)
    with NoWriteCapability():
        return check_anchors(harness, selected, extra_problems)



def _main() -> int:
    """`--recover-mutations`, for a tree an interrupted run left mutated."""
    repo = Path(__file__).resolve().parent.parent
    if "--recover-mutations" in sys.argv[1:]:
        return recover_mutations(repo)
    print(
        "guard_outcomes: a shared module, not a harness. Pass "
        "--recover-mutations to undo a mutation an interrupted guard-deletion "
        "run left in the tree (task row M5-C07).",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(_main())
