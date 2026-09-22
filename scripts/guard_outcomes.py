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
