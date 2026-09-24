#!/usr/bin/env python3
"""Tests for the upstream-pin rule in scripts/m7-evidence-guard.py (M8-C21).

The rule lets a verified row cite an upstream artifact -- a commit that is not
and never will be in this repository's history -- but ONLY when docs/sources.md
records that artifact: the full 40-character hash, inside a URL carrying that
hash, beside a labelled SHA-256 content digest.

The red fixture is the point of this file.  A tooling edit that silently
exempted every unresolvable hash would leave m7-evidence-guard.py,
fs-guard-deletion.py and test_guard_outcomes.py all green while the guard had
stopped guarding; that fail-open is what M8-C21 exists to prevent, and only a
case that MUST be reported can detect it.  The green fixture is pinned the same
way test_guard_outcomes.py pins its allowlist: against the real docs/sources.md
entry, so deleting or hollowing out that entry turns this test red rather than
leaving a stale copy of it passing in here.

    python3 scripts/test_evidence_guard_pins.py

Exit codes: 0 pass, non-zero on the first failed case.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS.parent

_spec = importlib.util.spec_from_file_location(
    "m7_evidence_guard", SCRIPTS / "m7-evidence-guard.py"
)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)  # type: ignore[union-attr]

# The upstream RFD commit sources.md pins, and the crates.io/vcs pins beside it.
RFD_COMMIT = "ccff4e7d2e431880225804a8c136c2ccfcb313d0"
SDK_COMMIT = "726c5030bfaa88cfdac2fb1f71a63abb331ce586"
RFD_DIGEST = "db16730db8bcd8d3598323cd0939ce9a655a83ed93a7fd2ce7a31e3ce7be8d37"
# A well-formed 40-hex hash that is in no history and in no sources.md record.
UNRECORDED = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"


def check(condition: bool, message: str) -> None:
    if not condition:
        sys.exit(f"test_evidence_guard_pins: {message}")


def unresolvable(_token: str) -> "bool | None":
    """Every hash is unresolvable: the case upstream pins always fall into."""
    return None


def resolvable_non_ancestor(_token: str) -> "bool | None":
    return False


def findings_for(line: str, pins: "set[str]", ancestry=unresolvable) -> "list[str]":
    found, _gates, _hashes, _pins = guard.row_findings(
        "docs/tasks.md", 1, line, set(), pins, ancestry
    )
    return found


def row(body: str) -> str:
    """A verified tasks.md row carrying `body` as its evidence cell."""
    return f"| M8-01 | [x] Pin stable ACP v1. | verified local | m8c1 worker | {body} | — |"


def main() -> int:
    real_sources = (REPO_ROOT / "docs" / "sources.md").read_text(encoding="utf-8")
    pins = guard.recorded_upstream_pins(real_sources)

    # --- the green fixture: the real sources.md entry ------------------------
    check(
        RFD_COMMIT in pins,
        "docs/sources.md no longer records the transport RFD pin "
        f"{RFD_COMMIT[:8]} with a URL carrying the hash and a labelled SHA-256 "
        "digest; either the record was weakened or the rule stopped reading it",
    )
    check(
        SDK_COMMIT in pins,
        "docs/sources.md no longer records the rust-sdk vcs pin "
        f"{SDK_COMMIT[:8]}; the five other upstream pins in M8-01 are the same "
        "kind of record and must be recognised the same way",
    )
    check(
        findings_for(row(f"The pin is 2026-07-02 at commit `{RFD_COMMIT[:8]}…`."), pins)
        == [],
        "a verified row citing the recorded upstream pin by its short form must "
        "pass: sources.md records repository, commit, path and digest",
    )
    check(
        findings_for(row(f"from rust-sdk commit `{SDK_COMMIT}`."), pins) == [],
        "the full 40-character form of a recorded pin must pass too",
    )

    # --- the red fixture: an upstream hash with no sources.md entry ----------
    # The marker words are deliberate.  The exemption is keyed on sources.md,
    # so writing "upstream pin (recorded)" into the tracker must buy nothing:
    # a tracker marker would be a new cue word addable at will.
    red = findings_for(
        row(f"upstream pin (recorded, verified) at commit `{UNRECORDED}`."), pins
    )
    check(len(red) == 1, f"the unrecorded upstream hash must be one finding, got {red}")
    check(
        "sources.md" in red[0],
        f"the finding must name the record that is missing, got {red[0]}",
    )
    check(
        len(findings_for(row(f"commit `{UNRECORDED[:8]}`."), pins)) == 1,
        "the short form of an unrecorded hash must fail as well",
    )

    # --- a record that exists but records too little ------------------------
    hollow = f"- Pinned: the transport RFD at `{RFD_COMMIT}`, SHA-256 `{RFD_DIGEST}`."
    check(
        guard.recorded_upstream_pins(hollow) == set(),
        "an entry with a hash and a digest but NO URL records no repository or "
        "path and must not create a pin",
    )
    check(
        len(findings_for(row(f"at commit `{RFD_COMMIT}`."),
                         guard.recorded_upstream_pins(hollow))) == 1,
        "a row whose sources.md entry lacks the URL must fail",
    )

    no_digest = (
        "- Pinned: the transport RFD, immutable at "
        f"[`{RFD_COMMIT}`](https://github.com/agentclientprotocol/"
        f"agent-client-protocol/blob/{RFD_COMMIT}/docs/rfds/transport.mdx)."
    )
    check(
        guard.recorded_upstream_pins(no_digest) == set(),
        "an entry with a URL but NO content digest does not record what the "
        "artifact contained and must not create a pin",
    )
    check(
        len(findings_for(row(f"at commit `{RFD_COMMIT}`."),
                         guard.recorded_upstream_pins(no_digest))) == 1,
        "a row whose sources.md entry lacks the digest must fail",
    )

    unlabelled = no_digest[:-1] + f", `{RFD_DIGEST}`."
    check(
        guard.recorded_upstream_pins(unlabelled) == set(),
        "a bare 64-hex blob with no SHA-256/checksum label is not a recorded "
        "digest: an unexplained number must not stand in for a re-hash",
    )

    # --- what the exemption must NOT launder --------------------------------
    check(
        len(findings_for(row(f"at commit `{RFD_COMMIT}`."), pins,
                         resolvable_non_ancestor)) == 1,
        "a hash git DOES resolve is a claim about this repository's history; "
        "being listed in sources.md must not excuse a non-ancestor commit",
    )
    check(
        guard.is_recorded_pin(RFD_COMMIT[:8], pins),
        "prefix matching from the row's short form is the intended match",
    )
    check(
        not guard.is_recorded_pin("deadbee", pins),
        "a hash that prefixes no recorded pin must not be exempt",
    )

    # The shapes review constructed against the looser predicate.  Each
    # satisfied "a 40-hex hash, a URL containing it, and a labelled digest
    # somewhere on the line", and none of them is a record of anything.
    # Pinned here so the tightening cannot be quietly undone.
    other = "c" * 40
    for label, line in {
        "a negated label is not a record": (
            f"No checksum was recorded for https://github.com/o/r/tree/{UNRECORDED};"
            f" the log id {RFD_DIGEST} is unrelated"
        ),
        "http is not https": (
            f"http://github.com/o/r/blob/{UNRECORDED}/f SHA-256 {RFD_DIGEST}"
        ),
        "a compare link names two commits and pins neither": (
            f"https://github.com/o/r/compare/{UNRECORDED}...{other} SHA-256 {RFD_DIGEST}"
        ),
        "a query parameter is not a repository path": (
            f"https://example.org/?q={UNRECORDED} checksum {RFD_DIGEST}"
        ),
    }.items():
        check(
            UNRECORDED not in guard.recorded_upstream_pins(line),
            f"must not be read as a pin record: {label}",
        )

    # A KNOWN LIMIT, asserted so that closing it announces itself.
    #
    # A line naming one commit in a blob/tree/commit URL and a labelled digest
    # of some *other* artifact satisfies every structural condition, and no
    # regex separates them.  This asserts the gap rather than hiding it: if a
    # future change makes the predicate reject this, the test goes red and
    # whoever tightened it must come here, read the reasoning and update it --
    # the same shape as the escaping-descendant test in the ACP supervisor.
    #
    # The gap cannot launder history: the exemption is reachable only for a
    # hash git cannot resolve, so a wrong pin can never turn a non-ancestor
    # commit into a verified row.
    unrelated_pair = (
        f"Observed (NOT a lock): https://github.com/o/r/commit/{UNRECORDED}/x"
        f" ; the crate checksum {RFD_DIGEST}"
    )
    check(
        UNRECORDED in guard.recorded_upstream_pins(unrelated_pair),
        "the digest-belongs-to-another-artifact gap is still open; if this "
        "fails the predicate was tightened -- update the limit recorded in "
        "recorded_upstream_pins and on task row M8-C21",
    )

    the_status_predicate_is_exercised_in_both_directions()

    print("test_evidence_guard_pins: PASS")
    return 0


def the_status_predicate_is_exercised_in_both_directions() -> None:
    """`row_is_verified` and `status_column`, driven rather than inspected.

    **Why this exists (M6-C10, second round).**  The widened predicate reads a
    `Status` column located from the table's own header, and rejects cells
    that claim verification in a negated or in-progress form.  Measured
    against the real documents, the negation list excludes exactly **2** rows
    and every entry other than `in progress` excludes **none** -- the awaiting
    spellings in use say "verification", not "verified", so they never reach
    it.  A list that currently cannot fire is indistinguishable from one that
    is broken, and the repository already holds journal cells reading "not
    verified" that would be admitted the day such a cell appeared in a table
    with a `Status` column.  So the rule is driven here instead of being
    trusted because the suite is green.
    """
    header = "| ID | Task | Status | Owner | Acceptance or evidence | Completed at |"
    other = "| Milestone | Current state | Gate statement | Completed at |"
    journal = "| At | Item | Event | Evidence or scope |"
    check(guard.status_column(header) == 2, "the task table's Status column is index 2")
    # M4-40: the milestone and journal tables name their verdict column in
    # their own headers too, and that is the only cell read for them.
    check(guard.status_column(other) == 1, "the milestone table's verdict is `Current state`, index 1")
    check(guard.status_column(journal) == 2, "the journal table's verdict is `Event`, index 2")
    check(not guard.verdict_is_exact(header), "a `Status` column uses the substring rule")
    check(guard.verdict_is_exact(other), "`Current state` keeps the exact rule it had before M4-40")
    check(guard.verdict_is_exact(journal), "`Event` keeps the exact rule it had before M4-40")
    check(
        guard.status_column("| Key | Current source references | Narrow evidence |") is None,
        "a table whose header names no verdict column has none",
    )

    def status(cell: str) -> str:
        return f"| M0-00 | [x] a task | {cell} | owner | evidence | — |"

    for cell in ("verified local", "verified (local; with a parenthetical)",
                 "implemented (verified local)", "re-verified local",
                 "first verified local at declared scope"):
        check(
            guard.row_is_verified(status(cell), 2),
            f"a status claiming verification must be in scope: {cell!r}",
        )
    for cell in ("implemented awaiting verification", "in progress",
                 "in progress (exit codes verified local; the rest planned)",
                 "not verified", "unverified", "planned", "open"):
        check(
            not guard.row_is_verified(status(cell), 2),
            f"a status not claiming verification must stay out of scope: {cell!r}",
        )

    # --- M4-40: ONLY the verdict column sets scope ---------------------------
    # Before M4-40 any cell equal to "verified"/"verified local" put a row in
    # scope, so a `planned` row whose Owner or Evidence cell happened to read
    # exactly `verified` was judged as a verified row, and a row in a table
    # with no verdict column at all was in scope by its wording.  Each case
    # below is in scope under that fallback and must not be now.
    for label, row, index in (
        ("an Owner cell reading `verified`",
         "| M0-00 | [ ] a task | planned | verified | evidence | — |", 2),
        ("an Evidence cell reading `verified local`",
         "| M0-00 | [ ] a task | open | owner | verified local | — |", 2),
        ("a table with no verdict column",
         "| K-01 | verified | prose |", None),
        ("a milestone row whose Gate statement reads `verified`",
         "| M9 / thing | in progress | verified | — |", 1),
    ):
        check(
            not guard.row_is_verified(row, index, index == 1),
            f"M4-40: {label} must not put a row in scope; only the table's own "
            f"verdict column may (row {row!r})",
        )
    # The rows the fallback used to admit rightly are still admitted, through
    # their own verdict column, with the exact rule they always had.
    check(
        guard.row_is_verified("| M1 / tunnel | verified local | prose | — |", 1, True),
        "a milestone row whose `Current state` is exactly `verified local` stays in scope",
    )
    check(
        guard.row_is_verified(
            "| 2026-09-17T18:29:16+10:00 | M4-07 | verified local | evidence |", 2, True
        ),
        "a journal row whose `Event` is exactly `verified local` stays in scope",
    )
    check(
        not guard.row_is_verified(
            "| 2026-09-17T18:29:16+10:00 | M4-07 | first verified local | e |", 2, True
        ),
        "the journal keeps its exact rule: widening it is a separate, measured "
        "decision (EXACT_VERDICT_HEADERS), not a side effect of M4-40",
    )
    check(
        not guard.row_is_verified("| M1 / tunnel | in progress | prose | — |", 1, True),
        "a milestone row not claiming verification stays out of scope",
    )


if __name__ == "__main__":
    sys.exit(main())
