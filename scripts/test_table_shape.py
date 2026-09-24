#!/usr/bin/env python3
"""Tests for the table cell-count rule in scripts/m7-evidence-guard.py (M4-33).

The rule fails a row whose cell count differs from the count its table's own
separator row declares.  M4-33 asked for it in those words: thirteen rows had
drifted, and the fourteenth was created *while the thirteen were being fixed*,
which is the argument for an assertion rather than a sweep.

WHY THE RED FIXTURES ARE THE POINT.  A cell-count rule that silently stopped
matching -- because the tables moved, because `is_separator` changed, because
`split_cells` started treating a code-span pipe as protected -- would leave
this file, m7-evidence-guard.py and every harness green while nothing was
checked.  That fail-open is the class M5-C11 collects.  So every case here that
matters is a case that MUST be reported, and the green fixtures are pinned
against the REAL docs, not against a copy, so hollowing the docs out turns this
red rather than leaving a stale duplicate passing in here.

    python3 scripts/test_table_shape.py

Exit codes: 0 pass, non-zero on the first failed case.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS.parent

_spec = importlib.util.spec_from_file_location(
    "m7_evidence_guard", SCRIPTS / "m7-evidence-guard.py"
)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)  # type: ignore[union-attr]


def check(condition: bool, message: str) -> None:
    if not condition:
        sys.exit(f"test_table_shape: {message}")


# The real header and separator of the M5 task table, used as the known row the
# boundary rule is proved against.  If these stop being 6 cells the docs were
# restructured and the figures below are stale -- which is the point.
HEADER = "| ID | Task | Status | Owner | Acceptance or evidence | Completed at |"
SEPARATOR = "|---|---|---|---|---|---|"


def main() -> int:
    # --- the boundary rule, proved on a known row ---------------------------
    check(
        guard.split_cells(HEADER)
        == ["ID", "Task", "Status", "Owner", "Acceptance or evidence", "Completed at"],
        f"the real 6-column header must split into exactly those 6 cells, got "
        f"{guard.split_cells(HEADER)}",
    )
    check(
        len(guard.split_cells(SEPARATOR)) == 6,
        "the separator declares the width and must itself be 6 cells, got "
        f"{len(guard.split_cells(SEPARATOR))}",
    )
    check(
        guard.split_cells("| a | b |") == ["a", "b"],
        "the leading and trailing pipes are row delimiters, not empty cells",
    )

    # --- the two facts the whole rule rests on ------------------------------
    # 1. `\|` is NOT a boundary.  This is why one backslash is the fix.
    check(
        guard.split_cells(r"| a \| b | c |") == [r"a \| b", "c"],
        "an escaped pipe must not split a cell; if it does, the documented fix "
        "for this defect does not work",
    )
    # 2. A pipe inside an inline code span IS a boundary.  Backticks do not
    #    protect it.  This is the defect itself, and a "fix" that made
    #    split_cells honour backticks would make the guard agree with a
    #    renderer that does not exist.
    check(
        guard.split_cells("| a `x | y` b | c |") == ["a `x", "y` b", "c"],
        "a pipe inside backticks must still split the row: GFM does not protect "
        "it, and the guard must see what the renderer sees",
    )

    # --- the red fixture: a planted stray pipe must be reported -------------
    body = "\n".join(
        [
            HEADER,
            SEPARATOR,
            "| M5-C13 | [ ] A task. | planned | a worker | prose `a | b` more | — |",
        ]
    )
    findings, tables, rows = guard.table_shape_findings("docs/tasks.md", body)
    check(len(findings) == 1, f"the planted stray pipe must be one finding, got {findings}")
    check(tables == 1 and rows == 1, f"one table and one row must be seen, got {tables}/{rows}")
    check(
        "M5-C13" in findings[0],
        f"the finding must name the ROW, not only a line number: {findings[0]}",
    )
    check(
        "docs/tasks.md:3" in findings[0],
        f"the finding must name the file and line: {findings[0]}",
    )
    check(
        "7 cells" in findings[0] and "declares 6" in findings[0],
        f"the finding must state both counts it compared: {findings[0]}",
    )

    # The same row with the pipe escaped is the green half of red-then-green.
    fixed = body.replace("`a | b`", r"`a \| b`")
    findings, _t, _r = guard.table_shape_findings("docs/tasks.md", fixed)
    check(findings == [], f"one backslash must clear the finding, got {findings}")

    # --- a blank line inside a table must NOT hide the rows below it --------
    # This is the defect the rule itself shipped with.  A streaming walk that
    # carries the declared width across a gap has no width for the rows after
    # the blank line and skips them in silence: three blank lines in the M4
    # table hid 29 rows, and adding a row to that table did not move the
    # scanned-row figure, which is the only reason it was caught.  A row no
    # separator governs is a finding now, and it is COUNTED as a row.
    split_table = "\n".join(
        [
            HEADER,
            SEPARATOR,
            "| M4-13 | [x] A task. | verified local | a worker | prose | — |",
            "",
            "| M4-14 | [x] A task with a stray | pipe. | verified local | a worker | p | — |",
        ]
    )
    findings, tables, rows = guard.table_shape_findings("docs/tasks.md", split_table)
    check(
        rows == 2,
        f"a row orphaned by a blank line must still be COUNTED as scanned; "
        f"got {rows} rows, so {2 - rows} row(s) were skipped in silence",
    )
    check(
        len(findings) == 1 and "not governed by any header/separator" in findings[0],
        f"the orphaned row must be reported, not skipped: {findings}",
    )
    check(
        "M4-14" in findings[0] and "blank line" in findings[0],
        f"the finding must name the row and the usual cause: {findings[0]}",
    )
    # Rejoining the table brings the row back under the separator, and its
    # stray pipe then becomes visible as the cell-count defect it is.
    rejoined = split_table.replace("\n\n", "\n")
    findings, _t, rows = guard.table_shape_findings("docs/tasks.md", rejoined)
    check(
        rows == 2 and len(findings) == 1 and "splits into 7 cells" in findings[0],
        f"once rejoined, the row's stray pipe must be reported as a cell-count "
        f"defect: {rows} rows, {findings}",
    )

    # --- a header that disagrees with its own separator ---------------------
    findings, _t, _r = guard.table_shape_findings(
        "docs/tasks.md", "| A | B | C |\n|---|---|\n| 1 | 2 |\n"
    )
    check(
        any("header row has 3 cells" in f for f in findings),
        f"a header wider than its separator must be reported: {findings}",
    )

    # --- each table is judged against its OWN separator ---------------------
    # Measuring every table against one width is the mistake that produced the
    # 23-row figure M4-33 records as wrong: the 4-column milestone summary is
    # not a defect merely for being narrower than the task tables.
    mixed = "\n".join(
        [
            "| Milestone | Current state | Gate statement | Completed at |",
            "|---|---|---|---|",
            "| M0 | implemented | a gate | — |",
            "",
            HEADER,
            SEPARATOR,
            "| M5-01 | [ ] A task. | planned | a worker | prose | — |",
        ]
    )
    findings, tables, rows = guard.table_shape_findings("docs/tasks.md", mixed)
    check(
        findings == [] and tables == 2 and rows == 2,
        f"a 4-column table beside a 6-column one is not a defect, got "
        f"{findings} over {tables} tables / {rows} rows",
    )

    # --- the green fixture: the REAL docs, pinned ---------------------------
    total_rows = 0
    total_tables = 0
    for rel in ("docs/m7-edge-cases.md", "docs/tasks.md"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        findings, tables, rows = guard.table_shape_findings(rel, text)
        check(
            findings == [],
            f"{rel} has rows whose cell count contradicts their table: {findings}",
        )
        total_tables += tables
        total_rows += rows
    # A floor, not an equality: rows are added constantly and an equality here
    # would be a tripwire on ordinary work.  A floor still catches the failure
    # that matters, which is the scan quietly matching far less than it did.
    # Raised from 690 by M4-41, which brought the completion history's 39
    # bullet entries into the table: 940 rows in 27 tables when it landed.
    check(
        total_rows >= 900 and total_tables >= 25,
        f"the shape scan now covers {total_rows} rows in {total_tables} tables, "
        f"far below the 940/27 measured when M4-41 landed; the tables have "
        f"moved or the walk stopped finding them",
    )

    # --- there is NO exempt section (M4-41) ---------------------------------
    # The `Completion history` log was exempted by name while it was written in
    # two formats at once; up to 300 of its rows were orphans no rule examined.
    # M4-41 made it one table and deleted the exemption.  This fixture is the
    # red half: an orphan run INSIDE that very section must fail exactly as it
    # does anywhere else, and the finding must be the orphan finding -- not
    # some other refusal that happens to fire on the same text.
    history_orphans = "\n".join(
        [
            "## Completion history",
            "",
            "| At | Item | Event | Evidence or scope |",
            "|---|---|---|---|",
            "| 2026-09-10T08:00:00+10:00 | M7-C01 | first verified local | e |",
            "",
            "- 2026-09-10T12:28:09+10:00: a bullet entry ends the table above.",
            "| 2026-09-10T12:30:00+10:00 | M7-C02 | reopened | e |",
            "| 2026-09-10T12:31:00+10:00 | M7-C03 | reopened | e |",
        ]
    )
    findings, _t, rows = guard.table_shape_findings("docs/tasks.md", history_orphans)
    check(
        rows == 3,
        f"all three history rows must be counted, got {rows}",
    )
    check(
        len(findings) == 2
        and all("is not governed by any header/separator" in f for f in findings)
        and findings[0].startswith("docs/tasks.md:8:")
        and findings[1].startswith("docs/tasks.md:9:"),
        f"orphan rows in the '## Completion history' section must each fail "
        f"with the orphan finding, not be exempted: {findings}",
    )
    check(
        not hasattr(guard, "EXEMPT_SECTION"),
        "EXEMPT_SECTION is back; M4-41 deleted it rather than leave a rule "
        "applying to nothing",
    )
    # And the tracker's real history is one well-formed table: every row sits
    # under the single `At | Item | Event` header.
    tasks = (REPO_ROOT / "docs/tasks.md").read_text(encoding="utf-8")
    history = tasks[tasks.index("## Completion history"):]
    check(
        history.count("| At | Item | Event | Evidence or scope |") == 1
        and "\n- 20" not in history,
        "the completion history must be ONE table with no bullet entries; a "
        "second header or a bullet splits it into fragments again (M4-41)",
    )

    # --- the status-column split must be split_cells, not a bare split -----
    #
    # M4-40, half discharged.  `status_column` and `row_is_verified` take a
    # Status index from the header and read that cell.  With a bare-pipe split
    # an escaped pipe ANYWHERE LEFT OF the Status column shifts every later
    # index, so the predicate reads a fragment of Task prose and calls it a
    # status.  On the real M4-33 row the naive split gives 18 cells and index 2
    # lands mid-sentence.
    #
    # This was invisible in every outcome: the exact-match `or` fallback still
    # found a bare `verified local` among the fragments, so the guard's verdict
    # was right for the wrong reason on that row.  A test written against the
    # verdict would pass with the defect present, which is why this one asserts
    # the SELECTED CELL.
    escaped = (
        r"| M4-33 | [x] Rows carry an unescaped `\|` in their cell. "
        r"| verified local | tooling | prose | — |"
    )
    index = guard.status_column(HEADER)
    check(index == 2, f"the Status column of the real header is index 2, got {index}")
    check(
        guard.split_cells(escaped)[index] == "verified local",
        f"index {index} must select the Status cell, got "
        f"{guard.split_cells(escaped)[index]!r}",
    )
    naive = [c.strip() for c in escaped.strip().strip("|").split("|")]
    check(
        naive[index] != "verified local",
        "this fixture is supposed to DEMONSTRATE the naive split going wrong; "
        "if a bare split now selects the right cell the fixture has lost its "
        "escaped pipe and is no longer testing anything",
    )
    # And the predicate itself must read that cell, with the exact-match
    # fallback removed from the picture so it cannot mask the result.
    saved_claims = guard.NOT_A_VERIFIED_CLAIM
    try:
        masked = escaped.replace("| verified local |", "| implemented (verified local) |")
        check(
            guard.row_is_verified(masked, index),
            "the Status cell says 'implemented (verified local)', which no "
            "exact match can reach, so this passes only if the index selected "
            "the right cell -- it is the fallback-free form of the case above",
        )
    finally:
        guard.NOT_A_VERIFIED_CLAIM = saved_claims

    # --- a scan that matches nothing must be FATAL, not a pass --------------
    # The adjective tell: ask which line fails if the scan found no tables at
    # all.  Before this, none did -- the guard printed PASS.
    #
    # There are THREE fatal conditions and each gets its own fixture.  Review
    # caught one red case standing for all three, which would have left the
    # zero-verified-rows `die` with nothing that could turn it red: a fatality
    # nobody can trigger is the same fail-open one level in.
    #
    # The second fixture is the load-bearing one.  Its table is well-formed and
    # full of rows -- it is only the *status wording* that matches nothing, so
    # the shape rules are perfectly happy and the gate and ancestry rules apply
    # to zero rows.  That is exactly the shape of the silent failure: a guard
    # that still prints its verbose line, still reports tables and rows, and
    # has quietly stopped checking any evidence at all.
    fatal_fixtures = {
        "no tables at all": "# A document with prose and no tables at all.\n",
        "tables and rows, but NO verified row": (
            HEADER
            + "\n"
            + SEPARATOR
            + "\n| M5-C13 | [ ] A task. | planned | a worker | prose | — |\n"
            + "| M5-C14 | [ ] Another. | in progress | a worker | prose | — |\n"
        ),
    }
    for label, body in fatal_fixtures.items():
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.md"
            fixture.write_text(body, encoding="utf-8")
            saved = guard.DOCS
            guard.DOCS = [str(fixture)]
            try:
                guard.scan(set(), set(), False)
            except SystemExit as exit_code:
                check(
                    exit_code.code == 2,
                    f"the '{label}' scan must exit 2 (environment error), got "
                    f"{exit_code.code}",
                )
            else:
                sys.exit(
                    f"test_table_shape: the '{label}' scan returned normally; a "
                    f"check whose success and whose non-execution look identical "
                    f"is not evidence"
                )
            finally:
                guard.DOCS = saved

    print(
        f"test_table_shape: PASS ({total_rows} rows in {total_tables} tables "
        f"checked in the real docs; 0 exempt)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
