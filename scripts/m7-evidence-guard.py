#!/usr/bin/env python3
"""IN-11 mechanical evidence guard.

A synthetic route harness is evidence only for the rows it actually drives and
for the partial numbers it produced; it must never be promoted to broader
"verified" status by citing a gate that does not exist or a commit that is not
in this branch's history.

This guard is READ-ONLY over docs/m7-edge-cases.md and docs/tasks.md.  It never
writes, edits, or reformats them.  It fails (exit 1) when a row marked verified:

  1. cites a `verify-*` harness gate that is neither a command in
     crates/tunnel-test-harness/src/main.rs nor referenced by
     scripts/m7-harness-verify.sh, or
  2. cites a commit hash that git resolves to a real commit object which is not
     an ancestor of HEAD (evidence borrowed from an unmerged sibling commit), or
  3. cites a commit hash that git cannot resolve at all AND that
     docs/sources.md does not record as a pinned upstream artifact (M8-C21).

Hex tokens that git does not resolve to a commit are ignored: they are digests,
blob ids, log-file fragments or squashed short hashes, not a claim that "this
commit is in our history".  Gate tokens embedded inside a longer path or
filename (e.g. a `...-verify-m7-transport-fixed.log` log name) are ignored via a
left word boundary, so only real gate citations are checked.

The upstream-pin rule (M8-C21) is keyed on docs/sources.md and on nothing else.
An upstream artifact is not in this repository's history, so a row that pins one
can never satisfy rule 2 -- and refusing every such row would make a pin row
permanently unverifiable, which is a strange conclusion for a repository whose
M8-01 reads "Pin stable ACP v1...".  The exemption is therefore narrow and
mechanical: the cited short hash must be a prefix of a full 40-character hash
that docs/sources.md records beside a URL carrying that same hash (repository,
commit and path) and beside a labelled SHA-256 content digest.  Absent that
entry the citation is still a hard failure, so adding a pin costs a
`sources.md` record, which is strictly more than deleting a cue word.  The rule
is deliberately NOT keyed on any marker in docs/tasks.md: a marker in the
tracker would be a new cue word that can be added or deleted at will, which is
the deny-list failure recorded as M8-C08 merely inverted.  Both halves are
pinned in scripts/test_evidence_guard_pins.py, red fixture included.

Usage:
  python3 scripts/m7-evidence-guard.py [--verbose]

Exit codes: 0 clean, 1 findings, 2 usage/environment error.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_RS = os.path.join(REPO_ROOT, "crates", "tunnel-test-harness", "src", "main.rs")
HARNESS_VERIFY = os.path.join(REPO_ROOT, "scripts", "m7-harness-verify.sh")
SOURCES = os.path.join(REPO_ROOT, "docs", "sources.md")
DOCS = [
    os.path.join(REPO_ROOT, "docs", "m7-edge-cases.md"),
    os.path.join(REPO_ROOT, "docs", "tasks.md"),
]

# A harness gate citation.  The negative lookbehind keeps us from matching a
# `verify-*` fragment that is part of a longer identifier or filesystem path
# (a log filename such as ...runtime-verify-m7-transport-fixed.log), so only a
# real, standalone gate citation is considered.
GATE_RE = re.compile(r"(?<![A-Za-z0-9._/-])(verify-m[0-9][a-z0-9-]*)")
# A candidate commit hash: 7..40 hex chars containing at least one a-f letter so
# a plain decimal count is not mistaken for a hash.  64-char sha256 digests are
# excluded by the length bound.  Every candidate is still confirmed against git
# before it is treated as a commit citation.
HASH_RE = re.compile(r"(?<![0-9a-fA-Fx])([0-9a-f]{7,40})(?![0-9a-fA-F])")

# A hash written as an explicit commit citation: "integrated as 7f5be40",
# "fixed as d864dac", "commit `0687abf`". These must resolve AND be ancestors.
#
# The broader HASH_RE cannot carry that requirement: these documents also quote
# SPKI fingerprints, source digests and patch checksums, none of which are
# commit objects, so demanding that every hex token resolve would fail on
# evidence that is perfectly correct. Cue words are what distinguish a claim
# about this repository's history from a quoted digest.
#
# Known limit: a bare parenthesised hash with no cue word, "(5a2018e)", is
# still only checked when it resolves. Citations in this project are written
# with a cue in practice, and widening the rule would reintroduce the false
# positives above.
COMMIT_CITATION_RE = re.compile(
    r"\b(?:as|commit|commits)\s+`?([0-9a-f]{7,40})`?(?![0-9a-fA-F])", re.IGNORECASE
)

# --- the upstream-pin record in docs/sources.md (M8-C21) ---------------------
#
# A full vcs hash: exactly 40 hex characters.  A short form is never accepted
# in sources.md; the record must name the artifact unambiguously, and the row's
# short citation is matched against it by prefix.
PIN_HASH_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-f]{40})(?![0-9a-fA-F])")
# A content digest: exactly 64 hex characters (a SHA-256).
PIN_DIGEST_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{64}(?![0-9a-fA-F])")
# The digest must be labelled, so an unexplained 64-hex blob cannot stand in
# for "we hashed the artifact".  crates.io checksums are SHA-256 of the
# published .crate and are written in sources.md as "checksum".
# The label must be ADJACENT to the digest, not merely somewhere on the line.
# Review constructed the false positives that forced this: a line reading "No
# checksum was recorded for <url>; the log id <64hex> is unrelated" satisfied a
# line-wide label search, and so did a digest belonging to a different artifact
# mentioned in the same sentence.  A pin must be one record, not three facts
# that happen to share a line.
# "SHA-256 of that file `<digest>`" is the shape sources.md actually uses, so
# the bridge between label and digest may contain words -- but it is bounded,
# and it may not skip over another digest to reach a later one.
PIN_LABELLED_DIGEST_RE = re.compile(
    r"(?:sha-?256|checksum)"
    r"(?:(?!(?<![0-9a-fA-F])[0-9a-f]{64}(?![0-9a-fA-F])).){0,48}?"
    r"(?<![0-9a-fA-F])[0-9a-f]{64}(?![0-9a-fA-F])",
    re.IGNORECASE,
)
# The hash must be a PATH SEGMENT of an https blob/tree/commit URL, not a
# substring of any URL anywhere on the line.  Review showed the looser form
# pins an unrelated commit named in passing, pins both ends of a /compare/A...B
# link, and accepts `https://example.org/?q=<hash>` with no repository at all.
# Every genuine record in sources.md is already of this shape.
PIN_URL_HASH_RE = re.compile(
    r"https://[^\s<>()\[\]`]*?/(?:blob|tree|commit|commits)/(?<![0-9a-fA-F])([0-9a-f]{40})(?![0-9a-fA-F])"
)


def recorded_upstream_pins(sources_text: str) -> "set[str]":
    """Full 40-character hashes docs/sources.md records as pinned artifacts.

    All three must appear on the same line of sources.md, which is one record:

      * the full 40-character hash,
      * a URL that itself contains that hash -- this is what makes the record
        name a repository, a commit and a path rather than a bare number, and
      * a labelled SHA-256 content digest (64 hex characters).

    An entry missing the URL or missing the digest records less than the rule
    requires and yields no pin, so the citation that depends on it fails.

    The hash must be a path segment of an https blob/tree/commit URL, and the
    digest must be label-adjacent, because review constructed false positives
    against the looser forms: an unrelated commit named in passing, both ends
    of a /compare/A...B link, an `http://` URL, `https://example.org/?q=<hash>`
    with no repository at all, and a line whose only "checksum" was a negation.

    What this CANNOT check, recorded rather than papered over.  A line that
    names one commit in a blob/tree/commit URL and a labelled digest of some
    *other* artifact satisfies every structural condition, and no regex can
    tell the two apart -- review constructed exactly that case.  The four
    remaining defences are: sources.md is small and reviewed; the exemption is
    reachable only for a hash git cannot resolve, so it can never launder a
    non-ancestor commit into a verified row; a wrong pin exempts a citation
    that is still counted and printed; and the self-test pins the shapes that
    are rejected.  A tighter rule would need sources.md to carry one record per
    line in a fixed form, which is a documentation change, not a guard change.
    """
    pins: "set[str]" = set()
    for line in sources_text.splitlines():
        if not PIN_LABELLED_DIGEST_RE.search(line):
            continue
        for match in PIN_URL_HASH_RE.finditer(line):
            pins.add(match.group(1))
    return pins


def is_recorded_pin(token: str, pins: "set[str]") -> bool:
    """True when the cited short hash is a prefix of a recorded full pin."""
    lowered = token.lower()
    return any(pin.startswith(lowered) for pin in pins)


def die(message: str) -> "None":
    sys.stderr.write(f"m7-evidence-guard: {message}\n")
    raise SystemExit(2)


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as error:
        die(f"cannot read {path}: {error}")


def known_gates() -> "set[str]":
    gates: "set[str]" = set()
    main_src = read_text(MAIN_RS)
    for match in re.finditer(r'command == "(verify-[a-z0-9-]+)"', main_src):
        gates.add(match.group(1))
    verify_src = read_text(HARNESS_VERIFY)
    for match in re.finditer(r"(?<![A-Za-z0-9._/-])(verify-m[0-9][a-z0-9-]*)", verify_src):
        gates.add(match.group(1))
    if not gates:
        die("found no known harness gates; the sources may have moved")
    return gates


def git(*args: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        ["git", "-C", REPO_ROOT, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


_commit_cache: "dict[str, bool | None]" = {}


def commit_ancestry(token: str) -> "bool | None":
    """Return True if token is a commit ancestor of HEAD, False if it is a real
    commit but NOT an ancestor, or None if git does not resolve it to a commit."""
    if token in _commit_cache:
        return _commit_cache[token]
    resolved = git("rev-parse", "--verify", "--quiet", f"{token}^{{commit}}")
    if resolved.returncode != 0 or not resolved.stdout.strip():
        _commit_cache[token] = None
        return None
    is_ancestor = git("merge-base", "--is-ancestor", token, "HEAD")
    verdict = is_ancestor.returncode == 0
    _commit_cache[token] = verdict
    return verdict


def is_table_row(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("|") and stripped.count("|") >= 4


def is_separator(line: str) -> bool:
    return bool(re.match(r"^\s*\|[\s:|-]+\|?\s*$", line))


# --- table shape (M4-33) -----------------------------------------------------
#
# THE CELL BOUNDARY RULE, STATED ONCE AND USED BY EVERYTHING BELOW.
#
# A cell boundary is a `|` character that is NOT immediately preceded by a
# backslash.  That is GFM's rule and it has two consequences that matter here:
#
#   * a `|` inside an inline code span is STILL a boundary.  Backticks do not
#     protect it.  This is the entire defect M4-33 records: a row writing
#     `git ls-tree -r HEAD | wc -l` renders one column wider than its table.
#   * `\|` is NOT a boundary, which is why one backslash is the whole fix.
#
# Note what this rule does NOT claim: it is not a general markdown parser.  It
# does not handle a literal backslash before a real delimiter (`...\\|`), which
# does not occur in these documents and would be a defect if it did.  It is
# deliberately the narrow rule that decides cell counts, and nothing more.


def split_cells(line: str) -> "list[str]":
    """Split one markdown table row into its cells.

    Boundaries are `|` not preceded by a backslash.  One leading and one
    trailing boundary pipe are row delimiters and are removed before splitting,
    so `| a | b |` is two cells and not four.
    """
    stripped = line.strip()
    bounds = [
        i
        for i, ch in enumerate(stripped)
        if ch == "|" and (i == 0 or stripped[i - 1] != "\\")
    ]
    if not bounds:
        return [stripped]
    start = 0
    end = len(stripped)
    if bounds[0] == 0:
        start = 1
        bounds = bounds[1:]
    if bounds and bounds[-1] == end - 1:
        end -= 1
        bounds = bounds[:-1]
    cells: "list[str]" = []
    prev = start
    for i in bounds:
        cells.append(stripped[prev:i])
        prev = i + 1
    cells.append(stripped[prev:end])
    return [cell.strip() for cell in cells]


def row_identifier(cells: "list[str]") -> str:
    """The row's own name, for a finding a reader can act on.

    A bare line number is not actionable in a 800-line tracker that is edited
    by several workers at once; the row id is what the reader searches for.
    """
    if not cells:
        return "?"
    first = cells[0].strip()
    match = re.match(r"^\**\[?[ xX]?\]?\**\s*([A-Za-z0-9][A-Za-z0-9.-]*)", first)
    return match.group(1) if match else (first[:24] or "?")


# The one section where a run of table rows with no separator is NOT reported.
#
# docs/tasks.md's completion history is an append-only log that has been written
# in TWO formats: 305 pipe-delimited rows and 39 markdown bullets, interleaved.
# Each bullet ends the table above it, so most of that section's rows are
# orphans.  It is a real defect and it is recorded as M4-41 -- it is exempted
# here rather than swept because converting a bullet into a row means inventing
# its Item and Event cells, and a guard that invented evidence would be a
# stranger defect than the one it fixed.
#
# The exemption is one named section, it is COUNTED, and the count is printed on
# every verbose run, because an exemption nobody measures is how a guard's scope
# quietly becomes nothing.  scripts/test_table_shape.py pins the count so the
# section cannot grow new orphans unnoticed.
EXEMPT_SECTION = "Completion history"


def table_shape_findings(
    rel: str, text: str
) -> "tuple[list[str], int, int, int]":
    """Findings for rows whose cell count differs from their table's header.

    Returns (findings, tables_seen, rows_checked, exempt_rows).

    The authority for a table's width is its OWN separator row (`|---|---|...`),
    which is what a markdown renderer uses and what the header therefore
    declares.  Each table is judged against its own separator, so the 4-column
    milestone summary and the 6-column task tables coexist without either being
    measured against the other -- the mistake that produced the 23-row figure
    M4-33 records as wrong.

    Every data row is checked, not only verified ones.  Eleven of the thirteen
    rows this rule was written for are `open` or `implemented`; a rule scoped to
    verified rows would have reported almost none of them.
    """
    findings: "list[str]" = []
    tables_seen = 0
    rows_checked = 0
    exempt_rows = 0

    # Work in BLOCKS of consecutive pipe-leading lines rather than streaming
    # line by line and carrying a `declared` width across gaps.
    #
    # Why: a blank line inside a table ends that table.  The next pipe-leading
    # line begins a NEW block, and a block with no separator on its second line
    # is not a table at all -- a renderer lays it out as a paragraph of
    # pipe-delimited text.  A streaming walk skips those rows (there is no
    # width to judge them against) and reports nothing, so a table sliced in
    # half by a stray blank line reads as clean.  That was true of this very
    # function when it was first written: three blank lines inside the M4 table
    # in docs/tasks.md hid 29 rows from it, and the only reason it was noticed
    # is that adding a row to that table did not move the scanned-row figure.
    # Rows no separator governs are now a finding, not a silence.
    blocks: "list[tuple[str, list[tuple[int, str]]]]" = []
    current: "list[tuple[int, str]]" = []
    section = ""
    block_section = ""
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("|"):
            if not current:
                block_section = section
            current.append((lineno, line))
            continue
        if current:
            blocks.append((block_section, current))
            current = []
        if line.startswith("#"):
            section = line.lstrip("#").strip()
    if current:
        blocks.append((block_section, current))

    for block_section, block in blocks:
        header_line, header = block[0]
        if len(block) >= 2 and is_separator(block[1][1]):
            declared = len(split_cells(block[1][1]))
            tables_seen += 1
            header_cells = len(split_cells(header))
            if header_cells != declared:
                findings.append(
                    f"{rel}:{header_line}: the header row has {header_cells} "
                    f"cells but its separator declares {declared}"
                )
            body = block[2:]
        else:
            # No separator: a renderer does not see a table here.
            declared = None
            body = block
        for lineno, line in body:
            cells = split_cells(line)
            rows_checked += 1
            if declared is None and block_section == EXEMPT_SECTION:
                # Counted, never silent, never fatal.  See EXEMPT_SECTION.
                exempt_rows += 1
            elif declared is None:
                findings.append(
                    f"{rel}:{lineno}: row '{row_identifier(cells)}' is not "
                    f"governed by any header/separator -- the run of table rows "
                    f"starting at {rel}:{header_line} has no '|---|' separator "
                    f"row, so a markdown renderer lays these out as a paragraph "
                    f"of pipe-delimited text and not as a table. A blank line "
                    f"inside a table is the usual cause."
                )
            elif len(cells) != declared:
                findings.append(
                    f"{rel}:{lineno}: row '{row_identifier(cells)}' splits into "
                    f"{len(cells)} cells but its table (header at {rel}:{header_line}) "
                    f"declares {declared}; an unescaped '|' -- often inside an inline "
                    f"code span, where backticks do NOT protect it -- adds a column. "
                    f"Write it as '\\|'."
                )
    return findings, tables_seen, rows_checked, exempt_rows


def row_is_verified(line: str) -> bool:
    """A row is verified only when its status *column* says so.

    In docs/tasks.md the `[x]` checkbox only means the task item is checked; the
    authoritative signal is the third data column (e.g. "verified local" versus
    "implemented awaiting verification" or "in progress").  In
    docs/m7-edge-cases.md the status column is a bare "Verified"/"Verified local"
    cell.  Matching a status cell (not a prose mention of the word) keeps
    awaiting-verification rows out of scope.
    """
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    for cell in cells:
        lowered = cell.lower()
        if lowered in ("verified", "verified local"):
            return True
    return False


def row_findings(
    rel: str,
    lineno: int,
    line: str,
    gates: "set[str]",
    pins: "set[str]",
    ancestry,
) -> "tuple[list[str], int, int, int]":
    """Findings for one verified row, plus (gate, commit, upstream-pin) counts.

    `ancestry` is the token -> True/False/None resolver, injected so the rule
    can be exercised against fixtures without inventing git objects.
    """
    findings: "list[str]" = []
    gate_citations = 0
    hash_citations = 0
    pin_citations = 0
    for match in GATE_RE.finditer(line):
        token = match.group(1)
        gate_citations += 1
        if token not in gates:
            findings.append(
                f"{rel}:{lineno}: verified row cites unknown harness gate "
                f"'{token}' (not a main.rs command nor in m7-harness-verify.sh)"
            )
    cited_as_commit = {
        match.group(1).lower() for match in COMMIT_CITATION_RE.finditer(line)
    }
    for match in HASH_RE.finditer(line):
        token = match.group(1)
        verdict = ancestry(token)
        if verdict is None:
            if token.lower() in cited_as_commit:
                # Written as a commit citation but git cannot resolve it.
                # Either it is an upstream artifact this repository pins and
                # records in docs/sources.md, which is legitimate evidence
                # (M8-C21), or it is a promotion resting on a worker's own SHA
                # after its worktree was removed, or on a branch that was
                # squashed away: evidence that reads as history but is not in
                # it.  Only the sources.md record separates the two.
                if is_recorded_pin(token, pins):
                    pin_citations += 1
                    continue
                hash_citations += 1
                findings.append(
                    f"{rel}:{lineno}: verified row cites commit '{token}' "
                    f"which git cannot resolve to any commit, and docs/sources.md "
                    f"records no pinned upstream artifact with that hash (a pin "
                    f"needs the full 40-character hash in a URL beside a labelled "
                    f"SHA-256 digest)"
                )
            continue  # otherwise a digest or fingerprint, not a history claim
        hash_citations += 1
        if verdict is False:
            # A hash git DOES resolve is a claim about this repository's
            # history and is judged as one.  Being listed in sources.md does
            # not launder a non-ancestor local commit.
            findings.append(
                f"{rel}:{lineno}: verified row cites commit '{token}' which is "
                f"a real commit but NOT an ancestor of HEAD"
            )
    return findings, gate_citations, hash_citations, pin_citations


def scan(gates: "set[str]", pins: "set[str]", verbose: bool) -> "list[str]":
    findings: "list[str]" = []
    rows_scanned = 0
    gate_citations = 0
    hash_citations = 0
    pin_citations = 0
    tables_seen = 0
    shape_rows = 0
    shape_findings = 0
    exempt_rows = 0
    for path in DOCS:
        rel = os.path.relpath(path, REPO_ROOT)
        text = read_text(path)
        shape, tables_n, shape_n, exempt_n = table_shape_findings(rel, text)
        findings.extend(shape)
        shape_findings += len(shape)
        tables_seen += tables_n
        shape_rows += shape_n
        exempt_rows += exempt_n
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not is_table_row(line) or is_separator(line):
                continue
            if not row_is_verified(line):
                continue
            rows_scanned += 1
            row, gate_n, hash_n, pin_n = row_findings(
                rel, lineno, line, gates, pins, commit_ancestry
            )
            findings.extend(row)
            gate_citations += gate_n
            hash_citations += hash_n
            pin_citations += pin_n
    # A scan that matched nothing is not a pass.  If the tables move, are
    # renamed or lose their separator rows, every rule in this guard silently
    # stops applying while the exit code stays 0 -- the failure mode M5-C11
    # collects.  Both scopes must have found work to do.
    if tables_seen == 0 or shape_rows == 0:
        die(
            f"table-shape scan matched nothing ({tables_seen} tables, "
            f"{shape_rows} rows) across {len(DOCS)} documents; the tables have "
            f"moved or their separator rows are gone, and the guard is not "
            f"guarding"
        )
    if rows_scanned == 0:
        die(
            "no verified rows matched across "
            f"{len(DOCS)} documents; the status wording changed and the "
            "gate/commit rules are silently inapplicable"
        )
    if verbose:
        sys.stderr.write(
            f"m7-evidence-guard: scanned {rows_scanned} verified rows, "
            f"{gate_citations} gate citations, {hash_citations} confirmed commit "
            f"citations, {pin_citations} upstream-pin citations; "
            f"{len(gates)} known gates, {len(pins)} recorded upstream pins; "
            f"table shape: {shape_rows} rows in {tables_seen} tables checked, "
            f"{shape_findings} findings, {exempt_rows} rows exempt "
            f"(the '{EXEMPT_SECTION}' log, M4-41)\n"
        )
    return findings


def main(argv: "list[str]") -> int:
    verbose = "--verbose" in argv[1:] or "-v" in argv[1:]
    unknown = [a for a in argv[1:] if a not in ("--verbose", "-v")]
    if unknown:
        die(f"unknown argument(s): {' '.join(unknown)}")
    if git("rev-parse", "--git-dir").returncode != 0:
        die("not a git repository")
    gates = known_gates()
    pins = recorded_upstream_pins(read_text(SOURCES))
    findings = scan(gates, pins, verbose)
    if findings:
        sys.stderr.write("m7-evidence-guard: FAIL\n")
        for finding in findings:
            sys.stderr.write(f"  {finding}\n")
        return 1
    sys.stderr.write(
        "m7-evidence-guard: PASS (no unverified-gate, non-ancestor-commit or "
        "unrecorded-upstream-pin promotions)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
