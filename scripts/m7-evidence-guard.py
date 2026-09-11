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
     an ancestor of HEAD (evidence borrowed from an unmerged sibling commit).

Hex tokens that git does not resolve to a commit are ignored: they are digests,
blob ids, log-file fragments or squashed short hashes, not a claim that "this
commit is in our history".  Gate tokens embedded inside a longer path or
filename (e.g. a `...-verify-m7-transport-fixed.log` log name) are ignored via a
left word boundary, so only real gate citations are checked.

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


def scan(gates: "set[str]", verbose: bool) -> "list[str]":
    findings: "list[str]" = []
    rows_scanned = 0
    gate_citations = 0
    hash_citations = 0
    for path in DOCS:
        rel = os.path.relpath(path, REPO_ROOT)
        text = read_text(path)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not is_table_row(line) or is_separator(line):
                continue
            if not row_is_verified(line):
                continue
            rows_scanned += 1
            for match in GATE_RE.finditer(line):
                token = match.group(1)
                gate_citations += 1
                if token not in gates:
                    findings.append(
                        f"{rel}:{lineno}: verified row cites unknown harness gate "
                        f"'{token}' (not a main.rs command nor in m7-harness-verify.sh)"
                    )
            for match in HASH_RE.finditer(line):
                token = match.group(1)
                verdict = commit_ancestry(token)
                if verdict is None:
                    continue  # not a real commit object; not a history claim
                hash_citations += 1
                if verdict is False:
                    findings.append(
                        f"{rel}:{lineno}: verified row cites commit '{token}' which is "
                        f"a real commit but NOT an ancestor of HEAD"
                    )
    if verbose:
        sys.stderr.write(
            f"m7-evidence-guard: scanned {rows_scanned} verified rows, "
            f"{gate_citations} gate citations, {hash_citations} confirmed commit "
            f"citations; {len(gates)} known gates\n"
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
    findings = scan(gates, verbose)
    if findings:
        sys.stderr.write("m7-evidence-guard: FAIL\n")
        for finding in findings:
            sys.stderr.write(f"  {finding}\n")
        return 1
    sys.stderr.write("m7-evidence-guard: PASS (no unverified-gate or non-ancestor-commit promotions)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
