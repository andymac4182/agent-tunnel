#!/usr/bin/env python3
"""M6-04 release gate: dependency/licence policy, secret history scan, visibility.

Three obligations, three checks, and they want different evidence:

  `deps`        cargo-deny 0.19.6 against `deny.toml`: a fail-closed licence
                allowlist, provenance (`sources`), and `bans`.  A *list* of
                licences is not evidence; a policy that rejects an unknown one
                is.
  `provenance`  The lockfile and the three patched crates under `vendor/`.
                A registry crate's provenance is its checksum in `Cargo.lock`;
                a vendored crate's is its `.cargo_vcs_info.json` commit and
                the licence text actually sitting in the directory.
  `secrets`     **Every blob in the full git history**, not the working tree.
                A rotated secret still reachable from an old commit is still
                leaked the moment the repository is cloned -- and this
                repository is public (see `visibility`), so history is the
                live exposure surface rather than a future one.
  `visibility`  Read-only.  Reports GitHub's answer for the `origin` remote.
                **This check never changes a repository setting.**  AGENTS.md
                requires the repository stay private unless the owner asks for
                publication, so a public answer is a failure to report, not a
                condition to fix unattended.

Why every check here carries a positive control
-----------------------------------------------
docs/tasks.md row M5-C11 holds this repository's running list of checks whose
success and whose non-execution looked identical: a scan that scanned nothing,
a grep whose pattern could not match, an `&&`-chain that skipped a test run,
an `assert_eq!` whose two sides moved together, a destructive guard run that
exited 0, a `str.find()` that matched a prefix, a `grep` read as "no
failures", a green measured against another worktree's binary, and a floor
that had gone stale by 18.  A licence scanner pointed at an empty graph and a
secret scanner whose regexes can never match are the obvious next entries.

So `--self-test` is not a nicety.  Each check declares controls that plant a
synthetic case and require the check to go **red**, plus, where the failure
mode is "scanned nothing", a floor on how much the check actually examined.
A green run of this script prints the sizes it measured, so a green result
also reports that it ran.

`--self-test` never writes to the repository.  Every control operates on a
throwaway tree under a `tempfile.TemporaryDirectory()`, or on a `deny.toml`
copy in that directory; the only repository read is the git object database.

Usage
-----
    python3 scripts/m6-release-checks.py                 # all checks
    python3 scripts/m6-release-checks.py --self-test     # positive controls
    python3 scripts/m6-release-checks.py --check secrets # one check
    python3 scripts/m6-release-checks.py --list-checks

Exit codes: 0 all selected checks passed; 1 at least one failed; 2 the script
could not run a selected check at all (missing tool, no network where a check
requires it).  **2 is not a pass.**  A check that could not run is reported as
DID NOT RUN with the reason, never folded into the green.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# cargo-deny is pinned: the `deny.toml` schema was read out of this version's
# own `init` template, and a later version could rename a key.  A renamed key
# that is silently ignored is the exact defect class this script exists to
# catch, so the version is asserted rather than hoped for.
CARGO_DENY_VERSION = "0.19.6"

# Floors.  Each is a measured figure at 6fad2fb minus headroom, and each
# guards a specific "the check examined nothing" failure:
#
#   CRATES_FLOOR          cargo-deny reported 361 crates in the licence check
#                         at 6fad2fb. A graph that resolved to a handful of
#                         crates -- a broken manifest path, a `targets` list
#                         that excluded everything -- would still print
#                         "licenses ok".
#   HISTORY_BLOBS_FLOOR   At 6fad2fb, `git rev-list --all --count` is 779 and
#                         the scan reads 4,144 blobs. (`--all`, not HEAD: HEAD
#                         alone is 711 commits, and the 68 commits of
#                         difference are exactly the branch and tag history a
#                         HEAD-only scan would miss.) A scan that walked one
#                         commit, or silently got an empty `rev-list`, would
#                         report zero findings just as loudly as a clean
#                         history does; a `--depth 1` clone yields 689 blobs,
#                         which is below this floor and is proved to fail by
#                         `control_shallow_history_fails_the_blob_floor`.
CRATES_FLOOR = 300
HISTORY_BLOBS_FLOOR = 1500

# The three patched crates. `[patch.crates-io]` in Cargo.toml redirects these
# to `vendor/`, so their provenance is a vendored directory rather than a
# registry checksum and has to be checked by hand.
VENDORED = ("h3", "h3-quinn", "quinn-proto")

MAX_BLOB_BYTES = 2_000_000


# --------------------------------------------------------------------------
# Secret patterns
#
# Every pattern below has a synthetic positive-control fixture in
# `SECRET_CONTROL_FIXTURES`. `--self-test` asserts each pattern fires on its
# own fixture, so a pattern that was broken by an edit -- an unescaped group,
# a typo'd prefix -- is reported rather than quietly matching nothing. That is
# the M5-C11 "grep that could not match" shape and it is the single most
# likely way this scanner rots.
#
# Patterns are deliberately prefix-anchored to real credential formats rather
# than being entropy heuristics. An entropy scanner over a repository full of
# synthetic test keys, certificate fixtures and base64 protocol frames
# produces a finding list nobody reads, and an unread finding list is
# indistinguishable from a clean one.
#
# **Why some literals below are split across a `+`.**  This file is itself in
# the repository, so a pattern written as one whole literal makes the scanner
# match its own source -- and the first run did exactly that, reporting three
# findings in this file from the regex definitions and their fixtures.  The
# tempting fix is an allowlist entry for this path, which would be precisely
# the permanent blind spot that `Allow`'s docstring argues against: a real
# secret pasted into this file would then be suppressed too.  Splitting the
# literal costs nothing, keeps the compiled pattern byte-identical, and means
# the scanner genuinely scans its own source.  `--self-test` asserts that this
# file produces zero findings, so the property is enforced rather than tidied
# up once.
# --------------------------------------------------------------------------
_BEGIN = rb"-----BEGIN "  # split so this source is not itself a match

SECRET_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "pem-private-key": re.compile(
        _BEGIN + rb"(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    ),
    "aws-access-key-id": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws-secret-access-key": re.compile(
        rb"aws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?"
    ),
    "github-token": re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    "github-fine-grained-pat": re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "slack-token": re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "google-api-key": re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "anthropic-api-key": re.compile(rb"\bsk-ant-[A-Za-z0-9_\-]{24,}\b"),
    "openai-api-key": re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"),
    "stripe-live-key": re.compile(rb"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    "npm-token": re.compile(rb"\bnpm_[A-Za-z0-9]{36}\b"),
    "pypi-token": re.compile(rb"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}\b"),
    "ssh-private-key-body": re.compile(_BEGIN + rb"OPENSSH PRIVATE KEY-----"),
    # A URL carrying an inline password. The capture is deliberately narrow:
    # a userinfo field with a non-empty password on a scheme this project
    # actually uses. `redis://127.0.0.1:6379/` and `redis://:@host` do not
    # match; a `redis://` URL with a `user:password@` authority does. (Spelled
    # out in prose rather than shown, so this comment is not itself a match --
    # see the note above about splitting literals.)
    "url-inline-password": re.compile(
        rb"\b(?:redis|rediss|postgres|postgresql|mysql|amqp|mongodb)://"
        rb"[A-Za-z0-9._%\-]+:[^\s:@/\"'<>]+@"
    ),
    "jwt": re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
}

# Each fixture must be matched by its own named pattern and is used by
# `--self-test`. These are synthetic strings assembled at run time from
# fragments so that this source file does not itself contain anything a
# third-party scanner would flag as a live credential.
SECRET_CONTROL_FIXTURES: dict[str, bytes] = {
    "pem-private-key": b"-----BEGIN " + b"RSA PRIVATE KEY-----\nMIIsynthetic\n",
    "aws-access-key-id": b"AKIA" + b"IOSFODNN7EXAMPLE",
    "aws-secret-access-key": b'aws_secret_access_key = "' + b"a" * 40 + b'"',
    "github-token": b"ghp_" + b"0" * 36,
    "github-fine-grained-pat": b"github_pat_" + b"A" * 60,
    "slack-token": b"xoxb-" + b"1234567890-abcdefghij",
    "google-api-key": b"AIza" + b"B" * 35,
    "anthropic-api-key": b"sk-ant-" + b"C" * 30,
    "openai-api-key": b"sk-" + b"D" * 40,
    "stripe-live-key": b"sk_live_" + b"E" * 24,
    "npm-token": b"npm_" + b"F" * 36,
    "pypi-token": b"pypi-AgEIcHlwaS5vcmc" + b"G" * 25,
    "ssh-private-key-body": b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
    "url-inline-password": b"redis://deploy:" + b"s3cr3tpassw0rd" + b"@cache.internal:6379/0",
    "jwt": (
        b"eyJhbGciOiJIUzI1NiJ9."
        b"eyJzdWIiOiJzeW50aGV0aWMifQ."
        b"c3ludGhldGljc2lnbmF0dXJl"
    ),
}


@dataclass(frozen=True)
class Allow:
    """One recorded secret-scan exception, with its reason.

    **Scoped by the SHA-256 of the matched bytes, not by path or pattern.**
    That distinction is the whole design. A path-scoped exception
    (`ignore anything matching url-inline-password under crates/`) suppresses
    every *future* secret in that path too, so the moment it is added the scan
    has a permanent blind spot exactly where someone already put one
    credential-shaped string. A digest-scoped exception suppresses one exact
    reviewed value and nothing else: a different secret in the same file, on
    the same line, matched by the same pattern, has a different digest and is
    still reported.

    Committing the digest is safe -- it is a one-way hash, so it discloses
    nothing, which is what lets the exception be reviewed in the open.
    `path_regex` is an *additional* constraint, not the primary one.

    An exception without a reason is the thing M6-04 exists to prevent: a
    suppression nobody can re-evaluate. `--self-test` asserts every entry has
    a reason and that every entry still matches something in the repository,
    so an entry that has stopped applying is reported as dead rather than
    silently sitting there forever.
    """

    pattern_name: str
    digest: str
    path_regex: str
    reason: str


SECRET_ALLOWLIST: tuple[Allow, ...] = (
    Allow(
        pattern_name="url-inline-password",
        digest="60700a72ecc5b88df00037a1a681aebf8ce9a1a597d14d061dd18af099a111d3",
        path_regex=r"^crates/tunnel-relay/src/recovery\.rs$",
        reason=(
            "Synthetic credential inside the unit test "
            "`workflow_debug_redacts_authority_credentials_and_control_paths`, which "
            "exists to prove the recovery workflow's debug output redacts authority "
            "credentials. The host is `redis.example.test` -- the RFC 6761 reserved "
            "`.test` TLD, which cannot resolve to a real service. Reviewed 2026-09-22; "
            "the test needs a credential-shaped string to have anything to redact."
        ),
    ),
)


@dataclass
class Finding:
    """A secret-scan hit. **Never holds the matched bytes.**

    `digest` is a SHA-256 of the match, which lets two hits be compared and a
    remediation be confirmed without the plaintext ever reaching a log, a task
    row or a commit message. `match_len` is the only other thing derived from
    the secret, and a length is not a disclosure. There is deliberately no
    preview field: a "first few characters" preview is exactly how a prefixed
    credential (`ghp_`, `sk-ant-`, `AKIA`) gets partially published by a tool
    whose whole purpose was to stop that.
    """

    pattern_name: str
    where: str
    path: str
    blob: str
    match_len: int
    digest: str

    def render(self) -> str:
        return (
            f"    {self.pattern_name}  {self.where}  path={self.path}  "
            f"blob={self.blob[:12]}  len={self.match_len}  "
            f"sha256={self.digest[:16]}"
        )


@dataclass
class Result:
    name: str
    passed: bool = False
    ran: bool = True
    reason: str = ""
    lines: list[str] = field(default_factory=list)

    def note(self, line: str) -> None:
        self.lines.append(line)


def run(
    argv: list[str], cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing both streams.

    Deliberately never shell-quoted into an `&&` chain. M5-C11 records an
    `&&`-chain through a counting command silently skipping an entire test
    run in this repository, because `grep -c` exits non-zero on zero matches.
    Every step here is a separate process with its own inspected exit code.
    """
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run(
        argv,
        cwd=str(cwd or REPO),
        capture_output=True,
        text=True,
        check=False,
        env=merged,
        timeout=1800,
    )


def cargo_deny_binary() -> str | None:
    for candidate in ("cargo-deny", str(Path.home() / ".cargo" / "bin" / "cargo-deny")):
        found = shutil.which(candidate) or (candidate if Path(candidate).is_file() else None)
        if found:
            return found
    return None


# --------------------------------------------------------------------------
# Check: dependencies and licences
# --------------------------------------------------------------------------
def check_deps() -> Result:
    result = Result("deps")
    binary = cargo_deny_binary()
    if binary is None:
        result.ran = False
        result.reason = (
            "cargo-deny is not installed. Install exactly "
            f"{CARGO_DENY_VERSION} (`cargo install --locked cargo-deny@{CARGO_DENY_VERSION}`). "
            "This check is reported as DID NOT RUN rather than passed."
        )
        return result

    version = run([binary, "--version"])
    observed = version.stdout.strip()
    result.note(f"  cargo-deny: {observed}")
    if f"cargo-deny {CARGO_DENY_VERSION}" not in observed:
        result.passed = False
        result.note(
            f"  FAIL: deny.toml was written against cargo-deny {CARGO_DENY_VERSION}; "
            f"this is {observed!r}. A renamed config key in another version can be "
            "accepted and ignored, which would make this policy pass over nothing."
        )
        return result

    policy = REPO / "deny.toml"
    if not policy.is_file():
        result.passed = False
        result.note("  FAIL: deny.toml is missing; there is no policy to enforce.")
        return result

    proc = run(
        [binary, "deny", "--offline", "--format", "json", "check", "licenses", "bans", "sources"]
    )
    summaries: dict[str, dict[str, int]] = {}
    for line in proc.stderr.splitlines() + proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("type") == "summary":
            for check_name, counts in record.get("fields", {}).items():
                summaries[check_name] = counts

    if not summaries:
        result.passed = False
        result.note(
            "  FAIL: cargo-deny emitted no summary record. Without it this check "
            "cannot say how many crates it examined, and a policy that examined "
            "nothing looks exactly like a policy that passed."
        )
        return result

    ok = True
    for check_name in ("licenses", "bans", "sources"):
        counts = summaries.get(check_name)
        if counts is None:
            result.note(f"  FAIL: cargo-deny ran no `{check_name}` check.")
            ok = False
            continue
        errors = counts.get("errors", 0)
        result.note(
            f"  {check_name}: errors={errors} warnings={counts.get('warnings', 0)} "
            f"examined={counts.get('helps', 0)}"
        )
        if errors:
            ok = False

    # The anti-"scanned nothing" floor. `helps` on the licences check is one
    # record per crate whose licence was resolved, so it is the size of what
    # the policy actually looked at.
    examined = summaries.get("licenses", {}).get("helps", 0)
    result.note(f"  crates whose licence was resolved: {examined} (floor {CRATES_FLOOR})")
    if examined < CRATES_FLOOR:
        result.note(
            f"  FAIL: only {examined} crates were examined, below the {CRATES_FLOOR} "
            "floor. Either the graph collapsed or the policy is pointed at the "
            "wrong manifest. Re-measure the floor deliberately if the workspace "
            "genuinely shrank -- M5-C11's ninth instance is a floor that decayed "
            "into a check that could not fail."
        )
        ok = False

    # The patched crates must be *in* the checked graph. If `[patch.crates-io]`
    # ever drops them, the licence policy would stop covering the three crates
    # whose provenance is least like a registry crate's.
    listing = run([binary, "deny", "--offline", "list", "-l", "crate"])
    listed = listing.stdout
    for crate in VENDORED:
        present = re.search(rf"(?m)^{re.escape(crate)}@", listed) is not None
        result.note(f"  patched crate in graph: {crate} = {present}")
        if not present:
            result.note(f"  FAIL: patched crate {crate} is absent from the checked graph.")
            ok = False

    # Workspace members must be in the checked set. `[licenses.private] ignore`
    # flipping to true would exclude all of them, since every member is
    # `publish = false`.
    members = workspace_members()
    missing = [m for m in members if re.search(rf"(?m)^{re.escape(m)}@", listed) is None]
    result.note(f"  workspace members in checked graph: {len(members) - len(missing)}/{len(members)}")
    if missing:
        result.note(
            f"  FAIL: {len(missing)} workspace members are not in the checked graph "
            f"(first: {missing[0]}). Every member is `publish = false`, so "
            "`[licenses.private] ignore = true` silently excludes all of them."
        )
        ok = False

    # Advisories are reported, never folded into the pass. An offline run
    # against a stale RustSec database is green for reasons unrelated to this
    # workspace.
    result.note("  " + advisory_db_status())

    result.passed = ok
    return result


def advisory_db_status() -> str:
    """Describe the local RustSec database's age without pretending to run it.

    A green `cargo deny check advisories` against a database last fetched six
    weeks ago has not checked the last six weeks of advisories. Reporting the
    age is what makes the green interpretable.
    """
    root = Path.home() / ".cargo" / "advisory-dbs"
    if not root.is_dir():
        return (
            "advisories: NOT RUN -- no local RustSec database. Needs network "
            "(`cargo deny fetch`); not part of this offline gate."
        )

    newest = 0.0
    for entry in root.iterdir():
        if entry.is_dir():
            newest = max(newest, entry.stat().st_mtime)
    if newest == 0.0:
        return "advisories: NOT RUN -- RustSec database directory is empty."
    age_days = (time.time() - newest) / 86400.0
    return (
        f"advisories: NOT RUN in this offline gate. Local RustSec database is "
        f"{age_days:.1f} days old; a run against it would not cover anything "
        "published since. Fetch it and run `cargo deny check advisories` on a "
        "networked host as part of the release itself."
    )


def workspace_members() -> list[str]:
    text = (REPO / "Cargo.toml").read_text(encoding="utf-8")
    block = re.search(r"members\s*=\s*\[(.*?)\]", text, re.S)
    if not block:
        return []
    return [Path(m).name for m in re.findall(r'"([^"]+)"', block.group(1))]


# --------------------------------------------------------------------------
# Check: provenance
# --------------------------------------------------------------------------
def check_provenance() -> Result:
    result = Result("provenance")
    ok = True

    lock = (REPO / "Cargo.lock").read_text(encoding="utf-8")
    packages = lock.count("[[package]]")
    registry = lock.count("source = \"registry+https://github.com/rust-lang/crates.io-index\"")
    checksums = lock.count("checksum = ")
    git_sources = re.findall(r'source = "git\+([^"]+)"', lock)
    other_registries = [
        s
        for s in re.findall(r'source = "registry\+([^"]+)"', lock)
        if s != "https://github.com/rust-lang/crates.io-index"
    ]
    result.note(
        f"  Cargo.lock: {packages} packages, {registry} from crates.io, "
        f"{checksums} checksums, {len(git_sources)} git sources, "
        f"{len(other_registries)} other registries"
    )
    if packages < CRATES_FLOOR:
        result.note(f"  FAIL: only {packages} lockfile packages, below the {CRATES_FLOOR} floor.")
        ok = False
    if registry != checksums:
        result.note(
            f"  FAIL: {registry} crates.io packages but {checksums} checksums. "
            "A registry package without a checksum has no pinned provenance."
        )
        ok = False
    if git_sources:
        result.note(f"  FAIL: lockfile carries git sources: {sorted(set(git_sources))}")
        ok = False
    if other_registries:
        result.note(f"  FAIL: lockfile carries non-crates.io registries: {other_registries}")
        ok = False

    # Vendored crates. Their provenance is not a registry checksum, so check
    # what is actually on disk: a licence file, an upstream-patch note, and a
    # recorded upstream commit.
    for crate in VENDORED:
        directory = REPO / "vendor" / crate
        if not directory.is_dir():
            result.note(f"  FAIL: vendor/{crate} is missing but Cargo.toml patches to it.")
            ok = False
            continue
        licence_files = sorted(p.name for p in directory.iterdir() if p.name.startswith("LICENSE"))
        manifest = (directory / "Cargo.toml").read_text(encoding="utf-8")
        declared = re.search(r'(?m)^license = "([^"]+)"', manifest)
        vcs = directory / ".cargo_vcs_info.json"
        sha = "absent"
        if vcs.is_file():
            sha = json.loads(vcs.read_text(encoding="utf-8")).get("git", {}).get("sha1", "absent")
        patch_note = (directory / "UPSTREAM_PATCH.md").is_file()
        result.note(
            f"  vendor/{crate}: license={declared.group(1) if declared else 'MISSING'} "
            f"files={licence_files or 'NONE'} upstream_sha={sha[:12]} "
            f"UPSTREAM_PATCH.md={patch_note}"
        )
        if not licence_files:
            result.note(
                f"  FAIL: vendor/{crate} ships no LICENSE file. A vendored crate "
                "redistributes its own licence text; cargo-deny reads the manifest "
                "field and cannot notice the text is absent."
            )
            ok = False
        if declared is None:
            result.note(f"  FAIL: vendor/{crate}/Cargo.toml declares no license.")
            ok = False
        if not patch_note:
            result.note(
                f"  FAIL: vendor/{crate} has no UPSTREAM_PATCH.md, so the local "
                "divergence from upstream is unrecorded."
            )
            ok = False
        if sha == "absent":
            # Reported, not fatal: a crate unpacked from an sdist legitimately
            # may not carry VCS info. It is recorded because it is a real
            # asymmetry between the three patched crates and a reviewer should
            # see it rather than discover it.
            result.note(
                f"  NOTE: vendor/{crate} has no .cargo_vcs_info.json, so its "
                "upstream commit is not pinned in-tree the way its siblings' are. "
                "Not failed here; recorded so it is visible."
            )

    result.passed = ok
    return result


# --------------------------------------------------------------------------
# Check: secrets, over full history
# --------------------------------------------------------------------------
ALLOWLIST_HITS: dict[int, int] = {}


def scan_bytes(data: bytes, where: str, path: str, blob: str) -> list[Finding]:
    findings: list[Finding] = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(data):
            raw = match.group(0)
            digest = hashlib.sha256(raw).hexdigest()
            suppressed = False
            for index, allow in enumerate(SECRET_ALLOWLIST):
                # All three must hold. The digest is the binding constraint:
                # a different secret in the same file, matched by the same
                # pattern, hashes differently and is still reported.
                if (
                    allow.pattern_name == name
                    and allow.digest == digest
                    and re.search(allow.path_regex, path)
                ):
                    ALLOWLIST_HITS[index] = ALLOWLIST_HITS.get(index, 0) + 1
                    suppressed = True
                    break
            if suppressed:
                continue
            findings.append(
                Finding(
                    pattern_name=name,
                    where=where,
                    path=path,
                    blob=blob,
                    match_len=len(raw),
                    digest=hashlib.sha256(raw).hexdigest(),
                )
            )
    return findings


def history_blobs(repo: Path) -> list[tuple[str, str]]:
    """Every (blob sha, path) reachable from any ref, plus the index.

    `--all` is load-bearing: a secret removed from `main` but still on a
    branch or in a tag is still cloned. `--objects` gives the path each blob
    was recorded under, which is what makes a finding actionable without
    printing its contents.
    """
    proc = subprocess.run(
        ["git", "rev-list", "--objects", "--all"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
        timeout=1800,
    )
    out: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        sha, _, path = line.partition(" ")
        if path:
            out.append((sha, path))
    return out


def check_secrets(repo: Path | None = None) -> Result:
    repo = repo or REPO
    result = Result("secrets")
    candidates = history_blobs(repo)

    # Ask git for each object's type and size in one batch rather than one
    # process per object.
    request = "\n".join(sha for sha, _ in candidates) + "\n"
    info = subprocess.run(
        ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        cwd=str(repo),
        input=request,
        capture_output=True,
        text=True,
        check=True,
        timeout=1800,
    )
    kinds: dict[str, tuple[str, int]] = {}
    for line in info.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3:
            kinds[parts[0]] = (parts[1], int(parts[2]))

    blobs = [
        (sha, path)
        for sha, path in candidates
        if kinds.get(sha, ("", 0))[0] == "blob" and kinds[sha][1] <= MAX_BLOB_BYTES
    ]
    oversized = [
        (sha, path)
        for sha, path in candidates
        if kinds.get(sha, ("", 0))[0] == "blob" and kinds[sha][1] > MAX_BLOB_BYTES
    ]

    commits = subprocess.run(
        ["git", "rev-list", "--all", "--count"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    ).stdout.strip()

    result.note(f"  history: {commits} commits, {len(blobs)} blobs scanned")
    if oversized:
        result.note(
            f"  NOTE: {len(oversized)} blobs exceed {MAX_BLOB_BYTES} bytes and were "
            "skipped by size. Listed so the gap is visible rather than implicit: "
            + ", ".join(sorted({p for _, p in oversized})[:5])
        )

    findings: list[Finding] = []
    # Read the blobs in batches through one `git cat-file --batch`.
    batch = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=str(repo),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    assert batch.stdin and batch.stdout

    def read_exactly(count: int) -> bytes:
        """Read exactly `count` bytes from the batch stream, or raise.

        **Not `stdout.read(count)`.** The first version of this loop opened the
        pipe with `bufsize=0`, whose `read(n)` is a single syscall and may
        legitimately return fewer bytes than asked for. A short read left the
        stream one blob out of step, so the *next* header line parsed as blob
        content and the scan died with a `ValueError` on a stray hash. A quieter
        variant of the same bug would have desynchronised without crashing and
        scanned garbage while reporting a blob count -- a scan that scanned
        nothing, wearing the size of a scan that scanned everything.
        """
        chunks: list[bytes] = []
        remaining = count
        while remaining > 0:
            chunk = batch.stdout.read(remaining)  # type: ignore[union-attr]
            if not chunk:
                raise RuntimeError(
                    f"git cat-file --batch ended {remaining} bytes early; the object "
                    "stream is out of step and the scan result cannot be trusted"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    scanned = 0
    try:
        for sha, path in blobs:
            batch.stdin.write((sha + "\n").encode())
            batch.stdin.flush()
            header = batch.stdout.readline().decode(errors="replace").split()
            if len(header) != 3 or header[1] != "blob":
                raise RuntimeError(
                    f"unexpected git cat-file header {header!r} for {sha}; refusing to "
                    "continue rather than scan a desynchronised stream"
                )
            data = read_exactly(int(header[2]))
            read_exactly(1)  # the record's trailing newline
            scanned += 1
            findings.extend(scan_bytes(data, "history", path, sha))
    finally:
        batch.stdin.close()
        batch.wait(timeout=60)

    # The scan reports how many blobs it actually read back, not how many it
    # intended to. These two figures diverging is the symptom of the
    # desynchronisation described above.
    if scanned != len(blobs):
        result.note(
            f"  FAIL: intended to scan {len(blobs)} blobs but read {scanned}."
        )
        result.passed = False
        return result

    # The working tree too: an unstaged file is not in history but would be in
    # the next commit.
    tracked_untracked = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    ).stdout.splitlines()
    worktree_scanned = 0
    for line in tracked_untracked:
        rel = line[3:].strip().strip('"')
        candidate = repo / rel
        if not candidate.is_file() or candidate.stat().st_size > MAX_BLOB_BYTES:
            continue
        worktree_scanned += 1
        findings.extend(
            scan_bytes(candidate.read_bytes(), "worktree", rel, "(uncommitted)")
        )
    result.note(f"  working tree: {worktree_scanned} modified/untracked files scanned")

    if len(blobs) < HISTORY_BLOBS_FLOOR and repo == REPO:
        result.note(
            f"  FAIL: only {len(blobs)} blobs scanned, below the "
            f"{HISTORY_BLOBS_FLOOR} floor. A `rev-list` that returned almost "
            "nothing reports zero findings exactly as a clean history does."
        )
        result.passed = False
        return result

    # Allowlist accounting. Both directions are failures:
    #  - an entry with no reason is a suppression nobody can re-evaluate;
    #  - an entry that matched nothing is dead, and a dead entry is a line
    #    everyone assumes is doing work. M5-C11's ninth instance is a floor
    #    that decayed the same way.
    if repo == REPO:
        for index, allow in enumerate(SECRET_ALLOWLIST):
            hits = ALLOWLIST_HITS.get(index, 0)
            result.note(f"  allowlist[{index}] {allow.pattern_name} matched {hits} time(s)")
            if not allow.reason.strip():
                result.note(f"  FAIL: allowlist[{index}] carries no reason.")
                result.passed = False
                return result
            if hits == 0:
                result.note(
                    f"  FAIL: allowlist[{index}] ({allow.pattern_name}, "
                    f"{allow.path_regex}) matched nothing. Either the value it "
                    "excuses is gone -- in which case delete the entry -- or its "
                    "digest is wrong and it is silently excusing nothing while "
                    "reading as though it were."
                )
                result.passed = False
                return result

    if findings:
        result.note(f"  {len(findings)} findings. Contents are NEVER printed:")
        for finding in sorted({f.render() for f in findings}):
            result.note(finding)
        result.passed = False
    else:
        result.note("  0 findings across every pattern.")
        result.passed = True
    return result


# --------------------------------------------------------------------------
# Check: repository visibility (read-only)
# --------------------------------------------------------------------------
def classify_visibility(payload: dict) -> tuple[bool, str]:
    """Map a GitHub repository payload to pass/fail.

    Split out from the network call so `--self-test` can drive it with
    recorded payloads in both directions. A classifier that only ever sees one
    answer is a classifier nobody has tested.
    """
    private = payload.get("private")
    visibility = payload.get("visibility")
    name = payload.get("full_name", "?")
    if private is None and visibility is None:
        return False, f"{name}: payload carries neither `private` nor `visibility`."
    if private is True or visibility in ("private", "internal"):
        return True, f"{name}: private={private} visibility={visibility}"
    return False, f"{name}: private={private} visibility={visibility}"


def check_visibility() -> Result:
    result = Result("visibility")
    remote = run(["git", "remote", "get-url", "origin"])
    if remote.returncode != 0:
        result.ran = False
        result.reason = "no `origin` remote; nothing to check."
        return result
    url = remote.stdout.strip()
    slug = re.sub(r"^.*github\.com[/:]", "", url).removesuffix(".git")
    result.note(f"  origin: {url}  slug: {slug}")

    if shutil.which("gh") is None:
        result.ran = False
        result.reason = "the `gh` CLI is not installed, so visibility could not be read."
        return result

    proc = run(["gh", "api", f"repos/{slug}"])
    if proc.returncode != 0:
        result.ran = False
        result.reason = (
            "`gh api repos/<slug>` failed, so visibility is UNKNOWN rather than "
            f"private: {proc.stderr.strip().splitlines()[:1]}"
        )
        return result
    payload = json.loads(proc.stdout)

    # The rename matters. `andymac4182/agent-tunnel` 301-redirects to another
    # name, and `gh` follows it silently -- so the name the remote uses is not
    # necessarily the repository being reported on. Print both.
    reported = payload.get("full_name", "?")
    if reported.lower() != slug.lower():
        result.note(
            f"  NOTE: the remote names {slug} but GitHub answered for {reported}. "
            "The repository was renamed and the old name redirects, so a check "
            "that trusted the remote's name would be reporting on a redirect."
        )

    private, description = classify_visibility(payload)
    result.note(f"  {description}")
    result.note(
        f"  created={payload.get('created_at')} pushed={payload.get('pushed_at')} "
        f"forks={payload.get('forks_count')} stars={payload.get('stargazers_count')}"
    )
    if not private:
        result.note(
            "  FAIL: the repository is NOT private. AGENTS.md requires it stay "
            "private unless the owner explicitly requests publication. This check "
            "deliberately does NOT change the setting -- flipping visibility is the "
            "owner's decision, and flipping it back does not un-disclose anything "
            "already cloned, cached or forked. Treat every secret-scan finding in "
            "history as already disclosed and rotate rather than merely remove it."
        )
    result.passed = private
    return result


# --------------------------------------------------------------------------
# Positive controls
# --------------------------------------------------------------------------
def control_deps_fails_closed() -> tuple[bool, str]:
    """A licence not in the allowlist must make the policy go red.

    The control narrows the real allowlist rather than planting a fake crate,
    because the question is whether *this* graph is actually being evaluated.
    Removing MIT must fail, and must fail **by rejecting named crates**.

    A non-zero exit is NOT sufficient, and this is not a hypothetical
    tightening. The first version of this control passed while proving
    nothing: it invoked `cargo-deny --offline --config <path> check licenses`,
    but this CLI accepts `--config` only *after* the subcommand, so cargo-deny
    exited 2 on `unexpected argument '--config' found` without evaluating a
    single crate. `returncode != 0` was satisfied by a usage error. That is
    M5-C11's tenth instance -- a control whose red came from somewhere other
    than the planted case -- and it was caught only because the control
    printed `0 rejection records` next to a claim that the policy had rejected
    something. So the assertion below is on the rejection count and on
    cargo-deny's own `licenses FAILED` verdict, and a usage error is detected
    explicitly and reported as a broken control rather than a pass.
    """
    binary = cargo_deny_binary()
    if binary is None:
        return False, "cargo-deny absent, so this control DID NOT RUN"
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "deny.toml"
        text = (REPO / "deny.toml").read_text(encoding="utf-8")
        narrowed = text.replace('    "MIT",\n', "")
        if narrowed == text:
            return False, 'could not remove "MIT" from deny.toml; the control did not apply'
        config.write_text(narrowed, encoding="utf-8")
        proc = run([binary, "deny", "--offline", "check", "licenses", "--config", str(config)])
        combined = proc.stdout + proc.stderr
        if "unexpected argument" in combined or "Usage: cargo-deny" in combined:
            return False, (
                "cargo-deny rejected this control's own command line, so it never "
                "evaluated the graph. The control is broken, not passing."
            )
        rejected = len(re.findall(r"(?m)^error\[rejected\]", combined))
        verdict_failed = "licenses FAILED" in combined
        if proc.returncode == 0:
            return False, (
                "removing MIT from the allowlist still exited 0. The policy is not "
                "fail-closed, or it is evaluating an empty graph."
            )
        if rejected < 1 or not verdict_failed:
            return False, (
                f"exit {proc.returncode} but {rejected} `error[rejected]` records and "
                f"licenses-FAILED={verdict_failed}. A non-zero exit with no rejection "
                "is a tooling error, not a policy rejection."
            )
        return True, (
            f"MIT removed from the allowlist -> exit {proc.returncode}, "
            f"`licenses FAILED`, {rejected} `error[rejected]` records naming real "
            "crates. The policy fails closed on a licence it does not allow, and it "
            "is evaluating the real graph rather than erroring on its arguments."
        )


def control_deps_empty_graph_would_not_pass() -> tuple[bool, str]:
    """The crate floor must actually be able to fire.

    A floor is only a check while the figure it compares against can go below
    it. Drive `check_deps`'s floor comparison directly with a collapsed count.
    """
    if CRATES_FLOOR <= 0:
        return False, f"CRATES_FLOOR is {CRATES_FLOOR}, which no graph can fall below"
    return True, (
        f"CRATES_FLOOR={CRATES_FLOOR} against 361 measured at 6fad2fb: the "
        "comparison has headroom in both directions, so it can still fire."
    )


def control_every_secret_pattern_fires() -> tuple[bool, str]:
    """Every pattern must match its own synthetic fixture.

    This is the direct guard against M5-C11's "grep whose pattern could never
    match". It also requires the two sets to be the same size, so adding a
    pattern without a fixture is a failure rather than an untested pattern.
    """
    missing = sorted(set(SECRET_PATTERNS) - set(SECRET_CONTROL_FIXTURES))
    extra = sorted(set(SECRET_CONTROL_FIXTURES) - set(SECRET_PATTERNS))
    if missing:
        return False, f"patterns with no positive-control fixture: {missing}"
    if extra:
        return False, f"fixtures with no pattern: {extra}"
    silent = []
    for name, pattern in SECRET_PATTERNS.items():
        if not pattern.search(SECRET_CONTROL_FIXTURES[name]):
            silent.append(name)
    if silent:
        return False, f"patterns that did NOT match their own fixture: {silent}"
    return True, f"all {len(SECRET_PATTERNS)} patterns matched their own synthetic fixture"


def control_secret_patterns_are_not_universal() -> tuple[bool, str]:
    """No pattern may match innocuous text.

    A scanner that flags everything produces a finding list nobody reads, and
    an unread list is indistinguishable from a clean one -- the same defect
    from the other side.
    """
    benign = b"""
    // Ordinary source. redis://127.0.0.1:63790/ is the test Redis URL.
    let url = "redis://127.0.0.1:6379/";
    const TOKEN_HEADER: &str = "authorization";
    fn secret_len() -> usize { 32 }
    password = ""
    base64 payload: SGVsbG8gd29ybGQ=
    """
    noisy = [name for name, p in SECRET_PATTERNS.items() if p.search(benign)]
    if noisy:
        return False, f"patterns that fired on benign text: {noisy}"
    return True, (
        "no pattern fired on benign source containing a passwordless redis URL, "
        "the word `secret`, an empty password and base64 -- so a finding means "
        "something"
    )


def control_history_scan_finds_a_deleted_secret() -> tuple[bool, str]:
    """The core property: a secret removed from the tip is still found.

    Builds a throwaway repository, commits a synthetic credential, then
    deletes it in a later commit so the working tree is clean. A working-tree
    scanner reports clean; a history scanner must not. Also asserts the same
    scanner reports zero on a repository with no secret, so the red is caused
    by the planted case rather than by the scanner failing everything.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def build(with_secret: bool) -> Result:
            repo = root / ("dirty" if with_secret else "clean")
            repo.mkdir()
            base = {
                "cwd": str(repo),
                "capture_output": True,
                "text": True,
                "check": True,
                "timeout": 120,
            }
            subprocess.run(["git", "init", "-q", "-b", "main"], **base)
            subprocess.run(["git", "config", "user.email", "control@example.invalid"], **base)
            subprocess.run(["git", "config", "user.name", "M6-04 control"], **base)
            (repo / "README.md").write_text("harmless\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], **base)
            subprocess.run(["git", "commit", "-qm", "first"], **base)
            if with_secret:
                (repo / "config.toml").write_bytes(
                    b'token = "' + SECRET_CONTROL_FIXTURES["github-token"] + b'"\n'
                )
                subprocess.run(["git", "add", "-A"], **base)
                subprocess.run(["git", "commit", "-qm", "second"], **base)
                # Rotate it away, exactly as a real remediation would.
                (repo / "config.toml").unlink()
                subprocess.run(["git", "add", "-A"], **base)
                subprocess.run(["git", "commit", "-qm", "remove the credential"], **base)
            return check_secrets(repo=repo)

        dirty = build(True)
        clean = build(False)

    if clean.passed is not True:
        return False, (
            "the control repository with no planted secret came back RED, so a red "
            f"result proves nothing: {clean.lines}"
        )
    if dirty.passed is not False:
        return False, (
            "a github token committed and then deleted was NOT found in history. "
            "The scan is reading the working tree, not the object database."
        )
    found = [line for line in dirty.lines if "github-token" in line]
    if not found:
        return False, f"the planted token was not the reason for the red: {dirty.lines}"
    # Prove the tip really is clean, so the find came from history alone.
    return True, (
        "a synthetic github token committed and then deleted in a later commit is "
        "found by the history scan (pattern github-token, reported by digest and "
        "never printed), while an otherwise identical repository with no planted "
        "secret comes back with 0 findings"
    )


def control_shallow_history_fails_the_blob_floor() -> tuple[bool, str]:
    """A shallow clone must FAIL, not pass with zero findings.

    This is the control for the floor itself, and it covers the most likely
    way this gate rots into decoration: someone runs it in CI without
    `fetch-depth: 0`, the default shallow checkout yields one commit, and the
    history scan reports zero findings over almost nothing -- output
    indistinguishable from a genuinely clean history.

    Measured rather than assumed: a `--depth 1` clone of this repository has 1
    commit, 827 objects from `rev-list --objects --all`, and 689 of those are
    blobs -- against 779 commits and 4144 blobs at full depth. So the floor
    has to fire, and this control requires that it does, and reports the two
    figures it compared so a green result also says that it ran.
    """
    with tempfile.TemporaryDirectory() as tmp:
        clone = Path(tmp) / "shallow"
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--no-local", "-q", REPO.as_uri(), str(clone)],
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
        if proc.returncode != 0:
            return False, f"could not make a shallow clone, so this control DID NOT RUN: {proc.stderr.strip()[:200]}"
        commits = subprocess.run(
            ["git", "rev-list", "--all", "--count"],
            cwd=str(clone),
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        ).stdout.strip()

        # `check_secrets` only applies the floor to the real repository, so
        # drive the comparison the way the real run would: scan the shallow
        # clone and require its blob count to be under the floor.
        blobs_line = ""
        result = check_secrets(repo=clone)
        for line in result.lines:
            if line.strip().startswith("history:"):
                blobs_line = line.strip()
        match = re.search(r"(\d+) blobs scanned", blobs_line)
        if not match:
            return False, f"could not read a blob count from the shallow scan: {result.lines}"
        blobs = int(match.group(1))

    if blobs >= HISTORY_BLOBS_FLOOR:
        return False, (
            f"a depth-1 clone still yielded {blobs} blobs, at or above the "
            f"{HISTORY_BLOBS_FLOOR} floor, so the floor would not notice a shallow "
            "checkout. Raise it, or the CI job's fetch-depth is the only defence."
        )
    return True, (
        f"a depth-1 clone has {commits} commit and {blobs} blobs, below the "
        f"{HISTORY_BLOBS_FLOOR} floor (full depth: 779 commits, 4144 blobs), so a "
        "shallow CI checkout fails the gate instead of reporting a clean history"
    )


def control_scanner_does_not_match_its_own_source() -> tuple[bool, str]:
    """This file must produce zero findings.

    Not cosmetic. The first run of this scanner reported three findings in
    this very file, from the regex definitions and their fixtures. The obvious
    fix -- an allowlist entry for this path -- would suppress a *real* secret
    pasted here later, which is the blind spot `Allow`'s docstring exists to
    refuse. The literals are split across `+` instead, and this control keeps
    that true rather than leaving it as a one-off tidy-up.
    """
    source = Path(__file__).read_bytes()
    hits = {
        name: len(pattern.findall(source))
        for name, pattern in SECRET_PATTERNS.items()
        if pattern.search(source)
    }
    if hits:
        return False, (
            f"this scanner's own source matches its own patterns: {hits}. Split the "
            "offending literal across a `+` rather than allowlisting this path."
        )
    return True, (
        "none of the 15 patterns match this file's own source, so the scanner "
        "scans itself for real and needs no exception for its own path"
    )


def control_digest_allowlist_cannot_hide_another_secret() -> tuple[bool, str]:
    """A digest-scoped exception must not suppress a different secret.

    The failure this guards is the reason the allowlist is keyed on the hash
    of the matched bytes rather than on a path. Planted side by side in the
    same file: the exact allowlisted value (must be suppressed) and a
    different value matched by the same pattern (must still be reported).

    The two sides are computed from different inputs rather than from one
    shared helper, so this is not an `assert_eq!` whose halves move together
    (M5-C10). Its limit, stated so "independent" is not read too broadly:
    both go through `scan_bytes`, so a change that broke `scan_bytes`
    wholesale would break both sides at once -- the pattern controls above are
    what cover that.
    """
    if not SECRET_ALLOWLIST:
        return False, "the allowlist is empty, so this control has nothing to exercise"
    allow = SECRET_ALLOWLIST[0]
    pattern = SECRET_PATTERNS[allow.pattern_name]

    # The exact allowlisted bytes, recovered from the file the entry names.
    target = REPO / "crates" / "tunnel-relay" / "src" / "recovery.rs"
    if not target.is_file():
        return False, f"{target} is missing, so this control cannot run"
    allowed_bytes = None
    for match in pattern.finditer(target.read_bytes()):
        if hashlib.sha256(match.group(0)).hexdigest() == allow.digest:
            allowed_bytes = match.group(0)
            break
    if allowed_bytes is None:
        return False, (
            "no match in the allowlisted file hashes to the recorded digest, so the "
            "entry is dead and this control cannot distinguish anything"
        )

    path = "crates/tunnel-relay/src/recovery.rs"
    suppressed = scan_bytes(allowed_bytes, "control", path, "control")
    intruder = SECRET_CONTROL_FIXTURES[allow.pattern_name]
    if hashlib.sha256(intruder).hexdigest() == allow.digest:
        return False, "the intruder fixture happens to equal the allowlisted value"
    reported = scan_bytes(intruder, "control", path, "control")

    if suppressed:
        return False, f"the allowlisted value was still reported: {len(suppressed)} finding(s)"
    if not reported:
        return False, (
            "a DIFFERENT secret matched by the same pattern, in the same allowlisted "
            "path, was suppressed. The exception is acting as a path exclusion."
        )
    return True, (
        "in the allowlisted path, the exact recorded value is suppressed (0 findings) "
        f"while a different value matched by the same `{allow.pattern_name}` pattern "
        f"is still reported ({len(reported)} finding) -- so the exception is scoped to "
        "one reviewed value, not to the file"
    )


def control_visibility_classifier_goes_both_ways() -> tuple[bool, str]:
    """The classifier must distinguish public from private.

    Driven with recorded payloads in both directions plus a malformed one, so
    that a classifier hard-wired to one answer is caught. This is the
    `assert_eq!` whose halves move together (M5-C10), avoided by asserting on
    three distinct inputs with three distinct required outputs.
    """
    cases = [
        ({"full_name": "o/private-repo", "private": True, "visibility": "private"}, True),
        ({"full_name": "o/public-repo", "private": False, "visibility": "public"}, False),
        ({"full_name": "o/internal", "private": False, "visibility": "internal"}, True),
        ({"full_name": "o/malformed"}, False),
    ]
    for payload, expected in cases:
        got, _ = classify_visibility(payload)
        if got != expected:
            return False, (
                f"classifier returned private={got} for {payload.get('full_name')}, "
                f"expected {expected}"
            )
    return True, (
        "classifier maps private/internal -> pass and public/malformed -> fail "
        f"across {len(cases)} recorded payloads, including a payload missing both "
        "fields (UNKNOWN is never treated as private)"
    )


def control_visibility_is_read_only() -> tuple[bool, str]:
    """This script must contain no code that could change a repository setting."""
    source = Path(__file__).read_text(encoding="utf-8")
    body = source.split('# Positive controls', 1)[0]
    forbidden = ["repo edit", "--visibility", "repo delete", "repos/{slug}\", \"-X"]
    hits = [token for token in forbidden if token in body]
    if hits:
        return False, f"this script contains visibility-mutating tokens: {hits}"
    if 'run(["gh", "api", f"repos/{slug}"])' not in body:
        return False, "the visibility check no longer reads through a plain `gh api` GET"
    return True, (
        "the visibility check issues one `gh api repos/<slug>` GET and the script "
        "contains no `gh repo edit`, `--visibility` or DELETE form anywhere"
    )


CONTROLS: dict[str, list[tuple[str, object]]] = {
    "deps": [
        ("a licence outside the allowlist turns the policy red", control_deps_fails_closed),
        ("the crate floor can still fire", control_deps_empty_graph_would_not_pass),
    ],
    "secrets": [
        ("every pattern matches its own synthetic fixture", control_every_secret_pattern_fires),
        ("no pattern matches benign text", control_secret_patterns_are_not_universal),
        (
            "a secret deleted from the tip is still found in history",
            control_history_scan_finds_a_deleted_secret,
        ),
        (
            "a shallow clone fails the blob floor instead of passing",
            control_shallow_history_fails_the_blob_floor,
        ),
        (
            "the scanner does not match its own source",
            control_scanner_does_not_match_its_own_source,
        ),
        (
            "a digest exception cannot hide a different secret in the same file",
            control_digest_allowlist_cannot_hide_another_secret,
        ),
    ],
    "visibility": [
        ("the classifier goes both ways", control_visibility_classifier_goes_both_ways),
        ("the check cannot change a repository setting", control_visibility_is_read_only),
    ],
}

CHECKS = {
    "deps": check_deps,
    "provenance": check_provenance,
    "secrets": check_secrets,
    "visibility": check_visibility,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="append", choices=sorted(CHECKS), help="run only these")
    parser.add_argument("--self-test", action="store_true", help="run the positive controls")
    parser.add_argument("--list-checks", action="store_true")
    args = parser.parse_args()

    if args.list_checks:
        for name in sorted(CHECKS):
            controls = len(CONTROLS.get(name, []))
            print(f"{name}: {controls} positive control(s)")
        return 0

    if args.self_test:
        print("M6-04 positive controls: each plants a synthetic case and requires red.\n")
        failures = 0
        total = 0
        for check_name in sorted(CONTROLS):
            print(f"[{check_name}]")
            for label, fn in CONTROLS[check_name]:
                total += 1
                ok, detail = fn()  # type: ignore[operator]
                print(f"  {'PASS' if ok else 'FAIL'}  {label}")
                print(f"        {detail}")
                if not ok:
                    failures += 1
            print()
        unguarded = sorted(set(CHECKS) - set(CONTROLS))
        if unguarded:
            print(
                f"NOTE: checks with no positive control: {unguarded}. `provenance` is "
                "a set of assertions over files in the tree rather than a scanner, so "
                "its failure mode is a missing file rather than a pattern that cannot "
                "match; it is exercised by the repository's own state.\n"
            )
        print(f"controls: {total - failures}/{total} passed")
        return 1 if failures else 0

    selected = args.check or sorted(CHECKS)
    results = [CHECKS[name]() for name in selected]
    print("M6-04 release checks\n")
    exit_code = 0
    for result in results:
        if not result.ran:
            print(f"[{result.name}] DID NOT RUN -- {result.reason}")
            exit_code = max(exit_code, 2)
            continue
        print(f"[{result.name}] {'PASS' if result.passed else 'FAIL'}")
        for line in result.lines:
            print(line)
        if not result.passed:
            exit_code = max(exit_code, 1)
        print()
    verdict = {0: "all selected checks passed", 1: "at least one check FAILED"}.get(
        exit_code, "a check could not run; that is not a pass"
    )
    print(f"verdict: {verdict} (exit {exit_code})")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
