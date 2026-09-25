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
  `visibility`  Read-only.  Compares GitHub's answer for the `origin` remote
                against the visibility the owner **declared** in
                `[workspace.metadata.release] repository-visibility` in the
                root `Cargo.toml`, and fails on disagreement **in either
                direction**.  The owner has explicitly requested publication,
                so the declaration is now `public` -- but the check was not
                changed by inverting a constant, because a check that asserts
                "public" cannot go red for the reason it names and would keep
                passing if the decision were reverted.  It is a comparison of
                two observations, and its control drives every recorded
                payload against both declarations.  **This check never changes
                a repository setting**; which of the two disagreeing sides is
                wrong is the owner's call, not this script's.

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
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The two answers `repository-visibility` may declare. `internal` is folded
# into `private` when GitHub reports it; it is not a declarable value here,
# because this repository is not in an organisation that can produce one.
VISIBILITY_VALUES = ("public", "private")

# cargo-deny is pinned: the `deny.toml` schema was read out of this version's
# own `init` template, and a later version could rename a key.  A renamed key
# that is silently ignored is the exact defect class this script exists to
# catch, so the version is asserted rather than hoped for.
CARGO_DENY_VERSION = "0.19.6"

# Whether cargo-deny is invoked with `--offline`. Mutated once by `main()`
# from `--no-offline`.
#
# **This was hard-coded, and that made the CI job known-broken rather than
# merely unexercised.** On a fresh runner with an empty `CARGO_HOME`,
# `--offline` makes `cargo metadata` fail with "no matching package", no
# summary record is produced, and `deps` fails -- so the job as first written
# could not have passed even had billing allowed it to run. The fix is in two
# halves: CI now runs `cargo fetch --locked` first so the registry cache and
# the extracted crate sources cargo-deny reads LICENSE files from are both
# present, and the flag exists so a networked host can skip `--offline`
# entirely.
OFFLINE: list[str] = ["--offline"]

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

# Size cap for a single blob, and exceeding it is a **FAIL**, not a skip.
#
# **Raised from 2,000,000, which was on course to silently drop the most
# important file in the repository.** The largest blob in history is
# `docs/tasks.md`, 1,373,974 bytes at b97a3bb and growing roughly 18 KB per
# commit -- about 35 commits from crossing a 2 MB cap. The file most likely to
# carry pasted evidence would have left the scan with a NOTE while the check
# still passed. 64 MiB is far above anything this repository plausibly
# commits, and if it is ever reached the run goes red and names the file
# rather than quietly narrowing its own scope.
MAX_BLOB_BYTES = 64 * 1024 * 1024


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
    "gitlab-pat": re.compile(rb"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    "slack-token": re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "google-api-key": re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "anthropic-api-key": re.compile(rb"\bsk-ant-[A-Za-z0-9_\-]{24,}\b"),
    "openai-api-key": re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"),
    "stripe-live-key": re.compile(rb"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    "npm-token": re.compile(rb"\bnpm_[A-Za-z0-9]{36}\b"),
    "pypi-token": re.compile(rb"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}\b"),
    "ssh-private-key-body": re.compile(_BEGIN + rb"OPENSSH PRIVATE KEY-----"),
    # A URL carrying an inline password, for a scheme this project uses.
    # Matches whether or not a username is present, and requires the password
    # to be non-empty. A URL with no userinfo at all, and one with an empty
    # password, both do not match. (Spelled out in prose rather than shown, so
    # this comment is not itself a match -- see the note above about splitting
    # literals.)
    #
    # **The username is optional, and that was a real gap rather than a
    # tightening.** The first version required a non-empty username, which
    # excluded the `scheme://:password@host` form -- Redis's default-user ACL
    # spelling, and therefore **the one credential shape this Redis-only
    # project actually uses**. The comment at the time described the exclusion
    # as only the empty-*password* case, so the gap was invisible from the
    # source. A pattern that cannot match the project's own credential format
    # is a check that cannot fail for the class that matters most here, and
    # "0 findings" over it would have been true and misleading at once.
    "url-inline-password": re.compile(
        rb"\b(?:redis|rediss|postgres|postgresql|mysql|amqp|mongodb|https?|ssh|ftp)://"
        rb"[A-Za-z0-9._%\-]*:[^\s:@/\"'<>]+@"
    ),
    # Redis's own config directive. In scope because Redis is the only
    # authoritative store in this project, so this is a credential shape it
    # would plausibly carry. Requires a non-empty value, so a commented-out or
    # empty directive does not match.
    #
    # **Anchored to the start of a line**, which is where a config directive
    # lives. Without the anchor it matched the prose "the requirepass
    # directive sets a password" -- found by the Fable review, and the reason
    # `control_secret_patterns_are_not_universal` now carries that sentence.
    "redis-requirepass": re.compile(rb"(?m)^[ \t]*requirepass[ \t=]+[^\s\"'#]+"),
    # A populated Authorization header.
    #
    # **The token must contain a lowercase letter and a digit**, which is true
    # of essentially every real opaque credential and false of the
    # SHOUTING_PLACEHOLDER spellings documentation uses. The length bound
    # alone was not enough: it matched
    # `Authorization: Bearer YOUR_ACCESS_TOKEN_HERE_PLEASE`, contradicting the
    # comment that claimed placeholders were excluded. The residual limit,
    # stated rather than glossed: an all-uppercase or all-digit real token
    # would be missed. That is a deliberate trade for not crying wolf on every
    # README, and it is why this pattern is a supplement to the
    # prefix-anchored vendor patterns rather than a replacement for them.
    "http-auth-header": re.compile(
        rb"[Aa]uthorization:\s*(?:"
        rb"Bearer\s+(?=[A-Za-z0-9._\-]{20,})(?=[A-Za-z0-9._\-]*[a-z])"
        rb"(?=[A-Za-z0-9._\-]*[0-9])[A-Za-z0-9._\-]{20,}"
        rb"|Basic\s+(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[0-9])"
        rb"[A-Za-z0-9+/]{16,}={0,2})"
    ),
    "jwt": re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
}

# **What this scanner does NOT cover, stated because "0 findings" is only
# meaningful alongside its scope.** Every pattern above is anchored to a known
# credential format -- a vendor prefix, a URL authority, a named config
# directive or header. The scanner therefore does not detect:
#
#   - generic assignments (`password = "..."`, `api_key: ...`) beyond the
#     specific AWS and Redis spellings above;
#   - raw high-entropy strings, hex secrets or bare base64 blobs with no
#     surrounding context;
#   - credentials that were never committed here at all -- deployment
#     secrets, relay identities and Redis credentials provisioned out of band.
#
# Those are deliberate omissions, not oversights: an entropy scanner over a
# repository full of synthetic test keys, certificate fixtures and base64
# protocol frames produces a finding list nobody reads, and an unread list is
# indistinguishable from a clean one. But the consequence has to be said out
# loud wherever a zero is reported, because "0 findings" reads as "no secrets"
# and means "no secrets **in these formats**". `check_secrets` prints this
# scope beside its count for exactly that reason.
COVERAGE_LIMITS = (
    "prefix-anchored vendor formats, URL authorities, Redis `requirepass` and "
    "Authorization headers only -- NOT generic assignments, raw entropy/hex "
    "blobs, or credentials never committed here"
)

# Each pattern's synthetic positive-control fixtures, used by `--self-test`.
# These are assembled at run time from fragments so that this source file does
# not itself contain anything a third-party scanner would flag as a live
# credential.
#
# **A tuple per pattern, not a single fixture**, so that a pattern with more
# than one real-world spelling is exercised in each of them. `url-inline-password`
# is the reason: it has a form with a username and a form without, and only the
# first was ever tested, which is precisely how the missing empty-username case
# went unnoticed. A pattern with one spelling simply has a one-element tuple.
SECRET_CONTROL_FIXTURES: dict[str, tuple[bytes, ...]] = {
    "pem-private-key": (b"-----BEGIN " + b"RSA PRIVATE KEY-----\nMIIsynthetic\n",),
    "aws-access-key-id": (b"AKIA" + b"IOSFODNN7EXAMPLE",),
    "aws-secret-access-key": (b'aws_secret_access_key = "' + b"a" * 40 + b'"',),
    "github-token": (b"ghp_" + b"0" * 36,),
    "github-fine-grained-pat": (b"github_pat_" + b"A" * 60,),
    "gitlab-pat": (b"glpat-" + b"H" * 20,),
    "slack-token": (b"xoxb-" + b"1234567890-abcdefghij",),
    "google-api-key": (b"AIza" + b"B" * 35,),
    "anthropic-api-key": (b"sk-ant-" + b"C" * 30,),
    "openai-api-key": (b"sk-" + b"D" * 40,),
    "stripe-live-key": (b"sk_live_" + b"E" * 24,),
    "npm-token": (b"npm_" + b"F" * 36,),
    "pypi-token": (b"pypi-AgEIcHlwaS5vcmc" + b"G" * 25,),
    "ssh-private-key-body": (b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",),
    "url-inline-password": (
        # With a username.
        b"redis://deploy:" + b"s3cr3tpassw0rd" + b"@cache.internal:6379/0",
        # **Without one -- Redis's default-user ACL form, the shape this
        # project actually uses, and the one the pattern used to miss.**
        b"rediss://:" + b"s3cr3tpassw0rd" + b"@cache.internal:6379/0",
        # A non-Redis scheme, since the scheme list is now wider.
        b"https://token:" + b"s3cr3tpassw0rd" + b"@git.internal/repo.git",
    ),
    "redis-requirepass": (
        b"requirepass " + b"s3cr3tpassw0rd",
        b"requirepass=" + b"s3cr3tpassw0rd",
    ),
    # Mixed case with digits, as a real opaque credential is -- the pattern now
    # requires that, so an all-uppercase fixture would not exercise it.
    "http-auth-header": (
        b"Authorization: Bearer " + b"s3cr3tT0ken" + b"Abcdef0123456789",
        b"Authorization: Basic " + b"c3ludGhldGljOnBhc3N3b3Jk0",
    ),
    "jwt": (
        b"eyJhbGciOiJIUzI1NiJ9."
        b"eyJzdWIiOiJzeW50aGV0aWMifQ."
        b"c3ludGhldGljc2lnbmF0dXJl",
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
    suppression nobody can re-evaluate. **`check_secrets` itself** asserts
    every entry has a reason and that every entry still matched something in
    the run just completed, so an entry that has stopped applying fails the
    check rather than sitting there forever. (An earlier version of this
    docstring credited `--self-test` with that; it does not, and saying so
    would have sent a reader to the wrong place to find out whether dead
    entries are caught at all.)
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
    # The two entries below appeared when the scheme list was widened to cover
    # an `https` URL with a `user:token@` authority -- a real leak vector,
    # since that is how a git remote carries an embedded token. (Spelled out
    # rather than shown: written literally, this comment is itself a match,
    # which is exactly what the self-source control caught here.) Both hits
    # below are the *opposite* of a
    # credential: they are fixtures asserting that a URL carrying userinfo is
    # REJECTED. Keeping the wider scheme and excusing these two exact values is
    # the right trade; narrowing the pattern again would have dropped the leak
    # vector to avoid two known-good strings.
    Allow(
        pattern_name="url-inline-password",
        digest="fdda8961c7346f6e935394f6a3c69be76d6d8ff3f18251e3cb5c4f6b65f296e3",
        path_regex=r"^crates/tunnel-mcp-export/src/config\.rs$",
        reason=(
            "One entry in a table of endpoint spellings a parser test feeds in; the "
            "userinfo form sits beside `http://0.0.0.0:1/mcp` and "
            "`http://example.invalid:1/mcp` as a case the parser must handle. The host "
            "is loopback and the value is a placeholder, not a credential. Reviewed "
            "2026-09-22."
        ),
    ),
    Allow(
        pattern_name="url-inline-password",
        digest="fbddae166ead16d1dd67736b19403ab1ac0095e344f663573848af911a7ce273",
        path_regex=r"membership_runtime\.rs$",
        reason=(
            "An `assert_eq!` requiring `ParsedAuthorityEndpoint::parse` on a URL with "
            "userinfo to return `CheckpointAuthorityError::InvalidEndpoint` -- a test "
            "that authority endpoints carrying credentials are refused. The host is "
            "under the RFC 2606 reserved `.example` TLD. The path pattern is "
            "deliberately unanchored because the same file is duplicated under `work/` "
            "backup trees; the digest is what actually scopes this entry, and a "
            "different credential in any of those copies still reports. Reviewed "
            "2026-09-22."
        ),
    ),
    # The three entries below are test fixtures from the M6-C72 commit
    # 6f4a504, still reachable in history.  4283e18 rewrote all three so the
    # working tree no longer contains them; rewriting history instead would
    # change the commit the M6-C72 task row cites.  Each entry is scoped by
    # the digest of one exact matched value.
    Allow(
        pattern_name="url-inline-password",
        digest="62bb628c89f2cfef6b25a03454ec637ff5818e8a22a2099e74cf19f7a7eac243",
        path_regex=r"^crates/tunnel-catalog/src/error\.rs$",
        reason=(
            "Synthetic URL-shaped text used as the message of an injected "
            "`io::Error` in the unit test "
            "`connection_failures_classify_by_typed_kind_only` (6f4a504), to show "
            "that connection failures are classified by typed kind and never by "
            "text. The user and password are placeholders and the host is not a "
            "real name. Reviewed 2026-09-23; rewritten in 4283e18."
        ),
    ),
    Allow(
        pattern_name="url-inline-password",
        digest="e3c0793fcf9496410250264db11a0ecfeec9b4d42f727220e707537067be8033",
        path_regex=r"^crates/tunnel-relay/src/redis_connection\.rs$",
        reason=(
            "Synthetic `format!` template for a URL with a user and a password "
            "placeholder, in the unit test "
            "`staged_failures_never_print_the_url_or_password` (6f4a504). It "
            "dials a closed loopback port to prove the diagnostic never prints "
            "the URL or password. The template occurs twice in that blob. "
            "Reviewed 2026-09-23; rewritten in 4283e18."
        ),
    ),
    Allow(
        pattern_name="url-inline-password",
        digest="e6a8d54f68a6ecd13c039045eb5b890c7c7966e835dfb0b8a2ba316064dc6cf9",
        path_regex=r"^crates/tunnel-relay/src/redis_connection\.rs$",
        reason=(
            "Synthetic `format!` template for Redis's default-user spelling (no "
            "user, a placeholder password) in the same unit test "
            "`staged_failures_never_print_the_url_or_password` (6f4a504), "
            "dialling a closed loopback port. Reviewed 2026-09-23; rewritten "
            "in 4283e18."
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
        # `blob` is a 40-char object id for a history finding and the literal
        # marker `(uncommitted)` for a working-tree one. Truncating to 12
        # unconditionally cut that marker to `(uncommitted`, so every
        # working-tree finding -- the ones a reader meets first, because they
        # are the ones they can still fix before pushing -- printed what
        # looked like a malformed object id (M6-C14). Shorten only what is
        # actually a hash.
        blob = self.blob[:12] if re.fullmatch(r"[0-9a-f]{40}", self.blob) else self.blob
        return (
            f"    {self.pattern_name}  {self.where}  path={self.path}  "
            f"blob={blob}  len={self.match_len}  "
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
def crate_floor_verdict(examined: int) -> tuple[bool, str]:
    """Decide whether `examined` crates clears the floor, and say so.

    **Factored out of `check_deps` so a control can drive it with a collapsed
    count.** It was not, and that was the defect: the control asserted
    `CRATES_FLOOR > 0` and printed a hard-coded "361 measured at 6fad2fb",
    which is a string literal rather than a measurement. A control that
    compares a constant against zero cannot fail, so the floor -- whose entire
    job is to notice a licence policy that examined nothing -- had no control
    at all while appearing in the list of ten as though it did. That is
    M5-C11's eleventh instance and the sharpest one yet, because it is the
    M5-C11 shape *inside the controls written to prevent the M5-C11 shape*.

    Returning the verdict and its text together is what makes it drivable:
    the control calls this with a collapsed count and requires False, and with
    the real count and requires True, so both branches are exercised against
    the same function the real check uses.
    """
    if examined < CRATES_FLOOR:
        return False, (
            f"  FAIL: only {examined} crates were examined, below the {CRATES_FLOOR} "
            "floor. Either the graph collapsed or the policy is pointed at the "
            "wrong manifest. Re-measure the floor deliberately if the workspace "
            "genuinely shrank -- M5-C11's ninth instance is a floor that decayed "
            "into a check that could not fail."
        )
    return True, f"  crates whose licence was resolved: {examined} (floor {CRATES_FLOOR})"


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
    # Anchored and terminated, not a substring: `"cargo-deny 0.19.6" in
    # "cargo-deny 0.19.60"` is True, so the substring form would have accepted
    # a different version as the pinned one.
    if re.fullmatch(rf"cargo-deny {re.escape(CARGO_DENY_VERSION)}", observed) is None:
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
        [binary, "deny", *OFFLINE, "--format", "json", "check", "licenses", "bans", "sources"]
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
        # `helps` is one record per crate whose licence was resolved, so it is
        # a size only for the licences check. `bans` and `sources` report 0
        # there even on a full graph, and printing "examined=0" beside them
        # read as "examined nothing" -- the exact alarm this script exists to
        # raise, fired spuriously, which trains a reader to ignore it.
        size = (
            f" crates_examined={counts.get('helps', 0)}"
            if check_name == "licenses"
            else " (this check reports no per-crate count)"
        )
        result.note(
            f"  {check_name}: errors={errors} warnings={counts.get('warnings', 0)}{size}"
        )
        if errors:
            ok = False

    # The anti-"scanned nothing" floor. `helps` on the licences check is one
    # record per crate whose licence was resolved, so it is the size of what
    # the policy actually looked at.
    examined = summaries.get("licenses", {}).get("helps", 0)
    floor_ok, floor_note = crate_floor_verdict(examined)
    result.note(floor_note)
    if not floor_ok:
        ok = False

    # The patched crates must be *in* the checked graph. If `[patch.crates-io]`
    # ever drops them, the licence policy would stop covering the three crates
    # whose provenance is least like a registry crate's.
    listing = run([binary, "deny", *OFFLINE, "list", "-l", "crate"])
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

    # The licence policy's scope, proved per advertised target (M6-C05).
    scope_ok, scope_notes = licence_scope(binary)
    for line in scope_notes:
        result.note(line)
    if not scope_ok:
        ok = False

    # Advisories are reported, never folded into the pass. An offline run
    # against a stale RustSec database is green for reasons unrelated to this
    # workspace.
    result.note("  " + advisory_db_status())

    result.passed = ok
    return result


# --------------------------------------------------------------------------
# The licence policy's scope (docs/tasks.md M6-C05)
#
# `Cargo.lock` pins more registry crates than cargo-deny checks, and the
# difference used to be an unexamined subtraction: a crate in the lockfile and
# outside the checked graph is outside the fail-closed allowlist.  That is
# correct only if no advertised target can build it, and nothing proved that.
#
# **The proof is `cargo tree`, not a `cargo metadata --filter-platform` walk.**
# The metadata walk was measured first (M5-C04 uses it for a deny-list, where
# over-reaching is safe) and it reaches 12 to 14 of the unchecked crates on
# every advertised target -- `jiff`, `defmt`, `aho-corasick` and others --
# while `cargo tree -i` on each prints nothing for any target: `cargo
# metadata`'s resolve lists dependencies whose features the real feature
# resolver never enables.  `cargo tree` runs that resolver, as a build does,
# and so does cargo-deny's graph.  So, for each advertised target, every
# registry crate `cargo tree --workspace --target T -e normal,build,dev`
# reaches must be in cargo-deny's checked set.  If it holds, every crate
# outside the checked set is unreachable on every advertised target, for
# normal, build and dev edges, under the workspace's own features.  If a
# feature change pulls one in (`aws-lc-sys` is the case the row names), it
# enters both graphs together and the allowlist judges it; if the two
# resolvers ever disagree, this fails naming the crate.
# --------------------------------------------------------------------------
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
# Registry crates one advertised target reaches, measured 293 to 296 across
# the four at the M6-C05 change.  Below this the walk examined too little to
# prove anything, however consistent its answer.
TARGET_REACH_FLOOR = 250
TREE_PACKAGE_RE = re.compile(r"^(\S+) v(\S+)(.*)$")


def lockfile_registry_crates(lock_text: str) -> set[tuple[str, str]]:
    packages = tomllib.loads(lock_text).get("package", [])
    return {
        (p["name"], p["version"]) for p in packages if p.get("source") == REGISTRY_SOURCE
    }


def checked_registry_crates(binary: str) -> set[tuple[str, str]] | None:
    """The registry crates cargo-deny's graph holds, from its own JSON listing."""
    proc = run([binary, "deny", *OFFLINE, "list", "-l", "crate", "-f", "json"])
    try:
        listing = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    crates = set()
    for key in listing:
        parts = key.split(" ")
        if len(parts) >= 3 and parts[2] == REGISTRY_SOURCE:
            crates.add((parts[0], parts[1]))
    return crates


def target_reach(target: str) -> set[tuple[str, str]] | None:
    """Registry crates the real feature resolver reaches for `target`."""
    proc = run(
        [
            "cargo", "tree", "--locked", *OFFLINE, "--workspace", "--target", target,
            "-e", "normal,build,dev", "--prefix", "none", "--format", "{p}",
        ]
    )
    if proc.returncode != 0:
        return None
    reached = set()
    for line in proc.stdout.splitlines():
        match = TREE_PACKAGE_RE.match(line.strip())
        # A path crate prints its directory, "(/...)"; the lockfile carries no
        # git sources (checked by `provenance`), so the rest are registry crates.
        if match and "(/" not in match.group(3):
            reached.add((match.group(1), match.group(2)))
    return reached


def licence_scope_verdict(
    lock: set[tuple[str, str]],
    checked: set[tuple[str, str]],
    reach: dict[str, set[tuple[str, str]] | None],
) -> tuple[bool, list[str]]:
    """Pure rule: every crate an advertised target reaches is licence-checked."""
    ok = True
    notes = []
    unchecked = lock - checked
    for target, reached in sorted(reach.items()):
        if reached is None:
            notes.append(f"  FAIL: licence scope: `cargo tree` failed for {target}")
            ok = False
            continue
        floor_ok = len(reached) >= TARGET_REACH_FLOOR
        outside = sorted(reached - checked)
        notes.append(
            f"  licence scope {target}: {len(reached)} registry crates reached, "
            f"{len(outside)} outside the checked graph"
        )
        if not floor_ok:
            notes.append(
                f"  FAIL: licence scope: {target} reached only {len(reached)} crates, "
                f"below the {TARGET_REACH_FLOOR} floor; the walk examined too little"
            )
            ok = False
        if outside:
            named = ", ".join(f"{n}@{v}" for n, v in outside[:5])
            notes.append(
                f"  FAIL: {len(outside)} crate(s) {target} can build are not licence-"
                f"checked: {named}"
            )
            ok = False
    stray = sorted(checked - lock)
    if stray:
        notes.append(f"  FAIL: cargo-deny checks crates the lockfile does not pin: {stray[:3]}")
        ok = False
    if ok:
        notes.append(
            f"  licence scope: {len(lock)} lockfile registry crates, {len(checked)} "
            f"licence-checked, {len(unchecked)} unreachable on all {len(reach)} "
            "advertised targets (normal, build and dev edges)"
        )
        if unchecked:
            notes.append(
                "  unreachable and unchecked: "
                + ", ".join(f"{n}@{v}" for n, v in sorted(unchecked))
            )
    return ok, notes


def licence_scope(binary: str) -> tuple[bool, list[str]]:
    try:
        targets = declared_targets()
    except ValueError as error:
        return False, [f"  FAIL: licence scope: no advertised targets to prove it for: {error}"]
    checked = checked_registry_crates(binary)
    if checked is None:
        return False, ["  FAIL: licence scope: cargo-deny's JSON crate listing did not parse"]
    lock = lockfile_registry_crates((REPO / "Cargo.lock").read_text(encoding="utf-8"))
    reach = {target: target_reach(target) for target in targets}
    return licence_scope_verdict(lock, checked, reach)


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
VCS_SHA_RE = re.compile(r"[0-9a-f]{40}")


def vendored_vcs_verdict(directory: Path, crate: str) -> tuple[str, str | None]:
    """The upstream commit a vendored crate records, or why it records none.

    Returns `(sha, problem)`.  **A missing or malformed `.cargo_vcs_info.json`
    is a FAIL** (docs/tasks.md M6-C02).  It used to be a NOTE, on the grounds
    that a crate unpacked from an sdist need not carry VCS info -- and that is
    how `vendor/h3-quinn` shipped with its provenance reduced to a version
    number while its two siblings pinned a commit.  Every patched crate here
    now records one, so the asymmetry cannot come back unseen: a patch is a
    diff, and a diff against an unrecorded tree cannot be re-derived.
    """
    vcs = directory / ".cargo_vcs_info.json"
    if not vcs.is_file():
        return "absent", (
            f"vendor/{crate} has no .cargo_vcs_info.json, so the upstream tree its "
            "patch was taken against is unrecorded. Copy the file from the "
            "published crate and check it against upstream history (M6-C02)."
        )
    try:
        info = json.loads(vcs.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return "malformed", f"vendor/{crate}/.cargo_vcs_info.json is not JSON: {error}"
    vcs_block = info.get("git") if isinstance(info, dict) else None
    sha = vcs_block.get("sha1") if isinstance(vcs_block, dict) else None
    if not isinstance(sha, str) or VCS_SHA_RE.fullmatch(sha) is None:
        return "malformed", (
            f"vendor/{crate}/.cargo_vcs_info.json records no 40-hex sha1 ({sha!r})"
        )
    if info.get("path_in_vcs") != crate:
        return sha, (
            f"vendor/{crate}/.cargo_vcs_info.json names path_in_vcs "
            f"{info.get('path_in_vcs')!r}, not {crate!r}: it describes another crate"
        )
    return sha, None


def check_provenance(root: Path | None = None) -> Result:
    root = root or REPO
    result = Result("provenance")
    ok = True

    lock = (root / "Cargo.lock").read_text(encoding="utf-8")
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
        directory = root / "vendor" / crate
        if not directory.is_dir():
            result.note(f"  FAIL: vendor/{crate} is missing but Cargo.toml patches to it.")
            ok = False
            continue
        licence_files = sorted(p.name for p in directory.iterdir() if p.name.startswith("LICENSE"))
        manifest = (directory / "Cargo.toml").read_text(encoding="utf-8")
        declared = re.search(r'(?m)^license = "([^"]+)"', manifest)
        sha, vcs_problem = vendored_vcs_verdict(directory, crate)
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
        if vcs_problem is not None:
            result.note(f"  FAIL: {vcs_problem}")
            ok = False

    result.passed = ok
    return result


# --------------------------------------------------------------------------
# Check: secrets, over full history
# --------------------------------------------------------------------------
# Per-scan allowlist hit counts. **Reset at the top of every `check_secrets`
# call**, because it is module-global and `--self-test` runs several scans in
# one process: without the reset, counts from a control's throwaway repository
# accumulate into the next scan's, so a dead entry in the real repository could
# be kept alive by a hit from a temporary one. That would silently defeat the
# dead-entry check, which is itself one of the guards here.
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
    ALLOWLIST_HITS.clear()
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

    largest = max(
        ((kinds[sha][1], path) for sha, path in candidates if kinds.get(sha, ("", 0))[0] == "blob"),
        default=(0, "(none)"),
    )
    result.note(f"  history: {commits} commits, {len(blobs)} blobs scanned")
    result.note(f"  coverage: {COVERAGE_LIMITS}")
    # **Printed unconditionally, including the zero.** Previously nothing was
    # printed when no blob exceeded the cap, so "nothing was skipped" was
    # reported by silence -- and silence is also what a broken size
    # computation would produce. The largest blob is named too, so the margin
    # to the cap is visible before it is crossed rather than after.
    result.note(
        f"  blobs over the {MAX_BLOB_BYTES:,}-byte cap: {len(oversized)}; "
        f"largest blob {largest[0]:,} bytes ({largest[1]})"
    )
    if oversized:
        result.note(
            f"  FAIL: {len(oversized)} blob(s) exceed the cap and were NOT scanned: "
            + ", ".join(sorted({p for _, p in oversized})[:5])
            + ". This is a FAIL rather than a note because an unscanned blob is "
            "exactly where a pasted credential would sit, and a gate that passes "
            "while skipping its largest files reports a clean history it did not "
            "measure. Raise MAX_BLOB_BYTES deliberately, or split the file."
        )
        result.passed = False
        return result

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
    worktree_skipped: list[str] = []
    worktree_oversized: list[str] = []
    for line in tracked_untracked:
        rel = line[3:].strip().strip('"')
        # **A rename entry is `R  old -> new`, and taking it whole produced a
        # path that does not exist, which was then skipped in silence.** The
        # renamed file -- the one most likely to have just been touched --
        # went unscanned while the count still went up for everything else.
        # Take the destination, which is the file actually on disk.
        if " -> " in rel:
            rel = rel.split(" -> ", 1)[1].strip().strip('"')
        candidate = repo / rel
        if not candidate.is_file():
            # Deletions land here legitimately; anything else is recorded
            # rather than dropped, so a parsing failure is visible.
            worktree_skipped.append(rel)
            continue
        if candidate.stat().st_size > MAX_BLOB_BYTES:
            # Same rule as the history path: an unscanned file is a FAIL, not
            # a note. Negligible at 64 MiB, but the two paths disagreeing is
            # how one of them quietly becomes the lenient one.
            worktree_oversized.append(rel)
            continue
        worktree_scanned += 1
        findings.extend(
            scan_bytes(candidate.read_bytes(), "worktree", rel, "(uncommitted)")
        )
    result.note(
        f"  working tree: {worktree_scanned} modified/untracked files scanned, "
        f"{len(worktree_skipped)} skipped (deleted or unreadable)"
        + (f": {worktree_skipped[:5]}" if worktree_skipped else "")
        + f", {len(worktree_oversized)} over cap"
    )
    if worktree_oversized:
        result.note(
            f"  FAIL: {len(worktree_oversized)} working-tree file(s) exceed the "
            f"{MAX_BLOB_BYTES:,}-byte cap and were NOT scanned: "
            f"{worktree_oversized[:5]}"
        )
        result.passed = False
        return result

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
# Check: packaging
#
# **Why this exists, and it is not tidiness.** Until now three places named
# the advertised target set and nothing reconciled them: a literal tuple in
# `scripts/package_release.py`, the `matrix.include` list in
# `.github/workflows/release.yml`, and the public downloads page's prose.
# docs/tasks.md row M6-C11 recorded that second packaging path and asked which
# is authoritative. The owner's answer is that **the release workflow is**, so
# `[workspace.metadata.release] advertised-targets` was brought into agreement
# with it, `package_release.py` now reads that table, and this check makes the
# agreement structural rather than a coincidence waiting to drift.
#
# **It runs locally and deliberately so.** GitHub Actions billing has blocked
# this repository since 2026-09-11, so `release.yml` has not executed at all
# and cannot be the thing that notices a divergence. This check reads the
# workflow as text on the machine running it.
#
# A triple-shaped literal, so a tuple reintroduced into the packager is seen
# whatever it is named. `x86_64-pc-windows-msvc`, `aarch64-apple-darwin`, etc.
TRIPLE_LITERAL = re.compile(r"\b(?:x86_64|aarch64|i686|armv7|riscv64gc|s390x|powerpc64le)-[a-z0-9_]+-[a-z0-9_.-]+\b")
# `target: <triple>` inside the workflow's build matrix.
# Matches ANY `target:` key at any indentation, not only matrix entries, so a
# `with: target: ...` step elsewhere in the workflow would be counted as one.
# Measured at this branch: all 4 matches are the matrix `include` entries and
# no `with: target:` exists, so the "matrix" wording is accurate today. The
# imprecision is left deliberately because it **fails closed** -- a stray
# `target:` adds an entry the declaration does not contain and the comparison
# FAILs; it can never hide a divergence. Scoping this to the matrix block
# means parsing YAML structure, which is a larger change than the fault.
WORKFLOW_MATRIX_TARGET = re.compile(r"(?m)^\s*target:\s*([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*$")
PACKAGER = "scripts/package_release.py"
RELEASE_WORKFLOW = ".github/workflows/release.yml"
SITE_RELEASES = "site/releases.js"
DECLARED_TRIPLE_RE = re.compile(r"[0-9a-z_]+(?:-[0-9a-z_.]+){2,3}")

# `site/releases.js` is loaded by every page under `site/docs/` and is the
# **machine-readable public advertisement**: it shows a release only when an
# asset exists for every triple in its own `targets` array, then labels each
# one.  `downloads.html` is prose; this file is the consumer that decides what
# the public is actually offered.  A browser cannot read `Cargo.toml` at
# runtime, so -- exactly as for `release.yml`'s matrix, which has the same
# constraint -- the literal stays and is **bound** here instead.
#
# Retiring a triple from the workflow and the manifest in one commit, with
# this file left alone, makes the site require an asset that is no longer
# built and render "No complete development release is published yet" for
# every release from then on.  Adding one has the mirror failure: the site
# never lists it.  Neither is visible to any other check.
SITE_TARGETS_ARRAY = re.compile(r"(?m)^\s*const\s+targets\s*=\s*\[([^\]]*)\]\s*;")
SITE_LABELS_ARRAY = re.compile(r"(?m)^\s*const\s+labels\s*=\s*\[([^\]]*)\]\s*;")


def site_array(source: str, pattern: re.Pattern[str]) -> list[str] | None:
    """The string items of a single-line JS array literal, or None if absent.

    None is distinct from `[]` on purpose: "the array this check binds could
    not be found" and "the array is empty" are different failures, and only
    the second could ever be a real declaration. Returning `[]` for a renamed
    or reformatted array would let it compare equal to nothing -- the
    "scanned nothing" shape docs/tasks.md M5-C11 catalogues.
    """
    found = pattern.findall(source)
    if len(found) != 1:
        return None
    return [item.strip().strip("'\"") for item in found[0].split(",")
            if item.strip()]


def site_array_count(source: str, pattern: re.Pattern[str]) -> int:
    """How many declarations of the bound array the source contains.

    Binding the *first* match was a real evasion: a second `const targets`
    later in the file -- an inner-scope shadow -- is what the rendering code
    would actually use there, and `search` never saw it, so `packaging` stayed
    green over a file whose effective list was wrong. The binding is only
    meaningful if there is exactly one thing to bind to.
    """
    return len(pattern.findall(source))


def packaging_verdict(declared: list[str], matrix: list[str],
                      packager_source: str,
                      site_source: str) -> tuple[bool, list[str]]:
    """Compare the declaration against the workflow matrix and the packager.

    Pure, so `--self-test` can drive it in both directions with recorded
    inputs. A comparison that only ever sees agreeing inputs is a comparison
    nobody has tested, which is the defect this whole file is about.
    """
    notes: list[str] = []
    ok = True
    declared_set, matrix_set = sorted(set(declared)), sorted(set(matrix))
    if not matrix_set:
        notes.append(
            f"  FAIL: no `target:` entries found in {RELEASE_WORKFLOW}. Either the "
            "workflow stopped declaring a matrix or this check's pattern no longer "
            "matches it; an empty matrix must never compare equal to anything."
        )
        return False, notes
    if declared_set != matrix_set:
        missing = [t for t in matrix_set if t not in declared_set]
        extra = [t for t in declared_set if t not in matrix_set]
        notes.append(
            f"  FAIL: the workflow matrix and the declaration disagree. Built but not "
            f"declared: {missing or 'none'}. Declared but not built: {extra or 'none'}. "
            "The release workflow is the authoritative packaging path (M6-C11), so the "
            "declaration follows it, not the reverse."
        )
        ok = False
    else:
        notes.append(
            f"  {len(declared_set)} advertised targets, and {RELEASE_WORKFLOW}'s matrix "
            f"builds exactly those: {declared_set}"
        )

    literals = sorted(set(TRIPLE_LITERAL.findall(packager_source)))
    if literals:
        notes.append(
            f"  FAIL: {PACKAGER} carries target-triple literals {literals}. It must read "
            "`advertised-targets` from the manifest; a second copy is the defect M6-C11 "
            "was filed for and M5-C11 catalogues."
        )
        ok = False
    else:
        notes.append(f"  {PACKAGER} carries no target-triple literal; it derives the set")

    # The public advertisement.  Bound rather than derived, because a browser
    # cannot read the manifest at runtime -- the same constraint as the
    # workflow matrix above, handled the same way.
    site_targets = site_array(site_source, SITE_TARGETS_ARRAY)
    site_labels = site_array(site_source, SITE_LABELS_ARRAY)
    target_decls = site_array_count(site_source, SITE_TARGETS_ARRAY)
    label_decls = site_array_count(site_source, SITE_LABELS_ARRAY)
    if target_decls > 1 or label_decls > 1:
        notes.append(
            f"  FAIL: {SITE_RELEASES} declares `const targets` {target_decls} time(s) and "
            f"`const labels` {label_decls} time(s); each must be declared exactly once. "
            "A second declaration -- an inner-scope shadow -- is what the code in that "
            "scope renders, so binding only the first would compare the wrong list and "
            "could pass over a file that advertises something else."
        )
        ok = False
    elif site_targets is None:
        notes.append(
            f"  FAIL: no `const targets = [...]` array found in {SITE_RELEASES}. Either "
            "the public advertisement stopped declaring one or this check's pattern no "
            "longer matches it; an array that cannot be found must never compare equal "
            "to the declaration."
        )
        ok = False
    elif sorted(set(site_targets)) != declared_set:
        missing = [t for t in declared_set if t not in site_targets]
        extra = [t for t in sorted(set(site_targets)) if t not in declared_set]
        notes.append(
            f"  FAIL: {SITE_RELEASES} and the declaration disagree. Declared but not "
            f"offered by the site: {missing or 'none'}. Offered but not declared: "
            f"{extra or 'none'}. The site shows a release only when an asset exists for "
            "every triple in its own array, so a declared target it does not list is "
            "never offered, and one it lists but nobody builds hides every release."
        )
        ok = False
    elif site_labels is None or len(site_labels) != len(site_targets):
        notes.append(
            f"  FAIL: {SITE_RELEASES} pairs `targets[i]` with `labels[i]` when it renders "
            f"the download list, and it declares {len(site_targets)} target(s) against "
            f"{'no labels array' if site_labels is None else str(len(site_labels)) + ' label(s)'}. "
            "A length mismatch mislabels a download or throws while rendering."
        )
        ok = False
    else:
        notes.append(
            f"  {SITE_RELEASES} advertises exactly the declared set, with "
            f"{len(site_labels)} label(s) paired to {len(site_targets)} target(s)"
        )
    return ok, notes


def check_packaging() -> Result:
    result = Result("packaging")
    try:
        declared = declared_targets()
    except ValueError as error:
        result.ran = False
        result.reason = f"no advertised-target declaration to compare against: {error}"
        return result

    workflow = REPO / RELEASE_WORKFLOW
    packager = REPO / PACKAGER
    site = REPO / SITE_RELEASES
    for path in (workflow, packager, site):
        if not path.is_file():
            result.ran = False
            result.reason = (
                f"{path.relative_to(REPO)} is missing, so the second packaging path "
                "could not be read. That is not a pass: it is the file this check exists "
                "to reconcile against."
            )
            return result

    matrix = WORKFLOW_MATRIX_TARGET.findall(workflow.read_text(encoding="utf-8"))
    result.note(f"  declared: [workspace.metadata.release] advertised-targets = {declared}")
    ok, notes = packaging_verdict(declared, matrix,
                                  packager.read_text(encoding="utf-8"),
                                  site.read_text(encoding="utf-8"))
    for line in notes:
        result.note(line)
    result.note(
        "  NOTE: this check reads the workflow as text. It has never run on a hosted "
        "runner -- Actions billing has blocked this repository since 2026-09-11 -- so "
        "agreement here is agreement between files, not evidence that the matrix "
        f"builds. {SITE_RELEASES} -- the machine-readable public advertisement -- IS "
        "compared here since M6-C18. `site/docs/downloads.html` states the platforms in "
        "prose and is still NOT machine-compared; that residue is recorded on M6-C11."
    )
    result.passed = ok
    return result


# --------------------------------------------------------------------------
# Check: repository visibility (read-only)
# --------------------------------------------------------------------------
def declared_visibility() -> str:
    """The visibility the owner declared, read from the workspace manifest.

    **The point of reading it rather than hard-coding it.** The owner has now
    explicitly requested publication (AGENTS.md; docs/tasks.md M6-C01), so the
    expected answer changed from private to public. Flipping a constant would
    have produced a check that still cannot fail for the reason it names: it
    would assert "public" whatever the repository actually is, and if the
    owner reverted the decision the check would go on passing on a repository
    that no longer matches the rule. So the expectation is data in
    `[workspace.metadata.release] repository-visibility` and this check is a
    **comparison of two observations** -- what the owner declared, and what
    GitHub answers -- which can disagree in either direction.

    Raises rather than defaulting. A default would be a second source of
    truth, and `advertised-targets` in the same table exists precisely because
    a second copy of a declaration is this repository's recurring defect
    (M5-C11).
    """
    declared = release_table().get("repository-visibility")
    if declared not in VISIBILITY_VALUES:
        raise ValueError(
            f"`repository-visibility` is {declared!r}; it must be one of "
            f"{sorted(VISIBILITY_VALUES)}"
        )
    return declared


def release_table() -> dict:
    """`[workspace.metadata.release]`, the single referent this gate reads."""
    table = tomllib.loads((REPO / "Cargo.toml").read_text(encoding="utf-8"))
    release = table.get("workspace", {}).get("metadata", {}).get("release")
    if release is None:
        raise ValueError("root Cargo.toml carries no [workspace.metadata.release] table")
    return release


def declared_targets() -> list[str]:
    """The advertised set. Raises rather than defaulting, for the same reason
    `declared_visibility` does: a default is a second source of truth."""
    targets = release_table().get("advertised-targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("`advertised-targets` must be a non-empty list")
    if not all(isinstance(t, str) for t in targets):
        raise ValueError("`advertised-targets` must be a list of strings")
    # Same acceptance rule as the other two readers of this declaration; see
    # docs/tasks.md M6-C20 for why they had three.
    duplicates = sorted({t for t in targets if targets.count(t) > 1})
    if duplicates:
        raise ValueError(f"`advertised-targets` repeats {duplicates}")
    malformed = [t for t in targets if not DECLARED_TRIPLE_RE.fullmatch(t)]
    if malformed:
        raise ValueError(f"`advertised-targets` are not target triples: {malformed}")
    return sorted(targets)


def observed_visibility(payload: dict) -> str | None:
    """GitHub's answer reduced to `public`/`private`, or None if unreadable.

    `internal` is an organisation-scoped form of not-public and is folded into
    `private` rather than silently becoming a third value nothing compares.
    """
    private = payload.get("private")
    visibility = payload.get("visibility")
    if private is True or visibility in ("private", "internal"):
        return "private"
    if private is False or visibility == "public":
        return "public"
    return None


def classify_visibility(payload: dict, expected: str) -> tuple[bool, str]:
    """Does GitHub's answer match the declared expectation?

    Split out from the network call so `--self-test` can drive it with
    recorded payloads against both expectations. A classifier that only ever
    sees one answer is a classifier nobody has tested, and one that only ever
    sees one *expectation* is an inverted constant wearing a comparison's
    clothes.
    """
    name = payload.get("full_name", "?")
    private = payload.get("private")
    visibility = payload.get("visibility")
    observed = observed_visibility(payload)
    described = f"{name}: private={private} visibility={visibility}"
    if observed is None:
        return False, (
            f"{described} -- the payload carries neither `private` nor `visibility`, "
            "so visibility is UNKNOWN and UNKNOWN is never a match."
        )
    if observed != expected:
        return False, f"{described} -- observed {observed}, declared {expected}"
    return True, f"{described} -- observed {observed}, matching the declared {expected}"


def check_visibility() -> Result:
    result = Result("visibility")
    try:
        expected = declared_visibility()
    except (ValueError, OSError, tomllib.TOMLDecodeError) as error:
        result.ran = False
        result.reason = f"no declared visibility to compare against: {error}"
        return result
    result.note(f"  declared: [workspace.metadata.release] repository-visibility = {expected!r}")

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

    matches, description = classify_visibility(payload, expected)
    result.note(f"  {description}")
    result.note(
        f"  created={payload.get('created_at')} pushed={payload.get('pushed_at')} "
        f"forks={payload.get('forks_count')} stars={payload.get('stargazers_count')}"
    )
    if not matches:
        observed = observed_visibility(payload) or "UNKNOWN"
        result.note(
            f"  FAIL: the repository is {observed} and the declaration in root "
            f"Cargo.toml says {expected}. One of the two is wrong, and this check "
            "does NOT decide which -- it deliberately changes no setting, because "
            "visibility is the owner's decision. If the repository should be "
            f"{expected}, change it on GitHub; if the declaration is out of date, "
            "change it here and in AGENTS.md **in the same commit**, so the rule "
            "and the reality never disagree silently again."
        )
    if expected == "public":
        result.note(
            "  NOTE: a public repository makes a committed secret unrecoverable. "
            "Deleting it, rewriting history or making the repository private later "
            "undoes nothing already cloned, cached, forked or indexed. Treat every "
            "secret-scan finding in this history as disclosed and rotate it rather "
            "than merely removing it -- and read the `secrets` check's 0 findings as "
            "'none in these formats', which is what its coverage line says."
        )
    result.passed = matches
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
        proc = run([binary, "deny", *OFFLINE, "check", "licenses", "--config", str(config)])
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
    """The crate floor must actually fire on a collapsed graph.

    **Rewritten; the previous version could not fail.** It asserted
    `CRATES_FLOOR > 0` and printed a hard-coded "361 measured at 6fad2fb" --
    a string literal, not a measurement -- while its docstring claimed to
    drive the comparison. See `crate_floor_verdict` for why that is M5-C11's
    eleventh instance.

    This version drives the real function three ways: a collapsed count (0,
    as an empty or broken graph would give) must be rejected, the boundary
    just below the floor must be rejected, and **the count cargo-deny
    actually reports right now** must be accepted. The last one is measured
    from the live graph rather than quoted, so if the workspace ever shrank
    below the floor this control goes red and names the real figure instead of
    a remembered one.
    """
    collapsed_ok, _ = crate_floor_verdict(0)
    boundary_ok, _ = crate_floor_verdict(CRATES_FLOOR - 1)
    exact_ok, _ = crate_floor_verdict(CRATES_FLOOR)
    if collapsed_ok:
        return False, "a graph of 0 crates cleared the floor; the floor cannot fire"
    if boundary_ok:
        return False, f"{CRATES_FLOOR - 1} crates cleared a floor of {CRATES_FLOOR}"
    if not exact_ok:
        return False, f"{CRATES_FLOOR} crates did not clear a floor of {CRATES_FLOOR}"

    # The live figure, measured rather than quoted.
    binary = cargo_deny_binary()
    if binary is None:
        return False, "cargo-deny absent, so the live half of this control DID NOT RUN"
    listing = run([binary, "deny", *OFFLINE, "list", "-l", "crate"])
    if listing.returncode != 0:
        return False, (
            "`cargo deny list` failed, so this control could not measure the live "
            f"graph: {listing.stderr.strip().splitlines()[:1]}"
        )
    live = len([line for line in listing.stdout.splitlines() if "@" in line])
    live_ok, live_note = crate_floor_verdict(live)
    if not live_ok:
        return False, (
            f"the live graph is {live} crates, which does NOT clear the floor of "
            f"{CRATES_FLOOR}: {live_note.strip()}"
        )
    return True, (
        f"`crate_floor_verdict` rejects 0 and {CRATES_FLOOR - 1}, accepts "
        f"{CRATES_FLOOR}, and accepts the live graph of **{live}** crates measured "
        "now from `cargo deny list` -- so the floor has headroom in both directions "
        "and both branches were exercised against the function the check uses"
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
    total = 0
    for name, pattern in SECRET_PATTERNS.items():
        fixtures = SECRET_CONTROL_FIXTURES[name]
        if not fixtures:
            return False, f"{name} has an empty fixture tuple, so it is untested"
        for index, fixture in enumerate(fixtures):
            total += 1
            if not pattern.search(fixture):
                silent.append(f"{name}[{index}]")
    if silent:
        return False, f"patterns that did NOT match their own fixture: {silent}"
    return True, (
        f"all {len(SECRET_PATTERNS)} patterns matched every one of their "
        f"{total} synthetic fixtures, including both the with-username and the "
        "empty-username URL authority forms"
    )


def control_secret_patterns_are_not_universal() -> tuple[bool, str]:
    """No pattern may match innocuous text.

    A scanner that flags everything produces a finding list nobody reads, and
    an unread list is indistinguishable from a clean one -- the same defect
    from the other side.
    """
    # Every line here is text that must NOT be flagged. The last four were
    # added after the Fable review found the three newest patterns firing on
    # them: a pattern that cries wolf on prose and documentation placeholders
    # produces a finding list nobody reads, and an unread list is
    # indistinguishable from a clean one -- the same defect from the other
    # side. They are kept as fixtures so the tightenings cannot regress.
    benign = b"""
    // Ordinary source. redis://127.0.0.1:63790/ is the test Redis URL.
    let url = "redis://127.0.0.1:6379/";
    const TOKEN_HEADER: &str = "authorization";
    fn secret_len() -> usize { 32 }
    password = ""
    base64 payload: SGVsbG8gd29ybGQ=
    Prose: the requirepass directive sets a password on the Redis primary.
    Docs: send Authorization: Bearer YOUR_ACCESS_TOKEN_HERE_PLEASE with each call.
    Docs: send Authorization: Bearer TOKEN with each call.
    # requirepass
    """
    noisy = [name for name, p in SECRET_PATTERNS.items() if p.search(benign)]
    if noisy:
        return False, f"patterns that fired on benign text: {noisy}"
    return True, (
        "no pattern fired on benign text containing a passwordless redis URL, the "
        "word `secret`, an empty password, base64, **prose mentioning "
        "`requirepass`, a commented-out `requirepass`, and two SHOUTING_PLACEHOLDER "
        "Bearer headers** -- so a finding means something"
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
                    b'token = "' + SECRET_CONTROL_FIXTURES["github-token"][0] + b'"\n'
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

    Both sides are measured at run time and printed, and **this docstring
    quotes no figure on purpose.** It used to state "779 commits and 4144
    blobs at full depth" as fact beside a printed line that measured -- the
    same split the crate-floor control had, a number a reader trusts sitting
    where nothing recomputes it. A figure in prose goes stale in silence; a
    figure in the output cannot.
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
    # The full-depth figures are measured here too, rather than quoted. A
    # remembered "4144 blobs" beside a live shallow figure is the same
    # hard-coded-number defect the crate-floor control carried.
    full_commits = subprocess.run(
        ["git", "rev-list", "--all", "--count"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    ).stdout.strip()
    # `history_blobs` returns every named object, trees included, so this is an
    # object count and is labelled as one. The shallow figure beside it is a
    # blob count, from the scan itself; the two are not the same measure and
    # printing both as "blobs" invited a false comparison.
    full_objects = len(history_blobs(REPO))
    return True, (
        f"a depth-1 clone has {commits} commit and {blobs} blobs scanned, below the "
        f"{HISTORY_BLOBS_FLOOR} floor; full depth right now is {full_commits} commits "
        f"and {full_objects} named objects (trees included, so an upper bound on "
        "blobs) -- so a shallow CI checkout fails the gate instead of reporting a "
        "clean history"
    )


def control_working_tree_branch_is_scanned() -> tuple[bool, str]:
    """An uncommitted secret must be found, including through a real rename.

    The working-tree branch had no control at all, which is how its
    rename-parsing bug survived: `git status --porcelain` writes a rename as
    `R  old -> new`, the whole string was taken as a path, and the resulting
    non-existent file was skipped in silence.

    **The first version of this control could not fail for the rename it
    named, and that is M5-C11's twelfth instance.** It wrote a one-line file,
    `git mv`d it, then *replaced the entire content* with the fixture and ran
    `git add -A`. Git's rename detection needs roughly 50% similarity, so
    porcelain emitted `A renamed.toml` / `D to-rename.toml` and **never an
    `R ... -> ...` line at all**. The `" -> "` branch was never entered:
    reverting the parser fix left this control green. Its message named a
    mechanism it had not exercised -- the same tell as instances ten and
    eleven, in the control added to close the previous round's minor.

    The tell was in the control's own output and went unread: the scan printed
    `1 skipped`, which a real rename does not produce, and the control never
    looked at that number. So it does now.

    Four properties, each asserted rather than assumed:

      1. the file keeps enough content for git to detect the rename, and
         porcelain is **asserted** to contain an `R` line with ` -> ` before
         anything is scanned -- if git ever stops detecting it, this control
         fails instead of quietly testing the `A`/`D` path;
      2. **no `git add -A`**, so the untracked file stays `??` and the
         modified file stays ` M`. Staging everything made the "untracked"
         case an `A` entry, so that half was untested too;
      3. all three secrets are reported as `worktree` findings;
      4. the scan reports **0 skipped** -- the figure that would have exposed
         the original defect immediately.
    """
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "wt"
        repo.mkdir()
        base = {"cwd": str(repo), "capture_output": True, "text": True, "check": True, "timeout": 120}
        subprocess.run(["git", "init", "-q", "-b", "main"], **base)
        subprocess.run(["git", "config", "user.email", "control@example.invalid"], **base)
        subprocess.run(["git", "config", "user.name", "M6-04 control"], **base)

        # Substantial, stable content: the rename is only detectable because
        # most of the file survives it.
        body = "".join(f"line {i} of stable content git can match on\n" for i in range(40))
        (repo / "README.md").write_text("harmless\n", encoding="utf-8")
        (repo / "tracked.toml").write_text(body, encoding="utf-8")
        (repo / "to-rename.toml").write_text(body, encoding="utf-8")
        subprocess.run(["git", "add", "-A"], **base)
        subprocess.run(["git", "commit", "-qm", "clean base"], **base)

        # Untracked -- left unstaged, so it appears as `??`.
        (repo / "untracked.toml").write_bytes(
            b'token = "' + SECRET_CONTROL_FIXTURES["gitlab-pat"][0] + b'"\n'
        )
        # Modified tracked -- appended, left unstaged, so it appears as ` M`.
        with (repo / "tracked.toml").open("ab") as handle:
            handle.write(b'token = "' + SECRET_CONTROL_FIXTURES["npm-token"][0] + b'"\n')
        # Renamed tracked. `git mv` stages the rename; appending keeps the
        # similarity high enough for git to report it as one.
        subprocess.run(["git", "mv", "to-rename.toml", "renamed.toml"], **base)
        with (repo / "renamed.toml").open("ab") as handle:
            handle.write(
                b'url = "' + SECRET_CONTROL_FIXTURES["url-inline-password"][1] + b'"\n'
            )

        porcelain = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        ).stdout
        rename_lines = [
            line for line in porcelain.splitlines() if line[:1] == "R" and " -> " in line
        ]
        untracked_lines = [line for line in porcelain.splitlines() if line.startswith("??")]
        if not rename_lines:
            return False, (
                "git did not report a rename, so the ` -> ` parsing branch is NOT "
                f"exercised and this control proves nothing. Porcelain was: "
                f"{porcelain.splitlines()}"
            )
        if not untracked_lines:
            return False, (
                "no `??` entry, so the untracked branch is not exercised: "
                f"{porcelain.splitlines()}"
            )

        result = check_secrets(repo=repo)

    if result.passed is not False:
        return False, f"uncommitted secrets were not reported at all: {result.lines}"

    worktree_line = next(
        (line for line in result.lines if line.strip().startswith("working tree:")), ""
    )
    skipped = re.search(r"(\d+) skipped", worktree_line)
    if not skipped:
        return False, f"could not read a skipped count from {worktree_line!r}"
    if int(skipped.group(1)) != 0:
        return False, (
            f"the scan skipped {skipped.group(1)} working-tree file(s) and still "
            "passed this control. A skipped file is how the rename bug hid: "
            f"{worktree_line.strip()}"
        )

    found = " ".join(result.lines)
    missing = [
        name
        for name, needle in (
            ("untracked", "untracked.toml"),
            ("modified", "tracked.toml"),
            ("renamed", "renamed.toml"),
        )
        if needle not in found
    ]
    if missing:
        return False, (
            f"these working-tree cases were NOT reported: {missing}. Findings were: "
            f"{[line.strip() for line in result.lines if 'worktree' in line]}"
        )
    return True, (
        f"git reported a real rename ({rename_lines[0].strip()}) and a `??` entry, and "
        "an untracked file, a modified tracked file and a renamed tracked file each "
        "carrying a different synthetic credential are all reported as `worktree` "
        "findings, with **0 skipped** -- so the ` -> ` branch was actually entered "
        "rather than named"
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
        f"none of the {len(SECRET_PATTERNS)} patterns match this file's own source, "
        "so the scanner scans itself for real and needs no exception for its own path"
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
    intruder = SECRET_CONTROL_FIXTURES[allow.pattern_name][0]
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


def control_packaging_matrix_divergence_is_caught() -> tuple[bool, str]:
    """A workflow matrix that disagrees with the declaration must go red.

    Driven with recorded inputs in four directions, because this check's whole
    value is that it fires when two files drift apart, and the live repository
    only ever shows it the agreeing case. An empty matrix is included because
    a pattern that stopped matching would otherwise compare equal to nothing
    and pass -- the "scanned nothing" shape of M5-C11.
    """
    declared = declared_targets()
    clean = (REPO / PACKAGER).read_text(encoding="utf-8")
    site = (REPO / SITE_RELEASES).read_text(encoding="utf-8")
    cases = [
        ("identical", declared, True),
        ("one target dropped from the matrix", declared[:-1], False),
        ("an extra target built but not declared", declared + ["i686-unknown-linux-gnu"], False),
        ("an empty matrix", [], False),
    ]
    for label, matrix, want in cases:
        got, notes = packaging_verdict(declared, matrix, clean, site)
        if got != want:
            return False, (
                f"case {label!r}: verdict {got}, expected {want}. Notes: "
                f"{[n.strip() for n in notes]}"
            )
    return True, (
        f"the comparison accepts the live {len(declared)}-target matrix and rejects a "
        "dropped target, an undeclared extra, and an empty matrix -- so a matrix that "
        "no longer parses cannot pass by matching nothing"
    )


def control_packaging_a_second_copy_of_the_set_is_caught() -> tuple[bool, str]:
    """A target-triple literal reintroduced into the packager must go red.

    This is the control for the defect the change removed: `package_release.py`
    used to carry `TARGETS = (...)` as a literal tuple beside the workflow's
    matrix, with nothing reconciling them (M6-C11). Reverting that must be
    caught rather than merely discouraged by a comment.
    """
    declared = declared_targets()
    clean = (REPO / PACKAGER).read_text(encoding="utf-8")
    site = (REPO / SITE_RELEASES).read_text(encoding="utf-8")
    clean_ok, clean_notes = packaging_verdict(declared, declared, clean, site)
    if not clean_ok:
        return False, (
            "the real packager does not pass its own check, so a red below would not "
            f"be attributable to the planted literal: {[n.strip() for n in clean_notes]}"
        )
    planted = clean + '\nTARGETS = ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin")\n'
    planted_ok, planted_notes = packaging_verdict(declared, declared, planted, site)
    if planted_ok:
        return False, (
            "a literal target tuple appended to the packager's source did NOT turn the "
            "check red. The literal scan cannot fire."
        )
    if not any("target-triple literals" in note for note in planted_notes):
        return False, f"it went red for another reason: {[n.strip() for n in planted_notes]}"
    return True, (
        "the real `scripts/package_release.py` passes with 0 triple literals, and the "
        "same source with a two-triple `TARGETS` tuple appended goes red naming the "
        "literals it found -- so the packager reading the manifest is asserted, not "
        "assumed"
    )


def control_packaging_site_list_divergence_is_caught() -> tuple[bool, str]:
    """The public advertisement drifting from the declaration must go red.

    This is the control for M6-C18. `site/releases.js` decides what the public
    is actually offered -- it shows a release only when an asset exists for
    every triple in its own array -- and nothing compared it to the
    declaration, so retiring a target would have made the site render "No
    complete development release is published yet" for every release, with
    every other check still green.

    Driven with recorded sources in both directions, including the two shapes
    that could pass by measuring nothing: an array this check can no longer
    find, and a labels array that no longer pairs with the targets it labels.
    """
    declared = declared_targets()
    clean_packager = (REPO / PACKAGER).read_text(encoding="utf-8")
    clean_site = (REPO / SITE_RELEASES).read_text(encoding="utf-8")

    def site_with(targets: list[str], labels: list[str] | None = None) -> str:
        body = ", ".join(f"'{t}'" for t in targets)
        names = labels if labels is not None else [f"Label {i}" for i in range(len(targets))]
        return (f"  const targets = [{body}];\n"
                f"  const labels = [{', '.join(repr(n) for n in names)}];\n")

    baseline, notes = packaging_verdict(declared, declared, clean_packager, clean_site)
    if not baseline:
        return False, (
            "the real site file does not pass its own check, so a red below would not "
            f"be attributable to the planted drift: {[n.strip() for n in notes]}"
        )

    cases = [
        ("identical to the declaration", site_with(declared), True),
        ("a declared target the site never offers", site_with(declared[:-1]), False),
        ("a target the site offers that nobody builds",
         site_with(declared + ["i686-unknown-linux-gnu"]), False),
        ("an empty array", site_with([]), False),
        ("the array renamed so the pattern cannot find it",
         clean_site.replace("const targets =", "const releaseTargets ="), False),
        ("labels no longer paired with targets",
         site_with(declared, labels=["only one label"]), False),
        ("a later shadowing `const targets` after the real one",
         clean_site + "\n  const targets = ['i686-unknown-linux-gnu'];\n", False),
    ]
    # Each red case must go red FOR ITS OWN REASON: a case that happened to be
    # caught by a sibling rule would credit this control with a rule it never
    # exercised.  The marker is a phrase only that rule's FAIL line contains.
    reasons = {
        "a later shadowing `const targets` after the real one": "each must be declared exactly once",
    }
    for label, source, want in cases:
        got, case_notes = packaging_verdict(declared, declared, clean_packager, source)
        if got != want:
            return False, (
                f"case {label!r}: verdict {got}, expected {want}. Notes: "
                f"{[n.strip() for n in case_notes]}"
            )
        marker = reasons.get(label)
        if marker and not any(marker in n for n in case_notes if "FAIL" in n):
            return False, (
                f"case {label!r} went red, but not for its own reason (expected a FAIL "
                f"naming {marker!r}): {[n.strip() for n in case_notes if 'FAIL' in n]}"
            )
    return True, (
        f"the comparison accepts the live {len(declared)}-target advertisement and "
        "rejects a dropped target, an offered-but-unbuilt extra, an empty array, an "
        "array it can no longer find, labels that no longer pair with their "
        "targets, and a later shadowing declaration (red for its own reason: "
        "declared more than once) -- so a renamed, emptied or shadowed array "
        "cannot pass by binding the wrong thing"
    )


def control_packaging_reads_the_manifest_not_a_tuple() -> tuple[bool, str]:
    """The packager's accepted set must follow the declaration.

    The scan above proves no literal is present; this proves the value the
    packager actually uses comes from the manifest, by importing it and
    comparing against an independent read of the same table.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("m6_package_release", REPO / PACKAGER)
    if spec is None or spec.loader is None:
        return False, f"could not load {PACKAGER}, so this control DID NOT RUN"
    module = importlib.util.module_from_spec(spec)
    sys.modules["m6_package_release"] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:  # noqa: BLE001 - a broken import is a failed control
        return False, f"{PACKAGER} could not be imported, so this control DID NOT RUN: {error}"
    accepted = sorted(module.advertised_targets())
    declared = declared_targets()
    if accepted != declared:
        return False, (
            f"the packager accepts {accepted} while the manifest declares {declared}"
        )
    if not hasattr(module, "advertised_targets"):
        return False, "the packager no longer exposes a manifest reader"
    return True, (
        f"`package_release.advertised_targets()` returns exactly the {len(declared)} "
        "triples an independent read of [workspace.metadata.release] gives, so the "
        "packager and this gate resolve the same declaration rather than two copies"
    )


def control_visibility_classifier_goes_both_ways() -> tuple[bool, str]:
    """The check must redden when reality disagrees with the declaration.

    **This is the control for the change the owner's publication decision
    forced, and the thing it exists to refuse is an inverted constant.** The
    expected answer moved from private to public; a check that simply asserted
    "public" would pass on any repository GitHub called public and would go on
    passing if the declaration were later reverted -- a check that cannot go
    red for the reason it names.

    So every recorded payload is driven against **both** declarations, and the
    required answer is `observed == declared` in all eight cells: public
    matches public and fails private, private matches private and fails
    public. A classifier hard-wired to either answer fails four of them. This
    is the `assert_eq!` whose halves move together (M5-C10), avoided by
    varying the two halves independently.
    """
    payloads = [
        ("private", {"full_name": "o/private-repo", "private": True, "visibility": "private"}),
        ("public", {"full_name": "o/public-repo", "private": False, "visibility": "public"}),
        # `internal` folds into private; recorded so the fold is exercised
        # rather than assumed.
        ("private", {"full_name": "o/internal", "private": False, "visibility": "internal"}),
        (None, {"full_name": "o/malformed"}),
    ]
    agreeing = 0
    disagreeing = 0
    for observed, payload in payloads:
        for declared in VISIBILITY_VALUES:
            want = observed == declared  # None never equals a declared value
            got, detail = classify_visibility(payload, declared)
            if got != want:
                return False, (
                    f"{payload.get('full_name')} observed={observed} declared={declared}: "
                    f"classifier said {got}, expected {want} ({detail})"
                )
            if want:
                agreeing += 1
            else:
                disagreeing += 1
    if agreeing == 0 or disagreeing == 0:
        return False, (
            f"the case matrix produced {agreeing} matching and {disagreeing} "
            "mismatching cells; a matrix with none of one kind proves nothing"
        )
    return True, (
        f"{len(payloads)} recorded payloads x {len(VISIBILITY_VALUES)} declared "
        f"expectations = {agreeing + disagreeing} cells, all correct: {agreeing} "
        f"agree and {disagreeing} disagree, so a *public* repository fails a "
        "`private` declaration AND a *private* repository fails the `public` one "
        "now declared -- the check compares two observations rather than asserting "
        "a constant. A payload carrying neither field is UNKNOWN and matches "
        "neither declaration."
    )


def control_visibility_declaration_is_read_not_assumed() -> tuple[bool, str]:
    """`declared_visibility` must read the manifest, and refuse junk.

    Without this, `classify_visibility`'s matrix above could be perfect while
    the expectation fed to it in a real run came from somewhere other than the
    declaration -- which is the whole mechanism.
    """
    live = declared_visibility()
    if live not in VISIBILITY_VALUES:
        return False, f"the live declaration is {live!r}, which is not a valid value"
    source = Path(__file__).read_text(encoding="utf-8")
    if "expected = declared_visibility()" not in source:
        return False, (
            "`check_visibility` no longer obtains its expectation from "
            "`declared_visibility()`, so this control is testing a function the "
            "check does not use"
        )
    text = (REPO / "Cargo.toml").read_text(encoding="utf-8")
    if f'repository-visibility = "{live}"' not in text:
        return False, (
            f"`declared_visibility()` returned {live!r} but root Cargo.toml does not "
            "contain that assignment, so the value did not come from the manifest"
        )
    # And the parser must refuse a value it cannot compare, rather than
    # defaulting to one of them.
    for junk in ('repository-visibility = "secret"', "# no key"):
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "Cargo.toml"
            probe.write_text(
                "[workspace]\nmembers = []\n\n[workspace.metadata.release]\n" + junk + "\n",
                encoding="utf-8",
            )
            table = tomllib.loads(probe.read_text(encoding="utf-8"))
            value = table["workspace"]["metadata"]["release"].get("repository-visibility")
            if value in VISIBILITY_VALUES:
                return False, f"{junk!r} produced the comparable value {value!r}"
    return True, (
        f"the expectation is read from root Cargo.toml (`repository-visibility = "
        f'"{live}"`, found verbatim in the file) rather than hard-coded, and a '
        "declaration of an uncomparable value or of nothing at all yields no "
        "expectation rather than defaulting to one"
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


def control_deps_licence_scope_covers_every_target() -> tuple[bool, str]:
    """A crate some advertised target builds but cargo-deny skips turns `deps` red.

    Uses the real graphs, then withdraws from cargo-deny's checked set one
    crate that only one advertised target reaches -- the shape of a
    target-specific dependency falling out of scope -- and requires the rule to
    fail naming that target and crate.  An empty reach must fail the floor
    rather than pass vacuously, and the real, unmodified inputs must pass.
    """
    binary = cargo_deny_binary()
    if binary is None:
        return False, "cargo-deny absent, so this control DID NOT RUN"
    checked = checked_registry_crates(binary)
    if checked is None:
        return False, "cargo-deny's JSON listing did not parse; the control did not run"
    lock = lockfile_registry_crates((REPO / "Cargo.lock").read_text(encoding="utf-8"))
    reach = {target: target_reach(target) for target in declared_targets()}
    if any(r is None for r in reach.values()):
        return False, "`cargo tree` failed for an advertised target; the control did not run"
    real_ok, real_notes = licence_scope_verdict(lock, checked, reach)
    if not real_ok:
        return False, "the real inputs fail: " + " | ".join(n.strip() for n in real_notes)
    only_one = None
    for target, reached in sorted(reach.items()):
        others = set().union(*(r for t, r in reach.items() if t != target))
        specific = sorted(reached - others)
        if specific:
            only_one = (target, specific[0])
            break
    if only_one is None:
        return False, "no crate is specific to one advertised target; the control cannot plant"
    target, crate = only_one
    ok, notes = licence_scope_verdict(lock, checked - {crate}, reach)
    name = f"{crate[0]}@{crate[1]}"
    if ok or not any("FAIL" in n and target in n and name in n for n in notes):
        return False, f"{name} withdrawn from the checked set: the rule did not fail naming {target}"
    empty_ok, _ = licence_scope_verdict(lock, checked, {t: set() for t in reach})
    if empty_ok:
        return False, "an empty reach for every target passed; the floor did not fire"
    return True, (
        f"real graphs pass; withdrawing {name} (reached only on {target}) fails naming "
        "both; an empty reach fails the floor"
    )


def control_provenance_requires_every_upstream_commit() -> tuple[bool, str]:
    """A vendored crate that stops recording its upstream commit turns `provenance` red.

    Runs the real check over a throwaway copy of `Cargo.lock` and `vendor/`,
    first unmodified (it must PASS, or the copies below prove nothing), then
    with each of three defeats applied to one crate at a time: the file
    deleted, the commit replaced by a non-hash, and the file borrowed from a
    sibling crate.  Each must FAIL, and FAIL on that crate's line.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copy2(REPO / "Cargo.lock", root / "Cargo.lock")
        shutil.copytree(REPO / "vendor", root / "vendor")
        baseline = check_provenance(root)
        if not baseline.passed:
            return False, "the unmodified copy does not pass: " + " | ".join(
                line.strip() for line in baseline.lines if "FAIL" in line
            )
        defeats = []
        for crate in VENDORED:
            vcs = root / "vendor" / crate / ".cargo_vcs_info.json"
            original = vcs.read_bytes()
            sibling = next(c for c in VENDORED if c != crate)
            cases = (
                ("deleted", None),
                ("sha replaced", original.replace(b'"sha1": "', b'"sha1": "not-a-commit-')),
                (
                    f"copied from {sibling}",
                    (root / "vendor" / sibling / ".cargo_vcs_info.json").read_bytes(),
                ),
            )
            for label, content in cases:
                if content is None:
                    vcs.unlink()
                else:
                    vcs.write_bytes(content)
                verdict = check_provenance(root)
                named = any("FAIL" in line and f"vendor/{crate}" in line for line in verdict.lines)
                if verdict.passed or not named:
                    return False, (
                        f"vendor/{crate} with its .cargo_vcs_info.json {label}: provenance "
                        f"{'PASSED' if verdict.passed else 'failed without naming the crate'}"
                    )
                defeats.append(f"{crate}:{label}")
                vcs.write_bytes(original)
    return True, (
        f"unmodified copy passes; {len(defeats)} defeats across {len(VENDORED)} "
        "patched crates each FAIL naming the crate"
    )


CONTROLS: dict[str, list[tuple[str, object]]] = {
    "provenance": [
        (
            "a patched crate without its upstream commit turns provenance red",
            control_provenance_requires_every_upstream_commit,
        ),
    ],
    "deps": [
        ("a licence outside the allowlist turns the policy red", control_deps_fails_closed),
        ("the crate floor can still fire", control_deps_empty_graph_would_not_pass),
        (
            "every crate an advertised target builds is licence-checked",
            control_deps_licence_scope_covers_every_target,
        ),
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
            "uncommitted and renamed working-tree files are scanned",
            control_working_tree_branch_is_scanned,
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
    "packaging": [
        (
            "a workflow matrix that disagrees with the declaration",
            control_packaging_matrix_divergence_is_caught,
        ),
        (
            "a target tuple reintroduced into the packager",
            control_packaging_a_second_copy_of_the_set_is_caught,
        ),
        (
            "the packager resolves the manifest, not a copy",
            control_packaging_reads_the_manifest_not_a_tuple,
        ),
        (
            "the public advertisement disagreeing with the declaration",
            control_packaging_site_list_divergence_is_caught,
        ),
    ],
    "visibility": [
        (
            "observed and declared are compared in all eight cells",
            control_visibility_classifier_goes_both_ways,
        ),
        (
            "the expectation is read from the manifest, not hard-coded",
            control_visibility_declaration_is_read_not_assumed,
        ),
        ("the check cannot change a repository setting", control_visibility_is_read_only),
    ],
}

CHECKS = {
    "deps": check_deps,
    "packaging": check_packaging,
    "provenance": check_provenance,
    "secrets": check_secrets,
    "visibility": check_visibility,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="append", choices=sorted(CHECKS), help="run only these")
    parser.add_argument("--self-test", action="store_true", help="run the positive controls")
    parser.add_argument("--list-checks", action="store_true")
    parser.add_argument(
        "--no-offline",
        action="store_true",
        help=(
            "let cargo-deny reach the network. Default is --offline, which needs a "
            "populated CARGO_HOME: run `cargo fetch --locked` first, or pass this."
        ),
    )
    args = parser.parse_args()

    global OFFLINE
    if args.no_offline:
        OFFLINE = []

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
            print(f"NOTE: checks with no positive control: {unguarded}.\n")
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
