#!/usr/bin/env python3
"""M6-01 release artifact: assemble one bundle, then check it as a stranger would.

Scope, stated before anything else
----------------------------------
This script produces and checks a release bundle for **one** target triple --
the one it is run on.  It makes no claim about any other OS or architecture.
`docs/testing.md`'s release-artifact gate asks for "every advertised
OS/architecture".  **"Advertised" now resolves to exactly one place**:
`[workspace.metadata.release] advertised-targets` in the root `Cargo.toml`,
declared by the owner.  This file contains no copy of that set -- it reads it,
and the `targets` check requires the manifest, `cargo metadata` and the set a
bundle froze into its `PROVENANCE.txt` to agree.  A bundle this script produces
is still evidence for its own `target` field and for nothing else, and
`targets` says so by naming, in every green run, the declared triples the
bundle does **not** cover.  Which of those triples this host can link and
execute, and by what route, is docs/tasks.md row M6-C13.

What the gate is actually for
-----------------------------
The point of a release artifact check is that the artifact works on a machine
that is **not the build machine**.  Every check here therefore runs against the
*unpacked bundle*, never against `target/` and never through `cargo run`:

  `checksums`   Every file in the bundle hashes to what `SHA256SUMS` records,
                and every file present is listed.  A digest proves the bytes.
  `provenance`  What *produced* the bytes: commit, tracked-diff and
                worktree-status digests, toolchain, build command, and the
                source-copy digest, cross-checked against the
                `scripts/m7-local-source-parity-build.sh` receipt.  A recorded
                hash proves the bytes; it does not prove what produced them,
                so the two are separate checks and the second is the harder
                one.
  `notices`     Third-party licence notices, **generated** from the bundled
                `Cargo.lock` rather than hand-written, and re-derived at check
                time from that same lockfile.  A hand-written NOTICE goes
                stale silently; a generated one that is re-derived cannot.
  `assets`      The required runtime assets are in the bundle and work.
                `tunnel-deadman` is the sharp case: `resolve_sentinel` looks
                for it *beside the running executable*, and its absence is a
                `degraded` doctor result and a one-line warning -- not an
                error.  A bundle that omits it ships a client whose process
                containment is off, announced only by a one-line warning the
                first time an export arms a sentinel.  The check replays that
                resolution rule and then **executes** the result, which is the
                step the product deliberately does not take.  Since M6-C08 the
                product requires a regular file with an execute bit, so it now
                rejects a zero-byte decoy too; what it still cannot do is tell
                an executable *script* of the right name from the sentinel,
                because that needs running the file and `doctor` promises to
                start nothing.  Executing it here is affordable and is the
                whole point of checking at assembly time.
  `cli`         `--help`, `--version`, both `check-config` forms and
                `check-serve-config` on every bundled `*-relay.toml`,
                executed from the unpacked bundle and asserting **content**,
                not exit status.  An exit code of 0 from a binary that
                printed nothing would pass an exit-status check.  The serving
                dry run is separate because legacy `check-config` parses a
                different type and cannot validate a serving document -- CI's
                own comment records that an example failing relay startup
                would otherwise ship green -- and it carries its own witness
                so a control corrupting a client example cannot credit it.
  `targets`     Which advertised set this bundle is one member of, read from
                the owner's declaration rather than from anything in this
                file, and cross-read by `cargo metadata` so a fault in this
                script's parser cannot hide.  A green result always names the
                declared targets this bundle does not cover, because "the
                bundle is sound" and "the set is covered" are different claims
                and conflating them is what M6-01 could not do for want of a
                declared set.
  `portability` Every bundled executable's dynamic dependencies resolve to
                system paths.  An artifact that links back to a path inside
                the build tree works only beside `target/`, which is exactly
                the failure this gate exists to catch, and it is invisible to
                every other check here because the binary runs fine *here*.

Why every check carries a control
---------------------------------
docs/tasks.md row M5-C11 holds this repository's running list of checks whose
success and whose non-execution looked identical.  The cheap tell it records
is a message stating something the code did not measure, sitting beside a
printed number that contradicted it -- `0 rejection records`, a hard-coded
`361`, `1 skipped`.  The number was there every time; the missing thing was an
assertion on it.

So each check below declares controls that **defeat its mechanism** and
require it to go red, and each control names the witness it expects: the
control asserts not merely that the check failed but that it failed *for the
reason the control planted*.  A control that goes red for an unrelated reason
is reported as a wrong witness and fails `--self-test`, in the shape
`scripts/m0-guard-exit-codes.py` established.

A green run prints the sizes it measured -- files checked, crates notified,
binaries inspected -- so a green result also reports that it ran.

`--self-test` never writes to the repository.  Controls copy the bundle into a
`tempfile.TemporaryDirectory()` and mutate the copy.

Usage
-----
    python3 scripts/m6-release-artifact.py notices --out NOTICE
    python3 scripts/m6-release-artifact.py bundle --receipt R --out DIR
    python3 scripts/m6-release-artifact.py verify --bundle DIR
    python3 scripts/m6-release-artifact.py verify --bundle DIR.tar.gz
    python3 scripts/m6-release-artifact.py --self-test --bundle DIR
    python3 scripts/m6-release-artifact.py verify --bundle DIR --check notices

`bundle` writes both a directory and a `.tar.gz` beside it with its own
digest.  `verify` takes either; given the archive it extracts it into a
temporary directory and checks that, which is the gate's "unpack into clean
temporary environments" step actually performed.  `--self-test` takes the
directory, because its controls mutate a copy.

Exit codes: 0 all selected checks passed; 1 at least one failed; 2 the script
could not run a selected check at all.  **2 is not a pass.**  A check that
could not run is reported as DID NOT RUN with the reason, never folded into
the green.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The pinned toolchain, asserted rather than hoped for.  A bundle built by a
# different rustc is a different artifact; recording the version without
# checking it would be a provenance field that proves nothing.
PINNED_RUST = "1.95.0"

# Floors.  Each exists because the corresponding "scanned nothing" failure is
# indistinguishable from a pass without it.  Measured at ec663a7: the bundle
# carries 3 executables and 4 configuration examples, and the lockfile
# resolves 353 registry crates.  The floors sit below the measurement with
# room for ordinary movement, and above zero by enough that an empty input
# cannot clear them.
MIN_BUNDLE_FILES = 10
MIN_EXECUTABLES = 3
MIN_NOTICE_CRATES = 300
MIN_EXAMPLES = 2
# Measured at ec663a7: 628 licence files totalling 3,145,598 bytes across the
# 342 registry crates that ship one.  The floor is an order of magnitude below
# that, which is still far above anything a NOTICE reduced to identifiers
# could reach -- the failure this floor exists to catch.
MIN_EMBEDDED_LICENCE_BYTES = 300_000

# The binaries a tester needs, and why each is here.
#
#   tunnel-client   the device CLI -- the thing a tester runs.
#   tunnel-relay    the server half; without it a tester has one end of a
#                   tunnel.
#   tunnel-deadman  NOT a product command.  It is the parent-death sentinel
#                   that `tunnel_deadman::sentinel_path()` looks for beside
#                   the running executable.  It is in this list because it is
#                   a **required runtime asset**, and because omitting it
#                   degrades rather than fails.
#
# `tunnel-test-harness` and the three `*-fixture` binaries are deliberately
# absent: they are test scaffolding, not something an outside tester runs.
BUNDLE_BINARIES = ("tunnel-client", "tunnel-relay", "tunnel-deadman")

# Configuration examples a tester needs in order to run the config checks at
# all.  These are the same files CI dry-runs.
BUNDLE_EXAMPLES = (
    "client.toml",
    "relay.toml",
    "m1-client.toml",
    "m1-relay.toml",
)

SHA256SUMS = "SHA256SUMS"
PROVENANCE = "PROVENANCE.txt"
NOTICE = "NOTICE"
LOCKFILE = "Cargo.lock"

# --------------------------------------------------------------------------
# The advertised target set.
#
# **There is no list of triples anywhere in this file.**  The set lives in
# `[workspace.metadata.release] advertised-targets` in the root `Cargo.toml`
# and is read from there, because a second copy here is precisely the defect
# docs/tasks.md row M5-C11 catalogues -- two readers that agree until someone
# edits one of them.  The only triples that appear in this file are inside
# controls, as synthetic values that must be *rejected*.
#
# Two independent readers parse that table -- `tomllib` below, and `cargo`
# itself via `cargo metadata` -- and `check_targets` requires them to agree
# with each other and with the set a bundle froze into its `PROVENANCE.txt`.
# --------------------------------------------------------------------------
MANIFEST = "Cargo.toml"
PROVENANCE_TARGET_SET = "advertised_targets"

# A target triple's shape, asserted rather than assumed: a declaration of
# `"linux"` or `""` would otherwise sail through every set comparison below
# while meaning nothing to rustc.
TRIPLE_RE = re.compile(r"[0-9a-z_]+(?:-[0-9a-z_.]+){2,3}")


class DeclarationError(Exception):
    """The declaration is absent or malformed.  Carries its own witness."""

    def __init__(self, witness: str, message: str) -> None:
        super().__init__(message)
        self.witness = witness


def declared_release_table(manifest: Path) -> dict:
    if not manifest.is_file():
        raise DeclarationError("advertised-set-missing", f"no manifest at {manifest}")
    try:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise DeclarationError("advertised-set-malformed",
                               f"{manifest} is not valid TOML: {error}") from error
    table = data.get("workspace", {}).get("metadata", {}).get("release")
    if table is None:
        raise DeclarationError(
            "advertised-set-missing",
            f"{manifest} carries no [workspace.metadata.release] table, so the "
            "advertised set has no referent")
    return table


def declared_targets(manifest: Path | None = None) -> list[str]:
    """The advertised set, read from the one place that declares it.

    Raises `DeclarationError` rather than returning a default.  A default
    would be a second source of truth wearing a fallback's clothes, and the
    whole point of this function is that there is exactly one.
    """
    table = declared_release_table(manifest or (REPO / MANIFEST))
    raw = table.get("advertised-targets")
    if raw is None:
        raise DeclarationError(
            "advertised-set-missing",
            "[workspace.metadata.release] declares no `advertised-targets`")
    if not isinstance(raw, list) or not all(isinstance(t, str) for t in raw):
        raise DeclarationError("advertised-set-malformed",
                               f"`advertised-targets` is {type(raw).__name__}, not a list of strings")
    if not raw:
        raise DeclarationError(
            "advertised-set-malformed",
            "`advertised-targets` is empty.  An empty set makes every bundle "
            "cover all of it, which is the vacuous pass this check exists to refuse")
    duplicates = sorted({t for t in raw if raw.count(t) > 1})
    if duplicates:
        raise DeclarationError("advertised-set-malformed",
                               f"`advertised-targets` repeats {duplicates}")
    malformed = [t for t in raw if not TRIPLE_RE.fullmatch(t)]
    if malformed:
        raise DeclarationError("advertised-set-malformed",
                               f"not target triples: {malformed}")
    return sorted(raw)


def classify_cargo_metadata(returncode: int, stdout: str) -> tuple[list[str] | None, str]:
    """Turn one `cargo metadata` invocation into a set and a **status**.

    **Split out, and the statuses kept distinct, because collapsing them was a
    real defect.**  The first version of this returned a bare `None` for four
    different conditions -- cargo missing, cargo exiting non-zero, JSON that
    would not parse, and a table that is not a list of triples -- and
    `check_targets` reported all four as "cargo could not be reached".  The
    last two are the second reader **disagreeing**, reported as the second
    reader being **absent**, which is the more forgiving of the two readings
    and the wrong one.  A reader that answers something else has not failed to
    run; it has contradicted the declaration.

    Pure, so `--self-test` can drive every status from recorded input without
    a cargo on the machine.
    """
    if returncode != 0:
        return None, "cargo-failed"
    try:
        metadata = json.loads(stdout)
    except json.JSONDecodeError:
        return None, "unparseable-json"
    if not isinstance(metadata, dict):
        return None, "unparseable-json"
    table = (metadata.get("metadata") or {}).get("release")
    if not isinstance(table, dict):
        return None, "no-release-table"
    raw = table.get("advertised-targets")
    if not isinstance(raw, list):
        return None, "targets-not-a-list"
    return sorted(str(t) for t in raw), "ok"


def cargo_declared_targets(manifest: Path | None = None) -> tuple[list[str] | None, str]:
    """The same table, read by cargo instead of by this script.

    Returns `(targets, status)`.  `check_targets` treats the statuses
    differently and deliberately: cargo absent or failing means the second
    reader **did not run**, which is not a pass; cargo answering with
    something other than the declaration means it **disagrees**, which is a
    failure with a witness.
    """
    root = (manifest or (REPO / MANIFEST)).parent
    if shutil.which("cargo") is None:
        return None, "cargo-absent"
    completed = run(["cargo", "metadata", "--no-deps", "--format-version", "1",
                     "--offline"], cwd=root, timeout=300)
    return classify_cargo_metadata(completed.returncode, completed.stdout)


def rustc_known_targets() -> set[str] | None:
    """Every triple rustc will accept, or `None` if rustc is unreachable."""
    if shutil.which("rustc") is None:
        return None
    completed = run(["rustc", "--print", "target-list"], cwd=REPO)
    if completed.returncode != 0:
        return None
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


# --------------------------------------------------------------------------
# Result plumbing
# --------------------------------------------------------------------------


@dataclass
class Result:
    name: str
    ok: bool
    ran: bool = True
    summary: str = ""
    # The machine-readable reason a check failed.  Controls match on this,
    # which is what makes "failed for the reason the control planted"
    # checkable instead of merely asserted in prose.
    witness: str | None = None
    notes: list[str] = field(default_factory=list)

    def note(self, line: str) -> None:
        self.notes.append(line)

    def render(self) -> str:
        if not self.ran:
            head = f"DID NOT RUN  {self.name}: {self.summary}"
        else:
            head = f"{'ok    ' if self.ok else 'FAILED'}  {self.name}: {self.summary}"
        if self.witness and not self.ok:
            head += f"  [witness={self.witness}]"
        return "\n".join([head] + [f"          {line}" for line in self.notes])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stranger_env(workdir: Path) -> dict[str, str]:
    """The environment a recipient's shell would not hand these binaries.

    `PATH` is narrowed to the system directories and every `CARGO_*`/`RUST*`
    variable is dropped, so a bundled binary cannot reach this checkout's
    toolchain, target directory or registry cache.  `cargo_is_unreachable`
    below turns that into a measurement rather than a claim: an earlier
    version of this file *printed* "no cargo, no target/" while inheriting
    the caller's `PATH` and checking neither.
    """
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(workdir),
        "TMPDIR": str(workdir),
    }


def cargo_is_unreachable(env: dict[str, str]) -> bool:
    """True when `cargo` cannot be found on the environment's own PATH."""
    return shutil.which("cargo", path=env["PATH"]) is None


def run(command: list[str], cwd: Path | None = None, env: dict | None = None,
        timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


# --------------------------------------------------------------------------
# Lockfile -> crate list.  Pure Python on purpose.
#
# The `notices` check has to be re-derivable **from the unpacked bundle on a
# machine with no cargo and no registry cache**, because that is the machine
# the gate is about.  So the crate list comes from the bundled `Cargo.lock`,
# parsed here, not from `cargo metadata`.  The generator (`notices`) uses
# cargo metadata for licence *text*, which only the build machine has; the
# checker uses the lockfile for the crate *set*, which travels with the
# bundle.  The two must agree, and `notices` is exactly that comparison.
# --------------------------------------------------------------------------


def parse_lockfile(text: str) -> list[tuple[str, str]]:
    """Return sorted (name, version) for every registry package in a Cargo.lock.

    Packages with no `source` are local -- workspace members and the three
    `[patch.crates-io]` crates under `vendor/`.  They are excluded here and
    handled separately, because their licence is this repository's own
    LICENSE plus the vendored crates' own texts, not a registry crate's.
    """
    crates: list[tuple[str, str]] = []
    name = version = source = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            if name and version and source:
                crates.append((name, version))
            name = version = source = None
            continue
        match = re.match(r'^(name|version|source) = "(.*)"$', line)
        if match:
            key, value = match.group(1), match.group(2)
            if key == "name":
                name = value
            elif key == "version":
                version = value
            else:
                source = value
    if name and version and source:
        crates.append((name, version))
    return sorted(set(crates))


# --------------------------------------------------------------------------
# NOTICE generation
# --------------------------------------------------------------------------


LICENCE_FILE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE")


def licence_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    found = [
        entry
        for entry in sorted(directory.iterdir())
        if entry.is_file() and entry.name.upper().startswith(LICENCE_FILE_PREFIXES)
    ]
    return found


def generate_notices(metadata: dict, lock_sha: str, lock_text: str) -> str:
    """Render NOTICE deterministically from cargo metadata.

    Deterministic because the check re-runs this and compares: entries are
    sorted, and nothing that varies between runs (paths, timestamps) is
    emitted.  The bundled `Cargo.lock` digest is recorded in the header so a
    NOTICE that has drifted from its lockfile is detectable from the bundle
    alone.
    """
    workspace = set(metadata["workspace_members"])
    third_party = sorted(
        (p for p in metadata["packages"] if p["id"] not in workspace and p.get("source")),
        key=lambda p: (p["name"].lower(), p["version"]),
    )
    vendored = sorted(
        (p for p in metadata["packages"] if p["id"] not in workspace and not p.get("source")),
        key=lambda p: (p["name"].lower(), p["version"]),
    )

    with_text = 0
    without_text: list[str] = []


    undecodable: list[str] = []
    body: list[str] = []
    for package in third_party:
        directory = Path(package["manifest_path"]).parent
        files = licence_files(directory)
        spdx = package.get("license") or "(no license field)"
        body.append(f"{package['name']} {package['version']}")
        body.append(f"    SPDX: {spdx}")
        if files:
            with_text += 1
            for entry in files:
                label = f"{package['name']} {package['version']} {entry.name}"
                raw = entry.read_bytes()
                digest = sha256_bytes(raw)
                body.append(f"    text: {entry.name} sha256={digest}")
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    # Recorded rather than mangled.  Embedding replacement
                    # characters would produce a licence text that is not the
                    # licence text, which is worse than saying so.
                    undecodable.append(label)
                    body.append("    text: not UTF-8; see the crate's own package")
                    continue
                if TEXT_END in text or TEXT_BEGIN in text:
                    # A licence file containing this file's own delimiter would
                    # corrupt the crate-set parse silently.  Refuse instead.
                    raise ValueError(f"{label} contains a NOTICE delimiter")
                # **The digest travels in the marker, so the block is bound
                # to it.** The check hashes the reconstructed content and
                # compares. Without that, blocks of the right length and
                # wrong content pass -- the count and the byte total would be
                # unchanged, and "byte-exact" would again be a word rather
                # than a measurement.
                #
                # The text is embedded **verbatim**: no rstrip, no reflow.
                # Trimming a licence is editing it, and the trailing newlines
                # an earlier version removed are exactly what made the digest
                # unverifiable.
                body.append(f"{TEXT_BEGIN} {label} sha256={digest}")
                body.append(text)
                body.append(f"{TEXT_END} {label}")
        else:
            without_text.append(f"{package['name']} {package['version']}")
            # Recorded explicitly rather than omitted.  A crate silently
            # missing from NOTICE and a crate that ships no licence file look
            # identical in a hand-written notices file; here they do not.
            body.append("    text: none shipped in the published crate")
        body.append("")

    # **The header's figures are recomputed from the assembled body by the same
    # function the checker uses, rather than accumulated while writing it.**
    # Two counters that measure almost-the-same thing drift -- the first draft
    # recorded raw file bytes here and line bytes in the checker, and the
    # 53-byte disagreement made the check fail on a correct NOTICE. Deriving
    # both from one function means the header cannot claim a quantity nothing
    # can reproduce.
    embedded_files, embedded_bytes = notice_embedded_texts("\n".join(body))

    header = [
        "THIRD-PARTY NOTICES",
        "",
        "Generated by scripts/m6-release-artifact.py from the resolved dependency",
        "graph.  Do not edit by hand: `verify --check notices` re-derives the crate",
        "set from the Cargo.lock shipped beside this file and fails on any",
        "difference, so a hand edit is reverted by the next check rather than",
        "silently preserved.",
        "",
        f"cargo_lock_sha256: {lock_sha}",
        f"registry_crates: {len(third_party)}",
        f"registry_crates_with_licence_text: {with_text}",
        f"registry_crates_without_licence_text: {len(without_text)}",
        f"embedded_licence_texts: {embedded_files}",
        f"embedded_licence_bytes: {embedded_bytes}",
        f"undecodable_licence_files: {len(undecodable)}",
        f"local_crates: {len(vendored)}",
        "",
        "The full text of every licence file the crates ship is embedded below,",
        "between BEGIN/END LICENCE TEXT delimiters and byte-exact.  This file is",
        "the licence notice that accompanies the binaries in this bundle, not an",
        "index to one: a SHA-256 lets a checker confirm nothing drifted and gives",
        "the recipient nothing they can read.",
        "",
        "Crates with no licence file in the published package are listed with their",
        "declared SPDX expression only.  That is a statement about what the crate",
        "shipped, not a missing entry:",
    ]
    header += [f"  {entry}" for entry in without_text] or ["  (none)"]
    header += [
        "",
        "The workspace's own crates are covered by the LICENSE file in this bundle.",
        "",
        "Locally patched crates (vendor/), covered by their own texts in the",
        "repository:",
    ]
    header += [f"  {p['name']} {p['version']}" for p in vendored] or ["  (none)"]

    # **The measured gap, stated rather than absorbed.**  `Cargo.lock` pins
    # every package any feature combination could need; the resolved
    # dependency graph is narrower, because optional and platform features
    # that are off do not enter it.  At ec663a7 the lockfile carries 381
    # registry packages and the resolved graph 353.  Notices are generated
    # from the resolved graph, because those are the crates that can be linked
    # into these binaries -- but the 28 that are only in the lockfile are
    # listed here by name rather than left as a silent subtraction, and
    # `verify --check notices` requires this list to equal the bundle's own
    # lockfile minus the notified set, in both directions.
    #
    # This delta is also the scope of the M6-04 licence policy, which reads
    # the same resolved graph: a crate in this list is not covered by that
    # gate either.  See docs/tasks.md row M6-C05.
    lock_only = sorted(set(parse_lockfile(lock_text)) - {
        (p["name"], p["version"]) for p in third_party
    })
    header += [
        "",
        "In the lockfile but NOT in the resolved dependency graph, and therefore",
        "not linked into these binaries.  Listed so the subtraction is visible:",
        UNRESOLVED_RULE,
    ]
    header += [f"  {name} {version}" for name, version in lock_only] or ["  (none)"]
    header += [UNRESOLVED_RULE, "", "=" * 70, ""]

    return "\n".join(header + body).rstrip() + "\n"


UNRESOLVED_RULE = "-" * 70

# Delimiters around each embedded licence text.
#
# **The texts are embedded, not summarised, and that is the point of the file.**
# MIT, the BSD family and Apache-2.0 all require the copyright notice and the
# licence text to accompany a binary distribution.  A digest lets a *checker*
# confirm nothing drifted; it discharges nothing owed to the person receiving
# the bundle, who cannot reconstruct a licence from its SHA-256.  An earlier
# version of this file recorded only SPDX ids and digests, which made the
# `notices` check green against a deliverable that did not do what notices
# exist for.
#
# Explicit delimiters rather than indentation, so the text is byte-exact:
# reflowing or indenting a licence is editing it.  `notice_crate_set` skips
# everything between them, and generation refuses outright if a licence file
# contains one of these markers, because that would corrupt the crate-set
# parse silently rather than loudly.
TEXT_BEGIN = "----- BEGIN LICENCE TEXT:"
TEXT_END = "----- END LICENCE TEXT:"


def notice_unresolved_set(text: str) -> set[tuple[str, str]]:
    """Recover the declared lockfile-minus-resolved-graph delta from a NOTICE.

    See `generate_notices` for why this exists.  It is parsed back out so the
    check can require the delta to be *exactly* what the bundle's own lockfile
    implies, rather than trusting the number in the header.
    """
    _, _, rest = text.partition(UNRESOLVED_RULE)
    block, _, _ = rest.partition(UNRESOLVED_RULE)
    crates = set()
    for raw in block.splitlines():
        parts = raw.split()
        if raw.startswith("  ") and len(parts) == 2:
            crates.add((parts[0], parts[1]))
    return crates


def notice_crate_set(text: str) -> set[tuple[str, str]]:
    """Recover the (name, version) set from a rendered NOTICE.

    Entry lines are exactly `name version` at column 0 in the body; header and
    indented lines are skipped.  The body is delimited by the `=` rule, so a
    name appearing in the header cannot be mistaken for an entry.
    """
    _, _, body = text.partition("=" * 70)
    crates = set()
    inside_text = False
    for raw in body.splitlines():
        # Embedded licence texts are arbitrary prose and routinely contain
        # two-word lines at column 0.  Without this the parse would invent
        # crates out of licence wording, so the delimiters are load-bearing
        # rather than decorative.
        if raw.startswith(TEXT_BEGIN):
            inside_text = True
            continue
        if raw.startswith(TEXT_END):
            inside_text = False
            continue
        if inside_text or not raw or raw.startswith(" "):
            continue
        parts = raw.split()
        if len(parts) == 2:
            crates.add((parts[0], parts[1]))
    return crates


def read_exact(path: Path) -> str:
    """Read a file without newline translation.

    **`Path.read_text()` cannot be used on the NOTICE.** Python opens text
    files in universal-newline mode, which rewrites `\\r\\n` and lone `\\r` to
    `\\n` on the way in.  Two of the 628 embedded licences contain carriage
    returns -- `generic-array` 0.14.7 and `nu-ansi-term` 0.50.3 -- so reading
    the NOTICE as text silently deleted 20 and 22 bytes from them and made
    their digests fail.  That is a real corruption of a licence text, and it
    was invisible until the digests were bound: the block count and the byte
    total were both still consistent with themselves.
    """
    return path.read_bytes().decode("utf-8")


def write_exact(path: Path, text: str) -> None:
    """Write a file without newline translation, for the same reason."""
    path.write_bytes(text.encode("utf-8"))


def notice_licence_blocks(text: str) -> list[tuple[str, str, str]]:
    """Return (label, declared sha256, exact content) for each embedded text.

    **The reconstruction is exact, and that is what lets the digest bind.**
    Each block is written as the BEGIN line, then the licence file's decoded
    text verbatim, then the END line, all joined with newlines.  Splitting the
    document on newlines therefore yields the file's own lines between the two
    markers, and re-joining them with newlines reproduces the file's text
    byte-for-byte -- including a trailing newline, which survives as a final
    empty element.  An earlier version wrote `text.rstrip("\\n")` here, which
    silently dropped trailing newlines from 34 of the 628 files and made the
    word "byte-exact" false for them.
    """
    blocks: list[tuple[str, str, str]] = []
    label = digest = None
    collected: list[str] = []
    for line in text.split("\n"):
        if line.startswith(TEXT_BEGIN):
            match = re.match(rf"{re.escape(TEXT_BEGIN)} (.*) sha256=([0-9a-f]{{64}})$",
                             line)
            if match:
                label, digest = match.group(1), match.group(2)
            else:
                label, digest = line[len(TEXT_BEGIN):].strip(), ""
            collected = []
            continue
        if line.startswith(TEXT_END):
            if label is not None:
                blocks.append((label, digest or "", "\n".join(collected)))
            label = digest = None
            collected = []
            continue
        if label is not None:
            collected.append(line)
    return blocks


def notice_embedded_texts(text: str) -> tuple[int, int]:
    """Return (number of embedded licence texts, total bytes of their content).

    Counted from the delimiters rather than trusted from the header, because a
    header figure nothing recomputes is the failure this whole file is about.
    """
    blocks = notice_licence_blocks(text)
    return len(blocks), sum(len(content.encode("utf-8")) for _, _, content in blocks)


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def read_sums(bundle: Path) -> dict[str, str] | None:
    path = bundle / SHA256SUMS
    if not path.is_file():
        return None
    sums = {}
    for line in read_exact(path).splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        sums[name] = digest
    return sums


def bundle_files(bundle: Path) -> list[Path]:
    return sorted(
        p for p in bundle.rglob("*") if p.is_file() and p.name != SHA256SUMS
    )


def check_checksums(bundle: Path) -> Result:
    sums = read_sums(bundle)
    if sums is None:
        return Result("checksums", False, summary=f"no {SHA256SUMS} in bundle",
                      witness="sums-file-missing")
    present = {str(p.relative_to(bundle)): p for p in bundle_files(bundle)}

    missing = sorted(set(sums) - set(present))
    if missing:
        return Result("checksums", False,
                      summary=f"{len(missing)} listed file(s) absent: {missing[:3]}",
                      witness="file-missing")
    unlisted = sorted(set(present) - set(sums))
    if unlisted:
        # An unlisted file is as bad as a mismatched one: it is bytes the
        # bundle carries that nothing attests.
        return Result("checksums", False,
                      summary=f"{len(unlisted)} file(s) not listed: {unlisted[:3]}",
                      witness="file-unlisted")
    bad = [name for name, digest in sums.items()
           if sha256_file(present[name]) != digest]
    if bad:
        return Result("checksums", False,
                      summary=f"{len(bad)} digest mismatch: {sorted(bad)[:3]}",
                      witness="digest-mismatch")
    if len(sums) < MIN_BUNDLE_FILES:
        return Result("checksums", False,
                      summary=f"only {len(sums)} files listed, floor is {MIN_BUNDLE_FILES}",
                      witness="floor")
    result = Result("checksums", True,
                    summary=f"{len(sums)} files verified, 0 unlisted")
    result.note(f"floor {MIN_BUNDLE_FILES}; every listed file present and matching")
    return result


def parse_fields(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and not key.startswith(" "):
            fields[key.strip()] = value.strip()
    return fields


PROVENANCE_REQUIRED = (
    "commit",
    "tracked_diff_sha256",
    "worktree_status_sha256",
    "target",
    "profile",
    "rustc_version",
    "cargo_version",
    "build_command",
    "source_copy_sha256",
    "receipt_sha256",
)


def check_provenance(bundle: Path) -> Result:
    path = bundle / PROVENANCE
    if not path.is_file():
        return Result("provenance", False, summary=f"no {PROVENANCE} in bundle",
                      witness="provenance-file-missing")
    fields = parse_fields(read_exact(path))

    absent = [key for key in PROVENANCE_REQUIRED if not fields.get(key)]
    if absent:
        return Result("provenance", False,
                      summary=f"missing field(s): {absent}",
                      witness="field-missing")

    if PINNED_RUST not in fields["rustc_version"]:
        return Result("provenance", False,
                      summary=f"rustc {fields['rustc_version']!r} is not the pinned {PINNED_RUST}",
                      witness="toolchain-mismatch")

    if not re.fullmatch(r"[0-9a-f]{40}", fields["commit"]):
        return Result("provenance", False,
                      summary=f"commit {fields['commit']!r} is not a full sha1",
                      witness="commit-malformed")

    # The load-bearing part: the recorded per-binary digests must equal the
    # digests of the bytes actually sitting in this bundle.  Without this the
    # provenance block is a description of some other build.
    recorded = {}
    for line in read_exact(path).splitlines():
        match = re.match(r"^\s+binary\s+(\S+)\s+sha256=([0-9a-f]{64})$", line)
        if match:
            recorded[match.group(1)] = match.group(2)
    if not recorded:
        return Result("provenance", False,
                      summary="no per-binary digests recorded",
                      witness="binary-digests-absent")
    for name, digest in sorted(recorded.items()):
        binary = bundle / "bin" / name
        if not binary.is_file():
            return Result("provenance", False,
                          summary=f"provenance names {name}, which is not in the bundle",
                          witness="binary-missing")
        actual = sha256_file(binary)
        if actual != digest:
            return Result("provenance", False,
                          summary=f"{name}: bundle {actual[:12]} != recorded {digest[:12]}",
                          witness="binary-digest-mismatch")

    if len(recorded) < MIN_EXECUTABLES:
        return Result("provenance", False,
                      summary=f"only {len(recorded)} binaries attested, floor {MIN_EXECUTABLES}",
                      witness="floor")

    result = Result("provenance", True,
                    summary=f"{len(recorded)} binaries attested to {fields['commit'][:12]}"
                            f" on {fields['target']}")
    result.note(f"toolchain {fields['rustc_version']} (pin {PINNED_RUST}); "
                f"profile {fields['profile']}")
    result.note(f"source copy {fields['source_copy_sha256'][:12]}; "
                f"receipt {fields['receipt_sha256'][:12]}")
    result.note(f"tracked diff {fields['tracked_diff_sha256'][:12]}; "
                f"worktree status {fields['worktree_status_sha256'][:12]}")
    return result


def check_notices(bundle: Path) -> Result:
    notice = bundle / NOTICE
    lock = bundle / LOCKFILE
    if not notice.is_file():
        return Result("notices", False, summary=f"no {NOTICE} in bundle",
                      witness="notice-missing")
    if not lock.is_file():
        # Without the lockfile the NOTICE cannot be re-derived from the bundle
        # and is exactly the hand-written artifact this check exists to avoid.
        return Result("notices", False,
                      summary=f"no {LOCKFILE} in bundle; NOTICE is unverifiable",
                      witness="lockfile-missing")

    text = read_exact(notice)
    fields = parse_fields(text)

    lock_sha = sha256_file(lock)
    recorded_sha = fields.get("cargo_lock_sha256", "")
    if recorded_sha != lock_sha:
        return Result("notices", False,
                      summary=f"NOTICE records lock {recorded_sha[:12]}, "
                              f"bundle ships {lock_sha[:12]}",
                      witness="lock-digest-mismatch")

    locked = set(parse_lockfile(lock.read_text()))
    actual = notice_crate_set(text)
    declared_unresolved = notice_unresolved_set(text)

    # Direction one: nothing notified that the lockfile does not pin.
    extra = sorted(actual - locked)
    if extra:
        return Result("notices", False,
                      summary=f"{len(extra)} crate(s) in NOTICE are not in the "
                              f"lockfile: {extra[:3]}",
                      witness="crate-set-mismatch")

    # Direction two: every lockfile crate is either notified or explicitly
    # declared as out of the resolved graph.  A crate that is in neither set
    # has been silently dropped, which is the whole failure mode a generated
    # NOTICE is supposed to remove.
    unaccounted = sorted(locked - actual - declared_unresolved)
    if unaccounted:
        return Result("notices", False,
                      summary=f"{len(unaccounted)} lockfile crate(s) are neither "
                              f"notified nor declared out of the resolved graph: "
                              f"{unaccounted[:3]}",
                      witness="crate-set-mismatch")

    # And the declared delta may not claim crates that are notified anyway,
    # nor crates the lockfile does not pin.
    bogus = sorted((declared_unresolved & actual) | (declared_unresolved - locked))
    if bogus:
        return Result("notices", False,
                      summary=f"{len(bogus)} crate(s) declared out of the resolved "
                              f"graph are notified or unpinned: {bogus[:3]}",
                      witness="unresolved-declaration-bogus")

    if len(actual) < MIN_NOTICE_CRATES:
        return Result("notices", False,
                      summary=f"only {len(actual)} crates notified, floor {MIN_NOTICE_CRATES}",
                      witness="floor")

    # **The licence texts themselves, counted from the delimiters rather than
    # read off the header.** This is the assertion whose absence made an
    # earlier version of this check green against a NOTICE that carried only
    # SPDX ids and digests -- a file that satisfies a drift check and
    # discharges nothing owed to the recipient.
    blocks = notice_licence_blocks(text)
    embedded = len(blocks)
    embedded_bytes = sum(len(content.encode("utf-8")) for _, _, content in blocks)

    # **Each block hashed against the digest in its own marker.** Counting
    # blocks and summing their length says nothing about what is *in* them: a
    # NOTICE whose 628 texts were replaced by filler of the same length would
    # satisfy both figures. This is what makes "byte-exact" a measurement, and
    # it is the reason the digests are emitted at all -- an unbound digest is
    # decoration.
    unbound = [label for label, digest, _ in blocks if not digest]
    if unbound:
        return Result("notices", False,
                      summary=f"{len(unbound)} embedded text(s) carry no digest to "
                              f"check against: {unbound[:3]}",
                      witness="licence-text-unbound")
    corrupt = [label for label, digest, content in blocks
               if sha256_bytes(content.encode("utf-8")) != digest]
    if corrupt:
        return Result("notices", False,
                      summary=f"{len(corrupt)} embedded licence text(s) do not match "
                              f"their recorded digest: {corrupt[:3]}",
                      witness="licence-text-digest-mismatch")

    claimed = int(fields.get("embedded_licence_texts", "-1"))
    claimed_bytes = int(fields.get("embedded_licence_bytes", "-1"))
    # `!=` on both, not `<` on the byte total: a header that *under*-claims is
    # as wrong as one that over-claims, and `<` let it through.
    if embedded != claimed or embedded_bytes != claimed_bytes:
        return Result("notices", False,
                      summary=f"NOTICE header claims {claimed} texts / "
                              f"{claimed_bytes} bytes, body carries {embedded} / "
                              f"{embedded_bytes}",
                      witness="embedded-text-count-mismatch")
    with_text = int(fields.get("registry_crates_with_licence_text", "-1"))
    if embedded < with_text:
        return Result("notices", False,
                      summary=f"{with_text} crates ship licence text but only "
                              f"{embedded} texts are embedded",
                      witness="licence-text-missing")
    if embedded_bytes < MIN_EMBEDDED_LICENCE_BYTES:
        return Result("notices", False,
                      summary=f"{embedded_bytes} bytes of licence text embedded, "
                              f"floor {MIN_EMBEDDED_LICENCE_BYTES}",
                      witness="licence-text-floor")

    without = int(fields.get("registry_crates_without_licence_text", "-1"))
    result = Result("notices", True,
                    summary=f"{len(actual)} registry crates, re-derived from the "
                            f"bundled lockfile and identical")
    result.note(f"floor {MIN_NOTICE_CRATES}; lock digest {lock_sha[:12]} matches the header")
    result.note(f"{embedded} licence texts embedded, {embedded_bytes} bytes "
                f"(floor {MIN_EMBEDDED_LICENCE_BYTES}); each block reconstructed from "
                f"the delimiters and hashed against its own recorded digest, so "
                f"byte-exact is measured rather than asserted")
    result.note(f"{without} crate(s) ship no licence text and are listed as such by name")
    result.note(f"{len(locked)} lockfile crates = {len(actual)} notified + "
                f"{len(declared_unresolved)} declared outside the resolved graph; "
                f"0 unaccounted")
    return result


def check_assets(bundle: Path) -> Result:
    """Required runtime assets, resolved the product's way and then executed.

    `ls bin/tunnel-deadman` proves a file is present.  It does not prove the
    running client can *find* it: `tunnel_deadman::resolve_sentinel` resolves
    the sentinel relative to `std::env::current_exe()`, so a bundle whose
    layout puts the client somewhere else would pass a file-existence check
    and still ship degraded containment.  So this replays that resolution rule
    and then runs the binary it finds.  It does **not** invoke `doctor`; see
    the comment at the sentinel block below for why that surface cannot answer
    here, and `docs/tasks.md` row M6-C07 for the defect.
    """
    # `tunnel-deadman` is deliberately **not** in this generic existence loop.
    # Its absence has a different meaning and a different fix from a missing
    # product command -- silent degradation rather than an unusable bundle --
    # so it gets its own branch and its own witness below.  Left in this loop
    # it trips `binary-missing` first and `sentinel-missing` becomes
    # unreachable, which is how the first version of this file was written and
    # what the `--self-test` wrong-witness rule caught.
    product = [name for name in BUNDLE_BINARIES if name != "tunnel-deadman"]
    missing = [name for name in product if not (bundle / "bin" / name).is_file()]
    if missing:
        return Result("assets", False,
                      summary=f"missing binaries: {missing}",
                      witness="binary-missing")

    examples = sorted((bundle / "examples").glob("*.toml")) if (bundle / "examples").is_dir() else []
    if len(examples) < MIN_EXAMPLES:
        return Result("assets", False,
                      summary=f"{len(examples)} configuration example(s), floor {MIN_EXAMPLES}",
                      witness="examples-missing")
    if not (bundle / "LICENSE").is_file():
        return Result("assets", False, summary="no LICENSE in bundle",
                      witness="license-missing")

    # The sentinel, checked by replaying the product's own resolution rule and
    # then executing the result.
    #
    # **Why not `tunnel-client doctor`, which is the surface that reports
    # containment.**  When this check was written, doctor's answer could not
    # be read from an unpacked bundle at all: `inspect` built
    # `process_containment` before it even attempted to load the
    # configuration and then discarded the whole result whenever any error
    # was present, so a bundle nobody had provisioned gave exit 3,
    # `CREDENTIAL_MISSING`, and `result: null`.  A check written against
    # doctor would have been red for every bundle regardless of whether the
    # sentinel was there -- the mirror image of a check that is green
    # regardless.  **That is fixed (M6-C07): `DoctorOutput::result` is no
    # longer an `Option` and the checks are reported on every path.**
    #
    # This check still does not ask doctor, and the reason has narrowed twice.
    # It is no longer that doctor reports `SENTINEL_PRESENT` for a zero-byte
    # decoy: **M6-C08 fixed that**, and `resolve_sentinel` now requires a
    # regular file with an execute bit, reporting anything else as
    # `PROCESS_CONTAINMENT_SENTINEL_UNUSABLE`.  So the product would now
    # reject the same zero-byte decoy this check rejects.
    #
    # What remains is the reason that was always the real one.  The product's
    # rule is a **mode** check and stops there deliberately -- doctor promises
    # to read a path and start nothing, and the resolution path runs before
    # every supervised child -- so it cannot tell an executable script named
    # `tunnel-deadman` from the sentinel.  This check can, because assembly
    # time is where a process launch is affordable.  Asking doctor would
    # therefore still be asking a question this check answers more strongly.
    #
    # So this replays `tunnel_deadman::resolve_sentinel`'s no-explicit-path
    # branch -- `SENTINEL_BIN` beside the running executable -- and then does
    # the thing the product deliberately does **not** do: it runs it.
    # Executing it is what tells an executable file of the right name from a
    # working sentinel.
    client = bundle / "bin" / "tunnel-client"
    sentinel = client.parent / "tunnel-deadman"
    if not sentinel.is_file():
        return Result("assets", False,
                      summary="no tunnel-deadman beside the bundled client; process "
                              "containment would be degraded, announced only by a "
                              "one-line warning at arm time",
                      witness="sentinel-missing")

    with tempfile.TemporaryDirectory() as workdir:
        # cwd is deliberately outside both the bundle and the repository: a
        # check that only passes because it was run from the build tree is not
        # evidence about a clean machine.  `stdin` is closed, so the sentinel's
        # blocking read cannot hold this check open.
        work = Path(workdir)
        probes = [
            ([], "no argument"),
            (["not-a-pid"], "a non-numeric leader"),
        ]
        for args, label in probes:
            try:
                completed = subprocess.run(
                    [str(sentinel)] + args, cwd=str(work), capture_output=True,
                    stdin=subprocess.DEVNULL, timeout=10, check=False,
                )
            except OSError as error:
                return Result("assets", False,
                              summary=f"the bundled sentinel could not be executed "
                                      f"({label}): {error}",
                              witness="sentinel-not-executable")
            if completed.returncode != 2:
                return Result("assets", False,
                              summary=f"the bundled sentinel answered {label} with exit "
                                      f"{completed.returncode}, not the sentinel's 2; "
                                      f"it is not a working tunnel-deadman",
                              witness="sentinel-not-the-sentinel")

    result = Result("assets", True,
                    summary=f"{len(BUNDLE_BINARIES)} binaries, {len(examples)} config "
                            f"examples, LICENSE; the sentinel resolves beside the "
                            f"client and runs, answering both usage probes as "
                            f"tunnel-deadman does")
    result.note("resolution replays tunnel_deadman::resolve_sentinel; both usage "
                "probes exited 2 from a cwd outside the bundle and the repository")
    # **The limit of this check, stated rather than left to be assumed from the
    # summary.**  Exit 2 on both usage probes rules out an absent, unexecutable
    # or wrong-architecture file; it does not rule out some *other* program
    # that also exits 2.  Identity of the bytes is `checksums` and
    # `provenance`, which bind bin/tunnel-deadman to a recorded digest, and the
    # `a decoy that also exits 2` control measures exactly this boundary --
    # `assets` green, `checksums` red -- so the layering is demonstrated
    # instead of claimed.
    result.note("behaviour only: exit 2 on both probes does not identify the bytes; "
                "checksums and provenance bind those, and a control measures the seam")
    result.note("doctor is not used here: since M6-C08 its containment answer "
                "requires a regular executable file, which rejects a zero-byte "
                "decoy, but it is a mode check and cannot tell an executable "
                "impostor from the sentinel -- it reads a path and starts "
                "nothing by design. This check runs the file, which is the "
                "stronger question and is only affordable at assembly time")
    return result


# Each CLI probe names the substring that proves the command actually produced
# its output.  Asserting exit status alone would pass a binary that printed
# nothing, which is the whole reason these are (command, witness) pairs.
CLI_PROBES = (
    ("tunnel-client", ["--help"], "tunnel-client"),
    ("tunnel-client", ["--version"], "tunnel-client "),
    ("tunnel-relay", ["--help"], "tunnel-relay"),
)


def check_cli(bundle: Path) -> Result:
    with tempfile.TemporaryDirectory() as workdir:
        work = Path(workdir)
        env = stranger_env(work)
        # Measured, not asserted.  The point of the scrubbed environment is
        # that the bundled binaries cannot reach this checkout's toolchain; if
        # `cargo` were still on the narrowed PATH the scrub would be doing
        # nothing and the note printed at the end would be a claim about a
        # condition nobody checked.
        if not cargo_is_unreachable(env):
            return Result("cli", False,
                          summary=f"cargo is still reachable on the narrowed PATH "
                                  f"{env['PATH']!r}; the clean-environment claim "
                                  f"would be untested",
                          witness="environment-not-scrubbed")
        for name, args, needle in CLI_PROBES:
            binary = bundle / "bin" / name
            if not binary.is_file():
                return Result("cli", False, summary=f"{name} absent",
                              witness="binary-missing")
            completed = run([str(binary)] + args, cwd=work, env=env)
            if completed.returncode != 0:
                return Result("cli", False,
                              summary=f"{name} {' '.join(args)} exited "
                                      f"{completed.returncode}",
                              witness="nonzero-exit")
            if needle not in completed.stdout:
                return Result("cli", False,
                              summary=f"{name} {' '.join(args)} printed "
                                      f"{len(completed.stdout)} bytes not containing "
                                      f"{needle!r}",
                              witness="output-content")

        # A real config check, from the bundle, on the bundle's own example.
        client = bundle / "bin" / "tunnel-client"
        config = bundle / "examples" / "m1-client.toml"
        completed = run([str(client), "config", "check", "--config", str(config)],
                        cwd=work, env=env)
        if completed.returncode != 0:
            return Result("cli", False,
                          summary=f"config check on the bundled example exited "
                                  f"{completed.returncode}: "
                                  f"{(completed.stderr or completed.stdout)[:160]}",
                          witness="config-check-failed")

        relay = bundle / "bin" / "tunnel-relay"
        completed = run([str(relay), "check-config",
                         str(bundle / "examples" / "relay.toml")], cwd=work, env=env)
        if completed.returncode != 0:
            return Result("cli", False,
                          summary=f"relay check-config on the bundled example exited "
                                  f"{completed.returncode}: "
                                  f"{(completed.stderr or completed.stdout)[:160]}",
                          witness="config-check-failed")

        # **And every bundled serving example through `check-serve-config`.**
        # `.github/workflows/ci.yml` documents why the previous line is not
        # enough: legacy `check-config` parses a different type and cannot
        # validate a serving document, "so without this step an example that
        # fails relay startup ships green".  The bundle ships `m1-relay.toml`,
        # which that workflow's `examples/*-relay.toml` glob selects, so
        # stopping at `check-config` here would reproduce in the release gate
        # exactly the hole CI added a step to close.
        serving = sorted((bundle / "examples").glob("*-relay.toml"))
        if not serving:
            return Result("cli", False,
                          summary="no *-relay.toml serving example in the bundle; the "
                                  "serving dry run would validate nothing",
                          witness="serving-example-missing")
        for example in serving:
            completed = run([str(relay), "check-serve-config", "--config", str(example)],
                            cwd=work, env=env)
            if completed.returncode != 0:
                return Result("cli", False,
                              summary=f"relay check-serve-config on {example.name} exited "
                                      f"{completed.returncode}: "
                                      f"{(completed.stderr or completed.stdout)[:160]}",
                              # A distinct witness from the two `check-config`
                              # steps above, deliberately: sharing one would
                              # let a control that corrupts a *client* example
                              # credit the serving dry run it never reached,
                              # and the serving dry run is the step that exists
                              # because the others cannot validate a serving
                              # document.
                              witness="serving-config-check-failed")

    result = Result("cli", True,
                    summary=f"{len(CLI_PROBES)} help/version probes, 2 config checks "
                            f"and {len(serving)} serving dry run(s), all from the "
                            f"unpacked bundle")
    result.note("each probe asserts an expected substring, not exit status alone")
    result.note("run with cwd in a temporary directory, PATH narrowed to the system "
                "directories and every CARGO_*/RUST* variable dropped; cargo proven "
                "unfindable on that PATH before the probes ran")
    return result


# **Exactly the directories macOS ships and protects, and nothing else.**
#
# An earlier version also accepted `@rpath/` and `/usr/local/lib/`, and neither
# belongs here.  `@rpath` is not a location at all: it resolves through the
# binary's own `LC_RPATH` entries, which a Cargo build can and does point at
# `target/`, so accepting it would wave through precisely the build-tree
# dependency this check exists to catch.  `/usr/local/lib` is where Homebrew
# installs, so a dependency there is present on the build machine and absent
# on a clean one -- the same failure wearing an absolute path.
#
# Neither appeared in this bundle (all 9 dependencies are `/usr/lib` or
# `/System`), so removing them changed no result here.  They were removed
# because the classifier's stated rule and its actual rule differed, which is
# the defect one level up from the one it checks for.
SYSTEM_PREFIXES = ("/usr/lib/", "/System/")


def check_portability(bundle: Path) -> Result:
    """Every bundled executable's dynamic dependencies are system paths.

    This is the only check here that can see the failure where a binary works
    perfectly on the build machine and nowhere else: a dynamic dependency
    resolved to a path inside `target/` or the source copy runs fine *here*
    and is missing on a clean machine.  Every other check in this file would
    be green.
    """
    tool = shutil.which("otool")
    if tool is None:
        return Result("portability", False, ran=False,
                      summary="otool is unavailable; dynamic dependencies were not inspected")

    inspected = 0
    total_deps = 0
    for name in BUNDLE_BINARIES:
        binary = bundle / "bin" / name
        if not binary.is_file():
            return Result("portability", False, summary=f"{name} absent",
                          witness="binary-missing")
        completed = run([tool, "-L", str(binary)])
        if completed.returncode != 0:
            return Result("portability", False,
                          summary=f"otool -L failed on {name}",
                          witness="otool-failed")
        deps = [line.strip().split(" (")[0]
                for line in completed.stdout.splitlines()[1:] if line.strip()]
        for dep in deps:
            total_deps += 1
            if not dep.startswith(SYSTEM_PREFIXES):
                return Result("portability", False,
                              summary=f"{name} links {dep}, which is not a system path",
                              witness="non-system-dependency")
        inspected += 1

    if inspected < MIN_EXECUTABLES:
        return Result("portability", False,
                      summary=f"inspected {inspected}, floor {MIN_EXECUTABLES}",
                      witness="floor")
    result = Result("portability", True,
                    summary=f"{inspected} executables, {total_deps} dynamic "
                            f"dependencies, all system paths")
    result.note("a dependency resolved inside the build tree would fail here and "
                "nowhere else in this gate")
    return result


# --------------------------------------------------------------------------
# Check: targets
#
# The other six checks answer "is this bundle sound?".  This one answers the
# question that made M6-01 unclosable: **which set is this bundle one of, and
# does everything that reads that set still agree about it?**
#
# Three readers of one declaration, compared against each other:
#
#   (1) this script's `tomllib` parse of `[workspace.metadata.release]`;
#   (2) `cargo metadata`'s view of the same table -- a reader this script did
#       not write, so a fault in (1) cannot hide behind it;
#   (3) the set the bundler froze into `PROVENANCE.txt` at build time.
#
# (3) is what makes a *divergence over time* visible rather than only a
# divergence right now: a bundle assembled against a three-triple set and
# checked after someone edited the manifest to two reddens, naming both sets.
# That is the control asked for by "fails if the declared set and whatever the
# tooling actually uses ever diverge".
#
# The check deliberately does **not** pass merely because the bundle's own
# triple is declared.  It always reports the declared targets this bundle does
# not cover, so a green `targets` can never be read as the set being covered.
# --------------------------------------------------------------------------
def check_targets(bundle: Path, manifest: Path | None = None) -> Result:
    path = bundle / PROVENANCE
    if not path.is_file():
        return Result("targets", False, summary=f"no {PROVENANCE} in bundle",
                      witness="provenance-file-missing")
    fields = parse_fields(read_exact(path))

    try:
        declared = declared_targets(manifest)
    except DeclarationError as error:
        return Result("targets", False, summary=str(error), witness=error.witness)

    recorded_raw = fields.get(PROVENANCE_TARGET_SET, "")
    if not recorded_raw:
        return Result(
            "targets", False,
            summary=f"{PROVENANCE} records no `{PROVENANCE_TARGET_SET}` field, so this "
                    "bundle does not say which set it was assembled against",
            witness="advertised-set-missing")
    recorded = sorted(t for t in (p.strip() for p in recorded_raw.split(",")) if t)
    if recorded != declared:
        return Result(
            "targets", False,
            summary=f"the bundle was assembled against {recorded} and the manifest now "
                    f"declares {declared}",
            witness="advertised-set-mismatch")

    result = Result("targets", True, summary="")

    # **The second reader is required, not optional.**  An earlier version
    # demoted its absence to a NOTE and still printed `ok` and exited 0, so
    # the whole "two independent readers" property could be silently absent --
    # and `check_cli` in this very file constructs an environment where
    # `cargo` is deliberately unfindable, which is exactly how such a hole
    # gets exercised by accident.  A check that keeps passing when half its
    # mechanism is missing is the shape docs/tasks.md M5-C11 exists for.
    by_cargo, status = cargo_declared_targets(manifest)
    if status in ("cargo-absent", "cargo-failed"):
        reason = {
            "cargo-absent": "`cargo` is not on PATH",
            "cargo-failed": "`cargo metadata` exited non-zero",
        }[status]
        return Result(
            "targets", False, ran=False,
            summary=(f"{reason}, so the second reader of this declaration DID NOT RUN. "
                     "Only tomllib and the bundle could be compared, and a reader that "
                     "did not run agrees with everything, so this is reported as DID "
                     "NOT RUN rather than folded into a pass."))
    if status != "ok":
        detail = {
            "unparseable-json": "`cargo metadata` produced output this check could not parse",
            "no-release-table": "`cargo metadata` reports no [workspace.metadata.release] table",
            "targets-not-a-list": "`cargo metadata` reports `advertised-targets` as something other than a list",
        }[status]
        return Result(
            "targets", False,
            summary=(f"{detail}, while tomllib reads {declared} from the same file. "
                     "That is the second reader DISAGREEING, not the second reader being "
                     "absent, and the two must not be reported as the same thing."),
            witness="second-reader-disagrees")
    if by_cargo != declared:
        return Result(
            "targets", False,
            summary=f"tomllib reads {declared} from the manifest and `cargo metadata` "
                    f"reads {by_cargo} from the same table",
            witness="advertised-set-mismatch")
    result.note(f"two independent readers agree: tomllib and `cargo metadata` both "
                f"return {len(declared)} triples from [workspace.metadata.release]")

    # Same rule as the second reader above: unreachable is DID NOT RUN, not a
    # note beside a green.
    known = rustc_known_targets()
    if known is None:
        return Result(
            "targets", False, ran=False,
            summary=("`rustc --print target-list` could not be read, so the declared "
                     "triples were NOT checked against a real target list. Reported as "
                     "DID NOT RUN rather than noted beside a pass."))
    unknown = [t for t in declared if t not in known]
    if unknown:
        return Result(
            "targets", False,
            summary=f"declared but unknown to rustc {len(known)}-target list: {unknown}",
            witness="advertised-target-unknown")
    result.note(f"all {len(declared)} declared triples appear in rustc's "
                f"{len(known)}-target list, so none is a typo that would only "
                "surface at build time")

    bundle_target = fields.get("target", "")
    if bundle_target not in declared:
        return Result(
            "targets", False,
            summary=f"this bundle's target {bundle_target!r} is not in the advertised "
                    f"set {declared}",
            witness="target-not-advertised")

    uncovered = [t for t in declared if t != bundle_target]
    result.summary = (f"{bundle_target} is 1 of {len(declared)} advertised targets; "
                      f"{len(uncovered)} NOT covered by this bundle: {uncovered}")
    result.note("this bundle is evidence for its own target and for no other. "
                "M6-01 closes when every declared target has a bundle that passes "
                "these checks on a host that can execute it -- see M6-C13 for the "
                "build route for the two Linux triples")
    return result


CHECKS = {
    "checksums": check_checksums,
    "provenance": check_provenance,
    "notices": check_notices,
    "assets": check_assets,
    "targets": check_targets,
    "cli": check_cli,
    "portability": check_portability,
}


# --------------------------------------------------------------------------
# Controls
#
# Each control copies the bundle, defeats one mechanism, re-runs one check,
# and requires it to go red **with a named witness**.  A red result carrying a
# different witness is reported as a wrong witness and fails, in the shape
# scripts/m0-guard-exit-codes.py established: a control that accepts any
# failure would pass even when the check broke for an unrelated reason, which
# is the same defect one level up.
# --------------------------------------------------------------------------


def copy_bundle(bundle: Path, destination: Path) -> Path:
    target = destination / bundle.name
    shutil.copytree(bundle, target, symlinks=True)
    # The build copies binaries out read-only (mode 555), which is correct for
    # a shipped bundle and would make every control that mutates one fail with
    # PermissionError rather than with its check's verdict.  The throwaway copy
    # is made writable so a control failure means the check failed, not that
    # the control could not run.
    for path in target.rglob("*"):
        if path.is_file():
            path.chmod(path.stat().st_mode | stat.S_IWUSR)
    return target


def expect_red(check: str, bundle: Path, expected_witness: str, **kwargs) -> tuple[bool, str]:
    result = CHECKS[check](bundle, **kwargs)
    if result.ok:
        return False, (f"{check} stayed GREEN with its mechanism defeated "
                       f"({result.summary})")
    if not result.ran:
        return False, f"{check} did not run ({result.summary}); that is not a red"
    if result.witness != expected_witness:
        return False, (f"{check} went red for the wrong reason: expected witness "
                       f"{expected_witness!r}, got {result.witness!r} "
                       f"({result.summary})")
    return True, f"{check} went red with witness {expected_witness!r}: {result.summary}"


def control_checksum_flipped_byte(bundle: Path) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        victim = copy / "examples" / "client.toml"
        data = bytearray(victim.read_bytes())
        data[0] ^= 0x01
        victim.write_bytes(bytes(data))
        return expect_red("checksums", copy, "digest-mismatch")


def control_checksum_removed_file(bundle: Path) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        (copy / "examples" / "client.toml").unlink()
        return expect_red("checksums", copy, "file-missing")


def control_checksum_smuggled_file(bundle: Path) -> tuple[bool, str]:
    """An added file nothing attests must be caught.

    A checksum file that only verifies what it lists would pass a bundle with
    an extra executable dropped into it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        (copy / "bin" / "smuggled").write_bytes(b"not attested by anything\n")
        return expect_red("checksums", copy, "file-unlisted")


def control_provenance_binary_swapped(bundle: Path) -> tuple[bool, str]:
    """The hash proves the bytes; this proves the hash is checked against them."""
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        shutil.copy2(copy / "bin" / "tunnel-deadman", copy / "bin" / "tunnel-client")
        return expect_red("provenance", copy, "binary-digest-mismatch")


def control_provenance_forged_commit(bundle: Path) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        path = copy / PROVENANCE
        write_exact(path, re.sub(r"^commit: .*$", "commit: not-a-commit",
                               read_exact(path), flags=re.M))
        return expect_red("provenance", copy, "commit-malformed")


def control_provenance_wrong_toolchain(bundle: Path) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        path = copy / PROVENANCE
        write_exact(path, re.sub(r"^rustc_version: .*$", "rustc_version: rustc 1.90.0",
                               read_exact(path), flags=re.M))
        return expect_red("provenance", copy, "toolchain-mismatch")


def control_notices_dropped_crate(bundle: Path) -> tuple[bool, str]:
    """A crate quietly removed from NOTICE must be detected.

    This is the staleness failure a hand-written notices file has: the
    lockfile moves and the notices file does not.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        path = copy / NOTICE
        lines = read_exact(path).splitlines(keepends=True)
        rule = next(i for i, line in enumerate(lines) if line.startswith("=" * 70))
        # Drop the first body entry: its name line and its indented detail.
        start = rule + 2
        end = start + 1
        while end < len(lines) and (lines[end].startswith(" ") or not lines[end].strip()):
            end += 1
        del lines[start:end]
        write_exact(path, "".join(lines))
        return expect_red("notices", copy, "crate-set-mismatch")


def control_notices_stale_lockfile(bundle: Path) -> tuple[bool, str]:
    """A NOTICE generated against a different lockfile must be detected."""
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        lock = copy / LOCKFILE
        lock.write_text(lock.read_text() + "\n# an edit the NOTICE never saw\n")
        return expect_red("notices", copy, "lock-digest-mismatch")


def control_notices_texts_stripped(bundle: Path) -> tuple[bool, str]:
    """A NOTICE reduced to identifiers and digests must not pass.

    **This is the control for the defect the first version of this file
    shipped.** Removing every embedded licence text leaves a NOTICE whose
    crate set still matches the lockfile exactly, whose header still matches
    its lockfile digest, and whose every other assertion still holds -- a
    perfectly consistent index to licences the recipient does not have. It
    must go red for the texts being gone, and for nothing else.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        path = copy / NOTICE
        kept = []
        inside = False
        for line in read_exact(path).splitlines():
            if line.startswith(TEXT_BEGIN):
                inside = True
                continue
            if line.startswith(TEXT_END):
                inside = False
                continue
            if not inside:
                kept.append(line)
        write_exact(path, "\n".join(kept) + "\n")
        return expect_red("notices", copy, "embedded-text-count-mismatch")


def control_notices_text_floor_is_not_vacuous(bundle: Path) -> tuple[bool, str]:
    """A NOTICE whose header agrees with a gutted body must still fail.

    The previous control leaves the header claiming texts the body lacks, so
    it is caught by the count comparison.  This one keeps header and body
    *consistent* at one tiny text, which defeats that comparison and must be
    caught by the byte floor instead -- otherwise a NOTICE could shrink to
    nothing as long as it was honest about it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        path = copy / NOTICE
        kept = []
        inside = False
        dropped = 0
        for line in read_exact(path).splitlines():
            if line.startswith(TEXT_BEGIN):
                inside = True
                dropped += 1
                if dropped > 1:
                    continue
            elif line.startswith(TEXT_END):
                if dropped > 1:
                    inside = False
                    continue
                inside = False
            elif inside and dropped > 1:
                continue
            kept.append(line)
        text = "\n".join(kept) + "\n"
        embedded, embedded_bytes = notice_embedded_texts(text)
        text = re.sub(r"^embedded_licence_texts: .*$",
                      f"embedded_licence_texts: {embedded}", text, flags=re.M)
        text = re.sub(r"^embedded_licence_bytes: .*$",
                      f"embedded_licence_bytes: {embedded_bytes}", text, flags=re.M)
        text = re.sub(r"^registry_crates_with_licence_text: .*$",
                      "registry_crates_with_licence_text: 1", text, flags=re.M)
        write_exact(path, text)
        return expect_red("notices", copy, "licence-text-floor")


def control_notices_text_replaced_by_filler(bundle: Path) -> tuple[bool, str]:
    """Same-length filler in place of a real licence must not pass.

    **This is the hole the count and the byte total cannot see.** Replacing a
    block's content with filler of exactly the same length leaves the number
    of blocks and the total byte count untouched, so before the digests were
    bound this produced a green `notices` over a NOTICE carrying no licence at
    all.  The control preserves the length deliberately, so it fails if the
    check ever falls back to measuring size.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        path = copy / NOTICE
        text = read_exact(path)
        blocks = notice_licence_blocks(text)
        if not blocks:
            return False, "the bundled NOTICE embeds no licence texts to tamper with"
        _, _, content = blocks[0]
        filler = "".join("x" if c != "\n" else "\n" for c in content)
        if filler == content:
            return False, "filler is identical to the original content"
        replaced = text.replace(content, filler, 1)
        if replaced == text:
            return False, "could not substitute the first licence block"
        write_exact(path, replaced)

        after = notice_licence_blocks(replaced)
        if len(after) != len(blocks):
            return False, f"the substitution changed the block count ({len(blocks)} -> {len(after)})"
        before_bytes = sum(len(c.encode()) for _, _, c in blocks)
        after_bytes = sum(len(c.encode()) for _, _, c in after)
        if before_bytes != after_bytes:
            return False, (f"the substitution changed the byte total "
                           f"({before_bytes} -> {after_bytes}); this control is only "
                           f"meaningful while both figures are preserved")
        ok, detail = expect_red("notices", copy, "licence-text-digest-mismatch")
        if not ok:
            return ok, detail
        return True, (f"{detail}; block count and byte total both unchanged, so only "
                      f"the digest could have caught it")


def control_notices_unbound_text_is_refused(bundle: Path) -> tuple[bool, str]:
    """A block whose marker carries no digest must be refused, not skipped.

    Without this, stripping `sha256=` from a marker would quietly exempt that
    block from the only check that looks inside it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        path = copy / NOTICE
        text = read_exact(path)
        stripped = re.sub(rf"^({re.escape(TEXT_BEGIN)} .*) sha256=[0-9a-f]{{64}}$",
                          r"\1", text, count=1, flags=re.M)
        if stripped == text:
            return False, "no BEGIN marker carried a digest to strip"
        write_exact(path, stripped)
        return expect_red("notices", copy, "licence-text-unbound")


def control_notices_false_unresolved_claim(bundle: Path) -> tuple[bool, str]:
    """A crate cannot be both notified and declared out of the resolved graph.

    Without this, the "declared outside the graph" block would be a way to
    make any accounting discrepancy disappear: list everything there and the
    subtraction always balances.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        path = copy / NOTICE
        text = read_exact(path)
        notified = sorted(notice_crate_set(text))
        if not notified:
            return False, "the bundled NOTICE notifies no crates at all"
        name, version = notified[0]
        head, rule, rest = text.partition(UNRESOLVED_RULE)
        write_exact(path, f"{head}{rule}\n  {name} {version}{rest}")
        return expect_red("notices", copy, "unresolved-declaration-bogus")


def control_assets_sentinel_removed(bundle: Path) -> tuple[bool, str]:
    """The sharp one.

    Removing `bin/tunnel-deadman` leaves a bundle in which every binary still
    runs, `--help`, `--version` and both config checks still pass, and the
    only symptom is a `degraded` doctor capability and a one-line warning.
    This control requires the gate to notice, and to notice *for that reason*
    -- `sentinel-missing`, not a generic failure.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        (copy / "bin" / "tunnel-deadman").unlink()
        ok, detail = expect_red("assets", copy, "sentinel-missing")
        if not ok:
            return ok, detail
        # And the point of the control: the *other* checks stay green, which
        # is why a file-existence check somewhere else is not a substitute.
        cli = check_cli(copy)
        if not cli.ok:
            return False, (f"{detail}; but cli also went red ({cli.summary}), so this "
                           f"control no longer isolates the silent-degradation case")
        return True, (f"{detail}; cli stayed green: the degradation is invisible to "
                      f"help, version and both config checks, and surfaces only as a "
                      f"one-line stderr warning when an export first arms a sentinel")


def control_assets_sentinel_is_a_decoy(bundle: Path) -> tuple[bool, str]:
    """A file of the right name that is not the sentinel must be caught.

    This is the case the product's own rule misses: `resolve_sentinel` accepts
    any `is_file()`, so an empty file named `tunnel-deadman` makes
    `availability()` answer `Armable` while every arming attempt fails.  The
    control plants exactly that and requires the gate to go red for *being the
    wrong binary*, not for the file being absent -- the two witnesses are
    distinct on purpose, because they need different fixes.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        decoy = copy / "bin" / "tunnel-deadman"
        decoy.unlink()
        decoy.write_text("#!/bin/sh\nexit 0\n")
        decoy.chmod(decoy.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return expect_red("assets", copy, "sentinel-not-the-sentinel")


def control_assets_decoy_that_exits_two(bundle: Path) -> tuple[bool, str]:
    """Measure the seam between behaviour and identity, rather than claim it.

    `assets` probes behaviour, so a decoy that also exits 2 passes it.  That is
    a real limit and the honest thing to do with it is to *demonstrate* where
    it is covered: this control requires `assets` to stay **green** on such a
    decoy and `checksums` to go **red**, because the digest binds the bytes.

    Written this way the control fails if either half stops holding -- if
    `assets` ever started catching this it would be over-claiming, and if
    `checksums` stopped catching it the decoy would ship.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        decoy = copy / "bin" / "tunnel-deadman"
        decoy.unlink()
        decoy.write_text("#!/bin/sh\nexit 2\n")
        decoy.chmod(decoy.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        behaviour = CHECKS["assets"](copy)
        if not behaviour.ok:
            return False, (f"assets went red on a decoy that exits 2 "
                           f"({behaviour.summary}); this control documents that it "
                           f"does not, so either the check or this note is now wrong")
        identity = CHECKS["checksums"](copy)
        if identity.ok:
            return False, "checksums stayed green on a substituted binary"
        if identity.witness != "digest-mismatch":
            return False, (f"checksums went red with witness {identity.witness!r}, "
                           f"not the digest mismatch that proves the bytes are bound")
        return True, ("assets green (behaviour matches) and checksums red with "
                      "'digest-mismatch' (bytes do not): the seam is where it is "
                      "documented to be")


def control_cli_content_not_exit_status(bundle: Path) -> tuple[bool, str]:
    """A binary that exits 0 and prints nothing must not pass.

    Replaces the client with a script that succeeds silently.  An exit-status
    check would call this a pass.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        stub = copy / "bin" / "tunnel-client"
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return expect_red("cli", copy, "output-content")


def control_cli_config_check_is_real(bundle: Path) -> tuple[bool, str]:
    """The config check must actually parse the example.

    A corrupted example must make it red; if it does not, the "config check"
    is validating nothing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        (copy / "examples" / "m1-client.toml").write_text("this is not = valid toml [[\n")
        return expect_red("cli", copy, "config-check-failed")


def control_cli_environment_scrub_is_checked(bundle: Path) -> tuple[bool, str]:
    """The environment guard must itself be exercised.

    `environment-not-scrubbed` was the one witness in this file with no
    control: the guard was shown to work by hand and never by the suite, which
    is the same "unexercised is untested" argument the rest of this file makes
    about everything else.

    The control replaces `stranger_env` with one whose PATH contains a
    directory holding an executable named `cargo`, which is exactly the state
    the guard exists to refuse, and requires `cli` to go red naming it.
    """
    global stranger_env
    with tempfile.TemporaryDirectory() as tmp:
        fake_bin = Path(tmp) / "bin"
        fake_bin.mkdir()
        cargo = fake_bin / "cargo"
        cargo.write_text("#!/bin/sh\nexit 0\n")
        cargo.chmod(cargo.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        original = stranger_env

        def leaky(workdir: Path) -> dict[str, str]:
            env = original(workdir)
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            return env

        stranger_env = leaky
        try:
            # Sanity: the replacement really does make cargo reachable, or the
            # control would be testing nothing.
            if cargo_is_unreachable(stranger_env(Path(tmp))):
                return False, "the planted cargo is still unreachable; control is vacuous"
            return expect_red("cli", bundle, "environment-not-scrubbed")
        finally:
            stranger_env = original


def control_cli_serving_dry_run_is_real(bundle: Path) -> tuple[bool, str]:
    """The serving dry run must actually parse the serving example.

    Its own witness, so this cannot be credited by the client config check
    failing first.  Without this control the serving step could be skipped
    entirely -- for instance if the glob stopped matching -- and `cli` would
    stay green, which is the hole CI's own comment says the step exists to
    close.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        (copy / "examples" / "m1-relay.toml").write_text("[not a serving document\n")
        return expect_red("cli", copy, "serving-config-check-failed")


def control_cli_serving_example_must_exist(bundle: Path) -> tuple[bool, str]:
    """A bundle with no serving example must not pass a serving dry run.

    The glob-matched-nothing case: zero iterations of a loop is a silent pass.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        for example in (copy / "examples").glob("*-relay.toml"):
            example.unlink()
        return expect_red("cli", copy, "serving-example-missing")


def control_portability_non_system_dependency(bundle: Path) -> tuple[bool, str]:
    """A binary linking outside the system must be caught.

    Real `install_name_tool` surgery would need a writable Mach-O rewrite;
    instead this control proves the *classifier* rejects a build-tree path,
    which is the rule the check turns on.  Both directions are exercised: a
    system path is accepted and a target/ path is not.
    """
    accept = [
        "/usr/lib/libSystem.B.dylib",
        "/System/Library/Frameworks/Security.framework/Versions/A/Security",
    ]
    # Each of these is a dependency that works on the build machine and is
    # missing or attacker-controlled on a clean one.  `@rpath` and
    # `/usr/local/lib` are in this list because the classifier used to accept
    # them.
    reject = [
        "/Users/someone/repo/target/release/deps/libthing.dylib",
        "@rpath/libthing.dylib",
        "@executable_path/../lib/libthing.dylib",
        "@loader_path/libthing.dylib",
        "/usr/local/lib/libssl.3.dylib",
        "/opt/homebrew/lib/libssl.3.dylib",
        "/Users/someone/.cargo/registry/src/libthing.dylib",
    ]
    for path in accept:
        if not path.startswith(SYSTEM_PREFIXES):
            return False, f"classifier rejected the system path {path}"
    for path in reject:
        if path.startswith(SYSTEM_PREFIXES):
            return False, f"classifier accepted the non-system path {path}"
    return True, (f"{len(accept)} system paths accepted and {len(reject)} rejected, "
                  f"including @rpath, @executable_path, @loader_path, /usr/local/lib "
                  f"and /opt/homebrew, which resolve off the build machine or not at "
                  f"all on a clean one")


def control_lockfile_parser_is_not_universal(bundle: Path) -> tuple[bool, str]:
    """The lockfile parser must return nothing for a lockfile with no packages.

    A parser that returned a fixed list, or that silently swallowed a parse
    failure, would make `notices` agree with itself forever.
    """
    if parse_lockfile("") != []:
        return False, "parser returned entries for an empty lockfile"
    if parse_lockfile("[[package]]\nname = \"x\"\nversion = \"1\"\n") != []:
        return False, "parser accepted a package with no source as a registry crate"
    one = parse_lockfile(
        '[[package]]\nname = "x"\nversion = "1"\nsource = "registry+https://e/"\n'
    )
    if one != [("x", "1")]:
        return False, f"parser did not read a well-formed registry package: {one}"
    return True, ("empty -> 0 crates, sourceless package -> 0 crates, one registry "
                  "package -> 1 crate")


# Two entries below are **unit probes, not witness controls**, and the
# distinction is recorded here because collapsing it overstates the suite.
# A witness control defeats a mechanism in a real bundle and requires the
# corresponding check to go red naming the witness it planted.  A unit probe
# invokes no check at all: it exercises a pure function's rule in both
# directions.  Both are worth running; only the first is evidence that a check
# can fail.  `--self-test` counts and labels them separately, so a reader
# cannot take 17 witness controls from a suite that has 15.
# --------------------------------------------------------------------------
# Controls for `targets`.
#
# The triples written below are the only triples in this file outside the
# declaration's own reader.  **Most, not all, are values the check must
# reject**: `NOT_A_REAL_TRIPLE` and `UNDECLARED_TRIPLE` are, but the probes
# below also use `aarch64-apple-darwin` as an *accepted* value -- in the
# duplicate and bare-string parser cases, and as one of the two sets the
# cargo-reader probe declares in its throwaway workspace.  The earlier
# wording here said every one of them was a rejected value, which was simply
# not true of three of them.
#
# What matters is the weaker and actually-true property: **none of them is a
# second copy of the advertised set**, and nothing outside this controls
# section reads any of them.  The check and the reader resolve the manifest.
# --------------------------------------------------------------------------
NOT_A_REAL_TRIPLE = "aarch64-unknown-moonos"
#: A real rustc target that is deliberately NOT advertised.  It was
#: `x86_64-pc-windows-msvc` until the owner's M6-C11 decision put that triple
#: **into** the declared set, at which point three controls here silently
#: stopped testing what they named -- the one that should have reddened for
#: `target-not-advertised` reddened for `advertised-set-mismatch` instead, and
#: only the witness rule caught it.  `assert_undeclared` below turns that from
#: a thing that happened into a thing that fails loudly.
UNDECLARED_TRIPLE = "i686-unknown-linux-gnu"


def assert_undeclared() -> str | None:
    """Return an error if `UNDECLARED_TRIPLE` has become advertised.

    Every control that plants an "outside the set" value depends on this
    constant actually being outside the set.  When the declared set changes
    under it, those controls do not fail -- they quietly test something else.
    """
    try:
        declared = declared_targets()
    except DeclarationError as error:
        return f"the declaration could not be read, so the control cannot apply: {error}"
    if UNDECLARED_TRIPLE in declared:
        return (f"UNDECLARED_TRIPLE {UNDECLARED_TRIPLE!r} is now in the advertised set "
                f"{declared}. This control no longer plants an undeclared triple and is "
                "testing something other than what it names. Pick another triple.")
    return None


def rewrite_provenance(bundle: Path, key: str, value: str | None) -> bool:
    """Set `key` in a copied bundle's PROVENANCE.txt, or drop it when None.

    Returns False when the key was not there to rewrite, so a control whose
    mutation silently did nothing fails as a broken control instead of
    reporting whatever the untouched bundle happened to say.
    """
    path = bundle / PROVENANCE
    lines = read_exact(path).splitlines()
    out: list[str] = []
    seen = False
    for line in lines:
        if line.startswith(f"{key}:"):
            seen = True
            if value is None:
                continue
            out.append(f"{key}: {value}")
        else:
            out.append(line)
    if not seen:
        return False
    write_exact(path, "\n".join(out) + "\n")
    # SHA256SUMS now disagrees, which is `checksums`' business and not this
    # check's; `targets` reads PROVENANCE directly, exactly as it does in a
    # real run.
    return True


def temp_manifest(tmp: Path, transform) -> Path:
    """A throwaway copy of the real workspace manifest, mutated by `transform`.

    The declaration is never edited in place.  Mutating a copy is what lets a
    control ask "what happens when the manifest changes under a bundle that
    already shipped?" without writing to the repository.
    """
    text = (REPO / MANIFEST).read_text(encoding="utf-8")
    manifest = tmp / MANIFEST
    manifest.write_text(transform(text), encoding="utf-8")
    return manifest


def standalone_manifest(tmp: Path, targets: list[str]) -> Path:
    """A minimal workspace manifest `cargo metadata` can actually load.

    `temp_manifest` copies the real root manifest, which still carries
    `[workspace] members`.  Those member directories do not exist beside a
    throwaway copy, so cargo fails to load it (exit 101, "failed to load
    manifest for workspace member") and `check_targets` reports the second
    reader as DID NOT RUN.  A control whose rule fires *before* the second
    reader is unaffected; a control whose rule fires *after* it -- the rustc
    known-triple test -- can never be reached that way.  That was
    docs/tasks.md M6-C17.

    `members = []` is a real, loadable virtual workspace, so both readers
    answer and the rule is reachable.  Not copying the real declaration
    costs nothing here: a control for this rule must declare a triple that
    is deliberately wrong, so it was never exercising the real set.  The
    real declaration is covered by the set-comparison controls above and by
    the live `targets` check.
    """
    body = ",\n    ".join(f'"{t}"' for t in targets)
    manifest = tmp / MANIFEST
    manifest.write_text(
        '[workspace]\nmembers = []\nresolver = "2"\n\n'
        f"[workspace.metadata.release]\nadvertised-targets = [\n    {body},\n]\n",
        encoding="utf-8")
    return manifest


def control_targets_bundle_target_is_not_advertised(bundle: Path) -> tuple[bool, str]:
    """A bundle for a triple outside the declared set must not pass.

    This is the case the declaration exists to make checkable: before it, a
    bundle for any triple at all was "a release artifact" and nothing could
    say otherwise.
    """
    broken = assert_undeclared()
    if broken:
        return False, broken
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        if not rewrite_provenance(copy, "target", UNDECLARED_TRIPLE):
            return False, "PROVENANCE.txt has no `target:` line; the control did not apply"
        return expect_red("targets", copy, "target-not-advertised")


def control_targets_frozen_set_diverges_from_manifest(bundle: Path) -> tuple[bool, str]:
    """The set the bundle froze must still equal the set now declared.

    Defeated from the bundle's side: a bundle assembled against a narrower set
    than the one the manifest declares today is exactly the artifact that
    would otherwise be presented as covering the current commitment.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copy = copy_bundle(bundle, Path(tmp))
        declared = declared_targets()
        narrowed = ",".join(declared[:-1])
        if not narrowed:
            return False, "the declared set has fewer than two triples; nothing to narrow"
        if not rewrite_provenance(copy, PROVENANCE_TARGET_SET, narrowed):
            return False, (f"PROVENANCE.txt has no `{PROVENANCE_TARGET_SET}:` line; the "
                           "control did not apply")
        return expect_red("targets", copy, "advertised-set-mismatch")


def control_targets_manifest_edit_reddens_a_shipped_bundle(bundle: Path) -> tuple[bool, str]:
    """The same divergence from the *declaration's* side, the bundle untouched.

    This is the control the requirement names: the declared set and what the
    tooling actually shipped are compared, and an edit to one of them alone
    goes red.  The bundle here is the real, unmodified artifact; only a
    throwaway copy of the manifest moves.
    """
    broken = assert_undeclared()
    if broken:
        return False, broken
    with tempfile.TemporaryDirectory() as tmp:
        manifest = temp_manifest(
            Path(tmp),
            lambda text: text.replace(
                "advertised-targets = [",
                f'advertised-targets = [\n    "{UNDECLARED_TRIPLE}",',
                1),
        )
        if declared_targets(manifest) == declared_targets():
            return False, ("the mutated manifest declares the same set as the real one; "
                           "the control did not apply")
        return expect_red("targets", bundle, "advertised-set-mismatch", manifest=manifest)


def control_targets_no_declaration_is_not_a_pass(bundle: Path) -> tuple[bool, str]:
    """Deleting the declaration must fail, not fall back to a default.

    The state this repository was in until this change -- no referent for
    "advertised" anywhere (M6-C04) -- must read as a failure rather than as a
    check with nothing to compare.
    """
    with tempfile.TemporaryDirectory() as tmp:
        manifest = temp_manifest(
            Path(tmp),
            lambda text: re.sub(r"(?ms)^\[workspace\.metadata\.release\].*?(?=^\[)", "", text),
        )
        if "[workspace.metadata.release]" in manifest.read_text(encoding="utf-8"):
            return False, "the release table survived the control's edit; it did not apply"
        return expect_red("targets", bundle, "advertised-set-missing", manifest=manifest)


def control_targets_unknown_triple_is_refused(bundle: Path) -> tuple[bool, str]:
    """A declared triple rustc does not know must fail here, not at build time.

    Both sides are moved together -- the manifest declares the bogus triple
    *and* the bundle's frozen set is rewritten to agree -- so the set
    comparison passes and the control actually reaches the rustc check it
    names.  Moving only the manifest would redden with
    `advertised-set-mismatch` and credit this control with a mechanism it
    never exercised.
    """
    known = rustc_known_targets()
    if known is None:
        return False, "rustc is unreachable, so this control DID NOT RUN"
    if NOT_A_REAL_TRIPLE in known:
        return False, f"{NOT_A_REAL_TRIPLE} is a real rustc target; pick another"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        copy = copy_bundle(bundle, root)
        bundle_target = parse_fields(read_exact(copy / PROVENANCE)).get("target", "")
        if bundle_target not in known:
            return False, (f"the bundle's own target {bundle_target!r} is not in rustc's "
                           "target list; the control cannot attribute a red to the "
                           "bogus triple")

        def frozen(targets: list[str]) -> str | None:
            """Declare `targets` and freeze the same set into the bundle copy."""
            declared = sorted(targets)
            written = standalone_manifest(ws, declared)
            if declared_targets(written) != declared:
                return "the standalone manifest did not read back as declared"
            if not rewrite_provenance(copy, PROVENANCE_TARGET_SET, ",".join(declared)):
                return "could not rewrite the frozen set; the control did not apply"
            return None

        # The negative arm first: the same construction, with every declared
        # triple real.  It must go GREEN.  Without this, a red below could be
        # coming from the standalone manifest itself -- an unloadable
        # workspace, a set the bundle does not match -- rather than from the
        # rule this control names, which is exactly the failure mode M6-C17
        # was.
        ws = root / "ws-known"
        ws.mkdir()
        broken = frozen([bundle_target])
        if broken:
            return False, broken
        control = check_targets(copy, manifest=ws / MANIFEST)
        if not control.ran:
            return False, (f"the all-known control arm DID NOT RUN ({control.summary}); "
                           "the second reader must answer for this construction or the "
                           "rule below is unreachable")
        if not control.ok:
            return False, (f"the all-known control arm went red ({control.witness}: "
                           f"{control.summary}); a red in the test arm could not then be "
                           "attributed to the unknown triple")

        # The test arm: identical but for one triple rustc does not know.
        ws = root / "ws-bogus"
        ws.mkdir()
        broken = frozen([bundle_target, NOT_A_REAL_TRIPLE])
        if broken:
            return False, broken
        ok, detail = expect_red("targets", copy, "advertised-target-unknown",
                                manifest=ws / MANIFEST)
        if not ok:
            return False, detail
        return True, (f"{detail}; and the same construction declaring only "
                      f"{bundle_target} goes green, so the red is attributable to "
                      f"{NOT_A_REAL_TRIPLE} and not to the throwaway workspace")


def control_targets_declaration_parser_rejects_junk(bundle: Path) -> tuple[bool, str]:
    """`declared_targets` in both directions -- a unit probe, not a witness control.

    It invokes no check.  It exists because every set comparison above is
    vacuous if the parser accepts an empty list: an empty advertised set makes
    every bundle cover all of it.
    """
    cases: list[tuple[str, str]] = [
        ("advertised-targets = []", "advertised-set-malformed"),
        ('advertised-targets = ["aarch64-apple-darwin", "aarch64-apple-darwin"]',
         "advertised-set-malformed"),
        ('advertised-targets = ["linux"]', "advertised-set-malformed"),
        ('advertised-targets = "aarch64-apple-darwin"', "advertised-set-malformed"),
        ("# no key at all", "advertised-set-missing"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        for index, (replacement, expected) in enumerate(cases):
            manifest = Path(tmp) / f"case{index}.toml"
            manifest.write_text(
                "[workspace]\nmembers = []\n\n[workspace.metadata.release]\n"
                + replacement + "\n",
                encoding="utf-8")
            try:
                got = declared_targets(manifest)
            except DeclarationError as error:
                if error.witness != expected:
                    return False, (f"case {index} raised witness {error.witness!r}, "
                                   f"expected {expected!r}")
                continue
            return False, f"case {index} was ACCEPTED as {got}; it must be refused"
        # And the real declaration must still be accepted, so the parser is not
        # simply refusing everything.
        accepted = declared_targets()
    return True, (f"the parser refuses an empty list, a duplicate, a non-triple, a bare "
                  f"string and a missing key with the right witness in each of "
                  f"{len(cases)} cases, and still accepts the real declaration's "
                  f"{len(accepted)} triples")


def control_targets_cargo_is_a_live_second_reader(bundle: Path) -> tuple[bool, str]:
    """`cargo metadata` really reads this table -- a unit probe, not a control.

    The claim "two independent readers" is worthless if the second one is
    stubbed or silently returning `None`.  A throwaway workspace is built with
    a declaration, read with both readers, then the declaration is changed and
    read again: cargo must follow the change.  It is a probe because it
    invokes no check.
    """
    if shutil.which("cargo") is None:
        return False, "cargo is not installed, so this probe DID NOT RUN"
    # Arbitrary values for a throwaway workspace, not a copy of the declared
    # set: what matters is only that the two lists differ, so cargo can be
    # shown following a change rather than agreeing with a fixed answer.  The
    # second deliberately includes a triple that is NOT advertised.
    broken = assert_undeclared()
    if broken:
        return False, broken
    first = ["aarch64-apple-darwin"]
    second = ["aarch64-apple-darwin", UNDECLARED_TRIPLE]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "member" / "src").mkdir(parents=True)
        (root / "member" / "src" / "lib.rs").write_text("", encoding="utf-8")
        (root / "member" / MANIFEST).write_text(
            '[package]\nname = "member"\nversion = "0.0.0"\nedition = "2021"\n',
            encoding="utf-8")
        manifest = root / MANIFEST

        def declare(targets: list[str]) -> None:
            body = ",\n    ".join(f'"{t}"' for t in targets)
            manifest.write_text(
                '[workspace]\nmembers = ["member"]\nresolver = "2"\n\n'
                f"[workspace.metadata.release]\nadvertised-targets = [\n    {body},\n]\n",
                encoding="utf-8")

        declare(first)
        by_cargo_first, status_first = cargo_declared_targets(manifest)
        by_toml_first = declared_targets(manifest)
        declare(second)
        by_cargo_second, status_second = cargo_declared_targets(manifest)

    if status_first != "ok" or status_second != "ok":
        return False, ("`cargo metadata` did not answer for the throwaway workspace "
                       f"(statuses {status_first!r}, {status_second!r}), so the second "
                       "reader DID NOT RUN and this probe measured nothing")
    if by_cargo_first != sorted(first) or by_toml_first != sorted(first):
        return False, (f"the two readers disagreed on a manifest declaring {first}: "
                       f"cargo={by_cargo_first} tomllib={by_toml_first}")
    if by_cargo_second != sorted(second):
        return False, (f"the declaration changed to {second} and cargo still reads "
                       f"{by_cargo_second}; it is not reading this table live")
    return True, ("`cargo metadata --no-deps` returns exactly what "
                  "[workspace.metadata.release] declares in a throwaway workspace, and "
                  "follows the declaration when it changes from 1 triple to 2 -- so the "
                  "second reader is live rather than a stub that agrees with everything")


def control_targets_absent_second_reader_is_not_a_pass(bundle: Path) -> tuple[bool, str]:
    """With `cargo` unfindable, `targets` must NOT report ok.

    **This control exists because the check used to pass in exactly this
    state.**  `cargo_declared_targets` returned `None`, the check demoted it
    to a NOTE, and the head line still read `ok` with exit 0 -- so the "two
    independent readers" property could be entirely absent from a green run.
    `check_cli` in this same file deliberately narrows `PATH` until `cargo` is
    unfindable, so this is a state the gate constructs on purpose elsewhere.

    The required result is `ran=False` -- DID NOT RUN, which `cmd_verify`
    turns into exit 2 -- and not merely "not ok": a check that could not run
    is not a red either, and conflating the two is the same collapse one level
    down.
    """
    saved = os.environ.get("PATH", "")
    try:
        # A PATH with no cargo on it.  An empty string would make `which`
        # fall back to a default path on some platforms, so use a real
        # directory that certainly holds no cargo.
        with tempfile.TemporaryDirectory() as empty:
            os.environ["PATH"] = empty
            if shutil.which("cargo") is not None:
                return False, "cargo is still findable, so the control did not apply"
            result = check_targets(bundle)
    finally:
        os.environ["PATH"] = saved
    if result.ok:
        return False, ("targets reported ok with `cargo` unfindable, so the second "
                       "reader can be silently absent from a green run")
    if result.ran:
        return False, (f"targets went red rather than DID NOT RUN ({result.summary}); an "
                       "unreachable reader is an inability to check, not a failed check")
    if "DID NOT RUN" not in result.summary:
        return False, f"it did not say so: {result.summary}"
    return True, ("with `cargo` unfindable, targets reports DID NOT RUN -- which "
                  "cmd_verify turns into exit 2, never a pass -- instead of printing ok "
                  "with the missing second reader demoted to a note")


def control_targets_second_reader_disagreement_is_not_absence(bundle: Path) -> tuple[bool, str]:
    """Four cargo conditions must not all read as "could not be reached".

    A unit probe over `classify_cargo_metadata`, because the four conditions
    cannot all be produced from a real cargo on demand.  The distinction is
    the point: cargo exiting non-zero is the reader **not running**, while
    cargo answering with no release table is the reader **disagreeing**, and
    the first version of this code reported both as absence -- the more
    forgiving reading of the two.
    """
    good = json.dumps({"metadata": {"release": {"advertised-targets": ["a-b-c"]}}})
    cases = [
        ("non-zero exit", 1, good, None, "cargo-failed"),
        ("unparseable output", 0, "not json at all", None, "unparseable-json"),
        ("a JSON scalar", 0, "42", None, "unparseable-json"),
        ("no release table", 0, json.dumps({"metadata": {}}), None, "no-release-table"),
        ("null metadata", 0, json.dumps({"metadata": None}), None, "no-release-table"),
        ("targets not a list", 0,
         json.dumps({"metadata": {"release": {"advertised-targets": "a-b-c"}}}),
         None, "targets-not-a-list"),
        ("a real answer", 0, good, ["a-b-c"], "ok"),
    ]
    seen = set()
    for label, code, out, want_targets, want_status in cases:
        targets, status = classify_cargo_metadata(code, out)
        if status != want_status:
            return False, f"{label}: status {status!r}, expected {want_status!r}"
        if targets != want_targets:
            return False, f"{label}: targets {targets!r}, expected {want_targets!r}"
        seen.add(status)
    if len(seen) < 4:
        return False, f"only {len(seen)} distinct statuses were produced: {sorted(seen)}"
    return True, (f"{len(cases)} recorded cargo outcomes map to {len(seen)} distinct "
                  f"statuses {sorted(seen)}, so a reader that answered something other "
                  "than the declaration is never reported as a reader that was absent")


# A control that requires the check to REFUSE TO RUN, rather than to go red
# with a planted witness.  It is neither of the other two things, and counting
# it as a witness control credits the suite with an entry that does not meet
# the definition the summary prints -- the same over-claim the two-figure
# split was introduced to prevent (docs/tasks.md M6-C19).
REFUSAL_CONTROLS = {
    "cargo unfindable: the check must not report ok",
}

UNIT_PROBES = {
    "four cargo outcomes are four statuses, not one",
    "the lockfile parser is not universal",
    "the dynamic-dependency classifier's rule",
    "the declaration parser refuses junk in five shapes",
    "cargo metadata is a live second reader of the declaration",
}

CONTROLS: dict[str, list[tuple[str, object]]] = {
    "checksums": [
        ("a flipped byte in a bundled file", control_checksum_flipped_byte),
        ("a listed file removed", control_checksum_removed_file),
        ("an unattested file smuggled in", control_checksum_smuggled_file),
    ],
    "provenance": [
        ("a binary swapped for another", control_provenance_binary_swapped),
        ("a forged commit field", control_provenance_forged_commit),
        ("a build by an unpinned toolchain", control_provenance_wrong_toolchain),
    ],
    "notices": [
        ("a crate dropped from NOTICE", control_notices_dropped_crate),
        ("every licence text stripped out", control_notices_texts_stripped),
        ("one text replaced by same-length filler", control_notices_text_replaced_by_filler),
        ("a text block with no digest to bind it", control_notices_unbound_text_is_refused),
        ("a gutted but self-consistent NOTICE", control_notices_text_floor_is_not_vacuous),
        ("a NOTICE stale against its lockfile", control_notices_stale_lockfile),
        ("a crate declared out of the graph and notified", control_notices_false_unresolved_claim),
        ("the lockfile parser is not universal", control_lockfile_parser_is_not_universal),
    ],
    "assets": [
        ("the tunnel-deadman sentinel removed", control_assets_sentinel_removed),
        ("a decoy file of the sentinel's name", control_assets_sentinel_is_a_decoy),
        ("a decoy that also exits 2", control_assets_decoy_that_exits_two),
    ],
    "targets": [
        ("a bundle built for a triple outside the declared set",
         control_targets_bundle_target_is_not_advertised),
        ("the set frozen into the bundle narrowed after the fact",
         control_targets_frozen_set_diverges_from_manifest),
        ("the declaration edited under an unmodified shipped bundle",
         control_targets_manifest_edit_reddens_a_shipped_bundle),
        ("the declaration deleted entirely",
         control_targets_no_declaration_is_not_a_pass),
        ("a declared triple rustc does not know",
         control_targets_unknown_triple_is_refused),
        ("the declaration parser refuses junk in five shapes",
         control_targets_declaration_parser_rejects_junk),
        ("cargo metadata is a live second reader of the declaration",
         control_targets_cargo_is_a_live_second_reader),
        ("cargo unfindable: the check must not report ok",
         control_targets_absent_second_reader_is_not_a_pass),
        ("four cargo outcomes are four statuses, not one",
         control_targets_second_reader_disagreement_is_not_absence),
    ],
    "cli": [
        ("a binary that exits 0 printing nothing", control_cli_content_not_exit_status),
        ("a corrupted configuration example", control_cli_config_check_is_real),
        ("cargo reachable on the probe PATH", control_cli_environment_scrub_is_checked),
        ("a corrupted serving example", control_cli_serving_dry_run_is_real),
        ("no serving example at all", control_cli_serving_example_must_exist),
    ],
    "portability": [
        ("the dynamic-dependency classifier's rule", control_portability_non_system_dependency),
    ],
}


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------


def cmd_notices(args: argparse.Namespace) -> int:
    completed = run(["cargo", "metadata", "--locked", "--format-version", "1",
                     "--offline"], cwd=REPO, timeout=300)
    if completed.returncode != 0:
        print(f"cargo metadata failed: {completed.stderr[:400]}", file=sys.stderr)
        return 2
    metadata = json.loads(completed.stdout)
    lock_text = (REPO / LOCKFILE).read_text()
    lock_sha = sha256_file(REPO / LOCKFILE)
    text = generate_notices(metadata, lock_sha, lock_text)
    write_exact(Path(args.out), text)
    crates = len(notice_crate_set(text))
    print(f"wrote {args.out}: {crates} registry crates, lock {lock_sha[:12]}")
    if crates < MIN_NOTICE_CRATES:
        print(f"refusing: {crates} crates is below the floor {MIN_NOTICE_CRATES}",
              file=sys.stderr)
        return 1
    return 0


def receipt_field(text: str, key: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key}:"):
            return stripped.split(":", 1)[1].strip()
        if stripped.startswith(f"{key}="):
            return stripped.split("=", 1)[1].strip()
    return ""


def cmd_bundle(args: argparse.Namespace) -> int:
    receipt = Path(args.receipt).resolve()
    if not receipt.is_file():
        print(f"no receipt at {receipt}", file=sys.stderr)
        return 2
    receipt_text = receipt.read_text()
    parity_bin = receipt.parent / "bundle" / "bin"
    if not parity_bin.is_dir():
        print(f"no parity bundle bin/ beside the receipt at {parity_bin}",
              file=sys.stderr)
        return 2

    out = Path(args.out).resolve()
    if out.exists():
        print(f"{out} exists; choose a fresh --out", file=sys.stderr)
        return 2
    (out / "bin").mkdir(parents=True)
    (out / "examples").mkdir()

    # Binaries.  The parity bundle packages tunnel-deadman since M6-C06; the
    # fallback to the parity build's own target directory -- the same build,
    # same source copy -- is kept so a receipt produced before that fix still
    # bundles, and so the sentinel is never silently dropped if a future
    # assembler's list changes again.
    target_root = receipt.parent / "cargo-target" / args.profile
    digests = {}
    for name in BUNDLE_BINARIES:
        source = parity_bin / name
        if not source.is_file():
            source = target_root / name
        if not source.is_file():
            print(f"binary {name} not found in the parity output", file=sys.stderr)
            return 2
        destination = out / "bin" / name
        shutil.copy2(source, destination)
        digests[name] = sha256_file(destination)

    # Cross-check against the receipt for every binary the receipt attests.
    # **`tunnel-deadman` is one of them since M6-C06**, which closed the gap
    # this comment used to record: the parity script packaged client, relay
    # and harness only, so the sentinel came from the same build's target
    # directory and was attested by this bundle's own digest rather than by
    # the receipt.  The set is still computed from the receipt rather than
    # assumed, and PROVENANCE.txt still names it, because a provenance file
    # that claims uniform receipt coverage it does not have is worse than one
    # that states the gap -- and a receipt predating M6-C06 still produces the
    # narrower set.
    receipt_attested = []
    for name, digest in sorted(digests.items()):
        recorded = receipt_field(receipt_text, f"binary_{name}_sha256")
        if not recorded:
            continue
        if recorded != digest:
            print(f"{name}: bundle {digest[:12]} != receipt {recorded[:12]}",
                  file=sys.stderr)
            return 1
        receipt_attested.append(name)

    for example in BUNDLE_EXAMPLES:
        shutil.copy2(REPO / "examples" / example, out / "examples" / example)
    shutil.copy2(REPO / "LICENSE", out / "LICENSE")
    shutil.copy2(REPO / LOCKFILE, out / LOCKFILE)

    notices_status = cmd_notices(argparse.Namespace(out=str(out / NOTICE)))
    if notices_status != 0:
        return notices_status

    # **The commit comes from the receipt, not from `git rev-parse HEAD`.**
    # The receipt records the base HEAD the *source copy* was taken from; the
    # checkout may have moved since the build.  Taking the commit from the
    # working tree would attribute these bytes to whatever is checked out now,
    # which is the provenance claim this file exists to make impossible.
    commit = receipt_field(receipt_text, "base_head")
    if not commit:
        print("receipt records no base_head", file=sys.stderr)
        return 2
    for key, expected in (("build_profile", args.profile),
                          ("rustc_host", None)):
        if expected is not None and receipt_field(receipt_text, key) != expected:
            print(f"receipt {key}={receipt_field(receipt_text, key)!r} is not the "
                  f"requested {expected!r}", file=sys.stderr)
            return 2
    # The advertised set is frozen into the bundle, read from the one place
    # that declares it.  Freezing it is what lets `verify --check targets`
    # notice a *later* edit to the manifest rather than only a disagreement
    # between two readers of the same current file.  A bundle that cannot
    # name the set it was assembled against is refused here rather than
    # written and caught downstream.
    try:
        advertised = declared_targets()
    except DeclarationError as error:
        print(f"refusing to bundle: {error} "
              f"([workspace.metadata.release] in {MANIFEST} is the declaration)",
              file=sys.stderr)
        return 2

    rustc = run(["rustc", "--version"], cwd=REPO).stdout.strip()
    cargo = run(["cargo", "--version"], cwd=REPO).stdout.strip()
    target = run(["rustc", "-vV"], cwd=REPO).stdout
    triple = next((line.split(":", 1)[1].strip()
                   for line in target.splitlines() if line.startswith("host:")), "unknown")

    lines = [
        "PROVENANCE",
        "",
        "What produced these bytes.  A digest in SHA256SUMS proves the bytes; it",
        "does not prove what produced them.  These fields are cross-checked by",
        "scripts/m6-release-artifact.py verify --check provenance, which recomputes",
        "every binary digest below from the bundle's own bytes.",
        "",
        f"commit: {commit}",
        f"tracked_diff_sha256: {receipt_field(receipt_text, 'tracked_diff_from_base_sha256')}",
        f"worktree_status_sha256: {receipt_field(receipt_text, 'worktree_status_sha256')}",
        f"source_copy_sha256: {receipt_field(receipt_text, 'source_manifest_snapshot_sha256')}",
        f"source_file_count: {receipt_field(receipt_text, 'source_file_count')}",
        f"workspace_lockfile_sha256: {receipt_field(receipt_text, 'workspace_lockfile_sha256')}",
        f"receipt_sha256: {sha256_file(receipt)}",
        f"target: {receipt_field(receipt_text, 'rustc_host') or triple}",
        f"{PROVENANCE_TARGET_SET}: {','.join(advertised)}",
        f"profile: {receipt_field(receipt_text, 'build_profile')}",
        f"rustc_version: {receipt_field(receipt_text, 'rustc_version') or rustc}",
        f"cargo_version: {receipt_field(receipt_text, 'cargo_version') or cargo}",
        f"build_command: {receipt_field(receipt_text, 'build_command')}",
        "",
        f"receipt_attested_binaries: {','.join(receipt_attested) or 'none'}",
        "",
        "Per-binary digests, recomputed from this bundle at check time.  A name",
        "absent from receipt_attested_binaries above is attested by this bundle's",
        "own digest and by the build it came from, not by the parity receipt:",
    ]
    for name in sorted(digests):
        lines.append(f"    binary {name} sha256={digests[name]}")
    lines += [
        "",
        "This bundle is evidence for the `target` above and for no other OS or",
        "architecture.  `advertised_targets` above is the set the owner declared",
        f"in [workspace.metadata.release] of the workspace {MANIFEST}, copied here",
        "so that `verify --check targets` can detect a later edit to it; this",
        "bundle covers exactly one member of that set.  See docs/tasks.md rows",
        "M6-01 and M6-C13 for what remains and why.",
        "",
    ]
    (out / PROVENANCE).write_text("\n".join(lines))

    sums = []
    for path in bundle_files(out):
        sums.append(f"{sha256_file(path)}  {path.relative_to(out)}")
    (out / SHA256SUMS).write_text("\n".join(sorted(sums)) + "\n")

    # **And a real archive, because the gate says "unpack".**  Checking a
    # directory the bundler just wrote tests the bundler; checking a directory
    # that came out of an archive tests what a tester would actually receive.
    # The two differ in ways that bite: file modes, and whether anything the
    # bundle needs was outside the tree being packed.  `verify` accepts the
    # archive directly and extracts it into a temporary directory, so the
    # unpack step is performed rather than assumed.
    archive = out.with_suffix(out.suffix + ".tar.gz")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(out, arcname=out.name)
    archive_digest = sha256_file(archive)
    archive.with_suffix(archive.suffix + ".sha256").write_text(
        f"{archive_digest}  {archive.name}\n"
    )

    print(f"bundle at {out}: {len(sums)} files, {len(digests)} binaries, target {triple}")
    print(f"archive at {archive}: sha256 {archive_digest}")
    return 0


def unpack(archive: Path, destination: Path) -> Path:
    """Extract a bundle archive and return its single root directory.

    `filter="data"` is deliberate: it refuses absolute paths, `..` traversal
    and special files, so checking an archive cannot itself write outside the
    temporary directory.
    """
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(destination, filter="data")
    roots = [entry for entry in destination.iterdir() if entry.is_dir()]
    if len(roots) != 1:
        raise ValueError(f"archive has {len(roots)} top-level directories, expected 1")
    return roots[0]


def cmd_verify(args: argparse.Namespace) -> int:
    target = Path(args.bundle).resolve()
    selected = [args.check] if args.check else list(CHECKS)

    if target.is_file():
        # The gate's own words are "download and unpack those artifacts into
        # clean temporary environments".  Given an archive, do the unpacking
        # here rather than checking a directory that never went through it.
        with tempfile.TemporaryDirectory() as tmp:
            try:
                bundle = unpack(target, Path(tmp))
            except (tarfile.TarError, ValueError) as error:
                print(f"could not unpack {target}: {error}", file=sys.stderr)
                return 2
            print(f"unpacked {target.name} ({sha256_file(target)[:12]}) into a "
                  f"temporary directory as {bundle.name}")
            results = [CHECKS[name](bundle) for name in selected]
    elif target.is_dir():
        results = [CHECKS[name](target) for name in selected]
    else:
        print(f"no bundle directory or archive at {target}", file=sys.stderr)
        return 2

    for result in results:
        print(result.render())
    if any(not r.ran for r in results):
        return 2
    return 0 if all(r.ok for r in results) else 1


def cmd_self_test(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle).resolve()
    if not bundle.is_dir():
        print(f"no bundle directory at {bundle}", file=sys.stderr)
        return 2
    selected = [args.check] if args.check else list(CONTROLS)
    failures = 0
    witness_total = 0
    probe_total = 0
    refusal_total = 0
    for check in selected:
        print(f"--- {check} ---")
        for label, control in CONTROLS[check]:
            is_probe = label in UNIT_PROBES
            is_refusal = label in REFUSAL_CONTROLS
            if is_probe:
                probe_total += 1
            elif is_refusal:
                refusal_total += 1
            else:
                witness_total += 1
            ok, detail = control(bundle)
            if not ok:
                failures += 1
            kind = "probe  " if is_probe else ("refusal" if is_refusal else "control")
            print(f"  {'ok    ' if ok else 'FAILED'}  [{kind}] {label}: {detail}")
    total = witness_total + probe_total + refusal_total
    # Reported as three numbers on purpose.  A single "17 of 17 controls" would
    # credit the suite with entries that never invoke a check, which is a
    # message stating something the code did not measure -- the shape
    # docs/tasks.md M5-C11 exists to track.  The third figure exists for the
    # same reason as the second: a control that requires the check to REFUSE
    # TO RUN plants no witness, so folding it into the witness count would
    # make that sentence false about it (M6-C19).
    print(f"\n{total - failures}/{total} passed: {witness_total} witness control(s) "
          f"that defeat a mechanism and require the named check to go red with the "
          f"witness they plant, {refusal_total} refusal control(s) that remove a "
          f"reader the check depends on and require it to report DID NOT RUN rather "
          f"than a pass, and {probe_total} unit probe(s) that exercise a pure "
          f"function's rule in both directions and invoke no check")
    return 0 if failures == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--check", choices=sorted(CHECKS))
    parser.add_argument("--bundle")
    sub = parser.add_subparsers(dest="command")

    notices = sub.add_parser("notices")
    notices.add_argument("--out", required=True)

    bundle_cmd = sub.add_parser("bundle")
    bundle_cmd.add_argument("--receipt", required=True)
    bundle_cmd.add_argument("--out", required=True)
    bundle_cmd.add_argument("--profile", default="release")

    verify = sub.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--check", choices=sorted(CHECKS))

    args = parser.parse_args()
    if args.self_test:
        return cmd_self_test(args)
    if args.command == "notices":
        return cmd_notices(args)
    if args.command == "bundle":
        return cmd_bundle(args)
    if args.command == "verify":
        return cmd_verify(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
