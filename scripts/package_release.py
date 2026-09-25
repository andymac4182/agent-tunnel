"""Package only distributable binaries, templates and licence notices."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("tunnel-client", "tunnel-relay", "tunnel-deadman")
# The relay ships only for Unix targets: it has never run on Windows, and
# docs/architecture.md promises Linux relay images and Windows *device*
# binaries (task row M6-C83). A Windows bundle is the device half.
DEVICE_BINARIES = ("tunnel-client", "tunnel-deadman")


def binaries_for(target):
    """The binaries one target's bundle carries."""
    return DEVICE_BINARIES if target.endswith("windows-msvc") else BINARIES


TRIPLE_RE = re.compile(r"[0-9a-z_]+(?:-[0-9a-z_.]+){2,3}")


def advertised_targets(root=ROOT):
    """The advertised set, read from the workspace manifest.

    **This used to be a literal tuple here, and that was the defect.** The
    same four triples were spelled out in this file, in
    `.github/workflows/release.yml`'s matrix and (as prose) on the public
    downloads page, with nothing reconciling them -- docs/tasks.md row M6-C11.
    They now come from `[workspace.metadata.release] advertised-targets` in
    the root `Cargo.toml`, which is the single **authority** for the word
    "advertised", and `scripts/m6-release-checks.py --check packaging` fails
    if the workflow matrix, `site/releases.js`'s array or that list ever
    diverge.

    **Two literal copies remain, and calling the manifest "the single
    referent" obscured them (docs/tasks.md M6-C18).** The workflow matrix is
    evaluated before any script runs and `site/releases.js` executes in a
    browser, so neither can read this table when it needs it; both keep a
    copy and both are machine-compared to it. This function has no copy at
    all -- it reads the table directly, which is why it is the one place the
    `packaging` check asserts carries no triple literal.

    It raises rather than falling back to a default: a default would be a
    second source of truth wearing a fallback's clothes, and this function
    exists precisely so there is only one.
    """
    table = tomllib.loads((root / "Cargo.toml").read_text())
    release = table.get("workspace", {}).get("metadata", {}).get("release")
    if release is None:
        raise ValueError("root Cargo.toml declares no [workspace.metadata.release] table")
    targets = release.get("advertised-targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("[workspace.metadata.release] advertised-targets must be a non-empty list")
    if not all(isinstance(target, str) for target in targets):
        raise ValueError("advertised-targets must be a list of strings")
    # The same acceptance rule as `m6-release-artifact.declared_targets`, and
    # for the same reason it has one: an empty, repeating or non-triple
    # declaration must be refused by every reader of it. These were three
    # parsers with three different rules -- this one and the checks script
    # accepted `["a","a","linux"]` while the artifact gate refused it, so the
    # packaging path would have published against a declaration the local gate
    # rejects. docs/tasks.md M6-C20.
    duplicates = sorted({t for t in targets if targets.count(t) > 1})
    if duplicates:
        raise ValueError(f"advertised-targets repeats {duplicates}")
    malformed = [t for t in targets if not TRIPLE_RE.fullmatch(t)]
    if malformed:
        raise ValueError(f"advertised-targets are not target triples: {malformed}")
    return tuple(sorted(targets))


#: Kept as a module-level name because `scripts/test_package_release.py`
#: imports it, but it is now *derived* rather than declared.
TARGETS = advertised_targets()


# --------------------------------------------------------------------------
# Documentation in the archive (docs/tasks.md M6-C50)
#
# The archive used to carry no documentation at all, so a tester holding only
# the download had no guide.  It now carries `docs/operator.md` and every
# local document the guide links, at the same relative paths, so the guide's
# links resolve inside the unpacked archive exactly as they do in the
# repository.  **The set is derived from the guide's own links**, not listed
# here: a link added to the guide ships its target with no second edit.
#
# The linked documents link further documents, and shipping that closure
# would ship the whole repository (it reaches 56 files, `docs/tasks.md`
# included).  So in the *shipped copies* only, a relative link to a file the
# archive does not carry is rewritten to that file at the archive's own
# source commit on GitHub -- the same commit `release.json` or
# `PROVENANCE.txt` names -- so every link in the archive either resolves
# inside it or names the exact source it was built from.  The guide itself is
# never rewritten: every local link it has must ship, and `release_documents`
# refuses a guide with a local link that cannot.  So the guide in the archive
# is byte-identical to the repository's, which is what lets
# `scripts/m6-release-artifact.py verify --check docs` execute the shipped
# copy.
# --------------------------------------------------------------------------
GUIDE = "docs/operator.md"
SOURCE_URL = "https://github.com/andymac4182/agentuplink"
_LINK_RE = re.compile(r"\]\(([^)\s]+)\)")


def _local_link(link):
    """The (path, fragment) a relative link names, or None for any other link."""
    if link.startswith("#") or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", link):
        return None
    path, _, fragment = link.partition("#")
    return path, fragment


def _resolve(document, path):
    """A link's target as a repository-relative POSIX path, or None if it escapes."""
    parts = []
    for part in PurePosixPath(document).parent.joinpath(path).parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part not in (".", ""):
            parts.append(part)
    return "/".join(parts)


def release_documents(root):
    """The guide and every local document it links, as repository paths."""
    guide = (root / GUIDE).read_bytes().decode("utf-8")
    shipped = {GUIDE}
    for link in _LINK_RE.findall(guide):
        local = _local_link(link)
        if local is None or not local[0]:
            continue
        target = _resolve(GUIDE, local[0])
        if target is None or not target.endswith(".md") or not (root / target).is_file():
            raise ValueError(
                f"{GUIDE} links {link!r}, which cannot ship as a document beside it; "
                "link a document under docs/ or an absolute URL"
            )
        shipped.add(target)
    return sorted(shipped)


def staged_document(root, document, shipped, sha):
    """One shipped document's text, with links to unshipped files pinned to `sha`."""
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("documents are pinned to a full 40-character source commit")
    # Bytes decoded, not `read_text`: text mode translates line endings, and
    # the guide must ship byte-identical to the checkout it came from.
    text = (root / document).read_bytes().decode("utf-8")

    def pin(match):
        link = match.group(1)
        local = _local_link(link)
        if local is None or not local[0]:
            return match.group(0)
        target = _resolve(document, local[0])
        if target in shipped:
            return match.group(0)
        if target is None:
            raise ValueError(f"{document} links {link!r} outside the repository")
        if document == GUIDE:
            raise ValueError(f"{GUIDE} links {link!r}, which does not ship")
        fragment = f"#{local[1]}" if local[1] else ""
        # GitHub serves a directory under /tree/ and a file under /blob/.
        kind = "tree" if (root / target).is_dir() else "blob"
        return f"]({SOURCE_URL}/{kind}/{sha}/{target}{fragment})"

    return _LINK_RE.sub(pin, text)


def stage_documents(root, destination, sha):
    """Write the shipped documents under `destination`; return their paths."""
    shipped = release_documents(root)
    for document in shipped:
        path = destination.joinpath(*document.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        # Bytes, not text mode, for the same reason in the other direction.
        path.write_bytes(staged_document(root, document, set(shipped), sha).encode("utf-8"))
    return shipped


def unresolved_links(bundle):
    """Every relative link in a bundle's documents that names no file in it."""
    problems = []
    for path in sorted((bundle / "docs").rglob("*.md")):
        document = path.relative_to(bundle).as_posix()
        for link in _LINK_RE.findall(path.read_bytes().decode("utf-8")):
            local = _local_link(link)
            if local is None or not local[0]:
                continue
            target = _resolve(document, local[0])
            if target is None or not (bundle / target).is_file():
                problems.append(f"{document} -> {link}")
    return problems


# --------------------------------------------------------------------------
# Examples in the archive (docs/tasks.md M6-C102)
#
# The archive used to carry `m1-client.toml` and `m1-relay.toml` only, while
# the guide it ships runs `m6-catalog*.toml`, `m7-cluster-relay.toml` and the
# `examples/service/` units, so a tester holding only the archive reached
# section 2.3 of the guide without its records examples.  **The set is now
# derived from the shipped documents' own text**: every `examples/...` path
# any of them names ships, and a directory named with a trailing `/` ships
# every file under it.  So a document that starts using a new example ships
# it with no second edit, and `scripts/verify_release_archive.py` checks the
# same rule against the *unpacked* archive's own documents.
#
# A Windows archive is the device half (M6-C83): it carries only the
# device-side examples the documents name -- client profiles -- because the
# relay, its records documents and the systemd/launchd units do not run there.
# --------------------------------------------------------------------------
EXAMPLE_RE = re.compile(r"examples/[A-Za-z0-9_./-]*[A-Za-z0-9_/]")


def device_side_example(path):
    """Whether an example path belongs in the device-only (Windows) archive."""
    name = PurePosixPath(path).name
    return "/" not in path.removeprefix("examples/") and "client" in name and name.endswith(".toml")


def named_examples(texts):
    """Every `examples/...` path the given document texts name, as written."""
    return sorted({match for text in texts for match in EXAMPLE_RE.findall(text)})


def release_examples(root, target):
    """The example files one target's archive carries, as repository paths."""
    texts = [(root / document).read_bytes().decode("utf-8") for document in release_documents(root)]
    shipped = set()
    for named in named_examples(texts):
        path = root / named
        if named.endswith("/") or path.is_dir():
            if not path.is_dir():
                raise ValueError(f"the shipped documents name {named!r}, which is not a directory")
            files = [f for f in sorted(path.rglob("*")) if f.is_file()]
            if not files:
                raise ValueError(f"the shipped documents name {named!r}, which is empty")
            shipped.update(f.relative_to(root).as_posix() for f in files)
        elif path.is_file():
            shipped.add(named)
        else:
            raise ValueError(f"the shipped documents name {named!r}, which does not exist")
    if target.endswith("windows-msvc"):
        shipped = {path for path in shipped if device_side_example(path)}
    if "examples/m1-client.toml" not in shipped:
        # `scripts/verify_release_archive.py` runs `config check` on it from
        # the unpacked archive; its absence is a packaging fault, not a
        # documentation choice.
        raise ValueError("the shipped documents no longer name examples/m1-client.toml")
    return sorted(shipped)


def version(root, sha, run):
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"[1-9][0-9]*", run):
        raise ValueError("invalid source SHA or CI run ID")
    base = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", base):
        raise ValueError("expected a numeric workspace version")
    return f"v{base}-main.{run}.{sha[:12]}"


def normalised_member(member):
    """Give a tar member the same mode and owner on every build host.

    Copying modes from the staging tree made the archive depend on the host:
    a Windows runner has no execute bits, so its Unix archives would ship
    binaries that cannot run. Directories and `bin/` entries are 0755,
    everything else 0644, owned by root.
    """
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    executable = member.isdir() or member.name.startswith("bin/")
    member.mode = 0o755 if executable else 0o644
    return member


def package(root, target, sha, run, output, metadata):
    # Read from the manifest under `root` rather than from the module-level
    # TARGETS, so a caller packaging a different checkout is checked against
    # *that* checkout's declaration.
    if target not in advertised_targets(root):
        raise ValueError("unsupported target")
    tag = version(root, sha, run)
    output.mkdir(parents=True, exist_ok=True)
    windows = target.endswith("windows-msvc")
    filename = f"agentuplink-{tag}-{target}." + ("zip" if windows else "tar.gz")
    archive = output / filename
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        (staging / "bin").mkdir()
        for binary in binaries_for(target):
            name = binary + (".exe" if windows else "")
            source = root / "target" / target / "release" / name
            if not source.is_file() or source.stat().st_size == 0:
                raise ValueError(f"missing release binary: {name}")
            shutil.copy2(source, staging / "bin" / name)
        shutil.copy2(root / "LICENSE", staging / "LICENSE")
        stage_documents(root, staging, sha)
        dangling = unresolved_links(staging)
        if dangling:
            raise ValueError(f"shipped documents link files the archive lacks: {dangling[:3]}")
        for example in release_examples(root, target):
            destination = staging.joinpath(*example.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Bytes, so a CRLF checkout cannot change what ships.
            destination.write_bytes((root / example).read_bytes())
        notices = staging / "notices"
        notices.mkdir()
        dependencies = []
        for dep in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
            dependencies.append({key: dep.get(key) for key in ("name", "version", "license", "source")})
            directory = Path(dep["manifest_path"]).parent
            destination = notices / f'{dep["name"]}-{dep["version"]}'
            names = {p for pattern in ("LICENSE*", "COPYING*", "NOTICE*", "COPYRIGHT*", "UPSTREAM_PATCH.md") for p in directory.glob(pattern) if p.is_file()}
            if dep.get("license_file"):
                names.add(directory / dep["license_file"])
            if names:
                destination.mkdir(exist_ok=True)
                for source in sorted(names):
                    shutil.copy2(source, destination / source.name)
        (notices / "dependencies.json").write_text(json.dumps(dependencies, indent=2) + "\n")
        manifest = {"version": tag, "sourceSha": sha, "ciRun": run, "target": target, "channel": "development"}
        (staging / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
        keep = (
            "Keep tunnel-client and tunnel-deadman together. This Windows bundle is the device half: the relay runs only on Linux and macOS.\n"
            if windows
            else "Keep all three binaries together, including tunnel-deadman.\n"
        )
        (staging / "README.txt").write_text("Agent Uplink development build. Not production-certified.\n" + keep + "Configure identity, relay and grants before connecting. Start with docs/operator.md in this archive; it and the documents it links describe this build's source commit.\nLinux builds require a compatible glibc (Ubuntu 24.04 build host).\nmacOS binaries are not code-signed or notarized; Windows binaries are not Authenticode-signed.\nSetup and support: https://agentuplink.dev/docs/setup\n")
        if windows:
            # strict_timestamps=False stores a pre-1980 mtime (crates.io sources
            # carry some, e.g. mtime 1 and 123456789) as 1980-01-01, which ZIP can encode,
            # instead of failing the Windows package (M6-C90).
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as handle:
                for file in sorted(staging.rglob("*")):
                    if file.is_file():
                        handle.write(file, file.relative_to(staging))
        else:
            with tarfile.open(archive, "w:gz") as handle:
                for file in sorted(staging.iterdir()):
                    handle.add(file, arcname=file.name, filter=normalised_member)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / f"{filename}.sha256").write_text(f"{digest}  {filename}\n")
    return archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root))
    print(package(root, args.target, args.sha, args.run, args.output, metadata))
