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
from pathlib import Path

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
        (staging / "examples").mkdir()
        examples = ("m1-client.toml",) if windows else ("m1-client.toml", "m1-relay.toml")
        for name in examples:
            shutil.copy2(root / "examples" / name, staging / "examples" / name)
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
        (staging / "README.txt").write_text("Agent Uplink development build. Not production-certified.\n" + keep + "Configure identity, relay and grants before connecting.\nLinux builds require a compatible glibc (Ubuntu 24.04 build host).\nmacOS binaries are not code-signed or notarized; Windows binaries are not Authenticode-signed.\nSetup and support: https://agentuplink.dev/docs/setup\n")
        if windows:
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
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
