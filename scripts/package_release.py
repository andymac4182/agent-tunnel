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


def advertised_targets(root=ROOT):
    """The advertised set, read from the workspace manifest.

    **This used to be a literal tuple here, and that was the defect.** The
    same four triples were spelled out in this file, in
    `.github/workflows/release.yml`'s matrix and (as prose) on the public
    downloads page, with nothing reconciling them -- docs/tasks.md row M6-C11.
    They now come from `[workspace.metadata.release] advertised-targets` in
    the root `Cargo.toml`, which is the single referent for the word
    "advertised", and `scripts/m6-release-checks.py --check packaging` fails
    if the workflow matrix and that list ever diverge.

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
        for binary in BINARIES:
            name = binary + (".exe" if windows else "")
            source = root / "target" / target / "release" / name
            if not source.is_file() or source.stat().st_size == 0:
                raise ValueError(f"missing release binary: {name}")
            shutil.copy2(source, staging / "bin" / name)
        shutil.copy2(root / "LICENSE", staging / "LICENSE")
        (staging / "examples").mkdir()
        for name in ("m1-client.toml", "m1-relay.toml"):
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
        (staging / "README.txt").write_text("Agent Uplink development build. Not production-certified.\nKeep all three binaries together, including tunnel-deadman.\nConfigure identity, relay and grants before connecting.\nLinux builds require a compatible glibc (Ubuntu 24.04 build host).\nmacOS binaries are not code-signed or notarized; Windows binaries are not Authenticode-signed.\nSetup and support: https://agentuplink.dev/docs/setup\n")
        if windows:
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                for file in sorted(staging.rglob("*")):
                    if file.is_file():
                        handle.write(file, file.relative_to(staging))
        else:
            with tarfile.open(archive, "w:gz") as handle:
                for file in sorted(staging.iterdir()):
                    handle.add(file, arcname=file.name)
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
