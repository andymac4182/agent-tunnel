"""Publish only a complete, checksum-verified matrix after successful main CI."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from package_release import TARGETS, version


def assets(directory, tag):
    result = []
    for target in TARGETS:
        extension = "zip" if target.endswith("windows-msvc") else "tar.gz"
        archive = directory / f"agentuplink-{tag}-{target}.{extension}"
        checksum = directory / f"{archive.name}.sha256"
        expected = f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
        if checksum.read_text() != expected:
            raise ValueError(f"checksum mismatch for {archive.name}")
        result.extend([archive, checksum])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    tag = version(Path(__file__).resolve().parents[1], args.sha, args.run)
    files = assets(args.directory, tag)
    listing = json.loads(subprocess.check_output(["gh", "release", "list", "--limit", "1000", "--json", "tagName,isDraft"]))
    existing = next((release for release in listing if release["tagName"] == tag), None)
    if existing and not existing["isDraft"]:
        print(f"Already published {tag}; immutable release left unchanged")
        return
    if not existing:
        subprocess.run(["gh", "release", "create", tag, "--target", args.sha, "--title", f"Agent Uplink {tag}", "--draft", "--prerelease", "--notes", f"Automated development build from successful main CI run {args.run}.\nSource: {args.sha}\nNot a production-readiness or complete platform-support claim.\nKeep tunnel-client, tunnel-relay and tunnel-deadman together. Verify the adjacent SHA-256 file before use.\nUnsigned binaries; macOS is not notarized. Linux requires a compatible Ubuntu 24.04 glibc baseline.\nSetup: https://agentuplink.dev/docs/setup"], check=True)
    subprocess.run(["gh", "release", "upload", tag, *map(str, files), "--clobber"], check=True)
    subprocess.run(["gh", "release", "edit", tag, "--draft=false", "--prerelease", "--latest=false"], check=True)


if __name__ == "__main__":
    main()
