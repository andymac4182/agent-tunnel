"""Verify one CI release archive from its UNPACKED contents on a native host.

docs/tasks.md M6-C13 (applied by default pending owner confirmation,
2026-09-25).  The release workflow used to smoke-test `target/<triple>/release`
and then pack what it had tested; nothing ran a binary *out of the archive a
tester downloads*.  This script is that check.  `.github/workflows/release.yml`
runs it in a separate job, on a fresh hosted runner of the target's own OS and
architecture that never built anything, against the archive and checksum file
the build job uploaded.  So every check below executes the shipped bytes on a
machine with no `target/` directory, from a working directory outside the
archive and the checkout, with `PATH` narrowed to the system directories and
`cargo` proven unreachable before any binary runs.

The checks are the CI archive's counterparts of the maintainer gate's
(`scripts/m6-release-artifact.py verify`), adapted to the CI archive's format,
which has no `SHA256SUMS`, `PROVENANCE.txt`, `Cargo.lock` or reconciled
`NOTICE`.  What that leaves unverified is stated in the `scope` line every run
prints, not left to a reader to infer:

  checksums    the adjacent `.sha256` file names the archive and its digest
  layout       safe member paths; exactly the target's binaries (no relay in
               a device-half archive: Windows, M6-C83, and every CI-only
               target, M6-C115); `release.json` agrees with
               the archive name and the expected commit and run
  targets      every binary's executable format and CPU architecture match
               the triple, and the verifying host is that OS and architecture,
               so every probe below is a native execution
  notices      `notices/dependencies.json` is complete enough to be real and
               every third-party crate either ships licence text or is listed
  assets       `tunnel-deadman` resolves beside the client and *runs* as the
               sentinel; every example the shipped documents name is present
               (M6-C102); every relative link in the shipped documents resolves
  cli          help, version, every subcommand's `--help` (D6), `config check`
               on the shipped client example, and (Unix) the relay's help and
               `check-serve-config` on every shipped serving example
  portability  every binary's dynamic dependencies are system libraries a
               clean machine of that OS has (ELF DT_NEEDED, Mach-O `otool -L`,
               PE import table)

`--self-test` re-runs the checks against deliberately damaged copies of the
unpacked archive and requires each to fail with its own witness, so a green
run is evidence that each check could have gone red on these bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_release import (  # noqa: E402
    binaries_for, device_only, device_side_example, named_examples, unresolved_links,
)

TOP_LEVEL = {"LICENSE", "README.txt", "bin", "docs", "examples", "notices", "release.json"}
# The dependency graph is ~360 crates; a list far below that was not produced
# by `cargo metadata` over this workspace.
MIN_DEPENDENCIES = 250
MIN_LICENCE_DIRECTORIES = 200
CLIENT_SUBCOMMAND_HELP = (
    ["connect", "--help"],
    ["config", "check", "--help"],
    ["doctor", "--help"],
    ["credentials", "--help"],
    ["credentials", "create", "--help"],
    ["credentials", "import", "--help"],
    ["check-config", "--help"],
)
RELAY_SUBCOMMAND_HELP = (["serve", "--help"], ["check-serve-config", "--help"],
                         ["provision-catalog", "--help"], ["recover", "--help"])

SCOPE = (
    "scope: the CI archive's own contents, executed natively. NOT covered: "
    "per-file checksums and a PROVENANCE.txt (the CI archive carries neither; "
    "build provenance is the GitHub attestation, verified with `gh attestation "
    "verify`), a lockfile reconciliation of notices, and a launched relay and "
    "device doing a real operation and a rotation from the archive"
)


@dataclass
class Result:
    name: str
    ok: bool
    summary: str = ""
    witness: str | None = None
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        head = f"{'ok    ' if self.ok else 'FAILED'}  {self.name}: {self.summary}"
        if self.witness and not self.ok:
            head += f"  [witness={self.witness}]"
        return "\n".join([head] + [f"          {line}" for line in self.notes])


def fail(name: str, witness: str, summary: str) -> Result:
    return Result(name, False, summary, witness)


# ---------------------------------------------------------------- targets
def windows(target: str) -> bool:
    return target.endswith("windows-msvc")


def exe(target: str, name: str) -> str:
    return name + (".exe" if windows(target) else "")


def target_os_arch(target: str) -> tuple[str, str]:
    arch = target.split("-", 1)[0]
    if "apple-darwin" in target:
        return "macos", arch
    if "linux" in target:
        return "linux", arch
    if windows(target):
        return "windows", arch
    raise ValueError(f"unknown target OS: {target}")


def host_os_arch() -> tuple[str, str]:
    system = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}.get(platform.system(), platform.system())
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    return system, arch


ELF_MACHINES = {62: "x86_64", 183: "aarch64"}
MACHO_CPUS = {0x01000007: "x86_64", 0x0100000C: "aarch64"}
PE_MACHINES = {0x8664: "x86_64", 0xAA64: "aarch64"}


def binary_format(path: Path) -> tuple[str, str]:
    """(format, architecture) read from the executable's own header."""
    data = path.read_bytes()[:4096]
    if data[:4] == b"\x7fELF":
        if data[4] != 2 or data[5] != 1:
            return "elf", "not-64-bit-little-endian"
        (machine,) = struct.unpack_from("<H", data, 18)
        return "elf", ELF_MACHINES.get(machine, f"machine-{machine}")
    if data[:4] in (b"\xcf\xfa\xed\xfe",):
        (cpu,) = struct.unpack_from("<I", data, 4)
        return "macho", MACHO_CPUS.get(cpu, f"cpu-{cpu:#x}")
    if data[:2] == b"MZ":
        (offset,) = struct.unpack_from("<I", data, 0x3C)
        whole = path.read_bytes()[: offset + 6]
        if whole[offset:offset + 4] != b"PE\0\0":
            return "pe", "no-pe-header"
        (machine,) = struct.unpack_from("<H", whole, offset + 4)
        return "pe", PE_MACHINES.get(machine, f"machine-{machine:#x}")
    return "unknown", "unknown"


EXPECTED_FORMAT = {"linux": "elf", "macos": "macho", "windows": "pe"}


# ---------------------------------------------------------------- unpacking
def unpack(archive: Path, destination: Path) -> list[str]:
    """Extract safely; return the member names. Refuses links and escapes."""
    destination.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as handle:
            for info in handle.infolist():
                names.append(info.filename)
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError(f"archive member {info.filename!r} is a symbolic link")
            for name in names:
                check_member_name(name)
            handle.extractall(destination)
    else:
        with tarfile.open(archive) as handle:
            for member in handle.getmembers():
                names.append(member.name)
                check_member_name(member.name)
                if not (member.isfile() or member.isdir()):
                    raise ValueError(f"archive member {member.name!r} is not a file or directory")
            handle.extractall(destination, filter="data")
    return names


def check_member_name(name: str) -> None:
    posix = PurePosixPath(name.replace("\\", "/"))
    if posix.is_absolute() or ".." in posix.parts or re.match(r"^[A-Za-z]:", name):
        raise ValueError(f"archive member {name!r} escapes the extraction directory")


# ---------------------------------------------------------------- checks
def check_checksums(archive: Path, checksum: Path) -> Result:
    if not checksum.is_file():
        return fail("checksums", "checksum-missing", f"no {checksum.name} beside the archive")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    expected = f"{digest}  {archive.name}\n"
    actual = checksum.read_text(encoding="utf-8")
    if actual != expected:
        return fail("checksums", "checksum-mismatch",
                    f"{checksum.name} does not state this archive's SHA-256 and name")
    return Result("checksums", True, f"{archive.name} SHA-256 {digest[:16]}... matches {checksum.name}")


def check_layout(root: Path, archive: Path, target: str, sha: str | None, run: str | None) -> Result:
    top = {entry.name for entry in root.iterdir()}
    if top != TOP_LEVEL:
        return fail("layout", "top-level", f"top level is {sorted(top)}, expected {sorted(TOP_LEVEL)}")
    shipped = sorted(entry.name for entry in (root / "bin").iterdir())
    expected = sorted(exe(target, name) for name in binaries_for(target))
    if shipped != expected:
        return fail("layout", "binary-set", f"bin/ holds {shipped}, expected {expected}")
    try:
        manifest = json.loads((root / "release.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return fail("layout", "release-json", f"release.json unreadable: {error}")
    extension = "zip" if windows(target) else "tar.gz"
    if archive.name != f"agentuplink-{manifest.get('version')}-{target}.{extension}":
        return fail("layout", "release-json", f"release.json version {manifest.get('version')!r} "
                                              f"does not name {archive.name}")
    if manifest.get("target") != target or manifest.get("channel") != "development":
        return fail("layout", "release-json", f"release.json target/channel {manifest.get('target')!r}/"
                                              f"{manifest.get('channel')!r}")
    if sha is not None and manifest.get("sourceSha") != sha:
        return fail("layout", "release-json", f"release.json sourceSha {manifest.get('sourceSha')!r} is not {sha}")
    if run is not None and manifest.get("ciRun") != run:
        return fail("layout", "release-json", f"release.json ciRun {manifest.get('ciRun')!r} is not {run}")
    if not windows(target):
        for name in expected:
            if not os.access(root / "bin" / name, os.X_OK):
                return fail("layout", "not-executable", f"bin/{name} has no execute bit after unpacking")
    return Result("layout", True, f"{len(top)} top-level entries, bin/ = {expected}, release.json "
                                  f"names {manifest['version']} at {manifest['sourceSha'][:12]}")


def check_targets(root: Path, target: str) -> Result:
    want_os, want_arch = target_os_arch(target)
    for name in binaries_for(target):
        fmt, arch = binary_format(root / "bin" / exe(target, name))
        if (fmt, arch) != (EXPECTED_FORMAT[want_os], want_arch):
            return fail("targets", "wrong-architecture",
                        f"bin/{exe(target, name)} is {fmt}/{arch}, expected {EXPECTED_FORMAT[want_os]}/{want_arch}")
    host = host_os_arch()
    if host != (want_os, want_arch):
        return fail("targets", "not-native-host",
                    f"this host is {host[0]}/{host[1]}; {target} must be verified on {want_os}/{want_arch}")
    return Result("targets", True, f"{len(binaries_for(target))} binaries are "
                                   f"{EXPECTED_FORMAT[want_os]}/{want_arch}, and so is this host")


def check_notices(root: Path) -> Result:
    try:
        dependencies = json.loads((root / "notices" / "dependencies.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return fail("notices", "dependencies-json", f"notices/dependencies.json unreadable: {error}")
    if not isinstance(dependencies, list) or len(dependencies) < MIN_DEPENDENCIES:
        count = len(dependencies) if isinstance(dependencies, list) else 0
        return fail("notices", "dependencies-floor", f"{count} dependencies listed, floor {MIN_DEPENDENCIES}")
    third_party = [d for d in dependencies if d.get("source")]
    unlicensed = [f"{d.get('name')}-{d.get('version')}" for d in third_party if not d.get("license")]
    if unlicensed:
        return fail("notices", "licence-missing", f"{len(unlicensed)} third-party crates list no licence: {unlicensed[:3]}")
    directories = {entry.name for entry in (root / "notices").iterdir() if entry.is_dir()}
    with_text = [d for d in third_party if f"{d['name']}-{d['version']}" in directories]
    if len(with_text) < MIN_LICENCE_DIRECTORIES:
        return fail("notices", "licence-text-floor",
                    f"{len(with_text)} third-party crates ship licence text, floor {MIN_LICENCE_DIRECTORIES}")
    empty = sorted(name for name in directories if not any((root / "notices" / name).iterdir()))
    if empty:
        return fail("notices", "licence-text-empty", f"{len(empty)} notice directories are empty: {empty[:3]}")
    if not (root / "LICENSE").is_file() or (root / "LICENSE").stat().st_size == 0:
        return fail("notices", "project-licence", "no project LICENSE")
    result = Result("notices", True, f"{len(dependencies)} dependencies listed, {len(third_party)} "
                                     f"third-party each with a licence expression, {len(with_text)} "
                                     f"shipping licence text")
    result.notes.append(f"{len(third_party) - len(with_text)} third-party crates publish no licence "
                        "file and are listed by expression only; not reconciled against a lockfile")
    return result


def check_assets(root: Path, target: str, work: Path) -> Result:
    sentinel = root / "bin" / exe(target, "tunnel-deadman")
    if not sentinel.is_file():
        return fail("assets", "sentinel-missing", "no tunnel-deadman beside the client")
    for args, label in (([], "no argument"), (["not-a-pid"], "a non-numeric leader")):
        try:
            completed = subprocess.run([str(sentinel), *args], cwd=work, env=stranger_env(work),
                                       stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False)
        except OSError as error:
            return fail("assets", "sentinel-not-executable", f"tunnel-deadman ({label}) could not run: {error}")
        if completed.returncode != 2:
            return fail("assets", "sentinel-not-the-sentinel",
                        f"tunnel-deadman answered {label} with exit {completed.returncode}, not 2")
    texts = [path.read_bytes().decode("utf-8") for path in sorted((root / "docs").rglob("*.md"))]
    if not texts:
        return fail("assets", "guide-missing", "no documents in docs/")
    named = named_examples(texts)
    missing = []
    for path in named:
        if device_only(target) and not device_side_example(path):
            continue
        location = root.joinpath(*path.rstrip("/").split("/"))
        present = location.is_dir() and any(location.iterdir()) if path.endswith("/") else location.is_file()
        if not present:
            missing.append(path)
    if missing:
        return fail("assets", "example-missing", f"the shipped documents name {missing}, absent from the archive")
    dangling = unresolved_links(root)
    if dangling:
        return fail("assets", "doc-link-unresolved", f"{len(dangling)} shipped links resolve to nothing: {dangling[:3]}")
    return Result("assets", True, f"sentinel beside the client exits 2 on both usage probes; "
                                  f"{len(named)} example paths named by {len(texts)} shipped documents, "
                                  f"every one required here present; every relative link resolves")


def stranger_env(work: Path) -> dict[str, str]:
    """An environment with no toolchain: system PATH only, no CARGO_*/RUST*."""
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        return {"PATH": rf"{system_root}\System32;{system_root}", "SystemRoot": system_root,
                "USERPROFILE": str(work), "TEMP": str(work), "TMP": str(work)}
    return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(work), "TMPDIR": str(work)}


def probe(binary: Path, args: list[str], work: Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(binary), *args], cwd=work, env=stranger_env(work), stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=60, check=False)


def check_cli(root: Path, target: str, work: Path) -> Result:
    env = stranger_env(work)
    if shutil.which("cargo", path=env["PATH"]) is not None:
        return fail("cli", "environment-not-scrubbed", f"cargo is reachable on {env['PATH']!r}")
    client = root / "bin" / exe(target, "tunnel-client")
    manifest = json.loads((root / "release.json").read_text(encoding="utf-8"))
    base = re.match(r"v([0-9]+\.[0-9]+\.[0-9]+)-", manifest["version"])
    probes = 0
    completed = probe(client, ["--help"], work)
    probes += 1
    if completed.returncode != 0 or "Usage:" not in completed.stdout:
        return fail("cli", "help", f"tunnel-client --help exited {completed.returncode}")
    completed = probe(client, ["--version"], work)
    probes += 1
    if completed.returncode != 0 or completed.stdout.strip() != f"tunnel-client {base.group(1) if base else '?'}":
        return fail("cli", "version", f"tunnel-client --version printed {completed.stdout.strip()!r} "
                                      f"for release {manifest['version']}")
    for args in CLIENT_SUBCOMMAND_HELP:
        completed = probe(client, args, work)
        probes += 1
        if completed.returncode != 0 or "Usage:" not in completed.stdout:
            return fail("cli", "subcommand-help", f"tunnel-client {' '.join(args)} exited {completed.returncode}")
    example = root / "examples" / "m1-client.toml"
    completed = probe(client, ["config", "check", "--config", str(example), "--json"], work)
    probes += 1
    try:
        verdict = json.loads(completed.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        verdict = {}
    if completed.returncode != 0 or verdict.get("ok") is not True:
        return fail("cli", "config-check", f"config check on the shipped m1-client.toml exited "
                                           f"{completed.returncode}: {(completed.stderr or completed.stdout)[:160]}")
    serving = []
    if "tunnel-relay" in binaries_for(target):
        relay = root / "bin" / "tunnel-relay"
        for args in (["--help"], *RELAY_SUBCOMMAND_HELP):
            completed = probe(relay, list(args), work)
            probes += 1
            if completed.returncode != 0 or "Usage: tunnel-relay" not in completed.stdout:
                return fail("cli", "subcommand-help", f"tunnel-relay {' '.join(args)} exited {completed.returncode}")
        serving = sorted((root / "examples").glob("*-relay.toml"))
        if not serving:
            return fail("cli", "serving-example-missing", "no *-relay.toml serving example shipped")
        for config in serving:
            completed = probe(relay, ["check-serve-config", "--config", str(config)], work)
            probes += 1
            if completed.returncode != 0:
                return fail("cli", "serving-config-check", f"check-serve-config on {config.name} exited "
                                                           f"{completed.returncode}: {completed.stderr[:160]}")
    result = Result("cli", True, f"{probes} probes from the unpacked archive, including "
                                 f"{len(CLIENT_SUBCOMMAND_HELP)} client subcommand --help, config check "
                                 f"and {len(serving)} serving dry run(s)")
    result.notes.append(f"cwd outside the archive and checkout, PATH={env['PATH']!r}, no CARGO_*/RUST*; "
                        "cargo proven unreachable on that PATH before any probe")
    return result


# The dynamic libraries a clean machine of each OS provides.  Linux: glibc's
# own libraries and the GCC runtime every glibc distribution installs.
LINUX_SYSTEM = re.compile(r"^(libc|libm|libdl|librt|libpthread|libutil|libgcc_s)\.so\.[0-9]+$"
                          r"|^ld-linux-(x86-64|aarch64)\.so\.[0-9]+$")
MACOS_SYSTEM_PREFIXES = ("/usr/lib/", "/System/")
# Windows: DLLs every supported Windows ships in System32.  The Visual C++
# runtime (vcruntime*/msvcp*) is a redistributable, absent on a clean machine.
WINDOWS_REDISTRIBUTABLE = re.compile(r"^(vcruntime|msvcp|concrt|vccorlib)[0-9_]*\.dll$", re.I)


def elf_needed(path: Path) -> list[str]:
    data = path.read_bytes()
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    dynamic = [s for s in sections if s[1] == 6]  # SHT_DYNAMIC
    if not dynamic:
        return []
    _, _, _, _, offset, size, link, _, _, entsize = dynamic[0]
    strtab = sections[link]
    names = []
    for index in range(size // entsize):
        tag, value = struct.unpack_from("<qQ", data, offset + index * entsize)
        if tag == 0:
            break
        if tag == 1:  # DT_NEEDED
            start = strtab[4] + value
            names.append(data[start:data.index(b"\0", start)].decode())
    return names


def pe_imports(path: Path) -> list[str]:
    data = path.read_bytes()
    (pe,) = struct.unpack_from("<I", data, 0x3C)
    (sections_count,) = struct.unpack_from("<H", data, pe + 6)
    (optional_size,) = struct.unpack_from("<H", data, pe + 20)
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("not a PE32+ image")
    import_rva, _ = struct.unpack_from("<II", data, optional + 112 + 8)
    sections = []
    for index in range(sections_count):
        base = optional + optional_size + index * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        sections.append((vaddr, max(vsize, rawsize), rawptr))

    def offset(rva: int) -> int:
        for vaddr, size, rawptr in sections:
            if vaddr <= rva < vaddr + size:
                return rva - vaddr + rawptr
        raise ValueError(f"RVA {rva:#x} is in no section")

    names = []
    cursor = offset(import_rva)
    while True:
        descriptor = struct.unpack_from("<IIIII", data, cursor)
        if descriptor == (0, 0, 0, 0, 0):
            break
        start = offset(descriptor[3])
        names.append(data[start:data.index(b"\0", start)].decode())
        cursor += 20
    return names


def read_dependencies(binary: Path, target_os: str) -> list[str]:
    """The dynamic dependencies a binary's own headers declare."""
    if target_os == "linux":
        return elf_needed(binary)
    if target_os == "windows":
        return pe_imports(binary)
    tool = shutil.which("otool")
    if tool is None:
        raise FileNotFoundError("otool")
    listing = subprocess.run([tool, "-L", str(binary)], capture_output=True, text=True, check=False)
    return [line.strip().split(" (")[0] for line in listing.stdout.splitlines()[1:] if line.strip()]


def non_system(dependencies: list[str], target_os: str) -> list[str]:
    """The dependencies a clean machine of `target_os` does not provide."""
    if target_os == "linux":
        return [d for d in dependencies if not LINUX_SYSTEM.match(d)]
    if target_os == "windows":
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        return [d for d in dependencies if WINDOWS_REDISTRIBUTABLE.match(d)
                or (system32.is_dir() and not (system32 / d).exists() and not d.lower().startswith("api-ms-win-"))]
    return [d for d in dependencies if not d.startswith(MACOS_SYSTEM_PREFIXES)]


def check_portability(root: Path, target: str, reader=read_dependencies) -> Result:
    """`reader` is the dependency reader; the self-test wraps the real one."""
    target_os, _ = target_os_arch(target)
    total = 0
    for name in binaries_for(target):
        binary = root / "bin" / exe(target, name)
        try:
            dependencies = reader(binary, target_os)
        except FileNotFoundError:
            return fail("portability", "otool-missing", "otool is unavailable; dependencies not inspected")
        bad = non_system(dependencies, target_os)
        if not dependencies:
            return fail("portability", "no-dependencies-read",
                        f"read no dynamic dependencies from bin/{exe(target, name)}; the parser saw nothing")
        if bad:
            return fail("portability", "non-system-dependency",
                        f"bin/{exe(target, name)} needs {bad}, which a clean {target_os} machine lacks")
        total += len(dependencies)
    return Result("portability", True, f"{len(binaries_for(target))} binaries, {total} dynamic "
                                       f"dependencies, all provided by a clean {target_os} system")


def run_checks(root: Path, archive: Path, checksum: Path, target: str, sha: str | None,
               run: str | None) -> list[Result]:
    with tempfile.TemporaryDirectory(prefix="verify-cwd-") as workdir:
        work = Path(workdir)
        results = [check_checksums(archive, checksum), check_layout(root, archive, target, sha, run)]
        if not results[-1].ok:
            return results
        results.append(check_targets(root, target))
        results.append(check_notices(root))
        results.append(check_assets(root, target, work))
        if results[2].ok:
            results.append(check_cli(root, target, work))
        results.append(check_portability(root, target))
        return results


# ---------------------------------------------------------------- self-test
def _copy(root: Path, into: Path) -> Path:
    copy = into / "copy"
    shutil.copytree(root, copy, symlinks=True)
    return copy


def _decoy(path: Path, exit_code: int) -> None:
    """Replace a binary with one of the same OS that exits `exit_code`."""
    if os.name == "nt":
        shutil.copy2(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "whoami.exe", path)
    else:
        path.write_text(f"#!/bin/sh\nexit {exit_code}\n")
        path.chmod(0o755)


def controls(root: Path, archive: Path, checksum: Path, target: str) -> list[tuple[str, str, bool | None, str]]:
    """(control, witness wanted, passed or None if skipped, detail) per planted defect."""
    out = []

    def expect(label, witness, check):
        with tempfile.TemporaryDirectory(prefix="verify-control-") as tmp:
            result = check(Path(tmp))
        if result is None:
            out.append((label, witness, None, "not applicable on this OS"))
            return
        passed = (not result.ok) and result.witness == witness
        out.append((label, witness, passed, result.render().splitlines()[0]))

    def flipped_checksum(tmp):
        bad = tmp / checksum.name
        bad.write_text("0" * 64 + f"  {archive.name}\n")
        return check_checksums(archive, bad)
    expect("checksum names another digest", "checksum-mismatch", flipped_checksum)

    def relay_in_wrong_half(tmp):
        copy = _copy(root, tmp)
        relay = copy / "bin" / exe(target, "tunnel-relay")
        if device_only(target):
            relay.write_bytes(b"not the relay")
        else:
            relay.unlink()
        return check_layout(copy, archive, target, None, None)
    expect("relay added to a device-only archive / removed from a full one", "binary-set", relay_in_wrong_half)

    def wrong_arch(tmp):
        copy = _copy(root, tmp)
        client = copy / "bin" / exe(target, "tunnel-client")
        data = bytearray(client.read_bytes())
        fmt, _ = binary_format(client)
        if fmt == "elf":
            struct.pack_into("<H", data, 18, 3)  # EM_386
        elif fmt == "macho":
            struct.pack_into("<I", data, 4, 0x07)  # CPU_TYPE_X86 (32-bit)
        else:
            (pe,) = struct.unpack_from("<I", data, 0x3C)
            struct.pack_into("<H", data, pe + 4, 0x14C)  # i386
        client.write_bytes(bytes(data))
        return check_targets(copy, target)
    expect("client header rewritten to another CPU", "wrong-architecture", wrong_arch)

    def notices_stripped(tmp):
        copy = _copy(root, tmp)
        for entry in (copy / "notices").iterdir():
            if entry.is_dir():
                shutil.rmtree(entry)
        return check_notices(copy)
    expect("licence texts removed", "licence-text-floor", notices_stripped)

    def sentinel_removed(tmp):
        copy = _copy(root, tmp)
        (copy / "bin" / exe(target, "tunnel-deadman")).unlink()
        return check_assets(copy, target, tmp)
    expect("sentinel removed", "sentinel-missing", sentinel_removed)

    def sentinel_decoy(tmp):
        copy = _copy(root, tmp)
        _decoy(copy / "bin" / exe(target, "tunnel-deadman"), 0)
        return check_assets(copy, target, tmp)
    expect("sentinel replaced by a program exiting 0", "sentinel-not-the-sentinel", sentinel_decoy)

    def example_removed(tmp):
        copy = _copy(root, tmp)
        (copy / "examples" / "m1-client.toml").unlink()
        return check_assets(copy, target, tmp)
    expect("a named example removed (M6-C102)", "example-missing", example_removed)

    def help_broken(tmp):
        copy = _copy(root, tmp)
        client = copy / "bin" / exe(target, "tunnel-client")
        # A wrapper that answers --help/--version like the client but exits
        # 2 on a subcommand --help, as the pre-D6 client did.
        if os.name == "nt":
            return None  # no shell to wrap the client with; reported as skipped
        real = copy / "bin" / "real-client"
        client.rename(real)
        client.write_text('#!/bin/sh\nd="$(dirname "$0")"\nif [ "$#" -gt 1 ]; then "$d/real-client" "$@"; exit 2; fi\n'
                          'exec "$d/real-client" "$@"\n')
        client.chmod(0o755)
        return check_cli(copy, target, tmp)
    expect("a subcommand --help exits 2 (D6)", "subcommand-help", help_broken)

    def planted_import(tmp):
        # Through check_portability itself: the real reader parses the real
        # client's headers, and one import a clean machine lacks is added to
        # what it returns, so the classification and the verdict both run.
        target_os, _ = target_os_arch(target)
        planted = {"linux": "libssl.so.3", "windows": "VCRUNTIME140.dll",
                   "macos": "/opt/homebrew/lib/libssl.3.dylib"}[target_os]

        def reader(binary, os_name):
            found = read_dependencies(binary, os_name)
            return found + [planted] if binary.name == exe(target, "tunnel-client") else found
        return check_portability(root, target, reader=reader)
    expect("a planted import the clean OS lacks", "non-system-dependency", planted_import)
    return out


# ---------------------------------------------------------------- main
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--checksum", type=Path, help="default: <archive>.sha256")
    parser.add_argument("--sha", help="the source commit release.json must name")
    parser.add_argument("--run", help="the CI run release.json must name")
    parser.add_argument("--self-test", action="store_true", help="also run the planted-defect controls")
    args = parser.parse_args()
    archive = args.archive.resolve()
    checksum = (args.checksum or archive.with_name(archive.name + ".sha256")).resolve()
    print(f"verify_release_archive: {archive.name} for {args.target} on {'/'.join(host_os_arch())}")
    print(SCOPE)
    with tempfile.TemporaryDirectory(prefix="verify-unpacked-") as unpacked:
        root = Path(unpacked)
        try:
            unpack(archive, root)
        except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
            print(f"FAILED  unpack: {error}  [witness=unsafe-archive]")
            return 1
        results = run_checks(root, archive, checksum, args.target, args.sha, args.run)
        for result in results:
            print(result.render())
        failed = [r.name for r in results if not r.ok]
        ran = [r.name for r in results]
        control_failures = 0
        if args.self_test and not failed:
            print("self-test: each planted defect must fail with its own witness")
            for label, witness, passed, detail in controls(root, archive, checksum, args.target):
                control_failures += passed is False
                status = "SKIPPED" if passed is None else "ok    " if passed else "FAILED"
                print(f"  {status}  {label} -> want {witness}: {detail}")
    print(f"summary: {len(ran) - len(failed)} of {len(ran)} checks passed ({', '.join(ran)})"
          + (f"; failed: {failed}" if failed else "")
          + (f"; {control_failures} control(s) did not go red as planted" if control_failures else ""))
    return 1 if failed or control_failures else 0


if __name__ == "__main__":
    sys.exit(main())
