#!/usr/bin/env python3
"""Delete one confinement guard at a time from `tunnel-fs-host`, run the tests
it should protect, and restore it.

This is the red-then-green evidence behind implementation gate 2 of
`docs/filesystem-api.md`.  A guard whose deletion leaves every test green is
**not** load-bearing on its own, and this script prints that outcome rather
than hiding it: several of the resolver's guards mask one another and are
red only in pairs or as a triple, which is why those combinations are cases
here in their own right.

    python3 scripts/fs-guard-deletion.py            # every case
    python3 scripts/fs-guard-deletion.py --list     # names only
    python3 scripts/fs-guard-deletion.py --case "32-hop"   # substring filter

Exit status is 0 when every case produced a usable result, and 1 when any case
could not be applied or did not build — see `run_tests` below, which refuses to
call a failed build a red test.  An earlier round of this evidence was wrong in
exactly that way: the harness restored the crate with `git checkout` between
runs, which also reverted an uncommitted cargo feature the tests needed, so
three cases reported "RED" for a build that never compiled.  That refusal is the
reason the numbers in task row M4-08 can be trusted, so do not remove it.

The working tree must be clean before running: every case is restored with
`git checkout -- crates/tunnel-fs-host`, which would discard uncommitted work
in that directory.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CRATE = REPO / "crates" / "tunnel-fs-host"
RESOLVER = CRATE / "src" / "resolver.rs"
POLICY = CRATE / "src" / "policy.rs"
IDENTITY = CRATE / "src" / "identity.rs"

# The tests need the hook that holds the TOCTOU window open; without it the
# four window guards cannot be measured at all.
CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-fs-host",
    "--locked",
    "--features",
    "race-window-hook",
]

# An edit is (file, exact text to remove or replace, replacement).
Edit = tuple[Path, str, str]

DIR_NOFOLLOW: Edit = (
    RESOLVER,
    "OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,\n"
    "                            Mode::empty(),",
    "OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,\n"
    "                            Mode::empty(),",
)
FILE_NOFOLLOW: Edit = (
    RESOLVER,
    "intent.flags() | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,",
    "intent.flags() | OFlags::CLOEXEC | OFlags::NONBLOCK,",
)
DIR_IDENTITY: Edit = (
    RESOLVER,
    """                    let identity = identity_of(&opened)?;
                    if !identity.is_same_file(seen) {
                        return Err(lost_race());
                    }
                    check_same_device(self.identity, identity)?;
                    if last {""",
    """                    let identity = identity_of(&opened)?;
                    check_same_device(self.identity, identity)?;
                    if last {""",
)
FILE_IDENTITY: Edit = (
    RESOLVER,
    """                    let identity = identity_of(&opened)?;
                    if !identity.is_same_file(seen) {
                        return Err(lost_race());
                    }
                    // Decided again on the descriptor, which is the only
                    // authority: the check above was taken on a name.""",
    """                    let identity = identity_of(&opened)?;""",
)
DIR_POST_DEVICE: Edit = (
    RESOLVER,
    "                    check_same_device(self.identity, identity)?;\n                    if last {",
    "                    if last {",
)
DIR_PRE_DEVICE: Edit = (
    RESOLVER,
    """                    check_same_device(self.identity, seen)?;
                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            OFlags::RDONLY | OFlags::DIRECTORY""",
    """                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            OFlags::RDONLY | OFlags::DIRECTORY""",
)
FILE_PRE_DEVICE: Edit = (
    RESOLVER,
    """                    check_same_device(self.identity, seen)?;
                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            intent.flags()""",
    """                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            intent.flags()""",
)
PRE_OPEN_KIND: Edit = (RESOLVER, "                    check_exportable(kind)?;\n", "")
POST_OPEN_KIND: Edit = (RESOLVER, "                    check_exportable(identity.kind())?;\n", "")

CASES: list[tuple[str, list[Edit]]] = [
    (
        "symlink feature refusal (rule 3)",
        [
            (
                RESOLVER,
                """                    if !self.features.has(Feature::Symlinks) {
                        // Rule 3: with the feature off a link met during
                        // traversal fails the walk rather than being followed.
                        return Err(FsError::refused(FsErrorCode::Eloop));
                    }
""",
                "",
            )
        ],
    ),
    (
        "32-hop link budget",
        [
            (
                RESOLVER,
                """                    hops += 1;
                    if hops > MAX_LINK_HOPS {
                        return Err(FsError::refused(FsErrorCode::Eloop));
                    }
""",
                "                    hops += 1;\n",
            )
        ],
    ),
    (
        "absolute link target re-rooting",
        [(RESOLVER, "                        ancestors.truncate(1);", "                        let _ = &ancestors;")],
    ),
    (
        "`..` clamped at the root",
        [
            (
                RESOLVER,
                """                if ancestors.len() > 1 {
                    ancestors.pop();
                }""",
                "                ancestors.pop();",
            )
        ],
    ),
    (
        "link-target component bound",
        [
            (
                RESOLVER,
                """                    if parts.len() > self.bounds.max_components() {
                        return Err(FsError::refused(FsErrorCode::Enametoolong));
                    }
""",
                "",
            )
        ],
    ),
    (
        "trailing-separator link target rule",
        [
            (
                RESOLVER,
                """                    if last && target.ends_with('/') {
                        require_directory = true;
                    }
""",
                "",
            )
        ],
    ),
    (
        "uniform race answer (ELOOP/ENOTDIR fold)",
        [
            (
                RESOLVER,
                """    if errno == rustix::io::Errno::LOOP || errno == rustix::io::Errno::NOTDIR {
        lost_race()
    } else {
        host_error(errno)
    }""",
                "    host_error(errno)",
            )
        ],
    ),
    ("mount boundary after the directory open", [DIR_POST_DEVICE]),
    ("mount boundary before the directory open", [DIR_PRE_DEVICE]),
    ("mount boundary before the file open", [FILE_PRE_DEVICE]),
    (
        "all three mount-boundary checks together",
        [DIR_PRE_DEVICE, FILE_PRE_DEVICE, DIR_POST_DEVICE],
    ),
    ("special-file refusal before the open", [PRE_OPEN_KIND]),
    ("special-file refusal on the descriptor", [POST_OPEN_KIND]),
    ("both special-file refusals", [PRE_OPEN_KIND, POST_OPEN_KIND]),
    ("O_NOFOLLOW on a directory component", [DIR_NOFOLLOW]),
    ("O_NOFOLLOW on the final file open", [FILE_NOFOLLOW]),
    ("post-open identity check on a directory", [DIR_IDENTITY]),
    ("post-open identity check on a file", [FILE_IDENTITY]),
    ("directory O_NOFOLLOW and its identity check together", [DIR_NOFOLLOW, DIR_IDENTITY]),
    ("file O_NOFOLLOW and its identity check together", [FILE_NOFOLLOW, FILE_IDENTITY]),
    (
        "hard-link write refusal (rule 4)",
        [
            (
                RESOLVER,
                """        check_hard_link_write(
            primitive,
            handle.identity(),
            self.features.has(Feature::HardLinks),
        )?;
""",
                "",
            )
        ],
    ),
    (
        "hard-link rule excludes directories",
        [
            (
                IDENTITY,
                "matches!(self.kind, FileKind::RegularFile) && self.links > 1",
                "self.links > 1",
            )
        ],
    ),
    (
        "grant check before resolution",
        [
            (
                RESOLVER,
                """        self.authorize(primitive)?;
        let handle = self.resolve(path, Intent::Write)?;""",
                "        let handle = self.resolve(path, Intent::Write)?;",
            )
        ],
    ),
    (
        "host errno translated by meaning",
        [
            (
                POLICY,
                """    if errno == Errno::NOENT {
        FsErrorCode::Enoent""",
                """    if errno == Errno::NOENT {
        FsErrorCode::Einval""",
            )
        ],
    ),
    (
        "EINTR retried rather than reported",
        [
            (
                RESOLVER,
                "            Err(errno) if errno == rustix::io::Errno::INTR => {}",
                "            Err(errno) if errno == rustix::io::Errno::INTR && false => {}",
            )
        ],
    ),
]


def cargo_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    env.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")
    env.setdefault("CARGO_INCREMENTAL", "0")
    return env


def run_tests() -> tuple[str, list[str]]:
    """Run the crate's suite and classify the outcome.

    A build that did not compile is **never** reported as a red test.  A
    deleted guard can leave the crate unbuildable — an unused import, a binding
    that is now dead — and counting that as evidence would credit the guard for
    a failure that says nothing about confinement.
    """
    try:
        done = subprocess.run(
            CARGO_TEST,
            cwd=REPO,
            env=cargo_env(),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return "RED (hung)", []
    combined = done.stdout + done.stderr
    if "error[" in combined or "error: could not compile" in combined:
        return "BUILD FAILED (not evidence)", []
    failures = sorted(
        {
            line.strip().removeprefix("test ").removesuffix(" ... FAILED")
            for line in done.stdout.splitlines()
            if line.strip().endswith("... FAILED")
        }
    )
    if done.returncode == 0:
        return "still green", []
    return "RED", failures


def restore() -> None:
    subprocess.run(
        ["git", "checkout", "--", str(CRATE.relative_to(REPO))], cwd=REPO, check=True
    )


def require_clean_tree() -> None:
    changed = subprocess.run(
        ["git", "status", "--porcelain", "--", str(CRATE.relative_to(REPO))],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if changed:
        sys.exit(
            "fs-guard-deletion: refusing to run with uncommitted changes under "
            "crates/tunnel-fs-host; each case is restored with `git checkout`, "
            "which would discard them."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print case names and exit")
    parser.add_argument("--case", help="run only cases whose name contains this text")
    arguments = parser.parse_args()

    cases = [case for case in CASES if not arguments.case or arguments.case in case[0]]
    if arguments.list:
        for name, _ in cases:
            print(name)
        return 0
    if not cases:
        sys.exit(f"fs-guard-deletion: no case matches {arguments.case!r}")

    require_clean_tree()

    results: list[tuple[str, str, list[str]]] = []
    for name, edits in cases:
        applied = True
        for path, old, new in edits:
            text = path.read_text()
            if old not in text:
                applied = False
                break
            path.write_text(text.replace(old, new, 1))
        if not applied:
            restore()
            results.append((name, "COULD NOT DELETE: guard text not found", []))
            print(f"{name}: guard text not found", flush=True)
            continue
        outcome, failures = run_tests()
        restore()
        results.append((name, outcome, failures))
        print(f"{name}: {outcome} {failures if failures else ''}".rstrip(), flush=True)

    print("\n=== summary ===")
    for name, outcome, failures in results:
        detail = f" -> {', '.join(failures)}" if failures else ""
        print(f"- {name}: {outcome}{detail}")
    red = sum(1 for _, outcome, _ in results if outcome == "RED")
    print(f"\n{red} of {len(results)} deletions turned a test red")

    unusable = [
        name
        for name, outcome, _ in results
        if outcome.startswith("BUILD") or outcome.startswith("COULD")
    ]
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
