#!/usr/bin/env python3
"""Re-derive the CUA parameter pin from the fetched upstream source (M5-C06).

`crates/tunnel-http-forward/src/cua_pin.rs::COMMAND_PARAMETERS` records, for
every allowlisted `computer.v1` command, the parameter names the pinned
`cua-computer-server` handler declares. A table transcribed by hand is only as
good as the transcription, and the repository's own rule is that a pin must be
re-derived from the artifact rather than believed.

This script is that re-derivation. It parses the *fetched* `handlers/base.py`
with `ast` -- not a regex over the Rust file, and not the repository's own
copy of anything -- and compares the signatures it finds against the table
parsed out of `cua_pin.rs`. A drift in either direction is a failure.

It is invoked by `scripts/m5-cua-refetch.sh`, which downloads and hash-verifies
the file first; the digests are the provenance and this is the meaning.

Usage: m5-cua-param-parity.py <base.py> <main.py> [cua_pin.rs]
Exit 0 only when every allowlisted command's pinned schema matches upstream.

**Why upstream's own dispatch makes this worth doing.** `main.py` dispatches
with `filtered_params = {k: v for k, v in params.items() if k in sig.parameters}`.
A parameter the handler does not declare is dropped with no error and no log.
So the cost of a wrong name is not a failed request -- it is a command that
runs with the wrong arguments and reports success.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PIN = REPO / "crates" / "tunnel-http-forward" / "src" / "cua_pin.rs"

#: The one allowlisted command that is not a handler method. `main.py`
#: registers it as a zero-argument lambda in the `handlers` dict.
VERSION_COMMAND = "version"
VERSION_EVIDENCE = '"version": lambda:'


def upstream_signatures(base_py: Path) -> dict[str, tuple[list[str], list[str]]]:
    """Every method defined in base.py, as (required, optional) name lists.

    `self` is dropped. A parameter with a default is optional; one without is
    required -- which is exactly the distinction upstream enforces, since a
    missing required argument raises `TypeError` inside the handler call.
    """
    tree = ast.parse(base_py.read_text(encoding="utf-8"))
    found: dict[str, tuple[list[str], list[str]]] = {}
    duplicates: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = node.args
        names = [a.arg for a in args.posonlyargs + args.args if a.arg != "self"]
        names += [a.arg for a in args.kwonlyargs]
        defaulted = len(args.defaults)
        positional = [a.arg for a in args.posonlyargs + args.args if a.arg != "self"]
        required = positional[: len(positional) - defaulted] if defaulted else positional
        optional = [n for n in names if n not in required]
        if node.name in found:
            duplicates.add(node.name)
        found[node.name] = (required, optional)

    for name in sorted(duplicates):
        print(
            f"note: {name} is defined more than once in base.py; the last wins",
            file=sys.stderr,
        )
    return found


def pinned_table(pin_rs: Path) -> dict[str, tuple[list[str], list[str]]]:
    """Parse COMMAND_PARAMETERS out of cua_pin.rs."""
    source = pin_rs.read_text(encoding="utf-8")
    # **The colon is load-bearing.** Without it this matched
    # `COMMAND_PARAMETERS_RENAMED` as a prefix, so renaming the constant --
    # the most obvious way to make the pin stop existing -- left this script
    # printing a green line over a table it had not found. That is the same
    # cannot-fail shape `docs/tasks.md` M5-C11 catalogues; it was caught by
    # running the rename as a red test rather than assuming the find worked.
    start = source.find("pub const COMMAND_PARAMETERS:")
    if start < 0:
        raise SystemExit("FAIL: COMMAND_PARAMETERS is not declared in cua_pin.rs")
    end = source.find("\n];", start)
    if end < 0:
        raise SystemExit("FAIL: COMMAND_PARAMETERS is not terminated")
    body = source[start:end]

    entry = re.compile(
        r"command:\s*\"(?P<command>[a-z_]+)\"\s*,\s*"
        r"required:\s*&\[(?P<required>[^\]]*)\]\s*,\s*"
        r"optional:\s*&\[(?P<optional>[^\]]*)\]",
        re.S,
    )
    names = re.compile(r"\"([a-z_]+)\"")
    table: dict[str, tuple[list[str], list[str]]] = {}
    for match in entry.finditer(body):
        table[match.group("command")] = (
            names.findall(match.group("required")),
            names.findall(match.group("optional")),
        )
    if not table:
        raise SystemExit(
            "FAIL: COMMAND_PARAMETERS parsed to zero entries -- the parser and "
            "the table have drifted apart, which is not the same as agreeing"
        )
    return table


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    base_py = Path(sys.argv[1])
    main_py = Path(sys.argv[2])
    pin_rs = Path(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PIN

    upstream = upstream_signatures(base_py)
    pinned = pinned_table(pin_rs)
    main_source = main_py.read_text(encoding="utf-8")

    failures: list[str] = []
    compared = 0

    for command, (want_required, want_optional) in sorted(pinned.items()):
        if command == VERSION_COMMAND:
            # Not a handler method: a registry lambda taking nothing.
            if VERSION_EVIDENCE not in main_source:
                failures.append(
                    f"{command}: main.py no longer registers it as a "
                    f"zero-argument lambda ({VERSION_EVIDENCE!r} not found)"
                )
            elif want_required or want_optional:
                failures.append(
                    f"{command}: pinned with parameters, but upstream takes none"
                )
            compared += 1
            continue

        if command not in upstream:
            failures.append(
                f"{command}: pinned here, but no such method in the fetched base.py"
            )
            continue

        got_required, got_optional = upstream[command]
        if sorted(got_required) != sorted(want_required):
            failures.append(
                f"{command}: required is {sorted(got_required)} upstream, "
                f"pinned as {sorted(want_required)}"
            )
        if sorted(got_optional) != sorted(want_optional):
            failures.append(
                f"{command}: optional is {sorted(got_optional)} upstream, "
                f"pinned as {sorted(want_optional)}"
            )
        compared += 1

    # **A comparison that compared nothing is not a green run.** Without this
    # the loop above is satisfied by an empty table, a renamed constant, or a
    # regex that stopped matching -- each of which would print the same
    # reassuring final line. The count is the check that the check ran.
    expected = 14
    if compared != expected:
        failures.append(
            f"compared {compared} commands, expected {expected}: the parity "
            f"check did not run over the whole allowlist"
        )

    # Positive control for the parser itself. These are commands the pin does
    # NOT allowlist, so they never appear in the loop above -- if the ast walk
    # silently found nothing, the loop and this control fail together and the
    # message says which.
    for control in ("run_command", "write_text"):
        if control not in upstream:
            failures.append(
                f"control: {control} was not found in base.py, so the "
                f"signature parser read nothing and every match above is vacuous"
            )

    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if failures:
        print(
            f"{len(failures)} parameter-pin mismatch(es) against the fetched "
            f"upstream source.",
            file=sys.stderr,
        )
        print(
            "Do not edit the table to match without reading why the signature "
            "moved: a changed parameter name is a silently broken adapter.",
            file=sys.stderr,
        )
        return 1

    print(
        f"ok   parameter pin: {compared} allowlisted commands re-derived from "
        f"the fetched base.py and main.py, all matching."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
