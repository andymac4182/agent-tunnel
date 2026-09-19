#!/usr/bin/env python3
"""Tests for the upstream-pin rule in scripts/m7-evidence-guard.py (M8-C21).

The rule lets a verified row cite an upstream artifact -- a commit that is not
and never will be in this repository's history -- but ONLY when docs/sources.md
records that artifact: the full 40-character hash, inside a URL carrying that
hash, beside a labelled SHA-256 content digest.

The red fixture is the point of this file.  A tooling edit that silently
exempted every unresolvable hash would leave m7-evidence-guard.py,
fs-guard-deletion.py and test_guard_outcomes.py all green while the guard had
stopped guarding; that fail-open is what M8-C21 exists to prevent, and only a
case that MUST be reported can detect it.  The green fixture is pinned the same
way test_guard_outcomes.py pins its allowlist: against the real docs/sources.md
entry, so deleting or hollowing out that entry turns this test red rather than
leaving a stale copy of it passing in here.

    python3 scripts/test_evidence_guard_pins.py

Exit codes: 0 pass, non-zero on the first failed case.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS.parent

_spec = importlib.util.spec_from_file_location(
    "m7_evidence_guard", SCRIPTS / "m7-evidence-guard.py"
)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)  # type: ignore[union-attr]

# The upstream RFD commit sources.md pins, and the crates.io/vcs pins beside it.
RFD_COMMIT = "ccff4e7d2e431880225804a8c136c2ccfcb313d0"
SDK_COMMIT = "726c5030bfaa88cfdac2fb1f71a63abb331ce586"
RFD_DIGEST = "db16730db8bcd8d3598323cd0939ce9a655a83ed93a7fd2ce7a31e3ce7be8d37"
# A well-formed 40-hex hash that is in no history and in no sources.md record.
UNRECORDED = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"


def check(condition: bool, message: str) -> None:
    if not condition:
        sys.exit(f"test_evidence_guard_pins: {message}")


def unresolvable(_token: str) -> "bool | None":
    """Every hash is unresolvable: the case upstream pins always fall into."""
    return None


def resolvable_non_ancestor(_token: str) -> "bool | None":
    return False


def findings_for(line: str, pins: "set[str]", ancestry=unresolvable) -> "list[str]":
    found, _gates, _hashes, _pins = guard.row_findings(
        "docs/tasks.md", 1, line, set(), pins, ancestry
    )
    return found


def row(body: str) -> str:
    """A verified tasks.md row carrying `body` as its evidence cell."""
    return f"| M8-01 | [x] Pin stable ACP v1. | verified local | m8c1 worker | {body} | — |"


def main() -> int:
    real_sources = (REPO_ROOT / "docs" / "sources.md").read_text(encoding="utf-8")
    pins = guard.recorded_upstream_pins(real_sources)

    # --- the green fixture: the real sources.md entry ------------------------
    check(
        RFD_COMMIT in pins,
        "docs/sources.md no longer records the transport RFD pin "
        f"{RFD_COMMIT[:8]} with a URL carrying the hash and a labelled SHA-256 "
        "digest; either the record was weakened or the rule stopped reading it",
    )
    check(
        SDK_COMMIT in pins,
        "docs/sources.md no longer records the rust-sdk vcs pin "
        f"{SDK_COMMIT[:8]}; the five other upstream pins in M8-01 are the same "
        "kind of record and must be recognised the same way",
    )
    check(
        findings_for(row(f"The pin is 2026-07-02 at commit `{RFD_COMMIT[:8]}…`."), pins)
        == [],
        "a verified row citing the recorded upstream pin by its short form must "
        "pass: sources.md records repository, commit, path and digest",
    )
    check(
        findings_for(row(f"from rust-sdk commit `{SDK_COMMIT}`."), pins) == [],
        "the full 40-character form of a recorded pin must pass too",
    )

    # --- the red fixture: an upstream hash with no sources.md entry ----------
    # The marker words are deliberate.  The exemption is keyed on sources.md,
    # so writing "upstream pin (recorded)" into the tracker must buy nothing:
    # a tracker marker would be a new cue word addable at will.
    red = findings_for(
        row(f"upstream pin (recorded, verified) at commit `{UNRECORDED}`."), pins
    )
    check(len(red) == 1, f"the unrecorded upstream hash must be one finding, got {red}")
    check(
        "sources.md" in red[0],
        f"the finding must name the record that is missing, got {red[0]}",
    )
    check(
        len(findings_for(row(f"commit `{UNRECORDED[:8]}`."), pins)) == 1,
        "the short form of an unrecorded hash must fail as well",
    )

    # --- a record that exists but records too little ------------------------
    hollow = f"- Pinned: the transport RFD at `{RFD_COMMIT}`, SHA-256 `{RFD_DIGEST}`."
    check(
        guard.recorded_upstream_pins(hollow) == set(),
        "an entry with a hash and a digest but NO URL records no repository or "
        "path and must not create a pin",
    )
    check(
        len(findings_for(row(f"at commit `{RFD_COMMIT}`."),
                         guard.recorded_upstream_pins(hollow))) == 1,
        "a row whose sources.md entry lacks the URL must fail",
    )

    no_digest = (
        "- Pinned: the transport RFD, immutable at "
        f"[`{RFD_COMMIT}`](https://github.com/agentclientprotocol/"
        f"agent-client-protocol/blob/{RFD_COMMIT}/docs/rfds/transport.mdx)."
    )
    check(
        guard.recorded_upstream_pins(no_digest) == set(),
        "an entry with a URL but NO content digest does not record what the "
        "artifact contained and must not create a pin",
    )
    check(
        len(findings_for(row(f"at commit `{RFD_COMMIT}`."),
                         guard.recorded_upstream_pins(no_digest))) == 1,
        "a row whose sources.md entry lacks the digest must fail",
    )

    unlabelled = no_digest[:-1] + f", `{RFD_DIGEST}`."
    check(
        guard.recorded_upstream_pins(unlabelled) == set(),
        "a bare 64-hex blob with no SHA-256/checksum label is not a recorded "
        "digest: an unexplained number must not stand in for a re-hash",
    )

    # --- what the exemption must NOT launder --------------------------------
    check(
        len(findings_for(row(f"at commit `{RFD_COMMIT}`."), pins,
                         resolvable_non_ancestor)) == 1,
        "a hash git DOES resolve is a claim about this repository's history; "
        "being listed in sources.md must not excuse a non-ancestor commit",
    )
    check(
        guard.is_recorded_pin(RFD_COMMIT[:8], pins),
        "prefix matching from the row's short form is the intended match",
    )
    check(
        not guard.is_recorded_pin("deadbee", pins),
        "a hash that prefixes no recorded pin must not be exempt",
    )

    print("test_evidence_guard_pins: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
