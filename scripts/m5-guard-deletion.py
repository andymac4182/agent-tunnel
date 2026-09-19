#!/usr/bin/env python3
"""Defeat one `computer.v1` guard at a time, run the tests it should protect,
and restore it.

This is the red-then-green evidence behind M5 chunk 2. One suite lives here:

* `m5c2` — `crates/tunnel-cua` and `crates/tunnel-cua-fixture`: the
  loopback endpoint check, the read-only operation allowlist, the strict
  request scanner, the pre-dispatch validation ordering, the backend outcome
  classification (the 200-with-`success:false` trap, the absent-`success`
  rule, the pre-dispatch 400/401 shape and the 503), the three-way capability
  intersection with its probe requirement, the absent-by-default capture
  authority, and the synthetic-image marker check.

It follows `scripts/acp-guard-deletion.py` and `scripts/fs-guard-deletion.py`,
**including their refusals, none of which may be removed**:

1. `run_tests` will not call a failed build a red test. A deleted guard can
   leave the crate unbuildable, and counting that as evidence would credit the
   guard for a failure that says nothing about behaviour.
2. A case whose `old` text is **not unique** in its file is refused outright
   rather than applied to the first match. `str.replace(old, new, 1)` edits
   whichever match comes first, so an ambiguous case would defeat some *other*
   guard and report a red for it under the wrong name.
3. A run that *timed out* returns `NOT EVIDENCE (timed out)`, not `RED (hung)`:
   a timed-out run names no failing test.

The classification of those outcomes is **not in this file**. It lives in
`scripts/guard_outcomes.py`, shared with the other harnesses, and it is an
**allow list**: everything that is not a usable outcome fails closed.

Usage:

    python3 scripts/m5-guard-deletion.py            # every case
    python3 scripts/m5-guard-deletion.py --list
    python3 scripts/m5-guard-deletion.py --case loopback
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_outcomes import unusable as unusable_outcomes  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CRATE = REPO / "crates" / "tunnel-cua"
FIXTURE = REPO / "crates" / "tunnel-cua-fixture"

ENDPOINT = CRATE / "src" / "endpoint.rs"
OPERATION = CRATE / "src" / "operation.rs"
OUTCOME = CRATE / "src" / "outcome.rs"
CAPABILITY = CRATE / "src" / "capability.rs"
SCHEMA = CRATE / "src" / "schema.rs"
PLAN = CRATE / "src" / "plan.rs"
JSON = CRATE / "src" / "json.rs"
MARKER = CRATE / "src" / "marker.rs"
CLIENT = FIXTURE / "src" / "client.rs"

# --no-fail-fast so every red test is named. Without it cargo stops after the
# first failing binary, and a case witnessed by tests in two binaries reports
# only the first.
CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-cua",
    "-p",
    "tunnel-cua-fixture",
    "--locked",
    "--no-fail-fast",
]

# An edit is (file, exact text to remove or replace, replacement).
Edit = tuple[Path, str, str]

CASES: list[tuple[str, list[Edit], bool]] = [
    # ------------------------------------------------- the endpoint check
    (
        # Proof 2 of the four: "the endpoint check refuses non-loopback
        # targets, with a guard case that reddens when deleted." This is that
        # guard case.
        "the backend endpoint must be a loopback address",
        [
            (
                ENDPOINT,
                """        if !ip.is_loopback() {
            return Err(EndpointError::NotLoopback);
        }
""",
                "",
            )
        ],
        False,
    ),
    (
        # The mapped-address canonicalization. Without it `::ffff:127.0.0.1` is
        # refused and, far worse for any check written against literals, the
        # two spellings of one address behave differently.
        "an IPv4-mapped IPv6 address is canonicalized before the loopback check",
        [(ENDPOINT, "    ip.to_canonical()", "    ip")],
        False,
    ),
    (
        # The quantifier. `any` instead of `all` is the steerable reading.
        "every resolved address must be loopback, not merely one of them",
        [
            (
                ENDPOINT,
                """        for address in rest {
            Self::new(*address)?;
        }
""",
                "",
            )
        ],
        False,
    ),
    (
        "the unspecified address is refused",
        [
            (
                ENDPOINT,
                """        if ip.is_unspecified() {
            return Err(EndpointError::Unspecified);
        }
""",
                "",
            )
        ],
        False,
    ),
    # ------------------------------------------------------- the allowlist
    (
        # Fail-closed: `parse` returning a pass-through would forward any name.
        "an unknown operation name does not parse",
        [
            (
                OPERATION,
                "        Self::ALL\n            .into_iter()\n            .find(|operation| operation.name() == name)\n    }",
                "        Self::ALL\n            .into_iter()\n            .find(|operation| operation.name() == name)\n            .or(Some(Self::Describe))\n    }",
            )
        ],
        False,
    ),
    (
        "a deferred input operation is refused rather than treated as unknown-but-allowed",
        [
            (
                OPERATION,
                """    ("click", Deferral::SynthesisesInput),
    ("double_click", Deferral::SynthesisesInput),
    ("move", Deferral::SynthesisesInput),
    ("drag", Deferral::SynthesisesInput),
    ("scroll", Deferral::SynthesisesInput),
    ("type_text", Deferral::SynthesisesInput),
    ("press_key", Deferral::SynthesisesInput),
    ("hotkey", Deferral::SynthesisesInput),
""",
                "",
            )
        ],
        False,
    ),
    (
        "describe maps to no upstream command",
        [
            (
                OPERATION,
                "            Self::Describe => None,",
                '            Self::Describe => Some("version"),',
            )
        ],
        False,
    ),
    # ------------------------------------------- pre-dispatch validation
    (
        "an unknown top-level member is refused rather than ignored",
        [
            (
                SCHEMA,
                """    for name in map.keys() {
        if !REQUEST_MEMBERS.contains(&name.as_str()) {
            return Err(SchemaError::UnknownMember);
        }
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "an unknown params member is refused rather than ignored",
        [
            (
                SCHEMA,
                """    for name in params.keys() {
        if !accepted.contains(&name.as_str()) {
            return Err(SchemaError::UnknownMember);
        }
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "the schema version is compared exactly",
        [
            (
                SCHEMA,
                """    if version != crate::SCHEMA_VERSION {
        return Err(SchemaError::UnsupportedVersion);
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "the request body limit is checked before the body is parsed",
        [
            (
                SCHEMA,
                """    if body.len() as u64 > limit {
        return Err(SchemaError::TooLarge { limit });
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "the display index is bounded",
        [
            (
                SCHEMA,
                """            if index > MAX_DISPLAY {
                return Err(SchemaError::OutOfRange { name: "display" });
            }
""",
                "",
            )
        ],
        False,
    ),
    (
        # The rule that makes "validated" and "dispatched" the same thing.
        "a duplicated member name is refused rather than resolved",
        [
            (
                JSON,
                """            if seen.contains(&name) {
                return Err(JsonError::DuplicateKey);
            }
""",
                "",
            )
        ],
        False,
    ),
    (
        "the request body must be a JSON object",
        [
            (
                JSON,
                """    if text.trim_start().as_bytes().first() != Some(&b'{') {
        return Err(JsonError::NotAnObject);
    }
""",
                "",
            )
        ],
        False,
    ),
    # The case "an operation outside the negotiated set is refused before
    # dispatch" used to live here, editing the fixture's dispatcher. The check
    # moved into `plan.rs` when the ordering contract moved into the production
    # crate, so it is now "the capability check runs before anything is planned
    # for dispatch", above.
    # ----------------------------------------- the outcome classification
    (
        # The trap: HTTP 200 with `success: false`.
        "a framed payload's success member decides, not the HTTP status",
        [
            (
                OUTCOME,
                """        Some(Value::Bool(false)) => Completion::Failed {
            code: failure_code(payload),
        },""",
                """        Some(Value::Bool(false)) => Completion::Ok(Value::Object(payload.clone())),""",
            )
        ],
        False,
    ),
    (
        # Absent is not true.
        "an absent success member is unknown rather than a success",
        [
            (
                OUTCOME,
                "        None => Completion::Unknown(UnknownReason::SuccessAbsent),",
                "        None => Completion::Ok(Value::Object(payload.clone())),",
            )
        ],
        False,
    ),
    (
        # Shape 3: pre-dispatch HTTPExceptions are NOT dispatched.
        "a pre-dispatch 400 or 401 is classified as not dispatched",
        [
            (
                OUTCOME,
                """    if cua_pin::PRE_DISPATCH_ERROR_STATUSES.contains(&status) {
        return Dispatch::NotDispatched(NotDispatched::BackendRejected { status });
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        # Shape 4: 503 is deliberate unavailability.
        "a 503 is deliberate unavailability rather than a dispatched unknown",
        [
            (
                OUTCOME,
                """    if status == UNAVAILABLE_STATUS {
        return Dispatch::NotDispatched(NotDispatched::BackendUnavailable);
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        # The direction of failure: unrecognised statuses must go to Unknown.
        "an unreasoned status fails towards unknown rather than not-dispatched",
        [
            (
                OUTCOME,
                """        return Dispatch::Dispatched(Completion::Unknown(UnknownReason::UnexpectedStatus {
            status,
        }));""",
                "        return Dispatch::NotDispatched(NotDispatched::NotReached);",
            )
        ],
        False,
    ),
    (
        # The single most load-bearing method in the crate.
        "an unknown outcome is never retryable",
        [
            (
                OUTCOME,
                "            Self::Dispatched(Completion::Ok(_) | Completion::Unknown(_)) => false,",
                "            Self::Dispatched(Completion::Ok(_)) => false,\n            Self::Dispatched(Completion::Unknown(_)) => true,",
            )
        ],
        False,
    ),
    (
        # The stage distinction: a failure after the write is Unknown, not
        # NotDispatched. This is the "unknown outcome that is really not
        # dispatched" trap in the one place it can actually be made.
        "a failure after the request was written is unknown, not not-dispatched",
        [
            (
                CLIENT,
                "            Self::Reading => {\n                Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost))\n            }",
                "            Self::Reading => Dispatch::NotDispatched(NotDispatched::NotReached),",
            )
        ],
        False,
    ),
    (
        "a truncated framing is distinguished from an absent one",
        [
            (
                OUTCOME,
                "        return Err(UnknownReason::Truncated);",
                "        return Err(UnknownReason::FramingAbsent);",
            )
        ],
        False,
    ),
    # --------------------------------------------- capability negotiation
    (
        # The config-echo trap: probe evidence must require a real dispatch.
        "probe evidence requires a dispatched, succeeded probe",
        [
            (
                CAPABILITY,
                """        if !matches!(dispatch, Dispatch::Dispatched(Completion::Ok(_))) {
            return None;
        }
""",
                "",
            )
        ],
        False,
    ),
    (
        "describe and capture cannot stand in for the probe",
        [
            (
                CAPABILITY,
                """        if !matches!(probe, Operation::ScreenInfo | Operation::CursorPosition) {
            return None;
        }
""",
                "",
            )
        ],
        False,
    ),
    (
        "the negotiated set is the intersection of all three inputs",
        [
            (
                CAPABILITY,
                "            local.contains(*operation)\n                && upstream.supports(*operation)\n                && grant.contains(*operation)",
                "            local.contains(*operation)\n                || upstream.supports(*operation)\n                || grant.contains(*operation)",
            )
        ],
        False,
    ),
    (
        # The M5-01 measurement: absent-by-default, not false.
        "an absent desktop_capture_authorized is unknown, not denied",
        [
            (
                CAPABILITY,
                """            Some(Value::Bool(false)) => Self::Denied,
            _ => Self::Unknown,""",
                """            Some(Value::Bool(false)) => Self::Denied,
            _ => Self::Denied,""",
            )
        ],
        False,
    ),
    (
        "an unknown capture authority still permits an attempt",
        [
            (
                CAPABILITY,
                "            Self::Granted | Self::Unknown => true,\n            Self::Denied => false,",
                "            Self::Granted => true,\n            Self::Denied | Self::Unknown => false,",
            )
        ],
        False,
    ),
    # ------------------------------------------------ the synthetic images
    (
        # Proof 4: a real capture must fail rather than pass silently.
        "a capture without the synthetic magic is refused",
        [
            (
                MARKER,
                "    if blob.len() < HEADER_LEN || &blob[..8] != MAGIC {\n        return Err(MarkerError::NotSynthetic);\n    }",
                "    if blob.len() < HEADER_LEN {\n        return Err(MarkerError::NotSynthetic);\n    }",
            )
        ],
        False,
    ),
    (
        # The byte-count-is-not-evidence rule, as a deletion: verifying only
        # the length is exactly the defect the scoping document names.
        "a capture is verified per marker rather than by length alone",
        [
            (
                MARKER,
                """            if found != marker(seed, x, y) {
                return Err(MarkerError::MarkerMismatch { x, y });
            }""",
                "            let _ = found;",
            )
        ],
        False,
    ),
    # ------------------------------- locally-answered is not dispatched
    (
        # The first review's headline finding: `describe` is answered from
        # device-side state and reporting it as a dispatch made
        # `reached_the_backend()` true with an empty ledger -- falsifying this
        # chunk's central invariant in the one case the fault table missed.
        "an operation answered from device-side state is not reported as a dispatch",
        [
            (
                CLIENT,
                "                return Dispatch::AnsweredLocally(self.describe());",
                "                return Dispatch::Dispatched(Completion::Ok(self.describe()));",
            )
        ],
        False,
    ),
    (
        "a locally-answered operation is planned as a local answer, never as a command",
        [
            (
                PLAN,
                """        return Ok(Planned::AnswerLocally { operation });""",
                """        return Ok(Planned::Dispatch {
            command: "version",
            payload: command_payload("version", request.params()),
            operation,
        });""",
            )
        ],
        False,
    ),
    (
        # The ordering itself, now that it lives in the production crate.
        "the capability check runs before anything is planned for dispatch",
        [
            (
                PLAN,
                """    if !permitted.contains(&operation) {
        return Err(Dispatch::NotDispatched(NotDispatched::NotPermitted));
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        # Discovery must not become a way to send an arbitrary command name.
        "the discovery entry point admits only the commands describe reads",
        [
            (
                PLAN,
                """    if !Operation::DESCRIBE_READS.contains(&command) {
        return Err(NotDispatched::Operation(crate::operation::Refusal::Unknown));
    }
""",
                "",
            )
        ],
        False,
    ),
    # ------------------------- capture authority, from the right response
    (
        # The second review finding: authority was read from the probe result,
        # a response that does not carry the key, so `Denied` was unreachable.
        "capture authority is read from a dispatched version reading",
        [
            (
                CAPABILITY,
                "            Dispatch::Dispatched(Completion::Ok(result)) => Self::from_status(result),",
                "            Dispatch::Dispatched(Completion::Ok(_)) => Self::Unknown,",
            )
        ],
        False,
    ),
    (
        "a version reading that did not happen is unknown rather than a denial",
        [
            (
                CAPABILITY,
                '''            _ => Self::Unknown,
        }
    }

    /// Whether a capture may be attempted.''',
                '''            _ => Self::Denied,
        }
    }

    /// Whether a capture may be attempted.''',
            )
        ],
        False,
    ),
    # --------------------------------- the wire outcome for a refusal
    (
        # The third review finding: a pre-dispatch refusal rendered as
        # `failed`, collapsing the distinction at the boundary a consumer sees.
        "a pre-dispatch refusal renders as its own wire outcome, not as failed",
        [
            (
                SCHEMA,
                "            outcome: ResponseOutcome::NotDispatched,",
                "            outcome: ResponseOutcome::Failed,",
            )
        ],
        False,
    ),
    (
        "a locally-answered operation renders as its own wire outcome",
        [
            (
                SCHEMA,
                "            outcome: ResponseOutcome::AnsweredLocally,",
                "            outcome: ResponseOutcome::Ok,",
            )
        ],
        False,
    ),
    # **A case that used to be here, and what happened to it.** "A capture is
    # verified against the seed the caller expected, not the one it carries"
    # deleted an `image.seed != seed` early return in `verify`. It came back
    # **still green**: the per-marker loop recomputes from the caller's seed, so
    # a mismatched image already fails at its first pixel and the early return
    # checked nothing. Rather than exempt it as a documented green, the
    # redundant check was deleted from `marker.rs` -- it also mis-reported the
    # failing pixel as (0, 0). A rule that nothing can break is not a guard.
]


@dataclass
class Suite:
    name: str
    crates: list[Path]
    cargo_test: list[str]
    cases: list[tuple[str, list[Edit], bool]] = field(default_factory=list)
    cwd: Path = REPO


SUITES: list[Suite] = [Suite("m5c2", [CRATE, FIXTURE], CARGO_TEST, CASES)]

#: Cases whose green result is itself the measurement. Empty today, and kept
#: so a future case that needs one has the mechanism rather than inventing it.
EXPECT_GREEN: set[str] = set()


def cargo_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    env.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")
    env.setdefault("CARGO_INCREMENTAL", "0")
    return env


def run_tests(suite: Suite) -> tuple[str, list[str]]:
    """Run one suite's tests and classify the outcome.

    A build that did not compile is **never** reported as a red test.
    """
    try:
        done = subprocess.run(
            suite.cargo_test,
            cwd=suite.cwd,
            env=cargo_env(),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return "NOT EVIDENCE (timed out)", []
    combined = done.stdout + done.stderr
    if "error[" in combined or "error: could not compile" in combined:
        return "BUILD FAILED", []
    failures = sorted(
        {
            line.strip().removeprefix("test ").removesuffix(" ... FAILED")
            for line in done.stdout.splitlines()
            if line.strip().endswith("... FAILED")
        }
    )
    if done.returncode == 0:
        return "still green", []
    if not failures:
        return "NOT EVIDENCE (no named failure)", []
    return "RED", failures


def restore(suite: Suite) -> None:
    subprocess.run(
        ["git", "checkout", "--"]
        + [str(crate.relative_to(REPO)) for crate in suite.crates],
        cwd=REPO,
        check=True,
    )


def require_clean_tree(suites: list[Suite]) -> None:
    for suite in suites:
        for crate in suite.crates:
            relative = str(crate.relative_to(REPO))
            changed = subprocess.run(
                ["git", "status", "--porcelain", "--", relative],
                cwd=REPO,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if changed:
                sys.exit(
                    "m5-guard-deletion: refusing to run with uncommitted changes "
                    f"under {relative}; each case is restored by checking the "
                    "crate out again, which would discard them."
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print case names and exit")
    parser.add_argument("--case", help="run only cases whose name contains this text")
    parser.add_argument("--suite", help="run only this suite (m5c2)")
    arguments = parser.parse_args()

    suites = SUITES
    if arguments.suite:
        suites = [suite for suite in SUITES if suite.name == arguments.suite]
        if not suites:
            sys.exit(f"m5-guard-deletion: no suite named {arguments.suite!r}")
    selected = [
        (suite, name, edits, expect_build_failure)
        for suite in suites
        for name, edits, expect_build_failure in suite.cases
        if not arguments.case or arguments.case in name
    ]
    if arguments.list:
        for suite, name, _, _ in selected:
            print(f"{suite.name}: {name}")
        return 0
    if not selected:
        sys.exit(f"m5-guard-deletion: no case matches {arguments.case!r}")

    require_clean_tree(suites)

    results: list[tuple[str, str, str, list[str]]] = []
    for suite, name, edits, expect_build_failure in selected:
        problem = None
        for path, old, new in edits:
            text = path.read_text()
            occurrences = text.count(old)
            if occurrences == 0:
                problem = "guard text not found"
                break
            if occurrences > 1:
                problem = f"guard text is ambiguous: {occurrences} occurrences"
                break
            path.write_text(text.replace(old, new, 1))
        if problem is not None:
            restore(suite)
            results.append((suite.name, name, f"COULD NOT APPLY: {problem}", []))
            print(f"[{suite.name}] {name}: {problem}", flush=True)
            continue
        outcome, failures = run_tests(suite)
        restore(suite)
        if name in EXPECT_GREEN:
            outcome = (
                "DOCUMENTED GREEN"
                if outcome == "still green"
                else f"EXPECTED A DOCUMENTED GREEN, GOT: {outcome}"
            )
        elif expect_build_failure:
            outcome = (
                "REFUSED BY COMPILER"
                if outcome == "BUILD FAILED"
                else f"EXPECTED A COMPILER REFUSAL, GOT: {outcome}"
            )
        elif outcome == "BUILD FAILED":
            outcome = "BUILD FAILED (not evidence)"
        results.append((suite.name, name, outcome, failures))
        print(
            f"[{suite.name}] {name}: {outcome} {failures if failures else ''}".rstrip(),
            flush=True,
        )

    print("\n=== summary ===")
    for suite_name, name, outcome, failures in results:
        detail = f" -> {', '.join(failures)}" if failures else ""
        print(f"- [{suite_name}] {name}: {outcome}{detail}")
    for suite in suites:
        rows = [row for row in results if row[0] == suite.name]
        if not rows:
            continue
        red = sum(1 for row in rows if row[2] == "RED")
        compiler = sum(1 for row in rows if row[2] == "REFUSED BY COMPILER")
        documented = sum(1 for row in rows if row[2] == "DOCUMENTED GREEN")
        measurable = len(rows) - compiler - documented
        print(f"\n{suite.name}: {red} of {measurable} defeated guards turned a test red")
        if documented:
            print(
                f"{suite.name}: {documented} guard(s) reported separately as a documented green"
            )
        if compiler:
            print(
                f"{suite.name}: {compiler} further guard(s) are enforced by the "
                "compiler and are reported separately, never counted as a red test"
            )

    unusable = unusable_outcomes(
        (suite_name, name, outcome) for suite_name, name, outcome, _ in results
    )
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
