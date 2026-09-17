#!/usr/bin/env python3
"""Defeat one ACP profile guard at a time, run the tests it should protect, and
restore it.

This is the red-then-green evidence behind M8 chunk 1: the pinned `tunnel-acp`
profile, its message validation and its pin assertions.  One suite lives here:

* `m8c1` — `crates/tunnel-acp`: the `http-forward/1` profile tables, the strict
  JSON scanner, the JSON-RPC message rules, the version negotiation, the v1
  turn-completion rule, and the two draft features that must stay off.

It follows `scripts/fs-guard-deletion.py`, **including both of that script's
refusals, which are what keep the numbers honest and neither of which may be
removed**:

1. `run_tests` will not call a failed build a red test.  A deleted guard can
   leave the crate unbuildable — an unused import, a binding that is now dead —
   and counting that as evidence would credit the guard for a failure that says
   nothing about behaviour.
2. A case whose `old` text is **not unique** in its file is refused outright
   rather than applied to the first match.  `str.replace(old, new, 1)` edits
   whichever match comes first, so an ambiguous case defeats some *other* guard
   and reports a red for it under the wrong name.

A third outcome exists here that the filesystem suite has no use for.  One
guard — `unstable_protocol_v2` staying off — is enforced by the compiler
rather than by a test: the pinned schema removes `ProtocolVersion::LATEST`
when that feature is enabled, so `src/pin.rs` stops compiling.  Turning the
feature on is therefore a **build failure by design**, and refusal 1 above
would report it as "not evidence".  That case is marked
`expect_build_failure`, reported as `REFUSED BY COMPILER`, and deliberately
**not counted in the red total**: a compile error is a stronger guarantee than
a red test, but it is a different kind of evidence and is not allowed to
inflate a count of deletions that turned a test red.

Some guards are defeated by replacing a condition rather than by deleting
lines, for the same reason gate 6 of the filesystem suite does it: the pinned
tables are arrays and removing an entry changes what a neighbouring test
measures rather than what this case names.  Where a case *adds* something — a
routed method, a response header, an enabled feature — it is defeating the
rule "only these, and nothing else", which cannot be measured by deletion at
all.

    python3 scripts/acp-guard-deletion.py                 # every case
    python3 scripts/acp-guard-deletion.py --list          # names only
    python3 scripts/acp-guard-deletion.py --case batch    # substring filter

Exit status is 0 when every case produced a usable result, and 1 when any case
could not be applied, or did not build when it was expected to.

The working tree must be clean before running: every case is restored by
checking the crate out again, which would discard uncommitted work there.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CRATE = REPO / "crates" / "tunnel-acp"
LIB = CRATE / "src" / "lib.rs"
JSON = CRATE / "src" / "json.rs"
MESSAGE = CRATE / "src" / "message.rs"
PIN = CRATE / "src" / "pin.rs"
MANIFEST = CRATE / "Cargo.toml"

CARGO_TEST = ["cargo", "test", "-p", "tunnel-acp", "--locked"]

# An edit is (file, exact text to remove or replace, replacement).
Edit = tuple[Path, str, str]

# ------------------------------------------------------------------ the batch

BATCH_FIRST: Edit = (
    MESSAGE,
    """    if top_level(body) == TopLevel::Array {
        return Err(AcpRejection::new(
            AcpRule::BatchNotSupported,
            "JSON-RPC batches are not supported by this transport",
        ));
    }
""",
    "",
)

# --------------------------------------------------------------------- cases

CASES: list[tuple[str, list[Edit], bool]] = [
    (
        "a batch is refused before anything else looks at the body",
        [BATCH_FIRST],
        False,
    ),
    (
        # The classification itself, rather than its placement.  With `[`
        # classified as anything else, a syntactically valid batch falls
        # through to the generic "not one JSON-RPC message object" answer and
        # loses its 501.
        "the top level classifies `[` as an array",
        [(JSON, "            b'[' => TopLevel::Array,", "            b'[' => TopLevel::Other,")],
        False,
    ),
    (
        "the jsonrpc member must be exactly \"2.0\"",
        [
            (
                MESSAGE,
                """    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(AcpRejection::new(
            AcpRule::JsonRpcVersion,
            "jsonrpc must be \\"2.0\\"",
        ));
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "an id must be a string or an integer",
        [
            (
                MESSAGE,
                """    if let Some(id) = id
        && !(id.is_string() || is_integer(id))
    {
        return Err(AcpRejection::new(
            AcpRule::RequestId,
            "id must be a string or an integer",
        ));
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "params must be an object",
        [
            (
                MESSAGE,
                """    if let Some(params) = object.get("params")
        && !params.is_object()
    {""",
                """    if let Some(params) = object.get("params")
        && !params.is_object()
        && false
    {""",
            )
        ],
        False,
    ),
    (
        "duplicate member names, compared after unescaping",
        [
            (
                JSON,
                """            if names.contains(&name) {
                return Err(JsonError::DuplicateKey);
            }
""",
                "",
            )
        ],
        False,
    ),
    (
        "a lone leading surrogate escape is refused, never repaired",
        [
            (
                JSON,
                """        if !(0xd800..=0xdbff).contains(&first) {
            return char::from_u32(u32::from(first)).ok_or(JsonError::Syntax);
        }""",
                """        if !(0xd800..=0xdbff).contains(&first) {
            return char::from_u32(u32::from(first)).ok_or(JsonError::Syntax);
        }
        return Ok(char::REPLACEMENT_CHARACTER);
        #[allow(unreachable_code)]""",
            )
        ],
        False,
    ),
    (
        "raw control characters inside a JSON string",
        [(JSON, "                0x00..=0x1f => return Err(JsonError::Syntax),", "")],
        False,
    ),
    (
        "trailing data after the top-level value",
        [
            (
                JSON,
                """    if scanner.position != input.len() {
        return Err(JsonError::TrailingData);
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "the nesting depth bound",
        [
            (
                JSON,
                """        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
""",
                "",
            )
        ],
        False,
    ),
    # ------------------------------------------------------- profile tables
    (
        # "Only HTTP/2" cannot be deleted; it is defeated by widening it.
        "the profile accepts HTTP/2 only",
        [
            (
                LIB,
                "        request.allow_http_version(HttpVersion::Http2);",
                "        request.allow_http_version(HttpVersion::Http2);\n"
                "        request.allow_http_version(HttpVersion::Http11);",
            )
        ],
        False,
    ),
    (
        "only POST, GET and DELETE are routed",
        [
            (
                LIB,
                "const ROUTES: &[Method] = &[Method::Post, Method::Get, Method::Delete];",
                "const ROUTES: &[Method] = &[Method::Post, Method::Get, Method::Delete, Method::Put];",
            )
        ],
        False,
    ),
    (
        "no response may carry acp-session-id",
        [
            (
                LIB,
                """    (headers::ACP_CONNECTION_ID, Occurrence::Singleton),
];

/// The advertised method/path pairs.""",
                """    (headers::ACP_CONNECTION_ID, Occurrence::Singleton),
    (headers::ACP_SESSION_ID, Occurrence::Singleton),
];

/// The advertised method/path pairs.""",
            )
        ],
        False,
    ),
    (
        "every pinned request header is a singleton",
        [
            (
                LIB,
                "    (headers::TUNNEL_PRINCIPAL_BINDING, Occurrence::Singleton),",
                "    (headers::TUNNEL_PRINCIPAL_BINDING, Occurrence::Repeatable),",
            )
        ],
        False,
    ),
    (
        "the RFD's request_permission shorthand is not an accepted method",
        [
            (
                LIB,
                """        let mut names = client_to_agent();
        names.extend(agent_to_client());
        names""",
                """        let mut names = client_to_agent();
        names.extend(agent_to_client());
        names.push(crate::RFD_PERMISSION_SHORTHAND);
        names""",
            )
        ],
        False,
    ),
    (
        "the shorthand resolves against the normative v1 name",
        [
            (
                LIB,
                """    if name == RFD_PERMISSION_SHORTHAND {
        return Some(
            agent_client_protocol::schema::v1::CLIENT_METHOD_NAMES.session_request_permission,
        );
    }
    None""",
                "    let _ = name;\n    None",
            )
        ],
        False,
    ),
    (
        "an unaccepted method is refused before dispatch",
        [
            (
                MESSAGE,
                """    if let Some(method) = message.method.as_deref()
        && !is_accepted_method(method)
    {""",
                """    if let Some(method) = message.method.as_deref()
        && !is_accepted_method(method)
        && false
    {""",
            )
        ],
        False,
    ),
    # --------------------------------------------------- negotiation and v2
    (
        "a protocol version that is not 1 is refused",
        [
            (
                MESSAGE,
                "    if number == PROTOCOL_VERSION_V1 {\n        return Ok(number);\n    }",
                "    if number == PROTOCOL_VERSION_V1 || number == 2 {\n        return Ok(number);\n    }",
            )
        ],
        False,
    ),
    (
        "an initialize must carry a protocolVersion",
        [
            (
                MESSAGE,
                """    let Some(field) = field else {
        return Err(AcpRejection::new(
            AcpRule::ProtocolVersionShape,
            "protocolVersion is required",
        )
        .with_id(message.id.as_ref()));
    };""",
                """    let Some(field) = field else {
        return Ok(PROTOCOL_VERSION_V1);
    };""",
            )
        ],
        False,
    ),
    (
        "a v2 prompt acknowledgement is not a v1 turn completion",
        [
            (
                MESSAGE,
                """    if !object.contains_key("stopReason") {
        return Err(AcpRejection::new(
            AcpRule::V2PromptAcknowledgement,
            "a session/prompt result without stopReason is a v2 acknowledgement, not a v1 turn completion",
        ));
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "a stop reason outside the pinned vocabulary is refused",
        [
            (
                MESSAGE,
                """    let response: PromptResponse = serde_json::from_value(result.clone()).map_err(|_| {
        AcpRejection::new(
            AcpRule::UnknownStopReason,
            "stopReason is not a value in the pinned ACP v1 vocabulary",
        )
    })?;
    Ok(response.stop_reason)""",
                """    let response: PromptResponse = serde_json::from_value(result.clone())
        .unwrap_or_else(|_| PromptResponse::new(StopReason::EndTurn));
    Ok(response.stop_reason)""",
            )
        ],
        False,
    ),
    # ------------------------------------------------------ identity headers
    (
        "initialize must not present a connection header",
        [
            (
                MESSAGE,
                """        if connection.is_some() {
            return Err(AcpRejection::new(
                AcpRule::ConnectionHeaderForbidden,
                "initialize opens a connection and must not present Acp-Connection-Id",
            )
            .with_id(id));
        }""",
                "        let _ = connection;",
            )
        ],
        False,
    ),
    (
        "every other POST must name its connection",
        [
            (
                MESSAGE,
                """    } else if connection.is_none() {
        return Err(AcpRejection::new(
            AcpRule::ConnectionHeaderRequired,
            "Acp-Connection-Id is required",
        )
        .with_id(id));
    }""",
                "    }",
            )
        ],
        False,
    ),
    (
        "a session-scoped method requires the session header",
        [
            (
                MESSAGE,
                """    if let Some(method) = message.method.as_deref()
        && requires_session_header(method)
        && session.is_none()
    {""",
                """    if let Some(method) = message.method.as_deref()
        && requires_session_header(method)
        && session.is_none()
        && false
    {""",
            )
        ],
        False,
    ),
    (
        "the session header and params.sessionId must agree",
        [
            (
                MESSAGE,
                """    if let (Some(session), Some(body)) = (session, message.session_id())
        && session != body
    {""",
                """    if let (Some(session), Some(body)) = (session, message.session_id())
        && session != body
        && false
    {""",
            )
        ],
        False,
    ),
    (
        "a GET must accept text/event-stream",
        [
            (
                MESSAGE,
                """    if !accept_covers(header(headers, headers::ACCEPT).unwrap_or(""), EVENT_STREAM) {
        return Err(AcpRejection::new(
            AcpRule::Accept,
            "Accept must list text/event-stream",
        ));
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "a GET and a DELETE must name their connection",
        [
            (
                MESSAGE,
                """    if header(headers, headers::ACP_CONNECTION_ID).is_some_and(|value| !value.is_empty()) {
        Ok(())
    } else {""",
                """    if true {
        Ok(())
    } else {""",
            )
        ],
        False,
    ),
    (
        "a POST must be application/json",
        [
            (
                MESSAGE,
                "    if media_type(content_type).eq_ignore_ascii_case(JSON) {",
                "    if true || media_type(content_type).eq_ignore_ascii_case(JSON) {",
            )
        ],
        False,
    ),
    # ------------------------------------------------------- the pinned facts
    (
        "the recorded checksum is the lockfile's",
        [
            (
                PIN,
                '"6395d81d91fd2ee93f48ea31cfc511356e75b9061ca0389cefd0308507cc11ba"',
                '"0000000000000000000000000000000000000000000000000000000000000000"',
            )
        ],
        False,
    ),
    (
        "the manifest requires the exact version",
        [
            (
                MANIFEST,
                'agent-client-protocol = { version = "=2.1.0", default-features = false }',
                'agent-client-protocol = { version = "2.1.0", default-features = false }',
            )
        ],
        False,
    ),
    (
        # Enabling this one really does enable it: the schema's method tables
        # gain three members, so both the manifest scan and the runtime
        # observation of the built artifact go red.
        "unstable_mcp_over_acp stays off",
        [
            (
                MANIFEST,
                'agent-client-protocol = { version = "=2.1.0", default-features = false }',
                'agent-client-protocol = { version = "=2.1.0", default-features = false, '
                'features = ["unstable_mcp_over_acp"] }',
            )
        ],
        False,
    ),
    (
        # Enforced by the compiler, not by a test: see the module docstring.
        "unstable_protocol_v2 stays off",
        [
            (
                MANIFEST,
                'agent-client-protocol = { version = "=2.1.0", default-features = false }',
                'agent-client-protocol = { version = "=2.1.0", default-features = false, '
                'features = ["unstable_protocol_v2"] }',
            )
        ],
        True,
    ),
]


@dataclass
class Suite:
    name: str
    crates: list[Path]
    cargo_test: list[str]
    cases: list[tuple[str, list[Edit], bool]] = field(default_factory=list)
    cwd: Path = REPO


SUITES: list[Suite] = [Suite("m8c1", [CRATE], CARGO_TEST, CASES)]


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
        return "RED (hung)", []
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
                    "acp-guard-deletion: refusing to run with uncommitted changes "
                    f"under {relative}; each case is restored by checking the "
                    "crate out again, which would discard them."
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print case names and exit")
    parser.add_argument("--case", help="run only cases whose name contains this text")
    arguments = parser.parse_args()

    suites = SUITES
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
        sys.exit(f"acp-guard-deletion: no case matches {arguments.case!r}")

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
                # Refusing is the whole point: `str.replace(old, new, 1)` would
                # silently edit the FIRST match, so a case whose text is not
                # unique measures some other guard — and reports a red for it
                # under this case's name.
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
        if expect_build_failure:
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
        measurable = len(rows) - compiler
        print(
            f"\n{suite.name}: {red} of {measurable} defeated guards turned a test red"
        )
        if compiler:
            print(
                f"{suite.name}: {compiler} further guard(s) are enforced by the "
                "compiler and are reported separately, never counted as a red test"
            )

    # Every "not evidence" outcome must reach this list, or a suite whose cases
    # all failed to build would exit 0 and read as a clean run.
    unusable = [
        f"[{suite_name}] {name}"
        for suite_name, name, outcome, _ in results
        if outcome.startswith(("BUILD", "COULD", "EXPECTED"))
    ]
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
