#!/usr/bin/env python3
"""Defeat one ACP profile guard at a time, run the tests it should protect, and
restore it.

This is the red-then-green evidence behind the M8 ACP chunks.  Two suites live
here:

* `m8c1` — `crates/tunnel-acp`: the `http-forward/1` profile tables, the strict
  JSON scanner, the JSON-RPC message rules, the version negotiation, the v1
  turn-completion rule, and the two draft features that must stay off.
* `m8c3` — the in-process HTTP/SSE bridge in `crates/tunnel-acp-export`: the
  SSE encoding, the one-subscriber rule, the subscription deadlines, the
  session routing, the workspace policy and the connection's cleanup.  Its
  sibling suite `m8c3-relay` holds the relay's `[http_forward]` profile
  allowlist, which lives in a different crate and needs a different test
  command.
* `m8c2` — the pure lifecycle in `crates/tunnel-acp/src/lifecycle.rs`, the
  supervisor in `crates/tunnel-acp-export` and the synthetic agent in
  `crates/tunnel-acp-fixture`: id scoping, resolve-exactly-once, the bounds,
  the permission deadline, the child's stdout rules, the stderr sink and the
  process-group kill.

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

A **third refusal**, added by chunk 2: a run that *timed out* returns
`NOT EVIDENCE (timed out)`, not `RED (hung)`.  A timed-out run names no failing
test, which is the same observation refusal 2's sibling makes below.  Recorded
as M8-C06.

The classification of those outcomes is **not in this file**.  It lives in
`scripts/guard_outcomes.py`, shared with `scripts/fs-guard-deletion.py`, and it
is an **allow list**: `RED` and `REFUSED BY COMPILER` are usable and everything
else fails closed.  The deny-list-of-prefixes each harness used to carry failed
open, which is how `RED (hung)` and `still green` both went uncounted (M8-C08).
A new outcome spelling added here therefore needs no change there.

A fourth outcome exists here that the filesystem suite has no use for.  One
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_outcomes import unusable as unusable_outcomes  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CRATE = REPO / "crates" / "tunnel-acp"
LIB = CRATE / "src" / "lib.rs"
JSON = CRATE / "src" / "json.rs"
MESSAGE = CRATE / "src" / "message.rs"
PIN = CRATE / "src" / "pin.rs"
MANIFEST = CRATE / "Cargo.toml"

# --no-fail-fast so every red test is named.  Without it cargo stops after the
# first failing binary, and a case whose guard is witnessed by tests in two
# binaries reports only the first -- which understates the evidence and, worse,
# makes a claim about the second witness that the run never checked.
CARGO_TEST = ["cargo", "test", "-p", "tunnel-acp", "--locked", "--no-fail-fast"]

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


# ------------------------------------------------------------- m8c2: chunk 2
#
# The pure lifecycle (`crates/tunnel-acp/src/lifecycle.rs`), the supervisor
# (`crates/tunnel-acp-export`) and the synthetic agent fixture
# (`crates/tunnel-acp-fixture`).
#
# Two kinds of case are deliberately absent rather than faked:
#
# * **A string id and a number id are different requests** is enforced by the
#   type (`RequestId::Text` / `RequestId::Number`), not by a branch.  There is
#   nothing to delete that leaves the crate compiling, so it is in the same
#   class as `unstable_protocol_v2` in the m8c1 suite -- except that it has no
#   `expect_build_failure` shape either, so it is simply not claimed here.
# * **The reader is a separate task** is a structural property of
#   `tokio::spawn(read_agent(..))`.  Defeating it means rewriting the
#   supervisor, not deleting a guard, and a rewrite is not a deletion result.

EXPORT = REPO / "crates" / "tunnel-acp-export"
FIXTURE = REPO / "crates" / "tunnel-acp-fixture"
LIFECYCLE = CRATE / "src" / "lifecycle.rs"
CHILD = EXPORT / "src" / "child.rs"
SUPERVISOR = EXPORT / "src" / "supervisor.rs"

C2_CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-acp",
    "-p",
    "tunnel-acp-export",
    "-p",
    "tunnel-acp-fixture",
    "--locked",
    "--no-fail-fast",
]

C2_CASES: list[tuple[str, list[Edit], bool]] = [
    # ------------------------------------------------ the permission deadline
    (
        "a permission deadline cancels, and never approves",
        [
            (
                LIFECYCLE,
                """                outcome: PermissionOutcome::Cancelled,
            });""",
                """                outcome: PermissionOutcome::Selected("permit-one".to_owned()),
            });""",
            )
        ],
        False,
    ),
    (
        "the deadline must be exceeded, not merely reached",
        [
            (
                LIFECYCLE,
                "&& entry.deadline.is_some_and(|deadline| now > deadline)",
                "&& entry.deadline.is_some_and(|deadline| now >= deadline)",
            )
        ],
        False,
    ),
    (
        # Two edits, because this one rule is written in two places: only a
        # permission is *given* a deadline, and only a permission is *checked*
        # against one.  Defeating either alone leaves the other standing and
        # the suite green, which would report the guard as not load-bearing
        # when it is -- so the case defeats the rule, not half of it.
        "only a permission expires on a permission deadline",
        [
            (
                LIFECYCLE,
                """        let deadline = match kind {
            PendingKind::Permission => Some(now.saturating_add(timeout)),
            PendingKind::Prompt | PendingKind::Call => None,
        };""",
                "        let deadline = Some(now.saturating_add(timeout));",
            ),
            (
                LIFECYCLE,
                """                entry.kind == PendingKind::Permission
                    && entry.deadline.is_some_and(|deadline| now > deadline)""",
                "                entry.deadline.is_some_and(|deadline| now > deadline)",
            ),
        ],
        False,
    ),
    (
        "the cancellation reaches the agent on the wire",
        [
            (
                SUPERVISOR,
                'PermissionOutcome::Cancelled => json!({"outcome": "cancelled"}),',
                'PermissionOutcome::Cancelled => json!({"outcome": "selected", "optionId": "permit-one"}),',
            )
        ],
        False,
    ),
    # ----------------------------------------------------------- id scoping
    (
        "a JSON-RPC id is scoped by its direction",
        [
            (
                LIFECYCLE,
                """            connection: connection.to_owned(),
            direction,
        }""",
                """            connection: connection.to_owned(),
            direction: Direction::HostToAgent,
        }""",
            )
        ],
        False,
    ),
    (
        "a duplicate pending id conflicts before dispatch",
        [
            (
                LIFECYCLE,
                """        if self.pending.contains_key(&key) {
            return Err(LifecycleRejection::new(
                LifecycleRule::DuplicatePendingId,
                "that request id is already outstanding in this scope",
            ));
        }
""",
                "",
            )
        ],
        False,
    ),
    (
        "a callback resolves exactly once",
        [
            (
                LIFECYCLE,
                "        let entry = self.pending.remove(&key).unwrap_or_else(|| unreachable!());",
                "        let entry = self.pending.get(&key).cloned().unwrap_or_else(|| unreachable!());",
            )
        ],
        False,
    ),
    (
        "a response must answer the kind of request outstanding",
        [
            (
                LIFECYCLE,
                "            (PendingKind::Permission, _) | (PendingKind::Prompt | PendingKind::Call, _) => false,",
                "            (PendingKind::Permission, _) | (PendingKind::Prompt | PendingKind::Call, _) => true,",
            )
        ],
        False,
    ),
    # -------------------------------------------------------------- the bounds
    (
        "the pending bound is reached at the bound, not one past it",
        [
            (
                LIFECYCLE,
                "        if self.pending_in(scope) >= self.limit {",
                "        if self.pending_in(scope) > self.limit {",
            )
        ],
        False,
    ),
    (
        "the session bound is reached at the bound, not one past it",
        [
            (
                LIFECYCLE,
                "        if self.sessions.len() >= self.session_limit {",
                "        if self.sessions.len() > self.session_limit {",
            )
        ],
        False,
    ),
    (
        "a second concurrent prompt on one session is refused",
        [
            (
                LIFECYCLE,
                """            SessionPhase::Prompting => Err(LifecycleRejection::new(
                LifecycleRule::PromptAlreadyActive,
                "this session already has an active prompt",
            )),""",
                "            SessionPhase::Prompting => Ok(()),",
            )
        ],
        False,
    ),
    (
        "a new session has no subscriber until one arrives",
        [
            (
                LIFECYCLE,
                "                phase: SessionPhase::AwaitingSubscriber,",
                "                phase: SessionPhase::Ready,",
            )
        ],
        False,
    ),
    # ---------------------------------------------------------- the lifecycle
    (
        "a child that vanished while admitting work failed, it did not stop",
        [
            (
                LIFECYCLE,
                "            (Self::Starting | Self::Ready, LifecycleEvent::Reaped) => Ok(Self::Failed),",
                "            (Self::Starting | Self::Ready, LifecycleEvent::Reaped) => Ok(Self::Stopped),",
            )
        ],
        False,
    ),
    (
        "draining stops admission",
        [(LIFECYCLE, "matches!(self, Self::Ready)", "matches!(self, Self::Ready | Self::Draining)")],
        False,
    ),
    (
        "draining closes every session",
        [
            (
                LIFECYCLE,
                """            for session in self.sessions.values_mut() {
                session.phase = SessionPhase::Closed;
            }
""",
                "",
            )
        ],
        False,
    ),
    # ------------------------------------------------------ the child's stdout
    (
        "an oversized line is refused before it is reassembled",
        [
            (
                CHILD,
                "        if line.len().saturating_add(take) > limit {",
                "        if line.len().saturating_add(take) > usize::MAX {",
            )
        ],
        False,
    ),
    (
        "a refused stdout line is counted",
        [
            (
                CHILD,
                """        ChildEnd::InvalidLine(rule) => {
            if rule == AcpRule::BatchNotSupported {
                counters.batch_output.fetch_add(1, Ordering::Relaxed);
            }
            counters.invalid_output.fetch_add(1, Ordering::Relaxed);
            kill.cancel();
        }""",
                """        ChildEnd::InvalidLine(_) => {
            kill.cancel();
        }""",
            )
        ],
        False,
    ),
    (
        "every end of a child's life signals its process group",
        [
            (
                CHILD,
                """        if kill_group(group) {
            supervisor_counters
                .group_kills
                .fetch_add(1, Ordering::Relaxed);
        }
""",
                "",
            )
        ],
        False,
    ),
    # ----------------------------------------------------------- the stderr sink
    # ------------------------------------------------------------- cleanup
    #
    # Added after the M8-C07 review found three processes alive at the end of a
    # guard run.  Each of these defeats one of the three places cleanup has to
    # happen, and each is witnessed by a **surviving process in the process
    # table**, not by a counter.
    (
        "a supervisor that is dropped rather than drained ends its child",
        [
            (
                SUPERVISOR,
                """    fn drop(&mut self) {
        self.child.kill();
    }""",
                "    fn drop(&mut self) {}",
            )
        ],
        False,
    ),
    (
        "the child handle kills the group synchronously, not only from a task",
        [
            (
                CHILD,
                """        self.kill.cancel();
        if !*self.exited.borrow() {
            let _ = kill_group(self.pid);
        }""",
                "        self.kill.cancel();",
            )
        ],
        False,
    ),
    (
        "the deadline ticker ends when the child does",
        [
            (
                SUPERVISOR,
                """        tokio::select! {
            () = child.wait_exited() => return,
            _ = ticker.tick() => {}
        }""",
                "        ticker.tick().await;",
            )
        ],
        False,
    ),
    (
        "a stderr flood is counted",
        [
            (
                CHILD,
                """                counters
                    .stderr_bytes
                    .fetch_add(read as u64, Ordering::Relaxed);
""",
                "",
            )
        ],
        False,
    ),
    (
        "the stderr sink reports passing its cap",
        [
            (
                CHILD,
                """                if total > cap && !reported {
                    reported = true;
                    counters.stderr_over_cap.fetch_add(1, Ordering::Relaxed);
                }
""",
                "",
            )
        ],
        False,
    ),
]


# ------------------------------------------------------------- m8c3: chunk 3
#
# The in-process HTTP/SSE bridge (`crates/tunnel-acp-export/src/bridge.rs` and
# `src/sse.rs`), its operator configuration, and the relay's `[http_forward]`
# profile allowlist.
#
# Two kinds of case are deliberately absent rather than faked:
#
# **Two earlier exemptions were wrong and are now cases.**  Both were claimed
# here as "cannot be measured", and review measured them:
#
# * **The 202 rule.**  The claim was that nothing could be defeated because no
#   assertion terminates on a status.  The mutation that matters is not
#   `202 -> 200`; it is a **lying 202** -- answer 202 and then never deliver the
#   result.  That is constructible, it reddens four tests, and it is exactly the
#   rule "no claim terminates on a status" exists to protect.  It has no
#   business being the one rule exempted from the standard everything else here
#   is held to.
# * **The inbound listener.**  A listener bound inside `AcpExport::from_config`
#   is a perfectly good deletion case and reddens `no_listener.rs`.  The
#   positive control inside that test checks the *detector*; it says nothing
#   about the export path, which is what a guard case has to defeat.

BRIDGE = EXPORT / "src" / "bridge.rs"
SSE = EXPORT / "src" / "sse.rs"
RELAY_CONFIG = REPO / "crates" / "tunnel-relay" / "src" / "config.rs"

# `--features tunnel-acp-fixture/interop` so the **pinned client's** own tests
# are part of this suite's evidence.  They are off by default -- the client
# drags a second `rustls` crypto provider into whatever build it is in
# (M8-C09) -- but a guard-deletion run is exactly where they belong: several of
# these rules are witnessed by the real client and by nothing else.
C3_CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-acp-export",
    "-p",
    "tunnel-acp-fixture",
    "--features",
    "tunnel-acp-fixture/interop",
    "--locked",
    "--no-fail-fast",
]

C3_RELAY_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-relay",
    "--lib",
    "--locked",
    "--no-fail-fast",
    "http_forward_profiles",
]

C3_CASES: list[tuple[str, list[Edit], bool]] = [
    # --------------------------------------------------------- the 202 rule
    (
        # A **lying 202**: the POST is still accepted, and the result the host
        # is waiting for on its session stream never arrives.  If any claim in
        # this chunk terminated on the status, this would stay green.
        "a 202 is followed by the result on the stream (prompt)",
        [
            (
                BRIDGE,
                """            }
            .unwrap_or_default();
            let _ = target.tx.send(Bytes::from(body)).await;
        });
        no_body(StatusCode::ACCEPTED)
    }

    async fn answer_permission(""",
                """            }
            .unwrap_or_default();
            let _ = body;
        });
        no_body(StatusCode::ACCEPTED)
    }

    async fn answer_permission(""",
            )
        ],
        False,
    ),
    (
        "a 202 is followed by the result on the stream (session/new)",
        [
            (
                BRIDGE,
                """                "result": {"sessionId": session},
            }))
            .unwrap_or_default();
            let _ = target.tx.send(Bytes::from(body)).await;""",
                """                "result": {"sessionId": session},
            }))
            .unwrap_or_default();
            let _ = (target, body);""",
            )
        ],
        False,
    ),
    # ----------------------------------------------------- one lost subscriber
    #
    # **Removed in M8 chunk 4, because the behaviour it guarded was
    # deliberately replaced rather than because the guard stopped mattering.**
    # The case restored chunk 3's destructive router — returning on the first
    # failed send, silently stopping every other stream on the connection — to
    # prove chunk 3's narrow fix was load-bearing. Chunk 3 said in terms that
    # its fix "is not the documented policy"; chunk 4 implemented the documented
    # policy, so an established stream that breaks now terminates the whole ACP
    # transport and the code this case mutated no longer exists. The `m8c4`
    # suite guards the policy that replaced it, including the consequence this
    # one existed for: the other streams no longer go quiet, they are closed and
    # errored. Deleting it silently would have left `COULD NOT APPLY` in a run
    # nobody read, which is how a suite rots.
    # -------------------------------------------------- a child ends its transport
    (
        "a child that is gone ends its transport",
        [
            (
                BRIDGE,
                """            () = connection.supervisor.wait_exited() => {
                end_with_child(&export, &connection).await;
                return;
            }""",
                "            () = connection.supervisor.wait_exited() => return,",
            )
        ],
        False,
    ),
    (
        # **Two edits, because the rule is written in two places**, and the
        # first run of this case proved why: a pump blocked on its queue is
        # woken by the shutdown signal, and a pump whose queue ran dry checks
        # the signal itself. Which one fires is a race, so defeating either
        # alone leaves the other standing and reports the rule as not
        # load-bearing when it is. The same shape as the m8c2 suite's "only a
        # permission expires on a permission deadline".
        "a broken stream errors its body rather than ending cleanly",
        [
            (
                BRIDGE,
                """            () = shutdown.cancelled() => {
                // A connection that ended while a stream was open fails the
                // body rather than ending it cleanly: `docs/acp.md` refuses to
                // let a broken ACP stream look like an orderly one.
                sender.fail(StreamFailure::Interrupted).await;
                return;
            }""",
                "            () = shutdown.cancelled() => return,",
            ),
            (
                BRIDGE,
                """            if shutdown.is_cancelled() {
                sender.fail(StreamFailure::Interrupted).await;
            }
            return;""",
                "            return;",
            ),
        ],
        False,
    ),
    # ------------------------------------------------------ the inbound listener
    (
        # "No listener" has no branch to delete, so the case *adds* one, in the
        # export's own constructor.  That is the path `no_listener.rs` is about;
        # its in-test positive control only checks the detector.
        "the ACP export opens no listener of its own",
        [
            (
                BRIDGE,
                """    pub fn from_config(config: &AcpExportConfig) -> Result<Self, AcpConfigError> {
        let validated = config.validate()?;""",
                """    pub fn from_config(config: &AcpExportConfig) -> Result<Self, AcpConfigError> {
        let validated = config.validate()?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("guard-deletion listener");
        std::mem::forget(listener);""",
            )
        ],
        False,
    ),
    # ------------------------------------------------------ the SSE encoding
    (
        "an SSE event ends with a blank line, not one newline",
        [(SSE, r'event.extend_from_slice(b"\n\n");', r'event.extend_from_slice(b"\n");')],
        False,
    ),
    (
        "an SSE event begins with `data: `",
        [(SSE, 'event.extend_from_slice(b"data: ");', 'event.extend_from_slice(b"data:");')],
        False,
    ),
    (
        # M8-C05, defeated by *adding* the header, because "only these headers"
        # cannot be measured by deletion.
        "no response carries acp-session-id (M8-C05)",
        [
            (
                SSE,
                """    if let Ok(value) = HeaderValue::from_str(connection) {""",
                """    headers.insert(
        http::HeaderName::from_static(tunnel_acp::headers::ACP_SESSION_ID),
        HeaderValue::from_static("session-1"),
    );
    if let Ok(value) = HeaderValue::from_str(connection) {""",
            )
        ],
        False,
    ),
    # --------------------------------------------------------- one subscriber
    (
        "a second subscriber on one stream is refused",
        [
            (
                BRIDGE,
                """        let Some(queue) = target.take() else {
            // The one-subscriber rule, and it is structural: there is nothing
            // left to take.
            self.inner
                .counters
                .subscribers_refused
                .fetch_add(1, Ordering::Relaxed);
            return no_body(StatusCode::CONFLICT);
        };""",
                """        let queue = target
            .take()
            .unwrap_or_else(|| mpsc::channel(STREAM_BACKLOG).1);""",
            )
        ],
        False,
    ),
    (
        "an expired session's window stays closed",
        [
            (
                BRIDGE,
                """            // silently reopens.
            target.close();""",
                "            // silently reopens.",
            )
        ],
        False,
    ),
    # ------------------------------------------------------------- readiness
    (
        "a session admits its prompt only once its subscriber arrived",
        [
            (
                BRIDGE,
                "            let _ = connection.supervisor.subscriber_ready(session);",
                "",
            )
        ],
        False,
    ),
    # ------------------------------------------------------------- deadlines
    (
        "a subscription that never arrives expires",
        [
            (
                BRIDGE,
                "        if !target.is_subscribed() && target.created.elapsed() > bound {",
                "        if false && !target.is_subscribed() && target.created.elapsed() > bound {",
            )
        ],
        False,
    ),
    (
        "a session subscription that never arrives expires",
        [
            (
                BRIDGE,
                "                .filter(|target| !target.is_subscribed() && target.created.elapsed() > bound)",
                "                .filter(|_target| false)",
            )
        ],
        False,
    ),
    # --------------------------------------------------------------- routing
    (
        "a session-scoped message goes to its own session's stream",
        [
            (
                BRIDGE,
                """        let target = match message.session.as_deref() {
            Some(session) => connection.session_target(session),
            None => Some(connection.with(|state| Arc::clone(&state.connection))),
        };""",
                """        let target = Some(connection.with(|state| Arc::clone(&state.connection)));""",
            )
        ],
        False,
    ),
    # ------------------------------------------------------ workspace policy
    (
        "the host cannot choose a workspace or attach MCP servers",
        [
            (
                BRIDGE,
                """        if params.get("cwd").and_then(Value::as_str) != Some(connection.workspace.as_str())""",
                """        if false
            && params.get("cwd").and_then(Value::as_str) != Some(connection.workspace.as_str())""",
            )
        ],
        False,
    ),
    # --------------------------------------------------------------- cleanup
    (
        "a connection that ends takes its child with it",
        [(BRIDGE, "    connection.supervisor.drain().await;", "")],
        False,
    ),
]

C3_RELAY_CASES: list[tuple[str, list[Edit], bool]] = [
    (
        "the relay's profile allowlist admits the ACP profile",
        [
            (
                RELAY_CONFIG,
                "            } else if let Some(profile) = tunnel_acp::AcpProfile::parse_id(id) {",
                "            } else if let Some(profile) = tunnel_acp::AcpProfile::parse_id(id).filter(|_| false) {",
            )
        ],
        False,
    ),
    (
        "and admits nothing else",
        [
            (
                RELAY_CONFIG,
                """            } else {
                return Err(ConfigError::Invalid(
                    "http_forward.profiles may name only mcp-2026-07-28, mcp-2025-11-25 and acp-http-v1",
                ));
            };""",
                """            } else {
                (
                    tunnel_acp::AcpProfile::HttpV1.id(),
                    tunnel_acp::AcpProfile::HttpV1
                        .policies(tunnel_acp::AcpLimits::default())
                        .map_err(|_| {
                            ConfigError::Invalid("pinned http_forward profile is inconsistent")
                        })?,
                )
            };""",
            )
        ],
        False,
    ),
]


# --------------------------------------------------------------- M8 chunk 4
#
# The policies chunk 4 implemented: the offered-option check, subscriber loss
# terminating an ACP transport, the connection-capacity discipline, the
# output-credit stall, and the `RESULT_STATUS` mapping.
#
# `TERMINAL` and `LIFECYCLE` are pure; the rest need a real child, so the suite
# runs the same three crates chunk 2 does.

TERMINAL = CRATE / "src" / "terminal.rs"

C4_CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-acp",
    "-p",
    "tunnel-acp-export",
    "-p",
    "tunnel-acp-fixture",
    "--locked",
    "--no-fail-fast",
]

C4_CASES: list[tuple[str, list[Edit], bool]] = [
    # ------------------------------------------------ the offered-option rule
    (
        "a permission response must name an offered option (M8-C11)",
        [
            (
                LIFECYCLE,
                """        if let Outcome::Permission(PermissionOutcome::Selected(option)) = &outcome
            && let Some(offered) = entry.offered.as_ref()
            && !offered.iter().any(|candidate| candidate == option)
        {""",
                """        if let Outcome::Permission(PermissionOutcome::Selected(option)) = &outcome
            && let Some(offered) = entry.offered.as_ref()
            && !offered.iter().any(|candidate| candidate == option)
            && false
        {""",
            )
        ],
        False,
    ),
    (
        # The refusal must leave the callback outstanding, or an invented
        # option consumes the host's real decision and the genuine answer that
        # follows is refused as unknown.
        "an unoffered option does not consume the outstanding callback",
        [
            (
                LIFECYCLE,
                """            return Err(LifecycleRejection::new(
                LifecycleRule::OptionNotOffered,
                "that optionId was not offered by the request it answers",
            ));""",
                """            self.pending.remove(&key);
            return Err(LifecycleRejection::new(
                LifecycleRule::OptionNotOffered,
                "that optionId was not offered by the request it answers",
            ));""",
            )
        ],
        False,
    ),
    (
        # The supervisor must record what the agent offered.  An empty list
        # admits no selection at all, so every permission turn fails.
        "the supervisor records the options the agent offered",
        [
            (
                SUPERVISOR,
                """    message
        .pointer("/params/options")
        .and_then(serde_json::Value::as_array)""",
                """    message
        .pointer("/params/options/never")
        .and_then(serde_json::Value::as_array)""",
            )
        ],
        False,
    ),
    # --------------------------------------------------- subscriber loss (v0)
    (
        "an established required stream that broke is noticed by the watchdog",
        [
            (
                BRIDGE,
                """        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(StreamSender::is_closed)""",
                """        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(StreamSender::is_closed)
            && false""",
            )
        ],
        False,
    ),
    (
        # Without the parked sender the watchdog has nothing to ask, so a
        # broken stream on a quiet connection is invisible.
        "the live body's sender is parked so a quiet connection still notices",
        [
            (
                BRIDGE,
                """        target.watch_body(sender.clone());""",
                """        let _ = &sender;""",
            )
        ],
        False,
    ),
    (
        # `docs/acp.md` names five consequences; this is the one a counter
        # would not notice going missing.
        "subscriber loss resolves pending permissions as cancelled",
        [
            (
                BRIDGE,
                """    let cancelled = connection.supervisor.cancel_all_permissions().await;""",
                """    let cancelled = 0usize;""",
            )
        ],
        False,
    ),
    # ------------------------------------------------- the capacity discipline
    (
        "the export refuses a connection beyond its global cap",
        [
            (
                BRIDGE,
                """    live < MAX_TRACKED_CONNECTIONS && held < MAX_CONNECTIONS_PER_BINDING""",
                """    held < MAX_CONNECTIONS_PER_BINDING""",
            )
        ],
        False,
    ),
    (
        # Without the per-principal share one authorized principal fills the
        # table and denies everybody else: the cross-principal denial channel.
        "one principal cannot fill the table and deny the rest",
        [
            (
                BRIDGE,
                """    live < MAX_TRACKED_CONNECTIONS && held < MAX_CONNECTIONS_PER_BINDING""",
                """    live < MAX_TRACKED_CONNECTIONS""",
            )
        ],
        False,
    ),
    # ------------------------------------------------ the output-credit stall
    (
        "an output-credit stall is bounded",
        [
            (
                BRIDGE,
                """        match tokio::time::timeout(stall_deadline, target.tx.send(Bytes::from(message.compact)))
            .await
        {""",
                """        match tokio::time::timeout(
            Duration::from_secs(86_400),
            target.tx.send(Bytes::from(message.compact)),
        )
        .await
        {""",
            )
        ],
        False,
    ),
    (
        # `docs/acp.md`: "never drop an event and continue".  Continuing past
        # the stalled message is the failure this rule exists to forbid.
        "a stalled event is never dropped and continued past",
        [
            (
                BRIDGE,
                """                end_with_subscriber_loss(&export, &connection).await;
                return;
            }
        }
    }
}""",
                """                continue;
            }
        }
    }
}""",
            )
        ],
        False,
    ),
    # --------------------------------------- the export applies the mapping
    (
        # Without this the mapping has no consumer and could drift freely.
        "the export classifies a completed turn through the terminal rule",
        [
            (
                BRIDGE,
                """    let counter = match terminal.result_status() {
        "succeeded" => &counters.terminals_succeeded,""",
                """    let counter = match "succeeded" {
        "succeeded" => &counters.terminals_succeeded,""",
            )
        ],
        False,
    ),
    (
        "a prompt whose child died is classified outcome_unknown by the export",
        [
            (
                BRIDGE,
                """                    record_terminal(
                        &connection.counters,
                        tunnel_acp::terminal::AcpTerminal::LostAfterDispatch,
                    );""",
                "",
            )
        ],
        False,
    ),
    # ------------------------------------------- the RESULT_STATUS mapping
    (
        "a lost process after dispatch is outcome_unknown, not a success",
        [
            (
                TERMINAL,
                """            Self::LostAfterDispatch => "outcome_unknown",""",
                """            Self::LostAfterDispatch => "succeeded",""",
            )
        ],
        False,
    ),
    (
        "a confirmed cancelled turn is cancelled",
        [
            (
                TERMINAL,
                """            Self::Turn(StopReason::Cancelled) => "cancelled",""",
                """            Self::Turn(StopReason::Cancelled) => "succeeded",""",
            )
        ],
        False,
    ),
    (
        # `StopReason` is `#[non_exhaustive]`, so a future variant lands in the
        # wildcard.  Reporting success there is how a protocol upgrade starts
        # claiming completions nobody verified.
        #
        # **This one cannot be reddened today, and that is the finding**, so it
        # is in `EXPECT_GREEN` rather than counted.  No test can construct the
        # variant it protects against: every variant the pinned schema defines
        # is matched by name above, and a future one does not exist to be
        # written down.  The guard is for the upgrade that adds one, and it
        # becomes measurable on the day the pin moves.
        "an unread stop reason is not silently a success",
        [
            (
                TERMINAL,
                """            Self::Turn(_) => "outcome_unknown",""",
                """            Self::Turn(_) => "succeeded",""",
            )
        ],
        False,
    ),
]

RELAY_CRATE = REPO / "crates" / "tunnel-relay"

# Cases whose **green result is the documented finding**.
#
# The mechanism is `scripts/fs-guard-deletion.py`'s, added there when failing
# closed changed that harness's exit contract (M8-C08).  An entry here is
# reported on its own line, never counted in a red total, and turns into the
# unusable `EXPECTED A DOCUMENTED GREEN, GOT: ...` if it ever goes red --
# because that would mean the rule became load-bearing and the comment
# explaining the green is now wrong.
#
# Every entry must carry a written reason at the case itself.
EXPECT_GREEN: frozenset[str] = frozenset(
    {
        "an unread stop reason is not silently a success",
    }
)

SUITES: list[Suite] = [
    Suite("m8c1", [CRATE], CARGO_TEST, CASES),
    Suite("m8c2", [CRATE, EXPORT, FIXTURE], C2_CARGO_TEST, C2_CASES),
    Suite("m8c3", [EXPORT, FIXTURE], C3_CARGO_TEST, C3_CASES),
    Suite("m8c3-relay", [RELAY_CRATE], C3_RELAY_TEST, C3_RELAY_CASES),
    Suite("m8c4", [CRATE, EXPORT, FIXTURE], C4_CARGO_TEST, C4_CASES),
]


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
        # Refusal 3.  This used to return "RED (hung)", which was counted as
        # neither red (the tally matches the exact string "RED") nor unusable
        # (the filter below is matched by prefix), so a suite whose every case
        # hung printed a 0-of-N summary and still exited 0.  A run that timed
        # out names no failing test, which is the same observation as the
        # no-named-failure case: not evidence.  Recorded as defect M8-C06.
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
        # Non-zero, but no test said it failed: a --locked lockfile refusal, a
        # doctest failure, a binary killed by a signal.  Something went wrong,
        # and "something went wrong" is not the same observation as "the test
        # that guards this rule went red".  Counting it as RED would let a
        # suite report a guard as load-bearing without a single test naming it.
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
                    "acp-guard-deletion: refusing to run with uncommitted changes "
                    f"under {relative}; each case is restored by checking the "
                    "crate out again, which would discard them."
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print case names and exit")
    parser.add_argument("--case", help="run only cases whose name contains this text")
    parser.add_argument(
        "--suite", help="run only this suite (m8c1, m8c2, m8c3, m8c3-relay, m8c4)"
    )
    arguments = parser.parse_args()

    suites = SUITES
    if arguments.suite:
        suites = [suite for suite in SUITES if suite.name == arguments.suite]
        if not suites:
            sys.exit(f"acp-guard-deletion: no suite named {arguments.suite!r}")
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
        print(
            f"\n{suite.name}: {red} of {measurable} defeated guards turned a test red"
        )
        if documented:
            print(
                f"{suite.name}: {documented} guard(s) reported separately as a documented green"
            )
        if compiler:
            print(
                f"{suite.name}: {compiler} further guard(s) are enforced by the "
                "compiler and are reported separately, never counted as a red test"
            )

    # Shared, and an allow list rather than a deny list: see
    # scripts/guard_outcomes.py and task row M8-C08.  Anything that is not RED
    # or REFUSED BY COMPILER fails closed and is named, including "still green"
    # -- a guard that was defeated with nothing going red is not load-bearing,
    # and a run of nothing but those must not exit 0.
    unusable = unusable_outcomes(
        (suite_name, name, outcome) for suite_name, name, outcome, _ in results
    )
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
