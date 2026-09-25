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
* `m8c5` — the cluster gate's own validator in
  `crates/tunnel-test-harness/src/production_cluster/acp_cluster.rs`: the three
  completed rotations, the socket bounds, the byte-identical isolation
  refusals, the forgery refusals, the revocation classification, the two
  explicit interruptions and the saturation threshold.  Its guards are
  validator rules, so defeating one stops that rule rejecting its own
  falsification and the gate's `every_claim_can_fail_on_its_own` names it.
* `m8c7` — the **parent-death sentinel** on the ACP path (M8-C07's trigger
  half): arming it at all, the sentinel firing on a bare end of file, the
  orderly stand-down, and the two fixture guards that keep the probe's helper
  in the group and its escaping descendant out of it.  It is the one suite
  here that carries a mandatory pre-build, because its tests `exec` two
  binaries from two packages (see `Suite.build` and task row M3-19).
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

The working tree must be clean before running.  Not because a restore would
discard uncommitted work -- since M5-C07 each case is restored by writing back
the exact bytes it recorded, so it no longer would -- but because a case
applied on top of an uncommitted edit cannot be told apart from it, and the
run would then credit a guard on the strength of somebody else's change.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_outcomes import AppliedCase  # noqa: E402
from guard_outcomes import check_anchors as shared_check_anchors  # noqa: E402
from guard_outcomes import classify_outcome  # noqa: E402
from guard_outcomes import forbid_writes_for_this_process  # noqa: E402
from guard_outcomes import install_interrupt_restore  # noqa: E402
from guard_outcomes import load_witness_debt  # noqa: E402
from guard_outcomes import read_only_entry  # noqa: E402
from guard_outcomes import refuse_resident_mutation  # noqa: E402
from guard_outcomes import require_declared_witnesses  # noqa: E402
from guard_outcomes import require_git_index  # noqa: E402
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
    #: A command that must succeed **before** this suite's tests run.
    #:
    #: **Task row M3-19, and it may not be removed to make a suite faster.**
    #: A suite whose tests `exec` a binary does not merely link the code under
    #: test.  `cargo test -p <pkg>` builds a package's `[[bin]]` as a plain
    #: executable only when that package has integration tests of its own, and
    #: it builds **no binary belonging to another package at all** — so a case
    #: that edits some *other* crate is run against whatever executable
    #: happened to be lying in the target directory.  That is not a
    #: hypothetical: the M3 suite's first run reported the sentinel's group
    #: kill as `still green` — a guard that is the entire mechanism, defeated,
    #: with nothing going red — because the deleted code was never rebuilt.
    #: A harness that silently tests a stale artifact is worse than no harness.
    #:
    #: Suites whose tests exec nothing leave this empty.
    build: list[str] = field(default_factory=list)


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
                """                .filter(|target| {
                    !target.is_subscribed()
                        && !target.is_closed()
                        && target.created.elapsed() > bound
                })""",
                "                .filter(|_target| false)",
            )
        ],
        False,
    ),
    (
        # **M8-C25.** Deleting only the `is_closed` term leaves the expiry
        # working and leaves every assertion about *closing* green: the window
        # still closes, the target is still closed, the late GET is still
        # refused 409. What it reintroduces is the re-count -- the sweep
        # matching the same already-closed target on every 20 ms tick -- so the
        # only thing that can redden is a test that asserts the counter counts
        # **expiries** rather than ticks. Before this fix nothing did, which is
        # why the rule was invisible to this harness while the defect was live,
        # and why M8-C17's lesson applies here by name: a rule with no guard
        # case is a rule this suite reports on without measuring.
        #
        # The expected witness is
        # `an_expired_session_window_is_counted_once_not_once_per_watchdog_tick`
        # in `crates/tunnel-acp-fixture/tests/bridge.rs`, whose message
        # "counted once per expiry, not once per watchdog tick" is unique to
        # this rule.
        "an expired session window is counted once, not once per watchdog tick",
        [
            (
                BRIDGE,
                """                        && !target.is_closed()
""",
                "",
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

# --------------------------------------------------------------- M8 chunk 5
#
# Chunk 5's guards are not codec rules; they are the cluster gate's own
# validator rules.  That is why this suite's test command is the harness's own
# library tests rather than the ACP crates': `every_claim_can_fail_on_its_own`
# asserts that each claim can fail on its own, so a rule that has been deleted
# or neutered stops rejecting its falsification and that test goes red by name.
#
# **This suite does not run the gate itself.**  The gate needs Redis, three
# relays and about fifty seconds; running it once per case would exceed the
# 600 s per-case ceiling on a cold build and would make every figure here a
# measure of the fixture's flakiness rather than of the guard.  What is
# measured is the validator, which is where every one of these rules lives.
HARNESS_CRATE = REPO / "crates" / "tunnel-test-harness"
ACP_CLUSTER = (
    HARNESS_CRATE / "src" / "production_cluster" / "acp_cluster.rs"
)

C5_CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "--no-fail-fast",
    "acp_cluster",
]

C5_CASES: list[tuple[str, list[Edit], bool]] = [
    # ------------------------------------------------- the three rotations
    (
        "three completed rotations are required, not recorded",
        [
            (
                ACP_CLUSTER,
                "            evidence.rotations_across_span >= REQUIRED_ROTATIONS,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the owner must have counted the rotations independently",
        [
            (
                ACP_CLUSTER,
                "            evidence.owner_rotations_across_span >= REQUIRED_ROTATIONS,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "a window shorter than the schedule counted recovery, not rotations",
        [
            (
                ACP_CLUSTER,
                "            evidence.rotation_span_met_schedule,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the rotation window must finish inside one membership record",
        [
            (
                ACP_CLUSTER,
                "            evidence.rotation_span_ms < ROTATION_CEILING.as_millis(),",
                "            true,",
            )
        ],
        False,
    ),
    (
        "every rotation round must move the device to one new data socket",
        [
            (
                ACP_CLUSTER,
                """            evidence.new_sockets_per_round.len()
                == usize::try_from(REQUIRED_ROTATIONS).unwrap_or(usize::MAX)
                && evidence.new_sockets_per_round.iter().all(|new| *new == 1),""",
                "            true,",
            )
        ],
        False,
    ),
    (
        "two device sockets at every settled steady state",
        [
            (
                ACP_CLUSTER,
                """            !evidence.steady_state_sockets.is_empty()
                && evidence.steady_state_sockets.iter().all(|open| *open == 2),""",
                "            true,",
            )
        ],
        False,
    ),
    (
        "at most one candidate data socket",
        [
            (
                ACP_CLUSTER,
                "            evidence.device_socket_peak <= 3,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "these must be rotations rather than a reconnect",
        [
            (
                ACP_CLUSTER,
                "            evidence.device_session_stable && evidence.device_epoch_stable,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "each held turn's side effect is recorded exactly once and never replayed",
        [
            (
                ACP_CLUSTER,
                """            evidence.side_effects_in_ledger == ROTATION_SESSIONS as u64
                && evidence.side_effects_after_settle == ROTATION_SESSIONS as u64,""",
                "            true,",
            )
        ],
        False,
    ),
    (
        "a permission callback arriving twice across the window is a duplicate",
        [
            (
                ACP_CLUSTER,
                """                "the permission callback arrived exactly once across the window",
                span.callbacks == 1,""",
                """                "the permission callback arrived exactly once across the window",
                true,""",
            )
        ],
        False,
    ),
    (
        "the held turn must complete end_turn, read off the wire",
        [
            (
                ACP_CLUSTER,
                """                "the held turn completed end_turn, read off the wire",
                span.stop_reason == "end_turn",""",
                """                "the held turn completed end_turn, read off the wire",
                true,""",
            )
        ],
        False,
    ),
    # --------------------------------------------- the M7-C80 accommodation
    (
        "every case must end inside the membership records' lifetime",
        [
            (
                ACP_CLUSTER,
                "            evidence.max_membership_age_at_case_end_ms < MEMBERSHIP_RECORD_LIFETIME.as_millis(),",
                "            true,",
            )
        ],
        False,
    ),
    (
        "an uncorrelated rotation-freeze refusal must fail the run (M3-15)",
        [
            (
                ACP_CLUSTER,
                """            evidence.not_dispatched_refusals == evidence.not_dispatched_retries
                && evidence.unexplained_refusal.is_none(),""",
                "            true,",
            )
        ],
        False,
    ),
    # ------------------------------------------------------- two tenants
    (
        "a live connection id must be inert in the other tenant",
        [
            (
                ACP_CLUSTER,
                "            evidence.connection_id_inert_in_other_tenant,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the two tenants must really have reused one session id",
        [
            (
                ACP_CLUSTER,
                "            evidence.session_ids_collide,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "every reply must be routed to the principal that asked",
        [
            (
                ACP_CLUSTER,
                "            evidence.replies_routed_per_principal,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "a same-tenant foreign id must be refused byte-identically",
        [
            (
                ACP_CLUSTER,
                "            evidence.same_tenant_foreign_matches_unknown,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "a cross-tenant foreign id must be refused byte-identically",
        [
            (
                ACP_CLUSTER,
                "            evidence.cross_tenant_foreign_matches_unknown,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the refusal must be the profile's not-found, not some other error",
        [
            (
                ACP_CLUSTER,
                "            evidence.foreign_refusal_status == 404,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the probes must not have opened anything on the other tenant's export",
        [
            (
                ACP_CLUSTER,
                "            evidence.tenant_b_sessions_opened == 1,",
                "            true,",
            )
        ],
        False,
    ),
    # ---------------------------------------------------------- forgeries
    (
        "every forged head must be refused before dispatch",
        [
            (
                ACP_CLUSTER,
                "            evidence.forgery_attempts == 3 && evidence.forgeries_refused == 3,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "not one forged head may reach the device",
        [
            (
                ACP_CLUSTER,
                "            evidence.forgery_dispatched == 0,",
                "            true,",
            )
        ],
        False,
    ),
    # --------------------------------------------------------- revocation
    (
        "revocation must withdraw the admitted exchange",
        [
            (
                ACP_CLUSTER,
                "            evidence.revocation_in_flight_withdrawn,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the withdrawn exchange must be classified execution: unknown",
        [
            (
                ACP_CLUSTER,
                """            evidence
                .revocation_in_flight_execution
                .split('+')
                .any(|execution| execution == "unknown"),""",
                "            true,",
            )
        ],
        False,
    ),
    (
        "nothing may be dispatched after revocation",
        [
            (
                ACP_CLUSTER,
                "            evidence.revocation_dispatched_after == 0,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "a withdrawn turn must never acquire a stop reason",
        [
            (
                ACP_CLUSTER,
                "            evidence.revocation_no_stop_reason,",
                "            true,",
            )
        ],
        False,
    ),
    # ------------------------------------------- explicit interruptions
    (
        "an interruption must be explicit, and a fabricated stopReason must fail",
        [
            (
                ACP_CLUSTER,
                """        if !interrupted {
            return Err(HarnessError::Process(format!(
                "ACP cluster gate failed: {label} did not produce an explicit interruption"
            )));
        }""",
                "        let _ = interrupted;",
            )
        ],
        False,
    ),
    (
        "a stopReason for a turn that never finished must fail the run",
        [
            (
                ACP_CLUSTER,
                """        if !no_stop_reason {
            return Err(HarnessError::Process(format!(
                "ACP cluster gate failed: {label} produced a stopReason for a turn that never finished, which is a fabricated terminal"
            )));
        }""",
                "        let _ = no_stop_reason;",
            )
        ],
        False,
    ),
    # --------------------------------------------------------- saturation
    (
        "the request direction of the peer hop must reach the enforced saturation threshold of its credit window",
        [
            (
                ACP_CLUSTER,
                "            evidence.ingress_request_direction_saturated,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the owner-to-device segment must have carried measured load",
        [
            (
                ACP_CLUSTER,
                "            evidence.owner_device_queue_limit > 0 && evidence.owner_device_queue_high_water > 0,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "a live stream must still be served while another is parked and stalling",
        [
            (
                ACP_CLUSTER,
                "            evidence.live_stream_served_while_parked && evidence.live_probe_status == 202,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the saturating upload must have completed, read off the wire",
        [
            (
                ACP_CLUSTER,
                '            evidence.saturating_upload_stop_reason == "end_turn",',
                "            true,",
            )
        ],
        False,
    ),
    (
        "admission must actually be attempted after revocation",
        [
            (
                ACP_CLUSTER,
                "            evidence.revocation_dispatch_attempts >= 2,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the request after revocation must meet the revocation's own typed refusal",
        [
            (
                ACP_CLUSTER,
                """            evidence.revocation_after_status == 404
                && evidence.revocation_after_code == "SERVICE_NOT_FOUND"
                && evidence.revocation_after_execution == "not_dispatched",""",
                "            true,",
            )
        ],
        False,
    ),
    (
        "a prompt on the revoked principal's own session must be refused",
        [
            (
                ACP_CLUSTER,
                "            evidence.revocation_after_prompt_status == 404,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "a message repeated under an id already seen must fail the run",
        [
            (
                ACP_CLUSTER,
                "                span.distinct_agent_ids >= 1 && span.identified_messages == span.distinct_agent_ids,",
                "                true,",
            )
        ],
        False,
    ),
    # ------------------------------------------------------------ hygiene
    (
        "an agent process outliving the gate must fail the run",
        [
            (
                ACP_CLUSTER,
                "    if evidence.leftover_processes != 0 {",
                "    if false {",
            )
        ],
        False,
    ),
    (
        "a case that did not execute must name itself",
        [
            (
                ACP_CLUSTER,
                '        ("every case executed", executed == CLUSTER_CASES.to_vec()),',
                '        ("every case executed", true),',
            )
        ],
        False,
    ),
    # ------------------------------------------- peer-key rotation (M8-C16)
    (
        "the staged key overlap must have reached every relay's verifier",
        [
            (
                ACP_CLUSTER,
                "            evidence.key_overlap_staged,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the withdrawn key must have left the ingress relay's own verifier",
        [
            (
                ACP_CLUSTER,
                "            evidence.key_left_ingress_verifier,\n        ),\n        (",
                "            true,\n        ),\n        (",
            )
        ],
        False,
    ),
    (
        "the key arm's teardown must be attributed to the withdrawn key",
        [
            (
                ACP_CLUSTER,
                '            evidence.key_rotation_reasons == vec!["membership_revoked".to_owned()],',
                "            true,",
            )
        ],
        False,
    ),
    (
        "the same-key control arm must name the version and nothing else",
        [
            (
                ACP_CLUSTER,
                '            evidence.version_bump_reasons == vec!["membership_changed".to_owned()],',
                "            true,",
            )
        ],
        False,
    ),
    (
        "the key arm must still be an owner self-revocation, as the documents assume",
        [
            (
                ACP_CLUSTER,
                """            evidence.key_rotation_owner_unready
                && evidence
                    .key_rotation_owner_reasons
                    .iter()
                    .any(|reason| reason == "membership_revoked"),""",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the control arm must leave the owner ready, or it controls for nothing",
        [
            (
                ACP_CLUSTER,
                "            !evidence.version_bump_owner_unready && evidence.version_bump_owner_reasons.is_empty(),",
                "            true,",
            )
        ],
        False,
    ),
    (
        "a key rotation must produce an explicit interruption",
        [
            (
                ACP_CLUSTER,
                """            "peer-key rotation",
            evidence.key_rotation_interrupted,""",
                """            "peer-key rotation",
            true,""",
            )
        ],
        False,
    ),
    (
        "a key rotation must never fabricate a stopReason",
        [
            (
                ACP_CLUSTER,
                """            evidence.key_rotation_no_stop_reason,
        ),
        (
            "owner loss",""",
                """            true,
        ),
        (
            "owner loss",""",
            )
        ],
        False,
    ),
    # -------------------------------- the recorded saturation impossibility
    (
        "both directions of the owner-to-device segment must be loaded at one instant",
        [
            (
                ACP_CLUSTER,
                """            evidence.owner_device_request_bytes_at_instant > 0
                && evidence.owner_device_response_bytes_at_instant > 0,""",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the segment must have been sampled while the upload was in flight",
        [
            (
                ACP_CLUSTER,
                "            evidence.owner_device_loaded_samples >= MIN_LOADED_SAMPLES,",
                "            true,",
            )
        ],
        False,
    ),
    # ------------------------------- the peer hop's coincident pair (M8-C22)
    (
        "the peer hop's live publication must have been read with the hop open",
        [
            (
                ACP_CLUSTER,
                "            evidence.peer_hop_live_samples >= MIN_PEER_HOP_SAMPLES,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the peer hop's request direction must reach the saturation threshold on the LIVE publication",
        [
            (
                ACP_CLUSTER,
                "            evidence.peer_hop_live_send_percent >= SATURATION_THRESHOLD_PERCENT,",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the peer hop's two directions must be disclosed as never loaded together",
        [
            (
                ACP_CLUSTER,
                """            !evidence.peer_hop_both_directions_saturated
                && evidence.peer_hop_coincident_percent < COINCIDENT_DISCLOSURE_CEILING_PERCENT,""",
                "            true,",
            )
        ],
        False,
    ),
    (
        "the rotation disclosure must carry this run's own measurement",
        [
            (
                ACP_CLUSTER,
                """            evidence.not_covered.len() == NOT_COVERED.len() + 1
                && evidence.not_covered.iter().any(|text| {
                    text.contains(&format!(
                        "across {} completed rotations in {} ms",
                        evidence.rotations_across_span, evidence.rotation_span_ms
                    ))
                }),""",
                "            true,",
            )
        ],
        False,
    ),
]


# --------------------------------------------------------------- M8 chunk 7
#
# The **parent-death sentinel** on the ACP path (task row M8-C07's trigger
# half), witnessed by `crates/tunnel-acp-fixture/tests/process_residue.rs`.
#
# Every case here is defeated in a crate whose binary the tests `exec` — the
# sentinel itself, or the fixture that hosts the probe — so this suite carries
# the mandatory `build` step M3-19 exists for.  Without it the deleted code is
# never rebuilt and a defeated guard reports `still green`.
#
# **One guard deliberately has no case here: the sentinel not widening the
# group kill's reach.**  There is nothing to delete that would close the reach,
# because no code in this repository closes it; the escaping-descendant test
# records a survival, and a deletion harness measures guards that hold a rule,
# not the absence of a mechanism.  M8-C07 and M3-09 carry the reach hole
# instead, and this comment exists so its absence is not read as an oversight.

DEADMAN = REPO / "crates" / "tunnel-deadman"
DEADMAN_LIB = DEADMAN / "src" / "lib.rs"
FIXTURE_LIB = FIXTURE / "src" / "lib.rs"

C7_CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-acp-fixture",
    "--test",
    "process_residue",
    "--locked",
    "--no-fail-fast",
]

#: Rebuilt before every case: the sentinel the supervisor spawns, and the
#: fixture binary that is both the `supervise` probe and its wrapper.  See
#: `Suite.build`.
C7_BUILD = [
    "cargo",
    "build",
    "--locked",
    "-p",
    "tunnel-deadman",
    "-p",
    "tunnel-acp-fixture",
    "--bins",
]

C7_CASES: list[tuple[str, list[Edit], bool]] = [
    (
        # Arming at all.  Without this the ACP export supervises children
        # exactly as it did before this chunk, and every group it owns
        # survives the device being SIGKILLed.  This case is the red half of
        # M8-C07's red-then-green.
        "every ACP stdio child is watched by a parent-death sentinel",
        [
            (
                CHILD,
                "    let deadman = group.and_then(tunnel_deadman::Deadman::arm);",
                "    let deadman: Option<tunnel_deadman::Deadman> = None;",
            )
        ],
        False,
    ),
    (
        # The whole mechanism, one crate down.  The sentinel still starts,
        # still watches and still exits -- and signals nothing, so the group it
        # was watching outlives the supervisor.  It is defeated in
        # `tunnel-deadman` rather than in the export precisely to exercise the
        # M3-19 rebuild: `cargo test -p tunnel-acp-fixture` builds no binary of
        # that package, so without `C7_BUILD` this case reports `still green`.
        "a bare end of file makes the sentinel kill the watched ACP process group",
        [(DEADMAN_LIB, "    kill_group(leader);\n    EXIT_FIRED", "    EXIT_FIRED")],
        False,
    ),
    (
        # The orderly path.  Dropping the handle instead of standing the
        # sentinel down still closes the pipe, but with **no token**, so the
        # sentinel reads a bare end of file and fires -- a redundant group
        # SIGKILL sent after this supervisor has already killed and reaped that
        # group, which is the one moment at which the id may genuinely have
        # been freed.  (The token-failure path `tunnel-deadman`'s module docs
        # name; it is not an argument about the stand-down's *ordering*, which
        # guards a crash window instead.)  The counter reads the sentinel's
        # exit status, so it is how a test sees "stood down" from "fired and
        # nobody noticed".
        "an orderly ACP shutdown stands the sentinel down rather than letting it fire",
        [
            (
                CHILD,
                "            if tokio::task::spawn_blocking(move || deadman.stand_down())\n                .await\n                .unwrap_or(false)\n            {\n                supervisor_counters\n                    .deadman_stood_down\n                    .fetch_add(1, Ordering::Relaxed);\n            }",
                "            drop(deadman);",
            )
        ],
        False,
    ),
    (
        # Not a product guard: a fixture guard.  If the helper the probe
        # publishes stops staying in the wrapper's process group, the two
        # SIGKILL measurements stop being about the group signal being sent and
        # become about something else -- while staying green.  Putting it in a
        # group of its own is the cheapest way to defeat that, and it must
        # redden rather than quietly weaken the pair.
        "the probe's helper is in the supervised child's group, not a group of its own",
        [
            (
                FIXTURE_LIB,
                """        let spawned = std::process::Command::new(executable)
            .arg(HELPER_MODE)
            .arg(helper_pid_file)""",
                """        let mut command = std::process::Command::new(executable);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        let spawned = command
            .arg(HELPER_MODE)
            .arg(helper_pid_file)""",
            )
        ],
        False,
    ),
    (
        # The other fixture guard, the mirror of the M3 suite's.  If the
        # descendant stops actually leaving the group, the plain group kill
        # reaches it and the reach measurement becomes a measurement of
        # nothing.  The `setsid` marker and the assertion on it are what stop
        # that.
        "an ACP descendant that failed to detach is refused, not measured",
        [
            (
                FIXTURE_LIB,
                "    let escaped = rustix::process::setsid().is_ok();",
                "    let escaped = false;",
            )
        ],
        False,
    ),
    (
        # Task row M5-C16, the ACP copy of M5-C11's `m5c8` case.  The sentinel
        # tests in `process_residue.rs` now *skip*, naming themselves, when
        # `availability()` says the helper is absent -- so an `availability()`
        # that reported it missing whatever is on disk would skip every one of
        # them and the coverage would vanish silently.  This defeats it into
        # exactly that.  `C7_BUILD` is load-bearing here rather than
        # boilerplate: with no helper beside the tests the control correctly
        # asserts `false == false` and this case would report `still green`
        # over a rule that was never exercised.  Its witness is declared in
        # `WITNESSES` below rather than owed in the debt ledger.
        "a present ACP sentinel helper cannot be reported as missing",
        [
            (
                DEADMAN_LIB,
                """    match resolution() {
        Resolution::Usable(_) => Availability::Armable,
        Resolution::Unusable(_) => Availability::SentinelUnusable,
        Resolution::Absent => Availability::SentinelMissing,
    }""",
                "    Availability::SentinelMissing",
            )
        ],
        False,
    ),
]


SUITES: list[Suite] = [
    Suite("m8c1", [CRATE], CARGO_TEST, CASES),
    Suite("m8c2", [CRATE, EXPORT, FIXTURE], C2_CARGO_TEST, C2_CASES),
    Suite("m8c3", [EXPORT, FIXTURE], C3_CARGO_TEST, C3_CASES),
    Suite("m8c3-relay", [RELAY_CRATE], C3_RELAY_TEST, C3_RELAY_CASES),
    Suite("m8c4", [CRATE, EXPORT, FIXTURE], C4_CARGO_TEST, C4_CASES),
    Suite("m8c5", [HARNESS_CRATE], C5_CARGO_TEST, C5_CASES),
    Suite("m8c7", [DEADMAN, EXPORT, FIXTURE], C7_CARGO_TEST, C7_CASES, build=C7_BUILD),
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
    if suite.build:
        # M3-19: rebuild every binary these tests will `exec`, transitively,
        # before running them.  A failure here is a build failure for the
        # case, never a red test — the same refusal the test run itself makes.
        try:
            built = subprocess.run(
                suite.build,
                cwd=suite.cwd,
                env=cargo_env(),
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            return "NOT EVIDENCE (timed out)", []
        if built.returncode != 0:
            return "BUILD FAILED", []
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


# **The `git checkout --` restore that used to live here is gone (M5-C07).**
# It was replaced by `guard_outcomes.AppliedCase`, which writes back the exact
# bytes it recorded before mutating.  Deleted rather than left unused on
# purpose: it checked out whole crate directories, so any other uncommitted
# work under them was discarded with the mutation -- the M4-32 mechanism -- and
# a dead helper spelling exactly that is an invitation to call it again.  It is
# not a rule being removed to go green: no case reaches it any more, and the
# tree-cleanliness contract it served is now held by `AppliedCase.restore` plus
# the journal that `refuse_resident_mutation` reads.


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
                    f"under {relative}; a case applied on top of them could not "
                    "be told apart from them, and the run would report a guard "
                    "as load-bearing on the strength of somebody else's edit. "
                    "Each case is restored by writing back the exact bytes it "
                    "recorded (M5-C07), so these changes would survive a run -- "
                    "but the evidence would not be trustworthy."
                )




#: The test(s) each case's deleted guard must make redden, keyed by
#: `(suite, case)`.
#:
#: **Measured, not read off the case text (task row M4-42).**  Every entry
#: below was taken from a run of this harness in which the case's guard was
#: deleted: of the tests that reddened, the entry names those whose path names
#: the mutated file's module (its stem as a `::` segment, or as the test
#: binary), and every reddened test when none does.  Suites m8c1, m8c2, m8c3, m8c3-relay, m8c4, m8c5 and m8c7 were
#: measured by run `acpdisc-9e2b` and then re-run in full with these entries in
#: force by run `acpver-5a70`, in which every case was classified plain `RED` --
#: its witness reddened again -- and none `RED (wrong witness)`.  A case whose
#: entry is wrong fails the next run closed, which is the point: an entry is a
#: claim the harness re-checks every time, not a label.
#:
#: A case not listed here is still owed a witness and is named in
#: `scripts/guard_witness_debt.json`; the ledger can only shrink, and a case may
#: not appear in both.
#:
#: **One entry predates M4-42's sweep and is not a moved debt (task row
#: M5-C16).**  `[m8c7] a present ACP sentinel helper cannot be reported as
#: missing` was added with its witness declared from the start, so it never
#: entered the ledger; its witness was measured red from this harness.
WITNESSES: dict[tuple[str, str], frozenset[str]] = {
    ('m8c1', 'a GET and a DELETE must name their connection'): frozenset({'message::tests::a_delete_must_name_its_connection', 'message::tests::a_get_must_accept_the_event_stream_and_name_its_connection'}),
    ('m8c1', 'a GET must accept text/event-stream'): frozenset({'message::tests::a_get_must_accept_the_event_stream_and_name_its_connection'}),
    ('m8c1', 'a POST must be application/json'): frozenset({'message::tests::a_post_must_be_application_json', 'message::tests::a_rejection_body_carries_no_consumer_data'}),
    ('m8c1', 'a batch is refused before anything else looks at the body'): frozenset({'message::tests::a_batch_is_refused_as_a_batch_with_501_and_its_own_code', 'message::tests::a_malformed_batch_is_still_refused_for_being_a_batch', 'message::tests::the_three_headline_refusals_have_three_distinct_answers'}),
    ('m8c1', 'a lone leading surrogate escape is refused, never repaired'): frozenset({'json::tests::the_scanner_refuses_a_lone_surrogate_and_accepts_a_pair'}),
    ('m8c1', 'a protocol version that is not 1 is refused'): frozenset({'message::tests::an_initialize_negotiates_its_version_in_both_directions', 'message::tests::protocol_version_2_is_refused_by_its_own_rule_with_its_own_code', 'message::tests::the_three_headline_refusals_have_three_distinct_answers'}),
    ('m8c1', 'a session-scoped method requires the session header'): frozenset({'message::tests::a_session_scoped_post_needs_both_headers_and_a_body_that_agrees'}),
    ('m8c1', 'a stop reason outside the pinned vocabulary is refused'): frozenset({'message::tests::a_v2_prompt_acknowledgement_is_never_read_as_a_v1_turn_completion'}),
    ('m8c1', 'a v2 prompt acknowledgement is not a v1 turn completion'): frozenset({'message::tests::a_v2_prompt_acknowledgement_is_never_read_as_a_v1_turn_completion'}),
    ('m8c1', 'an id must be a string or an integer'): frozenset({'message::tests::an_id_must_be_a_string_or_an_integer'}),
    ('m8c1', 'an initialize must carry a protocolVersion'): frozenset({'message::tests::an_initialize_negotiates_its_version_in_both_directions'}),
    ('m8c1', 'an unaccepted method is refused before dispatch'): frozenset({'message::tests::an_unaccepted_method_is_refused_before_anything_is_dispatched'}),
    ('m8c1', 'duplicate member names, compared after unescaping'): frozenset({'json::tests::the_scanner_refuses_duplicate_names_trailing_data_and_deep_nesting'}),
    ('m8c1', 'every other POST must name its connection'): frozenset({'message::tests::initialize_opens_a_connection_and_every_other_post_names_one'}),
    ('m8c1', 'every pinned request header is a singleton'): frozenset({'tests::every_pinned_request_header_rejects_a_repeat', 'tests::the_principal_binding_is_request_only_and_a_singleton'}),
    ('m8c1', 'initialize must not present a connection header'): frozenset({'message::tests::initialize_opens_a_connection_and_every_other_post_names_one'}),
    ('m8c1', 'no response may carry acp-session-id'): frozenset({'tests::neighbouring_header_spellings_are_refused_in_both_directions', 'tests::the_session_header_refusal_is_a_disclosed_divergence_from_the_pinned_sdk'}),
    ('m8c1', 'only POST, GET and DELETE are routed'): frozenset({'tests::exactly_post_get_and_delete_are_routed_at_the_single_endpoint', 'tests::only_http_2_is_accepted_and_http_1_1_is_an_unsupported_feature'}),
    ('m8c1', 'params must be an object'): frozenset({'message::tests::params_must_be_an_object'}),
    ('m8c1', 'raw control characters inside a JSON string'): frozenset({'json::tests::the_scanner_refuses_a_raw_control_character_in_a_string'}),
    ('m8c1', "the RFD's request_permission shorthand is not an accepted method"): frozenset({'message::tests::an_unaccepted_method_is_refused_before_anything_is_dispatched', 'tests::the_method_set_is_exact_and_comes_from_the_pinned_schema', 'tests::the_rfd_shorthand_resolves_but_is_not_itself_an_accepted_method'}),
    ('m8c1', 'the jsonrpc member must be exactly "2.0"'): frozenset({'message::tests::the_jsonrpc_member_must_be_exactly_2_0'}),
    ('m8c1', 'the manifest requires the exact version'): frozenset({'the_manifest_requires_the_exact_versions_with_no_default_features'}),
    ('m8c1', 'the nesting depth bound'): frozenset({'json::tests::the_scanner_refuses_duplicate_names_trailing_data_and_deep_nesting'}),
    ('m8c1', 'the profile accepts HTTP/2 only'): frozenset({'tests::only_http_2_is_accepted_and_http_1_1_is_an_unsupported_feature'}),
    ('m8c1', "the recorded checksum is the lockfile's"): frozenset({'each_pinned_crate_is_in_the_lockfile_exactly_once_at_its_recorded_checksum'}),
    ('m8c1', 'the session header and params.sessionId must agree'): frozenset({'message::tests::a_session_scoped_post_needs_both_headers_and_a_body_that_agrees'}),
    ('m8c1', 'the shorthand resolves against the normative v1 name'): frozenset({'tests::the_rfd_shorthand_resolves_but_is_not_itself_an_accepted_method'}),
    ('m8c1', 'the top level classifies `[` as an array'): frozenset({'json::tests::the_top_level_is_classified_from_the_first_non_whitespace_byte'}),
    ('m8c1', 'trailing data after the top-level value'): frozenset({'json::tests::the_scanner_refuses_duplicate_names_trailing_data_and_deep_nesting'}),
    ('m8c1', 'unstable_mcp_over_acp stays off'): frozenset({'no_workspace_manifest_enables_a_refused_draft_feature', 'pin::tests::mcp_over_acp_is_not_enabled_in_this_build', 'the_manifest_requires_the_exact_versions_with_no_default_features'}),
    ('m8c2', 'a JSON-RPC id is scoped by its direction'): frozenset({'tests::the_id_scope_carries_the_direction', 'the_agent_callback_bound_is_exact_at_sixteen_against_a_real_child', 'the_reader_handles_a_callback_while_a_prompt_is_pending'}),
    ('m8c2', 'a callback resolves exactly once'): frozenset({'lifecycle::tests::a_callback_resolves_exactly_once_and_a_late_response_cannot_repeat_it', 'lifecycle::tests::a_permission_response_must_name_an_option_the_agent_offered', 'lifecycle::tests::a_string_id_and_a_number_id_are_not_the_same_request', 'lifecycle::tests::an_id_reused_after_completion_is_accepted', 'lifecycle::tests::session_cancel_cancels_that_sessions_permissions_only', 'lifecycle::tests::the_pending_bound_is_exact_at_sixteen_per_direction'}),
    ('m8c2', 'a child that vanished while admitting work failed, it did not stop'): frozenset({'lifecycle::tests::the_child_lifecycle_is_a_transition_table_not_a_label'}),
    ('m8c2', 'a duplicate pending id conflicts before dispatch'): frozenset({'lifecycle::tests::a_duplicate_pending_id_conflicts_before_dispatch'}),
    ('m8c2', 'a new session has no subscriber until one arrives'): frozenset({'lifecycle::tests::a_prompt_before_the_subscriber_is_refused_for_readiness_not_for_the_bound'}),
    ('m8c2', 'a permission deadline cancels, and never approves'): frozenset({'lifecycle::tests::a_permission_deadline_resolves_as_cancelled_never_approved'}),
    ('m8c2', 'a refused stdout line is counted'): frozenset({'a_batch_line_from_the_child_is_refused_for_being_a_batch', 'a_malformed_stdout_line_kills_the_child_for_being_malformed', 'the_sse_stream_never_carries_a_batch_and_the_refusal_ends_the_transport'}),
    ('m8c2', 'a response must answer the kind of request outstanding'): frozenset({'lifecycle::tests::a_permission_answer_cannot_resolve_a_prompt'}),
    ('m8c2', 'a second concurrent prompt on one session is refused'): frozenset({'lifecycle::tests::one_active_prompt_per_session'}),
    ('m8c2', 'a stderr flood is counted'): frozenset({'a_stderr_flood_is_drained_and_counted_without_blocking_child_exit'}),
    ('m8c2', 'a supervisor that is dropped rather than drained ends its child'): frozenset({'a_supervisor_dropped_without_draining_still_kills_the_group'}),
    ('m8c2', 'an oversized line is refused before it is reassembled'): frozenset({'an_oversized_stdout_line_kills_the_child_rather_than_being_reassembled'}),
    ('m8c2', 'draining closes every session'): frozenset({'lifecycle::tests::draining_stops_admission_and_closes_every_session'}),
    ('m8c2', 'draining stops admission'): frozenset({'lifecycle::tests::draining_stops_admission_and_closes_every_session', 'lifecycle::tests::the_child_lifecycle_is_a_transition_table_not_a_label'}),
    ('m8c2', "every end of a child's life signals its process group"): frozenset({'a_descendant_that_calls_setsid_survives_the_process_group_kill', 'a_grandchild_dies_when_the_child_exits_by_itself', 'a_malformed_stdout_line_kills_the_child_for_being_malformed', 'a_prompt_runs_a_turn_and_the_lifecycle_drives_it', 'a_setsid_descendant_escapes_even_with_the_sentinel_armed', 'a_wrapper_grandchild_dies_with_the_process_group', 'an_oversized_stdout_line_kills_the_child_rather_than_being_reassembled'}),
    ('m8c2', 'the cancellation reaches the agent on the wire'): frozenset({'a_permission_timeout_resolves_as_cancelled_never_approved'}),
    ('m8c2', 'the deadline must be exceeded, not merely reached'): frozenset({'lifecycle::tests::a_permission_deadline_resolves_as_cancelled_never_approved'}),
    ('m8c2', 'the deadline ticker ends when the child does'): frozenset({'nothing_holds_the_child_handle_once_the_child_is_gone'}),
    ('m8c2', 'the pending bound is reached at the bound, not one past it'): frozenset({'lifecycle::tests::the_pending_bound_is_exact_at_sixteen_per_direction'}),
    ('m8c2', 'the session bound is reached at the bound, not one past it'): frozenset({'lifecycle::tests::the_session_bound_is_exact_at_eight_per_connection'}),
    ('m8c2', 'the stderr sink reports passing its cap'): frozenset({'a_stderr_flood_is_drained_and_counted_without_blocking_child_exit'}),
    ('m8c3', 'a 202 is followed by the result on the stream (prompt)'): frozenset({'a_prompt_before_its_session_subscriber_is_refused_and_nothing_is_dispatched', 'the_acp_export_serves_a_whole_conversation_with_nothing_listening', 'the_export_classifies_its_terminals_through_the_terminal_rule', 'the_pinned_client_completes_a_v1_conversation_with_a_permission_callback', 'the_pinned_clients_own_delete_ends_the_child'}),
    ('m8c3', 'a 202 is followed by the result on the stream (session/new)'): frozenset({'a_lost_established_connection_stream_terminates_the_whole_transport', 'a_lost_established_session_stream_terminates_the_whole_transport', 'a_prompt_before_its_session_subscriber_is_refused_and_nothing_is_dispatched', 'a_second_connection_subscriber_is_refused_409_and_the_first_keeps_the_stream', 'a_second_session_subscriber_is_refused_409', 'a_session_header_that_disagrees_with_the_body_is_refused_with_400', 'a_session_scoped_stream_answers_with_no_session_header', 'a_session_whose_subscriber_never_arrives_closes_its_window', 'an_expired_session_window_is_counted_once_not_once_per_watchdog_tick', 'every_sse_event_is_exactly_data_space_message_newline_newline', 'output_credit_stalls_are_bounded_and_the_event_is_never_skipped', 'the_acp_export_serves_a_whole_conversation_with_nothing_listening', 'the_export_classifies_its_terminals_through_the_terminal_rule', 'the_pinned_client_completes_a_v1_conversation_with_a_permission_callback', 'the_pinned_clients_own_delete_ends_the_child', 'the_sse_stream_never_carries_a_batch_and_the_refusal_ends_the_transport'}),
    ('m8c3', 'a broken stream errors its body rather than ending cleanly'): frozenset({'a_lost_established_connection_stream_terminates_the_whole_transport', 'a_lost_established_session_stream_terminates_the_whole_transport', 'the_sse_stream_never_carries_a_batch_and_the_refusal_ends_the_transport'}),
    ('m8c3', 'a child that is gone ends its transport'): frozenset({'the_sse_stream_never_carries_a_batch_and_the_refusal_ends_the_transport'}),
    ('m8c3', 'a connection that ends takes its child with it'): frozenset({'a_connection_whose_subscriber_never_arrives_is_ended_after_its_measured_deadline', 'a_lost_established_connection_stream_terminates_the_whole_transport', 'delete_answers_202_and_the_child_is_gone_from_the_process_table', 'the_pinned_clients_own_delete_ends_the_child'}),
    ('m8c3', 'a second subscriber on one stream is refused'): frozenset({'a_second_connection_subscriber_is_refused_409_and_the_first_keeps_the_stream', 'a_second_session_subscriber_is_refused_409', 'a_session_whose_subscriber_never_arrives_closes_its_window', 'an_expired_session_window_is_counted_once_not_once_per_watchdog_tick'}),
    ('m8c3', 'a session admits its prompt only once its subscriber arrived'): frozenset({'a_lost_established_session_stream_terminates_the_whole_transport', 'a_prompt_before_its_session_subscriber_is_refused_and_nothing_is_dispatched', 'output_credit_stalls_are_bounded_and_the_event_is_never_skipped', 'the_acp_export_serves_a_whole_conversation_with_nothing_listening', 'the_export_classifies_its_terminals_through_the_terminal_rule', 'the_pinned_client_completes_a_v1_conversation_with_a_permission_callback', 'the_pinned_clients_own_delete_ends_the_child', 'the_sse_stream_never_carries_a_batch_and_the_refusal_ends_the_transport'}),
    ('m8c3', 'a session subscription that never arrives expires'): frozenset({'a_session_whose_subscriber_never_arrives_closes_its_window', 'an_expired_session_window_is_counted_once_not_once_per_watchdog_tick'}),
    ('m8c3', "a session-scoped message goes to its own session's stream"): frozenset({'a_lost_established_session_stream_terminates_the_whole_transport', 'output_credit_stalls_are_bounded_and_the_event_is_never_skipped', 'the_pinned_client_completes_a_v1_conversation_with_a_permission_callback'}),
    ('m8c3', 'a subscription that never arrives expires'): frozenset({'a_connection_whose_subscriber_never_arrives_is_ended_after_its_measured_deadline', 'the_documented_ten_second_deadline_is_the_one_that_elapses'}),
    ('m8c3', 'an SSE event begins with `data: `'): frozenset({'sse::tests::one_message_is_one_data_line_and_a_blank_line'}),
    ('m8c3', 'an SSE event ends with a blank line, not one newline'): frozenset({'sse::tests::one_message_is_one_data_line_and_a_blank_line'}),
    ('m8c3', 'an expired session window is counted once, not once per watchdog tick'): frozenset({'an_expired_session_window_is_counted_once_not_once_per_watchdog_tick'}),
    ('m8c3', "an expired session's window stays closed"): frozenset({'a_session_whose_subscriber_never_arrives_closes_its_window', 'an_expired_session_window_is_counted_once_not_once_per_watchdog_tick'}),
    ('m8c3', 'no response carries acp-session-id (M8-C05)'): frozenset({'sse::tests::an_sse_response_never_carries_the_session_header'}),
    ('m8c3', 'the ACP export opens no listener of its own'): frozenset({'the_acp_export_serves_a_whole_conversation_with_nothing_listening'}),
    ('m8c3', 'the host cannot choose a workspace or attach MCP servers'): frozenset({'a_host_cannot_choose_a_workspace_or_attach_mcp_servers'}),
    ('m8c3-relay', 'and admits nothing else'): frozenset({'config::tests::http_forward_profiles_are_pinned_configured_and_otherwise_absent'}),
    ('m8c3-relay', "the relay's profile allowlist admits the ACP profile"): frozenset({'config::tests::http_forward_profiles_are_pinned_configured_and_otherwise_absent'}),
    ('m8c4', 'a confirmed cancelled turn is cancelled'): frozenset({'terminal::tests::a_confirmed_cancelled_turn_is_cancelled_and_a_lost_process_is_not'}),
    ('m8c4', 'a lost process after dispatch is outcome_unknown, not a success'): frozenset({'terminal::tests::a_confirmed_cancelled_turn_is_cancelled_and_a_lost_process_is_not', 'terminal::tests::a_refusal_before_dispatch_is_failed_and_not_unknown'}),
    ('m8c4', 'a permission response must name an offered option (M8-C11)'): frozenset({'lifecycle::tests::a_permission_response_must_name_an_option_the_agent_offered', 'lifecycle::tests::an_agent_that_offered_nothing_admits_no_selection'}),
    ('m8c4', 'a prompt whose child died is classified outcome_unknown by the export'): frozenset({'the_export_classifies_its_terminals_through_the_terminal_rule'}),
    ('m8c4', 'an established required stream that broke is noticed by the watchdog'): frozenset({'a_lost_established_connection_stream_terminates_the_whole_transport', 'a_lost_established_session_stream_terminates_the_whole_transport'}),
    ('m8c4', 'an output-credit stall is bounded'): frozenset({'output_credit_stalls_are_bounded_and_the_event_is_never_skipped'}),
    ('m8c4', 'an unoffered option does not consume the outstanding callback'): frozenset({'lifecycle::tests::a_permission_response_must_name_an_option_the_agent_offered'}),
    ('m8c4', 'one principal cannot fill the table and deny the rest'): frozenset({'bridge::capacity_tests::both_caps_are_exact_at_the_boundary_and_refuse_one_beyond', 'bridge::capacity_tests::one_principal_cannot_fill_the_table_and_deny_the_rest'}),
    ('m8c4', 'subscriber loss resolves pending permissions as cancelled'): frozenset({'a_lost_established_session_stream_terminates_the_whole_transport'}),
    ('m8c4', 'the export classifies a completed turn through the terminal rule'): frozenset({'the_export_classifies_its_terminals_through_the_terminal_rule'}),
    ('m8c4', 'the export refuses a connection beyond its global cap'): frozenset({'bridge::capacity_tests::a_full_table_has_no_admitting_input', 'bridge::capacity_tests::both_caps_are_exact_at_the_boundary_and_refuse_one_beyond'}),
    ('m8c4', "the live body's sender is parked so a quiet connection still notices"): frozenset({'a_lost_established_connection_stream_terminates_the_whole_transport', 'a_lost_established_session_stream_terminates_the_whole_transport'}),
    ('m8c4', 'the supervisor records the options the agent offered'): frozenset({'the_reader_handles_a_callback_while_a_prompt_is_pending'}),
    ('m8c5', 'a case that did not execute must name itself'): frozenset({'production_cluster::acp_cluster::tests::a_case_that_did_not_run_is_named_rather_than_counted', 'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a cross-tenant foreign id must be refused byte-identically'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a key rotation must never fabricate a stopReason'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a key rotation must produce an explicit interruption'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a live connection id must be inert in the other tenant'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a live stream must still be served while another is parked and stalling'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a message repeated under an id already seen must fail the run'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a permission callback arriving twice across the window is a duplicate'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "a prompt on the revoked principal's own session must be refused"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a same-tenant foreign id must be refused byte-identically'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a stopReason for a turn that never finished must fail the run'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a window shorter than the schedule counted recovery, not rotations'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'a withdrawn turn must never acquire a stop reason'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'admission must actually be attempted after revocation'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'an agent process outliving the gate must fail the run'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'an interruption must be explicit, and a fabricated stopReason must fail'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'an uncorrelated rotation-freeze refusal must fail the run (M3-15)'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'at most one candidate data socket'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'both directions of the owner-to-device segment must be loaded at one instant'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "each held turn's side effect is recorded exactly once and never replayed"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "every case must end inside the membership records' lifetime"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'every forged head must be refused before dispatch'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'every reply must be routed to the principal that asked'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'every rotation round must move the device to one new data socket'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'not one forged head may reach the device'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'nothing may be dispatched after revocation'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'revocation must withdraw the admitted exchange'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the control arm must leave the owner ready, or it controls for nothing'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the held turn must complete end_turn, read off the wire'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the key arm must still be an owner self-revocation, as the documents assume'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the key arm's teardown must be attributed to the withdrawn key"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the owner must have counted the rotations independently'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the owner-to-device segment must have carried measured load'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the peer hop's live publication must have been read with the hop open"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the peer hop's request direction must reach the saturation threshold on the LIVE publication"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the peer hop's two directions must be disclosed as never loaded together"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the probes must not have opened anything on the other tenant's export"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the refusal must be the profile's not-found, not some other error"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the request after revocation must meet the revocation's own typed refusal"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the request direction of the peer hop must reach the enforced saturation threshold of its credit window'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the rotation disclosure must carry this run's own measurement"): frozenset({'production_cluster::acp_cluster::tests::the_rotation_disclosure_carries_the_run_it_describes'}),
    ('m8c5', 'the rotation window must finish inside one membership record'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the same-key control arm must name the version and nothing else'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the saturating upload must have completed, read off the wire'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the segment must have been sampled while the upload was in flight'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the staged key overlap must have reached every relay's verifier"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the two tenants must really have reused one session id'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'the withdrawn exchange must be classified execution: unknown'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', "the withdrawn key must have left the ingress relay's own verifier"): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'these must be rotations rather than a reconnect'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'three completed rotations are required, not recorded'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c5', 'two device sockets at every settled steady state'): frozenset({'production_cluster::acp_cluster::tests::every_claim_can_fail_on_its_own'}),
    ('m8c7', 'a bare end of file makes the sentinel kill the watched ACP process group'): frozenset({'a_sigkilled_supervisor_still_kills_the_group'}),
    ('m8c7', 'an ACP descendant that failed to detach is refused, not measured'): frozenset({'a_setsid_descendant_escapes_even_with_the_sentinel_armed'}),
    ('m8c7', 'an orderly ACP shutdown stands the sentinel down rather than letting it fire'): frozenset({'an_orderly_shutdown_stands_the_sentinel_down_instead_of_firing_it'}),
    ('m8c7', 'every ACP stdio child is watched by a parent-death sentinel'): frozenset({'a_setsid_descendant_escapes_even_with_the_sentinel_armed', 'a_sigkilled_supervisor_still_kills_the_group', 'an_orderly_shutdown_stands_the_sentinel_down_instead_of_firing_it'}),
    ('m8c7', "the probe's helper is in the supervised child's group, not a group of its own"): frozenset({'a_sigkilled_supervisor_still_kills_the_group', 'an_orderly_shutdown_stands_the_sentinel_down_instead_of_firing_it', 'the_group_kill_reaches_an_in_group_helper', 'without_a_sentinel_a_sigkilled_supervisor_leaks_its_childs_group'}),
    ("m8c7", "a present ACP sentinel helper cannot be reported as missing"): frozenset(
        {"the_skip_cannot_hide_a_helper_that_is_on_disk"}
    ),
}

#: The pinned ledger, loaded once.
DEBT = load_witness_debt('acp-guard-deletion')



def require_witnesses(selected) -> None:
    """Refuse a value case that neither names a witness nor owes one.

    **The half that makes M4-23's fix hold.**  Without it the mechanism is
    opt-in: a case added with no entry in `WITNESSES` would fall back silently
    to "any red will do", which is the behaviour the mechanism exists to
    reject.  With it, a new case must either declare the test its guard owns
    or be added to `scripts/guard_witness_debt.json` by hand -- and the ledger
    is asserted never to grow, so the second route is not a route.
    """
    require_declared_witnesses(
        "acp-guard-deletion",
        (
            (
                suite.name,
                name,
                expect_build_failure,
                WITNESSES.get((suite.name, name), frozenset()),
            )
            for suite, name, edits, expect_build_failure in selected
            if name not in EXPECT_GREEN
        ),
        DEBT,
    )


def _anchor_selection(selected):
    """Every selected case reduced to `(suite, case, edits)`.

    Shared by the preflight and by the read-only `--check-anchors` entry, so
    the two cannot drift into checking different sets -- which is the class of
    mistake M4-36 is about.
    """
    return [(suite.name, name, edits) for suite, name, edits, _ in selected]


def check_anchors(selected: list[tuple[Suite, str, list[Edit], bool]]) -> int:
    """Resolve every selected case's guard text, and stop (M4-27).

    The resolution, the STALLED/AMBIGUOUS split and the empty-selection
    refusal all live in `scripts/guard_outcomes.py`, shared with the other
    three harnesses; this only drops the per-case `expect_build_failure` flag,
    which an anchor check has no use for.
    """
    return shared_check_anchors(
        "acp-guard-deletion",
        _anchor_selection(selected),
    )


def main() -> int:
    # M5-C07: make `SIGTERM`/`SIGHUP` raise, so the per-case `AppliedCase`
    # context manager restores on the way out instead of being skipped.
    install_interrupt_restore()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print case names and exit")
    parser.add_argument(
        "--check-anchors",
        action="store_true",
        help=(
            "check every case's guard text without building anything, and exit "
            "non-zero if any anchor is missing or ambiguous"
        ),
    )
    parser.add_argument("--case", help="run only cases whose name contains this text")
    parser.add_argument(
        "--suite",
        help="run only this suite (m8c1, m8c2, m8c3, m8c3-relay, m8c4, m8c5, m8c7)",
    )
    arguments = parser.parse_args()

    # **M4-36, and this is the load-bearing line.**  Write capability is
    # dropped here, on the strength of the flag alone, *before* any dispatch.
    # The read-only entry below still wraps its own barrier, but that one only
    # covers code reached through it -- and the bypass this guards against is
    # a dispatch that is never reached: nested under the preceding `if
    # arguments.list:` block it is present, correctly ordered and unreachable,
    # and `main()` falls through to the deletion loop. Taking the capability
    # away up here makes the destructive path the one that never had it
    # removed, so a lost dispatch raises on its first mutation instead of
    # deleting guards for hours and exiting 0.
    if arguments.check_anchors:
        forbid_writes_for_this_process()

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
    if arguments.check_anchors:
        # **M4-36.**  Read-only mode is a path without write capability,
        # not a branch in `main()`.  `read_only_entry` resolves the
        # anchors inside a scope in which `Path.write_text`, a writing
        # `Path.open`, `Path.unlink`, `os.replace` and `subprocess.run`
        # all raise, so a deletion loop that becomes reachable from here
        # raises on its first mutation and names itself instead of
        # running the destructive suite to completion and exiting 0.
        return read_only_entry(
            'acp-guard-deletion',
            _anchor_selection(selected),
        )
    if not selected:
        sys.exit(f"acp-guard-deletion: no case matches {arguments.case!r}")

    # **M5-C07, before anything is edited.**  `require_clean_tree`
    # below refuses on a dirty tree, which already stops a second run
    # stacking on a resident mutation -- but it can only say
    # "something is uncommitted", about a tree the operator may
    # believe they dirtied themselves.  This names the harness, suite,
    # case and files a previous interrupted run left mutated, because
    # a resident mutation is a guard deleted from the product and not
    # a tidying job.  Placed *after* the `--check-anchors` dispatch so
    # read-only mode stays a pure anchor check (M4-34, M4-36).
    # **M4-26, before anything else.**  Git writes `index.lock` and renames
    # it over `index`, so a process killed in that window loses the index --
    # and with no index every check that would notice a resident mutation
    # reports clean: `git status --porcelain` calls tracked files untracked,
    # and `git diff -- crates/` compares against nothing. This refuses rather
    # than running blind.
    require_git_index("acp-guard-deletion", REPO)
    refuse_resident_mutation("acp-guard-deletion", REPO)
    require_witnesses(selected)
    require_clean_tree(suites)

    # **Preflight (M4-27).**  Resolve every selected case's anchors before any
    # case executes, and fail closed listing *all* mismatches at once.  The
    # per-case refusal in the loop below already fails the run and names
    # itself, so this changes no outcome and no count -- it moves an existing
    # refusal from the end of a multi-hour run to its first second.
    if check_anchors(selected) != 0:
        return 1

    results: list[tuple[str, str, str, list[str]]] = []
    for suite, name, edits, expect_build_failure in selected:
        # **M5-C07.**  The apply/test/restore cycle runs inside a context
        # manager, so the restore happens on *every* way out of this block --
        # a refusal, an exception, a `KeyboardInterrupt`, or the `SystemExit`
        # that `install_interrupt_restore` turns a `SIGTERM` into.  It
        # restores the exact recorded original bytes rather than running `git
        # checkout --` over the crate, which would discard any other
        # uncommitted work under that path (M4-32).
        with AppliedCase("acp-guard-deletion", REPO, suite.name, name) as applied:
            problem = applied.apply_all(edits)
            if problem is not None:
                results.append((suite.name, name, f"COULD NOT APPLY: {problem}", []))
                print(f"[{suite.name}] {name}: {problem}", flush=True)
                continue
            outcome, failures = run_tests(suite)
        # **M4-23.**  One shared classification rule, so the witness check
        # cannot be present in some harnesses and absent from others -- which
        # is exactly how this defect came to be true of three of the five.
        outcome = classify_outcome(
            outcome,
            failures,
            documented_green=name in EXPECT_GREEN,
            expect_build_failure=expect_build_failure,
            expected_red=WITNESSES.get((suite.name, name), frozenset()),
            owed_witness=DEBT.owes(suite.name, name),
        )
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
    # **M4-23: the debt this run carried, said out loud.**  The defect this
    # mechanism closes left "no trace in either the output or the tally" -- a
    # corrupted outcome was byte-identical to a correct one. A case still
    # owed a witness is classified the old way, so the only thing standing
    # between that and silence is this line and the pin in
    # `scripts/test_guard_outcomes.py`. It prints on every run, including a
    # clean one, because a figure that appears only when it is bad is a
    # figure nobody learns to read.
    unattributed = sum(
        1
        for suite_name, name, outcome, _ in results
        if outcome == "RED" and DEBT.owes(suite_name, name)
    )
    attributed = sum(
        1
        for suite_name, name, outcome, _ in results
        if outcome == "RED" and not DEBT.owes(suite_name, name)
    )
    print(
        f"\nacp-guard-deletion: {attributed} red(s) were attributed to the test the "
        f"case declares; {unattributed} were credited to any failure in the "
        "suite's surface, because those cases do not yet name a witness "
        "(task row M4-23). An unattributed red is not evidence that this "
        "guard is load-bearing."
    )

    # **M4-26, again.**  The index loss that matters happens *mid-run*: a
    # check only at the start would certify an index that was gone by the
    # end, and a count from a run whose index state was not confirmed is not
    # a measurement.
    require_git_index("acp-guard-deletion", REPO)

    unusable = unusable_outcomes(
        (suite_name, name, outcome) for suite_name, name, outcome, _ in results
    )
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
