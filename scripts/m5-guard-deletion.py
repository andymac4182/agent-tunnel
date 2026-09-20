#!/usr/bin/env python3
"""Defeat one `computer.v1` guard at a time, run the tests it should protect,
and restore it.

This is the red-then-green evidence behind M5 chunks 2 and 3. Two suites live
here:

* `m5c2` — `crates/tunnel-cua` and `crates/tunnel-cua-fixture`: the
  loopback endpoint check, the read-only operation allowlist, the strict
  request scanner, the pre-dispatch validation ordering, the backend outcome
  classification (the 200-with-`success:false` trap, the absent-`success`
  rule, the pre-dispatch 400/401 shape and the 503), the three-way capability
  intersection with its probe requirement, the absent-by-default capture
  authority, and the synthetic-image marker check.
* `m5c3` -- the input half: the exclusive input lease, the capture-identity
  carry-forward with its staleness, target and bounds rules, the display-scale
  conversion, the narrower retry rule for operations that synthesise input,
  and the redaction that keeps typed text out of every diagnostic.
* `m5c4` -- supervising the backend: the parent-death sentinel and its
  stand-down, the group kill, the restart invalidation of the input lease and
  the capture identities, the non-reuse of both counters, the classification of
  an operation in flight across a restart, the probe-not-echo health rule, and
  the loopback and staleness checks the supervisor applies to the address a
  backend publishes.

  **It is the one suite here that carries a mandatory pre-build**, because its
  tests `exec` two binaries from two packages: `tunnel-cua-fixture` and
  `tunnel-deadman`. See `Suite.build` and task row M3-19. Its second case is
  defeated in `crates/tunnel-deadman`, a package `cargo test -p
  tunnel-cua-fixture` builds no binary of, so without the rebuild it would
  report `still green` for the entire mechanism.

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
LEASE = CRATE / "src" / "lease.rs"
CAPTURE = CRATE / "src" / "capture.rs"
FIXTURE_LIB = FIXTURE / "src" / "lib.rs"
FIXTURE_PROCESS = FIXTURE / "src" / "process.rs"
CLIENT = FIXTURE / "src" / "client.rs"

# Chunk 4.
EXPORT = REPO / "crates" / "tunnel-cua-export"
DEADMAN = REPO / "crates" / "tunnel-deadman"
SUPERVISION = CRATE / "src" / "supervision.rs"
EXPORT_CHILD = EXPORT / "src" / "child.rs"
EXPORT_HEALTH = EXPORT / "src" / "health.rs"
EXPORT_SUPERVISOR = EXPORT / "src" / "supervisor.rs"
DEADMAN_LIB = DEADMAN / "src" / "lib.rs"

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
        # **This case's subject changed under it, and the case was re-pointed
        # rather than deleted.** It used to delete the eight input names from
        # `DEFERRED_OPERATIONS`; chunk 3 carries those operations, so the rows
        # are gone and the case reported `COULD NOT APPLY` -- no evidence,
        # which must never be read as a pass. What the rule was ever about is
        # that a name the document's table carries and this build does not is
        # refused **as a deferral**, distinguishably from a typo. One entry is
        # left to say that about, so the case now deletes it.
        "a deferred operation is refused rather than treated as unknown-but-allowed",
        [
            (
                OPERATION,
                """pub const DEFERRED_OPERATIONS: &[(&str, Deferral)] =
    &[("accessibility_tree", Deferral::NeedsBackendProbe)];""",
                """pub const DEFERRED_OPERATIONS: &[(&str, Deferral)] = &[];""",
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
                # Re-pointed: the display parsing moved out of `validate_params`
                # into `display_of` when chunk 3 added eight more parameter
                # shapes, so the snippet lost four spaces of indentation. The
                # rule is unchanged.
                """    if index > MAX_DISPLAY {
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
                # Re-pointed: `dispatch_planned` now returns the plan beside the
                # outcome, so the arm returns a tuple. The substitution is the
                # same lie as before -- reporting a locally-answered operation
                # as a dispatch.
                "                return (Some(planned), Dispatch::AnsweredLocally(self.describe()));",
                "                return (Some(planned), Dispatch::Dispatched(Completion::Ok(self.describe())));",
            )
        ],
        False,
    ),
    (
        "a locally-answered operation is planned as a local answer, never as a command",
        [
            (
                PLAN,
                # Re-pointed: the local-answer arm became a `let ... else` when
                # chunk 3 made the command depend on the parameters, and
                # `command_payload` gained the capture argument -- so the old
                # replacement no longer compiled and reported BUILD FAILED,
                # which the harness refuses to call a red test. Same
                # substitution: plan a dispatch where a local answer is due.
                """    let Some(command) = dispatch_command(operation, request.params()) else {
        return Ok(Planned::AnswerLocally { operation });
    };""",
                """    let command = dispatch_command(operation, request.params()).unwrap_or("version");""",
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


# ---------------------------------------------------------------- chunk 3
#: The input half: the exclusive lease, the capture-identity carry-forward,
#: the display-scale conversion, the narrower retry rule and the keystroke
#: redaction. Same crates and same cargo invocation as `m5c2`; a separate list
#: so the two chunks' counts stay separable in a task row.
#:
#: **One rule of chunk 3 has no case here, and the omission is deliberate.**
#: `Planned`'s variants are `#[non_exhaustive]`, so an outside crate cannot
#: forge a dispatch -- and after chunk 3 a forged one skips the lease and the
#: capture check rather than merely an allowlist. A deletion harness looks for
#: a red *test*, and there is no red test for "this does not compile
#: elsewhere"; that is exactly how the claim drifted last round. Three
#: `compile_fail,E0639` doctests in `crates/tunnel-cua/src/plan.rs` enforce it
#: instead.
CASES_C3: list[tuple[str, list[Edit], bool]] = [
    # ------------------------------------------------------- the input lease
    (
        # The refusal the whole contract exists for: two authorized agents must
        # not interleave keyboard or pointer actions.
        "an input operation is refused to a session that does not hold the lease",
        [
            (
                LEASE,
                "        if holder.session != session {\n"
                "            return Err(LeaseRefusal::HeldByAnotherSession);\n"
                "        }\n"
                "        if grant_revision > holder.grant_revision {",
                "        if grant_revision > holder.grant_revision {",
            )
        ],
        False,
    ),
    (
        # A lease is never taken implicitly, so an unleased target must refuse
        # rather than fall through to a dispatch.
        "an input operation with no lease at all is refused rather than admitted",
        [
            (
                LEASE,
                "        let holder = self.held.get(target).ok_or(LeaseRefusal::NotHeld)?;",
                "        let Some(holder) = self.held.get(target) else {\n"
                "            return Ok(LeaseId(0));\n"
                "        };",
            )
        ],
        False,
    ),
    (
        # M3-16, the half that is closed: a revoked holder is refused at the
        # point of use.
        "a superseded grant revision refuses the lease holder",
        [
            (
                LEASE,
                "        if grant_revision > holder.grant_revision {\n"
                "            return Err(LeaseRefusal::GrantRevoked);\n"
                "        }\n",
                "",
            )
        ],
        False,
    ),
    (
        # A release must name the holding it owns, or one agent drops another's
        # lease mid-gesture.
        "a release must name the current holding and not merely the target",
        [
            (
                LEASE,
                "        if holder.lease != grant.lease {\n"
                "            return Err(LeaseRefusal::NotTheHolder);\n"
                "        }\n",
                "",
            )
        ],
        False,
    ),
    (
        # The reconcile must be driven by the revision, not by being called.
        "reconciling a grant frees only leases whose revision is behind",
        [
            (
                LEASE,
                "holder.session == session && grant_revision > holder.grant_revision",
                "holder.session == session",
            )
        ],
        False,
    ),
    # ------------------------------------------- the capture carry-forward
    (
        # Staleness: a newer capture supersedes the one a coordinate names.
        "a superseded capture is refused rather than acted on",
        [
            (
                CAPTURE,
                "        if self.current.get(&(target.clone(), identity.display())) != Some(&id) {\n"
                "            return Err(CaptureRefusal::Superseded);\n"
                "        }\n",
                "",
            )
        ],
        False,
    ),
    (
        # Target identity: a coordinate from another machine's screen.
        "a capture belonging to another target session is refused",
        [
            (
                CAPTURE,
                "        if identity.target() != target {\n"
                "            return Err(CaptureRefusal::TargetMismatch);\n"
                "        }\n",
                "",
            )
        ],
        False,
    ),
    (
        # Coordinate dimensions.
        "coordinates outside the capture are refused",
        [
            (
                CAPTURE,
                "        if !identity.contains(point) {\n"
                "            return Err(CaptureRefusal::OutsideCapture);\n"
                "        }\n",
                "",
            )
        ],
        False,
    ),
    (
        # The bound is half-open: the pixel at `width` does not exist.
        "the capture bound is half-open, so the pixel at the width is outside",
        [
            (
                CAPTURE,
                "        point.x < self.width && point.y < self.height",
                "        point.x <= self.width && point.y <= self.height",
            )
        ],
        False,
    ),
    (
        # **Display scale.** Forwarding the pixel clicks at half the intended
        # position on a 2x display, on the right screen, with no error anywhere.
        "a capture pixel is converted through the display scale",
        [
            (
                CAPTURE,
                # Re-pointed: the review round moved the multiplication into a
                # `u64` intermediate. The rule is unchanged -- the conversion
                # must happen -- and the replacement is the same pass-through.
                "        (\n"
                "            (point.x as u64 * identity / scale) as u32,\n"
                "            (point.y as u64 * identity / scale) as u32,\n"
                "        )",
                "        (point.x, point.y)",
            )
        ],
        False,
    ),
    (
        # A capture that could not be recorded must issue no identity: a zero
        # scale would make every backend coordinate zero.
        "impossible capture geometry is refused rather than recorded",
        [
            (
                CAPTURE,
                # Re-pointed: the review round added the `MAX_CAPTURE_DIMENSION`
                # bounds, so `cargo fmt` broke the condition across lines. The
                # rule is unchanged: impossible geometry issues no identity.
                "        if width == 0\n"
                "            || height == 0\n"
                "            || width > MAX_CAPTURE_DIMENSION\n"
                "            || height > MAX_CAPTURE_DIMENSION\n"
                "            || scale_percent == 0\n"
                "            || scale_percent > MAX_SCALE_PERCENT\n"
                "        {\n"
                "            return Err(GeometryError);\n"
                "        }\n",
                "",
            )
        ],
        False,
    ),
    # ------------------------------- the ordering, where the planner reads it
    (
        "the planner checks the input lease before it plans a dispatch",
        [
            (
                PLAN,
                "        context\n"
                "            .leases\n"
                "            .check(context.target, context.session, context.grant_revision)\n"
                "            .map_err(|refusal| {\n"
                "                Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Lease(refusal)))\n"
                "            })?;\n",
                "",
            )
        ],
        False,
    ),
    (
        "the planner resolves the capture identity before it plans a dispatch",
        [
            (
                PLAN,
                "        resolve_capture(operation, request.params(), context)?",
                "        None",
            )
        ],
        False,
    ),
    (
        # Checking only the start point is the natural mistake.
        "a drag is bounds-checked at both ends",
        [
            (
                PLAN,
                "            context\n"
                "                .captures\n"
                "                .resolve_point(*capture, context.target, *from)\n"
                "                .map_err(refuse)?;\n",
                "",
            )
        ],
        False,
    ),
    (
        # A click that ignored the button would send `left_click` for a right
        # click.
        "the button selects the upstream click command",
        [
            (
                PLAN,
                "        Params::Click { button, .. } => Some(button.upstream_command()),",
                "        Params::Click { .. } => operation.upstream_command(),",
            )
        ],
        False,
    ),
    (
        # The conversion has to be *used*, not merely available.
        "the request payload carries the converted coordinate and not the raw pixel",
        [
            (
                PLAN,
                "        capture.map_or((point.x, point.y), |identity| {\n"
                "            identity.to_backend_point(point)\n"
                "        })",
                "        (point.x, point.y)",
            )
        ],
        False,
    ),
    # --------------------------------------------------------- the retry rule
    (
        # **The rule that costs a duplicated click if it is wrong.**
        "an input operation that reached the backend is never retryable",
        [
            (
                OUTCOME,
                "            Self::Dispatched(_) => false,\n"
                "            Self::NotDispatched(NotDispatched::PeerUnavailable) => false,",
                "            Self::Dispatched(_) => true,\n"
                "            Self::NotDispatched(NotDispatched::PeerUnavailable) => false,",
            )
        ],
        False,
    ),
    (
        # M3-15: a rotation freeze is indistinguishable from a fault state, so
        # a click is never retried on one.
        "a peer-unavailable refusal is never auto-retried for an input operation",
        [
            (
                OUTCOME,
                "            Self::Dispatched(_) => false,\n"
                "            Self::NotDispatched(NotDispatched::PeerUnavailable) => false,",
                "            Self::Dispatched(_) => false,\n"
                "            Self::NotDispatched(NotDispatched::PeerUnavailable) => true,",
            )
        ],
        False,
    ),
    (
        # And the wire has to carry it, or a consumer re-derives the rule.
        "a failed input operation renders as non-retryable on the wire",
        [
            (
                SCHEMA,
                "                retryable: !operation.mutates_target(),",
                "                retryable: true,",
            )
        ],
        False,
    ),
    # ------------------------------------------------ never log typed text
    (
        # `AGENTS.md`: diagnostics carry identifiers, phases and counters, never
        # keystrokes. The redaction is the enforcement, not the reminder.
        "typed text is redacted from every diagnostic",
        [
            (
                SCHEMA,
                "        write!(\n"
                "            formatter,\n"
                '            "Keystrokes(<redacted, {} chars>)",\n'
                "            self.characters()\n"
                "        )",
                '        write!(formatter, "Keystrokes({})", self.0)',
            )
        ],
        False,
    ),
    (
        # A key name is mapped onto a keyboard layout by the backend; one
        # carrying a separator or a control character is a name this profile
        # has not reasoned about.
        "a key name is restricted to a conservative character set",
        [
            (
                SCHEMA,
                "    if !text\n"
                "        .bytes()\n"
                "        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')\n"
                "    {\n"
                "        return Err(SchemaError::OutOfRange { name });\n"
                "    }\n",
                "",
            )
        ],
        False,
    ),
    # ------------------------------- the click counter counts effects
    (
        # **The trap in one case.** With `double_click` contributing 1 the
        # ledger would be counting dispatches, and the control that reads 2 is
        # the thing that breaks -- which is the point of having it.
        "the click counter counts effects, so a double click contributes two",
        [(FIXTURE_LIB, '        "double_click" => 2,', '        "double_click" => 1,')],
        False,
    ),
    # ------------------- the review round's four rules
    (
        # **The major review finding.** `acquire` used to write the supplied
        # revision into an existing holding, so a revoked holder could clear
        # its own `GrantRevoked` refusal by taking the lease again -- and
        # `reconcile_grant` would then free nothing. One call defeated both
        # halves of the M3-16 story.
        "a revoked holder cannot re-acquire its own lease to clear the refusal",
        [
            (
                LEASE,
                "            if grant_revision > holder.grant_revision {\n"
                "                return Err(LeaseRefusal::GrantRevoked);\n"
                "            }\n",
                "",
            )
        ],
        False,
    ),
    (
        # The plan's `Debug` is hand-written because a derived one renders the
        # payload, and for `type_text` the payload is the text.
        "a planned dispatch never renders its payload, because the payload can be keystrokes",
        [
            (
                PLAN,
                '                .field(\n'
                '                    "payload",\n'
                '                    &format_args!("<{} bytes>", payload.to_string().len()),\n'
                '                )\n',
                '                .field("payload", payload)\n',
            )
        ],
        False,
    ),
    (
        # The M3-15 rule has to be *derived* at the wire, not assumed, or a
        # future facade gets the default wrong.
        "a not-dispatched refusal of a known operation derives its retryability",
        [
            (
                SCHEMA,
                "        let retryable =\n"
                "            crate::outcome::Dispatch::NotDispatched(refusal).retry_is_safe_for(operation);",
                "        let retryable = true;",
            )
        ],
        False,
    ),
    (
        # A capture dimension nobody bounded reaches `contains` and
        # `to_backend_point`.
        "a capture dimension is bounded where the capture is recorded",
        [
            (
                CAPTURE,
                "            || width > MAX_CAPTURE_DIMENSION\n"
                "            || height > MAX_CAPTURE_DIMENSION\n",
                "",
            )
        ],
        False,
    ),
]



#: `cargo test -p <pkg>` builds a package's `[[bin]]` as a plain executable
#: only when that package has integration tests, and it builds **no binary
#: belonging to another package at all** (M3-19). Chunk 4's tests `exec` both
#: the fixture binary and the sentinel, so both are rebuilt before every case.
C4_CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-cua",
    "-p",
    "tunnel-cua-export",
    "-p",
    "tunnel-cua-fixture",
    "--locked",
    "--no-fail-fast",
]

C4_BUILD = [
    "cargo",
    "build",
    "--locked",
    "-p",
    "tunnel-deadman",
    "-p",
    "tunnel-cua-fixture",
    "--bins",
]


# --------------------------------------------------------------- chunk 4
#: Supervising the backend. Every rule chunk 4 adds, defeated one at a time.
#:
#: Two of these live outside `crates/tunnel-cua*` -- one in
#: `crates/tunnel-deadman` -- which is why this suite carries `C4_BUILD`.
CASES_C4: list[tuple[str, list[Edit], bool]] = [
    # ------------------------------------------------- the sentinel is armed
    (
        # Arming at all. Without this the CUA supervisor supervises exactly as
        # it did before, and the backend's process group survives the device
        # being SIGKILLed -- for CUA, a process that can still drive a desktop.
        "every supervised CUA backend is watched by a parent-death sentinel",
        [
            (
                EXPORT_CHILD,
                "    let deadman = tunnel_deadman::Deadman::arm(pid);",
                "    let deadman: Option<tunnel_deadman::Deadman> = None;",
            )
        ],
        False,
    ),
    (
        # The whole mechanism, one crate down. The sentinel still starts, still
        # watches and still exits -- and signals nothing, so the group it was
        # watching outlives the supervisor. Defeated in `tunnel-deadman`
        # precisely to exercise the M3-19 rebuild: `cargo test -p
        # tunnel-cua-fixture` builds no binary of that package, so without
        # `C4_BUILD` this case reports `still green` for the entire mechanism.
        "a bare end of file makes the sentinel kill the watched backend's group",
        [(DEADMAN_LIB, "    kill_group(leader);\n    EXIT_FIRED", "    EXIT_FIRED")],
        False,
    ),
    (
        # The supervisor's own group kill on the orderly path. Without it the
        # backend's in-group helper -- the worker that never reads stdin --
        # outlives the backend it belongs to.
        "the supervisor signals the backend's whole process group, not only its leader",
        [
            (
                EXPORT_CHILD,
                """        if kill_group(pid) {
            supervisor_counters
                .group_kills
                .fetch_add(1, Ordering::Relaxed);
        }""",
                "",
            )
        ],
        False,
    ),
    (
        # The backend must lead a group of its own. Without this it shares the
        # device's group, and the group kill above would signal the device.
        "a supervised backend is started as the leader of its own process group",
        [(EXPORT_CHILD, "    command.process_group(0);", "")],
        False,
    ),
    # ----------------------------------------------- the restart invalidation
    (
        # **The restart contract, half one.** Without the lease invalidation a
        # consumer keeps exclusive input authority over a backend that no
        # longer exists, and its retry passes the lease check.
        "a supervised restart drops every input lease",
        [
            (
                LEASE,
                """    pub fn invalidate_all(&mut self) -> Vec<TargetSession> {
        let freed: Vec<TargetSession> = self.held.keys().cloned().collect();
        self.held.clear();
        freed
    }""",
                """    pub fn invalidate_all(&mut self) -> Vec<TargetSession> {
        Vec::new()
    }""",
            )
        ],
        False,
    ),
    (
        # **The restart contract, half two.** Without the capture invalidation
        # a consumer clicks at coordinates picked from an image the dead
        # backend produced, on a screen nobody has looked at since.
        "a supervised restart forgets every capture identity",
        [
            (
                CAPTURE,
                """    pub fn invalidate_all(&mut self) -> usize {
        let forgotten = self.by_id.len();
        self.by_id.clear();
        self.current.clear();
        forgotten
    }""",
                """    pub fn invalidate_all(&mut self) -> usize {
        0
    }""",
            )
        ],
        False,
    ),
    (
        # The monotonic capture counter. Reset it and the first capture after a
        # restart reissues id 1, so a stale click resolves against a *different
        # image*, passes the bounds check, and is dispatched at coordinates
        # nobody picked. This is the failure that looks most like success.
        "a capture identity is never reissued after a restart",
        [
            (
                CAPTURE,
                """        let forgotten = self.by_id.len();
        self.by_id.clear();""",
                """        let forgotten = self.by_id.len();
        self.next = 0;
        self.by_id.clear();""",
            )
        ],
        False,
    ),
    (
        # The same rule for leases: a reissued lease id would let a
        # pre-restart grant pass `release`.
        "a lease id is never reissued after a restart",
        [
            (
                LEASE,
                """        let freed: Vec<TargetSession> = self.held.keys().cloned().collect();
        self.held.clear();""",
                """        let freed: Vec<TargetSession> = self.held.keys().cloned().collect();
        self.next = 0;
        self.held.clear();""",
            )
        ],
        False,
    ),
    (
        # **The trap itself.** Reclassify an operation that reached the backend
        # as not dispatched, and the supervisor becomes the route by which a
        # caller is told to retry a click that may already have landed.
        "an operation in flight across a restart is unknown, never not-dispatched",
        [
            (
                SUPERVISION,
                """        InFlight::ReachedBackend => {
            Dispatch::Dispatched(Completion::Unknown(UnknownReason::BackendRestarted))
        }""",
                """        InFlight::ReachedBackend => Dispatch::NotDispatched(NotDispatched::NotReached),""",
            )
        ],
        False,
    ),
    (
        # Both registries in one call. Splitting them is the defect: a lease
        # dropped without its captures leaves a consumer able to re-acquire and
        # click at coordinates from a dead backend's image.
        "a restart invalidates both registries, never one of them",
        [
            (
                SUPERVISION,
                "        captures_forgotten: captures.invalidate_all(),",
                "        captures_forgotten: 0,",
            )
        ],
        False,
    ),
    (
        # The invalidation must happen on **every** end of the backend's life,
        # not only on a deliberate restart: a backend that crashed leaves
        # exactly the same stale authority behind.
        "stopping a backend invalidates as much as restarting one",
        [
            (
                EXPORT_SUPERVISOR,
                "        authority.invalidate(self.generation)",
                "        Invalidation::default()",
            )
        ],
        False,
    ),
    # ----------------------------------------------- health is a probe, not an echo
    (
        # **The anti-echo rule.** Let any operation stand as a probe and
        # `describe` -- answered entirely from device state, with no bytes sent
        # -- can report that a backend the OS has permitted nothing can act.
        "only an OS-gated read-only operation may stand as a health probe",
        [
            (
                EXPORT_HEALTH,
                """    if !PROBE_OPERATIONS.contains(&request.operation()) {
        return Health::Unhealthy(Unhealthy::NotAProbe);
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        # Only `Working` permits a dispatch. Widen it to `Started` and a
        # backend that has proven nothing is allowed to act.
        "nothing but probe evidence permits an operation to be dispatched",
        [
            (
                EXPORT_HEALTH,
                "        matches!(self, Self::Working(_))",
                "        matches!(self, Self::Working(_) | Self::Started)",
            )
        ],
        False,
    ),
    # --------------------------------------------- the endpoint the backend published
    (
        # The loopback policy, applied to the process that is actually
        # listening. Without it a backend that bound a routable address is
        # handed to consumers.
        "the address a backend publishes goes through the loopback check",
        [
            (
                EXPORT_SUPERVISOR,
                "            return BackendEndpoint::new(address).map_err(StartError::Endpoint);",
                "            return Ok(BackendEndpoint::new(address).unwrap_or_else(|_| {\n                BackendEndpoint::new(std::net::SocketAddr::from(([127, 0, 0, 1], 1)))\n                    .expect(\"loopback\")\n            }));",
            )
        ],
        False,
    ),
    (
        # The stale address. Without the removal before the spawn, a restart
        # whose new backend is slow to bind reads the dead backend's port --
        # or whatever bound it next, which on loopback is any local process.
        "the previous generation's address file is removed before every start",
        [
            (
                EXPORT_SUPERVISOR,
                "        let _ = tokio::fs::remove_file(&self.process.address_file).await;",
                "",
            )
        ],
        False,
    ),
    # ------------------------------------------------------- the fixture's own guards
    (
        # The journal is what makes an effect count survive a restart. Without
        # it every cross-restart count reads zero and "the count did not
        # increase" is true of nothing.
        "the effect journal records what the backend was asked to do",
        [(FIXTURE_LIB, "        self.append(&entry);", "")],
        False,
    ),
    (
        # The in-group helper must stay in the backend's group. Put it in a
        # group of its own and the "trigger" measurement silently becomes a
        # "reach" measurement: the helper would survive for the wrong reason
        # and the sentinel would be blamed for not reaching it.
        "the in-group helper really is in the supervised backend's group",
        [
            (
                FIXTURE_PROCESS,
                """    let spawned = std::process::Command::new(executable)
        .arg(HELPER_MODE)""",
                """    let mut spawned = std::process::Command::new(executable);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        spawned.process_group(0);
    }
    let spawned = spawned
        .arg(HELPER_MODE)""",
            )
        ],
        False,
    ),
    (
        # The supervisor route's lifecycle check. Without it a succeeded probe
        # answered by something other than the supervised process -- a stale
        # reply, or whatever took the port -- reports a dead backend as
        # working. This is the public route; the free classifier is
        # crate-private precisely because it cannot make this check.
        "a probe cannot report a backend that is gone as working",
        [
            (
                EXPORT_SUPERVISOR,
                """        let lifecycle = self.health();
        if !lifecycle.process_is_running() {
            return lifecycle;
        }
""",
                "",
            )
        ],
        False,
    ),
    (
        # The escaping descendant must actually escape. A fixture that failed
        # to detach would be killed by the plain group signal and every reach
        # measurement built on it would be vacuous.
        "the detaching descendant really does leave the backend's process group",
        [
            (
                FIXTURE_PROCESS,
                "        DetachRoute::Setsid => rustix::process::setsid().is_ok(),",
                "        DetachRoute::Setsid => false,",
            )
        ],
        False,
    ),
]


@dataclass
class Suite:
    name: str
    crates: list[Path]
    cargo_test: list[str]
    cases: list[tuple[str, list[Edit], bool]] = field(default_factory=list)
    cwd: Path = REPO
    #: Binaries to rebuild before each case. See M3-19 and the `m5c4` note in
    #: this module's documentation.
    build: list[str] = field(default_factory=list)


SUITES: list[Suite] = [
    Suite("m5c2", [CRATE, FIXTURE], CARGO_TEST, CASES),
    Suite("m5c3", [CRATE, FIXTURE], CARGO_TEST, CASES_C3),
    Suite(
        "m5c4",
        [CRATE, EXPORT, FIXTURE, DEADMAN],
        C4_CARGO_TEST,
        CASES_C4,
        build=C4_BUILD,
    ),
]

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
    if suite.build:
        # M3-19: rebuild every binary these tests will `exec`, transitively,
        # before running them. A failure here is a build failure for the case,
        # never a red test -- the same refusal the test run itself makes.
        try:
            built = subprocess.run(
                suite.build,
                cwd=suite.cwd,
                env=cargo_env(),
                capture_output=True,
                text=True,
                timeout=900,
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
            timeout=900,
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
    parser.add_argument("--suite", help="run only this suite (m5c2, m5c3 or m5c4)")
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
