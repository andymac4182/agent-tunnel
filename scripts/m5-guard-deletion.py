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

  **It carries a mandatory pre-build**, because its tests `exec` two binaries
  from two packages: `tunnel-cua-fixture` and `tunnel-deadman`. See
  `Suite.build` and task row M3-19. Its second case is defeated in
  `crates/tunnel-deadman`, a package `cargo test -p tunnel-cua-fixture` builds
  no binary of, so without the rebuild it would report `still green` for the
  entire mechanism.

* `m5c5` -- restart attribution: the lifecycle epoch that makes a supervised
  restart reach a consumer as a restart rather than as a lost connection, the
  ordering that makes it fire at all, and the refusals that keep attribution
  from widening retryability or overwriting a definitive answer.

  **It carries the same pre-build as `m5c4`, for the same reason**: two of its
  cases are witnessed only by `tunnel-cua-fixture`'s integration tests, which
  `exec` the fixture binary. Without the rebuild both would report `still
  green`.

* `m5c6` -- what a restart cannot see: the per-operation map of input state a
  backend may have left asserted on the target, the restart's unconditional
  declaration of it, and the two narrowings that would turn that declaration
  back into silence.

  **These cases defeat declarations, not repairs.** Nothing in this chunk
  releases a held button or key. That is a policy decision rather than a
  limit of the backend: the pinned 0.3.46 registry does carry `mouse_up` and
  `key_up`, and the device declines to issue them because a `mouse_up` is a
  *drop* and a `key_up` is synthesised input outside any lease. See
  `docs/tasks.md` M5-C09.

  A device that declared nothing would behave **identically** against the
  backend -- same requests, same outcomes, same journal -- so no behavioural
  test can tell the two apart and a guard suite is the only thing that can.
  It carries `m5c4`'s pre-build, for `m5c4`'s reason.

* `m5c7` -- the parameter pin: the table of parameter names read out of the
  pinned `handlers/base.py`, the payload builder checked against it, and the
  one narrow exception for a parameter whose loss changes nothing.

  **Its first two cases restore defects this repository actually shipped.**
  The released `/cmd` dispatcher discards any parameter its handler does not
  declare, with no error and no log, so a wrong name is not a failed request
  -- it is a command that runs with the wrong arguments and reports success.
  `drag` was sent four endpoint names that upstream has never declared, and
  `scroll` was sent the cursor point under `x`/`y`, which upstream reads as
  wheel amounts. Neither could fail against the Lane A fixture, which accepts
  whatever it is sent; only a pin against the fetched source could catch
  them, and `scripts/m5-cua-param-parity.py` is the half of that pin that
  runs against upstream rather than against us.

  It spans three crates, `tunnel-http-forward` included, because the table
  lives beside the codec. It carries `m5c4`'s pre-build, for `m5c4`'s reason.

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

# Chunk 7. The pinned CUA artifact table lives in the forwarding codec's
# crate, beside the profile whose wire shape it defines.
FORWARD = REPO / "crates" / "tunnel-http-forward"
CUA_PIN = FORWARD / "src" / "cua_pin.rs"

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
                # Re-pointed again on `m5-code` (M5-C14): the conversion now
                # returns `Option`, `None` for an undeclared scale; the
                # replacement is still the pass-through.
                "        Some((\n"
                "            (point.x as u64 * identity / scale) as u32,\n"
                "            (point.y as u64 * identity / scale) as u32,\n"
                "        ))",
                "        Some((point.x, point.y))",
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
                # Re-pointed on `m5-code` (M5-C14): the conversion is fallible
                # now, because an undeclared scale is refused rather than
                # defaulted. The rule is unchanged -- the converted coordinate
                # must be the one sent -- and the replacement is still the raw
                # pixel.
                "        Some(identity) => identity\n"
                "            .to_backend_point(point)\n"
                "            .ok_or(crate::capture::CaptureRefusal::ScaleUndeclared),",
                "        Some(_) => Ok((point.x, point.y)),",
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

#: Chunk 7 spans `tunnel-http-forward` too, because the pinned parameter
#: table lives there. Omitting it would leave both table cases reporting
#: `still green` while the rule they defeat was never compiled.
C7_CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-cua",
    "-p",
    "tunnel-http-forward",
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


# --------------------------------------------------------------- chunk 5
#: Restart attribution: the wiring that makes `restart_outcome` reachable from
#: the dispatch path (task row M5-C10).
#:
#: **Why these are here rather than in a report.** Chunk 5 first held these
#: five mutations red by hand and cited the tally in its PR body, which is the
#: defect M4-27 was reopened for: a failure mode nobody but the author can
#: re-run is not evidence. Each is now a case.
#:
#: The `.watching()` call sites in `tests/supervision.rs` are deliberately
#: **not** cases: this harness defeats guards in the *product*, and editing a
#: test to remove its own coverage measures nothing about behaviour. The
#: dispatcher-side equivalent is the last case here, which makes `watching`
#: accept the handle and drop it -- exactly what an unwired dispatcher does.
#:
#: Shares `m5c4`'s build and test set: the restart attribution is witnessed by
#: `tunnel-cua-fixture`'s integration tests, which `exec` the fixture binary.
CASES_C5: list[tuple[str, list[Edit], bool]] = [
    (
        # **The one that would be a double click.** Widening an in-flight
        # unknown to `NotDispatched` tells the caller to retry a click that may
        # already have landed -- the M5-04 trap, arriving through attribution
        # rather than through the supervisor itself.
        "attribution never widens what a retry is allowed to do",
        [
            (
                SUPERVISION,
                """        Dispatch::Dispatched(Completion::Unknown(_)) => restart_outcome(InFlight::ReachedBackend),
        Dispatch::NotDispatched(NotDispatched::NotReached) => restart_outcome(InFlight::NotReached),""",
                """        Dispatch::Dispatched(Completion::Unknown(_)) => {
            Dispatch::NotDispatched(NotDispatched::NotReached)
        }
        Dispatch::NotDispatched(NotDispatched::NotReached) => restart_outcome(InFlight::NotReached),""",
            )
        ],
        False,
    ),
    (
        # The row's whole point: with attribution inert the contract still
        # holds -- `TransportLost` is equally dispatched, unknown and
        # non-retryable -- and only the *named reason* is lost. A test that
        # asserted the arm alone would stay green here, which is why the
        # assertions this defeats compare the reason.
        "a restart reaches the consumer as a restart, not as a lost connection",
        [
            (
                SUPERVISION,
                """    match &transport {
        Dispatch::Dispatched(Completion::Unknown(_)) => restart_outcome(InFlight::ReachedBackend),
        Dispatch::NotDispatched(NotDispatched::NotReached) => restart_outcome(InFlight::NotReached),
        _ => transport,
    }""",
                "    transport",
            )
        ],
        False,
    ),
    (
        # Without the equality guard every exchange is reported as a restart,
        # including the overwhelming majority that ran while the supervisor did
        # nothing at all. A diagnostic that names every failure a restart is
        # worth less than one that names none.
        "an exchange the supervisor never disturbed keeps the transport's own answer",
        [
            (
                SUPERVISION,
                """    if before == after {
        return transport;
    }""",
                "    let _ = (before, after);",
            )
        ],
        False,
    ),
    (
        # Attribution must not destroy information. Rewriting `Dispatched(_)`
        # wholesale turns a backend's definitive `Ok` into `Unknown` because
        # something restarted afterwards, which is strictly worse than not
        # attributing at all.
        "a definitive answer survives a restart that happened around it",
        [
            (
                SUPERVISION,
                "        Dispatch::Dispatched(Completion::Unknown(_)) => restart_outcome(InFlight::ReachedBackend),",
                "        Dispatch::Dispatched(_) => restart_outcome(InFlight::ReachedBackend),",
            )
        ],
        False,
    ),
    (
        # **The ordering, and it is the whole outcome rather than a narrow
        # race.** The epoch must advance before the kill: an exchange against
        # the dying backend reads its "after" value the instant the socket
        # closes, which is at the kill and not at the replacement's spawn.
        # Moving this one line below the kill leaves every restart-killed
        # exchange reported as `TransportLost`. It is also why
        # `BackendGeneration`, which advances later still, cannot be used here.
        "the lifecycle epoch advances before the kill, not after it",
        [
            (
                EXPORT_SUPERVISOR,
                """        self.epoch.disturb();
        if let Some(running) = self.running.take() {
            running.child.kill();
            running.child.wait_exited().await;
        }""",
                """        if let Some(running) = self.running.take() {
            running.child.kill();
            running.child.wait_exited().await;
        }
        self.epoch.disturb();""",
            )
        ],
        False,
    ),
    (
        # The dispatcher-side form of "the dispatcher is not watching":
        # `watching`
        # takes the handle and drops it, leaving the detached default. This is
        # what makes the watched/unwatched pair in `tests/supervision.rs`
        # evidence -- the epoch really is what decides, and a dispatcher that
        # takes no handle really does fall back to the transport's own reason.
        "a dispatcher handed a lifecycle epoch actually keeps it",
        [
            (
                CLIENT,
                "        self.epoch = epoch;",
                "        let _ = epoch;",
            )
        ],
        False,
    ),
]

#: Chunk 6 -- what a restart cannot see. Shares `m5c4`'s build and test set:
#: two of these cases are witnessed end to end by
#: `tunnel-cua-fixture/tests/supervision.rs`, which `exec`s the fixture binary.
#:
#: **Every case here defeats a *declaration*, not a repair.** Nothing in this
#: chunk releases a held button or key -- a decision, not an impossibility;
#: the pinned registry carries `mouse_up` and `key_up` and the device declines
#: to issue them. So what these cases measure is whether the device still
#: admits what it has chosen not to resolve. A silent device and an honest one
#: behave identically against the backend, which is exactly why only a guard
#: suite can tell them apart.
CASES_C6: list[tuple[str, list[Edit], bool]] = [
    (
        # The declaration the restart makes, deleted outright. A supervisor
        # that reports only what it took away from itself reports the
        # reassuring half of a restart alone.
        "a restart declares what it could not observe about the target",
        [
            (
                SUPERVISION,
                "        residue: RESTART_RESIDUE,",
                "        residue: DesktopResidue::NONE,",
            )
        ],
        False,
    ),
    (
        # **The tempting narrowing, and the wrong one.** The device's own
        # registries are not a witness to the desktop: a lease released just
        # before the kill empties them, and the agent who inherits a held
        # button holds no lease at the moment of the restart at all. A device
        # that said "nothing was held, so the desktop is clean" would be
        # making the claim this whole row exists to stop -- and it would still
        # pass every test that restarts a *busy* backend, which is why the
        # idle restart is asserted in the same breath.
        "the declaration does not narrow to what the device happened to hold",
        [
            (
                SUPERVISION,
                """    Invalidation {
        generation,
        leases_released: leases.invalidate_all(),
        captures_forgotten: captures.invalidate_all(),
        residue: RESTART_RESIDUE,
    }""",
                """    let mut invalidation = Invalidation {
        generation,
        leases_released: leases.invalidate_all(),
        captures_forgotten: captures.invalidate_all(),
        residue: RESTART_RESIDUE,
    };
    if !invalidation.freed_anything() {
        invalidation.residue = DesktopResidue::NONE;
    }
    invalidation""",
            )
        ],
        False,
    ),
    (
        # A drag is the one operation that can end with the button still down
        # *and* the gesture carried half way. Declaring nothing for it is the
        # single most consequential silence in the map, because a later
        # `move` against a held button is a drag nobody asked for.
        #
        # **This case does not move `RESTART_RESIDUE`, and that is expected.**
        # `Click` still contributes `POINTER_BUTTON` to the fold, so the
        # restart declaration is unchanged and
        # `a_restart_declares_every_kind_an_input_operation_can_leave` stays
        # green. What reddens is the per-operation map, which is the rule
        # under test here. Do not "fix" this by asserting the fold.
        "an interrupted drag declares the button it may have left down",
        [
            (
                SUPERVISION,
                "        Operation::Drag => DesktopResidue::POINTER_BUTTON.union(DesktopResidue::PARTIAL_EFFECT),",
                "        Operation::Drag => DesktopResidue::NONE,",
            )
        ],
        False,
    ),
    (
        # If everything declares everything, a consumer learns nothing from
        # being told. The reads synthesise no input, so a residue on one is
        # not caution -- it is noise that devalues the real declarations.
        "an operation that synthesises no input declares no residue",
        [
            (
                SUPERVISION,
                """        | Operation::CursorPosition => DesktopResidue::NONE,""",
                """        | Operation::CursorPosition => DesktopResidue::POINTER_BUTTON,""",
            )
        ],
        False,
    ),
    (
        # The kinds are inherited differently and cleared by different things:
        # a held modifier re-interprets every later keystroke, a held button
        # every later move. Collapsing them keeps the declaration non-empty --
        # so a test that only asked "is something declared" would stay green.
        "a held key and a held button stay different declarations",
        [
            (
                SUPERVISION,
                "        Operation::PressKey | Operation::Hotkey => DesktopResidue::KEY_HELD,",
                "        Operation::PressKey | Operation::Hotkey => DesktopResidue::POINTER_BUTTON,",
            )
        ],
        False,
    ),
]

#: Chunk 7 -- the parameter pin (M5-C06).
#:
#: The command names were already pinned; the parameter names were not. The
#: released dispatcher drops any parameter its handler does not declare,
#: silently, so the cost of a wrong name is a command that runs with the
#: wrong arguments and answers `success`. These cases defeat the three things
#: that now stop that: the pinned table read out of `handlers/base.py`, the
#: payload builder that is checked against it, and the narrow escape hatch
#: for a parameter whose loss changes nothing.
#:
#: **Two of them would have been green before this chunk**, which is the
#: point: `a_payload_may_name_a_parameter_upstream_discards` and
#: `the_scroll_deltas_may_be_dropped_for_the_cursor_point` reproduce exactly
#: what the adapter shipped, and the suite is what makes them red.
CASES_C7: list[tuple[str, list[Edit], bool]] = [
    (
        # The original defect, restored. `drag` upstream takes a `path`; the
        # four-name spelling was discarded whole and the call then raised a
        # TypeError for the missing required argument -- inside a 200.
        "a payload may name a parameter upstream discards",
        [
            (
                PLAN,
                """            json!({"command": command, "params": {
                "path": [[start_x, start_y], [end_x, end_y]],
            }})""",
                """            json!({"command": command, "params": {
                "start_x": start_x, "start_y": start_y,
                "end_x": end_x, "end_y": end_y,
            }})""",
            )
        ],
        False,
    ),
    (
        # **The subtle half, and the reason a name check alone is not
        # enough.** `x` and `y` ARE declared on `scroll`, so sending the
        # cursor point under them passes every name assertion -- and scrolls
        # by the coordinate while discarding the deltas. Only the payload's
        # value is evidence here.
        #
        # Re-pointed on `m5-code` (M5-C13): `scroll` no longer carries a
        # point to substitute, so the defeat now drops the deltas for
        # constants. The rule it measures is the same -- the payload's `x`/`y`
        # must be the consumer's deltas.
        "the scroll deltas may be dropped for constants",
        [
            (
                PLAN,
                """        Params::Scroll { dx, dy } => {
            json!({"command": command, "params": {"x": dx, "y": dy}})
        }""",
                """        Params::Scroll { dx, dy } => {
            let _ = (dx, dy);
            json!({"command": command, "params": {"x": 0, "y": 0}})
        }""",
            )
        ],
        False,
    ),
    (
        # The pinned table itself, moved off upstream. If the table can drift
        # without a test noticing, the payload check is the adapter agreeing
        # with the adapter.
        "the pinned parameter table may disagree with the payload builder",
        [
            (
                CUA_PIN,
                """        command: "drag",
        required: &["path"],""",
                """        command: "drag",
        required: &["start_x"],""",
            )
        ],
        False,
    ),
    (
        # The escape hatch, opened. A `knowingly discarded` list that anything
        # may join is not an exception to the pin, it is the absence of one.
        "the knowingly-discarded list may be widened to anything",
        [
            (
                CUA_PIN,
                """pub const PARAMETERS_KNOWINGLY_DISCARDED: &[(&str, &str)] =
    &[("screenshot", "display"), ("get_screen_size", "display")];""",
                """pub const PARAMETERS_KNOWINGLY_DISCARDED: &[(&str, &str)] = &[
    ("screenshot", "display"),
    ("get_screen_size", "display"),
    ("drag", "start_x"),
    ("drag", "start_y"),
    ("drag", "end_x"),
    ("drag", "end_y"),
];""",
            )
        ],
        False,
    ),
    (
        # The lookup, defeated. Returning `None` makes every command look
        # unpinned, which a check that skipped unknown commands would have
        # read as nothing to do.
        "the parameter lookup may answer for no command at all",
        [
            (
                CUA_PIN,
                """    COMMAND_PARAMETERS
        .iter()
        .find(|entry| entry.command == command)""",
                """    COMMAND_PARAMETERS
        .iter()
        .find(|entry| entry.command == command && command.is_empty())""",
            )
        ],
        False,
    ),
    (
        # **The fixture side**, which is code under test rather than an
        # assertion -- the same reason `m5c5`'s sixth case binds. A fixture
        # still reading the old spelling would record no point for a drag,
        # and the ledger is what every dispatch test judges against.
        "the fixture may keep reading the old drag spelling",
        [
            (
                FIXTURE_LIB,
                """    let path_start = || {
        let first = request.pointer("/params/path/0")?.as_array()?;""",
                """    let path_start = || {
        let first = request.pointer("/params/start_path/0")?.as_array()?;""",
            )
        ],
        False,
    ),
]


# --------------------------------------------------------------- chunk 8
#: The guard on the **skip** that chunk 8 adds (task row M5-C11).
#:
#: `crates/tunnel-cua-fixture/tests/process_residue.rs` no longer asserts
#: `armed == 1` when the `tunnel-deadman` helper is absent -- it reports that
#: the test did not run, and why, because `armed == 1` fails identically
#: whether the helper is missing or the arming code regressed.  That buys a
#: new hazard, which is the one M5-C11 names: a skip that decided "absent"
#: while the helper was present would make all four measurements vanish
#: **silently**, which is the same defect one level up and the reason a
#: `#[cfg]` guard is recorded there as rejected.
#:
#: `the_skip_cannot_hide_a_helper_that_is_on_disk` is the positive control for
#: that, and this case is what shows the control is load-bearing rather than
#: decorative: defeat `availability()` into always reporting the helper
#: missing -- the exact regression that would silently skip everything -- and
#: the control must go red.
#:
#: **`C4_BUILD` is load-bearing for this suite, not boilerplate.** The control
#: compares the skip's decision against the filesystem, so with no
#: `tunnel-deadman` binary beside the tests it correctly asserts
#: `false == false` and this case would report `still green` over a rule that
#: was never exercised.  The helper must be built for the case to be able to
#: fail at all.
CASES_C8: list[tuple[str, list[Edit], bool]] = [
    (
        "a present sentinel helper cannot be reported as missing",
        [
            (
                DEADMAN_LIB,
                # **Re-anchored at M6-C08**, which replaced the two-valued
                # `sentinel_path().is_some()` test with a three-valued
                # `Resolution`.  The defeat is unchanged in substance: make
                # `availability()` report the helper missing whatever is on
                # disk, and the positive control must notice.
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


# --------------------------------------------------------------- chunk 9
#: `m5-code`: the rows closed without a desktop -- M5-C05 (the lease stops
#: being honoured when the device learns a revision), M5-C12 (an unselectable
#: display is refused), M5-C13 (`scroll` takes no position), M5-C14 (capture
#: dimensions from the PNG the released server sends; no default scale) and
#: M5-04 (a cancellation reports the stage it hit).
#:
#: **Every case here names its witness** in `WITNESSES` below, so none of them
#: is credited to an unrelated red, and none is added to
#: `scripts/guard_witness_debt.json`.
IMAGE = CRATE / "src" / "image.rs"

CASES_C9: list[tuple[str, list[Edit], bool]] = [
    (
        "M5-C05: learning a grant revision frees the lease it superseded in the same step",
        [
            (
                CLIENT,
                """        self.grant_revision = revision;
        leases.reconcile_grant(self.session, revision)
    }""",
                """        self.grant_revision = revision;
        let _ = &mut leases;
        Vec::new()
    }""",
            )
        ],
        False,
    ),
    (
        "M5-C12: a display no pinned backend can select is refused before dispatch",
        [
            (
                PLAN,
                """    if let Params::Capture { display } | Params::ScreenInfo { display } = request.params()
        && !schema::SELECTABLE_DISPLAYS.contains(display)
    {
        return Err(Dispatch::NotDispatched(NotDispatched::DisplayNotSelectable));
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "M5-C13: a scroll that names a position is refused rather than validated and dropped",
        [
            (
                SCHEMA,
                """        Operation::Scroll => &["dx", "dy"],""",
                """        Operation::Scroll => &["capture", "x", "y", "dx", "dy"],""",
            )
        ],
        False,
    ),
    (
        "M5-C14: a capture with no declared scale refuses a coordinate at resolution",
        [
            (
                CAPTURE,
                """        if identity.scale_percent.is_none() {
            return Err(CaptureRefusal::ScaleUndeclared);
        }
""",
                "",
            )
        ],
        False,
    ),
    (
        "M5-C14: an undeclared scale is never defaulted to 1x in the conversion",
        [
            (
                CAPTURE,
                """        let Some(scale) = self.scale_percent else {
            return None;
        };
""",
                """        let scale = match self.scale_percent {
            Some(scale) => scale,
            None => IDENTITY_SCALE_PERCENT,
        };
""",
            )
        ],
        False,
    ),
    (
        "M5-C14: the device records an undeclared scale rather than assuming 1x",
        [
            (
                CLIENT,
                """            None => captures.record_undeclared_scale(&self.target, display, width, height),""",
                """            None => captures.record(&self.target, display, width, height, 100),""",
            )
        ],
        False,
    ),
    (
        "M5-C14: capture dimensions are read from the PNG the released server sends",
        [
            (
                CLIENT,
                """        let Ok((width, height)) = tunnel_cua::image::capture_dimensions(result) else {""",
                """        let Ok((width, height)) = Err::<(u32, u32), ()>(()) else {""",
            )
        ],
        False,
    ),
    (
        "M5-C14: a PNG header whose CRC does not match is refused",
        [
            (
                IMAGE,
                """    if crc32(&header[12..29]) != recorded {
        return Err(ImageHeaderError::BadCrc);
    }
""",
                "",
            )
        ],
        False,
    ),
    (
        "M5-C05: ending a session releases the leases it holds",
        [
            (
                CLIENT,
                """            .release_all_for_session(session)
    }""",
                """            .holder(&TargetSession::new(""))
            .map(|_| Vec::new())
            .unwrap_or_default()
    }""",
            )
        ],
        False,
    ),
    (
        "M5-04: a cancellation after writing began is unknown, never not dispatched",
        [
            (
                CLIENT,
                """        began.store(true, std::sync::atomic::Ordering::SeqCst);
""",
                "",
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
    Suite(
        "m5c5",
        [CRATE, EXPORT, FIXTURE],
        C4_CARGO_TEST,
        CASES_C5,
        build=C4_BUILD,
    ),
    Suite(
        "m5c6",
        [CRATE, EXPORT, FIXTURE],
        C4_CARGO_TEST,
        CASES_C6,
        build=C4_BUILD,
    ),
    # The parameter pin spans three crates: the table lives in
    # `tunnel-http-forward`, the payload builder in `tunnel-cua`, and the
    # ledger that judges a drag in `tunnel-cua-fixture`. A run that omitted
    # `tunnel-http-forward` would report `still green` for both table cases.
    Suite(
        "m5c7",
        [CRATE, FORWARD, FIXTURE],
        C7_CARGO_TEST,
        CASES_C7,
        build=C4_BUILD,
    ),
    # Chunk 8 defeats `availability()` in `tunnel-deadman`, so that crate is
    # in the restore set; the control it must turn red lives in
    # `tunnel-cua-fixture`, which `C4_CARGO_TEST` runs.
    Suite(
        "m5c8",
        [CRATE, EXPORT, FIXTURE, DEADMAN],
        C4_CARGO_TEST,
        CASES_C8,
        build=C4_BUILD,
    ),
    # `m5-code`. The export crate is in the test set because the supervision
    # tests in `tunnel-cua-fixture` drive it, and in the restore set only for
    # symmetry with `m5c8`; no case here mutates it.
    Suite(
        "m5c9",
        [CRATE, EXPORT, FIXTURE],
        C4_CARGO_TEST,
        CASES_C9,
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
                    "m5-guard-deletion: refusing to run with uncommitted changes "
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
#: **Empty for suites `m5c2`..`m5c8`, and deliberately so (task row M4-23);
#: `m5c9` is written with its witnesses from the start.**  A witness is a
#: measurement -- the test that actually reddens when *this* guard is deleted,
#: one `cargo test` per case -- and it cannot be read off the case's text.
#: Filling this in by writing a plausible test name beside each case would
#: produce a harness that checks 100 guesses and reports them as attribution,
#: which is the defect this mechanism exists to remove, with the added harm
#: that the run would now *claim* to have been attributed.
#:
#: So every case here is named in `scripts/guard_witness_debt.json` instead,
#: keeps the old unattributed classification, and is reported as owing a
#: witness.  Moving a case out of that ledger and into this table is the unit
#: of progress; the ledger can only shrink, and a case may not appear in both.
WITNESSES: dict[tuple[str, str], frozenset[str]] = {
    # `m5c9` is the first suite in this harness written with its witnesses,
    # each measured by running the case and reading which test reddened.
    (
        "m5c9",
        "M5-C05: learning a grant revision frees the lease it superseded in the same step",
    ): frozenset(
        {"a_revoked_grant_stops_the_lease_being_honoured_the_moment_the_device_learns_of_it"}
    ),
    (
        "m5c9",
        "M5-C12: a display no pinned backend can select is refused before dispatch",
    ): frozenset(
        {
            "plan::tests::a_display_no_pinned_backend_can_select_is_refused_before_dispatch",
            "the_ledger_equals_the_commands_that_were_dispatched_and_nothing_more",
        }
    ),
    (
        "m5c9",
        "M5-C13: a scroll that names a position is refused rather than validated and dropped",
    ): frozenset(
        {
            "plan::tests::a_scroll_that_names_a_position_is_refused_rather_than_silently_not_honoured"
        }
    ),
    (
        "m5c9",
        "M5-C14: a capture with no declared scale refuses a coordinate at resolution",
    ): frozenset(
        {"capture::tests::an_undeclared_scale_is_refused_at_resolution_and_never_defaulted"}
    ),
    (
        "m5c9",
        "M5-C14: an undeclared scale is never defaulted to 1x in the conversion",
    ): frozenset(
        {"capture::tests::an_undeclared_scale_is_refused_at_resolution_and_never_defaulted"}
    ),
    (
        "m5c9",
        "M5-C14: the device records an undeclared scale rather than assuming 1x",
    ): frozenset({"a_capture_whose_scale_nobody_declared_refuses_every_coordinate"}),
    (
        "m5c9",
        "M5-C14: capture dimensions are read from the PNG the released server sends",
    ): frozenset({"a_capture_identity_and_its_display_scale_flow_into_the_click"}),
    (
        "m5c9",
        "M5-C14: a PNG header whose CRC does not match is refused",
    ): frozenset({"image::tests::every_malformed_header_is_refused_by_name"}),
    (
        "m5c9",
        "M5-04: a cancellation after writing began is unknown, never not dispatched",
    ): frozenset({"a_cancelled_click_reports_what_is_known_and_is_never_repeated"}),
    (
        "m5c9",
        "M5-C05: ending a session releases the leases it holds",
    ): frozenset({"ending_a_session_releases_its_lease_and_only_its_lease"}),
}

#: The pinned ledger, loaded once.
DEBT = load_witness_debt('m5-guard-deletion')



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
        "m5-guard-deletion",
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
        "m5-guard-deletion",
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
        help="run only this suite (m5c2, m5c3, m5c4, m5c5, m5c6, m5c7 or m5c8)",
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
    if arguments.check_anchors:
        # **M4-36.**  Read-only mode is a path without write capability,
        # not a branch in `main()`.  `read_only_entry` resolves the
        # anchors inside a scope in which `Path.write_text`, a writing
        # `Path.open`, `Path.unlink`, `os.replace` and `subprocess.run`
        # all raise, so a deletion loop that becomes reachable from here
        # raises on its first mutation and names itself instead of
        # running the destructive suite to completion and exiting 0.
        return read_only_entry(
            'm5-guard-deletion',
            _anchor_selection(selected),
        )
    if not selected:
        sys.exit(f"m5-guard-deletion: no case matches {arguments.case!r}")

    # **M5-C07, before anything is edited.**  `require_clean_tree` below
    # refuses on a dirty tree, which already stops a second run stacking on a
    # resident mutation -- but it can only say "something is uncommitted",
    # about a tree the operator may believe they dirtied themselves.  This
    # names the harness, suite, case and files a previous interrupted run left
    # mutated, because a resident mutation is a guard deleted from the product
    # and not a tidying job.  Placed *after* the `--check-anchors` dispatch so
    # read-only mode stays a pure anchor check (M4-34, M4-36).
    # **M4-26, before anything else.**  Git writes `index.lock` and renames
    # it over `index`, so a process killed in that window loses the index --
    # and with no index every check that would notice a resident mutation
    # reports clean: `git status --porcelain` calls tracked files untracked,
    # and `git diff -- crates/` compares against nothing. This refuses rather
    # than running blind.
    require_git_index("m5-guard-deletion", REPO)
    refuse_resident_mutation("m5-guard-deletion", REPO)
    require_witnesses(selected)
    require_clean_tree(suites)

    # **Preflight (M4-27).**  Resolve every selected case's anchors before any
    # case executes, and fail closed listing *all* mismatches at once.  The
    # per-case refusal in the loop below already fails the run and names
    # itself, so this changes no outcome and no count -- it moves an existing
    # refusal from the end of a multi-hour run to its first second.  This is
    # the loop the row names as the shape the preflight belongs in.
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
        with AppliedCase("m5-guard-deletion", REPO, suite.name, name) as applied:
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
        f"\nm5-guard-deletion: {attributed} red(s) were attributed to the test the "
        f"case declares; {unattributed} were credited to any failure in the "
        "suite's surface, because those cases do not yet name a witness "
        "(task row M4-23). An unattributed red is not evidence that this "
        "guard is load-bearing."
    )

    # **M4-26, again.**  The index loss that matters happens *mid-run*: a
    # check only at the start would certify an index that was gone by the
    # end, and a count from a run whose index state was not confirmed is not
    # a measurement.
    require_git_index("m5-guard-deletion", REPO)

    unusable = unusable_outcomes(
        (suite_name, name, outcome) for suite_name, name, outcome, _ in results
    )
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
