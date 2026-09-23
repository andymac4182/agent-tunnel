#!/usr/bin/env python3
"""Defeat one operator-surface guard at a time, run the tests it should
protect, and restore it.

This is the red-then-green evidence behind two of M0-03's client operator
surfaces: the exit-code vocabulary the row was opened for, and the `doctor`
report (M6-C07).  The guards live in `crates/tunnel-client/src/main.rs` and
`crates/tunnel-client/src/doctor.rs` and are witnessed by that binary's unit
tests plus the real-process fixtures in
`crates/tunnel-client/tests/exit_codes_cli.rs` and
`crates/tunnel-client/tests/doctor_cli.rs`.

**The filename says exit codes and the harness now covers more than that.**
Kept here rather than split into a second file because the witness suite is
the same one -- `cargo test -p tunnel-client` builds and runs every target
both surfaces are witnessed by -- and a harness that names a different
package than the tests it runs is the M3-19 failure this whole family of
scripts exists to avoid.  A second file would have had to duplicate the
suite definition to avoid duplicating nothing.

**What the row is about.** `CliError::exit_code` used to match `&'static str`
with a `_ => 1` arm.  Six live causes had no entry in that table, so they
exited `1`, "unexpected internal failure" -- including `OWNER_BUSY` (another
connector already holds the device) and `CANCELLED` (the session was
interrupted).  Those need different operator actions and the process's exit
status, the first thing a supervisor or a tester reads, said the same thing
about all of them.  The fix replaces the string table with a closed `Cause`
enum matched exhaustively.

**Two kinds of case live here, and the distinction is the point.**

* Cases marked `expect_build_failure` are the *totality* rule.  Removing an
  arm from `Cause::exit_code`, `Cause::code` or `Cause::from_client` makes
  the match non-exhaustive, and the crate does not compile.  These are
  reported as `REFUSED BY COMPILER` and are **never counted as a red test**:
  a build failure names no behaviour, and counting it as one would credit the
  guard for a failure that says nothing.  They are still worth running,
  because a `_` arm reintroduced anywhere would turn the refusal into a
  silent green -- which is the original defect returning.
* Every other case edits a *value* the compiler cannot check -- which number
  a cause maps to, which string it publishes, whether a transport detail is
  appended to a message -- and must turn **the test it names** red.  Each
  such case declares `expected_red`, and a run in which those tests are not
  among the failures reports `RED (wrong witness)`, which is not a usable
  outcome and fails the run.  This is stricter than the other four harnesses
  here, which accept any named failure; see `Case` for the measured reason.

**One rule is deliberately not here.**  Exit `6` (`OUTCOME_UNKNOWN`) is
documented in `docs/runtime.md` and has no producer in this binary, so there
is nothing to defeat.  A case for it would have to add the producer first,
and an addition is not a deletion: it would measure the case's own code.
The gap is named in `docs/runtime.md` and in M0-03 instead of being faked
here.

It follows `scripts/m3-guard-deletion.py`, `scripts/acp-guard-deletion.py`,
`scripts/fs-guard-deletion.py` and `scripts/m5-guard-deletion.py`,
**including their refusals, none of which may be removed**:

1. `run_tests` will not call a failed build a red test.
2. A case whose `old` text is not unique in its file is refused outright
   rather than applied to the first match.
3. A run that timed out returns `NOT EVIDENCE (timed out)`, not `RED (hung)`.

and adds a fourth of its own:

4. A red test that is not the one the case named is `RED (wrong witness)`,
   and a value case that names no test at all is refused before any file is
   edited.

The classification of those outcomes lives in `scripts/guard_outcomes.py`,
shared with the other harnesses, and is an allow list: everything that is not
a usable outcome fails closed.

Usage:

    python3 scripts/m0-guard-exit-codes.py            # every case
    python3 scripts/m0-guard-exit-codes.py --list
    python3 scripts/m0-guard-exit-codes.py --check-anchors
    python3 scripts/m0-guard-exit-codes.py --case owner
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
CLIENT = REPO / "crates" / "tunnel-client"

MAIN = CLIENT / "src" / "main.rs"
LIB = CLIENT / "src" / "lib.rs"
DOCTOR = CLIENT / "src" / "doctor.rs"
CREDENTIALS = CLIENT / "src" / "credentials.rs"
CLIENT_LIB = CLIENT / "src" / "lib.rs"

#: The whole client suite.  It is seconds long, and the guards here are
#: witnessed by both the binary's unit tests and the process fixtures, which
#: are separate test targets: naming one target would silently drop the other
#: half of the evidence.  `--no-fail-fast` so every red test is named.
CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-client",
    "--locked",
    "--no-fail-fast",
]

#: The fixtures in `exit_codes_cli.rs` `exec` the built `tunnel-client`
#: binary, so the binary must be rebuilt before each case.  `cargo test -p`
#: does build this package's own binaries for its integration tests, so this
#: is belt and braces rather than the M3-19 situation -- but it is cheap, and
#: the failure it prevents (a case reported as `still green` because the
#: measurement ran against a stale executable) is the one that makes a
#: harness worse than no harness.
CARGO_BUILD_BINARIES = [
    "cargo",
    "build",
    "--locked",
    "-p",
    "tunnel-client",
    "--bins",
]

# An edit is (file, exact text to remove or replace, replacement).
Edit = tuple[Path, str, str]


@dataclass(frozen=True)
class Case:
    """One defeated guard, and the test that must notice.

    **`expected_red` is the reason this is a class and not the 3-tuple the
    other four harnesses use.**  Those harnesses classify a case as `RED` on
    *any* named failing test, so a case can be green-lit by a test that has
    nothing to do with the rule it claims to prove.  That is not theoretical
    here: the redaction case below was first written with a single edit and
    reported `RED` -- against an unrelated `m2_runtime` rotation test, while
    the fixture it existed for stayed green.  It was caught only because the
    wrong witness happened to be *visibly* unrelated.  A wrong witness that
    reddens something plausible is invisible, and a tally of such cases reads
    exactly like a tally of real ones.

    So every value case names the test(s) that must be among the failures.
    If they are not, the outcome is `RED (wrong witness)`, which is not in
    `guard_outcomes.USABLE_OUTCOMES` and therefore fails the run.  A value
    case with no declared witness is refused before anything is edited.

    `expect_build_failure` cases declare none: a build failure names no test,
    and requiring one would be incoherent.
    """

    name: str
    edits: list[Edit]
    expected_red: frozenset[str] = frozenset()
    expect_build_failure: bool = False


CASES: list[Case] = [
    # ------------------------------------------- the distinctions themselves
    Case(
        # The headline case.  This *is* the old behaviour: before this row,
        # `OWNER_BUSY` fell through `_ => 1`.  A tester who started a second
        # connector saw "unexpected internal failure" and had no way to learn
        # that the answer was to stop the first one.
        "a held owner slot is not reported as an internal failure",
        [
            (
                MAIN,
                "            Self::OwnerBusy | Self::ResourceExhausted => 7,",
                "            Self::OwnerBusy | Self::ResourceExhausted => 1,",
            )
        ],
        # The rule is that a held owner slot is not an internal failure, so
        # the witnesses are the two tests that say exactly that.
        frozenset(
            {
                "tests::causes_needing_different_actions_do_not_share_an_exit_code",
                "tests::owner_busy_cli_diagnostic_is_terminal_and_actionable",
            }
        ),
    ),
    Case(
        # Also the old behaviour.  An interrupted session is the single most
        # common non-success outcome a foreground `connect` has, and it was
        # indistinguishable from a crash.
        "an interrupted session is not reported as an internal failure",
        [(MAIN, "            Self::Cancelled => 130,", "            Self::Cancelled => 1,")],
        # Since M6-C23/M6-C27 the status also has a process-level witness: a
        # real `connect` stopped during its handshake must exit 130, and the
        # unit test alone could not show that value reaching `$?`.  Measured
        # red in the first run of the new stop-request cases (log nonce
        # `m6c23-m0guard-20260923T011929Z-10280`).
        frozenset(
            {
                "tests::causes_needing_different_actions_do_not_share_an_exit_code",
                "sigterm_during_the_tls_handshake_exits_cancelled",
            }
        ),
    ),
    Case(
        # A stale authorization is an authorization decision, not a bug.  The
        # documented meaning of `3` is "untrusted credentials / authorization
        # denied"; putting this at `1` tells an operator to file a defect
        # report instead of re-authorizing.
        "a stale authorization is reported as an authorization failure",
        [
            (
                MAIN,
                "            Self::CredentialError | Self::AuthorizationStale => 3,",
                "            Self::CredentialError => 3,\n            Self::AuthorizationStale => 1,",
            )
        ],
        frozenset({"tests::causes_needing_different_actions_do_not_share_an_exit_code"}),
    ),
    Case(
        # The one non-doctor status any fixture in this repository can reach
        # on a real process.  Defeating it is what proves
        # `a_refused_relay_connection_exits_four_and_names_the_transport` can
        # redden **for the reason it names** rather than merely being green:
        # the `ExitCode::from` plumbing between `Cause::exit_code` and the
        # caller's `$?` has no other witness.
        "the chosen exit code reaches the process exit status",
        [
            (
                MAIN,
                "            Self::TransportError | Self::SessionClosed => 4,",
                "            Self::TransportError | Self::SessionClosed => 1,",
            )
        ],
        # **The witness is the process fixture, and declaring it is the whole
        # point of this case.**  The same edit also reddens the unit test
        # `every_client_error_variant_maps_to_an_actionable_exit_code`, so
        # without a declared witness this case would report `RED` even if the
        # process fixture were deleted -- and the `ExitCode::from` plumbing,
        # which nothing else witnesses, would be uncovered and look covered.
        frozenset({"a_refused_relay_connection_exits_four_and_names_the_transport"}),
    ),
    # ------------------------------------------------ the published vocabulary
    Case(
        # The exit code is what a script reads; the code string is what a
        # human and a log search read.  They are separate surfaces and both
        # have to be pinned, or a mapping can be "fixed" in one and left
        # wrong in the other.
        "the published diagnostic code is not interchangeable with another",
        [
            (
                MAIN,
                '            Self::OwnerBusy => "OWNER_BUSY",',
                '            Self::OwnerBusy => "SUPERVISOR_FAILED",',
            )
        ],
        # The code string, not the number: the test that asserts
        # `code() == "OWNER_BUSY"`, plus the cross-crate parity assertion
        # this edit also breaks.
        frozenset(
            {
                "tests::owner_busy_cli_diagnostic_is_terminal_and_actionable",
                "tests::the_cli_and_the_library_publish_the_same_diagnostic_code",
            }
        ),
    ),
    # -------------------------------------------------------- the redaction
    Case(
        # **Redaction is the hard constraint on these surfaces.**  An error
        # message's whole job is to describe internal state, so it is exactly
        # where a backend error escapes.
        #
        # **This case applies two edits, and the reason is a measurement.**
        # It was first written with only the second edit -- appending `detail`
        # to the generic transport arm -- and the run reported `RED` against
        # an unrelated `m2_runtime` rotation test while the redaction fixture
        # it was written for **stayed green**.  A case that reddens something
        # other than the rule it names is not evidence for that rule, so the
        # first edit was found by probing rather than assumed: `sanitize_error`
        # discards the underlying error at construction, so with it intact the
        # appended `detail` is the constant `"transport failure"` and nothing
        # leaks.  The redaction here is genuinely two independent layers, and
        # only defeating both puts `IO error: Connection refused (os error 61)`
        # in front of an operator.
        #
        # It must redden `assert_transport_message_is_bounded`, which is the
        # assertion in that fixture that can redden at all.  The endpoint and
        # path entries in `assert_redacted` cannot: this error path does not
        # produce them even fully unredacted, and the fixture says so rather
        # than letting them read as coverage.
        "a transport failure does not print the underlying backend error",
        [
            (
                LIB,
                '    let _ = error;\n    "transport failure".to_owned()',
                "    error.to_owned()",
            ),
            (
                LIB,
                '            Self::Transport { scope, .. } => format!("{scope} failed"),',
                '            Self::Transport { scope, detail } => format!("{scope} failed: {detail}"),',
            ),
        ],
        frozenset({"a_refused_relay_connection_exits_four_and_names_the_transport"}),
    ),
    # ------------------------------------------------ the shared vocabulary
    Case(
        # The cross-crate rule, and the one this row got wrong before a
        # reviewer would have.  `CLI_DIAGNOSTIC_EXIT_CODES` is what the
        # production-cluster chaos gate classifies a connector's
        # pre-readiness exit against.  A cause mapped to a status outside it
        # is classified `Unclassified`, which blocks release -- and until
        # this row the gate held its *own copy* of the list, so the drift
        # was invisible on both sides.  Mapping to an unpublished status
        # must fail in the connector's own tests, not at a release gate
        # hours later.
        "an exit status outside the published vocabulary is refused",
        [
            (
                MAIN,
                "            Self::OwnerBusy | Self::ResourceExhausted => 7,",
                "            Self::OwnerBusy | Self::ResourceExhausted => 9,",
            )
        ],
        frozenset({"tests::every_exit_status_is_in_the_published_vocabulary"}),
    ),
    # ------------------------------------------------- the doctor's report
    Case(
        # **M6-C07, and the surface an outside tester reads first.**  `doctor`
        # computes `supervisor_ipc` and `process_containment` before it even
        # attempts to load the configuration, and used to throw the whole
        # `DoctorResult` away whenever an error was present -- so a machine
        # nobody had provisioned yet, which is every fresh install, got
        # `result: null` and could not read the one surface that says whether
        # process containment is available.
        #
        # **This edit isolates "on a failing run" rather than blanking the
        # checks outright.**  Blanking them unconditionally would also redden
        # the success fixtures, and a case that reddens the happy path proves
        # nothing about the failing one.  The `..result` update syntax keeps
        # every other check intact, so the only thing the witnesses can be
        # reacting to is the capability report going missing on error.
        "a failing run still reports the host capability checks",
        [
            (
                DOCTOR,
                "            ok,\n            result,\n            error,",
                "            ok,\n"
                "            result: if ok {\n"
                "                result\n"
                "            } else {\n"
                "                DoctorResult {\n"
                "                    supervisor_ipc: CapabilityCheck {\n"
                '                        status: "not_run",\n'
                '                        code: "NOT_RUN",\n'
                "                    },\n"
                "                    process_containment: CapabilityCheck {\n"
                '                        status: "not_run",\n'
                '                        code: "NOT_RUN",\n'
                "                    },\n"
                "                    ..result\n"
                "                }\n"
                "            },\n"
                "            error,",
            )
        ],
        # Both layers, deliberately.  The unit test proves the in-process
        # shape; the four process fixtures prove it survives serialization to
        # the stdout an actual tester reads, which is the only place the
        # defect was ever visible.  Naming one layer would let the other be
        # deleted without this case noticing.
        frozenset(
            {
                "doctor::tests::"
                "invalid_configuration_is_exit_two_and_does_not_inspect_credentials",
                "doctor_binary_rejects_invalid_configuration_with_exit_two",
                "doctor_binary_redacts_missing_credential_and_returns_exit_three",
                "doctor_binary_returns_exit_three_for_permissive_private_key",
                "doctor_binary_returns_exit_three_for_permissive_credential_directory",
            }
        ),
    ),
    # ------------------------------------------- stop requests (M6-C23/C27)
    Case(
        # **M6-C23.**  SIGTERM is what systemd and launchd send to stop a
        # service.  Before this row nothing handled it, and a service stop
        # killed the connector with no output and no `stopped` event.
        # Listening for a signal nobody sends in its place is that defect:
        # SIGTERM keeps its default action (or its inherited `SIG_IGN`).
        "SIGTERM reaches the orderly stop path",
        [
            (
                MAIN,
                "                terminate: signal(SignalKind::terminate()).map_err(signal_error)?,",
                "                terminate: signal(SignalKind::user_defined2()).map_err(signal_error)?,",
            )
        ],
        # Every SIGTERM fixture, and only those: the default-disposition ones
        # die by the signal (no exit status), the inherited-ignored one runs
        # out the 10 s handshake deadline and exits 5.
        frozenset(
            {
                "sigterm_during_the_tls_handshake_exits_cancelled",
                "sigterm_during_the_websocket_upgrade_exits_cancelled",
                "sigterm_inherited_as_ignored_still_cancels_the_handshake",
                "sigterm_without_json_reports_the_cancellation_on_stderr",
            }
        ),
    ),
    Case(
        # The same rule for SIGINT, which `ctrl_c()` already covered -- but
        # only after the session was ready.
        "SIGINT reaches the orderly stop path",
        [
            (
                MAIN,
                "                interrupt: signal(SignalKind::interrupt()).map_err(signal_error)?,",
                "                interrupt: signal(SignalKind::user_defined1()).map_err(signal_error)?,",
            )
        ],
        frozenset(
            {
                "sigint_during_the_tls_handshake_exits_cancelled",
                "sigint_during_the_websocket_upgrade_exits_cancelled",
                "sigint_inherited_as_ignored_still_cancels_the_handshake",
            }
        ),
    ),
    Case(
        # **M6-C27's mechanism, restored exactly.**  The handlers are still
        # installed, but nothing listens for them until the session is ready
        # -- the pre-fix shape, where the `ctrl_c` select was armed only after
        # `connect_with_http_handlers` returned.  A signal during the
        # handshake is then swallowed and the run ends at the 10 s deadline
        # with exit 5 `DEADLINE_EXCEEDED`.
        "a stop request during the handshake is listened for",
        [
            (
                MAIN,
                "        signal = stop.recv() => {\n            let signal = signal?;\n            // Cancel, then",
                "        signal = std::future::pending::<Result<StopSignal, CliError>>() => {\n            let signal = signal?;\n            // Cancel, then",
            )
        ],
        frozenset(
            {
                "sigterm_during_the_tls_handshake_exits_cancelled",
                "sigterm_during_the_websocket_upgrade_exits_cancelled",
                "sigterm_inherited_as_ignored_still_cancels_the_handshake",
                "sigterm_without_json_reports_the_cancellation_on_stderr",
                "sigint_during_the_tls_handshake_exits_cancelled",
                "sigint_during_the_websocket_upgrade_exits_cancelled",
                "sigint_inherited_as_ignored_still_cancels_the_handshake",
            }
        ),
    ),
    Case(
        # **The timing assertion's own case.**  A handler that reports
        # `CANCELLED` but never cancels the attempt still exits 130 -- after
        # the 2 s bounded unwind rather than at once.  Only the "promptly"
        # assertion can see that, so this is the case that proves it is not
        # decoration: without it every fixture here would stay green.
        "a stop request cancels the connect attempt rather than waiting it out",
        [
            (
                MAIN,
                "            cancellation.cancel();\n            match bounded(&mut connect",
                "            match bounded(&mut connect",
            )
        ],
        frozenset(
            {
                "sigterm_during_the_tls_handshake_exits_cancelled",
                "sigterm_during_the_websocket_upgrade_exits_cancelled",
                "sigterm_inherited_as_ignored_still_cancels_the_handshake",
                "sigterm_without_json_reports_the_cancellation_on_stderr",
                "sigint_during_the_tls_handshake_exits_cancelled",
                "sigint_during_the_websocket_upgrade_exits_cancelled",
                "sigint_inherited_as_ignored_still_cancels_the_handshake",
            }
        ),
    ),
    Case(
        # **The M6-C23 review's first finding.**  Every wait on the stop path
        # -- the drain join, the pre-ready unwind, the MCP reap wait, the
        # closed-session join -- goes through `bounded`, whose first arm is
        # the next stop request.  With that arm never firing, a second
        # SIGINT or SIGTERM no longer ends a wait: the operator is back to
        # `SIGKILL`.
        "a second stop request ends every wait on the stop path",
        [
            (
                MAIN,
                "        second = next_stop => Ok(Bounded::Interrupted(second?)),",
                "        second = std::future::pending::<Result<StopSignal, CliError>>() => Ok(Bounded::Interrupted(second?)),",
            )
        ],
        frozenset(
            {
                "tests::a_second_stop_during_the_reap_wait_exits_cancelled_promptly",
                "tests::a_second_stop_during_a_hung_join_exits_cancelled_promptly",
            }
        ),
    ),
    Case(
        # "Nothing may wait forever": the same waits with their bound
        # stretched far past the test's patience.  The hung-join test then
        # waits out the stretched bound and reddens on its timing assertion.
        "a wait on the stop path is bounded",
        [
            (
                MAIN,
                "        result = tokio::time::timeout(bound, work) => {",
                "        result = tokio::time::timeout(bound * 30, work) => {",
            )
        ],
        frozenset({"tests::a_stop_whose_join_hangs_exits_cancelled_within_the_bound"}),
    ),
    # ------------------------------------------------- totality, by compiler
    Case(
        # **The structural half of M6-C07, and the reason the fix was a type
        # change rather than a value change.**  `DoctorOutput::result` is not
        # an `Option`: `DoctorResult` already carries a per-check `not_run`
        # status, so "this check did not run" is expressible inside the
        # struct, and an outer `Option` is a second, coarser way to say the
        # same thing whose only additional power is to discard the checks
        # that *did* run.  Restoring the `Option` makes `inspection()` fail to
        # type-check, so the original `if ok { Some(result) } else { None }`
        # cannot be reintroduced by editing a value.  Reported as a compiler
        # refusal and never counted as a red test.
        "the doctor's result cannot be made optional again",
        [
            (
                DOCTOR,
                "    pub(crate) result: DoctorResult,",
                "    pub(crate) result: Option<DoctorResult>,",
            )
        ],
        expect_build_failure=True,
    ),
    Case(
        # **M6-C25, restored exactly.**  Every refusal of the certificate by
        # the TLS stack becomes a key mismatch again and the version check is
        # gone, so a v1 certificate whose key matches is reported as
        # "does not match its private key" -- what `credentials import`
        # printed before the row.
        "a v1 certificate is not reported as a key mismatch",
        [
            (
                CREDENTIALS,
                "    if version != x509_parser::x509::X509Version::V3 {",
                "    if version != version {",
            ),
            (
                CREDENTIALS,
                "        Err(error) => Err(CredentialError::CertificateRefused(error.to_string())),",
                "        Err(error) => Err(CredentialError::KeyMismatch(error.to_string())),",
            ),
        ],
        frozenset(
            {
                "credentials::tests::"
                "a_v1_certificate_is_refused_for_its_version_not_as_a_key_mismatch"
            }
        ),
    ),
    Case(
        # **M6-C42, restored exactly.**  The doctor's key-match check reports
        # any refusal as `CREDENTIAL_KEY_MISMATCH`, as it did when it called
        # `CertifiedKey::from_der` and discarded the error.
        "the doctor reports only a real key mismatch as one",
        [
            (
                DOCTOR,
                "        Err(error) => failed(credential_code(&error)),",
                '        Err(_) => failed("CREDENTIAL_KEY_MISMATCH"),',
            )
        ],
        frozenset({"doctor::tests::an_unusable_certificate_is_invalid_not_a_key_mismatch"}),
    ),
    Case(
        # **M6-C32.**  The relay's identity refusal is left unclassified, so
        # the device reports the close as a retryable transport loss -- the
        # row's measured symptom, and what an automatic reconnect would
        # retry forever.  The process-level half of this rule needs a relay
        # and Redis and is run by `scripts/m6-provisioning-verify.sh`.
        "the relay's identity refusal is a terminal credential error",
        [
            (
                CLIENT_LIB,
                "        && &*frame.reason == CONTROL_IDENTITY_REJECTED_CLOSE_REASON)",
                '        && &*frame.reason == "defeated")',
            )
        ],
        frozenset({"tests::an_identity_rejected_close_is_a_non_retryable_credential_error"}),
    ),
    Case(
        # The rule that replaced the string table.  Removing an arm leaves
        # the match non-exhaustive and the crate does not build.  Reported
        # separately and never counted as a red test.
        "every cause must state an exit code or the crate does not compile",
        [
            (
                MAIN,
                "            Self::DeadlineExceeded => 5,\n",
                "",
            )
        ],
        expect_build_failure=True,
    ),
    Case(
        # The same rule for the classification of connector errors.  A new
        # `ClientError` variant cannot reach the CLI unclassified.
        "every connector error must be classified or the crate does not compile",
        [
            (
                MAIN,
                "            ClientError::OwnerBusy => Self::OwnerBusy,\n",
                "",
            )
        ],
        expect_build_failure=True,
    ),
]


@dataclass
class Suite:
    name: str
    crates: list[Path]
    cargo_test: list[str]
    cases: list[Case] = field(default_factory=list)
    cwd: Path = REPO


#: A second suite, for the rule whose witness lives in the production-cluster
#: harness rather than in the connector.  It is separate because it names a
#: different package: `cargo test -p tunnel-client` builds no test target of
#: `tunnel-test-harness`, so a case edited into the classifier would be run
#: against nothing at all and reported as `still green` -- the M3-19 failure.
HARNESS = REPO / "crates" / "tunnel-test-harness"
CHAOS = HARNESS / "src" / "production_cluster" / "chaos.rs"

HARNESS_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "--no-fail-fast",
    "production_cluster::chaos::tests::a_pre_readiness",
]

HARNESS_CASES: list[Case] = [
    Case(
        # The other half of the cross-crate rule.  A classifier that accepts
        # every status classifies a signal death and a spurious success as
        # interruptions, which is worse than the drift it replaced: the gate
        # would report a clean run through exactly the failures it exists to
        # catch.  The `Some(9)` and `Some(-1)` assertions are what stop it.
        "the exit classifier does not accept every status",
        [
            (
                CHAOS,
                "            if u8::try_from(code)\n                .is_ok_and(|code| tunnel_client::CLI_DIAGNOSTIC_EXIT_CODES.contains(&code)) =>",
                "            if u8::try_from(code).is_ok_and(|_| true) =>",
            )
        ],
        frozenset(
            {
                "production_cluster::chaos::tests::"
                "a_pre_readiness_cli_exit_is_classified_only_for_typed_exit_codes"
            }
        ),
    ),
]

SUITES: list[Suite] = [
    Suite("m0c03-exit-codes", [CLIENT], CARGO_TEST, CASES),
    Suite("m0c03-classifier", [HARNESS], HARNESS_TEST, HARNESS_CASES),
]

#: Cases whose green result is itself the measurement.  Empty today, and kept
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
        built = subprocess.run(
            CARGO_BUILD_BINARIES,
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
                    "m0-guard-exit-codes: refusing to run with uncommitted changes "
                    f"under {relative}; a case applied on top of them could not "
                    "be told apart from them, and the run would report a guard "
                    "as load-bearing on the strength of somebody else's edit. "
                    "Each case is restored by writing back the exact bytes it "
                    "recorded (M5-C07), so these changes would survive a run -- "
                    "but the evidence would not be trustworthy."
                )



def _anchor_selection(selected):
    """Every selected case reduced to `(suite, case, edits)`.

    Shared by the preflight and by the read-only `--check-anchors` entry, so
    the two cannot drift into checking different sets -- which is the class of
    mistake M4-36 is about.
    """
    return [(suite.name, case.name, case.edits) for suite, case in selected]


def check_anchors(selected: list[tuple[Suite, Case]]) -> int:
    """Resolve every selected case's guard text, and stop (M4-27)."""
    return shared_check_anchors(
        "m0-guard-exit-codes",
        _anchor_selection(selected),
    )


def require_witnesses(selected: list[tuple[Suite, Case]]) -> None:
    """Refuse a value case that names no test, before anything is edited.

    The refusal is the half that makes the mechanism hold: without it
    `expected_red` is opt-in, and a case added with the field omitted falls
    back silently to the "any red will do" behaviour it exists to reject.

    This harness's own copy of the rule moved into `guard_outcomes` when
    M4-23 gave the other three harnesses the same mechanism -- one copy, so
    the next fix cannot be applied to some of them and not the rest.
    """
    require_declared_witnesses(
        'm0-guard-exit-codes',
        (
            (suite.name, case.name, case.expect_build_failure, case.expected_red)
            for suite, case in selected
        ),
        DEBT,
    )


#: This harness owes no witnesses: every value case declares one.
DEBT = load_witness_debt('m0-guard-exit-codes')


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
    parser.add_argument("--suite", help="run only this suite (m0c03-exit-codes, m0c03-classifier)")
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
            sys.exit(f"m0-guard-exit-codes: no suite named {arguments.suite!r}")
    selected = [
        (suite, case)
        for suite in suites
        for case in suite.cases
        if not arguments.case or arguments.case in case.name
    ]
    if arguments.list:
        for suite, case in selected:
            witnesses = ", ".join(sorted(case.expected_red)) or "(compiler refusal)"
            print(f"{suite.name}: {case.name} -> {witnesses}")
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
            'm0-guard-exit-codes',
            _anchor_selection(selected),
        )
    if not selected:
        sys.exit(f"m0-guard-exit-codes: no case matches {arguments.case!r}")

    # M5-C07, before anything is edited: name the harness, suite, case and
    # files a previous interrupted run left mutated.  Placed after the
    # `--check-anchors` dispatch so read-only mode stays a pure anchor check
    # (M4-34, M4-36).
    # **M4-26, before anything else.**  Git writes `index.lock` and renames
    # it over `index`, so a process killed in that window loses the index --
    # and with no index every check that would notice a resident mutation
    # reports clean: `git status --porcelain` calls tracked files untracked,
    # and `git diff -- crates/` compares against nothing. This refuses rather
    # than running blind.
    require_git_index("m0-guard-exit-codes", REPO)
    refuse_resident_mutation("m0-guard-exit-codes", REPO)
    require_witnesses(selected)
    require_clean_tree(suites)

    # Preflight (M4-27): resolve every selected case's anchors before any
    # case executes, and fail closed listing all mismatches at once.
    if check_anchors(selected) != 0:
        return 1

    results: list[tuple[str, str, str, list[str]]] = []
    for suite, case in selected:
        name = case.name
        with AppliedCase("m0-guard-exit-codes", REPO, suite.name, name) as applied:
            problem = applied.apply_all(case.edits)
            if problem is not None:
                results.append((suite.name, name, f"COULD NOT APPLY: {problem}", []))
                print(f"[{suite.name}] {name}: {problem}", flush=True)
                continue
            outcome, failures = run_tests(suite)
        # **M4-23.**  The witness check this harness has always carried,
        # now the shared rule all five use.  `RED` means *something* failed;
        # it does not mean the rule this case names was what noticed, and an
        # outcome spelt `RED (wrong witness)` is absent from
        # `guard_outcomes.USABLE_OUTCOMES`, so it fails the run rather than
        # being counted as evidence for a rule it did not test.
        outcome = classify_outcome(
            outcome,
            failures,
            documented_green=name in EXPECT_GREEN,
            expect_build_failure=case.expect_build_failure,
            expected_red=case.expected_red,
            owed_witness=False,
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
            f"\n{suite.name}: {red} of {measurable} defeated guards turned "
            "the test they named red"
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

    # **M4-26, again.**  The index loss that matters happens *mid-run*: a
    # check only at the start would certify an index that was gone by the
    # end, and a count from a run whose index state was not confirmed is not
    # a measurement.
    require_git_index("m0-guard-exit-codes", REPO)

    unusable = unusable_outcomes(
        (suite_name, name, outcome) for suite_name, name, outcome, _ in results
    )
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
