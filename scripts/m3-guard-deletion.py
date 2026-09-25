#!/usr/bin/env python3
"""Defeat one process-containment guard at a time, run the tests it should
protect, and restore it.

This is the red-then-green evidence behind M3-09.  Two suites live here
(later suites -- M6-C08's doctor, M3-25's pin wait, M7-C89's readiness
against the pin set and M7-C92/M7-C93's finite echo -- are described where
they are defined):

* `m3c09` — `crates/tunnel-deadman` and the stdio export's child supervision
  in `crates/tunnel-mcp-export`, witnessed by the process-table measurements
  in `crates/tunnel-mcp-fixture/tests/process_residue.rs`: the sentinel firing
  on a bare end of file, the sentinel being armed at all, the stand-down on
  the orderly path, and the fixture's own honesty about whether it really
  detached.
* `m3c09-deadman` — the resolution rule that decides whether an installation
  is watched at all, witnessed by `tunnel-deadman`'s own unit tests.

**One rule of M3-09 is deliberately not here**, and is recorded in that row's
"Not covered" list instead: the *ordering* of the stand-down against the group
kill.  Hoisting the stand-down above the kill leaves every test in both suites
green — measured by doing it, not inferred — and the reason is not the obvious
one — on a hoist the sentinel does not
fire early, it **does not fire at all**.  `watch` returns `EXIT_STOOD_DOWN` on
the stand-down token without calling `kill_group`, so in both orderings the
group is killed by the supervisor's own `kill_group` and the sentinel exits
stood-down either way; the `deadman_stood_down` counter reads that exit status,
so it increments in both.

What the ordering really guards is a **crash window**: the hoist leaves the
group alive and unwatched between the two calls, so a `SIGKILL` of the device
inside it leaks the group.  It is microseconds wide and cannot be hit
deterministically without widening it — and widening it is an **addition**,
which a deletion case may not make.  Hence no case, rather than a case that
would pass either way and look like coverage.

**The fourth case is not like the others and is the point of having it.**  It
defeats the *fixture*, not the product: it makes the escaping descendant fail
to escape.  Every containment measurement in `process_residue.rs` is built on
a descendant that genuinely left the process group, and a fixture that quietly
stopped detaching would turn those measurements into a test of nothing while
leaving them green.  The case proves the tests refuse that fixture instead of
reporting it as containment.

It follows `scripts/acp-guard-deletion.py`, `scripts/fs-guard-deletion.py` and
`scripts/m5-guard-deletion.py`, **including their refusals, none of which may
be removed**:

1. `run_tests` will not call a failed build a red test.  A deleted guard can
   leave the crate unbuildable, and counting that as evidence would credit the
   guard for a failure that says nothing about behaviour.
2. A case whose `old` text is **not unique** in its file is refused outright
   rather than applied to the first match.  `str.replace(old, new, 1)` edits
   whichever match comes first, so an ambiguous case would defeat some *other*
   guard and report a red for it under the wrong name.
3. A run that *timed out* returns `NOT EVIDENCE (timed out)`, not `RED (hung)`:
   a timed-out run names no failing test.

The classification of those outcomes is **not in this file**.  It lives in
`scripts/guard_outcomes.py`, shared with the other harnesses, and it is an
**allow list**: everything that is not a usable outcome fails closed.

Usage:

    python3 scripts/m3-guard-deletion.py            # every case
    python3 scripts/m3-guard-deletion.py --list
    python3 scripts/m3-guard-deletion.py --case sentinel
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
DEADMAN = REPO / "crates" / "tunnel-deadman"
EXPORT = REPO / "crates" / "tunnel-mcp-export"
FIXTURE = REPO / "crates" / "tunnel-mcp-fixture"

CLIENT = REPO / "crates" / "tunnel-client"

DEADMAN_LIB = DEADMAN / "src" / "lib.rs"
CHILD = EXPORT / "src" / "child.rs"
FIXTURE_LIB = FIXTURE / "src" / "lib.rs"
DOCTOR = CLIENT / "src" / "doctor.rs"
HARNESS = REPO / "crates" / "tunnel-test-harness"
HARNESS_CLUSTER = HARNESS / "src" / "production_cluster.rs"

# Only the containment measurements: the rest of this fixture crate's suite is
# the M3-02 end-to-end work and says nothing about these guards.  --no-fail-fast
# so every red test is named.
CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-mcp-fixture",
    "--test",
    "process_residue",
    "--locked",
    "--no-fail-fast",
]

#: **A fourth refusal, and this suite is the reason it exists (task row
#: M3-19).**  The tests here do not merely link the code under test: they
#: `exec` two *binaries*, `tunnel-mcp-fixture` and `tunnel-deadman`, and read
#: the process table for what those binaries did.  `cargo test --test
#: process_residue` selects test targets, and it builds **no binary belonging
#: to another package at all** — so a case that edits `crates/tunnel-deadman`
#: is run against whatever sentinel executable happened to be lying in the
#: target directory.
#:
#: That was measured, not assumed.  The first run of this suite reported the
#: sentinel's group kill as `still green` — a guard that is the entire
#: mechanism, defeated, with nothing going red — because the deleted code was
#: never rebuilt and the binary on disk still had it.  A harness that silently
#: tests a stale artifact is worse than no harness: it reports "this guard is
#: not load-bearing" about a guard that is.
#:
#: So every case builds these binaries first, and a build failure here is a
#: build failure for the case.  **This step may not be removed to make the
#: suite faster.**
CARGO_BUILD_BINARIES = [
    "cargo",
    "build",
    "--locked",
    "-p",
    "tunnel-deadman",
    "-p",
    "tunnel-mcp-fixture",
    "--bins",
]

# An edit is (file, exact text to remove or replace, replacement).
Edit = tuple[Path, str, str]


@dataclass(frozen=True)
class Case:
    """One defeated guard, and the test that must notice.

    **`expected_red` is why this is a class rather than the 3-tuple this file
    used to carry**, and the mechanism is lifted from
    `scripts/m0-guard-exit-codes.py` rather than reinvented.  Without it a
    case is classified `RED` on *any* named failing test, so a case can be
    green-lit by a failure that has nothing to do with the rule it claims to
    prove -- and a tally of such cases reads exactly like a tally of real
    ones.  That is the M5-C11 defect class applied to the evidence itself: the
    run's success and its measuring nothing look identical.

    Every value case therefore names the test(s) that must be among the
    failures.  If they are not, the outcome is `RED (wrong witness)`, which is
    absent from `guard_outcomes.USABLE_OUTCOMES` and fails the run.  A value
    case with no declared witness is refused before anything is edited.

    `expect_build_failure` cases declare none: a build failure names no test,
    and requiring one would be incoherent.
    """

    name: str
    edits: list[Edit]
    expected_red: frozenset[str] = frozenset()
    expect_build_failure: bool = False


CASES: list[Case] = [
    # ------------------------------------------- the sentinel fires on EOF
    Case(
        # The whole mechanism.  Without this line the sentinel still starts,
        # still watches and still exits — and the group it was watching
        # outlives the supervisor exactly as it did before this chunk.  This
        # case is also the red half of M3-09's red-then-green: with it applied,
        # the measured leak is the one the row records.
        "a bare end of file makes the sentinel kill the watched process group",
        [(DEADMAN_LIB, "    kill_group(leader);\n    EXIT_FIRED", "    EXIT_FIRED")],
        # The rule is that the sentinel signals the group when the supervisor
        # dies unexpectedly, so the witness is the measurement of exactly
        # that: a SIGKILLed supervisor whose child's group is gone afterwards.
        frozenset({"a_sigkilled_supervisor_still_kills_the_group"}),
    ),
    Case(
        # Arming at spawn.  A sentinel armed late — or not at all — leaves a
        # window in which a device crash orphans the group.
        "every stdio child is watched by a parent-death sentinel",
        [
            (
                CHILD,
                "    let deadman = group.and_then(tunnel_deadman::Deadman::arm);",
                "    let deadman: Option<tunnel_deadman::Deadman> = None;",
            )
        ],
        # An unarmed supervisor leaks the group on a SIGKILL: the same
        # measurement, reached because the sentinel that would have fired was
        # never spawned at all.
        frozenset({"a_sigkilled_supervisor_still_kills_the_group"}),
    ),
    Case(
        # The orderly path.  Dropping the handle instead of standing the
        # sentinel down still closes the pipe, but with **no token**, so the
        # sentinel reads a bare end of file and fires — a redundant group
        # `SIGKILL` sent after the supervisor has already killed and reaped
        # that group, which is the one moment at which the id may genuinely
        # have been freed.  (This is the token-failure path the deadman
        # module's docs name; it is not an argument about the *ordering* of
        # the stand-down, which guards a crash window instead.)  The counter
        # is how a test sees the difference between "stood down" and "fired
        # and nobody noticed".
        "an orderly end stands the sentinel down rather than letting it fire",
        [
            (
                CHILD,
                "            if tokio::task::spawn_blocking(move || deadman.stand_down())\n                .await\n                .unwrap_or(false)\n            {\n                supervisor_counters\n                    .deadman_stood_down\n                    .fetch_add(1, Ordering::Relaxed);\n            }",
                "            drop(deadman);",
            )
        ],
        # The `deadman_stood_down` counter distinguishes "stood down" from
        # "fired and nobody noticed", and exactly one test reads it.
        frozenset({"an_orderly_shutdown_stands_the_sentinel_down_instead_of_firing_it"}),
    ),
    # ------------------------------------ the fixture's honesty about itself
    Case(
        # Not a product guard: a fixture guard.  If the descendant stops
        # actually leaving the process group, the plain group kill reaches it
        # and every containment claim in `process_residue.rs` becomes a
        # measurement of nothing — while staying green.  The escape marker and
        # the assertion on it are what stop that, so defeating the escape must
        # redden the measurements rather than quietly weaken them.
        "a descendant that failed to detach is refused, not measured",
        [
            (
                FIXTURE_LIB,
                "        DetachRoute::Setsid => rustix::process::setsid().is_ok(),",
                "        DetachRoute::Setsid => false,",
            )
        ],
        # The escape marker's own assertion: a descendant that did not detach
        # must be refused rather than measured as containment.
        frozenset({"a_setsid_descendant_escapes_the_group_kill"}),
    ),
    # ------------------------------ the skip cannot hide a present helper
    Case(
        # Task row M5-C16, the MCP copy of M5-C11's `m5c8` case.  The sentinel
        # tests in `process_residue.rs` now *skip*, naming themselves, when
        # `availability()` says the helper is absent -- so an `availability()`
        # that reported it missing whatever is on disk would skip every one
        # of them and the coverage would vanish silently.  This defeats it
        # into exactly that.  `CARGO_BUILD_BINARIES` is load-bearing here
        # rather than boilerplate: with no helper beside the tests the control
        # correctly asserts `false == false` and this case would report
        # `still green` over a rule that was never exercised.
        "a present sentinel helper cannot be reported as missing",
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
        # The positive control compares the skip's decision against an
        # independent filesystem read; it is the only test that can notice
        # a skip taken while the helper is present, because every sentinel
        # test it guards goes *green* by skipping.
        frozenset({"the_skip_cannot_hide_a_helper_that_is_on_disk"}),
    ),
]


@dataclass
class Suite:
    name: str
    crates: list[Path]
    cargo_test: list[str]
    cases: list[Case] = field(default_factory=list)
    cwd: Path = REPO


#: A second suite, for the rules whose witnesses are `tunnel-deadman`'s own
#: unit tests rather than the process-table measurements.  It is separate
#: because a single `cargo test --test process_residue` names a target that
#: only the fixture crate has, and **this suite edits only a package its own
#: invocation rebuilds** — the rule M3-19 exists to state.
DEADMAN_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-deadman",
    "--locked",
    "--no-fail-fast",
]

DEADMAN_CASES: list[Case] = [
    Case(
        # The rule that makes a missing sentinel *detectable*.  Without it, a
        # configured path that names nothing resolves to a path anyway; `arm`
        # then fails at spawn instead of at resolution, and `availability` —
        # which the device's doctor reports and which starts no process —
        # would tell an operator the installation is watched when it is not.
        # A packaging slip would then be invisible in the one place built to
        # show it.
        #
        # **Re-anchored at M6-C08.**  The guard used to read `return
        # path.is_file().then_some(path);`; the explicit branch now delegates
        # to `classify`, and taking the path on trust is spelt as returning
        # `Usable` without classifying it.  The rule is unchanged.
        "a configured sentinel path that names no file resolves to no sentinel",
        [
            (
                DEADMAN_LIB,
                "        return classify(PathBuf::from(explicit));",
                "        return Resolution::Usable(PathBuf::from(explicit));",
            )
        ],
        frozenset({"tests::an_explicit_path_to_a_non_file_resolves_to_no_sentinel"}),
    ),
    # ------------------------------------------------------------- M3-18
    Case(
        # The whole of M3-18.  Without the pin the sentinel watches a group it
        # holds no member of, so once the watched child is reaped the id is
        # free and a late firing could land on a stranger.  The witness asks
        # the kernel whether the group still exists after its leader is
        # reaped, which only a member the sentinel has not reaped can make
        # true.
        "the sentinel pins the watched group with a member it does not reap",
        [
            (
                DEADMAN_LIB,
                "    let pin = GroupPin::join(leader);",
                "    let pin: Option<GroupPin> = None;",
            )
        ],
        frozenset({"the_watched_group_id_stays_allocated_after_its_last_member_is_reaped"}),
    ),
    Case(
        # A group that had already emptied when the sentinel started can
        # never be pinned, and its id belongs to nobody the sentinel watches:
        # without this refusal the bare end of file signals it anyway.
        "a sentinel that could pin nothing never signals the id it was given",
        [
            (
                DEADMAN_LIB,
                "    if !watched {\n        return EXIT_NOTHING_WATCHED;\n    }\n",
                "",
            )
        ],
        frozenset({"a_sentinel_given_a_group_that_no_longer_exists_never_signals_that_id"}),
    ),
    # ------------------------------------------------------------- M6-C08
    Case(
        # **The defect the row measured.**  Without the execute test, a
        # zero-byte 0644 file named `tunnel-deadman` resolves as usable and
        # `doctor` reports `PROCESS_CONTAINMENT_SENTINEL_PRESENT` for an
        # installation that contains nothing.  The edit keeps the
        # regular-file half, so this defeats the execute rule *alone* and
        # cannot be credited to the other one.
        "a file of the sentinel's name this process cannot execute is not a sentinel",
        [
            (
                DEADMAN_LIB,
                "        && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()",
                "",
            )
        ],
        frozenset({"tests::a_zero_byte_decoy_wearing_the_sentinels_name_is_not_a_sentinel"}),
    ),
    Case(
        # **`access(EXEC_OK)` rather than a mode-bit test, defeated on its
        # own** -- the Fable review's finding.  Substituting the obvious
        # `mode() & 0o111 != 0` leaves every other case in this suite green:
        # it accepts the zero-byte 0644 decoy's opposite, a file whose
        # execute bit is set for a class this process is not in.  A rule that
        # answers "somebody may execute this" where the caller asked "may I"
        # reports containment present for a sentinel that cannot be run.
        "the execute test asks whether this process may execute, not whether anybody may",
        [
            (
                DEADMAN_LIB,
                "        && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()",
                "        && {\n"
                "            use std::os::unix::fs::PermissionsExt as _;\n"
                "            std::fs::metadata(path)\n"
                "                .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)\n"
                "        }",
            )
        ],
        frozenset({"tests::a_sentinel_this_process_may_not_execute_is_not_a_sentinel"}),
    ),
    Case(
        # The other half, defeated on its own for the same reason.  A
        # directory carries execute bits meaning "searchable" and
        # `access(EXEC_OK)` succeeds on one, so the execute test alone
        # accepts a directory named `tunnel-deadman`.  The old `is_file()`
        # rule got this right by accident; it has to keep getting it right on
        # purpose.
        "a directory the process may search is not a sentinel",
        [
            (
                DEADMAN_LIB,
                "    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())\n",
                "    true\n",
            )
        ],
        frozenset({"tests::a_directory_wearing_the_sentinels_name_is_not_a_sentinel"}),
    ),
    Case(
        # The distinct status itself.  Folding "a file is there and cannot be
        # run" back into "nothing is there" restores a report that is true
        # about containment and useless as advice: the operator is told to
        # install a `tunnel-deadman` they are looking straight at.
        "a file that is present and unusable is not reported as nothing being there",
        [
            (
                DEADMAN_LIB,
                "    } else {\n        Resolution::Unusable(path)\n    }\n}",
                "    } else {\n        Resolution::Absent\n    }\n}",
            )
        ],
        frozenset(
            {
                "tests::a_file_that_is_there_and_unusable_is_reported_apart_from_"
                "nothing_being_there"
            }
        ),
    ),
    Case(
        # Returning on the first unusable candidate is what the old rule did
        # -- it returned on the first `is_file()` -- and it would let a decoy
        # in `deps` hide the real sentinel one directory up.
        #
        # **What that costs, corrected by the Fable review.**  Not a silent
        # green: `process_residue.rs` hands the resolved path to its probe
        # through `SENTINEL_PATH_ENV` and asserts `armed == "1"` before
        # measuring anything, so an unspawnable candidate fails that
        # assertion with its own message.  The cost is that the failure reads
        # as a broken mechanism when the mechanism is fine and the wrong file
        # was chosen -- worth fixing, and worth describing accurately.  It
        # also needs a hand-placed file: cargo puts no `tunnel-deadman` in
        # `deps/`.
        "an unusable candidate does not shadow a usable one further along the search",
        [
            (
                DEADMAN_LIB,
                "            Resolution::Unusable(path) => rejected = rejected.or(Some(path)),",
                "            Resolution::Unusable(path) => return Resolution::Unusable(path),",
            )
        ],
        frozenset({"tests::a_decoy_in_deps_does_not_shadow_the_real_sentinel_above_it"}),
    ),
    Case(
        # An explicit `TUNNEL_DEADMAN_BIN` that names an unusable file must
        # not fall back to the search.  A fallback would resolve to some
        # *other* file and report success -- the shape of M6-C08 itself, one
        # level up: a configuration mistake reported as a working
        # installation.
        "an explicit sentinel path that is unusable does not fall back to the search",
        [
            (
                DEADMAN_LIB,
                "        return classify(PathBuf::from(explicit));",
                "        let explicit = classify(PathBuf::from(explicit));\n"
                "        if let Resolution::Usable(_) = explicit {\n"
                "            return explicit;\n"
                "        }",
            )
        ],
        frozenset({"tests::an_explicit_unusable_path_does_not_fall_back_to_the_search"}),
    ),
]

#: The doctor's own mapping, in its own suite because it lives in a different
#: package and M3-19's rule is that a suite may only edit packages its own
#: `cargo test` invocation rebuilds.
DOCTOR_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-client",
    "--locked",
    "--no-fail-fast",
    "doctor::",
]

DOCTOR_CASES: list[Case] = [
    Case(
        # The product rule and the surface that reports it are separate
        # guards, and only this one is about what an operator reads.  The
        # resolution rule could be perfect and this mapping could still fold
        # the two degraded states together, which is the state M6-C08 asked
        # not to be left in.
        "an unusable sentinel is reported with its own doctor code",
        [
            (
                DOCTOR,
                '            code: "PROCESS_CONTAINMENT_SENTINEL_UNUSABLE",',
                '            code: "PROCESS_CONTAINMENT_SENTINEL_MISSING",',
            )
        ],
        frozenset(
            {
                "doctor::tests::a_missing_parent_death_sentinel_is_reported_and_"
                "does_not_fail_the_doctor"
            }
        ),
    ),
]

#: The re-sign pin-availability rule (M3-25 / M7-C89), in its own suite for
#: the same M3-19 reason as the others: it edits `tunnel-test-harness`, and
#: only a `cargo test -p tunnel-test-harness` invocation rebuilds it.
#:
#: **Why the rule is witnessed through scripted relays rather than through the
#: gate it protects.**  The condition the wait exists for is rare in every
#: population M3-25 measured, and those populations differ, so each is named
#: rather than rounded into one figure: 1 M3-04 red in 26 baseline isolation
#: re-signs (3.8%); 2 engagements in 109 post-fix re-signs across three gates
#: (1.8%), both in cloud-client and none in the 59 isolation re-signs.  A case
#: witnessed by `verify-m3-mcp-isolation` would therefore be green almost every
#: time **with the rule deleted** -- the M5-C11 shape this whole family of
#: harnesses exists to refuse: a case whose defeat and whose success look the
#: same.
#:
#: **Decision and application are witnessed separately, and the second was
#: missing.**  The first three cases defeat `pin_publication_outstanding`, the
#: rule's *decision*.  Their witnesses call that function (or the wait loop)
#: directly, so none of them could see whether the wait was ever *applied*:
#: the Fable review of `3cf2c1e` measured that deleting the call site, or
#: making the bound proceed instead of failing, still left this suite at three
#: of three.  The call site now lives in `settle_resign` -- moved out of
#: `resign_membership_now`, which needs a Redis-backed cluster and so no unit
#: test could reach -- and the last two cases defeat the application, each
#: witnessed by a test that drives the path it defeats.
#:
#: **Still not witnessed here, and said rather than implied:** the single line
#: in `resign_membership_now` that calls `settle_resign`.  Replacing it with a
#: literal skips convergence and the pin wait together, and only the cluster
#: gates would notice.  Convergence was never unit-witnessed before this suite
#: existed; the pin wait no longer adds to that surface.
#:
#: Several filters, not one prefix, because the witnesses do not share one.
#: libtest accepts any number of filters after `--`, and runs a test that
#: matches any of them.
PIN_WAIT_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-test-harness",
    "--locked",
    "--lib",
    "--no-fail-fast",
    "--",
    "production_cluster::tests::pin_",
    "production_cluster::tests::a_resign_waits_until_the_emptied_pin_set_is_reinstalled",
    "production_cluster::tests::a_converged_resign_still_waits_for_its_pin_set",
    "production_cluster::tests::only_a_pin_set_this_resign_emptied_is_waited_for",
    "production_cluster::tests::a_pin_set_that_never_returns_fails_the_resign_at_the_bound",
]

PIN_WAIT_CASES: list[Case] = [
    Case(
        # The pending clause.  Without it a re-sign stops waiting for a
        # publication that failed closed and has not been retried, which is
        # the exact state the M3-04 / M7-C83 dispatch window is.
        "a failed-closed pin publication still pending is waited for",
        [
            (
                HARNESS_CLUSTER,
                "    publication_pending || (installed_before && pins_empty)",
                "    installed_before && pins_empty",
            )
        ],
        frozenset({"production_cluster::tests::pin_publication_pending_is_outstanding"}),
    ),
    Case(
        # The emptied-set clause.  The pending flag says a publication was
        # retried, not that it put anything back; dropping this clause lets a
        # re-sign return with an empty pin set whose retry has already run.
        "a pin set this re-sign emptied is waited for",
        [
            (
                HARNESS_CLUSTER,
                "    publication_pending || (installed_before && pins_empty)",
                "    publication_pending",
            )
        ],
        frozenset(
            {"production_cluster::tests::pin_set_emptied_by_the_resign_is_outstanding"}
        ),
    ),
    Case(
        # The `installed_before` guard.  Without it the wait would demand a
        # pin set back on a relay that deliberately has none, turning a
        # key-revocation gate's held withdrawal into a 30-second hang -- a
        # flaky red converted into a lost run, which is worse.
        "a pin set deliberately withdrawn before the re-sign is not waited for",
        [
            (
                HARNESS_CLUSTER,
                "    publication_pending || (installed_before && pins_empty)",
                "    publication_pending || pins_empty",
            )
        ],
        frozenset(
            {
                "production_cluster::tests::"
                "pin_set_absent_before_the_resign_is_not_outstanding"
            }
        ),
    ),
    Case(
        # The APPLICATION: the line that applies the pin wait once record
        # versions have converged.  Defeated, a converged re-sign returns
        # immediately -- exactly the pre-fix behaviour, and exactly the moment
        # `verify-m3-mcp-isolation` dispatched into an empty pin set.  The
        # rule's decision is untouched, so the three cases above cannot see
        # this; that is the gap the Fable review of `3cf2c1e` measured.
        "a re-sign whose record versions converged still waits for its pin set",
        [
            (
                HARNESS_CLUSTER,
                "            return wait_for_pins_over(relays, installed_before, "
                "budgets.pins, budgets.pins_poll)\n                .await;",
                "            return {\n"
                "                let _ = installed_before;\n"
                "                Ok((0, 0))\n"
                "            };",
            )
        ],
        frozenset(
            {"production_cluster::tests::a_converged_resign_still_waits_for_its_pin_set"}
        ),
    ),
    Case(
        # The bound FAILS rather than proceeds.  Defeated, a pin set that
        # never comes back is waited for until the budget runs out and then
        # reported as success -- which re-creates the condition at the one
        # moment it is known to be present, and turns a diagnosable timeout
        # into the original defect.
        "a pin set that never comes back fails the re-sign at the bound",
        [
            (
                HARNESS_CLUSTER,
                "            return Err(HarnessError::Timeout(format!(\n"
                '                "verified peer pins were not reinstalled on {} of {} '
                'running relays \\\n'
                '                 within {} ms after a membership re-sign",\n'
                "                owing.len(),\n"
                "                relays.iter().filter(|relay| relay.is_running()).count(),\n"
                "                budget.as_millis(),\n"
                "            )));",
                "            return Ok((widest, started.elapsed().as_millis()));",
            )
        ],
        frozenset(
            {
                "production_cluster::tests::"
                "a_pin_set_that_never_returns_fails_the_resign_at_the_bound"
            }
        ),
    ),
]

#: **M7-C89, the product half of the condition `m3c25-resign-pin-wait` guards
#: in the fixture.**  That suite proves the harness waits for an emptied pin
#: set before dispatching; this one proves the relay stops *claiming* to be
#: ready while the set is empty.  It lives beside its sibling because the two
#: are one condition seen from two sides, and because PR #82's fixture wait
#: removed the only thing that ever noticed the product half -- so the
#: product half has to be guarded somewhere a suite run will reach.
#:
#: The witness drives the production Axum router and the real
#: `PeerRuntime::is_ready`, with every other readiness input held true, and
#: shows the transport refusing a real dial with the same empty set.
RELAY = REPO / "crates" / "tunnel-relay"
PEER_RUNTIME = RELAY / "src" / "peer_runtime.rs"

READINESS_PINS_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-relay",
    "--locked",
    "--no-fail-fast",
    "--test",
    "m7_health_endpoints",
]

READINESS_PINS_CASES: list[Case] = [
    Case(
        # The whole fix.  Defeated, readiness reads membership and route
        # state only -- the pre-M7-C89 predicate -- and `/readyz` answers 200
        # while every peer dial is refused `PinsUnavailable`.
        "readiness and public admission answer against the transport pin set",
        [
            (
                PEER_RUNTIME,
                "        !self.client.pin_snapshot().is_empty()\n"
                "            && self.bindings.is_ready()",
                "        self.bindings.is_ready()",
            )
        ],
        frozenset({"readiness_and_admission_withdraw_with_the_transport_pin_set"}),
    ),
]

#: **M7-C92 and M7-C93: the finite (unary) echo on an M2 session.**  M7-C92
#: made the relay issue the owner `STREAM_FORGET` that releases a finite
#: echo's connector OPEN journal entry, without which a device session
#: refused request 129; M7-C93 made a finite echo in flight across a data
#: rotation keep an honest fence.  It sits beside M7-C89 because both are
#: relay-actor rules witnessed by the relay's own tests.
#:
#: The witnesses are the deterministic actor regressions in
#: `actor_rotation_freeze_tests.rs`, which drive the real actor handlers with
#: a connector stand-in.  Each one observes only control messages, data
#: frames and the relay fence, which is what let the same file be run against
#: the code before either fix and go red there.  The real-binary gates
#: (`m7c92_...` and `m7c93_...` in `m6_provisioning_process.rs`) need Redis
#: and are run by `scripts/m6-provisioning-verify.sh`, not here.
ACTOR = RELAY / "src" / "actor.rs"
UNARY_ECHO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-relay",
    "--locked",
    "--no-fail-fast",
    "--lib",
    "--",
    "actor::rotation_freeze_tests::",
]
UNARY_FREEZE = "actor::rotation_freeze_tests::"
UNARY_ECHO_CASES: list[Case] = [
    Case(
        # The whole of M7-C92.  Without the tombstone a completed echo leaves
        # nothing for the FORGET flush to find -- the pre-fix relay -- and the
        # connector's 128-entry retention fills.
        "a completed unary echo is retained for its owner STREAM_FORGET",
        [
            (
                ACTOR,
                "                    if let Some(tombstone) = completed_tombstone\n"
                "                        && let Some(session) = self.session_mut(&key)\n"
                "                    {\n"
                "                        session.unary_tombstones.insert(stream_id, tombstone);\n"
                "                    }",
                "                    let _ = completed_tombstone;",
            )
        ],
        frozenset(
            {
                UNARY_FREEZE + "completed_unary_echo_is_forgotten_once_its_fin_is_acknowledged",
                UNARY_FREEZE
                + "unary_echo_completing_during_freeze_keeps_the_roster_and_is_forgotten_after",
            }
        ),
    ),
    Case(
        # Idempotency: the owner may not assert a terminal the connector has
        # not acknowledged.  Defeated, the FORGET goes out on the connector's
        # FIN alone and the connector must defer or refuse its proof.
        "the unary FORGET waits for the connector's ACK of the relay's FIN",
        [
            (
                ACTOR,
                "                if identity.peer_acked < UNARY_ECHO_FIN_SEQUENCE {\n"
                "                    return None;\n"
                "                }\n",
                "",
            )
        ],
        frozenset(
            {UNARY_FREEZE + "completed_unary_echo_is_forgotten_once_its_fin_is_acknowledged"}
        ),
    ),
    Case(
        # A REJECTED is correlated by the OPEN's own message ID, never by the
        # stream and operation alone.
        "a REJECTED unary OPEN is forgotten only when it answers that OPEN",
        [
            (
                ACTOR,
                "                        && pending.forget.open_message_id == rejected.reply_to\n",
                "",
            )
        ],
        frozenset(
            {UNARY_FREEZE + "rejected_unary_echo_open_is_forgotten_with_no_stream_evidence"}
        ),
    ),
    Case(
        # Review F1: a late ACK for a finite echo whose stream ID a later
        # echo's FORGET already passed must still reach its tombstone.
        # Defeated, the ACK is dropped as stale and the tombstone leaks until
        # the session closes.
        "a late ACK below the watermark still reaches its unary tombstone",
        [
            (
                ACTOR,
                "            || (frame.kind == FrameKind::Ack\n"
                "                && session.unary_tombstones.contains_key(&frame.stream_id));",
                ";",
            )
        ],
        frozenset(
            {
                UNARY_FREEZE
                + "late_ack_below_the_watermark_still_forgets_an_out_of_order_unary_echo"
            }
        ),
    ),
    Case(
        # M7-C93's first defect, restored: a dispatched echo fenced at its DATA
        # sequence although its FIN was already sent.
        "a unary echo is fenced at the last sequence it emitted",
        [
            (
                ACTOR,
                "                let last_emitted = pending.relay_last_emitted();\n"
                "                entries.push(StreamFence::new(*stream_id, direction, last_emitted));",
                "                let last_emitted = pending.send_sequence;\n"
                "                entries.push(StreamFence::new(*stream_id, direction, last_emitted));",
            )
        ],
        frozenset(
            {
                UNARY_FREEZE + "dispatched_unary_echo_is_fenced_at_its_fin",
                UNARY_FREEZE + "unary_echo_authorized_during_freeze_dispatches_after_commit",
            }
        ),
    ),
    Case(
        # M7-C93's third defect, restored: an authorization result during the
        # freeze dispatches DATA and FIN past the frozen fence.
        "a unary echo authorized while frozen is held until the writer resumes",
        [
            (
                ACTOR,
                "        if Self::rotation_frozen(session) {\n"
                "            // A frozen writer emits no sequenced frame (docs/protocol.md\n",
                "        if false {\n"
                "            // A frozen writer emits no sequenced frame (docs/protocol.md\n",
            )
        ],
        frozenset(
            {UNARY_FREEZE + "unary_echo_authorized_during_freeze_dispatches_after_commit"}
        ),
    ),
    Case(
        # M7-C93's second defect, restored: an echo that completes after
        # QUIESCE vanishes from the fence, and the relay cannot freeze.
        "a unary echo completed during the freeze stays in that roster's fence",
        [
            (
                ACTOR,
                "            if tombstone.frozen_snapshot_id.as_deref() == Some(snapshot_id) {",
                "            if false {",
            )
        ],
        frozenset(
            {
                UNARY_FREEZE
                + "unary_echo_completing_during_freeze_keeps_the_roster_and_is_forgotten_after"
            }
        ),
    ),
]

#: **M7-C97: the connector resumes OPEN admission at COMMIT.**  The owner
#: resumes admission when ROTATE_COMMITTED arrives; the connector used to wait
#: for ROTATE_COMPLETE, so an OPEN landing between the two was refused
#: `GOAWAY` and a healthy session answered `503 DEVICE_REJECTED`.  Witnessed by
#: a connector actor test that drives a real commit into `Retiring`.
RETIRING_ADMISSION_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-client",
    "--locked",
    "--no-fail-fast",
    "--lib",
    "--",
    "m2_runtime::tests::",
]
RETIRING_ADMISSION_CASES: list[Case] = [
    Case(
        "an OPEN the owner admits while retiring is not refused as draining",
        [
            (
                CLIENT / "src" / "m2_runtime.rs",
                "        self.accepting = resumed;\n",
                "        self.accepting = self.rotation.phase() == RotationPhase::Active;\n",
            )
        ],
        frozenset(
            {
                "m2_runtime::tests::"
                "an_open_admitted_by_the_owner_while_retiring_is_not_refused_as_draining"
            }
        ),
    ),
    Case(
        # Review S2: losing the active carrier closes admission in every
        # phase.  Defeated, a Retiring connector whose new carrier died keeps
        # admitting onto the recovery placeholder.
        "admission closes when the active carrier is lost, whatever the phase",
        [
            (
                CLIENT / "src" / "m2_runtime.rs",
                "            self.accepting = false;\n"
                "            self.writes_frozen = true;\n"
                "            if !self.recovery_requested",
                "            self.writes_frozen = true;\n"
                "            if !self.recovery_requested",
            )
        ],
        frozenset(
            {
                "m2_runtime::tests::"
                "an_open_after_the_active_carrier_dies_while_retiring_is_refused_as_draining"
            }
        ),
    ),
]

#: **M3-32: a consumer release after the response head is its own recorded
#: outcome.**  The ingress cannot tell a release after the application's final
#: message from one in the middle of it without interpreting the body, so it
#: records `released` and leaves the call's outcome to the device's record.
#: The witnesses are the bridge's in-process exchanges: one holds the device's
#: END and FIN back until after the consumer lets go of a completed SSE call,
#: the other releases mid-stream.
BRIDGE = REPO / "crates" / "tunnel-http-bridge"
BRIDGE_OWNER = BRIDGE / "src" / "owner.rs"
RELEASE_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-http-bridge",
    "--locked",
    "--no-fail-fast",
    "--test",
    "streaming",
]
RELEASE_CASES: list[Case] = [
    Case(
        "a consumer that releases the response body after its head is recorded as released",
        [
            (
                BRIDGE_OWNER,
                "            let _ = self.exchange.release(HttpErrorCode::Cancelled);",
                "            self.fail(Origin::Consumer, HttpErrorCode::Cancelled);",
            )
        ],
        frozenset(
            {
                "a_release_after_the_final_event_and_before_end_is_recorded_as_released",
                "consumer_drop_mid_body_resets_both_directions_and_the_handler_observes_it",
            }
        ),
    ),
]

#: **M3-33, then M3-15: the cloud-client gate resends only the relay's own
#: rotation-freeze refusal.**  The gate's classifier used to accept any
#: retryable `not_dispatched` 503, which M7-C83's empty-pin-set refusal also
#: is, so a freeze could have masked that signature (M3-33 narrowed it to the
#: owner-not-ready message and hint).  Since M3-15 the owner holds a request
#: that lands in a freeze and names one that outlasts the hold
#: `ROTATION_FREEZE`, so the owner-not-ready body is a fault refusal and the
#: classifier requires the freeze code instead.  Defeating the code check lets
#: the fault body through, and the unit test's owner-not-ready arm goes red.
WIRE = HARNESS / "src" / "production_cluster" / "mcp_cloud_client" / "wire.rs"
WIRE_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-test-harness",
    "--locked",
    "--lib",
    "--no-fail-fast",
    "--",
    "production_cluster::mcp_cloud_client::wire::tests::",
]
WIRE_CASES: list[Case] = [
    Case(
        "the cloud-client gate resends only a refusal carrying the rotation-freeze code",
        [
            (
                WIRE,
                '    (value["code"] == ROTATION_FREEZE_CODE\n'
                '        && value["execution"] == "not_dispatched"',
                '    (value["execution"] == "not_dispatched"',
            )
        ],
        frozenset(
            {
                "production_cluster::mcp_cloud_client::wire::tests::"
                "only_the_rotation_freeze_503_carries_a_retry_hint"
            }
        ),
    ),
    Case(
        "the cloud-client gate resends a rotation-freeze refusal only with the bounded hint",
        [
            (
                WIRE,
                "        && (1..=MIN_RETRY_HINT_MS).contains(&hint))\n"
                "    .then(|| Duration::from_millis(hint).min(MAX_RETRY_AFTER))",
                "        && hint > 0)\n"
                "    .then(|| Duration::from_millis(hint).min(MAX_RETRY_AFTER))",
            )
        ],
        frozenset(
            {
                "production_cluster::mcp_cloud_client::wire::tests::"
                "only_the_rotation_freeze_503_carries_a_retry_hint"
            }
        ),
    ),
]

#: **M3-15: the owner holds a new OPEN across a data-rotation freeze.**
#: Owner decision, 2026-09-25: an OPEN landing between QUIESCE and COMMITTED
#: is held, bounded in time and count, and admitted once the freeze ends; a
#: freeze that outlasts the bound is refused with the distinct
#: `ROTATION_FREEZE`, locally and through a forwarded hop.  The witnesses are
#: the deterministic actor regressions in `actor_freeze_hold_tests.rs`, the
#: HTTP mapping test in `http.rs` and the real HTTP/3 round trip in
#: `peer_cleanup_h3_tests.rs`.  **Not a case, deliberately:** the shutdown
#: release (`release_held_opens_at_shutdown`) is redundant with the
#: session-loss release, because shutdown closes every session first, so
#: defeating it leaves every test green; and the release hooks at the commit
#: and abort handlers are duplicated by the actor's after-command service, so
#: defeating one is only visible to a test that bypasses the actor loop.
#: The bound case deletes the refusal rather than the deadline check: without
#: the check an expired entry is kept and the actor loop's deadline branch
#: fires again at once, so the paused-time run-loop test livelocks instead of
#: going red (measured: the first form of the case timed out).
FREEZE_HOLD = RELAY / "src" / "actor_freeze_hold.rs"
RELAY_HTTP = RELAY / "src" / "http.rs"
RELAY_FS = RELAY / "src" / "http" / "fs.rs"
FREEZE_HOLD_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-relay",
    "--locked",
    "--no-fail-fast",
    "--lib",
    "--",
    "freeze",
]
HOLD = "actor::rotation_freeze_tests::freeze_hold_tests::"
FREEZE_HOLD_CASES: list[Case] = [
    Case(
        # The whole decision.  Without the attempt-freeze condition every
        # frozen OPEN is refused at once, exactly as before M3-15.
        "an OPEN in a scheduled rotation freeze is held rather than refused",
        [
            (
                ACTOR,
                "            if !freeze_hold::attempt_frozen(session) {\n"
                "                let _ = response.send(Err(RelayError::OwnerNotReady));",
                "            {\n"
                "                let _ = response.send(Err(RelayError::OwnerNotReady));",
            )
        ],
        frozenset({HOLD + "an_open_during_a_freeze_is_admitted_after_commit"}),
    ),
    Case(
        "a held OPEN is refused with ROTATION_FREEZE once the bound passes",
        [
            (
                FREEZE_HOLD,
                "                        self.freeze_hold.counters.refused_after_bound += 1;\n"
                "                        held.refuse(HoldRefusal::RotationFreeze);\n",
                "                        self.freeze_hold.counters.refused_after_bound += 1;\n",
            )
        ],
        frozenset({HOLD + "an_open_held_past_the_bound_is_refused_with_rotation_freeze"}),
    ),
    Case(
        "the per-device hold cap refuses the OPEN over it",
        [
            (
                FREEZE_HOLD,
                "        if device_held >= per_device_cap\n"
                "            || tenant_held >= MAX_HELD_PER_TENANT",
                "        if tenant_held >= MAX_HELD_PER_TENANT",
            )
        ],
        frozenset({HOLD + "the_hold_cap_is_enforced_per_device"}),
    ),
    Case(
        "a held OPEN whose consumer went away is dropped, not dispatched",
        [
            (
                FREEZE_HOLD,
                "    pub(super) fn service_held_scope(&mut self, scope: &DeviceScope, now: Instant) {\n"
                "        self.freeze_hold.sweep_cancelled(scope);\n",
                "    pub(super) fn service_held_scope(&mut self, scope: &DeviceScope, now: Instant) {\n",
            )
        ],
        frozenset({HOLD + "a_consumer_cancelling_during_the_hold_dispatches_nothing"}),
    ),
    Case(
        "a session's end answers its held OPENs",
        [
            (
                ACTOR,
                "        // dispatched; answer them now rather than at their deadline.\n"
                "        self.service_held_scope(&key.scope(), tokio::time::Instant::now());\n",
                "        // dispatched; answer them now rather than at their deadline.\n",
            )
        ],
        frozenset({HOLD + "session_loss_during_the_hold_releases_with_the_fault_refusal"}),
    ),
    Case(
        "a local ROTATION_FREEZE refusal keeps its distinct consumer body",
        [
            (
                RELAY_HTTP,
                "        RelayError::RotationFreeze => {\n"
                "            rotation_freeze_response(crate::actor::ROTATION_FREEZE_RETRY_AFTER_MS)\n"
                "        }\n",
                "",
            )
        ],
        frozenset(
            {
                "http::tests::"
                "rotation_freeze_refusal_is_distinct_from_the_owner_not_ready_fault_refusal"
            }
        ),
    ),
    Case(
        "a forwarded ROTATION_FREEZE refusal reaches the ingress as its own error",
        [
            (
                PEER_RUNTIME,
                "            if let Some(retry_after_ms) = rotation_freeze_retry_after(&response) {\n"
                "                return Err(PeerRuntimeError::RotationFreeze { retry_after_ms });\n"
                "            }\n",
                "",
            )
        ],
        frozenset(
            {
                "http::peer_cleanup_tests::peer_cleanup_h3_tests::"
                "forwarded_rotation_freeze_refusal_keeps_its_distinct_reason"
            }
        ),
    ),
    Case(
        "a unary echo in a scheduled rotation freeze is held rather than refused",
        [
            (
                ACTOR,
                "            if !freeze_hold::attempt_frozen(session) {\n"
                "                let _ = response.send(EchoOutcome::Failure {",
                "            {\n"
                "                let _ = response.send(EchoOutcome::Failure {",
            )
        ],
        frozenset({HOLD + "a_unary_echo_during_a_freeze_is_held_then_dispatched_after_commit"}),
    ),
    Case(
        "the unary echo route answers a held echo's bound refusal as ROTATION_FREEZE",
        [
            (
                RELAY_HTTP,
                "    if code == crate::actor::ROTATION_FREEZE_ECHO_CODE {\n"
                "        return rotation_freeze_response(crate::actor::ROTATION_FREEZE_RETRY_AFTER_MS);\n"
                "    }\n",
                "",
            )
        ],
        frozenset(
            {
                "http::tests::"
                "rotation_freeze_refusal_is_distinct_from_the_owner_not_ready_fault_refusal"
            }
        ),
    ),
    Case(
        "the filesystem upgrade answers a freeze past the bound as ROTATION_FREEZE",
        [
            (
                RELAY_FS,
                "    if matches!(error, crate::actor::RelayError::RotationFreeze) {\n"
                "        return rotation_freeze_fs_error();\n"
                "    }\n",
                "",
            )
        ],
        frozenset({"http::fs::tests::a_rotation_freeze_answers_its_own_filesystem_code"}),
    ),
    Case(
        "a held request belongs to its session, not to a successor",
        [
            (
                FREEZE_HOLD,
                "                .get(scope)\n"
                "                .filter(|session| session.key == held.key);",
                "                .get(scope);",
            )
        ],
        frozenset({HOLD + "a_successor_session_never_inherits_a_held_open"}),
    ),
    Case(
        "the per-tenant hold cap refuses the request over it",
        [
            (
                FREEZE_HOLD,
                "            || tenant_held >= MAX_HELD_PER_TENANT\n",
                "",
            )
        ],
        frozenset({HOLD + "the_hold_cap_is_enforced_per_tenant"}),
    ),
    Case(
        "the relay-wide hold cap refuses the request over it",
        [
            (
                FREEZE_HOLD,
                "            || self.total >= MAX_HELD_TOTAL\n",
                "",
            )
        ],
        frozenset({HOLD + "the_hold_cap_is_enforced_per_relay"}),
    ),
    Case(
        "the actor loop wakes at the earliest hold deadline with no command",
        [
            (
                ACTOR,
                "                () = sleep_until_hold_deadline(self.freeze_hold.next_deadline()),\n"
                "                    if !self.freeze_hold.is_empty() =>\n"
                "                {\n"
                "                    self.service_held_opens(tokio::time::Instant::now());\n"
                "                }\n",
                "",
            )
        ],
        frozenset({HOLD + "the_run_loop_refuses_a_held_open_at_its_deadline_without_a_command"}),
    ),
    Case(
        "a commit flushes the frozen writes before it admits the held requests",
        [
            (
                ACTOR,
                "        self.flush_frozen_writes(key);\n"
                "        // Then admit the OPENs held across the freeze, in arrival order.\n",
                "        // Then admit the OPENs held across the freeze, in arrival order.\n",
            )
        ],
        frozenset({HOLD + "an_open_during_a_freeze_is_admitted_after_commit"}),
    ),
    Case(
        # A reorder, not a deletion: the review of #156 asked for the case
        # that releases the hold before the flush.  The witness sees the
        # release find the frozen record still queued.
        "a commit releases the hold only after it flushes the frozen writes",
        [
            (
                ACTOR,
                "        self.flush_frozen_writes(key);\n"
                "        // Then admit the OPENs held across the freeze, in arrival order.\n"
                "        self.service_held_scope(&key.scope(), tokio::time::Instant::now());\n",
                "        // Then admit the OPENs held across the freeze, in arrival order.\n"
                "        self.service_held_scope(&key.scope(), tokio::time::Instant::now());\n"
                "        self.flush_frozen_writes(key);\n",
            )
        ],
        frozenset({HOLD + "an_open_during_a_freeze_is_admitted_after_commit"}),
    ),
]

#: **M3-31: an HTTP stream's owner STREAM_FORGET is published by its own
#: close.**  The close is usually the event that makes the FORGET provable,
#: and before M3-31 it published nothing, so the connector's OPEN journal held
#: the entry until the session's next inbound frame or the 500 ms tick.
FORGET_AT_CLOSE_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-relay",
    "--locked",
    "--no-fail-fast",
    "--lib",
    "--",
    "actor::rotation_freeze_tests::an_http_stream_is_forgotten_at_its_own_close",
]
FORGET_AT_CLOSE_CASES: list[Case] = [
    Case(
        "an owner close publishes the STREAM_FORGET it made provable",
        [
            (
                ACTOR,
                "                let _ = self.flush_owner_stream_forgets(&key);\n"
                "                let _ = response.send(closed);",
                "                let _ = response.send(closed);",
            )
        ],
        frozenset(
            {
                "actor::rotation_freeze_tests::"
                "an_http_stream_is_forgotten_at_its_own_close_once_its_proof_is_complete"
            }
        ),
    ),
]

#: The M3-32 review's race: a head the consumer had already dropped is not a
#: release.  Witnessed by the owner module's own unit tests.
RELEASE_RACE_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-http-bridge",
    "--locked",
    "--no-fail-fast",
    "--lib",
    "--",
    "owner::tests::",
]
RELEASE_RACE_CASES: list[Case] = [
    Case(
        "a head the consumer never took does not make leaving a release",
        [
            (
                BRIDGE_OWNER,
                "            self.committed.store(false, Ordering::SeqCst);\n",
                "",
            )
        ],
        frozenset({"owner::tests::a_head_the_consumer_never_took_is_not_a_release"}),
    ),
]

#: **The M7 connector, journal and echo rows** (branch `m7-connector`, task
#: rows M7-C84, M7-C94, M7-C95, M7-C98, M7-C109 and M7-C110).  Each case
#: defeats one rule and names the tests that must notice it; each was also
#: shown red by hand before its fix (docs/tasks.md, the row's evidence).
M7_CONNECTOR_RELAY_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-relay",
    "--locked",
    "--no-fail-fast",
    "--lib",
    "--",
    "actor::",
    "http::peer_cleanup_tests::peer_cleanup_h3_tests::",
]
PEER_H3 = "http::peer_cleanup_tests::peer_cleanup_h3_tests::"
PEER_RUNTIME = RELAY / "src" / "peer_runtime.rs"
RELAY_HTTP = RELAY / "src" / "http.rs"
M7_CONNECTOR_RELAY_CASES: list[Case] = [
    Case(
        # M7-C109: count a closed stream until the connector's own terminal.
        "a closed stream keeps its connector slot until the connector's terminal",
        [
            (
                ACTOR,
                "        if !stream.terminal || stream.open_pending {\n"
                "            return true;\n"
                "        }\n",
                "        if true {\n"
                "            return !stream.terminal;\n"
                "        }\n",
            )
        ],
        frozenset(
            {
                "actor::stream_identity_tests::"
                "a_closed_stream_holds_its_connector_slot_until_the_connector_terminal_arrives"
            }
        ),
    ),
    Case(
        # M7-C110, the owner: a superseded owner token is answered on its own
        # stream.  Defeated, quinn finishes the stream bare and the ingress's
        # HTTP/3 client fails the whole peer connection.
        "a superseded owner token is answered OWNER_CHANGED on its own stream",
        [
            (
                RELAY_HTTP,
                "        let _ = request.reject_owner_changed().await;\n"
                "        return Err(PeerRuntimeError::OwnerChanged {\n"
                "            retry_after_ms: crate::peer_runtime::OWNER_NOT_READY_RETRY_AFTER_MS,\n"
                "        });\n"
                "    }\n"
                "    if owner.lease_expires_at",
                "        drop(request);\n"
                "        return Err(PeerRuntimeError::OwnerChanged {\n"
                "            retry_after_ms: crate::peer_runtime::OWNER_NOT_READY_RETRY_AFTER_MS,\n"
                "        });\n"
                "    }\n"
                "    if owner.lease_expires_at",
            )
        ],
        frozenset(
            {
                PEER_H3 + "a_superseded_owner_token_is_refused_owner_changed_on_its_own_stream",
                PEER_H3 + "the_ingress_drops_a_stale_route_on_owner_changed_and_answers_typed",
            }
        ),
    ),
    Case(
        # M7-C110, the ingress: OWNER_CHANGED drops the cached route.
        "the ingress drops its cached route on OWNER_CHANGED",
        [
            (
                PEER_RUNTIME,
                "                if let Some(hook) = self.route_hook.as_ref() {\n"
                "                    hook.invalidate_owner_route().await;\n"
                "                }\n",
                "",
            )
        ],
        frozenset(
            {PEER_H3 + "the_ingress_drops_a_stale_route_on_owner_changed_and_answers_typed"}
        ),
    ),
    Case(
        # M7-C94: an exit other than completion abandons the entry instead of
        # dropping it.  Defeated, the pre-fix removal returns.
        "a unary echo that fails is abandoned and driven to its forget, not dropped",
        [
            (
                ACTOR,
                "        if forgets_unary {\n"
                "            self.abandon_pending(key, stream_id, code, execution);\n"
                "            return;\n"
                "        }\n",
                "",
            )
        ],
        frozenset(
            {
                UNARY_FREEZE
                + "a_unary_echo_whose_consumer_left_is_still_forgotten_and_keeps_the_session",
                UNARY_FREEZE + "a_unary_echo_invalidated_before_dispatch_is_reset_and_forgotten",
                UNARY_FREEZE
                + "a_unary_echo_abandoned_during_a_freeze_keeps_the_roster_and_resets_after_commit",
            }
        ),
    ),
    Case(
        # M7-C94: the connector's own RESET is recorded as its terminal.
        "a connector RESET on a unary echo is recorded as its terminal",
        [
            (
                ACTOR,
                "                        pending.abandon.connector_terminal = true;\n",
                "",
            )
        ],
        frozenset(
            {
                UNARY_FREEZE + "a_unary_echo_reset_by_the_connector_is_acknowledged_and_forgotten",
                UNARY_FREEZE + "a_unary_echo_invalidated_before_dispatch_is_reset_and_forgotten",
            }
        ),
    ),
    Case(
        # M7-C94: an undispatched abandoned echo is ended by the relay's RESET.
        "an abandoned undispatched unary echo is ended with the relay's RESET",
        [
            (
                ACTOR,
                "            let owes_reset =\n"
                "                !pending.dispatched && !pending.abandon.relay_reset && pending.abandon.admitted;",
                "            let owes_reset = false;",
            )
        ],
        frozenset(
            {
                UNARY_FREEZE + "a_unary_echo_invalidated_before_dispatch_is_reset_and_forgotten",
                UNARY_FREEZE
                + "a_unary_echo_abandoned_during_a_freeze_keeps_the_roster_and_resets_after_commit",
            }
        ),
    ),
]
M7_CONNECTOR_CLIENT_CASES: list[Case] = [
    Case(
        # M7-C84: an error raised after the stop's own cancellation is a stop.
        "an orderly stop that lands inside a tick is reported as stopped",
        [
            (
                CLIENT / "src" / "m2_runtime.rs",
                "        Err(error) => super::session_failure_result(cancellation_requested, error),",
                "        Err(error) => Err(error),",
            )
        ],
        frozenset(
            {
                "m2_runtime::tests::"
                "a_stop_inside_the_forget_barrier_tick_is_reported_as_stopped_by_the_real_loop",
                "m2_runtime::tests::"
                "a_stop_during_a_pending_forget_barrier_ends_the_session_as_stopped",
            }
        ),
    ),
    Case(
        # M7-C98: the writer resumes at COMMITTED on the activated carrier.
        "the connector writer resumes after ROTATE_COMMITTED",
        [
            (
                CLIENT / "src" / "m2_runtime.rs",
                "        self.writes_frozen = !resumed;",
                "        self.writes_frozen = true;",
            )
        ],
        frozenset(
            {
                "m2_runtime::tests::the_writer_resumes_on_the_activated_carrier_after_committed",
            }
        ),
    ),
    Case(
        # M7-C95: exhausted retention that never recovers gives the session up.
        "a session whose OPEN retention stays exhausted gives up with a typed cause",
        [
            (
                CLIENT / "src" / "m2_runtime.rs",
                "                if let Err(error) = actor.check_open_retention_exhaustion() {\n"
                "                    break Err(error);\n"
                "                }\n",
                "",
            )
        ],
        frozenset(
            {
                "m2_runtime::tests::"
                "an_owner_that_never_forgets_makes_the_session_give_up_with_a_typed_cause",
            }
        ),
    ),
]

SUITES: list[Suite] = [
    Suite("m3c09", [DEADMAN, EXPORT, FIXTURE], CARGO_TEST, CASES),
    Suite("m3c09-deadman", [DEADMAN], DEADMAN_TEST, DEADMAN_CASES),
    Suite("m6c08-doctor", [CLIENT], DOCTOR_TEST, DOCTOR_CASES),
    Suite("m3c25-resign-pin-wait", [HARNESS], PIN_WAIT_TEST, PIN_WAIT_CASES),
    Suite("m7c89-readiness-pins", [RELAY], READINESS_PINS_TEST, READINESS_PINS_CASES),
    Suite("m7c92-unary-echo", [RELAY], UNARY_ECHO_TEST, UNARY_ECHO_CASES),
    Suite(
        "m7c97-retiring-admission",
        [CLIENT],
        RETIRING_ADMISSION_TEST,
        RETIRING_ADMISSION_CASES,
    ),
    Suite("m3c32-release", [BRIDGE], RELEASE_TEST, RELEASE_CASES),
    Suite("m3c32-release-race", [BRIDGE], RELEASE_RACE_TEST, RELEASE_RACE_CASES),
    Suite("m3c33-m3c15-freeze-resend", [HARNESS], WIRE_TEST, WIRE_CASES),
    Suite("m3c15-freeze-hold", [RELAY], FREEZE_HOLD_TEST, FREEZE_HOLD_CASES),
    Suite("m3c31-forget-at-close", [RELAY], FORGET_AT_CLOSE_TEST, FORGET_AT_CLOSE_CASES),
    Suite(
        "m7-connector-relay",
        [RELAY],
        M7_CONNECTOR_RELAY_TEST,
        M7_CONNECTOR_RELAY_CASES,
    ),
    Suite(
        "m7-connector-client",
        [CLIENT],
        RETIRING_ADMISSION_TEST,
        M7_CONNECTOR_CLIENT_CASES,
    ),
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

    The binaries the tests `exec` are rebuilt first; see
    [`CARGO_BUILD_BINARIES`] for why a stale one is a silent false green.
    """
    try:
        built = subprocess.run(
            CARGO_BUILD_BINARIES,
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


def sweep_residue() -> None:
    """Kill anything this suite's fixtures left behind.

    Unlike every other guard-deletion harness in this repository, the cases
    here deliberately defeat process cleanup, and a case that goes red is
    *precisely* a case where something survived.  The fixture's own pid guards
    handle the ordinary path, but a build failure or a timeout can leave a
    descendant with a 180-second lifetime running on a developer's machine.
    Nothing else in this file may assume it was tidy.
    """
    for mode in ("detached", "descendant", "wrapper", "supervise", "daemonize"):
        subprocess.run(
            ["/usr/bin/pkill", "-9", "-f", f"tunnel-mcp-fixture {mode}"],
            capture_output=True,
            check=False,
        )
    subprocess.run(
        ["/usr/bin/pkill", "-9", "-f", "tunnel-deadman "],
        capture_output=True,
        check=False,
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
                    "m3-guard-deletion: refusing to run with uncommitted changes "
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
    """Resolve every selected case's guard text, and stop (M4-27).

    The resolution, the STALLED/AMBIGUOUS split and the empty-selection
    refusal all live in `scripts/guard_outcomes.py`, shared with the other
    three harnesses; this only drops the per-case `expect_build_failure` flag,
    which an anchor check has no use for.
    """
    return shared_check_anchors(
        "m3-guard-deletion",
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
        'm3-guard-deletion',
        (
            (suite.name, case.name, case.expect_build_failure, case.expected_red)
            for suite, case in selected
        ),
        DEBT,
    )


#: This harness owes no witnesses: every value case declares one.
DEBT = load_witness_debt('m3-guard-deletion')


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
    parser.add_argument("--suite", help="run only this suite (see --list)")
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
            sys.exit(f"m3-guard-deletion: no suite named {arguments.suite!r}")
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
            'm3-guard-deletion',
            _anchor_selection(selected),
        )
    if not selected:
        sys.exit(f"m3-guard-deletion: no case matches {arguments.case!r}")

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
    require_git_index("m3-guard-deletion", REPO)
    refuse_resident_mutation("m3-guard-deletion", REPO)
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
    for suite, case in selected:
        name = case.name
        # **M5-C07.**  The apply/test/restore cycle runs inside a context
        # manager, so the restore happens on *every* way out of this block --
        # a refusal, an exception, a `KeyboardInterrupt`, or the `SystemExit`
        # that `install_interrupt_restore` turns a `SIGTERM` into.  It
        # restores the exact recorded original bytes rather than running `git
        # checkout --` over the crate, which would discard any other
        # uncommitted work under that path (M4-32).  This harness is the one
        # M4-36 bypassed into running its whole destructive suite under
        # `--check-anchors`, so an interrupted case here is not hypothetical.
        #
        # The residue sweep is in a `finally` for the same reason the restore
        # is in a context manager: this suite's cases deliberately defeat
        # process cleanup, so an *interrupted* case is exactly the one whose
        # fixtures are most likely to have outlived it.  Leaving the sweep
        # after the `with` block meant an interrupt skipped it -- the tree
        # stayed clean, but descendants with a 180-second lifetime were left
        # running on the developer's machine.  It is inside the `try` so it
        # also runs after the restore rather than racing it.
        try:
            with AppliedCase("m3-guard-deletion", REPO, suite.name, name) as applied:
                problem = applied.apply_all(case.edits)
                if problem is not None:
                    results.append((suite.name, name, f"COULD NOT APPLY: {problem}", []))
                    print(f"[{suite.name}] {name}: {problem}", flush=True)
                    continue
                outcome, failures = run_tests(suite)
        finally:
            sweep_residue()
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

    # **M4-26, again.**  The index loss that matters happens *mid-run*: a
    # check only at the start would certify an index that was gone by the
    # end, and a count from a run whose index state was not confirmed is not
    # a measurement.
    require_git_index("m3-guard-deletion", REPO)

    unusable = unusable_outcomes(
        (suite_name, name, outcome) for suite_name, name, outcome, _ in results
    )
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
