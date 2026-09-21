#!/bin/sh
set -eu

# Gate 9 over a **run set**, checking the half a single run cannot check.
#
# A connector that stops closes both of its sockets and the relay may notice
# either loss first.  Control first tears the session down as `CONTROL_CLOSED`;
# data first as `REVERSE_CHANNEL_UNAVAILABLE`.  Both are the same event and the
# consumer must be told the same thing, but before M4-35 only the first
# published a cause, so the second reached the consumer with no close code at
# all -- 7 red in 24 runs on the measuring host.
#
# That is why a run count alone is not evidence here.  Twenty green runs are
# equally consistent with a fix that works and with a scheduler that simply
# stopped taking the ordering that used to fail, and the second is worth
# nothing.  So this asserts two things a single run cannot:
#
#   1. every run in the set passed; and
#   2. the set actually **exercised both orderings**, read from the gate's own
#      `held_session_teardown_reason` evidence rather than from a relay log.
#
# Rule 2 is a coverage check, not a contract: which ordering a run takes is a
# scheduling race, so a set can legitimately never see one of them.  That is
# exit 3 -- a third verdict, neither pass nor fail.
#
# WHAT TO DO ON EXIT 3: re-run with a larger RUNS.  Do **not** treat it as a
# failure, and do not treat it as a pass: the tree is fine and the set simply
# did not cover the ordering it was run to cover, so it answers nothing.  A 1
# means something is actually wrong.
#
# WHAT THIS IS FOR, AND WHAT IT IS NOT.  It is an **on-demand** check, run by a
# person closing a row that turns on this behaviour.  It is deliberately NOT
# wired into `m4-harness-verify.sh` or any other registry, and must not be:
# exit 3 is expected on a correct tree, so a registry that ran this would go
# intermittently red for a reason that is not a defect -- which is precisely
# the instrument-unreliability defect M4-35 exists to have removed.  The
# per-run rule inside gate 9 is the part that belongs in the registry, and it
# is already there.
#
# CHOOSING RUNS.  The default is deliberate rather than round.  Three post-fix
# sets of 20 took the data-first ordering 11, 8 and 2 times -- a factor of five
# on one host with one binary -- so the rate is not merely low, it is unstable,
# and the low end is what a default has to survive.  At the lowest observed
# rate (2 in 20) a 20-run set misses that ordering about one time in eight,
# which is far too often for the default of a script whose whole purpose is to
# cover it; 40 runs cut that to roughly one in sixty.  So the default is 40 and
# a smaller N is a spot check you opt into, rather than the other way round.
# Budget about a minute per run.
#
# Usage: scripts/m4-gate9-ordering.sh [runs]   (default 40; see CHOOSING RUNS)

if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m4-gate9-ordering: TEST_REDIS_URL is required for a disposable Redis primary." >&2
  exit 2
fi
if [ -z "${TUNNEL_CATALOG_REDIS_URL:-}" ]; then
  TUNNEL_CATALOG_REDIS_URL="$TEST_REDIS_URL"
  export TUNNEL_CATALOG_REDIS_URL
fi

RUNS=${1:-40}
control=0
reverse=0
other=0
unattributed=0
failed=0

run=1
while [ "$run" -le "$RUNS" ]; do
  red=0
  out=$(cargo run --locked -p tunnel-test-harness -- verify-m4-fs-epoch-change 2>&1) || red=1
  # A red run's reason is NOT on the evidence line -- the harness prints that
  # only after every rule passes -- so it has to be read out of the failing
  # rule itself.  The ordering rule is checked before the close-code rule for
  # exactly this reason: a run that took the third, unclosed teardown ordering
  # reports `observed Some("DEVICE_OFFLINE")` here instead of wearing the
  # `expected 1012, observed None` signature M4-35 closed.
  reason=$(printf '%s\n' "$out" \
    | sed -n -e 's/.*held_session_teardown_reason=Some(\("[A-Z_]*"\)).*/\1/p' \
             -e 's/.*by either socket (observed Some(\("[A-Z_]*"\))).*/\1/p' \
    | tr -d '"' | head -1)
  if [ "$red" -ne 0 ]; then
    failed=$((failed + 1))
    # Print why, rather than swallowing it: a red run whose reason nobody sees
    # is how an unclosed path gets mistaken for a closed one coming back.
    printf '%s\n' "$out" | grep -E "gate failed:|managed process error" >&2 || \
      echo "m4-gate9-ordering: run ${run} failed with no gate line" >&2
  fi
  case "$reason" in
    CONTROL_CLOSED) control=$((control + 1)) ;;
    REVERSE_CHANNEL_UNAVAILABLE) reverse=$((reverse + 1)) ;;
    "") unattributed=$((unattributed + 1)) ;;
    # A reason outside the two is not "no reason": it is a teardown this gate
    # does not cover, and saying so is the whole point of printing it.
    *) other=$((other + 1)) ;;
  esac
  echo "m4-gate9-ordering: run ${run}/${RUNS} reason=${reason:-none}" >&2
  run=$((run + 1))
done

echo "m4-gate9-ordering: runs=${RUNS} failed=${failed} control_first=${control} data_first=${reverse} other_reason=${other} unattributed=${unattributed}" >&2

if [ "$failed" -ne 0 ]; then
  echo "m4-gate9-ordering: ${failed} of ${RUNS} runs failed; their gate lines are above." >&2
  exit 1
fi
if [ "$other" -ne 0 ]; then
  echo "m4-gate9-ordering: ${other} run(s) ended for a teardown this gate does not cover." >&2
  exit 1
fi
if [ "$unattributed" -ne 0 ]; then
  echo "m4-gate9-ordering: ${unattributed} run(s) recorded no teardown reason, so the set is not attributable." >&2
  exit 1
fi
if [ "$control" -eq 0 ] || [ "$reverse" -eq 0 ]; then
  echo "m4-gate9-ordering: every one of ${RUNS} runs took the same ordering, so this set covers nothing about the other one." >&2
  echo "m4-gate9-ordering: this is NOT a failure and NOT a pass -- the tree is fine and the set answers nothing. Re-run with a larger run count (try $((RUNS * 2)))." >&2
  exit 3
fi

echo "m4-gate9-ordering: ${RUNS} runs passed, both socket-loss orderings exercised" >&2
