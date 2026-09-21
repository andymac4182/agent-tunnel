#!/bin/sh
set -eu

# Gate 9 over a **run set**, checking the half a single run cannot check.
#
# A connector that stops closes both of its sockets and the relay may notice
# either loss first.  Control first tears the session down as `CONTROL_CLOSED`;
# data first as `REVERSE_CHANNEL_UNAVAILABLE`.  Both are the same event and the
# consumer must be told the same thing, but before M4-35 only the first
# published a cause, so the second reached the consumer with no close code at
# all -- roughly a third of runs on the measuring host.
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
# scheduling race, so on a host that always schedules one way this exits 3 and
# says the set proved nothing about the other ordering -- which is a different
# verdict from a failure, and is reported as one.  Raise RUNS rather than
# treating a 3 as a pass.
#
# Usage: scripts/m4-gate9-ordering.sh [runs]   (default 12)

if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m4-gate9-ordering: TEST_REDIS_URL is required for a disposable Redis primary." >&2
  exit 2
fi
if [ -z "${TUNNEL_CATALOG_REDIS_URL:-}" ]; then
  TUNNEL_CATALOG_REDIS_URL="$TEST_REDIS_URL"
  export TUNNEL_CATALOG_REDIS_URL
fi

RUNS=${1:-12}
control=0
reverse=0
other=0
failed=0

run=1
while [ "$run" -le "$RUNS" ]; do
  out=$(cargo run --locked -p tunnel-test-harness -- verify-m4-fs-epoch-change 2>&1) || failed=$((failed + 1))
  reason=$(printf '%s\n' "$out" \
    | sed -n 's/.*held_session_teardown_reason=Some(\("[A-Z_]*"\)).*/\1/p' \
    | tr -d '"' | head -1)
  case "$reason" in
    CONTROL_CLOSED) control=$((control + 1)) ;;
    REVERSE_CHANNEL_UNAVAILABLE) reverse=$((reverse + 1)) ;;
    *) other=$((other + 1)) ;;
  esac
  echo "m4-gate9-ordering: run ${run}/${RUNS} reason=${reason:-none}" >&2
  run=$((run + 1))
done

echo "m4-gate9-ordering: runs=${RUNS} failed=${failed} control_first=${control} data_first=${reverse} unattributed=${other}" >&2

if [ "$failed" -ne 0 ]; then
  echo "m4-gate9-ordering: ${failed} of ${RUNS} runs failed." >&2
  exit 1
fi
if [ "$other" -ne 0 ]; then
  echo "m4-gate9-ordering: ${other} run(s) recorded no teardown reason, so the set is not attributable." >&2
  exit 1
fi
if [ "$control" -eq 0 ] || [ "$reverse" -eq 0 ]; then
  echo "m4-gate9-ordering: every run took the same ordering, so this set proves nothing about the other one. Not a failure; raise the run count." >&2
  exit 3
fi

echo "m4-gate9-ordering: ${RUNS} runs passed, both socket-loss orderings exercised" >&2
