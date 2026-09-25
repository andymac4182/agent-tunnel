#!/bin/sh
# Task row M6-06: clean shutdown from every data-socket rotation phase, on
# shipped binaries against a real Redis.
#
#   TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/m6-shutdown-phases-verify.sh
#
# 1. Builds `tunnel-relay`, and `tunnel-client` **with `--features
#    test-hooks`** into a separate directory, so the hooked client can never
#    be mistaken for the shipped one and the gate never runs a stale build.
#    The hook (`TUNNEL_CLIENT_TEST_HOLD`) holds a rotation at a chosen step;
#    the default build has no such variable.
# 2. Runs `crates/tunnel-relay/tests/m6_shutdown_phases_process.rs`: for each
#    of active, preparing, quiescing, draining, committing and aborting, the
#    client (first test) and the relay (second test) is sent SIGTERM while it
#    reports that phase, and must exit 0 in order, leave no process in its
#    group, release the device's owner slot, and give the echo in flight an
#    explicit outcome.
#
# Both tests are `#[ignore]`d in the ordinary workspace run.  A filtered or
# skipped test prints `0 passed` and exits 0, so this script requires the
# run's own pass count, every case's `m606-shutdown ok` line and both
# matrices' summary lines, and exits 1 when any is missing: green here means
# the tests ran.
set -eu

if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m6-shutdown-phases-verify: TEST_REDIS_URL (a disposable plaintext Redis) is required." >&2
  exit 2
fi
export TEST_REDIS_URL

target_dir=${CARGO_TARGET_DIR:-$(pwd)/target}
hooks_dir="$target_dir/m606-test-hooks"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/m6-shutdown-phases-verify.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

echo "m6-shutdown-phases-verify: build tunnel-relay" >&2
cargo build --locked -p tunnel-relay --bins
echo "m6-shutdown-phases-verify: build tunnel-client --features test-hooks" >&2
CARGO_TARGET_DIR="$hooks_dir" cargo build --locked -p tunnel-client --bins --features test-hooks
export TUNNEL_CLIENT_BIN="$hooks_dir/debug/tunnel-client"

echo "m6-shutdown-phases-verify: shutdown matrix" >&2
cargo test -p tunnel-relay --test m6_shutdown_phases_process --locked -- --ignored --nocapture --test-threads=1 \
  > "$scratch/shutdown.log" 2>&1 || { cat "$scratch/shutdown.log" >&2; exit 1; }
cat "$scratch/shutdown.log"
for needle in "test result: ok. 2 passed" \
  "m606-shutdown matrix ok side=client cases=6" "m606-shutdown matrix ok side=relay cases=6" \
  "client=$TUNNEL_CLIENT_BIN"; do
  if ! grep -q -- "$needle" "$scratch/shutdown.log"; then
    echo "m6-shutdown-phases-verify: FAILED: output lacks '$needle'" >&2
    exit 1
  fi
done
for side in client relay; do
  for phase in active preparing quiescing draining committing aborting; do
    if ! grep -q -- "m606-shutdown ok case=$side-$phase " "$scratch/shutdown.log"; then
      echo "m6-shutdown-phases-verify: FAILED: no ok line for $side-$phase" >&2
      exit 1
    fi
  done
done
echo "m6-shutdown-phases-verify: ok" >&2
