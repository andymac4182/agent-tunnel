#!/bin/sh
# Task row M6-C23: `tunnel-client connect` reconnects after losing its relay,
# proved with shipped binaries against a real Redis.
#
#   TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/m6-reconnect-verify.sh
#
# 1. Builds `tunnel-relay` and `tunnel-client` into the caller's target
#    directory, so the gate never runs a stale client.
# 2. Runs `crates/tunnel-relay/tests/m6_reconnect_process.rs`: a relay
#    SIGKILLed and restarted, then stopped with SIGTERM and restarted, under a
#    running `connect` that must reconnect and serve an echo each time; and a
#    `connect` started before its relay, which must back off until `serve`
#    appears; a device certificate not yet valid (clock skew), which must be
#    retried until it is; an expired one, which must exit 3 at once; and a
#    device_id mismatch, which the relay refuses with 1008
#    DEVICE_IDENTITY_REJECTED (M6-C32) and which must exit 3 without a retry;
#    and a rogue device CA and a wrong server CA (M6-C54), each exit 3; and
#    (M6-C68) a device whose path is cut behind a proxy while the relay's side
#    stays open, which the relay must evict within its idle timeout so the
#    device's reconnect is admitted -- after a healthy idle session has first
#    survived longer than that timeout.
#
# Both tests are `#[ignore]`d in the ordinary workspace run because they need
# Redis.  A filtered or skipped test would print `0 passed` and exit 0, so this
# script requires the run's own pass count and each gate's `m6c23-reconnect ok`
# line, and exits 1 when any is missing: green here means the tests ran.
set -eu

if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m6-reconnect-verify: TEST_REDIS_URL (a disposable plaintext Redis) is required." >&2
  exit 2
fi
export TEST_REDIS_URL

target_dir=${CARGO_TARGET_DIR:-$(pwd)/target}
if [ -n "${M6_RECONNECT_BIN_DIR:-}" ]; then
  export TUNNEL_CLIENT_BIN="$M6_RECONNECT_BIN_DIR/tunnel-client"
  export TUNNEL_RELAY_BIN="$M6_RECONNECT_BIN_DIR/tunnel-relay"
else
  export TUNNEL_CLIENT_BIN="$target_dir/debug/tunnel-client"
fi
scratch=$(mktemp -d "${TMPDIR:-/tmp}/m6-reconnect-verify.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

echo "m6-reconnect-verify: build tunnel-relay and tunnel-client" >&2
cargo build --locked -p tunnel-relay -p tunnel-client --bins

echo "m6-reconnect-verify: reconnect gates" >&2
cargo test -p tunnel-relay --test m6_reconnect_process --locked -- --ignored --nocapture --test-threads=1 \
  > "$scratch/reconnect.log" 2>&1 || { cat "$scratch/reconnect.log" >&2; exit 1; }
cat "$scratch/reconnect.log"
for needle in "test result: ok. 7 passed" "m6c23-reconnect ok label=restart nonce=" \
  "m6c23-reconnect ok label=late-relay nonce=" "m6c23-reconnect ok label=not-yet-valid nonce=" \
  "m6c23-reconnect ok label=expired nonce=" "m6c23-reconnect ok label=identity nonce=" "m6c23-reconnect ok label=issuer nonce=" \
  "m6c68-liveness ok label=cut-path nonce=" \
  "client=$TUNNEL_CLIENT_BIN"; do
  if ! grep -q -- "$needle" "$scratch/reconnect.log"; then
    echo "m6-reconnect-verify: FAILED: output lacks '$needle'" >&2
    exit 1
  fi
done
echo "m6-reconnect-verify: ok" >&2
