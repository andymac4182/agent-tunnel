#!/bin/sh
# Task row M6-C21: operator provisioning of one relay and one device, proved
# with shipped binaries against a real Redis.
#
#   TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/m6-provisioning-verify.sh
#
# 1. Builds `tunnel-relay` and `tunnel-client` into the caller's target
#    directory, so the end-to-end gate never runs a stale client.
# 2. Runs the catalog-level tests of first activation and provisioning
#    (`crates/tunnel-catalog/tests/redis_provisioning.rs`).
# 3. Runs the end-to-end gate (`crates/tunnel-relay/tests/m6_provisioning_process.rs`):
#    empty namespace -> `activate-first-incarnation` -> `provision-catalog` ->
#    `serve` + `connect` -> one echo through the tunnel, then two identity
#    refusals (task row M6-C32) that must reach the device as a terminal
#    CREDENTIAL_ERROR, exit 3, and a not-yet-valid credential that must stay
#    a retryable TRANSPORT_ERROR, exit 4.
# 4. Runs task row M7-C92's gate in the same binary: 300 sequential unary
#    echoes (more than twice the connector's 128-entry OPEN retention) and
#    two data rotations in one device session, every one answered 200.
#
# Both tests are `#[ignore]`d in the ordinary workspace run because they need
# Redis.  A filtered or skipped test would print `0 passed` and exit 0, so this
# script requires each run's own pass count and the gate's `m6c21-e2e ok`
# line, and exits 1 when either is missing: green here means the tests ran.
set -eu

if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m6-provisioning-verify: TEST_REDIS_URL (a disposable plaintext Redis) is required." >&2
  exit 2
fi
: "${TUNNEL_CATALOG_REDIS_URL:=$TEST_REDIS_URL}"
export TEST_REDIS_URL TUNNEL_CATALOG_REDIS_URL

target_dir=${CARGO_TARGET_DIR:-$(pwd)/target}
# M6_PROVISIONING_BIN_DIR runs the end-to-end gate against another build of
# both binaries, such as an unpacked release bundle's bin/; the default is the
# pair this script builds.
if [ -n "${M6_PROVISIONING_BIN_DIR:-}" ]; then
  export TUNNEL_CLIENT_BIN="$M6_PROVISIONING_BIN_DIR/tunnel-client"
  export TUNNEL_RELAY_BIN="$M6_PROVISIONING_BIN_DIR/tunnel-relay"
else
  export TUNNEL_CLIENT_BIN="$target_dir/debug/tunnel-client"
fi
scratch=$(mktemp -d "${TMPDIR:-/tmp}/m6-provisioning-verify.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

echo "m6-provisioning-verify: build tunnel-relay and tunnel-client" >&2
cargo build --locked -p tunnel-relay -p tunnel-client --bins

require() {
  label=$1
  log=$2
  shift 2
  for needle in "$@"; do
    if ! grep -q -- "$needle" "$log"; then
      echo "m6-provisioning-verify: FAILED $label: output lacks '$needle'" >&2
      exit 1
    fi
  done
  echo "m6-provisioning-verify: ok $label" >&2
}

echo "m6-provisioning-verify: catalog first activation and provisioning" >&2
cargo test -p tunnel-catalog --test redis_provisioning --locked -- --ignored --test-threads=1 \
  > "$scratch/catalog.log" 2>&1 || { cat "$scratch/catalog.log" >&2; exit 1; }
cat "$scratch/catalog.log"
require "catalog provisioning tests" "$scratch/catalog.log" "test result: ok. 3 passed"

echo "m6-provisioning-verify: end-to-end shipped-binary gate" >&2
cargo test -p tunnel-relay --test m6_provisioning_process --locked -- --ignored --nocapture \
  --test-threads=1 > "$scratch/e2e.log" 2>&1 || { cat "$scratch/e2e.log" >&2; exit 1; }
cat "$scratch/e2e.log"
require "end-to-end gate" "$scratch/e2e.log" "test result: ok. 2 passed" "m6c21-e2e ok nonce=" \
  "client=$TUNNEL_CLIENT_BIN" \
  "m6c32 device_id mismatch exit=3 code=CREDENTIAL_ERROR retryable=false" \
  "m6c32 unknown credential key exit=3 code=CREDENTIAL_ERROR retryable=false" \
  "m6c32 credential not yet valid exit=4 code=TRANSPORT_ERROR retryable=true" \
  "m7c92-echo ok nonce=" "required=300 sessions=1"
if [ -n "${TUNNEL_RELAY_BIN:-}" ]; then
  require "end-to-end gate ran the requested relay" "$scratch/e2e.log" "relay=$TUNNEL_RELAY_BIN"
fi
