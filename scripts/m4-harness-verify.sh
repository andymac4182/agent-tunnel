#!/bin/sh
set -eu

# M4 harness gates.  The M4 filesystem gates run over the M7 production cluster
# fixture (three in-process relays, real HTTP/3 peers, real device WebSockets)
# but prove M4 behavior, so they are registered here rather than in the M7 or
# M3 suites.  Keep Cargo configuration supplied by the caller intact.
if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m4-harness-verify: TEST_REDIS_URL is required for a disposable Redis primary." >&2
  exit 2
fi

if [ -z "${TUNNEL_CATALOG_REDIS_URL:-}" ]; then
  export TUNNEL_CATALOG_REDIS_URL="$TEST_REDIS_URL"
fi

gate() {
  label=$1
  shift
  echo "m4-harness-verify: ${label}" >&2
  "$@"
}

gate "build locked workspace binaries" \
  cargo build --locked --workspace --bins

gate "M4 filesystem gate 4: descriptor, refusal matrix, 9P session, capability matrix and refused mutations" \
  cargo run --locked -p tunnel-test-harness -- verify-m4-fs-real-path

gate "M4 filesystem gate 5: write grants, the hard-link write rule, an interrupted write and partial failure" \
  cargo run --locked -p tunnel-test-harness -- verify-m4-fs-write-path

echo "m4-harness-verify: implemented M4 harness suite passed" >&2
