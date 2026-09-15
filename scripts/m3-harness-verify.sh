#!/bin/sh
set -eu

# M3 harness gates.  M3 application gates run over the M7 production cluster
# fixture (three in-process relays, real HTTP/3 peers, real device WebSockets)
# but prove M3 behavior, so they are registered here rather than in the M7
# suite.  Keep Cargo configuration supplied by the caller intact.
if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m3-harness-verify: TEST_REDIS_URL is required for a disposable Redis primary." >&2
  exit 2
fi

if [ -z "${TUNNEL_CATALOG_REDIS_URL:-}" ]; then
  export TUNNEL_CATALOG_REDIS_URL="$TEST_REDIS_URL"
fi

gate() {
  label=$1
  shift
  echo "m3-harness-verify: ${label}" >&2
  "$@"
}

gate "build locked workspace binaries" \
  cargo build --locked --workspace --bins

gate "M3 http-forward/1 gate 3 over non-owner ingress, peer HTTP/3 and the device WebSocket" \
  cargo run --locked -p tunnel-test-harness -- verify-m3-http-forward-real-path
gate "M3 http-forward/1 gate 4 rotation points, CANCEL/RESET race and outcome_unknown" \
  cargo run --locked -p tunnel-test-harness -- verify-m3-http-forward-rotation
gate "M3 MCP cloud client (rmcp) over non-owner ingress and the rotating tunnel to stdio and Streamable HTTP exports" \
  cargo run --locked -p tunnel-test-harness -- verify-m3-mcp-cloud-client

echo "m3-harness-verify: implemented M3 harness suite passed" >&2
