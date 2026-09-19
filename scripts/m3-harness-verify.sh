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
gate "M3-04 MCP session isolation, concurrent correlation, unknown outcomes, revocation and rotation across two principals" \
  cargo run --locked -p tunnel-test-harness -- verify-m3-mcp-isolation

# M3-09.  These read the process table for what the stdio export's children
# left behind, and one of them SIGKILLs a supervisor, so they are registered
# here rather than left to `cargo test --workspace` alone: a gate names the
# claim, and a green workspace run does not.  `--test-threads=1` because the
# measurements are of a shared, global resource — the process table — and two
# of them running at once would read each other's descendants.
#
# These tests `exec` the `tunnel-mcp-fixture` and `tunnel-deadman` binaries and
# `cargo test --test` builds neither (M3-19), so they depend on the workspace
# `--bins` build above having already refreshed them.  Do not reorder them.
gate "M3-09 stdio export process-tree residue: two escaping descendants, the in-group control, and a SIGKILLed supervisor" \
  cargo test --locked -p tunnel-mcp-fixture --test process_residue -- --test-threads=1

echo "m3-harness-verify: implemented M3 harness suite passed" >&2
