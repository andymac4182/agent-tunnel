#!/bin/sh
# The ACP demo (docs/demo/acp.md): the official pinned ACP client runs one
# session -- initialize, session/new, streaming updates, a permission callback
# answered, and a turn cancelled -- through a real local relay to a device's
# ACP export, which supervises the repository's synthetic ACP agent on stdio.
#
#   TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/demo-acp.sh
#
# Every hop is a shipped binary in its own process: `tunnel-relay serve` (the
# relay, provisioned from examples/m6-catalog-acp.toml with the shipped
# commands), `tunnel-client connect` (the device, holding the ACP export), the
# agent `tunnel-acp-fixture agent` (started by the device, never by the
# relay), and `acp-demo-client` (the consumer, built from
# agent-client-protocol-http =2.1.0).  The bring-up is the M6-C57 gate's,
# driven by crates/tunnel-relay/tests/m6_provisioning_process.rs.
#
# Needs: a disposable plaintext Redis (TEST_REDIS_URL; the test puts a local
# TLS forwarder in front of it because `serve` accepts only rediss://), and
# `openssl` on PATH.  Uses a fresh random Redis namespace and deletes it.
#
# Exit 0 only when the demo's own transcript and the agent's own marker file
# both show every step, and the test printed its `m8-acp-demo ok` line.
set -eu

if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "demo-acp: TEST_REDIS_URL (a disposable plaintext Redis) is required." >&2
  exit 2
fi
: "${TUNNEL_CATALOG_REDIS_URL:=$TEST_REDIS_URL}"
export TEST_REDIS_URL TUNNEL_CATALOG_REDIS_URL

target_dir=${CARGO_TARGET_DIR:-$(pwd)/target}
export TUNNEL_CLIENT_BIN="$target_dir/debug/tunnel-client"
export TUNNEL_ACP_FIXTURE_BIN="$target_dir/debug/tunnel-acp-fixture"
export TUNNEL_ACP_DEMO_CLIENT_BIN="$target_dir/debug/acp-demo-client"

echo "demo-acp: build tunnel-relay, tunnel-client, the ACP agent and the demo client" >&2
cargo build --locked -p tunnel-relay -p tunnel-client -p tunnel-acp-fixture --bins
# Its own command: the pinned client's reqwest must not join the build above.
cargo build --locked -p tunnel-acp-fixture --features interop --bin acp-demo-client

log=$(mktemp "${TMPDIR:-/tmp}/demo-acp.XXXXXX")
trap 'rm -f "$log"' EXIT
echo "demo-acp: run the session through a local relay" >&2
if ! cargo test --locked -p tunnel-relay --test m6_provisioning_process -- --ignored \
  --nocapture --exact m8_acp_demo_official_client_runs_a_session_through_the_relay \
  > "$log" 2>&1; then
  cat "$log" >&2
  echo "demo-acp: FAILED (the transcript above names the step)" >&2
  exit 1
fi
grep -E '^demo: |^m8-acp-demo ok' "$log"
for needle in "test result: ok. 1 passed" "demo: PASS" "m8-acp-demo ok nonce="; do
  if ! grep -q -- "$needle" "$log"; then
    cat "$log" >&2
    echo "demo-acp: FAILED: output lacks '$needle'" >&2
    exit 1
  fi
done
echo "demo-acp: ok" >&2
