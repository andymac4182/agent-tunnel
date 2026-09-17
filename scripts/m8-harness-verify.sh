#!/bin/sh
set -eu

# M8 harness gates.  The ACP gates run over the M7 production cluster fixture
# (three in-process relays, real HTTP/3 peers, real device WebSockets) but
# prove M8 behavior, so they are registered here rather than in the M7, M4 or
# M3 suites.  Keep Cargo configuration supplied by the caller intact.
if [ -z "${TEST_REDIS_URL:-}" ]; then
  echo "m8-harness-verify: TEST_REDIS_URL is required for a disposable Redis primary." >&2
  exit 2
fi

if [ -z "${TUNNEL_CATALOG_REDIS_URL:-}" ]; then
  export TUNNEL_CATALOG_REDIS_URL="$TEST_REDIS_URL"
fi

# The ACP gate starts the agent fixture by absolute path.  `cargo build` below
# puts it next to the harness binary, which is where the gate looks by
# default; this only has to be set when the caller has moved it.
if [ -n "${TUNNEL_ACP_FIXTURE_BIN:-}" ]; then
  export TUNNEL_ACP_FIXTURE_BIN
fi

gate() {
  label=$1
  shift
  echo "m8-harness-verify: ${label}" >&2
  "$@"
}

gate "build locked workspace binaries" \
  cargo build --locked --workspace --bins

# **What this gate does not claim.**  It re-signs membership only at case
# boundaries and at most every 15 s, which is a harness accommodation for the
# open defect M7-C80 — a same-key membership re-sign invalidates every peer
# admission and every stream riding it, and ACP is a long-lived SSE response
# through a non-owner ingress.  Nothing here shows an ACP connection surviving
# normal cluster operation.  The gate's own NOT_COVERED carries this too.
gate "M8 ACP over three relays: a v1 conversation, permissions, cancellation, subscriber loss and an unknown outcome through a non-owner ingress" \
  cargo run --locked -p tunnel-test-harness -- verify-m8-acp-real-path

echo "m8-harness-verify: implemented M8 harness suite passed" >&2
