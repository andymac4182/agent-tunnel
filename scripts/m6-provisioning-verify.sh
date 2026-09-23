#!/bin/sh
# Task row M6-C21: operator provisioning of one relay and one device, proved
# with shipped binaries against a real Redis.
#
#   TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/m6-provisioning-verify.sh
#
# 1. Builds `tunnel-relay` and `tunnel-client` into the caller's target
#    directory, so the end-to-end gate never runs a stale client.
# 2. Runs the catalog-level tests of first activation and provisioning
#    (`crates/tunnel-catalog/tests/redis_provisioning.rs`), and the Redis
#    connection stage tests (`redis_connection_stage.rs`, task row M6-C72).
# 3. Runs the end-to-end gate (`crates/tunnel-relay/tests/m6_provisioning_process.rs`):
#    empty namespace -> `activate-first-incarnation` -> `provision-catalog` ->
#    `serve` + `connect` -> one echo through the tunnel, then two identity
#    refusals (task row M6-C32) that must reach the device as a terminal
#    CREDENTIAL_ERROR, exit 3, and a not-yet-valid credential that must stay
#    a retryable TRANSPORT_ERROR, exit 4.  Before activating, it also runs
#    `activate-first-incarnation` against a wrong Redis CA, a wrong password,
#    an ACL user without INFO and a Redis that requires a client certificate,
#    and requires each to print its own stage and class (M6-C72).
# 4. Runs task row M7-C92's gate in the same binary: 300 sequential unary
#    echoes (more than twice the connector's 128-entry OPEN retention) and
#    two data rotations in one device session, every one answered 200, and
#    task row M7-C93's gate: echoes paced across two rotations, capped below
#    the retention so it can only be red for the rotation defect.
# 5. Runs task row M6-C57's gates in the same binary: an MCP, an ACP and a
#    filesystem service, each provisioned from its shipped records example
#    (examples/m6-catalog-{mcp,acp,fs}.toml) with the shipped commands and
#    served by `connect` with the export that example documents, backed by
#    the repository's MCP and ACP fixture binaries and a temporary directory.
#    Each must answer one real consumer request from the device-side backend:
#    MCP `initialize` and a `tools/call`, ACP `initialize`, and a 9P read of
#    a synthetic file.
# 6. Runs task row M6-C31's gate in the same binary: with `serve` running and
#    never restarted, `add-user`, `add-device` (a new key and a certificate
#    from the test's synthetic device CA), `add-service` and `set-grant` add a
#    second user and device; the second device connects and serves the
#    second user an echo; the first request after `set-grant` is served and
#    the first after `revoke-grant` refused; `revoke-device` closes the live
#    session (`AUTHORIZATION_REVOKED`) and the device exits 3.  Its catalog
#    test (M6-C31, in step 2) proves each addition refuses an unprovisioned
#    namespace, a stale incarnation and every duplicate, and leaves the
#    incarnation, run and reservation keys unchanged.
#
# 7. Runs task row M6-C65's catalog test in step 2: the `unbound` and
#    `run_changed` classes of `serve`'s fence, `rebind-redis-run`'s catalog
#    call with each refusal, and a single relay's continuity token.  The
#    M6-C65 process gate restarts a Redis, so it is not run here (it never
#    touches `TEST_REDIS_URL`); `scripts/m6-redis-restart-verify.sh` runs it
#    against its own Redis container, and this step skips it by name.
#
# Every Redis test these steps run is `#[ignore]`d in the ordinary workspace
# run because it needs Redis: the 5 catalog provisioning tests, the 3 Redis
# connection stage tests, and the 7 end-to-end tests (M6-C21, M7-C92, M7-C93,
# the three M6-C57 service gates and M6-C31).  A filtered or skipped test
# would print `0 passed` and exit 0, so this script requires each run's own
# pass count and each gate's own `ok` line (`m6c21-e2e`, `m7c92-echo`,
# `m7c93-rotation`, `m6c57-mcp`, `m6c57-acp`, `m6c57-fs`, each M6-C57 line
# with the refused stranger's exact `stranger_status=401`, `m6c31-catalog`
# with its measured fields), and exits 1 when any is missing: green here
# means the tests ran.
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
# The M6-C57 backends are test fixtures, never bundled, so they are always
# the pair this script builds.
export TUNNEL_MCP_FIXTURE_BIN="$target_dir/debug/tunnel-mcp-fixture"
export TUNNEL_ACP_FIXTURE_BIN="$target_dir/debug/tunnel-acp-fixture"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/m6-provisioning-verify.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

echo "m6-provisioning-verify: build tunnel-relay, tunnel-client and the MCP and ACP fixtures" >&2
cargo build --locked -p tunnel-relay -p tunnel-client -p tunnel-mcp-fixture \
  -p tunnel-acp-fixture --bins

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
cargo test -p tunnel-catalog --test redis_provisioning --locked -- --ignored --nocapture --test-threads=1 \
  > "$scratch/catalog.log" 2>&1 || { cat "$scratch/catalog.log" >&2; exit 1; }
cat "$scratch/catalog.log"
require "catalog provisioning tests" "$scratch/catalog.log" "test result: ok. 5 passed" \
  "m6c65-catalog ok namespace="

echo "m6-provisioning-verify: Redis connection stage, lane and class (M6-C72)" >&2
cargo test -p tunnel-catalog --test redis_connection_stage --locked -- --ignored --nocapture \
  > "$scratch/stage.log" 2>&1 || { cat "$scratch/stage.log" >&2; exit 1; }
cat "$scratch/stage.log"
require "Redis connection stage tests" "$scratch/stage.log" "test result: ok. 3 passed" \
  "m6c72-real ok case=auth" "m6c72-real ok case=noperm" \
  "m6c72-real ok case=lane-timeout stage=connection_establishment"

echo "m6-provisioning-verify: end-to-end shipped-binary gate" >&2
cargo test -p tunnel-relay --test m6_provisioning_process --locked -- --ignored --nocapture \
  --test-threads=1 --skip m6c65_ > "$scratch/e2e.log" 2>&1 || { cat "$scratch/e2e.log" >&2; exit 1; }
cat "$scratch/e2e.log"
require "end-to-end gate" "$scratch/e2e.log" "test result: ok. 7 passed" "m6c21-e2e ok nonce=" \
  "m6c57-mcp ok nonce=" "tools_call=200 marker_echoed=true" \
  "backend_invocations=1 stranger_status=401" \
  "m6c57-acp ok nonce=" "agent_protocol_version=1 connection_id=present stranger_status=401" \
  "m6c57-fs ok nonce=" "matches_file=true stranger_status=401" \
  "client=$TUNNEL_CLIENT_BIN" \
  "m6c32 device_id mismatch exit=3 code=CREDENTIAL_ERROR retryable=false" \
  "m6c32 unknown credential key exit=3 code=CREDENTIAL_ERROR retryable=false" \
  "m6c32 credential not yet valid exit=4 code=TRANSPORT_ERROR retryable=true" \
  "m6c72-stage ok case=wrong Redis CA" "m6c72-stage ok case=wrong Redis password" \
  "m6c72-stage ok case=ACL user without INFO" "m6c72-stage ok case=missing client certificate" \
  "m7c92-echo ok nonce=" "required=300 sessions=1" \
  "m7c93-rotation ok nonce=" "max=120 sessions=1" \
  "m6c31-catalog ok nonce=" "serve_restarts=0 grant_pickup_ms=" \
  "grant_pickup_attempts=1" "revoke_grant_attempts=1" \
  "close_reason=AUTHORIZATION_REVOKED" "device_exit=3 revoked_device_grant_refused=true"
if [ -n "${TUNNEL_RELAY_BIN:-}" ]; then
  require "end-to-end gate ran the requested relay" "$scratch/e2e.log" "relay=$TUNNEL_RELAY_BIN"
fi
