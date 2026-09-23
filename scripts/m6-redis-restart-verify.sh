#!/bin/sh
# Task row M6-C65: a single relay keeps serving the same namespace across
# Redis restarts, and still refuses a Redis that came back older or empty,
# proved with shipped binaries against a Redis container this gate owns.
#
#   scripts/m6-redis-restart-verify.sh
#
# 1. Builds `tunnel-relay` and `tunnel-client` into the caller's target
#    directory, so the gate never runs a stale client.
# 2. Runs `m6c65_redis_restart_keeps_the_namespace_and_refuses_lost_data`
#    (`crates/tunnel-relay/tests/m6_provisioning_process.rs`).  It starts its
#    own `redis:8.4.0-alpine` container, pinned by digest (AOF, `appendfsync always`,
#    `aof-load-truncated no`, as deploy/fly/redis/entrypoint.sh configures the
#    Fly Redis) on a free loopback port, labelled with the run's nonce and
#    removed with its volume however the test ends.  It never reads or
#    restarts `TEST_REDIS_URL`'s Redis: that one is shared.  In order:
#    provision, `serve` with `redis_restart_continuity_seconds = 1`,
#    `connect`, echo; `docker restart` Redis under the running relay, which
#    must re-bind by itself and serve the echo again from the same process,
#    and again after `docker kill` and start; a copy of the data under
#    `appendfsync everysec` must be refused (`class=persistence`), as must
#    `serve` with continuity on such a Redis;
#    stop the relay, restart Redis, and require `serve` to refuse with
#    `stage=authority_identity class=run_changed`, `rebind-redis-run` without
#    its declaration to be refused, and with it the echo to be served again;
#    snapshot the RDB, revoke the grant, then replace Redis with one loaded
#    from that snapshot: the serving relay must refuse it (`class=continuity`)
#    and never serve the resurrected grant for 75 s, and a fresh `serve` must
#    refuse it, also after an operator wrongly re-attests it; finally replace
#    Redis with an empty one: refused as
#    `class=unbound` by the serving relay, a fresh `serve` and
#    `rebind-redis-run`, with nothing written into it.
#
# The test is `#[ignore]`d in the ordinary workspace run because it needs
# Docker.  A filtered or skipped test would print `0 passed` and exit 0, so
# this script requires the run's own pass count and each phase's ok line, and
# exits 1 when any is missing: green here means the gate ran.
set -eu

if ! command -v docker >/dev/null 2>&1; then
  echo "m6-redis-restart-verify: Docker is required." >&2
  exit 2
fi

target_dir=${CARGO_TARGET_DIR:-$(pwd)/target}
if [ -n "${M6_REDIS_RESTART_BIN_DIR:-}" ]; then
  export TUNNEL_CLIENT_BIN="$M6_REDIS_RESTART_BIN_DIR/tunnel-client"
  export TUNNEL_RELAY_BIN="$M6_REDIS_RESTART_BIN_DIR/tunnel-relay"
else
  export TUNNEL_CLIENT_BIN="$target_dir/debug/tunnel-client"
fi
scratch=$(mktemp -d "${TMPDIR:-/tmp}/m6-redis-restart-verify.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

echo "m6-redis-restart-verify: build tunnel-relay and tunnel-client" >&2
cargo build --locked -p tunnel-relay -p tunnel-client --bins

echo "m6-redis-restart-verify: Redis restart gate (M6-C65)" >&2
cargo test -p tunnel-relay --test m6_provisioning_process --locked -- --ignored --nocapture \
  --test-threads=1 --exact m6c65_redis_restart_keeps_the_namespace_and_refuses_lost_data \
  > "$scratch/restart.log" 2>&1 || { cat "$scratch/restart.log" >&2; exit 1; }
cat "$scratch/restart.log"
for needle in "test result: ok. 1 passed" "m6c65-unattended ok nonce=" "relay_restarts=0" \
  "m6c65-crash ok nonce=" "m6c65-persistence ok nonce=" "class=persistence" \
  "m6c65-operator ok nonce=" "class=run_changed" \
  "m6c65-reattest-refused ok nonce=" \
  "m6c65-rollback ok nonce=" "class=continuity" \
  "m6c65-empty ok nonce=" "class=unbound" \
  "client=$TUNNEL_CLIENT_BIN"; do
  if ! grep -q -- "$needle" "$scratch/restart.log"; then
    echo "m6-redis-restart-verify: FAILED: output lacks '$needle'" >&2
    exit 1
  fi
done
echo "m6-redis-restart-verify: ok" >&2
