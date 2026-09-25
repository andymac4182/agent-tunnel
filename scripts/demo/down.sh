#!/usr/bin/env bash
# Tear down the local demo (task row M6-C127): stop the device, every feature
# backend and the relay (SIGTERM, then SIGKILL after 10 s), remove the
# throwaway Redis container, and delete the synthetic state directory.
# Idempotent: safe to run when nothing is up.
#
#   scripts/demo/down.sh               # stop everything, delete state
#   scripts/demo/down.sh --keep-logs   # keep scripts/demo/.state/logs for a post-mortem
#
# Never touches the shared test Redis container or anything remote.
set -eu
. "$(dirname "$0")/lib/common.sh"

KEEP_LOGS=0
for arg in "$@"; do
  case $arg in
    --keep-logs) KEEP_LOGS=1 ;;
    --remote) demo_say "remote mode has nothing to tear down (the live relay is never modified)"; exit 0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) demo_die "unknown argument $arg" ;;
  esac
done
demo_guard_container

demo_say "stopping the local demo"
# Device first, so the relay sees an orderly close; then backends; relay last.
demo_stop_pid device
if [ -d "$DEMO_PIDS" ]; then
  for f in "$DEMO_PIDS"/*.pid; do
    [ -e "$f" ] || continue
    name=$(basename "$f" .pid)
    [ "$name" = relay ] && continue
    demo_stop_pid "$name"
  done
fi
demo_stop_pid relay

# Anything still running from this state directory (a lost pid file, or a
# process a crashed up.sh started) is found by its command line.
leftover=$(pgrep -f "$DEMO_STATE/" 2>/dev/null || true)
if [ -n "$leftover" ]; then
  for pid in $leftover; do
    [ "$pid" = "$$" ] && continue
    kill -TERM "$pid" 2>/dev/null && demo_info "stopped leftover pid $pid"
  done
  sleep 1
  for pid in $(pgrep -f "$DEMO_STATE/" 2>/dev/null || true); do
    [ "$pid" = "$$" ] && continue
    kill -KILL "$pid" 2>/dev/null && demo_info "killed leftover pid $pid"
  done
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$DEMO_REDIS_CONTAINER"; then
    docker rm -f -v "$DEMO_REDIS_CONTAINER" >/dev/null
    demo_info "removed container $DEMO_REDIS_CONTAINER"
  fi
else
  demo_warn "docker is not reachable; could not check for $DEMO_REDIS_CONTAINER"
fi

if [ -d "$DEMO_STATE" ]; then
  if [ "$KEEP_LOGS" = 1 ] && [ -d "$DEMO_LOGS" ]; then
    find "$DEMO_STATE" -mindepth 1 -maxdepth 1 ! -name logs -exec rm -rf {} +
    demo_info "kept logs in $DEMO_LOGS; everything else deleted"
  else
    rm -rf "$DEMO_STATE"
    demo_info "deleted $DEMO_STATE"
  fi
fi
demo_say "local demo is down"
