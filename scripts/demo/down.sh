#!/usr/bin/env bash
# Tear down the local demo (task row M6-C127): stop the device, every feature
# backend and the relay (SIGTERM, then SIGKILL after 10 s), with their direct
# children; remove the throwaway Redis container; delete the synthetic state
# directory. Idempotent: safe to run when nothing is up.
#
#   scripts/demo/down.sh               # stop everything, delete state
#   scripts/demo/down.sh --keep-logs   # keep scripts/demo/.state/logs for a post-mortem
#
# Safety: a process is signalled only if its recorded start time and command
# line still match (a reused pid is left alone); only a container carrying the
# agentuplink.demo=1 label is removed; the state directory is deleted only if
# it is scripts/demo/.state and holds the marker up.sh writes. Never touches
# the shared test Redis or anything remote. Exit 1 if something was left.
set -eu
. "$(dirname "$0")/lib/common.sh"

KEEP_LOGS=0
for arg in "$@"; do
  case $arg in
    --keep-logs) KEEP_LOGS=1 ;;
    --remote) demo_say "remote mode has nothing to tear down (the live relay is never modified)"; exit 0 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) demo_die "unknown argument $arg" ;;
  esac
done
demo_guard_container
LEFT=0

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

if ! command -v docker >/dev/null 2>&1; then
  demo_warn "docker is not installed; nothing to remove"
elif ! demo_docker info >/dev/null 2>&1; then
  demo_warn "Docker is not answering; could not check for $DEMO_REDIS_CONTAINER (run down.sh again when it does)"
  LEFT=1
else
  named=$(demo_named_container) || { LEFT=1; named=; }
  if [ -n "$named" ]; then
    labelled=$(demo_labelled_container) || labelled=
    if [ -z "$labelled" ]; then
      demo_warn "a container named $DEMO_REDIS_CONTAINER exists without the $DEMO_LABEL label; not removing it"
      LEFT=1
    else
      # A removal already in progress (a stuck Docker Desktop) is not an
      # error here; wait up to 60 s for the container to disappear.
      demo_timeout 60 docker rm -f -v "$DEMO_REDIS_CONTAINER" >/dev/null 2>&1 || true
      i=0
      while [ -n "$(demo_labelled_container 2>/dev/null || echo unknown)" ] && [ "$i" -lt 12 ]; do
        sleep 5; i=$((i + 1))
      done
      if [ -n "$(demo_labelled_container 2>/dev/null || echo unknown)" ]; then
        demo_warn "container $DEMO_REDIS_CONTAINER is still present after 60 s (Docker Desktop stuck?); run down.sh again later"
        LEFT=1
      else
        demo_info "removed container $DEMO_REDIS_CONTAINER"
      fi
    fi
  fi
fi

if [ -d "$DEMO_STATE" ]; then
  if [ ! -f "$DEMO_STATE_MARKER" ]; then
    demo_warn "$DEMO_STATE has no up.sh marker; not deleting it"
    LEFT=1
  elif [ "$KEEP_LOGS" = 1 ] && [ -d "$DEMO_LOGS" ]; then
    find "$DEMO_STATE" -mindepth 1 -maxdepth 1 ! -name logs ! -name "$(basename "$DEMO_STATE_MARKER")" -exec rm -rf {} +
    demo_info "kept logs in $DEMO_LOGS; everything else deleted"
  else
    rm -rf "$DEMO_STATE"
    demo_info "deleted $DEMO_STATE"
  fi
fi
if [ "$LEFT" = 1 ]; then
  demo_say "local demo is down except for what is reported above"
  exit 1
fi
demo_say "local demo is down"
