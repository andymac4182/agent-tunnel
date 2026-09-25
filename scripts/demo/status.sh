#!/usr/bin/env bash
# Report the demo's health (task row M6-C127). Exit 0 when every part is
# healthy, 1 otherwise. Prints identifiers, phases and status codes only.
#
#   scripts/demo/status.sh            # local demo
#   scripts/demo/status.sh --quiet    # exit status only
#   scripts/demo/status.sh --remote   # the live Fly relay (read-only)
set -u
. "$(dirname "$0")/lib/common.sh"

QUIET=0
for arg in "$@"; do
  case $arg in
    --quiet) QUIET=1 ;;
    --remote) DEMO_MODE=remote ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) demo_die "unknown argument $arg" ;;
  esac
done
if [ "$QUIET" = 1 ]; then exec >/dev/null; fi

healthy=1
fail() { demo_bad "$*"; healthy=0; }

probe() {
  curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 10 --cacert "$(demo_ca)" "$(demo_base_url)$1" 2>/dev/null || true
}

if [ "$DEMO_MODE" = remote ]; then
  demo_say "status: live relay $DEMO_REMOTE_URL"
  for f in oidc-key.pem relay-ca.pem; do
    [ -r "$DEMO_REMOTE_DIR/$f" ] && demo_ok "$DEMO_REMOTE_DIR/$f readable" || fail "$DEMO_REMOTE_DIR/$f missing"
  done
  for ep in /livez /readyz; do
    r=$(probe "$ep")
    [ "${r%% *}" = 200 ] && demo_ok "$ep -> HTTP ${r%% *} in $(demo_ms "${r##* }")" || fail "$ep -> HTTP ${r%% *}"
  done
  demo_info "device $DEMO_REMOTE_DEVICE, echo service $DEMO_REMOTE_ECHO_SERVICE, http service $DEMO_REMOTE_HTTP_SERVICE"
  demo_info "(whether that device is connected shows in 'show.sh --remote echo': 503 DEVICE_OFFLINE means it is not)"
  [ "$healthy" = 1 ] && exit 0 || exit 1
fi

demo_say "status: local demo ($DEMO_STATE)"
if [ ! -f "$DEMO_STATE/ids.env" ]; then
  if [ -f "$DEMO_STATE/ids.env.pending" ]; then fail "up.sh did not finish; run scripts/demo/down.sh then up.sh"; else fail "not up (run scripts/demo/up.sh)"; fi
  exit 1
fi
demo_load_ids

state=$(docker inspect -f '{{.State.Status}}' "$DEMO_REDIS_CONTAINER" 2>/dev/null || echo absent)
[ "$state" = running ] && demo_ok "redis container $DEMO_REDIS_CONTAINER running (127.0.0.1:$DEMO_REDIS_PORT, TLS)" || fail "redis container $DEMO_REDIS_CONTAINER: $state"

for p in relay device; do
  demo_pid_alive "$p" && demo_ok "$p process running (pid $(cat "$DEMO_PIDS/$p.pid"))" || fail "$p process not running (log: $DEMO_LOGS/$p.log)"
done
for f in "$DEMO_PIDS"/*.pid; do
  [ -e "$f" ] || continue
  name=$(basename "$f" .pid)
  case $name in relay|device) continue ;; esac
  demo_pid_alive "$name" && demo_ok "backend $name running (pid $(cat "$f"))" || fail "backend $name not running (log: $DEMO_LOGS/$name.log)"
done

for ep in /livez /readyz; do
  r=$(probe "$ep")
  [ "${r%% *}" = 200 ] && demo_ok "relay $ep -> HTTP ${r%% *} in $(demo_ms "${r##* }")" || fail "relay $ep -> HTTP ${r%% *}"
done

phase=$(grep -o '"phase":"[a-z_]*"' "$DEMO_LOGS/device.log" 2>/dev/null | tail -1 | cut -d'"' -f4)
rotations=$(grep -c '"phase":"retiring"' "$DEMO_LOGS/device.log" 2>/dev/null || true)
case $phase in
  active) demo_ok "device $DEMO_DEVICE phase=active (data-socket rotations so far: ${rotations:-0})" ;;
  preparing|quiescing|draining|retiring) demo_ok "device $DEMO_DEVICE phase=$phase (rotating now)" ;;
  *) fail "device $DEMO_DEVICE phase=${phase:-unknown}" ;;
esac

demo_info "consumer URL  $DEMO_CONSUMER_URL (CA: $DEMO_PKI/server-ca.pem)"
for name in $DEMO_FEATURES; do
  demo_info "service $(printf '%-9s' "$name") $(demo_service_id "$name")"
done
todo=
for n in $(demo_feature_names); do
  case " $DEMO_FEATURES " in *" $n "*) ;; *) todo="$todo $n" ;; esac
done
[ -z "$todo" ] || demo_info "not yet available (TODO plug-ins):$todo"

[ "$healthy" = 1 ] && exit 0 || exit 1
