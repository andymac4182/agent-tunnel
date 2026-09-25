#!/usr/bin/env bash
# Acceptance check for the demo environment (task row M6-C130): run the full
# presenter sequence N times from clean (default 3) and require, each round,
#
#   * up.sh from nothing succeeds, and a second up.sh is a no-op ("already up"),
#   * show.sh for every ready feature exits 0, and a TODO feature exits 2,
#   * a token minted by token.sh is accepted by the relay,
#   * with an MCP session left open, down.sh leaves no device-side child,
#     no demo container, no process started from the state
#     directory, no pid recorded by up.sh still alive, and no state directory,
#   * a second down.sh is a no-op,
#   * no output of any command contains a JWT-shaped string or a PEM block.
#
#   scripts/demo/selftest.sh [ROUNDS]
#
# Prints one `demo-selftest round=N ok ...` line per round and a final
# `demo-selftest ok rounds=N` line; exits 1 at the first failure. Green means
# every round ran: the final line names the rounds it counted.
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
. "$DIR/lib/common.sh"
ROUNDS=${1:-3}
OUT=$(mktemp -d "${TMPDIR:-/tmp}/agentuplink-demo-selftest.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
nonce=$(uuidgen)
head=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "demo-selftest nonce=$nonce head=$head rounds=$ROUNDS"

die() { echo "demo-selftest FAILED round=$round: $*" >&2; echo "--- last output:" >&2; tail -40 "$OUT/last" >&2; exit 1; }
run() { # LABEL WANT_RC CMD...
  local label=$1 want=$2 rc
  shift 2
  "$@" >"$OUT/last" 2>&1
  rc=$?
  cat "$OUT/last" >>"$OUT/all"
  [ "$rc" = "$want" ] || die "$label exited $rc (wanted $want)"
}

# The first plug-in up.sh did not bring up (a TODO stub), if any.
first_todo() {
  local ready n
  ready=" $(. "$DEMO_STATE/ids.env"; echo "$DEMO_FEATURES") "
  for n in $(demo_feature_names); do
    if ! printf '%s' "$ready" | grep -q " $n "; then echo "$n"; return 0; fi
  done
}

round=0
"$DIR/down.sh" >/dev/null 2>&1
while [ "$round" -lt "$ROUNDS" ]; do
  round=$((round + 1))
  : >"$OUT/all"
  t0=$(demo_now_ms)
  run up 0 "$DIR/up.sh"
  up_ms=$(( $(demo_now_ms) - t0 ))
  run up-again 0 "$DIR/up.sh"
  grep -q "already up and healthy" "$OUT/last" || die "second up.sh was not a no-op"
  run status 0 "$DIR/status.sh"
  shown=
  for name in $(. "$DEMO_STATE/ids.env"; echo "$DEMO_FEATURES"); do
    run "show $name" 0 "$DIR/show.sh" "$name"
    grep -q "all steps as expected" "$OUT/last" || die "show $name did not report all steps as expected"
    shown="$shown$name,"
  done
  run "show all" 0 "$DIR/show.sh" all
  todo=$(first_todo)
  if [ -n "$todo" ]; then run "show $todo (TODO)" 2 "$DIR/show.sh" "$todo"; fi
  tok=$("$DIR/token.sh" echo:invoke 60 </dev/null) || die "token.sh failed"
  (. "$DEMO_STATE/ids.env"
   printf 'Authorization: Bearer %s\n' "$tok" | curl -s -o /dev/null -w '%{http_code}' -H @- --cacert "$DEMO_PKI/server-ca.pem" \
     --data-binary token-check "$DEMO_CONSUMER_URL/v1/devices/$DEMO_DEVICE/services/$DEMO_SERVICE_ECHO/echo") >"$OUT/last" 2>&1
  [ "$(cat "$OUT/last")" = 200 ] || die "token.sh token was not accepted: $(cat "$OUT/last")"
  # Leave an MCP session open, so the device has a live stdio child that
  # down.sh must not orphan.
  children=
  case " $(. "$DEMO_STATE/ids.env"; echo "$DEMO_FEATURES") " in *" mcp "*)
    tok=$("$DIR/token.sh" http:invoke 60 </dev/null) || die "token.sh failed"
    (. "$DEMO_STATE/ids.env"
     printf 'Authorization: Bearer %s\n' "$tok" | curl -s -o /dev/null -w '%{http_code}' -H @- --cacert "$DEMO_PKI/server-ca.pem" \
       -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
       --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"selftest","version":"1"}}}' \
       "$DEMO_CONSUMER_URL/v1/devices/$DEMO_DEVICE/services/$DEMO_SERVICE_MCP/http/mcp") >"$OUT/last" 2>&1
    [ "$(cat "$OUT/last")" = 200 ] || die "open MCP session: $(cat "$OUT/last")"
    children=$(pgrep -P "$(cat "$DEMO_PIDS/device.pid")" | tr '\n' ' ')
    [ -n "$children" ] || die "the open MCP session has no device-side child process"
    ;;
  esac
  unset tok
  pids="$(cat "$DEMO_PIDS"/*.pid 2>/dev/null | tr '\n' ' ') $children"
  run down 0 "$DIR/down.sh"
  run down-again 0 "$DIR/down.sh"
  for pid in $pids; do kill -0 "$pid" 2>/dev/null && die "pid $pid survived down.sh"; done
  pgrep -f "$DEMO_STATE/" >/dev/null 2>&1 && die "a process started from $DEMO_STATE survived down.sh"
  docker ps -a --format '{{.Names}}' | grep -qx "$DEMO_REDIS_CONTAINER" && die "container $DEMO_REDIS_CONTAINER survived down.sh"
  [ ! -e "$DEMO_STATE" ] || die "$DEMO_STATE survived down.sh"
  if grep -Eq 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.|-----BEGIN' "$OUT/all"; then
    die "output contains a token- or PEM-shaped string"
  fi
  echo "demo-selftest round=$round ok up_ms=$up_ms shown=${shown%,} todo_refused=${todo:-none} token_sh=200 stopped_pids=$(echo $pids | wc -w | tr -d ' ') mcp_children_stopped=$(echo $children | wc -w | tr -d ' ') container_removed=true state_removed=true secrets_in_output=0"
done
echo "demo-selftest ok rounds=$round nonce=$nonce head=$head"
