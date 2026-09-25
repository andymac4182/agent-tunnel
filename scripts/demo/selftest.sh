#!/usr/bin/env bash
# Acceptance check for the demo environment (task row M6-C130): run the full
# presenter sequence N times from clean (default 3) and require, each round,
#
#   * up.sh from nothing succeeds, and a second up.sh is a no-op ("already up"),
#   * show.sh for every ready feature exits 0, and a TODO feature exits 2,
#   * a token minted by token.sh is accepted by the relay,
#   * with an MCP session left open (so the device has a live stdio child),
#     down.sh leaves none of the recorded processes or that child running
#     (compared by start time and command line, not pid alone), no demo
#     container and no state directory, and a second down.sh is a no-op,
#   * no output of any command, and no file in .state/logs/, contains a JWT-
#     or PEM-shaped string. The scanner is first shown to match a synthetic
#     JWT and a synthetic PEM block (a positive control), so a 0 is not a
#     scanner that cannot match.
#
#   scripts/demo/selftest.sh [ROUNDS]
#
# Prints one `demo-selftest round=N ok ...` line per round and a final
# `demo-selftest ok rounds=N` line; exits 1 at the first failure, after
# cleaning up with `down.sh --keep-logs`.
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
. "$DIR/lib/common.sh"
ROUNDS=${1:-3}
OUT=$(mktemp -d "${TMPDIR:-/tmp}/agentuplink-demo-selftest.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
nonce=$(uuidgen)
head=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "demo-selftest nonce=$nonce head=$head rounds=$ROUNDS"
round=0

die() {
  echo "demo-selftest FAILED round=$round: $*" >&2
  echo "--- last output (redacted):" >&2
  tail -40 "$OUT/last" | demo_redact >&2
  "$DIR/down.sh" --keep-logs >/dev/null 2>&1 && echo "--- cleaned up; logs kept in $DEMO_LOGS" >&2
  exit 1
}
run() { # LABEL WANT_RC CMD...
  local label=$1 want=$2 rc
  shift 2
  "$@" >"$OUT/last" 2>&1
  rc=$?
  cat "$OUT/last" >>"$OUT/all"
  [ "$rc" = "$want" ] || die "$label exited $rc (wanted $want)"
}
# Count the files among the arguments that contain a secret-shaped string.
secret_hits() { grep -Elc -- "$DEMO_SECRET_PATTERN" "$@" 2>/dev/null | wc -l | tr -d ' '; }

# Positive control: the scanner must find both shapes.
printf 'x eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGljc2ln x\n' >"$OUT/control-jwt"
printf -- '-----BEGIN PRIVATE KEY-----\nc3ludGhldGlj\n-----END PRIVATE KEY-----\n' >"$OUT/control-pem"
[ "$(secret_hits "$OUT/control-jwt" "$OUT/control-pem")" = 2 ] ||
  die "secret scanner positive control failed: it did not match a synthetic JWT and PEM"
[ "$(demo_redact <"$OUT/control-pem" | secret_hits /dev/stdin)" = 0 ] ||
  die "demo_redact left a PEM block in place"
rm -f "$OUT/control-jwt" "$OUT/control-pem"
echo "demo-selftest scanner positive control ok (synthetic JWT and PEM both matched; redaction removes the PEM)"

# The first plug-in up.sh did not bring up (a TODO stub), if any.
first_todo() {
  local ready n
  ready=" $(. "$DEMO_STATE/ids.env"; echo "$DEMO_FEATURES") "
  for n in $(demo_feature_names); do
    if ! printf '%s' "$ready" | grep -q " $n "; then echo "$n"; return 0; fi
  done
}

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

  # Leave an MCP session open, so the device has a live stdio child.
  : >"$OUT/identities"
  children=0
  case " $(. "$DEMO_STATE/ids.env"; echo "$DEMO_FEATURES") " in *" mcp "*)
    tok=$("$DIR/token.sh" http:invoke 60 </dev/null) || die "token.sh failed"
    (. "$DEMO_STATE/ids.env"
     printf 'Authorization: Bearer %s\n' "$tok" | curl -s -o /dev/null -w '%{http_code}' -H @- --cacert "$DEMO_PKI/server-ca.pem" \
       -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
       --data-binary '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"selftest","version":"1"}}}' \
       "$DEMO_CONSUMER_URL/v1/devices/$DEMO_DEVICE/services/$DEMO_SERVICE_MCP/http/mcp") >"$OUT/last" 2>&1
    [ "$(cat "$OUT/last")" = 200 ] || die "open MCP session: $(cat "$OUT/last")"
    for kid in $(pgrep -P "$(demo_recorded_pid device)" 2>/dev/null); do
      printf '%s\n%s\n' "$kid" "$(demo_identity "$kid")" >>"$OUT/identities"
      children=$((children + 1))
    done
    [ "$children" -gt 0 ] || die "the open MCP session has no device-side child process"
    ;;
  esac
  unset tok
  recorded=0
  for f in "$DEMO_PIDS"/*.pid; do
    [ -e "$f" ] || continue
    sed -n 1,2p "$f" >>"$OUT/identities"
    recorded=$((recorded + 1))
  done

  # Scan the logs before down.sh deletes them.
  log_hits=$(secret_hits "$DEMO_LOGS"/*.log)
  log_files=$(ls "$DEMO_LOGS"/*.log 2>/dev/null | wc -l | tr -d ' ')
  [ "$log_hits" = 0 ] || die "$log_hits file(s) in $DEMO_LOGS contain a token- or PEM-shaped string"

  run down 0 "$DIR/down.sh"
  run down-again 0 "$DIR/down.sh"
  while read -r pid && read -r id; do
    demo_same_process "$pid" "$id" && die "pid $pid ($id) survived down.sh"
  done <"$OUT/identities"
  left=$(demo_labelled_container) || die "Docker not answering; cannot check the container"
  [ -z "$left" ] || die "container $DEMO_REDIS_CONTAINER survived down.sh"
  [ ! -e "$DEMO_STATE" ] || die "$DEMO_STATE survived down.sh"
  [ "$(secret_hits "$OUT/all")" = 0 ] || die "command output contains a token- or PEM-shaped string"
  echo "demo-selftest round=$round ok up_ms=$up_ms shown=${shown%,} todo_refused=${todo:-none} token_sh=200 stopped_recorded=$recorded stopped_mcp_children=$children container_removed=true state_removed=true logs_scanned=$log_files secrets_in_output=0 secrets_in_logs=0"
done
echo "demo-selftest ok rounds=$round nonce=$nonce head=$head"
