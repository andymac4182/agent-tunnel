# shellcheck shell=bash
# Feature plug-in: authenticated echo through the relay (task row M6-C128).
# Contract: scripts/demo/features/_template.sh.
FEATURE_NAME="echo"
FEATURE_TITLE="Authenticated echo: consumer -> relay -> device -> back"
FEATURE_READY=1
FEATURE_REMOTE=1

feature_service() {
  printf 'type = "echo"\ndisplay_name = "Demo echo"\noperations = ["echo:invoke"]'
}
feature_grant_operations() { printf '["echo:invoke"]'; }
feature_export() {
  printf '[exports."%s"]\ntype = "echo"\ndevice_canary = "demo-mac:"\n' "$1"
}

echo_steps() {
  local path="/v1/devices/$DEMO_DEVICE/services/$SERVICE/echo" token other body i times ok
  body=$DEMO_TMP/echo-body
  printf 'hello-from-the-demo' >"$body"

  demo_step "1. POST a synthetic payload with a token that carries echo:invoke"
  demo_info "route: POST /v1/devices/<device>/services/<echo service>/echo"
  token=$(demo_token echo:invoke)
  demo_call POST "$path" "$token" "$body"
  if demo_expect "echo" 200; then
    demo_info "reply: $(head -c 200 "$DEMO_BODY" | demo_redact)  (device canary + payload, from the device)"
  else
    demo_explain_unreachable || return 0
  fi

  demo_step "2. Five more echoes, to show steady-state latency"
  times=
  ok=0
  i=1
  while [ "$i" -le 5 ]; do
    printf 'hello-%s' "$i" >"$body"
    demo_call POST "$path" "$token" "$body"
    if [ "$DEMO_HTTP" = 200 ]; then ok=$((ok + 1)); times="$times $DEMO_TIME"; else demo_expect "echo $i" 200; fi
    i=$((i + 1))
  done
  demo_info "$ok of 5 x HTTP 200: $(python3 -c 'import sys; t=[float(x)*1000 for x in sys.argv[1:] if x!="-"]; print("min %d ms, median %d ms, max %d ms" % (min(t), sorted(t)[len(t)//2], max(t)) if t else "no timings")' $times)"

  demo_step "3. The relay refuses a call with no token"
  demo_call POST "$path" - "$body"
  demo_expect "no token" 401

  demo_step "4. ... and a valid token without echo:invoke (scope http:invoke only)"
  other=$(demo_token http:invoke)
  demo_call POST "$path" "$other" "$body"
  if [ "$DEMO_MODE" = remote ] && [ "$DEMO_HTTP" = 401 ]; then
    demo_ok "wrong scope -> HTTP 401 in $(demo_ms "$DEMO_TIME") (the live relay predates M6-C53's 403)"
  else
    demo_expect "wrong scope" 403
  fi
  unset token other
}

feature_show() { echo_steps; }
feature_show_remote() {
  demo_info "live relay: $DEMO_REMOTE_URL, device $DEMO_DEVICE"
  echo_steps
}
