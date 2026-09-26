# shellcheck shell=bash
# Feature plug-in: HTTP forward to a tiny synthetic web app on the device
# (task row M6-C128). Contract: scripts/demo/features/_template.sh.
#
# The relay's http-forward profiles are MCP and ACP only (there is no
# generic-HTTP profile on origin/main), so the web app speaks MCP Streamable
# HTTP 2026-07-28 (stateless) and serves its page as a tool result. The
# device export is a `streamable-http` MCP backend at a loopback URL: the app
# is reachable only on the device's 127.0.0.1, and only via the relay from
# anywhere else.
FEATURE_NAME=http
FEATURE_TITLE="HTTP forward: relay -> device -> loopback-only web app"
FEATURE_READY=1
FEATURE_REMOTE=1
FEATURE_REQUIRES=python3

HTTP_PROFILE=mcp-2026-07-28

feature_service() {
  printf 'type = "http-forward"\ndisplay_name = "Demo web app"\noperations = ["http:invoke"]\nhttp_forward_profile = "%s"' "$HTTP_PROFILE"
}
feature_grant_operations() { printf '["http:invoke"]'; }
feature_relay_profile() { printf '%s' "$HTTP_PROFILE"; }
feature_export() {
  printf '[exports."%s"]\ntype = "http-forward"\n\n[exports."%s".mcp]\nprofile = "%s"\n\n[exports."%s".mcp.backend]\nkind = "streamable-http"\nurl = "http://127.0.0.1:%s/mcp"\n' \
    "$1" "$1" "$HTTP_PROFILE" "$1" "$DEMO_WEB_PORT"
}
feature_start() {
  demo_spawn web-app "$DEMO_LOGS/web-app.log" python3 "$DEMO_DIR/backends/demo-web-app.py" "$DEMO_WEB_PORT"
  local i=0
  until curl -s -o /dev/null "http://127.0.0.1:$DEMO_WEB_PORT/" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -lt 40 ] || { demo_bad "web app did not start (log: $DEMO_LOGS/web-app.log)"; return 1; }
    sleep 0.25
  done
  demo_ok "web app listening on 127.0.0.1:$DEMO_WEB_PORT (loopback only)"
}

# http_mcp ID METHOD NAME PARAMS_JSON TOKEN [extra curl args...]
http_mcp() {
  local id=$1 method=$2 name=$3 params=$4 token=$5 req=$DEMO_TMP/mcp-request
  shift 5 # any further arguments are extra curl arguments
  printf '{"jsonrpc":"2.0","id":%s,"method":"%s","params":%s}' "$id" "$method" "$params" >"$req"
  set -- -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
    -H "mcp-protocol-version: 2026-07-28" -H "mcp-method: $method" "$@"
  if [ -n "$name" ]; then set -- "$@" -H "mcp-name: $name"; fi
  demo_call POST "/v1/devices/$DEMO_DEVICE/services/$SERVICE/http/mcp" "$token" "$req" "$@"
}

http_page_summary() {
  demo_jsonrpc | python3 -c '
import json, re, sys
line = sys.stdin.read().strip()
if not line:
    print("no JSON-RPC result"); sys.exit(0)
msg = json.loads(line)
res = msg.get("result") or {}
texts = [c.get("text", "") for c in res.get("content", [])] + [c.get("text", "") for c in res.get("contents", [])]
page = "".join(texts)
title = re.search(r"<title>(.*?)</title>", page)
served = re.search(r"served: (\d+)", page)
print("page %d bytes, title \"%s\", marker %s, device-side request #%s" % (
    len(page), title.group(1) if title else "?",
    "present" if "agentuplink-demo-page-v1" in page else "MISSING",
    served.group(1) if served else "?"))'
}

http_steps() {
  local token other meta
  meta='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}'
  token=$(demo_token http:invoke)

  demo_step "1. Discover the device-side app through the relay (server/discover)"
  demo_info "route: POST /v1/devices/<device>/services/<http service>/http/mcp"
  http_mcp 1 server/discover "" "{$meta}" "$token"
  if demo_expect "server/discover" 200; then
    demo_info "server: $(demo_jsonrpc | python3 -c 'import json,sys; r=json.loads(sys.stdin.read() or "{}").get("result",{}); print(r.get("serverInfo",{}).get("name","?"), "speaking", ",".join(r.get("supportedVersions",[])))')"
  else
    demo_explain_unreachable || return 0
  fi

  demo_step "2. Fetch the page (tools/call demo_page)"
  http_mcp 2 tools/call demo_page "{\"name\":\"demo_page\",\"arguments\":{},$meta}" "$token"
  if demo_expect "tools/call demo_page" 200; then
    demo_info "$(http_page_summary)"
  fi

  demo_step "3. The relay refuses a token without http:invoke (scope echo:invoke only)"
  other=$(demo_token echo:invoke)
  http_mcp 3 tools/call demo_page "{\"name\":\"demo_page\",\"arguments\":{},$meta}" "$other"
  if [ "$DEMO_MODE" = remote ] && [ "$DEMO_HTTP" = 401 ]; then
    demo_ok "wrong scope -> HTTP 401 in $(demo_ms "$DEMO_TIME") (the live relay predates M6-C53's 403)"
  else
    demo_expect "wrong scope" 403
  fi

  demo_step "4. ... and a header the profile does not allow (X-Demo-Extra)"
  http_mcp 4 tools/call demo_page "{\"name\":\"demo_page\",\"arguments\":{},$meta}" "$token" -H 'x-demo-extra: 1'
  demo_expect "unlisted header" 400 && demo_info "code $(demo_error_code) (refused at the relay, before the device)"
  unset token other
}

feature_show() {
  demo_step "0. On the device, the web app answers only on loopback"
  local r
  r=$(curl -s -o "$DEMO_TMP/direct" -w '%{http_code} %{time_total}' "http://127.0.0.1:$DEMO_WEB_PORT/" 2>/dev/null || echo "000 -")
  DEMO_HTTP=${r%% *}; DEMO_TIME=${r##* }; DEMO_BODY=$DEMO_TMP/direct
  demo_expect "GET http://127.0.0.1:$DEMO_WEB_PORT/ (device side, no relay)" 200
  http_steps
}
feature_show_remote() {
  demo_info "live relay: $DEMO_REMOTE_URL, device $DEMO_DEVICE"
  http_steps
}
