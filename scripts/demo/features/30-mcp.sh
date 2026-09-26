# shellcheck shell=bash
# Feature plug-in: an MCP server on the device, used as a remote MCP server
# through the relay (task row M6-C128). Contract: scripts/demo/features/_template.sh.
#
# The backend is the repository's synthetic fixture server
# (`tunnel-mcp-fixture stdio`), which the device starts as a stdio child in a
# synthetic workspace. The profile is mcp-2025-11-25, which has sessions, so
# this step also shows the session lifecycle.
FEATURE_NAME=mcp
FEATURE_TITLE="MCP: a stdio MCP server on the device, called as a remote MCP server"
FEATURE_READY=1
FEATURE_REMOTE=0
FEATURE_CARGO_PACKAGES=tunnel-mcp-fixture

MCP_PROFILE=mcp-2025-11-25

feature_service() {
  printf 'type = "http-forward"\ndisplay_name = "Demo MCP fixture server"\noperations = ["http:invoke"]\nhttp_forward_profile = "%s"' "$MCP_PROFILE"
}
feature_grant_operations() { printf '["http:invoke"]'; }
feature_relay_profile() { printf '%s' "$MCP_PROFILE"; }
feature_export() {
  mkdir -p "$DEMO_STATE/mcp-workspace"
  printf '[exports."%s"]\ntype = "http-forward"\n\n[exports."%s".mcp]\nprofile = "%s"\n\n[exports."%s".mcp.backend]\nkind = "stdio"\ncommand = "%s"\nargs = ["stdio"]\nworkspace = "%s"\n' \
    "$1" "$1" "$MCP_PROFILE" "$1" "$(demo_bin tunnel-mcp-fixture)" "$DEMO_STATE/mcp-workspace"
}

# mcp_post ID_OR_EMPTY METHOD PARAMS_JSON TOKEN [SESSION]
mcp_post() {
  local id=$1 method=$2 params=$3 token=$4 session=${5:-} req=$DEMO_TMP/mcp-request
  if [ -n "$id" ]; then
    printf '{"jsonrpc":"2.0","id":%s,"method":"%s","params":%s}' "$id" "$method" "$params" >"$req"
  else
    printf '{"jsonrpc":"2.0","method":"%s"}' "$method" >"$req"
  fi
  set -- -H 'content-type: application/json' -H 'accept: application/json, text/event-stream'
  if [ -n "$session" ]; then
    set -- "$@" -H "mcp-protocol-version: $MCP_PROFILE_VERSION" -H "mcp-session-id: $session"
  fi
  demo_call POST "/v1/devices/$DEMO_DEVICE/services/$SERVICE/http/mcp" "$token" "$req" "$@"
}
MCP_PROFILE_VERSION=2025-11-25

feature_show() {
  local token session marker
  token=$(demo_token http:invoke)
  marker="demo-marker-$(date +%s)"

  demo_step "1. initialize a session with the device's MCP server"
  demo_info "route: POST /v1/devices/<device>/services/<mcp service>/http/mcp"
  mcp_post 1 initialize "{\"protocolVersion\":\"$MCP_PROFILE_VERSION\",\"capabilities\":{},\"clientInfo\":{\"name\":\"agentuplink-demo\",\"version\":\"1\"}}" "$token"
  if ! demo_expect "initialize" 200; then demo_explain_unreachable; return 0; fi
  session=$(demo_header mcp-session-id)
  demo_info "server: $(demo_jsonrpc | python3 -c 'import json,sys; r=json.loads(sys.stdin.read() or "{}").get("result",{}); print(r.get("serverInfo",{}).get("name","?"), "protocol", r.get("protocolVersion","?"))'); session id $( [ -n "$session" ] && echo issued || echo MISSING)"

  demo_step "2. notifications/initialized"
  mcp_post "" notifications/initialized "" "$token" "$session"
  demo_expect "notifications/initialized" 202

  demo_step "3. tools/list"
  mcp_post 2 tools/list '{}' "$token" "$session"
  if demo_expect "tools/list" 200; then
    demo_info "tools: $(demo_jsonrpc | python3 -c 'import json,sys; r=json.loads(sys.stdin.read() or "{}").get("result",{}); print(", ".join(t.get("name","?") for t in r.get("tools",[])))')"
  fi

  demo_step "4. tools/call echo with a synthetic marker; the device-side server returns it"
  mcp_post 3 tools/call "{\"name\":\"echo\",\"arguments\":{\"marker\":\"$marker\"}}" "$token" "$session"
  if demo_expect "tools/call echo" 200; then
    if grep -q "$marker" "$DEMO_BODY"; then
      demo_ok "marker $marker came back from the device-side server"
    else
      demo_bad "marker not found in the tool result"; DEMO_FAILURES=$((DEMO_FAILURES + 1))
    fi
  fi

  demo_step "5. A caller without a token cannot reach the server"
  mcp_post 4 tools/list '{}' - "$session"
  demo_expect "no token" 401

  demo_step "6. DELETE the session (the device stops the stdio server)"
  demo_call DELETE "/v1/devices/$DEMO_DEVICE/services/$SERVICE/http/mcp" "$token" - \
    -H "mcp-protocol-version: $MCP_PROFILE_VERSION" -H "mcp-session-id: $session"
  demo_expect "DELETE session" 204
  unset token
}
