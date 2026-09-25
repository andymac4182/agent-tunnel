# shellcheck shell=bash
# Shared helpers for scripts/demo/*.sh (task rows M6-C127..M6-C130).
#
# Sourced, never executed. Works with macOS's bash 3.2: no associative
# arrays, no mapfile, no ${var,,}.
#
# Secrets rule: nothing here prints a token, a private key or a request
# payload that is not synthetic demo text. Tokens are minted in memory,
# handed to curl on stdin (`-H @-`) so they never appear in `ps`, and never
# written to disk. Response bodies pass through demo_redact before printing.

DEMO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO_ROOT=$(cd "$DEMO_DIR/../.." && pwd)
# The state directory is fixed: down.sh deletes it recursively, so it must
# never be redirected somewhere else. up.sh writes $DEMO_STATE_MARKER into it
# first, and down.sh deletes nothing that lacks the marker.
if [ -n "${DEMO_STATE:-}" ] && [ "$DEMO_STATE" != "$DEMO_DIR/.state" ]; then
  printf 'demo: refusing DEMO_STATE=%s; the state directory is always %s\n' "$DEMO_STATE" "$DEMO_DIR/.state" >&2
  exit 1
fi
DEMO_STATE=$DEMO_DIR/.state
DEMO_STATE_MARKER=$DEMO_STATE/.agentuplink-demo-state
DEMO_LOGS=$DEMO_STATE/logs
DEMO_PIDS=$DEMO_STATE/pids
DEMO_PKI=$DEMO_STATE/pki

# Ports and names. Deliberately not the defaults of examples/ (8443/9443) or
# the shared test Redis (63790), so the demo never collides with them.
DEMO_CONSUMER_PORT=${DEMO_CONSUMER_PORT:-18443}
DEMO_DEVICE_PORT=${DEMO_DEVICE_PORT:-19443}
DEMO_REDIS_PORT=${DEMO_REDIS_PORT:-16380}
DEMO_WEB_PORT=${DEMO_WEB_PORT:-18931}
DEMO_REDIS_CONTAINER=${DEMO_REDIS_CONTAINER:-agentuplink-demo-redis}
DEMO_LABEL=agentuplink.demo=1
DEMO_DOCKER_TIMEOUT=${DEMO_DOCKER_TIMEOUT:-10}
DEMO_REDIS_IMAGE=${DEMO_REDIS_IMAGE:-redis:8.4.0-alpine}
DEMO_NAMESPACE=agentuplink-demo
DEMO_INCARNATION=demo-local
DEMO_ISSUER=https://issuer.demo.invalid/
DEMO_AUDIENCE=agent-tunnel
DEMO_SUBJECT=demo-presenter
DEMO_KID=demo-issuer-1
DEMO_CONSUMER_URL=https://localhost:$DEMO_CONSUMER_PORT

# The container the rest of the project's tests share. The demo must never
# touch it; demo_guard_container refuses it by name.
SHARED_REDIS_CONTAINER=agent-tunnel-m7-isolated-20260911
SHARED_REDIS_PORT=63790

# Remote mode (opt-in, read-only): the live Fly relay and the operator
# material in ~/agentuplink-fly. Only read, never written.
DEMO_REMOTE_DIR=${DEMO_REMOTE_DIR:-$HOME/agentuplink-fly}
DEMO_REMOTE_URL=${DEMO_REMOTE_URL:-https://agentuplink-relay.fly.dev}
DEMO_REMOTE_ISSUER=${DEMO_REMOTE_ISSUER:-https://issuer.example.test/}
DEMO_REMOTE_KID=${DEMO_REMOTE_KID:-agentuplink-fly-issuer-2}
DEMO_REMOTE_SUBJECT=${DEMO_REMOTE_SUBJECT:-fly-smoke-user}
# Catalog identifiers of the synthetic smoke identity on the live relay (not
# secrets: a call also needs a token signed by the issuer key). Override with
# the environment or a gitignored scripts/demo/remote.env.
DEMO_REMOTE_DEVICE=${DEMO_REMOTE_DEVICE:-04aa013f-d9ad-400d-8179-0dfbe074c4e1}
DEMO_REMOTE_ECHO_SERVICE=${DEMO_REMOTE_ECHO_SERVICE:-3d304efc-fe56-4d04-a78a-0d417dfcc09d}
DEMO_REMOTE_HTTP_SERVICE=${DEMO_REMOTE_HTTP_SERVICE:-8f6efd3e-9b7c-4bcd-bba8-4727943bbbd3}

DEMO_MODE=${DEMO_MODE:-local}

# ---------------------------------------------------------------- output

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_B=$(printf '\033[1m'); C_G=$(printf '\033[32m'); C_R=$(printf '\033[31m')
  C_Y=$(printf '\033[33m'); C_0=$(printf '\033[0m')
else
  C_B=; C_G=; C_R=; C_Y=; C_0=
fi

demo_say() { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
demo_step() { printf '\n%s--- %s%s\n' "$C_B" "$*" "$C_0"; }
demo_info() { printf '    %s\n' "$*"; }
demo_ok() { printf '    %sOK%s   %s\n' "$C_G" "$C_0" "$*"; }
demo_bad() { printf '    %sFAIL%s %s\n' "$C_R" "$C_0" "$*"; }
demo_warn() { printf '    %sWARN%s %s\n' "$C_Y" "$C_0" "$*"; }
demo_die() { printf '%sdemo: %s%s\n' "$C_R" "$*" "$C_0" >&2; exit 1; }

# Strip anything shaped like a bearer token or PEM block from text before it
# is shown. Demo bodies are synthetic; this is a second line of defence.
demo_redact() {
  sed -E \
    -e 's/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/[redacted-token]/g' \
    -e 's/(Bearer )[A-Za-z0-9._~+\/=-]+/\1[redacted]/g' \
    -e '/-----BEGIN/,/-----END/{/-----END/!d;s/.*/[redacted-pem]/;}'
}

# The shapes demo_redact removes, for scanners (selftest.sh): a JWT, or the
# start of a PEM block.
DEMO_SECRET_PATTERN='eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.|-----BEGIN'

# ---------------------------------------------------------------- state

demo_load_ids() {
  if [ "$DEMO_MODE" = remote ]; then
    # shellcheck disable=SC1091
    if [ -f "$DEMO_DIR/remote.env" ]; then . "$DEMO_DIR/remote.env"; fi
    DEMO_DEVICE=$DEMO_REMOTE_DEVICE
    DEMO_SERVICE_ECHO=$DEMO_REMOTE_ECHO_SERVICE
    DEMO_SERVICE_HTTP=$DEMO_REMOTE_HTTP_SERVICE
    return 0
  fi
  [ -f "$DEMO_STATE/ids.env" ] || demo_die "no local demo is up (missing $DEMO_STATE/ids.env); run scripts/demo/up.sh"
  # shellcheck disable=SC1091
  . "$DEMO_STATE/ids.env"
}

# demo_service_id FEATURE -> the catalog service UUID up.sh assigned it.
demo_service_id() {
  local var
  var="DEMO_SERVICE_$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')"
  eval "printf '%s' \"\${$var:-}\""
}

demo_bin() {
  if [ -n "${DEMO_BIN_DIR:-}" ]; then
    printf '%s/%s' "$DEMO_BIN_DIR" "$1"
  else
    printf '%s/debug/%s' "${CARGO_TARGET_DIR:-$REPO_ROOT/target}" "$1"
  fi
}

demo_uuid() { uuidgen | tr '[:upper:]' '[:lower:]'; }

demo_now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

# ---------------------------------------------------------------- processes

# A process identity: its start time and command line. A pid alone can be
# reused by an unrelated process after ours exits; the pair cannot.
demo_identity() { ps -o lstart=,command= -p "$1" 2>/dev/null; }

# demo_spawn NAME LOGFILE CMD... : start CMD in the background and record its
# pid and identity in $DEMO_PIDS/NAME.pid. Survives this shell; down.sh
# stops it. The identity is sampled once the command line has settled: a
# fork shows the parent shell's command line until exec, and macOS's python3
# re-executes itself.
demo_spawn() {
  local name=$1 log=$2 pid id prev='' i=0
  shift 2
  mkdir -p "$DEMO_PIDS"
  "$@" >"$log" 2>&1 </dev/null &
  pid=$!
  while [ "$i" -lt 30 ]; do
    id=$(demo_identity "$pid")
    [ -n "$id" ] || break
    case $id in *"$(basename "$1")"*) [ "$id" = "$prev" ] && break ;; esac
    prev=$id
    sleep 0.1
    i=$((i + 1))
  done
  printf '%s\n%s\n' "$pid" "$(demo_identity "$pid")" >"$DEMO_PIDS/$name.pid"
}

# demo_same_process PID IDENTITY : the pid still runs the recorded process.
demo_same_process() {
  [ -n "$1" ] && [ -n "$2" ] && [ "$(demo_identity "$1")" = "$2" ]
}

demo_recorded_pid() { sed -n 1p "$DEMO_PIDS/$1.pid" 2>/dev/null; }

demo_pid_alive() {
  local f="$DEMO_PIDS/$1.pid"
  [ -f "$f" ] || return 1
  demo_same_process "$(sed -n 1p "$f")" "$(sed -n 2p "$f")"
}

# demo_signal_verified PID IDENTITY SIGNAL : signal only the recorded process.
demo_signal_verified() {
  demo_same_process "$1" "$2" && kill "-$3" "$1" 2>/dev/null
}

# Stop one recorded process and its direct children: SIGTERM, wait up to
# 10 s, then SIGKILL. Every signal is sent only after the recorded identity
# is compared, so a reused pid is never signalled. The children are the
# `pgrep -P` of the recorded pid, identified before the parent is signalled
# (the device's stdio MCP servers, for example).
demo_stop_pid() {
  local name=$1 f="$DEMO_PIDS/$1.pid" pid id i kid kid_id kids=
  [ -f "$f" ] || return 0
  pid=$(sed -n 1p "$f"); id=$(sed -n 2p "$f")
  if demo_same_process "$pid" "$id"; then
    mkdir -p "$DEMO_PIDS"
    : >"$DEMO_PIDS/.children"
    for kid in $(pgrep -P "$pid" 2>/dev/null); do
      printf '%s\n%s\n' "$kid" "$(demo_identity "$kid")" >>"$DEMO_PIDS/.children"
    done
    kids=$(cat "$DEMO_PIDS/.children"); rm -f "$DEMO_PIDS/.children"
    demo_signal_verified "$pid" "$id" TERM
    i=0
    while demo_same_process "$pid" "$id" && [ "$i" -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    if demo_signal_verified "$pid" "$id" KILL; then
      demo_info "stopped $name (pid $pid) with SIGKILL after 10 s"
    else
      demo_info "stopped $name (pid $pid)"
    fi
    while [ -n "$kids" ]; do
      kid=$(printf '%s\n' "$kids" | sed -n 1p); kid_id=$(printf '%s\n' "$kids" | sed -n 2p)
      kids=$(printf '%s\n' "$kids" | sed '1,2d')
      demo_same_process "$kid" "$kid_id" || continue
      demo_signal_verified "$kid" "$kid_id" TERM
      sleep 1
      demo_signal_verified "$kid" "$kid_id" KILL
      demo_info "stopped a leftover child of $name (pid $kid)"
    done
  elif [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    demo_warn "pid $pid recorded for $name now belongs to another process; not signalled"
  fi
  rm -f "$f"
}

# demo_timeout SECONDS CMD... : run CMD, killing it after SECONDS. Returns
# CMD's status, or 124 on timeout. (macOS has no timeout(1).) Docker Desktop
# under load has left `docker run` hanging for over 20 minutes.
demo_timeout() {
  local secs=$1 pid i=0
  shift
  "$@" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$i" -ge $((secs * 10)) ]; then
      pkill -TERM -P "$pid" 2>/dev/null; kill -TERM "$pid" 2>/dev/null; sleep 1
      pkill -KILL -P "$pid" 2>/dev/null; kill -KILL "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      return 124
    fi
    sleep 0.1
    i=$((i + 1))
  done
  wait "$pid"
}

# PING the demo Redis over TLS from the host, through the published port,
# verifying its certificate against the demo server CA. Exit 0 on PONG.
demo_redis_ping() {
  python3 - "$DEMO_REDIS_PORT" "$DEMO_PKI/server-ca.pem" <<'PY'
import socket, ssl, sys
ctx = ssl.create_default_context(cafile=sys.argv[2])
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(b"PING\r\n")
            sys.exit(0 if tls.recv(64).startswith(b"+PONG") else 1)
except Exception:
    sys.exit(1)
PY
}

demo_port_free() {
  ! nc -z 127.0.0.1 "$1" >/dev/null 2>&1
}

demo_guard_container() {
  [ "$DEMO_REDIS_CONTAINER" != "$SHARED_REDIS_CONTAINER" ] ||
    demo_die "refusing to use the shared test Redis container $SHARED_REDIS_CONTAINER"
  [ "$DEMO_REDIS_PORT" != "$SHARED_REDIS_PORT" ] ||
    demo_die "refusing DEMO_REDIS_PORT=$SHARED_REDIS_PORT: that port is the shared test Redis"
}

# demo_docker ARGS... : docker, bounded at $DEMO_DOCKER_TIMEOUT seconds (10 by
# default). On a timeout it says Docker is not answering and returns 124.
# Docker Desktop under load has left single calls hanging for over 20 minutes.
# `docker run` and `docker rm` use longer explicit bounds (up.sh, down.sh).
demo_docker() {
  local rc=0
  demo_timeout "$DEMO_DOCKER_TIMEOUT" docker "$@" || rc=$?
  if [ "$rc" = 124 ]; then
    printf '%sdemo: Docker not answering: "docker %s" gave no answer in %s s (Docker Desktop overloaded or stuck)%s\n' \
      "$C_R" "$1" "$DEMO_DOCKER_TIMEOUT" "$C_0" >&2
  fi
  return "$rc"
}

# Print the demo container's name if it exists AND carries the demo label.
demo_labelled_container() {
  demo_docker ps -a --filter "label=$DEMO_LABEL" --filter "name=^/${DEMO_REDIS_CONTAINER}\$" --format '{{.Names}}'
}

# Print the name of any container with the demo's name, labelled or not.
demo_named_container() {
  demo_docker ps -a --filter "name=^/${DEMO_REDIS_CONTAINER}\$" --format '{{.Names}}'
}

# ---------------------------------------------------------------- tokens

b64url() { openssl base64 -A | tr -d '=' | tr '+/' '-_'; }

# demo_token SCOPE [TTL_SECONDS] -> a signed consumer JWT on stdout. Callers
# must keep it in a variable and never echo it.
demo_token() {
  local scope=$1 ttl=${2:-300} key kid iss sub now h c s
  if [ "$DEMO_MODE" = remote ]; then
    key=$DEMO_REMOTE_DIR/oidc-key.pem; kid=$DEMO_REMOTE_KID
    iss=$DEMO_REMOTE_ISSUER; sub=$DEMO_REMOTE_SUBJECT
  else
    key=$DEMO_PKI/oidc-key.pem; kid=$DEMO_KID; iss=$DEMO_ISSUER; sub=$DEMO_SUBJECT
  fi
  [ -r "$key" ] || demo_die "issuer key not readable: $key"
  now=$(date +%s)
  h=$(printf '{"alg":"RS256","kid":"%s","typ":"JWT"}' "$kid" | b64url)
  c=$(printf '{"iss":"%s","aud":"%s","sub":"%s","iat":%s,"exp":%s,"scope":"%s"}' \
    "$iss" "$DEMO_AUDIENCE" "$sub" "$now" "$((now + ttl))" "$scope" | b64url)
  s=$(printf '%s.%s' "$h" "$c" | openssl dgst -sha256 -sign "$key" -binary | b64url)
  printf '%s.%s.%s' "$h" "$c" "$s"
}

# ---------------------------------------------------------------- consumer calls

demo_base_url() {
  if [ "$DEMO_MODE" = remote ]; then printf '%s' "$DEMO_REMOTE_URL"; else printf '%s' "$DEMO_CONSUMER_URL"; fi
}

demo_ca() {
  if [ "$DEMO_MODE" = remote ]; then printf '%s' "$DEMO_REMOTE_DIR/relay-ca.pem"; else printf '%s' "$DEMO_PKI/server-ca.pem"; fi
}

# demo_call METHOD PATH TOKEN|- BODYFILE|- [extra curl args...]
# Sets DEMO_HTTP (status), DEMO_TIME (seconds), DEMO_BODY (file with the
# response body) and DEMO_HEADERS (file with response headers). The token is
# passed to curl on stdin, never on its command line. TOKEN "-" sends none.
demo_call() {
  local method=$1 path=$2 token=$3 body=$4 out
  shift 4
  [ -n "${DEMO_TMP:-}" ] || DEMO_TMP=$(mktemp -d "${TMPDIR:-/tmp}/agentuplink-demo.XXXXXX")
  DEMO_BODY=$DEMO_TMP/body
  DEMO_HEADERS=$DEMO_TMP/headers
  set -- -sS --max-time 35 --cacert "$(demo_ca)" -X "$method" -D "$DEMO_HEADERS" \
    -o "$DEMO_BODY" -w '%{http_code} %{time_total}' "$@"
  if [ "$body" != - ]; then set -- "$@" --data-binary "@$body"; fi
  if [ "$token" != - ]; then
    out=$(printf 'Authorization: Bearer %s\n' "$token" | curl -H @- "$@" "$(demo_base_url)$path" 2>&1) || true
  else
    out=$(curl "$@" "$(demo_base_url)$path" </dev/null 2>&1) || true
  fi
  DEMO_HTTP=${out%% *}
  DEMO_TIME=${out##* }
  case $DEMO_HTTP in [0-9][0-9][0-9]) ;; *) DEMO_HTTP=000; DEMO_TIME=-; demo_info "curl: $(printf '%s' "$out" | demo_redact | tail -1)" ;; esac
  : >>"$DEMO_BODY"
}

demo_ms() { python3 -c "import sys; print('%d ms' % round(float(sys.argv[1])*1000))" "$1" 2>/dev/null || printf '%s s' "$1"; }

# demo_expect LABEL WANT : report the last demo_call against an expected status.
demo_expect() {
  local label=$1 want=$2
  if [ "$DEMO_HTTP" = "$want" ]; then
    demo_ok "$label -> HTTP $DEMO_HTTP in $(demo_ms "$DEMO_TIME")"
    return 0
  fi
  demo_bad "$label -> HTTP $DEMO_HTTP (expected $want) in $(demo_ms "$DEMO_TIME")"
  demo_info "body: $(head -c 300 "$DEMO_BODY" | tr '\n' ' ' | demo_redact)"
  DEMO_FAILURES=$((${DEMO_FAILURES:-0} + 1))
  return 1
}

# After a failed first step: explain the usual causes and tell the caller
# to stop (return 1) instead of repeating the same refusal.
demo_explain_unreachable() {
  local code
  code=$(demo_error_code)
  case "$DEMO_HTTP:$code" in
    503:DEVICE_OFFLINE)
      if [ "$DEMO_MODE" = remote ]; then
        demo_info "the live relay's device is not connected. Start it in another terminal:"
        demo_info "  tunnel-client connect --config $DEMO_REMOTE_DIR/device/client.toml --json"
      else
        demo_info "the device is not connected: scripts/demo/status.sh, then down.sh + up.sh"
      fi ;;
    404:NOT_FOUND|404:SERVICE_NOT_FOUND)
      demo_info "the relay does not serve this service (remote: the live relay has no [http_forward] profile or catalog record for it)" ;;
    000:*) demo_info "the relay did not answer at $(demo_base_url)" ;;
    *) return 0 ;;
  esac
  demo_info "skipping the remaining steps of this feature"
  return 1
}

# The error `code` of a JSON refusal body, if any.
demo_error_code() {
  python3 -c '
import json, sys
try:
    body = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
code = body.get("code") or (body.get("error") or {}).get("code") if isinstance(body, dict) else None
print(code or "")' "$DEMO_BODY"
}

# The first JSON-RPC message of an MCP response, plain JSON or SSE.
demo_jsonrpc() {
  python3 -c '
import json, sys
raw = open(sys.argv[1], encoding="utf-8", errors="replace").read()
for chunk in [raw] + [l[5:].strip() for l in raw.splitlines() if l.startswith("data:")]:
    try:
        msg = json.loads(chunk)
    except Exception:
        continue
    if isinstance(msg, dict) and ("result" in msg or "error" in msg):
        print(json.dumps(msg)); break' "$DEMO_BODY"
}

demo_header() {
  tr -d '\r' <"$DEMO_HEADERS" | awk -v k="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" \
    'BEGIN{FS=": "} tolower($1)==k {print $2}' | tail -1
}

# ---------------------------------------------------------------- features

# Feature plug-ins live in features/NN-name.sh and are sourced in a subshell
# (see features/_template.sh for the contract).
demo_feature_files() { ls "$DEMO_DIR"/features/[0-9][0-9]-*.sh 2>/dev/null; }

demo_feature_file() {
  local f
  for f in $(demo_feature_files); do
    case $(basename "$f" .sh) in [0-9][0-9]-"$1") printf '%s' "$f"; return 0 ;; esac
  done
  return 1
}

demo_feature_names() {
  local f
  for f in $(demo_feature_files); do basename "$f" .sh | sed 's/^[0-9][0-9]-//'; done
}

# Reset every hook to its default, then source one plug-in.
demo_load_feature() {
  FEATURE_NAME=; FEATURE_TITLE=; FEATURE_READY=0; FEATURE_TODO=
  FEATURE_CARGO_PACKAGES=; FEATURE_REQUIRES=; FEATURE_REMOTE=0
  feature_service() { :; }
  feature_grant_operations() { :; }
  feature_relay_profile() { :; }
  feature_relay_toml() { :; }
  feature_export() { :; }
  feature_start() { :; }
  feature_show() { demo_warn "no demo steps defined"; }
  feature_show_remote() { demo_warn "no remote demo for this feature"; }
  # shellcheck disable=SC1090
  . "$1"
  [ -n "$FEATURE_NAME" ] || demo_die "$1 does not set FEATURE_NAME"
}
