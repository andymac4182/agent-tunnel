#!/bin/sh
# M3-17: off-the-shelf MCP clients through a real local relay.
#
#   scripts/m3-sdk-conformance.sh
#   M3SC_KEEP=1 scripts/m3-sdk-conformance.sh      # keep the work directory
#   M3SC_HOLD=1 M3SC_KEEP=1 scripts/m3-sdk-conformance.sh   # pause with both stacks up
#   M3SC_PLAIN_REDIS=127.0.0.1:63790 ...            # TLS-front an existing plaintext Redis
#
# Pinned in tests/mcp-sdk-conformance (never a runtime dependency):
#   * the official MCP TypeScript SDK   @modelcontextprotocol/sdk 1.30.1 (npm lockfile)
#   * the official MCP Python SDK       mcp 2.2.0 (uv/pip hash-locked requirements.txt)
#   * the official MCP conformance suite @modelcontextprotocol/conformance 0.2.0-alpha.11
#   * the suite's reference "everything" server, fetched from
#     modelcontextprotocol/conformance at REFERENCE_COMMIT and SHA-256 checked
#
# Three relays share one TLS Redis endpoint (`tunnel-relay serve` refuses a
# plaintext catalog; see step 4), each in its own nonce-named namespace, each
# with one device (`tunnel-client connect`) exporting one mcp-2025-11-25
# service:
#   reference  the suite's reference server (Streamable HTTP backend on
#              loopback): the TypeScript SDK's cases and the conformance
#              suite.  It refuses the Python SDK's initialize (M3-47), which
#              is checked as a known upstream incompatibility;
#   sdkserver  ts-sdk-server.mjs, a plain server on the pinned TypeScript SDK
#              with the reference server's names: initialize, tools,
#              resources, prompts, progress and log notifications, for both
#              SDKs;
#   fixture    the repository's rmcp fixture over stdio: tools, `_meta`,
#              ordered progress, and a cancel that must reach the device's
#              server after dispatch (the Python session's close after it
#              may meet M3-48, reported as `result=known`).
# Every client goes client -> relay consumer listener (HTTPS + bearer token)
# -> device WebSocket (mTLS) -> tunnel-client -> MCP server.  Nothing
# bypasses the relay.  The conformance suite also runs directly against the
# reference server, so a relay-only failure is attributable.
#
# Exit status 0 only if every SDK case passed, every conformance scenario
# passed directly, and every conformance scenario passed through the relay
# except those listed in tests/mcp-sdk-conformance/relay-expected-failures.txt
# (each of which must still fail, so a stale entry is red too).
#
# Requirements: cargo, node >= 24 with npm, uv (or python3 >= 3.10 with
# venv/pip), openssl, curl, and either a plaintext test Redis
# (M3SC_PLAIN_REDIS or TEST_REDIS_URL) or docker.  Network access to npm, PyPI and
# raw.githubusercontent.com for the pinned, hash-checked installs.
set -eu

REFERENCE_COMMIT=c321dd32035556e6769d3724a8ee97d87c3faaac   # conformance 0.2.0-alpha.11 gitHead
REFERENCE_SHA256=488ddabf5573078dbc4c21d980701ba05033ad83316bdbde20005228151a5205
REFERENCE_URL=https://raw.githubusercontent.com/modelcontextprotocol/conformance/$REFERENCE_COMMIT/examples/servers/typescript/everything-server.ts
# The CI Redis image, by digest.
REDIS_IMAGE=${M3SC_REDIS_IMAGE:-redis:8.4.0-alpine@sha256:6cbef353e480a8a6e7f10ec545f13d7d3fa85a212cdcc5ffaf5a1c818b9d3798}
# Fewer scenarios than this means the suite did not really run.
CONFORMANCE_SCENARIO_FLOOR=31

repo=$(cd "$(dirname "$0")/.." && pwd)
suite="$repo/tests/mcp-sdk-conformance"
nonce="m3sc-$(date +%s)-$$-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
head=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)
work=${M3SC_DIR:-${TMPDIR:-/tmp}/m3-sdk-conformance-$nonce}
work=${work%/}
container=
plain_redis=
issuer="https://issuer.m3sc.agentuplink.test/"
audience="agent-tunnel"
profile="mcp-2025-11-25"
start_epoch=$(date +%s)

say() { echo "m3-sdk-conformance: $*" >&2; }
fail() { say "FAIL: $*"; exit 1; }
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
set_key() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
path, key, value = sys.argv[1:4]
lines = open(path).read().split("\n")
if not any(l.startswith(f"{key} = ") for l in lines):
    sys.exit(f"example {path} has no '{key}' line")
open(path, "w").write("\n".join(f"{key} = {value}" if l.startswith(f"{key} = ") else l for l in lines))
PY
}
wait_for_line() { # file pattern pid what
  n=0
  until grep -q "$2" "$1" 2>/dev/null; do
    n=$((n + 1))
    if [ "$n" -ge 240 ] || ! kill -0 "$3" 2>/dev/null; then
      tail -20 "$1" >&2 || true
      fail "$4 did not start"
    fi
    sleep 0.25
  done
}

pids=
cleanup() {
  status=$?
  for pid in $pids; do kill "$pid" 2>/dev/null || true; done
  for pid in $pids; do wait "$pid" 2>/dev/null || true; done
  if [ -n "$container" ]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  if [ -n "$plain_redis" ]; then
    python3 "$suite/redis_tls_proxy.py" purge "${plain_redis%:*}" "${plain_redis##*:}" "$nonce" >&2 || true
  fi
  if [ "$status" = 0 ] && [ "${M3SC_KEEP:-0}" != 1 ]; then
    rm -rf "$work"
  else
    say "exit $status; work directory kept: $work"
  fi
}
trap cleanup EXIT INT TERM

for tool in cargo node npm openssl curl python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing prerequisite: $tool"
done
node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 24 ? 0 : 1)' \
  || fail "node >= 24 is required"

mkdir -p "$work/logs"
chmod 700 "$work"
log="$work/logs/m3-sdk-conformance.log"
echo "nonce=$nonce head=$head" > "$log"
say "nonce=$nonce head=$head work=$work"

# 1. Binaries: the shipped relay and device, and the rmcp fixture server.
say "build tunnel-relay, tunnel-client and tunnel-mcp-fixture"
(cd "$repo" && cargo build --locked -p tunnel-relay -p tunnel-client -p tunnel-mcp-fixture --bins) \
  >"$work/logs/build.log" 2>&1 || { tail -30 "$work/logs/build.log" >&2; fail "cargo build"; }
bin=${CARGO_TARGET_DIR:-$repo/target}/debug

# 2. The pinned clients, suite and reference server.
say "install the pinned npm packages (npm ci)"
(cd "$suite" && npm ci --ignore-scripts --no-audit --no-fund) >"$work/logs/npm.log" 2>&1 \
  || { tail -30 "$work/logs/npm.log" >&2; fail "npm ci"; }
say "install the pinned Python SDK (hash-checked)"
venv="$work/venv"
if command -v uv >/dev/null 2>&1; then
  uv venv -q --python ">=3.10" "$venv" >"$work/logs/python.log" 2>&1
  VIRTUAL_ENV="$venv" uv pip sync -q --require-hashes "$suite/python/requirements.txt" >>"$work/logs/python.log" 2>&1 \
    || { tail -30 "$work/logs/python.log" >&2; fail "uv pip sync"; }
else
  python3 -m venv "$venv" >"$work/logs/python.log" 2>&1
  "$venv/bin/python" -m pip install -q --require-hashes --no-deps -r "$suite/python/requirements.txt" \
    >>"$work/logs/python.log" 2>&1 || { tail -30 "$work/logs/python.log" >&2; fail "pip install"; }
fi
python_sdk=$("$venv/bin/python" -c 'import importlib.metadata as m; print(m.version("mcp"))')
[ "$python_sdk" = 2.2.0 ] || fail "python mcp is $python_sdk, not the pinned 2.2.0"
ts_sdk=$(node -p 'require(process.argv[1]).version' "$suite/node_modules/@modelcontextprotocol/sdk/package.json")
[ "$ts_sdk" = 1.30.1 ] || fail "@modelcontextprotocol/sdk is $ts_sdk, not the pinned 1.30.1"
say "fetch the reference server at $REFERENCE_COMMIT"
mkdir -p "$suite/.reference"
curl -sSfL "$REFERENCE_URL" -o "$suite/.reference/everything-server.ts.part" \
  || fail "could not fetch the reference server"
got=$(openssl dgst -sha256 -r "$suite/.reference/everything-server.ts.part" | cut -d' ' -f1)
[ "$got" = "$REFERENCE_SHA256" ] || fail "reference server sha256 $got != pinned $REFERENCE_SHA256"
mv "$suite/.reference/everything-server.ts.part" "$suite/.reference/everything-server.ts"
echo "sdk typescript=@modelcontextprotocol/sdk@$ts_sdk python=mcp@$python_sdk conformance=0.2.0-alpha.11 reference=$REFERENCE_COMMIT" >> "$log"

# 3. Synthetic PKI: one server CA (relay listeners and Redis), one device CA.
cat > "$work/server-ext.cnf" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
# Python >= 3.13 verifies strictly (VERIFY_X509_STRICT) and refuses a CA
# without keyUsage, which a bare `openssl req -x509` omits (task row M3-48).
ca_ext="-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign"
# shellcheck disable=SC2086
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=m3sc synthetic server CA" $ca_ext \
  -keyout "$work/server-ca-key.pem" -out "$work/server-ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -keyout "$work/relay-key.pem" -out "$work/relay.csr" 2>/dev/null
openssl x509 -req -in "$work/relay.csr" -CA "$work/server-ca.pem" -CAkey "$work/server-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "$work/server-ext.cnf" -out "$work/relay-cert.pem" 2>/dev/null
cat "$work/relay-cert.pem" "$work/server-ca.pem" > "$work/relay-cert-chain.pem"
# shellcheck disable=SC2086
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=m3sc synthetic device CA" $ca_ext \
  -keyout "$work/device-ca-key.pem" -out "$work/device-ca.pem" 2>/dev/null

# 4. A TLS Redis endpoint.  With M3SC_PLAIN_REDIS=host:port, or CI's
#    TEST_REDIS_URL=redis://host:port/, a TLS front (redis_tls_proxy.py) is put
#    before that existing plaintext test Redis, and this run's keys (all named
#    with its nonce) are purged on exit.  Otherwise a TLS Redis container of
#    this run's own is started.
plain_redis=${M3SC_PLAIN_REDIS:-}
if [ -z "$plain_redis" ] && [ -n "${TEST_REDIS_URL:-}" ]; then
  plain_redis=$(printf '%s' "$TEST_REDIS_URL" | sed -E 's#^redis://([^/]+)/?.*$#\1#')
fi
if [ -n "$plain_redis" ]; then
  plain_host=${plain_redis%:*}
  plain_port=${plain_redis##*:}
  say "TLS front for the plaintext test Redis at $plain_host:$plain_port (keys namespaced by $nonce)"
  python3 "$suite/redis_tls_proxy.py" serve "$work/relay-cert-chain.pem" "$work/relay-key.pem" \
    "$plain_host" "$plain_port" "$work/redis-port" >"$work/logs/redis-proxy.log" 2>&1 &
  proxy_pid=$!
  pids="$pids $proxy_pid"
  n=0
  until [ -s "$work/redis-port" ]; do
    n=$((n + 1))
    { [ "$n" -lt 80 ] && kill -0 "$proxy_pid" 2>/dev/null; } || { cat "$work/logs/redis-proxy.log" >&2; fail "redis TLS front"; }
    sleep 0.25
  done
  redis_port=$(cat "$work/redis-port")
else
  container="m3-sdk-conformance-$nonce"
  mkdir -p "$work/redis"
  cp "$work/relay-cert.pem" "$work/redis/cert.pem"
  cp "$work/relay-key.pem" "$work/redis/key.pem"
  cp "$work/server-ca.pem" "$work/redis/ca.pem"
  chmod 644 "$work/redis/"*.pem   # synthetic; the container's redis user must read it
  chmod 755 "$work/redis"
  redis_port=$(free_port)
  say "start TLS Redis container $container on 127.0.0.1:$redis_port"
  docker run -d --rm --name "$container" -p "127.0.0.1:$redis_port:6380" \
    -v "$work/redis:/tls:ro" "$REDIS_IMAGE" redis-server --port 0 --tls-port 6380 \
    --tls-cert-file /tls/cert.pem --tls-key-file /tls/key.pem --tls-ca-cert-file /tls/ca.pem \
    --tls-auth-clients no --save '' --appendonly no >"$work/logs/redis.log" 2>&1 \
    || { cat "$work/logs/redis.log" >&2; fail "docker run redis"; }
fi

# 5. A synthetic identity issuer and one consumer token (scope http:invoke).
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/issuer-key.pem" 2>/dev/null
modulus=$(openssl rsa -noout -modulus -in "$work/issuer-key.pem" | sed 's/^Modulus=//' | xxd -r -p | b64url)
printf '{"keys":[{"kid":"m3sc-issuer","kty":"RSA","alg":"RS256","n":"%s","e":"AQAB"}]}\n' \
  "$modulus" > "$work/issuer-jwks.json"
records="$repo/examples/m6-catalog-mcp.toml"
toml_get() {
  python3 -c 'import sys,tomllib; d=tomllib.load(open(sys.argv[1],"rb")); print(d[sys.argv[2]][sys.argv[3]])' "$records" "$1" "$2"
}
device_id=$(toml_get device id)
service_id=$(toml_get service id)
subject=$(toml_get user oidc_subject)
now=$(date +%s)
jwt_header=$(printf '{"alg":"RS256","kid":"m3sc-issuer","typ":"JWT"}' | b64url)
jwt_payload=$(printf '{"iss":"%s","aud":"%s","sub":"%s","iat":%s,"exp":%s,"scope":"http:invoke"}' \
  "$issuer" "$audience" "$subject" "$now" "$((now + 3600))" | b64url)
jwt_signature=$(printf '%s.%s' "$jwt_header" "$jwt_payload" | openssl dgst -sha256 -sign "$work/issuer-key.pem" | b64url)
token="$jwt_header.$jwt_payload.$jwt_signature"

# 6. The reference server, on loopback, for the reference stack's backend.
ref_port=$(free_port)
say "start the reference server on 127.0.0.1:$ref_port"
(cd "$suite" && PORT=$ref_port AGENTUPLINK_LOOPBACK_ONLY=1 NODE_OPTIONS="--import $suite/preload.mjs" \
  exec node_modules/.bin/tsx .reference/everything-server.ts) >"$work/logs/reference-server.log" 2>&1 &
ref_pid=$!
pids="$pids $ref_pid"
wait_for_line "$work/logs/reference-server.log" "running on" "$ref_pid" "the reference server"
sdk_port=$(free_port)
say "start the TypeScript SDK server on 127.0.0.1:$sdk_port"
(cd "$suite" && PORT=$sdk_port exec node ts-sdk-server.mjs) >"$work/logs/ts-sdk-server.log" 2>&1 &
sdk_pid=$!
pids="$pids $sdk_pid"
wait_for_line "$work/logs/ts-sdk-server.log" "running on" "$sdk_pid" "the TypeScript SDK server"

# 7. One relay and one device per stack.
start_stack() { # name backend-kind [backend-url]
  name=$1 kind=$2 backend_url=${3:-}
  dir="$work/$name"
  mkdir -p "$dir/device/workspace"
  consumer_port=$(free_port)
  device_port=$(free_port)

  cp "$records" "$dir/device/catalog.toml"
  cp "$repo/examples/m1-client.toml" "$dir/device/client.toml"
  set_key "$dir/device/client.toml" relay_url "\"wss://127.0.0.1:$device_port/v1/tunnel/control\""
  python3 - "$dir/device/client.toml" "$service_id" "$profile" "$kind" "$bin/tunnel-mcp-fixture" \
    "$dir/device/workspace" "$backend_url" <<'PY'
import sys
path, service, profile, kind, command, workspace, url = sys.argv[1:8]
text = open(path).read()
start = text.index('[exports."')
end = text.index("\n\n", start)
backend = (f'kind = "stdio"\ncommand = "{command}"\nargs = ["stdio"]\nworkspace = "{workspace}"'
           if kind == "stdio" else f'kind = "streamable-http"\nurl = "{url}"')
export = (f'[exports."{service}"]\ntype = "http-forward"\n\n'
          f'[exports."{service}".mcp]\nprofile = "{profile}"\n\n'
          f'[exports."{service}".mcp.backend]\n{backend}')
open(path, "w").write(text[:start] + export + text[end:])
PY
  "$bin/tunnel-client" credentials create --config "$dir/device/client.toml" --csr-out device.csr \
    >"$work/logs/$name-credentials.log" 2>&1 || { cat "$work/logs/$name-credentials.log" >&2; fail "$name credentials create"; }
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:%s\n' \
    "$device_id" > "$dir/device-ext.cnf"
  openssl x509 -req -in "$dir/device/device.csr" -CA "$work/device-ca.pem" -CAkey "$work/device-ca-key.pem" \
    -CAcreateserial -days 1 -extfile "$dir/device-ext.cnf" -out "$dir/device/device-cert.pem" 2>/dev/null
  "$bin/tunnel-client" credentials import --config "$dir/device/client.toml" \
    --certificate device-cert.pem --server-ca "$work/server-ca.pem" >>"$work/logs/$name-credentials.log" 2>&1 \
    || { cat "$work/logs/$name-credentials.log" >&2; fail "$name credentials import"; }

  cp "$repo/examples/m1-relay.toml" "$dir/relay.toml"
  set_key "$dir/relay.toml" consumer_bind "\"127.0.0.1:$consumer_port\""
  set_key "$dir/relay.toml" device_bind "\"127.0.0.1:$device_port\""
  set_key "$dir/relay.toml" oidc_issuer "\"$issuer\""
  set_key "$dir/relay.toml" oidc_jwks_path "\"$work/issuer-jwks.json\""
  set_key "$dir/relay.toml" redis_url "\"rediss://localhost:$redis_port/0\""
  set_key "$dir/relay.toml" redis_namespace "\"$nonce-$name\""
  set_key "$dir/relay.toml" device_tls_cert_chain "\"$work/relay-cert-chain.pem\""
  set_key "$dir/relay.toml" device_tls_private_key "\"$work/relay-key.pem\""
  set_key "$dir/relay.toml" device_tls_client_ca "\"$work/device-ca.pem\""
  set_key "$dir/relay.toml" consumer_tls_cert_chain "\"$work/relay-cert-chain.pem\""
  set_key "$dir/relay.toml" consumer_tls_private_key "\"$work/relay-key.pem\""
  set_key "$dir/relay.toml" node_id "\"m3sc-$name\""
  set_key "$dir/relay.toml" boot_id "\"$nonce-$name-boot\""
  set_key "$dir/relay.toml" deployment_incarnation "\"$nonce-$name\""
  {
    printf 'redis_tls_root_ca_path = "%s"\n' "$work/server-ca.pem"
    cat "$dir/relay.toml"
    printf '\n[http_forward]\nprofiles = ["%s"]\n' "$profile"
  } > "$dir/relay.toml.new"
  mv "$dir/relay.toml.new" "$dir/relay.toml"

  n=0
  until "$bin/tunnel-relay" activate-first-incarnation --config "$dir/relay.toml" >"$work/logs/$name-activate.log" 2>&1; do
    n=$((n + 1))
    [ "$n" -lt 60 ] || { cat "$work/logs/$name-activate.log" >&2; fail "$name activate-first-incarnation"; }
    sleep 0.25
  done
  "$bin/tunnel-relay" provision-catalog --config "$dir/relay.toml" --records "$dir/device/catalog.toml" \
    >"$work/logs/$name-provision.log" 2>&1 || { cat "$work/logs/$name-provision.log" >&2; fail "$name provision-catalog"; }

  RUST_LOG=${RUST_LOG:-warn} "$bin/tunnel-relay" serve --config "$dir/relay.toml" >"$work/logs/$name-relay.log" 2>&1 &
  relay_pid=$!
  pids="$pids $relay_pid"
  wait_for_line "$work/logs/$name-relay.log" '^tunnel-relay listening' "$relay_pid" "the $name relay"
  RUST_LOG=${RUST_LOG:-warn} "$bin/tunnel-client" connect --config "$dir/device/client.toml" >"$work/logs/$name-connect.log" 2>&1 &
  device_pid=$!
  pids="$pids $device_pid"
  wait_for_line "$work/logs/$name-connect.log" '^Connected:' "$device_pid" "the $name device"
  echo "https://localhost:$consumer_port/v1/devices/$device_id/services/$service_id/http/mcp" > "$dir/url"
  echo "https://localhost:$consumer_port" > "$dir/origin"
  say "$name stack up: relay :$consumer_port, device connected, backend $kind"
}
start_stack reference streamable-http "http://127.0.0.1:$ref_port/mcp"
start_stack sdkserver streamable-http "http://127.0.0.1:$sdk_port/mcp"
start_stack fixture stdio
sdkserver_url=$(cat "$work/sdkserver/url")
reference_url=$(cat "$work/reference/url")
reference_origin=$(cat "$work/reference/origin")
fixture_url=$(cat "$work/fixture/url")
fixture_workspace="$work/fixture/device/workspace"

# Demo and debugging: keep both stacks up for your own clients.
if [ "${M3SC_HOLD:-0}" = 1 ]; then
  umask 077
  printf '%s' "$token" > "$work/consumer-token"
  {
    echo "REFERENCE_URL=$reference_url"
    echo "SDKSERVER_URL=$sdkserver_url"
    echo "FIXTURE_URL=$fixture_url"
    echo "FIXTURE_WORKSPACE=$fixture_workspace"
    echo "SERVER_CA=$work/server-ca.pem"
    echo "TOKEN_FILE=$work/consumer-token"
    echo "PYTHON=$venv/bin/python"
  } > "$work/stack.env"
  say "M3SC_HOLD=1: stacks are up; see $work/stack.env; touch $work/release to continue"
  until [ -e "$work/release" ]; do sleep 1; done
fi

# 8. The SDK clients through the relay.
failed=0
results="$work/logs/sdk-cases.txt"
: > "$results"
run_case_set() { # label command...
  label=$1
  shift
  if ! "$@" >>"$results" 2>"$work/logs/$label.stderr"; then
    say "$label: at least one case failed"
    failed=1
  fi
}
say "TypeScript SDK $ts_sdk through the relay"
run_case_set ts-reference env AGENTUPLINK_TOKEN="$token" NODE_EXTRA_CA_CERTS="$work/server-ca.pem" \
  node "$suite/ts-client.ts" reference "$reference_url"
run_case_set ts-sdkserver env AGENTUPLINK_TOKEN="$token" NODE_EXTRA_CA_CERTS="$work/server-ca.pem" \
  node "$suite/ts-client.ts" reference "$sdkserver_url"
run_case_set ts-fixture env AGENTUPLINK_TOKEN="$token" NODE_EXTRA_CA_CERTS="$work/server-ca.pem" \
  node "$suite/ts-client.ts" fixture "$fixture_url" "$fixture_workspace"
say "Python SDK $python_sdk through the relay"
for mode in legacy auto; do
  run_case_set "py-$mode-sdkserver" env AGENTUPLINK_TOKEN="$token" AGENTUPLINK_CA="$work/server-ca.pem" \
    "$venv/bin/python" "$suite/python/py_client.py" reference "$mode" "$sdkserver_url"
  run_case_set "py-$mode-known-m3-47" env AGENTUPLINK_TOKEN="$token" AGENTUPLINK_CA="$work/server-ca.pem" \
    "$venv/bin/python" "$suite/python/py_client.py" known-m3-47 "$mode" "$reference_url"
  run_case_set "py-$mode-fixture" env AGENTUPLINK_TOKEN="$token" AGENTUPLINK_CA="$work/server-ca.pem" \
    "$venv/bin/python" "$suite/python/py_client.py" fixture "$mode" "$fixture_url" "$fixture_workspace"
done
# The relay's own DNS-rebinding answer: any request carrying Origin (which a
# browser always sends) is refused before admission, naming the header.  This
# stands in for the conformance suite's dns-rebinding-protection scenario,
# which cannot run through the relay (task row M3-49).
origin_reply=$(curl -sS --cacert "$work/server-ca.pem" -o - -w ' status=%{http_code}' \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' -H 'Origin: http://evil.example.com' \
  --data '{"jsonrpc":"2.0","id":1,"method":"ping"}' "$reference_url" 2>&1 || true)
case "$origin_reply" in
  *'"header":"origin"'*' status=400')
    echo "sdk=curl case=origin-refused result=pass status=400 header=origin" >> "$results" ;;
  *)
    echo "sdk=curl case=origin-refused result=fail" >> "$results"; failed=1 ;;
esac
sed 's/^/  /' "$results" >&2
cat "$results" >> "$log"

# 9. The conformance suite: directly against the reference server, then
#    through the relay (the preload adds the bearer token for the relay origin).
conformance="$suite/node_modules/@modelcontextprotocol/conformance/dist/index.js"
say "conformance suite 0.2.0-alpha.11 (--spec-version 2025-11-25), direct"
(cd "$work" && node "$conformance" server --url "http://127.0.0.1:$ref_port/mcp" --spec-version 2025-11-25 \
  -o "$work/conformance-direct") >"$work/logs/conformance-direct.log" 2>&1 || true
say "conformance suite through the relay"
(cd "$work" && AGENTUPLINK_RELAY_ORIGIN="$reference_origin" AGENTUPLINK_TOKEN="$token" \
  NODE_EXTRA_CA_CERTS="$work/server-ca.pem" NODE_OPTIONS="--import $suite/preload.mjs" \
  node "$conformance" server --url "$reference_url" --spec-version 2025-11-25 \
  -o "$work/conformance-relay") >"$work/logs/conformance-relay.log" 2>&1 || true

python3 - "$work/conformance-direct" "$work/conformance-relay" "$suite/relay-expected-failures.txt" \
  "$CONFORMANCE_SCENARIO_FLOOR" >>"$log" 2>"$work/logs/conformance-verdict.txt" <<'PY' || failed=1
import glob, json, os, re, sys
direct_dir, relay_dir, expected_path, floor = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])

def load(root):
    out = {}
    for path in glob.glob(os.path.join(root, "server-*", "checks.json")):
        scenario = re.sub(r"^server-(.*)-\d{4}-\d\d-\d\dT[\d-]+Z$", r"\1", os.path.basename(os.path.dirname(path)))
        checks = json.load(open(path))
        out[scenario] = [(c.get("id"), c.get("status")) for c in checks]
    return out

expected = {}
for line in open(expected_path):
    line = line.split("#", 1)[0].strip()
    if line:
        scenario, row = line.split()
        expected[scenario] = row

direct, relay = load(direct_dir), load(relay_dir)
bad = []
passed = lambda checks: bool(checks) and all(s in ("SUCCESS", "INFO", "WARNING") for _, s in checks)
for scenario in sorted(set(direct) | set(relay)):
    d, r = direct.get(scenario), relay.get(scenario)
    dn = "missing" if d is None else ("pass" if passed(d) else "fail")
    rn = "missing" if r is None else ("pass" if passed(r) else "fail")
    failing = [cid for cid, s in (r or []) if s not in ("SUCCESS", "INFO", "WARNING")]
    tag = ""
    if dn != "pass":
        bad.append(f"{scenario}: fails directly against the reference server")
    if rn != "pass" and scenario not in expected:
        bad.append(f"{scenario}: fails only through the relay and has no row")
    if rn == "pass" and scenario in expected:
        bad.append(f"{scenario}: listed as an expected relay failure ({expected[scenario]}) but passed")
    if scenario in expected:
        tag = f" expected_failure_row={expected[scenario]}"
    ok_d = sum(1 for _, s in d or [] if s == "SUCCESS")
    ok_r = sum(1 for _, s in r or [] if s == "SUCCESS")
    print(f"conformance scenario={scenario} direct={dn}({ok_d}/{len(d or [])}) "
          f"relay={rn}({ok_r}/{len(r or [])}){' failed_checks=' + ','.join(failing) if failing else ''}{tag}")
for scenario in expected:
    if scenario not in relay:
        bad.append(f"{scenario}: listed as an expected relay failure but did not run")
if len(direct) < floor or len(relay) < floor:
    bad.append(f"only {len(direct)} direct and {len(relay)} relay scenarios ran (floor {floor})")
print(f"conformance scenarios direct={len(direct)} relay={len(relay)} "
      f"relay_pass={sum(1 for s in relay.values() if passed(s))} verdict={'fail' if bad else 'pass'}")
for line in bad:
    print(f"conformance problem: {line}", file=sys.stderr)
sys.exit(1 if bad else 0)
PY
grep '^conformance' "$log" | sed 's/^/  /' >&2
[ -s "$work/logs/conformance-verdict.txt" ] && sed 's/^/  /' "$work/logs/conformance-verdict.txt" >&2

sdk_pass=$(grep -c 'result=pass' "$results" || true)
sdk_fail=$(grep -c 'result=fail' "$results" || true)
sdk_known=$(grep -c 'result=known' "$results" || true)
elapsed=$(( $(date +%s) - start_epoch ))
summary="summary nonce=$nonce head=$head sdk_cases_pass=$sdk_pass sdk_cases_fail=$sdk_fail sdk_cases_known=$sdk_known elapsed_s=$elapsed"
echo "$summary" >> "$log"
say "$summary"
if [ -n "${M3SC_LOG_COPY:-}" ]; then cp "$log" "$M3SC_LOG_COPY"; fi
# A run that reported nothing is not a pass.
[ "$sdk_pass" -ge 70 ] || { say "only $sdk_pass SDK cases passed; expected at least 70"; failed=1; }
[ "$failed" = 0 ] || fail "see $work/logs"
say "ok: the pinned TypeScript and Python MCP SDKs and the conformance suite work through the relay"
