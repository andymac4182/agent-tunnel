#!/bin/sh
# The MCP demo (docs/demo/mcp.md): a real MCP server on the "device", exported
# through a real local relay, exercised by a real MCP client.
#
#   scripts/demo-mcp.sh                  # run the demo end to end, then clean up
#   DEMO_KEEP=1 scripts/demo-mcp.sh      # leave relay, device and Redis running
#   DEMO_PROFILE=mcp-2026-07-28 scripts/demo-mcp.sh
#
# Everything is synthetic and local: a throwaway PKI and identity issuer made
# with openssl, a TLS Redis in a new Docker container of its own (the relay
# refuses a plaintext catalog), the shipped `tunnel-relay` and `tunnel-client`
# binaries configured from the shipped examples, the repository's
# deterministic MCP server (`tunnel-mcp-fixture`) as the device's MCP server,
# and the pinned official Rust MCP SDK (rmcp 3.4.0, via
# `tunnel-test-harness mcp-demo-client`) as the cloud-side client.  Traffic
# goes client -> relay consumer listener (HTTPS + bearer token) -> device
# WebSocket (mTLS) -> tunnel-client -> MCP server over stdio.  Nothing
# bypasses the relay.
#
# Requirements: cargo, openssl, docker, and the redis:8.4.0-alpine image.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
profile=${DEMO_PROFILE:-mcp-2025-11-25}
case "$profile" in
  mcp-2025-11-25) client_profile=2025-11-25 ;;
  mcp-2026-07-28) client_profile=2026-07-28 ;;
  *) echo "demo-mcp: DEMO_PROFILE is mcp-2025-11-25 or mcp-2026-07-28" >&2; exit 2 ;;
esac
redis_image=${DEMO_REDIS_IMAGE:-redis:8.4.0-alpine}
nonce=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
work=${DEMO_DIR:-${TMPDIR:-/tmp}/agentuplink-mcp-demo-$nonce}
work=${work%/}
container="agentuplink-mcp-demo-$nonce"
issuer="https://issuer.demo.agentuplink.test/"
audience="agent-tunnel"

say() { echo "demo-mcp: $*" >&2; }
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
# Replace the whole `key = ...` line of a TOML example.
set_key() {
  file=$1 key=$2 value=$3
  grep -q "^$key = " "$file" || { say "example $file has no '$key' line"; exit 1; }
  python3 - "$file" "$key" "$value" <<'PY'
import sys
path, key, value = sys.argv[1:4]
lines = open(path).read().split("\n")
lines = [f"{key} = {value}" if l.startswith(f"{key} = ") else l for l in lines]
open(path, "w").write("\n".join(lines))
PY
}

relay_pid=
device_pid=
cleanup() {
  status=$?
  if [ "${DEMO_KEEP:-0}" = 1 ] && [ "$status" = 0 ]; then
    say "DEMO_KEEP=1: relay pid $relay_pid, device pid $device_pid and container $container keep running"
    say "stop them with: kill $relay_pid $device_pid; docker rm -f $container; rm -rf $work"
    return
  fi
  [ -n "$device_pid" ] && kill "$device_pid" 2>/dev/null || true
  [ -n "$relay_pid" ] && kill "$relay_pid" 2>/dev/null || true
  [ -n "$device_pid" ] && wait "$device_pid" 2>/dev/null || true
  [ -n "$relay_pid" ] && wait "$relay_pid" 2>/dev/null || true
  docker rm -f "$container" >/dev/null 2>&1 || true
  if [ "$status" = 0 ]; then
    rm -rf "$work"
  else
    say "FAILED (exit $status); logs kept in $work (relay.log, connect.log)"
  fi
}
trap cleanup EXIT INT TERM

# 1. Build the shipped binaries, the demo MCP server and the demo client.
say "build tunnel-relay, tunnel-client, tunnel-mcp-fixture and tunnel-test-harness"
(cd "$repo" && cargo build --locked -p tunnel-relay -p tunnel-client \
  -p tunnel-mcp-fixture -p tunnel-test-harness --bins)
bin=${CARGO_TARGET_DIR:-$repo/target}/debug
mkdir -p "$work/device" "$work/redis"
chmod 700 "$work"
say "work directory $work (profile $profile)"

# 2. A synthetic server PKI: one CA and one leaf for localhost/127.0.0.1,
#    used by the relay's two listeners and by the demo Redis.
cat > "$work/server-ext.cnf" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Agent Uplink demo server CA" \
  -keyout "$work/server-ca-key.pem" -out "$work/server-ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -keyout "$work/relay-key.pem" -out "$work/relay.csr" 2>/dev/null
openssl x509 -req -in "$work/relay.csr" -CA "$work/server-ca.pem" -CAkey "$work/server-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "$work/server-ext.cnf" -out "$work/relay-cert.pem" 2>/dev/null
cat "$work/relay-cert.pem" "$work/server-ca.pem" > "$work/relay-cert-chain.pem"

# 3. A TLS Redis of the demo's own (never the shared development Redis).
cp "$work/relay-cert.pem" "$work/redis/cert.pem"
cp "$work/relay-key.pem" "$work/redis/key.pem"
cp "$work/server-ca.pem" "$work/redis/ca.pem"
chmod 644 "$work/redis/"*.pem  # synthetic key; the container's redis user must read it
redis_port=$(free_port)
say "start TLS Redis container $container on 127.0.0.1:$redis_port"
docker run -d --rm --name "$container" -p "127.0.0.1:$redis_port:6380" \
  -v "$work/redis:/tls:ro" "$redis_image" redis-server --port 0 --tls-port 6380 \
  --tls-cert-file /tls/cert.pem --tls-key-file /tls/key.pem --tls-ca-cert-file /tls/ca.pem \
  --tls-auth-clients no --save '' --appendonly no >/dev/null &
docker_pid=$!
attempt=0
while kill -0 "$docker_pid" 2>/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 240 ]; then
    kill "$docker_pid" 2>/dev/null || true
    say "docker run did not return within 60 s; check that Docker can start containers (docker run --rm alpine:3 true)"
    exit 1
  fi
  sleep 0.25
done
wait "$docker_pid" || { say "docker run failed"; exit 1; }

# 4. A synthetic identity issuer: an RSA key published to the relay as JWKS.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/issuer-key.pem" 2>/dev/null
modulus=$(openssl rsa -noout -modulus -in "$work/issuer-key.pem" | sed 's/^Modulus=//' \
  | xxd -r -p | b64url)
printf '{"keys":[{"kid":"demo-issuer","kty":"RSA","alg":"RS256","n":"%s","e":"AQAB"}]}\n' \
  "$modulus" > "$work/issuer-jwks.json"

# 5. The records: the shipped MCP example, with the chosen profile.
cp "$repo/examples/m6-catalog-mcp.toml" "$work/device/catalog.toml"
set_key "$work/device/catalog.toml" http_forward_profile "\"$profile\""
device_id=$(python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["device"]["id"])' "$work/device/catalog.toml")
service_id=$(python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["service"]["id"])' "$work/device/catalog.toml")
subject=$(python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["user"]["oidc_subject"])' "$work/device/catalog.toml")

consumer_port=$(free_port)
device_port=$(free_port)

# 6. The device: the shipped client example, with one MCP export whose
#    backend is the fixture MCP server over stdio.
cp "$repo/examples/m1-client.toml" "$work/device/client.toml"
set_key "$work/device/client.toml" relay_url "\"wss://127.0.0.1:$device_port/v1/tunnel/control\""
python3 - "$work/device/client.toml" "$service_id" "$profile" "$bin/tunnel-mcp-fixture" "$work/device/mcp-workspace" <<'PY'
import sys
path, service, profile, command, workspace = sys.argv[1:6]
text = open(path).read()
start = text.index('[exports."')
end = text.index("\n\n", start)
export = (f'[exports."{service}"]\ntype = "http-forward"\n\n'
          f'[exports."{service}".mcp]\nprofile = "{profile}"\n\n'
          f'[exports."{service}".mcp.backend]\nkind = "stdio"\ncommand = "{command}"\n'
          f'args = ["stdio"]\nworkspace = "{workspace}"')
open(path, "w").write(text[:start] + export + text[end:])
PY
mkdir -p "$work/device/mcp-workspace"
say "device key and CSR (tunnel-client credentials create)"
"$bin/tunnel-client" credentials create --config "$work/device/client.toml" --csr-out device.csr >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Agent Uplink demo device CA" \
  -keyout "$work/device-ca-key.pem" -out "$work/device-ca.pem" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:%s\n' \
  "$device_id" > "$work/device-ext.cnf"
openssl x509 -req -in "$work/device/device.csr" -CA "$work/device-ca.pem" -CAkey "$work/device-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "$work/device-ext.cnf" -out "$work/device/device-cert.pem" 2>/dev/null
"$bin/tunnel-client" credentials import --config "$work/device/client.toml" \
  --certificate device-cert.pem --server-ca "$work/server-ca.pem" >/dev/null

# 7. The relay: the shipped relay example plus the MCP profile.
cp "$repo/examples/m1-relay.toml" "$work/relay.toml"
set_key "$work/relay.toml" consumer_bind "\"127.0.0.1:$consumer_port\""
set_key "$work/relay.toml" device_bind "\"127.0.0.1:$device_port\""
set_key "$work/relay.toml" oidc_issuer "\"$issuer\""
set_key "$work/relay.toml" oidc_jwks_path "\"$work/issuer-jwks.json\""
set_key "$work/relay.toml" redis_url "\"rediss://localhost:$redis_port/0\""
set_key "$work/relay.toml" redis_namespace "\"mcp-demo-$nonce\""
set_key "$work/relay.toml" device_tls_cert_chain "\"$work/relay-cert-chain.pem\""
set_key "$work/relay.toml" device_tls_private_key "\"$work/relay-key.pem\""
set_key "$work/relay.toml" device_tls_client_ca "\"$work/device-ca.pem\""
set_key "$work/relay.toml" consumer_tls_cert_chain "\"$work/relay-cert-chain.pem\""
set_key "$work/relay.toml" consumer_tls_private_key "\"$work/relay-key.pem\""
set_key "$work/relay.toml" boot_id "\"mcp-demo-boot-$nonce\""
set_key "$work/relay.toml" deployment_incarnation "\"mcp-demo-$nonce\""
{
  printf 'redis_tls_root_ca_path = "%s"\n' "$work/server-ca.pem"
  cat "$work/relay.toml"
  printf '\n[http_forward]\nprofiles = ["%s"]\npublic_url = "https://localhost:%s"\n' "$profile" "$consumer_port"
} > "$work/relay.toml.new"
mv "$work/relay.toml.new" "$work/relay.toml"

# 8. Provision the catalog (the Redis container may still be starting).
say "first incarnation and catalog records (tunnel-relay activate-first-incarnation, provision-catalog)"
attempt=0
until "$bin/tunnel-relay" activate-first-incarnation --config "$work/relay.toml" >"$work/activate.log" 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 40 ]; then cat "$work/activate.log" >&2; exit 1; fi
  sleep 0.25
done
"$bin/tunnel-relay" provision-catalog --config "$work/relay.toml" --records "$work/device/catalog.toml" >/dev/null

# 9. Serve, then connect the device.
say "start the relay (tunnel-relay serve) on https://localhost:$consumer_port"
RUST_LOG=${RUST_LOG:-warn} "$bin/tunnel-relay" serve --config "$work/relay.toml" >"$work/relay.log" 2>&1 &
relay_pid=$!
attempt=0
until grep -q '^tunnel-relay listening' "$work/relay.log"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 120 ] || ! kill -0 "$relay_pid" 2>/dev/null; then cat "$work/relay.log" >&2; exit 1; fi
  sleep 0.25
done
say "connect the device (tunnel-client connect)"
RUST_LOG=${RUST_LOG:-warn} "$bin/tunnel-client" connect --config "$work/device/client.toml" >"$work/connect.log" 2>&1 &
device_pid=$!
attempt=0
until grep -q '^Connected:' "$work/connect.log"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 120 ] || ! kill -0 "$device_pid" 2>/dev/null; then cat "$work/connect.log" >&2; exit 1; fi
  sleep 0.25
done

# 10. A consumer token from the synthetic issuer: scope http:invoke, one hour.
now=$(date +%s)
header=$(printf '{"alg":"RS256","kid":"demo-issuer","typ":"JWT"}' | b64url)
payload=$(printf '{"iss":"%s","aud":"%s","sub":"%s","iat":%s,"exp":%s,"scope":"http:invoke"}' \
  "$issuer" "$audience" "$subject" "$now" "$((now + 3600))" | b64url)
signature=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$work/issuer-key.pem" | b64url)
printf '%s.%s.%s' "$header" "$payload" "$signature" > "$work/consumer-token"
chmod 600 "$work/consumer-token"

url="https://localhost:$consumer_port/v1/devices/$device_id/services/$service_id/http/mcp"
say "MCP endpoint: $url"
say "run the MCP client (tunnel-test-harness mcp-demo-client, rmcp 3.4.0)"
AGENTUPLINK_TOKEN=$(cat "$work/consumer-token") "$bin/tunnel-test-harness" mcp-demo-client \
  --url "$url" --ca "$work/server-ca.pem" --profile "$client_profile"
say "ok: the device's MCP server answered a real MCP client through the relay"
if [ "${DEMO_KEEP:-0}" = 1 ]; then
  say "endpoint:     $url"
  say "server CA:    $work/server-ca.pem"
  say "bearer token: $work/consumer-token (valid one hour, scope http:invoke)"
fi
