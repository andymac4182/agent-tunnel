#!/usr/bin/env bash
# The four-adapter demo (docs/demo/adapters.md, task rows M4-63 to M4-69).
#
#   scripts/adapters-demo.sh
#
# One local relay, one device exporting a synthetic directory with a
# read/write/list/delete grant, and one consumer that lends a single shared
# client to all four native adapters -- always through the relay:
#
#   packages/client/demo/adapters-demo.ts (node)
#       --HTTPS+WSS, bearer token--> tunnel-relay serve
#       --mTLS WebSocket--> tunnel-client connect --> the exported directory
#
# The relay, PKI, Redis and enrolment steps are the same as scripts/fs-demo.sh
# (the M4-54 filesystem demo); what differs is the grant (read, write, list,
# delete), the export layout, and the consumer, which drives Files SDK,
# just-bash, a Mastra Agent and the AI SDK tool loop. The two agents use a
# scripted model from ai/test: no LLM, no API key, no network beyond loopback.
#
# Every check prints `ok <name>` or `FAILED <name>`; the script exits 1 on the
# first failed check. DEMO_NEGATIVE_CONTROL=1 changes one host file after the
# consumer read it, so the checksum checks must fail -- proof they can go red.
#
# Needs: cargo, node >= 24, npm, openssl, python3, curl, and docker (unless
# DEMO_REDIS_URL is given). Synthetic data only. DEMO_KEEP=1 keeps the work
# directory; DEMO_BIN_DIR reuses prebuilt tunnel-relay/tunnel-client.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
nonce="adapters-demo-$(date -u +%Y%m%dT%H%M%SZ)-$$"
echo "adapters-demo nonce=$nonce head=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown) uncommitted_paths=$(git -C "$repo" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"

ok() { echo "ok $*"; }
fail() { echo "FAILED $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "prerequisite: '$1' is not on PATH"; }
for tool in node npm openssl python3 curl; do need "$tool"; done
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }

work=$(mktemp -d "${TMPDIR:-/tmp}/adapters-demo.XXXXXX")
work=$(cd "$work" && pwd -P)
case "$work/" in "$repo"/*) fail "refusing: work directory $work is inside the repository" ;; esac
relay_pid=""
client_pid=""
redis_container=""
cleanup() {
  status=$?
  [ -n "$client_pid" ] && kill "$client_pid" 2>/dev/null && wait "$client_pid" 2>/dev/null || true
  [ -n "$relay_pid" ] && kill "$relay_pid" 2>/dev/null && wait "$relay_pid" 2>/dev/null || true
  [ -n "$redis_container" ] && docker rm -f "$redis_container" >/dev/null 2>&1 || true
  if [ "${DEMO_KEEP:-0}" = 1 ]; then
    echo "cleanup: kept $work (DEMO_KEEP=1); stopped relay, device and Redis (exit=$status)"
  else
    rm -rf "$work"
    echo "cleanup: stopped relay, device and Redis; removed $work (exit=$status)"
  fi
}
trap cleanup EXIT

echo "== binaries"
if [ -n "${DEMO_BIN_DIR:-}" ]; then
  bin=$DEMO_BIN_DIR
else
  echo "building tunnel-relay and tunnel-client (cargo build --locked)"
  (cd "$repo" && cargo build --locked -q -p tunnel-relay -p tunnel-client --bins)
  bin=${CARGO_TARGET_DIR:-$repo/target}/debug
fi
relay=$bin/tunnel-relay
client=$bin/tunnel-client
[ -x "$relay" ] && [ -x "$client" ] || fail "no tunnel-relay/tunnel-client in $bin"
ok "binaries: $relay, $client"
if [ ! -d "$repo/packages/client/node_modules/just-bash" ] || [ ! -d "$repo/packages/client/node_modules/@mastra/core" ] || [ ! -d "$repo/packages/client/node_modules/files-sdk" ] || [ ! -d "$repo/packages/client/node_modules/ai" ]; then
  echo "installing the client's pinned dev dependencies (npm ci)"
  (cd "$repo/packages/client" && npm ci --silent)
fi
ok "packages/client dependencies present (files-sdk, just-bash, @mastra/core, ai)"

echo "== keys and certificates (generated now, in $work/pki)"
pki=$work/pki
mkdir -m 700 "$pki"
ca() { # NAME CN
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$2" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$pki/$1-key.pem" -out "$pki/$1.pem" 2>/dev/null
}
server_cert() { # NAME CA
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$1" \
    -keyout "$pki/$1-key.pem" -out "$pki/$1.csr" 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n' > "$pki/$1.ext"
  openssl x509 -req -in "$pki/$1.csr" -CA "$pki/$2.pem" -CAkey "$pki/$2-key.pem" \
    -CAcreateserial -days 1 -extfile "$pki/$1.ext" -out "$pki/$1-leaf.pem" 2>/dev/null
  cat "$pki/$1-leaf.pem" "$pki/$2.pem" > "$pki/$1.pem"
}
ca relay-ca "Synthetic relay CA $nonce"
ca device-ca "Synthetic device CA $nonce"
server_cert relay relay-ca
issuer="https://issuer.adapters-demo.invalid/"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$pki/oidc-key.pem" 2>/dev/null
modulus=$(openssl rsa -noout -modulus -in "$pki/oidc-key.pem" | sed 's/^Modulus=//')
n=$(printf '%s' "$modulus" | python3 -c 'import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))' | b64url)
printf '{"keys":[{"kid":"adapters-demo-issuer","kty":"RSA","alg":"RS256","n":"%s","e":"AQAB"}]}' "$n" > "$pki/oidc-jwks.json"
ok "relay CA and listener certificate (127.0.0.1, localhost), device CA, issuer key and JWKS"

echo "== Redis (TLS only)"
if [ -n "${DEMO_REDIS_URL:-}" ]; then
  redis_url=$DEMO_REDIS_URL
  redis_ca=${DEMO_REDIS_CA:?DEMO_REDIS_CA must name the CA of DEMO_REDIS_URL}
  ok "using DEMO_REDIS_URL (its CA from DEMO_REDIS_CA)"
else
  need docker
  redis_port=$(free_port)
  redis_container="adapters-demo-redis-$$"
  mkdir "$pki/redis"
  cp "$pki/relay.pem" "$pki/redis/chain.pem"
  cp "$pki/relay-key.pem" "$pki/redis/key.pem"
  # Synthetic, run-scoped key: readable by the image's redis user.
  chmod 644 "$pki/redis/chain.pem" "$pki/redis/key.pem"
  docker create --name "$redis_container" -p "127.0.0.1:$redis_port:6379" \
    "${DEMO_REDIS_IMAGE:-redis:8.4.0-alpine}" redis-server --port 0 --tls-port 6379 \
    --tls-cert-file /tls/chain.pem --tls-key-file /tls/key.pem --tls-auth-clients no \
    --appendonly yes --appendfsync always >/dev/null
  docker cp "$pki/redis/." "$redis_container:/tls" >/dev/null
  docker start "$redis_container" >/dev/null
  for _ in $(seq 1 50); do
    docker logs "$redis_container" 2>&1 | grep -q "Ready to accept connections tls" && break
    sleep 0.2
  done
  docker logs "$redis_container" 2>&1 | grep -q "Ready to accept connections tls" \
    || { docker logs "$redis_container"; fail "Redis did not start"; }
  redis_url="rediss://localhost:$redis_port/0"
  redis_ca=$pki/relay-ca.pem
  ok "disposable Redis container $redis_container, TLS only, on 127.0.0.1:$redis_port"
fi

echo "== the synthetic export (the device's directory)"
export_root=$work/device/export
mkdir -p "$export_root/docs/guide" "$export_root/data" "$export_root/outbox" "$export_root/uploads"
cat > "$export_root/README.md" <<EOF
# Synthetic adapter demo export

Generated by scripts/adapters-demo.sh for run $nonce. Nothing here is real data.
EOF
printf 'line one\nline two\nline three\n' > "$export_root/docs/notes.txt"
printf '# Chapter 1\n\nSynthetic text.\n' > "$export_root/docs/guide/chapter-1.md"
python3 - "$export_root/data/numbers.csv" <<'PY'
import sys
with open(sys.argv[1], "w") as f:
    f.write("n,square,cube\n")
    for n in range(1, 501):
        f.write(f"{n},{n*n},{n*n*n}\n")
PY
# 200 KiB of deterministic bytes (byte i = i % 251): several full-msize reads.
python3 -c 'import sys; sys.stdout.buffer.write(bytes(i % 251 for i in range(204800)))' > "$export_root/data/blob.bin"
seed_files=$(cd "$export_root" && find . -type f | sed 's#^\.##' | LC_ALL=C sort)
ok "export root with $(echo "$seed_files" | wc -l | tr -d ' ') files; empty /outbox and /uploads for the writes"

printf "%s\n" "$seed_files" > "$work/seed-files.txt"

echo "== device enrolment (tunnel-client credentials create / import)"
tenant=$(uuid); user=$(uuid); device=$(uuid); service=$(uuid)
case "$(uname -s)" in Darwin) case_sensitivity="insensitive-preserving" ;; *) case_sensitivity="sensitive" ;; esac
cat > "$work/device/client.toml" <<EOF
device_id = "$device"
relay_url = "wss://127.0.0.1:DEVICE_PORT/v1/tunnel/control"

[credentials]
client_certificate = "credentials/device-cert-chain.pem"
client_key = "credentials/device-key.pem"
server_ca = "credentials/relay-ca.pem"

[exports."$service"]
type = "fs"

[exports."$service".fs]
root = "$export_root"
capabilities = ["read", "write", "list", "delete"]

[limits]
max_streams = 64
max_queue_frames = 128
max_queue_bytes = 8388608
grant_timeout_ms = 5000
operation_timeout_ms = 30000

[rotation]
interval_seconds = 300
handshake_timeout_seconds = 10
overlap_seconds = 30
EOF
consumer_port=$(free_port)
device_port=$(free_port)
sed -i.bak "s/DEVICE_PORT/$device_port/" "$work/device/client.toml" && rm "$work/device/client.toml.bak"
"$client" credentials create --config "$work/device/client.toml" --csr-out device.csr
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:%s\n' "$device" > "$pki/device.ext"
openssl x509 -req -in "$work/device/device.csr" -CA "$pki/device-ca.pem" -CAkey "$pki/device-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "$pki/device.ext" -out "$work/device/device-cert.pem" 2>/dev/null
"$client" credentials import --config "$work/device/client.toml" --certificate device-cert.pem --server-ca "$pki/relay-ca.pem"
ok "device $device enrolled; its key never left $work/device"

echo "== relay configuration and catalog (tunnel-relay activate-first-incarnation / provision-catalog)"
namespace="adapters-demo-$$-$(date -u +%H%M%S)"
cat > "$work/relay.toml" <<EOF
redis_tls_root_ca_path = "$redis_ca"
consumer_bind = "127.0.0.1:$consumer_port"
device_bind = "127.0.0.1:$device_port"
oidc_issuer = "$issuer"
oidc_audience = ["agent-tunnel"]
oidc_jwks_path = "$pki/oidc-jwks.json"
redis_url = "$redis_url"
redis_namespace = "$namespace"
device_tls_cert_chain = "$pki/relay.pem"
device_tls_private_key = "$pki/relay-key.pem"
device_tls_client_ca = "$pki/device-ca.pem"
consumer_tls_cert_chain = "$pki/relay.pem"
consumer_tls_private_key = "$pki/relay-key.pem"
node_id = "relay-adapters-demo"
boot_id = "boot-$nonce"
deployment_incarnation = "$namespace"
max_devices_per_user = 16
max_queue_bytes = 4194304

[rotation]
interval_seconds = 300
handshake_timeout_seconds = 10
overlap_seconds = 30
EOF
cat > "$work/device/catalog.toml" <<EOF
[tenant]
id = "$tenant"
display_name = "Demo tenant"

[user]
id = "$user"
display_name = "Demo user"
oidc_subject = "adapters-demo-user"
role = "member"

[device]
id = "$device"
display_name = "Demo device"
certificate = "device-cert.pem"

[service]
id = "$service"
type = "fs"
display_name = "Demo files"
operations = ["fs:connect", "fs:read", "fs:list", "fs:write", "fs:delete"]
fs_case_sensitivity = "$case_sensitivity"

[grant]
operations = ["fs:connect", "fs:read", "fs:list", "fs:write", "fs:delete"]
EOF
"$relay" check-serve-config --config "$work/relay.toml" > /dev/null
"$relay" activate-first-incarnation --config "$work/relay.toml"
"$relay" provision-catalog --config "$work/relay.toml" --records "$work/device/catalog.toml"
ok "namespace $namespace: tenant, user, device, fs service and a read+write+list+delete grant"

echo "== serve and connect"
RUST_LOG=warn "$relay" serve --config "$work/relay.toml" > "$work/relay.log" 2>&1 &
relay_pid=$!
for _ in $(seq 1 100); do
  [ "$(curl -sS --max-time 2 --cacert "$pki/relay-ca.pem" "https://127.0.0.1:$consumer_port/readyz" 2>/dev/null || true)" = '{"status":"ready"}' ] && break
  kill -0 "$relay_pid" 2>/dev/null || { cat "$work/relay.log"; fail "relay exited before it was ready"; }
  sleep 0.2
done
ok "relay ready: consumer https://127.0.0.1:$consumer_port, device wss://127.0.0.1:$device_port"
"$client" connect --config "$work/device/client.toml" > "$work/device.log" 2>&1 &
client_pid=$!

mint_token() { # SUBJECT SCOPE
  now=$(date +%s)
  header=$(printf '{"alg":"RS256","kid":"adapters-demo-issuer","typ":"JWT"}' | b64url)
  claims=$(printf '{"iss":"%s","aud":"agent-tunnel","sub":"%s","iat":%s,"exp":%s,"scope":"%s"}' "$issuer" "$1" "$now" "$((now + 900))" "$2" | b64url)
  signature=$(printf '%s.%s' "$header" "$claims" | openssl dgst -sha256 -sign "$pki/oidc-key.pem" -binary | b64url)
  printf '%s.%s.%s' "$header" "$claims" "$signature"
}
umask 077
mint_token adapters-demo-user fs:connect > "$work/consumer.token"
mint_token adapters-demo-stranger fs:connect > "$work/stranger.token"
umask 022
endpoint="https://127.0.0.1:$consumer_port/v1/devices/$device/services/$service/fs"
descriptor() { # TOKEN_FILE -> HTTP status; body in $work/descriptor.json
  curl -sS --max-time 5 --cacert "$pki/relay-ca.pem" -o "$work/descriptor.json" -w '%{http_code}' \
    -H "Authorization: Bearer $(cat "$1")" "$endpoint" 2>/dev/null || true
}
online=""
status=""
for _ in $(seq 1 80); do
  kill -0 "$client_pid" 2>/dev/null || { cat "$work/device.log"; fail "tunnel-client exited"; }
  status=$(descriptor "$work/consumer.token")
  if [ "$status" = 200 ] && tr -d ' \n' < "$work/descriptor.json" | grep -q '"availability":"online"'; then
    online=yes
    break
  fi
  sleep 0.25
done
[ -n "$online" ] || { cat "$work/device.log" "$work/relay.log" "$work/descriptor.json"; fail "the export never came online (last descriptor HTTP $status)"; }
ok "device connected; descriptor GET $endpoint -> 200, availability online"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("descriptor: schema=%s root.readOnly=%s operations=%s" % (d.get("schemaVersion"), d["root"]["readOnly"], ",".join(sorted(d["operations"]))))' "$work/descriptor.json"
stranger=$(descriptor "$work/stranger.token")
[ "$stranger" = 401 ] || fail "an unprovisioned subject got HTTP $stranger, not 401"
ok "an unprovisioned subject is refused: HTTP $stranger"

echo "== consumer: packages/client/demo/adapters-demo.ts"
set +e
env -u NODE_TLS_REJECT_UNAUTHORIZED NODE_EXTRA_CA_CERTS="$pki/relay-ca.pem" \
  DEMO_ENDPOINT="$endpoint" DEMO_TOKEN_FILE="$work/consumer.token" \
  node "$repo/packages/client/demo/adapters-demo.ts" > "$work/consumer.out" 2> "$work/consumer.err"
consumer_status=$?
set -e
grep -v '^DEMO-RESULT ' "$work/consumer.out" || true
[ "$consumer_status" = 0 ] || { tail -40 "$work/consumer.err" >&2; fail "consumer exited $consumer_status"; }
grep '^DEMO-RESULT ' "$work/consumer.out" | sed 's/^DEMO-RESULT //' > "$work/result.json"
[ -s "$work/result.json" ] || fail "consumer printed no DEMO-RESULT line"

if [ "${DEMO_NEGATIVE_CONTROL:-0}" = 1 ]; then
  echo "negative control: appending one byte to the host's /data/blob.bin and /docs/notes.txt after the consumer read them"
  printf 'x' >> "$export_root/data/blob.bin"
  printf 'x' >> "$export_root/docs/notes.txt"
fi

echo
echo "== checks against the host directory"
checks=0
python3 "$repo/scripts/adapters-demo-check.py" "$work/result.json" "$export_root" "$work/seed-files.txt" || checks=$?
[ "$checks" = 0 ] || fail "consumer report disagrees with the host directory"
kill -0 "$client_pid" 2>/dev/null || fail "the device exited during the demo"
ok "device still connected after the consumer closed its session"
echo "adapters-demo: PASS nonce=$nonce"
