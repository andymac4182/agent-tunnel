#!/usr/bin/env bash
# Local proof of the Fly.io deployment (docs/deploy-fly.md, task row M6-C60).
#
#   TUNNEL_CLIENT=/path/to/tunnel-client deploy/fly/local-proof.sh
#
# Runs the two images from deploy/fly with Docker, as close to the Fly topology
# as one machine allows:
#   - Redis is TLS-only with a password and AOF on a volume, reachable only on
#     a private network under the name agentuplink-redis.internal;
#   - the relay's two listeners are published as plain TCP ports, so TLS
#     passes through to the relay exactly as a Fly service with no handlers;
#   - every secret reaches the containers as an environment variable, as
#     `fly secrets import` delivers it;
#   - provisioning runs in one-off containers of the relay image with the
#     records copied in, as `fly machine run --rm --file-local` does.
# A real tunnel-client on the host connects with a device certificate and a
# consumer request is echoed through it. Then `docker stop` must end the relay
# with its orderly SIGTERM path (exit 0), not a kill.
#
# Every key and certificate is generated at run time in a temporary directory
# outside the repository and deleted on exit; the containers, network and
# volume are removed on exit too. Each check prints `ok <name>` or exits 1.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
client=${TUNNEL_CLIENT:?set TUNNEL_CLIENT to a host tunnel-client binary}
# Free loopback ports, unless given: other local relays often hold the usual ones.
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
consumer_port=${CONSUMER_PORT:-$(free_port)}
device_port=${DEVICE_PORT:-$(free_port)}
relay_image=${RELAY_IMAGE:-agentuplink-relay:m6c60}
redis_image=${REDIS_IMAGE:-agentuplink-redis:m6c60}
nonce="m6c60-proof-$(date -u +%Y%m%dT%H%M%SZ)-$$"
echo "nonce=$nonce head=$(git -C "$repo" rev-parse --short HEAD) uncommitted_paths=$(git -C "$repo" status --porcelain | wc -l | tr -d ' ')"

work=$(mktemp -d "${TMPDIR:-/tmp}/m6c60-proof.XXXXXX")
case "$work/" in "$repo"/*) echo "refusing: key directory $work is inside the repository" >&2; exit 1 ;; esac
prefix="m6c60-$$"
net=$prefix-net
volume=$prefix-redis-data
redis=$prefix-redis
relay=$prefix-relay
client_pid=""

cleanup() {
  status=$?
  [ -n "$client_pid" ] && kill "$client_pid" 2>/dev/null || true
  docker rm -f "$relay" "$redis" "$prefix-provision" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$work"
  echo "cleanup: removed containers, network $net, volume $volume and key directory (exit=$status)"
}
trap cleanup EXIT

ok() { echo "ok $*"; }
fail() { echo "FAILED $*" >&2; exit 1; }
b64() { base64 < "$1" | tr -d '\n'; }
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }

echo "== images"
# PROOF_SKIP_BUILD=1 runs images built elsewhere (RELAY_IMAGE, REDIS_IMAGE),
# for example a deliberately broken one, to show a check can go red.
if [ "${PROOF_SKIP_BUILD:-0}" != 1 ]; then
  docker build -q -f "$repo/deploy/fly/relay/Dockerfile" -t "$relay_image" "$repo" >/dev/null
  docker build -q -t "$redis_image" "$repo/deploy/fly/redis" >/dev/null
fi
docker image inspect "$relay_image" "$redis_image" --format '{{.RepoTags}} {{.Id}} {{.Architecture}} user={{.Config.User}}'

echo "== keys (generated now, in $work)"
pki=$work/pki
mkdir -m 700 "$pki"
ca() {
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$2" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$pki/$1-key.pem" -out "$pki/$1.pem" 2>/dev/null
}
server_cert() { # name ca san
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$1" \
    -keyout "$pki/$1-key.pem" -out "$pki/$1.csr" 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" > "$pki/$1.ext"
  openssl x509 -req -in "$pki/$1.csr" -CA "$pki/$2.pem" -CAkey "$pki/$2-key.pem" \
    -CAcreateserial -days 1 -extfile "$pki/$1.ext" -out "$pki/$1.pem" 2>/dev/null
}
ca relay-ca "Synthetic relay server CA $nonce"
ca device-ca "Synthetic device CA $nonce"
ca redis-ca "Synthetic Redis CA $nonce"
server_cert device-server relay-ca "IP:127.0.0.1,DNS:localhost,DNS:agentuplink-relay.fly.dev"
server_cert consumer-server relay-ca "IP:127.0.0.1,DNS:localhost,DNS:agentuplink-relay.fly.dev"
server_cert redis-server redis-ca "DNS:agentuplink-redis.internal"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$pki/oidc-key.pem" 2>/dev/null
modulus=$(openssl rsa -noout -modulus -in "$pki/oidc-key.pem" | sed 's/^Modulus=//')
n=$(printf '%s' "$modulus" | xxd -r -p | b64url)
printf '{"keys":[{"kid":"m6c60-issuer","kty":"RSA","alg":"RS256","n":"%s","e":"AQAB"}]}' "$n" > "$pki/oidc-jwks.json"
redis_password=$(openssl rand -hex 24)
ok "generated 3 CAs, 3 server certificates, an issuer key and a ${#redis_password}-character Redis password"

# The env files are what `fly secrets import` reads: NAME=VALUE per line.
umask 077
cat > "$work/redis.env" <<EOF
REDIS_TLS_CERT_CHAIN_B64=$(b64 "$pki/redis-server.pem")
REDIS_TLS_KEY_B64=$(b64 "$pki/redis-server-key.pem")
REDIS_PASSWORD=$redis_password
EOF
cat > "$work/relay.env" <<EOF
AT_REDIS_URL=$(printf '%s://:%s@%s' rediss "$redis_password" agentuplink-redis.internal:6379/0)
AT_REDIS_CA_B64=$(b64 "$pki/redis-ca.pem")
AT_DEVICE_TLS_CERT_CHAIN_B64=$(b64 "$pki/device-server.pem")
AT_DEVICE_TLS_KEY_B64=$(b64 "$pki/device-server-key.pem")
AT_DEVICE_CLIENT_CA_B64=$(b64 "$pki/device-ca.pem")
AT_CONSUMER_TLS_CERT_CHAIN_B64=$(b64 "$pki/consumer-server.pem")
AT_CONSUMER_TLS_KEY_B64=$(b64 "$pki/consumer-server-key.pem")
AT_OIDC_JWKS_B64=$(b64 "$pki/oidc-jwks.json")
EOF
umask 022

echo "== no generated secret is in either image"
for key in redis-server-key device-server-key consumer-server-key; do
  needle=$(sed -n 2p "$pki/$key.pem")
  hits=$(docker save "$relay_image" "$redis_image" | grep -c -a -F -- "$needle" || true)
  [ "$hits" = 0 ] || fail "a line of $key.pem is in an image"
done
hits=$(docker save "$relay_image" "$redis_image" | grep -c -a -F -- "$redis_password" || true)
[ "$hits" = 0 ] || fail "the Redis password is in an image"
ok "no key line and no password in the saved images (the check greps the same bytes the containers receive)"

echo "== Redis: private network, TLS only, password, AOF on a volume"
docker network create "$net" >/dev/null
docker volume create "$volume" >/dev/null
docker run -d --name "$redis" --network "$net" --network-alias agentuplink-redis.internal \
  --env-file "$work/redis.env" -v "$volume:/data" "$redis_image" >/dev/null
for _ in $(seq 1 50); do
  docker logs "$redis" 2>&1 | grep -q "Ready to accept connections tls" && break
  sleep 0.2
done
docker logs "$redis" 2>&1 | grep -q "Ready to accept connections tls" || { docker logs "$redis"; fail "redis did not start"; }
ok "redis listening with TLS"
redis_cli() {
  docker exec "$redis" redis-cli --tls --insecure -h 127.0.0.1 -p 6379 "$@" 2>&1
}
# With the password, read from the container's own config into REDISCLI_AUTH.
redis_authed() {
  docker exec "$redis" sh -c 'REDISCLI_AUTH=$(sed -n "s/^requirepass //p" /run/agentuplink-redis/redis.conf) exec redis-cli --tls --insecure "$@"' sh "$@"
}
[ "$(redis_cli PING)" = "NOAUTH Authentication required." ] || fail "redis answered without the password"
ok "redis refuses a client without the password"
plain=$(docker exec "$redis" redis-cli -h 127.0.0.1 -p 6379 PING 2>&1 || true)
case "$plain" in PONG) fail "redis answered in plaintext" ;; esac
ok "redis has no plaintext port ($plain)"
for pair in appendonly:yes appendfsync:always aof-load-truncated:no maxmemory-policy:noeviction port:0 tls-port:6379; do
  got=$(redis_authed CONFIG GET "${pair%%:*}" | sed -n 2p | tr -d '\r')
  [ "$got" = "${pair#*:}" ] || fail "redis ${pair%%:*} is '$got', not '${pair#*:}'"
done
ok "redis durability and listener settings: appendonly yes, appendfsync always, aof-load-truncated no, maxmemory-policy noeviction, port 0, tls-port 6379"
run_id_1=$(redis_authed INFO server | sed -n 's/^run_id://p' | tr -d '\r')
echo "redis run_id=$run_id_1"

echo "== provisioning in one-off relay containers (fly machine run --rm)"
dev=$(uuidgen | tr 'A-Z' 'a-z')
tenant=$(uuidgen | tr 'A-Z' 'a-z')
user=$(uuidgen | tr 'A-Z' 'a-z')
svc=$(uuidgen | tr 'A-Z' 'a-z')
canary="m6c60-canary-$nonce"
device_dir=$work/device
mkdir -p "$device_dir"
cat > "$device_dir/client.toml" <<EOF
device_id = "$dev"
relay_url = "wss://127.0.0.1:$device_port/v1/tunnel/control"

[credentials]
client_certificate = "credentials/device-cert-chain.pem"
client_key = "credentials/device-key.pem"
server_ca = "credentials/relay-ca.pem"

[exports."$svc"]
type = "echo"
device_canary = "$canary"

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
"$client" credentials create --config "$device_dir/client.toml" --csr-out device.csr
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:%s\n' "$dev" > "$pki/device.ext"
openssl x509 -req -in "$device_dir/device.csr" -CA "$pki/device-ca.pem" -CAkey "$pki/device-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "$pki/device.ext" -out "$device_dir/device-cert.pem" 2>/dev/null
"$client" credentials import --config "$device_dir/client.toml" --certificate device-cert.pem --server-ca "$pki/relay-ca.pem"
"$client" doctor --config "$device_dir/client.toml" --json | grep -q '"ok":true' || fail "doctor"
ok "device key created on the host, certificate issued with the device role SAN, imported"

provision=$work/provision
mkdir -p "$provision"
cp "$device_dir/device-cert.pem" "$provision/device-cert.pem"
cat > "$provision/catalog.toml" <<EOF
[tenant]
id = "$tenant"
display_name = "M6-C60 proof tenant"

[user]
id = "$user"
display_name = "M6-C60 proof user"
oidc_subject = "m6c60-user"
role = "member"

[device]
id = "$dev"
display_name = "M6-C60 proof device"
certificate = "device-cert.pem"

[service]
id = "$svc"
type = "echo"
display_name = "M6-C60 proof echo"
operations = ["echo:invoke"]

[grant]
operations = ["echo:invoke"]
EOF
chmod 644 "$provision"/*
one_off() { # args passed to the entrypoint
  docker create --name "$prefix-provision" --network "$net" --env-file "$work/relay.env" "$relay_image" "$@" >/dev/null
  docker cp "$provision/." "$prefix-provision:/tmp/provision" >/dev/null
  set +e
  docker start -a "$prefix-provision" 2>&1
  code=$?
  set -e
  docker rm "$prefix-provision" >/dev/null
  return $code
}
out=$(one_off check-serve-config) || fail "check-serve-config: $out"
echo "$out"
out=$(one_off activate-first-incarnation) || fail "activate: $out"
echo "$out"
case "$out" in "Activated deployment incarnation fly-1 as the first incarnation of namespace agentuplink-fly-1"*) ;; *) fail "activate output" ;; esac
out=$(one_off provision-catalog /tmp/provision/catalog.toml) || fail "provision: $out"
echo "$out"
case "$out" in "Provisioned namespace agentuplink-fly-1"*) ;; *) fail "provision output" ;; esac
ok "activated and provisioned through the image's entrypoint"

echo "== relay: both listeners published as plain TCP (passthrough)"
start_relay() {
  docker run -d --name "$relay" --network "$net" --env-file "$work/relay.env" \
    -p "127.0.0.1:$consumer_port:8443" -p "127.0.0.1:$device_port:9443" "$relay_image" >/dev/null
}
readyz() { curl -sS --max-time 3 --cacert "$pki/relay-ca.pem" "https://127.0.0.1:$consumer_port/readyz" 2>/dev/null || true; }
wait_ready() {
  for _ in $(seq 1 100); do
    [ "$(readyz)" = '{"status":"ready"}' ] && return 0
    sleep 0.2
  done
  docker logs "$relay" 2>&1 | tail -20
  return 1
}
start_relay
wait_ready || fail "relay never answered ready"
ok "/readyz through the published consumer port: $(readyz)"
pid1=$(docker exec "$relay" sh -c 'sed -n "s/^Name:\t//p;s/^Uid:\t//p" /proc/1/status | tr "\t\n" "  "')
echo "container PID 1: $pid1"
case "$pid1" in "tunnel-relay 10001 "*) ;; *) fail "PID 1 is not tunnel-relay as uid 10001" ;; esac
leaked=$(docker exec "$relay" sh -c 'tr "\0" "\n" < /proc/1/environ | grep -c "^AT_" || true')
[ "$leaked" = 0 ] || fail "the relay process still has $leaked AT_ variables"
ok "tunnel-relay is PID 1 as uid 10001 and holds no AT_ secret variable in its environment"

# TLS 1.3 reports a missing client certificate after the handshake, on the
# first read, so send one byte and print what the server said.
noauth=$(printf 'x' | openssl s_client -connect "127.0.0.1:$device_port" -servername localhost \
  -CAfile "$pki/relay-ca.pem" -quiet 2>&1 | grep -i -E "alert|error" | head -2 | tr '\n' ' ' || true)
echo "device listener without a client certificate: ${noauth:-no alert text}"
case "$noauth" in *"certificate required"*) ok "the device listener refuses a TLS client with no certificate" ;; *) fail "device listener accepted a client with no certificate" ;; esac
lines_before=$(docker logs "$relay" 2>&1 | wc -l | tr -d ' ')
nc -z 127.0.0.1 "$device_port"
nc -z 127.0.0.1 "$consumer_port"
sleep 1
lines_after=$(docker logs "$relay" 2>&1 | wc -l | tr -d ' ')
echo "log lines added by two bare TCP connects (what a tcp_check does): $((lines_after - lines_before))"

echo "== device connects from the host with its certificate"
"$client" connect --config "$device_dir/client.toml" --json > "$work/connect.log" 2> "$work/connect.err" &
client_pid=$!
now=$(date +%s)
header=$(printf '{"alg":"RS256","kid":"m6c60-issuer","typ":"JWT"}' | b64url)
claims=$(printf '{"iss":"https://issuer.example.test/","aud":"agent-tunnel","sub":"m6c60-user","iat":%s,"exp":%s,"scope":"echo:invoke"}' "$now" "$((now + 300))" | b64url)
signature=$(printf '%s.%s' "$header" "$claims" | openssl dgst -sha256 -sign "$pki/oidc-key.pem" -binary | b64url)
token="$header.$claims.$signature"
payload="m6c60-payload-$nonce"
echo_once() {
  curl -sS --max-time 10 --cacert "$pki/relay-ca.pem" -o "$work/echo.body" -w '%{http_code}' \
    -H "Authorization: Bearer $token" --data-binary "$payload" \
    "https://127.0.0.1:$consumer_port/v1/devices/$dev/services/$svc/echo" 2>/dev/null || true
}
code=""
for _ in $(seq 1 60); do
  code=$(echo_once)
  [ "$code" = 200 ] && break
  sleep 0.5
done
[ "$code" = 200 ] || { cat "$work/connect.log" "$work/connect.err"; fail "echo returned HTTP $code"; }
body=$(cat "$work/echo.body")
[ "$body" = "$canary$payload" ] || fail "echo body '$body'"
ok "consumer HTTPS -> relay -> device mTLS WebSocket -> echo: HTTP 200, body = canary + payload ($body)"
docker stats --no-stream --format '{{.Name}} mem={{.MemUsage}}' "$relay" "$redis"

echo "== docker stop sends SIGTERM; the relay must drain and exit 0"
ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
start=$(ms)
docker stop -t 60 "$relay" >/dev/null
elapsed=$(( $(ms) - start ))
state=$(docker inspect -f 'exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' "$relay")
docker logs "$relay" 2>&1 | grep -E "tunnel-relay (stopping|stopped)" || true
echo "relay after docker stop: $state after ${elapsed} ms (docker would kill at 60 s)"
[ "$state" = "exit=0 oom=false" ] || fail "relay did not exit 0 on SIGTERM"
docker logs "$relay" 2>&1 | grep -q "tunnel-relay stopped: signal=SIGTERM" || fail "no orderly stop line"
ok "orderly SIGTERM stop, exit 0, in ${elapsed} ms with one device connected"
set +e
wait "$client_pid"
client_exit=$?
set -e
client_pid=""
echo "device after the relay stopped: exit=$client_exit last=$(tail -1 "$work/connect.log")"

echo "== relay restart on the same Redis serves again"
docker rm "$relay" >/dev/null
start_relay
wait_ready || fail "restarted relay never answered ready"
"$client" connect --config "$device_dir/client.toml" --json > "$work/connect2.log" 2> "$work/connect2.err" &
client_pid=$!
code=""
for _ in $(seq 1 60); do
  code=$(echo_once)
  [ "$code" = 200 ] && break
  sleep 0.5
done
[ "$code" = 200 ] || fail "echo after relay restart returned HTTP $code"
ok "restarted relay admitted the device again and echoed"
echo "== Redis stop, then a Redis restart, as a Fly host migration or redeploy would"
docker stop -t 30 "$redis" >/dev/null
echo "redis after docker stop: $(docker inspect -f 'exit={{.State.ExitCode}}' "$redis")"
docker logs "$redis" 2>&1 | grep -E "Received SIGTERM|ready to exit" || true
sleep 2
echo "running relay while Redis is down: readyz=$(readyz) echo=HTTP $(echo_once)"
docker start "$redis" >/dev/null
for _ in $(seq 1 50); do
  docker logs "$redis" 2>&1 | grep -c "Ready to accept connections tls" | grep -q 2 && break
  sleep 0.2
done
run_id_2=$(redis_authed INFO server | sed -n 's/^run_id://p' | tr -d '\r')
keys=$(redis_authed DBSIZE)
echo "redis restarted: run_id=$run_id_2 (was $run_id_1), keys kept by AOF=$keys"
sleep 3
echo "running relay after the Redis restart: readyz=$(readyz) echo=HTTP $(echo_once) body=$(head -c 200 "$work/echo.body")"
if kill -0 "$client_pid" 2>/dev/null; then
  kill -TERM "$client_pid"
  echo "device was still running after the Redis restart; sent it SIGTERM"
fi
set +e
wait "$client_pid"
client_exit=$?
set -e
client_pid=""
echo "device: exit=$client_exit last=$(tail -1 "$work/connect2.log")"
docker stop -t 60 "$relay" >/dev/null
docker rm "$relay" >/dev/null
start_relay
sleep 5
echo "a fresh relay on the restarted Redis: $(docker inspect -f 'running={{.State.Running}} exit={{.State.ExitCode}}' "$relay")"
docker logs "$relay" 2>&1 | grep -v '^{' | tail -3
echo "proof complete nonce=$nonce"
