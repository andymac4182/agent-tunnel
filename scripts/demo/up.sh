#!/usr/bin/env bash
# Bring up the complete LOCAL demo on this Mac (task row M6-C127):
#
#   * a dedicated throwaway Redis container with TLS (never the shared one),
#   * a synthetic server CA, device CA and consumer-token issuer in the
#     gitignored state directory scripts/demo/.state/,
#   * `tunnel-relay serve` against that Redis, its namespace activated and
#     provisioned with the shipped commands (provision-catalog, add-service,
#     set-grant),
#   * one device (`tunnel-client connect`) exporting every feature plug-in in
#     scripts/demo/features/ that is marked ready, plus their backends.
#
# Idempotent: when the demo is already up and healthy it says so and exits 0;
# when it finds a partial or stale demo it tears it down first.
#
#   scripts/demo/up.sh            # local demo
#   scripts/demo/up.sh --remote   # opt-in: check the live Fly relay material
#   scripts/demo/up.sh --rebuild  # force a cargo build even if binaries exist
#
# Set DEMO_BIN_DIR to use prebuilt binaries (an unpacked release's bin/, for
# example) instead of building with cargo.
set -eu
. "$(dirname "$0")/lib/common.sh"

REBUILD=0
for arg in "$@"; do
  case $arg in
    --remote) DEMO_MODE=remote ;;
    --rebuild) REBUILD=1 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) demo_die "unknown argument $arg" ;;
  esac
done

started=$(demo_now_ms)

# ------------------------------------------------------------------ remote
if [ "$DEMO_MODE" = remote ]; then
  demo_say "remote mode: live relay $DEMO_REMOTE_URL (read-only use of $DEMO_REMOTE_DIR)"
  for f in oidc-key.pem relay-ca.pem; do
    [ -r "$DEMO_REMOTE_DIR/$f" ] || demo_die "remote material missing: $DEMO_REMOTE_DIR/$f"
    demo_ok "found $f (not printed)"
  done
  exec "$DEMO_DIR/status.sh" --remote
fi

# ------------------------------------------------------------------ already up?
if [ -f "$DEMO_STATE/ids.env" ] && "$DEMO_DIR/status.sh" --quiet >/dev/null 2>&1; then
  demo_say "the local demo is already up and healthy; nothing to do"
  "$DEMO_DIR/status.sh"
  exit 0
fi
if [ -d "$DEMO_STATE" ] || docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$DEMO_REDIS_CONTAINER"; then
  demo_say "found a partial or stale demo; tearing it down first"
  "$DEMO_DIR/down.sh"
fi

# ------------------------------------------------------------------ preflight
demo_say "pre-flight"
for cmd in docker openssl python3 curl nc uuidgen; do
  command -v "$cmd" >/dev/null 2>&1 || demo_die "missing required command: $cmd"
done
docker info >/dev/null 2>&1 || demo_die "docker is not running (start Docker Desktop)"
demo_guard_container
for port in "$DEMO_CONSUMER_PORT" "$DEMO_DEVICE_PORT" "$DEMO_REDIS_PORT" "$DEMO_WEB_PORT"; do
  demo_port_free "$port" || demo_die "port $port is in use; stop what holds it or set DEMO_*_PORT"
done
demo_ok "docker, openssl, python3 and curl present; ports $DEMO_CONSUMER_PORT $DEMO_DEVICE_PORT $DEMO_REDIS_PORT $DEMO_WEB_PORT free"

# Which plug-ins are ready, and what they need built.
ready_features=
packages="tunnel-relay tunnel-client tunnel-deadman"
for f in $(demo_feature_files); do
  (demo_load_feature "$f"; [ "$FEATURE_READY" = 1 ]) || continue
  name=$(demo_load_feature "$f"; printf '%s' "$FEATURE_NAME")
  extra=$(demo_load_feature "$f"; printf '%s' "$FEATURE_CARGO_PACKAGES")
  needs=$(demo_load_feature "$f"; printf '%s' "$FEATURE_REQUIRES")
  for cmd in $needs; do
    command -v "$cmd" >/dev/null 2>&1 || demo_die "feature $name needs $cmd on PATH"
  done
  ready_features="$ready_features $name"
  packages="$packages $extra"
done
[ -n "$ready_features" ] || demo_die "no feature plug-in is ready"
demo_ok "features:$ready_features"

# ------------------------------------------------------------------ binaries
need_build=$REBUILD
if [ -z "${DEMO_BIN_DIR:-}" ]; then
  for p in $packages; do [ -x "$(demo_bin "$p")" ] || need_build=1; done
  if [ "$need_build" = 1 ]; then
    demo_say "building$(printf ' %s' $packages) (cargo --locked; first build takes a few minutes)"
    set --
    for p in $packages; do set -- "$@" -p "$p"; done
    (cd "$REPO_ROOT" && cargo build --locked "$@" --bins) >"$DEMO_DIR/.build.log" 2>&1 ||
      { tail -20 "$DEMO_DIR/.build.log" >&2; demo_die "cargo build failed (full log: $DEMO_DIR/.build.log)"; }
    rm -f "$DEMO_DIR/.build.log"
  fi
fi
for p in $packages; do [ -x "$(demo_bin "$p")" ] || demo_die "missing binary $(demo_bin "$p")"; done
RELAY=$(demo_bin tunnel-relay)
CLIENT=$(demo_bin tunnel-client)
demo_ok "binaries: $(dirname "$RELAY")"

# ------------------------------------------------------------------ state + PKI
umask 077
mkdir -p "$DEMO_STATE" "$DEMO_LOGS" "$DEMO_PIDS" "$DEMO_PKI" "$DEMO_STATE/device" "$DEMO_STATE/catalog"
demo_say "generating synthetic PKI and issuer in $DEMO_STATE (gitignored)"
(
  cd "$DEMO_PKI"
  printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' >ca-ext.cnf
  for ca in server-ca device-ca; do
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=Agent Uplink demo $ca (synthetic)" \
      -keyout "$ca-key.pem" -out "$ca.csr" 2>/dev/null
    openssl x509 -req -in "$ca.csr" -signkey "$ca-key.pem" -days 2 -extfile ca-ext.cnf -out "$ca.pem" 2>/dev/null
  done
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' >server-ext.cnf
  for srv in relay redis; do
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout "$srv-key.pem" -out "$srv.csr" 2>/dev/null
    openssl x509 -req -in "$srv.csr" -CA server-ca.pem -CAkey server-ca-key.pem -CAcreateserial \
      -days 2 -extfile server-ext.cnf -out "$srv.pem" 2>/dev/null
  done
  # The Redis container runs as its own user; its synthetic key must be
  # readable there. It lives only in this throwaway state directory.
  mkdir -p redis-tls && cp redis.pem redis-key.pem server-ca.pem redis-tls/ && chmod 755 redis-tls && chmod 644 redis-tls/*
  # Consumer token issuer: an RSA key and the JWKS the relay reads.
  openssl genrsa -out oidc-key.pem 2048 2>/dev/null
  modulus=$(openssl rsa -in oidc-key.pem -noout -modulus 2>/dev/null | sed 's/^Modulus=//')
  python3 - "$modulus" "$DEMO_KID" >oidc-jwks.json <<'PY'
import base64, json, sys
n = bytes.fromhex(sys.argv[1])
b = lambda v: base64.urlsafe_b64encode(v).rstrip(b"=").decode()
print(json.dumps({"keys": [{"kty": "RSA", "kid": sys.argv[2], "alg": "RS256", "use": "sig",
                            "n": b(n), "e": b((65537).to_bytes(3, "big"))}]}))
PY
  rm -f ./*.csr
)
demo_ok "server CA, device CA, relay and Redis certificates, token issuer"

# ------------------------------------------------------------------ Redis
demo_say "starting throwaway Redis container $DEMO_REDIS_CONTAINER (TLS, 127.0.0.1:$DEMO_REDIS_PORT)"
rc=0
demo_timeout 120 docker run -d --name "$DEMO_REDIS_CONTAINER" --label agentuplink.demo=1 \
  -p "127.0.0.1:$DEMO_REDIS_PORT:6379" -v "$DEMO_PKI/redis-tls:/tls:ro" \
  "$DEMO_REDIS_IMAGE" redis-server --port 0 --tls-port 6379 \
  --tls-cert-file /tls/redis.pem --tls-key-file /tls/redis-key.pem \
  --tls-ca-cert-file /tls/server-ca.pem --tls-auth-clients no \
  --appendonly yes --appendfsync always --no-appendfsync-on-rewrite no >/dev/null || rc=$?
[ "$rc" = 0 ] || demo_die "docker run did not start $DEMO_REDIS_CONTAINER (status $rc; 124 = no answer in 120 s: Docker Desktop is overloaded or stuck, restart it), then run down.sh and up.sh"
i=0
until demo_redis_ping; do
  i=$((i + 1)); [ "$i" -lt 60 ] || demo_die "Redis did not answer PING over TLS on 127.0.0.1:$DEMO_REDIS_PORT in 30 s"
  sleep 0.5
done
demo_ok "Redis answers PING over TLS"

# ------------------------------------------------------------------ IDs
{
  printf 'DEMO_TENANT=%s\nDEMO_USER=%s\nDEMO_DEVICE=%s\n' "$(demo_uuid)" "$(demo_uuid)" "$(demo_uuid)"
  for name in $ready_features; do
    printf 'DEMO_SERVICE_%s=%s\n' "$(printf '%s' "$name" | tr '[:lower:]-' '[:upper:]_')" "$(demo_uuid)"
  done
  printf 'DEMO_FEATURES="%s"\n' "${ready_features# }"
} >"$DEMO_STATE/ids.env.tmp"
mv "$DEMO_STATE/ids.env.tmp" "$DEMO_STATE/ids.env.pending"
# shellcheck disable=SC1091
. "$DEMO_STATE/ids.env.pending"

# ------------------------------------------------------------------ relay config
profiles=
for name in $ready_features; do
  p=$(demo_load_feature "$(demo_feature_file "$name")"; feature_relay_profile)
  if [ -n "$p" ]; then
    case " $profiles " in *" \"$p\","*) ;; *) profiles="$profiles \"$p\"," ;; esac
  fi
done
cat >"$DEMO_STATE/relay.toml" <<EOF
# Generated by scripts/demo/up.sh. Synthetic demo relay; do not reuse.
consumer_bind = "127.0.0.1:$DEMO_CONSUMER_PORT"
device_bind = "127.0.0.1:$DEMO_DEVICE_PORT"
oidc_issuer = "$DEMO_ISSUER"
oidc_audience = ["$DEMO_AUDIENCE"]
oidc_jwks_path = "$DEMO_PKI/oidc-jwks.json"
redis_url = "rediss://localhost:$DEMO_REDIS_PORT/0"
redis_tls_root_ca_path = "$DEMO_PKI/server-ca.pem"
redis_namespace = "$DEMO_NAMESPACE"
device_tls_cert_chain = "$DEMO_PKI/relay.pem"
device_tls_private_key = "$DEMO_PKI/relay-key.pem"
device_tls_client_ca = "$DEMO_PKI/device-ca.pem"
consumer_tls_cert_chain = "$DEMO_PKI/relay.pem"
consumer_tls_private_key = "$DEMO_PKI/relay-key.pem"
node_id = "relay-demo-local"
deployment_incarnation = "$DEMO_INCARNATION"
max_devices_per_user = 16
max_queue_bytes = 4194304

[rotation]
interval_seconds = 300
handshake_timeout_seconds = 10
overlap_seconds = 30
EOF
if [ -n "$profiles" ]; then
  printf '\n[http_forward]\nprofiles = [%s]\n' "$(printf '%s' "$profiles" | sed 's/^ //; s/,$//')" >>"$DEMO_STATE/relay.toml"
fi
"$RELAY" check-serve-config --config "$DEMO_STATE/relay.toml" >"$DEMO_LOGS/check-serve-config.log" 2>&1 ||
  { cat "$DEMO_LOGS/check-serve-config.log" >&2; demo_die "relay configuration refused"; }
demo_ok "relay configuration valid (profiles:${profiles:- none})"

# ------------------------------------------------------------------ device credentials
demo_say "creating the device key and certificate (key never leaves $DEMO_STATE/device)"
DEVICE_DIR=$DEMO_STATE/device
{
  cat <<EOF
# Generated by scripts/demo/up.sh. Synthetic demo device.
device_id = "$DEMO_DEVICE"
relay_url = "wss://localhost:$DEMO_DEVICE_PORT/v1/tunnel/control"

[credentials]
client_certificate = "credentials/device-cert-chain.pem"
client_key = "credentials/device-key.pem"
server_ca = "credentials/relay-ca.pem"

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
  for name in $ready_features; do
    printf '\n'
    (demo_load_feature "$(demo_feature_file "$name")"; feature_export "$(demo_service_id "$name")")
  done
} >"$DEVICE_DIR/client.toml"
"$CLIENT" credentials create --config "$DEVICE_DIR/client.toml" --csr-out device.csr >"$DEMO_LOGS/credentials.log" 2>&1 ||
  { cat "$DEMO_LOGS/credentials.log" >&2; demo_die "credentials create failed"; }
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:%s\n' "$DEMO_DEVICE" >"$DEMO_PKI/device-ext.cnf"
openssl x509 -req -in "$DEVICE_DIR/device.csr" -CA "$DEMO_PKI/device-ca.pem" -CAkey "$DEMO_PKI/device-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "$DEMO_PKI/device-ext.cnf" -out "$DEVICE_DIR/device-cert.pem" 2>/dev/null
"$CLIENT" credentials import --config "$DEVICE_DIR/client.toml" --certificate device-cert.pem \
  --server-ca "$DEMO_PKI/server-ca.pem" >>"$DEMO_LOGS/credentials.log" 2>&1 ||
  { cat "$DEMO_LOGS/credentials.log" >&2; demo_die "credentials import failed"; }
"$CLIENT" doctor --config "$DEVICE_DIR/client.toml" --json >"$DEMO_LOGS/doctor.log" 2>&1 ||
  { cat "$DEMO_LOGS/doctor.log" >&2; demo_die "tunnel-client doctor failed"; }
demo_ok "device $DEMO_DEVICE: key, certificate and profile healthy (doctor ok)"

# ------------------------------------------------------------------ catalog
demo_say "activating the namespace and writing the catalog (shipped commands)"
"$RELAY" activate-first-incarnation --config "$DEMO_STATE/relay.toml" >"$DEMO_LOGS/catalog.log" 2>&1 ||
  { cat "$DEMO_LOGS/catalog.log" >&2; demo_die "activate-first-incarnation failed"; }
CAT=$DEMO_STATE/catalog
first=1
for name in $ready_features; do
  file=$(demo_feature_file "$name")
  sid=$(demo_service_id "$name")
  service=$(demo_load_feature "$file"; feature_service)
  grant=$(demo_load_feature "$file"; feature_grant_operations)
  if [ "$first" = 1 ]; then
    cat >"$CAT/records.toml" <<EOF
[tenant]
id = "$DEMO_TENANT"
display_name = "Demo tenant"

[user]
id = "$DEMO_USER"
display_name = "Demo presenter"
oidc_subject = "$DEMO_SUBJECT"
role = "member"

[device]
id = "$DEMO_DEVICE"
display_name = "Demo Mac"
certificate = "../device/device-cert.pem"

[service]
id = "$sid"
$service

[grant]
operations = $grant
EOF
    "$RELAY" provision-catalog --config "$DEMO_STATE/relay.toml" --records "$CAT/records.toml" >>"$DEMO_LOGS/catalog.log" 2>&1 ||
      { tail -5 "$DEMO_LOGS/catalog.log" >&2; demo_die "provision-catalog failed"; }
    first=0
  else
    printf '[service]\ntenant = "%s"\ndevice = "%s"\nid = "%s"\n%s\n' "$DEMO_TENANT" "$DEMO_DEVICE" "$sid" "$service" >"$CAT/service-$name.toml"
    printf '[grant]\ntenant = "%s"\nuser = "%s"\ndevice = "%s"\nservice = "%s"\noperations = %s\n' \
      "$DEMO_TENANT" "$DEMO_USER" "$DEMO_DEVICE" "$sid" "$grant" >"$CAT/grant-$name.toml"
    "$RELAY" add-service --config "$DEMO_STATE/relay.toml" --records "$CAT/service-$name.toml" >>"$DEMO_LOGS/catalog.log" 2>&1 ||
      { tail -5 "$DEMO_LOGS/catalog.log" >&2; demo_die "add-service for $name failed"; }
    "$RELAY" set-grant --config "$DEMO_STATE/relay.toml" --records "$CAT/grant-$name.toml" >>"$DEMO_LOGS/catalog.log" 2>&1 ||
      { tail -5 "$DEMO_LOGS/catalog.log" >&2; demo_die "set-grant for $name failed"; }
  fi
  demo_ok "service $name = $sid (grant $grant)"
done

# ------------------------------------------------------------------ relay
demo_say "starting tunnel-relay serve (consumer https://localhost:$DEMO_CONSUMER_PORT, device wss://localhost:$DEMO_DEVICE_PORT)"
demo_spawn relay "$DEMO_LOGS/relay.log" "$RELAY" serve --config "$DEMO_STATE/relay.toml"
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$DEMO_PKI/server-ca.pem" "$DEMO_CONSUMER_URL/readyz" 2>/dev/null)" = 200 ]; do
  demo_pid_alive relay || { tail -5 "$DEMO_LOGS/relay.log" >&2; demo_die "relay exited during startup"; }
  i=$((i + 1)); [ "$i" -lt 60 ] || demo_die "relay /readyz not 200 after 30 s (log: $DEMO_LOGS/relay.log)"
  sleep 0.5
done
demo_ok "relay ready (/readyz 200)"

# ------------------------------------------------------------------ backends + device
for name in $ready_features; do
  (demo_load_feature "$(demo_feature_file "$name")"; feature_start) || demo_die "backend for $name failed to start"
done
demo_say "connecting the device (tunnel-client connect)"
demo_spawn device "$DEMO_LOGS/device.log" "$CLIENT" connect --config "$DEVICE_DIR/client.toml" --json
i=0
until grep -q '"phase":"active"' "$DEMO_LOGS/device.log" 2>/dev/null; do
  demo_pid_alive device || { tail -3 "$DEMO_LOGS/device.log" | demo_redact >&2; demo_die "device exited during startup"; }
  i=$((i + 1)); [ "$i" -lt 60 ] || demo_die "device not active after 30 s (log: $DEMO_LOGS/device.log)"
  sleep 0.5
done
demo_ok "device session active"

mv "$DEMO_STATE/ids.env.pending" "$DEMO_STATE/ids.env"
elapsed=$(( $(demo_now_ms) - started ))
demo_say "local demo is up in $((elapsed / 1000)).$(( (elapsed % 1000) / 100 )) s. Next: scripts/demo/show.sh list"
"$DEMO_DIR/status.sh"
