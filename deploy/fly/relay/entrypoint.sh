#!/bin/sh
# Entrypoint of the Fly.io relay image (docs/deploy-fly.md).
#
# 1. Writes each secret from its environment variable (set with
#    `fly secrets import`) to an owner-only file under
#    /var/lib/agent-tunnel/secrets. PEM and JSON secrets arrive base64-encoded
#    on one line, because Fly secrets are single values.
# 2. Writes the serving configuration: `redis_url` from AT_REDIS_URL, then the
#    baked template /etc/agent-tunnel/relay.toml.in.
# 3. Removes the secret variables from the environment and `exec`s
#    tunnel-relay, so the relay is the process that receives SIGTERM.
#
# Usage (the image's CMD is `serve`):
#   serve
#   check-serve-config
#   activate-first-incarnation
#   provision-catalog RECORDS [--dry-run]
#   rebind-redis-run --redis-restarted-in-place
#   add-user | add-device | add-service | set-grant --records PATH [--dry-run]
#   revoke-grant | revoke-device | revoke-credential --tenant UUID ... [--dry-run]
#
# The seven catalog commands (docs/operator.md section 2.5, M6-C31) run in a
# one-off machine of the relay app while `serve` runs elsewhere, the same way
# provisioning does (docs/deploy-fly.md section 6.6, M6-C91). Their arguments
# go to tunnel-relay unchanged, each as its own argv entry, after the
# `--config` this script writes; this shell never evaluates them.
set -eu

base=/var/lib/agent-tunnel
secrets=$base/secrets
config=$base/run/relay.toml
template=/etc/agent-tunnel/relay.toml.in

die() {
  echo "agent-tunnel-relay-entrypoint: $*" >&2
  exit 1
}

umask 077
rm -rf "$secrets"
mkdir -m 700 "$secrets"

# write_secret VARIABLE FILE: decode a base64 secret into FILE (mode 0600).
write_secret() {
  eval "value=\${$1:-}"
  [ -n "$value" ] || die "secret $1 is not set (see docs/deploy-fly.md, step 4)"
  printf '%s' "$value" | base64 -d > "$secrets/$2" 2>/dev/null \
    || die "secret $1 is not valid base64"
  [ -s "$secrets/$2" ] || die "secret $1 decodes to nothing"
  chmod 600 "$secrets/$2"
}

write_secret AT_DEVICE_TLS_CERT_CHAIN_B64 device-server-chain.pem
write_secret AT_DEVICE_TLS_KEY_B64 device-server-key.pem
write_secret AT_DEVICE_CLIENT_CA_B64 device-client-ca.pem
write_secret AT_CONSUMER_TLS_CERT_CHAIN_B64 consumer-server-chain.pem
write_secret AT_CONSUMER_TLS_KEY_B64 consumer-server-key.pem
write_secret AT_REDIS_CA_B64 redis-ca.pem
write_secret AT_OIDC_JWKS_B64 oidc-jwks.json

# The URL is written into TOML, so refuse anything that could leave the string.
url=${AT_REDIS_URL:-}
[ -n "$url" ] || die "secret AT_REDIS_URL is not set (see docs/deploy-fly.md, step 4)"
case "$url" in
  rediss://*) ;;
  *) die "AT_REDIS_URL must start with rediss:// (the relay refuses plaintext Redis)" ;;
esac
case "$url" in
  *[!A-Za-z0-9:@._/%-]*) die "AT_REDIS_URL may contain only letters, digits and : @ . _ / % -" ;;
esac

{
  printf 'redis_url = "%s"\n' "$url"
  cat "$template"
} > "$config"
chmod 600 "$config"

command=${1:-serve}
[ "$#" -gt 0 ] && shift
unset AT_DEVICE_TLS_CERT_CHAIN_B64 AT_DEVICE_TLS_KEY_B64 AT_DEVICE_CLIENT_CA_B64 \
  AT_CONSUMER_TLS_CERT_CHAIN_B64 AT_CONSUMER_TLS_KEY_B64 AT_REDIS_CA_B64 \
  AT_OIDC_JWKS_B64 AT_REDIS_URL value url

case "$command" in
  serve | check-serve-config | activate-first-incarnation)
    [ "$#" -eq 0 ] || die "$command takes no arguments"
    exec /usr/local/bin/tunnel-relay "$command" --config "$config"
    ;;
  rebind-redis-run)
    # docs/deploy-fly.md section 6.4 (M6-C65): only after a Redis restart
    # that kept its data, never after a restore.
    [ "$#" -eq 1 ] && [ "$1" = --redis-restarted-in-place ] \
      || die "usage: rebind-redis-run --redis-restarted-in-place"
    exec /usr/local/bin/tunnel-relay rebind-redis-run --config "$config" --redis-restarted-in-place
    ;;
  provision-catalog)
    [ "$#" -ge 1 ] || die "usage: provision-catalog RECORDS [--dry-run]"
    records=$1
    shift
    exec /usr/local/bin/tunnel-relay provision-catalog --config "$config" --records "$records" "$@"
    ;;
  add-user | add-device | add-service | set-grant | revoke-grant | revoke-device | revoke-credential)
    # docs/deploy-fly.md section 6.6 (M6-C91). tunnel-relay parses and checks
    # the arguments; the configuration is always the one written above.
    [ "$#" -ge 1 ] || die "usage: $command --records PATH [--dry-run], or $command --tenant UUID ... [--dry-run]"
    for argument in "$@"; do
      case "$argument" in
        --config | --config=*) die "$command: the entrypoint sets --config; do not pass it" ;;
      esac
    done
    exec /usr/local/bin/tunnel-relay "$command" --config "$config" "$@"
    ;;
  *)
    die "unknown command '$command' (serve, check-serve-config, activate-first-incarnation, provision-catalog, rebind-redis-run, add-user, add-device, add-service, set-grant, revoke-grant, revoke-device, revoke-credential)"
    ;;
esac
