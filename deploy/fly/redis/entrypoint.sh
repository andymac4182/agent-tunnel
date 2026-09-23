#!/bin/sh
# Entrypoint of the Fly.io Redis image (docs/deploy-fly.md). Runs as root only
# long enough to write the TLS files and configuration, then hands over to the
# official image's entrypoint, which drops to the `redis` user and `exec`s
# redis-server.
#
# Secrets (Fly secrets, i.e. environment variables):
#   REDIS_TLS_CERT_CHAIN_B64  server certificate chain, PEM, base64 on one line
#   REDIS_TLS_KEY_B64         its private key, PEM, base64 on one line
#   REDIS_PASSWORD            the `requirepass` password: 32 to 128 letters/digits
set -eu

die() {
  echo "agentuplink-redis-entrypoint: $*" >&2
  exit 1
}

[ "$(id -u)" = 0 ] || die "must start as root (it drops to the redis user itself)"
run=/run/agentuplink-redis
data=/data/redis

umask 077
rm -rf "$run"
mkdir -m 700 "$run"

for pair in REDIS_TLS_CERT_CHAIN_B64:tls-chain.pem REDIS_TLS_KEY_B64:tls-key.pem; do
  var=${pair%%:*}
  file=$run/${pair#*:}
  eval "value=\${$var:-}"
  [ -n "$value" ] || die "secret $var is not set (see docs/deploy-fly.md, step 3)"
  printf '%s' "$value" | base64 -d > "$file" 2>/dev/null || die "secret $var is not valid base64"
  [ -s "$file" ] || die "secret $var decodes to nothing"
done

password=${REDIS_PASSWORD:-}
case "$password" in
  *[!A-Za-z0-9]* | "") die "REDIS_PASSWORD must be 32 to 128 letters and digits" ;;
esac
[ "${#password}" -ge 32 ] && [ "${#password}" -le 128 ] \
  || die "REDIS_PASSWORD must be 32 to 128 letters and digits"

# The Fly volume is mounted at /data and holds lost+found, so Redis keeps its
# files in a subdirectory it owns.
mkdir -p "$data"
chown redis:redis "$data"
chmod 700 "$data"

cat > "$run/redis.conf" <<CONF
# TLS only: no plaintext port. Clients authenticate with the password; the
# server certificate is checked by the relay against its redis-ca.pem.
port 0
tls-port 6379
tls-cert-file $run/tls-chain.pem
tls-key-file $run/tls-key.pem
tls-auth-clients no
tls-protocols "TLSv1.2 TLSv1.3"
# Fly's private network is IPv6 (<app>.internal); listen on both families.
bind * -::*
protected-mode yes
# docs/cluster.md, "Redis durability, backup, and recovery".
appendonly yes
appendfsync always
# Keep fsyncing while the AOF is rewritten; the relay's Redis restart
# continuity (M6-C65) checks all three settings with CONFIG GET.
no-appendfsync-on-rewrite no
aof-load-truncated no
maxmemory-policy noeviction
dir $data
CONF
# The password goes in last, through printf, so the directive line is never
# spelled out with its value in this file.
printf 'requirepass %s\n' "$password" >> "$run/redis.conf"
chown -R redis:redis "$run"
chmod 600 "$run"/*
unset REDIS_TLS_CERT_CHAIN_B64 REDIS_TLS_KEY_B64 REDIS_PASSWORD value password

# The official entrypoint drops to the redis user and execs redis-server. Its
# own permission fixing is skipped: the files above are already owned by redis.
export SKIP_FIX_PERMS=1
cd "$data"
exec /usr/local/bin/docker-entrypoint.sh redis-server "$run/redis.conf"
