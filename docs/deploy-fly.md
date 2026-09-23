# Deploying one relay on Fly.io (private alpha)

Status: written for task row M6-C60 on 2026-09-23 against `origin/main` at
`496396e`, with flyctl `v0.4.106`. **Nothing here has been run against Fly.**
The images, the configuration and the provisioning path were proved locally
with Docker (section 7). Every `fly` command below is one the owner runs, in
order, and each one that costs money is marked **Costs money**. The prices are
in section 8.

The fences below are tagged `text`. Unlike [operator.md](operator.md), this
file is not executed by `scripts/m6-release-artifact.py verify --check docs`:
a `fly` command needs an account, and running it creates billable resources.

## 1. What gets deployed, and why

Two Fly apps in one region:

| App | Machine | Public address | Holds |
| --- | --- | --- | --- |
| `agentuplink-relay` | one `shared-cpu-1x`, 256 MB | dedicated IPv4 and IPv6; TCP 443 (consumers) and TCP 9443 (devices), both passed through untouched | nothing durable; secrets are written to its root filesystem at each start |
| `agentuplink-redis` | one `shared-cpu-1x`, 256 MB | none; private network only, `agentuplink-redis.internal:6379` | the Redis catalog, AOF on a 1 GB volume |

The files are in [`deploy/fly/`](../deploy/fly): a `Dockerfile`, entrypoint
and `fly.toml` for each app, the relay's serving configuration
(`deploy/fly/relay/relay.toml`) and the local proof (`deploy/fly/local-proof.sh`).

**One relay, not a cluster.** A cluster needs HTTP/3 peers over UDP, a
membership publisher and an HTTPS checkpoint authority, and this alpha ships
neither authority (M6-C22, [operator.md](operator.md#33-a-cluster)). Two relay
machines would be two unclustered relays on one Redis namespace, which is not
supported. Every deploy below passes `--ha=false`; never scale either app
above one machine. Two Redis machines would be two unrelated Redis servers
behind one `.internal` name.

The decisions, and what each rests on:

- **Both relay listeners are TCP passthrough.** A device authenticates with
  its client certificate in the TLS handshake of the WebSocket, and the relay
  reads that certificate itself (`device_tls_client_ca`). Fly's `tls` or `http`
  handler would terminate TLS at Fly's edge, and the certificate would never
  arrive. The consumer listener is TLS terminated by the relay too:
  `consumer_tls_cert_chain` and `consumer_tls_private_key` are required
  settings and `serve` has no plaintext listener (`crates/tunnel-relay/src/main.rs`,
  `ServeConfig` in `config.rs`), so Fly's HTTP handler, which forwards
  plaintext, cannot sit in front of it either. Fly: "If you don't specify
  handlers, we just forward TCP to your app as-is"
  (<https://fly.io/docs/networking/services/>). Consequence: Fly's managed
  certificates (`fly certs`) are not used; the relay's certificates are yours.
- **A dedicated IPv4 address.** The same page lists "You want your app to
  accept raw TCP and handle TLS termination" among the reasons to allocate a
  dedicated IPv4; a shared IPv4 carries only HTTP on 80 and TLS through Fly's
  handler. IPv6 is dedicated and free
  (<https://fly.io/docs/about/pricing/>). The allocation command is
  `fly ips allocate-v4` (<https://fly.io/docs/flyctl/ips-allocate-v4/>).
- **Never stopped for idleness.** `auto_stop_machines = "off"`,
  `auto_start_machines = false`, `min_machines_running = 1` on both services.
  `fly launch` writes `auto_stop_machines = "stop"` with
  `min_machines_running = 0`; with no setting at all Fly "won't automatically
  stop or suspend" machines (<https://fly.io/docs/launch/autostop-autostart/>).
  The settings are explicit so that neither default can apply. A stopped relay
  drops every device session and owner lease. (`fly launch` is not used here:
  it would rewrite `fly.toml`.)
- **No per-machine connection cap below the relay's own.** A service's
  `concurrency.type = "connections"` is the default, and Fly stops sending new
  connections to a machine at `hard_limit`
  (<https://fly.io/docs/reference/configuration/>). The relay admits at most
  1,024 devices by default and each device holds more than one connection, so
  both services set `hard_limit = 1000` per listener.
- **Health checks.** The consumer service checks `GET /readyz` over HTTPS on
  the private network (`tls_skip_verify`, because the relay's certificate names
  its public host). The device service has a bare TCP check; the local proof
  measured that a bare connect adds no relay log line. **`/readyz` does not
  cover Redis on a non-cluster relay:** it stays `200` while Redis is down or
  has restarted, and every request then fails `503` (measured, M6-C61).
- **Stopping.** `kill_signal = "SIGTERM"`, `kill_timeout = 60`. Fly's default
  signal is SIGINT and its default timeout 5 s, at most 300 s
  (<https://fly.io/docs/reference/configuration/>). `serve` handles both
  signals the same way and its drain has no deadline of its own
  ([operator.md](operator.md#4-service-installation-upgrade-backup-and-recovery)).
  Measured locally: with one device connected, `docker stop` ended the relay
  with exit `0` in 338 ms. Both images' entrypoints `exec` the server, so on
  Fly the server is the process Fly's init signals.
- **`[deploy] strategy = "immediate"`.** `bluegreen` would boot a second relay
  beside the first and cannot be used with a volume; `rolling` has nothing to
  roll to with one machine (<https://fly.io/docs/reference/configuration/>).
  A relay redeploy therefore ends every device session, as any relay restart
  does ([operator.md](operator.md#4-service-installation-upgrade-backup-and-recovery)).
- **Secrets never enter the image.** Each image's entrypoint writes the
  secrets from environment variables, which is how Fly delivers `fly secrets`,
  into owner-only files at start-up, then removes them from the environment
  before it `exec`s the server. The relay runs as uid 10001. The relay's Redis
  TLS loader refuses a symlink anywhere in a path and a private key readable by
  anyone else ([redis-tls.md](redis-tls.md)), so the files live under
  `/var/lib/agent-tunnel/secrets` (mode `0700`), not under `/var/run`, which is
  a symlink on Debian. Fly's own `[[files]]` from secrets was not used: its
  documentation states no file mode or owner.

### Redis: our own, not a managed Redis

The relay needs, from Redis: `EVAL` of Lua scripts that call `SCAN`, `TIME`,
`GET`, `SET`, `HGET`, `HSET`, `HGETALL`, `HLEN`, `EXISTS`, `EXPIRE`,
`PEXPIREAT`, `SADD`, `SMEMBERS`, `SCARD`, `DEL`, `INCR`, `STRLEN`, `ZADD`,
`ZRANGE`, `ZREM`, `ZREMRANGEBYSCORE` and `ZCARD`, including keys the script
finds by `SCAN MATCH` rather than receives in `KEYS`; `MULTI`/`EXEC`
pipelines; `WATCH`/`UNWATCH`; `SCAN`, `TYPE`, `SETNX`, `HSETNX`, `PTTL`, `PING`;
and `INFO server` with a `run_id` line, which the relay binds each namespace to
(counted from `crates/tunnel-catalog/src/redis.rs` and `redis/*.rs`). It also
needs `appendfsync always`, `aof-load-truncated no` and
`maxmemory-policy noeviction` ([cluster.md](cluster.md#redis-durability-backup-and-recovery)),
and `rediss://`: `serve` refuses a plaintext Redis URL (measured with this
image: `check-serve-config` on a `redis://` URL exits `1` with "redis_url must
use rediss://; plaintext redis:// is only supported by the disposable local
test harness, not relay serve", from `crates/tunnel-relay/src/config.rs`).

Upstash through Fly was checked against that list and rejected:

- Fly's Upstash databases are reached "via a private IPv6 address restricted
  to your Fly organization" with `redis://` URLs
  (<https://fly.io/docs/upstash/redis/>); a TLS endpoint there is not
  documented, and the relay refuses `redis://`.
- Upstash's scripting page says "Pass every key the script touches through
  KEYS when possible" and to derive values "rather than from clock or random
  sources" (<https://upstash.com/docs/redis/commands/scripting/eval>). The relay's
  scripts read keys they find with `SCAN` and call `TIME`.
- Upstash's compatibility page lists no per-command support and says only that
  "most unsupported items are on our roadmap"
  (<https://upstash.com/docs/redis/overall/compatibility>); nothing documents
  whether `INFO server` has a `run_id`, or what it means on a replicated
  service. Without one `serve` cannot start.
- Eviction and fsync are the provider's: Fly's page describes Upstash eviction
  as random removal when enabled, and exposes no AOF setting.

A self-hosted Redis (`redis:8.4.0-alpine`, the version every local harness here
uses) meets every item and is what the local proof ran against.

**What self-hosting costs in operations:** a Redis restart changes its
`run_id`, and the relay then refuses that namespace until recovery, which this
alpha cannot perform (M6-C22). Measured locally: a relay started after a Redis
restart exits `1` with `Redis catalog connection failed; stage=authority_identity`,
even though AOF kept all 24 keys. On Fly a machine restarts on host
maintenance, on a `fly deploy` of the Redis app, and on a crash, so **every one
of those is an outage** that ends with section 6.4, a new namespace and a
re-provisioning (M6-C62).

## 2. Before you start

You need flyctl (this was written against `v0.4.106`), `openssl`, and a
`tunnel-client` for the Mac from a release bundle ([operator.md](operator.md#1-download-and-verify)).

```text
fly version
fly auth whoami
fly platform regions
```

Choose the two app names (they are global) and one region. This runbook uses
`agentuplink-relay`, `agentuplink-redis` and `syd`. If you change them, change
`app` and `primary_region` in both `deploy/fly/*/fly.toml`, the host in
`AT_REDIS_URL` (section 4) and the certificate names (section 3.1).

Edit `deploy/fly/relay/relay.toml` where it says `EDIT`: `oidc_issuer` and
`oidc_audience` for your consumer identity issuer, and a fresh
`redis_namespace`, `node_id` and `deployment_incarnation`. These are baked into
the relay image, so the provisioning machines and the serving machine cannot
disagree about them. Then check the files (free, contacts nothing billable):

```text
fly config validate --strict -c deploy/fly/redis/fly.toml
fly config validate --strict -c deploy/fly/relay/fly.toml
```

`--strict` reports an unknown top-level key but, measured with `v0.4.106`,
not a misspelled key inside `[[services]]`, and it does not check values such as
`protocol`; it is a type check, not a proof the settings mean what they say.

## 3. Credentials (local, free)

Work in a directory outside the repository and never commit anything from it.
The repository's `.gitignore` excludes `*.pem`, but the directory should not be
inside the checkout at all.

```text
mkdir -m 700 ~/agentuplink-fly && cd ~/agentuplink-fly
```

### 3.1 Certificate authorities and server certificates

The alpha ships no certificate authority. The commands below make throwaway
ones, as [operator.md](operator.md#21-device-credentials) does; use your own
issuer if you have one. Three separate CAs: one for the relay's server
certificates, one for device certificates, one for Redis.

```text
for ca in relay-ca device-ca redis-ca; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=agentuplink $ca" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout $ca-key.pem -out $ca.pem
done
server_cert() {  # NAME CA SAN
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout $1-key.pem -out $1.csr
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" > $1.ext
  openssl x509 -req -in $1.csr -CA $2.pem -CAkey $2-key.pem -CAcreateserial -days 90 -extfile $1.ext -out $1.pem
}
server_cert relay-server relay-ca DNS:agentuplink-relay.fly.dev
server_cert redis-server redis-ca DNS:agentuplink-redis.internal
openssl rand -hex 24 > redis-password.txt
```

This uses one server certificate for both relay listeners; the relay accepts
separate ones (section 4 names both pairs). Anyone calling the consumer listener
must trust `relay-ca.pem`, because the certificate is not from a public CA.

### 3.2 The consumer identity issuer

The relay verifies consumer bearer tokens against the JWKS file in
`AT_OIDC_JWKS_B64`, for the `oidc_issuer` and `oidc_audience` in `relay.toml`
(RS256 or EdDSA). Use your issuer's published JWKS. For a first smoke test
without an issuer, `deploy/fly/local-proof.sh` shows how to make a one-key JWKS
and sign a token with `openssl`; tokens need `iss`, `aud`, `sub` equal to the
catalog user's `oidc_subject`, `exp`, and `echo:invoke` in `scope`. Save the
JWKS as `~/agentuplink-fly/oidc-jwks.json`; section 4 reads it from there.

### 3.3 The device, and the catalog records

Create the device key on the Mac and have the device CA sign it, exactly as
[operator.md section 2.1](operator.md#21-device-credentials) does, with the
profile at `~/agentuplink-fly/device/client.toml`, the certificate signed by
`device-ca.pem`, `relay-ca.pem` imported as the server CA, and the Fly address
as `relay_url`:

```text
device_id = "<device UUID>"
relay_url = "wss://agentuplink-relay.fly.dev:9443/v1/tunnel/control"
```

Write the catalog records as in [operator.md section 2.3](operator.md#23-tenant-scoped-authorization-and-the-first-incarnation)
(`examples/m6-catalog.toml` is the template) into `~/agentuplink-fly/catalog.toml`,
with a copy of the device certificate beside it as
`~/agentuplink-fly/device-cert.pem`. The records are not secret.

## 4. Create the apps and set the secrets

Creating an app costs nothing by itself.

```text
fly apps create agentuplink-redis -o personal
fly apps create agentuplink-relay -o personal
```

**Costs money: $2.00 a month** from now until it is released. The dedicated
IPv4 the device and consumer listeners need:

```text
fly ips allocate-v4 -a agentuplink-relay
fly ips allocate-v6 -a agentuplink-relay
fly ips list -a agentuplink-relay
```

Secrets are read from standard input as `NAME=VALUE` lines, so no secret is on
a command line. `--stage` stores them without starting anything. PEM and JSON
values are base64 on one line; the entrypoints decode them.

```text
cd ~/agentuplink-fly
b64() { base64 < "$1" | tr -d '\n'; }
{
  echo "REDIS_TLS_CERT_CHAIN_B64=$(b64 redis-server.pem)"
  echo "REDIS_TLS_KEY_B64=$(b64 redis-server-key.pem)"
  echo "REDIS_PASSWORD=$(cat redis-password.txt)"
} | fly secrets import -a agentuplink-redis --stage
{
  echo "AT_REDIS_URL=rediss://:$(cat redis-password.txt)@agentuplink-redis.internal:6379/0"
  echo "AT_REDIS_CA_B64=$(b64 redis-ca.pem)"
  echo "AT_DEVICE_TLS_CERT_CHAIN_B64=$(b64 relay-server.pem)"
  echo "AT_DEVICE_TLS_KEY_B64=$(b64 relay-server-key.pem)"
  echo "AT_DEVICE_CLIENT_CA_B64=$(b64 device-ca.pem)"
  echo "AT_CONSUMER_TLS_CERT_CHAIN_B64=$(b64 relay-server.pem)"
  echo "AT_CONSUMER_TLS_KEY_B64=$(b64 relay-server-key.pem)"
  echo "AT_OIDC_JWKS_B64=$(b64 oidc-jwks.json)"
} | fly secrets import -a agentuplink-relay --stage
fly secrets list -a agentuplink-redis
fly secrets list -a agentuplink-relay
```

`fly secrets list` shows names and digests, never values. The relay's
entrypoint refuses to start, naming the variable, if any of the eight is
missing, is not base64, or (for `AT_REDIS_URL`) is not `rediss://` or contains
a character that could break out of the TOML string.

## 5. Redis

**Costs money: $0.15 a month** for the 1 GB volume, plus snapshot storage
beyond Fly's free 10 GB (daily snapshots, 5-day retention, are on by default):

```text
fly volumes create agentuplink_redis_data -a agentuplink-redis -r syd -s 1
```

It warns that a single volume has no redundancy. That is expected: there is
exactly one Redis, and its durability is the AOF on this volume plus Fly's
daily snapshots.

**Costs money: $2.47 a month** (one `shared-cpu-1x` 256 MB machine in `syd`).
Run from the Redis directory, whose `fly.toml` and `Dockerfile` are the
defaults there. `--no-public-ips` keeps Redis off the internet; its `fly.toml`
has no services:

```text
cd deploy/fly/redis && fly deploy --ha=false --no-public-ips && cd ../../..
fly machine list -a agentuplink-redis
fly logs -a agentuplink-redis --no-tail
```

Expect exactly one machine, and `Ready to accept connections tls` in the log.
`fly ips list -a agentuplink-redis` must be empty.

## 6. The relay

### 6.1 Build the image once

The build runs on Fly's remote builder. Fly's pricing page does not list a
builder charge (section 8). The image label is what the provisioning machines
and the serving machine will both run:

```text
fly deploy . --config deploy/fly/relay/fly.toml \
  --dockerfile deploy/fly/relay/Dockerfile \
  --ignorefile deploy/fly/relay/Dockerfile.dockerignore \
  --build-only --push --image-label fly-1
```

### 6.2 Activate and provision (before any relay serves)

**Costs money: a few seconds of a `shared-cpu-1x` machine each**, well under
one cent. Each command runs the image's entrypoint in a one-off machine that
is removed when it exits, with the app's secrets, and reaches Redis over the
private network. The first command only validates. The other two write Redis,
must run in this order, and neither may be repeated
([operator.md section 2.3](operator.md#23-tenant-scoped-authorization-and-the-first-incarnation)):

```text
fly machine run registry.fly.io/agentuplink-relay:fly-1 check-serve-config \
  -a agentuplink-relay -r syd --rm
fly machine run registry.fly.io/agentuplink-relay:fly-1 activate-first-incarnation \
  -a agentuplink-relay -r syd --rm
cd ~/agentuplink-fly
fly machine run registry.fly.io/agentuplink-relay:fly-1 provision-catalog /tmp/provision/catalog.toml \
  -a agentuplink-relay -r syd --rm \
  --file-local /tmp/provision/catalog.toml=catalog.toml \
  --file-local /tmp/provision/device-cert.pem=device-cert.pem
fly logs -a agentuplink-relay --no-tail
fly machine list -a agentuplink-relay
```

The log must show `Activated deployment incarnation ... as the first
incarnation of namespace ...` and then `Provisioned namespace ...`. **The
machine list must be empty before the next step:** a leftover one-off machine
would be updated into a second relay by `fly deploy`. Remove one with
`fly machine destroy <id> -a agentuplink-relay`.

`fly ssh console` is not an option at this point: there is no relay machine
to connect to, because `serve` refuses to start on a namespace with no
incarnation, and a relay started between the two commands can leave the
namespace unprovisionable (M6-C34).

Two things here were not measured on Fly. That the one-off machines receive
the app's secrets rests on Fly's documentation: "An app's secrets are
available as environment variables at runtime on every Machine belonging to
that Fly App, whether the Machine is managed by Fly Launch or not"
(<https://fly.io/docs/apps/secrets/>). They do **not** receive `fly.toml`'s
`[env]`: "fly machine run doesn't read your fly.toml" (Fly staff,
<https://community.fly.io/t/why-does-fly-machine-run-shell-see-secrets-but-not-the-environment/25793>),
which is why the namespace and incarnation are baked into the image rather
than set in `[env]`. If a secret is missing, the entrypoint exits naming it
and nothing is written to Redis; stop there, do not deploy the relay, and
report it. And the positional command replacing the image's `CMD` while keeping its
`ENTRYPOINT` is the documented shape `fly machine run <image> [command]`
(`fly machine run --help`, `v0.4.106`), not something run here.

### 6.3 Serve

**Costs money: $2.47 a month** (one `shared-cpu-1x` 256 MB machine in `syd`).
Deploy the exact image that was provisioned:

```text
fly deploy . --config deploy/fly/relay/fly.toml \
  --image registry.fly.io/agentuplink-relay:fly-1 --ha=false
fly machine list -a agentuplink-relay
fly checks list -a agentuplink-relay
fly logs -a agentuplink-relay --no-tail
```

Expect one machine, both checks passing, and `tunnel-relay listening:
consumer=0.0.0.0:8443 device=0.0.0.0:9443` in the log. From the Mac:

```text
curl --cacert ~/agentuplink-fly/relay-ca.pem https://agentuplink-relay.fly.dev/readyz
tunnel-client connect --config ~/agentuplink-fly/device/client.toml --json
```

In a second terminal, with a token from your issuer (section 3.2):

```text
curl --cacert ~/agentuplink-fly/relay-ca.pem \
  -H "Authorization: Bearer $TOKEN" --data-binary hello \
  https://agentuplink-relay.fly.dev/v1/devices/<device UUID>/services/<service UUID>/echo
```

The reply is the export's `device_canary` followed by `hello`. `/readyz`
answering `200` is not enough on its own: a non-cluster relay answers `200`
even when Redis is unusable (M6-C61), so the echo is the check.

### 6.4 After a Redis restart

The relay refuses the namespace from then on; `/readyz` still says ready and
consumer calls fail `503 AUTHORIZATION_UNAVAILABLE`. Until recovery ships
(M6-C22), the way back is a new namespace:

1. Edit `redis_namespace` and `deployment_incarnation` in
   `deploy/fly/relay/relay.toml`.
2. Section 6.1 with a new `--image-label`, section 6.2 with that label, then
   section 6.3 with that label.

The device's key, certificate and profile are unchanged. The old namespace's
keys stay in Redis; nothing shipped removes them.

### 6.5 Teardown

Irreversible, and the only way to stop all charges. The IPv4 is released with
its app:

```text
fly apps destroy agentuplink-relay
fly apps destroy agentuplink-redis
```

## 7. The local proof

`deploy/fly/local-proof.sh` builds both images and runs them with Docker on
one machine, as close to the Fly topology as it allows: Redis TLS-only with a
password and AOF on a volume, reachable only on a private Docker network under
the name `agentuplink-redis.internal`; the relay's listeners published as
plain TCP ports, so TLS passes through as it does with a Fly service with no
handlers; every secret delivered as an environment variable; provisioning in
one-off relay containers with the records copied in. It generates every key in
a temporary directory outside the repository and removes the directory, the
containers, the network and the volume when it exits.

```text
TUNNEL_CLIENT=/path/to/tunnel-client deploy/fly/local-proof.sh
```

Measured on `496396e` plus these files (log nonce
`m6c60-proof-20260923T092514Z-69923`, arm64 images):

| Check | Result |
| --- | --- |
| Generated keys and the Redis password in either saved image | none |
| Redis without the password; Redis in plaintext | `NOAUTH`; connection reset |
| Redis `CONFIG GET` | `appendonly yes`, `appendfsync always`, `aof-load-truncated no`, `maxmemory-policy noeviction`, `port 0`, `tls-port 6379` |
| `check-serve-config`, `activate-first-incarnation`, `provision-catalog` in one-off containers | all three succeed |
| `/readyz` through the published consumer port | `{"status":"ready"}` |
| PID 1 in the relay container | `tunnel-relay`, uid 10001, no `AT_` variable in its environment |
| Device listener, TLS client without a certificate | `tlsv13 alert certificate required` |
| Host `tunnel-client` with its device certificate, then a consumer echo | HTTP 200, body = canary + payload |
| `docker stop -t 60` on the relay with the device connected | `tunnel-relay stopping: signal=SIGTERM`, `stopped: signal=SIGTERM`, exit `0`, 338 ms |
| The device when the relay stopped | exit `4`, `TRANSPORT_ERROR`, retryable |
| A second relay on the same Redis | serves; the device reconnects and echoes |
| `docker stop` on Redis | exit `0`, "Redis is now ready to exit" |
| The running relay while Redis is down, and after Redis restarted with a new `run_id` (AOF kept 24 keys) | `/readyz` ready both times; echo `503` `AUTHORIZATION_UNAVAILABLE`, `not_dispatched`; the device session ended, exit `4` |
| A fresh relay on the restarted Redis | exit `1`, `Redis catalog connection failed; stage=authority_identity` |
| Memory with one device connected (`docker stats`) | relay 2.6 MiB, Redis 6.1 MiB |

**The proof can go red.** Run against a copy of the relay image whose
entrypoint calls `tunnel-relay` without `exec` (`PROOF_SKIP_BUILD=1
RELAY_IMAGE=...`), it stopped at `FAILED PID 1 is not tunnel-relay as uid
10001`, exit `1` (log nonce `m6c60-proof-20260923T092655Z-71302`): that shell
would have been the process `docker stop` and Fly signal, and a shell as PID 1
ignores SIGTERM.

What the proof cannot show: Fly's proxy, its health checkers, its init as PID
1 forwarding the signal, IPv6-only `.internal` addressing (the Docker network
is IPv4), secrets delivered to `fly machine run` machines, and amd64, which is
what Fly runs (section 7.1).

## 8. Cost list

Prices from <https://fly.io/docs/about/pricing/>, read 2026-09-23 for region
`syd` (other regions differ; `iad` is $1.94 for the same machine). Monthly
figures are Fly's own 30-day figures.

| Resource | Created by | Price | Monthly |
| --- | --- | --- | --- |
| Dedicated IPv4 on `agentuplink-relay` | `fly ips allocate-v4` (section 4) | $2/mo | $2.00 |
| IPv6 on `agentuplink-relay` | `fly ips allocate-v6` (section 4) | included | $0.00 |
| Redis machine, `shared-cpu-1x` 256 MB, `syd` | `fly deploy` (section 5) | $0.00000095/s | $2.47 |
| Relay machine, `shared-cpu-1x` 256 MB, `syd` | `fly deploy` (section 6.3) | $0.00000095/s | $2.47 |
| Redis volume, 1 GB | `fly volumes create` (section 5) | $0.15/GB/mo provisioned, billed even when detached | $0.15 |
| Volume snapshots (daily, 5-day retention by default) | the volume | $0.08/GB/mo stored; first 10 GB free each month | $0.00 at this size |
| One-off provisioning machines | `fly machine run` (section 6.2) | $0.00000095/s while running | under $0.01 once |
| Outbound data to the internet (Oceania) | device and consumer traffic | $0.04/GB | usage |
| Data between the two apps in one region; inbound data | — | free | $0.00 |
| Stopped machines (if you stop one instead of destroying it) | — | $0.15 per GB of rootfs per 30 days | usage |
| Fly-managed TLS certificates | not used (passthrough) | first 10 free | $0.00 |
| Remote builder | `fly deploy --build-only` (section 6.1) | not listed on the pricing page | not verified |

**Standing total: $7.09 a month in `syd`**, plus outbound data. Upstash is not
used, so its per-command pricing does not apply.
