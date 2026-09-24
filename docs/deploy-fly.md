# Deploying one relay on Fly.io (private alpha)

Status: written for task row M6-C70 on 2026-09-23 against `origin/main` at
`496396e`, with flyctl `v0.4.106`, and corrected after the first real run on
2026-09-23 (M6-C70 has its evidence). The images, the configuration and the
provisioning path were proved locally with Docker (section 7). On Fly, the
coordinator ran it with the owner's approval: sections 4, 5, 6.1 and 6.3 with
the current image, and `/readyz`, `connect` and the echo succeeded from the
Mac. **Section 6.2 (activate and provision) has not yet run on Fly with an
image built from `main`.** Its steps 3 and 4 succeeded on Fly only with a
diagnostic image; the `main` image was then deployed onto that already
provisioned namespace. A fresh operator's provisioning path is proven locally
(`deploy/fly/local-proof.sh`), not yet on Fly with a `main` image.

**Use a relay image built from `main` at or after `721ed2a`** (PR #97), which
has the M6-C73 fix. On a fresh Fly machine the first DNS lookup of
`agentuplink-redis.internal` took 2,038 ms, and before that fix the relay's
Redis client allowed 1 s for the whole connection including the lookup, so
`activate-first-incarnation`, `provision-catalog` and `serve` all failed on a
cold machine with a connection timeout (M6-C72, M6-C73; measured on Fly with a
diagnostic build). Resolving the name first with `getent hosts` does not help:
nothing caches the lookup across processes. Since M6-C73 each startup
connection gets 10 s. **The relay now runs `main-af23c2f`**, built from
`af23c2f` with these deploy files. It replaced `main-721ed2a` in place on
2026-09-24 with no re-provisioning, and it has M6-C65 continuity on
(section 6.3, "Upgrade to `main-af23c2f`"). A lane reconnect inside a running relay still has
2 s (M6-C74), which matters after a Redis restart (section 6.4).

Every `fly` command below is one the owner runs, in
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
  has restarted, and every request then fails `503` (measured, M6-C67).
- **Stopping.** `kill_signal = "SIGTERM"`, `kill_timeout = 60`. Fly's default
  signal is SIGINT and its default timeout 5 s, at most 300 s
  (<https://fly.io/docs/reference/configuration/>). `serve` handles both
  signals the same way and its drain has no deadline of its own
  ([operator.md](operator.md#4-service-installation-upgrade-backup-and-recovery)).
  Measured locally: with one device connected, `docker stop` ended the relay
  with exit `0` in 407 ms. Both images' entrypoints `exec` the server, so on
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
`run_id`, and the relay's namespace is bound to the run it was activated on.
On Fly a machine restarts on host maintenance, on a `fly deploy` of the Redis
app, and on a crash. Since M6-C65 the namespace survives a restart that kept
Redis's data: a relay that stays up across it re-binds by itself, and a relay
started after it needs one command (section 6.4). **Before M6-C65 every one
of those restarts was an outage** that ended with a new namespace and a
re-provisioning: measured locally, a relay started after a Redis restart
exited `1` with `Redis catalog connection failed; stage=authority_identity`,
even though AOF kept all 24 keys. The relay image must be built from a
commit that has M6-C65 for any of this; `main-721ed2a` does not.

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
server_cert() {  # NAME CA SAN DAYS
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout $1-key.pem -out $1.csr
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" > $1.ext
  openssl x509 -req -in $1.csr -CA $2.pem -CAkey $2-key.pem -CAcreateserial -days $4 -extfile $1.ext -out $1.pem
}
server_cert relay-server relay-ca DNS:agentuplink-relay.fly.dev 90
server_cert redis-server redis-ca DNS:agentuplink-redis.internal 365
openssl rand -hex 24 > redis-password.txt
```

The relay certificate lasts 90 days and the Redis one 365, because replacing
the Redis certificate restarts Redis (section 6.5). This uses one server
certificate for both relay listeners; the relay accepts
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

**Known gap: no memory limit.** The Redis entrypoint sets
`maxmemory-policy noeviction` but no `maxmemory`, so the policy never applies
and Redis can grow until the 256 MB VM runs out of memory (an out-of-memory
kill is a Redis restart, section 6.4). The fix, `maxmemory 160mb` or similar,
belongs in the next planned Redis rebuild. It was not made in place because
redeploying Redis restarted it, which ended the live namespace; with a relay
image that has M6-C65 a Redis redeploy is an ordinary restart (section 6.4).

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

The build runs natively on amd64 on Fly's remote builder (Depot). **May cost
money:** Fly announced 300 free build minutes a month and $0.05 a minute after
that; its pricing page does not list the charge (section 8). A build takes
about 3 minutes on Fly's remote builder (Depot, amd64), measured by the
coordinator on 2026-09-23. The image label is what the provisioning machines
and the serving machine will both run:

```text
fly deploy . --config deploy/fly/relay/fly.toml \
  --dockerfile deploy/fly/relay/Dockerfile \
  --ignorefile deploy/fly/relay/Dockerfile.dockerignore \
  --build-only --push --image-label fly-1
```

Build from a checkout of `main` at or after `af23c2f`. The live relay's image
was built that way from `af23c2f`, labelled `main-af23c2f`
(`registry.fly.io/agentuplink-relay:main-af23c2f@sha256:e6ac84d4bb660f3eec52eeb0730a264f1635a6369545133bee97c9dc1e76723c`,
32 MB). The previous image, and the rollback target, is `main-721ed2a`
(`@sha256:decd4e56b8fc8d1fe190428fa2d3ce8f410bd0299cc652fe2921d4fba29d18b7`). It has no
M6-C65 (section 6.4).

### 6.2 Activate and provision (before any relay serves)

Not yet run on Fly with an image built from `main`: on Fly, steps 3 and 4 have
succeeded only with the diagnostic image of M6-C73. The steps are the ones the
local proof runs (section 7).

**Costs money: a few seconds of a `shared-cpu-1x` machine each**, well under
one cent in total. Each step runs the image's entrypoint in a one-off machine
of the relay app. The machine gets the app's secrets and reaches Redis over
the private network, and it has no services, so nothing public reaches it.

**`fly machine run` returns once the machine has started, not when it has
finished.** So each step runs the machine detached under a fixed name, finds
its ID by that name, waits for it to stop, reads its log and exit status, and
destroys it. Do not start a step until the one before it has printed its
success line.

**Everything after `--` is the relay's command line.** Without it, flyctl
reads the relay's own flags (`--dry-run`) as its own and refuses them with
`Error: unknown flag` before creating anything. The `mid` helper needs `jq`;
if it prints `STOP`, do not go on: `fly logs --machine ""` waits forever.
Machine names must be unique in the app, so destroy each step's machine before
reusing its name.

```text
cd ~/agentuplink-fly
IMAGE=registry.fly.io/agentuplink-relay:fly-1
mid() {
  ID=$(fly machine list -a agentuplink-relay --json | jq -r --arg n "$1" '.[] | select(.name == $n) | .id')
  if [ -n "$ID" ]; then echo "ID=$ID"; else echo "STOP: no machine named $1"; fi
}

# Step 1, validates only and writes nothing.
fly machine run $IMAGE --name step1 -a agentuplink-relay -r syd --restart no --detach \
  -- check-serve-config
mid step1
fly machine wait $ID -a agentuplink-relay --state stopped
fly logs -a agentuplink-relay --machine $ID --no-tail
fly machine status $ID -a agentuplink-relay
fly machine destroy $ID -a agentuplink-relay
```

Success is `Relay serving configuration is valid: consumer_bind=0.0.0.0:8443
device_bind=0.0.0.0:9443 cluster=absent recovery=absent.` in the log, and an
exit code of `0` in the status events. Step 2 checks the records against the
same configuration without contacting Redis:

```text
# Step 2, validates the records only and writes nothing.
fly machine run $IMAGE --name step2 -a agentuplink-relay -r syd --restart no --detach \
  --file-local /tmp/provision/catalog.toml=catalog.toml \
  --file-local /tmp/provision/device-cert.pem=device-cert.pem \
  -- provision-catalog /tmp/provision/catalog.toml --dry-run
mid step2
fly machine wait $ID -a agentuplink-relay --state stopped
fly logs -a agentuplink-relay --machine $ID --no-tail
fly machine destroy $ID -a agentuplink-relay
```

Success is `Provisioning records are valid for namespace <your namespace>:
...`, ending `This dry run contacted no Redis authority and wrote nothing.`
Steps 3 and 4 write Redis, in this order:

```text
# Step 3, writes the incarnation.
fly machine run $IMAGE --name step3 -a agentuplink-relay -r syd --restart no --detach \
  -- activate-first-incarnation
mid step3
fly machine wait $ID -a agentuplink-relay --state stopped
fly logs -a agentuplink-relay --machine $ID --no-tail
fly machine status $ID -a agentuplink-relay
fly machine destroy $ID -a agentuplink-relay
```

Success is `Activated deployment incarnation <incarnation> as the first
incarnation of namespace <namespace>.`

```text
# Step 4, writes the catalog records.
fly machine run $IMAGE --name step4 -a agentuplink-relay -r syd --restart no --detach \
  --file-local /tmp/provision/catalog.toml=catalog.toml \
  --file-local /tmp/provision/device-cert.pem=device-cert.pem \
  -- provision-catalog /tmp/provision/catalog.toml
mid step4
fly machine wait $ID -a agentuplink-relay --state stopped
fly logs -a agentuplink-relay --machine $ID --no-tail
fly machine status $ID -a agentuplink-relay
fly machine destroy $ID -a agentuplink-relay
fly machine list -a agentuplink-relay
```

Success is `Provisioned namespace <namespace> for deployment incarnation
<incarnation>: ...`. **The machine list must be empty before section 6.3:**
`fly deploy` would update a leftover one-off machine into a second relay.

**Which failures can be repeated.** Every step prints `tunnel-relay: ...` and
exits `1` on failure. Read the message before running anything again:

| Step | Failure | Repeat? |
| --- | --- | --- |
| 1, 2 | any | Yes. Neither contacts Redis. Fix `relay.toml` (then rebuild, section 6.1) or the records, and run it again. |
| any | the entrypoint names a missing or invalid secret | Yes. Nothing ran. Fix the secret with `fly secrets import --stage` and run it again. |
| 3 | `Redis catalog connection failed; stage=... class=...` | Yes. Every connection failure happens before the activation script runs, and the script checks the namespace is empty and writes both keys together, so nothing was written. The words say which failure it was (M6-C72): `class=auth` is a password that does not match Redis's, `class=tls_certificate` a CA that did not sign Redis's certificate, `class=dns` a host name that does not resolve, `class=timeout` a connection that did not open within 10 s (M6-C73). Fix that and retry; section 6.2.1 confirms it from Redis's side. An image from before PR #97 printed `stage=authority_connection` and nothing else for all of these. |
| 3 | "namespace already has a deployment incarnation" | Do not repeat. If an earlier run of step 3 printed its success line, or its outcome is unknown and this is the rerun, the incarnation is written: go on to step 4. Otherwise the namespace was used before: choose a new one (section 6.4.1). |
| 3 | "namespace is not empty" | No. Choose a new namespace. |
| 4 | fails connecting to Redis, or at `stage=authority_identity` because step 3 has not succeeded | Yes. `provision-catalog` makes the same connection and incarnation check as `serve` before it writes anything (`crates/tunnel-relay/src/provisioning.rs`, `provision_catalog`). |
| 4 | "invalid provisioning records" or "invalid device certificate" | Yes. These are checked before Redis is contacted. |
| 4 | "namespace was already provisioned" | No. The one-shot reservation is taken before any record is written, so this means an earlier run got at least that far. If that run printed `Provisioned namespace`, you are done. If its outcome is unknown, or it failed part-way, the namespace may be partly written and nothing shipped repairs it (M6-C35): choose a new namespace. |
| 4 | "namespace holds records other than its active incarnation" | No. Something wrote the namespace between steps 3 and 4, for example a relay started too early (M6-C34). Choose a new namespace. |

Stopping a step's machine part-way is also covered by the binary: a writing
command finishes its current bounded Redis step on the first stop signal and
exits with its own outcome; a second signal abandons it with exit `130`, and
the namespace must then be treated as partial ([operator.md section 2.3](operator.md#23-tenant-scoped-authorization-and-the-first-incarnation)).

#### 6.2.1 When step 3 or 4 cannot reach Redis

The relay's `class=` says which failure it was (M6-C72; operator.md section
2.4 lists the words). These two checks confirm it from Redis's side and from
the relay's secrets, without changing anything that step 3 or 4 wrote. They
were written when the relay printed only `stage=authority_connection`.

**What Redis saw**, read on the Redis machine; this does not restart it. Open
a shell there, then run the second line inside it (it reads the password from
Redis's own configuration, so it never appears on a command line):

```text
fly ssh console -a agentuplink-redis
REDISCLI_AUTH=$(sed -n "s/^requirepass //p" /run/agentuplink-redis/redis.conf) redis-cli --tls --insecure --no-auth-warning INFO stats | grep -E "^(total_connections_received|acl_access_denied_auth):"
```

Then, back on the Mac, `fly logs -a agentuplink-redis --no-tail`.

Measured locally against this image: `acl_access_denied_auth` goes up by one
for each attempt with a wrong password. `total_connections_received` counts
only connections that completed TLS: a correct relay attempt adds about seven
(its main connection and lanes), a wrong password adds one, and a bare TCP
connect (the health check) or a failed TLS handshake adds none. A TLS
verification failure appears in the Redis log as `Error accepting a client
connection: ... alert unknown ca`; an unresolvable name or a connection that
never arrives leaves no trace in either.

**What the relay's secrets can do**, from a one-off machine in the relay app
using the Redis image (it has `redis-cli`), with the relay's own
`AT_REDIS_URL` and `AT_REDIS_CA_B64`. **Costs money: a few seconds of a
machine.** It prints the host, the password's length and never its value, how
long the name took to resolve, then a `PING` and Redis's `run_id`:

```text
fly machine run docker.io/library/redis:8.4.0-alpine --name probe -a agentuplink-relay -r syd --restart no --detach \
  --entrypoint sh -- -c 'printf %s "$AT_REDIS_CA_B64" | base64 -d > /tmp/ca.pem; rest="${AT_REDIS_URL#rediss://}"; creds="${rest%%@*}"; export REDISCLI_AUTH="${creds#:}"; hostport="${rest#*@}"; host="${hostport%%:*}"; echo "host=$host password_chars=${#REDISCLI_AUTH}"; time getent hosts "$host"; redis-cli --tls --cacert /tmp/ca.pem --sni "$host" -h "$host" -p 6379 --no-auth-warning PING; redis-cli --tls --cacert /tmp/ca.pem --sni "$host" -h "$host" -p 6379 --no-auth-warning INFO server | grep -E "^(run_id|redis_version):"'
mid probe
fly machine wait $ID -a agentuplink-relay --state stopped
fly logs -a agentuplink-relay --machine $ID --no-tail
fly machine destroy $ID -a agentuplink-relay
```

| Probe prints | Meaning |
| --- | --- |
| `PONG` and a `run_id` | The relay's secrets, the name and the network are fine; the fault is inside the relay process. Stop and report it. |
| `AUTH failed: WRONGPASS ...` | `AT_REDIS_URL`'s password is not Redis's `REDIS_PASSWORD`. Re-import the relay's `AT_REDIS_URL` from the same `redis-password.txt` (section 4) and retry step 3. |
| `SSL_connect failed: certificate verify failed` | `AT_REDIS_CA_B64` is not the CA that signed Redis's certificate. Re-import it and retry. |
| no address from `getent`, or a long `time` | Name resolution; check the host in `AT_REDIS_URL` against the Redis app's name. A first lookup of about 2 s on a fresh machine is normal on Fly and is what M6-C73 fixes. |

The image is named by tag and is therefore not pinned: `fly machine run`
refused `redis:8.4.0-alpine@sha256:...` (a tag and a digest together) as "not
a valid image", and a digest-only reference has not been tried. It is the
same Redis the Redis app runs. `time` is BusyBox's, which reports to 10 ms;
the image's `date` has no `%N`, so do not time with `date`.

The first three outputs were produced locally with this probe, with the
relay's real secrets and a wrong password and a wrong CA substituted (log
nonce `m6c60-diag-20260923T102308Z-27180`). Every one of these
failures happens before the activation script runs, so step 3 is safe to
retry after the fix.

`fly ssh console` is not an option at this point: there is no relay machine
to connect to, because `serve` refuses to start on a namespace with no
incarnation, and a relay started between steps 3 and 4 can leave the
namespace unprovisionable (M6-C34).

Three things here were not measured on Fly. That the one-off machines receive
the app's secrets rests on Fly's documentation: "An app's secrets are
available as environment variables at runtime on every Machine belonging to
that Fly App, whether the Machine is managed by Fly Launch or not"
(<https://fly.io/docs/apps/secrets/>). They do **not** receive `fly.toml`'s
`[env]`: "fly machine run doesn't read your fly.toml" (Fly staff,
<https://community.fly.io/t/why-does-fly-machine-run-shell-see-secrets-but-not-the-environment/25793>),
which is why the namespace and incarnation are baked into the image rather
than set in `[env]`. The positional command replacing the image's `CMD` while
keeping its `ENTRYPOINT` is the documented shape `fly machine run <image>
[command]`. And that `fly machine status` lists the exit code among its events
is from flyctl's behaviour as generally documented, not from a run here; the
log's success line is the check that matters.

### 6.3 Serve

**First, remove every leftover one-off machine.** A machine that a failed or
retried step left behind stays in the app, stopped, and `fly deploy` updates
every machine of the app into a relay, so a leftover becomes a second relay
(this happened on the first real run: two stopped leftovers). List them and
destroy each one by ID:

```text
fly machine list -a agentuplink-relay --json | jq -r '.[] | "\(.id) \(.name) \(.state)"'
fly machine destroy <id> -a agentuplink-relay
fly machine list -a agentuplink-relay
```

No `--force`: a leftover is stopped, and `destroy` without it refuses a
running machine, so a mistyped ID cannot kill the serving relay. Before the
first deploy the list must be empty. On a later redeploy it must
hold only the serving relay, whose name Fly chose at its first deploy.

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
even when Redis is unusable (M6-C67), so the echo is the check.
On the then-live relay (`main-721ed2a`), 150 sequential echoes on one device
session all returned `200` with the canary, past the old 128-request limit
(M7-C92; measured by the coordinator on 2026-09-23).

**Upgrade to `main-af23c2f` (2026-09-24, measured by the coordinator).**
Before touching Fly, the upgrade was rehearsed locally. A namespace was
provisioned by the `721ed2a` binaries on a Redis configured like the Fly
Redis entrypoint of that time (`88f71e2`). A relay built from `af23c2f` with continuity at 5 s then
served it without re-provisioning. Old and new clients echoed, and the
relay survived a `docker restart` and a `docker kill`. Rolling back to
the `721ed2a` relay also worked. On Fly:
- A read-only `CONFIG GET` on the Redis machine returned `appendonly yes`,
  `appendfsync always` and `no-appendfsync-on-rewrite no`. With any other
  values the new relay exits with `class=persistence`.
- The image was built by section 6.1 with `--image-label main-af23c2f`
  (`registry.fly.io/agentuplink-relay:main-af23c2f@sha256:e6ac84d4bb660f3eec52eeb0730a264f1635a6369545133bee97c9dc1e76723c`).
- Section 6.3's `fly deploy --image …main-af23c2f --ha=false` updated the
  one relay machine in place.
- The log showed `tunnel-relay listening: consumer=0.0.0.0:8443
  device=0.0.0.0:9443` and then `tunnel-relay Redis restart continuity:
  interval_seconds=5`, and both checks passed.
- From the Mac, with a `tunnel-client` built from `af23c2f`: `/readyz`
  returned `200`, the device reached `active`, and 150 of 150 echoes on
  one session returned `200`.
- After `fly machine restart --signal SIGTERM`, the device went through
  `backoff`, `reconnecting`, `reconnected` and `ready` on its own. The
  second echo attempt returned `200`, 4 s after the restart.
- An in-place restart of the Fly Redis machine has not been exercised on
  Fly. The local rehearsal and the M6-C65 gate are the evidence for it.
- Rollback: `fly deploy . --config deploy/fly/relay/fly.toml --image
  registry.fly.io/agentuplink-relay:main-721ed2a --ha=false`. That image
  has no M6-C65, so after a rollback any Redis restart ends the namespace
  (section 6.4.1).
- The entrypoint of `main-af23c2f` accepts only `serve`,
  `check-serve-config`, `activate-first-incarnation`, `provision-catalog`
  and `rebind-redis-run`, so with that image the catalog commands (M6-C31)
  cannot run through `fly machine run`. An image built from a commit with
  M6-C91 accepts them in a one-off machine (section 6.6).

**Restarting the relay.** Use `--signal SIGTERM`, which is the signal Fly
sends on a deploy or a stop (`kill_signal` in `fly.toml`):

```text
fly machine restart <id> -a agentuplink-relay --signal SIGTERM
fly logs -a agentuplink-relay --no-tail
```

The log shows `tunnel-relay stopping: signal=SIGTERM` and then `tunnel-relay
stopped: signal=SIGTERM`. `fly machine restart` sends SIGINT unless told
otherwise; the relay handles SIGINT the same orderly way (measured on Fly:
`stopping`, `stopped`, exit `0`), but SIGTERM is the production path. A
restart ends every device session, and the device reconnects by itself if
its `tunnel-client` comes from a release that has reconnect (`main` at or
after PR #94, M6-C23). **The device bundle must come from such a release.**
From the coordinator's `fly logs` and `connect --json` output on
2026-09-23:

- With a `tunnel-client` release build from `721ed2a`, `fly machine restart
  <relay machine id> --signal SIGTERM` logged `stopping: signal=SIGTERM`,
  `stopped: signal=SIGTERM` and then `listening`. The device's
  `connect --json` output went `TRANSPORT_ERROR`, backoff, `reconnecting`,
  `reconnected`, `ready`, then a status line with
  `"command":"connect-status"` and `"phase":"active"`, without the device
  being restarted, and the first echo afterwards returned `200`.
- With the first run's bundle from `8dad443`, which predates reconnect, the
  device exited `4`, `TRANSPORT_ERROR` "control read failed", and had to be
  started again. That is the bundle in `~/agentuplink-fly/agentuplink-bundle`;
  replace it with one built from a release that includes reconnect.

**Upgrading the relay image, same namespace.** Build the new image with its
own label (section 6.1) and deploy it exactly as above with that label. The
namespace, the incarnation and Redis are untouched, so there is nothing to
provision again. This was measured on 2026-09-23, when the relay moved from
the diagnostic image to `main-721ed2a`: `fly deploy --image
registry.fly.io/agentuplink-relay:main-721ed2a --ha=false` updated the relay
machine in place. The coordinator's `fly logs` output shows the old relay's
`Main child exited normally with code: 0` at 12:51:07Z, then `reboot:
Restarting system`; `Preparing to run: ... serve` at 12:51:09Z and `tunnel-relay
listening: consumer=0.0.0.0:8443 device=0.0.0.0:9443` in the same second, on a
fresh VM; and both checks logged failing at 12:51:09Z and passing at
12:51:10Z. It ends the device sessions like any restart. Change
`redis_namespace` or `deployment_incarnation` only when section 6.4.1 says so:
a new value in `relay.toml` needs section 6.2 again.

### 6.4 After a Redis restart

A Redis restart gives Redis a new `run_id`, and the relay's namespace is bound
to the old one. Restarts happen on Fly host maintenance, on a crash, on any
`fly deploy` of the Redis app, and on `fly secrets import` for the Redis app
without `--stage` (which restarts its machine to apply the secret). The
binding is a fence against a Redis that came back without its data, from an
older snapshot, or as another machine, so the relay needs proof the data
survived before it serves again ([operator.md](operator.md) section 4, "Redis
restarts", M6-C65). **All of this needs a relay image built from a commit
with M6-C65**; `main-721ed2a` does not have it, and with that image the only
way back is section 6.4.1. The Redis image is unchanged.

This is for the one Redis machine restarting on its own volume. There is no
replica here; a Redis rebuilt on a new volume, or a volume restored from a
Fly snapshot, is not a restart: section 6.4.1.

**The relay kept running across the restart.** `relay.toml` sets
`redis_restart_continuity_seconds = 5`. The relay checks with `CONFIG GET`,
when it starts and again before each re-binding, that Redis runs `appendonly
yes`, `appendfsync always` and `no-appendfsync-on-rewrite no`, and refuses
otherwise (`class=persistence`); it also reads them on the running Redis after
every token, so a runtime `CONFIG SET` downgrade is caught too. Do not change
them at runtime. The Redis entrypoint sets the first two;
`no-appendfsync-on-rewrite no` is Redis's default and is set explicitly only
from this commit on, so the running Fly Redis gets the explicit line at its
next rebuild. A read-only `CONFIG GET` on the running Fly Redis on 2026-09-24
returned `appendonly yes`, `appendfsync always` and
`no-appendfsync-on-rewrite no` (section 6.3).
Once Redis is back from its AOF, the relay re-binds the namespace by itself,
and `fly logs -a agentuplink-relay --no-tail` shows `tunnel-relay: Redis
authority restarted; namespace re-bound to the new Redis run`. Device
sessions end with `AUTHORITY_UNAVAILABLE` when Redis goes away, and devices
reconnect by themselves; a reconnect can wait out the previous session's
owner lease, up to 30 s. Measured locally with `docker restart` and with
`docker kill` then `docker start` of an AOF Redis and the shipped binaries
(`scripts/m6-redis-restart-verify.sh`): the echo was served again 0.3 to 54 s
after the restart, from the same relay process. **Not run on Fly.** Each re-binding attempt is a lane reconnect, which has 2 s including
the DNS lookup of `agentuplink-redis.internal` (M6-C74); a lookup slower than
that fails the attempt and the relay tries again on its next token, every
5 s. While Redis is down or refused, `/readyz` still answers ready (M6-C67)
and every consumer call gets `503` `AUTHORIZATION_UNAVAILABLE`.

If the log shows `tunnel-relay: Redis authority continuity check failed;
stage=authority_identity class=continuity` instead, Redis came back older
than the relay's last acknowledged token -- an older snapshot, or lost data.
The relay keeps refusing that run even if you re-attest it; do not run the
command below. `class=persistence` means the Redis configuration lost
`appendfsync always` or one of the other two settings: fix the Redis image
and restart it. Go to section 6.4.1
(or restore Redis properly and recover). `class=unbound` means Redis came back
empty: section 6.4.1.

**The relay started after the restart** (both machines moved, a crash, a
deploy). It exits `1` each time with `tunnel-relay: Redis catalog connection
failed; stage=authority_identity class=run_changed`. The `[[restart]]` policy
tries 10 times and then leaves the machine **stopped**: `fly machine list`
shows it `stopped`, and `min_machines_running = 1` does not start it (that
setting governs auto-stop, which is off). A fresh relay has no token to
compare, so you re-attest the namespace once. First check that Redis restarted
from its own volume: `fly machine list -a agentuplink-redis` shows the same
machine, and `fly volumes list -a agentuplink-redis` the same volume, as
before; no volume was restored from a snapshot. Then, like section 6.2's
steps:

```text
cd ~/agentuplink-fly
IMAGE=registry.fly.io/agentuplink-relay:fly-1   # the image the relay runs
fly machine run $IMAGE --name rebind -a agentuplink-relay -r syd --restart no --detach \
  -- rebind-redis-run --redis-restarted-in-place
mid rebind
fly machine wait $ID -a agentuplink-relay --state stopped
fly logs -a agentuplink-relay --machine $ID --no-tail
fly machine status $ID -a agentuplink-relay
fly machine destroy $ID -a agentuplink-relay
fly machine list -a agentuplink-relay
fly machine start <relay machine id> -a agentuplink-relay
```

Success is `Re-bound namespace <namespace> (deployment incarnation
<incarnation>) from Redis run <old> to <new>, on the operator's declaration that
Redis restarted in place; not verified.` (or `... already bound to Redis
run <run>; nothing changed.`), exit `0`. `--redis-restarted-in-place` is your
declaration that Redis was not restored or replaced: the command refuses an
empty Redis (`class=unbound`) but cannot tell a restore of an older snapshot
from a restart, and re-binding a restored Redis would bring back whatever it
held, such as a revoked grant. After a restore, use section 6.4.1. The
command was run locally against a restarted Redis by
`scripts/m6-redis-restart-verify.sh`, not on Fly; the entrypoint's
`rebind-redis-run` case is new with M6-C65 and was checked with `sh -n` only.

#### 6.4.1 A new namespace

For a Redis that came back empty or older, or a relay image without M6-C65,
the way back is a new namespace. Redis's data and the device's key,
certificate and profile are all kept:

1. Stop the relay if it is still running, so nothing is served while you
   work: `fly machine stop <id> -a agentuplink-relay`.
2. Edit `redis_namespace` and `deployment_incarnation` in
   `deploy/fly/relay/relay.toml` to values never used before.
3. Section 6.1 with a new `--image-label` (for example `fly-2`).
4. Section 6.2 with that label: all four steps, with the same `catalog.toml`
   and `device-cert.pem`. The UUIDs can be reused because the records go into
   the new namespace.
5. Section 6.3 with that label. If `fly machine list` then shows the relay
   `stopped`, start it with `fly machine start <id> -a agentuplink-relay`.
6. Reconnect the device and repeat the echo.

The old namespace's keys stay in Redis; nothing shipped removes them.

### 6.5 Certificate expiry and rotation

Section 3.1 issues the relay's server certificate for 90 days and the CAs for
365. Nothing here renews anything. Read from the code, not measured:

- **The relay's server certificate** (`relay-server.pem`) expires on day 91.
  The relay keeps serving it; every new TLS handshake from a device or a
  consumer is then refused by the client, because rustls checks the validity
  window. `connect` fails to reach the relay, and `curl` reports an expired
  certificate. Sessions already open are not affected until they reconnect.
  To rotate: issue a new `relay-server.pem` from the same `relay-ca.pem`
  (section 3.1's `server_cert` line) and set the four relay certificate
  secrets again with `fly secrets import -a agentuplink-relay` **without**
  `--stage`. That restarts the relay machine, which ends every device session;
  devices must reconnect. Redis is not touched, so the namespace survives.
- **The Redis server certificate** (`redis-server.pem`) is checked by the
  relay each time it opens a Redis connection. After it expires, a relay that
  (re)connects to Redis fails its TLS handshake. Rotating it means
  `fly secrets import -a agentuplink-redis`, which restarts Redis, **which is
  a Redis restart (section 6.4)**. With a relay image that has M6-C65 the
  running relay re-binds the namespace by itself once Redis is back with its
  AOF; with an older image the namespace can no longer be served and a new one
  must be provisioned (section 6.4.1). Plan it as maintenance either way. For
  that reason section 3.1 issues the Redis certificate for 365 days, as long
  as its CA.
- **The CAs** expire on day 366. A new relay CA must also be imported into
  every device (`credentials import --server-ca`).
- **The device certificate** carries the validity your issuer gave it, and
  `provision-catalog` copies that window into the credential record. After it
  expires the relay refuses the device. Renewing the certificate of the
  *same* device is not implemented (M6-C56). A new key and certificate can be
  registered as a **new device**, with a new device UUID, by `tunnel-relay
  add-device` (with `add-service` and `set-grant` for its export and grant)
  on the running relay, and the old device revoked with `revoke-device`
  ([operator.md section 2.5](operator.md), M6-C31). The device profile's
  `device_id` and export names change to the new UUIDs; the namespace is
  kept. On Fly, each of those commands runs in a one-off machine exactly as
  section 6.6 shows (its "Revocation" part has `revoke-device`). The relay
  entrypoint accepts them from the commit that adds section 6.6 on (M6-C91);
  an image built before that, including `main-af23c2f`, refuses them with
  `unknown command`.

### 6.6 Day-2 catalog changes: onboarding a tester, and revocation

**Not yet run on Fly** (M6-C91). The route is proven locally by
`deploy/fly/local-proof.sh` (section 7): with `serve` running, each command
ran in a one-off container of the relay image through its entrypoint, with its
records copied in, and the new tester's echo succeeded.

The seven catalog commands of [operator.md section 2.5](operator.md) (`add-user`,
`add-device`, `add-service`, `set-grant`, `revoke-grant`, `revoke-device`,
`revoke-credential`) change the namespace **while the relay serves**, with no
restart and no redeploy. On Fly each one runs like section 6.2's steps: in a
one-off machine of the relay app, which gets the app's secrets, reaches Redis
over the private network, has no services, and is destroyed afterwards. The
entrypoint writes the same secret files and the same configuration as `serve`,
then runs `tunnel-relay COMMAND --config <that configuration> ARGS...`, passing
each argument after `--` unchanged. Do not pass `--config`; the entrypoint
refuses it. Records files and certificates reach the machine with
`--file-local`, as in section 6.2. The records are not secret.

**Why a one-off machine and not `fly ssh console`.** The one-off machine is
the path section 6.2 already uses on Fly, runs as the image's `relay` user, and
leaves nothing behind once destroyed. A console session on the serving relay
would need the records copied onto it, and running the entrypoint there would
rewrite the secrets directory the running relay reads.

**Use the image the relay serves**, built from a commit with M6-C91. The
`redis_namespace` and `deployment_incarnation` baked into it are what the
command writes to; a command run with another image's values is refused
(`the relay configuration's incarnation is not active`) or goes to another
namespace. The relay now serves `main-af23c2f`, which has no M6-C91: build a
new image (section 6.1) and upgrade the relay to it (section 6.3, "Upgrading
the relay image"), then use that label here. The catalog code did not change
between `af23c2f` and M6-C91; only the entrypoint did.

**Costs money: a few seconds of a `shared-cpu-1x` machine per command**,
well under one cent each ($0.00000095 a second in `syd`, section 8). Creating
the records and the device credential is local and free.

**Destroy every one-off machine.** A leftover machine becomes a second relay
at the next `fly deploy` (section 6.3). The helper below destroys the machine
whether the command succeeded or not; check `fly machine list -a
agentuplink-relay` shows only the serving relay when you finish.

The helper is section 6.2's five commands in order. It needs `jq`. It stops if
the machine did not start or cannot be found. The command's exit code is in
the `fly machine status` events: `0` for success, `1` for any refusal, and the
log line names the reason:

```text
cd ~/agentuplink-fly
IMAGE=registry.fly.io/agentuplink-relay:<label the relay serves>
# oneoff NAME [--file-local /tmp/provision/FILE=LOCAL]... -- COMMAND ARGS...
oneoff() {
  name=$1; shift
  fly machine run "$IMAGE" --name "$name" -a agentuplink-relay -r syd --restart no --detach "$@" \
    || { echo "STOP: $name did not start"; return 1; }
  ID=$(fly machine list -a agentuplink-relay --json | jq -r --arg n "$name" '.[] | select(.name == $n) | .id')
  [ -n "$ID" ] || { echo "STOP: no machine named $name"; return 1; }
  fly machine wait "$ID" -a agentuplink-relay --state stopped
  fly logs -a agentuplink-relay --machine "$ID" --no-tail
  fly machine status "$ID" -a agentuplink-relay
  fly machine destroy "$ID" -a agentuplink-relay
}
```

#### Onboarding a tester

Free, on the Mac: the tester's user, device and grant. The tester creates the
device key and certificate request on their own machine with
`tunnel-client credentials create`, exactly as in [operator.md section
2.1](operator.md#21-device-credentials), with their own device UUID and export
(service) UUID in the profile, and sends you only the request. Sign it with
`device-ca.pem` (section 3.1) and a `urn:agent-tunnel:device:<device UUID>`
SAN, and send back the certificate and `relay-ca.pem`. Then write the four
records documents in `~/agentuplink-fly/tester-2/`, as in [operator.md section
2.5](operator.md): `user.toml` (the tenant of `catalog.toml`, a new user UUID,
and the `sub` your issuer gives the tester as `oidc_subject`), `device.toml`
(owner = the new user, `certificate = "device-cert.pem"`), `service.toml` and
`grant.toml`, with the signed certificate beside them as `device-cert.pem`.
The files go to the same directory in the machine, so the relative
`certificate` path still works.

**Costs money: four or five one-off machines, a few seconds each.** First
the dry run, which checks every document against the image's configuration and
contacts no Redis, then the four writes in this order:

```text
cd ~/agentuplink-fly/tester-2
oneoff user2-dry --file-local /tmp/provision/user.toml=user.toml \
  -- add-user --records /tmp/provision/user.toml --dry-run
oneoff user2 --file-local /tmp/provision/user.toml=user.toml \
  -- add-user --records /tmp/provision/user.toml
oneoff device2 --file-local /tmp/provision/device.toml=device.toml \
  --file-local /tmp/provision/device-cert.pem=device-cert.pem \
  -- add-device --records /tmp/provision/device.toml
oneoff service2 --file-local /tmp/provision/service.toml=service.toml \
  -- add-service --records /tmp/provision/service.toml
oneoff grant2 --file-local /tmp/provision/grant.toml=grant.toml \
  -- set-grant --records /tmp/provision/grant.toml
fly machine list -a agentuplink-relay
```

Success lines: `Catalog change is valid for namespace ... This dry run
contacted no Redis authority and wrote nothing.` for the dry run, `Added to
namespace ...` for each addition, and `Added grant ... revision=1` for the
grant. **Keep `add-device`'s log line:** its `credential=` is what
`revoke-credential` needs, and nothing lists credentials. A refusal exits
`1` and names the record, for example `add-user refused for user ...: catalog
conflict: user already exists`; nothing was written, so fix the document and
run that step again. Each write is one Redis script, so it happened completely
or not at all.

The tester then runs `tunnel-client connect` with their profile, and a token
from your issuer with their `sub` and `echo:invoke` gets `200` from the echo
of section 6.3 on their device and service. Nothing on the relay restarts.

#### Revocation

**Costs money: one one-off machine, a few seconds.** Revocations take
identifiers, not documents, so there is no `--file-local`. Each one has a
`--dry-run` too. Use the one you need:

```text
# The grant only: the next request is refused (403 or 404).
oneoff revoke1 -- revoke-grant --tenant <tenant> --user <user> --device <device> --service <service>
# The whole device, every credential and grant it has; its live session closes
# with AUTHORIZATION_REVOKED within about a second.
oneoff revoke1 -- revoke-device --tenant <tenant> --device <device>
# One credential, for example a lost key: the credential= from add-device.
oneoff revoke1 -- revoke-credential --tenant <tenant> --device <device> --credential <credential>
fly machine list -a agentuplink-relay
```

Each prints what it revoked. A revoked device or credential cannot be
reactivated, and a revoked device's UUID cannot be added again: give a
replacement a new UUID. Changing or deactivating a user is not supported in
this alpha ([operator.md section 2.5](operator.md)); to cut a tester off, revoke
their grants or their devices.

### 6.7 Teardown

Irreversible, and the only way to stop all charges. The IPv4, the volume and
its snapshots, and the machines go with their app:

```text
fly apps destroy agentuplink-relay
fly apps destroy agentuplink-redis
fly apps list
```

`fly apps list` should then show no app of yours. If it shows a
`fly-builder-...` app, a classic remote builder was created for your
organization; destroy it the same way.

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

Since M6-C91 it also runs section 6.6 while the relay serves: every catalog
command with `--dry-run`, then `add-user`, `add-device`, `add-service` and
`set-grant` for a second tester with a second device certificate from the
proof's device CA, that tester's echo, `revoke-grant`, `revoke-device` and
`revoke-credential`, each in a one-off container through the entrypoint, with
its exit code checked. It also checks that an unknown command and a `--config`
argument are refused. `PROOF_PREFIX` names the containers, network and volume
(default `m6c60`).

```text
TUNNEL_CLIENT=/path/to/tunnel-client deploy/fly/local-proof.sh
```

Measured on the committed tree: log nonce
`m6c60-proof-20260923T093131Z-75524`, head `b459155`, 0 uncommitted paths,
arm64 images (relay `73077e81d2f2`, Redis `72c903b23e8d`). Earlier runs during
development differ only in the stop time.

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
| `docker stop -t 60` on the relay with the device connected | `tunnel-relay stopping: signal=SIGTERM`, `stopped: signal=SIGTERM`, exit `0`, 407 ms |
| The device when the relay stopped | exit `4`, `TRANSPORT_ERROR`, retryable |
| A second relay on the same Redis | serves; the device reconnects and echoes |
| `docker stop` on Redis | exit `0`, "Redis is now ready to exit" |
| The running relay while Redis is down, and after Redis restarted with a new `run_id` (AOF kept 24 keys) | `/readyz` ready both times; echo `503` `AUTHORIZATION_UNAVAILABLE`, `not_dispatched`; the device session ended, exit `4` |
| A fresh relay on the restarted Redis | exit `1`, `Redis catalog connection failed; stage=authority_identity` |
| Memory with one device connected (`docker stats`) | relay 2.6 MiB, Redis 6.1 MiB |

**Re-run for M6-C91** on the committed tree: log nonce
`m6c60-proof-20260924T111646Z-86279`, head `332cf39`, 0 uncommitted paths,
arm64 relay image `ddb0496c8ea8`, a `tunnel-client` built from the same tree,
exit `0`. Every check above that the script asserts passed again. Two rows of
the table above describe the older binaries and are superseded by this run:
a device with reconnect (M6-C23) does not exit when the relay stops, so the
proof now gives it 5 s and then stops it (M6-C92; it printed `sent it
SIGTERM`, device exit `130`); and with M6-C65 a fresh relay on the restarted
Redis kept running (`Redis restart continuity: interval_seconds=5`). The day-2
phase, each command in its own one-off container, with `serve` running:

| Check | Result |
| --- | --- |
| An unknown command; `add-user ... --config ...` | both refused by the entrypoint, exit `1` |
| All seven catalog commands with `--dry-run` | exit `0`, each `This dry run contacted no Redis authority and wrote nothing.` |
| `add-user`, with a records path holding a space, `$(...)`, a backquote and a quote | exit `0`; the same again exit `1`, `catalog conflict: user already exists` |
| `add-device` (certificate from the proof's device CA), `add-service`, `set-grant` | exit `0` each; the grant `revision=1` |
| The new tester's echo through the new device | HTTP 200, body = canary + payload, no relay restart |
| `revoke-grant`, then that echo | exit `0`; HTTP 404 `DEVICE_NOT_FOUND` |
| `revoke-device` | exit `0`; the device's session ended and its reconnect was refused, `connect` exit `3`, `CREDENTIAL_ERROR` |
| `revoke-credential` of a third device's credential, then again | exit `0`; exit `1`, `no active credential` |
| The first tester's echo afterwards | HTTP 200 |
| Key lines or the Redis password in any day-2 output; a leftover one-off container | none; none |

**The day-2 phase can go red.** With the relay image's entrypoint replaced by
the one before M6-C91 (`PROOF_SKIP_BUILD=1 RELAY_IMAGE=...`, log nonce
`m6c60-proof-20260924T111650Z-86369`), the first catalog command answered
`unknown command 'add-user'` and the proof stopped at `FAILED no --config
refusal`, exit `1`.

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

### 7.1 amd64

Fly runs amd64; this Mac is arm64. The Dockerfile names no platform, so the
same file builds natively for arm64 here and natively for amd64 on Fly's
remote builder. Building it here with `--platform linux/amd64` runs the whole
release compile under QEMU: stopped after 1,008 s at `sha1_smol`, which the
native build reaches at 56 s of 172 s, so it projected to roughly 50 minutes.

A cross-compile instead, as a check only (not committed, and not what Fly
builds): the same `rust:1.95.0` builder running natively, with
`gcc-x86-64-linux-gnu`, `libc6-dev-amd64-cross`, the
`x86_64-unknown-linux-gnu` target and
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc`, then
`cargo build --locked --release -p tunnel-relay --target x86_64-unknown-linux-gnu`.
It finished in 1 m 42 s (log nonce `m6c60-cross-amd64-20260923T093413Z-77648`,
`b459155`), produced an `ELF 64-bit LSB pie executable, x86-64` dynamically
linked against `/lib64/ld-linux-x86-64.so.2`, and that binary, run in an amd64
`debian:trixie-slim` container, passed `check-serve-config` on this
`relay.toml`. That shows the tree compiles, links and starts for amd64 against
the runtime image's glibc. It does not show the amd64 image Fly will build,
which is built from the committed Dockerfile on Fly's builder.

## 8. Cost list

Prices from <https://fly.io/docs/about/pricing/>, read 2026-09-23. Machine
prices are per region: the page has one table per region, and a script scales
a base price by a per-region `markup_ratio`. **The machine figure, worked
out:** `iad` has ratio `1` and lists `shared-cpu-1x` 256 MB at $1.94 a month
($0.00000075 a second). `syd` has ratio `1.269230769`, and
$1.944 × 1.269230769 = $2.467, which is the $2.47 (`$0.00000095` a second)
the `syd` table lists. The page's first table, for `ams` (ratio
`1.038461538`), lists $2.02 ($0.00000078 a second); that is not the base, so
$2.02 × 1.2692 = $2.56 over-counts. Monthly figures are Fly's own 30-day
figures ($ per second × 2,592,000).

| Resource | Created by | Price | Monthly |
| --- | --- | --- | --- |
| Dedicated IPv4 on `agentuplink-relay` | `fly ips allocate-v4` (section 4) | $2/mo | $2.00 |
| IPv6 on `agentuplink-relay` | `fly ips allocate-v6` (section 4) | included | $0.00 |
| Redis machine, `shared-cpu-1x` 256 MB, `syd` | `fly deploy` (section 5) | $0.00000095/s | $2.47 |
| Relay machine, `shared-cpu-1x` 256 MB, `syd` | `fly deploy` (section 6.3) | $0.00000095/s | $2.47 |
| Redis volume, 1 GB | `fly volumes create` (section 5) | $0.15/GB/mo provisioned, billed even when detached | $0.15 |
| Volume snapshots (daily, 5-day retention by default) | the volume | $0.08/GB/mo stored; first 10 GB free each month | $0.00 at this size |
| One-off machines (provisioning, day-2 catalog changes) | `fly machine run` (sections 6.2, 6.4, 6.6) | $0.00000095/s while running | under $0.01 each |
| Outbound data to the internet (Oceania) | device and consumer traffic | $0.04/GB | usage |
| Data between the two apps in one region; inbound data | — | free | $0.00 |
| Stopped machines (if you stop one instead of destroying it) | — | $0.15 per GB of rootfs per 30 days | usage |
| Fly-managed TLS certificates | not used (passthrough) | first 10 free | $0.00 |
| Remote builder (Depot) | `fly deploy --build-only` (section 6.1) | not on the pricing page; Fly's 2024 announcement: 300 build minutes a month free, then $0.05 a minute (<https://community.fly.io/t/depot-remote-builders-becoming-the-default/21756>) | $0.00 expected: one build is about 3 minutes on Depot; at most about $0.15 a build past the allowance |

**Standing total: $7.09 a month in `syd`** ($2.00 + $2.47 + $2.47 + $0.15),
plus outbound data and any builder minutes past the allowance. Upstash is not
used, so its per-command pricing does not apply.
