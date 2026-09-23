# Operator guide (private alpha)

Status: written for task row M6-02 on 2026-09-23 against `origin/main` at
`dd12b1c`; section 2.3 (catalog provisioning and first incarnation activation)
added for task row M6-C21 on 2026-09-23 against `0da55ac`; sections 3.1 and
4 (reconnect, service units, upgrade) revised for M6-C23 on 2026-09-23
against `da2a24d`. This is the guide
an outside tester follows first. It covers what to download and verify, device
credentials, catalog provisioning, relay configuration, readiness, and the
diagnostics the binaries have today. **Where the alpha cannot do something,
this guide says "not supported in this alpha" and names the task row, instead of
describing a procedure the code does not have.**

## How this guide is tested

Every command in a `console` block below is executed, as written, by
`scripts/m6-release-artifact.py verify --check docs` against an unpacked
release bundle. All of those blocks form **one shell session**, in document
order: it starts in an empty directory that holds only the downloaded archive,
with `PATH` narrowed to the system directories, so each step depends on the
steps before it exactly as it does in your terminal. Lines without a `$ `
prompt are output the command must print, in order; `...` stands for text
within a line that varies between runs, and a line that is only `...` is
refused. Commands that print nothing (`cd`, `mkdir`, `tar -xzf` and the like)
are checked by exit status alone; every command that runs a `tunnel-*` binary
must also show output. A command whose documented exit status is non-zero is
written `...; echo "exit=$?"` and the status is part of the checked output.
The check goes red when a command fails, when it stops printing what is shown,
when a fence carries any tag other than `console`, `sh shape-only` or a named
prose tag, or when a section's number of commands, output lines or shape-only
commands moves from the count pinned in the script.

**The first step is only as real as the archive the check is given.** Run as
`verify --bundle agentuplink-bundle.tar.gz`, the check copies that archive and
the `.sha256` file beside it into the session untouched, so the checksum step
below checks a real download. Run against an unpacked directory, it has to
build an archive and a checksum itself, and it says in its output that the
first step then could not have failed for a real download's reason.

Commands marked **shape-only** need a live Redis authority or a live relay,
so the check cannot run them. Only six may be marked that way:
`tunnel-relay serve`, `tunnel-client connect`, `tunnel-relay recovery-observe`,
`tunnel-relay recover`, and the two provisioning commands that write Redis,
`tunnel-relay activate-first-incarnation` and `tunnel-relay provision-catalog`
(never with `--dry-run`, which contacts no Redis and is executed below). It
checks only that the real binary accepts the documented subcommand and flags;
**their runtime behaviour is not checked by this guide.** The two provisioning
commands, `serve` and `connect` are instead run end to end, against a real
Redis, by `scripts/m6-provisioning-verify.sh` (section 2.3), and `connect`'s
reconnect across a relay restart by `scripts/m6-reconnect-verify.sh`
(section 3.1).

The same check also compares the client exit-code table in
[runtime.md](runtime.md#client-exit-codes) with the `Cause` mapping in
`crates/tunnel-client/src/main.rs`, and goes red if they disagree.

## What the alpha can and cannot do today

Read this first. With the release bundle, a Redis server that speaks TLS, an
identity issuer and a certificate issuer, an outside tester can bring up **one
relay and one device** and run the synthetic echo through them (sections 2
and 3). Anything larger is not supported yet:

| Capability | State in this alpha | Row |
| --- | --- | --- |
| Download, checksum, provenance and licence notices | Supported for `aarch64-apple-darwin` only | M6-01, M6-C13 |
| Device key, CSR, certificate import, local `doctor` | Supported | — |
| Relay and cluster configuration dry runs, local state initialization | Supported | — |
| Creating one tenant, user, device, credential record, service and grant in the Redis catalog | Supported, once per namespace, with `tunnel-relay provision-catalog` (section 2.3) | M6-C21 |
| First activation of a deployment incarnation in a new Redis namespace | Supported with `tunnel-relay activate-first-incarnation` (section 2.3) | M6-C21 |
| Adding, changing or revoking records after the first provisioning (more devices, users, grants) | **Not supported in this alpha**: no shipped command writes them | M6-C31 |
| Cluster membership publishing and the HTTPS checkpoint authority | **Not supported in this alpha**: a cluster relay needs both and neither is shipped | M6-C22 |
| Automatic reconnect of `connect` after a relay restart or a network loss | Supported, with bounded jittered backoff (section 3.1) | M6-C23 |
| Service installation | Example systemd units (relay and client) and a launchd agent (client) in `examples/service/`, checked but not packaged in the bundle (section 4); **Windows service: not supported in this alpha** | M6-C23 |
| Upgrade | Stop, replace the binaries from one bundle, start (section 4); **rolling or mixed-version upgrade: not supported in this alpha** | M6-C23 |
| Supervisor IPC, `status` | **Not supported in this alpha** | M6-06 |
| Backup and restore of the Redis catalog | Operator's Redis tooling only; restore goes through the recovery commands, which need an external signing authority that is not shipped | M6-C22 |
| Metrics endpoint and audit log | **Not supported in this alpha** | M6-C24 |

## 1. Download and verify

The declared release targets live in `[workspace.metadata.release]
advertised-targets` in the root `Cargo.toml`: `aarch64-apple-darwin`,
`x86_64-apple-darwin`, `x86_64-pc-windows-msvc` and
`x86_64-unknown-linux-gnu`. **Only `aarch64-apple-darwin` has a bundle that
passes the release checks.** The other three have no host here that can run
their checks (M6-C13), so treat any build for them as unverified. The hosted CI
that would build them has not run since 2026-09-11, and no GitHub release has
been published, so the only way to get a verified bundle today is from a
maintainer who built it with `scripts/m6-release-artifact.py bundle`.

A bundle is one `.tar.gz` plus a `.sha256` file beside it. This guide calls
them `agentuplink-bundle.tar.gz` and `agentuplink-bundle.tar.gz.sha256`;
substitute your file names. Check the archive before unpacking it, then check
every file inside against `SHA256SUMS`:

```console
$ shasum -a 256 -c agentuplink-bundle.tar.gz.sha256
agentuplink-bundle.tar.gz: OK
$ tar -xzf agentuplink-bundle.tar.gz
$ cd agentuplink-bundle
$ shasum -a 256 -c --quiet SHA256SUMS; echo "exit=$?"
exit=0
```

`shasum -c` checks only the files `SHA256SUMS` lists. The release check also
fails on any file that is present and **not** listed; a maintainer runs it with
`python3 scripts/m6-release-artifact.py verify --bundle agentuplink-bundle.tar.gz`.

`PROVENANCE.txt` says what produced the bytes: the source commit, the target,
the pinned toolchain, and which binaries the build receipt attests. A bundle is
evidence for its own `target` line and for no other platform:

```console
$ grep -E '^(commit|target|rustc_version|receipt_attested_binaries):' PROVENANCE.txt
commit: ...
target: ...
rustc_version: rustc 1.95.0 ...
receipt_attested_binaries: tunnel-client,tunnel-deadman,tunnel-relay
```

`NOTICE` carries the full text of every third-party licence, not just their
names. It is generated from the `Cargo.lock` shipped beside it:

```console
$ grep -E '^(registry_crates|embedded_licence_texts):' NOTICE
registry_crates: ...
embedded_licence_texts: ...
```

Keep the three binaries in `bin/` together. `tunnel-deadman` is not a command
you run: the client looks for it beside its own executable to contain
supervised child processes, and `doctor` reports whether it found it. Put
`bin/` on your `PATH`:

```console
$ export PATH="$PWD/bin:$PATH"
$ tunnel-client --version
tunnel-client 0.1.0
$ tunnel-relay --help
Usage: tunnel-relay [--help | check-config [PATH] | check-serve-config --config PATH | initialize --config PATH | recovery-initialize --config PATH | recovery-observe --config PATH | recover --config PATH ...| serve --config PATH]
```

`tunnel-relay` has no `--version`; use `PROVENANCE.txt`.

The public [downloads page](../site/docs/downloads.html) describes a second
archive format, produced by `scripts/package_release.py` for the release
workflow. It has no `PROVENANCE.txt` or `SHA256SUMS`, and none of the checks
above cover it (M6-C11, M6-01).

## 2. Credential provisioning

Four kinds of credential are involved. The device credential and the catalog
records that authorize it can be provisioned with the shipped binaries; the
relay's listener identities and the Redis credentials are files you supply.

### 2.1 Device credentials

The device creates its private key locally and never sends it anywhere. Your
issuer signs a certificate signing request (CSR), and the client imports the
certificate only if it matches the pending key. Start from the example profile.
Relative paths in a profile resolve from the profile's own directory.

**Three values in the profile must match the catalog records of section 2.3,
or the relay will not serve the device:** `device_id` is the catalog device
UUID (the relay refuses anything else), the certificate must carry the URI SAN
`urn:agent-tunnel:device:<that UUID>`, and each `[exports."<id>"]` table is
named by the catalog service UUID. The example profile and
`examples/m6-catalog.toml` share synthetic placeholder UUIDs; generate your own
with `uuidgen` and change both files together. Before M6-C30 the example
profile used `m1-device-a` and an export named `echo`, and could never be
served. A mismatch is hard to diagnose: a wrong `device_id` makes `connect`
exit with only `TRANSPORT_ERROR` "control read failed" (M6-C32), and a wrong
export name makes every call fail with `DEVICE_REJECTED`:

```console
$ mkdir trial
$ cp examples/m1-client.toml trial/client.toml
$ tunnel-client config check --config trial/client.toml
Runtime client configuration is valid.
$ tunnel-client doctor --config trial/client.toml --json; echo "exit=$?"
{"schema_version":1,"command":"doctor","ok":false,...,"process_containment":{"status":"ok","code":"PROCESS_CONTAINMENT_SENTINEL_PRESENT"}},"error":{"code":"CREDENTIAL_MISSING",...}}
exit=3
$ tunnel-client credentials create --config trial/client.toml --csr-out device.csr
Created local credential request at trial/device.csr and private key at trial/credentials/device-key.pem.
```

`credentials create` never overwrites. It writes the key owner-only (`0600`)
inside an owner-only (`0700`) directory, and refuses if the key or CSR already
exists. A device with a key and no certificate cannot connect yet, and says so:

```console
$ tunnel-client connect --config trial/client.toml --json; echo "exit=$?"
{"schema_version":1,"command":"connect","ok":false,"result":null,"error":{"code":"CREDENTIAL_ERROR",...}}
exit=3
```

**Signing is your issuer's job; the project ships no certificate authority.**
The next four commands stand in for an issuer so this rehearsal can finish on
one machine. They create a throwaway, synthetic CA that is valid for two days.
Do not use it for anything else. The certificate must be X.509 v3 and carry the
device's role SAN, which is why the extensions file is there. A v1 certificate
is refused on import with a message that wrongly blames a key mismatch
(M6-C25). A certificate without the SAN imports cleanly, but the relay's
device listener cannot parse a device identity from it (read from the source);
`provision-catalog` refuses such a certificate before anything is written
(section 2.3):

```console
$ mkdir -m 700 trial-ca
$ openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Synthetic trial CA" -keyout trial-ca/ca-key.pem -out trial-ca/ca.pem
$ printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:33333333-3333-4333-8333-333333333333\n' > trial-ca/device-ext.cnf
$ openssl x509 -req -in trial/device.csr -CA trial-ca/ca.pem -CAkey trial-ca/ca-key.pem -CAcreateserial -days 1 -extfile trial-ca/device-ext.cnf -out trial/device-cert.pem
$ openssl x509 -in trial/device-cert.pem -noout -subject
...device/33333333-3333-4333-8333-333333333333
```

Import the signed certificate with the CA bundle that the device should trust
for the **relay's** device listener. In a real deployment that is a separate
CA from the device issuer; this rehearsal uses one CA for both. Paths given to
`import` also resolve from the profile's directory:

```console
$ tunnel-client credentials import --config trial/client.toml --certificate device-cert.pem --server-ca ../trial-ca/ca.pem
Imported 1 client certificate(s) and 1 server CA certificate(s).
$ tunnel-client doctor --config trial/client.toml --json; echo "exit=$?"
{"schema_version":1,"command":"doctor","ok":true,"result":{"config":{"status":"ok"},"credential_key_match":{"status":"ok"},"permissions":{"status":"ok","private_key":{"status":"ok","mode":"0600"},"credential_directory":{"status":"ok","mode":"0700"}},...
exit=0
```

A healthy local `doctor` does **not** mean the relay will admit the device. The
relay also needs the device's CA in its `device_tls_client_ca` file, and a
matching device and credential record in the Redis catalog, which section 2.3
creates. Certificate renewal and self-service enrollment are not implemented
(`credentials renew` and `enroll` in
[runtime.md](runtime.md#proposed-cli-surface)).

### 2.2 Relay listener identities

The relay reads PEM files named in its configuration. It generates none of
them, and `check-serve-config` validates the names without reading the files.
See `examples/m1-relay.toml`:

| Setting | What it holds |
| --- | --- |
| `consumer_tls_cert_chain`, `consumer_tls_private_key` | Server certificate and key for the public consumer HTTPS listener |
| `consumer_tls_client_ca` (optional) | CA for consumer client certificates, only if consumers must also use mTLS |
| `device_tls_cert_chain`, `device_tls_private_key` | Server certificate and key for the device mTLS listener |
| `device_tls_client_ca` | CA that issued device certificates (section 2.1) |
| `oidc_issuer`, `oidc_audience`, `oidc_jwks_path` | Your consumer identity issuer, accepted audiences, and a local JWKS file of its public verification keys |

Keep private keys owner-only and outside source control. Use separate CAs for
server identity, device clients and cluster peers
([runtime.md](runtime.md#device-authentication-contract)).

### 2.3 Tenant-scoped authorization and the first incarnation

Tenants, users, devices, device credential registrations, services and grants
are records in the Redis catalog ([cluster.md](cluster.md#decisions-and-deployment-boundary)).
`serve` refuses to start on a namespace until a deployment incarnation has been
activated there: it exits `1` with `Redis catalog connection failed;
stage=authority_identity`. Two `tunnel-relay` commands bring an **empty**
namespace to the point where one relay serves one device (task row M6-C21).
Both read the relay's own serving configuration, so they reach Redis exactly as
`serve` will: the same `redis_url`, TLS files, `redis_namespace` and
`deployment_incarnation`, and the user's identity is bound to its
`oidc_issuer`.

The records are one TOML document: one tenant, one user with the `sub` claim
your identity issuer gives them, one device and its certificate, one service,
and one grant. `examples/m6-catalog.toml` is a complete example whose UUIDs
match the example client profile. Put it beside the device certificate, because
its `certificate` path is relative to the document. Then dry-run it. The dry run
reads the relay configuration, the records and the certificate, applies every
rule the write applies, and contacts no Redis. It derives the credential's
SPKI pin and validity from the certificate with the parser the relay's device
listener uses, and refuses a certificate whose role SAN does not name
`device.id`:

```console
$ cp examples/m6-catalog.toml trial/catalog.toml
$ tunnel-relay provision-catalog --config examples/m1-relay.toml --records trial/catalog.toml --dry-run
Provisioning records are valid for namespace agent-tunnel-m1: tenant=11111111-1111-4111-8111-111111111111 user=22222222-2222-4222-8222-222222222222 device=33333333-3333-4333-8333-333333333333 credential=... service=44444444-4444-4444-8444-444444444444 spki_sha256=... grant_operations=echo:invoke. This dry run contacted no Redis authority and wrote nothing.
```

Then, against your Redis, activate the relay's incarnation and write the
records, in that order. **Do not start `serve` until `provision-catalog` has
succeeded.** Provisioning refuses a namespace holding any key other than the
incarnation binding, and nothing shipped removes a key a relay has written, so
a relay started between the two commands can leave the namespace
unprovisionable (M6-C34); if that happens, choose a new `redis_namespace` and
start again. **Shape-only:** both write Redis, which this guide's
check does not have. `scripts/m6-provisioning-verify.sh` runs them, `serve`,
`connect` and an echo end to end with these binaries and the two examples
against a real Redis:

```sh shape-only
tunnel-relay activate-first-incarnation --config /etc/agent-tunnel/relay.toml
tunnel-relay provision-catalog --config /etc/agent-tunnel/relay.toml --records /etc/agent-tunnel/catalog.toml
```

`activate-first-incarnation` prints `Activated deployment incarnation ... as the
first incarnation of namespace ...`. It refuses a namespace that holds any key
at all, including one that already has an incarnation: changing an
incarnation is recovery's job (section 4), and this command cannot be used to
skip it. `provision-catalog` prints `Provisioned namespace ...` with the
identifiers it wrote. It refuses a namespace without an active incarnation,
and it runs **once** per namespace: a second run, or a run after a partial
failure, is refused, and a namespace left partly written is discarded, not
repaired. Choose a new `redis_namespace` and start again. No identifier it
prints is secret; it prints no certificate, key or token.

Because an interrupted write cannot be undone, neither command stops part-way
on the first SIGTERM or Ctrl-C: it says it received the signal, finishes (each
Redis step is bounded), and prints and exits with its own outcome. A second
signal abandons it at once with exit `130` and says the outcome is unknown;
treat that namespace as partial. `initialize`, `recovery-initialize` and
`recover` behave the same way (M6-C23).

The activation also binds the namespace to the Redis server's run id. A Redis
restart that loses the run (no persistence, or a restore) makes `serve` refuse
again, and the way back is recovery, not a second activation.

Once `serve` and `connect` are running (section 3.1), a consumer calls
`POST /v1/devices/<device.id>/services/<service.id>/echo` on the consumer
listener with `Authorization: Bearer <token>`. The token must be issued by
`oidc_issuer` for one of `oidc_audience`, carry `sub` equal to `oidc_subject`,
and have `echo:invoke` in its `scope`. The reply is the export's
`device_canary` followed by the request body.

**Not supported in this alpha:** anything after the first provisioning. There
is no shipped command to add a second device, user or grant, to change a
grant, or to revoke a device or credential (M6-C31); the catalog library has
the revocation and grant operations, but no command exposes them. A cluster
also needs the authorities in section 3.3 (M6-C22).

### 2.4 Redis credentials

The relay connects to Redis over `rediss://` with the URL in `redis_url`, plus
optional CA and client-certificate files. [redis-tls.md](redis-tls.md) gives the
fields and the file rules. If the URL carries a password, the relay redacts it
from its errors, but the URL is still in the configuration file, so protect that
file like a key. No least-privilege Redis ACL for the relay has been derived or
tested; the Redis durability settings the design needs are in
[cluster.md](cluster.md#redis-durability-backup-and-recovery).

## 3. Deployment

Redis is the only coordination store. There is no second store and no local
catalog. One Redis primary serves every relay; there is no automatic failover.

### 3.1 One relay

Validate the serving configuration first. `check-serve-config` applies every
rule `serve` applies to the document, but it opens no socket, contacts no
Redis, and reads no credential file:

```console
$ tunnel-relay check-serve-config --config examples/m1-relay.toml
Relay serving configuration is valid: consumer_bind=127.0.0.1:8443 device_bind=127.0.0.1:9443 cluster=absent recovery=absent. ...
$ tunnel-relay check-serve-config --config trial/client.toml; echo "exit=$?"
tunnel-relay: invalid relay TOML: unknown field `credentials` ...
exit=1
```

The relay exits `0` or `1`, and `130` when a stop request ends `serve` before an orderly completion or a second one abandons a writing command (section 4). It does not otherwise use the client's exit-code table.
Then start it. **Shape-only:** this command needs your provisioned files and a
provisioned Redis namespace (section 2.3). `scripts/m6-provisioning-verify.sh`
runs it end to end:

```sh shape-only
tunnel-relay serve --config /etc/agent-tunnel/relay.toml
```

`serve` stops on SIGTERM or SIGINT (Ctrl-C), the same way for both: it prints
`tunnel-relay stopping: signal=SIGTERM`, drains its listeners and, in a
cluster, its peer and membership tasks, prints `tunnel-relay stopped:
signal=SIGTERM` and exits `0` (measured on a one-node cluster; M6-C23). A stop
request during startup exits `130` with nothing bound. It logs JSON lines to
stderr; set `RUST_LOG` (default `info`) to change the level.

The device side runs in the foreground until it stops. **Shape-only:**

```sh shape-only
tunnel-client connect --config /etc/agent-tunnel/client.toml --json
```

`connect` **reconnects by itself** (M6-C23). When the relay cannot be
reached, or a session ends because the relay restarted or the network
dropped, it waits and tries again: about 1 s, then doubling to a 60 s cap,
each delay jittered so devices that lost the same relay do not return
together. Under `--json` it prints a `disconnected` and a `backoff` event for
each failure, `reconnecting` when it tries again and `reconnected` (then the
usual `ready`) when a new session is up. Causes no retry can fix -- a bad
profile, a relay certificate your `server_ca` does not trust, a relay that
refuses the device certificate, a device certificate that has expired -- exit
at once with their own status. A certificate that is only not yet valid on
somebody's clock is clock skew and is retried, with a message saying so. The
full classification and its reasons are in
[runtime.md](runtime.md#reconnecting-connect). The profile's `[reconnect]`
table sets the policy. This rehearsal gives up after one retry so it ends:

```console
$ sed 's#wss://relay.example.test/#wss://127.0.0.1:9/#' trial/client.toml > trial/unreachable.toml
$ printf '\n[reconnect]\ninitial_delay_ms = 100\nmax_delay_ms = 200\nmax_attempts = 1\n' >> trial/unreachable.toml
$ tunnel-client connect --config trial/unreachable.toml --json; echo "exit=$?"
{"schema_version":1,"command":"connect","ok":true,"result":{"state":"disconnected","attempt":1,"sessions":0,"code":"TRANSPORT_ERROR","message":"websocket handshake failed"},"error":null}
{"schema_version":1,"command":"connect","ok":true,"result":{"state":"backoff","attempt":1,"sessions":0,"code":"TRANSPORT_ERROR","delay_ms":...},"error":null}
{"schema_version":1,"command":"connect","ok":true,"result":{"state":"reconnecting","attempt":1,"sessions":0},"error":null}
{"schema_version":1,"command":"connect","ok":false,"result":null,"error":{"code":"TRANSPORT_ERROR","message":"websocket handshake failed (gave up after 1 consecutive reconnect attempts)","retryable":true}}
exit=4
```

With `--no-reconnect` (or `enabled = false` in `[reconnect]`) the first
failure is the exit, as it was before M6-C23, for a supervisor that prefers
to own restarts:

```console
$ tunnel-client connect --config trial/unreachable.toml --json --no-reconnect; echo "exit=$?"
{"schema_version":1,"command":"connect","ok":false,"result":null,"error":{"code":"TRANSPORT_ERROR",...,"retryable":true}}
exit=4
```

Two limits, both measured (runtime.md has the detail). **After a relay
crash**, the relay's claim on the device outlives it in Redis for up to the
owner lease (30 s by default), and reconnects are refused `OWNER_BUSY` until
it lapses: a device reconnected about 30 s after a SIGKILLed relay was back,
and in under a second after one stopped with SIGTERM (M6-C40). **A refusal after TLS** -- a revoked or
inactive catalog credential, a `device_id` that does not match the
certificate, a protocol version the relay does not speak -- looks to the
client like a relay that dropped the connection, and is retried (M6-C38;
M6-C32 makes the single-relay identity refusals terminal, M6-C43 tracks the
cluster case). Each retry prints its `disconnected` and `backoff` events with
the cause, and `attempt` counts them; set `max_attempts` if a supervisor
should see it fail.

### 3.2 Health endpoints and load balancers

The consumer listener serves two unauthenticated endpoints. Their bodies are
deliberately minimal:

| Endpoint | Answers | Meaning |
| --- | --- | --- |
| `GET /livez` | `200 {"status":"live"}` | The process answers HTTP. It consults nothing else. |
| `GET /readyz` | `200 {"status":"ready"}` or `503 {"status":"unready"}` | Whether this relay should receive new public work |

A relay without `[cluster]` is always ready once it is serving. A cluster relay
is ready only while its membership is current, its required peer routes are
probed reachable, it has capacity, **and its set of approved peer keys is not
empty** (M7-C89). Before M7-C89, a relay whose membership went unready had the
set emptied and already reported `unready`; the fault was on **recovery**: when
membership returned to ready, nothing republished the set until the next peer
refresh tick, so for that interval (`min(membership_reconcile_seconds, 5 s)`
plus any probe pass in flight) the relay answered `ready` while refusing every
request that needed another relay. `/readyz` and public admission are now the
same check and it reads the set every peer dial reads. **A non-empty set is
necessary for a peer dial, not sufficient:** a set that lacks one peer's key
still reads ready, and a dial to that peer then fails its TLS pin check.

What a load balancer should do:

- Route new public traffic only to relays that answer `200` on `/readyz`.
  Leave `/livez` to the process supervisor for restart decisions. Do not use
  it for routing.
- Expect short `503` episodes during ordinary operation. After a membership
  change, readiness can stay `503` until the next peer refresh tick
  (`min(membership_reconcile_seconds, 5 s)` plus any probe pass in flight);
  M7-C91 would shorten this. Mark a relay down only after several consecutive
  failures.
- Health checks prove nothing about the private HTTP/3 peer path, which runs
  over UDP between relays ([runtime.md](runtime.md#debugging-and-deployment-contract)).
- The device listener needs direct TLS termination in the relay or layer-4
  passthrough. An HTTP proxy in front of it strips the device's client
  certificate.

A relay that is not ready refuses public work with `503` and
`not_dispatched`, so nothing is executed and lost. Open rows on this path:
M7-C86 and M7-C90 (when a relay withdraws peer trust) and M7-C80, M7-C81 and
M7-C83 (membership re-signs).

### 3.3 A cluster

**A cluster cannot be brought up with what this alpha ships** (M6-C22). Each
relay also needs:

- a peer certificate and key, and the CA for other relays' peer certificates;
- the public keys of your **membership publisher**, which signs every relay's
  membership record and writes it to Redis;
- an **HTTPS checkpoint authority** that returns a signed, nonce-bound
  checkpoint when the relay starts.

The project ships neither the publisher nor the checkpoint authority. The
contract they must meet is in
[cluster.md](cluster.md#relay-trust-bootstrap-and-redis-key-distribution).

The configuration and the relay's local state can still be prepared and checked.
`examples/m7-cluster-relay.toml` is a complete placeholder configuration. Note
that it has no `boot_id`: cluster mode refuses one and generates a fresh one per
process:

```console
$ tunnel-relay check-serve-config --config examples/m7-cluster-relay.toml
Relay serving configuration is valid: ... cluster=configured recovery=configured. ...
```

Each relay keeps two local state files that must survive restarts and
upgrades, and must **never** be reset or restored from an older copy. Both are
created once, explicitly, in an owner-only directory. `serve` opens them and
never creates them:

```console
$ mkdir -m 700 state
$ tunnel-relay initialize --config examples/m7-cluster-relay.toml
Initialized membership version state for deployment example-deployment node relay-a.
$ tunnel-relay initialize --config examples/m7-cluster-relay.toml; echo "exit=$?"
tunnel-relay: membership state already exists
exit=1
$ tunnel-relay recovery-initialize --config examples/m7-cluster-relay.toml
Initialized recovery approval fence for deployment example-deployment namespace agent-tunnel-cluster.
```

`membership_version_state_path` records the highest membership version the
relay has accepted, so a restarted relay cannot be fed an older signed snapshot.
`recovery.fence_path` records the highest recovery approval consumed. Starting
each relay is the `serve` command from section 3.1.

## 4. Service installation, upgrade, backup and recovery

**Example service units are in `examples/service/` of the source tree**
(M6-C23): `tunnel-relay.service` and `tunnel-client.service` for systemd, and
`local.agent-tunnel.tunnel-client.plist`, a launchd agent for the client on
macOS. They are examples: adjust the paths, the account and the hardening
lines, and they are **not** in the release bundle. **Windows service
installation is not supported in this alpha**: Windows builds handle Ctrl-C
only, and no service wrapper is shipped. How the units were checked:
`systemd-analyze verify` (systemd 257, in a Debian container) accepts both
systemd units with no warning, and `plutil -lint` accepts the plist, by
`scripts/m6-service-units-check.sh`, which also proves each check can fail by
running it on broken copies. Its `--live` mode boots systemd in a privileged
container with a Linux build of `tunnel-client` and **measured the client
unit**: against an unreachable relay the service stays active while the
client backs off, and `systemctl stop` records exit `130` as a clean stop
(`Result=success`; a failure without `SuccessExitStatus=130`); an invalid
profile exits `2` and is not restarted (restarted five times without
`RestartPreventExitStatus`). The relay unit is checked statically only
(running it needs Redis), and the launchd agent was linted, not loaded.

Every setting follows from how the binaries stop and reconnect
([runtime.md](runtime.md#stopping-connect-and-serve)):

- **`KillSignal=SIGTERM`, `KillMode=mixed`.** Both binaries treat SIGTERM as an
  orderly stop in every phase. `mixed` sends it to the main process only, so
  `connect` ends its supervised MCP/ACP children itself instead of racing
  systemd for them; whatever is left at the timeout gets SIGKILL.
- **`SuccessExitStatus=130`.** A stop before a session is ready, while
  `connect` waits to reconnect, or while `serve` is still starting exits `130`
  `CANCELLED`. That is a clean stop, not a failure. A stop with a live
  session, or of a serving relay, exits `0`.
- **`TimeoutStopSec=`** is the real bound on a stop. `connect` bounds its own
  drain at `rotation.handshake_timeout_seconds + rotation.overlap_seconds`
  (40 s by default) plus 5 s for the child reap and 5 s for blocking work, so
  its unit allows 60 s. `serve`'s drain has no deadline of its own, so its
  unit's 45 s is the bound. Raise them together with those settings.
- **`Restart=` complements reconnect; it does not replace it.** The client
  retries relay restarts and network loss inside the process, with backoff
  (section 3.1), so the unit restarts it only for what the process cannot
  handle: a crash, an internal failure (exit `1`), an `OWNER_BUSY` that
  outlived the stale-lease window (exit `7`), or an attempt limit you set
  (exit `4` or `5`), after `RestartSec=30s`. **`RestartPreventExitStatus=2 3`**
  keeps a configuration or credential error (a certificate refused on either
  side) from restarting in a loop: the unit stays failed and
  `journalctl -u tunnel-client` shows the error. If your supervisor should own
  every restart instead, add `--no-reconnect` to `ExecStart`. The relay does
  not retry its own startup (an unreachable Redis exits `1`), so its unit
  restarts it on failure after 10 s. Both units stop restarting after five
  starts in ten minutes.
- **launchd** sends SIGTERM and waits `ExitTimeOut` seconds (default 20; the
  plist sets 60, for the same reason as `TimeoutStopSec`) before SIGKILL.
  `KeepAlive` with `SuccessfulExit = false` restarts the client after an
  unsuccessful exit, at most every `ThrottleInterval` (30 s). launchd has no
  equivalent of `RestartPreventExitStatus`, so a configuration or credential
  error is retried every 30 s: read the log file the plist names. Whether
  launchd resets the signal dispositions it starts a job with was not checked
  here; the binaries override an inherited `SIG_IGN` anyway.

SIGHUP is not handled by either binary; neither reloads its configuration.
runtime.md lists what is measured and what is not; in short, the handshake,
startup and backoff phases, a live stop and a reconnect across a relay
restart are measured on the real binaries, the second-signal and bound logic
of `connect`'s waits only by unit tests.

**Upgrade.** What the code supports is **stop, replace, start**:

1. Stop the service (`systemctl stop`, or `launchctl bootout`). Stopping a
   relay ends the device sessions it owns; the devices back off and
   reconnect by themselves when it returns (measured: under a second after
   an orderly restart, about 30 s after a crash; M6-C40). In-flight operations on those sessions end with them,
   and a mutation's outcome can be unknown ([protocol.md](protocol.md)).
2. Replace **all three binaries from one bundle** together
   (`tunnel-client`, `tunnel-relay`, and `tunnel-deadman`, which the client
   finds beside itself).
3. Start it again with the same configuration.

**What carries over:** the Redis catalog (tenants, devices, credential
records, grants, the active incarnation), the relay's configuration and
`state/` files (section 3.3; keep them), and the device's profile, key and
certificate. **What does not:** sessions, owner leases, attachment tickets
and supervised MCP/ACP child processes -- every device starts a new session
with new children. **Not supported in this alpha:** an in-place or rolling
upgrade without ending sessions; relays of different versions against one
Redis namespace, or a client and a relay from different bundles -- nothing
versions the catalog records, and the only version check is the protocol
major, which a relay refuses at HELLO without a reason the client can read,
so a mismatched client retries it (M6-C38); and a downgrade. A relay that
dies instead of stopping holds its devices' owner records until their lease
lapses (up to 30 s), so stop relays with SIGTERM, not SIGKILL.

**Backup and restore.** Only the Redis catalog holds durable state. Back it up
with your Redis tooling, using the durability settings in
[cluster.md](cluster.md#redis-durability-backup-and-recovery). Leases, presence
and tickets are not recoverable state. A restore, a restart with a different
Redis identity, or any doubt about which Redis is authoritative must go through
recovery. Do not just restart the relays.

**Recovery** is three commands, specified in [recovery-cli.md](recovery-cli.md).
`recovery-initialize` is shown in section 3.3. The other two need a live Redis,
and `recover` needs a signed approval from an external recovery authority,
which is not shipped (M6-C22). **Shape-only:**

```sh shape-only
tunnel-relay recovery-observe --config /etc/agent-tunnel/relay.toml
tunnel-relay recover --config /etc/agent-tunnel/relay.toml \
  --approval /etc/agent-tunnel/recovery/approval.json \
  --expected-nonce NONCE-FROM-YOUR-RECOVERY-AUTHORITY \
  --acknowledgement-id CHANGE-RECORD-ID \
  --old-primary-fenced --old-relays-fenced
```

`recovery-observe` is read-only and reports `quiescence: "unproven"`. The two
`--old-*-fenced` flags are your declaration that the old Redis primary and the
old relays are stopped; the relay cannot verify it.

## 5. Metrics, logs and audit retention

**There is no metrics endpoint and no audit log in this alpha** (M6-C24). The
relay does not serve `/metrics`, and a gate asserts that it stays unserved
(`crates/tunnel-test-harness/src/production_cluster/i04_fail_closed.rs`). The
metrics list in [runtime.md](runtime.md#debugging-and-deployment-contract) is a
design contract, not a delivered surface. The relay's peer-fault diagnostics
snapshot exists in-process for the test gates and is not exposed to operators.

What an operator can read today:

| Surface | Where | Content |
| --- | --- | --- |
| Relay log | stderr of `tunnel-relay serve`, JSON lines, level from `RUST_LOG` | Bounded warnings and errors. No retention or rotation: that is your log shipper's job |
| `/livez`, `/readyz` | Consumer listener | Section 3.2 |
| `connect --json` | stdout of `tunnel-client connect` | One JSON object per lifecycle change: session, epoch, generation, connection IDs, rotation and recovery progress and deadlines, and the **local socket addresses** of the control, active and candidate connections. No payloads or credentials |
| `doctor --json` | Section 6 | Local checks only |

**Redaction.** These guarantees are claimed and tested today. The
`connect --json` events are **not** among them beyond carrying no payloads or
credentials: they include local socket addresses and deadline timestamps.

- `doctor` output holds only fixed codes, statuses, permission modes,
  certificate counts and timestamps, never a path or credential body.
- A transport error message is pinned by a test to a bounded label with no
  path, certificate or endpoint (M0-03).
- Public error responses carry a code from an allowlist, which the
  fail-closed gate asserts (M7-I04), rather than backend error text.

Diagnostics across the whole system are **not** yet proven payload-free.
M0-04 is in progress, and M0-06 records that one redaction test cannot tell
redaction from deletion. Computer-use (M5) is not part of this alpha, so no
shipped path handles typed text. Treat logs as sensitive regardless.

## 6. Diagnostics

`doctor` checks the local profile: the configuration, whether the certificate
matches the key, owner-only permissions, certificate expiry, and whether
`tunnel-deadman` is beside the client. It opens no network connection. **It
always prints its full `result`, even when it fails** (M6-C07), so a
half-provisioned machine can still see which checks passed. `not_run` means a
check could not be attempted, which is different from `failed`:

```console
$ tunnel-client doctor --config trial/absent.toml --json; echo "exit=$?"
{"schema_version":1,"command":"doctor","ok":false,"result":{"config":{"status":"failed","code":"INVALID_CONFIG"},"credential_key_match":{"status":"not_run"},...,"process_containment":{"status":"ok","code":"PROCESS_CONTAINMENT_SENTINEL_PRESENT"}},"error":{"code":"INVALID_CONFIG",...}}
exit=2
```

`doctor` exits `0` when every local check passes, `2` for a configuration it
cannot read, and `3` for a credential, permission or expiry failure (the two
earlier runs in section 2.1). `PROCESS_CONTAINMENT_SENTINEL_MISSING` or
`..._UNUSABLE` means `tunnel-deadman` is absent or unusable. That degrades
cleanup of supervised child processes but does not change the exit status.

**`status` is not implemented in this alpha**, and neither is `doctor
--network`. Both are refused rather than ignored:

```console
$ tunnel-client status --config trial/client.toml; echo "exit=$?"
tunnel-client: unknown command
exit=2
$ tunnel-client doctor --config trial/client.toml --network; echo "exit=$?"
tunnel-client: usage: tunnel-client doctor --config PATH
exit=2
```

**Client exit codes** are in the table in
[runtime.md](runtime.md#client-exit-codes). That table is checked against the
code by this guide's check. This guide runs real processes that exit `0`, `2`,
`3` and `4`. Exit `7` (`OWNER_BUSY`, `RESOURCE_EXHAUSTED`) and `130`
(`CANCELLED`) need a live relay and are covered by unit tests only. Exit `6`
has no producer today. With `--json`, `config check` and `connect` print
exactly one result object:

```console
$ tunnel-client config check --config trial/client.toml --json
{"schema_version":1,"command":"config check","ok":true,"result":{"state":"valid"},"error":null}
```

Where to look next: [runtime.md](runtime.md#error-and-incident-vocabulary)
has the error vocabulary and the runbook questions, and
[cluster.md](cluster.md) has cluster failure behaviour.
