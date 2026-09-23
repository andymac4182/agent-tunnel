# Operator guide (private alpha)

Status: written for task row M6-02 on 2026-09-23 against `origin/main` at
`dd12b1c`. This is the guide an outside tester follows first. It covers what to
download and verify, device credentials, relay configuration, readiness, and
the diagnostics the binaries have today. **Where the alpha cannot do something,
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

Commands marked **shape-only** need a provisioned Redis authority or a live
relay, so the check cannot run them. Only four may be marked that way:
`tunnel-relay serve`, `tunnel-client connect`, `tunnel-relay recovery-observe`
and `tunnel-relay recover`. It checks only that the real binary accepts
the documented subcommand and flags; **their runtime behaviour is not checked by
this guide.**

The same check also compares the client exit-code table in
[runtime.md](runtime.md#client-exit-codes) with the `Cause` mapping in
`crates/tunnel-client/src/main.rs`, and goes red if they disagree.

## What the alpha can and cannot do today

Read this first. An outside tester cannot bring up a working relay and device
from the release bundle alone:

| Capability | State in this alpha | Row |
| --- | --- | --- |
| Download, checksum, provenance and licence notices | Supported for `aarch64-apple-darwin` only | M6-01, M6-C13 |
| Device key, CSR, certificate import, local `doctor` | Supported | — |
| Relay and cluster configuration dry runs, local state initialization | Supported | — |
| Creating tenants, users, devices, credential records and grants in the Redis catalog | **Not supported in this alpha**: no shipped command writes them | M6-C21 |
| First activation of a deployment incarnation in a new Redis namespace | **Not supported in this alpha** | M6-C21 |
| Cluster membership publishing and the HTTPS checkpoint authority | **Not supported in this alpha**: a cluster relay needs both and neither is shipped | M6-C22 |
| Service installation (systemd, launchd, Windows service) | **Not supported in this alpha** | M6-C23 |
| In-place upgrade, supervisor IPC, `status` | **Not supported in this alpha** | M6-C23, M6-06 |
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

Four kinds of credential are involved. Only the first can be provisioned with
the shipped binaries.

### 2.1 Device credentials

The device creates its private key locally and never sends it anywhere. Your
issuer signs a certificate signing request (CSR), and the client imports the
certificate only if it matches the pending key. Start from the example profile.
Relative paths in a profile resolve from the profile's own directory:

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
Do not use it for anything else. The certificate must be X.509 v3, which is why
the extensions file is there. A v1 certificate is refused on import with a
message that wrongly blames a key mismatch (M6-C25):

```console
$ mkdir -m 700 trial-ca
$ openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Synthetic trial CA" -keyout trial-ca/ca-key.pem -out trial-ca/ca.pem
$ printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > trial-ca/device-ext.cnf
$ openssl x509 -req -in trial/device.csr -CA trial-ca/ca.pem -CAkey trial-ca/ca-key.pem -CAcreateserial -days 1 -extfile trial-ca/device-ext.cnf -out trial/device-cert.pem
$ openssl x509 -in trial/device-cert.pem -noout -subject
...device/m1-device-a
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
matching device and credential record in the Redis catalog. No shipped command
creates that record (section 2.3). Certificate renewal and self-service
enrollment are not implemented (`credentials renew` and `enroll` in
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

### 2.3 Tenant-scoped authorization

Tenants, users, devices, device credential registrations, services and grants
are records in the Redis catalog ([cluster.md](cluster.md#decisions-and-deployment-boundary)).
**Creating them is not supported in this alpha.** The only code that writes
them is the test harness's fixture seeding, which is not in the bundle. The
same is true of the first activation of a deployment incarnation in an empty
namespace: `serve` refuses to start without it (derived from the catalog's
startup check, not measured here). This is M6-C21, and it is
the main reason an outside tester cannot yet run an end-to-end tunnel from the
bundle.

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

The relay exits `0` or `1`, and `130` when a stop request ends `serve` before an orderly completion (section 4). It does not otherwise use the client's exit-code table.
Then start it. **Shape-only:** this command needs your provisioned files and a
provisioned Redis namespace (section 2.3):

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

`connect` does **not** reconnect by itself. If the relay cannot be reached, it
exits at once with status `4`:

```console
$ sed 's#wss://relay.example.test/#wss://127.0.0.1:9/#' trial/client.toml > trial/unreachable.toml
$ tunnel-client connect --config trial/unreachable.toml --json; echo "exit=$?"
{"schema_version":1,"command":"connect","ok":false,"result":null,"error":{"code":"TRANSPORT_ERROR",...,"retryable":true}}
exit=4
```

A session the relay closes also ends the process (`SESSION_CLOSED`, exit `4`).
Restarting it is up to whatever runs it (section 4).

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

**Service installation is not supported in this alpha** (M6-C23). No unit files
are shipped. What a unit needs from the binaries is now there: both stop on
SIGTERM, which service managers send by default, and on SIGINT, through one
orderly path, in every phase, and whatever disposition they inherited
([runtime.md](runtime.md#stopping-connect-and-serve) has the table). A
`connect` whose session is live drains, prints its `stopped` event naming the
signal and exits `0`; one stopped before its session is ready exits `130`
`CANCELLED` with a diagnostic; a `serve` that is serving drains and exits `0`,
one stopped during startup exits `130`. A second stop request during the drain
abandons it with `130`. If your unit can stop the service while it is still
starting, count `130` as a clean stop (`SuccessExitStatus=130` under systemd).
Measured by process-level tests for every phase named in runtime.md; a stop
during a data rotation and a non-cluster `serve` while serving are not
measured. SIGHUP is not handled. Because `connect` does not reconnect by
itself (section 3.1), whatever supervises it must restart it.

**In-place upgrade is not supported in this alpha.** Stopping a relay ends the
device sessions it owns. Devices must start a fresh session, and in-flight
operations can end with an unknown outcome
([protocol.md](protocol.md)). Keep the relay's `state/` files across the
upgrade (section 3.3). Replace all three binaries from one bundle together.

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
