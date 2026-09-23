# Operator guide (private alpha)

Status: written for task row M6-02 on 2026-09-23 against `origin/main` at
`dd12b1c`; section 2.3 (catalog provisioning and first incarnation activation)
added for task row M6-C21 on 2026-09-23 against `0da55ac`; sections 3.1 and
4 (reconnect, service units, upgrade) revised for M6-C23 on 2026-09-23
against `da2a24d`; section 2.3 extended to MCP, ACP and filesystem services for
M6-C57 on 2026-09-23 against `721ed2a`; section 2.5 (day-2 catalog changes)
added for M6-C31 on 2026-09-24 against `6091f4c` and merged forward to
`8f486bf`. This is the guide
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
so the check cannot run them. Only thirteen may be marked that way:
`tunnel-relay serve`, `tunnel-client connect`, `tunnel-relay recovery-observe`,
`tunnel-relay recover`, the two provisioning commands that write Redis,
`tunnel-relay activate-first-incarnation` and `tunnel-relay provision-catalog`,
and the seven day-2 catalog commands of section 2.5 (never with `--dry-run`,
which contacts no Redis and is executed below). It
checks only that the real binary accepts the documented subcommand and flags;
**their runtime behaviour is not checked by this guide.** The provisioning
and day-2 commands, `serve` and `connect` are instead run end to end, against
a real Redis, by `scripts/m6-provisioning-verify.sh` (sections 2.3 and 2.5),
and `connect`'s reconnect across a relay restart by
`scripts/m6-reconnect-verify.sh` (section 3.1).

The same check also compares the client exit-code table in
[runtime.md](runtime.md#client-exit-codes) with the `Cause` mapping in
`crates/tunnel-client/src/main.rs`, and goes red if they disagree.

## What the alpha can and cannot do today

Read this first. With the release bundle, a Redis server that speaks TLS, an
identity issuer and a certificate issuer, an outside tester can bring up **one
relay and one device** and serve one service through them: the synthetic echo,
an MCP server, an ACP agent or a filesystem export (sections 2 and 3). Further
users, devices, services and grants are added to that relay, and revoked,
while it runs (section 2.5). Anything larger is not supported yet:

| Capability | State in this alpha | Row |
| --- | --- | --- |
| Download, checksum, provenance and licence notices | Supported for `aarch64-apple-darwin` only | M6-01, M6-C13 |
| Device key, CSR, certificate import, local `doctor` | Supported | — |
| Relay and cluster configuration dry runs, local state initialization | Supported | — |
| Creating one tenant, user, device, credential record, service and grant in the Redis catalog | Supported, once per namespace, with `tunnel-relay provision-catalog` (section 2.3) | M6-C21 |
| Service types `provision-catalog` can create | The synthetic echo (`echo`), an MCP server or an ACP agent (`http-forward`, by `http_forward_profile`), and a filesystem export (`fs`), one per namespace (section 2.3); any other type is refused by the dry run | M6-C57 |
| First activation of a deployment incarnation in a new Redis namespace | Supported with `tunnel-relay activate-first-incarnation` (section 2.3) | M6-C21 |
| Adding users, devices, services and grants after the first provisioning, replacing a grant, and revoking a grant, device or credential | Supported while `serve` runs, with `add-user`, `add-device`, `add-service`, `set-grant`, `revoke-grant`, `revoke-device` and `revoke-credential` (section 2.5); a second tenant, and changing or deactivating a user or service, are **not supported in this alpha** | M6-C31 |
| Cluster membership publishing and the HTTPS checkpoint authority | **Not supported in this alpha**: a cluster relay needs both and neither is shipped | M6-C22 |
| Automatic reconnect of `connect` after a relay restart or a network loss | Supported, with bounded jittered backoff (section 3.1) | M6-C23 |
| Service installation | Example systemd units (relay and client) and a launchd agent (client) in `examples/service/`, checked but not packaged in the bundle (section 4); **Windows service: not supported in this alpha** | M6-C23 |
| Upgrade | Stop, replace the binaries from one bundle, start (section 4); **rolling or mixed-version upgrade: not supported in this alpha** | M6-C23 |
| Supervisor IPC, `status` | **Not supported in this alpha** | M6-06 |
| Backup and restore of the Redis catalog | Operator's Redis tooling only; restore goes through the recovery commands, which need an external signing authority that is not shipped | M6-C22 |
| A Redis restart in place that keeps its data (one relay) | Supported: a serving relay with `redis_restart_continuity_seconds` re-binds by itself on a durable Redis (`appendfsync always`); a relay started after the restart needs `tunnel-relay rebind-redis-run` once (section 4). A Redis that came back empty or older than the relay's last token is refused. **Failover to a replica, or a restore: not supported this way** | M6-C65 |
| Metrics endpoint and audit log | **Not supported in this alpha** | M6-C24 |
| One relay and its Redis on Fly.io | Dockerfiles, `fly.toml` files, a runbook and a cost list in [deploy-fly.md](deploy-fly.md), proved with Docker on one machine and run on Fly: one relay serves from an image built from `main`, measured end to end from a Mac (reconnect through a relay restart included) | M6-C70 |

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

**The bundle carries no documentation**, not even this guide (M6-C50). Read
this guide and every document it links from the repository at the `commit`
line of the bundle's `PROVENANCE.txt`, for example
`https://github.com/andymac4182/agentuplink/blob/<commit>/docs/operator.md`,
so the guide and the binaries describe the same code.

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
served. `credentials import` refuses a certificate whose SAN names a device
other than `device_id`. It compares them as UUIDs, as the relay does, so case
and hyphens do not matter. If the profile or the catalog changes afterwards, the
relay refuses the session and `connect` exits `3` with a non-retryable
`CREDENTIAL_ERROR`, "the relay refused this device's identity" (M6-C32). The
relay gives the same refusal for a certificate key the catalog does not hold,
and it does not say which check failed. A credential whose catalog
`not_before` is still in the future is different. That is clock skew, not a
wrong identity, so `connect` reports it as a retryable `TRANSPORT_ERROR` and
retries it with backoff until the credential is valid (section 3.1). A cluster
relay is different. It looks the key up before routing and, for an unknown
key, still closes the socket without a reason. That reads as a retryable
`TRANSPORT_ERROR`, which `connect` retries (M6-C43, read from the source, not
measured; M6-C38). A wrong export name still makes every
call fail with `DEVICE_REJECTED`:

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
device's role SAN, which is why the extensions file is there. Without one,
macOS's bundled `openssl` (LibreSSL) issues a v1 certificate. OpenSSL 3 issues
v3, but with no role SAN. `credentials import` refuses both before installing
anything, and names the fault each time (M6-C25): "client certificate is X.509
v1; the relay accepts only v3 certificates", "client certificate has no device
role URI SAN", or, for a SAN naming another device, "names device ... in its
role SAN but the profile's device_id is ...". Only a certificate whose public
key is not the pending key's is reported as "does not match its private key".
`provision-catalog` also refuses a certificate without the SAN before it
writes anything (section 2.3):

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

**What the relay accepts from your identity issuer** (M6-C51; the rules below
are read from the source and were met by a hand-made issuer in a dogfood run,
not tested one by one). `oidc_jwks_path` is a local JSON file
`{"keys":[...]}` of **RSA keys only**: each needs `kty = "RSA"`, a non-empty
`kid`, `n` and `e`, and an `alg` that is `RS256` or absent. Any other key type
makes `serve` refuse to start. The relay never fetches the issuer's JWKS URL,
so a key rotation at the issuer means editing this file and restarting `serve`.
A token is accepted only if its header has `alg` `RS256` and a `kid` from that
file, and its claims have `iss` equal to `oidc_issuer` **byte for byte**
(including any trailing `/`), an `aud` in `oidc_audience`, a non-empty `sub`,
and an unexpired `exp`. `nbf` is checked if present. There is no clock leeway.
`scope` is one space-separated string. Every refusal of these, and a `sub`
without a catalog user, gets the same `401`, and the relay logs nothing about
it (M6-C52), so check the claims before looking anywhere else. The project
ships no issuer and no token tool.

Keep private keys owner-only and outside source control. Use separate CAs for
server identity, device clients and cluster peers
([runtime.md](runtime.md#device-authentication-contract)).

### 2.3 Tenant-scoped authorization and the first incarnation

Tenants, users, devices, device credential registrations, services and grants
are records in the Redis catalog ([cluster.md](cluster.md#decisions-and-deployment-boundary)).
`serve` refuses to start on a namespace until a deployment incarnation has been
activated there: it exits `1` with `Redis catalog connection failed;
stage=authority_identity class=catalog`. Two `tunnel-relay` commands bring an **empty**
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
`device.id`. Operation names are matched exactly. There are no wildcards, so
the dry run refuses any name containing `*` with "wildcards are not
supported" (M6-C36). Before that change, `operations = ["*"]` was accepted
and provisioned a grant that authorized nothing:

```console
$ cp examples/m6-catalog.toml trial/catalog.toml
$ tunnel-relay provision-catalog --config examples/m1-relay.toml --records trial/catalog.toml --dry-run
Provisioning records are valid for namespace agent-tunnel-m1: tenant=11111111-1111-4111-8111-111111111111 user=22222222-2222-4222-8222-222222222222 device=33333333-3333-4333-8333-333333333333 credential=... service=44444444-4444-4444-8444-444444444444 service_type=echo spki_sha256=... grant_operations=echo:invoke. This dry run contacted no Redis authority and wrote nothing.
```

**Service types (M6-C57).** The records document provisions one service, of
one of these types; the dry run refuses any other type, and refuses a service
of these types that the relay could not serve, naming the field:

* `type = "echo"`, operation `echo:invoke`: the synthetic echo above.
* `type = "http-forward"`, operation `http:invoke`, with `http_forward_profile`
  naming the application protocol: `mcp-2025-11-25` or `mcp-2026-07-28` for an
  MCP server, `acp-http-v1` for an ACP agent. The relay configuration given
  with `--config` must list the same profile in `[http_forward] profiles`,
  because the relay answers a service whose profile it does not serve with
  `404`, so the dry run refuses it.
* `type = "fs"`, operations `fs:connect` (admits a session, required in the
  grant) and at least one of `fs:read`, `fs:list`, `fs:write` and `fs:delete`,
  with `fs_case_sensitivity` stating how the device's export directory treats
  letter case: `insensitive-preserving` for a default macOS volume, `sensitive`
  for a case-sensitive one.

Before M6-C57 the dry run accepted any `type`, but the write recorded only the
operation names. So an MCP, ACP or filesystem service was provisioned without
the field the relay serves it by, and every request got `404`.
`examples/m6-catalog-mcp.toml`, `m6-catalog-acp.toml` and `m6-catalog-fs.toml`
are complete records documents, one per type, with the same tenant, user and
device as `m6-catalog.toml`. Each one's comment shows the export table the
device's client profile needs. Their service and grant tables, and dry runs
against a relay configuration that serves both HTTP profiles:

```console
$ cp examples/m6-catalog-mcp.toml examples/m6-catalog-acp.toml examples/m6-catalog-fs.toml trial/
$ sed -n '/^\[service\]/,$p' trial/m6-catalog-mcp.toml
[service]
id = "55555555-5555-4555-8555-555555555555"
type = "http-forward"
display_name = "Trial MCP server"
operations = ["http:invoke"]
http_forward_profile = "mcp-2025-11-25"
[grant]
operations = ["http:invoke"]
$ tunnel-relay provision-catalog --config examples/m1-relay.toml --records trial/m6-catalog-mcp.toml --dry-run; echo "exit=$?"
tunnel-relay: invalid provisioning records: service.http_forward_profile "mcp-2025-11-25" is not served by this relay: add it to the [http_forward] profiles of the relay configuration given with --config
exit=1
$ cp examples/m1-relay.toml trial/relay.toml
$ printf '\n[http_forward]\nprofiles = ["mcp-2025-11-25", "acp-http-v1"]\n' >> trial/relay.toml
$ tunnel-relay provision-catalog --config trial/relay.toml --records trial/m6-catalog-mcp.toml --dry-run
Provisioning records are valid for namespace agent-tunnel-m1: ... service=55555555-5555-4555-8555-555555555555 service_type=http-forward http_forward_profile=mcp-2025-11-25 spki_sha256=... grant_operations=http:invoke. This dry run contacted no Redis authority and wrote nothing.
$ sed -n '/^\[service\]/,$p' trial/m6-catalog-acp.toml
[service]
id = "66666666-6666-4666-8666-666666666666"
type = "http-forward"
display_name = "Trial ACP agent"
operations = ["http:invoke"]
http_forward_profile = "acp-http-v1"
[grant]
operations = ["http:invoke"]
$ tunnel-relay provision-catalog --config trial/relay.toml --records trial/m6-catalog-acp.toml --dry-run
Provisioning records are valid for namespace agent-tunnel-m1: ... service=66666666-6666-4666-8666-666666666666 service_type=http-forward http_forward_profile=acp-http-v1 spki_sha256=... grant_operations=http:invoke. This dry run contacted no Redis authority and wrote nothing.
$ sed -n '/^\[service\]/,$p' trial/m6-catalog-fs.toml
[service]
id = "77777777-7777-4777-8777-777777777777"
type = "fs"
display_name = "Trial files"
operations = ["fs:connect", "fs:read", "fs:list"]
fs_case_sensitivity = "insensitive-preserving"
[grant]
operations = ["fs:connect", "fs:read", "fs:list"]
$ tunnel-relay provision-catalog --config trial/relay.toml --records trial/m6-catalog-fs.toml --dry-run
Provisioning records are valid for namespace agent-tunnel-m1: ... service=77777777-7777-4777-8777-777777777777 service_type=fs fs_case_sensitivity=insensitive-preserving spki_sha256=... grant_operations=fs:connect,fs:list,fs:read. This dry run contacted no Redis authority and wrote nothing.
$ sed 's/^type = "echo"/type = "files"/' trial/catalog.toml > trial/unsupported.toml
$ tunnel-relay provision-catalog --config trial/relay.toml --records trial/unsupported.toml --dry-run; echo "exit=$?"
tunnel-relay: invalid provisioning records: service.type "files" is not a type provision-catalog can create; it creates echo, http-forward (MCP and ACP, selected by http_forward_profile) and fs
exit=1
```

The relay you run with `serve` must then use the same `[http_forward]` table.
`scripts/m6-provisioning-verify.sh` provisions each of the three examples with
the shipped commands and runs `serve` and `connect` against a real Redis, with
the export each example's comment shows. The backends are the repository's
synthetic MCP server and ACP agent and a temporary directory holding one
generated file. For each type it checks that the device-side backend answers
one real request through the relay: an MCP `initialize` and a `tools/call`, an
ACP `initialize`, and a 9P read of the file.

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

The activation also binds the namespace to the Redis server's run id, and
Redis draws a new run id **every time it starts**. The binding is a fence: a
Redis that restarted may have come back without data, from an older backup, or
as a stale replica, and a relay must not serve authorization from that. So
after a Redis restart `serve` refuses the namespace with
`stage=authority_identity class=run_changed` until something proves the data
survived, even with persistence on and every key intact. A single relay has
two ways back, both keeping the same namespace with nothing reprovisioned
(M6-C65, section 4, "Redis restarts"): a serving relay configured with
`redis_restart_continuity_seconds` re-binds by itself when a durable Redis
still holds the last token it wrote, and after any other in-place restart the
operator runs `tunnel-relay rebind-redis-run` once. Neither is a path through
a failover or a restore. A second activation is still refused
("namespace already has a deployment incarnation; changing it requires
recovery").

Once `serve` and `connect` are running (section 3.1), a consumer calls
`POST /v1/devices/<device.id>/services/<service.id>/echo` on the consumer
listener with `Authorization: Bearer <token>`. The token must be issued by
`oidc_issuer` for one of `oidc_audience`, carry `sub` equal to `oidc_subject`,
and have `echo:invoke` in its `scope`. The reply is the export's
`device_canary` followed by the request body.

The other types use other routes on the same listener, with the same token
rules, and each needs its own operation in the token's `scope`:

* **MCP**: `/v1/devices/<device.id>/services/<service.id>/http/mcp`, scope
  `http:invoke`, speaking MCP's Streamable HTTP. The request must not carry a
  `User-Agent` or `Accept-Encoding` header, or it gets `400
  HTTP_INVALID_HEAD`, and most HTTP clients send both by default (M6-C58).
* **ACP**: `/v1/devices/<device.id>/services/<service.id>/http/acp`, scope
  `http:invoke`, over **HTTP/2** only. An HTTP/1.1 request gets `501
  HTTP_UNSUPPORTED_FEATURE`. As for MCP, the request must not carry a
  `User-Agent` or `Accept-Encoding` header: the ACP profile refuses both
  (M6-C58).
* **Filesystem**: `/v1/devices/<device.id>/services/<service.id>/fs`, scope
  `fs:connect`. A `GET` returns the export's descriptor. A WebSocket upgrade
  with subprotocol `agent-tunnel.9p.v1` opens a 9P2000.L session
  ([filesystem-api.md](filesystem-api.md)). The bundle ships no client for it.

Further users, devices, services and grants, grant changes and revocations
are section 2.5's commands, run against the same namespace while `serve` runs
(M6-C31). A cluster also needs the authorities in section 3.3 (M6-C22).

### 2.4 Redis credentials

The relay connects to Redis over `rediss://` with the URL in `redis_url`, plus
optional CA and client-certificate files. [redis-tls.md](redis-tls.md) gives the
fields and the file rules. If the URL carries a password, the relay redacts it
from its errors, but the URL is still in the configuration file, so protect that
file like a key. **Do not disable Redis's `default` user when the append-only
file is on** (M6-C66): with `user default off` and the relay on its own ACL
user, Redis 8.4.0 refused to replay the relay's `MULTI`/`EXEC` transactions from
the append-only file on restart (1,298 `NOPERM` errors in its log) and came back
with 5 keys, none of them a tenant, device or credential. With `default`
enabled behind the same password, the same file replayed to 69 keys. No least-privilege Redis ACL for the relay has been derived or
tested; the Redis durability settings the design needs are in
[cluster.md](cluster.md#redis-durability-backup-and-recovery).

When `serve`, `activate-first-incarnation`, `provision-catalog`,
`recovery-observe` or `recover` cannot open Redis, the error names where and
how it failed, in fixed words only (M6-C72): `Redis catalog connection failed;
stage=STAGE [lane=N/6] class=CLASS`. It never prints the URL, a host name, a
password or text from Redis. The relay opens one connection and then six lane
connections; `lane=` appears only when a lane failed, so `lane=3/6` means the
first connection and two lanes worked. `stage` is one of `tls_setup`,
`connection_establishment` (DNS, TCP, TLS handshake and `AUTH`), `ping`,
`primary_identity` (`INFO server`), `authority_profile` or
`authority_identity` (the incarnation check). `class` is `timeout`, `dns`
(the Redis host name did not resolve), `refused`, `io`, `tls_certificate` (the server certificate was rejected, for
example a wrong CA), `tls_alert` (Redis refused the handshake, for example a
missing or unaccepted client certificate), `tls`, `auth` (wrong user or
password), `noperm` (the ACL user may not run the command, for example
`INFO`), `reply`, `invalid_reply`, `run_id_conflict`, `unbound` (the
namespace has no incarnation or run binding: never activated, or Redis came
back without its data), `run_changed` (the namespace is bound to an earlier
Redis run: Redis restarted; section 4, "Redis restarts"), `continuity` (Redis
restarted without the serving relay's last continuity token: it came back
older than that token), `persistence` (the restarted Redis does not show
`appendonly yes`, `appendfsync always` and `no-appendfsync-on-rewrite no`, or
refused `CONFIG GET`), `config` (the configuration was rejected before any
exchange) or `catalog`.
The recovery commands print `recovery Redis connection failed;` followed by
the same `stage=` and `class=` words.

Each Redis connection the relay opens at startup, and each recovery
connection, gets **10 seconds** to open, covering the DNS lookup, TCP
connect, TLS handshake and `AUTH`. After that, each command gets 2 seconds
(M6-C73). A lane that reconnects inside a running relay, for example after a
Redis restart, still has only 2 seconds for the whole reconnect, DNS lookup
included (M6-C74). On a fresh Fly machine the first lookup of a `.internal`
name took about 2 seconds. Before M6-C73 the connection budget was redis-rs's
one-second default, so that lookup alone failed `activate-first-incarnation`
with `stage=connection_establishment class=timeout`.

### 2.5 Day-2 catalog changes: more users and devices, grants, revocation

`provision-catalog` runs once per namespace. After that, seven `tunnel-relay`
commands change the catalog **while `serve` is running**, with no restart
(task row M6-C31). This is how each further tester gets their own user and
device on your relay:

| Command | What it does |
| --- | --- |
| `add-user --records USER.toml` | Adds one user, bound to the `sub` your identity issuer gives them, as a member of an existing tenant |
| `add-device --records DEVICE.toml` | Adds one device, owned by an existing member, with the credential of its issued certificate |
| `add-service --records SERVICE.toml` | Adds one service to an existing device, of the types in section 2.3 |
| `set-grant --records GRANT.toml` | Adds the grant of one user on one service, or replaces it (the revision goes up) |
| `revoke-grant --tenant T --user U --device D --service S` | Revokes one grant |
| `revoke-device --tenant T --device D` | Revokes a device, every credential and grant it has, and its owner lease |
| `revoke-credential --tenant T --device D --credential C` | Revokes one credential of a device, for example a lost key |

Each command also takes `--config`, the relay's own serving configuration,
exactly as `provision-catalog` does, and `--dry-run`. A dry run applies every
rule the write applies to the records themselves and contacts no Redis: the
service types and operations of section 2.3, the device certificate's SAN and
validity, and the no-wildcard rule. What depends on what the namespace already
holds (the tenant exists, the device's owner is an active member, every
identifier is new, the service a grant names has those operations) is checked
by the write. Each write is one Redis script, so it happens completely or not
at all. It refuses a namespace `provision-catalog` has not run on, a relay
configuration whose incarnation is not the active one, and any duplicate: an
existing user, `sub`, device, certificate key or service is refused by name and
nothing is overwritten. None of the commands changes the incarnation. Records
documents refuse unknown fields, like section 2.3's.

A second tester, in the tenant of `examples/m6-catalog.toml`. Their user:

```console
$ printf '[user]\ntenant = "11111111-1111-4111-8111-111111111111"\nid = "88888888-8888-4888-8888-888888888888"\ndisplay_name = "Second tester"\noidc_subject = "second-tester"\n' > trial/user-2.toml
$ tunnel-relay add-user --config examples/m1-relay.toml --records trial/user-2.toml --dry-run
Catalog change is valid for namespace agent-tunnel-m1: add-user tenant=11111111-1111-4111-8111-111111111111 user=88888888-8888-4888-8888-888888888888 role=member. This dry run contacted no Redis authority and wrote nothing.
```

Their device is set up exactly as in section 2.1, with its own `device_id` and
export name, and its certificate is signed by the same issuer. The records
document names the owner and the certificate; like section 2.3's, the path is
relative to the document. The dry run refuses a certificate issued for another
device:

```console
$ mkdir trial-2
$ sed -e 's/33333333-3333-4333-8333-333333333333/99999999-9999-4999-8999-999999999999/' -e 's/44444444-4444-4444-8444-444444444444/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/' examples/m1-client.toml > trial-2/client.toml
$ tunnel-client credentials create --config trial-2/client.toml --csr-out device.csr
Created local credential request at trial-2/device.csr and private key at trial-2/credentials/device-key.pem.
$ printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:99999999-9999-4999-8999-999999999999\n' > trial-ca/device-2-ext.cnf
$ openssl x509 -req -in trial-2/device.csr -CA trial-ca/ca.pem -CAkey trial-ca/ca-key.pem -CAcreateserial -days 1 -extfile trial-ca/device-2-ext.cnf -out trial-2/device-cert.pem
$ printf '[device]\ntenant = "11111111-1111-4111-8111-111111111111"\nowner = "88888888-8888-4888-8888-888888888888"\nid = "99999999-9999-4999-8999-999999999999"\ndisplay_name = "Second tester device"\ncertificate = "device-cert.pem"\n' > trial-2/device.toml
$ tunnel-relay add-device --config examples/m1-relay.toml --records trial-2/device.toml --dry-run
Catalog change is valid for namespace agent-tunnel-m1: add-device tenant=11111111-1111-4111-8111-111111111111 device=99999999-9999-4999-8999-999999999999 owner=88888888-8888-4888-8888-888888888888 credential=... spki_sha256=... credential_valid=.... This dry run contacted no Redis authority and wrote nothing.
$ sed 's/"device-cert.pem"/"..\/trial\/device-cert.pem"/' trial-2/device.toml > trial-2/wrong-device.toml
$ tunnel-relay add-device --config examples/m1-relay.toml --records trial-2/wrong-device.toml --dry-run; echo "exit=$?"
tunnel-relay: invalid device certificate: its urn:agent-tunnel:device: SAN must name device.id 99999999-9999-4999-8999-999999999999
exit=1
```

Its service and the second tester's grant on it. The grant document names the
user, device and service; `set-grant` with the same four identifiers later
replaces it:

```console
$ printf '[service]\ntenant = "11111111-1111-4111-8111-111111111111"\ndevice = "99999999-9999-4999-8999-999999999999"\nid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"\ntype = "echo"\ndisplay_name = "Second tester echo"\noperations = ["echo:invoke"]\n' > trial-2/service.toml
$ tunnel-relay add-service --config examples/m1-relay.toml --records trial-2/service.toml --dry-run
Catalog change is valid for namespace agent-tunnel-m1: add-service tenant=11111111-1111-4111-8111-111111111111 device=99999999-9999-4999-8999-999999999999 service=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa service_type=echo operations=echo:invoke. This dry run contacted no Redis authority and wrote nothing.
$ printf '[grant]\ntenant = "11111111-1111-4111-8111-111111111111"\nuser = "88888888-8888-4888-8888-888888888888"\ndevice = "99999999-9999-4999-8999-999999999999"\nservice = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"\noperations = ["echo:invoke"]\n' > trial-2/grant.toml
$ tunnel-relay set-grant --config examples/m1-relay.toml --records trial-2/grant.toml --dry-run
Catalog change is valid for namespace agent-tunnel-m1: set-grant tenant=11111111-1111-4111-8111-111111111111 user=88888888-8888-4888-8888-888888888888 device=99999999-9999-4999-8999-999999999999 service=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa grant_operations=echo:invoke. This dry run contacted no Redis authority and wrote nothing.
```

Revocations take identifiers, not a document. `add-device` prints the
credential identifier `revoke-credential` needs:

```console
$ tunnel-relay revoke-grant --config examples/m1-relay.toml --tenant 11111111-1111-4111-8111-111111111111 --user 88888888-8888-4888-8888-888888888888 --device 99999999-9999-4999-8999-999999999999 --service aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa --dry-run
Catalog change is valid for namespace agent-tunnel-m1: revoke-grant tenant=11111111-1111-4111-8111-111111111111 user=88888888-8888-4888-8888-888888888888 device=99999999-9999-4999-8999-999999999999 service=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa. This dry run contacted no Redis authority and wrote nothing.
$ tunnel-relay revoke-device --config examples/m1-relay.toml --tenant 11111111-1111-4111-8111-111111111111 --device 99999999-9999-4999-8999-999999999999 --dry-run
Catalog change is valid for namespace agent-tunnel-m1: revoke-device tenant=11111111-1111-4111-8111-111111111111 device=99999999-9999-4999-8999-999999999999. This dry run contacted no Redis authority and wrote nothing.
```

Then, against your Redis, the writes. **Shape-only:** they write Redis, which
this guide's check does not have. `scripts/m6-provisioning-verify.sh` runs
the four additions, `revoke-grant` and `revoke-device` end to end against a
real Redis while `serve` is running, and `revoke-credential`'s refusal of a
credential that is no longer active:

```sh shape-only
tunnel-relay add-user --config /etc/agent-tunnel/relay.toml --records /etc/agent-tunnel/user-2.toml
tunnel-relay add-device --config /etc/agent-tunnel/relay.toml --records /etc/agent-tunnel/device-2.toml
tunnel-relay add-service --config /etc/agent-tunnel/relay.toml --records /etc/agent-tunnel/service-2.toml
tunnel-relay set-grant --config /etc/agent-tunnel/relay.toml --records /etc/agent-tunnel/grant-2.toml
tunnel-relay revoke-grant --config /etc/agent-tunnel/relay.toml --tenant 11111111-1111-4111-8111-111111111111 --user 88888888-8888-4888-8888-888888888888 --device 99999999-9999-4999-8999-999999999999 --service aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
tunnel-relay revoke-device --config /etc/agent-tunnel/relay.toml --tenant 11111111-1111-4111-8111-111111111111 --device 99999999-9999-4999-8999-999999999999
tunnel-relay revoke-credential --config /etc/agent-tunnel/relay.toml --tenant 11111111-1111-4111-8111-111111111111 --device 99999999-9999-4999-8999-999999999999 --credential bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
```

Each addition prints `Added to namespace ...:` and the identifiers it wrote.
**Keep `add-device`'s output:** the `credential=` identifier it prints is
what `revoke-credential` needs, and no command lists credentials.
`set-grant` prints `Added grant` or `Replaced grant` with the grant's
`revision=`. Each revocation prints what it revoked. A refusal exits `1` and
names the record, for example `add-user refused for user ...: catalog
conflict: user already exists`, or `revoke-grant refused: no grant (...) in
this namespace`. `set-grant` refuses a revoked device ("the device is
revoked"). A revoked device's identifier cannot be added again, because
its lease fence must never go backwards, so give a replacement device a new
UUID. As with `provision-catalog`, a first SIGTERM or Ctrl-C lets a command
finish, and a second abandons it with exit `130` and an unknown outcome.

**When a change takes effect.** The relay caches no catalog record. Every
device connection looks up its certificate's key, and every consumer request
looks up the user and authorizes the grant, in Redis. So:

* **A new user, device, service or grant** is used by the next connection or
  request, with no restart. Measured in 8 runs of the end-to-end gate at
  `72ae080`, with `serve` running throughout: the first request after
  `set-grant` was served every time, 16 to 226 ms after the command exited
  (six of the eight under 30 ms), and the second device's first echo was
  served 131 to 145 ms after its `connect` started.
* **`revoke-grant`**: the next request is refused (`403` or `404`). Measured:
  the first request after the command was refused every time, 9 to 26 ms
  after it exited. A request already admitted keeps the authorization it was
  given for at most 5 seconds.
* **`revoke-device` and `revoke-credential`**: the next request is refused,
  and the relay also **closes the device's live session** at its next
  maintenance check, with close reason `AUTHORIZATION_REVOKED`. That holds
  even when a lease renewal lands on the same check: `revoke-device` deletes
  the device's owner lease, and before the M6-C31 review such a check
  reported `OWNER_FENCED` instead. Checks run
  every 500 ms for up to 64 sessions at a time on each relay, so the bound is
  about 500 ms plus one Redis round trip for up to 64 connected devices, and
  another 500 ms for each further 64 (read from the source; only one session
  was measured). Measured for `revoke-device`: the first request after it was
  refused every time, and the session closed 102 to 486 ms after the command
  exited; the device then reported the refused reconnect, `connect` exiting
  `3` with a non-retryable `CREDENTIAL_ERROR`. `revoke-credential` uses the
  same maintenance check but its session close was not measured.

**Not supported in this alpha:** a second tenant, changing or deactivating a
user or a membership, changing a service's type or operations, and
reactivating a revoked device or credential. Renewing a device certificate is
M6-C56. A namespace left partly provisioned (M6-C35) can take these additions,
but it is still not repaired.

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
`examples/m1-relay.toml` sets `boot_id = "replace-with-a-unique-boot-id"`.
For one relay, **delete that line** rather than choosing a value. A `boot_id`
must be fresh for every process ([cluster.md](cluster.md)), so a fixed value
written into a configuration file is reused on every restart. Without the line,
`serve` generates a fresh one each time it starts (measured: `check-serve-config`
and `serve` both accept a configuration without it; M6-C61).

Then start it. **Shape-only:** this command needs your provisioned files and a
provisioned Redis namespace (section 2.3). `scripts/m6-provisioning-verify.sh`
runs it end to end:

```sh shape-only
tunnel-relay serve --config /etc/agent-tunnel/relay.toml
```

Once in each `rotation.interval_seconds`, the device's data socket rotates.
Around that moment a new request can be refused with `503`
`{"code":"PEER_UNAVAILABLE",...,"retryable":true,"retry_after_ms":250}`, even on
a single relay. Consumers must retry it. In a 32-minute run this happened at 4
of 7 MCP rotations (M6-C64; what a consumer should see there is still open as
M3-15).

`serve` stops on SIGTERM or SIGINT (Ctrl-C), the same way for both: it prints
`tunnel-relay stopping: signal=SIGTERM`, drains its listeners and, in a
cluster, its peer and membership tasks, prints `tunnel-relay stopped:
signal=SIGTERM` and exits `0` (measured on a one-node cluster; M6-C23; and on
a one-node relay without `[cluster]`, for both signals, in a dogfood run; M6-C60). A stop
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

When the relay is stopped or restarted (SIGTERM or SIGINT), the relay logs
the session closed with reason `SHUTDOWN`, but the device sees only
`{"code":"TRANSPORT_ERROR","message":"control read failed","retryable":true}`,
the same as a network failure (measured in a dogfood run; M6-C60). With
reconnect on, that is a `disconnected` event and the device reconnects when
the relay returns (measured: under a second after an orderly restart); with
`--no-reconnect` it is the exit, status `4`, and restarting it is up to
whatever runs it (section 4). A `connect` started again straight after a
relay restart was admitted at once. A second `connect` for a device whose
session is still live exits `7` with `OWNER_BUSY`.

**After a network change while the relay stays up** -- a laptop waking on
another network, a NAT or VPN change -- the relay notices within a stated
bound (M6-C68). It sends a WebSocket Ping on every device control socket
every **10 s** and ends a session from which nothing at all -- no message,
no Ping, no Pong -- has arrived for **30 s**; its log line carries
`phase="control_liveness_timeout"` and the closure is counted under cause
`liveness_timeout` in the relay's task-closure diagnostics. That releases the
device's owner slot exactly as a device's own close does, so the client,
refused `OWNER_BUSY` meanwhile, is readmitted at its next attempt: measured
at about 30 s after the path was cut, well inside the client's 60 s
`OWNER_BUSY` window. The bound is 30 s from the device's last frame plus the
relay's 5 s disconnect hand-off; neither value is configurable (both are
`tunnel-protocol` constants, `DEVICE_CONTROL_PING_INTERVAL` and
`DEVICE_CONTROL_IDLE_TIMEOUT`). A healthy idle device is not affected: it
answers each Ping. Anything between a device and the relay -- a load
balancer or proxy in TCP passthrough, as on Fly -- sees a control frame at
least every 10 s, so an idle timeout of 30 s or more there never reaps a
live session. This applies to a device attached to the relay that owns it;
on a cluster, a device attached through a non-owner relay is not yet covered
(M6-C68 records it).

Two limits, both measured (runtime.md has the detail). **After a relay
crash**, the relay's claim on the device outlives it in Redis for up to the
owner lease (30 s by default), and reconnects are refused `OWNER_BUSY` until
it lapses: a device reconnected about 30 s after a SIGKILLed relay was back,
and in under a second after one stopped with SIGTERM (M6-C40). **A refusal after TLS** -- a revoked or
inactive catalog credential, a `device_id` that does not match the
certificate, a protocol version the relay does not speak -- looks to the
client like a relay that dropped the connection, and is retried (M6-C38).
On a single relay the identity refusals -- a revoked, expired or unknown
credential, a `device_id` mismatch -- now close with a typed reason and exit
`3` without a retry (M6-C32, measured with reconnect on); a protocol-version
refusal and a cluster relay's unknown-key refusal (M6-C43) are still retried. Each retry prints its `disconnected` and `backoff` events with
the cause, and `attempt` counts them; set `max_attempts` if a supervisor
should see it fail.

### 3.2 Health endpoints and load balancers

The consumer listener serves two unauthenticated endpoints. Their bodies are
deliberately minimal:

| Endpoint | Answers | Meaning |
| --- | --- | --- |
| `GET /livez` | `200 {"status":"live"}` | The process answers HTTP. It consults nothing else. |
| `GET /readyz` | `200 {"status":"ready"}` or `503 {"status":"unready"}` | Whether this relay should receive new public work |

A relay without `[cluster]` is always ready once it is serving, even while
its Redis authority is unavailable: after a Redis restart it answered `200`
on `/readyz` while every request got `503` `AUTHORIZATION_UNAVAILABLE`
(M6-C67). A cluster relay
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
  certificate. [deploy-fly.md](deploy-fly.md) does this on Fly.io with TCP
  services that have no handlers, for the consumer listener as well, because
  the relay terminates consumer TLS itself.

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
  handle: a crash, an internal failure (exit `1`), `OWNER_BUSY` (exit `7`), or
  an attempt limit you set (exit `4` or `5`), after `RestartSec=30s`. **`RestartPreventExitStatus=2 3`**
  keeps a configuration or credential error (a certificate refused on either
  side) from restarting in a loop: the unit stays failed and
  `journalctl -u tunnel-client` shows the error. If your supervisor should own
  every restart instead, add `--no-reconnect` to `ExecStart`. The relay does
  not retry its own startup (an unreachable Redis exits `1`), so its unit
  restarts it on failure after 10 s, and stops after five starts in ten
  minutes.
- **The client unit has no start limit (`StartLimitIntervalSec=0`), and exit
  `7` is restarted, deliberately.** Before M6-C68, when a device's network
  path vanished while its relay stayed up, the relay kept the old session and
  refused every reconnect `OWNER_BUSY` until it was itself restarted
  (measured by the M6-C23 review: exit `7` after 60.7 s). A relay with the
  M6-C68 fix ends such a session within 30 s of the device's last frame
  (section 3.1), inside the client's 60 s `OWNER_BUSY` window, so the client
  reconnects without exiting. The unit settings stay, because they are what
  keeps the state visible and self-healing wherever the relay does not let
  go in time -- an older relay, or a device attached through a non-owner
  cluster relay (not yet covered): a restart cannot help while the relay
  holds the session, since a fresh process's first `OWNER_BUSY` is terminal.
  With the usual start limit the unit would be **failed and quiet** about
  three and a half minutes after the network change, and would stay failed
  after the relay recovered; with `7` in `RestartPreventExitStatus` it would
  fail at once. Instead it retries every 30 s, each attempt writes the
  `OWNER_BUSY` refusal to the journal, `systemctl status` shows it
  restarting, and it reconnects by itself once the relay lets go. If this
  happens, restarting the **relay** (SIGTERM) clears it.
- **launchd** sends SIGTERM and waits `ExitTimeOut` seconds (default 20; the
  plist sets 60, for the same reason as `TimeoutStopSec`) before SIGKILL.
  `KeepAlive` with `SuccessfulExit = false` restarts the client after an
  unsuccessful exit, at most every `ThrottleInterval` (30 s). launchd has no
  equivalent of `RestartPreventExitStatus`, so a configuration or credential
  error is retried every 30 s: read the log file the plist names. Whether
  launchd resets the signal dispositions it starts a job with was not checked
  here; the binaries override an inherited `SIG_IGN` anyway.

A non-cluster `serve` stopped while serving, with a device connected,
printed its `stopping` and `stopped` lines and exited `0` for both SIGTERM
and SIGINT (dogfood run; M6-C60). SIGHUP is not handled by either binary; neither reloads its configuration.
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
and tickets are not recoverable state. A restore, a cluster's Redis restart,
or any doubt about which Redis is authoritative must go through recovery. Do
not just restart the relays. A single relay's Redis that restarted in place
has its own path, below.

**Redis restarts (one relay, M6-C65).** Redis draws a new run id every time it
starts, and the namespace is bound to the run it was activated or last
re-bound on (section 2.3), so after a restart the relay needs proof that Redis
came back with its data. This covers **one Redis restarting in place from its
own AOF** (a restart, a crash, a host reboot, a redeploy on the same volume).
It is not a failover path: a promoted replica, a restored backup or a new
volume must go through recovery or a new namespace. What the relay accepts, by
case:

| Redis came back | A serving relay with `redis_restart_continuity_seconds` | A relay started afterwards, or one without it |
| --- | --- | --- |
| From its own AOF, with every write it acknowledged, and durable (`appendonly yes`, `appendfsync always`, `no-appendfsync-on-rewrite no`) | Re-binds by itself and serves again; it prints `tunnel-relay: Redis authority restarted; namespace re-bound to the new Redis run` | Refused, `stage=authority_identity class=run_changed`, until you run `rebind-redis-run` once |
| The same, but not durable, or `CONFIG GET` refused | Refused, `class=persistence`; it tries again on every token | Refused, `class=run_changed`; with continuity set, `serve` refuses to start, `class=persistence` |
| From a copy older than the relay's last token (an earlier snapshot or backup, a replica that had not received it) | Refused, `class=continuity`; it keeps refusing that run, even after `rebind-redis-run` | Refused, `class=run_changed`; do **not** run `rebind-redis-run` |
| Empty | Refused, `class=unbound` | Refused, `class=unbound`, and `rebind-redis-run` refuses too |

`redis_restart_continuity_seconds = N` (a top-level key, `1..=60`) makes a
relay without `[cluster]` write a random token (a UUID v4, 122 random bits)
into its namespace every `N` seconds and remember the last one Redis
acknowledged. After a restart, a lane that reaches the new Redis run re-binds
the namespace only if all of these hold: Redis holds that token (or one whose
write outcome the relay could not learn); the token was acknowledged at most
`N` seconds plus the command deadlines (5 s) before the relay's last reply
from the old run, so a token loop that stopped or kept failing while Redis
still answered does not count; and `CONFIG GET` on the new run shows
`appendonly yes`, `appendfsync always` and `no-appendfsync-on-rewrite no`.
`serve` checks the same three settings when it starts and refuses to start
with continuity on a Redis that does not show them, or whose ACL user may not
run `CONFIG GET` (grant `+config|get`). If the token loop ever ends while the
relay serves, the relay prints `Redis restart continuity task ...; token
re-binding is off` and a later restart needs `rebind-redis-run`.

Why that is enough for an in-place restart: AOF replay restores a prefix of
the command history, so a Redis holding the relay's last acknowledged token
holds every write acknowledged before it, and with `appendfsync always` (also
during an AOF rewrite) nothing acknowledged after it is lost by a restart or
a crash. **What it does not catch:** the token only proves Redis is not older
than the relay's last token. An asynchronous replica promoted after a failover
usually holds that token and can still lack writes the old primary
acknowledged after it; a restore or snapshot taken within about `N` seconds
before Redis went away (plus any time the token loop was failing) holds it
too and can lack writes acknowledged after it -- including a `revoke-grant`,
`revoke-device` or `revoke-credential` you ran in that window. So do not set
it on a replicated or failover Redis, and never restore a backup under it. It
is refused with `[cluster]`: a cluster relay never adopts another Redis run,
by token or by re-attestation. The relay itself stays up across the restart;
device sessions end with `AUTHORITY_UNAVAILABLE` and the devices reconnect by
themselves. Measured with the shipped binaries on an AOF Redis
(`scripts/m6-redis-restart-verify.sh`): the echo was served again 40 to 54 s
after a `docker restart` or a `docker kill` and start, most of it the previous
session's owner lease (M6-C40).

A relay that was not running across the restart has no token to compare, so
it refuses the namespace, and you re-attest it once, after checking that Redis
restarted from its own data directory (not a restore, not a new or replaced
volume, not a promoted replica):

```sh shape-only
tunnel-relay rebind-redis-run --config /etc/agent-tunnel/relay.toml --redis-restarted-in-place
```

It prints `Re-bound namespace NS (deployment incarnation INC) from Redis run
OLD to NEW, on the operator's declaration that Redis restarted in place; not
verified.`, or `... is already bound to Redis run RUN; nothing changed.`, and
`serve` then starts on the same namespace. A relay that is still running and
has not refused that run for continuity picks the new binding up at its next
Redis command, with no restart (from the code; the gate measures the
stopped-relay case and the refusal). Run ids are Redis's own random server
identifiers, not secrets. It refuses a namespace with no incarnation or run
binding (`class=unbound`: Redis came back empty; nothing is written), a
namespace whose incarnation is not the configured one, a `[cluster]`
configuration (a cluster recovers Redis with the commands below), and any run
without `--redis-restarted-in-place`. **What it cannot check:** Redis restored
from an older consistent backup, or a promoted replica, looks exactly like
Redis restarted in place, so the flag is your declaration, as `recover`'s
fencing flags are. After a restore, re-binding would bring back whatever the
backup had, such as a revoked credential or grant; use recovery or a new
namespace instead.

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
(`CANCELLED`) need a live relay, so this guide's check does not run them.
`OWNER_BUSY`, exit `7`, was measured by hand against a live relay: a second
`connect` for a device that already has a live session (M6-C60). Exit `6`
has no producer today. With `--json`, `config check` and `connect` print
exactly one result object:

```console
$ tunnel-client config check --config trial/client.toml --json
{"schema_version":1,"command":"config check","ok":true,"result":{"state":"valid"},"error":null}
```

Where to look next: [runtime.md](runtime.md#error-and-incident-vocabulary)
has the error vocabulary and the runbook questions, and
[cluster.md](cluster.md) has cluster failure behaviour.
