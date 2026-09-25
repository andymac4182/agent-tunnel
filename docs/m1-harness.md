# M1 acceptance harness

Status: the local M1 acceptance is verified. On
2026-09-09 macOS arm64 with pinned Rust 1.95.0 and Redis 8.4, the locked
formatting/Clippy checks, 62 workspace tests, five explicitly executed real Redis integration tests, and the
Redis AOF restart check passed. Full real HTTPS/WSS CLI acceptance passed for
five clients across two tenants, including admission certificate/ticket/stale
epoch negatives and private H3 success/negative probes. This page records local
evidence and preserves the M7 boundaries; production HA and multi-relay readiness remain later gates.

The harness is the shared setup layer for M1 tests. It creates an isolated,
randomly named Redis key namespace, seeds the production authority
implementation, creates a fixture PKI and OIDC issuer, and starts the
production relay on ephemeral loopback listeners. Acceptance code drives those
listeners through real TLS, HTTPS, and WebSocket clients. It must fail when
Redis is absent or the production authority cannot be used; creating in-memory
fixtures alone is not a successful run.

Hosted verification: [M1 CI checks](https://github.com/andymac4182/agent-tunnel/pull/10/checks).

## Run it

Build every workspace binary before invoking the harness:

```sh
cargo build --workspace --locked --bins
TEST_REDIS_URL=redis://127.0.0.1:56379 \
  cargo run --locked -p tunnel-test-harness -- verify
```

`TEST_REDIS_URL` is an explicit disposable-harness input. It may use loopback
plaintext Redis because it never starts the production `tunnel-relay serve`
configuration; a serving configuration must use `rediss://`.

`verify` is the single M1 entry point. It requires `TEST_REDIS_URL`, leases a
fresh run namespace, and executes the full acceptance flow through
`acceptance::verify`, `admission::verify`, and `peer::verify` as those modules
are wired into the binary. It must use the production Redis authority and real
consumer, device, and peer sockets. A missing Redis URL, failed connection,
failed authority setup, or failed socket probe is an error. There is no implicit
fixture-only success; a run is successful only when the complete verification
flow reaches its acceptance result. The local run reached that result; hosted
CI remains pending.

The harness reports non-secret correlation values such as the generated key
namespace, run ID, listener addresses, tenant/device counts, and probe phases.
Preserve that output with the commit and environment when reporting evidence,
but redact URLs that contain credentials and any tokens, CSRs, or private key
material. Preserve the local evidence with the commit and environment; hosted
CI evidence is still pending.

## Disposable Redis

Use a disposable local Redis instance or a dedicated CI service. For Docker,
bind only to loopback and remove the container after the run:

```sh
docker run --rm --name agent-tunnel-m1-redis \
  -p 127.0.0.1:56379:6379 \
  -d redis:8.4.0-alpine

export TEST_REDIS_URL=redis://127.0.0.1:56379
cargo build --workspace --locked --bins
cargo run --locked -p tunnel-test-harness -- verify

docker stop agent-tunnel-m1-redis
```

The harness appends a validated random suffix to its namespace prefix, so
concurrent runs on the same Redis service do not share authority keys. It uses
the supplied Redis URL and cleans only keys that belong to its run. It must not
call `FLUSHDB` or remove keys outside that namespace. Do not point the command
at a production instance or a Redis service containing user data.

The run namespace isolates fixture cleanup; it does not claim that M1 has
separate TTL namespaces for lease records. In the narrow M1 Redis profile, the
durable device hash stores lease fields and expiry without a Redis TTL. Relay
lease validity is checked logically, and complete `deployment_incarnation` plus
`run_id` guards make stale owner fields non-authoritative. Separate TTL
namespaces remain an M7 design.

A disposable Redis run is suitable for acceptance setup, not evidence of
automatic promotion or three-relay recovery. Redis is the durable authority
catalog for every tenant, user, membership, device, service, grant, and
credential record formerly assigned to PostgreSQL. Relay sockets, queues,
in-flight operations, and other process-local session state remain ephemeral;
Redis restart does not restore a live transport. The local AOF restart check
passed with the exact catalog-conflict assertion plus persistent revocations and
a new owner incarnation. It covers one Redis instance only, not HA failover.
`connect_for_recovery` and `activate` are operator-only actions and require an
external durable catalog, revocation reconciliation, and a new approved
incarnation before they are called. A new incarnation fences owners but cannot
by itself prove that revocations were not rolled back. The external checkpoint
gate and safe backup/rollback handling remain M7 work; M1 does not claim safe
restoration of arbitrary backups. Deployment must still define persistence,
backup/restore, ACLs, readiness, and the fail-closed behavior when authority is
unavailable or its `deployment_incarnation` has changed. Redis discovery or
replica acknowledgement does not establish relay identity, ownership,
fencing, or completed application effects.

The separate restart fixture is available as:

```sh
./scripts/m1-redis-restart-verify.sh
```

It creates an isolated AOF Redis container, asks the harness to seed a named
namespace, restarts that container, and asks the harness to check the receipt.
The local AOF restart acceptance passed, including the catalog-conflict,
revocation, and new-owner-incarnation assertions. It is evidence for the
single-instance restart profile only; running the default `verify` command is
still the M1 acceptance entry point.

## What the M1 probes cover

The acceptance topology contains two tenants, five devices, and four consumers.
The relay uses the same Redis authority and JWT verifier that the runtime uses:

- OIDC fixtures issue short-lived RSA JWTs, and the relay is configured with the
  fixture issuer, audience, and approved public JWK. Private signing keys never
  enter relay configuration or diagnostic output.
- Device certificates are issued by the fixture PKI with separate device,
  server, and peer roles. The device endpoint requires a client certificate on
  both WebSockets. Consumer HTTPS uses the configured bearer verifier.
- The `echo` export is the only M1 service. Its canary bytes are synthetic and
  may contain binary values so tests detect accidental string conversion.
- Authorization and certificate identities come from the production Redis
  authority and verified TLS metadata. A request header, URL parameter, peer
  address, or caller-supplied device label cannot create identity.

The private peer check is deliberately a separate transport probe. The local
acceptance passed its mutual-TLS, peer-role, approved-SPKI-pin, bounded HTTP/3
body, and negative cases for wrong roots, roles, pins, size, and deadline.
That proves the selected QUIC/H3/rustls boundary only. It does not prove M7's
three-relay owner routing, signed Redis membership/public-key distribution,
leases, fencing, HA failover, recovery, or cross-node consumer ingress; those
remain planned M7 acceptance work.

M1 opens one mTLS control WebSocket and one mTLS data WebSocket per client
session. M1 has no scheduled data-socket rotation, retained replay, or automatic
reconnect: a transport failure closes the pair and the caller starts a fresh
session. Rotation, immutable drain fences, and replay/recovery belong to M2.
M1 exposes no remote MCP, filesystem, ACP, or computer-use adapter.

## Credential provisioning

The client creates a private key locally and emits a CSR. An approved external
issuer signs the CSR; the client then imports the issued certificate chain and a
separately supplied relay trust bundle. Import checks that the certificate
public key matches the pending private key and refuses to overwrite configured
files. There is no automatic enrollment or local certificate issuer in M1.

The runtime client configuration is checked with `RuntimeConfig`:

```sh
cargo run --locked -p tunnel-client -- \
  config check --config examples/m1-client.toml

cargo run --locked -p tunnel-client -- \
  credentials create --config examples/m1-client.toml \
  --csr-out credentials/device.csr.pem

# Have the approved external issuer sign credentials/device.csr.pem.
cargo run --locked -p tunnel-client -- \
  credentials import --config examples/m1-client.toml \
  --certificate credentials/device-cert-chain.pem \
  --server-ca credentials/relay-ca.pem

cargo run --locked -p tunnel-client -- \
  connect --config examples/m1-client.toml
```

Paths supplied to the client are resolved relative to the configuration file.
The example therefore places its placeholder credential files beneath
`examples/credentials/` when invoked from the repository root. `connect` stays
in the foreground; `--json` is available on `config check` and `connect` for
versioned structured diagnostics.

The legacy command remains available for the bootstrap configuration type:

```sh
cargo run --locked -p tunnel-client -- check-config examples/client.toml
```

`check-config` parses `tunnel_core::ClientConfig` and its historical rotation
fields. It does not validate the M1 `RuntimeConfig`. The relay has the
analogous legacy `check-config [PATH]` command and a separate runtime command:

```sh
cargo run --locked -p tunnel-relay -- check-config examples/relay.toml
cargo run --locked -p tunnel-relay -- \
  check-serve-config --config examples/m1-relay.toml
cargo run --locked -p tunnel-relay -- \
  serve --config examples/m1-relay.toml
```

`serve --config` reads OIDC/JWKS, `redis_url`, `redis_namespace`,
`deployment_incarnation`, and TLS paths and starts the public consumer HTTPS
listener plus the device mTLS listener. The checked-in relay example is a
shape/reference file; its placeholder credentials, Redis endpoint/namespace,
incarnation, and public keys must be replaced before starting a real relay.

`check-serve-config --config PATH` is the read-only dry run for that same
`ServeConfig`. It applies every rule `serve` applies to the configuration
document, including the Redis authority namespace rule and the Redis TLS,
rotation, cluster and recovery cross-field rules, and it opens no listener,
makes no Redis or peer connection, reads no credential, key or JWKS material,
and writes nothing. It exits 0 when the configuration is valid and 1 with a
redacted field-level reason on stderr otherwise. Validating the referenced
material is `serve`'s own startup work, so a successful dry run is evidence
about the configuration document and not about the deployment's files.

Use it, not `check-config`, for a serving document: the legacy
`check-config [PATH]` parses `tunnel_core::RelayConfig`, which cannot represent
a `ServeConfig` at all. `examples/m1-relay.toml` previously shipped
`redis_namespace = "agent-tunnel/m1"`, a namespace the Redis authority refuses,
so the `serve --config` command above failed at startup while CI's legacy
`check-config examples/relay.toml` stayed green on a different file. CI now
dry-runs every `examples/*-relay.toml`.

## Fault injection and later milestones

The harness library includes a TLS-opaque TCP pass-through proxy for M2. A test
can insert bounded pauses, byte drops, or close-after-byte faults in either
direction and assert accepted/active/completed connection counts and byte/fault
counters. Reuse this proxy to exercise transport failure and drain behavior
through real sockets; do not put fault behavior in the relay handler or
silently retry an ambiguous operation.

Computer-use work uses only synthetic content in a dedicated disposable VM or
test computer. Never run a computer-control test against a contributor's active
desktop. M1's harness does not open a desktop session or invoke a remote
adapter.

## Hosted CI evidence

Recorded for task row M1-04, which asks for the exact commit, runner and
command. Hosted GitHub Actions runs again since 2026-09-24; the dated local
results above are unchanged by it.

| Commit | Run and job | Runner | Command | Result |
| --- | --- | --- | --- | --- |
| `50b12df` | 36006258279, `M1 real-socket acceptance (Redis)` 107655066179 | ubuntu-latest (ubuntu-24.04), Redis `8.4.0-alpine` service container | `cargo test -p tunnel-catalog --test redis_catalog --locked -- --ignored`; `cargo run --locked -p tunnel-test-harness -- verify`; `bash scripts/m1-redis-restart-verify.sh`; `sh scripts/m6-redis-restart-verify.sh` | success; `M1 acceptance passed: clients=5 echo_requests=21 ... auth_rejections=4` |
| `50b12df` | 36006258279, `M1 real-socket acceptance (macOS, Redis)` 107655066592 | macos-latest (macos-26-arm64), Homebrew Redis 8.10.1 started by the job | the `redis_catalog` tests and `verify` as above; the two restart scripts need Docker and are Linux-only | success; same acceptance line |
| `50b12df` | 36006258279, `Rust (ubuntu-latest)`, `Rust (macos-latest)`, `Rust (windows-latest)` | ubuntu-24.04, macos-26-arm64, windows-2025-vs2026 | `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo test --workspace --all-targets --locked --no-fail-fast` (Windows adds `--exclude tunnel-relay`, M6-C83); the example-configuration dry runs | success on all three |

There is **no Windows M1 acceptance**: the relay refuses to start off Unix
(M6-C83) and credential creation and import are unsupported there. Whether
Windows is advertised as a client-only target is an open owner decision on
M1-04. Before `4aab5c4` the hosted acceptance was **not reliably green**: its
pre-body admission assertion failed on four hosted Linux runs and, at `64863b5`,
on macOS (run 36097122395, job 107951664801). That was M6-C85, a harness
ordering race and not a relay defect. A held request was counted as holding
an admission permit once it was queued on the client, so the ninth request
could take the eighth permit first. From `4aab5c4` each hold waits for the
relay's `100 Continue`, which is written only once the handler holds both
permits, and the ninth request is sent once and must be answered
`429 ADMISSION_LIMIT`. The hosted repeats after that fix are below.

| Commit | Run and attempt | Job | Runner | Result |
| --- | --- | --- | --- | --- |
| `4aab5c4` | 36101014774, attempt 1 (`ci-main-probe`) | `M1 real-socket acceptance (Redis)` 107963302386 | ubuntu-latest, Redis `8.4.0-alpine` service | success; `M1 acceptance passed: clients=5 echo_requests=21 ...` |
| `4aab5c4` | 36101014774, attempt 1 | `M1 real-socket acceptance (macOS, Redis)` 107963302352 | macos-latest, Homebrew Redis | success; same line |
| `4aab5c4` | 36101014774, attempt 2 | `M1 real-socket acceptance (Redis)` 107970760129 | ubuntu-latest | success |
| `4aab5c4` | 36101014774, attempt 2 | `M1 real-socket acceptance (macOS, Redis)` 107970760302 | macos-latest | success |
| `4aab5c4` | 36101014774, attempt 3 | `M1 real-socket acceptance (Redis)` 107977833722 | ubuntu-latest | success |
| `4aab5c4` | 36101014774, attempt 3 | `M1 real-socket acceptance (macOS, Redis)` 107977833981 | macos-latest | success |

Six of six hosted M1 jobs passed at `4aab5c4`. Locally at the same commit, the
acceptance passed 30 of 30 under 16 CPU burners, against 2 of 20 red before the
fix, and `scripts/m1-harness-verify.sh` passed 5 of 5.

## Required checks and evidence

The required repository checks are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The local macOS arm64 checks and full M1 acceptance passed as recorded above.
CI must run these locked checks on its supported Linux, macOS, and Windows
jobs, build the workspace binaries, and keep the Redis-backed acceptance result
visible. Hosted CI results are linked in this document. Report
M7 cluster routing, HA failover, and any unexecuted platform job as pending.

Diagnostics use a versioned structured envelope with `schema_version`, command,
success, and typed error fields. Events should identify the tenant/device
principal, owner/session/connection, stream direction, phase, and counters such
as queue bytes, sequence cursors, fence/ACK positions, and active sockets.
They must never include request bodies, file contents, screenshots, bearer
tokens, CSRs, private keys, passwords, Redis URL credentials, or unredacted
authorization URLs. Redaction tests use synthetic marker values and must fail
if a marker appears in logs or status output.
