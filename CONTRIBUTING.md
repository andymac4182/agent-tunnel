# Contributing

Agent Tunnel is implementing M1. Start with [the roadmap](docs/roadmap.md),
the matching protocol/design document, and the [M1 harness guide](docs/m1-harness.md).
Keep implementation, planned behavior, and verified evidence separate in code,
tests, and documentation.

Hosted verification: [M1 CI checks](https://github.com/andymac4182/agent-tunnel/pull/10/checks).

## Current verification evidence

The local M1 gate passed on 2026-09-09 on macOS arm64 with Rust 1.95.0 and
Redis 8.4: formatting, strict Clippy, 62 workspace tests, five explicit Redis
integration tests, the full real-socket/CLI/H3 acceptance harness and the
same-dataset Redis AOF restart check. Hosted CI results are linked in this document. The [harness guide](docs/m1-harness.md) records the runnable boundary.

## M1 boundaries

The client has two configuration types. `tunnel-client config check --config
PATH` parses the live `RuntimeConfig`; the legacy `tunnel-client check-config
[PATH]` command parses `tunnel_core::ClientConfig` and its historical rotation
fields. The client provisions a private key and CSR locally, relies on an
approved external issuer, and imports only a matching certificate chain plus a
separate server CA bundle. It opens one mTLS control WebSocket and one mTLS
data WebSocket. M1 closes both on transport failure and requires a fresh
session; it does not rotate data sockets or replay retained operations.

The relay's `serve --config PATH` command reads its OIDC issuer/audience/JWKS,
`redis_url`, `redis_namespace`, `deployment_incarnation`, and TLS paths before
starting the consumer HTTPS and device mTLS listeners. Its `check-config [PATH]`
command remains the legacy bootstrap validator. M1 exposes the synthetic `echo`
export only. MCP, filesystem, ACP, and computer-use adapters are later
milestones.

Redis is the M1 authority for tenant, user, membership, device, service, grant,
and credential records. A Redis URL or namespace does not by itself establish
relay identity or fencing. Persistence, restore, ACLs, authority-loss behavior,
and deployment incarnation handling must be explicit; multi-relay ownership,
signed membership/public keys, and recovery are M7 work.

The bounded private H3 probe is transport evidence for mTLS, peer role identity,
approved public-key pins, and body/deadline limits. It is separate from the M7
three-relay cluster, Redis membership/key approval, ownership, fencing, and
recovery work.

## Local checks

Run from the repository root with the pinned Rust toolchain and committed
lockfile:

```sh
cargo build --workspace --locked --bins
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

cargo run --locked -p tunnel-client -- \
  config check --config examples/m1-client.toml
cargo run --locked -p tunnel-client -- \
  check-config examples/client.toml
cargo run --locked -p tunnel-relay -- \
  check-config examples/relay.toml
```

The configuration commands are read-only. `tunnel-relay serve` and client
`connect` require real credentials, OIDC public keys, Redis, and listener
configuration; the checked-in M1 examples contain paths and values to replace,
not working secrets.

M1 acceptance requires a reachable disposable Redis service. After exporting a
`TEST_REDIS_URL`, build the workspace binaries and run the single fail-closed
harness command:

```sh
cargo build --workspace --locked --bins
TEST_REDIS_URL=redis://127.0.0.1:56379 \
  cargo run --locked -p tunnel-test-harness -- verify
```

`verify` is the one entry point for the full acceptance run, including
`acceptance::verify`, `admission::verify`, and `peer::verify` as they land. It
must use the production Redis authority and real relay sockets. It must not report
success from fixture construction alone. Follow [docs/m1-harness.md](docs/m1-harness.md)
for a disposable local Redis container, the credential CSR/import flow, and
evidence/redaction rules.

When reporting a check, include the commit, toolchain, operating system, exact
command, and result. The local M1 evidence above includes real HTTPS/WSS CLI
traffic, admission negatives, and private H3 success/negative probes. Hosted
CI remains pending. Do not turn a local unit test, an in-process router call,
or an unexecuted Redis job into a claim of real-socket acceptance.

## Redis persistence and recovery

The harness uses an isolated Redis key namespace and cleans only keys belonging
to its run. Redis is the durable authority catalog for every tenant, user,
membership, device, service, grant, and credential record formerly assigned to
PostgreSQL. Socket connections, queues, in-flight operations, and other
process-local session state remain ephemeral; Redis restart does not recover a
live transport. In the narrow M1 Redis profile, the durable device hash also
stores lease fields and expiry; lease validity is checked logically, the hash
has no Redis TTL, and complete `deployment_incarnation` plus `run_id` guards
make stale owner fields non-authoritative. Separate TTL namespaces remain an
M7 design. The local AOF check passed with catalog-conflict, persistent
revocation, and new-owner-incarnation assertions. It covers one Redis instance
and does not prove HA failover or multi-relay recovery. `connect_for_recovery`
and `activate` are operator-only actions and require an external durable
catalog, revocation reconciliation, and a new approved incarnation before
they are called. A new incarnation fences owners but cannot by itself prove
that revocations were not rolled back. The external checkpoint gate and safe
backup/rollback handling remain M7 work; M1 does not claim safe restoration of
arbitrary backups. A real deployment must still define persistence,
backup/restore, access control, startup readiness, and the fail-closed result
when authority is unavailable or its incarnation changes. Do not treat
discovery, replica acknowledgement, or a Redis mutation as proof of relay
identity, ownership, or application side effects.

## Test data and desktop safety

Use isolated key namespaces, fixture certificates, synthetic JWTs, and
deterministic echo canaries. The harness owns bounded cleanup for each run. Use
the TLS-opaque fault proxy from the harness in M2 transport tests; inject
pauses, byte drops, and close faults through its bounded API and assert its
counters rather than changing the application handler.

Computer-use tests run only against a dedicated disposable VM or isolated test
computer containing synthetic fixture content. Never exercise computer control
against a contributor's active desktop, normal desktop session, or real
account. Screenshots and logs must contain fixture content only.

## Diagnostics and redaction

Diagnostics are versioned structured records. Include stable non-secret IDs and
state such as tenant/device principal, owner/session/connection, stream
direction, phase, queue bytes, sequence cursors, fence/ACK positions, active
sockets, and operation outcome. Keep payloads out of logs and status output.

Never emit bearer tokens, private keys, CSRs, passwords, Redis URL credentials,
file contents, screenshots, or unredacted authorization bodies. Redaction tests
should plant synthetic marker values and assert that they do not occur in logs,
JSON diagnostics, failure traces, or saved harness output.

## Pull requests and CI

Keep changes small and tie each behavior to its invariant and acceptance gate.
Protocol changes update the wire contract and meaningful failure tests together.
Use `--locked` for Cargo validation and keep `Cargo.lock` committed. CI must run
formatting, strict Clippy, and workspace tests on the supported Linux, macOS,
and Windows jobs, build the workspace binaries, and keep the Redis-backed M1
acceptance result visible. The local acceptance and AOF restart results are
recorded above; CI results are linked in this document. A green configuration check alone
does not prove mTLS, tenant isolation, adapter compatibility, cluster routing,
or release readiness.

Describe PRs with the behavior changed, the relevant invariant, and exact
verification evidence. Do not claim unvalidated tests, remote adapters, M2
rotation/replay, or M7 cluster behavior as delivered.
