# Agent Tunnel

A Rust reverse tunnel that will let hosts and agents access MCP servers, virtual filesystems, computer-use services, and CLI agents on enrolled computers through outbound connections.

```text
Agent in the cloud → Agent Tunnel Server → WebSocket tunnel → Desktop machine
                                                              ├─ ACP agent
                                                              ├─ MCP services
                                                              ├─ CUA computer use
                                                              └─ Virtual filesystem
```

The desktop CLI initiates the tunnel with mTLS. Authorized cloud agents call server endpoints; no inbound desktop port is required. Service traffic flows in both directions over the data channel.

**Status: M1 and M2 are locally verified. M7 implementation and integration
verification are in progress.** On
2026-09-09, macOS arm64 with Rust 1.95.0 and Redis 8.4 passed formatting,
strict Clippy, 62 workspace tests, five real Redis integration tests, the
five-client/two-tenant HTTPS/WSS/CLI acceptance harness, the private H3 probe
and the Redis AOF restart check. See [the evidence and repeatable commands](docs/m1-harness.md).
M2 ordered rotation and bounded retained replay are also locally verified: 151 workspace tests, the real-socket fault suite, and three actual 300-second rotations in 903.05 seconds. See [M2 evidence and repeatable commands](docs/m2-verification.md).
M7 adds signed Redis membership, incarnation-scoped ownership/tickets, owner
fencing, dynamic peer pins, private mTLS HTTP/3 routing, cluster startup
wiring, and a reusable three-relay Redis acceptance harness. See [M7 evidence
and repeatable commands](docs/m7-verification.md). M3/M4/M5/M8 adapters and
M6 release packaging remain subsequent milestones.
The repository remains private; its MIT license prepares for a future OSS release.

Hosted verification: [M1 CI checks](https://github.com/andymac4182/agent-tunnel/pull/10/checks).

## What we are building

- An Axum relay cluster serving multiple users, with multiple connected devices and concurrent host/agent consumers per user.
- A Rust M1 client CLI authenticating to the relay with mandatory mTLS on both device WebSockets.
- One control WebSocket and one data WebSocket per M1 device session. A transport failure closes the pair and requires a fresh session; M1 has no data-socket rotation or retained replay.
- M1 catalog authority uses Redis for tenant, user, membership, device, service, grant, and credential records. Its persistence, restore, and fail-closed behavior are explicit deployment requirements.
- A private HTTP/3 mutual-TLS peer transport with signed Redis membership/key approval, owner routing/fencing, dynamic pins, and a three-relay synthetic acceptance harness. Automatic Redis promotion and HA recovery remain outside the supported profile.
- M2 data connection rotation every **300 seconds by default**, configurable per deployment, with explicit per-stream drain watermarks and acknowledgements before handover.
- A reusable M1 acceptance harness using Redis-backed authority, with fixture PKI, configured JWT public keys, real relay listeners, and an echo export. Its local M1 verification is recorded above; CI results are linked in this document.
- A **9P/WebSocket filesystem API** with native adapters for Files SDK, Mastra, AI SDK, and just-bash; separate MCP and [CUA](https://github.com/trycua/cua) services are planned milestones.
- ACP over HTTP through the tunnel, so an authorized host can interact with an allowlisted agent supervised by the CLI.
- Explicit grants for each device, service, filesystem mount, and computer-use capability.

All authority records formerly assigned to PostgreSQL, including tenant, user,
membership, device, service, grant, and credential records, live in the Redis
catalog. Redis persistence is required for that catalog; relay sockets, queues,
in-flight operations, and other process-local session state remain ephemeral
and are not reconstructed by a Redis restart. The local AOF check proves the
tested single-instance restart behavior, including revocations and a new owner
incarnation; it does not prove HA failover. Redis discovery alone does not
establish relay identity or make failover strongly consistent. M1 uses a bounded
local authority profile; M7 adds signed relay membership/public-key records,
ownership leases, fencing, and explicit recovery. A disposable Redis run is not
evidence of multi-relay recovery. In the narrow M1 Redis profile, the durable
device hash also stores lease fields and expiry; relay lease validation is
logical, the hash has no Redis TTL, and complete `deployment_incarnation` plus
`run_id` guards make stale owner fields non-authoritative. Separate TTL
namespaces remain an M7 design. `connect_for_recovery` and `activate` are
operator-only recovery actions: call them only after an external durable
catalog is available, revocations have been reconciled, and a new approved
incarnation has been established. A new incarnation fences owners but cannot
by itself prove that revocations were not rolled back. The external checkpoint
gate and safe backup/rollback handling remain M7 work; M1 does not claim safe
restoration of arbitrary backups.

## Start here

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Components, users/devices, routing, trust boundaries, scaling |
| [Tunnel protocol](docs/protocol.md) | Pairing, rotation, replay, failure semantics, limits |
| [Runtime and client CLI](docs/runtime.md) | Axum listeners, device mTLS, commands, debug surfaces |
| [M1 acceptance harness](docs/m1-harness.md) | Redis-backed real-socket verification, credentials, fixtures, and evidence |
| [M2 verification](docs/m2-verification.md) | Rotation implementation status and required recovery/real-socket evidence |
| [Task tracker](docs/tasks.md) | Stable milestone task IDs, owners, status, acceptance scope, and evidence |
| [Relay cluster](docs/cluster.md) | HTTP/3 peers, mTLS, Redis key distribution, ownership, recovery |
| [Filesystem API](docs/filesystem-api.md) | Endpoint, authentication, capabilities, paths, byte/operation semantics |
| [SDK adapter contracts](docs/filesystem-adapters.md) | Files SDK, Mastra, AI SDK, just-bash, compatibility gaps and implementation slices |
| [ACP over HTTP](docs/acp.md) | Host-to-CLI-agent sessions, streaming, callbacks, permissions, cancellation |
| [HTTP forwarding](docs/http-forwarding.md) | Bounded request/response records over ordered tunnel streams |
| [MCP compatibility](docs/mcp.md) | Current and legacy protocol profiles, HTTP and stdio bridges |
| [Filesystem and CUA integration](docs/integrations.md) | Upstream contracts, adapters, compatibility spikes |
| [Build roadmap](docs/roadmap.md) | Ordered milestones with acceptance gates |
| [Testing](docs/testing.md) | Contract, isolation, failure, load, and platform testing |
| [Design decisions](docs/decisions.md) | Initial choices and decisions still to validate |
| [Sources](docs/sources.md) | Research provenance and immutable upstream references |

## Run the starter

Install Rust through rustup; the repository pins Rust 1.95.0. From the repository root:

```sh
cargo build --workspace --locked --bins
cargo run --locked -p tunnel-client -- --help
cargo run --locked -p tunnel-client -- config check --config examples/m1-client.toml
cargo run --locked -p tunnel-client -- check-config examples/client.toml
cargo run --locked -p tunnel-relay -- check-config examples/relay.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The client `config check` command validates the M1 `RuntimeConfig`; the legacy
`check-config` command validates the bootstrap `tunnel_core::ClientConfig` and
its historical rotation fields. These validation commands are read-only; the
M1 runtime path also starts real HTTPS/WSS listeners when `serve` or `connect`
is run with credentials. The checked-in M1 relay file is a shape/reference file
whose `redis_url`, `redis_namespace`, `deployment_incarnation`, OIDC JWKS, and
TLS paths must be replaced before `serve`. See [the M1 harness guide](docs/m1-harness.md)
for disposable Redis and the exact acceptance command. Local verification is
recorded above; CI results are linked in this document.

## First implementation goal

The locally verified M1 slice connects five clients across two tenants to a
relay, routes authorized echo streams over the two mTLS sockets, and covers
isolation, bounded memory, authorization, quota, revocation, admission
negative cases, and fresh-session behavior after transport failure. Its private
H3 probe includes success and negative cases for the transport boundary only;
it is not cluster routing. Redis membership recovery, HA failover, ownership,
and expanded fencing wait for M7. M2 adds locally verified ordered rotation
and bounded retained transport replay; remote adapters remain later milestones.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Transport and privileged adapters are Rust. A shared TypeScript filesystem client and small native SDK adapters provide the application integration layer. Create device keys and CSRs locally, use an approved external issuer, and import only a matching certificate chain plus explicit server trust bundle. Credentials stay in the runtime secret store, outside this repository.

License: [MIT](LICENSE).
