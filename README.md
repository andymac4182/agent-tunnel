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

**Status: project bootstrap and design.** The working code validates configuration. Networking, authentication, adapters, and remote execution are planned, not implemented. This repository starts private; MIT licensing prepares it for a future open-source release without changing its visibility.

## What we are building

- An Axum relay cluster serving multiple users, with multiple connected devices and concurrent host/agent consumers per user.
- A Rust client CLI authenticating to the relay with mTLS on both device WebSockets.
- Peer-to-peer HTTP/3 connections with mTLS between relay servers; Redis distributes approved server public keys and routing presence.
- One persistent control WebSocket and one active data WebSocket per device connection.
- Data connection rotation every **300 seconds by default**, configurable per deployment. Explicit per-stream drain watermarks and acknowledgements precede handover; a bounded replacement overlap briefly permits a third socket.
- Independent stream identities and sequence counters in each direction, preserved across scheduled socket rotation.
- A **9P/WebSocket filesystem API** with native adapters for Files SDK, Mastra, AI SDK, and just-bash; separate MCP and [CUA](https://github.com/trycua/cua) services.
- ACP over HTTP through the tunnel, so an authorized host can interact with an allowlisted agent supervised by the CLI.
- Explicit grants for each device, service, filesystem mount, and computer-use capability.

Cluster support is required for the private alpha. Development begins with a single-process test fixture, then proves three-node ownership/routing and failure behavior before release. Redis discovery alone does not establish identity or make failover strongly consistent; the trust and recovery profile is explicit in the cluster design.

## Start here

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Components, users/devices, routing, trust boundaries, scaling |
| [Tunnel protocol](docs/protocol.md) | Pairing, rotation, replay, failure semantics, limits |
| [Runtime and client CLI](docs/runtime.md) | Axum listeners, device mTLS, commands, debug surfaces |
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
cargo run --locked -p tunnel-client -- --help
cargo run --locked -p tunnel-client -- check-config examples/client.toml
cargo run --locked -p tunnel-relay -- check-config examples/relay.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

These commands check configuration and run starter tests. They do not open a tunnel or enable access to your computer. See the example TOML files for the exact supported configuration fields; service grants and adapter configuration will arrive with their milestones.

## First implementation goal

Connect three enrolled test devices belonging to two users to a relay, route concurrent echo streams only to authorized devices, and rotate their data sockets repeatedly while the control connection remains stable. Prove isolation, bounded memory, and reconnect behavior before connecting real files or desktops.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Transport and privileged adapters are Rust. A shared TypeScript filesystem client and small native SDK adapters provide the application integration layer. Credentials stay in the runtime secret store, outside this repository.

License: [MIT](LICENSE).
