# Agent Tunnel

A Rust reverse tunnel that will let agents access MCP servers, files, and computer-use services on enrolled computers through outbound connections.

**Status: project bootstrap and design.** The working code validates configuration. Networking, authentication, adapters, and remote execution are planned, not implemented. This repository starts private; MIT licensing prepares it for a future open-source release without changing its visibility.

## What we are building

- A self-hostable relay serving multiple users, with multiple connected devices and concurrent agent consumers per user.
- One persistent control WebSocket and one active data WebSocket per device connection.
- Data connection rotation every **300 seconds by default**, configurable per deployment. A bounded replacement overlap briefly permits a third socket so streams can move without restarting work.
- Protocol-neutral logical streams, with adapters for MCP, a **9P filesystem over WebSocket for just-bash**, and [CUA](https://github.com/trycua/cua).
- Explicit grants for each device, service, filesystem mount, and computer-use capability.

The initial deployment is one relay process with durable identity/policy storage. Multi-user support is part of the first network milestone; distributed relay deployment follows later.

## Start here

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Components, users/devices, routing, trust boundaries, scaling |
| [Tunnel protocol](docs/protocol.md) | Pairing, rotation, replay, failure semantics, limits |
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

See [CONTRIBUTING.md](CONTRIBUTING.md). Transport and privileged adapters are Rust. The just-bash integration will have a small TypeScript package implementing its native interface. Credentials stay in the runtime secret store, outside this repository.

License: [MIT](LICENSE).
