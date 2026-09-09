# Initial design decisions

Status: proposed baseline accepted for planning, 2026-09-09. Decisions become implemented only when the linked roadmap gate passes.

| Decision | Choice and rationale | Validation point |
| --- | --- | --- |
| Name and visibility | Agent Tunnel; private `andymac4182/agent-tunnel`, intended for OSS release | Repository bootstrap |
| Language | Rust core, relay, daemon, and privileged adapters; thin TypeScript just-bash package | M0/M4 |
| License | MIT initial project license; publication remains a separate decision | M0; review third-party notices before release |
| Connectivity | Outbound WSS over commonly available HTTPS infrastructure | M1 proxy and TLS tests |
| Channel separation | One control and one data socket per connected device, independent bounded queues | M1 load/fairness checks |
| Data rotation | Default 300s configurable interval; monotonic timing and bounded preparation/overlap | M2 state-machine and real-socket tests |
| Handover | Two steady-state sockets; maximum three during replacement overlap | M2; strict-two alternative below |
| Stream lifecycle | Logical stream survives scheduled socket rotation; process restarts may interrupt it | M2 |
| Delivery | Transport sequence deduplication, explicit operation status; no general exactly-once claim | M2/M3/M5 fault injection |
| Multi-user scope | Personal tenant per user initially, explicit memberships/grants, many devices and consumers | M1 adversarial isolation fixture |
| First deployment | Single relay process with SQLite durable catalog; horizontal ownership later | M1/M7 |
| Trust | Relay terminates TLS and is trusted with payloads; device applies local allowlists | M1 |
| Filesystem transport | just-bash connects via binary WebSocket, carrying 9P2000.L through a logical tunnel stream | M4 codec and adapter tests |
| Filesystem access | Read-only named roots first, capability-confined writes after platform tests | M4 |
| Computer use | CUA behind typed device adapter, one active controller lease per desktop | M5 compatibility spike |
| MCP | Explicit 2026-07-28 profile and separate 2025-11-25 compatibility path | M3 official SDK tests |

## Rotation tradeoff

With a hard limit of two total sockets, the old data socket must close before the new one connects. This introduces a bounded pause and requires the same buffering/replay machinery. The recommended baseline allows a temporary third socket, because pre-authenticating its replacement reduces avoidable downtime. No long-running stream is allowed to pin the old physical socket indefinitely. A strict-two mode is deferred until there is a deployment need and dedicated failure tests.

The five-minute value is a scheduled rotation interval, not a security credential lifetime or an unconditional physical-connection maximum. A failed handover can delay rotation while the old connection is healthy; the protocol defines limits and explicit termination behavior. If infrastructure has a hard connection lifetime, add a separately enforced lifetime setting and start rotation early enough to meet it.

## Decisions still requiring experiments

- Confirm CUA's most reliable local control path on each target OS: computer-server API first, native Rust driver as a candidate. Do not promise identical desktop capabilities on all platforms.
- Choose and pin the Rust filesystem confinement implementation after Linux/macOS/Windows escape-race testing; platform support is a release gate.
- Select the self-hostable OAuth/OIDC integration and device credential provisioning library. Do not implement cryptographic primitives or an authorization server from scratch.
- Tune chunk sizes, windows, replay budgets, fairness, and load targets using measurements. Initial protocol numbers are bounded defaults, not benchmark results.
- Determine when remote tree scans need dedicated safe search/list APIs to avoid just-bash issuing one network call per file. Do not use arbitrary shell execution as the optimization.
- Design end-to-end encryption, mobile apps, continuous video/WebRTC, generic TCP exports, and VM provisioning only when prioritized separately.
