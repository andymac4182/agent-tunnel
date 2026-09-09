# Build roadmap

Status: bootstrap complete locally; future milestones are unimplemented. Sequence work by passing the acceptance gates below. No delivery-date or throughput claim is implied.

## M0 — Repository and executable configuration

Deliver the private MIT-licensed repo, Rust workspace, config-only client/relay commands, strict default/override validation, cross-platform CI, architecture, protocol, integration research, and test plan. Default data rotation is 300s, handshake deadline 10s, overlap budget 30s.

Gate: formatting, strict Clippy, workspace tests, CLI example checks, and hosted Linux/macOS/Windows CI pass on the committed source. The README identifies what actually runs.

## M1 — Authenticated multi-user tunnel vertical slice

Create `tunnel-protocol` and implement versioned framing plus a single relay node. Implement durable tenant/user/device/service/grant records, device enrollment, consumer authentication, revocation, connection epoch ownership, one-use data tickets, and fixed local service registration. Add bounded control/data queues, per-user device capacity, explicit offline presence, TLS deployment configuration, reconnect jitter, and graceful shutdown.

Use an in-memory echo adapter to prove routing before enabling privileged services. Keep development credentials restricted to a loopback harness; select and test a self-hostable OAuth/OIDC provider and device proof mechanism before a publicly reachable deployment.

Gate: two users, three devices, at least two simultaneous consumers for one user. Allowed streams reach only their intended export. Cross-user discovery, ticket theft/reuse, stale epochs, grant revocation, unauthorized origin, and quota exhaustion are rejected. Real WSS works through a reverse proxy without inbound device ports. Empty/expired credentials cannot establish a usable tunnel.

## M2 — Rotation, flow control, and fault recovery

Implement the state machine in [protocol.md](protocol.md), first as a pure model, then over actual sockets. Add ordered sequence accounting, bounded replay, byte credits, fair scheduling, cutover acknowledgment, drain deadline, retries, and reset semantics. Freeze effective rotation configuration for a connection epoch so both peers agree. Persist service operation outcomes only where the service can support meaningful recovery.

Gate: repeated rotation at a short configured interval and at the real 300s default; long streams span at least three rotations. At most one control and two data sockets per device during overlap. No duplicate adapter delivery, unbounded buffers, hung streams, or side-effect retries at any injected failure point. Control stays responsive during saturated data traffic. Test data loss and control loss separately, including simultaneous replacement races.

M1 and M2 are prerequisites for a remotely usable adapter release. Codec/adapter spikes can run in parallel against an in-process transport.

## M3 — MCP service adapter

Implement Rust local stdio and Streamable HTTP exports and an authenticated relay gateway. Pin RMCP and fixture SDK versions. Separate current 2026-07-28 behavior from a deliberate 2025-11-25 compatibility profile; see [mcp.md](mcp.md).

Gate: an actual MCP client discovers and invokes a local test server through the relay and device. Streaming, cancellation, server messages, concurrent request-ID reuse, rotation, and backend crashes follow the negotiated profile. Only fixed exports are reachable, and no upstream credential is taken from consumer input.

## M4 — 9P filesystem over WebSocket and just-bash

M4a: select a maintained Rust 9P2000.L codec/server library or implement a small audited codec if the compatibility spike finds none. Record dependency license, parser bounds, supported operations, and fuzz results. Build a read-only server over named, confined mounts. Define the versioned WebSocket binding, message size, attach mapping, session ownership, and POSIX error translation.

M4b: implement `packages/just-bash-fs` with a binary WebSocket 9P client implementing the pinned just-bash `IFileSystem`. Node is the first supported runtime; browser builds get separate authentication, Origin, and buffering gates. Use one persistent socket per mounted session; no per-operation HTTP filesystem API. Encode wide fields with BigInt and keep encoding/date conversion at the TypeScript boundary.

M4c: add explicit write grants, create/append/truncate, mkdir/remove, rename, links, permissions, and times according to verified platform capability. Compose copy/recursive operations through 9P and document partial-failure behavior. Unsupported operations return errors; never fake successful permissions or links. Add read limits, fid/tag caps, cleanup, cancellation, and consumer-disconnect behavior.

Gate: actual `new Bash({ fs })` scripts list, read, grep, write, append, copy, rename, and remove synthetic files on an enrolled machine through the consumer WebSocket and rotating device tunnel. Binary content survives byte-for-byte. Fids/tags survive scheduled rotation and cannot cross mounts/users. Session loss invalidates fids, partial or ambiguous writes are surfaced without replay, and OS-specific escape/race tests pass before writes are enabled on that OS.

## M5 — CUA computer-use adapter

Pin and probe CUA computer-server and native Rust driver compatibility on the target OS. Implement typed screenshot and input operations via the supported local backend, capability negotiation, operation deadlines, device-owned backend credentials, and a per-desktop input-controller lease. Begin with screenshots; enable input only under an explicit local export and consumer grant.

Gate: in a dedicated disposable desktop VM, a remote agent screenshots a fixture app, focuses it, types deterministic text, and verifies the resulting pixels/state. Repeat across data rotation. Reject competing input controllers and unauthorized screenshot/input requests. Backend disconnect after dispatch produces an unknown outcome, never an automatic second click or typing action. Publish actual backend/OS coverage.

## M6 — Operable private alpha and OSS release preparation

Add deployment examples, credential storage, service install/uninstall instructions, metrics/audit policy, dependency/license/secret checks, graceful upgrades, resource-limit tuning, and platform artifact packaging. Complete soak, chaos, parser fuzzing, independent boundary review, and clean-machine installation tests described in [testing.md](testing.md).

Gate: verified release binaries on supported OS/architectures, checksums and build provenance, resource graphs from the load/soak runs, complete multi-user end-to-end demo, and documented backup/recovery/revocation behavior. Review third-party notices and select the supported compatibility matrix. Keep the repository private until the owner explicitly chooses to publish it.

## M7 — Horizontal relay scale

Move durable state to PostgreSQL, add authenticated owner routing and leased/fenced connection ownership, and prove that both sockets of a device epoch reach its owner. Bound forwarding queues and handle rolling upgrades and owner loss. Add region affinity only when measurements justify it.

Gate: at least three relay instances, two users and many devices, forced owner death/network partition, duplicate connection attempts, and rolling deployment. No split ownership or cross-tenant delivery. Report interruption behavior honestly; in-memory stream state is not recovered merely because the catalog is durable.

## Parallel work and first PRs

After M0, split independent work into: protocol model/codec, identity and relay routing, daemon connection lifecycle, 9P/just-bash compatibility spike, and CUA compatibility spike. The last two use mocks/disposable environments until transport and authorization gates pass.

First implementation PRs should be small enough to review:

1. Protocol types, byte parser bounds, golden fixtures, and pure state-machine tests.
2. Durable identity/grant schema and auth boundary tests.
3. Real loopback relay + two-user echo fixture, then TLS/proxy verification.
4. Rotation and flow control integrated into that fixture.

Each PR updates the implementation status and links its evidence. Add feature CI gates when the feature exists; do not create permanently skipped tests that imply coverage.
