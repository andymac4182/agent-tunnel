# Design decisions

Status: implementation baseline, revised 2026-09-09. User-selected requirements are fixed; M1 echo, Redis authority, device mTLS and bounded H3 transport evidence are recorded in [m1-harness.md](m1-harness.md). Proposed cluster, rotation and adapter behavior requires its later milestone gates.

M1 uses logically expiring owner fields in durable Redis device hashes; the table's separate ephemeral coordination layout is a cluster target. M1 does not implement automatic promotion or external catalog high-water verification for arbitrary backup restores.

| Decision | Choice and rationale | Validation point |
| --- | --- | --- |
| Name / visibility | Agent Tunnel; private `andymac4182/agent-tunnel`, MIT, intended OSS publication later | M0/M6 |
| Primary flow | Cloud agent → server → outbound device WebSocket tunnel → desktop ACP/MCP/CUA/VFS | Full alpha end-to-end fixture |
| Language | Rust client/relay and privileged adapters; shared TS filesystem client and thin native SDK adapters | M1/M4 |
| Server / CLI | Axum consumer and device listeners; existing `tunnel-client` binary evolves into connection supervisor | M1 and runtime gates |
| Device authentication | Mandatory mTLS on both control and every data socket; certificate-bound one-use data attachment | M1 certificate/ticket tests |
| Consumer authentication | Separate scoped OAuth credentials; no device certificate sharing with SDKs/cloud hosts | M1 isolation |
| Channel separation | One control + one data WebSocket per device, independent bounded queues | M1/M2 |
| Rotation | Default 300s configurable; one bounded candidate creates at most three device sockets temporarily | M2 |
| Handover | Prepare, quiesce, drain immutable per-stream fences, commit, retire; absolute overlap deadline | M2 model and real sockets |
| Ordering | Unique session/stream identity with independent direction counters; continuity across carrier rotation | M2 gap/duplicate/race tests |
| Effects | Transport deduplication within retained state, explicit unknown/partial application effects, no general exactly-once claim | All adapter fault suites |
| Multi-user scope | Explicit tenant memberships, per-device/service grants, many devices/consumers | M1/M7 |
| Shared durable state | One authoritative Redis deployment; durable catalog and ephemeral leases use separate namespaces; authorization snapshots bounded to five seconds | M1/M7 |
| Peer transport | Private HTTP/3 over QUIC with mTLS and explicit adapter to shared application services | M7 compatibility and UDP tests |
| Redis role | Single authoritative store for the durable catalog, signed approved public-key directory, presence and fenced owner leases; no private keys/payloads | M7 forged/stale record and restore tests |
| Trust authority | External issuers and signed membership checkpoints independent of Redis; separate device/peer roles | M1/M7 |
| Coordination limit | One authoritative Redis primary, no automatic promotion; quiesce/new incarnation after rollback/restart/promotion | M7 failure/recovery |
| Cluster release scope | Three-node validation required before private alpha; one node is a development slice | M7 before M6 |
| Filesystem endpoint | Authenticated descriptor GET plus binary 9P2000.L/WSS at one service URL; Node first | M4 |
| Native filesystem views | Files SDK Adapter, Mastra WorkspaceFilesystem, just-bash IFileSystem, AI SDK FilesV4 | Installed-package conformance |
| Filesystem semantics | Confined read-only roots first; bounded writes/composites, explicit capability gaps | M4 per-OS gates |
| Conditional writes | No strong CAS baseline; Mastra timestamp precheck requires explicit advisory opt-in | M4 stale/race tests |
| ACP | Versioned draft HTTP profile to CLI-owned in-process bridge and allowlisted stdio child | M8 upstream interoperability |
| MCP | Explicit 2026-07-28 profile and separate 2025-11-25 compatibility | M3 actual SDK tests |
| Computer use | CUA typed adapter, one active controller lease per desktop, dedicated VM tests | M5 |
| Debugging | Explicit state owners, bounded queues, typed errors, redacted transition/fence/lease diagnostics | Runtime/alpha gates |
| Payload trust | Relay terminates TLS and is trusted with content; device still enforces local policy | M1/M7 |

## Storage authority

The initial supported profile has one authoritative Redis primary and no automatic promotion. Redis separates durable catalog records (tenants, memberships, devices, credentials, grants, services and revocation versions) from ephemeral coordination records (presence, owner leases and one-use tickets). Durable catalog keys have no lease TTL and are independent of deployment_incarnation; ephemeral coordination keys are TTL-bound and incarnation-scoped. A fresh deployment incarnation is supplied and approved externally after restart, restore, rollback or ambiguous authority, and is persisted outside Redis before new sessions are admitted.

AOF/fsync settings and verified backups define Redis durability but do not provide consensus, linearizable failover or authority to promote another writer. Restore and rollback procedures stop admission, fence old writers, verify the durable catalog/signed directory, keep services unready on ambiguity, and require fresh relay/device sessions. Signed peer keys are accepted only under an operator-installed root/checkpoint; Redis key presence never bootstraps root trust. No alternate storage dependency or compatibility authority is retained in this profile.

## Rotation tradeoff

The baseline permits a temporary third socket to authenticate the replacement before stopping the old writer. It then explicitly drains old transport delivery before committing. Long-lived HTTP responses, file handles and agent operations continue on stable logical streams; they cannot pin the old physical socket indefinitely. Drain acknowledgements do not mean an agent task or filesystem mutation completed.

A hard two-socket mode would require closing the old data socket before establishing the replacement, with a longer data pause and its own recovery tests. That optional mode is deferred. The configured five-minute interval schedules rotation; it is not a certificate lifetime or unconditional physical-connection maximum. Failed pre-commit attempts may return to a healthy old connection only by the protocol's serialized abort decision, preserving sequence state. A separate hard connection lifetime requires an explicit setting and early rotation budget.

## Compatibility and experiment gates

- Pin a proven Axum/rustls/WebSocket/QUIC/H3 combination. Axum's HTTP/1 and HTTP/2 server does not natively become an HTTP/3 peer server by enabling a flag.
- Select an external CA/issuer integration and self-hostable consumer OAuth/OIDC provider. No custom cryptographic primitives or general authorization server.
- Pin exact ACP HTTP SDK/schema versions; the HTTP transport is draft. Do not advertise support based only on similarly shaped JSON-RPC.
- Compile native adapters against actual published packages and lockfiles; inspected source revisions alone are not interoperability evidence. The Files SDK native HTTP gateway and experimental AI sandbox are separate deferred profiles.
- Select the Rust 9P codec and confinement abstraction after parser and Linux/macOS/Windows escape-race testing. Do not equate `.L` wire flags with host OS constants.
- Confirm CUA backend transport and capabilities per OS. Confirm ACP process-tree cleanup and the actual OS sandbox guarantee; changing `cwd` alone does not confine a coding agent.
- Measure chunk/window sizes, replay budgets, fairness and load limits. Defaults are safety bounds, not performance claims.
- Automatic coordination failover, durable stream replay, strong filesystem CAS, browser auth, end-to-end encryption, mobile apps, continuous video/WebRTC, arbitrary TCP exports and VM provisioning require separately prioritized designs.

See [runtime.md](runtime.md), [cluster.md](cluster.md), [protocol.md](protocol.md), [filesystem-api.md](filesystem-api.md), [filesystem-adapters.md](filesystem-adapters.md), and [acp.md](acp.md) for normative detail and open gates.
