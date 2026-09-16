# Build roadmap

The [task tracker](tasks.md) records task status, ownership, discovered defects, and acceptance evidence within each milestone.

Status: M1 is merged to main. M2 and M7 are complete and locally verified. Every M7 task row is verified and the 98-row edge-case matrix is closed at 98 of 98, each row at its own declared scope with dated evidence. Three rows were settled by renegotiating what they asked for, on recorded owner decisions, rather than by passing a test, and several rows carry named limits that survive their closure; see [the task tracker](tasks.md) and [the matrix](m7-edge-cases.md). The final local chain at the M7 tip passed formatting, strict locked Clippy, 1055 workspace tests, all 78 gates, the M1 acceptance, and both M2 plans including three actual 300-second rotations. M3 is in progress and not complete. At the merged revision `db1da30`, seven of its rows are verified local — the four `http-forward/1` implementation gates (M3-05 to M3-08) and the MCP pinning, export and cloud-client rows (M3-01 to M3-03) — each against a registered gate in `scripts/m3-harness-verify.sh` — directly or, for M3-01 and M3-02, through the cloud-client gate — that passed 7 of 7 runs there, 3 inside the script and 4 standalone, alongside a green formatting, strict locked Clippy and 1310-test workspace chain and all 45 distinct M7 gates, each run once. The M3 gate itself is still open: M3-04 (session isolation, concurrent request correlation and explicit unknown outcomes) remains implemented awaiting verification because `verify-m3-mcp-isolation` failed 2 of 17 runs at that revision, and 2 of 10 more after the gate gained a timeout diagnostic; the consumer sees `503 PEER_UNAVAILABLE` with an `unknown` execution for a request issued just after a membership re-sign, which is the transport-failure arm — a hop closed mid-request or a fresh dial refused on an empty transport pin set, reached through M7-C83's failed-closed pin publication — but does not establish either, nor whether the owner was reached. So the roadmap's request-ID-reuse and server-message scope is not fully proven, and M3-09 to M3-17 — process-tree residue, `Last-Event-ID` resume, `Origin` and OAuth, HTTP/2 and non-Unix hosts, resources/prompts/subscriptions/sampling/elicitation, and a pinned conformance suite or non-Rust SDK — remain planned. Remaining milestones, in the order the alpha requires them: M3 MCP adapter, M4 filesystem API and native SDK adapters, M8 ACP over HTTP, M5 CUA computer use, runtime operations and diagnostics, then M6 operable private alpha.
On 2026-09-09 macOS arm64 with pinned Rust 1.95.0 and Redis 8.4, formatting,
strict locked Clippy, 62 workspace tests, five explicitly executed real Redis integration tests, the AOF restart
check, and the full real HTTPS/WSS CLI acceptance passed for five
clients across two tenants. The acceptance included admission certificate,
ticket, and stale-epoch negatives plus private H3 success/negative probes.
Work passes through concrete acceptance gates, without delivery-date or
throughput claims. Primary scenario: **cloud agent → Agent Tunnel Server →
outbound WebSocket tunnel → desktop ACP/MCP/CUA or filesystem export**.

GitHub tracking: [v0.1 Private alpha](https://github.com/andymac4182/agent-tunnel/milestone/1). Existing milestone identifiers remain stable, but their numbers are not execution order. **M7 clustering is required before M6 alpha release**, and its trust/routing foundations begin alongside M1.

| Work | Tracking issue |
| --- | --- |
| M1: Axum, CLI mTLS, authenticated multi-user tunnel | [#1](https://github.com/andymac4182/agent-tunnel/issues/1) |
| M2: ordered streams, drain and data rotation | [#2](https://github.com/andymac4182/agent-tunnel/issues/2) |
| M3: MCP adapters | [#3](https://github.com/andymac4182/agent-tunnel/issues/3) |
| M4: shared filesystem API and four native SDK adapters | [#4](https://github.com/andymac4182/agent-tunnel/issues/4) |
| M5: CUA computer use | [#5](https://github.com/andymac4182/agent-tunnel/issues/5) |
| M6: alpha reliability and artifacts | [#6](https://github.com/andymac4182/agent-tunnel/issues/6) |
| M7: HTTP/3 mTLS relay cluster and Redis key distribution | [#7](https://github.com/andymac4182/agent-tunnel/issues/7) |
| M8: ACP over HTTP to CLI-supervised agents | [#8](https://github.com/andymac4182/agent-tunnel/issues/8) |
| CLI operations and diagnostics | [#9](https://github.com/andymac4182/agent-tunnel/issues/9) |

Hosted verification: [M1 CI checks](https://github.com/andymac4182/agent-tunnel/pull/10/checks).
Hosted CI status: since 2026-09-11 GitHub Actions jobs on this repository fail before starting because of an account payment/spending-limit block, so M2 and M7 evidence is local-only until that is restored.
## M0 — Repository and executable configuration

Delivered or under active implementation: private MIT-licensed repo, Rust workspace, strict legacy configuration validation, the M1 `RuntimeConfig` client CLI, local CSR/import commands for externally issued device credentials, Axum consumer/device listeners, configured Redis authority and JWT/JWKS authorization, pinned TLS/WSS/H3 transport helpers, and a reusable real-resource harness. Local evidence covers the locked checks, 62 workspace tests, five explicitly executed real Redis integration tests, AOF same-dataset restart, and full real M1 acceptance; CI results are linked in this document. Redis is the authority catalog for every tenant, user, membership, device, service, grant, and credential record formerly assigned to PostgreSQL. Relay sockets, queues, in-flight operations, and other process-local session state remain ephemeral. In the narrow M1 Redis profile, the durable device hash also stores lease fields and expiry without a Redis TTL; logical lease validation and complete `deployment_incarnation` plus `run_id` guards make stale owner fields non-authoritative. Separate TTL namespaces remain an M7 design. `redis_url`, `redis_namespace`, and `deployment_incarnation` remain deployment inputs whose persistence, restore, and fail-closed behavior require explicit evidence. Legacy configuration retains the documented 300-second/10-second/30-second rotation defaults for the future M2 profile; M1 itself does not rotate or replay.

Gate: the local macOS arm64 run satisfies the formatting, strict Clippy,
workspace test, Redis integration, AOF restart, and full M1 acceptance checks.
Hosted Linux/macOS/Windows CI must repeat the locked checks and keep the
acceptance result visible; that evidence remains pending until the pull request
runs there. New fields/commands in [runtime.md](runtime.md) remain proposals
unless the source and acceptance evidence say otherwise.

## M1 — Axum and authenticated multi-user tunnel

Verified local slice: pinned Axum/rustls/WebSocket and QUIC/H3 dependencies run under Rust 1.95.0. The runnable M1 path has separate consumer HTTPS and mandatory device mTLS WSS listeners, external-issuer credential provisioning through local CSR/import, configured JWT public keys, Redis-backed authority for all tenant/user/membership/device/service/grant/credential records, and the synthetic `echo` export. The client uses one mTLS control socket and one mTLS data socket; a transport failure closes both and requires a fresh session. There is no M1 data rotation, retained replay, or automatic replay of effects. No token-only fallback is allowed for either device socket.

The reusable harness seeds the production Redis authority with two tenants, five devices, four consumers, grants, and fixture credentials in an isolated run namespace, then drives real listeners. The local acceptance passed the live CLI echo/list/authentication, quota, revocation, disconnect, admission-negative, proxy, and private H3 checks. Its H3 peer check proves peer mTLS/role/pin/body transport only. It does not implement M7's three-relay routing, signed Redis membership/public-key distribution, ownership leases, fencing, HA failover, or recovery. One relay with an echo adapter is the first runnable fixture, not the alpha deployment architecture. Remote MCP, filesystem, ACP, and CUA adapters remain later work.

Gate: the local run verifies two tenants, five devices, multiple consumers, real
public HTTPS, both mTLS device sockets, echo isolation, authorization,
revocation, quotas, disconnect behavior, admission negatives, and the bounded
private H3 success/negative cases. Real WSS passes through a TCP load balancer
with mTLS verified at the Rust listener; the desktop opens no inbound port.
Public consumers cannot forge internal verified identity headers. M7 multi-relay routing remains a separate gate.

## M2 — Independent ordering and drain before handover

Locally verified on 2026-09-10: 151 workspace tests, strict locked checks,
five Redis tests, AOF restart and full M1 regression pass. The real-socket
M2 suite passes three accelerated rotations, targeted recovery/abort/control
loss/cancellation/revocation faults, and three actual 300-second rotations in
903.05 seconds. See [M2 evidence](m2-verification.md). Hosted M2 CI is pending.

Implement [protocol.md](protocol.md) as a pure state machine before real socket I/O. Each logical stream has independent sequence spaces per direction, tied to a unique session/stream identity and preserved through scheduled rotation. Physical connection IDs, generations and owner epochs fence carriers without resetting logical counters. Bound credits, queued bytes, replay, tombstones, roster snapshots and recovery time.

Scheduled handover is **prepare → quiesce → drain → commit → retire**. Freeze old writers at immutable per-stream fences, pause new stream admission, wait for contiguous acknowledgements in both directions, then activate the candidate and retire the old socket within the original overlap budget. A delivery drain does not wait for a long-running agent task to complete. Cancellation remains responsive; no next replacement begins while the old transport remains allocated.

Gate: pure/property tests cover every phase and lost/duplicate/stale message boundary, sequence gaps, terminal records, pending stream-open races, uncertain commit, abort and deadline expiry. Real streams span at least three rotations, accelerated and at the actual 300s default. At most one control plus two data sockets exists during bounded overlap. No duplicate adapter delivery, counter reset, cross-stream ordering dependency, unbounded buffering or automatic replay of ambiguous effects. Recovery replays only missing retained transport ranges; owner/process loss produces explicit interruptions.

M1/M2 gate remotely usable service adapters. Adapter/codec research can run in parallel against in-process fixtures.

## M7 — Cluster foundations and three-node integration

This is required for alpha, despite its retained issue number. The implemented
slice provides [cluster.md](cluster.md)'s direct owner routing over bounded
bidirectional HTTP/3 streams, mandatory peer mTLS, externally signed Redis
membership/public keys, approved trust anchors, Redis-backed authorization
authority, owner leases, and connector-enforced fencing. Use separate device
and peer roles. Redis mutation alone cannot enroll a server.

The supported first coordination profile is one authoritative Redis primary with
no automatic promotion. The local AOF check proves same-dataset restart
persistence, including catalog conflict, revocation, and new-owner-incarnation
assertions; it does not implement automatic HA or backup-rollback detection.
`connect_for_recovery` and `activate` remain operator-only actions that require
an external durable catalog, reconciled revocations, and a new approved
incarnation before they are called. A new incarnation fences owners but cannot
by itself prove that revocations were not rolled back. Test and document the
external checkpoint gate, quiesce/incarnation recovery, rollback detection,
and promotion behavior in M7; do not describe Redis replication as consensus.
Membership expiry, authorization expiry, owner lease expiry and certificate
expiry are distinct deadlines. Coordination high availability is a separate
future gate, and M1 does not claim safe restoration of arbitrary backups.

The synthetic local harness uses three real mTLS QUIC relays and isolated
Redis to exercise routing contracts, membership verification, owner contention,
stale release and pin revocation. Its synthetic owner callback does not prove
production device sockets, authorization and rotation together. The production
three-relay harness and expanded transport faults must pass before those gates
can close. Redis recovery/rollback, UDP partitions and process pauses also
require acceptance evidence; no automatic promotion is claimed.

### Mandatory M7 edge-case acceptance expansion

M7 must cover every applicable case and analogous failure in the Kaizen
`tunnel-edge-cases.md` inventory supplied on 2026-09-10. Track each source case
in [the M7 edge-case matrix](m7-edge-cases.md), with an Agent Tunnel invariant,
concrete regression or fault-injection test, and revision-specific evidence.
An existing unit test is not evidence for a cross-relay lifecycle requirement.
Uncovered cases remain open M7 gates; adaptations and non-applicability require
an explicit reason. Include the inventory's incidents and outstanding staging
proof, not only its numbered tables.

Preserve Agent Tunnel's own contract: scheduled data-carrier rotation retains
logical streams, ambiguous side effects are never retried, and missing owner
or authorization state never redirects work to an unrelated backend. Exercise
ownership races, tenant isolation, readiness, Redis/peer loss, key changes,
backpressure, physical write stalls, cancellation, terminal cleanup, protocol
compatibility, partial responses, and shutdown using bounded synthetic loads.
Release/source parity and state-preserving rollback remain required evidence.

## M3 — MCP service adapter

Implement Rust local stdio and Streamable HTTP exports with the bounded [HTTP forwarding contract](http-forwarding.md). Pin RMCP and actual fixture SDK releases. Separate the 2026-07-28 protocol profile from deliberate 2025-11-25 compatibility; see [mcp.md](mcp.md). HTTP framing does not merge MCP and ACP lifecycle rules.

Gate: an actual cloud-side MCP client discovers/invokes a deterministic desktop server through non-owner ingress, HTTP/3 peer forwarding and the rotating tunnel. Streaming, cancellation, server messages, request-ID reuse, metadata and backend crashes follow the selected profile. Only fixed exports are reachable; upstream credentials are device configuration.

## M4 — Shared filesystem API and native SDK adapters

Follow [filesystem-api.md](filesystem-api.md), its descriptor schema, [filesystem-adapters.md](filesystem-adapters.md), and upstream source research. Node is the first certified consumer runtime; browser authentication is a separate gate.

1. **M4a — endpoint and shared client:** descriptor GET plus authenticated 9P2000.L WebSocket upgrade at the same service URL, a confined read-only Rust provider, bounded binary codec, and `@agent-tunnel/client`. Bind attach to verified grants; 9P user names cannot change authority. Audit or implement the small .L codec with golden fixtures and fuzz bounds.
2. **M4b — native read views:** Files SDK `Adapter<Raw>`, Mastra `WorkspaceFilesystem`, and just-bash `IFileSystem`, compiling against real installed pinned declarations. Share one scoped client rather than fork the wire protocol. Document object keys vs directory paths, stat/date conversions, pagination and resource ownership.
3. **M4c — explicit write grants:** OS-proven confinement, creates/truncation/append/rename, composite partial failures, optional features and structured unknown outcomes. Mastra defaults to rejecting `expectedMtime`; its explicit advisory check-before-write mode enables upstream-style edits without claiming atomic compare-and-swap. Files SDK retries and Bash tool error wrapping must preserve effect uncertainty.
4. **M4d — native AI SDK Files:** implement `FilesV4` upload/metadata/download/delete over a configured upload directory, bounded session-scoped opaque references, streamed bytes and explicit retention. These references are not IDs recognized by unrelated model providers. FilesV4 does not expose directory/list/rename operations.
5. **M4e — end-to-end compatibility:** run real framework clients/tools against the same server export and synthetic dataset, with operations appropriate to each interface. Test managed AI uploads through another read view, and test tool input/output and structured failures without paid model calls.

Gate: Bash read/write/grep/copy/rename transcripts, Files object workflows, Mastra read-edit-read under the explicit timestamp policy, and AI Files upload/download/delete all pass through the real endpoint and rotating device tunnel. Preserve binary bytes, fids/tags during scheduled drain, tenant isolation and declared limits. Session loss invalidates mount handles and adapter reference maps. No ambiguous write replay. Enable writes per OS only after escape/race tests pass.

The native Files SDK `createFilesClient` speaks a separate HTTP gateway protocol. Its optional gateway, mutation error fidelity, browser profile, atomic conditional writes and experimental AI sandbox integration are explicitly deferred compatibility work. Raw 9P/WSS is not a drop-in URL for those clients.

## M8 — ACP over HTTP to desktop agents

Implement [acp.md](acp.md) and [http-forwarding.md](http-forwarding.md). Pin and prove the official Rust ACP HTTP/core SDK transport profile; HTTP binding is draft and version-sensitive. The desktop CLI supervises a fixed local ACP stdio agent behind an in-process HTTP handler. Host GET/POST/DELETE traverse the server and existing data WebSocket; there is no new device listener or host-selected executable.

Gate: an official HTTP client initializes, subscribes, creates sessions, prompts, receives streaming updates and permission callbacks, responds, cancels and deletes against a deterministic child agent. Test two users reusing IDs, subscriber loss, child crashes, output backpressure and missed HTTP acknowledgements across three relays and three rotations. Permission timeout cannot approve an action; ambiguous prompts are never resubmitted. Validate process-tree cleanup on each supported desktop OS. Restrict real-agent tests to dedicated workspaces/VMs and publish the sandbox guarantees actually proven.

## M5 — CUA computer-use adapter

Pin/probe CUA computer-server and Rust driver compatibility per OS. Implement typed screenshot/input, capability negotiation, deadlines, device-held backend credentials and one input-controller lease per desktop. Begin with screenshots; input requires both an explicit local export and consumer grant.

Gate: a cloud-side fixture calls the server through non-owner ingress to screenshot a dedicated disposable desktop VM, focus its fixture app, type deterministic text and verify state. Repeat across rotation. Reject competing input controllers and unauthorized screenshot/input. Backend disconnect after dispatch gives an unknown outcome, never a second click. Tests never control the user's active desktop.

## Runtime operations and debugging

Implement the CLI contract and redacted status/doctor surfaces in [runtime.md](runtime.md) alongside M1/M2/M7, then ACP process lifecycle alongside M8. Use one state owner per connection/device, bounded channels, typed errors, cancellation and a supervisor that joins child tasks. Network handlers only authenticate, parse bounded input and invoke typed services.

Gate: inspect phase, owner/session/connection IDs, stream-direction sequence cursors, drain fences/ACKs, certificate/membership/lease expiry and queue bytes without payload logs. CLI config/status/doctor are deterministic and read-only unless an explicitly documented command requests a connection or mutation. Test exit codes, local IPC authorization, invalid credentials and clean shutdown from every rotation phase.

## M6 — Operable private alpha and release artifacts

Requires M1/M2/M7 transport and cluster gates, M3/M4/M5/M8 supported adapter gates, and runtime diagnostics. Add deployment examples, credential provisioning, backup/recovery, metrics/audit retention, service installation, graceful upgrades, dependency/license/secret checks and packaging. Complete the suites in [testing.md](testing.md); report any narrower supported platform scope explicitly.

Gate: clean-machine release binaries on advertised OS/architectures, checksums/provenance, soak/resource evidence, three-node multi-user demo of **cloud agent → server → WebSocket → desktop ACP/MCP/CUA/VFS**, and verified credential/revocation/recovery procedures. Keep the repository private until the owner explicitly requests publication.

## First implementation PRs and parallel work

1. Pure protocol identifiers, codec bounds, stream ordering and drain state machine with fixtures/property tests.
2. Pinned Axum device-mTLS and bidirectional HTTP/3 transport spikes; shared identity and verified TLS types.
3. Redis authority schema, issuer integration, signed Redis membership and owner/fencing model.
4. Real two-user echo slice, initially one relay then forced three-node routing.
5. Integrate drain/recovery/backpressure and CLI status into that slice.
6. Independently implement MCP, filesystem, ACP and CUA fixtures; enable each only after its transport/auth/platform gates pass.

Each PR remains small enough to review, updates implementation status and links test evidence. Research/adapter compilation can proceed independently of transport work; production exposure cannot. Add required CI when a feature exists, without permanently skipped jobs that imply coverage.
