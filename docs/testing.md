# Verification plan

This document defines acceptance gates across the project. M1's locked Rust checks, Redis catalog regressions, same-dataset AOF restart and real HTTPS/WSS/CLI/private-H3 harness have local evidence in [m1-harness.md](m1-harness.md). M2 rotation/replay has separate local evidence in [m2-verification.md](m2-verification.md). M7 cluster implementation and verification are in progress; remote adapters, backup rollback verification and performance/soak gates remain open. See [tasks.md](tasks.md) for current task status.

Read [the protocol plan](protocol.md) for authoritative connection and rotation rules, [runtime.md](runtime.md) for mTLS/CLI behavior, [cluster.md](cluster.md) for peer trust and ownership, [the filesystem API](filesystem-api.md) and [adapters](filesystem-adapters.md) for filesystem contracts, and [acp.md](acp.md) for agent HTTP transport. [The integrations plan](integrations.md) also covers computer use. Every implementation milestone must update this document to identify which checks actually run and link to their test code or CI job.

## Current bootstrap checks

Run these commands from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo run --locked -p tunnel-client -- check-config examples/client.toml
cargo run --locked -p tunnel-relay -- check-config examples/relay.toml
```

The initial CI runs formatting, linting, and Rust tests on Linux, macOS, and Windows. The executable scaffolds check configuration; a successful exit is evidence of configuration validation only. Record the exact commit and runner when reporting a check as passed. The initial CI does not establish network connectivity, tenant isolation, upstream compatibility, or release readiness.

Configuration tests must preserve these defaults and reject invalid values:

- `[rotation].interval_seconds` defaults to 300 and accepts 1–86,400 seconds.
- `handshake_timeout_seconds` defaults to 10 and accepts 1–300 seconds. `overlap_seconds` defaults to 30 and accepts 1–3,600 seconds. Overlap begins when the candidate connection attempt starts, including its handshake.
- The cross-field rule is `handshake_timeout_seconds < overlap_seconds < interval_seconds`. An individually valid value can still violate this rule.
- Client `device_id` accepts 1–128 ASCII characters from `[A-Za-z0-9._-]`. Relay limits default to 1,024 total connected clients and 16 per user, with per-user capacity no greater than total capacity.
- Empty/default and partial configuration, unknown or duplicate keys, incorrect types, negative/overflowing values, valid boundaries, and the checked-in examples must be covered. Add boundary and cross-field cases whenever an invariant changes.

## Repeatable M7 harness commands

Build the workspace binaries with `cargo build --workspace --locked` before
running the process-based fixtures. Use a dedicated Redis primary and set
`TEST_REDIS_URL` to its URL; the harness creates isolated namespaces and uses
synthetic payloads and ephemeral certificates.

```sh
cargo run -p tunnel-test-harness --locked -- verify-m7-transport
cargo run -p tunnel-test-harness --locked -- verify-m7-cluster
cargo run -p tunnel-test-harness --locked -- verify-m7-production
cargo run -p tunnel-test-harness --locked -- verify-m7-redis-partition
```

The transport command exercises real mTLS/H3 fault cases. The cluster command
uses a synthetic owner callback. The production command uses real relay actors,
CLI/device WebSockets and public consumers across three relays. The Redis
partition command is being implemented under M7-I05/I17 and is not yet verified;
it must block both existing and newly accepted Redis connections, reject new
admission and expired-authority dispatch, then prove fresh authorized recovery.
A command passing cannot close unrelated rows in [m7-edge-cases.md](m7-edge-cases.md).
Record the tested revision and outcomes in [m7-verification.md](m7-verification.md).

## Deterministic transport and state-machine tests

Keep protocol transitions separable from socket I/O so ordinary unit and property tests can drive them. Cover `Connecting`, `Active(g)`, `Preparing(g,n)`, `Quiescing(g,n)`, `Draining(g,n)`, `Committing(g,n)`, `Retiring(g,n)`, `Aborting(g,n)`, `Recovering`, and `Closed`, with control ownership, connection deadlines, and operation status modeled separately. Candidate `n` is fresh and greater than prior attempts, including aborted attempts. Use Tokio's paused clock and explicit advancement for rotation tests; wall-clock sleeps are unsuitable for these assertions.

Exercise the default interval and shorter configured intervals. At each deadline test just before it, at it, and just after it. Cover replacement success, rejection, timeout, duplicate handshake messages, delayed acknowledgement, old-generation messages arriving late, simultaneous disconnects, and cancellation while a replacement is pending. Verify the chosen deadline starts from the protocol-defined event and that a slow handshake cannot silently extend the maximum overlap.

Property tests generate event sequences with reordered, repeated, and dropped events. Assertions must include:

- At steady state a device uses one control WebSocket and one data WebSocket. During rotation, only the explicitly permitted replacement overlap is allowed.
- Candidate readiness permits no sequenced DATA/FIN/RESET. Quiesce first freezes OPEN admission and each old writer, then fixes immutable per-stream/direction fences under one snapshot/attempt. Queued payload and terminal frames remain bounded and unsent until activation or coordinated abort; local cancellation may stop adapter work immediately.
- Commit is owner-controlled and requires both complete fence sets plus contiguous receiver acknowledgment through every fence. FROZEN arriving on control before delayed old data is not drain proof. Only after both proofs may COMMIT/COMMITTED enable candidate writers in the defined order.
- Existing streams and operation IDs survive scheduled drain without adapter restart or replay of the drained prefix. Draining means transport receipt/retention or accounted terminal discard, not adapter consumption, stream completion, durable storage, or HTTP response completion. WebSocket retirement/Close does not synthesize logical FIN.
- Each `(session, stream, direction)` owns a unique persistent sequence space. Different streams/directions may use the same numbers safely; neither physical connection nor generation changes that identity. Rotation/abort cannot reset counters, stream IDs are never reused in a session, and no global order is imposed across streams. Duplicate arrivals, gaps, half-close, FIN, and counter exhaustion cannot reorder, duplicate delivery, or wrap.
- Both pending OPEN/OPENED and cancelled/reset/half-closed entries remain in the bounded drain roster until their outstanding prefixes are accounted for. Owner-ordered `STREAM_FORGET` is serialized with QUIESCE; test its final-state evidence, zero-frame REJECTED tombstones and delayed connector cleanup. Race OPEN, FIN, CANCEL/RESET and reclamation with freeze; test all 128 tracked entries and the control-message byte limit without unbounded snapshot pagination.
- RESET consumes one sequence per direction at most and participates in fences, ACKs and replay, including when sent after FIN. It uses reserved bounded terminal capacity and its two-byte reason payload cannot carry arbitrary JSON; exhausted data credit cannot block termination or permit a reset loop. Later DATA/FIN stays forbidden.
- Only known-uncommitted attempts with a healthy old transport can coordinate ABORT/ABORTED before the deadline. ABORTED proves candidate resources are released; the owner resumes old writes and admits another candidate only after both endpoint closures. Changed fences/IDs, duplicate/stale proofs, delayed commit, and competing abort/commit cannot change the owner's single decision. An uncertain or accepted commit never rolls back to old.
- Missing drain ACKs, old-socket loss, candidate failure, and lost close acknowledgments meet the original absolute overlap deadline. An unfinished drain/abort at timeout force-closes both attempt transports and enters bounded recovery with a fresh greater generation or fails; it cannot resume old. After commit, force old retirement. No stream, retry, duplicate message, or close handshake extends the budget.
- Recovery reconciles emitted, contiguous receive/ACK, terminal, and credit state before admission; replay only retained missing ranges with original identities. Missing buffers, receiver rollback below an observed ACK, conflicting FIN, or unknown side effects fail explicitly rather than bypass the scheduled drain proof.
- ACKs cannot decrease progress or acknowledge unsent sequences. An ACK indicates transport acceptance, never application success or durable storage.
- Absolute cumulative credit increases only once per advertised limit. Duplicate/delayed window updates and replayed data cannot create credit or consume the same logical bytes twice; both socket generations share the session budget.
- Stale sessions and generations cannot attach a data connection, acknowledge another generation's work, resurrect a disconnected device, or receive newly routed work.
- A duplicate or late event never creates a second terminal result or repeats a side effect. Cancellation, completion, and disconnect races converge on one terminal outcome.
- Control loss, token expiry, and revocation cause the protocol-defined admission and teardown behavior, including during overlap.
- Pending handshakes, draining generations, queued bytes, and operation tracking remain bounded under any generated sequence.

Use reproducible seeds and preserve minimized failing event traces. Add a regression case for each discovered failure rather than relying on a longer random run alone.

## Frame parsing and transport conformance

Give the frame codec independent tests before introducing real sockets. Test round trips, negotiated versions, unknown frame kinds, malformed lengths, truncated payloads, invalid encoding, duplicate identifiers, sequence violations, binary payloads, and configured maximum sizes. Parsing must reject oversized input before allocating according to an attacker-supplied length.

Fuzz decode, incremental decode, and the state-machine input boundary with arbitrary bytes and valid-frame mutations. Check for panics, unbounded allocation or CPU use, invalid state transitions, and cross-stream payload mixing. Retain a small corpus and short smoke runs in CI; run longer sanitizer-enabled fuzz jobs separately on supported platforms. Keep fuzz output free of credentials and private desktop or file contents.

Test WebSocket fragmentation, ping/pong, clean close, abrupt TCP reset, and proxies that close idle sockets. The proposed data framing permits exactly one tunnel frame per binary WebSocket message: reject text messages, concatenated frames, wrong header/length fields, nonzero reserved fields, and unsupported flags. Confirm compression remains disabled under the initial policy. Verify TLS certificate validation and rejection of invalid or expired certificates using an isolated test certificate authority. Test the actual negotiated WebSocket subprotocol and protocol version once specified.

## Real WebSocket end-to-end suite

Run actual relay and device processes on loopback using ephemeral ports and temporary state directories. Fake device capabilities are appropriate for transport tests, but claimed device-path compatibility requires real mTLS WebSockets on both control and data. A codec-only plaintext harness is separate evidence. Run deterministic fault injection through a supported TLS-pass-through proxy. Drive the public consumer entry point rather than calling relay routing functions directly.

The minimum multi-tenant fixture has two users in separate tenants, five devices, and concurrent consumers: user A owns three devices, user B owns two, and each user has at least two consumers. Use distinct canary responses and files for every device so misrouting is directly observable. Include identical user-controlled device labels and numerical stream identifiers across tenants. Add a third user in A's tenant with a limited grant to one of A's devices: prove permitted sharing works while other devices and ungranted capabilities remain denied. Here a device is the user-facing computer represented by a protocol `connector_id`.

Required scenarios:

| Area | Evidence required |
| --- | --- |
| Routing | Concurrent operations reach the selected authorized device and return to the initiating consumer, including when that user owns multiple devices. |
| Rotation | Repeated accelerated rotations and at least one run using the actual 300-second default preserve the control session and obey overlap limits. Keep a checksummed file stream, MCP request, ACP HTTP/SSE response, and fake computer operation active through at least three rotations; prove freeze/drain precedes commit without reopening adapters. |
| Session fencing | A reconnected device fences its previous session according to the protocol. Late cleanup from the old connection cannot remove or overwrite the new registration. |
| Reconnection races | Simultaneous reconnect attempts, old/new data handshakes, repeated connection identifiers, and dropped registration replies do not produce two authoritative sessions. |
| Control failure | Losing the control connection before, during, or after replacement enforces the specified admission and teardown rules; an orphaned data socket cannot retain authority. |
| Lifecycle | Consumer cancellation, device shutdown, relay restart, and graceful deployment shutdown produce explicit terminal outcomes and release queues and registrations. |
| Persistence boundary | Restart, verified backup/restore and rollback behavior matches the Redis durable-catalog versus ephemeral-coordination guarantees. A fresh relay must not claim to know a prior side effect's outcome when that outcome was never durably recorded; ambiguous authority remains fail-closed. |

Specifically distinguish a control reconnect that raises the epoch and can resume adapter-approved retained same-process streams from a connector or relay process restart, which creates fresh v0 sessions. The 9P adapter is deliberately stricter: an epoch change terminates its filesystem session and invalidates its fids. An unrelated second process presenting the same connector identity must receive a conflict unless explicitly authorized to take over. Control recovery must also close obsolete transports before creating replacements so it preserves the total socket bound.

### Authorization and revocation matrix

Run each negative case against discovery, device selection, control registration, data attachment, capability invocation, stream continuation, and result delivery where applicable. A request supplied with another user's identifier must never inherit that user's authority.

- Missing, malformed, expired, wrong-audience, and insufficient-scope credentials.
- A valid credential for user A addressing user B's device, session, operation, or capability. Assert both denial and absence of B's canary data in responses, events, and consumer-visible logs.
- Replayed or stolen test data-attachment credentials used with the wrong device, user, control session, generation, or connection; enforce every binding and reuse rule the protocol specifies.
- Revocation while idle, queued, executing, streaming, reconnecting, or overlapping data generations. Measure enforcement time against the implementation's documented revocation policy.
- Authorization changing between discovery and invocation, or between operation admission and completion. Verify which in-flight work is cancelled and what completion information may still be delivered.
- A device reconnecting after revocation or after a newer session has become authoritative.

Use test identities and synthetic credentials exclusively. Logs should include enough non-secret correlation data to diagnose a denial; snapshots must prove that bearer tokens, pairing secrets, and file/screenshot payloads are redacted. The initial cluster milestone must rerun the matrix across at least three relay instances with reconnects landing on different instances; passing a single-process test does not establish distributed fencing.

## Device mTLS, CLI lifecycle, and diagnostics

Compile the selected Axum/rustls/WSS and separate Quinn/h3 dependency stack with exact pins and Cargo.lock under Rust 1.95.0 before claiming compatibility. Inspect actual TLS 1.3 negotiation and verified identity propagation through HTTP upgrade. Test mandatory client authentication on control and every initial/candidate/recovery data socket: no certificate, bad chain/name/usage, wrong role, expired/revoked/unknown device key, mismatched tenant/device claim, forged certificate headers, stolen ticket with another valid key, expired/reused ticket, and control credential presented as a data ticket must fail before dispatch. Device, relay-peer and consumer roles remain separate. Verify device resumption and early data are disabled; neither TLS success nor a ticket alone creates authority.

Use fixture PKI for credential create/import, key matching, owner-only key-file permissions and Windows ACLs, and atomic interrupted replacement. Test the gated enrollment flow's CSR possession, immutable identity/role binding, one-use authorization, concurrent redemption and lost-reply receipt recovery before advertising self-service enrollment. Renewal drains/closes the old pair and establishes a new credential/epoch; it must not mix keys in one epoch or exceed socket bounds. Certificate expiry and revocation terminate already-open sockets independently of data rotation and preserve ambiguous in-flight outcomes.

Snapshot implemented CLI help, flag precedence, versioned JSON/NDJSON, stdout/stderr separation, redaction, and documented exit codes as commands land; retain the bootstrap exit behavior until its planned replacement is implemented. `config check`, `status`, and default `doctor` must not connect, start exports, or invoke a desktop. `doctor --network` performs only bounded non-owning readiness checks and cannot acquire an epoch or consume an attachment ticket. Test missing supervisor, per-profile lock contention, same-user-only IPC, graceful disconnect deadlines, signal handling, permanent trust failure versus supervised transient retry, and joining child tasks/processes after shutdown.

For each runtime runbook, inject the corresponding DNS, trust, mTLS, ticket, drain-gap, peer UDP, ownership, and registry failure. Assert diagnostics identify the failed layer, include safe correlation/deadline/fence information, and remain bounded during pressure. Scan planted secrets and payload markers out of logs, JSON, status and diagnostic bundles. No diagnostic test accesses a real desktop or changes a filesystem export as a probe.

## Initial cluster and coordination gates

Use three real relay processes, one supported authoritative Redis primary with separate durable-catalog and ephemeral-coordination namespaces, synthetic signed membership records, and real private mTLS HTTP/3. Force control, active data, candidate data and consumer ingress onto different nodes over successive scenarios. Consumer/device ingress forwards directly to one owner; internal routing never adds device sockets or another forwarding hop. An all-local routing fixture cannot satisfy this gate.

| Boundary | Required planned evidence |
| --- | --- |
| Peer transport | Actual QUIC/TLS 1.3 and ALPN `h3`, mutual role/key validation, full-duplex request/response bodies before request completion, cancellation, GOAWAY, bounded stream/connection buffers, and connection/key-rotation ceilings. Block UDP and reject unapproved peers without HTTP/2, plaintext, or disabled-verification fallback. Disable 0-RTT. |
| Signed Redis directory | Reject forged signatures/keys, wrong deployment/incarnation/role/address, duplicate fields, excessive record size/keys, expired/not-yet-valid records, lower versions and equal-version conflicts. Require a fresh nonce-bound authority checkpoint at process start; Redis key presence or a successful read cannot create or extend trust. |
| Trust lifecycle | Rotate current/next peer keys within the bounded overlap, revoke connected peers/devices, drop all Pub/Sub hints, partition the registry, restart with stale snapshots, and simulate skew/clock rollback. Measure five-second connected reconciliation and the documented signed-expiry bound under partition; stale caches cannot extend it. Membership/CA private keys must not be in Redis or ordinary relay configuration. |
| Shared authorization | Redis-native tenant/device key scoping, durable catalog revisions, concurrent grant/revocation updates, bounded atomic scripts/functions, least-privilege publisher versus relay identities, and rolling schema/version changes. Durable-catalog read/write failure stops new admission immediately; snapshot lifetime starts at catalog-read initiation and never exceeds five seconds or renews through cache hits. Inject catalog-operation failures independently from ephemeral lease/coordination failures even though both use the same authoritative Redis. |
| Ownership and tickets | Exercise atomic acquire/increment/renew/compare-release/one-use consumption under races, lost replies and stale node/boot/session tokens. Validate the complete owner token, exact credential/ticket binding, connector fencing ACK before readiness, and rejection before buffer allocation. Old cleanup cannot delete the successor; unknown acquisition/renewal cannot assume authority. |
| Lease deadlines | Test 30-second TTL, 10-second renewal, five-second owner margin, two-second registry RPC deadline and challenge-send-based device permission of at most 20 seconds. Delay replies, suspend/resume processes and race dispatch after await; authority is checked immediately before each dispatch and cannot be extended from reply receipt or heartbeat traffic. |
| Forwarded admission | Reject forged source identity, destination owner, tenant/grant, internal headers, credential context and hop budget. The owner independently verifies consumer grants and ticket/device context. Retry route admission once only with proven `NOT_DISPATCHED`; lost/partial acknowledgments preserve uncertainty and never repeat effects. |
| Coordination failure | Partition Redis, kill/restart/restore the primary, simulate missing/rolled-back epochs, unknown authority, two primaries and exhausted counters. Test AOF/fsync and verified backup restore as durability behavior only; neither backup success nor replica acknowledgment authorizes promotion. The initial profile rejects automatic promotion: stop admission, fence/close sessions, remain unready, verify the durable catalog/signed directory, and require operator quiescence plus a fresh externally authorized incarnation/checkpoint. Unfenced old writers or incomplete/ambiguous restores block recovery. |

### Continuation verification checkpoint (2026-09-10T08:24:36+10:00)

The maximum encoded-record fix is now linked: peer sends fragment transport
chunks while preserving one complete record and its whole reservation. Current
scoped results are recorded in [m7-verification.md](m7-verification.md): cluster
47, protocol/core 85/8, relay/transport libraries 106/18, Redis catalog/cluster
5/9, Redis recovery/races 10/2, live boot replacement 1, privileged RPC 7, and
operator recovery workflow 3 tests pass. Rebuilt transport fault acceptance
passes all flags; two full production acceptance runs and the process-pause
fixture pass on that build. The first production revocation-recovery timeout
remains unexplained, so I22 stays open. Pressure I23, readiness C20, the final
workspace/Clippy/format gate, M1/M2 reruns and row-by-row matrix closure remain
open. These counts do not imply current hosted CI or full milestone acceptance.

The reusable M7 script includes both newly linked boot-replacement and operator
recovery targets. Later readiness/runtime edits require affected acceptance
reruns. The following older checkpoint remains as chronological evidence and
must not be read as overriding this scoped update or [tasks.md](tasks.md).

### Current M7 evidence boundaries (2026-09-10)

The focused transport command is evidence for the HTTP/3 component path. The fixed `verify-m7-transport` runtime passes M7-C03's stated narrow gates in `/tmp/agent-tunnel-m7-runtime-verify-m7-transport-fixed.log`: duplex, role/pin, oversize, truncation, idle, cancellation, revocation, sibling, budget, UDP partition, no TCP fallback, 0-RTT disabled, joined shutdown, mutation positive control, and stable admissions. The root cause was test-only `ClientSessionMemoryCache(4)` ticket eviction; bounded size 16 preserves reuse. This closes the narrow transport component scope. The earlier `mutation_positive=false` run remains chronological; broader relay/production fallback evidence remains open.

M7-C06's earlier health-route gap has an implementation in place: redacted `livez`/`readyz` routes and a readiness dispatch gate are now present. The focused log `/tmp/agent-tunnel-m7-validation-m7_health_endpoints.log` records one passing `livez_stays_observable_while_readiness_and_dispatch_fail_closed` test, which closes only the local endpoint/dispatch-gate slice. Test live configured `rediss` authority and both public liveness/readiness endpoints while Redis or membership authority is unavailable; synthetic readiness fixtures and Redis-directory tests do not establish startup checkpoint refresh, full dependency-loss behavior, or fail-closed admission in that process-level condition.

M7-C07 requires direct returned-error cleanup from each relevant control, data, and peer handler. Receiver-drop, queue-budget, stale-successor, and cancellation regressions cover bounded cleanup components, but they do not close every handler path that returns an error after admission. The latest focused cleanup checkpoint passes 1/1 with a real H3 `PeerClientStream`: a valid envelope receives 200/OPEN, a declared one-byte consumer prefix with no payload is followed by FIN, `RecordingHandler` increments its error count before revocation, and the raw stream is terminal while the original stream queue remains charged. This closes the direct consumer returned-error cleanup and sibling-isolation subset. The staged control-cleanup fixture's two-catalog setup was rejected in review and is being corrected to one authority or explicitly scoped direct post-admission handler testing. The remaining control/data returned-error cases are staged by `peer_deadlines` after successful control registration and data admission, using malformed peer framing before actor cleanup; no new control/data result is claimed and broad all-exit coverage remains open. The earlier 86/87 and 0/1 failures remain chronological evidence in [m7-verification.md](m7-verification.md). See [tasks.md](tasks.md).

M7-C16's Redis TLS API and real peer mTLS forwarder fixture passed build 40800 with all four flags true: authenticated catalog connection, wrong-CA rejection, wrong-server-name rejection, and wrong-client-identity rejection. This closes the narrow TLS fixture scope; full relay `rediss` deployment and health integration remain open. M7-C17's false-flag handling fix in `main` requires fresh production, transport, and partition command runs; earlier passing output remains dated baseline evidence.

M7-C18 must bind each inbound and outbound peer flow to the actual authenticated certificate during signed key overlap. A first signed-valid SPKI is insufficient: an overlap certificate can be globally approved while failing equality against that first key. The focused log `/tmp/agent-tunnel-m7-validation-m7_live_membership.log` now records one test passed in 0.07 seconds, covering real H3 old/new positives, an unknown same-node certificate rejection, and no-hint signed removal/expiry. This closes the narrow certificate-binding slice; broader propagation remains M7-I06.

M7-C19 is in handover. The generic encoded-record boundary is explicit: a valid `CompleteDeviceData` body of 65,600 bytes encodes to 65,608 bytes, above the 65,536-byte H3 chunk maximum. `peer_fault_harness` is frozen after changing only `crates/tunnel-transport/src/peer.rs`, where unvalidated `send_chunked(&[u8])` methods/helper sequentially split by the actual `BodyBudget.max_chunk_bytes`. Wire the two send helpers in `peer_runtime.rs`, remove the unused `Bytes` import, add focused tests, and run transport/maximum-size production validation. Consumer workaround bodies remain 65,528 bytes. Preserve the advertised limit and required auth/isolation behavior; runtime verification is pending and no pass is claimed. Dedicated security auditing is deferred to Daybreak when requested.

The fresh local suite checkpoint records relay library 88 passed/0 failed,
health endpoints 1/0, persistence 4/0, readiness 9/0, harness library 27
passed with 1 ignored, harness main 6/0, live membership 1/0, and privileged
RPC 4/0 in `/tmp/agent-tunnel-m7-validation-tests.log`. The standalone binary
build passed in `/tmp/agent-tunnel-m7-validation-build.log`; this is local
library/harness/build evidence and does not establish production three-relay
acceptance or hosted CI.

The task-owned fixture permission correction now gets the latest
`verify-m7-production` run past the strict membership-state parent check, but
the run fails later with `production echo closed before response`
(`/tmp/agent-tunnel-m7-runtime-production-current.log`). Static phase diagnosis
is active and has not identified whether the initial or maximum-size canary
failed. No C19, canary-isolation, or complete production acceptance assertion
is counted. `real_cluster_harness` repairs only its task-owned fixture
directory while production private-path checks remain strict. Affected current
production rows stay implemented-awaiting-verification under C06/I12/I20 until
the focused diagnosis and required reruns pass; earlier startup and production
passes remain dated history.

The real signed key-rotation and expiry socket slice now has one narrow pass recorded above; M7-I06 remains active for propagation, expiry bounds, and deployment diagnostics. The M7-I07 production-pressure implementation is present and compiles, but no runtime pressure result is recorded; compile session 21471's fixture issues remain chronological evidence in [m7-verification.md](m7-verification.md). A read-only `verify_scope` audit is checking applicability, evidence scope, and circular adapter dependencies before the 98-row matrix is edited. The I20 verifier fix and production `new_with_store` wiring are implemented; the corrected persistence fixture must still prove save-before-publish behavior in a runtime rerun.

The corrected catalog session 32255 passed 23 unit tests, including six approval and six full-schema tests, plus five `redis_catalog` and nine `redis_cluster` tests, with current-generation mutation regressions. The exclusive-validator recovery checkpoint then passed `redis_recovery_races` 2/2 (`/tmp/agent-tunnel-m7-validation-redis-recovery-races.log`) and `redis_recovery` 10/10 (`/tmp/agent-tunnel-m7-validation-redis-recovery.log`), including oversized-key, cumulative-key-byte, and dedicated-connection cases. These are bounded I19/I21 subsets; operator CLI recovery and post-EXEC ambiguity remain open. The staged operator module now has redacted `Debug`, supervised blocking phases, and staged Redis workflow tests. `recovery.rs.disabled` contains three ignored recovery test cases, but they are not linked into Cargo and have not run; `wiring.md` likewise has no integration evidence. The canonical recovery snapshot must include orphan, direct-lookup, and epoch keys and bind one catalog generation atomically. Avoid `WATCH` phantoms and pre-bound `HGETALL`/`SMEMBERS` allocation, reject a same-incarnation live-owner bypass, and retain bounded raw `SCAN` handling. The hardened I20 store uses standard OS sidecar locking, safe no-follow FD validation, and a private parent; its verifier fix and production `new_with_store` wiring are implemented. The local persistence/restart log `/tmp/agent-tunnel-m7-validation-m7_membership_persistence.log` records 4/4 passed, closing that local scope alongside prior `membership_version_state` unit coverage; full server-process deployment and configured health/readiness integration remain C06. The owned synthetic process-pause command passed with three relays and fresh-owner recovery; it does not exercise a desktop or close the broader lifecycle gate. The privileged RPC baseline is 4 passed/0 failed in the fresh suite; the expanded target passed 6/6 in `/tmp/agent-tunnel-m7-validation-m7_privileged_rpc-final.log`, including shared-pool same-ID isolation and deadline/retained-worker cleanup. Its source now has seven tests, with the corrected deadline assertion and a separate active-worker shutdown case awaiting validation; no fixed sleeps remain. A separate active synthetic state-admission slice covers EC065/EC066 without claiming production adapters, Redis, SQLite, or later adapter semantics. See [m7-verification.md](m7-verification.md).

The `real_cluster_harness` EC011 public `/livez` 200, `/readyz` 503 during an actual Redis partition, then `/readyz` 200 after restore assertions and mandatory-flag mapping are implemented; Cargo/runtime verification remains pending. An active `verify_scope` synthetic RPC slice targets EC065/EC066 terminal/commit/success-ACK counts and frozen, fenced, pending, poisoned, stopped, and uncertain manager-state admission. That slice has no runtime result yet. `scripts/m7-harness-verify.sh` and the M7 CI job have passed only local script-syntax and workflow-YAML checks; no hosted CI result is claimed. Keep the M7 gate and 98-row matrix open until these scoped checks and the remaining lifecycle/adapter evidence are rerun.

Verify independent device `AUTHORIZATION_CHALLENGE`/`AUTHORIZATION_CONFIRMED` for every frozen stream context: grant scope/digest/revision and owner binding, latest one-use nonce, and deadline anchored at device challenge creation before queueing. The owner supplies only remaining lifetime from the original Redis catalog read-start deadline; cached reads cannot renew it. Test the five-second authorization ceiling while ownership permission remains valid for 20 seconds, two-second refresh/timeout, delayed/duplicate/reordered confirmations, snapshot predating the challenge, and clock suspension. Buffered decoded 9P requests and later privileged steps must recheck after every await and expire without dispatch; reset stale streams, discard undispatched work, and preserve already-started outcomes. Late confirmation cannot revive a closed context, and changed grants require fresh OPEN. Exercise the 64-context, one-outstanding-nonce, 2 KiB single-context message and bounded renewal-queue limits during saturated rotation/cancellation traffic.

Send the maximum legal complete device data WebSocket through a non-owner ingress: 64-byte header plus 65,536-byte payload is 65,600 bytes, and its eight-byte peer record prefix makes 65,608 charged bytes. Fragment the HTTP/3 body at every parser boundary, verify intact delivery, and reject 65,601-byte bodies before allocation. Separately test 32,768-byte control, 65,536-byte consumer-chunk and 125-byte close body ceilings and malformed peer kinds/flags/reserved fields. Charge reassembly, queued records and copies across both directions: a 256 KiB stream holds three maximum data records and blocks the fourth; an 8 MiB connection holds 127 and blocks the 128th across its streams. Transfers between parser and queue transfer ownership of the charge, while copies consume additional budget; cancellation/errors release reservations.

Kill owner and ingress processes independently, reconnect devices to a new owner, and rotate peer keys during tunnel drain. Owner loss creates fresh sessions and invalidates filesystem fids/adapter state as specified; no HTTP/3 route cache or durable catalog restores replay buffers or ACP subprocess state. Distinguish readiness from liveness under dependency loss. Rerun tenant isolation, quotas, cancellation and unknown-side-effect fixtures through both forwarding segments with saturated traffic, and record bounded per-hop as well as end-to-end memory.

## Failure semantics and side effects

Fault injection must cut the data connection before send, after partial send, after backend acceptance, after the backend side effect, and before the terminal result reaches the consumer. Repeat during rotation and relay/device restart. Include append, rename, and a synthetic computer click counter so repeated effects are visible.

Every operation must finish with the protocol's precise outcome, including an indeterminate outcome when execution may have happened but its result cannot be established. Do not promise exactly-once execution across a crash without the necessary durable backend support. Never automatically replay a non-idempotent operation merely because a new data connection exists.

Test deduplication identifiers within their declared scope, duplicate terminal responses, reconnect retries, and expiration of any deduplication record. When a safe retry is supported, prove it produces one effect. When it is unsupported, prove the caller receives an actionable ambiguous-result error and the backend receives no automatic retry. Separate idempotent reads, resumable streams, idempotent writes, and non-idempotent operations in the test fixtures.

## Flow control and resource limits

Use generated binary files and synthetic screenshots, including empty data, invalid text bytes, and payloads above every configured threshold. Transfer small interactive responses concurrently with large file reads, file writes, and screenshot streams. Slow or stop an individual reader and verify that its queues are bounded and other users and devices continue to make progress.

Assert maximum frame size, maximum operation size, per-stream and per-connection queue limits, in-flight operation limits, and per-user/device quotas. Test admission at the limit and one unit over it, cancellation of a blocked writer, disk-full errors, exhausted file handles, and memory-pressure behavior. Verify that heartbeat, cancellation, revocation, and rotation control messages remain responsive while the data path is saturated.

Measure peak resident memory, queue high-water marks, end-to-end latency, fairness, and bytes transferred. A successful checksum proves content integrity; a successful return code alone does not. Use a streaming generator and sink so the harness does not conceal relay buffering by preloading entire files into memory.

## Filesystem API and framework interoperability

Test the common path from each framework's native adapter through the shared TypeScript filesystem client, authenticated binary WebSocket, relay logical stream, and confined Rust 9P2000.L server. Use the endpoint discovery and session contract in [filesystem-api.md](filesystem-api.md); constructing a compatible-looking object or passing an in-process mock proves neither endpoint interoperability nor authorization. Consumer filesystem sockets are separate from the device's two steady-state sockets; monitor both classes so multiple mounted clients do not produce a false rotation-bound failure.

### Contract compilation and capability profiles

Pin each published package, its exact resolved dependencies, and the upstream source/interface revision in [filesystem-adapters.md](filesystem-adapters.md). Compile the actual adapters against installed Files SDK, Mastra, just-bash, and AI SDK declarations using a checked-in lockfile. Type assertions, locally copied interface substitutes, suppressed type errors, and tests that import only our own types cannot satisfy this gate. Record differences between a source snapshot and its published package before choosing the implementation pin. A dependency update must rerun contract compilation and affected behavior tests before advancing that pin.

| Consumer | Required evidence |
| --- | --- |
| Files SDK | Register the native provider/adapter with the pinned SDK and exercise supported SDK filesystem methods through it; prove optional methods and advertised capabilities match the selected mount profile. |
| Mastra | Mount the implementation of the pinned `WorkspaceFilesystem` contract in a real Workspace and exercise Workspace filesystem operations; filesystem access must not imply a host command-execution sandbox. |
| just-bash | Pass the pinned `IFileSystem` implementation to `new Bash({ fs })`; run the command transcripts below with optional host/network execution features disabled. |
| AI SDK native files | Compile `FilesV4` against pinned `@ai-sdk/provider`; exercise `ai.uploadFile` and the provider instance's optional metadata/download/delete methods using `createFilesApi`. This is a managed file-object view, with the reference restrictions below, not a directory API. |
| AI SDK live tools | Register native filesystem tools or supported individual `files-sdk/ai-sdk` factories; validate actual schemas, abort propagation, bounded output and structured partial/unknown outcomes. Keep these gates separate from FilesV4. Ordinary CI does not require paid model calls. |

Run each supported adapter against a read-only mount and the documented writable profile. Where a framework expects an operation the endpoint cannot provide, prove the published adapter behavior: reject construction if that capability is mandatory, or expose an explicit unsupported-operation error if the framework permits it. An absent capability must never become fabricated metadata, a silently ignored option, or a successful no-op. Compile-time interface coverage and runtime capability coverage are separate results.

### Discovery, authentication, and session admission

Exercise authenticated `GET /v1/devices/{device}/services/{service}/fs` without Upgrade for the JSON descriptor, then upgrade that same endpoint to WebSocket. Check schema `agent-tunnel.fs.v1`, subprotocol `agent-tunnel.9p.v1`, dialect `9P2000.L`, online/offline availability, opaque grant revision, effective operation capabilities, extensions, and limits. Reject malformed descriptors, unsupported versions/dialects, inconsistent limits, and untrusted endpoint origins before opening a usable session. Descriptors must not contain host paths, secret credentials, or information about unauthorized mounts.

Generate static descriptor fixtures and Rust/TypeScript contract checks from the checked-in API schema when implemented. Exercise each limit exactly at and one unit beyond its advertised value, and a smaller configured value; verify the server, shared client, and native adapters agree. Cover the initial 65,536-byte `msize`, 64 in-flight requests, 256 fids, 16 MiB buffered-file bound, 1 MiB queue bound, 10,000 traversal entries, depth 64, 30-second request timeout, and 300-second idle-session timeout as defined in the API plan. Use paused clocks for deadline boundaries and real sockets for enforcement. A large streamed file must not bypass per-frame/queue bounds or be confused with a whole-file buffered read.

Instrument the 32 MiB concurrent internal materialization reservation separately from caller memory. Concurrent reads, conversions and adapter-retained cache copies share that budget; enforce the limit before allocating and release reservations on success, failure, cancellation and transfer of result ownership. Sequential completed reads must reuse the quota even if the caller retains ordinary returned values. Returned Uint8Array/Buffer/string values are outside this internal bound, while any retained adapter copy stays charged; no test may claim the client controls application result-history memory. Check conversion-copy peaks and growth beyond a prior stat, not only final output length.

Repeat the authorization matrix for descriptor retrieval, WebSocket upgrade, 9P attach, operation admission, and open-fid use. Change grants, mount availability, and policy between discovery and upgrade and between upgrade and attach: a cached descriptor must not authorize access or restore removed rights. A stale `X-Agent-Tunnel-Grant-Revision` returns 409 `CAPABILITIES_CHANGED` before admission; changed session capabilities close the session instead of silently broadening it. Revoke a writable grant while writes are queued and report any already-started mutation accurately. Changing permissions or reconnecting must not reuse a previous caller's capability cache, fids, or authorization context.

Node is the initial adapter runtime; verify its supported credential transport, TLS validation, cleanup, deadlines, and cancellation. Browser support gets separate Origin, CORS, credential-transport, and buffering tests before it is advertised. Credentials cannot appear in URL queries, exception messages, or snapshots. If short-lived attachment tickets are introduced, test expiry, intended audience, single-use/binding rules, and concurrent redemption independently of the long-lived device data-ticket tests.

### Shared dataset and native semantics

Build one synthetic mount dataset and access that same authorized mount through Files SDK, Mastra, just-bash, and AI SDK tools concurrently. A file created through one writable view must be readable byte-for-byte through every other view; rename/remove must be visible without undocumented persistent caching. Compare native directory and metadata results after normalizing only documented differences. AI SDK FilesV4 uploads are also visible as ordinary files in their configured upload directory, while its native methods accept only its own references. Use real relay/device processes and sockets; preserve a separate fast mocked suite for error translation and upstream contract fixtures.

Include virtual `/`, relative and absolute paths, repeated separators, `.`/`..`, Unicode and combining characters, spaces, literal `%`/`#`/`?`, rejected NULs, platform separators, empty files, and every byte value. Test each upstream text/byte representation and all advertised encodings; invalid UTF-8 must not corrupt byte reads. Host filenames that cannot be represented by the documented path encoding must produce the documented explicit result. Numeric size/time conversion must fail on unrepresentable values rather than round or wrap.

Force multi-page directory results, short reads/writes, entry/depth limits, cancellation during traversal, and concurrent directory changes. Treat 9P directory cookies as opaque; adapters that return a whole listing must collect pages within the documented resource bounds and reject incomplete results rather than imply completeness. Test any framework pagination/filter/order options against its declared semantics, and reject unsupported options before mutation. No adapter may claim snapshot listing consistency without server support.

Maintain a common operation/error fixture table for missing files, denial, read-only mounts, unsupported operations, already-exists/type conflicts, offline devices, limits, cancellation, partial writes, and unknown mutation outcomes. Test the translation into every framework's native result/error shape, including `exists` behavior that must not turn unauthorized or unavailable files into ordinary absence. Preserve execution-outcome information when wrapping errors for SDK or model-visible tools without disclosing host paths or tokens.

Read-only tests must deny every mutation entry point, including composite copy/move, append, recursive changes, metadata setters, and optional native SDK methods. Inject failures after truncation, after a short write, and after rename but before reply; assert partial/unknown outcomes and no automatic mutation replay. Files SDK examples use zero retries; additionally count backend dispatches with application retries enabled to prove partial/unknown errors remain permanently nonretryable. Uncertified mutation plugins remain outside supported configurations. Shared `conditionalWrites` stays false: requests for atomic conditions fail with `ENOTSUP` before mutation, and neither QIDs nor stat-then-write may masquerade as compare-and-swap. Exclusive creation is a separately tested supported primitive.

Derive descriptor methods from the [primitive authorization table](filesystem-api.md#primitive-authorization-and-derived-capabilities), then test malicious raw 9P clients that bypass every SDK. Exercise each opcode, access mode and flag combination: writable open/create/read/write rights, `O_TRUNC`, append/exclusive modes, size-changing `Tsetattr` versus mode/time fields, unsupported ownership bits, rename/remove variants, links and unknown opcodes. A read-only grant must reject mutating flags before backend access, and an already-open fid cannot retain removed rights. Metadata/traversal and both rename endpoints remain confined. Copy capability requires its underlying read/create/write permissions; the descriptor must not promise unenforceable copy-only, grep-only or framework-only access.

Test both Mastra timestamp policies through its actual read-tracking/edit tools. Default `mtimePolicy:'reject'` rejects an internally supplied `expectedMtime` before parent creation/truncation/write, and must not claim ordinary writable read-edit compatibility. Explicit `check-before-write` compares the same millisecond mtime returned by stat: an existing mismatch throws the actual `StaleFileError`, while a match or missing file proceeds as pinned LocalFilesystem does; unrelated stat errors survive. Inject a writer between check and write and changes within timestamp precision to demonstrate the documented advisory race. This selected adapter policy never changes endpoint `conditionalWrites:false` or claims lost-update protection.

Files SDK fixtures must cover strict relative object keys, no-follow resolution, required `url`/`signedUploadUrl` permanent errors, object prefix versus directory behavior, delimiter/cursor binding and expiry, inclusive ranges if enabled, explicit native move, and Buffer/Blob/text limits enforced against actual bytes despite file growth after head. Borrowed-client tests close one adapter while another has live fids, proving wrapper cleanup cannot close the shared connection or bypass aggregate budgets. just-bash tool tests preserve `drainOperationFailures()` partial/unknown results across shell error wrapping and bound its 64-entry per-execution scope. The optional Files SDK native HTTP gateway and experimental AI sandbox profiles require separate exact-client tests before support is claimed.

### AI SDK FilesV4 managed references

Drive pinned `ai.uploadFile` for byte, strictly decoded base64, text and streaming uploads; invoke optional metadata/download/delete directly on the FilesV4 instance. Count provider calls and backend dispatches under actual helper failures: the inspected helper calls once and rethrows, with no `maxRetries` option to disable. Require an explicitly configured writable upload directory; create unpredictable names exclusively, treating filename/mediaType as bounded display metadata. Test collisions, read-only grants, cancellation, short writes, partial uploads and lost final replies. A reference is returned only after confirmed completion; incomplete files stay tracked for explicit cleanup and are never reported as successful uploads.

Exercise the 256-reference bound before file creation, unknown/foreign provider IDs, another adapter/principal/export/session's IDs, stale references after close, and nonempty per-call header overrides. References survive scheduled socket rotations but expire with the adapter/session; close must neither silently delete ordinary uploaded files nor evict/delete older objects to make quota room. Metadata remains session-local and cannot imply persistent arbitrary object metadata.

Test references as aliases for assigned virtual paths: another authorized view replaces the path, then metadata/download observe and delete removes its current occupant. Rename away produces absence unless a new occupant appears; the reference never follows the renamed file. Uploaded display metadata may become stale after replacement and must remain labeled advisory. Race replacement with stat/QID checks to prove no immutable object identity or delete-only-if-original guarantee is implied.

Read uploaded bytes through the other authorized VFS views and verify checksums. Reject arbitrary existing-path-to-reference conversion. To form model input, use bounded bytes or a separate model-provider upload; no OpenAI/Anthropic/etc. reference may be fabricated from an Agent Tunnel ID. Keep native provider conformance independent from directory tools, experimental sandbox sessions and live paid model inference.

Verify public/signed URL, download-URL, watch, and any other optional methods against the documented capability matrix. Unsupported URL methods must not fabricate a relay URL, leak bearer tokens, expose local `file:` paths, or silently create a public share. Files needed as AI SDK model input must be fetched through the authorized byte-reading path and bounded before conversion; tool calls must not cause arbitrary remote URL fetching. Consumer input cannot choose a host URL, host root, provider executable, or arbitrary backend headers.

## 9P over WebSocket and just-bash compatibility

The shared endpoint codec/session suite applies to every filesystem adapter. The just-bash suite additionally verifies `IFileSystem` and simulated shell behavior through that same endpoint. The following existing 9P requirements remain release gates for the common client/server, including when a framework exposes fewer operations.

### Codec, session, and cancellation conformance

Maintain byte-exact golden fixtures shared by the Rust server and TypeScript client. Include little-endian integers, UTF-8 string lengths, QIDs, request/reply tags, and `Rlerror`. Use the [pinned 9P2000.L operation reference](https://github.com/chaos/diod/blob/de51d1ee1bd5ccf1d8c16b96227c8bb03ec50106/protocol.md) for the selected dialect. Verify 64-bit offsets, sizes, and timestamps without JavaScript precision loss; range-check conversion to just-bash numbers and `Date` values.

Exercise version negotiation before ordinary requests, unsupported dialects, reserved tags, and messages exactly at and one byte above negotiated `msize`. `msize` covers the complete 9P message, independently of the outer tunnel-frame limit. Reject impossible sizes and truncated strings before allocation. The selected endpoint profile rejects repeated `Tversion` after attach by terminating the session; test pending-fid/tag cleanup rather than silently resetting hidden adapter state. The general [9P version/session contract](https://9fans.github.io/plan9port/man/man9/version.html) does not broaden this profile.

The consumer WebSocket carries exactly one complete 9P message per binary message. Exercise valid WebSocket-level fragmentation, and reject text messages, multiple 9P messages packed into one consumer message, and a 9P message split across multiple consumer messages. Independently fragment and coalesce 9P bytes across outer tunnel frames: the logical-stream parser must not mistake tunnel-frame boundaries for 9P message boundaries. Fuzz the incremental Rust and TypeScript codecs with the same corpus and compare accepted values and rejection behavior.

Test root attach, zero-element and partial walks, fid cloning, open/create, directory pagination, short reads/writes, clunk, and the implemented metadata/link/rename operations. Cover exhausted fid/tag quotas and cleanup after failed walks and interrupted operations. Concurrent outstanding requests require distinct tags within one 9P connection, while fids occupy that connection's namespace; independent consumers can use identical numbers safely. These are separate from tunnel stream and operation identities. See the [9P transaction and fid rules](https://9fans.github.io/plan9port/man/man9/intro.html).

Race `Tflush` with pending reads/writes, original responses, multiple flushes, invalid `oldtag`, and shutdown. Verify original responses arriving before `Rflush` are honored, tags are not reused prematurely, and no original response is delivered after the completed flush. Cancellation must not be represented as rollback of a completed filesystem mutation. Base ordering tests on the [9P flush contract](https://9fans.github.io/plan9port/man/man9/flush.html); a disconnected session can still leave a mutation outcome unknown.

Keep an open fid and concurrent tags active across repeated scheduled data rotations, checking byte offsets, checksums, response correlation, and no repeated backend writes. Data-only recovery may retain them only when the control owner and all required stream state remain intact. Consumer WebSocket loss, tunnel epoch change, or any process restart terminates the filesystem session: invalidate old fids and pending tags, require fresh version/attach, and never blindly retry a pending write.

Repeat the authorization matrix through 9P. A forged `Tattach` username, numeric uid, or export name cannot exceed the authenticated grant. Identical fid/tag values on another user's socket must neither reference their file nor cancel their request. Test grants with different roots on the same device, revocation with open fids, stale fid reuse after reconnect, and root selection fixed by authorization. The filesystem milestone cannot pass using an in-process provider call that bypasses the WebSocket entry point.

### just-bash interface and filesystem behavior

Cover the required `IFileSystem` methods: `readFile`, `readFileBuffer`, `writeFile`, `appendFile`, `exists`, `stat`, `mkdir`, `readdir`, `rm`, `cp`, `mv`, `chmod`, `symlink`, `link`, `readlink`, `lstat`, `realpath`, and `utimes`. Also test synchronous `resolvePath` and `getAllPaths`; neither may depend on a synchronous remote network call. If `getAllPaths` uses the upstream-permitted empty result, document that behavior and exercise affected discovery behavior. Test optional `readFileBytes` and `readdirWithFileTypes` if implemented.

Fixtures must exercise binary fidelity, text encoding, empty files, directory ordering assumptions, timestamp/`Date` conversion, missing paths, file/directory type conflicts, permission errors, link metadata, recursive operations, and Linux `Rlerror` to just-bash error translation on every supported host OS. Check supported host-platform behavior explicitly; do not pass a test by silently granting unsupported POSIX permission semantics on another OS. Restricted provider profiles must expose and test explicit unsupported-operation results, including link operations until their confinement guarantees are established.

Check Linux open-flag translation, `Rgetattr` validity masks, opaque `Treaddir` cookies, incomplete `Rwalk` results, and short `Twrite` handling. Test append under concurrent writers without a stat-then-write race; copy and recursive operations must use bounded composition with cancellation. Inject a failure between chunks of a write and verify partial file contents are reported accurately: the 9P profile does not promise atomic multi-message uploads. Ensure `mv` fails across roots/devices and never silently becomes copy-and-delete.

For every operation, test configured root confinement: absolute paths, `..`, platform separators, Unicode names, symlink chains, hard links, link cycles, cross-root rename/copy, and links changed concurrently with access. Concurrent rename/symlink races must not escape the authorized root. Mounts granted to one user or device must remain unavailable through another identity.

Run real just-bash command transcripts such as read/write pipelines, globbing, `find`, `stat`, recursive copy, rename, and binary file round trips against the remote adapter and compare their supported behavior with a local reference filesystem. Include tunnel loss and rotation during those commands. The adapter must preserve the distinction between an operation that failed before execution and one whose outcome is unknown. Verify read-only mounts deny all mutation methods, and host shell execution is unnecessary for the transcripts.

## ACP HTTP-to-stdio integration

Pin the stable ACP v1 schema, experimental HTTP transport revision and actual official Rust/client SDK artifacts before claiming compatibility. The [ACP plan](acp.md) selects the 2026-05-04 transport RFD baseline; package versions and draft ACP v2 are distinct. Run an official host HTTP client against Axum, through mTLS device sockets and the CLI's in-process HTTP handler, to a deterministic stdio child with no model credentials. Assert no inbound device listener is opened and HTTP/SSE bodies travel on logical data streams, leaving control for admission/cancellation/health.

Test initialize's 200 response and `Acp-Connection-Id`, connection/session GET subscriptions, session creation, 202 POST admission with the actual JSON-RPC result on SSE, session/header/body consistency, prompt updates and final stopReason, DELETE, rejected batches and unsupported protocol versions. Require one subscriber per connection/session, readiness within the ten-second subscription deadline, and no prompt admission before its session subscriber is ready. HTTP 202, SSE heartbeats and transport ACKs must not be mistaken for prompt completion.

Keep two sessions active through three rotations, with prompts, callbacks and pending responses spanning the drain. Reuse identical numeric/string JSON-RPC IDs in opposite directions, other connections and another tenant; route replies by the complete connection/direction/session context. Test duplicate pending IDs, legitimate reuse after completion, oversized/malformed stdio lines, output floods and response records without a sessionId. The bridge's bounded callback/request tables cannot leak correlation across users or deadlock behind a pending prompt.

Exercise `session/request_permission` allow/reject/cancel responses through POST, offered-option validation, wrong caller/session/direction, duplicate/late resolution, timeout and subscriber loss. Only an explicit valid selected option authorizes it; timeout/disconnect cancels pending permissions. Test `session/cancel` separately from SDK-supported `$/cancel_request`, accept updates until the original prompt result, and distinguish confirmed `stopReason:'cancelled'` from a lost process. Optional filesystem/terminal callbacks refer to the remote ACP host and require negotiated/local policy; neither a title nor an agent-provided URL/command creates permission or invokes the device VFS automatically.

Drop initialization/session/prompt/permission/DELETE acknowledgments before and after dispatch, lose the operation-ID response, break connection and session SSE independently, and crash the child after an instrumented fake effect. No POST replay or silent child restart is allowed; JSON-RPC IDs are not durable idempotency keys. Required established SSE loss terminates the v0 connection without Last-Event-ID replay, cancels pending work and requires fresh initialization. Authorized operation lookup reports known or `outcome_unknown` results; expired/absent records do not prove nonexecution. Optional agent session load/resume requires separately tested user/workspace binding and never resubmits an ambiguous prompt.

Repeat across three relays with GET/POST entering a non-owner, peer key rotation, owner loss, grant expiry/revocation and both forwarding segments saturated. Test forged internal identity headers, another user's connection/session IDs, fixed executable/cwd/argument/environment policy, and rejected consumer MCP attachments. Authenticate every HTTP request and SSE subscription; renewed tokens cannot transfer ownership. Verify per-principal child/state isolation, minimal environment, capped stderr, output-credit stall, reserved cancellation capacity, and process-group/job termination and descendant reaping on each supported OS. Only a verified sandbox profile may claim restricted execution; synthetic process-policy tests never run an agent on the user's active desktop.

## MCP and computer-use integration

For MCP, test against a pinned SDK/server fixture with initialization, negotiated capabilities, request/response correlation, notifications, cancellation, concurrent calls, structured errors, and streaming behavior for each supported transport profile. Exercise a long-running request across rotation. Confirm that MCP session state and its lifecycle follow the adapter contract instead of being inferred from the lifetime of one data WebSocket. Keep other exposed capabilities functional while MCP work is active.

For CUA, pin each supported backend profile separately. Use recorded synthetic contract fixtures or fake local servers in ordinary CI. The Python computer-server profile requires tests for its `/cmd` response format and its sequential `/ws` request behavior without correlation IDs. If a Rust `cua-driver` profile is selected, validate its own protocol and capability discovery independently. Tunnel credentials must not be forwarded as CUA cloud credentials.

Actual computer-use tests run only in a dedicated disposable VM or isolated test computer with synthetic content. Never target a contributor's live desktop or a normal CI runner desktop. A person grants any required OS screen recording, accessibility, or interactive-session permissions during test-image setup; tests verify both permission-granted and permission-denied behavior without trying to bypass those prompts.

The GUI fixture should display a known test window, unique screen markers, a text field, and a click counter. Check screenshot dimensions and markers, targeted input, expected field contents, one click per operation, cancellation, unsupported capabilities, and lost permissions. Use screenshots containing only fixture content as test artifacts. Record OS, display scale, keyboard layout, backend version, and granted permissions with each run. Do not infer Windows/macOS/Linux feature parity from the success of a single backend on one OS.

## Soak, chaos, and load experiments

The following are proposed experiment sizes and acceptance targets for the first working transport. They have not been measured and are not product guarantees. Record hardware, OS, commit, configuration, TLS settings, network conditions, and raw measurements; revise the targets through a documented decision after obtaining a baseline.

| Experiment | Proposed workload | Initial acceptance target |
| --- | --- | --- |
| Baseline | 20 users × 5 devices, 2 consumers per user, 1 KiB echo payloads, 100 aggregate requests/second for 15 minutes | No cross-user/device delivery, corrupt payloads, or unexpected errors; relay-added p95 round-trip latency below 25 ms on a same-host loopback baseline. |
| Data saturation | Concurrent generated 1 GiB streaming transfers and 4 MiB screenshot payloads, with small interactive requests in parallel | Queue limits hold; no buffering proportional to file size; control deadlines remain satisfied. Record throughput and interactive latency before setting a network SLO. |
| Rotation soak | 100 devices over 24 hours with the 300-second default, plus a separate accelerated run | No leaked sessions or sockets and no duplicate side effects. After warmup, RSS has no sustained upward trend; compare equivalent load windows and investigate growth above 10%. |
| Failure recovery | Delayed/dropped data, abrupt close, control loss, 30-second network outages, and relay/device process termination | All admitted operations receive a documented terminal outcome or explicit disconnect/unknown-outcome indication; reconnect obeys configured backoff and produces one authoritative session. |
| Tenant fairness | One tenant reaches its configured bandwidth/concurrency quota while other tenants keep low-rate interactive traffic | The busy tenant is throttled or rejected according to policy; other tenants retain bounded queues and no unauthorized resource access. Establish latency bounds from the baseline. |

Report expected errors caused by fault injection separately from unexplained failures. Count connection generations, active/draining sockets, per-direction fence/ACK gaps, quiesce/drain/commit/retirement durations, forced closes, peer queue bytes, lease/trust freshness, operation outcomes, unknown outcomes, retries, and denied requests. Preserve a small reproducible failure trace instead of uploading all payloads or continuous desktop recordings.

## Gates by milestone

| Milestone | Required evidence before completion |
| --- | --- |
| Bootstrap, current | Config defaults/validation tests; formatting, linting, and workspace tests in the initial OS matrix. No transport claims. |
| Protocol, relay, and CLI | Deterministic state-machine/property tests, codec/fuzz fixtures, mandatory mTLS on both device sockets, credential/identity separation, pure config/read-only diagnostics, lifecycle/exit-code checks, and real-socket multi-user routing. |
| Initial cluster | Three-node private HTTP/3 with one authoritative Redis primary; separate durable-catalog and ephemeral-lease namespaces; signed membership/checkpoint/key lifecycle; complete owner-token/ticket/fencing tests; bounded authorization/lease expiry; independent catalog-operation, UDP and Redis-authority failure plus verified backup/restore and new-incarnation recovery; no unsafe automatic promotion. |
| Drain, reconnect, and reliability | Unique retained sequence spaces; immutable fences and both drain proofs before commit; abort/uncertain-commit/deadline races; missing-range-only recovery; duplicate-effects fixtures; bounded backpressure; concurrent adapter streams through three rotations and a real-default-interval run. |
| Filesystem API and adapters | Descriptor/upgrade/attach authorization races; shared 9P2000.L fid/tag/flush/session tests; actual pinned Files SDK, Mastra, AI SDK and just-bash contracts; common dataset/read-edit-read tools; both Mastra timestamp policies; native FilesV4 upload/download/delete/reference lifecycle; root confinement, read-only, partial-write, and unknown-outcome tests. |
| MCP | Pinned MCP lifecycle tests and failure propagation through the public consumer API, with filesystem and other capabilities active concurrently. |
| ACP | Actual pinned HTTP-to-stdio client conversation, callbacks and permissions, separate directional correlation, SSE loss/cleanup, three-rotation/three-node isolation, process supervision, and explicit unknown outcomes without prompt replay. |
| Computer use | Per-profile fake backend tests in CI, plus documented dedicated-VM results for each OS/backend combination advertised as supported. |
| First release | Soak/load report, full supported-platform integration matrix, clean-consumer artifact tests, dependency/license review, and documented limits and recovery behavior. |

Keep fast unit/config/codec tests in every pull request. Add protocol and adapter suites to required pull-request jobs as their implementations land. Schedule longer property, fuzz, real-interval rotation, soak, and VM runs separately, and make their relevant results release requirements. A skipped VM or upstream contract job must remain visible as unverified coverage.

For release artifacts, build for every advertised OS/architecture, record checksums and provenance, then download and unpack those artifacts into clean temporary environments. Execute their help/version/config checks and launch the packaged relay and device for a real consumer-to-device operation and a rotation. Verify that expected configuration examples, notices, and required runtime assets are present and that no workspace-only dependency is masking a missing file. macOS/Linux/Windows CI success is not by itself evidence for every architecture on those systems.
