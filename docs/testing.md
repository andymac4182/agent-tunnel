# Verification plan

This document describes the evidence required as Agent Tunnel is implemented. The bootstrap currently validates configuration and contains tests for that configuration. It does not implement a tunnel, a filesystem adapter, MCP forwarding, or computer control. The transport, isolation, compatibility, and performance checks below are planned gates, not passing results.

Read [the protocol plan](protocol.md) for the authoritative connection and rotation rules and [the integrations plan](integrations.md) for upstream adapter contracts. Every implementation milestone must update this document to identify which checks actually run and link to their test code or CI job.

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

## Deterministic transport and state-machine tests

Keep protocol transitions separable from socket I/O so ordinary unit and property tests can drive them. Cover `Connecting`, `Active(g)`, `Preparing(g,g+1)`, `Switching(g,g+1)`, `Recovering`, and `Closed`, with control ownership, connection deadlines, and operation status modeled separately. Use Tokio's paused clock and explicit advancement for rotation tests; wall-clock sleeps are unsuitable for these assertions.

Exercise the default interval and shorter configured intervals. At each deadline test just before it, at it, and just after it. Cover replacement success, rejection, timeout, duplicate handshake messages, delayed acknowledgement, old-generation messages arriving late, simultaneous disconnects, and cancellation while a replacement is pending. Verify the chosen deadline starts from the protocol-defined event and that a slow handshake cannot silently extend the maximum overlap.

Property tests generate event sequences with reordered, repeated, and dropped events. Assertions must include:

- At steady state a device uses one control WebSocket and one data WebSocket. During rotation, only the explicitly permitted replacement overlap is allowed.
- A replacement becomes eligible only after the authenticated handshake and relay commit. Each sender switches newly sequenced frames to the selected generation at its protocol-defined cutover event; asymmetric receipt of the commit is handled safely.
- Commit is relay-owned, generations strictly increase, and a post-commit failure cannot roll back to an old generation. Repeated rotation requests coalesce and cannot extend the current overlap deadline.
- Existing streams retain their stream and operation identities while outstanding frames reconcile across generations. Before commit, overlap expiry discards the candidate; after commit, it retires the old socket and either recovers streams on the selected/newer generation or reports explicit failure.
- Each stream direction delivers contiguous sequences once. Duplicates received on both sockets, missing frames, half-close, and sequence exhaustion cannot reorder data, deliver after `FIN`, or wrap counters.
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

Run actual relay and device processes on loopback using ephemeral ports and temporary state directories. Fake device capabilities are appropriate for transport tests, but the control and data paths must use real WebSocket connections. Run deterministic fault injection through a local proxy and include a separate TLS-enabled path. Drive the public consumer entry point rather than calling relay routing functions directly.

The minimum multi-tenant fixture has two users in separate tenants, five devices, and concurrent consumers: user A owns three devices, user B owns two, and each user has at least two consumers. Use distinct canary responses and files for every device so misrouting is directly observable. Include identical user-controlled device labels and numerical stream identifiers across tenants. Add a third user in A's tenant with a limited grant to one of A's devices: prove permitted sharing works while other devices and ungranted capabilities remain denied. Here a device is the user-facing computer represented by a protocol `connector_id`.

Required scenarios:

| Area | Evidence required |
| --- | --- |
| Routing | Concurrent operations reach the selected authorized device and return to the initiating consumer, including when that user owns multiple devices. |
| Rotation | Repeated accelerated rotations and at least one run using the actual 300-second default preserve the control session and obey overlap limits. |
| Session fencing | A reconnected device fences its previous session according to the protocol. Late cleanup from the old connection cannot remove or overwrite the new registration. |
| Reconnection races | Simultaneous reconnect attempts, old/new data handshakes, repeated connection identifiers, and dropped registration replies do not produce two authoritative sessions. |
| Control failure | Losing the control connection before, during, or after replacement enforces the specified admission and teardown rules; an orphaned data socket cannot retain authority. |
| Lifecycle | Consumer cancellation, device shutdown, relay restart, and graceful deployment shutdown produce explicit terminal outcomes and release queues and registrations. |
| Persistence boundary | Restart behavior matches the documented persistence guarantees. A fresh relay must not claim to know a prior side effect's outcome when that outcome was never durably recorded. |

Specifically distinguish a control reconnect that raises the epoch and can resume adapter-approved retained same-process streams from a connector or relay process restart, which creates fresh v0 sessions. The 9P adapter is deliberately stricter: an epoch change terminates its filesystem session and invalidates its fids. An unrelated second process presenting the same connector identity must receive a conflict unless explicitly authorized to take over. Control recovery must also close obsolete transports before creating replacements so it preserves the total socket bound.

### Authorization and revocation matrix

Run each negative case against discovery, device selection, control registration, data attachment, capability invocation, stream continuation, and result delivery where applicable. A request supplied with another user's identifier must never inherit that user's authority.

- Missing, malformed, expired, wrong-audience, and insufficient-scope credentials.
- A valid credential for user A addressing user B's device, session, operation, or capability. Assert both denial and absence of B's canary data in responses, events, and consumer-visible logs.
- Replayed or stolen test data-attachment credentials used with the wrong device, user, control session, generation, or connection; enforce every binding and reuse rule the protocol specifies.
- Revocation while idle, queued, executing, streaming, reconnecting, or overlapping data generations. Measure enforcement time against the implementation's documented revocation policy.
- Authorization changing between discovery and invocation, or between operation admission and completion. Verify which in-flight work is cancelled and what completion information may still be delivered.
- A device reconnecting after revocation or after a newer session has become authoritative.

Use test identities and synthetic credentials exclusively. Logs should include enough non-secret correlation data to diagnose a denial; snapshots must prove that bearer tokens, pairing secrets, and file/screenshot payloads are redacted. A relay scale-out milestone must rerun the matrix across two or more relay instances with reconnects landing on different instances; passing a single-process test does not establish distributed fencing.

## Failure semantics and side effects

Fault injection must cut the data connection before send, after partial send, after backend acceptance, after the backend side effect, and before the terminal result reaches the consumer. Repeat during rotation and relay/device restart. Include append, rename, and a synthetic computer click counter so repeated effects are visible.

Every operation must finish with the protocol's precise outcome, including an indeterminate outcome when execution may have happened but its result cannot be established. Do not promise exactly-once execution across a crash without the necessary durable backend support. Never automatically replay a non-idempotent operation merely because a new data connection exists.

Test deduplication identifiers within their declared scope, duplicate terminal responses, reconnect retries, and expiration of any deduplication record. When a safe retry is supported, prove it produces one effect. When it is unsupported, prove the caller receives an actionable ambiguous-result error and the backend receives no automatic retry. Separate idempotent reads, resumable streams, idempotent writes, and non-idempotent operations in the test fixtures.

## Flow control and resource limits

Use generated binary files and synthetic screenshots, including empty data, invalid text bytes, and payloads above every configured threshold. Transfer small interactive responses concurrently with large file reads, file writes, and screenshot streams. Slow or stop an individual reader and verify that its queues are bounded and other users and devices continue to make progress.

Assert maximum frame size, maximum operation size, per-stream and per-connection queue limits, in-flight operation limits, and per-user/device quotas. Test admission at the limit and one unit over it, cancellation of a blocked writer, disk-full errors, exhausted file handles, and memory-pressure behavior. Verify that heartbeat, cancellation, revocation, and rotation control messages remain responsive while the data path is saturated.

Measure peak resident memory, queue high-water marks, end-to-end latency, fairness, and bytes transferred. A successful checksum proves content integrity; a successful return code alone does not. Use a streaming generator and sink so the harness does not conceal relay buffering by preloading entire files into memory.

## 9P over WebSocket and just-bash compatibility

The required path is real just-bash → TypeScript `IFileSystem`/9P client → authenticated binary WebSocket → relay logical stream → Rust 9P2000.L filesystem server. Test that complete path. Pin the upstream just-bash version and exact interface revision recorded in the integrations plan. A dependency update must compile the adapter against the pinned upstream interface and rerun behavior tests before updating that pin.

### Codec, session, and cancellation conformance

Maintain byte-exact golden fixtures shared by the Rust server and TypeScript client. Include little-endian integers, UTF-8 string lengths, QIDs, request/reply tags, and `Rlerror`. Use the [pinned 9P2000.L operation reference](https://github.com/chaos/diod/blob/de51d1ee1bd5ccf1d8c16b96227c8bb03ec50106/protocol.md) for the selected dialect. Verify 64-bit offsets, sizes, and timestamps without JavaScript precision loss; range-check conversion to just-bash numbers and `Date` values.

Exercise version negotiation before ordinary requests, unsupported dialects, reserved tags, and messages exactly at and one byte above negotiated `msize`. `msize` covers the complete 9P message, independently of the outer tunnel-frame limit. Reject impossible sizes and truncated strings before allocation. A successful version renegotiation clears outstanding I/O and fids according to the [9P version/session contract](https://9fans.github.io/plan9port/man/man9/version.html).

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

Report expected errors caused by fault injection separately from unexplained failures. Count connection generations, active/draining sockets, queued bytes, operation outcomes, unknown outcomes, retries, and denied requests. Preserve a small reproducible failure trace instead of uploading all payloads or continuous desktop recordings.

## Gates by milestone

| Milestone | Required evidence before completion |
| --- | --- |
| Bootstrap, current | Config defaults/validation tests; formatting, linting, and workspace tests in the initial OS matrix. No transport claims. |
| Protocol and relay | Deterministic state-machine/property tests, codec tests and fuzz smoke corpus, real-socket happy path and accelerated rotation, two-user routing and authorization suite. |
| Reconnect and reliability | Session-fencing races, control-loss/revocation matrix, duplicate-effects fixtures, bounded backpressure, fault-injected end-to-end suite, and a real-default-interval rotation run. |
| Filesystem and MCP | Shared 9P2000.L codec fixtures, fid/tag/flush/session tests, pinned just-bash contracts and Bash transcripts over the consumer WebSocket, root-confinement tests, MCP lifecycle tests, and failure propagation through the public consumer API. |
| Computer use | Per-profile fake backend tests in CI, plus documented dedicated-VM results for each OS/backend combination advertised as supported. |
| First release | Soak/load report, full supported-platform integration matrix, clean-consumer artifact tests, dependency/license review, and documented limits and recovery behavior. |

Keep fast unit/config/codec tests in every pull request. Add protocol and adapter suites to required pull-request jobs as their implementations land. Schedule longer property, fuzz, real-interval rotation, soak, and VM runs separately, and make their relevant results release requirements. A skipped VM or upstream contract job must remain visible as unverified coverage.

For release artifacts, build for every advertised OS/architecture, record checksums and provenance, then download and unpack those artifacts into clean temporary environments. Execute their help/version/config checks and launch the packaged relay and device for a real consumer-to-device operation and a rotation. Verify that expected configuration examples, notices, and required runtime assets are present and that no workspace-only dependency is masking a missing file. macOS/Linux/Windows CI success is not by itself evidence for every architecture on those systems.
