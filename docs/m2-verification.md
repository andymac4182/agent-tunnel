# M2 implementation and verification

Status: M2 implementation and local acceptance are complete on 2026-09-10,
macOS arm64, pinned Rust 1.95.0. Hosted CI must repeat these checks; local
verification does not claim a released alpha or implemented remote adapters.

| Local gate | Evidence |
| --- | --- |
| Formatting and static checks | `cargo fmt --all -- --check` and strict locked workspace/all-targets Clippy pass. |
| Workspace | 151 tests pass: catalog 7, client 35, core 8, protocol 75, relay 11, harness 10, transport 5. |
| Redis authority | Five explicitly executed integration tests and the isolated pinned Redis AOF restart acceptance pass. |
| M1 regression | Five clients across two tenants; 21 echo requests, CLI smoke/echo, authorization, revocation, quota and cleanup assertions pass. |
| Accelerated M2 | Three rotations, generations 1–4, 12.14 seconds; initial/empty/split/coalesced records, three maximum-size records, slow consumption, post-handover traffic and cleanup. |
| Actual default | Three rotations at the 300-second policy, generations 1–4, 903.05 seconds, with traffic and cleanup. |
| Targeted faults | Retained data recovery, deterministic pre-commit candidate abort, control loss, cancellation and revocation pass with bounded cleanup. |

The default run used the final runtime. A subsequent harness-only cleanup
adjustment accepts terminal socket errors when a peer Close frame was already
observed; the updated accelerated and fault suites passed separately. It does
not relax unexpected EOF handling before an observed Close or alter runtime
transport behavior.

M2 preserves the authenticated session and each stream's two sequence spaces
while replacing physical data sockets. The relay coordinates every attempt.
The control socket remains open, and at most two data sockets coexist within
the original overlap deadline. See [the protocol](protocol.md) for normative
ordering, drain, replay and ambiguous-operation semantics.

## Implementation order

1. Pure bounded ordering/replay and rotation state machines, with deterministic
   clocks and malformed, duplicate, stale and out-of-order input tests.
2. Typed control messages and runtime policy negotiation, with a 300-second
   default, immutable attempt identities and bounded roster/proof encoding.
3. Real client and relay integration: authenticated candidate attachment,
   writer flush barriers, immutable fences, bilateral drain, commit and actual
   transport retirement. All carriers share the session's memory budget.
4. Retained data recovery, terminal tombstone reclamation and diagnostics.
   Recovery cannot resubmit an application operation or roll back a commit.
5. Real-socket acceptance, fault injection and default-interval evidence.

The M2 runtime advertises `ordered-rotation-v1`. Client and relay negotiate
the componentwise minimum of their validated rotation policies; the resulting
handshake deadline remains below overlap, and overlap below the interval.
The explicit M1 library profile remains available for regression fixtures.
The CLI defaults to M2 once that runtime is integrated.

Retained recovery has one absolute 30-second budget and at most three physical
connection attempts, with 100 ms and 200 ms retry delays. Retries never restart
that budget. Every physical attempt receives a fresh connection identity and
generation. The budget starts at RECOVERY_BEGIN and includes closing abandoned
data resources; a replacement ticket is issued only after both endpoints prove
those resources closed. Control loss ends the session rather than claiming
resumable control state.
These bounds are exercised by the real-socket evidence above.
The initial runtime may terminate the entire retained session when any stream
cannot be reconciled safely. It must report that interruption explicitly and
must not resubmit operations. Selectively preserving other streams after a
failed reconciliation requires a peer-visible failure agreement; M2 does not
infer that agreement from an empty replay list.

The initial model retains at most 256 physical connection identities per
session and rejects further allocation explicitly. It never evicts an identity
and then accepts a delayed close against a reused ID. This caps the lifetime of
the initial profile (roughly 21 hours at the default interval, fewer with
failed attempts); a fresh session interrupts retained operations. Removing
that limit requires generation-bound closure evidence with equivalent stale
event tests, not an unbounded identity set.

## Required evidence

| Gate | Required assertion |
| --- | --- |
| Independent ordering | Stream and direction counters continue across generations; one blocked stream cannot reorder another. |
| Duplicate suppression | Identical retained duplicates never reach an adapter twice; conflicting duplicates fail explicitly. |
| Immutable drain | Pending OPEN, FIN, RESET and unreclaimed terminal entries are included; a control FROZEN message cannot conceal an old-data gap. |
| Commit | Both immutable fence sets are acknowledged before activation; an uncertain or accepted commit never returns to the old carrier. |
| Socket resources | Peak is one control plus two data sockets; retirement or forced closure completes before another candidate opens. |
| Abort and deadline | Candidate failure can coordinate a known-uncommitted abort; retries and duplicate messages never extend the original deadline. |
| Recovery | Only missing retained sequences replay, without new credit or duplicate adapter delivery; missing history produces explicit interruption/unknown outcome. |
| Bounds | Replay, gaps, queues, credits, tracked streams, snapshots and control messages stay within hard caps under faults. |
| Cancellation | Cancellation, authorization expiry and shutdown remain responsive in every rotation phase. |
| Accelerated run | A single long-lived synthetic stream spans at least three real data rotations without reopening its operation. |
| Default run | Repeat at the actual 300-second interval for at least three rotations; record elapsed time and generations. |
| Regression | Complete M1 real Redis/HTTPS/WSS/CLI acceptance and authorization-negative probes continue to pass. |

The default-interval run must use wall-clock network execution. Advancing a
test clock proves state-machine behavior but does not satisfy that gate.
Fixtures remain synthetic and isolated; these tests do not control a desktop.

## Synthetic streaming fixture

The harness opens the authenticated consumer WebSocket at
`/v1/devices/{device_id}/services/{service_id}/stream`, with subprotocol
`agent-tunnel.echo.v1`. The existing consumer JWT and service grant authorize
this echo-only fixture. Each request is a four-byte big-endian byte length
followed by at most 65,536 bytes. The response uses the same framing and
prepends the fixture's device canary, bounded to 256 bytes. Empty records,
split records and multiple complete records in one message are exercised.
Consumer messages are bounded to 65,540 bytes, including record prefixes;
coalescing does not remove that message limit.
This fixture framing is separate from the future MCP, ACP and 9P bindings.

On failure, acceptance reports the named scenario stage, redacted connector
termination reason, physical carrier identities and logical sequence/queue
counters. It does not log request bodies, consumer tokens or attachment
tickets. An explicit disconnect is an interruption, not proof that an
application effect completed or permission to resubmit it.

## Validation commands

The existing required checks remain:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
TEST_REDIS_URL=redis://127.0.0.1:6379/ bash scripts/m1-harness-verify.sh
bash scripts/m1-redis-restart-verify.sh
```

The M2 acceptance entry points are:

```sh
TEST_REDIS_URL=redis://127.0.0.1:6379/ sh scripts/m2-harness-verify.sh accelerated
TEST_REDIS_URL=redis://127.0.0.1:6379/ sh scripts/m2-harness-verify.sh default
```

The accelerated command also requires the targeted fault suite to pass.
Use the script's `faults` mode to repeat only that suite during debugging.

Run Redis commands only against a disposable test instance. The accelerated suite does not replace the actual default-interval or
regression suites; keep each gate in CI and record its result.
