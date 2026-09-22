# Verification plan

This document defines acceptance gates across the project. M1's locked Rust checks, Redis catalog regressions, same-dataset AOF restart and real HTTPS/WSS/CLI/private-H3 harness have local evidence in [m1-harness.md](m1-harness.md). M2 rotation/replay has separate local evidence in [m2-verification.md](m2-verification.md). M7 cluster implementation and verification are in progress; remote adapters, backup rollback verification and performance/soak gates remain open. See [tasks.md](tasks.md) for current task status.

Read [the protocol plan](protocol.md) for authoritative connection and rotation rules, [runtime.md](runtime.md) for mTLS/CLI behavior, [cluster.md](cluster.md) for peer trust and ownership, [the filesystem API](filesystem-api.md) and [adapters](filesystem-adapters.md) for filesystem contracts, and [acp.md](acp.md) for agent HTTP transport. [The integrations plan](integrations.md) also covers computer use. Every implementation milestone must update this document to identify which checks actually run and link to their test code or CI job.

## Current bootstrap checks

Run these commands from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo run --locked -p tunnel-client -- config check --config examples/m1-client.toml
cargo run --locked -p tunnel-client -- check-config examples/client.toml
cargo run --locked -p tunnel-relay -- check-config examples/relay.toml
cargo run --locked -p tunnel-relay -- check-serve-config --config examples/m1-relay.toml
```

Each checked-in example must be validated by the parser that actually loads it, not by a parser that merely accepts a similar shape. `examples/m1-relay.toml` is the relay's serving document, so only `check-serve-config --config PATH` — which constructs the same `ServeConfig` as `serve --config PATH` — is evidence for it; the relay's legacy `check-config [PATH]` parses `tunnel_core::RelayConfig` and cannot represent a serving document at all. CI expands `examples/*-relay.toml` and dry-runs every match, and `crates/tunnel-relay/tests/example_configs.rs` plus `crates/tunnel-client/tests/example_configs.rs` walk the examples directory and fail on any file not classified with its parser, so a newly added example cannot escape coverage. Keep a serving example's filename matching that glob.

All four validation commands are read-only: they open no socket, contact no Redis authority, and read no credential, key or JWKS material. `check-serve-config` exits 0 when the configuration is valid and 1 with a redacted field-level reason on stderr when it is not; validating the referenced credential material stays in `serve`'s own startup.

The initial CI runs formatting, linting, and Rust tests on Linux, macOS, and Windows. The executable scaffolds check configuration; a successful exit is evidence of configuration validation only. Record the exact commit and runner when reporting a check as passed. The initial CI does not establish network connectivity, tenant isolation, upstream compatibility, or release readiness.

Configuration tests must preserve these defaults and reject invalid values:

- `[rotation].interval_seconds` defaults to 300 and accepts 1–86,400 seconds.
- `handshake_timeout_seconds` defaults to 10 and accepts 1–300 seconds. `overlap_seconds` defaults to 30 and accepts 1–3,600 seconds. Overlap begins when the candidate connection attempt starts, including its handshake.
- The cross-field rule is `handshake_timeout_seconds < overlap_seconds < interval_seconds`. An individually valid value can still violate this rule.
- Client `device_id` accepts 1–128 ASCII characters from `[A-Za-z0-9._-]`. Relay limits default to 1,024 total connected clients and 16 per user, with per-user capacity no greater than total capacity.
- Listener `handshake_timeout` defaults to 10 seconds, `pre_request_timeout` to 15 seconds and `http1_header_read_timeout` to 10 seconds. Each accepts 100 ms–300 seconds inclusive, and the cross-field rule is `http1_header_read_timeout <= pre_request_timeout`. A zero value is rejected rather than treated as "disabled", and an invalid value must return a typed error and release the listener instead of accepting connections with an unbounded permit. See the [bounded listener connection permits](runtime.md#bounded-listener-connection-permits) contract.
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
cargo run -p tunnel-test-harness --locked -- verify-m7-queue-saturation
cargo run -p tunnel-test-harness --locked -- verify-m7-remote-body-limits
```

The transport command exercises real mTLS/H3 fault cases. The cluster command
uses a synthetic owner callback. The production command uses real relay actors,
CLI/device WebSockets and public consumers across three relays.

`verify-m7-production` also records and asserts the IN-10/OG-05 heartbeat,
liveness and shutdown evidence, printed as a
`M7 production heartbeat/liveness/shutdown:` line and enforced by
`validate_production_liveness_evidence`:

- **Heartbeat.** The relay actor's owner-lease renewal is the only periodic
  authority round trip the product actually performs end to end, so the gate
  samples `Catalog::current_owner` for both tenant device scopes across the
  whole run and counts each advance of `lease_expires_at` per owner token.
  Every measured interval must fall inside `[owner_lease / 3, owner_lease]`,
  both edges derived from the fixture's configured
  `PRODUCTION_OWNER_LEASE`: the actor marks a lease due for renewal at
  `last_lease_renewal.elapsed() >= owner_lease / 3`, and a renewal later than
  the lease itself would have fenced the owner. The protocol `PING`/`PONG`
  pair is deliberately *not* used as heartbeat evidence — both peers answer an
  inbound `PING`, but nothing in the product emits one and the `WELCOME`
  heartbeat interval/timeout fields are advertised without being driven, so
  asserting on them would require adding a product heartbeat purely for the
  test.
- **Liveness vs readiness.** The gate probes one surviving relay's `/livez`
  and `/readyz` before and after the owner relay is shut down and requires
  both a ready and an unready observation, with the live envelope still served
  at the moment readiness failed closed.
- **Shutdown.** A dedicated real CLI epoch on its own device fanout (so the
  shared fixture's ordered route schedule and socket accounting are unchanged)
  is interrupted with `SIGINT`, and its join is *measured*. The measured
  duration must land inside one complete configured rotation cycle
  (`interval + handshake_timeout + overlap` from the fixture's `ROTATION`), the
  process must exit through its own stop path rather than be force-killed, and
  the stopped CLI must have released its Redis owner.

### Bounded multi-fault chaos classification (`verify-m7-chaos`)

```sh
cargo run -p tunnel-test-harness --locked -- verify-m7-chaos
```

The chaos gate (OG-08) fronts Redis with an opaque TCP proxy, starts one real
three-relay production cluster, and runs a fixed seven-round schedule that
repeats owner kill, CLI process pause and peer UDP loss and exercises a full
Redis pause once, each built from an existing fault injector: Redis pause
(`ProxyHandle::pause_all`), non-owner peer UDP loss (`set_peer_path_drop`), CLI
process pause (`SIGSTOP`/`SIGCONT` via `ProcessPauseGuard`) and owner kill
(`SIGKILL` of the owning `tunnel-client`). Redis pause is scheduled once, as
the terminal round, while the other three faults repeat.

The signed membership lease is **not** latched: the membership supervisor keeps
reconciling and restores `Ready` from the current pass alone once a
strictly-newer signed checkpoint and a catalog snapshot land together
(`crates/tunnel-relay/src/membership_runtime.rs`). The round records whether
that re-arm happened as `redis_membership_recovery=`, observed over a bounded
budget and **never asserted**, because it is measurably position-dependent in
this fixture:

* with the Redis pause mid-schedule, every relay returns to `Ready` on its own
  (observed at roughly 28 s after resume);
* as the terminal round of a ~60-second run it does not re-arm at all
  (0/3 relays Ready after 45 s of waiting).

The fixture's signed membership record lifetime is itself 60 seconds with a
20-second refresh (`membership_record_lifetime_seconds` /
`membership_refresh_seconds` in `production_cluster.rs`), so by the last round
there is no headroom left to absorb a full outage. Even in the mid-schedule
position where membership does re-arm, the cluster cannot be *reused*: the
record expires again shortly afterwards (`MembershipExpired`) and every fresh
owner CLI then fails its device control WebSocket handshake with a typed
`TRANSPORT_ERROR` on all three relays. Repeating the Redis fault with an
observed *session* recovery therefore needs a fixture change to the membership
record lifetime and its refresh across an outage -- not a schedule change -- so
the round is left terminal rather than given a recovery it does not have.
Every observed close or interruption is mapped into the closed vocabulary the
diagnostics already use — `bounded_close`, `admission_unavailable`,
`peer_unavailable`, `owner_released`, `outcome_unknown`,
`client_exit_before_ready`, `unclassified`. Unknown outcomes (a timed-out or
unsendable probe) are preserved as `outcome_unknown`, not discarded; an
observation that matches no bucket (for example an echo from a killed or paused
owner, or an unexpected HTTP status) is recorded as `unclassified`.

A `tunnel-client` that exits before readiness on the establish path is
classified rather than surfaced as an opaque harness error: the CLI's exit codes
are their own closed vocabulary (`CliError::exit_code` in
`crates/tunnel-client/src/main.rs` — 1 other, 2 invocation/config, 3 credential,
4 transport or supervisor-absent, 5 deadline exceeded, 6 outcome unknown), and
its typed `--json` diagnostic code is carried alongside. Such an exit is counted
in `client_exit_before_ready`; the validator requires every one of them to have
carried a typed exit code, so a signal death or an unexpected success exit
blocks release.

Reconnects are measured **at second scale and attributed to the client**. The
fanout fixture records the exact instant of every accepted device-fanout socket,
and each round brackets its own deliberate session recycle, so the enforced
metric `max_cli_reconnects_per_window` is the largest number of
*client-attributed* accepts inside any real one-second window, with the
fixture's recycle sockets (roughly two per round) excluded and bounded
separately by `max_recycle_sockets_round`. The previous whole-round average is
retained only for continuity: a ten-reconnect burst inside a ten-second round
averaged to one per second and passed a twelve-per-second threshold, which the
windowed metric now catches.

`validate_chaos_evidence` blocks release when any interruption is unclassified,
when client-attributed reconnects in any one-second window exceed the documented
ceiling of four, when a recycle exceeds six sockets, when accept instants were
evicted (making the window an undercount), when the reconnect attribution totals
disagree, when a pre-readiness CLI exit carried no typed exit code, when the
concurrent
device-fanout socket peak exceeds four, when a fault type was never exercised,
or when a per-round or final recovery echo did not succeed. The gate runs as part of
`scripts/m7-harness-verify.sh`. Its structured validator and its table-driven
M7-C17 mutation cases live in `crates/tunnel-test-harness/src/production_cluster/chaos.rs`.

### Evidence-promotion guard (`scripts/m7-evidence-guard.py`)

```sh
python3 scripts/m7-evidence-guard.py --verbose
```

A read-only IN-11 guard over `docs/m7-edge-cases.md` and `docs/tasks.md`. For
every row whose status column says verified it fails when the row cites a
`verify-*` harness gate that is neither a `tunnel-test-harness` command nor
referenced by `scripts/m7-harness-verify.sh`, or a commit hash that git
resolves to a real commit which is not an ancestor of `HEAD`. Hex tokens git
cannot resolve to a commit (digests, blob ids, squashed short hashes) and
gate fragments embedded in a longer path or log filename are ignored, so only
real citations are checked. The guard never writes to the docs.

### Concurrent same-identifier tenants and the duplicate-owner race

`verify-m7-production` keeps both tenants' device sessions online at the
identical device and service UUIDs for the whole run, and prints two extra
payload-free evidence lines beside its summary line. Neither line records a
payload, credential or canary byte; every field is a count, a boolean or an
epoch number.

`M7 production concurrent tenant isolation` reports that both tenants enrolled
the same device and service UUID with distinct tenant scopes, certificates and
keys; how many instants both tenants were sampled holding a live complete owner
token at once (`concurrent_owner_samples`); that those owners sat on different
relay nodes with different session identities; how many exact canary matches
each tenant made while the other was online; that the canaries differ; that
neither route ever emitted the other tenant's canary
(`cross_tenant_canary_absent`, asserted by expecting the wrong canary on a
throwaway stream in each direction and requiring that exchange to fail); and
the committed scheduled replacement generations each tenant reached. An offline
tenant-B device shows up as a missing concurrent owner sample, and a `503`
accepted in place of a routed canary as a missing exact canary; the validator
rejects both, so neither can satisfy the gate.

`M7 production duplicate owner race` reports the race of two real CLI processes
for one tenant's exact owner scope, run while the other tenant's
same-identifier session is still online. It records that both children were
spawned before any owner observation; that exactly one atomic winner took the
scope; the cluster-wide relay control-registration conflict delta, which must be
exactly one and must still be exactly one after a further settle window (a
reconnect storm raises it); that the loser emitted the exact non-retryable
`OWNER_BUSY` terminal diagnostic and exited non-success; that the winner's token
and canary, the tenant's independent sibling, and the same-identifier tenant's
owner and canary all survived; the winner and successor epochs, which stay above
the JavaScript-safe integer bound because the run seeds tenant A's durable epoch
there before any owner exists; and that a compare-release with the superseded
token was refused without disturbing the successor or the other tenant.

Composing the two properties in one run is the point: a scope key that lost its
tenant qualifier would evict the surviving same-identifier tenant during the
race rather than leave it untouched.

Two timing notes for anyone extending this gate. A pooled consumer stream is
cancelled after the fixture's 10-second peer HTTP/3 idle timeout, so an
application stream cannot be held idle across the race phase; tenant B's
stream is exercised on every tenant-A rotation and retired before the later
phases, which open fresh streams where they need one. The loser's structured
terminal diagnostic is drained with a longer budget than the component
owner-contention gate uses, because this gate reaches the race phase on a busy
machine; the assertion itself is unchanged. The Redis
partition command is being implemented under M7-I05/I17 and is not yet verified;
it must block both existing and newly accepted Redis connections, reject new
admission and expired-authority dispatch, then prove fresh authorized recovery.
The queue-saturation command drives the configured bounded data message queue to
its reachable physical bound behind a blackholed carrier; see
"Physical versus logical queue occupancy" below for what it does and does not
prove.
The remote-body-limits command drives the public echo stream through a
non-owner ingress and checks the maximum, zero, limit-plus-one (whole and split
prefix), truncated and coalesced record boundaries against owner-only peer
chunk reads and dispatch counters, so the forwarded and owner-local ingress
paths cannot drift on the bounded body-limit decision. Its final stage pins
the forwarded route's idle bound: a stream that completed a maximum record and
then carries no traffic is closed by the relay only after the fixture's
10-second peer HTTP/3 idle timeout. A remote exchange that idles or stalls
past that bound therefore fails to complete by design, which the owner-local
route does not enforce.
A command passing cannot close unrelated rows in [m7-edge-cases.md](m7-edge-cases.md).
Record the tested revision and outcomes in [m7-verification.md](m7-verification.md).

### Real owner-lease expiry, epoch retention and stale-release fencing

```sh
cargo run -p tunnel-test-harness --locked -- verify-m7-owner-lease-expiry
```

The owner-contention command only ever observes a *graceful* owner
disappearance: the CLI exits, the relay releases its lease and a successor
claims the retained epoch. That path never exercises the durable lease
deadline. This command does.

Every relay reaches Redis through an opaque TCP proxy. Once a real CLI owner
session is serving and has echoed, the proxy pauses both directions of every
Redis socket, including sockets accepted after the barrier. The relay can then
neither renew nor release the lease and logs its documented "lease expiry
remains the fencing fallback" path, so the owner hash can only disappear
through the `PEXPIREAT` deadline written by the claim script. A second catalog
handle, connected directly to the upstream Redis rather than through the proxy,
is the only authority reader that still works during the barrier; it watches
that disappearance and then attempts the predecessor's exact
compare-and-release.

The gate asserts, payload-free:

- the predecessor's exact owner token was still present after the barrier, so
  the later absence is an expiry rather than a pre-existing condition;
- the disappearance was observed at or after the lease deadline carried in the
  predecessor's own claim, with the measured margin recorded, and no earlier
  than one missed renewal tick (the relay renews at a third of the lease);
- at least one Redis socket was still paused when the absence was observed, so
  no relay release or delete could have removed the hash;
- the relay's monotonic lifetime application-dispatch counter did not advance
  across the expiry. The per-device counter legitimately drops to zero once the
  expired session is unregistered, so equality would be the wrong contract
  there and only "did not advance" is required of it;
- the predecessor's exact compare-and-release is refused both immediately after
  expiry and again once a successor holds the lease, leaving the successor's
  complete token unchanged;
- the retained epoch, seeded above 2^53 before any claim, is honoured: the
  predecessor claims above the seed and the successor strictly above the
  predecessor. The epoch key carries no TTL, so a reset to one would fail here.

This is relay no-forward and authority evidence. It is not a claim about device
side effects, and it does not establish any HA or automatic-failover behaviour:
the successor is a fresh CLI process started after the predecessor is joined.

### Configured recovery with an unfenced writer

```sh
cargo test -p tunnel-test-harness --locked --test m7_recovery_process -- \
  --ignored --test-threads=1
```

This process-bound gate crosses the executable and socket boundaries: a
configured relay serves an authenticated device, the operator recovery CLI
consumes a signed approval after the measured lifetime-plus-skew quiescence
wait, and a fresh candidate-incarnation relay serves a new device session. A
separate device is revoked before the approval and stays unauthorized
afterwards.

Because an operator's fencing declaration is a claim rather than a proof, the
gate also keeps one writer deliberately unfenced:

- after the operator observes the durable catalog digest, that writer revokes a
  third device through its still-open handle on the old incarnation. The next
  observation must report a different digest, and an approval bound to the
  earlier digest must be refused with the bounded
  `recovery approval does not match the live catalog observation` diagnostic —
  the sole `Display` text for `CatalogDigestMismatch`, so no other refusal can
  satisfy it. The refusal precedes approval-version persistence, so the
  corrected approval reuses that version and changes only the bound digest;
- after the corrected approval activates the candidate incarnation, the same
  still-connected writer attempts an ownership claim. Redis itself must refuse
  it with the typed `active deployment incarnation` conflict. This is stronger
  than the existing fresh-connect refusal, which a process holding an open
  connection would never reach.

The gate returns payload-free evidence and a strict validator re-checks every
flag plus the measured quiescence floor, so neither half can silently regress
to a declaration. Operator fencing remains a prerequisite: nothing here
discovers external writers automatically.

### Fail-closed admission with a request-body sentinel

```sh
cargo run -p tunnel-test-harness --locked -- verify-m7-i04-fail-closed
```

`verify-m7-i04-fail-closed` extends the three-relay admission family with the
negative membership, body-consumption and fallback scopes. Its instrument is a
*request-body sentinel*: an `http_body::Body` that declares a `content-length`
and then delivers a controlled number of bytes. Reading the sentinel's own poll
count is not enough, because the client transport polls a body regardless of
whether the relay reads it; the evidence is the pair
`declared_body_bytes > 0, delivered_body_bytes = 0` together with an exact typed
response that arrives inside a bound far below the relay's ten-second body
deadline.

That inference is only sound with a control, so the gate always runs one first:
the same withheld sentinel against a fully valid target must reach
`408 BODY_TIMEOUT/not_dispatched` after roughly ten seconds. A passing control
proves the body read really is on this route, which is what makes every
zero-delivery rejection falsifiable. Treat a fast control as a gate failure, not
as a faster machine.

The same run records two further non-vacuity controls. A service-type label
against a device with exactly one active service must still return the exact
owner canary, otherwise the ambiguous-label rejection proves only that the label
path is broken. And a successful remote echo through the non-owner ingress must
precede the caller-named-peer-address check, otherwise zero honeypot datagrams
only prove that no peer hop happened at all.

Named scenarios and the rows they inform: absent, unknown-service, inactive,
ambiguous-label and cross-device-destination targets, with the same duplicate
label rejected identically through the stream upgrade and both candidates still
visible in the service listing (`EC-003`, M7-C47); a UDP and TCP
honeypot that consumer headers name but no relay may reach (`EC-017`);
cross-scope rejection before any body read or peer forward, with the owner-side
`lifetime_consumer_chunk_reads` counter at zero (`EC-049`); a zero-byte body that
stays live and is distinct from a failed body stream (`EC-031`); consumed,
body-free and failed-body requests during a real owner process loss, each with a
proven `not_dispatched` outcome and zero cluster-wide dispatch (`FP-04`,
`IN-03`); a SIGKILLed owner connector with at most one committed effect and a
mandatory fresh owner identity (`EC-023`, `EC-048`); and the explicit advertised
route set with every excluded path typed, recorded as the route boundary for the
excluded browser surface (`EC-009`).

Two limits are deliberate. The relay performs **no** automatic reselection on
any method; the former unreachable admission retry budget was removed rather
than wired to a route, and [cluster.md](cluster.md) records that decision. The
gate proves zero reselection (including typed `405 METHOD_NOT_ALLOWED` /
`not_dispatched` for GET, HEAD and OPTIONS shapes at the lost owner's echo
route with zero dispatch) plus one bounded *consumer-driven* safe retry after
the successor owner is committed. The gate also uses the policy
rotation interval rather than the accelerated M2 one, because a three-second
replacement carrier injects unrelated owner-readiness windows into admission
outcomes; owner readiness is instead established by a bounded precondition
helper before each must-succeed probe, never inside a measured window.

### Process bootstrap and capacity fault matrix

```sh
cargo test -p tunnel-test-harness --test m7_deployment_failures --locked \
  -- --ignored --test-threads=1
```

This process matrix drives the built relay executable through every FP-10
bootstrap prerequisite: local peer identity, signed membership, signed
checkpoint authority, Redis authority, peer reachability, and capacity. Each
case must expose `/livez` as live while `/readyz` stays `503 unready`, emit a
bounded typed credential-free diagnostic, and release all three listener ports.
The capacity cases fail during configuration validation, so the executable
never reaches a listener and the matrix requires `initialize` itself to fail
with the exact named bound.

The `unreachable-peer` case is the one fault whose documented outcome is not a
bounded exit. Signed membership names a second relay whose advertised peer
endpoint has no listener, and the relay must stay alive, live and unready while
emitting its typed probe-failure diagnostic. The case then binds a real peer
listener at that exact advertised address, presenting the second relay's own
signed peer certificate and answering the reserved authenticated health route,
and requires the same process (same pid, no restart) to converge to ready
before releasing its ports. Requiring an exit instead would deadlock two relays
booting together, so the matrix asserts convergence rather than failure there.
Loss of an authority *after* a ready start is
`m7_deployment_runtime_faults.rs`.

### Dynamic configured peer-SPKI replacement

```sh
cargo test -p tunnel-test-harness --test m7_deployment_spki_replacement --locked \
  -- --ignored --test-threads=1
```

Two configured relay executables run over separate `rediss://` forwarders and a
live signed checkpoint authority. Relay A is **never restarted** and is the
subject: the signed relay-B record walks old -> old+new -> new while a harness
peer client presents the retired, the replacement and an unapproved certificate
to A's private listener, and an impostor QUIC server presents the retired
certificate at relay B's endpoint after the overlap ends. The gate requires, in
order: the replacement SPKI is refused before any record approves it; both keys
are accepted during the overlap while the established device session keeps its
original generation and a public canary still returns the exact canary plus
payload bytes; A's readiness stays ready for every sample across the overlap;
the retired SPKI is refused once the replacement-only record is adopted, with
A's readiness reflecting that pin transition while relay B is still running; the
relay whose own key was retired surrenders its owner claim and closes its device
session; a public request across the retired route returns
`503 CLUSTER_UNREADY` / `not_dispatched` and the impostor receives a connection
from A but never a request stream; an untrusted signer naming a rogue SPKI
leaves A unready with both the rogue and the replacement certificate refused;
and a trusted record restores the replacement-only key set.

That rogue-signer phase is also **the regression for which unready states may
keep a relay's peer pins** ([cluster.md](cluster.md#implementation-and-acceptance-gates)).
An earlier attempt at the M7-C83 fix retained pins for *every* unready state and
broke this gate: relay A completed mTLS and answered the probe `accepted` where
this phase requires `rejected`, failing with `relay A did not reach the expected
rejected outcome for the relay-b-replacement certificate before the bounded
deadline (last=accepted)`. Rejected trust evidence therefore still withdraws the
pin set, and only a local or transient unready state retains it. Red-then-green
in both directions at the fix revision: with the retention widened back the gate
fails at this phase in 65 s, and with the split in place it passes in 68 s.

The retention split has a second consequence that is **not** yet resolved, and
is why that work is held back as M7-C86: `verify-m7-trust-expiry` regresses on
the branch carrying it (interleaved on one machine with pre-built binaries,
10 of 10 without the retention and 6 of 10 with it)
with `expired target pooled stream was not observed with its exact owner
session/cursor before reclamation`. The stream *is* closed by the expiry in
every run - the owner records `PeerMembershipExpired` and one terminal event
either way - and exactly one of the gate's seventeen joined conditions differs:
the ingress's receive-side outcome, `TrustExpired` when it passes and `Closed`
when it fails. **Why that differs is not established**: three hypotheses were
tested and refuted, including that the ingress reclassifies only once its own
dispatcher has recorded the reason - instrumenting `dispatch_invalidations` on
both revisions produced identical traces in passing and failing runs. What
remains is an unconfirmed ordering hypothesis, recorded on M7-C86.

The retention work that fixes the isolation blackout is **not landed**; it is
held on M7-C86 because it regresses this gate. At `85cdd24` on
`m3c10-gate-only` this gate
is unaffected: interleaved against `origin/main` with both binaries pre-built,
8 of 8 on each arm.

An attribution change keyed on `VerifiedPeerBinding::valid_until` was written
and then reverted: instrumentation showed the trust/checkpoint window, already
carried monotonically, is *earlier*, so that arm could only fire later than the
one that exists. The dispatcher was then instrumented on both revisions and
latches `TrustExpired` identically in every run, passing or failing, so this is
not a missed latch either. Measured interleaved on one machine with both
binaries pre-built, the gate is **10 of 10 at the branch base and 6 of 10 on
the branch**. The remaining difference is an ordering race whose mechanism is
recorded as an unconfirmed hypothesis on M7-C83. Every transition
asserts payload-free, credential-free process diagnostics, and cleanup joins
both relay processes, the impostor, the checkpoint authority, both Redis
forwarders and the catalog namespace. The deterministic statement of the same
replacement rule is `tunnel-cluster`'s
`membership::tests::peer_key_replacement_walks_old_then_overlap_then_new`.

The replacement process is then required to serve, not merely to converge. Once
A is ready again, the gate waits for the replacement's own `/readyz`, attaches a
fresh device session to the device listener that process now owns, reads the
owner claim back from Redis and requires it to name the same node and deployment
incarnation under a **different `boot_id`** from the claim the retired process
held, with a fresh session id and a higher owner epoch, and then drives a public
consumer request into relay A which must return the exact canary and payload
bytes across the replaced peer route. The session must still be the one the
replacement served when it is stopped, and its generation must not have moved
across the canary. Typical evidence is
`replacement_epoch=2 replacement_device_generation=1 replacement_canary_attempts=9`.

Two convergence tolerances are bounded and counted rather than silent. The
device attach is retried inside the transition deadline, because a relay that
is still failing closed refuses it at the upgrade or during the control
handshake. The canary tolerates the typed `503` pre-dispatch boundary
(`CLUSTER_UNREADY` while A's readiness is still converging, `PEER_UNTRUSTED`
while A's peer trust for the replacement is), and at most two `401` outcomes.
The `401` allowance exists because the relay maps a *catalog* failure inside
consumer authentication to `UNAUTHORIZED` rather than to the
`AUTHORIZATION_UNAVAILABLE` boundary that sits beside it in the same function,
so an authority blip during convergence is indistinguishable at the HTTP
boundary from a real rejection; the third `401` fails the gate, so a genuinely
broken authorization can never be waited out. Both counts appear in the
evidence line, and four consecutive local runs recorded `pre_dispatch_401=0`.
Relay A's own signed record is also re-issued at a higher version before the
replacement process boots: every record in this fixture carries a lifetime
shorter than the relay's 60-second bound, and without that refresh the
replacement's peer trust for relay A ages out mid-phase.

One boundary is deliberate and not claimed by this gate: the typed public
outcome across the retired route is the readiness boundary rather than
`PEER_UNTRUSTED`, because the relay withdraws that route from readiness before a
consumer request reaches peer resolution; the pin failure itself is observed on
the authenticated probe path, where A dials the retired certificate, refuses it
and opens no stream. The non-convergence originally recorded here — a relay booting
beside a peer flapping between ready and unready never reaching `/readyz` ready
within 20 s (0 of 123 samples) — was a product defect and has been fixed: probe
admission required the *receiving* relay's readiness-derived route set, which
was cleared whenever that relay's membership readiness dropped, so a peer which
was reachable but momentarily unready refused the probe and the prober observed
`H3_FRAME_UNEXPECTED` ("Stream finished without receiving response headers").
Reachability is now measured independently of the responder's own readiness; see
the readiness paragraph in [cluster.md](cluster.md) and the deterministic
regressions `real_h3_probe_converges_while_peer_cluster_readiness_is_withdrawn`
and `real_h3_probe_converges_across_a_peer_readiness_flap`. With that fix in
place the replacement boot is now asserted through the replacement process
itself as described above, so a device session and consumer request served *by*
the replaced process are covered by this gate.

### Live-catalog Redis process restart

```sh
bash scripts/m7-redis-lane-restart-verify.sh
```

Requires Docker; the script owns one pinned, loopback-only Redis container on a
fixed host port and never touches `TEST_REDIS_URL`. `tunnel-test-harness
redis-lane-restart` connects **one** `RedisCatalog` to that container, seeds its
synthetic fixture through the production `Catalog` contract, serves a read, and
signals the script through a two-word handshake file. The script then restarts
that Redis process on the same port and signals back, so the same live catalog
meets a genuinely new `run_id` on a real socket rather than a fake authority.

The gate requires the primary's `run_id` to differ across the restart, the
catalog to have served a read before it, the first post-restart command to fail
closed without replay, the very next command to be refused with the typed
`CatalogError::Conflict("Redis server run id")`, and every one of the remaining
twelve bounded commands to be refused with that same typed conflict — never a
value, never another typed shape. A catalog connected *after* the restart then
reads the seeded authorization back, so the refusal is specific to the identity
the first catalog verified rather than a client that stopped working. Evidence
is one payload-free line naming both run identifiers and the per-command outcome
sequence. This is the process-level counterpart to `redis_lane_reconnect`, which
severs the socket without changing the primary.

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
| Forwarded admission | Reject forged source identity, destination owner, tenant/grant, internal headers, credential context and hop budget. The owner independently verifies consumer grants and ticket/device context. The relay performs no automatic route-admission retry; prove zero reselection on every method and that only a consumer-driven retry of a proven `NOT_DISPATCHED` request bridges an owner change. Lost/partial acknowledgments preserve uncertainty and never repeat effects. |
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

Listener connection permits need real-socket evidence, not a counter assertion. Fill every one of the 64 permits with connections that complete an actual TLS 1.3 handshake and then send no application byte, and prove that a further connection is refused while they are held, that each silent connection is closed within the configured pre-request bound, that the permit count returns to full, and that a further connection is then served. Separately prove the bound cannot kill an established connection: an in-flight request lasting several times the bound must still complete, and a keep-alive connection that already dispatched a request must still serve a second request after the bound elapsed. `crates/tunnel-transport/tests/m7_listener_permits.rs` holds these regressions.

Assert maximum frame size, maximum operation size, per-stream and per-connection queue limits, in-flight operation limits, and per-user/device quotas. Test admission at the limit and one unit over it, cancellation of a blocked writer, disk-full errors, exhausted file handles, and memory-pressure behavior. Verify that heartbeat, cancellation, revocation, and rotation control messages remain responsive while the data path is saturated.

An in-flight operation limit that is only relay-global is not a tenant-isolation test. A capacity regression must prove that one tenant saturating its own allowance still leaves another tenant's public request admitted, that the relay-global bound independently refuses a tenant whose own scope is empty, and that every permit returns exactly once when a request is abandoned or an upgrade is cancelled. `crates/tunnel-relay/src/http/tenant_admission_tests.rs` runs two fully independent tenants through the real consumer route on a loopback listener for those invariants; a double release is detected by the released capacity readmitting more streams than the bound allows, not by inspecting a counter alone.

Measure peak resident memory, queue high-water marks, end-to-end latency, fairness, and bytes transferred. A successful checksum proves content integrity; a successful return code alone does not. Use a streaming generator and sink so the harness does not conceal relay buffering by preloading entire files into memory.

### Physical versus logical queue occupancy

A session's logical admission count (`queue_messages`, which is pending
operations plus streams) is not occupancy and must never be reported as
saturation evidence. The relay publishes the physical counters a gate needs:
`data_queue_depth`/`data_queue_capacity` and
`control_queue_depth`/`control_queue_capacity` are live item counts taken from
the bounded channels themselves, `*_depth_high_water` and
`queue_bytes_high_water` are saturating latches that a bounded observation
window cannot miss, `queue_bytes_limit` exposes the configured budget beside its
use, and `control_queue_refusals`/`data_queue_refusals` plus
`control_queue_enqueued`/`data_queue_enqueued` separate "never refused" from
"actually still flowing". All are payload-free.

`verify-m7-queue-saturation` is the configured-bound gate built on them. It runs
through a non-owner ingress, admits the full `max_streams_per_device` cap and
proves the next admission is refused, blackholes the exact correlated data
carrier, and then requires physical residency, retained reserved control and
data capacity with a byte headroom floor, an advancing accepted-control-enqueue
count during the blackhole, a real cancellation with an immutable first-terminal
observation, bounded physical drain, and three same-owner rotations beginning
with the one that replaces exactly the paused carrier. Across those rotations it
requires generations to advance by one and never rewind, the socket bound to
hold, and each attempt to keep one absolute deadline: the same start and the same
deadline across at least two observations of that attempt, and within the
configured overlap of that attempt's own start.

Two limits are deliberately **not** in this gate, with reasons recorded so the
omission is not mistaken for coverage. Public body and length-prefix limits stay
with M7-C24 and EC-007: while building this gate, a record whose length prefix
declares one byte above `max_body_bytes` was observed not to fail closed on the
**remote** consumer ingress. `handle_consumer_stream` breaks the connection on
`declared > MAX_BODY_BYTES`, but the peer path in `handle_remote_consumer_stream`
treats the same condition as an incomplete record and waits for more bytes, so an
over-limit prefix stalls instead of being refused. A maximum-size body on that
route also failed to complete in this fixture while the established production
gate's maximum-body probe passes, so the difference needs its own diagnosis
rather than an assertion bolted onto a saturation gate. Late, reordered and
duplicate frames, GOAWAY, and active privileged-adapter traffic across rotations
remain with their own tasks; echo rotation here is supporting evidence only.

Two bounds make the nominal 128-entry data channel unreachable from the public
echo route, and the gate asserts that rather than hiding it. The consumer
ingress admits one in-flight record per stream, and
`max_queue_messages = 2 * max_streams_per_device`, so residency is capped at 64
entries for every admissible body size; a maximum 64 KiB record additionally
spans two frames charging 131,208 bytes, so only 31 such records fit the 4 MiB
budget (62 entries). Separately, the frames the kernel socket buffers absorb
before the writer blocks are no longer charged, so the gate derives the absorbed
count from the relay's own accepted-enqueue counter rather than assuming a
buffer size. A workload that cannot fill the channel must say so with numbers;
it must not be relabelled as success against a logical count.

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

#### The table, as satisfied (2026-09-17, task row M4-14)

Four adapters exist, as export subpaths of `packages/client`. Two commands carry
the evidence and they are separate on purpose:

```sh
cd packages/client && npm ci && npm run typecheck   # contract compilation
cd packages/client && npm run test:peers            # registration and behaviour
```

**Compilation** is `npm run typecheck`. Each adapter's *source* imports the
upstream declarations — `import type { Adapter, … } from 'files-sdk'`,
`from '@mastra/core/workspace'`, `from 'just-bash'`, `from '@ai-sdk/provider'` —
and is annotated with the upstream interface (`implements WorkspaceFilesystem`,
`implements IFileSystem`, `const adapter: FilesAdapter`, `const api:
TunnelFilesApi`), so `tsc` checks the implementations against the installed
`.d.ts` under the lockfile. There is no `any`, no assertion onto an upstream
type and no `@ts-expect-error` anywhere in `src/adapters/`. Those imports are
**type-only**, so they erase at run time and the package keeps zero runtime
dependencies; the four packages are exact-pinned dev and peer dependencies, and
`npm test` is still green with `node_modules` deleted.

`test/peers/contract.peers.ts` additionally asserts the installed versions are
the pinned ones and that the upstream `FilesError` class and the
`@mastra/core/workspace` error namespace are assignable to the option types the
adapters ask consumers for — so an upstream signature change is a type error
here rather than a surprise at a consumer's call site.

| Row | What was run | Result |
| --- | --- | --- |
| Files SDK | `new Files({ adapter: createFilesAdapter({ remote, FilesError }) })`, then `head`, `exists`, `download`, `upload`, `copy`, `move`, `delete`, `list` through the wrapper; `files.capabilities` read back; `url`/`signedUploadUrl` permanent errors; a conditional upload refused before any socket traffic. | Pass. `capabilities` reports `rangeRead` and `delimiter` true, `metadata`, `cacheControl`, `serverSideCopy` and `multipart` false, `signedUrl: { supported: false }`, and every conditional primitive false. |
| Files SDK retries | `new Files({ adapter, retries: 5 })` with a dispatched `Twrite` that never answers, then a 1011 close. | Pass, and this is the row that matters: **one `Twrite` on the wire, not six.** The error is a real `FilesError`, `Provider`, `permanent: true`, `applied: false`, with the client's `FilesystemError` and its `outcome: 'unknown'` as `cause`. |
| Mastra | `new Workspace({ filesystem: new TunnelMastraFilesystem({ remote, errors }) })`, `workspace.init()`, then `readFile`, `writeFile`, `exists`, `stat`, `readdir` through `workspace.filesystem`, then `workspace.destroy()`. | Pass. `workspace.sandbox` is `undefined`: filesystem access implies no host command-execution sandbox. `destroy()` leaves the borrowed client `ready`. |
| Mastra errors | The real `FileNotFoundError`, `FileExistsError` and `StaleFileError` raised through the adapter. | Pass, by `instanceof` against the installed classes. |
| just-bash | `new Bash({ fs: new TunnelJustBashFilesystem({ remote }), cwd: '/', defenseInDepth: { excludeViolationTypes: ['setTimeout'] } })`, then `cat`, `ls`, a `wc -l` pipeline, `echo > file`, `cp && mv && ls`, `find -name`, and a 256-byte binary round trip through `wc -c`. Network, Python and JavaScript execution all off. | Pass. **The `setTimeout` exclusion is required**: just-bash 3.4.2 blocks the global for the duration of a script and the shared client arms a timer for every request deadline, so without it the first `cat` fails before a byte reaches the socket. One exclusion is enough. |
| just-bash failures | Shell `>>`, and a dispatched write that never answers. | Pass. **Both reject out of `exec`** rather than becoming an exit status — a redirect-target failure is not turned into a shell status in just-bash 3.4.2 — so `>>` leaves the file untouched, and the interrupted write gives a wrapper reading `ExecResult` nothing at all, not even a nonzero status. `drainOperationFailures()` holds one record with `outcome: 'unknown'`, which is the only place the outcome exists. |
| AI SDK FilesV4 | `ai.uploadFile({ api, … })` with a counting wrapper; then `getFileMetadata`, `downloadFile` and `deleteFile` invoked on the instance itself. | Pass. **One provider call**, matching the inspected helper: it calls once and rethrows, with no `maxRetries` to disable. An ambiguous upload rethrows with `outcome: 'unknown'`, mints no reference, sends one `Twrite`, and leaves its path in `incompleteUploads()`. |
| AI SDK live tools | — | **Not satisfied.** No tool factories are implemented: no native filesystem `tool()` definitions, no filtered `files-sdk/ai-sdk` factories, no `bash-tool` wrapper. Input schemas, abort propagation, bounded output and model-visible outcome fields are all untested. This row remains open. |

**What none of this establishes.** Every socket is the loopback harness in
`packages/client/test/harness/`. It is not `crates/tunnel-relay` and not
`crates/tunnel-fs-provider`; there is no TLS, no tunnel, no grant, no
confinement and no filesystem behind it. This document's own rule applies
without qualification, so no row above is evidence of endpoint interoperability
or authorization. The read-only-mount and writable-profile pairing below is
run for all four: `createFilesApi` refuses construction over a read-only export,
and the Files SDK, Mastra and just-bash adapters each refuse their whole write
surface — `upload`/`delete`/`copy`/`move`, `writeFile`/`appendFile`/`deleteFile`/
`copyFile`/`moveFile`/`mkdir`/`rmdir`, and `writeFile`/`appendFile`/`rm`/`mkdir`/
`cp`/`mv`/`chmod`/`utimes` — with **no mutating opcode reaching the socket**,
while reads keep working. What that does *not* establish: a real read-only
**grant**, enforced by a device. These refusals are the client's, taken from a
descriptor it was handed, and the descriptor "is informative, never an
authorization credential".

Run each supported adapter against a read-only mount and the documented writable profile. Where a framework expects an operation the endpoint cannot provide, prove the published adapter behavior: reject construction if that capability is mandatory, or expose an explicit unsupported-operation error if the framework permits it. An absent capability must never become fabricated metadata, a silently ignored option, or a successful no-op. Compile-time interface coverage and runtime capability coverage are separate results.

### Discovery, authentication, and session admission

Exercise authenticated `GET /v1/devices/{device}/services/{service}/fs` without Upgrade for the JSON descriptor, then upgrade that same endpoint to WebSocket. Check schema `agent-tunnel.fs.v1`, subprotocol `agent-tunnel.9p.v1`, dialect `9P2000.L`, online/offline availability, opaque grant revision, effective operation capabilities, extensions, and limits. Reject malformed descriptors, unsupported versions/dialects, inconsistent limits, and untrusted endpoint origins before opening a usable session. Descriptors must not contain host paths, secret credentials, or information about unauthorized mounts.

Generate static descriptor fixtures and Rust/TypeScript contract checks from the checked-in API schema when implemented. Exercise each limit exactly at and one unit beyond its advertised value, and a smaller configured value; verify the server, shared client, and native adapters agree. Cover the initial 65,536-byte `msize`, 64 in-flight requests, 256 fids, 16 MiB buffered-file bound, 1 MiB queue bound, 10,000 traversal entries, depth 64, 30-second request timeout, and 300-second idle-session timeout as defined in the API plan. Use paused clocks for deadline boundaries and real sockets for enforcement. A large streamed file must not bypass per-frame/queue bounds or be confused with a whole-file buffered read.

Instrument the 32 MiB concurrent internal materialization reservation separately from caller memory. Concurrent reads, conversions and adapter-retained cache copies share that budget; enforce the limit before allocating and release reservations on success, failure, cancellation and transfer of result ownership. Sequential completed reads must reuse the quota even if the caller retains ordinary returned values. Returned Uint8Array/Buffer/string values are outside this internal bound, while any retained adapter copy stays charged; no test may claim the client controls application result-history memory. Check conversion-copy peaks and growth beyond a prior stat, not only final output length.

Repeat the authorization matrix for descriptor retrieval, WebSocket upgrade, 9P attach, operation admission, and open-fid use. Change grants, mount availability, and policy between discovery and upgrade and between upgrade and attach: a cached descriptor must not authorize access or restore removed rights. A stale `X-Agent-Tunnel-Grant-Revision` returns 409 `CAPABILITIES_CHANGED` before admission; changed session capabilities close the session instead of silently broadening it. Revoke a writable grant while writes are queued and report any already-started mutation accurately. Changing permissions or reconnecting must not reuse a previous caller's capability cache, fids, or authorization context.

Node is the initial adapter runtime; verify its supported credential transport, TLS validation, cleanup, deadlines, and cancellation. Browser support gets separate Origin, CORS, credential-transport, and buffering tests before it is advertised. Credentials cannot appear in URL queries, exception messages, or snapshots. If short-lived attachment tickets are introduced, test expiry, intended audience, single-use/binding rules, and concurrent redemption independently of the long-lived device data-ticket tests.

### Implementation gate 4: the endpoint, the upgrade and the read path

The gate is `verify-m4-fs-real-path`, registered in
[`scripts/m4-harness-verify.sh`](../scripts/m4-harness-verify.sh) and
implemented in
`crates/tunnel-test-harness/src/production_cluster/fs_real_path.rs`. It runs on
the real three-relay production cluster against the authoritative Redis catalog,
a real device connector and real sockets. Its evidence struct is payload-free,
its validator is one array of named rules, and a single-mutation unit test
requires every one of those rules to notice a field weakened on its own.

**What the gate must observe, and where each rule comes from.** The
authorization matrix of
[filesystem-api.md](filesystem-api.md#confinement-and-capability-model) is
proven by seeding six filesystem exports side by side on one device — a
`read`+`list` grant, a `list`-only grant, a `read`-only grant, a grant revoked
under a live session, a grant naming only the session scope, and an export
whose host declares filesystem exports unsupported — so a session's answer
cannot be credited to a different export's configuration. Against them: the descriptor from the grant; `403 ACCESS_DENIED`
for the empty grant and for the unsupported host; `401` with no token, `404` for
an unknown device, `405` for a method this URL does not serve, `409
CAPABILITIES_CHANGED` for a stale `X-Agent-Tunnel-Grant-Revision`, and `426`
for an upgrade offering no `agent-tunnel.9p.v1`; the upgrade itself with the
subprotocol selected and `9P2000.L` negotiated; a forged `Tattach` that cannot
be admitted; a checksummed read of a file large enough to span many messages; a
`Treaddir` paged by opaque cookie; the `list`-without-`read` and
`read`-without-`list` cases; a flushed request whose late reply is dropped
without closing the session; a fid number re-bound while a descriptor for its
previous binding is held; every mutating opcode refused with the export
unchanged; and a non-owner relay refusing the upgrade.

**A cached descriptor never authorizes access.** A stale header value proves
only that the relay compares numbers, so the gate also moves a grant for real.
It reads the descriptor, advances that grant's revision in the authoritative
catalog with `upsert_grant` naming the same operations — so only the revision
moves — and polls a fresh descriptor under a bounded deadline until it reports
a different `grantRevision`. The revision a consumer would have cached is then
refused `409 CAPABILITIES_CHANGED` at the descriptor *and* at the WSS upgrade,
while the current revision is still admitted through to an attached root.
Separately, on an export nothing else in the run touches, a grant is revoked
with a 9P session live on it after that session has read a file: the consumer
then only reads its socket, and observes the session closed with **1008** with
no further 9P reply. Both changes are made through the same production catalog
the relays read, not through a harness shortcut.

**A descriptor must carry no host detail.** The gate scans the raw response body
for the export root's own host path and for owner identity fields, rather than
asserting only on the parsed fields it expects: an assertion that checks what is
present cannot notice what else came with it.

**The bounds that are structural and the bounds that are not.** Gate 4 enforces
`msize` on every frame, the tag and fid quotas, the carrier's credit and replay
limits, the traversal-entry budget on a `Treaddir` resume, and the consumer
token's expiry. It enforces **no clock**: the 30-second request deadline, the
composite operation deadlines, the 300-second idle-session timeout and the
queued- and buffered-byte budgets of
[filesystem-api.md](filesystem-api.md#initial-enforced-limits) are not
implemented, so no gate may report them as covered. Exercising each limit
exactly at and one unit beyond its advertised value, with paused clocks for the
deadline boundaries, remains required and remains unmet for the clock half.

**Red-then-green.** The guards gate 4 adds are measured by deleting them one at
a time with [`scripts/fs-guard-deletion.py`](../scripts/fs-guard-deletion.py)
`--suite gate4`, which restores the crate by checkout between cases, refuses to
run against a dirty working tree, refuses to call a failed build a red test, and
refuses a case whose text is not unique in its file. A guard whose deletion
leaves every test green is **printed as such** rather than counted among the
load-bearing ones; several of gate 4's mask one another and are red only in
combination, and the honest form of that claim is the combination, not the
single.

**What this gate does not prove, and must not be read as proving.** A filesystem
session across the relay-to-relay peer hop, because gate 4 admits one only at
the owning relay. Anything across a scheduled data-socket rotation, a consumer
loss or a control-epoch change. Any write, and therefore any partial or unknown
mutation outcome. Any adapter, any TypeScript client, and any second
implementation reading gate 3's golden fixtures.

### Implementation gate 5: write grants and partial failure

The gate is `verify-m4-fs-write-path`, registered in
[`scripts/m4-harness-verify.sh`](../scripts/m4-harness-verify.sh) beside gate 4's
and implemented in
`crates/tunnel-test-harness/src/production_cluster/fs_write_path.rs`. It runs on
the same real three-relay production cluster, the same authoritative Redis
catalog, the same device connector and the same consumer WSS sockets, and it
speaks the wire with the same 9P client — which moved up a level so that one
copy of it serves both gates rather than two that could drift apart.

It is a **sibling** of the gate-4 gate rather than an extension of it. The two
prove different things and share one device: gate 4's exports are read-only and
gate 5 seeds two writable ones beside them, so a refusal in one can never be
credited to the other's configuration. The device's own `[exports.<service>.fs]`
allowlist is the **same and the widest** for every export gate 5 configures,
which is deliberate: the narrowing the read-only case turns on is the relay's
OPEN, derived from the grant, and a difference configured on the device would
let a refusal be credited to the connector's allowlist instead.

**What one run proves, in the order it takes it.** Every byte of fixture content
is synthetic and generated in the gate; no evidence field, log line or error
message can carry a path, a name or file content, because the evidence struct
holds scalars, closed labels and identifier-free strings only.

* **The descriptor a write grant produces.** `root.readOnly` is *derived* from
  the grant by gate 1, so a writable export reporting it false — with nothing
  having configured the flag — is what makes the advertised flag and the
  enforced grant provably the same thing. Gate 4's export reports it true in the
  same run.
* **A checksummed write spanning many messages.** A 393,216-byte synthetic file
  is created with `Tlcreate` and written across more than four maximum-size
  `Twrite` messages, then read back **on a fresh fid** — so the bytes come from
  a descriptor the session resolved again rather than from the one that wrote
  them — and compared on the host at exactly the length that was sent. A
  replayed chunk changes the length, the checksum, or both.
* **Every name-changing primitive, observed on the host.** `Tlcreate`,
  `Tmkdir`, `Trenameat`, `Tunlinkat` without `AT_REMOVEDIR` and with it. The
  directory is emptied first, which is the profile's own non-recursive default.
* **A truncating open and a size-changing `Tsetattr`.** The truncation happens
  through the descriptor after the hard-link rule has permitted it; the
  resolving open carries no `O_TRUNC`, which is gate 2's pinned choice and is
  what keeps a refused write from following a truncation that already happened.
* **The hard-link write refusal, on a genuinely multiply-linked file.** The
  second link is made **out of band**, because the profile refuses to create one
  without the `hardLinks` feature and a fixture built through the wire would be
  proving something else. The run records the observed `st_nlink` as well as the
  four refusals, so the rest of the case cannot be credited to a write simply
  being denied. A write open, a read-write open, a truncating open and a
  size-changing `Tsetattr` are each `EPERM`; the content is verified **intact**;
  and an ordinary read of the same file is still served, because the link count
  discloses nothing the grant does not already permit.
* **A read-only grant refusing every mutating primitive before dispatch.** All
  eleven of them — the two mutating `Tlopen` flag shapes on an ordinary
  unopened file, `Tlcreate`, `Twrite`, `Tmkdir`, `Tunlinkat`, `Trenameat`,
  `Tsetattr`, `Tsymlink`, `Tlink` and `Tremove` — on its own export, with the
  export byte-for-byte unchanged afterwards and every name the mutations would
  have created checked absent. The validator requires each errno to be one of
  the three a **pre-dispatch** refusal can carry: `EPERM` from gate 1's
  capability table, `EINVAL` from gate 3's session for a fid used in a way its
  state forbids, and `ENOTSUP` from gate 3's flag decoding. `EACCES` can only be
  the host's answer, so a refusal carrying it would mean a mutation was
  dispatched under a read-only grant, and a single-mutation case covers exactly
  that. The two flag shapes are additionally required to be `EPERM`
  specifically: the contract denies every mutating **flag**, and a refusal taken
  for the node's kind would have happened under a write grant too.
* **A write interrupted mid-stream.** The consumer pipelines twenty-four
  full-`msize` writes back to back, reads only the first four replies, and then
  **abandons the transport** — no close frame, no drain. Some of the remaining
  writes will have been performed and some will not, and the consumer can never
  learn which: that is the contract's `unknown`, and the only honest thing to
  assert is what must be true either way. Every **acknowledged** byte is on the
  host and correct, which is `bytesAcknowledged` as a lower bound confirmed by
  replies; the whole file is a **prefix of the source**, so nothing landed at
  the wrong offset or out of order; and the host holds no more than was sent.
  Observed landing points have ranged across runs from six blocks to
  twenty-two, which is the case being genuinely partial rather than arranged.

  **Non-replay is claimed structurally here, not measured, and the distinction
  matters.** A `Twrite` is positioned, so a block re-applied at its own offset
  is byte-identical and leaves the file a perfect prefix either way — no
  comparison of the result can tell a replay from its absence. What the prefix
  check does catch is a block applied at the **wrong** offset, which is a
  different defect. The non-replay claim rests on the gate re-sending nothing
  after the interruption and on `Provider::step` popping each queued entry
  exactly once. The device-side counter that would measure it,
  `mutations_applied`, is now published in the connector's status snapshot, but
  a *consumer* cannot read it — there is no wire field for an outcome — and
  correlating it across a session this gate deliberately abandoned is not
  something the gate attempts.
* **A host failure surfacing the right errno without a name.** A directory the
  export may traverse and may not write to — mode `0o500` — answers `EACCES` to
  a create inside it. The rendering of what came back is scanned for the refused
  name, the directory's name and the export's host path, and the session is
  required to survive and answer afterwards, which is gate 3's three-way split
  of refusals: an `Rlerror` a correct client can recover from keeps the session.

**Waiting for the host to settle is polled, never slept.** The interrupted case
reads the file until its length stops changing and stops the moment it is
stable, bounded at twenty seconds. A fixed sleep would be either flaky or a
correctness signal, and this is neither: a slow run still passes, and a run
where the device kept writing after its consumer vanished fails by the length
check rather than by a wait that was too short.

**What the gate cannot see, and says so.** There is no wire field for an
outcome, so a consumer cannot read the device's own ledger. The ledger is
asserted directly in `crates/tunnel-fs-provider/tests/mutations.rs`, where
driving `accept` and `step` by hand lets a test perform a mutation and decline
to confirm delivery — the shape a dropped consumer has — and it is **published**
on the device in `ConnectionStatus::fs`, so an operator can read what a consumer
cannot. Classifying an in-flight mutation from a client's own dispatch and reply
history is the shared client's job and is gate 6's.

**Red-then-green.** Nineteen cases in a `gate5` suite of
[`scripts/fs-guard-deletion.py`](../scripts/fs-guard-deletion.py), spanning the
resolver's write module and the dispatcher; **nineteen of nineteen turn a test
red**. The suite runs with `--no-fail-fast`, which is not a detail: `cargo test
-p a -p b` otherwise stops at the first failing binary, so a deletion that
breaks tests in both crates was reported against only one of them and the
attribution in an earlier round was wrong.

One case reaches two pinned claims and both are now reported. Deleting the
hard-link check makes a multiply-linked file writable *and* lets a truncating
open truncate it, and that content-intact assertion is the only form in which
"truncation happens through the descriptor after the rule permitted it" is
measurable by deletion — the alternative ordering is a different implementation,
not a deletion. **The truncating case lives in its own test for exactly that
reason:** it was once the last iteration of a refusal loop, where the first
iteration's panic meant it was never reached and the red belonged to a different
assertion entirely.

Two cases need the `post-effect-hook` feature, which no shipped build enables
and which follows gate 2's `race-window-hook` precedent: the window between a
creating syscall and the identity read that gives its reply a qid is
microseconds wide, so a test steps into it deliberately rather than racing for
it. Without that hook the rule it protects — after the effect, a failure is
`unknown` and never `not_started` — could only be asserted.

The connector's settling of the mutation ledger has **no unit test** and is
deliberately absent from the suite rather than listed there with a green it did
not earn; it is exercised only through the harness gate.

### Implementation gate 6: the shared client, and the fuzzing both codecs share

The client is `packages/client`. One command runs everything, offline, with
`node_modules` deleted:

```sh
cd packages/client && npm test
```

Type checking is separate and is the only thing that needs an install
(`npm ci && npm run typecheck`), which keeps the suite runnable with nothing
fetched. There are still **zero runtime dependencies**; RFC 6455's client half
is written out in `src/websocket.ts` rather than depended on, because the
contract needs `Authorization` on the upgrade and neither Node's global
`WebSocket` nor a dependency-free package can otherwise send one.

**The shared fuzzing this document asks for.** "Fuzz the incremental Rust and
TypeScript codecs with the same corpus and compare accepted values and rejection
behavior" is not what gate 3's 43 golden fixtures did: nothing was generated,
and neither codec was ever run against input the other had judged.
`packages/client/fuzz/` generates the corpus in **one** place — 4,096 cases,
deterministic from a seed the corpus file records — and both implementations
produce a verdict on every one:

* The generator knows the wire **shape** of all 41 message types and draws each
  field from a pool of boundary values, so the cases land inside fields rather
  than spending themselves on the truncation and unknown-opcode paths a
  byte-flipper reaches. It then mutates a share of what it built, mixes in pure
  noise, packs two frames into one binary message, and chunks streams.
* Nothing in the generator imports either codec, so a rule one of them gets
  wrong cannot also be wrong in the generator and cancel out.
* The canonical form a verdict is compared in is written out **twice**, once per
  side. A shared renderer would be a third implementation both sides trusted,
  and a field either codec dropped would be dropped from the comparison with it.
* `crates/tunnel-fs-ninep/tests/shared_fuzz.rs` is the Rust half. It runs in the
  ordinary workspace suite, compares against its checked-in verdicts and
  **refuses to rewrite them** — the same rule the golden fixtures follow, so an
  ordinary run cannot overwrite the evidence it checks. Rewriting after a
  deliberate change is `AGENT_TUNNEL_FUZZ_WRITE=1 cargo test -p tunnel-fs-ninep
  --test shared_fuzz`.
* `npm test` regenerates the corpus from the seed and asserts it is exactly what
  the committed file holds, so a corpus trimmed by hand to the cases that agree
  fails rather than quietly narrowing the cross-check. A failing case is
  reproducible from the seed alone.

The rule is **accept and agree, or both refuse**, compared over a shared refusal
vocabulary rather than over "it threw". Four disagreements were found, all in the
TypeScript and all fixed; the Rust codec was right in every one. They are
recorded with their reasoning in
[filesystem-api.md](filesystem-api.md#pinned-in-code-gate-3)'s gate-3 residue,
which that fuzzing closes. The two verdict files are byte-identical.

The corpus weights `NOTAG` for the two version opcodes and draws `Rlerror` from
an errno pool, because a uniform tag pool spent almost every version frame on
the one refusal that guards it: 41 of 41 message types are now decoded, where
`Tversion` was reached once and `Rlerror` three times in 4,096 cases. Nothing new
surfaced, and **that is a weaker result than it may look**: both codecs decode an
`Rversion`'s `msize` without judging it, so agreement shows the rule is in
neither codec rather than that it belongs in a session — and the Rust side has no
consumer-side `Rversion` rule to compare against at all, being the server end.
The differences that remain between the two implementations are session-layer
rules a corpus of frames does not reach.

**What the client's own suite covers.** The namespace, with every refused class
refused by its own rule and the checking **order** that decides which rule a path
violating several of them reports. The descriptor: the schema's rules, the HTTP
failure vocabulary of
[filesystem-api.md](filesystem-api.md#http-failures-before-upgrade) at every
status it tabulates, and the refusals that must happen before a session opens.
The upgrade: the grant-revision header, the selected subprotocol, the accept
hash, and an extension nothing offered. The session: one `Tversion` on `NOTAG`
and one `Tattach`, a reply for a tag nothing waits on, a reply of the wrong type,
an `Rread` longer than its `Tread`, a text frame, two 9P messages in one binary
message, valid WebSocket fragmentation reassembled, the tag and fid quotas, and
`Tflush` — including an original reply that beat its `Rflush` and is honoured.
The bytes: a file spanning many messages at `msize` 256, a write spanning many,
a short write whose remainder goes as a fresh write rather than a replay, copy,
stat, directory enumeration, create, rename and recursive removal. The limits:
the materialization ceiling enforced against the running total while reading,
its release on ownership transfer, and `msize` negotiation reducing.

**The outcome classification, which is the obligation gate 5 named for this
side.** There is no wire field for an outcome, so the client derives one from its
own dispatch and reply history. It is tested as a pure function and over a real
socket that goes away mid-write: a dispatched mutation with no reply is
`unknown` at **every** close code the contract pins, an error carrying `partial`
or `unknown` is never retryable, and a truncating open that fails afterwards is
never reported `not_started`. What makes that last floor correct is asserted as a
fact about the **client** — the open it sent carried `O_TRUNC`, so it asked for
an effect — and not by checking that the harness then truncated, which would be
asserting the harness's own handler. For the same reason the interrupted write
uses content whose bytes all differ: an all-zero source makes the "landed at the
right offset" comparison true by construction.

A composite that made something and then failed is covered on its own, because
it is the client's version of the defect gate 5 removed on the device side: a
`copy` whose source turns out to be absent has already created its destination,
and a caller told `not_started` would believe the export untouched. The same
floor is exercised for a recursive `mkdir` interrupted after one `Rmkdir` and a
recursive `remove` that unlinked a child before failing, and in the other
direction for the traversal budget, which fires during a post-order descent and
must therefore report `not_started` with zero `Tunlinkat` on the wire.

Two of those cases are about the **type** of the failure rather than its floor,
and they are the ones an outcome can escape through: a directory entry the device
listed but this namespace refuses — an ordinary host file called `bad.` — and an
exception from the caller's own chunk source, which `writeStream` iterates inside
the composite. Both are `PathRefusal` or a plain `Error`, neither carries an
`outcome`, and both are reachable **after** the composite has applied something.
Each is asserted to arrive as a `FilesystemError` carrying the floor with the
original as `cause`, and — when nothing has applied — to be passed through
unchanged.

**What this suite does not prove, and must not be read as proving.** Every socket
in it is a loopback socket to a harness in `packages/client/test/harness/`. That
harness is real in the ways that matter for the transport — a real TCP
connection, a real HTTP request, a real RFC 6455 handshake, real frames — and its
**WebSocket** framing is written separately from the client's, so the two halves
of that layer are independent. Its **9P** layer is not: the harness encodes and
decodes with the client's own codec, so nothing it asserts is a second opinion
about 9P bytes. The second opinion about those is the shared corpus above, where
the other implementation is the Rust one. And the harness is **not a relay and
not a device**. There is no TLS, no tunnel, no logical stream,
no grant, no confinement, no provider and no filesystem behind it; its 9P replies
are whatever a test says they are. This document's own rule applies without
qualification: "constructing a compatible-looking object or passing an in-process
mock proves neither endpoint interoperability nor authorization", and nothing
here is evidence about `crates/tunnel-relay` or `crates/tunnel-fs-provider`.
Rotation, revocation under a live session, the cross-relay
hop, and every clock the device does not enforce remain exactly as gates 4 and 5
left them.

### Implementation gate 6: the four native adapters

Added 2026-09-17 (task row M4-14). The adapters are export subpaths of the same
package, so they run under the same one command:

```sh
cd packages/client && npm test
```

**525 tests, 525 pass, 0 fail**, offline with `node_modules` deleted — 105 of
them the adapter suites. The contract-compilation evidence, which needs an install, is
tabulated under [Contract compilation and capability
profiles](#the-table-as-satisfied-2026-09-17-task-row-m4-14) above; this section
is the behaviour.

**Why the offline suites use stand-in framework classes, and why that is not the
substitution this document forbids.** `npm test` runs with `node_modules`
deleted, so it cannot load `files-sdk` or `@mastra/core`. The two adapters that
need a *runtime* class — Files SDK's `FilesError`, Mastra's nine error classes —
take them as constructor options, and the offline suites pass local classes with
the same constructor shapes and assert exactly which arguments the adapter chose.
The interface those stand-ins stand in for is checked by `tsc` against the
installed declarations, and the real classes are used in `test/peers/`. The
Files SDK suite also carries upstream's own retry predicate copied verbatim from
`internal/retry.ts` as a test **oracle**, so a suite that cannot load the package
can still ask the question the package asks; the real `Files` wrapper with
`retries: 5` counts dispatches in the peers suite.

**What the suites cover.** The object-key namespace, refused by gate 1's rules
under gate 1's names, with the two key-shaped refusals — absolute and
trailing-separator — under their own; a percent sign kept literal rather than
decoded into traversal. The advertised capability surface, each flag checked
against the method that would honour it: a non-`/` delimiter refused because
`supportsDelimiter` means upstream will not gate it, user metadata and
cache-control refused rather than dropped, `url` and `signedUploadUrl` permanent.
Inclusive byte ranges, which are not `slice`'s. `exists` false only for a
confirmed absence, in all four views. A directory refused by an object `delete`
rather than reported absent. A native rename with no `Tunlinkat` on the wire.
Bounded, single-use, query-bound pagination cursors, and a traversal budget that
fails rather than returning a short complete page. Mastra's eleven operations,
both timestamp policies — including a matching stat, a real `StaleFileError` on
a mismatch, a missing file proceeding as the pinned `LocalFilesystem` does, and
an unrelated stat failure preserved — and the `createdAt` fallback declared in
`getInfo().metadata`. just-bash's synchronous members asserted to send nothing,
its lexical `..` clamp, and `drainOperationFailures()` with its bound and its
counted overflow. FilesV4 uploads from bytes, text, strictly decoded base64 and a
stream; the reference bound refused before a file is created and with nothing
evicted; foreign provider keys, unknown ids, closed-adapter ids and nonempty
header overrides all refused; a reference proven to be an alias for a path by
having another writer replace what it resolves to.

**The composites the adapters own, which are not the client's.** `upload`,
`copy` and `move` create the key's parent directories first, and so do Mastra's
`writeFile` and `copyFile` — so each is a composite **at the adapter layer**, and
a directory made there followed by a failure is the same class of defect the
shared client spent three rounds removing from `writeInto`, `mkdir` and `remove`.
`RemoteFilesystem.mkdir` now returns how many directories it created, which is
what decides the floor: a chain that found every component present sets none, and
a chain that made one puts the failure at `partial` however the failing step
describes itself. Five sites are covered, each measured by deleting its floor and
requiring the case to fail: a Files SDK `move` onto a made parent, an `upload` and
a `copy` whose `Tlcreate` is refused, and the two Mastra ones — where the
assertion is also that the result is **not** `PermissionError`, which a tool
reads as "nothing happened". A sixth case is the inverse: an `upload` whose write
is **confirmed** and whose trailing courtesy `stat` then fails must still
succeed, without `lastModified`, because reporting a completed write as a failure
that never started is worse than losing an optional field.

**A page the adapter can actually produce.** Each listed key is a `stat`, and the
session refuses a request past `maxInflightRequests` locally — the profile pins
that at 64. A page fanned out at once therefore could not be produced at all for
a directory with more keys than the quota, which made `DEFAULT_PAGE` of 100 a
number this adapter could never fulfil. The fan-out is bounded at a quarter of
the quota, leaving room for another borrower of the same client, and the case
lists strictly more keys than the quota in one page. A second case covers the
failure path, which is where an unbounded pool does its real damage:
`Promise.all` rejects at the first failure, so without a shared flag the
survivors drain the rest of the page *after* the caller already holds an error,
spending the quota the bound exists to protect and swallowing their own
failures. The peer fails exactly one stat — a peer that failed every stat would
kill every worker at once and a pool that had kept going would still have looked
bounded — and the run is required to settle strictly below the page and to stay
settled.

**Mastra's `readdir` follows the pinned `LocalFilesystem` in three places** that a
tool depends on and that are not obvious: a nested entry's name carries its
subpath, so `/a/x.txt` and `/b/x.txt` are distinguishable and addressable; an
extension filter applies to files only, so directories survive it and the
structure the names are relative to survives with them; and an extension is
matched by **equality** against `extname`, with or without its leading dot, so
`.ts` and `ts` select `x.ts` and a bare `s` selects nothing.

**The outcome rows, which are the point of the whole section.** For each adapter,
a dispatched mutation with no reply and a 1011 close, and a composite that
applied one step and then failed. Files SDK: a permanent `Provider` error with
`applied` unset and the outcome surviving only on `cause`, with upstream's
predicate asserted to refuse a retry. Mastra: `TUNNEL_UNKNOWN` and
`TUNNEL_PARTIAL`, asserted **not** to be `FileNotFoundError` — the class of
mistake that reads as "nothing happened". just-bash: the record present in the
side channel, and absent for a `not_started` failure, because a channel for
ambiguous mutations should not fill with unambiguous ones. FilesV4: a throw, with
`incompleteUploads()` holding the path, and a delete that rejects rather than
answering `deleted: false`. Every adapter is also asserted to put no path, name
or content into the message it hands its framework.

**Read-only, for all four.** A read-only descriptor refuses `createFilesApi` at
construction, and the other three refuse their whole write surface with no
mutating opcode reaching the socket while reads keep working. These are the
client's own refusals, taken from a descriptor it was handed; no device has
enforced one.

**What these suites do not prove.** The same loopback harness, with the same
consequence: not a relay, not a device, no TLS, no grant, no confinement. And the
AI SDK **live tools** row of the contract-compilation table is not satisfied at
all — no tool factories exist, so schemas, abort propagation, bounded output and
model-visible outcome fields are untested.

### Implementation gate 6, end to end: the real client against real sockets (`verify-m4-fs-client-e2e`)

The two sections above are the shared client and the four adapters against a
**loopback harness**. Gate 6 says in terms that this is not enough —
"compilation against a source interface or a fake in-memory adapter is
insufficient to claim remote compatibility" — and this gate is the sentence
that residue asked for. It is the first evidence in `packages/client`'s history
about `crates/tunnel-relay` and `crates/tunnel-fs-provider` rather than about a
peer that speaks the wire.

**How node is driven.** `crates/tunnel-test-harness/src/production_cluster/fs_client_e2e.rs`
stands up the three-relay production cluster, a real Redis catalog and a real
device connector serving five filesystem exports seeded side by side, then
spawns `node` on `packages/client/e2e/gate.ts`, which imports that package's own
`src/`. A child process is the shape, and the alternatives are named rather than
dismissed: embedding a JavaScript runtime in the harness, or reimplementing the
client in Rust, each give up the only thing worth proving — that *the package*
interoperates. Three channels, each for what it carries: a **plan file** named
in argv, because a consumer token must not appear in a process listing;
**stdout** as newline-delimited JSON ending in exactly one report; and **stdin**
carrying `go` lines. Every judgement is taken in Rust by
`validate_fs_client_e2e_evidence` over scalars, counts and closed labels, so a
driver that decided for itself what passing meant could not smuggle a verdict
past the validator.

**TLS is proven by a pair, because a connect that resolved proves nothing.**
The **cluster relay's** server leaf carries `127.0.0.1` as an IP subject
alternative name — `rcgen` turns a name that parses as an address into one — so
the endpoint can be the loopback address the relay binds with no name to
resolve. `node` trusts the fixture CA through `NODE_EXTRA_CA_CERTS` and verifies
the chain the ordinary way, and the client's own `allowInsecureLoopback` is
never passed.

The leaf that carries the address is **only** that one, and the distinction is
load-bearing rather than tidy. It was first written into the shared
`CertificateProfile::server`, which every fixture listener in the harness uses,
and `verify-m7-redis-tls` builds `wrong_server_name_rejected` by dialling its
forwarder at `rediss://127.0.0.1` and requiring refusal. A name granted to every
listener made the wrong name a right name, so that negative case could no longer
fail and the gate went red 3 of 3 — task row M4-17. The widening is now an
opt-in, `CertificateProfile::server_with_loopback_ip`, asked for at the cluster
relay leaf that gate 6's driver actually dials; the Redis TLS forwarder issues
from `server_without_ip_sans` at its own site; and a unit test asserts the
forwarder's leaf is refused for `127.0.0.1` and accepted for `localhost`.
State precisely what that test guards: because `server_without_ip_sans` is a
subtraction, a re-widening of the shared default is **neutralised** at this
site rather than caught, and the test stays green because the leaf stays
narrow. The test reddens when this leaf itself changes — the site pointed back
at `issue_server`, the subtraction broken, or an IP SAN introduced below the
profile — and it does so in milliseconds instead of through a gate run. The
companion assertion that the opt-in leaf *is* accepted for `127.0.0.1` is what
keeps the refusal a real observation rather than an artefact of a verifier
that never checks IP SANs at all.

That much was true of the first round of this gate too, and it was **not
enough**: the driver set `tlsVerified = true` once `connectFilesystem` returned,
which is equally true when verification is off, and review demonstrated the
whole gate passing under `NODE_TLS_REJECT_UNAUTHORIZED=0`. Three things replace
that assertion, and all three are observations:

* The harness **refuses to run** when `NODE_TLS_REJECT_UNAUTHORIZED` is set in
  its own environment. Removing it from the child would not be enough on its
  own — an operator who set it meant something by it, and reporting a verified
  chain in an environment configured not to verify would be the same mistake
  one layer down.
* It is removed from every child's environment, and the driver reports what its
  process **actually saw**, which the validator pins to `unset`.
* A **negative probe** runs the same driver against the same endpoint in a
  second process with `NODE_EXTRA_CA_CERTS` withheld — the variable is read once
  at startup and cannot be withdrawn inside a run, which is why it is a separate
  process. The client must refuse with `INSECURE_ENDPOINT`, non-retryable, which
  is its own code for a certificate it could not verify and which it
  deliberately does not report as an outage.

A verified chain being **accepted** and an unverifiable one being **refused** are
what make the pair evidence about verification; neither alone is.

**Nothing is a sleep.** Two of the cases need the harness to act at a point
inside the driver's run, and both are rendezvous on stdin rather than a wait
chosen to be long enough:

* The **grant-revision** case. The client fetches a descriptor, announces the
  revision it read, and holds. The harness moves the grant in the authoritative
  catalog, polls a fresh descriptor until it reports the new revision, and only
  then releases the driver — whose upgrade then carries a revision that no
  longer exists and is refused `409 CAPABILITIES_CHANGED`. That refusal is the
  only way to observe from outside that `X-Agent-Tunnel-Grant-Revision` is sent
  at all.
* The **ledger readings**. One consumer session is one device exchange, and the
  driver holds at three points, so the harness can wait for the device's
  exchange count to reach a known number and read `ConnectionStatus::fs` at a
  boundary rather than at a guess about how far the device has got.

**What one run proves.** The descriptor fetched and validated by the client's
own schema rules; an unsigned token refused `UNAUTHENTICATED`; the authenticated
upgrade with `agent-tunnel.9p.v1` selected and the 65,536-byte `msize`
negotiated; a checksummed 393,216-byte `readFile` over **eight** `Rread` messages; a
checksummed 393,216-byte `writeStream` over **twelve** `Twrite` messages each
answered by its own `Rwrite`, verified byte for byte on the host by the harness
— and both counts are **counted at the transport**, by the opcode byte of each
complete message the socket carried, because one consumer binary message is one
complete 9P message in this profile. A first round divided the file size by the
maximum payload instead, which would have reported "more than four messages" for
a chunking that never happened; its arithmetic guess of seven was wrong for both
directions; a forty-entry directory listed with
every name exactly once; a read-only grant refusing mutations **at both layers**
— `ENOTSUP` and `not_started` locally for four operations the descriptor does
not advertise, which is the statement that a caller's mistake never reaches the
socket, and `EPERM` from the device for `Tlcreate`, `Tmkdir`, `Tunlinkat` and a
writable `Tlopen` issued through the raw session a custom 9P client would use,
with the export byte-for-byte unchanged afterwards; and the Mastra adapter
driven end to end over the same sockets, reading, writing, listing, stat-ing and
refusing `appendFile`.

**The `unknown` outcome is deterministic, not a race.** Gate 5 named this
obligation for the client's side: there is no wire field for an outcome, so a
dispatched mutation with no reply is `unknown` and the device's own ledger is
the only place the truth lives. Reaching that honestly needs a mutation that is
genuinely dispatched and unanswered, and `writeStream` cannot provide one — it
awaits each `Rwrite` before sending the next, so at most one write is ever
outstanding and the close would land in a window that is a coin toss. So the
case uses the exported `ConsumerSession` directly: `sendRaw` encodes and sends
inside its promise executor, so issuing twenty-four writes without awaiting puts
all twenty-four on the transport, and the session is closed in the **same
synchronous turn**, before the event loop can deliver one reply. Everything
under it is the same product code `connectFilesystem` runs.

**The client's view and the device's ledger disagree twice, and both times the
client is right not to claim.** This is the point of reading them side by side
rather than either alone.

* The `unknown` exchange is the **first** the device serves, so its counters are
  a delta from zero. The client reports `unknown` for twenty-four writes and
  acknowledges nothing; in the recorded runs the device reports two mutations
  dispatched, two applied, two **acknowledged** and 32,768 bytes written — the
  `Tlcreate` and one `Twrite`. **Those numbers are recorded, not pinned.**
  `SocketTransport.close()` ends and destroys the socket at once, discarding
  node's userland write buffer, so "all twenty-four are dispatched" means all
  twenty-four were handed to `send`; how many reach the device depends on kernel
  socket buffering, and in practice most of them never leave the process. One write reached the
  host and its reply reached the carrier, and no field on the wire could have
  told the client so. The harness checks the host file holds exactly those bytes
  at the source pattern's own offsets — so nothing was applied twice or out of
  order — that it equals the ledger's `bytes_written`, and that
  `mutations_applied - mutations_acknowledged == mutation_unknown`, the identity
  gate 5 pins.
* The read-only exchange is bracketed by two more readings. The client reports
  **`failed`** for the three mutating opcodes, which is the wire's floor and the
  strongest thing an `Rlerror` licenses — and `not_started` for the writable
  open, because opening for writing carries no effect, which is gate 5's own
  `Primitive::is_mutating` distinction reaching the client through
  `isMutatingRequest`. The device, meanwhile, dispatched nothing, applied
  nothing and wrote nothing.

**One defect is measured rather than assumed, and it is tracked as task row
M4-16.** `FsCounters::mutations_refused` documents itself as "mutating requests
refused before the host was touched", and over that read-only exchange it stays
at **zero** while three such refusals happen. The reason is structural: the
refusal is taken by gate 3's session inside `Provider::accept`, which returns a
`SessionError` and never produces the decoded primitives the ledger classifies a
mutation from, so `Provider::refuse` can only count `errors_sent`. A mutation
refused at **admission** is therefore invisible in the one place an operator
reads how far a mutation got; only a mutation refused after the queue wait is
counted.

A first round **pinned** that zero, which was the wrong shape for a
characterisation: it made the gate *require* the provider to disagree with its
own documentation, so landing M4-16's fix would have turned this gate red. The
value is now recorded in the evidence and printed in the summary, and what is
asserted is only the bound that holds either way — the counter never exceeds the
mutations the case sent. What discriminates about the read-only exchange is the
other reading beside it: nothing dispatched, nothing applied, nothing written.

**Red-then-green.** `scripts/fs-guard-deletion.py --suite gate6-e2e` deletes one
rule of the validator at a time — replacing its condition with `true`, because
the rule list is a fixed-length array and removing an entry stops the crate
compiling, which that script refuses to call a red test — and requires the
mutation table in the same file to go red. **14 of 14** deletions do.

**What this gate does not prove.** The seventh component, the AI SDK live
directory tools, still does not exist. Three of the four adapters have still
never spoken to a relay, and the one that has reached its framework as stand-in
error classes with the same constructor shapes the offline suites use — so
"registered with the real thing that consumes it" (task row M4-14) and "driven
against real relay and device sockets" (this row) are two facts proven
separately rather than one fact proven once. No grant has been revoked under a
live *client* session, a consumer still reaches only the owning relay, and the
shared dataset across all four views, two adapters borrowing one client, clocks
and budgets are exactly as gate 6 left them. A filesystem session **has** now
been held across a scheduled data-socket rotation, but by the harness's own 9P
client and not by the shared TypeScript client: that is gate 7 below.

### Implementation gate 7: a live 9P session across a real rotation (`verify-m4-fs-rotation`)

The gate is `verify-m4-fs-rotation`, registered in
[`scripts/m4-harness-verify.sh`](../scripts/m4-harness-verify.sh) beside gates
4, 5 and 6 and implemented in
`crates/tunnel-test-harness/src/production_cluster/fs_rotation.rs`. It runs on
the same real three-relay production cluster, the same authoritative Redis
catalog and the same consumer WSS sockets, on its own seeded `rotation` export
so that a fid surviving a rotation cannot be credited to another case's grant.

It exists because [protocol.md](protocol.md) states that "9P fids, request tags
and negotiated session state … remain intact through scheduled data socket
rotation", that "the relay neither duplicates `Tattach` nor reconstructs fids
during cutover", and that compatibility tests must cover "reads/writes spanning
rotations" — and until this gate the four filesystem cluster gates contained
**no occurrence** of `rotat`, `epoch` or `restart` in 6,029 lines.

**The rotation is concurrent with a 9P exchange, not sequential with it.** A
rotation between two quiet exchanges would prove nothing, so the gate holds one
`Rread` in flight across the freeze:

* The fid is opened and serves three full-`msize` reads first, so a later
  failure cannot be blamed on a session that never worked.
* Once the carrier has settled, the **device data socket's connector→relay**
  bytes are paused at the harness TCP proxy. The control socket and the
  rotation candidate are untouched, so the attempt itself is unmodified.
* One `Tread` is sent and its reply deliberately not read. The request crosses
  on the still-flowing relay→connector direction, the device performs it, and
  the connector sequences the `Rread` into the paused socket.
* At `ROTATE_QUIESCE` the owner fixes the attempt's immutable per-direction
  fences. The connector's fence for this stream therefore covers a frame the
  owner has not received, so the owner cannot prove its drain and stays frozen
  until the bytes are released — well inside the overlap deadline.

The concurrency proof is drawn from the owner's own rotation state machine
rather than from a timestamp: at a frozen phase with the attempt active,
`connector_fence_sequences[stream]` is strictly greater than that stream's
`recv_contiguous_connector_to_relay`. That **inequality** is the assertion;
the sequence numbers themselves depend on how many frames the transfer had
already used and are not fixed run to run. One run at this tip: fence **12**
against cursor **10**, phase `quiescing`, candidate generation 2 over old
generation 1. (A second run at the same tip showed fence 13 against the same
cursor, which is why the gate asserts the inequality and not the values.)

**The assertions are on the operation, not on liveness.** That a session still
exists proves nothing. Measured at this tip: the held tag **7** came back as an
`Rread` of **65,525** bytes carrying the tag that was outstanding across the
freeze; the transfer delivered **1,572,864 of 1,572,864** bytes over **25**
`Rread` messages on one fid with an exact FNV-1a checksum; rotations completed
**0 → 1**, active generation **1 → 2**, epoch **1 → 1**, **zero** replayed
frames and no deadline-forced retirement; the fid opened before the rotation
still answered `Tgetattr` with the same size after it, the attach fid still
walked, and exactly **one** `Tattach` was sent in the whole run.

**Guards.** `python3 scripts/fs-guard-deletion.py --suite gate7-rotation` is
**19 of 21** red at this tip. The two exceptions are recorded rather than
hidden: "the owner was actually frozen when it was sampled" and "a rotation
attempt was active at the sample" are each still green when defeated alone,
because the composite in-flight rule already subsumes both — the predicate
returns false unless the attempt is active **and** the phase is frozen. They
are kept for the error message they give a failing run, and the two cases that
defeat the predicate's own clauses are what hold those conditions.

**Suite status.** This gate passes, but `scripts/m4-harness-verify.sh` as a
whole does **not** at the tip that introduced it: the connector fix this gate
depends on (M4-22) reaches a latent relay defect, **M4-25**, that closes a
revoked filesystem session without the contractual `1008`, so
`verify-m4-fs-real-path` is red 3 of 3. The two must land together. Nothing in
this gate's own evidence touches revocation.

**What this gate does not prove.** Only **rotation**, of M4-06's five transport
events. Consumer loss is now gate 8 below and epoch change gate 9; device
process restart is still uncovered on the filesystem path, and revocation is
covered by gate 4 and not here. The session runs against the **owning** relay, because
gate 4 admits a filesystem session only there, so the rotation crossed the
device data socket and not the relay-to-relay peer hop. Nothing here is driven
by the shared TypeScript client. Nothing here covers a **write** spanning a
rotation, and nothing here exercises `Tflush` across one.

### Implementation gate 8: a 9P session lost mid-exchange (`verify-m4-fs-consumer-loss`)

The gate is `verify-m4-fs-consumer-loss`, registered in
[`scripts/m4-harness-verify.sh`](../scripts/m4-harness-verify.sh) beside gates
4, 5, 6 and 7 and implemented in
`crates/tunnel-test-harness/src/production_cluster/fs_consumer_loss.rs`. It
runs on the same real three-relay production cluster, the same authoritative
Redis catalog and the same consumer WSS sockets, on its own seeded
`consumer-loss` export so that a fid answering in the replacement session
cannot be credited to another case's grant.

It covers M4-06's **consumer loss** clause, and its contract is the *opposite*
of gate 7's. [protocol.md](protocol.md) states both in one paragraph: fids and
tags "remain intact through scheduled data socket rotation", but "the first
filesystem profile restores no fids across a consumer WebSocket reconnect …
terminate that filesystem session, fail pending calls explicitly and create a
fresh 9P session". The **same-owner** sentence — "replacement of a failed data
socket may preserve the filesystem session only while the same control owner
and all ordered stream state are retained" — licenses retention for exactly one
event, and a consumer reconnect is not it. A gate that asserted fid survival
here would be asserting the violation.

**The loss is concurrent with a 9P exchange, not sequential with it.** A
consumer that goes away between two settled exchanges would prove nothing, so
the gate loses one with a request outstanding and proves it from the owner's
own per-stream cursors rather than from timing. Once the carrier has settled,
the device data socket's connector→relay direction is paused at the harness
proxy; the owner's `last_emitted_relay_to_connector` and
`recv_contiguous_connector_to_relay` for the stream are fixed *while paused*;
one `Tread` is sent whose reply is never read; and the consumer is abandoned at
the instant the owner shows the emit cursor advanced while the receive cursor
has not — the relay had dispatched a 9P record toward the device and had
received no answer to it. The paused bytes are released *after* the loss, so
the device's `Rread` really does arrive at a relay whose consumer is gone.

**The assertions are on the protocol objects, not on liveness.** The lost
stream is deregistered at the owner; the device's own tunnel session survives
the loss of one consumer with its identity and epoch unchanged. The contract
clause proper is then driven in two pieces, in the order the session machine
checks them, because a single probe would conflate them. A replacement session
that names the lost session's file fid *before* attaching is **closed** with
the profile's protocol violation rather than served — `SessionError::
BeforeAttach` answers `Close(ProtocolViolation)` and is consulted before the
fid table, which is the "require fresh version/attach" half. A replacement
session that *has* attached, on a root fid of its own, then finds both of the
lost session's fid numbers unbound, refused with the errno for a fid that is
not allocated in this session. That session then walks, opens and reads the
whole file back with an exact checksum — binding the lost file-fid *number*
freshly as it does so, which is the other half of the contract: the number is
reusable once the session that held it is gone.

Reusing the *same fid numbers* is what gives the case its force: if fids leaked
across consumer sessions, that fid would still be bound to the file and would
answer.

**Observed, not pinned.** One run at this tip: emit cursor **7 → 8** against a
receive cursor held at **10**, both stale fids refused with errno **22**, the
pre-attach probe closed with **1002**, **786,432 of 786,432** bytes over **13**
`Rread` messages with an exact checksum, epoch **1 → 1**, and exactly **two**
`Tattach` across the run. The gate asserts the *inequality* and the errno
*derived* from `FsErrorCode::Einval`, never these figures; three runs at this
tip agreed on them, but nothing depends on that.

**What this gate does not prove.** Only **consumer loss**, of the three events
M4-06 still named as uncovered. Epoch change is now gate 9 below; **device
process restart** remains uncovered on the filesystem path. The loss is of the consumer's own
WebSocket, so nothing here faults the device carrier or the control socket, and
the "data-only recovery" clause of the same-owner contract — a replacement of a
*failed* data socket — is still untested. The session runs against the
**owning** relay, because gate 4 admits a filesystem session only there.
Nothing here is driven by the shared TypeScript client, and the outstanding
operation is a **read**: no write and no `Tflush` has been lost mid-exchange.

### Implementation gate 9: a 9P session across a control-epoch change (`verify-m4-fs-epoch-change`)

The gate is `verify-m4-fs-epoch-change`, registered in
[`scripts/m4-harness-verify.sh`](../scripts/m4-harness-verify.sh) beside gates
4, 5, 6, 7 and 8 and implemented in
`crates/tunnel-test-harness/src/production_cluster/fs_epoch_change.rs`. It runs
on the same real three-relay production cluster, the same authoritative Redis
catalog and the same consumer WSS sockets, on its own seeded `epoch-change`
export so that a fid answering in the replacement session cannot be credited to
another case's grant.

It covers M4-06's **control-epoch change** clause.
[filesystem-api.md](filesystem-api.md) names that event in the same sentence as
gate 8's — "Consumer loss, control-epoch change, grant expiry, or process
restart invalidates the filesystem session" — and [protocol.md](protocol.md)
says what "invalidates" obliges: across a **control-session reconnect** the
profile "restores no fids … terminate that filesystem session, fail pending
calls explicitly and create a fresh 9P session". The **same-owner** sentence
licenses retention for exactly one event, replacement of a *failed data socket*
while **the same control owner** is retained, and a control-session reconnect
is the event that destroys that qualifier. So this gate, like gate 8 and unlike
gate 7, proves a fid does **not** survive.

**The epoch is genuinely acquired, not simulated.** Nothing here writes an
epoch number. `tunnel-client` has no automatic reconnect — its documented
policy is to "close control and data and require a fresh session" — so the gate
stops the connector, waits for the authoritative catalog to report the owner
**released**, and starts a second connector on the same device identity and the
same export. Both the catalog's owner token and the device's own `WELCOME`
must show a strictly greater epoch, and the two must agree. That second
assertion is what separates an epoch change the device **sees** from one it
does not: a revocation or an owner-lease loss advances the durable epoch while
the device's live session keeps its stale one and is closed with a reason
rather than a new epoch, which is a different contract and not this gate.

**The change is concurrent with a 9P exchange, not sequential with it.** The
construction is gate 8's and is proven from the owner's own per-stream cursors
rather than from timing: with the device socket's connector→relay direction
paused, the cursors are fixed *while paused*, one `Tread` is sent whose reply is
never read, and the control session is replaced at the instant the owner shows
the emit cursor advanced while the receive cursor has not.

**The assertions are on the operation.** The pending call is **failed
explicitly** with a close code rather than left hanging or answered; the held
stream is deregistered at the owner; a replacement session naming the earlier
file fid *before* attaching is closed with the profile's protocol violation;
a replacement session that *has* attached, on a root fid of its own, finds both
reused fid numbers refused with the errno for a fid not allocated in this
session; and that session then reads the whole file back on its own fid with an
exact checksum, so the refusals are fid scoping and neither a broken export nor
a replacement connector that never served it.

**This gate found a defect, recorded as M4-28.** "Fail pending calls
explicitly" is the one obligation gate 8 could not test, because its consumer
was gone and had nobody to be failed to. Here the consumer is still connected,
and it was receiving a close with **no code at all**: `close_session` drains a
session's streams by cancelling `closed`, which carries no reset reason, so the
consumer pump sent `Close(None)`. That is the sibling of **M4-25**, which fixed
the same codeless close for a revoked grant.

The fix derives the code from the **cause**, not from the fact of
cancellation — which is the distinction review forced, and the same one M4-25
turned on. `close_session` is reached from roughly **thirty** reasons, and
almost none of them mean the device went away: `SHUTDOWN` fences every session
when the *relay* stops, and an authority outage, an owner fence, a rotation or
recovery failure and a device framing fault are each something else. Keying off
cancellation alone would have told those consumers "the device is not
connected" on exactly the opposite ground to the one 1012 is justified by. So
the actor publishes a typed `StreamTeardownCause` whose only variant is
`DeviceGone`, and every other reason publishes nothing and keeps the close it
already had.

**Which teardowns qualify, corrected at M4-35.** M4-28 published for
`CONTROL_CLOSED` alone, and that left the same event arriving codeless
intermittently: a connector that stops closes **both** of its sockets, and
which loss the relay notices first is a race. Control first is
`CONTROL_CLOSED`; **data first** is a frame that fails to queue toward the
device, which tears the session down as `REVERSE_CHANNEL_UNAVAILABLE` instead.
Over **24** instrumented runs of this gate every failure carried the second
reason and every pass the first, at **7 red**. The gate is widened to that
second teardown but **not** to its reason string: `queue_data` returns the same
failure when the session's own queue **budget** refuses the bytes, which is the
relay declining to buffer while the device is healthy. So the publication is
gated on the *fact* the string is ambiguous about — the carrier's sender is
closed, so the socket task holding its receiver is finished — and a budget
refusal still publishes nothing. Publication precedes
`closed.cancel()`, the same ordering invariant M4-25 established; the
resolution still runs after the peer-reset resolution so a revocation closes
1008, and before the framing verdict which outranks everything.

**Observed, not pinned.** One run at this tip: emit cursor **7 → 8** against a
receive cursor held at **10**, epoch **1 → 2** in the catalog and **1 → 2** in
the device's own `WELCOME`, the held call closed with **1012**, both stale fids
refused with errno **22**, the pre-attach probe closed with **1002**,
**786,432 of 786,432** bytes over **13** `Rread` messages with an exact
checksum, and exactly **two** `Tattach` across the run. The gate asserts the
*inequalities* and the codes *derived* from `FsErrorCode::Einval` and
`SessionErrorCode::close_code()`, never these figures.

**A coverage check that is deliberately not in the registry.**
`scripts/m4-gate9-ordering.sh` runs this gate N times and reports which
socket-loss ordering each run took, failing if any run fails and exiting
**3** — neither pass nor fail — when a set never exercised one of the two.
It is **on-demand only** and must stay that way: exit 3 is expected on a
correct tree, so a registry running it would go intermittently red for
something that is not a defect. The per-run rule inside the gate is the
part that belongs here, and it is here. Three post-fix sets of 20 took the
data-first ordering 11, 8 and 2 times, so the default N is 40 rather than
20: at the low end of that spread a 20-run set misses the ordering about
one time in eight.

**Guards.** `python3 scripts/fs-guard-deletion.py --suite gate9-epoch-change`
is **28 of 28** red at this tip, with **one** further case reported as
`DOCUMENTED GREEN` and never counted as a red test: "the relay had dispatched a
record toward the device", shared by name with gate 8 and subsumed by the
composite in-flight rule beside it for the same reason.

**What this gate does not prove.** Only **control-epoch change**, of the two
events M4-06 still named as uncovered. **Device process restart remains
uncovered**: it needs the append-only journal pattern from M5 chunk 4, because
an in-memory ledger dies with the process and makes "the count did not
increase" true of nothing. The operation held across the change is a **read**:
no write and no `Tflush` has been held across an epoch change. The session runs
against the **owning** relay, because gate 4 admits a filesystem session only
there, so nothing here crosses the relay-to-relay peer hop. Nothing here is
driven by the shared TypeScript client. The `CarrierEvent::Fin` / `CarrierEvent::Closed`
sibling of the path M4-28 fixed is **not** changed, and is now **measured as
not taken**: across **24** instrumented runs of this gate the consumer pump
left through `closed.cancelled()` every time and through that arm never, so
giving it a close code would still be a fix without evidence. See M4-35.

### Implementation gate 11: a 9P session across a failed data socket's replacement (`verify-m4-fs-data-recovery`)

The gate is `verify-m4-fs-data-recovery`, implemented in
`crates/tunnel-test-harness/src/production_cluster/fs_data_recovery.rs` and run
by hand. It is deliberately **not** registered in
[`scripts/m4-harness-verify.sh`](../scripts/m4-harness-verify.sh): it is red,
and what it reproduces is filed as **M4-29**. It runs on the same real
three-relay production cluster, the same authoritative Redis catalog and the
same consumer WSS sockets, on its own seeded `data-recovery` export.

It covers M4-06's **"data-only recovery"** clause, and that clause is the one
event in [protocol.md](protocol.md)'s filesystem paragraph whose contract points
*towards* retention rather than away from it: "Replacement of a failed data
socket may preserve the filesystem session only while the same control owner
and all ordered stream state are retained." Gates 8, 9 and 10 each drive an
event from the preceding sentence and each therefore prove a fid does **not**
survive. Gate 7 drives a *scheduled* rotation, which is a clean attempt and not
a failure at all. This gate drives the second sentence's own event, which
nothing had ever driven with a filesystem session attached.

**It is a failure, not a rotation, and that is asserted.** The device data
socket is destroyed at the harness TCP proxy — no rotation handshake, no
`ROTATE_*` exchange, no candidate prepared in advance, no chance to quiesce.
The rotation policy is left at its default 300-second interval and the scenario
is bounded far below it, so the owner's `rotations_completed` is **0 either
side** and the generation change can only be the failure's. The dead carrier's
connection id differs from the replacement's, the failed connection is gone at
the proxy and a replacement was dialled through it, and the owner labels the
episode a lost **data** transport, derived through
`tunnel_relay::recovery_reason_name` rather than pinned — `ControlLost` is gate
9's event, and there a fid must not survive.

**The failure is concurrent with a 9P exchange.** The construction is gate 8's,
proven from the owner's own per-stream cursors rather than from timing: with the
connector→relay direction paused, the cursors are fixed *while paused*, one
`Tread` is sent whose reply is never read, and the socket is destroyed at the
instant the emit cursor has advanced while the receive cursor has not. The
paused bytes are **never released** — the connection is gone — so the `Rread`
the device had already produced dies inside the failed carrier. A reply the
consumer later reads is therefore one the transport carried over, not one that
was merely late.

**The trap is inverted, so retention is not assumed either.** The sentence
licenses preservation *conditionally*, so a gate that merely observed a
surviving fid would prove nothing: a fid surviving an event that had also moved
the control owner or lost ordered stream state would be the violation. Both
qualifiers are therefore asserted as an explicit antecedent, and each conjunct
is separately load-bearing — the catalog's owner token and the owning relay
agreeing on an unchanged session identity and epoch, a control socket that was
never replaced, a recovery that released exactly the carrier that died and
installed exactly the one that replaced it, `total_replayed_frames` advancing,
and a stream that kept both its id and the relay's stable `operation_id`. A
unit test defeats each conjunct on its own so none can rot into a field nothing
reads.

**The assertions are on the operation.** The held tag comes back as an `Rread`
carrying data on the fid that was open before the socket died; the whole file is
read on that one fid across the failure with an exact checksum over many
messages; the fid still answers `Tgetattr` at the same size; the attach fid
still walks; a tag allocated after the recovery correlates; and exactly **one**
`Tattach` is sent all run.

**What it found.** When the recovery completes, all of that holds — the contract
is satisfied. But the gate is red **8 of 8** at the tip that introduced it, in
two modes: the retained recovery going terminal with a candidate attached and a
replay staged, and the recovery completing but the session then answering
nothing further while the owner shows the stream fully quiesced. The control
that makes this filesystem-specific is `verify-m7-i08-recovery-attempts`, the
product's own retained-recovery gate on the echo adapter, which exits 0 at the
same tip on the same host. `python3 scripts/fs-guard-deletion.py --suite
gate11-data-recovery` reports **39 of 39** deletions red, with one case
reported as `DOCUMENTED GREEN` — the composite-masked in-flight half that gates
8, 9 and 10 each carry for the same reason, held directly in both directions by
`the_in_flight_predicate_needs_both_halves`.

**Thirteen rules were removed rather than exempted.** The same-owner qualifier
was first written as thirteen validator rules beside the antecedent
conjunction, and the guard suite reported every one of them still green: the
conjunction already rejects every run they would have rejected. They are gone,
and the property moved to where it can be defeated — the conjunction is one
conjunct per line, the suite's last **fourteen** cases delete one conjunct
each, and each of those turns the gate's per-conjunct unit test red as well as
its mutation table.

The conjunction is written as an **array** rather than as a `&&` chain, and
that is load-bearing: as a chain the head conjunct carries no `&&`, so it did
not match the suite's single edit shape and was the one conjunct that could not
be defeated — the same unfalsifiable-rule problem, reappearing at the one line
the edit shape could not reach. Two further corrections came with it.
`stream_id_stable` was one fact under two names — `stream.is_some()` for a
stream found *by* that id — and is replaced by `sole_consumer_stream_at_owner`,
counted from the stream table's length so the two are orthogonal. And
`stream_not_terminal` is new, because a present-but-terminal stream satisfies
every other ordered-state conjunct; on a mode B run it reads **true**, which is
what rules a dead stream out as that mode's explanation.

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

## HTTP forwarding over the real path (`verify-m3-http-forward-real-path`)

```sh
TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/m3-harness-verify.sh
cargo run -p tunnel-test-harness --locked -- verify-m3-http-forward-real-path
```

Implementation gate 3 of [http-forwarding.md](http-forwarding.md). The gate starts the three-relay production cluster with an `http-forward` service and grant seeded for one device, attaches that device's `tunnel-client` (with a registered in-process handler) to relay-a so relay-a owns it, and sends every consumer request through relay-c, so each exchange crosses the public Axum route, the credited peer HTTP/3 hop, the owner actor stream and the device data WebSocket. The validator (`validate_http_forward_real_path_evidence` in `production_cluster/http_forward_real_path.rs`) is re-run at the command boundary, and its unit test rejects every single-field mutation of passing evidence.

It proves, in one run:

* **Saturation with concurrent work.** A 16 MiB `/echo` upload is echoed back by the handler while the consumer does not read the response for 2.5 s; the upload writer must have stalled below its total. While it is stalled, `/events` is cancelled by a consumer disconnect and `/permission` must answer within 2 s. The cancelled exchange must end with the owner stream released by `RESET(4005 CANCELLED)`, the ingress recording `HTTP_CANCELLED` with an aborted response, the device response aborted (never completed) and the handler's cancellation token fired within 5 s of the disconnect. The same `/permission` request is also answered through the owner's own public route.
* **Bounded queues at every hop**, from payload-free diagnostics: ingress request/response handoffs ≤ 65,536; ingress response body queue ≤ 4 × 65,528; peer in-flight and receive queues ≤ 196,608 (inside the 256 KiB per-stream budget) at both ends; owner and device receive buffers ≤ the 131,072-byte window; owner and device parked writes ≤ 65,536; owner replay ≤ 131,072; owner session data high-water ≤ its data limit. Each saturated hop must also exceed half its window, so a bound cannot pass vacuously.
* **Checksums both ways.** The handler's SHA-256 of the received upload and the consumer's SHA-256 of the echo both equal the SHA-256 of the 16 MiB synthetic source, and the echo body ends cleanly.
* **One long-lived session past the former 128-stream ceiling (M7-C82).** After every measurement above, 160 small `POST /permission` requests run one at a time through the same device session, on a fresh consumer connection every 32 requests. All 160 must answer 200 with the exact body, the highest device stream ID must exceed the 128 tracked-entry cap, the handler must record exactly 160 dispatches (one per request), the connector's retained OPEN journal must peak at no more than **two** entries while serving them (the loop runs one request at a time, so the cap itself would be a vacuous bound; observed 1), the count of stream IDs reclaimed at the [OPEN retry horizon](protocol.md#open-retry-horizon-and-journal-reclamation) must rise by **exactly** 160 over its pre-loop baseline, and the session must still be the same ready, non-failed session afterwards. A typed `not_dispatched` refusal (never dispatched, so it cannot account for a second dispatch) may be retried at most 12 times in total; exceeding that fails the run inside the loop, and it is deliberately not also a validator rule, which could only restate the cap the loop enforces. The retired-record coalescing counter is printed but not required to be zero: a gap in that record can be a stream ID the owner allocated and never named in an `OPEN` or a `STREAM_FORGET`, so it can increment legitimately under control-queue pressure (observed 0). Red-then-green: with the pre-fix connector the session died at sequential request 124 with the device readiness `Closed { reason: "STREAM_FORGET unknown stream or OPEN journal entry" }`, the journal peak at 128 and a 502 at the consumer. Observed at the boundary: 4 stream IDs allocated before the loop and 3 reclaimed, so the one ID the run never reclaims belongs to the earlier phase — by elimination the `/events` exchange the consumer cancelled by disconnecting, the only aborted exchange in the run. Because the connector's journal is adapter-agnostic, this is also the per-session ceiling every `mcp-2026-07-28` MCP request used to hit.
* **No credential or address leakage.** The consumer sends a valid bearer and a synthetic cookie. The handler must see neither `authorization`, `cookie`, `host`, forwarded-identity nor `x-agent-tunnel-*` fields, and no header value may contain the token, the cookie value or any relay consumer, device or peer address; the consumer's response headers are checked the same way. An `x-agent-tunnel-owner` probe must be refused with 400 and an unauthenticated probe with 401, before the handler is ever invoked.

It deliberately does not cover rotation, freeze or recovery on HTTP streams, owner-side record re-validation or control `CANCEL` for HTTP streams (all gate 4, next section), per-profile ACP/MCP/CUA allowlists (gate 5), or HTTP/2 consumers; see "Not proven by gate 3" in [http-forwarding.md](http-forwarding.md#pinned-in-code-gate-3). Set `M3_HTTP_FORWARD_DIAGNOSTICS=1` to print the payload-free per-hop records.

## HTTP forwarding across rotation and faults (`verify-m3-http-forward-rotation`)

```sh
TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/m3-harness-verify.sh
cargo run -p tunnel-test-harness --locked -- verify-m3-http-forward-rotation
```

Implementation gate 4 of [http-forwarding.md](http-forwarding.md). It uses the same three-relay topology as gate 3: relay-a owns the device and consumers enter through relay-c. The device runs a short scheduled-rotation policy (interval 6 s, handshake 2 s, overlap 5 s), and every device socket passes a TCP proxy, so the gate counts sockets and can pause one direction of one socket. Correctness comes from owner rotation observations, owner and device record logs, handler counters, checksums and diagnostics. It never relies on fixed sleeps. The validator (`validate_http_forward_rotation_evidence` in `production_cluster/http_forward_rotation.rs`) is re-run at the command boundary. Its unit test rejects every listed single-rule mutation of passing evidence, and a second test checks that each upload rotation point is distinct. A run takes about 80 s. `M3_ROTATION_CASES=head,sse,…` selects cases while debugging; a partial run fails validation by design.

It proves, in one run:

* **Refusal before admission.** A head carrying `x-agent-tunnel-owner` is refused with 400. The relay's `ingress_rejected_before_admission` counter rises by one, and the ingress exchange count, owner stream count, owner exchange count and handler invocations stay unchanged.
* **Seven rotation points.** Each case's HTTP stream is seen by the owner at a completed rotation, captured at QUIESCE and recorded at the COMMIT decision:
  * `head`: request HEAD only, at a record boundary;
  * `partial-header`: 3 bytes into a BODY record header;
  * `partial-body`: inside a BODY payload;
  * `end-before-fin`: END sequenced, FIN not;
  * `early-response`: response HEAD while the upload is unfinished;
  * `credit-stall`: a 6 MiB download the consumer does not read, with the owner receive buffer above half its window;
  * `sse`: across two distinct rotations, with event bytes split inside a UTF-8 character and inside delimiters.

  The three in-record positions are reached with the owner relay's one-shot fixture hold, released once the observation exists. For every case, the observation's relay fence must equal the owner's frozen `last_emitted`, both acknowledgement cursors must reach their fences, and the new generation must be newer. The handler must be invoked once, and the device must log exactly one HEAD and one END followed by FIN. The consumer must get 200 with an exact body (a SHA-256 digest for uploads, exact bytes for downloads and SSE) that ends cleanly. Neither the device nor the ingress may record an error or progress-budget expiry, and the owner must publish `STREAM_FORGET`.
* **CANCEL racing a queued RESET.** The data socket's connector→relay bytes are paused after the handler emits one more chunk, so the next rotation freezes and cannot drain. The consumer then disconnects. The handler's cancellation must be observed while the owner is still frozen. The owner must hold `RESET(CANCELLED)` unsequenced behind the freeze and send a scoped `CANCEL`, and the device record must show `cancel_received`. After release, the owner's RESET sequence must be exactly the rotation's relay fence + 1, on the new generation. Device and ingress must record `HTTP_CANCELLED`, and the stream must be forgotten.
* **Lost acknowledgement and owner loss.** A synthetic side-effect handler blocks after incrementing its counter. The gate then either blackholes relay-a→relay-b for a request entered through relay-b, or shuts relay-a down for one entered through relay-c. Either way the handler count must be 1 before the fault and still 1 at the outcome. The consumer must get a 5xx body whose code and `execution: unknown` map to `outcome_unknown`, and the ingress exchange record must show `unknown` execution.
* **No extra sockets.** Every settled steady state has exactly two device TCP connections, and the peak before owner loss is at most three. The session ID is unchanged and at least 9 rotations complete.

The fixture's signed membership records live 60 s. A newer record version invalidates in-flight peer hops, so the gate re-signs only at case boundaries, at most every 15 s. After each re-sign it waits for relay-c and relay-b to answer `/ping`, and for the owner to reclaim those pings. Its record, credit-stall and FIN-after-END budgets are 60 s, and a compile-time assertion keeps them above the 44 s bound it waits for one observation, so no case can fail on its own budget first. `M3_ROTATION_RESIGN_SPACING_MS` overrides the re-sign spacing only to reproduce defect M7-C81 in [tasks.md](tasks.md); a run with it is not gate evidence, and the evidence validator refuses any run whose recorded `resign_spacing_ms` is below 15,000. See "Not proven by gate 4" in [http-forwarding.md](http-forwarding.md#pinned-in-code-gate-4) for what this gate does not cover.

## MCP through the real cluster (`verify-m3-mcp-cloud-client`)

```sh
TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/m3-harness-verify.sh
cargo run -p tunnel-test-harness --locked -- verify-m3-mcp-cloud-client
```

M3-03. The gate runs the pinned official Rust MCP SDK (rmcp 3.4.0) as a cloud consumer against the three-relay production cluster: every request carries the consumer bearer token into relay-c's public route, crosses the peer HTTP/3 hop to the owner relay-a, the rotating device data WebSocket and `tunnel-client`, which serves the MCP exports it registers from its own `[exports.<service>.mcp]` configuration, exactly as `tunnel-client connect` does. The relays serve both profiles from a `ServeConfig [http_forward] profiles` table, and each of the four seeded catalog services selects its profile through the `http_forward_profile` capability. The device runs the same short rotation policy as gate 4 (interval 6 s, handshake 2 s, overlap 5 s). A run takes about 160 s.

The desktop fixture is `tunnel-mcp-fixture`: a stdio child per export (one child per request for `mcp-2026-07-28`, one per session for `mcp-2025-11-25`) or its rmcp Streamable HTTP server as a separate loopback process. rmcp 3.4.0 has no TLS client without `reqwest`, which this workspace does not pin, so the gate puts rmcp's own Unix-socket HTTP client behind a byte-copying TLS sidecar: it parses no HTTP, so every header, body byte and disconnect the relay sees is rmcp's.

It runs seven cases for each of the four combinations (stdio and Streamable HTTP × both profiles), each with a fresh client:

* **discovery** — `server/discover` (2026) or `initialize` (2025) exactly once, `tools/list` once listing every fixture tool, and one `echo` whose arguments, `_meta` (including the 2026 per-request protocol version) and image block come back exactly. 2025 must carry `Mcp-Session-Id`; 2026 must not.
* **notifications** — six progress notifications during a call, then five `notifications/message` logs. The wire order (recorded by the client's transport ledger) must be 1..6 and seq 0..4; the client handler proves the multiset only, because rmcp may run notification handlers concurrently. For 2026 the logs arrive on the call's own response stream and no standalone GET is opened; for 2025 they arrive on the standalone GET stream.
* **cancellation** — the client cancels a running `sleep`. The server must record the cancellation, no result or error may be delivered for that call, a later call must work, and for a stdio export the synthetic descendant the tool started inside the child's process group must be gone. For 2026 stdio the bridge must have written exactly one `notifications/cancelled`; for 2025 the client's own `notifications/cancelled` POST must have been forwarded; for 2026 the owner stream ends with `RESET(4005 CANCELLED)` (the Streamable HTTP backend may instead end with the device's FIN first: which terminal the owner records is a race).
* **crash** — the backend exits after its first progress event. The call must fail with an error that never contains the fixture's stderr marker, the tool must have run exactly once with no result delivered, and a later call must work: for 2026 stdio on a fresh child, for 2025 after the session's 404 and one re-initialization (the operator's supervisor restarts an HTTP backend; the export never does).
* **rotation-discovery** and **rotation-invocation** — a held `tools/list` and a held `gate` call are each observed by the owner at a completed rotation while the request was fully sequenced and no response had ended, with the fences accounted for, then answered exactly. Each dispatches once.
* **streaming** — 48 progress events of 4 KiB each, gated after events 11, 23 and 35 so the owner observes the open response at three distinct rotations. The events must be byte-exact and in wire order (compared by SHA-256 over the messages in arrival order), the result exact, the tool invoked once, and neither the device nor the ingress may record an error.

Every case's evidence is validated by `validate_mcp_cloud_client_evidence` (`production_cluster/mcp_cloud_client.rs`), re-run at the command boundary; its unit test rejects every listed single-rule mutation of passing evidence. Correctness comes from owner rotation observations, owner and device diagnostics, MCP export counters, fixture marker files and the transport ledger; the gate never uses a fixed sleep as a signal. `M3_MCP_COMBOS=stdio-2026,…` and `M3_MCP_CASES=discovery,…` select work while debugging; a partial run fails the completeness rules by design, after reporting any case rule it broke.

A device session is stopped only once its rotation state is settled: one run in fifteen stopped a session inside a rotation attempt and its `ConnectionHandle::stop` failed the stream-forget barrier with `data writer stopped before barrier completion`, the same connector diagnostic two earlier survey failures produced. That diagnostic is spurious for a requested stop, recorded as defect M7-C84 in [tasks.md](tasks.md); the wait narrows the window rather than removing it. It is bounded, it does not hide a stop failure, and a failing stop reports the device phase it stopped in.

Records are always matched by operation ID as well as stream ID: each combination runs on its own device session (stream IDs restart, and the owner's bounded diagnostics outlive a session). One session per combination started as the workaround for defect M7-C82 in [tasks.md](tasks.md), where a session admitted at most 128 streams in its whole lifetime and then died. That ceiling is gone: the connector releases an OPEN journal entry at the [OPEN retry horizon](protocol.md#open-retry-horizon-and-journal-reclamation), and `verify-m3-http-forward-real-path` proves one session serving 160 sequential streams past it. This gate keeps one session per combination as its own scoping choice — it isolates each profile/transport combination's stream IDs and export children — so its `highest_call_stream_id < 128` rule is retained as a cheap invariant of that scoping rather than as evidence about the product ceiling, and is no longer the reason the arrangement exists. The defect row's own reproduction was re-run once against the fixed connector, with `connect_device` temporarily hoisted out of the combination loop and that rule and the per-combination child rule temporarily relaxed: one device session served all four combinations and all 28 cases across 51 rotations, reaching call stream ID 141 with the session stable throughout, and the run then failed only on this gate's own bookkeeping rule that there is one session per combination. That patch was reverted and is not part of the gate. The validator also requires no MCP export child to be left running after its session stopped. Membership records live 60 s, so the gate re-signs at case boundaries at most every 15 s (defect M7-C80), waits for every relay's peer readiness and for two consecutive device answers to a `GET /mcp` (405 from the device export), and records the oldest age any case ended at.

Because the relay pauses new stream admission during a rotation freeze, a POST can be refused with a retryable `503 PEER_UNAVAILABLE` `not_dispatched`, and rmcp does not retry it. The relay answers *every* owner-not-ready condition with that same body — a freeze, but also a missing active carrier, an unfenced owner or an unknown owner write — so the body alone cannot say which it was. The gate therefore watches the connector's own rotation phase (`quiescing`, `draining`, `committing`) and resends such a refusal only while that watch says a rotation is frozen, or within 750 ms of one. The resend cap is derived from the gate's own rotation policy rather than fixed: a freeze ends when the attempt commits or its handshake budget expires, so the cap is that budget at the relay's smallest hint (250 ms) plus four, which is 12 for this policy, and a slow-but-legal drain cannot fail a call. A refusal outside a freeze is never resent, so it fails its call and the gate with it; because the owner freezes before the connector sees `ROTATE_QUIESCE`, such a refusal records the connector's phase, completed rotation count and time since the last freeze, and that cause is printed with the evidence. Every case's POST and standalone-GET refusal and retry counts are printed and validated: refusals must equal retries in both, stay within the same bound, and no unexplained refusal may be recorded. The coincidence window, the derived cap, the unexplained-cause report and the refusal parser have their own unit tests; a refusal is rare and timing-dependent, so there is no cluster red-then-green for them. See M3-15 in [tasks.md](tasks.md).

**Red-then-green.** Each guard was removed, the affected cases re-run, and the guard restored:

* not writing `notifications/cancelled` to a 2026 child and not forwarding a 2025 client's `notifications/cancelled`: both stdio cancellation cases reported `server_observed_cancel=false`;
* making the stdio child's process-group kill a no-op: every stdio cancellation and crash case reported `descendant_killed=Some(false)`, and the four synthetic descendants outlived the run;
* replaying a 2026 request on a fresh child when the first child ends: the crash case reported `invocations=2` and two `before-crash` progress events on the wire;
* leaking a finished 2026 child instead of reaping it: the combination reported `children_running_after_stop=3` after its device session stopped.

See "Not proven by M3-03" in [mcp.md](mcp.md#pinned-in-code-m3-03) for what this gate does not cover.

## MCP isolation, correlation and unknown outcomes (`verify-m3-mcp-isolation`)

```sh
TEST_REDIS_URL=redis://127.0.0.1:63790/ scripts/m3-harness-verify.sh
cargo run -p tunnel-test-harness --locked -- verify-m3-mcp-isolation
```

M3-04. The gate runs on the same three-relay production cluster and the same
short rotation policy as the M3-03 gate (interval 6 s, handshake 2 s, overlap
5 s), against the same `tunnel-mcp-fixture` stdio server, but with **two
distinct authenticated principals of one tenant** — `consumer-a-1` and
`consumer-a-2`, each with its own bearer token and its own grant on the same
device and services — a **third principal** (`owner-a`) that exists only
to have its grant revoked, so revocation cannot disturb the other cases, and a
**fourth of another tenant entirely** (`consumer-b-1`), whose token is valid
and whose grants are real but hold in tenant B only. The device also exports a
**Streamable HTTP** service (`http-2025`) alongside the two stdio ones, backed
by a single shared `tunnel-mcp-fixture` HTTP process the gate starts itself. A
run takes about 40 s.

Its client is raw HTTP, deliberately. M3-03 already pins the official rmcp
client end to end; this gate has to send what a conforming client never sends:
another principal's session ID, deliberately colliding JSON-RPC IDs and
progress tokens in both directions, and a request whose acknowledgement is
lost. It therefore builds every message itself and reads every answer as
bytes. Everything else on the path is production: relay-c's public route, the
peer HTTP/3 hop, relay-a's owner actor, the rotating device data WebSocket and
`tunnel-client`'s configured `[exports.<service>.mcp]` stdio exports.

All eight cases run on **one device session** (defect M7-C82 is fixed), up to
the owner loss that necessarily ends it, and membership is re-signed at case
boundaries at most every 15 s (defect M7-C80).

* **binding-forgery.** The consumer sends `tunnel-principal-binding` itself,
  on both profiles and all three routes, once with a single value and once
  with the header repeated with two different values: twelve attempts, each
  refused `400 HTTP_INVALID_HEAD` `not_dispatched`, each counted as an ingress
  rejection by relay-c, and zero device dispatches. This is the whole basis of
  the unkeyed design — because a consumer can never put the header on the
  wire, the digest does not have to be secret — so it is a gate case and not
  only a unit test. (Header names are lowercased by the HTTP parser, so every
  spelling a consumer can send arrives as the same key; the relay unit test
  `a_consumer_supplied_principal_binding_is_refused` pins that.)
* **session-isolation.** Each principal opens its own `mcp-2025-11-25`
  session. Consumer B then presents consumer A's session ID on POST, GET and
  DELETE: all three must answer 404, and each answer must be indistinguishable
  — status, every response header except `date`, and the body bytes — from the
  same route's answer for a session that never existed, so a leaked ID neither
  works nor reveals that the session exists. Both sessions
  must still answer exactly afterwards. Each principal then opens its
  standalone GET stream and calls `log` with its own label, concurrently and
  with the same JSON-RPC ID: each stream must carry exactly its own four
  `notifications/message` and none of the other's. Exactly two sessions and
  two children were opened, so a refused request never spawned one.
* **streamable-binding.** The same rule as `session-isolation`, over the same
  real cluster, but against the **Streamable HTTP** export instead of a stdio
  one. This is the case that separates the binding from process isolation: the
  stdio export gives every session its own child process, so a foreign session
  ID failing there has two possible explanations, while a Streamable HTTP
  backend is an address the export forwards to — one process, one session
  table, shared by every principal — so the binding is the only thing that can
  refuse it. The gate asserts that shape rather than assuming it: the export
  must spawn no per-session child. It does keep a per-session binding table —
  `SessionBindings::permits` is exactly what refuses the foreign principal,
  before the backend is dialled — so what the case rules out is a *process*
  boundary and the backend itself doing the refusing, not an export-side
  session object. The stdio session counter reads zero here only because it
  is never incremented for this backend kind.  Each principal opens a session
  through the cluster, consumer B presents consumer A's session ID on POST,
  GET and DELETE, all three must answer 404 indistinguishably from an unknown
  session, and both principals' own sessions must still answer exactly
  afterwards. Each principal then ends its own session, and the end is checked
  by the session becoming unusable — a reused ID answering 404 — rather than
  by a status code, because this backend acknowledges a DELETE with 202 where
  the stdio export answers 204, and an acknowledgement is not evidence. Before
  this case, M3-04 proved the Streamable HTTP binding only through
  `tunnel-mcp-fixture`'s in-process bridge.
* **cross-tenant.** `consumer-b-1`, fully authenticated and genuinely
  authorized in tenant B, drives tenant A's device and MCP service: one
  `initialize`, and then tenant A's *live* session ID on POST, GET and DELETE,
  each paired with the same route naming a session that never existed. All
  seven must be refused with a 4xx and `not_dispatched` — never `unknown`,
  which would mean the relay could not rule out that a foreign tenant's
  request reached this tenant's device — and each live/absent pair must be
  indistinguishable, so a refusal never tells a foreign tenant which of this
  tenant's sessions are live. Observed: `404 DEVICE_NOT_FOUND`
  `not_dispatched` on all seven. Nothing may be dispatched, no export session
  may be opened, the device exchange log may not grow, and tenant A's own
  session must still answer exactly afterwards. Tenant separation for the echo
  path is M7 admission evidence; this drives it for an MCP export, where a
  session ID is an extra handle a foreign tenant could try.
* **correlation.** Both principals issue the six colliding JSON-RPC IDs of
  `COLLIDING_IDS` at once — including `9007199254740993` and
  `9007199254740994`, which a JSON implementation reading IDs as doubles would
  collapse into one — first against the sessionless `mcp-2026-07-28` export
  and then on their own `mcp-2025-11-25` sessions, where they also reuse the
  same progress-token values across sessions and principals. All 24 answers
  must carry their own caller's ID and echo their own caller's arguments; none
  may be misrouted. A `progress` call on each session with one shared token
  must see its own 1, 2, 3. A genuine duplicate — the same ID, and separately
  the same progress token, while the first is still in flight on one session —
  must be refused with 400.
* **revocation.** The third principal opens a session, is answered once, and
  holds a call in the fixture. Its grant is then revoked in Redis. A fresh
  request must be refused with `404 SERVICE_NOT_FOUND` and `not_dispatched`
  (a transient `503 PEER_UNAVAILABLE` is retried, so a rotation freeze cannot
  be mistaken for a revocation), nothing may be dispatched to the device
  afterwards, and the *admitted* exchange must be withdrawn within five
  seconds with a typed interruption rather than a result. Observed: refused in
  about 10 ms, withdrawn in about 500 ms, `502 HTTP_STREAM_INTERRUPTED` with
  `execution: unknown` — the tool had already been dispatched, so neither a
  result nor a claim that nothing ran would be true. The recorded blast radius
  is exactly that: the other principals' sessions still answer and the device
  session survives. The revoked principal's own device-side session is *not*
  ended; it simply becomes unreachable, and its child holds a `max_children`
  slot for as long as the device session lives, or until
  `session_idle_seconds` (M3-16). The Streamable HTTP export has the same
  setting for its own session table, so an abandoned session there is
  forgotten rather than held for ever.
* **rotation-span.** One call is held open until the owner has completed three
  scheduled rotations, then released: it must answer 200 exactly once with the
  fixture's exact text, on the same device session, with one dispatch. This
  case is also the validator's control for the revocation withdrawal above: an
  identical held call that is never revoked stays open far longer than the
  five-second withdrawal bound and is answered.
* **unknown-outcome.** A call is held until the fixture has appended its
  invocation to `invocations.log` — the synthetic side effect, which has then
  provably run exactly once. The gate then blackholes the owner→ingress peer
  path, and in a second round shuts relay-a down. Either way the consumer must
  get a 5xx whose `{code, execution}` maps to `outcome_unknown`, the side
  effect must still be recorded exactly once at the outcome, and nothing may
  be retried or replayed. The side effect is counted at an observed event, not
  after a sleep: the lost-acknowledgement round settles when the device has
  finished and recorded that exchange (a replay would be a second record,
  matched by stream ID because the connector's log is bounded), and the
  owner-loss round settles when the connector leaves readiness, because the
  device session a replay would need is gone with it. Each round records which
  event it settled on, and the validator requires the expected one.

**Known failure, about 1 in 6 runs on `main`.** This gate is not reliably green
and must not be read as a pass/fail signal for an unrelated change. The failure
is always the `unknown-outcome` case: the consumer's POST is answered
`503 PEER_UNAVAILABLE` with `execution="not_dispatched"` about 14 ms after it
was issued, the ingress relay carries exactly one
`ingress/pool_connect/transport_pins_unavailable` fault tuple, **no** relay
carries an owner-role tuple, and the run carries exactly one
`membership pin publication failed closed` warning. That is a membership
re-sign racing the periodic reconcile, which leaves the runtime briefly unready
and withdraws the whole transport pin set, so a fresh dial to the owner is
refused before any I/O. The fix is known and is held back as **M7-C86** because
it regresses `verify-m7-trust-expiry`; with it applied this gate is 12 of 12,
without it 10 of 12. See the M3-04 and M7-C86 rows in [tasks.md](tasks.md).

Evidence is validated by `validate_mcp_isolation_evidence`
(`production_cluster/mcp_isolation.rs`), re-run at the command boundary; its
unit test rejects every listed single-rule mutation of passing evidence.
Correctness comes from HTTP statuses, response headers and bodies, MCP export
counters, fixture marker files, device exchange records, connector readiness,
owner session snapshots and the connector's OPEN journal occupancy. No sleep
is a correctness signal: the standalone GET streams are opened and their heads
answered before either call starts (the answered head is the device's own
signal that the session's standalone stream is registered), and each unknown
outcome is counted at the settle event above. Sleeps appear only as the poll
interval of bounded waits on those signals. The OPEN journal peak is
sampled continuously from the connector's status watch and must stay within a
bound derived from the case concurrency — the correlation case issues two
adjacent bursts of `CORRELATION_CALLS * 2` streams and the second can begin
while the first's `STREAM_FORGET`s are still in flight, so both may be
unreclaimed at once: `CORRELATION_CALLS * 4` = 24 — not from the roughly
seventy streams the run serves on that one session; observed 12 to 18 across
six runs. The gate ends
every session it can with DELETE; exactly two cannot be ended (the revoked
principal's, whose DELETE the relay refuses along with everything else it
sends, and the one whose owner relay was killed), and **no** export child may
be left running once the connector stops, because dropping the connector's
handler registry ends every session its exports still hold.

**Red-then-green.**

* Removing the owner's re-derivation and comparison
  (`OwnerRequestWriter::validate`): a head carrying another principal's
  binding, and a head carrying none, both reached the device. The owner test
  `the_owner_verifies_the_principal_binding_it_derived_itself` fails on both.
* Removing the ingress refusal (`refuse_consumer_principal_binding`'s guard):
  the relay unit test fails, and with the handler's call site removed the
  `binding-forgery` gate case reports admitted attempts and a nonzero device
  dispatch.
* Removing the export's session shutdown (`StdioExport`'s `Drop` and
  `shutdown_sessions`): `an_unended_legacy_session_dies_with_its_export` and
  `shutdown_ends_every_open_legacy_session` fail with the wrapper's grandchild
  outliving its process group, and the gate reports `children_after_stop=2`.
* Restoring the Streamable HTTP export's oldest-first eviction:
  `one_principal_cannot_evict_another_by_opening_sessions` fails — one
  principal's 257 `initialize` calls drop another principal's live session.
* Removing the device's principal-binding check on legacy sessions
  (`tunnel-mcp-export/src/stdio.rs`): consumer B's POST, GET and DELETE on
  consumer A's session ID were accepted with 200, 200 and 204 — B could read
  A's session and end it — and the gate failed with
  `another principal's session ID was accepted: post 200 get 200 delete 204`.
  The same removal fails the `tunnel-mcp-fixture` `principal_binding` tests
  for both export kinds.
* Disabling the Streamable HTTP export's binding comparison
  (`SessionBindings::permits` accepting any binding for a known session):
  consumer B's POST, GET and DELETE on consumer A's Streamable HTTP session
  were accepted with 200, 200 and 202, and the gate failed with
  `a Streamable HTTP session ID was accepted for another principal: post 200
  get 200 delete 202`.
* Driving the `cross-tenant` case with `consumer-a-2` — a principal of *this*
  tenant holding a real grant — instead of `consumer-b-1`: the gate failed
  with `a cross-tenant consumer was not refused before dispatch on every
  route: 0 of 7 refused, initialize 200`. The case therefore detects an
  admitted consumer rather than passing because every request happens to fail;
  its green result is the tenant boundary doing the work. A defect injected
  into tenant scoping itself would be the stronger red, but the catalog's
  grants are tenant-scoped by construction and cannot be seeded across
  tenants, so this is the red the fixture can express.
* Skipping the `revoke_grant` call in the revocation case: the fresh request
  was still served, the case ended on an unrelated transient
  `503 PEER_UNAVAILABLE`, and the gate failed with
  `a fresh request after revocation is refused, not dispatched`. That run also
  showed the held call ending anyway at about 30 s on the exchange's own
  progress deadline, which is why the withdrawal now has its own five-second
  bound and the rotation-span control.

See "Not proven by M3-04" in [mcp.md](mcp.md#pinned-in-code-m3-04) for what
this gate does not cover.

## MCP and computer-use integration

For MCP, test against a pinned SDK/server fixture with initialization, negotiated capabilities, request/response correlation, notifications, cancellation, concurrent calls, structured errors, and streaming behavior for each supported transport profile. Exercise a long-running request across rotation. Confirm that MCP session state and its lifecycle follow the adapter contract instead of being inferred from the lifetime of one data WebSocket. Keep other exposed capabilities functional while MCP work is active.

The M3-01/M3-02/M3-04 suite runs with the ordinary workspace test command. It is not a harness gate and needs no Redis or network, only loopback and a temporary Unix socket:

```sh
cargo test --locked -p tunnel-mcp -p tunnel-mcp-export -p tunnel-mcp-fixture
```

`tunnel-mcp-fixture` builds the synthetic rmcp 3.4.0 server binary. Its `rmcp_stdio`, `rmcp_http`, `export_guards` and `principal_binding` tests run the pinned rmcp client through the in-process gate-2 bridge against the stdio export and the Streamable HTTP export, for both `mcp-2026-07-28` and `mcp-2025-11-25`. [mcp.md](mcp.md#pinned-in-code-m3-01-and-m3-02) lists what they cover and what they do not. `principal_binding` covers the M3-04 session binding for both export kinds through that bridge; over the real cluster, `verify-m3-mcp-isolation` now drives both kinds too — the stdio exports in `session-isolation` and the Streamable HTTP export in `streamable-binding`. The end-to-end tests are `cfg(unix)`. The same fixture binary is the desktop server of the real-path gate above.

For CUA, pin each supported backend profile separately. Use recorded synthetic contract fixtures or fake local servers in ordinary CI. The Python computer-server profile requires tests for its `/cmd` response format and its sequential `/ws` request behavior without correlation IDs. There is exactly one pinned profile — `cua-computer-server` 0.3.46 over `/cmd`, recorded in [sources.md](sources.md#just-bash-and-cua); the Rust `cua-driver` profile named here earlier is withdrawn, because `cua-driver` is not a published crate and the driver is reached as an optional extra of that same Python server. Capability discovery still needs its own test per backend, because the released server filters its command registry by backend. Tunnel credentials must not be forwarded as CUA cloud credentials.

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

## Dependency, licence and secret checks (`scripts/m6-release-checks.py`)

The M6-04 release gate. Four checks, each of which can be selected alone with
`--check <name>`:

| Check | What it enforces | How it can fail |
| --- | --- | --- |
| `deps` | `cargo-deny` **0.19.6** against `deny.toml`: a fail-closed licence allowlist, `sources` provenance, and `bans`. | An SPDX expression that cannot be satisfied from the allowlist; a non-crates.io registry or git source; fewer than 300 crates resolved; a patched crate absent from the graph; fewer than 24 workspace members in the checked set; a cargo-deny version other than the pinned one. |
| `provenance` | `Cargo.lock` integrity and the three `[patch.crates-io]` crates under `vendor/`. | A registry package with no checksum; any git source; a vendored crate with no LICENSE text, no `license` field, or no `UPSTREAM_PATCH.md`. |
| `secrets` | 18 credential patterns across **every blob reachable from every ref**, plus the modified, untracked and renamed working tree. | Any match that is not an allowlisted digest; fewer than 1,500 blobs scanned; **any blob over the 64 MiB cap**; an allowlist entry with no reason or that matched nothing. |
| `visibility` | The `origin` repository's GitHub visibility. **Read-only** -- it never changes a setting. | The repository is not private. A missing token or `gh` reports DID NOT RUN, which is exit 2 and is *not* a pass. **Expected to fail today** while the repository is public (M6-C01). |

Four properties are worth knowing before reading a green result:

- **Licence policy scope is every target, not the release targets.** `[graph]
  targets` in `deny.toml` is deliberately empty, which in cargo-deny means the
  union of all platforms. The only crate in this workspace with a copyleft
  branch (`r-efi`, `MIT OR Apache-2.0 OR LGPL-2.1-or-later`) reaches the graph
  only through `getrandom`'s UEFI backend, so narrowing the target list would
  remove the one interesting case from the scan.
- **Secret findings are reported by SHA-256 digest, never by content.** A
  finding names its pattern, path, blob and digest. Reviewed exceptions are
  keyed on the digest of the matched bytes rather than on a path, so an
  exception excuses one value and a different secret in the same file is still
  reported.
- **The advisories check is not part of this gate.** It needs a freshly
  fetched RustSec database; `deps` prints the local database's age and the
  words `NOT RUN` rather than folding a stale green into the pass. See M6-C03.
- **What `0 findings` does and does not mean.** Every pattern is anchored
  to a known credential format -- a vendor prefix, a URL authority, Redis's
  `requirepass`, an Authorization header. The scanner does **not** detect
  generic assignments beyond the AWS and Redis spellings, raw high-entropy
  or hex blobs, or credentials that were never committed here (deployment
  secrets, relay identities, out-of-band Redis credentials). So a zero means
  "no secrets **in these formats**", not "no secrets", and the check prints
  its coverage line beside the count so the two are never read apart. The
  omissions are deliberate: an entropy scanner over a repository full of
  synthetic keys and base64 protocol frames produces a finding list nobody
  reads, and an unread list is indistinguishable from a clean one.

`--self-test` runs the **eleven positive controls**, each of which plants a
synthetic case and requires the corresponding check to go red: the licence
policy rejecting a licence removed from the allowlist (asserted on cargo-deny's
rejection count and verdict, not merely on a non-zero exit); the crate floor
rejecting a collapsed count and accepting the live one; every secret pattern
matching each of its fixtures and none matching benign text; a credential
committed and then deleted still being found in history; uncommitted and
**renamed** working-tree files being scanned; a `--depth 1` clone falling below
the blob floor; the scanner not matching its own source; and a digest exception
not suppressing a different secret in the same file.

The CI job is ordered to run `--self-test` **before** the checks, so a scanner
that has stopped working fails the job instead of passing it quietly. **That
job has never executed on a hosted runner** -- GitHub Actions billing has
blocked this repository's CI since 2026-09-11 -- so it is reviewed YAML whose
structure was asserted locally, not a green job. Its cargo environment *was*
exercised locally against an empty `CARGO_HOME`: without `cargo fetch --locked`
the `--offline` checks fail with no summary record, and with it they pass at
361 crates, which is why the fetch step exists.

Run the checks against a full-depth checkout. Under a shallow clone
`git rev-list --objects --all` returns one commit's objects, and the history
scan would report zero findings over almost nothing; the CI job sets
`fetch-depth: 0` and the blob floor is the backstop.

**`--all` covers every ref this clone has, which is not the same as every ref
the remote has.** A branch that exists only on the server, or a stale local
copy of one, is outside the scan. Run `git fetch --prune --all` first when the
result is being used as a release gate rather than a spot check; CI's
`fetch-depth: 0` checkout satisfies this for the refs it fetches.

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

**"Every advertised OS/architecture" has no referent in this repository, and that is a prerequisite defect rather than a detail.** No document, `Cargo.toml` key, release note or CI file declares a supported OS/architecture set. The closest thing is `.github/workflows/ci.yml`'s `os: [ubuntu-latest, macos-latest, windows-latest]`, which names three *runner labels* and no architecture at all, and `deny.toml` refers to "the advertised release targets" as though the set existed. Until an owner declares it, this gate's scope cannot be evaluated: a run cannot be complete against an unspecified set, and any claim that it is complete is a claim about a set the claimant chose. See [tasks.md](tasks.md) row M6-C04, which also records what this host can and cannot build.

`scripts/m6-release-artifact.py` produces and checks a release bundle **for one target triple, the one it runs on**, and says so in the bundle's own `PROVENANCE.txt`. `bundle` assembles `bin/` (`tunnel-client`, `tunnel-relay`, and `tunnel-deadman` — the parent-death sentinel, which is a *required runtime asset* rather than a product command), the configuration examples, `LICENSE`, the `Cargo.lock` the build resolved, a generated `NOTICE`, a `PROVENANCE.txt` cross-checked against the `m7-local-source-parity-build.sh` receipt, and `SHA256SUMS` — then writes a `.tar.gz` and its own digest. `verify` accepts either the directory or the archive; given the archive it **extracts it into a temporary directory and checks that**, so the gate's "unpack into clean temporary environments" step is performed rather than assumed, and file modes and completeness are exercised as a recipient would meet them. `verify` runs six checks against the unpacked bundle, never through `cargo run` and never against `target/`: `checksums`, `provenance`, `notices`, `assets`, `cli` and `portability`. `cli` runs the help and version probes, both `check-config` forms, **and `check-serve-config` on every bundled `*-relay.toml`** — the last because this workflow's own comment records that legacy `check-config` parses a different type and cannot validate a serving document, so an example that fails relay startup would otherwise ship green; it carries its own witness so a control corrupting a client example cannot credit it. Three of them exist because of a failure the others cannot see. **`notices` carries the licence texts themselves, generated rather than written**: the full text of every licence file the crates ship is embedded verbatim between delimiters — 628 files, **3,145,598 bytes** at `ec663a7`, each block carrying its own SHA-256 in its opening marker and **re-hashed at check time**, so "byte-exact" is a measurement rather than a word — because MIT, the BSD family and Apache-2.0 require the notice and text to *accompany* a binary distribution, and a SHA-256 discharges nothing owed to the recipient. An earlier version of this file recorded only SPDX identifiers and digests, which made the check green against a deliverable that did not do what notices exist for. The crate set and the embedded texts are both re-derived at check time from the `Cargo.lock` shipped beside the NOTICE, counted from the delimiters rather than read off the header, so a hand edit, a lockfile that moved underneath it, a NOTICE quietly reduced to identifiers, **or a block replaced by filler of exactly the same length** all fail — the last of these is invisible to a count and a byte total, which is why the digests are bound rather than merely printed; every lockfile crate must be either notified or explicitly listed as outside the resolved dependency graph, so the subtraction is never silent. **`assets` replays the product's own resolution rule and then executes the result**, rather than testing for a file: `tunnel_deadman::resolve_sentinel` looks for the sentinel beside `current_exe()`, and its absence is a `degraded` doctor capability plus a one-line warning the first time an export arms one, so a bundle that omits it ships working binaries with containment off and nothing in the help, version or config surfaces showing it. It does **not** ask `doctor`. When this check was written it could not: `doctor` computed the capability checks and then discarded the whole result whenever any error was present, so a fresh bundle returned `CREDENTIAL_MISSING` with `result: null`. That is fixed — `DoctorOutput::result` is no longer an `Option` and the checks are reported on every path (row M6-C07) — and this check still does not ask, now for a better reason: `doctor`'s containment answer comes from `availability()`, which is satisfied by `resolve_sentinel`'s bare `is_file()`, so asking would make the release gate inherit a product defect instead of catching it. Executing the sentinel is the stronger check regardless: `resolve_sentinel` accepts any `is_file()`, so a zero-byte or non-executable decoy of the right name makes the product itself report the sentinel present, and only running it tells a present file from a working one. The check is deliberately **behavioural, not an identity check** — a decoy that also exits 2 passes it, and the bytes are bound by `checksums` and `provenance` instead; a control measures that seam by requiring `assets` green and `checksums` red on exactly such a decoy, so the layering is demonstrated rather than claimed. **`portability`** requires every bundled executable's dynamic dependency to resolve under `/usr/lib` or `/System` — and nothing else, `@rpath`, `@executable_path`, `@loader_path`, `/usr/local/lib` and `/opt/homebrew` included, since each resolves off the build machine or not at all on a clean one — because a binary that links back into the build tree runs perfectly here and nowhere else, and is green under every other check. The `cli` and `assets` probes additionally run with `PATH` narrowed to the system directories and every `CARGO_*`/`RUST*` variable dropped, and the check **proves `cargo` is unfindable on that `PATH` before the probes run**, so the clean-environment property is measured rather than announced — and a control plants a `cargo` on that `PATH` and requires the check to refuse it, because a guard nothing exercises is a guard nothing tests. `--self-test` runs **twenty-one witness controls plus two unit probes**, reported as two figures: a witness control defeats a mechanism in a real bundle and requires the named check to go red **with the witness it planted**, while a probe exercises a pure function's rule in both directions and invokes no check at all. A red for another reason is reported as a wrong witness and fails, in the shape `scripts/m0-guard-exit-codes.py` established.

What this does **not** establish, stated because the gate's own sentence invites the opposite reading: one bundle is evidence for its own triple and no other; the gate's "launch the packaged relay and device for a real consumer-to-device operation and a rotation" clause is **not** covered by these six checks, which stop at help, version, config validation and capability reporting; and `macOS/Linux/Windows CI success is not by itself evidence for every architecture` remains true in the stronger form that this repository has no CI success at all while Actions billing is blocked.

For the local macOS-arm64 CLI scope of IN-10/OG-05, `scripts/m7-local-source-parity-build.sh` builds the workspace binaries from an immutable copy of the current `HEAD` source inputs (crates, vendor, examples, root Cargo metadata) and emits an immutable `source-parity-receipt.txt` tying the copied source digest to each binary's sha256. `scripts/m7-local-artifact-verify.sh --build-receipt <receipt>` then cross-checks that receipt — the recorded base `HEAD`, tracked-diff digest and worktree-status digest must equal the current checkout's, and every supplied binary's sha256 must equal the receipt's digest — and only then records `binary_provenance=verified` and source-to-binary provenance as verified; any mismatch is fatal, so provenance is never falsely claimed. Without `--build-receipt` the verifier still records provenance as unverified. **Both scripts assemble a `bin/` directory, and both used to assemble one without `tunnel-deadman` in it (M6-C06).** The sentinel is resolved relative to the client's own `current_exe()`, so it is a property of shipping the client rather than a packaging preference: a bundle without it ships a client that supervises children correctly and leaks their process groups on every crash, announced only by a one-line stderr warning the first time an export arms one and invisible to `--help`, `--version` and both config checks. The parity build now copies it; the verifier takes `--deadman-bin` and defaults it to the sentinel beside `--client-bin`, and fails rather than assemble a bundle without one. Both then call one shared assertion, `scripts/client-bundle-sentinel.sh` — shared as an assertion and not as a binary list, because the three assemblers legitimately carry different binaries and what they must agree on is narrower than any of their lists. It executes the file rather than testing for it, because `resolve_sentinel` accepts any `is_file()`, and it prints what it verified, so a pass and a call that never ran are not the same line. `scripts/m6-guard-client-bundle-sentinel.py` is the red-then-green evidence: **nine cases, seven red with the witness each declared and two documented green**, split into an `assembler` suite that edits the verifier and runs it for real and a `rule` suite that probes the assertion directly — separate because three of the rule's witnesses are unreachable through the verifier's own input validation, and a witness no case can reach is the defect recorded as instance fourteen of row M5-C11. The parity build's own copy line is anchored by that harness's `--check-anchors` but no case runs that script, because its assembly step sits behind a full workspace Cargo build; its red-then-green was measured by hand and recorded on the M6-C06 row rather than asserted here. Both scripts are single-host, local macOS-arm64, this-source-only observers; they make no release, other-OS/architecture, hosted-CI or full-M7-row claim, and neither builds nor mutates the original checkout. Drive the source-matched CLI into an acceptance gate by exporting `TUNNEL_CLIENT_BIN=<bundle>/bin/tunnel-client` (the verifier writes a `tunnel-client-env.sh` for this) so `verify-m7-production` and `verify-m7-chaos`/`verify-m7-i08-recovery-attempts` record heartbeat, liveness, bounded shutdown and no-reconnect-storm evidence against the exact receipt-matched binary.

## Survey stability, measured 2026-09-14

The full gate survey is not a stable pass/fail signal on this machine, and the
reason is worth stating plainly rather than discovering again.

Five consecutive surveys returned 75/75, 72/75, 73/75, 74/75 and 69/75, and the
failing gates were almost entirely different each time. Three findings came out
of chasing them:

* Some were real defects the survey deserves credit for: a peer transport
  reporting a clean remote close as a failure, a refused forwarded device
  attachment collapsing a shared peer connection, and a diagnostics scanner
  that correctly refused a vocabulary it had not been taught.
* Some were the survey's own doing: a 4 MB write timing out against a Redis
  carrying the rest of the run, and a failing diagnostics child whose stderr
  was discarded because the survey never set `C11_CHILD_FAILURE_DIR`.
* Some were the machine. One failure was a CLI killed with signal 9, which is
  memory pressure, not a product result. Disk reached 97% during this work.

Reducing the parallel lane from three jobs to two did **not** stabilise it: that
run still failed five gates, again a different five. So parallelism is not the
single cause and the cap is not the fix.

What follows from this: a single survey result is evidence about one run, not
about the branch. A gate that fails once should be rerun standalone on an idle
machine before it is called a defect, and a gate that passes once should not be
recorded as verified on that basis alone. Where a gate has been measured
repeatedly, the measured rate belongs in its row. The owner-local stream
capacity gate, for instance, fails roughly half of its standalone runs and its
earlier clean survey results were luck.

### Chaos gate startup flake, measured 2026-09-15

`verify-m7-chaos` sometimes fails before its scenario starts, with the owner CLI
exiting before production readiness and a typed `TRANSPORT_ERROR`. Measured
rates: zero failures in four consecutive standalone runs on an idle machine, and
one in three under six competing CPU hogs. It is a startup condition, not a
classification result: when it fires, no round has run.

It is recorded rather than fixed because it has not been reproduced under
instrumentation and the cause is not established. Do not read a single chaos
failure of this shape as a classification finding; rerun it standalone first,
and check whether the failure names a round.
