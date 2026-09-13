# M7 task-specific edge-case tests

This is the test-planning index for [M7 tasks](tasks.md#m7--relay-cluster-redis-membership-owner-routing-and-integration).
The [98-row acceptance matrix](m7-edge-cases.md) remains authoritative for each
case's applicability, required invariant, evidence, status and completion time.

Each task lists the cases it contributes to and the distinctions its tests must
preserve. References overlap deliberately: a single case can need component,
public-ingress, real-peer, process, adapter and artifact evidence from different
tasks. The number of referenced cases is not a promised closure count. M7-I10 is
the reconciliation gate for the complete matrix, not an additional set of cases.

## How to use the references

1. For every named case, read its complete matrix row and identify every required
   assertion and variant. Preserve Required, Analogous, Partial and N/A-with-boundary
   applicability; an excluded surface still needs its stated boundary proof.
2. Record which part this task proves and which part still requires another task
   or fixture. A completed component task retains its original narrow scope;
   linking it here does not silently widen or reopen it. Track missing integration
   work explicitly under M7-I10 and add a stable task before implementing newly
   identified work, following the task tracker's updating rules.
3. Share fixture setup where useful, but keep assertions and evidence attributable
   to each case. One test may prove several cases only when it independently
   exercises and asserts every case's full required scope. Separate test functions
   are not mandatory when equally precise evidence comes from named scenarios.
4. Establish a valid baseline and prove the intended fault or race occurred at
   the intended boundary. A startup error cannot stand in for a refresh fault;
   producer timeout cannot stand in for a physical writer timeout; readiness
   snapshots cannot stand in for restored route usability.
5. Preserve execution certainty and observability: queued bytes are not physical
   delivery; transport ACK is not application success; a partial response does
   not prove the backend did nothing. Use body-read/dispatch/effect counters,
   sequence/fence checks, resource/deadline observations and live siblings where
   the individual row requires them.
6. Record exact fixture/test/command, source revision or immutable source/build
   identity, binary provenance when relevant, observed assertions, outcome and
   bounded evidence location per case. Follow the matrix timing/reopening rules
   after relevant source or fixture changes. Passing a task, a broad summary flag
   or a shared fixture does not automatically verify its linked cases.

A compact evidence entry can use:
`case ID; task ID; fixture/scenario; build; fault precondition; observed assertions;
result; evidence path; remaining scope`.
Keep failed, partial, historical and complete results distinguishable.

## Per-task test scope

The case lists below are planning and regression references, not new assignments,
new acceptance results or a change to the main thread's execution order.

### M7-C01

Verify signed membership records, nonce-bound checkpoints, version/conflict rejection, key overlap, role/endpoint binding, and bounded records.

**Edge cases to test:** `FP-10`, `EC-010`, `EC-015`, `EC-017`, `EC-019`, `EC-035`, `OG-07`.

Component contribution: exercise valid and forged signatures, nonce/expiry, fresh/stale/equal-conflicting versions, bounded records, key overlap, and exact role/node/endpoint binding separately. Runtime refresh, live pooled-connection replacement, mixed protocol versions, and recovery need their own integration evidence; signed schema tests do not prove them.

### M7-C02

Verify Redis incarnation-scoped leases, retained epochs, presence/tickets, exact-token renew/release, revocation fencing, and durable catalog separation.

**Edge cases to test:** `FP-08`, `EC-004`, `EC-005`, `EC-014`, `EC-015`, `EC-020`, `EC-022`, `EC-026`, `EC-060`, `IN-04`, `OG-07`.

Catalog contribution: use real Redis for atomic concurrent claims, retained high epochs, one-use tickets, revocation, exact complete-token renew/release, and durable versus expiring state. Prove committed-but-lost replies with an independent read and command count. Local actor promotion, reconnect races, and rollback remain distinct integration assertions.

### M7-C03

Verify authenticated private HTTP/3 peer transport, ALPN/role/pin checks, bounded streams/bodies, cancellation, joined shutdown, and no fallback/0-RTT.

**Edge cases to test:** `FP-03`, `EC-017`, `EC-019`, `EC-028`, `EC-029`, `EC-033`, `EC-034`, `EC-045`, `EC-046`, `EC-048`, `EC-049`, `EC-050`, `EC-051`, `EC-052`.

Transport contribution: test actual QUIC/mTLS role/pin/ALPN failures, body and resource boundaries, canceled pool creation, absolute deadlines, independent duplex cancellation, and bounded joins. Prove each injected stage was reached. A transport-only pass cannot establish public routing, owner fencing, physical consumer-write timeout, or adapter outcomes.

### M7-C04

Verify strict request envelopes, one-hop owner routing, source/destination/scope matching, owner-side JWT validation, and redaction.

**Edge cases to test:** `FP-04`, `FP-05`, `FP-06`, `FP-09`, `EC-001`, `EC-003`, `EC-006`, `EC-007`, `EC-008`, `EC-017`, `EC-025`, `EC-041`, `EC-048`, `EC-049`, `EC-054`, `EC-063`.

Envelope/routing contribution: test exact tenant/principal/device/service and complete owner binding, authenticated source, one hop, owner-side credentials, and body digest/length. Exercise safe not-dispatched versus admitted/unknown retry decisions separately. Real ingress header stripping, body-consumption sentinels, upgrade races, and backend effect counts are additional proof.

### M7-C05

Verify owner actor registration, tenant-scoped duplicate handling, selected-tenant disconnect, owner fencing, and stale cleanup.

**Edge cases to test:** `FP-08`, `FP-09`, `EC-001`, `EC-004`, `EC-005`, `EC-020`, `EC-021`, `EC-022`, `EC-023`, `EC-024`, `EC-026`, `EC-060`, `IN-04`, `IN-08`.

Actor contribution: test duplicate claim refusal without changing the winner, exact-token cleanup, tenant-selected disconnect, retained epochs, and pending versus active registration. Delay claim, fence acknowledgement, and data attachment independently; component state transitions do not alone prove cross-relay readiness or reconnect safety.

### M7-C06

Verify cluster startup/readiness wiring, signed checkpoint refresh, configured Redis TLS, dynamic pins, and separate liveness/readiness.

**Edge cases to test:** `FP-10`, `EC-010`, `EC-011`, `EC-013`, `EC-015`, `EC-018`, `EC-019`, `EC-048`, `EC-051`, `EC-055`, `OG-07`.

Configured-process tests: vary identity/trust/checkpoint, Redis TLS/authority, approved peer bind, reachability and capacity independently. Assert livez/readyz, no premature dispatch, bounded failure/cleanup, and a successful fresh route after restoration. Stage-specific Redis diagnostics, stale boot/records, and deadline policy each require their own fault evidence.

### M7-C07

Verify peer returned-error cleanup and cancellation-drop cleanup through every exit path.

**Edge cases to test:** `FP-07`, `EC-029`, `EC-036`, `EC-037`, `EC-038`, `EC-043`, `EC-045`, `EC-046`, `EC-047`, `EC-059`, `EC-060`, `EC-061`, `IN-06`.

Cleanup contribution: cover returned errors and dropped/canceled futures before and after registration for control and data paths. Verify exact-generation release, joined tasks, single terminal classification, and unaffected siblings. Adapter reciprocal-close behavior, sequence cursor variants, and process faults require tests at those surfaces.

### M7-C08

Verify transport in-flight memory reservations, retained clones, release, and failed-reservation rollback.

**Edge cases to test:** `EC-028`, `EC-029`, `EC-032`, `EC-033`, `EC-034`, `EC-051`.

Memory contribution: test prefix/body/encoded-copy and retained-clone charges at exact limits and limit-plus-one, failed reservation rollback, repeated transfer, and release on error/cancel. Measure record-count as well as byte caps. Real blocked writers and tenant/device saturation remain integration cases.

### M7-C09

Verify the h3-quinn pending-read cancellation repair and sibling-stream isolation.

**Edge cases to test:** `EC-032`, `EC-045`, `EC-046`, `EC-050`, `EC-051`, `IN-06`.

Pending-read contribution: cancel a read at the affected h3-quinn boundary, prove cleanup and subsequent progress, and keep an independent sibling active. Do not treat canceled reads as evidence for late-frame validation, reverse-direction close delivery, or saturated pool behavior without those additional assertions.

### M7-C10

Verify fresh NoLiveOwner control admission, raw bearer forwarding, and single length-prefix echo framing.

**Edge cases to test:** `FP-02`, `FP-06`, `EC-007`, `EC-021`, `EC-024`, `EC-031`, `EC-041`.

Admission/framing contribution: exercise a genuinely absent owner, fresh authenticated control admission, preserved raw bearer for owner revalidation, and exactly one internal echo prefix. Separately test an existing but unready owner and a token change before upgrade; empty bodies must be distinguished from a failed or unpolled body.

### M7-C11

Emit payload-free success summaries with relay, tenant, owner, route, generation, fencing, revocation, and owner-death counters.

**Edge cases to test:** `EC-013`, `EC-027`, `EC-040`, `EC-061`, `IN-01`, `IN-05`, `IN-09`, `OG-02`, `OG-08`.

Diagnostics tests: record bounded relay/tenant/owner/route IDs, epochs, generations, phases, counters, and distinct close causes. Inject each Redis/peer/owner/write stage and scan success and failure logs with secret/payload/path/endpoint sentinels. Correlate the entire multi-process time window; a redacted summary alone is insufficient.

### M7-C12

Clean up actor registrations when the awaiting caller disappears before receiving the registration result.

**Edge cases to test:** `EC-020`, `EC-021`, `EC-026`, `EC-036`, `EC-060`.

Registration cancellation contribution: hold the claim result, cancel the awaiting caller before delivery, then release the result and prove exact cleanup without selectable pending state. Check committed-claim and duplicate-cleanup variants. Lost Redis replies and public readiness races remain separate.

### M7-C13

Release outbound queue-budget charges when cancellation drops a handler receiver or writer.

**Edge cases to test:** `EC-028`, `EC-029`, `EC-032`, `EC-033`, `EC-036`, `EC-038`, `EC-045`, `EC-060`.

Queue-accounting contribution: cancel/drop handler receiver and writer at each reservation/queue boundary; assert all charges return once and reserved controls remain bounded. Keep a sibling alive. This is not physical delivery or deadline evidence unless a real socket write is demonstrably blocked.

### M7-C14

Distinguish authority-read failure from confirmed revocation in maintenance diagnostics.

**Edge cases to test:** `FP-03`, `EC-011`, `EC-013`, `EC-019`, `EC-027`, `EC-056`, `EC-061`, `IN-05`, `IN-12`.

Authority classification contribution: independently inject failed authority reads and confirmed revocation; assert distinct typed diagnostics and fail-closed admission. Neither failure may extend credentials or become authoritative no-target. Runtime expiry and restoration need established-route evidence.

### M7-C15

Verify redacted `livez`/`readyz` routes and the readiness dispatch gate under Redis and membership-authority loss.

**Edge cases to test:** `FP-10`, `EC-010`, `EC-011`, `EC-040`, `OG-02`.

Health-endpoint contribution: prove exact redacted livez/readyz responses and dispatch refusal when trust or authority is unavailable. Endpoint unit tests do not prove configured TLS dependency failures, peer capacity, or restored route usability; link those separate process runs.

### M7-C16

Verify the Redis TLS API and real peer mTLS forwarder against configured authority and certificate-role boundaries.

**Edge cases to test:** `FP-10`, `EC-010`, `EC-013`, `EC-017`, `EC-019`, `EC-049`.

TLS contribution: test the configured Redis authority and real peer positive path plus wrong CA, server name, client identity, role, and pin separately. Assert failure before protected body dispatch. Failures during TLS must not be substituted for post-TLS read/write-stage tests.

### M7-C17

Verify acceptance commands fail when required flags are false.

**Edge cases to test:** `IN-11`, `OG-01`, `OG-08`.

Acceptance-validator contribution: force every mandatory Boolean false and every required count below threshold; require nonzero exit and a bounded diagnostic. Re-run the actual commands against the rebuilt executable. Validator correctness does not supply any missing scenario or full-matrix evidence.

### M7-C18

Bind inbound and outbound peer traffic to the actual authenticated certificate during signed key overlap.

**Edge cases to test:** `FP-07`, `EC-008`, `EC-019`, `EC-048`, `EC-056`, `EC-064`, `OG-06`.

Certificate-binding contribution: use distinct actual old/new authenticated certificates during signed overlap, reject unknown same-node certificates, and withdraw existing pooled traffic on removal/expiry without Pub/Sub hints. A same-SPKI key-ID update is metadata coverage only; consumer expiry and adapter lease/pin checks stay separate.

### M7-C19

Fix and verify the maximum-size consumer boundary and bounded chunking.

**Edge cases to test:** `EC-031`, `EC-033`, `EC-034`, `EC-044`.

Maximum-record contribution: send exact maximum complete messages using legal smaller transport chunks, reconstruct byte-for-byte, and release full-record/copy reservations. Also test over-limit, empty, truncated, and coalesced variants where applicable. This does not replace adversarial direction/sequence/generation tests.

### M7-C20

Include authenticated peer route reachability and capacity in readiness.

**Edge cases to test:** `FP-10`, `EC-011`, `EC-024`, `EC-025`, `EC-048`, `EC-051`, `IN-01`.

Peer-readiness tests: independently fault authenticated route reachability and capacity, assert readiness withdrawal and no dispatch, then restore and require a real successful echo. Ready/capacity snapshots alone do not prove recovery. Include bounded probes/waiters and ensure probes preserve customer capacity.

### M7-C21

Align partition admission evidence with the production readiness response.

**Edge cases to test:** `FP-03`, `EC-011`, `EC-012`, `IN-12`, `OG-03`.

Partition-admission contribution: align the expected public status with actual readiness semantics; separate known absent target from uncertain authority/selected owner. Prove zero unintended dispatch during the fault and successful recovery, without accepting a broad status-code match or unrelated failure.

### M7-C22

Eliminate ACK feedback and preserve bounded carrier control delivery during saturation, rotation and terminal cleanup.

**Edge cases to test:** `EC-028`, `EC-029`, `EC-030`, `EC-032`, `EC-036`, `EC-037`, `EC-038`, `EC-039`, `EC-044`, `EC-047`, `EC-057`, `EC-058`, `EC-060`, `IN-02`, `IN-06`.

Carrier-control contribution: exercise delayed credit across multiple maximum records, whole-record preflight, bounded FIFO retry, and no ACK feedback. Under saturation, independently exercise cancel, revocation, rotation, terminal cleanup, late DATA/ACK/credit, and sibling progress. Require physical flush/fence evidence for drain; queue acceptance is not delivery.

### M7-C23

Reject control-bearing and oversized opaque principal identities consistently before catalog lookup or fixture publication.

**Edge cases to test:** `FP-09`, `EC-001`, `EC-002`, `EC-063`, `OG-04`.

Identity-boundary contribution: test empty, control-bearing, delimiter, Unicode, exact byte-limit and oversized opaque IDs consistently before lookup/publication. Verify memory/Redis parity and same-label tenant isolation. Preserve distinct opaque normalization forms; input validation alone does not establish live cross-tenant routing.

### M7-C24

Preserve raw unary HTTP echo semantics across the length-prefixed peer stream.

**Edge cases to test:** `FP-04`, `FP-05`, `EC-007`, `EC-031`, `EC-034`, `EC-049`, `EC-053`, `EC-054`.

Unary HTTP contribution: test raw small/empty/maximum/repeated public bodies, exactly one internal prefix, legal chunking and exact single-response decoding. Reject missing/truncated/extra/oversized responses; assert real owner dispatch and tenant/header boundaries. Separately prove body polling and effect certainty: a framing pass cannot authorize replay or prove a partial backend response safe.

### M7-C25

Preserve authenticated owner-not-ready admission as bounded retry metadata and not_dispatched.

**Edge cases to test:** `FP-02`, `FP-04`, `EC-021`, `EC-024`, `IN-03`.

Pending-owner tests: hold a committed owner before fence acknowledgement/data readiness, prove ingress receives authenticated bounded retry metadata with not_dispatched, and observe no body read/dispatch. Release readiness and assert bounded convergence. Owner-unready must not collapse into generic failure or permit unsafe-method/body replay.

### M7-C26

Preserve active customer streams after failed readiness probes and verify peer-path recovery.

**Edge cases to test:** `FP-10`, `EC-011`, `EC-024`, `EC-025`, `EC-048`, `EC-051`, `IN-01`.

Peer-capacity/readiness contribution: use real authenticated H3 route probes alongside an established customer stream. Exhaust or deny peer checkout/stream capacity, require readiness withdrawal and zero new selected dispatch while the held stream remains usable, and distinguish capacity from blackhole timeout, transport, reconnecting and unknown outcomes. Restore capacity/reachability and require a fresh authenticated echo on the recovered path. Keep probe deadlines bounded, preserve the existing pooled connection on checkout failure, and ensure customer traffic cannot keep readiness alive by itself. This section covers the readiness-preserving probe and active-stream survival slice; broader saturation, queue-control, local owner-capacity and full production matrix scopes remain separate.

### M7-I01

Complete the three-relay production path through control, active data, replacement data, and consumer ingress on different nodes.

**Edge cases to test:** `FP-06`, `FP-07`, `FP-09`, `EC-001`, `EC-019`, `EC-025`, `EC-039`, `EC-041`, `EC-042`, `EC-048`, `IN-02`, `IN-07`, `OG-04`.

Production-path contribution: exercise actual control, active/replacement data and consumer ingress on different relays. Check exact owner/direct-hop path, retained control/logical streams, generations/fences and socket high-water. Baseline forwarding/rotation does not establish deliberately delayed upgrade, trust-change, or active privileged-adapter races.

### M7-I02

Run two genuinely concurrent authenticated tenant sessions using the same connector/device UUID and prove A/B canary isolation.

**Edge cases to test:** `FP-09`, `EC-001`, `EC-002`, `EC-033`, `EC-064`, `IN-01`, `OG-04`.

Tenant-isolation tests: keep two authenticated tenants with identical device/service IDs live concurrently, use independent canaries and counters, and prove each survives the other's activity. Add per-tenant quota/pressure and pooled privileged-operation collisions separately; sequential sessions cannot prove concurrency.

### M7-I03

Rerun the checkpoint-refresh repair and prove the verifier accepts the fresh version while rejecting stale/equal conflicting records.

**Edge cases to test:** `FP-10`, `EC-010`, `EC-011`, `EC-015`, `EC-019`, `OG-07`.

Checkpoint-refresh tests: start a configured relay, observe a fresh nonce-bound higher version accepted, and reject stale/equal-conflicting/expired records without publishing them. Capture readiness and actual route behavior before/after refresh. Startup failure is not evidence that the intended refresh-stage negative was exercised.

### M7-I04

Close the negative admission/readiness/fallback matrix: missing owner, Redis/peer loss, stale membership, wrong pin/role, revoked key, and no unrelated backend fallback.

**Edge cases to test:** `FP-01`, `FP-02`, `FP-03`, `FP-04`, `FP-06`, `FP-10`, `EC-003`, `EC-006`, `EC-007`, `EC-009`, `EC-011`, `EC-012`, `EC-017`, `EC-021`, `EC-023`, `EC-024`, `EC-025`, `EC-031`, `EC-041`, `EC-048`, `EC-049`, `IN-03`, `IN-12`, `OG-03`.

Public admission integration: vary absent/ambiguous/duplicate/inactive targets, forged headers, forbidden routes/destinations, authority/peer/trust failures and recovered routes. For readiness/reselection/upgrade rows, separately control each race point and observe body-read plus dispatch counters. GET/HEAD/OPTIONS, consumed/unpolled/failed bodies, and device/consumer upgrade paths are distinct scenarios. Record the excluded-browser route boundary rather than claiming browser tests.

### M7-I05

Exercise owner contention, stale release, owner death, process pause, UDP partition, and Redis partition with explicit interruption or unknown outcomes.

**Edge cases to test:** `FP-04`, `FP-05`, `FP-06`, `FP-08`, `EC-004`, `EC-005`, `EC-014`, `EC-020`, `EC-021`, `EC-022`, `EC-023`, `EC-024`, `EC-025`, `EC-026`, `EC-041`, `EC-048`, `EC-054`, `EC-055`, `EC-060`, `IN-03`, `IN-04`, `IN-08`, `OG-01`.

Ownership integration contribution: contention, stale release, owner death, pause, UDP and Redis partitions need independently proven triggers and exact outcomes. Outstanding claim-to-promotion lost replies, old/new boot reconnects, delayed readiness and upgrade races require additional fixtures. Post-dispatch cases need a backend effect counter and explicit unknown, not the safe not-dispatched classifier.

### M7-I06

Exercise staged key rotation, missed Pub/Sub hints, trust expiry, certificate/device revocation, and bounded propagation diagnostics.

**Edge cases to test:** `FP-07`, `EC-008`, `EC-019`, `EC-048`, `EC-056`, `EC-064`, `OG-06`.

Trust-lifecycle integration: stage actual certificates, missed notifications, signed trust expiry, device revocation, consumer expiry and pooled boot/incarnation replacement separately. Establish a positive stream first; bound withdrawal at ingress and owner, preserve an authorized sibling, and prove rotation/cache cannot extend the earliest deadline. Same-SPKI metadata rotation cannot substitute for certificate rotation.

### M7-I07

Exercise resource boundaries and cancellation under saturation: peer prefix/body/copy charge, stream/connection caps, queue backpressure, blackholed writes, and sibling-stream survival.

**Edge cases to test:** `EC-028`, `EC-029`, `EC-030`, `EC-032`, `EC-033`, `EC-034`, `EC-036`, `EC-037`, `EC-038`, `EC-043`, `EC-044`, `EC-045`, `EC-046`, `EC-047`, `EC-049`, `EC-051`, `EC-052`, `EC-060`, `IN-01`, `IN-06`.

Pressure/cancellation integration: enumerate each byte/record/queue/stream/connection/tenant cap at limit and limit-plus-one. Exercise concurrent producers, physical blackholes, one-direction stalls, pre-admission cancel, undeliverable cancel, late frames and duplicate cleanup with live siblings. Preserve separate fragmentation, cursor/terminal, reciprocal-close and GOAWAY assertions; one pressure summary cannot close all these rows.

### M7-I08

Exercise same-owner rotation with active synthetic adapter streams while preserving control, logical stream IDs, fids/operation IDs, fences, and the socket bound.

**Edge cases to test:** `FP-07`, `EC-008`, `EC-039`, `EC-042`, `EC-043`, `EC-052`, `EC-053`, `EC-056`, `EC-057`, `EC-058`, `EC-059`, `EC-064`, `IN-02`, `IN-07`, `IN-09`, `OG-01`.

Active-adapter rotation integration: retain synthetic logical IDs, fids/operation IDs, control and owner through three peer-forwarded rotations. Assert immutable fences, physical flush/ACK/checksum, socket bound and one absolute deadline with forced phase delays. Independently test planned-close/backoff, GOAWAY, credential expiry, partial responses and adapter close/shutdown; echo rotation is only supporting evidence.

### M7-I09

Exercise recovery, verified backup/rollback, external checkpoint/incarnation change, and unfenced-old-writer refusal.

**Edge cases to test:** `EC-015`, `EC-019`, `EC-035`, `EC-055`, `EC-066`, `OG-07`.

Recovery contribution: verify the backup, externally approved restored digest/Redis identity, lifetime-plus-skew fencing wait, new incarnation/checkpoint, retained revocation and fresh authenticated sessions. Stale protocol negotiation and stale live pooled identities need their own negative tests. Frozen/pending/unknown recovery states must not imply successful service or replay.

### M7-I10

Close the complete 98-row edge-case matrix.

**Edge cases to test:** `EC-003`, `EC-009`, `EC-020`, `EC-025`, `EC-035`, `EC-043`, `EC-044`, `EC-047`, `EC-049`, `EC-053`, `EC-054`, `EC-057`, `EC-059`, `EC-060`, `EC-061`, `IN-03`, `IN-10`, `IN-11`, `OG-01`, `OG-02`, `OG-05`, `OG-07`, `OG-08`.

Full-matrix reconciliation applies to all 98 rows; the listed IDs highlight cross-task, analogue and aggregate checks particularly easy to miss. For each row, name its fixture and every required assertion, actual fault precondition, build/revision, result and evidence. Track uncovered integration work explicitly before implementing it; never widen a completed component task silently or count this umbrella task as 98 new closures.

### M7-I11

Add the privileged-adapter RPC analogue required by the SQLite source rows without adding SQLite.

**Edge cases to test:** `EC-016`, `EC-053`, `EC-059`, `EC-062`, `EC-063`, `EC-064`, `EC-065`, `EC-066`, `EC-067`, `IN-13`, `OG-06`.

Privileged-RPC analogue contribution: use synthetic real-mTLS RPC, exact tenant/device/service/role/assignment/epoch, bounded bodies and shared-pool namespace isolation. Separate backend effect from consumer-confirmed success; test partial and late responses, frozen/poisoned/stopped states, worker deadlines and joined shutdown. Preserve no SQLite/direct-URL/token fallback. Existing analogue proof does not establish every real production-route or future adapter case.

### M7-I12

Rerun all required Rust checks and M1/M2 regressions after the final M7 fixes.

**Edge cases to test:** `FP-07`, `EC-039`, `EC-042`, `EC-055`, `EC-056`, `EC-058`, `IN-10`, `IN-11`, `OG-01`, `OG-05`, `OG-08`.

Final regression/artifact contribution: run required Rust and M1/M2 commands after relevant final changes, including actual configured rotation intervals where required. Record the exact source/build and binary provenance, then run packaged-client heartbeat, pause, shutdown and three-relay checks. Signatures/help output alone do not establish source parity or functional acceptance; aggregate gates require all contributing row evidence.

### M7-I13

Make required production acceptance assertions fail the command and verify pin rejection after WebSocket upgrade.

**Edge cases to test:** `FP-07`, `EC-019`, `EC-048`, `IN-11`, `OG-08`.

Production-validator/revocation contribution: establish a successful upgraded WSS stream before removing trust, then observe bounded rejection on that same stream. Independently force required flags/counts to fail the command. Pre-upgrade rejection and unrelated transport failures cannot satisfy the established-stream case.

### M7-I14

Assert the physical per-device socket high-water bound in the production harness.

**Edge cases to test:** `EC-033`, `EC-039`, `EC-042`, `EC-058`, `IN-01`, `IN-07`.

Socket-bound contribution: measure actual per-device socket high-water through replacement generations and concurrent tenants, including cleanup. Assert two steady-state sockets and the allowed temporary third. Socket counts alone do not establish logical-stream retention, drain fences, adapter completion or memory quotas.

### M7-I15

Reject unrelated harness failures as owner-death evidence.

**Edge cases to test:** `FP-03`, `FP-05`, `EC-023`, `EC-027`, `EC-054`, `IN-09`, `OG-08`.

Owner-death classifier contribution: prove owner loss occurred and accept only the intended typed outcome; reject unrelated HTTP/TLS/startup failures as evidence. Separately identify pre-dispatch versus admitted/unknown work. The classifier test cannot establish no duplicate backend effect.

### M7-I16

Exercise a real UDP blackhole and restoration with bounded H3 interruption and fresh-path recovery.

**Edge cases to test:** `FP-03`, `FP-07`, `EC-029`, `EC-045`, `EC-048`, `EC-051`, `EC-052`, `IN-09`.

UDP-fault contribution: prove the intended existing peer path is blackholed, require bounded interruption, restore it and observe a fresh trusted response with no replay. Keep connection/resource/cleanup bounds. UDP path failure does not substitute for a physically stalled consumer writer or graceful HTTP/3 GOAWAY.

### M7-I17

Make TCP partition injection block existing and newly accepted connections before forwarding.

**Edge cases to test:** `FP-03`, `EC-011`, `EC-013`, `EC-014`, `EC-020`, `IN-12`, `OG-07`.

Fault-injector contribution: pause both established and newly accepted connections, await in-flight barriers, then prove no forwarding before resume. Downstream tests must separately show which Redis stage or commit/reply boundary was reached; a generic TCP cut is not a DNS, TLS or committed-write countermodel.

### M7-I18

Exercise suspension and resumption of the actual synthetic CLI process across authorization expiry.

**Edge cases to test:** `EC-005`, `EC-023`, `EC-055`, `EC-056`, `EC-059`, `IN-10`, `OG-05`.

Actual-process pause contribution: suspend the synthetic CLI across the relevant authority/deadline boundary, resume, and prove stale ownership fails, children/sockets join and fresh ownership can recover. Distinguish authorization, lease and heartbeat limits. Packaged-binary provenance and adapter child shutdown remain additional scopes.

### M7-I19

Verify an external signed recovery approval bound to the restored durable catalog digest and live Redis identity.

**Edge cases to test:** `EC-014`, `EC-015`, `EC-019`, `EC-066`, `OG-07`.

Recovery-approval contribution: bind a valid external signature to the exact restored durable catalog digest, live Redis identity and candidate incarnation/checkpoint. Reject altered bindings and replay, preserve revocation and classify uncertain activation. The approval check alone does not prove lifetime quiescence, fresh serving or protocol rollback.

### M7-I20

Persist identity-bound membership version high-water state across relay restarts.

**Edge cases to test:** `FP-10`, `EC-010`, `EC-015`, `EC-019`, `EC-035`, `OG-07`.

Persistence contribution: test persist-before-publish and restart high-water state with identity binding; reject corrupt, mismatched or rolled-back state. Process startup and current routing must separately prove fail-closed behavior. A persisted membership version is not peer protocol-feature negotiation.

### M7-I21

Complete the canonical recovery snapshot and atomic catalog-generation concurrency fence.

**Edge cases to test:** `EC-014`, `EC-015`, `EC-020`, `EC-026`, `EC-066`, `OG-07`.

Snapshot/concurrency contribution: validate bounded schema/relationships and exact namespace, WATCH/generation fences, phantom mutation refusal, canceled-watch cleanup and unknown post-commit outcomes. Independently observe durable state after lost replies. Catalog atomicity does not alone prove actor promotion or process recovery.

### M7-I22

Diagnose and fix owner/data recovery after live peer-key revocation.

**Edge cases to test:** `FP-07`, `EC-019`, `EC-039`, `EC-042`, `EC-048`, `EC-056`, `EC-058`, `IN-02`, `IN-07`.

Revocation-recovery contribution: remove trust during a real active/candidate data generation, prove established-stream interruption and duplicate-response refusal, then assert the specifically permitted recovery outcome with exact owner/generation/fences and socket bound. Do not conflate same-owner recovery with fresh ownership or infer credential-expiry coverage.

### M7-I23

Resolve pressure acceptance post-cancellation dispatch-counter failure.

**Edge cases to test:** `EC-028`, `EC-032`, `EC-036`, `EC-037`, `EC-038`, `EC-060`, `IN-06`.

Pressure-counter contribution: separate legitimately accepted pre-cleanup work from post-cancellation dispatch, observe a stable no-replay interval, exact cleanup, live siblings and a fresh canary. Retain the existing narrow acceptance scope; pending-open cancellation, physical timeout and adversarial late-frame cases need their own triggers.

### M7-I24

Make RunningRelay cancellation and shutdown cover every owned task.

**Edge cases to test:** `EC-020`, `EC-026`, `EC-029`, `EC-036`, `EC-038`, `EC-043`, `EC-045`, `EC-046`, `EC-059`, `EC-060`, `EC-061`.

Owned-task lifecycle contribution: retain/join listener, actor, registration, renewal and child handles; inject cancellation/panic while each is held. Verify late committed-claim cleanup and duplicate terminal paths cannot release successor resources. Local supervision proof does not establish full process chaos or adapter reciprocal close.

### M7-I25

Redact source values from relay TOML parse diagnostics.

**Edge cases to test:** `EC-013`, `EC-040`, `EC-061`, `OG-02`.

Parse-redaction contribution: use actual invalid configs with secret/path/endpoint sentinels and assert only bounded category/field/location output. Test both source-level formatting and the binary failure path. TOML redaction does not replace runtime Redis, peer or lifecycle log scans.

### M7-I26

Prove actual duplicate-control rejection in owner-contention acceptance.

**Edge cases to test:** `FP-08`, `EC-004`, `EC-005`, `EC-022`, `EC-026`, `IN-04`, `IN-08`.

Contention contribution: use actual concurrent CLI claims, observe exactly one authoritative conflict and a terminal loser without reconnect loops, preserve winner and sibling, then verify a higher-epoch successor and rejected delayed cleanup. Old/new boot reconnect races remain distinct from initial duplicate claims.

### M7-I27

Diagnose owner loss during the latest production pressure cleanup.

**Edge cases to test:** `EC-027`, `EC-028`, `EC-029`, `EC-032`, `EC-038`, `EC-055`, `EC-057`, `EC-061`, `IN-05`, `IN-09`, `OG-08`.

Owner-loss diagnosis: reproduce and correlate the exact carrier/owner close cause before unregistering state; distinguish queue exhaustion, delayed credit, physical write timeout, lease expiry and planned drain. A passing pressure rerun is not proof of a different stalled-write failure. Keep the intended stall active long enough to observe the relay's own deadline and joined cleanup.

### M7-I28

Return an actionable non-retryable owner-busy result to the actual CLI.

**Edge cases to test:** `FP-08`, `EC-004`, `EC-027`, `IN-08`, `IN-09`, `OG-05`.

CLI conflict contribution: run the actual client into a duplicate-owner rejection and assert actionable bounded OWNER_BUSY, non-retryable terminal exit, unchanged owner/sibling and no reconnect loop. Broader heartbeat/shutdown and packaged-client parity require their separate artifact/lifecycle tests.

## Traceability history

- 2026-09-10T14:51:55+10:00: Added explicit references for all 53 current M7 tasks,
  covering all 98 matrix IDs. This records task contributions and case-specific
  evidence requirements only; no tests were run and no task or matrix result,
  owner, completion timestamp or work order was changed by this update.


### M7-C27

**Edge cases to test:** `EC-028`, `EC-049`, `IN-01`.

Require authenticated owner stream-capacity admission before public WebSocket upgrade, exact typed no-dispatch rejection, unchanged unknown outcomes for generic transport failure, and bounded release when the public upgrade is abandoned. Exercise both owner-local and remote ingress. Concurrent load must observe the configured cap and distinguish capacity from reconnecting, transport, timeout and unknown outcomes; this alone does not close the broader queue-control or saturation scopes.

### M7-C28

Reset only completed-episode mutable carrier closure evidence after verified recovery activation.

**Edge cases to test:** `EC-039`, `EC-055`, `EC-057`, `EC-058`, `IN-09`.

Drive a successful recovery and a second real recovery begin. Preserve the first completed attestation and digest while excluding its already released connection IDs from the new episode. Repeat actual socket recovery faults and retain precise abnormal-close diagnostics. A focused actor pass does not establish physical writer deadlines or sibling survival under production backpressure.

### M7-C29

Accept queued recovery messages without restarting either endpoint's absolute deadline.

**Edge cases to test:** `EC-039`, `EC-055`, `EC-057`, `EC-058`, `IN-09`.

Reproduce a valid sender duration made stale by control-queue/transit delay while the receiver deadline remains live. Require exact attempt/roster binding, bounded wire values and acceptance without increasing the receiver deadline. An expired local deadline still fails closed. Repeat real recovery faults and preserve the first carrier-loss cause; this does not alone prove the original stalled physical-write boundary.

### M7-C30

Preserve OPEN control idempotency with bounded retained state.

**Edge cases to test:** `EC-038`, `EC-044`, `EC-060`.

An identical completed OPEN must replay only its exact original OPENED (or REJECTED) response. The initial admission still queues OPENED plus its independent authorization challenge atomically, but retrying OPEN must not issue or replay a grant challenge. Preserve the existing operation and authorization deadlines; an identical pending request must coalesce. Test a duplicate after authorization confirmation/refresh and after the original challenge deadline, without changing the active grant or operation. Reusing an ID with changed stream/operation/content is a protocol error. A new message ID for an existing stream retains typed STREAM_EXISTS. Define bounded retention and exact StreamForget cleanup, including admission pressure and terminal streams; do not add an unbounded journal.
