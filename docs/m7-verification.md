# M7 implementation and verification

## Session continuation: reviews merged, four repairs integrated, six workers resumed — 2026-09-11T18:53:06+10:00

M7 remains open. Branch `andymac4182/c/m7-cluster-foundations` is pushed (draft PR #12 against main); its head at this checkpoint is fc38699. PR #10 (M1) was merged into main as 3c14b71 after an independent review found no blockers; its five should-fix items are tracker rows M7-C31..C35. PR #11 (M2) is retargeted to main but deliberately not merged standalone: the review found the relay never freezes its old writer at the rotation fence and never reclaimed terminal streams, and read-only verification against d21b116 confirmed the writer freeze (M7-C36), OPEN-during-quiesce (C37), local PREPARE queue failure (C38), the 256-entry connection-history cap (C39), unbounded handler writes (C40) and the Draining/Retiring recovery mismatch (C41) still open, while STREAM_FORGET reclamation, DRAINED reply pinning and abort-reason derivation are fixed with tests. M2 lands through PR #12.

Integrated on the branch with fmt, strict Clippy, 44 workspace targets (759 passed / 0 failed / 47 ignored) and the explicit Redis catalog, scope-isolation, cluster and recovery suites passing: the credential-expiry validator/relay anchoring fix (dd509cc; native gate passes twice), the pooled-stream trust-expiry attribution fix (28e81cc; native gate passes three times), the jsonwebtoken 10.3.0 upgrade with configuration-time key bounds (f87034f; Dependabot advisory closed, M7-C34 verified local), and 1,855 lines of C17 validator mutation coverage (eabbdd9; `verify-m7-cluster` and the M1/M2 inline gates still lack pure validators).

Hosted GitHub Actions is unusable: every job on main and the branches fails in under ten seconds with an account payment/spending-limit annotation, so all evidence is local. Local infrastructure: Redis runs in Docker (`agent-tunnel-m7-isolated-20260911`, `redis://127.0.0.1:63790/`); workers use isolated git worktrees under `.claude/worktrees/` (gitignored) with private `CARGO_TARGET_DIR` clones because the harness resolves relay/client binaries beside the running executable; the survey runner `run-all-gates.sh` in the session scratchpad runs all 53 `scripts/m7-harness-verify.sh` gates independently with bounded deadlines.

Six workers were killed by an API session limit with uncommitted edits preserved in their worktrees and were resumed with context: configured dependency restoration (its chain already passed the restoration test in 32.97 s with a new catalog Redis lane reconnect path), late DATA/FIN terminal ordering, GOAWAY rotation (drain deadline versus device disconnect margin under diagnosis), writer freeze at the fence (C36/C37), rotation edge defects (C38/C39/C40) and the EC-036/EC-041 race regressions. After integration the required order is: full locked Rust checks, the 53-gate survey on a quiet machine, M1 and accelerated/default M2 regressions, then tracker/matrix closure updates. C41 needs an owner decision (implement protocol.md's Draining→Recovering and forced retirement, or narrow the document).

## Native65 recovery passes; remaining failures isolated — 2026-09-11T04:45:31+10:00

M7 remains **48/58 tasks and 47/98 matrix rows verified**. The scope correction at 2026-09-11T04:31:11+10:00 reopened EC-036 and EC-041: post-admission abandonment and consumer owner revalidation do not prove their broader pending-open and device ticket/generation races. C10, FP-06, EC-040 and IN-01 remain closed at their supported scopes. All ten continuation workers have active bounded assignments; root owns live integration and Cargo/native runs.

Native63 passed M1 (22.44 seconds), accelerated M2 (13.54), peer transport (8.00), cluster (4.31) and production (20.76), completing at 2026-09-11T04:16:45+10:00. These precede the latest trust/GOAWAY changes. Current75 relay library tests pass 197, harness tests pass 143 with one ignored, and the actual HTTP/3 immediate-invalidation regression passes in 0.02 seconds. Strict all-target Clippy75-2 and binaries pass. The latest full workspace/Redis baseline remains current71: 702 passed/46 ignored and 31 explicit Redis cases; final postfix full checks remain required.

Native65 source digest `95a76529f4d0061e7fc4177123b0e2485d6e09c8ecf2ebe742896ce24a911146` was observed at 2026-09-11T04:37:35+10:00. Its immutable manifest and runtime receipts are `/tmp/agent-tunnel-native-20260910-integrated65/`; source-copy provenance remains false. I08 rotation faults pass 9.99 seconds at 04:38:19, proving the exact faulted generation/connection, same-session recovery to generation4, stable control/stream and joined cleanup. This does not cover three failed recovery attempts.

Credential expiry fails 19.25 seconds at 04:37:55. CLI shutdown ordering is repaired; the remaining strict timing failure reports a post-expiry probe at Unix1789065475043 against token expiry1789065475000, observed monotonic15974 versus challenge admission deadline15931. Deadline/evidence semantics are under review; no timing assertion is relaxed. GOAWAY fails 14.63 seconds at 04:38:09 after the shared admission seam, because committed rotation does not activate the observed candidate; cleanup also reports peer transport/H3_REQUEST_CANCELLED errors. Trust expiry fails 14.58 seconds at 04:38:34 because the exact owner/session/cursor terminal observation is still missing. Immediate handler cancellation is preserved while a context-aware first-cause cleanup repair is staged.

Configured dependency restoration test76 compiles and runs against the immutable Native65 relay, but fails in 4.40 seconds with `restoration device stop: control read failed`; no restoration completion is claimed. The C22 saturation stage is held after independent review found an unreachable workload: 64 maximum records cannot fill128 physical data entries and retained-plus-encoded charging exhausts4MiB near32 records. The correction must prove actual Binary occupancy, immutable first-terminal evidence and physical drain within bounded observations. Late-frame receipts, configured SPKI replacement, full scope matrix, final all-native/default300-second rotations/source-copy and later milestones remain outstanding.

## Current workspace and Redis pass; Native62 failures retained — 2026-09-11T04:14:12+10:00

The full current workspace sweep passes 702 tests, zero failures and 46 ignored tests across 51 targets; all 31 explicit Redis integration cases then pass against the isolated Redis primary. Logs are `/tmp/agent-tunnel-continuation-workspace71.log` and `/tmp/agent-tunnel-continuation-redis71.log`. The sum of reported test-body durations is 8.93 seconds and 4.98 seconds respectively; those sums exclude compilation and runner overhead. Current70 strict all-target Clippy and binaries also pass. These results do not close the final post-fix I12 gate.

Native62 source `f3f5602289ac1e4196482145fb700d7bc7d165175a9be1bbe3a75d469ff752bd` was observed at 2026-09-11T04:04:43+10:00. Its immutable manifest and per-command runtime receipts are under `/tmp/agent-tunnel-native-20260910-integrated62/`; source-copy provenance remains false. Admission/framing passes 15.54 seconds at 04:05:17 with the tightened exact `PEER_UNAVAILABLE/not_dispatched` owner-change rejection. The original side-effect suite passes 12.28 seconds at 04:05:44 and M2 faults pass 16.19 seconds at 04:06:12. A stale staged wiring hunk had reverted only the C10 success-output fields; root restored that line after Native62. Mandatory validation and the production owner revalidation remained intact throughout.

Three failures remain explicit. Credential expiry reaches scenario completion but cleanup reports tenant-A CLI exit 4 (17.92 seconds, 04:05:02); the staged correction stops and joins the CLI before closing its device proxy and retains bounded diagnostics for every failed cleanup. Late DATA/FIN fails because the exact logical stream has been reclaimed before terminal observation (14.32 seconds, 04:05:32); absence is not accepted as receipt evidence. I08 recovery fails because its required exact faulted-carrier identity is missing (12.12 seconds, 04:05:56). Workers are repairing these causes while preserving the strict assertions.

The crossed ROTATE_DRAINED reply repair is causally verified: the actual relay handler regression fails with the connector DRAINED ID in place of the immutable connector FROZEN ID before repair, then passes in the full 191-test relay run. The full workspace sweep now also covers the corrected late-frame mandatory-evidence validator. An independent literal row audit promotes EC-036, EC-040 and IN-01 from Native61, and FP-06/EC-041 plus the declared M7-C10 task from Native62; EC-061 and OG-02 remain open because terminal-before-unregister ordering and the full per-fault correlation tuple are not proved. Trust terminal causality, deterministic GOAWAY admission, configured saturation, configured restoration/dynamic pins and later milestones remain open. Current counts are 48/58 tasks and 49/98 matrix rows; the milestone remains in progress.

## Owner-change race repaired; C11 and C27 verified locally — 2026-09-11T04:01:07+10:00

M7 is now **47/58 tasks and 44/98 matrix rows verified**. C11 and C27 close at their declared component scope; no linked matrix row is promoted. C10 has a causal native red/green result and awaits final independent scope review.

Native60 reproduced C10 before the production repair: the authenticated held request received HTTP101 after a complete different higher-epoch owner token was committed (9.11 seconds, 2026-09-11T03:48:59+10:00). The fix retains the selected route and re-reads the full authoritative OwnerToken after admission/barrier and immediately before constructing101. Changed, missing, unreadable or timed-out ownership returns the bounded OwnerNotReady response; generic transport failures retain unknown execution. This is a final admission re-read, not a claim of a globally atomic catalog-to-network transaction.

Native61 observes source `efd635ccbd6c0aebbcf6a8e3e7b62b1911c31a04d877cd9c48e3090a3979d695` at2026-09-11T03:54:31+10:00: client `a23fe3a281a1d8db2a40ff3c74cc1d6004b7f4baa46ac7c49c5bc3a43ab885d0`, relay `cfb654a590b4f1322c8db9ed9f0ff1166ff506bd4b487f85d917178d65168cac`, harness `369390cb428e35d8c21fcd541eb010bca1ed95ff034deb85a4c4f6e1dc3bb377`. Manifest/runtime receipts are `/tmp/agent-tunnel-native-20260910-integrated61/`; source-copy provenance remains false. Its full admission/framing command passes15.72 seconds at03:54:47, including raw-bearer remote authentication, exact owner change before101, typed rejection with zero body reads/dispatch, fresh absent-owner control, empty WSS/unary framing and truncated-body rejection, plus joined cleanup.

C27 same-build public abandoned upgrade passes14.40 seconds at03:55:02, owner-local64-stream capacity7.91 seconds at03:55:10 and remote concurrent load12.89 seconds at03:55:23. Both local/remote pre101 barriers reclaim exact registrations, observe no101 and no dispatch; load admits64 with64 typed refusals and zero reconnecting/transport/timeout/unknown outcomes. The focused HTTP response regression also positively preserves unknown execution for generic transport closure and typed not-dispatched capacity/owner-not-ready outcomes (one test,0.00 seconds). These complete C27 admission/capacity/abandonment scope. Broader EC028 physical queue/control saturation and EC049 request-body preflight remain open.

C11 complete matrix passes94.05 seconds at03:56:57: eight real success/fault cases, all nine safe-field families,83 captured/joined streams and101435 bytes. Expected managed roles and relevant safe fields are checked independently per case. Redis uses library clients, not invented child processes; actual owner death now emits an exact fixed owner_death field derived from owner shutdown and observed closure. Secret/payload/path/endpoint scanning and identifier-boundary matching remain strict. This completes C11 diagnostics scope; source-copy artifacts and wider fault semantics remain separate. Current69 harness142 tests/one ignored, response regression and strict Clippy69-2 pass; binaries69 build21.59 seconds.

Native59 I08 active-carrier recovery passes10.52 seconds at03:44:33, retaining exact fenced successor/status/owner/stream evidence after two planned rotations. Credential expiry fails19.78 seconds at03:44:22 with rotation_drained_reply; root reproduced the actual relay handler sending reply_to=connector-drained instead of connector-frozen in the focused regression (0.01 seconds, expiry70-red2.log). The production reply is now pinned to the immutable peer FROZEN message; current70 relay/harness/strict/build validation is running. The initial regression used inconsistent future timestamps and waited for a nonexistent message; root stopped that owned test, corrected its monotonic setup and added a bounded receive before the causal red result.

The standalone late DATA/FIN fixture is integrated after independent source review, with exact owner receive/delivery cursor advance, stable full OwnerToken, sole stream/operation/service/carrier, typed owner send failure and zero queue/replay before cleanup. Runtime proof is pending; no ACK/WINDOW/sibling/saturation scope is claimed. Configured saturation is held for a feasible workload distributed across per-stream replay budgets, direct paused-socket binding and exact rotation-attempt correlation. Trust-expiry cause plumbing is held for preserving cancellation guarantees and current C10 changes. GOAWAY now needs a deterministic in-flight admission seam instead of racing readiness polling. C06 configured restoration/dynamic pins, full current-source regression/default rotations/source-copy and all later milestones remain open.

## Public abandonment and configured deployment pass; two diagnostic gates repaired — 2026-09-11T03:43:43+10:00

M7 remains **45/58 tasks and 44/98 matrix rows verified** while C06/C27 full-scope review runs. Native58 observed 2026-09-11T03:33:49+10:00 has source digest `0103318349e6a808a387a117c5964c4f079f1fafadc5c9b8d88166d2f01b8a9d`, client `a23fe3a281a1d8db2a40ff3c74cc1d6004b7f4baa46ac7c49c5bc3a43ab885d0`, relay `f824d4745b90f0cf0484a14c6ddcba00d58c29e39257654573480500b2aa1191` and harness `205d02ce607b7c1dcedbaa9f330294d56f82419a638cfcc92b22f119e5cd5216`. Immutable native receipt is `/tmp/agent-tunnel-native-20260910-integrated58/manifest.json`; source-copy provenance remains false.

Public abandoned upgrade passes 14.43 seconds at 03:34:04: actual authenticated TLS/WSS owner-local and remote requests reach the one-shot post-admission barrier with no 101 response, exact owner/stream/operation correlation, zero application dispatch, typed 429 ADMISSION_LIMIT/not_dispatched while the permit is held, physical registration reclamation and two actual CLI processes with sibling recovery/cleanup. The configured pending limit is one; this is not full data-queue saturation or public request-body preflight evidence. The barrier regression passes one test in 0.01 seconds and all 28 validator mutation cases pass in one test in 0.00 seconds. Strict workspace Clippy66-2 passes 14.17 seconds; binaries66 build in 17.48 seconds.

Same-snapshot key rotation passes 10.43 seconds at 03:34:31, peer readiness 17.15 seconds at 03:34:48 and peer capacity 30.96 seconds at 03:35:19. GOAWAY fails 16.10 seconds at 03:34:20: the later authenticated admission returns CLUSTER_UNREADY/not_dispatched after listener drain affects peer readiness, and relay-a cleanup reports H3_REQUEST_CANCELLED. The strict GoAway classification is not relaxed; listener/readiness/cleanup repair is assigned.

All seven configured C06 targets then pass with live source frozen to the same digest: nine outer tests / 22 scenarios. Target durations are baseline 2.02, bootstrap faults 29.48, runtime dependency loss 12.50, six Redis stages 19.03, checkpoint refresh 7.94, approved-port cases 3.75 and recovery/revocation/fresh-canary 65.71 seconds. Receipt `work/c06-native58-receipt.json` was recorded at 2026-09-11T03:41:35+10:00 after confirming unchanged source. Configured-process write syscall injection is not claimed by the distinct in-process redis-rs AsyncWrite/EOF observer.

Native57 M2 faults passed 14.59 seconds at 03:23:03. Its I08 active-carrier path failed because a successful recovery legitimately clears relay rotation diagnostics; the fixture now checks the exact retained typed fenced-successor activation, old/new carrier identities, closure roster and live owner/session instead. Native57 credential expiry failed 21.82 seconds at 03:22:38 with bounded rotation_protocol and repeated ACK165 below fence166; a finer fixed-label ROTATE branch classifier is integrated. Native57 C11 failed 13.56 seconds at 03:23:17 because the Redis case uses library connections rather than the two claimed managed children. A source audit confirms zero for that case and retains exact expected counts for the other seven cases. All three reviewed diagnostic changes are live; tests/strict checks/build67 are running.

C10 owner-token race remains staged for causal red/green verification, bounded ownership cleanup and exclusion of replacement canary counters. Trust terminal cause attribution and configured saturation/late-DATA/FIN evidence remain under independent review. Final current-source full Rust/Redis/all native gates, three actual 300-second M2 rotations, source-copy provenance and subsequent milestones remain required.

## Client retry release causally verified; native failures retained — 2026-09-11T03:19:08+10:00

M7 remains **45/58 tasks and44/98 matrix rows verified**; no closure. Current61 client102/protocol86/relay187/harness139 tests pass, zero failures and one harness ignored test. Strict all-target Clippy61-3 passes19.93 seconds and binaries build20.04 seconds. This is a dated regression baseline, not final I12.

Native56 observed2026-09-11T03:03:56+10:00, source30a1c0e2adcdef0496fcf49a22e883ffc0169134a72ab81903afa83c5aaccb26, client02843152e8d7457205ddd4ca4d5b3bdf0d0742d237ba0a7c3158ae6af0806e07, relayb523c65cb878c06a507d43875f155cd688aafb5229560a60d385609b615f2832, harness a3b0926ff72f22dc8011c17ba91dbf78d26178614c215717fd06e6959b162ff0. Source-copy provenance remains false. Credential expiry fails12.97 seconds at03:04:10 during pre-rotation keepalives; tenant-A CLI exit4 is reported during cleanup. No new protocol subtype was captured on that earlier path. A bounded all-error CLI diagnostic sample is now integrated. GOAWAY fails21.51 seconds at03:04:31: later admission returns503 PEER_UNAVAILABLE with execution=unknown; owner later closes RECOVERY_START_FAILED and peer cleanup returns H3_REQUEST_CANCELLED. The required not_dispatched gate remains strict.

The EC057 client release defect is repaired: finish_recovery_candidate_loss records its local closure but no longer marks the physical allocation released before the following authenticated RECOVERY_BEGIN consumes that evidence. A regression using owned joinable initial carrier tasks reaches attempts2and3, passing0.01 seconds. Restoring only the original premature released-set insertion fails at actual attempt2 with RecoveryResourcesNotReleased in0.00 seconds; exact fixed source is restored. Logs /tmp/agent-tunnel-continuation-client-release63-green2.log and client-release63-legacy-red.log. Independent closure review/native recovery remain pending. Pending retry-timer shutdown separately passes0.16 seconds, and unrelated H3 error classification passes0.00 seconds.

C11 now independently requires exact managed-child counts/roles per case and relevant per-case safe fields while preserving the nine-family matrix union. Current64 client/harness tests, strict Clippy and binary build are running. Trust latch integration is held for causal membership-expiry attribution, full owner fencing, authoritative timing and actual terminal-transition evidence. C27 is held for exact owner/operation correlation and stricter pre101/cleanup evidence; C10 depends on that seam. Configured saturation was rejected as proof of physical message-queue occupancy: pending+stream counts alone only establish logical admission counts. Pressure owns its correction; fragmentation continues standalone late DATA/FIN and recovery independently reviews it. All needed workers have been retriggered with bounded assignments; root owns Cargo/native commands.

Final current-source full Rust/Redis/M7/M1/M2, three actual300-second M2 rotations, source-copy provenance and later milestones remain required.

## Diagnostic matrix pass and recovery client blocker — 2026-09-11T02:59:20+10:00

M7 remains **45/58 tasks and 44/98 matrix rows verified**. Native55 C11 passes at2026-09-11T02:45:29+10:00 in90.35 seconds: all8 actual Redis/peer/owner/write success/fault commands,83 joined streams,85182 captured bytes and all9 safe-field families. The original side-effect command also passes11.99 seconds at02:45:41. These are dated binary-snapshot results; the manifest still records source_provenance_verified=false. Independent C11 audit retains per-case field and expected-process-role completeness as follow-up rather than promoting linked matrix rows.

The owner-fault flake was reproduced on unchanged Native54 binaries: two passes then a TLS peer close without close_notify failure. The fixture had already recorded its armed exactly-one-effect owner loss but then attempted a new response and read loop. It now returns after the observed owner loss/cancellation; narrowly classified physical closure remains accepted only at the armed one-effect/no-response boundary. Protocol errors remain failures. A real loopback WebSocket causal regression is now integrated and awaiting the current library run.

EC057 relay retry pacing is live with immediate first attempt,100/200ms subsequent gaps and one fixed episode deadline. Its new actor regression passes0.35 seconds; temporarily restoring immediate retries causally fails in0.01 seconds with attempt2 where attempt1 was required. Live source was restored. Independent review found a separate client blocker: local candidate closure was marked released before both authenticated closure sides removed the protocol allocation, so the next RECOVERY_BEGIN can fail RecoveryResourcesNotReleased. A client-path fix and attempt2/3 regression are assigned; EC057 is not accepted. Whole-session reconnect remains unimplemented.

GOAWAY pre-upgrade admission now records its typed diagnostic using the same request identity; the fixture closes its admitted public stream after receiving the exact response and compares the complete owner token. A bounded expiry CLI protocol-cause classifier is live. Trust terminal latches, C27 pre101 abandonment, C10 owner-token race, late DATA/FIN and full saturation remain staged or in review. Current61 library validation is running. Final current-source Rust/Redis/all native gates, three actual300-second M2 rotations, source-copy provenance and subsequent milestones remain outstanding.

## Native admission pass; expiry and GOAWAY failures narrowed — 2026-09-11T02:34:47+10:00

M7 remains **45/58 tasks and 44/98 matrix rows verified**. No new full-scope closure. Native52 (`/tmp/agent-tunnel-native-20260910-integrated52`, observed2026-09-11T02:24:40+10:00) records source digest16eb92d904915a5dddcecf8199955a3afe34b623280e6cc0c3ba06c24f7008a4 and binary hashes in its manifest. The receipt identifies a stable snapshot; source-copy provenance remains false.

- Admission/framing passes7.89 seconds at02:25:24: real three-relay fresh control/greater epoch, empty WSS/unary exactly one owner dispatch, exactly one length prefix, owner body-read evidence, truncated prefix no dispatch and joined cleanup. Raw bearer preservation and owner-token change before101 remain C10 work.
- Trust expiry fails14.72 seconds at02:24:56 because the exact terminal stream/cursor is not observed before reclamation. Missing state is not accepted as proof. A bounded immutable correlated terminal observation is under review.
- Credential expiry/rotation fails20.12 seconds at02:25:16 with an actual CLI `PROTOCOL_ERROR`, retryable=false, during draining. Exact owner terminal records CONTROL_CLOSED five milliseconds after the held expiry observation; no rotation deadline event exists. The last CLI status has two drain fences and one drain ACK. Causal client protocol repair remains pending.
- GOAWAY fails66.83 seconds at02:26:30 because the fixture incorrectly required cumulative pooled accepted-stream count1. The corrected live gate retains exact logical identity and exactly one active stream while allowing prior completed probes. Native53 then advances through GOAWAY, response and later-request rejection but fails92.84 seconds at02:33:20 waiting for an ingress GoAway diagnostic; peer cleanup also times out. Full EC052 remains open.
- C11 fails61.02 seconds at02:27:31 on its owner-fault child after five prior matrix cases. Same-snapshot isolated owner-fault rerun passes with12sentinels and7typed snapshot files. The initial failure is not explained or erased; actionable redacted child-failure diagnostics and full matrix rerun remain required.

Focused native Rust checks pass126 harness library tests/one ignored, seven main command-exit tests and21 transport unit tests. All five real-H3 GOAWAY tests pass0.92 seconds. The configured executable Redis matrix now passes all six DNS/TCP/TLS/read/post-PONG boundaries17.26 seconds. An actual redis-rs in-process transport observer separately proves INFO AsyncWrite failure versus peer read EOF, passing0.00 seconds; it is not an OS syscall or configured-process write-injection claim. Strict Clippy57 passes23.13 seconds and binaries build23.43 seconds.

Native53 observed02:31:47 has source356ac9edc6ff3eeeba5911218f00b5ec5aa94b8a4848a0f2fae5bee40bcad748, clientf5fca19a851591f5a0dcf5406861cb3e67ec4539a6b80be133354551e542fab3, relayce67cc542fa9ede4c783510d30b77048563fa9226f4f6996e47ee905d7491711, harnessaa15fc646453aff3cfb03f829d9153c7dc18cfbf09190d2777ef13a88df46f27. Final full Rust/Redis/M7/M1/M2, three actual300-second rotations, source-copy and later milestones remain open. Root owns Cargo/native commands; workers stage patches and independent reviews.

## Expanded validators and native fixture integration — 2026-09-11T02:24:28+10:00

M7 remains **45/58 tasks and 44/98 matrix rows verified**. No additional task or matrix row is closed. All eight original workers have been resumed for specific outstanding implementation or review work; completed stages are being integrated rather than restarted without a new assignment.

The expanded harness library suite passes **126 tests, zero failures, one ignored** in 2.62 seconds (`/tmp/agent-tunnel-continuation-harness54-2-native.log`). Three initial failures were overly specific test expectations for existing error text; the mandatory error and nonzero-exit checks remain. Strict all-target Clippy55 passes in20.24 seconds; the workspace binary build is running. This does not replace the final full workspace, explicit Redis, native acceptance or source-copy gates.

Live source now includes exact logical stream/session correlation through signed-trust expiry, a three-relay planned peer GOAWAY/rotation fixture, real fresh-owner and single-prefix admission/framing, and the eight-case C11 complete diagnostic window. C11 captures joined child streams, actual-use secret/payload/path/endpoint sentinels and all three typed relay snapshots, including the failed owner before removal. It scans every captured stream and reports bounded counts and source/build identifiers. A source/build receipt is still needed; environment labels alone do not prove provenance. These new native fixtures have not yet passed.

Native51 credential expiry fails19.31 seconds at2026-09-11T01:59:05+10:00 after the held expiry phase, during post-release rotation. Repeated ACK166 below fence167 precedes CLI exit1 and relay CONTROL_CLOSED; neither FIN timeout nor rotation-deadline expiry is established. New bounded CLI error-code and exact owner/stream/fence diagnostics are live for the next run. EC057 retry pacing remains staged: the proposed third candidate must be reachable under closure bounds, every failed candidate needs exact fence evidence, and all attempts must share the immutable recovery deadline. Public abandonment before101 and full queue saturation remain open. Later milestones remain unstarted.

## Concurrent-load and lifecycle pass; expiry close regression repaired — 2026-09-11T01:58:32+10:00

M7 remains **45/58 tasks and 44/98 matrix rows verified**. No full task or matrix row is newly closed by this checkpoint. All eight original workers are running or have returned concrete implementation/review stages, and needed follow-ups have been retriggered. The linked fragmentation worker is confirmed active.

Native50 concurrent-load passes15.36 seconds at2026-09-11T01:44:33+10:00:128 attempts,64 admitted streams,64 typed capacity refusals,zero reconnecting/transport/timeout/unknown outcomes,256 ordered records, bounded queues, responsive cancellation, tenant/sibling survival and joined cleanup. Native50 lifecycle passes14.49 seconds at01:44:47 with a real blocked response path, observed queued work, cancellation join, stable dispatch, sibling progress and fresh-stream recovery. C27 is under exact-scope closure review against Native49 owner-local capacity and current real-H3 abandonment evidence.

Native50 credential expiry fails23.00 seconds at01:44:18. The corrected challenge14838..16838ms contains token expiry around16216ms, but the independently enforced public token deadline closes the owner stream first with no authorization failure code. The new actor regression fails causally with None versus AUTHORIZATION_EXPIRED before repair (0.01 seconds), then both close-path regressions pass0.01 seconds after recording the owner-held expired credential at the first correlated terminal transition. Existing failure reasons, a valid early close, mismatched operations and duplicate closes retain their prior meaning. Logs `/tmp/agent-tunnel-continuation-expiry-close-{red,green}.log`. Native proof of this repair is pending.

The C22 authenticated saturated-carrier FIFO regression passes: DATA/DATA/FIN order and sequences1/2/3, cumulative ACK/WINDOW feedback and bounded retained-state release. This is component evidence, not full cross-peer/write-deadline scope. Log `/tmp/agent-tunnel-continuation-c22-fifo51.log`. Trust-expiry logical correlation, real three-relay GOAWAY, actual100/200ms recovery pacing and full C11 diagnostic capture remain staged/reviewed. Final current-source Rust/Redis/M7/M1/M2, three actual300-second rotations and source-copy provenance remain required; later milestones remain unstarted.

## Full Rust/Redis pass and two overlap repairs verified — 2026-09-11T01:44:58+10:00

M7 has **45/58 tasks and 44/98 matrix rows verified**. C18 was reopened for a destination overlap bug and is now reverified after a causal real-H3 regression. C17 remains reopened for incomplete all-command validator coverage. C11 remains staged for full inner-process capture/redaction review. Later milestones remain unstarted.

The complete workspace passes642 tests, zero failed,46 ignored across51 reported targets in53.77 seconds; all31 explicit Redis catalog integration cases then pass in4.83 seconds. Logs `/tmp/agent-tunnel-continuation-workspace48.log` and `redis48.log`. All26 transport tests pass, including five real-H3 GOAWAY cases in0.94 seconds. Strict Clippy49 and Clippy50-2 pass. These baselines precede the final pending recovery/C11/trust-correlation changes and are not the final milestone gate.

Two separate overlap defects are repaired. Local readiness now selects the configured certificate key rather than the last valid overlap key; its causal red-to-green regression and all15 membership/persistence tests pass. Outbound routing now lets the completed mTLS identity reach certificate-specific signed binding instead of first comparing it to an arbitrary preselected overlap pin. The first proposed regression bypassed the production provider and falsely passed; the corrected provider path fails in0.01 seconds before repair and passes0.07 seconds afterward. Node/boot, endpoint, server-name, observed SPKI and trust-deadline checks remain.

Native47 key rotation passes9.38 seconds at2026-09-11T01:23:09+10:00 and production passes19.80 seconds at01:23:29. Native49 trust expiry now reaches the actual old-key deadline, exact target-local expiry, route withdrawal and consumer ClosedAfterSend, then fails11.71 seconds at01:39:29 because its owner-cursor helper incorrectly requires unchanged physical active_connection_id through valid scheduled M2 rotations and forbids legitimate terminal FIN progress. Exact logical-stream correlation is being repaired; no complete trust-expiry pass is claimed. The route-specific evidence distinguishes relay-c→relay-a Unreachable from relay-c→relay-b Reachable while relay-c membership stays Ready.

Native49 owner-local capacity passes10.17 seconds at01:39:39. Immediate early abandonment is preserved; the retained-anchor barrier separates relay reclamation from connector processing before replacement. All64 active streams, typed429 STREAM_LIMIT/not_dispatched, zero dispatch delta, bounded retry metadata, held/fresh canaries and joined cleanup pass. Native50 is running corrected credential-expiry timing, concurrent-load and lifecycle; no result is claimed here.

Native48 credential expiry fails24.70 seconds at01:27:52. Diagnostics show a generic terminal tombstone with authorization still in flight and no expiry code. The held challenge13018..15018ms expired before the consumer token around16000ms, so this was a fixture deadline-ordering failure. The gate now holds only successful refreshes in the final1.5 seconds, requires the explicit challenge deadline to exceed projected token expiry by250ms, and rejects terminal/expired challenges at the boundary. The strict AUTHORIZATION_EXPIRED and zero-dispatch checks remain; production timeouts are unchanged.

Native49 client `f5fca19a851591f5a0dcf5406861cb3e67ec4539a6b80be133354551e542fab3`; relay `0d0f5ccb016f8d4c72d1d67b0f9e8cec3e70a3d430219665a5f8bf0142d7e54e`; harness `bfa27b8f0e8b6e5b9b7fa2dfa7be848c1af1855f2ef2229b692775e09ad011bc`. Native50 has the same client/relay and harness `314b5ff51a7bf5bb92eda6be4d300cc830d7adae5def40bf5b1a5d627d45adbc`, observed2026-09-11T01:43:54+10:00. Source-copy provenance remains unverified. EC057 review found documented100/200ms retry delays lack a production scheduler; bounded pacing is assigned with unchanged30-second episode and three-attempt ceiling. Final current-source M7/M1/M2 checks, three actual300-second rotations, source-copy verification and later milestones remain required.

## Capacity and reachability verified; trust repair passes causal regression — 2026-09-11T01:22:23+10:00

M7 has **45/58 tasks and 44/98 matrix rows verified**. C20 is reverified and C26 first verified from the full readiness/capacity scope. C17 is reopened: seven passing validator tests do not prove every mandatory field across all acceptance commands. C11 remains open for full correlated inner-process diagnostics and real sensitive-value injection. All eight original workers have been retriggered for concrete implementation or review; no later milestone is started.

Native45 peer capacity passes30.47 seconds at2026-09-11T01:06:26+10:00 with128 authenticated held streams distributed43/43/42 across three owners. Typed Capacity, liveness, readiness/admission withdrawal, zero new selected dispatch, held-stream survival and fresh recovery echo pass. Native46 peer reachability passes16.58 seconds at01:08:44 on the same binary cohort. Eleven real-H3 probe tests separately pass, including stale publication fencing that still returns the actual probe error, blackhole Timeout and pooled customer survival. Native45 production passes21.34 seconds at01:07:17; Native46 admission passes23.73 seconds at01:09:20.

Native46 owner-local capacity fails11.81 seconds at01:08:56: after reclaiming the abandoned64th stream, held stream0 closes before its response. Owner remains alive, active63/retained64, with no authorization-in-flight or peer consumer error. It is assigned to pressure; older owner-local passes are not current closure. Native45 trust expiry fails before expiry on PEER_UNTRUSTED baseline admission. The affected connector now attaches both sockets directly to its owner, retaining a remote public consumer path, and the fixture invalidation callback matches the serving relay.

The configured local-SPKI regression causally fails bootstrap with PeerRejected while a different overlap key is valid. Selecting the exact configured certificate key fixes it; all10 membership-readiness and5 durable membership tests pass. Expired matching keys produce CheckpointExpired/TrustExpired, while wrong/revoked/future pins remain rejected. The earlier unchanged-refresh admission cancellation is repaired by comparing signed trust boundaries while preserving the original monotonic deadline. Natural expiry during the actual three-relay stream still requires a native pass.

Passive planned GOAWAY now succeeds without a post-GOAWAY open using a narrow version-preserving h3 0.0.8 control-frame observation patch. Four of five real-H3 tests pass; forced-deadline closure now correctly propagates an H3 error and its test assertion is being corrected. EC-052 still requires actual GOAWAY during three-relay rotation. Credential expiry during a held rotation remains failed: native45 reports its gated authorization completed, but the owner closes at its rotation deadline before the required typed expiry observation. Follow-up catalog/actor diagnostics are in review.

Native45/46 snapshot client `1b4bdfcfd762d8fd6c19fa652f2009b23bd8cdbcc9bacd5f4667e5b618d18d8a`; relay `2fc1ac705d93c0bb7e26d692e8f28fbc5ce9e3bc06a8603fa9fce02a30371ffd`; harness `93acebb42a73a90623eb135b83fc98b988035d9f8a3e31de71b6a2abac835cbc`. Current source differs after trust/GOAWAY changes. Startup fake-Redis fixtures now accept the bounded authorization lanes concurrently and all6 startup cases pass. Current full workspace, explicit Redis, all M7/M1/M2 commands, three actual300-second M2 rotations, source-copy provenance and later milestones remain outstanding.

## Acceptance exit gate verified; peer cancellation repair under regression — 2026-09-11T00:51:23+10:00

M7 now has **44/58 tasks and 44/98 matrix rows verified**. C17 closes from seven exact main ExitCode/mandatory-flag/count regressions plus Native43 transport/partition and Native44 production. C11 stays open because its task-test scope also requires correlated multiprocess sentinel scans across each fault stage; passing summaries alone do not close it.

Native44 production passes19.22 seconds at2026-09-11T00:46:41+10:00 and pressure passes15.94 seconds at00:46:57 with exact no-replay, responsive cancellation, sibling and fresh-owner recovery. Peer capacity advances through full authenticated filling, then fails30.28 seconds at00:46:22 because a refresh unexpectedly succeeds while all route permits should be held. The prior fill failure is resolved at this run's scope, but exact refresh-boundary diagnostics are pending. Trust expiry establishes both clients under v1, then fails baseline public admission503 at00:45:52 before the five-second key expiry; typed admission/readiness diagnostics are being added, so no trust-expiry outcome is claimed.

Peer admission token propagation is live. The real-H3 regression passes0.02 seconds after correcting its sibling success handler to consume request FIN before finishing its response. It proves two same-identity handlers drop before dispatch, unrelated source success, and typed outbound Closed. Full relay validation passes183 library,2 binary and1 health tests, then fails durable_refresh_preserves_existing_peer_admission. The new deadline-shrink comparison invalidates an unchanged healthy admission; monotonic conversion versus actual signed expiry is under repair. No full relay or expiry gate is marked passed.

Native44 snapshot observed2026-09-11T00:45:43+10:00: client `1b4bdfcfd762d8fd6c19fa652f2009b23bd8cdbcc9bacd5f4667e5b618d18d8a`; relay `11353b8d95175b96bc3b54ad0b52b868600ec7fd8a21cda61e700b831cdd2fa9`; harness `6c1e8736467a7f56e2dd32f06b9d0a9b250212441e254d928f1cb37d85db7a33`. Strict Clippy44-2 and binaries44 passed. Current-source full Rust/Redis/M7/M1/M2, three actual300-second rotations, source-copy provenance and later milestones remain outstanding.

## Peer planned drain passes; expiry and capacity integration continue — 2026-09-11T00:43:59+10:00

M7 remains **43/58 tasks and 44/98 matrix rows verified**. All eight original workers have been retriggered for concrete follow-up implementation or review. No later milestone is started.

The PeerServer/client planned-close repair now passes all four real-H3 tests in0.92 seconds: raw GOAWAY with preserved admitted response, actual PeerServer planned drain, forced-deadline cancellation/join, and emergency pin revocation. The complete transport package passes21 unit tests plus4 H3 tests. The client waits for all existing stream leases before acknowledging GOAWAY, preserving response consumption before QUIC closure. Its current signal requires an exact RemoteClosing observed on a new open; idle/no-new-open remote GOAWAY remains an explicit gap under repair. This component result does not close EC-052's three-relay rotation scope.

The new actual-H3 admission-cancellation regression is causally red in4.02 seconds: cancellation of the inbound authenticated source admission does not drop both held handlers. Its API-only seam is live, but production cancellation propagation remains staged. Native43 signed-trust expiry fails16.47 seconds at2026-09-11T00:40:23+10:00 during client startup because its five-second key window begins too early; this fixture-precondition failure is not security-outcome evidence. The fixture is being reordered to establish both clients before v2 publication.

Native43 credential expiry fails22.22 seconds at00:40:45. New diagnostics identify wait_for_expiry, exact selected rotation12248..20248ms, gate entered/released with one matched held authorization, and expiry14:40:42Z. The owner disappears at the rotation deadline before the required expiry predicate is observed; the strict zero-dispatch and typed expiry assertions remain. Transport passes7.85 seconds at00:40:53 and Redis partition passes10.55 seconds at00:41:04, including bounded authority-loss interruption, readiness withdrawal/recovery, fresh owner and payload-free success summaries.

The reviewed capacity fixture now performs an exact per-device zero-body echo on each new peer exchange before adding it to the held roster. It preserves the same128-stream cap, two-second operation bound, scheduled held-stream keepalives and owned cleanup. Strict checks/build are running; no native capacity pass is claimed.

Native43 snapshot observed2026-09-11T00:40:06+10:00: client `5a0bd88e63125a74d3dc900653f4e3b06306a609d559918dbfb55bbacb98f5d6`; relay `b17190f92cad968f8ed380a45eac214a3fee3ef6c7232352e9a9699412a33af2`; harness `1a565c084f7a3fe8b2db9908ebe0ffc29a57c2c62b01aa9786d71d199b0c494d`. Source-copy provenance remains unverified. Final current-source Rust/Redis/M7/M1/M2, three actual300-second rotations and subsequent roadmap milestones remain outstanding.

## Admission and Redis regressions pass; capacity and planned drain remain open — 2026-09-11T00:34:15+10:00

M7 has **43/58 tasks and 44/98 matrix rows verified**. EC-007 now closes the authenticated forged-header boundary from Native41 admission, and EC-059 closes the declared real-H3 synthetic worker shutdown analogue from its causal red-to-green repair and complete RPC11/11. No real desktop adapter is implied.

Native41 admission passes22.76 seconds at2026-09-11T00:14:56+10:00, including all eight remote/owner-local HTTP corpus results and exact dispatch accounting. Expiry fails22.62 seconds at00:15:18 after the exact held old carrier remains Draining with ACK167 below fence168 until the eight-second overlap deadline. Payload-free phase/token/gate/exact-stream diagnostics are now live for the next run; no production deadline changed.

The Redis source repair isolates atomic authorization EVALs on four bounded physical connections, verified against the primary run ID, while mutations/WATCH/recovery stay on the original connection. The corrected regression causally fails old source because both unrelated authorization and owner read remain blocked while one EVAL reply is held, then passes0.10 seconds with the repair. All31 explicit Redis catalog integration cases pass, including recovery/WATCH and same-authority races. The test keeps its shared250ms observation below locked redis-rs1.7.0's500ms response timeout; earlier red1/red2 runs were fixture-precondition failures and are not promoted.

Native42 peer capacity still fails32.05 seconds at00:27:15, at fill_response peer keepalive index0 with121 held peers. H3 has123 active requests, no handler errors and5/128 permits; owner auth-inflight is0/2/0, while many streams have already terminated during the failed keepalive phase. The four-lane repair is not claimed to close capacity. Production passes19.90 seconds at00:27:35. Exact I08 route faults pass11.70 seconds at00:27:46 and exercise the actual typed terminal branch: TRANSPORT_ERROR, retryable=true, data_reader_closed, exact owner/stream terminal and joined cleanup. Earlier same-session recovery remains dated evidence; reconnect/backoff is still open.

PeerServer planned GOAWAY source is integrated. The forced-deadline and emergency pin-revocation tests pass0.93 and0.01 seconds. Normal admitted-response draining remains failed: locked h3 waits for peer GOAWAY before accept returns None. A client drain response is being designed without closing QUIC while response data is merely queued. Required-false-flag main ExitCode tests7/7 pass. The signed peer-trust expiry fixture is integrated before production token handling; root is resolving routine compile/lint issues before its causal native run.

Native42 snapshot observed2026-09-11T00:26:42+10:00: client `5a0bd88e63125a74d3dc900653f4e3b06306a609d559918dbfb55bbacb98f5d6`; relay `08445dd7dfe67a34cfe919478e8a844c1690f9198e261e318ccc912babac3cfd`; harness `54592dafab1c11d7c86054e09ffb3fcff9705a53e3f60d4a99a57a295a4c8160`. Source-copy provenance remains unverified. Final current-source Rust/Redis/M7/M1/M2, three actual300-second rotations, source-copy and later milestones remain outstanding.

## Echo credit verified; admission accounting and expiry fixture remain open — 2026-09-11T00:06:38+10:00

M7 remains **43/58 tasks and 42/98 matrix rows verified**. The bounded echo response-credit repair passes its three wire tests and the actual connector maximum-body/canary response regression. Native39 confirms all eight remote and owner-local HTTP body cases, including empty and maximum bodies, return the exact expected response with the owner alive. Admission still fails14.20 seconds at2026-09-10T23:55:25+10:00 because observed dispatch delta is4 while eight logical operations succeeded. The owner-local nonstream echo dispatch counter is under repair; the required no-replay and exact-count assertions are retained. Native39 owner-local capacity passes10.07 seconds at23:55:35 and complete production passes19.57 seconds at23:55:55.

Native40 expiry reaches the first planned rotation after the revised two-second pre-rotation hold timing, then fails15.13 seconds at2026-09-11T00:04:39+10:00 because the tenant-B sibling closes before its held-barrier response. The pre-rotation wait currently keeps only the barrier stream active; the required sibling and short-token streams are being checked against the existing idle deadline. No expiry or production timeout has been extended. Strict all-target Clippy40 and workspace binaries pass; the latest complete workspace611/Redis30 baseline predates these changes. The live actual-PeerServer regression remains an intentional causal red until the reviewed GOAWAY production repair is integrated.

Peer planned GOAWAY, active signed-trust expiry cancellation, a synthetic worker post-shutdown admission fence, and isolated Redis authorization transport are staged under independent review. The Redis regression will hold one actual EVAL reply and require unrelated authorization progress before release; source inspection alone is not treated as capacity evidence. All eight original workers have been retriggered for concrete outstanding work. No later milestone is started.

Native39 snapshot `/tmp/agent-tunnel-native-20260910-integrated39` was observed2026-09-10T23:55:11+10:00: client `eeea7d554dfd48a34cdfbb7aa1bf5f1c2f78961b255b4bc861985e4a9c294147`, relay `80ad3a6fbb50d92f0aa77de729a8d812bd4089de084ef7f6f11f381cab2cda3e`, harness `943c3d6711a826e3d0d284968f6a9a5fe8d01b4a88315ea0309e915178419c2c`. Native40 has the same client/relay and harness `d408bf7eda55734410490d50b076586f9f87d884de081b775e2a1df8e9da907f`, observed2026-09-11T00:04:23+10:00. Source-copy provenance remains unverified. Final current-source Rust, explicit Redis, complete M7, M1/M2 including three actual300-second rotations, source-copy and later milestones remain outstanding.

## Native37 recovery pass and new causal regressions — 2026-09-10T23:54:35+10:00

M7 now has **43/58 tasks and 42/98 matrix rows verified**. Root closed EC-032 from current real stalled-consumer/cancellation/sibling evidence and EC-053 at its declared real-H3 synthetic partial-response/late-terminal analogue scope. EC-059 remains open after source review found the synthetic worker registry can admit new work after shutdown; a direct regression and admission fence are being staged. No later adapter implementation is implied.

Native37 passes actual I08 route faults (11.84 seconds at 23:37:19), M1 (22.45 seconds at 23:37:43), and accelerated M2 (17.06 seconds at 23:38:00). I08 performs two planned retirements then closes the exact active relay-b data route while control remains open; the same owner/session/control/stream recovers to generation4, with four ordered records and joined cleanup. It explicitly does not claim GOAWAY. Expiry fails early on fixture JWT InvalidAudience (1.68 seconds); explicit expected issuer/audience/subject validation is now fixed. Native38 reaches the expiry transport but fails23.11 seconds at23:41:10 with owner TERMINAL_FIN_TIMEOUT, and capacity fails25.46 seconds at23:41:35 on peer keepalive index113 while the public keepalive passes. Hold timing, exact auth-gate scope and capacity refresh progress are under repair; production timeouts and stream caps remain unchanged.

Two causal regressions now reproduce separate defects. The focused actual PeerServer test fails0.01 seconds with an untyped QUIC close instead of GOAWAY (`/tmp/agent-tunnel-continuation-peer-server-goaway-red3.log`). The maximum echo test fails at CreditExceeded limit65536, attempted65792 (`/tmp/agent-tunnel-continuation-max-echo-credit-red.log`): the valid request plus its bounded canary exceeds OPEN response credit. The bounded echo credit repair, actual M2 runtime maximum-response test and eventual CLI diagnostic are integrated for verification. The request body limit remains65536. GOAWAY production code remains staged pending emergency precedence and forced cleanup review.

Native38 snapshot observed23:40:46: client `eeea7d554dfd48a34cdfbb7aa1bf5f1c2f78961b255b4bc861985e4a9c294147`; relay `855f0ae4368a9837cee381a577f57a5c0841e4478bb63b0272579ca72a484f2f`; harness `7462ad6aafe261d483cdc089fd6cd62503077415c50b32a69d2fa30153d652a5`. Source-copy provenance remains unverified. Final current-source Rust, Redis, full M7, three actual300-second M2 rotations, source-copy and later milestones remain outstanding.

## Native36 diagnostics and integrated expiry fixture — 2026-09-10T23:37:51+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. Native36 completed five commands without runner timeout: peer capacity FAIL 64.16 seconds at 23:28:54, admission FAIL 9.37 seconds at 23:29:03, I08 rotation faults FAIL 1.37 seconds at 23:29:05, pressure PASS 18.96 seconds at 23:29:24, and production PASS 20.24 seconds at 23:29:44. Pressure proves bounded backpressure, observed queue budget, sibling survival, cancellation without replay and fresh-owner recovery. Production includes three relays, two tenants, three ingress relays, four rotations, eight ordered records, CLI, isolation, authorization negatives, stale-owner fencing, key withdrawal and owner death.

Capacity now identifies `capacity_probe`, public stream 0, one public and 127 held peer streams. At the failure boundary all three owners remain active, with active/terminal stream counts 13/15, 12/26 and 4/24; authorization failure counters are zero. Target H3 accepted 160, active 94, completed 62, cancelled 4, handler errors zero and permits 34/128, while ingress stream permits are 0/128 on the target route. Later shutdown CONTROL_CLOSED/RECOVERY_START_FAILED records are not attributed as the root cause. Admission reaches owner-local maximum-body forwarding before HTTP 503 `REVERSE_CHANNEL_INTERRUPTED`, `execution=unknown`; target owner is absent with exact CONTROL_CLOSED at snapshot 766ms and lifetime dispatch 7. The immediate CLI sample is still running with no protocol category, so its eventual terminal cause remains unresolved.

The I08 fault failure is a fixture/CLI status mismatch: the fixture requires phase, while `ConnectStatusResult` omitted the existing runtime phase. The CLI now emits phase. The independently reviewed credential-expiry module and physical rotation barrier are integrated, along with exact original owner-token diagnostics and retained admission cleanup joins. Root corrected integration type/lifetime errors and adds an explicit unchanged dispatch assertion at the held expiry boundary. Current strict all-target Clippy passes 16.08 seconds and the 12 expiry evidence tests pass after 17.22-second compile. Native37 is running a new immutable snapshot for I08 faults, expiry through rotation, M1 and accelerated M2; it has no completed result at this checkpoint.

Native36 observed 2026-09-10T23:27:49+10:00: client `5ae00d66ef1fbc4f8d1e56dfdca79d74d71cd2e28936ad7ebef9114c2904a599`; relay `855f0ae4368a9837cee381a577f57a5c0841e4478bb63b0272579ca72a484f2f`; harness `ad4d453bfd692312659ac1d9e573b3eac910a7ba72ef20422a2218adb66d8946`. Runtime results: `/tmp/agent-tunnel-native-20260910-integrated36/runtime-results.json`. Source-copy provenance remains unverified. Planned GOAWAY and peer trust expiry with missed hints remain under source review and staged regression work. Final current-source workspace/full M7/default three actual 300-second rotations/source-copy gates and later milestones remain outstanding.

## Current workspace and Redis regression pass — 2026-09-10T23:27:14+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. The current integrated source passes strict all-target Clippy (13.81 seconds) and the complete workspace suite (611 passed, zero failed, 45 ignored, 49 reported targets; compile 46.46 seconds). This includes all 116 client tests and the five added fixed-deadline, rotation-deferral and malformed-proof regressions. Explicit real Redis integration then passes all 30 ignored catalog cases, including duplicate service rejection without namespace mutation, opaque tenant identity isolation, one-use tickets, owner fencing, withheld replies and recovery races. Logs are `/tmp/agent-tunnel-continuation-integrated36-clippy5.log`, `/tmp/agent-tunnel-continuation-integrated36-workspace-tests.log`, and `/tmp/agent-tunnel-continuation-redis36.log`.

The native35 peer-capacity and expanded admission failures remain open. Payload-free exact phase/stream/owner diagnostics and shared owned cleanup are integrated; final admission identity/cleanup refinements are staged. The new actual-CLI planned/unexpected data-route fault fixture compiles and its evidence validators pass, but it has no native result yet. Credential expiry through an exact active rotation and planned peer GOAWAY draining remain staged. No native36 or final source-copy pass is claimed. Later milestones remain unstarted; final M1/M2, three actual 300-second M2 rotations, full M7 and source-copy gates remain required after the final runtime changes.

## Native35 ACK-ordering repair results — 2026-09-10T23:00:21+10:00

Counts remain **43/58 M7 tasks and 40/98 matrix rows verified**. The deterministic FORGET regression is green after the narrow ACK-reordering repair. The complete client suite passes 111 tests; the first full run's sole failure was the sandbox refusing a local listener, and the authorized native rerun passes. Strict all-target Clippy passes in 16.69 seconds and binaries build in 19.93 seconds. Five additional deadline, rotation-deferral and malformed-proof regressions are now integrated and awaiting verification.

Native35 completed all six commands without runner timeout: lifecycle PASS 19.84 seconds at 22:55:05, peer readiness PASS 22.13 seconds at 22:55:27, peer capacity FAIL 30.88 seconds at 22:55:58, clean I08 rotation PASS 15.25 seconds at 22:56:13, expanded admission FAIL 9.54 seconds at 22:56:22, and M2 faults PASS 13.42 seconds at 22:56:36. Lifecycle proves cancellation, stable dispatch, sibling survival and fresh-stream recovery. Readiness includes actual recovered-route echo. I08 preserves exact identities and bilateral fences through three rotations, with four checksummed records and joined CLI cleanup. Capacity still times out in public keepalive. Admission's expanded forged-header HTTPS corpus receives HTTP 503 with no recognized typed body; its exact request phase is under diagnosis.

Snapshot observed 22:54:44: client `5ae00d66ef1fbc4f8d1e56dfdca79d74d71cd2e28936ad7ebef9114c2904a599`; relay `f1c9ebc02e9769cd66f7086c028c60f8f8cb7808cd35ef0bfc5039a3950ef5cd`; harness `8a3b45c1cd1896a50cd2681defda38ee56ef70a2e2c8d8a2ea826be40310461b`. Logs and immutable runtime results are under `/tmp/agent-tunnel-native-20260910-integrated35`. Source-copy provenance remains unverified.

Shared cluster/lifecycle cleanup and the planned/unexpected data-route fault fixture are now integrated for compilation. Cleanup retains joins and aggregates failures. A blocking membership persistence write cannot be forcibly cancelled: the final joined shutdown may exceed its diagnostic deadline, and the source comment records that limit. The expiry-through-rotation fixture remains staged for final independent review. Full current-source workspace/Redis/M1/M2/default-M2/M7/source-copy gates and later milestones remain outstanding.

## Confirmed cross-channel FORGET regression — 2026-09-10T22:49:36+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. Native34 completed with failures in peer readiness (28.80 seconds), lifecycle (16.33 seconds), peer capacity (17.15 seconds), and I08 clean rotation (13.72 seconds). No case reached the runner timeout. Lifecycle recorded the exact static category `stream_forget_connector_incomplete`, one physical public response-writer timeout, and CLI exit 1. Native33 had passed lifecycle in 18.64 seconds with unchanged client source; the subsequent failure shows that pass was insufficient to clear the ordering race.

A deterministic client regression now reproduces the defect: both terminal directions exist and the owner's final R2C sender proof is valid, but control-channel STREAM_FORGET arrives before the independent data-channel ACK for the connector's C2R terminal. The unmodified runtime fails immediately with `STREAM_FORGET connector sender evidence is incomplete` (one test failed, runtime below 0.01 seconds after a 9.66-second compile). The staged repair retains only this narrow valid proof for a fixed five-second revalidation window. Review additionally requires proof convergence to be tracked independently from deferred immutable-roster reclamation during rotation. No repair pass is claimed yet.

The real public-router GOAWAY test passes (one test, 0.12 seconds after a 3.18-second compile). An admitted response is fully drained; a later request returns HTTP 503 `PEER_UNAVAILABLE` with `not_dispatched`, no retry metadata, and no additional owner dispatch. Test-only structural lint cleanup followed and awaits the next complete checks. This does not close full EC-052 or I08 scope.

Shared lifecycle and I08 cleanup remain under correction for consuming timeouts, retained joins, error aggregation, and actual control-route evidence. Credential expiry is staged with token admission before an exact old-route rotation barrier and requires a near-expiry refresh gate plus an explicit post-expiry attempt. Current full workspace, Redis, native M1/M2/M7, three actual 300-second M2 rotations, and source-copy provenance gates remain outstanding. Later milestones have not started.

## Native32 stream-close regression and current integration — 2026-09-10T22:28:32+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. Native32 finished at22:22:29; root session25087 is closed. M2 faults passed13.05s. Lifecycle failed15.37s, peer capacity16.05s, peer readiness28.26s and I08 clean rotation16.00s. None reached the runner timeout. The delayed runner initially waited for macOS to hydrate its cloud-evicted script, then started normally; the guarded stop refused once its snapshot existed. A local copy of the inspected runner is available at /tmp/agent-tunnel-run-native-snapshot-20260910.py for subsequent runs.

Lifecycle now observes one exact public response-writer timeout, unlike native31's zero. It then loses the owner after the CLI exits1 with PROTOCOL_ERROR; owner closure is CONTROL_CLOSED, sibling6/6, target145 local sends/33 dispatches. Capacity now fails during public keepalive rather than at the earlier cumulative128 stream-credit stall. Readiness loses its owner just after baseline stream closure. I08 completes three rotations but cleanup reports CLI exit1. Scope and pressure workers are tracing owner FORGET versus connector validation, including possible cross-channel ordering where control FORGET overtakes the final data ACK; this is a source hypothesis, not yet a confirmed fix.

Both real H3 reuse cases pass through production initial-handshake config APIs (0.33s; combined compile/run29.96s). Strict all-target Clippy passed26.94s after two test-only lint corrections; binaries passed24.91s. Snapshot22:21:00 hashes: client60eaae7535db4b460a6df869587e6478b8a22fe2a91221e782d0a931d3156793; relayf1c9ebc02e9769cd66f7086c028c60f8f8cb7808cd35ef0bfc5039a3950ef5cd; harnessb418a8f7e4bb1aec40ce19464e4ca524f8977cddf3d4833291b4f759ef7c9da4. Source-copy provenance remains unverified.

Dual owner-local/remote public admission probes are now live, awaiting native verification. A real Redis duplicate-service publication test passes1/0.04s after correcting its required test-namespace prefix; the two metadata keys from the initial failed fixture were exactly enumerated and removed. The public router GOAWAY component and locked existing H3 dev dependencies are integrated for compilation; no public GOAWAY pass is claimed yet. Expiry now has an explicit post-expiry local attempt but awaits a real deterministic rotation barrier and shared owned cleanup. Planned data-fault cleanup remains under correction. Final complete Rust/Redis/native/default-M2/source-copy gates and later milestones remain outstanding.

## Reclamation and stream-credit regressions repaired — 2026-09-10T22:14:38+10:00

Counts remain **43/58 M7 tasks and 40/98 matrix rows verified**. Owner STREAM_FORGET and the reviewed dropped-registration correlation test now pass the complete relay library suite: 179 passed, zero failed, runtime 2.54 seconds after a 16.75-second compile. That run also includes the bounded duplex forwarding repair and three authorization-expiry/write-deadline helper tests. Native lifecycle remains pending; the native31 failure is the pre-fix causal regression.

The real locked-registry Quinn regression failed at replacement 1 after exactly one completed stream at limit 8 and seven completed streams at limit 128 (1.03 seconds). The reviewed local quinn-proto 0.11.17 patch changes only the positive MAX_STREAMS advertisement threshold, preserves the existing concurrency limits, and passes both real H3 cases (0.34 seconds after a 22.80-second compile). A separate reviewed fix now installs the existing bidi and uni16 limits before the QUIC handshake; the production-like cluster acceptance endpoint callsite also applies that policy. A rerun through those production config APIs, strict all-target Clippy, and native binaries is active; no native32 result exists yet.

An initial rebuild failed when disk space was exhausted. Lossless native compression recovered 1,609,564,160 allocated bytes across 55 old immutable inode groups and 82 paths. Every path retained its byte hash, executable metadata and hardlink group; the latest integrated31 bundle was excluded. The plan and per-group verification receipt are /tmp/agent-tunnel-native-compression-{plan,receipt}-20260910-2210.json. No source, logs, receipts, or unrelated files were removed.

Credential-expiry, exact data-route fault cleanup and public GOAWAY fixtures remain under review. The expiry probe must distinguish local writer success from peer acceptance and include an actual post-expiry attempt plus authoritative matching terminal evidence. Final full workspace/Redis/M1/M2/default three actual300-second rotations, full M7 matrix, current source-copy gates and later milestones remain outstanding.

## Owner reclamation integrated and GOAWAY component pass — 2026-09-10T21:52:21+10:00

Counts remain **43/58 M7 tasks and 40/98 matrix rows verified**. The real authenticated H3 GOAWAY test passes one case in 0.12 seconds after a 2.70-second compile. It observes typed pre-open GoAway while an admitted A response is held, then completes that response and performs one fresh B request, with bounded owned cleanup. The HTTP 503 PEER_UNAVAILABLE/not_dispatched result is source-mapped; this component test does not execute a public HTTP rejection. No EC-052 full-row or I08 completion is claimed. The locked h3 non-exhaustive error is matched with RemoteClosing { .. }; no feature or version change was needed.

Owner-originated STREAM_FORGET, ordered retry/QUIESCE admission, late-frame fencing, transactional terminal replies and independent terminal-FIN debt are now live. Connector-originated FORGET is rejected as UNEXPECTED_STREAM_FORGET, consistent with the documented owner-only protocol. The old missing-emission regression now passes. The relay library run currently has 175 passes and one old dropped-registration test failure; review is determining its correct pending-OPEN tombstone/ordered reclamation assertions. Earlier compile errors were corrected by retaining the received stream ID before moving a frame and removing an unused QUIESCE tuple value. Static terminal diagnostics include the three new close reasons.

The duplex repair is staged with a scoped local forwarder, three-frame bound and a distinct authorization Expired outcome; physical writer TimedOut remains separate. Its final review is pending. The Quinn 0.11.17 positive-credit correction is staged with unchanged 128 concurrency limits and upstream provenance. A test-only real H3 reuse run is active against the unmodified dependency; no dependency fix or native32 result exists yet. Credential-expiry and planned-close fixtures remain under evidence/cleanup correction. Final full-source checks and later milestones remain outstanding.

## Native31 findings and current repairs — 2026-09-10T21:28:14+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. Native31 completed; root session 99005 is closed. M2 faults passed in 13.89 seconds at 21:28:14. Lifecycle failed in 128.91 seconds at 21:27:28, and peer capacity failed in 32.07 seconds at 21:28:00. Neither failure reached the runner timeout.

Lifecycle now preserves the exact owner in Active with two streams and a running CLI, while the sibling completed 60 of 60 canaries. The target sent 104 records before its producer timed out; owner dispatch was 82 and public writer timeouts remained zero. The same consumer request has an ingress-send timeout and owner-send H3_REQUEST_CANCELLED. This identifies the consumer forwarding path for review: its serial biased input branch can wait on peer writes before reading a pending response. A bounded duplex correction is being staged; no physical writer-stall pass is claimed.

Peer capacity keeps 121 actual owner streams alive, with zero terminal streams and zero target handler errors. The next request stalls in H3 dispatch after 128 total requests were accepted and seven completed; the target has seven of 128 application permits available. The locked Quinn implementation batches MAX_STREAMS credit until more than one eighth of its window has been returned and does not send STREAMS_BLOCKED from open(). This is a source-backed candidate for the remaining credit stall, under focused investigation; no application cap or timeout is being raised to pass the fixture.

The duplicate pending-catalog rotation request regression failed at callback session survival, then passed after exact pending-request coalescing. Current formatting, strict all-target Clippy (24.05 seconds), binary build (20.18 seconds), whitespace and shell syntax checks pass. Owner FORGET has a stable staged implementation under final review. Expiry and planned-close fixtures have additional evidence/cleanup corrections pending; actual H3 GOAWAY is staged separately.

Snapshot observed 21:25:17: client 8da45794ed347d4b4596596881c677303797386ee3a0aa193a26ea008f69dc4c; relay d4090edad2d2cc6bf932e81497045b4657a275661a9dc5142fa55555c1a1e1e8; harness 3d68d7aa4ee27d34b90771f8882f0a6b598ac54c89f2d99c497069ae98659396. Source-copy provenance remains unverified. Final full Rust/Redis/native/default-M2/source-copy gates and later milestones remain outstanding.

## Recovery integration and pending capacity run — 2026-09-10T21:18:53+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. The reviewed Preparing/data-loss repair is live and its five focused loss tests pass. It preserves exact attempt and carrier identity, cancels only the superseded pending ticket, and ignores stale catalog callbacks before classifying their result. Candidate-attached and Aborting loss paths remain explicitly fail-closed. A further duplicate-request callback regression is being corrected to exercise a real M2 fixture before root verifies it red-to-green.

The reviewed peer-capacity keepalive fixture is live. It verifies exact Echo responses, preserves in-flight pulse ownership, and measures a heartbeat-free dispatch comparison below the existing idle limit. Strict all-target Clippy found an unused assignment and an eight-argument helper in this fixture; the minimal correction is staged by the owning worker. No native31 result exists yet. Native30 clean CLI rotation remains the latest passing native gate; current source-copy provenance and final workspace regressions remain outstanding.

Owner FORGET is still staged while review resolves a shared deadline being cleared by unrelated reclamation and assesses other terminal debts. Credential expiry through rotation, planned versus unexpected close, and actual HTTP/3 GOAWAY have active implementation/review owners. All eight original workers have been resumed when their concrete follow-up needed work. Later milestones remain unstarted.

## Native30 clean CLI rotation pass — 2026-09-10T21:05:56+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. Native30 completed (root13711 closed), with I08 synthetic rotation PASS14.69s at21:04:19. The real CLI retained control/session/epoch/stream/operation and synthetic fid through exact generations1→2→3→4; all three latched attempts retained owner identity, immutable fence/ACK digests, bilateral writer flush, commit acceptance and old-carrier closure. Four returned envelopes verified SHA-256, replay remained0, physical device fanout peaked3, and graceful CLI/consumer/cluster cleanup joined. This is synthetic Echo evidence; full I08 forced-phase deadlines, planned-close/backoff, GOAWAY, expiry and adapter-response/close scopes remain open.

Snapshot observed21:04:04: client8da45794ed347d4b4596596881c677303797386ee3a0aa193a26ea008f69dc4c, relay319b13903b33f94de9cdae76dc979194ef138bed3e332c3ddadc4abda1eca062, harnessdeda390d9bece7db059c2e68c23ee9f34d10122b19a42aafe3206d773079db7a. Source-copy provenance remains unverified. Current strict all-target Clippy passed14.57s, bins18.03s, full client110 tests pass, and harness68 tests/1ignored pass. The earlier harness run had67pass/1fail/1ignored because its port-release assertion raced concurrent fixtures; the corrected test retains transferred listener ownership and verifies both exact addresses remain exclusively reserved. All seven new I08 envelope/evidence tests and the forced-process join test pass.

ManagedProcess now bounds forced reaping and output joins, attempts final aborted-handle joins, and reports unresolved cleanup. I08 explicitly requests Unix SIGINT before shutdown and requires successful exit; non-Unix graceful-stop support is an explicit unsupported result, not a passing cross-platform claim. Root additionally bounded the signal command and ensures request errors still reach process/output cleanup.

Owner FORGET remains staged: review caught unrelated successful reclamation clearing a failed-FIN deadline, plus other terminal paths requiring debt assessment. The Preparing/data-loss recovery patch has sorted exact closure IDs and stale catalog callback checks staged under final review; candidate-attached/Aborting remains fail-closed. Peer-capacity heartbeat cancellation was repaired in stage, with strict measured idle gaps still being tightened. Credential expiry and planned/abnormal close fixtures are being staged. No Cargo/native process is active at this checkpoint; current full workspace and all final gates remain outstanding.

## Native29 timing pass and current work — 2026-09-10T20:55:30+10:00

Counts remain **43/58 M7 tasks, 40/98 matrix rows verified** pending full-scope review. Native29 completed (root87830 closed). Snapshot observed20:51:22: client7fca6abb98f1fae1687a79ed2d42054cf677e5cb8b4216ec8c8f978426e5637a, relay319b13903b33f94de9cdae76dc979194ef138bed3e332c3ddadc4abda1eca062, harness2910cc4bd12f001b71a718f2cbd72f3456803dd0c30344488ec4298ee69faa8d. Source-copy provenance is unverified.

Timing PASS52.01s at20:52:23: delayed authorization expired2010ms before owner-safe expiry with dispatch1-to1; partition lease withdrawal30257ms (safe wait25257ms), readiness withdrawal, dispatch1-to1 and new-epoch echo; exact old-generation/candidate rotation deadline2000ms, terminal failed status, dispatch2-to2, new epoch and echo. Full EC055 process pause and EC058 phase-delay scope are not implied by this one passing command. Tail reviews full-row eligibility.

I08 FAIL8.20s at20:51:31 because its known admitted stream temporarily had authorization_in_flight during periodic refresh. Live fixture now preserves exact stream identity during that refresh and requires completed authorization before accepting final rotation proof. Its CLI cleanup also returned SIGKILL: generic ManagedProcess::shutdown waits then kills, so lifecycle stages an explicit graceful-stop path and bounded owned reaping/drain joins. No I08 pass claimed.

Strict all-target Clippy passed integrated29-clippy4 in15.00s; binaries passed23.85s; new consumer diagnostics2tests passed. These predate the subsequently integrated reviewed connector FORGET proof/adapter-debt validation. Full client tests are active46339 after correcting one new test enum constructor. Owner FORGET and recovery ordering fixes remain staged, as do peer-capacity keepalives and credential expiry through rotation. Final required checks remain outstanding; later milestones unstarted.

## Native28 diagnosis and integration — 2026-09-10T20:44:40+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. Native28 is complete (root session88669 closed). It used the exact native27 binary hashes with actor INFO diagnostics; source-copy provenance remains unverified. Timing failed50.81s at20:35:44 and lifecycle failed106.67s at20:37:31. No additional completion is recorded.

Timing now has exact ROTATION_DEADLINE_EXPIRED and a latched event matching old generation1, candidate2, session/epoch, start45158, deadline47158 and fired47158. The fixture rejected this because the failed connector retained its candidate identity. Source confirms publish_closed preserves the previous status metadata and changes only phase. The live fixture now accepts this exact authoritative event only after relay session removal and client closed/failed; identity clearing is no longer required. Exact tenant/device/session/epoch/carrier/timestamp/cause checks and joined terminal cleanup remain mandatory. Native rerun is pending.

Lifecycle exposed client_request at20:37:29 then RECOVERY_START_FAILED at20:37:31. Source review found a request/disconnect ordering race: start_catalog_rotation can enter Preparing before DisconnectData, while begin_recovery_after_loss requires Active. Membership stages the production correction and recovery reviews legal transitions, owned candidate/ticket cleanup and both event orders. This evidence does not establish a public response-writer timeout; that counter remains0 despite effective accepted send buffer8192.

Live source now includes bounded exact terminal-close FIFO events, four-sided request-correlated consumer peer diagnostics, the I08 exact completed rotation proof latch, and deduplicated CLI status events. I08 fixture/main wiring awaits its final owned cleanup correction. Root focused relay diagnostic tests are compiling as72389; current source is not yet fully compiled or verified. Owner FORGET and complementary connector validation remain staged under review; the live owner regression is still red. Peer keepalive stage is under independent review. Final full Rust/Redis/native/source-copy gates remain required; later milestones are unstarted.

## Native27 outcome — 2026-09-10T20:28:59+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. Native27 is complete; root session57577 must not be polled. No Cargo or native command is currently active. Current strict all-target Clippy passed integrated27-clippy6 (14.08s), binaries passed integrated27-bins (17.50s), client107 tests pass, harness59/1ignored pass, accepted-socket3 tests pass, and the real drained-deadline latch regression passes1. The new timing cleanup classifier was compiled by strict Clippy afterward. The last complete workspace remains integrated24 (559 passed/44ignored); one owner FORGET regression remains intentionally red pending the staged implementation.

Snapshot observed20:23:06 at `/tmp/agent-tunnel-native-20260910-integrated27`. Client64c6c8ac5ed17d34d59c424d47577c4deb734cd23c445ad902668022e90419d3; relayafc7f5956a03439ed8c2e789005922eabc30b48e92068ed690f70e569590972e; harnessbae7b53f0908c673306f0c926907f46c89ff1a7f2a3dac0a70e4611b36ae4173. This is a binary observation bundle without source-copy provenance.

Device revocation PASS4.66s at20:23:11, with244ms observed revocation phase: exact credential no longer resolves, B stream terminates, owner releases, new ingress rejects with unchanged dispatch, same-UUID tenant-A owner/stream survives, cleanup joins. Concurrent load PASS13.81s at20:23:25:64 admitted,64 typed capacity refusals,256 ordered records, four producers on one stream, tenant/sibling progress, bounded queues, joined cleanup and physical peak3. Rejection probes are paced to isolate device capacity from the separate ingress admission limit; all admitted streams still run concurrently.

Lifecycle FAIL89.68s at20:24:54. Requested and effective accepted send buffer both8192, but public writer timeout count remains0; owner disappears, dispatch61, sibling38/39, pump134 then timeout. Exact generation1 owner ingress_receive is h3_error and CLI exits4/control_read. The buffer hypothesis is insufficient. Lifecycle investigates four-sided peer/writer events without relaxing timeout policy.

Timing FAIL53.77s at20:25:48. Exact ACK1/fence2 barrier is held, then owner disappears and CLI fails/control_read; no DeadlineExpired log or latched deadline event is present in this run. The new with_rotation_mut deadline-error latch passes its focused real-state regression, but another close path can occur first. Membership stages bounded exact session terminal events captured before removal; the fixture's strict event/cleanup predicate remains unchanged.

Peer capacity FAIL37.08s at20:26:25, held116/128 by retained client handles. Target accepted128, active7, completed12, error109,121/128 permits available. Owner snapshots show owner0 active0/43 terminal43, owner1 active0/43 terminal43, owner2 active7/30 terminal23; authorization failure buckets are all0. This proves held client handles are not live owner occupancy. Pressure stages verified periodic Echo exchanges with exact response checking and bounded idle margins; no production timeout change. Zero STREAMS_BLOCKED frames alone do not rule out H3/QUIC credit waiting.

Remaining staged work: owner FORGET relay emission/retry/late-frame/RESET cleanup (scope, recovery review), connector complementary-direction validator (fragmentation), exact I08 completed proof and response checksum (mid, tail review), peer keepalive fixture (pressure), session terminal diagnostics (membership), and physical writer/peer-path investigation (lifecycle). All original workers have been restarted for needed work; completed workers are resumed when a concrete follow-up exists. Final current-source full Rust/Redis/M1/M2 fault/default3x300s/M7/source-copy checks remain required; later M3/M4/M8/M5/M6 are unstarted.

## Native26 outcome and current integration — 2026-09-10T20:13:10+10:00

Counts remain **43/58 M7 tasks and 40/98 matrix rows verified**. Native26 is complete; root session57287 must not be polled. All four gates failed within their own bounds: device revocation 3.13s at20:04:15, concurrent load 16.94s at20:04:32, peer capacity 35.79s at20:05:08, timing 52.02s at20:06:00. Preserve `/tmp/agent-tunnel-native-20260910-integrated26/runtime-results.json` and its manifest.

Revocation reached the relay's AUTHORIZATION_REVOKED path, then cleanup treated the connector supervisor's joined control-read terminal result as a cleanup failure. The live fixture now permits that exact stop result only after the revoked connector's owner absence and matching terminal readiness are already observed; all other causes/connectors remain failures. `ConnectionHandle::stop` awaits the supervisor through its owned join before returning that result. Native verification is pending.

Load failed with one429/other response. The public WebSocket path has a separate64-permit ingress admission limit held for each socket lifetime; the63 simultaneous over-cap probes can exceed that limit beside held workload streams. The live fixture now paces those rejection probes in windows of four while preserving all64 admitted streams for concurrent workload, and separately labels ADMISSION_LIMIT/SOCKET_LIMIT in diagnostics. Only typed device capacity responses still count as its capacity proof. This fixture adjustment awaits native evidence.

Peer capacity reported116 held, but target relay-a had cumulatively accepted128, only4 active,124/128 stream permits free, and112 generic errors. The generic error bucket included PeerTransportError::Cancelled; live diagnostics now classify those as cancelled. Cumulative QUIC MAX_STREAMS bidi tx1/rx1 and many resets/stops suggest credit/lifecycle accounting requires further investigation. No causal fix or capacity completion is claimed.

The timing pending-record fault now holds ACK1 below fence2 and reaches the exact drain deadline, but the final session removal precedes a diagnostic latch event. A deadline crossed inside state.drained after the earlier maintenance poll is under source review. CLI terminal cleanup has the same control-read result distinction as revocation. Owner STREAM_FORGET remains staged: independent review found sender/receiver final-state incompatibility, missing pre-QUIESCE retry, drop/rejection fencing gaps, late sequenced-frame cleanup gaps and unbounded retry behavior. The one live owner-forget regression remains intentionally red.

The accepted consumer socket buffer patch is live, rebased to preserve C20 diagnostics. It configures accepted streams with safe socket2 and routes accept/configuration errors through cancellation and child joins. Requested/effective sizes are observational; the lifecycle gate still requires an actual public writer timeout. Root fixed the helper argument lint and test constant qualification. Current strict Clippy integrated27-clippy3 is active as57895; current full tests and new native27 remain pending. Parsed pending OPEN and I08 proof repairs remain staged under independent review. Later milestones remain unstarted.

## Current verification — 2026-09-10T20:05:04+10:00

M7 remains **43/58 tasks and 40/98 matrix rows verified**. The last complete workspace baseline is integrated24: 559 passed, 44 ignored, 45 targets. The explicit Redis suite subsequently passed all 29 ignored tests across nine targets. Native25 passed M1 (25.54s), accelerated M2 (13.76s), M2 faults (16.38s), and pressure (16.48s); concurrent load failed on one unexpected HTTP admission response. These results remain historical observations for their exact source/binary snapshot.

Current live source adds target peer-server connection/QUIC diagnostics, bounded status/code diagnostics for unexpected load HTTP responses, an exact outstanding old-carrier record before the timing rotation fault, and the device-revocation fixture with owned bounded cleanup. Strict all-target Clippy passed integrated26-clippy3 in 17.34s before the final cleanup aggregation/test refinement; binaries passed integrated26-bins in 18.79s afterward. The held-route fanout test reproduced a scheduler-dependent expired-deadline assertion, which was corrected to prove actual join, closed route, and idempotent shutdown. All three focused fanout tests then passed. The owner STREAM_FORGET regression remains intentionally failing in live source while its production repair is staged and independently reviewed; do not claim a current full-suite pass.

Native integrated26 is active as root session57287, observed 20:04:12+10:00: device revocation, concurrent load, peer capacity, then timing boundaries. Snapshot `/tmp/agent-tunnel-native-20260910-integrated26` is an observation bundle without source-copy provenance. Hashes: client e9dfb315893f13644ece29e12d59d84c00d3e99640b87e090ff96f6cc4c92784; relay 8391917dbf667dda888fdf8b10719ce96d104b37f267f123c7511a45da4c5909; harness 95ead96f776e0d577b8b15df76fe99789a0f543a994795b03c604d61ed532a62. No Cargo process is active.

All eight original workers were restarted for concrete remaining work. Current staged work includes owner-ordered STREAM_FORGET and companion regressions, parsed pending-OPEN memory accounting, accepted consumer-socket buffer setup/cleanup, and synthetic rotation proof. Independent I08 review found loss of completed pure-state proof, missing exact attempt identity, and request-only checksum verification; these are being corrected before integration. Device-revocation scope uses library connection handles and a 20-second observation phase; it does not prove actual CLI revocation or five-second propagation. No new completion is recorded. Final current-source regressions, M1/M2 faults/default three 300-second rotations, full M7 acceptance and source-copy verification remain required. Later M3/M4/M8/M5/M6 remain unstarted.

## Current verification — 2026-09-10T19:42:14+10:00

M7 remains **43/58 tasks and40/98 matrix rows verified**. Latest integrated24 passes559 workspace tests/44ignored across45 targets, strict all-target Clippy, formatting and binaries. Client104 tests pass; the exact M2 REJECTED regression now exercises actual OPENED before a stale rejection. Logs `/tmp/agent-tunnel-continuation-integrated24-{clippy2,tests,bins2}.log`. Cargo9680 and native58217 are finished; no executable check is currently running.

Native24 observed19:37:00: owner-local capacity PASS8.05s at19:37:09, with abandoned64th reclamation, stableexactowner,64active/63local, exact429 STREAM_LIMIT/not_dispatched/zero dispatch delta, surviving customer and fresh canary, joined normal cleanup. The client previously counted terminal entries as active; separate64active/128retained bounds and exact pending OPEN reply correlation repair that reproduced failure. C27 stays open for its complete remaining scope. No reopening occurred; the mistaken19:30:36 history count is corrected by the later entry.

Peer capacity still FAIL28.77s19:37:38 at124/128held, exactroute4/128available, stage h3_dispatch after sender mutex acquisition. Target-side QUIC/H3 accounting is next; no cap or deadline relaxation. Timing FAIL53.3s19:38:31: exactbarrier g1-to-g2 completed normally, then both relay/client moved to g2-to-g3; deadline event FIFO empty. This proves the existing one-way pause did not hold the tested attempt until expiry. A deterministic pre-rotation pause plus exact outstanding old-carrier record is staged. Lifecycle remains native21failed; source/macOS probe found listenerSO_SNDBUF8192 became65328 onaccepted TCP, so its harness-only buffer hook must apply to the accepted stream before rerunning.

Native24 hashes: client60b727306e80f0896efbae3defd2b66cf28db9b5ed8b4534d465573ce607e65b; relayfc99fcf85a5f82940e11c049a651e0faced884cde5d1995d6e98ec12f06efde5; harness759ea6983550e7f4ad7bff2a38a51b66a1333ef50ce0863a12067e6d09e03826. Native24 is an observation snapshot, not a source-copy receipt. Verified source-copy integrated22 bundle was separately run as native23: M1 PASS20.8s19:27:52 and acceleratedM2 PASS14.51s19:28:07, with receipt-bound identical hashes. These predate the current capacity repair. Preserve the source-copy receipt and all runtime results.

Native24's first binary build failed from disk exhaustion; no source failure was counted. Root hash-verified and hardlinked32 byte-identical task-owned snapshot binaries while preserving every original path/hash and source-copy receipt; dedup receipt is in chat work/native-binary-dedup-20260910.json. Retrybuild passed18.60s. No source, unrelated cache or historical test log was removed.

All8 existing workers are active: fragmentation reviews I06cleanup/nested supervisor ownership; membership stages bounded owned revocation cleanup; lifecycle stages accepted-socket sendbuffer; recovery stages outstanding-traffic rotation fault; pressure stages target H3accounting; scope stages owner-origin STREAM_FORGET; mid stages synthetic rotation/latching fixes; tail independently reviews retention/rotation scopes. I06 and I08 stages are NOT live. Final explicit Redis, M1/M2fault/default3x300s, completeM7 and finalsourcecopy gates remain required; later M3/M4/M8/M5/M6 unstarted.

## Current verification — 2026-09-10T19:23:10+10:00

Counts are **43/58 M7 tasks and 40/98 matrix rows verified**. C30 first completed at19:19:23: bounded exact OPEN retries, pending FORGET cleanup and receive-order stream reservation pass red-to-green regressions, independent fragmentation/tail reviews,102 client tests and native22 M2 faults. Current full workspace integrated22 passes556 tests/44ignored, formatting, strict all-target Clippy and all binaries. Logs `/tmp/agent-tunnel-continuation-integrated22-{clippy5,tests,bins}.log`.

Native22 finished: timing failed54.05s19:18:17 (expected candidate2 deadline recovery, observed quiescing/candidate3); owner-local capacity failed22.59s19:18:39 (original64th admitted with authorization before drop, reclaim0, exact generation1 owner ingress-receive timeout and owner absent); peer capacity failed28.8s19:19:08 (123/128 held, H3 dispatch wait despite5/128 available exact-route permits); M2 faults passed14.53s19:19:23. Session49060 is complete. Lifecycle remains failed from native21 with an exact generation1 owner H3 receive error and no public writer timeout. Workers investigate the causal paths; no admission or timeout contract has been relaxed.

The actual allowlisted source-copy build completed at19:23:10. Session91674 is complete. Receipt `/tmp/agent-tunnel-source-parity-20260910-integrated22/source-parity-receipt.txt` verifies149 source files with identical before/copy/after manifest ed9046a018a562a98a4703e67ab415908e2a3ea96424938cced67bb631db7785. All3 copied binary hashes exactly match native22 (client61ed3c559701283b40b364bab7254c3effc941b64453bfa1090c861b20ddf299; relay533b6e23a58752b0df4fd94e6437c35865c7547710588b7c30ecd4d2aea13588; harness4a2f57fcce89dc5823511f047167945b52ead0fe5c6fb37145ac6bcae9e995ee), with bounded signature/help checks passed. This supplements native22's observation-only manifest; the original manifest remains unchanged. Source-copy build scope only, excluding unlisted files, external toolchain/cache contents and other platforms. Acceptance from the copied bundle is still required.

Device revocation and synthetic rotation fixtures remain staged for independent review. Root resumes source integration after the completed source freeze. Explicit Redis, final M1/M2 accelerated/fault/default3x300s, full M7 acceptance and final-source parity remain required. Later M3/M4/M8/M5/M6 remain unstarted.

## Current verification — 2026-09-10T19:17:22+10:00

Current source passes formatting, strict all-target Clippy, **556 workspace tests / 44 ignored across45 test targets**, all binary builds, and102 client tests (86library,11main,5doctor). Logs: `/tmp/agent-tunnel-continuation-integrated22-{clippy5,tests,bins}.log`, `c30-client-tests-final.log`. The deadline-event regression also passes. No Cargo session is active.

Both extra C30 defects are repaired and reproduced red-to-green: exact STREAM_FORGET purges matching pending OPEN entries before tombstoning, and the first received request reserves its stream ID through rejection/cancellation/compaction using an ordinal rather than BTree ordering. Fragmentation's final source review found no further C30 blockers; tail review/current native M2 faults are pending. Counts remain42/58 tasks,40/98 matrix until final scoped closure is recorded.

Native integrated22 is active as session49060: timing-boundaries, owner-local-capacity, peer-capacity, M2-faults. Snapshot observed19:17:22, manifest `/tmp/agent-tunnel-native-20260910-integrated22/manifest.json`; source provenance remains unverified. Client61ed3c559701283b40b364bab7254c3effc941b64453bfa1090c861b20ddf299, relay533b6e23a58752b0df4fd94e6437c35865c7547710588b7c30ecd4d2aea13588, harness4a2f57fcce89dc5823511f047167945b52ead0fe5c6fb37145ac6bcae9e995ee. Lifecycle is not repeated in this cohort: its known native21 failure has no causal fix yet. New device-revocation and synthetic rotation fixtures remain staged under independent worker ownership. Final explicit Redis, M1, default M2, full M7/source-parity and later milestones remain required.

## Execution override — 2026-09-10T19:11:40+10:00

Counts remain **42/58 M7 tasks and 40/98 matrix rows verified**. Native21 observed19:01:07 and both children completed: timing failed51.31s at19:01:58 (candidate2 expected, preparing/candidate3 observed); lifecycle failed83.49s at19:03:22 (owner absent, dispatch58, sibling35/36, pump138, zero public writer timeouts, exact generation1 owner ingress-receive H3 error, CLI control_read). The candidate-pause timing experiment did not establish causality. Session1127 is finished and must not be polled.

C30 initial journal implementation is live. It passes19 focused OPEN regressions and98 full client tests (82library,11main,5doctor). Root fixed test-module message_size lookup and two Clippy lints; integrated22-clippy2 passed before later fixture changes. Logs use c30-open-green2 and c30-client-tests. The pending OPEN plus STREAM_FORGET case then reproduced a retained FIFO entry after journal compaction; its exact purge fix now passes a red-to-green regression (c30-pending-forget-{red,green}). Retained rejected/cancelled stream-ID reuse is a further open C30 boundary; fragmentation stages a first-received reservation regression and fix. C30 remains open.

New live fixture/diagnostic changes: lifecycle prebound relay-b8KiB send buffer, bounded internal scenario operations and cleanup with uncancelled managed-process reaping; owner-local pre-abandon/tail/cross-relay diagnostics at the original drop point (optional authorization barrier remains unapplied); peer per-attempt validation/connect/permit/H3/envelope progress plus exact route pool counters. Root corrected the progress enum's numeric mapping and attached owner-local pre-abandon diagnostics to the actual failing reclaim-open path. These changes await native reruns.

Timing now binds the old carrier to the same active/candidate identities as its authoritative barrier. A bounded8-entry rotation-deadline event FIFO survives session removal without changing deadline behavior. Root added tenant identity, grouped terminal parameters into RotationBarrier, and retained strict terminal-phase matching. Its focused relay test is running as Cargo session75939; no native session is active. Current complete formatting/strict/workspace, explicit Redis, M1/M2/default3x300s, M7 and source-parity gates remain pending. Last complete workspace is still integrated15 (539passed/44ignored). Later milestones remain unstarted; preserve all dirty/untracked work.

## Native20 outcome — 2026-09-10T18:53:31+10:00

All four native children completed with failure; none reached the runner's 270-second kill bound. Timing (51.66s) passed into the rotation phase, then failed to observe exact candidate-generation-2 deadline recovery while the snapshot showed quiescing/candidate3. Lifecycle (121.43s) hit its own overall scenario deadline without typed physical-writer evidence. Peer capacity (29.25s) stalled at124/128 held streams: two pooled connections,14/16 available connection permits, and stream permits[128/128,4/128]. This rules out exhausting the16-connection pool in that run; the precise H3 admission stage remains under investigation. Owner-local capacity (22.08s) again failed reclaim index0 with owner absent/63dispatches and CLI still running. Immediate raw TLS drop did not resolve it; clean TLS shutdown is not an established cause.

No Cargo or native session is active. Session60497 is complete and must not be polled. Counts remain42/58 tasks,40/98 matrix. All eight existing workers are active on specific C30, lifecycle, peer/owner-local capacity, timing, membership and rotation scopes. C30 is not live yet: independent review found that arbitrary first-by-message-ID operation lookup can reject a legitimate original stream's FORGET after a different-operation STREAM_EXISTS rejection; the stage is being corrected with a regression. Final-source checks remain pending as described below.

## Execution override — 2026-09-10T18:49:46+10:00

Current verified counts are **42/58 M7 tasks and 40/98 matrix rows**. Native18 successor-pending-owner passed in 2.52 seconds at 18:25:18; independent review and exact A-to-B ownership, WELCOME/fence/data identity, pre-ready rejection/no-read/no-dispatch, B-only positive and joined cleanup evidence closed EC-021 and EC-024 at 18:29:45. FP-02 remains verified from native17. Preserve earlier completion history.

Native19 observed 18:37:36. Timing failed in 40.76 seconds during the lease phase at the fresh-client WebSocket handshake; reaching that phase implies the prior authorization phase returned success, but the complete timing gate remains open. Owner-local capacity failed in 23.51 seconds at reclaim index 0, with the owner session absent, 63 dispatches and a still-running CLI with no recorded terminal error. The cause is unconfirmed. Native18 peer capacity failed in 33.17 seconds while holding 122 of 128 intended streams.

Current formatting, strict all-target Clippy and binary builds pass (integrated20-clippy3 and integrated20-bins logs). New live fixture changes are the scoped real-Redis authorization-result delay, readiness recovery barrier, bounded sibling traffic during the public-write stall, redacted peer-pool counters, and immediate raw-connection abandonment at the owner-local registration barrier. The last change tests a lifecycle hypothesis; it does not establish why an owner disappeared. Production limits and timeout semantics are unchanged.

Native integrated20 is running as root session60497: timing-boundaries, lifecycle, peer-capacity, owner-local-capacity. Its immutable snapshot is `/tmp/agent-tunnel-native-20260910-integrated20/`; logs use `/tmp/agent-tunnel-continuation-native-integrated20-<command>.log`. These are binary observations, with source provenance still unverified. No Cargo session is active.

C30 OPEN idempotency remains staged and its three current live regressions intentionally fail. Completed OPEN retries must replay only the retained OPENED or REJECTED; the independent authorization challenge is only in the initial atomic admission pair. Retrying OPEN must not renew authorization. Root corrected the new task-test draft accordingly. Last complete workspace remains integrated15 (539 passed, 44 ignored), preceding current source. Final full workspace, explicit Redis, M1, accelerated/fault and three actual 300-second M2 rotations, M7 acceptance and source-copy parity remain required. Later milestones remain unstarted. Root alone runs Cargo; workers stage patches and source reviews.

## Execution override — 2026-09-10T18:25:02+10:00

Counts are **42/58 M7 tasks and 38/98 matrix rows verified**. FP02 first completed at18:20:55 after source review plus native17 pending-owner success at18:18:25. Exact bounded HTTP/WSS retry responses, zero owner-side body reads/dispatch before readiness and a positive afterward are verified. Public HTTP body consumption is outside that closure; EC021 waits for exact successor identity evidence.

Native17 observed18:17:34. Pending owner passed1.61s. Peer capacity failed23.82s after holding123 of128 intended streams, with a concurrent rotation-roster warning and admission timeout. Owner-local capacity failed24.43s with an echo closing before its response. Capacity fixtures now use the normal300/10/30 policy to isolate their limits from accelerated rotation; all stream/queue limits are unchanged. Owner-local phase diagnostics are being staged.

The successor-owner fixture and bounded proxy cleanup helper are now live and have cleared independent review plus strict integrated18 Clippy and binary builds. Root fixed the startup-timeout import, cloned the reused rotation config and exposed the harness command. Native integrated18 is active as session15907, running successor-pending-owner followed by peer-capacity. No Cargo session is active. Source provenance remains unverified.

Lifecycle's H3 receive-idle behavior is already an intentional transport contract covered by existing tests. Do not weaken it to make the public writer timeout fixture pass. Lifecycle is investigating a scoped server send-buffer reduction and legal sibling traffic to isolate the public write deadline. Recovery stages a timing-only real-Redis catalog decorator to delay one successful authorization result while leaving owner/lease queries live. Fragmentation stages bounded C30 OPEN idempotency; its three live regressions are intentionally red. Last complete workspace remains integrated15 (539pass/44ignored), predating these latest changes. Later roadmap milestones remain unstarted and all final-source regression/parity gates remain required.

## Integrated16 runtime outcome — 2026-09-10T18:12:52+10:00

All four native children ended. Load passed in 16.62 seconds with 64 admitted streams, 64 typed capacity rejections, 256 ordered records, four same-stream producers, sibling/tenant progress, responsive cancellation, joined cleanup and a peak of three device sockets. Pressure passed in 17.25 seconds, including bounded queues, sibling progress, no cancellation replay and same-owner recovery.

Lifecycle failed in 98.60 seconds. The owner-side diagnostic recorded five ingress-receive terminal events, with the selected device/session/generation-5 event classified `timed_out`; owner-send and public response-write timeout counters were zero. The CLI then reported retained recovery after `data_reader_closed/active/g5`. Timing failed in 49.33 seconds: the broad Redis pause triggered a 501-ms `resolve_device` authority failure before the authorization barrier. This is an invalid fixture for isolating the two-second authorization deadline. These two gates remain open; their failures are not converted to success.

Logs: `/tmp/agent-tunnel-continuation-native-integrated16-<command>.log`. The manifest is in `/tmp/agent-tunnel-native-20260910-integrated16/`; source provenance remains unverified. Integrated17 strict all-target Clippy passes after wiring owner-local capacity and the authenticated peer-pool capacity fixture. Three C30 OPEN replay regressions remain intentionally red while their production repair is staged. Counts stay42/58 tasks and37/98 matrix.

## Execution override — 2026-09-10T18:10:00+10:00

M7 is **42/58 tasks verified**, with **37/98 edge-case rows verified**. C28 and C29 first completed at 17:51:32+10:00 for their specific recovery-state and deadline repairs. C30 was added for OPEN message-ID idempotency; the broader milestone remains open. Later M3/M4/M8/M5/M6 implementation has not started.

The last complete workspace run is integrated15: formatting, strict all-target Clippy, **539 passed / 44 ignored**, and all binary builds. Client tests passed 86. Logs are `/tmp/agent-tunnel-continuation-integrated15-{fmt,clippy,tests,bins}.log`. Source changed afterward. Current integrated16 strict Clippy and binary build pass; full tests remain pending.

Native integrated15 observed 17:51:12+10:00. M2 faults passed 19.19s, pending owner passed 4.25s, and production passed 19.76s. Pending-owner evidence includes zero owner-side ConsumerChunk reads before HTTP/WSS readiness and [1,0,0] afterward, exact 503/not_dispatched responses, the same owner, and joined cleanup. Concurrent load failed with one transport outcome; pressure failed its two-second terminal-cleanup deadline. Neither failure is yet attributed to a production cause. Load had passed integrated13/14. IN01 stays open. Snapshot receipts remain binary observations without source provenance.

Live changes after integrated15: exact pending OPEN cancellation removes the matching head/queued request before later admission (two red-to-green regressions); authoritative authorization challenge timestamps and fixture ordering; bounded owner-side peer transport diagnostics; bounded load/pressure failure categories. Integrated16 native timing/lifecycle/load/pressure is running as session81651 using an immutable binary snapshot. Its manifest is `/tmp/agent-tunnel-native-20260910-integrated16/manifest.json`.

Root alone runs Cargo. No Cargo session is active at this checkpoint. Agent stages live under repo `work/`. Fragmentation implements bounded OPEN replay/retention in scratch; pressure repairs the 128-peer-stream fixture to use one public canary and 127 authenticated production peer admissions; scope has staged owner-local 64-stream capacity with the CLI consumer on a different ingress; mid has staged successor control-only readiness, under membership review. Source-copy parity, final full workspace, explicit Redis, M1 and actual default three-300-second M2 checks remain required. Preserve all dirty/untracked work and both Redis instances; never flush shared Redis.

## Integrated13 outcomes — 2026-09-10T17:35:53+10:00

Native integrated13 passes concurrent load14.02s at17:28:17 and M2faults13.95s at17:30:26. Load exercises128attempts,64admitted/64typedcapacityrejections,256orderedrecords,4same-streamproducers,tenant/siblingprogress,responsivecancellation,joinedcleanup andpeak3. Lifecycle still fails98.55s with activeg5 reader loss and retained recovery; the old queued-duration protocol rejection is gone. Timing fails17.21s because its paused-client probe times out without the required typed expiry. Logs /tmp/agent-tunnel-continuation-native-integrated13-<command>.log and snapshot manifest in /tmp/agent-tunnel-native-20260910-integrated13. No source-provenance claim.

Current transport classification repair passes10realH3 probe tests and18transport tests. Expired candidate RESUME before the maintenance tick is reproduced and repaired;4focused Resume regressions pass while retaining immutable episode and exact identity/replay guards. Integrated13 strict Clippy,build and77harness tests pass before these latest core changes. Full final-source checks remain pending; counts40/57tasks,37/98matrix.

## Native integrated12 and current repairs — 2026-09-10T17:25:21+10:00

Current counts:40/57 tasks and37/98 matrix rows. Integrated12 full workspace passed formatting, strict all-target Clippy,526normal tests/44ignored and binary builds. Later source changes require a fresh complete pass. Logs: /tmp/agent-tunnel-continuation-integrated12-{fmt,clippy,tests,bins}.log.

Native integrated12 passes owner-loss-effect4.72s (FP05 first completion17:06:34), side-effect12.06s (EC054 reverified17:06:46), M2faults15.96s, peer-readiness22.20s and Redis-partition12.37s (EC011 reverified17:08:21). FP05 uses a synthetic append counter through real public POST and three relays: one effect before owner loss, exact503/unknown, zero replay/later effects, unchanged sibling owner with exact200 response, and joined HTTP tasks. No real adapter claim. Its binary hashes and observation time are in /tmp/agent-tunnel-native-20260910-integrated12/manifest.json; this does not prove source provenance.

The same snapshot fails concurrent load15.34s at its final validator and lifecycle28.64s with data_reader_closed/active/g1 followed by recovery_resume_remaining_budget. Load fixture cleanup evidence was assigned after validation; ordering is corrected, rerun pending. C29 now tracks the valid queued RESUME failure. The reviewed no-extension repair preserves the fixed local deadline and exact identity/replay guards; its valid/expired/context regression passes3/3. Original carrier loss and candidate-expiry ordering still need verification.

Current real WebSocket deferred-OPEN/CANCEL regression is red; current real H3 permit-capacity classification regression is red (9pass/1fail). These are unresolved production issues, not superseded by the older full workspace pass. EC055 authoritative timing diagnostics and command are connected; initial compile type inference is corrected and strict validation is underway. Full final-source socket/Redis/default-M2/M7 acceptance and source parity remain open.

## Renewal and native regression update — 2026-09-10T16:55:07+10:00

Current relay189 tests/5ignored and strict workspace Clippy2 reverify C07/C12/C13 after the admission changes; tasks40/56, matrix35/98. Integrated11 passes side-effect14.61s, public admission22.77s, transport7.85s, pressure17.53s and production21.15s (four rotations). Its FP05 append fixture fails7.27s because intentional owner shutdown produces a held-response control close which cleanup treats as unexpected. Expected-close scope, postfault owner sampling and nested HTTP joins remain under repair. Logs /tmp/agent-tunnel-continuation-native-integrated11-<command>.log.

The renewal-burst regression is red before repair and green after retaining bounded pending challenges and updating refresh state only on successful enqueue. The green verifies all20 challenges through four freed slots and unchanged deferred deadline. Logs /tmp/agent-tunnel-continuation-refresh-burst-{red,green}.log. Current full client75 tests pass including precise safe Resume diagnostics; no timing predicate was relaxed. Full harness tests exposed an allowlist omission (55pass/1fail), now patched pending rerun. Pending-OPEN critical-control starvation remains unresolved; these passes do not close C22 or the lifecycle gate.

## Current integration checkpoint — 2026-09-10T16:47:51+10:00

Integrated10 native binaries passed pending-owner HTTPS/WSS (3.71s), side-effect interruption (12.37s), key rotation (5.41s), and strengthened peer-readiness recovery (18.08s). Pending admission returns exact503/not_dispatched/retryable250ms/Retry-After1 with zero dispatch before a successful post-ready canary. C25 first completed16:38:37; EC054 reverified16:39:27 and FP07 reverified16:39:32. These do not close successor-specific/body-sentinel or actual adapter scopes. Counts:37/56 M7 tasks and35/98 matrix rows.

The same snapshot failed concurrent load (19.28s, four transport outcomes, CLI queue_limit), owner-loss-effect (18.78s, wrong synthetic OPEN operation/framing before backend append), and lifecycle (48.41s, owner lost at23 dispatches, recovering, CLI protocol cause recovery_resume_context, no typed physical-write timeout). Logs `/tmp/agent-tunnel-continuation-native-integrated10-<command>.log`; hashes and timestamps in `/tmp/agent-tunnel-native-20260910-integrated10/manifest.json`. This receipt does not establish source provenance.

FP05 fixture source now uses echo_stream and exactly one framed device record for each raw public body; runtime remains pending. The current full relay package passes189 tests with5 ignored, including real-H3 cancellation/reuse and retained terminal replay-budget release: `/tmp/agent-tunnel-continuation-integrated11-relay-tests.log`. Full client73 tests passed before adding a deterministic renewal-burst regression, which fails with exact Err(QueueLimit): `/tmp/agent-tunnel-continuation-refresh-burst-red.log`. The seventeenth challenge overflows the fixed16-message channel after refresh state mutation. Pending OPEN also currently suppresses critical control reads and renewal processing; both are unresolved C22 work. Latest full-workspace507pass/44ignored remains historical integrated6 evidence.

Status: implementation in progress after locally verified M2 (`dbe4c03`).
The M1 HTTP/3 probe proves the transport boundary; it does not prove cluster
routing. No M7 acceptance gate is satisfied by adding types or configuration.

The M2 baseline also passed all hosted checks in
[CI run 34372389312](https://github.com/andymac4182/agent-tunnel/actions/runs/34372389312):
Linux, macOS and Windows Rust checks, M1 real-socket acceptance, and M2
rotation/recovery acceptance including the default interval.

## Current acceptance status (2026-09-10)

| Check | Latest local outcome | Scope |
| --- | --- | --- |
| Locked workspace tests | Current integrated rerun remains open | Client55 tests pass. Latest workspace attempt found missing RelayActor background_failure field in new lifecycle code; earlier run hit disk-full linking. No complete current workspace result. |
| Strict all-targets Clippy | Current client passes; workspace rerun pending | Current client diagnostic passes strict Clippy. Earlier scoped relay pass predates per-operation task ownership changes. |
| Workspace formatting | Final rerun pending | Earlier checkpoints pass; current lifecycle, recovery and admission edits require the final check. |
| Expanded HTTP/3 fault command | Dated scoped pass; affected final rerun pending | Earlier acceptance proves bounded authenticated transport, role/pin rejection, framing, cancellation, budgets, UDP loss/recovery and joined shutdown. It does not close all production route or adapter faults. |
| M2 real-socket faults and default rotations | Isolated diagnostic snapshot passes three actual300-second rotations | The10:10 copied snapshot completes in905.6s on separate Redis. Prior09:30 authority failure remains unexplained. Pending lifecycle/control changes still require final-source regression review. |
| Production three-relay command | Current1000 snapshot passes all mandatory flags | Same-UUID tenant isolation, four rotations and production flags pass on the stated snapshot. New task-ownership/control diagnostic edits require affected reruns. |
| Peer readiness loss/recovery | Current1000 snapshot passes in14,607ms | Six real-H3 probes and targeted UDP loss/fresh-path recovery pass; current native pressure still loses the owner while all peer routes remain ready. |
| Operator recovery CLI | Positive actual-CLI Redis/TLS case passed | Initialize, observe, quiescence refusal, fresh-incarnation recovery, retained revocation and approval replay refusal pass against the same disposable Redis through authenticated TLS. Full backup/rollback process exercise remains open. |
| Relay cleanup/lifecycle | I24 reopened for every-task scope | Earlier outer-supervisor and ten real-H3 cleanup passes remain scoped evidence. New per-operation JoinSet, claim cleanup guard and bounded shutdown need current integrated tests. |
| Complete98-row acceptance matrix | Open;16/98 rows verified | All98 rows have been independently audited; missing admission, ownership, pressure/close, recovery, artifact and applicable synthetic adapter gates remain explicit. |

The entries below preserve component findings and their subsequent repairs.
They are local worktree evidence; they do not assert hosted CI or alpha readiness.
Rows labelled as a dated baseline are historical evidence and do not become
current after later implementation changes until their exact rerun is recorded.

## Implementation order

1. Bounded signed membership/checkpoints, peer records and request contracts.
   Reuse the catalog's complete `OwnerToken`; do not introduce a second owner
   authority or duplicate ownership types in transport handlers.
2. Atomic Redis coordination: incarnation-scoped TTL leases/presence/tickets,
   retained epochs, and bounded signed-record storage. Durable tenant, grant,
   credential and revocation records remain independent of incarnation.
3. Reusable full-duplex HTTP/3 with separate relay mTLS, bounded streams and
   cancellation. Keep the existing M1 probe as a regression fixture.
4. Owner routing, owner-side authorization, connector fencing and diagnostics.
   The owner alone runs M2 rotation. Each ingress forwards directly to it.
5. Three real relays and isolated Redis acceptance, including rotation,
   partitions, key lifecycle, owner death, recovery and resource bounds.

The contract crate depends on catalog identity types. The catalog does not
depend on cluster policy: it stores bounded signed bytes, while cluster policy
verifies them against operator-installed trust and a fresh checkpoint. A Redis
record cannot supply its own trusted signing key.

## Required evidence

Initial coordination checks pass locally against the disposable Redis fixture:
five existing catalog integration tests and nine cluster integration tests in the
latest explicit rerun.
The new tests cover concurrent owner claims, TTL versus durable keys, one-use
ticket binding, credential revocation after issue, concurrent ticket consumption,
expired owner rejection, and opaque membership publication. These component
results do not satisfy the three-relay acceptance gate below.

The cluster contract crate's 29 unit tests pass, including signed membership,
nonce checkpoints, strict request envelopes, retry certainty and peer-record
resource accounting. Prior local runs also passed the full-duplex transport
command and synthetic three-relay command. These commands use a synthetic owner
callback and do not prove the production relay actor, device WebSockets, OIDC
revalidation and rotation together.

The current worktree requires fresh validation after tenant-scoped session and
bounded cleanup changes. The initial 2026-09-10 locked offline workspace check identified interrupted
edits in those paths. After repairs, the all-targets workspace check passed,
along with 85 protocol tests and 34 relay library tests. These are component
results; the updated complete socket acceptance remains pending.
Production multi-node membership loading and configured peer idle/drain behavior
are also under review before integration acceptance.

The mandatory edge-case expansion is tracked in
[docs/m7-edge-cases.md](m7-edge-cases.md). It maps all 98 rows from the
2026-09-10 Kaizen inventory source file, its dated incidents, and its outstanding
staging gates to Agent Tunnel invariants and concrete tests. Component tests
remain component evidence only; every row is Unverified until its
revision-specific cross-relay, lifecycle, Redis-authority, or adapter evidence
is run. The matrix also records the required fail-closed no-fallback boundary,
the privileged-adapter analogue of the source SQLite cases without adding
SQLite, and Agent Tunnel's same-owner data-carrier rotation semantics.

| Gate | Required assertion |
| --- | --- |
| Membership | Valid signatures, deployment/role/key/endpoint binding; forged, expired, replayed, downgraded and conflicting records fail closed. |
| Checkpoint | Startup nonce and minimum versions are verified; a stale Redis snapshot cannot bootstrap trust after restart. |
| Coordination | Concurrent acquisition, exact-token renewal/release, TTL and ticket consumption remain atomic; catalog keys survive incarnation changes. |
| H3 transport | Real bidirectional bodies, mTLS negatives, bounded buffering, cancellation and joined tasks; no fallback or 0-RTT. |
| Routing | Control, active/replacement data and consumer ingress deliberately use different nodes, with exactly one hop to the owner. |
| Authorization | Ingress and owner independently validate scope; a relay credential cannot substitute for a consumer grant or device enrollment. |
| Rotation | Three same-owner rotations drain immutable logical stream fences through peer forwarding. |
| Failure | Owner death, UDP/Redis partitions and process pauses interrupt explicitly; no automatic operation retry or Redis promotion. |
| Resources | Prefix/body/copy charges, stream and connection caps, small-record item caps and cancellation remain bounded. |
| Regression | Existing M1 and M2 suites, locked Rust checks and real Redis tests remain green. |

See [cluster.md](cluster.md) for the normative trust, routing, timing and
recovery contracts. Tests use synthetic data and dedicated resources.

## Component verification history (2026-09-10)

After the tenant-scope and directory fixes, locked offline runs passed 85
protocol tests, 42 relay library tests, 44 cluster tests, and 12 transport
tests. An earlier explicit Redis run passed five catalog and seven cluster
integration tests, including the three-node membership directory and per-node
conflict and capacity checks. A later explicit rerun passed five catalog and
nine cluster integration tests, including the signed role/endpoint/node
mismatch negatives; the actor test registers both tenants sharing a device
UUID, rejects duplicates, and disconnects only the selected tenant.

These results precede the final peer cleanup edits. Full formatting, strict
Clippy, workspace tests and socket acceptance must be rerun after those edits
and the production three-relay harness are complete. The 98-row edge-case
matrix remains unverified at the full acceptance scope.

### Fault-run finding: pending H3 receive cancellation

The expanded real `verify-m7-transport` blackhole case reproducibly panicked
in `h3-quinn` 0.0.10 `RecvStream::stop_sending` after a response-head timeout.
The pending read future owns the Quinn stream, leaving the adapter's optional
stream field empty; cancellation unconditionally unwraps it. `recv_id` has the
same assumption. The backtrace reaches this through
`PeerClientRecv::recv_response`. The narrow vendored fix and real-socket
regression below resolve this observed panic; broader M7 gates remain open.

The test was first corrected to retain the blackholed stream. Body truncation
now waits until the client receives a prefix before the server resets, and
requires a transport error rather than accepting clean EOF. Fixture fixes
alone do not close the underlying cancellation finding.

### Pending-read cancellation regression, 2026-09-10

The expanded `verify-m7-transport` command passed locally after the vendored
h3-quinn 0.0.10 cancellation fix. The previous command panicked when a pending
receive was stopped on timeout. The adapter now retains its Quinn receive
stream directly, caches its stream ID, and stops that stream synchronously.
The regression holds one response body pending until its idle deadline, repeats
cancellation three times, and verifies a sibling stream on the same HTTP/3
connection still completes. The command also exercises head/body truncation,
idle blackholes, saturation cancellation and active pin revocation. See
`vendor/h3-quinn/UPSTREAM_PATCH.md` for the narrow dependency patch.

Command (local macOS, locked dependencies, disposable loopback listeners):
`cargo run -p tunnel-test-harness --locked --offline -- verify-m7-transport`
returned exit 0. This is transport-component evidence only. Production
three-relay connector startup and the full M7 matrix remain open.

The subsequent locked offline workspace test command passed, including all 18
harness unit tests after fixing a target-acceptance/teardown race in the proxy
snapshot test. Strict workspace/all-targets Clippy also passed before that
small test-only correction. The rebuilt `verify-m2-faults` command returned
exit 0 against the isolated Redis fixture; reset/broken-pipe diagnostics are
expected during its injected socket faults. The production M7 run still
fails: fresh control ingress requires an existing owner before registration
can claim one. That admission-path defect is under repair; these regression
results do not close the production gate.


### Production path findings after initial admission repair

Fresh control now takes the local atomic registration path only when the
catalog reports no live owner. Data ingress and authority errors remain
fail-closed. The next real run identified two consumer path defects: the full
Authorization header was forwarded where the envelope requires a raw token,
and the peer handler added a second length prefix to an already-framed actor
response. Both were corrected; the next run successfully exchanged echo
records through non-owner ingress and the peer-forwarded device data socket.

Sustained traffic then reached a transport `BodyTooLarge` error at 262169 bytes
against a 262144-byte limit. The transport counters accumulated lifetime
traffic rather than in-flight memory. This is an open defect: long-lived
streams must retain bounded memory without a tiny cumulative transfer ceiling.
That run did not complete rotation and is not a passing production gate.

The five public-API membership/readiness regressions in
`crates/tunnel-relay/tests/m7_readiness.rs` passed with locked offline Cargo.
They reject an invalid signature, an expired checkpoint before reading the
catalog, and missing local membership. Failed refresh makes the runtime
unready and blocks new peer admission without extending existing signed trust;
explicitly expired membership invalidates already admitted peers. These tests
use synthetic authority/catalog doubles and do not replace process-level
Redis/peer outage or readiness endpoint acceptance.


### In-flight memory regression result

The safe RAII accounting repair passed the real `verify-m7-transport` command,
including repeated transfers on one stream and multiple streams on one pooled
connection beyond the configured cumulative byte totals. Reservations now
bound retained memory rather than lifetime traffic. Unit tests cover retained
clones, final-drop release, failed connection reservation rollback, and empty
chunks. No unsafe code is used in this repair.

The next production run retained sustained echo traffic and reached scheduled
rotation. Candidate ingress then correctly rejected an unready membership
runtime: the fixture authority reused checkpoint version 1 with a new nonce
on refresh. The fixture must advance checkpoint versions; the verifier's
rollback/conflict protections must remain unchanged.


### Cross-relay rotation reached; isolation fixture expansion required

After checkpoint versions advanced monotonically, the real production run
attached replacement generations 2, 3 and 4 and passed the three accelerated
rotation assertions. The command then failed at a consumer negative expecting
a denial but receiving HTTP 503. Both tenants deliberately reuse the same
device/service UUID; tenant B therefore addresses its own authorized device,
which was not connected. Treating this response as a cross-tenant denial would
be weak evidence. The next task connects both devices concurrently and proves
separate canary delivery, while using a genuinely unauthorized principal for
the negative. The full command has not passed.


### False-success acceptance defect: M7-I13

The expanded two-tenant run returned distinct canaries for the two concurrently
connected devices sharing device/service UUIDs, and preserved tenant A's stream
after tenant B's exchange. It also observed three committed rotations and a
built CLI control/data session. However, the command returned exit 0 with:

```text
relays=3 tenants=2 ingress_relays=3 rotations=3 ordered_records=7
cli=true tenant_isolation=true authorization_negatives=true stale_owner=true
key_revocation=false owner_death=true
```

This is not a complete acceptance pass. The harness discarded failed required
boolean assertions. Its pin-removal probe also checked the HTTP upgrade alone,
although peer admission occurs after that upgrade. M7-I13 requires mandatory
result validation plus a bounded post-upgrade no-delivery assertion. The
observed tenant-isolation result closes only that narrow fixture task; signed
membership revocation and the complete M7 gate remain open.

## Strict production rerun and cleanup guards (2026-09-10)

The current uncommitted worktree built with locked offline Cargo and passed
`TEST_REDIS_URL=redis://127.0.0.1:60278/ tunnel-test-harness verify-m7-production`
against dedicated local Redis and real loopback mTLS/H3/WSS listeners (exit 0).
Output: `relays=3 tenants=2 ingress_relays=3 rotations=4 ordered_records=7
cli=true tenant_isolation=true authorization_negatives=true stale_owner=true
key_revocation=true owner_death=true`. The harness enforces per-device physical
socket peak at most three and predecessor drain before CLI restart. This closes
M7-I01/I13/I14 at that dated local scope, not the full edge-case matrix;
subsequent fixture and production changes keep the current rows open pending
the latest rerun described below.

Focused locked offline relay tests passed: `terminal_cleanup` (3 tests) and
`dropped_stale_control_cleanup_cannot_close_successor_session` (1 test).
Pre-reply cancellation reclamation (M7-C12) is still in progress; rerun affected
checks after its edits.

The rebuilt `verify-m7-transport` also passed on 2026-09-10: duplex, role/pin rejection, truncation, idle timeout, cancellation, sibling isolation, budget reclamation and joined shutdown all returned true (exit 0).

Locked offline workspace tests passed again on 2026-09-10 with loopback
network permission (exit 0; `/tmp/agent-tunnel-workspace-tests.log`). The first
sandboxed attempt failed ten socket-binding fixture tests with EPERM, then
the identical test command passed with networking enabled. Explicit Redis
tests remain separate. This run precedes the pending C12/C13 and partition edits.

Review identified M7-I15: owner-death acceptance counted any harness connection
error as a successful interruption. Its historical passing output therefore
does not independently prove the intended no-owner response; a stricter
classifier and production rerun are required.

Explicit locked offline Redis integration rerun passed on 2026-09-10: five `redis_catalog` tests and seven `redis_cluster` tests, with `--ignored --test-threads=1` against the dedicated local primary. This precedes new M7-I09 recovery regressions.

## Recovery regression increment (2026-09-10)

All nine ignored `redis_cluster` tests passed with locked offline Cargo against
the dedicated local primary. New tests prove that a live owner prevents
incarnation activation, operator release allows activation, the old catalog
cannot renew or claim afterward, durable membership and grant revocation
survive, and ordinary startup rejects a mismatched stored Redis run identity.
The test changes only UUID-qualified fixture metadata; it does not restart
Redis or prove backup rollback detection. M7-I09 remains open for external
checkpoint, backup verification and rollback evidence.

The recovery-test increment also passed `cargo clippy -p tunnel-catalog --all-targets --locked --offline -- -D warnings` on 2026-09-10. This is catalog-only validation while actor/HTTP cleanup edits remain active.

## Drop-safe outbound accounting intermediate check (2026-09-10)

`cargo check -p tunnel-relay --all-targets --locked --offline` passed after
QueueCharge ownership moved into queued text/binary items. It reported four
unused API/field warnings, which must be removed before strict Clippy.
The subsequent relay test command passed 51 unit tests and five readiness
tests (loopback allowed; `/tmp/agent-tunnel-relay-tests.log`). These are the
existing regressions; new pre-reply cancellation tests and the final
production rerun remain required for C12/C13.

The new relay test `dropped_outbound_receivers_release_shared_queue_budget` passed (locked offline Cargo, 2026-09-10). It verifies both control and data receiver-drop release; it does not yet prove rotation cancellation or in-flight writer cleanup.

The current relay increment passed all 53 unit tests and strict all-targets
relay Clippy on 2026-09-10 (locked offline Cargo). C12 remains open: the
oneshot helper regression proves return of an undelivered value, but not
reclamation of admitted actor state. A deterministic stateful regression
is still required. The earlier transient-owner polling test failed and was
removed rather than accepted as timing-dependent evidence.

The combined harness built on 2026-09-10. First UDP-restoration runtime failed: server refused the replacement QUIC connection after the blackhole. M7-I16 remains open; this is not accepted as a successful recovery.

The first real Redis-partition run failed its recovery deadline: the relay correctly closed the old device session when authority expired, but the fixture required that same owner to recover. The scenario must establish a fresh authenticated session with a newer fenced epoch, join its predecessor, and prove no replay. This failure leaves M7-I05 open.

Nine membership-readiness integration tests passed with locked offline Cargo on 2026-09-10. New cases cover staged key overlap, explicit old-key removal, old-key expiry, and reconcile without refresh hint. These exercise the signed runtime with controlled fixtures; real network propagation remains M7-I06.

UDP restoration rerun passed after restoring forwarding before retiring the old peer. `verify-m7-transport` returned all ten flags true, including udp_blackhole_restored and joined_shutdown, with the one-connection server cap retained. M7-I16 closes at its real transport scope; process-pause and three-relay UDP lifecycle cases remain separate.

Global pause existing/new-connection regression passed (2026-09-10). An intermediate production rerun failed because the key-revocation fixture required WebSocket upgrade even when the relay rejected at HTTP 503. That failure remains historical fixture evidence; the corrected production rerun recorded below superseded it for M7-I13 at its declared local scope.

## Real Redis partition recovery passed (2026-09-10)

Rebuilt `verify-m7-redis-partition` exited 0: `relays=3 paused_connections=1
partition_ms=8213 admission_rejected=true dispatch_interrupted=true recovery=true`.
The injected outage produced expected owner-check and cleanup warnings. The
fixture verifies explicit admission rejection, bounded active-stream closure,
unchanged owner dispatch count after authorization expiry, and a fresh
authenticated session with a higher epoch after old-owner fencing. The narrow
owned process-pause result is recorded as I18 below; broader process-pause,
rollback, and production UDP lifecycle cases remain M7-I05/I09.

The stateful `dropped_control_reply_reclaims_admitted_state_before_stale_cleanup`
test passed through the production response-completion helper. Data and echo
response-completion coverage remains open under C12.

The combined admitted-state regression passed after adding production data response-completion cleanup. Review found its echo branch closes the receiver before admission and thus covers only the early cancellation path; post-admission echo cleanup remains required. Normal production rerun reached restored pin verification but received HTTP 503, so the broader production gate is still open.

Current locked offline workspace Clippy and workspace tests passed again on
2026-09-10 (loopback enabled for tests). The diagnostic production run passed
the revocation/restoration phase but failed with connection refused at the
owner-death probe. Source review found its ingress was hardcoded to relay-c,
which can itself be the newly selected CLI owner being shut down. M7-I15 must
select a surviving ingress explicitly; the old generic-error success branch
would have concealed this defect.

C12 admitted-state regression passed with the strengthened echo branch: it first admits a real M2 echo stream, then exercises undelivered response cleanup through the production helper, asserts stream removal/cancellation and budget release. Control/data helper cleanup and stale-successor protection are exercised in the same test.

All ten relay cleanup tests passed on 2026-09-10, including new C13 receiver/writer lifetime, rejected enqueue rollback and idempotent release regressions. C13 closes at its focused accounting scope; current production recovery validation remains open.

The next diagnostic run confirmed repeated data attachment under the original epoch, followed by the fixture timing out while waiting for an impossible automatic higher epoch. The recovery predicate now accepts the exact original OwnerToken only when client session/epoch and active control/data match, or a matching newer owner; positive restored echo remains required. This preserves M2 same-owner data recovery instead of requiring an unnecessary full reconnect.

Corrected production rerun passed (exit 0): relays=3, tenants=2, ingress_relays=3, rotations=4, ordered_records=7; CLI, tenant isolation, authorization negatives, stale owner, key revocation and owner death all true. The run uses exact owner/client recovery matching, positive restored echo, and a surviving ingress after owner shutdown. This revalidates I01/I13/I14/I15 at their declared production scope, not the complete 98-case matrix.

The next full locked offline workspace test run passed on the corrected production baseline (exit 0, 2026-09-10). Dedicated M1/M2 acceptance reruns remain necessary before the next milestone boundary.

M1 acceptance rerun passed after shared cleanup changes (2026-09-10): clients=5, echo_requests=21, list_assertions=5, auth_rejections=4, revocation_ms=5, disconnects=3, proxy_connections=2, proxy_closes=1, quota_assertions=6, queue_rejections=1, cli_echoes=1, cli_smoke=1. This is local fixture evidence, not hosted CI.

M2 socket-fault rerun exited 0 on 2026-09-10 after cleanup changes; the logged connection-reset/broken-pipe messages are expected injected faults. Rebuilt session 54854 also completed the three actual default 300-second rotations with exit 0; the log had no payload summary, so the earlier 903.05-second elapsed time remains the only elapsed-time claim.

C14 maintenance diagnostics regression passed after reading the structured REJECTED code. Authority-read failure now reports AUTHORITY_UNAVAILABLE; confirmed ownership loss and identity denial remain OWNER_FENCED/AUTHORIZATION_REVOKED. The test verifies session closure remains fail closed.

The focused cluster membership unit slice passed on 2026-09-10:
`cargo test -p tunnel-cluster membership::tests --locked --offline` returned
exit 0 with 10 tests, including signed RoleNotAllowed, EndpointNotAllowed and
PeerNodeMismatch negatives. This closes C01 at the membership component scope;
live Redis refresh and restart/recovery evidence remains C06/I03/I19/I20/I21.

The owned synthetic process-pause command passed on 2026-09-10:
`verify-m7-process-pause` exited 0 with
`relays=3 peak_sockets=3 elapsed_ms=8029 interrupted=true joined=true
fresh_owner=true recovery=true`. This proves the owned synthetic CLI
suspension, bounded join, fresh-owner recovery, and scoped relay no-forward
counter; it does not exercise a desktop or close the broader M7-I05 lifecycle
gate. Output: `/tmp/agent-tunnel-process-pause.log`.

Relay session 6135 terminated at compile with `QueuedText`. Corrected session
64400 reached 75 passed and 1 failed: the C07 `attachdata` path returned
`Unauthorized`. All `membership_version_state` tests passed in that session,
closing the store component scope while I20 production load/save wiring remains
active. The first recovery-test pass also failed 5 of 6 cases on fixture time
ordering; that fixture repair is awaiting rerun, so I19/I20 remain open.

At the earlier C06 implementation snapshot, redacted `livez`/`readyz` routes
and a readiness dispatch gate had been added after the absent-route/
unconditional-200 finding; focused endpoint, redaction, dependency-loss, and
admission tests were still pending and no live `rediss`/health endpoint result
was recorded. The current focused endpoint result is recorded in the latest
validation section; live `rediss` integration remains open. The pure six-test
I19 approval-verifier slice is dated baseline evidence; the canonical recovery
snapshot and atomic catalog-generation fence remain open. The audit found
omitted orphan/direct-lookup/epoch keys, `WATCH` phantoms, pre-bound
`HGETALL`/`SMEMBERS` allocation, and a same-incarnation live-owner bypass.
I20's store then had standard OS sidecar locking, safe no-follow FD validation,
and a private parent directory; at that earlier audit point runtime wiring
remained open. The completed verifier fix and `new_with_store` wiring are
recorded in the latest validation section.

The Redis TLS API and real mTLS forwarder fixture passed in build 40800:
`verify-m7-redis-tls` exited 0 with
`authenticated_catalog_connection=true`, `wrong_ca_rejected=true`,
`wrong_server_name_rejected=true`, and `wrong_client_identity_rejected=true`.
Output: `/tmp/agent-tunnel-redis-tls.log`. This closes the narrow TLS fixture
scope only; full relay `rediss` deployment and health integration remain C06.
Transport session 87755 exited 1 only because `mutation_positive=false`; its
production assertions still reported `no_tcp_fallback=true`,
`zero_rtt_disabled=true`, `raw_idle=true`, and admissions `1->1`. The positive
control fix is active work and C03 remains open.
False-flag handling in `main` is fixed; the affected acceptance commands require
a fresh rerun before C11/I13 can be promoted. The focused privileged RPC suite then
passed its narrow component scope: `cargo test -p tunnel-test-harness --test
m7_privileged_rpc --locked --offline -- --test-threads=1` exited 0 with 3 tests
in 0.04s. The tests cover bounded bodies before manager dispatch, partial
responses as a transport-interruption analogue without internal replay, and
exact mTLS owner/assignment/epoch/route binding over the synthetic manager and
real `PeerRuntime`; they do not verify production adapters, Redis, SQLite, or
later adapter semantics. The command output is in
`/tmp/agent-tunnel-rpc-tests.log`. Relay session 6135 terminated at compile;
corrected session 64400 reached 75 passed and 1 failed on `attachdata`
`Unauthorized`, so no full relay package pass is counted here. Focused
device-epoch test session 43644 failed before test execution because a
`membership_runtime` `MutexGuard` was held across an await and was not `Send`;
the owner fix is pending rerun, so no C07 result is counted.

Corrected catalog session 32255 exited 0 with 23 unit tests, including six
approval and six full-schema tests, plus five `redis_catalog` and nine
`redis_cluster` tests. Current-generation mutation regressions passed. Output:
`/tmp/agent-tunnel-catalog-current.log`. Session 77305's earlier compile
failure preceded this corrected pass. This does not prove the new signed
recovery integration: seven tests are staged by `finish_cleanup` and are being
linked next.

At that earlier validation point, the real signed key-rotation/expiry socket
test for I06 was active with `m7_readiness_tests` and no new result was counted.
The I07 production-pressure implementation was present in
`real_cluster_harness`, but no Cargo or runtime result was recorded. A
read-only `verify_scope` audit is checking applicability,
evidence scope, and circular adapter dependencies before the 98-row matrix is
edited. At that earlier checkpoint, the I20 staged verifier change was fixing
healthy-refresh closure after normal checkpoint save invalidated all healthy
peers; the verifier fix and `new_with_store` production wiring are now
complete, with the corrected fixture rerun recorded below still pending.

Source review found a certificate-overlap binding defect tracked as C18:
`PeerBindingProvider::binding` selects the first signed-valid SPKI, so an
incoming/new-server overlap certificate can be globally approved yet fail
equality against that first key. The fix must use certificate-specific signed
binding plus exact node/boot/endpoint validation, with real H3 old/new positive
controls and an unknown-key negative. At that earlier source-review point no
runtime result was recorded; the later narrow result is in the latest
validation section and broader propagation remains I06. The read-only matrix audit also advises
waiting for the root production result before revising any 98-row dispositions.

Redis recovery session 41268 exited 0:
`cargo test -p tunnel-catalog --lib --test redis_recovery --locked --offline
-- --include-ignored --test-threads=1` passed 24 unit and 8 real Redis
recovery tests. The bounded verified subset covers signed activation and digest
preservation, revoked-digest mismatch, orphan fingerprint/epoch/unknown keys,
durable TTL, missing durable device epoch (the current seed always creates 0),
live-owner blocking of same and new incarnation, and expired, untrusted, or
wrong-run refusal. Output: `/tmp/agent-tunnel-redis-recovery.log`. This does
not close I19/I21: cancellation, ambiguous EXEC, deterministic-generation-race,
and operator-workflow evidence remain open.

Compile session 21471 failed only on new fixture issues: a shadowed runtime
helper, missing `ClusterConfig` state path, and missing mutation-pressure
fixture. Agents are fixing those issues; no I07 runtime result is counted.
That recorded session predates completion of the I20 `new_with_store` wiring and
verifier fix; the corrected persistence fixture and its runtime rerun remain
pending.

## Latest scoped validation (2026-09-10)

The earlier full relay validation log, `/tmp/agent-tunnel-m7-validation-tests.log`,
contained 87 tests: 86 passed and one C07 failure in
`http::peer_cleanup_tests::peer_consumer_error_reclaims_scoped_stream_and_queue_charge`.
The focused cleanup log, `/tmp/agent-tunnel-m7-validation-cleanup.log`, contains
0 passed and 1 failed; both failures end with the peer response missing H3
response headers; this remains chronological evidence. The most recent focused
cleanup checkpoint passes 1/1 with a real H3 `PeerClientStream`: a valid
envelope receives 200/OPEN, a declared one-byte consumer prefix with no payload
is followed by FIN, `RecordingHandler` increments its error count before
revocation, and the raw stream is terminal while the original stream's queue
bytes remain charged. This proves the direct consumer returned-error cleanup and
sibling-isolation subset. The earlier terminalized-challenge result remains
chronology. The remaining control/data returned-error cases are staged by
`peer_deadlines` after successful control registration and data admission, using
malformed peer framing before actor cleanup; broad all-exit coverage remains
open. The staged control-cleanup fixture's two-catalog setup was rejected in
review; it is being corrected to one authority or explicitly scoped direct
post-admission handler testing. No new control/data result is counted.

The fresh suite/build checkpoint in `/tmp/agent-tunnel-m7-validation-tests.log`
records relay library 88 passed/0 failed, health endpoints 1/0, persistence
4/0, readiness 9/0, harness library 27 passed with 1 ignored, harness main 6/0,
live membership 1/0, and privileged RPC 4/0. The standalone binaries build
also passed (`/tmp/agent-tunnel-m7-validation-build.log`). This is local
library/harness and build evidence, not a production three-relay acceptance
pass or hosted CI result.
The 4-test privileged RPC baseline is preserved. The expanded target then
passed 6/6 in `/tmp/agent-tunnel-m7-validation-m7_privileged_rpc-final.log`,
including shared-pool isolation for colliding customer/privileged IDs,
deadline and retained-worker cleanup, body bounds, partial-response
uncertainty, and exact mTLS owner/epoch/route checks. The source target now
has seven tests: the shutdown-named case was corrected to assert deadline
behavior, and a separate active-worker shutdown case is awaiting validation;
there are no fixed sleeps in the deadline assertion. This remains a synthetic
manager over real mTLS `PeerRuntime` component analogue, not production
adapter, Redis, SQLite, or later adapter evidence.

An earlier `verify-m7-transport` runtime failed only its mutation positive
control; that failure remains chronological. The fixed runtime now passes all
stated gates in `/tmp/agent-tunnel-m7-runtime-verify-m7-transport-fixed.log`,
including no TCP fallback, 0-RTT disabled, raw-idle handling, mutation positive
control, and stable admissions. The root cause was test-only
`ClientSessionMemoryCache(4)` ticket eviction; bounded size 16 preserves reuse.
This closes C03's narrow transport scope. `peer_fault_harness` is frozen for
handover after the separate C19 `peer.rs`-only chunking change; that change is
unvalidated. Broader relay/production matrix evidence remains open.

The task-owned fixture permission correction now gets the latest
`verify-m7-production` run past the strict membership-state parent check, but
the run fails later with `production echo closed before response`
(`/tmp/agent-tunnel-m7-runtime-production-current.log`). Static phase diagnosis
is active and has not identified whether the initial or maximum-size canary
failed. No C19, canary-isolation, or complete production acceptance assertion
is counted. `real_cluster_harness` repairs only its task-owned fixture
directory while production private-path checks remain strict. Affected current
rows stay implemented-awaiting-verification under C06/I12/I20 until the
focused diagnosis and required reruns pass; prior startup and production
passes remain dated history.

M7-C19 is in handover. The generic encoded-record boundary is explicit: a
valid `CompleteDeviceData` body of 65,600 bytes encodes to 65,608 bytes, above
the 65,536-byte H3 chunk maximum. `peer_fault_harness` is frozen after changing
only `crates/tunnel-transport/src/peer.rs`, where unvalidated
`send_chunked(&[u8])` methods/helper sequentially split by the actual
`BodyBudget.max_chunk_bytes`. The continuation task must wire the two send
helpers in `peer_runtime.rs`, remove the unused `Bytes` import, add focused
tests, and run transport/maximum-size production validation. Consumer
workaround bodies remain 65,528 bytes. Preserve the advertised limit and
required auth/isolation behavior; runtime verification is pending and no
boundary pass is claimed. Dedicated security auditing is deferred to Daybreak
when requested.

The focused health endpoint log, `/tmp/agent-tunnel-m7-validation-m7_health_endpoints.log`,
passes one test, `livez_stays_observable_while_readiness_and_dispatch_fail_closed`.
It verifies the narrow local redacted endpoint and dispatch-gate behavior only.
Configured `rediss` authority loss, full health integration, and the broader
readiness matrix remain C06/I04. The live membership log,
`/tmp/agent-tunnel-m7-validation-m7_live_membership.log`, passes one test in
0.07 seconds, `m7_signed_membership_rotation_closes_old_h3_and_preserves_new_sibling`.
That slice proves old/new certificate positives, rejection of an unknown
same-node certificate, and no-hint signed removal/expiry. It closes the narrow
C18 slice; propagation, expiry bounds, and deployment diagnostics remain I06.

The local persistence/restart log, `/tmp/agent-tunnel-m7-validation-m7_membership_persistence.log`,
now has 4 passed and 0 failed, alongside prior `membership_version_state` unit
coverage in relay session 64400. This verifies the local store and
persist-before-publish scope for I20. Full server-process deployment and
configured health/readiness integration remain C06; the broader gate still
requires fail-closed corrupt/mismatched-state coverage. The exclusive-validator
recovery checkpoint passed `redis_recovery_races` 2/2
(`/tmp/agent-tunnel-m7-validation-redis-recovery-races.log`) and
`redis_recovery` 10/10 (`/tmp/agent-tunnel-m7-validation-redis-recovery.log`),
including oversized-key, cumulative-key-byte, and dedicated-connection cases.
These are verified I19/I21 subsets only. Operator CLI recovery and post-EXEC
ambiguity remain open. The staged `recovery.rs.disabled` module now contains
three ignored recovery test cases, but they are not linked into Cargo and have
not run; `wiring.md` likewise has no integration evidence. Read-only
observation followed by external trusted public-key approval and a persisted
approval-version fence remains required; there is no private signing or
automatic promotion, and old-primary quiescence remains an operator
responsibility.

The I07 production-pressure implementation now compiles, but no runtime
pressure result is recorded. The earlier session 21471 fixture compile failure
is retained above as chronology. The `real_cluster_harness` EC011 public
`/livez` 200, `/readyz` 503 during a real Redis partition, then `/readyz` 200
after restore assertions and mandatory-flag mapping are implemented; Cargo and
runtime verification remain pending. An active `verify_scope`
synthetic RPC slice targets EC065/EC066 terminal/commit/success-ACK counts and
the frozen, fenced, pending, poisoned, stopped, and uncertain manager-state
admission cases; it also has no result yet. The EC065 source-RPC
transport-finish/application-success countermodel correction is active and
unverified. I21 retains the requirement to bound
raw `SCAN` key-response allocation before processing; the bound code is
implemented, with two ignored Redis regressions for oversized keys and
cumulative bytes awaiting rerun. Neither slice proves a later production
adapter or hosted deployment.

The repository now includes `scripts/m7-harness-verify.sh` and an M7 CI job.
Only local script-syntax and workflow-YAML checks have been performed; no
hosted CI result is claimed. These scoped results do not change the open M7
gate or the 98-row matrix disposition.

Component audit plus corrected catalog session 32255 (23 unit tests, five
`redis_catalog`, and nine `redis_cluster`, all passed) closes C02 at its
catalog/coordination component scope. C04/C05 also close at their named
component scope using component regressions and dated production evidence; the
current production startup failure does not provide a current cross-relay
claim. The seven staged
signed-recovery integration tests and external signed recovery/rollback remain
I19/I20/I21 tasks. No hosted CI result or current full M7 gate pass is claimed.

## Continuation component checkpoint (2026-09-10T08:06:16+10:00)

Existing branch `andymac4182/c/m7-cluster-foundations`, base HEAD
`dbe4c03b82ac59e52d01f427c4ed05b148a9b8a6`, plus the preserved M7 worktree.
Root is the sole Cargo runner, using Rust 1.95.0, locked/offline dependencies,
shared target `/tmp/m1-harness-check.xDlqRa/target`, debug/incremental disabled
and two build jobs. No milestone or matrix-wide completion is claimed.

- `cargo test -p tunnel-cluster --locked --offline`: 47 passed, no ignored tests. Log `/tmp/agent-tunnel-continuation-cluster-unit.log`.
- `cargo test -p tunnel-catalog --test redis_recovery --test redis_recovery_races --locked --offline -- --ignored --test-threads=1`: 10 + 2 passed against dedicated Redis at loopback port 60278. Log `/tmp/agent-tunnel-continuation-redis-recovery-permitted.log`. The initial sandboxed run could not connect (OS error 1); normal loopback permission resolved this environment limitation.
- `cargo test -p tunnel-catalog --test redis_catalog --test redis_cluster --locked --offline -- --ignored --test-threads=1`: 5 + 9 passed on the same isolated fixture profile. Log `/tmp/agent-tunnel-continuation-redis-catalog-cluster.log`.

These checks reverify the unchanged cluster/catalog component slices. Staged
operator recovery, peer fragmentation, production routing, pressure, current
M1/M2 gates, and full workspace checks still require execution.

Continuation focused checks: `cargo test -p tunnel-protocol -p tunnel-core --locked --offline` passed 85 + 8 tests (`/tmp/agent-tunnel-continuation-protocol-core.log`). After the C19 edits, `cargo test -p tunnel-transport -p tunnel-relay --lib --locked --offline` passed relay 106 and transport 18 tests (`/tmp/agent-tunnel-continuation-transport-relay.log`). This includes the maximum-record reconstruction and all three linked H3 cleanup tests: post-admission control truncation, duplicate-owner refusal, and data-carrier truncation; the first remains explicitly component scope. The rebuilt harness and client bins passed their locked/offline build (`/tmp/agent-tunnel-continuation-build.log`). Production acceptance is in progress; no pass is yet claimed.

Production result at 2026-09-10T08:11:50+10:00: `/tmp/agent-tunnel-continuation-production.log` exits 1 with `key-revocation owner/data recovery exceeded its bounded deadline`. The command advanced past initial/maximum canaries and three rotations, but this partial scope is not a production acceptance pass. Follow-up M7-I22 records diagnosis and required rerun.

At 2026-09-10T08:15:59+10:00, the rebuilt `verify-m7-transport` passed every required flag
(`/tmp/agent-tunnel-continuation-transport-acceptance.log`): duplex, role/pin
refusal, oversize, truncation, idle deadline, cancellation, active pin
revocation, sibling isolation, budget reclamation, restored UDP blackhole,
no TCP fallback, disabled 0-RTT, and joined shutdown.

Staged test results: membership boot replacement passed 1/1 in 1.52 seconds
after explicit Arc trait-object coercions; its unused fixture fields still
need strict lint cleanup. RPC passed 6/7: the new active shutdown test loses
response headers before reaching the shutdown barrier. Log
`/tmp/agent-tunnel-continuation-membership-rpc-fixed.log`. Operator recovery
passed 2/3, with live-owner test returning `CatalogUnavailable` before its
expected `ActivationFailed` stage. Log
`/tmp/agent-tunnel-continuation-recovery-workflow.log`. Both failures remain
open and must not be counted as successful stage coverage. Production
pressure exits 1 on `cancellation_not_replayed=false`
(`/tmp/agent-tunnel-continuation-pressure.log`), tracked as M7-I23.

`verify-m7-process-pause` passed at 2026-09-10T08:18:36+10:00 on the fragmentation build: three relays, peak three device sockets, elapsed 8,029 ms, explicit interruption, owned child joined, fresh higher owner, and recovery canary. Log `/tmp/agent-tunnel-continuation-process-pause.log`. Later readiness changes will require this gate again. The M7 reusable script now includes linked operator-recovery and live boot-replacement targets; `sh -n scripts/m7-harness-verify.sh` passes, but the full script has not passed.

At 2026-09-10T08:23:16+10:00, both `/tmp/agent-tunnel-continuation-production-diagnostics.log`
and `/tmp/agent-tunnel-continuation-production-repeat.log` record exit0:
three relays, two tenants, three device ingress relays, four replacement
generations, eight ordered records, and all CLI/isolation/auth/fencing/peer
revocation/owner-death flags true. Both include the original maximum-size
single-WebSocket request. The second run was required by the unexplained
previous timeout; neither passing run explains that intermittent failure, so
M7-I22 remains open. Diagnostics changed fixture observability only.

The corrected `m7_live_membership_boot_replacement` and `m7_privileged_rpc`
targets pass 1 + 7 tests (`/tmp/agent-tunnel-continuation-membership-rpc-final.log`).
The RPC fixture's five-second active-worker deadline now has a consistent
stream lifetime; all original partial/terminal/effect/confirmed-success and
join assertions remain. This reverifies I11's synthetic analogue scope.

Operator `recovery_workflow` now passes all three ignored tests at 2026-09-10T08:24:36+10:00: persistence failure refuses activation; schema-valid live-owner activation refusal consumes the approval version; unknown post-EXEC outcome remains ambiguous and consumes the version. The fixture now signs after its owner claim updates durable epoch/generation. Log `/tmp/agent-tunnel-continuation-recovery-workflow-final.log`. Binary-level CLI tests and the complete operator/runbook gate remain pending.

At 2026-09-10T08:25:58+10:00, `verify-m7-redis-partition` passed all flags on the diagnostics
build: three relays, one paused Redis fixture connection, 6,124ms partition,
new admission rejected, active dispatch interrupted, livez observable, readyz
unready during partition and ready after fresh-owner recovery. Log
`/tmp/agent-tunnel-continuation-redis-partition-fixed.log`. The classifier now
recognizes only exact CLUSTER_UNREADY/not_dispatched in addition to the existing
authorization rejection classes, keeping unknown/unrelated failures negative.

`cargo test -p tunnel-relay --test recovery_cli --locked --offline -- --test-threads=1`
passed four tests: strict unknown/duplicate/missing arguments, initialize
create-only, recover missing-fence refusal before approval/Redis access, and
observe without reading the fence/trust files. Log
`/tmp/agent-tunnel-continuation-recovery-cli.log`. The M7 script includes these
binary tests as well as all three ignored public-workflow tests.

At 2026-09-10T08:31:55+10:00, `verify-m7-pressure` passes all required flags: real three-relay
CLI baseline, 34 complete 64KiB records sent before bounded cancellation,
observed bounded queue pressure, live sibling canary, joined producer, exact
bulk-stream cleanup, stable post-cleanup dispatch, higher-owner recovery and
recovery canary. Peak device sockets3, elapsed9,100ms. Log
`/tmp/agent-tunnel-continuation-pressure-cleanup.log`. The attempted workload
remains256 records; cancellation stops at the observed pressure point. An
intermediate proposed loose counter allowance was rejected before claiming
verification. The final fixture separately bounds pre-cleanup in-flight work
and requires no counter movement after terminal/buffer cleanup convergence.

Strict workspace Clippy is still in progress. Current fixes remove redundant
borrows/range checks in catalog recovery, consolidate equivalent orphan
checks, initialize Redis TLS options directly, and represent the existing
readiness guard as Option<Response>. No lint is disabled. Catalog all-targets
strict Clippy passes; full workspace rerun remains required.

At 2026-09-10T08:40:40+10:00, M1 real-socket `verify` passes on the latest successful pressure build: clients5, echoes21, list5, auth rejections4, disconnects3, proxyconnections2, quotaassertions6, queue rejection1, CLI echo1 and smoke1. Log `/tmp/agent-tunnel-continuation-m1-regression.log`. The same built harness is now running three actual300-second M2 rotations; no pass is claimed yet. Ongoing source changes still require their affected final gates.

Peer readiness component filter passes9/9 with current route revision fencing, per-route capacity and monotonic probe expiry. Log `/tmp/agent-tunnel-continuation-peer-readiness.log`. This does not yet prove real H3 probe or productionmain wiring; those remain C20. One unused sibling snapshot in the concurrently staged cleanup test is being corrected before strict Clippy.

At 2026-09-10T08:45:39+10:00, strict relay binary Clippy passes after productionmain readiness wiring (`/tmp/agent-tunnel-continuation-relay-main-clippy.log`). The executable installs verified nonlocal routes, starts its authenticated peer listener while public admission is unready, and supervises bounded probes with membership/pin invalidation. Real-H3 and configured process proof remain pending. Review separately found the RunningRelay drop/early-error cleanup gaps now tracked as I24. Workspace format check currently fails on formatting across staged recovery/readiness/cleanup modules; no final format pass yet.

At 2026-09-10T08:49:27+10:00, client library tests pass39/39 (`/tmp/agent-tunnel-continuation-client-lib.log`). M2 targeted real-socket faults `verify-m2-faults` exit0 (`/tmp/agent-tunnel-continuation-m2-faults.log`; expected injected proxy resets are logged, no separate numeric summary is emitted). The owned disposable Redis AOF restart script passes (`/tmp/agent-tunnel-continuation-aof-restart.log`) using the pressure-build harness and a uniquely labelled fresh container; cleanup exits0. This proves same-dataset AOF behavior, not backup rollback.

New cleanup/probe tests have not passed yet: first compile was blocked by a prematurely linked missing probe child, then the linked compile found two wrong sibling snapshot references plus unused imports/variables. Exact log `/tmp/agent-tunnel-continuation-cleanup-h3-linked.log`; owners are correcting these without changing production assertions.

At 2026-09-10T08:52:43+10:00, the corrected real H3 cleanup child suite passes6/6 in2.03s (`/tmp/agent-tunnel-continuation-cleanup-h3-fixed.log`): control malformed/refusal, data truncation/idle-deadline and consumer cancel/server-shutdown paths. The idle fixture first observes exact carrier recovery, drains legitimate control notifications, then requires zero queue charge. Remaining applicable per-route exits are being added; C07 stays open. Subsequent unused-snapshot/import corrections need the final lint/run.

Local doctor unit checks pass8/8 and actual CLI tests pass5/5 on Unix (`/tmp/agent-tunnel-continuation-doctor.log`, `/tmp/agent-tunnel-continuation-doctor-cli.log`). Success, invalid config, key/directory permissions, missing credential/redaction, key mismatch and expiry are exercised at their stated scopes. A duplicated report field still raises a non-test dead-code warning and is being corrected before strict client Clippy. No network doctor, supervisor IPC or other OS result is claimed.

At 2026-09-10T08:57:28+10:00, `verify-m2-default` completed exit0 after three actual300-second rotations on the earlier pressure build (`/tmp/agent-tunnel-continuation-m2-default.log`). This predates current relay lifecycle changes and is not final-source M2 closure. Strict client all-targets Clippy now passes after doctor report/lint corrections (`/tmp/agent-tunnel-continuation-client-clippy-fixed.log`).

The rebuilt focused `verify-m7-key-rotation` gate passes: relays3, preparing phase, candidate generation2, observed pin revocation and stream interruption, retained same-owner recovery, duplicate dispatch rejected, peak sockets3, elapsed4,005ms. Log `/tmp/agent-tunnel-continuation-key-rotation.log`; build log `/tmp/agent-tunnel-continuation-build-key-rotation.log`. A real opaque TCP proxy holds the exact active device direction and the candidate is revalidated at withdrawal. This proves that focused outcome, not every rotation phase or the cause of the earlier intermittent ordinary-production failure; I22 stays open.

At 2026-09-10T08:59:03+10:00, `m7_startup` runs6 actual relay-binary tests: five pass and one fails because unknown-field TOML diagnostics include the synthetic secret value. Log `/tmp/agent-tunnel-continuation-startup.log`; tracked I25. Corrupt/insecure membership state, unavailable checkpoint/Redis and identity/config refusals pass. Later-stage cases use a bounded TLS RESP stub to reach the binary startup branches; this is not a real authoritative Redis/configured deployment pass. The secret is test-only and the failing assertion remains required.

At 2026-09-10T08:59:54+10:00, final client package test run passes39 library +8 binary unit +5 actual doctor CLI tests with no warning (`/tmp/agent-tunnel-continuation-client-final.log`). Strict client all-targets Clippy also passes. This closes M0-05 local Unix doctor scope; network and supervisor IPC remain explicitly unimplemented.

At 2026-09-10T09:04:28+10:00, the current relay library suite runs133 tests:132 pass and one capacity-probe expectation fails (`/tmp/agent-tunnel-continuation-relay-lib-reborrow.log`). All ten real-H3 cleanup cases and five other real-probe tests pass, alongside three initial lifecycle component tests. The capacity test receives bounded Transport(Timeout) from an exhausted stream permit instead of expected Capacity; the owner is checking the actual transport contract and automatic readiness withdrawal/recovery. No complete relaylib pass is claimed. Later lifecycle panic/deadline and real-listener additions remain in progress.

At 2026-09-10T09:10:28+10:00, redacted `m7_startup` passes all6 actual-binary tests with no warning (`/tmp/agent-tunnel-continuation-startup-redacted.log`). The operator workflow target still passes its original3 cases, but the new actualCLI case correctly refuses its plaintext Redis configuration before initialize (`/tmp/agent-tunnel-continuation-recovery-cli-workflow.log`). The test is being upgraded to authenticated TLS forwarding to the same disposable Redis, preserving configured policy. No CLI-success/activation claim yet.

At 2026-09-10T09:17:18+10:00, the full relay library suite passes135/135 (`/tmp/agent-tunnel-continuation-relay-lib-lifecycle.log`). This includes all10 real-H3 cleanup cases, all6 real-H3 readiness probes,10 readiness component cases, the TOML source-redaction regression and5 lifecycle cases. The capacity recovery repair retires the pooled destination after a failed authenticated round trip under the existing outer deadline; the next probe can establish a fresh authenticated connection. No deadline extension or hidden retry is used in that focused test (`/tmp/agent-tunnel-continuation-peer-probes-retire.log`).

The actual operator recovery CLI positive case passes against a synthetic TLS forwarder to the same disposable Redis authority (`/tmp/agent-tunnel-continuation-recovery-cli-tls.log`): create-only initialization, redacted observation, explicit quiescence refusal, approved fresh-incarnation recovery, retained durable revocation and approval replay refusal. The original3 workflow cases passed in the earlier target run; the new focused case is a separate pass. The TLS fixture has bounded connections, handshakes, forwarding lifetime and joined shutdown; production `rediss://` policy remains enforced.

Current relay all-target Clippy initially found scoped-lock-across-await and fixture argument-order defects; these have been corrected but the strict rerun is pending. The expanded production readiness build currently fails a UDP proxy borrow-check error (`/tmp/agent-tunnel-continuation-build-readiness.log`); no three-relay readiness result is claimed. The CLI readiness command and implemented-suite script are wired, with mandatory evidence validation. New source changes require affected production/M1/M2 reruns before final closure.

At 2026-09-10T09:19:33+10:00, strict relay all-targets Clippy passes (`/tmp/agent-tunnel-continuation-relay-clippy-tls-fixed.log`). Together with the135-test relay run and six actual-binary startup cases, this verifies I25 TOML diagnostic redaction. The subsequent lifecycle supervisor follow-up adds unexpected-success/panic handling and abort-on-drop joins; those new changes still need the final suite. The corrected readiness binary build passes (`/tmp/agent-tunnel-continuation-build-readiness-fixed.log`); subsequent UDP cleanup adjustments require a rebuilt runtime pass.

At 2026-09-10T09:27:27+10:00, the final relay supervisor slice passes137 library tests (`/tmp/agent-tunnel-continuation-relay-lib-supervisors.log`), the complete non-ignored relay package suite (`/tmp/agent-tunnel-continuation-relay-package-current.log`) and strict relay all-targets Clippy (`/tmp/agent-tunnel-continuation-relay-clippy-supervisors.log`). The package run includes health1, membership persistence4, readiness9, actual startup6 and recoveryCLI4; the four real-Redis workflow cases are explicitly ignored in that ordinary run and retain their separately recorded executed evidence.

C07 is verified at the handler cleanup scope: post-admission guards enclose all response/record/transport exits and map error/drop to the same exact identity-bound cleanup; ten real-H3 tests verify representative malformed, cancellation, timeout and shutdown exits plus sibling/budget invariants. This does not close every three-relay fault combination. I24 is verified at the lifecycle scope: seven regressions cover real listener drop/rebind, unexpected exit/panic, actor failure, cancellation and sibling joins; actor and maintenance tasks are retained, supervisor outcomes are typed, and shutdown continues cleanup after the first failure. Configured executable deployment remains C06.

Workspace formatting passes at this checkpoint (`/tmp/agent-tunnel-continuation-fmt-readiness.log`). Workspace Clippy has progressed into the harness but still finds fixture-only lint issues and pending revocation-helper refactoring (`/tmp/agent-tunnel-continuation-workspace-clippy-recovery.log`); no complete workspace pass is claimed.

At 2026-09-10T09:36:55+10:00, the copied/hash-recorded runtime snapshot at `work/runtime-snapshot-20260910-0930` in the continuation workspace completed a sequential isolated acceptance batch. Snapshot manifest records94 source files and three binary SHA-256 values; build log `/tmp/agent-tunnel-continuation-build-runtime-snapshot.log` passes. Logs use `/tmp/agent-tunnel-continuation-snapshot-<command>.log`:

- `verify`, `verify-m2-faults`, `verify-m7-transport`, `verify-m7-key-rotation`, `verify-m7-redis-partition` and `verify-m7-process-pause` exit0.
- `verify-m7-peer-readiness` fails after restored peer health with an unlocalized closed recovery echo; phase/owner diagnostics are being added before further changes.
- `verify-m7-production` rejects a restored-path503. Source confirms the recovery classifier omitted exact CLUSTER_UNREADY/not_dispatched; the repair admits that precise bounded case and adds redacted code/execution diagnostics, but needs a rebuilt pass. The existing log does not contain the body and cannot alone prove this was its cause.
- `verify-m7-pressure` fails with lost live owner during stream cleanup; I23 is reopened and new I27 tracks the changed readiness/proxy interaction. No generic owner-loss result is accepted as pressure cleanup evidence.

Three actual300-second rotations are still running from the same copied snapshot; no completion is claimed yet. The actual one-node configured process test compiles but fails initialization on the macOS temporary-path symlink (`/tmp/agent-tunnel-continuation-deployment-process.log`,65.06s); the fixture must canonicalize its owned private directory, preserving production state-path validation. The snapshot passes are local scoped evidence and do not close M7 or hosted/source-parity gates.

At 2026-09-10T09:38:57+10:00, expanded privileged RPC suite runs10 cases:8 pass and2 fail (`/tmp/agent-tunnel-continuation-privileged-extended.log`). The new signed key/lease/owner-change test and the previously passing shared customer/privileged ID test both fail a customer response with RemoteStatus400. The newly added typed direct-authority fallback rejection and exact late-terminal correlation cases pass, along with prior role/scope, body-bound, partial-unknown, admission-state and worker deadline/join cases. I11 is reopened until the customer regression is corrected and the full expanded suite reruns.

At 2026-09-10T09:51:37+10:00, the copied runtime snapshot default-interval M2 run is confirmed failed, replacing the earlier in-progress status. `/tmp/agent-tunnel-continuation-m2-default-core-snapshot.log` records owner_check_failed AUTHORITY_UNAVAILABLE at2026-09-09T23:34:47.764827Z, generation1, zero rotations, emitted28/received27 and closed control. Redis container inspection reports running since12:14:42Z with zero restarts. Namespace cleanup is prefix-scoped; no global cleanup is present in the fixture. No cause is claimed until authority failure paths and concurrent fixture effects are assessed. Current peer capacity repair separately passes6/6 (`/tmp/agent-tunnel-continuation-peer-probes-clean-release.log`), including completed held response, live customer reuse of the original connection, and recovery after permit release.

At 2026-09-10T09:58:11+10:00, current copied binaries from `work/runtime-snapshot-20260910-1000` pass four sequential three-relay gates (logs `/tmp/agent-tunnel-continuation-current-<command>.log`): peer-readiness14,607ms with all flags; production four rotations with all required flags; pressure33 attempts/peak3/12,912ms with exact cleanup, no replay and both canaries; owner-contention17,352ms with exact authoritative conflict counter, terminal loser, sibling, higher-epoch successor and stale-cleanup refusal. The snapshot manifest is an observation of source/binary hashes, not build attestation or release parity. Admission then fails because graceful node shutdown correctly removed the owner; fixture is being changed to an actual path outage preserving the selected owner.

The configured executable gate passes1/1 in3.89s (`/tmp/agent-tunnel-continuation-deployment-process-current.log`): real Redis via TLS, signed HTTPS checkpoint and membership, production initialize/serve, public livez/readyz and SIGINT/port release. Relaylib138/138 passes (`/tmp/agent-tunnel-continuation-relay-lib-counters.log`); formatting passes (`/tmp/agent-tunnel-continuation-fmt-current.log`). Whole-workspace strict Clippy reaches one admission large-enum lint; the boxed correction awaits rerun. Expanded privileged RPC improves to9/10, leaving key-overlap selection assertion; explicit signed predecessor removal is now implemented and awaiting runtime.

At 2026-09-10T10:02:59+10:00, filtered live Redis diagnostics show zero rejected connections, evictions, error replies and client buffer-limit disconnects. SLOWLOG contains37 retained entries, most recent22:51:20Z, all at most30,082microseconds; none coincides with the23:34:47Z M2 failure. These observations do not exclude client-side scheduling, lock wait, transport delay or errors outside server execution. The existing2-second catalog deadline includes connection mutex acquisition plus command/response. Maintenance currently collapses renewal and identity errors; typed operation/category/elapsed diagnostics are being added without changing failure policy. A separate loopback-only Redis container `agent-tunnel-m2-isolated-20260910` is prepared on port59949 for the next long regression; original M7 fixture remains on60278.

At 2026-09-10T10:11:15+10:00, interrupted pressure repetition and admission startup are traced to macOS crash reports: `tunnel-test-harness-2026-09-10-100330.ips` and `tunnel-client-2026-09-10-100314.ips` record SIGKILL Code Signature Invalid (Taskgated). Snapshot hashes remain unchanged and subsequent codesign verification plus CLI preflight pass for all three binaries. No pressure failure is inferred from the empty interrupted log; no signature mutation was made. A later actual admission retry still upgrades during selected-owner path loss; exact route/admission diagnosis remains open.

The typed maintenance diagnostics pass relay139/139 (`/tmp/agent-tunnel-continuation-relay-authority-diagnostics-fixed.log`). Rebuilt, signature-checked copied binaries start isolated default M2 at2026-09-10T10:10:00+10:00 against port59949, log `/tmp/agent-tunnel-continuation-m2-default-isolated-diagnostics.log`; no completion yet. Separate lifecycle source review finds detached per-operation catalog futures beyond the previously verified outer supervisors; I24 is reopened while preserving the earlier narrow evidence.

At 2026-09-10T10:17:01+10:00, expanded privileged RPC passes10/10 (`/tmp/agent-tunnel-continuation-privileged-final-application-id.log`). The remaining400 was classified before authority validation because the successor envelope used assignment-1 instead of the shared application ID required by this fixture. Corrected IDs preserve all scope/lease/owner checks. Signed key-ID removal with shared SPKI is metadata/binding evidence; separate real certificate/pin gates are required for cryptographic rotation.

The attempted full workspace checkpoint is incomplete: strict Clippy found one obsolete admission local (removed), tests failed during linking with errno28 disk full, and formatting reached an in-progress recovery fixture. This was not a test assertion result. Cargo package-clean removed obsolete workspace-generated artifacts from the unused repository target, preserving the active shared /tmp target and source; it reported3.7GiB of generated files removed, leaving2.8GiB free. No unrelated user caches or data were removed.

At 2026-09-10T10:24:20+10:00, read-only row audit confirms complete current production evidence for FP-09/EC-001/IN-07/OG-04 (same authenticated route identity across tenants and retained same-owner rotation stream), now8/98 matrix rows verified. It explicitly leaves generic duplicate CLI diagnostics, full bootstrap, delay/revalidation/ticket races and artifact parity open. Actual live membership test binary also passes1/1 (`/tmp/agent-tunnel-continuation-live-membership-current-binary.log`), with signed certificate removal/rotation closing old H3 while preserving the new sibling.

At 2026-09-10T10:26:55+10:00, isolated M2 default completes exit0 in905.6s using signature-checked10:10 copied binaries and independent Redis59949. `/tmp/agent-tunnel-continuation-m2-default-isolated-diagnostics.log` has only a proxy Broken pipe during teardown; the command validates all three actual300-second rotations. Native/tmp pressure repetition separately reproduces owner loss in4.68s (`/tmp/agent-tunnel-continuation-pressure-native-stability-1.log`): stream_cleanup, relay-a, dispatches21, sessions0, bothpeer routesreachable andcapacityready16. This is a real gate failure distinct from macOS signature interruption; I23 is reopened and I27 remains active.

## Client diagnostic and integration checkpoint (2026-09-10T10:37:54+10:00)

The fixed exact policy-1008 `OWNER_BUSY` classifier passes all55 client tests and strict client all-targets Clippy. Logs: `/tmp/agent-tunnel-continuation-owner-busy-fixed-tests.log` and `...-clippy.log`. The first integrated workspace attempt fails to compile because the new actor initializer references a missing `background_failure` field; no workspace test result is claimed. The lifecycle owner is correcting this plus cleanup-worker join-result handling before a fresh run. New selected-owner admission, rollback TLS and pressure terminal diagnostics remain unverified.

## Current native owner contention and pressure (2026-09-10T10:45:33+10:00)

The native1044 snapshot builds successfully and every copied executable passes codesign/help preflight. `verify-m7-owner-contention` exits0 with all flags, fixture17,487ms (outer21.12s). The exact fixed OWNER_BUSY diagnostic, not a generic transport closure, is required by the parser. This closes I28 and the exact-scope conflict rows FP-08/EC-004/IN-08.

The same snapshot pressure command fails after2.50s before rotation. Actor closure is CONTROL_CLOSED; client exits1 with SESSION_CLOSED/retryabletrue, dispatches21, no live session and both peer routes ready with capacity16. The CLI currently discards the joined runtime error, so a typed diagnostic correction is pending. Admission runs20.22s then fails with production echo closed before response while the targeted UDP fault spans scheduled rotations; phase/route isolation investigation remains open. Logs are `/tmp/agent-tunnel-continuation-native-1044-verify-m7-{owner-contention,pressure,admission}.log`.

## Relay, recovery and complete synthetic RPC checkpoint (2026-09-10T10:53:07+10:00)

Current relay strict all-targets Clippy and167 non-ignored package tests (143 library) pass; `/tmp/agent-tunnel-continuation-1048-relay-{clippy,tests}.log`. Explicit new namespace backup rollback passes1/1 in1.01s and all four shared-TLS recovery workflows pass in12.53s, logs `...-1048-recovery-{backup,workflow}.log`. The rollback fixture restores the older active snapshot, refuses mismatched approval, restores reconciled revocation and activates only with a fresh exact approval. Configured serve plus a fresh device handshake remains open.

Current10/10 synthetic RPC tests pass with forged tenant/device cases included; actual unsupported database config test1/1 passes and no SQLite/SQLx is present in workspace/relay/harness manifests or lockfile. Logs `/tmp/agent-tunnel-continuation-1052-{rpc,forbidden-config}.log`. This closes EC-062/063/064, IN-13, OG-06 at their explicitly synthetic analogue scope, bringing the matrix to16/98. The source inventory section8 requires coexistence and lease revalidation; same-SPKI signed key-ID metadata coverage is distinguished from cryptographic certificate rotation.

Client57 tests pass after preserving the joined runtime error. Native1050 pressure still fails2.45s, now with RESOURCE_EXHAUSTED/retryablefalse,22dispatches, actor CONTROL_CLOSED and healthy peers. Source tracing identifies the bounded128-frame carrier queue as a candidate: roughly six commands per64KiB echo can saturate it at21 records. A bounded backpressure fix and regression are in progress; no queue limit was raised and no pressure assertion was weakened.

## Resumed agents and expanded lifecycle proof (2026-09-10T11:49:40+10:00)

The user requested continuation and retriggering needed agents. Four agents had stopped on usage-limit errors; live account tool now reports0percent consumed, and all four were retriggered. Artifact, admission and review followups were also triggered as needed. Both disposable Redis fixtures return PONG. No usage reset was consumed.

All146 relay library tests and strict relay all-targets Clippy pass, logs `/tmp/agent-tunnel-continuation-1148-relay-{lifecycle,clippy}.log`. Newly held registration/renewal and background panic cases verify the previously reopened I24 scope. No full workspace, client backpressure or configured process chaos claim follows from this package pass.

The artifact observer now completes required metadata and codesign/help/version checks without the earlier awk error; log `/tmp/agent-tunnel-continuation-artifact-observation-1140.log`. Existing-binary provenance remains explicitly unverified. Prior bundled owner-contention test passed17,307ms. The separate source-copy build still has not run.

Configured-process fixture compilation now reaches missing imports after common-helper extraction; `/tmp/agent-tunnel-continuation-1152-process.log`. No fault-case runtime assertions ran. New recovery-process fixture is source-ready. Client backpressure review identified same-stream deferred DATA could be overtaken by later DATA/FIN and full StreamState cloning can exceed intended copy accounting; both are under correction before acceptance.

## Resumed validation at 2026-09-10T11:59:11+10:00

The user requested continuation and restart of every needed agent. Relevant stopped agents were retriggered; completed agents were reused for concrete follow-up repairs and independent review. No usage reset was consumed.

Current client regression suite passes59 tests (43 library,11 CLI,5 doctor integration) after replacing immediate carrier-full failure with bounded deferred output, coalescing carrier ACK/window control, preserving same-stream retained DATA/DATA/FIN order, and reserving MPSC/byte capacity before sequence mutation. Log: `/tmp/agent-tunnel-continuation-client-backpressure.log`. Strict client and real pressure acceptance remain pending; this does not close I23/I27.

The new configured recovery fixture now compiles. Its first runtime fails before serving because its namespace does not match the fixture-only seed guard; the test is not accepted. Log: `/tmp/agent-tunnel-continuation-recovery-process.log`. Independent process-fixture review found an incorrect Redis directory key prefix, swallowed bootstrap reason, overly broad diagnostics, and incomplete error-path cleanup. Those are assigned fixes; new process gates have no passing claim. Matrix remains16/98.

### Current Redis gates and independent control-path review

All26 explicitly ignored Redis tests pass against isolated fixture namespaces: redis_catalog5, redis_cluster9, redis_recovery10, redis_recovery_races2. Logs: `/tmp/agent-tunnel-continuation-current-redis_{catalog,cluster,recovery,recovery_races}.log`. This is current catalog/recovery component evidence; configured server recovery and full cluster gates remain separate.

Independent source review after the initial client59 pass found a pre-existing ACK feedback loop on both relay/client, deferred control debt lost when the old active carrier becomes retiring, slot-only rather than byte-and-slot control reservation, Pong/Barrier bypasses, and deferred STREAM_FORGET accounting gaps. Relay/client fixes and meaningful callsite regressions are in progress. The earlier59-test pass therefore cannot close the current pressure/rotation requirement.

### Relay and client control regression checkpoint

Current relay package174 tests pass (148lib,2binary,24integration), and strict all-targets relay Clippy passes. The actual actor callsite regression proves no outgoing ACK for incoming ACK/WINDOW_UPDATE while first and duplicate DATA are re-ACKed. Typed bootstrap reasons and joined-shutdown categories also pass. Logs: `/tmp/agent-tunnel-continuation-relay-control-{tests,clippy,bin}.log`. Native relay copy `/tmp/agent-tunnel-relay-native-20260910-121024/tunnel-relay` passes exact-byte hash, codesign and help preflight; SHA25685d1c021f3e13ca598ec6f13ef2e3e7b7ddbef4825ccf7aa421c7aff7bbb616a. This is a binary observation, not source-copy attestation.

Current client61 tests (45lib,11CLI,5doctor) and strict all-targets Clippy pass after ACK/deferred-control changes. Logs `/tmp/agent-tunnel-continuation-client-controls-{tests,clippy}.log`. Independent review remains open for physical delivery before retiring-carrier closure, Ping control starvation, minimum-budget actual data flow and directional forget timing. No pressure/rotation completion is claimed from these tests. The combined four configured-process targets encountered a fixture compile mismatch (shutdown returns ExitStatus, not unit); correction assigned before runtime.

### Configured process results at 2026-09-10T12:15:08+10:00

The extracted configured baseline passes1/1 in6.06s with the native121024 relay. Both new live dependency-loss tests pass2/2 in14.54s: actual Redis TLS proxy loss and actual HTTPS checkpoint authority loss withdraw readiness to exact503/unready while liveness remains200/live; SIGINT joins and releases the process listeners. The shared helpers preserve activity expectations and cleanup checks. These are process/health slices of C06/I04; public routed-body/fallback and all98 rows remain broader gates. Log: `/tmp/agent-tunnel-continuation-configured-process-gates.log`. The reusable M7 script now includes the two ignored runtime-dependency tests.

The nine-case bootstrap matrix reached its last local certificate/key mismatch case; the relay correctly emitted bounded rustls KeyMismatch, but the fixture demanded an unrelated word. Exact-cause predicate corrected, full rerun pending. Recovery reached real public HTTP canary; current observed body is exact canary plus payload. The fixture had confused internal transport framing with the public body; source corrected with phase labels and joined HTTP connection cleanup. No recovery-process pass claimed.

The complete nine-case bootstrap matrix now passes1/1 in26.62s against the native121024 relay after correcting the exact KeyMismatch predicate. Log `/tmp/agent-tunnel-continuation-configured-process-retry.log`. All9 cases preserve typed diagnostics, no-ready behavior and joined cleanup. The reusable gate script includes this ignored target. Recovery now passes initial authenticated HTTP echo but fails the actual operator `recovery-observe` catalog operation; no recovery-process closure is claimed. Client dependency compilation included an in-progress unused PendingStreamForget warning, not a strict-client pass; client repair continues separately.


## Current workspace and routed acceptance (2026-09-10T12:53:30+10:00)

The current workspace passes formatting, strict all-target locked offline Clippy, all484 normal tests (37ignored), and all binary builds. Logs: `/tmp/agent-tunnel-continuation-workspace-1248-{fmt,clippy,tests,bins}.log`. The normal run does not execute the37ignored tests. Separately, the earlier current catalog run executed all26 Redis tests successfully; backup rollback1/1, recovery workflow4/4, configured baseline1/1, bootstrap9cases, runtime dependency-loss2/2 and configured recovery1/1 also passed at their declared scopes.

Native binaries copied into `/tmp/agent-tunnel-native-20260910-1250` match the built bytes, pass codesign verification and help preflight, and have a SHA256 observation receipt. This is binary observation, not a clean source-build or release provenance claim.

Three fresh routed commands remain failing and block their gates:

- Pressure:6.93s, the bulk stream became terminal before intentional cancellation; the actual CLI remained running with no recorded CLI error. This differs from the earlier session-wide RESOURCE_EXHAUSTED failure and requires exact stream cause evidence.
- Admission:26.70s, selected-ingress-to-owner peer fault was followed by failure of the sibling canary; its supposed isolation has not been proved.
- Lifecycle:15.91s, the exact consumer response path was paused/closed and16records sent, but no queue pressure was observed. Pausing alone is not physical-write deadline or queue saturation proof.

Logs: `/tmp/agent-tunnel-continuation-native-1250-verify-m7-{pressure,admission,lifecycle}.log`. No row is promoted from these failures.

Independent source review also found a closed-retiring-writer flush can abort before healthy candidate absolute-credit reissue, and pending STREAM_FORGET barriers can be overtaken by new controls or an installed rotation candidate. Those callsite races remain M7-C22 work; the passing64client tests do not prove these newly identified cases.


## Configured recovery and port binding completion (2026-09-10T13:07:57+10:00)

The selected process targets pass3/3 against the native1250 relay and isolated Redis59949. Port collision and signed address update pass2/2 in8.27s; configured recovery passes1/1 in63.07s after a measured61s post-fence wait. The candidate membership is signed and published only after quiescence, with a fresh checkpoint. Old-incarnation serve is refused, a fresh authorized device returns its canary, and prior revocation remains enforced. Actual backup/rollback and recovery workflow evidence completes M7-I09. The CLI's fencing flags are operator declarations; the test establishes elapsed time and joined old processes, not automatic external-writer discovery.

The port test requires AddrInUse while the exact approved UDP address remains held, then verifies signed membership v2 with the actually selected approved endpoint, exact ready/liveness and joined cleanup. It completes EC-018 at its deployment-startup scope. Log: `/tmp/agent-tunnel-continuation-1309-configured-fixtures.log`.


## Native cluster and catalog completion checkpoint (2026-09-10T13:23:37+10:00)

Native1312 passes production (4rotations,2tenants,3ingresses,allmandatoryflags) and deterministic public admission (allnegative/lookup/selectedowner dispatch deltas0,siblingdelta1). Same binary snapshot also passes transport8.03s,RedisTLS0.12s,cluster1.65s,peerreadiness17.89s,ownercontention22.16s,keyrotation6.23s,Redispartition13.40s andprocesspause14.75s. These elapsed figures are outer command time; individual evidence records carry their narrower scenario time. All logs use `/tmp/agent-tunnel-continuation-native-1312-verify-m7-<command>.log`. The cluster command is silent on success and returned0.

Pressure still fails9.01s: first bulk operation leads to a terminal stream while CLI remains running,peer readiness2/2 and queue/replay0. Lifecycle still fails7.75s with peerclose after64records; client send-buffer control has since been added to reach the intended blocked-write boundary. Neither is counted as a pass. New post-QUIESCE forget/closed-writer continuity fixes remain C22 and require finalnative/M2 reruns.

EC-002 now closes from25catalogtests,strictClippy and actual generatedUnicode/key-isolation1/1. EC-014 now closes from2/2 realRedis concurrentauthority/lostreply tests with an8connection boundedproxy,250ms postfailure replayobservation,exactselectedcommandcount1 and independentdurableepoch/generation+1. Logs `/tmp/agent-tunnel-continuation-ec014-complete-{clippy,tests}.log`. Matrix20/98; wholeM7 remainsinprogress.


## Fresh native regression checkpoint (2026-09-10T13:46:32+10:00)

Formatting, strict workspace all-target Clippy, 490 normal tests (42 ignored) and all binaries pass. Logs: `/tmp/agent-tunnel-continuation-workspace-1345-{fmt,clippy,tests,bins}.log`. Current client count is 68. Native1345 binaries match the build bytes and pass strict codesign/help; the observation receipt does not prove source provenance.

Actual M1 passes20.52s. High-epoch owner contention passes21.25s (scenario17450ms), with original9007199254740993, successor9007199254740994, generation unchanged by guarded fixture seed, single atomic winner, exact terminal loser, no reconnect loop, stale cleanup refusal and both canaries. EC-022/IN-04 complete. Independent scope audit closes EC-010 from the configured startup/port matrix; process capacity remains FP-10. Matrix33/98; M7 tasks37/51.

Pressure fails7.29s with a terminal stream at receive/delivery cursor4 while client is running, readiness is healthy and queues/replay are zero. Lifecycle fails9.50s with peer closure after34 records despite the small send buffer. M2 accelerated and fault commands fail1.15s/2.57s at maximum framing record1, before rotations, with the same terminal sequence boundary. This is a current shared core regression candidate; exact cause is under investigation. The initial peer lifetime-budget hypothesis was withdrawn because per-send reservations are released after each completed write. No generic timeout or terminal state is accepted as pressure proof.

Logs use `/tmp/agent-tunnel-continuation-native-1345-<command>.log`. The long default rotation run is deferred until the short M2 gates pass. The production key-revocation fixture has also been tightened in source to establish a successful upgraded consumer stream before pin withdrawal; its new post-upgrade scope awaits runtime.

## Native credit1 record-credit regression checkpoint (2026-09-10T14:31:07+10:00)

The immutable binaries in `/tmp/agent-tunnel-native-20260910-credit1` pass
accelerated M2 (14.82s), M2 faults (16.02s), production pressure (15.41s),
and production routing with actual post-upgrade peer-pin revocation (20.26s).
The separate `verify-m2-default` process, session12491, completed with exit0
after three actual 300-second rotations; no newly measured total duration is claimed.
Its log is `/tmp/agent-tunnel-continuation-native-credit1-verify-m2-default.log`;
other command logs use the same prefix. M1/current high-epoch ownership passed
on the earlier native1345 snapshot. The binary observation JSON contains exact
SHA-256 values and strict signature/help checks; source parity remains unverified.

The real failure was partial relay emission of a maximum record when remaining
absolute credit covered only its first chunk. Whole-record credit preflight,
bounded pending FIFO, and active-carrier credit retry repair this path. The
focused three-record regression passes and checks all delayed records, sequence
order, empty pending bytes and nonterminal state. Its log is
`/tmp/agent-tunnel-continuation-credit-record-regression-fixed.log`.

The new public HTTPS identity probe still failed on this snapshot because remote
unary forwarding omitted the internal length prefix (M7-C24). The current source
now repairs request/response framing and adds exact empty/maximum/repeated public
body probes. Typed stalled-consumer response diagnostics are also integrated.
Those later source changes require their own strict and native checks; no
blanket current-worktree pass is inferred from credit1. The 98-row scope audit
closed no additional rows from these narrower transport results alone.

## Integrated1 scoped validation (2026-09-10T14:41:06+10:00)

Formatting, strict workspace all-target Clippy,497 normal tests with44ignored,
and workspace binaries pass. Logs `/tmp/agent-tunnel-continuation-integrated-1435-<gate>.log`.
The native snapshot `/tmp/agent-tunnel-native-20260910-integrated1` has an exact
binary observation JSON, strict signature/help passes, and runtime-results.json.
Real admission passes25.28s; M1 passes21.63s; pressure passes18.45s; production
passes21.85s; accelerated M2 passes15.14s; M2 faults pass14.47s. These close C24,
I13 and the exact I23 cleanup scope. The actual300-second integrated1 regression
is running separately; prior credit1 default run passed.

Lifecycle fails79.94s after owner session loss at23 dispatches with no matched
physical response-write timeout. This remains an unverified gate. Configured
Redis-stage fixture fails11.88s because post-TLS faults do not reach its expected
explicit PING/primary-identity stages; driver initialization traffic is under
review. Configured checkpoint refresh fails5.38s at initial child startup, and
its diagnostic is being improved before cause attribution. Failure logs use
`/tmp/agent-tunnel-continuation-integrated1-process-<test>.log`.

A read-only Git diff check encountered a compressed/dataless Git pack and
reported it too short; no pack modification or repository repair was made.
Cargo.lock remained materialized and locked builds passed. Source-copy artifact
parity remains a distinct final gate.

At 2026-09-10T15:21:54+10:00, integrated3 fixture reruns report:

- Peer fragmentation passes in 0.12 seconds, with seven malformed cases rejected and zero malformed dispatch. Current 20 peer-frame component tests also pass. This closes EC-034 only.
- Pending owner fails its control-only snapshot precondition. Source now removes logical socket-count predicates that did not describe physical carrier presence; the paused handshake remains the causal barrier. Rerun pending.
- Side effect fails at post-consumer-interruption owner sampling because the synthetic device exited normally before the assertion. Source now services its established session until explicit fixture cancellation. Rerun pending.
- Lifecycle fails after 75.28 seconds: 93 producer records sent, 23 dispatches, then owner session lost and CLI retained recovery, with no typed response-write timeout. The proxy now optionally sets its target-side receive buffer before connect; only this fixture requests 8 KiB. A typed physical timeout remains required.
- The refreshed checkpoint diagnostic still fails startup: the process rejects membership while the local verifier accepts the first signed response. The divergent policy or sequence remains under investigation. Log /tmp/agent-tunnel-continuation-integrated3-checkpoint-diagnostic.log.

The integrated2 configured Redis stage test passed all four injected boundaries in 13.21 seconds. Its parser handles driver initialization before PING and primary identity; this does not claim DNS fault coverage or all of EC-013. C26 and C27 are staged for review; no production patch or complete current workspace pass is claimed.

At 2026-09-10T15:43:17+10:00, configured checkpoint refresh passes1/1 in8.93s. The ordered diagnostic corrected the earlier interpretation: initial fresh refresh and intentional equal-version rejection had passed; fresh recovery then failed because persisted membership version1 cannot accept equal record1. The fixture now signs/publishes record2 and checkpoint minimum2 before fresh checkpoint3/restart. Exact readiness, negative restarts, version/nonce/byte advancement and cleanup pass. M7-I03 closes at local configured-process scope.

Integrated5 lifecycle still fails39.34s under300s policy: last target phase active, dispatch23, no typed physical write timeout, CLI PROTOCOL_ERROR (nonretryable). Thus accelerated rotation is not the full cause; further protocol-cause diagnostics are required. The latest pending-owner failure remains exact post-ready canary; its backend lifetime is now retained until HTTP/owner observation, awaiting rerun.

Root applied a minimal C26 candidate that reports failed health probes without force-closing shared customer connections. Original real H3 customer-survival regression and all7 existing probe tests pass. Actual native peer-readiness recovery and broader regressions remain pending. The larger retirement implementation stays in work/m7-c26-edit for comparison; it is not live.

At 2026-09-10T15:48:53+10:00, integrated6 strict workspace Clippy and bins pass. Snapshot observed2026-09-10T15:46:48+10:00: client25d502b54f665e82551475ae8e71bc415ac896619557b3c62f21288090d55c7a, relay06bb628f64a52796c278079cdb705bc63236a87c2d3b11a6cfe373e3f959e118, harness822a5fd60d7bd98efeabe049bba541dccd10de8afac5ce580f8a24ea4eb87079. Source provenance unverified.

- Side-effect PASS12.27s: terminal=close observed9994ms within20000ms; exactly one raw request and one effect, no duplicates/post-failure effects, owner retained. This closes EC-054 at its synthetic three-relay forwarding scope.
- Peer-readiness FAIL18.86s: restored health/capacity/membership snapshots all ready, fresh consumer echo still closes. The same failure predates the minimal C26 candidate, so its cause remains open.
- Pending-owner FAIL2.48s: selected DATA has matching epoch/generation/stream but fixture has not yet consumed authorization confirmation on the separate control socket. Bounded pending-data handling is needed; authorization itself must remain strict.
- Lifecycle and concurrent-load results are still pending in native session11877. Full normal workspace suite is running in session36136 after successful fmt.

### Successive recovery and admission review — 2026-09-10T16:09:37+10:00

The focused `cargo test -p tunnel-client --locked --offline successive_recovery_does_not_reuse_completed_episode_closures -- --nocapture` reproduced stale closure evidence after actual recovery activation (0passed/1failed). Log: `/tmp/agent-tunnel-continuation-successive-recovery-red.log`. The regression retains the completed attestation and then drives a second recovery episode. C28 tracks the narrow mutable-map reset and subsequent runtime verification.

Integrated8 strict harness Clippy and binary build passed; its real peer-readiness run passed16.63s, following integrated7's16.67s pass and integrated6's18.86s failure. This is evidence of an intermittent recovery result, not proof that the earlier failure has been resolved. Logs: `/tmp/agent-tunnel-continuation-integrated8-{harness-clippy,bins}.log` and `/tmp/agent-tunnel-continuation-native-integrated8-verify-m7-peer-readiness.log`.

The independent M2 control-burst regression is red (one pass, one failure): `/tmp/agent-tunnel-continuation-m2-control-burst-regression.log`. It exercises actual OPEN handling beyond the bounded control response channel while preserving an established sibling. A transactional admission repair is staged separately. C27's pre-upgrade capacity mapping remains staged while review checks retained terminal-state bounds and dropped-admission lease cleanup.

### Recovery patch runtime — 2026-09-10T16:15:03+10:00

The corrected valid-protocol successive-recovery regression passes1/1; the remaining client regressions pass70 tests with the known C22 control-burst test explicitly excluded. Logs `/tmp/agent-tunnel-continuation-successive-recovery-green2.log` and `/tmp/agent-tunnel-continuation-recovery-client-regressions.log`. An initial green attempt exposed test-only attempt_no=0, corrected to1; no production policy was relaxed.

Integrated9 binaries were observed16:12:51 (source provenance remains false): client5c6c0f2b846475aa28d6fceb91cc8088d643174afa78547997b45a968fdba6b8, relay06bb628f64a52796c278079cdb705bc63236a87c2d3b11a6cfe373e3f959e118, harness88369450ddbbfcbee5127c2e2b1f24dd4064b472549c517d1d8dc9c87e6eb502. Real M2 faults pass13.24s; peer-readiness passes20.34s. Lifecycle fails97.98s after the response stall: target phase recovering, dispatch23, pump94, then session lost; CLI reports TRANSPORT_ERROR/retryable/retained_recovery, with no stale-closure protocol rejection and no typed physical-write timeout. This verifies the changed failure classification but leaves the original data-loss and physical writer timeout gate unresolved. Logs `/tmp/agent-tunnel-continuation-native-integrated9-<command>.log`. All batch children ended; no active root runtime remains.
