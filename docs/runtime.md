# Axum runtime, device mTLS, and CLI

Status: runtime implementation design, 2026-09-09. M1 implements the client `config check`, `credentials create`, `credentials import` and foreground `connect` commands; the relay implements `serve` with Axum HTTPS, both device mTLS WebSockets and Redis/JWT authority. Legacy `check-config` remains supported. See [M1 evidence](m1-harness.md). Status/doctor IPC, enrollment and generic adapters below remain planned. M2 rotation and M7 cluster work have separate current evidence in their verification documents. The local-only doctor slice is implemented and locally verified as described below.

The M1 relay uses one bounded actor for its finite echo sessions; the target per-device actor architecture below will isolate richer M2/M7 state. M1 owner fields expire logically within durable Redis device hashes; physical TTL lease namespaces are a later cluster change. Normal startup cannot initialize missing authority metadata. Recovery requires an operator to reconcile durable authorization history; changing the owner incarnation does not verify an arbitrary restored backup.

This document fixes the runtime boundaries. [protocol.md](protocol.md) defines socket pairing and rotation; [cluster.md](cluster.md) defines peer trust, routing, ownership, and Redis failure behavior; [acp.md](acp.md) defines remotely controlled agent exports.

## Three listener roles

| Role | Transport and implementation | Authentication | Exposure |
| --- | --- | --- | --- |
| Consumer API | HTTPS HTTP/1.1 and HTTP/2, Axum; consumer filesystem WSS initially uses HTTP/1.1 upgrade | Scoped OAuth access token; authorized user/consumer principal | Public API hostname, e.g. `api.example.test:443` |
| Device tunnel | WSS over HTTP/1.1 and TLS 1.3, Axum behind an in-process rustls acceptor | Mandatory device client certificate on **control and every data connection** | Separate device hostname/listener, e.g. `devices.example.test:443` |
| Cluster peer API | HTTP/3 over QUIC/UDP and TLS 1.3; dedicated `quinn` + `h3` + `h3-quinn` adapter | Mandatory relay certificate plus approved peer identity/key record | Private node addresses, e.g. UDP `8443`; reachable between relay nodes only |

Ports above are examples, configurable independently. Separate sockets/listener configurations are the initial deployment profile; sharing a port through SNI is a later deployment capability requiring its own tests. The public consumer listener never exposes private peer routes. Consumer OAuth tokens cannot authenticate a device or a relay peer.

Axum is the web framework for public HTTP and device WebSockets. Its documented `serve` path supports HTTP/1 and HTTP/2; HTTP/3 needs a distinct integration, not a configuration flag on `axum::serve`. Implement a small peer HTTP/3 transport adapter calling shared typed application services. Do not require public Axum routes, WebSocket extractors, or Tower body assumptions to work unchanged over HTTP/3. Sources: [Axum serve](https://docs.rs/axum/latest/axum/fn.serve.html), [Axum WebSockets](https://docs.rs/axum/latest/axum/extract/ws/), [h3](https://docs.rs/h3/latest/h3/), [h3-quinn](https://docs.rs/h3-quinn/latest/h3_quinn/).

The two steady-state WebSockets belong to each CLI device connection. Peer QUIC connections and consumer connections are separate. Private HTTP/3 forwarding does not add a third steady-state device socket. During data rotation, one control plus old and candidate data sockets remain bounded by the existing overlap deadline.

## Rust stack and dependency gate

Use Tokio for async execution, Axum for the two TCP listener roles, rustls/tokio-rustls for explicit TLS handling, tokio-tungstenite for the CLI WSS client, and tracing for structured events. Use hyper/hyper-util where connection setup needs more control than `axum::serve` provides. The device acceptor must preserve authenticated TLS metadata through HTTP upgrade and into the connection actor.

Research snapshot, not selected dependency pins:

| Package documentation observed | Version | Purpose / gate |
| --- | --- | --- |
| Axum | 0.8.9 | HTTP routing, upgrade handling, per-connection identity injection |
| rustls | 0.23.44 | Mandatory client verification, client certificate configuration, revocation integration |
| tokio-tungstenite | 0.30.0 | Outbound WSS with supplied rustls configuration |
| quinn | 0.11.11 | UDP/QUIC transport and verified peer certificate extraction |
| h3 / h3-quinn | 0.0.8 / 0.0.10 | Explicit private HTTP/3 server/client bridge |

These versions were observed independently; this is **not a proven compatible combination**. Before adding dependencies, compile a minimal bidirectional TLS/WSS and HTTP/3 spike with pinned versions and feature sets under Rust 1.95.0 on supported platforms. Record the selected crypto provider, license/MSRV results, Cargo.lock, and enabled TLS features. Reject duplicated incompatible rustls types at the adapter boundary instead of hiding them behind unsafe conversions. Sources: [rustls verifier](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html), [custom WSS connector](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/fn.connect_async_tls_with_config.html), [Quinn peer identity](https://docs.rs/quinn/latest/quinn/struct.Connection.html#method.peer_identity).

## Device authentication contract

1. The CLI verifies the relay certificate chain and expected DNS name against its configured server trust bundle. Development uses a dedicated fixture CA. There is no `--insecure`, anonymous TLS fallback, certificate auto-accept, or plaintext production endpoint.
2. The device TLS acceptor requires a client certificate and verifies the chain, validity, intended client usage, and proof of possession before accepting HTTP requests. Configure the rustls verifier to require authentication; never use `allow_unauthenticated` on this listener.
3. Parse the approved certificate identity and map its public-key fingerprint/credential ID to an active durable device credential record. That record supplies the tenant and device ID. A valid certificate from the device issuer alone is insufficient if its credential is unknown, disabled, or not assigned to that device.
4. The acceptor constructs an internal `VerifiedTlsIdentity { role, principal_id, credential_id, public_key_fingerprint, certificate_expires_at }`. Authentication middleware resolves current device state and inserts an `AuthenticatedDevice` extension. These types have constructors restricted to the verification boundary.
5. Control upgrade authorizes the device, acquires ownership as specified in [cluster.md](cluster.md), and binds the connection epoch to the credential ID. Data upgrade repeats mTLS authentication and verifies the one-use pairing ticket against the same device, credential, session, epoch, and generation.
6. A ticket is supplemental attachment authority, never a replacement for mTLS. A stolen ticket and a different valid device certificate cannot attach. A caller-supplied device/tenant name cannot override the certificate mapping.
7. Every new stream also requires consumer grants and device-local export policy. mTLS proves the device identity; it does not grant the caller filesystem, MCP, CUA, or ACP permissions.

`X-Client-Cert`, `X-Device-ID`, forwarded certificate headers, URL parameters, and peer IP addresses never create `VerifiedTlsIdentity`. Strip or ignore them at the edge. If a different relay accepts a data socket, verified identity is conveyed only through the authenticated, typed peer envelope defined in the cluster contract; the owner checks the device/credential and attachment binding again.

Use separate trust purposes for public server authentication, device client credentials, and cluster peer credentials. Prefer separate issuers or constrained intermediates; any shared root requires tested role restrictions and registry checks. A device certificate must fail cluster admission, and a relay certificate must fail device admission. The CLI needs no Redis access and does not accept Redis membership as device enrollment authority.

Disable TLS resumption and early data on the initial device mTLS profile, so every socket establishes fresh certificate evidence. Disable QUIC 0-RTT on peers. Resumption can be added only with revocation-aware identity restoration and replay tests. No mutation or ticket consumption may occur from early data.

## Provisioning, renewal, and revocation

Initial network development uses externally provisioned credentials. An administrator configures trusted issuers and creates the tenant/device credential binding; the CLI creates its private key locally and exports a CSR. An approved issuer signs the CSR; the CLI imports only a matching certificate chain and its server trust bundle. Certificate import verifies that the issued public key matches the pending local key. It never changes server trust based on an unauthenticated network response.

The first production enrollment flow is a separate implementation gate:

1. An authenticated tenant administrator creates a short-lived, one-use enrollment authorization for one device. The authorization binds the tenant, requested device record, audience, expiry, and enrollment purpose.
2. The CLI contacts a narrow enrollment route on the **server-authenticated consumer HTTPS listener** using an independently supplied CA bundle or platform-trusted public server certificate. An unenrolled device cannot yet authenticate with a client certificate; this route cannot open control/data sockets or invoke services.
3. `enroll` reads the authorization from protected stdin or a secret-store reference, creates its private key locally, and submits a bounded CSR. Never pass codes in process arguments, URLs, logs, or copied command examples.
4. The enrollment service verifies authorization, CSR possession, and allowed certificate fields; it supplies authoritative identity/tenant bindings and atomically consumes the authorization with credential creation. The device cannot choose another tenant or certificate role in its CSR.
5. Return the public certificate chain and enrollment receipt; validate the chain/key/identity, persist credentials atomically, and connect using mTLS. Retried enrollment resolves through a bounded receipt/idempotency mechanism, not an unscoped reusable enrollment code.

Keep the issuing private key in an external CA/signing service or a narrowly isolated issuer component; it is not a relay configuration value or Redis entry. Initial externally provisioned credentials avoid implementing a CA in the transport milestone. Automated enrollment requires a selected issuer, issuance profile, issuance audit, and recovery tests before it is advertised.

The initial credential store may use owner-only files with atomic replacement and tested permissions: private directory/file modes on Unix, explicit owner ACLs on Windows. OS keychain/non-exportable key integration is a separate supported-backend gate. Configuration stores credential references, certificate paths, and trust-bundle paths, not PEM private-key text. Never silently downgrade from an unavailable selected secure store. Diagnostic output may show key fingerprints and certificate expiry, never private-key bytes.

Renewal uses the existing authenticated device plus current authorization and a new local CSR/key. Publish the new credential as an explicit overlap with an absolute deadline, then drain current work and close the old socket pair before connecting a fresh control/data epoch with the new credential. This deliberate reconnect may end sessions; expose pending mutations as `outcome_unknown` where required. Do not mix two credential IDs in one epoch or preserve an old certificate indefinitely to keep a stream open.

Data-socket rotation every 300 seconds and certificate renewal are independent. The connection actor enforces certificate expiry even on an already-open control socket. Revocation closes affected control/data sockets and stops new dispatch independently of socket rotation; already-dispatched side effects retain their actual or unknown outcome. Bound revocation propagation and behavior on stale authorization state through the cluster/policy contract. Short-lived certificates reduce exposure but do not replace revocation checks.

## Proposed CLI surface

Keep the existing binary name `tunnel-client`. `tunnel-client check-config [PATH]` and help are implemented today; current errors exit 1. The following is the future command contract, not runnable examples of delivered features.

| Command | Defined behavior |
| --- | --- |
| `tunnel-client config check --config PATH` | Parse and validate local configuration without network calls or service startup; retain `check-config [PATH]` as an alias |
| `tunnel-client credentials create --config PATH --csr-out PATH` | Generate a pending local key, write a public CSR without overwriting an existing credential |
| `tunnel-client credentials import --config PATH --certificate PATH --server-ca PATH` | Validate/import the certificate for the pending key and trusted server bundle from explicit local inputs |
| `tunnel-client enroll --server HTTPS_URL --code-stdin --server-ca PATH --config PATH` | Perform the gated enrollment flow above; omit `--server-ca` only for platform-trusted public PKI |
| `tunnel-client connect --config PATH` | Foreground supervisor; establish the mTLS socket pair, register fixed exports, reconnect with bounded jitter until graceful shutdown |
| `tunnel-client status --config PATH --json` | Read the local supervisor's redacted status through authenticated local IPC; does not start a tunnel |
| `tunnel-client doctor --config PATH --json` | Check local config, credential/key match, permissions, expiry, and local IPC; no exports are invoked |
| `tunnel-client doctor --config PATH --network --json` | Additionally test DNS, server verification, mTLS, and a bounded non-owning readiness route; does not acquire a device epoch |
| `tunnel-client credentials renew --config PATH` | Request/import a new credential through the configured issuer and perform the explicit drain/reconnect lifecycle |
| `tunnel-client disconnect --config PATH --timeout 30s` | Ask the same-user supervisor to stop admission and drain to a deadline, then close both sockets |

Common future flags: `--config PATH`, `--json`, `--log-level LEVEL`, `--log-format text|json`, and `--timeout DURATION` for bounded commands. `connect --rotation-interval 300s` proposes an override within validated relay limits; the effective value is frozen for the epoch and reported in status. Precedence is explicit flags, configuration file, then documented defaults. Do not introduce arbitrary environment-variable overrides of trust or credential values.

Configuration includes a device endpoint URL, credential reference, server trust reference, rotation/backoff/drain policy, and named export definitions. It rejects credentials in URLs, cleartext non-fixture endpoints, unknown fields, invalid timing relationships, and unsafe export roots. Configuration edits take effect after validation on explicit restart; live reload is deferred to avoid partially changing grants and identity mid-session.

`connect` stays in the foreground initially; systemd/launchd/Windows service integration can supervise it later. Only one local supervisor may hold a profile's credentials/runtime lock. Same-user local IPC uses an owner-restricted Unix socket or Windows named pipe with a tested ACL; never expose unauthenticated local TCP administration. The command must fail clearly if the requested supervisor is absent.

Remote agents may invoke only locally configured exports. The CLI has no remotely supplied executable path, arbitrary shell command, or generic TCP proxy mode. A named ACP export selects a fixed local agent and approved launch configuration; [acp.md](acp.md) specifies request handling and permissions. ACP is an application service carried by the data channel; it cannot become a tunnel-control command.

Proposed stable exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Requested operation succeeded; foreground connect completed an orderly stop |
| 1 | Unexpected internal failure |
| 2 | Invalid invocation or configuration |
| 3 | Missing, invalid, expired, or untrusted credentials / authorization denied |
| 4 | Network or service unavailable / supervisor absent |
| 5 | Deadline exceeded |
| 6 | Operation outcome unknown or incomplete drain requiring reconciliation |
| 130 | Interrupted before an orderly completion could be recorded |

Do not change the implemented bootstrap exit behavior until CLI parsing and its compatibility tests are added. Reconnectable network errors during `connect` remain supervised and visible rather than exiting immediately; permanent trust/configuration errors exit without an infinite retry loop.

`--json` emits versioned JSON on stdout and logs on stderr. Finite commands emit one result object; `connect --json` emits newline-delimited lifecycle events. Each result contains `schema_version`, `command`, `ok`, and either `result` or `error { code, message, retryable, operation_id? }`. Never interleave human progress text with JSON. `retryable` permits retrying safe admission/connection work, not replaying an ambiguous mutation.

## State ownership and crate boundaries

Use a single actor per device ownership epoch. That actor owns control/data attachment state, current and candidate generation, unique physical connection IDs, ticket consumption, per-direction/per-stream sequence allocation, drain watermarks, stream accounting, and shutdown. Socket reader tasks send typed events; bounded writer tasks perform I/O from actor-selected effects. No HTTP handler directly mutates rotation state, and no mutex guard is held across an I/O await.

Data handover follows the authoritative drain rules in [protocol.md](protocol.md): quiesce new payload assignment to the old socket, record each direction/stream's final old-generation sequence, wait for acknowledgment through those watermarks, commit the candidate, and retire the drained old socket. A payload queued while draining remains bounded and is sent on the selected new generation after commit. The default 30-second overlap budget still includes candidate handshake and drain; pending work cannot extend it. Frame sequence identity belongs to a stream direction for its retained session and never resets on socket rotation.

The retained M2 carrier-recovery path keeps the same authenticated control actor and logical session. Its first recovery candidate is eligible after the closure barrier; later failed candidates use the shared 100 ms and 200 ms gaps, with at most three physical attempts under one immutable episode deadline. Each `RECOVERY_CLOSED` list is a per-attempt delta; prior IDs remain in fenced recovery history and are not repeated on the next wire exchange. A failed final attempt is terminal. This path does not implement whole-session control reconnect, process-restart recovery, owner migration, or resume after retention expiry; those boundaries require fresh sessions and explicit operation uncertainty.

Keep transition logic synchronous and deterministic: `(state, event, monotonic_time) -> (next_state, effects)`. Name typed state variants after the authoritative protocol state table, including explicit quiescence, draining, commit, and retirement phases; a generic `connected: bool` cannot represent them. Effects such as opening a candidate, dispatching an adapter request, persisting ownership, and setting deadlines are explicit. Clock, randomness, credential lookup, and network boundaries are injected for tests.

Every queue has a count and byte limit; a full queue returns a typed overload or pauses admission. Charge candidate traffic to the existing session budget. Fair scheduling, cancellation, slow adapters, peer forwarding, and replay share explicit resource budgets. Do not add unbounded channels, detached retries, or background tasks whose owner/shutdown path is unclear.

Supervise tasks in owned groups; a reader/writer panic or unexpected exit becomes an actor event and fails the affected scope. Shutdown first stops admission, then requests adapter-specific cancellation/drain, records terminal or unknown outcomes, closes data/control, and joins tasks within a deadline. Avoid global mutable registries except bounded routing indexes whose entries point to actor handles.

| Boundary | Responsibility |
| --- | --- |
| `tunnel-core` | IDs, configuration, policy values, typed domain errors |
| `tunnel-protocol` | Codec, limits, pure state transitions and model fixtures |
| `tunnel-identity` (future) | TLS identity extraction, trust/credential contracts; no business routing |
| `tunnel-relay` | Axum listeners, authentication middleware, request admission, actor supervision |
| `tunnel-cluster` (future) | Private HTTP/3 adapter, approved peer directory and fenced owner routing |
| `tunnel-client` | CLI, local credential store, device lifecycle, export supervision and IPC |
| `tunnel-vfs`, `tunnel-mcp`, `tunnel-cua`, `tunnel-acp` (future) | Typed adapter operations with independent local policy and failure semantics |

Create crates at their implementation milestone; keep narrowly used helpers as modules until separation improves ownership or testing. Domain services accept typed authenticated principals and bounded request objects, not Axum request bodies or raw headers. Use typed errors in libraries and contextual cause chains at binary boundaries; a single error conversion table maps them to HTTP, WebSocket, peer, and CLI responses.

Initial cluster operation uses the deliberately constrained authority profile in [cluster.md](cluster.md): several relays, one authoritative Redis primary over an authenticated `rediss://` connection, separate durable-catalog and ephemeral-coordination namespaces, no automatic Redis failover, and explicit quiescence plus a newly supplied externally approved incarnation after authority loss, restart or restore. Durable catalog records survive an incarnation change; leases, presence and tickets do not. AOF/fsync and verified backups are durability choices, not consensus or promotion authority. A missing, ambiguous or unverified Redis authority makes the service unready and stops admission. This trades automatic failover for a failure model that can be tested and explained. It does not claim a highly available coordination layer.

## Implemented local doctor

`tunnel-client doctor --config PATH [--json]` reads the local profile and credential files, checks certificate/key match, Unix private-key and parent-directory permissions, and client/server-CA certificate validity. It opens no network connection and invokes no export. Relative credential paths resolve from the profile directory.

Exit 0 means those local checks passed; exit 2 means invalid invocation/configuration; exit 3 means a credential, permission or expiry failure. JSON uses schema version 1, omits paths and credential contents, and explicitly reports `SUPERVISOR_IPC_NOT_IMPLEMENTED`. `--network` is rejected because that mode is not implemented. Non-Unix permission validation reports unsupported rather than claiming a pass.

Current macOS evidence is 39 library tests, 8 binary unit tests, 5 actual CLI fixtures and strict client all-targets Clippy; see [the continuation evidence](m7-verification.md). This does not verify the broader IPC/status/diagnostic-bundle contract below.

## Debugging and deployment contract

Each transition emits a structured event with stable event name, reason code, previous/next state, duration/deadline, and applicable IDs: trace/request, tenant, device, credential fingerprint, relay, cluster incarnation, owner epoch, socket generation, stream, and operation. Store opaque identifiers under log-access policy; never add high-cardinality IDs as metric labels. Validate incoming trace context and generate trusted internal IDs when absent or malformed.

`status` provides current state, owner/epoch, active/candidate/draining connection IDs and generations, certificate expiry, negotiated rotation policy, last successful rotation, retry deadline, last typed error, queue/replay/drain byte counts, pending per-direction/per-stream drain watermarks, absolute drain/overlap deadlines, stream count, and redacted export capability names. A bounded detail option lists stream watermark progress with a truncation indicator when the snapshot budget is reached. Snapshots come from the actor through a bounded request, so they describe one consistent state. They must not include raw certificate chains, environment values, endpoint query strings, file paths/content, prompts, screenshots, tool arguments, enrollment codes, tickets, or tokens.

Metrics cover connection/authentication failures by bounded reason, rotation duration/outcome, overlap time, queue occupancy, credit stalls, peer RTT, request latency, denied admission, and unknown outcomes. Separate readiness from liveness: a process can be alive but unable to serve because trust, Redis authority, or owner routing is unavailable. Public health output exposes only readiness; detailed state is restricted administration data.

Logs and optional local diagnostic bundles contain redacted configuration structure, build/protocol versions, dependency fingerprint, clock/expiry health, limits, and bounded recent state events. Use synthetic payload tracing only in dedicated test fixtures. Payload logging and TLS session-key logging stay disabled in production, including debug mode. Sampling and retention budgets are configuration, not unbounded file growth.

Public consumer HTTPS may terminate at an explicitly configured reverse proxy; its upstream channel must be protected and forwarded host/proto values accepted only from configured proxy addresses. The device mTLS listener initially requires direct TLS termination inside the relay or **layer-4 TCP passthrough**. A generic HTTP proxy that replaces device TLS with its own upstream connection cannot preserve the required mTLS identity through arbitrary headers.

Peer HTTP/3 requires bidirectional private UDP reachability and QUIC support through the actual load-balancer/firewall path. A successful HTTPS health check does not prove it. Peer credentials and node identity terminate at the participating relay, not an unrelated public proxy. No silent HTTP/2 fallback is permitted in the initial cluster profile. Configure and test UDP idle timeouts, maximum streams, connection/stream windows, keepalive, and graceful draining against the deployment path.

## Error and incident vocabulary

Keep transport failures, authentication decisions, admission, and application outcomes distinct. A TLS failure may happen before an HTTP request exists; it produces a local diagnostic and handshake metric, not a fabricated HTTP response or application operation ID.

| Typed category | Example diagnostic | Operator interpretation |
| --- | --- | --- |
| `TlsTrust` | `SERVER_CERT_UNTRUSTED`, `DEVICE_CERT_EXPIRED` | Verify trust bundle, role, expected name, expiry, and clock; never suppress verification |
| `DeviceAdmission` | `DEVICE_CREDENTIAL_REVOKED`, `DEVICE_DISABLED` | Resolve the durable credential/policy record through an authorized administrator |
| `Pairing` | `DATA_TICKET_USED`, `DATA_KEY_MISMATCH` | Diagnose attachment/epoch/credential lifecycle; a retry needs a fresh authorized ticket |
| `PeerAdmission` | `PEER_KEY_UNAPPROVED`, `PEER_TRUST_STALE` | Inspect signed membership and node identity; public HTTPS health is unrelated |
| `Ownership` | `OWNER_FENCED`, `AUTHORITY_UNAVAILABLE` | Follow cluster recovery; never manually copy an old epoch into a new process |
| `Capacity` | `STREAM_LIMIT`, `QUEUE_BUDGET_EXCEEDED` | Work was refused before dispatch; return a bounded retry hint |
| `Rotation` | `CANDIDATE_TIMEOUT`, `DRAIN_TIMEOUT` | Inspect connection IDs, watermark gaps, credit stalls, and the absolute overlap deadline |
| `Adapter` | `ADAPTER_UNAVAILABLE`, `OUTCOME_UNKNOWN` | Distinguish failure before dispatch from an operation that may have executed |

The codes above are proposed public vocabulary, to freeze with the error-schema implementation. Logs retain nested causes locally; external errors contain only the stable safe code, a short explanation, request/operation ID where available, and a permitted retry hint. Do not leak host paths or raw TLS/backend errors through consumer responses.

Initial runbooks should answer a bounded set of questions:

1. **A CLI cannot connect:** use local `doctor` to verify configuration and credentials, then `doctor --network` to distinguish DNS, server trust, device mTLS, and application admission. Never replace verification with a permissive TLS option during diagnosis.
2. **Control is up but data is absent:** inspect the selected owner, credential ID, ticket result, connection ID, and candidate deadline. Check both direct and forwarded attachment admission without printing a ticket.
3. **Rotation is draining:** inspect old-generation final sequence versus contiguous ACK for each pending stream direction, queued bytes, and remaining overlap time. Preserve the fixed deadline; a stuck adapter cannot keep the old socket alive forever.
4. **Only cross-node requests fail:** check peer UDP reachability and ALPN, then mutual certificate identity, signed key membership freshness, owner fencing, and bounded forwarding capacity in that order.
5. **A mutation disconnected:** query the authorized operation status. Report a known result or explicit ambiguity; neither reconnect nor a transport ACK authorizes repeating the mutation.
6. **Redis authority was lost or restored:** fail closed and follow the quiescence, verified-backup and externally approved new-incarnation process in [cluster.md](cluster.md); do not restart relays independently using a remembered lease or local catalog snapshot.

Each runbook must link a reproducible synthetic fixture and the expected event sequence before alpha release. Production debugging changes must not weaken authentication, increase unbounded buffers, or invoke a real desktop as a probe.

## Implementation and verification gates

1. **TLS identity spike:** direct device mTLS on both WSS endpoints, certificate extraction into typed Axum identity, custom client rustls configuration, and two sockets plus one bounded candidate. Prove no certificate, wrong issuer, expired certificate, wrong role, unknown/revoked device, stolen ticket, wrong key, and forged identity headers fail before dispatch.
2. **Peer stack spike:** two real processes negotiate HTTP/3 over UDP with mutual certificates, verify allowed identities/keys, exchange bounded streaming request/response bodies, cancel streams, and reject missing/wrong-role/unapproved peers. Pin the compiled dependency set and document tested platforms; no business adapter is required yet.
3. **CLI contract:** snapshot help and versioned JSON, test all exit-code mappings and flag precedence, exercise credential create/import with fixture PKI, enforce key-file/IPC permissions, and prove `config check`, `status`, and default `doctor` do not open tunnels or invoke exports.
4. **Lifecycle:** deterministic model/property tests for rotation, concurrent requests, bounded queues, cancellation, credential renewal, expiry, and task shutdown. Fake time and injected failures must reproduce every state transition and ambiguous-operation result without wall-clock sleeps.
5. **Real deployment:** test public OAuth HTTPS and device mTLS WSS through supported proxy arrangements, plus private HTTP/3 across three relays. Prove both socket admissions preserve identity when they reach different nodes; inspect actual ALPN/TLS/peer identity rather than infer success from an HTTP response.
6. **Debuggability:** a fixture trace reconstructs an authorized request through ingress, owner, CLI, adapter, and result across rotation; induced failures identify the responsible layer. Automated redaction checks scan logs/status/bundles for planted secrets and payload markers; pressure tests verify diagnostic paths stay bounded.
7. **Provisioning release gate:** selected issuer and renewal profile, atomic enrollment receipt behavior, short-lived one-use authorization, role separation, revocation cutoff, expired open-session closure, and recoverable interrupted credential replacement are tested before self-service enrollment is shipped.

Keep all transport fixtures synthetic. CUA integration uses disposable desktop VMs; no runtime or diagnostic test should control the user's active desktop. Validate repository changes with the locked Rust checks in [testing.md](testing.md); document actual interoperability evidence before changing the project's implementation status.
