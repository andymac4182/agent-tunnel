# Axum runtime, device mTLS, and CLI

Status: runtime implementation design, 2026-09-09. M1 implements the client `config check`, `credentials create`, `credentials import` and foreground `connect` commands; the relay implements `serve` with Axum HTTPS, both device mTLS WebSockets and Redis/JWT authority, plus the read-only `check-serve-config --config PATH` dry run for that serving configuration. Legacy `check-config` remains supported. See [M1 evidence](m1-harness.md). Status/doctor IPC, enrollment and generic adapters below remain planned. M2 rotation and M7 cluster work have separate current evidence in their verification documents. The local-only doctor slice is implemented and locally verified as described below.

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

### Bounded listener connection permits

Both public listeners supervise at most 64 concurrent TLS handshakes and HTTP connections, and one permit is held for the whole HTTP connection. A permit is therefore bounded in time as well as in count by three validated `ListenerTimeouts` values, so an anonymous consumer connection (or a connection presenting one valid device certificate) cannot hold a permit by completing the TLS handshake and then staying silent:

| Bound | Default | Accepted range | Phase it covers |
| --- | --- | --- | --- |
| `handshake_timeout` | 10 s | 100 ms..=300 s | TCP accept until the TLS 1.3 handshake completes |
| `pre_request_timeout` | 15 s | 100 ms..=300 s | Handshake completion until the connection dispatches its first complete HTTP request: HTTP/1-versus-HTTP/2 sniffing, the HTTP/2 preamble, and the first request head |
| `http1_header_read_timeout` | 10 s | 100 ms..=300 s, not above `pre_request_timeout` | Each single HTTP/1 request-head read, including an idle keep-alive gap between requests |

A silent connection therefore holds a permit for at most 25 seconds by default, then is closed and returns it. The pre-request bound is disarmed permanently by the first dispatched request, so an established device WebSocket upgrade, an in-flight consumer request, and a streaming response body are never closed by it; `http1_header_read_timeout` is armed by Hyper only when it can read a new request head, so it does not apply during an in-flight request, a streaming body, or after an upgrade. HTTP/2 has no header-read deadline of its own, and `hyper_util`'s protocol sniffer has no deadline at all, which is why the pre-request bound is enforced by the listener rather than delegated to Hyper. Hyper discards a configured header-read deadline unless a timer is installed on its builder, so the listener installs a Tokio timer on both the HTTP/1 and HTTP/2 builders. Raising the permit count is not a substitute for these deadlines. An invalid value fails closed: the listener returns a typed error and releases the socket instead of accepting with an unbounded permit.

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

Keep the existing binary name `tunnel-client`. `check-config [PATH]`, `config check`, `credentials create`, `credentials import`, `connect` and `doctor` are implemented today, and they select the exit statuses in the client exit-code table below. `status`, `enroll`, `credentials renew`, `disconnect` and `doctor --network` are **not** implemented; `--network` is rejected rather than ignored. The following is the command contract, and the unimplemented rows are not runnable examples of delivered features.

| Command | Defined behavior |
| --- | --- |
| `tunnel-client config check --config PATH` | Parse and validate local configuration without network calls or service startup; retain `check-config [PATH]` as an alias |
| `tunnel-client credentials create --config PATH --csr-out PATH` | Generate a pending local key, write a public CSR without overwriting an existing credential |
| `tunnel-client credentials import --config PATH --certificate PATH --server-ca PATH` | Validate/import the certificate for the pending key and trusted server bundle from explicit local inputs |
| `tunnel-client enroll --server HTTPS_URL --code-stdin --server-ca PATH --config PATH` | Perform the gated enrollment flow above; omit `--server-ca` only for platform-trusted public PKI |
| `tunnel-client connect --config PATH` | Foreground supervisor; establish the mTLS socket pair, register fixed exports, and run until graceful shutdown. **Implemented without the reconnect loop:** today an unreachable relay exits `4` at once and a closed session ends the process (`SESSION_CLOSED`, exit `4`); only a failed *data* socket is retried within one session (the retained carrier-recovery path below). Reconnect with bounded jitter is not implemented (M6-C23) |
| `tunnel-client status --config PATH --json` | Read the local supervisor's redacted status through authenticated local IPC; does not start a tunnel |
| `tunnel-client doctor --config PATH --json` | Check local config, credential/key match, permissions, expiry, and local IPC; no exports are invoked |
| `tunnel-client doctor --config PATH --network --json` | Additionally test DNS, server verification, mTLS, and a bounded non-owning readiness route; does not acquire a device epoch |
| `tunnel-client credentials renew --config PATH` | Request/import a new credential through the configured issuer and perform the explicit drain/reconnect lifecycle |
| `tunnel-client disconnect --config PATH --timeout 30s` | Ask the same-user supervisor to stop admission and drain to a deadline, then close both sockets |

Common future flags: `--config PATH`, `--json`, `--log-level LEVEL`, `--log-format text|json`, and `--timeout DURATION` for bounded commands. `connect --rotation-interval 300s` proposes an override within validated relay limits; the effective value is frozen for the epoch and reported in status. Precedence is explicit flags, configuration file, then documented defaults. Do not introduce arbitrary environment-variable overrides of trust or credential values.

Configuration includes a device endpoint URL, credential reference, server trust reference, rotation/backoff/drain policy, and named export definitions. It rejects credentials in URLs, cleartext non-fixture endpoints, unknown fields, invalid timing relationships, and unsafe export roots. Configuration edits take effect after validation on explicit restart; live reload is deferred to avoid partially changing grants and identity mid-session.

`connect` stays in the foreground initially; systemd/launchd/Windows service integration can supervise it later. Only one local supervisor may hold a profile's credentials/runtime lock. Same-user local IPC uses an owner-restricted Unix socket or Windows named pipe with a tested ACL; never expose unauthenticated local TCP administration. The command must fail clearly if the requested supervisor is absent.

Remote agents may invoke only locally configured exports. The CLI has no remotely supplied executable path, arbitrary shell command, or generic TCP proxy mode. A named ACP export selects a fixed local agent and approved launch configuration; [acp.md](acp.md) specifies request handling and permissions. ACP is an application service carried by the data channel; it cannot become a tunnel-control command.

### Client exit codes

These are the exit statuses `tunnel-client` selects, and they are implemented rather than proposed. `Cause::exit_code` in `crates/tunnel-client/src/main.rs` is the authority.

**`Cause::exit_code` is the authority for everything except two paths, which are named here because "the authority" would otherwise be wrong.** `doctor` computes its own statuses in `crates/tunnel-client/src/doctor.rs` (`0`, `2`, `3`) and returns from `main` before the async command runner, so it never reaches `Cause`; and a failure to install the process crypto provider returns a bare `ExitCode::FAILURE` (`1`) with a message and **no diagnostic code**, because it happens before argument parsing and before any `--json` contract exists. Both are consistent with the table below; neither is derived from it.

**This table is a copy, and since M6-02 it is checked against the code.** `scripts/m6-release-artifact.py verify --check docs` parses `Cause::code` and `Cause::exit_code` out of `crates/tunnel-client/src/main.rs` and fails unless every cause appears in exactly one row below whose status is the one the source selects, and unless every status the source produces has a row; its controls edit this table and the source in turn and require it to go red. It does not check the *Meaning* or *What the operator does* columns, nor `doctor`'s own statuses (those are executed instead, by [the operator guide](operator.md#6-diagnostics)). Also checked mechanically: `tunnel_client::CLI_DIAGNOSTIC_EXIT_CODES` is the single definition of the set of statuses, `every_exit_status_is_in_the_published_vocabulary` fails if any cause maps outside it, `the_cli_and_the_library_publish_the_same_diagnostic_code` pins `Cause::code` against `ClientError::code`, and `scripts/m0-guard-exit-codes.py` holds each individual mapping to its meaning with a named witness test. A reviewer changing a status must still edit this table by hand; the docs check then says whether the edit matches.

| Code | Meaning | Diagnostic codes that select it | What the operator does |
| --- | --- | --- | --- |
| 0 | Requested operation succeeded; foreground `connect` completed an orderly stop | — | nothing |
| 1 | Unexpected internal failure | `PROTOCOL_ERROR`, `SUPERVISOR_FAILED`, `SIGNAL_ERROR`, and the codeless crypto-provider bail-out | report it; this is a defect or a version skew |
| 2 | Invalid invocation or configuration; nothing was attempted | `INVALID_INVOCATION`, `CONFIG_ERROR`, `INVALID_CONFIG`; also `doctor`'s own `INVALID_CONFIG` | fix the command line or the profile |
| 3 | Missing, invalid, expired, or untrusted credentials / authorization denied | `CREDENTIAL_ERROR`, `AUTHORIZATION_STALE`; also `doctor`'s `CREDENTIAL_*` family | run `doctor`; re-enroll or re-authorize |
| 4 | Network or service unavailable; the relay could not be reached or closed the session | `TRANSPORT_ERROR`, `SESSION_CLOSED` | check reachability, then retry |
| 5 | Deadline exceeded | `DEADLINE_EXCEEDED` | check latency, or raise the bounded deadline |
| 6 | Operation outcome unknown or incomplete drain requiring reconciliation | *(no producer today — see below)* | query the authorized operation status; never replay the mutation |
| 7 | Refused before dispatch: the device owner slot is already held, or a bounded local budget was exhausted. No session work started | `OWNER_BUSY`, `RESOURCE_EXHAUSTED` | stop the other connector, or wait and retry |
| 130 | Interrupted before an orderly completion could be recorded | `CANCELLED` | re-run; an orderly `Ctrl-C` stop exits `0` instead. **Not what Ctrl-C during the connect handshake produces:** the `ctrl_c` handler is armed only after connecting, so a SIGINT then either kills the process by signal with no diagnostic (a shell also reports that as 130) or, if inherited as ignored, is ignored until the handshake deadline exits `5` `DEADLINE_EXCEEDED` (measured; M6-C27) |

`7` was added by task row M0-03. Before it, `OWNER_BUSY` and `RESOURCE_EXHAUSTED` fell through a `_ => 1` arm and were reported as "unexpected internal failure" — together with `CANCELLED`, `AUTHORIZATION_STALE`, `PROTOCOL_ERROR` and `SUPERVISOR_FAILED`, six live causes sharing one status. A refused-before-dispatch outcome is neither a network failure (`4`) nor a defect (`1`): nothing is wrong, something else holds the slot.

**Exit `6` is documented and unreachable.** No path in `tunnel-client` constructs an ambiguous-outcome cause today, so nothing can produce `6`. It is listed here because the ambiguous-mutation contract is a design requirement and the code is reserved for it; it is deliberately absent from the `Cause` enum, because an enum variant nothing constructs is a surface that reads as covered and is not. Closing the gap means giving the ambiguous-outcome path a producer, not adding the variant.

The **relay** does not use this table. `tunnel-relay` still exits `0` or `1` per its bootstrap behavior; see the dry-run section below. Wiring the relay to this vocabulary waits for relay CLI parsing and its compatibility tests.

Permanent trust/configuration errors exit without a retry loop. **So, today, do reconnectable network errors:** `connect` exits `4` immediately when the relay cannot be reached (measured by [the operator guide](operator.md#31-one-relay)), and a closed session ends the process, so restarting it belongs to whatever supervises it. Supervised reconnection is design intent, not delivered behaviour (M6-C23).

### Relay configuration dry run

`tunnel-relay check-serve-config --config PATH` is implemented. It is the read-only dry run for the `ServeConfig` that `tunnel-relay serve --config PATH` constructs: it applies every rule `serve` applies to the configuration document, including the authoritative Redis namespace rule the catalog owns, the Redis TLS-material and `rediss://` scheme pairing, rotation timing, and the cluster and recovery cross-field rules.

The command is inert and deterministic. It reads the one configuration file named on the command line and nothing else; it binds no listener, makes no Redis or peer connection, reads no credential, private key or JWKS material, and creates or modifies no file. It is therefore safe to run against a production configuration, and it returns the same verdict on a checkout whose placeholder credential paths do not exist. Validating the referenced material remains `serve`'s own startup work: a successful dry run is evidence about the configuration document, not about the deployment's files.

It takes no flag other than `--config PATH`. A dry run that could select a different authority file, namespace or trust path than `serve` would prove nothing about the deployment, so no override exists.

Exit codes follow the relay's implemented bootstrap behavior: `0` when the configuration is valid, `1` with a redacted field-level reason on stderr when it is not or when the file cannot be read. The client exit-code table above is not wired into the relay; that change waits for relay CLI parsing and its compatibility tests. The relay's legacy `check-config [PATH]` stays a `tunnel_core::RelayConfig` check and is not evidence for a serving document.

`--json` emits versioned JSON on stdout and logs on stderr. Finite commands emit one result object; `connect --json` emits newline-delimited lifecycle events. Each result contains `schema_version`, `command`, `ok`, and either `result` or `error { code, message, retryable, operation_id? }`. Never interleave human progress text with JSON. `retryable` permits retrying safe admission/connection work, not replaying an ambiguous mutation.

## State ownership and crate boundaries

Use a single actor per device ownership epoch. That actor owns control/data attachment state, current and candidate generation, unique physical connection IDs, ticket consumption, per-direction/per-stream sequence allocation, drain watermarks, stream accounting, and shutdown. Socket reader tasks send typed events; bounded writer tasks perform I/O from actor-selected effects. No HTTP handler directly mutates rotation state, and no mutex guard is held across an I/O await.

Data handover follows the authoritative drain rules in [protocol.md](protocol.md): quiesce new payload assignment to the old socket, record each direction/stream's final old-generation sequence, wait for acknowledgment through those watermarks, commit the candidate, and retire the drained old socket. A payload queued while draining remains bounded and is sent on the selected new generation after commit. The default 30-second overlap budget still includes candidate handshake and drain; pending work cannot extend it. Frame sequence identity belongs to a stream direction for its retained session and never resets on socket rotation.

The retained M2 carrier-recovery path keeps the same authenticated control actor and logical session. Its first recovery candidate is eligible after the closure barrier; later failed candidates use the shared 100 ms and 200 ms gaps, with at most three physical attempts under one immutable episode deadline. Each `RECOVERY_CLOSED` list is a per-attempt delta; prior IDs remain in fenced recovery history and are not repeated on the next wire exchange. A failed final attempt is terminal. This path does not implement whole-session control reconnect, process-restart recovery, owner migration, or resume after retention expiry; those boundaries require fresh sessions and explicit operation uncertainty.

Keep transition logic synchronous and deterministic: `(state, event, monotonic_time) -> (next_state, effects)`. Name typed state variants after the authoritative protocol state table, including explicit quiescence, draining, commit, and retirement phases; a generic `connected: bool` cannot represent them. Effects such as opening a candidate, dispatching an adapter request, persisting ownership, and setting deadlines are explicit. Clock, randomness, credential lookup, and network boundaries are injected for tests.

Every queue has a count and byte limit; a full queue returns a typed overload or pauses admission. Charge candidate traffic to the existing session budget. The per-device session byte budget carves out `131,072` bytes (four 32 KiB control messages) that only control-lane charges may use: data-lane charges are refused above `max_queue_bytes - 131,072`, control-lane charges only at `max_queue_bytes`, and the session snapshot reports `control_reserved_bytes`, `data_bytes_limit` and `data_bytes_high_water` beside `queue_bytes_limit` (see [protocol.md](protocol.md)). Fair scheduling, cancellation, slow adapters, peer forwarding, and replay share explicit resource budgets. Do not add unbounded channels, detached retries, or background tasks whose owner/shutdown path is unclear.

Public consumer admission uses two layered permit bounds, not one. `max_pending_operations` (default 64, validated 1..=64) is the relay-global process bound; it is reserved before a request body is read and is deliberately not tenant-scoped. `max_pending_operations_per_owner` (default 48, validated 1..=64) bounds the permits one `(tenant_id, device_id)` owner scope may hold at once and is reserved only after the authenticated catalog identity fixes that scope. The effective per-owner bound is `min(max_pending_operations_per_owner, max_pending_operations)`, because the global permit is always reserved first. The relay-global permit is held for the whole operation round trip, including the lifetime of a public stream, so without the per-owner bound one tenant's in-flight operations refuse every other tenant's public request with the typed `ADMISSION_LIMIT` outcome. The default leaves at least a quarter of relay ingress capacity unreachable by any single tenant/device while keeping one owner enough headroom for its `max_streams_per_device` allowance spread across a cluster's non-owner ingress relays; deployments serving many concurrent tenants should lower it. Both bounds refuse with the same typed `ADMISSION_LIMIT` / `not_dispatched` outcome and a bounded retry hint; neither adds a new refusal code. Each permit is released exactly once on drop, so an abandoned request, a refused peer admission, a cancelled upgrade and a normal close all return capacity. A per-scope entry exists only while it holds at least one permit, so the registry is bounded by the relay-global permit count rather than by the catalog. Scope-level rate limits for principals and connector counts remain the separate planned limits in [protocol.md](protocol.md); the catalog-read routes (`/v1/devices`, `/v1/devices/{device}/services`) take only the relay-global permit because they hold it for one bounded catalog read and never across a device round trip.

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

Exit 0 means those local checks passed; exit 2 means invalid invocation/configuration; exit 3 means a credential, permission or expiry failure. JSON uses schema version 1, omits paths and credential contents, and explicitly reports `SUPERVISOR_IPC_NOT_IMPLEMENTED`.

**`result` is always present, including on a failing run** (M6-C07). Every check reports its own status, and `not_run` is a distinct status from `failed`, so a report says which checks were attempted rather than leaving a reader to infer it from the report's absence. This matters most where it used to be worst: `supervisor_ipc` and `process_containment` describe the host rather than the configuration, are computed before the configuration is even read, and an unprovisioned machine — where every run fails — is exactly the population that needs to read them. Emitting the result alongside an error leaks nothing: every leaf of the report is a fixed status or code string, a permission mode, a certificate count or a unix timestamp. `--network` is rejected because that mode is not implemented. Non-Unix permission validation reports unsupported rather than claiming a pass.

Current macOS evidence is 39 library tests, 8 binary unit tests, 5 actual CLI fixtures and strict client all-targets Clippy; see [the continuation evidence](m7-verification.md). This does not verify the broader IPC/status/diagnostic-bundle contract below.

## Debugging and deployment contract

Each transition emits a structured event with stable event name, reason code, previous/next state, duration/deadline, and applicable IDs: trace/request, tenant, device, credential fingerprint, relay, cluster incarnation, owner epoch, socket generation, stream, and operation. Store opaque identifiers under log-access policy; never add high-cardinality IDs as metric labels. Validate incoming trace context and generate trusted internal IDs when absent or malformed.

`status` provides current state, owner/epoch, active/candidate/draining connection IDs and generations, certificate expiry, negotiated rotation policy, last successful rotation, retry deadline, last typed error, queue/replay/drain byte counts, pending per-direction/per-stream drain watermarks, absolute drain/overlap deadlines, stream count, and redacted export capability names. A bounded detail option lists stream watermark progress with a truncation indicator when the snapshot budget is reached. Snapshots come from the actor through a bounded request, so they describe one consistent state. They must not include raw certificate chains, environment values, endpoint query strings, file paths/content, prompts, screenshots, tool arguments, enrollment codes, tickets, or tokens.

Metrics cover connection/authentication failures by bounded reason, rotation duration/outcome, overlap time, queue occupancy, credit stalls, peer RTT, request latency, denied admission, and unknown outcomes. Separate readiness from liveness: a process can be alive but unable to serve because trust, Redis authority, or owner routing is unavailable. Public health output exposes only readiness; detailed state is restricted administration data.

Logs and optional local diagnostic bundles contain redacted configuration structure, build/protocol versions, dependency fingerprint, clock/expiry health, limits, and bounded recent state events. Use synthetic payload tracing only in dedicated test fixtures. Payload logging and TLS session-key logging stay disabled in production, including debug mode. Sampling and retention budgets are configuration, not unbounded file growth.

Every peer fault a relay observes while dispatching to a remote owner, or while serving a forwarded request as the owner, is published on the relay's typed snapshot as one bounded `peer_fault_diagnostics` tuple: a role (`ingress` or `owner`), a stage from the closed dispatch order `validation`, `pool_connect`, `stream_permit_checkout`, `sender_lock`, `h3_dispatch`, `envelope_send`, `complete`, `head`, `body`, `lease`, `owner`, and a closed cause label (for example `no_live_owner`, `identity_mismatch`, `transport_goaway`, `transport_h3`, `transport_timeout`, `transport_pins_unavailable`, `membership_expired`, `owner_not_ready`, `capacity`, `remote_unauthorized`, `deadline`). `transport_pins_unavailable` is its own cause rather than a generic authentication failure because it means this relay publishes no approved peer trust evidence at all: no socket was opened and no peer certificate examined, so the consumer is answered `not_dispatched` with a bounded retry hint instead of an unknown outcome. The tuple carries only correlation identifiers: tenant, device, session, owner epoch, owner node, service and request identifiers. Transport error text, payloads, bearer tokens, endpoints and paths never enter it. Each request records at most one tuple, and an owner-side handler records it before the owner registration it refers to is closed, so a fault outlives the state it describes. The snapshot retains saturating stage and cause counters, the latest tuple per stage and a ring of the thirty-two most recent tuples. An owner admission decision (`owner_not_ready`, `capacity`, a remote status) observed by the ingress while waiting for the response head is attributed to the `owner` stage; a transport failure at the same point stays at `head`. The `verify-m7-c11-diagnostics` matrix parses every captured relay snapshot strictly against this schema and requires exact tuples where the induced fault implies them, and `verify-m7-og02-correlation` reports the tuples and correlation families each fault gate produced.

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
