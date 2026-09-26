# MCP adapter plan

Status: M3-01 (pins), M3-02 (device exports over `http-forward/1`) and M3-03 (a real cloud-side client across relays and rotations) are **verified local at `db1da30`, 2026-09-16**, each through `verify-m3-mcp-cloud-client`, which passed 7 of 7 runs at that revision — 3 inside `scripts/m3-harness-verify.sh` and 4 standalone. M3-01 and M3-02 have no gate of their own and rest on that gate plus their unit tests. M3-04 (isolation, correlation, unknown outcomes and revocation) is **verified local at `fc5dde3`, 2026-09-25**, on branch `m3-reliability`: `verify-m3-mcp-isolation` passed in every one of 10 consecutive `scripts/m3-harness-verify.sh` runs at that revision, 10 of 10 standalone on a hosted Linux runner at the same revision, and 20 of 20 standalone under CPU load at two earlier revisions of the branch. The peer-trust flake that held it back is closed on this gate by M7-C89's re-sign pin wait rather than by the M7-C86 retention, which stays an open M7 row; the suite's other intermittents were diagnosed and fixed there (M3-20, M3-21/M3-24, M3-23, M3-27, M3-29, M3-30). The suite was held off hosted CI by M3-31 (the real-path gate's OPEN-journal peak on hosted Linux); branch `m3-features` explains that row (the retained entry was an earlier-phase entry still in flight, not a leak) and adds an `m3-acceptance` job to `ci.yml`. See the M3-04 and M3-25 rows in [tasks.md](tasks.md). Gate 5 of the forwarding contract is verified local for MCP only; no ACP or CUA profile exists, and those stay in M8 and M5. The M3 gates prove both profiles against the pinned rmcp 3.4.0 client and the deterministic fixture server. **M3-17** adds off-the-shelf evidence for the `mcp-2025-11-25` profile: the official TypeScript SDK (1.30.1), the official Python SDK (2.2.0) and the official conformance suite (0.2.0-alpha.11), each pinned in `tests/mcp-sdk-conformance` and run through real local relays by `scripts/m3-sdk-conformance.sh`. See [Off-the-shelf clients (M3-17)](#off-the-shelf-clients-m3-17). See [Pinned in code](#pinned-in-code-m3-01-and-m3-02), [Pinned in code (M3-03)](#pinned-in-code-m3-03) and [Pinned in code (M3-04)](#pinned-in-code-m3-04). MCP compatibility is separate from the tunnel wire protocol. The tunnel's control and data WebSockets do not require an external MCP client to support a custom transport.

## Two explicit compatibility profiles

The current upstream specification is **2026-07-28**. It changes HTTP transport and discovery behavior compared with 2025-11-25. The official Rust SDK documents support for both. Build profile-specific tests instead of mixing lifecycle rules. References are pinned in [sources.md](sources.md).

| Concern | 2026-07-28 target | 2025-11-25 compatibility target |
| --- | --- | --- |
| Startup | Discovery/negotiation with per-request metadata | `initialize` and `notifications/initialized` lifecycle |
| HTTP | POST with JSON or request-scoped SSE response | POST plus optional GET SSE stream |
| Protocol sessions | No protocol-level session IDs | MCP session IDs are scoped to the authenticated principal, device and service (M3-04) |
| Resume | No Last-Event-ID transport resume | Resume only where the backend profile supports it |
| Cancellation | Response-stream disconnect cancels that request | Version-specific cancellation behavior |

Do not silently convert between versions. Prefer transparent routing to a compatible upstream server. Any stdio-to-HTTP lifecycle translation must be implemented explicitly using a pinned SDK and conformance-tested before advertising that profile. Unknown methods and version metadata are not discarded merely because the relay does not interpret them.

## Gateway boundaries

Expose a consumer endpoint per authorized device/service. The relay terminates consumer HTTP authentication, validates the version's required headers and body relationship, and opens a tunnel logical stream to the device's fixed local export. It forwards status, content type, bounded headers, streaming bodies, cancellation, and errors. Preserve HTTP request boundaries independently from tunnel chunk boundaries.

For local stdio servers, the device daemon supervises an explicitly configured subprocess through the official Rust SDK. Keep stdout reserved for MCP messages and stderr separate. Each consumer gets an isolated upstream instance/session by default; sharing requires an adapter that proves request-ID, notification, and authorization isolation. A tool result cannot redirect the daemon to another executable or endpoint.

Local Streamable HTTP exports use a fixed allowlisted endpoint. Strip hop-by-hop headers and incoming upstream Authorization values. Consumer credentials authorize the relay; local backend credentials remain device-owned. Respect version-specific lifecycle, SSE parsing, server-initiated messages, progress, errors, and backpressure. Never reduce MCP support to only `tools/call` if claiming generic bridging.

HTTP authorization follows the selected MCP spec: protected-resource discovery, correct resource audience, minimal scopes, and issuer validation. Use an external compatible authorization server. Do not pass relay tokens through to local tools. Implement strict Origin validation for browser-capable endpoints.

## Rotation and cancellation

Scheduled data rotation changes the underlying tunnel carrier while keeping the logical request/stream open. It must not close the consumer HTTP/SSE response merely to rotate a socket. A true consumer disconnect propagates profile-appropriate cancellation; in 2026-07-28 the response-stream closure has cancellation semantics. A dead device/control epoch produces an explicit interruption, not a fabricated successful tool response.

**A new MCP request that arrives during a rotation freeze is held, not refused** (task row M3-15; owner decision, 2026-09-25). The relay pauses new stream admission from QUIESCE to COMMIT. The owner now holds a POST or standalone GET that lands there, for at most 1.5 s and 8 per device (64 per tenant, 256 per relay), and admits it once the rotation commits (or the attempt aborts onto the old carrier), so a client that does not retry a `503`, rmcp 3.4.0 included, does not see a scheduled rotation. Only a freeze that outlasts the hold, or a full hold, reaches the client, as `503 ROTATION_FREEZE` `not_dispatched` with `retry_after_ms` 250 and `Retry-After: 1`. That code means the scheduled freeze and nothing else, so a gateway may resend it. The owner-not-ready fault body (`503 PEER_UNAVAILABLE`, `"selected owner is not ready; retry after the bounded hint"`) is unchanged and should not be treated as a rotation. The bound, cap and every outcome are in [protocol.md, "Quiesce admission"](protocol.md#scheduled-handover-prepare-fence-drain-commit-retire) and [http-forwarding.md, "Rotation and recovery"](http-forwarding.md#rotation-and-recovery).

Transport replay only resends unacknowledged transport sequences in a live epoch; the receiving tunnel endpoint deduplicates before delivering bytes to MCP. It does not re-invoke a tool. If the process loses state after the tool may have executed, return an ambiguous outcome rather than automatically rerunning the request. MCP protocol/session IDs and tunnel stream IDs have separate lifecycles.

## M3 acceptance

- Real official SDK client to relay to device to a deterministic local stdio server and an HTTP server.
- Discovery or initialization, tool/resource/prompt discovery, calls, binary/image content, errors, notifications and cancellation appropriate to each profile.
- A streaming call crosses at least three scheduled data rotations without consumer disconnect, duplicated output, or repeated invocation.
- Concurrent consumers reuse identical JSON-RPC IDs without cross-delivery; another user cannot discover or invoke the export or resume its legacy session.
- Malformed headers, unsupported versions, hostile origins, invalid token audiences, backend redirects, oversized bodies, child crashes, and unknown tool outcomes fail predictably.
- Advertise only the profile/capabilities proven by the pinned client/server fixture matrix.

## Pinned in code (M3-01 and M3-02)

Recorded 2026-09-16. Each item is pinned in code and covered by the tests named at the end.

### Artifacts and what they support

- **Specification.** The profiles follow the snapshot in [sources.md](sources.md) (`aa8ce049…`): the 2026-07-28 Streamable HTTP page and the 2025-11-25 transports page, both re-read for this pin.
- **Official Rust SDK: `rmcp = "=3.4.0"`.** It was released on crates.io on 2026-09-15 from `modelcontextprotocol/rust-sdk` commit `fd7811fdaa9fefa1c8034534b4d7a31c97204f89` (path `crates/rmcp`). The `Cargo.lock` checksum is `b23c62fe489ac1d401ab32688cfacac3737a8978dc3343e5361464c7724fd3cb`, and the crate's rust-version is 1.88. Its `ProtocolVersion` knows `2026-07-28`, `2025-11-25` and `2025-06-18`. Its client offers `ClientLifecycleMode::Discover` (the `server/discover` and per-request `_meta` lifecycle), `Initialize` (legacy) and `Auto`. Its Streamable HTTP server serves 2026-07-28 requests statelessly and optional legacy sessions to older versions. The 2026 profile is therefore served natively, not faked: rmcp is both the pinned client and the pinned fixture server for both profiles.
- **Where rmcp is used.** Only the `tunnel-mcp-fixture` crate uses it: the synthetic server binary (`server` and `transport-io` features) and the end-to-end tests (`client`, `transport-streamable-http-client-unix-socket`, `transport-streamable-http-server`). The relay and the connector do not link rmcp.
- **Why the export bridge is not built on rmcp.** An rmcp proxy would re-type every message. Its typed params, for example `CallToolRequestParams` (fields `_meta`, `name`, `arguments`, `inputResponses`, `requestState`, with no flatten), silently drop unknown fields when they are deserialized and serialized again. That would break the rule above that unknown methods and metadata are not discarded, and it would re-encode request IDs. The device bridge therefore forwards raw JSON-RPC bytes, and rmcp proves interoperability from both ends.
- **Fixtures.** `tunnel-mcp-fixture` is a deterministic synthetic server with the tools `echo` (arguments, `_meta` and an image block), `progress`, `sleep` (records its cancellation), `crash` (writes a stderr marker, exits 3), `stderr_flood` and `big`. It writes only to the test's temporary marker directory. The M3 gates run no other official client or server. The TypeScript SDK, the Python SDK and the conformance suite are pinned and run separately, as test-only dependencies, by M3-17 (see [Off-the-shelf clients (M3-17)](#off-the-shelf-clients-m3-17)).

### Profiles (`tunnel-mcp`)

The two profiles are separate `McpProfile` values with separate tables. There is no shared "MCP" allowlist.

| | `mcp-2026-07-28` | `mcp-2025-11-25` |
| --- | --- | --- |
| `MCP-Protocol-Version` | `2026-07-28` | `2025-11-25` |
| Routes (export path) | `POST /mcp`; `GET` and `DELETE /mcp` are routed only to be answered 405 | `POST /mcp`, `GET /mcp`, `DELETE /mcp` |
| stdio server requirement | implements 2026-07-28 itself over stdio (`server/discover`, per-request `_meta`, no `initialize`); no lifecycle translation; one child per request, so no server state across requests | implements 2025-11-25 over stdio (`initialize` lifecycle); one child per session |
| Request headers | `content-type`, `accept`, `mcp-protocol-version`, `mcp-method`, `mcp-name`, prefix `mcp-param-` | `content-type`, `accept`, `mcp-protocol-version`, `mcp-session-id`, `last-event-id` |
| Response headers | `content-type`, `cache-control`, `x-accel-buffering` | `content-type`, `cache-control`, `x-accel-buffering`, `mcp-session-id` |
| Query | none | none |

- **Header rules.** Every header is a singleton, and each `mcp-param-*` name is a singleton on its own. The prefix rule is a new codec feature (`HeaderPolicy::allow_prefix`): it cannot overlap a forbidden or unsupported name or prefix. The 2026 page requires intermediaries to forward `Mcp-Param-*` headers they do not recognize, so the whole family is allowlisted.
- **Dropped headers (M6-C58).** The public ingress removes `user-agent`, `accept-encoding`, `accept-language` and `sec-fetch-mode` before the codec sees the request, as it removes `authorization` and `cookie` once it has verified them, unless a profile allowlists them (neither MCP profile does). **`cache-control` joined the list in M3-46**: the official Python SDK (mcp 2.2.0) sends `Cache-Control: no-store` on the 2025-11-25 standalone GET stream (httpx2's SSE helper), and refusing it failed that stream for every Python client. A request cache directive has no authority, and nothing on the path caches. Like the rest of the list, it is dropped for every http-forward profile, including `mcp-2026-07-28` and `acp-http-v1`. They are what stock clients add by default: curl and Python `httpx` send the first two, and Node's built-in `fetch` (undici, measured on the wire) sends all four. Refusing them failed a client's first request. Dropping them changes nothing the export can observe: the device always sends `Accept-Encoding: identity` to its backend and `identity` is acceptable to every client, `accept-language` is a negotiation hint no export acts on, and `sec-fetch-mode` is advisory Fetch Metadata. None of them is forwarded. A browser is still refused, because it also sends `origin`.
- **Refused headers.** Everything else is refused before admission, and the ingress's `400 HTTP_INVALID_HEAD` names the first unlisted header in the error body's `header` field (M6-C58). That includes `origin`, since browser-capable endpoints are deferred and the relay has no CORS or cookie profile, and, in 2026, `mcp-session-id` and `last-event-id`. The 2026 page says a server SHOULD ignore the last two. This profile refuses them instead, because a 2026 client never sends them.
- **Limits.** Consumer HTTP/1.1 and HTTP/2 are both accepted. The finite body limits are:

  | Limit | Default | Ceiling |
  | --- | --- | --- |
  | JSON-RPC request | 1 MiB | 16 MiB |
  | `application/json` response (device-enforced) | 8 MiB | 64 MiB |
  | Cumulative `text/event-stream` response | 64 MiB | 1 GiB |

  The codec's response limit is the SSE limit. The device applies the JSON limit by content type, and to each child stdout message.
- **Zero-body rules.** A POST carries one JSON object. GET and DELETE carry no body; a non-empty one is refused with 400. 202 and 204 responses are sent with no body.
- **2026 GET and DELETE.** The specification says a 2026-only server SHOULD answer GET and DELETE with 405. The codec can only refuse an unlisted route as `HTTP_INVALID_HEAD` (400), so the 2026 profile routes GET and DELETE to the device. The device answers 405 with a JSON-RPC error that has no ID, before any backend is involved.

### Dispatch policy (buffer before dispatch)

The device collects the complete request body within its limit and validates it before it invokes any backend. The relay validates only heads; the device validates the body. Validation (`tunnel_mcp::message`) covers:

- `Content-Type: application/json`, otherwise 415;
- an `Accept` that covers both `application/json` and `text/event-stream`, otherwise 406;
- one strict JSON object: duplicate member names (compared after unescaping), invalid UTF-8, lone surrogates, depth above 64 and trailing data are rejected, and batches are refused;
- `"jsonrpc":"2.0"`, and an ID that is a string or an integer.

The profile-specific checks follow.

- **2026-07-28.**
  - `MCP-Protocol-Version` and `Mcp-Method` are required on both requests and notifications. `Mcp-Method` must equal the body `method`.
  - On requests, `MCP-Protocol-Version` must also equal `params._meta["io.modelcontextprotocol/protocolVersion"]`.
  - `Mcp-Name` must equal `params.name` for `tools/call` and `prompts/get`, and `params.uri` for `resources/read`. A Base64 sentinel value is decoded before the comparison.
  - Every `Mcp-Param-*` value must be representable.
  - A failed check gets 400 with `-32020`, or `-32022` plus `data.supported` for another version. A client JSON-RPC response gets 400.
  - `Mcp-Param-*` values are not compared with tool arguments. That needs the tool's `inputSchema`, which only the server holds.
- **2025-11-25.** The version header must be `2025-11-25`, and it is required on every request except `initialize`. It may be absent on GET and DELETE.

Rejections are local JSON-RPC errors with fixed messages. They never echo header or body values.

### Exports (`tunnel-mcp-export`)

**Configuration.** An export is `[exports.<service-id>.mcp]` on a `type = "http-forward"` export in the device runtime file (`tunnel_mcp_export::config`), with `profile`, `backend` and optional `limits`. `tunnel-client connect` registers every configured MCP export as the service's in-process handler. `Debug` prints no argument or environment values.

**Streamable HTTP backend** (`kind = "streamable-http"`). The URL must be `http://<loopback IP literal>:<port>/<canonical path>`: no DNS name, userinfo, query or fragment.

- The `Host`, the path and the optional bearer token come from configuration only. The token file is read once at startup and inserted as `Authorization`; the value is marked sensitive.
- `Accept-Encoding: identity` is always sent. Any other response `Content-Encoding` is a local 502.
- A 3xx is a local 502 and is never followed.
- 401, 403 and 407 are local 502s, so the backend's `WWW-Authenticate` never reaches the consumer.
- Response headers are reduced to the profile table.
- Dropping the response body closes the backend connection. For 2026-07-28 that is the cancellation signal.
- A failure before the request is written is a 502 JSON-RPC error. A failure after it is an interruption (`HTTP_STREAM_INTERRUPTED`, execution `dispatched`), never a fabricated result.

**Stdio backend** (`kind = "stdio"`). The server must implement the selected revision itself; see the profile table. The bridge never translates lifecycles.

- The command and workspace are absolute paths. Arguments are fixed, up to 64 values of up to 4096 bytes each.
- The child environment is cleared first; then explicit values and allowlisted inherited names are set. Nothing runs through a shell.
- `max_children` is 1 to 64, default 8.
- `session_idle_seconds` is 1 to 86400, default 600. It applies to 2025-11-25 sessions only.
- stdout carries newline-delimited JSON-RPC. Each line must be one strict object within the JSON limit; otherwise the child is killed and its exchanges are interrupted.
- stderr is drained, and only its byte count is kept.
- **Process group.** The child runs in its own process group (`process_group(0)`). Every end of its life sends `SIGKILL` to the whole group through `rustix`, so the crate keeps `forbid(unsafe_code)`. That covers a kill on a dropped handle or cancellation, a crash, a normal exit and a session end. A wrapper such as `npx`, `uvx` or a shell script therefore cannot orphan the real server.
  - **Boundary.** A descendant that leaves the group (`setsid`, `setpgid`, or a daemonizing double fork) is not killed. This is **measured, not assumed**: `crates/tunnel-mcp-fixture/tests/process_residue.rs` starts such a descendant by both routes, confirms it really left the group, and reads it back out of the process table alive afterwards.
  - **Ordering.** The group is signalled after the leader is reaped. POSIX does not reuse a process-group ID while any member lives.
- **Parent-death sentinel.** The group kill above only happens on an end of life **the device process lives to see**. A `SIGKILL`, a `process::exit` or a crash runs no `Drop` at all, so nobody signalled the group and even an in-group helper — the `npx` wrapper's real server, the case the group kill exists for — was orphaned and survived. Each child is therefore also watched by a `tunnel-deadman` sentinel: a sibling process, in a process group of its own, holding the read end of a pipe the device holds the write end of. When the device dies for any reason the kernel closes that descriptor, the sentinel wakes on end of file and signals the group. It is stood down only after the child has been killed and reaped, and the stand-down is counted from the sentinel's own exit status rather than from the device having asked. **The sentinel is a separate executable (`tunnel-deadman`) and must be installed alongside the device binary**, or beside it on `PATH` via `TUNNEL_DEADMAN_BIN`. Without it the device supervises children exactly as before and leaks their process groups on every crash, with nothing to distinguish that from correct operation — so a missing sentinel warns once on stderr, and `tunnel-client doctor` reports it as `process_containment: degraded / PROCESS_CONTAINMENT_SENTINEL_MISSING`. It is a degradation, not a refusal to run: it does not change the doctor's exit code.
  - **The group id it signals is pinned (M3-18).** The sentinel joins a *pin* — a copy of `tunnel-deadman` run as `--pin` — to the watched group when it starts and does not reap it until it has decided, so the group always has a member (alive, or an unreaped zombie) and its id cannot be reissued to anything else while the sentinel could still signal it. A sentinel started after the group had already emptied cannot pin it and never signals that id.
  - **What it does not do.** It does **not** widen the group kill's reach. It sends the same group signal from a different process, so a descendant that left the group escapes it exactly as it escapes the device. Reach and trigger are separate holes with separate fixes, and only the trigger is closed here.
- **Not contained, by platform.** A detaching descendant is contained by a kernel boundary or not at all: cgroup v2 (`cgroup.kill`) on Linux, a job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` on Windows, and on **macOS nothing in-process** — short of a sandbox, container or VM, an MCP server that daemonizes leaves processes running after the export ends. macOS is the only host any of this has run on. One further Unix mechanism does close the reach and is none of those three: running each export under a **dedicated uid** and sweeping with a kill-by-uid, which reaches a detached descendant because the kernel's permission check is on the uid and not on the process group. It needs uid provisioning the device does not have, and it is **unusable for M5 specifically**: a computer-use backend has to run inside the user's own GUI session, as the user, so a separate uid is exactly what it cannot have. Operators running a server that detaches must treat its descendants as their own to clean up.
  - **Tracked.** The residue is recorded as M3-09 in [tasks.md](tasks.md), with its ACP sibling at M8-C07.

**2026-07-28 over stdio.**

- **One child per request.** Each POSTed request gets its own child, so IDs, progress and notifications cannot cross between requests or consumers.
- **Response shape.** If the first message is the final response, it is returned as `application/json`. Otherwise the response is SSE: the child's notifications, then the final response, each forwarded as the child's exact line.
- **Protocol violations.** A child request on that stream, or a response for another ID, is a violation: the child is killed and the exchange interrupted.
- **Cancellation.** Closing the response stream makes the bridge write `notifications/cancelled` with the original request ID to the child. It then allows 1 s and kills the child.
- **Client messages.** A client notification gets 202 with no body and is dropped: no per-request child exists to receive it, and this revision defines no client notification over HTTP. A client JSON-RPC response gets 400.
- **Server requirements.** A server implementing only 2025-11-25 cannot be exported under this profile. Because each request gets a fresh process, the server keeps no state across requests.

**2025-11-25 over stdio.**

- **Sessions.** An `initialize` without `Mcp-Session-Id` starts one child and one session. Its random 128-bit ID is returned in `Mcp-Session-Id` only when the result succeeds. A request without the header gets 400; an unknown session gets 404. The session also records the principal binding it was opened with, and every later POST, GET and DELETE must present exactly that value; any other gets the unknown-session 404, byte for byte (M3-04, below).
- **Routing.** A response is routed to its POST by ID. A notification carrying that request's `progressToken` follows the request. Every other server message, including server requests, goes to the one standalone GET stream (a second one gets 409). With no GET stream, such messages wait in a backlog bounded to 64 messages and the JSON limit; an overflow ends the session.
- **Disconnects.** A disconnect is not cancellation. The client's POSTed `notifications/cancelled` is forwarded unchanged.
- **Duplicates.** A request whose ID, or whose `progressToken`, is already in flight on the session gets 400. A reused token is never rebound to another request.
- **Stalled streams.** The session's stdout pump never waits on one stream. When a request's stream queue (64 messages) or the GET stream's queue is full, only that stream is interrupted (`stalled_streams`).
- **Idle expiry.** A session with no POST, no newly opened GET and no request in flight for `session_idle_seconds` ends as if its child had exited.
  - **Effect.** Its streams are interrupted, the process group is killed, the slot is freed and later requests get 404.
  - **Why an open GET does not count.** Holding a GET open is not activity, so an idle client cannot pin a child and its slot with one GET.
- **Session end.** DELETE kills the child (204). A crash ends the session: open streams are interrupted and later requests get 404. The rmcp client then re-initializes, and the crashed call is not replayed.

### Relay (gate 5)

- **Configuration.** `ServeConfig` gains an `[http_forward]` table: `profiles` (only the two identifiers above), plus optional `request_body_bytes`, `response_body_bytes` and `deadline_seconds`.
- **Profile selection.** A catalog service chooses its profile through its Redis service record capability `{"http_forward_profile": "<id>"}`. Both the ingress and the owner select from their own catalog read, after authorization. A service with no capability, or one naming a profile the relay does not serve, gets 404 before normalization, routing or any stream.
- **Harness fixture.** The gate-3/4 harness serves its synthetic test profile under the identifier `fixture-http-forward`, which production configuration cannot name.
- **Fixture hold.** The relay now defines only an `HttpRelayInterposer` hook. The one-shot hold itself lives in `tunnel-test-harness` (`http_relay_hold`), and the `test-fixtures` cargo feature is gone. `serve` builds its exports only from `ServeConfig`, which has no interposer setting, so no relay artifact, workspace-built or not, contains a hold implementation.

### Tests

- **`tunnel-mcp`.** Per-profile route and header acceptance, with neighbouring names, methods, paths, queries and credentials rejected. Every singleton rejects a repeat. The strict JSON scanner is covered, and so are the message rules for both profiles.
- **`tunnel-http-forward`.** The prefix rule and its forbidden-overlap refusals.
- **`tunnel-mcp-export`.** Configuration validation (URL, path, environment and shell refusals) and bounded body collection and streaming.
- **`tunnel-mcp-fixture`.** The pinned rmcp client talks over a Unix-socket gateway through the gate-2 bridge `forward`/`serve` to both export kinds and both profiles.
  - `rmcp_stdio`: discovery or initialize, `_meta` and arguments preserved, image content, ordered progress, a byte-exact 300 KiB result, stream-close cancellation reaching the child as `notifications/cancelled` (2026), a forwarded client cancel (2025), and a crash that is interrupted, not replayed, with stderr not leaked.
  - `rmcp_http`: the same flows against rmcp's own Streamable HTTP server.
  - `session_lifecycle`: idle expiry with an open GET; activity keeps a session alive; a stalled consumer does not block another request on the same session; duplicate progress tokens get 400; a wrapper's grandchild dies with its process group after a completed 2026 request, a crash, or a legacy DELETE.
  - `export_guards`: unlisted headers, routes and versions never spawn a child; 2026 GET and DELETE get 405 and a 2026 notification gets 202; `-32020` and `-32022`; 413; four concurrent requests reusing the ID `9007199254740993` with distinct progress tokens are isolated and byte-exact; an oversized child line is interrupted; 4 MiB of stderr is drained and not forwarded; `max_children` gives 503; legacy session 400, 404, 409 and DELETE; hostile loopback backends (redirect to a metadata address, a 401 challenge, gzip, private response headers) and a closed port.
- **`tunnel-client`.** Configuration parsing, handler registration and `Debug` redaction.
- **`tunnel-relay`.** Profile selection, `[http_forward]` parsing, and no interposer or `test-fixtures` feature.

### Not proven by M3-01/M3-02

- A real cloud-side client through non-owner ingress, the HTTP/3 hop and the rotating tunnel: these end-to-end tests use the in-process gate-2 bridge. That path is covered by the M3-03 gate below.
- Session or consumer isolation bound to the authenticated principal, concurrent consumers through the relay, revocation, lost acknowledgements and unknown tool outcomes across relays. These are now implemented and covered by `verify-m3-mcp-isolation`; see [Pinned in code (M3-04)](#pinned-in-code-m3-04). The M3-01/M3-02 tests themselves run through the in-process bridge with no ingress, so every request there carries no principal binding at all.
- Resources, prompts, subscriptions (`subscriptions/listen`), MRTR input requests, sampling and elicitation. The bridge forwards them as raw messages, but no test exercises them (M3-13).
- Server→client log notifications (`notifications/message`) and per-request cancellation over the real cluster; both are covered by M3-03 below.
- `Last-Event-ID` resume. The stdio bridge emits no event IDs, so a legacy stream cannot resume; an HTTP backend's own resume is forwarded but untested (M3-10).
- Browser `Origin` handling, OAuth protected-resource discovery and audience checks (M3-11). HTTP/2 consumers (M3-12).
- Descendants that leave the child's process group. Now **measured** rather than assumed, and still not contained on macOS: see the process policy above and M3-09. Non-Unix hosts, where both the group kill and the sentinel are absent and the end-to-end tests are `cfg(unix)` (M3-12).
- Throughput and cost of one child per 2026 request with real servers.

## Pinned in code (M3-03)

Recorded 2026-09-16. The harness gate `verify-m3-mcp-cloud-client` (see [testing.md](testing.md#mcp-through-the-real-cluster-verify-m3-mcp-cloud-client)) runs the pinned rmcp 3.4.0 client as a cloud consumer through non-owner ingress (relay-c), the peer HTTP/3 hop, the owner actor (relay-a), the rotating device data WebSocket and `tunnel-client`'s configured MCP exports, against the deterministic `tunnel-mcp-fixture` desktop server.

### Coverage matrix

Every cell was observed in three consecutive standalone runs.

| Behaviour | stdio / 2026-07-28 | stdio / 2025-11-25 | Streamable HTTP / 2026-07-28 | Streamable HTTP / 2025-11-25 |
| --- | --- | --- | --- | --- |
| Discovery | `server/discover` once, no session header | `initialize` once, `Mcp-Session-Id` returned | `server/discover` once | `initialize` once |
| Tool call | `tools/list` once; `echo` arguments, `_meta` and image exact, one invocation | same | same | same |
| Progress notifications | 1..6 in wire order during the call | same | same | same |
| Server→client messages | five `notifications/message` on the call's response stream | five on the standalone GET stream | five on the response stream | five on the standalone GET stream |
| Streaming | 48 × 4 KiB progress events across three rotations, byte-exact, one child | same, one session child | same | same |
| Cancellation | stream close → one bridge `notifications/cancelled`, child group killed, owner `RESET(4005)` | client `notifications/cancelled` forwarded, child group killed at session end | backend connection dropped, backend observed the cancellation, owner `RESET(4005)` or device FIN | client `notifications/cancelled` forwarded |
| Backend crash mid-call | interruption, one invocation, fresh child for the next call | interruption, session ended, 404 then one re-initialization | interruption, restarted backend serves the next call | interruption, 404 then one re-initialization |
| Rotation during discovery and invocation | held `tools/list` and held call each observed dispatched-and-unanswered at a rotation, one dispatch | same | same | same |

### What the gate pins

- **The client is the official SDK.** rmcp 3.4.0's `StreamableHttpClientTransport` drives the lifecycle; the harness only decorates rmcp's own Unix-socket HTTP client with a payload-free ledger (POSTs by method, responses by call, session headers, standalone streams, log and progress order) and puts a byte-copying TLS sidecar in front of it, because rmcp has no TLS client without `reqwest` and the workspace pins none.
- **The device is configured as production configures it.** The gate writes `[exports.<service>.mcp]` tables into the connector's runtime file, parses them with `RuntimeConfig`, and registers them with `HttpHandlers::with_mcp_exports`, as `tunnel-client connect` does. The relays build their profile set from a `ServeConfig [http_forward]` table, and each catalog service selects one through `http_forward_profile`.
- **Ordering evidence is the wire, not the client handler.** rmcp may run a client's notification handlers concurrently; one run delivered log seq 4 before 3 to the handler while the wire order was intact. Progress and log ordering are therefore compared on the transport (a SHA-256 over the messages in arrival order for the 48-event stream), and the handler proves only the multiset.
- **One device session per combination.** Stream IDs restart with a session and the owner's bounded diagnostics outlive one, so every record is matched by operation ID as well. This started as the workaround for the 128-stream session ceiling (M7-C82 in [tasks.md](tasks.md)); that ceiling is fixed, and the arrangement is kept only to isolate each combination's stream IDs and export children.
- **Rotation freezes hold new requests (M3-15).** The owner holds a POST or standalone GET that lands between QUIESCE and COMMIT and admits it after the commit, so rmcp, which does not retry a `503`, sees nothing. The gate resends a POST only when the relay itself answers `503 ROTATION_FREEZE` `not_dispatched`, meaning a freeze outlasted the 1.5 s hold or the hold was full, and at most 12 times (the handshake budget at the relay's 250 ms hint, plus four). The owner-not-ready body now answers only fault states and fails its call. A standalone GET's refusal carries no body for rmcp to show, so it is still resent only while the gate's own watch on the connector's rotation phase says a rotation is frozen (or within 750 ms of one). A GET refused outside that window fails the call and records the connector's phase and rotation count. Each case's refusals and resends are printed and must be equal and bounded. The owner relay's `rotation_freeze_hold` counters (held, admitted after the hold, refused after the bound, the longest wait) are printed with the run. Before M3-15 the gate resent the owner-not-ready body inside an observed freeze instead.
- **A session's streams are scoped to its combination.** Each combination runs on its own session, and the validator requires its highest call stream ID to stay under 128 and no export child to survive the session's stop. The stream-ID rule is now an invariant of that scoping, not evidence about a product ceiling: a connector session releases an OPEN journal entry at the [OPEN retry horizon](protocol.md#open-retry-horizon-and-journal-reclamation) and serves an unbounded number of sequential streams, proven by 160 sequential streams on one session in `verify-m3-http-forward-real-path`, and by a one-off re-run of this gate with `connect_device` hoisted out of the combination loop, where a single session served all four combinations and all 28 cases to call stream ID 141 (M7-C82).

### Not proven by M3-03

- Session or consumer isolation bound to the authenticated principal, concurrent consumers with colliding JSON-RPC IDs, lost acknowledgements and revocation: covered by `verify-m3-mcp-isolation`, not by this gate. See [Pinned in code (M3-04)](#pinned-in-code-m3-04).
- Sampling (`sampling/createMessage`), elicitation, MRTR input requests and `subscriptions/listen`; resources and prompts (M3-13). The bridge forwards them as raw messages and rmcp can express some of them, but no case exercises them.
- `Last-Event-ID` resume of an interrupted stream (M3-10). The 2025 Streamable HTTP backend's own event IDs make rmcp attempt a resume after a crash; the gate bounds those attempts rather than proving resume.
- A process-group kill for a Streamable HTTP backend: the device does not own that process. The gate restarts it as an operator's supervisor would.
- HTTP/2 consumers, browser `Origin` handling and the MCP authorization profile (M3-11, M3-12).
- ~~An ingress exchange record for a consumer that disconnects before any response head (M3-14).~~ Closed on branch `m3-features`: the ingress now records it with `HTTP_CANCELLED`, and the cancellation case requires that whenever the owner recorded `RESET(4005)`.


## Pinned in code (M3-04)

Recorded 2026-09-16. The harness gate `verify-m3-mcp-isolation` (see
[testing.md](testing.md#mcp-isolation-correlation-and-unknown-outcomes-verify-m3-mcp-isolation))
runs two distinct authenticated principals of one tenant, plus a third whose
grant is revoked, as raw-HTTP cloud consumers through non-owner ingress
(relay-c), the peer HTTP/3 hop, the owner actor (relay-a), the rotating device
data WebSocket and `tunnel-client`'s configured MCP exports, against the
deterministic `tunnel-mcp-fixture` desktop server.

### The principal binding

The device sees no principal, and it never will: nothing about the consumer's
identity belongs in a device-visible header. A 2025-11-25 session ID was
therefore unguessable but not scoped — any authorized consumer of the same
export who learned one could use it. The binding closes that without telling
the device who anyone is.

- **The ingress derives it.** After it strips the public credentials and
  before it normalizes anything, the relay ingress derives
  `tunnel-principal-binding`: a SHA-256 digest over a versioned domain
  separator and the tenant, principal, device and service identifiers,
  truncated to 128 bits and hex encoded
  (`tunnel_relay::http::forward::principal_binding`).
- **The owner re-derives it and never adopts it.** The ingress is not trusted
  with it. The owner re-authenticates the consumer's forwarded token and
  authorizes the grant for itself, so it holds the same four identifiers
  independently; it derives the binding from *those* and compares it with the
  relayed head, resetting the exchange with `HTTP_INVALID_HEAD`
  `not_dispatched` on a mismatch or on an absent binding, before a byte
  reaches the device (`OwnerRequestWriter`, `http/forward/owner_relay.rs`).
  This matters precisely because the digest is unkeyed over catalog
  identifiers: a compromised or buggy ingress holding one principal's token
  could otherwise compute another principal's binding and land its requests on
  that principal's session. The ingress is the only endpoint that *derives the
  value a consumer's request will carry*; it is not the only endpoint that
  checks it.
- **It carries no identity.** The value is one way, and it is scoped to one
  device and one service, so the same principal presents unrelated values on
  unrelated exports and the device learns only "the same consumer as before".
- **It is stable across relays.** Every relay derives the same value from the
  same catalog facts, so a session opened through one ingress is usable
  through another. It is deliberately not keyed: a shared cluster secret would
  add a distribution problem without adding security, because the value's
  integrity comes from the next point, not from secrecy.
- **A consumer can never supply it.** An ingress request that carries the
  header at all is refused with `400 HTTP_INVALID_HEAD` `not_dispatched`
  before anything is forwarded, and counted as an ingress rejection. The
  value is never taken from the request and never merely overwritten, so a
  forged binding can neither reach a device nor be confused with a derived
  one. Header names are lowercased by the HTTP parser, so one predicate
  (`refuse_consumer_principal_binding`) covers every spelling, and a repeated
  header is refused like a single one. The gate case `binding-forgery` drives
  this through the real route on both profiles and all three methods.
- **Only the session profile carries it.** It is in the `mcp-2025-11-25`
  request allowlist and nowhere else: the sessionless `mcp-2026-07-28` profile
  refuses it like any other unlisted header, and no profile allows it on a
  response. It is a singleton, like every other header in these profiles.
- **Both export kinds enforce it.** A stdio session records the binding it was
  opened with; POST, GET and DELETE all require exactly that value. The
  Streamable HTTP export does not own the backend's session identifiers, so it
  records which binding each backend-issued session was handed to and refuses
  every other principal — and every session it did not see issued — before the
  backend is dialled. Only the exchange that opened a session binds it, so a
  backend that echoes a different identifier on a later request cannot bind
  that identifier to the caller. The binding is never forwarded upstream.
  - **Capacity is refused, never taken from somebody else.** The table holds
    `MAX_TRACKED_SESSIONS` (256) sessions and at most `MAX_SESSIONS_PER_BINDING`
    (32) per principal. A principal at either bound is refused a new
    `initialize` with `503` *before the backend is dialled* (and the refusal is
    counted in the export's `rejected`), so the backend never creates a
    session this export could not track. An earlier revision evicted the
    oldest entry instead, which was a cross-principal denial channel: any
    authorized principal could drop every other principal's live session —
    forcing a re-initialization and losing its subscription state — by opening
    257 sessions.
  - **Entries expire.** An entry leaves when its own session does — a
    successful DELETE, or a backend that answers 404 for it — or when it has
    gone unused for the export's `session_idle_seconds` (default 600, the same
    setting and bounds the stdio backend has). Without the expiry a client
    that crashed and restarted without a DELETE leaked one slot per restart:
    after 32 restarts that principal was refused every `initialize` until the
    device process restarted, and 256 abandoned sessions would have locked the
    export for everyone. Expiry fails closed — a forgotten session is answered
    404 and its own holder re-initializes; no other principal is affected —
    and it is per entry, so a session in use is never forgotten.
- **A mismatch is an unknown session.** The same status, code and message,
  byte for byte, so a leaked ID proves nothing about whether the session
  exists.
- **Without an ingress there is no principal.** The in-process bridge used by
  the export tests supplies no binding, so sessions there are bound to "no
  principal" and still refuse any other value. That is the only configuration
  in which the binding is absent.
- **A session does not outlive the export that served it.** A legacy session
  is pumped by a detached task that owns the child process and its
  `max_children` permit, so ending the export has to end the sessions
  explicitly. Dropping an `McpExport`, calling `McpExport::shutdown`, or
  dropping the connector's `HttpHandlers` registry ends every open session and
  kills each session child's process group, whether or not anyone sent a
  DELETE.

### What the gate pins

- Two principals, each with its own token and grant on the same device and
  service: one's session ID is refused for the other on POST, GET and DELETE
  with byte-identical answers to an unknown session; both sessions keep
  working; and each principal's standalone GET stream carries only its own
  server notifications.
- Twenty-four concurrent calls whose JSON-RPC IDs and progress tokens collide
  deliberately across sessions and principals, in both profiles, each answered
  to its own caller with exact results; a genuine duplicate on one session is
  refused with 400.
- Revocation of a consumer grant: refused in about 10 ms with
  `404 SERVICE_NOT_FOUND` `not_dispatched`, the admitted exchange withdrawn in
  about 500 ms with `502 HTTP_STREAM_INTERRUPTED` and `execution: unknown`,
  nothing dispatched afterwards, and the other principals and the device
  session untouched.
- One call held across three completed scheduled rotations, answered exactly
  once with exact bytes and one dispatch.
- A lost acknowledgement and owner process loss, each after the fixture has
  recorded its synthetic side effect: `outcome_unknown` at the consumer, the
  side effect recorded exactly once, nothing replayed.

### Proven by M3-04 over the real cluster

The cluster gate `verify-m3-mcp-isolation` drives **both** export kinds. The
stdio exports carry the `session-isolation` case; the Streamable HTTP export
carries `streamable-binding`, which is what separates the binding from process
isolation — one backend process and one session table serve every principal
there, so a foreign session ID that is refused is refused by the binding and
by nothing else. A consumer authorized in **another tenant** is driven by the
`cross-tenant` case against this tenant's device, session and service, and is
refused before dispatch on every route, indistinguishably from one naming a
session that never existed.

### Not proven by M3-04

- **Server→client JSON-RPC requests.** The pinned fixture issues none, so
  colliding *server→client* request IDs are unproven. What is proven in that
  direction is colliding progress tokens and server notifications (M3-13).
  Sampling (`sampling/createMessage`), elicitation, MRTR input requests and
  `subscriptions/listen` are likewise unexercised.
- Browser `Origin` handling, OAuth protected-resource discovery and audience
  checks at the export (M3-11).
- `Last-Event-ID` resume of an interrupted legacy stream (M3-10).
- **Concurrent colliding request IDs through one shared backend process.** The
  cluster gate's `streamable-binding` case now drives the Streamable HTTP
  export, where every session shares one backend, for *session* separation;
  but the colliding JSON-RPC IDs and progress tokens of the `correlation` case
  still run on the stdio exports only, where each session has its own child.
  So shared-process *correlation* remains unproven here (M3-13).
- ~~**Ending a device-side session on revocation.**~~ Closed by M3-16 on
  branch `feat-mcp-demo` (applied by default pending owner confirmation,
  2026-09-25): see [Revocation ends the session (M3-16)](#revocation-ends-the-session-m3-16).
  The gate's `revocation` case now also requires the revoked principal's
  device-side session to end within 5 s.

## Off-the-shelf clients (M3-17)

Recorded 2026-09-26. `scripts/m3-sdk-conformance.sh` runs the MCP clients a demo audience would actually use against device-exported servers, through real local relays. The route is `tunnel-relay serve` and `tunnel-client connect`, configured from the shipped examples, with a bearer token from a synthetic issuer. The recipe is [demo/mcp-sdk-conformance.md](demo/mcp-sdk-conformance.md).

### Pins (test-only)

These pins live in `tests/mcp-sdk-conformance` and are never a runtime dependency.

| Artifact | Version | How it is pinned |
| --- | --- | --- |
| Official TypeScript SDK `@modelcontextprotocol/sdk` | 1.30.1 (latest protocol `2025-11-25`) | exact version, `package-lock.json` integrity hashes |
| Official Python SDK `mcp` | 2.2.0 (handshake revisions through `2025-11-25`, plus `2026-07-28`) | `python/requirements.txt`, compiled with `uv pip compile --universal --generate-hashes`, installed with `--require-hashes` |
| Official conformance suite `@modelcontextprotocol/conformance` | 0.2.0-alpha.11 (gitHead `c321dd32…`) | exact version, lockfile |
| The suite's reference server `examples/servers/typescript/everything-server.ts` | at `c321dd32035556e6769d3724a8ee97d87c3faaac` | fetched and checked against its SHA-256 on every run; run under `tsx` 4.23.15 |

The device exports three `mcp-2025-11-25` services, each on its own relay and namespace:

- the **reference server** (Streamable HTTP backend on loopback);
- **`ts-sdk-server.mjs`**, a plain `McpServer` on the pinned TypeScript SDK that uses the reference server's tool, resource and prompt names;
- the **rmcp fixture** over stdio.

### What passes through the relay

| Case | TypeScript SDK | Python SDK (`legacy` and `auto`) |
| --- | --- | --- |
| `initialize`, `Mcp-Session-Id`, protocol `2025-11-25` | reference, SDK server, fixture | SDK server, fixture (not the reference server: M3-47) |
| `tools/list`, `tools/call` (text, image, `isError`) | reference, SDK server | SDK server |
| `tools/call` arguments and `_meta` preserved, image block | fixture | fixture |
| `resources/list`, `resources/read` (text and blob) | reference, SDK server | SDK server |
| `prompts/list`, `prompts/get` (with arguments) | reference, SDK server | SDK server |
| Streamed `notifications/progress`, in order | reference, SDK server, fixture | SDK server, fixture |
| Streamed `notifications/message` after `logging/setLevel` | reference, SDK server | SDK server |
| Cancellation: an abort **after** the fixture logged the call reaches the device's server (`cancelled-<label>` marker), and the session stays usable | fixture | fixture (the close after it can meet M3-48) |
| Session `DELETE` | all | all |

The **conformance suite** (`server --spec-version 2025-11-25`) passes **31 of 31 scenarios (73 checks)** directly against the reference server. Through the relay it passes **30 of 31**. The exception is `dns-rebinding-protection` (M3-49). That scenario covers only unauthenticated plain-HTTP localhost servers. Its raw request path cannot carry the bearer token, and it sends `Host: evil.example.com` as the TLS server name. The relay's own answer to a rebinding request is checked instead: a request that carries `Origin` gets `400 HTTP_INVALID_HEAD` with `header: origin`. The suite carries no credential option, so a Node `--import` preload (`preload.mjs`) adds the bearer to `fetch` calls for the relay's origin only.

### Incompatibilities found

| Row | What | Where |
| --- | --- | --- |
| M3-46 | The relay refused the Python SDK's `Cache-Control: no-store` on the standalone GET stream. | relay; **fixed** by dropping `cache-control` at the ingress, for every http-forward profile (`mcp-2025-11-25`, `mcp-2026-07-28`, `acp-http-v1`) |
| M3-47 | The reference server refuses the Python SDK's `initialize` with `-32020 Missing MCP-Protocol-Version header`. The SDK sends `_meta: {}`, which that server reads as a 2026 request. Reproduced directly, without the relay. | upstream (conformance reference server); the harness checks that the relay forwards the refusal unchanged |
| M3-48 | After a forwarded `notifications/cancelled`, the stdio export holds the cancelled request's POST open. It answers `502` only when the session is deleted, and the Python SDK then raises `ClosedResourceError` from `Client.__aexit__`. rmcp's own Streamable HTTP server answers such a POST at once with an empty event stream. | device bridge (stdio, 2025-11-25); open |
| M3-49 | The conformance suite's `dns-rebinding-protection` scenario cannot run through the relay. | suite scope; the relay refuses `Origin` instead |

Also observed, but not recorded as rows:

- In its default `auto` mode, the Python SDK first probes `server/discover` with the 2026 headers. The `mcp-2025-11-25` profile answers `400 HTTP_INVALID_HEAD` (`header: mcp-method`), and the SDK falls back to `initialize`. That costs one extra round trip and works.
- Python 3.13 and later verify certificates with `VERIFY_X509_STRICT` and refuse a CA without `keyUsage`, which a bare `openssl req -x509` produces. The harness's synthetic CAs carry `keyUsage`.

### Not proven by M3-17

- The `mcp-2026-07-28` profile with a non-Rust SDK. The TypeScript SDK 1.30.1 does not speak it, and the Python SDK's 2026 mode is not run here.
- Rotation, crash and isolation with these SDKs. Those stay proven with rmcp by the M3 gates.
- Sampling, elicitation and other server-to-client requests through an SDK client. The conformance suite drives the reference server's `tools-call-sampling` and `tools-call-elicitation` through the relay, and both pass. No SDK client case does.
- Hosted CI beyond one run. The script runs in the `m3-acceptance` job; hosted run 36197864485 passed it (76 SDK cases, conformance 30/31 through the relay) at `2242b33`.

## The demo path, discovery and revocation (branch `feat-mcp-demo`)

Recorded 2026-09-26. [docs/demo/mcp.md](demo/mcp.md) is the runnable recipe.

### Demo (M3-39)

`scripts/demo-mcp.sh` brings up one relay and one device from the shipped
binaries and examples. It uses a throwaway PKI and identity issuer and its
own TLS Redis. It exports `tunnel-mcp-fixture` over stdio, and drives it
through the relay's public route with the pinned rmcp 3.4.0 client
(`tunnel-test-harness mcp-demo-client`). The client covers discovery,
lifecycle, tools (text and image), resources (text and blob), prompts, a
subscription and its update, and progress and log notifications. Both
profiles pass. The client is the harness binary, not a shipped one, and no
hosted agent has been connected (M3-40).

### Fixture additions (part of M3-13)

`tunnel-mcp-fixture` now advertises `resources` (with `subscribe`) and
`prompts`:

- two resources: `fixture://synthetic/readme.txt` (text) and
  `fixture://synthetic/pixel.png` (blob);
- one prompt: `greet`, with a required `name`;
- a `touch` tool, which sends `notifications/resources/updated` to a
  2025-11-25 subscriber;
- a 2026-07-28 `subscriptions/listen` handler, which reports each accepted
  URI once and then ends the subscription cleanly.

Only the stdio export, driven by the demo client, exercises these. Sampling,
elicitation and MRTR input requests are still unexercised, and so is the
Streamable HTTP export (M3-13 stays open).

### Protected-resource discovery (M3-11)

The consumer listener serves RFC 9728 metadata at
`GET /.well-known/oauth-protected-resource/v1/devices/{device}/services/{service}/http/{path}`.
The metadata holds:

- `resource`: the endpoint URL;
- `authorization_servers`: the relay's `oidc_issuer`;
- `scopes_supported`: `http:invoke`, plus any scope every token must carry;
- `bearer_methods_supported`: `["header"]`.

**Set `public_url` in production.** Without it, the resource origin comes from the request's own `Host` or `:authority`. That is correct only when clients reach the relay directly at the name they use. Behind a proxy or load balancer that rewrites the authority, the metadata would name the wrong resource, and clients would refuse it.

The route is unauthenticated. It serves the same document for any
well-formed device and service, so it does not reveal whether a device,
service or grant exists. The host in `resource` comes from
`[http_forward] public_url` (`https://host[:port]`) when that is set.
Otherwise it comes from the request's own authority.

Every credential refusal on an `http-forward` route carries a
`WWW-Authenticate: Bearer` challenge with `resource_metadata` and `scope`.
The `scope` is the same set as `scopes_supported`, space-separated:

- A request with no token gets no `error` parameter.
- A token refused for its signature, claims, key or identity gets
  `error="invalid_token"`.
- A token without the route's scope gets `403` with
  `error="insufficient_scope"`.

A `503` for the relay's own fault, and a refusal for a missing grant, carry
no challenge.

Token validation itself is unchanged: issuer, audience, signature, expiry,
scope, catalog identity and grant, on the ingress and again on the owner.
Audiences are still the configured `oidc_audience` list. An issuer that puts
the RFC 8707 `resource` value into `aud` therefore needs that URL listed
there (M3-42). Browser `Origin` is still refused on both profiles.

Evidence:

- `http::mcp_authorization_tests`, over the real consumer router;
- `http::forward::authorization::tests`;
- the demo, whose client performs the discovery before any MCP traffic.

### Revocation ends the session (M3-16)

This is option (c) from the row, applied by default pending owner
confirmation (2026-09-25).

The owner relay watches each consumer it admits to a session-keyed export
(it sends the message only to connectors that advertised
`principal-sessions-end-v1`; see [protocol.md](protocol.md#control-messages)
for that gate, the read cap and jitter, and the refusal of held requests):
the `mcp-2025-11-25` profile, the only one that carries the principal
binding. It keeps at most 64 per device session and re-reads each one's grant
about once a second. When the grant is revoked or expired, or no longer
allows `http:invoke`, the owner sends the device `PRINCIPAL_SESSIONS_END`
(see [protocol.md](protocol.md#control-messages)), naming the service and the
opaque binding.

The connector then ends that binding's sessions on that export:

- a stdio session is removed and its child's process group killed, as a
  `DELETE` would;
- a Streamable HTTP export forgets the backend sessions it bound to that
  binding.

Other principals' sessions are untouched, and the device still learns no
identity. The export counts these in `sessions_revoked`.

Evidence:

- `principal_binding` tests in `tunnel-mcp-fixture`, for both export kinds;
- the protocol codec tests;
- `verify-m3-mcp-isolation`'s `revocation` case, which requires the device
  session to end within 5 s.

Residuals are in M3-41:

- the message is not journaled, so one lost with its control socket leaves
  the sessions to idle expiry;
- a request already in flight at revocation is withdrawn by the relay with
  `502 HTTP_STREAM_INTERRUPTED`, `execution: unknown`. That outcome is
  truthful but not revocation-specific (M3-44);
- no upstream `DELETE` is sent to a Streamable HTTP backend;
- M5-C05 does not use the message yet.

