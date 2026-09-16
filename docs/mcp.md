# MCP adapter plan

Status: M3-01 (pins), M3-02 (device exports over `http-forward/1`) and M3-03 (a real cloud-side client across relays and rotations) are implemented, awaiting verification, 2026-09-16; see [Pinned in code](#pinned-in-code-m3-01-and-m3-02) and [Pinned in code (M3-03)](#pinned-in-code-m3-03). M3-04 (isolation, correlation and unknown outcomes) is not implemented. MCP compatibility is separate from the tunnel wire protocol. The tunnel's control and data WebSockets do not require an external MCP client to support a custom transport.

## Two explicit compatibility profiles

The current upstream specification is **2026-07-28**. It changes HTTP transport and discovery behavior compared with 2025-11-25. The official Rust SDK documents support for both. Build profile-specific tests instead of mixing lifecycle rules. References are pinned in [sources.md](sources.md).

| Concern | 2026-07-28 target | 2025-11-25 compatibility target |
| --- | --- | --- |
| Startup | Discovery/negotiation with per-request metadata | `initialize` and `notifications/initialized` lifecycle |
| HTTP | POST with JSON or request-scoped SSE response | POST plus optional GET SSE stream |
| Protocol sessions | No protocol-level session IDs | Scope MCP session IDs to authenticated principal/device/service |
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
- **Fixtures.** `tunnel-mcp-fixture` is a deterministic synthetic server with the tools `echo` (arguments, `_meta` and an image block), `progress`, `sleep` (records its cancellation), `crash` (writes a stderr marker, exits 3), `stderr_flood` and `big`. It writes only to the test's temporary marker directory. No other official client or server artifact, such as the TypeScript SDK or the MCP conformance suite, is pinned or run. That is M3-03 work.

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
- **Refused headers.** Everything else is refused before admission. That includes `origin`, since browser-capable endpoints are deferred and the relay has no CORS or cookie profile, plus `user-agent`, `accept-encoding` and, in 2026, `mcp-session-id` and `last-event-id`. The 2026 page says a server SHOULD ignore the last two. This profile refuses them instead, because a 2026 client never sends them.
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
  - **Boundary.** A descendant that leaves the group (`setsid`, `setpgid`, or a daemonizing double fork) is not killed.
  - **Ordering.** The group is signalled after the leader is reaped. POSIX does not reuse a process-group ID while any member lives.
  - **Tracked.** The residue is recorded as M3-09 in [tasks.md](tasks.md).

**2026-07-28 over stdio.**

- **One child per request.** Each POSTed request gets its own child, so IDs, progress and notifications cannot cross between requests or consumers.
- **Response shape.** If the first message is the final response, it is returned as `application/json`. Otherwise the response is SSE: the child's notifications, then the final response, each forwarded as the child's exact line.
- **Protocol violations.** A child request on that stream, or a response for another ID, is a violation: the child is killed and the exchange interrupted.
- **Cancellation.** Closing the response stream makes the bridge write `notifications/cancelled` with the original request ID to the child. It then allows 1 s and kills the child.
- **Client messages.** A client notification gets 202 with no body and is dropped: no per-request child exists to receive it, and this revision defines no client notification over HTTP. A client JSON-RPC response gets 400.
- **Server requirements.** A server implementing only 2025-11-25 cannot be exported under this profile. Because each request gets a fresh process, the server keeps no state across requests.

**2025-11-25 over stdio.**

- **Sessions.** An `initialize` without `Mcp-Session-Id` starts one child and one session. Its random 128-bit ID is returned in `Mcp-Session-Id` only when the result succeeds. A request without the header gets 400; an unknown session gets 404.
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
- Session or consumer isolation bound to the authenticated principal (M3-04 acceptance). The device cannot see the principal, so legacy session IDs are unguessable but not principal-scoped (M3-04).
- Concurrent consumers through the relay, revocation, lost acknowledgements and unknown tool outcomes across relays (M3-04).
- Resources, prompts, subscriptions (`subscriptions/listen`), MRTR input requests, sampling and elicitation. The bridge forwards them as raw messages, but no test exercises them (M3-13).
- Server→client log notifications (`notifications/message`) and per-request cancellation over the real cluster; both are covered by M3-03 below.
- `Last-Event-ID` resume. The stdio bridge emits no event IDs, so a legacy stream cannot resume; an HTTP backend's own resume is forwarded but untested (M3-10).
- Browser `Origin` handling, OAuth protected-resource discovery and audience checks (M3-11). HTTP/2 consumers (M3-12).
- Descendants that leave the child's process group (M3-09). Non-Unix hosts, where the group kill is absent and the end-to-end tests are `cfg(unix)` (M3-12).
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
- **One device session per combination.** Stream IDs restart with a session and the owner's bounded diagnostics outlive one, so every record is matched by operation ID as well. A session is also limited to 128 streams for its lifetime (M7-C82 in [tasks.md](tasks.md)).
- **Rotation freezes refuse new requests.** The relay pauses stream admission from QUIESCE to COMMIT, so a POST can be refused with a retryable `503 PEER_UNAVAILABLE` `not_dispatched`, and rmcp does not retry it. That body is the relay's answer to every owner-not-ready condition, not only a freeze, so the gate resends a refusal only while its own watch on the connector's rotation phase says a rotation is frozen (or within 750 ms of one). The cap is derived from the rotation policy (the handshake budget at the relay's 250 ms hint, plus four; 12 here), so a slow drain cannot fail a call. A refusal outside a freeze fails the call and records the connector's phase and rotation count as its cause, because the owner freezes before the connector sees `ROTATE_QUIESCE`. Each case's POST and standalone-GET refusals and retries are printed and must be equal and bounded, with no unexplained refusal (M3-15).
- **A device session is limited.** Each combination runs on its own session and the validator requires its highest call stream ID to stay under 128 and no export child to survive the session's stop (M7-C82).

### Not proven by M3-03

- Session or consumer isolation bound to the authenticated principal, concurrent consumers with colliding JSON-RPC IDs, lost acknowledgements and revocation (M3-04).
- Sampling (`sampling/createMessage`), elicitation, MRTR input requests and `subscriptions/listen`; resources and prompts (M3-13). The bridge forwards them as raw messages and rmcp can express some of them, but no case exercises them.
- `Last-Event-ID` resume of an interrupted stream (M3-10). The 2025 Streamable HTTP backend's own event IDs make rmcp attempt a resume after a crash; the gate bounds those attempts rather than proving resume.
- A process-group kill for a Streamable HTTP backend: the device does not own that process. The gate restarts it as an operator's supervisor would.
- HTTP/2 consumers, browser `Origin` handling and the MCP authorization profile (M3-11, M3-12).
- An ingress exchange record for a consumer that disconnects before any response head (M3-14): the owner records the cancellation, the ingress records nothing.

