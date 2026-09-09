# Bounded HTTP forwarding over a logical tunnel stream

Status: proposed implementation contract, 2026-09-09. The codec and bridge are not implemented. This document defines **`http-forward/1`**, an internal Agent Tunnel encoding; it is not a new public HTTP or ACP standard.

The intended route is **cloud agent → Agent Tunnel's Axum API → optional owner HTTP/3 hop → existing device data WebSocket → desktop adapter**. Responses follow the reverse route. The desktop adapter can be an in-process ACP HTTP-to-stdio service, an MCP bridge, or a typed CUA HTTP facade. The client CLI opens the device connections; no public inbound desktop port is required.

Read [runtime.md](runtime.md), [cluster.md](cluster.md), and [protocol.md](protocol.md) for authentication, owner fencing, admission, outer frames, credits, and socket rotation. This encoding preserves HTTP request/response structure; adapter documents retain authority over their application lifecycles and permissions.

## One exchange, one stream

An authorized `OPEN` selects a fixed device export, its application compatibility profile, and `http-forward/1`. The accepted context binds tenant, principal, device, service, owner token, grant version, operation/request IDs, deadline, and negotiated byte limits. These authoritative fields are outside the HTTP heads. The caller cannot override them with HTTP headers, JSON fields, paths, or an embedded URL.

One admitted logical stream contains exactly one HTTP request in the owner→device direction and one HTTP response in the device→owner direction. A second HTTP request needs a new stream. A long-lived SSE GET keeps its stream; concurrent ACP POSTs get separate streams bound to the same independently authorized ACP connection. There is no HTTP pipelining or request multiplexing inside one logical stream.

The owner and device run this codec after the outer protocol has ordered and deduplicated DATA payloads. Bytes from successive DATA frames form a continuous byte stream in each direction. Record headers/payloads may cross DATA frames, and one DATA frame may contain several records. Outer WebSocket, HTTP/3, and DATA boundaries never define HTTP body or JSON-RPC message boundaries.

The cluster peer route wraps these records in its independently authenticated admission envelope. It preserves ordered request/response bodies and uses no new HTTP/3 route or arbitrary destination. An owner remains the sole authority for tunnel sequences. Consumer credentials may reach the owner for independent verification as specified in the cluster contract; they never appear in the device's HTTP heads.

## Exact v1 record encoding

Each record begins with this fixed eight-byte header. Integers use unsigned network byte order. `payload_length` excludes the eight-byte header.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 1 | Record kind |
| 1 | 1 | Flags, exactly zero in v1 |
| 2 | 2 | Reserved, exactly zero |
| 4 | 4 | Payload length |
| 8 | Declared length | Payload |

| Kind byte | Name | Payload |
| --- | --- | --- |
| `0x01` | `REQUEST_HEAD` | Bounded UTF-8 JSON request head |
| `0x02` | `RESPONSE_HEAD` | Bounded UTF-8 JSON response head |
| `0x03` | `BODY` | 1–65,528 raw body octets; no base64 or JSON escaping |
| `0x04` | `END` | Exactly zero bytes |

The maximum complete record is 65,536 bytes, fitting the default DATA payload ceiling when unsplit. HEAD payloads have the smaller 16 KiB cap below. Reject unknown kinds, nonzero flags/reserved bytes, invalid kind-specific lengths, and allocation overflow immediately after reading the fixed header. The selected application encoding supplies the version; no redundant magic, stream ID, or application sequence number is added inside each record.

For example, the BODY record containing ASCII `hello` is:

```text
03 00 00 00 00 00 00 05 68 65 6c 6c 6f
```

The END record is always:

```text
04 00 00 00 00 00 00 00
```

The incremental decoder retains at most one unfinished eight-byte record header, one bounded HEAD, or one bounded BODY fragment. It must stream BODY fragments into credited downstream buffers; it must not collect the entire HTTP body before emitting it. Partial records have a fixed completion deadline and share the stream's queue/byte budget.

### Request head schema

All fields below are required; there are no additional fields in v1:

```json
{
  "method": "POST",
  "path": "/acp",
  "query": "",
  "http_version": "2",
  "headers": [
    ["content-type", "application/json"],
    ["accept", "application/json, text/event-stream"],
    ["acp-connection-id", "connection-demo"],
    ["acp-session-id", "session-demo"]
  ],
  "body_length": null
}
```

`method` is one of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, or `OPTIONS`, restricted further by the selected route; `path` is a canonical path within the selected local service; `query` is the validated query component without `?`; `http_version` is the accepted consumer HTTP version (`"1.1"` or `"2"`), not the peer protocol. The ingress derives that version from its HTTP connection. ACP's HTTP/2 requirement is checked before admission and again against the selected profile.

`headers` is an ordered array of exactly two-string arrays, preserving separately allowed repeated field values. `body_length` is either `null` for an unknown streaming length or a canonical unsigned decimal string (`"0"` or a nonzero first digit followed by decimal digits), at most `u64::MAX`. No signs, leading zeros, floating point, or JSON-number coercion. Every request also has a finite configured cumulative body limit regardless of this field.

### Response head schema

All fields are required, with no additional fields:

```json
{
  "status": 200,
  "headers": [["content-type", "text/event-stream"], ["cache-control", "no-store"]],
  "body_length": null
}
```

`status` is an integer from 200 through 599. There is exactly one final response head. No reason phrase, raw status line, or informational 1xx record is carried. The ingress handles `Expect: 100-continue` locally after authorization/admission; backend 100/103 responses are consumed locally. A 101 upgrade, CONNECT, or protocol switch is unsupported by this profile and must fail before establishing a different tunnel.

`body_length` describes **actual response body bytes**, not a selected representation's hypothetical size. Responses to HEAD and status 204, 205, or 304 require `"0"`, no BODY, and END. Omit forwarded Content-Length metadata for these responses in v1; applications requiring its representation-size hint need an explicit extension. Ordinary response lengths follow the request head's decimal-string rules.

JSON heads must be one object, contain valid UTF-8, and reject duplicate keys, unknown keys, invalid types, and trailing non-whitespace data. Require valid Unicode scalar values when decoding escapes. Do not rely on a deserializer that silently accepts duplicate keys or replaces invalid text. Whitespace and object-key order are insignificant; JSON serialization need not be canonical because identity is bound through authenticated admission rather than head signatures.

## Directional state machine

The successful grammar is:

```text
owner → device: REQUEST_HEAD, BODY*, END, outer FIN
device → owner: RESPONSE_HEAD, BODY*, END, outer FIN
```

| State | Accepted input | Transition |
| --- | --- | --- |
| `AwaitHead` | Correct head for this direction | Validate all fields and policy, then `Body` |
| `Body` | Nonempty BODY | Stream bytes, update checked counters, remain `Body` |
| `Body` | END | Check declared/actual length and body restrictions, then `AwaitFin` |
| `AwaitFin` | Outer ordered FIN, with no extra data | Mark direction complete |
| Any unfinished state | Outer RESET or unrecoverable carrier failure | Mark direction interrupted; preserve known dispatch state |

A second head, wrong-direction head, BODY before HEAD or after END, repeated END, record bytes after END, FIN before END, or EOF within a record is a protocol error. FIN must follow the final DATA containing END in sequence order, has no HTTP-record payload, and consumes the outer protocol sequence as usual. Request FIN half-closes only the request; it does not close the response stream or cancel the operation.

Directions progress independently. A backend may begin a final response after request HEAD and before the upload ends; the bridge must read/write both directions concurrently. This is essential for streaming and early rejection. An early response does not by itself claim request-body completion. Continue bounded upload forwarding or discard under the adapter's explicit rejection policy. If the response fully completes first, the request sender may reset an unfinished upload; preserve the already completed HTTP response while aborting remaining request work. Never fabricate a successful request END for bytes that were not received.

Do not dispatch an unvalidated head. The initial JSON-command profiles for ACP, MCP, and typed CUA additionally wait for their complete bounded request body and schema/policy validation before invocation; generic HTTP framing alone cannot authorize a partially parsed command. This is a selected-profile policy, not a universal requirement that every MCP HTTP request be buffered. A profile permitting streaming request dispatch must declare its partial-write/cancellation semantics, validation boundary, and budget before forwarding early body bytes to a mutating backend.

## Paths, headers, and HTTP normalization

This is a fixed-export bridge, not a general reverse proxy. The public route maps to a configured local service path. `path` has at most 1,024 ASCII bytes, starts with exactly one `/`, and uses only `/`, ASCII alphanumerics, `-`, `.`, `_`, and `~`. Reject empty, `.`/`..` segments, repeated slashes, backslashes, percent escapes, query/fragment delimiters, absolute URLs, authority forms, and NUL. `/` alone is valid only if that export declares it. The complete method/path pair must match an advertised route; filesystem names and user data belong in the adapter's typed body/parameters rather than a path splice.

`query` is empty unless the service profile names allowed query parameters. Maximum 2 KiB and 32 pairs; validate percent escapes and decode exactly once for policy checks. Reject invalid UTF-8 or decoded controls, unrecognized keys, credential-bearing parameters, and duplicates unless that specific parameter permits them. Preserve the accepted original query bytes for the target; downstream code must not perform a second authorization decode. A query cannot select another service, backend address, executable, or workspace.

Header names are lowercase ASCII HTTP token characters, 1–128 bytes. Values contain printable ASCII or horizontal tab only, at most 4 KiB; reject CR, LF, NUL, other controls, and obsolete folded lines. Trim boundary optional whitespace once at ingress. Permit at most 32 field entries and 8 KiB of total decoded name/value bytes, including repeats; the serialized head must still fit 16 KiB. Singleton fields must occur once; accepted list/repeated semantics belong to the profile, never generic comma concatenation.

Apply direction-specific header allowlists at ingress, owner, and device. Candidate fields include content type, accept, cache policy, request conditions, and the selected ACP/MCP version/session metadata. The implementation PR must enumerate the actual set for each pinned application profile. An unknown application header fails validation; it is not silently treated as supported.

Never pass HTTP routing/framing authority or credentials through this array: `host`, `connection` and every field it nominates, `keep-alive`, `proxy-connection`, `transfer-encoding`, `te`, `trailer`, `upgrade`, `expect`, `content-length`, `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, forwarded identity headers, or `x-agent-tunnel-*` internal metadata. Public-layer OAuth challenges, browser cookies/CORS, and operation-ID headers are constructed by the authenticated ingress layer. Adapter-owned backend credentials are inserted locally from fixed configuration. Do not forward private backend WWW-Authenticate challenges as if they were relay login instructions.

The HTTP libraries validate their own message framing before the bridge strips transport headers. Reject conflicting/duplicate Content-Length and conflicting Transfer-Encoding/Content-Length requests before dispatch rather than laundering them through normalization. Decode HTTP transfer framing into body octets once; never copy chunk-size lines into BODY. Validate any incoming Content-Length against the actual bytes and carry its checked length as `body_length`. The receiving HTTP adapter may generate its own Content-Length or streaming framing from that typed value; it must not copy consumer framing verbatim. [HTTP field forwarding and length semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1), [HTTP/1 message framing](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)

No trailer records exist in v1. Reject declared trailers before dispatch; a nonempty trailer discovered during body reading causes a scoped reset rather than silently dropping potentially meaningful metadata. For the initial profiles accept identity content encoding only, request identity from fixed HTTP backends, and reject unsupported encodings. This prevents hidden decompression from changing body limits or byte counters. Other encodings require an explicit bounded profile.

Never follow backend redirects automatically. A permitted Location value must be mapped to a public route within the same authorized export; private addresses, credentials, or cross-service targets are errors. Fixed local HTTP services use operator-configured targets and no caller-supplied host/proxy settings. In-process desktop handlers construct typed Rust HTTP requests directly and require no local listener.

## Backpressure, streaming, and deadlines

BODY data is raw binary; preserve byte order and content exactly. For SSE, forward its headers and body bytes incrementally without parsing/reformatting events, inserting synthetic events, joining complete messages, or waiting for END. Body chunks may split UTF-8 characters, JSON, SSE lines, and blank event delimiters. The application/SSE parser consumes the reconstructed HTTP body. Flush available output promptly; proxy response buffering/compression must be disabled for the deployed streaming route.

Every record byte, including headers and HEAD JSON, is charged to the existing directional credits and device/session budget. Per-hop pending queues also obey [cluster.md](cluster.md): initially 256 KiB per peer stream, 8 MiB per peer connection, and bounded request counts. The HTTP adapter has no independent unbounded body/event queue. Read upstream only with downstream capacity; do not issue WINDOW_UPDATE merely because bytes moved to another queue that remains charged. A replay of an existing outer sequence consumes no new logical credit.

The common profile requires concrete per-request request/response cumulative byte limits and a wall-clock deadline at admission. Known lengths above the selected limit fail before BODY allocation. Streaming responses may have a larger configured cumulative limit than finite JSON responses, but no unlimited sentinel is allowed. The adapter chooses useful finite limits and reports them in service discovery; the lower deployment/global limits still apply.

Starting transport progress budgets: first HEAD within 10 seconds after OPENED, a partly received record completed within 10 seconds from its first byte, output-credit stall bounded to 30 seconds, and FIN within 10 seconds after END. HEAD/record/FIN progress clocks pause only while this endpoint's recorded rotation freeze prevents sending, or while this receiver has deliberately withheld credit; the independently bounded overlap/credit-stall timers keep those pauses finite. The absolute application deadline never pauses. Application silence between records is governed by the ACP/MCP/CUA profile; an SSE connection is not killed merely because it has no current event. These values are configurable with hard ceilings. Trickled bytes do not restart progress budgets, and unrelated heartbeats do not extend them.

Reserve bounded control capacity for cancellation, reset/error handling, drain acknowledgments, and terminal status. A credit-stalled BODY cannot prevent the owner from processing cancellation. Do not hold a shared mutex across socket, HTTP-body, or child-process I/O; supervise separate directional pumps with one exchange owner and explicit shared terminal state.

## Cancellation, resets, and execution uncertainty

Use the outer tunnel `RESET` exactly as defined in [protocol.md](protocol.md): one unsigned 16-bit reason code in network byte order, using the shared reason-code registry. There is no JSON reset payload and no extra HTTP error/reset record. HTTP forwarding uses the protocol's applicable adapter-failure/cancellation reason; HTTP-specific detail belongs in bounded `RESULT_STATUS` metadata and the scoped operation-status lookup, not a private numeric extension to RESET.

HTTP error detail uses a `code` chosen from `HTTP_BAD_RECORD`, `HTTP_INVALID_HEAD`, `HTTP_BODY_LIMIT`, `HTTP_LENGTH_MISMATCH`, `HTTP_UNSUPPORTED_FEATURE`, `HTTP_STREAM_INTERRUPTED`, `HTTP_CANCELLED`, or `HTTP_DEADLINE_EXCEEDED`, plus `execution` equal to `not_dispatched`, `dispatched`, or `unknown`. Limit this adapter-specific detail to 512 serialized bytes inside the normal bounded status envelope. It reports the emitting endpoint's knowledge; only the device's authoritative dispatch record can prove a command did not run. An ingress that lost the acknowledgment reports `unknown`, not `not_dispatched`. No HTTP bodies, arbitrary backend errors, private paths, or credentials belong in control/status metadata.

On local cancellation/error, stop local adapter delivery and unfinished pumps immediately, retain the terminal tombstone, and send a scoped control `CANCEL` promptly where remote cancellation is needed. `RESULT_STATUS` reports the actual or unknown outcome independently. Queue the outer RESET through the owner actor: it consumes a sequence, remains ordered behind previously assigned DATA/FIN, and participates in fences, ACKs, and replay. Reserved terminal capacity bypasses application-byte-credit exhaustion, **not sequence order or a rotation freeze**. Control cancellation can therefore stop work before the queued RESET reaches the peer.

Retain receive cursors, emitted frames, and drain-roster references until protocol-driven `STREAM_FORGET` permits reclamation. Consume/account for pre-reset in-flight peer frames in sequence as terminal discard without delivering them to the adapter. A received RESET triggers the local terminal response at most once as specified by the protocol. Resetting during rotation cannot erase a fence gap; crossed resets cannot resurrect a stream or overwrite a stronger known application result.

Consumer disconnect maps to bounded best-effort application cancellation plus RESET for unfinished exchanges. Cancellation of a response body is protocol-sensitive: current MCP and legacy MCP have separate rules, and an ACP GET loss has the connection cleanup policy in [acp.md](acp.md). `session/cancel` and permission responses are ordinary separately admitted ACP POSTs, not an HTTP forwarding codec feature. Request FIN and scheduled physical-socket closure never synthesize those messages.

Before public response headers are committed, a forwarding failure can become a scoped 502, 503, or 504 gateway response with sanitized Agent Tunnel error metadata. After headers/body begin, fail/reset that HTTP stream; never append a forged JSON-RPC error or successful SSE event to its body, and never turn truncation into an ordinary successful END. The host may already have seen partial output; the separate operation facility reports actual or unknown outcome. A completed HTTP response remains completed if only the unfinished upload is subsequently aborted.

Outer ACK, receipt of HEAD, HTTP 200/202, response END, and child/tool completion are distinct facts. The bridge records admission, dispatch, and HTTP completion separately from application outcome. No retry may reopen an HTTP exchange after forwarding could have reached the device. In particular, a GET may allocate an ACP subscriber or trigger application behavior; this codec does not infer retry safety from the method name. Only explicit adapter semantics plus proved `not_dispatched` permit an admission retry. Never replay an ambiguous prompt, tool call, write, or click under a fresh operation ID.

## Rotation and recovery

During scheduled handover, freeze old-generation DATA/FIN/RESET assignment, retain partial codec state and bounded pending bytes, drain through the immutable per-stream fences, commit the replacement, and resume the same stream/counters. HEAD does not repeat. BODY may resume partway through a record. END, FIN, and RESET queued during quiescence wait behind their preceding sequences and are sent only on activation or an explicit coordinated abort. Local cancellation and bounded control CANCEL/RESULT_STATUS remain available during freeze; closing the old physical socket has no HTTP completion meaning.

Drain acknowledges transport receipt/accounting, not whole-response completion, so a long-lived SSE response cannot indefinitely pin the old socket. Control acknowledgments remain responsive during stalls; inability to drain within the overlap budget follows the protocol's explicit abort/recovery/failure path.

Recoverable loss with retained outer sequence/parser state replays only missing bounded transport bytes, deduplicated before this codec. An owner/process loss that destroys that state terminates the exchange. Do not reconstruct it by starting HTTP again, issue a second HEAD to a new handler, or infer resume from Content-Length. This transport has no ACP Last-Event-ID mechanism and cannot strengthen ACP/MCP recovery guarantees.

## Implementation and verification gates

1. Implement a pure bounded record decoder/encoder and directional state machine. Golden fixtures cover every kind, exact lengths/endianness, all split points, coalesced records, arbitrary binary BODY, and empty bodies. Fuzz malformed lengths, duplicate JSON keys, invalid UTF-8, flags, path/header ambiguities, wrong-direction records, FIN/END races, and integer limits.
2. Connect the codec to an in-process streaming Rust HTTP handler. Test early response during upload, request half-close with continuing response, 204/205/304/HEAD restrictions, exact Content-Length checks, trailers/encoding rejection, SSE split across every delimiter, cancellation, and absence of an inbound local listener.
3. Put the handler behind the real Axum→owner HTTP/3→device WebSocket path. Saturate one stream while another cancels/answers permission, measure bounded queues at every hop, and verify bytes with checksums. Confirm no private credentials/addresses cross the public/device headers.
4. Rotate through HEAD, partial BODY/header, END-before-FIN, early response, credit stalls, and long-lived SSE. Race control CANCEL with queued RESET during freeze and prove prompt local cancellation, no out-of-order RESET, preserved fence accounting, and eventual STREAM_FORGET. No duplicate dispatch, repeated HEAD, event rewriting, ordering loss, fabricated END, or extra steady-state device sockets is permitted. Inject owner loss and lost acknowledgments after a synthetic side effect and assert `outcome_unknown` without retry.
5. Run the selected official ACP and MCP client/server fixtures plus a synthetic CUA HTTP facade through the shared bridge. Advertise only application profiles that pass their own lifecycle gates. The common codec passing its tests does not establish application compatibility.

The implementation PR pins codec fixtures, all limits, per-profile header/path allowlists, HTTP library features, and the supported errors in code. Keep this codec independent of Axum extractors, ACP JSON-RPC types, and child supervision so its behavior can be reasoned about and tested without a running server.
