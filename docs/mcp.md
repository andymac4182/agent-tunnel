# MCP adapter plan

Status: planned. MCP compatibility is separate from the tunnel wire protocol. The tunnel's control and data WebSockets do not require an external MCP client to support a custom transport.

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
