# Files SDK integration contract research

Researched 2026-09-09. This is implementation planning; no adapter, remote
filesystem, published package installation, or interoperability test exists yet.
Read the [VFS design](../filesystem-api.md) for Agent Tunnel's normative endpoint contract.

## Verified upstream snapshot

- Project: [haydenbleasel/files-sdk](https://github.com/haydenbleasel/files-sdk).
- Inspected commit: `a56c91381343ee017becf70c46b66c72cf9c1b09`, committed
  2026-09-07. Its [package manifest][manifest] declares `files-sdk` **2.4.0**,
  MIT, ESM, and separate `files-sdk/client`, `files-sdk/api`, and
  `files-sdk/ai-sdk` exports. This is a source pin, not an installed artifact pin.
- The AI integration accepts peer `ai` versions `^6.0.0 || ^7.0.0` and `zod`
  `^3.23.0 || ^4.0.0`; select exact versions and a lockfile in the compatibility
  spike. Do not infer that every allowed combination has been tested here.
- The homepage and mutable cached source initially disagreed about versions;
  these notes use the immutable commit throughout.

## Compatibility boundary

Files SDK provides object/key storage semantics, not the complete POSIX-like
filesystem interface used by a shell. Its exported extension interface is
`Adapter<Raw>`, passed to `new Files({ adapter })`. The planned Agent Tunnel
adapter maps this object view onto one granted remote mount. The privileged
filesystem implementation and authorization remain in Rust.

There are two distinct upstream integration seams:

| Seam | Upstream protocol | Agent Tunnel decision |
| --- | --- | --- |
| `Files` + custom `Adapter` | Adapter chooses I/O | Primary path: thin TypeScript object adapter over the shared authenticated 9P/WSS client |
| `createFilesClient({ endpoint, headers })` | Files SDK HTTP gateway | Separate possible compatibility facade; a raw 9P/WSS URL does not satisfy it |

The [HTTP client][client] posts JSON operation envelopes, gets download bytes
using query parameters, and uses upload byte/proxy flows. Its
[gateway implementation][gateway] is `createFilesRouter({ files, authorize, ... })`.
Matching a generic JSON API or accepting an `endpoint` option is insufficient:
direct compatibility requires its exact request, response, authentication,
capability, upload-token, range, and error contracts. A future Rust facade must
be independently certified against the pinned native client. It is not required
to make the custom adapter work and is outside the initial WSS profile.

The pinned manifest and [provider catalog][catalog] expose no built-in just-bash, Mastra,
9P, or WebSocket provider. This establishes the inspected extension surface,
not a claim about every third-party integration. Mastra and just-bash use their
own thin adapters over the same Agent Tunnel client; wrapping Files SDK does
not automatically implement either framework's native filesystem interface.

## Required adapter implementation

The [public interface][core] requires `name`, `raw`, `upload`, `download`, `head`,
`exists`, `delete`, `copy`, `list`, `url`, and `signedUploadUrl`. `move`,
`deleteMany`, resumable uploads, and atomic conditional primitives are optional.
Implement `move` explicitly because upstream otherwise composes copy and delete.

Planned mappings, bounded by the shared VFS operation and policy limits:

| SDK operation | Agent Tunnel object-view behavior |
| --- | --- |
| `upload(key, body)` | Replace/create one regular file; stream into the VFS write path; acknowledge only its documented commit outcome |
| `download(key, options)` | Open and stream file bytes; map inclusive byte ranges to offset/count reads |
| `head(key)` | Read metadata only; body accessors lazily start a bounded read |
| `exists(key)` | False only for absence; denied, unavailable, and invalid requests throw |
| `delete(key)` | Unlink one regular file; no implicit recursive directory deletion |
| `copy(from, to)` | Compose bounded reads/writes within the mount; preserve partial/unknown outcomes |
| `move(from, to)` | Same-mount rename under the VFS rename contract; cross-mount moves rejected |
| `list(options)` | Bounded regular-file key enumeration with prefix, page cursor, and optional `/` delimiter |
| `url`, `signedUploadUrl` | Explicit unsupported-operation errors in the WSS profile |

Do not wrap the upstream Node `files-sdk/fs` adapter around a host path; that
would bypass the remote API and its Rust confinement boundary. `raw` may expose
only the already-scoped Agent Tunnel client/session, never device credentials,
host directory handles, or an unconstrained service-selection escape hatch.

## Object-view semantics to implement

1. One adapter instance addresses exactly one tenant/device/service/mount binding.
   Keys are relative UTF-8 paths using `/`. Reject absolute paths, NUL, traversal,
   empty components, backslashes, and platform-ambiguous names according to the
   normative VFS contract. Never decode percent escapes twice. Reject invalid
   keys rather than silently mapping two keys to the same path.
2. Ordinary operations require a nonempty file key. Only listing may use an empty
   prefix. SDK `prefix` is convenience namespacing; authorization is always the
   server-side grant. Test the SDK's prefix composition and stripping against
   the adapter's independently validated keys.
3. Expose regular files in the object view. Directories become list prefixes;
   empty directories are intentionally not object entries. Do not follow symlink
   entries during object enumeration or object operations in the first profile.
   Explicitly test this narrower view alongside the richer just-bash view.
4. Persist file bytes and filesystem modification time. Do not invent stored MIME
   metadata, HTTP cache directives, custom object metadata, or strong ETags from
   an ordinary stat. Return `application/octet-stream` unless a documented
   inference policy applies; reject upload options promising unsupported durable
   metadata. Do not create hidden sidecar files merely to satisfy an SDK option.
5. SDK file sizes, range bounds, and timestamps are JS numbers. Reject values
   outside safe integer/range limits when converting from the client's BigInt
   wire fields; report modification times in milliseconds. Binary content never
   takes a text round trip.
6. `StoredFile` exposes text/bytes/blob/stream body accessors. Use upstream
   `createStoredFile` only after verifying its consumption behavior, cancellation,
   lazy metadata reads, and allocation limits. Apply both per-read byte limits
   and cumulative materialization limits; streaming alone does not bound callers
   that request `arrayBuffer()` or `text()`.
7. A paginated list binds its opaque cursor to the mount/session, grant version,
   prefix, delimiter, and enumeration lifetime. Bound traversal work, depth,
   entries, cursor storage, and bytes. No complete-tree buffering to produce a
   small page. Document concurrent-directory-change behavior and reject expired
   cursors explicitly. A later request cannot reuse another principal's cursor.
8. Begin with `supportsRange: true` only after range tests pass, and
   `supportsDelimiter: true` only for implemented delimiter semantics; initially
   accept `/` and reject other nonempty delimiters. Advertise metadata,
   cache-control, server-side copy, resumable upload, and conditional capabilities
   as unavailable. Advertise `signedUrl: { supported: false }`.
9. Do not emulate atomic conditional create/replace/read/delete with a stat check
   followed by an operation. Leave the optional conditional methods absent until
   the server offers an atomic primitive and generation semantics are certified.
   Basic chunked uploads do not imply resumable-upload protocol support.

## Failures, retries, and isolation

Upstream [retry logic][retry] defaults to zero retries, but retries transient
`Provider` errors when the caller enables a retry budget. Abort and `permanent`
errors stop retrying. Buffered uploads can be retried by the core; streams cannot
be reread. Therefore setting example retries to zero is not enough protection.

Map absence to `NotFound`, authorization denial to `Unauthorized`, write-policy
denial to `ReadOnly`, and collisions to `Conflict`. For invalid/unsupported
requests use a permanent `Provider` error. Preserve a sanitized typed Agent
Tunnel error as `cause`, including operation identity and `not_started`,
`partial`, or `unknown` outcome as appropriate. All unresolved mutations must
stop SDK retries even if the caller configures a nonzero retry budget. Tests must
prove no second mutation reaches the device.

The upstream [error class][errors] has `applied` for known committed conditional
operations; this is not an unknown-outcome marker. Never set it merely because a
request might have reached the device. Generic errors and aborts do not prove
rollback. Adapter closure cancels local waits and releases remote resources
without retrying a mutation. Scheduled tunnel data rotation keeps the underlying
mount session alive; actual session loss invalidates every outstanding handle.

The native HTTP [wire error][wire] carries `code`, `message`, `aborted`, and
`timedOut`; it omits the typed cause and outcome details. This is another reason
HTTP-gateway compatibility needs a separate error-contract decision before it
can promise Agent Tunnel's required ambiguity reporting.

## AI SDK tools through Files SDK

Upstream [`files-sdk/ai-sdk`][tools] builds eight tool factories over `Files`.
Its write tools default to approval gates; its read-only option removes writes.
These application controls supplement Rust-side authorization. The factory does
not filter unavailable URL tools based on adapter capabilities: use the exported
individual factories or filter deliberately so `getFileUrl` and `signUploadUrl`
are absent for the WSS-only profile. Do not give the model tools that can only fail.

The [download executor][executors] checks `head()` before reading the body; the
[schema][schemas] defaults to 1 MiB and caps the requested limit at 10 MiB. A file
can grow between those calls. Enforce the actual received-byte ceiling in the
shared client/adapter, and use a bounded tool wrapper when a stricter per-tool
limit is needed. Keep binary-as-base64 output bounded, including expansion.

## Implementation and certification gates

- Freeze source/package/peer versions, install the real npm artifact into a clean
  Node consumer, compile `Adapter` without private imports, and verify exports.
- Exercise real `new Files({ adapter })` upload/download/head/exists/copy/move/
  delete/list/listAll/file/search calls against synthetic remote files; verify
  prefix and delimiter handling, metadata-only reads, binary hashes, empty files,
  short reads/writes, directory changes, and numeric conversion edges.
- Reject unsupported URL, metadata, cache, conditional, resumable, and delimiter
  requests before side effects. Verify every advertised capability against actual
  operation behavior. Check lazy body accessors after revocation/disconnect.
- Force disconnect after dispatch for every mutation while SDK retries are
  enabled; verify one dispatch and preserved ambiguous outcome. Abort before,
  during, and after dispatch, and test copy partial failure separately from rename.
- Repeat reads, upload streams, and pagination across scheduled data rotations;
  saturate queues and enforce consumer, tenant, device, mount, and byte budgets.
- Run two tenants and overlapping consumers with identical object keys; reject
  cross-mount cursors, stale grants, symlinks, traversal, and unauthorized writes.
- Invoke the actual AI SDK tool executors with bounded fixtures and record the
  tested AI SDK version. Model calls are not required to establish the tool/VFS
  contract; an optional real-agent example must state its separate evidence.
- Native `createFilesClient` HTTP compatibility remains uncertified unless a
  facade is implemented and its complete protocol receives its own test suite.

[manifest]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/package.json
[catalog]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/providers/index.ts
[core]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/index.ts
[client]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/client/files-client.ts
[gateway]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/api/index.ts
[retry]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/internal/retry.ts
[errors]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/internal/errors.ts
[wire]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/internal/files-router/protocol.ts
[tools]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/ai-sdk/index.ts
[executors]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/internal/ai-tools/executors.ts
[schemas]: https://github.com/haydenbleasel/files-sdk/blob/a56c91381343ee017becf70c46b66c72cf9c1b09/packages/files-sdk/src/internal/ai-tools/schemas.ts
