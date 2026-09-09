# Mastra filesystem adapter research

Researched 2026-09-09. Status: implementation specification; no adapter, package,
connection, or interoperability test exists yet. This document scopes Mastra's
filesystem API integration. The shared endpoint and filesystem semantics are
defined in [filesystem-api.md](../filesystem-api.md); Mastra uses that protocol.

## Compatibility target and evidence

Pin the implementation spike to Mastra commit
[`d0d12483ed7e3b4da51668740b86255a4c1b28a0`](https://github.com/mastra-ai/mastra/tree/d0d12483ed7e3b4da51668740b86255a4c1b28a0).
Its [`@mastra/core` manifest](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/package.json)
declares version **1.65.0**, Apache-2.0, Node **>=22.13.0**, and a Zod peer.
This is a verified source snapshot, not proof of published-package compatibility.
Resolve the exact released package, lockfile, and integrity during the spike.
Use Node first; this Buffer-based contract is not a browser-support claim.

The extension is `WorkspaceFilesystem`, exported by `@mastra/core/workspace`.
The optional `MastraFilesystem` base class supplies logging and lifecycle helpers.
There is no generic `Workspace({ filesystem: "wss://..." })` integration in this
contract. Agent Tunnel supplies a TypeScript provider implementing that interface
over the shared authenticated endpoint; all privileged filesystem work stays Rust.
See the [interface](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/filesystem/filesystem.ts)
and [exports](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/index.ts).

The live [reference](https://mastra.ai/reference/workspace/filesystem) currently
differs from pinned source on encoding defaults and metadata. Implement against
the pinned interface and confirm behavior with the actual package: no encoding
returns `Buffer`; a supplied `BufferEncoding` requests text decoding. Do not
interpret the documentation's `'binary'` example as a separate binary wire codec.

## Required API and endpoint responsibilities

All eleven filesystem operations below return Promises. Required properties are
`id`, `name`, `provider`, and `status` through the lifecycle interface. Optional
properties include `readOnly`, `basePath`, `icon`, `displayName`, and `description`.
Set an opaque per-session `id`, a stable provider name, and effective `readOnly`.
Omit `basePath`: the remote machine's disk path is not a local Mastra path.

| Mastra operation | Required behavior in our provider |
| --- | --- |
| `readFile(path, options?)` | Read bytes in bounded chunks; return Buffer by default or decode with the requested Node encoding. |
| `writeFile(path, content, options?)` | Accept string, Buffer, or Uint8Array; UTF-8 encode strings; support recursive parents, overwrite control, and the conditional-write contract below. |
| `appendFile(path, content)` | Create missing file and parents; append using the server's granted append capability, never read-concatenate-rewrite. |
| `deleteFile(path, options?)` | Remove a file; reject directories; `force` suppresses only missing-file errors. |
| `copyFile(src, dest, options?)` | Copy bytes; honor overwrite and recursive options; bound traversal and expose partial failure. |
| `moveFile(src, dest, options?)` | Rename within one export when supported; preserve overwrite requirements; never claim cross-export atomicity. |
| `mkdir(path, options?)` | Honor recursive creation; reject an existing file. |
| `rmdir(path, options?)` | Honor recursive/force flags; reject a nonempty directory without recursion. |
| `readdir(path, options?)` | Return FileEntry records; implement recursive, extension, and maxDepth options with resource bounds. |
| `exists(path)` | Return false only for absent paths; reject permission, offline, expired-session, and quota errors. |
| `stat(path)` | Return FileStat with virtual path, name, file/directory type, byte size, and Date timestamps. |

The option shapes are defined in the pinned
[filesystem interface](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/filesystem/filesystem.ts).
Match `LocalFilesystem` defaults where its interface leaves them unspecified:
write creates parents unless `recursive: false`; overwrite defaults to true;
append creates parents. Its recursive directory results use slash-separated
relative descendant names, and extension filtering accepts `.ts` or `ts`.
See [LocalFilesystem](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/filesystem/local-filesystem.ts).

`readFile` and `readdir` materialize complete results in Mastra's API. Apply the
shared client's per-operation byte/entry limits even when internal 9P reads and
directory pagination stream. Reject before exceeding limits; do not return a
truncated result as complete. Cancellation and deadlines must settle pending
Promises although these Mastra method signatures have no AbortSignal argument.

Normalize `/`, relative paths, empty mount-root paths, and `.` into one virtual
export namespace. CompositeFilesystem strips its prefix before calling a
provider. Reject escapes after normalization and again in Rust during resolution.
`stat` follows permitted symlinks; optional `realpath` returns a virtual canonical
path. Preserve `isSymlink` and safe virtual `symlinkTarget` in directory entries.
Never expose a host absolute target or follow a link outside the granted export.
Traversal must detect cycles and enforce depth/entry limits.

Mastra's FileStat cannot represent device nodes or sockets; reject unsupported
special-file access instead of presenting those as readable regular files.
Convert byte size to Number only when safely representable. `createdAt` is
required although remote birthtime can be unavailable: use the shared design's
documented timestamp fallback and expose its provenance in provider metadata.
Timestamp conversion must be identical in stat and conditional-write comparisons.

## Conditional writes and errors

`WriteOptions.expectedMtime` is a Date. The pinned local implementation compares
`getTime()` and throws `StaleFileError` for an existing changed file; a missing file
is treated as a permitted create. It then performs a separate write: upstream's
implementation is not atomic compare-and-swap. Mastra's
[write tool](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/tools/write-file.ts)
forwards an internal expected timestamp to the provider. The
[tool wrapper](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/tools/tools.ts#L271)
attaches a prior read's timestamp even when `requireReadBeforeWrite` is disabled.
Neither tool inputs nor successful write output expose the consistency guarantee.

Proposed adapter option: `mtimePolicy: 'reject' | 'check-before-write'`, default
`'reject'`. Under the default, reject expectedMtime with an unsupported-capability
error before mutation. Native read-then-edit workflows therefore require an
explicitly selected `'check-before-write'` profile on an authorized writable export.

That profile matches Mastra's local behavior: compare the existing file's current
mtime with expectedMtime using identical `getTime()` conversion; throw the actual
StaleFileError on mismatch; proceed with creation if the file is missing; preserve
all other stat errors. Check before truncation or writing bytes. This advisory
preflight permits a writer to race between metadata comparison and mutation and
misses same-millisecond changes. It is not atomic compare-and-swap or protection
against lost updates. Expose the profile and limitation in provider instructions
and `getInfo().metadata`; do not silently discard expectedMtime.

The shared endpoint keeps `conditionalWrites: false`; requests requiring strong
conditions remain unsupported. This adapter option does not add a wire operation
or advertise a stronger server capability. See
[the endpoint contract](../filesystem-api.md) for normative behavior.

Translate known filesystem failures into the actual exported
[Mastra error classes](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/errors.ts):

| Condition | Mastra-facing error |
| --- | --- |
| Missing file / missing directory | `FileNotFoundError` / `DirectoryNotFoundError` (`ENOENT`) |
| Existing destination | `FileExistsError` (`EEXIST`) |
| Directory used as file / file used as directory | `IsDirectoryError` / `NotDirectoryError` |
| Nonempty directory | `DirectoryNotEmptyError` (`ENOTEMPTY`) |
| Denied grant or path | `PermissionError(path, operation)` (`EACCES`) |
| Provider configured read-only | `WorkspaceReadOnlyError(operation)` (`READ_ONLY`) |
| Conditional timestamp mismatch | `StaleFileError(path, expectedMtime, actualMtime)` (`ESTALE`) |

Keep one compatible `@mastra/core` peer instance so `instanceof` remains reliable.
Preserve distinct typed tunnel errors for unavailable service, expired session,
resource limits, unsupported capability, partial operation, and unknown mutation
outcome. Do not map these to ENOENT, catch them as `exists === false`, or retry an
unacknowledged write. Include only virtual paths in messages and causes.

## Workspace configuration and lifecycle

Proposed Agent Tunnel symbols below are design placeholders, **not published
packages or existing API**. The shared client factory and ownership rules will
be finalized with the endpoint implementation.

```ts
import { Workspace } from '@mastra/core/workspace';
// Proposed local adapter: implements the pinned WorkspaceFilesystem contract.
import { TunnelMastraFilesystem } from './proposed-agent-tunnel-adapter.js';

const filesystem = new TunnelMastraFilesystem({
  remote: authorizedVfsSession,
  mtimePolicy: 'check-before-write', // Explicit best-effort Mastra compatibility.
});
const workspace = new Workspace({ filesystem });
await workspace.init();
// Attach this workspace to a Mastra Agent; its file tools use the remote export.
// Application shutdown:
await workspace.destroy();
```

Alternatively `new Workspace({ mounts: { '/computer': filesystem } })` provides
paths such as `/computer/report.txt`. Configure either `filesystem` or `mounts`,
never both. Multiple mount prefixes cannot overlap. No sandbox is needed for file
tools. A provider does not become visible to `execute_command` merely by providing
a VFS API: real sandbox mounting is separate, optional future work. Omit
`getMountConfig` and return undefined from optional `resolveAbsolutePath`; do not
advertise FUSE, a local disk path, or native shell access.
See [filesystem and mounts documentation](https://mastra.ai/docs/sandbox/filesystem).

For multiple users, `filesystem` can be an async `({ requestContext }) => provider`
resolver. Select sessions from server-authenticated context, never untrusted
prompt fields. Partition any pool by tenant, principal, device, export, grant,
and connection epoch. Do not reuse one mutable provider while changing its token
for each request. The app owns bounded pooling and teardown of dynamic providers;
`Workspace.init()` initializes only its static provider. Mastra memoizes dynamic
resolution per RequestContext. See the pinned
[Workspace implementation](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/workspace.ts).

Prefer extending `MastraFilesystem`; implement init/destroy and call ensureReady
inside operations. Its wrappers coalesce concurrent initialization and teardown
and use `ready` for filesystem readiness. Optional lifecycle methods can be
sync or async; `getInstructions` and `resolveAbsolutePath` are synchronous and must
not perform I/O. Keep instructions limited to virtual paths and negotiated policy.
See [base class](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/filesystem/mastra-filesystem.ts)
and [lifecycle types](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/lifecycle.ts).

Set effective readOnly before registering a static workspace so Mastra can omit
write tools. Dynamic providers keep those tools registered and reject writes at
runtime. Tool visibility/approval is supplementary; Rust still enforces every
grant and mount rule. Observed revocation invalidates access immediately, including pooled
sessions; cluster authorization propagation is bounded to five seconds as
specified in [cluster.md](../cluster.md). Data-socket rotation retains the logical filesystem session; actual
consumer-session loss invalidates it and settles all outstanding operations.

Mastra's composite implements cross-mount copy by whole-file read/write and move
by copy then delete; these are not atomic or necessarily streaming. A failed
destination write must prevent source deletion. The provider's read cap still
applies, and a delete failure can leave two copies. Document this separately from
same-export rename. See [CompositeFilesystem](https://github.com/mastra-ai/mastra/blob/d0d12483ed7e3b4da51668740b86255a4c1b28a0/packages/core/src/workspace/filesystem/composite-filesystem.ts).

## Implementation and release gates

1. Compile the complete provider with the exact published Mastra dependency and
   a strict TypeScript fixture; install the built adapter in a clean Node consumer.
2. Run operation contracts against synthetic files through the real WSS endpoint,
   relay, and Rust export: encodings, byte equality, options, typed errors, and
   optional realpath. Compare documented defaults against pinned LocalFilesystem.
3. Invoke actual Mastra file tools with a deterministic fixture; verify read,
   list, grep, stat, mkdir, write, edit, and delete without requiring an LLM call.
4. Test static and dynamic read-only behavior, one tenant with concurrent agents,
   two tenants with overlapping filenames, grant revocation, and pool teardown.
5. Test repeated init/destroy races, bad credentials, offline devices, bounded
   listings/reads, rotation during a read/write, cancellation, and lost replies.
6. Test both mtime profiles: default rejection performs no mutation; the explicit
   profile supports native read/edit tools, rejects observed mismatches, permits
   missing-file creation, preserves stat errors, and exhibits the documented
   concurrent/same-millisecond race. Gate writes on exclusive create, partial
   write/copy/remove reporting, and no automatic mutation retries.
7. Exercise composite routing, failed mount initialization, cross-mount copy/move,
   and source preservation after a failed destination write. An initialized
   composite can contain a failed child; probe the selected provider itself.
8. Publish only observed Node/OS/package compatibility. Browser, sandbox-native
   mounts, LSP host paths, and remote command execution require separate gates.
