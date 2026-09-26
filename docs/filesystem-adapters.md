# SDK adapter implementation plan

Status: design ready for implementation, 2026-09-09; **amended 2026-09-17 — all four adapters are now implemented against installed, exact-pinned published packages** (task row M4-14, *implemented awaiting verification*). The [filesystem endpoint contract](filesystem-api.md) is authoritative. External SDK facts were pinned in the linked research notes from *source* snapshots; what an installed artifact actually contains is recorded in [Pinned packages, as installed](#pinned-packages-as-installed) below, including the three places the artifact differs from what this plan assumed.

The `@agent-tunnel/*` names below remain **proposed package names**. The adapters ship as export subpaths of `packages/client` — `@agent-tunnel/client/files-sdk`, `/mastra`, `/just-bash`, `/ai-sdk` — rather than as four published packages, because splitting one lockfile and one offline test command into five is packaging work that changes no interface and would have to be undone to keep `npm test` runnable with `node_modules` deleted. The ownership table's *contents* are implemented as written; only the artifact boundary is deferred.

## Pinned packages, as installed

Verified 2026-09-17 against the npm registry and against the installed trees in `packages/client/node_modules`, with `packages/client/package-lock.json` committed. Every version this plan named exists; one it left as a range is now exact.

| Package | Pinned | Exists | What the installed artifact actually declares |
| --- | --- | --- | --- |
| `files-sdk` | 2.4.0 | yes (latest is 2.5.0) | `Adapter<Raw>` requires `name`, `raw`, `upload`, `download`, `head`, `exists`, `delete`, `copy`, `list`, `url`, `signedUploadUrl`, exactly as planned, with `move`, `deleteMany`, `resumableUpload` and `conditional` optional. `FilesErrorCode` is `NotFound`, `Unauthorized`, `Conflict`, `ReadOnly`, `Provider`. |
| `@mastra/core` | 1.65.0 | yes (latest is 1.67.0) | `WorkspaceFilesystem` has exactly the eleven asynchronous operations the plan counts, plus `id`/`name`/`provider`, optional `readOnly`/`basePath`/`icon`, and the optional lifecycle. `engines.node` is `>=22.13.0`. |
| `just-bash` | 3.4.2 | yes (it is latest) | `IFileSystem` is the eighteen methods [testing.md](testing.md) lists plus synchronous `resolvePath`/`getAllPaths` and optional `readFileBytes`/`readdirWithFileTypes`. `engines.node` is `>=20.18.1`. |
| `ai` | 7.0.94 | yes (latest is 7.0.105) | `uploadFile` accepts a `FilesV4` or a `ProviderV4`, calls `uploadFile` **once** and rethrows, with no `maxRetries` option — as the plan states. `engines.node` is `>=22`. |
| `@ai-sdk/provider` | **4.0.11** | yes | The plan named only a peer range. 4.0.11 is the exact version `ai` 7.0.94 depends on, so it is the pin: any other would pair `ai.uploadFile` with a **different `FilesV4`** than the adapter was compiled against. It does not make the tree single-copy — the committed tree already holds three (`4.0.11`, and `4.0.4` and `3.0.14` nested under `@mastra/core`) — it makes the copy the helper reaches the copy the adapter was checked against. `FilesV4` requires `specificationVersion: 'v4'`, `provider` and `uploadFile`; metadata, download and delete are optional. |

The intersection of the pinned `engines` is **Node 22.13 or newer**, which is what the plan's matrix says. `packages/client` itself requires Node 24 for its own type-stripping test runner; that is this repository's tooling choice and not a consumer requirement.

### Three differences from what this plan assumed

1. **`files-sdk`'s retry gate makes the error class load-bearing.** Its `canRetry` is `error.code === "Provider" && !(error.aborted || error.permanent)`, applied to the result of `FilesError.wrap(cause)` — which returns `cause` unchanged **only** when `cause instanceof FilesError` and otherwise builds a fresh `Provider` error with `permanent` unset. An adapter throwing its own error type would therefore have every failure, an `unknown` mutation included, classified as retryable. `createFilesAdapter` takes the consumer's own `FilesError` class as a required option for that reason; `instanceof` is identity-sensitive, so a second copy of `files-sdk` in a tree would otherwise break the same way. **The requirement is that `FilesError` comes from the same module instance as the `Files` it is passed to** — `import { Files, FilesError } from 'files-sdk'`, one import, one copy. The adapter **cannot verify this**: a `FilesError` from a second installed copy is a perfectly good class with the right shape, and the `Files` wrapper would silently rebuild every failure it produced — including an `unknown` mutation — as a retryable `Provider` error. The injection moves the identity check to the consumer; it does not perform one, and nothing at run time reports the mistake.
2. **`just-bash`'s defense-in-depth blocks `globalThis.setTimeout` for the duration of a script.** The shared client arms a timer for every request deadline, so a `Bash` over a remote filesystem fails its first command before a byte reaches the socket. Upstream's own violation message names the remedy for trusted host-runtime code, and a `fs` the application injected is exactly that: supported constructions pass `defenseInDepth: { excludeViolationTypes: ['setTimeout'] }`. It is the **only** exclusion needed. Nothing in this plan anticipated it; it was found by running the real `Bash`.
3. **`just-bash` 3.4.2 does not re-export three of `IFileSystem`'s own option types.** `ReadFileOptions`, `WriteFileOptions` and `DirentEntry` are declared in `dist/fs/interface.d.ts` and used in the interface's signatures, but the package root omits them from its `export type` list and its `exports` map exposes only `.` and `./browser`. They are extracted from the installed interface with `Parameters<>`/`ReturnType<>` rather than copied, because a local substitute is what [testing.md](testing.md) says cannot satisfy contract compilation.

Two smaller observations, recorded because they are easy to get wrong: `ai.uploadFile` turns a plain **string** `data` into `{ type: 'data', data }`, which `FilesV4` defines as *base64*, not inline text — plain text must go through `{ type: 'text', text }`; and neither `files-sdk` nor `ai` exposes `./package.json` through its `exports` map, so a version assertion reads the installed tree rather than importing it.

## Supported integration paths

| Consumer | Native integration seam | Planned binding | What the endpoint does not imply |
| --- | --- | --- | --- |
| Files SDK 2.4.0 | `Adapter<Raw>` passed to `new Files({ adapter })` | `createFilesAdapter({ remote })` maps object keys to regular files | Its native `createFilesClient({ endpoint })` speaks a different HTTP protocol |
| Mastra `@mastra/core` 1.65.0 source | `WorkspaceFilesystem`, preferably extending `MastraFilesystem` | `TunnelMastraFilesystem` supplied to `Workspace({ filesystem })` or `mounts` | No automatic mount inside a native shell/sandbox |
| just-bash 3.4.2 source | `IFileSystem` supplied to `Bash({ fs })` | `TunnelJustBashFilesystem` | No host shell execution; interpretation remains in the consumer |
| AI SDK `ai` 7.0.94 source | `FilesV4` from `@ai-sdk/provider` | `createFilesApi` for managed upload objects | No directory API and no model-provider access to tunnel object IDs |
| AI SDK file/browsing tools | `tool` / `files-sdk/ai-sdk` / bounded Bash tools | Tools close over an authorized shared client or adapter | File attachments alone do not create a live filesystem |

Source references: [Files SDK](research/files-sdk.md), [Mastra](research/mastra.md), [AI SDK](research/ai-sdk.md), [just-bash and 9P mapping](integrations.md). The full initial matrix targets **Node 22.13 or newer**, subject to the intersection of the pinned packages' engines. Do not force one experimental package's transitive just-bash version onto the primary adapter; test package combinations separately.

## Packages, ownership, and API surface

| Proposed package | Owns | Peers |
| --- | --- | --- |
| `@agent-tunnel/client` | Descriptor, authenticated WSS, 9P codec, lifecycle, bytes, limits, scoped errors | No framework dependency |
| `@agent-tunnel/files-sdk` | `createFilesAdapter({ remote })`, `Adapter<RemoteFilesystem>` | `files-sdk` |
| `@agent-tunnel/mastra` | `TunnelMastraFilesystem({ remote, mtimePolicy? })` | `@mastra/core` |
| `@agent-tunnel/just-bash` | `TunnelJustBashFilesystem({ remote })`, local path helpers | `just-bash` |
| `@agent-tunnel/ai-sdk` | `createFilesApi`, bounded file tools, structured mutation outcomes | `ai`, `@ai-sdk/provider`; optional bridge peers isolated by export |

The application creates the shared connection. Adapters **borrow** it and never change its token, endpoint, root, or grant. Adapter destruction releases only its own pending work, fids, cursors, and references; the application calls `remote.close()` after all borrowers stop. Mastra's init/destroy hooks manage its wrapper state, not an injected shared connection. Do not return raw fids or bypass methods through framework escape hatches. Multiple adapters share aggregate quotas and cannot each allocate a separate full client budget.

Client/fid operations must be leased so closing one adapter cannot clunk another's active handles. Keys for all caches, cursors, and model file references include session/export/principal ownership. Sharing among different authenticated users is prohibited even when paths and device IDs look identical.

### Proposed connection examples

```ts
// Specification examples; Agent Tunnel packages do not exist yet.
import { connectFilesystem } from '@agent-tunnel/client';
import { Files } from 'files-sdk';
import { createFilesAdapter } from '@agent-tunnel/files-sdk';
import { Workspace } from '@mastra/core/workspace';
import { TunnelMastraFilesystem } from '@agent-tunnel/mastra';
import { Bash } from 'just-bash';
import { TunnelJustBashFilesystem } from '@agent-tunnel/just-bash';

const remote = await connectFilesystem({ endpoint, token: getAccessToken });
const files = new Files({ adapter: createFilesAdapter({ remote }), retries: 0 });
const filesystem = new TunnelMastraFilesystem({ remote });
const workspace = new Workspace({ filesystem });
await workspace.init();
const bash = new Bash({ fs: new TunnelJustBashFilesystem({ remote }), cwd: '/' });

// Same regular file, three native views (after it exists in the test fixture):
await files.head('notes.txt');
await filesystem.readFile('/notes.txt');
await bash.exec('cat /notes.txt');

// Stop users of these objects, then release wrappers and the connection.
await workspace.destroy();
await remote.close();
```

Examples assume already-authorized endpoint/token variables. A model never supplies them. Test constructor options against installed peer declarations before turning these examples into executable samples. Only actual server grants enable writes; optional SDK approvals are additional application controls.

## Files SDK: object API view

Implement the required `Adapter<Raw>` methods `upload`, `download`, `head`, `exists`, `delete`, `copy`, `list`, `url`, `signedUploadUrl`, plus `name` and the already-scoped `raw` client. Implement optional `move` explicitly so Files SDK does not substitute copy/delete for rename. Full signatures and source links are in [research/files-sdk.md](research/files-sdk.md).

Keys are nonempty relative paths for file operations. Reject leading `/`, dot or parent segments, empty components, backslash/NUL and unsupported host names. Percent signs are literal; do not decode keys into traversal. Only listing accepts an empty prefix. Map `key` to virtual `/${key}`; SDK prefix options do not grant permission. Upload creates parent directories as needed and replaces/creates a regular file; directory deletion is not an object delete. Deny symlink traversal in this profile, including intermediate components, using server-enforced no-follow resolution, not a preflight lstat race. This requires the provider/client to support a per-open no-follow policy; if that cannot be enforced, restrict the Files SDK profile to an export whose provider disallows links throughout.

`head` reads metadata without downloading. `download` streams bytes and supports inclusive ranges only once its capability tests pass. `StoredFile` text/Buffer/Blob accessors must enforce the actual byte count and total materialization budget; a preceding stat cannot protect against file growth. Missing/denied/offline remain distinct. Sizes outside JS safe integer range fail explicitly.

List regular-file keys; directories are prefixes and empty directories are absent from the object view. Implement prefix matching as object-key prefix matching, not just a directory lookup. Accept `/` delimiter only; report unsupported nonempty delimiters. Use bounded lazy traversal and session-local opaque pagination tokens bound to query/grant. Defaults: page size 100, maximum 1,000; at most 16 live cursors per adapter, 60-second idle expiry, and total traversal limits from the descriptor. Exceeding traversal limits fails explicitly, not with a false complete page. No stable snapshot/order guarantee during host directory changes. Reject expired/wrong-session/wrong-query cursors; never silently restart pagination.

Persist bytes and host modification time only. Omit ETags/version IDs and report `application/octet-stream` unless a separately documented inference policy applies. Reject requests for persistent custom metadata or cache-control semantics; no hidden sidecar metadata files. Leave atomic conditional and resumable-upload methods absent. Advertise unsupported features explicitly: Files SDK defaults must not accidentally imply metadata, server-side copy, signing, or cache support.

`url` and `signedUploadUrl` are required methods but throw a permanent unsupported `FilesError`; advertise `signedUrl: { supported: false }`. Never fabricate an HTTP URL, expose a host file URL, or embed an access token in a URL. The raw WebSocket endpoint cannot serve an image/PDF attachment to an arbitrary model HTTP fetcher.

Preserve `FilesError` codes where meaningful (`NotFound`, `Unauthorized`, `ReadOnly`, `Conflict`). For partial/unknown mutation errors, use permanent, nonretryable `Provider` errors with a sanitized typed tunnel cause. Do not misuse upstream `applied` as “may have happened.” Examples set `retries: 0`; the adapter must also prevent retry if the application enables SDK retries. Mutation plugins such as failover, soft-delete, dedup, compression, and versioning are uncertified and cannot be enabled in supported examples without separate semantics/limit tests.

### Native Files SDK HTTP endpoint compatibility

`files-sdk/client`'s `createFilesClient({ endpoint, headers })` will **not** accept the canonical `/fs` WebSocket API. A future route such as `/compat/files-sdk/v1` could expose the upstream `createFilesRouter({ files, authorize, ... })` protocol using this adapter behind an app-owned TypeScript gateway. That gateway is an optional separate component; Rust remains the relay/device/privileged filesystem implementation.

It needs a distinct implementation issue and pinned native-client conformance suite: operation envelopes, upload/download/ranges, capabilities, auth, cancellation, limits, and outcome reporting. The pinned HTTP error shape omits the typed cause and partial/unknown outcome fields. Until a reviewed extension or compatible nonretryable error policy preserves those outcomes, do not advertise native HTTP client support for mutations. Resolve auth per request and bind streamed bodies to that context; never reuse a globally privileged Files instance to serve arbitrary tenants.

## Mastra: workspace filesystem view

Implement its eleven asynchronous operations, required identity/name/provider/status properties, and lifecycle. Return Buffer by default from `readFile`, or decode the requested Node encoding. Writes create parents by default unless `recursive:false`; append creates missing parents and files. Honor `overwrite:false` using exclusive creation, and reject unsupported move-without-overwrite semantics rather than doing a racy existence check. Translate the actual exported error classes and retain typed tunnel partial/unknown errors. See [research/mastra.md](research/mastra.md) for the full mapping.

Expose virtual paths only. Omit local `basePath`/mount configuration; no FUSE or sandbox execution capability is implied. Support static `Workspace({ filesystem })`, mount maps, and request-context resolvers without sharing principals. A Mastra cross-mount move may itself compose read/write/delete; this is not the endpoint's native rename and may leave duplicates. The supported baseline does not promise bounded cross-provider copy through that upstream implementation; certify it separately or keep those operations disabled in application tools.

Mastra requires `createdAt` and numeric sizes. When birth time is unavailable, use the observed mtime for `createdAt` and expose `createdAtSource:'mtime-fallback'` through provider metadata/instructions. This is a compatibility convention, not a historical creation-time claim. Apply the same safe Date/ms conversion throughout. Unknown node types fail instead of becoming fake regular files. Materialized directory/file results fail on limits rather than silently truncate.

### Timestamp checks: explicit compatibility choice

The `mtimePolicy` constructor option is `'reject'` by default. A requested `expectedMtime` then fails before any mutation. Native Mastra read tracking often supplies this condition internally even if the model did not request it; this default therefore does not support ordinary read-then-edit tools on writable mounts.

Applications choosing Mastra's existing advisory behavior can explicitly use:

```ts
const filesystem = new TunnelMastraFilesystem({
  remote,
  mtimePolicy: 'check-before-write',
});
```

For that profile, perform stat before any create/truncate/parent mutation. Compare the same millisecond value returned in `stat().modifiedAt` with `expectedMtime.getTime()`. Existing mismatch throws the real `StaleFileError`; matching or missing file proceeds as the pinned LocalFilesystem does. Other stat errors are preserved. A concurrent writer between check and write, or within timestamp precision, can still be overwritten. The longer remote race window must be documented; this is **not atomic conditional write or protection against lost updates**. Expose the selected policy in provider instructions/metadata. The endpoint's `conditionalWrites` remains false.

Only the explicit check-before-write profile can claim native Mastra read/edit compatibility after its real tool tests pass. Strict/atomic timestamp or ETag semantics require a separate managed-provider concurrency design; do not silently upgrade this claim.

## just-bash: shell filesystem view

Implement the pinned `IFileSystem` directly over the shared client. Keep byte/encoding conversions and synchronous `resolvePath`/`getAllPaths` local; initially `getAllPaths` returns the upstream-permitted empty array. The [existing method-to-9P table](integrations.md) remains applicable. Use `MountableFs` for multiple exports; clamp virtual `..` according to just-bash's contract and still enforce host confinement in Rust.

The shell runs in the consumer. Disable optional network, JS/Python execution, and any host-exec custom commands in supported default examples. A VFS adapter does not expose the remote machine's installed programs. Shell commands using unsupported permissions/links fail with documented filesystem errors.

The wrapper also exposes a bounded structured `drainOperationFailures()` result for completed Bash executions, recording partial/unknown remote mutations without raw content. Limit 64 entries per execution and report overflow explicitly. A Bash exit code/stderr alone may lose structured error causes; AI tool wrappers must include this side channel when reporting a failed execution and must never infer “safe to retry” from a nonzero exit code. Concurrent Bash executions use separate wrapper/error scopes, even if they borrow one connection.

## AI SDK: native file objects and live tools

### FilesV4

Implement `FilesV4` (`specificationVersion:'v4'`, `provider:'agent-tunnel.files'`) with `uploadFile` and supported metadata/download/delete methods. Pass it directly to `ai.uploadFile({ api, ... })`; do not invent model/embedding/image providers just to register files. It is a file-object API, not a directory API. Exact inputs/outputs are in [research/ai-sdk.md](research/ai-sdk.md).

`createFilesApi({ remote, uploadDirectory })` requires an explicitly configured writable virtual directory. Upload creates an unpredictable ID with exclusive creation; `filename` and mediaType are bounded display metadata, never a path selector. Accept bytes, strictly decoded base64, UTF-8 text, or bounded streams. Return `{'agent-tunnel': opaqueId}` only after confirmed completion. Scope a bounded in-memory reference map to this adapter instance, principal/export, and session; maximum 256 references, all charged to its quota. On overload reject before creating a file. No implicit oldest-file deletion.

References survive scheduled data rotation but expire when the adapter/session closes. The files themselves remain ordinary files in the explicitly configured upload directory. Closing an adapter does not silently delete them. Application-owned cleanup must enumerate that directory under its grant or track acknowledged created paths; durable reference catalogs and automatic retention are separate extensions. No arbitrary-path-to-reference helper in the first release. Track partial uploads and their owned paths for explicit cleanup; failure is not success just because a file exists.

The initial reference is an alias for its assigned virtual path, **not an immutable file identity or version**. If another authorized VFS writer replaces that path, metadata/download see its current occupant and delete removes the current occupant. Rename away yields absence unless a replacement appears; the reference does not follow renames. Display metadata from upload is advisory and may no longer describe changed content. Use a dedicated upload directory and document this behavior to callers. A QID/stat preflight cannot make deletion conditional on identity. Immutable object references or delete-only-if-the-original-object-still-exists require a separately designed managed provider/atomic operation; the baseline makes neither guarantee.

Metadata/download/delete accept only references minted by that adapter. Reject foreign provider keys and nonempty per-call header overrides that could change identity. Preserve current grants, errors and unknown outcomes. Metadata display values exist only for the reference lifetime; the VFS does not gain persistent object metadata. A read-only export rejects required upload and does not advertise it as a useful upload destination.

The inspected `ai.uploadFile` helper calls `FilesV4.uploadFile` once and rethrows failures; it has no `maxRetries` option to disable. Invoke optional metadata/download/delete methods on the FilesV4 instance itself. The adapter and application still must not retry ambiguous mutations; prove dispatch count under actual pinned helper calls. Shared internal materialization limits include adapter-owned conversions/caches until result ownership passes to the application; they cannot bound values the application retains afterward.

Tunnel references cannot be resolved by unrelated model providers. To send a file to a model, read bounded bytes into a FilePart or upload those bytes to that provider's real file API; document the resulting second copy/retention separately. Do not relabel an Agent Tunnel ID as an OpenAI/Anthropic/etc. ID.

### Live directory tools

**Implemented 2026-09-25 (task row M4-63), first option only.** `createFilesystemTools({ remote })` on `@agent-tunnel/client/ai-sdk` returns `list_directory`, `read_file` (at most `maxReadBytes`, default 64 KiB, with `truncated` measured by reading one byte past the bound), `stat` and — only when the descriptor is writable and advertises `writeFile` — `write_file` (exclusive by default, at most `maxWriteBytes`, refused before dispatch above it). Input schemas are Standard Schema v1 objects with a JSON Schema converter, so `ai` is imported by type only; failures are returned as `{ ok: false, code, outcome, retrySafe }` and only a cancellation is re-thrown. `retrySafe` is `true` for a read that is `not_started` or `failed`, but for `write_file` only when `not_started`, because `failed` on a mutation means "at least this much" (see [filesystem-api.md](filesystem-api.md)). The `files-sdk/ai-sdk` factories and the `bash-tool` wrapper below remain unimplemented. It runs against a real relay and device in [docs/demo/adapters.md](demo/adapters.md).

Provide bounded `read`, `list`, `write` and other granted tools over the shared client, with input schemas and abort propagation. Tool outputs carry explicit `outcome` for partial/unknown mutations and byte/truncation metadata. Credentials, endpoint, user and export are closed-over trusted context; the model cannot choose them.

Alternatively use the supported individual factories from `files-sdk/ai-sdk` over the Files adapter, filtering unsupported URL and ungranted write tools. Bound actual received content, not only a pre-read `head`. Or wrap the just-bash instance with `bash-tool`, preserving structured operation failures and limiting output. Its inspected hydration/text wrapper can UTF-8-decode binary data and fully buffer files; disable automatic initial uploads and do not certify it for binary streaming.

AI SDK's `Experimental_SandboxSession` and `@ai-sdk/sandbox-just-bash` are a separate exact-version integration gate. They include process methods as well as files, have buffering caveats, and the inspected package uses a different just-bash major version. Do not claim this endpoint can be passed directly to them. If prioritized, use remote filesystem operations plus a local simulated Bash for `run`/`spawn`; native remote process execution remains outside this API.

## As implemented: `partial`, `unknown`, and what each interface cannot say

`docs/filesystem-api.md` gives the shared client a four-word outcome vocabulary — `not_started`, `failed`, `partial`, `unknown` — and forbids the automatic replay of an ambiguous mutation. **None of the four interfaces above has that vocabulary.** Each adapter therefore chooses a surface, and the choice is recorded here rather than left to be inferred from a mapping table.

| Consumer | Where `partial`/`unknown` goes | What it cannot express, stated |
| --- | --- | --- |
| Files SDK | A `Provider` `FilesError` with `permanent: true`, carrying the client's `FilesystemError` as `cause`. `applied` is **never** set — upstream it means a conditional mutation committed, which is a stronger claim than "may have happened". | `FilesError` has no outcome field, so `partial` and `unknown` arrive identically and survive only on `cause.outcome`. A consumer that logs the error and drops the cause has lost the distinction. |
| Mastra | A `FilesystemError` with code `TUNNEL_PARTIAL` or `TUNNEL_UNKNOWN` and the client's error attached as `cause`. Never one of Mastra's semantic classes. | Mastra has no outcome concept and `code` is the only field open enough to carry one, so a tool switching on Mastra's own error classes falls through to a default. That is the correct outcome and the limit of the interface: `FileNotFoundError` after a half-applied write reads as "nothing happened". |
| just-bash | A plain `Error` whose message is a code and an operation, **plus** the bounded `drainOperationFailures()` side channel carrying operation, code, virtual path, outcome and acknowledged bytes. 64 entries per execution, with overflow counted rather than dropped. | A Bash exit code and a line of stderr keep none of it. An AI tool wrapper reporting a failed execution must include the drained result and must never infer "safe to retry" from a nonzero exit code. |
| AI SDK `FilesV4` | A throw, carrying the client's `FilesystemError` unchanged. `uploadFile` mints no reference and records the path it was writing in `incompleteUploads()`. | `warnings` rides only on results, and these calls have none. `deleteFile`'s `deleted: false` is the one field an ambiguous outcome could have been flattened into: after an `unknown` nobody knows the provider did not delete it, and `true` would be worse. There is no third value, so the call rejects. |

The rule the four share: **no adapter emits a failure its framework would classify as retryable.** For Files SDK that is structural — `permanent: true` on every `Provider` error it builds, reads and session losses included, because the shared client never reconnects behind the caller's back and no second attempt through a closed client could succeed.

### Named limits of the implemented adapters

* **`appendFile` is unsupported in every view that has one.** Gate 5 does not advertise `nativeAppend`. Mastra's `appendFile` and shell `>>` both fail with an explicit unsupported-operation error rather than a stat-then-positioned-write, which is the race the contract forbids. In `just-bash` 3.4.2 a redirect-target failure **rejects out of `exec`** rather than becoming a shell exit status, so a consumer must catch it.
* **Recursive directory copy is refused, not composed.** The shared client's `copy` is a bounded file read and write; Mastra's `copyFile({ recursive: true })` and `cp -r` are refused rather than half-copying a tree.
* **`lstat` is `stat` and `realpath` is the identity**, for as long as `symlinks` is absent from the feature set. Named rather than implied.
* **`readFileBytes` is not implemented.** Its `ByteString` return type is branded and only upstream's own constructors produce one; upstream declares the method optional and falls back to `readFileBuffer`.
* **`getAllPaths()` returns the empty array**, which upstream permits: it is synchronous and this filesystem is remote. Glob discovery that depends on it finds nothing; globs resolved through `readdir` work.
* **The Mastra adapter implements `WorkspaceFilesystem` rather than extending `MastraFilesystem`.** Extending the base class is a *value* import of `@mastra/core`, which would put a framework dependency inside a package whose shape is that it has none; upstream's own class documentation sanctions implementing the interface directly. The cost, named: no Mastra logger reaches the adapter.
* **Files SDK `url` and `signedUploadUrl` are permanent unsupported errors**, `signedUrl: { supported: false }` is advertised, and the `conditional` block is absent entirely so every compare-and-set call fails before provider I/O.
* **Files SDK pagination cursors are live, session-local traversals** keyed in a per-adapter map: at most 16, 60-second idle expiry, single use, and bound to their own prefix, delimiter and grant revision. A reused, expired or re-queried cursor is refused rather than silently restarting page one.

## Delivery slices and acceptance

1. **M4a: shared endpoint and client.** Descriptor/schema/auth/upgrade, Rust 9P provider, confined read operations, binary streams, capabilities, lifecycle, cleanup, deadlines and limits. Pure codec fixtures then real relay/device WSS tests.
2. **M4b: native read views.** Files SDK Adapter, Mastra WorkspaceFilesystem, just-bash IFileSystem, and AI SDK bounded tools, all reading the same fixture tree. Compile installed peers and verify formats/paths/errors through their actual APIs. Advertise read-only until write gates pass.
3. **M4c: explicit writes and semantics.** Test exact creates/truncation/append/rename, SDK retries, partial mutations, Files prefix/cursors, Mastra's two timestamp policies, and just-bash structured failures. A full read-edit-read sequence must work through the intended framework tools.
4. **M4d: native AI FilesV4.** Actual upload/metadata/download/delete helpers over managed files, reference lifecycle, quotas, cross-user rejection, lost replies, streamed cancellation, and model-reference boundary. No live paid model call required for conformance.
5. **M4e: certify and publish compatibility matrix.** Exact artifacts/peer ranges, Node versions/OS/provider capabilities, cross-framework dataset visibility, three data rotations, multi-user isolation, external host writers, and clean consumer installation. Record unsupported features with tests that fail as documented.

Optional later issues: Files SDK native HTTP gateway, AI experimental sandbox sessions, durable file-object references, true managed-provider conditional mutations, browser transport, and signed-download grants. Their absence must remain explicit; they do not block the primary native-adapter VFS API. The supported initial scope is fully enumerated above, so choosing a codec/library can proceed without inventing endpoint or framework semantics during implementation.
