# AI SDK files, tools, and sandbox integration

Researched 2026-09-09. These are verified upstream contracts and proposed Agent
Tunnel bindings. None of the bindings exists in this repository yet. Package
versions below are source-manifest versions; published artifacts have not been
installed, typechecked, or tested for interoperability.

## Compatibility targets

| Component | Inspected immutable source | Manifest version / runtime |
| --- | --- | --- |
| AI SDK | [vercel/ai at 45f2b6a](https://github.com/vercel/ai/tree/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563) | `ai` 7.0.94; Node >=22 |
| Provider contract | [provider manifest](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/provider/package.json) | `@ai-sdk/provider` 4.0.11; Node >=22 |
| AI SDK just-bash sandbox | [sandbox manifest](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/sandbox-just-bash/package.json) | `@ai-sdk/sandbox-just-bash` 1.0.104; Node >=22; depends on just-bash `^2.14.5` |
| bash-tool | [70ba5ad manifest](https://github.com/vercel-labs/bash-tool/blob/70ba5ad4d01be465e76acb5b6bd0c6221a2af1b9/package.json) | 1.3.19; AI SDK peer `^6.0.0 || ^7.0.0` |
| just-bash VFS | [062ce00 manifest](https://github.com/vercel-labs/just-bash/blob/062ce005c0a7676163852fb6f0c8590cbdaa1d45/packages/just-bash/package.json) | 3.4.2; Node >=20.19 |

Pin the selected published packages and a JS lockfile in the implementation PR.
Node 22 or newer is the intersection for the researched AI SDK 7 integration.
Do not infer SDK 6 compatibility for FilesV4 or experimental sandbox APIs from
bash-tool's broader peer range. Test any additional major separately.

## What “AI SDK files” means

| Upstream surface | Actual purpose | Agent Tunnel integration |
| --- | --- | --- |
| `FilePart` / UI file attachments | File content, URLs, or provider references supplied to a model | Explicitly read bounded bytes or upload to the chosen model provider; this does not mount a directory |
| `uploadFile` and `FilesV4` | File objects with provider references; optional metadata/download/delete | A native files adapter is feasible, with opaque object IDs and explicit storage ownership |
| `tool({ inputSchema, execute })` | Application code executed for model tool calls | Call the shared filesystem client or a local just-bash instance using that client |
| `Experimental_SandboxSession` | File primitives plus command/process primitives passed to tools | Optional exact-version adapter; file operations remain remote, simulated shell remains in the consumer |
| Vercel Sandbox `FileSystem` | `node:fs/promises`-like operations on a Vercel microVM | Separate product; its API alone does not establish an arbitrary remote VFS mount |

Current AI SDK really does include files and sandbox contracts. Neither is a
general directory/provider interface equivalent to just-bash's `IFileSystem`.
Sources: [file content types](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/provider-utils/src/types/content-part.ts),
[FilesV4](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/provider/src/files/v4/files-v4.ts),
[tool types](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/provider-utils/src/types/tool.ts),
[sandbox types](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/provider-utils/src/types/sandbox.ts),
and [Vercel Sandbox reference](https://vercel.com/docs/sandbox/sdk-reference#filesystem).

## Native FilesV4 binding

Implement a TypeScript object satisfying `FilesV4` from `@ai-sdk/provider` with
`specificationVersion: 'v4'` and proposed provider ID `agent-tunnel.files`.
`uploadFile` is required. Presence of the other three optional methods indicates
support; omit methods that a configured adapter does not support. A read-only
mount still rejects the required upload method explicitly.

| Method | Verified input | Verified result |
| --- | --- | --- |
| `uploadFile` | Tagged `data`, required `mediaType`, optional `filename`, common options | `providerReference`, required `warnings`, optional filename/media type/byte size/creation/expiry/provider metadata |
| `getFileMetadata` | `file: Record<string,string>`, common options | Own provider reference, required `warnings`, same optional metadata |
| `downloadFile` | `file: Record<string,string>`, common options | `content: ReadableStream<Uint8Array>`, required `warnings`, optional media type/provider metadata |
| `deleteFile` | `file: Record<string,string>`, common options | Own provider reference, `deleted: boolean`, required `warnings`, optional provider metadata |

Common options are `abortSignal`, `headers`, and `providerOptions`. Headers are
for HTTP providers; the tunnel adapter must reject nonempty per-call headers
rather than allowing credential/tenant changes on its existing WebSocket.
Validate namespaced provider options; reject unknown tunnel options before I/O.
Return only reported metadata: `byteSize` is a safe JS number, timestamps are
`Date`, and no retention expiry is invented.

The upload data variants are `{ type: 'data', data: Uint8Array | base64String }`,
`{ type: 'text', text: string }`, and
`{ type: 'stream', stream: ReadableStream<Uint8Array> }`. UTF-8 encode text and
strictly decode base64; do not interpret a plain data string as UTF-8.
Propagate cancellation and transfer limits. Failed uploads release their input
stream; downloaded streams must be drained or cancelled by the consumer.
Sources: [call/result types](https://github.com/vercel/ai/tree/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/provider/src/files/v4),
[upload helper](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/ai/src/upload-file/upload-file.ts).

Proposed storage binding for the implementation plan:

1. Construct the adapter with an already authorized mount session and an
   explicitly configured upload directory. Every transfer uses the same shared
   WebSocket/9P client as the VFS adapters. No per-file HTTP API is required.
2. Create an unpredictable object ID and an exclusive file in that directory;
   `filename` is bounded display metadata, never a path or host selector.
3. Return `{ 'agent-tunnel': objectId }` only after confirmed transfer completion.
   Maintain a bounded mapping to mount identity and the managed file. Never use
   a raw path, tenant token, host inode, or 9P fid as the public object ID.
4. For a first implementation, mappings are adapter-session scoped. Closing that
   session invalidates its references; scheduled device data rotation does not.
   Document partial uploads and managed-file retention/cleanup explicitly.
   References across process restarts require a separately designed durable
   object catalog, not just storing a fid or assuming a path is unchanged.
5. Metadata/download/delete validate the owning session and current grant every
   time. Only the assigned upload path is reachable through the reference. This is a
   path alias: replacement at that path changes the content read or deleted;
   it does not promise immutable object identity or follow renames. No arbitrary
   filesystem path is inferred from the supplied reference. Preserve unknown delete/write
   outcomes and require reconciliation; never claim success after a lost reply.

These choices make FilesV4 a useful file-object API over the endpoint. Directory
listing, named-file editing, rename, and path traversal remain VFS operations.
Do not silently turn an upload filename into an overwrite of an existing file.
An optional helper to register existing paths must be separately specified and
must not grant deletion rights to preexisting files by default.

The supported upstream entry point accepts the FilesV4 object directly:

```ts
import { uploadFile } from 'ai';
import type { FilesV4 } from '@ai-sdk/provider';

declare const tunnelFiles: FilesV4; // Proposed adapter; not implemented.
const uploaded = await uploadFile({
  api: tunnelFiles,
  data: { type: 'text', text: 'fixture content' },
  filename: 'example.txt',
});
const downloaded = await tunnelFiles.downloadFile?.({
  file: uploaded.providerReference,
});
// Drain or cancel downloaded.content when the capability is available.
```

No fake model provider registration is needed. Although `ProviderV4.files()`
exists, `ProviderV4` also requires model factory methods unrelated to this
filesystem. Source: [ProviderV4](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/provider/src/provider/v4/provider-v4.ts).

## Giving remote files to a model

An Agent Tunnel provider reference is meaningful only to our adapter. A model's
OpenAI/Anthropic/Google provider cannot automatically resolve that reference.
Read bounded bytes from the authorized mount and supply a `FilePart`, or stream
those bytes to the model provider's real `uploadFile` API and use its returned
reference. This second route copies data into that provider's storage and needs
its own deletion/retention policy. Never relabel a tunnel object as an `openai`
file ID. Do not put relay credentials or authenticated WebSocket URLs in model
content. Source: [provider-reference behavior](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/content/docs/03-ai-sdk-core/39-file-uploads.mdx).

## Live VFS through tools and just-bash

The initial live-directory integration is `Bash({ fs: tunnelFs })` with the
planned just-bash `IFileSystem` adapter. Pass that Bash instance as `sandbox` to
`await createBashTool({ sandbox, destination: '/' })`, then pass its `tools` to
an AI SDK `ToolLoopAgent`. `/` is the virtual mount root, never the host root.
Use an app-supplied model and SDK-version-appropriate step bound; SDK 7 uses
`isStepCount`, while the researched bash-tool README specifies `stepCountIs`
for SDK 6. These are integration examples, not verified runnable repository code.

The shell interpreter executes in the consumer. Only file operations cross the
tunnel; this does not expose native host execution. Disable optional consumer
network/JavaScript/Python features in the initial fixture. Authorization remains
in the filesystem/device layers even when the model submits a shell command.

The current bash-tool wrapper converts Buffer uploads to UTF-8 strings. Its
`readFile` and `writeFile` tools are text-oriented, and the read tool lacks its
own output cap. Avoid initial `files`/`uploadDirectory` hydration for remote
mounts; it writes before tool construction returns. Use bounded direct tools
over the shared client for binary transfers, read ranges, and accurate structured
unknown-outcome results. A bash exit code alone cannot describe ambiguous writes.
Sources: [tool construction](https://github.com/vercel-labs/bash-tool/blob/70ba5ad4d01be465e76acb5b6bd0c6221a2af1b9/src/tool.ts),
[just-bash wrapper](https://github.com/vercel-labs/bash-tool/blob/70ba5ad4d01be465e76acb5b6bd0c6221a2af1b9/src/sandbox/just-bash.ts),
[read tool](https://github.com/vercel-labs/bash-tool/blob/70ba5ad4d01be465e76acb5b6bd0c6221a2af1b9/src/tools/read-file.ts).

Direct file tools should close over an authenticated session, validate input
with `inputSchema`, forward `execute`'s `abortSignal`, and return bounded JSON
results with operation outcome and truncation fields. Do not let model arguments
choose credentials, device membership, mount roots, or an arbitrary endpoint.

## Experimental SandboxSession binding

The actual source type exported as `Experimental_SandboxSession` by `ai` includes
`description`, six read/write primitives, `run`, and `spawn`. Its current prose
reference still shows only description/run, so source/types take precedence.
Reads support byte streams, byte arrays, and text; missing files return `null`.
Only confirmed absence becomes null, never permission/offline errors. Text reads
accept encoding and 1-based inclusive line ranges, allowing an end past EOF.
Writes accept streams/bytes/text, create parents recursively, and overwrite.
`spawn` returns stdout/stderr byte streams with `wait()` and idempotent `kill()`.

The proposed direct adapter can route the six file methods through the shared
client and keep run/spawn in local simulated just-bash. Implement every required
method and bounded buffering before advertising full compatibility. Never map
run/spawn to a host shell as an incidental part of enabling files.

The upstream `createJustBashSandbox({ sandbox })` wrapping route is available:
create a just-bash `Sandbox` with `fs`, create a provider session, and call
`restricted()` for the tool-facing interface. However, its dependency targets
just-bash 2.x while this project targets 3.4.2; cross-version class types and
runtime behavior require a spike. Its current file stream implementation fully
buffers reads/writes and does not establish our bounded-streaming guarantee.
The API is experimental and may change in patch releases; pin exact versions.
Sources: [session source](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/sandbox-just-bash/src/just-bash-sandbox-session.ts),
[provider construction](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/sandbox-just-bash/src/just-bash-sandbox.ts),
[just-bash custom fs](https://github.com/vercel-labs/just-bash/blob/062ce005c0a7676163852fb6f0c8590cbdaa1d45/packages/just-bash/src/sandbox/Sandbox.ts).

## Implementation gates

- Compile each published-package consumer with `strict` and `skipLibCheck: false`;
  verify optional-peer behavior and exact exports in a clean Node >=22 fixture.
- Test FilesV4 bytes/base64/text/streams, missing references, safe-integer/date
  bounds, stream cancellation, partial upload cleanup, and false/unknown deletes.
- Prove a tunnel reference cannot read/delete another user's object or become a
  model provider reference; use mocked models and synthetic bytes in normal CI.
- Exercise real `Bash({ fs })` plus real AI SDK tool execution over WSS/9P, with
  directory operations, text/binary distinctions, limits, and injected failures.
- Test SandboxSession line ranges, non-UTF-8 encodings, parent creation, stream
  backpressure, abort-before/during dispatch, and local process wait/kill behavior.
- Rotate device data sockets during uploads, downloads, and shell file access;
  preserve logical sessions, bounded buffers, and explicit mutation outcomes.
- Assert zero host processes launched, no auto-hydration, no credentials in
  prompts/logs, and no remote input/computer actions during these filesystem tests.

The inspected `ai.uploadFile` helper invokes the supplied FilesV4 upload method once and rethrows failures (cancelling a stream input on error). It has no `maxRetries` option. Optional metadata/download/delete methods are called on the provider instance; core exposes no corresponding helper in this snapshot. Adapter/application retry policy remains explicit. [Upload implementation](https://github.com/vercel/ai/blob/45f2b6a5bc06bdb40a847ea961f8d7ca7cd86563/packages/ai/src/upload-file/upload-file.ts).
