# Demo: the four native adapters through a local relay

One local relay, one device exporting a synthetic directory, and one consumer
that makes **one** connection with the shared TypeScript client
(`packages/client`) and lends it to all four native adapters. Every byte goes
device → relay → consumer; nothing reads the export directly.

```
packages/client/demo/adapters-demo.ts (node)
    --HTTPS + WSS, bearer token-->  tunnel-relay serve
    --mTLS device WebSocket-->      tunnel-client connect  -->  the exported directory
```

| Adapter | Framework, exact pin | What the demo does through the framework's own API |
| --- | --- | --- |
| Files SDK | `files-sdk` 2.4.0 | `new Files({ adapter: createFilesAdapter(...) })`: paginated `list`, `head`, `download` (hashed), `upload`, `exists`, `upload` then `delete` |
| just-bash | `just-bash` 3.4.2 | `new Bash({ fs: new TunnelJustBashFilesystem(...) })`: `ls`, `find` piped to `xargs md5sum`, `cat` piped to `wc -l`, `grep -c`, and an `echo >` redirect that writes on the device |
| Mastra | `@mastra/core` 1.65.0 | an `Agent` whose `Workspace` is `TunnelMastraFilesystem`; a scripted model calls the workspace's own `mastra_workspace_list_files`, `mastra_workspace_read_file` and `mastra_workspace_write_file` tools |
| AI SDK | `ai` 7.0.94, `@ai-sdk/provider` 4.0.11 | the real `generateText` tool loop over `createFilesystemTools` (`list_directory`, a bounded and truncated `read_file`, `stat`, `write_file` twice — the second refused as `EEXIST`); then `FilesV4` through the real `ai.uploadFile`, with `getFileMetadata` and `downloadFile` |

**No LLM and no API key.** Both agents use `MockLanguageModelV4` from `ai/test`
driven by a script (`packages/client/demo/scripted-model.ts`): the script
decides which tool to call; the framework does everything else for real —
offers the tools, validates the input against each tool's schema, calls
`execute`, and feeds the result into the next step.

## Prerequisites

- `cargo` (Rust 1.95.0 from `rust-toolchain.toml`), `node` ≥ 24 (24.21.0 is
  pinned in `packages/client/.node-version`), `npm`, `openssl`, `python3`,
  `curl`.
- `docker`, for a disposable TLS-only Redis (`redis:8.4.0-alpine`) — or set
  `DEMO_REDIS_URL` (a `rediss://` URL) and `DEMO_REDIS_CA`.
- Free disk for a debug build of `tunnel-relay` and `tunnel-client`.

## Run it

From the repository root:

```sh
scripts/adapters-demo.sh
```

or, from `packages/client`, `npm run demo:adapters`. To reuse a prebuilt pair
of binaries instead of building:

```sh
DEMO_BIN_DIR=/path/to/target/debug scripts/adapters-demo.sh
```

The script:

1. builds `tunnel-relay` and `tunnel-client` (`cargo build --locked`) and runs
   `npm ci` in `packages/client` if the four frameworks are not installed;
2. generates a relay CA and listener certificate, a device CA, and an identity
   issuer key with its JWKS, all in a temporary directory outside the
   repository;
3. starts a disposable TLS-only Redis container;
4. writes the synthetic export — `README.md`, `docs/notes.txt`,
   `docs/guide/chapter-1.md`, `data/numbers.csv` (500 rows),
   `data/blob.bin` (200 KiB, byte *i* = *i* mod 251) and empty `outbox/` and
   `uploads/` directories;
5. enrols the device (`tunnel-client credentials create` / `import`), with
   an fs export whose capabilities are `read`, `write`, `list`, `delete`;
6. provisions the catalog (`tunnel-relay activate-first-incarnation`,
   `provision-catalog`) with a grant of `fs:connect`, `fs:read`, `fs:list`,
   `fs:write`, `fs:delete`, starts `tunnel-relay serve` and
   `tunnel-client connect`, and waits for the descriptor to say `online`;
7. checks that an unprovisioned subject is refused `401`;
8. runs the consumer, `packages/client/demo/adapters-demo.ts`, with the relay
   CA in `NODE_EXTRA_CA_CERTS` (TLS verification is never disabled) and the
   token read from a file, never from argv;
9. checks the consumer's report against the **host directory's own bytes** with
   `scripts/adapters-demo-check.py`.

Everything it started — relay, device, Redis container, key directory — is
stopped and removed on exit. `DEMO_KEEP=1` keeps the work directory
(`relay.log`, `device.log`, `consumer.out`, `consumer.err`, `result.json`).

## Expected output

A transcript per adapter, then one line per check. Abridged from a run at
`5dc41f7` on macOS arm64:

```
== AI SDK 7.0.94: generateText over createFilesystemTools, scripted model
  tools offered on step 1: ["list_directory","read_file","stat","write_file"]
  tool list_directory({"path":"/data"})
    -> {"ok":true,"path":"/data","entries":[{"name":"blob.bin","kind":"file"},{"name":"numbers.csv","kind":"file"}],"truncated":false}
  tool read_file({"path":"/data/numbers.csv","maxBytes":64})
    -> {"ok":true,"path":"/data/numbers.csv","encoding":"utf8","content":"n,square,cube\n1,1,1\n…","bytesReturned":64,"truncated":true}
  tool stat({"path":"/data/blob.bin"})
    -> {"ok":true,"path":"/data/blob.bin","kind":"file","size":"204800","modifiedAt":"…"}
  tool write_file({"path":"/outbox/ai-sdk.txt","content":"Written by an AI SDK tool call.\n"})
    -> {"ok":true,"path":"/outbox/ai-sdk.txt","bytesWritten":32,"outcome":"applied"}
  tool write_file({"path":"/outbox/ai-sdk.txt","content":"second attempt"})
    -> {"ok":false,"code":"EEXIST","outcome":"failed","retrySafe":true}
  model text: Saw 5 tool results.

== checks against the host directory
ok descriptor advertises a writable grant: appendFile,chmod,copy,mkdir,readDirectory,readFile,readStream,realpath,remove,stat,utimes,writeFile,writeStream
ok Files SDK list() returns every seeded key: 5 of 5
ok Files SDK download() of /data/blob.bin: size and SHA-256 equal the host's: 204800 bytes
ok just-bash find | xargs md5sum equals the host's MD5 of every file: 4 of 4 match
ok Mastra Agent called list_files, read_file and write_file through the Workspace: …
ok AI SDK read_file returned exactly the first 64 host bytes and said truncated
ok FilesV4 upload is one file on the device's disk whose SHA-256 equals the download's: 1 file(s) in /uploads
ok the export holds exactly the seed files plus the demo's writes: 10 files
ok device still connected after the consumer closed its session
adapters-demo: PASS nonce=adapters-demo-…
```

There are 28 `ok` checks in all. The last line is `adapters-demo: PASS` and
the exit status is 0.

### Proving the checks can fail

```sh
DEMO_NEGATIVE_CONTROL=1 scripts/adapters-demo.sh   # must exit 1
```

appends one byte to the host's `/data/blob.bin` and `/docs/notes.txt` after
the consumer has read them. Four checks must turn `FAILED` — the Files SDK
`head` size and `download` digest, the just-bash `md5sum` comparison and the
AI SDK `stat` size — and the script exits 1.

## Checks without a relay

The same adapters against the package's loopback harness, which speaks the
wire but is **not** the relay or a device:

```sh
cd packages/client
npm ci
npm run check     # lint, typecheck, build, npm test, npm run test:peers
```

`npm test` needs no install (the adapters import their frameworks by type
only). `npm run test:peers` hands each adapter to the real framework — including
the real `generateText` loop and a real Mastra `Agent` with a scripted model.

## Failure recovery

| Symptom | Cause and fix |
| --- | --- |
| `FAILED prerequisite: 'docker' is not on PATH` | Start Docker, or pass `DEMO_REDIS_URL` and `DEMO_REDIS_CA` for an existing TLS Redis. |
| `Redis did not start` | The image could not be pulled or the port was taken; re-run (the port is chosen fresh each time), or set `DEMO_REDIS_IMAGE`. |
| `relay exited before it was ready` | The script prints `relay.log`. Usually a stale binary: rebuild, or point `DEMO_BIN_DIR` at a current `target/debug`. |
| `the export never came online` | The device could not connect; the script prints `device.log`, `relay.log` and the last descriptor. Check that nothing is intercepting `127.0.0.1`. |
| `consumer exited N` | The script prints the tail of `consumer.err`. `Cannot find package 'files-sdk'` (or another framework) means `npm ci` in `packages/client` did not complete. `INSECURE_ENDPOINT` means the relay CA was not trusted — do not work around it with `NODE_TLS_REJECT_UNAUTHORIZED=0`; the consumer refuses to run that way. |
| A `FAILED` check | The consumer's view of the export disagrees with the host's bytes. Re-run with `DEMO_KEEP=1` and compare `result.json` with the kept `device/export`. |
| Interrupted run left a container | `docker rm -f $(docker ps -aq --filter name=adapters-demo-redis-)` |

## What this demo does not show

- **A rotating device tunnel.** The run is shorter than one 300-second data
  rotation; framework clients across a rotation remain open under M4-05.
- **Hosted CI.** The demo is local evidence on macOS arm64. It is not a CI job.
- **Limits at their advertised value and one beyond** (M4-21), and two
  consumers with different users against one export.
- **Real model behaviour.** The scripted model always picks the scripted tool;
  what a real model would call, and how it reads a `retrySafe: false` result,
  is not demonstrated.
- **The alternative AI SDK bindings** named in
  [filesystem-adapters.md](../filesystem-adapters.md#live-directory-tools) —
  filtered `files-sdk/ai-sdk` factories and a `bash-tool` wrapper — are not
  implemented; `createFilesystemTools` is the binding this demo uses.

The relay, PKI, Redis and enrolment steps are the same as the single-adapter
filesystem demo's `scripts/fs-demo.sh` (task row M4-54, another branch); this
script differs in the grant, the export and the consumer. Folding the shared
setup into one helper once both have merged is task row M4-67.
