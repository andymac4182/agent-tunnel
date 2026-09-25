# Demo: a remote filesystem through a local relay

Status: written for task row M4-54 on 2026-09-26 on branch `feat-fs-demo`.
Everything below runs on one machine with shipped binaries and the shared
TypeScript client. The consumer never talks to the device directly: every byte
goes consumer → relay → device and back.

```text
packages/client (node)                 tunnel-relay serve              tunnel-client connect
  connectFilesystem ──HTTPS descriptor──▶ consumer listener
  just-bash Bash     ──WSS 9P2000.L─────▶ (bearer token)   ──mTLS WSS──▶ export root (read + list)
  Mastra Workspace                        Redis catalog (TLS)
```

## What it shows

1. A device exports a **synthetic directory** (six files, four directories, an
   escaping symlink) with a `read` + `list` grant.
2. The **shared client** (`connectFilesystem`) fetches the descriptor, upgrades
   to `agent-tunnel.9p.v1` with a bearer token, then lists, stats, reads and
   walks the whole tree.
3. A real **just-bash** `Bash` (3.4.2) over `TunnelJustBashFilesystem` runs
   `ls`, `find`, `cat | wc -l` and `md5sum` against the remote export.
4. A real **Mastra** `Workspace` (`@mastra/core` 1.65.0) over
   `TunnelMastraFilesystem`, using Mastra's own error classes, lists the tree
   recursively, stats and reads a file, and answers `exists`.
5. A real **Files SDK** `Files` (`files-sdk` 2.4.0) over `createFilesAdapter`
   lists every key, then `head`s and downloads a 200 KiB binary file.
6. The export **refuses** what the grant does not allow: a write (shared
   client, Mastra, Files SDK and a bash redirection), a path climbing out of
   the export, and a symlink that points outside it.
7. **Revocation of a live session.** With the consumer's session still open,
   the operator runs `tunnel-relay revoke-grant`; the consumer's next
   operation fails `AUTH_EXPIRED`, its socket is closed **1008 by the relay**
   within the 5-second authorization snapshot, and a fresh descriptor request
   for the same subject gets 404 (the export is no longer disclosed to it).
8. The script **checks the consumer's report against the host directory**:
   every file's SHA-256 (shared client) and MD5 (just-bash `md5sum`), the
   Mastra listing, and that the host export is unchanged.

## Prerequisites

- Rust toolchain from `rust-toolchain.toml` (for `cargo build`), or prebuilt
  `tunnel-relay` and `tunnel-client` in one directory.
- Node 24 (`packages/client/.node-version`) and npm. The script runs `npm ci`
  in `packages/client` once if `just-bash` or `@mastra/core` is missing.
- `openssl`, `python3`, `curl`.
- A Redis. The relay refuses a plaintext Redis, so the script offers three
  ways, in this order of preference:
  - `DEMO_PLAINTEXT_REDIS=127.0.0.1:6379` — a local plaintext Redis you already
    run; the script fronts it with a small TLS terminator of its own (no
    Docker) and deletes its namespace's keys on exit;
  - nothing set — Docker starts a disposable TLS-only `redis:8.4.0-alpine`;
  - `DEMO_REDIS_URL=rediss://host:port/db` with `DEMO_REDIS_CA=/path/to/ca.pem`
    — your own TLS Redis.

## Run it

From the repository root:

```sh
scripts/fs-demo.sh
```

With binaries you already built (for example with a per-worktree
`CARGO_TARGET_DIR`):

```sh
DEMO_BIN_DIR="$CARGO_TARGET_DIR/debug" scripts/fs-demo.sh
```

Options:

| Variable | Effect |
| --- | --- |
| `DEMO_BIN_DIR` | Use `tunnel-relay` and `tunnel-client` from this directory instead of building |
| `DEMO_PLAINTEXT_REDIS` | `host:port` of a plaintext Redis to front with the script's TLS terminator (no Docker) |
| `DEMO_REDIS_URL`, `DEMO_REDIS_CA` | Use an existing TLS Redis instead of starting a container |
| `DEMO_REDIS_IMAGE` | The Redis image for the disposable container (default `redis:8.4.0-alpine`) |
| `DEMO_KEEP=1` | Keep the work directory (keys, configs, logs, the export) after the run |
| `DEMO_NEGATIVE_CONTROL=1` | Change one host file after the consumer read it; the run must end `FAILED` |
| `DEMO_NEGATIVE_CONTROL=revoke` | Signal the consumer without revoking its grant; the run must end `FAILED` |

It takes about 20 seconds after the build. Every key, certificate, config and
the exported directory live in a fresh `mktemp -d` directory outside the
repository; the relay, the device and the Redis container are stopped and
removed on exit, whatever the outcome.

## What the script does, step by step

Each step uses the same commands [operator.md](../operator.md) and
[join-relay.md](../join-relay.md) document:

| Step | Command |
| --- | --- |
| Relay listener CA and leaf (`127.0.0.1`, `localhost`), device CA, issuer key and JWKS | `openssl` |
| Device key and CSR | `tunnel-client credentials create --config client.toml --csr-out device.csr` |
| Device certificate with `URI:urn:agent-tunnel:device:<id>` | `openssl x509 -req` |
| Certificate import | `tunnel-client credentials import --certificate device-cert.pem --server-ca relay-ca.pem` |
| Relay config check | `tunnel-relay check-serve-config --config relay.toml` |
| First incarnation | `tunnel-relay activate-first-incarnation --config relay.toml` |
| Tenant, user, device, `fs` service, `read`+`list` grant | `tunnel-relay provision-catalog --config relay.toml --records catalog.toml` |
| Relay | `tunnel-relay serve --config relay.toml` (waits for `/readyz`) |
| Device | `tunnel-client connect --config client.toml` with an `[exports.<service>.fs]` table, `capabilities = ["read", "list"]` |
| Consumer token | an RS256 JWT with `scope: "fs:connect"`, signed by the demo issuer key, written to a `0600` file (never on a command line) |
| Consumer | `node packages/client/demo/filesystem-demo.ts` with `NODE_EXTRA_CA_CERTS=relay-ca.pem` |
| Revocation, while the consumer's session is live | `tunnel-relay revoke-grant --config relay.toml --tenant T --user U --device D --service S` |

The consumer endpoint is
`https://127.0.0.1:<port>/v1/devices/<device>/services/<service>/fs`: a `GET`
returns the `agent-tunnel.fs.v1` descriptor, and the client upgrades the same
URL to a WebSocket carrying 9P2000.L.

## Expected output

Trimmed; UUIDs, ports, the nonce and the README hash vary per run.

```text
fs-demo nonce=fs-demo-20260925T131315Z-97510 head=... uncommitted_paths=0
ok binaries: .../tunnel-relay, .../tunnel-client
ok disposable Redis container fs-demo-redis-97510, TLS only, on 127.0.0.1:54107
ok export root with 6 files, 4 directories and one escaping symlink
ok device ... enrolled; its key never left .../device
Provisioned namespace fs-demo-... service_type=fs fs_case_sensitivity=insensitive-preserving ... grant_operations=fs:connect,fs:list,fs:read.
ok relay ready: consumer https://127.0.0.1:54130, device wss://127.0.0.1:54131
ok device connected; descriptor GET https://127.0.0.1:.../fs -> 200, availability online
descriptor: schema=agent-tunnel.fs.v1 root.readOnly=True operations=readDirectory,readFile,readStream,realpath,stat
ok an unprovisioned subject is refused: HTTP 401

== 1. shared client: connectFilesystem through the relay
connected: msize=65536 availability=online
root.readOnly=true caseSensitivity=insensitive-preserving

== 2. shared client: list, stat, read and walk
ls /
  d data
  d docs
  d empty-dir
  - README.md
  /data/blob.bin  204800 bytes sha256=3a419cbb0accd5c9…
  /data/numbers.csv  9088 bytes sha256=009f312fb4df2060…
  ...
walked 10 entries (6 files)

== 3. just-bash: a real Bash over the remote export
$ find / -type f | sort | xargs md5sum   (exit 0)
  7187ed1abd931ef095fe72afb3fd0e31  /data/blob.bin
  6020c7e4d3bca3a3538364554e5a8320  /data/numbers.csv
  ...

== 4. Mastra: Workspace over TunnelMastraFilesystem
readdir / recursive: 10 entries
stat /data/numbers.csv: type=file size=9088
exists /missing.txt: false

== 5. Files SDK: new Files({ adapter }) over createFilesAdapter
list: 6 keys
head data/blob.bin: size=204800; download sha256=3a419cbb0accd5c9…

== 6. what the export refuses
write /new.txt (read-only grant): refused ENOTSUP outcome=not_started
read /../outside.txt (climbs out of the export): refused PathRefusal:PATH_DOTDOT_COMPONENT
read /escape-link (symlink to a file outside the export): refused ELOOP outcome=not_started
mastra writeFile /new.txt: refused TUNNEL_ENOTSUP
files-sdk upload new.txt: refused Provider
bash: echo synthetic > /new.txt: refused TunnelFilesystemError: ENOTSUP (writeFile)

== 7. revocation under a live session
session live; waiting for the operator to revoke the grant
after revoke-grant: operation refused AUTH_EXPIRED after 238 ms; socket closed 1008 by the relay; state=closed

closed the session
  Revoked grant in namespace fs-demo-...: ... revision=2. New requests are refused now; a stream already admitted ends within its 5 s authorization snapshot.
descriptor for the revoked subject: HTTP 404

== checks against the host directory
ok shared client walked every file: 6 of 6
ok shared client walked every directory: 4 of 4
ok every file's size and SHA-256 read through the relay equals the host's: 6 of 6 match
ok the escaping symlink is never followed: not walked as a file or directory
ok just-bash find lists every file: exit 0, 6 files
ok just-bash md5sum of every file equals the host's: 6 of 6 match
ok just-bash pipeline cat | wc -l: 3
ok Mastra recursive readdir lists the tree: 10 entries
ok Mastra stat and readFile of /data/numbers.csv equal the host's
ok Files SDK list returns every key: 6 keys
ok Files SDK head and download of data/blob.bin equal the host's: 204800 bytes
ok revoking the grant ends the live session with 1008 (AUTH_EXPIRED) within the 5 s snapshot: code=AUTH_EXPIRED close=1008 after 238 ms
ok the revoked subject gets no new descriptor (the export is not disclosed): HTTP 404
ok refused: ... (six lines)
ok the descriptor reports a read-only root
ok the host export is unchanged by the refused writes
ok device still connected after the consumer closed its session
fs-demo: PASS nonce=...
cleanup: stopped relay, device and Redis; removed ... (exit=0)
```

The synthetic symlink `escape-link` is **not listed** by the device (the
`symlinks` feature is off, so a link is neither served nor enumerated), and
reading it by name is refused `ELOOP` before anything outside the export is
opened. The write refusals are `not_started`: the shared client refuses a write
the descriptor does not advertise before a byte is sent, and the device would
refuse it again (`EPERM`) if a custom client sent one anyway.

On Linux the case line reads `fs_case_sensitivity=sensitive`; the script
chooses it from `uname`.

## Proving the checks can fail

```sh
DEMO_NEGATIVE_CONTROL=1 scripts/fs-demo.sh; echo "exit=$?"
```

appends one byte to the host's `/docs/notes.txt` after the consumer has read
it. The run must end with exactly these two failures and exit 1:

```text
FAILED every file's size and SHA-256 read through the relay equals the host's: 5 of 6 match; mismatched ['/docs/notes.txt']
FAILED just-bash md5sum of every file equals the host's: 5 of 6 match
FAILED consumer report disagrees with the host directory
exit=1
```

```sh
DEMO_NEGATIVE_CONTROL=revoke scripts/fs-demo.sh; echo "exit=$?"
```

signals the consumer without running `revoke-grant`. It must end with at
least these failures and exit 1:

```text
FAILED revoking the grant ends the live session with 1008 (AUTH_EXPIRED) within the 5 s snapshot: ...
FAILED the revoked subject gets no new descriptor (the export is not disclosed): HTTP 200
FAILED consumer report disagrees with the host directory
exit=1
```

## Failure recovery

| Symptom | Cause and fix |
| --- | --- |
| `FAILED prerequisite: 'node' is not on PATH` | Install Node 24 (`packages/client/.node-version`). |
| `npm ci` fails | The client's dev dependencies are exact-pinned in `packages/client/package-lock.json` and need the npm registry once. Run `cd packages/client && npm ci` by hand to see the error. |
| `FAILED Redis did not start`, or the run stalls at `== Redis (TLS only)` | Docker is not running, is overloaded, or the image is missing (`docker pull redis:8.4.0-alpine`). Run without Docker: `DEMO_PLAINTEXT_REDIS=127.0.0.1:6379 scripts/fs-demo.sh` against any local Redis. |
| `FAILED revoke-grant exited ...` | The script prints its output; the relay config or the namespace is wrong, which the earlier provisioning steps would normally have caught. |
| `Redis catalog connection failed; stage=... class=tls_certificate` from `activate-first-incarnation` | `DEMO_REDIS_CA` does not sign the Redis server certificate, or the URL's host is not in its SANs. |
| `FAILED relay exited before it was ready` | The script prints `relay.log`. A port clash is the usual cause; rerun (ports are picked fresh each run). |
| `FAILED the export never came online (last descriptor HTTP 503)` | The device did not connect. The script prints the device and relay logs; a `CREDENTIAL_ERROR` means the certificate's device SAN does not match `device_id`. |
| `FAILED consumer exited 1` | The script prints the consumer's stderr, which names the failing error code (for example `UNAUTHENTICATED` for a token the relay refused). |
| A run interrupted with Ctrl-C | The `EXIT` trap still stops the relay, the device and the container. If a container named `fs-demo-redis-<pid>` survives a `kill -9`, remove it with `docker rm -f fs-demo-redis-<pid>`. |

To look around after a run, use `DEMO_KEEP=1`: the work directory holds
`relay.toml`, `device/client.toml`, `device/catalog.toml`, `relay.log`,
`device.log`, `consumer.out` and `result.json` (the consumer's report).

## Limits of this demo

- **Read-only.** The grant is `read` + `list`. Write grants exist and are
  verified by `verify-m4-fs-write-path` (M4-12), but a writable demo is not part
  of this recipe; see task row M4-04 for what keeps that row open.
- **One relay.** A filesystem session is admitted only at the owning relay
  (task row M4-06, peer hop).
- **The AI SDK `FilesV4` view** is not driven here (it manages upload
  references and needs a write grant); the shared client, just-bash, Mastra
  and Files SDK are (task row M4-05).
- The consumer token is minted by the script's own issuer key; a real
  deployment uses its identity provider.
