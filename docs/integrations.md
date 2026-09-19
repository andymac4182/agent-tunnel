# Filesystem and computer-use integrations

Status: proposed integration contracts, researched on 2026-09-09. No adapter or upstream interoperability is implemented. Rust owns the relay, desktop CLI and privileged providers. A shared TypeScript filesystem client supplies native Files SDK, Mastra, AI SDK Files and just-bash adapters; the normative endpoint is in [filesystem-api.md](filesystem-api.md), and complete SDK mappings are in [filesystem-adapters.md](filesystem-adapters.md).

This document retains the detailed just-bash/9P and CUA compatibility research. [mcp.md](mcp.md) specifies MCP versions; [acp.md](acp.md) specifies host HTTP control of a CLI-supervised agent.

## Boundaries

```text
Agent in the cloud
  ├── Files SDK / Mastra / AI SDK Files / just-bash native adapter
  │     └── shared client: HTTP capability discovery + binary 9P2000.L WSS
  ├── computer.v1 API client → typed CUA operations
  ├── MCP client → selected MCP HTTP profile
  └── ACP HTTP client → request POST + streaming event GET
                   │
          Agent Tunnel Server (Axum)
                   │ optional private HTTP/3 peer hop with mTLS
          owning relay
                   │ control WS + draining/rotating data WS, both device mTLS
          desktop Rust CLI (initiates both outbound connections)
            ├── mount stream → confined Rust 9P2000.L provider
            ├── computer adapter → configured local CUA backend
            ├── MCP adapter → fixed stdio process or local HTTP service
            └── in-process ACP HTTP bridge → allowlisted ACP stdio agent
```

These are logical services multiplexed over the shared data transport. CUA's
optional local WebSocket is not another public tunnel control or data channel.
Remote callers select a registered device and service ID; they cannot supply a
host URL, filesystem root, executable, or process arguments.

Each logical mount/action stream is bound to the authenticated tenant, caller,
device, service and grant. The device rechecks its local policy. Register filesystem and
computer capabilities separately: permission to inspect a workspace does not
grant clipboard access or keyboard input. Scope desktop actions to an explicit
OS user session, since one physical device can have several logged-in users.

## just-bash compatibility target

The inspected revision is
[`062ce005c0a7676163852fb6f0c8590cbdaa1d45`](https://github.com/vercel-labs/just-bash/tree/062ce005c0a7676163852fb6f0c8590cbdaa1d45).
Its [package manifest](https://github.com/vercel-labs/just-bash/blob/062ce005c0a7676163852fb6f0c8590cbdaa1d45/packages/just-bash/package.json)
declares version `3.4.2`, Node `>=20.19`, and Apache-2.0. These describe the source
snapshot; published-package installation and interoperability remain release gates.

Implement the public
[`IFileSystem` contract](https://github.com/vercel-labs/just-bash/blob/062ce005c0a7676163852fb6f0c8590cbdaa1d45/packages/just-bash/src/fs/interface.ts),
then instantiate `Bash` with the adapter through its `fs` option. File I/O is
asynchronous. Two local bookkeeping methods, `resolvePath` and `getAllPaths`, are
synchronous and must never wait on the network. `getAllPaths` is required in the
type but explicitly permits an empty array. Start with that behavior and test
shell globbing against remote `readdir`; do not pretend a partial cache is a
complete listing.

### 9P over the consumer WebSocket

Proposed dialect: **9P2000.L**, with the operations needed by just-bash explicitly
tested. This dialect adds Linux-oriented metadata and link operations to the
original protocol. Reference the pinned
[diod protocol description](https://github.com/chaos/diod/blob/de51d1ee1bd5ccf1d8c16b96227c8bb03ec50106/protocol.md)
and [Linux v9fs documentation](https://docs.kernel.org/filesystems/9p.html).
Supporting this application profile does not yet claim general Linux kernel-mount
compatibility; locks, xattrs and other unused operations need separate certification.

The TS adapter opens an authenticated WebSocket to a registered filesystem service
on the relay. One WebSocket binary message carries one complete length-prefixed 9P
message; WebSocket fragmentation is reassembled before decoding. Reject text
messages, inconsistent lengths and oversized allocations. The relay carries these
bytes through a logical stream on the existing device data channel. This is a
filesystem protocol connection, not an HTTP filesystem RPC API or a host TCP mount.

Negotiate `Tversion/Rversion` with exactly `9P2000.L` and bounded `msize`; reject
unsupported dialects explicitly. Use `Tattach` to create the root fid for the
already-authorized mount. The caller's `uname`, `n_uname`, `gid`, or `aname` must
never confer OS privileges or select arbitrary host directories. Bind these fields
to the device's configured identity/root policy or reject mismatches. There is no
unauthenticated raw 9P listener. Authentication belongs to the WebSocket/tunnel
session; do not invent a 9P `Tauth` mechanism for relay bearer tokens.

Scope fids, tags and qid identities to the logical mount session. Allocate unique
live 16-bit tags, reserve `NOTAG` for version negotiation, and recycle tags only
after their reply or completed flush handling. Bound live fids and in-flight
requests; clunk fids in cleanup paths. Handle partial `Rwalk` success correctly.
A fid from another user, mount or dead session is never valid here.

Planned device data-channel rotation preserves the mount stream and its fid/tag
state. On actual consumer/session loss, close the mount and release its fids;
reconnect negotiates and attaches afresh. Do not silently replay outstanding
writes, appends, renames or removals. `Tflush` cancels a pending reply/operation
according to protocol rules; it does not prove that a mutation was rolled back.
Report an unknown outcome if delivery succeeded but its result cannot be recovered.

### just-bash to 9P2000.L mapping

| just-bash method | 9P exchange / adapter implementation |
| --- | --- |
| `readFile` | Resolve/walk, `Tlopen`, offset-based `Tread` chunks, `Tclunk`; decode bytes in TS |
| `readFileBuffer` | Same reads → `Uint8Array`; no UTF-8 round trip |
| optional `readFileBytes` | Same bytes converted to the upstream branded byte-string representation; otherwise use the upstream buffer fallback |
| `writeFile` | Existing file: `Tlopen` with truncation; absent file: `Tlcreate`; loop over short `Twrite` results, then `Tclunk` |
| `appendFile` | Open/create with supported Linux `O_APPEND` semantics; `Twrite`; never emulate append by stat-then-write |
| `exists` | Path resolution/`Twalk`; absent target → false, preserve denied/unavailable failures |
| `stat`, `lstat` | `Tgetattr`; TS resolver follows final symlink for stat, preserves it for lstat |
| `mkdir` | `Tmkdir`; compose parent creation for `recursive` |
| `readdir` | `Tlopen` directory + `Treaddir` using returned directory cookies; return names |
| optional `readdirWithFileTypes` | Same `Treaddir` records include entry types; use metadata fallback when needed |
| `rm` | `Tunlinkat`; compose bounded postorder traversal for recursive removal and handle force semantics |
| `cp` | Compose reads, creates, writes and directory traversal; 9P2000.L has no server-copy request |
| `mv` | `Trenameat` within one mount; explicit cross-root/device failure |
| `chmod` | `Tsetattr` mode valid-bit; reject unsupported permission semantics |
| `symlink`, `link` | `Tsymlink`, `Tlink`, only when the root provider permits links |
| `readlink`, `realpath` | `Treadlink`; realpath is bounded virtual resolution through walk/readlink |
| `utimes` | `Tsetattr` time and explicit-time valid-bits; convert Date into seconds/nanoseconds |
| `resolvePath` | Pure POSIX-style virtual-path normalization in TS |
| `getAllPaths` | Local `[]` initially, as permitted by the interface |

`readFileBytes` and `readdirWithFileTypes` are optional upstream; the remaining
table entries are required methods. An adapter can implement a method that
returns a documented unsupported-operation error on a restricted provider, but
we must publish that provider's capability profile rather than claim complete
filesystem compatibility. Read-only providers return `EROFS` for mutations.

Decode 9P little-endian 64-bit fields as `bigint`; never route them through JSON
numbers. Range-check conversions for just-bash's numeric size and `Date` fields;
fail explicitly when they cannot be represented. Use scoped qid identity rather
than leaking host inode/device identifiers. Honor the `Rgetattr` valid mask.
`FsStat` also needs file/directory/symlink flags, mode, size and modification time.
Translate `.L` Linux errno and open-flag values deliberately on every host OS;
native macOS/Windows constants are not interchangeable. File payloads remain bytes.
Encoding conversions belong in the adapter. Include
empty files, all byte values, Unicode, malformed UTF-8, base64 and hex fixtures.

### Filesystem semantics and isolation

The root provider maps a configured host directory to virtual `/`. Root selection
is part of the grant, not the request path. Reject NULs and unsupported path
forms. Normalize `..` according to the virtual filesystem contract; the upstream
[contract tests](https://github.com/vercel-labs/just-bash/blob/062ce005c0a7676163852fb6f0c8590cbdaa1d45/packages/just-bash/src/fs/interface.contract.test.ts)
clamp traversal above virtual `/` and keep absolute symlink targets virtual.
That lexical rule does not secure host access by itself. Use descriptor-relative,
capability-scoped operations, verify ancestor/link traversal during access, and
test concurrent symlink replacement. Never rely only on a string prefix check or
on `canonicalize` followed by a separate path-based open.

Block special device files, sockets and FIFOs. Hard links require explicit
policy: links to an inode also reachable outside the root can leak or modify
outside data without pathname traversal. Ship a restricted provider first, with
unsupported link operations clearly advertised, until those semantics are tested.
Bound bytes, directory entries, traversal depth, open operations and wall time.
Recursive copy/removal must have bounded work and cancellation points.

9P has no multi-request transaction or durable operation-status API. `writeFile`
can leave partial data on failure; do not call it an atomic upload. An eventual
opt-in atomic-replace helper could stage, fsync and rename, with its own documented
failure and link semantics. Rename atomicity remains limited to the underlying
filesystem. Cross-device/root moves fail explicitly. Copy traverses the consumer
connection; server-side copy would need a separately negotiated extension and is
not part of this baseline. Metadata caches are session-scoped and invalidated after writes;
external host changes mean no permanent read cache without a coherence mechanism.

just-bash executes the simulated shell in the consumer, and remote file operations
cross the tunnel. This does not require forwarding shell commands to the host.
Its [configuration documentation](https://github.com/vercel-labs/just-bash/blob/062ce005c0a7676163852fb6f0c8590cbdaa1d45/packages/just-bash/README.md)
exposes independent network and execution options; the example integration should
leave optional network, JavaScript and Python execution off initially.

## CUA compatibility targets

The pinned CUA artifact is the published distribution **`cua-computer-server`
0.3.46**, built from
[`c07d287af35cf37cfcf94290c46db2720ec47822`](https://github.com/trycua/cua/tree/c07d287af35cf37cfcf94290c46db2720ec47822/libs/python/computer-server).
[sources.md](sources.md#just-bash-and-cua) records the wheel and sdist digests,
the acquisition method and the Python requirement (3.12-3.13). The permalinks
below point at that release commit. They previously pointed at
`bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15`, a development commit whose manifest
declares 0.3.45; every `main.py` line range cited here is byte-identical between
the two, and `sources.md` records that reconciliation.

**There is one pinned profile, not two.** Earlier revisions of this section
listed a native Rust **Cua Driver** as a second candidate profile, citing a
workspace `Cargo.toml` that declares `0.24.0`. That premise was wrong and is
**withdrawn, not deferred**: `cua-driver` is not a published crate
(`index.crates.io` returns 404 for it, and 200 for a control crate from the same
host). It is an optional extra of the Python server — 0.3.46 declares
`driver = ["cua-driver>=0.22.2,<0.23.0"]`, a PyPI distribution, in a range that
excludes the `0.24.0` previously quoted — and is reached through the server's own
`computer_server/handlers/cua_driver.py` backend, behind the same `/cmd` surface.
Do not plan a separate stdio or Rust-SDK profile for it.

**Computer Server:** optional Python sidecar with local HTTP `/cmd`, WebSocket
`/ws`, status/discovery endpoints, and optional MCP `/mcp`. Use this for an
initial `computer.v1` adapter without reimplementing OS automation.
[Server documentation](https://github.com/trycua/cua/blob/c07d287af35cf37cfcf94290c46db2720ec47822/libs/python/computer-server/README.md).
`computer.v1` is an [`http-forward/1`](http-forwarding.md) profile carrying its
own schema, not a typed gateway of its own. Only `/cmd` is pinned; `/mcp`,
`/pty`, `/responses` and `/playwright_exec` are outside it.

### Computer Server adapter

`POST /cmd` accepts `{"command":"screenshot","params":{}}`. In the released
0.3.46
[HTTP implementation](https://github.com/trycua/cua/blob/c07d287af35cf37cfcf94290c46db2720ec47822/libs/python/computer-server/computer_server/main.py#L763-L872),
the response is `data: <JSON>\n\n` framing with `text/plain` media type. Parse that
framing with byte/event limits; a successful HTTP status can still contain
`success:false`. Do not assume a normal JSON response or a conventional
`text/event-stream` response. Prefer one `/cmd` exchange per logical request.
Both properties were confirmed against the released sdist, not only the
development tree; upstream's own auth-availability test asserts a 200 whose body
text contains `success`. Two further shapes the adapter must handle: the success
payload is `{"success": True, **result}`, so a handler result carrying its own
`success` key wins; and pre-dispatch failures — malformed body, missing or
unknown command, cloud auth — are raised as `HTTPException` and arrive as real
400/401 responses with **no** `data:` framing at all.

The local [`/ws` implementation](https://github.com/trycua/cua/blob/c07d287af35cf37cfcf94290c46db2720ec47822/libs/python/computer-server/computer_server/main.py#L627-L760)
processes commands sequentially and does not echo a tunnel request ID. If used,
allow one in-flight command per local socket and track correlation in the Rust
adapter. Rotation of the outer data WebSocket must leave the local operation
running. A reconnect must never repeat a click or typed text merely because its
result was lost.

| Proposed computer.v1 operation | Computer Server command |
| --- | --- |
| `describe` | Local configuration + `version`, `/commands`, explicit backend probes |
| `capture` | `screenshot`; normalize output into bounded binary image + dimensions |
| `screen_info`, `cursor_position` | `get_screen_size`, `get_cursor_position` |
| `click`, `double_click`, `move` | `left_click` / `right_click`, `double_click`, `move_cursor` |
| `drag`, `scroll` | `drag`, `scroll`; validate backend-specific coordinate and delta semantics |
| `type_text`, `press_key`, `hotkey` | Same command names; preserve keyboard layout behavior |
| `accessibility_tree` | `get_accessibility_tree`, only when backed by real supported data |

The [command registry](https://github.com/trycua/cua/blob/c07d287af35cf37cfcf94290c46db2720ec47822/libs/python/computer-server/computer_server/main.py#L393-L477)
also exposes shell, host files, clipboard, window management and other features.
All nine operations in the table above map to command names that 0.3.46 actually
registers, so the table is unchanged by the pin. Two released details it does not
capture: the registry is filtered by `backend_policy.exposed_command_registry`,
which under `CUA_BACKEND=vnc` narrows the map to a VNC-remote subset, so the
advertised set is backend-dependent and `/commands` must be read per backend
rather than assumed; and twelve aliases exist (`click`, `type`, `key`, `shell`,
`exec` and the file-command spellings). Send canonical names and do not depend on
alias resolution.
Do not forward arbitrary command names: the initial allowlist is the table above.
Our VFS has its own provider and confinement, rather than inheriting CUA's host
file commands. Capability discovery is the intersection of local configuration,
upstream backend support and the caller's grant. Unknown commands fail closed.

Use an exclusive input lease per target OS session to prevent two authorized
agents from interleaving keyboard/mouse actions. Screenshot reads may be shared
within the same permitted scope. Carry capture identity, coordinate dimensions,
display scale and target identity into subsequent actions, and reject stale or
mismatched capture coordinates. Preserve upstream permission-denied or unsupported
results; do not silently escalate scope, change backend, or steal focus.

### Authentication and platform limits

Computer Server defaults to `127.0.0.1`. In the inspected `/cmd` and `/ws` paths,
local mode does not require authentication when `CONTAINER_NAME` is absent; the
upstream [auth availability tests](https://github.com/trycua/cua/blob/c07d287af35cf37cfcf94290c46db2720ec47822/libs/python/computer-server/tests/test_auth_availability.py)
explicitly preserve this behavior. Those tests ship in the 0.3.46 sdist (not in
the wheel) and are byte-identical to the inspected tree's. They also record a
setting this section previously omitted: `UNAVAILABLE_WITHOUT_CONTAINER_NAME`,
which, when truthy with `CONTAINER_NAME` unset, makes the server answer 503 (or
`UNAVAILABLE_WITHOUT_CONTAINER_NAME_RESPONSE_STATUS_CODE`). A supervising device
must treat that 503 as "backend deliberately unavailable", not as a transient
fault to retry through. Cloud mode uses CUA-specific container/API-key
authentication (`X-Container-Name` and `X-API-Key` on `/cmd`), which is separate
from our relay identity and grants. Do not forward relay tokens into CUA or
advertise upstream cloud auth as generic local bearer-token protection.

Bind local backends to loopback and never publish their port through a generic
proxy. A shared host's untrusted local processes remain a separate trust concern:
run the sidecar under the intended OS user and isolate it where practical; verify
the configured endpoint belongs to that backend before advertising it. The device
agent enforces tunnel authorization before every local request. Credentials and
image/text payloads are excluded from routine logs.

| Platform/backend | Constraint that must appear in support documentation |
| --- | --- |
| macOS Cua Driver | Accessibility and Screen Recording depend on the responsible app identity. Use the supported installed app or embedded-host lifecycle; launching a raw daemon from an unrelated helper does not establish a stable production TCC identity. |
| Windows Cua Driver | Runtime must own an interactive user desktop, not service Session 0. UIAccess, elevation and foreground restrictions affect operations. |
| Linux legacy Computer Server | Its native handler describes X11/Xvfb capture and returns a simulated accessibility tree; do not claim full accessibility support. |
| Linux Cua Driver | Separate native AT-SPI/X11/Wayland implementation; certify supported desktop/backend combinations independently. |
| VNC Computer Server | Screen/pointer/keyboard only; host shell, files, PTY, browser and window surfaces are refused by upstream policy. |
| Computer Server with Cua Driver backend | Separate held-key/mouse-down/up calls are unsupported; capture scope and escalation policy are explicit. Android is not supported by this backend. |

Sources that ship in the pinned 0.3.46 distribution:
[legacy Linux handler](https://github.com/trycua/cua/blob/c07d287af35cf37cfcf94290c46db2720ec47822/libs/python/computer-server/computer_server/handlers/linux.py#L1-L80),
[backend selection](https://github.com/trycua/cua/blob/c07d287af35cf37cfcf94290c46db2720ec47822/libs/python/computer-server/computer_server/handlers/factory.py),
[Cua Driver backend handler](https://github.com/trycua/cua/blob/c07d287af35cf37cfcf94290c46db2720ec47822/libs/python/computer-server/computer_server/handlers/cua_driver.py).

Sources that do **not** ship in it, and so are monorepo reading rather than
pinned artifact — left at the 2026-09-09 development commit and not repointed,
because no release commit of ours governs them:
[driver lifecycle and permissions](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/README.md),
[Windows runtime requirements](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/rust/Skills/cua-driver/WINDOWS.md#L471-L528),
[native platform crates](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/rust/README.md).
The platform limits they support are unverified against any released artifact.

## Integration acceptance gates

1. **Contract CI:** pin just-bash, compile `TunnelFileSystem` against its public
   interface, exercise filesystem behavior against Rust fixtures, and run a real
   `Bash({ fs })` workflow that lists, searches, reads and modifies fixture files.
   Cover links, timestamps, binary data, globbing, root traversal and access errors.
   Add 9P codec golden vectors, partial walks, short writes, tag/flush races, fid
   exhaustion, errno translation, directory cookies and mount cleanup. Validate
   the actual just-bash → WebSocket → relay → device → 9P filesystem path.
2. **Transport CI:** use a CUA fixture server with the observed `/cmd` framing and
   sequential `/ws` behavior. Verify result correlation, malformed/oversized
   responses, HTTP success with command failure, cancellation, and unknown outcome
   after input was delivered. Include capture responses spanning data rotation.
3. **Isolation CI:** two tenants and several devices with identical service names;
   deny cross-tenant files/screens/actions, revoked grants, unregistered endpoints,
   and shell/clipboard requests outside the computer allowlist. Verify input leases.
4. **Real backend gates:** run pinned CUA in disposable GUI VMs with known test
   applications. Capture a fixture window, click a known control, type a unique
   marker and independently verify the resulting UI state. Grant OS permissions
   deliberately during runner provisioning. Never run these jobs on a developer's
   active desktop or an arbitrary shared CI runner.
5. **Compatibility releases:** record upstream commit, installed artifact version,
   OS/backend, permissions, command schema and MCP profile. Test one stable backend
   profile before expanding support. CI fixtures validate protocol handling; only
   real upstream runs justify an interoperability claim. See [testing.md](testing.md).
