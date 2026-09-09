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

The inspected CUA revision is
[`bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15`](https://github.com/trycua/cua/tree/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15).
It contains two useful surfaces. Pin and test each independently; a shared
repository does not make their command schemas or MCP protocol support identical.

1. **Computer Server:** optional Python sidecar with local HTTP `/cmd`, WebSocket
   `/ws`, status/discovery endpoints, and optional MCP `/mcp`. Use this for an
   initial typed `computer.v1` adapter without reimplementing OS automation.
   [Server documentation](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/python/computer-server/README.md).
2. **Cua Driver:** native Rust runtime with `cua-driver mcp` over stdio and an
   application SDK. Expose the configured stdio command through the MCP adapter
   as another supported backend profile. Evaluate direct Rust SDK embedding after
   lifecycle, distribution and OS permission attribution are proven. The inspected
   [Rust workspace](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/rust/Cargo.toml)
   declares `0.24.0`; this is not a claim that the release was installed or tested.
   [Driver integration documentation](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/README.md).

### Computer Server adapter

`POST /cmd` accepts `{"command":"screenshot","params":{}}`. In the inspected
[HTTP implementation](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/python/computer-server/computer_server/main.py#L763-L872),
the response is `data: <JSON>\n\n` framing with `text/plain` media type. Parse that
framing with byte/event limits; a successful HTTP status can still contain
`success:false`. Do not assume a normal JSON response or a conventional
`text/event-stream` response. Prefer one `/cmd` exchange per logical request.

The local [`/ws` implementation](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/python/computer-server/computer_server/main.py#L627-L760)
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

The [command registry](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/python/computer-server/computer_server/main.py#L393-L477)
also exposes shell, host files, clipboard, window management and other features.
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
upstream [auth availability tests](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/python/computer-server/tests/test_auth_availability.py)
explicitly preserve this behavior. Cloud mode uses CUA-specific container/API-key
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

Sources: [driver lifecycle and permissions](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/README.md),
[Windows runtime requirements](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/rust/Skills/cua-driver/WINDOWS.md#L471-L528),
[legacy Linux handler](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/python/computer-server/computer_server/handlers/linux.py#L1-L80),
[native platform crates](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/rust/README.md),
[backend selection](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/python/computer-server/computer_server/handlers/factory.py).

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
