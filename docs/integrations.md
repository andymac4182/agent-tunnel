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
declares 0.3.45. `main.py` is byte-identical between the two, so every line range
cited here still holds; `handlers/cua_driver.py` is **not** identical, and
`sources.md` records that reconciliation in full.

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
The reason a 200 can carry a failure is structural, not incidental: the success
and error payloads are both yielded from one generator inside a
`StreamingResponse`, so the status is committed **after the response has begun**
and before the command's outcome is known. Read the payload, never the status, to
decide whether a command succeeded. Both properties were **read from the source
in the released sdist**, not only from the development tree, and neither has been
observed on a socket; upstream's own auth-availability test asserts a 200 whose
body text contains `success`. Two further shapes the adapter must handle: the success
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
rather than assumed; and twelve aliases exist (`click` and `tap`, `type`, `key`,
`shell`, `exec`, and the six file-command spellings `read_file`, `write_file`,
`ls`, `mkdir`, `rm`, `rmdir`). Send canonical names and do not depend on alias
resolution.
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

**Both the command names and the parameter names above are pinned.** M5-01 read
the released registry and recorded which commands 0.3.46 accepts, which is what
`tunnel_http_forward::cua_pin::ALLOWED_COMMANDS` carries. M5-C06 then read
`computer_server/handlers/base.py` — pinned separately as
`cua_pin::BASE_PY_SHA256` — and recorded each command's parameter schema in
`cua_pin::COMMAND_PARAMETERS`, which `scripts/m5-cua-refetch.sh` re-derives from
the re-fetched source rather than comparing against itself.

Reading it corrected two spellings this repository had chosen and shipped.
`drag` takes `path: List[Tuple[int, int]]`, not the `start_x`/`start_y`/
`end_x`/`end_y` members the adapter used to send, which exist on no backend.
`scroll` takes `x`/`y` as wheel **amounts**, not a position, so the `dx`/`dy`
members were discarded and the cursor coordinate was scrolled by instead — the
silent half, and the reason a pinned command name with unpinned parameter names
is a half-pin. The released dispatcher drops any member its handler does not
declare, with no error and no log.

What is **not** measured is any real backend: nothing has been probed, and the
table's own "validate backend-specific coordinate and delta semantics" still
stands as a warning about semantics rather than names. Three consumer-facing
consequences of the pin were closed on `m5-code` without a desktop, each
against the pinned 0.3.46 source rather than a probe:

- **Display selection (M5-C12).** No pinned handler declares a display, so
  `capture` and `screen_info` accept only the backend's default display
  (`tunnel_cua::schema::SELECTABLE_DISPLAYS`). Any other index is refused
  before dispatch with `NotDispatched::DisplayNotSelectable` instead of being
  answered from the default display under the requested label. `display` is
  still sent, always `0`, knowing no backend declares it
  (`cua_pin::PARAMETERS_KNOWINGLY_DISCARDED`).
- **`scroll` takes no position (M5-C13).** Every pinned backend scrolls at the
  cursor. The consumer schema used to take a capture and a point, bounds-check
  the point and then drop it; it now takes `dx`/`dy` only, and a request naming
  a position is refused. A consumer that wants a position sends `move` first.
  The sign is pinned beside the names: **positive `dy` scrolls up**, as the
  macOS, Windows and VNC handlers state and the Linux (`scroll_up`/
  `scroll_down`) and Cua Driver handlers fix in code
  (`cua_pin::SCROLL_SIGN_CONVENTION`); only Android, which maps the amount
  onto a swipe, is inferred. On the Cua Driver backend a non-zero `dy`
  silently drops `dx`, and `dx = dy = 0` is a dispatched failure.
- **Capture identity from what the server sends (M5-C14).** A released
  `screenshot` answers `{success, image_data, format}` (VNC omits `format`) and
  never sends `width`, `height` or a scale. The device reads the dimensions
  from the PNG's `IHDR` (`tunnel_cua::image`), and takes the display scale
  only from an explicit device declaration; with none, every coordinate on that
  capture is refused with `CaptureRefusal::ScaleUndeclared` rather than
  defaulted to 1x. The server cannot supply the scale: the macOS handler
  resizes any capture wider than 1,920 px before encoding it, and its
  `get_screen_size` reports the `ImageGrab` pixel size, so image width over
  screen width measures that resize, not the point scale (and whether the
  `ImageGrab` pixel size equals the input point space on a HiDPI display is
  itself unmeasured). Where a real device
  gets the declaration from is an owner decision that needs a probe (M5-C02).

### The device export (Lane B)

`tunnel-client` serves a `computer-v1` export only in a build with the
non-default `cua` feature, and only when `AGENT_TUNNEL_CUA_LANE_B=1` is set
(task row M5-C21); the relay routes the profile like MCP and ACP. The export
supervises the backend (above), probes it read-only, negotiates the
intersection of its `[exports.<id>.cua]` operations, the backend's
`/commands` and the caller's grant, and answers through the device-side
facade. Three wire-level facts from the first run against the real server:
`/commands` is an object keyed by command name (M5-C27), `/cmd` over HTTP/1.1
is `Transfer-Encoding: chunked` (M5-C22), and a stock client's `accept` is
dropped at the ingress for this profile (M5-C26).

- **Sessions** are keyed by the relay's opaque principal binding, so each
  authenticated principal has its own input lease and capture identities.
- **A request with no principal binding is refused**
  (`principal_binding_missing`, not retryable). It is never given a shared
  session.
- **Two provisional `computer.v1` operations carry the lease** (M5-C20; the
  owner decision on whether they move into the pure schema is still open):

  | Operation | Request `params` | Answer |
  | --- | --- | --- |
  | `acquire_input_lease` | `{}` (may be omitted; nothing else allowed) | `answered_locally`, `result: {"held": true, "lease": <id>, "target": <name>}`; or `not_dispatched` with `lease_held_by_another_session`, retryable |
  | `release_input_lease` | `{}` | `answered_locally`, `result: {"held": false, "lease": null, "target": <name>}`; or `not_dispatched` with `lease_not_held`, retryable |

  Both are answered from device state before the schema sees the body, and
  never reach the backend. An input operation never takes the lease itself:
  without it, input is refused with `lease_not_held`. The lease belongs to the
  principal binding's session, and there is no idle expiry (M5-C29).
- **The display scale** comes from a declared point space (`point_width`,
  `point_height`; M5-C19 option (b), applied by default pending owner
  confirmation). Each capture's ratio is derived from its own PNG, and a
  declaration that the capture or the backend's `get_screen_size`
  contradicts refuses every coordinate.

The recipe, run against a Linux guest, is [docs/demo/cua.md](demo/cua.md).

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
This last file is the one place the released artifact differs behaviourally from
the 2026-09-09 development tree: it makes `desktop_capture_authorized`
conditional on `hasattr`, so on the supported 0.22.x SDK the released server
**omits that key** from session state rather than failing. Treat capture
authority as absent-by-default, not as false.

Sources that do **not** ship in it, and so are monorepo reading rather than
pinned artifact — left at the 2026-09-09 development commit and not repointed,
because no release commit of ours governs them:
[driver lifecycle and permissions](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/README.md),
[Windows runtime requirements](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/rust/Skills/cua-driver/WINDOWS.md#L471-L528),
[native platform crates](https://github.com/trycua/cua/blob/bd4c10020cd7cac07c0d19b0f53ba4b007fbcb15/libs/cua-driver/rust/README.md).
The platform limits they support are unverified against any released artifact.

### Supervising the backend

The device **supervises** the CUA backend rather than merely pointing at a
configured endpoint: it starts it, stops it, restarts it, and probes whether it
can act. `crates/tunnel-cua-export` is that supervisor, and the three things it
does are separated on purpose.

**Lifecycle.** The backend is started in its own process group. On every end of
its life that the device lives to see, the device signals that whole group with
`SIGKILL`, so a wrapper (`uvx`, a shell script, a Python launcher) cannot leave
the real backend or its workers running. One of the two signals is sent after
the leader has been reaped — on a natural exit it is the only one — so it
targets a group id that is in principle recyclable; that residue is recorded
rather than claimed away. The backend publishes the loopback address it bound and
the device reads it back and puts it through the loopback check, so the policy is
enforced against the process that is actually listening rather than against a
configured number; a backend that publishes a routable or wildcard address is
killed rather than advertised. The address file is removed before every start, so
a dead generation's port is never handed out.

**Containment, at the honesty this profile needs.** An escaped descendant of a
CUA backend is a process that can move the mouse and type on a real desktop, so
the two halves must not be conflated.

- **Trigger** — whether anything sends the group signal at all — **is closed.** A
  `SIGKILL`, a `process::exit` or a crash of the device runs **no `Drop`**, so
  without a sentinel even an ordinary **in-group** worker is orphaned. Each
  supervised backend is therefore watched by a `tunnel-deadman` sentinel: a
  sibling process, in a process group of its own, holding the read end of a pipe
  the device holds the write end of. When the device dies for any reason the
  kernel closes that descriptor, the sentinel wakes on end of file and signals
  the group. It is stood down only after the backend has been killed and reaped,
  and the stand-down is counted from the sentinel's own exit status rather than
  from the device having asked.
- **Reach** — which processes a group signal can touch — is **not closed on
  macOS, and the sentinel does not close it.** The sentinel sends the same group
  signal from a different process, and `killpg`'s delivery set does not mention
  the sender. `cgroup v2` closes it on Linux and a job object closes it on
  Windows; macOS has neither in-process. **Stated plainly, because for CUA it
  matters more than it did for MCP or ACP: a supervised CUA backend on macOS
  cannot be contained if it detaches.** A descendant that calls `setsid`, calls
  `setpgid` or double-forks survives the device's death, and on macOS that is an
  operator constraint — run the backend under the intended OS user, and isolate
  it in a VM or a container where the residue matters.

**The sentinel is a separate executable (`tunnel-deadman`) and must be installed
alongside the device binary**, or named by `TUNNEL_DEADMAN_BIN`. Without it the
device supervises exactly as it did before and leaks the backend's process group
on every crash, with nothing to distinguish that from correct operation — so a
missing sentinel warns once on stderr, `tunnel_deadman::availability()` answers
before any backend is started, and `tunnel-client doctor` reports
`process_containment: degraded / PROCESS_CONTAINMENT_SENTINEL_MISSING`. It is a
degradation, not a refusal: it changes neither the verdict nor the exit code.

**A file of that name is not the same finding as no file, and is reported
apart** (M6-C08). A `tunnel-deadman` that is not a regular file, or that this
process has no execute permission on, cannot be spawned — so containment is
equally absent, but the remedy is to replace it rather than to install one, and
being told to install a binary you are looking straight at is worse than being
told nothing. That state is `degraded /
PROCESS_CONTAINMENT_SENTINEL_UNUSABLE`, and the stderr warning names the
offending path.

**What `PROCESS_CONTAINMENT_SENTINEL_PRESENT` establishes, exactly.** That a
regular file of that name is at the resolved path and the kernel grants *this
process* execute permission on it — `access(EXEC_OK)`, so ACLs and mount flags
count, and a file whose execute bit is set only for a class this process is not
in is correctly rejected. It does **not** establish that the file is the
sentinel, and it does not establish that spawning will succeed: an executable
*script* named `tunnel-deadman` passes, and so does a file `execve` will reject
with `ENOEXEC`. A spawn that fails after this answer gets its own warning naming
the path and the error, not the "install one" advice. Proving the file really is
the sentinel means running it, which `doctor` deliberately does not do — it
reads a path and starts nothing. That probe lives at bundle-assembly time, where
a process launch is affordable and a failure is free to fix.

**Health is a probe, not a config echo.** `version` answering, or `/commands`
listing, proves the HTTP server is up — **not** that the automation backend can
act. A CUA backend can be present, listening and answering while being unable to
move a pointer, because macOS gates accessibility and screen recording behind
grants the process may not hold. The device therefore reports a backend as
working only on a **dispatched, succeeded, read-only, OS-gated** operation:
`get_screen_size` or `get_cursor_position`, **never a click**. A running process
is reported as running, which is a different answer and never permits a
dispatch. Capture authority is read separately, from the `version` response, and
absence is `Unknown` rather than denied — the released 0.3.46 server omits
`desktop_capture_authorized` on the supported 0.22.x SDK, so refusing on absence
would refuse capture on every correctly permissioned host.

**A restart invalidates the input lease and every outstanding capture identity,
and fails in-flight operations as `unknown`, never as retryable.** This is the
sharpest rule in the profile. A supervisor that restarts a hung backend has
destroyed the only witness to what that backend had already done, so an operation
that had reached it has an outcome nobody can establish. Reporting that as *not
dispatched* is the trap: the caller retries, and the click lands twice. Two
layers enforce it, and both are needed because a consumer that ignores the first
still meets the second — the in-flight operation is told `unknown` and is not
retryable for any operation, and every lease and capture identity is dropped, so
a retry is refused **above the dispatch boundary** and never reaches the backend
at all. Neither registry reuses an identifier after a restart: a reissued capture
id would let a stale click resolve against a different image, pass the bounds
check, and be dispatched at coordinates nobody picked.

**Declared, not resolved.** A backend killed mid-drag may have left a button
down, one killed mid-hotkey a modifier held, one killed mid-type a prefix
entered. Nothing in this repository observes any of that, and nothing here
repairs it — **by decision, not by impossibility**; see below. What a restart now
does is **say so**: every `Invalidation` carries a
`DesktopResidue` naming which kinds of input state the departed backend may have
left asserted on the target, folded over every operation that synthesises input,
because the device keeps no register of what was in flight. It is stamped
unconditionally — including on a restart that freed no lease and no capture,
since the device's own registries are not a witness to the desktop, and the agent
who inherits a held button holds no lease at the moment of the restart at all.

**A release sweep is available and is refused, which is a policy decision.** The
pinned 0.3.46 registry **does** carry the primitives a sweep would need:
`main.py` L431-441, at the release commit this section already links and whose
digest `scripts/m5-cua-refetch.sh` pins, registers `mouse_down`, `mouse_up`,
`key_down` and `key_up`. The platform table above records that *one* backend —
Computer Server with the Cua Driver backend — stubs all four
(`handlers/cua_driver.py` L348, L355, L484, L489); that is one row of six and is
not a registry-wide limit. Nothing here may say a sweep is inexpressible.

It is refused on its merits instead. A `mouse_up` is not a neutral release: it is
a **drop**, completing whatever drag the dead backend began, wherever the pointer
now happens to sit. A `key_up` on a modifier is synthesised input issued outside
any lease, on behalf of no authorized caller. Both would mean the supervisor
synthesising input, which M5's health probe is forbidden from doing and for this
exact reason, and both would require widening `ALLOWED_COMMANDS` in
`crates/tunnel-http-forward/src/cua_pin.rs` — an allowlist, not a capability
claim, and not a thing to widen for a recovery nobody has measured the need for.
So the device declares and does not repair.

`DesktopResidue` therefore offers a union and no difference, no `clear` and no
`observe`: **no read `computer.v1` allowlists reports held input**, and a release
is input this supervisor refuses to issue. `cursor_position` reports where the
pointer is and never whether a button is down. The registry does conditionally
expose `get_desktop_state` (`main.py` L466-467, implemented at
`handlers/cua_driver.py` L584); it is a pass-through to the `cua-driver` SDK, so
**whether its payload carries held-button or modifier state is unread here** and
is an open question rather than a settled negative.

**Still open, and it needs a VM.** Two measurements would earn a narrower
contract, and neither can be taken on a loopback fixture: whether the pinned
server releases held input on client disconnect or process exit, and what
`get_desktop_state` actually reports. With `mouse_up` and `key_up` genuinely
available, an *authorized* recovery sweep is a real future option that such a
measurement could justify — it is deferred, not ruled out. See `docs/tasks.md`
M5-C08, M5-C09 and M5-C09a.

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
