# Sources and research notes

Inspected 2026-09-09. Upstream facts below inform the design; they are not a claim that Agent Tunnel already integrates or runs these projects.

## Product inspiration

[Georgios Konstantopoulos's post](https://x.com/gakonst/status/2097279023764140358) was read in an authenticated browser. It describes a cloud agent using outward-connected enrolled computers, local tools/files, and optional isolated environments. Treat it as a demonstration of the product direction, not a tunnel specification. Agent Tunnel's two-channel rotation requirements come from the project owner.

## MCP

Specification snapshot: `aa8ce049f089f92618340190d4ece141f663310d`.

- [2026-07-28 Streamable HTTP](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/aa8ce049f089f92618340190d4ece141f663310d/docs/specification/2026-07-28/basic/transports/streamable-http.mdx): request-scoped streaming, current metadata/headers, cancellation, and backward compatibility.
- [2026-07-28 authorization](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/aa8ce049f089f92618340190d4ece141f663310d/docs/specification/2026-07-28/basic/authorization/index.mdx): protected-resource discovery and scoped, audience-bound HTTP authorization.
- [2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports): explicit legacy compatibility target.
- [Official Rust SDK snapshot](https://github.com/modelcontextprotocol/rust-sdk/tree/744b9f904c7f17d589326e61ddbe126cb9d58888): the earlier candidate snapshot, superseded by the published pin below.
- **Pinned 2026-09-16 (M3-01):** crates.io [`rmcp` 3.4.0](https://crates.io/crates/rmcp/3.4.0), released 2026-09-15 from [rust-sdk `fd7811fdaa9fefa1c8034534b4d7a31c97204f89`](https://github.com/modelcontextprotocol/rust-sdk/tree/fd7811fdaa9fefa1c8034534b4d7a31c97204f89/crates/rmcp) (commit taken from the crate's `.cargo_vcs_info.json`). `Cargo.lock` checksum `b23c62fe489ac1d401ab32688cfacac3737a8978dc3343e5361464c7724fd3cb`; the manifest requires `=3.4.0`.
  - Inspected in the published source: protocol versions `2026-07-28`, `2025-11-25` and `2025-06-18`; client lifecycles `Discover`, `Initialize` and `Auto`; stateless 2026 Streamable HTTP serving and legacy sessions; and a Unix-socket Streamable HTTP client.
  - It is used only as the fixture server and test client. Why the device bridge does not re-type messages through it is recorded in [mcp.md](mcp.md#pinned-in-code-m3-01-and-m3-02).
  - No conformance suite or non-Rust SDK is pinned yet.

## Filesystem SDK APIs

- [Files SDK research](research/files-sdk.md): `haydenbleasel/files-sdk` source 2.4.0, native `Adapter<Raw>` and separate HTTP gateway protocol; object semantics and error fidelity. [Project](https://files-sdk.dev/).
- [Mastra research](research/mastra.md): `WorkspaceFilesystem`, real required methods, read-tracker timestamp behavior and explicit advisory compatibility policy. [Workspace documentation](https://mastra.ai/docs/workspace/filesystem).
- [AI SDK research](research/ai-sdk.md): actual provider `FilesV4` upload/metadata/download/delete contract, model file parts, tools and separately gated experimental sandbox surfaces. [Source](https://github.com/vercel/ai).

These records contain inspected immutable source references and distinguish source versions from unverified published-package compatibility. [filesystem-adapters.md](filesystem-adapters.md) maps those findings into the shared 9P/WSS endpoint without claiming all SDKs speak the same native protocol.

**Pinned 2026-09-17 (M4-14): the published packages, installed.** The notes above are *source* snapshots. These are the artifacts the four adapters are compiled and registered against, exact-pinned in `packages/client/package.json` as both dev and peer dependencies with `packages/client/package-lock.json` committed:

- [`files-sdk` 2.4.0](https://www.npmjs.com/package/files-sdk/v/2.4.0) — `Adapter<Raw>` for `new Files({ adapter })`. Latest on the registry is 2.5.0; the pin is the version the research note inspected.
- [`@mastra/core` 1.65.0](https://www.npmjs.com/package/@mastra/core/v/1.65.0) — `WorkspaceFilesystem` and `Workspace` from its `./workspace` export. Latest is 1.67.0.
- [`just-bash` 3.4.2](https://www.npmjs.com/package/just-bash/v/3.4.2) — `IFileSystem` for `new Bash({ fs })`. It is the current latest.
- [`ai` 7.0.94](https://www.npmjs.com/package/ai/v/7.0.94) — the `uploadFile` helper. Latest is 7.0.105.
- [`@ai-sdk/provider` 4.0.11](https://www.npmjs.com/package/@ai-sdk/provider/v/4.0.11) — `FilesV4`. **Exact rather than a range**, because it is the version `ai` 7.0.94 itself depends on and any other would put two copies of the interface in a consumer's tree.

What the installed artifacts actually declare, where they differ from the source notes, and the three upstream behaviours only running them revealed are recorded in [filesystem-adapters.md](filesystem-adapters.md#pinned-packages-as-installed). No adapter has been run against a relay or a device.

## ACP

[acp.md](acp.md) records the official Agent Client Protocol v1 method/schema sources and draft HTTP binding. The CLI HTTP-to-stdio bridge requires pinned official SDK interoperability, callback/permission routing and no ambiguous prompt replay. See [official ACP documentation](https://agentclientprotocol.com/).

## just-bash and CUA

[integrations.md](integrations.md) records exact source revisions and method-level permalinks for both projects. The proposed TypeScript adapter follows the actual `IFileSystem` contract. CUA backend transport/authentication details and OS differences require a compatibility spike before release.

## Plan 9 filesystem protocol

- [Plan 9 9P introduction](https://9fans.github.io/plan9port/man/man9/intro.html): messages, tags, fids, and lifecycle.
- [Version negotiation](https://9fans.github.io/plan9port/man/man9/version.html): initial Tversion/Rversion exchange and negotiated maximum message size.
- [diod 9P2000.L protocol](https://github.com/chaos/diod/blob/de51d1ee1bd5ccf1d8c16b96227c8bb03ec50106/protocol.md): dialect reference for Linux-style metadata, open, links, rename and errors; see the integration operation mapping.
- [Linux v9fs documentation](https://docs.kernel.org/filesystems/9p.html): reference implementation context. A kernel mount is not required for the just-bash adapter; WebSocket is this project's transport binding.

9P2000.L is the proposed initial dialect because its operation set maps naturally to just-bash's POSIX-like interface. This is an engineering choice, not evidence of an existing compatible TypeScript package. Audit candidate codecs and negotiate the exact dialect; do not assume a crate named 9p implements .L or treat .L wire flags as native macOS/Windows constants.

## Rust transport building blocks

- [Tokio](https://docs.rs/tokio/latest/tokio/): candidate async runtime.
- [Axum WebSocket support](https://docs.rs/axum/latest/axum/extract/ws/index.html): relay upgrades and message limits.
- [tokio-tungstenite](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/): outbound async WebSocket implementation.

Axum is the selected web framework. [runtime.md](runtime.md) records the mTLS listener/CLI design and observed library versions; [cluster.md](cluster.md) cites HTTP/3, Redis consistency/ACL/notification behavior, rustls verification and membership-trust sources. The QUIC/H3 adapter is a separate listener sharing typed application services with Axum.

These mutable library links identify implementation candidates. The bootstrap only depends on configuration parsing libraries in Cargo.lock. Pin and record network dependencies when implementation starts.
