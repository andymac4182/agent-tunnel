# Sources and research notes

Inspected 2026-09-09. Upstream facts below inform the design; they are not a claim that Agent Tunnel already integrates or runs these projects.

## Product inspiration

[Georgios Konstantopoulos's post](https://x.com/gakonst/status/2097279023764140358) was read in an authenticated browser. It describes a cloud agent using outward-connected enrolled computers, local tools/files, and optional isolated environments. Treat it as a demonstration of the product direction, not a tunnel specification. Agent Tunnel's two-channel rotation requirements come from the project owner.

## MCP

Specification snapshot: `aa8ce049f089f92618340190d4ece141f663310d`.

- [2026-07-28 Streamable HTTP](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/aa8ce049f089f92618340190d4ece141f663310d/docs/specification/2026-07-28/basic/transports/streamable-http.mdx): request-scoped streaming, current metadata/headers, cancellation, and backward compatibility.
- [2026-07-28 authorization](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/aa8ce049f089f92618340190d4ece141f663310d/docs/specification/2026-07-28/basic/authorization/index.mdx): protected-resource discovery and scoped, audience-bound HTTP authorization.
- [2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports): explicit legacy compatibility target.
- [Official Rust SDK snapshot](https://github.com/modelcontextprotocol/rust-sdk/tree/744b9f904c7f17d589326e61ddbe126cb9d58888): candidate implementation dependency. Select an actual published version and run interoperability fixtures before M3.

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

These mutable library links identify design candidates. The bootstrap only depends on configuration parsing libraries in Cargo.lock. Pin and record network dependencies when implementation starts.
