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
- [`@ai-sdk/provider` 4.0.11](https://www.npmjs.com/package/@ai-sdk/provider/v/4.0.11) — `FilesV4`. **Exact rather than a range**, because it is the version `ai` 7.0.94 itself depends on: the pin makes the `FilesV4` `ai.uploadFile` reaches the same one the adapter was compiled against. It does not make the tree single-copy — `@mastra/core` brings two more nested copies of its own.

What the installed artifacts actually declare, where they differ from the source notes, and the three upstream behaviours only running them revealed are recorded in [filesystem-adapters.md](filesystem-adapters.md#pinned-packages-as-installed). No adapter has been run against a relay or a device.

## ACP

[acp.md](acp.md) records the official Agent Client Protocol v1 method/schema sources and draft HTTP binding. The CLI HTTP-to-stdio bridge requires pinned official SDK interoperability, callback/permission routing and no ambiguous prompt replay. See [official ACP documentation](https://agentclientprotocol.com/).

**Pinned 2026-09-17 (M8-01): the published crates, compiled against.** Before this, the repository pinned nothing for ACP: `acp.md` carried two observed source commits that it explicitly disclaimed as "not a dependency lock". These are the artifacts `crates/tunnel-acp` is built against, exact-pinned in `crates/tunnel-acp/Cargo.toml` with the checksums `Cargo.lock` records. `crates/tunnel-acp/tests/pin.rs` reads the lockfile and the manifests and fails if either moves.

- crates.io [`agent-client-protocol` 2.1.0](https://crates.io/crates/agent-client-protocol/2.1.0), `Cargo.lock` checksum `6395d81d91fd2ee93f48ea31cfc511356e75b9061ca0389cefd0308507cc11ba`, from rust-sdk [`726c5030bfaa88cfdac2fb1f71a63abb331ce586`](https://github.com/agentclientprotocol/rust-sdk/tree/726c5030bfaa88cfdac2fb1f71a63abb331ce586/src/agent-client-protocol) (commit and subdirectory taken from the crate's `.cargo_vcs_info.json`). The manifest requires `=2.1.0`.
- crates.io [`agent-client-protocol-http` 2.1.0](https://crates.io/crates/agent-client-protocol-http/2.1.0), checksum `5f0d39290be11146183166d4d077013b94a204516c9ecbbb058a234c28c5babc`, from the **same** commit, subdirectory [`src/agent-client-protocol-http`](https://github.com/agentclientprotocol/rust-sdk/tree/726c5030bfaa88cfdac2fb1f71a63abb331ce586/src/agent-client-protocol-http). Its published description is "HTTP and WebSocket transport for the Agent Client Protocol (ACP)". The manifest requires `=2.1.0` and enables **neither** of its two features (`client`, `server`), so the pin is recorded without linking reqwest, axum or tungstenite; chunk 2 selects one.
- crates.io [`agent-client-protocol-schema` 1.7.0](https://crates.io/crates/agent-client-protocol-schema/1.7.0), checksum `ca98360c7bb8cc97d7acd49e2a8a851c3f7bee6b2f0535036d8ab86b5fcd223d`, from the **protocol** repository at [`272bf799f35a258c6a4107a0410ed361e83683d3`](https://github.com/agentclientprotocol/agent-client-protocol/tree/272bf799f35a258c6a4107a0410ed361e83683d3/agent-client-protocol-schema) (2026-08-20). This is not named in our manifest — the core crate requires it as `=1.7.0` — but it is where the normative v1 wire types live, so it is pinned and checked here too. **It is the immutable v1 schema reference**: the request, response and notification types, `ProtocolVersion`, the `AGENT_METHOD_NAMES`/`CLIENT_METHOD_NAMES` tables and the `StopReason` vocabulary. `agent-client-protocol-derive` 2.1.0 (`7e8d5f32208cdc11238004bec4e4229d68fb937598f900e153468ca084865fa5`) comes with the core crate.
- **The transport reference** is the upstream **Streamable HTTP & WebSocket Transport RFD**, immutable at [`ccff4e7d2e431880225804a8c136c2ccfcb313d0`](https://github.com/agentclientprotocol/agent-client-protocol/blob/ccff4e7d2e431880225804a8c136c2ccfcb313d0/docs/rfds/streamable-http-websocket-transport.mdx), path `docs/rfds/streamable-http-websocket-transport.mdx`, SHA-256 of that file `db16730db8bcd8d3598323cd0939ce9a655a83ed93a7fd2ce7a31e3ce7be8d37`. The rendered page at `agentclientprotocol.com/rfds/streamable-http-websocket-transport` is mutable and reported `dateModified` 2026-09-14 when read.

**The revision reconciliation, which is the correction this pin carries.** `acp.md` targeted "the Streamable HTTP & WebSocket Transport RFD, using its last listed revision, **2026-05-04**". That was wrong when it was written. The RFD's own revision history, at the immutable commit above and on the live page, ends with **2026-07-02** ("Moved to Active to reflect current Transports Working Group focus"), preceded by 2026-06-05 (durability and reliability expectations; `Last-Event-ID` resumability deferred to v2). Both predate the 2026-09-09 reading that produced `acp.md`. The pin is therefore **2026-07-02**, not 2026-05-04, and `acp.md` has been corrected.

**The SDK does not name a revision at all.** Neither published crate's README, `CHANGELOG.md`, package description nor source contains the string "RFD", a revision date, or the designation "Streamable HTTP"; the HTTP crate's README says only "HTTP/WebSocket transport for ACP agents". So the SDK's conformance to any revision of the RFD is **inferred from its behaviour**, not stated by upstream. What was read in the published source: `src/protocol.rs` defines `acp-connection-id` and `acp-session-id`; `src/server.rs` routes `POST`, `GET` and `DELETE` at one configurable path; `src/http_server.rs` answers 415 for a non-`application/json` POST, 406 for a GET that does not accept `text/event-stream`, 400 for a missing `Acp-Connection-Id`, 404 for an unknown one, 409 for a second subscriber, 202 for a non-`initialize` POST and for DELETE. That matches the structural model the RFD's 2026-04-23 and 2026-05-04 revisions describe. **Two divergences from this profile were also read there and are recorded rather than left to be met later:** `handle_get` (`src/http_server.rs:410-413`) inserts `Acp-Session-Id` on every session-scoped SSE response, which this profile's response allowlist refuses (**M8-C05**); and `src/server.rs` routes `OPTIONS` through a CORS layer, which this profile does not accept. Neither is a defect in the SDK — they are places where the pinned artifact and the pinned document differ, and the profile follows the document.

**Where the pinned SDK and the pinned RFD revision disagree: batches.** The RFD says, at this commit and in its MCP-deviation table, "Batch JSON-RPC requests return 501", listing batch requests as phase-4 work. The SDK's 2.0.0 changelog adds the opposite — "Preserve incoming JSON-RPC batch frames and grouped responses across HTTP and WebSocket transports" — and `src/http_server.rs` routes `TransportFrame::Batch` on POST and on the SSE streams. The SDK therefore implements something **later than** the 2026-07-02 revision on this point. Agent Tunnel's `acp-http-v1` profile follows the RFD and refuses a batch with 501, which is the stricter of the two; this is recorded as task row **M8-C02** because a later chunk that puts the SDK's own server or client behind this profile will meet the disagreement. Nothing in this repository has been run against either, so this is a reading of published source, not an observed interoperability failure.

**Two draft surfaces are off, and asserted.** The 2.x SDK implements protocol v1 and draft v2 in one crate: v1 through `Client.builder()`/`Agent.builder()`/`Proxy.builder()`, v2 only through the `.v2()` counterparts behind the `unstable_protocol_v2` feature, and MCP-over-ACP behind `unstable_mcp_over_acp`. `acp.md`'s "keep v2 disabled" and "MCP-over-ACP is outside the first ACP milestone" therefore cost nothing upstream — they mean not enabling those flags — and `crates/tunnel-acp/src/pin.rs` asserts their absence rather than assuming it: the schema's method-name tables are read back through serde to observe the built artifact, `tests/pin.rs` scans every workspace manifest, and `ProtocolVersion::LATEST` — which upstream deliberately removes when the v2 draft is enabled — is referenced so the crate cannot compile with it on.

**Not established.** No ACP client, server or agent has been run against anything in this repository: compiling against these crates is not running against them, and the profile tables passing their own tests says nothing about interoperability. crates.io's JSON API was not readable from the build host (HTTP 403), so publication timestamps come from the crates' own changelogs and from the dates of the release commits above rather than from registry metadata. No conformance suite and no non-Rust ACP SDK is pinned. The `server` feature of the transport crate has never been compiled here. **The `client` feature now is** — this sentence said "`client` and `server`" until the m8c6 verification pass, and chunk 3 had already falsified the `client` half: `tunnel-acp-fixture`'s non-default `interop` feature takes `agent-client-protocol-http` with `features = ["client"]`, `cargo tree -p tunnel-acp-fixture --features interop -e features` reports it enabled, and `cargo test -p tunnel-acp-fixture --features interop --locked` runs 43 tests green. Recorded as M8-C19. Note the first sentence of this paragraph stands unchanged: compiling the client feature is still not running against an ACP **server** or a real agent.

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
