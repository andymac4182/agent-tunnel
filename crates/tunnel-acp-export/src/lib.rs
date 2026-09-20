#![forbid(unsafe_code)]
//! The device-side ACP export: one stdio child per ACP transport connection,
//! and the in-process HTTP/SSE bridge in front of it (task row M8-02's
//! supervisor **and** bridge halves, and M8-03's lifecycle half).
//!
//! **What this crate is.** Child startup from configuration only, newline
//! JSON-RPC stdio framing validated by the pinned `tunnel-acp` profile, the
//! `starting`/`ready`/`draining`/`stopped`/`failed` lifecycle driven as a
//! transition table, bounded channels, a **separate reader** that keeps
//! handling agent callbacks while a prompt is pending, a capped stderr drain
//! that never blocks child exit, a process-group `SIGKILL` on every end of a
//! child's life — and, since chunk 3, [`bridge::AcpExport`]: the in-process
//! `HttpHandler` that serves the ACP Streamable HTTP binding over
//! `tunnel-http-bridge`'s gate-2 `forward`/`serve` path, with connection- and
//! session-scoped SSE streams, one subscriber each, and the documented
//! subscription deadlines.
//!
//! **What this crate is not, and does not claim.**
//!
//! * **No tunnel, no relay, no cluster.** The bridge runs over the in-process
//!   gate-2 path. The rotating device WebSockets, three relays, peer hops and
//!   cross-tenant isolation are chunks 4 and 5.
//! * **No principal.** `docs/acp.md` derives a principal at the relay ingress,
//!   and there is no ingress in front of the in-process bridge: every request
//!   in this crate's tests carries `tunnel-principal-binding: None`. That is
//!   the M3-01/M3-02 precedent exactly, and it is recorded rather than left for
//!   a reader to infer.
//! * **No process-tree containment — and that is the *reach* half only.**
//!   Group containment has two independent halves and this crate closes
//!   exactly one of them. **Reach**: which processes a group signal can touch.
//!   The group kill reaches the child's process group; a descendant that calls
//!   `setsid`, calls `setpgid` or double-forks has left that group and is
//!   **not** killed, by anything here. That is the inherited hole
//!   `docs/tasks.md` records as M3-09, it needs a kernel boundary (cgroup v2,
//!   a job object, a sandbox or VM) that macOS does not offer in-process, and
//!   `tunnel-acp-fixture` ships a descendant that deliberately escapes and
//!   survives so the test measures the survival rather than asserting a
//!   containment that does not exist. **Trigger**: whether anything sends the
//!   signal at all. That half *is* closed, by the [`tunnel_deadman`] sentinel
//!   — see [`child`] — and it is closed for in-group members only, because a
//!   sentinel sends the same group signal from a different process and
//!   therefore inherits the same reach.
//! * **No per-OS coverage.** Process groups and `SIGKILL` are Unix-only, and
//!   macOS is the only host any of this has run on. Nothing here was exercised
//!   on Linux or Windows.
//!
//! The clock lives here and nowhere below: `tunnel_acp::lifecycle` takes
//! caller-supplied observations and never reads `Instant`.

pub mod bridge;
pub mod child;
pub mod config;
pub mod sse;
pub mod supervisor;

pub use bridge::{
    AcpDiagnostics, AcpExport, ExportError, MAX_CONNECTIONS_PER_BINDING, MAX_TRACKED_CONNECTIONS,
    OUTPUT_STALL_DEADLINE, STREAM_BACKLOG,
};
pub use child::{
    ChildConfig, ChildCounters, ChildEnd, ChildEvent, ChildHandle, ChildMessage, SendError,
    SpawnError,
};
pub use config::{
    AcpAgentConfig, AcpConfigError, AcpDeadlinesConfig, AcpExportConfig, AcpLimitsConfig,
    DEFAULT_OUTPUT_STALL_MS, DEFAULT_PERMISSION_TIMEOUT_MS, DEFAULT_SUBSCRIBE_DEADLINE_MS,
};
pub use sse::{ExportBody, sse_event};
pub use supervisor::{
    AgentEvent, ConnectionScope, Diagnostics, OutboundMessage, PromptTicket, Supervisor,
    SupervisorConfig, SupervisorError,
};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
