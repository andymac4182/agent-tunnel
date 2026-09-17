#![forbid(unsafe_code)]
//! The device-side ACP supervisor: one stdio child per authorized ACP
//! transport connection (task row M8-02's supervisor half, and M8-03's
//! lifecycle half).
//!
//! **What this crate is.** Child startup from configuration only, newline
//! JSON-RPC stdio framing validated by the pinned `tunnel-acp` profile, the
//! `starting`/`ready`/`draining`/`stopped`/`failed` lifecycle driven as a
//! transition table, bounded channels, a **separate reader** that keeps
//! handling agent callbacks while a prompt is pending, a capped stderr drain
//! that never blocks child exit, and a process-group `SIGKILL` on every end of
//! a child's life.
//!
//! **What this crate is not, and does not claim.**
//!
//! * **No HTTP, no SSE, no tunnel, no relay, no real ACP client.** Nothing
//!   here has spoken to an ACP implementation; the only agent it has run is
//!   the synthetic fixture in `tunnel-acp-fixture`. Chunks 3 to 5.
//! * **No process-tree containment.** The group kill reaches the child's
//!   process group. A descendant that calls `setsid`, calls `setpgid` or
//!   double-forks leaves that group and is **not** killed — the inherited hole
//!   `docs/tasks.md` records as M3-09. `tunnel-acp-fixture` ships a descendant
//!   that deliberately escapes and survives, and the test that runs it
//!   measures the survival rather than asserting containment.
//! * **No per-OS coverage.** Process groups and `SIGKILL` are Unix-only, and
//!   macOS is the only host any of this has run on. Nothing here was exercised
//!   on Linux or Windows.
//!
//! The clock lives here and nowhere below: `tunnel_acp::lifecycle` takes
//! caller-supplied observations and never reads `Instant`.

pub mod child;
pub mod supervisor;

pub use child::{
    ChildConfig, ChildCounters, ChildEnd, ChildEvent, ChildHandle, ChildMessage, SendError,
    SpawnError,
};
pub use supervisor::{
    AgentEvent, ConnectionScope, Diagnostics, PromptTicket, Supervisor, SupervisorConfig,
    SupervisorError,
};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
