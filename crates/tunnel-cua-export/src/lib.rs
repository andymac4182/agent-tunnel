#![forbid(unsafe_code)]
//! Device-side supervision of one `computer.v1` backend (task row M5-C08,
//! chunk 4).
//!
//! The owner's decision for M5 is that the device **supervises** the backend —
//! "ensures it's running and working" — so this crate carries lifecycle *and*
//! health. They are separated on purpose, into two modules that cannot
//! substitute for one another:
//!
//! * [`child`] is **lifecycle**: start the backend, kill it, reap it, signal
//!   its process group, arm a [`tunnel_deadman`] sentinel. It knows nothing
//!   about `computer.v1` and cannot form an opinion about whether the backend
//!   *works*.
//! * [`health`] is **health**, and it is a probe rather than a config echo.
//!   Its only route to a working verdict runs through
//!   [`tunnel_cua::capability::ProbeEvidence`], which requires a
//!   **read-only, OS-gated** operation paired with a dispatched success.
//!
//! [`supervisor`] joins them, and on the [`Supervisor`] route the join is
//! one-directional: a running process is never *reported* as working, and a
//! working verdict there implies a running process, because
//! [`Supervisor::assess`] refuses one for a backend that has gone.
//!
//! **What that is not.** It is a tightening against mistakes, not a proof
//! against fabrication. `Dispatch` and `Completion` are public enums with
//! public payloads, so a caller can write down a dispatched success that never
//! happened and obtain `Health::Working` from it — review compiled exactly that
//! counterexample against an earlier draft of this crate, which claimed the
//! stronger thing. See [`health`]'s header for the half that does hold, which
//! is the half the config-echo trap is actually about.
//!
//! # Why the health half cannot be an echo
//!
//! `<scratchpad>/m5-scoping-and-decisions.md` names *capability negotiation
//! with a config echo standing in for a probe* as a trap. It is sharper here
//! than anywhere else in M5: `version` or `/commands` answering proves the
//! **HTTP server** is up, not that the automation backend can act. A CUA
//! backend can be present, listening and answering while being entirely
//! unable to move a pointer, because macOS gates accessibility and
//! screen-recording behind grants the process may not hold.
//!
//! So the probe must exercise something the OS permission layer gates, and it
//! must change nothing: `get_screen_size` or `get_cursor_position`, **never a
//! click**. [`health::Unhealthy::NotAProbe`] is what an operation outside that
//! pair gets, `version` and `describe` included.
//!
//! One measured finding from chunk 1 constrains the reading:
//! `desktop_capture_authorized` is **absent by default** on the supported
//! 0.22.x SDK, so an absent value is `Unknown` and must never be read as
//! denied. This crate does not re-derive that; it uses
//! [`tunnel_cua::capability::CaptureAuthority`], which already carries it.
//!
//! # Containment, stated at the honesty M5 needs
//!
//! An escaped descendant of a CUA backend is a process that can move the
//! mouse and type on a real desktop, so the two halves of process containment
//! are worth more here than they were for MCP or ACP, and neither may be
//! overstated:
//!
//! * **Trigger** — whether anything sends the group signal at all — **is
//!   closed**. A `SIGKILL`, a `process::exit` or a crash of this process runs
//!   no `Drop`, so without a sentinel even an ordinary **in-group** child is
//!   orphaned. [`child`] arms a [`tunnel_deadman::Deadman`] per backend and
//!   stands it down only after the leader is killed and reaped.
//! * **Reach** — which processes a signal can touch — is **not closed on
//!   macOS, and a deadman does not close it.** The sentinel sends the same
//!   group signal from a different process, and `killpg`'s delivery set does
//!   not mention the sender. `cgroup v2` closes it on Linux and a job object
//!   closes it on Windows; macOS has neither in-process, so there it is an
//!   **operator constraint**. Plainly: **a supervised CUA backend on macOS
//!   cannot be contained if it detaches.**
//!
//! Because a missing sentinel reverts to the old behaviour indistinguishably
//! from correct operation, three visibility layers carry it — and all three
//! already exist, so this crate inherits rather than rebuilds them:
//! [`tunnel_deadman::Deadman::arm`] warns once per process,
//! [`tunnel_deadman::availability`] answers before any child exists, and
//! `tunnel-client doctor` reports `process_containment` as a **degradation,
//! not a refusal** — it changes neither the verdict nor the exit code.
//!
//! # Restart is the trap that bites
//!
//! A supervised restart must invalidate the input lease and every outstanding
//! capture identity, and must fail in-flight operations as `unknown`, never
//! retryable. That decision is [`tunnel_cua::supervision`], in the pure crate.
//! What this crate adds is the guarantee that it **cannot be skipped**:
//! [`supervisor::Supervisor::restart`] and
//! [`supervisor::Supervisor::stop`] take an [`supervisor::InputAuthority`] as
//! a required argument, so there is no way to end a backend's life without
//! invalidating what was held against it.
//!
//! # Scope
//!
//! No relay wiring, no real backend, no Lane B, and nothing that touches this
//! host's input or screen. The Lane A fixture remains the only backend this
//! crate has ever been pointed at, and it has no HTTP client of its own: the
//! health probe is a trait the caller implements.

pub mod child;
pub mod config;
pub mod health;
pub mod supervisor;

pub use config::BackendProcess;
pub use health::Health;
pub use supervisor::Supervisor;
