#![forbid(unsafe_code)]
//! The confined read-only 9P2000.L provider — implementation gate 4's device
//! half, defined by `docs/filesystem-api.md`.
//!
//! This crate is the dispatcher that sits between gate 3's pure session state
//! machine and gate 2's OS-confined resolver. Gate 3 says which primitives a
//! request needs and which virtual paths it names; gate 2 turns a virtual path
//! into a descriptor inside the export; this crate is what decides, in the right
//! order, that a request is still authorized *now* and then performs it.
//!
//! ```text
//!   bytes ──▶ FrameDecoder (gate 3) ──▶ [Provider::accept] ──▶ queue
//!                                                               │
//!                          live grant ◀── Authority ────────────┤
//!                                                               ▼
//!   bytes ◀── Frame::encode (gate 3) ◀── [Provider::step] ──▶ ExportRoot (gate 2)
//! ```
//!
//! # No socket, no runtime, no clock
//!
//! Everything that needs one of those is the caller's. [`Provider`] is a
//! synchronous state machine over decoded frames: the WebSocket, the tunnel DATA
//! frames, the deadlines and the live catalog snapshot all reach it through
//! [`Authority`] and through the caller's own choice of when to call
//! [`Provider::step`]. That is what lets this crate's own tests exercise the
//! flush race, the grant-revision recheck and the freshness recheck against a
//! real temporary filesystem with no relay, no Redis and no timing dependency.
//!
//! # What gate 4 refuses on purpose
//!
//! **Writes, creates, removes, renames and every `Tsetattr` are gate 5's**, and
//! this crate refuses them with `ENOTSUP` *even when the grant would permit
//! them* — see [`Provider`]'s own documentation. Partial and unknown mutation
//! outcomes are gate 5's too, so every refusal this crate can produce is
//! `not_started`. Adapters are gate 6's and nothing here knows about one.
//!
//! # The five obligations gate 3 handed this gate
//!
//! Each is discharged in one named place, and each is listed here because a
//! reader looking for it should not have to find it:
//!
//! 1. **`Tlopen` is re-classified with the resolver's kind**, not with the flags
//!    and not with the qid the session recorded at walk time —
//!    [`Provider::open_primitives_now`].
//! 2. **A reply whose tag the dispatcher flushed is dropped**, never fed to
//!    `Session::complete`, which cannot tell it from an invented tag —
//!    [`Provider::step`].
//! 3. **The resolved-descriptor cache is keyed by fid *generation***, not by fid
//!    number — [`Provider::cached`] and [`Provider::prune`].
//! 4. **The outward `OsStr` refusal** is taken where an `OsStr` becomes a
//!    `String`, which is `tunnel_fs_host::DirReader::next_entry`; this crate is
//!    what turns it into a failed `Treaddir` rather than a skipped entry.
//! 5. **The metadata-only open** a `list`-without-`read` grant needs is
//!    `tunnel_fs_host::ExportRoot::metadata`, used here for every `Tgetattr` and
//!    for every walk step.
//!
//! and the two the contract assigns here directly: the **grant-revision
//! recheck** and the **freshness recheck after a queue wait**, both in
//! [`Provider::step`], immediately before the host is touched.
//!
//! # Payload-free
//!
//! Nothing here owns a path, a name or file content beyond the reply it is
//! building. [`ProviderStats`] is counters. Every error is a gate-1 [`FsError`]
//! or a [`SessionErrorCode`], both `Copy` over field-free enums.

#[cfg(unix)]
mod provider;

#[cfg(unix)]
pub use provider::{Authority, Authorization, Outbound, Provider, ProviderStats};

use tunnel_fs_core::{Limits, SessionErrorCode};

/// The WebSocket subprotocol a consumer must offer, and the relay must select.
pub use tunnel_fs_core::TRANSPORT_SUBPROTOCOL as SUBPROTOCOL;
/// The 9P dialect this profile speaks.
pub use tunnel_fs_ninep::DIALECT;

/// The limits an export serves under when an operator configures nothing.
///
/// The contract's initial table, unreduced. Negotiation only ever reduces, so
/// this is the ceiling an operator narrows from and never a value a consumer can
/// raise.
///
/// # Panics
///
/// Never: the values are the contract's own and satisfy every cross-field rule
/// gate 1 enforces. The `expect` is the assertion that they still do.
#[must_use]
pub fn default_limits() -> Limits {
    Limits::new([
        65_536,     // maxMessageBytes
        64,         // maxInflightRequests
        256,        // maxFids
        1_048_576,  // maxQueuedBytes
        16_777_216, // maxBufferedFileBytes
        33_554_432, // maxTotalBufferedBytes
        4_096,      // maxPathBytes
        256,        // maxPathComponents
        10_000,     // maxTraversalEntries
        64,         // maxTraversalDepth
        30,         // requestTimeoutSeconds
        300,        // defaultOperationTimeoutSeconds
        3_600,      // maxOperationTimeoutSeconds
        300,        // sessionIdleSeconds
    ])
    .expect("the contract's own initial limits satisfy gate 1's cross-field rules")
}

/// Why the provider closed a consumer socket, as a bounded sanitized token.
///
/// The contract: "Close reasons contain only bounded sanitized identifiers."
/// This is that identifier, and it is gate 1's own vocabulary rather than a
/// second one invented here.
#[must_use]
pub const fn close_reason(code: SessionErrorCode) -> &'static str {
    code.as_str()
}
