//! The owner relay's fixture interposition point.
//!
//! Implementation gate 4 rotates a stream while its owner→device record
//! stream stops at a named position: inside a BODY record's eight-byte
//! header, inside a BODY payload, or after END but before the outer FIN.
//! The real ingress writes a record header, its payload, END and FIN back to
//! back, so those positions are otherwise only reachable by timing.
//!
//! The relay defines only this hook and its vocabulary.  **No implementation
//! ships in `tunnel-relay`**: the one-shot hold lives in
//! `tunnel-test-harness` (`http_relay_hold`), and the only way to attach one
//! is [`super::HttpForwardExports::with_fixture_interposer`], which the
//! `tunnel-relay serve` binary never calls: its exports are built from
//! `ServeConfig`, which has no interposer setting.  A relay artifact built
//! from this crate, alone or in a unified workspace build, therefore contains
//! no code that can hold a production write.  This replaces the gate-4
//! `test-fixtures` cargo feature, which Cargo feature unification compiled
//! into workspace-built relay binaries.

use std::future::Future;
use std::pin::Pin;

/// Where the owner's request relay may stop.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HttpRelayHoldPoint {
    /// After forwarding the first `bytes` (1..=7) of the next BODY record
    /// header.
    InsideBodyHeader { bytes: u8 },
    /// After forwarding the next BODY record header and half of its
    /// payload chunk.
    InsideBodyPayload,
    /// After END was forwarded, before the request FIN.
    BeforeRequestFin,
}

/// A fixture interposer on the owner's request relay.  Test infrastructure
/// only; see the module documentation.
#[doc(hidden)]
pub trait HttpRelayInterposer: Send + Sync + 'static {
    /// The point an armed interposer waits at, if any.
    fn armed_point(&self) -> Option<HttpRelayHoldPoint>;

    /// Called when the relay reaches `point`.  An interposer not armed at
    /// exactly this point must return immediately, and an armed one must
    /// release itself within a bounded time.
    fn hold_at(&self, point: HttpRelayHoldPoint) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
