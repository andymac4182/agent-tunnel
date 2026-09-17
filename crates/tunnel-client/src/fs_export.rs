//! The device half of implementation gate 4: serving 9P2000.L over one logical
//! tunnel stream.
//!
//! The connector actor stays the only owner of each stream's sequence, credit
//! and authorization state, exactly as it is for `http-forward/1`. This module
//! only turns the ordered bytes of one stream into 9P frames, hands them to
//! [`tunnel_fs_provider::Provider`], and writes the provider's answers back.
//!
//! # Where each rule is enforced
//!
//! * **Framing.** The device's transport rule is an ordered byte stream, so
//!   inbound bytes go through gate 3's [`FrameDecoder`], which may split one
//!   message across tunnel DATA frames and pack several into one. The relay
//!   enforces the *other* rule — one complete 9P message per consumer binary
//!   message — with gate 3's `decode_exact`. Conflating the two is the bug
//!   `docs/testing.md` warns about, which is why they are two functions.
//! * **Authorization.** The connector confirms each stream's authorization
//!   against the owner within the five-second ceiling of `docs/cluster.md`, and
//!   [`StreamAuthority`] is the window through which the provider reads it
//!   after every queue wait. The provider never caches it.
//! * **Capabilities.** The four capabilities arrive in the OPEN's bounded
//!   `fs_capabilities` metadata and are **intersected** with the device's own
//!   local allowlist, so a relay cannot widen what the operator configured.
//!   That is the connector's independent local enforcement, not a duplicate of
//!   the relay's check.
//!
//! # Blocking
//!
//! [`tunnel_fs_provider::Provider::step`] performs the host call inline, on the
//! exchange task. Every call it makes is one bounded `openat`, `statat`,
//! `pread`, `pwrite` or `getdents` against a local filesystem, so the stall is
//! short — but it is a stall, and on a network or FUSE filesystem it would not
//! be short. Gate 4 expected gate 5 to move the step onto a blocking pool;
//! **gate 5 did not**, so the call is still inline and a `pwrite` is now among
//! the ones it makes. It stays residue rather than a claim, and
//! `docs/filesystem-api.md` records that the prediction did not come true.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;

use tunnel_fs_core::{Capability, CapabilitySet, Feature, FeatureSet, Limits, SessionErrorCode};
use tunnel_fs_ninep::{FrameDecoder, MAX_MESSAGE_BYTES};
use tunnel_fs_provider::{
    Authority, Authorization, Outbound, Provider, ProviderStats, RECORD_HEADER_LEN, default_limits,
    encode_close, encode_message,
};
use tunnel_http_bridge::{Frame, FrameReceiver, FrameSender};

/// What an operator configured for one filesystem export.
#[derive(Clone, Debug)]
pub struct FsExport {
    /// The host directory the export is rooted at.
    ///
    /// Operator configuration, and the one path in this profile opened by name.
    /// It is never logged: `Debug` is derived on the struct for the connector's
    /// own use and the struct never reaches a diagnostic record.
    pub root: std::path::PathBuf,
    /// The capabilities this device will serve **at most**.
    ///
    /// The session's effective grant is this intersected with what the relay's
    /// OPEN named. The contract's local-allowlist rule: "The connector
    /// independently enforces its local allowlist."
    pub allowed: CapabilitySet,
    /// The features this provider implements.
    ///
    /// Operator configuration, and **default absent except for
    /// [`ALWAYS_IMPLEMENTED`]**: the contract's features are opt-in, and
    /// `hardLinks` in particular disables the `st_nlink` write refusal, so a
    /// build that enabled one by omission would widen an export nobody asked to
    /// widen. `exclusiveCreate` is the one exception and is not a choice —
    /// `Tlcreate` is always exclusive here, so the flag reports what is true
    /// rather than what was configured.
    pub features: FeatureSet,
    /// The negotiated limits.
    pub limits: Limits,
}

impl FsExport {
    /// An export rooted at `root`, serving the read-only profile.
    #[must_use]
    pub fn read_only(root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            root: root.into(),
            allowed: CapabilitySet::from_slice(&[Capability::Read, Capability::List]),
            features: FeatureSet::NONE.with(ALWAYS_IMPLEMENTED),
            limits: default_limits(),
        }
    }
}

/// The features this implementation has whether an operator names them or not.
///
/// **`exclusiveCreate` is not a configuration choice here, it is a property.**
/// `Tlcreate` opens `O_CREAT | O_EXCL` unconditionally, so exclusive creation
/// is what this provider always does; leaving the flag off by default would
/// tell a client honouring "`overwrite:false` uses exclusive create" that the
/// one guarantee it needs is absent, and it would then reach for the
/// exists-then-create race the contract forbids. An operator cannot turn it
/// off, because there is nothing to turn off.
///
/// Every other feature stays opt-in and absent by default — `hardLinks` in
/// particular, because advertising it switches off the `st_nlink` write
/// refusal.
pub const ALWAYS_IMPLEMENTED: Feature = Feature::ExclusiveCreate;

/// The features an operator's `[exports.<service>.fs]` table named, plus the
/// ones this build always has.
///
/// Unknown names are **ignored rather than refused**, for the same reason an
/// unknown capability name is: the list is forward-compatible, a feature this
/// build cannot implement is one it must treat as absent, and refusing the
/// export instead would make adding a feature a breaking change for every older
/// device. The direction of the leniency is the safe one — an unknown name can
/// only ever fail to turn something *on*.
#[must_use]
pub fn parse_features(names: &[String]) -> FeatureSet {
    let mut set = FeatureSet::NONE.with(ALWAYS_IMPLEMENTED);
    for name in names {
        if let Some(feature) = Feature::ALL
            .into_iter()
            .find(|feature| feature.as_str() == name.trim())
        {
            set = set.with(feature);
        }
    }
    set
}

/// The capabilities the OPEN's `fs_capabilities` metadata named.
///
/// Unknown names are **ignored rather than refused**, which is the one place
/// this profile is deliberately lenient and is worth stating: the field is a
/// forward-compatible list from the relay, and a capability this build does not
/// know is one it cannot enforce, so treating it as absent is the only safe
/// reading. Refusing the session instead would make adding a capability a
/// breaking change for every older device.
#[must_use]
pub fn parse_capabilities(metadata: &str) -> CapabilitySet {
    let mut set = CapabilitySet::DENY;
    for name in metadata.split(',') {
        if let Some(capability) = Capability::parse(name.trim()) {
            set = set.with(capability);
        }
    }
    set
}

/// The live authorization of one admitted stream, as the provider sees it.
///
/// Three atomics rather than a lock: the connector actor writes them as it
/// confirms and invalidates the stream's authorization context, and the
/// exchange task reads them before every host call. A lock here would make the
/// actor wait on a task it is not allowed to block on.
#[derive(Debug)]
pub struct StreamAuthority {
    revision: AtomicU64,
    /// Every capability bit, as gate 1 packs them.
    grant: AtomicU64,
    fresh: AtomicBool,
}

impl StreamAuthority {
    /// The authority for a stream admitted at `revision` with `grant`.
    #[must_use]
    pub fn new(revision: u64, grant: CapabilitySet) -> Self {
        Self {
            revision: AtomicU64::new(revision),
            grant: AtomicU64::new(pack(grant)),
            fresh: AtomicBool::new(true),
        }
    }

    /// Record that the authorization context is confirmed and inside its
    /// deadline.
    pub fn confirm(&self, revision: u64, grant: CapabilitySet) {
        self.revision.store(revision, Ordering::Release);
        self.grant.store(pack(grant), Ordering::Release);
        self.fresh.store(true, Ordering::Release);
    }

    /// The capabilities this session currently carries.
    ///
    /// A renewal re-states them rather than re-deriving them: the contract says
    /// normal renewal "cannot broaden permissions or change frozen scope or
    /// revision", and any such change closes the stream instead. So there is
    /// nothing for a confirmation to change here, and a confirmation that
    /// *could* change it would be the widening the rule forbids.
    #[must_use]
    pub fn current_grant(&self) -> CapabilitySet {
        unpack(self.grant.load(Ordering::Acquire))
    }

    /// Record that the context is stale, invalidated or revoked.
    ///
    /// The next host call the provider would make closes the session instead.
    pub fn invalidate(&self) {
        self.fresh.store(false, Ordering::Release);
    }
}

/// The provider's view of a [`StreamAuthority`] the connector also holds.
///
/// A named wrapper rather than an implementation on `Arc<StreamAuthority>`,
/// because both the trait and `Arc` come from other crates.
#[derive(Clone, Debug)]
pub struct SharedAuthority(Arc<StreamAuthority>);

impl SharedAuthority {
    /// Share `authority` with a provider.
    #[must_use]
    pub const fn new(authority: Arc<StreamAuthority>) -> Self {
        Self(authority)
    }
}

impl Authority for SharedAuthority {
    fn current(&self) -> Authorization {
        Authorization {
            revision: self.0.revision.load(Ordering::Acquire),
            grant: unpack(self.0.grant.load(Ordering::Acquire)),
            fresh: self.0.fresh.load(Ordering::Acquire),
        }
    }
}

fn pack(grant: CapabilitySet) -> u64 {
    let mut bits = 0_u64;
    for (index, capability) in Capability::ALL.into_iter().enumerate() {
        if grant.allows(capability) {
            bits |= 1 << index;
        }
    }
    bits
}

fn unpack(bits: u64) -> CapabilitySet {
    let mut set = CapabilitySet::DENY;
    for (index, capability) in Capability::ALL.into_iter().enumerate() {
        if bits & (1 << index) != 0 {
            set = set.with(capability);
        }
    }
    set
}

/// How one filesystem exchange ended. Payload-free.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsExchangeReport {
    /// The provider's counters at the end of the session.
    pub stats: ProviderStats,
    /// The close code the session ended with, if it ended with one.
    pub closed_with: Option<SessionErrorCode>,
    /// The session ended because the inbound byte stream violated the 9P
    /// framing rules.
    pub framing_violation: bool,
    /// The export root could not be opened at all.
    pub root_unavailable: bool,
    /// The grant named no capability this device serves.
    pub empty_grant: bool,
}

/// Serve one filesystem stream to completion.
///
/// Reads ordered bytes from `inbound`, writes the provider's records to
/// `outbound`, and returns a payload-free report.
#[cfg_attr(not(unix), allow(unused_variables))]
pub async fn serve(
    export: FsExport,
    grant: CapabilitySet,
    authority: Arc<StreamAuthority>,
    inbound: FrameReceiver,
    outbound: FrameSender,
) -> FsExchangeReport {
    #[cfg(not(unix))]
    {
        // Gate 2 declares filesystem exports unsupported on a non-Unix host in
        // one function, and this is the other side of that declaration: the
        // connector answers no session rather than a degraded one.
        let _ = (export, grant, authority, inbound);
        let _ = outbound.finish();
        FsExchangeReport {
            root_unavailable: true,
            ..FsExchangeReport::default()
        }
    }
    #[cfg(unix)]
    {
        serve_unix(export, grant, authority, inbound, outbound).await
    }
}

#[cfg(unix)]
async fn serve_unix(
    export: FsExport,
    grant: CapabilitySet,
    authority: Arc<StreamAuthority>,
    mut inbound: FrameReceiver,
    outbound: FrameSender,
) -> FsExchangeReport {
    let mut report = FsExchangeReport::default();
    // The connector's own local allowlist, applied as an intersection: a relay
    // cannot name a capability the operator did not configure.
    let effective = intersect(grant, export.allowed);
    if effective.is_empty() {
        report.empty_grant = true;
        let _ = outbound.finish();
        return report;
    }
    let Ok(root) = tunnel_fs_host::ExportRoot::open(
        &export.root,
        effective,
        export.features,
        export.limits.path_bounds(),
    ) else {
        report.root_unavailable = true;
        let _ = outbound.finish();
        return report;
    };
    let Some(mut provider) = Provider::new(root, export.limits, SharedAuthority::new(authority))
    else {
        report.empty_grant = true;
        let _ = outbound.finish();
        return report;
    };

    let mut decoder = FrameDecoder::new();
    let mut applied_msize = MAX_MESSAGE_BYTES;
    // Admitting **every request already available** takes priority over
    // performing a queued one.
    //
    // This is not an optimisation, and getting it wrong makes a rule
    // unenforceable rather than slow. A loop that drained the queue after each
    // decoded frame would perform a pipelined `Tread` before it had even
    // decoded the `Tflush` that follows it, so the flush could never win the
    // race and `Provider`'s drop path would be unreachable from a client — the
    // contract permits the flush to lose, but a dispatcher that makes it
    // *always* lose has not implemented cancellation, it has implemented
    // nothing. So each turn of this loop prefers input that is ready now and
    // performs exactly one queued request when none is.
    //
    // `FrameReceiver::recv` awaits only its channel and does its bookkeeping
    // after, so dropping it in the `select!` below loses nothing; that is what
    // makes "read what is ready, otherwise make progress" expressible at all.
    'stream: loop {
        let ready = if provider.has_work() {
            tokio::select! {
                biased;
                frame = inbound.recv() => Some(frame),
                () = std::future::ready(()) => None,
            }
        } else {
            Some(inbound.recv().await)
        };

        let bytes = match ready {
            // Nothing is waiting to be read: perform one queued request.
            None => {
                if emit(&outbound, provider.step(), &mut provider, &mut report).await {
                    break 'stream;
                }
                continue;
            }
            Some(None) => break,
            Some(Some(Frame::Data(bytes))) => bytes,
            // Either terminal ends the session; a 9P session has no half-close.
            Some(Some(Frame::Fin | Frame::Reset(_))) => break,
        };

        let mut input: &[u8] = &bytes;
        loop {
            let decoded = match decoder.decode(&mut input) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => {
                    // Every framing failure is answered by closing with 1002
                    // and is never an `Rlerror`: the tag that would correlate
                    // one is part of the frame that failed to decode.
                    report.framing_violation = true;
                    report.closed_with = Some(SessionErrorCode::ProtocolViolation);
                    emit_close(&outbound, SessionErrorCode::ProtocolViolation).await;
                    break 'stream;
                }
            };
            // Only the answers that need no host work — the version handshake
            // and `Tflush` — come back here; everything else is queued.
            let admitted = provider.accept(&decoded);
            if emit(&outbound, admitted, &mut provider, &mut report).await {
                break 'stream;
            }
            // The decoder's bound follows the negotiation, reduction only and
            // only at a frame boundary.
            if provider.msize() < applied_msize && decoder.apply_msize(provider.msize()).is_ok() {
                applied_msize = provider.msize();
            }
        }
    }
    report.stats = provider.stats();
    provider.close();
    let _ = outbound.finish();
    report
}

/// Write one batch of the provider's answers. Returns whether the session ended.
///
/// A reply is encoded and sent one at a time rather than collected first, so the
/// bytes this task holds outside the carrier are bounded by one `msize` however
/// many requests a client pipelined.
#[cfg(unix)]
async fn emit(
    outbound: &FrameSender,
    outbounds: Vec<Outbound>,
    provider: &mut Provider<SharedAuthority>,
    report: &mut FsExchangeReport,
) -> bool {
    for out in outbounds {
        match out {
            Outbound::Frame(frame) => {
                let mut encoded = Vec::new();
                if frame.encode(provider.msize(), &mut encoded).is_err() {
                    report.closed_with = Some(SessionErrorCode::ProtocolViolation);
                    emit_close(outbound, SessionErrorCode::ProtocolViolation).await;
                    return true;
                }
                let mut record = Vec::with_capacity(encoded.len() + RECORD_HEADER_LEN);
                encode_message(&encoded, &mut record);
                // The mutation ledger is settled here and nowhere else,
                // because this is the only place that knows whether the reply
                // left. A reply reporting an effect that reached the carrier is
                // acknowledged; one that did not is the contract's `unknown`
                // outcome — "Session loss during a potentially dispatched
                // mutation carries `outcome: unknown`" — and it is recorded
                // rather than guessed either way. Reaching the carrier is all a
                // device can ever confirm, and the contract is explicit that it
                // proves neither the side effect nor its delivery.
                if outbound.send_data(Bytes::from(record)).await.is_err() {
                    provider.note_effect_undelivered();
                    return true;
                }
                provider.confirm_effect_delivered();
            }
            Outbound::Close(code) => {
                report.closed_with = Some(code);
                emit_close(outbound, code).await;
                return true;
            }
        }
    }
    false
}

async fn emit_close(outbound: &FrameSender, code: SessionErrorCode) {
    let mut record = Vec::with_capacity(6);
    encode_close(code, &mut record);
    let _ = outbound.send_data(Bytes::from(record)).await;
}

/// The capabilities both the relay's OPEN and the local allowlist name.
///
/// Public because the connector applies it **before** building the stream's
/// [`StreamAuthority`]: the authority is what the provider rechecks a queued
/// request against, so it must hold the effective grant rather than the wider
/// one the relay named. Applying it twice is harmless — the operation is
/// idempotent — and [`serve`] applies it again so the narrowing is a property of
/// this module rather than of its caller.
#[must_use]
pub fn intersect(left: CapabilitySet, right: CapabilitySet) -> CapabilitySet {
    let mut set = CapabilitySet::DENY;
    for capability in Capability::ALL {
        if left.allows(capability) && right.allows(capability) {
            set = set.with(capability);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::{StreamAuthority, intersect, pack, parse_capabilities, unpack};
    use std::sync::Arc;
    use tunnel_fs_core::{Capability, CapabilitySet};
    use tunnel_fs_provider::Authority as _;

    #[test]
    fn capability_metadata_round_trips_and_ignores_what_it_cannot_enforce() {
        assert_eq!(parse_capabilities(""), CapabilitySet::DENY);
        assert_eq!(
            parse_capabilities("read,list"),
            CapabilitySet::from_slice(&[Capability::Read, Capability::List])
        );
        // A name this build cannot enforce is treated as absent, never as a
        // reason to refuse the session.
        assert_eq!(
            parse_capabilities("read, execute, list"),
            CapabilitySet::from_slice(&[Capability::Read, Capability::List])
        );
        assert_eq!(parse_capabilities("execute,admin,*"), CapabilitySet::DENY);
    }

    #[test]
    fn the_local_allowlist_narrows_and_never_widens() {
        let relay = CapabilitySet::from_slice(&[
            Capability::Read,
            Capability::Write,
            Capability::List,
            Capability::Delete,
        ]);
        let local = CapabilitySet::from_slice(&[Capability::Read, Capability::List]);
        let effective = intersect(relay, local);
        assert!(effective.allows(Capability::Read));
        assert!(effective.allows(Capability::List));
        assert!(!effective.allows(Capability::Write));
        assert!(!effective.allows(Capability::Delete));
        // And the other way: a relay naming less than the allowlist wins too.
        assert_eq!(
            intersect(CapabilitySet::from_slice(&[Capability::Read]), local),
            CapabilitySet::from_slice(&[Capability::Read])
        );
    }

    #[test]
    fn every_capability_set_survives_the_atomic_packing() {
        for bits in 0..16_u8 {
            let mut set = CapabilitySet::DENY;
            for (index, capability) in Capability::ALL.into_iter().enumerate() {
                if bits & (1 << index) != 0 {
                    set = set.with(capability);
                }
            }
            assert_eq!(unpack(pack(set)), set);
        }
    }

    #[test]
    fn an_invalidated_authority_reports_stale_without_changing_the_grant() {
        let grant = CapabilitySet::from_slice(&[Capability::Read, Capability::List]);
        let authority = super::SharedAuthority::new(Arc::new(StreamAuthority::new(11, grant)));
        let live = authority.current();
        assert_eq!(live.revision, 11);
        assert_eq!(live.grant, grant);
        assert!(live.fresh);

        authority.0.invalidate();
        let live = authority.current();
        assert!(!live.fresh);
        assert_eq!(live.grant, grant, "invalidation is not a narrowing");

        authority
            .0
            .confirm(12, CapabilitySet::from_slice(&[Capability::List]));
        let live = authority.current();
        assert_eq!(live.revision, 12);
        assert!(live.fresh);
        assert_eq!(live.grant, CapabilitySet::from_slice(&[Capability::List]));
    }
}
