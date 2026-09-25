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

#[cfg(unix)]
use bytes::Bytes;

use tunnel_fs_core::{Capability, CapabilitySet, Feature, FeatureSet, Limits, SessionErrorCode};
use tunnel_fs_provider::{Authority, Authorization, ProviderStats, default_limits};
use tunnel_http_bridge::{FrameReceiver, FrameSender};
// The serving half needs the Unix-only dispatcher; on any other host `serve`
// answers no session, and `RuntimeConfig::validate` has already refused an fs
// export there with "filesystem exports are unsupported on this host".
#[cfg(unix)]
use tunnel_fs_ninep::{FrameDecoder, MAX_MESSAGE_BYTES};
#[cfg(unix)]
use tunnel_fs_provider::{Outbound, Provider, RECORD_HEADER_LEN, encode_close, encode_message};
#[cfg(unix)]
use tunnel_http_bridge::Frame;

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
    /// The session was closed because it stayed idle -- nothing queued,
    /// nothing received -- for the export's `sessionIdleSeconds` (M4-21).
    pub idle_timeout: bool,
    /// The session was closed because a reply waited and the carrier granted
    /// no credit for the export's `requestTimeoutSeconds` (M4-21): the
    /// consumer stopped taking replies.
    pub reply_stalled: bool,
    /// A stalled session ended with a stream RESET rather than a close record,
    /// because part of a reply was already on the carrier or the close record
    /// itself could not be sent (M4-21).
    pub stall_reset: bool,
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
    // The descriptor's `sessionIdleSeconds`, applied here because this is the
    // one place on the device that has both the clock and the knowledge that
    // nothing is queued (task row M4-21). The provider is clockless by design.
    let idle = std::time::Duration::from_secs(export.limits.session_idle_seconds());
    // The descriptor's `requestTimeoutSeconds`, applied as a **stall** bound
    // (task row M4-21, applied by default pending owner confirmation,
    // 2026-09-25; narrowed on review). The session is closed only when a reply
    // is waiting and the carrier has granted **no credit at all** for that
    // long: a consumer that has stopped taking replies. A slow but steady
    // consumer keeps its session however long the whole transfer takes,
    // because every credit grant moves a chunk and restarts the clock. Without
    // this a consumer that pipelined requests and stopped reading held the
    // session, its fids and its root descriptor for as long as it kept the
    // socket, because queued or unsent work is never idle.
    let stall_limit = std::time::Duration::from_secs(export.limits.request_timeout_seconds());
    let mut out = Outgoing::default();
    let mut last_activity = tokio::time::Instant::now();
    // Admitting every request already available takes priority over
    // performing a queued one, and -- since M4-21's review -- also over
    // waiting for carrier credit: input is read **while a reply is parked**,
    // so a `Tflush` for a queued request still reaches the provider in time to
    // win, and a request queued behind a stalled reply can still be flushed.
    // A loop that performed a pipelined `Tread` before decoding the `Tflush`
    // behind it would make cancellation unreachable from a client. Input is
    // bounded by `PENDING_CAP`: past it the loop stops reading, so a consumer
    // that sends refusable frames and takes no replies cannot grow this
    // buffer without bound.
    'stream: loop {
        let reading = !out.terminal && out.bytes < PENDING_CAP;
        let can_step = out.records.is_empty() && !out.terminal && provider.has_work();
        let idle_wait = out.records.is_empty() && !out.terminal && !provider.has_work();
        let stall_at = out.progress_at + stall_limit;
        let idle_at = last_activity + idle;
        let chunk = out.next_chunk(&outbound);
        enum Event {
            Input(Option<Frame>),
            Sent(Result<(), tunnel_http_bridge::SendError>),
            Stalled,
            Step,
            Idle,
        }
        let event = tokio::select! {
            biased;
            frame = inbound.recv(), if reading => Event::Input(frame),
            sent = send_chunk(&outbound, chunk.clone()), if chunk.is_some() => Event::Sent(sent),
            () = tokio::time::sleep_until(stall_at), if chunk.is_some() => Event::Stalled,
            () = std::future::ready(()), if can_step => Event::Step,
            () = tokio::time::sleep_until(idle_at), if idle_wait => Event::Idle,
            // Nothing to read (the buffer is full or a close is queued) and
            // nothing to send: only possible once a terminal record is out.
            else => break 'stream,
        };
        match event {
            Event::Input(None | Some(Frame::Fin | Frame::Reset(_))) => break 'stream,
            Event::Input(Some(Frame::Data(bytes))) => {
                last_activity = tokio::time::Instant::now();
                let mut input: &[u8] = &bytes;
                loop {
                    let decoded = match decoder.decode(&mut input) {
                        Ok(Some(frame)) => frame,
                        Ok(None) => break,
                        Err(_) => {
                            // Every framing failure is answered by closing
                            // with 1002 and is never an `Rlerror`: the tag
                            // that would correlate one is part of the frame
                            // that failed to decode.
                            report.framing_violation = true;
                            out.push_close(&mut report, SessionErrorCode::ProtocolViolation);
                            break;
                        }
                    };
                    // Only the answers that need no host work -- the version
                    // handshake and `Tflush` -- come back here; everything
                    // else is queued.
                    let answered = provider.accept(&decoded);
                    if out.push(answered, &provider, &mut report) {
                        break;
                    }
                    // The decoder's bound follows the negotiation, reduction
                    // only and only at a frame boundary.
                    if provider.msize() < applied_msize
                        && decoder.apply_msize(provider.msize()).is_ok()
                    {
                        applied_msize = provider.msize();
                    }
                }
            }
            Event::Step => {
                let performed = provider.step();
                out.push(performed, &provider, &mut report);
            }
            Event::Sent(Err(_)) => {
                // The carrier is gone. An effect whose reply did not get out
                // is `unknown`: it happened and the consumer was never told.
                provider.note_effect_undelivered();
                break 'stream;
            }
            Event::Sent(Ok(())) => {
                last_activity = tokio::time::Instant::now();
                match out.advance(chunk.map_or(0, |bytes| bytes.len())) {
                    Advanced::Partial => {}
                    Advanced::Record { effect } => {
                        // The mutation ledger is settled here and nowhere
                        // else, because this is the only place that knows the
                        // reply reached the carrier -- all a device can ever
                        // confirm; the contract is explicit that it proves
                        // neither the side effect nor its delivery.
                        if effect {
                            provider.confirm_effect_delivered();
                        }
                    }
                    Advanced::Terminal => break 'stream,
                }
            }
            Event::Stalled => {
                // No credit for `requestTimeoutSeconds` with a reply waiting.
                provider.note_effect_undelivered();
                report.reply_stalled = true;
                if out.front_sent() == 0 {
                    // Nothing of the waiting record has left, so the stream is
                    // at a record boundary and a close record is well formed.
                    // It is a courtesy a stalled consumer may never make room
                    // for, so it is bounded; if it cannot be sent whole the
                    // stream is reset instead.
                    report.closed_with = Some(SessionErrorCode::DeadlineExceeded);
                    let mut record = Vec::with_capacity(6);
                    encode_close(SessionErrorCode::DeadlineExceeded, &mut record);
                    if tokio::time::timeout(
                        CLOSE_RECORD_GRACE,
                        outbound.send_data(Bytes::from(record)),
                    )
                    .await
                    .is_err()
                    {
                        report.stall_reset = true;
                        outbound.reset(STALL_RESET);
                    }
                } else {
                    // Part of a record is already on the carrier. Appending a
                    // close record now would splice it into the middle of that
                    // reply, and the relay's record decoder would read the
                    // splice as a framing violation. The stream is reset
                    // instead: the relay closes the consumer 1011
                    // `SESSION_LOST` and forwards none of the partial reply
                    // (`crates/tunnel-relay/src/http/fs.rs`, M4-21).
                    report.stall_reset = true;
                    report.closed_with = Some(SessionErrorCode::SessionLost);
                    outbound.reset(STALL_RESET);
                }
                provider.close();
                report.stats = provider.stats();
                return report;
            }
            Event::Idle => {
                // Nothing queued and nothing performing: the session is idle.
                // The contract's "Idle session timeout with no requests or
                // operations" ends it here, with gate 1's own deadline code,
                // rather than holding a device-side session and its fids for
                // as long as a consumer cares to keep a socket.
                report.idle_timeout = true;
                out.push_close(&mut report, SessionErrorCode::DeadlineExceeded);
            }
        }
    }
    report.stats = provider.stats();
    provider.close();
    let _ = outbound.finish();
    report
}

/// The most a session holds outside the carrier before it stops reading
/// input: two full messages. A step's reply is at most one `msize`, and the
/// answers `accept` produces while it waits (`Rflush`, `Rlerror`) are small.
#[cfg(unix)]
const PENDING_CAP: usize = 2 * MAX_MESSAGE_BYTES as usize;

/// The smallest amount a send waits for when the carrier shows no credit.
/// Credit comes back in the sizes of frames already sent, which are at least
/// this large unless the whole record was smaller, so a wait of this size is
/// satisfied by the first grant that could carry any of it.
#[cfg(unix)]
const MIN_CREDIT_WAIT: usize = 512;

/// The RESET a stalled reply ends with: a deadline, with the reply's effect
/// possibly applied. `reset_reason_for` carries it as `ADAPTER_FAILURE`.
#[cfg(unix)]
const STALL_RESET: tunnel_http_bridge::ResetDetail = tunnel_http_bridge::ResetDetail {
    code: tunnel_http_bridge::HttpErrorCode::DeadlineExceeded,
    execution: tunnel_http_bridge::Execution::Unknown,
};

/// Records produced by the provider and not yet wholly on the carrier.
#[cfg(unix)]
struct Outgoing {
    records: std::collections::VecDeque<OutRecord>,
    /// Bytes of `records` not yet sent.
    bytes: usize,
    /// When the carrier last granted credit, or when a reply started waiting.
    progress_at: tokio::time::Instant,
    /// A close record is queued: nothing is read or performed after it.
    terminal: bool,
}

#[cfg(unix)]
struct OutRecord {
    bytes: Bytes,
    sent: usize,
    /// The reply reports an effect the provider is holding as undelivered.
    effect: bool,
    /// A close record: the session ends once it is out.
    close: bool,
}

#[cfg(unix)]
enum Advanced {
    Partial,
    Record { effect: bool },
    Terminal,
}

#[cfg(unix)]
impl Default for Outgoing {
    fn default() -> Self {
        Self {
            records: std::collections::VecDeque::new(),
            bytes: 0,
            progress_at: tokio::time::Instant::now(),
            terminal: false,
        }
    }
}

#[cfg(unix)]
impl Outgoing {
    fn enqueue(&mut self, record: OutRecord) {
        if self.records.is_empty() {
            self.progress_at = tokio::time::Instant::now();
        }
        self.bytes += record.bytes.len();
        self.terminal |= record.close;
        self.records.push_back(record);
    }

    /// Queue the provider's answers. Returns whether the session is closing.
    fn push(
        &mut self,
        outbounds: Vec<Outbound>,
        provider: &Provider<SharedAuthority>,
        report: &mut FsExchangeReport,
    ) -> bool {
        for out in outbounds {
            match out {
                Outbound::Frame(frame) => {
                    let mut encoded = Vec::new();
                    if frame.encode(provider.msize(), &mut encoded).is_err() {
                        self.push_close(report, SessionErrorCode::ProtocolViolation);
                        return true;
                    }
                    let mut record = Vec::with_capacity(encoded.len() + RECORD_HEADER_LEN);
                    encode_message(&encoded, &mut record);
                    self.enqueue(OutRecord {
                        bytes: Bytes::from(record),
                        sent: 0,
                        effect: provider.reply_carries_effect(),
                        close: false,
                    });
                }
                Outbound::Close(code) => {
                    self.push_close(report, code);
                    return true;
                }
            }
        }
        false
    }

    fn push_close(&mut self, report: &mut FsExchangeReport, code: SessionErrorCode) {
        if self.terminal {
            return;
        }
        report.closed_with = Some(code);
        let mut record = Vec::with_capacity(6);
        encode_close(code, &mut record);
        self.enqueue(OutRecord {
            bytes: Bytes::from(record),
            sent: 0,
            effect: false,
            close: true,
        });
    }

    /// The next piece of the front record to offer the carrier: as much as
    /// the carrier has credit for, so any grant at all is progress.
    fn next_chunk(&self, outbound: &FrameSender) -> Option<Bytes> {
        let front = self.records.front()?;
        let remaining = front.bytes.len() - front.sent;
        let available = outbound.available_credit();
        let take = remaining
            .min(outbound.capacity())
            .min(if available > 0 {
                available
            } else {
                MIN_CREDIT_WAIT
            })
            .max(1);
        Some(front.bytes.slice(front.sent..front.sent + take))
    }

    fn advance(&mut self, sent: usize) -> Advanced {
        self.progress_at = tokio::time::Instant::now();
        self.bytes -= sent;
        let Some(front) = self.records.front_mut() else {
            return Advanced::Partial;
        };
        front.sent += sent;
        if front.sent < front.bytes.len() {
            return Advanced::Partial;
        }
        let done = self.records.pop_front().expect("front exists");
        if done.close {
            Advanced::Terminal
        } else {
            Advanced::Record {
                effect: done.effect,
            }
        }
    }

    fn front_sent(&self) -> usize {
        self.records.front().map_or(0, |front| front.sent)
    }
}

/// Offer one piece of a record to the carrier. Cancel-safe for this loop's
/// use: a piece no larger than the carrier's capacity is one credit
/// acquisition followed by a queue push that never waits, so it is either
/// wholly queued or not queued at all.
#[cfg(unix)]
async fn send_chunk(
    outbound: &FrameSender,
    chunk: Option<Bytes>,
) -> Result<(), tunnel_http_bridge::SendError> {
    match chunk {
        Some(bytes) => outbound.send_data(bytes).await,
        None => std::future::pending().await,
    }
}

/// How long a close record may wait for carrier credit before the stream is
/// reset instead. The close is a courtesy the consumer may never read -- a
/// consumer that stopped taking replies is exactly the one that also withholds
/// the credit this needs -- so it is bounded rather than awaited (M4-21).
#[cfg(unix)]
const CLOSE_RECORD_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

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

    /// Task row M4-21: the descriptor advertises `sessionIdleSeconds`, and
    /// until this nothing applied it -- a consumer could hold a device-side
    /// session, its fids and its root descriptor for as long as it kept a
    /// socket open. A session with nothing queued and nothing received for
    /// that long is now closed by the device with gate 1's deadline code.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_idle_session_is_closed_at_the_advertised_idle_limit() {
        use tunnel_fs_core::{Limits, SessionErrorCode};
        let root = tempfile::tempdir().expect("synthetic export root");
        let limits = Limits::new([
            65_536, 64, 256, 1_048_576, 16_777_216, 33_554_432, 4_096, 256, 10_000, 64, 30, 300,
            3_600, 1, // sessionIdleSeconds: the smallest value gate 1 admits
        ])
        .expect("valid limits");
        assert_eq!(limits.session_idle_seconds(), 1);
        let export = super::FsExport {
            limits,
            ..super::FsExport::read_only(root.path())
        };
        let grant = CapabilitySet::from_slice(&[Capability::Read, Capability::List]);
        let authority = Arc::new(StreamAuthority::new(1, grant));
        // The inbound sender is held for the whole test: the consumer is
        // connected and silent, not gone.
        let (_inbound_tx, inbound_rx, _) = tunnel_http_bridge::channel(65_536);
        let (outbound_tx, mut outbound_rx, _) = tunnel_http_bridge::channel(65_536);
        let started = std::time::Instant::now();
        let report = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            super::serve(export, grant, authority, inbound_rx, outbound_tx),
        )
        .await
        .expect("an idle session must end at its advertised idle limit");
        assert!(report.idle_timeout);
        assert_eq!(report.closed_with, Some(SessionErrorCode::DeadlineExceeded));
        assert!(
            started.elapsed() >= std::time::Duration::from_secs(1),
            "not before the limit"
        );
        let mut expected = Vec::new();
        tunnel_fs_provider::encode_close(SessionErrorCode::DeadlineExceeded, &mut expected);
        match outbound_rx.recv().await {
            Some(tunnel_http_bridge::Frame::Data(bytes)) => {
                assert_eq!(bytes.as_ref(), expected.as_slice(), "the close record");
            }
            other => panic!("expected the close record, got {other:?}"),
        }
    }

    /// A 9P test consumer over the two in-memory stream halves `serve` uses:
    /// it writes requests into the inbound direction and decodes the device's
    /// records from the outbound one, taking credit only as fast as it reads.
    #[cfg(unix)]
    struct TestConsumer {
        tx: tunnel_http_bridge::FrameSender,
        rx: tunnel_http_bridge::FrameReceiver,
        records: tunnel_fs_provider::RecordDecoder,
    }

    #[cfg(unix)]
    #[derive(Debug)]
    enum Seen {
        Reply(tunnel_fs_ninep::Frame),
        Close(tunnel_fs_core::SessionErrorCode),
        /// The stream was reset, after this many bytes of a partial record.
        Reset(usize),
        End,
    }

    #[cfg(unix)]
    impl TestConsumer {
        async fn send(&self, frame: tunnel_fs_ninep::Frame) {
            let mut bytes = Vec::new();
            frame.encode(65_536, &mut bytes).expect("encode request");
            self.tx
                .send_data(bytes::Bytes::from(bytes))
                .await
                .expect("queue the request");
        }

        /// The next thing the device said, reading at most `per_second`
        /// bytes a second (`None`: as fast as it arrives).
        async fn next(&mut self, per_second: Option<u64>) -> Seen {
            loop {
                match self.records.next_record().expect("well-formed records") {
                    Some(tunnel_fs_provider::Record::Message(message)) => {
                        let frame = tunnel_fs_ninep::decode_exact(
                            &message,
                            tunnel_fs_ninep::MAX_MESSAGE_BYTES,
                        )
                        .expect("a 9P reply");
                        return Seen::Reply(frame);
                    }
                    Some(tunnel_fs_provider::Record::Close(code)) => return Seen::Close(code),
                    None => {}
                }
                match self.rx.recv().await {
                    Some(tunnel_http_bridge::Frame::Data(bytes)) => {
                        if let Some(rate) = per_second {
                            let micros = bytes.len() as u64 * 1_000_000 / rate;
                            tokio::time::sleep(std::time::Duration::from_micros(micros)).await;
                        }
                        self.records.push(&bytes).expect("record framing");
                    }
                    Some(tunnel_http_bridge::Frame::Reset(_)) => {
                        return Seen::Reset(self.records.retained());
                    }
                    Some(tunnel_http_bridge::Frame::Fin) | None => return Seen::End,
                }
            }
        }

        async fn reply(&mut self) -> tunnel_fs_ninep::Frame {
            match self.next(None).await {
                Seen::Reply(frame) => frame,
                other => panic!("expected a reply, got {other:?}"),
            }
        }
    }

    /// An export holding `data.bin` of `len` synthetic bytes, served with the
    /// given request deadline, and a consumer that has attached and opened it
    /// as fid 1.
    #[cfg(unix)]
    async fn opened_session(
        len: usize,
        request_timeout_seconds: u64,
        inbound_capacity: usize,
        outbound_capacity: usize,
    ) -> (
        TestConsumer,
        tokio::task::JoinHandle<super::FsExchangeReport>,
        tempfile::TempDir,
    ) {
        use tunnel_fs_ninep::{Frame, Message, NOFID, NONUNAME, NOTAG};
        let root = tempfile::tempdir().expect("synthetic export root");
        let bytes: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
        std::fs::write(root.path().join("data.bin"), bytes).expect("synthetic file");
        let limits = tunnel_fs_core::Limits::new([
            65_536,
            64,
            256,
            1_048_576,
            16_777_216,
            33_554_432,
            4_096,
            256,
            10_000,
            64,
            request_timeout_seconds,
            300,
            3_600,
            300,
        ])
        .expect("valid limits");
        let export = super::FsExport {
            limits,
            ..super::FsExport::read_only(root.path())
        };
        let grant = CapabilitySet::from_slice(&[Capability::Read, Capability::List]);
        let authority = Arc::new(StreamAuthority::new(1, grant));
        let (inbound_tx, inbound_rx, _) = tunnel_http_bridge::channel(inbound_capacity);
        let (outbound_tx, outbound_rx, _) = tunnel_http_bridge::channel(outbound_capacity);
        let task = tokio::spawn(super::serve(
            export,
            grant,
            authority,
            inbound_rx,
            outbound_tx,
        ));
        let mut consumer = TestConsumer {
            tx: inbound_tx,
            rx: outbound_rx,
            records: tunnel_fs_provider::RecordDecoder::new(),
        };
        consumer
            .send(Frame::new(
                NOTAG,
                Message::Tversion {
                    msize: 65_536,
                    version: tunnel_fs_ninep::DIALECT.to_owned(),
                },
            ))
            .await;
        assert!(matches!(
            consumer.reply().await.message,
            Message::Rversion { .. }
        ));
        consumer
            .send(Frame::new(
                1,
                Message::Tattach {
                    fid: 0,
                    afid: NOFID,
                    uname: String::new(),
                    aname: String::new(),
                    n_uname: NONUNAME,
                },
            ))
            .await;
        assert!(matches!(
            consumer.reply().await.message,
            Message::Rattach { .. }
        ));
        consumer
            .send(Frame::new(
                2,
                Message::Twalk {
                    fid: 0,
                    newfid: 1,
                    names: vec!["data.bin".to_owned()],
                },
            ))
            .await;
        assert!(matches!(
            consumer.reply().await.message,
            Message::Rwalk { .. }
        ));
        consumer
            .send(Frame::new(
                3,
                Message::Tlopen {
                    fid: 1,
                    flags: tunnel_fs_ninep::flags::O_RDONLY,
                },
            ))
            .await;
        assert!(matches!(
            consumer.reply().await.message,
            Message::Rlopen { .. }
        ));
        (consumer, task, root)
    }

    #[cfg(unix)]
    fn tread(tag: u16, offset: u64, count: u32) -> tunnel_fs_ninep::Frame {
        tunnel_fs_ninep::Frame::new(
            tag,
            tunnel_fs_ninep::Message::Tread {
                fid: 1,
                offset,
                count,
            },
        )
    }

    /// Task row M4-21, as narrowed on review: the request deadline bounds a
    /// **stall**, not a transfer. Four pipelined 60 KiB reads drained at
    /// 32 KiB/s take about 7.5 seconds, and **each single reply** takes about
    /// two -- twice the 1-second deadline configured here -- so the session
    /// survives only if every credit grant restarts the clock, not merely the
    /// start of each reply. The first implementation measured from each
    /// request's admission and closed this consumer after its first reply.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_slow_but_steady_consumer_keeps_its_session() {
        const READS: u16 = 4;
        const COUNT: u32 = 60 * 1_024;
        let (mut consumer, task, _root) =
            opened_session(READS as usize * COUNT as usize, 1, 65_536, 8_192).await;
        for index in 0..READS {
            consumer
                .send(tread(
                    10 + index,
                    u64::from(index) * u64::from(COUNT),
                    COUNT,
                ))
                .await;
        }
        let started = std::time::Instant::now();
        let mut answered = 0_u16;
        let mut bytes = 0_usize;
        while answered < READS {
            match consumer.next(Some(32 * 1_024)).await {
                Seen::Reply(frame) => match frame.message {
                    tunnel_fs_ninep::Message::Rread { data } => {
                        bytes += data.len();
                        answered += 1;
                    }
                    other => panic!("expected Rread, got {other:?}"),
                },
                Seen::Close(code) => panic!("the session closed {code} after {answered} replies"),
                other => panic!("the session ended after {answered} replies: {other:?}"),
            }
        }
        assert!(
            started.elapsed() > std::time::Duration::from_secs(4),
            "the drain must outlast the deadline for this to prove anything"
        );
        assert_eq!(bytes, READS as usize * COUNT as usize);
        drop(consumer);
        let report = task.await.expect("session task");
        assert!(!report.reply_stalled, "{report:?}");
        assert!(!report.stall_reset);
    }

    /// Task row M4-21: a consumer that stops taking replies is closed once the
    /// carrier has granted no credit for the request deadline -- and, because
    /// part of the waiting reply is already on the carrier, by a stream RESET
    /// rather than a close record spliced into the middle of that reply. The
    /// relay turns that RESET into a 1011 `SESSION_LOST` close and forwards
    /// none of the partial reply (see the relay's
    /// `a_reset_after_a_partial_record_closes_the_consumer_1011_and_forwards_nothing`).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_consumer_that_stops_taking_replies_is_reset_at_the_stall_deadline() {
        let (mut consumer, task, _root) = opened_session(64 * 1_024, 1, 65_536, 8_192).await;
        consumer.send(tread(10, 0, 32 * 1_024)).await;
        // Take nothing: the first 8 KiB of the reply fills the carrier's credit
        // and the rest waits.
        let started = std::time::Instant::now();
        let report = tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("a stalled consumer must be closed at the deadline")
            .expect("session task");
        assert!(started.elapsed() >= std::time::Duration::from_secs(1));
        assert!(report.reply_stalled, "{report:?}");
        assert!(
            report.stall_reset,
            "part of the reply was out: a RESET, not a close record"
        );
        assert_eq!(
            report.closed_with,
            Some(tunnel_fs_core::SessionErrorCode::SessionLost)
        );
        match consumer.next(None).await {
            Seen::Reset(partial) => assert!(partial > 0, "a partial record was held"),
            other => panic!("expected the partial reply then a RESET, got {other:?}"),
        }
    }

    /// Task row M4-21's review: input is read **while a reply waits for
    /// credit**. The inbound direction here holds exactly one `Tflush`, so the
    /// second one can only be queued once the loop has read the first -- which
    /// the first implementation never did while it was parked on a send. And
    /// the flush it reads must win: the queued read it names is never
    /// performed.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_flush_is_read_while_a_reply_waits_for_credit() {
        use tunnel_fs_ninep::{Frame, Message};
        let flush = |tag: u16, oldtag: u16| Frame::new(tag, Message::Tflush { oldtag });
        let mut one = Vec::new();
        flush(12, 11).encode(65_536, &mut one).expect("encode");
        let (mut consumer, task, _root) = opened_session(64 * 1_024, 30, one.len(), 8_192).await;
        consumer.send(tread(10, 0, 32 * 1_024)).await;
        consumer.send(tread(11, 0, 32 * 1_024)).await;
        // Read 10's reply is now parked on the carrier's credit and read 11
        // is queued behind it. Neither flush can be queued unless the loop
        // is reading input meanwhile.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            consumer.send(flush(12, 11)).await;
            consumer.send(flush(13, 11)).await;
        })
        .await
        .expect("input must be read while a reply waits for credit");
        let mut tags = Vec::new();
        for _ in 0..3 {
            match consumer.next(None).await {
                Seen::Reply(frame) => tags.push((frame.tag, frame.message.message_type())),
                other => panic!("expected a reply, got {other:?}"),
            }
        }
        assert_eq!(tags[0].0, 10, "the parked read is delivered: {tags:?}");
        assert!(
            tags.iter().all(|(tag, _)| *tag != 11),
            "the flushed read must never be performed: {tags:?}"
        );
        drop(consumer);
        let report = task.await.expect("session task");
        assert_eq!(report.stats.dropped_after_flush, 1, "{report:?}");
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
