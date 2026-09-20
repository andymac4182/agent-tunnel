//! A live 9P2000.L filesystem session held **with a request outstanding**
//! while the device's **control session is replaced and the owner claim takes
//! a strictly greater epoch**, over the real cluster: a consumer WSS session
//! through the owning relay's public route, the owner actor, the device data
//! WebSocket and `tunnel-client`'s filesystem export.
//!
//! This is M4-06's *control-epoch change* clause.  [`docs/filesystem-api.md`]
//! names it in the same sentence as this gate's predecessor's event:
//!
//! > Consumer loss, control-epoch change, grant expiry, or process restart
//! > invalidates the filesystem session.
//!
//! and `docs/protocol.md` states what "invalidates" obliges, in the paragraph
//! whose *other* sentence licensed gate 7's opposite conclusion:
//!
//! > The first filesystem profile restores no fids across a consumer
//! > WebSocket reconnect, **control-session reconnect** or
//! > adapter/connector/relay process restart: terminate that filesystem
//! > session, **fail pending calls explicitly** and create a fresh 9P session.
//! > Generic tunnel resume support must not silently opt the filesystem
//! > adapter into stronger recovery guarantees.  Replacement of a failed data
//! > socket may preserve the filesystem session only while the same control
//! > owner and all ordered stream state are retained.
//!
//! Reading the clause settles what this gate must assert, and it is not what
//! the same-owner sentence would suggest.  That sentence licenses retention
//! for exactly one event — replacement of a *failed data socket*, and then
//! only while **the same control owner** is retained.  A control-session
//! reconnect is the event that destroys that qualifier: it is named in the
//! *first* sentence, and across it the profile restores no fids at all.  So
//! this gate, like gate 8 and unlike gate 7, must prove that a fid does
//! **not** survive — and a gate asserting survival here would be asserting
//! the violation.
//!
//! The clause carries one obligation gate 8 could not test.  Gate 8's
//! consumer was *gone*, so "fail pending calls explicitly" had nobody to fail
//! them to.  Here the consumer is still connected and still holding an
//! unanswered tag, so the obligation is observable: the gate asserts that the
//! held exchange is **closed with a code** rather than left hanging or
//! quietly answered.
//!
//! **The epoch change is genuinely acquired, not simulated.**  Nothing here
//! writes an epoch number.  `tunnel-client` has no automatic reconnect — its
//! documented transport-failure policy is to "close control and data and
//! require a fresh session" — so the gate stops the connector, waits for the
//! authoritative catalog to report the owner *released*, and starts a second
//! connector on the **same device identity and the same export**.  That
//! connector's own `Tattach`-free control handshake re-claims the device, and
//! the claim script increments the owner epoch.  What is asserted is the
//! strict inequality `epoch_after > epoch_before` read back out of the Redis
//! catalog's owner token, together with a **changed session identity**: a
//! control-session reconnect that kept the same session would not be one.
//!
//! **What makes the change concurrent rather than sequential.**  An epoch
//! change between two settled 9P exchanges would be "an event between two
//! quiet periods", which proves nothing.  The construction is gate 8's, and
//! it is proven from the owner's own per-stream sequence cursors rather than
//! from timing:
//!
//! 1. The consumer opens a fid and reads the first part of a synthetic file,
//!    so the fid is established and serving before anything is perturbed.
//! 2. The device data socket's **connector→relay** bytes are paused at the
//!    harness TCP proxy once the carrier has settled.
//! 3. The owner is sampled *while paused*, fixing this stream's
//!    `last_emitted_relay_to_connector` and
//!    `recv_contiguous_connector_to_relay`.
//! 4. The consumer sends one `Tread` and does **not** read its reply.  The
//!    request crosses on the still-flowing relay→connector direction, so the
//!    owner's `last_emitted_relay_to_connector` for this stream **advances**;
//!    the reply is sequenced into the paused direction, so the owner's
//!    `recv_contiguous_connector_to_relay` **cannot** advance.
//! 5. The gate waits for exactly that pair and replaces the control session
//!    at that instant.  The proof that the exchange was outstanding across
//!    the epoch change is `emitted_at_change > emitted_before &&
//!    recv_contiguous_at_change == recv_contiguous_before`: the relay had
//!    dispatched a 9P record toward the device and had received no answer to
//!    it, on the owner's own cursors.
//!
//! **The assertions are on the operation, not on liveness.**  A cluster that
//! still runs proves nothing about a fid.  What is asserted is that the
//! pending call is failed explicitly with a close code, that the epoch
//! genuinely advanced and the session identity genuinely changed, and then —
//! the contract clause proper — that a replacement consumer session opened
//! **under the new epoch** restores no fids, driven in the two pieces the
//! session machine checks them in, exactly as gate 8 drives them:
//!
//! * **"require fresh version/attach"** — a replacement session that names
//!   the earlier session's file fid *before* attaching is **closed** with the
//!   profile's protocol violation rather than served.  `SessionError` checks
//!   `BeforeAttach` before it consults the fid table, so this probe gets its
//!   own throwaway session and runs first.
//! * **"restores no fids"** — a replacement session that *has* attached, on a
//!   root fid of its own, then finds the earlier session's fid numbers
//!   unbound: they answer `Rlerror` with the errno for a fid that is not
//!   allocated in this session.
//!
//! That session then shows the refusals were fid scoping and not a broken
//! export — nor a second connector that failed to serve the same root — by
//! walking, opening and reading the whole file back with an exact checksum,
//! binding the earlier session's file-fid *number* freshly as it does so.
//!
//! The reuse of the *same fid numbers* is deliberate and is the whole force
//! of the case: if fids leaked across a control-epoch change, fid 1 would
//! still be bound to the file and would answer.
//!
//! All fixture content is synthetic and generated here; no evidence field
//! carries a path, a name or file content.

use std::time::{Duration, Instant};

use tokio::time::{sleep, timeout};
use tunnel_client::{
    ConnectOptions, FsExportSettings, LocalExport, LocalExportKind, http_forward::HttpHandlers,
};
use tunnel_fs_ninep::{GETATTR_BASIC, Message, flags::O_RDONLY};
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot};
use uuid::Uuid;

use super::fs_wire as wire;
use wire::{NinepClient, Target, UpgradeFailure, errno_of, unexpected};

use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::{
    Direction as ProxyDirection, Harness, HarnessError, HarnessOptions, ProxyConfig, ProxyHandle,
    Result, TcpProxy,
};

/// The subprotocol the server must select.
const SUBPROTOCOL: &str = tunnel_fs_core::TRANSPORT_SUBPROTOCOL;
/// The dialect `Rversion` must name.
const DIALECT: &str = tunnel_fs_ninep::DIALECT;
/// The `msize` the gate offers, which is also the profile ceiling.
const OFFERED_MSIZE: u32 = tunnel_fs_ninep::MAX_MESSAGE_BYTES;
/// The largest `count` an `Rread` can answer under [`OFFERED_MSIZE`].
const READ_COUNT: u32 = OFFERED_MSIZE - tunnel_fs_ninep::COUNTED_REPLY_OVERHEAD;

/// The errno an `Rlerror` for a fid that is not allocated in this session
/// carries.
///
/// Derived, not pinned: `SessionError::UnknownFid` answers
/// `FsError::refused(FsErrorCode::Einval)`, so the value is read back out of
/// the library rather than written here as a literal.
const UNKNOWN_FID_ERRNO: u32 = tunnel_fs_core::FsErrorCode::Einval.errno();

/// The close code the held exchange's session is ended with when the device
/// that was serving it goes away.
///
/// Derived, not pinned, exactly as [`UNKNOWN_FID_ERRNO`] is:
/// `SessionErrorCode::DeviceOffline` is the profile's "the export's backend is
/// the thing that went away" code, which is what a control-session
/// replacement is from the consumer's side — the relay is healthy and the
/// device it was proxying to is not.  `close_code()` maps it to 1012 at this
/// revision; the gate asserts the expression, not the number.
const DEVICE_GONE_CLOSE: u16 = match tunnel_fs_core::SessionErrorCode::DeviceOffline.close_code() {
    Some(code) => code,
    // Unreachable: `close_code()` returns `Some` for this variant.
    None => panic!("DeviceOffline must carry a close code"),
};

/// The close code a session that speaks before `Tattach` is ended with.
///
/// `SessionError::BeforeAttach` answers `Close(ProtocolViolation)`, the 9P
/// profile's 1002.  This is the "require fresh version/attach" half of the
/// contract clause, and it is checked **before** the fid table is, which is
/// why the fid probes below have to run on an attached session.
const PROTOCOL_VIOLATION_CLOSE: u16 =
    match tunnel_fs_core::SessionErrorCode::ProtocolViolation.close_code() {
        Some(code) => code,
        // Unreachable: `close_code()` returns `Some` for this variant.
        None => panic!("ProtocolViolation must carry a close code"),
    };

/// The synthetic file the held session is reading.
///
/// Large enough that the read the session is holding is a full-`msize`
/// `Rread` and that the replacement session's verifying transfer needs many
/// messages, so neither is a single-frame special case.
const EPOCH_FILE_BYTES: usize = 786_432;
/// The replacement session's whole-file transfer must need more than this
/// many `Rread` messages.
const MIN_READ_MESSAGES: usize = 10;
/// How much of the file is read before anything is perturbed, establishing
/// that the fid serves normally first.
const PREFIX_READS: usize = 3;

/// The fid numbers the first session binds, and which the replacement session
/// then probes.
///
/// The replacement session deliberately reuses these exact numbers: the
/// contract clause is that no fid is restored across a control-session
/// reconnect, and reusing the numbers is what makes a leak observable instead
/// of merely unlikely.
const ATTACH_FID: u32 = 0;
const FILE_FID: u32 = 1;

/// The root fid the replacement session attaches on.
///
/// Deliberately **not** [`ATTACH_FID`]: the replacement session has to hold a
/// working root while it probes the earlier session's fid numbers, and if it
/// attached on [`ATTACH_FID`] then a probe of that number would be answering
/// from this session's own binding rather than showing the absence of the
/// earlier one.
const SECOND_ROOT_FID: u32 = 5;

/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for a cluster state change.
const WAIT: Duration = Duration::from_secs(30);
/// How long the held consumer socket is given to be failed explicitly.
///
/// Bounded: the point of the rule is that the profile does *not* leave a
/// pending call hanging, so a run that reaches this deadline has found the
/// defect rather than a slow cluster.
const PENDING_CALL_WAIT: Duration = Duration::from_secs(30);
/// The poll interval for every bounded wait here.
const POLL: Duration = Duration::from_millis(20);
/// The whole scenario's bound.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(300);

/// What the owner recorded about the stream the session was held on.
///
/// Payload-free: sequences, identifiers and lifecycle bits only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EpochChangeObservation {
    /// The consumer stream the filesystem session ran on.
    pub stream_id: u64,
    /// The owner's relay→connector emit cursor for this stream, sampled while
    /// the reverse direction was already paused and before the held `Tread`.
    pub emitted_before: u64,
    /// The same cursor at the instant the control session was replaced.  It
    /// must have advanced: the relay dispatched the request toward the device.
    pub emitted_at_change: u64,
    /// The owner's contiguous connector→relay receive cursor for this stream,
    /// sampled at the same instant as [`Self::emitted_before`].
    pub recv_contiguous_before: u64,
    /// The same cursor at the instant of the change.  It must **not** have
    /// advanced: no answer to that request had reached the owner.
    pub recv_contiguous_at_change: u64,
}

impl EpochChangeObservation {
    /// Whether this sample shows a 9P request the relay had dispatched and
    /// had received no answer to, at the instant the control session was
    /// replaced.  This is the gate's concurrency proof, and it is the owner's
    /// own record rather than a timestamp comparison.
    #[must_use]
    pub fn request_outstanding_at_change(&self) -> bool {
        self.emitted_at_change > self.emitted_before
            && self.recv_contiguous_at_change == self.recv_contiguous_before
    }
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsEpochChangeEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    /// The negotiated session parameters, so a run cannot pass on a session
    /// that never reached 9P.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub negotiated_dialect: String,

    /// Bytes read on the fid **before** anything was perturbed.
    pub prefix_bytes: usize,
    /// The owner's sample either side of the change.
    pub change: EpochChangeObservation,
    /// Whether that sample proves the request was outstanding at the change.
    pub request_outstanding_at_change: bool,
    /// How many polls the outstanding state took to observe, for diagnosis.
    pub change_polls: usize,
    /// The tag that was outstanding when the control session was replaced.
    pub held_tag: u16,

    // The event itself, read back out of the authoritative catalog.
    /// The owner epoch before the control session was replaced.
    pub epoch_before: u64,
    /// The owner epoch after.  It must be **strictly greater**: a control
    /// session that re-claimed the device without advancing the epoch would
    /// not be the event this gate exists to drive.
    pub epoch_after: u64,
    /// The device session identity either side.  A control-session reconnect
    /// that kept its session would not be one, so these must differ.
    pub session_id_before: String,
    pub session_id_after: String,
    /// The epoch the **device itself** was told, from each connector's own
    /// `WELCOME`.
    ///
    /// This is the half of the event the device *sees*, and asserting it
    /// alongside the catalog's view is what separates this gate's event from
    /// the epoch changes a device never learns about — a revocation or an
    /// owner-lease loss advances the durable epoch while the device's live
    /// session keeps its stale one and is closed with a reason rather than a
    /// new epoch.  Here both views must advance, and must agree.
    pub device_epoch_before: u64,
    pub device_epoch_after: u64,
    /// Whether the catalog reported the owner genuinely released between the
    /// two connectors, so the second claim is a fresh admission rather than an
    /// overlapping one.
    pub owner_released_between: bool,
    /// The second connector reached `active` on the same device identity.
    pub second_connector_active: bool,

    // The clause's own obligation, which gate 8 could not observe.
    /// Whether the held exchange's session was **closed** rather than left
    /// hanging: "fail pending calls explicitly".
    pub pending_call_closed: bool,
    /// The close code that failure carried.
    pub pending_call_close_code: Option<u16>,
    /// Whether the held `Tread` was instead **answered** across the epoch
    /// change.  It must not be: a reply served from a session the contract
    /// says is invalidated would be the violation.
    pub pending_call_answered: bool,

    /// The first session's stream is deregistered at the owner.
    pub held_stream_deregistered: bool,

    // The contract clause proper, driven on a session opened under the **new**
    // epoch that reuses the same fid numbers.
    /// A replacement session that speaks **before** its own `Tattach` is
    /// closed rather than served.  The close code observed.
    pub pre_attach_probe_close_code: Option<u16>,
    /// And it was closed rather than answered: no `Rgetattr`, no `Rlerror`.
    pub pre_attach_probe_answered: bool,

    /// The replacement session reached 9P on its own terms.
    pub second_session_msize: u32,
    /// Whether probing the earlier session's file fid, on an **attached**
    /// replacement session, was refused rather than answered.
    pub stale_file_fid_refused: bool,
    /// The errno that refusal carried.
    pub stale_file_fid_errno: Option<u32>,
    /// Whether the earlier session's attach fid was likewise unbound.
    pub stale_attach_fid_refused: bool,
    pub stale_attach_fid_errno: Option<u32>,
    /// The replacement session had to establish its own root.
    pub second_session_attached: bool,
    /// The whole file read back on the replacement session's own fid, proving
    /// the refusals above were fid scoping and neither a broken export nor a
    /// second connector that never served this root.
    pub second_session_bytes: usize,
    pub second_session_expected_bytes: usize,
    pub second_session_checksum_matches: bool,
    pub second_session_messages: usize,
    /// The file the replacement session sees is the same size as before, so
    /// nothing the held session was doing damaged it.
    pub second_session_getattr_size: u64,
    /// `Tattach` count across the whole run: one per attached session, two in
    /// total, and never a third that would mean a session was reconstructed.
    pub attach_count: usize,
}

/// Validate every rule; the first violated rule is named.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_fs_epoch_change_evidence(evidence: &FsEpochChangeEvidence) -> Result<()> {
    let checks: Vec<(String, bool)> = vec![
        (
            "the production cluster ran three relays".into(),
            evidence.relay_count == 3,
        ),
        (
            "the owning relay was identified".into(),
            !evidence.owner_node.is_empty(),
        ),
        (
            "the server selected the filesystem subprotocol".into(),
            evidence.selected_subprotocol == SUBPROTOCOL,
        ),
        (
            "Tversion negotiated the 9P2000.L dialect".into(),
            evidence.negotiated_dialect == DIALECT,
        ),
        (
            "Tversion negotiated a bounded msize".into(),
            evidence.negotiated_msize > 0 && evidence.negotiated_msize <= OFFERED_MSIZE,
        ),
        (
            "the fid served a real read before anything was perturbed".into(),
            evidence.prefix_bytes > 0,
        ),
        // The concurrency rules.  Without these the gate would prove only that
        // an epoch changed somewhere near a filesystem session.
        (
            "the relay had dispatched a 9P record toward the device when the control \
             session was replaced"
                .into(),
            evidence.change.emitted_at_change > evidence.change.emitted_before,
        ),
        (
            "the relay had received no answer to that record when the control session was \
             replaced: the 9P exchange was outstanding across the epoch change"
                .into(),
            evidence.request_outstanding_at_change && evidence.change.request_outstanding_at_change(),
        ),
        (
            "a stream was identified for the held exchange".into(),
            evidence.change.stream_id > 0,
        ),
        // The event itself, genuinely acquired rather than written.
        (
            "the owner claim took a strictly greater epoch".into(),
            evidence.epoch_after > evidence.epoch_before,
        ),
        (
            "an epoch was actually observed before the change".into(),
            evidence.epoch_before > 0,
        ),
        (
            "the control session was genuinely replaced: the device session identity changed"
                .into(),
            !evidence.session_id_before.is_empty()
                && !evidence.session_id_after.is_empty()
                && evidence.session_id_before != evidence.session_id_after,
        ),
        (
            "the device itself was told a strictly greater epoch in its own WELCOME: this is \
             an epoch change the device sees, not one it is merely fenced by"
                .into(),
            evidence.device_epoch_after > evidence.device_epoch_before
                && evidence.device_epoch_before > 0,
        ),
        (
            "the device's own view of the new epoch agrees with the catalog's".into(),
            evidence.device_epoch_after == evidence.epoch_after,
        ),
        (
            "the owner was released between the two connectors, so the second claim is a \
             fresh admission rather than an overlapping one"
                .into(),
            evidence.owner_released_between,
        ),
        (
            "the replacement connector reached active on the same device".into(),
            evidence.second_connector_active,
        ),
        // The clause's own obligation: fail pending calls explicitly.
        (
            "the pending call was failed explicitly rather than left hanging".into(),
            evidence.pending_call_closed,
        ),
        (
            // The observed code is named in the rule so a failing run says
            // which code it saw rather than only that it was wrong.
            format!(
                "that failure carried the profile's close code for a backend that went away \
                 (expected {DEVICE_GONE_CLOSE}, observed {:?})",
                evidence.pending_call_close_code
            ),
            evidence.pending_call_close_code == Some(DEVICE_GONE_CLOSE),
        ),
        (
            "the held Tread was not answered across the epoch change: a session the contract \
             invalidates must not serve a reply"
                .into(),
            !evidence.pending_call_answered,
        ),
        (
            "the held exchange's stream was deregistered at the owner".into(),
            evidence.held_stream_deregistered,
        ),
        // The contract clause: no fid is restored across a control-session
        // reconnect.  First its "require fresh version/attach" half.
        (
            "a replacement session that spoke before its own Tattach was closed, not served"
                .into(),
            !evidence.pre_attach_probe_answered,
        ),
        (
            "that close was the profile's protocol violation".into(),
            evidence.pre_attach_probe_close_code == Some(PROTOCOL_VIOLATION_CLOSE),
        ),
        (
            "the replacement session reached 9P on its own terms".into(),
            evidence.second_session_msize > 0 && evidence.second_session_msize <= OFFERED_MSIZE,
        ),
        (
            "the earlier session's file fid was not restored across the epoch change".into(),
            evidence.stale_file_fid_refused,
        ),
        (
            "that refusal was because the fid is not allocated in this session".into(),
            evidence.stale_file_fid_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "the earlier session's attach fid was not restored across the epoch change".into(),
            evidence.stale_attach_fid_refused,
        ),
        (
            "that refusal too was because the fid is not allocated in this session".into(),
            evidence.stale_attach_fid_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "the replacement session established its own root with its own Tattach".into(),
            evidence.second_session_attached,
        ),
        // The export is undamaged, so the refusals above are fid scoping.
        (
            "the replacement session read the whole file back on its own fid".into(),
            evidence.second_session_bytes == evidence.second_session_expected_bytes
                && evidence.second_session_expected_bytes == EPOCH_FILE_BYTES,
        ),
        (
            "that transfer's checksum matched the synthetic content".into(),
            evidence.second_session_checksum_matches,
        ),
        (
            "that transfer spanned many Rread messages rather than one".into(),
            evidence.second_session_messages >= MIN_READ_MESSAGES,
        ),
        (
            "the file was undamaged by the held session".into(),
            evidence.second_session_getattr_size == EPOCH_FILE_BYTES as u64,
        ),
        (
            "each attached session attached exactly once: two Tattach across the run".into(),
            evidence.attach_count == 2,
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "fs epoch change gate failed: {rule}"
            )));
        }
    }
    Ok(())
}

/// Deterministic synthetic content: byte `i` is `(i % 251)`.
///
/// 251 is prime and below 256, so the pattern does not align with any power of
/// two the transport uses and a dropped or duplicated block changes the
/// checksum.
fn synthetic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// FNV-1a over 64 bits.  A checksum, not a digest: it only has to detect a
/// byte that moved.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Run the gate: start the cluster, replace the control session under a live
/// 9P exchange, and validate the evidence.
///
/// # Errors
/// Any harness, cluster or validation failure.
pub async fn verify() -> Result<FsEpochChangeEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("fs epoch change harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result.and_then(|evidence| {
            validate_fs_epoch_change_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs epoch change scenario exceeded its bounded deadline".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

/// The owner's snapshot of this device session.
fn session_of<'s>(
    snapshot: &'s RelaySnapshot,
    session_id: &str,
) -> Result<&'s RelaySessionSnapshot> {
    snapshot
        .sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .ok_or_else(|| HarnessError::Process("the owner has no session for this device".into()))
}

async fn owner_snapshot(cluster: &ProductionCluster) -> Result<RelaySnapshot> {
    cluster.relay("relay-a")?.snapshot().await
}

/// Wait until the owner reports exactly one consumer stream and return its id.
async fn wait_fs_stream(cluster: &ProductionCluster, session_id: &str) -> Result<u64> {
    let deadline = Instant::now() + WAIT;
    loop {
        let snapshot = owner_snapshot(cluster).await?;
        if let Ok(session) = session_of(&snapshot, session_id)
            && let [stream] = session.streams.as_slice()
        {
            return Ok(stream.stream_id);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "the filesystem consumer stream was not registered".into(),
            ));
        }
        sleep(POLL).await;
    }
}

/// Open one consumer 9P session on this export and negotiate `Tversion`.
async fn open_session(
    target: &Target,
    ca: &[u8],
    token: &str,
) -> Result<(NinepClient, u32, String)> {
    let mut session = match NinepClient::connect(target, ca, token, Some(SUBPROTOCOL)).await {
        Ok(session) => session,
        Err(UpgradeFailure::Status { status, .. }) => {
            return Err(HarnessError::Http(format!(
                "the filesystem upgrade was refused with HTTP status {status}"
            )));
        }
        Err(UpgradeFailure::Harness(error)) => return Err(error),
    };
    let selected = session.selected_subprotocol().to_owned();
    let (msize, dialect) = session.version(OFFERED_MSIZE).await?;
    let _ = dialect;
    Ok((session, msize, selected))
}

/// Wait for the catalog to report an owner claim for this device whose epoch
/// is strictly greater than `floor`, and return its epoch and session id.
///
/// The epoch is read from the authoritative Redis catalog's owner token
/// rather than from a relay snapshot, so the inequality this gate turns on is
/// the claim the cluster actually agreed on.
async fn wait_owner_epoch_above(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    floor: u64,
) -> Result<(u64, String, String)> {
    let deadline = Instant::now() + OWNER_WAIT;
    loop {
        let owner = cluster
            .catalog
            .current_owner(tenant_id, device_id, chrono::Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?;
        if let Some(owner) = owner
            && owner.token.epoch > floor
        {
            return Ok((
                owner.token.epoch,
                owner.token.session_id.clone(),
                owner.token.node_id.clone(),
            ));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "no owner claim took an epoch above the one held before the change".into(),
            ));
        }
        sleep(POLL).await;
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<FsEpochChangeEvidence> {
    let mut evidence = FsEpochChangeEvidence {
        relay_count: cluster.relays.len(),
        second_session_expected_bytes: EPOCH_FILE_BYTES,
        ..FsEpochChangeEvidence::default()
    };
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("the filesystem device is missing".into()))?;
    let echo_service = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("the device has no primary service".into()))?;
    let service = harness
        .fs_service("epoch-change")
        .ok_or_else(|| {
            HarnessError::InvalidInput("the epoch-change filesystem export was not seeded".into())
        })?
        .service_id;

    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    std::fs::write(
        directory.path().join("big.bin"),
        synthetic_bytes(EPOCH_FILE_BYTES),
    )
    .map_err(HarnessError::Io)?;

    // The device attaches directly to relay-a, which becomes the owner, and
    // every device socket passes this proxy so one direction of the settled
    // data socket can be held.
    let owner_device_addr = cluster
        .relay("relay-a")?
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| HarnessError::Process("relay-a is not running".into()))?;
    let proxy = TcpProxy::bind(owner_device_addr, ProxyConfig::default()).await?;

    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut device_profile = write_device_profile(
        profile_directory.path(),
        device.id,
        echo_service,
        "m4-fs-epoch-change-canary",
        proxy.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    device_profile.config.exports.insert(
        service.to_string(),
        LocalExport {
            kind: LocalExportKind::Fs,
            device_canary: None,
            mcp: None,
            acp: None,
            fs: Some(FsExportSettings {
                root: directory.path().to_path_buf(),
                capabilities: vec!["read".to_owned(), "list".to_owned()],
                features: Vec::new(),
            }),
        },
    );
    device_profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;

    // The filesystem export is served by the connector itself, so the handler
    // registry is empty.  The **same** configuration starts both connectors:
    // the replacement is the same device identity serving the same export, so
    // the only thing that changes across the event is the control session and
    // the epoch it claims.
    let mut first = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect_with_http_handlers(
            ConnectOptions::new(device_profile.config.clone()),
            HttpHandlers::new(),
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("fs epoch change device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("fs epoch change device: {error}")))?;

    let mut second_client: Option<tunnel_client::ConnectionHandle> = None;
    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, first.wait_ready())
            .await
            .map_err(|_| {
                HarnessError::Timeout("fs epoch change device readiness timed out".into())
            })?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        evidence.device_epoch_before = session.epoch;
        exercise(
            cluster,
            harness,
            &proxy,
            &first,
            &mut second_client,
            &device_profile.config,
            device.tenant_id,
            device.id,
            service,
            &session.session_id,
            &mut evidence,
        )
        .await
    }
    .await;
    if scenario.is_err() {
        // Payload-free: identifiers, labels and counters only.
        eprintln!(
            "fs epoch change device phase: {:?}",
            first.status_snapshot().phase
        );
        eprintln!("fs epoch change partial evidence: {evidence:?}");
    }
    // The first connector is stopped inside `exercise`; stopping it again is
    // harmless and covers the paths that failed before reaching that point.
    let stop_first = timeout(CLEANUP_TIMEOUT, first.stop()).await;
    let stop_second = match second_client {
        Some(client) => Some(timeout(CLEANUP_TIMEOUT, client.stop()).await),
        None => None,
    };
    scenario?;
    match (stop_first, stop_second) {
        (Ok(Ok(())) | Ok(Err(_)), Some(Ok(Ok(())))) | (Ok(Ok(())), None) => Ok(evidence),
        (_, Some(Ok(Err(error)))) => Err(HarnessError::Process(format!(
            "replacement device stop: {error}"
        ))),
        (_, Some(Err(_))) => Err(HarnessError::Timeout(
            "replacement device stop timed out".into(),
        )),
        (Ok(Err(error)), None) => Err(HarnessError::Process(format!("device stop: {error}"))),
        (Err(_), _) => Err(HarnessError::Timeout("device stop timed out".into())),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn exercise(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    proxy: &ProxyHandle,
    first: &tunnel_client::ConnectionHandle,
    second_client: &mut Option<tunnel_client::ConnectionHandle>,
    config: &tunnel_client::ConnectConfig,
    tenant_id: Uuid,
    device_id: Uuid,
    service: Uuid,
    session_id: &str,
    evidence: &mut FsEpochChangeEvidence,
) -> Result<()> {
    // The owner claim, so the gate is speaking to the relay that owns the
    // device rather than to whichever relay answered first, and so the epoch
    // this gate compares against is the one the cluster agreed on.
    {
        let deadline = Instant::now() + OWNER_WAIT;
        loop {
            let owner = cluster
                .catalog
                .current_owner(tenant_id, device_id, chrono::Utc::now())
                .await
                .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?;
            if let Some(owner) = owner
                && owner.token.session_id == session_id
            {
                evidence.owner_node = owner.token.node_id.clone();
                evidence.epoch_before = owner.token.epoch;
                evidence.session_id_before = owner.token.session_id.clone();
                break;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the device owner claim was not observed".into(),
                ));
            }
            sleep(POLL).await;
        }
    }
    let owner_addr = cluster.relay("relay-a")?.consumer_addr()?;
    let ca = harness.pki.server_ca.certificate_der.clone();
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            scope: Some("echo:invoke fs:connect".to_owned()),
            ..OidcTokenOptions::default()
        },
    )?;
    let target = Target {
        consumer_addr: owner_addr,
        device_id,
        service: service.to_string(),
    };

    // ---------------------------------------------------------------------
    // Session one: established, serving, then held across the epoch change.
    // ---------------------------------------------------------------------
    let (mut session, msize, selected) = open_session(&target, &ca, &token).await?;
    evidence.selected_subprotocol = selected;
    evidence.negotiated_msize = msize;
    evidence.negotiated_dialect = DIALECT.to_owned();

    session.attach(ATTACH_FID).await?;
    evidence.attach_count = 1;

    match session.walk(ATTACH_FID, FILE_FID, &["big.bin"]).await? {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match session.lopen(FILE_FID, O_RDONLY).await? {
        Message::Rlopen { .. } => {}
        other => return Err(unexpected("Rlopen", &other)),
    }

    let stream_id = wait_fs_stream(cluster, session_id).await?;

    // 1. Serve the fid normally first, so a later failure cannot be blamed on
    //    a session that never worked.
    let mut prefix = 0_usize;
    for _ in 0..PREFIX_READS {
        match session.read(FILE_FID, prefix as u64, READ_COUNT).await? {
            Message::Rread { data } if !data.is_empty() => prefix += data.len(),
            other => return Err(unexpected("a non-empty Rread", &other)),
        }
    }
    evidence.prefix_bytes = prefix;

    // 2. Settle the carrier and pause the data socket's connector→relay bytes,
    //    so a reply cannot settle the exchange before the epoch change.
    let connection = {
        let deadline = Instant::now() + WAIT;
        loop {
            let device = first.status_snapshot();
            let open = proxy.connections();
            if device.phase == "active"
                && device.candidate_generation.is_none()
                && let Some(control) = device.control_local_addr
                && let Some(data) = open
                    .iter()
                    .find(|connection| connection.source_addr != control)
                && open.len() == 2
                && device.active_local_addr == Some(data.source_addr)
            {
                break data.id;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the device carrier never settled before the held read".into(),
                ));
            }
            sleep(POLL).await;
        }
    };
    proxy
        .pause(ProxyDirection::ClientToTarget, connection)
        .await?;

    // 3. Fix the owner's cursors for this stream **while paused**, so the
    //    comparison below is against a baseline nothing can move.
    let mut observation = EpochChangeObservation {
        stream_id,
        ..EpochChangeObservation::default()
    };
    {
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
        let stream = owner
            .streams
            .iter()
            .find(|stream| stream.stream_id == stream_id)
            .ok_or_else(|| {
                HarnessError::Process("the filesystem stream vanished before the held read".into())
            })?;
        observation.emitted_before = stream.last_emitted_relay_to_connector;
        observation.recv_contiguous_before = stream.recv_contiguous_connector_to_relay;
    }

    // 4. Send one Tread and deliberately do not read its reply.  The request
    //    crosses on the still-flowing relay→connector direction, the device
    //    performs it, and the connector sequences the Rread into the paused
    //    socket.
    let held_tag = session
        .send(Message::Tread {
            fid: FILE_FID,
            offset: prefix as u64,
            count: READ_COUNT,
        })
        .await?;
    evidence.held_tag = held_tag;

    // 5. Wait for the owner to show the request dispatched and unanswered, and
    //    replace the control session at that instant.
    {
        let deadline = Instant::now() + WAIT;
        let mut polls = 0_usize;
        loop {
            polls += 1;
            let snapshot = owner_snapshot(cluster).await?;
            let owner = session_of(&snapshot, session_id)?;
            if let Some(stream) = owner
                .streams
                .iter()
                .find(|stream| stream.stream_id == stream_id)
            {
                let sample = EpochChangeObservation {
                    emitted_at_change: stream.last_emitted_relay_to_connector,
                    recv_contiguous_at_change: stream.recv_contiguous_connector_to_relay,
                    ..observation.clone()
                };
                // Only a sample that actually shows the record dispatched and
                // unanswered ends the wait.
                if sample.request_outstanding_at_change() {
                    evidence.change_polls = polls;
                    observation = sample;
                    break;
                }
            }
            if Instant::now() >= deadline {
                // Release before failing so cleanup is not wedged.
                let _ = proxy
                    .resume(ProxyDirection::ClientToTarget, connection)
                    .await;
                return Err(HarnessError::Process(
                    "the held Tread was never observed dispatched and unanswered at the owner"
                        .into(),
                ));
            }
            sleep(POLL).await;
        }
    }
    evidence.request_outstanding_at_change = observation.request_outstanding_at_change();
    evidence.change = observation;

    // ---------------------------------------------------------------------
    // The event: the control session is replaced and the claim takes a
    // strictly greater epoch.  Nothing here writes an epoch number.
    // ---------------------------------------------------------------------
    // The connector has no automatic reconnect — its documented policy is to
    // "close control and data and require a fresh session" — so the control
    // session is replaced by stopping this connector and starting another on
    // the same identity and the same export.  The paused direction is released
    // first so the stop is not wedged behind it; the exchange stays
    // outstanding regardless, because the consumer never reads its reply and
    // the sample that proves it was outstanding is already fixed.
    proxy
        .resume(ProxyDirection::ClientToTarget, connection)
        .await?;
    timeout(CLEANUP_TIMEOUT, first.stop())
        .await
        .map_err(|_| HarnessError::Timeout("the first connector did not stop".into()))?
        .map_err(|error| HarnessError::Process(format!("first connector stop: {error}")))?;

    // The authoritative catalog must report the owner released, so the second
    // claim is a fresh admission rather than an overlapping one.
    cluster.wait_for_no_owner(tenant_id, device_id).await?;
    evidence.owner_released_between = true;

    let mut replacement = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect_with_http_handlers(
            ConnectOptions::new(config.clone()),
            HttpHandlers::new(),
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("the replacement connector did not start".into()))?
    .map_err(|error| HarnessError::Process(format!("replacement connector: {error}")))?;
    let replacement_session = timeout(STARTUP_TIMEOUT, replacement.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout("replacement connector readiness timed out".into()))?
        .map_err(|error| HarnessError::Process(format!("replacement not ready: {error}")))?;
    let replacement_session_id = replacement_session.session_id.clone();
    // The epoch the device itself was told, from its own `WELCOME`.
    evidence.device_epoch_after = replacement_session.epoch;
    evidence.second_connector_active = replacement.status_snapshot().phase == "active";
    *second_client = Some(replacement);

    // The epoch is read back out of the authoritative catalog, and the strict
    // inequality against the epoch held before is what this gate turns on.
    let (epoch_after, owner_session_id, _node) =
        wait_owner_epoch_above(cluster, tenant_id, device_id, evidence.epoch_before).await?;
    evidence.epoch_after = epoch_after;
    evidence.session_id_after = owner_session_id;

    // ---------------------------------------------------------------------
    // The clause's own obligation: fail pending calls explicitly.  Gate 8's
    // consumer was gone and had nobody to be failed to; this one is still
    // connected and still holding an unanswered tag, so the obligation is
    // observable here for the first time.
    // ---------------------------------------------------------------------
    match timeout(PENDING_CALL_WAIT, session.recv_event()).await {
        Ok(Ok(wire::Event::Close(code))) => {
            evidence.pending_call_closed = true;
            evidence.pending_call_close_code = code;
        }
        Ok(Ok(wire::Event::Frame(_))) => {
            // A reply served from a session the contract invalidates.  Recorded
            // rather than thrown, so the validator names the violated rule.
            evidence.pending_call_answered = true;
        }
        Ok(Ok(wire::Event::Ended)) => {
            // The socket ended without a code: that is not "explicitly".
            evidence.pending_call_closed = true;
            evidence.pending_call_close_code = None;
        }
        Ok(Err(error)) => {
            return Err(HarnessError::Process(format!(
                "reading the held session after the epoch change: {error}"
            )));
        }
        Err(_) => {
            // Left hanging.  The validator names this; it is not a harness
            // timeout, it is the finding.
            evidence.pending_call_closed = false;
        }
    }
    session.abandon();

    // The held exchange's stream is deregistered at the owner.  The first
    // device session is gone, so its absence is what is waited on.
    {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = owner_snapshot(cluster).await?;
            let gone = match session_of(&snapshot, session_id) {
                Ok(owner) => !owner
                    .streams
                    .iter()
                    .any(|stream| stream.stream_id == stream_id),
                // The whole session is gone, which subsumes its streams.
                Err(_) => true,
            };
            if gone {
                evidence.held_stream_deregistered = true;
                break;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the held exchange's stream was never deregistered at the owner".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    // ---------------------------------------------------------------------
    // Session two: the contract clause, under the **new** epoch.  No fid is
    // restored across a control-session reconnect, and the same fid numbers
    // are reused so a leak would show.
    // ---------------------------------------------------------------------
    // Wait until the replacement session is serving consumers before probing,
    // so a refusal cannot be a device that has not finished attaching.
    {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = owner_snapshot(cluster).await?;
            if session_of(&snapshot, &replacement_session_id).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the replacement device session never registered at the owner".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    // First the "require fresh version/attach" half of the clause, on its own
    // throwaway session: a replacement session that names the earlier
    // session's file fid *before* attaching is closed rather than served.
    // `BeforeAttach` is checked before the fid table, which is why this probe
    // needs its own session and why the fid probes below run on an attached
    // one.
    {
        let (mut probe, _, _) = open_session(&target, &ca, &token).await?;
        probe
            .send(Message::Tgetattr {
                fid: FILE_FID,
                request_mask: GETATTR_BASIC,
            })
            .await?;
        match probe.recv_event().await? {
            wire::Event::Close(code) => evidence.pre_attach_probe_close_code = code,
            wire::Event::Frame(_) => evidence.pre_attach_probe_answered = true,
            wire::Event::Ended => evidence.pre_attach_probe_close_code = None,
        }
    }

    let (mut second, second_msize, _) = open_session(&target, &ca, &token).await?;
    evidence.second_session_msize = second_msize;

    // This session attaches on its **own** root fid, so it holds a working
    // root while it probes the earlier session's fid numbers.
    second.attach(SECOND_ROOT_FID).await?;
    evidence.attach_count += 1;
    evidence.second_session_attached = true;

    // The earlier session's file fid must not be bound here.
    match second.getattr(FILE_FID, GETATTR_BASIC).await? {
        Message::Rgetattr(_) => {
            return Err(HarnessError::Process(
                "the earlier session's file fid answered under a new control epoch: the profile \
                 restored a fid across a control-session reconnect"
                    .into(),
            ));
        }
        other => {
            evidence.stale_file_fid_refused = matches!(other, Message::Rlerror { .. });
            evidence.stale_file_fid_errno = errno_of(&other);
        }
    }
    // And neither must its attach fid: a walk from it is refused rather than
    // rooted at the export.
    match second.walk(ATTACH_FID, 9, &["big.bin"]).await? {
        Message::Rwalk { .. } => {
            return Err(HarnessError::Process(
                "the earlier session's attach fid walked under a new control epoch: the profile \
                 restored a fid across a control-session reconnect"
                    .into(),
            ));
        }
        other => {
            evidence.stale_attach_fid_refused = matches!(other, Message::Rlerror { .. });
            evidence.stale_attach_fid_errno = errno_of(&other);
        }
    }

    // The export answers normally on this session's own root, so the refusals
    // above are fid scoping — and not a replacement connector that never
    // served this export at all.  Binding FILE_FID here, fresh, is also the
    // other half of the contract: the *number* is reusable once the session
    // that held it is gone.
    match second.walk(SECOND_ROOT_FID, FILE_FID, &["big.bin"]).await? {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match second.lopen(FILE_FID, O_RDONLY).await? {
        Message::Rlopen { .. } => {}
        other => return Err(unexpected("Rlopen", &other)),
    }
    match second.getattr(FILE_FID, GETATTR_BASIC).await? {
        Message::Rgetattr(attributes) => evidence.second_session_getattr_size = attributes.size,
        other => return Err(unexpected("Rgetattr", &other)),
    }

    let mut transferred: Vec<u8> = Vec::with_capacity(EPOCH_FILE_BYTES);
    let mut messages = 0_usize;
    loop {
        match second
            .read(FILE_FID, transferred.len() as u64, READ_COUNT)
            .await?
        {
            Message::Rread { data } => {
                if data.is_empty() {
                    break;
                }
                messages += 1;
                transferred.extend_from_slice(&data);
            }
            other => return Err(unexpected("Rread", &other)),
        }
    }
    evidence.second_session_bytes = transferred.len();
    evidence.second_session_messages = messages;
    evidence.second_session_checksum_matches =
        fnv1a(&transferred) == fnv1a(&synthetic_bytes(EPOCH_FILE_BYTES));

    second.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> FsEpochChangeEvidence {
        FsEpochChangeEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: 65_536,
            negotiated_dialect: DIALECT.into(),
            prefix_bytes: 196_575,
            change: EpochChangeObservation {
                stream_id: 1,
                emitted_before: 4,
                emitted_at_change: 5,
                recv_contiguous_before: 4,
                recv_contiguous_at_change: 4,
            },
            request_outstanding_at_change: true,
            change_polls: 3,
            held_tag: 7,
            epoch_before: 1,
            epoch_after: 2,
            session_id_before: "session-one".into(),
            session_id_after: "session-two".into(),
            device_epoch_before: 1,
            device_epoch_after: 2,
            owner_released_between: true,
            second_connector_active: true,
            pending_call_closed: true,
            pending_call_close_code: Some(DEVICE_GONE_CLOSE),
            pending_call_answered: false,
            held_stream_deregistered: true,
            pre_attach_probe_close_code: Some(PROTOCOL_VIOLATION_CLOSE),
            pre_attach_probe_answered: false,
            second_session_msize: 65_536,
            stale_file_fid_refused: true,
            stale_file_fid_errno: Some(UNKNOWN_FID_ERRNO),
            stale_attach_fid_refused: true,
            stale_attach_fid_errno: Some(UNKNOWN_FID_ERRNO),
            second_session_attached: true,
            second_session_bytes: EPOCH_FILE_BYTES,
            second_session_expected_bytes: EPOCH_FILE_BYTES,
            second_session_checksum_matches: true,
            second_session_messages: 12,
            second_session_getattr_size: EPOCH_FILE_BYTES as u64,
            attach_count: 2,
        }
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_fs_epoch_change_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsEpochChangeEvidence));
        let mutations: Vec<Mutation> = vec![
            ("relays", |e| e.relay_count = 2),
            ("owner not identified", |e| e.owner_node.clear()),
            ("subprotocol", |e| {
                e.selected_subprotocol = "agent-tunnel.echo.v1".into();
            }),
            ("dialect", |e| e.negotiated_dialect = "9P2000.u".into()),
            ("msize", |e| e.negotiated_msize = 0),
            ("msize above the ceiling", |e| {
                e.negotiated_msize = OFFERED_MSIZE + 1;
            }),
            ("the fid never served before the change", |e| {
                e.prefix_bytes = 0;
            }),
            // The concurrency rules.
            ("the request was never dispatched", |e| {
                e.change.emitted_at_change = e.change.emitted_before;
            }),
            ("the reply had already been received", |e| {
                e.change.recv_contiguous_at_change = e.change.recv_contiguous_before + 1;
            }),
            ("the in-flight summary contradicts its sample", |e| {
                e.request_outstanding_at_change = false;
            }),
            ("no stream was identified", |e| e.change.stream_id = 0),
            // The event itself.
            ("the epoch did not advance", |e| e.epoch_after = e.epoch_before),
            ("the epoch went backwards", |e| e.epoch_after = 0),
            ("no epoch was observed before the change", |e| {
                e.epoch_before = 0;
                e.epoch_after = 1;
            }),
            ("the session identity did not change", |e| {
                e.session_id_after = e.session_id_before.clone();
            }),
            ("no session was identified before the change", |e| {
                e.session_id_before.clear();
            }),
            ("no session was identified after the change", |e| {
                e.session_id_after.clear();
            }),
            // The device's own view of the event.
            ("the device was never told a greater epoch", |e| {
                e.device_epoch_after = e.device_epoch_before;
            }),
            ("the device's WELCOME epoch went backwards", |e| {
                e.device_epoch_before = 7;
                e.device_epoch_after = 6;
            }),
            ("no device epoch was observed before the change", |e| {
                e.device_epoch_before = 0;
            }),
            (
                "the device's view disagreed with the catalog's",
                |e| {
                    e.device_epoch_after = e.epoch_after + 1;
                },
            ),
            ("the owner was never released between connectors", |e| {
                e.owner_released_between = false;
            }),
            ("the replacement connector never became active", |e| {
                e.second_connector_active = false;
            }),
            // The clause's own obligation.
            ("the pending call was left hanging", |e| {
                e.pending_call_closed = false;
            }),
            ("the pending call closed for the wrong reason", |e| {
                e.pending_call_close_code = Some(1011);
            }),
            ("the pending call closed with no code at all", |e| {
                e.pending_call_close_code = None;
            }),
            ("the held Tread was answered across the epoch change", |e| {
                e.pending_call_answered = true;
            }),
            ("the held stream was never deregistered", |e| {
                e.held_stream_deregistered = false;
            }),
            // The contract clause.
            ("a pre-attach probe was served rather than closed", |e| {
                e.pre_attach_probe_answered = true;
            }),
            ("a pre-attach probe closed for the wrong reason", |e| {
                e.pre_attach_probe_close_code = Some(1011);
            }),
            ("a pre-attach probe closed with no code", |e| {
                e.pre_attach_probe_close_code = None;
            }),
            ("the replacement session never reached 9P", |e| {
                e.second_session_msize = 0;
            }),
            ("the earlier file fid was restored", |e| {
                e.stale_file_fid_refused = false;
            }),
            ("the file fid was refused for the wrong reason", |e| {
                e.stale_file_fid_errno = Some(UNKNOWN_FID_ERRNO + 1);
            }),
            ("the file fid refusal carried no errno", |e| {
                e.stale_file_fid_errno = None;
            }),
            ("the earlier attach fid was restored", |e| {
                e.stale_attach_fid_refused = false;
            }),
            ("the attach fid was refused for the wrong reason", |e| {
                e.stale_attach_fid_errno = Some(UNKNOWN_FID_ERRNO + 1);
            }),
            ("the replacement session never attached", |e| {
                e.second_session_attached = false;
            }),
            ("the replacement session read a short file", |e| {
                e.second_session_bytes = EPOCH_FILE_BYTES - 1;
            }),
            ("the checksum did not match", |e| {
                e.second_session_checksum_matches = false;
            }),
            ("the transfer was a single message", |e| {
                e.second_session_messages = 1;
            }),
            ("the file was damaged", |e| {
                e.second_session_getattr_size = 1;
            }),
            ("a session was reconstructed", |e| e.attach_count = 3),
            ("a session never attached", |e| e.attach_count = 1),
        ];
        for (name, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_fs_epoch_change_evidence(&evidence).is_err(),
                "mutation `{name}` must be rejected: no rule here is decorative"
            );
        }
    }

    /// The concurrency predicate itself, independent of the rule list: it must
    /// be false for a settled exchange and true only when the relay had
    /// dispatched a record it had received no answer to.
    #[test]
    fn outstanding_predicate_requires_a_dispatched_and_unanswered_record() {
        let outstanding = EpochChangeObservation {
            stream_id: 1,
            emitted_before: 4,
            emitted_at_change: 5,
            recv_contiguous_before: 4,
            recv_contiguous_at_change: 4,
        };
        assert!(outstanding.request_outstanding_at_change());

        let never_dispatched = EpochChangeObservation {
            emitted_at_change: 4,
            ..outstanding.clone()
        };
        assert!(
            !never_dispatched.request_outstanding_at_change(),
            "a request the relay never emitted was not outstanding across the epoch change"
        );

        let already_answered = EpochChangeObservation {
            recv_contiguous_at_change: 5,
            ..outstanding.clone()
        };
        assert!(
            !already_answered.request_outstanding_at_change(),
            "a record the owner had already received is a settled exchange"
        );

        // A reply that arrived for an *earlier* request still counts as the
        // exchange having been answered: the baseline is fixed while the
        // reverse direction is paused, so any advance at all is an answer.
        let partially_answered = EpochChangeObservation {
            emitted_at_change: 9,
            recv_contiguous_at_change: 5,
            ..outstanding
        };
        assert!(
            !partially_answered.request_outstanding_at_change(),
            "any advance of the receive cursor means an answer crossed the paused direction"
        );
    }

    /// The epoch rule is a **strict** inequality on a genuinely acquired
    /// claim, not a "changed" check: an epoch that went backwards is not an
    /// epoch change this contract recognises.
    #[test]
    fn epoch_rule_is_strictly_increasing() {
        // Both views move together: the point under test is the *direction*
        // of the inequality, not the agreement rule beside it.
        let mut backwards = passing();
        backwards.epoch_before = 7;
        backwards.epoch_after = 6;
        backwards.device_epoch_before = 7;
        backwards.device_epoch_after = 6;
        assert!(
            validate_fs_epoch_change_evidence(&backwards).is_err(),
            "an epoch that went backwards is not an epoch change this contract recognises"
        );

        // An epoch that merely *differs* is not enough either, and neither is
        // one that stood still.
        let mut unchanged = passing();
        unchanged.epoch_before = 7;
        unchanged.epoch_after = 7;
        unchanged.device_epoch_before = 7;
        unchanged.device_epoch_after = 7;
        assert!(
            validate_fs_epoch_change_evidence(&unchanged).is_err(),
            "a re-claim that did not advance the epoch is not the event"
        );

        let mut forwards = passing();
        forwards.epoch_before = 7;
        forwards.epoch_after = 8;
        forwards.device_epoch_before = 7;
        forwards.device_epoch_after = 8;
        validate_fs_epoch_change_evidence(&forwards).expect("a strictly greater epoch passes");
    }
}
