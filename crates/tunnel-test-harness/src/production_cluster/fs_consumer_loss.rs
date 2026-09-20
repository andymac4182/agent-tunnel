//! A live 9P2000.L filesystem session **lost with a request outstanding**,
//! over the real cluster: a consumer WSS session through the owning relay's
//! public route, the owner actor, the device data WebSocket and
//! `tunnel-client`'s filesystem export.
//!
//! This is M4-06's *consumer loss* clause, and its contract is the **opposite**
//! of the rotation clause's.  `docs/protocol.md` states both in one paragraph:
//!
//! > The first filesystem profile restores no fids across a consumer WebSocket
//! > reconnect, control-session reconnect or adapter/connector/relay process
//! > restart: terminate that filesystem session, fail pending calls explicitly
//! > and create a fresh 9P session.  Generic tunnel resume support must not
//! > silently opt the filesystem adapter into stronger recovery guarantees.
//! > Replacement of a failed data socket may preserve the filesystem session
//! > only while the same control owner and all ordered stream state are
//! > retained.
//!
//! The last sentence is the **same-owner contract** that M4-06's note points
//! at, and reading it settles what this gate must assert.  It licenses fid
//! retention for exactly one event — replacement of a *failed data socket*,
//! and then only while the same control owner and all ordered stream state are
//! retained.  A consumer WebSocket reconnect is named in the *first* sentence,
//! on the other side of the contract: across it no fid is restored at all.  So
//! where `verify-m4-fs-rotation` proves that a fid **survives**, this gate must
//! prove that a fid **does not** — and a gate that asserted survival here would
//! be asserting the violation.
//!
//! **What makes the loss concurrent rather than sequential.**  A consumer that
//! goes away between two settled 9P exchanges proves nothing: the interesting
//! case is loss *while an exchange is outstanding*, because that is when a tag
//! and a fid are in a state someone has to define.  The construction is the
//! filesystem-path analogue of the rotation gate's, and it is proven from the
//! owner's own per-stream sequence cursors rather than from timing:
//!
//! 1. The consumer opens a fid and reads the first part of a synthetic file,
//!    so the fid is established and serving before anything is perturbed.
//! 2. The device data socket's **connector→relay** bytes are paused at the
//!    harness TCP proxy once the carrier has settled.  The control socket is
//!    untouched, so this is a consumer-loss gate and not a carrier-fault one.
//! 3. The owner is sampled *while paused*, fixing this stream's
//!    `last_emitted_relay_to_connector` and
//!    `recv_contiguous_connector_to_relay`.
//! 4. The consumer sends one `Tread` and does **not** read its reply.  The
//!    request crosses on the still-flowing relay→connector direction, so the
//!    owner's `last_emitted_relay_to_connector` for this stream **advances**;
//!    the reply is sequenced into the paused direction, so the owner's
//!    `recv_contiguous_connector_to_relay` **cannot** advance.
//! 5. The gate waits for exactly that pair and loses the consumer at that
//!    instant.  The proof that the exchange was outstanding at the loss is
//!    `emitted_at_loss > emitted_before && recv_contiguous_at_loss ==
//!    recv_contiguous_before`: the relay had dispatched a 9P record toward the
//!    device and had received no answer to it, on the owner's own cursors.
//! 6. The paused bytes are released *after* the loss, so the device's `Rread`
//!    really does arrive at a relay whose consumer is gone.  That is the
//!    cleanup path the contract describes, driven rather than short-circuited.
//!
//! **The assertions are on the protocol objects, not on liveness.**  A session
//! that tidied itself up proves nothing about a fid.  What is asserted is that
//! the lost stream is **deregistered** at the owner, that the device's tunnel
//! session **survives** the loss of one consumer, and then — the contract
//! clause proper — that a **replacement** consumer session on the same export
//! restores no fids.
//!
//! That last part is driven in two pieces, because the session machine checks
//! them in that order and a single probe would conflate them:
//!
//! * **"require fresh version/attach"** — a replacement session that names the
//!   lost session's file fid *before* attaching is **closed** with the
//!   profile's protocol violation rather than served.  `SessionError` checks
//!   `BeforeAttach` before it consults the fid table, so this probe gets its
//!   own throwaway session and runs first.
//! * **"restores no fids"** — a replacement session that *has* attached, on a
//!   root fid of its own, then finds the lost session's fid numbers unbound:
//!   they answer `Rlerror` with the errno for a fid that is not allocated in
//!   this session.  Attaching on a *different* root number is what makes this
//!   probe mean anything — a session that attached on the lost session's own
//!   attach fid would be answering from its own binding.
//!
//! That session then shows the refusals were fid scoping and not a broken
//! export, by walking, opening and reading the whole file back with an exact
//! checksum — binding the lost session's file-fid *number* freshly as it does
//! so, which is the other half of the contract: the number is reusable once
//! the session that held it is gone.
//!
//! The reuse of the *same fid numbers* is deliberate and is the whole force of
//! the case: if fids leaked across consumer sessions, fid 1 would still be
//! bound to the file and would answer.
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
/// the library rather than written here as a literal.  (It evaluates to 22 at
/// this revision; the gate asserts the expression, not the number.)
const UNKNOWN_FID_ERRNO: u32 = tunnel_fs_core::FsErrorCode::Einval.errno();

/// The synthetic file the lost session is reading.
///
/// Large enough that the read the consumer is lost on is a full-`msize`
/// `Rread` and that the second session's verifying transfer needs many
/// messages, so neither is a single-frame special case.
const LOSS_FILE_BYTES: usize = 786_432;
/// The second session's whole-file transfer must need more than this many
/// `Rread` messages.
const MIN_READ_MESSAGES: usize = 10;
/// How much of the file is read before anything is perturbed, establishing
/// that the fid serves normally first.
const PREFIX_READS: usize = 3;

/// The fid numbers the lost session binds, and which the replacement session
/// then probes.
///
/// The replacement session deliberately reuses these exact numbers: the
/// contract clause is that no fid is restored across a consumer reconnect, and
/// reusing the numbers is what makes a leak observable instead of merely
/// unlikely.
const ATTACH_FID: u32 = 0;
const FILE_FID: u32 = 1;

/// The root fid the replacement session attaches on.
///
/// Deliberately **not** [`ATTACH_FID`]: the replacement session has to hold a
/// working root while it probes the lost session's fid numbers, and if it
/// attached on [`ATTACH_FID`] then a probe of that number would be answering
/// from this session's own binding rather than showing the absence of the lost
/// one.
const SECOND_ROOT_FID: u32 = 5;

/// The close code a session that speaks before `Tattach` is ended with.
///
/// `SessionError::BeforeAttach` answers `Close(ProtocolViolation)`, which is
/// the 9P profile's 1002.  This is the "require fresh version/attach" half of
/// the contract clause, and it is checked **before** the fid table is, which
/// is why the fid probes below have to run on an attached session.
const PROTOCOL_VIOLATION_CLOSE: u16 = 1002;

/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for a cluster state change.
const WAIT: Duration = Duration::from_secs(30);
/// The poll interval for every bounded wait here.
const POLL: Duration = Duration::from_millis(20);
/// The whole scenario's bound.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(300);

/// What the owner recorded about the stream the consumer was lost on.
///
/// Payload-free: sequences, identifiers and lifecycle bits only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LossObservation {
    /// The consumer stream the filesystem session ran on.
    pub stream_id: u64,
    /// The owner's relay→connector emit cursor for this stream, sampled while
    /// the reverse direction was already paused and before the held `Tread`.
    pub emitted_before: u64,
    /// The same cursor at the instant the consumer was lost.  It must have
    /// advanced: the relay dispatched the request toward the device.
    pub emitted_at_loss: u64,
    /// The owner's contiguous connector→relay receive cursor for this stream,
    /// sampled at the same instant as [`Self::emitted_before`].
    pub recv_contiguous_before: u64,
    /// The same cursor at the instant of the loss.  It must **not** have
    /// advanced: no answer to that request had reached the owner.
    pub recv_contiguous_at_loss: u64,
}

impl LossObservation {
    /// Whether this sample shows a 9P request the relay had dispatched and had
    /// received no answer to, at the instant the consumer was lost.  This is
    /// the gate's concurrency proof, and it is the owner's own record rather
    /// than a timestamp comparison.
    #[must_use]
    pub fn request_outstanding_at_loss(&self) -> bool {
        self.emitted_at_loss > self.emitted_before
            && self.recv_contiguous_at_loss == self.recv_contiguous_before
    }
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsConsumerLossEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    /// The negotiated session parameters, so a run cannot pass on a session
    /// that never reached 9P.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub negotiated_dialect: String,

    /// Bytes read on the fid **before** anything was perturbed.
    pub prefix_bytes: usize,
    /// The owner's sample either side of the loss.
    pub loss: LossObservation,
    /// Whether that sample proves the request was outstanding at the loss.
    pub request_outstanding_at_loss: bool,
    /// How many polls the outstanding state took to observe, for diagnosis.
    pub loss_polls: usize,
    /// The tag that was outstanding when the consumer went away, and which no
    /// consumer will ever read.
    pub abandoned_tag: u16,

    /// Session cleanup: the lost stream is deregistered at the owner.
    pub lost_stream_deregistered: bool,
    /// The device's tunnel session survived the loss of one consumer: losing a
    /// consumer must end that filesystem session and nothing wider.
    pub device_session_survived: bool,
    /// Session identity and epoch either side of the loss.  The device session
    /// is the same one; it is the 9P session on top of it that ended.
    pub session_id_stable: bool,
    pub epoch_before: u64,
    pub epoch_after: u64,

    // The contract clause proper, driven on a **second** consumer session that
    // reuses the same fid numbers.
    /// A replacement session that speaks **before** its own `Tattach` is
    /// closed rather than served: the contract requires a fresh
    /// version/attach, and this is that half of it.  The close code observed.
    pub pre_attach_probe_close_code: Option<u16>,
    /// And it was closed rather than answered: no `Rgetattr`, no `Rlerror`.
    pub pre_attach_probe_answered: bool,

    /// The second session reached 9P on its own terms.
    pub second_session_msize: u32,
    /// Whether probing the lost session's file fid, on an **attached**
    /// replacement session, was refused rather than answered.
    pub stale_file_fid_refused: bool,
    /// The errno that refusal carried.  A fid that is not allocated in this
    /// session, not a host error.
    pub stale_file_fid_errno: Option<u32>,
    /// Whether the lost session's attach fid was likewise unbound: a walk from
    /// it is refused rather than rooted at the export.
    pub stale_attach_fid_refused: bool,
    pub stale_attach_fid_errno: Option<u32>,
    /// The second session had to establish its own root: exactly one `Tattach`
    /// per session, never inherited.
    pub second_session_attached: bool,
    /// The whole file read back on the second session's own fid, proving the
    /// refusals above were fid scoping and not a broken export.
    pub second_session_bytes: usize,
    pub second_session_expected_bytes: usize,
    pub second_session_checksum_matches: bool,
    pub second_session_messages: usize,
    /// The file the second session sees is the same size as before the loss,
    /// so nothing the lost session was doing damaged it.
    pub second_session_getattr_size: u64,
    /// `Tattach` count across the whole run: one per session, two in total,
    /// and never a third that would mean a session was reconstructed.
    pub attach_count: usize,
}

/// Validate every rule; the first violated rule is named.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_fs_consumer_loss_evidence(evidence: &FsConsumerLossEvidence) -> Result<()> {
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
        // The concurrency rule.  Without this the gate would prove only that a
        // consumer went away somewhere near a filesystem session.
        (
            "the relay had dispatched a 9P record toward the device when the consumer \
             was lost"
                .into(),
            evidence.loss.emitted_at_loss > evidence.loss.emitted_before,
        ),
        (
            "the relay had received no answer to that record when the consumer was lost: \
             the 9P exchange was outstanding across the loss"
                .into(),
            evidence.request_outstanding_at_loss && evidence.loss.request_outstanding_at_loss(),
        ),
        (
            "a tag was outstanding when the consumer was lost".into(),
            evidence.loss.stream_id > 0,
        ),
        // Session cleanup.
        (
            "the lost consumer's stream was deregistered at the owner".into(),
            evidence.lost_stream_deregistered,
        ),
        (
            "the device's tunnel session survived the loss of one consumer".into(),
            evidence.device_session_survived,
        ),
        (
            "the device session kept its identity across the consumer loss".into(),
            evidence.session_id_stable,
        ),
        (
            "losing a consumer did not change the control epoch".into(),
            evidence.epoch_after == evidence.epoch_before,
        ),
        // The contract clause: no fid is restored across a consumer reconnect.
        // First its "require fresh version/attach" half.
        (
            "a replacement session that spoke before its own Tattach was closed, \
             not served"
                .into(),
            !evidence.pre_attach_probe_answered,
        ),
        (
            "that close was the profile's protocol violation".into(),
            evidence.pre_attach_probe_close_code == Some(PROTOCOL_VIOLATION_CLOSE),
        ),
        (
            "the second consumer session reached 9P on its own terms".into(),
            evidence.second_session_msize > 0
                && evidence.second_session_msize <= OFFERED_MSIZE,
        ),
        (
            "the lost session's file fid was not restored into the second session".into(),
            evidence.stale_file_fid_refused,
        ),
        (
            "that refusal was because the fid is not allocated in this session".into(),
            evidence.stale_file_fid_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "the lost session's attach fid was not restored into the second session".into(),
            evidence.stale_attach_fid_refused,
        ),
        (
            "that refusal too was because the fid is not allocated in this session".into(),
            evidence.stale_attach_fid_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "the second session established its own root with its own Tattach".into(),
            evidence.second_session_attached,
        ),
        // The export is undamaged, so the refusals above are fid scoping.
        (
            "the second session read the whole file back on its own fid".into(),
            evidence.second_session_bytes == evidence.second_session_expected_bytes
                && evidence.second_session_expected_bytes == LOSS_FILE_BYTES,
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
            "the file was undamaged by the lost session".into(),
            evidence.second_session_getattr_size == LOSS_FILE_BYTES as u64,
        ),
        (
            "each session attached exactly once: two Tattach across the run".into(),
            evidence.attach_count == 2,
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "fs consumer loss gate failed: {rule}"
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

/// Run the gate: start the cluster, lose a consumer mid-exchange, and validate
/// the evidence.
///
/// # Errors
/// Any harness, cluster or validation failure.
pub async fn verify() -> Result<FsConsumerLossEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("fs consumer loss harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result.and_then(|evidence| {
            validate_fs_consumer_loss_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs consumer loss scenario exceeded its bounded deadline".into(),
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

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<FsConsumerLossEvidence> {
    let mut evidence = FsConsumerLossEvidence {
        relay_count: cluster.relays.len(),
        second_session_expected_bytes: LOSS_FILE_BYTES,
        ..FsConsumerLossEvidence::default()
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
        .fs_service("consumer-loss")
        .ok_or_else(|| {
            HarnessError::InvalidInput("the consumer-loss filesystem export was not seeded".into())
        })?
        .service_id;

    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    std::fs::write(
        directory.path().join("big.bin"),
        synthetic_bytes(LOSS_FILE_BYTES),
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
        "m4-fs-consumer-loss-canary",
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
    // registry is empty.
    let mut client = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect_with_http_handlers(
            ConnectOptions::new(device_profile.config.clone()),
            HttpHandlers::new(),
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("fs consumer loss device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("fs consumer loss device: {error}")))?;

    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| {
                HarnessError::Timeout("fs consumer loss device readiness timed out".into())
            })?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        exercise(
            cluster,
            harness,
            &proxy,
            &client,
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
            "fs consumer loss device phase: {:?}",
            client.status_snapshot().phase
        );
        eprintln!("fs consumer loss partial evidence: {evidence:?}");
    }
    let stop = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    scenario?;
    match stop {
        Ok(Ok(())) => Ok(evidence),
        Ok(Err(error)) => Err(HarnessError::Process(format!("device stop: {error}"))),
        Err(_) => Err(HarnessError::Timeout("device stop timed out".into())),
    }
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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn exercise(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    proxy: &ProxyHandle,
    client: &tunnel_client::ConnectionHandle,
    tenant_id: Uuid,
    device_id: Uuid,
    service: Uuid,
    session_id: &str,
    evidence: &mut FsConsumerLossEvidence,
) -> Result<()> {
    // The owner claim, so the gate is speaking to the relay that owns the
    // device rather than to whichever relay answered first.
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
    // Session one: established, serving, then lost with a request in flight.
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

    {
        let snapshot = owner_snapshot(cluster).await?;
        evidence.epoch_before = session_of(&snapshot, session_id)?.epoch;
    }

    // 2. Settle the carrier and pause the data socket's connector→relay bytes.
    //    The control socket is untouched: this gate loses a consumer, it does
    //    not fault a carrier.
    let connection = {
        let deadline = Instant::now() + WAIT;
        loop {
            let device = client.status_snapshot();
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
    let mut observation = LossObservation {
        stream_id,
        ..LossObservation::default()
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
    //    crosses on the still-flowing relay→connector direction; the device
    //    performs it and sequences the Rread into the paused socket.
    let abandoned_tag = session
        .send(Message::Tread {
            fid: FILE_FID,
            offset: prefix as u64,
            count: READ_COUNT,
        })
        .await?;
    evidence.abandoned_tag = abandoned_tag;

    // 5. Wait for the owner to show the request dispatched and unanswered, and
    //    lose the consumer at that instant.
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
                let sample = LossObservation {
                    emitted_at_loss: stream.last_emitted_relay_to_connector,
                    recv_contiguous_at_loss: stream.recv_contiguous_connector_to_relay,
                    ..observation.clone()
                };
                // Only a sample that actually shows the record dispatched and
                // unanswered ends the wait.
                if sample.request_outstanding_at_loss() {
                    evidence.loss_polls = polls;
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
    evidence.request_outstanding_at_loss = observation.request_outstanding_at_loss();
    evidence.loss = observation;

    // The consumer is gone, mid-exchange, with that tag outstanding and its
    // reply still inside the paused direction.  No close frame, no drain.
    session.abandon();

    // 6. Release the bytes **after** the loss, so the device's Rread really
    //    does arrive at a relay whose consumer has gone away.  That is the
    //    cleanup path the contract describes, driven rather than skipped.
    proxy
        .resume(ProxyDirection::ClientToTarget, connection)
        .await?;

    // ---------------------------------------------------------------------
    // Session cleanup: the lost stream is deregistered, the device survives.
    // ---------------------------------------------------------------------
    {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = owner_snapshot(cluster).await?;
            if let Ok(owner) = session_of(&snapshot, session_id) {
                if !owner
                    .streams
                    .iter()
                    .any(|stream| stream.stream_id == stream_id)
                {
                    evidence.lost_stream_deregistered = true;
                    evidence.device_session_survived = true;
                    evidence.session_id_stable = owner.session_id == session_id;
                    evidence.epoch_after = owner.epoch;
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the lost consumer's stream was never deregistered at the owner".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    // ---------------------------------------------------------------------
    // Session two: the contract clause.  No fid is restored across a consumer
    // reconnect, and the same fid numbers are reused so a leak would show.
    // ---------------------------------------------------------------------
    // First, the "require fresh version/attach" half of the clause, on its own
    // throwaway session: a replacement session that names the lost session's
    // file fid *before* attaching is closed rather than served.  This probe
    // needs its own session precisely because it ends it, and it is run first
    // so the fid probes below cannot be confused with it: `BeforeAttach` is
    // checked before the fid table is, so a pre-attach probe could never
    // distinguish "that fid is not allocated here" from "you have not
    // attached", which is why the fid probes run on an attached session.
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
    // root while it probes the lost session's fid numbers.  Attaching on
    // ATTACH_FID instead would make a probe of that number answer from this
    // session's binding rather than show the absence of the lost one.
    second.attach(SECOND_ROOT_FID).await?;
    evidence.attach_count += 1;
    evidence.second_session_attached = true;

    // The lost session's file fid must not be bound here.
    match second.getattr(FILE_FID, GETATTR_BASIC).await? {
        Message::Rgetattr(_) => {
            return Err(HarnessError::Process(
                "the lost session's file fid answered in a new consumer session: the profile \
                 restored a fid across a consumer WebSocket reconnect"
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
                "the lost session's attach fid walked in a new consumer session: the profile \
                 restored a fid across a consumer WebSocket reconnect"
                    .into(),
            ));
        }
        other => {
            evidence.stale_attach_fid_refused = matches!(other, Message::Rlerror { .. });
            evidence.stale_attach_fid_errno = errno_of(&other);
        }
    }

    // The export answers normally on this session's own root, so the refusals
    // above are fid scoping and not a broken export.  Binding FILE_FID here,
    // fresh, is also the other half of the contract: the *number* is reusable
    // once the session that held it is gone.
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

    let mut transferred: Vec<u8> = Vec::with_capacity(LOSS_FILE_BYTES);
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
        fnv1a(&transferred) == fnv1a(&synthetic_bytes(LOSS_FILE_BYTES));

    second.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> FsConsumerLossEvidence {
        FsConsumerLossEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: 65_536,
            negotiated_dialect: DIALECT.into(),
            prefix_bytes: 196_575,
            loss: LossObservation {
                stream_id: 1,
                emitted_before: 4,
                emitted_at_loss: 5,
                recv_contiguous_before: 4,
                recv_contiguous_at_loss: 4,
            },
            request_outstanding_at_loss: true,
            loss_polls: 3,
            abandoned_tag: 7,
            lost_stream_deregistered: true,
            device_session_survived: true,
            session_id_stable: true,
            epoch_before: 1,
            epoch_after: 1,
            pre_attach_probe_close_code: Some(PROTOCOL_VIOLATION_CLOSE),
            pre_attach_probe_answered: false,
            second_session_msize: 65_536,
            stale_file_fid_refused: true,
            stale_file_fid_errno: Some(UNKNOWN_FID_ERRNO),
            stale_attach_fid_refused: true,
            stale_attach_fid_errno: Some(UNKNOWN_FID_ERRNO),
            second_session_attached: true,
            second_session_bytes: LOSS_FILE_BYTES,
            second_session_expected_bytes: LOSS_FILE_BYTES,
            second_session_checksum_matches: true,
            second_session_messages: 12,
            second_session_getattr_size: LOSS_FILE_BYTES as u64,
            attach_count: 2,
        }
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_fs_consumer_loss_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsConsumerLossEvidence));
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
            ("the fid never served before the loss", |e| {
                e.prefix_bytes = 0;
            }),
            // The concurrency rules.
            ("the request was never dispatched", |e| {
                e.loss.emitted_at_loss = e.loss.emitted_before;
            }),
            ("the reply had already been received", |e| {
                e.loss.recv_contiguous_at_loss = e.loss.recv_contiguous_before + 1;
            }),
            ("the in-flight summary contradicts its sample", |e| {
                e.request_outstanding_at_loss = false;
            }),
            ("no stream was identified", |e| e.loss.stream_id = 0),
            // Session cleanup.
            ("the lost stream was never deregistered", |e| {
                e.lost_stream_deregistered = false;
            }),
            ("the device session did not survive", |e| {
                e.device_session_survived = false;
            }),
            ("the device session changed identity", |e| {
                e.session_id_stable = false;
            }),
            ("losing a consumer changed the epoch", |e| e.epoch_after = 2),
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
            ("the second session never reached 9P", |e| {
                e.second_session_msize = 0;
            }),
            ("the lost file fid was restored", |e| {
                e.stale_file_fid_refused = false;
            }),
            ("the file fid was refused for the wrong reason", |e| {
                e.stale_file_fid_errno = Some(UNKNOWN_FID_ERRNO + 1);
            }),
            ("the file fid refusal carried no errno", |e| {
                e.stale_file_fid_errno = None;
            }),
            ("the lost attach fid was restored", |e| {
                e.stale_attach_fid_refused = false;
            }),
            ("the attach fid was refused for the wrong reason", |e| {
                e.stale_attach_fid_errno = Some(UNKNOWN_FID_ERRNO + 1);
            }),
            ("the second session never attached", |e| {
                e.second_session_attached = false;
            }),
            ("the second session read a short file", |e| {
                e.second_session_bytes = LOSS_FILE_BYTES - 1;
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
                validate_fs_consumer_loss_evidence(&evidence).is_err(),
                "mutation `{name}` must be rejected: no rule here is decorative"
            );
        }
    }

    /// The concurrency predicate itself, independent of the rule list: it must
    /// be false for a settled exchange and true only when the relay had
    /// dispatched a record it had received no answer to.
    #[test]
    fn outstanding_predicate_requires_a_dispatched_and_unanswered_record() {
        let outstanding = LossObservation {
            stream_id: 1,
            emitted_before: 4,
            emitted_at_loss: 5,
            recv_contiguous_before: 4,
            recv_contiguous_at_loss: 4,
        };
        assert!(outstanding.request_outstanding_at_loss());

        let never_dispatched = LossObservation {
            emitted_at_loss: 4,
            ..outstanding.clone()
        };
        assert!(
            !never_dispatched.request_outstanding_at_loss(),
            "a request the relay never emitted was not outstanding across the loss"
        );

        let already_answered = LossObservation {
            recv_contiguous_at_loss: 5,
            ..outstanding.clone()
        };
        assert!(
            !already_answered.request_outstanding_at_loss(),
            "a record the owner had already received is a settled exchange"
        );

        // A reply that arrived for an *earlier* request still counts as the
        // exchange having been answered: the baseline is fixed while the
        // reverse direction is paused, so any advance at all is an answer.
        let partially_answered = LossObservation {
            emitted_at_loss: 9,
            recv_contiguous_at_loss: 5,
            ..outstanding
        };
        assert!(
            !partially_answered.request_outstanding_at_loss(),
            "any advance of the receive cursor means an answer crossed the paused direction"
        );
    }
}
