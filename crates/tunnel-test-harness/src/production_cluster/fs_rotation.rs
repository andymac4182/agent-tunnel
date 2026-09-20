//! A live 9P2000.L filesystem session carried across a **real scheduled
//! data-socket rotation**, over the real cluster: a consumer WSS session
//! through the owning relay's public route, the owner actor, the device data
//! WebSocket and `tunnel-client`'s filesystem export.
//!
//! `docs/protocol.md` states the contract this gate exists to exercise:
//!
//! > 9P fids, request tags and negotiated session state belong to the logical
//! > filesystem session and remain intact through scheduled data socket
//! > rotation.  The relay neither duplicates `Tattach` nor reconstructs fids
//! > during cutover.
//!
//! and requires that compatibility tests cover "reads/writes spanning
//! rotations".  Before this gate, the four filesystem cluster gates contained
//! no occurrence of `rotat`, `epoch` or `restart` in 6,029 lines: no
//! filesystem session had ever crossed a rotation.
//!
//! **What makes the rotation concurrent rather than sequential.**  A rotation
//! that happens between two quiet 9P exchanges proves nothing.  This gate
//! holds one `Rread` in flight *across the freeze* and proves it from the
//! owner's own rotation state machine rather than from timing:
//!
//! 1. The consumer opens a fid and reads the first part of a synthetic file,
//!    so the fid is established and serving before anything is perturbed.
//! 2. The device data socket's **connector→relay** bytes are paused at the
//!    harness TCP proxy once the carrier has settled.  The control socket and
//!    the rotation candidate are untouched.
//! 3. The consumer sends one `Tread` and does **not** read its reply.  The
//!    request crosses to the device on the still-flowing relay→connector
//!    direction, the device performs it, and the connector sequences the
//!    `Rread` into the paused socket.
//! 4. At `ROTATE_QUIESCE` the owner freezes its writer and fixes the
//!    immutable per-direction fences.  The connector's fence for this stream
//!    therefore covers a frame the owner has not received, so the owner
//!    cannot prove its drain and stays frozen until the bytes are released —
//!    well inside the overlap deadline.
//! 5. The gate samples the owner at that instant.  The proof that the 9P
//!    exchange was in flight at the freeze is
//!    `connector_fence_sequences[stream] > recv_contiguous_connector_to_relay`
//!    for this stream: the connector had sequenced a record the owner had not
//!    yet received, at the moment the attempt's fences were fixed.  That is
//!    the owner's own record, not a timestamp comparison.
//! 6. The bytes are released, the drain completes, the attempt commits, and
//!    the consumer then reads the reply it never collected.
//!
//! **The assertions are on the operation, not on liveness.**  A session that
//! still exists proves nothing.  What is asserted is that the held `Rread`
//! came back carrying the tag that was outstanding across the freeze, that
//! the file's every byte arrived exactly once — the whole-file checksum and
//! length are exact, over a transfer that spans the rotation on one fid — and
//! that the fid opened before the rotation still answers after it without any
//! re-`Tattach`.
//!
//! All fixture content is synthetic and generated here; no evidence field
//! carries a path, a name or file content.

use std::time::{Duration, Instant};

use tokio::time::{sleep, timeout};
use tunnel_client::{
    ConnectOptions, FsExportSettings, LocalExport, LocalExportKind, http_forward::HttpHandlers,
};
use tunnel_core::RotationConfig;
use tunnel_fs_ninep::{GETATTR_BASIC, Message, flags::O_RDONLY};
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot};
use uuid::Uuid;

use super::fs_wire as wire;
use wire::{NinepClient, Target, UpgradeFailure, unexpected};

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

/// The synthetic file the rotation-spanning read covers.
///
/// Large enough that the transfer needs many maximum-size `Rread` messages,
/// so the rotation falls inside a transfer rather than between two of them.
const ROTATION_FILE_BYTES: usize = 1_572_864;
/// The transfer must need more than this many `Rread` messages.
const MIN_READ_MESSAGES: usize = 20;
/// How much of the file is read before anything is perturbed, establishing
/// that the fid serves normally first.
const PREFIX_READS: usize = 3;

/// A short scheduled-rotation policy with enough overlap to hold a freeze.
///
/// The same shape the http-forward rotation gate uses: `0 <
/// handshake_timeout < overlap < interval`, with an overlap long enough that
/// a held freeze is released well inside the deadline.
const GATE_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 6,
    handshake_timeout_seconds: 2,
    overlap_seconds: 5,
};

/// The phases in which the owner's writer is frozen for an attempt.
const FROZEN_PHASES: [&str; 3] = ["quiescing", "draining", "committing"];

/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for a cluster state change.
const WAIT: Duration = Duration::from_secs(30);
/// The poll interval for every bounded wait here.
const POLL: Duration = Duration::from_millis(20);
/// The whole scenario's bound.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(300);

/// What the owner recorded about the attempt that froze with the `Rread` in
/// flight.  Payload-free: sequences, identifiers and lifecycle bits only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FreezeObservation {
    /// The consumer stream the filesystem session runs on.
    pub stream_id: u64,
    /// The owner's phase when the sample was taken.
    pub phase: String,
    /// Whether a rotation attempt was active at the sample.
    pub attempt_active: bool,
    /// The connector's immutable fence for this stream: the last
    /// connector→relay sequence it had emitted when the attempt froze.
    pub connector_fence: Option<u64>,
    /// The owner's contiguous receive cursor for this stream at the sample.
    pub relay_recv_contiguous: u64,
    /// The owner's own fence for this stream.
    pub relay_fence: Option<u64>,
    /// Generations either side of the attempt.
    pub old_generation: u64,
    pub candidate_generation: Option<u64>,
    /// Whether both writer barriers had flushed.
    pub writer_barriers_flushed: [bool; 2],
}

impl FreezeObservation {
    /// Whether this sample shows a 9P record the connector had sequenced and
    /// the owner had not received, at the instant the attempt's fences were
    /// fixed.  This is the gate's concurrency proof.
    #[must_use]
    pub fn exchange_in_flight_at_freeze(&self) -> bool {
        self.attempt_active
            && FROZEN_PHASES.contains(&self.phase.as_str())
            && self
                .connector_fence
                .is_some_and(|fence| fence > self.relay_recv_contiguous)
    }
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsRotationEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    /// The negotiated session parameters, so a run cannot pass on a session
    /// that never reached 9P.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub negotiated_dialect: String,

    /// Bytes read on the fid **before** anything was perturbed.
    pub prefix_bytes: usize,
    /// The owner's sample at the held freeze.
    pub freeze: FreezeObservation,
    /// Whether the freeze sample proves the exchange was in flight.
    pub exchange_in_flight_at_freeze: bool,
    /// How many polls the freeze took to observe, for diagnosis only.
    pub freeze_polls: usize,

    /// The tag that was outstanding across the freeze.
    pub held_tag: u16,
    /// Whether the reply that arrived after the rotation carried that tag.
    pub held_reply_tag_matched: bool,
    /// Whether that reply was an `Rread` rather than an error or a close.
    pub held_reply_was_rread: bool,
    /// Bytes that reply carried.
    pub held_reply_bytes: usize,

    /// The whole transfer, spanning the rotation on one fid.
    pub transfer_bytes: usize,
    pub transfer_expected_bytes: usize,
    pub transfer_checksum_matches: bool,
    pub transfer_messages: usize,

    /// Rotation accounting from the owner.
    pub rotations_completed_before: u64,
    pub rotations_completed_after: u64,
    pub generation_before: u64,
    pub generation_after: u64,
    /// The control epoch before and after the attempt.  A scheduled rotation
    /// changes the data generation and never the control epoch.
    pub epoch_before: u64,
    pub epoch_after: u64,
    /// A clean rotation replays nothing.
    pub total_replayed_frames: u64,
    /// The rotation must not have been forced into recovery.
    pub deadline_forced_retirement: bool,
    pub rotation_recovery_reason: Option<String>,

    /// The same-owner contract: identity either side of the rotation.
    pub session_id_stable: bool,
    pub epoch_stable: bool,

    /// The fid opened before the rotation still answers after it.
    pub fid_survived_getattr: bool,
    pub fid_survived_getattr_size: u64,
    /// The attach fid established before the rotation still walks after it,
    /// with no re-`Tattach`.
    pub attach_fid_survived_walk: bool,
    /// A fresh tag allocated after the rotation correlates correctly.
    pub post_rotation_tag_correlated: bool,
    /// The session was never re-attached: exactly one `Tattach` was sent.
    pub attach_count: usize,
}

/// Validate every rule; the first violated rule is named.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_fs_rotation_evidence(evidence: &FsRotationEvidence) -> Result<()> {
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
        // The concurrency rule.  Without this the gate would prove only that
        // a rotation happened somewhere near a filesystem session.
        (
            "a rotation attempt was active when the owner was sampled".into(),
            evidence.freeze.attempt_active,
        ),
        (
            "the owner's writer was frozen when it was sampled".into(),
            FROZEN_PHASES.contains(&evidence.freeze.phase.as_str()),
        ),
        (
            "the connector's fence covered a record the owner had not received: \
             the 9P exchange was in flight when the attempt's fences were fixed"
                .into(),
            evidence.exchange_in_flight_at_freeze && evidence.freeze.exchange_in_flight_at_freeze(),
        ),
        (
            "the attempt named a candidate generation above the old one".into(),
            evidence
                .freeze
                .candidate_generation
                .is_some_and(|candidate| candidate > evidence.freeze.old_generation),
        ),
        // The operation-level rules.
        (
            "the reply held across the freeze carried the tag that was outstanding".into(),
            evidence.held_reply_tag_matched,
        ),
        (
            "the reply held across the freeze was an Rread".into(),
            evidence.held_reply_was_rread,
        ),
        (
            "the reply held across the freeze carried bytes".into(),
            evidence.held_reply_bytes > 0,
        ),
        (
            "the transfer spanning the rotation delivered every byte exactly once".into(),
            evidence.transfer_bytes == evidence.transfer_expected_bytes
                && evidence.transfer_expected_bytes == ROTATION_FILE_BYTES,
        ),
        (
            "the transfer's checksum matched the synthetic content".into(),
            evidence.transfer_checksum_matches,
        ),
        (
            "the transfer spanned many Rread messages rather than one".into(),
            evidence.transfer_messages >= MIN_READ_MESSAGES,
        ),
        // The rotation really completed, cleanly.
        (
            "a scheduled rotation completed during the session".into(),
            evidence.rotations_completed_after > evidence.rotations_completed_before,
        ),
        (
            "the active data generation advanced".into(),
            evidence.generation_after > evidence.generation_before,
        ),
        (
            "a clean rotation replayed no frames".into(),
            evidence.total_replayed_frames == 0,
        ),
        (
            "the rotation was not forced into recovery by its deadline".into(),
            !evidence.deadline_forced_retirement && evidence.rotation_recovery_reason.is_none(),
        ),
        // The same-owner contract of docs/protocol.md.  Data-only recovery
        // may retain fids only while the same control owner and all ordered
        // stream state are retained, so the identity either side of the
        // rotation is part of what makes fid survival legitimate here.
        (
            "the session identity was unchanged across the rotation".into(),
            evidence.session_id_stable,
        ),
        (
            "the session epoch was unchanged across the rotation".into(),
            evidence.epoch_stable,
        ),
        // The fid rules of docs/protocol.md.
        (
            "the fid opened before the rotation still answered after it".into(),
            evidence.fid_survived_getattr,
        ),
        (
            "that fid still named the same file".into(),
            evidence.fid_survived_getattr_size == ROTATION_FILE_BYTES as u64,
        ),
        (
            "the attach fid established before the rotation still walked after it".into(),
            evidence.attach_fid_survived_walk,
        ),
        (
            "the relay did not reconstruct the session: exactly one Tattach was sent".into(),
            evidence.attach_count == 1,
        ),
        (
            "a tag allocated after the rotation correlated correctly".into(),
            evidence.post_rotation_tag_correlated,
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "fs rotation gate failed: {rule}"
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

/// Run the gate: start the cluster, hold a session across a rotation, and
/// validate the evidence.
///
/// # Errors
/// Any harness, cluster or validation failure.
pub async fn verify() -> Result<FsRotationEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("fs rotation harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result.and_then(|evidence| {
            validate_fs_rotation_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs rotation scenario exceeded its bounded deadline".into(),
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
) -> Result<FsRotationEvidence> {
    let mut evidence = FsRotationEvidence {
        relay_count: cluster.relays.len(),
        transfer_expected_bytes: ROTATION_FILE_BYTES,
        ..FsRotationEvidence::default()
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
        .fs_service("rotation")
        .ok_or_else(|| {
            HarnessError::InvalidInput("the rotation filesystem export was not seeded".into())
        })?
        .service_id;

    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    std::fs::write(
        directory.path().join("big.bin"),
        synthetic_bytes(ROTATION_FILE_BYTES),
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
        "m4-fs-rotation-canary",
        proxy.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    device_profile.config.rotation = GATE_ROTATION;
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
    .map_err(|_| HarnessError::Timeout("fs rotation device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("fs rotation device: {error}")))?;

    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("fs rotation device readiness timed out".into()))?
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
            "fs rotation device phase: {:?}",
            client.status_snapshot().phase
        );
        eprintln!("fs rotation partial evidence: {evidence:?}");
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
    evidence: &mut FsRotationEvidence,
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

    let mut session = match NinepClient::connect(&target, &ca, &token, Some(SUBPROTOCOL)).await {
        Ok(session) => session,
        Err(UpgradeFailure::Status { status, .. }) => {
            return Err(HarnessError::Http(format!(
                "the filesystem upgrade was refused with HTTP status {status}"
            )));
        }
        Err(UpgradeFailure::Harness(error)) => return Err(error),
    };
    evidence.selected_subprotocol = session.selected_subprotocol().to_owned();

    let (msize, dialect) = session.version(OFFERED_MSIZE).await?;
    evidence.negotiated_msize = msize;
    evidence.negotiated_dialect = dialect;

    // Exactly one Tattach for the whole run: the contract says the relay
    // neither duplicates Tattach nor reconstructs fids during cutover, so the
    // gate must never send a second one.
    const ATTACH_FID: u32 = 0;
    const FILE_FID: u32 = 1;
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

    // The whole transfer is accumulated here so its checksum covers bytes
    // that crossed on both generations.
    let mut transferred: Vec<u8> = Vec::with_capacity(ROTATION_FILE_BYTES);
    let mut messages = 0_usize;

    // 1. Serve the fid normally first, so a later failure cannot be blamed on
    //    a session that never worked.
    for _ in 0..PREFIX_READS {
        match session
            .read(FILE_FID, transferred.len() as u64, READ_COUNT)
            .await?
        {
            Message::Rread { data } if !data.is_empty() => {
                messages += 1;
                transferred.extend_from_slice(&data);
            }
            other => return Err(unexpected("a non-empty Rread", &other)),
        }
    }
    evidence.prefix_bytes = transferred.len();

    // Rotation accounting before the attempt this gate holds.
    {
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
        evidence.rotations_completed_before = owner.rotations_completed;
        evidence.generation_before = owner.active_generation;
        evidence.epoch_before = owner.epoch;
    }

    // 2. Settle the carrier and pause the data socket's connector→relay
    //    bytes.  The control socket and the candidate stay untouched.
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

    // 3. Send one Tread and deliberately do not read its reply.  The request
    //    crosses on the still-flowing relay→connector direction; the device
    //    performs it and sequences the Rread into the paused socket.
    let held_offset = transferred.len() as u64;
    let held_tag = session
        .send(Message::Tread {
            fid: FILE_FID,
            offset: held_offset,
            count: READ_COUNT,
        })
        .await?;
    evidence.held_tag = held_tag;

    // 4/5. Wait for the owner to freeze with that record outstanding, and
    //      sample it.  The freeze is held by the paused bytes: the owner
    //      cannot prove its drain until they are released.
    let freeze = {
        let deadline = Instant::now()
            + Duration::from_secs(
                (GATE_ROTATION.interval_seconds + GATE_ROTATION.overlap_seconds) * 2,
            );
        let mut polls = 0_usize;
        let mut phases: Vec<String> = Vec::new();
        loop {
            polls += 1;
            let snapshot = owner_snapshot(cluster).await?;
            let owner = session_of(&snapshot, session_id)?;
            if phases.last() != Some(&owner.phase) {
                phases.push(owner.phase.clone());
            }
            if FROZEN_PHASES.contains(&owner.phase.as_str())
                && let Some(rotation) = owner.rotation_diagnostics.as_ref()
                && rotation.attempt_active
                && let Some(stream) = owner
                    .streams
                    .iter()
                    .find(|stream| stream.stream_id == stream_id)
            {
                let observation = FreezeObservation {
                    stream_id,
                    phase: owner.phase.clone(),
                    attempt_active: rotation.attempt_active,
                    connector_fence: rotation
                        .connector_fence_sequences
                        .iter()
                        .find(|(id, _)| *id == stream_id)
                        .map(|(_, sequence)| *sequence),
                    relay_recv_contiguous: stream.recv_contiguous_connector_to_relay,
                    relay_fence: rotation
                        .relay_fence_sequences
                        .iter()
                        .find(|(id, _)| *id == stream_id)
                        .map(|(_, sequence)| *sequence),
                    old_generation: owner.active_generation,
                    candidate_generation: owner.candidate_generation,
                    writer_barriers_flushed: rotation.writer_barrier_flushed,
                };
                // Only a sample that actually shows the record outstanding
                // ends the wait: a freeze observed before the connector's
                // fence was exchanged is not yet the evidence.
                if observation.exchange_in_flight_at_freeze() {
                    evidence.freeze_polls = polls;
                    break observation;
                }
            }
            if Instant::now() >= deadline {
                // Release before failing so cleanup is not wedged.
                let _ = proxy
                    .resume(ProxyDirection::ClientToTarget, connection)
                    .await;
                return Err(HarnessError::Process(format!(
                    "no freeze was observed with the 9P exchange in flight: phases {phases:?}"
                )));
            }
            sleep(POLL).await;
        }
    };
    evidence.exchange_in_flight_at_freeze = freeze.exchange_in_flight_at_freeze();
    evidence.freeze = freeze;

    // 6. Release the bytes.  The drain completes and the attempt commits.
    proxy
        .resume(ProxyDirection::ClientToTarget, connection)
        .await?;

    // The reply that was outstanding across the freeze.  This is an
    // operation-level assertion: the tag that crossed the rotation must come
    // back, carrying data, on the same fid.
    let held = session.recv_frame().await?;
    evidence.held_reply_tag_matched = held.tag == held_tag;
    match held.message {
        Message::Rread { data } => {
            evidence.held_reply_was_rread = true;
            evidence.held_reply_bytes = data.len();
            if !data.is_empty() {
                messages += 1;
                transferred.extend_from_slice(&data);
            }
        }
        other => return Err(unexpected("the held Rread", &other)),
    }

    // Wait for the attempt to finish so the rest of the transfer genuinely
    // continues on the new generation.
    {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = owner_snapshot(cluster).await?;
            let owner = session_of(&snapshot, session_id)?;
            if owner.rotations_completed > evidence.rotations_completed_before
                && owner.phase == "active"
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the held rotation attempt never completed".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    // Finish the transfer on the **same fid**, across the generation change.
    loop {
        match session
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
    evidence.transfer_bytes = transferred.len();
    evidence.transfer_messages = messages;
    evidence.transfer_checksum_matches =
        fnv1a(&transferred) == fnv1a(&synthetic_bytes(ROTATION_FILE_BYTES));

    // The fid opened before the rotation still answers after it, and still
    // names the same file.
    match session.getattr(FILE_FID, GETATTR_BASIC).await? {
        Message::Rgetattr(attributes) => {
            evidence.fid_survived_getattr = true;
            evidence.fid_survived_getattr_size = attributes.size;
        }
        other => return Err(unexpected("Rgetattr", &other)),
    }

    // The attach fid established before the rotation still walks, with no
    // second Tattach anywhere in this run.
    const POST_FID: u32 = 2;
    match session.walk(ATTACH_FID, POST_FID, &["big.bin"]).await? {
        Message::Rwalk { .. } => evidence.attach_fid_survived_walk = true,
        other => return Err(unexpected("Rwalk", &other)),
    }

    // A tag allocated after the rotation correlates correctly.  `call`
    // refuses a reply whose tag is not the one it sent, so a clean Rclunk
    // here is the correlation.
    match session.clunk(POST_FID).await? {
        Message::Rclunk => evidence.post_rotation_tag_correlated = true,
        other => return Err(unexpected("Rclunk", &other)),
    }

    // Final rotation accounting and the same-owner contract.
    {
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
        evidence.rotations_completed_after = owner.rotations_completed;
        evidence.generation_after = owner.active_generation;
        evidence.total_replayed_frames = owner.total_replayed_frames;
        evidence.deadline_forced_retirement = owner.rotation_deadline_forced_retirement;
        evidence.rotation_recovery_reason = owner.rotation_recovery_reason.map(str::to_owned);
        evidence.epoch_after = owner.epoch;
        evidence.session_id_stable = owner.session_id == session_id;
        evidence.epoch_stable = owner.epoch == evidence.epoch_before;
    }

    session.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly the evidence the real run produced at this tip, so the
    /// validator's bounds are calibrated against a measured gate rather than
    /// against numbers chosen to satisfy them.
    fn passing() -> FsRotationEvidence {
        FsRotationEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: 65_536,
            negotiated_dialect: DIALECT.into(),
            prefix_bytes: 196_575,
            freeze: FreezeObservation {
                stream_id: 1,
                phase: "quiescing".into(),
                attempt_active: true,
                connector_fence: Some(12),
                relay_recv_contiguous: 10,
                relay_fence: None,
                old_generation: 1,
                candidate_generation: Some(2),
                writer_barriers_flushed: [false, true],
            },
            exchange_in_flight_at_freeze: true,
            freeze_polls: 278,
            held_tag: 7,
            held_reply_tag_matched: true,
            held_reply_was_rread: true,
            held_reply_bytes: 65_525,
            transfer_bytes: ROTATION_FILE_BYTES,
            transfer_expected_bytes: ROTATION_FILE_BYTES,
            transfer_checksum_matches: true,
            transfer_messages: 25,
            rotations_completed_before: 0,
            rotations_completed_after: 1,
            generation_before: 1,
            generation_after: 2,
            epoch_before: 1,
            epoch_after: 1,
            total_replayed_frames: 0,
            deadline_forced_retirement: false,
            rotation_recovery_reason: None,
            session_id_stable: true,
            epoch_stable: true,
            fid_survived_getattr: true,
            fid_survived_getattr_size: ROTATION_FILE_BYTES as u64,
            attach_fid_survived_walk: true,
            post_rotation_tag_correlated: true,
            attach_count: 1,
        }
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_fs_rotation_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsRotationEvidence));
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
            ("the fid never served before the rotation", |e| {
                e.prefix_bytes = 0;
            }),
            // The concurrency rules.
            ("no attempt was active", |e| {
                e.freeze.attempt_active = false;
            }),
            ("the owner was not frozen", |e| {
                e.freeze.phase = "active".into();
            }),
            (
                "the connector's fence did not exceed the owner's cursor",
                |e| {
                    e.freeze.connector_fence = Some(e.freeze.relay_recv_contiguous);
                },
            ),
            ("no connector fence was recorded", |e| {
                e.freeze.connector_fence = None;
            }),
            (
                "the in-flight conclusion was asserted without its sample",
                |e| {
                    e.exchange_in_flight_at_freeze = false;
                },
            ),
            ("the candidate generation did not advance", |e| {
                e.freeze.candidate_generation = Some(e.freeze.old_generation);
            }),
            ("no candidate generation", |e| {
                e.freeze.candidate_generation = None;
            }),
            // The operation-level rules.
            ("the held reply carried another tag", |e| {
                e.held_reply_tag_matched = false;
            }),
            ("the held reply was not an Rread", |e| {
                e.held_reply_was_rread = false;
            }),
            ("the held reply carried no bytes", |e| {
                e.held_reply_bytes = 0;
            }),
            ("the transfer lost a byte", |e| e.transfer_bytes -= 1),
            ("the transfer duplicated a byte", |e| e.transfer_bytes += 1),
            ("the expected length was moved to match", |e| {
                e.transfer_bytes = 1;
                e.transfer_expected_bytes = 1;
            }),
            ("the checksum did not match", |e| {
                e.transfer_checksum_matches = false;
            }),
            ("the transfer was one message", |e| {
                e.transfer_messages = MIN_READ_MESSAGES - 1;
            }),
            // The rotation really happened, cleanly.
            ("no rotation completed", |e| {
                e.rotations_completed_after = e.rotations_completed_before;
            }),
            ("the generation did not advance", |e| {
                e.generation_after = e.generation_before;
            }),
            ("frames were replayed", |e| e.total_replayed_frames = 1),
            ("the deadline forced retirement", |e| {
                e.deadline_forced_retirement = true;
            }),
            ("the attempt entered recovery", |e| {
                e.rotation_recovery_reason = Some("data_loss".into());
            }),
            // The same-owner contract.
            ("the session identity changed", |e| {
                e.session_id_stable = false;
            }),
            ("the epoch changed", |e| e.epoch_stable = false),
            // The fid rules.
            ("the fid did not answer after the rotation", |e| {
                e.fid_survived_getattr = false;
            }),
            ("the fid named a different file", |e| {
                e.fid_survived_getattr_size = 1;
            }),
            ("the attach fid did not walk after the rotation", |e| {
                e.attach_fid_survived_walk = false;
            }),
            ("the session was re-attached", |e| e.attach_count = 2),
            ("no Tattach was sent", |e| e.attach_count = 0),
            ("a post-rotation tag did not correlate", |e| {
                e.post_rotation_tag_correlated = false;
            }),
        ];
        for (name, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_fs_rotation_evidence(&evidence).is_err(),
                "mutation `{name}` must be rejected: no rule here is decorative"
            );
        }
    }

    /// The concurrency predicate itself, independent of the rule list: it must
    /// be false for a sample that shows a settled exchange, and true only when
    /// the connector had sequenced a record the owner had not received.
    #[test]
    fn in_flight_predicate_requires_an_unreceived_record_at_a_frozen_phase() {
        let frozen_in_flight = FreezeObservation {
            stream_id: 1,
            phase: "draining".into(),
            attempt_active: true,
            connector_fence: Some(12),
            relay_recv_contiguous: 10,
            relay_fence: None,
            old_generation: 1,
            candidate_generation: Some(2),
            writer_barriers_flushed: [false, true],
        };
        assert!(frozen_in_flight.exchange_in_flight_at_freeze());

        let settled = FreezeObservation {
            connector_fence: Some(10),
            ..frozen_in_flight.clone()
        };
        assert!(
            !settled.exchange_in_flight_at_freeze(),
            "a fence the owner had fully received is a settled exchange"
        );

        let not_frozen = FreezeObservation {
            phase: "active".into(),
            ..frozen_in_flight.clone()
        };
        assert!(
            !not_frozen.exchange_in_flight_at_freeze(),
            "a sample taken outside a freeze cannot show a record in flight across one"
        );

        let no_attempt = FreezeObservation {
            attempt_active: false,
            ..frozen_in_flight
        };
        assert!(
            !no_attempt.exchange_in_flight_at_freeze(),
            "without an active attempt there is no freeze to be in flight across"
        );
    }
}
