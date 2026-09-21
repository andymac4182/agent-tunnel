//! A live 9P2000.L filesystem session carried across **two real scheduled
//! data-socket rotations**, holding a **`Twrite`** across the first and a
//! **`Tflush`** across the second, over the real cluster: a consumer WSS
//! session through the owning relay's public route, the owner actor, the
//! device data WebSocket and `tunnel-client`'s filesystem export.
//!
//! # The clause
//!
//! `docs/protocol.md` requires that compatibility tests cover "reads/**writes**
//! spanning rotations", and M4-06 names tags, fids **and flush** through
//! rotation.  Gate 7 holds one `Rread` across a scheduled rotation and is the
//! worked example this gate follows.  What gate 7 does not do — and what no
//! gate in this repository did before this one — is span a rotation with
//! anything but a **read**: no `Twrite` and no `Tflush` had ever been
//! outstanding across one.  Those are this gate's two halves.
//!
//! # Why a write is harder than a read, and what that changes
//!
//! A read that spans an event is either answered or it is not, and the answer
//! is the whole of its effect.  **A write that spans an event may have
//! applied, and that is the entire point of the clause.**  So before the event
//! is fired the gate has to be able to tell "the bytes landed" from "the bytes
//! did not" **from outside the connector and outside its process**, or it
//! cannot classify anything afterwards.
//!
//! Gate 10 established the pattern and the reason: an in-memory ledger makes
//! "the count did not increase" true of nothing.  Its journal was the export's
//! own host directory, read by the harness directly, and its effect was a
//! **directory entry**.  A `Twrite`'s effect is bytes at an offset, so the
//! journal question is sharper — a region of a file always contains *some*
//! bytes, and "these are not the payload" is only a usable answer if the
//! bytes that were there before could never be mistaken for it.
//!
//! This gate buys that discrimination by construction rather than by
//! assumption:
//!
//! * the target file is seeded entirely with [`FILLER_BYTE`], which is zero;
//! * every payload byte is produced by [`payload_bytes`], which sets the high
//!   bit, so **no payload byte can ever be zero**;
//! * [`classify_region`] therefore has three answers and not two —
//!   [`RegionState::Untouched`] when every byte is still the filler,
//!   [`RegionState::Written`] when the region is exactly the payload, and
//!   [`RegionState::Torn`] for anything else.  A partially applied write is
//!   its own answer and is never folded into either of the other two.
//!
//! `payload_and_filler_can_never_be_confused` holds the disjointness directly,
//! so if the payload generator ever stopped setting the high bit the
//! discrimination would fail there rather than silently degrade here.
//!
//! **Both directions are observed in the same run**, which is what stops the
//! journal being a rule that can only ever say one thing:
//!
//! * the held region is read **before** the `Twrite` is sent and must be
//!   `Untouched` — the negative direction;
//! * a prefix `Twrite` is performed and acknowledged normally first, and its
//!   region must read back `Written` — the positive direction, established
//!   before anything is perturbed.
//!
//! # What this gate may claim about "exactly once", and what it may not
//!
//! A 9P `Twrite` carries an **explicit offset**.  Applying the identical frame
//! twice is therefore byte-for-byte idempotent, and no amount of reading the
//! host file can distinguish one application from two.  Saying otherwise would
//! be evidence that proves less than it claims, so this gate does not say it.
//!
//! What it does say, and what the host image genuinely defeats, is that **no
//! byte outside the two written regions changed**: the whole file is
//! checksummed against the exact expected image and its length is exact, so a
//! frame replayed at any other offset — the realistic way a rotation could
//! duplicate an effect — shows up.  Alongside it the owner's own
//! `total_replayed_frames` must be zero, which is the relay's record that no
//! frame was replayed at all.  Together those are the honest content of
//! "once"; the idempotent-same-offset case is stated here as out of reach
//! rather than quietly counted as proven.
//!
//! # Why the outcome here is not `Outcome::Unknown`
//!
//! Gate 10 derived [`tunnel_fs_core::Outcome::Unknown`] from "the journal says
//! performed, and the exchange carried no answer", because a `SIGKILL`
//! destroys the answer.  **A scheduled rotation is lossless**, and the whole
//! contract of this event is that the held exchange completes across it.  So
//! the classification this gate derives is the opposite one, and it is derived
//! from the same two facts rather than asserted:
//! [`FsRotationWriteEvidence::held_write_ambiguous`] is
//! `journal showed the effect && no answer arrived`, and the validator
//! requires it to be **false** — a clean scheduled rotation must leave no
//! ambiguous write behind.  Had the answer been lost the derivation would flip
//! and the gate would fail, which is what makes the rule defeatable rather than
//! decorative.  Mapping this run's success onto an `Outcome` variant would be a
//! misuse: `Outcome` spells `NotStarted`, `Failed`, `Partial` and `Unknown`,
//! and none of them means "performed and acknowledged".
//!
//! # The `Tflush` half
//!
//! For a flush the question is different again: a flush across a rotation is
//! about whether **the flushed tag is still correctly suppressed afterwards**.
//! The construction is gate 4's pipelined flush — [`FLUSH_PIPELINE_DEPTH`]
//! full-`msize` reads queued ahead of a victim read so the `Tflush` is
//! readable long before the device reaches its victim — with the rotation
//! placed underneath it: the `Rflush` is sequenced into the **paused**
//! direction, so it is outstanding across the freeze exactly as the `Rwrite`
//! was.  After the second rotation commits, the assertion is the one a client
//! can actually see: the `Rflush` came back on its own tag, and **no reply
//! carrying the flushed tag ever arrived** — not before its `Rflush`, not
//! after it, and not resurrected by the generation change.
//!
//! # Concurrency is proven from the owner's own cursors, never from timing
//!
//! Both halves use gate 7's construction and gate 7's predicate, on gate 7's
//! own [`FreezeObservation`]: the device data socket's **connector→relay**
//! bytes are paused at the harness TCP proxy once the carrier has settled, one
//! request is sent and its reply never read, and the owner is sampled at a
//! frozen phase with an attempt active.  The proof that the exchange was in
//! flight when the attempt's fences were fixed is
//! `connector_fence_sequences[stream] > recv_contiguous_connector_to_relay`
//! for this stream — the owner's own record, not a timestamp comparison.
//!
//! All fixture content is synthetic and generated here; no evidence field
//! carries a path, a name or file content.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use tokio::time::{sleep, timeout};
use tunnel_client::{
    ConnectOptions, FsExportSettings, LocalExport, LocalExportKind, http_forward::HttpHandlers,
};
use tunnel_core::RotationConfig;
use tunnel_fs_ninep::{
    Message,
    flags::{O_RDONLY, O_RDWR},
};
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot};
use uuid::Uuid;

use super::fs_wire as wire;
use wire::{NinepClient, Target, UpgradeFailure, unexpected};

use super::{
    CLEANUP_TIMEOUT, FreezeObservation, ProductionCluster, RunningHarness, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::{
    ConnectionId, Direction as ProxyDirection, Harness, HarnessError, HarnessOptions, ProxyConfig,
    ProxyHandle, Result, TcpProxy,
};

/// The subprotocol the server must select.
const SUBPROTOCOL: &str = tunnel_fs_core::TRANSPORT_SUBPROTOCOL;
/// The dialect `Rversion` must name.
const DIALECT: &str = tunnel_fs_ninep::DIALECT;
/// The `msize` the gate offers, which is also the profile ceiling.
const OFFERED_MSIZE: u32 = tunnel_fs_ninep::MAX_MESSAGE_BYTES;
/// The largest `count` an `Rread` can answer under [`OFFERED_MSIZE`].
const READ_COUNT: u32 = OFFERED_MSIZE - tunnel_fs_ninep::COUNTED_REPLY_OVERHEAD;

/// The byte the target file is seeded with, everywhere.
///
/// Zero, and [`payload_bytes`] never produces a zero, so "still the filler"
/// and "the payload landed" can never be confused.  That disjointness is the
/// whole basis of this gate's outside-the-connector classification and is held
/// directly by `payload_and_filler_can_never_be_confused`.
const FILLER_BYTE: u8 = 0x00;

/// The seeded size of the file both writes land in.
///
/// Large enough that the two written regions are far apart and most of the
/// file is filler either side of them, so a frame replayed at a wrong offset
/// has somewhere to show up.
const TARGET_FILE_BYTES: usize = 262_144;
/// Where the prefix write lands: the positive direction of the journal, taken
/// before anything is perturbed.
const PREFIX_OFFSET: u64 = 0;
/// How many bytes the prefix write carries.
const PREFIX_PAYLOAD_BYTES: usize = 4_096;
/// Where the write held across the first rotation lands.
///
/// Well past the prefix region and well short of the end, so neither the
/// prefix write nor a short file could account for it.
const HELD_OFFSET: u64 = 131_072;
/// How many bytes the held write carries.
///
/// One `Twrite` under the negotiated `msize`, so the whole mutation is a
/// single frame and "the bytes landed" is not confounded by a multi-frame
/// transfer that could legitimately be half applied.
const HELD_PAYLOAD_BYTES: usize = 32_768;

/// How many full-`msize` reads the flush half queues ahead of its victim.
///
/// Gate 4's figure and gate 4's reason: the device admits every frame that is
/// already readable before it performs a queued request, so with a single
/// outstanding `Tread` the flush is still on the wire when the device performs
/// the victim and the victim's reply wins every time on a loopback cluster.
/// Queueing several 64 KiB reads first means the device has to perform, encode
/// and send each of those — real work, not a sleep — before it reaches the
/// victim, by which time the `Tflush` is long readable.
const FLUSH_PIPELINE_DEPTH: usize = 8;

/// A short scheduled-rotation policy with enough overlap to hold a freeze.
///
/// Gate 7's shape: `0 < handshake_timeout < overlap < interval`, with an
/// overlap long enough that a held freeze is released well inside the
/// deadline.  This gate holds **two** freezes, so the interval matters twice:
/// the second attempt is the next scheduled one after the first commits.
const GATE_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 6,
    handshake_timeout_seconds: 2,
    overlap_seconds: 5,
};

/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for a cluster state change.
const WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for the host directory to show an effect.
const JOURNAL_WAIT: Duration = Duration::from_secs(30);
/// The poll interval for every bounded wait here.
const POLL: Duration = Duration::from_millis(20);
/// The whole scenario's bound.  Two scheduled rotations rather than one, so
/// this is wider than gate 7's.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(420);

/// What the host directory says about one region of the target file.
///
/// Read by the harness from the export's own host directory, so it is
/// independent of the connector, of the relay and of the 9P session — which is
/// what makes it usable to classify a mutation whose answer has not arrived.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RegionState {
    /// The file could not be read at all, or is shorter than the region.
    #[default]
    Unreadable,
    /// Every byte in the region is still [`FILLER_BYTE`].
    Untouched,
    /// The region is exactly the expected payload.
    Written,
    /// Neither: some of the payload is there and some is not.
    Torn,
}

impl RegionState {
    /// The stable spelling, for the command's evidence line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::Untouched => "untouched",
            Self::Written => "written",
            Self::Torn => "torn",
        }
    }
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsRotationWriteEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    /// The negotiated session parameters, so a run cannot pass on a session
    /// that never reached 9P.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub negotiated_dialect: String,

    // ---- The journal's two directions, established before the event. ----
    /// The held region as the host directory saw it **before** the held
    /// `Twrite` was sent.  Must be [`RegionState::Untouched`]: the negative
    /// direction of the discrimination.
    pub held_region_before_send: RegionState,
    /// The prefix region after a normal acknowledged `Twrite`.  Must be
    /// [`RegionState::Written`]: the positive direction.
    pub prefix_region_after_write: RegionState,
    /// Bytes the prefix `Twrite` acknowledged on the wire.
    pub prefix_acknowledged_bytes: usize,

    // ---- The write held across the first rotation. ----
    /// The held region as the host directory saw it **before the freeze**.
    /// This is what makes the mutation "dispatched and performed" rather than
    /// "perhaps never delivered", and it is read from outside the connector.
    pub held_region_before_freeze: RegionState,
    /// The owner's sample at the first held freeze.
    pub write_freeze: FreezeObservation,
    /// Whether that sample proves the write was in flight across the freeze.
    pub write_exchange_in_flight_at_freeze: bool,
    /// How many polls the first freeze took to observe, for diagnosis only.
    pub write_freeze_polls: usize,
    /// The tag the held `Twrite` carried.
    pub held_write_tag: u16,
    /// Whether the reply that arrived after the rotation carried that tag.
    pub held_write_reply_tag_matched: bool,
    /// Whether that reply was an `Rwrite` rather than an error or a close.
    pub held_write_reply_was_rwrite: bool,
    /// The byte count that `Rwrite` acknowledged.
    pub held_write_acknowledged_bytes: usize,
    /// Whether an answer for the held write arrived at all.
    pub held_write_answered: bool,
    /// Derived, not asserted: the journal showed the effect **and** no answer
    /// arrived.  Must be false across a clean scheduled rotation.
    pub held_write_ambiguous: bool,
    /// The held region as the host directory saw it **after** the rotation
    /// committed.
    pub held_region_after_rotation: RegionState,

    // ---- The whole-file image, after both writes and both rotations. ----
    pub image_bytes: usize,
    pub image_expected_bytes: usize,
    /// Whether the whole host file equals the exact expected image: filler
    /// everywhere except the two written regions.
    pub image_checksum_matches: bool,

    // ---- The flush held across the second rotation. ----
    /// The owner's sample at the second held freeze.
    pub flush_freeze: FreezeObservation,
    /// Whether that sample proves the flush exchange was in flight across it.
    pub flush_exchange_in_flight_at_freeze: bool,
    pub flush_freeze_polls: usize,
    /// The tag the `Tflush` itself carried.
    pub flush_tag: u16,
    /// The tag the `Tflush` named as its victim.
    pub flushed_victim_tag: u16,
    /// Whether the `Rflush` came back on the flush's own tag.
    pub rflush_observed: bool,
    /// Whether **any** reply carrying the flushed tag was seen, before its
    /// `Rflush` or after it.  Must be false.
    pub flushed_victim_reply_observed: bool,
    /// Replies for the flushed tag seen **after** its `Rflush`.  Must be zero.
    pub flushed_replies_after_rflush: usize,
    /// How many of the pipelined reads queued ahead of the victim were
    /// answered.  Must be all of them: a flush that took the queue with it
    /// would be cancelling more than its victim.
    pub flush_pipeline_replies: usize,

    // ---- Rotation accounting from the owner, across both attempts. ----
    pub rotations_completed_before: u64,
    pub rotations_completed_after_write: u64,
    pub rotations_completed_after_flush: u64,
    pub generation_before: u64,
    pub generation_after: u64,
    /// The control epoch before and after.  A scheduled rotation changes the
    /// data generation and never the control epoch.
    pub epoch_before: u64,
    pub epoch_after: u64,
    /// A clean rotation replays nothing.
    pub total_replayed_frames: u64,
    /// Neither rotation may have been forced into recovery.
    pub deadline_forced_retirement: bool,
    pub rotation_recovery_reason: Option<String>,

    // ---- The same-owner contract and the fid rules. ----
    pub session_id_stable: bool,
    pub epoch_stable: bool,
    /// The fid opened before either rotation still answered a read after both.
    pub fid_survived_read: bool,
    /// A read taken on that fid, back over the held region, matched the
    /// payload — the effect is visible **through the session** as well as in
    /// the host directory.
    pub fid_read_back_matches_payload: bool,
    /// A fresh tag allocated after the rotations correlated correctly.
    pub post_rotation_tag_correlated: bool,
    /// The session was never re-attached: exactly one `Tattach` was sent.
    pub attach_count: usize,
}

impl FsRotationWriteEvidence {
    /// Whether the host directory discriminated a written region from an
    /// untouched one **in this run**, in both directions.
    ///
    /// Without both, the journal is a rule that can only ever say one thing
    /// and the classification of the held write rests on nothing.
    ///
    /// **Written as an array rather than as a `&&` chain, and that is
    /// load-bearing**, for gate 11's reason: as a chain the head conjunct
    /// carries no `&&` and so does not match the one edit shape the
    /// guard-deletion suite keys on, which leaves exactly one conjunct the
    /// suite cannot defeat.  Every element here has an identical shape, so
    /// `every_journal_direction_defeats_the_discrimination_on_its_own` fails if
    /// any of them stops mattering.
    #[must_use]
    pub fn journal_discriminated_both_directions(&self) -> bool {
        let directions = [
            self.held_region_before_send == RegionState::Untouched,
            self.prefix_region_after_write == RegionState::Written,
            self.prefix_acknowledged_bytes == PREFIX_PAYLOAD_BYTES,
        ];
        directions.into_iter().all(|held| held)
    }

    /// Whether the held write was **dispatched and performed** before the
    /// rotation froze, as seen from outside the connector.
    #[must_use]
    pub fn held_write_performed_before_freeze(&self) -> bool {
        self.held_region_before_freeze == RegionState::Written
    }
}

/// Validate every rule; the first violated rule is named.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_fs_rotation_write_evidence(evidence: &FsRotationWriteEvidence) -> Result<()> {
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
        // The journal has to be able to say both things before anything it
        // says about the held write means anything.
        (
            "the host directory discriminated a written region from an untouched \
             one, in both directions, before the event"
                .into(),
            evidence.journal_discriminated_both_directions(),
        ),
        // The concurrency rules for the write half.
        (
            "a rotation attempt was active when the owner was sampled for the write".into(),
            evidence.write_freeze.attempt_active,
        ),
        (
            "the connector's fence covered a record the owner had not received: \
             the Twrite was in flight when the first attempt's fences were fixed"
                .into(),
            evidence.write_exchange_in_flight_at_freeze
                && evidence.write_freeze.exchange_in_flight_at_freeze(),
        ),
        (
            "the first attempt named a candidate generation above the old one".into(),
            evidence
                .write_freeze
                .candidate_generation
                .is_some_and(|candidate| candidate > evidence.write_freeze.old_generation),
        ),
        // The write's effect, seen from outside the connector.
        (
            "the host directory showed the held write performed before the freeze".into(),
            evidence.held_write_performed_before_freeze(),
        ),
        (
            "the held write's effect was whole rather than torn".into(),
            evidence.held_region_before_freeze != RegionState::Torn,
        ),
        // The operation-level rules for the write half.
        (
            "the reply held across the first rotation carried the tag that was outstanding".into(),
            evidence.held_write_reply_tag_matched,
        ),
        (
            "the reply held across the first rotation was an Rwrite".into(),
            evidence.held_write_reply_was_rwrite,
        ),
        (
            "the Rwrite acknowledged exactly the bytes the Twrite carried".into(),
            evidence.held_write_acknowledged_bytes == HELD_PAYLOAD_BYTES,
        ),
        (
            "the held write was answered".into(),
            evidence.held_write_answered,
        ),
        // The derived classification.  A lossless scheduled rotation must not
        // leave a mutation whose outcome a caller cannot settle.
        (
            "a clean scheduled rotation left no ambiguous write".into(),
            !evidence.held_write_ambiguous,
        ),
        (
            "the held write's effect was still whole after the rotation committed".into(),
            evidence.held_region_after_rotation == RegionState::Written,
        ),
        // The whole-file image: nothing landed anywhere it should not have.
        (
            "the host file was exactly its seeded length".into(),
            evidence.image_bytes == evidence.image_expected_bytes
                && evidence.image_expected_bytes == TARGET_FILE_BYTES,
        ),
        (
            "no byte outside the two written regions changed".into(),
            evidence.image_checksum_matches,
        ),
        // The concurrency rules for the flush half.
        (
            "a rotation attempt was active when the owner was sampled for the flush".into(),
            evidence.flush_freeze.attempt_active,
        ),
        (
            "the connector's fence covered a record the owner had not received: \
             the flush exchange was in flight when the second attempt's fences were fixed"
                .into(),
            evidence.flush_exchange_in_flight_at_freeze
                && evidence.flush_freeze.exchange_in_flight_at_freeze(),
        ),
        (
            "the second attempt named a candidate generation above the old one".into(),
            evidence
                .flush_freeze
                .candidate_generation
                .is_some_and(|candidate| candidate > evidence.flush_freeze.old_generation),
        ),
        // The operation-level rules for the flush half.
        (
            "the flush held across the second rotation was answered on its own tag".into(),
            evidence.rflush_observed,
        ),
        (
            "the flush named a victim other than itself".into(),
            evidence.flushed_victim_tag != evidence.flush_tag,
        ),
        (
            "the flushed tag was never answered at all, across the rotation".into(),
            !evidence.flushed_victim_reply_observed,
        ),
        (
            "no reply for the flushed tag followed its Rflush".into(),
            evidence.flushed_replies_after_rflush == 0,
        ),
        (
            "the flush cancelled its victim and nothing else: every pipelined \
             read queued ahead of it was still answered"
                .into(),
            evidence.flush_pipeline_replies == FLUSH_PIPELINE_DEPTH,
        ),
        // Both rotations really completed, cleanly.
        (
            "a scheduled rotation completed while the write was held".into(),
            evidence.rotations_completed_after_write > evidence.rotations_completed_before,
        ),
        (
            "a second scheduled rotation completed while the flush was held".into(),
            evidence.rotations_completed_after_flush > evidence.rotations_completed_after_write,
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
            "neither rotation was forced into recovery by its deadline".into(),
            !evidence.deadline_forced_retirement && evidence.rotation_recovery_reason.is_none(),
        ),
        // The same-owner contract of docs/protocol.md.
        (
            "the session identity was unchanged across both rotations".into(),
            evidence.session_id_stable,
        ),
        (
            "the session epoch was unchanged across both rotations".into(),
            evidence.epoch_stable,
        ),
        // The fid rules of docs/protocol.md.
        (
            "the fid opened before the rotations still answered after them".into(),
            evidence.fid_survived_read,
        ),
        (
            "that fid read the held write's bytes back".into(),
            evidence.fid_read_back_matches_payload,
        ),
        (
            "the relay did not reconstruct the session: exactly one Tattach was sent".into(),
            evidence.attach_count == 1,
        ),
        (
            "a tag allocated after the rotations correlated correctly".into(),
            evidence.post_rotation_tag_correlated,
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "fs rotation write gate failed: {rule}"
            )));
        }
    }
    Ok(())
}

/// Deterministic synthetic payload with the high bit always set.
///
/// Byte `i` is `((i % 251) | 0x80)`.  251 is prime and below 256, so the
/// pattern does not align with any power of two the transport uses and a
/// dropped or duplicated block changes the checksum; the high bit is what
/// makes every byte differ from [`FILLER_BYTE`], which is the property
/// [`classify_region`] depends on.
fn payload_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|index| ((index % 251) as u8) | 0x80).collect()
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

/// Classify one region of the target file against the payload it should hold.
///
/// Three answers, not two: a partially applied write is [`RegionState::Torn`]
/// and is never folded into either of the others.
fn classify_region(image: &[u8], offset: u64, payload: &[u8]) -> RegionState {
    let Ok(start) = usize::try_from(offset) else {
        return RegionState::Unreadable;
    };
    let Some(end) = start.checked_add(payload.len()) else {
        return RegionState::Unreadable;
    };
    let Some(region) = image.get(start..end) else {
        return RegionState::Unreadable;
    };
    if region == payload {
        RegionState::Written
    } else if region.iter().all(|byte| *byte == FILLER_BYTE) {
        RegionState::Untouched
    } else {
        RegionState::Torn
    }
}

/// Read the export's own host file directly, from the harness.
///
/// This is the journal: it is the connector's only durable effect surface, it
/// is read without going through the connector, the relay or the 9P session,
/// and it is therefore usable to classify a mutation whose answer has not
/// arrived.
fn read_host_image(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

/// The expected whole-file image after both writes: filler everywhere except
/// the two written regions.
fn expected_image() -> Vec<u8> {
    let mut image = vec![FILLER_BYTE; TARGET_FILE_BYTES];
    let prefix = payload_bytes(PREFIX_PAYLOAD_BYTES);
    let held = payload_bytes(HELD_PAYLOAD_BYTES);
    let prefix_start = PREFIX_OFFSET as usize;
    image[prefix_start..prefix_start + prefix.len()].copy_from_slice(&prefix);
    let held_start = HELD_OFFSET as usize;
    image[held_start..held_start + held.len()].copy_from_slice(&held);
    image
}

/// Run the gate: start the cluster, hold a write and a flush across two
/// scheduled rotations, and validate the evidence.
///
/// # Errors
/// Any harness, cluster or validation failure.
pub async fn verify() -> Result<FsRotationWriteEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("fs rotation write harness startup timed out".into())
        })??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result.and_then(|evidence| {
            validate_fs_rotation_write_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs rotation write scenario exceeded its bounded deadline".into(),
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
) -> Result<FsRotationWriteEvidence> {
    let mut evidence = FsRotationWriteEvidence {
        relay_count: cluster.relays.len(),
        image_expected_bytes: TARGET_FILE_BYTES,
        ..FsRotationWriteEvidence::default()
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
        .fs_service("rotation-write")
        .ok_or_else(|| {
            HarnessError::InvalidInput("the rotation-write filesystem export was not seeded".into())
        })?
        .service_id;

    // The export's host directory.  The target file is seeded entirely with
    // the filler byte, so every later reading of it is a statement about what
    // this session did and nothing else.
    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let target_path = directory.path().join("target.bin");
    std::fs::write(&target_path, vec![FILLER_BYTE; TARGET_FILE_BYTES]).map_err(HarnessError::Io)?;

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
        "m4-fs-rotation-write-canary",
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
                capabilities: vec!["read".to_owned(), "write".to_owned(), "list".to_owned()],
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
    .map_err(|_| HarnessError::Timeout("fs rotation write device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("fs rotation write device: {error}")))?;

    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| {
                HarnessError::Timeout("fs rotation write device readiness timed out".into())
            })?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        exercise(
            cluster,
            harness,
            &proxy,
            &client,
            &target_path,
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
            "fs rotation write device phase: {:?}",
            client.status_snapshot().phase
        );
        eprintln!("fs rotation write partial evidence: {evidence:?}");
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

/// Settle the carrier and return the data socket's proxy connection id.
async fn settled_data_connection(
    client: &tunnel_client::ConnectionHandle,
    proxy: &ProxyHandle,
) -> Result<ConnectionId> {
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
            return Ok(data.id);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "the device carrier never settled before a held exchange".into(),
            ));
        }
        sleep(POLL).await;
    }
}

/// Wait for the owner to freeze with a record this stream's connector had
/// sequenced and the owner had not received, and sample it.
///
/// Gate 7's construction and gate 7's predicate.  Only a sample that actually
/// shows the record outstanding ends the wait: a freeze observed before the
/// connector's fence was exchanged is not yet the evidence.
async fn wait_for_held_freeze(
    cluster: &ProductionCluster,
    session_id: &str,
    stream_id: u64,
    proxy: &ProxyHandle,
    connection: ConnectionId,
    label: &str,
) -> Result<(FreezeObservation, usize)> {
    let deadline = Instant::now()
        + Duration::from_secs((GATE_ROTATION.interval_seconds + GATE_ROTATION.overlap_seconds) * 2);
    let mut polls = 0_usize;
    let mut phases: Vec<String> = Vec::new();
    loop {
        polls += 1;
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
        if phases.last() != Some(&owner.phase) {
            phases.push(owner.phase.clone());
        }
        if let Some(rotation) = owner.rotation_diagnostics.as_ref()
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
            if observation.exchange_in_flight_at_freeze() {
                return Ok((observation, polls));
            }
        }
        if Instant::now() >= deadline {
            // Release before failing so cleanup is not wedged.
            let _ = proxy
                .resume(ProxyDirection::ClientToTarget, connection)
                .await;
            return Err(HarnessError::Process(format!(
                "no freeze was observed with the {label} exchange in flight: phases {phases:?}"
            )));
        }
        sleep(POLL).await;
    }
}

/// Wait for a scheduled rotation to complete past `completed_before`.
async fn wait_rotation_completed(
    cluster: &ProductionCluster,
    session_id: &str,
    completed_before: u64,
) -> Result<u64> {
    let deadline = Instant::now() + WAIT;
    loop {
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
        if owner.rotations_completed > completed_before && owner.phase == "active" {
            return Ok(owner.rotations_completed);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "a held rotation attempt never completed".into(),
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
    target_path: &Path,
    tenant_id: Uuid,
    device_id: Uuid,
    service: Uuid,
    session_id: &str,
    evidence: &mut FsRotationWriteEvidence,
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

    match session.walk(ATTACH_FID, FILE_FID, &["target.bin"]).await? {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match session.lopen(FILE_FID, O_RDWR).await? {
        Message::Rlopen { .. } => {}
        other => return Err(unexpected("Rlopen", &other)),
    }

    let stream_id = wait_fs_stream(cluster, session_id).await?;

    let prefix_payload = payload_bytes(PREFIX_PAYLOAD_BYTES);
    let held_payload = payload_bytes(HELD_PAYLOAD_BYTES);

    // The journal's **negative** direction, taken before the held write is
    // sent: the region it will land in is still untouched filler.
    evidence.held_region_before_send =
        classify_region(&read_host_image(target_path), HELD_OFFSET, &held_payload);

    // The journal's **positive** direction: one normal acknowledged Twrite,
    // performed before anything is perturbed, whose bytes the harness then
    // reads straight out of the export's own host directory.  A later failure
    // cannot be blamed on a session that never wrote, and a journal that could
    // only ever say "untouched" is ruled out here.
    match session
        .call(Message::Twrite {
            fid: FILE_FID,
            offset: PREFIX_OFFSET,
            data: prefix_payload.clone(),
        })
        .await?
    {
        Message::Rwrite { count } => evidence.prefix_acknowledged_bytes = count as usize,
        other => return Err(unexpected("Rwrite", &other)),
    }
    evidence.prefix_region_after_write = classify_region(
        &read_host_image(target_path),
        PREFIX_OFFSET,
        &prefix_payload,
    );

    // Rotation accounting before the first attempt this gate holds.
    {
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
        evidence.rotations_completed_before = owner.rotations_completed;
        evidence.generation_before = owner.active_generation;
        evidence.epoch_before = owner.epoch;
    }

    // ---------------- The write half ----------------

    // Settle the carrier and pause the data socket's connector→relay bytes.
    // The control socket and the candidate stay untouched.
    let connection = settled_data_connection(client, proxy).await?;
    proxy
        .pause(ProxyDirection::ClientToTarget, connection)
        .await?;

    // Send one Twrite and deliberately do not read its reply.  The request
    // crosses on the still-flowing relay→connector direction; the device
    // performs it and sequences the Rwrite into the paused socket.
    evidence.held_write_tag = session
        .send(Message::Twrite {
            fid: FILE_FID,
            offset: HELD_OFFSET,
            data: held_payload.clone(),
        })
        .await?;

    // Wait for the **host directory** to show the write performed, before the
    // freeze.  This is gate 10's discipline and it is not optional: without it
    // the rotation could freeze before the write reached the device, and the
    // gate would then be measuring an undispatched request — a different and
    // far weaker claim.
    {
        let deadline = Instant::now() + JOURNAL_WAIT;
        loop {
            let state = classify_region(&read_host_image(target_path), HELD_OFFSET, &held_payload);
            if state == RegionState::Written {
                evidence.held_region_before_freeze = state;
                break;
            }
            if Instant::now() >= deadline {
                evidence.held_region_before_freeze = state;
                let _ = proxy
                    .resume(ProxyDirection::ClientToTarget, connection)
                    .await;
                return Err(HarnessError::Process(format!(
                    "the host directory never showed the held write performed: {}",
                    state.as_str()
                )));
            }
            sleep(POLL).await;
        }
    }

    let (write_freeze, write_polls) =
        wait_for_held_freeze(cluster, session_id, stream_id, proxy, connection, "Twrite").await?;
    evidence.write_exchange_in_flight_at_freeze = write_freeze.exchange_in_flight_at_freeze();
    evidence.write_freeze = write_freeze;
    evidence.write_freeze_polls = write_polls;

    // Release the bytes.  The drain completes and the attempt commits.
    proxy
        .resume(ProxyDirection::ClientToTarget, connection)
        .await?;

    // The reply that was outstanding across the freeze.
    let held = session.recv_frame().await?;
    evidence.held_write_reply_tag_matched = held.tag == evidence.held_write_tag;
    match held.message {
        Message::Rwrite { count } => {
            evidence.held_write_reply_was_rwrite = true;
            evidence.held_write_acknowledged_bytes = count as usize;
            evidence.held_write_answered = true;
        }
        other => return Err(unexpected("the held Rwrite", &other)),
    }
    // Derived from what the wire and the host directory actually did, not
    // asserted: the effect was performed, and an answer either arrived or did
    // not.  Across a lossless scheduled rotation it must arrive.
    evidence.held_write_ambiguous =
        evidence.held_write_performed_before_freeze() && !evidence.held_write_answered;

    evidence.rotations_completed_after_write =
        wait_rotation_completed(cluster, session_id, evidence.rotations_completed_before).await?;
    evidence.held_region_after_rotation =
        classify_region(&read_host_image(target_path), HELD_OFFSET, &held_payload);

    // ---------------- The flush half ----------------

    // The same construction, on the next scheduled attempt.  The carrier has
    // to settle again first: the generation that was the candidate is now the
    // active one, and the proxy connection for it is a different socket.
    let flush_connection = settled_data_connection(client, proxy).await?;
    proxy
        .pause(ProxyDirection::ClientToTarget, flush_connection)
        .await?;

    // Gate 4's pipelined flush, with the rotation placed underneath it.  Every
    // read below is the same full-`msize` slice, because what they are for is
    // the host work they cost: the device has to perform, encode and send each
    // of them before it reaches the victim, by which time the `Tflush` is long
    // readable.
    let mut pending: BTreeSet<u16> = BTreeSet::new();
    for _ in 0..FLUSH_PIPELINE_DEPTH {
        let tag = session
            .send(Message::Tread {
                fid: FILE_FID,
                offset: 0,
                count: READ_COUNT,
            })
            .await?;
        pending.insert(tag);
    }
    // Sent last, so it is the last request in the device's queue and every
    // read above stands between it and the dispatcher.
    let victim = session
        .send(Message::Tread {
            fid: FILE_FID,
            offset: 0,
            count: READ_COUNT,
        })
        .await?;
    evidence.flushed_victim_tag = victim;
    evidence.flush_tag = session.send(Message::Tflush { oldtag: victim }).await?;

    let (flush_freeze, flush_polls) = wait_for_held_freeze(
        cluster,
        session_id,
        stream_id,
        proxy,
        flush_connection,
        "Tflush",
    )
    .await?;
    evidence.flush_exchange_in_flight_at_freeze = flush_freeze.exchange_in_flight_at_freeze();
    evidence.flush_freeze = flush_freeze;
    evidence.flush_freeze_polls = flush_polls;

    proxy
        .resume(ProxyDirection::ClientToTarget, flush_connection)
        .await?;

    // Read until the `Rflush` and every pipelined read have been answered, and
    // no further.  Bounding it this way rather than by a fixed count leaves
    // the socket in step either way, so a failure is reported by the rule it
    // violated instead of by the next reply landing on the wrong tag.
    let mut seen_rflush = false;
    let mut replies_after = 0_usize;
    let expected_pipeline = pending.len();
    while !seen_rflush || !pending.is_empty() {
        let frame = session.recv_frame().await?;
        if frame.tag == evidence.flush_tag {
            if !matches!(frame.message, Message::Rflush) {
                return Err(unexpected("Rflush", &frame.message));
            }
            seen_rflush = true;
        } else if frame.tag == victim {
            evidence.flushed_victim_reply_observed = true;
            if seen_rflush {
                replies_after += 1;
            }
        } else if !pending.remove(&frame.tag) {
            return Err(HarnessError::Process(
                "a reply arrived for a tag that was never sent".into(),
            ));
        }
    }
    evidence.rflush_observed = seen_rflush;
    evidence.flushed_replies_after_rflush = replies_after;
    evidence.flush_pipeline_replies = expected_pipeline;

    evidence.rotations_completed_after_flush = wait_rotation_completed(
        cluster,
        session_id,
        evidence.rotations_completed_after_write,
    )
    .await?;

    // ---------------- After both rotations ----------------

    // The whole host image: filler everywhere except the two written regions.
    // This is what defeats a frame replayed at some other offset.  From here
    // on every exchange is serial again, and the client refuses a reply
    // carrying any tag but the one it just sent, so a late reply for the
    // flushed tag would fail the very next call rather than pass unnoticed.
    let image = read_host_image(target_path);
    evidence.image_bytes = image.len();
    evidence.image_checksum_matches = fnv1a(&image) == fnv1a(&expected_image());

    // The fid opened before either rotation still answers, and reads the held
    // write's own bytes back: the effect is visible through the session as
    // well as in the host directory.
    match session
        .read(FILE_FID, HELD_OFFSET, HELD_PAYLOAD_BYTES as u32)
        .await?
    {
        Message::Rread { data } => {
            evidence.fid_survived_read = true;
            evidence.fid_read_back_matches_payload = data == held_payload;
        }
        other => return Err(unexpected("Rread", &other)),
    }

    // A tag allocated after the rotations correlates correctly.  `call`
    // refuses a reply whose tag is not the one it sent, so a clean Rclunk on a
    // freshly walked fid is the correlation.
    const POST_FID: u32 = 2;
    match session.walk(ATTACH_FID, POST_FID, &["target.bin"]).await? {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match session.lopen(POST_FID, O_RDONLY).await? {
        Message::Rlopen { .. } => {}
        other => return Err(unexpected("Rlopen", &other)),
    }
    match session.clunk(POST_FID).await? {
        Message::Rclunk => evidence.post_rotation_tag_correlated = true,
        other => return Err(unexpected("Rclunk", &other)),
    }

    // Final rotation accounting and the same-owner contract.
    {
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
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
    fn passing() -> FsRotationWriteEvidence {
        FsRotationWriteEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: 65_536,
            negotiated_dialect: DIALECT.into(),
            held_region_before_send: RegionState::Untouched,
            prefix_region_after_write: RegionState::Written,
            prefix_acknowledged_bytes: PREFIX_PAYLOAD_BYTES,
            held_region_before_freeze: RegionState::Written,
            write_freeze: FreezeObservation {
                stream_id: 1,
                phase: "quiescing".into(),
                attempt_active: true,
                connector_fence: Some(9),
                relay_recv_contiguous: 8,
                relay_fence: None,
                old_generation: 1,
                candidate_generation: Some(2),
                writer_barriers_flushed: [false, true],
            },
            write_exchange_in_flight_at_freeze: true,
            write_freeze_polls: 131,
            held_write_tag: 4,
            held_write_reply_tag_matched: true,
            held_write_reply_was_rwrite: true,
            held_write_acknowledged_bytes: HELD_PAYLOAD_BYTES,
            held_write_answered: true,
            held_write_ambiguous: false,
            held_region_after_rotation: RegionState::Written,
            image_bytes: TARGET_FILE_BYTES,
            image_expected_bytes: TARGET_FILE_BYTES,
            image_checksum_matches: true,
            flush_freeze: FreezeObservation {
                stream_id: 1,
                phase: "draining".into(),
                attempt_active: true,
                connector_fence: Some(21),
                relay_recv_contiguous: 15,
                relay_fence: None,
                old_generation: 2,
                candidate_generation: Some(3),
                writer_barriers_flushed: [false, true],
            },
            flush_exchange_in_flight_at_freeze: true,
            flush_freeze_polls: 96,
            flush_tag: 15,
            flushed_victim_tag: 14,
            rflush_observed: true,
            flushed_victim_reply_observed: false,
            flushed_replies_after_rflush: 0,
            flush_pipeline_replies: FLUSH_PIPELINE_DEPTH,
            rotations_completed_before: 0,
            rotations_completed_after_write: 1,
            rotations_completed_after_flush: 2,
            generation_before: 1,
            generation_after: 3,
            epoch_before: 1,
            epoch_after: 1,
            total_replayed_frames: 0,
            deadline_forced_retirement: false,
            rotation_recovery_reason: None,
            session_id_stable: true,
            epoch_stable: true,
            fid_survived_read: true,
            fid_read_back_matches_payload: true,
            post_rotation_tag_correlated: true,
            attach_count: 1,
        }
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_fs_rotation_write_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsRotationWriteEvidence));
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
            // The journal's two directions.
            ("the held region was not untouched before the write", |e| {
                e.held_region_before_send = RegionState::Written;
            }),
            ("the held region was unreadable before the write", |e| {
                e.held_region_before_send = RegionState::Unreadable;
            }),
            (
                "the prefix write left no trace in the host directory",
                |e| {
                    e.prefix_region_after_write = RegionState::Untouched;
                },
            ),
            ("the prefix write was torn", |e| {
                e.prefix_region_after_write = RegionState::Torn;
            }),
            ("the prefix write acknowledged the wrong count", |e| {
                e.prefix_acknowledged_bytes = PREFIX_PAYLOAD_BYTES - 1;
            }),
            // The write half's concurrency rules.
            ("no attempt was active at the write freeze", |e| {
                e.write_freeze.attempt_active = false;
            }),
            ("the owner was not frozen at the write freeze", |e| {
                e.write_freeze.phase = "active".into();
            }),
            (
                "the connector's fence did not exceed the owner's cursor at the write freeze",
                |e| {
                    e.write_freeze.connector_fence = Some(e.write_freeze.relay_recv_contiguous);
                },
            ),
            ("no connector fence at the write freeze", |e| {
                e.write_freeze.connector_fence = None;
            }),
            (
                "the write in-flight conclusion was asserted without its sample",
                |e| e.write_exchange_in_flight_at_freeze = false,
            ),
            ("the first candidate generation did not advance", |e| {
                e.write_freeze.candidate_generation = Some(e.write_freeze.old_generation);
            }),
            ("no first candidate generation", |e| {
                e.write_freeze.candidate_generation = None;
            }),
            // The write's effect from outside the connector.
            ("the host directory never showed the write performed", |e| {
                e.held_region_before_freeze = RegionState::Untouched;
            }),
            ("the write's effect was torn", |e| {
                e.held_region_before_freeze = RegionState::Torn;
            }),
            ("the host file could not be read at the freeze", |e| {
                e.held_region_before_freeze = RegionState::Unreadable;
            }),
            // The write half's operation-level rules.
            ("the held reply carried another tag", |e| {
                e.held_write_reply_tag_matched = false;
            }),
            ("the held reply was not an Rwrite", |e| {
                e.held_write_reply_was_rwrite = false;
            }),
            ("the Rwrite acknowledged too few bytes", |e| {
                e.held_write_acknowledged_bytes = HELD_PAYLOAD_BYTES - 1;
            }),
            ("the Rwrite acknowledged too many bytes", |e| {
                e.held_write_acknowledged_bytes = HELD_PAYLOAD_BYTES + 1;
            }),
            ("the held write was never answered", |e| {
                e.held_write_answered = false;
            }),
            ("the rotation left an ambiguous write", |e| {
                e.held_write_ambiguous = true;
            }),
            ("the write's effect was gone after the rotation", |e| {
                e.held_region_after_rotation = RegionState::Untouched;
            }),
            ("the write's effect was torn after the rotation", |e| {
                e.held_region_after_rotation = RegionState::Torn;
            }),
            // The whole-file image.
            ("the host file lost a byte", |e| e.image_bytes -= 1),
            ("the host file gained a byte", |e| e.image_bytes += 1),
            ("the expected length was moved to match", |e| {
                e.image_bytes = 1;
                e.image_expected_bytes = 1;
            }),
            ("a byte outside the written regions changed", |e| {
                e.image_checksum_matches = false;
            }),
            // The flush half's concurrency rules.
            ("no attempt was active at the flush freeze", |e| {
                e.flush_freeze.attempt_active = false;
            }),
            ("the owner was not frozen at the flush freeze", |e| {
                e.flush_freeze.phase = "active".into();
            }),
            (
                "the connector's fence did not exceed the owner's cursor at the flush freeze",
                |e| {
                    e.flush_freeze.connector_fence = Some(e.flush_freeze.relay_recv_contiguous);
                },
            ),
            ("no connector fence at the flush freeze", |e| {
                e.flush_freeze.connector_fence = None;
            }),
            (
                "the flush in-flight conclusion was asserted without its sample",
                |e| e.flush_exchange_in_flight_at_freeze = false,
            ),
            ("the second candidate generation did not advance", |e| {
                e.flush_freeze.candidate_generation = Some(e.flush_freeze.old_generation);
            }),
            ("no second candidate generation", |e| {
                e.flush_freeze.candidate_generation = None;
            }),
            // The flush half's operation-level rules.
            ("the flush was never answered", |e| {
                e.rflush_observed = false;
            }),
            ("the flush named itself as its victim", |e| {
                e.flushed_victim_tag = e.flush_tag;
            }),
            ("the flushed tag was answered", |e| {
                e.flushed_victim_reply_observed = true;
            }),
            ("a reply for the flushed tag followed its Rflush", |e| {
                e.flushed_replies_after_rflush = 1;
            }),
            ("the flush took the queue with it", |e| {
                e.flush_pipeline_replies = FLUSH_PIPELINE_DEPTH - 1;
            }),
            // Both rotations really happened, cleanly.
            ("no rotation completed while the write was held", |e| {
                e.rotations_completed_after_write = e.rotations_completed_before;
            }),
            (
                "no second rotation completed while the flush was held",
                |e| {
                    e.rotations_completed_after_flush = e.rotations_completed_after_write;
                },
            ),
            ("the generation did not advance", |e| {
                e.generation_after = e.generation_before;
            }),
            ("frames were replayed", |e| e.total_replayed_frames = 1),
            ("the deadline forced retirement", |e| {
                e.deadline_forced_retirement = true;
            }),
            ("an attempt entered recovery", |e| {
                e.rotation_recovery_reason = Some("data_loss".into());
            }),
            // The same-owner contract.
            ("the session identity changed", |e| {
                e.session_id_stable = false;
            }),
            ("the epoch changed", |e| e.epoch_stable = false),
            // The fid rules.
            ("the fid did not answer after the rotations", |e| {
                e.fid_survived_read = false;
            }),
            ("the fid read back the wrong bytes", |e| {
                e.fid_read_back_matches_payload = false;
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
                validate_fs_rotation_write_evidence(&evidence).is_err(),
                "mutation `{name}` must be rejected: no rule here is decorative"
            );
        }
    }

    /// The discrimination this whole gate rests on: a payload byte and the
    /// filler byte can never be the same value.
    ///
    /// If [`payload_bytes`] ever stopped setting the high bit, "the region is
    /// all filler" would stop meaning "nothing was written" — an untouched
    /// region and a region written with a zero byte would read alike, and
    /// every classification here would quietly weaken.  Held at the generator
    /// rather than inferred from a passing run.
    #[test]
    fn payload_and_filler_can_never_be_confused() {
        let payload = payload_bytes(2_048);
        assert_eq!(payload.len(), 2_048);
        assert!(
            payload.iter().all(|byte| *byte != FILLER_BYTE),
            "a payload byte equal to the filler byte makes an untouched region \
             indistinguishable from a written one"
        );
        // And the payload is not a constant: a checksum over it has to be able
        // to detect a block that moved.
        assert!(
            payload.iter().collect::<BTreeSet<_>>().len() > 1,
            "a constant payload cannot detect a block that moved"
        );
    }

    /// [`classify_region`] must have three answers and never fold a partial
    /// write into either of the other two.
    #[test]
    fn a_partly_applied_write_is_torn_and_is_neither_of_the_others() {
        let payload = payload_bytes(64);
        let mut image = vec![FILLER_BYTE; 256];
        assert_eq!(
            classify_region(&image, 32, &payload),
            RegionState::Untouched
        );

        image[32..96].copy_from_slice(&payload);
        assert_eq!(classify_region(&image, 32, &payload), RegionState::Written);

        // Half of it applied.
        let mut half = vec![FILLER_BYTE; 256];
        half[32..64].copy_from_slice(&payload[..32]);
        assert_eq!(classify_region(&half, 32, &payload), RegionState::Torn);

        // One byte wrong is still not "written".
        let mut nearly = image.clone();
        nearly[95] ^= 0x01;
        assert_eq!(classify_region(&nearly, 32, &payload), RegionState::Torn);

        // A region past the end of the file is unreadable, not untouched: a
        // truncated file must never read as "nothing was written here".
        assert_eq!(
            classify_region(&image, 240, &payload),
            RegionState::Unreadable
        );
        assert_eq!(
            classify_region(&[], 0, &payload),
            RegionState::Unreadable,
            "a file that could not be read at all is unreadable, not untouched"
        );
    }

    /// The journal antecedent is a conjunction and each conjunct must defeat
    /// it on its own.  Without this, a direction could rot into a field
    /// nothing reads while the summary bit still said the host directory had
    /// discriminated anything.
    #[test]
    fn every_journal_direction_defeats_the_discrimination_on_its_own() {
        assert!(passing().journal_discriminated_both_directions());
        type Mutation = (&'static str, fn(&mut FsRotationWriteEvidence));
        let conjuncts: Vec<Mutation> = vec![
            ("negative direction", |e| {
                e.held_region_before_send = RegionState::Written;
            }),
            ("positive direction", |e| {
                e.prefix_region_after_write = RegionState::Untouched;
            }),
            ("the prefix write's acknowledged count", |e| {
                e.prefix_acknowledged_bytes = 0;
            }),
        ];
        for (label, mutate) in conjuncts {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                !evidence.journal_discriminated_both_directions(),
                "a journal direction did not defeat the discrimination: {label}"
            );
        }
    }

    /// The ambiguity classification is **derived** from two facts and must
    /// move with both of them.  A field that were merely asserted false would
    /// pass this gate on a run where the answer was lost.
    #[test]
    fn ambiguity_is_derived_from_the_journal_and_the_answer_together() {
        let performed_and_answered = passing();
        assert!(performed_and_answered.held_write_performed_before_freeze());
        assert!(
            !(performed_and_answered.held_write_performed_before_freeze()
                && !performed_and_answered.held_write_answered),
            "a performed and answered write is not ambiguous"
        );

        let performed_unanswered = FsRotationWriteEvidence {
            held_write_answered: false,
            ..passing()
        };
        assert!(
            performed_unanswered.held_write_performed_before_freeze()
                && !performed_unanswered.held_write_answered,
            "an effect the journal saw whose answer never arrived is exactly the \
             ambiguous case the flush paragraph names"
        );

        let never_performed = FsRotationWriteEvidence {
            held_region_before_freeze: RegionState::Untouched,
            held_write_answered: false,
            ..passing()
        };
        assert!(
            !never_performed.held_write_performed_before_freeze(),
            "a write the journal never saw is not an ambiguous one, and a gate \
             that read it as ambiguous would be measuring a refusal that never \
             dispatched"
        );
    }

    /// The expected whole-file image must actually differ from the seeded one
    /// in both regions, or the image checksum could pass on a run where
    /// nothing was ever written.
    #[test]
    fn the_expected_image_differs_from_the_seeded_file_in_both_regions() {
        let seeded = vec![FILLER_BYTE; TARGET_FILE_BYTES];
        let expected = expected_image();
        assert_eq!(expected.len(), TARGET_FILE_BYTES);
        assert_ne!(fnv1a(&expected), fnv1a(&seeded));
        assert_eq!(
            classify_region(
                &expected,
                PREFIX_OFFSET,
                &payload_bytes(PREFIX_PAYLOAD_BYTES)
            ),
            RegionState::Written
        );
        assert_eq!(
            classify_region(&expected, HELD_OFFSET, &payload_bytes(HELD_PAYLOAD_BYTES)),
            RegionState::Written
        );
        // The two regions do not overlap, and there is filler between them and
        // after them: a frame replayed at a wrong offset has somewhere to show.
        assert!(PREFIX_OFFSET as usize + PREFIX_PAYLOAD_BYTES < HELD_OFFSET as usize);
        assert!(HELD_OFFSET as usize + HELD_PAYLOAD_BYTES < TARGET_FILE_BYTES);
        assert!(
            expected[PREFIX_PAYLOAD_BYTES..HELD_OFFSET as usize]
                .iter()
                .all(|byte| *byte == FILLER_BYTE)
        );
    }
}
