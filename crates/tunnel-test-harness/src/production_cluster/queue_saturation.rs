//! M7-C22 / M7-I07 / M7-I27 configured message-queue saturation gate.
//!
//! # The configured bounds
//!
//! Read from the relay configuration rather than assumed
//! (`RelayLimits::default` plus the production override in
//! `production_cluster.rs`):
//!
//! ```text
//! max_queue_bytes        = 4 MiB = 4_194_304   (one shared session byte budget)
//! control reserve        = 4 * 32 KiB = 131_072 (RESERVED_CONTROL_BYTES, M7-C49)
//! data byte limit        = 4_194_304 - 131_072 = 4_063_232
//! max_queue_messages     = 128                 (separate control and data channel slots)
//! max_streams_per_device = 64
//! max_body_bytes         = MAX_PAYLOAD_LEN = 65_536
//! HEADER_LEN             = 64
//! M2_INITIAL_WINDOW_BYTES= 131_072             (per stream, per direction)
//! ```
//!
//! # Charge accounting
//!
//! Every logical echo record costs the shared session byte budget **twice**:
//! once as the retained replay chunk (`reserve_m2_bytes`) and once as the
//! encoded outbound frame (`queue_data`).  For a body of `B` bytes whose
//! record fits one tunnel frame,
//!
//! ```text
//! frames(B) = ceil((B + 4) / 65_536)
//! charge(B) = (B + 4) + (B + 4) + 64 = 2B + 72        // one-frame records
//! ```
//!
//! and the record occupies `frames(B)` physical entries of the bounded data
//! channel.
//!
//! # Why 128 physical data entries is unreachable
//!
//! The public consumer ingress admits **exactly one in-flight record per
//! stream**.  `handle_consumer_stream` awaits the complete echo response
//! before reading the next WebSocket message, and caps its reassembly buffer
//! at `MAX_BODY_BYTES + 4`, so a consumer cannot pipeline a second record.
//! Physical data-queue residency from consumer DATA is therefore bounded by
//! the **data byte limit** (the session budget minus the control reservation),
//!
//! ```text
//! entries(B) = min(64, floor(4_063_232 / charge(B))) * frames(B)
//! ```
//!
//! Maximising over every admissible body size gives **64 entries**:
//!
//! ```text
//! B <=     31_708 : charge <=    63_488 -> 64 streams admitted -> 64 entries
//! B  = 31_709..65_532 : charge >  63_488 -> n = data limit/charge < 64 -> < 64 entries
//! B >=     65_533 : record spans 2 frames, charge = 131_208
//!                   n = 4_063_232 / 131_208 = 30 -> 60 entries
//! ```
//!
//! That is exactly the objection an independent review raised against the
//! previous attempt: 64 maximum records cannot fill 128 entries, and the
//! 64 maximum records that would produce 128 entries need
//! `64 * 131_208 = 8_397_312` bytes, precisely 2.00x the 4 MiB budget, so
//! admission refuses at 31 records (62 entries).  No body size escapes the
//! result, because `max_queue_messages = 2 * max_streams_per_device` by
//! design: the second slot per stream is reserved for a record's continuation
//! frame, its ACK and its terminal frame.  **Filling all 128 entries from the
//! public echo route is therefore not a reachable scenario, and this gate does
//! not pretend otherwise.**
//!
//! # The smallest defensible alternative this gate implements
//!
//! Saturate the *reachable* bound and prove which bound binds, instead of
//! lowering the physical-occupancy requirement to a logical count:
//!
//! 1. Admit exactly `max_streams_per_device` streams and prove the next one is
//!    refused, so the stream cap is shown to be the binding constraint.
//! 2. Blackhole the exact carrier and drive one in-flight record on every
//!    admitted stream, so `max_streams_per_device` frames are physically
//!    resident at once: `max_streams_per_device - 1` inside the bounded
//!    channel plus exactly one owned by the blocked physical writer, which
//!    still holds its byte charge.  Both halves are read from relay
//!    diagnostics, never inferred from an admission count.
//! 3. Prove the other half of the data channel stays reserved and free, which
//!    is what `max_queue_messages = 2 * max_streams_per_device` exists for.
//! 4. Prove control, cancellation, revocation and rotation keep their reserved
//!    bounded capacity.  All four classes share one bounded control channel and
//!    one shared byte budget, so at peak residency the gate requires zero
//!    control refusals, free control slots, and byte headroom above a floor of
//!    32 times the 32 KiB control bound.  It additionally requires the relay's
//!    accepted-control-enqueue counter to *advance* during the blackhole
//!    window, which is positive evidence that control traffic kept flowing
//!    rather than merely not being refused.  Since M7-C49 the relay also
//!    reserves control capacity in **bytes**: data-lane reservations are
//!    refused above `data_bytes_limit = max_queue_bytes - 131_072`, and the
//!    relay latches `data_bytes_high_water`, the highest total charge at which
//!    a data reservation was admitted.  The gate requires that latch to stay
//!    at or below the data byte limit and derives
//!    `control_bytes_available_at_data_peak = max_queue_bytes -
//!    data_bytes_high_water`, which must be at least the 131_072-byte
//!    reservation: control bytes remained available at the data-byte peak,
//!    not only control slots.
//! 5. Prove real cancellation and fresh admission once the carrier is writable
//!    again, with an immutable first-terminal observation for the cancelled
//!    stream.  These run after the resume by necessity: the blackholed carrier
//!    has a five-second physical write bound, and a consumer-initiated cancel
//!    cannot wake a relay handler parked on the blackholed response, so a
//!    cancellation cannot be driven to completion inside that window.
//!
//! One further effect is physical, not configured, and the gate measures it
//! instead of assuming it away.  The owner's writer hands each frame to the TLS
//! socket and releases its byte charge when the send completes, so the frames
//! the kernel absorbs before the write blocks are *not* simultaneously resident
//! in the bounded channel.  Simultaneous residency is therefore
//!
//! ```text
//! resident = admitted_in_flight - absorbed
//!          = 64 - ceil(absorbed_wire_bytes / wire_bytes_per_record)
//! ```
//!
//! Larger records absorb fewer frames, so the record size is pushed as high as
//! the reserved byte floor allows.  With a floor of `4 MiB / 4 = 1_048_576`
//! bytes the admissible charge is `(4_194_304 - 1_048_576) / 64 = 49_152` bytes
//! per record, so `B <= 24_540`.  `B = 20_000` keeps a comfortable margin:
//!
//! ```text
//! charge(20_000)           = 40_072 bytes, 1 frame, 20_068 wire bytes
//! 64 streams * 40_072      = 2_564_608 bytes = 61.1% of the 4 MiB budget
//! reserved byte headroom   = 1_629_696 bytes  (>= 32 * the 32 KiB control bound)
//! per-stream credit        = 131_072 / 20_004 = 6 records, 1 in flight
//! ```
//!
//! The gate asserts the exact configured quantity (all 64 in-flight records
//! admitted, counted by the relay's own accepted-enqueue counter), closes the
//! residency accounting against the measured absorbed count, bounds that
//! absorbed count by an explicitly-labelled environment constant, and still
//! requires simultaneous residency above a configured floor of
//! `max_queue_messages / 4`.
//!
//! Every one of these inequalities is re-derived at runtime from the bounds the
//! relay itself reports, so the gate proves feasibility instead of assuming it.

use super::{
    ConsumerStream, ProductionCluster, ProductionRelay, RunningHarness, StreamConnectFailure,
    connect_failure_to_harness, open_consumer_stream,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{ConnectionId, Direction, HarnessError, ProxyConfig, ProxyHandle, Result, TcpProxy};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tunnel_client::{ConnectOptions, ConnectionHandle, ConnectionStatus, TransportProfile};
use tunnel_core::RotationConfig;
use uuid::Uuid;

/// Rotation schedule for this gate.
///
/// The saturation window must not collide with a scheduled handover, and the
/// correlated rotation must still fire inside the scenario deadline.
pub(super) const SATURATION_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 15,
    handshake_timeout_seconds: 1,
    overlap_seconds: 3,
};

/// Configured bounds this gate requires the relay to report.
const EXPECTED_QUEUE_BYTES_LIMIT: usize = 4 * 1024 * 1024;
const EXPECTED_QUEUE_MESSAGES: usize = 128;
const EXPECTED_MAX_STREAMS_PER_DEVICE: usize = 64;
/// `tunnel_relay::actor::RESERVED_CONTROL_BYTES`: four 32 KiB control slots
/// carved out of the shared session budget for rotation, cancellation,
/// revocation and control replies (M7-C49).  Data-lane reservations are
/// refused above `EXPECTED_DATA_BYTES_LIMIT`, so data can never consume them.
const EXPECTED_CONTROL_RESERVED_BYTES: usize = 4 * 32 * 1024;
const EXPECTED_DATA_BYTES_LIMIT: usize =
    EXPECTED_QUEUE_BYTES_LIMIT - EXPECTED_CONTROL_RESERVED_BYTES;

/// `tunnel_protocol::HEADER_LEN`, `MAX_PAYLOAD_LEN`, and the four-byte record
/// length prefix the relay prepends before chunking a record into frames.
const FRAME_HEADER_BYTES: usize = 64;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const RECORD_PREFIX_BYTES: usize = 4;
/// `wire::M2_INITIAL_WINDOW_BYTES`: the per-stream, per-direction cumulative
/// DATA byte credit advertised at echo-stream admission.
const M2_INITIAL_WINDOW_BYTES: usize = 128 * 1024;

/// Derived workload.  See the module derivation above.
const SATURATION_RECORD_BYTES: usize = 20_000;

/// Wire bytes the kernel socket buffers and the paused proxy may absorb before
/// the owner's physical writer blocks.
///
/// This is an **environment** bound, not a product bound: the writer hands each
/// frame to the TLS socket and releases its byte charge once the send completes,
/// so however much the operating system buffers is subtracted from the frames
/// that can be simultaneously resident in the bounded channel.  The gate
/// measures the absorbed count from relay diagnostics and requires it to stay
/// under this bound rather than assuming any particular buffer size.
const MAX_ABSORBED_WIRE_BYTES: usize = 1024 * 1024;

/// Hard floor on simultaneous physical residency, expressed in configured
/// terms: at least a quarter of the bounded data channel must be physically
/// occupied at once, so the gate cannot pass on a trivial occupancy.
const MIN_RESIDENT_FRAMES: usize = EXPECTED_QUEUE_MESSAGES / 4;

/// Minimum session byte budget that must still be free at peak residency, so
/// control, cancellation, revocation and rotation keep reserved bounded byte
/// capacity rather than merely reserved slots.
///
/// One quarter of the configured budget is `1_048_576` bytes, which is 32
/// times the `max_control_bytes` 32 KiB control bound: room for 32 maximum
/// control messages queued simultaneously.  The derived workload leaves
/// `2_141_696` bytes, twice that floor.
const MIN_SATURATION_HEADROOM_BYTES: usize = EXPECTED_QUEUE_BYTES_LIMIT / 4;

/// The paused proxy requests the smallest permitted target receive buffer so
/// the owner's physical writer blocks after bounded absorption.
const PAUSED_TARGET_RECEIVE_BUFFER_BYTES: u32 = 1_024;

/// The send buffer requested on every relay's accepted device sockets for
/// this gate: a small request (the transport accepts 1 KiB to 1 MiB), so the kernel can
/// absorb about one 20 KB record on the blackholed carrier rather than the
/// many an autotuned Linux buffer holds.
pub(super) const DEVICE_SEND_BUFFER_BYTES: u32 = 4_096;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const SATURATION_TIMEOUT: Duration = Duration::from_secs(8);
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Fixed bound on drain observations: 200 * 25 ms = 5 s.
const DRAIN_OBSERVATION_BOUND: usize = 200;
/// Re-samples used to prove the first terminal observation is immutable.
const TERMINAL_IMMUTABILITY_SAMPLES: usize = 8;
const TERMINAL_SAMPLE_INTERVAL: Duration = Duration::from_millis(25);
/// Three same-owner rotations at a fifteen-second interval, plus the
/// saturation sequence, must fit inside the scenario deadline.
const SATURATION_ROTATION_COUNT: u64 = 3;
const ROTATION_TIMEOUT: Duration = Duration::from_secs(90);
/// Bounded window for the live reserved-control-capacity observation, well
/// inside the relay's five-second physical write bound on the paused carrier.
const CONTROL_PROGRESS_TIMEOUT: Duration = Duration::from_secs(3);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const SIBLING_TIMEOUT: Duration = Duration::from_secs(20);

/// Physical frames a logical record of `body` bytes occupies in the bounded
/// data channel.
const fn frames_per_record(body: usize) -> usize {
    (body + RECORD_PREFIX_BYTES).div_ceil(MAX_PAYLOAD_BYTES)
}

/// Charge levied on the shared session byte budget by one logical record of
/// `body` bytes that fits a single tunnel frame: the retained replay chunk
/// plus the encoded frame.
const fn charge_per_record(body: usize) -> usize {
    2 * (body + RECORD_PREFIX_BYTES) + FRAME_HEADER_BYTES
}

/// Wire bytes one such record occupies on the carrier socket.
const fn wire_bytes_per_record(body: usize) -> usize {
    body + RECORD_PREFIX_BYTES + FRAME_HEADER_BYTES
}

/// Records one stream may emit against its initial cumulative send credit
/// without any `WINDOW_UPDATE`.
const fn records_per_stream_by_credit(body: usize) -> usize {
    M2_INITIAL_WINDOW_BYTES / (body + RECORD_PREFIX_BYTES)
}

/// Physical data-channel entries a one-in-flight-record-per-stream workload
/// can make resident at this record size, under the data byte limit (the
/// shared session budget minus the control reservation) and the per-device
/// stream cap.
const fn reachable_entries(body: usize, data_bytes_limit: usize, max_streams: usize) -> usize {
    let admissible = data_bytes_limit / charge_per_record(body);
    let streams = if admissible < max_streams {
        admissible
    } else {
        max_streams
    };
    streams * frames_per_record(body)
}

/// Payload-free evidence from the configured message-queue saturation gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueSaturationEvidence {
    /// Number of production relays serving during the gate.
    pub relay_count: usize,
    /// Relays whose membership runtime reached `Ready`.
    pub membership_ready_relays: usize,
    /// Every consumer stream entered through a relay that is not the owner.
    pub non_owner_ingress: bool,
    /// Session byte budget the owner relay reported for the live session.
    pub configured_queue_bytes_limit: usize,
    /// Bytes of that budget the relay reserves for control messages; data-lane
    /// reservations can never consume them.
    pub configured_control_reserved_bytes: usize,
    /// Greatest total charge at which the relay admits a data-lane
    /// reservation: `configured_queue_bytes_limit -
    /// configured_control_reserved_bytes`.
    pub configured_data_bytes_limit: usize,
    /// Configured bound of the owner's physical outbound data channel.
    pub configured_data_queue_capacity: usize,
    /// Configured bound of the owner's physical outbound control channel.
    pub configured_control_queue_capacity: usize,
    /// Per-device stream cap the gate saturated, proven by a refusal at
    /// cap-plus-one rather than assumed from configuration.
    pub configured_max_streams_per_device: usize,
    /// Record body size the derived workload used.
    pub workload_record_bytes: usize,
    /// Shared-budget charge one such record levies.
    pub workload_charge_per_record_bytes: usize,
    /// Physical data-channel entries one such record occupies.
    pub workload_frames_per_record: usize,
    /// Streams the workload drove concurrently, one in-flight record each.
    pub workload_streams: usize,
    /// Records one stream could emit against its initial credit.
    pub workload_records_per_stream_by_credit: usize,
    /// Physical entries this workload can make resident under the live bounds.
    pub workload_reachable_entries: usize,
    /// The greatest physical residency any admissible body size can reach on
    /// this route, computed from the live bounds.  Documented as strictly below
    /// the data-channel bound: 128 entries is unreachable.
    pub route_maximum_reachable_entries: usize,
    /// Streams actually admitted before the cap refused one more.
    pub streams_admitted: usize,
    /// Admission at cap-plus-one was refused, so the per-device stream cap is
    /// the binding constraint rather than the message-queue bound.
    pub stream_cap_refused_one_more: bool,
    /// Highest physical data-channel occupancy observed in a live sample.
    pub data_queue_depth_observed: usize,
    /// Highest physical data-channel occupancy the relay itself latched.
    pub data_queue_depth_high_water: usize,
    /// In-flight records the relay actually admitted onto the bounded data
    /// channel during the blackhole window, counted by its own accepted-enqueue
    /// counter.  This must equal the reachable bound exactly.
    pub data_enqueues_during_blackhole: u64,
    /// Frames physically resident at peak: the latched channel high water plus
    /// the one frame the blocked physical writer owns and still charges.
    pub physically_resident_frames: usize,
    /// Frames the kernel socket buffers absorbed before the writer blocked, so
    /// they were no longer charged or resident.  Derived, not assumed:
    /// `admitted - resident`.
    pub writer_absorbed_frames: usize,
    /// Wire bytes those absorbed frames account for.
    pub writer_absorbed_wire_bytes: usize,
    /// The full reachable in-flight bound was admitted and the residency
    /// accounting closes against the measured absorbed count.
    pub reachable_bound_saturated: bool,
    /// Free data-channel slots retained at peak residency.  This is the
    /// reserved second slot per stream that `max_queue_messages =
    /// 2 * max_streams_per_device` exists to guarantee.
    pub reserved_free_data_slots_at_peak: usize,
    /// A terminal or acknowledgement frame was accepted onto the data channel
    /// at peak residency, proving the reserved half is usable and not merely
    /// counted.
    pub reserved_data_slot_accepted_at_peak: bool,
    /// Peak session byte charge the relay latched.
    pub queue_bytes_high_water: usize,
    /// Highest total session charge at which the relay admitted a data-lane
    /// reservation.  Bounded by the data byte limit by construction, so it is
    /// the data-byte peak from which reserved control bytes are derived.
    pub data_bytes_high_water: usize,
    /// `configured_queue_bytes_limit - data_bytes_high_water`: the least
    /// control byte capacity that remained available at the data-byte peak.
    /// Must be at least the configured control reservation.
    pub control_bytes_available_at_data_peak: usize,
    /// Free session byte budget at peak residency.
    pub queue_bytes_headroom_at_peak: usize,
    /// Physical control-channel occupancy at peak residency.
    pub control_queue_depth_at_peak: usize,
    /// Highest physical control-channel occupancy the relay latched.
    pub control_queue_depth_high_water: usize,
    /// Control enqueues refused for want of budget or a slot.  Cancellation,
    /// revocation and rotation control all share this one path, so zero
    /// refusals at peak residency is the no-starvation proof for all of them.
    pub control_queue_refusals: u64,
    /// Accepted control enqueues the relay recorded during the blackhole
    /// window, beyond the count taken before the pause.  A positive value is
    /// direct evidence that control traffic kept flowing at peak residency.
    pub control_enqueues_during_blackhole: u64,
    /// A cancellation was accepted once the carrier was writable again, and its
    /// stream reached a terminal state.
    pub cancellation_accepted_after_resume: bool,
    /// A fresh stream was admitted through the non-owner ingress after the
    /// cancellation freed a slot at the per-device stream cap.
    pub fresh_stream_admitted_after_cancellation: bool,
    /// A stream untouched by the cancellation round-tripped after the drain.
    pub sibling_stream_survived: bool,
    /// The first terminal observation for the cancelled stream never changed.
    pub first_terminal_observation_immutable: bool,
    /// Re-samples compared against that first observation.
    pub terminal_observations: usize,
    /// The proxy acknowledged a pause on the exact correlated data direction.
    pub paused_target_to_client: u64,
    /// The paused proxy connection was correlated to the carrier's own local
    /// address rather than taken by ordinal.
    pub paused_connection_correlated: bool,
    /// Generation of the exact paused carrier.
    pub paused_generation: u64,
    /// Observation index, within the fixed bound, at which physical occupancy
    /// returned to zero after the resume.
    pub physical_drain_observations: usize,
    /// The fixed observation bound the drain had to meet.
    pub physical_drain_observation_bound: usize,
    /// Physical occupancy reached zero within that bound.
    pub physical_drain_completed: bool,
    /// The first scheduled rotation that followed the drain replaced exactly the
    /// carrier that had been paused.
    pub rotation_replaced_paused_carrier: bool,
    /// Generation the first correlated rotation committed.
    pub rotation_committed_generation: u64,
    /// Same-owner rotations completed after the drain.
    pub rotations_completed_after_drain: u64,
    /// Highest generation observed across those rotations.  Generations advance
    /// by exactly one per rotation and never rewind.
    pub final_generation: u64,
    /// Rotation attempts whose absolute deadline was observed at least twice,
    /// which is what makes "never extended" a measurement rather than a claim.
    pub rotation_attempts_with_observed_deadline: usize,
    /// Every observation of a given attempt reported the same start and the same
    /// absolute deadline: no phase change or retry extended it.
    pub rotation_deadline_never_extended: bool,
    /// Each observed attempt's deadline stayed within the configured overlap of
    /// that attempt's own start, so one absolute bound covers the whole attempt
    /// rather than one bound per phase.
    pub rotation_deadline_within_configured_overlap: bool,
    /// Peak simultaneously open device sockets at the controlling proxy.
    pub device_socket_peak_open: usize,
    /// Application dispatches recorded across a fixed window after the drain;
    /// a saturated and drained queue must not replay.
    pub dispatch_delta_after_drain: u64,
    /// Wall-clock milliseconds spent in the gate.
    pub elapsed_ms: u64,
}

/// Validate the configured saturation evidence contract.
#[allow(clippy::too_many_lines)]
pub fn validate_queue_saturation_evidence(evidence: &QueueSaturationEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "queue saturation expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.membership_ready_relays != 3 {
        return Err(HarnessError::Process(format!(
            "queue saturation expected three Ready memberships, observed {}",
            evidence.membership_ready_relays
        )));
    }
    if evidence.configured_queue_bytes_limit != EXPECTED_QUEUE_BYTES_LIMIT {
        return Err(HarnessError::Process(format!(
            "queue saturation relay reported a {} byte session budget, expected {}",
            evidence.configured_queue_bytes_limit, EXPECTED_QUEUE_BYTES_LIMIT
        )));
    }
    if evidence.configured_control_reserved_bytes != EXPECTED_CONTROL_RESERVED_BYTES {
        return Err(HarnessError::Process(format!(
            "queue saturation relay reserved {} control bytes, expected {}",
            evidence.configured_control_reserved_bytes, EXPECTED_CONTROL_RESERVED_BYTES
        )));
    }
    if evidence.configured_data_bytes_limit != EXPECTED_DATA_BYTES_LIMIT
        || evidence.configured_data_bytes_limit
            != evidence
                .configured_queue_bytes_limit
                .saturating_sub(evidence.configured_control_reserved_bytes)
    {
        return Err(HarnessError::Process(format!(
            "queue saturation relay reported a {} byte data limit, expected {} (budget {} minus reserved {})",
            evidence.configured_data_bytes_limit,
            EXPECTED_DATA_BYTES_LIMIT,
            evidence.configured_queue_bytes_limit,
            evidence.configured_control_reserved_bytes
        )));
    }
    if evidence.configured_data_queue_capacity != EXPECTED_QUEUE_MESSAGES
        || evidence.configured_control_queue_capacity != EXPECTED_QUEUE_MESSAGES
    {
        return Err(HarnessError::Process(format!(
            "queue saturation expected {} control and data queue slots, observed control={} data={}",
            EXPECTED_QUEUE_MESSAGES,
            evidence.configured_control_queue_capacity,
            evidence.configured_data_queue_capacity
        )));
    }
    if evidence.configured_max_streams_per_device != EXPECTED_MAX_STREAMS_PER_DEVICE {
        return Err(HarnessError::Process(format!(
            "queue saturation expected a {} stream per-device cap, observed {}",
            EXPECTED_MAX_STREAMS_PER_DEVICE, evidence.configured_max_streams_per_device
        )));
    }

    // Derivation self-consistency: the reported workload arithmetic must follow
    // from the reported record size and bounds.
    if evidence.workload_record_bytes == 0 || evidence.workload_record_bytes > MAX_PAYLOAD_BYTES {
        return Err(HarnessError::Process(format!(
            "queue saturation record size {} is outside 1..={}",
            evidence.workload_record_bytes, MAX_PAYLOAD_BYTES
        )));
    }
    if evidence.workload_charge_per_record_bytes
        != charge_per_record(evidence.workload_record_bytes)
    {
        return Err(HarnessError::Process(format!(
            "queue saturation reported charge {} for a {} byte record, expected {}",
            evidence.workload_charge_per_record_bytes,
            evidence.workload_record_bytes,
            charge_per_record(evidence.workload_record_bytes)
        )));
    }
    if evidence.workload_frames_per_record != frames_per_record(evidence.workload_record_bytes) {
        return Err(HarnessError::Process(format!(
            "queue saturation reported {} frames per record, expected {}",
            evidence.workload_frames_per_record,
            frames_per_record(evidence.workload_record_bytes)
        )));
    }
    if evidence.workload_records_per_stream_by_credit
        != records_per_stream_by_credit(evidence.workload_record_bytes)
        || evidence.workload_records_per_stream_by_credit == 0
    {
        return Err(HarnessError::Process(format!(
            "queue saturation reported {} credit-admissible records per stream, expected {}",
            evidence.workload_records_per_stream_by_credit,
            records_per_stream_by_credit(evidence.workload_record_bytes)
        )));
    }
    if evidence.workload_reachable_entries
        != reachable_entries(
            evidence.workload_record_bytes,
            evidence.configured_data_bytes_limit,
            evidence.configured_max_streams_per_device,
        )
    {
        return Err(HarnessError::Process(format!(
            "queue saturation reported {} reachable entries, which does not follow from the live bounds",
            evidence.workload_reachable_entries
        )));
    }
    // The documented unreachability of the nominal channel bound.  If a future
    // configuration or ingress change makes 128 entries reachable, this gate
    // must be reopened rather than silently keep asserting the smaller bound.
    let route_maximum = (1..=MAX_PAYLOAD_BYTES)
        .map(|body| {
            reachable_entries(
                body,
                evidence.configured_data_bytes_limit,
                evidence.configured_max_streams_per_device,
            )
        })
        .max()
        .unwrap_or(0);
    if evidence.route_maximum_reachable_entries != route_maximum {
        return Err(HarnessError::Process(format!(
            "queue saturation reported a route maximum of {} entries, expected {}",
            evidence.route_maximum_reachable_entries, route_maximum
        )));
    }
    if evidence.route_maximum_reachable_entries >= evidence.configured_data_queue_capacity {
        return Err(HarnessError::Process(format!(
            "queue saturation recorded {} reachable entries against a {} slot data channel: the full message-queue bound is now reachable and this gate must be reopened to assert it",
            evidence.route_maximum_reachable_entries, evidence.configured_data_queue_capacity
        )));
    }
    if evidence.workload_reachable_entries != evidence.route_maximum_reachable_entries {
        return Err(HarnessError::Process(format!(
            "queue saturation workload reaches {} entries but {} are reachable on this route; the workload must saturate the reachable bound",
            evidence.workload_reachable_entries, evidence.route_maximum_reachable_entries
        )));
    }
    if evidence.workload_streams != evidence.configured_max_streams_per_device {
        return Err(HarnessError::Process(format!(
            "queue saturation drove {} streams, expected the full {} stream cap",
            evidence.workload_streams, evidence.configured_max_streams_per_device
        )));
    }
    if evidence.streams_admitted != evidence.configured_max_streams_per_device {
        return Err(HarnessError::Process(format!(
            "queue saturation admitted {} streams, expected {}",
            evidence.streams_admitted, evidence.configured_max_streams_per_device
        )));
    }

    // Physical, not logical, occupancy.
    if evidence.physically_resident_frames != evidence.data_queue_depth_high_water + 1 {
        return Err(HarnessError::Process(format!(
            "queue saturation reported {} resident frames against a {} channel high water; residency is the latched depth plus the one frame the blocked writer owns",
            evidence.physically_resident_frames, evidence.data_queue_depth_high_water
        )));
    }
    // The exact configured quantity: every in-flight record the per-device
    // stream cap allows was admitted onto the bounded data channel.
    if evidence.data_enqueues_during_blackhole
        != u64::try_from(evidence.workload_reachable_entries).unwrap_or(u64::MAX)
    {
        return Err(HarnessError::Process(format!(
            "queue saturation admitted {} in-flight records onto the data channel, expected the reachable bound {}",
            evidence.data_enqueues_during_blackhole, evidence.workload_reachable_entries
        )));
    }
    // Residency accounting must close against the measured absorbed count.
    if evidence
        .physically_resident_frames
        .saturating_add(evidence.writer_absorbed_frames)
        != evidence.workload_reachable_entries
    {
        return Err(HarnessError::Process(format!(
            "queue saturation residency accounting does not close: resident={} absorbed={} admitted={}",
            evidence.physically_resident_frames,
            evidence.writer_absorbed_frames,
            evidence.workload_reachable_entries
        )));
    }
    if evidence.writer_absorbed_wire_bytes
        != evidence
            .writer_absorbed_frames
            .saturating_mul(wire_bytes_per_record(evidence.workload_record_bytes))
    {
        return Err(HarnessError::Process(
            "queue saturation absorbed wire bytes do not follow from the absorbed frame count"
                .into(),
        ));
    }
    if evidence.writer_absorbed_wire_bytes > MAX_ABSORBED_WIRE_BYTES {
        return Err(HarnessError::Process(format!(
            "queue saturation socket absorption reached {} wire bytes, above the {} environment bound; the blackhole is not holding the writer",
            evidence.writer_absorbed_wire_bytes, MAX_ABSORBED_WIRE_BYTES
        )));
    }
    if evidence.physically_resident_frames < MIN_RESIDENT_FRAMES {
        return Err(HarnessError::Process(format!(
            "queue saturation held only {} frames physically resident, below the {} floor of a quarter of the bounded data channel",
            evidence.physically_resident_frames, MIN_RESIDENT_FRAMES
        )));
    }
    if evidence.data_queue_depth_high_water > evidence.configured_data_queue_capacity
        || evidence.data_queue_depth_observed > evidence.configured_data_queue_capacity
    {
        return Err(HarnessError::Process(format!(
            "queue saturation exceeded the data channel bound: observed={} high_water={} capacity={}",
            evidence.data_queue_depth_observed,
            evidence.data_queue_depth_high_water,
            evidence.configured_data_queue_capacity
        )));
    }
    // Byte corroboration of physical occupancy.  At the instant the bounded
    // channel held `data_queue_depth_high_water` items, each carried both its
    // retained replay chunk and its encoded frame, so at least that many full
    // record charges were simultaneously reserved.  The frame the blocked
    // writer owns is deliberately excluded: the byte and depth latches are
    // updated at different instants, so including it would not be a sound
    // lower bound.  A logical admission count cannot produce this number.
    if evidence.queue_bytes_high_water
        < evidence
            .data_queue_depth_high_water
            .saturating_mul(evidence.workload_charge_per_record_bytes)
    {
        return Err(HarnessError::Process(format!(
            "queue saturation latched only {} peak session bytes, below the {} that {} channel-resident records must charge",
            evidence.queue_bytes_high_water,
            evidence
                .data_queue_depth_high_water
                .saturating_mul(evidence.workload_charge_per_record_bytes),
            evidence.data_queue_depth_high_water
        )));
    }
    if evidence.queue_bytes_high_water > evidence.configured_queue_bytes_limit {
        return Err(HarnessError::Process(format!(
            "queue saturation exceeded its session byte budget: {} of {}",
            evidence.queue_bytes_high_water, evidence.configured_queue_bytes_limit
        )));
    }
    // Reserved control **bytes** at the data-byte peak (M7-C49).  The data-lane
    // latch must corroborate the channel-resident records the same way the
    // total latch does, must never exceed the data byte limit (data never
    // consumed the reservation), and the control capacity derived from it must
    // be at least the reservation and must follow from the reported bounds.
    if evidence.data_bytes_high_water
        < evidence
            .data_queue_depth_high_water
            .saturating_mul(evidence.workload_charge_per_record_bytes)
    {
        return Err(HarnessError::Process(format!(
            "queue saturation latched only {} peak data-lane bytes, below the {} that {} channel-resident records must charge",
            evidence.data_bytes_high_water,
            evidence
                .data_queue_depth_high_water
                .saturating_mul(evidence.workload_charge_per_record_bytes),
            evidence.data_queue_depth_high_water
        )));
    }
    if evidence.data_bytes_high_water > evidence.configured_data_bytes_limit
        || evidence.data_bytes_high_water > evidence.queue_bytes_high_water
    {
        return Err(HarnessError::Process(format!(
            "queue saturation data-lane peak {} consumed reserved control bytes: data limit {} (total peak {})",
            evidence.data_bytes_high_water,
            evidence.configured_data_bytes_limit,
            evidence.queue_bytes_high_water
        )));
    }
    if evidence.control_bytes_available_at_data_peak
        != evidence
            .configured_queue_bytes_limit
            .saturating_sub(evidence.data_bytes_high_water)
    {
        return Err(HarnessError::Process(format!(
            "queue saturation control bytes available at the data peak ({}) do not follow from the budget {} and the data-lane peak {}",
            evidence.control_bytes_available_at_data_peak,
            evidence.configured_queue_bytes_limit,
            evidence.data_bytes_high_water
        )));
    }
    if evidence.control_bytes_available_at_data_peak < evidence.configured_control_reserved_bytes {
        return Err(HarnessError::Process(format!(
            "queue saturation left only {} control bytes at the data-byte peak, below the {} byte reservation",
            evidence.control_bytes_available_at_data_peak,
            evidence.configured_control_reserved_bytes
        )));
    }

    // Reserved bounded capacity.
    if evidence.reserved_free_data_slots_at_peak
        != evidence
            .configured_data_queue_capacity
            .saturating_sub(evidence.data_queue_depth_high_water)
    {
        return Err(HarnessError::Process(
            "queue saturation reserved free data slots do not follow from the reported bounds"
                .into(),
        ));
    }
    if evidence.reserved_free_data_slots_at_peak < evidence.configured_max_streams_per_device - 1 {
        return Err(HarnessError::Process(format!(
            "queue saturation retained only {} free data slots at peak, below the reserved second slot per stream",
            evidence.reserved_free_data_slots_at_peak
        )));
    }
    if evidence.queue_bytes_headroom_at_peak < MIN_SATURATION_HEADROOM_BYTES {
        return Err(HarnessError::Process(format!(
            "queue saturation left only {} free session bytes for control, cancellation, revocation and rotation, below the {} floor",
            evidence.queue_bytes_headroom_at_peak, MIN_SATURATION_HEADROOM_BYTES
        )));
    }
    if evidence.control_queue_depth_at_peak >= evidence.configured_control_queue_capacity
        || evidence.control_queue_depth_high_water >= evidence.configured_control_queue_capacity
    {
        return Err(HarnessError::Process(format!(
            "queue saturation starved reserved control slots: depth={} high_water={} capacity={}",
            evidence.control_queue_depth_at_peak,
            evidence.control_queue_depth_high_water,
            evidence.configured_control_queue_capacity
        )));
    }
    if evidence.control_queue_refusals != 0 {
        return Err(HarnessError::Process(format!(
            "queue saturation refused {} control enqueues; cancellation, revocation and rotation control must never be starved by data",
            evidence.control_queue_refusals
        )));
    }
    if evidence.control_enqueues_during_blackhole == 0 {
        return Err(HarnessError::Process(
            "queue saturation observed no accepted control enqueue while the data channel was physically occupied; reserved control capacity must stay live, not merely unrefused"
                .into(),
        ));
    }

    let required = [
        ("non_owner_ingress", evidence.non_owner_ingress),
        (
            "stream_cap_refused_one_more",
            evidence.stream_cap_refused_one_more,
        ),
        (
            "reachable_bound_saturated",
            evidence.reachable_bound_saturated,
        ),
        (
            "reserved_data_slot_accepted_at_peak",
            evidence.reserved_data_slot_accepted_at_peak,
        ),
        (
            "cancellation_accepted_after_resume",
            evidence.cancellation_accepted_after_resume,
        ),
        (
            "fresh_stream_admitted_after_cancellation",
            evidence.fresh_stream_admitted_after_cancellation,
        ),
        ("sibling_stream_survived", evidence.sibling_stream_survived),
        (
            "first_terminal_observation_immutable",
            evidence.first_terminal_observation_immutable,
        ),
        (
            "paused_connection_correlated",
            evidence.paused_connection_correlated,
        ),
        (
            "physical_drain_completed",
            evidence.physical_drain_completed,
        ),
        (
            "rotation_replaced_paused_carrier",
            evidence.rotation_replaced_paused_carrier,
        ),
        (
            "rotation_deadline_never_extended",
            evidence.rotation_deadline_never_extended,
        ),
        (
            "rotation_deadline_within_configured_overlap",
            evidence.rotation_deadline_within_configured_overlap,
        ),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "queue saturation required gate {name} was false"
        )));
    }

    if evidence.terminal_observations < TERMINAL_IMMUTABILITY_SAMPLES {
        return Err(HarnessError::Process(format!(
            "queue saturation compared only {} terminal observations, expected at least {}",
            evidence.terminal_observations, TERMINAL_IMMUTABILITY_SAMPLES
        )));
    }
    if evidence.paused_target_to_client == 0 {
        return Err(HarnessError::Process(
            "queue saturation proxy did not acknowledge the exact target-to-client pause".into(),
        ));
    }
    if evidence.paused_generation == 0 {
        return Err(HarnessError::Process(
            "queue saturation did not bind a paused carrier generation".into(),
        ));
    }
    if evidence.physical_drain_observation_bound != DRAIN_OBSERVATION_BOUND {
        return Err(HarnessError::Process(format!(
            "queue saturation reported drain bound {}, expected {}",
            evidence.physical_drain_observation_bound, DRAIN_OBSERVATION_BOUND
        )));
    }
    if evidence.physical_drain_observations == 0
        || evidence.physical_drain_observations > evidence.physical_drain_observation_bound
    {
        return Err(HarnessError::Process(format!(
            "queue saturation drained in {} observations, outside 1..={}",
            evidence.physical_drain_observations, evidence.physical_drain_observation_bound
        )));
    }
    if evidence.rotation_committed_generation <= evidence.paused_generation {
        return Err(HarnessError::Process(format!(
            "queue saturation rotation committed generation {} which does not follow the paused carrier generation {}",
            evidence.rotation_committed_generation, evidence.paused_generation
        )));
    }
    if evidence.rotations_completed_after_drain < SATURATION_ROTATION_COUNT {
        return Err(HarnessError::Process(format!(
            "queue saturation completed {} same-owner rotations after the drain, expected {}",
            evidence.rotations_completed_after_drain, SATURATION_ROTATION_COUNT
        )));
    }
    if evidence.final_generation
        != evidence
            .paused_generation
            .saturating_add(evidence.rotations_completed_after_drain)
    {
        return Err(HarnessError::Process(format!(
            "queue saturation ended at generation {} after {} rotations from generation {}; generations must advance by exactly one per rotation and never rewind",
            evidence.final_generation,
            evidence.rotations_completed_after_drain,
            evidence.paused_generation
        )));
    }
    if evidence.rotation_attempts_with_observed_deadline == 0 {
        return Err(HarnessError::Process(
            "queue saturation observed no rotation attempt deadline twice, so it cannot claim the deadline was never extended"
                .into(),
        ));
    }
    if evidence.device_socket_peak_open > 3 {
        return Err(HarnessError::Process(format!(
            "queue saturation device sockets exceeded the bounded three-socket peak: {}",
            evidence.device_socket_peak_open
        )));
    }
    if evidence.dispatch_delta_after_drain != 0 {
        return Err(HarnessError::Process(format!(
            "queue saturation recorded {} additional application dispatches after the drain; a drained queue must not replay",
            evidence.dispatch_delta_after_drain
        )));
    }
    Ok(())
}

/// One bounded, comparable terminal observation for the cancelled stream.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TerminalObservation {
    stream_present: bool,
    terminal: bool,
    last_emitted_relay_to_connector: u64,
    peer_acked_relay_to_connector: u64,
    recv_contiguous_connector_to_relay: u64,
    delivered_contiguous_connector_to_relay: u64,
    terminal_events: usize,
    terminal_receipts: usize,
}

impl TerminalObservation {
    /// The first terminal observation is retained: the terminal event count
    /// never changes, and while the tombstone is still present it remains
    /// terminal at the same relay-side final emitted sequence.  A reclaimed
    /// stream (STREAM_FORGET after the connector's receipt) is absent with
    /// its retained terminal event intact.
    fn retains_first_terminal(&self, first: &Self) -> bool {
        self.terminal_events == first.terminal_events
            && first.stream_present
            && first.terminal
            && (!self.stream_present
                || (self.terminal
                    && self.last_emitted_relay_to_connector
                        == first.last_emitted_relay_to_connector))
    }

    /// Connector-side progress since `previous` must be monotonic while the
    /// tombstone is present, the ACK cursor may never pass the relay's final
    /// sequence, at most one independent terminal receipt may be recorded,
    /// and a reclaimed stream never reappears.
    fn advances_bounded(&self, previous: &Self) -> bool {
        if !previous.stream_present {
            return !self.stream_present && self.terminal_receipts == previous.terminal_receipts;
        }
        if !self.stream_present {
            return self.terminal_receipts >= previous.terminal_receipts
                && self.terminal_receipts <= 1;
        }
        self.peer_acked_relay_to_connector >= previous.peer_acked_relay_to_connector
            && self.peer_acked_relay_to_connector <= self.last_emitted_relay_to_connector
            && self.recv_contiguous_connector_to_relay
                >= previous.recv_contiguous_connector_to_relay
            && self.delivered_contiguous_connector_to_relay
                >= previous.delivered_contiguous_connector_to_relay
            && self.delivered_contiguous_connector_to_relay
                <= self.recv_contiguous_connector_to_relay
            && self.terminal_receipts >= previous.terminal_receipts
            && self.terminal_receipts <= 1
    }
}

/// Snapshot of the owner session's bounded queue accounting.
#[derive(Clone, Copy, Debug)]
struct QueueObservation {
    queue_bytes: usize,
    queue_bytes_limit: usize,
    queue_bytes_high_water: usize,
    control_reserved_bytes: usize,
    data_bytes_limit: usize,
    data_bytes_high_water: usize,
    control_depth: usize,
    control_capacity: usize,
    control_depth_high_water: usize,
    control_refusals: u64,
    data_depth: Option<usize>,
    data_capacity: Option<usize>,
    data_depth_high_water: usize,
    data_refusals: u64,
    control_enqueued: u64,
    data_enqueued: u64,
    active_generation: u64,
    candidate_generation: Option<u64>,
    rotations_completed: u64,
    rotation_started_at_ms: Option<u64>,
    rotation_deadline_ms: Option<u64>,
    sockets: u8,
    live_streams: usize,
}

/// Run the bounded real three-relay configured saturation gate.
pub(super) async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<QueueSaturationEvidence> {
    let owner_device_addr = {
        let relay = cluster.relay("relay-a")?;
        relay
            .running
            .as_ref()
            .map(|running| running.device_addr)
            .ok_or_else(|| {
                HarnessError::Process("queue saturation owner relay is not running".into())
            })?
    };
    // Bind the paused socket directly in front of the owner relay's device
    // listener, with the smallest permitted target receive buffer, so the exact
    // carrier this gate pauses is the one whose physical writer blocks.
    let device_proxy = TcpProxy::bind(
        owner_device_addr,
        ProxyConfig {
            target_receive_buffer_bytes: Some(PAUSED_TARGET_RECEIVE_BUFFER_BYTES),
            ..ProxyConfig::default()
        },
    )
    .await?;
    let scenario = run_with_proxy(cluster, harness, &device_proxy).await;
    let proxy_cleanup = match timeout(super::CLEANUP_TIMEOUT, device_proxy.shutdown()).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "queue saturation device proxy cleanup timed out".into(),
        )),
    };
    match (scenario, proxy_cleanup) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(evidence), Ok(())) => Ok(evidence),
    }
}

async fn run_with_proxy(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    device_proxy: &ProxyHandle,
) -> Result<QueueSaturationEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "queue saturation gate started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    let membership_ready_relays = cluster
        .relays
        .iter()
        .filter(|relay| {
            matches!(
                relay.membership.readiness(),
                tunnel_relay::MembershipReadiness::Ready
            )
        })
        .count();
    if membership_ready_relays != 3 {
        return Err(HarnessError::Process(format!(
            "queue saturation gate started with {membership_ready_relays}/3 relays Ready"
        )));
    }

    let device =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("queue saturation device is missing".into())
        })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("queue saturation service is missing".into()))?;
    let canary = format!("m7-queue-saturation:{}", device.id);
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_directory.path(),
        device.id,
        service_id,
        &canary,
        device_proxy.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = SATURATION_ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("queue saturation client config: {error}"))
    })?;

    let mut client = connect_client(profile.config.clone()).await?;
    let session = match timeout(STARTUP_TIMEOUT, client.wait_ready()).await {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => {
            let _ = client.stop().await;
            return Err(HarnessError::Process(format!(
                "queue saturation client not ready: {error}"
            )));
        }
        Err(_) => {
            let _ = client.stop().await;
            return Err(HarnessError::Timeout(
                "queue saturation client readiness timed out".into(),
            ));
        }
    };

    let outcome = run_saturation(
        cluster,
        harness,
        device_proxy,
        &mut client,
        device.tenant_id,
        device.id,
        service_id,
        &canary,
        &session.session_id,
        membership_ready_relays,
        started,
    )
    .await;
    let _ = device_proxy.resume_all().await;
    let stop = client.stop().await;
    match (outcome, stop) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(HarnessError::Process(format!(
            "queue saturation client shutdown failed: {error}"
        ))),
        (Ok(evidence), Ok(())) => Ok(evidence),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_saturation(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    device_proxy: &ProxyHandle,
    client: &mut ConnectionHandle,
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    canary: &str,
    session_id: &str,
    membership_ready_relays: usize,
    started: Instant,
) -> Result<QueueSaturationEvidence> {
    let owner_relay = cluster.relay("relay-a")?;
    let owner = cluster
        .catalog
        .current_owner(tenant_id, device_id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading queue saturation owner: {error}")))?
        .ok_or_else(|| {
            HarnessError::Process("queue saturation client did not retain an owner".into())
        })?;
    if owner.token.node_id != "relay-a" || owner.token.session_id != session_id {
        return Err(HarnessError::Process(format!(
            "queue saturation owner landed on {} session {}",
            owner.token.node_id, owner.token.session_id
        )));
    }

    // Every consumer stream enters through relay-c, which is not the owner.
    let ingress = cluster.relay("relay-c")?;
    let ingress_addr = ingress.consumer_addr()?;
    let non_owner_ingress = ingress.node_id != owner.token.node_id;
    if !non_owner_ingress {
        return Err(HarnessError::Process(
            "queue saturation ingress relay must not be the owner".into(),
        ));
    }
    let token = harness.oidc.issue(&harness.topology.consumers_a[0].name)?;

    let baseline = read_queue_observation(owner_relay, device_id).await?;
    let queue_bytes_limit = baseline.queue_bytes_limit;
    let control_reserved_bytes = baseline.control_reserved_bytes;
    let data_bytes_limit = baseline.data_bytes_limit;
    let control_capacity = baseline.control_capacity;
    let data_capacity = baseline.data_capacity.ok_or_else(|| {
        HarnessError::Process(
            "queue saturation owner session has no attached data carrier to saturate".into(),
        )
    })?;
    let max_streams = EXPECTED_MAX_STREAMS_PER_DEVICE;
    let reachable = reachable_entries(SATURATION_RECORD_BYTES, data_bytes_limit, max_streams);
    let route_maximum = (1..=MAX_PAYLOAD_BYTES)
        .map(|body| reachable_entries(body, data_bytes_limit, max_streams))
        .max()
        .unwrap_or(0);
    if reachable != route_maximum {
        return Err(HarnessError::Process(format!(
            "queue saturation record size reaches {reachable} entries but {route_maximum} are reachable on this route"
        )));
    }

    // Admit exactly the per-device cap, then prove the next admission is
    // refused.  That is what makes the stream cap, rather than the
    // message-queue bound, demonstrably the binding constraint.
    let mut streams = Vec::with_capacity(max_streams);
    for index in 0..max_streams {
        let mut stream = open_consumer_stream(
            ingress_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device_id,
            service_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;
        stream
            .round_trip(
                format!("m7-queue-saturation-warmup-{index}").as_bytes(),
                canary.as_bytes(),
            )
            .await?;
        streams.push(stream);
    }
    let streams_admitted = streams.len();
    let stream_cap_refused_one_more = matches!(
        open_consumer_stream(
            ingress_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device_id,
            service_id,
        )
        .await,
        Err(StreamConnectFailure::Status { .. })
    );
    if !stream_cap_refused_one_more {
        return Err(HarnessError::Process(format!(
            "queue saturation admitted a stream beyond the {max_streams} per-device cap"
        )));
    }

    // Bind the paused socket directly: correlate the proxy connection to the
    // carrier's own local address, never by ordinal.
    let status = client.status_snapshot();
    let paused_connection = correlate_data_connection(device_proxy, &status)?;
    let paused_generation = read_queue_observation(owner_relay, device_id)
        .await?
        .active_generation;
    if paused_generation == 0 {
        return Err(HarnessError::Process(
            "queue saturation owner reported no active carrier generation".into(),
        ));
    }
    let before_pause = read_queue_observation(owner_relay, device_id).await?;
    let control_enqueued_before_pause = before_pause.control_enqueued;
    let data_enqueued_before_pause = before_pause.data_enqueued;
    device_proxy
        .pause(Direction::TargetToClient, paused_connection)
        .await?;
    let paused_at = Instant::now();
    let paused_target_to_client = device_proxy.stats().paused_target_to_client;
    if paused_target_to_client == 0 {
        return Err(HarnessError::Process(
            "queue saturation proxy did not acknowledge the exact target-to-client pause".into(),
        ));
    }

    // Offer one in-flight record on every admitted stream.  The consumer
    // ingress admits no second record per stream, so this is the complete
    // reachable residency.
    let cancellation = CancellationToken::new();
    let mut pumps = Vec::with_capacity(streams.len());
    for stream in streams {
        pumps.push(tokio::spawn(pump_one_record(stream, cancellation.clone())));
    }

    let measured = measure_peak_residency(
        owner_relay,
        device_id,
        reachable,
        paused_at,
        data_enqueued_before_pause,
    )
    .await;
    let measured = match measured {
        Ok(value) => value,
        Err(error) => {
            abandon(&cancellation, pumps, device_proxy, paused_connection).await;
            return Err(error);
        }
    };

    // Reserved capacity, proven at peak residency from diagnostics alone so the
    // bounded blackhole window is not spent on handshakes.
    let probes = probe_reserved_capacity_at_peak(
        owner_relay,
        device_id,
        data_capacity,
        control_enqueued_before_pause,
        &measured,
    )
    .await;
    let probes = match probes {
        Ok(value) => value,
        Err(error) => {
            abandon(&cancellation, pumps, device_proxy, paused_connection).await;
            return Err(error);
        }
    };

    // Resume the exact paused direction and require physical drain within a
    // fixed bounded number of observations.
    device_proxy
        .resume(Direction::TargetToClient, paused_connection)
        .await?;
    let drain = wait_for_physical_drain(owner_relay, device_id).await?;
    cancellation.cancel();
    let mut surviving = Vec::new();
    for pump in pumps {
        if let Ok(Ok(Ok(stream))) = timeout(Duration::from_secs(5), pump).await {
            surviving.push(stream);
        }
    }

    // A real cancellation, now that the carrier is writable: close one stream
    // and require the owner to retire exactly that stream.
    let live_before_cancel = owner_live_stream_ids(owner_relay, device_id).await?;
    if live_before_cancel.is_empty() {
        return Err(HarnessError::Process(
            "queue saturation had no live stream to cancel".into(),
        ));
    }
    if let Some(mut stream) = surviving.pop() {
        let _ = timeout(Duration::from_secs(5), stream.close()).await;
    }
    let cancellation_accepted_after_resume =
        wait_for_stream_retirement(owner_relay, device_id, live_before_cancel.len()).await?;
    // The public stream carries no owner stream id, so the cancelled stream is
    // the exact one that left the live set: the terminal observation below
    // must sample that stream, not whichever live stream sorts first.
    let live_after_cancel = owner_live_stream_ids(owner_relay, device_id).await?;
    let retired: Vec<u64> = live_before_cancel
        .iter()
        .copied()
        .filter(|stream_id| !live_after_cancel.contains(stream_id))
        .collect();
    let cancelled_stream_id = match retired.as_slice() {
        [stream_id] => *stream_id,
        _ => {
            return Err(HarnessError::Process(format!(
                "queue saturation cancellation retired {} streams, expected exactly one",
                retired.len()
            )));
        }
    };

    // An immutable first-terminal observation for the cancelled stream: the
    // retained terminal event count may not change once observed, and while
    // the tombstone is present it stays terminal at the relay's final
    // emitted sequence.  The connector may still deliver the ACK for the
    // relay's FIN, the reply to a record it already held when the owner
    // cancelled, and its own FIN receipt, after which STREAM_FORGET reclaims
    // the tombstone: connector-side cursors and the receipt are therefore
    // required to be monotonic and bounded rather than frozen, and the
    // stream may leave the live set exactly once and never return.
    let first_terminal =
        read_terminal_observation(owner_relay, device_id, cancelled_stream_id).await?;
    let mut terminal_observations = 0usize;
    let mut first_terminal_observation_immutable = true;
    let mut previous = first_terminal.clone();
    for _ in 0..TERMINAL_IMMUTABILITY_SAMPLES {
        sleep(TERMINAL_SAMPLE_INTERVAL).await;
        let again = read_terminal_observation(owner_relay, device_id, cancelled_stream_id).await?;
        terminal_observations += 1;
        if !again.retains_first_terminal(&first_terminal) || !again.advances_bounded(&previous) {
            tracing::warn!(
                stream_id = cancelled_stream_id,
                first = ?first_terminal,
                previous = ?previous,
                again = ?again,
                sample = terminal_observations,
                "queue saturation terminal observation changed"
            );
            first_terminal_observation_immutable = false;
            break;
        }
        previous = again;
    }

    // The freed slot at the per-device cap must be usable again through the
    // non-owner ingress.
    let fresh_stream_admitted_after_cancellation = match timeout(
        ADMISSION_TIMEOUT,
        open_consumer_stream(
            ingress_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device_id,
            service_id,
        ),
    )
    .await
    {
        Ok(Ok(mut fresh)) => {
            let _ = fresh.close().await;
            true
        }
        Ok(Err(_)) | Err(_) => false,
    };

    // A stream untouched by the cancellation must still work after the drain.
    //
    // Each surviving stream still owes the echo of the record it offered while
    // the carrier was blackholed.  Requiring that exact response first is
    // stronger than skipping it: it proves the queued record was delivered and
    // echoed rather than dropped when the queue drained.  A fresh round trip on
    // the same stream then proves the stream is still usable.
    let saturation_payload = vec![b'q'; SATURATION_RECORD_BYTES];
    let mut sibling_stream_survived = false;
    for stream in surviving.iter_mut() {
        let queued_record_echoed = timeout(
            SIBLING_TIMEOUT,
            expect_echo(stream, &saturation_payload, canary.as_bytes()),
        )
        .await
        .is_ok_and(|result| result.is_ok());
        if !queued_record_echoed {
            continue;
        }
        if timeout(
            SIBLING_TIMEOUT,
            stream.round_trip(b"m7-queue-saturation-sibling-after", canary.as_bytes()),
        )
        .await
        .is_ok_and(|result| result.is_ok())
        {
            sibling_stream_survived = true;
            break;
        }
    }

    let dispatches_after_drain = total_application_dispatches(cluster).await?;
    sleep(Duration::from_millis(500)).await;
    let dispatch_delta_after_drain = total_application_dispatches(cluster)
        .await?
        .saturating_sub(dispatches_after_drain);

    // Correlate the exact rotation attempt: the scheduled handover that
    // follows must replace the carrier this gate paused.
    let rotation = wait_for_correlated_rotation(owner_relay, device_id, paused_generation).await?;

    for stream in surviving.iter_mut() {
        let _ = stream.close().await;
    }

    let device_socket_peak_open =
        usize::try_from(device_proxy.diagnostics().peak_active).unwrap_or(usize::MAX);
    let physically_resident_frames = measured.data_depth_high_water.saturating_add(1);

    Ok(QueueSaturationEvidence {
        relay_count: cluster.relays.len(),
        membership_ready_relays,
        non_owner_ingress,
        configured_queue_bytes_limit: queue_bytes_limit,
        configured_control_reserved_bytes: control_reserved_bytes,
        configured_data_bytes_limit: data_bytes_limit,
        configured_data_queue_capacity: data_capacity,
        configured_control_queue_capacity: control_capacity,
        configured_max_streams_per_device: max_streams,
        workload_record_bytes: SATURATION_RECORD_BYTES,
        workload_charge_per_record_bytes: charge_per_record(SATURATION_RECORD_BYTES),
        workload_frames_per_record: frames_per_record(SATURATION_RECORD_BYTES),
        workload_streams: streams_admitted,
        workload_records_per_stream_by_credit: records_per_stream_by_credit(
            SATURATION_RECORD_BYTES,
        ),
        workload_reachable_entries: reachable,
        route_maximum_reachable_entries: route_maximum,
        streams_admitted,
        stream_cap_refused_one_more,
        data_queue_depth_observed: measured.data_depth.unwrap_or(0),
        data_queue_depth_high_water: measured.data_depth_high_water,
        data_enqueues_during_blackhole: measured
            .data_enqueued
            .saturating_sub(data_enqueued_before_pause),
        physically_resident_frames,
        writer_absorbed_frames: reachable.saturating_sub(physically_resident_frames),
        writer_absorbed_wire_bytes: reachable
            .saturating_sub(physically_resident_frames)
            .saturating_mul(wire_bytes_per_record(SATURATION_RECORD_BYTES)),
        reachable_bound_saturated: measured
            .data_enqueued
            .saturating_sub(data_enqueued_before_pause)
            >= u64::try_from(reachable).unwrap_or(u64::MAX)
            && physically_resident_frames >= MIN_RESIDENT_FRAMES,
        reserved_free_data_slots_at_peak: data_capacity
            .saturating_sub(measured.data_depth_high_water),
        reserved_data_slot_accepted_at_peak: probes.reserved_data_slot_accepted,
        control_enqueues_during_blackhole: probes.control_enqueues_during_blackhole,
        queue_bytes_high_water: measured
            .queue_bytes_high_water
            .max(drain.queue_bytes_high_water),
        data_bytes_high_water: measured
            .data_bytes_high_water
            .max(drain.data_bytes_high_water),
        control_bytes_available_at_data_peak: queue_bytes_limit.saturating_sub(
            measured
                .data_bytes_high_water
                .max(drain.data_bytes_high_water),
        ),
        queue_bytes_headroom_at_peak: queue_bytes_limit.saturating_sub(measured.queue_bytes),
        control_queue_depth_at_peak: measured.control_depth,
        control_queue_depth_high_water: drain
            .control_depth_high_water
            .max(measured.control_depth_high_water),
        control_queue_refusals: drain.control_refusals.max(measured.control_refusals),
        cancellation_accepted_after_resume,
        fresh_stream_admitted_after_cancellation,
        sibling_stream_survived,
        first_terminal_observation_immutable,
        terminal_observations,
        paused_target_to_client,
        paused_connection_correlated: true,
        paused_generation,
        physical_drain_observations: drain.observations,
        physical_drain_observation_bound: DRAIN_OBSERVATION_BOUND,
        physical_drain_completed: drain.completed,
        rotation_replaced_paused_carrier: rotation.replaced_paused_carrier,
        rotation_committed_generation: rotation.committed_generation,
        rotations_completed_after_drain: rotation.rotations_completed,
        final_generation: rotation.final_generation,
        rotation_attempts_with_observed_deadline: rotation.attempts_with_observed_deadline,
        rotation_deadline_never_extended: rotation.deadline_never_extended,
        rotation_deadline_within_configured_overlap: rotation.deadline_within_configured_overlap,
        device_socket_peak_open,
        dispatch_delta_after_drain,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

async fn abandon(
    cancellation: &CancellationToken,
    pumps: Vec<tokio::task::JoinHandle<Result<ConsumerStream>>>,
    device_proxy: &ProxyHandle,
    paused_connection: ConnectionId,
) {
    cancellation.cancel();
    for pump in pumps {
        pump.abort();
        let _ = pump.await;
    }
    let _ = device_proxy
        .resume(Direction::TargetToClient, paused_connection)
        .await;
}

/// Offer exactly one record on one stream and hold the stream open.
///
/// The device's physical response path is blackholed, so the response never
/// arrives; the consumer ingress admits no second record on this stream while
/// the first is in flight, which is precisely the residency bound being
/// measured.  The stream is returned so the caller can cancel or reuse it
/// deterministically.
async fn pump_one_record(
    mut stream: ConsumerStream,
    cancellation: CancellationToken,
) -> Result<ConsumerStream> {
    let payload = vec![b'q'; SATURATION_RECORD_BYTES];
    let length = u32::try_from(payload.len()).map_err(|_| {
        HarnessError::InvalidInput("queue saturation record length overflow".into())
    })?;
    let mut frame = Vec::with_capacity(payload.len() + RECORD_PREFIX_BYTES);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    let send = stream.socket.send(Message::Binary(frame.into()));
    tokio::select! {
        () = cancellation.cancelled() => return Ok(stream),
        result = send => {
            if result.is_err() {
                return Ok(stream);
            }
        }
    }
    cancellation.cancelled().await;
    Ok(stream)
}

/// Poll the owner until the reachable physical residency is reached, and
/// return that observation together with the live stream roster taken from the
/// same snapshot, so no extra actor round trip is spent inside the bounded
/// blackhole window.
async fn measure_peak_residency(
    owner: &ProductionRelay,
    device_id: Uuid,
    reachable: usize,
    paused_at: Instant,
    data_enqueued_before_pause: u64,
) -> Result<QueueObservation> {
    let deadline = Instant::now() + SATURATION_TIMEOUT;
    let mut best = read_queue_observation(owner, device_id).await?;
    loop {
        let observation = read_queue_observation(owner, device_id).await?;
        if observation.data_depth_high_water >= best.data_depth_high_water {
            best = observation;
        }
        if observation.queue_bytes > observation.queue_bytes_limit {
            return Err(HarnessError::Process(format!(
                "queue saturation exceeded the configured session byte budget: {} of {}",
                observation.queue_bytes, observation.queue_bytes_limit
            )));
        }
        // The latched high water survives carrier teardown, so a live carrier
        // is a precondition: a detached carrier can never be the peak-residency
        // observation this gate reports.
        if observation.data_depth.is_none() {
            return Err(HarnessError::Process(format!(
                "queue saturation lost the blackholed carrier {} ms after the pause, before peak residency: high_water={} resident={} reachable={reachable} queue_bytes={} enqueued={} refusals={}",
                paused_at.elapsed().as_millis(),
                best.data_depth_high_water,
                best.data_depth_high_water.saturating_add(1),
                best.queue_bytes,
                best.data_enqueued,
                best.data_refusals
            )));
        }
        // The workload is fully offered once the relay has accepted one
        // in-flight record per admitted stream.  Simultaneous residency is then
        // read from the latched channel high water; the difference is the socket
        // absorption the caller accounts for.
        if observation
            .data_enqueued
            .saturating_sub(data_enqueued_before_pause)
            >= u64::try_from(reachable).unwrap_or(u64::MAX)
        {
            return Ok(observation);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Process(format!(
                "queue saturation reached only {} resident frames of the reachable {reachable} in {} ms: depth={:?} high_water={} enqueued={} refusals={} queue_bytes={} of {} control_depth={} control_refusals={} live_streams={}",
                best.data_depth_high_water.saturating_add(1),
                paused_at.elapsed().as_millis(),
                best.data_depth,
                best.data_depth_high_water,
                best.data_enqueued,
                best.data_refusals,
                best.queue_bytes,
                best.queue_bytes_limit,
                best.control_depth,
                best.control_refusals,
                best.live_streams
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

struct ReservedCapacityProbes {
    control_enqueues_during_blackhole: u64,
    reserved_data_slot_accepted: bool,
}

/// Prove reserved bounded capacity at peak physical residency.
///
/// Control, cancellation, revocation and rotation control all reach the
/// connector through the one bounded control channel and the one shared byte
/// budget.  At peak residency this requires, from relay diagnostics only, that
/// no control enqueue was refused, that control slots remain free, that the
/// shared byte budget retains its documented headroom, that the reserved half
/// of the data channel is free, and that the relay's accepted-control-enqueue
/// counter advanced during the blackhole window.  The last condition is what
/// distinguishes live reserved capacity from capacity that merely happened not
/// to be exercised.
///
/// Only snapshots are taken here.  The blackholed carrier has a five-second
/// physical write bound, so this window must not spend time on handshakes; real
/// cancellation and fresh admission run after the resume.
async fn probe_reserved_capacity_at_peak(
    owner: &ProductionRelay,
    device_id: Uuid,
    data_capacity: usize,
    control_enqueued_before_pause: u64,
    at_peak: &QueueObservation,
) -> Result<ReservedCapacityProbes> {
    if at_peak.control_depth >= at_peak.control_capacity || at_peak.control_refusals != 0 {
        return Err(HarnessError::Process(format!(
            "queue saturation starved reserved control capacity at peak residency: control_depth={} capacity={} refusals={}",
            at_peak.control_depth, at_peak.control_capacity, at_peak.control_refusals
        )));
    }
    let reserved_data_slot_accepted = at_peak.data_depth.is_some_and(|depth| {
        data_capacity.saturating_sub(depth) >= EXPECTED_MAX_STREAMS_PER_DEVICE - 1
    });
    if !reserved_data_slot_accepted {
        return Err(HarnessError::Process(format!(
            "queue saturation left no reserved free data slot at peak residency: depth={:?} capacity={data_capacity}",
            at_peak.data_depth
        )));
    }

    // Require the accepted-control-enqueue counter to advance while the data
    // channel stays physically occupied.  The relay's challenge cadence and
    // stream bookkeeping both emit control, and the control socket is not
    // paused, so a stalled counter would mean control had been starved.
    let deadline = Instant::now() + CONTROL_PROGRESS_TIMEOUT;
    let mut best = *at_peak;
    loop {
        let observation = read_queue_observation(owner, device_id).await?;
        if observation.control_refusals != 0 {
            return Err(HarnessError::Process(format!(
                "queue saturation refused {} control enqueues while the data channel was physically occupied",
                observation.control_refusals
            )));
        }
        if observation.control_enqueued > best.control_enqueued {
            best = observation;
        }
        if observation.data_depth.is_none() {
            return Err(HarnessError::Process(format!(
                "queue saturation lost its blackholed carrier before reserved control capacity could be observed: control_enqueued={} before_pause={}",
                best.control_enqueued, control_enqueued_before_pause
            )));
        }
        let progressed = best
            .control_enqueued
            .saturating_sub(control_enqueued_before_pause);
        if progressed > 0 {
            return Ok(ReservedCapacityProbes {
                control_enqueues_during_blackhole: progressed,
                reserved_data_slot_accepted,
            });
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Process(format!(
                "queue saturation observed no accepted control enqueue during the blackhole window: control_enqueued={} before_pause={} control_depth={} data_depth={:?}",
                best.control_enqueued,
                control_enqueued_before_pause,
                best.control_depth,
                best.data_depth
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

struct DrainOutcome {
    observations: usize,
    completed: bool,
    queue_bytes_high_water: usize,
    data_bytes_high_water: usize,
    control_depth_high_water: usize,
    control_refusals: u64,
}

/// Require physical occupancy to return to zero within a fixed bounded number
/// of observations after the exact paused direction is resumed.
async fn wait_for_physical_drain(owner: &ProductionRelay, device_id: Uuid) -> Result<DrainOutcome> {
    let mut last = read_queue_observation(owner, device_id).await?;
    for observation in 1..=DRAIN_OBSERVATION_BOUND {
        let current = read_queue_observation(owner, device_id).await?;
        last = current;
        if current.data_depth.is_none_or(|depth| depth == 0) {
            return Ok(DrainOutcome {
                observations: observation,
                completed: true,
                queue_bytes_high_water: current.queue_bytes_high_water,
                data_bytes_high_water: current.data_bytes_high_water,
                control_depth_high_water: current.control_depth_high_water,
                control_refusals: current.control_refusals,
            });
        }
        sleep(DRAIN_POLL_INTERVAL).await;
    }
    Err(HarnessError::Process(format!(
        "queue saturation did not physically drain within {DRAIN_OBSERVATION_BOUND} observations: depth={:?} queue_bytes={} control_refusals={}",
        last.data_depth, last.queue_bytes, last.control_refusals
    )))
}

/// Wait for the owner to retire exactly one stream after a cancellation.
async fn wait_for_stream_retirement(
    owner: &ProductionRelay,
    device_id: Uuid,
    live_before: usize,
) -> Result<bool> {
    let deadline = Instant::now() + ADMISSION_TIMEOUT;
    loop {
        let observation = read_queue_observation(owner, device_id).await?;
        if observation.control_refusals != 0 {
            return Err(HarnessError::Process(format!(
                "queue saturation refused {} control enqueues while cancelling",
                observation.control_refusals
            )));
        }
        if observation.live_streams < live_before {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Process(format!(
                "queue saturation cancellation did not retire a stream: live={} before={live_before}",
                observation.live_streams
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

struct RotationCorrelation {
    replaced_paused_carrier: bool,
    committed_generation: u64,
    rotations_completed: u64,
    final_generation: u64,
    attempts_with_observed_deadline: usize,
    deadline_never_extended: bool,
    deadline_within_configured_overlap: bool,
}

/// Correlate the exact rotation attempt that follows the drain, then carry the
/// same owner through three same-owner rotations.
///
/// The carrier this gate paused must be the one the first scheduled handover
/// replaces: its generation is the immediate predecessor of the first committed
/// generation and a candidate was observed while it was still active.  Across
/// every attempt the socket bound holds, generations advance by exactly one and
/// never rewind, and each attempt keeps **one absolute deadline** that no phase
/// change extends and that never exceeds the configured overlap measured from
/// that attempt's own start.
async fn wait_for_correlated_rotation(
    owner: &ProductionRelay,
    device_id: Uuid,
    paused_generation: u64,
) -> Result<RotationCorrelation> {
    let deadline = Instant::now() + ROTATION_TIMEOUT;
    let overlap_ms = SATURATION_ROTATION.overlap_seconds.saturating_mul(1_000);
    let mut observed_candidate_for_paused_carrier = false;
    let mut first_committed_generation = None;
    let mut highest_generation = paused_generation;
    // One entry per attempt, keyed by its candidate generation:
    // (candidate, started_at_ms, deadline_ms, samples).
    let mut attempts: Vec<(u64, u64, u64, usize)> = Vec::new();
    let mut deadline_never_extended = true;
    let mut deadline_within_configured_overlap = true;
    loop {
        let observation = read_queue_observation(owner, device_id).await?;
        if observation.sockets > 3 {
            return Err(HarnessError::Process(format!(
                "queue saturation rotation exposed {} device sockets, above the bounded three",
                observation.sockets
            )));
        }
        if observation.active_generation < highest_generation {
            return Err(HarnessError::Process(format!(
                "queue saturation rotation rewound the active generation from {highest_generation} to {}",
                observation.active_generation
            )));
        }
        highest_generation = highest_generation.max(observation.active_generation);
        if observation.active_generation == paused_generation
            && observation.candidate_generation.is_some()
        {
            observed_candidate_for_paused_carrier = true;
        }
        if let (Some(candidate), Some(started), Some(attempt_deadline)) = (
            observation.candidate_generation,
            observation.rotation_started_at_ms,
            observation.rotation_deadline_ms,
        ) {
            match attempts
                .iter_mut()
                .find(|(generation, _, _, _)| *generation == candidate)
            {
                Some((_, recorded_start, recorded_deadline, samples)) => {
                    if *recorded_deadline != attempt_deadline || *recorded_start != started {
                        deadline_never_extended = false;
                    }
                    *samples = samples.saturating_add(1);
                }
                None => {
                    if attempt_deadline.saturating_sub(started) > overlap_ms {
                        deadline_within_configured_overlap = false;
                    }
                    attempts.push((candidate, started, attempt_deadline, 1));
                }
            }
        }
        if observation.candidate_generation.is_none()
            && observation.active_generation > paused_generation
        {
            if first_committed_generation.is_none() {
                first_committed_generation = Some(observation.active_generation);
            }
            if observation.rotations_completed >= SATURATION_ROTATION_COUNT {
                let committed_generation =
                    first_committed_generation.unwrap_or(observation.active_generation);
                return Ok(RotationCorrelation {
                    replaced_paused_carrier: observed_candidate_for_paused_carrier
                        && committed_generation == paused_generation.saturating_add(1),
                    committed_generation,
                    rotations_completed: observation.rotations_completed,
                    final_generation: observation.active_generation,
                    attempts_with_observed_deadline: attempts
                        .iter()
                        .filter(|(_, _, _, samples)| *samples >= 2)
                        .count(),
                    deadline_never_extended,
                    deadline_within_configured_overlap,
                });
            }
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "queue saturation did not observe {SATURATION_ROTATION_COUNT} same-owner rotations of the paused carrier: active={} candidate={:?} rotations={} paused={paused_generation} attempts_seen={}",
                observation.active_generation,
                observation.candidate_generation,
                observation.rotations_completed,
                attempts.len()
            )));
        }
        sleep(DRAIN_POLL_INTERVAL).await;
    }
}

async fn read_queue_observation(
    owner: &ProductionRelay,
    device_id: Uuid,
) -> Result<QueueObservation> {
    let snapshot = owner.snapshot().await?;
    let session = snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
        .ok_or_else(|| {
            HarnessError::Process(
                "queue saturation owner snapshot lost the live device session".into(),
            )
        })?;
    Ok(QueueObservation {
        queue_bytes: session.queue_bytes,
        queue_bytes_limit: session.queue_bytes_limit,
        queue_bytes_high_water: session.queue_bytes_high_water,
        control_reserved_bytes: session.control_reserved_bytes,
        data_bytes_limit: session.data_bytes_limit,
        data_bytes_high_water: session.data_bytes_high_water,
        control_depth: session.control_queue_depth,
        control_capacity: session.control_queue_capacity,
        control_depth_high_water: session.control_queue_depth_high_water,
        control_refusals: session.control_queue_refusals,
        data_depth: session.data_queue_depth,
        data_capacity: session.data_queue_capacity,
        data_depth_high_water: session.data_queue_depth_high_water,
        data_refusals: session.data_queue_refusals,
        control_enqueued: session.control_queue_enqueued,
        data_enqueued: session.data_queue_enqueued,
        active_generation: session.active_generation,
        candidate_generation: session.candidate_generation,
        rotations_completed: session.rotations_completed,
        rotation_started_at_ms: session.rotation_started_at_ms,
        rotation_deadline_ms: session.rotation_deadline_ms,
        sockets: session.sockets,
        live_streams: session
            .streams
            .iter()
            .filter(|stream| !stream.terminal)
            .count(),
    })
}

async fn owner_live_stream_ids(owner: &ProductionRelay, device_id: Uuid) -> Result<Vec<u64>> {
    let snapshot = owner.snapshot().await?;
    let session = snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
        .ok_or_else(|| {
            HarnessError::Process(
                "queue saturation owner snapshot lost the live device session".into(),
            )
        })?;
    Ok(session
        .streams
        .iter()
        .filter(|stream| !stream.terminal)
        .map(|stream| stream.stream_id)
        .collect())
}

async fn read_terminal_observation(
    owner: &ProductionRelay,
    device_id: Uuid,
    stream_id: u64,
) -> Result<TerminalObservation> {
    let snapshot = owner.snapshot().await?;
    let session = snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string());
    let stream = session.and_then(|session| {
        session
            .streams
            .iter()
            .find(|stream| stream.stream_id == stream_id)
    });
    Ok(TerminalObservation {
        stream_present: stream.is_some(),
        terminal: stream.is_some_and(|stream| stream.terminal),
        last_emitted_relay_to_connector: stream
            .map_or(0, |stream| stream.last_emitted_relay_to_connector),
        peer_acked_relay_to_connector: stream
            .map_or(0, |stream| stream.peer_acked_relay_to_connector),
        recv_contiguous_connector_to_relay: stream
            .map_or(0, |stream| stream.recv_contiguous_connector_to_relay),
        delivered_contiguous_connector_to_relay: stream
            .map_or(0, |stream| stream.delivered_contiguous_connector_to_relay),
        terminal_events: snapshot
            .stream_terminal_events
            .iter()
            .filter(|event| event.stream_id == stream_id)
            .count(),
        terminal_receipts: snapshot
            .stream_terminal_receipt_events
            .iter()
            .filter(|event| event.stream_id == stream_id)
            .count(),
    })
}

/// Read one already-pending echo response and require it to be exactly the
/// connector canary followed by the expected payload.
///
/// This is the read half of `ConsumerStream::round_trip`, needed because the
/// saturation record was sent without awaiting its response.
async fn expect_echo(stream: &mut ConsumerStream, payload: &[u8], canary: &[u8]) -> Result<()> {
    let expected = canary.len().saturating_add(payload.len());
    let total = expected.saturating_add(4);
    let mut response = Vec::with_capacity(total);
    loop {
        match stream.socket.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                if response.len().saturating_add(bytes.len()) > total {
                    return Err(HarnessError::Http(
                        "queue saturation queued-record echo exceeded its bounded reassembly"
                            .into(),
                    ));
                }
                response.extend_from_slice(&bytes);
                if response.len() < total {
                    continue;
                }
                let declared =
                    u32::from_be_bytes([response[0], response[1], response[2], response[3]])
                        as usize;
                if declared != expected
                    || response[4..4 + canary.len()] != *canary
                    || response[4 + canary.len()..] != *payload
                {
                    return Err(HarnessError::Http(
                        "queue saturation queued-record echo did not match the offered record"
                            .into(),
                    ));
                }
                return Ok(());
            }
            Some(Ok(Message::Ping(bytes))) => {
                stream
                    .socket
                    .send(Message::Pong(bytes))
                    .await
                    .map_err(|_| HarnessError::Http("queue saturation echo pong failed".into()))?;
            }
            Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
            Some(Ok(Message::Close(_))) | None => {
                return Err(HarnessError::Http(
                    "queue saturation stream closed before its queued record was echoed".into(),
                ));
            }
            Some(Ok(Message::Text(_))) => {
                return Err(HarnessError::Http(
                    "queue saturation stream returned text".into(),
                ));
            }
            Some(Err(_)) => {
                return Err(HarnessError::Http(
                    "queue saturation stream failed before its queued record was echoed".into(),
                ));
            }
        }
    }
}

async fn total_application_dispatches(cluster: &ProductionCluster) -> Result<u64> {
    let mut total = 0_u64;
    for relay in &cluster.relays {
        total = total.saturating_add(relay.snapshot().await?.lifetime_application_dispatches);
    }
    Ok(total)
}

fn correlate_data_connection(
    proxy: &ProxyHandle,
    status: &ConnectionStatus,
) -> Result<ConnectionId> {
    let source_addr = status.active_local_addr.ok_or_else(|| {
        HarnessError::Process(
            "queue saturation client did not publish an active data socket to pause".into(),
        )
    })?;
    proxy
        .diagnostics()
        .active_connections
        .into_iter()
        .find(|connection| connection.source_addr == source_addr)
        .map(|connection| connection.id)
        .ok_or_else(|| {
            HarnessError::Process(format!(
                "queue saturation proxy did not expose the active data socket {source_addr}"
            ))
        })
}

async fn connect_client(config: tunnel_client::ConnectConfig) -> Result<ConnectionHandle> {
    timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config,
            cancellation: CancellationToken::new(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("queue saturation client startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("starting queue saturation client: {error}")))
}

#[cfg(test)]
mod tests {
    use super::TerminalObservation;
    use super::{
        DRAIN_OBSERVATION_BOUND, EXPECTED_CONTROL_RESERVED_BYTES, EXPECTED_DATA_BYTES_LIMIT,
        EXPECTED_MAX_STREAMS_PER_DEVICE, EXPECTED_QUEUE_BYTES_LIMIT, EXPECTED_QUEUE_MESSAGES,
        M2_INITIAL_WINDOW_BYTES, MAX_ABSORBED_WIRE_BYTES, MAX_PAYLOAD_BYTES, MIN_RESIDENT_FRAMES,
        MIN_SATURATION_HEADROOM_BYTES, QueueSaturationEvidence, SATURATION_RECORD_BYTES,
        SATURATION_ROTATION_COUNT, TERMINAL_IMMUTABILITY_SAMPLES, charge_per_record,
        frames_per_record, reachable_entries, records_per_stream_by_credit,
        validate_queue_saturation_evidence, wire_bytes_per_record,
    };
    use crate::acceptance_test_support::assert_rejected;

    /// The maximum-record workload an independent review rejected: prove with
    /// the real constants that it cannot fill the configured message queue.
    #[test]
    fn maximum_record_workload_cannot_fill_the_configured_message_queue() {
        let record = MAX_PAYLOAD_BYTES + 4;
        assert_eq!(frames_per_record(MAX_PAYLOAD_BYTES), 2);
        let chunks = [MAX_PAYLOAD_BYTES, record - MAX_PAYLOAD_BYTES];
        let charge: usize = chunks.iter().map(|chunk| chunk + (chunk + 64)).sum();
        assert_eq!(charge, 131_208);
        let admissible = EXPECTED_QUEUE_BYTES_LIMIT / charge;
        assert_eq!(admissible, 31);
        assert_eq!(admissible * chunks.len(), 62);
        assert!(admissible * chunks.len() < EXPECTED_QUEUE_MESSAGES);
        // Against the data byte limit that data admission actually sees, one
        // fewer maximum record fits.
        assert_eq!(EXPECTED_DATA_BYTES_LIMIT / charge, 30);
        assert_eq!(
            reachable_entries(
                MAX_PAYLOAD_BYTES,
                EXPECTED_DATA_BYTES_LIMIT,
                EXPECTED_MAX_STREAMS_PER_DEVICE
            ),
            60
        );
        // The 64 maximum records that would produce 128 entries need exactly
        // twice the configured budget.
        assert_eq!(EXPECTED_MAX_STREAMS_PER_DEVICE * charge, 8_397_312);
        assert_eq!(
            EXPECTED_MAX_STREAMS_PER_DEVICE * charge,
            2 * EXPECTED_QUEUE_BYTES_LIMIT + 8_704
        );
    }

    /// The full 128-entry data channel is unreachable from the public echo
    /// route for **every** admissible body size, because the consumer ingress
    /// admits one in-flight record per stream and
    /// `max_queue_messages = 2 * max_streams_per_device`.
    #[test]
    fn no_admissible_record_size_can_fill_the_data_channel() {
        let mut best = 0usize;
        let mut best_body = 0usize;
        for body in 1..=MAX_PAYLOAD_BYTES {
            let entries = reachable_entries(
                body,
                EXPECTED_DATA_BYTES_LIMIT,
                EXPECTED_MAX_STREAMS_PER_DEVICE,
            );
            assert!(
                entries < EXPECTED_QUEUE_MESSAGES,
                "body {body} reached {entries} entries, which would fill the {EXPECTED_QUEUE_MESSAGES} slot channel"
            );
            if entries > best {
                best = entries;
                best_body = body;
            }
        }
        assert_eq!(best, EXPECTED_MAX_STREAMS_PER_DEVICE);
        assert_eq!(best, EXPECTED_QUEUE_MESSAGES / 2);
        assert!(best_body <= 31_708);
        // The exact body size at which the whole shared byte budget would be
        // consumed by 64 one-frame records, the M7-C49 defect: without a byte
        // reservation this left zero control bytes.
        assert_eq!(
            EXPECTED_MAX_STREAMS_PER_DEVICE * charge_per_record(32_732),
            EXPECTED_QUEUE_BYTES_LIMIT
        );
        assert!(
            EXPECTED_MAX_STREAMS_PER_DEVICE * charge_per_record(32_733)
                > EXPECTED_QUEUE_BYTES_LIMIT
        );
        // With the reservation, the data byte limit is consumed in full by 64
        // records of 31,708 bytes and the 131,072 reserved control bytes are
        // untouched; a 32,732-byte workload now admits only 62 records.
        assert_eq!(EXPECTED_CONTROL_RESERVED_BYTES, 131_072);
        assert_eq!(EXPECTED_DATA_BYTES_LIMIT, 4_063_232);
        assert_eq!(
            EXPECTED_MAX_STREAMS_PER_DEVICE * charge_per_record(31_708),
            EXPECTED_DATA_BYTES_LIMIT
        );
        assert_eq!(EXPECTED_DATA_BYTES_LIMIT / charge_per_record(32_732), 62);
        assert!(
            EXPECTED_QUEUE_BYTES_LIMIT - 62 * charge_per_record(32_732)
                >= EXPECTED_CONTROL_RESERVED_BYTES
        );
    }

    /// The derived workload must saturate that reachable bound, hold enough
    /// wire bytes to actually block the physical writer, and retain the
    /// documented reserved byte capacity.
    #[test]
    fn derived_workload_saturates_the_reachable_bound_with_reserved_capacity() {
        assert_eq!(charge_per_record(SATURATION_RECORD_BYTES), 40_072);
        assert_eq!(wire_bytes_per_record(SATURATION_RECORD_BYTES), 20_068);
        assert_eq!(frames_per_record(SATURATION_RECORD_BYTES), 1);
        assert_eq!(
            reachable_entries(
                SATURATION_RECORD_BYTES,
                EXPECTED_DATA_BYTES_LIMIT,
                EXPECTED_MAX_STREAMS_PER_DEVICE
            ),
            EXPECTED_MAX_STREAMS_PER_DEVICE
        );
        assert_eq!(records_per_stream_by_credit(SATURATION_RECORD_BYTES), 6);
        // The workload's full data charge stays inside the data byte limit, so
        // at its peak the whole control reservation is still available.
        assert!(
            EXPECTED_MAX_STREAMS_PER_DEVICE * charge_per_record(SATURATION_RECORD_BYTES)
                <= EXPECTED_DATA_BYTES_LIMIT
        );
        assert!(
            EXPECTED_QUEUE_BYTES_LIMIT
                - EXPECTED_MAX_STREAMS_PER_DEVICE * charge_per_record(SATURATION_RECORD_BYTES)
                >= EXPECTED_CONTROL_RESERVED_BYTES
        );
        assert_eq!(M2_INITIAL_WINDOW_BYTES, 128 * 1024);
        let charge_at_peak =
            EXPECTED_MAX_STREAMS_PER_DEVICE * charge_per_record(SATURATION_RECORD_BYTES);
        assert_eq!(charge_at_peak, 2_564_608);
        assert_eq!(EXPECTED_QUEUE_BYTES_LIMIT - charge_at_peak, 1_629_696);
        // Reserved byte capacity must stay above the floor, which is itself 32
        // times the 32 KiB control bound.
        assert_eq!(MIN_SATURATION_HEADROOM_BYTES, 1_048_576);
        assert_eq!(MIN_SATURATION_HEADROOM_BYTES, 32 * 32 * 1024);
        assert!(EXPECTED_QUEUE_BYTES_LIMIT - charge_at_peak > MIN_SATURATION_HEADROOM_BYTES);
        // Enough wire bytes to exceed the socket buffers and actually block the
        // owner's physical writer rather than draining through it, and few
        // enough absorbed frames to leave residency above the configured floor.
        assert_eq!(
            EXPECTED_MAX_STREAMS_PER_DEVICE * wire_bytes_per_record(SATURATION_RECORD_BYTES),
            1_284_352
        );
        assert!(
            EXPECTED_MAX_STREAMS_PER_DEVICE * wire_bytes_per_record(SATURATION_RECORD_BYTES)
                > MAX_ABSORBED_WIRE_BYTES
        );
        let worst_absorbed_frames =
            MAX_ABSORBED_WIRE_BYTES / wire_bytes_per_record(SATURATION_RECORD_BYTES);
        assert_eq!(worst_absorbed_frames, 52);
        assert!(
            EXPECTED_MAX_STREAMS_PER_DEVICE - worst_absorbed_frames < MIN_RESIDENT_FRAMES,
            "the absorption bound is looser than the residency floor, so the floor is the binding requirement"
        );
        assert_eq!(MIN_RESIDENT_FRAMES, 32);
        // The record size is at the top of the band the reserved byte floor
        // allows, which minimises absorbed frames.
        assert!(
            EXPECTED_MAX_STREAMS_PER_DEVICE * charge_per_record(SATURATION_RECORD_BYTES)
                <= EXPECTED_QUEUE_BYTES_LIMIT - MIN_SATURATION_HEADROOM_BYTES
        );
        assert_eq!(
            EXPECTED_QUEUE_MESSAGES - EXPECTED_MAX_STREAMS_PER_DEVICE,
            EXPECTED_MAX_STREAMS_PER_DEVICE
        );
    }

    fn valid_evidence() -> QueueSaturationEvidence {
        QueueSaturationEvidence {
            relay_count: 3,
            membership_ready_relays: 3,
            non_owner_ingress: true,
            configured_queue_bytes_limit: EXPECTED_QUEUE_BYTES_LIMIT,
            configured_control_reserved_bytes: EXPECTED_CONTROL_RESERVED_BYTES,
            configured_data_bytes_limit: EXPECTED_DATA_BYTES_LIMIT,
            configured_data_queue_capacity: EXPECTED_QUEUE_MESSAGES,
            configured_control_queue_capacity: EXPECTED_QUEUE_MESSAGES,
            configured_max_streams_per_device: EXPECTED_MAX_STREAMS_PER_DEVICE,
            workload_record_bytes: SATURATION_RECORD_BYTES,
            workload_charge_per_record_bytes: charge_per_record(SATURATION_RECORD_BYTES),
            workload_frames_per_record: 1,
            workload_streams: EXPECTED_MAX_STREAMS_PER_DEVICE,
            workload_records_per_stream_by_credit: 6,
            workload_reachable_entries: EXPECTED_MAX_STREAMS_PER_DEVICE,
            route_maximum_reachable_entries: EXPECTED_MAX_STREAMS_PER_DEVICE,
            streams_admitted: EXPECTED_MAX_STREAMS_PER_DEVICE,
            stream_cap_refused_one_more: true,
            data_queue_depth_observed: 43,
            data_queue_depth_high_water: 43,
            data_enqueues_during_blackhole: EXPECTED_MAX_STREAMS_PER_DEVICE as u64,
            physically_resident_frames: 44,
            writer_absorbed_frames: EXPECTED_MAX_STREAMS_PER_DEVICE - 44,
            writer_absorbed_wire_bytes: (EXPECTED_MAX_STREAMS_PER_DEVICE - 44)
                * wire_bytes_per_record(SATURATION_RECORD_BYTES),
            reachable_bound_saturated: true,
            reserved_free_data_slots_at_peak: EXPECTED_QUEUE_MESSAGES - 43,
            reserved_data_slot_accepted_at_peak: true,
            queue_bytes_high_water: 43 * 40_072,
            data_bytes_high_water: 43 * 40_072,
            control_bytes_available_at_data_peak: EXPECTED_QUEUE_BYTES_LIMIT - 43 * 40_072,
            queue_bytes_headroom_at_peak: EXPECTED_QUEUE_BYTES_LIMIT - 2_564_608,
            control_queue_depth_at_peak: 1,
            control_queue_depth_high_water: 4,
            control_queue_refusals: 0,
            control_enqueues_during_blackhole: 3,
            cancellation_accepted_after_resume: true,
            fresh_stream_admitted_after_cancellation: true,
            sibling_stream_survived: true,
            first_terminal_observation_immutable: true,
            terminal_observations: TERMINAL_IMMUTABILITY_SAMPLES,
            paused_target_to_client: 1,
            paused_connection_correlated: true,
            paused_generation: 1,
            physical_drain_observations: 9,
            physical_drain_observation_bound: DRAIN_OBSERVATION_BOUND,
            physical_drain_completed: true,
            rotation_replaced_paused_carrier: true,
            rotation_committed_generation: 2,
            rotations_completed_after_drain: SATURATION_ROTATION_COUNT,
            final_generation: 1 + SATURATION_ROTATION_COUNT,
            rotation_attempts_with_observed_deadline: 3,
            rotation_deadline_never_extended: true,
            rotation_deadline_within_configured_overlap: true,
            device_socket_peak_open: 3,
            dispatch_delta_after_drain: 0,
            elapsed_ms: 12_345,
        }
    }

    #[test]
    fn queue_saturation_validation_accepts_complete_evidence() {
        assert!(validate_queue_saturation_evidence(&valid_evidence()).is_ok());
    }

    #[test]
    fn every_queue_saturation_flag_and_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut QueueSaturationEvidence));
        let flags: [Disable; 13] = [
            ("non_owner_ingress", |e| e.non_owner_ingress = false),
            ("stream_cap_refused_one_more", |e| {
                e.stream_cap_refused_one_more = false
            }),
            ("reachable_bound_saturated", |e| {
                e.reachable_bound_saturated = false
            }),
            ("reserved_data_slot_accepted_at_peak", |e| {
                e.reserved_data_slot_accepted_at_peak = false
            }),
            ("cancellation_accepted_after_resume", |e| {
                e.cancellation_accepted_after_resume = false
            }),
            ("fresh_stream_admitted_after_cancellation", |e| {
                e.fresh_stream_admitted_after_cancellation = false
            }),
            ("sibling_stream_survived", |e| {
                e.sibling_stream_survived = false
            }),
            ("first_terminal_observation_immutable", |e| {
                e.first_terminal_observation_immutable = false
            }),
            ("paused_connection_correlated", |e| {
                e.paused_connection_correlated = false
            }),
            ("physical_drain_completed", |e| {
                e.physical_drain_completed = false
            }),
            ("rotation_replaced_paused_carrier", |e| {
                e.rotation_replaced_paused_carrier = false
            }),
            ("rotation_deadline_never_extended", |e| {
                e.rotation_deadline_never_extended = false
            }),
            ("rotation_deadline_within_configured_overlap", |e| {
                e.rotation_deadline_within_configured_overlap = false
            }),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_queue_saturation_evidence(&evidence), name);
        }

        type Mutate = (&'static str, fn(&mut QueueSaturationEvidence));
        let bounds: [Mutate; 36] = [
            ("relay_count", |e| e.relay_count = 2),
            // M7-C49 reserved control bytes at the data-byte peak.
            ("configured_control_reserved_bytes", |e| {
                e.configured_control_reserved_bytes = 0
            }),
            ("configured_data_bytes_limit_not_derived", |e| {
                e.configured_data_bytes_limit = EXPECTED_QUEUE_BYTES_LIMIT
            }),
            ("configured_data_bytes_limit_wrong", |e| {
                e.configured_data_bytes_limit = EXPECTED_DATA_BYTES_LIMIT - 1;
                e.configured_control_reserved_bytes = EXPECTED_CONTROL_RESERVED_BYTES + 1;
            }),
            ("data_bytes_high_water_too_small", |e| {
                e.data_bytes_high_water = 1;
                e.control_bytes_available_at_data_peak = EXPECTED_QUEUE_BYTES_LIMIT - 1;
            }),
            ("data_bytes_high_water_consumed_reserve", |e| {
                e.data_bytes_high_water = EXPECTED_DATA_BYTES_LIMIT + 1;
                e.queue_bytes_high_water = EXPECTED_DATA_BYTES_LIMIT + 1;
                e.control_bytes_available_at_data_peak = EXPECTED_CONTROL_RESERVED_BYTES - 1;
            }),
            ("data_bytes_high_water_above_total_peak", |e| {
                e.data_bytes_high_water = e.queue_bytes_high_water + 1;
                e.control_bytes_available_at_data_peak =
                    EXPECTED_QUEUE_BYTES_LIMIT - e.data_bytes_high_water;
            }),
            ("control_bytes_available_at_data_peak_not_derived", |e| {
                e.control_bytes_available_at_data_peak += 1
            }),
            ("control_bytes_available_at_data_peak_below_reserve", |e| {
                e.data_bytes_high_water = EXPECTED_QUEUE_BYTES_LIMIT - 1;
                e.queue_bytes_high_water = EXPECTED_QUEUE_BYTES_LIMIT - 1;
                e.control_bytes_available_at_data_peak = 1;
            }),
            ("membership_ready_relays", |e| e.membership_ready_relays = 2),
            ("configured_queue_bytes_limit", |e| {
                e.configured_queue_bytes_limit = 256 * 1024
            }),
            ("configured_data_queue_capacity", |e| {
                e.configured_data_queue_capacity = 64
            }),
            ("configured_control_queue_capacity", |e| {
                e.configured_control_queue_capacity = 64
            }),
            ("configured_max_streams_per_device", |e| {
                e.configured_max_streams_per_device = 32
            }),
            ("workload_record_bytes", |e| e.workload_record_bytes = 0),
            ("workload_charge_per_record_bytes", |e| {
                e.workload_charge_per_record_bytes = 1
            }),
            ("workload_frames_per_record", |e| {
                e.workload_frames_per_record = 2
            }),
            ("workload_records_per_stream_by_credit", |e| {
                e.workload_records_per_stream_by_credit = 1
            }),
            ("workload_record_bytes_too_large", |e| {
                e.workload_record_bytes = MAX_PAYLOAD_BYTES + 1
            }),
            ("workload_reachable_entries", |e| {
                e.workload_reachable_entries = 32
            }),
            ("route_maximum_reachable_entries", |e| {
                e.route_maximum_reachable_entries = 32
            }),
            ("workload_streams", |e| e.workload_streams = 16),
            ("streams_admitted", |e| e.streams_admitted = 16),
            ("physically_resident_frames", |e| {
                e.physically_resident_frames = 20
            }),
            ("data_enqueues_during_blackhole", |e| {
                e.data_enqueues_during_blackhole = 32
            }),
            ("writer_absorbed_frames", |e| e.writer_absorbed_frames = 1),
            ("writer_absorbed_wire_bytes", |e| {
                e.writer_absorbed_wire_bytes = 1
            }),
            ("data_queue_depth_high_water", |e| {
                e.data_queue_depth_high_water = EXPECTED_QUEUE_MESSAGES + 1
            }),
            ("queue_bytes_high_water_too_small", |e| {
                e.queue_bytes_high_water = 1
            }),
            ("queue_bytes_high_water_too_large", |e| {
                e.queue_bytes_high_water = EXPECTED_QUEUE_BYTES_LIMIT + 1
            }),
            ("reserved_free_data_slots_at_peak", |e| {
                e.reserved_free_data_slots_at_peak = 1
            }),
            ("min_resident_frames_floor", |e| {
                e.physically_resident_frames = MIN_RESIDENT_FRAMES - 1;
                e.writer_absorbed_frames =
                    EXPECTED_MAX_STREAMS_PER_DEVICE - (MIN_RESIDENT_FRAMES - 1);
                e.writer_absorbed_wire_bytes =
                    e.writer_absorbed_frames * wire_bytes_per_record(SATURATION_RECORD_BYTES);
                e.data_queue_depth_high_water = MIN_RESIDENT_FRAMES - 2;
            }),
            ("queue_bytes_headroom_at_peak", |e| {
                e.queue_bytes_headroom_at_peak = 1
            }),
            ("control_queue_depth_at_peak", |e| {
                e.control_queue_depth_at_peak = EXPECTED_QUEUE_MESSAGES
            }),
            ("control_queue_refusals", |e| e.control_queue_refusals = 1),
            ("control_enqueues_during_blackhole", |e| {
                e.control_enqueues_during_blackhole = 0
            }),
        ];
        for (_, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(
                validate_queue_saturation_evidence(&evidence),
                "queue saturation",
            );
        }

        for mutate in [
            (|e: &mut QueueSaturationEvidence| e.terminal_observations = 0)
                as fn(&mut QueueSaturationEvidence),
            |e: &mut QueueSaturationEvidence| e.paused_target_to_client = 0,
            |e: &mut QueueSaturationEvidence| e.paused_generation = 0,
            |e: &mut QueueSaturationEvidence| {
                e.physical_drain_observation_bound = DRAIN_OBSERVATION_BOUND + 1
            },
            |e: &mut QueueSaturationEvidence| {
                e.physical_drain_observations = DRAIN_OBSERVATION_BOUND + 1
            },
            |e: &mut QueueSaturationEvidence| e.rotation_committed_generation = e.paused_generation,
            |e: &mut QueueSaturationEvidence| e.device_socket_peak_open = 4,
            |e: &mut QueueSaturationEvidence| {
                e.rotations_completed_after_drain = SATURATION_ROTATION_COUNT - 1
            },
            |e: &mut QueueSaturationEvidence| e.final_generation = 2,
            |e: &mut QueueSaturationEvidence| e.rotation_attempts_with_observed_deadline = 0,
            |e: &mut QueueSaturationEvidence| e.dispatch_delta_after_drain = 1,
        ] {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(
                validate_queue_saturation_evidence(&evidence),
                "queue saturation",
            );
        }
    }

    fn terminal_sample(
        stream_present: bool,
        peer_acked: u64,
        recv: u64,
        delivered: u64,
        receipts: usize,
    ) -> TerminalObservation {
        TerminalObservation {
            stream_present,
            terminal: stream_present,
            last_emitted_relay_to_connector: if stream_present { 3 } else { 0 },
            peer_acked_relay_to_connector: peer_acked,
            recv_contiguous_connector_to_relay: recv,
            delivered_contiguous_connector_to_relay: delivered,
            terminal_events: 1,
            terminal_receipts: receipts,
        }
    }

    #[test]
    fn terminal_observation_accepts_late_connector_progress_and_one_reclamation() {
        let first = terminal_sample(true, 1, 1, 1, 0);
        let acked = terminal_sample(true, 2, 2, 2, 0);
        let receipted = terminal_sample(true, 3, 2, 2, 1);
        let reclaimed = terminal_sample(false, 0, 0, 0, 1);
        for (label, sample, previous) in [
            ("ack and reply", &acked, &first),
            ("connector receipt", &receipted, &acked),
            ("reclaimed tombstone", &reclaimed, &receipted),
            ("stays reclaimed", &reclaimed, &reclaimed),
        ] {
            assert!(
                sample.retains_first_terminal(&first),
                "{label}: first terminal must be retained"
            );
            assert!(
                sample.advances_bounded(previous),
                "{label}: progress must be accepted"
            );
        }
    }

    #[test]
    fn terminal_observation_rejects_every_mutation_of_the_first_terminal() {
        let first = terminal_sample(true, 1, 1, 1, 0);
        let mutations: &[(&str, TerminalObservation)] = &[
            ("terminal event count changed", {
                let mut sample = first.clone();
                sample.terminal_events = 2;
                sample
            }),
            ("terminal flag dropped while present", {
                let mut sample = first.clone();
                sample.terminal = false;
                sample
            }),
            ("relay final sequence moved", {
                let mut sample = first.clone();
                sample.last_emitted_relay_to_connector = 4;
                sample
            }),
        ];
        for (label, sample) in mutations {
            assert!(
                !sample.retains_first_terminal(&first),
                "{label}: must not count as a retained first terminal"
            );
        }
        let regressions: &[(&str, TerminalObservation, TerminalObservation)] = &[
            (
                "ack cursor regressed",
                terminal_sample(true, 1, 2, 2, 0),
                terminal_sample(true, 2, 2, 2, 0),
            ),
            (
                "ack cursor beyond the relay final sequence",
                terminal_sample(true, 4, 2, 2, 0),
                first.clone(),
            ),
            (
                "delivered ahead of received",
                terminal_sample(true, 2, 1, 2, 0),
                first.clone(),
            ),
            (
                "second terminal receipt",
                terminal_sample(true, 3, 2, 2, 2),
                terminal_sample(true, 3, 2, 2, 1),
            ),
            (
                "receipt withdrawn",
                terminal_sample(true, 3, 2, 2, 0),
                terminal_sample(true, 3, 2, 2, 1),
            ),
            (
                "reclaimed stream reappeared",
                terminal_sample(true, 3, 2, 2, 1),
                terminal_sample(false, 0, 0, 0, 1),
            ),
            (
                "receipt changed after reclamation",
                terminal_sample(false, 0, 0, 0, 0),
                terminal_sample(false, 0, 0, 0, 1),
            ),
        ];
        for (label, sample, previous) in regressions {
            assert!(
                !sample.advances_bounded(previous),
                "{label}: must be rejected as unbounded or non-monotonic progress"
            );
        }
        assert!(
            !terminal_sample(false, 0, 0, 0, 0)
                .retains_first_terminal(&terminal_sample(false, 0, 0, 0, 0)),
            "a first sample that never saw the tombstone cannot anchor immutability"
        );
    }
}
