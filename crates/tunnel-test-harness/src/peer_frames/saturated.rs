//! M7-I07 / M7-C22 conjunction gate: reserved control capacity proven *by
//! delivery*, and the frame-ordering guarantees proven *under saturation*, on
//! one genuinely saturated non-owner-ingress route.
//!
//! # The gap this closes
//!
//! Two rows carry the same remaining clause from opposite sides.
//!
//! * `verify-m7-queue-saturation` drives real physical queue occupancy through
//!   non-owner ingress against a real owner, and proves free slots and free
//!   bytes are *reserved* for control, cancellation, revocation and rotation.
//!   It never delivers one of those messages on the saturated carrier, and it
//!   injects no late, duplicate or reordered frame (M7-C22's clause:
//!   "proven by reservation rather than by delivery").
//! * `verify-m7-ec044-peer-frames` injects reordered, duplicate and late
//!   frames through a real mTLS/HTTP3 ingress-to-owner forward into a live
//!   relay actor, but runs one idle admitted session with a single outstanding
//!   record, no sibling and no GOAWAY (M7-I07's clause).
//!
//! Neither covers the conjunction, which is the thing in question: that
//! reserved control capacity is *usable* and that frame ordering still holds
//! while the data path is genuinely saturated.
//!
//! # Why this is a separate gate rather than an extension of
//! `verify-m7-queue-saturation`
//!
//! That gate's saturated carrier is an actual `tunnel-client` process's mTLS
//! data socket, blackholed by pausing one direction of a TCP proxy in front of
//! the owner's device listener.  The fixture does not terminate that TLS
//! session, so it cannot place a reordered, duplicated or post-FIN frame on
//! it, and the real CLI never emits one; there is also no peer GOAWAY seam on
//! a device carrier, which is an HTTP/3 concept between relays.  Lowering that
//! gate's workload or replacing its real client would weaken an existing
//! proof.  This gate instead saturates the carrier the EC-044 fixture already
//! terminates itself, so injection and saturation can coexist without either
//! being faked.
//!
//! # How the carrier is saturated
//!
//! The device data carrier runs on its own peer client whose
//! `max_connection_body_bytes` is deliberately small.  That value becomes the
//! QUIC connection receive window (`configure_quic_connection` calls
//! `set_receive_window`), so once the fixture stops reading, the owner's
//! physical writer blocks after absorbing at most that many wire bytes and the
//! owner's bounded outbound data channel fills.  This is the exact analogue of
//! the queue-saturation gate's 1 KiB proxy receive buffer: an *environment*
//! bound, never a product bound.  The device control carrier and every
//! consumer stream run on a second, ordinarily-windowed client, so the control
//! plane is not blocked by the saturated data plane — which is the property
//! under test.
//!
//! The workload is the queue-saturation gate's own derivation, unchanged:
//! 20,000-byte records, one in-flight record per logical stream, the full
//! 64-stream per-device cap, and a required physical residency floor of
//! `max_queue_messages / 4`.
//!
//! # A structural property this gate measures rather than assumes
//!
//! `handle_peer_device_data` services one forwarded carrier from a **single**
//! `tokio::select!` loop: the same task reads inbound `CompleteDeviceData`
//! records and writes outbound frames.  While its physical write is parked on
//! QUIC flow control it is therefore not reading, so a *fully* blackholed
//! forwarded carrier cannot deliver an inbound frame at all.  That is ordinary
//! end-to-end backpressure rather than a defect — an owner that cannot write
//! to an ingress has no reason to keep consuming from it — but it means a
//! frame injected into a fully stalled carrier would simply sit in the QUIC
//! buffer and prove nothing.
//!
//! So the gate does not pretend the carrier is frozen.  It consumes a
//! **bounded, counted** number of already-queued frames — the drain allowance
//! — only when an injected frame has not yet been accounted, which lets the
//! owner's single loop alternate back to its receive branch.  Every allowance
//! read strictly lowers physical residency, so the gate records the allowance
//! it used and asserts the *minimum* residency observed across the whole
//! injection sequence stayed above the same floor the saturation phase had to
//! reach.  Saturation is therefore continuously measured during injection, not
//! asserted once and assumed.
//!
//! # The settle barrier
//!
//! The EC-044 gate samples each cursor behind the owner's own ACK read off the
//! data carrier.  That is unavailable here by construction: the ACK is queued
//! behind the saturated backlog, and reading far enough to reach it would
//! drain the very occupancy under test.  This gate uses the owner's own
//! `data_queue_enqueued` counter instead: `inbound_m2_stream_data` queues the
//! ACK for a frame last, after the receive cursor, delivery, byte release and
//! credit update, so an observed increment is the same settle point expressed
//! as a bounded, payload-free counter.  Nothing else enqueues on that channel
//! during an injection step, and the counter is read from the relay's redacted
//! snapshot.

use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use tokio::time::{Instant, sleep, timeout};
use tunnel_catalog::Catalog;
use tunnel_cluster::{envelope::InternalRoute, peer_frame::PeerRecordKind};
use tunnel_protocol::{ControlMessage, Frame, control::decode_control};
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot, StreamTerminalEvent};
use tunnel_transport::{PeerTransportError, PeerTransportLimits};

use super::{
    ConsumerPhase, FixtureSetup, FrameContext, RawStream, RunningFixture, admit_data, admit_open,
    consumer_envelope, device_id, forward_frame, framed, http_error, next_consumer_record,
    open_consumer_phase, register_control, service_id, snapshot, start_running, stream_snapshot,
    tenant_id, user_id, wait_for,
};
use crate::{HarnessError, Result};

/// Configured bounds this gate requires the owner to report, identical to the
/// queue-saturation gate's.  They are asserted, never assumed.
const EXPECTED_QUEUE_BYTES_LIMIT: usize = 4 * 1024 * 1024;
const EXPECTED_CONTROL_RESERVED_BYTES: usize = 4 * 32 * 1024;
const EXPECTED_DATA_BYTES_LIMIT: usize =
    EXPECTED_QUEUE_BYTES_LIMIT - EXPECTED_CONTROL_RESERVED_BYTES;
const EXPECTED_QUEUE_MESSAGES: usize = 128;
const EXPECTED_MAX_STREAMS_PER_DEVICE: usize = 64;

/// `tunnel_protocol::HEADER_LEN` plus the four-byte record length prefix the
/// relay prepends before chunking a record into frames.
const FRAME_HEADER_BYTES: usize = 64;
const RECORD_PREFIX_BYTES: usize = 4;

/// The queue-saturation gate's derived workload, unchanged.
const SATURATION_RECORD_BYTES: usize = 20_000;

/// Hard floor on simultaneous physical residency, in configured terms: at
/// least a quarter of the bounded data channel occupied at once.  The same
/// floor the queue-saturation gate uses, and it must hold continuously across
/// every injection step, not only at the peak.
const MIN_RESIDENT_FRAMES: usize = EXPECTED_QUEUE_MESSAGES / 4;

/// Streams whose relay-to-connector request frame is read before saturation so
/// the fixture knows the owner's send cursor for them: reorder, duplicate,
/// late, sibling and revocation.
const NAMED_STREAMS: usize = 5;
/// Streams opened purely to occupy the bounded data channel.  Their request
/// frames are never read, which is what makes them resident.
const SATURATION_STREAMS: usize = EXPECTED_MAX_STREAMS_PER_DEVICE - NAMED_STREAMS;

/// Already-queued frames the fixture may consume from the saturated carrier to
/// let the owner's single-task carrier loop alternate back to its receive
/// branch.  Each read strictly lowers residency, so the budget is bounded well
/// below the distance between the reachable occupancy and the residency floor.
const CARRIER_DRAIN_BUDGET: usize = 48;

/// In-flight application body budget for the data carrier's own client.
const CARRIER_WINDOW_BYTES: usize = 128 * 1024;
/// QUIC flow-control windows advertised by that client at the handshake.  They
/// decide how many wire bytes the owner's writer can hand off before it blocks,
/// exactly as a small socket receive buffer does for a local device socket.
const CARRIER_CONNECTION_WINDOW_BYTES: usize = 192 * 1024;
const CARRIER_STREAM_WINDOW_BYTES: usize = 128 * 1024;
/// Chunk and stream bounds for that client.  They must admit one complete
/// `CompleteDeviceData` record, and `max_chunk_bytes <= max_stream_body_bytes
/// <= max_connection_body_bytes` is enforced by `PeerTransportLimits`.
const CARRIER_CHUNK_BYTES: usize = 64 * 1024;

/// `RelayLimits::operation_timeout`: a pending record the connector never
/// answers is failed after this long, which bounds the whole saturated window.
const OPERATION_TIMEOUT_MS: u64 = 30_000;
/// The saturated window must finish comfortably inside that bound, or the
/// occupancy the gate measures would be decaying underneath it.
const SATURATION_WINDOW_BOUND_MS: u64 = 20_000;

const POLL: Duration = Duration::from_millis(10);
/// Gap between the two samples that establish a settled enqueue baseline.
const QUIET_INTERVAL: Duration = Duration::from_millis(60);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(8);
const PHASE_TIMEOUT: Duration = Duration::from_secs(25);
const GATE_TIMEOUT: Duration = Duration::from_secs(180);
/// Re-samples used to prove the first terminal identity never changes.
const TERMINAL_SAMPLES: usize = 8;
const TERMINAL_SAMPLE_INTERVAL: Duration = Duration::from_millis(25);

/// Body of the one reordered response record, and the offset at which it is
/// split across two sequenced DATA frames.
const REORDER_BODY: &[u8] = b"saturated-reorder-response-body";
const REORDER_SPLIT: usize = 11;
const DUPLICATE_BODY: &[u8] = b"saturated-duplicate-response";
const SIBLING_BODY: &[u8] = b"saturated-sibling-response";
const LATE_BODY: &[u8] = b"saturated-late-response";

/// Shared-budget charge one logical record of `body` bytes levies: the
/// retained replay chunk plus the encoded frame.
const fn charge_per_record(body: usize) -> usize {
    2 * (body + RECORD_PREFIX_BYTES) + FRAME_HEADER_BYTES
}

/// Bounded, payload-free evidence for one saturated conjunction run.
///
/// Every field is a count, cursor, phase bit or typed label drawn from the
/// owner relay's own redacted snapshot or from bytes the fixture observed on a
/// real peer stream.  No frame payload, credential or transport error text is
/// retained.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SaturatedFrameEvidence {
    // ---- shape -----------------------------------------------------------
    /// A real relay actor ran behind the production peer ingress handler.
    pub real_owner_ingress: bool,
    /// Every consumer stream and the device carriers entered through a peer
    /// identity that is not the owner node.
    pub non_owner_ingress: bool,
    /// Control registration and data carrier attachment both crossed mTLS,
    /// HTTP/3 and `PeerRuntime` admission.
    pub authenticated_carrier: bool,
    /// The device data carrier ran on its own QUIC connection, so blocking it
    /// does not block the control plane.
    pub carrier_connection_isolated: bool,
    /// Negotiated session profile.  The shared frame validator runs for `m2`.
    pub session_profile: String,

    // ---- configured bounds ----------------------------------------------
    pub configured_queue_bytes_limit: usize,
    pub configured_control_reserved_bytes: usize,
    pub configured_data_bytes_limit: usize,
    pub configured_data_queue_capacity: usize,
    pub configured_control_queue_capacity: usize,
    /// Per-device stream cap, proven by a refusal at cap-plus-one rather than
    /// read from configuration.
    pub configured_max_streams_per_device: usize,
    pub stream_cap_refused_one_more: bool,

    // ---- workload --------------------------------------------------------
    pub workload_record_bytes: usize,
    pub workload_charge_per_record_bytes: usize,
    pub workload_saturation_streams: usize,
    pub workload_named_streams: usize,
    pub streams_admitted: usize,

    // ---- saturation ------------------------------------------------------
    /// Highest physical data-channel occupancy the owner latched.
    pub data_queue_depth_high_water: usize,
    /// Frames physically resident at peak: the latched channel high water plus
    /// the one frame the blocked physical writer owns and still charges.
    pub physically_resident_frames: usize,
    /// Configured residency floor this gate had to reach and stay above.
    pub resident_frames_floor: usize,
    /// Lowest physical occupancy observed at any injection step, so saturation
    /// is measured continuously rather than once.
    pub min_resident_frames_during_injection: usize,
    /// Free data-channel slots retained at peak residency: the reserved second
    /// slot per stream that `max_queue_messages = 2 * max_streams_per_device`
    /// exists to guarantee.
    pub reserved_free_data_slots_at_peak: usize,
    /// Peak session byte charge the owner latched.
    pub queue_bytes_high_water: usize,
    /// Highest total charge at which a data-lane reservation was admitted.
    pub data_bytes_high_water: usize,
    /// `configured_queue_bytes_limit - data_bytes_high_water`: the least
    /// control byte capacity that remained available at the data-byte peak.
    pub control_bytes_available_at_data_peak: usize,
    /// Already-queued frames consumed to let the owner's single-task carrier
    /// loop alternate, and the bound on that allowance.
    pub carrier_drain_records_consumed: usize,
    pub carrier_drain_budget: usize,
    /// Milliseconds between the first saturation stream's admission and the
    /// last saturated assertion, and the bound it had to stay inside so the
    /// owner's pending-operation timeout cannot have expired underneath it.
    pub saturation_window_ms: u64,
    pub saturation_window_bound_ms: u64,
    pub operation_timeout_ms: u64,

    // ---- item 1: reserved control capacity proven by delivery ------------
    /// The consumer grant was revoked in the authoritative catalog while the
    /// data carrier was saturated.
    pub revocation_grant_revoked: bool,
    /// The owner's `AUTHORIZATION_INVALIDATED` revocation close was actually
    /// received on the control carrier at peak data residency.
    pub revocation_close_delivered: bool,
    /// It named the exact stream whose challenge was refused.
    pub revocation_close_stream_matched: bool,
    /// The owner's own typed reason for the close.
    pub revocation_close_reason: String,
    /// The owner's typed authorization failure code for that stream: the close
    /// was acted on, not merely sent.
    pub revocation_failure_code: String,
    /// The stream the revocation closed reached a terminal state.
    pub revocation_stream_terminal: bool,
    /// Application dispatches recorded across the revocation.  A revoked
    /// authorization must dispatch nothing.
    pub revocation_dispatch_delta: u64,
    /// Physical data-channel occupancy at the instant the close was delivered.
    pub data_queue_depth_at_revocation: usize,
    /// Control enqueues the owner accepted while the data carrier was
    /// saturated, and control enqueues it refused.  A positive accepted count
    /// with zero refusals is the reserved-capacity-is-usable measurement.
    pub control_enqueues_during_saturation: u64,
    pub control_queue_refusals_during_saturation: u64,

    // ---- item 2: frame ordering under saturation -------------------------
    /// Receive and delivered contiguous connector-to-relay cursors after the
    /// out-of-order frame at `n + 1` was forwarded and accounted, before `n`
    /// arrived.  A buffered frame leaves both at zero.
    pub reorder_recv_after_gap: u64,
    pub reorder_delivered_after_gap: u64,
    /// The same cursors once the missing frame at `n` landed.
    pub reorder_recv_after_fill: u64,
    pub reorder_delivered_after_fill: u64,
    /// The reordered pair was reassembled in sequence order, byte exact.
    pub reorder_order_restored: bool,
    /// Physical occupancy observed during the reorder step.
    pub reorder_resident_frames: usize,

    /// Delivered contiguous cursor immediately before and after the duplicate.
    pub duplicate_delivered_before: u64,
    pub duplicate_delivered_after: u64,
    /// Adapter records observed for the duplicate phase's stream.  A duplicate
    /// must not produce a second one.
    pub duplicate_adapter_records: usize,
    pub duplicate_resident_frames: usize,
    /// A sibling stream, untouched by the revocation close and by both
    /// injections, completed its own outstanding round trip byte exact while
    /// the carrier was still saturated.
    pub sibling_survived_terminals: bool,
    /// Physical occupancy observed across that sibling round trip.
    pub sibling_resident_frames: usize,
    /// Neither the duplicate nor the post-FIN frame produced a second
    /// delivery: `duplicate_adapter_records == 1 && late_adapter_bytes == 0`.
    pub no_double_delivery: bool,

    /// Delivered contiguous cursor latched with the terminal FIN.
    pub late_fin_cursor: u64,
    /// Stream terminal latches recorded for the late phase's stream.  The
    /// first terminal is immutable, so a post-FIN DATA frame must not add one.
    pub late_stream_terminals: usize,
    /// Adapter response bytes observed beyond the FIN cursor.  Must be zero.
    pub late_adapter_bytes_after_fin: usize,
    /// Typed terminal reason recorded when the late frame fenced the session.
    pub late_session_reason: String,
    pub late_resident_frames: usize,
    /// The complete first terminal identity was re-sampled and never changed.
    pub terminal_identity_immutable: bool,
    pub terminal_identity_samples: usize,

    // ---- item 3: peer GOAWAY on the saturated route ----------------------
    /// The owner's peer listener was asked for its planned HTTP/3 GOAWAY drain
    /// while the carrier was saturated.
    pub goaway_requested: bool,
    /// A fresh peer stream was refused with the typed pre-dispatch GOAWAY
    /// class, which is the ingress-observable proof the GOAWAY landed.
    pub goaway_refused_new_peer_stream: bool,
    pub goaway_refusal_class: String,
    /// The GOAWAY was requested only after the post-FIN fence had already
    /// closed the session.  Recorded rather than implied: the owner's planned
    /// drain is a listener-wide `GOAWAY(0)` that ends the session within tens
    /// of milliseconds, and the fence has to be the session's own last event,
    /// so the two cannot be ordered the other way round.
    pub goaway_requested_after_fence: bool,
    /// The owner's peer listener reported that it actually wrote the planned
    /// HTTP/3 GOAWAY on a peer connection.
    pub goaway_sent_by_owner: bool,

    /// The peer server task and both client supervisors were cancelled and
    /// joined within their bound.
    pub cleanup_joined: bool,
    pub elapsed_ms: u64,
}

/// Typed label for the owner's revocation close.
pub const GRANT_UNAVAILABLE: &str = "GRANT_UNAVAILABLE";
/// Typed pre-dispatch refusal class for a peer stream opened after GOAWAY.
pub const GOAWAY_CLASS: &str = "goaway";

impl SaturatedFrameEvidence {
    /// Validate the exact conjunction contract.
    ///
    /// Pure over the evidence value, so the CLI boundary and every red control
    /// can be exercised without a live fixture.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<()> {
        let mut failures: Vec<&'static str> = Vec::new();

        if !self.real_owner_ingress {
            failures.push("real_owner_ingress");
        }
        if !self.non_owner_ingress {
            failures.push("non_owner_ingress");
        }
        if !self.authenticated_carrier {
            failures.push("authenticated_carrier");
        }
        if !self.carrier_connection_isolated {
            failures.push("carrier_connection_isolated");
        }
        if self.session_profile != "m2" {
            failures.push("session_profile");
        }

        // Configured bounds, asserted rather than assumed.
        if self.configured_queue_bytes_limit != EXPECTED_QUEUE_BYTES_LIMIT {
            failures.push("configured_queue_bytes_limit");
        }
        if self.configured_control_reserved_bytes != EXPECTED_CONTROL_RESERVED_BYTES {
            failures.push("configured_control_reserved_bytes");
        }
        if self.configured_data_bytes_limit != EXPECTED_DATA_BYTES_LIMIT
            || self.configured_data_bytes_limit
                != self
                    .configured_queue_bytes_limit
                    .saturating_sub(self.configured_control_reserved_bytes)
        {
            failures.push("configured_data_bytes_limit");
        }
        if self.configured_data_queue_capacity != EXPECTED_QUEUE_MESSAGES
            || self.configured_control_queue_capacity != EXPECTED_QUEUE_MESSAGES
        {
            failures.push("configured_queue_capacity");
        }
        if self.configured_max_streams_per_device != EXPECTED_MAX_STREAMS_PER_DEVICE {
            failures.push("configured_max_streams_per_device");
        }
        if !self.stream_cap_refused_one_more {
            failures.push("stream_cap_refused_one_more");
        }

        // Workload derivation self-consistency.
        if self.workload_record_bytes != SATURATION_RECORD_BYTES {
            failures.push("workload_record_bytes");
        }
        if self.workload_charge_per_record_bytes != charge_per_record(self.workload_record_bytes) {
            failures.push("workload_charge_per_record_bytes");
        }
        if self.workload_named_streams != NAMED_STREAMS {
            failures.push("workload_named_streams");
        }
        if self.workload_saturation_streams != SATURATION_STREAMS {
            failures.push("workload_saturation_streams");
        }
        if self.streams_admitted != self.workload_saturation_streams + self.workload_named_streams
            || self.streams_admitted != self.configured_max_streams_per_device
        {
            failures.push("streams_admitted");
        }
        // The whole admitted workload must fit under the data byte limit, or
        // the occupancy the gate reports could not have been admitted at all.
        if self
            .streams_admitted
            .saturating_mul(self.workload_charge_per_record_bytes)
            > self.configured_data_bytes_limit
        {
            failures.push("workload_fits_data_bytes_limit");
        }

        // Saturation: real physical occupancy, above the configured floor, and
        // still above it at every injection step.
        if self.resident_frames_floor != MIN_RESIDENT_FRAMES {
            failures.push("resident_frames_floor");
        }
        if self.physically_resident_frames != self.data_queue_depth_high_water.saturating_add(1) {
            failures.push("physically_resident_frames");
        }
        if self.physically_resident_frames < self.resident_frames_floor {
            failures.push("saturation_reached_floor");
        }
        if self.min_resident_frames_during_injection < self.resident_frames_floor {
            failures.push("min_resident_frames_during_injection");
        }
        if self.min_resident_frames_during_injection > self.physically_resident_frames {
            failures.push("min_resident_frames_bounded_by_peak");
        }
        if self.reserved_free_data_slots_at_peak
            != self
                .configured_data_queue_capacity
                .saturating_sub(self.data_queue_depth_high_water)
            || self.reserved_free_data_slots_at_peak == 0
        {
            failures.push("reserved_free_data_slots_at_peak");
        }
        if self.queue_bytes_high_water == 0
            || self.queue_bytes_high_water > self.configured_queue_bytes_limit
        {
            failures.push("queue_bytes_high_water");
        }
        if self.data_bytes_high_water == 0
            || self.data_bytes_high_water > self.configured_data_bytes_limit
        {
            failures.push("data_bytes_high_water");
        }
        if self.control_bytes_available_at_data_peak
            != self
                .configured_queue_bytes_limit
                .saturating_sub(self.data_bytes_high_water)
            || self.control_bytes_available_at_data_peak < self.configured_control_reserved_bytes
        {
            failures.push("control_bytes_available_at_data_peak");
        }
        if self.carrier_drain_budget != CARRIER_DRAIN_BUDGET {
            failures.push("carrier_drain_budget");
        }
        if self.carrier_drain_records_consumed > self.carrier_drain_budget {
            failures.push("carrier_drain_records_consumed");
        }
        if self.operation_timeout_ms != OPERATION_TIMEOUT_MS {
            failures.push("operation_timeout_ms");
        }
        if self.saturation_window_bound_ms != SATURATION_WINDOW_BOUND_MS
            || self.saturation_window_bound_ms >= self.operation_timeout_ms
        {
            failures.push("saturation_window_bound_ms");
        }
        if self.saturation_window_ms == 0
            || self.saturation_window_ms > self.saturation_window_bound_ms
        {
            failures.push("saturation_window_ms");
        }

        // Item 1: the reservation proven by delivery.
        if !self.revocation_grant_revoked {
            failures.push("revocation_grant_revoked");
        }
        if !self.revocation_close_delivered {
            failures.push("revocation_close_delivered");
        }
        if !self.revocation_close_stream_matched {
            failures.push("revocation_close_stream_matched");
        }
        if self.revocation_close_reason.is_empty() {
            failures.push("revocation_close_reason");
        }
        if self.revocation_failure_code != GRANT_UNAVAILABLE {
            failures.push("revocation_failure_code");
        }
        if !self.revocation_stream_terminal {
            failures.push("revocation_stream_terminal");
        }
        if self.revocation_dispatch_delta != 0 {
            failures.push("revocation_dispatch_delta");
        }
        if self.data_queue_depth_at_revocation.saturating_add(1) < self.resident_frames_floor {
            failures.push("data_queue_depth_at_revocation");
        }
        if self.control_enqueues_during_saturation == 0 {
            failures.push("control_enqueues_during_saturation");
        }
        if self.control_queue_refusals_during_saturation != 0 {
            failures.push("control_queue_refusals_during_saturation");
        }

        // Item 2: ordering guarantees, under saturation.
        if self.reorder_recv_after_gap != 0 {
            failures.push("reorder_recv_after_gap");
        }
        if self.reorder_delivered_after_gap != 0 {
            failures.push("reorder_delivered_after_gap");
        }
        if self.reorder_recv_after_fill != self.reorder_delivered_after_fill {
            failures.push("reorder_recv_after_fill");
        }
        if self.reorder_delivered_after_fill < 2 {
            failures.push("reorder_delivered_after_fill");
        }
        if self.reorder_delivered_after_fill <= self.reorder_delivered_after_gap {
            failures.push("reorder_cursor_advance");
        }
        if !self.reorder_order_restored {
            failures.push("reorder_order_restored");
        }
        if self.reorder_resident_frames < self.resident_frames_floor {
            failures.push("reorder_resident_frames");
        }

        if self.duplicate_delivered_before == 0 {
            failures.push("duplicate_delivered_before");
        }
        if self.duplicate_delivered_after != self.duplicate_delivered_before {
            failures.push("duplicate_delivered_after");
        }
        if self.duplicate_adapter_records != 1 {
            failures.push("duplicate_adapter_records");
        }
        if self.duplicate_resident_frames < self.resident_frames_floor {
            failures.push("duplicate_resident_frames");
        }
        if !self.sibling_survived_terminals {
            failures.push("sibling_survived_terminals");
        }
        if self.sibling_resident_frames < self.resident_frames_floor {
            failures.push("sibling_resident_frames");
        }
        if self.no_double_delivery
            != (self.duplicate_adapter_records == 1 && self.late_adapter_bytes_after_fin == 0)
            || !self.no_double_delivery
        {
            failures.push("no_double_delivery");
        }

        if self.late_fin_cursor == 0 {
            failures.push("late_fin_cursor");
        }
        if self.late_stream_terminals != 1 {
            failures.push("late_stream_terminals");
        }
        if self.late_adapter_bytes_after_fin != 0 {
            failures.push("late_adapter_bytes_after_fin");
        }
        if self.late_session_reason != "INVALID_SEQUENCE" {
            failures.push("late_session_reason");
        }
        if self.late_resident_frames < self.resident_frames_floor {
            failures.push("late_resident_frames");
        }
        if self.terminal_identity_samples != TERMINAL_SAMPLES {
            failures.push("terminal_identity_samples");
        }
        if !self.terminal_identity_immutable {
            failures.push("terminal_identity_immutable");
        }

        // Item 3: the peer GOAWAY and the surviving sibling.
        if !self.goaway_requested {
            failures.push("goaway_requested");
        }
        if !self.goaway_refused_new_peer_stream {
            failures.push("goaway_refused_new_peer_stream");
        }
        if self.goaway_refusal_class != GOAWAY_CLASS {
            failures.push("goaway_refusal_class");
        }
        if !self.goaway_requested_after_fence {
            failures.push("goaway_requested_after_fence");
        }
        if !self.goaway_sent_by_owner {
            failures.push("goaway_sent_by_owner");
        }

        if !self.cleanup_joined {
            failures.push("cleanup_joined");
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Http(format!(
                "saturated peer-frame conjunction evidence was incomplete: {}",
                failures.join(",")
            )))
        }
    }

    /// One bounded, payload-free evidence line for the gate script.
    #[must_use]
    pub fn evidence_line(&self) -> String {
        format!(
            "M7 saturated peer frames passed: non_owner_ingress={} carrier_connection_isolated={} profile={} streams_admitted={} stream_cap_refused_one_more={} record_bytes={} charge_per_record={} data_queue_depth_high_water={} physically_resident_frames={} resident_floor={} min_resident_during_injection={} reserved_free_data_slots_at_peak={} queue_bytes_high_water={} data_bytes_high_water={} control_bytes_available_at_data_peak={} carrier_drain_records_consumed={}/{} saturation_window_ms={}/{} revocation_close_delivered={} revocation_close_reason={} revocation_failure_code={} revocation_stream_terminal={} revocation_dispatch_delta={} data_queue_depth_at_revocation={} control_enqueues_during_saturation={} control_queue_refusals_during_saturation={} reorder_recv_after_gap={} reorder_delivered_after_gap={} reorder_recv_after_fill={} reorder_delivered_after_fill={} reorder_order_restored={} reorder_resident_frames={} duplicate_delivered_before={} duplicate_delivered_after={} duplicate_adapter_records={} duplicate_resident_frames={} no_double_delivery={} late_fin_cursor={} late_stream_terminals={} late_adapter_bytes_after_fin={} late_session_reason={} late_resident_frames={} terminal_identity_immutable={} terminal_identity_samples={} goaway_refused_new_peer_stream={} goaway_refusal_class={} goaway_sent_by_owner={} goaway_requested_after_fence={} sibling_survived_terminals={} sibling_resident_frames={} cleanup_joined={} elapsed_ms={}",
            self.non_owner_ingress,
            self.carrier_connection_isolated,
            self.session_profile,
            self.streams_admitted,
            self.stream_cap_refused_one_more,
            self.workload_record_bytes,
            self.workload_charge_per_record_bytes,
            self.data_queue_depth_high_water,
            self.physically_resident_frames,
            self.resident_frames_floor,
            self.min_resident_frames_during_injection,
            self.reserved_free_data_slots_at_peak,
            self.queue_bytes_high_water,
            self.data_bytes_high_water,
            self.control_bytes_available_at_data_peak,
            self.carrier_drain_records_consumed,
            self.carrier_drain_budget,
            self.saturation_window_ms,
            self.saturation_window_bound_ms,
            self.revocation_close_delivered,
            self.revocation_close_reason,
            self.revocation_failure_code,
            self.revocation_stream_terminal,
            self.revocation_dispatch_delta,
            self.data_queue_depth_at_revocation,
            self.control_enqueues_during_saturation,
            self.control_queue_refusals_during_saturation,
            self.reorder_recv_after_gap,
            self.reorder_delivered_after_gap,
            self.reorder_recv_after_fill,
            self.reorder_delivered_after_fill,
            self.reorder_order_restored,
            self.reorder_resident_frames,
            self.duplicate_delivered_before,
            self.duplicate_delivered_after,
            self.duplicate_adapter_records,
            self.duplicate_resident_frames,
            self.no_double_delivery,
            self.late_fin_cursor,
            self.late_stream_terminals,
            self.late_adapter_bytes_after_fin,
            self.late_session_reason,
            self.late_resident_frames,
            self.terminal_identity_immutable,
            self.terminal_identity_samples,
            self.goaway_refused_new_peer_stream,
            self.goaway_refusal_class,
            self.goaway_sent_by_owner,
            self.goaway_requested_after_fence,
            self.sibling_survived_terminals,
            self.sibling_resident_frames,
            self.cleanup_joined,
            self.elapsed_ms,
        )
    }
}

/// Transport limits for the data carrier's own client.
fn carrier_limits() -> PeerTransportLimits {
    PeerTransportLimits {
        max_chunk_bytes: CARRIER_CHUNK_BYTES,
        max_stream_body_bytes: CARRIER_CHUNK_BYTES,
        max_connection_body_bytes: CARRIER_WINDOW_BYTES,
        ..PeerTransportLimits::default()
    }
}

/// QUIC flow-control configuration for the data carrier's own client.
///
/// These windows are advertised at the handshake, which is the only point at
/// which they bind: credit already granted to the peer cannot be revoked
/// later.  They are an **environment** bound, exactly like the 1 KiB proxy
/// receive buffer the queue-saturation gate puts in front of the owner's
/// device listener, and they apply only to this fixture's own carrier
/// connection.  Nothing the relay enforces is changed by them.
fn carrier_transport() -> std::sync::Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .receive_window(quinn::VarInt::from_u32(
            u32::try_from(CARRIER_CONNECTION_WINDOW_BYTES).unwrap_or(u32::MAX),
        ))
        .stream_receive_window(quinn::VarInt::from_u32(
            u32::try_from(CARRIER_STREAM_WINDOW_BYTES).unwrap_or(u32::MAX),
        ));
    std::sync::Arc::new(transport)
}

/// Run the M7-I07/M7-C22 saturated conjunction gate.
pub async fn verify() -> Result<SaturatedFrameEvidence> {
    let running = start_running(FixtureSetup {
        carrier_client_limits: Some(carrier_limits()),
        carrier_transport: Some(carrier_transport()),
        planned_drain: true,
    })
    .await?;

    let run_result = match timeout(GATE_TIMEOUT, run_gate(&running)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "saturated peer-frame fixture exceeded its bounded run".to_owned(),
        )),
    };
    let cleanup_result = running.shutdown().await;

    let mut evidence = match (run_result, cleanup_result) {
        (Ok(evidence), Ok(())) => evidence,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(cleanup)) => {
            return Err(HarnessError::Process(format!(
                "{error}; saturated peer-frame cleanup also failed: {cleanup}"
            )));
        }
    };
    evidence.cleanup_joined = true;
    evidence.validate()?;
    Ok(evidence)
}

/// Mutable bookkeeping shared by the phases.
struct Saturation {
    /// Already-queued frames consumed so far to let the owner's single-task
    /// carrier loop alternate.
    drain_used: usize,
    /// Lowest physical occupancy observed at any injection step.
    min_resident: usize,
    /// Control enqueue and refusal counters sampled before the carrier stalled.
    control_enqueued_baseline: u64,
    control_refusals_baseline: u64,
}

#[allow(clippy::too_many_lines)]
async fn run_gate(running: &RunningFixture) -> Result<SaturatedFrameEvidence> {
    let started = Instant::now();
    let mut evidence = SaturatedFrameEvidence {
        real_owner_ingress: true,
        non_owner_ingress: true,
        resident_frames_floor: MIN_RESIDENT_FRAMES,
        workload_record_bytes: SATURATION_RECORD_BYTES,
        workload_charge_per_record_bytes: charge_per_record(SATURATION_RECORD_BYTES),
        workload_named_streams: NAMED_STREAMS,
        workload_saturation_streams: SATURATION_STREAMS,
        carrier_drain_budget: CARRIER_DRAIN_BUDGET,
        operation_timeout_ms: OPERATION_TIMEOUT_MS,
        saturation_window_bound_ms: SATURATION_WINDOW_BOUND_MS,
        ..SaturatedFrameEvidence::default()
    };

    // Phase 0: authenticated control registration on the ordinary client, and
    // the device data carrier on its own small-windowed client.
    let (mut control, welcome) = register_control(running).await?;
    let carrier_client = running.carrier_client.as_ref().ok_or_else(|| {
        HarnessError::InvalidInput("saturated gate needs a dedicated carrier client".to_owned())
    })?;
    let mut data = RawStream::open_on(running, carrier_client, InternalRoute::DeviceData, "data")
        .await
        .map_err(|error| http_error("opening saturated data carrier", error))?;
    admit_data(running, &mut data, &welcome.ticket).await?;
    evidence.authenticated_carrier = true;
    evidence.carrier_connection_isolated = true;

    let session = wait_for(running, "device session", |snapshot| {
        snapshot
            .sessions
            .iter()
            .find(|session| session.session_id == welcome.session_id)
            .filter(|session| session.sockets >= 2)
            .cloned()
    })
    .await?;
    evidence.session_profile = session.profile.to_owned();

    let context = FrameContext {
        epoch: welcome.epoch,
        generation: session.active_generation,
        session_id: welcome.session_id.clone(),
    };

    let baseline = owner_session(running, &context.session_id).await?;
    evidence.configured_queue_bytes_limit = baseline.queue_bytes_limit;
    evidence.configured_control_reserved_bytes = baseline.control_reserved_bytes;
    evidence.configured_data_bytes_limit = baseline.data_bytes_limit;
    evidence.configured_control_queue_capacity = baseline.control_queue_capacity;
    evidence.configured_data_queue_capacity = baseline.data_queue_capacity.ok_or_else(|| {
        HarnessError::Process(
            "saturated gate owner session has no attached data carrier to saturate".to_owned(),
        )
    })?;

    // Phase 1: the five named streams.  Their relay-to-connector request frame
    // is read now, while the carrier is still writable, so each phase knows the
    // owner's send cursor for its own stream.
    tracing::info!(phase = "saturated_named_streams", "opening named streams");
    let mut reorder =
        open_consumer_phase(running, &mut control, &mut data, &context, "sat-reorder").await?;
    let mut duplicate =
        open_consumer_phase(running, &mut control, &mut data, &context, "sat-duplicate").await?;
    let mut sibling =
        open_consumer_phase(running, &mut control, &mut data, &context, "sat-sibling").await?;
    let mut late =
        open_consumer_phase(running, &mut control, &mut data, &context, "sat-late").await?;
    let revocation =
        open_consumer_phase(running, &mut control, &mut data, &context, "sat-revoke").await?;

    // A handle on the peer connection this run's consumer ingress already
    // uses, held now so the GOAWAY phase can probe that exact connection
    // rather than letting the pool dial a fresh one.
    let ingress_connection = running
        .client
        .connect(running.destination.clone())
        .await
        .map_err(|error| http_error("holding the saturated ingress connection", error))?;

    // Phase 2: saturate.  From here the fixture stops reading the carrier, so
    // every dispatched record stays physically resident in the owner's bounded
    // outbound data channel.
    tracing::info!(
        phase = "saturated_fill_streams",
        "opening saturation streams"
    );
    let saturation_started = Instant::now();
    let mut occupants = Vec::with_capacity(SATURATION_STREAMS);
    for index in 0..SATURATION_STREAMS {
        occupants.push(open_saturation_stream(running, &mut control, &context, index).await?);
    }
    tracing::info!(
        phase = "saturated_fill_complete",
        "saturation streams opened"
    );
    evidence.streams_admitted = SATURATION_STREAMS + NAMED_STREAMS;

    // The per-device cap is the binding constraint, proven by a refusal rather
    // than read from configuration.  This runs before the GOAWAY so a refusal
    // here cannot be a post-GOAWAY class.
    evidence.stream_cap_refused_one_more = refused_beyond_stream_cap(running).await?;
    evidence.configured_max_streams_per_device = evidence.streams_admitted;

    let peak = wait_for_saturation(running, &context.session_id).await?;
    evidence.data_queue_depth_high_water = peak.data_queue_depth_high_water;
    evidence.physically_resident_frames = peak.data_queue_depth_high_water.saturating_add(1);
    evidence.reserved_free_data_slots_at_peak = peak
        .data_queue_capacity
        .unwrap_or(0)
        .saturating_sub(peak.data_queue_depth_high_water);
    evidence.queue_bytes_high_water = peak.queue_bytes_high_water;
    evidence.data_bytes_high_water = peak.data_bytes_high_water;
    evidence.control_bytes_available_at_data_peak = peak
        .queue_bytes_limit
        .saturating_sub(peak.data_bytes_high_water);

    let mut state = Saturation {
        drain_used: 0,
        min_resident: peak.data_queue_depth.unwrap_or(0).saturating_add(1),
        control_enqueued_baseline: peak.control_queue_enqueued,
        control_refusals_baseline: peak.control_queue_refusals,
    };

    // Phase 3 (item 1): a real revocation close, delivered and acted on, at
    // peak data residency.
    tracing::info!(phase = "saturated_phase_revocation", "phase start");
    timeout(
        PHASE_TIMEOUT,
        phase_revocation(
            running,
            &mut control,
            &mut data,
            &context,
            &revocation,
            &mut state,
            &mut evidence,
        ),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("saturated revocation phase exceeded its bound".to_owned())
    })??;

    // Phase 4 (item 2): reordered and duplicate frames on the saturated route.
    tracing::info!(phase = "saturated_phase_reorder", "phase start");
    timeout(
        PHASE_TIMEOUT,
        phase_reorder(
            running,
            &mut data,
            &context,
            &mut reorder,
            &mut state,
            &mut evidence,
        ),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("saturated reorder phase exceeded its bound".to_owned())
    })??;

    tracing::info!(phase = "saturated_phase_duplicate", "phase start");
    timeout(
        PHASE_TIMEOUT,
        phase_duplicate(
            running,
            &mut data,
            &context,
            &mut duplicate,
            &mut state,
            &mut evidence,
        ),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("saturated duplicate phase exceeded its bound".to_owned())
    })??;

    // Phase 5: a sibling stream, still saturated, survives the terminals.
    tracing::info!(phase = "saturated_phase_sibling", "phase start");
    timeout(
        PHASE_TIMEOUT,
        phase_sibling(
            running,
            &mut data,
            &context,
            &mut sibling,
            &mut state,
            &mut evidence,
        ),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("saturated sibling phase exceeded its bound".to_owned())
    })??;

    // Phase 6 (item 2, terminal half): the late frame fences the session, so it
    // is the session's own last event.
    tracing::info!(phase = "saturated_phase_late", "phase start");
    timeout(
        PHASE_TIMEOUT,
        phase_late(
            running,
            &mut data,
            &context,
            &mut late,
            &mut state,
            &mut evidence,
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("saturated late phase exceeded its bound".to_owned()))??;

    // Phase 7 (item 3): the peer GOAWAY on the same peer connection.  See
    // `phase_goaway` for why it follows the fence.
    tracing::info!(phase = "saturated_phase_goaway", "phase start");
    timeout(
        PHASE_TIMEOUT,
        phase_goaway(running, &ingress_connection, &mut evidence),
    )
    .await
    .map_err(|_| HarnessError::Timeout("saturated GOAWAY phase exceeded its bound".to_owned()))??;

    let live = owner_session(running, &context.session_id).await.ok();
    evidence.control_enqueues_during_saturation =
        live.as_ref()
            .map_or(evidence.control_enqueues_during_saturation, |session| {
                session
                    .control_queue_enqueued
                    .saturating_sub(state.control_enqueued_baseline)
                    .max(evidence.control_enqueues_during_saturation)
            });
    evidence.control_queue_refusals_during_saturation = live.as_ref().map_or(
        evidence.control_queue_refusals_during_saturation,
        |session| {
            session
                .control_queue_refusals
                .saturating_sub(state.control_refusals_baseline)
                .max(evidence.control_queue_refusals_during_saturation)
        },
    );

    evidence.saturation_window_ms =
        u64::try_from(saturation_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    evidence.carrier_drain_records_consumed = state.drain_used;
    evidence.min_resident_frames_during_injection = state.min_resident;
    evidence.no_double_delivery =
        evidence.duplicate_adapter_records == 1 && evidence.late_adapter_bytes_after_fin == 0;
    evidence.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    // Keep every occupant stream alive until the end of the run; dropping them
    // earlier would release the occupancy the phases were measured against.
    for mut occupant in occupants {
        occupant.send.cancel();
        occupant.recv.cancel();
    }
    control.send.cancel();
    control.recv.cancel();
    Ok(evidence)
}

/// Open one consumer stream whose dispatched record is deliberately left
/// unread on the carrier, so it stays physically resident.
async fn open_saturation_stream(
    running: &RunningFixture,
    control: &mut RawStream,
    context: &FrameContext,
    index: usize,
) -> Result<RawStream> {
    let label = format!("sat-fill-{index}");
    let mut stream = RawStream::open(running, InternalRoute::ConsumerStreams, "consumer").await?;
    let envelope = consumer_envelope(running, &label)?;
    stream
        .send_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().map_err(|error| {
                HarnessError::InvalidInput(format!("encoding saturation envelope: {error}"))
            })?,
        )
        .await?;
    stream
        .expect_ok(running, "saturated consumer admission")
        .await?;
    admit_open(control, &context.session_id, context.epoch).await?;
    let body = vec![b'q'; SATURATION_RECORD_BYTES];
    stream
        .send_record(PeerRecordKind::ConsumerChunk, &framed(&body))
        .await?;
    Ok(stream)
}

/// One consumer admission beyond the per-device cap must be refused.
///
/// The refusal is an owner admission outcome on an accepted peer stream, not a
/// transport error, so the stream opens and the owner answers it.
async fn refused_beyond_stream_cap(running: &RunningFixture) -> Result<bool> {
    let mut stream = RawStream::open(running, InternalRoute::ConsumerStreams, "consumer").await?;
    let envelope = consumer_envelope(running, "sat-overflow")?;
    stream
        .send_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().map_err(|error| {
                HarnessError::InvalidInput(format!("encoding overflow envelope: {error}"))
            })?,
        )
        .await?;
    let refused = stream
        .expect_ok(running, "saturated cap overflow admission")
        .await
        .is_err();
    stream.send.cancel();
    stream.recv.cancel();
    Ok(refused)
}

/// Wait until the owner's bounded data channel has reached the configured
/// residency floor, reading nothing from the carrier.
async fn wait_for_saturation(
    running: &RunningFixture,
    session_id: &str,
) -> Result<RelaySessionSnapshot> {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let session = owner_session(running, session_id).await?;
        if session.data_queue_depth_high_water.saturating_add(1) >= MIN_RESIDENT_FRAMES {
            tracing::info!(
                phase = "saturated_peak",
                depth = session.data_queue_depth.unwrap_or(0),
                high_water = session.data_queue_depth_high_water,
                capacity = session.data_queue_capacity.unwrap_or(0),
                enqueued = session.data_queue_enqueued,
                refusals = session.data_queue_refusals,
                queue_bytes = session.queue_bytes,
                "saturation peak"
            );
            return Ok(session);
        }
        if Instant::now() >= deadline {
            let depth = session.data_queue_depth.unwrap_or(0);
            let high_water = session.data_queue_depth_high_water;
            let dispatches = snapshot(running).await?.lifetime_application_dispatches;
            return Err(HarnessError::Process(format!(
                "saturated gate reached only {high_water} latched and {depth} live data-channel entries, below the {MIN_RESIDENT_FRAMES} frame floor (data_enqueued={} data_refusals={} queue_bytes={} queue_messages={} streams={} dispatches={dispatches})",
                session.data_queue_enqueued,
                session.data_queue_refusals,
                session.queue_bytes,
                session.queue_messages,
                session.streams.len(),
            )));
        }
        sleep(POLL).await;
    }
}

async fn owner_session(running: &RunningFixture, session_id: &str) -> Result<RelaySessionSnapshot> {
    let snapshot = snapshot(running).await?;
    session_of(&snapshot, session_id).ok_or_else(|| {
        // Name the owner's own bounded terminal vocabulary rather than only
        // the absence, so a gate failure is diagnosable without tracing.
        let reasons: Vec<&str> = snapshot
            .session_terminal_events
            .iter()
            .filter(|event| event.session_id == session_id)
            .map(|event| event.reason)
            .collect();
        HarnessError::Process(format!(
            "saturated gate owner session is no longer present (terminal reasons=[{}] owner_stages={:?} owner_causes={:?})",
            reasons.join("|"),
            snapshot.peer_fault_diagnostics.stage_counts,
            snapshot.peer_fault_diagnostics.cause_counts,
        ))
    })
}

fn session_of(snapshot: &RelaySnapshot, session_id: &str) -> Option<RelaySessionSnapshot> {
    snapshot
        .sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .cloned()
}

/// Live physical residency: the bounded channel's occupancy plus the one frame
/// the parked physical writer owns and still charges.
fn resident_frames(session: &RelaySessionSnapshot) -> usize {
    session.data_queue_depth.unwrap_or(0).saturating_add(1)
}

/// Sample residency and fold it into the run's continuous minimum.
async fn sample_residency(
    running: &RunningFixture,
    session_id: &str,
    state: &mut Saturation,
) -> Result<usize> {
    let session = owner_session(running, session_id).await?;
    let resident = resident_frames(&session);
    state.min_resident = state.min_resident.min(resident);
    Ok(resident)
}

/// Forward one connector frame and wait until the owner has finished
/// accounting it, using the owner's own data-channel enqueue counter as the
/// settle barrier.
///
/// `inbound_m2_stream_data` queues the frame's ACK last, after the receive
/// cursor, delivery, byte release and credit update, so an increment of
/// `data_queue_enqueued` is exactly the settle point the EC-044 gate reads off
/// the wire.  While the owner's single-task carrier loop is parked on its
/// physical write it is not reading, so a bounded number of already-queued
/// frames is consumed to let it alternate; every such read is counted against
/// the run's allowance and lowers residency, which the caller re-samples.
async fn forward_and_settle(
    running: &RunningFixture,
    data: &mut RawStream,
    session_id: &str,
    frame: &Frame,
    state: &mut Saturation,
) -> Result<()> {
    let baseline = quiet_enqueue_baseline(running, session_id).await?;
    forward_and_wait(running, data, session_id, frame, state, move |session| {
        session.data_queue_enqueued > baseline
    })
    .await
}

/// Forward a frame the owner must account by advancing this stream's
/// contiguous receive cursor.
///
/// Where a frame is expected to make progress, the stream's own cursor is a
/// stronger barrier than the channel counter: it cannot be satisfied by an
/// unrelated enqueue still in flight from an earlier phase.
async fn forward_expecting_recv(
    running: &RunningFixture,
    data: &mut RawStream,
    context: &FrameContext,
    stream_id: u64,
    expected_recv: u64,
    frame: &Frame,
    state: &mut Saturation,
) -> Result<()> {
    forward_and_wait(
        running,
        data,
        &context.session_id,
        frame,
        state,
        move |session| {
            session
                .streams
                .iter()
                .find(|stream| stream.stream_id == stream_id)
                .is_some_and(|stream| stream.recv_contiguous_connector_to_relay >= expected_recv)
        },
    )
    .await
}

/// A data-channel enqueue count that is not still moving.
///
/// The two frames this gate expects to make *no* progress — the out-of-order
/// frame ahead of its gap and the duplicate — can only be settled on the
/// channel counter, and a counter still catching up from the previous phase
/// would satisfy that barrier without the frame under test having been seen at
/// all.  Requiring the count to be unchanged across two consecutive samples
/// before the frame is forwarded removes that race.
async fn quiet_enqueue_baseline(running: &RunningFixture, session_id: &str) -> Result<u64> {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    let mut previous = owner_session(running, session_id)
        .await?
        .data_queue_enqueued;
    loop {
        sleep(QUIET_INTERVAL).await;
        let current = owner_session(running, session_id)
            .await?
            .data_queue_enqueued;
        if current == previous {
            return Ok(current);
        }
        previous = current;
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "saturated gate owner data-channel enqueues never settled".to_owned(),
            ));
        }
    }
}

/// Forward one connector frame and poll the owner's own snapshot until
/// `settled` holds, consuming the bounded drain allowance whenever the owner's
/// single-task carrier loop needs to alternate back to its receive branch.
async fn forward_and_wait<F>(
    running: &RunningFixture,
    data: &mut RawStream,
    session_id: &str,
    frame: &Frame,
    state: &mut Saturation,
    settled: F,
) -> Result<()>
where
    F: Fn(&RelaySessionSnapshot) -> bool,
{
    let refusals = owner_session(running, session_id)
        .await?
        .data_queue_refusals;
    forward_frame(data, frame).await?;

    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let session = owner_session(running, session_id).await?;
        if session.data_queue_refusals > refusals {
            return Err(HarnessError::Process(format!(
                "saturated gate owner refused {} data enqueues while accounting an injected frame",
                session.data_queue_refusals.saturating_sub(refusals)
            )));
        }
        if settled(&session) {
            state.min_resident = state.min_resident.min(resident_frames(&session));
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "saturated gate owner did not account an injected frame within its bound (drain allowance used {} of {CARRIER_DRAIN_BUDGET}, depth={:?} enqueued={} refusals={} queue_bytes={})",
                state.drain_used,
                session.data_queue_depth,
                session.data_queue_enqueued,
                session.data_queue_refusals,
                session.queue_bytes,
            )));
        }
        // Let the owner's single carrier task alternate back to its receive
        // branch by freeing exactly one frame of connection flow control.
        if state.drain_used >= CARRIER_DRAIN_BUDGET {
            return Err(HarnessError::Process(format!(
                "saturated gate exhausted its {CARRIER_DRAIN_BUDGET} record carrier drain allowance without the owner accounting an injected frame (depth={:?} enqueued={} refusals={} queue_bytes={})",
                session.data_queue_depth,
                session.data_queue_enqueued,
                session.data_queue_refusals,
                session.queue_bytes,
            )));
        }
        match timeout(SETTLE_TIMEOUT, data.next_record()).await {
            Ok(Ok(Some(_))) => state.drain_used = state.drain_used.saturating_add(1),
            Ok(Ok(None)) => {
                return Err(HarnessError::Http(
                    "saturated data carrier closed while an injected frame was outstanding"
                        .to_owned(),
                ));
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "saturated data carrier read deadline while draining its allowance".to_owned(),
                ));
            }
        }
        sleep(POLL).await;
    }
}

/// Item 1: a real revocation close, delivered on the control plane and acted
/// on, while the data carrier is saturated.
///
/// The consumer grant is revoked in the authoritative catalog, then a fresh
/// authorization challenge is sent for an already established stream.  The
/// owner re-reads the catalog, finds no grant, and takes
/// `invalidate_stream_challenge`: it queues `AUTHORIZATION_INVALIDATED` on the
/// bounded **control** channel and latches the stream terminal with the typed
/// `GRANT_UNAVAILABLE` failure code.  Delivery is read off the control carrier
/// and the action is read from the owner's own snapshot, both at peak data
/// residency.
async fn phase_revocation(
    running: &RunningFixture,
    control: &mut RawStream,
    data: &mut RawStream,
    context: &FrameContext,
    revocation: &ConsumerPhase,
    state: &mut Saturation,
    evidence: &mut SaturatedFrameEvidence,
) -> Result<()> {
    let stream_id = revocation.stream_id;
    let before = snapshot(running).await?;
    let dispatches_before = before.lifetime_application_dispatches;
    let grant = stream_snapshot(&before, &context.session_id, stream_id).ok_or_else(|| {
        HarnessError::Process("saturated revocation stream is not established".to_owned())
    })?;
    let _ = grant;

    running
        .catalog
        .revoke_grant(
            tenant_id(),
            user_id(),
            device_id(),
            service_id(),
            Utc::now(),
        )
        .await
        .map_err(|error| HarnessError::Http(format!("saturated gate grant revocation: {error}")))?;
    evidence.revocation_grant_revoked = true;
    tracing::info!(phase = "saturated_revoked", "grant revoked");

    let challenge_id = format!("sat-revoke-challenge-{stream_id}");
    let challenge =
        ControlMessage::AuthorizationChallenge(tunnel_protocol::AuthorizationChallenge::new(
            format!("sat-revoke-{stream_id}"),
            context.session_id.clone(),
            context.epoch,
            stream_id,
            challenge_id.clone(),
            format!("sat-revoke-nonce-{stream_id}"),
            service_id().to_string(),
            revocation.permission_digest.clone(),
            revocation.grant_revision,
        ));
    let encoded = tunnel_protocol::control::encode_control(&challenge).map_err(|error| {
        HarnessError::InvalidInput(format!("encoding saturated revocation challenge: {error}"))
    })?;
    control
        .send_record(PeerRecordKind::CompleteControlText, &encoded)
        .await?;
    tracing::info!(
        phase = "saturated_challenge_sent",
        "revocation challenge sent"
    );

    evidence.data_queue_depth_at_revocation = owner_session(running, &context.session_id)
        .await?
        .data_queue_depth
        .unwrap_or(0);
    state.min_resident = state
        .min_resident
        .min(evidence.data_queue_depth_at_revocation.saturating_add(1));

    // Delivery: the owner's revocation close, read off the control carrier
    // while the data carrier stays saturated.
    let invalidated = next_invalidation(control).await?;
    tracing::info!(phase = "saturated_invalidated", "revocation close received");
    evidence.revocation_close_delivered = true;
    evidence.revocation_close_stream_matched = invalidated.stream_id == stream_id
        && invalidated.session_id == context.session_id
        && invalidated.challenge_id == challenge_id;
    evidence.revocation_close_reason = invalidated.reason.clone();

    // Action: the owner's own typed failure code and terminal latch.
    let failure = wait_for(running, "saturated revocation failure code", |snapshot| {
        stream_snapshot(snapshot, &context.session_id, stream_id)
            .and_then(|stream| {
                stream
                    .authorization_failure_code
                    .map(|code| (code, stream.terminal))
            })
            .or_else(|| {
                snapshot
                    .stream_terminal_events
                    .iter()
                    .find(|event| {
                        event.session_id == context.session_id && event.stream_id == stream_id
                    })
                    .and_then(|event| event.authorization_failure_code.map(|code| (code, true)))
            })
    })
    .await?;
    evidence.revocation_failure_code = failure.0.to_owned();
    evidence.revocation_stream_terminal = failure.1;

    let after = snapshot(running).await?;
    evidence.revocation_dispatch_delta = after
        .lifetime_application_dispatches
        .saturating_sub(dispatches_before);

    let session = owner_session(running, &context.session_id).await?;
    evidence.control_enqueues_during_saturation = session
        .control_queue_enqueued
        .saturating_sub(state.control_enqueued_baseline);
    evidence.control_queue_refusals_during_saturation = session
        .control_queue_refusals
        .saturating_sub(state.control_refusals_baseline);

    // Discharge the revoked stream's terminal debt exactly as a connector
    // does.  `invalidate_stream_challenge` latches the stream terminal and
    // arms a five-second fail-closed window that clears only once the stream
    // is physically removed, and `owner_stream_forget_state` requires both
    // directions to carry an acknowledged terminal.  A real connector answers
    // `AUTHORIZATION_INVALIDATED` by closing its half of the stream, so the
    // fixture sends that `FIN`, waits for the owner's own terminal frame to be
    // enqueued, and acknowledges it.  Without this the owner would fail the
    // whole session closed with `TERMINAL_FIN_TIMEOUT` a few seconds later and
    // every later phase would be measuring a dying session.
    tracing::info!(
        phase = "saturated_revoked_fin",
        "closing the revoked stream"
    );
    let fin = Frame::fin(
        context.epoch,
        context.generation,
        stream_id,
        1,
        revocation.relay_last_emitted,
    );
    forward_expecting_recv(running, data, context, stream_id, 1, &fin, state).await?;
    let last_emitted = wait_for(running, "saturated revoked terminal frame", |snapshot| {
        stream_snapshot(snapshot, &context.session_id, stream_id)
            .filter(|stream| stream.last_emitted_relay_to_connector > revocation.relay_last_emitted)
            .map(|stream| stream.last_emitted_relay_to_connector)
    })
    .await?;
    tracing::info!(
        phase = "saturated_revoked_ack",
        last_emitted,
        "acknowledging the revoked stream terminal"
    );
    let ack = Frame::ack(context.epoch, context.generation, stream_id, last_emitted);
    forward_and_wait(
        running,
        data,
        &context.session_id,
        &ack,
        state,
        move |session| {
            !session
                .streams
                .iter()
                .any(|stream| stream.stream_id == stream_id)
        },
    )
    .await?;
    Ok(())
}

/// Read the owner's next `AUTHORIZATION_INVALIDATED` from the control carrier.
async fn next_invalidation(
    control: &mut RawStream,
) -> Result<tunnel_protocol::AuthorizationInvalidated> {
    loop {
        let Some(record) = control.next_record().await? else {
            return Err(HarnessError::Http(
                "saturated control carrier closed before the revocation close".to_owned(),
            ));
        };
        if record.kind() != PeerRecordKind::CompleteControlText {
            continue;
        }
        let message = decode_control(record.body()).map_err(|error| {
            HarnessError::Http(format!("decoding saturated control message: {error}"))
        })?;
        if let ControlMessage::AuthorizationInvalidated(invalidated) = message {
            return Ok(invalidated);
        }
    }
}

/// Item 2, ordering half: one solicited response record split across two
/// sequenced DATA frames, tail before head, on the saturated carrier.
async fn phase_reorder(
    running: &RunningFixture,
    data: &mut RawStream,
    context: &FrameContext,
    phase: &mut ConsumerPhase,
    state: &mut Saturation,
    evidence: &mut SaturatedFrameEvidence,
) -> Result<()> {
    let stream_id = phase.stream_id;
    let record = framed(REORDER_BODY);
    let (head, tail) = record.split_at(REORDER_SPLIT);

    let tail_frame = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        2,
        phase.relay_last_emitted,
        tail.to_vec(),
    );
    forward_and_settle(running, data, &context.session_id, &tail_frame, state).await?;
    let gap = cursors(running, context, stream_id).await?;
    evidence.reorder_recv_after_gap = gap.0;
    evidence.reorder_delivered_after_gap = gap.1;

    let head_frame = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        1,
        phase.relay_last_emitted,
        head.to_vec(),
    );
    forward_expecting_recv(running, data, context, stream_id, 2, &head_frame, state).await?;
    let filled = cursors(running, context, stream_id).await?;
    evidence.reorder_recv_after_fill = filled.0;
    evidence.reorder_delivered_after_fill = filled.1;

    // Byte-exact reassembly is the order proof: had the owner appended in
    // arrival order the record would be the tail followed by the head, whose
    // leading four bytes are not this record's length prefix at all.
    let delivered = next_consumer_record(&mut phase.stream).await?;
    evidence.reorder_order_restored = delivered == REORDER_BODY;
    evidence.reorder_resident_frames =
        sample_residency(running, &context.session_id, state).await?;

    phase.stream.send.cancel();
    phase.stream.recv.cancel();
    Ok(())
}

/// Item 2, duplicate half: an already-accepted sequence replayed on the
/// saturated carrier must move no cursor and deliver nothing twice.
async fn phase_duplicate(
    running: &RunningFixture,
    data: &mut RawStream,
    context: &FrameContext,
    phase: &mut ConsumerPhase,
    state: &mut Saturation,
    evidence: &mut SaturatedFrameEvidence,
) -> Result<()> {
    let stream_id = phase.stream_id;
    let accepted = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        1,
        phase.relay_last_emitted,
        framed(DUPLICATE_BODY),
    );
    forward_expecting_recv(running, data, context, stream_id, 1, &accepted, state).await?;
    evidence.duplicate_delivered_before = cursors(running, context, stream_id).await?.1;

    let first = next_consumer_record(&mut phase.stream).await?;
    if first != DUPLICATE_BODY {
        return Err(HarnessError::Http(
            "saturated duplicate baseline record did not reach the adapter".to_owned(),
        ));
    }

    forward_and_settle(running, data, &context.session_id, &accepted, state).await?;
    evidence.duplicate_delivered_after = cursors(running, context, stream_id).await?.1;
    evidence.duplicate_adapter_records = 1 + phase.stream.drain_buffered().len();
    evidence.duplicate_resident_frames =
        sample_residency(running, &context.session_id, state).await?;

    phase.stream.send.cancel();
    phase.stream.recv.cancel();
    Ok(())
}

/// A sibling stream survives the terminals and the injections.
///
/// The sibling was admitted with the rest of the workload and still owes the
/// response to the record it holds.  Answering it after the revocation close
/// and both injections, while the carrier is still saturated, is the survival
/// proof: a terminal on one stream and a refused frame on another leave an
/// untouched stream able to complete its own round trip byte exact.
async fn phase_sibling(
    running: &RunningFixture,
    data: &mut RawStream,
    context: &FrameContext,
    sibling: &mut ConsumerPhase,
    state: &mut Saturation,
    evidence: &mut SaturatedFrameEvidence,
) -> Result<()> {
    let stream_id = sibling.stream_id;
    let response = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        1,
        sibling.relay_last_emitted,
        framed(SIBLING_BODY),
    );
    forward_expecting_recv(running, data, context, stream_id, 1, &response, state).await?;
    let delivered = next_consumer_record(&mut sibling.stream).await?;
    evidence.sibling_survived_terminals = delivered == SIBLING_BODY;
    evidence.sibling_resident_frames =
        sample_residency(running, &context.session_id, state).await?;

    sibling.stream.send.cancel();
    sibling.stream.recv.cancel();
    Ok(())
}

/// Item 2, terminal half: a DATA frame after the terminal FIN on the saturated
/// carrier.  Exactly one terminal survives, its identity never changes, the
/// session fails closed with the typed reason, and no adapter byte appears past
/// the FIN cursor.
async fn phase_late(
    running: &RunningFixture,
    data: &mut RawStream,
    context: &FrameContext,
    phase: &mut ConsumerPhase,
    state: &mut Saturation,
    evidence: &mut SaturatedFrameEvidence,
) -> Result<()> {
    let stream_id = phase.stream_id;
    let response = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        1,
        phase.relay_last_emitted,
        framed(LATE_BODY),
    );
    forward_expecting_recv(running, data, context, stream_id, 1, &response, state).await?;
    let delivered = next_consumer_record(&mut phase.stream).await?;
    if delivered != LATE_BODY {
        return Err(HarnessError::Http(
            "saturated late baseline record did not reach the adapter".to_owned(),
        ));
    }
    evidence.late_resident_frames = sample_residency(running, &context.session_id, state).await?;

    let fin = Frame::fin(
        context.epoch,
        context.generation,
        stream_id,
        2,
        phase.relay_last_emitted,
    );
    forward_expecting_recv(running, data, context, stream_id, 2, &fin, state).await?;

    let first_terminal = wait_for(running, "saturated late terminal", |snapshot| {
        terminal_event(snapshot, &context.session_id, stream_id)
    })
    .await?;
    evidence.late_fin_cursor = first_terminal.delivered_contiguous_connector_to_relay;

    // The terminal has been latched.  A DATA frame after it is a terminal
    // precedence violation on a real peer forward, not a late event.
    let late = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        3,
        phase.relay_last_emitted,
        framed(b"saturated-late-after-fin"),
    );
    // The fence tears the session down, so the owner's own session terminal
    // event is this frame's barrier rather than any per-session counter.  The
    // drain allowance still applies: the owner's single-task carrier loop is
    // parked on its physical write and would otherwise never read the frame.
    forward_frame(data, &late).await?;
    evidence.late_session_reason =
        wait_for_session_close(running, data, &context.session_id, state).await?;

    // The first terminal identity is immutable: the complete retained tuple is
    // re-sampled and compared, and no second terminal may appear.
    let mut immutable = true;
    let mut samples = 0usize;
    for _ in 0..TERMINAL_SAMPLES {
        sleep(TERMINAL_SAMPLE_INTERVAL).await;
        let snapshot = snapshot(running).await?;
        samples += 1;
        let again = terminal_event(&snapshot, &context.session_id, stream_id);
        let count = snapshot
            .stream_terminal_events
            .iter()
            .filter(|event| event.session_id == context.session_id && event.stream_id == stream_id)
            .count();
        if again.as_ref() != Some(&first_terminal) || count != 1 {
            immutable = false;
            break;
        }
    }
    evidence.terminal_identity_samples = samples;
    evidence.terminal_identity_immutable = immutable;

    let snapshot = snapshot(running).await?;
    evidence.late_stream_terminals = snapshot
        .stream_terminal_events
        .iter()
        .filter(|event| event.session_id == context.session_id && event.stream_id == stream_id)
        .count();

    // Nothing may reach the adapter past the FIN.  The consumer stream is
    // drained to its end; any record here would be a post-terminal delivery.
    let mut after_fin = 0usize;
    loop {
        match phase.stream.next_record().await {
            Ok(Some(record)) => after_fin = after_fin.saturating_add(record.body().len()),
            Ok(None) => break,
            // A fenced session tears the forwarded consumer stream down; an
            // interrupted read is the expected shape and proves nothing was
            // delivered, so it ends the drain rather than failing the phase.
            Err(_) => break,
        }
    }
    evidence.late_adapter_bytes_after_fin = after_fin;

    phase.stream.send.cancel();
    phase.stream.recv.cancel();
    Ok(())
}

/// Item 3: a real peer HTTP/3 GOAWAY on the saturated route.
///
/// The owner's planned listener drain is requested and the ingress-observable
/// consequence is asserted: a fresh peer stream on the very connection that
/// carried this run's consumer ingress is refused with the typed pre-dispatch
/// GOAWAY class rather than admitted.
///
/// **Recorded ordering limit.** That drain sends a listener-wide `GOAWAY(0)`,
/// which ends this device session within tens of milliseconds -- measured at
/// roughly 70 ms.  The post-FIN fence has to be the session's own last event
/// for `INVALID_SEQUENCE` to be attributable to the injected frame rather than
/// to the drain, so the GOAWAY is requested only after that fence has already
/// closed the session.  The consequence is that the surviving sibling is
/// asserted against the stream terminals under saturation (`phase_sibling`)
/// and not across the GOAWAY itself.
async fn phase_goaway(
    running: &RunningFixture,
    ingress: &tunnel_transport::PeerConnectionHandle,
    evidence: &mut SaturatedFrameEvidence,
) -> Result<()> {
    running.request_planned_goaway()?;
    evidence.goaway_requested = true;
    evidence.goaway_requested_after_fence = !evidence.late_session_reason.is_empty();

    // The owner's own listener diagnostics: the planned HTTP/3 GOAWAY was
    // actually written on a peer connection, not merely requested.
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let stats = running.server_diagnostics.snapshot();
        if stats
            .connections
            .iter()
            .any(|connection| connection.planned_goaway_sent)
        {
            evidence.goaway_sent_by_owner = true;
            break;
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "saturated gate owner never reported a planned GOAWAY on a peer connection"
                    .to_owned(),
            ));
        }
        sleep(POLL).await;
    }

    // The ingress-observable consequence, taken on the very connection that
    // carried this run's consumer ingress.  The handle is held from before the
    // drain deliberately: asking the pool for a connection instead would let it
    // dial a fresh one against a listener that has already closed admission,
    // which is a different (and untyped) outcome.
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let request = http::Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}{}",
                super::SERVER_NAME,
                tunnel_relay::peer_runtime::PeerRuntime::path(InternalRoute::ConsumerStreams)
            ))
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|error| {
                HarnessError::InvalidInput(format!("building saturated GOAWAY probe: {error}"))
            })?;
        match ingress.open(request).await {
            Err(PeerTransportError::GoAway) => {
                evidence.goaway_refused_new_peer_stream = true;
                evidence.goaway_refusal_class = GOAWAY_CLASS.to_owned();
                return Ok(());
            }
            Err(other) => {
                return Err(HarnessError::Http(format!(
                    "saturated gate expected a typed GOAWAY refusal, observed {other}"
                )));
            }
            Ok(opened) => {
                let (mut send, mut recv) = opened.split();
                send.cancel();
                recv.cancel();
                if Instant::now() >= deadline {
                    return Err(HarnessError::Timeout(
                        "saturated gate still admitted peer streams after the planned GOAWAY"
                            .to_owned(),
                    ));
                }
                sleep(POLL).await;
            }
        }
    }
}

/// Wait for the owner's own bounded session terminal event, consuming the
/// bounded drain allowance so the parked carrier loop can read the frame that
/// fences the session.
async fn wait_for_session_close(
    running: &RunningFixture,
    data: &mut RawStream,
    session_id: &str,
    state: &mut Saturation,
) -> Result<String> {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let snapshot = snapshot(running).await?;
        if let Some(event) = snapshot
            .session_terminal_events
            .iter()
            .find(|event| event.session_id == session_id)
        {
            return Ok(event.reason.to_owned());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "saturated gate owner never closed the fenced session within its bound".to_owned(),
            ));
        }
        if state.drain_used < CARRIER_DRAIN_BUDGET
            && let Ok(Ok(Some(_))) = timeout(SETTLE_TIMEOUT, data.next_record()).await
        {
            state.drain_used = state.drain_used.saturating_add(1);
        }
        sleep(POLL).await;
    }
}

fn terminal_event(
    snapshot: &RelaySnapshot,
    session_id: &str,
    stream_id: u64,
) -> Option<StreamTerminalEvent> {
    snapshot
        .stream_terminal_events
        .iter()
        .find(|event| event.session_id == session_id && event.stream_id == stream_id)
        .cloned()
}

/// Receive and delivered contiguous connector-to-relay cursors for one stream.
async fn cursors(
    running: &RunningFixture,
    context: &FrameContext,
    stream_id: u64,
) -> Result<(u64, u64)> {
    let snapshot = snapshot(running).await?;
    Ok(
        stream_snapshot(&snapshot, &context.session_id, stream_id).map_or((0, 0), |stream| {
            (
                stream.recv_contiguous_connector_to_relay,
                stream.delivered_contiguous_connector_to_relay,
            )
        }),
    )
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{
        CARRIER_DRAIN_BUDGET, GOAWAY_CLASS, GRANT_UNAVAILABLE, MIN_RESIDENT_FRAMES, NAMED_STREAMS,
        SATURATION_STREAMS, SATURATION_WINDOW_BOUND_MS, SaturatedFrameEvidence, charge_per_record,
    };
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> SaturatedFrameEvidence {
        SaturatedFrameEvidence {
            real_owner_ingress: true,
            non_owner_ingress: true,
            authenticated_carrier: true,
            carrier_connection_isolated: true,
            session_profile: "m2".to_owned(),
            configured_queue_bytes_limit: 4 * 1024 * 1024,
            configured_control_reserved_bytes: 4 * 32 * 1024,
            configured_data_bytes_limit: 4 * 1024 * 1024 - 4 * 32 * 1024,
            configured_data_queue_capacity: 128,
            configured_control_queue_capacity: 128,
            configured_max_streams_per_device: 64,
            stream_cap_refused_one_more: true,
            workload_record_bytes: 20_000,
            workload_charge_per_record_bytes: charge_per_record(20_000),
            workload_saturation_streams: SATURATION_STREAMS,
            workload_named_streams: NAMED_STREAMS,
            streams_admitted: 64,
            data_queue_depth_high_water: 52,
            physically_resident_frames: 53,
            resident_frames_floor: MIN_RESIDENT_FRAMES,
            min_resident_frames_during_injection: 38,
            reserved_free_data_slots_at_peak: 76,
            queue_bytes_high_water: 2_544_540,
            data_bytes_high_water: 2_544_540,
            control_bytes_available_at_data_peak: 4 * 1024 * 1024 - 2_544_540,
            carrier_drain_records_consumed: 21,
            carrier_drain_budget: CARRIER_DRAIN_BUDGET,
            saturation_window_ms: 4_200,
            saturation_window_bound_ms: SATURATION_WINDOW_BOUND_MS,
            operation_timeout_ms: 30_000,
            revocation_grant_revoked: true,
            revocation_close_delivered: true,
            revocation_close_stream_matched: true,
            revocation_close_reason: "grant unavailable".to_owned(),
            revocation_failure_code: GRANT_UNAVAILABLE.to_owned(),
            revocation_stream_terminal: true,
            revocation_dispatch_delta: 0,
            data_queue_depth_at_revocation: 52,
            control_enqueues_during_saturation: 3,
            control_queue_refusals_during_saturation: 0,
            reorder_recv_after_gap: 0,
            reorder_delivered_after_gap: 0,
            reorder_recv_after_fill: 2,
            reorder_delivered_after_fill: 2,
            reorder_order_restored: true,
            reorder_resident_frames: 48,
            duplicate_delivered_before: 1,
            duplicate_delivered_after: 1,
            duplicate_adapter_records: 1,
            duplicate_resident_frames: 44,
            sibling_survived_terminals: true,
            sibling_resident_frames: 42,
            no_double_delivery: true,
            late_fin_cursor: 2,
            late_stream_terminals: 1,
            late_adapter_bytes_after_fin: 0,
            late_session_reason: "INVALID_SEQUENCE".to_owned(),
            late_resident_frames: 38,
            terminal_identity_immutable: true,
            terminal_identity_samples: 8,
            goaway_requested: true,
            goaway_refused_new_peer_stream: true,
            goaway_refusal_class: GOAWAY_CLASS.to_owned(),
            goaway_sent_by_owner: true,
            goaway_requested_after_fence: true,
            cleanup_joined: true,
            elapsed_ms: 9_000,
        }
    }

    #[test]
    fn saturated_validator_accepts_complete_evidence() {
        valid_evidence()
            .validate()
            .expect("complete saturated conjunction evidence is valid");
    }

    /// Every flag, count and bound in the validator has a red case that reaches
    /// the shared nonzero CLI exit path with its own named field.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_saturated_flag_and_bound_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut SaturatedFrameEvidence));
        let cases: [Mutate; 53] = [
            ("real_owner_ingress", |e| e.real_owner_ingress = false),
            ("non_owner_ingress", |e| e.non_owner_ingress = false),
            ("authenticated_carrier", |e| e.authenticated_carrier = false),
            ("carrier_connection_isolated", |e| {
                e.carrier_connection_isolated = false
            }),
            ("session_profile", |e| e.session_profile = "m1".to_owned()),
            ("configured_queue_bytes_limit", |e| {
                e.configured_queue_bytes_limit = 1024
            }),
            ("configured_control_reserved_bytes", |e| {
                e.configured_control_reserved_bytes = 0
            }),
            ("configured_data_bytes_limit", |e| {
                e.configured_data_bytes_limit = 4 * 1024 * 1024
            }),
            ("configured_queue_capacity", |e| {
                e.configured_data_queue_capacity = 64
            }),
            ("configured_max_streams_per_device", |e| {
                e.configured_max_streams_per_device = 32
            }),
            ("stream_cap_refused_one_more", |e| {
                e.stream_cap_refused_one_more = false
            }),
            ("workload_record_bytes", |e| e.workload_record_bytes = 1_000),
            ("workload_charge_per_record_bytes", |e| {
                e.workload_charge_per_record_bytes = 1
            }),
            ("workload_named_streams", |e| e.workload_named_streams = 4),
            ("workload_saturation_streams", |e| {
                e.workload_saturation_streams = 1
            }),
            ("streams_admitted", |e| e.streams_admitted = 63),
            ("workload_fits_data_bytes_limit", |e| {
                e.workload_charge_per_record_bytes = 4 * 1024 * 1024;
                e.workload_record_bytes = 20_000;
            }),
            ("resident_frames_floor", |e| e.resident_frames_floor = 1),
            ("physically_resident_frames", |e| {
                e.physically_resident_frames = 52
            }),
            ("saturation_reached_floor", |e| {
                e.data_queue_depth_high_water = 4;
                e.physically_resident_frames = 5;
                e.reserved_free_data_slots_at_peak = 124;
                e.min_resident_frames_during_injection = 5;
            }),
            ("min_resident_frames_during_injection", |e| {
                e.min_resident_frames_during_injection = 3
            }),
            ("min_resident_frames_bounded_by_peak", |e| {
                e.min_resident_frames_during_injection = 99
            }),
            ("reserved_free_data_slots_at_peak", |e| {
                e.reserved_free_data_slots_at_peak = 1
            }),
            ("queue_bytes_high_water", |e| e.queue_bytes_high_water = 0),
            ("data_bytes_high_water", |e| e.data_bytes_high_water = 0),
            ("control_bytes_available_at_data_peak", |e| {
                e.control_bytes_available_at_data_peak = 1
            }),
            ("carrier_drain_budget", |e| e.carrier_drain_budget = 1_000),
            ("carrier_drain_records_consumed", |e| {
                e.carrier_drain_records_consumed = CARRIER_DRAIN_BUDGET + 1
            }),
            ("operation_timeout_ms", |e| e.operation_timeout_ms = 1_000),
            ("saturation_window_bound_ms", |e| {
                e.saturation_window_bound_ms = 60_000
            }),
            ("saturation_window_ms", |e| {
                e.saturation_window_ms = SATURATION_WINDOW_BOUND_MS + 1
            }),
            ("revocation_grant_revoked", |e| {
                e.revocation_grant_revoked = false
            }),
            ("revocation_close_delivered", |e| {
                e.revocation_close_delivered = false
            }),
            ("revocation_close_stream_matched", |e| {
                e.revocation_close_stream_matched = false
            }),
            ("revocation_close_reason", |e| {
                e.revocation_close_reason = String::new()
            }),
            ("revocation_failure_code", |e| {
                e.revocation_failure_code = "AUTHORIZATION_CHANGED".to_owned()
            }),
            ("revocation_stream_terminal", |e| {
                e.revocation_stream_terminal = false
            }),
            ("revocation_dispatch_delta", |e| {
                e.revocation_dispatch_delta = 1
            }),
            ("data_queue_depth_at_revocation", |e| {
                e.data_queue_depth_at_revocation = 2
            }),
            ("control_enqueues_during_saturation", |e| {
                e.control_enqueues_during_saturation = 0
            }),
            ("control_queue_refusals_during_saturation", |e| {
                e.control_queue_refusals_during_saturation = 1
            }),
            ("reorder_recv_after_gap", |e| e.reorder_recv_after_gap = 2),
            ("reorder_delivered_after_gap", |e| {
                e.reorder_delivered_after_gap = 1
            }),
            ("reorder_recv_after_fill", |e| e.reorder_recv_after_fill = 1),
            ("reorder_delivered_after_fill", |e| {
                e.reorder_delivered_after_fill = 1;
                e.reorder_recv_after_fill = 1;
            }),
            ("reorder_order_restored", |e| {
                e.reorder_order_restored = false
            }),
            ("reorder_resident_frames", |e| e.reorder_resident_frames = 4),
            ("duplicate_delivered_before", |e| {
                e.duplicate_delivered_before = 0;
                e.duplicate_delivered_after = 0;
            }),
            ("duplicate_delivered_after", |e| {
                e.duplicate_delivered_after = 2
            }),
            ("duplicate_adapter_records", |e| {
                e.duplicate_adapter_records = 2
            }),
            ("duplicate_resident_frames", |e| {
                e.duplicate_resident_frames = 4
            }),
            ("sibling_survived_terminals", |e| {
                e.sibling_survived_terminals = false
            }),
            ("sibling_resident_frames", |e| e.sibling_resident_frames = 4),
        ];
        for (field, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(evidence.validate(), field);
        }
    }

    /// The remaining red cases: terminal, GOAWAY and cleanup dimensions.
    #[test]
    fn every_saturated_terminal_and_goaway_bound_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut SaturatedFrameEvidence));
        let cases: [Mutate; 13] = [
            ("no_double_delivery", |e| e.no_double_delivery = false),
            ("late_fin_cursor", |e| e.late_fin_cursor = 0),
            ("late_stream_terminals", |e| e.late_stream_terminals = 2),
            ("late_adapter_bytes_after_fin", |e| {
                e.late_adapter_bytes_after_fin = 1
            }),
            ("late_session_reason", |e| {
                e.late_session_reason = "STREAM_CLOSED".to_owned()
            }),
            ("late_resident_frames", |e| e.late_resident_frames = 4),
            ("terminal_identity_samples", |e| {
                e.terminal_identity_samples = 3
            }),
            ("terminal_identity_immutable", |e| {
                e.terminal_identity_immutable = false
            }),
            ("goaway_requested", |e| e.goaway_requested = false),
            ("goaway_refused_new_peer_stream", |e| {
                e.goaway_refused_new_peer_stream = false
            }),
            ("goaway_requested_after_fence", |e| {
                e.goaway_requested_after_fence = false
            }),
            ("goaway_sent_by_owner", |e| e.goaway_sent_by_owner = false),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (field, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(evidence.validate(), field);
        }
    }

    /// The GOAWAY refusal class is a closed label, not free text.
    #[test]
    fn saturated_validator_rejects_an_unexpected_goaway_class() {
        let mut evidence = valid_evidence();
        evidence.goaway_refusal_class = "closed".to_owned();
        assert_rejected(evidence.validate(), "goaway_refusal_class");
    }
}
