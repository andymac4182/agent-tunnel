//! A live 9P2000.L filesystem session carried across the **replacement of a
//! failed data socket**, over the real cluster: a consumer WSS session through
//! the owning relay's public route, the owner actor, the device data WebSocket
//! and `tunnel-client`'s filesystem export.
//!
//! This is M4-06's *"data-only recovery" clause proper*, and it is the one
//! event in the whole paragraph whose contract points **towards** retention.
//! `docs/protocol.md` states the paragraph in two sentences:
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
//! Gates 8, 9 and 10 each drove an event named in the *first* sentence — a
//! consumer reconnect, a control-session reconnect, a connector process
//! restart — and each therefore had to prove a fid does **not** survive,
//! because each of those events destroys the second sentence's qualifier.
//! `verify-m4-fs-rotation` drives a *scheduled* rotation, which is a clean
//! attempt and not a failure at all.  **No gate had ever driven the second
//! sentence's own event**: a data socket that genuinely *failed*, with a
//! filesystem session attached.  That is this gate, and it is the positive
//! case the other four are the negative of.
//!
//! **The trap here is inverted, so retention is not assumed either.**  The
//! sentence licenses preservation *conditionally*: "**only while** the same
//! control owner and all ordered stream state are retained".  A gate that
//! simply observed a surviving fid would prove nothing, because a fid
//! surviving a failure that had *also* changed the control owner or lost
//! ordered stream state would be the violation, not the contract.  So the two
//! qualifiers are **asserted as conditions of the run**, not assumed:
//!
//! * **"the same control owner ... retained"** — the *control* socket is never
//!   touched, and that is checked from two independent places rather than from
//!   the harness's intent.  The authoritative catalog's owner token must name
//!   the **same session identity** and the **same epoch** either side of the
//!   failure, and the owner relay's own session snapshot must agree.  A
//!   control-session reconnect or an owner handover would move one of them;
//!   gate 9 is the gate where they do move, and there a fid does not survive.
//! * **"all ordered stream state ... retained"** — the replacement carrier must
//!   be a *retained recovery* of the same logical session rather than a fresh
//!   one.  The connector reports a recovery attempt whose released carrier is
//!   exactly the carrier that died and whose successor is exactly the carrier
//!   that replaced it; the owner's `total_replayed_frames` advances, which is
//!   the ordered state being carried over rather than re-established; and the
//!   consumer stream keeps its `stream_id` **and its `operation_id`**, the
//!   relay's own stable logical-operation identity, which is defined to
//!   survive carrier generations.
//!
//! **And this is a *failure*, not a scheduled rotation.**  The distinction is
//! the whole reason the clause was still open, so it is driven rather than
//! declared.  The device's rotation policy is left at its default 300-second
//! interval and the scenario is bounded far below it, so no scheduled attempt
//! can fire; `rotations_completed` is asserted **unchanged** across the event,
//! at zero.  The carrier is destroyed by closing the device data socket at the
//! harness TCP proxy — a transport death with no rotation handshake, no
//! `ROTATE_*` exchange, no candidate prepared in advance and no chance for
//! either endpoint to quiesce.  What replaces it is the product's own bounded
//! retained recovery, reached through `RecoveryReason::OldTransportLost`.
//!
//! **What makes the failure concurrent rather than sequential.**  A socket
//! that dies between two settled 9P exchanges proves nothing: the interesting
//! case is death *while an exchange is outstanding*, because that is when a
//! tag, a fid and a produced-but-undelivered reply are all in a state someone
//! has to define.  The construction is gate 8's canonical one, proven from the
//! owner's own per-stream cursors rather than from timing:
//!
//! 1. The consumer opens a fid and reads the first part of a synthetic file,
//!    so the fid is established and serving before anything is perturbed.
//! 2. The device data socket's **connector→relay** bytes are paused at the
//!    proxy once the carrier has settled.  The control socket is untouched.
//! 3. The owner is sampled *while paused*, fixing this stream's
//!    `last_emitted_relay_to_connector` and
//!    `recv_contiguous_connector_to_relay`.
//! 4. The consumer sends one `Tread` and does **not** read its reply.  The
//!    request crosses on the still-flowing relay→connector direction, so the
//!    emit cursor **advances**; the reply is sequenced into the paused
//!    direction, so the receive cursor **cannot**.
//! 5. The gate waits for exactly that pair and **destroys the socket** at that
//!    instant.  The proof that the exchange was outstanding at the failure is
//!    `emitted_at_failure > emitted_before && recv_contiguous_at_failure ==
//!    recv_contiguous_before`, on the owner's own record.
//! 6. The paused bytes are **never released**: the connection is gone, so the
//!    `Rread` the device had already produced dies inside the failed carrier.
//!    The reply the consumer eventually reads is therefore one the transport
//!    carried over, not one that was merely late.
//!
//! **The assertions are on the operation, not on liveness.**  A session that
//! still exists proves nothing.  What is asserted is that the held tag came
//! back carrying data on the fid that was open before the socket died, that
//! the whole file's every byte arrived exactly once across the failure on that
//! one fid with an exact checksum, that the fid opened beforehand still
//! answers `Tgetattr` at the same size, that the attach fid still walks, and
//! that exactly **one** `Tattach` was sent all run — the contract's "the relay
//! neither duplicates `Tattach` nor reconstructs fids".
//!
//! All fixture content is synthetic and generated here; no evidence field
//! carries a path, a name or file content.

use std::time::{Duration, Instant};

use tokio::time::{sleep, timeout};
use tunnel_client::{
    ConnectOptions, FsExportSettings, LocalExport, LocalExportKind, http_forward::HttpHandlers,
};
use tunnel_fs_ninep::{GETATTR_BASIC, Message, flags::O_RDONLY};
use tunnel_protocol::rotation::RecoveryReason;
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

/// The synthetic file the failure-spanning read covers.
///
/// Large enough that the transfer needs many maximum-size `Rread` messages, so
/// the socket dies inside a transfer rather than between two of them.
const RECOVERY_FILE_BYTES: usize = 1_572_864;
/// The transfer must need more than this many `Rread` messages.
const MIN_READ_MESSAGES: usize = 20;
/// How much of the file is read before anything is perturbed, establishing
/// that the fid serves normally first.
const PREFIX_READS: usize = 3;

/// The fid numbers the held session binds.
const ATTACH_FID: u32 = 0;
const FILE_FID: u32 = 1;
/// A fid bound **after** the recovery, so a freshly allocated tag and fid are
/// shown to correlate on the replacement carrier.
const POST_FID: u32 = 2;

/// The owner's label for a recovery entered because the authenticated **data**
/// transport was lost.
///
/// Derived, not pinned: the relay publishes `rotation_recovery_reason` through
/// its own closed mapping of the protocol's `RecoveryReason`, so the gate reads
/// the value back out of the library rather than writing the string here.  The
/// distinction matters: `ControlLost` is gate 9's event, and there a fid must
/// **not** survive.
const OLD_TRANSPORT_LOST: &str =
    tunnel_relay::recovery_reason_name(RecoveryReason::OldTransportLost);

/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for a cluster state change.
const WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for the connector to complete its retained recovery.
///
/// Comfortably above the protocol's own recovery episode budget, so a run that
/// exceeds it is a product failure and not a tight harness bound.
const RECOVERY_WAIT: Duration = Duration::from_secs(60);
/// A bound on any single 9P round trip **after** the recovery.
///
/// Every exchange past the carrier replacement gets its own deadline rather
/// than sharing the scenario's.  [`SCENARIO_TIMEOUT`] fires in `verify`, which
/// *drops* the scenario future, so the status-and-evidence dump in `run` never
/// executes and a hang reports with no evidence attached — and a session that
/// answers nothing after the recovery is M4-29 mode B, the case whose evidence
/// matters most.  Generous enough that only a session that has genuinely
/// stopped answering trips it.
const POST_RECOVERY_REPLY: Duration = Duration::from_secs(30);
/// The poll interval for every bounded wait here.
const POLL: Duration = Duration::from_millis(20);
/// The whole scenario's bound.
///
/// Deliberately far below the device's default 300-second rotation interval,
/// so no scheduled rotation attempt can fire during the run and the generation
/// change this gate observes can only be the failure's.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(240);

/// What the owner recorded about the stream the data socket died under.
///
/// Payload-free: sequences, identifiers and lifecycle bits only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FailureObservation {
    /// The consumer stream the filesystem session ran on.
    pub stream_id: u64,
    /// The owner's relay→connector emit cursor for this stream, sampled while
    /// the reverse direction was already paused and before the held `Tread`.
    pub emitted_before: u64,
    /// The same cursor at the instant the data socket was destroyed.  It must
    /// have advanced: the relay dispatched the request toward the device.
    pub emitted_at_failure: u64,
    /// The owner's contiguous connector→relay receive cursor for this stream,
    /// sampled at the same instant as [`Self::emitted_before`].
    pub recv_contiguous_before: u64,
    /// The same cursor at the instant of the failure.  It must **not** have
    /// advanced: no answer to that request had reached the owner.
    pub recv_contiguous_at_failure: u64,
}

impl FailureObservation {
    /// Whether this sample shows a 9P request the relay had dispatched and had
    /// received no answer to, at the instant the data socket died.  This is
    /// the gate's concurrency proof, and it is the owner's own record rather
    /// than a timestamp comparison.
    #[must_use]
    pub fn request_outstanding_at_failure(&self) -> bool {
        self.emitted_at_failure > self.emitted_before
            && self.recv_contiguous_at_failure == self.recv_contiguous_before
    }
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsDataRecoveryEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    /// The negotiated session parameters, so a run cannot pass on a session
    /// that never reached 9P.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub negotiated_dialect: String,

    /// Bytes read on the fid **before** anything was perturbed.
    pub prefix_bytes: usize,
    /// The owner's sample either side of the failure.
    pub failure: FailureObservation,
    /// Whether that sample proves the request was outstanding at the failure.
    pub request_outstanding_at_failure: bool,
    /// How many polls the outstanding state took to observe, for diagnosis.
    pub failure_polls: usize,
    /// The tag that was outstanding when the socket died.
    pub held_tag: u16,

    // ---- This was a failure, not a scheduled rotation. ----
    /// The physical carrier identity the owner had before the failure, and the
    /// one it has after.  They must differ: the socket really was replaced.
    pub connection_id_before: String,
    pub connection_id_after: String,
    /// The owner's active generation either side.  A replacement allocates a
    /// strictly greater generation.
    pub generation_before: u64,
    pub generation_after: u64,
    /// Completed **scheduled** rotations either side.  Both must be zero: the
    /// interval is the default 300 s and the run is bounded far below it, so a
    /// generation change here cannot be the timer's.
    pub rotations_completed_before: u64,
    pub rotations_completed_after: u64,
    /// Whether the destroyed connection was gone from the proxy afterwards and
    /// a **replacement** device connection was dialled through it, so the
    /// carrier replacement is visible at the transport and not only in
    /// diagnostics.
    pub failed_connection_closed_at_proxy: bool,
    pub replacement_connection_observed_at_proxy: bool,

    // ---- Qualifier one: the same control owner is retained. ----
    /// The authoritative catalog's owner token either side of the failure.
    /// Same session identity, same epoch: the control owner did not change.
    pub catalog_owner_session_stable: bool,
    pub catalog_epoch_before: u64,
    pub catalog_epoch_after: u64,
    /// The owner relay's own session snapshot agrees with the catalog.
    pub owner_session_id_stable: bool,
    pub owner_epoch_before: u64,
    pub owner_epoch_after: u64,
    /// The control socket the connector holds was never replaced.
    pub control_carrier_unchanged: bool,

    // ---- Qualifier two: all ordered stream state is retained. ----
    /// The connector entered a bounded retained recovery rather than making a
    /// fresh session.
    pub recovery_attempted: bool,
    /// And the **owner's** own record of why: a lost data transport, not a
    /// lost control socket.  Read from the relay snapshot so the two endpoints
    /// have to agree about what failed.
    ///
    /// **This one is latched from a poll, so a `None` here can be the harness
    /// rather than the product.**  `rotation_recovery_reason` is *live* state
    /// the rotation state machine clears when the episode closes, and the latch
    /// below samples at the poll interval — so an episode that opens and closes
    /// inside one window leaves this `None` and fails the run on a rule the
    /// product did not break.  If this rule alone ever fails while every other
    /// qualifier holds, suspect that race before attributing it to M4-29; no
    /// run has yet shown it.
    pub owner_recovery_reason: Option<String>,
    /// The recovery released exactly the carrier that died and installed
    /// exactly the carrier that replaced it.
    pub recovery_released_failed_carrier: bool,
    pub recovery_successor_is_active_carrier: bool,
    /// The owner replayed retained frames onto the replacement carrier.  A
    /// clean rotation leaves this at zero; ordered state carried across a
    /// failure does not.
    pub replayed_frames_before: u64,
    pub replayed_frames_after: u64,
    /// The consumer stream kept the relay's own stable logical operation
    /// identity, which is defined to survive carrier generations.
    pub operation_id_stable: bool,
    /// The stream this session ran on was never deregistered at the owner: a
    /// stream bearing **this** id is still there after the failure.
    pub stream_remained_registered: bool,
    /// And it is the session's **only** consumer stream.
    ///
    /// Deliberately **not** derived from the same lookup as
    /// [`Self::stream_remained_registered`].  An earlier revision recorded a
    /// "stream id stable" bit that was literally `stream.is_some()` for a
    /// stream found *by* matching that id, so the two could never disagree in
    /// any run the gate can produce — a duplicated fact wearing two names,
    /// which is what the thirteen removed rules were removed for.  Counted
    /// independently, the two are orthogonal and together say something
    /// neither says alone: retention, rather than a deregister followed by a
    /// re-register under a fresh id, which would leave this true and
    /// `stream_remained_registered` false.
    pub sole_consumer_stream_at_owner: bool,
    /// The stream is not in a terminal state.
    ///
    /// A stream can be **present and finished**, and every other
    /// ordered-stream-state bit here is satisfied by one, so without this a
    /// retained-but-dead stream would pass the antecedent.  `terminal` is
    /// published on the owner's stream snapshot and was previously never read.
    ///
    /// **What it turned out to be worth, stated as measured rather than as
    /// predicted.**  It does *not* name M4-29 mode A: that mode fails earlier,
    /// at the connector's own recovery wait, before this block runs at all, and
    /// it is named there.  What this rules out is a terminal stream as the
    /// explanation for **mode B** — observed `true` on a mode B run, so in that
    /// mode the owner's stream is registered, sole, non-terminal and fully
    /// quiesced, and still answers nothing.
    pub stream_not_terminal: bool,

    // ---- The clause proper, on the operation. ----
    /// The held reply came back on the **same consumer session**, carrying the
    /// tag that was outstanding when the socket died.
    pub held_reply_tag_matched: bool,
    pub held_reply_was_rread: bool,
    pub held_reply_bytes: usize,
    /// The whole file, read on **one fid** across the failure.
    pub transfer_bytes: usize,
    pub transfer_expected_bytes: usize,
    pub transfer_messages: usize,
    pub transfer_checksum_matches: bool,
    /// The fid opened before the failure still answers afterwards, at the same
    /// size.
    pub fid_survived_getattr: bool,
    pub fid_survived_getattr_size: u64,
    /// The attach fid established before the failure still walks.
    pub attach_fid_survived_walk: bool,
    /// A tag and fid allocated **after** the recovery correlate correctly on
    /// the replacement carrier.
    pub post_recovery_tag_correlated: bool,
    /// `Tattach` count across the whole run.  Exactly one: the relay neither
    /// duplicates `Tattach` nor reconstructs fids.
    ///
    /// **Assigned by the code path rather than counted off the wire**, as it is
    /// in gates 7 to 10: this gate sends one `Tattach` and records one, so the
    /// rule asserts that the gate never *asks* for a second, not that the
    /// transport never carried one.  The claim it supports is still the
    /// contract's — a fid that answers after the failure was not re-established
    /// by a fresh attach, because no fresh attach was sent — but the wire-level
    /// version of it would need the client to count sends, which no fs gate
    /// does.
    pub attach_count: usize,
}

impl FsDataRecoveryEvidence {
    /// Whether both qualifiers the same-owner sentence names actually held for
    /// this run.  Fid retention is licensed **only while** they do, so this is
    /// the antecedent of the contract clause and not a summary of it.
    ///
    /// **Written as an array rather than as a `&&` chain, and that is
    /// load-bearing.**  As a chain, the *head* conjunct carries no `&&` and so
    /// does not match the one edit shape the guard-deletion suite keys on: it
    /// was the single conjunct the suite could not defeat, which is exactly the
    /// unfalsifiable-rule problem the thirteen removed rules were removed for,
    /// reappearing at the one line the edit shape could not reach.  Every
    /// element here has an identical shape, so all fourteen are deletable by
    /// the same case, and `every_same_owner_qualifier_defeats_the_antecedent_on_its_own`
    /// fails if any of them stops mattering.
    #[must_use]
    pub fn same_owner_contract_qualifiers_held(&self) -> bool {
        let qualifiers = [
            self.catalog_owner_session_stable,
            self.catalog_epoch_after == self.catalog_epoch_before,
            self.owner_session_id_stable,
            self.owner_epoch_after == self.owner_epoch_before,
            self.control_carrier_unchanged,
            self.recovery_attempted,
            self.owner_recovery_reason.as_deref() == Some(OLD_TRANSPORT_LOST),
            self.recovery_released_failed_carrier,
            self.recovery_successor_is_active_carrier,
            self.replayed_frames_after > self.replayed_frames_before,
            self.operation_id_stable,
            self.stream_remained_registered,
            self.sole_consumer_stream_at_owner,
            self.stream_not_terminal,
        ];
        qualifiers.into_iter().all(|held| held)
    }
}

/// Validate every rule; the first violated rule is named.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_fs_data_recovery_evidence(evidence: &FsDataRecoveryEvidence) -> Result<()> {
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
        // a socket died somewhere near a filesystem session.
        // This half is **documented green**, not load-bearing, and it is kept
        // rather than removed.  The composite rule immediately below subsumes
        // it: `request_outstanding_at_failure()` is false unless the emit
        // cursor advanced **and** the receive cursor did not, so the composite
        // already rejects every run this rule would have.  It is kept because
        // it names the violated condition precisely when a run fails, and the
        // predicate's own clause is held directly — in **both** directions — by
        // `the_in_flight_predicate_needs_both_halves` below.  Gates 8, 9 and 10
        // each carry the same case for the same reason.
        (
            "the relay had dispatched a 9P record toward the device when the data socket \
             failed"
                .into(),
            evidence.failure.emitted_at_failure > evidence.failure.emitted_before,
        ),
        (
            "the relay had received no answer to that record when the data socket failed: \
             the 9P exchange was outstanding across the failure"
                .into(),
            evidence.request_outstanding_at_failure
                && evidence.failure.request_outstanding_at_failure(),
        ),
        (
            "the held exchange ran on a registered consumer stream".into(),
            evidence.failure.stream_id > 0,
        ),
        // This was a failure, not a scheduled rotation.  The whole clause
        // turns on the difference, so it is asserted rather than described.
        (
            "the data carrier really was replaced: a different physical connection".into(),
            !evidence.connection_id_before.is_empty()
                && !evidence.connection_id_after.is_empty()
                && evidence.connection_id_after != evidence.connection_id_before,
        ),
        (
            "the replacement carrier took a strictly greater generation".into(),
            evidence.generation_after > evidence.generation_before,
        ),
        (
            "no scheduled rotation completed: the generation change was the failure's, \
             not the timer's"
                .into(),
            evidence.rotations_completed_before == 0 && evidence.rotations_completed_after == 0,
        ),
        (
            "the failed data socket was gone at the transport, not only in diagnostics".into(),
            evidence.failed_connection_closed_at_proxy,
        ),
        (
            "a replacement device data socket was dialled through the proxy".into(),
            evidence.replacement_connection_observed_at_proxy,
        ),
        // The two qualifiers, as **one** rule rather than as a rule each.
        //
        // The contract licenses retention "only while" both hold, so a run in
        // which a fid survived without them would be the violation rather than
        // the clause.  Stating each conjunct here *as well* was tried and
        // removed: the guard-deletion suite reported all thirteen **still
        // green** when defeated, because this conjunction already rejects every
        // run they would have rejected, so none of them could ever be the rule
        // that failed a run.  They are not exempted as documented-green — they
        // are gone, and the property is held where it can actually be defeated:
        // `same_owner_contract_qualifiers_held` is one conjunct per line, each
        // separately deletable by the guard suite, and
        // `every_same_owner_qualifier_defeats_the_antecedent_on_its_own` fails
        // if any conjunct stops mattering.
        (
            "the same control owner and all ordered stream state were retained, which is \
             the only condition under which the profile permits preserving this filesystem \
             session across a failed data socket"
                .into(),
            evidence.same_owner_contract_qualifiers_held(),
        ),
        // The clause proper, on the operation.
        (
            "the reply outstanding when the socket died came back on the same consumer \
             session"
                .into(),
            evidence.held_reply_was_rread,
        ),
        (
            "it carried the tag that was outstanding across the failure".into(),
            evidence.held_reply_tag_matched,
        ),
        (
            "that reply carried data rather than an empty read".into(),
            evidence.held_reply_bytes > 0,
        ),
        (
            "the whole file was read on one fid across the failure".into(),
            evidence.transfer_bytes == evidence.transfer_expected_bytes
                && evidence.transfer_expected_bytes == RECOVERY_FILE_BYTES,
        ),
        (
            "that transfer's checksum matched the synthetic content: no byte was lost, \
             duplicated or reordered across the failure"
                .into(),
            evidence.transfer_checksum_matches,
        ),
        (
            "that transfer spanned many Rread messages rather than one".into(),
            evidence.transfer_messages >= MIN_READ_MESSAGES,
        ),
        (
            "the fid opened before the failure still answered afterwards".into(),
            evidence.fid_survived_getattr,
        ),
        (
            "and still named the same file".into(),
            evidence.fid_survived_getattr_size == RECOVERY_FILE_BYTES as u64,
        ),
        (
            "the attach fid established before the failure still walked".into(),
            evidence.attach_fid_survived_walk,
        ),
        (
            "a tag allocated after the recovery correlated on the replacement carrier".into(),
            evidence.post_recovery_tag_correlated,
        ),
        (
            "exactly one Tattach across the run: no fid was reconstructed".into(),
            evidence.attach_count == 1,
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "fs data recovery gate failed: {rule}"
            )));
        }
    }
    Ok(())
}

/// Await one post-recovery 9P round trip under [`POST_RECOVERY_REPLY`],
/// naming the step rather than letting it expire against the scenario budget.
///
/// # Errors
/// A `HarnessError::Timeout` naming `step`, or the exchange's own error.
async fn bounded<F>(step: &str, exchange: F) -> Result<Message>
where
    F: std::future::Future<Output = Result<Message>>,
{
    timeout(POST_RECOVERY_REPLY, exchange)
        .await
        .map_err(|_| HarnessError::Timeout(format!("{step} was never answered (M4-29 mode B)")))?
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

/// Run the gate: start the cluster, fail a data socket mid-exchange, and
/// validate the evidence.
///
/// # Errors
/// Any harness, cluster or validation failure.
pub async fn verify() -> Result<FsDataRecoveryEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("fs data recovery harness startup timed out".into())
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
            if let Err(error) = validate_fs_data_recovery_evidence(&evidence) {
                // Payload-free: identifiers, labels and counters only.  A
                // violated rule is otherwise named without the evidence that
                // violated it, and the conjunctive same-owner rule cannot say
                // which of its qualifiers failed (M4-29).
                eprintln!("fs data recovery rejected evidence: {evidence:?}");
                return Err(error);
            }
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs data recovery scenario exceeded its bounded deadline".into(),
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
) -> Result<FsDataRecoveryEvidence> {
    let mut evidence = FsDataRecoveryEvidence {
        relay_count: cluster.relays.len(),
        transfer_expected_bytes: RECOVERY_FILE_BYTES,
        ..FsDataRecoveryEvidence::default()
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
        .fs_service("data-recovery")
        .ok_or_else(|| {
            HarnessError::InvalidInput("the data-recovery filesystem export was not seeded".into())
        })?
        .service_id;

    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    std::fs::write(
        directory.path().join("big.bin"),
        synthetic_bytes(RECOVERY_FILE_BYTES),
    )
    .map_err(HarnessError::Io)?;

    // The device attaches directly to relay-a, which becomes the owner, and
    // every device socket passes this proxy so the settled data socket can be
    // destroyed at the transport while the control socket keeps running.
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
        "m4-fs-data-recovery-canary",
        proxy.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    // The rotation policy is deliberately left at its default 300-second
    // interval: the scenario is bounded far below it, so no scheduled attempt
    // can fire and `rotations_completed` staying at zero is load-bearing.
    device_profile.config.exports.insert(
        service.to_string(),
        LocalExport {
            kind: LocalExportKind::Fs,
            device_canary: None,
            mcp: None,
            acp: None,
            cua: None,
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
    .map_err(|_| HarnessError::Timeout("fs data recovery device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("fs data recovery device: {error}")))?;

    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| {
                HarnessError::Timeout("fs data recovery device readiness timed out".into())
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
        // Payload-free: the connector's own bounded status record, which names
        // the recovery attempt, its carriers and its deadlines.
        eprintln!(
            "fs data recovery device status: {:?}",
            client.status_snapshot()
        );
        eprintln!("fs data recovery partial evidence: {evidence:?}");
        // Why the owner ended any device session, from its bounded terminal
        // latch: reason labels, identifiers and monotonic times only.
        if let Ok(snapshot) = owner_snapshot(cluster).await {
            for event in &snapshot.session_terminal_events {
                eprintln!(
                    "fs data recovery owner session terminal: session={} epoch={} reason={} \
                     active_generation={} candidate_generation={:?} closed_at_ms={}",
                    event.session_id,
                    event.epoch,
                    event.reason,
                    event.active_generation,
                    event.candidate_generation,
                    event.closed_at_ms
                );
            }
        }
    }
    let stop = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    if scenario.is_err() {
        // The connector's own terminal error, which a failed recovery (M4-29
        // mode A, M4-48) otherwise leaves unstated: `phase="failed"` names that
        // it ended, not why. `ClientError` renders bounded protocol text only.
        match &stop {
            Ok(Err(error)) => eprintln!("fs data recovery device terminal error: {error}"),
            Ok(Ok(())) => eprintln!("fs data recovery device terminal error: none"),
            Err(_) => eprintln!("fs data recovery device terminal error: stop timed out"),
        }
    }
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
    evidence: &mut FsDataRecoveryEvidence,
) -> Result<()> {
    // The owner claim, so the gate is speaking to the relay that owns the
    // device rather than to whichever relay answered first.  The token read
    // here is also the **before** half of the same-owner qualifier.
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
                evidence.catalog_epoch_before = owner.token.epoch;
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

    // Exactly one Tattach for the whole run.  The contract says the relay
    // neither duplicates Tattach nor reconstructs fids, so the gate must never
    // send a second one.
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

    // The whole transfer is accumulated here so its checksum covers bytes that
    // crossed on both carriers.
    let mut transferred: Vec<u8> = Vec::with_capacity(RECOVERY_FILE_BYTES);
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

    // The owner's carrier accounting before the failure.
    let operation_id_before = {
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
        evidence.owner_epoch_before = owner.epoch;
        evidence.generation_before = owner.active_generation;
        evidence.connection_id_before = owner.active_connection_id.clone();
        evidence.rotations_completed_before = owner.rotations_completed;
        evidence.replayed_frames_before = owner.total_replayed_frames;
        owner
            .streams
            .iter()
            .find(|stream| stream.stream_id == stream_id)
            .map(|stream| stream.operation_id.clone())
            .ok_or_else(|| {
                HarnessError::Process("the filesystem stream vanished before the held read".into())
            })?
    };

    // 2. Settle the carrier and pause the data socket's connector→relay bytes.
    //    The control socket is untouched, and its identity is recorded so the
    //    same-owner qualifier can be checked at the transport too.
    let control_addr_before = client.status_snapshot().control_local_addr;
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
    let mut observation = FailureObservation {
        stream_id,
        ..FailureObservation::default()
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
    let held_offset = transferred.len() as u64;
    let held_tag = session
        .send(Message::Tread {
            fid: FILE_FID,
            offset: held_offset,
            count: READ_COUNT,
        })
        .await?;
    evidence.held_tag = held_tag;

    // 5. Wait for the owner to show the request dispatched and unanswered, and
    //    destroy the data socket at that instant.
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
                let sample = FailureObservation {
                    emitted_at_failure: stream.last_emitted_relay_to_connector,
                    recv_contiguous_at_failure: stream.recv_contiguous_connector_to_relay,
                    ..observation.clone()
                };
                // Only a sample that actually shows the record dispatched and
                // unanswered ends the wait.
                if sample.request_outstanding_at_failure() {
                    evidence.failure_polls = polls;
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
    evidence.request_outstanding_at_failure = observation.request_outstanding_at_failure();
    evidence.failure = observation;

    // 6. The data socket dies.  No rotation handshake, no quiescing, no
    //    candidate prepared in advance — and the paused bytes are **never**
    //    released, so the `Rread` the device had already produced dies inside
    //    the failed carrier.  The control socket is untouched.
    proxy.close(connection).await?;

    // The connector's bounded retained recovery installs a replacement.
    //
    // The owner's `rotation_recovery_reason` is **live** state: the rotation
    // state machine clears it once the episode closes, so it is latched here
    // while the recovery is in progress rather than read after the fact.  That
    // is why this wait polls both endpoints rather than only the connector.
    {
        let deadline = Instant::now() + RECOVERY_WAIT;
        loop {
            if evidence.owner_recovery_reason.is_none()
                && let Ok(snapshot) = owner_snapshot(cluster).await
                && let Ok(owner) = session_of(&snapshot, session_id)
                && let Some(reason) = owner
                    .rotation_recovery_reason
                    .or(owner.last_activated_recovery_reason)
            {
                evidence.owner_recovery_reason = Some(reason.to_owned());
            }
            let device = client.status_snapshot();
            if device.phase == "active"
                && device.recovery_attempt.is_some()
                && let Some(active) = device.active_connection_id.as_deref()
                && active != evidence.connection_id_before
            {
                evidence.recovery_attempted = true;
                evidence.recovery_released_failed_carrier = device
                    .recovery_old_connection_id
                    .as_deref()
                    .is_some_and(|old| old == evidence.connection_id_before);
                evidence.recovery_successor_is_active_carrier = device
                    .recovery_successor_connection_id
                    .as_deref()
                    .is_some_and(|successor| successor == active);
                evidence.control_carrier_unchanged =
                    device.control_local_addr == control_addr_before;
                break;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Process(format!(
                    "the connector never completed a retained recovery after the data socket \
                     failed: phase={} recovery_attempt={:?}",
                    device.phase, device.recovery_attempt
                )));
            }
            sleep(POLL).await;
        }
    }

    // The failed connection is gone at the transport and a replacement device
    // connection was dialled through the proxy, so the carrier replacement is
    // visible there and not only in the connector's diagnostics.
    {
        let open = proxy.connections();
        evidence.failed_connection_closed_at_proxy =
            !open.iter().any(|entry| entry.id == connection);
        let control = client.status_snapshot().control_local_addr;
        // The replacement must be a **new** connection — an id the proxy
        // allocated after the one that died — and the device must again be
        // holding exactly two sockets, control plus one data.  Without both,
        // this would also be satisfied by the surviving control connection or
        // by a leftover carrier, and would stop saying "a replacement was
        // dialled" at all.
        evidence.replacement_connection_observed_at_proxy = open.len() == 2
            && open
                .iter()
                .any(|entry| entry.id > connection && Some(entry.source_addr) != control);
    }

    // The owner's view of the replacement, and both halves of the qualifier
    // the contract names.
    {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = owner_snapshot(cluster).await?;
            let owner = session_of(&snapshot, session_id)?;
            if owner.phase == "active"
                && owner.active_connection_id != evidence.connection_id_before
            {
                evidence.owner_session_id_stable = owner.session_id == session_id;
                evidence.owner_epoch_after = owner.epoch;
                evidence.generation_after = owner.active_generation;
                evidence.connection_id_after = owner.active_connection_id.clone();
                evidence.rotations_completed_after = owner.rotations_completed;
                evidence.replayed_frames_after = owner.total_replayed_frames;
                // Three **independent** facts about the owner's stream table,
                // deliberately not three readings of one lookup.
                let stream = owner
                    .streams
                    .iter()
                    .find(|stream| stream.stream_id == stream_id);
                // 1. A stream bearing this id is still there: never
                //    deregistered.
                evidence.stream_remained_registered = stream.is_some();
                // 2. It is the session's only consumer stream.  Counted from
                //    the table's length rather than from the lookup above, so a
                //    deregister followed by a re-register under a fresh id
                //    leaves this true while (1) goes false.
                evidence.sole_consumer_stream_at_owner = owner.streams.len() == 1;
                // 3. It carries the same stable logical operation identity.
                evidence.operation_id_stable =
                    stream.is_some_and(|stream| stream.operation_id == operation_id_before);
                // 4. And it is not finished.  A stream can be present and
                //    terminal, which satisfies (1) to (3); on a mode B run this
                //    reads true, which is what rules a dead stream out as that
                //    mode's explanation.
                evidence.stream_not_terminal = stream.is_some_and(|stream| !stream.terminal);
                break;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the owner never installed a replacement data carrier".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    // The authoritative catalog's owner token, the **after** half of the
    // same-owner qualifier.  A control-session reconnect or an owner handover
    // would move one of these; a failed data socket must not.
    {
        let owner = cluster
            .catalog
            .current_owner(tenant_id, device_id, chrono::Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?
            .ok_or_else(|| {
                HarnessError::Process("the device has no owner after the data socket failed".into())
            })?;
        evidence.catalog_owner_session_stable = owner.token.session_id == session_id;
        evidence.catalog_epoch_after = owner.token.epoch;
    }

    // The reply that was outstanding when the socket died, read on the **same
    // consumer session**.  This is the operation-level assertion the clause
    // turns on: the tag that crossed the failure must come back, carrying
    // data, on the fid that was open before it.
    //
    // **Bounded here rather than left to the scenario deadline.**  Everything
    // from this point on is a 9P round trip on the replacement carrier, and
    // M4-29 mode B is precisely a session that answers none of them.  The
    // scenario timeout in `verify` *drops* this future when it fires, so the
    // caller's status-and-evidence dump never runs and the whole failure
    // reports as "exceeded its bounded deadline" with nothing attached.  A
    // timeout per step keeps the failure attributable to a named step and lets
    // that dump execute.
    let held = timeout(POST_RECOVERY_REPLY, session.recv_frame())
        .await
        .map_err(|_| {
            HarnessError::Timeout(
                "the reply outstanding when the data socket failed never arrived on the \
                 replacement carrier (M4-29 mode B)"
                    .into(),
            )
        })??;
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

    // Finish the transfer on the **same fid**, across the carrier change.
    // Each read is bounded for the reason the held reply above is.
    loop {
        let reply = timeout(
            POST_RECOVERY_REPLY,
            session.read(FILE_FID, transferred.len() as u64, READ_COUNT),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "a post-recovery Tread on the retained fid was never answered after \
                 {} of {RECOVERY_FILE_BYTES} bytes (M4-29 mode B)",
                transferred.len()
            ))
        })??;
        match reply {
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
        fnv1a(&transferred) == fnv1a(&synthetic_bytes(RECOVERY_FILE_BYTES));

    // The fid opened before the failure still answers after it, and still
    // names the same file.
    match bounded(
        "a Tgetattr on the fid retained across the failure",
        session.getattr(FILE_FID, GETATTR_BASIC),
    )
    .await?
    {
        Message::Rgetattr(attributes) => {
            evidence.fid_survived_getattr = true;
            evidence.fid_survived_getattr_size = attributes.size;
        }
        other => return Err(unexpected("Rgetattr", &other)),
    }

    // The attach fid established before the failure still walks, with no
    // second Tattach anywhere in this run.
    match bounded(
        "a Twalk from the attach fid retained across the failure",
        session.walk(ATTACH_FID, POST_FID, &["big.bin"]),
    )
    .await?
    {
        Message::Rwalk { .. } => evidence.attach_fid_survived_walk = true,
        other => return Err(unexpected("Rwalk", &other)),
    }

    // A tag allocated after the recovery correlates correctly.  `call` refuses
    // a reply whose tag is not the one it sent, so a clean Rclunk here is the
    // correlation.
    match bounded(
        "a Tclunk on a fid allocated after the recovery",
        session.clunk(POST_FID),
    )
    .await?
    {
        Message::Rclunk => evidence.post_recovery_tag_correlated = true,
        other => return Err(unexpected("Rclunk", &other)),
    }

    session.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> FsDataRecoveryEvidence {
        FsDataRecoveryEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: 65_536,
            negotiated_dialect: DIALECT.into(),
            prefix_bytes: 196_575,
            failure: FailureObservation {
                stream_id: 1,
                emitted_before: 7,
                emitted_at_failure: 8,
                recv_contiguous_before: 10,
                recv_contiguous_at_failure: 10,
            },
            request_outstanding_at_failure: true,
            failure_polls: 3,
            held_tag: 7,
            connection_id_before: "carrier-1".into(),
            connection_id_after: "carrier-2".into(),
            generation_before: 1,
            generation_after: 2,
            rotations_completed_before: 0,
            rotations_completed_after: 0,
            failed_connection_closed_at_proxy: true,
            replacement_connection_observed_at_proxy: true,
            catalog_owner_session_stable: true,
            catalog_epoch_before: 1,
            catalog_epoch_after: 1,
            owner_session_id_stable: true,
            owner_epoch_before: 1,
            owner_epoch_after: 1,
            control_carrier_unchanged: true,
            recovery_attempted: true,
            owner_recovery_reason: Some(OLD_TRANSPORT_LOST.to_owned()),
            recovery_released_failed_carrier: true,
            recovery_successor_is_active_carrier: true,
            replayed_frames_before: 0,
            replayed_frames_after: 1,
            operation_id_stable: true,
            stream_remained_registered: true,
            sole_consumer_stream_at_owner: true,
            stream_not_terminal: true,
            held_reply_tag_matched: true,
            held_reply_was_rread: true,
            held_reply_bytes: 65_525,
            transfer_bytes: RECOVERY_FILE_BYTES,
            transfer_expected_bytes: RECOVERY_FILE_BYTES,
            transfer_messages: 25,
            transfer_checksum_matches: true,
            fid_survived_getattr: true,
            fid_survived_getattr_size: RECOVERY_FILE_BYTES as u64,
            attach_fid_survived_walk: true,
            post_recovery_tag_correlated: true,
            attach_count: 1,
        }
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_fs_data_recovery_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsDataRecoveryEvidence));
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
            ("the fid never served before the failure", |e| {
                e.prefix_bytes = 0;
            }),
            // The concurrency rules.
            ("the record was never dispatched", |e| {
                e.failure.emitted_at_failure = e.failure.emitted_before;
                e.request_outstanding_at_failure = false;
            }),
            ("an answer had already reached the owner", |e| {
                e.failure.recv_contiguous_at_failure = e.failure.recv_contiguous_before + 1;
                e.request_outstanding_at_failure = false;
            }),
            (
                "the summary bit claimed outstanding while the cursors did not",
                |e| {
                    e.failure.recv_contiguous_at_failure = e.failure.recv_contiguous_before + 1;
                },
            ),
            ("no registered stream", |e| e.failure.stream_id = 0),
            // Failure, not rotation.
            ("the carrier was never replaced", |e| {
                e.connection_id_after = e.connection_id_before.clone();
            }),
            ("no carrier identity before", |e| {
                e.connection_id_before.clear();
            }),
            ("no carrier identity after", |e| {
                e.connection_id_after.clear();
            }),
            ("the generation did not advance", |e| {
                e.generation_after = e.generation_before;
            }),
            ("a scheduled rotation had already completed", |e| {
                e.rotations_completed_before = 1;
            }),
            ("a scheduled rotation completed across the event", |e| {
                e.rotations_completed_after = 1;
            }),
            ("the failed socket was still open at the proxy", |e| {
                e.failed_connection_closed_at_proxy = false;
            }),
            ("no replacement socket was dialled", |e| {
                e.replacement_connection_observed_at_proxy = false;
            }),
            // Qualifier one.
            ("the catalog owner session changed", |e| {
                e.catalog_owner_session_stable = false;
            }),
            ("the catalog owner epoch advanced", |e| {
                e.catalog_epoch_after = e.catalog_epoch_before + 1;
            }),
            ("the owner relay's session identity changed", |e| {
                e.owner_session_id_stable = false;
            }),
            ("the owner relay's epoch advanced", |e| {
                e.owner_epoch_after = e.owner_epoch_before + 1;
            }),
            ("the control socket was replaced too", |e| {
                e.control_carrier_unchanged = false;
            }),
            // Qualifier two.
            ("no retained recovery was entered", |e| {
                e.recovery_attempted = false;
            }),
            // The control-loss label is the *live* label for gate 9's event,
            // so this mutation is the exact confusion the rule exists to
            // refuse rather than an arbitrary wrong string.
            ("the recovery was a lost control socket instead", |e| {
                e.owner_recovery_reason = Some(
                    tunnel_relay::recovery_reason_name(RecoveryReason::ControlLost).to_owned(),
                );
            }),
            ("the recovery reported no reason at all", |e| {
                e.owner_recovery_reason = None;
            }),
            ("the recovery released some other carrier", |e| {
                e.recovery_released_failed_carrier = false;
            }),
            ("the recovery's successor is not the active carrier", |e| {
                e.recovery_successor_is_active_carrier = false;
            }),
            ("no retained frames were replayed", |e| {
                e.replayed_frames_after = e.replayed_frames_before;
            }),
            ("the logical operation identity changed", |e| {
                e.operation_id_stable = false;
            }),
            ("the stream was deregistered", |e| {
                e.stream_remained_registered = false;
            }),
            ("the session gained a second consumer stream", |e| {
                e.sole_consumer_stream_at_owner = false;
            }),
            ("the retained stream was terminal", |e| {
                e.stream_not_terminal = false;
            }),
            // The clause proper.
            ("the held reply never came back", |e| {
                e.held_reply_was_rread = false;
            }),
            ("the held reply carried another tag", |e| {
                e.held_reply_tag_matched = false;
            }),
            ("the held reply was empty", |e| e.held_reply_bytes = 0),
            ("the transfer was short", |e| {
                e.transfer_bytes = RECOVERY_FILE_BYTES - 1;
            }),
            (
                "the expected length was moved to match a short transfer",
                |e| {
                    e.transfer_bytes = RECOVERY_FILE_BYTES - 1;
                    e.transfer_expected_bytes = RECOVERY_FILE_BYTES - 1;
                },
            ),
            ("the checksum did not match", |e| {
                e.transfer_checksum_matches = false;
            }),
            ("the transfer was one message", |e| e.transfer_messages = 1),
            ("the fid did not survive", |e| {
                e.fid_survived_getattr = false;
            }),
            ("the fid named a different file", |e| {
                e.fid_survived_getattr_size = 1;
            }),
            ("the attach fid did not survive", |e| {
                e.attach_fid_survived_walk = false;
            }),
            ("a post-recovery tag did not correlate", |e| {
                e.post_recovery_tag_correlated = false;
            }),
            ("a second Tattach was sent", |e| e.attach_count = 2),
        ];
        for (label, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_fs_data_recovery_evidence(&evidence).is_err(),
                "the validator accepted a defeated run: {label}"
            );
        }
    }

    /// The same-owner antecedent is a conjunction, and each conjunct must be
    /// able to defeat it on its own.  Without this, a qualifier could rot into
    /// a field nothing reads while the summary bit still said the contract
    /// licensed retention.
    #[test]
    fn every_same_owner_qualifier_defeats_the_antecedent_on_its_own() {
        assert!(passing().same_owner_contract_qualifiers_held());
        type Mutation = (&'static str, fn(&mut FsDataRecoveryEvidence));
        let conjuncts: Vec<Mutation> = vec![
            ("catalog session", |e| {
                e.catalog_owner_session_stable = false;
            }),
            ("catalog epoch", |e| {
                e.catalog_epoch_after = e.catalog_epoch_before + 1;
            }),
            ("owner session", |e| e.owner_session_id_stable = false),
            ("owner epoch", |e| {
                e.owner_epoch_after = e.owner_epoch_before + 1;
            }),
            ("control carrier", |e| e.control_carrier_unchanged = false),
            ("recovery attempted", |e| e.recovery_attempted = false),
            ("recovery reason", |e| {
                e.owner_recovery_reason = Some(
                    tunnel_relay::recovery_reason_name(RecoveryReason::ControlLost).to_owned(),
                );
            }),
            ("released carrier", |e| {
                e.recovery_released_failed_carrier = false;
            }),
            ("successor carrier", |e| {
                e.recovery_successor_is_active_carrier = false;
            }),
            ("replayed frames", |e| {
                e.replayed_frames_after = e.replayed_frames_before;
            }),
            ("operation id", |e| e.operation_id_stable = false),
            ("registration", |e| e.stream_remained_registered = false),
            ("sole stream", |e| e.sole_consumer_stream_at_owner = false),
            ("not terminal", |e| e.stream_not_terminal = false),
        ];
        for (label, mutate) in conjuncts {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                !evidence.same_owner_contract_qualifiers_held(),
                "a same-owner qualifier did not defeat the antecedent: {label}"
            );
        }
    }

    /// The in-flight predicate is a conjunction, and neither half may be
    /// dropped.  The validator's "the relay had dispatched a 9P record" rule is
    /// subsumed by this predicate, so this is where that clause is actually
    /// defeated — in both directions, rather than being taken on trust because
    /// a rule beside it happens to say the same words.
    #[test]
    fn the_in_flight_predicate_needs_both_halves() {
        let outstanding = FailureObservation {
            stream_id: 1,
            emitted_before: 7,
            emitted_at_failure: 8,
            recv_contiguous_before: 10,
            recv_contiguous_at_failure: 10,
        };
        assert!(outstanding.request_outstanding_at_failure());
        // Nothing was dispatched: the emit cursor never moved.
        assert!(
            !FailureObservation {
                emitted_at_failure: outstanding.emitted_before,
                ..outstanding.clone()
            }
            .request_outstanding_at_failure()
        );
        // It was dispatched and answered: the receive cursor moved too.
        assert!(
            !FailureObservation {
                recv_contiguous_at_failure: outstanding.recv_contiguous_before + 1,
                ..outstanding.clone()
            }
            .request_outstanding_at_failure()
        );
    }

    /// The recovery reason is derived from the library rather than pinned, and
    /// it must be the *data transport* one.  A gate that accepted any reason
    /// would pass on a control loss, which is gate 9's event and the one where
    /// a fid must **not** survive.
    #[test]
    fn the_recovery_reason_is_the_libraries_own_lost_data_transport_label() {
        assert_eq!(
            OLD_TRANSPORT_LOST,
            tunnel_relay::recovery_reason_name(RecoveryReason::OldTransportLost)
        );
        assert_ne!(
            OLD_TRANSPORT_LOST,
            tunnel_relay::recovery_reason_name(RecoveryReason::ControlLost)
        );
    }
}
