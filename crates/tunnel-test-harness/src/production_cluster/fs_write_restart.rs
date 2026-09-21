//! A live 9P2000.L filesystem session holding a **`Twrite`** outstanding while
//! the connector's **real operating-system process is killed and a replacement
//! process is started**, over the real cluster: a consumer WSS session through
//! the owning relay's public route, the owner actor, the device data WebSocket
//! and a `tunnel-client` **child process** serving a filesystem export from a
//! real host directory.
//!
//! # The clause, and why it needed a gate of its own
//!
//! `docs/protocol.md`'s flush paragraph names two operations and two events:
//!
//! > If a **write or rename** outcome becomes ambiguous after a transport or
//! > **process failure**, the just-bash adapter reports that ambiguity and
//! > does not blindly resubmit the operation in the new session.
//!
//! Gate 10 (`verify-m4-fs-process-restart`) drives the process failure, but
//! its held operation is a `Tlcreate`.  Gate 12
//! (`verify-m4-fs-rotation-write`) drives a `Twrite`, but its event is a
//! *scheduled rotation*, which is lossless by contract.  So the clause's own
//! pairing — **a write, across a process failure** — was named by the contract
//! and exercised by no gate.  This is that pairing.
//!
//! ## Why a `Twrite` and not a `Trename`
//!
//! The clause offers both, and one of them would have been a second copy of
//! gate 10.  `docs/filesystem-api.md` says so outright: "Native in-filesystem
//! rename is the only baseline single namespace operation with backend
//! atomicity."  A `Trename`'s effect is therefore a **namespace** effect that
//! either happened or did not — structurally the same evidence shape as gate
//! 10's directory entry, down to counting names in a host directory.  A
//! `Twrite`'s effect is **bytes at an offset**, and the same document puts it
//! on the other side of the line: operations that "may partially apply", with
//! "plain close/write acknowledgment does not mean fsync".  So the write is
//! the half of the clause that is not already covered by shape, and it is the
//! one this gate drives.
//!
//! # What is genuinely new here: the lossless assumption does not hold
//!
//! Gate 12 could assert `held_write_ambiguous == false`, because a scheduled
//! rotation is lossless and the held exchange must complete across it.  A
//! `SIGKILL` **destroys the answer**.  So the expected classification here is
//! the opposite one, and it is gate 10's: the journal showed the effect, the
//! exchange carried no answer, therefore [`tunnel_fs_core::Outcome::Unknown`] —
//! which `Outcome::is_settled` says is **not** settled, and is therefore not
//! retryable.
//!
//! Gate 10 derived exactly this for a directory entry.  Doing it for bytes at
//! an offset is strictly harder, because **a file region always contains some
//! bytes**: "these are not the payload" is only a usable answer if what was
//! there before could never be mistaken for the payload.  That discrimination
//! is gate 12's and is reused from it rather than reimplemented — the target
//! file is seeded entirely with [`FILLER_BYTE`], which is zero, every payload
//! byte comes from [`payload_bytes`] with its high bit set, and
//! [`classify_region`] answers [`RegionState::Untouched`],
//! [`RegionState::Written`], [`RegionState::Torn`] or
//! [`RegionState::Unreadable`].  Sharing them is deliberate: a second copy
//! could drift, and `payload_and_filler_can_never_be_confused` already holds
//! the disjointness both gates rest on.
//!
//! Both directions are established **in this run**, before anything is
//! perturbed, so the journal is never a rule that can only say one thing: the
//! held region reads `Untouched` before the `Twrite` is sent, and a prefix
//! `Twrite` performed and acknowledged normally reads back `Written`.
//!
//! # What the contract says about a **torn** write across a process failure
//!
//! It was worth reading before asserting anything, and the answer is mostly
//! that **it says nothing** — which is recorded here rather than papered over
//! with an invented rule.
//!
//! * `docs/filesystem-api.md` **permits** partial application for exactly this
//!   class of operation and withholds any durability promise from a plain
//!   acknowledged write.
//! * `docs/cluster.md` says the owner "records terminal state when known and
//!   preserves the ambiguity when it is not", and "do not retry a partially
//!   forwarded request body automatically".
//! * `docs/tcp-connect.md` says of the same situation on another transport: "a
//!   TCP write failure may follow a partial write; preserve certainty as
//!   unknown where appropriate.  Do not reopen the destination and replay
//!   bytes."
//!
//! Nowhere is a torn region required to be repaired, rolled back, or reported
//! as torn.  Every obligation is about **what the caller is told** and about
//! **not resubmitting**.  So this gate asserts exactly that and no more:
//!
//! 1. **`Torn` is an admissible outcome of this event, not a corner case.**
//!    [`FsWriteRestartEvidence::held_write_reached_the_device`] accepts
//!    `Written` **or** `Torn`, and rejects only `Untouched` and `Unreadable` —
//!    which mean the measurement was never set up, not that a defect was
//!    found.  Narrowing it to `Written` would have quietly excluded a state
//!    the contract explicitly permits, and it is the mistake gate 12 could
//!    afford to make and this gate cannot.
//!    `a_torn_held_region_is_accepted_by_every_rule_that_reads_it` is the
//!    guard against someone tightening it back, and it fails if they do.
//! 2. **A torn write is still `Unknown` to the caller, never `Partial`.**
//!    This is not a judgement call; it is read out of the library.
//!    `Outcome::Partial` is documented as "some **acknowledged** effect
//!    applied and the rest did not", and this caller's exchange carried no
//!    acknowledgement at all.  The harness can see the tear from outside
//!    because it reads the host file directly; the *caller* cannot, and the
//!    classification is what the caller is entitled to.  So
//!    [`classify_held_outcome`] returns `Unknown` for `Written` and `Torn`
//!    alike, and `a_torn_region_is_unknown_to_the_caller_and_never_partial`
//!    defeats that derivation directly.
//! 3. **Whatever state the region is in, the restart does not change it.**
//!    This is the "does not blindly resubmit" obligation, observed on the
//!    bytes themselves and the write analogue of gate 10's "the journal count
//!    did not move": `held_region_after_restart == held_region_before_kill`,
//!    and again after a caller retries.  A torn region silently completed by
//!    the replacement process would be a resubmission; a written region
//!    reverted would be a rollback the contract never promised.  Both are
//!    defeated by this rule.
//!
//! **Recorded boundary, because the alternative is evidence that proves less
//! than it claims.**  This gate *admits and classifies* a torn region; it does
//! not *manufacture* one.  A `SIGKILL` destroys the process, not the kernel's
//! page cache, so a single `Twrite` whose `write()` has already returned is
//! observed whole, and on every run measured here `held_region_before_kill`
//! was `Written`.  Producing a genuine tear would need a machine-level crash
//! or an injected filesystem fault, neither of which this harness has.  The
//! `Torn` branch is therefore proven by its unit tests and admitted by the
//! validator, and this file says so rather than implying the gate tore a
//! write.  `torn_observed_before_kill` is recorded as a diagnostic — it is
//! never asserted on, precisely because nothing here can make it true on
//! demand.
//!
//! # What may be claimed about "once", and what may not
//!
//! Gate 12's limit applies here unchanged and is repeated rather than quietly
//! dropped: a 9P `Twrite` carries an **explicit offset**, so applying the
//! identical frame twice is byte-for-byte idempotent and **no amount of
//! reading the host file can distinguish one application from two**.  The
//! region-stability rules above cannot see an idempotent same-offset replay.
//!
//! What *is* proven about the retry is stronger than a byte comparison anyway:
//! the resubmitted `Twrite` is refused **above the dispatch boundary**, with
//! the errno for a fid this session never allocated rather than anything the
//! host could have produced, so it never reached the provider at all.  And a
//! frame replayed at any *other* offset — the realistic way a restart could
//! duplicate an effect — is caught by `image_outside_held_region_matches`,
//! which compares every byte outside the held region against the exact
//! expected image.
//!
//! # The event, and what makes it concurrent with the exchange
//!
//! Both are gate 10's, unchanged, because they are already the right
//! construction: the connector is the workspace's own `tunnel-client` binary
//! spawned as a child process, the event is a **`SIGKILL`** so there is no
//! unwind and no graceful close, and the evidence records the first pid, that
//! it exited **on a signal**, and that the replacement runs under a different
//! pid.
//!
//! Concurrency is proven from the owner's own per-stream cursors and never
//! from timing.  The device data socket's **connector→relay** bytes are paused
//! at the harness TCP proxy once the carrier has settled; the owner is sampled
//! **while paused**, fixing this stream's baseline; one `Twrite` is sent and
//! its reply never read, so `last_emitted_relay_to_connector` advances while
//! `recv_contiguous_connector_to_relay` cannot; and the kill lands only once
//! that pair holds **and** the host file shows the write performed.  The
//! paused direction is never released, so the `Rwrite` the device produced is
//! discarded with the proxy — an answer that was produced and **lost**, which
//! is the event in its exact form.
//!
//! All fixture content is synthetic and generated here; no evidence field
//! carries a path, a name or file content.

use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use tokio::time::{sleep, timeout};
use tunnel_fs_core::Outcome;
use tunnel_fs_ninep::{GETATTR_BASIC, Message, flags::O_RDONLY, flags::O_RDWR};
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot};
use uuid::Uuid;

use super::fs_rotation_write::{FILLER_BYTE, RegionState, classify_region, payload_bytes};
use super::fs_wire as wire;
use wire::{NinepClient, Target, UpgradeFailure, errno_of, unexpected};

use super::{
    ProductionCluster, RunningHarness, STARTUP_TIMEOUT, client_binary_path,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::process::{ManagedProcess, ProcessSpec};
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

/// The close code the held exchange's session is ended with when the process
/// that was serving it is killed.
///
/// Derived, not pinned, exactly as [`UNKNOWN_FID_ERRNO`] is: from the consumer
/// side a dead connector process is the profile's "the export's backend is the
/// thing that went away", and the gate asserts the expression rather than the
/// number `close_code()` maps it to at this revision.
const DEVICE_GONE_CLOSE: u16 = match tunnel_fs_core::SessionErrorCode::DeviceOffline.close_code() {
    Some(code) => code,
    // Unreachable: `close_code()` returns `Some` for this variant.
    None => panic!("DeviceOffline must carry a close code"),
};

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
/// Where the write held across the process restart lands.
///
/// Well past the prefix region and well short of the end, so neither the
/// prefix write nor a short file could account for it.
const HELD_OFFSET: u64 = 131_072;
/// How many bytes the held write carries.
///
/// One `Twrite` under the negotiated `msize`, so the whole mutation is a
/// single frame: "the bytes landed" is then a fact about one operation rather
/// than about a multi-frame transfer that could legitimately be half applied
/// for reasons that have nothing to do with the kill.
const HELD_PAYLOAD_BYTES: usize = 32_768;

/// How many reads the session performs before anything is perturbed,
/// establishing that it serves normally first.
const PREFIX_READS: usize = 2;
/// The replacement session's whole-file transfer must need more than this many
/// `Rread` messages, so it is not a single-frame special case.
const MIN_READ_MESSAGES: usize = 3;

/// The fid numbers the first session binds, and which the replacement session
/// then probes.
///
/// The replacement session deliberately reuses these exact numbers: the
/// contract clause is that no fid is restored across a process restart, and
/// reusing the numbers is what makes a leak observable instead of merely
/// unlikely.
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
/// A bounded wait for the killed pid to be reaped.
const EXIT_WAIT: Duration = Duration::from_secs(30);
/// How long the host file is given to show the held write performed.
///
/// Bounded: a run that reaches this deadline has **not** found a defect, it has
/// failed to set up the measurement — the write never reached the device — and
/// the gate says so rather than killing the process anyway and reporting a
/// `NotStarted` as though it were an `Unknown`.
const JOURNAL_WAIT: Duration = Duration::from_secs(30);
/// How long the held consumer socket is given to be failed explicitly.
///
/// Bounded, and **this bound is evidence**: the derivation below reads the
/// *absence* of a reply, so every way the answer can be lost has to reach it
/// rather than hang to the scenario deadline.  That is gate 12's rule for when
/// a read must be bounded, and it applies here for the same reason.
const PENDING_CALL_WAIT: Duration = Duration::from_secs(30);
/// The status the public consumer route answers while the cluster has not
/// finished admitting a device session.
///
/// Derived, not pinned: it is the status the relay's own not-ready outcome
/// carries, read out of the crate rather than written here as a literal.
const CLUSTER_NOT_READY_STATUS: u16 = http::StatusCode::SERVICE_UNAVAILABLE.as_u16();
/// How long the replacement session waits out that not-ready window.
///
/// A **setup** bound, not an evidence bound: see [`open_session_when_ready`].
const READY_WAIT: Duration = Duration::from_secs(30);
/// The poll interval for every bounded wait here.
const POLL: Duration = Duration::from_millis(20);
/// The whole scenario's bound.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(300);
/// How long a connector process is given to exit on its own before cleanup
/// kills it.  A connector never exits on its own, so this is a floor on the
/// cleanup cost rather than a real grace, and it is short for that reason.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// What the owner recorded about the stream the session was held on.
///
/// Payload-free: sequences, identifiers and lifecycle bits only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WriteRestartObservation {
    /// The consumer stream the filesystem session ran on.
    pub stream_id: u64,
    /// The owner's relay→connector emit cursor for this stream, sampled while
    /// the reverse direction was already paused and before the held `Twrite`.
    pub emitted_before: u64,
    /// The same cursor at the instant the process was killed.  It must have
    /// advanced: the relay dispatched the write toward the device.
    pub emitted_at_kill: u64,
    /// The owner's contiguous connector→relay receive cursor for this stream,
    /// sampled at the same instant as [`Self::emitted_before`].
    pub recv_contiguous_before: u64,
    /// The same cursor at the instant of the kill.  It must **not** have
    /// advanced: no answer to that write had reached the owner.
    pub recv_contiguous_at_kill: u64,
}

impl WriteRestartObservation {
    /// Whether this sample shows a 9P write the relay had dispatched and had
    /// received no answer to, at the instant the process was killed.  This is
    /// the gate's concurrency proof, and it is the owner's own record rather
    /// than a timestamp comparison.
    #[must_use]
    pub fn request_outstanding_at_kill(&self) -> bool {
        self.emitted_at_kill > self.emitted_before
            && self.recv_contiguous_at_kill == self.recv_contiguous_before
    }
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsWriteRestartEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    /// The negotiated session parameters, so a run cannot pass on a session
    /// that never reached 9P.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub negotiated_dialect: String,

    /// Bytes read on the file fid **before** anything was perturbed.
    pub prefix_bytes: usize,

    // ---- The journal's two directions, established before the event. ----
    /// The held region as the host file saw it **before** the held `Twrite`
    /// was sent.  Must be [`RegionState::Untouched`]: the negative direction.
    pub held_region_before_send: RegionState,
    /// The prefix region after a normal acknowledged `Twrite`.  Must be
    /// [`RegionState::Written`]: the positive direction.
    pub prefix_region_after_write: RegionState,
    /// Bytes the prefix `Twrite` acknowledged on the wire.
    pub prefix_acknowledged_bytes: usize,

    // ---- The write held across the kill. ----
    /// The owner's sample either side of the kill.
    pub restart: WriteRestartObservation,
    /// Whether that sample proves the write was outstanding at the kill.
    pub request_outstanding_at_kill: bool,
    /// How many polls the outstanding state took to observe, for diagnosis.
    pub restart_polls: usize,
    /// The tag that was outstanding when the process was killed.
    pub held_tag: u16,
    /// The held region as the host file saw it at the instant before the kill.
    ///
    /// [`RegionState::Written`] **or** [`RegionState::Torn`]: the contract
    /// permits this class of operation to apply partially, so both mean the
    /// write reached the device and both are admitted.
    pub held_region_before_kill: RegionState,
    /// Diagnostic only, and deliberately never asserted on: whether any poll
    /// before the kill caught the region mid-application.  Nothing in this
    /// harness can make it true on demand, so a rule reading it would be a
    /// rule that cannot fail for a reason anybody controls.
    pub torn_observed_before_kill: bool,
    /// How many polls the effect took to appear, for diagnosis.
    pub journal_polls: usize,

    // ---- The event itself: a real operating-system process, really killed.
    /// The first connector process's pid.
    pub first_pid: u32,
    /// Whether that pid actually exited.
    pub first_process_exited: bool,
    /// Whether it exited on a signal rather than under its own control.  A
    /// graceful stop would let the connector close its sockets in order and
    /// would not be this event.
    pub first_process_killed_by_signal: bool,
    /// The replacement connector process's pid.  It must differ: a "restart"
    /// that reused the process would not be one.
    pub second_pid: u32,
    /// The replacement process reached an active device session at the owner.
    pub second_process_active: bool,

    // ---- The cluster's corroboration that this was a real admission cycle.
    pub epoch_before: u64,
    pub epoch_after: u64,
    pub session_id_before: String,
    pub session_id_after: String,
    /// Whether the catalog reported the owner genuinely released between the
    /// two processes, so the second claim is a fresh admission.
    pub owner_released_between: bool,

    // ---- The clause's obligations. ----
    /// Whether the held exchange's session was **closed** rather than left
    /// hanging: "fail pending calls explicitly".
    pub pending_call_closed: bool,
    /// The close code that failure carried.
    pub pending_call_close_code: Option<u16>,
    /// Whether the held `Twrite` was instead **answered** across the restart.
    pub pending_call_answered: bool,
    /// Whether the held tag came back as an `Rlerror`.  The trap in its exact
    /// form: an `Rlerror` on a write the host file proves landed would tell a
    /// caller the write failed — `Outcome::Failed`, which **is** settled — and
    /// a caller acting on that may assume no side effect occurred.
    pub pending_call_errored: bool,
    /// How the held write classifies, derived from the host file and the
    /// exchange rather than asserted.
    ///
    /// `None` means the run never reached the classification, which is not the
    /// same as classifying it weakly and is rejected by its own rule.
    pub held_call_outcome: Option<Outcome>,
    /// The first session's stream is deregistered at the owner.
    pub held_stream_deregistered: bool,

    // ---- "does not blindly resubmit", observed on the bytes. ----
    /// The held region after the replacement process has claimed the device
    /// and before any 9P traffic reaches it.  Must equal
    /// [`Self::held_region_before_kill`]: the restart neither completed a torn
    /// write nor rolled a whole one back.
    pub held_region_after_restart: RegionState,
    /// Whether probing the earlier session's file fid, on an **attached**
    /// replacement session, was refused rather than answered.
    pub stale_file_fid_refused: bool,
    pub stale_file_fid_errno: Option<u32>,
    /// Whether re-issuing the held `Twrite` on the fid it was originally
    /// issued on is refused *above* the dispatch boundary.
    pub retry_refused_above_dispatch: bool,
    /// The errno that refusal carried.
    ///
    /// This is the errno a session-level unknown-fid refusal carries, and it
    /// is **corroboration, not proof of origin**: `policy::code_for` maps any
    /// errno it does not recognise to `Einval` as well, and the host write
    /// path returns `Einval` directly, so this value alone does not establish
    /// that the retry stopped above the provider.  What establishes that is
    /// [`Self::host_mtime_unchanged_across_retry`].
    pub retry_refusal_errno: Option<u32>,
    /// The held region after that retry.  Must still equal
    /// [`Self::held_region_before_kill`].
    pub held_region_after_retry: RegionState,
    /// Whether the target file's modification time is the **same instant**
    /// before and after the retry.
    ///
    /// This is the rule that actually carries "the retry never reached the
    /// provider", and it is the one measurement that can: the bytes cannot,
    /// because a `Twrite` names an explicit offset and a resubmission of the
    /// identical frame is byte-for-byte idempotent, and the errno cannot,
    /// because the host can produce `Einval` too.  An `mtime` is neither.  A
    /// write that reached `tunnel-fs-host` calls `pwrite`, and `pwrite`
    /// advances `mtime` whether or not it changed a single byte -- so a
    /// resubmission that got through is visible here precisely in the case
    /// the byte comparison is blind to.
    ///
    /// Sampled around the retry alone, not across the restart: the reads the
    /// replacement session performs do not touch `mtime`, but a `Twrite` that
    /// landed would.
    pub host_mtime_unchanged_across_retry: bool,
    /// The two samples behind [`Self::host_mtime_unchanged_across_retry`],
    /// carried so a failure names the instants rather than only the verdict.
    pub host_mtime_before_retry: Option<SystemTime>,
    pub host_mtime_after_retry: Option<SystemTime>,

    // ---- The whole-file image. ----
    pub image_bytes: usize,
    pub image_expected_bytes: usize,
    /// Whether every byte **outside** the held region matches the exact
    /// expected image: filler everywhere except the prefix region.  The held
    /// region is excluded because when it is torn its content is not known in
    /// advance, and asserting a content this gate cannot predict would be the
    /// invented rule the contract does not supply.
    pub image_outside_held_region_matches: bool,

    // ---- The replacement session serves the same export. ----
    pub second_session_msize: u32,
    pub second_session_attached: bool,
    /// The held region as the **replacement session** classifies it over 9P,
    /// so the host's view and the export's view must agree — including when
    /// both say `Torn`.
    pub held_region_over_ninep: RegionState,
    /// Whether the whole file read back over 9P is byte-for-byte the host's.
    pub ninep_image_matches_host: bool,
    pub second_session_bytes: usize,
    pub second_session_expected_bytes: usize,
    pub second_session_messages: usize,
    /// The file the replacement session sees is the size it always was.
    pub second_session_getattr_size: u64,
    /// `Tattach` count across the whole run: one per attached session, two in
    /// total, and never a third that would mean a session was reconstructed.
    pub attach_count: usize,
}

impl FsWriteRestartEvidence {
    /// Whether the host file discriminated a written region from an untouched
    /// one **in this run**, in both directions.
    ///
    /// Without both, the journal is a rule that can only ever say one thing and
    /// the classification of the held write rests on nothing.
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

    /// Whether the held write **reached the device**, as seen from outside the
    /// connector.
    ///
    /// `Written` **or** `Torn`.  Both mean the mutation was dispatched and at
    /// least partly performed, which is what makes its lost answer an
    /// ambiguity rather than a refusal a caller may retry.  `Untouched` and
    /// `Unreadable` mean the measurement was never set up.
    ///
    /// Admitting `Torn` is the whole difference between this gate and a second
    /// copy of gate 10, and it is not a convenience: `docs/filesystem-api.md`
    /// permits this class of operation to apply partially, so a rule that
    /// demanded `Written` would be asserting a promise the contract withholds.
    #[must_use]
    pub fn held_write_reached_the_device(&self) -> bool {
        matches!(
            self.held_region_before_kill,
            RegionState::Written | RegionState::Torn
        )
    }

    /// Whether the bytes are exactly as the kill left them, through the
    /// replacement process's admission and through a caller's retry.
    ///
    /// This is "does not blindly resubmit the operation in the new session",
    /// observed on the effect surface.  Both conjuncts compare against the
    /// **same** pre-kill state, so a torn region completed later and a written
    /// region reverted later are each caught, and the array shape is gate 11's
    /// for gate 11's reason.
    #[must_use]
    pub fn region_unchanged_since_the_kill(&self) -> bool {
        let stages = [
            self.held_region_after_restart == self.held_region_before_kill,
            self.held_region_after_retry == self.held_region_before_kill,
        ];
        stages.into_iter().all(|held| held)
    }
}

/// The classification the caller is entitled to, in one place.
///
/// Derived from two facts and nothing else: whether the host file showed the
/// write reach the device, and what the exchange carried.  It is a function
/// rather than an expression at the call site so that
/// `a_torn_region_is_unknown_to_the_caller_and_never_partial` defeats the
/// derivation the run actually uses.
///
/// **`Outcome::Partial` is never returned, and that is read out of the library
/// rather than decided here.**  `Partial` is documented as "some
/// *acknowledged* effect applied and the rest did not"; this exchange carried
/// no acknowledgement at all, so a torn region is `Unknown` exactly as a whole
/// one is.  The harness can see the tear because it reads the host file
/// directly.  The caller cannot, and the caller is who the outcome describes.
#[must_use]
pub fn classify_held_outcome(evidence: &FsWriteRestartEvidence) -> Outcome {
    if !evidence.held_write_reached_the_device() {
        // Nothing observable ever landed, so the caller may treat it as never
        // dispatched — settled, and retryable.
        Outcome::NotStarted
    } else if evidence.pending_call_errored {
        // "Dispatched, and the provider reported it made no change."  A
        // settled outcome, and a false one: the host file says otherwise.
        Outcome::Failed
    } else {
        Outcome::Unknown
    }
}

/// Validate every rule; the first violated rule is named.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_fs_write_restart_evidence(evidence: &FsWriteRestartEvidence) -> Result<()> {
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
            "the session served a real read before anything was perturbed".into(),
            evidence.prefix_bytes > 0,
        ),
        // The journal has to be able to say both things before anything it
        // says about the held write means anything.
        (
            "the host file discriminated a written region from an untouched one, in both \
             directions, before the event"
                .into(),
            evidence.journal_discriminated_both_directions(),
        ),
        // The concurrency rules.  Without these the gate would prove only that
        // a process restarted somewhere near a filesystem session.
        (
            "the relay had dispatched a 9P record toward the device when the process was killed"
                .into(),
            evidence.restart.emitted_at_kill > evidence.restart.emitted_before,
        ),
        (
            "the relay had received no answer to that record when the process was killed: the \
             Twrite was outstanding across the restart"
                .into(),
            evidence.request_outstanding_at_kill && evidence.restart.request_outstanding_at_kill(),
        ),
        (
            "a stream was identified for the held exchange".into(),
            evidence.restart.stream_id > 0,
        ),
        // The effect, seen from outside the connector.  `Torn` is admitted
        // here on purpose; see `held_write_reached_the_device`.
        (
            "the held write had reached the device before the process was killed, so the lost \
             answer is an unknown and not a refusal that never dispatched"
                .into(),
            evidence.held_write_reached_the_device(),
        ),
        // The event itself: a real process, really killed, really replaced.
        (
            "a first connector process was identified".into(),
            evidence.first_pid > 0,
        ),
        (
            "the first connector process exited".into(),
            evidence.first_process_exited,
        ),
        (
            "the first connector process was killed rather than stopped gracefully".into(),
            evidence.first_process_killed_by_signal,
        ),
        (
            "the replacement is a different process".into(),
            evidence.second_pid > 0 && evidence.second_pid != evidence.first_pid,
        ),
        (
            "the replacement process served the device".into(),
            evidence.second_process_active,
        ),
        // The cluster's corroboration.
        (
            "the owner was released between the two processes".into(),
            evidence.owner_released_between,
        ),
        (
            "the replacement claim took a strictly greater epoch".into(),
            evidence.epoch_after > evidence.epoch_before,
        ),
        (
            "an epoch was actually observed before the restart".into(),
            evidence.epoch_before > 0,
        ),
        (
            "the device session identity changed across the restart".into(),
            !evidence.session_id_before.is_empty()
                && !evidence.session_id_after.is_empty()
                && evidence.session_id_before != evidence.session_id_after,
        ),
        // "fail pending calls explicitly".
        (
            "the pending call was failed rather than left hanging".into(),
            evidence.pending_call_closed,
        ),
        (
            "the pending call was failed explicitly, with a close code".into(),
            evidence.pending_call_close_code == Some(DEVICE_GONE_CLOSE),
        ),
        (
            "the pending call was not served a normal reply from a session the contract \
             invalidates"
                .into(),
            !evidence.pending_call_answered,
        ),
        (
            // Load-bearing against a **derivation** regression, which is the
            // only way this state can arise: an `Rlerror` on the held tag is
            // classified as `Outcome::Failed` by `classify_held_outcome`, so
            // evidence recording the error and an `Unknown` alongside it is
            // evidence whose classifier has stopped agreeing with what it saw.
            // The classification rule below cannot catch that, because it only
            // sees the classification.
            "a write the host file proves reached the device was not reported to the caller as an \
             error, which is a settled outcome a caller may resubmit after"
                .into(),
            !evidence.pending_call_errored,
        ),
        (
            // **The whole clause, in one rule.**  A companion rule asserting
            // `!is_settled()` on this field is deliberately *not* written: it
            // is the rule gate 10 removed as not load-bearing, because
            // `Outcome::Unknown` is the only value admitted here and the
            // library already says that value is unsettled, so it could never
            // be the rule that rejected anything.  The library property is
            // held directly instead, by
            // `an_unknown_outcome_is_not_settled_and_a_failed_one_is`.
            "the held write classifies as an unknown outcome".into(),
            evidence.held_call_outcome == Some(Outcome::Unknown),
        ),
        (
            "the held exchange's stream was deregistered at the owner".into(),
            evidence.held_stream_deregistered,
        ),
        // "does not blindly resubmit", observed on the bytes.
        (
            "the bytes the kill left behind were neither completed nor rolled back by the \
             restart or by a caller's retry"
                .into(),
            evidence.region_unchanged_since_the_kill(),
        ),
        (
            "the earlier session's file fid is unbound after the restart".into(),
            evidence.stale_file_fid_refused,
        ),
        (
            "the stale file fid refusal carried the errno for a fid this session never allocated"
                .into(),
            evidence.stale_file_fid_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "a caller that retries the write anyway is refused above the dispatch boundary".into(),
            evidence.retry_refused_above_dispatch,
        ),
        (
            "that retry carried the errno a session-level unknown-fid refusal carries".into(),
            evidence.retry_refusal_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "the retry left the target file's modification time untouched, so it never reached \
             the host at all"
                .into(),
            evidence.host_mtime_unchanged_across_retry,
        ),
        // The whole-file image: nothing landed anywhere it should not have.
        (
            "the host file was exactly its seeded length".into(),
            evidence.image_bytes == evidence.image_expected_bytes
                && evidence.image_expected_bytes == TARGET_FILE_BYTES,
        ),
        (
            "no byte outside the held region changed".into(),
            evidence.image_outside_held_region_matches,
        ),
        // The refusals were fid scoping and not a broken export.
        (
            "the replacement session negotiated a bounded msize".into(),
            evidence.second_session_msize > 0 && evidence.second_session_msize <= OFFERED_MSIZE,
        ),
        (
            "the replacement session established its own root".into(),
            evidence.second_session_attached,
        ),
        (
            "the replacement session read the whole file back".into(),
            evidence.second_session_bytes == evidence.second_session_expected_bytes
                && evidence.second_session_expected_bytes == TARGET_FILE_BYTES,
        ),
        (
            "that transfer needed many messages rather than one".into(),
            evidence.second_session_messages > MIN_READ_MESSAGES,
        ),
        (
            "the export's own view of the file is byte for byte the host's".into(),
            evidence.ninep_image_matches_host,
        ),
        (
            "the export classifies the held region exactly as the host does".into(),
            evidence.held_region_over_ninep == evidence.held_region_before_kill,
        ),
        (
            "the file is the size it always was".into(),
            evidence.second_session_getattr_size == TARGET_FILE_BYTES as u64,
        ),
        (
            "exactly one Tattach per attached session, and never a reconstructed one".into(),
            evidence.attach_count == 2,
        ),
    ];
    for (rule, held) in checks {
        if !held {
            return Err(HarnessError::Process(format!(
                "M4 filesystem write restart evidence failed: {rule}"
            )));
        }
    }
    Ok(())
}

/// Read the export's own host file directly, from the harness.
///
/// This is the journal: it is the connector's only durable effect surface, it
/// is read without going through the connector, the relay or the 9P session,
/// and it therefore outlives the process under test and spans both its
/// generations.
fn read_host_image(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

/// The target file's modification time, or `None` if it cannot be read.
///
/// `None` is deliberately *not* treated as "unchanged" by the caller: two
/// unreadable samples compare equal, and a rule that passes because the
/// measurement failed twice is exactly the shape this gate refuses elsewhere.
fn read_host_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// The expected whole-file image **outside** the held region: filler
/// everywhere except the prefix write.
///
/// The held region is deliberately absent from this: when it is torn its
/// content is not predictable, and the gate has no contract licence to predict
/// it.
fn expected_image_outside_held_region() -> Vec<u8> {
    let mut image = vec![FILLER_BYTE; TARGET_FILE_BYTES];
    let prefix = payload_bytes(PREFIX_PAYLOAD_BYTES);
    let start = PREFIX_OFFSET as usize;
    image[start..start + prefix.len()].copy_from_slice(&prefix);
    image
}

/// Whether every byte outside the held region matches the expected image.
///
/// A shared helper so the run and
/// `a_byte_moved_outside_the_held_region_is_caught` test the same comparison.
fn image_outside_held_region_matches(image: &[u8]) -> bool {
    if image.len() != TARGET_FILE_BYTES {
        return false;
    }
    let expected = expected_image_outside_held_region();
    let held_start = HELD_OFFSET as usize;
    let held_end = held_start + HELD_PAYLOAD_BYTES;
    image[..held_start] == expected[..held_start] && image[held_end..] == expected[held_end..]
}

/// A TOML `"..."` literal with the escapes this profile can produce.
fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Run the gate: start the cluster, kill the connector's real process under a
/// live 9P write, restart it, and validate the evidence.
///
/// # Errors
/// Any harness, cluster or validation failure.
pub async fn verify() -> Result<FsWriteRestartEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("fs write restart harness startup timed out".into())
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
            validate_fs_write_restart_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs write restart scenario exceeded its bounded deadline".into(),
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

/// Open one consumer 9P session, waiting out the cluster's own not-ready
/// window.
///
/// **This is setup, not evidence, and it is deliberately narrow.**  The owner
/// claim landing in the catalog and the replacement device session reaching
/// `active` at the owner are not the same instant as the public consumer route
/// being willing to upgrade onto it, and a second run of this gate caught the
/// gap: the replacement session's upgrade was refused
/// [`CLUSTER_NOT_READY_STATUS`] while every cluster fact the gate had already
/// recorded said the restart had completed.  That is a race in the *gate's*
/// sequencing, not a finding about the product, and reporting it as a finding
/// would be evidence that proves something other than what it claims.
///
/// Only [`CLUSTER_NOT_READY_STATUS`] is retried, and only until
/// [`READY_WAIT`] expires — every other status fails immediately and the
/// expiry fails naming the status, so a route that is genuinely refusing this
/// consumer can never be waited into silence.
async fn open_session_when_ready(
    target: &Target,
    ca: &[u8],
    token: &str,
) -> Result<(NinepClient, u32, String)> {
    let deadline = Instant::now() + READY_WAIT;
    loop {
        match NinepClient::connect(target, ca, token, Some(SUBPROTOCOL)).await {
            Ok(mut session) => {
                let selected = session.selected_subprotocol().to_owned();
                let (msize, dialect) = session.version(OFFERED_MSIZE).await?;
                let _ = dialect;
                return Ok((session, msize, selected));
            }
            Err(UpgradeFailure::Status { status, .. })
                if status == CLUSTER_NOT_READY_STATUS && Instant::now() < deadline => {}
            Err(UpgradeFailure::Status { status, .. }) => {
                return Err(HarnessError::Http(format!(
                    "the filesystem upgrade was refused with HTTP status {status}"
                )));
            }
            Err(UpgradeFailure::Harness(error)) => return Err(error),
        }
        sleep(POLL).await;
    }
}

/// Wait for the catalog to report an owner claim for this device whose epoch is
/// strictly greater than `floor`, and return its epoch and session id.
async fn wait_owner_epoch_above(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    floor: u64,
) -> Result<(u64, String)> {
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
            return Ok((owner.token.epoch, owner.token.session_id.clone()));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "no owner claim took an epoch above the one held before the restart".into(),
            ));
        }
        sleep(POLL).await;
    }
}

/// Wait for the catalog to report an owner claim and return its epoch, session
/// id and node.
async fn wait_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<(u64, String, String)> {
    let deadline = Instant::now() + OWNER_WAIT;
    loop {
        let owner = cluster
            .catalog
            .current_owner(tenant_id, device_id, chrono::Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?;
        if let Some(owner) = owner {
            return Ok((
                owner.token.epoch,
                owner.token.session_id.clone(),
                owner.token.node_id.clone(),
            ));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "the device owner claim was not observed".into(),
            ));
        }
        sleep(POLL).await;
    }
}

/// Start one `tunnel-client` **child process** on this config and wait until
/// the owner reports an active device session for it.
async fn start_connector_process(
    cluster: &ProductionCluster,
    name: &str,
    config_path: &Path,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<(ManagedProcess, String)> {
    let binary = client_binary_path()?;
    let mut process = ManagedProcess::spawn(
        name,
        ProcessSpec::new(binary)
            .arg("connect")
            .arg("--config")
            .arg(config_path.to_string_lossy().to_string())
            .arg("--json"),
    )
    .await?;
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = process.try_wait()? {
            return Err(HarnessError::Process(format!(
                "the {name} connector process exited before it served the device: {status}"
            )));
        }
        let owner = cluster
            .catalog
            .current_owner(tenant_id, device_id, chrono::Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?;
        if let Some(owner) = owner {
            let snapshot = owner_snapshot(cluster).await?;
            if let Ok(session) = session_of(&snapshot, &owner.token.session_id)
                && session.phase == "active"
            {
                return Ok((process, owner.token.session_id.clone()));
            }
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "the {name} connector process never reached an active device session"
            )));
        }
        sleep(POLL).await;
    }
}

#[allow(clippy::too_many_lines)]
async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<FsWriteRestartEvidence> {
    let mut evidence = FsWriteRestartEvidence {
        relay_count: cluster.relays.len(),
        image_expected_bytes: TARGET_FILE_BYTES,
        second_session_expected_bytes: TARGET_FILE_BYTES,
        ..FsWriteRestartEvidence::default()
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
        .fs_service("write-restart")
        .ok_or_else(|| {
            HarnessError::InvalidInput("the write-restart filesystem export was not seeded".into())
        })?
        .service_id;

    // The export's own host directory, holding the one file that is also the
    // journal.  It is a `TempDir` held for the whole run, so both process
    // generations serve the same root and the bytes span them.
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
    let profile = write_device_profile(
        profile_directory.path(),
        device.id,
        echo_service,
        "m4-fs-write-restart-canary",
        proxy.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;

    // The connector here is a **real child process**, so its configuration has
    // to reach it as a file rather than as a struct.  The *same* file starts
    // both processes: the replacement is the same device identity serving the
    // same root, so the only thing that changes across the event is which
    // process is running.
    let config_text = format!(
        "{existing}\n[exports.{service}]\ntype = \"fs\"\n\n[exports.{service}.fs]\nroot = {root}\ncapabilities = [\"read\", \"write\", \"list\"]\n",
        existing = std::fs::read_to_string(&profile.config_path).map_err(HarnessError::Io)?,
        service = toml_string(&service.to_string()),
        root = toml_string(&directory.path().to_string_lossy()),
    );
    std::fs::write(&profile.config_path, config_text).map_err(HarnessError::Io)?;

    let (mut first, first_session_id) = start_connector_process(
        cluster,
        "m4-fs-write-restart-first",
        &profile.config_path,
        device.tenant_id,
        device.id,
    )
    .await?;
    evidence.first_pid = first.id().unwrap_or_default();

    let mut second_process: Option<ManagedProcess> = None;
    let scenario = exercise(
        cluster,
        harness,
        &proxy,
        &mut first,
        &mut second_process,
        &profile.config_path,
        &target_path,
        device.tenant_id,
        device.id,
        service,
        &first_session_id,
        &mut evidence,
    )
    .await;
    if scenario.is_err() {
        // Payload-free: identifiers, labels and counters only.
        eprintln!("fs write restart partial evidence: {evidence:?}");
    }

    // The first process is killed inside `exercise`; a bounded reap here covers
    // the paths that failed before reaching that point.
    let stop_first = first.shutdown(STOP_GRACE).await;
    let stop_second = match second_process {
        Some(process) => Some(process.shutdown(STOP_GRACE).await),
        None => None,
    };
    scenario?;
    // A first process that is already dead cannot be shut down again, and that
    // is the expected state, so only the replacement's reaping is load-bearing.
    let _ = stop_first;
    match stop_second {
        None | Some(Ok(_)) => Ok(evidence),
        Some(Err(error)) => Err(HarnessError::Process(format!(
            "replacement connector process stop: {error}"
        ))),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn exercise(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    proxy: &ProxyHandle,
    first: &mut ManagedProcess,
    second_process: &mut Option<ManagedProcess>,
    config_path: &Path,
    target_path: &Path,
    tenant_id: Uuid,
    device_id: Uuid,
    service: Uuid,
    session_id: &str,
    evidence: &mut FsWriteRestartEvidence,
) -> Result<()> {
    // The owner claim, so the gate speaks to the relay that owns the device and
    // the epoch it compares against is the one the cluster agreed on.
    {
        let (epoch, owner_session_id, node) = wait_owner(cluster, tenant_id, device_id).await?;
        if owner_session_id != session_id {
            return Err(HarnessError::Process(
                "the owner claim names a different device session than the first process".into(),
            ));
        }
        evidence.owner_node = node;
        evidence.epoch_before = epoch;
        evidence.session_id_before = owner_session_id;
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

    let prefix_payload = payload_bytes(PREFIX_PAYLOAD_BYTES);
    let held_payload = payload_bytes(HELD_PAYLOAD_BYTES);

    // ---------------------------------------------------------------------
    // Session one: established, serving, then held across the process death.
    // ---------------------------------------------------------------------
    let (mut session, msize, selected) = open_session(&target, &ca, &token).await?;
    evidence.selected_subprotocol = selected;
    evidence.negotiated_msize = msize;
    evidence.negotiated_dialect = DIALECT.to_owned();

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

    // 1. Serve the session normally first, so a later failure cannot be blamed
    //    on a session that never worked.
    let mut prefix = 0_usize;
    for _ in 0..PREFIX_READS {
        match session.read(FILE_FID, prefix as u64, READ_COUNT).await? {
            Message::Rread { data } if !data.is_empty() => prefix += data.len(),
            other => return Err(unexpected("a non-empty Rread", &other)),
        }
    }
    evidence.prefix_bytes = prefix;

    // 2. The journal's **negative** direction, taken before the held write is
    //    sent: the region it will land in is still untouched filler.
    evidence.held_region_before_send =
        classify_region(&read_host_image(target_path), HELD_OFFSET, &held_payload);

    // 3. The journal's **positive** direction: one normal acknowledged Twrite,
    //    performed before anything is perturbed, whose bytes the harness then
    //    reads straight out of the export's own host file.  A journal that
    //    could only ever say "untouched" is ruled out here.
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

    // 4. Settle the carrier and pause the data socket's connector→relay bytes,
    //    so a reply cannot settle the exchange before the process dies.
    //
    //    The connector is a child process, so its sockets are identified from
    //    the proxy rather than from a status snapshot.  Both of its connections
    //    arrive here; the control socket is established first, so the data
    //    socket is the later of the two.  A mis-identification cannot pass
    //    silently: pausing the control socket would leave the write's reply
    //    flowing, the owner's receive cursor would advance, and step 6's
    //    bounded wait would fail rather than report an outstanding exchange.
    let connection = {
        let deadline = Instant::now() + WAIT;
        loop {
            let open = proxy.connections();
            let snapshot = owner_snapshot(cluster).await?;
            if open.len() == 2
                && let Ok(owner) = session_of(&snapshot, session_id)
                && owner.phase == "active"
                && owner.candidate_generation.is_none()
                && let Some(data) = open.iter().max_by_key(|connection| connection.id)
            {
                break data.id;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the device carrier never settled before the held write".into(),
                ));
            }
            sleep(POLL).await;
        }
    };
    proxy
        .pause(ProxyDirection::ClientToTarget, connection)
        .await?;

    // 5. Fix the owner's cursors for this stream **while paused**, so the
    //    comparison below is against a baseline nothing can move.
    let mut observation = WriteRestartObservation {
        stream_id,
        ..WriteRestartObservation::default()
    };
    {
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
        let stream = owner
            .streams
            .iter()
            .find(|stream| stream.stream_id == stream_id)
            .ok_or_else(|| {
                HarnessError::Process("the filesystem stream vanished before the held write".into())
            })?;
        observation.emitted_before = stream.last_emitted_relay_to_connector;
        observation.recv_contiguous_before = stream.recv_contiguous_connector_to_relay;
    }

    // 6. Send one `Twrite` and deliberately do not read its reply.  The request
    //    crosses on the still-flowing relay→connector direction, the device
    //    performs it — which is what puts the bytes in the host file — and the
    //    connector sequences the `Rwrite` into the paused socket, where it
    //    stays and is ultimately lost with the process.
    let held_tag = session
        .send(Message::Twrite {
            fid: FILE_FID,
            offset: HELD_OFFSET,
            data: held_payload.clone(),
        })
        .await?;
    evidence.held_tag = held_tag;

    // 7. Wait for the owner to show the write dispatched and unanswered.
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
                let sample = WriteRestartObservation {
                    emitted_at_kill: stream.last_emitted_relay_to_connector,
                    recv_contiguous_at_kill: stream.recv_contiguous_connector_to_relay,
                    ..observation.clone()
                };
                if sample.request_outstanding_at_kill() {
                    evidence.restart_polls = polls;
                    observation = sample;
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Process(
                    "the held Twrite was never observed dispatched and unanswered at the owner"
                        .into(),
                ));
            }
            sleep(POLL).await;
        }
    }
    evidence.request_outstanding_at_kill = observation.request_outstanding_at_kill();
    evidence.restart = observation;

    // 8. **The journal.**  Wait until the host file shows the held write reach
    //    the device, so the kill lands after the effect rather than racing it.
    //    Without this the gate could kill the process before the write arrived
    //    and would then be measuring a refusal that never dispatched —
    //    retryable, and a much weaker claim than the one the contract is about.
    //
    //    The wait ends on **either** `Written` or `Torn`.  Stopping only on
    //    `Written` would silently exclude the partial application
    //    `docs/filesystem-api.md` explicitly permits, and would leave the gate
    //    unable to report the very state it exists to classify.
    {
        let deadline = Instant::now() + JOURNAL_WAIT;
        let mut polls = 0_usize;
        loop {
            polls += 1;
            let state = classify_region(&read_host_image(target_path), HELD_OFFSET, &held_payload);
            if state == RegionState::Torn {
                evidence.torn_observed_before_kill = true;
            }
            if matches!(state, RegionState::Written | RegionState::Torn) {
                evidence.journal_polls = polls;
                evidence.held_region_before_kill = state;
                break;
            }
            if Instant::now() >= deadline {
                evidence.held_region_before_kill = state;
                return Err(HarnessError::Timeout(format!(
                    "the held write never reached the device: the host file still reads {}, so \
                     this run cannot measure an unknown outcome",
                    state.as_str()
                )));
            }
            sleep(POLL).await;
        }
    }

    // ---------------------------------------------------------------------
    // The event: the connector's real process is killed.  No unwind, no
    // graceful close, no chance to fail anything on the way out.  The paused
    // direction is deliberately **not** released: the answer this write
    // produced is lost with the process, which is the ambiguity the clause is
    // about.  The relay learns the device is gone through the control socket,
    // which is a separate connection and is not paused.
    // ---------------------------------------------------------------------
    let first_pid = first
        .id()
        .ok_or_else(|| HarnessError::Process("the first connector process has no pid".into()))?;
    evidence.first_pid = first_pid;
    super::send_process_signal(first_pid, "-KILL")?;
    let status = timeout(EXIT_WAIT, first.wait()).await.map_err(|_| {
        HarnessError::Timeout("the killed connector process was never reaped".into())
    })??;
    evidence.first_process_exited = true;
    // A process that exited on a signal has no exit code; one that shut down
    // under its own control does.  Read from the status rather than assumed
    // from the signal that was sent.
    evidence.first_process_killed_by_signal = status.code().is_none();

    // ---------------------------------------------------------------------
    // The clause's obligation: fail pending calls explicitly.
    // ---------------------------------------------------------------------
    match timeout(PENDING_CALL_WAIT, session.recv_event()).await {
        Ok(Ok(wire::Event::Close(code))) => {
            evidence.pending_call_closed = true;
            evidence.pending_call_close_code = code;
        }
        Ok(Ok(wire::Event::Frame(frame))) => {
            // A reply served from a session the contract invalidates.  Recorded
            // rather than thrown, so the validator names the violated rule —
            // and an `Rlerror` is recorded *as such*, because telling a caller
            // that a performed write failed is the specific trap this gate
            // exists to exclude.  The two are **disjoint**, not nested:
            // recording an error as both would make the error rule unreachable
            // behind the answered rule.
            if matches!(frame.message, Message::Rlerror { .. }) {
                evidence.pending_call_errored = true;
            } else {
                evidence.pending_call_answered = true;
            }
        }
        Ok(Ok(wire::Event::Ended)) => {
            // The socket ended without a code: that is not "explicitly".
            evidence.pending_call_closed = true;
            evidence.pending_call_close_code = None;
        }
        Ok(Err(error)) => {
            return Err(HarnessError::Process(format!(
                "reading the held session after the process restart: {error}"
            )));
        }
        Err(_) => {
            // Left hanging.  The validator names this; it is not a harness
            // timeout, it is the finding.
            evidence.pending_call_closed = false;
        }
    }
    session.abandon();

    // The classification, derived rather than asserted, and identical for a
    // whole region and a torn one: the caller saw no acknowledgement either
    // way, so `Outcome::Partial` — which the library defines in terms of an
    // *acknowledged* effect — does not describe it.
    evidence.held_call_outcome = Some(classify_held_outcome(evidence));

    // The authoritative catalog must report the owner released, so the second
    // claim is a fresh admission rather than an overlapping one.
    cluster.wait_for_no_owner(tenant_id, device_id).await?;
    evidence.owner_released_between = true;

    // The held exchange's stream is deregistered at the owner.
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
    // The restart: a **new process**, on the same identity and the same export
    // root, from the same configuration file.
    // ---------------------------------------------------------------------
    let (replacement, replacement_session_id) = start_connector_process(
        cluster,
        "m4-fs-write-restart-second",
        config_path,
        tenant_id,
        device_id,
    )
    .await?;
    evidence.second_pid = replacement.id().unwrap_or_default();
    evidence.second_process_active = true;
    *second_process = Some(replacement);

    let (epoch_after, owner_session_id) =
        wait_owner_epoch_above(cluster, tenant_id, device_id, evidence.epoch_before).await?;
    evidence.epoch_after = epoch_after;
    evidence.session_id_after = owner_session_id;
    if evidence.session_id_after != replacement_session_id {
        return Err(HarnessError::Process(
            "the owner claim after the restart names a session the replacement process did not \
             open"
                .into(),
        ));
    }

    // **The bytes the kill left behind, sampled before any 9P traffic reaches
    // the replacement process.**  Whatever state they are in, the restart may
    // not have changed it: a torn region completed here would be the adapter
    // resubmitting, and a written region reverted would be a rollback nothing
    // in the contract promises.
    evidence.held_region_after_restart =
        classify_region(&read_host_image(target_path), HELD_OFFSET, &held_payload);

    // ---------------------------------------------------------------------
    // Session two: the contract clause, against the **new process**, on a
    // session that reuses the same fid numbers so a leak would show.
    // ---------------------------------------------------------------------
    let (mut second, second_msize, _) = open_session_when_ready(&target, &ca, &token).await?;
    evidence.second_session_msize = second_msize;

    // This session attaches on its **own** root fid, so it holds a working root
    // while it probes the earlier session's fid numbers.
    second.attach(SECOND_ROOT_FID).await?;
    evidence.attach_count += 1;
    evidence.second_session_attached = true;

    // The earlier session's file fid — the one the held write was issued on,
    // and the one a caller resuming that write would reach for — must not be
    // bound here.
    match second.getattr(FILE_FID, GETATTR_BASIC).await? {
        Message::Rgetattr(_) => {
            return Err(HarnessError::Process(
                "the fid the outstanding write was issued on answered after a connector process \
                 restart: the profile restored a fid across a process restart"
                    .into(),
            ));
        }
        other => {
            evidence.stale_file_fid_refused = matches!(other, Message::Rlerror { .. });
            evidence.stale_file_fid_errno = errno_of(&other);
        }
    }

    // ---- the control: a caller that retries the write anyway ---------------
    //
    // The trap in its operational form.  A consumer that read the lost answer
    // as "it never happened" would resubmit, and the question is whether
    // anything below it would let that reach the provider.  It does not: the
    // fid is not allocated in this session, so the session state machine —
    // which runs in the *connector* process, inside `tunnel_fs_provider`'s
    // `accept`, before a request is ever queued toward the host — refuses the
    // write above the dispatch boundary.
    //
    // **What proves that, and what does not.**  Not the errno: `Einval` is
    // also what `tunnel_fs_host::policy` maps every errno it does not
    // recognise to, and what the host write path returns directly, so the
    // value is consistent with the refusal having come from the host instead.
    // Not the bytes either: a `Twrite` names an explicit offset, so a
    // resubmission of the identical frame is byte-for-byte idempotent and
    // invisible in a comparison of the file's contents.
    //
    // The file's **modification time** is neither.  A write that reached the
    // host calls `pwrite`, and `pwrite` advances `mtime` whether or not it
    // changed a byte — so the one case the byte comparison is blind to is
    // exactly the case `mtime` reports.  Sampling it either side of the retry
    // turns "it cannot have reached the host" from an argument about the code
    // into a measurement of the effect surface.  (Reads do not touch `mtime`,
    // so the replacement session's own traffic cannot move it.)
    //
    // Not the relay's emit cursor, which would have been the obvious place to
    // look: the relay is a byte pump for this message — it decodes only to
    // check framing and keeps no fid table — so the frame really does cross
    // relay→connector, and `last_emitted_relay_to_connector` advances for a
    // refused write exactly as for an accepted one.  The cursor cannot
    // discriminate here, and asserting that it does not move would be false.
    //
    // The region comparison below still earns its place against the cases that
    // are *not* idempotent — a replay at a different offset, or a torn region
    // quietly completed — and the whole-file image covers the rest.
    evidence.host_mtime_before_retry = read_host_mtime(target_path);
    match second
        .call(Message::Twrite {
            fid: FILE_FID,
            offset: HELD_OFFSET,
            data: held_payload.clone(),
        })
        .await?
    {
        Message::Rwrite { .. } => {
            return Err(HarnessError::Process(
                "a retried write was performed on a fid from before the process restart".into(),
            ));
        }
        other => {
            evidence.retry_refused_above_dispatch = matches!(other, Message::Rlerror { .. });
            evidence.retry_refusal_errno = errno_of(&other);
        }
    }
    evidence.host_mtime_after_retry = read_host_mtime(target_path);
    // Both samples must have been readable *and* equal.  Two `None`s compare
    // equal, which would let a failed measurement pass as a held rule.
    evidence.host_mtime_unchanged_across_retry = matches!(
        (evidence.host_mtime_before_retry, evidence.host_mtime_after_retry),
        (Some(before), Some(after)) if before == after
    );
    let host_image = read_host_image(target_path);
    evidence.held_region_after_retry = classify_region(&host_image, HELD_OFFSET, &held_payload);
    evidence.image_bytes = host_image.len();
    evidence.image_outside_held_region_matches = image_outside_held_region_matches(&host_image);

    // The export answers normally on this session's own root, so the refusals
    // above are fid scoping and not a replacement process that never served
    // this root.  Binding FILE_FID here, fresh, is also the other half of the
    // contract: the *number* is reusable once the session that held it is gone.
    match second
        .walk(SECOND_ROOT_FID, FILE_FID, &["target.bin"])
        .await?
    {
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

    let mut transferred: Vec<u8> = Vec::with_capacity(TARGET_FILE_BYTES);
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
    // Two independent views of the same effect: the host's, read by the
    // harness, and the export's, read over 9P by a session on the replacement
    // process.  They must agree — including when both say `Torn`.
    evidence.ninep_image_matches_host = transferred == host_image;
    evidence.held_region_over_ninep = classify_region(&transferred, HELD_OFFSET, &held_payload);

    second.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed instant for the fixtures: the rule is about the two samples
    /// being the *same* instant, never about which instant it is.
    fn fixed_mtime() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn passing() -> FsWriteRestartEvidence {
        FsWriteRestartEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: 65_536,
            negotiated_dialect: DIALECT.into(),
            prefix_bytes: 131_024,
            held_region_before_send: RegionState::Untouched,
            prefix_region_after_write: RegionState::Written,
            prefix_acknowledged_bytes: PREFIX_PAYLOAD_BYTES,
            restart: WriteRestartObservation {
                stream_id: 1,
                emitted_before: 4,
                emitted_at_kill: 5,
                recv_contiguous_before: 4,
                recv_contiguous_at_kill: 4,
            },
            request_outstanding_at_kill: true,
            restart_polls: 3,
            held_tag: 7,
            held_region_before_kill: RegionState::Written,
            torn_observed_before_kill: false,
            journal_polls: 2,
            first_pid: 4_242,
            first_process_exited: true,
            first_process_killed_by_signal: true,
            second_pid: 4_243,
            second_process_active: true,
            epoch_before: 1,
            epoch_after: 2,
            session_id_before: "session-one".into(),
            session_id_after: "session-two".into(),
            owner_released_between: true,
            pending_call_closed: true,
            pending_call_close_code: Some(DEVICE_GONE_CLOSE),
            pending_call_answered: false,
            pending_call_errored: false,
            held_call_outcome: Some(Outcome::Unknown),
            held_stream_deregistered: true,
            held_region_after_restart: RegionState::Written,
            stale_file_fid_refused: true,
            stale_file_fid_errno: Some(UNKNOWN_FID_ERRNO),
            retry_refused_above_dispatch: true,
            retry_refusal_errno: Some(UNKNOWN_FID_ERRNO),
            host_mtime_unchanged_across_retry: true,
            host_mtime_before_retry: Some(fixed_mtime()),
            host_mtime_after_retry: Some(fixed_mtime()),
            held_region_after_retry: RegionState::Written,
            image_bytes: TARGET_FILE_BYTES,
            image_expected_bytes: TARGET_FILE_BYTES,
            image_outside_held_region_matches: true,
            second_session_msize: 65_536,
            second_session_attached: true,
            held_region_over_ninep: RegionState::Written,
            ninep_image_matches_host: true,
            second_session_bytes: TARGET_FILE_BYTES,
            second_session_expected_bytes: TARGET_FILE_BYTES,
            second_session_messages: 5,
            second_session_getattr_size: TARGET_FILE_BYTES as u64,
            attach_count: 2,
        }
    }

    /// The same run, but the kill caught the write half applied.
    ///
    /// Every field that reads the region says `Torn` **consistently**, because
    /// that is what a real torn run would look like: the host, the restart
    /// sample, the retry sample and the export's own view all describe the same
    /// bytes.
    fn passing_torn() -> FsWriteRestartEvidence {
        FsWriteRestartEvidence {
            held_region_before_kill: RegionState::Torn,
            torn_observed_before_kill: true,
            held_region_after_restart: RegionState::Torn,
            held_region_after_retry: RegionState::Torn,
            held_region_over_ninep: RegionState::Torn,
            ..passing()
        }
    }

    #[test]
    fn an_unknown_outcome_is_not_settled_and_a_failed_one_is() {
        // The distinction the whole gate turns on, held against the library
        // rather than against this file's own reading of it.  If `Outcome` ever
        // made `Unknown` settled, the gate's central rule would become
        // satisfiable by the very report it exists to forbid, and this test is
        // what would fail first.
        assert!(!Outcome::Unknown.is_settled());
        assert!(Outcome::Failed.is_settled());
        assert!(Outcome::NotStarted.is_settled());
        // And the ordering that stops a later observation weakening an earlier
        // one: a write once seen as `Unknown` can never be reported as
        // `NotStarted` again.
        assert_eq!(
            Outcome::Unknown.merge(Outcome::NotStarted),
            Outcome::Unknown
        );
    }

    #[test]
    fn a_torn_held_region_is_accepted_by_every_rule_that_reads_it() {
        // **The guard against this gate being narrowed back into gate 10.**
        // `docs/filesystem-api.md` permits this class of operation to apply
        // partially, so a torn region is an admissible outcome of the event and
        // not a defect.  If anyone tightens `held_write_reached_the_device` to
        // `== RegionState::Written`, or tightens any region rule to demand a
        // whole write, this test is what fails.
        validate_fs_write_restart_evidence(&passing_torn())
            .expect("a torn region is an admissible outcome of a process failure");
        assert!(passing_torn().held_write_reached_the_device());
    }

    #[test]
    fn a_torn_region_is_unknown_to_the_caller_and_never_partial() {
        // The derivation the run actually uses, defeated directly.
        //
        // `Outcome::Partial` is "some **acknowledged** effect applied and the
        // rest did not".  This caller's exchange carried no acknowledgement at
        // all, so the tear the harness can see from outside is not information
        // the caller has, and the outcome it is entitled to is the same as for
        // a whole write.
        assert_eq!(classify_held_outcome(&passing_torn()), Outcome::Unknown);
        assert_eq!(classify_held_outcome(&passing()), Outcome::Unknown);
        assert_ne!(classify_held_outcome(&passing_torn()), Outcome::Partial);

        // And the two states that are **not** this event, each derived rather
        // than asserted.
        let untouched = FsWriteRestartEvidence {
            held_region_before_kill: RegionState::Untouched,
            ..passing()
        };
        assert_eq!(classify_held_outcome(&untouched), Outcome::NotStarted);
        let unreadable = FsWriteRestartEvidence {
            held_region_before_kill: RegionState::Unreadable,
            ..passing()
        };
        assert_eq!(classify_held_outcome(&unreadable), Outcome::NotStarted);
        let errored = FsWriteRestartEvidence {
            pending_call_errored: true,
            ..passing()
        };
        assert_eq!(classify_held_outcome(&errored), Outcome::Failed);
        assert!(classify_held_outcome(&errored).is_settled());
    }

    #[test]
    fn every_journal_direction_defeats_the_discrimination_on_its_own() {
        assert!(passing().journal_discriminated_both_directions());
        type Defeat = fn(&mut FsWriteRestartEvidence);
        let defeats: Vec<(&str, Defeat)> = vec![
            ("the negative direction", |e| {
                e.held_region_before_send = RegionState::Written;
            }),
            ("the positive direction", |e| {
                e.prefix_region_after_write = RegionState::Untouched;
            }),
            ("the acknowledged byte count", |e| {
                e.prefix_acknowledged_bytes = PREFIX_PAYLOAD_BYTES - 1;
            }),
        ];
        for (label, defeat) in defeats {
            let mut evidence = passing();
            defeat(&mut evidence);
            assert!(
                !evidence.journal_discriminated_both_directions(),
                "{label} must defeat the discrimination on its own"
            );
        }
    }

    #[test]
    fn every_stage_defeats_the_region_stability_on_its_own() {
        assert!(passing().region_unchanged_since_the_kill());
        assert!(passing_torn().region_unchanged_since_the_kill());
        // A torn region silently completed after the restart is a
        // resubmission, and a written region reverted is a rollback the
        // contract never promised.  Each stage catches its own.
        let completed_by_the_restart = FsWriteRestartEvidence {
            held_region_after_restart: RegionState::Written,
            ..passing_torn()
        };
        assert!(!completed_by_the_restart.region_unchanged_since_the_kill());
        let completed_by_the_retry = FsWriteRestartEvidence {
            held_region_after_retry: RegionState::Written,
            ..passing_torn()
        };
        assert!(!completed_by_the_retry.region_unchanged_since_the_kill());
        let rolled_back = FsWriteRestartEvidence {
            held_region_after_restart: RegionState::Untouched,
            ..passing()
        };
        assert!(!rolled_back.region_unchanged_since_the_kill());
    }

    #[test]
    fn a_byte_moved_outside_the_held_region_is_caught() {
        // The comparison the run uses, defeated directly.  A frame replayed at
        // some other offset is the realistic way a restart could duplicate an
        // effect, and this is what sees it.
        let mut image = expected_image_outside_held_region();
        let held_start = HELD_OFFSET as usize;
        image[held_start..held_start + HELD_PAYLOAD_BYTES]
            .copy_from_slice(&payload_bytes(HELD_PAYLOAD_BYTES));
        assert!(image_outside_held_region_matches(&image));

        // The held region may hold anything at all, including a tear, without
        // the rule firing: that is exactly what it excludes.
        let mut torn = image.clone();
        torn[held_start + 16] = FILLER_BYTE;
        assert!(image_outside_held_region_matches(&torn));

        // A byte before the held region, a byte after it, and a truncated
        // file, each caught.
        let mut before = image.clone();
        before[PREFIX_PAYLOAD_BYTES + 8] = 0x7f;
        assert!(!image_outside_held_region_matches(&before));
        let mut after = image.clone();
        let last = after.len() - 1;
        after[last] = 0x7f;
        assert!(!image_outside_held_region_matches(&after));
        assert!(!image_outside_held_region_matches(
            &image[..image.len() - 1]
        ));
        assert!(!image_outside_held_region_matches(&[]));
    }

    #[test]
    fn the_in_flight_predicate_needs_both_halves() {
        // The predicate itself, defeated in each direction.  Without these the
        // composite rule could be satisfied by a sample that shows only one of
        // the two facts.
        let outstanding = WriteRestartObservation {
            stream_id: 1,
            emitted_before: 4,
            emitted_at_kill: 5,
            recv_contiguous_before: 4,
            recv_contiguous_at_kill: 4,
        };
        assert!(outstanding.request_outstanding_at_kill());
        assert!(
            !WriteRestartObservation {
                emitted_at_kill: 4,
                ..outstanding.clone()
            }
            .request_outstanding_at_kill(),
            "a record that was never dispatched is not outstanding"
        );
        assert!(
            !WriteRestartObservation {
                recv_contiguous_at_kill: 5,
                ..outstanding
            }
            .request_outstanding_at_kill(),
            "a record that was already answered is not outstanding"
        );
    }

    #[test]
    fn the_held_region_never_overlaps_the_prefix_and_both_fit() {
        // The fixture's own geometry, so a later change to one constant cannot
        // quietly make the two regions overlap and turn the journal's two
        // directions into one.
        assert!(PREFIX_OFFSET as usize + PREFIX_PAYLOAD_BYTES < HELD_OFFSET as usize);
        assert!(HELD_OFFSET as usize + HELD_PAYLOAD_BYTES < TARGET_FILE_BYTES);
        // And the held write is a single frame, so "the bytes landed" is a
        // fact about one operation.
        assert!(HELD_PAYLOAD_BYTES < READ_COUNT as usize);
    }

    /// The mtime rule must be defeated by a *failed measurement*, not only by
    /// a moved timestamp.
    ///
    /// `Option<SystemTime>` has an equality that says `None == None`, so the
    /// obvious spelling -- compare the two samples -- reports "unchanged" when
    /// the file could not be stat'd at either end.  That is the shape this
    /// gate refuses everywhere else: a rule that holds because nothing was
    /// measured is not evidence, and it would hold for a run in which the
    /// export had vanished entirely.
    #[test]
    fn an_unmeasured_mtime_is_not_an_unchanged_mtime() {
        // Both samples missing: equal as `Option`s, and still not evidence.
        let mut evidence = passing();
        evidence.host_mtime_before_retry = None;
        evidence.host_mtime_after_retry = None;
        assert_eq!(
            evidence.host_mtime_before_retry, evidence.host_mtime_after_retry,
            "the trap only exists because these compare equal",
        );
        evidence.host_mtime_unchanged_across_retry = matches!(
            (evidence.host_mtime_before_retry, evidence.host_mtime_after_retry),
            (Some(before), Some(after)) if before == after
        );
        assert!(
            !evidence.host_mtime_unchanged_across_retry,
            "two unreadable samples must not report an unchanged mtime",
        );
        validate_fs_write_restart_evidence(&evidence)
            .expect_err("an unmeasured mtime must fail the rule");

        // One side missing, either side.
        for (before, after) in [(Some(fixed_mtime()), None), (None, Some(fixed_mtime()))] {
            let mut evidence = passing();
            evidence.host_mtime_before_retry = before;
            evidence.host_mtime_after_retry = after;
            evidence.host_mtime_unchanged_across_retry = matches!(
                (before, after),
                (Some(b), Some(a)) if b == a
            );
            validate_fs_write_restart_evidence(&evidence)
                .expect_err("a half-measured mtime must fail the rule");
        }

        // And the positive direction: two readable, equal samples hold it.
        let evidence = passing();
        assert!(evidence.host_mtime_unchanged_across_retry);
        validate_fs_write_restart_evidence(&evidence).expect("passing evidence");
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_fs_write_restart_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsWriteRestartEvidence));
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
            ("the session never served a read first", |e| {
                e.prefix_bytes = 0;
            }),
            // The journal's two directions.
            ("the negative direction of the journal", |e| {
                e.held_region_before_send = RegionState::Written;
            }),
            ("the positive direction of the journal", |e| {
                e.prefix_region_after_write = RegionState::Untouched;
            }),
            ("the prefix write acknowledged the wrong count", |e| {
                e.prefix_acknowledged_bytes = PREFIX_PAYLOAD_BYTES - 1;
            }),
            // The concurrency rules.
            ("the write was never dispatched", |e| {
                e.restart.emitted_at_kill = e.restart.emitted_before;
            }),
            ("the reply had already been received", |e| {
                e.restart.recv_contiguous_at_kill = e.restart.recv_contiguous_before + 1;
            }),
            ("the in-flight summary contradicts its sample", |e| {
                e.request_outstanding_at_kill = false;
            }),
            ("no stream was identified", |e| e.restart.stream_id = 0),
            // The effect.  Both non-arrival states are rejected; `Torn` is
            // deliberately **not** in this table, and
            // `a_torn_held_region_is_accepted_by_every_rule_that_reads_it`
            // holds that it must not be.  Each moves every region field
            // together, because the stability rule compares them against this
            // one and a lone edit would be caught there instead.
            (
                "the write had not reached the device before the kill",
                |e| {
                    e.held_region_before_kill = RegionState::Untouched;
                    e.held_region_after_restart = RegionState::Untouched;
                    e.held_region_after_retry = RegionState::Untouched;
                    e.held_region_over_ninep = RegionState::Untouched;
                },
            ),
            ("the host file could not be read at all", |e| {
                e.held_region_before_kill = RegionState::Unreadable;
                e.held_region_after_restart = RegionState::Unreadable;
                e.held_region_after_retry = RegionState::Unreadable;
                e.held_region_over_ninep = RegionState::Unreadable;
            }),
            // The event itself.
            ("no first process was identified", |e| e.first_pid = 0),
            ("the first process never exited", |e| {
                e.first_process_exited = false;
            }),
            ("the first process shut down gracefully", |e| {
                e.first_process_killed_by_signal = false;
            }),
            ("the replacement reused the same process", |e| {
                e.second_pid = e.first_pid;
            }),
            ("no replacement process was identified", |e| {
                e.second_pid = 0;
            }),
            ("the replacement process never served the device", |e| {
                e.second_process_active = false;
            }),
            // The cluster's corroboration.
            ("the owner was never released between them", |e| {
                e.owner_released_between = false;
            }),
            ("the epoch did not advance", |e| {
                e.epoch_after = e.epoch_before;
            }),
            ("the epoch went backwards", |e| e.epoch_after = 0),
            ("no epoch was observed before the restart", |e| {
                e.epoch_before = 0;
                e.epoch_after = 1;
            }),
            ("the session identity did not change", |e| {
                e.session_id_after = e.session_id_before.clone();
            }),
            ("no session was identified before the restart", |e| {
                e.session_id_before.clear();
            }),
            ("no session was identified after the restart", |e| {
                e.session_id_after.clear();
            }),
            // "fail pending calls explicitly".
            ("the pending call was left hanging", |e| {
                e.pending_call_closed = false;
            }),
            ("the pending call was closed with no code at all", |e| {
                e.pending_call_close_code = None;
            }),
            ("the pending call was closed with the wrong code", |e| {
                e.pending_call_close_code = Some(DEVICE_GONE_CLOSE + 1);
            }),
            ("the pending call was answered", |e| {
                e.pending_call_answered = true;
            }),
            // The trap.  The three mutations below are deliberately kept apart:
            // an `Rlerror` on the held tag, the classification that follows
            // from it, and the library property that makes that classification
            // mean something.  A single field would let one rule mask the other
            // two.
            (
                // The error alone, with the classification left as it is.  That
                // is the derivation regression the rule exists for, and with
                // `answered` and `errored` disjoint no other rule can reject
                // it, so the named rule is load-bearing rather than shadowed.
                "a write that reached the device was reported to the caller as an error",
                |e| e.pending_call_errored = true,
            ),
            (
                "a write that reached the device was reported as an error and classified to match",
                |e| {
                    e.pending_call_errored = true;
                    e.held_call_outcome = Some(Outcome::Failed);
                },
            ),
            (
                "the outcome was classified as settled, which licenses a retry",
                |e| e.held_call_outcome = Some(Outcome::Failed),
            ),
            (
                "the outcome was classified as never dispatched, which the host file contradicts",
                |e| e.held_call_outcome = Some(Outcome::NotStarted),
            ),
            (
                "the outcome was classified as partial, which claims an acknowledgement the \
                 caller never received",
                |e| e.held_call_outcome = Some(Outcome::Partial),
            ),
            ("the outcome was never classified at all", |e| {
                e.held_call_outcome = None;
            }),
            ("the held stream was never deregistered", |e| {
                e.held_stream_deregistered = false;
            }),
            // "does not blindly resubmit", on the bytes.
            ("the restart completed the write itself", |e| {
                e.held_region_before_kill = RegionState::Torn;
                e.held_region_after_retry = RegionState::Torn;
                e.held_region_over_ninep = RegionState::Torn;
            }),
            ("the restart rolled the write back", |e| {
                e.held_region_after_restart = RegionState::Untouched;
            }),
            ("the retry moved the bytes", |e| {
                e.held_region_after_retry = RegionState::Untouched;
            }),
            ("the stale file fid was not refused", |e| {
                e.stale_file_fid_refused = false;
            }),
            ("the stale file fid refusal carried no errno", |e| {
                e.stale_file_fid_errno = None;
            }),
            ("the stale file fid refusal carried another errno", |e| {
                e.stale_file_fid_errno = Some(UNKNOWN_FID_ERRNO + 1);
            }),
            ("the retry was not refused", |e| {
                e.retry_refused_above_dispatch = false;
            }),
            (
                "the retry carried an errno no session-level unknown-fid refusal carries",
                |e| e.retry_refusal_errno = Some(tunnel_fs_core::FsErrorCode::Eexist.errno()),
            ),
            // The rule that actually carries "it never reached the host": a
            // resubmission that got through advances `mtime` even when it
            // rewrites byte-for-byte identical content, which is the one case
            // every comparison of the file's *bytes* is blind to.
            (
                "the retry reached the host and rewrote the identical bytes, which the byte \
                 comparisons cannot see but the modification time can",
                |e| {
                    e.host_mtime_unchanged_across_retry = false;
                    e.host_mtime_after_retry = Some(fixed_mtime() + Duration::from_millis(1));
                },
            ),
            // The whole-file image.
            ("the host file changed length", |e| {
                e.image_bytes = TARGET_FILE_BYTES - 1;
            }),
            ("an expected length that is not the fixture's", |e| {
                e.image_bytes = TARGET_FILE_BYTES - 1;
                e.image_expected_bytes = TARGET_FILE_BYTES - 1;
            }),
            ("a byte outside the held region moved", |e| {
                e.image_outside_held_region_matches = false;
            }),
            // The refusals were fid scoping and not a broken export.
            ("the replacement session negotiated no msize", |e| {
                e.second_session_msize = 0;
            }),
            ("the replacement session msize above the ceiling", |e| {
                e.second_session_msize = OFFERED_MSIZE + 1;
            }),
            ("the replacement session never attached", |e| {
                e.second_session_attached = false;
            }),
            ("a short transfer", |e| e.second_session_bytes -= 1),
            ("an expected transfer that is not the fixture's", |e| {
                e.second_session_expected_bytes = TARGET_FILE_BYTES - 1;
                e.second_session_bytes = TARGET_FILE_BYTES - 1;
            }),
            ("a single-message transfer", |e| {
                e.second_session_messages = MIN_READ_MESSAGES;
            }),
            ("the two views of the file disagree", |e| {
                e.ninep_image_matches_host = false;
            }),
            ("the two views classify the held region differently", |e| {
                e.held_region_over_ninep = RegionState::Untouched;
            }),
            ("the file changed size", |e| {
                e.second_session_getattr_size = TARGET_FILE_BYTES as u64 - 1;
            }),
            ("an extra Tattach", |e| e.attach_count = 3),
            ("a missing Tattach", |e| e.attach_count = 1),
        ];
        for (label, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_fs_write_restart_evidence(&evidence).is_err(),
                "mutation `{label}` must be rejected"
            );
        }
    }
}
