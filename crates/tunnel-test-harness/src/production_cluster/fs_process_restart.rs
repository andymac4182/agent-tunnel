//! A live 9P2000.L filesystem session held **with a mutation outstanding**
//! while the connector's **real operating-system process is killed and a
//! replacement process is started**, over the real cluster: a consumer WSS
//! session through the owning relay's public route, the owner actor, the
//! device data WebSocket and a `tunnel-client` **child process** serving a
//! filesystem export from a real host directory.
//!
//! This is M4-06's *process restart* clause, the last of the five transport
//! events that row names.  [`docs/filesystem-api.md`] puts it in the same
//! sentence as the three events gates 7, 8 and 9 closed:
//!
//! > Consumer loss, control-epoch change, grant expiry, or process restart
//! > invalidates the filesystem session.
//!
//! and `docs/protocol.md` states what "invalidates" obliges, naming this
//! gate's event explicitly in its first sentence:
//!
//! > The first filesystem profile restores no fids across a consumer
//! > WebSocket reconnect, control-session reconnect or
//! > **adapter/connector/relay process restart**: terminate that filesystem
//! > session, **fail pending calls explicitly** and create a fresh 9P
//! > session.  Generic tunnel resume support must not silently opt the
//! > filesystem adapter into stronger recovery guarantees.  Replacement of a
//! > failed data socket may preserve the filesystem session only while the
//! > same control owner and all ordered stream state are retained.
//!
//! The same document's flush paragraph carries the clause that makes this
//! event different from the other four, and it is the one this gate is really
//! about:
//!
//! > If a write or rename outcome becomes ambiguous after a transport or
//! > **process failure**, the just-bash adapter **reports that ambiguity and
//! > does not blindly resubmit** the operation in the new session.
//!
//! # What the clause licenses, and what it therefore forbids asserting
//!
//! Reading the clause settles the expected assertion, and — as in gates 8 and
//! 9 — it is the opposite of what the same-owner sentence would suggest.  That
//! sentence licenses fid retention for exactly one event, "replacement of a
//! *failed data socket* ... only while the same control owner and all ordered
//! stream state are retained".  A process restart destroys **both** qualifiers
//! at once: the control owner is a different process, and every byte of
//! ordered stream state it held died with it.  A process restart is named in
//! the *first* sentence, across which the profile restores **no fids at all**.
//! So this gate, like gates 8 and 9 and unlike gate 7, must prove that a fid
//! does **not** survive; a gate asserting survival here would be asserting the
//! violation.
//!
//! The flush paragraph then adds the obligation that is unique to this event.
//! A mutation that reached the device and whose answer was lost is
//! **ambiguous**.  [`tunnel_fs_core::Outcome`] has the vocabulary for exactly
//! that distinction and orders it: `NotStarted` means "refused before anything
//! was dispatched", and `Outcome::is_settled` — "whether the caller may assume
//! no side effect occurred" — is true only of `NotStarted` and `Failed`.
//! `Unknown` is not settled, and is therefore **not retryable**.  Reporting an
//! ambiguous mutation as `NotStarted` is how a write replays.
//!
//! # Why this needed a journal, and why it was twice declined as a tail
//!
//! **An in-memory ledger dies with the process, which makes "the count did not
//! increase" true of nothing.**  A gate that killed the connector and then
//! counted effects in the connector's own memory would read zero after the
//! restart and pass vacuously.  The pattern that answers this already exists
//! in this repository: M5 chunk 4's append-only journal in
//! `crates/tunnel-cua-fixture` and `crates/tunnel-cua-export`, whose
//! properties are that the record is written **before** any fault is applied,
//! that it **outlives the process that made it**, and that the test **waits
//! for it to show the effect before restarting** — so what is measured is an
//! `Unknown` rather than a `NotDispatched`.
//!
//! Here the journal is not a side file.  It is the **export's own host
//! directory**, which is the connector's only durable effect surface:
//!
//! * The held operation is a `Tlcreate`, so its effect is a **directory
//!   entry**.  An entry appears at the moment the provider performs the
//!   create, before anything is answered, and it is still there when the
//!   process that made it is gone.
//! * [`journal_entries`] counts those entries by reading the host directory
//!   directly — from the harness, not through the connector — so the count is
//!   independent of the process under test and spans both its generations.
//! * The gate **waits for the entry to appear before killing the process**.
//!   Without that wait the kill could land before the create reached the
//!   device, and the gate would then be measuring a refusal that never
//!   dispatched: a different and far weaker claim, and precisely the one the
//!   contract says a caller may retry.
//!
//! [`FsProcessRestartEvidence::held_call_outcome`] is the classification this
//! buys, and it is derived from what the wire actually did rather than
//! asserted: the journal showed the effect **and** the exchange was closed
//! without an answer, so the outcome is [`tunnel_fs_core::Outcome::Unknown`].
//! Had the held tag come back as an `Rlerror`, the outcome would be
//! `Outcome::Failed` — settled, and a caller told that may assume no side
//! effect occurred, which would be false.  The validator holds both the
//! identity and `!is_settled()`, the second read out of the library.
//!
//! # Why the restart is a real process restart
//!
//! Gate 9 replaced the **control session** by stopping an in-process
//! `tunnel_client::ConnectionHandle` and starting another.  That is not this
//! event.  The connector here is the workspace's own `tunnel-client` binary,
//! spawned as a child process with a config file naming a filesystem export
//! rooted at a real host directory, and the event is a **`SIGKILL`**: no
//! unwind, no graceful close frame, no chance for the connector to fail
//! anything on its way out.  The evidence records the first process's pid, that
//! that pid **exited**, and that the replacement runs under a **different**
//! pid, so "restart" is a fact about processes and not a figure of speech.  The
//! cluster's own corroboration is carried alongside: the catalog reports the
//! owner released between the two processes, and the replacement claim takes a
//! strictly greater epoch on a changed session identity.
//!
//! `SIGKILL` rather than `SIGTERM` is deliberate.  A graceful stop would let
//! the connector close its sockets in order, and a session failed explicitly
//! by an orderly shutdown proves nothing about the clause, which is about what
//! happens when a process **fails**.
//!
//! # What makes the restart concurrent with the exchange
//!
//! A restart between two settled 9P exchanges would be "an event between two
//! quiet periods", which proves nothing.  The construction is gate 8's and
//! gate 9's, proven from the owner's own per-stream sequence cursors rather
//! than from timing:
//!
//! 1. The consumer attaches, creates one file normally and reads part of a
//!    synthetic file, so the session is established and serving before
//!    anything is perturbed.
//! 2. The device data socket's **connector→relay** bytes are paused at the
//!    harness TCP proxy once the carrier has settled.
//! 3. The owner is sampled *while paused*, fixing this stream's
//!    `last_emitted_relay_to_connector` and
//!    `recv_contiguous_connector_to_relay`.
//! 4. The consumer sends one `Tlcreate` and does **not** read its reply.  The
//!    request crosses on the still-flowing relay→connector direction, so the
//!    owner's `last_emitted_relay_to_connector` for this stream **advances**;
//!    the reply is sequenced into the paused direction, so the owner's
//!    `recv_contiguous_connector_to_relay` **cannot** advance.
//! 5. The gate waits for exactly that pair, *and then* for the journal to show
//!    the create performed, and kills the process at that instant.  The proof
//!    that the mutation was outstanding across the restart is
//!    `emitted_at_kill > emitted_before && recv_contiguous_at_kill ==
//!    recv_contiguous_before`, on the owner's own cursors; the proof that it
//!    was *dispatched and performed* is the journal.
//!
//! **The paused direction is never released.**  Gate 9 resumed before stopping
//! its connector so a graceful stop could not wedge behind the pause; a
//! `SIGKILL` needs no cooperation, so this gate holds the pause instead and
//! the buffered `Rlcreate` is discarded with the proxy.  That is not a
//! convenience — it is the event in its exact form: an answer that was
//! produced and **lost**.  Releasing it could let the reply settle the
//! exchange as a success and would destroy the very ambiguity the gate exists
//! to measure.  The relay still learns the device is gone, because the
//! connector's **control** socket is a separate connection through the same
//! proxy and is not paused: the killed process's control socket closes, and
//! that is what invalidates the filesystem session.
//!
//! This also makes a mis-identification of the two proxy connections fail
//! loudly rather than pass quietly.  If the control socket were paused by
//! mistake, the `Tlcreate` would still cross the data socket and be answered,
//! `recv_contiguous_connector_to_relay` would advance, and step 5 would time
//! out on its bounded deadline instead of reporting an outstanding exchange.
//!
//! # The assertions are on the operation, not on liveness
//!
//! A cluster that still runs proves nothing about a fid, and a connector that
//! restarts proves nothing about a tag.  What is asserted is:
//!
//! * the pending call is **failed explicitly with a close code**, never
//!   answered and never left hanging — the clause gate 9 found was being
//!   violated, checked again here on a different cause;
//! * the held mutation classifies as `Outcome::Unknown`, which is **not
//!   settled** and therefore not retryable;
//! * the journal shows the effect happened **exactly once**, counted from the
//!   host directory across both process generations;
//! * a replacement consumer session, opened against the **new process** and
//!   reusing the same fid numbers, restores no fids — driven in the two pieces
//!   the session machine checks them in, exactly as gates 8 and 9 drive them;
//! * **the control**: a caller that retries the mutation anyway, on the fid it
//!   held before the restart, is refused *above* the dispatch boundary with the
//!   unknown-fid errno, and the journal count **does not move**.  A count of
//!   two would be the "unknown outcome read as not dispatched" trap arriving
//!   through a process restart.
//!
//! The replacement session then shows the refusals were fid scoping and not a
//! broken export — nor a second process that failed to serve the same root —
//! by walking, opening and reading a whole synthetic file back with an exact
//! checksum, binding the earlier session's file-fid *number* freshly as it
//! does so.
//!
//! The reuse of the *same fid numbers* is deliberate and is the whole force of
//! the case: if fids leaked across a process restart, the earlier numbers would
//! still be bound and would answer.
//!
//! All fixture content is synthetic and generated here; no evidence field
//! carries a path, a name or file content.

use std::path::Path;
use std::time::{Duration, Instant};

use tokio::time::{sleep, timeout};
use tunnel_fs_core::Outcome;
use tunnel_fs_ninep::{GETATTR_BASIC, Message, flags::O_RDONLY, flags::O_WRONLY};
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot};
use uuid::Uuid;

use super::fs_wire as wire;
use wire::{NinepClient, Target, UpgradeFailure, errno_of, unexpected};

use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, STARTUP_TIMEOUT, client_binary_path,
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
/// Derived, not pinned, exactly as [`UNKNOWN_FID_ERRNO`] is:
/// `SessionErrorCode::DeviceOffline` is the profile's "the export's backend is
/// the thing that went away" code, which is what a dead connector process is
/// from the consumer's side — the relay is healthy and the device it was
/// proxying to is not.  `close_code()` maps it to 1012 at this revision; the
/// gate asserts the expression, not the number.
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

/// The directory inside the export whose entries are the journal.
const JOURNAL_DIR: &str = "effects";
/// The entry created normally, before anything is perturbed.  Its presence is
/// what shows the mutation path worked at all, so a later absence cannot be
/// blamed on an export that never created anything.
const SETTLED_ENTRY: &str = "effect-settled";
/// The entry whose `Tlcreate` is outstanding when the process is killed.
const HELD_ENTRY: &str = "effect-held";
/// How many entries the journal must hold at the end: the settled one and the
/// held one, each exactly once.  Three would be a replay.
const EXPECTED_JOURNAL_ENTRIES: usize = 2;

/// The synthetic file the replacement session reads back.
///
/// Large enough that the transfer needs many messages, so it is not a
/// single-frame special case.
const RESTART_FILE_BYTES: usize = 786_432;
/// The replacement session's whole-file transfer must need more than this many
/// `Rread` messages.
const MIN_READ_MESSAGES: usize = 10;
/// How much of the file is read before anything is perturbed, establishing
/// that the session serves normally first.
const PREFIX_READS: usize = 3;

/// The fid numbers the first session binds, and which the replacement session
/// then probes.
///
/// The replacement session deliberately reuses these exact numbers: the
/// contract clause is that no fid is restored across a process restart, and
/// reusing the numbers is what makes a leak observable instead of merely
/// unlikely.
const ATTACH_FID: u32 = 0;
const FILE_FID: u32 = 1;
/// The directory fid the held `Tlcreate` is issued on.  `Tlcreate` rebinds the
/// parent fid to the file it makes, so this is a walked clone of the root and
/// never the session's own attach fid.
const JOURNAL_FID: u32 = 2;
/// A second walked clone, spent on the settled create.
const SETTLED_FID: u32 = 3;

/// The root fid the replacement session attaches on.
///
/// Deliberately **not** [`ATTACH_FID`]: the replacement session has to hold a
/// working root while it probes the earlier session's fid numbers, and if it
/// attached on [`ATTACH_FID`] then a probe of that number would be answering
/// from this session's own binding rather than showing the absence of the
/// earlier one.
const SECOND_ROOT_FID: u32 = 5;
/// A scratch fid the replacement session walks its own journal handle onto.
const SECOND_JOURNAL_FID: u32 = 6;
/// A scratch fid for the "the export still walks" probe.
const SECOND_SCRATCH_FID: u32 = 9;

/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for a cluster state change.
const WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for the killed pid to be reaped.
const EXIT_WAIT: Duration = Duration::from_secs(30);
/// How long the journal is given to show the held create performed.
///
/// Bounded: a run that reaches this deadline has **not** found a defect, it has
/// failed to set up the measurement — the create never reached the device — and
/// the gate says so rather than killing the process anyway and measuring a
/// `NotStarted` it would then have to report as an `Unknown`.
const JOURNAL_WAIT: Duration = Duration::from_secs(30);
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
/// How long a connector process is given to exit on its own before cleanup
/// kills it.  A connector never exits on its own, so this is a floor on the
/// cleanup cost rather than a real grace, and it is short for that reason.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// What the owner recorded about the stream the session was held on.
///
/// Payload-free: sequences, identifiers and lifecycle bits only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcessRestartObservation {
    /// The consumer stream the filesystem session ran on.
    pub stream_id: u64,
    /// The owner's relay→connector emit cursor for this stream, sampled while
    /// the reverse direction was already paused and before the held
    /// `Tlcreate`.
    pub emitted_before: u64,
    /// The same cursor at the instant the process was killed.  It must have
    /// advanced: the relay dispatched the mutation toward the device.
    pub emitted_at_kill: u64,
    /// The owner's contiguous connector→relay receive cursor for this stream,
    /// sampled at the same instant as [`Self::emitted_before`].
    pub recv_contiguous_before: u64,
    /// The same cursor at the instant of the kill.  It must **not** have
    /// advanced: no answer to that mutation had reached the owner.
    pub recv_contiguous_at_kill: u64,
}

impl ProcessRestartObservation {
    /// Whether this sample shows a 9P mutation the relay had dispatched and
    /// had received no answer to, at the instant the process was killed.  This
    /// is the gate's concurrency proof, and it is the owner's own record rather
    /// than a timestamp comparison.
    #[must_use]
    pub fn request_outstanding_at_kill(&self) -> bool {
        self.emitted_at_kill > self.emitted_before
            && self.recv_contiguous_at_kill == self.recv_contiguous_before
    }
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsProcessRestartEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    /// The negotiated session parameters, so a run cannot pass on a session
    /// that never reached 9P.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub negotiated_dialect: String,

    /// Bytes read on the file fid **before** anything was perturbed.
    pub prefix_bytes: usize,
    /// The journal entry count after the settled create and before the held
    /// one, so the mutation path is known to have worked first.
    pub journal_entries_before_held: usize,
    /// The owner's sample either side of the kill.
    pub restart: ProcessRestartObservation,
    /// Whether that sample proves the mutation was outstanding at the kill.
    pub request_outstanding_at_kill: bool,
    /// How many polls the outstanding state took to observe, for diagnosis.
    pub restart_polls: usize,
    /// The tag that was outstanding when the process was killed.
    pub held_tag: u16,

    // The journal: the whole reason this event needed its own chunk.
    /// Journal entries counted **from the host directory** at the instant
    /// before the kill.  It must include the held entry: that is what makes the
    /// held call an unknown rather than a refusal that never dispatched.
    pub journal_entries_before_kill: usize,
    /// Whether the held create's own entry was present before the kill.
    pub held_effect_present_before_kill: bool,
    /// How many polls that took, for diagnosis.
    pub journal_polls: usize,

    // The event itself: a real operating-system process, really killed.
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

    // The cluster's corroboration that the restart was a real admission cycle.
    /// The owner epoch before the kill, from the authoritative catalog.
    pub epoch_before: u64,
    /// The owner epoch after.  It must be **strictly greater**: a replacement
    /// process that re-claimed the device without advancing the epoch would
    /// mean the first claim never ended.
    pub epoch_after: u64,
    /// The device session identity either side.  A process restart that kept
    /// the same session would not be one, so these must differ.
    pub session_id_before: String,
    pub session_id_after: String,
    /// Whether the catalog reported the owner genuinely released between the
    /// two processes, so the second claim is a fresh admission and not an
    /// overlapping one.
    pub owner_released_between: bool,

    // The clause's obligations.
    /// Whether the held exchange's session was **closed** rather than left
    /// hanging: "fail pending calls explicitly".
    pub pending_call_closed: bool,
    /// The close code that failure carried.
    pub pending_call_close_code: Option<u16>,
    /// Whether the held `Tlcreate` was instead **answered** across the restart.
    /// It must not be: a reply served from a session the contract says is
    /// invalidated would be the violation.
    pub pending_call_answered: bool,
    /// Whether the held tag came back as an `Rlerror`.  This is the trap in its
    /// exact form: an `Rlerror` on a mutation that the journal proves was
    /// performed would tell a caller the mutation failed — `Outcome::Failed`,
    /// which **is** settled — and a caller acting on that may assume no side
    /// effect occurred and resubmit.
    pub pending_call_errored: bool,
    /// How the held mutation classifies, derived from the three observations
    /// above and the journal rather than asserted.
    ///
    /// `None` means the run never reached the classification, which is not the
    /// same as classifying it weakly and is rejected by its own rule.
    pub held_call_outcome: Option<Outcome>,

    /// The first session's stream is deregistered at the owner.
    pub held_stream_deregistered: bool,

    // The contract clause proper, driven against the **new process** on a
    // session that reuses the same fid numbers.
    /// A replacement session that speaks **before** its own `Tattach` is closed
    /// rather than served.  The close code observed.
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
    /// Whether the earlier session's **journal** fid — the one the outstanding
    /// mutation was issued on — was likewise unbound.
    pub stale_journal_fid_refused: bool,
    pub stale_journal_fid_errno: Option<u32>,

    // The control: a caller that retries anyway.
    /// Whether re-issuing the held `Tlcreate` on the fid it was originally
    /// issued on is refused *above* the dispatch boundary.
    pub retry_refused_above_dispatch: bool,
    /// The errno that refusal carried.  It must be the unknown-fid errno: a
    /// refusal from the host (an `Eexist`, say) would mean the retry reached
    /// the provider, which is a weaker and different claim.
    pub retry_refusal_errno: Option<u32>,
    /// Journal entries after that retry.  It must equal
    /// [`Self::journal_entries_before_kill`]: the retry moved nothing.
    pub journal_entries_after_retry: usize,

    /// The replacement session had to establish its own root.
    pub second_session_attached: bool,
    /// The journal as the **replacement session** sees it, over 9P rather than
    /// from the host directory, so the two independent views must agree.
    pub journal_entries_over_ninep: usize,
    /// The journal as the host directory finally reports it, across both
    /// process generations.  Exactly one settled effect and one held effect.
    pub journal_entries_final: usize,
    /// Whether the held effect appears exactly once in the final journal.
    pub held_effect_exactly_once: bool,
    /// The whole synthetic file read back on the replacement session's own fid,
    /// proving the refusals above were fid scoping and neither a broken export
    /// nor a replacement process that never served this root.
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
pub fn validate_fs_process_restart_evidence(evidence: &FsProcessRestartEvidence) -> Result<()> {
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
        (
            "the mutation path worked before the held mutation was issued".into(),
            evidence.journal_entries_before_held == 1,
        ),
        // The concurrency rules.  Without these the gate would prove only that
        // a process restarted somewhere near a filesystem session.
        (
            "the relay had dispatched a 9P record toward the device when the process was killed"
                .into(),
            evidence.restart.emitted_at_kill > evidence.restart.emitted_before,
        ),
        (
            "the relay had received no answer to that record when the process was killed: the 9P \
             mutation was outstanding across the restart"
                .into(),
            evidence.request_outstanding_at_kill && evidence.restart.request_outstanding_at_kill(),
        ),
        (
            "a stream was identified for the held exchange".into(),
            evidence.restart.stream_id > 0,
        ),
        // The journal.  These are the rules that make the outcome measurable at
        // all, and they are the reason this event is a chunk and not a tail.
        (
            "the held mutation had reached the device and been performed before the process was \
             killed, so the lost answer is an unknown and not a refusal that never dispatched"
                .into(),
            evidence.held_effect_present_before_kill,
        ),
        (
            "the journal, read from the host directory, held both effects at the kill".into(),
            evidence.journal_entries_before_kill == EXPECTED_JOURNAL_ENTRIES,
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
        // "fail pending calls explicitly", on a cause gate 9 could not produce.
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
        // The trap, in its exact form.
        (
            // Load-bearing against a **derivation** regression, which is the
            // only way this state can arise: an `Rlerror` on the held tag is
            // classified as `Outcome::Failed` a few lines below, so evidence
            // that records the error and an `Unknown` alongside it is evidence
            // whose classifier has stopped agreeing with what it saw.  The
            // classification rules cannot catch that, because they only see the
            // classification.
            "a mutation the journal proves was performed was not reported to the caller as an \
             error, which is a settled outcome a caller may resubmit after"
                .into(),
            !evidence.pending_call_errored,
        ),
        (
            "the held mutation classifies as an unknown outcome".into(),
            evidence.held_call_outcome == Some(Outcome::Unknown),
        ),
        (
            "that classification is one the caller may not assume away: an unknown outcome is not \
             settled, so it is not retryable"
                .into(),
            evidence
                .held_call_outcome
                .is_some_and(|outcome| !outcome.is_settled()),
        ),
        (
            "the held exchange's stream was deregistered at the owner".into(),
            evidence.held_stream_deregistered,
        ),
        // The contract clause proper.
        (
            "a replacement session that speaks before attaching is closed with the profile's \
             protocol violation"
                .into(),
            evidence.pre_attach_probe_close_code == Some(PROTOCOL_VIOLATION_CLOSE),
        ),
        (
            "that session was closed rather than served".into(),
            !evidence.pre_attach_probe_answered,
        ),
        (
            "the replacement session negotiated a bounded msize".into(),
            evidence.second_session_msize > 0 && evidence.second_session_msize <= OFFERED_MSIZE,
        ),
        (
            "the replacement session established its own root".into(),
            evidence.second_session_attached,
        ),
        (
            "the earlier session's file fid is unbound after the restart".into(),
            evidence.stale_file_fid_refused,
        ),
        (
            "the stale file fid refusal carried the errno for a fid this session never \
             allocated"
                .into(),
            evidence.stale_file_fid_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "the earlier session's attach fid is unbound after the restart".into(),
            evidence.stale_attach_fid_refused,
        ),
        (
            "the stale attach fid refusal carried the errno for a fid this session never \
             allocated"
                .into(),
            evidence.stale_attach_fid_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "the fid the outstanding mutation was issued on is unbound after the restart".into(),
            evidence.stale_journal_fid_refused,
        ),
        (
            "the stale mutation fid refusal carried the errno for a fid this session never \
             allocated"
                .into(),
            evidence.stale_journal_fid_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        // The control.
        (
            "a caller that retries the mutation anyway is refused above the dispatch boundary"
                .into(),
            evidence.retry_refused_above_dispatch,
        ),
        (
            "that retry was refused for its fid and never reached the provider".into(),
            evidence.retry_refusal_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "the refused retry moved no effect".into(),
            evidence.journal_entries_after_retry == evidence.journal_entries_before_kill,
        ),
        // The measurement this chunk exists for.
        (
            "the effect happened exactly once across both process generations".into(),
            evidence.journal_entries_final == EXPECTED_JOURNAL_ENTRIES,
        ),
        (
            "the held effect appears exactly once".into(),
            evidence.held_effect_exactly_once,
        ),
        (
            "the replacement session's own view of the journal agrees with the host's".into(),
            evidence.journal_entries_over_ninep == evidence.journal_entries_final,
        ),
        // The refusals were fid scoping and not a broken export.
        (
            "the replacement session read the whole file back".into(),
            evidence.second_session_bytes == evidence.second_session_expected_bytes
                && evidence.second_session_expected_bytes == RESTART_FILE_BYTES,
        ),
        (
            "the bytes it read match byte for byte".into(),
            evidence.second_session_checksum_matches,
        ),
        (
            "that transfer needed many messages rather than one".into(),
            evidence.second_session_messages > MIN_READ_MESSAGES,
        ),
        (
            "the file is the size it always was".into(),
            evidence.second_session_getattr_size == RESTART_FILE_BYTES as u64,
        ),
        (
            "exactly one Tattach per attached session, and never a reconstructed one".into(),
            evidence.attach_count == 2,
        ),
    ];
    for (rule, held) in checks {
        if !held {
            return Err(HarnessError::Process(format!(
                "M4 filesystem process restart evidence failed: {rule}"
            )));
        }
    }
    Ok(())
}

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

/// Count the journal's entries by reading the **host directory**, not by
/// asking the connector.
///
/// This is the whole point of the journal: the count is taken from a surface
/// that outlives the process under test, so it spans both generations and does
/// not read zero the moment the first one dies.
fn journal_entries(root: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(root.join(JOURNAL_DIR)).map_err(HarnessError::Io)? {
        let entry = entry.map_err(HarnessError::Io)?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
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
/// live 9P mutation, restart it, and validate the evidence.
///
/// # Errors
/// Any harness, cluster or validation failure.
pub async fn verify() -> Result<FsProcessRestartEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("fs process restart harness startup timed out".into())
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
            validate_fs_process_restart_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs process restart scenario exceeded its bounded deadline".into(),
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
/// the owner reports an active device session for it.  Returns the process and
/// the session identity the cluster admitted.
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
) -> Result<FsProcessRestartEvidence> {
    let mut evidence = FsProcessRestartEvidence {
        relay_count: cluster.relays.len(),
        second_session_expected_bytes: RESTART_FILE_BYTES,
        ..FsProcessRestartEvidence::default()
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
        .fs_service("process-restart")
        .ok_or_else(|| {
            HarnessError::InvalidInput(
                "the process-restart filesystem export was not seeded".into(),
            )
        })?
        .service_id;

    // The export's own host directory, which is also the journal.  It is a
    // `TempDir` held for the whole run, so both process generations serve the
    // same root and the entry count spans them.
    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    std::fs::write(
        directory.path().join("big.bin"),
        synthetic_bytes(RESTART_FILE_BYTES),
    )
    .map_err(HarnessError::Io)?;
    std::fs::create_dir(directory.path().join(JOURNAL_DIR)).map_err(HarnessError::Io)?;

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
        "m4-fs-process-restart-canary",
        proxy.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;

    // The connector here is a **real child process**, so its configuration has
    // to reach it as a file rather than as a struct.  The profile's own file is
    // extended with the filesystem export, and the *same* file starts both
    // processes: the replacement is the same device identity serving the same
    // root, so the only thing that changes across the event is which process is
    // running.
    let config_text = format!(
        "{existing}\n[exports.{service}]\ntype = \"fs\"\n\n[exports.{service}.fs]\nroot = {root}\ncapabilities = [\"read\", \"write\", \"list\"]\n",
        existing = std::fs::read_to_string(&profile.config_path).map_err(HarnessError::Io)?,
        service = toml_string(&service.to_string()),
        root = toml_string(&directory.path().to_string_lossy()),
    );
    std::fs::write(&profile.config_path, config_text).map_err(HarnessError::Io)?;

    let (mut first, first_session_id) = start_connector_process(
        cluster,
        "m4-fs-process-restart-first",
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
        directory.path(),
        device.tenant_id,
        device.id,
        service,
        &first_session_id,
        &mut evidence,
    )
    .await;
    if scenario.is_err() {
        // Payload-free: identifiers, labels and counters only.
        eprintln!("fs process restart partial evidence: {evidence:?}");
    }

    // The first process is killed inside `exercise`; a bounded reap here covers
    // the paths that failed before reaching that point.
    //
    // `ManagedProcess::shutdown` waits `grace` for the child to exit **on its
    // own** before killing it, and a connector never does, so the grace is
    // deliberately short: the whole call is then bounded by that plus the
    // forced reap, and there is nothing here for an outer deadline to race.
    let stop_first = first.shutdown(STOP_GRACE).await;
    let stop_second = match second_process {
        Some(process) => Some(process.shutdown(STOP_GRACE).await),
        None => None,
    };
    scenario?;
    // A first process that is already dead cannot be shut down again, and that
    // is the expected state, so only the replacement's reaping is load-bearing
    // here.
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
    root: &Path,
    tenant_id: Uuid,
    device_id: Uuid,
    service: Uuid,
    session_id: &str,
    evidence: &mut FsProcessRestartEvidence,
) -> Result<()> {
    // The owner claim, so the gate is speaking to the relay that owns the
    // device rather than to whichever relay answered first, and so the epoch it
    // compares against is the one the cluster agreed on.
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

    // ---------------------------------------------------------------------
    // Session one: established, serving, then held across the process death.
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

    // 1. Serve the session normally first, so a later failure cannot be blamed
    //    on a session that never worked — on the **read** path and, because
    //    this gate's held operation is a mutation, on the **mutation** path
    //    too.
    let mut prefix = 0_usize;
    for _ in 0..PREFIX_READS {
        match session.read(FILE_FID, prefix as u64, READ_COUNT).await? {
            Message::Rread { data } if !data.is_empty() => prefix += data.len(),
            other => return Err(unexpected("a non-empty Rread", &other)),
        }
    }
    evidence.prefix_bytes = prefix;

    // `Tlcreate` rebinds the parent fid to the file it makes, so each create
    // spends a walked clone of the root rather than the session's own root.
    match session
        .walk(ATTACH_FID, SETTLED_FID, &[JOURNAL_DIR])
        .await?
    {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match session
        .call(Message::Tlcreate {
            fid: SETTLED_FID,
            name: SETTLED_ENTRY.to_owned(),
            flags: O_WRONLY,
            mode: 0o644,
            gid: 0,
        })
        .await?
    {
        Message::Rlcreate { .. } => {}
        other => return Err(unexpected("Rlcreate", &other)),
    }
    evidence.journal_entries_before_held = journal_entries(root)?.len();

    // The fid the held mutation will be issued on, walked while everything
    // still flows so the walk itself is not part of the event.
    match session
        .walk(ATTACH_FID, JOURNAL_FID, &[JOURNAL_DIR])
        .await?
    {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }

    // 2. Settle the carrier and pause the data socket's connector→relay bytes,
    //    so a reply cannot settle the exchange before the process dies.
    //
    //    The connector is a child process, so its sockets are identified from
    //    the proxy rather than from a status snapshot.  Both of its connections
    //    arrive here; the control socket is established first, so the data
    //    socket is the later of the two.  A mis-identification cannot pass
    //    silently: pausing the control socket would leave the mutation's reply
    //    flowing, the owner's receive cursor would advance, and step 5's
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
                    "the device carrier never settled before the held mutation".into(),
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
    let mut observation = ProcessRestartObservation {
        stream_id,
        ..ProcessRestartObservation::default()
    };
    {
        let snapshot = owner_snapshot(cluster).await?;
        let owner = session_of(&snapshot, session_id)?;
        let stream = owner
            .streams
            .iter()
            .find(|stream| stream.stream_id == stream_id)
            .ok_or_else(|| {
                HarnessError::Process(
                    "the filesystem stream vanished before the held mutation".into(),
                )
            })?;
        observation.emitted_before = stream.last_emitted_relay_to_connector;
        observation.recv_contiguous_before = stream.recv_contiguous_connector_to_relay;
    }

    // 4. Send one `Tlcreate` and deliberately do not read its reply.  The
    //    request crosses on the still-flowing relay→connector direction, the
    //    device performs it — which is what puts the entry in the journal — and
    //    the connector sequences the `Rlcreate` into the paused socket, where
    //    it stays and is ultimately lost.
    let held_tag = session
        .send(Message::Tlcreate {
            fid: JOURNAL_FID,
            name: HELD_ENTRY.to_owned(),
            flags: O_WRONLY,
            mode: 0o644,
            gid: 0,
        })
        .await?;
    evidence.held_tag = held_tag;

    // 5. Wait for the owner to show the mutation dispatched and unanswered.
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
                let sample = ProcessRestartObservation {
                    emitted_at_kill: stream.last_emitted_relay_to_connector,
                    recv_contiguous_at_kill: stream.recv_contiguous_connector_to_relay,
                    ..observation.clone()
                };
                // Only a sample that actually shows the record dispatched and
                // unanswered ends the wait.
                if sample.request_outstanding_at_kill() {
                    evidence.restart_polls = polls;
                    observation = sample;
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Process(
                    "the held Tlcreate was never observed dispatched and unanswered at the owner"
                        .into(),
                ));
            }
            sleep(POLL).await;
        }
    }
    evidence.request_outstanding_at_kill = observation.request_outstanding_at_kill();
    evidence.restart = observation;

    // 6. **The journal, and the reason this event needed one.**  Wait until the
    //    host directory shows the held create *performed*, so the kill lands
    //    after the effect rather than racing it.  Without this the gate could
    //    kill the process before the mutation reached the device and would then
    //    be measuring a refusal that never dispatched — retryable, and a much
    //    weaker claim than the one the contract is about.
    {
        let deadline = Instant::now() + JOURNAL_WAIT;
        let mut polls = 0_usize;
        loop {
            polls += 1;
            let entries = journal_entries(root)?;
            if entries.iter().any(|name| name == HELD_ENTRY) {
                evidence.journal_polls = polls;
                evidence.held_effect_present_before_kill = true;
                evidence.journal_entries_before_kill = entries.len();
                break;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the held mutation never reached the device: the journal never recorded it, \
                     so this run cannot measure an unknown outcome"
                        .into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    // ---------------------------------------------------------------------
    // The event: the connector's real process is killed.  No unwind, no
    // graceful close, no chance to fail anything on the way out.  The paused
    // direction is deliberately **not** released: the answer this mutation
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
    // under its own control does.  That is the distinction between this event
    // and a graceful stop, and it is read from the status rather than assumed
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
            // that a performed mutation failed is the specific trap this gate
            // exists to exclude.
            // The two are **disjoint**, not nested: an `Rlerror` is recorded
            // as an error and nothing else, a normal reply as an answer and
            // nothing else.  Recording an error as both would make the
            // error rule unreachable behind the answered rule, and a rule that
            // can never be the one to reject anything is not load-bearing.
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

    // The classification, derived rather than asserted.  The journal says the
    // mutation was performed, so it was dispatched; the exchange carried no
    // answer, so whether the effect applied was never reported.  That is
    // exactly `Outcome::Unknown`, and `Outcome::is_settled` — read out of the
    // library — says a caller may not assume it away.
    evidence.held_call_outcome = Some(if !evidence.held_effect_present_before_kill {
        Outcome::NotStarted
    } else if evidence.pending_call_errored {
        // "Dispatched, and the provider reported it made no change."  A settled
        // outcome, and a false one: the journal says otherwise.
        Outcome::Failed
    } else {
        Outcome::Unknown
    });

    // The authoritative catalog must report the owner released, so the second
    // claim is a fresh admission rather than an overlapping one.
    cluster.wait_for_no_owner(tenant_id, device_id).await?;
    evidence.owner_released_between = true;

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
    // The restart: a **new process**, on the same identity and the same export
    // root, from the same configuration file.
    // ---------------------------------------------------------------------
    let (replacement, replacement_session_id) = start_connector_process(
        cluster,
        "m4-fs-process-restart-second",
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

    // ---------------------------------------------------------------------
    // Session two: the contract clause, against the **new process**.  No fid is
    // restored across a process restart, and the same fid numbers are reused so
    // a leak would show.
    // ---------------------------------------------------------------------
    // First the "require fresh version/attach" half of the clause, on its own
    // throwaway session: a replacement session that names the earlier session's
    // file fid *before* attaching is closed rather than served.  `BeforeAttach`
    // is checked before the fid table, which is why this probe needs its own
    // session and why the fid probes below run on an attached one.
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

    // This session attaches on its **own** root fid, so it holds a working root
    // while it probes the earlier session's fid numbers.
    second.attach(SECOND_ROOT_FID).await?;
    evidence.attach_count += 1;
    evidence.second_session_attached = true;

    // The earlier session's file fid must not be bound here.
    match second.getattr(FILE_FID, GETATTR_BASIC).await? {
        Message::Rgetattr(_) => {
            return Err(HarnessError::Process(
                "the earlier session's file fid answered after a connector process restart: the \
                 profile restored a fid across a process restart"
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
    match second
        .walk(ATTACH_FID, SECOND_SCRATCH_FID, &["big.bin"])
        .await?
    {
        Message::Rwalk { .. } => {
            return Err(HarnessError::Process(
                "the earlier session's attach fid walked after a connector process restart: the \
                 profile restored a fid across a process restart"
                    .into(),
            ));
        }
        other => {
            evidence.stale_attach_fid_refused = matches!(other, Message::Rlerror { .. });
            evidence.stale_attach_fid_errno = errno_of(&other);
        }
    }
    // And neither must the fid the outstanding mutation was issued on, which is
    // the one a caller resuming that operation would reach for.
    match second.getattr(JOURNAL_FID, GETATTR_BASIC).await? {
        Message::Rgetattr(_) => {
            return Err(HarnessError::Process(
                "the fid the outstanding mutation was issued on answered after a connector \
                 process restart"
                    .into(),
            ));
        }
        other => {
            evidence.stale_journal_fid_refused = matches!(other, Message::Rlerror { .. });
            evidence.stale_journal_fid_errno = errno_of(&other);
        }
    }

    // ---- the control: a caller that retries the mutation anyway ----------
    //
    // This is the trap in its operational form.  A consumer that read the lost
    // answer as "it never happened" would resubmit, and the question is whether
    // anything below it would let that reach the provider.  It does not: the
    // fid is not allocated in this session, so the session machine refuses the
    // mutation *above* the dispatch boundary with the unknown-fid errno — not
    // an `Eexist` from the host, which would mean the retry got through — and
    // the journal count does not move.
    match second
        .call(Message::Tlcreate {
            fid: JOURNAL_FID,
            name: HELD_ENTRY.to_owned(),
            flags: O_WRONLY,
            mode: 0o644,
            gid: 0,
        })
        .await?
    {
        Message::Rlcreate { .. } => {
            return Err(HarnessError::Process(
                "a retried mutation was performed on a fid from before the process restart".into(),
            ));
        }
        other => {
            evidence.retry_refused_above_dispatch = matches!(other, Message::Rlerror { .. });
            evidence.retry_refusal_errno = errno_of(&other);
        }
    }
    evidence.journal_entries_after_retry = journal_entries(root)?.len();

    // The journal as the replacement session sees it over 9P, so the host's
    // view and the export's view have to agree.
    match second
        .walk(SECOND_ROOT_FID, SECOND_JOURNAL_FID, &[JOURNAL_DIR])
        .await?
    {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match second.lopen(SECOND_JOURNAL_FID, O_RDONLY).await? {
        Message::Rlopen { .. } => {}
        other => return Err(unexpected("Rlopen", &other)),
    }
    {
        let mut names: Vec<String> = Vec::new();
        let mut offset = 0_u64;
        loop {
            match second
                .readdir(SECOND_JOURNAL_FID, offset, READ_COUNT)
                .await?
            {
                Message::Rreaddir { data } => {
                    if data.is_empty() {
                        break;
                    }
                    let entries = tunnel_fs_ninep::parse_entries(&data).map_err(|error| {
                        HarnessError::Process(format!("malformed Rreaddir block: {error}"))
                    })?;
                    if entries.is_empty() {
                        break;
                    }
                    for entry in &entries {
                        offset = entry.offset;
                        if entry.name != "." && entry.name != ".." {
                            names.push(entry.name.clone());
                        }
                    }
                }
                other => return Err(unexpected("Rreaddir", &other)),
            }
        }
        names.sort();
        names.dedup();
        evidence.journal_entries_over_ninep = names.len();
    }

    // **The effect count, read from the host directory, across both process
    // generations.**  Two would be the "unknown outcome read as not dispatched"
    // trap arriving through a process restart.
    let final_entries = journal_entries(root)?;
    evidence.journal_entries_final = final_entries.len();
    evidence.held_effect_exactly_once = final_entries
        .iter()
        .filter(|name| *name == HELD_ENTRY)
        .count()
        == 1;

    // The export answers normally on this session's own root, so the refusals
    // above are fid scoping — and not a replacement process that never served
    // this export at all.  Binding FILE_FID here, fresh, is also the other half
    // of the contract: the *number* is reusable once the session that held it
    // is gone.
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

    let mut transferred: Vec<u8> = Vec::with_capacity(RESTART_FILE_BYTES);
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
        fnv1a(&transferred) == fnv1a(&synthetic_bytes(RESTART_FILE_BYTES));

    second.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> FsProcessRestartEvidence {
        FsProcessRestartEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: 65_536,
            negotiated_dialect: DIALECT.into(),
            prefix_bytes: 196_575,
            journal_entries_before_held: 1,
            restart: ProcessRestartObservation {
                stream_id: 1,
                emitted_before: 4,
                emitted_at_kill: 5,
                recv_contiguous_before: 4,
                recv_contiguous_at_kill: 4,
            },
            request_outstanding_at_kill: true,
            restart_polls: 3,
            held_tag: 7,
            journal_entries_before_kill: EXPECTED_JOURNAL_ENTRIES,
            held_effect_present_before_kill: true,
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
            pre_attach_probe_close_code: Some(PROTOCOL_VIOLATION_CLOSE),
            pre_attach_probe_answered: false,
            second_session_msize: 65_536,
            stale_file_fid_refused: true,
            stale_file_fid_errno: Some(UNKNOWN_FID_ERRNO),
            stale_attach_fid_refused: true,
            stale_attach_fid_errno: Some(UNKNOWN_FID_ERRNO),
            stale_journal_fid_refused: true,
            stale_journal_fid_errno: Some(UNKNOWN_FID_ERRNO),
            retry_refused_above_dispatch: true,
            retry_refusal_errno: Some(UNKNOWN_FID_ERRNO),
            journal_entries_after_retry: EXPECTED_JOURNAL_ENTRIES,
            second_session_attached: true,
            journal_entries_over_ninep: EXPECTED_JOURNAL_ENTRIES,
            journal_entries_final: EXPECTED_JOURNAL_ENTRIES,
            held_effect_exactly_once: true,
            second_session_bytes: RESTART_FILE_BYTES,
            second_session_expected_bytes: RESTART_FILE_BYTES,
            second_session_checksum_matches: true,
            second_session_messages: 12,
            second_session_getattr_size: RESTART_FILE_BYTES as u64,
            attach_count: 2,
        }
    }

    #[test]
    fn an_unknown_outcome_is_not_settled_and_a_failed_one_is() {
        // The distinction the whole gate turns on, held against the library
        // rather than against this file's own reading of it.  If `Outcome`ever
        // made `Unknown` settled, the gate's central rule would become
        // satisfiable by the very report it exists to forbid, and this test is
        // what would fail first.
        assert!(!Outcome::Unknown.is_settled());
        assert!(Outcome::Failed.is_settled());
        assert!(Outcome::NotStarted.is_settled());
        // And the ordering that stops a later observation weakening an earlier
        // one: a mutation once seen as `Unknown` can never be reported as
        // `NotStarted` again.
        assert_eq!(
            Outcome::Unknown.merge(Outcome::NotStarted),
            Outcome::Unknown
        );
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_fs_process_restart_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsProcessRestartEvidence));
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
            ("the mutation path never worked first", |e| {
                e.journal_entries_before_held = 0;
            }),
            // The concurrency rules.
            ("the mutation was never dispatched", |e| {
                e.restart.emitted_at_kill = e.restart.emitted_before;
            }),
            ("the reply had already been received", |e| {
                e.restart.recv_contiguous_at_kill = e.restart.recv_contiguous_before + 1;
            }),
            ("the in-flight summary contradicts its sample", |e| {
                e.request_outstanding_at_kill = false;
            }),
            ("no stream was identified", |e| e.restart.stream_id = 0),
            // The journal rules.
            ("the effect had not happened before the kill", |e| {
                e.held_effect_present_before_kill = false;
            }),
            // The retry rule compares against this field, so a mutation that
            // moved it alone would be rejected by that rule instead and would
            // leave this one masked.  Both move together, so the named rule is
            // the only one left to reject it.
            (
                "the journal did not hold both effects at the kill, with the retry count \
                 consistent",
                |e| {
                    e.journal_entries_before_kill = 1;
                    e.journal_entries_after_retry = 1;
                },
            ),
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
                e.epoch_after = e.epoch_before
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
                e.pending_call_close_code = Some(PROTOCOL_VIOLATION_CLOSE);
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
                "a performed mutation was reported to the caller as an error",
                |e| e.pending_call_errored = true,
            ),
            (
                "a performed mutation was reported as an error and classified to match",
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
                "the outcome was classified as never dispatched, which the journal contradicts",
                |e| e.held_call_outcome = Some(Outcome::NotStarted),
            ),
            (
                "the outcome was classified as partial, which is neither what happened nor \
                 unknown",
                |e| e.held_call_outcome = Some(Outcome::Partial),
            ),
            ("the outcome was never classified at all", |e| {
                e.held_call_outcome = None;
            }),
            ("the held stream was never deregistered", |e| {
                e.held_stream_deregistered = false;
            }),
            // The contract clause proper.
            ("the pre-attach probe was not closed", |e| {
                e.pre_attach_probe_close_code = None;
            }),
            ("the pre-attach probe was closed with the wrong code", |e| {
                e.pre_attach_probe_close_code = Some(DEVICE_GONE_CLOSE);
            }),
            ("the pre-attach probe was answered", |e| {
                e.pre_attach_probe_answered = true;
            }),
            ("the replacement session negotiated no msize", |e| {
                e.second_session_msize = 0;
            }),
            ("the replacement session msize above the ceiling", |e| {
                e.second_session_msize = OFFERED_MSIZE + 1;
            }),
            ("the replacement session never attached", |e| {
                e.second_session_attached = false;
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
            ("the stale attach fid was not refused", |e| {
                e.stale_attach_fid_refused = false;
            }),
            ("the stale attach fid refusal carried another errno", |e| {
                e.stale_attach_fid_errno = Some(UNKNOWN_FID_ERRNO + 1);
            }),
            ("the stale mutation fid was not refused", |e| {
                e.stale_journal_fid_refused = false;
            }),
            (
                "the stale mutation fid refusal carried another errno",
                |e| {
                    e.stale_journal_fid_errno = Some(UNKNOWN_FID_ERRNO + 1);
                },
            ),
            // The control.
            ("the retry was not refused", |e| {
                e.retry_refused_above_dispatch = false;
            }),
            (
                "the retry was refused by the host rather than above the dispatch boundary",
                |e| e.retry_refusal_errno = Some(tunnel_fs_core::FsErrorCode::Eexist.errno()),
            ),
            ("the refused retry moved an effect anyway", |e| {
                e.journal_entries_after_retry = EXPECTED_JOURNAL_ENTRIES + 1;
            }),
            // The measurement.
            ("the effect happened twice", |e| {
                e.journal_entries_final = EXPECTED_JOURNAL_ENTRIES + 1;
                e.journal_entries_over_ninep = EXPECTED_JOURNAL_ENTRIES + 1;
            }),
            ("the effect never happened", |e| {
                e.journal_entries_final = 1;
                e.journal_entries_over_ninep = 1;
            }),
            ("the held effect appears more than once", |e| {
                e.held_effect_exactly_once = false;
            }),
            ("the two views of the journal disagree", |e| {
                e.journal_entries_over_ninep = EXPECTED_JOURNAL_ENTRIES + 1;
            }),
            // The refusals were fid scoping and not a broken export.
            ("a short transfer", |e| e.second_session_bytes -= 1),
            ("an expected size that is not the fixture's", |e| {
                e.second_session_expected_bytes = RESTART_FILE_BYTES - 1;
                e.second_session_bytes = RESTART_FILE_BYTES - 1;
            }),
            ("a checksum mismatch", |e| {
                e.second_session_checksum_matches = false;
            }),
            ("a single-message transfer", |e| {
                e.second_session_messages = MIN_READ_MESSAGES;
            }),
            ("the file changed size", |e| {
                e.second_session_getattr_size = RESTART_FILE_BYTES as u64 - 1;
            }),
            ("an extra Tattach", |e| e.attach_count = 3),
            ("a missing Tattach", |e| e.attach_count = 1),
        ];
        for (label, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_fs_process_restart_evidence(&evidence).is_err(),
                "mutation `{label}` must be rejected"
            );
        }
    }

    #[test]
    fn the_in_flight_predicate_needs_both_halves() {
        // The predicate itself, defeated in each direction.  Without these the
        // composite rule could be satisfied by a sample that shows only one of
        // the two facts.
        let outstanding = ProcessRestartObservation {
            stream_id: 1,
            emitted_before: 4,
            emitted_at_kill: 5,
            recv_contiguous_before: 4,
            recv_contiguous_at_kill: 4,
        };
        assert!(outstanding.request_outstanding_at_kill());
        assert!(
            !ProcessRestartObservation {
                emitted_at_kill: 4,
                ..outstanding.clone()
            }
            .request_outstanding_at_kill(),
            "a record that was never dispatched is not outstanding"
        );
        assert!(
            !ProcessRestartObservation {
                recv_contiguous_at_kill: 5,
                ..outstanding
            }
            .request_outstanding_at_kill(),
            "a record that was already answered is not outstanding"
        );
    }
}
