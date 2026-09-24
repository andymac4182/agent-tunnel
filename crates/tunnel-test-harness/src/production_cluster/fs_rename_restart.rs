//! A live 9P2000.L filesystem session holding a **`Trename`** outstanding
//! while the connector's **real operating-system process is killed and a
//! replacement process is started**, over the real cluster: a consumer WSS
//! session through the owning relay's public route, the owner actor, the
//! device data WebSocket and a `tunnel-client` **child process** serving a
//! filesystem export from a real host directory.
//!
//! # The clause
//!
//! `docs/protocol.md`'s flush paragraph names two operations and two events:
//!
//! > If a **write or rename** outcome becomes ambiguous after a transport or
//! > **process failure**, the just-bash adapter reports that ambiguity and
//! > does not blindly resubmit the operation in the new session.
//!
//! Gate 10 (`verify-m4-fs-process-restart`) drives the process failure on a
//! `Tlcreate`.  Gate 13 (`verify-m4-fs-write-restart`) drives it on a
//! `Twrite` and closed the write half.  This gate is the **rename** half, and
//! it is the last operation the sentence names.
//!
//! # Why this is not a second copy of gate 10, contrary to the reasoning that
//! # deferred it
//!
//! Gate 13's module recorded its choice of a `Twrite` this way: a `Trename`'s
//! effect "is therefore a **namespace** effect that either happened or did
//! not — structurally the same evidence shape as gate 10's directory entry,
//! down to counting names in a host directory."
//!
//! That reasoning was re-derived here rather than inherited, and it does not
//! survive contact with either gate's instrument — though the first version
//! of *this* paragraph overstated the case and is corrected here.  **Five of
//! gate 10's six journal rules are counts, and the sixth is one-sided.**
//! Read out of `fs_process_restart.rs` rather than from the row's summary:
//!
//! ```text
//! journal_entries_before_held == 1
//! journal_entries_before_kill == EXPECTED_JOURNAL_ENTRIES
//! journal_entries_after_retry == journal_entries_before_kill
//! journal_entries_final       == EXPECTED_JOURNAL_ENTRIES
//! journal_entries_over_ninep  == journal_entries_final
//! held_effect_exactly_once                      // per name, not a count
//! ```
//!
//! A rename within one directory removes one name and creates one, so it
//! holds all five counts fixed: they are invariant across the very operation
//! being measured.  The sixth, `held_effect_exactly_once`, *is* per name — it
//! filters the final listing for `HELD_ENTRY` and requires exactly one — so
//! the honest claim is not "gate 10 has no per-name rule" but that its one
//! per-name rule **only ever looks at the name that appears**.
//!
//! That is what a rename needs and does not get.  A rename is **two-sided**:
//! a name appears *and* a name vanishes, and backend atomicity is a promise
//! about the two together.  Gate 10's rule would see the destination arrive
//! and would say nothing at all about the source still being there — so
//! [`NamespaceState::BothPresent`], the exact state a copy-then-unlink leaves
//! behind, satisfies it.  This gate's classifier reads **both** names and
//! rejects that state.  The gap the sixth rule does not close is the whole
//! reason this module exists, and it leaves the inode rule, the errno-origin
//! control and the forbidden-intermediate rule without any counterpart.  This gate measures the
//! namespace **per name**, and it records the count beside it precisely so
//! that the blindness is a measured fact of the run rather than an assertion
//! in a comment: see [`FsRenameRestartEvidence::entry_count_instrument_was_blind`].
//!
//! The deeper point is that backend atomicity — the property invoked to
//! dismiss the rename — is what makes it *worth* driving:
//!
//! * `docs/filesystem-api.md` says "Native in-filesystem rename is the **only**
//!   baseline single namespace operation with backend atomicity; it is not a
//!   multi-file transaction or durability promise", and its `rename` row says
//!   "Native in-export rename ...; **do not substitute copy/delete**."
//! * A `Twrite` has **no** such promise, which is why gate 13 must *admit*
//!   its intermediate state: a `Torn` region is permitted, and narrowing the
//!   rule to `Written` would assert something the contract withholds.
//! * A rename's intermediate states — both names present, or neither — are
//!   the ones the promise **forbids**.
//!
//! So the same event lands opposite obligations on the two operations, and
//! that single sentence at `docs/filesystem-api.md` is what separates them.
//! Gate 10's `Tlcreate` has no intermediate state to take a position on
//! either way, because a create has only one side.
//!
//! # What this gate can prove that gates 10 and 13 could not
//!
//! ## The errno becomes proof of origin rather than corroboration
//!
//! Gate 13 recorded, correctly, that the errno on a refused retry is weak
//! evidence: a session-level unknown-fid refusal carries `Einval`, and
//! `tunnel_fs_host::policy` maps every errno it does **not** recognise to
//! `Einval` as well, so the value alone cannot say whether the refusal came
//! from above the dispatch boundary or from the host.  Gate 13 therefore had
//! to carry the claim on the file's modification time instead.
//!
//! A rename does not have that problem, and the reason was re-derived from
//! the mapping itself.  `tunnel_fs_host::policy::code_from_errno` maps
//! `Errno::NOENT` to [`tunnel_fs_core::FsErrorCode::Enoent`] — a **distinct,
//! recognised** code, not folded into `Einval`.  And a rename is not
//! idempotent: once the held rename has moved `source.bin` away, the identical
//! operation reaching the host again finds no source and the host's
//! `renameat` returns `ENOENT`.
//!
//! That gives this gate a discriminator with two *different* readings on the
//! same instrument, in the same run, on the same names:
//!
//! * The retry issued on the **stale** fid from before the restart is refused
//!   above the dispatch boundary and carries [`UNKNOWN_FID_ERRNO`] (`Einval`).
//! * The **same rename**, issued on a **valid, freshly bound** fid in the same
//!   replacement session, reaches the host and carries [`ABSENT_SOURCE_ERRNO`]
//!   (`Enoent`).
//!
//! The second is this gate's **positive control for the errno instrument**,
//! and it is what upgrades the first from corroboration to proof of origin: a
//! channel that answered `Einval` no matter what would fail it.  It is the
//! same discipline gate 13 applied to `mtime`, applied to the measurement
//! gate 13 had to give up on.
//!
//! **The two readings travel the same host path, and that was re-derived
//! rather than assumed.**  `tunnel_fs_provider`'s dispatcher sends both
//! `Message::Trename` and `Message::Trenameat` to the same `perform_rename`,
//! which calls the same `ExportRoot::rename_checked`, which calls one
//! `rustix::fs::renameat`.  The opcodes differ only in how the endpoints are
//! named — by fid, or by name in a directory — and the control uses the
//! name-addressed form because that is the only one that can present the host
//! with a source that is absent.
//!
//! ## The rename is proven native **over the wire and across the kill**
//!
//! "Do not substitute copy/delete" is measurable because a `renameat` moves a
//! **name** and leaves the **inode** alone, while a copy-then-unlink produces
//! a new one.  So [`FsRenameRestartEvidence::rename_preserved_the_inode`]
//! reads the source's inode before the held rename and the destination's
//! after it, and requires them equal.  Its instrument is controlled the way
//! everything else here is: two genuinely different files must report two
//! different inodes
//! ([`FsRenameRestartEvidence::inode_instrument_discriminates`]), so a reader
//! that returned a constant cannot satisfy the rule by standing still.
//!
//! **This is not the first time that substitution has been measured, and an
//! earlier draft of this paragraph claimed it was.**  `identity_survives_a_rename`
//! in `crates/tunnel-fs-host/tests/identity_and_aliasing.rs` already drives
//! `ExportRoot::rename` and asserts `Identity::is_same_file`, which is
//! `device == device && inode == inode`, plus an equal `qid_path`.  At the
//! host crate, on a direct call, the property is covered.
//!
//! What this gate adds is the part that unit test cannot reach, and the claim
//! is narrowed to exactly that: the same property **over the 9P wire, through
//! the relay, across a `SIGKILL` of the connector's process, and read from
//! the export's own host directory by the harness rather than through the
//! code under test**.  The unit test calls the function and asks the function
//! what happened; this asks the filesystem, after the process that called it
//! is gone.  A rename reimplemented as a copy and an unlink would redden both
//! — and only this one would also catch it being reimplemented somewhere
//! between the consumer session and `ExportRoot`.
//!
//! ## The ambiguity is two-valued, and the post-state is self-describing
//!
//! Gate 13's caller is told `Unknown` and cannot resolve it: bytes at an
//! offset do not say who put them there.  A rename's post-state **does**: a
//! later session that looks can see which of the two states obtains.  So the
//! derivation here can distinguish a genuinely undispatched rename
//! ([`Outcome::NotStarted`], settled and retryable) from a performed one
//! whose answer was destroyed ([`Outcome::Unknown`], not settled), from the
//! host's namespace rather than from a timeout — and the replacement
//! session's own `Trenameat` control witnesses the same fact from **inside**
//! the export, over 9P.
//!
//! What the caller may do with that is still constrained, and that is the
//! clause: it may **look**, and it may not **blindly resubmit**.
//!
//! # What the contract does **not** say, recorded rather than invented
//!
//! Nothing requires a rename interrupted by a process death to be completed,
//! rolled back, or reported as half-done — every obligation is about what the
//! caller is told and about not resubmitting.  `docs/cluster.md` requires the
//! owner to preserve the ambiguity and not retry automatically;
//! `docs/tcp-connect.md` says of the same situation on another transport to
//! "preserve certainty as unknown" and not replay.  This gate asserts what
//! those sentences license and no more.
//!
//! # Recorded boundaries, because the alternative is evidence that claims
//! # more than it proves
//!
//! 1. **The forbidden intermediate states are classified but not
//!    manufactured.**  [`NamespaceState::BothPresent`] and
//!    [`NamespaceState::NeitherPresent`] are what a non-atomic rename would
//!    leave behind, and the validator rejects them wherever it samples.  But
//!    `renameat` is a single syscall and a `SIGKILL` destroys a process, not
//!    the kernel mid-syscall, so this harness cannot produce either state on
//!    demand — exactly as gate 13 cannot produce a `Torn` region.  The
//!    classifier's ability to *report* them is held in both directions by
//!    unit tests, the validator's refusal of them is defeated by the
//!    guard-deletion suite, and **no run measured here observed one**.  That
//!    is stated here rather than left for a reader to discover.
//! 2. **"Exactly once" is claimed, and this is the one place it can be.**  A
//!    `Twrite` names an offset and is byte-for-byte idempotent, which is why
//!    gate 13 recorded that it could not claim it.  A rename is not: a second
//!    application cannot find its source.  So the namespace itself carries
//!    the no-resubmission claim here, and the `Enoent` control is what shows
//!    a resubmission that *did* get through would have been visible.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use tokio::time::{Instant, sleep, timeout};
use tunnel_fs_core::Outcome;
use tunnel_fs_ninep::{GETATTR_BASIC, Message, flags::O_RDONLY};
use uuid::Uuid;

use super::fs_rotation_write::payload_bytes;
use super::fs_wire as wire;
use wire::{NinepClient, Target, UpgradeFailure, errno_of, unexpected};

use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot};

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

/// The errno a rename whose **source name does not exist** carries back from
/// the host.
///
/// Derived, not pinned, and it is the whole reason this gate's refusal
/// evidence is stronger than gate 13's: `tunnel_fs_host::policy::code_from_errno`
/// maps `Errno::NOENT` to [`tunnel_fs_core::FsErrorCode::Enoent`] rather than
/// folding it into `Einval` the way it folds everything it does not
/// recognise.  So this value and [`UNKNOWN_FID_ERRNO`] are **distinguishable**,
/// and a refusal can be attributed to one side of the dispatch boundary or
/// the other rather than merely being consistent with both.
const ABSENT_SOURCE_ERRNO: u32 = tunnel_fs_core::FsErrorCode::Enoent.errno();

/// The close code the held exchange's session is ended with when the process
/// that was serving it is killed.
///
/// Derived, not pinned: from the consumer side a dead connector process is
/// the profile's "the export's backend is the thing that went away", and the
/// gate asserts the expression rather than the number `close_code()` maps it
/// to at this revision.
const DEVICE_GONE_CLOSE: u16 = match tunnel_fs_core::SessionErrorCode::DeviceOffline.close_code() {
    Some(code) => code,
    // Unreachable: `close_code()` returns `Some` for this variant.
    None => panic!("DeviceOffline must carry a close code"),
};

/// The name the held rename moves **from**.
const SOURCE_NAME: &str = "source.bin";
/// The name the held rename moves **to**.
const DESTINATION_NAME: &str = "destination.bin";
/// The name the control rename — the journal's positive direction, performed
/// and acknowledged normally before anything is perturbed — moves from.
const CONTROL_SOURCE_NAME: &str = "control-source.bin";
/// The name that control rename moves to.
const CONTROL_DESTINATION_NAME: &str = "control-destination.bin";

/// How many bytes each of the two files holds.
///
/// Large enough that the replacement session's read of the renamed file needs
/// more than one `Rread`, so "the export still serves this file" is a fact
/// about a real transfer rather than about a single-frame special case.
const FILE_BYTES: usize = 262_144;

/// The replacement session's transfer must need more than this many `Rread`
/// messages.
const MIN_READ_MESSAGES: usize = 3;

/// How many names the export root holds, at every instant this gate samples
/// it.
///
/// **This constant is the argument of the module header made measurable.**  A
/// rename inside one directory removes one name and creates one name, so a
/// count is the same before and after the operation.  Gate 10's journal rules
/// are counts; this gate records that they would have seen nothing here.
const EXPECTED_ENTRY_COUNT: usize = 2;

/// How many reads the session performs before anything is perturbed,
/// establishing that it serves normally first.
const PREFIX_READS: usize = 2;

/// The fid numbers the first session binds, and which the replacement session
/// then probes.
///
/// The replacement session deliberately reuses these exact numbers: the
/// contract clause is that no fid is restored across a process restart, and
/// reusing the numbers is what makes a leak observable instead of merely
/// unlikely.
const ATTACH_FID: u32 = 0;
const SOURCE_FID: u32 = 1;
const CONTROL_FID: u32 = 2;

/// The root fid the replacement session attaches on.
///
/// Deliberately none of the above: the replacement session has to hold a
/// working root while it probes the earlier session's fid numbers, and if it
/// attached on one of them then a probe of that number would be answering
/// from this session's own binding rather than showing the absence of the
/// earlier one.
const SECOND_ROOT_FID: u32 = 5;
/// A fresh fid the replacement session binds the renamed file on.
const SECOND_FILE_FID: u32 = 6;

/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for a cluster state change.
const WAIT: Duration = Duration::from_secs(30);
/// A bounded wait for the killed pid to be reaped.
const EXIT_WAIT: Duration = Duration::from_secs(30);
/// How long the host directory is given to show the held rename performed.
///
/// Bounded: a run that reaches this deadline has **not** found a defect, it
/// has failed to set up the measurement — the rename never reached the device
/// — and the gate says so rather than killing the process anyway and
/// reporting a `NotStarted` as though it were an `Unknown`.
const JOURNAL_WAIT: Duration = Duration::from_secs(30);
/// How long the held consumer socket is given to be failed explicitly.
///
/// Bounded, and **this bound is evidence**: the derivation below reads the
/// *absence* of a reply, so every way the answer can be lost has to reach it
/// rather than hang to the scenario deadline.
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
/// cleanup cost rather than a real grace.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// How the export root's namespace reads, per name.
///
/// **Per name, and never as a count.**  The two names a rename moves between
/// are read separately, because the only instrument that can see a rename in
/// one directory is one that distinguishes *which* names are present.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NamespaceState {
    /// The directory could not be read, so nothing was measured.
    ///
    /// Distinct from every other value on purpose: a failed measurement must
    /// never be reported as one of the meaningful states, which is how a rule
    /// comes to hold because nothing was observed.
    #[default]
    Unreadable,
    /// The source is present and the destination is absent: the rename has
    /// not been performed.
    BeforeRename,
    /// The source is absent and the destination is present: the rename has
    /// been performed.
    AfterRename,
    /// **Both names present.**  Forbidden by backend atomicity: it is what a
    /// copy that has not yet unlinked its source looks like from outside.
    BothPresent,
    /// **Neither name present.**  Forbidden for the same reason: it is what
    /// an unlink that has not yet created its destination looks like.
    NeitherPresent,
}

impl NamespaceState {
    /// A short label for diagnostics.  Payload-free.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::BeforeRename => "before-rename",
            Self::AfterRename => "after-rename",
            Self::BothPresent => "both-present",
            Self::NeitherPresent => "neither-present",
        }
    }

    /// Whether this state is one backend atomicity forbids.
    ///
    /// `Unreadable` is deliberately **not** counted here: it means the
    /// measurement failed, which is a different finding from observing a
    /// namespace caught between two states, and folding them together would
    /// let a failed read be reported as an atomicity violation.
    #[must_use]
    pub fn is_forbidden_intermediate(self) -> bool {
        matches!(self, Self::BothPresent | Self::NeitherPresent)
    }
}

/// Classify the export root's namespace from the names it holds.
///
/// A free function over the names rather than over a path, so the unit tests
/// drive the **same** expression the run does, in all five directions,
/// including the two the harness cannot produce against a real filesystem.
#[must_use]
pub fn classify_namespace(entries: &[String], source: &str, destination: &str) -> NamespaceState {
    let has_source = entries.iter().any(|entry| entry == source);
    let has_destination = entries.iter().any(|entry| entry == destination);
    match (has_source, has_destination) {
        (true, false) => NamespaceState::BeforeRename,
        (false, true) => NamespaceState::AfterRename,
        (true, true) => NamespaceState::BothPresent,
        (false, false) => NamespaceState::NeitherPresent,
    }
}

/// What the owner recorded about the stream the session was held on.
///
/// Payload-free: sequences, identifiers and lifecycle bits only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RenameRestartObservation {
    /// The consumer stream the filesystem session ran on.
    pub stream_id: u64,
    /// The owner's relay→connector emit cursor for this stream, sampled while
    /// the reverse direction was already paused and before the held rename.
    pub emitted_before: u64,
    /// The same cursor at the instant the process was killed.  It must have
    /// advanced: the relay dispatched the rename toward the device.
    pub emitted_at_kill: u64,
    /// The owner's contiguous connector→relay receive cursor for this stream,
    /// sampled at the same instant as [`Self::emitted_before`].
    pub recv_contiguous_before: u64,
    /// The same cursor at the instant of the kill.  It must **not** have
    /// advanced: no answer to that rename had reached the owner.
    pub recv_contiguous_at_kill: u64,
}

impl RenameRestartObservation {
    /// Whether this sample shows a 9P rename the relay had dispatched and had
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
pub struct FsRenameRestartEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    /// The negotiated session parameters, so a run cannot pass on a session
    /// that never reached 9P.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub negotiated_dialect: String,

    /// Bytes read on the source fid **before** anything was perturbed.
    pub prefix_bytes: usize,

    // ---- The journal's two directions, established before the event. ----
    /// The held pair's namespace **before** the held rename was sent.  Must
    /// be [`NamespaceState::BeforeRename`]: the negative direction.
    pub held_namespace_before_send: NamespaceState,
    /// The control pair's namespace before its rename.  Must also be
    /// [`NamespaceState::BeforeRename`].
    pub control_namespace_before: NamespaceState,
    /// The control pair's namespace after a normal acknowledged rename.  Must
    /// be [`NamespaceState::AfterRename`]: the positive direction, which is
    /// what stops the classifier being a rule that can only say one thing.
    pub control_namespace_after: NamespaceState,

    // ---- The inode instrument: "do not substitute copy/delete". ----
    /// The source file's inode before the held rename.
    pub source_inode_before: Option<u64>,
    /// The destination file's inode after it.  Must be the same number: a
    /// `renameat` moves a name and leaves the inode alone, and a
    /// copy-then-unlink does not.
    pub destination_inode_after: Option<u64>,
    /// The control pair's inodes, which must likewise match each other.
    pub control_source_inode: Option<u64>,
    pub control_destination_inode: Option<u64>,

    // ---- The rename held across the kill. ----
    /// The owner's sample either side of the kill.
    pub restart: RenameRestartObservation,
    /// Whether that sample proves the rename was outstanding at the kill.
    pub request_outstanding_at_kill: bool,
    /// How many polls the outstanding state took to observe, for diagnosis.
    pub restart_polls: usize,
    /// The tag that was outstanding when the process was killed.
    pub held_tag: u16,
    /// The held pair's namespace at the instant before the kill.  Must be
    /// [`NamespaceState::AfterRename`]: the rename reached the device.
    pub held_namespace_before_kill: NamespaceState,
    /// How many polls the effect took to appear, for diagnosis.
    pub journal_polls: usize,
    /// Whether any sample taken across the whole run read as a state backend
    /// atomicity forbids.
    ///
    /// **Recorded boundary:** nothing in this harness can make this true on
    /// demand — `renameat` is one syscall and a `SIGKILL` cannot interrupt it
    /// — so this is the rename analogue of gate 13's `Torn` branch.  The rule
    /// below is still written, because it is what would redden if a rename
    /// ever stopped being native, and the classifier's ability to report
    /// those states is held in both directions by unit tests.
    pub forbidden_intermediate_observed: bool,

    // ---- The count instrument, recorded to show it sees nothing. ----
    /// Names in the export root before the held rename.
    pub entry_count_before: usize,
    /// Names in it after.  **Equal, by construction**: this is the measured
    /// form of the module header's argument that gate 10's count-based
    /// journal is blind to a rename.
    pub entry_count_after: usize,

    // ---- The event itself: a real operating-system process, really killed.
    /// The first connector process's pid.
    pub first_pid: u32,
    /// Whether that pid actually exited.
    pub first_process_exited: bool,
    /// Whether it exited on a signal rather than under its own control.
    pub first_process_killed_by_signal: bool,
    /// The replacement connector process's pid.  It must differ.
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
    /// Whether the held rename was instead **answered** across the restart.
    pub pending_call_answered: bool,
    /// Whether the held tag came back as an `Rlerror`.  The trap in its exact
    /// form: an `Rlerror` on a rename the host namespace proves happened
    /// would tell a caller it failed — `Outcome::Failed`, which **is**
    /// settled — and a caller acting on that may assume no side effect
    /// occurred and reissue it.
    pub pending_call_errored: bool,
    /// How the held rename classifies, derived from the host namespace and
    /// the exchange rather than asserted.
    ///
    /// `None` means the run never reached the classification, which is not
    /// the same as classifying it weakly and is rejected by its own rule.
    pub held_call_outcome: Option<Outcome>,
    /// The first session's stream is deregistered at the owner.
    pub held_stream_deregistered: bool,

    // ---- "does not blindly resubmit", observed on the namespace. ----
    /// The held pair's namespace after the replacement process has claimed
    /// the device and before any 9P traffic reaches it.
    pub held_namespace_after_restart: NamespaceState,
    /// Whether probing the earlier session's source fid, on an **attached**
    /// replacement session, was refused rather than answered.
    pub stale_source_fid_refused: bool,
    pub stale_source_fid_errno: Option<u32>,
    /// Whether re-issuing the held `Trename` on the fid it was originally
    /// issued on is refused *above* the dispatch boundary.
    pub retry_refused_above_dispatch: bool,
    /// The errno that refusal carried.  [`UNKNOWN_FID_ERRNO`].
    pub retry_refusal_errno: Option<u32>,
    /// The held pair's namespace after that retry.
    pub held_namespace_after_retry: NamespaceState,

    /// **The positive control for the errno instrument.**
    ///
    /// The same rename, issued on a **valid, freshly bound** directory fid in
    /// the replacement session, naming the same absent source.  It reaches
    /// the host, whose `renameat` finds no source, and it must carry
    /// [`ABSENT_SOURCE_ERRNO`].
    ///
    /// Without this, [`Self::retry_refusal_errno`] is a rule that can only
    /// ever read one value, and an errno channel that answered `Einval`
    /// regardless would satisfy it while proving nothing.  With it, the two
    /// refusals are *different readings of the same instrument*, which is
    /// what makes the retry's value evidence about **where** it was refused
    /// rather than merely consistent with the claim.
    pub absent_source_control_refused: bool,
    pub absent_source_control_errno: Option<u32>,
    /// The namespace after that control, which must still be unchanged: the
    /// control fails, so it must mutate nothing.
    pub held_namespace_after_control: NamespaceState,

    // ---- The replacement session serves the same export. ----
    pub second_session_msize: u32,
    pub second_session_attached: bool,
    /// The renamed file, read back whole on the replacement session.
    pub second_session_bytes: usize,
    pub second_session_expected_bytes: usize,
    pub second_session_messages: usize,
    /// Whether those bytes are exactly the ones the source file held before
    /// the rename: the name moved and the content came with it.
    pub renamed_content_matches: bool,
    /// The file the replacement session sees is the size it always was.
    pub second_session_getattr_size: u64,
    /// The export's own `Treaddir` view of the root, classified the same way
    /// the host's is — so the host's namespace and the export's agree.
    pub namespace_over_ninep: NamespaceState,
    /// Whether walking the **source** name on the replacement session is
    /// refused: the name is genuinely gone from inside the export too.
    pub source_name_walk_refused: bool,
    /// `Tattach` count across the whole run: one per attached session, two in
    /// total, and never a third that would mean a session was reconstructed.
    pub attach_count: usize,
}

impl FsRenameRestartEvidence {
    /// Whether the host namespace discriminated the two rename states **in
    /// this run**, in both directions.
    ///
    /// Without both, the journal is a classifier that can only ever say one
    /// thing and the classification of the held rename rests on nothing.
    ///
    /// **Written as an array rather than as a `&&` chain, and that is
    /// load-bearing**, for gate 11's reason: as a chain the head conjunct
    /// carries no `&&` and so does not match the one edit shape the
    /// guard-deletion suite keys on, which leaves exactly one conjunct the
    /// suite cannot defeat.  Every element here has an identical shape.
    #[must_use]
    pub fn journal_discriminated_both_directions(&self) -> bool {
        let directions = [
            self.held_namespace_before_send == NamespaceState::BeforeRename,
            self.control_namespace_before == NamespaceState::BeforeRename,
            self.control_namespace_after == NamespaceState::AfterRename,
        ];
        directions.into_iter().all(|held| held)
    }

    /// Whether the rename moved a **name** and left the **inode** alone.
    ///
    /// This is `docs/filesystem-api.md`'s "do not substitute copy/delete",
    /// measured rather than trusted.  Both samples must be readable: two
    /// `None`s compare equal, and a rule that holds because nothing was
    /// measured is not evidence.
    #[must_use]
    pub fn rename_preserved_the_inode(&self) -> bool {
        matches!(
            (self.source_inode_before, self.destination_inode_after),
            (Some(before), Some(after)) if before == after
        )
    }

    /// Whether the control rename likewise preserved its inode.
    #[must_use]
    pub fn control_rename_preserved_the_inode(&self) -> bool {
        matches!(
            (self.control_source_inode, self.control_destination_inode),
            (Some(before), Some(after)) if before == after
        )
    }

    /// **The positive control for the inode instrument.**
    ///
    /// Two genuinely different files must report two different inodes.  The
    /// rules above pass on *equality*, which is also exactly what a reader
    /// that returned a constant — or zero, or the device number — would
    /// report for everything.  This is the reading that shows the instrument
    /// discriminates at all, taken on the same filesystem in the same run.
    #[must_use]
    pub fn inode_instrument_discriminates(&self) -> bool {
        matches!(
            (self.source_inode_before, self.control_source_inode),
            (Some(held), Some(control)) if held != control
        )
    }

    /// Whether the namespace is exactly as the kill left it, through the
    /// replacement process's admission, through a caller's retry, and through
    /// the errno control.
    ///
    /// This is "does not blindly resubmit the operation in the new session",
    /// observed on the effect surface, and for a rename it is a genuine
    /// exactly-once claim rather than the weaker statement gate 13 could
    /// make: a resubmitted rename is not idempotent, so one that got through
    /// would have moved a name and this would see it.
    #[must_use]
    pub fn namespace_unchanged_since_the_kill(&self) -> bool {
        let stages = [
            self.held_namespace_after_restart == self.held_namespace_before_kill,
            self.held_namespace_after_retry == self.held_namespace_before_kill,
            self.held_namespace_after_control == self.held_namespace_before_kill,
        ];
        stages.into_iter().all(|held| held)
    }

    /// Whether a **count** of the export root's names saw nothing across the
    /// event.
    ///
    /// This rule asserts the *blindness of a different instrument*, and it is
    /// here because the reasoning that deferred this clause rested on the
    /// claim that a rename is measurable "down to counting names in a host
    /// directory".  A rename inside one directory removes one name and
    /// creates one, so the count cannot move — and a reader checking whether
    /// this gate duplicates gate 10 can see the count standing still beside a
    /// namespace that changed.
    ///
    /// It is a real measurement, not a tautology: a rename implemented as a
    /// copy that had not yet unlinked, or a provider that left a temporary
    /// name behind, would move it.
    #[must_use]
    pub fn entry_count_instrument_was_blind(&self) -> bool {
        let counts = [
            self.entry_count_before == EXPECTED_ENTRY_COUNT,
            self.entry_count_after == EXPECTED_ENTRY_COUNT,
        ];
        counts.into_iter().all(|held| held)
    }

    /// Whether the two refusals read **differently** on the same instrument.
    ///
    /// The retry, refused above the dispatch boundary, and the control, which
    /// reached the host — this is what turns the retry's errno from a value
    /// consistent with the claim into evidence for it.
    #[must_use]
    pub fn errno_instrument_discriminates(&self) -> bool {
        matches!(
            (self.retry_refusal_errno, self.absent_source_control_errno),
            (Some(retry), Some(control)) if retry != control
        )
    }
}

/// The classification the caller is entitled to, in one place.
///
/// Derived from two facts and nothing else: whether the host namespace showed
/// the rename performed, and what the exchange carried.  It is a function
/// rather than an expression at the call site so that the unit tests defeat
/// the derivation the run actually uses.
///
/// **`Outcome::Partial` is never returned, and that is read out of the
/// library rather than decided here.**  `Partial` is documented as "some
/// *acknowledged* effect applied and the rest did not"; this exchange carried
/// no acknowledgement at all.  A rename has no partial form in any case — it
/// is the one baseline operation the contract gives backend atomicity — so
/// the value would be doubly wrong.
#[must_use]
pub fn classify_held_outcome(evidence: &FsRenameRestartEvidence) -> Outcome {
    if evidence.held_namespace_before_kill != NamespaceState::AfterRename {
        // The namespace says the rename never happened.  Unlike a write,
        // whose bytes cannot say who put them there, a rename's post-state is
        // self-describing — so this really is derivable rather than a
        // timeout's default, and the caller may treat it as settled.
        Outcome::NotStarted
    } else if evidence.pending_call_errored {
        // "Dispatched, and the provider reported it made no change."  A
        // settled outcome, and a false one: the namespace says otherwise.
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
pub fn validate_fs_rename_restart_evidence(evidence: &FsRenameRestartEvidence) -> Result<()> {
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
        // says about the held rename means anything.
        (
            "the host namespace discriminated a performed rename from an unperformed one, in \
             both directions, before the event"
                .into(),
            evidence.journal_discriminated_both_directions(),
        ),
        // **The positive control for the inode instrument**, held beside the
        // journal's directions because it is the same kind of thing: the
        // journal rules out a classifier that could only say "before", and
        // this rules out an inode reader that could only say "the same".
        (
            "two different files reported two different inodes, so the instrument the atomicity \
             rule reads can discriminate at all"
                .into(),
            evidence.inode_instrument_discriminates(),
        ),
        (
            "a normally acknowledged rename moved a name and left the inode alone".into(),
            evidence.control_rename_preserved_the_inode(),
        ),
        // The concurrency rules.
        (
            "the relay had dispatched a 9P record toward the device when the process was killed"
                .into(),
            evidence.restart.emitted_at_kill > evidence.restart.emitted_before,
        ),
        (
            "the relay had received no answer to that record when the process was killed: the \
             Trename was outstanding across the restart"
                .into(),
            evidence.request_outstanding_at_kill && evidence.restart.request_outstanding_at_kill(),
        ),
        (
            "a stream was identified for the held exchange".into(),
            evidence.restart.stream_id > 0,
        ),
        // The effect, seen from outside the connector.
        (
            "the held rename had reached the device before the process was killed, so the lost \
             answer is an unknown and not a refusal that never dispatched"
                .into(),
            evidence.held_namespace_before_kill == NamespaceState::AfterRename,
        ),
        // **Backend atomicity**, the property that separates this gate from
        // gate 13 and the one `docs/filesystem-api.md` grants to exactly this
        // operation.
        (
            "the held rename moved a name and left the inode alone, so it was a native rename \
             and not a copy and an unlink"
                .into(),
            evidence.rename_preserved_the_inode(),
        ),
        (
            "no sample ever read the namespace in a state backend atomicity forbids: both names \
             present, or neither"
                .into(),
            !evidence.forbidden_intermediate_observed,
        ),
        // The count instrument, recorded standing still.
        (
            "a count of the export root's names was the same either side of the rename, which is \
             why a count-based journal cannot be this gate's evidence"
                .into(),
            evidence.entry_count_instrument_was_blind(),
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
            // evidence whose classifier has stopped agreeing with what it
            // saw.  The classification rule below cannot catch that, because
            // it only sees the classification.
            "a rename the host namespace proves reached the device was not reported to the caller \
             as an error, which is a settled outcome a caller may resubmit after"
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
            "the held rename classifies as an unknown outcome".into(),
            evidence.held_call_outcome == Some(Outcome::Unknown),
        ),
        (
            "the held exchange's stream was deregistered at the owner".into(),
            evidence.held_stream_deregistered,
        ),
        // "does not blindly resubmit", observed on the namespace.  For a
        // rename this is a genuine exactly-once claim.
        (
            "the namespace the kill left behind was neither completed, reverted nor re-applied by \
             the restart, by a caller's retry or by the errno control"
                .into(),
            evidence.namespace_unchanged_since_the_kill(),
        ),
        (
            "the earlier session's source fid is unbound after the restart".into(),
            evidence.stale_source_fid_refused,
        ),
        (
            "the stale source fid refusal carried the errno for a fid this session never allocated"
                .into(),
            evidence.stale_source_fid_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        (
            "a caller that retries the rename anyway is refused above the dispatch boundary".into(),
            evidence.retry_refused_above_dispatch,
        ),
        (
            "that retry carried the errno a session-level unknown-fid refusal carries".into(),
            evidence.retry_refusal_errno == Some(UNKNOWN_FID_ERRNO),
        ),
        // **The positive control that makes the errno above proof of origin.**
        //
        // **A companion rule asserting that the two refusals *differ* was
        // written here and then removed, on gate 10's and gate 11's
        // precedent.**  It could never be the rule that rejected a run: the
        // rule above requires the control to read `ABSENT_SOURCE_ERRNO` and
        // the retry rule requires `UNKNOWN_FID_ERRNO`, and those two constants
        // are different values — so whenever both of those rules hold, the
        // difference holds automatically, and whenever it fails one of them
        // has already failed.  The property is held where it can be defeated
        // instead: `the_absent_source_errno_is_distinct_from_the_unknown_fid_errno`
        // defeats the premise directly out of the library, and
        // `an_errno_channel_that_cannot_discriminate_fails_the_gate` defeats
        // the helper.  `errno_instrument_discriminates()` is kept as a helper
        // because the evidence line prints it, which is worth more to a reader
        // than a rule that cannot speak.
        (
            "the same rename on a valid fid reached the host and was refused for an absent source"
                .into(),
            evidence.absent_source_control_refused
                && evidence.absent_source_control_errno == Some(ABSENT_SOURCE_ERRNO),
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
            "the replacement session read the renamed file back whole".into(),
            evidence.second_session_bytes == evidence.second_session_expected_bytes
                && evidence.second_session_expected_bytes == FILE_BYTES,
        ),
        (
            "that transfer needed many messages rather than one".into(),
            evidence.second_session_messages > MIN_READ_MESSAGES,
        ),
        (
            "the renamed file holds exactly the bytes the source held, so the name moved and the \
             content came with it"
                .into(),
            evidence.renamed_content_matches,
        ),
        (
            "the file is the size it always was".into(),
            evidence.second_session_getattr_size == FILE_BYTES as u64,
        ),
        (
            "the export's own directory view classifies the namespace exactly as the host does"
                .into(),
            evidence.namespace_over_ninep == evidence.held_namespace_before_kill,
        ),
        (
            "the source name is gone from inside the export too, not merely from the host's view"
                .into(),
            evidence.source_name_walk_refused,
        ),
        (
            "exactly one Tattach per attached session, and never a reconstructed one".into(),
            evidence.attach_count == 2,
        ),
    ];
    for (rule, held) in checks {
        if !held {
            return Err(HarnessError::Process(format!(
                "M4 filesystem rename restart evidence failed: {rule}"
            )));
        }
    }
    Ok(())
}

/// The export root's names, read **from the host directory**, not through the
/// connector.
///
/// This is the journal: it is the connector's only durable effect surface, it
/// is read without going through the connector, the relay or the 9P session,
/// and it therefore outlives the process under test and spans both its
/// generations.
fn host_entries(root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Classify the held pair's namespace from the host directory.
///
/// Returns [`NamespaceState::Unreadable`] when the directory itself cannot be
/// listed, so a failed measurement is never reported as one of the four
/// meaningful states.
fn host_namespace(root: &Path) -> NamespaceState {
    if std::fs::read_dir(root).is_err() {
        return NamespaceState::Unreadable;
    }
    classify_namespace(&host_entries(root), SOURCE_NAME, DESTINATION_NAME)
}

/// One file's inode number, or `None` if it cannot be read.
///
/// `None` is deliberately *not* treated as "matching" by the callers: two
/// unreadable samples compare equal, and a rule that passes because the
/// measurement failed twice is exactly the shape this gate refuses elsewhere.
fn host_inode(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|metadata| metadata.ino())
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
/// live 9P rename, restart it, and validate the evidence.
///
/// # Errors
/// Any harness, cluster or validation failure.
pub async fn verify() -> Result<FsRenameRestartEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("fs rename restart harness startup timed out".into())
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
            validate_fs_rename_restart_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs rename restart scenario exceeded its bounded deadline".into(),
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
/// `active` at the owner are not the same instant as the public consumer
/// route being willing to upgrade onto it.  That is a race in the *gate's*
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

/// Wait for the catalog to report an owner claim for this device whose epoch
/// is strictly greater than `floor`, and return its epoch and session id.
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

/// Wait until the owner holds this device session **with its data carrier
/// attached**.
///
/// An owner claim is written when the control socket is admitted, before the
/// connector's data socket attaches, and an upgrade in that window is correctly
/// refused 503: the contract admits a filesystem session only for an online
/// device. On macOS the window was always shorter than this gate's first
/// upgrade took to arrive; on hosted x86_64 Linux the first upgrade landed in
/// it in 3 of 3 runs (task row M4-51), so the gate raced its own fixture.
async fn wait_data_attached(cluster: &ProductionCluster, session_id: &str) -> Result<()> {
    let deadline = Instant::now() + OWNER_WAIT;
    loop {
        if let Ok(snapshot) = owner_snapshot(cluster).await
            && let Ok(session) = session_of(&snapshot, session_id)
            && session.sockets >= 2
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "the owner never reported this device session's data carrier attached".into(),
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
) -> Result<FsRenameRestartEvidence> {
    let mut evidence = FsRenameRestartEvidence {
        relay_count: cluster.relays.len(),
        second_session_expected_bytes: FILE_BYTES,
        ..FsRenameRestartEvidence::default()
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
        .fs_service("rename-restart")
        .ok_or_else(|| {
            HarnessError::InvalidInput("the rename-restart filesystem export was not seeded".into())
        })?
        .service_id;

    // The export's own host directory, holding the two names that are also the
    // journal.  It is a `TempDir` held for the whole run, so both process
    // generations serve the same root and the namespace spans them.
    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let payload = payload_bytes(FILE_BYTES);
    std::fs::write(directory.path().join(SOURCE_NAME), &payload).map_err(HarnessError::Io)?;
    std::fs::write(directory.path().join(CONTROL_SOURCE_NAME), &payload)
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
    let profile = write_device_profile(
        profile_directory.path(),
        device.id,
        echo_service,
        "m4-fs-rename-restart-canary",
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
    //
    // **`delete` and `atomicRename` are both here, and both were re-derived
    // from the code rather than copied from gate 13's config.**  A rename is
    // gated twice over, and missing either gate would have this gate's held
    // operation refused before it ever dispatched — so the run would be
    // measuring a permission denial rather than an ambiguity:
    //
    // * `tunnel_fs_core::capability` requires `Primitive::Rename` to hold
    //   **both** `Write` and `Delete`, because it creates a name at the
    //   destination and removes one at the source.  Gate 13's
    //   `["read", "write", "list"]` does not.
    // * `ExportRoot::rename_checked` opens with `authorize(Primitive::Rename)`,
    //   which additionally requires the **`atomicRename` feature**.  Features
    //   default to none and are opt-in, and — the trap worth naming —
    //   `FsExportSettings` documents that "a name this build does not know is
    //   ignored rather than refused", so a misspelling here does not fail
    //   loudly at config load; it silently leaves the feature off and surfaces
    //   much later as an `ENOTSUP` on the held operation.  The spelling is
    //   taken from `capability::Feature::AtomicRename`'s own `as_str`.
    let config_text = format!(
        "{existing}\n[exports.{service}]\ntype = \"fs\"\n\n[exports.{service}.fs]\nroot = {root}\ncapabilities = [\"read\", \"write\", \"list\", \"delete\"]\nfeatures = [\"atomicRename\"]\n",
        existing = std::fs::read_to_string(&profile.config_path).map_err(HarnessError::Io)?,
        service = toml_string(&service.to_string()),
        root = toml_string(&directory.path().to_string_lossy()),
    );
    std::fs::write(&profile.config_path, config_text).map_err(HarnessError::Io)?;

    let (mut first, first_session_id) = start_connector_process(
        cluster,
        "m4-fs-rename-restart-first",
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
        &payload,
        device.tenant_id,
        device.id,
        service,
        &first_session_id,
        &mut evidence,
    )
    .await;
    if scenario.is_err() {
        // Payload-free: identifiers, labels and counters only.
        eprintln!("fs rename restart partial evidence: {evidence:?}");
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

/// Sample the namespace and record a forbidden intermediate if one is seen.
///
/// Every sample in the run goes through here, so the atomicity rule reads
/// **every** observation rather than only the ones a later rule happens to
/// compare.
fn sample_namespace(root: &Path, evidence: &mut FsRenameRestartEvidence) -> NamespaceState {
    let state = host_namespace(root);
    if state.is_forbidden_intermediate() {
        evidence.forbidden_intermediate_observed = true;
    }
    state
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
    payload: &[u8],
    tenant_id: Uuid,
    device_id: Uuid,
    service: Uuid,
    session_id: &str,
    evidence: &mut FsRenameRestartEvidence,
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
    wait_data_attached(cluster, session_id).await?;
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

    match session.walk(ATTACH_FID, SOURCE_FID, &[SOURCE_NAME]).await? {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match session.lopen(SOURCE_FID, O_RDONLY).await? {
        Message::Rlopen { .. } => {}
        other => return Err(unexpected("Rlopen", &other)),
    }

    let stream_id = wait_fs_stream(cluster, session_id).await?;

    // 1. Serve the session normally first, so a later failure cannot be blamed
    //    on a session that never worked.
    let mut prefix = 0_usize;
    for _ in 0..PREFIX_READS {
        match session.read(SOURCE_FID, prefix as u64, READ_COUNT).await? {
            Message::Rread { data } if !data.is_empty() => prefix += data.len(),
            other => return Err(unexpected("a non-empty Rread", &other)),
        }
    }
    evidence.prefix_bytes = prefix;

    // 2. The journal's **negative** direction, and the count instrument's
    //    first reading, both taken before anything is perturbed.
    evidence.held_namespace_before_send = sample_namespace(root, evidence);
    evidence.entry_count_before = host_entries(root).len();
    evidence.source_inode_before = host_inode(&root.join(SOURCE_NAME));

    // 3. The journal's **positive** direction: one normal acknowledged rename
    //    on its own pair of names, performed before anything is perturbed,
    //    whose effect the harness then reads straight out of the export's own
    //    host directory.  A classifier that could only ever say "before" is
    //    ruled out here.
    //
    //    It is also the **inode instrument's** control pair: this rename must
    //    preserve its own inode, and its source's inode must differ from the
    //    held pair's, which is what shows the reader discriminates rather
    //    than returning a constant.
    evidence.control_namespace_before = classify_namespace(
        &host_entries(root),
        CONTROL_SOURCE_NAME,
        CONTROL_DESTINATION_NAME,
    );
    evidence.control_source_inode = host_inode(&root.join(CONTROL_SOURCE_NAME));
    match session
        .walk(ATTACH_FID, CONTROL_FID, &[CONTROL_SOURCE_NAME])
        .await?
    {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match session
        .call(Message::Trename {
            fid: CONTROL_FID,
            dfid: ATTACH_FID,
            name: CONTROL_DESTINATION_NAME.to_owned(),
        })
        .await?
    {
        Message::Rrename => {}
        other => return Err(unexpected("Rrename", &other)),
    }
    evidence.control_namespace_after = classify_namespace(
        &host_entries(root),
        CONTROL_SOURCE_NAME,
        CONTROL_DESTINATION_NAME,
    );
    evidence.control_destination_inode = host_inode(&root.join(CONTROL_DESTINATION_NAME));

    // 4. Settle the carrier and pause the data socket's connector→relay bytes,
    //    so a reply cannot settle the exchange before the process dies.
    //
    //    The connector is a child process, so its sockets are identified from
    //    the proxy rather than from a status snapshot.  Both of its connections
    //    arrive here; the control socket is established first, so the data
    //    socket is the later of the two.  A mis-identification cannot pass
    //    silently: pausing the control socket would leave the rename's reply
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
                    "the device carrier never settled before the held rename".into(),
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
    let mut observation = RenameRestartObservation {
        stream_id,
        ..RenameRestartObservation::default()
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
                    "the filesystem stream vanished before the held rename".into(),
                )
            })?;
        observation.emitted_before = stream.last_emitted_relay_to_connector;
        observation.recv_contiguous_before = stream.recv_contiguous_connector_to_relay;
    }

    // 6. Send one `Trename` and deliberately do not read its reply.  The
    //    request crosses on the still-flowing relay→connector direction, the
    //    device performs it — which is what moves the name in the host
    //    directory — and the connector sequences the `Rrename` into the paused
    //    socket, where it stays and is ultimately lost with the process.
    let held_tag = session
        .send(Message::Trename {
            fid: SOURCE_FID,
            dfid: ATTACH_FID,
            name: DESTINATION_NAME.to_owned(),
        })
        .await?;
    evidence.held_tag = held_tag;

    // 7. Wait for the owner to show the rename dispatched and unanswered.
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
                let sample = RenameRestartObservation {
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
                    "the held Trename was never observed dispatched and unanswered at the owner"
                        .into(),
                ));
            }
            sleep(POLL).await;
        }
    }
    evidence.request_outstanding_at_kill = observation.request_outstanding_at_kill();
    evidence.restart = observation;

    // 8. **The journal.**  Wait until the host directory shows the held rename
    //    reach the device, so the kill lands after the effect rather than
    //    racing it.  Without this the gate could kill the process before the
    //    rename arrived and would then be measuring a refusal that never
    //    dispatched — retryable, and a much weaker claim than the one the
    //    contract is about.
    {
        let deadline = Instant::now() + JOURNAL_WAIT;
        let mut polls = 0_usize;
        loop {
            polls += 1;
            let state = sample_namespace(root, evidence);
            if state == NamespaceState::AfterRename {
                evidence.journal_polls = polls;
                evidence.held_namespace_before_kill = state;
                break;
            }
            if Instant::now() >= deadline {
                evidence.held_namespace_before_kill = state;
                return Err(HarnessError::Timeout(format!(
                    "the held rename never reached the device: the host namespace still reads \
                     {}, so this run cannot measure an unknown outcome",
                    state.as_str()
                )));
            }
            sleep(POLL).await;
        }
    }
    // The inode the destination name now refers to, and the count instrument's
    // second reading.  Taken here, before the kill, so the atomicity claim is
    // about the operation rather than about anything the restart did.
    evidence.destination_inode_after = host_inode(&root.join(DESTINATION_NAME));
    evidence.entry_count_after = host_entries(root).len();

    // ---------------------------------------------------------------------
    // The event: the connector's real process is killed.  No unwind, no
    // graceful close, no chance to fail anything on the way out.  The paused
    // direction is deliberately **not** released: the answer this rename
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
            // A reply served from a session the contract invalidates.
            // Recorded rather than thrown, so the validator names the violated
            // rule — and an `Rlerror` is recorded *as such*, because telling a
            // caller that a performed rename failed is the specific trap this
            // gate exists to exclude.  The two are **disjoint**, not nested:
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

    // The classification, derived rather than asserted.  Unlike gate 13's
    // bytes, the namespace is self-describing, so `NotStarted` here is a real
    // reading of the host rather than a default.
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
        "m4-fs-rename-restart-second",
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
    wait_data_attached(cluster, &replacement_session_id).await?;

    // **The namespace the kill left behind, sampled before any 9P traffic
    // reaches the replacement process.**  The restart may not have changed it:
    // a rename re-applied here would be the adapter resubmitting, and one
    // reverted would be a rollback nothing in the contract promises.
    evidence.held_namespace_after_restart = sample_namespace(root, evidence);

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

    // The earlier session's source fid — the one the held rename was issued
    // on, and the one a caller resuming that rename would reach for — must not
    // be bound here.
    match second.getattr(SOURCE_FID, GETATTR_BASIC).await? {
        Message::Rgetattr(_) => {
            return Err(HarnessError::Process(
                "the fid the outstanding rename was issued on answered after a connector process \
                 restart: the profile restored a fid across a process restart"
                    .into(),
            ));
        }
        other => {
            evidence.stale_source_fid_refused = matches!(other, Message::Rlerror { .. });
            evidence.stale_source_fid_errno = errno_of(&other);
        }
    }

    // ---- the control: a caller that retries the rename anyway -------------
    //
    // The trap in its operational form.  A consumer that read the lost answer
    // as "it never happened" would resubmit, and the question is whether
    // anything below it would let that reach the provider.  It does not: the
    // fid is not allocated in this session, so the session state machine —
    // which runs in the *connector* process, before a request is ever queued
    // toward the host — refuses it above the dispatch boundary.
    //
    // **And unlike gate 13, the errno here says so.**  Gate 13 had to record
    // that its `Einval` was consistent with a host refusal too.  A rename is
    // not idempotent: the source name is gone, so the identical operation
    // *reaching* the host produces `ENOENT`, which
    // `tunnel_fs_host::policy::code_from_errno` maps to a **distinct**
    // `FsErrorCode::Enoent` rather than folding into `Einval`.  The control
    // immediately below establishes that reading on the same instrument, in
    // this run, so the two values discriminate.
    match second
        .call(Message::Trename {
            fid: SOURCE_FID,
            dfid: SECOND_ROOT_FID,
            name: DESTINATION_NAME.to_owned(),
        })
        .await?
    {
        Message::Rrename => {
            return Err(HarnessError::Process(
                "a retried rename was performed on a fid from before the process restart".into(),
            ));
        }
        other => {
            evidence.retry_refused_above_dispatch = matches!(other, Message::Rlerror { .. });
            evidence.retry_refusal_errno = errno_of(&other);
        }
    }
    evidence.held_namespace_after_retry = sample_namespace(root, evidence);

    // ---- the positive control for that errno ------------------------------
    //
    // The **same rename**, on a **valid** directory fid this session owns,
    // naming the same absent source.  It is refused by the host rather than by
    // the session, and it must therefore carry a different errno.
    //
    // `Trenameat` is the name-addressed form of the operation the retry above
    // issued by fid.  `tunnel_fs_provider` dispatches `Trename` and
    // `Trenameat` to the *same* `perform_rename`, which calls the same
    // `ExportRoot::rename_checked`, so this reading is taken on the same
    // instrument and the same host path — and it is the only form that can
    // present the host with a source that is **absent**, which is exactly the
    // state the held rename created.
    //
    // **Where inside the host it is refused was re-derived, and the answer is
    // stated rather than guessed at.**  `rename_checked` calls
    // `inspect_removable` on the source before it reaches
    // `rustix::fs::renameat`, and that helper's first act is a `statat`.  So
    // an absent source is refused at the inspection rather than at the rename
    // itself.  It makes no difference to this rule and it is recorded anyway:
    // both are **host syscalls**, both map their errno through the one
    // `policy::code_from_errno` (`host_error` and `mutation_error` differ only
    // in the `Outcome` they carry, not in the code), and what this control
    // establishes is that the call **reached the host at all** — which is
    // precisely what the retry above must not have done.
    //
    // It must also mutate nothing, and the namespace sample after it is what
    // holds that.
    match second
        .call(Message::Trenameat {
            olddirfid: SECOND_ROOT_FID,
            oldname: SOURCE_NAME.to_owned(),
            newdirfid: SECOND_ROOT_FID,
            newname: DESTINATION_NAME.to_owned(),
        })
        .await?
    {
        Message::Rrenameat => {
            return Err(HarnessError::Process(
                "a rename naming a source the held rename moved away was performed, so the host \
                 namespace does not agree that the held rename happened"
                    .into(),
            ));
        }
        other => {
            evidence.absent_source_control_refused = matches!(other, Message::Rlerror { .. });
            evidence.absent_source_control_errno = errno_of(&other);
        }
    }
    evidence.held_namespace_after_control = sample_namespace(root, evidence);

    // The source name is gone from inside the export too, not merely from the
    // host's view: a walk to it must be refused.
    match second
        .walk(SECOND_ROOT_FID, SECOND_FILE_FID, &[SOURCE_NAME])
        .await?
    {
        Message::Rwalk { .. } => {
            return Err(HarnessError::Process(
                "the export still resolves the name the held rename moved away".into(),
            ));
        }
        other => evidence.source_name_walk_refused = matches!(other, Message::Rlerror { .. }),
    }

    // The export answers normally on this session's own root, so the refusals
    // above are fid scoping and not a replacement process that never served
    // this root.  Binding the destination on a fresh fid is also the other
    // half of the contract: the file is still there, under its new name.
    match second
        .walk(SECOND_ROOT_FID, SECOND_FILE_FID, &[DESTINATION_NAME])
        .await?
    {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match second.lopen(SECOND_FILE_FID, O_RDONLY).await? {
        Message::Rlopen { .. } => {}
        other => return Err(unexpected("Rlopen", &other)),
    }
    match second.getattr(SECOND_FILE_FID, GETATTR_BASIC).await? {
        Message::Rgetattr(attributes) => evidence.second_session_getattr_size = attributes.size,
        other => return Err(unexpected("Rgetattr", &other)),
    }

    let mut transferred: Vec<u8> = Vec::with_capacity(FILE_BYTES);
    let mut messages = 0_usize;
    loop {
        match second
            .read(SECOND_FILE_FID, transferred.len() as u64, READ_COUNT)
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
    // The name moved and the content came with it: a rename is not a copy of
    // some other file's bytes into a new name.
    evidence.renamed_content_matches = transferred == payload;

    // Two independent views of the same namespace: the host's, read by the
    // harness, and the export's, read over 9P by a session on the replacement
    // process.
    evidence.namespace_over_ninep = read_namespace_over_ninep(&mut second).await?;

    second.close().await;
    Ok(())
}

/// Classify the export root's namespace from the **export's own** `Treaddir`,
/// so the host's view and the export's must agree.
async fn read_namespace_over_ninep(session: &mut NinepClient) -> Result<NamespaceState> {
    const DIR_FID: u32 = 7;
    match session.walk(SECOND_ROOT_FID, DIR_FID, &[]).await? {
        Message::Rwalk { .. } => {}
        other => return Err(unexpected("Rwalk", &other)),
    }
    match session.lopen(DIR_FID, O_RDONLY).await? {
        Message::Rlopen { .. } => {}
        other => return Err(unexpected("Rlopen", &other)),
    }
    let mut names = Vec::new();
    let mut offset = 0_u64;
    loop {
        match session.readdir(DIR_FID, offset, READ_COUNT).await? {
            Message::Rreaddir { data } => {
                if data.is_empty() {
                    break;
                }
                let entries = tunnel_fs_ninep::readdir::parse_entries(&data).map_err(|error| {
                    HarnessError::Process(format!("parsing the export's directory block: {error}"))
                })?;
                if entries.is_empty() {
                    break;
                }
                for entry in entries {
                    // The cookie is opaque and is resumed from, never
                    // interpreted: `docs/filesystem-api.md` promises no
                    // snapshot or stable sort, so the only thing this loop may
                    // do with an offset is hand it back.
                    offset = entry.offset;
                    names.push(entry.name);
                }
            }
            other => return Err(unexpected("Rreaddir", &other)),
        }
    }
    Ok(classify_namespace(&names, SOURCE_NAME, DESTINATION_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> FsRenameRestartEvidence {
        FsRenameRestartEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: 65_536,
            negotiated_dialect: DIALECT.into(),
            prefix_bytes: 131_024,
            held_namespace_before_send: NamespaceState::BeforeRename,
            control_namespace_before: NamespaceState::BeforeRename,
            control_namespace_after: NamespaceState::AfterRename,
            source_inode_before: Some(1_001),
            destination_inode_after: Some(1_001),
            control_source_inode: Some(1_002),
            control_destination_inode: Some(1_002),
            restart: RenameRestartObservation {
                stream_id: 1,
                emitted_before: 4,
                emitted_at_kill: 5,
                recv_contiguous_before: 4,
                recv_contiguous_at_kill: 4,
            },
            request_outstanding_at_kill: true,
            restart_polls: 3,
            held_tag: 7,
            held_namespace_before_kill: NamespaceState::AfterRename,
            journal_polls: 2,
            forbidden_intermediate_observed: false,
            entry_count_before: EXPECTED_ENTRY_COUNT,
            entry_count_after: EXPECTED_ENTRY_COUNT,
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
            held_namespace_after_restart: NamespaceState::AfterRename,
            stale_source_fid_refused: true,
            stale_source_fid_errno: Some(UNKNOWN_FID_ERRNO),
            retry_refused_above_dispatch: true,
            retry_refusal_errno: Some(UNKNOWN_FID_ERRNO),
            held_namespace_after_retry: NamespaceState::AfterRename,
            absent_source_control_refused: true,
            absent_source_control_errno: Some(ABSENT_SOURCE_ERRNO),
            held_namespace_after_control: NamespaceState::AfterRename,
            second_session_msize: 65_536,
            second_session_attached: true,
            second_session_bytes: FILE_BYTES,
            second_session_expected_bytes: FILE_BYTES,
            second_session_messages: 5,
            renamed_content_matches: true,
            second_session_getattr_size: FILE_BYTES as u64,
            namespace_over_ninep: NamespaceState::AfterRename,
            source_name_walk_refused: true,
            attach_count: 2,
        }
    }

    #[test]
    fn the_passing_fixture_validates() {
        assert!(validate_fs_rename_restart_evidence(&passing()).is_ok());
    }

    /// The library property gate 10 removed a rule for, held directly and
    /// defeated in **both** directions.
    #[test]
    fn an_unknown_outcome_is_not_settled_and_a_failed_one_is() {
        assert!(
            !Outcome::Unknown.is_settled(),
            "an unknown outcome must not be settled: a caller may not assume no side effect \
             occurred"
        );
        assert!(
            Outcome::Failed.is_settled(),
            "a failed outcome must be settled, which is what makes reporting a performed rename \
             as failed the trap this gate excludes"
        );
    }

    /// The classifier must be able to report **all five** states, including
    /// the two the harness cannot produce against a real filesystem.
    ///
    /// This is the gate 13 precedent for its `Torn` branch: a state the
    /// validator refuses but the run cannot manufacture is held by a unit
    /// test rather than left as a branch nothing ever evaluates.
    #[test]
    fn the_namespace_classifier_reports_every_state() {
        let source = SOURCE_NAME.to_owned();
        let destination = DESTINATION_NAME.to_owned();
        assert_eq!(
            classify_namespace(std::slice::from_ref(&source), SOURCE_NAME, DESTINATION_NAME),
            NamespaceState::BeforeRename
        );
        assert_eq!(
            classify_namespace(
                std::slice::from_ref(&destination),
                SOURCE_NAME,
                DESTINATION_NAME
            ),
            NamespaceState::AfterRename
        );
        assert_eq!(
            classify_namespace(
                &[source.clone(), destination.clone()],
                SOURCE_NAME,
                DESTINATION_NAME
            ),
            NamespaceState::BothPresent
        );
        assert_eq!(
            classify_namespace(&[], SOURCE_NAME, DESTINATION_NAME),
            NamespaceState::NeitherPresent
        );
    }

    /// Both forbidden states are recognised as forbidden, and the three that
    /// are not are not — including `Unreadable`, which is a failed
    /// measurement rather than an atomicity violation.
    #[test]
    fn only_the_two_intermediate_states_are_forbidden() {
        assert!(NamespaceState::BothPresent.is_forbidden_intermediate());
        assert!(NamespaceState::NeitherPresent.is_forbidden_intermediate());
        assert!(!NamespaceState::BeforeRename.is_forbidden_intermediate());
        assert!(!NamespaceState::AfterRename.is_forbidden_intermediate());
        assert!(
            !NamespaceState::Unreadable.is_forbidden_intermediate(),
            "a directory that could not be read is a failed measurement, and folding it into the \
             atomicity verdict would report a missing instrument as a violated promise"
        );
    }

    /// The validator must reject either forbidden state having been observed.
    #[test]
    fn a_forbidden_intermediate_state_fails_the_gate() {
        let mut evidence = passing();
        evidence.forbidden_intermediate_observed = true;
        assert!(validate_fs_rename_restart_evidence(&evidence).is_err());
    }

    /// The derivation, defeated in all three directions.
    #[test]
    fn the_held_outcome_is_derived_from_the_namespace_and_the_answer() {
        let mut evidence = passing();
        assert_eq!(classify_held_outcome(&evidence), Outcome::Unknown);

        // The namespace says it never happened: settled, and retryable.
        evidence.held_namespace_before_kill = NamespaceState::BeforeRename;
        assert_eq!(classify_held_outcome(&evidence), Outcome::NotStarted);

        // Performed, but the caller was told it failed: settled, and false.
        evidence.held_namespace_before_kill = NamespaceState::AfterRename;
        evidence.pending_call_errored = true;
        assert_eq!(classify_held_outcome(&evidence), Outcome::Failed);
    }

    /// `Outcome::Partial` is never this event's answer, in any combination of
    /// the two inputs the derivation reads.
    #[test]
    fn the_held_outcome_is_never_partial() {
        let mut evidence = passing();
        for state in [
            NamespaceState::Unreadable,
            NamespaceState::BeforeRename,
            NamespaceState::AfterRename,
            NamespaceState::BothPresent,
            NamespaceState::NeitherPresent,
        ] {
            for errored in [false, true] {
                evidence.held_namespace_before_kill = state;
                evidence.pending_call_errored = errored;
                assert_ne!(
                    classify_held_outcome(&evidence),
                    Outcome::Partial,
                    "a rename has no acknowledged-partial form: it is the one baseline operation \
                     the contract gives backend atomicity"
                );
            }
        }
    }

    /// The inode rules must require **both** samples readable: two `None`s
    /// compare equal, and a rule that holds because nothing was measured is
    /// not evidence.
    #[test]
    fn an_unreadable_inode_never_satisfies_the_atomicity_rule() {
        let mut evidence = passing();
        evidence.source_inode_before = None;
        evidence.destination_inode_after = None;
        assert!(
            !evidence.rename_preserved_the_inode(),
            "two unreadable inode samples must not be reported as a preserved inode"
        );
        assert!(validate_fs_rename_restart_evidence(&evidence).is_err());
    }

    /// A copy-and-unlink implementation changes the inode, and that is the
    /// substitution `docs/filesystem-api.md` forbids.
    #[test]
    fn a_changed_inode_fails_the_gate() {
        let mut evidence = passing();
        evidence.destination_inode_after = Some(9_999);
        assert!(!evidence.rename_preserved_the_inode());
        assert!(validate_fs_rename_restart_evidence(&evidence).is_err());
    }

    /// **The inode instrument's positive control**, defeated: an inode reader
    /// that returned the same number for every file satisfies every equality
    /// rule above while proving nothing, and this is what catches it.
    #[test]
    fn an_inode_reader_that_cannot_discriminate_fails_the_gate() {
        let mut evidence = passing();
        evidence.control_source_inode = evidence.source_inode_before;
        evidence.control_destination_inode = evidence.source_inode_before;
        assert!(
            !evidence.inode_instrument_discriminates(),
            "two different files reporting one inode means the instrument is not discriminating"
        );
        assert!(validate_fs_rename_restart_evidence(&evidence).is_err());
    }

    /// **The errno instrument's positive control**, defeated: a channel that
    /// answered the unknown-fid errno regardless would satisfy the retry rule
    /// while saying nothing about where the refusal came from.
    #[test]
    fn an_errno_channel_that_cannot_discriminate_fails_the_gate() {
        let mut evidence = passing();
        evidence.absent_source_control_errno = Some(UNKNOWN_FID_ERRNO);
        assert!(
            !evidence.errno_instrument_discriminates(),
            "the two refusals must read differently for the retry's errno to say where it was \
             refused"
        );
        assert!(validate_fs_rename_restart_evidence(&evidence).is_err());
    }

    /// The two errnos really are different values in the library, which is
    /// the premise the control rests on.  If `Enoent` were ever folded into
    /// `Einval` the way unrecognised errnos are, this gate's discriminator
    /// would silently become gate 13's weaker one.
    #[test]
    fn the_absent_source_errno_is_distinct_from_the_unknown_fid_errno() {
        assert_ne!(
            ABSENT_SOURCE_ERRNO, UNKNOWN_FID_ERRNO,
            "an absent source and an unallocated fid must be distinguishable errnos for the \
             retry refusal to be proof of origin rather than corroboration"
        );
    }

    /// Each direction of the journal must matter on its own.
    #[test]
    fn every_journal_direction_defeats_the_discrimination_on_its_own() {
        type Defeat = fn(&mut FsRenameRestartEvidence);
        let defeats: [(&str, Defeat); 3] = [
            ("the held pair's negative direction", |evidence| {
                evidence.held_namespace_before_send = NamespaceState::AfterRename;
            }),
            ("the control pair's negative direction", |evidence| {
                evidence.control_namespace_before = NamespaceState::AfterRename;
            }),
            ("the control pair's positive direction", |evidence| {
                evidence.control_namespace_after = NamespaceState::BeforeRename;
            }),
        ];
        for (label, defeat) in defeats {
            let mut evidence = passing();
            defeat(&mut evidence);
            assert!(
                !evidence.journal_discriminated_both_directions(),
                "{label} must defeat the discrimination on its own"
            );
            assert!(validate_fs_rename_restart_evidence(&evidence).is_err());
        }
    }

    /// Each stage of the no-resubmission rule must matter on its own.
    #[test]
    fn every_unchanged_stage_defeats_the_no_resubmission_rule_on_its_own() {
        type Defeat = fn(&mut FsRenameRestartEvidence);
        let defeats: [(&str, Defeat); 3] = [
            ("after the restart", |evidence| {
                evidence.held_namespace_after_restart = NamespaceState::BeforeRename;
            }),
            ("after the retry", |evidence| {
                evidence.held_namespace_after_retry = NamespaceState::BeforeRename;
            }),
            ("after the errno control", |evidence| {
                evidence.held_namespace_after_control = NamespaceState::BeforeRename;
            }),
        ];
        for (label, defeat) in defeats {
            let mut evidence = passing();
            defeat(&mut evidence);
            assert!(
                !evidence.namespace_unchanged_since_the_kill(),
                "{label} must defeat the no-resubmission rule on its own"
            );
            assert!(validate_fs_rename_restart_evidence(&evidence).is_err());
        }
    }

    /// The count instrument standing still is a real measurement: a provider
    /// that left an extra name behind moves it.
    #[test]
    fn a_moved_entry_count_fails_the_blindness_rule() {
        let mut evidence = passing();
        evidence.entry_count_after = EXPECTED_ENTRY_COUNT + 1;
        assert!(!evidence.entry_count_instrument_was_blind());
        assert!(validate_fs_rename_restart_evidence(&evidence).is_err());
    }

    /// Each **reading** of the count must matter on its own.
    ///
    /// The guard-deletion suite found this missing: with only the test above,
    /// deleting the `entry_count_before` conjunct changed no test outcome,
    /// because the mutation moved the *after* reading and the surviving
    /// conjunct rejected it anyway.  That is the same masking this module
    /// fixes everywhere else, at the one array that had no per-element defeat
    /// test -- the journal directions and the unchanged stages each already
    /// had one, and this array did not.
    #[test]
    fn every_entry_count_reading_defeats_the_blindness_rule_on_its_own() {
        type Defeat = fn(&mut FsRenameRestartEvidence);
        let defeats: [(&str, Defeat); 2] = [
            ("the reading before the rename", |evidence| {
                evidence.entry_count_before = EXPECTED_ENTRY_COUNT + 1;
            }),
            ("the reading after the rename", |evidence| {
                evidence.entry_count_after = EXPECTED_ENTRY_COUNT + 1;
            }),
        ];
        for (label, defeat) in defeats {
            let mut evidence = passing();
            defeat(&mut evidence);
            assert!(
                !evidence.entry_count_instrument_was_blind(),
                "{label} must defeat the blindness rule on its own"
            );
            assert!(validate_fs_rename_restart_evidence(&evidence).is_err());
        }
    }

    /// Every rule in the validator must be defeasible by some mutation of the
    /// evidence, and each mutation must be rejected.
    #[test]
    fn every_rule_rejects_its_own_mutation() {
        type Mutation = (&'static str, fn(&mut FsRenameRestartEvidence));
        let mutations: [Mutation; 45] = [
            ("relay count", |e| e.relay_count = 2),
            ("owner node", |e| e.owner_node = String::new()),
            ("subprotocol", |e| e.selected_subprotocol = "other".into()),
            ("dialect", |e| e.negotiated_dialect = "9P2000".into()),
            ("msize", |e| e.negotiated_msize = 0),
            ("prefix reads", |e| e.prefix_bytes = 0),
            ("journal discrimination", |e| {
                e.held_namespace_before_send = NamespaceState::AfterRename;
            }),
            ("inode instrument discrimination", |e| {
                // Both control inodes move to the held file's, so the *control*
                // pair still agrees with itself and only the discrimination
                // rule is left to reject the run.
                e.control_source_inode = e.source_inode_before;
                e.control_destination_inode = e.source_inode_before;
            }),
            ("the control rename's own inode", |e| {
                e.control_destination_inode = Some(9_999);
            }),
            // The dispatched-record rule is deliberately absent: it is
            // subsumed by the composite below, is declared in the suite's
            // `EXPECT_GREEN`, and cannot be isolated from it — any evidence
            // that defeats it defeats the composite too.
            ("the composite in-flight predicate", |e| {
                e.request_outstanding_at_kill = false;
            }),
            ("stream id", |e| e.restart.stream_id = 0),
            ("the held rename reached the device", |e| {
                // Every namespace field moves together, so the *later* samples
                // still agree with the pre-kill one and only this rule fails.
                e.held_namespace_before_kill = NamespaceState::BeforeRename;
                e.held_namespace_after_restart = NamespaceState::BeforeRename;
                e.held_namespace_after_retry = NamespaceState::BeforeRename;
                e.held_namespace_after_control = NamespaceState::BeforeRename;
                e.namespace_over_ninep = NamespaceState::BeforeRename;
            }),
            ("the held rename preserved its inode", |e| {
                e.destination_inode_after = Some(9_999);
            }),
            ("a forbidden intermediate state", |e| {
                e.forbidden_intermediate_observed = true;
            }),
            ("the entry count stood still", |e| {
                e.entry_count_after = EXPECTED_ENTRY_COUNT + 1;
            }),
            ("first pid", |e| e.first_pid = 0),
            ("first exit", |e| e.first_process_exited = false),
            ("killed by signal", |e| {
                e.first_process_killed_by_signal = false;
            }),
            ("second pid", |e| e.second_pid = e.first_pid),
            ("the replacement served the device", |e| {
                e.second_process_active = false;
            }),
            ("owner release", |e| e.owner_released_between = false),
            ("epoch advance", |e| e.epoch_after = e.epoch_before),
            ("an epoch was observed at all", |e| e.epoch_before = 0),
            ("session identity", |e| {
                e.session_id_after = e.session_id_before.clone();
            }),
            ("pending close", |e| e.pending_call_closed = false),
            ("close code", |e| e.pending_call_close_code = None),
            ("pending answered", |e| e.pending_call_answered = true),
            ("pending errored", |e| e.pending_call_errored = true),
            ("the held outcome", |e| {
                e.held_call_outcome = Some(Outcome::Failed);
            }),
            ("stream deregistration", |e| {
                e.held_stream_deregistered = false
            }),
            ("the namespace after the retry", |e| {
                e.held_namespace_after_retry = NamespaceState::BeforeRename;
            }),
            ("stale fid refusal", |e| e.stale_source_fid_refused = false),
            ("stale fid errno", |e| {
                e.stale_source_fid_errno = Some(ABSENT_SOURCE_ERRNO);
            }),
            ("retry refusal", |e| e.retry_refused_above_dispatch = false),
            ("retry errno", |e| e.retry_refusal_errno = Some(99)),
            ("the absent-source control", |e| {
                e.absent_source_control_refused = false;
            }),
            ("replacement msize", |e| e.second_session_msize = 0),
            ("replacement attach", |e| e.second_session_attached = false),
            ("replacement transfer", |e| e.second_session_bytes = 0),
            ("replacement message count", |e| {
                e.second_session_messages = 1
            }),
            ("renamed content", |e| e.renamed_content_matches = false),
            ("renamed size", |e| e.second_session_getattr_size = 0),
            ("the export's own namespace view", |e| {
                e.namespace_over_ninep = NamespaceState::BeforeRename;
            }),
            ("the source name walk", |e| {
                e.source_name_walk_refused = false
            }),
            ("attach count", |e| e.attach_count = 3),
        ];
        for (label, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_fs_rename_restart_evidence(&evidence).is_err(),
                "mutation `{label}` must be rejected"
            );
        }
    }
}
