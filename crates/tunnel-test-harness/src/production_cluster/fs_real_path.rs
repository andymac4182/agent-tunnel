//! Implementation gate 4 of `docs/filesystem-api.md` over the real cluster:
//! a consumer HTTPS descriptor read and a real WSS 9P2000.L session through
//! the owning relay's public route, the owner actor, the device data
//! WebSocket and `tunnel-client`'s filesystem export, against six filesystem
//! exports seeded side by side on one device.
//!
//! What one run proves, in the order [`run`] takes it:
//!
//! * The descriptor a grant produces, and that it carries no host path and no
//!   host identity field.
//! * The HTTP refusal matrix before any upgrade: `403` for an empty grant and
//!   for an unsupported host, `401`, `404`, `405`, `409` and `426`.
//! * A real upgrade: the server selects `agent-tunnel.9p.v1`, `Tversion`
//!   negotiates `9P2000.L` and an `msize`, and `Tattach` binds a directory.
//! * A forged `Tattach` — a non-empty `uname`, and separately a non-`NOFID`
//!   `afid` — is not admitted and closes the socket with `1002`.
//! * A checksummed read spanning many `Rread` messages, and a `Treaddir`
//!   paged by opaque cookie over more than four pages with every name once.
//! * The capability matrix: `list` without `read` and `read` without `list`,
//!   each on its own export.
//! * A pipelined `Tflush`, a fid-generation collision, a non-owner relay's
//!   refusal, and every mutation refused with the host file unchanged.
//! * A **real** grant revision advanced in the catalog between discovery and
//!   upgrade: the superseded revision is refused at both the descriptor and
//!   the upgrade, and the current one is admitted.
//! * A **real** revocation under a live 9P session on its own export: the
//!   session closes, nothing further is answered, and the close code is
//!   recorded.
//!
//! Every byte of fixture content is synthetic and generated here; no evidence
//! field, log line or error message carries a path, a name or file content.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use http_body_util::BodyExt as _;
use tempfile::TempDir;
use tokio::time::{sleep, timeout};
use tunnel_client::{
    ConnectOptions, FsExportSettings, LocalExport, LocalExportKind, http_forward::HttpHandlers,
};
use tunnel_fs_core::FsErrorCode;
use tunnel_fs_ninep::{
    GETATTR_BASIC, Message, NOFID, Qid, QidKind,
    flags::{O_DIRECTORY, O_RDONLY, O_WRONLY},
    parse_entries,
};
use uuid::Uuid;

mod wire;

use wire::{Event, NinepClient, Target, UpgradeFailure, errno_of, unexpected};

use super::http_forward_real_path::{connect_consumer, empty_stream, once_stream, request};
use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, SCENARIO_TIMEOUT, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::{Harness, HarnessError, HarnessOptions, Result};

/// The descriptor's schema identifier.
const SCHEMA_VERSION: &str = tunnel_fs_core::SCHEMA_VERSION;
/// The subprotocol the server must select.
const SUBPROTOCOL: &str = tunnel_fs_core::TRANSPORT_SUBPROTOCOL;
/// The dialect `Rversion` must name.
const DIALECT: &str = tunnel_fs_ninep::DIALECT;
/// The contract's `403` code.
const ACCESS_DENIED: &str = "ACCESS_DENIED";
/// The contract's `401` code.
const UNAUTHENTICATED: &str = "UNAUTHENTICATED";
/// The contract's `404` code.
const EXPORT_NOT_FOUND: &str = "EXPORT_NOT_FOUND";
/// The contract's `409` code.
const CAPABILITIES_CHANGED: &str = "CAPABILITIES_CHANGED";
/// The contract's `503` code for a relay that does not own the device.
const BACKEND_UNAVAILABLE: &str = "BACKEND_UNAVAILABLE";

/// Denied by this export's grant, before the host was consulted.
const EPERM: u32 = FsErrorCode::Eperm.errno();
/// A structurally invalid request, which is what a write on a fid never
/// opened for writing is.
const EINVAL: u32 = FsErrorCode::Einval.errno();
/// A framing or lifecycle violation closes the consumer socket with this code.
const PROTOCOL_VIOLATION_CLOSE: u16 = 1002;
/// An authorization invalidation closes the consumer socket with this code.
/// The contract has one close for the whole class — an expired snapshot, a
/// moved revision and a revoked grant alike — and it is 1008.
const AUTHORIZATION_CLOSE: u16 = 1008;

/// The `msize` the gate offers, which is also the profile ceiling.
const OFFERED_MSIZE: u32 = tunnel_fs_ninep::MAX_MESSAGE_BYTES;
/// The largest `count` an `Rread` can answer under [`OFFERED_MSIZE`].
const READ_COUNT: u32 = OFFERED_MSIZE - tunnel_fs_ninep::COUNTED_REPLY_OVERHEAD;
/// The synthetic file the checksummed read covers.  Comfortably more than four
/// maximum-size `Rread` messages, so the multi-message path is exercised rather
/// than assumed.
const READ_FILE_BYTES: usize = 393_216;
/// More than four `Rread` messages must carry the file.
const MIN_READ_MESSAGES: usize = 5;
/// Entries in the paged directory.
const READDIR_ENTRIES: usize = 40;
/// The `count` each `Treaddir` offers.  One entry is `qid[13] offset[8]
/// type[1] name_len[2]` plus an eight-byte name, so this admits nine entries a
/// page and forces five pages for forty entries.
const READDIR_COUNT: u32 = 288;
/// More than four pages must be needed.
const MIN_READDIR_PAGES: usize = 5;
/// The file the `list`-without-`read` export reports the size of.
const SIZED_FILE_BYTES: u64 = 4_096;
/// The file the `read`-without-`list` export serves.
const READ_ONLY_FILE_BYTES: usize = 2_048;
/// The two files the fid-generation collision reads.
const COLLISION_FILE_BYTES: usize = 1_024;
/// How many full-`msize` reads the flush case queues ahead of its victim.
///
/// One request ahead of the flush is not enough to observe anything.  The
/// device admits every frame that is already readable before it performs a
/// queued request, so with a single outstanding `Tread` the flush is still on
/// the wire when the device performs it, and the victim's reply wins every
/// time on a loopback cluster.  Queueing several 64 KiB reads first means the
/// device has to perform, encode and send each of those — real work, not a
/// sleep — before it reaches the victim, by which time the `Tflush` is long
/// readable.  Eight is well past the one or two that suffice.
const FLUSH_PIPELINE_DEPTH: usize = 8;
/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);
/// The file the revoked session reads before its grant goes away.
const REVOCABLE_FILE_BYTES: usize = 512;
/// How long an authorization change may take to become observable.
///
/// A relay may hold an authorization snapshot for up to five seconds and a
/// live stream re-challenges on the same ceiling, so a change is not visible
/// instantly.  This is the bound on the wait, not the wait itself: every loop
/// below polls or blocks on the real signal and stops the moment it arrives,
/// so a run that is merely slow still passes and a run where the change never
/// becomes observable fails by name rather than by a sleep that was too short.
const AUTHORIZATION_WAIT: Duration = Duration::from_secs(60);
/// How long to wait between polls of an authorization change.
const AUTHORIZATION_POLL: Duration = Duration::from_millis(100);

/// The bounded evidence one gate run produces.
///
/// Scalars, closed labels and identifier-free strings only: no path, no file
/// name, no content and no credential is representable here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsRealPathEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    pub non_owner_node: String,
    // (a) the descriptor a grant produces.
    pub descriptor_status: u16,
    pub descriptor_content_type: String,
    pub descriptor_cache_control: String,
    pub descriptor_schema_version: String,
    pub descriptor_subprotocol: String,
    pub descriptor_dialect: String,
    pub descriptor_root_read_only: bool,
    pub descriptor_operations: Vec<String>,
    pub descriptor_device_matches: bool,
    pub descriptor_service_matches: bool,
    pub descriptor_grant_revision_present: bool,
    pub descriptor_host_path_leak: bool,
    pub descriptor_identity_field_leak: bool,
    // (b)-(f) the HTTP refusal matrix, before any 9P byte.
    pub empty_grant_status: u16,
    pub empty_grant_code: String,
    pub unsupported_host_status: u16,
    pub unsupported_host_code: String,
    pub unauthenticated_status: u16,
    pub unauthenticated_code: String,
    pub unknown_device_status: u16,
    pub unknown_device_code: String,
    pub method_not_allowed_status: u16,
    pub stale_revision_status: u16,
    pub stale_revision_code: String,
    pub missing_subprotocol_status: u16,
    // (o) a relay that does not own the device.
    pub non_owner_upgrade_status: u16,
    pub non_owner_upgrade_code: String,
    // (g) the upgrade and the dialect.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub negotiated_dialect: String,
    pub attach_qid_is_directory: bool,
    // (h) forged attach fields.
    pub forged_uname_close_code: Option<u16>,
    pub forged_uname_admitted: bool,
    pub forged_afid_close_code: Option<u16>,
    pub forged_afid_admitted: bool,
    // (i) a checksummed read spanning many messages.
    pub read_file_bytes: u64,
    pub read_observed_bytes: u64,
    pub read_checksum_matches: bool,
    pub read_messages: usize,
    // (j) a cookie-paged directory.
    pub readdir_entries_expected: usize,
    pub readdir_names_observed: usize,
    pub readdir_pages: usize,
    pub readdir_every_name_exactly_once: bool,
    // (k) `list` without `read`.
    pub list_only_getattr_size_matches: bool,
    pub list_only_open_errno: Option<u32>,
    // (l) `read` without `list`.
    pub read_only_read_matches: bool,
    pub read_only_getattr_errno: Option<u32>,
    pub read_only_directory_open_errno: Option<u32>,
    // (m) a pipelined flush.
    pub flush_rflush_observed: bool,
    /// Whether **any** reply carrying the flushed tag was seen, before its
    /// `Rflush` or after it.  Must be false.
    ///
    /// This is the observable form of the dispatcher's obligation to drop a
    /// reply whose tag it has flushed rather than feed it to
    /// `Session::complete`: the `Rflush` released that tag, so a frame
    /// carrying it is a reply that should never have been produced.  The
    /// protocol itself permits a victim's reply to arrive first — that is the
    /// flush losing the race — so what makes this assertable is the
    /// arrangement rather than the protocol: the victim is queued behind
    /// [`FLUSH_PIPELINE_DEPTH`] full reads, so the flush is readable long
    /// before the device reaches it.  A run where the flush lost would fail
    /// here, and that is the intent: on this path the flush winning is the
    /// only way the drop is reachable from a client at all.
    pub flush_victim_reply_observed: bool,
    /// Replies for the flushed tag seen **after** its `Rflush`.  Must be zero:
    /// the `Rflush` released that tag, so a later reply on it is the late reply
    /// the dispatcher must drop.
    pub flush_replies_after_rflush: usize,
    pub flush_session_survived: bool,
    // (n) a fid-generation collision.
    pub fid_reuse_first_read_matches: bool,
    pub fid_reuse_stale_read_errno: Option<u32>,
    pub fid_reuse_second_read_matches: bool,
    // (p) mutations refused, host unchanged.
    pub mutation_write_open_errno: Option<u32>,
    pub mutation_write_errno: Option<u32>,
    pub mutation_create_errno: Option<u32>,
    pub mutation_mkdir_errno: Option<u32>,
    pub mutation_host_unchanged: bool,
    // (q) a real grant revision advanced between discovery and upgrade.
    /// Whether `upsert_grant` moved the revision the catalog holds off the one
    /// the descriptor had just published.  Without this the rest of the case
    /// would prove only that the relay refuses a number it never issued.
    pub revision_advanced_in_catalog: bool,
    /// The status of the descriptor read that first reported the new revision.
    pub revised_descriptor_status: u16,
    /// Whether that descriptor's `grantRevision` differs from the one a
    /// consumer would have cached before the change.
    pub revised_revision_differs: bool,
    /// A descriptor read carrying the superseded revision.
    pub superseded_descriptor_status: u16,
    pub superseded_descriptor_code: String,
    /// The WSS upgrade carrying the superseded revision.
    pub superseded_upgrade_status: u16,
    pub superseded_upgrade_code: String,
    /// Whether the upgrade carrying the *current* revision was admitted and
    /// reached an attached root, so the refusal above is the revision's doing
    /// and not the export becoming unusable.
    pub current_revision_upgrade_admitted: bool,
    // (r) a real revocation under a live 9P session.
    /// Whether the session read its file before anything was revoked.
    pub revoked_session_served_before: bool,
    /// Whether the consumer's socket ended at all within the bound.
    pub revoked_session_closed: bool,
    /// The close code the consumer observed, or `None` for a socket that ended
    /// without one.
    pub revoked_session_close_code: Option<u16>,
    /// 9P replies that arrived after the revocation.  Must be zero.
    pub revoked_session_replies_after: usize,
}

/// Every rule gate 4 must satisfy.  Returns the first violated one, so a
/// regression names the property rather than the run.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_fs_real_path_evidence(evidence: &FsRealPathEvidence) -> Result<()> {
    let checks: [(&str, bool); 54] = [
        ("three relays", evidence.relay_count == 3),
        (
            "the upgrade ran against the owning relay and the refusal against another",
            !evidence.owner_node.is_empty()
                && !evidence.non_owner_node.is_empty()
                && evidence.owner_node != evidence.non_owner_node,
        ),
        ("descriptor status 200", evidence.descriptor_status == 200),
        (
            "descriptor content type",
            evidence.descriptor_content_type == "application/json",
        ),
        (
            "descriptor is not cached",
            evidence.descriptor_cache_control == "no-store",
        ),
        (
            "descriptor schema version",
            evidence.descriptor_schema_version == SCHEMA_VERSION,
        ),
        (
            "descriptor transport subprotocol",
            evidence.descriptor_subprotocol == SUBPROTOCOL,
        ),
        (
            "descriptor transport dialect",
            evidence.descriptor_dialect == DIALECT,
        ),
        (
            "descriptor root is read-only",
            evidence.descriptor_root_read_only,
        ),
        (
            "descriptor advertises operations",
            !evidence.descriptor_operations.is_empty(),
        ),
        (
            "descriptor names the seeded export",
            evidence.descriptor_device_matches && evidence.descriptor_service_matches,
        ),
        (
            "descriptor carries an opaque grant revision",
            evidence.descriptor_grant_revision_present,
        ),
        (
            "descriptor carries no host path",
            !evidence.descriptor_host_path_leak,
        ),
        (
            "descriptor carries no host identity field",
            !evidence.descriptor_identity_field_leak,
        ),
        (
            "an empty grant is refused",
            evidence.empty_grant_status == 403 && evidence.empty_grant_code == ACCESS_DENIED,
        ),
        (
            "an unsupported host is refused",
            evidence.unsupported_host_status == 403
                && evidence.unsupported_host_code == ACCESS_DENIED,
        ),
        (
            "an unauthenticated read is refused",
            evidence.unauthenticated_status == 401
                && evidence.unauthenticated_code == UNAUTHENTICATED,
        ),
        (
            "an unknown device is undiscoverable",
            evidence.unknown_device_status == 404
                && evidence.unknown_device_code == EXPORT_NOT_FOUND,
        ),
        (
            "there is no JSON RPC at this URL",
            evidence.method_not_allowed_status == 405,
        ),
        (
            "a stale grant revision is refused",
            evidence.stale_revision_status == 409
                && evidence.stale_revision_code == CAPABILITIES_CHANGED,
        ),
        (
            "an upgrade without the subprotocol is refused",
            evidence.missing_subprotocol_status == 426,
        ),
        (
            "a relay that does not own the device refuses the session",
            evidence.non_owner_upgrade_status == 503
                && evidence.non_owner_upgrade_code == BACKEND_UNAVAILABLE,
        ),
        (
            "the server selected the 9P subprotocol",
            evidence.selected_subprotocol == SUBPROTOCOL,
        ),
        (
            "the negotiated dialect is the only one this profile speaks",
            evidence.negotiated_dialect == DIALECT,
        ),
        (
            "the negotiated msize is the offered ceiling",
            evidence.negotiated_msize == OFFERED_MSIZE,
        ),
        (
            "the attached root is a directory",
            evidence.attach_qid_is_directory,
        ),
        (
            "a forged uname is not admitted",
            !evidence.forged_uname_admitted
                && evidence.forged_uname_close_code == Some(PROTOCOL_VIOLATION_CLOSE),
        ),
        (
            "a forged afid is not admitted",
            !evidence.forged_afid_admitted
                && evidence.forged_afid_close_code == Some(PROTOCOL_VIOLATION_CLOSE),
        ),
        (
            "the read covered every byte of the file",
            evidence.read_file_bytes == READ_FILE_BYTES as u64
                && evidence.read_observed_bytes == evidence.read_file_bytes,
        ),
        (
            "the read checksum equals the written checksum",
            evidence.read_checksum_matches,
        ),
        (
            "the read spanned more than four messages",
            evidence.read_messages >= MIN_READ_MESSAGES,
        ),
        (
            "every directory entry was listed",
            evidence.readdir_entries_expected == READDIR_ENTRIES
                && evidence.readdir_names_observed == READDIR_ENTRIES,
        ),
        (
            "the listing was paged over more than four pages",
            evidence.readdir_pages >= MIN_READDIR_PAGES,
        ),
        (
            "every directory name appeared exactly once",
            evidence.readdir_every_name_exactly_once,
        ),
        (
            "a list grant can stat and reports the real size",
            evidence.list_only_getattr_size_matches,
        ),
        (
            "a list grant cannot open a file for reading",
            evidence.list_only_open_errno == Some(EPERM),
        ),
        (
            "a read grant reads the file's bytes",
            evidence.read_only_read_matches,
        ),
        (
            "a read grant cannot stat",
            evidence.read_only_getattr_errno == Some(EPERM),
        ),
        (
            "a read grant cannot enumerate a directory",
            evidence.read_only_directory_open_errno == Some(EPERM),
        ),
        (
            "the flush was answered and no reply followed its Rflush",
            evidence.flush_rflush_observed && evidence.flush_replies_after_rflush == 0,
        ),
        (
            "the flushed tag was never answered at all",
            !evidence.flush_victim_reply_observed,
        ),
        (
            "the session survived the flush",
            evidence.flush_session_survived,
        ),
        (
            "a re-bound fid does not reuse the previous binding's descriptor",
            evidence.fid_reuse_first_read_matches
                && evidence.fid_reuse_stale_read_errno.is_some()
                && evidence.fid_reuse_second_read_matches,
        ),
        (
            "every mutation was refused",
            evidence.mutation_write_open_errno == Some(EPERM)
                && evidence.mutation_write_errno == Some(EINVAL)
                && evidence.mutation_create_errno == Some(EPERM)
                && evidence.mutation_mkdir_errno == Some(EPERM),
        ),
        (
            "the host file is unchanged after the refused mutations",
            evidence.mutation_host_unchanged,
        ),
        (
            "a real grant revision moved in the catalog",
            evidence.revision_advanced_in_catalog,
        ),
        (
            "a fresh descriptor reports the moved revision",
            evidence.revised_descriptor_status == 200 && evidence.revised_revision_differs,
        ),
        (
            "a descriptor read carrying the superseded revision is refused",
            evidence.superseded_descriptor_status == 409
                && evidence.superseded_descriptor_code == CAPABILITIES_CHANGED,
        ),
        (
            "an upgrade carrying the superseded revision is refused",
            evidence.superseded_upgrade_status == 409
                && evidence.superseded_upgrade_code == CAPABILITIES_CHANGED,
        ),
        (
            "the upgrade carrying the current revision is admitted",
            evidence.current_revision_upgrade_admitted,
        ),
        (
            "the session served its file before the revocation",
            evidence.revoked_session_served_before,
        ),
        (
            "a revoked grant ends the live session",
            evidence.revoked_session_closed,
        ),
        (
            "the revoked session closed for an authorization invalidation",
            evidence.revoked_session_close_code == Some(AUTHORIZATION_CLOSE),
        ),
        (
            "nothing was answered after the revocation",
            evidence.revoked_session_replies_after == 0,
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "fs real-path gate failed: {rule}"
            )));
        }
    }
    Ok(())
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<FsRealPathEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("fs harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result.and_then(|evidence| {
            validate_fs_real_path_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs real-path scenario exceeded its bounded deadline".into(),
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

/// Deterministic synthetic content: byte `i` is `(i % 251)`.
///
/// 251 is prime and below 256, so the pattern does not align with any power of
/// two the transport uses and a dropped or duplicated block changes the
/// checksum.
fn synthetic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// FNV-1a over 64 bits.  A checksum, not a digest: it only has to detect a
/// byte that moved, and it needs no dependency.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// One export's temporary tree, kept alive for the whole run.
struct Fixture {
    label: &'static str,
    service_id: Uuid,
    directory: TempDir,
}

/// Build the six export roots, each with only the content its own cases need.
fn build_fixtures(harness: &RunningHarness) -> Result<Vec<Fixture>> {
    let mut fixtures = Vec::new();
    for label in [
        "read-list",
        "list-only",
        "read-only",
        "revocable",
        "empty-grant",
        "unsupported-host",
    ] {
        let service = harness.fs_service(label).ok_or_else(|| {
            HarnessError::InvalidInput(format!("the {label} filesystem export was not seeded"))
        })?;
        let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
        let root = directory.path();
        match label {
            "read-list" => {
                std::fs::write(root.join("big.bin"), synthetic_bytes(READ_FILE_BYTES))
                    .map_err(HarnessError::Io)?;
                std::fs::write(root.join("a.bin"), synthetic_bytes(COLLISION_FILE_BYTES))
                    .map_err(HarnessError::Io)?;
                // A different length as well as different bytes, so a reply
                // from the wrong binding cannot coincide.
                std::fs::write(
                    root.join("b.bin"),
                    synthetic_bytes(COLLISION_FILE_BYTES + 7)
                        .iter()
                        .map(|byte| byte ^ 0x5a)
                        .collect::<Vec<_>>(),
                )
                .map_err(HarnessError::Io)?;
                std::fs::write(root.join("target.bin"), synthetic_bytes(64))
                    .map_err(HarnessError::Io)?;
                let pages = root.join("pages");
                std::fs::create_dir(&pages).map_err(HarnessError::Io)?;
                for index in 0..READDIR_ENTRIES {
                    // Eight bytes each, so the page arithmetic above is exact.
                    std::fs::write(pages.join(format!("entry-{index:02}")), [])
                        .map_err(HarnessError::Io)?;
                }
            }
            "list-only" => {
                std::fs::write(
                    root.join("sized.bin"),
                    synthetic_bytes(SIZED_FILE_BYTES as usize),
                )
                .map_err(HarnessError::Io)?;
            }
            "read-only" => {
                std::fs::write(root.join("only.bin"), synthetic_bytes(READ_ONLY_FILE_BYTES))
                    .map_err(HarnessError::Io)?;
                std::fs::create_dir(root.join("sub")).map_err(HarnessError::Io)?;
            }
            "revocable" => {
                std::fs::write(root.join("live.bin"), synthetic_bytes(REVOCABLE_FILE_BYTES))
                    .map_err(HarnessError::Io)?;
            }
            // No session is ever admitted for these two, so their trees exist
            // only so the connector can open the root the operator configured.
            _ => {
                std::fs::write(root.join("unused.bin"), synthetic_bytes(16))
                    .map_err(HarnessError::Io)?;
            }
        }
        fixtures.push(Fixture {
            label,
            service_id: service.service_id,
            directory,
        });
    }
    Ok(fixtures)
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<FsRealPathEvidence> {
    let mut evidence = FsRealPathEvidence {
        relay_count: cluster.relays.len(),
        ..FsRealPathEvidence::default()
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
    let fixtures = build_fixtures(harness)?;

    // The device attaches directly to relay-a, which becomes the owner; gate 4
    // admits a filesystem session only there.
    let owner_relay = cluster.relay("relay-a")?;
    let owner_device_addr = owner_relay
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| HarnessError::Process("relay-a is not running".into()))?;
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut device_profile = write_device_profile(
        profile_directory.path(),
        device.id,
        echo_service,
        "m4-fs-canary",
        owner_device_addr,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    for fixture in &fixtures {
        device_profile.config.exports.insert(
            fixture.service_id.to_string(),
            LocalExport {
                kind: LocalExportKind::Fs,
                device_canary: None,
                mcp: None,
                fs: Some(FsExportSettings {
                    root: fixture.directory.path().to_path_buf(),
                    // The device's own allowlist is the same for every export:
                    // the narrowing the matrix turns on is the relay's OPEN,
                    // derived from the grant, so a difference configured here
                    // would prove the connector rather than the grant.
                    capabilities: vec!["read".to_owned(), "list".to_owned()],
                }),
            },
        );
    }
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
    .map_err(|_| HarnessError::Timeout("fs device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("fs device: {error}")))?;

    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("fs device readiness timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        exercise(
            cluster,
            harness,
            &fixtures,
            device.tenant_id,
            device.id,
            &session.session_id,
            &mut evidence,
        )
        .await
    }
    .await;
    if scenario.is_err() {
        // Payload-free: identifiers, labels and counters only.
        eprintln!("fs device status: {:?}", client.status_snapshot().phase);
        eprintln!("fs partial evidence: {evidence:?}");
    }
    let stop = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    scenario?;
    match stop {
        Ok(Ok(())) => Ok(evidence),
        Ok(Err(error)) => Err(HarnessError::Process(format!("device stop: {error}"))),
        Err(_) => Err(HarnessError::Timeout("device stop timed out".into())),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn exercise(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    fixtures: &[Fixture],
    tenant_id: Uuid,
    device_id: Uuid,
    session_id: &str,
    evidence: &mut FsRealPathEvidence,
) -> Result<()> {
    let owner = await_owner(cluster, tenant_id, device_id, session_id).await?;
    evidence.owner_node = owner;
    let owner_relay = cluster.relay("relay-a")?;
    let non_owner_relay = cluster.relay("relay-c")?;
    evidence.non_owner_node = non_owner_relay.node_id.clone();
    let owner_addr = owner_relay.consumer_addr()?;
    let non_owner_addr = non_owner_relay.consumer_addr()?;
    let ca = harness.pki.server_ca.certificate_der.clone();
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            scope: Some("echo:invoke fs:connect".to_owned()),
            ..OidcTokenOptions::default()
        },
    )?;
    let fixture = |label: &str| -> Result<&Fixture> {
        fixtures
            .iter()
            .find(|fixture| fixture.label == label)
            .ok_or_else(|| HarnessError::InvalidInput(format!("fixture {label} is missing")))
    };
    let read_list = fixture("read-list")?;
    let path_of = |label: &str| -> Result<String> {
        Ok(fixture(label)?
            .directory
            .path()
            .to_string_lossy()
            .into_owned())
    };

    // (a) The descriptor a grant produces.
    let url = |device: Uuid, service: Uuid| format!("/v1/devices/{device}/services/{service}/fs");
    let (status, headers, body) = http_get(
        owner_addr,
        &ca,
        "GET",
        &url(device_id, read_list.service_id),
        Some(&token),
        &[],
    )
    .await?;
    evidence.descriptor_status = status;
    evidence.descriptor_content_type = headers
        .iter()
        .find(|(name, _)| name == "content-type")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    evidence.descriptor_cache_control = headers
        .iter()
        .find(|(name, _)| name == "cache-control")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let descriptor: serde_json::Value =
        serde_json::from_slice(&body).map_err(HarnessError::Json)?;
    let text = |pointer: &str| -> String {
        descriptor
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    evidence.descriptor_schema_version = text("/schemaVersion");
    evidence.descriptor_subprotocol = text("/transport/subprotocol");
    evidence.descriptor_dialect = text("/transport/dialect");
    evidence.descriptor_root_read_only = descriptor
        .pointer("/root/readOnly")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_default();
    evidence.descriptor_operations = descriptor
        .pointer("/operations")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    evidence.descriptor_device_matches = text("/deviceId") == device_id.to_string();
    evidence.descriptor_service_matches = text("/serviceId") == read_list.service_id.to_string();
    evidence.descriptor_grant_revision_present = !text("/grantRevision").is_empty();
    // The raw body, not the parsed tree: a host path could appear in a field
    // this gate does not name, and the point is that it appears nowhere.
    let raw = String::from_utf8_lossy(&body).into_owned();
    evidence.descriptor_host_path_leak = raw.contains(path_of("read-list")?.as_str());
    evidence.descriptor_identity_field_leak = raw.contains("uid") || raw.contains("gid");

    // (b)+(c) Two exports whose grant admits no session at all.
    for (label, status_field, code_field) in [
        (
            "empty-grant",
            &mut evidence.empty_grant_status,
            &mut evidence.empty_grant_code,
        ),
        (
            "unsupported-host",
            &mut evidence.unsupported_host_status,
            &mut evidence.unsupported_host_code,
        ),
    ] {
        let service = fixture(label)?.service_id;
        let (status, _, body) = http_get(
            owner_addr,
            &ca,
            "GET",
            &url(device_id, service),
            Some(&token),
            &[],
        )
        .await?;
        *status_field = status;
        *code_field = error_code(&body);
    }

    // (d) No token, an unknown device, and a method this URL does not serve.
    let (status, _, body) = http_get(
        owner_addr,
        &ca,
        "GET",
        &url(device_id, read_list.service_id),
        None,
        &[],
    )
    .await?;
    evidence.unauthenticated_status = status;
    evidence.unauthenticated_code = error_code(&body);
    let (status, _, body) = http_get(
        owner_addr,
        &ca,
        "GET",
        &url(Uuid::new_v4(), read_list.service_id),
        Some(&token),
        &[],
    )
    .await?;
    evidence.unknown_device_status = status;
    evidence.unknown_device_code = error_code(&body);
    let (status, _, _) = http_get(
        owner_addr,
        &ca,
        "POST",
        &url(device_id, read_list.service_id),
        Some(&token),
        &[],
    )
    .await?;
    evidence.method_not_allowed_status = status;

    // (e) A grant revision that is no longer current.
    let (status, _, body) = http_get(
        owner_addr,
        &ca,
        "GET",
        &url(device_id, read_list.service_id),
        Some(&token),
        &[(wire::GRANT_REVISION_HEADER, "99999")],
    )
    .await?;
    evidence.stale_revision_status = status;
    evidence.stale_revision_code = error_code(&body);

    let target = |addr, service: Uuid| Target {
        consumer_addr: addr,
        device_id,
        service: service.to_string(),
    };

    // (f) An upgrade that offers a subprotocol this profile does not speak.
    match NinepClient::connect(
        &target(owner_addr, read_list.service_id),
        &ca,
        &token,
        Some("agent-tunnel.echo.v1"),
    )
    .await
    {
        Ok(client) => {
            client.close().await;
            return Err(HarnessError::Process(
                "an upgrade offering the wrong subprotocol was admitted".into(),
            ));
        }
        Err(failure) => {
            let (status, _) = failure.into_status()?;
            evidence.missing_subprotocol_status = status;
        }
    }

    // (o) The same upgrade at a relay that does not own the device.
    match NinepClient::connect(
        &target(non_owner_addr, read_list.service_id),
        &ca,
        &token,
        Some(SUBPROTOCOL),
    )
    .await
    {
        Ok(client) => {
            client.close().await;
            return Err(HarnessError::Process(
                "a relay that does not own the device admitted a filesystem session".into(),
            ));
        }
        Err(failure) => {
            let (status, body) = failure.into_status()?;
            evidence.non_owner_upgrade_status = status;
            evidence.non_owner_upgrade_code = error_code(&body.unwrap_or_default());
        }
    }

    // (h) Two forged `Tattach`es, each on its own fresh session.
    for (afid, uname, close_field, admitted_field) in [
        (
            NOFID,
            "synthetic-operator",
            &mut evidence.forged_uname_close_code,
            &mut evidence.forged_uname_admitted,
        ),
        (
            0,
            "",
            &mut evidence.forged_afid_close_code,
            &mut evidence.forged_afid_admitted,
        ),
    ] {
        let mut client =
            open_session(&target(owner_addr, read_list.service_id), &ca, &token).await?;
        client.version(OFFERED_MSIZE).await?;
        // The reply, if any, is read as an event: a refusal here is a close
        // frame rather than an `Rlerror`, because a lifecycle violation is not
        // correlated to a tag.
        let _tag = client
            .send(Message::Tattach {
                fid: 1,
                afid,
                uname: uname.to_owned(),
                aname: String::new(),
                n_uname: tunnel_fs_ninep::NONUNAME,
            })
            .await?;
        loop {
            match client.recv_event().await {
                Ok(Event::Frame(frame)) => {
                    if matches!(frame.message, Message::Rattach { .. }) {
                        *admitted_field = true;
                    }
                }
                Ok(Event::Close(code)) => {
                    *close_field = code;
                    break;
                }
                Ok(Event::Ended) | Err(_) => break,
            }
        }
    }

    // (g) A real session on the read+list export.
    let mut client = open_session(&target(owner_addr, read_list.service_id), &ca, &token).await?;
    evidence.selected_subprotocol = client.selected_subprotocol().to_owned();
    let (msize, dialect) = client.version(OFFERED_MSIZE).await?;
    evidence.negotiated_msize = msize;
    evidence.negotiated_dialect = dialect;
    let root_fid = 0_u32;
    let qid = client.attach(root_fid).await?;
    evidence.attach_qid_is_directory = qid.kind == QidKind::Directory;

    // (i) A checksummed read spanning many `Rread` messages.
    let read_fid = 1_u32;
    expect_walk(client.walk(root_fid, read_fid, &["big.bin"]).await?, 1)?;
    expect_open(client.lopen(read_fid, O_RDONLY).await?)?;
    let (bytes, messages) = read_whole(&mut client, read_fid, READ_COUNT).await?;
    evidence.read_file_bytes = READ_FILE_BYTES as u64;
    evidence.read_observed_bytes = bytes.len() as u64;
    evidence.read_messages = messages;
    evidence.read_checksum_matches = fnv1a(&bytes) == fnv1a(&synthetic_bytes(READ_FILE_BYTES));
    expect_clunk(client.clunk(read_fid).await?)?;

    // (j) A directory paged by opaque cookie.
    let dir_fid = 2_u32;
    expect_walk(client.walk(root_fid, dir_fid, &["pages"]).await?, 1)?;
    expect_open(client.lopen(dir_fid, O_RDONLY | O_DIRECTORY).await?)?;
    let (names, pages) = read_directory(&mut client, dir_fid, READDIR_COUNT).await?;
    evidence.readdir_entries_expected = READDIR_ENTRIES;
    evidence.readdir_names_observed = names.len();
    evidence.readdir_pages = pages;
    let unique: BTreeSet<&String> = names.iter().collect();
    let expected: BTreeSet<String> = (0..READDIR_ENTRIES)
        .map(|index| format!("entry-{index:02}"))
        .collect();
    evidence.readdir_every_name_exactly_once = unique.len() == names.len()
        && unique.into_iter().cloned().collect::<BTreeSet<_>>() == expected;
    expect_clunk(client.clunk(dir_fid).await?)?;

    // (m) A pipelined `Tread` and an immediate `Tflush` of its tag.
    flush_case(&mut client, root_fid, evidence).await?;

    // (n) A fid-generation collision on one fid number.
    fid_collision_case(&mut client, root_fid, evidence).await?;

    // (p) Mutations refused, with the host file unchanged.
    let target_path = read_list.directory.path().join("target.bin");
    let before = std::fs::read(&target_path).map_err(HarnessError::Io)?;
    mutation_case(&mut client, root_fid, evidence).await?;
    let after = std::fs::read(&target_path).map_err(HarnessError::Io)?;
    evidence.mutation_host_unchanged =
        before.len() == after.len() && fnv1a(&before) == fnv1a(&after);
    client.close().await;

    // (k) `list` without `read`.
    list_only_case(
        &target(owner_addr, fixture("list-only")?.service_id),
        &ca,
        &token,
        evidence,
    )
    .await?;

    // (l) `read` without `list`.
    read_only_case(
        &target(owner_addr, fixture("read-only")?.service_id),
        &ca,
        &token,
        evidence,
    )
    .await?;

    let principal_id = harness
        .topology
        .consumers_a
        .first()
        .map(|consumer| consumer.id)
        .ok_or_else(|| HarnessError::InvalidInput("the consumer principal is missing".into()))?;

    // (q) A real grant revision moved between discovery and upgrade.  Last
    // among the `read-list` cases, because it changes that export's grant and
    // every case above reads the revision the fixture seeded.
    revision_change_case(
        cluster,
        &Grant {
            tenant_id,
            principal_id,
            device_id,
            service_id: read_list.service_id,
        },
        harness
            .fs_service("read-list")
            .ok_or_else(|| HarnessError::InvalidInput("the read-list export is missing".into()))?
            .operations,
        owner_addr,
        &ca,
        &token,
        evidence,
    )
    .await?;

    // (r) A real revocation under a live session, on an export nothing else
    // in this run has touched.
    let revocable = fixture("revocable")?;
    revocation_case(
        cluster,
        &Grant {
            tenant_id,
            principal_id,
            device_id,
            service_id: revocable.service_id,
        },
        &target(owner_addr, revocable.service_id),
        &ca,
        &token,
        evidence,
    )
    .await?;
    Ok(())
}

/// The catalog coordinates of one grant, so the two authorization cases take a
/// name rather than four bare `Uuid`s in a row.
struct Grant {
    tenant_id: Uuid,
    principal_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
}

/// The descriptor's `grantRevision`, or the empty string.
fn grant_revision(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/grantRevision")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// (q) A grant whose revision really moves between discovery and upgrade.
///
/// The gate's other revision case sends a number the catalog never issued,
/// which proves only that the relay compares. This one changes the grant in
/// the authoritative catalog and then holds the descriptor a consumer would
/// have cached against the change: a cached descriptor is informative and is
/// never itself an authorization credential, so the superseded revision has to
/// be refused at the descriptor *and* at the upgrade, while the current one is
/// still admitted.
///
/// The re-grant names the same operations as the seed. The point being proven
/// is the revision, so a capability difference here would let a refusal be
/// credited to a lost permission instead.
async fn revision_change_case(
    cluster: &ProductionCluster,
    grant: &Grant,
    operations: &[&str],
    owner_addr: std::net::SocketAddr,
    ca: &[u8],
    token: &str,
    evidence: &mut FsRealPathEvidence,
) -> Result<()> {
    let path = format!(
        "/v1/devices/{}/services/{}/fs",
        grant.device_id, grant.service_id
    );
    // What a consumer that discovered the export a moment ago would hold.
    let (status, _, body) = http_get(owner_addr, ca, "GET", &path, Some(token), &[]).await?;
    if status != 200 {
        return Err(HarnessError::Process(format!(
            "the descriptor before the revision change answered {status}"
        )));
    }
    let cached = grant_revision(&body);
    if cached.is_empty() {
        return Err(HarnessError::Process(
            "the descriptor carried no grant revision to supersede".into(),
        ));
    }

    let snapshot = cluster
        .catalog
        .upsert_grant(&tunnel_catalog::GrantSpec {
            tenant_id: grant.tenant_id,
            principal_id: grant.principal_id,
            device_id: grant.device_id,
            service_id: grant.service_id,
            permissions: tunnel_catalog::PermissionSet {
                operations: operations
                    .iter()
                    .map(|operation| (*operation).to_owned())
                    .collect(),
            },
            constraints: serde_json::Value::Object(serde_json::Map::new()),
            expires_at: None,
            active: true,
        })
        .await
        .map_err(|error| HarnessError::Redis(format!("revising the grant: {error}")))?;
    evidence.revision_advanced_in_catalog = snapshot.revision.to_string() != cached;

    // A relay may serve an authorization snapshot for up to five seconds, so
    // the change is not visible the instant the catalog takes it.  Poll the
    // real signal — a descriptor reporting a different revision — under a
    // bounded deadline rather than sleeping for the ceiling and assuming.
    let deadline = Instant::now() + AUTHORIZATION_WAIT;
    let current = loop {
        let (status, _, body) = http_get(owner_addr, ca, "GET", &path, Some(token), &[]).await?;
        let revision = grant_revision(&body);
        if status == 200 && !revision.is_empty() && revision != cached {
            evidence.revised_descriptor_status = status;
            break revision;
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "the revised grant revision never reached the descriptor".into(),
            ));
        }
        sleep(AUTHORIZATION_POLL).await;
    };
    evidence.revised_revision_differs = current != cached;
    // The cached revision at the descriptor.
    let (status, _, body) = http_get(
        owner_addr,
        ca,
        "GET",
        &path,
        Some(token),
        &[(wire::GRANT_REVISION_HEADER, cached.as_str())],
    )
    .await?;
    evidence.superseded_descriptor_status = status;
    evidence.superseded_descriptor_code = error_code(&body);

    let target = Target {
        consumer_addr: owner_addr,
        device_id: grant.device_id,
        service: grant.service_id.to_string(),
    };
    // The cached revision at the upgrade.  This is the gate's own must-prove:
    // a descriptor a consumer already holds authorizes nothing.
    match NinepClient::connect_with(
        &target,
        ca,
        token,
        Some(SUBPROTOCOL),
        &[(wire::GRANT_REVISION_HEADER, cached.as_str())],
    )
    .await
    {
        Ok(client) => {
            client.close().await;
            return Err(HarnessError::Process(
                "an upgrade carrying a superseded grant revision was admitted".into(),
            ));
        }
        Err(failure) => {
            let (status, body) = failure.into_status()?;
            evidence.superseded_upgrade_status = status;
            evidence.superseded_upgrade_code = error_code(&body.unwrap_or_default());
        }
    }

    // The current revision, so the refusal above is the revision's doing and
    // not the export having become unusable.  Carried all the way to an
    // attached root: a `101` alone would not show the session working.
    let mut client = match NinepClient::connect_with(
        &target,
        ca,
        token,
        Some(SUBPROTOCOL),
        &[(wire::GRANT_REVISION_HEADER, current.as_str())],
    )
    .await
    {
        Ok(client) => client,
        Err(failure) => {
            let (status, _) = failure.into_status()?;
            return Err(HarnessError::Http(format!(
                "the upgrade carrying the current grant revision was refused with {status}"
            )));
        }
    };
    client.version(OFFERED_MSIZE).await?;
    let qid = client.attach(0).await?;
    evidence.current_revision_upgrade_admitted = qid.kind == QidKind::Directory;
    client.close().await;
    Ok(())
}

/// (r) A grant revoked while a 9P session on it is live.
///
/// The session is opened on an export nothing else in this run touches, so the
/// only authorization change under it is this revocation.  After the revoke
/// the consumer only *reads*: what is being proven is what a consumer observes
/// without asking for anything, which is the honest form of "the session was
/// closed for it" — a reply that arrived because the gate poked the socket
/// would prove nothing about the relay noticing on its own.
async fn revocation_case(
    cluster: &ProductionCluster,
    grant: &Grant,
    target: &Target,
    ca: &[u8],
    token: &str,
    evidence: &mut FsRealPathEvidence,
) -> Result<()> {
    let mut client = open_session(target, ca, token).await?;
    client.version(OFFERED_MSIZE).await?;
    let root_fid = 0_u32;
    client.attach(root_fid).await?;
    let fid = 1_u32;
    expect_walk(client.walk(root_fid, fid, &["live.bin"]).await?, 1)?;
    expect_open(client.lopen(fid, O_RDONLY).await?)?;
    let (bytes, _) = read_whole(&mut client, fid, READ_COUNT).await?;
    evidence.revoked_session_served_before = bytes == synthetic_bytes(REVOCABLE_FILE_BYTES);

    cluster
        .catalog
        .revoke_grant(
            grant.tenant_id,
            grant.principal_id,
            grant.device_id,
            grant.service_id,
            chrono::Utc::now(),
        )
        .await
        .map_err(|error| HarnessError::Redis(format!("revoking the grant: {error}")))?;

    // Bounded by a deadline, not by a fixed wait: the loop ends the moment the
    // socket does, and a socket that never ends fails by name.
    let deadline = Instant::now() + AUTHORIZATION_WAIT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, client.recv_event()).await {
            Ok(Ok(Event::Frame(_))) => {
                // A reply after the grant went away.  Counted rather than
                // refused here, so the validator names the rule it broke.
                evidence.revoked_session_replies_after += 1;
            }
            Ok(Ok(Event::Close(code))) => {
                evidence.revoked_session_closed = true;
                evidence.revoked_session_close_code = code;
                break;
            }
            Ok(Ok(Event::Ended)) => {
                // The socket ended with no close frame at all, which is a
                // distinct observation from a close carrying a code.
                evidence.revoked_session_closed = true;
                break;
            }
            Ok(Err(error)) => {
                // Transport-level, so it carries no payload: the socket failed
                // before or instead of a close frame.
                eprintln!("fs revocation: the consumer socket failed: {error}");
                evidence.revoked_session_closed = true;
                break;
            }
            Err(_) => break,
        }
    }
    Ok(())
}

/// Wait for this device's owner claim to name `session_id`, bounded.
async fn await_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    session_id: &str,
) -> Result<String> {
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
            return Ok(owner.token.node_id.clone());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "the device owner claim was not observed".into(),
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Open a session that must be admitted, turning a refusal into a failure.
async fn open_session(target: &Target, ca: &[u8], token: &str) -> Result<NinepClient> {
    match NinepClient::connect(target, ca, token, Some(SUBPROTOCOL)).await {
        Ok(client) => Ok(client),
        Err(UpgradeFailure::Status { status, .. }) => Err(HarnessError::Http(format!(
            "the filesystem upgrade was refused with HTTP status {status}"
        ))),
        Err(UpgradeFailure::Harness(error)) => Err(error),
    }
}

/// One authenticated HTTPS request to the filesystem URL.
async fn http_get(
    addr: std::net::SocketAddr,
    ca: &[u8],
    method: &str,
    path: &str,
    token: Option<&str>,
    extra: &[(&str, &str)],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let (mut sender, task) = connect_consumer(addr, ca).await?;
    let body = if method == "POST" {
        once_stream(b"{}")
    } else {
        empty_stream()
    };
    let response = timeout(
        Duration::from_secs(20),
        sender.send_request(request(method, path, token, extra, body)?),
    )
    .await
    .map_err(|_| HarnessError::Timeout("filesystem descriptor request timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("filesystem descriptor request: {error}")))?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect::<Vec<_>>();
    let body = timeout(Duration::from_secs(20), response.into_body().collect())
        .await
        .map_err(|_| HarnessError::Timeout("filesystem descriptor body timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("filesystem descriptor body: {error}")))?
        .to_bytes()
        .to_vec();
    drop(sender);
    task.abort();
    Ok((status, headers, body))
}

/// The `error.code` of the contract's JSON error envelope, or the empty string.
fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn expect_walk(message: Message, names: usize) -> Result<Vec<Qid>> {
    match message {
        Message::Rwalk { qids } if qids.len() == names => Ok(qids),
        Message::Rwalk { qids } => Err(HarnessError::Process(format!(
            "a walk of {names} names returned {} qids",
            qids.len()
        ))),
        other => Err(unexpected("Rwalk", &other)),
    }
}

fn expect_open(message: Message) -> Result<Qid> {
    match message {
        Message::Rlopen { qid, .. } => Ok(qid),
        other => Err(unexpected("Rlopen", &other)),
    }
}

fn expect_clunk(message: Message) -> Result<()> {
    match message {
        Message::Rclunk => Ok(()),
        other => Err(unexpected("Rclunk", &other)),
    }
}

/// Read a whole open fid, returning its bytes and how many `Rread` messages
/// carried them.
async fn read_whole(client: &mut NinepClient, fid: u32, count: u32) -> Result<(Vec<u8>, usize)> {
    let mut bytes = Vec::new();
    let mut messages = 0_usize;
    loop {
        match client.read(fid, bytes.len() as u64, count).await? {
            Message::Rread { data } => {
                if data.is_empty() {
                    return Ok((bytes, messages));
                }
                messages += 1;
                bytes.extend_from_slice(&data);
            }
            other => return Err(unexpected("Rread", &other)),
        }
    }
}

/// Page a directory by opaque cookie, returning every name and the number of
/// pages that carried at least one entry.
async fn read_directory(
    client: &mut NinepClient,
    fid: u32,
    count: u32,
) -> Result<(Vec<String>, usize)> {
    let mut names = Vec::new();
    let mut pages = 0_usize;
    let mut cookie = 0_u64;
    loop {
        match client.readdir(fid, cookie, count).await? {
            Message::Rreaddir { data } => {
                let entries = parse_entries(&data).map_err(|error| {
                    HarnessError::Process(format!("Rreaddir block refused: {error:?}"))
                })?;
                if entries.is_empty() {
                    return Ok((names, pages));
                }
                pages += 1;
                // The cookie is opaque: it is carried back unchanged and never
                // interpreted, ordered or assumed to be an index.
                cookie = entries.last().map(|entry| entry.offset).unwrap_or(cookie);
                names.extend(entries.into_iter().map(|entry| entry.name));
            }
            other => return Err(unexpected("Rreaddir", &other)),
        }
    }
}

/// (m) Pipeline several reads, then a `Tflush` of the last one's tag.
///
/// What is asserted is that **no reply for the flushed tag ever arrives**,
/// because that is the only thing a client can see of the rule "a reply whose
/// tag the dispatcher flushed is dropped rather than completed".  For the drop
/// to be reachable the flush has to reach the device before its victim is
/// performed, which is what [`FLUSH_PIPELINE_DEPTH`] buys: the reads queued
/// ahead of the victim are the window, and the device admits every readable
/// frame before performing each one.
async fn flush_case(
    client: &mut NinepClient,
    root_fid: u32,
    evidence: &mut FsRealPathEvidence,
) -> Result<()> {
    let fid = 3_u32;
    expect_walk(client.walk(root_fid, fid, &["big.bin"]).await?, 1)?;
    expect_open(client.lopen(fid, O_RDONLY).await?)?;
    // Everything below goes out back to back with no reply awaited in
    // between, so the device sees one pipelined burst.  Every read is the same
    // full-`msize` slice of the largest file the export holds, because what
    // the earlier reads are for is the host work they cost.
    let mut pending: BTreeSet<u16> = BTreeSet::new();
    for _ in 0..FLUSH_PIPELINE_DEPTH {
        let tag = client
            .send(Message::Tread {
                fid,
                offset: 0,
                count: READ_COUNT,
            })
            .await?;
        pending.insert(tag);
    }
    // Sent last, so it is the last request in the device's queue and every
    // read above stands between it and the dispatcher.
    let victim = client
        .send(Message::Tread {
            fid,
            offset: 0,
            count: READ_COUNT,
        })
        .await?;
    let flush = client.send(Message::Tflush { oldtag: victim }).await?;
    let mut seen_rflush = false;
    let mut replies_after = 0_usize;
    // Read until the `Rflush` and every pipelined read have been answered, and
    // no further: that is one frame per queued read plus the `Rflush` when the
    // dispatcher dropped the victim's reply as it must, and one more when it
    // did not.  Bounding it this way rather than by a fixed count leaves the
    // socket in step either way, so a failure is reported by the rule it
    // violated instead of by the next reply landing on the wrong tag.
    while !seen_rflush || !pending.is_empty() {
        let frame = client.recv_frame().await?;
        if frame.tag == flush {
            if !matches!(frame.message, Message::Rflush) {
                return Err(unexpected("Rflush", &frame.message));
            }
            seen_rflush = true;
        } else if frame.tag == victim {
            evidence.flush_victim_reply_observed = true;
            if seen_rflush {
                replies_after += 1;
            }
        } else if !pending.remove(&frame.tag) {
            return Err(HarnessError::Process(
                "a reply arrived for a tag that was never sent".into(),
            ));
        }
    }
    evidence.flush_rflush_observed = seen_rflush;
    evidence.flush_replies_after_rflush = replies_after;
    // From here on every exchange is serial, and the client refuses a reply
    // carrying any tag but the one it just sent.  That is what extends "no
    // reply for the flushed tag" past the frames counted above: a reply the
    // device produced late would fail the very next call rather than pass
    // unnoticed.
    expect_clunk(client.clunk(fid).await?)?;
    // A flush of a tag that is no longer outstanding is still answered, which
    // is what lets a client reserve a flushed tag until its flush lifecycle
    // completes without having to know who won the race.
    match client.flush(victim).await? {
        Message::Rflush => {}
        other => return Err(unexpected("Rflush", &other)),
    }
    // The session survives: a following request on a new tag is answered.
    let probe = 4_u32;
    expect_walk(client.walk(root_fid, probe, &["a.bin"]).await?, 1)?;
    expect_clunk(client.clunk(probe).await?)?;
    evidence.flush_session_survived = true;
    Ok(())
}

/// (n) One fid number bound twice, with a read between the bindings.
async fn fid_collision_case(
    client: &mut NinepClient,
    root_fid: u32,
    evidence: &mut FsRealPathEvidence,
) -> Result<()> {
    let fid = 5_u32;
    expect_walk(client.walk(root_fid, fid, &["a.bin"]).await?, 1)?;
    expect_open(client.lopen(fid, O_RDONLY).await?)?;
    let (first, _) = read_whole(client, fid, READ_COUNT).await?;
    evidence.fid_reuse_first_read_matches = first == synthetic_bytes(COLLISION_FILE_BYTES);
    expect_clunk(client.clunk(fid).await?)?;

    expect_walk(client.walk(root_fid, fid, &["b.bin"]).await?, 1)?;
    // The new binding is not open, so a read on it must be refused rather than
    // answered from the previous binding's descriptor.
    evidence.fid_reuse_stale_read_errno = errno_of(&client.read(fid, 0, READ_COUNT).await?);
    expect_open(client.lopen(fid, O_RDONLY).await?)?;
    let (second, _) = read_whole(client, fid, READ_COUNT).await?;
    let expected: Vec<u8> = synthetic_bytes(COLLISION_FILE_BYTES + 7)
        .iter()
        .map(|byte| byte ^ 0x5a)
        .collect();
    evidence.fid_reuse_second_read_matches = second == expected;
    expect_clunk(client.clunk(fid).await?)?;
    Ok(())
}

/// (p) Every mutation this profile can be asked for, on a read+list session.
async fn mutation_case(
    client: &mut NinepClient,
    root_fid: u32,
    evidence: &mut FsRealPathEvidence,
) -> Result<()> {
    let fid = 6_u32;
    expect_walk(client.walk(root_fid, fid, &["target.bin"]).await?, 1)?;
    // A write needs a fid opened for writing, and the grant refuses that open.
    evidence.mutation_write_open_errno = errno_of(&client.lopen(fid, O_WRONLY).await?);
    expect_open(client.lopen(fid, O_RDONLY).await?)?;
    evidence.mutation_write_errno = errno_of(
        &client
            .call(Message::Twrite {
                fid,
                offset: 0,
                data: vec![0x5a; 8],
            })
            .await?,
    );
    expect_clunk(client.clunk(fid).await?)?;
    evidence.mutation_create_errno = errno_of(
        &client
            .call(Message::Tlcreate {
                fid: root_fid,
                name: "created.bin".to_owned(),
                flags: O_WRONLY,
                mode: 0o600,
                gid: 0,
            })
            .await?,
    );
    evidence.mutation_mkdir_errno = errno_of(
        &client
            .call(Message::Tmkdir {
                dfid: root_fid,
                name: "made".to_owned(),
                mode: 0o700,
                gid: 0,
            })
            .await?,
    );
    Ok(())
}

/// (k) `list` without `read`: metadata is served, content is not.
async fn list_only_case(
    target: &Target,
    ca: &[u8],
    token: &str,
    evidence: &mut FsRealPathEvidence,
) -> Result<()> {
    let mut client = open_session(target, ca, token).await?;
    client.version(OFFERED_MSIZE).await?;
    let root_fid = 0_u32;
    client.attach(root_fid).await?;
    let fid = 1_u32;
    expect_walk(client.walk(root_fid, fid, &["sized.bin"]).await?, 1)?;
    match client.getattr(fid, GETATTR_BASIC).await? {
        Message::Rgetattr(attributes) => {
            evidence.list_only_getattr_size_matches = attributes.size == SIZED_FILE_BYTES;
        }
        other => return Err(unexpected("Rgetattr", &other)),
    }
    evidence.list_only_open_errno = errno_of(&client.lopen(fid, O_RDONLY).await?);
    client.close().await;
    Ok(())
}

/// (l) `read` without `list`: content is served, metadata and enumeration are
/// not.
async fn read_only_case(
    target: &Target,
    ca: &[u8],
    token: &str,
    evidence: &mut FsRealPathEvidence,
) -> Result<()> {
    let mut client = open_session(target, ca, token).await?;
    client.version(OFFERED_MSIZE).await?;
    let root_fid = 0_u32;
    client.attach(root_fid).await?;
    let fid = 1_u32;
    expect_walk(client.walk(root_fid, fid, &["only.bin"]).await?, 1)?;
    expect_open(client.lopen(fid, O_RDONLY).await?)?;
    let (bytes, _) = read_whole(&mut client, fid, READ_COUNT).await?;
    evidence.read_only_read_matches = bytes == synthetic_bytes(READ_ONLY_FILE_BYTES);
    evidence.read_only_getattr_errno = errno_of(&client.getattr(fid, GETATTR_BASIC).await?);
    expect_clunk(client.clunk(fid).await?)?;
    // A clone of the root rather than the root fid itself, so a refused open
    // cannot leave the session's own root in a half-open state.
    let dir_fid = 2_u32;
    expect_walk(client.walk(root_fid, dir_fid, &[]).await?, 0)?;
    evidence.read_only_directory_open_errno =
        errno_of(&client.lopen(dir_fid, O_RDONLY | O_DIRECTORY).await?);
    client.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> FsRealPathEvidence {
        FsRealPathEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            non_owner_node: "relay-c".into(),
            descriptor_status: 200,
            descriptor_content_type: "application/json".into(),
            descriptor_cache_control: "no-store".into(),
            descriptor_schema_version: SCHEMA_VERSION.into(),
            descriptor_subprotocol: SUBPROTOCOL.into(),
            descriptor_dialect: DIALECT.into(),
            descriptor_root_read_only: true,
            descriptor_operations: vec!["readFile".into()],
            descriptor_device_matches: true,
            descriptor_service_matches: true,
            descriptor_grant_revision_present: true,
            descriptor_host_path_leak: false,
            descriptor_identity_field_leak: false,
            empty_grant_status: 403,
            empty_grant_code: ACCESS_DENIED.into(),
            unsupported_host_status: 403,
            unsupported_host_code: ACCESS_DENIED.into(),
            unauthenticated_status: 401,
            unauthenticated_code: UNAUTHENTICATED.into(),
            unknown_device_status: 404,
            unknown_device_code: EXPORT_NOT_FOUND.into(),
            method_not_allowed_status: 405,
            stale_revision_status: 409,
            stale_revision_code: CAPABILITIES_CHANGED.into(),
            missing_subprotocol_status: 426,
            non_owner_upgrade_status: 503,
            non_owner_upgrade_code: BACKEND_UNAVAILABLE.into(),
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: OFFERED_MSIZE,
            negotiated_dialect: DIALECT.into(),
            attach_qid_is_directory: true,
            forged_uname_close_code: Some(PROTOCOL_VIOLATION_CLOSE),
            forged_uname_admitted: false,
            forged_afid_close_code: Some(PROTOCOL_VIOLATION_CLOSE),
            forged_afid_admitted: false,
            read_file_bytes: READ_FILE_BYTES as u64,
            read_observed_bytes: READ_FILE_BYTES as u64,
            read_checksum_matches: true,
            // Exactly at the boundary: one fewer must fail.
            read_messages: MIN_READ_MESSAGES,
            readdir_entries_expected: READDIR_ENTRIES,
            readdir_names_observed: READDIR_ENTRIES,
            readdir_pages: MIN_READDIR_PAGES,
            readdir_every_name_exactly_once: true,
            list_only_getattr_size_matches: true,
            list_only_open_errno: Some(EPERM),
            read_only_read_matches: true,
            read_only_getattr_errno: Some(EPERM),
            read_only_directory_open_errno: Some(EPERM),
            flush_rflush_observed: true,
            flush_victim_reply_observed: false,
            flush_replies_after_rflush: 0,
            flush_session_survived: true,
            fid_reuse_first_read_matches: true,
            fid_reuse_stale_read_errno: Some(EINVAL),
            fid_reuse_second_read_matches: true,
            mutation_write_open_errno: Some(EPERM),
            mutation_write_errno: Some(EINVAL),
            mutation_create_errno: Some(EPERM),
            mutation_mkdir_errno: Some(EPERM),
            mutation_host_unchanged: true,
            revision_advanced_in_catalog: true,
            revised_descriptor_status: 200,
            revised_revision_differs: true,
            superseded_descriptor_status: 409,
            superseded_descriptor_code: CAPABILITIES_CHANGED.into(),
            superseded_upgrade_status: 409,
            superseded_upgrade_code: CAPABILITIES_CHANGED.into(),
            current_revision_upgrade_admitted: true,
            revoked_session_served_before: true,
            revoked_session_closed: true,
            revoked_session_close_code: Some(AUTHORIZATION_CLOSE),
            revoked_session_replies_after: 0,
        }
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_fs_real_path_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsRealPathEvidence));
        let mutations: Vec<Mutation> = vec![
            ("relays", |e| e.relay_count = 2),
            ("one relay served both roles", |e| {
                e.non_owner_node = e.owner_node.clone();
            }),
            ("descriptor status", |e| e.descriptor_status = 204),
            ("descriptor content type", |e| {
                e.descriptor_content_type = "text/plain".into();
            }),
            ("descriptor caching", |e| {
                e.descriptor_cache_control = "max-age=60".into();
            }),
            ("descriptor schema", |e| {
                e.descriptor_schema_version = "agent-tunnel.fs.v2".into();
            }),
            ("descriptor subprotocol", |e| {
                e.descriptor_subprotocol = "agent-tunnel.echo.v1".into();
            }),
            ("descriptor dialect", |e| {
                e.descriptor_dialect = "9P2000.u".into();
            }),
            ("descriptor read-only", |e| {
                e.descriptor_root_read_only = false;
            }),
            ("descriptor operations", |e| {
                e.descriptor_operations.clear();
            }),
            ("descriptor device", |e| {
                e.descriptor_device_matches = false;
            }),
            ("descriptor service", |e| {
                e.descriptor_service_matches = false;
            }),
            ("descriptor revision", |e| {
                e.descriptor_grant_revision_present = false;
            }),
            ("descriptor host path", |e| {
                e.descriptor_host_path_leak = true;
            }),
            ("descriptor identity field", |e| {
                e.descriptor_identity_field_leak = true;
            }),
            ("empty grant", |e| e.empty_grant_status = 200),
            ("empty grant code", |e| {
                e.empty_grant_code = "EXPORT_NOT_FOUND".into();
            }),
            ("unsupported host", |e| e.unsupported_host_status = 200),
            ("unauthenticated", |e| e.unauthenticated_status = 403),
            ("unknown device", |e| e.unknown_device_status = 403),
            ("method", |e| e.method_not_allowed_status = 200),
            ("stale revision", |e| e.stale_revision_status = 200),
            ("subprotocol refusal", |e| {
                e.missing_subprotocol_status = 101;
            }),
            ("non-owner upgrade", |e| {
                e.non_owner_upgrade_status = 101;
            }),
            ("selected subprotocol", |e| {
                e.selected_subprotocol = String::new();
            }),
            ("negotiated dialect", |e| {
                e.negotiated_dialect = "9P2000".into();
            }),
            ("negotiated msize", |e| {
                e.negotiated_msize = OFFERED_MSIZE - 1;
            }),
            ("attach qid", |e| e.attach_qid_is_directory = false),
            ("forged uname admitted", |e| {
                e.forged_uname_admitted = true;
            }),
            ("forged afid close", |e| e.forged_afid_close_code = None),
            ("read bytes", |e| e.read_observed_bytes -= 1),
            ("read checksum", |e| e.read_checksum_matches = false),
            ("read messages", |e| e.read_messages -= 1),
            ("listing count", |e| e.readdir_names_observed -= 1),
            ("listing pages", |e| e.readdir_pages -= 1),
            ("listing duplicates", |e| {
                e.readdir_every_name_exactly_once = false;
            }),
            ("list-only stat", |e| {
                e.list_only_getattr_size_matches = false;
            }),
            ("list-only open", |e| e.list_only_open_errno = None),
            ("read-only read", |e| e.read_only_read_matches = false),
            ("read-only stat", |e| {
                e.read_only_getattr_errno = Some(EINVAL);
            }),
            ("read-only enumerate", |e| {
                e.read_only_directory_open_errno = Some(EINVAL);
            }),
            ("flush unanswered", |e| e.flush_rflush_observed = false),
            ("flushed tag answered", |e| {
                e.flush_victim_reply_observed = true;
            }),
            ("late reply after flush", |e| {
                e.flush_replies_after_rflush = 1;
            }),
            ("flush survival", |e| e.flush_session_survived = false),
            ("stale fid read answered", |e| {
                e.fid_reuse_stale_read_errno = None;
            }),
            ("mutation create", |e| e.mutation_create_errno = None),
            ("host changed", |e| e.mutation_host_unchanged = false),
            ("the catalog revision never moved", |e| {
                e.revision_advanced_in_catalog = false;
            }),
            ("the revised descriptor was refused", |e| {
                e.revised_descriptor_status = 409;
            }),
            ("the descriptor reported the same revision", |e| {
                e.revised_revision_differs = false;
            }),
            ("a superseded revision was served a descriptor", |e| {
                e.superseded_descriptor_status = 200;
            }),
            ("a superseded descriptor refusal named another code", |e| {
                e.superseded_descriptor_code = ACCESS_DENIED.into();
            }),
            ("a superseded revision was admitted an upgrade", |e| {
                e.superseded_upgrade_status = 101;
            }),
            ("a superseded upgrade refusal named another code", |e| {
                e.superseded_upgrade_code = BACKEND_UNAVAILABLE.into();
            }),
            ("the current revision was refused an upgrade", |e| {
                e.current_revision_upgrade_admitted = false;
            }),
            ("the revoked session never served anything", |e| {
                e.revoked_session_served_before = false;
            }),
            ("the revoked session stayed open", |e| {
                e.revoked_session_closed = false;
            }),
            ("the revoked session closed without a code", |e| {
                e.revoked_session_close_code = None;
            }),
            ("the revoked session closed as a protocol violation", |e| {
                e.revoked_session_close_code = Some(PROTOCOL_VIOLATION_CLOSE);
            }),
            ("a reply arrived after the revocation", |e| {
                e.revoked_session_replies_after = 1;
            }),
        ];
        for (name, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_fs_real_path_evidence(&evidence).is_err(),
                "mutation {name} passed"
            );
        }
    }

    #[test]
    fn synthetic_content_is_deterministic_and_checksum_detects_a_moved_byte() {
        let bytes = synthetic_bytes(1_024);
        assert_eq!(bytes, synthetic_bytes(1_024));
        assert_eq!(bytes[251], 0);
        let mut moved = bytes.clone();
        moved.swap(0, 1);
        assert_ne!(fnv1a(&bytes), fnv1a(&moved));
    }
}
