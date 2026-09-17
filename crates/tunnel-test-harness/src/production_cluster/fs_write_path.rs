//! Implementation gate 5 of `docs/filesystem-api.md` over the real cluster:
//! **write grants and partial failure**, through a consumer WSS 9P2000.L
//! session, the owning relay's public route, the owner actor, the device data
//! WebSocket and `tunnel-client`'s filesystem export.
//!
//! Gate 4's sibling gate proved the endpoint and the read path, and refused
//! every mutation at three layers; every refusal it could produce was
//! `not_started`. This gate is where a request can actually have happened, so
//! the questions it answers are different ones:
//!
//! * A **checksummed write** of a synthetic file large enough to span many
//!   `Twrite` messages, read back byte for byte on a fresh session, at exactly
//!   the length that was sent — a replayed chunk changes both.
//! * `Tlcreate`, `Tmkdir`, `Tunlinkat`, `Trenameat` and a size-changing
//!   `Tsetattr`, each observed on the host afterwards.
//! * A truncating open, whose truncation happens **through the descriptor**
//!   after the hard-link rule has permitted it.
//! * A **read-only grant refusing every mutating primitive before dispatch**,
//!   on its own export, with the host file unchanged.
//! * The **hard-link write refusal** on a genuinely multiply-linked file, with
//!   the content verified intact — the rule gate 2 pinned, reachable on a real
//!   write for the first time.
//! * A **write interrupted mid-stream**: the consumer drops its socket with
//!   writes outstanding, and a fresh session reads the file back. Every
//!   acknowledged byte is present and correct, nothing beyond what was sent
//!   exists, and no byte appears twice. That is the honest shape of "the
//!   outcome is reported accurately and nothing is replayed": the acknowledged
//!   prefix is a lower bound confirmed by replies, and the remainder is
//!   `unknown` — neither claimed applied nor claimed refused.
//! * A **host failure** — a directory the export may traverse and may not write
//!   to — surfacing `EACCES` with no name, no host path and no content anywhere
//!   in the session's bytes.
//!
//! Every byte of fixture content is synthetic and generated here; no evidence
//! field, log line or error message carries a path, a name or file content.

use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::time::timeout;
use tunnel_client::{
    ConnectOptions, FsExportSettings, LocalExport, LocalExportKind, http_forward::HttpHandlers,
};
use tunnel_fs_core::FsErrorCode;
use tunnel_fs_ninep::{
    Message, Qid,
    flags::{AT_REMOVEDIR, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, SETATTR_SIZE},
};
use uuid::Uuid;

use super::fs_wire as wire;
use wire::{NinepClient, Target, UpgradeFailure, errno_of, unexpected};

use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, SCENARIO_TIMEOUT, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::{Harness, HarnessError, HarnessOptions, Result};

/// The subprotocol the server must select.
const SUBPROTOCOL: &str = tunnel_fs_core::TRANSPORT_SUBPROTOCOL;

/// Denied by the grant, before the host was consulted.
const EPERM: u32 = FsErrorCode::Eperm.errno();
/// Denied by the host.
const EACCES: u32 = FsErrorCode::Eacces.errno();
/// A flag combination the profile refuses outright.
const ENOTSUP: u32 = FsErrorCode::Enotsup.errno();

/// The `msize` the gate offers, which is also the profile ceiling.
const OFFERED_MSIZE: u32 = tunnel_fs_ninep::MAX_MESSAGE_BYTES;
/// The largest payload one `Twrite` can carry under [`OFFERED_MSIZE`].
///
/// A `Twrite` body is `fid[4] offset[8] count[4] data[count]` after the
/// seven-byte header, so a full message leaves this much for the data.
const WRITE_CHUNK: usize = (OFFERED_MSIZE as usize) - 7 - 4 - 8 - 4;
/// The largest `count` an `Rread` can answer.
const READ_COUNT: u32 = OFFERED_MSIZE - tunnel_fs_ninep::COUNTED_REPLY_OVERHEAD;
/// The synthetic file the checksummed write covers.
///
/// Comfortably more than four maximum-size `Twrite` messages, so the
/// multi-message write path is exercised rather than assumed.
const WRITE_FILE_BYTES: usize = 393_216;
/// More than four `Twrite` messages must carry the file.
const MIN_WRITE_MESSAGES: usize = 5;
/// The file the truncating open empties.
const TRUNCATED_FILE_BYTES: usize = 8_192;
/// The size a `Tsetattr` resizes a file to.
const RESIZED_BYTES: u64 = 1_024;
/// The file the hard-link rule protects.
const LINKED_FILE_BYTES: usize = 2_048;
/// How many blocks the interrupted write pipelines before abandoning its
/// socket.
///
/// Enough that the device cannot have performed them all before the transport
/// goes away, and few enough that the run stays bounded. Each is a full-`msize`
/// write, so this is real host work rather than a sleep.
const INTERRUPT_BLOCKS: usize = 24;
/// How many replies the interrupted case reads before it drops the socket.
///
/// Above zero, so there is an acknowledged prefix to check, and well below
/// [`INTERRUPT_BLOCKS`], so there is an unacknowledged remainder for the
/// `unknown` half to be about.
const INTERRUPT_ACKS: usize = 4;
/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);

/// The bounded evidence one gate run produces.
///
/// Scalars, closed labels and identifier-free strings only: no path, no file
/// name, no content and no credential is representable here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsWritePathEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    // (a) a checksummed write spanning many messages, read back byte for byte.
    /// Whether the descriptor for the writable export reports a writable root.
    ///
    /// Derived from the grant by gate 1, so a `false` here would mean the
    /// advertised flag disagreed with what is enforced.
    pub descriptor_root_read_only: bool,
    /// Whether the descriptor advertises at least one mutating operation.
    pub descriptor_advertises_write: bool,
    pub write_file_bytes: u64,
    /// Bytes the device acknowledged across every `Rwrite`.
    pub write_acknowledged_bytes: u64,
    /// How many `Twrite` messages carried the file.
    pub write_messages: usize,
    /// Whether a **fresh session** read the file back byte for byte.
    ///
    /// A fresh session rather than the writing one: reading back through the
    /// same fid would be answered from the same descriptor, and what is being
    /// proven is the bytes on the host.
    pub write_readback_matches: bool,
    /// Whether the file's length on the host is exactly what was sent.
    ///
    /// The no-replay half: a chunk written twice lengthens the file, and a
    /// chunk written twice *at the same offset* changes nothing — which is why
    /// the checksum above is asserted as well as this.
    pub write_length_exact: bool,
    // (b) the name-changing primitives.
    pub create_observed_on_host: bool,
    pub mkdir_observed_on_host: bool,
    pub unlink_observed_on_host: bool,
    pub rename_observed_on_host: bool,
    pub rmdir_observed_on_host: bool,
    // (c) a truncating open, and a size-changing `Tsetattr`.
    pub truncate_emptied_the_file: bool,
    pub setattr_size_observed_on_host: bool,
    // (d) the read-only grant, on its own export.
    /// Every mutating primitive's errno, in the order the gate sends them.
    ///
    /// Each must be a pre-dispatch refusal, and the validator checks that
    /// rather than the list being non-empty.
    pub read_only_refusal_errnos: Vec<u32>,
    /// How many mutating primitives were attempted under the read-only grant.
    pub read_only_refusals_attempted: usize,
    /// Whether the read-only export's file is byte-for-byte unchanged after
    /// all of them.
    pub read_only_host_unchanged: bool,
    // (e) the hard-link write refusal, on a real multiply-linked file.
    /// Whether the fixture really has two links to one inode.
    ///
    /// Without this the rest of the case would prove only that a write was
    /// refused, not that the link count is why.
    pub hard_link_count_observed: u64,
    pub hard_link_write_open_errno: Option<u32>,
    pub hard_link_read_write_open_errno: Option<u32>,
    pub hard_link_truncate_open_errno: Option<u32>,
    pub hard_link_setattr_size_errno: Option<u32>,
    /// Whether the multiply-linked file's content is byte-for-byte intact.
    ///
    /// The half that matters for the truncating case: the refusal must not
    /// follow a truncation that already destroyed the content.
    pub hard_link_content_intact: bool,
    /// Whether a plain read of the same file still succeeds.
    pub hard_link_read_still_served: bool,
    // (f) a write interrupted mid-stream.
    pub interrupt_blocks_sent: usize,
    pub interrupt_acknowledged_bytes: u64,
    /// The file's length on the host after the socket went away.
    pub interrupt_host_bytes: u64,
    /// Whether every acknowledged byte is present and correct.
    pub interrupt_acknowledged_prefix_matches: bool,
    /// Whether the whole file is a prefix of the source.
    ///
    /// This is the no-replay assertion: a block applied twice would put the
    /// wrong bytes at some offset, and a block applied out of order would too.
    pub interrupt_is_source_prefix: bool,
    /// Whether the host holds no more than was sent.
    pub interrupt_within_sent_bytes: bool,
    /// Whether the gate re-sent anything after the interruption.
    ///
    /// **Always false, and structural rather than measured — which is worth
    /// saying plainly, because the prefix checks above cannot detect a replay
    /// and it would be easy to read them as if they could.** A `Twrite` is
    /// positioned, so a block re-applied at its own offset is byte-identical
    /// and leaves the file a perfect prefix of the source either way. What the
    /// prefix checks *do* catch is a block applied at the **wrong** offset or
    /// out of order, which is a different defect.
    ///
    /// The non-replay claim rests on two things that are not this field: no
    /// code path in this gate re-sends anything after the interruption, and no
    /// path in the dispatcher performs a queued request twice — `step` pops
    /// each entry once. The device-side counter that *would* measure it is
    /// `mutations_applied`, which is now published in the connector's status
    /// snapshot; reading it from a consumer is not possible, because there is
    /// no wire field for an outcome, and correlating it across a session the
    /// gate deliberately abandoned is not something this gate attempts.
    pub interrupt_replayed: bool,
    // (g) a host failure.
    pub host_failure_errno: Option<u32>,
    /// Whether any byte the session received carried the refused name, the
    /// directory's name or the host path.
    pub host_failure_leaked_a_name: bool,
    /// Whether the session survived the host failure and answered afterwards.
    pub host_failure_session_survived: bool,
}

/// Every rule gate 5 must satisfy. Returns the first violated one, so a
/// regression names the property rather than the run.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_fs_write_path_evidence(evidence: &FsWritePathEvidence) -> Result<()> {
    // The refusals a mutating primitive may meet under a `read`+`list` grant,
    // and the reason the set is exactly these three. All are taken **before**
    // the host, which is what makes every one of them `not_started`:
    //
    // * `EPERM` — gate 1's capability table, for a missing `write` or `delete`
    //   and for an unadvertised `symlinks` or `hardLinks` feature.
    // * `EINVAL` — gate 3's session, for a fid used in a way its state forbids:
    //   a `Twrite` needs a fid open for writing, and this grant cannot open
    //   one.
    // * `ENOTSUP` — gate 3's flag decoding, for a combination the profile
    //   refuses outright rather than one it lacks permission for.
    //
    // A code outside this set would mean a mutation reached the host under a
    // read-only grant, which is the failure this whole case exists to catch.
    const PRE_DISPATCH: [u32; 3] = [EPERM, FsErrorCode::Einval.errno(), ENOTSUP];

    let checks: [(&str, bool); 35] = [
        ("three relays", evidence.relay_count == 3),
        (
            "the session ran against the owning relay",
            !evidence.owner_node.is_empty(),
        ),
        (
            "the writable export's descriptor is not read-only",
            !evidence.descriptor_root_read_only,
        ),
        (
            "the writable export advertises a mutating operation",
            evidence.descriptor_advertises_write,
        ),
        (
            "the write covered the whole synthetic file",
            evidence.write_file_bytes == WRITE_FILE_BYTES as u64,
        ),
        (
            "every byte sent was acknowledged",
            evidence.write_acknowledged_bytes == WRITE_FILE_BYTES as u64,
        ),
        (
            "the write spanned more than four messages",
            evidence.write_messages >= MIN_WRITE_MESSAGES,
        ),
        (
            "a fresh session read the write back byte for byte",
            evidence.write_readback_matches,
        ),
        (
            "the written file is exactly as long as what was sent",
            evidence.write_length_exact,
        ),
        (
            "a create reached the host",
            evidence.create_observed_on_host,
        ),
        ("a mkdir reached the host", evidence.mkdir_observed_on_host),
        (
            "an unlink reached the host",
            evidence.unlink_observed_on_host,
        ),
        (
            "a rename reached the host",
            evidence.rename_observed_on_host,
        ),
        (
            "a directory removal reached the host",
            evidence.rmdir_observed_on_host,
        ),
        (
            "a truncating open emptied the file",
            evidence.truncate_emptied_the_file,
        ),
        (
            "a size-changing Tsetattr reached the host",
            evidence.setattr_size_observed_on_host,
        ),
        (
            "every mutating primitive was attempted under the read-only grant",
            evidence.read_only_refusals_attempted >= 10
                && evidence.read_only_refusal_errnos.len() == evidence.read_only_refusals_attempted,
        ),
        (
            "every read-only refusal was taken before dispatch",
            evidence
                .read_only_refusal_errnos
                .iter()
                .all(|errno| PRE_DISPATCH.contains(errno)),
        ),
        (
            // The contract: "Read-only policy denies every mutating opcode
            // **and flag**, including `O_TRUNC` on open." The first two
            // attempts are exactly those two flag shapes on an ordinary
            // unopened file, so `EPERM` here is the grant refusing a flag —
            // where `ENOTSUP` would mean the profile refused the combination
            // for some other reason and the grant was never consulted.
            "a mutating open flag is refused by the grant itself",
            evidence
                .read_only_refusal_errnos
                .first()
                .is_some_and(|errno| *errno == EPERM)
                && evidence
                    .read_only_refusal_errnos
                    .get(1)
                    .is_some_and(|errno| *errno == EPERM),
        ),
        (
            "the read-only export is byte-for-byte unchanged",
            evidence.read_only_host_unchanged,
        ),
        (
            "the hard-link fixture really has a second link",
            evidence.hard_link_count_observed >= 2,
        ),
        (
            "a write open of a multiply-linked file is EPERM",
            evidence.hard_link_write_open_errno == Some(EPERM),
        ),
        (
            "a read-write open of a multiply-linked file is EPERM",
            evidence.hard_link_read_write_open_errno == Some(EPERM),
        ),
        (
            "a truncating open of a multiply-linked file is EPERM",
            evidence.hard_link_truncate_open_errno == Some(EPERM),
        ),
        (
            "a size-changing Tsetattr on a multiply-linked file is EPERM",
            evidence.hard_link_setattr_size_errno == Some(EPERM),
        ),
        (
            "the multiply-linked file's content is intact",
            evidence.hard_link_content_intact,
        ),
        (
            "reading a multiply-linked file is unaffected",
            evidence.hard_link_read_still_served,
        ),
        (
            "the interrupted write pipelined every block",
            evidence.interrupt_blocks_sent == INTERRUPT_BLOCKS,
        ),
        (
            "the interrupted write acknowledged a prefix",
            evidence.interrupt_acknowledged_bytes > 0,
        ),
        (
            "every acknowledged byte survived the interruption",
            evidence.interrupt_acknowledged_prefix_matches
                && evidence.interrupt_host_bytes >= evidence.interrupt_acknowledged_bytes,
        ),
        (
            // What this catches is a block applied at the wrong offset or out
            // of order — **not** a replay, which a positioned write makes
            // invisible to any comparison of the result.
            "the interrupted file is a prefix of the source, so nothing landed out of place",
            evidence.interrupt_is_source_prefix,
        ),
        (
            "the interrupted file holds no more than was sent",
            evidence.interrupt_within_sent_bytes,
        ),
        (
            "nothing was re-sent after the interruption",
            !evidence.interrupt_replayed,
        ),
        (
            "a host permission failure surfaces EACCES",
            evidence.host_failure_errno == Some(EACCES),
        ),
        (
            "the host failure leaked no name and the session survived",
            !evidence.host_failure_leaked_a_name && evidence.host_failure_session_survived,
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "fs write-path gate failed: {rule}"
            )));
        }
    }
    Ok(())
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<FsWritePathEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("fs write harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result.and_then(|evidence| {
            validate_fs_write_path_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs write-path scenario exceeded its bounded deadline".into(),
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
/// 251 is prime and below 256, so the pattern aligns with no power of two the
/// transport or the `msize` uses. That is what makes the prefix checks below
/// mean something: a block written at the wrong offset, or written twice,
/// leaves bytes that do not match the source at that position.
fn synthetic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// FNV-1a over 64 bits. A checksum, not a digest.
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

/// The three exports this gate needs, each with only the content its own cases
/// use.
fn build_fixtures(harness: &RunningHarness) -> Result<Vec<Fixture>> {
    let mut fixtures = Vec::new();
    for label in ["write-full", "write-interrupted", "read-list"] {
        let service = harness.fs_service(label).ok_or_else(|| {
            HarnessError::InvalidInput(format!("the {label} filesystem export was not seeded"))
        })?;
        let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
        let root = directory.path();
        match label {
            "write-full" => {
                std::fs::write(
                    root.join("truncate.bin"),
                    synthetic_bytes(TRUNCATED_FILE_BYTES),
                )
                .map_err(HarnessError::Io)?;
                std::fs::write(
                    root.join("resize.bin"),
                    synthetic_bytes(TRUNCATED_FILE_BYTES),
                )
                .map_err(HarnessError::Io)?;
                std::fs::write(root.join("movable.bin"), synthetic_bytes(64))
                    .map_err(HarnessError::Io)?;
                std::fs::write(root.join("doomed.bin"), synthetic_bytes(64))
                    .map_err(HarnessError::Io)?;
                // The multiply-linked file, and its second name. The link is
                // made **out of band**: the profile refuses to create one
                // without the `hardLinks` feature, so a fixture built through
                // the wire would be proving something else.
                std::fs::write(root.join("linked.bin"), synthetic_bytes(LINKED_FILE_BYTES))
                    .map_err(HarnessError::Io)?;
                std::fs::hard_link(root.join("linked.bin"), root.join("linked-second.bin"))
                    .map_err(HarnessError::Io)?;
                // A directory the export may traverse and may not write to.
                // `0o500` is read and execute for the owner: the walk reaches
                // it and `openat` with `O_CREAT` inside it is `EACCES`.
                let locked = root.join("locked");
                std::fs::create_dir(&locked).map_err(HarnessError::Io)?;
                set_mode(&locked, 0o500)?;
            }
            "write-interrupted" => {
                // Nothing: the case creates its own file and then abandons the
                // socket, so an existing file would confuse "what is on the
                // host" with "what was there before".
            }
            // The read-only export the denial matrix runs against.
            _ => {
                std::fs::write(root.join("target.bin"), synthetic_bytes(256))
                    .map_err(HarnessError::Io)?;
                std::fs::create_dir(root.join("tree")).map_err(HarnessError::Io)?;
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

fn set_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(HarnessError::Io)
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<FsWritePathEvidence> {
    let mut evidence = FsWritePathEvidence {
        relay_count: cluster.relays.len(),
        ..FsWritePathEvidence::default()
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
        "m4-fs-write-canary",
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
                    // **The device's allowlist is the same for every export**,
                    // and it is the widest one: the narrowing the read-only
                    // case turns on is the relay's OPEN, derived from the
                    // grant. A difference configured here would let a refusal
                    // be credited to the connector's allowlist instead of to
                    // the grant, which is the thing being proven.
                    capabilities: vec![
                        "read".to_owned(),
                        "write".to_owned(),
                        "list".to_owned(),
                        "delete".to_owned(),
                    ],
                    // `atomicRename` because `Trenameat` needs it and
                    // `exclusiveCreate` because this implementation's create
                    // always is. **`hardLinks` is deliberately absent**: with
                    // it on, the `st_nlink` write refusal switches off, and
                    // that refusal is one of the things this gate exists to
                    // prove is reachable on a real write.
                    features: vec!["atomicRename".to_owned(), "exclusiveCreate".to_owned()],
                }),
            },
        );
    }
    device_profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;

    let mut client = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect_with_http_handlers(
            ConnectOptions::new(device_profile.config.clone()),
            HttpHandlers::new(),
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("fs write device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("fs write device: {error}")))?;

    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("fs write device readiness timed out".into()))?
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
        eprintln!(
            "fs write device status: {:?}",
            client.status_snapshot().phase
        );
        eprintln!("fs write partial evidence: {evidence:?}");
    }
    // The locked directory has to be writable again before the fixture's own
    // cleanup can remove it, and that has to happen whether the scenario
    // passed or failed.
    if let Some(writable) = fixtures
        .iter()
        .find(|fixture| fixture.label == "write-full")
    {
        let _ = set_mode(&writable.directory.path().join("locked"), 0o700);
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
    evidence: &mut FsWritePathEvidence,
) -> Result<()> {
    evidence.owner_node = await_owner(cluster, tenant_id, device_id, session_id).await?;
    let owner_relay = cluster.relay("relay-a")?;
    let owner_addr = owner_relay.consumer_addr()?;
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
    let writable = fixture("write-full")?;
    let target = |service: Uuid| Target {
        consumer_addr: owner_addr,
        device_id,
        service: service.to_string(),
    };

    // The descriptor a write grant produces, which is where `root.readOnly`
    // being *derived* from the grant becomes observable: gate 4's export
    // reported it true, and this one must report it false without anything
    // having configured the flag.
    descriptor_case(
        owner_addr,
        &ca,
        &token,
        device_id,
        writable.service_id,
        evidence,
    )
    .await?;

    // (a)-(c) Every mutation, on the writable export.
    let mut client = open_session(&target(writable.service_id), &ca, &token).await?;
    client.version(OFFERED_MSIZE).await?;
    let root_fid = 0_u32;
    client.attach(root_fid).await?;
    write_case(&mut client, root_fid, writable, evidence).await?;
    names_case(&mut client, root_fid, writable, evidence).await?;
    truncate_and_resize_case(&mut client, root_fid, writable, evidence).await?;
    hard_link_case(&mut client, root_fid, writable, evidence).await?;
    host_failure_case(&mut client, root_fid, evidence, writable).await?;
    client.close().await;

    // (d) The read-only grant, on its own export.
    read_only_case(
        &target(fixture("read-list")?.service_id),
        &ca,
        &token,
        fixture("read-list")?,
        evidence,
    )
    .await?;

    // (e) A write interrupted mid-stream, on an export nothing else touches.
    let interrupted = fixture("write-interrupted")?;
    interrupted_case(
        &target(interrupted.service_id),
        &ca,
        &token,
        interrupted,
        evidence,
    )
    .await?;
    Ok(())
}

/// The descriptor a write grant produces.
async fn descriptor_case(
    owner_addr: std::net::SocketAddr,
    ca: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    evidence: &mut FsWritePathEvidence,
) -> Result<()> {
    let path = format!("/v1/devices/{device_id}/services/{service_id}/fs");
    let (status, _, body) =
        super::fs_real_path::http_get(owner_addr, ca, "GET", &path, Some(token), &[]).await?;
    if status != 200 {
        return Err(HarnessError::Http(format!(
            "the writable export's descriptor answered HTTP {status}"
        )));
    }
    let descriptor: serde_json::Value =
        serde_json::from_slice(&body).map_err(HarnessError::Json)?;
    evidence.descriptor_root_read_only = descriptor
        .pointer("/root/readOnly")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    evidence.descriptor_advertises_write = descriptor
        .pointer("/operations")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|operation| operation.starts_with("write") || operation == "mkdir")
        });
    Ok(())
}

/// (a) A checksummed write spanning many messages, read back on a fresh fid.
async fn write_case(
    client: &mut NinepClient,
    root_fid: u32,
    fixture: &Fixture,
    evidence: &mut FsWritePathEvidence,
) -> Result<()> {
    let body = synthetic_bytes(WRITE_FILE_BYTES);
    evidence.write_file_bytes = body.len() as u64;

    // `Tlcreate` rebinds the parent fid to the file it makes, so the clone is
    // what is spent rather than the session's own root.
    let created = 1_u32;
    expect_walk(client.walk(root_fid, created, &[]).await?, 0)?;
    match client
        .call(Message::Tlcreate {
            fid: created,
            name: "written.bin".to_owned(),
            flags: O_WRONLY,
            mode: 0o644,
            gid: 0,
        })
        .await?
    {
        Message::Rlcreate { .. } => {}
        other => return Err(unexpected("Rlcreate", &other)),
    }

    let mut offset = 0_usize;
    let mut messages = 0_usize;
    while offset < body.len() {
        let end = (offset + WRITE_CHUNK).min(body.len());
        let count = match client
            .call(Message::Twrite {
                fid: created,
                offset: offset as u64,
                data: body[offset..end].to_vec(),
            })
            .await?
        {
            Message::Rwrite { count } => count as usize,
            other => return Err(unexpected("Rwrite", &other)),
        };
        if count == 0 {
            return Err(HarnessError::Process(
                "a Twrite acknowledged no bytes at all".into(),
            ));
        }
        messages += 1;
        offset += count;
    }
    evidence.write_acknowledged_bytes = offset as u64;
    evidence.write_messages = messages;
    expect_clunk(client.clunk(created).await?)?;

    // Read back through a **fresh fid**, so the bytes come from a descriptor
    // this session resolved again rather than from the one that wrote them.
    let reader = 2_u32;
    expect_walk(client.walk(root_fid, reader, &["written.bin"]).await?, 1)?;
    expect_open(client.lopen(reader, O_RDONLY).await?)?;
    let read_back = read_whole(client, reader, READ_COUNT).await?;
    expect_clunk(client.clunk(reader).await?)?;
    evidence.write_readback_matches =
        read_back.len() == body.len() && fnv1a(&read_back) == fnv1a(&body);

    // And on the host, at exactly the length that was sent: a replayed chunk
    // changes the length, the checksum, or both.
    let on_disk =
        std::fs::read(fixture.directory.path().join("written.bin")).map_err(HarnessError::Io)?;
    evidence.write_length_exact = on_disk.len() == body.len() && fnv1a(&on_disk) == fnv1a(&body);
    Ok(())
}

/// (b) Create, mkdir, rename, unlink and a directory removal.
async fn names_case(
    client: &mut NinepClient,
    root_fid: u32,
    fixture: &Fixture,
    evidence: &mut FsWritePathEvidence,
) -> Result<()> {
    let root = fixture.directory.path();
    let parent = 3_u32;
    expect_walk(client.walk(root_fid, parent, &[]).await?, 0)?;

    // A create, on a fid the session then clunks without writing: the file's
    // existence is the observation.
    match client
        .call(Message::Tlcreate {
            fid: parent,
            name: "created.bin".to_owned(),
            flags: O_WRONLY,
            mode: 0o600,
            gid: 0,
        })
        .await?
    {
        Message::Rlcreate { .. } => {}
        other => return Err(unexpected("Rlcreate", &other)),
    }
    evidence.create_observed_on_host = root.join("created.bin").is_file();
    expect_clunk(client.clunk(parent).await?)?;

    let dir_parent = 4_u32;
    expect_walk(client.walk(root_fid, dir_parent, &[]).await?, 0)?;
    match client
        .call(Message::Tmkdir {
            dfid: dir_parent,
            name: "made".to_owned(),
            mode: 0o755,
            gid: 0,
        })
        .await?
    {
        Message::Rmkdir { .. } => {}
        other => return Err(unexpected("Rmkdir", &other)),
    }
    evidence.mkdir_observed_on_host = root.join("made").is_dir();

    let made = 5_u32;
    expect_walk(client.walk(root_fid, made, &["made"]).await?, 1)?;
    match client
        .call(Message::Trenameat {
            olddirfid: dir_parent,
            oldname: "movable.bin".to_owned(),
            newdirfid: made,
            newname: "moved.bin".to_owned(),
        })
        .await?
    {
        Message::Rrenameat => {}
        other => return Err(unexpected("Rrenameat", &other)),
    }
    evidence.rename_observed_on_host =
        !root.join("movable.bin").exists() && root.join("made/moved.bin").is_file();

    match client
        .call(Message::Tunlinkat {
            dirfid: dir_parent,
            name: "doomed.bin".to_owned(),
            flags: 0,
        })
        .await?
    {
        Message::Runlinkat => {}
        other => return Err(unexpected("Runlinkat", &other)),
    }
    evidence.unlink_observed_on_host = !root.join("doomed.bin").exists();

    // A directory needs `AT_REMOVEDIR`, which gate 1 authorizes as its own
    // primitive; it has to be emptied first, which is the profile's own
    // non-recursive default.
    match client
        .call(Message::Tunlinkat {
            dirfid: made,
            name: "moved.bin".to_owned(),
            flags: 0,
        })
        .await?
    {
        Message::Runlinkat => {}
        other => return Err(unexpected("Runlinkat", &other)),
    }
    match client
        .call(Message::Tunlinkat {
            dirfid: dir_parent,
            name: "made".to_owned(),
            flags: AT_REMOVEDIR,
        })
        .await?
    {
        Message::Runlinkat => {}
        other => return Err(unexpected("Runlinkat", &other)),
    }
    evidence.rmdir_observed_on_host = !root.join("made").exists();
    expect_clunk(client.clunk(made).await?)?;
    expect_clunk(client.clunk(dir_parent).await?)?;
    Ok(())
}

/// (c) A truncating open, and a size-changing `Tsetattr`.
async fn truncate_and_resize_case(
    client: &mut NinepClient,
    root_fid: u32,
    fixture: &Fixture,
    evidence: &mut FsWritePathEvidence,
) -> Result<()> {
    let root = fixture.directory.path();
    let fid = 6_u32;
    expect_walk(client.walk(root_fid, fid, &["truncate.bin"]).await?, 1)?;
    expect_open(client.lopen(fid, O_WRONLY | O_TRUNC).await?)?;
    // The truncation happened **through the descriptor**, after the hard-link
    // rule permitted it: the resolving open carries no `O_TRUNC`, so a refused
    // write can never follow a truncation that already destroyed the content.
    let length = std::fs::metadata(root.join("truncate.bin"))
        .map_err(HarnessError::Io)?
        .len();
    evidence.truncate_emptied_the_file = length == 0;
    expect_clunk(client.clunk(fid).await?)?;

    let resize = 7_u32;
    expect_walk(client.walk(root_fid, resize, &["resize.bin"]).await?, 1)?;
    match client.call(setattr_size(resize, RESIZED_BYTES)).await? {
        Message::Rsetattr => {}
        other => return Err(unexpected("Rsetattr", &other)),
    }
    evidence.setattr_size_observed_on_host = std::fs::metadata(root.join("resize.bin"))
        .map_err(HarnessError::Io)?
        .len()
        == RESIZED_BYTES;
    expect_clunk(client.clunk(resize).await?)?;
    Ok(())
}

/// (e) The hard-link write refusal, on a real multiply-linked file.
async fn hard_link_case(
    client: &mut NinepClient,
    root_fid: u32,
    fixture: &Fixture,
    evidence: &mut FsWritePathEvidence,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let path = fixture.directory.path().join("linked.bin");
    let expected = synthetic_bytes(LINKED_FILE_BYTES);
    evidence.hard_link_count_observed = std::fs::metadata(&path).map_err(HarnessError::Io)?.nlink();

    let fid = 8_u32;
    expect_walk(client.walk(root_fid, fid, &["linked.bin"]).await?, 1)?;
    evidence.hard_link_write_open_errno = errno_of(&client.lopen(fid, O_WRONLY).await?);
    evidence.hard_link_read_write_open_errno = errno_of(&client.lopen(fid, O_RDWR).await?);
    evidence.hard_link_truncate_open_errno =
        errno_of(&client.lopen(fid, O_WRONLY | O_TRUNC).await?);
    evidence.hard_link_setattr_size_errno = errno_of(&client.call(setattr_size(fid, 0)).await?);

    // Intact, which is the half that matters for the truncating case.
    let after = std::fs::read(&path).map_err(HarnessError::Io)?;
    evidence.hard_link_content_intact =
        after.len() == expected.len() && fnv1a(&after) == fnv1a(&expected);

    // And reading is unaffected: the link count discloses nothing the grant
    // does not already permit.
    expect_open(client.lopen(fid, O_RDONLY).await?)?;
    let read_back = read_whole(client, fid, READ_COUNT).await?;
    evidence.hard_link_read_still_served =
        read_back.len() == expected.len() && fnv1a(&read_back) == fnv1a(&expected);
    expect_clunk(client.clunk(fid).await?)?;
    Ok(())
}

/// (g) A host failure the export cannot prevent, surfaced without a name.
async fn host_failure_case(
    client: &mut NinepClient,
    root_fid: u32,
    evidence: &mut FsWritePathEvidence,
    fixture: &Fixture,
) -> Result<()> {
    let locked = 9_u32;
    expect_walk(client.walk(root_fid, locked, &["locked"]).await?, 1)?;
    let reply = client
        .call(Message::Tlcreate {
            fid: locked,
            name: "denied.bin".to_owned(),
            flags: O_WRONLY,
            mode: 0o644,
            gid: 0,
        })
        .await?;
    evidence.host_failure_errno = errno_of(&reply);
    // The whole rendering of what came back, not just the code. An `Rlerror`
    // carries a `u32` and nothing else by construction, so this is the
    // demonstration of a property the type already has — and the host path is
    // checked too, because that is the one string a provider could plausibly
    // have interpolated.
    let rendered = format!("{reply:?}");
    let host_path = fixture.directory.path().to_string_lossy().into_owned();
    evidence.host_failure_leaked_a_name = rendered.contains("denied")
        || rendered.contains("locked")
        || rendered.contains(host_path.as_str());
    expect_clunk(client.clunk(locked).await?)?;

    // The session survives a refused request, which is the three-way split gate
    // 3 pinned: an `Rlerror` a correct client can recover from keeps the
    // session, where a framing or lifecycle violation closes it.
    let probe = 10_u32;
    expect_walk(client.walk(root_fid, probe, &["linked.bin"]).await?, 1)?;
    expect_clunk(client.clunk(probe).await?)?;
    evidence.host_failure_session_survived = true;
    Ok(())
}

/// (d) Every mutating primitive, refused before dispatch by a read-only grant.
async fn read_only_case(
    target: &Target,
    ca: &[u8],
    token: &str,
    fixture: &Fixture,
    evidence: &mut FsWritePathEvidence,
) -> Result<()> {
    let root = fixture.directory.path();
    let before = std::fs::read(root.join("target.bin")).map_err(HarnessError::Io)?;

    let mut client = open_session(target, ca, token).await?;
    client.version(OFFERED_MSIZE).await?;
    let root_fid = 0_u32;
    client.attach(root_fid).await?;
    let file = 1_u32;
    expect_walk(client.walk(root_fid, file, &["target.bin"]).await?, 1)?;
    let tree = 2_u32;
    expect_walk(client.walk(root_fid, tree, &["tree"]).await?, 1)?;
    // A second, unopened binding of the same file, so the two mutating
    // `Tlopen` shapes below are refused by the **grant** rather than by
    // anything else. Aiming them at the directory fid would have them refused
    // for its kind — gate 3 denies a writable `O_DIRECTORY` outright — and a
    // refusal that would have happened under a write grant too proves nothing
    // about the read-only one. Aiming them at `file` would meet the session's
    // "already open" rule instead. This binding meets neither.
    let unopened = 4_u32;
    expect_walk(client.walk(root_fid, unopened, &["target.bin"]).await?, 1)?;
    // Opened read-only, so the `Twrite` below is refused for the fid's *state*
    // rather than for the flags — which is the second of the three layers and
    // is what makes "the mutating flag is rejected before any backend access"
    // observable from a client.
    expect_open(client.lopen(file, O_RDONLY).await?)?;

    // Every mutating opcode the profile defines, plus the two mutating `Tlopen`
    // flag shapes, which are refusals of a *flag* rather than of an opcode.
    let mutations: Vec<Message> = vec![
        Message::Tlopen {
            fid: unopened,
            flags: O_WRONLY,
        },
        Message::Tlopen {
            fid: unopened,
            flags: O_WRONLY | O_TRUNC,
        },
        Message::Tlcreate {
            fid: tree,
            name: "created.bin".to_owned(),
            flags: O_WRONLY,
            mode: 0o644,
            gid: 0,
        },
        Message::Twrite {
            fid: file,
            offset: 0,
            data: vec![0x5a; 8],
        },
        Message::Tmkdir {
            dfid: tree,
            name: "sub".to_owned(),
            mode: 0o755,
            gid: 0,
        },
        Message::Tunlinkat {
            dirfid: root_fid,
            name: "target.bin".to_owned(),
            flags: 0,
        },
        Message::Trenameat {
            olddirfid: root_fid,
            oldname: "target.bin".to_owned(),
            newdirfid: tree,
            newname: "moved.bin".to_owned(),
        },
        setattr_size(file, 0),
        Message::Tsymlink {
            fid: tree,
            name: "alias".to_owned(),
            target: "target.bin".to_owned(),
            gid: 0,
        },
        Message::Tlink {
            dfid: tree,
            fid: file,
            name: "hard".to_owned(),
        },
    ];
    evidence.read_only_refusals_attempted = mutations.len();
    for mutation in mutations {
        let described = mutation.message_type();
        let reply = client.call(mutation).await?;
        let Some(errno) = errno_of(&reply) else {
            return Err(HarnessError::Process(format!(
                "{described} was admitted under a read-only grant"
            )));
        };
        evidence.read_only_refusal_errnos.push(errno);
    }
    // `Tremove` is last and on its own, because 9P releases its fid on either
    // answer and a refusal here would otherwise change the fid state every
    // later case depends on.
    let removable = 3_u32;
    expect_walk(client.walk(root_fid, removable, &["target.bin"]).await?, 1)?;
    let reply = client.call(Message::Tremove { fid: removable }).await?;
    if let Some(errno) = errno_of(&reply) {
        evidence.read_only_refusal_errnos.push(errno);
        evidence.read_only_refusals_attempted += 1;
    } else {
        return Err(HarnessError::Process(
            "Tremove was admitted under a read-only grant".into(),
        ));
    }
    client.close().await;

    let after = std::fs::read(root.join("target.bin")).map_err(HarnessError::Io)?;
    evidence.read_only_host_unchanged = before.len() == after.len()
        && fnv1a(&before) == fnv1a(&after)
        && !root.join("created.bin").exists()
        && !root.join("tree/sub").exists()
        && !root.join("tree/moved.bin").exists()
        && !root.join("tree/alias").exists()
        && !root.join("tree/hard").exists();
    Ok(())
}

/// (f) A write interrupted mid-stream, with no replay afterwards.
///
/// The arrangement is what makes this assertable. The consumer pipelines
/// [`INTERRUPT_BLOCKS`] full-`msize` writes back to back, reads only
/// [`INTERRUPT_ACKS`] replies, and then **abandons the transport** — no close
/// frame, no drain. Some of the remaining writes will have been performed on
/// the host and some will not, and the consumer can never learn which: that is
/// the contract's `unknown`, and the only honest thing to assert about it is
/// what must be true either way.
///
/// What must be true either way, and is:
///
/// * every **acknowledged** byte is on the host and correct — the acknowledged
///   prefix is `bytesAcknowledged`, a lower bound confirmed by replies;
/// * the whole file is a **prefix of the source** — a block applied twice, or
///   at the wrong offset, would put bytes there that do not match — though a
///   block replayed at its *own* offset would not, which is why non-replay is
///   claimed structurally below rather than measured here;
/// * the host holds **no more than was sent**;
/// * and nothing is re-sent — structurally, because there is no retry in this
///   function. A retry would be a second dispatch of a mutation whose first
///   dispatch is ambiguous, which is precisely what the contract forbids.
async fn interrupted_case(
    target: &Target,
    ca: &[u8],
    token: &str,
    fixture: &Fixture,
    evidence: &mut FsWritePathEvidence,
) -> Result<()> {
    let block = synthetic_bytes(INTERRUPT_BLOCKS * WRITE_CHUNK);
    let mut client = open_session(target, ca, token).await?;
    client.version(OFFERED_MSIZE).await?;
    let root_fid = 0_u32;
    client.attach(root_fid).await?;
    let created = 1_u32;
    expect_walk(client.walk(root_fid, created, &[]).await?, 0)?;
    match client
        .call(Message::Tlcreate {
            fid: created,
            name: "partial.bin".to_owned(),
            flags: O_WRONLY,
            mode: 0o644,
            gid: 0,
        })
        .await?
    {
        Message::Rlcreate { .. } => {}
        other => return Err(unexpected("Rlcreate", &other)),
    }

    // Every block goes out back to back with no reply awaited in between, so
    // the device sees one pipelined burst and cannot have finished it.
    let mut tags = Vec::with_capacity(INTERRUPT_BLOCKS);
    for index in 0..INTERRUPT_BLOCKS {
        let offset = index * WRITE_CHUNK;
        let tag = client
            .send(Message::Twrite {
                fid: created,
                offset: offset as u64,
                data: block[offset..offset + WRITE_CHUNK].to_vec(),
            })
            .await?;
        tags.push(tag);
    }
    evidence.interrupt_blocks_sent = tags.len();

    // Read only the first few replies. Each is an `Rwrite` whose count is what
    // the host acknowledged for that block.
    let mut acknowledged = 0_u64;
    for _ in 0..INTERRUPT_ACKS {
        let frame = client.recv_frame().await?;
        match frame.message {
            Message::Rwrite { count } => acknowledged += u64::from(count),
            other => return Err(unexpected("Rwrite", &other)),
        }
    }
    evidence.interrupt_acknowledged_bytes = acknowledged;

    // Gone, mid-stream, with writes still outstanding.
    client.abandon();

    // The device notices the transport is gone asynchronously, so the host is
    // polled until it stops changing rather than read once after a sleep: a
    // fixed wait would either be flaky or be a correctness signal, and this is
    // neither. What is bounded is the wait, not the result.
    let path = fixture.directory.path().join("partial.bin");
    let settled = await_settled(&path).await?;
    evidence.interrupt_host_bytes = settled.len() as u64;

    let acknowledged = usize::try_from(acknowledged).unwrap_or(0);
    evidence.interrupt_acknowledged_prefix_matches = settled.len() >= acknowledged
        && settled[..acknowledged.min(settled.len())] == block[..acknowledged.min(settled.len())];
    evidence.interrupt_is_source_prefix =
        settled.len() <= block.len() && settled[..] == block[..settled.len()];
    evidence.interrupt_within_sent_bytes = settled.len() <= block.len();
    // Nothing was re-sent. This is a **structural** claim about this function —
    // there is no retry in it — and not something the checks above measured: a
    // positioned write replayed at its own offset is byte-identical, so no
    // comparison of the resulting file could tell the two apart.
    evidence.interrupt_replayed = false;
    Ok(())
}

/// Read a file until its length stops changing, bounded.
///
/// Polls the real signal — the host's own file — and stops the moment it is
/// stable, so a slow run still passes and a run where the device kept writing
/// after its consumer vanished fails by the length check rather than by a sleep
/// that was too short.
async fn await_settled(path: &std::path::Path) -> Result<Vec<u8>> {
    /// How long the host may still be changing after the socket went away.
    const SETTLE_BOUND: Duration = Duration::from_secs(20);
    /// How long a length must hold before it counts as settled.
    const STABLE_FOR: Duration = Duration::from_millis(500);
    /// How often to look.
    const POLL: Duration = Duration::from_millis(50);

    let deadline = Instant::now() + SETTLE_BOUND;
    let mut last = usize::MAX;
    let mut stable_since = Instant::now();
    loop {
        let current = std::fs::read(path).map_err(HarnessError::Io)?;
        if current.len() == last {
            if stable_since.elapsed() >= STABLE_FOR {
                return Ok(current);
            }
        } else {
            last = current.len();
            stable_since = Instant::now();
        }
        if Instant::now() >= deadline {
            return Ok(current);
        }
        tokio::time::sleep(POLL).await;
    }
}

/// A `Tsetattr` naming only a new size.
///
/// The one mask bit the hard-link rule governs, and the only `Tsetattr` shape
/// this gate sends: mode and time changes are outside that rule by design, so
/// including one here would weaken what the refusal below demonstrates.
const fn setattr_size(fid: u32, size: u64) -> Message {
    Message::Tsetattr {
        fid,
        valid: SETATTR_SIZE,
        mode: 0,
        uid: 0,
        gid: 0,
        size,
        atime_sec: 0,
        atime_nsec: 0,
        mtime_sec: 0,
        mtime_nsec: 0,
    }
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
        tokio::time::sleep(Duration::from_millis(50)).await;
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

/// Read a whole open fid.
async fn read_whole(client: &mut NinepClient, fid: u32, count: u32) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        match client.read(fid, bytes.len() as u64, count).await? {
            Message::Rread { data } => {
                if data.is_empty() {
                    return Ok(bytes);
                }
                bytes.extend_from_slice(&data);
            }
            other => return Err(unexpected("Rread", &other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> FsWritePathEvidence {
        FsWritePathEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            descriptor_root_read_only: false,
            descriptor_advertises_write: true,
            write_file_bytes: WRITE_FILE_BYTES as u64,
            write_acknowledged_bytes: WRITE_FILE_BYTES as u64,
            // Exactly at the boundary: one fewer must fail.
            write_messages: MIN_WRITE_MESSAGES,
            write_readback_matches: true,
            write_length_exact: true,
            create_observed_on_host: true,
            mkdir_observed_on_host: true,
            unlink_observed_on_host: true,
            rename_observed_on_host: true,
            rmdir_observed_on_host: true,
            truncate_emptied_the_file: true,
            setattr_size_observed_on_host: true,
            read_only_refusal_errnos: vec![EPERM; 11],
            read_only_refusals_attempted: 11,
            read_only_host_unchanged: true,
            hard_link_count_observed: 2,
            hard_link_write_open_errno: Some(EPERM),
            hard_link_read_write_open_errno: Some(EPERM),
            hard_link_truncate_open_errno: Some(EPERM),
            hard_link_setattr_size_errno: Some(EPERM),
            hard_link_content_intact: true,
            hard_link_read_still_served: true,
            interrupt_blocks_sent: INTERRUPT_BLOCKS,
            interrupt_acknowledged_bytes: (INTERRUPT_ACKS * WRITE_CHUNK) as u64,
            interrupt_host_bytes: (INTERRUPT_ACKS * WRITE_CHUNK) as u64,
            interrupt_acknowledged_prefix_matches: true,
            interrupt_is_source_prefix: true,
            interrupt_within_sent_bytes: true,
            interrupt_replayed: false,
            host_failure_errno: Some(EACCES),
            host_failure_leaked_a_name: false,
            host_failure_session_survived: true,
        }
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_fs_write_path_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsWritePathEvidence));
        let mutations: Vec<Mutation> = vec![
            ("relays", |e| e.relay_count = 2),
            ("no owner", |e| e.owner_node = String::new()),
            ("the writable export advertised read-only", |e| {
                e.descriptor_root_read_only = true;
            }),
            ("the writable export advertised no mutation", |e| {
                e.descriptor_advertises_write = false;
            }),
            ("a short write went unnoticed", |e| {
                e.write_acknowledged_bytes -= 1;
            }),
            ("the write file shrank", |e| e.write_file_bytes -= 1),
            ("the write took fewer messages", |e| e.write_messages -= 1),
            ("the read-back differed", |e| {
                e.write_readback_matches = false;
            }),
            ("the written length was wrong", |e| {
                e.write_length_exact = false;
            }),
            ("no create", |e| e.create_observed_on_host = false),
            ("no mkdir", |e| e.mkdir_observed_on_host = false),
            ("no unlink", |e| e.unlink_observed_on_host = false),
            ("no rename", |e| e.rename_observed_on_host = false),
            ("no directory removal", |e| e.rmdir_observed_on_host = false),
            ("the truncate left bytes", |e| {
                e.truncate_emptied_the_file = false;
            }),
            ("the resize did not apply", |e| {
                e.setattr_size_observed_on_host = false;
            }),
            ("too few mutations were attempted read-only", |e| {
                e.read_only_refusal_errnos.pop();
                e.read_only_refusals_attempted -= 1;
                e.read_only_refusal_errnos.pop();
                e.read_only_refusals_attempted -= 1;
            }),
            ("a mutating open flag was refused for another reason", |e| {
                e.read_only_refusal_errnos[0] = ENOTSUP;
            }),
            ("a read-only refusal came from the host", |e| {
                // `EACCES` can only be the host's answer, so a refusal carrying
                // it means a mutation was dispatched under a read-only grant.
                e.read_only_refusal_errnos[0] = EACCES;
            }),
            ("a read-only mutation changed the host", |e| {
                e.read_only_host_unchanged = false;
            }),
            ("the fixture had only one link", |e| {
                e.hard_link_count_observed = 1;
            }),
            ("a multiply-linked write open was admitted", |e| {
                e.hard_link_write_open_errno = None;
            }),
            ("a multiply-linked read-write open was admitted", |e| {
                e.hard_link_read_write_open_errno = None;
            }),
            ("a multiply-linked truncating open was admitted", |e| {
                e.hard_link_truncate_open_errno = None;
            }),
            ("a multiply-linked resize was admitted", |e| {
                e.hard_link_setattr_size_errno = None;
            }),
            ("the multiply-linked file lost its content", |e| {
                e.hard_link_content_intact = false;
            }),
            ("reading a multiply-linked file was refused", |e| {
                e.hard_link_read_still_served = false;
            }),
            ("the interrupted write sent fewer blocks", |e| {
                e.interrupt_blocks_sent -= 1;
            }),
            ("the interrupted write acknowledged nothing", |e| {
                e.interrupt_acknowledged_bytes = 0;
            }),
            ("an acknowledged byte was lost", |e| {
                e.interrupt_acknowledged_prefix_matches = false;
            }),
            ("the host holds less than was acknowledged", |e| {
                e.interrupt_host_bytes = 1;
            }),
            ("the interrupted file is not a source prefix", |e| {
                e.interrupt_is_source_prefix = false;
            }),
            ("the host holds more than was sent", |e| {
                e.interrupt_within_sent_bytes = false;
            }),
            ("an ambiguous mutation was re-sent", |e| {
                e.interrupt_replayed = true;
            }),
            ("the host failure named another code", |e| {
                e.host_failure_errno = Some(EPERM);
            }),
            ("the host failure leaked a name", |e| {
                e.host_failure_leaked_a_name = true;
            }),
            ("the session did not survive the host failure", |e| {
                e.host_failure_session_survived = false;
            }),
        ];
        for (name, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_fs_write_path_evidence(&evidence).is_err(),
                "mutation {name} passed"
            );
        }
    }

    #[test]
    fn one_write_chunk_fits_inside_one_message() {
        // The arithmetic the pipelined cases depend on: a `Twrite` body is
        // `fid[4] offset[8] count[4] data[count]` after the seven-byte header,
        // so a chunk exactly this size fills a message and one byte more would
        // be refused by the framing rather than shortened.
        assert_eq!(WRITE_CHUNK + 7 + 4 + 8 + 4, OFFERED_MSIZE as usize);
        // And the file really does need more than the minimum number of
        // messages, so `write_messages >= MIN_WRITE_MESSAGES` is a bound the
        // run has to clear rather than one it clears by arithmetic.
        assert_eq!(
            WRITE_FILE_BYTES
                .div_ceil(WRITE_CHUNK)
                .max(MIN_WRITE_MESSAGES),
            WRITE_FILE_BYTES.div_ceil(WRITE_CHUNK)
        );
    }
}
