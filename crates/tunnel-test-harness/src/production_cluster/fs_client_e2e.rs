//! Implementation gate 6 of `docs/filesystem-api.md` over the real cluster:
//! the **actual `@agent-tunnel/client`**, run by `node`, against the production
//! relay's real descriptor endpoint and WSS upgrade, a real Redis catalog, a
//! real grant and a real device connector serving filesystem exports.
//!
//! Gates 4 and 5 drove the endpoint with a 9P client written in this crate.
//! That proves the endpoint and proves nothing about the published package,
//! which is what gate 6 says in terms it must prove: "compilation against a
//! source interface or a fake in-memory adapter is insufficient to claim remote
//! compatibility". Every socket in `packages/client`'s own tests is a loopback
//! socket to a harness that speaks the wire and is not the product. This gate
//! is the sentence that residue asked for.
//!
//! **How node is driven, and why a child process.** The client is TypeScript;
//! the cluster is Rust. The alternatives were to embed a JavaScript runtime in
//! the harness or to re-implement the client's behaviour here, and both give up
//! the only thing worth proving — that *the package* interoperates. So the
//! harness spawns `node` on `packages/client/e2e/gate.ts`, which imports that
//! package's own `src/` and reports newline-delimited JSON on stdout. Three
//! channels, each for what it carries:
//!
//! * a **plan file** named in argv, carrying the endpoints, one consumer token
//!   and the shape of the synthetic content — a file rather than an argument
//!   vector, so a token never appears in a process listing;
//! * **stdout**, one JSON object per line, ending in exactly one `report`;
//! * **stdin**, carrying `go` lines, which is how the two rendezvous below are
//!   made races the harness wins rather than sleeps.
//!
//! Every judgement is taken here, by [`validate_fs_client_e2e_evidence`],
//! against evidence that is scalars, counts and closed labels. A driver that
//! decided for itself what passing meant could not smuggle a verdict past it.
//!
//! What one run proves, in the order [`exercise`] takes it:
//!
//! * **TLS is real.** `node` verifies the relay's certificate against the
//!   fixture CA through `NODE_EXTRA_CA_CERTS`; `allowInsecureLoopback` is never
//!   passed, so an unverifiable chain is `INSECURE_ENDPOINT` and not a session.
//! * **The descriptor**, fetched by the client and validated by its own schema
//!   rules, naming the subprotocol, the dialect and an opaque grant revision.
//! * **The `grantRevision` header matters.** The client reads a descriptor, the
//!   harness moves the grant in the authoritative catalog, and the upgrade
//!   carrying the revision the client read is refused `409
//!   CAPABILITIES_CHANGED`. That is the only way to observe from outside that
//!   the header was sent at all.
//! * **An unauthenticated descriptor read** is `UNAUTHENTICATED`.
//! * **An outcome the client classifies `unknown`**, with the device's own
//!   ledger read beside it. This is gate 5's own residue: "there is no wire
//!   field for an outcome", so a dispatched mutation with no reply is `unknown`
//!   on this side and the device's counters are the only place the truth lives.
//! * **The authenticated upgrade**, its selected subprotocol and negotiated
//!   `msize`, a checksummed read spanning many `Rread` messages, a checksummed
//!   write spanning many `Twrite` messages verified on the host, and a
//!   directory listing with every name exactly once.
//! * **A read-only grant refusing mutations at both layers**: locally, because
//!   the descriptor does not advertise them, and on the device, through the raw
//!   session a custom 9P client would use — with the export unchanged after.
//! * **One adapter**, not only the raw client, driven end to end over the same
//!   sockets.
//!
//! Every byte of fixture content is synthetic and generated here; no evidence
//! field, log line or error message carries a path, a name or file content.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{sleep, timeout};
use tunnel_client::{
    ConnectOptions, ConnectionHandle, FsExportSettings, LocalExport, LocalExportKind,
    http_forward::HttpHandlers,
};
use uuid::Uuid;

use super::fs_real_path::http_get;
use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, SCENARIO_TIMEOUT, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::{Harness, HarnessError, HarnessOptions, Result};

/// The descriptor's schema identifier.
const SCHEMA_VERSION: &str = tunnel_fs_core::SCHEMA_VERSION;
/// The subprotocol the server must select and the client must verify.
const SUBPROTOCOL: &str = tunnel_fs_core::TRANSPORT_SUBPROTOCOL;
/// The dialect `Rversion` must name.
const DIALECT: &str = tunnel_fs_ninep::DIALECT;
/// The profile's `msize` ceiling, which is also what the descriptor advertises.
const OFFERED_MSIZE: u32 = tunnel_fs_ninep::MAX_MESSAGE_BYTES;

/// The synthetic file the checksummed read covers.  Comfortably more than four
/// maximum-size `Rread` messages.
const READ_FILE_BYTES: usize = 393_216;
/// The synthetic file the checksummed write covers, for the same reason.
const WRITE_FILE_BYTES: usize = 393_216;
/// More than four messages must carry each of them.
const MIN_MESSAGES: usize = 5;
/// Entries in the listed directory.
const LISTING_ENTRIES: usize = 40;
/// The file the read-only grant serves.
const READ_ONLY_FILE_BYTES: usize = 2_048;
/// The file the adapter reads.
const ADAPTER_READ_BYTES: usize = 4_096;
/// The file the adapter writes.
const ADAPTER_WRITE_BYTES: usize = 1_024;
/// How many writes the `unknown` case issues without awaiting any of them.
///
/// Below the 64-tag quota, so the refusal under test is the close rather than
/// the client's own local accounting, and well above one, so the ledger has
/// something to disagree about.
const UNKNOWN_WRITES: usize = 24;
/// How much each of those writes carries.  Half a maximum message, so the
/// framing is ordinary and the arithmetic against the host file is exact.
const UNKNOWN_CHUNK_BYTES: usize = 32_768;
/// How long the owner claim may take to land in the catalog.
const OWNER_WAIT: Duration = Duration::from_secs(30);
/// How long an authorization change may take to become observable.
///
/// A relay may hold an authorization snapshot for up to five seconds, so a
/// change is not visible instantly.  This is a bound on a wait that ends the
/// moment the real signal arrives, never a wait that is itself the signal.
const AUTHORIZATION_WAIT: Duration = Duration::from_secs(60);
/// How long to wait between polls of an authorization change.
const AUTHORIZATION_POLL: Duration = Duration::from_millis(100);
/// How long the device's completed exchange may take to reach its diagnostics.
const LEDGER_WAIT: Duration = Duration::from_secs(30);
/// How long one line of the driver's report may take to arrive.
const DRIVER_LINE_WAIT: Duration = Duration::from_secs(180);

/// The device's filesystem mutation ledger, as this gate reads it.
///
/// Counters and nothing else, which is what `ConnectionStatus::fs` is built to
/// be: no path, name, byte of content or credential is representable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceLedger {
    pub exchanges: u64,
    pub mutations_refused: u64,
    pub mutations_dispatched: u64,
    pub mutations_applied: u64,
    pub mutations_acknowledged: u64,
    pub mutation_failed: u64,
    pub mutation_partial: u64,
    pub mutation_unknown: u64,
    pub bytes_written: u64,
}

impl From<&tunnel_client::FsCounters> for DeviceLedger {
    fn from(counters: &tunnel_client::FsCounters) -> Self {
        Self {
            exchanges: counters.exchanges,
            mutations_refused: counters.mutations_refused,
            mutations_dispatched: counters.mutations_dispatched,
            mutations_applied: counters.mutations_applied,
            mutations_acknowledged: counters.mutations_acknowledged,
            mutation_failed: counters.mutation_failed,
            mutation_partial: counters.mutation_partial,
            mutation_unknown: counters.mutation_unknown,
            bytes_written: counters.bytes_written,
        }
    }
}

/// The bounded evidence one gate run produces.
///
/// Scalars, closed labels, counts and identifier-free strings only: no path, no
/// file name, no content and no credential is representable here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FsClientE2eEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    /// The module specifier the driver resolved for the client under test, as
    /// `node` produced it, compared against this repository's own path.
    pub client_module_path: String,
    pub client_module_is_the_package: bool,
    /// Whether `connectFilesystem` itself — not only the pieces it composes —
    /// was driven against the real endpoint.
    pub public_entry_point_used: bool,
    /// The relay this gate expects to own the device.
    pub expected_owner_node: String,
    /// Every endpoint the driver was given was `https:`, and the driver never
    /// passed `allowInsecureLoopback`.
    pub endpoints_all_https: bool,
    /// Cases the driver could not carry out.  Must be empty: a case that did
    /// not run must never read as a case that passed.
    pub driver_failures: Vec<String>,

    // (a) TLS, observed rather than assumed, and the descriptor.
    /// What the driver's own process saw for `NODE_TLS_REJECT_UNAUTHORIZED`.
    ///
    /// Must be `unset`. Setting it to `0` turns node's certificate verification
    /// off process-wide, and an earlier round of this gate passed with it set:
    /// the driver asserted a verified chain once a connect resolved, which is
    /// equally true of an unverified one. The harness removes it from the
    /// child's environment and refuses to run when its own environment sets it,
    /// and this field is what the child actually saw.
    pub node_tls_reject_unauthorized: String,
    /// The same, for the negative probe's process.
    pub probe_tls_reject_unauthorized: String,
    /// The probe process ran with no fixture CA at all.
    pub probe_extra_ca: String,
    /// The code the client produced for a certificate it could not verify.
    pub probe_code: String,
    pub probe_retryable: bool,
    pub descriptor_schema_version: String,
    pub descriptor_subprotocol: String,
    pub descriptor_dialect: String,
    pub descriptor_grant_revision_present: bool,
    pub descriptor_operations: Vec<String>,
    pub descriptor_read_only: bool,
    pub descriptor_availability: String,

    // (b) an unauthenticated descriptor read.
    pub unauthenticated_code: String,
    pub unauthenticated_outcome: String,

    // (c) the grant-revision header against a revision that really moved.
    pub revision_advanced_in_catalog: bool,
    pub revision_upgrade_status: u16,
    pub revision_upgrade_code: String,
    pub revision_upgrade_outcome: String,
    pub revision_upgrade_retryable: bool,

    // (d) the authenticated upgrade.
    pub selected_subprotocol: String,
    pub negotiated_msize: u32,
    pub session_lifecycle: String,

    // (e) a checksummed read spanning many messages.
    pub read_bytes: u64,
    pub read_checksum_matches: bool,
    pub read_messages: usize,

    // (f) a checksummed write spanning many messages, verified on the host.
    pub write_bytes: u64,
    pub write_messages: usize,
    pub write_acknowledgements: usize,
    pub write_host_bytes: u64,
    pub write_host_checksum_matches: bool,

    // (g) a directory listing.
    pub listing_names_observed: usize,
    pub listing_every_name_exactly_once: bool,

    // (h) a read-only grant refusing mutations at both layers.
    pub read_only_read_matches: bool,
    pub read_only_root_read_only: bool,
    pub read_only_advertises_no_mutation: bool,
    pub read_only_client_codes: Vec<String>,
    pub read_only_client_outcomes: Vec<String>,
    pub read_only_device_create_code: String,
    pub read_only_device_mkdir_code: String,
    pub read_only_device_unlink_code: String,
    pub read_only_device_open_write_code: String,
    pub read_only_device_outcomes: Vec<String>,
    pub read_only_any_retryable: bool,
    pub read_only_host_unchanged: bool,
    /// The device's ledger on both sides of the read-only exchange.
    ///
    /// The client reports an `Rlerror` to a mutation as `failed`, which gate 6
    /// pins as "the wire's floor rather than the device's ledger": the reply
    /// proves the request arrived and was answered, and no wire field says
    /// whether anything applied. These two readings are the other side of that
    /// sentence, and their delta is what the device actually knows.
    pub read_only_ledger_before: DeviceLedger,
    pub read_only_ledger_after: DeviceLedger,
    /// Mutations the device's ledger counts as refused before the host was
    /// touched, over that exchange.
    ///
    /// **It is zero, and that is a gap rather than a surprise.** The refusal is
    /// taken at admission, where no decoded primitive exists to classify the
    /// request as a mutation, so `Provider::refuse` counts only `errors_sent`.
    /// The validator pins the zero so a change to that behaviour is read rather
    /// than absorbed.
    pub read_only_device_refused: u64,
    /// Whether the device applied anything at all under a read-only grant.
    pub read_only_device_applied_anything: bool,
    /// Mutating requests the client could report no better than `failed` — the
    /// wire's floor — while the device applied nothing.
    ///
    /// Named for what it counts. An earlier round called this an overstatement
    /// "against the ledger", which it is not: the ledger's own refusal counter
    /// is zero for these (see [`FsClientE2eEvidence::read_only_device_refused`]
    /// and task row M4-16), so the comparison the name implied could not be
    /// made. What it is is a count of the client's reports at the floor, and
    /// the ledger half of the disagreement is the applied/dispatched/written
    /// zeroes beside it.
    pub read_only_client_reported_failed: usize,

    // (i) an outcome the client classifies `unknown`, beside the device's own
    // ledger.
    pub unknown_requests: usize,
    pub unknown_classified_unknown: usize,
    pub unknown_any_retryable: bool,
    pub unknown_client_acknowledged_bytes: u64,
    pub unknown_close_codes: Vec<u16>,
    /// The ledger before the first filesystem exchange.  All zero.
    pub ledger_before: DeviceLedger,
    /// The ledger once that one exchange has completed.
    pub ledger_after: DeviceLedger,
    /// `mutations_applied - mutations_acknowledged == mutation_unknown`, which
    /// gate 5 pins as an identity rather than a coincidence.
    pub ledger_identity_holds: bool,
    /// Bytes actually on the host afterwards.
    pub unknown_host_bytes: u64,
    /// Those bytes are the source pattern at their own offsets: nothing was
    /// applied twice, out of order, or beyond what was sent.
    pub unknown_host_pattern_matches: bool,
    /// The host holds exactly what the device's ledger says it wrote.
    pub unknown_host_matches_ledger: bool,
    /// What the device did and the client could not learn.  Recorded rather
    /// than required: the honest reading of this case is that the client
    /// declines to claim and the ledger is the only place the answer lives.
    pub device_applied_beyond_client_knowledge: u64,

    // (j) one adapter, not only the raw client.
    pub adapter_name: String,
    pub adapter_read_matches: bool,
    pub adapter_write_bytes: u64,
    pub adapter_listing_names: i64,
    pub adapter_stat_size_matches: bool,
    pub adapter_append_refused: String,
    pub adapter_host_write_matches: bool,
}

/// Every rule gate 6's end-to-end half must satisfy.  Returns the first
/// violated one, so a regression names the property rather than the run.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_fs_client_e2e_evidence(evidence: &FsClientE2eEvidence) -> Result<()> {
    let ledger = &evidence.ledger_after;
    let checks: [(&str, bool); 47] = [
        ("three relays", evidence.relay_count == 3),
        (
            "the session ran against the relay this gate attached the device to",
            !evidence.owner_node.is_empty() && evidence.owner_node == evidence.expected_owner_node,
        ),
        (
            "the driver ran the package's own sources",
            evidence.client_module_is_the_package && !evidence.client_module_path.is_empty(),
        ),
        (
            "the composed public entry point was driven, not only its pieces",
            evidence.public_entry_point_used,
        ),
        (
            "every endpoint the client was given was https",
            evidence.endpoints_all_https,
        ),
        (
            "every case the driver was asked for ran",
            evidence.driver_failures.is_empty(),
        ),
        (
            // Three facts, and none of them is "a connect resolved".
            "node could not have skipped certificate verification",
            evidence.node_tls_reject_unauthorized == "unset"
                && evidence.probe_tls_reject_unauthorized == "unset",
        ),
        (
            // The negative half. A verified chain being accepted says nothing
            // on its own; an unverifiable one being refused is what makes the
            // pair an observation about verification.
            "the same client refuses the same endpoint with the fixture CA withheld",
            evidence.probe_extra_ca == "unset"
                && evidence.probe_code == "INSECURE_ENDPOINT"
                && !evidence.probe_retryable,
        ),
        (
            "the descriptor carries this profile's schema version",
            evidence.descriptor_schema_version == SCHEMA_VERSION,
        ),
        (
            "the descriptor names this profile's subprotocol",
            evidence.descriptor_subprotocol == SUBPROTOCOL,
        ),
        (
            "the descriptor names this profile's dialect",
            evidence.descriptor_dialect == DIALECT,
        ),
        (
            "the descriptor carries an opaque grant revision",
            evidence.descriptor_grant_revision_present,
        ),
        (
            "the writable export advertises a mutating operation",
            evidence
                .descriptor_operations
                .iter()
                .any(|operation| operation == "writeStream"),
        ),
        (
            "the writable export's root is not read-only",
            !evidence.descriptor_read_only,
        ),
        (
            "the device is online",
            evidence.descriptor_availability == "online",
        ),
        (
            "an unsigned token is refused at discovery",
            evidence.unauthenticated_code == "UNAUTHENTICATED"
                && evidence.unauthenticated_outcome == "not_started",
        ),
        (
            "a real grant revision moved in the catalog",
            evidence.revision_advanced_in_catalog,
        ),
        (
            "an upgrade carrying the superseded revision is refused",
            evidence.revision_upgrade_status == 409
                && evidence.revision_upgrade_code == "CAPABILITIES_CHANGED",
        ),
        (
            // The outcome and the retryability come from the client's own
            // `upgradeRejectionError`, which is the function `connectFilesystem`
            // calls on this path — exported for this gate rather than copied,
            // so a driver cannot assert a constant it wrote itself.
            "that refusal happened before anything could be admitted",
            evidence.revision_upgrade_outcome == "not_started"
                && !evidence.revision_upgrade_retryable,
        ),
        (
            "the client observed the selected subprotocol",
            evidence.selected_subprotocol == SUBPROTOCOL,
        ),
        (
            "the negotiated msize is the profile ceiling",
            evidence.negotiated_msize == OFFERED_MSIZE,
        ),
        (
            "the session reached ready",
            evidence.session_lifecycle == "ready",
        ),
        (
            "the read covered every byte of the file",
            evidence.read_bytes == READ_FILE_BYTES as u64,
        ),
        (
            "the read checksum equals the written checksum",
            evidence.read_checksum_matches,
        ),
        (
            "the read spanned more than four messages",
            evidence.read_messages >= MIN_MESSAGES,
        ),
        (
            "the write sent every byte of the file",
            evidence.write_bytes == WRITE_FILE_BYTES as u64,
        ),
        (
            "the write spanned more than four messages, each of them acknowledged",
            evidence.write_messages >= MIN_MESSAGES
                && evidence.write_acknowledgements == evidence.write_messages,
        ),
        (
            "the host holds exactly the bytes the client sent",
            evidence.write_host_bytes == WRITE_FILE_BYTES as u64
                && evidence.write_host_checksum_matches,
        ),
        (
            "every directory entry was listed",
            evidence.listing_names_observed == LISTING_ENTRIES,
        ),
        (
            "every directory name appeared exactly once",
            evidence.listing_every_name_exactly_once,
        ),
        (
            "a read-only grant still serves its file",
            evidence.read_only_read_matches,
        ),
        (
            "a read-only grant derives a read-only root",
            evidence.read_only_root_read_only && evidence.read_only_advertises_no_mutation,
        ),
        (
            "the client refused every mutation it was asked for locally",
            evidence.read_only_client_codes.len() == 4
                && evidence
                    .read_only_client_codes
                    .iter()
                    .all(|code| code == "ENOTSUP"),
        ),
        (
            "nothing a client refused locally can have happened",
            evidence.read_only_client_outcomes.len() == 4
                && evidence
                    .read_only_client_outcomes
                    .iter()
                    .all(|outcome| outcome == "not_started"),
        ),
        (
            "the device refused every mutating primitive a raw session sent",
            evidence.read_only_device_create_code == "EPERM"
                && evidence.read_only_device_mkdir_code == "EPERM"
                && evidence.read_only_device_unlink_code == "EPERM"
                && evidence.read_only_device_open_write_code == "EPERM",
        ),
        (
            // The three mutating **opcodes** are answered `Rlerror`, and gate 6
            // pins that an `Rlerror` to a mutation is `failed` on this side:
            // the reply proves the request arrived and was answered, and no
            // wire field says whether anything applied. `not_started` there
            // would be a claim the client cannot make. The writable open is
            // `not_started` because opening for writing carries no effect —
            // `isMutatingRequest` splits `Tlopen` on `O_TRUNC`, which is gate
            // 5's own `Primitive::is_mutating` distinction. Both halves are
            // asserted exactly, because either one drifting would be a client
            // inventing or losing a distinction the wire has.
            "a refused mutation is reported at the wire's floor and no lower",
            evidence.read_only_device_outcomes == ["failed", "failed", "failed", "not_started"],
        ),
        (
            "the device applied nothing and wrote nothing under a read-only grant",
            !evidence.read_only_device_applied_anything
                && evidence.read_only_ledger_after.bytes_written
                    == evidence.read_only_ledger_before.bytes_written
                && evidence.read_only_ledger_after.mutations_dispatched
                    == evidence.read_only_ledger_before.mutations_dispatched,
        ),
        (
            // `FsCounters::mutations_refused` documents itself as "mutating
            // requests refused before the host was touched", and these three
            // are exactly that — and it does not move, because the refusal is
            // taken by gate 3's session in `Provider::accept`, which returns a
            // `SessionError` and never produces the decoded primitives the
            // ledger classifies a mutation from, so `refuse` can only count
            // `errors_sent`. **That is a defect, tracked as task row M4-16, and
            // this gate does not assert it either way.** An earlier round
            // pinned the counter at zero, which made the gate *require* the
            // provider to disagree with its own documentation and would have
            // turned the fix red. The value is recorded in the evidence and
            // read in the summary; what is asserted here is only the bound that
            // is true whether or not M4-16 lands.
            "the ledger's refusal counter never exceeds the mutations sent",
            evidence.read_only_device_refused <= 3,
        ),
        (
            "the ledger readings bracket exactly the read-only exchange",
            evidence.read_only_ledger_before.exchanges == 2
                && evidence.read_only_ledger_after.exchanges == 3,
        ),
        (
            "no refusal was reported retryable",
            !evidence.read_only_any_retryable,
        ),
        (
            "the read-only export is unchanged",
            evidence.read_only_host_unchanged,
        ),
        (
            "every dispatched unanswered mutation is unknown",
            evidence.unknown_requests == UNKNOWN_WRITES
                && evidence.unknown_classified_unknown == UNKNOWN_WRITES,
        ),
        (
            "an ambiguous mutation is never retryable",
            !evidence.unknown_any_retryable,
        ),
        (
            "the client acknowledged nothing it did not see acknowledged",
            evidence.unknown_client_acknowledged_bytes == 0,
        ),
        (
            "the ledger read covers exactly the one exchange this case made",
            evidence.ledger_before == DeviceLedger::default() && ledger.exchanges == 1,
        ),
        (
            // **The content of this rule is the host, not the identity.**
            // `mutations_acknowledged` and `mutation_unknown` are both gated on
            // the same undelivered-effect decision in the provider, so
            // `applied - acknowledged == unknown` cannot fail within one
            // session and proves nothing about this run; it is checked and
            // recorded because it is gate 5's stated invariant and a future
            // concurrent dispatcher could break it, not because it discriminates
            // here. What does discriminate is that the bytes on the host equal
            // the ledger's own `bytes_written` and lie at the source pattern's
            // offsets — so nothing was applied twice, out of order, or beyond
            // what was sent.
            "the host holds exactly what the device's ledger says it wrote",
            evidence.unknown_host_matches_ledger
                && evidence.unknown_host_pattern_matches
                && evidence.ledger_identity_holds
                && ledger.mutations_dispatched >= ledger.mutations_applied,
        ),
        (
            "one adapter drove the same sockets end to end",
            evidence.adapter_name == "mastra"
                && evidence.adapter_read_matches
                && evidence.adapter_write_bytes == ADAPTER_WRITE_BYTES as u64
                && evidence.adapter_host_write_matches
                && evidence.adapter_listing_names == 2
                && evidence.adapter_stat_size_matches
                && evidence.adapter_append_refused == "FilesystemError",
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "fs client end-to-end gate failed: {rule}"
            )));
        }
    }
    Ok(())
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<FsClientE2eEvidence> {
    let options = HarnessOptions::from_env()?.fs_services(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("fs client harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result.and_then(|evidence| {
            if let Err(error) = validate_fs_client_e2e_evidence(&evidence) {
                // The evidence is scalars, counts and closed labels by
                // construction, so printing all of it discloses nothing and is
                // the only way a failed rule can be diagnosed from a run.
                eprintln!("fs client evidence: {evidence:?}");
                return Err(error);
            }
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "fs client end-to-end scenario exceeded its bounded deadline".into(),
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
/// The driver generates the same bytes from the same rule, so nothing of the
/// content travels in the plan file.
fn synthetic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// FNV-1a over 64 bits.  A checksum, not a digest, and it needs no dependency.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The filesystem path inside a `file:` URL, or `None` for anything else.
///
/// `import.meta.resolve` answers a URL, and comparing a URL to a path would
/// compare two spellings of the same thing; this takes the path out so the
/// comparison can be made on canonicalised files.
fn url_path(url: &str) -> Option<PathBuf> {
    url.strip_prefix("file://").map(PathBuf::from)
}

/// The repository root, from this crate's own manifest directory.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// One export's temporary tree, kept alive for the whole run.
struct Fixture {
    label: &'static str,
    service_id: Uuid,
    directory: TempDir,
}

/// The five export roots, each with only the content its own case needs.
fn build_fixtures(harness: &RunningHarness) -> Result<Vec<Fixture>> {
    let mut fixtures = Vec::new();
    for label in [
        "client-rw",
        "client-ro",
        "client-revision",
        "client-unknown",
        "client-adapter",
    ] {
        let service = harness.fs_service(label).ok_or_else(|| {
            HarnessError::InvalidInput(format!("the {label} filesystem export was not seeded"))
        })?;
        let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
        let root = directory.path();
        match label {
            "client-rw" => {
                std::fs::write(root.join("big.bin"), synthetic_bytes(READ_FILE_BYTES))
                    .map_err(HarnessError::Io)?;
                let pages = root.join("pages");
                std::fs::create_dir(&pages).map_err(HarnessError::Io)?;
                for index in 0..LISTING_ENTRIES {
                    std::fs::write(pages.join(format!("entry-{index:02}")), [])
                        .map_err(HarnessError::Io)?;
                }
            }
            "client-ro" => {
                std::fs::write(root.join("only.bin"), synthetic_bytes(READ_ONLY_FILE_BYTES))
                    .map_err(HarnessError::Io)?;
            }
            "client-adapter" => {
                std::fs::write(root.join("source.bin"), synthetic_bytes(ADAPTER_READ_BYTES))
                    .map_err(HarnessError::Io)?;
            }
            // The revision export is never admitted past its upgrade, and the
            // `unknown` export's only file is the one the driver creates.
            _ => {
                std::fs::write(root.join("seed.bin"), synthetic_bytes(16))
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
) -> Result<FsClientE2eEvidence> {
    let mut evidence = FsClientE2eEvidence {
        relay_count: cluster.relays.len(),
        ..FsClientE2eEvidence::default()
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
        "m4-fs-client-canary",
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
                    // The same allowlist on every export, deliberately: the
                    // narrowing the read-only case turns on is the relay's
                    // OPEN, derived from the grant, so a difference configured
                    // here would credit the connector for the grant's refusal.
                    capabilities: vec![
                        "read".to_owned(),
                        "list".to_owned(),
                        "write".to_owned(),
                        "delete".to_owned(),
                    ],
                    features: Vec::new(),
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
            &client,
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
            "fs client device status: {:?}",
            client.status_snapshot().phase
        );
        eprintln!("fs client partial evidence: {evidence:?}");
    }
    let stop = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    scenario?;
    match stop {
        Ok(Ok(())) => Ok(evidence),
        Ok(Err(error)) => Err(HarnessError::Process(format!("device stop: {error}"))),
        Err(_) => Err(HarnessError::Timeout("device stop timed out".into())),
    }
}

/// One line of the driver's newline-delimited report.
#[derive(serde::Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
enum DriverEvent {
    /// The revision the client read, awaiting the catalog change.
    Descriptor { revision: String },
    /// Nothing has connected for the `unknown` case yet.
    UnknownStart,
    /// The `unknown` case is over — successfully or not — and the ledger may be
    /// read. The driver emits this from a `finally`, so a case that threw does
    /// not leave this side waiting on a rendezvous that never comes.
    UnknownDone,
    /// Nothing has connected for the read-only case yet.
    ReadOnlyStart,
    /// The read-only case is over, on either path.
    ReadOnlyDone,
    /// The negative TLS probe, from its own process.
    #[serde(rename_all = "camelCase")]
    TlsProbe {
        code: String,
        retryable: bool,
        node_tls_reject_unauthorized: String,
        extra_ca: String,
    },
    /// The one terminal line.
    Report { report: Box<DriverReport> },
}

/// What the driver reports.  Mirrors [`FsClientE2eEvidence`]'s driver-side half
/// field for field, and carries nothing else.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DriverReport {
    node_tls_reject_unauthorized: String,
    client_module_path: String,
    public_entry_point_used: bool,
    descriptor_schema_version: String,
    descriptor_subprotocol: String,
    descriptor_dialect: String,
    descriptor_grant_revision_present: bool,
    descriptor_operations: Vec<String>,
    descriptor_read_only: bool,
    descriptor_availability: String,
    unauthenticated_code: String,
    unauthenticated_outcome: String,
    revision_upgrade_status: u16,
    revision_upgrade_code: String,
    revision_upgrade_outcome: String,
    revision_upgrade_retryable: bool,
    selected_subprotocol: String,
    negotiated_msize: u32,
    session_lifecycle: String,
    read_bytes: u64,
    read_checksum_matches: bool,
    read_messages: usize,
    write_bytes: u64,
    write_messages: usize,
    write_acknowledgements: usize,
    listing_names_observed: usize,
    listing_every_name_exactly_once: bool,
    read_only_read_matches: bool,
    read_only_root_read_only: bool,
    read_only_advertises_no_mutation: bool,
    read_only_client_codes: Vec<String>,
    read_only_client_outcomes: Vec<String>,
    read_only_device_create_code: String,
    read_only_device_mkdir_code: String,
    read_only_device_unlink_code: String,
    read_only_device_open_write_code: String,
    read_only_device_outcomes: Vec<String>,
    read_only_any_retryable: bool,
    unknown_requests: usize,
    unknown_classified_unknown: usize,
    unknown_any_retryable: bool,
    unknown_client_acknowledged_bytes: u64,
    unknown_close_codes: Vec<u16>,
    adapter_name: String,
    adapter_read_matches: bool,
    adapter_write_bytes: u64,
    adapter_listing_names: i64,
    adapter_stat_size_matches: bool,
    adapter_append_refused: String,
    failures: Vec<String>,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn exercise(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    device_client: &ConnectionHandle,
    fixtures: &[Fixture],
    tenant_id: Uuid,
    device_id: Uuid,
    session_id: &str,
    evidence: &mut FsClientE2eEvidence,
) -> Result<()> {
    evidence.owner_node = await_owner(cluster, tenant_id, device_id, session_id).await?;
    let owner_relay = cluster.relay("relay-a")?;
    // The device attached to `relay-a`, and gate 4 admits a filesystem session
    // only at the relay that owns the device. Comparing the claim against that
    // node's own identifier is the check; a non-empty string would have been
    // satisfied by any owner at all, including one this gate did not arrange.
    evidence.expected_owner_node = owner_relay.node_id.clone();
    let owner_addr = owner_relay.consumer_addr()?;
    let ca = harness.pki.server_ca.certificate_der.clone();
    let principal = &harness.topology.consumers_a[0];
    let token = harness.oidc.issue_with(
        &principal.name,
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

    // The certificate the fixture issues carries `127.0.0.1` as an IP SAN, so
    // the endpoint names the address the relay actually listens on and node
    // verifies the chain against the fixture CA with no name to resolve and no
    // verification to disable.  Disabling verification is not available here
    // and would not be taken if it were: "TLS certificate verification is
    // mandatory outside the explicit loopback development harness", and this
    // client's own `allowInsecureLoopback` is exactly that harness and is never
    // passed by the driver.
    let endpoint = |service: Uuid| {
        format!(
            "https://127.0.0.1:{}/v1/devices/{device_id}/services/{service}/fs",
            owner_addr.port()
        )
    };
    let rw = fixture("client-rw")?;
    let ro = fixture("client-ro")?;
    let revision = fixture("client-revision")?;
    let unknown = fixture("client-unknown")?;
    let adapter = fixture("client-adapter")?;

    let listing_names = (0..LISTING_ENTRIES)
        .map(|index| format!("entry-{index:02}"))
        .collect::<Vec<_>>();
    let plan = serde_json::json!({
        "endpoints": {
            "readWrite": endpoint(rw.service_id),
            "readOnly": endpoint(ro.service_id),
            "revision": endpoint(revision.service_id),
            "unknown": endpoint(unknown.service_id),
            "adapter": endpoint(adapter.service_id),
        },
        "token": token,
        "read": {
            "path": "/big.bin",
            "bytes": READ_FILE_BYTES,
            "checksum": fnv1a(&synthetic_bytes(READ_FILE_BYTES)).to_string(),
        },
        "write": { "path": "/written.bin", "bytes": WRITE_FILE_BYTES },
        "listing": { "path": "/pages", "names": listing_names },
        "readOnlyCase": {
            "readPath": "/only.bin",
            "bytes": READ_ONLY_FILE_BYTES,
            "writePath": "/new.bin",
            "renameTo": "/moved.bin",
        },
        "unknownCase": {
            "path": "/pending.bin",
            "writes": UNKNOWN_WRITES,
            "chunkBytes": UNKNOWN_CHUNK_BYTES,
        },
        "adapterCase": {
            "readPath": "/source.bin",
            "bytes": ADAPTER_READ_BYTES,
            "writePath": "/copy.bin",
            "writeBytes": ADAPTER_WRITE_BYTES,
            "listing": ["source.bin", "copy.bin"],
        },
    });
    evidence.endpoints_all_https = plan["endpoints"].as_object().is_some_and(|endpoints| {
        endpoints.values().all(|value| {
            value
                .as_str()
                .is_some_and(|url| url.starts_with("https://"))
        })
    });

    // **Refuse to run at all if this process could hand the driver a way to skip
    // certificate verification.** Removing the variable from the child's
    // environment is not enough on its own: an operator who set it meant
    // something by it, and a gate that silently ignored it would be reporting a
    // verified chain in an environment configured not to verify. The child's
    // environment is scrubbed as well, and the driver reports what it saw.
    if std::env::var_os("NODE_TLS_REJECT_UNAUTHORIZED").is_some() {
        return Err(HarnessError::InvalidInput(
            "NODE_TLS_REJECT_UNAUTHORIZED is set in this environment; this gate proves \
             certificate verification and will not run where it can be skipped"
                .into(),
        ));
    }

    let work = tempfile::tempdir().map_err(HarnessError::Io)?;
    let plan_path = work.path().join("plan.json");
    write_private(
        &plan_path,
        &serde_json::to_vec(&plan).map_err(HarnessError::Json)?,
    )?;
    let ca_path = work.path().join("fixture-ca.pem");
    std::fs::write(&ca_path, harness.pki.server_ca.certificate_pem.as_bytes())
        .map_err(HarnessError::Io)?;

    let root = repository_root();
    let driver = root.join("packages/client/e2e/gate.ts");
    if !driver.is_file() {
        return Err(HarnessError::InvalidInput(
            "the gate-6 driver is not where this gate expects it".into(),
        ));
    }

    // The TLS negative probe, first and in its own process, because
    // `NODE_EXTRA_CA_CERTS` is read once at startup and cannot be withdrawn
    // inside a run. The same driver, the same endpoint, the same client — and
    // no fixture CA. It must be refused.
    tls_probe(&driver, &plan_path, evidence).await?;

    // Nothing has opened a filesystem session yet, so this reading is zero and
    // is asserted to be: it is what makes the `unknown` case's ledger a delta
    // from nothing rather than a number that has to be disentangled from every
    // other case's writes. The probe opens none: it is refused at TLS.
    evidence.ledger_before = DeviceLedger::from(&device_client.status_snapshot().fs);

    let mut child = tokio::process::Command::new("node")
        .arg(&driver)
        .arg(&plan_path)
        .env("NODE_EXTRA_CA_CERTS", &ca_path)
        // A driver that inherited a proxy would not be speaking to this relay.
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("NODE_OPTIONS")
        // The one that made an earlier round's TLS claim vacuous.
        .env_remove("NODE_TLS_REJECT_UNAUTHORIZED")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            HarnessError::Process(format!("spawning the gate-6 node driver: {error}"))
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| HarnessError::Process("the node driver has no stdin".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| HarnessError::Process("the node driver has no stdout".into()))?;
    let mut lines = BufReader::new(stdout).lines();

    let mut report: Option<DriverReport> = None;
    let mut plan_removed = false;
    loop {
        let line = timeout(DRIVER_LINE_WAIT, lines.next_line())
            .await
            .map_err(|_| HarnessError::Timeout("the node driver stopped reporting".into()))?
            .map_err(HarnessError::Io)?;
        let Some(line) = line else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }
        if !plan_removed {
            // The driver's first event proves it has read the plan, and the
            // plan is the one file in this run that holds a consumer token.
            // The temporary directory is removed on the ordinary path anyway;
            // this narrows the window in which a `SIGKILL` of the harness could
            // leave the token on disk to the driver's own startup.
            let _ = std::fs::remove_file(&plan_path);
            plan_removed = true;
        }
        let event: DriverEvent = serde_json::from_str(&line).map_err(HarnessError::Json)?;
        match event {
            DriverEvent::Descriptor { revision: cached } => {
                // The client has read a descriptor and is holding at the
                // upgrade.  Move the grant in the authoritative catalog, wait
                // for a fresh descriptor to report the change, and only then
                // release it: the header the client is about to send names a
                // revision that no longer exists, which is the only way to see
                // from outside that it sends one at all.
                advance_revision(
                    cluster,
                    harness,
                    owner_addr,
                    &ca,
                    &token,
                    device_id,
                    revision.service_id,
                    &cached,
                    evidence,
                )
                .await?;
                release(&mut stdin).await?;
            }
            DriverEvent::UnknownStart => {
                release(&mut stdin).await?;
            }
            DriverEvent::UnknownDone => {
                // The `unknown` case is the first exchange this device serves,
                // so one completed exchange is exactly it.
                evidence.ledger_after = await_exchanges(device_client, 1).await?;
                release(&mut stdin).await?;
            }
            DriverEvent::TlsProbe { .. } => {
                // Read from the probe's own process, not this one.
            }
            DriverEvent::ReadOnlyStart => {
                // Two exchanges have completed by now — the `unknown` case and
                // the read-write one — and waiting for the count to reach two
                // is what makes this reading a boundary rather than a guess
                // about how far the device has got.
                evidence.read_only_ledger_before = await_exchanges(device_client, 2).await?;
                release(&mut stdin).await?;
            }
            DriverEvent::ReadOnlyDone => {
                evidence.read_only_ledger_after = await_exchanges(device_client, 3).await?;
                release(&mut stdin).await?;
            }
            DriverEvent::Report { report: reported } => {
                report = Some(*reported);
            }
        }
    }
    let status = timeout(CLEANUP_TIMEOUT, child.wait())
        .await
        .map_err(|_| HarnessError::Timeout("the node driver did not exit".into()))?
        .map_err(HarnessError::Io)?;
    if !status.success() {
        return Err(HarnessError::Process(
            "the node driver exited with a failure".into(),
        ));
    }
    let report =
        report.ok_or_else(|| HarnessError::Process("the node driver produced no report".into()))?;
    absorb(&report, evidence);

    // What the host holds, which is the half no client can report about itself.
    let rw_root = rw.directory.path();
    let written = std::fs::read(rw_root.join("written.bin")).unwrap_or_default();
    evidence.write_host_bytes = written.len() as u64;
    evidence.write_host_checksum_matches =
        fnv1a(&written) == fnv1a(&synthetic_bytes(WRITE_FILE_BYTES));

    let ro_root = ro.directory.path();
    let ro_entries = std::fs::read_dir(ro_root)
        .map_err(HarnessError::Io)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    let ro_content = std::fs::read(ro_root.join("only.bin")).unwrap_or_default();
    evidence.read_only_host_unchanged = ro_entries.len() == 1
        && ro_entries.contains("only.bin")
        && ro_content == synthetic_bytes(READ_ONLY_FILE_BYTES);

    let pending = std::fs::read(unknown.directory.path().join("pending.bin")).unwrap_or_default();
    evidence.unknown_host_bytes = pending.len() as u64;
    let chunk = synthetic_bytes(UNKNOWN_CHUNK_BYTES);
    evidence.unknown_host_pattern_matches = pending.len() <= UNKNOWN_WRITES * UNKNOWN_CHUNK_BYTES
        && pending
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == chunk[index % UNKNOWN_CHUNK_BYTES]);
    let ledger = evidence.ledger_after;
    evidence.ledger_identity_holds = ledger
        .mutations_applied
        .saturating_sub(ledger.mutations_acknowledged)
        == ledger.mutation_unknown;
    evidence.unknown_host_matches_ledger = evidence.unknown_host_bytes == ledger.bytes_written;
    evidence.device_applied_beyond_client_knowledge = ledger
        .bytes_written
        .saturating_sub(evidence.unknown_client_acknowledged_bytes);

    // The read-only exchange, as the device recorded it.
    let before = evidence.read_only_ledger_before;
    let after = evidence.read_only_ledger_after;
    evidence.read_only_device_refused = after
        .mutations_refused
        .saturating_sub(before.mutations_refused);
    evidence.read_only_device_applied_anything = after.mutations_applied > before.mutations_applied;
    evidence.read_only_client_reported_failed = evidence
        .read_only_device_outcomes
        .iter()
        .filter(|outcome| *outcome == "failed")
        .count();
    // The path `node` resolved for the client, compared against this
    // repository's own file. A file-exists check would have said only that a
    // package is present somewhere; this says the module the driver loaded is
    // that file.
    let expected_module = std::fs::canonicalize(root.join("packages/client/src/index.ts")).ok();
    let resolved_module =
        url_path(&evidence.client_module_path).and_then(|path| std::fs::canonicalize(path).ok());
    evidence.client_module_is_the_package =
        expected_module.is_some() && expected_module == resolved_module;

    let adapter_written =
        std::fs::read(adapter.directory.path().join("copy.bin")).unwrap_or_default();
    evidence.adapter_host_write_matches = adapter_written == synthetic_bytes(ADAPTER_WRITE_BYTES);

    // Counters and closed labels, so this line is safe to print and is the one
    // an operator reads when the client's view and the device's differ.
    eprintln!(
        "fs client end-to-end: the client classified {} of {} dispatched writes unknown and \
         acknowledged {} bytes; the device's ledger reports {} dispatched, {} applied, {} \
         acknowledged, {} unknown and {} bytes written",
        evidence.unknown_classified_unknown,
        evidence.unknown_requests,
        evidence.unknown_client_acknowledged_bytes,
        ledger.mutations_dispatched,
        ledger.mutations_applied,
        ledger.mutations_acknowledged,
        ledger.mutation_unknown,
        ledger.bytes_written,
    );
    Ok(())
}

/// Copy the driver's half of the report into the evidence.
fn absorb(report: &DriverReport, evidence: &mut FsClientE2eEvidence) {
    evidence.driver_failures = report.failures.clone();
    evidence.node_tls_reject_unauthorized = report.node_tls_reject_unauthorized.clone();
    evidence.client_module_path = report.client_module_path.clone();
    evidence.public_entry_point_used = report.public_entry_point_used;
    evidence.descriptor_schema_version = report.descriptor_schema_version.clone();
    evidence.descriptor_subprotocol = report.descriptor_subprotocol.clone();
    evidence.descriptor_dialect = report.descriptor_dialect.clone();
    evidence.descriptor_grant_revision_present = report.descriptor_grant_revision_present;
    evidence.descriptor_operations = report.descriptor_operations.clone();
    evidence.descriptor_read_only = report.descriptor_read_only;
    evidence.descriptor_availability = report.descriptor_availability.clone();
    evidence.unauthenticated_code = report.unauthenticated_code.clone();
    evidence.unauthenticated_outcome = report.unauthenticated_outcome.clone();
    evidence.revision_upgrade_status = report.revision_upgrade_status;
    evidence.revision_upgrade_code = report.revision_upgrade_code.clone();
    evidence.revision_upgrade_outcome = report.revision_upgrade_outcome.clone();
    evidence.revision_upgrade_retryable = report.revision_upgrade_retryable;
    evidence.selected_subprotocol = report.selected_subprotocol.clone();
    evidence.negotiated_msize = report.negotiated_msize;
    evidence.session_lifecycle = report.session_lifecycle.clone();
    evidence.read_bytes = report.read_bytes;
    evidence.read_checksum_matches = report.read_checksum_matches;
    evidence.read_messages = report.read_messages;
    evidence.write_bytes = report.write_bytes;
    evidence.write_messages = report.write_messages;
    evidence.write_acknowledgements = report.write_acknowledgements;
    evidence.listing_names_observed = report.listing_names_observed;
    evidence.listing_every_name_exactly_once = report.listing_every_name_exactly_once;
    evidence.read_only_read_matches = report.read_only_read_matches;
    evidence.read_only_root_read_only = report.read_only_root_read_only;
    evidence.read_only_advertises_no_mutation = report.read_only_advertises_no_mutation;
    evidence.read_only_client_codes = report.read_only_client_codes.clone();
    evidence.read_only_client_outcomes = report.read_only_client_outcomes.clone();
    evidence.read_only_device_create_code = report.read_only_device_create_code.clone();
    evidence.read_only_device_mkdir_code = report.read_only_device_mkdir_code.clone();
    evidence.read_only_device_unlink_code = report.read_only_device_unlink_code.clone();
    evidence.read_only_device_open_write_code = report.read_only_device_open_write_code.clone();
    evidence.read_only_device_outcomes = report.read_only_device_outcomes.clone();
    evidence.read_only_any_retryable = report.read_only_any_retryable;
    evidence.unknown_requests = report.unknown_requests;
    evidence.unknown_classified_unknown = report.unknown_classified_unknown;
    evidence.unknown_any_retryable = report.unknown_any_retryable;
    evidence.unknown_client_acknowledged_bytes = report.unknown_client_acknowledged_bytes;
    evidence.unknown_close_codes = report.unknown_close_codes.clone();
    evidence.adapter_name = report.adapter_name.clone();
    evidence.adapter_read_matches = report.adapter_read_matches;
    evidence.adapter_write_bytes = report.adapter_write_bytes;
    evidence.adapter_listing_names = report.adapter_listing_names;
    evidence.adapter_stat_size_matches = report.adapter_stat_size_matches;
    evidence.adapter_append_refused = report.adapter_append_refused.clone();
}

/// Move the grant's revision in the catalog and wait for the change to be
/// observable in a fresh descriptor.
///
/// The re-grant names the same operations as the seed: the point being proven
/// is the revision, so a capability difference here would let the refusal be
/// credited to a lost permission instead.
#[allow(clippy::too_many_arguments)]
async fn advance_revision(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    owner_addr: std::net::SocketAddr,
    ca: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    cached: &str,
    evidence: &mut FsClientE2eEvidence,
) -> Result<()> {
    if cached.is_empty() {
        return Err(HarnessError::Process(
            "the client read a descriptor with no grant revision".into(),
        ));
    }
    let principal = &harness.topology.consumers_a[0];
    let service = harness.fs_service("client-revision").ok_or_else(|| {
        HarnessError::InvalidInput("the revision filesystem export was not seeded".into())
    })?;
    let snapshot = cluster
        .catalog
        .upsert_grant(&tunnel_catalog::GrantSpec {
            tenant_id: principal.tenant_id,
            principal_id: principal.id,
            device_id,
            service_id,
            permissions: tunnel_catalog::PermissionSet {
                operations: service
                    .operations
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

    // Bounded by a deadline, not by a fixed wait: the loop ends the moment a
    // descriptor reports the new revision, and a change that never becomes
    // observable fails by name.
    let path = format!("/v1/devices/{device_id}/services/{service_id}/fs");
    let deadline = Instant::now() + AUTHORIZATION_WAIT;
    loop {
        let (status, _, body) = http_get(owner_addr, ca, "GET", &path, Some(token), &[]).await?;
        let current = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/grantRevision")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        if status == 200 && !current.is_empty() && current != cached {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "the revised grant revision never reached the descriptor".into(),
            ));
        }
        sleep(AUTHORIZATION_POLL).await;
    }
}

/// Write a file only this user can read.
///
/// The plan carries a consumer token, and a world-readable temporary file is a
/// worse place for one than a process environment.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).map_err(HarnessError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(HarnessError::Io)?;
    }
    Ok(())
}

/// The TLS negative probe: the same driver, the same endpoint, no fixture CA.
///
/// This is the half that makes "the client verified the relay's certificate" an
/// observation. A connect that resolves says only that *something* answered; it
/// is equally true when verification is off. So the same client is pointed at
/// the same endpoint in a process that cannot build a chain to the fixture CA,
/// and must refuse with `INSECURE_ENDPOINT` -- which this client deliberately
/// distinguishes from an outage and never marks retryable, since retrying
/// reaches the same untrusted peer.
async fn tls_probe(
    driver: &Path,
    plan_path: &Path,
    evidence: &mut FsClientE2eEvidence,
) -> Result<()> {
    let output = timeout(
        DRIVER_LINE_WAIT,
        tokio::process::Command::new("node")
            .arg(driver)
            .arg(plan_path)
            .arg("--tls-probe")
            .env_remove("NODE_EXTRA_CA_CERTS")
            .env_remove("NODE_TLS_REJECT_UNAUTHORIZED")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("NODE_OPTIONS")
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("the TLS probe did not finish".into()))?
    .map_err(|error| HarnessError::Process(format!("spawning the TLS probe: {error}")))?;
    if !output.status.success() {
        return Err(HarnessError::Process(
            "the TLS probe exited with a failure".into(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| HarnessError::Process("the TLS probe reported nothing".into()))?;
    match serde_json::from_str::<DriverEvent>(line).map_err(HarnessError::Json)? {
        DriverEvent::TlsProbe {
            code,
            retryable,
            node_tls_reject_unauthorized,
            extra_ca,
        } => {
            evidence.probe_code = code;
            evidence.probe_retryable = retryable;
            evidence.probe_tls_reject_unauthorized = node_tls_reject_unauthorized;
            evidence.probe_extra_ca = extra_ca;
            Ok(())
        }
        _ => Err(HarnessError::Process(
            "the TLS probe reported something other than a probe result".into(),
        )),
    }
}

/// Release the driver from a rendezvous.
async fn release(stdin: &mut tokio::process::ChildStdin) -> Result<()> {
    stdin.write_all(b"go\n").await.map_err(HarnessError::Io)?;
    stdin.flush().await.map_err(HarnessError::Io)
}

/// Wait for the device to have folded exactly `count` completed filesystem
/// exchanges into its diagnostics, and return the ledger then.
///
/// The wait is on the real signal — the exchange count reaching a known number
/// — under a bound, rather than a sleep chosen to be long enough. The number is
/// knowable because the driver holds at each rendezvous: one consumer session
/// is one exchange, and the cases before each reading are a fixed list.
async fn await_exchanges(device_client: &ConnectionHandle, count: u64) -> Result<DeviceLedger> {
    let deadline = Instant::now() + LEDGER_WAIT;
    loop {
        let ledger = DeviceLedger::from(&device_client.status_snapshot().fs);
        if ledger.exchanges >= count {
            return Ok(ledger);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "the device never recorded the filesystem exchange".into(),
            ));
        }
        sleep(AUTHORIZATION_POLL).await;
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
        sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> FsClientE2eEvidence {
        FsClientE2eEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            client_module_path: "file:///repo/packages/client/src/index.ts".into(),
            client_module_is_the_package: true,
            public_entry_point_used: true,
            expected_owner_node: "relay-a".into(),
            endpoints_all_https: true,
            driver_failures: Vec::new(),
            node_tls_reject_unauthorized: "unset".into(),
            probe_tls_reject_unauthorized: "unset".into(),
            probe_extra_ca: "unset".into(),
            probe_code: "INSECURE_ENDPOINT".into(),
            probe_retryable: false,
            descriptor_schema_version: SCHEMA_VERSION.into(),
            descriptor_subprotocol: SUBPROTOCOL.into(),
            descriptor_dialect: DIALECT.into(),
            descriptor_grant_revision_present: true,
            descriptor_operations: vec!["readFile".into(), "writeStream".into()],
            descriptor_read_only: false,
            descriptor_availability: "online".into(),
            unauthenticated_code: "UNAUTHENTICATED".into(),
            unauthenticated_outcome: "not_started".into(),
            revision_advanced_in_catalog: true,
            revision_upgrade_status: 409,
            revision_upgrade_code: "CAPABILITIES_CHANGED".into(),
            revision_upgrade_outcome: "not_started".into(),
            revision_upgrade_retryable: false,
            selected_subprotocol: SUBPROTOCOL.into(),
            negotiated_msize: OFFERED_MSIZE,
            session_lifecycle: "ready".into(),
            read_bytes: READ_FILE_BYTES as u64,
            read_checksum_matches: true,
            read_messages: 7,
            write_bytes: WRITE_FILE_BYTES as u64,
            write_messages: 7,
            write_acknowledgements: 7,
            write_host_bytes: WRITE_FILE_BYTES as u64,
            write_host_checksum_matches: true,
            listing_names_observed: LISTING_ENTRIES,
            listing_every_name_exactly_once: true,
            read_only_read_matches: true,
            read_only_root_read_only: true,
            read_only_advertises_no_mutation: true,
            read_only_client_codes: vec![
                "ENOTSUP".into(),
                "ENOTSUP".into(),
                "ENOTSUP".into(),
                "ENOTSUP".into(),
            ],
            read_only_client_outcomes: vec![
                "not_started".into(),
                "not_started".into(),
                "not_started".into(),
                "not_started".into(),
            ],
            read_only_device_create_code: "EPERM".into(),
            read_only_device_mkdir_code: "EPERM".into(),
            read_only_device_unlink_code: "EPERM".into(),
            read_only_device_open_write_code: "EPERM".into(),
            read_only_device_outcomes: vec![
                "failed".into(),
                "failed".into(),
                "failed".into(),
                "not_started".into(),
            ],
            read_only_any_retryable: false,
            read_only_host_unchanged: true,
            // Two exchanges have completed: the `unknown` case, which applied
            // one write, and the read-write case, whose `Tlcreate` and seven
            // `Twrite`s are eight mutations of which seven carried bytes. The
            // numbers are consistent with each other deliberately -- a fixture
            // that was not would let a rule about their difference pass on
            // arithmetic that could not occur.
            read_only_ledger_before: DeviceLedger {
                exchanges: 2,
                mutations_refused: 0,
                mutations_dispatched: 10,
                mutations_applied: 10,
                mutations_acknowledged: 8,
                mutation_failed: 0,
                mutation_partial: 0,
                mutation_unknown: 2,
                bytes_written: 393_216 + UNKNOWN_CHUNK_BYTES as u64,
            },
            // The read-only exchange refuses three mutating opcodes and a
            // writable open, and moves nothing: the refusals never reach the
            // queue, so not even `mutations_refused` records them (task row
            // M4-16).
            read_only_ledger_after: DeviceLedger {
                exchanges: 3,
                mutations_refused: 0,
                mutations_dispatched: 10,
                mutations_applied: 10,
                mutations_acknowledged: 8,
                mutation_failed: 0,
                mutation_partial: 0,
                mutation_unknown: 2,
                bytes_written: 393_216 + UNKNOWN_CHUNK_BYTES as u64,
            },
            read_only_device_refused: 0,
            read_only_device_applied_anything: false,
            read_only_client_reported_failed: 3,
            unknown_requests: UNKNOWN_WRITES,
            unknown_classified_unknown: UNKNOWN_WRITES,
            unknown_any_retryable: false,
            unknown_client_acknowledged_bytes: 0,
            unknown_close_codes: vec![1000],
            ledger_before: DeviceLedger::default(),
            ledger_after: DeviceLedger {
                exchanges: 1,
                mutations_refused: 0,
                mutations_dispatched: 5,
                mutations_applied: 4,
                mutations_acknowledged: 0,
                mutation_failed: 0,
                mutation_partial: 0,
                mutation_unknown: 4,
                bytes_written: 3 * UNKNOWN_CHUNK_BYTES as u64,
            },
            ledger_identity_holds: true,
            unknown_host_bytes: 3 * UNKNOWN_CHUNK_BYTES as u64,
            unknown_host_pattern_matches: true,
            unknown_host_matches_ledger: true,
            device_applied_beyond_client_knowledge: 3 * UNKNOWN_CHUNK_BYTES as u64,
            adapter_name: "mastra".into(),
            adapter_read_matches: true,
            adapter_write_bytes: ADAPTER_WRITE_BYTES as u64,
            adapter_listing_names: 2,
            adapter_stat_size_matches: true,
            adapter_append_refused: "FilesystemError".into(),
            adapter_host_write_matches: true,
        }
    }

    #[test]
    fn every_rule_is_load_bearing() {
        validate_fs_client_e2e_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut FsClientE2eEvidence));
        let mutations: Vec<Mutation> = vec![
            ("relays", |e| e.relay_count = 2),
            ("no owner", |e| e.owner_node.clear()),
            ("a driver that loaded some other package", |e| {
                e.client_module_is_the_package = false;
            }),
            ("a driver that reported no module at all", |e| {
                e.client_module_path.clear();
            }),
            ("the composed entry point never driven", |e| {
                e.public_entry_point_used = false;
            }),
            ("an owner this gate did not arrange", |e| {
                e.expected_owner_node = "relay-b".into();
            }),
            ("a plaintext endpoint", |e| e.endpoints_all_https = false),
            ("a case that did not run", |e| {
                e.driver_failures.push("read-write:SESSION_LOST".into());
            }),
            ("a driver that could have skipped verification", |e| {
                e.node_tls_reject_unauthorized = "0".into();
            }),
            ("a probe that could have skipped verification", |e| {
                e.probe_tls_reject_unauthorized = "0".into();
            }),
            ("a probe that was handed the fixture CA after all", |e| {
                e.probe_extra_ca = "/tmp/fixture-ca.pem".into();
            }),
            ("an unverifiable certificate the client accepted", |e| {
                e.probe_code = "ADMITTED".into();
            }),
            ("an unverifiable certificate reported as an outage", |e| {
                e.probe_code = "BACKEND_UNAVAILABLE".into();
            }),
            ("an untrusted peer worth retrying", |e| {
                e.probe_retryable = true;
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
            ("descriptor revision", |e| {
                e.descriptor_grant_revision_present = false;
            }),
            ("no mutating operation", |e| {
                e.descriptor_operations = vec!["readFile".into()];
            }),
            ("a read-only writable export", |e| {
                e.descriptor_read_only = true;
            }),
            ("an offline device", |e| {
                e.descriptor_availability = "offline".into();
            }),
            ("an unsigned token admitted", |e| {
                e.unauthenticated_code = "EXPORT_NOT_FOUND".into();
            }),
            ("an unsigned token with an outcome", |e| {
                e.unauthenticated_outcome = "unknown".into();
            }),
            ("a revision that never moved", |e| {
                e.revision_advanced_in_catalog = false;
            }),
            ("a superseded revision admitted", |e| {
                e.revision_upgrade_code = String::new();
            }),
            ("a refusal that was not a 409", |e| {
                e.revision_upgrade_status = 403;
            }),
            ("a superseded revision that may have happened", |e| {
                e.revision_upgrade_outcome = "unknown".into();
            }),
            ("a superseded revision reported retryable", |e| {
                e.revision_upgrade_retryable = true;
            }),
            ("the wrong subprotocol", |e| {
                e.selected_subprotocol = "agent-tunnel.echo.v1".into();
            }),
            ("a reduced msize", |e| e.negotiated_msize = 4_096),
            ("a session that never became ready", |e| {
                e.session_lifecycle = "connecting".into();
            }),
            ("a short read", |e| e.read_bytes = 1_024),
            ("a read that did not checksum", |e| {
                e.read_checksum_matches = false;
            }),
            ("a read in one message", |e| e.read_messages = 1),
            ("a short write", |e| e.write_bytes = 1_024),
            ("a write in one message", |e| e.write_messages = 1),
            ("writes the device never acknowledged", |e| {
                e.write_acknowledgements = 1;
            }),
            ("a host file of the wrong length", |e| {
                e.write_host_bytes = 1_024;
            }),
            ("a host file that did not checksum", |e| {
                e.write_host_checksum_matches = false;
            }),
            ("a short listing", |e| e.listing_names_observed = 2),
            ("a duplicated listing name", |e| {
                e.listing_every_name_exactly_once = false;
            }),
            ("a read-only grant that served nothing", |e| {
                e.read_only_read_matches = false;
            }),
            ("a read-only grant with a writable root", |e| {
                e.read_only_root_read_only = false;
            }),
            ("a read-only grant advertising a mutation", |e| {
                e.read_only_advertises_no_mutation = false;
            }),
            ("a mutation the client sent anyway", |e| {
                e.read_only_client_codes[1] = "ADMITTED".into();
            }),
            ("a local refusal with an outcome", |e| {
                e.read_only_client_outcomes[0] = "unknown".into();
            }),
            ("a create the device admitted", |e| {
                e.read_only_device_create_code = "ADMITTED".into();
            }),
            ("a mkdir the device admitted", |e| {
                e.read_only_device_mkdir_code = "ADMITTED".into();
            }),
            ("an unlink the device admitted", |e| {
                e.read_only_device_unlink_code = "ADMITTED".into();
            }),
            ("a writable open the device admitted", |e| {
                e.read_only_device_open_write_code = "ADMITTED".into();
            }),
            ("a device refusal reported below the wire's floor", |e| {
                e.read_only_device_outcomes[2] = "not_started".into();
            }),
            ("a writable open reported as an effect", |e| {
                e.read_only_device_outcomes[3] = "failed".into();
            }),
            ("a ledger counting more refusals than were sent", |e| {
                e.read_only_device_refused = 4;
            }),
            ("a mutation the device dispatched to the host", |e| {
                e.read_only_ledger_after.mutations_dispatched += 1;
            }),
            ("a read-only grant that applied something", |e| {
                e.read_only_device_applied_anything = true;
            }),
            ("a read-only grant that wrote bytes", |e| {
                e.read_only_ledger_after.bytes_written += 1;
            }),
            ("a ledger reading taken at the wrong boundary", |e| {
                e.read_only_ledger_before.exchanges = 1;
            }),
            ("a read-only exchange the device never finished", |e| {
                e.read_only_ledger_after.exchanges = 2;
            }),
            ("a refusal reported retryable", |e| {
                e.read_only_any_retryable = true;
            }),
            ("a read-only export that changed", |e| {
                e.read_only_host_unchanged = false;
            }),
            ("a dispatched mutation reported not_started", |e| {
                e.unknown_classified_unknown = UNKNOWN_WRITES - 1;
            }),
            ("fewer writes than the case issued", |e| {
                e.unknown_requests = 1;
            }),
            ("an ambiguous mutation reported retryable", |e| {
                e.unknown_any_retryable = true;
            }),
            ("bytes acknowledged that were never acknowledged", |e| {
                e.unknown_client_acknowledged_bytes = 4;
            }),
            ("a ledger reading that covers other exchanges", |e| {
                e.ledger_before.exchanges = 1;
            }),
            ("a ledger reading of no exchange at all", |e| {
                e.ledger_after.exchanges = 0;
            }),
            ("a ledger whose identity does not hold", |e| {
                e.ledger_identity_holds = false;
            }),
            ("a device that applied more than it dispatched", |e| {
                e.ledger_after.mutations_applied = e.ledger_after.mutations_dispatched + 1;
            }),
            ("a host holding more than the ledger claims", |e| {
                e.unknown_host_matches_ledger = false;
            }),
            ("a host whose bytes are not the source pattern", |e| {
                e.unknown_host_pattern_matches = false;
            }),
            ("no adapter", |e| e.adapter_name.clear()),
            ("an adapter that read the wrong bytes", |e| {
                e.adapter_read_matches = false;
            }),
            ("an adapter write of the wrong length", |e| {
                e.adapter_write_bytes = 1;
            }),
            ("an adapter write the host did not receive", |e| {
                e.adapter_host_write_matches = false;
            }),
            ("an adapter listing that did not match", |e| {
                e.adapter_listing_names = -1;
            }),
            ("an adapter stat of the wrong size", |e| {
                e.adapter_stat_size_matches = false;
            }),
            ("an adapter that emulated an append", |e| {
                e.adapter_append_refused = "ADMITTED".into();
            }),
        ];
        for (name, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_fs_client_e2e_evidence(&evidence).is_err(),
                "the validator accepted {name}"
            );
        }
    }
}
