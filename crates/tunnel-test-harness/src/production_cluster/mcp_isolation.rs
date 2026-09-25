//! M3-04 over the real cluster: MCP session isolation, concurrent request
//! correlation, explicit unknown outcomes with no replay of side effects,
//! revocation and a long-running call that spans scheduled rotations.
//!
//! Two distinct authenticated principals of the same tenant (`consumer-a-1`
//! and `consumer-a-2`), each holding its own bearer token and its own grant
//! on the same device and the same MCP services, drive raw HTTP through
//! non-owner ingress (relay-c), the peer HTTP/3 hop, the owner actor
//! (relay-a), the rotating device data WebSocket and `tunnel-client`'s
//! configured MCP exports against the deterministic `tunnel-mcp-fixture`
//! stdio server.  A third principal (`owner-a`) exists only to have its
//! grant revoked, so the isolation and correlation principals stay usable.
//!
//! The client is raw HTTP on purpose.  M3-03 already pins the official rmcp
//! client end to end; this gate has to send things a conforming client never
//! sends — another principal's session ID, deliberately colliding JSON-RPC
//! IDs and progress tokens in both directions, and a request whose
//! acknowledgement is lost — so it builds every message itself.
//!
//! Cases, in order, on one device session (M7-C82 is fixed, so the session is
//! reused and its OPEN journal is asserted to stay bounded) until owner loss
//! necessarily ends it:
//!
//! * `session-isolation`: consumer A's `mcp-2025-11-25` session ID is
//!   refused for consumer B on POST, GET and DELETE with exactly the answer
//!   an unknown session gets; A's session keeps working; each consumer's
//!   standalone GET stream receives only its own server notifications.
//! * `correlation`: many in-flight calls with deliberately colliding
//!   JSON-RPC IDs and progress tokens — reused across sessions and across
//!   principals, in both the sessionless 2026 profile and the 2025 session
//!   profile — are each answered to the right caller with exact results,
//!   while a genuine duplicate on one session is refused.
//! * `revocation`: a third principal's grant is revoked mid-call and then
//!   mid-session; the in-flight exchange ends with a typed error, nothing is
//!   dispatched afterwards, and the recorded blast radius is compared with
//!   what docs/cluster.md claims.
//! * `rotation-span`: one call held open across three completed scheduled
//!   rotations completes exactly once with exact bytes and one dispatch.
//! * `unknown-outcome`: a lost acknowledgement (the owner→ingress peer path
//!   is blackholed) and then owner process loss, each after the fixture has
//!   already recorded its synthetic side effect.  The consumer must see an
//!   explicit unknown outcome, the side effect must have run exactly once,
//!   and nothing may be retried or replayed.
//!
//! All payloads, credentials and processes are synthetic.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};
use tunnel_client::ConnectOptions;
use tunnel_client::http_forward::{DeviceHttpDiagnostics, HttpHandlers, McpExportDiagnostics};
use tunnel_core::RotationConfig;
use tunnel_mcp_export::ExportDiagnostics;

use super::http_forward_real_path::{ConsumerStream, connect_consumer, request};
use super::mcp_cloud_client::wire::{
    FreezeWatch, HttpBackend, MIN_RETRY_HINT_MS, RETRY_MARGIN, count_lines, fixture_binary_path,
    rotation_freeze_hint, wait_file,
};
use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::{Harness, HarnessError, HarnessOptions, Result};

/// The same short scheduled-rotation policy the other M3 cluster gates use.
pub const ISOLATION_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 6,
    handshake_timeout_seconds: 2,
    overlap_seconds: 5,
};
pub const PROFILE_2026: &str = "mcp-2026-07-28";
pub const PROFILE_2025: &str = "mcp-2025-11-25";
/// The harness fixture labels of the two stdio services this gate drives.
const SERVICE_2025: &str = "stdio-2025";
const SERVICE_2026: &str = "stdio-2026";
/// The legacy-profile service this gate exports through a **Streamable HTTP**
/// backend rather than a stdio child.
///
/// The stdio export gives every session its own child process, so its session
/// isolation is partly process isolation.  This backend is one shared process
/// for every session and every principal, so a session ID presented by the
/// wrong principal is separated by the principal binding alone.
const SERVICE_HTTP_2025: &str = "http-2025";
/// The cases, in order.
pub const MCP_ISOLATION_CASES: [&str; 8] = [
    "binding-forgery",
    "session-isolation",
    "streamable-binding",
    "cross-tenant",
    "correlation",
    "revocation",
    "rotation-span",
    "unknown-outcome",
];
/// Concurrent calls per principal in the correlation case.  Each principal
/// uses the same JSON-RPC IDs and the same progress tokens as the other.
pub const CORRELATION_CALLS: usize = 6;
/// The JSON-RPC IDs both principals reuse.  The first is deliberately past
/// 2^53, which is where a JSON number implementation that reads IDs as
/// doubles would collapse two distinct IDs into one.
pub const COLLIDING_IDS: [&str; CORRELATION_CALLS] = [
    "9007199254740993",
    "9007199254740994",
    "1",
    "\"shared-a\"",
    "\"shared-b\"",
    "0",
];
/// Consumer attempts to supply the relay-only principal binding: two
/// profiles × three routes × (one value, then a repeated one).
pub const FORGERY_ATTEMPTS: usize = 2 * 3 * 2;
/// Server notifications each principal asks for in the isolation case.
pub const ISOLATION_LOG_COUNT: u64 = 4;
/// Completed scheduled rotations one held call must span.
pub const ROTATION_SPAN: u64 = 3;
/// The OPEN journal bound on the reused device session (M7-C82).
///
/// Derived, not tuned.  The correlation case issues two adjacent bursts of
/// `CORRELATION_CALLS` calls per principal — `CORRELATION_CALLS * 2` streams
/// each — and the second burst can begin while the first burst's
/// `STREAM_FORGET`s are still in flight, so both bursts may be unreclaimed at
/// once: `CORRELATION_CALLS * 4`.  Nothing in the run can exceed that, and it
/// is far under `MAX_JOURNAL_ENTRIES`, so the rule still says what it is meant
/// to say — the journal is a function of concurrency, not of the roughly
/// seventy streams the run serves on one session.
pub const JOURNAL_ENTRY_BOUND: usize = CORRELATION_CALLS * 4;
const JOURNAL_TRACKED_ENTRIES: usize = tunnel_protocol::control_journal::MAX_JOURNAL_ENTRIES;

const SCENARIO_TIMEOUT: Duration = Duration::from_secs(1_200);
const WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(25);
/// A held call must survive this long: three rotation intervals plus their
/// overlaps, with headroom.
const ROTATION_BOUND: Duration = Duration::from_secs(
    (ISOLATION_ROTATION.interval_seconds + ISOLATION_ROTATION.overlap_seconds)
        * (ROTATION_SPAN + 2),
);
/// How long the rotation-span case waits for the one scheduled rotation
/// completion it anchors on: at most one interval until the next attempt
/// starts, plus that attempt's own handshake and overlap, doubled for
/// headroom (M3-34).
const ANCHOR_BOUND: Duration = Duration::from_secs(
    (ISOLATION_ROTATION.interval_seconds
        + ISOLATION_ROTATION.handshake_timeout_seconds
        + ISOLATION_ROTATION.overlap_seconds)
        * 2,
);
/// The quiet window the anchor buys: after an observed completion, no
/// scheduled freeze begins for one whole interval.  The session open and the
/// spanning call (99-330 ms after the anchor in every recorded run, M3-34)
/// must fit inside it with margin, so a shorter policy would reintroduce the
/// race this anchor exists to remove.
const ANCHOR_MIN_INTERVAL_SECONDS: u64 = 3;
const _: () = assert!(
    ISOLATION_ROTATION.interval_seconds >= ANCHOR_MIN_INTERVAL_SECONDS,
    "the rotation-span anchor needs an interval long enough to open a session and dispatch the call before the next freeze (M3-34)"
);
/// How long an explicit outcome may take to reach the consumer after a
/// fault.
const OUTCOME_WAIT: Duration = Duration::from_secs(90);
/// How long the consumer's own call is given to finish after its side effect
/// failed to appear, so the failure can name what the consumer saw.  This is
/// a diagnostic grace on the failure path only: it asserts nothing, and a
/// call still outstanding when it expires is reported as such.
const OUTCOME_STATUS_GRACE: Duration = Duration::from_secs(15);
/// A revoked grant must stop dispatch within this bound.
pub const REVOCATION_BOUND: Duration = Duration::from_secs(30);
/// An admitted exchange must be withdrawn this soon after the revocation.
/// The bound separates the revocation from the exchange's own progress
/// deadline: with the revocation skipped, the identical held call runs to
/// that deadline at about 30 s, and with it the call ends in well under a
/// second.
pub const REVOCATION_WITHDRAWAL_BOUND: Duration = Duration::from_secs(5);
const MEMBERSHIP_RESIGN_SPACING: Duration = Duration::from_secs(15);

/// What this gate does not prove.  Recorded rather than faked.
pub const NOT_COVERED: [&str; 4] = [
    "server-to-client JSON-RPC requests (sampling/createMessage, elicitation/create, MRTR input): the pinned fixture issues none, so colliding server-to-client request IDs are unproven (M3-13)",
    "Origin validation and the MCP authorization profile, including token audience checks at the export (M3-11)",
    "Last-Event-ID resume of an interrupted legacy stream (M3-10)",
    "concurrent colliding request IDs through one shared backend process: the streamable-binding case drives the shared Streamable HTTP backend for session separation, but the correlation case's colliding IDs and progress tokens are driven on the stdio exports only (M3-13)",
];

// ---- evidence ---------------------------------------------------------------

/// `binding-forgery`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ForgeryEvidence {
    /// Consumer requests that presented the relay-only principal binding.
    pub attempts: usize,
    /// How many were refused `400 HTTP_INVALID_HEAD` `not_dispatched`.
    pub refused: usize,
    /// Ingress rejections the relay counted while they were sent.
    pub ingress_rejections: u64,
    /// Device dispatches while they were sent.  None of them is admitted, so
    /// this must be zero.
    pub dispatched: u64,
}

/// `session-isolation`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IsolationEvidence {
    /// Consumer A opened a session and consumer B opened a different one.
    pub sessions_distinct: bool,
    /// A's session ID presented by B: POST, GET and DELETE statuses.
    pub foreign_post_status: u16,
    pub foreign_get_status: u16,
    pub foreign_delete_status: u16,
    /// B's answer for A's session is byte-identical to its answer for a
    /// session that never existed.
    pub foreign_matches_unknown: bool,
    /// A's session still answered exactly after every refusal.
    pub owner_still_served: bool,
    /// The other principal's session was likewise untouched.
    pub sibling_still_served: bool,
    /// Notifications seen on each principal's standalone GET stream.
    pub own_notifications: u64,
    pub sibling_notifications: u64,
    /// No notification of one principal appeared on the other's stream.
    pub no_cross_delivery: bool,
    /// Legacy sessions the device opened during the case.
    pub sessions_opened: u64,
    /// Child processes the device spawned during the case: one per session,
    /// never one for a refused request.
    pub children_spawned: u64,
}

/// `streamable-binding`.
///
/// The same principal-binding rule as `session-isolation`, driven over the
/// real cluster against a **Streamable HTTP** backend instead of a stdio
/// child.  This is the case that separates the binding from *process*
/// isolation: one backend process serves every session here, so a foreign
/// session ID cannot be refused by a process boundary.  What refuses it is
/// the export's own principal-binding table (`SessionBindings::permits`),
/// before the backend is dialled.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StreamableBindingEvidence {
    /// The backend really was the shared Streamable HTTP one: the export
    /// started **no per-session child process**, because a Streamable HTTP
    /// backend is an address the export forwards to.
    ///
    /// The export does keep a per-session table of its own — the principal
    /// bindings it refuses a foreign principal from — and that table is the
    /// point of the case, not something it rules out.  What is ruled out is a
    /// process boundary, and the backend itself doing the refusing.  The
    /// counter below reads zero for a different reason: it counts stdio
    /// sessions and is never incremented for this backend kind.
    pub shared_backend: bool,
    /// Both principals' sessions came from that one backend and differ.
    pub sessions_distinct: bool,
    /// A's session ID presented by B: POST, GET and DELETE statuses.
    pub foreign_post_status: u16,
    pub foreign_get_status: u16,
    pub foreign_delete_status: u16,
    /// B's answer for A's session is indistinguishable from its answer for a
    /// session that never existed, field for field.
    pub foreign_matches_unknown: bool,
    /// Both principals' own sessions still answered exactly afterwards.
    pub owner_still_served: bool,
    pub sibling_still_served: bool,
    /// The export's stdio session counter during the case.  Zero: it counts
    /// stdio sessions only and is never incremented for a Streamable HTTP
    /// backend.  It is *not* evidence that the export tracks no session
    /// state — it tracks principal bindings, which is what refuses the
    /// foreign principal.
    pub sessions_opened: u64,
    /// How many of those two each owning principal ended itself, counted by
    /// the session becoming unusable afterwards rather than by a status.
    pub sessions_ended: usize,
}

/// `cross-tenant`.
///
/// A consumer authenticated and authorized in another tenant drives this
/// tenant's device and service.  Nothing it sends may reach the device, this
/// tenant's MCP session, or any answer that distinguishes an existing session
/// from an absent one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CrossTenantEvidence {
    /// The foreign principal really is of the other tenant.
    pub foreign_tenant: bool,
    /// Opening a fresh session on this tenant's export: status and typed
    /// outcome.
    pub initialize_status: u16,
    pub initialize_code: String,
    pub initialize_execution: String,
    /// Presenting this tenant's live session ID on POST, GET and DELETE.
    pub session_post_status: u16,
    pub session_get_status: u16,
    pub session_delete_status: u16,
    /// Every one of those was refused, and every refusal was the same typed
    /// answer as the request that named no session at all: a foreign tenant
    /// learns nothing about whether the session exists.
    pub refused: usize,
    pub attempts: usize,
    pub uniform_refusal: bool,
    /// Device dispatches and export sessions gained while the foreign tenant
    /// was driving: zero of each.
    pub dispatched: u64,
    pub sessions_opened: u64,
    /// The device exchange log did not grow, so nothing reached the device.
    pub device_exchanges: u64,
    /// This tenant's own session still answered exactly afterwards.
    pub tenant_session_served: bool,
}

/// `correlation`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorrelationEvidence {
    /// Concurrent calls each principal made with the colliding IDs.
    pub calls_per_principal: usize,
    /// Every sessionless 2026 answer carried its caller's own ID and result.
    pub sessionless_exact: bool,
    /// Every 2025 answer on each principal's own session did too.
    pub session_exact: bool,
    /// Progress notifications reached the request that carried the token,
    /// even though both principals used the same token values.
    pub progress_exact: bool,
    /// A genuine duplicate (the same in-flight ID, or the same in-flight
    /// progress token, on one session) is refused.
    pub duplicate_id_status: u16,
    pub duplicate_token_status: u16,
    /// Answers observed in total, and how many carried a wrong ID or result.
    pub answers: usize,
    pub misrouted: usize,
}

/// `revocation`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationEvidence {
    /// The revoked principal's call was answered before revocation.
    pub baseline_status: u16,
    /// Whether the admitted exchange was withdrawn by the revocation itself,
    /// inside [`REVOCATION_BOUND`], rather than only ending when the gate
    /// released the fixture afterwards.
    pub in_flight_withdrawn: bool,
    /// How long after the revocation the admitted exchange ended.  The
    /// `rotation-span` case holds an identical call, unrevoked, for longer
    /// than [`REVOCATION_BOUND`] and it completes with a result, so a
    /// withdrawal inside the bound is the revocation's doing and not a
    /// deadline every held call would hit.
    pub withdrawn_within_ms: u128,
    /// The in-flight exchange's terminal status and typed code.  A status of
    /// zero means the consumer's transport ended with no response at all.
    pub in_flight_status: u16,
    pub in_flight_code: String,
    pub in_flight_execution: String,
    /// A fresh request after revocation, and how long it took to fail.
    pub after_status: u16,
    pub after_code: String,
    pub after_execution: String,
    pub failed_within_ms: u128,
    /// Device dispatches after the revocation landed.
    pub dispatched_after: u64,
    /// The recorded blast radius: whether the unrevoked principals' sessions
    /// and the device session itself survived.
    pub sibling_principal_served: bool,
    pub device_session_survived: bool,
    /// Whether the revoked principal's own legacy session survived the
    /// revocation as a device object (it does: the device holds sessions,
    /// the relay holds authorization).
    pub revoked_session_unreachable: bool,
}

/// `rotation-span`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RotationSpanEvidence {
    /// Completed scheduled rotations while the call was open, counted from
    /// the anchoring completion the call was sent after (M3-34).
    pub rotations_spanned: u64,
    /// The call reached the device before any rotation it is credited with
    /// began: once its hold had started, the owner session was still
    /// `active` with the anchor's completed count (M3-34).  A call that was
    /// refused into a freeze and resent until after it would read `false`.
    pub dispatched_between_rotations: bool,
    /// Milliseconds from the anchoring rotation's completion being observed
    /// to the call's hold starting on the device.  Reported, not asserted.
    pub anchor_to_dispatch_ms: u128,
    pub status: u16,
    /// The call's result text matched the fixture's exactly.
    pub result_exact: bool,
    /// Dispatches of the held tool during the case.
    pub invocations: u64,
    /// The device session that served it did not change.
    pub session_stable: bool,
}

/// The observed event a fault's replay check settles on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Settle {
    /// The device finished and recorded the exchange.
    DeviceRecord,
    /// The device session the call was dispatched on is gone.
    SessionEnded,
}

impl Settle {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceRecord => "device_exchange_record",
            Self::SessionEnded => "device_session_ended",
        }
    }
}

/// One explicit unknown outcome after a synthetic side effect.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnknownOutcomeEvidence {
    pub fault: String,
    /// The event the gate waited for before counting the side effect again,
    /// so the replay check is tied to something observable rather than to a
    /// sleep: `device_exchange_record` when the device finished and recorded
    /// the exchange, `device_session_ended` when the session the call was
    /// dispatched on is gone and nothing can be re-dispatched on it.
    pub settled_on: String,
    /// Device exchange records that appeared for this call.  Meaningful only
    /// for `device_exchange_record`; the connector keeps a bounded log, so it
    /// is matched by stream ID, not by length.
    pub device_exchanges: usize,
    /// Side-effect records before the fault and after the outcome.
    pub side_effects_before_fault: u64,
    pub side_effects_after_outcome: u64,
    pub status: u16,
    pub body_code: String,
    pub body_execution: String,
    /// The product's own classification of `{code, execution}`.
    pub result_outcome: String,
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpIsolationEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    pub ingress_node: String,
    pub non_owner_ingress: bool,
    pub relay_profiles: Vec<String>,
    /// Distinct authenticated principals the gate drove.
    pub principals: usize,
    /// Device sessions used: one, plus one more after owner loss ends it.
    pub device_sessions: usize,
    /// The reused session's highest OPEN journal occupancy (M7-C82).
    pub journal_entries_peak: usize,
    /// Principals of another tenant the gate drove against this tenant.
    pub foreign_tenant_principals: usize,
    pub forgery: ForgeryEvidence,
    pub isolation: IsolationEvidence,
    pub streamable_binding: StreamableBindingEvidence,
    pub cross_tenant: CrossTenantEvidence,
    pub correlation: CorrelationEvidence,
    pub revocation: RevocationEvidence,
    pub rotation_span: RotationSpanEvidence,
    pub lost_ack: UnknownOutcomeEvidence,
    pub owner_loss: UnknownOutcomeEvidence,
    pub resign_spacing_ms: u128,
    /// Legacy sessions the gate opened, and how many it was able to end with
    /// DELETE.  The two it cannot end are the revoked principal's (its grant
    /// is gone, so the relay refuses the DELETE too) and the one whose owner
    /// relay was killed.
    pub sessions_opened: usize,
    pub sessions_deleted: usize,
    /// Export child processes still running after the connector stopped.
    /// Zero: dropping an export ends every session it still holds and kills
    /// each session child's process group, whether or not anyone ended the
    /// session first.
    pub children_after_stop: u64,
    /// Retryable `ROTATION_FREEZE` refusals the consumers received (a
    /// rotation freeze that outlasted the owner's bounded hold, or a full
    /// hold; M3-15), how many were resent, and the connector state at the
    /// first that this gate's own watch did not see as frozen.  Reported, not
    /// asserted.  Before M3-15 these counted the owner-not-ready body resent
    /// inside an observed freeze (M3-30); that body now answers only fault
    /// states and is returned to its case, which fails on it.
    pub freeze_refusals: u64,
    pub freeze_resends: u64,
    pub unexplained_refusal: Option<String>,
    pub not_covered: Vec<String>,
}

// ---- validator --------------------------------------------------------------

/// Check one run's evidence against the M3-04 rules.
///
/// # Errors
/// [`HarnessError::Process`] naming the first rule that did not hold.
#[allow(clippy::too_many_lines)]
pub fn validate_mcp_isolation_evidence(evidence: &McpIsolationEvidence) -> Result<()> {
    let isolation = &evidence.isolation;
    let streamable = &evidence.streamable_binding;
    let cross_tenant = &evidence.cross_tenant;
    let correlation = &evidence.correlation;
    let revocation = &evidence.revocation;
    let rotation = &evidence.rotation_span;
    let mut profiles = evidence.relay_profiles.clone();
    profiles.sort();
    let unknown = |outcome: &UnknownOutcomeEvidence, fault: &str, settle: &str| {
        outcome.fault == fault
            && outcome.side_effects_before_fault == 1
            && outcome.side_effects_after_outcome == 1
            // Counted at an observed event, not after a sleep.
            && outcome.settled_on == settle
            && (settle != "device_exchange_record" || outcome.device_exchanges == 1)
            && outcome.result_outcome == "outcome_unknown"
            && outcome.body_execution == "unknown"
            && !outcome.body_code.is_empty()
            && (500..=599).contains(&outcome.status)
    };
    let forgery = &evidence.forgery;
    let checks: [(&str, bool); 46] = [
        ("three relays ran", evidence.relay_count == 3),
        (
            "the ingress was not the owner",
            evidence.non_owner_ingress
                && evidence.ingress_node == "relay-c"
                && evidence.owner_node == "relay-a",
        ),
        (
            "both pinned profiles were served",
            profiles == vec![PROFILE_2025.to_owned(), PROFILE_2026.to_owned()],
        ),
        (
            "two authenticated principals drove the isolation and correlation cases",
            evidence.principals == 2,
        ),
        (
            "one device session served every case, up to the owner loss that ends it",
            evidence.device_sessions == 1,
        ),
        (
            "the reused session's OPEN journal stayed bounded",
            evidence.journal_entries_peak <= JOURNAL_ENTRY_BOUND
                && JOURNAL_ENTRY_BOUND < JOURNAL_TRACKED_ENTRIES,
        ),
        (
            "every consumer-supplied principal binding was refused",
            forgery.attempts == FORGERY_ATTEMPTS
                && forgery.refused == FORGERY_ATTEMPTS
                && forgery.ingress_rejections == FORGERY_ATTEMPTS as u64,
        ),
        (
            "a forged principal binding never reached the device",
            forgery.dispatched == 0,
        ),
        (
            "each principal opened its own distinct session",
            isolation.sessions_distinct,
        ),
        (
            "another principal's session ID is refused on POST, GET and DELETE",
            isolation.foreign_post_status == 404
                && isolation.foreign_get_status == 404
                && isolation.foreign_delete_status == 404,
        ),
        (
            "the refusal is byte-identical to an unknown session",
            isolation.foreign_matches_unknown,
        ),
        (
            "the owning principal's session was unaffected",
            isolation.owner_still_served && isolation.sibling_still_served,
        ),
        (
            "each principal received its own server notifications",
            isolation.own_notifications == ISOLATION_LOG_COUNT
                && isolation.sibling_notifications == ISOLATION_LOG_COUNT,
        ),
        (
            "no notification crossed between principals",
            isolation.no_cross_delivery,
        ),
        (
            "exactly one session and one child per principal, and none for a refusal",
            isolation.sessions_opened == 2 && isolation.children_spawned == 2,
        ),
        (
            "the Streamable HTTP binding case ran against one shared backend, not a child per session",
            streamable.shared_backend && streamable.sessions_distinct,
        ),
        (
            "a Streamable HTTP session ID is refused for another principal on every route",
            streamable.foreign_post_status == 404
                && streamable.foreign_get_status == 404
                && streamable.foreign_delete_status == 404,
        ),
        (
            "that refusal is indistinguishable from an unknown Streamable HTTP session",
            streamable.foreign_matches_unknown,
        ),
        (
            "both Streamable HTTP sessions were still served exactly afterwards",
            streamable.owner_still_served && streamable.sibling_still_served,
        ),
        (
            "each principal ended its own Streamable HTTP session, and it was then unusable",
            streamable.sessions_ended == 2,
        ),
        (
            "the cross-tenant case was driven by a principal of another tenant",
            evidence.foreign_tenant_principals == 1 && cross_tenant.foreign_tenant,
        ),
        (
            "a cross-tenant consumer could not open a session on this tenant's export",
            (400..500).contains(&cross_tenant.initialize_status)
                && cross_tenant.initialize_execution == "not_dispatched"
                && !cross_tenant.initialize_code.is_empty(),
        ),
        (
            "a cross-tenant consumer was refused, before dispatch, on every route it tried",
            cross_tenant.attempts == 7 && cross_tenant.refused == cross_tenant.attempts,
        ),
        (
            "a cross-tenant refusal never reveals whether the named session exists",
            cross_tenant.uniform_refusal,
        ),
        (
            "nothing a cross-tenant consumer sent reached the device or opened a session",
            cross_tenant.dispatched == 0
                && cross_tenant.sessions_opened == 0
                && cross_tenant.device_exchanges == 0,
        ),
        (
            "this tenant's own session was untouched by the cross-tenant attempts",
            cross_tenant.tenant_session_served,
        ),
        (
            "both principals ran the full set of colliding calls",
            correlation.calls_per_principal == CORRELATION_CALLS,
        ),
        (
            "every sessionless answer went to its own caller",
            correlation.sessionless_exact,
        ),
        (
            "every session answer went to its own caller",
            correlation.session_exact,
        ),
        (
            "colliding progress tokens followed their own request",
            correlation.progress_exact,
        ),
        (
            "a genuine duplicate on one session is refused",
            correlation.duplicate_id_status == 400 && correlation.duplicate_token_status == 400,
        ),
        (
            "every concurrent call was answered and none was misrouted",
            correlation.answers == CORRELATION_CALLS * 4 && correlation.misrouted == 0,
        ),
        (
            "the revoked principal was served before revocation",
            revocation.baseline_status == 200,
        ),
        (
            // Observed and recorded blast radius: revoking the consumer's
            // grant withdraws the admitted exchange inside the bound, and the
            // consumer gets a typed interruption rather than a result.  Its
            // execution is `unknown`, because the tool had already been
            // dispatched when the grant went away; a fabricated result, or a
            // claim that nothing ran, would both be wrong.
            "the admitted exchange was withdrawn with a typed error, not a result",
            revocation.in_flight_withdrawn
                && revocation.withdrawn_within_ms <= REVOCATION_WITHDRAWAL_BOUND.as_millis()
                // A bare connection close is not a typed outcome: the answer
                // must be a 5xx whose code and execution the product's own
                // parsers accept.
                && (500..=599).contains(&revocation.in_flight_status)
                && tunnel_http_forward::HttpErrorCode::parse(&revocation.in_flight_code).is_some()
                && tunnel_http_bridge::Execution::parse(&revocation.in_flight_execution).is_some(),
        ),
        (
            // The control for the rule above: an identical held call that was
            // never revoked stays open longer than the revocation bound and
            // is answered, so the withdrawal is the revocation's doing.
            "an unrevoked call outlives the withdrawal bound and is answered",
            rotation.status == 200
                && ROTATION_BOUND.as_millis() > REVOCATION_BOUND.as_millis()
                && u128::from(
                    rotation.rotations_spanned
                        * (ISOLATION_ROTATION.interval_seconds
                            + ISOLATION_ROTATION.overlap_seconds)
                        * 1_000,
                ) > REVOCATION_WITHDRAWAL_BOUND.as_millis(),
        ),
        (
            "a fresh request after revocation is refused, not dispatched",
            revocation.after_status == 404
                && revocation.after_code == "SERVICE_NOT_FOUND"
                && revocation.after_execution == "not_dispatched",
        ),
        (
            "revocation failed closed promptly",
            revocation.failed_within_ms <= REVOCATION_BOUND.as_millis(),
        ),
        (
            "nothing was dispatched to the device after revocation",
            revocation.dispatched_after == 0,
        ),
        (
            "the revoked principal's session became unreachable",
            revocation.revoked_session_unreachable,
        ),
        (
            "the blast radius spared the other principals and the device session",
            revocation.sibling_principal_served && revocation.device_session_survived,
        ),
        (
            "one call spanned the required scheduled rotations",
            rotation.rotations_spanned >= ROTATION_SPAN,
        ),
        (
            "the spanning call reached the device before the rotations it spanned began",
            rotation.dispatched_between_rotations,
        ),
        (
            "the spanning call completed exactly once with exact bytes",
            rotation.status == 200 && rotation.result_exact && rotation.invocations == 1,
        ),
        (
            "the spanning call stayed on one device session",
            rotation.session_stable,
        ),
        (
            "a lost acknowledgement is an explicit unknown outcome with no replay",
            unknown(
                &evidence.lost_ack,
                "owner_to_ingress_path_blackholed",
                "device_exchange_record",
            ),
        ),
        (
            "owner loss is an explicit unknown outcome with no replay",
            unknown(
                &evidence.owner_loss,
                "owner_process_loss",
                "device_session_ended",
            ),
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "MCP isolation gate failed: {rule}"
            )));
        }
    }
    // Two sessions cannot be ended by the gate: the revoked principal's
    // (the relay refuses its DELETE along with everything else it sends) and
    // the one whose owner relay was killed.  Their children must still be
    // gone once the connector stops, because the export ends every session it
    // holds when it is dropped.
    let unendable = evidence
        .sessions_opened
        .saturating_sub(evidence.sessions_deleted);
    if evidence.sessions_opened == 0 || unendable != 2 || evidence.children_after_stop != 0 {
        return Err(HarnessError::Process(format!(
            "MCP isolation gate failed: {} of {} sessions were ended and {} export children survived",
            evidence.sessions_deleted, evidence.sessions_opened, evidence.children_after_stop
        )));
    }
    if evidence.not_covered.len() != NOT_COVERED.len() {
        return Err(HarnessError::Process(
            "MCP isolation gate failed: the not-covered record was not carried".into(),
        ));
    }
    if evidence.resign_spacing_ms != MEMBERSHIP_RESIGN_SPACING.as_millis() {
        return Err(HarnessError::Process(
            "MCP isolation gate failed: membership was not re-signed at the recorded spacing"
                .into(),
        ));
    }
    Ok(())
}

// ---- consumer plumbing ------------------------------------------------------

fn body_stream(bytes: Bytes) -> StreamBody<ConsumerStream> {
    StreamBody::new(Box::pin(futures_util::stream::once(async move {
        Ok(Frame::data(bytes))
    })))
}

fn empty() -> StreamBody<ConsumerStream> {
    StreamBody::new(Box::pin(futures_util::stream::empty()))
}

/// The data frames of an in-memory request body, so it can be sent again
/// frame for frame after a freeze refusal (M3-30).
async fn collect_frames(body: StreamBody<ConsumerStream>) -> Result<Vec<Bytes>> {
    let mut body = std::pin::pin!(body);
    let mut frames = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| HarnessError::Http(format!("request body: {error}")))?;
        if let Ok(data) = frame.into_data() {
            frames.push(data);
        }
    }
    Ok(frames)
}

fn replay_frames(frames: &[Bytes]) -> StreamBody<ConsumerStream> {
    let frames = frames.to_vec();
    StreamBody::new(Box::pin(futures_util::stream::iter(
        frames.into_iter().map(|data| Ok(Frame::data(data))),
    )))
}

/// One consumer answer, reduced to what the gate asserts on.
#[derive(Clone, Debug, Default)]
struct Answer {
    status: u16,
    session: Option<String>,
    /// Every response header except `date`, sorted, so two answers can be
    /// compared field for field and not only by status and body.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    /// Whether two answers are indistinguishable to a consumer: the same
    /// status, the same header fields and the same body bytes.
    fn indistinguishable_from(&self, other: &Self) -> bool {
        self.status == other.status && self.headers == other.headers && self.body == other.body
    }
}

impl Answer {
    /// The JSON-RPC messages in the body, whether it is one JSON object or an
    /// SSE stream of `data:` events.
    fn messages(&self) -> Vec<Value> {
        let Ok(text) = std::str::from_utf8(&self.body) else {
            return Vec::new();
        };
        if text.trim_start().starts_with('{') {
            return serde_json::from_str(text).into_iter().collect();
        }
        // One SSE event is a block of fields, and `data:` is only one of
        // them.
        //
        // Events are split on a blank line written as `\n\n`.  A server that
        // terminated events with `\r\n\r\n` would collapse into one block
        // here; the pinned rmcp server and the fixture both use `\n\n`, and
        // no gate drives a `\r\n` server, so this is recorded rather than
        // handled.  The stdio export happens to put `data:` last, but a
        // Streamable HTTP backend follows it with `id:` and `retry:`, so
        // treating the whole block after `data: ` as the payload dropped
        // every message the shared backend sent.  Join this event's `data:`
        // lines, as the SSE grammar says to, and ignore the rest.
        text.split("\n\n")
            .filter_map(|event| {
                let data = event
                    .lines()
                    .filter_map(|line| {
                        line.strip_prefix("data:")
                            .map(|value| value.strip_prefix(' ').unwrap_or(value))
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                serde_json::from_str(&data).ok()
            })
            .collect()
    }

    /// The final JSON-RPC response (the last message carrying an `id`).
    fn final_message(&self) -> Option<Value> {
        self.messages()
            .into_iter()
            .rfind(|message| message.get("id").is_some() && message.get("method").is_none())
    }

    /// The `{code, execution}` an error body carries.  A relay admission
    /// refusal is a flat `ErrorBody`; a gateway outcome nests the same two
    /// fields under `error`.  Both are read here, and neither is invented.
    fn error(&self) -> (String, String) {
        let parsed: Value = serde_json::from_slice(&self.body).unwrap_or_default();
        let field = |name: &str| {
            parsed["error"][name]
                .as_str()
                .or_else(|| parsed[name].as_str())
                .unwrap_or_default()
                .to_owned()
        };
        (field("code"), field("execution"))
    }

    /// The retry hint of the relay's retryable **rotation-freeze** refusal
    /// (`rotation_freeze_response` in `tunnel-relay/src/http.rs`), or `None`
    /// for any other answer (M3-15).
    ///
    /// The owner holds a request that lands in a rotation freeze and admits
    /// it once the freeze ends, so this answer means the freeze outlasted the
    /// hold or the hold was full.  It is the one refusal the relay itself
    /// calls the scheduled freeze.  The owner-not-ready body, which before
    /// M3-15 was resent inside an observed freeze (M3-30), now answers only
    /// fault states and is never resent; nor is the empty-pin-set refusal
    /// (M7-C83).
    fn rotation_freeze_hint(&self) -> Option<Duration> {
        if self.status != 503 {
            return None;
        }
        rotation_freeze_hint(&self.body)
    }

    /// A payload-free description of this answer for a failure message: the
    /// status, the typed relay code and execution, and the JSON-RPC error
    /// number of the final message, if any.
    fn describe(&self) -> String {
        let (code, execution) = self.error();
        let rpc_error = self
            .final_message()
            .and_then(|message| message["error"]["code"].as_i64());
        // The relay's retryable owner-not-ready refusal carries a bounded
        // hint; its presence is what separates it from other 503s.
        let retry_after_ms = serde_json::from_slice::<Value>(&self.body)
            .ok()
            .and_then(|parsed| parsed["retry_after_ms"].as_u64());
        format!(
            "status {} code={code:?} execution={execution:?} retry_after_ms={retry_after_ms:?} jsonrpc_error={rpc_error:?}",
            self.status
        )
    }

    fn result_outcome(&self) -> String {
        let (code, execution) = self.error();
        match (
            tunnel_http_forward::HttpErrorCode::parse(&code),
            tunnel_http_bridge::Execution::parse(&execution),
        ) {
            (Some(code), Some(execution)) => {
                tunnel_http_bridge::result_outcome(tunnel_http_bridge::ResetDetail {
                    code,
                    execution,
                })
                .to_owned()
            }
            _ => String::new(),
        }
    }
}

/// One authenticated consumer: a principal, its token and the export it
/// drives.  Every exchange opens its own connection, so concurrent calls are
/// genuinely concurrent and a cancelled one cannot disturb another.
#[derive(Clone)]
struct Consumer {
    label: &'static str,
    token: String,
    ingress: std::net::SocketAddr,
    ca: Vec<u8>,
    /// The device session's rotation phase, fed from the connector (M3-30).
    freeze: Arc<FreezeWatch>,
    /// Freeze refusals seen and resent, shared by every consumer.
    refusals: Arc<FreezeRefusals>,
}

/// How many times one request is sent again after a retryable
/// `not_dispatched` refusal that coincided with an observed rotation freeze.
/// Derived as the cloud-client gate derives its cap: a freeze ends when the
/// attempt commits or its handshake budget expires, so the cap covers that
/// budget at the relay's smallest hint, plus a margin.
const FREEZE_RESENDS: u64 = (ISOLATION_ROTATION.handshake_timeout_seconds * 1_000)
    .div_ceil(MIN_RETRY_HINT_MS)
    + RETRY_MARGIN;

/// Payload-free counts of the relay's retryable owner-not-ready refusals.
#[derive(Debug, Default)]
struct FreezeRefusals {
    refusals: std::sync::atomic::AtomicU64,
    resends: std::sync::atomic::AtomicU64,
    unexplained: std::sync::Mutex<Option<String>>,
}

impl FreezeRefusals {
    fn snapshot(&self) -> (u64, u64, Option<String>) {
        use std::sync::atomic::Ordering;
        (
            self.refusals.load(Ordering::SeqCst),
            self.resends.load(Ordering::SeqCst),
            self.unexplained
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
    }
}

impl Consumer {
    /// Send one request and read its whole answer.
    ///
    /// The owner pauses new stream admission from QUIESCE to COMMIT
    /// (docs/protocol.md, "Quiesce admission") and holds a request that lands
    /// there until the freeze ends (M3-15).  Only a freeze that outlasts the
    /// bounded hold, or a full hold, reaches the consumer, as a retryable
    /// `503 ROTATION_FREEZE` `not_dispatched` refusal.  Nothing was
    /// dispatched and the relay names the cause itself, so it is sent again
    /// after its hint, at most [`FREEZE_RESENDS`] times; this gate's own
    /// freeze watch is only consulted to report one it did not see.  Every
    /// other refusal, the owner-not-ready fault body and the empty-pin-set
    /// refusal (M7-C83) included, is returned to its case unchanged.
    async fn send(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: StreamBody<ConsumerStream>,
    ) -> Result<Answer> {
        use std::sync::atomic::Ordering;
        let frames = collect_frames(body).await?;
        let mut resends = 0;
        loop {
            let answer = self
                .send_once(method, uri, headers, replay_frames(&frames))
                .await?;
            let Some(hint) = answer.rotation_freeze_hint() else {
                return Ok(answer);
            };
            self.refusals.refusals.fetch_add(1, Ordering::SeqCst);
            if !self.freeze.coincides() {
                self.refusals
                    .unexplained
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_or_insert_with(|| self.freeze.unexplained());
            }
            if resends >= FREEZE_RESENDS {
                return Ok(answer);
            }
            resends += 1;
            self.refusals.resends.fetch_add(1, Ordering::SeqCst);
            sleep(hint).await;
        }
    }

    async fn send_once(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: StreamBody<ConsumerStream>,
    ) -> Result<Answer> {
        let (mut sender, connection) = connect_consumer(self.ingress, &self.ca).await?;
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender
            .send_request(request(method, uri, Some(&self.token), headers, body)?)
            .await
            .map_err(|error| {
                HarnessError::Http(format!("{} {method} {uri}: {error}", self.label))
            })?;
        let status = response.status().as_u16();
        let session = response
            .headers()
            .get(tunnel_mcp::headers::MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter(|(name, _)| name.as_str() != "date")
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        headers.sort();
        let body = response
            .into_body()
            .collect()
            .await
            .map(|collected| collected.to_bytes().to_vec())
            .unwrap_or_default();
        connection.abort();
        Ok(Answer {
            status,
            session,
            headers,
            body,
        })
    }

    /// Open a standalone GET stream and return it only once the device has
    /// answered its head.  That answer is the deterministic signal that the
    /// session's standalone stream is registered, so the caller can start a
    /// call that produces server notifications without sleeping first.
    async fn open_standalone(&self, uri: &str, session: &str) -> Result<StandaloneStream> {
        let headers = [
            ("accept", "text/event-stream"),
            ("mcp-protocol-version", "2025-11-25"),
            (tunnel_mcp::headers::MCP_SESSION_ID, session),
        ];
        let (mut sender, connection) = connect_consumer(self.ingress, &self.ca).await?;
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        let built = request("GET", uri, Some(&self.token), &headers, empty())?;
        let response = timeout(WAIT, sender.send_request(built))
            .await
            .map_err(|_| HarnessError::Timeout(format!("{}: standalone stream head", self.label)))?
            .map_err(|error| {
                HarnessError::Http(format!("{}: standalone stream: {error}", self.label))
            })?;
        let status = response.status().as_u16();
        if status != 200 {
            connection.abort();
            return Err(HarnessError::Process(format!(
                "{}: standalone stream answered {status}",
                self.label
            )));
        }
        Ok(StandaloneStream {
            body: response.into_body(),
            connection,
            text: String::new(),
        })
    }
}

/// An open standalone GET stream.
struct StandaloneStream {
    body: hyper::body::Incoming,
    connection: tokio::task::JoinHandle<()>,
    text: String,
}

impl StandaloneStream {
    /// Collect `want` `notifications/message` events, or as many as arrive
    /// within `bound`, then close the stream.
    async fn collect(mut self, want: usize, bound: Duration) -> Vec<Value> {
        let deadline = Instant::now() + bound;
        let mut events = Vec::new();
        while events.len() < want && Instant::now() < deadline {
            let Ok(Some(Ok(frame))) = timeout(bound, self.body.frame()).await else {
                break;
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            self.text.push_str(&String::from_utf8_lossy(&data));
            events = self
                .text
                .split("\n\n")
                .filter_map(|event| event.strip_prefix("data: "))
                .filter_map(|data| serde_json::from_str::<Value>(data).ok())
                .filter(|message| message["method"] == "notifications/message")
                .collect();
        }
        self.connection.abort();
        events
    }
}

// ---- message construction ---------------------------------------------------

fn legacy_headers(session: Option<&str>) -> Vec<(&str, &str)> {
    let mut headers = vec![
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
    ];
    if let Some(session) = session {
        headers.push(("mcp-protocol-version", "2025-11-25"));
        headers.push((tunnel_mcp::headers::MCP_SESSION_ID, session));
    }
    headers
}

fn initialize_body() -> Bytes {
    Bytes::from(
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "m3-isolation", "version": "1"},
            },
        })
        .to_string(),
    )
}

/// A `tools/call` body whose ID is written as a raw JSON token, so a
/// 64-bit-exact ID survives into the bytes on the wire.
fn call_body(id: &str, tool: &str, arguments: &Value, meta: Option<Value>) -> Bytes {
    let mut params = json!({"name": tool, "arguments": arguments.clone()});
    if let Some(meta) = meta {
        params["_meta"] = meta;
    }
    let body = json!({"jsonrpc": "2.0", "method": "tools/call", "params": params});
    let text = body.to_string();
    // Splice the literal ID token in after `{"jsonrpc":"2.0"`.
    let (head, tail) = text.split_at("{\"jsonrpc\":\"2.0\"".len());
    Bytes::from(format!("{head},\"id\":{id}{tail}"))
}

/// The 2026 profile mirrors the method, the name and the protocol version.
fn current_headers(tool: &str) -> Vec<(&str, &str)> {
    vec![
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", tool),
    ]
}

fn current_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "m3-isolation", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

/// The exact text the fixture's `echo` returns for these arguments, as the
/// gate reconstructs it: the echoed arguments must be there verbatim.
fn echo_matches(message: &Value, arguments: &Value) -> bool {
    message["result"]["content"]
        .as_array()
        .and_then(|blocks| blocks.first())
        .and_then(|block| block["text"].as_str())
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .is_some_and(|echoed| echoed["arguments"] == *arguments)
}

/// Compare a JSON-RPC ID with the literal token the request carried.
fn id_matches(message: &Value, literal: &str) -> bool {
    message
        .get("id")
        .is_some_and(|id| serde_json::to_string(id).unwrap_or_default() == literal)
}

// ---- the gate ---------------------------------------------------------------

struct Gate<'a> {
    cluster: &'a mut ProductionCluster,
    config: tunnel_client::ConnectConfig,
    client: Option<tunnel_client::ConnectionHandle>,
    device_diagnostics: DeviceHttpDiagnostics,
    mcp_diagnostics: McpExportDiagnostics,
    session_id: String,
    tenant_id: uuid::Uuid,
    device_id: uuid::Uuid,
    services: std::collections::BTreeMap<&'static str, uuid::Uuid>,
    marker_dirs: std::collections::BTreeMap<&'static str, PathBuf>,
    membership_signed_at: Instant,
    /// Highest OPEN journal occupancy seen by the sampler below (M7-C82).
    journal_peak: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    journal_task: Option<tokio::task::JoinHandle<()>>,
    /// The connector's rotation phase, shared with every consumer (M3-30).
    freeze: Arc<FreezeWatch>,
}

impl Gate<'_> {
    fn uri(&self, label: &'static str) -> String {
        let service = self.services.get(label).copied().unwrap_or_default();
        format!("/v1/devices/{}/services/{service}/http/mcp", self.device_id)
    }

    fn markers(&self, label: &'static str) -> &Path {
        self.marker_dirs
            .get(label)
            .map_or_else(|| Path::new("."), PathBuf::as_path)
    }

    fn invocations(&self, label: &'static str, tool: &str) -> u64 {
        count_lines(&self.markers(label).join("invocations.log"), tool)
    }

    fn export(&self, label: &'static str) -> ExportDiagnostics {
        self.services
            .get(label)
            .and_then(|service| self.mcp_diagnostics.get(&service.to_string()))
            .unwrap_or_default()
    }

    /// Bring up one device session and wait until relay-a owns it.
    async fn connect_device(&mut self) -> Result<String> {
        let handlers = HttpHandlers::new()
            .with_mcp_exports(&self.config)
            .map_err(|error| HarnessError::InvalidInput(format!("MCP exports: {error}")))?;
        self.device_diagnostics = handlers.diagnostics();
        self.mcp_diagnostics = handlers.mcp_diagnostics_source();
        let client = timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect_with_http_handlers(
                ConnectOptions::new(self.config.clone()),
                handlers,
            ),
        )
        .await
        .map_err(|_| HarnessError::Timeout("device startup timed out".into()))?
        .map_err(|error| HarnessError::Process(format!("device connect: {error}")))?;
        let client = self.client.insert(client);
        let watched = client.clone();
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("device session did not become ready".into()))?
            .map_err(|error| HarnessError::Process(format!("device ready: {error}")))?;
        self.session_id = session.session_id.clone();
        self.watch_journal(&watched);
        let deadline = Instant::now() + WAIT;
        loop {
            let owner = self
                .cluster
                .catalog
                .current_owner(self.tenant_id, self.device_id, chrono::Utc::now())
                .await
                .ok()
                .flatten();
            if let Some(owner) = owner
                && owner.token.session_id == self.session_id
            {
                return Ok(owner.token.node_id.clone());
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "no relay claimed the device session".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    /// Sample the connector's OPEN journal occupancy continuously, so a peak
    /// between two cases cannot be missed (M7-C82).
    fn watch_journal(&mut self, client: &tunnel_client::ConnectionHandle) {
        use std::sync::atomic::Ordering;
        let peak = std::sync::Arc::clone(&self.journal_peak);
        let freeze = Arc::clone(&self.freeze);
        // Stop the previous session's watcher first, then start this device
        // session's freeze watch from nothing, so a reconnect (after owner
        // loss) never inherits the previous session's last freeze.
        if let Some(task) = self.journal_task.take() {
            task.abort();
        }
        freeze.reset();
        let mut status = client.status();
        {
            let snapshot = status.borrow_and_update();
            peak.fetch_max(snapshot.open_journal_entries, Ordering::Relaxed);
            freeze.record(&snapshot.phase, snapshot.rotations_completed);
        }
        // The same watch also feeds the rotation phase every consumer reads
        // before it resends a freeze refusal (M3-30).
        self.journal_task = Some(tokio::spawn(async move {
            while status.changed().await.is_ok() {
                let (entries, phase, rotations) = {
                    let snapshot = status.borrow_and_update();
                    (
                        snapshot.open_journal_entries,
                        snapshot.phase.clone(),
                        snapshot.rotations_completed,
                    )
                };
                peak.fetch_max(entries, Ordering::Relaxed);
                freeze.record(&phase, rotations);
            }
        }));
    }

    fn journal_peak(&self) -> usize {
        self.journal_peak.load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn rotations_completed(&self) -> Result<u64> {
        let snapshot = self.cluster.relay("relay-a")?.snapshot().await?;
        Ok(snapshot
            .sessions
            .iter()
            .find(|session| session.session_id == self.session_id)
            .map_or(0, |session| session.rotations_completed))
    }

    async fn device_session_present(&self) -> bool {
        let Ok(relay) = self.cluster.relay("relay-a") else {
            return false;
        };
        let Ok(snapshot) = relay.snapshot().await else {
            return false;
        };
        snapshot
            .sessions
            .iter()
            .any(|session| session.session_id == self.session_id)
    }

    /// Re-sign membership between cases (M7-C80): no case may straddle a
    /// refresh, and the fixture's records outlive any single case.
    async fn boundary(&mut self) -> Result<()> {
        if self.membership_signed_at.elapsed() >= MEMBERSHIP_RESIGN_SPACING {
            self.cluster.resign_membership_now().await?;
            self.membership_signed_at = Instant::now();
        }
        let deadline = Instant::now() + WAIT;
        loop {
            if self
                .cluster
                .relays
                .iter()
                .filter(|relay| relay.running.is_some())
                .all(|relay| relay.peer_runtime.is_ready())
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "peers did not become ready at a case boundary".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    /// Open one legacy session for `consumer` and complete its lifecycle.
    async fn open_session(&self, consumer: &Consumer, uri: &str) -> Result<String> {
        let answer = consumer
            .send(
                "POST",
                uri,
                &legacy_headers(None),
                body_stream(initialize_body()),
            )
            .await?;
        if answer.status != 200 {
            return Err(self
                .session_open_refused(consumer, "initialize", &answer)
                .await);
        }
        let session = answer.session.clone().ok_or_else(|| {
            HarnessError::Process(format!(
                "{}: initialize returned no session",
                consumer.label
            ))
        })?;
        let initialized = Bytes::from(
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
        );
        let answer = consumer
            .send(
                "POST",
                uri,
                &legacy_headers(Some(&session)),
                body_stream(initialized),
            )
            .await?;
        if answer.status != 202 {
            return Err(self
                .session_open_refused(consumer, "notifications/initialized", &answer)
                .await);
        }
        Ok(session)
    }

    /// Wait for a held call's fixture marker `waiting-<gate>`, racing it
    /// against the call's own answer.
    ///
    /// A hold answered without its side effect starting would otherwise
    /// leave the wait to expire with nothing said about what the consumer
    /// saw (M3-26, M3-30).  The failure names the answer (status, typed code,
    /// execution, JSON-RPC error number), the owner session's rotation phase
    /// and the relays' peer fault tuples, all payload-free, so a rotation
    /// freeze refusal and a dial refused on an empty pin set read apart.
    async fn wait_hold_started(
        &self,
        gate: &str,
        what: &str,
        call: &mut tokio::task::JoinHandle<Result<Answer>>,
    ) -> Result<()> {
        let marker = self.markers(SERVICE_2025).join(format!("waiting-{gate}"));
        let started = tokio::select! {
            started = wait_file(&marker, WAIT) => started,
            joined = &mut *call => {
                let observed = match joined {
                    Ok(Ok(answer)) => answer.describe(),
                    Ok(Err(error)) => format!("request failed: {error}"),
                    Err(error) => format!("task did not join: {error}"),
                };
                let phase = self.owner_phase().await;
                let forensics = self.cluster.peer_path_forensics().await;
                return Err(HarnessError::Process(format!(
                    "{what} was answered before it started: {observed}; owner session {phase}; peer path: {forensics}"
                )));
            }
        };
        if !started {
            call.abort();
            let phase = self.owner_phase().await;
            return Err(HarnessError::Timeout(format!(
                "{what} never started and was still unanswered after {} s; owner session {phase}",
                WAIT.as_secs()
            )));
        }
        Ok(())
    }

    /// The owner session's rotation phase and completed-rotation count, for
    /// a failure message.
    async fn owner_phase(&self) -> String {
        let Ok(relay) = self.cluster.relay("relay-a") else {
            return "unknown (no relay-a)".into();
        };
        let Ok(snapshot) = relay.snapshot().await else {
            return "unknown (no snapshot)".into();
        };
        snapshot
            .sessions
            .iter()
            .find(|session| session.session_id == self.session_id)
            .map_or_else(
                || "missing".into(),
                |session| {
                    format!(
                        "phase={:?} rotations_completed={}",
                        session.phase, session.rotations_completed
                    )
                },
            )
    }

    /// A session-opening step answered with anything but success, described
    /// payload-free with the relays' peer fault tuples and pin state: a
    /// `503 PEER_UNAVAILABLE` here is otherwise indistinguishable between a
    /// rotation freeze and a dial refused on an empty pin set (M3-30).
    async fn session_open_refused(
        &self,
        consumer: &Consumer,
        step: &str,
        answer: &Answer,
    ) -> HarnessError {
        let phase = self.owner_phase().await;
        let forensics = self.cluster.peer_path_forensics().await;
        HarnessError::Process(format!(
            "{}: {step} answered {}; owner session {phase}; peer path: {forensics}",
            consumer.label,
            answer.describe()
        ))
    }

    /// End one legacy session as its owning principal would, and report
    /// whether the device accepted the DELETE.
    async fn delete_session(&self, consumer: &Consumer, session: &str) -> Result<bool> {
        let uri = self.uri(SERVICE_2025);
        let answer = consumer
            .send(
                "DELETE",
                &uri,
                &[
                    ("mcp-protocol-version", "2025-11-25"),
                    (tunnel_mcp::headers::MCP_SESSION_ID, session),
                ],
                empty(),
            )
            .await?;
        if answer.status != 204 {
            eprintln!(
                "MCP isolation gate: {} could not end its session: status {}",
                consumer.label, answer.status
            );
        }
        Ok(answer.status == 204)
    }

    // ---- case: binding forgery ---------------------------------------------

    /// Every consumer attempt to supply the relay-only principal binding,
    /// on both profiles and every route the profile serves.
    ///
    /// This is the whole basis of the unkeyed design: because a consumer can
    /// never put the header on the wire, the digest does not have to be
    /// secret.  A forgery must be refused before admission — not stripped,
    /// not overwritten — with an answer that says nothing about the header.
    async fn binding_forgery(&mut self, consumer: &Consumer) -> Result<ForgeryEvidence> {
        let name = tunnel_mcp::headers::TUNNEL_PRINCIPAL_BINDING;
        let forged = "0a1b2c3d4e5f60718a7f2c9a1b4d6e8f";
        let other = "7f2c9a1b4d6e8f0a1b2c3d4e5f60718a";
        let rejections_before = self.ingress_rejections().await?;
        let dispatched_before =
            self.export(SERVICE_2025).dispatched + self.export(SERVICE_2026).dispatched;
        let mut evidence = ForgeryEvidence::default();
        let list =
            Bytes::from(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string());
        for label in [SERVICE_2025, SERVICE_2026] {
            let uri = self.uri(label);
            let version = if label == SERVICE_2025 {
                "2025-11-25"
            } else {
                "2026-07-28"
            };
            for method in ["POST", "GET", "DELETE"] {
                // One value, then the same header twice with different
                // values: neither may be admitted, and a repeat must not be
                // collapsed into an accepted singleton.
                for repeated in [false, true] {
                    let mut headers = vec![
                        ("content-type", "application/json"),
                        ("accept", "application/json, text/event-stream"),
                        ("mcp-protocol-version", version),
                        (name, forged),
                    ];
                    if repeated {
                        headers.push((name, other));
                    }
                    if method != "POST" {
                        headers.retain(|(header, _)| *header != "content-type");
                    }
                    let body = if method == "POST" {
                        body_stream(list.clone())
                    } else {
                        empty()
                    };
                    let answer = consumer.send(method, &uri, &headers, body).await?;
                    evidence.attempts += 1;
                    let (code, execution) = answer.error();
                    if answer.status == 400
                        && code == "HTTP_INVALID_HEAD"
                        && execution == "not_dispatched"
                    {
                        evidence.refused += 1;
                    } else {
                        eprintln!(
                            "MCP isolation gate: forged binding on {label} {method} (repeated={repeated}) answered {} {code} {execution}",
                            answer.status
                        );
                    }
                }
            }
        }
        evidence.ingress_rejections = self
            .ingress_rejections()
            .await?
            .saturating_sub(rejections_before);
        evidence.dispatched = (self.export(SERVICE_2025).dispatched
            + self.export(SERVICE_2026).dispatched)
            .saturating_sub(dispatched_before);
        Ok(evidence)
    }

    /// The highest device exchange stream ID recorded for `service`.  The
    /// connector keeps a bounded log, so a new exchange is identified by its
    /// stream ID rather than by the log growing.
    fn highest_device_stream(&self, service: &str) -> u64 {
        self.device_diagnostics
            .snapshot()
            .iter()
            .filter(|record| record.service_id == service)
            .map(|record| record.stream_id)
            .max()
            .unwrap_or(0)
    }

    /// Requests relay-c refused before admission.
    async fn ingress_rejections(&self) -> Result<u64> {
        Ok(self
            .cluster
            .relay("relay-c")?
            .snapshot()
            .await?
            .http_forward
            .ingress_rejected_before_admission)
    }

    // ---- case: session isolation -------------------------------------------

    async fn session_isolation(
        &mut self,
        alice: &Consumer,
        bob: &Consumer,
    ) -> Result<(IsolationEvidence, String, String)> {
        let uri = self.uri(SERVICE_2025);
        let before = self.export(SERVICE_2025);
        let mut evidence = IsolationEvidence::default();
        let alice_session = self.open_session(alice, &uri).await?;
        let bob_session = self.open_session(bob, &uri).await?;
        evidence.sessions_distinct = alice_session != bob_session;

        let list =
            Bytes::from(json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}).to_string());
        // Bob presents Alice's session ID on every legacy route.
        let foreign = bob
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(&alice_session)),
                body_stream(list.clone()),
            )
            .await?;
        evidence.foreign_post_status = foreign.status;
        // The same request naming a session that never existed: the control
        // for every route below.
        let absent_id = "ffffffffffffffffffffffffffffffff";
        let absent = bob
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(absent_id)),
                body_stream(list.clone()),
            )
            .await?;
        fn get_headers(session: &str) -> Vec<(&str, &str)> {
            vec![
                ("accept", "text/event-stream"),
                ("mcp-protocol-version", "2025-11-25"),
                (tunnel_mcp::headers::MCP_SESSION_ID, session),
            ]
        }
        fn delete_headers(session: &str) -> Vec<(&str, &str)> {
            vec![
                ("mcp-protocol-version", "2025-11-25"),
                (tunnel_mcp::headers::MCP_SESSION_ID, session),
            ]
        }
        let foreign_get = bob
            .send("GET", &uri, &get_headers(&alice_session), empty())
            .await?;
        let absent_get = bob
            .send("GET", &uri, &get_headers(absent_id), empty())
            .await?;
        evidence.foreign_get_status = foreign_get.status;
        let foreign_delete = bob
            .send("DELETE", &uri, &delete_headers(&alice_session), empty())
            .await?;
        let absent_delete = bob
            .send("DELETE", &uri, &delete_headers(absent_id), empty())
            .await?;
        evidence.foreign_delete_status = foreign_delete.status;
        // Indistinguishable on every route, field for field: status, every
        // response header except `date`, and the body bytes.
        evidence.foreign_matches_unknown = foreign.indistinguishable_from(&absent)
            && foreign_get.indistinguishable_from(&absent_get)
            && foreign_delete.indistinguishable_from(&absent_delete);

        // Both sessions still work.
        let alice_answer = alice
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(&alice_session)),
                body_stream(list.clone()),
            )
            .await?;
        evidence.owner_still_served = alice_answer.status == 200
            && alice_answer
                .final_message()
                .is_some_and(|message| id_matches(&message, "7") && message["result"].is_object());
        let bob_answer = bob
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(&bob_session)),
                body_stream(list),
            )
            .await?;
        evidence.sibling_still_served = bob_answer.status == 200
            && bob_answer
                .final_message()
                .is_some_and(|message| id_matches(&message, "7") && message["result"].is_object());

        // No cross-delivery: each principal's standalone stream carries only
        // the notifications its own call asked for.
        let alice_call = async {
            alice
                .send(
                    "POST",
                    &uri,
                    &legacy_headers(Some(&alice_session)),
                    body_stream(call_body(
                        "11",
                        "log",
                        &json!({"label": "alice", "count": ISOLATION_LOG_COUNT}),
                        None,
                    )),
                )
                .await
        };
        let bob_call = async {
            bob.send(
                "POST",
                &uri,
                &legacy_headers(Some(&bob_session)),
                body_stream(call_body(
                    "11",
                    "log",
                    &json!({"label": "bob", "count": ISOLATION_LOG_COUNT}),
                    None,
                )),
            )
            .await
        };
        // Both standalone streams are opened, and the device has answered
        // both heads, before either call starts: the answered head is the
        // signal that the session's standalone stream is registered, so the
        // ordering here is a real event and not a sleep.
        let alice_stream = alice.open_standalone(&uri, &alice_session).await?;
        let bob_stream = bob.open_standalone(&uri, &bob_session).await?;
        let (alice_events, bob_events, alice_result, bob_result) = tokio::join!(
            alice_stream.collect(ISOLATION_LOG_COUNT as usize, Duration::from_secs(10)),
            bob_stream.collect(ISOLATION_LOG_COUNT as usize, Duration::from_secs(10)),
            alice_call,
            bob_call,
        );
        let alice_result = alice_result?;
        let bob_result = bob_result?;
        let label_of = |events: &[Value]| -> Vec<String> {
            events
                .iter()
                .filter_map(|event| event["params"]["data"]["label"].as_str())
                .map(str::to_owned)
                .collect()
        };
        let alice_labels = label_of(&alice_events);
        let bob_labels = label_of(&bob_events);
        evidence.own_notifications = alice_labels.len() as u64;
        evidence.sibling_notifications = bob_labels.len() as u64;
        evidence.no_cross_delivery = alice_labels.iter().all(|label| label == "alice")
            && bob_labels.iter().all(|label| label == "bob")
            && alice_result.status == 200
            && bob_result.status == 200
            && alice_result
                .final_message()
                .is_some_and(|message| id_matches(&message, "11"))
            && bob_result
                .final_message()
                .is_some_and(|message| id_matches(&message, "11"));

        let after = self.export(SERVICE_2025);
        evidence.sessions_opened = after.sessions_opened - before.sessions_opened;
        evidence.children_spawned = after.children_spawned - before.children_spawned;
        // Fail here rather than letting a later case fail for an unrelated
        // reason: every case after this one uses these two sessions, so a
        // binding that did not hold would first show up as a missing session.
        if evidence.foreign_post_status != 404
            || evidence.foreign_get_status != 404
            || evidence.foreign_delete_status != 404
        {
            return Err(HarnessError::Process(format!(
                "another principal's session ID was accepted: post {} get {} delete {}",
                evidence.foreign_post_status,
                evidence.foreign_get_status,
                evidence.foreign_delete_status
            )));
        }
        Ok((evidence, alice_session, bob_session))
    }

    // ---- case: Streamable HTTP principal binding ---------------------------

    /// The same binding rule as `session_isolation`, over the real cluster
    /// against the Streamable HTTP export.
    ///
    /// M3-04 previously proved this export's binding only through
    /// `tunnel-mcp-fixture`'s in-process bridge.  Driving it here puts the
    /// whole path under it — non-owner ingress, the peer HTTP/3 hop, the
    /// owner actor, the rotating device WebSocket and the device's export —
    /// and, because one backend process serves every session on this export,
    /// removes the stdio case's per-session child as an alternative
    /// explanation for a foreign session ID being refused.
    async fn streamable_binding(
        &mut self,
        alice: &Consumer,
        bob: &Consumer,
    ) -> Result<StreamableBindingEvidence> {
        let uri = self.uri(SERVICE_HTTP_2025);
        let before = self.export(SERVICE_HTTP_2025);
        let mut evidence = StreamableBindingEvidence::default();
        let alice_session = self.open_session(alice, &uri).await?;
        let bob_session = self.open_session(bob, &uri).await?;
        evidence.sessions_distinct = alice_session != bob_session;

        let list =
            Bytes::from(json!({"jsonrpc": "2.0", "id": 21, "method": "tools/list"}).to_string());
        let absent_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        fn get_headers(session: &str) -> Vec<(&str, &str)> {
            vec![
                ("accept", "text/event-stream"),
                ("mcp-protocol-version", "2025-11-25"),
                (tunnel_mcp::headers::MCP_SESSION_ID, session),
            ]
        }
        fn delete_headers(session: &str) -> Vec<(&str, &str)> {
            vec![
                ("mcp-protocol-version", "2025-11-25"),
                (tunnel_mcp::headers::MCP_SESSION_ID, session),
            ]
        }

        let foreign = bob
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(&alice_session)),
                body_stream(list.clone()),
            )
            .await?;
        let absent = bob
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(absent_id)),
                body_stream(list.clone()),
            )
            .await?;
        evidence.foreign_post_status = foreign.status;

        let foreign_get = bob
            .send("GET", &uri, &get_headers(&alice_session), empty())
            .await?;
        let absent_get = bob
            .send("GET", &uri, &get_headers(absent_id), empty())
            .await?;
        evidence.foreign_get_status = foreign_get.status;

        let foreign_delete = bob
            .send("DELETE", &uri, &delete_headers(&alice_session), empty())
            .await?;
        let absent_delete = bob
            .send("DELETE", &uri, &delete_headers(absent_id), empty())
            .await?;
        evidence.foreign_delete_status = foreign_delete.status;
        evidence.foreign_matches_unknown = foreign.indistinguishable_from(&absent)
            && foreign_get.indistinguishable_from(&absent_get)
            && foreign_delete.indistinguishable_from(&absent_delete);

        let exact = |answer: &Answer| {
            answer.status == 200
                && answer.final_message().is_some_and(|message| {
                    id_matches(&message, "21") && message["result"].is_object()
                })
        };
        let alice_answer = alice
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(&alice_session)),
                body_stream(list.clone()),
            )
            .await?;
        evidence.owner_still_served = exact(&alice_answer);
        let bob_answer = bob
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(&bob_session)),
                body_stream(list),
            )
            .await?;
        evidence.sibling_still_served = exact(&bob_answer);

        let after = self.export(SERVICE_HTTP_2025);
        evidence.sessions_opened = after.sessions_opened - before.sessions_opened;
        // A Streamable HTTP backend is an address the export forwards to, not
        // a process it starts.  If the export had spawned a child here it
        // would be a stdio backend and this case would prove nothing the
        // stdio case does not.
        evidence.shared_backend =
            after.children_spawned == before.children_spawned && evidence.sessions_opened == 0;

        // Each principal ends its own session, and the end is checked by the
        // session becoming unusable rather than by a status code: the shared
        // backend acknowledges a DELETE with 202, not the stdio export's 204,
        // and an acknowledgement is not evidence that the session is gone.
        for (consumer, session) in [(alice, &alice_session), (bob, &bob_session)] {
            let deleted = consumer
                .send("DELETE", &uri, &delete_headers(session), empty())
                .await?;
            let after = consumer
                .send(
                    "POST",
                    &uri,
                    &legacy_headers(Some(session)),
                    body_stream(Bytes::from(
                        json!({"jsonrpc": "2.0", "id": 22, "method": "tools/list"}).to_string(),
                    )),
                )
                .await?;
            if (200..300).contains(&deleted.status) && after.status == 404 {
                evidence.sessions_ended += 1;
            } else {
                eprintln!(
                    "MCP isolation gate: {} could not end its Streamable HTTP session: delete {} reuse {}",
                    consumer.label, deleted.status, after.status
                );
            }
        }

        if evidence.foreign_post_status != 404
            || evidence.foreign_get_status != 404
            || evidence.foreign_delete_status != 404
        {
            return Err(HarnessError::Process(format!(
                "a Streamable HTTP session ID was accepted for another principal: post {} get {} delete {}",
                evidence.foreign_post_status,
                evidence.foreign_get_status,
                evidence.foreign_delete_status
            )));
        }
        Ok(evidence)
    }

    // ---- case: cross-tenant consumers --------------------------------------

    /// A consumer authenticated and authorized in another tenant drives this
    /// tenant's device and MCP session.
    ///
    /// Tenant separation is proven for the echo path by the M7 admission
    /// gates, but M3-04 never drove it for an MCP export, where a session ID
    /// is an extra handle a foreign tenant could try.  Nothing here may reach
    /// the device, and every refusal must be the same typed answer whether or
    /// not the session named actually exists — otherwise the refusal itself
    /// tells a foreign tenant which of this tenant's sessions are live.
    async fn cross_tenant(
        &mut self,
        foreign: &Consumer,
        tenant: &Consumer,
        tenant_session: &str,
        foreign_tenant_id: uuid::Uuid,
    ) -> Result<CrossTenantEvidence> {
        let uri = self.uri(SERVICE_2025);
        let service = self
            .services
            .get(SERVICE_2025)
            .map(ToString::to_string)
            .unwrap_or_default();
        let before = self.export(SERVICE_2025);
        let dispatched_before = before.dispatched;
        let exchanges_before = self.highest_device_stream(&service);
        let mut evidence = CrossTenantEvidence {
            foreign_tenant: foreign_tenant_id != self.tenant_id,
            ..CrossTenantEvidence::default()
        };

        let list =
            Bytes::from(json!({"jsonrpc": "2.0", "id": 31, "method": "tools/list"}).to_string());
        let absent_id = "dddddddddddddddddddddddddddddddd";
        let mut answers = Vec::new();

        // Opening a fresh session: the foreign tenant has no grant for this
        // device at all, so this is refused before any session exists.
        let initialize = foreign
            .send(
                "POST",
                &uri,
                &legacy_headers(None),
                body_stream(initialize_body()),
            )
            .await?;
        evidence.initialize_status = initialize.status;
        let (code, execution) = initialize.error();
        evidence.initialize_code = code;
        evidence.initialize_execution = execution;
        answers.push(initialize);

        // This tenant's live session ID, then one that never existed, on
        // every legacy route.  The pairs must be indistinguishable.
        let post_live = foreign
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(tenant_session)),
                body_stream(list.clone()),
            )
            .await?;
        let post_absent = foreign
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(absent_id)),
                body_stream(list.clone()),
            )
            .await?;
        evidence.session_post_status = post_live.status;
        fn get_headers(session: &str) -> Vec<(&str, &str)> {
            vec![
                ("accept", "text/event-stream"),
                ("mcp-protocol-version", "2025-11-25"),
                (tunnel_mcp::headers::MCP_SESSION_ID, session),
            ]
        }
        fn delete_headers(session: &str) -> Vec<(&str, &str)> {
            vec![
                ("mcp-protocol-version", "2025-11-25"),
                (tunnel_mcp::headers::MCP_SESSION_ID, session),
            ]
        }
        let get_live = foreign
            .send("GET", &uri, &get_headers(tenant_session), empty())
            .await?;
        let get_absent = foreign
            .send("GET", &uri, &get_headers(absent_id), empty())
            .await?;
        evidence.session_get_status = get_live.status;
        let delete_live = foreign
            .send("DELETE", &uri, &delete_headers(tenant_session), empty())
            .await?;
        let delete_absent = foreign
            .send("DELETE", &uri, &delete_headers(absent_id), empty())
            .await?;
        evidence.session_delete_status = delete_live.status;

        evidence.uniform_refusal = post_live.indistinguishable_from(&post_absent)
            && get_live.indistinguishable_from(&get_absent)
            && delete_live.indistinguishable_from(&delete_absent);
        answers.extend([
            post_live,
            post_absent,
            get_live,
            get_absent,
            delete_live,
            delete_absent,
        ]);

        evidence.attempts = answers.len();
        evidence.refused = answers
            .iter()
            .filter(|answer| {
                let (_, execution) = answer.error();
                // Refused, and refused before anything was dispatched: a
                // foreign tenant must never receive an `unknown` outcome,
                // because that would mean the relay could not rule out that
                // its request reached this tenant's device.
                (400..500).contains(&answer.status) && execution == "not_dispatched"
            })
            .count();

        let after = self.export(SERVICE_2025);
        evidence.dispatched = after.dispatched.saturating_sub(dispatched_before);
        evidence.sessions_opened = after.sessions_opened - before.sessions_opened;
        evidence.device_exchanges = self
            .highest_device_stream(&service)
            .saturating_sub(exchanges_before);

        // This tenant's own session is untouched by all of it.
        let served = tenant
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(tenant_session)),
                body_stream(list),
            )
            .await?;
        evidence.tenant_session_served = served.status == 200
            && served
                .final_message()
                .is_some_and(|message| id_matches(&message, "31") && message["result"].is_object());

        if evidence.refused != evidence.attempts {
            return Err(HarnessError::Process(format!(
                "a cross-tenant consumer was not refused before dispatch on every route: {} of {} refused, initialize {} {} {}",
                evidence.refused,
                evidence.attempts,
                evidence.initialize_status,
                evidence.initialize_code,
                evidence.initialize_execution
            )));
        }
        Ok(evidence)
    }

    // ---- case: correlation --------------------------------------------------

    async fn correlation(
        &mut self,
        alice: &Consumer,
        bob: &Consumer,
        alice_session: &str,
        bob_session: &str,
    ) -> Result<CorrelationEvidence> {
        let legacy_uri = self.uri(SERVICE_2025);
        let current_uri = self.uri(SERVICE_2026);
        let mut evidence = CorrelationEvidence {
            calls_per_principal: CORRELATION_CALLS,
            ..CorrelationEvidence::default()
        };

        // (a) Sessionless 2026: both principals reuse every ID at once.
        let mut tasks = Vec::new();
        for (consumer, who) in [(alice, "alice"), (bob, "bob")] {
            for id in COLLIDING_IDS {
                let arguments = json!({"who": who, "id": id});
                let consumer = consumer.clone();
                let uri = current_uri.clone();
                let body = call_body(id, "echo", &arguments, Some(current_meta()));
                tasks.push(tokio::spawn(async move {
                    let answer = consumer
                        .send("POST", &uri, &current_headers("echo"), body_stream(body))
                        .await;
                    (id, arguments, answer)
                }));
            }
        }
        let mut sessionless_exact = true;
        for task in tasks {
            let (id, arguments, answer) = task
                .await
                .map_err(|error| HarnessError::Process(format!("sessionless join: {error}")))?;
            let answer = answer?;
            evidence.answers += 1;
            let ok = answer.status == 200
                && answer.final_message().is_some_and(|message| {
                    id_matches(&message, id) && echo_matches(&message, &arguments)
                });
            if !ok {
                sessionless_exact = false;
                evidence.misrouted += 1;
            }
        }
        evidence.sessionless_exact = sessionless_exact;

        // (b) 2025 sessions: the same IDs and the same progress tokens on two
        // sessions of two principals, all in flight at once.
        let mut tasks = Vec::new();
        for (consumer, session, who) in [(alice, alice_session, "alice"), (bob, bob_session, "bob")]
        {
            for id in COLLIDING_IDS {
                let arguments = json!({"who": who, "id": id});
                let consumer = consumer.clone();
                let uri = legacy_uri.clone();
                let session = session.to_owned();
                // The progress token collides across sessions and principals
                // deliberately; it is unique only within one session.
                let meta = json!({"progressToken": format!("token-{id}")});
                let body = call_body(id, "echo", &arguments, Some(meta));
                tasks.push(tokio::spawn(async move {
                    let answer = consumer
                        .send(
                            "POST",
                            &uri,
                            &legacy_headers(Some(&session)),
                            body_stream(body),
                        )
                        .await;
                    (id, arguments, answer)
                }));
            }
        }
        let mut session_exact = true;
        for task in tasks {
            let (id, arguments, answer) = task
                .await
                .map_err(|error| HarnessError::Process(format!("session join: {error}")))?;
            let answer = answer?;
            evidence.answers += 1;
            let ok = answer.status == 200
                && answer.final_message().is_some_and(|message| {
                    id_matches(&message, id) && echo_matches(&message, &arguments)
                });
            if !ok {
                session_exact = false;
                evidence.misrouted += 1;
            }
        }
        evidence.session_exact = session_exact;

        // (c) Colliding progress tokens follow their own request: a `progress`
        // call on each session with the same token must see its own events.
        let token = json!({"progressToken": "shared-progress-token"});
        let progress_body = |who: &str| {
            call_body(
                "77",
                "progress",
                &json!({"steps": 3, "who": who}),
                Some(token.clone()),
            )
        };
        let alice_progress_headers = legacy_headers(Some(alice_session));
        let bob_progress_headers = legacy_headers(Some(bob_session));
        let (alice_progress, bob_progress) = tokio::join!(
            alice.send(
                "POST",
                &legacy_uri,
                &alice_progress_headers,
                body_stream(progress_body("alice")),
            ),
            bob.send(
                "POST",
                &legacy_uri,
                &bob_progress_headers,
                body_stream(progress_body("bob")),
            ),
        );
        let progress_ok = |answer: &Answer| {
            let values: Vec<f64> = answer
                .messages()
                .iter()
                .filter(|message| message["method"] == "notifications/progress")
                .filter_map(|message| message["params"]["progress"].as_f64())
                .collect();
            answer.status == 200
                && values == vec![1.0, 2.0, 3.0]
                && answer
                    .final_message()
                    .is_some_and(|message| id_matches(&message, "77"))
        };
        let alice_progress = alice_progress?;
        let bob_progress = bob_progress?;
        evidence.progress_exact = progress_ok(&alice_progress) && progress_ok(&bob_progress);

        // (d) A genuine duplicate on one session is refused while the first
        // is in flight: the same ID, and separately the same progress token.
        let held = call_body(
            "\"held\"",
            "gate",
            &json!({"label": "dup"}),
            Some(json!({"progressToken": "duplicate-token"})),
        );
        let uri = legacy_uri.clone();
        let session = alice_session.to_owned();
        let holder = {
            let consumer = alice.clone();
            tokio::spawn(async move {
                consumer
                    .send(
                        "POST",
                        &uri,
                        &legacy_headers(Some(&session)),
                        body_stream(held),
                    )
                    .await
            })
        };
        let mut holder = holder;
        self.wait_hold_started("gatedup", "the duplicate-probe hold", &mut holder)
            .await?;
        let duplicate_id = alice
            .send(
                "POST",
                &legacy_uri,
                &legacy_headers(Some(alice_session)),
                body_stream(call_body(
                    "\"held\"",
                    "echo",
                    &json!({"duplicate": "id"}),
                    None,
                )),
            )
            .await?;
        evidence.duplicate_id_status = duplicate_id.status;
        let duplicate_token = alice
            .send(
                "POST",
                &legacy_uri,
                &legacy_headers(Some(alice_session)),
                body_stream(call_body(
                    "\"other\"",
                    "echo",
                    &json!({"duplicate": "token"}),
                    Some(json!({"progressToken": "duplicate-token"})),
                )),
            )
            .await?;
        evidence.duplicate_token_status = duplicate_token.status;
        std::fs::write(self.markers(SERVICE_2025).join("release-gatedup"), b"go")
            .map_err(HarnessError::Io)?;
        let released = timeout(WAIT, holder)
            .await
            .map_err(|_| HarnessError::Timeout("the duplicate-probe hold never released".into()))?
            .map_err(|error| HarnessError::Process(format!("hold join: {error}")))??;
        if released.status != 200 {
            return Err(HarnessError::Process(format!(
                "the duplicate-probe hold answered {}",
                released.status
            )));
        }
        Ok(evidence)
    }

    // ---- case: revocation ---------------------------------------------------

    async fn revocation(
        &mut self,
        victim: &Consumer,
        sibling: &Consumer,
        sibling_session: &str,
        principal_id: uuid::Uuid,
    ) -> Result<RevocationEvidence> {
        let uri = self.uri(SERVICE_2025);
        let mut evidence = RevocationEvidence::default();
        let service_id = self.services.get(SERVICE_2025).copied().unwrap_or_default();

        // A session and one answered call before anything is revoked.
        let session = self.open_session(victim, &uri).await?;
        let baseline = victim
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(&session)),
                body_stream(call_body("1", "echo", &json!({"phase": "baseline"}), None)),
            )
            .await?;
        evidence.baseline_status = baseline.status;

        // A call is held mid-flight, then the grant is revoked.
        let held = call_body("2", "gate", &json!({"label": "revoke"}), None);
        let in_flight = {
            let consumer = victim.clone();
            let uri = uri.clone();
            let session = session.clone();
            tokio::spawn(async move {
                consumer
                    .send(
                        "POST",
                        &uri,
                        &legacy_headers(Some(&session)),
                        body_stream(held),
                    )
                    .await
            })
        };
        let mut in_flight = in_flight;
        self.wait_hold_started("gaterevoke", "the revocation hold", &mut in_flight)
            .await?;
        let dispatched_before = self.export(SERVICE_2025).dispatched;
        let revoked_at = Instant::now();
        self.cluster
            .catalog
            .revoke_grant(
                self.tenant_id,
                principal_id,
                self.device_id,
                service_id,
                chrono::Utc::now(),
            )
            .await
            .map_err(|error| HarnessError::Process(format!("revoke grant: {error}")))?;

        // A fresh request must fail closed promptly and never be dispatched.
        let deadline = Instant::now() + REVOCATION_BOUND;
        let after = loop {
            let attempt = victim
                .send(
                    "POST",
                    &uri,
                    &legacy_headers(Some(&session)),
                    body_stream(call_body("3", "echo", &json!({"phase": "after"}), None)),
                )
                .await?;
            // Only the revocation's own typed refusal ends the wait; a
            // transient owner-not-ready 503 is retried, so this loop cannot
            // mistake a rotation freeze for a revocation.
            let (code, _) = attempt.error();
            if (attempt.status == 404 && code == "SERVICE_NOT_FOUND") || Instant::now() >= deadline
            {
                break attempt;
            }
            sleep(POLL).await;
        };
        evidence.failed_within_ms = revoked_at.elapsed().as_millis();
        evidence.after_status = after.status;
        let (code, execution) = after.error();
        evidence.after_code = code;
        evidence.after_execution = execution;
        evidence.revoked_session_unreachable = after.status != 200;

        // The held exchange is left running, still blocked in the fixture, for
        // the whole revocation bound.  If revocation withdraws an admitted
        // exchange the consumer's request ends on its own inside that bound;
        // otherwise it is still open, and the gate says so rather than
        // releasing it early and reading a success as if it proved anything.
        let mut in_flight = in_flight;
        let withdrawn = timeout(REVOCATION_BOUND, &mut in_flight).await;
        evidence.in_flight_withdrawn = withdrawn.is_ok();
        evidence.withdrawn_within_ms = revoked_at.elapsed().as_millis();
        let terminal =
            match withdrawn {
                Ok(joined) => Some(joined),
                Err(_) => {
                    // Still open: release it and record what the consumer got.
                    std::fs::write(self.markers(SERVICE_2025).join("release-gaterevoke"), b"go")
                        .map_err(HarnessError::Io)?;
                    Some(timeout(OUTCOME_WAIT, in_flight).await.map_err(|_| {
                        HarnessError::Timeout("the revoked call never ended".into())
                    })?)
                }
            };
        match terminal {
            Some(Ok(Ok(answer))) => {
                evidence.in_flight_status = answer.status;
                let (code, execution) = answer.error();
                evidence.in_flight_code = code;
                evidence.in_flight_execution = execution;
            }
            Some(Ok(Err(error))) => {
                // The consumer's transport ended with no answer at all.
                // Nothing is invented here: the evidence stays empty and the
                // validator refuses it, because a bare close is not the typed
                // interruption the documentation claims.
                eprintln!("MCP isolation gate: revoked call ended in transport: {error}");
            }
            Some(Err(error)) => {
                return Err(HarnessError::Process(format!("revocation join: {error}")));
            }
            None => {}
        }
        // Whatever happened to the admitted exchange, nothing new may have
        // been dispatched to the device after the grant went away.  The held
        // call's own dispatch was counted before the revocation.
        evidence.dispatched_after = self
            .export(SERVICE_2025)
            .dispatched
            .saturating_sub(dispatched_before);
        std::fs::write(self.markers(SERVICE_2025).join("release-gaterevoke"), b"go")
            .map_err(HarnessError::Io)?;
        let sibling_answer = sibling
            .send(
                "POST",
                &uri,
                &legacy_headers(Some(sibling_session)),
                body_stream(call_body("4", "echo", &json!({"phase": "sibling"}), None)),
            )
            .await?;
        evidence.sibling_principal_served = sibling_answer.status == 200
            && sibling_answer
                .final_message()
                .is_some_and(|message| id_matches(&message, "4"));
        evidence.device_session_survived = self.device_session_present().await;
        Ok(evidence)
    }

    // ---- case: a call spanning rotations ------------------------------------

    /// The owner session's rotation phase and completed-rotation count.
    async fn owner_rotation(&self) -> Result<(String, u64)> {
        let snapshot = self.cluster.relay("relay-a")?.snapshot().await?;
        Ok(snapshot
            .sessions
            .iter()
            .find(|session| session.session_id == self.session_id)
            .map_or_else(
                || ("missing".to_owned(), 0),
                |session| (session.phase.clone(), session.rotations_completed),
            ))
    }

    /// Wait for the owner to complete its next scheduled rotation and return
    /// the new completed count and when it was observed.
    ///
    /// The owner starts a scheduled rotation only once its session has been
    /// `active` for a whole interval since the previous `ROTATE_COMPLETE`
    /// (`last_rotation`, reset in the same step that increments
    /// `rotations_completed`; `rotation_due` in `tunnel-relay` `actor.rs`).
    /// So from a completion observed here, no freeze can begin for
    /// `ISOLATION_ROTATION.interval_seconds`: the case's requests start in
    /// that window rather than wherever the rotation schedule happens to be
    /// when the case begins (M3-34).
    async fn after_rotation_complete(&self) -> Result<(u64, Instant)> {
        let (_, entry) = self.owner_rotation().await?;
        let deadline = Instant::now() + ANCHOR_BOUND;
        loop {
            let (phase, completed) = self.owner_rotation().await?;
            if completed > entry {
                return Ok((completed, Instant::now()));
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "no scheduled rotation completed within {} s (rotation interval {} s) to anchor the spanning call; owner session phase={phase:?} rotations_completed={completed}",
                    ANCHOR_BOUND.as_secs(),
                    ISOLATION_ROTATION.interval_seconds
                )));
            }
            sleep(POLL).await;
        }
    }

    /// One held call that must be in flight across `ROTATION_SPAN` completed
    /// scheduled rotations.
    ///
    /// The case anchors on a rotation completion before it sends anything
    /// (M3-34).  Unanchored, it began wherever the 6 s schedule happened to
    /// be: on hosted Linux the case starts at about 6.1 s, at the session's
    /// first freeze, and the spanning call reached the owner after it had
    /// quiesced but before the connector had seen `ROTATE_QUIESCE` (the owner
    /// quiesces as soon as the candidate attaches), so the call was refused
    /// `not_dispatched` outside any freeze the gate could observe, and was
    /// correctly not resent (M3-30).  A resend would not have helped the
    /// case either: a call admitted only after that rotation is not in
    /// flight across it.  So the case also proves, rather than assumes, that
    /// the call reached the device before any rotation it is credited with
    /// began, and counts rotations from the anchor.
    async fn rotation_span(
        &mut self,
        consumer: &Consumer,
    ) -> Result<(RotationSpanEvidence, String)> {
        let uri = self.uri(SERVICE_2025);
        let (rotations_before, anchored_at) = self.after_rotation_complete().await?;
        let session = self.open_session(consumer, &uri).await?;
        let before = self.invocations(SERVICE_2025, "gate");
        let session_before = self.session_id.clone();
        let body = call_body("5", "gate", &json!({"label": "span"}), None);
        let call = {
            let consumer = consumer.clone();
            let uri = uri.clone();
            let session = session.clone();
            tokio::spawn(async move {
                consumer
                    .send(
                        "POST",
                        &uri,
                        &legacy_headers(Some(&session)),
                        body_stream(body),
                    )
                    .await
            })
        };
        let mut call = call;
        self.wait_hold_started("gatespan", "the spanning call", &mut call)
            .await?;
        let anchor_to_dispatch_ms = anchored_at.elapsed().as_millis();
        // The hold has started, so the call is on the device.  If the owner
        // is still `active` with the anchor's count, no rotation has begun
        // since the anchor, so every rotation counted below began after the
        // call was dispatched.
        let (phase_at_dispatch, completed_at_dispatch) = self.owner_rotation().await?;
        let dispatched_between_rotations =
            phase_at_dispatch == "active" && completed_at_dispatch == rotations_before;
        if !dispatched_between_rotations {
            eprintln!(
                "MCP isolation gate: the spanning call started {anchor_to_dispatch_ms} ms after its anchor (rotation interval {} ms) with the owner session phase={phase_at_dispatch:?} rotations_completed={completed_at_dispatch} (anchor {rotations_before})",
                ISOLATION_ROTATION.interval_seconds * 1_000
            );
        }
        let deadline = Instant::now() + ROTATION_BOUND;
        let spanned = loop {
            let spanned = self
                .rotations_completed()
                .await?
                .saturating_sub(rotations_before);
            if spanned >= ROTATION_SPAN {
                break spanned;
            }
            if Instant::now() >= deadline {
                call.abort();
                return Err(HarnessError::Timeout(format!(
                    "only {spanned} rotations completed while the call was open"
                )));
            }
            sleep(POLL).await;
        };
        std::fs::write(self.markers(SERVICE_2025).join("release-gatespan"), b"go")
            .map_err(HarnessError::Io)?;
        let answer = timeout(OUTCOME_WAIT, call)
            .await
            .map_err(|_| HarnessError::Timeout("the spanning call never answered".into()))?
            .map_err(|error| HarnessError::Process(format!("span join: {error}")))??;
        let result_exact = answer.final_message().is_some_and(|message| {
            id_matches(&message, "5")
                && message["result"]["content"]
                    .as_array()
                    .and_then(|blocks| blocks.first())
                    .and_then(|block| block["text"].as_str())
                    == Some("released-span")
        });
        Ok((
            RotationSpanEvidence {
                rotations_spanned: spanned,
                dispatched_between_rotations,
                anchor_to_dispatch_ms,
                status: answer.status,
                result_exact,
                invocations: self
                    .invocations(SERVICE_2025, "gate")
                    .saturating_sub(before),
                session_stable: self.session_id == session_before,
            },
            session,
        ))
    }

    // ---- case: explicit unknown outcomes ------------------------------------

    /// Hold a call until the fixture has recorded its synthetic side effect,
    /// apply `fault`, release, and record the outcome the consumer saw.
    async fn unknown_outcome<F>(
        &mut self,
        consumer: &Consumer,
        session: &str,
        label: &'static str,
        fault_name: &str,
        settle: Settle,
        fault: F,
    ) -> Result<UnknownOutcomeEvidence>
    where
        F: AsyncFnOnce(&mut Self) -> Result<()>,
    {
        let uri = self.uri(SERVICE_2025);
        let before = self.invocations(SERVICE_2025, "gate");
        let body = call_body("6", "gate", &json!({"label": label}), None);
        // How long the consumer's POST stayed outstanding is itself evidence:
        // it separates an immediate pin-watcher close from a handshake or
        // idle deadline.  Diagnostics only, on the failure path.
        let issued = Instant::now();
        let call = {
            let consumer = consumer.clone();
            let uri = uri.clone();
            let session = session.to_owned();
            tokio::spawn(async move {
                let answered = consumer
                    .send(
                        "POST",
                        &uri,
                        &legacy_headers(Some(&session)),
                        body_stream(body),
                    )
                    .await;
                (answered, issued.elapsed())
            })
        };
        let service = self
            .services
            .get(SERVICE_2025)
            .map(ToString::to_string)
            .unwrap_or_default();
        let highest_before = self.highest_device_stream(&service);
        let waiting = self
            .markers(SERVICE_2025)
            .join(format!("waiting-gate{label}"));
        if !wait_file(&waiting, WAIT).await {
            // The side effect never ran.  Reporting only that fact cannot
            // distinguish a request lost or refused before dispatch from one
            // dispatched but never recorded, which is exactly the ambiguity
            // that left the cause of this gate's observed timeouts open (see
            // M7-C83).  Give the consumer's own call a bounded grace and name
            // what it saw.  Failure path only: it asserts nothing and cannot
            // turn a failing run green.
            let mut call = call;
            let observed = match timeout(OUTCOME_STATUS_GRACE, &mut call).await {
                Ok(Ok((Ok(answer), latency))) => {
                    let (code, execution) = answer.error();
                    format!(
                        "consumer status {} code={code:?} execution={execution:?} answered {} ms after it was issued",
                        answer.status,
                        latency.as_millis(),
                    )
                }
                Ok(Ok((Err(error), latency))) => format!(
                    "consumer request failed after {} ms: {error}",
                    latency.as_millis()
                ),
                Ok(Err(error)) => format!("consumer task did not join: {error}"),
                Err(_) => {
                    // Keep the pre-diagnostic cleanup: a call still running
                    // when the grace expires is stopped, not left to the
                    // process.
                    call.abort();
                    "consumer request still outstanding".to_owned()
                }
            };
            // The consumer's status alone cannot say whether the request ever
            // left the ingress.  Join it with the relays' own bounded
            // `role/stage/cause` tuples and their transport pin state, which
            // together separate a fresh dial refused on an empty pin set from
            // a hop closed under a request the owner had already seen.
            let forensics = self.cluster.peer_path_forensics().await;
            return Err(HarnessError::Timeout(format!(
                "the {fault_name} side effect never ran ({observed}); peer path: {forensics}"
            )));
        }
        // The side effect has run exactly once at this point.
        let side_effects_before_fault = self
            .invocations(SERVICE_2025, "gate")
            .saturating_sub(before);
        fault(self).await?;
        std::fs::write(
            self.markers(SERVICE_2025)
                .join(format!("release-gate{label}")),
            b"go",
        )
        .map_err(HarnessError::Io)?;
        let answer = timeout(OUTCOME_WAIT, call)
            .await
            .map_err(|_| HarnessError::Timeout(format!("{fault_name} outcome timed out")))?
            .map_err(|error| HarnessError::Process(format!("{fault_name} join: {error}")))?;
        let answer = answer.0.unwrap_or_default();
        // Settle on an observed event, never on a sleep.  A fault the session
        // survives settles when the device has finished and recorded the
        // exchange, because a replay would be a second record; a fault that
        // ends the session settles when the connector leaves readiness,
        // because the stream a replay would need is gone with it.
        let deadline = Instant::now() + OUTCOME_WAIT;
        loop {
            let ended = self
                .client
                .as_ref()
                .is_none_or(|client| !client.readiness().borrow().is_ready());
            let recorded = self.highest_device_stream(&service) > highest_before;
            if settle == Settle::SessionEnded && ended {
                break;
            }
            if settle == Settle::DeviceRecord && recorded {
                break;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "the {fault_name} exchange never settled (recorded={recorded} session_ended={ended})"
                )));
            }
            sleep(POLL).await;
        }
        let (code, execution) = answer.error();
        Ok(UnknownOutcomeEvidence {
            settled_on: settle.as_str().to_owned(),
            device_exchanges: self
                .device_diagnostics
                .snapshot()
                .iter()
                .filter(|record| record.service_id == service && record.stream_id > highest_before)
                .count(),
            fault: fault_name.to_owned(),
            side_effects_before_fault,
            side_effects_after_outcome: self
                .invocations(SERVICE_2025, "gate")
                .saturating_sub(before),
            status: answer.status,
            body_code: code,
            body_execution: execution,
            result_outcome: answer.result_outcome(),
        })
    }
}

/// The device runtime configuration: the harness device profile plus one
/// `[exports.<service>.mcp]` stdio table per service this gate drives,
/// parsed and validated by `tunnel-client` exactly as `connect` loads it.
fn device_config_text(
    base: &str,
    services: &[(&'static str, uuid::Uuid, &'static str)],
    fixture: &Path,
    marker_dirs: &std::collections::BTreeMap<&'static str, PathBuf>,
    http_backend: &HttpBackend,
) -> Result<String> {
    let quote = |value: &str| serde_json::to_string(value).unwrap_or_default();
    let mut text = base.to_owned();
    for (label, service_id, profile) in services {
        let workspace = marker_dirs
            .get(label)
            .ok_or_else(|| HarnessError::InvalidInput("marker directory missing".into()))?;
        text.push_str(&format!(
            "\n[exports.\"{service_id}\"]\ntype = \"http-forward\"\n\n[exports.\"{service_id}\".mcp]\nprofile = {}\n\n[exports.\"{service_id}\".mcp.backend]\n",
            quote(profile),
        ));
        if *label == SERVICE_HTTP_2025 {
            text.push_str(&format!(
                "kind = \"streamable-http\"\nurl = {}\n",
                quote(&format!("http://{}/mcp", http_backend.address))
            ));
        } else {
            text.push_str(&format!(
                "kind = \"stdio\"\ncommand = {}\nargs = [\"stdio\"]\nworkspace = {}\nmax_children = 16\nsession_idle_seconds = 600\n",
                quote(&fixture.to_string_lossy()),
                quote(&workspace.to_string_lossy()),
            ));
        }
    }
    Ok(text)
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<McpIsolationEvidence> {
    let options = HarnessOptions::from_env()?
        .mcp_services(true)
        .rotation(ISOLATION_ROTATION);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("MCP isolation harness startup timed out".into()))??;
    let serve = tunnel_relay::HttpForwardServeConfig {
        profiles: vec![PROFILE_2026.to_owned(), PROFILE_2025.to_owned()],
        request_body_bytes: None,
        response_body_bytes: None,
        deadline_seconds: None,
        public_url: None,
    };
    let exports = match serve.exports() {
        Ok(exports) => exports,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(HarnessError::InvalidInput(format!(
                "[http_forward] profiles: {error}"
            )));
        }
    };
    let relay_profiles = exports.profile_ids().map(str::to_owned).collect();
    harness.http_forward = Some(exports);
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        run(&mut cluster, &harness, relay_profiles),
    )
    .await
    {
        Ok(result) => result.and_then(|evidence| {
            if let Err(error) = validate_mcp_isolation_evidence(&evidence) {
                eprintln!("MCP isolation evidence: {evidence:?}");
                return Err(error);
            }
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "MCP isolation scenario exceeded its bounded deadline".into(),
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

#[allow(clippy::too_many_lines)]
async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    relay_profiles: Vec<String>,
) -> Result<McpIsolationEvidence> {
    let mut evidence = McpIsolationEvidence {
        relay_count: cluster.relays.len(),
        relay_profiles,
        ingress_node: "relay-c".to_owned(),
        principals: 2,
        resign_spacing_ms: MEMBERSHIP_RESIGN_SPACING.as_millis(),
        not_covered: NOT_COVERED.iter().map(|item| (*item).to_owned()).collect(),
        ..McpIsolationEvidence::default()
    };
    evidence.relay_profiles.sort();
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("isolation gate device is missing".into()))?;
    let echo_service = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("isolation gate echo service missing".into()))?;
    let mut services = std::collections::BTreeMap::new();
    let mut wanted = Vec::new();
    for service in &harness.mcp_services {
        if service.label == SERVICE_2025
            || service.label == SERVICE_2026
            || service.label == SERVICE_HTTP_2025
        {
            services.insert(service.label, service.service_id);
            wanted.push((service.label, service.service_id, service.profile));
        }
    }
    if wanted.len() != 3 {
        return Err(HarnessError::InvalidInput(
            "the two stdio and one Streamable HTTP MCP services were not seeded".into(),
        ));
    }
    let fixture = fixture_binary_path()?;
    let root = tempfile::tempdir().map_err(HarnessError::Io)?;
    let root_path = root.path().canonicalize().map_err(HarnessError::Io)?;
    let mut marker_dirs = std::collections::BTreeMap::new();
    for (label, _, _) in &wanted {
        let dir = root_path.join(label);
        std::fs::create_dir_all(&dir).map_err(HarnessError::Io)?;
        marker_dirs.insert(*label, dir);
    }
    let owner_device_addr = cluster
        .relay("relay-a")?
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| HarnessError::Process("relay-a is not running".into()))?;
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let device_profile = write_device_profile(
        profile_directory.path(),
        device.id,
        echo_service,
        "m3-mcp-isolation-canary",
        owner_device_addr,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    // One shared Streamable HTTP backend process for the legacy HTTP export.
    // The device forwards to its address; it starts no child per session, so
    // the binding case over it cannot be explained by process isolation.
    let http_marker_dir = marker_dirs
        .get(SERVICE_HTTP_2025)
        .cloned()
        .ok_or_else(|| HarnessError::InvalidInput("HTTP marker directory missing".into()))?;
    let mut http_backend = HttpBackend::start(&fixture, &http_marker_dir, true).await?;
    let base = std::fs::read_to_string(&device_profile.config_path).map_err(HarnessError::Io)?;
    let text = device_config_text(&base, &wanted, &fixture, &marker_dirs, &http_backend)?;
    let mut config = tunnel_client::ConnectConfig::parse(&text)
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;
    config.rotation = ISOLATION_ROTATION;
    config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;

    let ingress = cluster.relay("relay-c")?.consumer_addr()?;
    let ca = harness.pki.server_ca.certificate_der.clone();
    let scope = OidcTokenOptions {
        scope: Some("echo:invoke http:invoke".to_owned()),
        ..OidcTokenOptions::default()
    };
    let principal = |index: usize| -> Result<&crate::fixture::ConsumerFixture> {
        harness
            .topology
            .consumers_a
            .get(index)
            .ok_or_else(|| HarnessError::InvalidInput("a consumer principal is missing".into()))
    };
    let freeze = Arc::new(FreezeWatch::default());
    let refusals = Arc::new(FreezeRefusals::default());
    let alice = Consumer {
        label: "consumer-a-1",
        token: harness
            .oidc
            .issue_with(&principal(0)?.name, scope.clone())?,
        ingress,
        ca: ca.clone(),
        freeze: Arc::clone(&freeze),
        refusals: Arc::clone(&refusals),
    };
    let bob = Consumer {
        label: "consumer-a-2",
        token: harness
            .oidc
            .issue_with(&principal(1)?.name, scope.clone())?,
        ingress,
        ca: ca.clone(),
        freeze: Arc::clone(&freeze),
        refusals: Arc::clone(&refusals),
    };
    // The revocation victim is a third principal, so revoking it cannot
    // disturb the isolation and correlation evidence.
    let victim = Consumer {
        label: "owner-a",
        token: harness
            .oidc
            .issue_with(&harness.topology.owner_a.name, scope.clone())?,
        ingress,
        ca: ca.clone(),
        freeze: Arc::clone(&freeze),
        refusals: Arc::clone(&refusals),
    };
    let victim_id = harness.topology.owner_a.id;
    // A fully authenticated consumer of the *other* tenant, holding the same
    // scopes against its own tenant's devices.  Its token is valid; what it
    // lacks is any grant in this tenant.
    let foreign_principal = harness
        .topology
        .consumers_b
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("a tenant-B consumer is missing".into()))?;
    let carol = Consumer {
        label: "consumer-b-1",
        token: harness.oidc.issue_with(&foreign_principal.name, scope)?,
        ingress,
        ca: ca.clone(),
        freeze: Arc::clone(&freeze),
        refusals: Arc::clone(&refusals),
    };
    let foreign_tenant_id = harness.topology.tenant_b.id;

    let mut gate = Gate {
        cluster,
        config,
        client: None,
        device_diagnostics: DeviceHttpDiagnostics::default(),
        mcp_diagnostics: McpExportDiagnostics::default(),
        session_id: String::new(),
        tenant_id: device.tenant_id,
        device_id: device.id,
        services,
        marker_dirs,
        membership_signed_at: Instant::now()
            .checked_sub(MEMBERSHIP_RESIGN_SPACING)
            .unwrap_or_else(Instant::now),
        journal_peak: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        journal_task: None,
        freeze: Arc::clone(&freeze),
    };

    let started = Instant::now();
    let run_result = async {
        evidence.owner_node = gate.connect_device().await?;
        evidence.non_owner_ingress = evidence.owner_node == "relay-a";
        evidence.device_sessions += 1;

        eprintln!(
            "MCP isolation gate: binding-forgery at {} ms",
            started.elapsed().as_millis()
        );
        gate.boundary().await?;
        evidence.forgery = gate.binding_forgery(&alice).await?;

        eprintln!(
            "MCP isolation gate: session-isolation at {} ms",
            started.elapsed().as_millis()
        );
        gate.boundary().await?;
        let (isolation, alice_session, bob_session) = gate.session_isolation(&alice, &bob).await?;
        evidence.isolation = isolation;
        evidence.sessions_opened += 2;

        eprintln!(
            "MCP isolation gate: streamable-binding at {} ms",
            started.elapsed().as_millis()
        );
        gate.boundary().await?;
        evidence.streamable_binding = gate.streamable_binding(&alice, &bob).await?;
        eprintln!(
            "MCP isolation gate: streamable-binding foreign post/get/delete {}/{}/{} indistinguishable={} shared_backend={} sessions_ended={}",
            evidence.streamable_binding.foreign_post_status,
            evidence.streamable_binding.foreign_get_status,
            evidence.streamable_binding.foreign_delete_status,
            evidence.streamable_binding.foreign_matches_unknown,
            evidence.streamable_binding.shared_backend,
            evidence.streamable_binding.sessions_ended,
        );

        eprintln!(
            "MCP isolation gate: cross-tenant at {} ms",
            started.elapsed().as_millis()
        );
        gate.boundary().await?;
        evidence.cross_tenant = gate
            .cross_tenant(&carol, &alice, &alice_session, foreign_tenant_id)
            .await?;
        eprintln!(
            "MCP isolation gate: cross-tenant {} of {} refused, initialize {} {} {}, uniform={} dispatched={} device_exchanges={}",
            evidence.cross_tenant.refused,
            evidence.cross_tenant.attempts,
            evidence.cross_tenant.initialize_status,
            evidence.cross_tenant.initialize_code,
            evidence.cross_tenant.initialize_execution,
            evidence.cross_tenant.uniform_refusal,
            evidence.cross_tenant.dispatched,
            evidence.cross_tenant.device_exchanges,
        );
        evidence.foreign_tenant_principals = 1;

        eprintln!(
            "MCP isolation gate: correlation at {} ms",
            started.elapsed().as_millis()
        );
        gate.boundary().await?;
        evidence.correlation = gate
            .correlation(&alice, &bob, &alice_session, &bob_session)
            .await?;

        eprintln!(
            "MCP isolation gate: revocation at {} ms",
            started.elapsed().as_millis()
        );
        gate.boundary().await?;
        evidence.revocation = gate
            .revocation(&victim, &alice, &alice_session, victim_id)
            .await?;
        evidence.sessions_opened += 1;

        eprintln!(
            "MCP isolation gate: rotation-span at {} ms",
            started.elapsed().as_millis()
        );
        gate.boundary().await?;
        let (rotation_span, span_session) = gate.rotation_span(&alice).await?;
        evidence.rotation_span = rotation_span;
        evidence.sessions_opened += 1;

        eprintln!(
            "MCP isolation gate: unknown-outcome at {} ms",
            started.elapsed().as_millis()
        );
        gate.boundary().await?;
        evidence.lost_ack = gate
            .unknown_outcome(
                &alice,
                &alice_session,
                "lostack",
                "owner_to_ingress_path_blackholed",
                Settle::DeviceRecord,
                async |gate: &mut Gate<'_>| {
                    gate.cluster
                        .set_peer_path_drop_from("relay-a", "relay-c", true)
                },
            )
            .await?;
        gate.cluster
            .set_peer_path_drop_from("relay-a", "relay-c", false)?;
        evidence.journal_entries_peak = gate.journal_peak();

        // The lost-acknowledgement case blackholed a peer path; wait for the
        // route to recover before anything else is sent.
        gate.boundary().await?;
        // End every session this gate can still end, as a well-behaved client
        // would.  The revoked principal's session cannot be ended: the relay
        // refuses its DELETE along with everything else it sends.
        for (consumer, session) in [
            (&alice, &alice_session),
            (&bob, &bob_session),
            (&alice, &span_session),
        ] {
            if gate.delete_session(consumer, session).await? {
                evidence.sessions_deleted += 1;
            }
        }

        // Owner loss ends the device session, so it is last.
        gate.boundary().await?;
        let owner_session = gate.open_session(&alice, &gate.uri(SERVICE_2025)).await?;
        evidence.sessions_opened += 1;
        evidence.owner_loss = gate
            .unknown_outcome(
                &alice,
                &owner_session,
                "ownerloss",
                "owner_process_loss",
                Settle::SessionEnded,
                async |gate: &mut Gate<'_>| gate.cluster.shutdown_node("relay-a").await,
            )
            .await?;
        Ok::<_, HarnessError>(())
    }
    .await;

    if let Some(task) = gate.journal_task.take() {
        task.abort();
    }
    if let Some(client) = gate.client.take() {
        let _ = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    }
    // The connector kills each export child's process group when its exports
    // are dropped with the session; give that a bounded moment to land.
    for _ in 0..40 {
        if gate.export(SERVICE_2025).children_running + gate.export(SERVICE_2026).children_running
            == 0
        {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    evidence.children_after_stop =
        gate.export(SERVICE_2025).children_running + gate.export(SERVICE_2026).children_running;
    drop(gate);
    // The Streamable HTTP backend is the gate's own process, not the
    // connector's, so the gate ends it whatever the run did.
    http_backend.stop().await;
    (
        evidence.freeze_refusals,
        evidence.freeze_resends,
        evidence.unexplained_refusal,
    ) = refusals.snapshot();
    eprintln!(
        "MCP isolation gate: rotation-freeze refusals={} resent={} first_outside_an_observed_freeze={:?}",
        evidence.freeze_refusals, evidence.freeze_resends, evidence.unexplained_refusal
    );
    run_result?;
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &str) -> Answer {
        Answer {
            status,
            body: body.as_bytes().to_vec(),
            ..Answer::default()
        }
    }

    /// M3-15: only the relay's retryable rotation-freeze refusal carries a
    /// resend hint.  The owner-not-ready body (resent inside a freeze before
    /// M3-15, M3-30) now answers only fault states; it, an `unknown` 503, a
    /// non-retryable one and any other status reach their case unchanged.
    #[test]
    fn only_the_retryable_rotation_freeze_refusal_is_a_resend_candidate() {
        // Byte-for-byte the relay bodies (`tunnel-relay/src/http.rs`):
        // `rotation_freeze_response(250)`,
        // `retryable_peer_failure_response(250)` and
        // `peer_trust_unavailable_response()`.
        let refusal = r#"{"code":"ROTATION_FREEZE","execution":"not_dispatched","message":"device data rotation is in progress; retry after the bounded hint","retryable":true,"retry_after_ms":250}"#;
        let owner_not_ready = r#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched","message":"selected owner is not ready; retry after the bounded hint","retryable":true,"retry_after_ms":250}"#;
        let empty_pin_set = r#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched","message":"no approved peer trust evidence is published; retry after the bounded hint","retryable":true,"retry_after_ms":5000}"#;
        assert_eq!(
            answer(503, refusal).rotation_freeze_hint(),
            Some(Duration::from_millis(250))
        );
        let shorter = refusal.replace(r#""retry_after_ms":250"#, r#""retry_after_ms":40"#);
        assert_eq!(
            answer(503, &shorter).rotation_freeze_hint(),
            Some(Duration::from_millis(40))
        );
        assert_eq!(answer(503, owner_not_ready).rotation_freeze_hint(), None);
        assert_eq!(answer(503, empty_pin_set).rotation_freeze_hint(), None);
        let long = refusal.replace(r#""retry_after_ms":250"#, r#""retry_after_ms":5000"#);
        let no_hint = refusal.replace(r#","retry_after_ms":250"#, "");
        for body in [
            long.as_str(),
            no_hint.as_str(),
            r#"{"code":"ROTATION_FREEZE","execution":"unknown","message":"device data rotation is in progress; retry after the bounded hint","retryable":true,"retry_after_ms":250}"#,
            r#"{"code":"ROTATION_FREEZE","execution":"not_dispatched","retryable":false,"retry_after_ms":250}"#,
            r#"{"code":"ROTATION_FREEZE","execution":"not_dispatched"}"#,
            "not json",
        ] {
            assert_eq!(answer(503, body).rotation_freeze_hint(), None, "{body}");
        }
        assert_eq!(answer(502, refusal).rotation_freeze_hint(), None);
        const { assert!(FREEZE_RESENDS >= 1) };
    }

    fn outcome(fault: &str, settle: Settle) -> UnknownOutcomeEvidence {
        UnknownOutcomeEvidence {
            fault: fault.to_owned(),
            settled_on: settle.as_str().to_owned(),
            device_exchanges: usize::from(settle == Settle::DeviceRecord),
            side_effects_before_fault: 1,
            side_effects_after_outcome: 1,
            status: 504,
            body_code: "HTTP_DEADLINE_EXCEEDED".into(),
            body_execution: "unknown".into(),
            result_outcome: "outcome_unknown".into(),
        }
    }

    fn passing() -> McpIsolationEvidence {
        McpIsolationEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            ingress_node: "relay-c".into(),
            non_owner_ingress: true,
            relay_profiles: vec![PROFILE_2025.to_owned(), PROFILE_2026.to_owned()],
            principals: 2,
            device_sessions: 1,
            journal_entries_peak: 1,
            forgery: ForgeryEvidence {
                attempts: FORGERY_ATTEMPTS,
                refused: FORGERY_ATTEMPTS,
                ingress_rejections: FORGERY_ATTEMPTS as u64,
                dispatched: 0,
            },
            isolation: IsolationEvidence {
                sessions_distinct: true,
                foreign_post_status: 404,
                foreign_get_status: 404,
                foreign_delete_status: 404,
                foreign_matches_unknown: true,
                owner_still_served: true,
                sibling_still_served: true,
                own_notifications: ISOLATION_LOG_COUNT,
                sibling_notifications: ISOLATION_LOG_COUNT,
                no_cross_delivery: true,
                sessions_opened: 2,
                children_spawned: 2,
            },
            foreign_tenant_principals: 1,
            streamable_binding: StreamableBindingEvidence {
                shared_backend: true,
                sessions_distinct: true,
                foreign_post_status: 404,
                foreign_get_status: 404,
                foreign_delete_status: 404,
                foreign_matches_unknown: true,
                owner_still_served: true,
                sibling_still_served: true,
                sessions_opened: 0,
                sessions_ended: 2,
            },
            cross_tenant: CrossTenantEvidence {
                foreign_tenant: true,
                initialize_status: 404,
                initialize_code: "DEVICE_NOT_FOUND".into(),
                initialize_execution: "not_dispatched".into(),
                session_post_status: 404,
                session_get_status: 404,
                session_delete_status: 404,
                refused: 7,
                attempts: 7,
                uniform_refusal: true,
                dispatched: 0,
                sessions_opened: 0,
                device_exchanges: 0,
                tenant_session_served: true,
            },
            correlation: CorrelationEvidence {
                calls_per_principal: CORRELATION_CALLS,
                sessionless_exact: true,
                session_exact: true,
                progress_exact: true,
                duplicate_id_status: 400,
                duplicate_token_status: 400,
                answers: CORRELATION_CALLS * 4,
                misrouted: 0,
            },
            revocation: RevocationEvidence {
                baseline_status: 200,
                in_flight_withdrawn: true,
                withdrawn_within_ms: 500,
                in_flight_status: 502,
                in_flight_code: "HTTP_STREAM_INTERRUPTED".into(),
                in_flight_execution: "unknown".into(),
                after_status: 404,
                after_code: "SERVICE_NOT_FOUND".into(),
                after_execution: "not_dispatched".into(),
                failed_within_ms: 500,
                dispatched_after: 0,
                sibling_principal_served: true,
                device_session_survived: true,
                revoked_session_unreachable: true,
            },
            rotation_span: RotationSpanEvidence {
                rotations_spanned: ROTATION_SPAN,
                dispatched_between_rotations: true,
                anchor_to_dispatch_ms: 40,
                status: 200,
                result_exact: true,
                invocations: 1,
                session_stable: true,
            },
            lost_ack: outcome("owner_to_ingress_path_blackholed", Settle::DeviceRecord),
            owner_loss: outcome("owner_process_loss", Settle::SessionEnded),
            resign_spacing_ms: MEMBERSHIP_RESIGN_SPACING.as_millis(),
            sessions_opened: 5,
            sessions_deleted: 3,
            children_after_stop: 0,
            freeze_refusals: 0,
            freeze_resends: 0,
            unexplained_refusal: None,
            not_covered: NOT_COVERED.iter().map(|item| (*item).to_owned()).collect(),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn validator_accepts_passing_evidence_and_rejects_every_single_mutation() {
        validate_mcp_isolation_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut McpIsolationEvidence));
        let mutations: Vec<Mutation> = vec![
            ("relays", |e| e.relay_count = 2),
            ("owner ingress", |e| e.non_owner_ingress = false),
            ("ingress node", |e| e.ingress_node = "relay-a".into()),
            ("owner node", |e| e.owner_node = "relay-c".into()),
            ("profiles", |e| {
                e.relay_profiles = vec![PROFILE_2025.to_owned()];
            }),
            ("principals", |e| e.principals = 1),
            ("device sessions", |e| e.device_sessions = 2),
            ("journal", |e| {
                e.journal_entries_peak = JOURNAL_ENTRY_BOUND + 1;
            }),
            ("a forgery was admitted", |e| e.forgery.refused -= 1),
            ("a forgery was not counted", |e| {
                e.forgery.ingress_rejections -= 1
            }),
            ("fewer forgeries were tried", |e| e.forgery.attempts -= 1),
            ("a forgery reached the device", |e| e.forgery.dispatched = 1),
            ("sessions distinct", |e| {
                e.isolation.sessions_distinct = false;
            }),
            ("foreign POST", |e| e.isolation.foreign_post_status = 200),
            ("foreign GET", |e| e.isolation.foreign_get_status = 200),
            ("foreign DELETE", |e| {
                e.isolation.foreign_delete_status = 204;
            }),
            ("refusal distinguishable", |e| {
                e.isolation.foreign_matches_unknown = false;
            }),
            ("owner session broken", |e| {
                e.isolation.owner_still_served = false;
            }),
            ("sibling session broken", |e| {
                e.isolation.sibling_still_served = false;
            }),
            ("own notifications", |e| e.isolation.own_notifications = 3),
            ("sibling notifications", |e| {
                e.isolation.sibling_notifications = 5;
            }),
            ("cross delivery", |e| {
                e.isolation.no_cross_delivery = false;
            }),
            ("the Streamable HTTP backend was not shared", |e| {
                e.streamable_binding.shared_backend = false;
            }),
            ("Streamable HTTP sessions not distinct", |e| {
                e.streamable_binding.sessions_distinct = false;
            }),
            ("Streamable HTTP foreign POST", |e| {
                e.streamable_binding.foreign_post_status = 200;
            }),
            ("Streamable HTTP foreign GET", |e| {
                e.streamable_binding.foreign_get_status = 200;
            }),
            ("Streamable HTTP foreign DELETE", |e| {
                e.streamable_binding.foreign_delete_status = 202;
            }),
            ("Streamable HTTP refusal distinguishable", |e| {
                e.streamable_binding.foreign_matches_unknown = false;
            }),
            ("Streamable HTTP owner session broken", |e| {
                e.streamable_binding.owner_still_served = false;
            }),
            ("Streamable HTTP sibling session broken", |e| {
                e.streamable_binding.sibling_still_served = false;
            }),
            ("a Streamable HTTP session outlived its DELETE", |e| {
                e.streamable_binding.sessions_ended = 1;
            }),
            ("no foreign tenant was driven", |e| {
                e.foreign_tenant_principals = 0;
            }),
            ("the cross-tenant principal was of this tenant", |e| {
                e.cross_tenant.foreign_tenant = false;
            }),
            ("a cross-tenant consumer opened a session", |e| {
                e.cross_tenant.initialize_status = 200;
            }),
            ("a cross-tenant refusal claimed uncertainty", |e| {
                e.cross_tenant.initialize_execution = "unknown".into();
            }),
            ("a cross-tenant refusal carried no code", |e| {
                e.cross_tenant.initialize_code = String::new();
            }),
            ("a cross-tenant request was not refused", |e| {
                e.cross_tenant.refused -= 1;
            }),
            ("fewer cross-tenant routes were tried", |e| {
                e.cross_tenant.attempts -= 1;
                e.cross_tenant.refused -= 1;
            }),
            ("a cross-tenant refusal revealed the session", |e| {
                e.cross_tenant.uniform_refusal = false;
            }),
            ("a cross-tenant request reached the device", |e| {
                e.cross_tenant.dispatched = 1;
            }),
            ("a cross-tenant request opened an export session", |e| {
                e.cross_tenant.sessions_opened = 1;
            }),
            ("a cross-tenant request produced a device exchange", |e| {
                e.cross_tenant.device_exchanges = 1;
            }),
            ("the tenant's own session was disturbed", |e| {
                e.cross_tenant.tenant_session_served = false;
            }),
            ("sessions opened", |e| e.isolation.sessions_opened = 3),
            ("children spawned", |e| e.isolation.children_spawned = 3),
            ("calls per principal", |e| {
                e.correlation.calls_per_principal = CORRELATION_CALLS - 1;
            }),
            ("sessionless correlation", |e| {
                e.correlation.sessionless_exact = false;
            }),
            ("session correlation", |e| {
                e.correlation.session_exact = false;
            }),
            ("progress correlation", |e| {
                e.correlation.progress_exact = false;
            }),
            ("duplicate id accepted", |e| {
                e.correlation.duplicate_id_status = 200;
            }),
            ("duplicate token accepted", |e| {
                e.correlation.duplicate_token_status = 200;
            }),
            ("missing answers", |e| e.correlation.answers -= 1),
            ("misrouted", |e| e.correlation.misrouted = 1),
            ("revocation baseline", |e| {
                e.revocation.baseline_status = 403;
            }),
            ("the exchange was not withdrawn", |e| {
                e.revocation.in_flight_withdrawn = false;
            }),
            ("the withdrawal was slower than the bound", |e| {
                e.revocation.withdrawn_within_ms = REVOCATION_WITHDRAWAL_BOUND.as_millis() + 1;
            }),
            ("the withdrawn exchange returned a result", |e| {
                e.revocation.in_flight_status = 200;
            }),
            ("the withdrawal carried no typed code", |e| {
                e.revocation.in_flight_code.clear();
            }),
            ("the withdrawal carried no execution", |e| {
                e.revocation.in_flight_execution.clear();
            }),
            ("revocation not refused", |e| {
                e.revocation.after_status = 200;
            }),
            ("revocation refused with another code", |e| {
                e.revocation.after_code = "DEVICE_NOT_FOUND".into();
            }),
            ("revocation dispatched", |e| {
                e.revocation.after_execution = "dispatched".into();
            }),
            ("revocation slow", |e| {
                e.revocation.failed_within_ms = REVOCATION_BOUND.as_millis() + 1;
            }),
            ("dispatch after revocation", |e| {
                e.revocation.dispatched_after = 1;
            }),
            ("revoked session reachable", |e| {
                e.revocation.revoked_session_unreachable = false;
            }),
            ("blast radius sibling", |e| {
                e.revocation.sibling_principal_served = false;
            }),
            ("blast radius device", |e| {
                e.revocation.device_session_survived = false;
            }),
            ("rotations spanned", |e| {
                e.rotation_span.rotations_spanned = ROTATION_SPAN - 1;
            }),
            ("span dispatched inside a freeze", |e| {
                e.rotation_span.dispatched_between_rotations = false;
            }),
            ("span status", |e| e.rotation_span.status = 504),
            ("span bytes", |e| e.rotation_span.result_exact = false),
            ("span replayed", |e| e.rotation_span.invocations = 2),
            ("span session changed", |e| {
                e.rotation_span.session_stable = false;
            }),
            ("lost ack fault", |e| e.lost_ack.fault = "other".into()),
            ("lost ack side effect missing", |e| {
                e.lost_ack.side_effects_before_fault = 0;
            }),
            ("lost ack replayed", |e| {
                e.lost_ack.side_effects_after_outcome = 2;
            }),
            ("lost ack second device exchange", |e| {
                e.lost_ack.device_exchanges = 2;
            }),
            ("lost ack settled on nothing", |e| {
                e.lost_ack.settled_on.clear();
            }),
            ("owner loss settled on the wrong event", |e| {
                e.owner_loss.settled_on = Settle::DeviceRecord.as_str().to_owned();
            }),
            ("lost ack outcome", |e| {
                e.lost_ack.result_outcome = "failed".into();
            }),
            ("lost ack execution", |e| {
                e.lost_ack.body_execution = "dispatched".into();
            }),
            ("lost ack code", |e| e.lost_ack.body_code.clear()),
            ("lost ack status", |e| e.lost_ack.status = 200),
            ("owner loss fault", |e| e.owner_loss.fault = "other".into()),
            ("owner loss replayed", |e| {
                e.owner_loss.side_effects_after_outcome = 2;
            }),
            ("owner loss outcome", |e| {
                e.owner_loss.result_outcome = "failed".into();
            }),
            ("a child survived the export", |e| e.children_after_stop = 1),
            ("a session leaked", |e| e.sessions_opened += 1),
            ("no session was ended", |e| e.sessions_deleted = 0),
            ("not covered dropped", |e| e.not_covered.clear()),
            ("resign spacing", |e| e.resign_spacing_ms = 0),
        ];
        for (name, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_mcp_isolation_evidence(&evidence).is_err(),
                "mutation {name} passed"
            );
        }
    }
}
