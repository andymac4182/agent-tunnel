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
use super::mcp_cloud_client::wire::{count_lines, fixture_binary_path, wait_file};
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
/// The cases, in order.
pub const MCP_ISOLATION_CASES: [&str; 6] = [
    "binding-forgery",
    "session-isolation",
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
/// How long an explicit outcome may take to reach the consumer after a
/// fault.
const OUTCOME_WAIT: Duration = Duration::from_secs(90);
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
pub const NOT_COVERED: [&str; 6] = [
    "server-to-client JSON-RPC requests (sampling/createMessage, elicitation/create, MRTR input): the pinned fixture issues none, so colliding server-to-client request IDs are unproven (M3-13)",
    "Origin validation and the MCP authorization profile, including token audience checks at the export (M3-11)",
    "Last-Event-ID resume of an interrupted legacy stream (M3-10)",
    "principal binding for a Streamable HTTP backend over the real cluster: proven in tunnel-mcp-fixture's principal_binding tests through the in-process bridge, not here",
    "cross-tenant consumers: both correlation principals are of one tenant, and tenant separation is M7 admission evidence",
    "correlation through one shared backend process: the 2025-11-25 stdio export gives each session its own child, so its correlation is process-isolated by construction; the Streamable HTTP export, where every session shares one backend, is not driven here (M3-13)",
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
    /// Completed scheduled rotations while the call was open.
    pub rotations_spanned: u64,
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
    pub forgery: ForgeryEvidence,
    pub isolation: IsolationEvidence,
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
    let checks: [(&str, bool); 34] = [
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
        text.split("\n\n")
            .filter_map(|event| event.strip_prefix("data: "))
            .filter_map(|data| serde_json::from_str(data).ok())
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
}

impl Consumer {
    async fn send(
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
        let mut status = client.status();
        {
            let snapshot = status.borrow_and_update();
            peak.fetch_max(snapshot.open_journal_entries, Ordering::Relaxed);
        }
        if let Some(task) = self.journal_task.take() {
            task.abort();
        }
        self.journal_task = Some(tokio::spawn(async move {
            while status.changed().await.is_ok() {
                let entries = status.borrow_and_update().open_journal_entries;
                peak.fetch_max(entries, Ordering::Relaxed);
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
            return Err(HarnessError::Process(format!(
                "{}: initialize answered {}",
                consumer.label, answer.status
            )));
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
            return Err(HarnessError::Process(format!(
                "{}: notifications/initialized answered {}",
                consumer.label, answer.status
            )));
        }
        Ok(session)
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
        if !wait_file(&self.markers(SERVICE_2025).join("waiting-gatedup"), WAIT).await {
            holder.abort();
            return Err(HarnessError::Timeout(
                "the duplicate-probe hold never started".into(),
            ));
        }
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
        if !wait_file(&self.markers(SERVICE_2025).join("waiting-gaterevoke"), WAIT).await {
            in_flight.abort();
            return Err(HarnessError::Timeout(
                "the revocation hold never started".into(),
            ));
        }
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

    async fn rotation_span(
        &mut self,
        consumer: &Consumer,
    ) -> Result<(RotationSpanEvidence, String)> {
        let uri = self.uri(SERVICE_2025);
        let session = self.open_session(consumer, &uri).await?;
        let before = self.invocations(SERVICE_2025, "gate");
        let rotations_before = self.rotations_completed().await?;
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
        if !wait_file(&self.markers(SERVICE_2025).join("waiting-gatespan"), WAIT).await {
            call.abort();
            return Err(HarnessError::Timeout(
                "the spanning call never started".into(),
            ));
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
        let call = {
            let consumer = consumer.clone();
            let uri = uri.clone();
            let session = session.to_owned();
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
            call.abort();
            return Err(HarnessError::Timeout(format!(
                "the {fault_name} side effect never ran"
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
        let answer = answer.unwrap_or_default();
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
) -> Result<String> {
    let quote = |value: &str| serde_json::to_string(value).unwrap_or_default();
    let mut text = base.to_owned();
    for (label, service_id, profile) in services {
        let workspace = marker_dirs
            .get(label)
            .ok_or_else(|| HarnessError::InvalidInput("marker directory missing".into()))?;
        text.push_str(&format!(
            "\n[exports.\"{service_id}\"]\ntype = \"http-forward\"\n\n[exports.\"{service_id}\".mcp]\nprofile = {}\n\n[exports.\"{service_id}\".mcp.backend]\nkind = \"stdio\"\ncommand = {}\nargs = [\"stdio\"]\nworkspace = {}\nmax_children = 16\nsession_idle_seconds = 600\n",
            quote(profile),
            quote(&fixture.to_string_lossy()),
            quote(&workspace.to_string_lossy()),
        ));
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
        if service.label == SERVICE_2025 || service.label == SERVICE_2026 {
            services.insert(service.label, service.service_id);
            wanted.push((service.label, service.service_id, service.profile));
        }
    }
    if wanted.len() != 2 {
        return Err(HarnessError::InvalidInput(
            "the two stdio MCP services were not seeded".into(),
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
    let base = std::fs::read_to_string(&device_profile.config_path).map_err(HarnessError::Io)?;
    let text = device_config_text(&base, &wanted, &fixture, &marker_dirs)?;
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
    let alice = Consumer {
        label: "consumer-a-1",
        token: harness
            .oidc
            .issue_with(&principal(0)?.name, scope.clone())?,
        ingress,
        ca: ca.clone(),
    };
    let bob = Consumer {
        label: "consumer-a-2",
        token: harness
            .oidc
            .issue_with(&principal(1)?.name, scope.clone())?,
        ingress,
        ca: ca.clone(),
    };
    // The revocation victim is a third principal, so revoking it cannot
    // disturb the isolation and correlation evidence.
    let victim = Consumer {
        label: "owner-a",
        token: harness
            .oidc
            .issue_with(&harness.topology.owner_a.name, scope)?,
        ingress,
        ca: ca.clone(),
    };
    let victim_id = harness.topology.owner_a.id;

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
    run_result?;
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

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
