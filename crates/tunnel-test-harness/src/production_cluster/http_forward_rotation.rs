//! Implementation gate 4 of docs/http-forwarding.md over the real cluster:
//! `http-forward/1` exchanges through non-owner ingress (relay-c), the peer
//! HTTP/3 hop, the owner actor (relay-a) and the device data WebSocket are
//! carried across real scheduled data-socket rotations.
//!
//! Each rotation point is its own exchange, route and handler counter, and
//! each is proven from the owner's payload-free rotation observation: the
//! record position the owner had sequenced (request) and received
//! (response) when it froze its writer at QUIESCE, the attempt's fences and
//! acknowledgement cursors, and the device's own record log.
//!
//! * `head`: the request HEAD crossed, no BODY yet.
//! * `partial-header`: three bytes of a BODY record header crossed.
//! * `partial-body`: a BODY header and part of its payload crossed.
//! * `end-before-fin`: END crossed, the request FIN had not.
//! * `early-response`: the response HEAD crossed while the upload was open.
//! * `credit-stall`: the owner withheld response credit (consumer not reading).
//! * `sse`: a long-lived SSE response spanned two rotations between events.
//!
//! The record positions inside a record header, inside a payload and between
//! END and FIN are only reachable by timing on the real path (the ingress
//! writes them back to back), so the owner relay's one-shot fixture hold
//! stops its next actor write there until the rotation has frozen; the
//! rotation, sequencing, carriers and device are unchanged.
//!
//! Then: a control `CANCEL` races the queued RESET during a freeze that is
//! held by pausing the active data socket's connector→relay bytes; lost
//! acknowledgements (the owner→ingress path blackholed) and owner process
//! loss after a synthetic side effect must each report `outcome_unknown` with
//! the handler invoked exactly once.  A head the codec would reject is
//! refused at ingress before any owner stream exists.
//!
//! All payloads, credentials and headers are synthetic.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, mpsc};
use tokio::time::{sleep, timeout};
use tunnel_client::http_forward::{
    DeviceHttpDiagnostics, DeviceHttpExchangeRecord, HttpExport, HttpHandler, HttpHandlerError,
    HttpHandlerFuture, HttpHandlers,
};
use tunnel_client::{ConnectOptions, LocalExport, LocalExportKind};
use tunnel_core::RotationConfig;
use tunnel_http_bridge::{BridgeConfig, ChannelBody, HandlerCancellation, Profile};
use tunnel_http_forward::{HttpVersion, Method, Occurrence, RequestPolicy, ResponsePolicy};
use tunnel_relay::http_forward_diagnostics::{
    HttpExchangeRecord, HttpOwnerStreamRecord, HttpRotationObservation, RelayHttpStreamSnapshot,
};
use tunnel_relay::{
    HttpForwardExport, HttpForwardExports, HttpRelayHoldPoint, RelaySessionSnapshot, RelaySnapshot,
};

use crate::http_relay_hold::HttpRelayHold;

use super::http_forward_real_path::{
    ConsumerStream, connect_consumer, empty_stream, full_body, handler_body, request,
    synthetic_chunk,
};
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

/// A short scheduled-rotation policy with enough overlap to hold a freeze.
pub const GATE_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 6,
    handshake_timeout_seconds: 2,
    overlap_seconds: 5,
};
/// The rotation cases, in order.
pub const ROTATION_CASES: [&str; 7] = [
    "head",
    "partial-header",
    "partial-body",
    "end-before-fin",
    "early-response",
    "credit-stall",
    "sse",
];
/// The owner's per-stream advertised window.
pub const STREAM_WINDOW_BYTES: usize = 128 * 1024;
/// The credit-stall download, larger than every buffer on the path.
pub const DOWNLOAD_BYTES: usize = 6 * 1024 * 1024;
const UPLOAD_CHUNK: usize = 50_000;
const UPLOAD_CHUNKS: usize = 4;
const HEADER_BYTES_AT_FENCE: u8 = 3;
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(360);
const WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(20);
const MAX_ROTATIONS_PER_CASE: u64 = 4;
const OUTCOME_WAIT: Duration = Duration::from_secs(45);
const MEMBERSHIP_RESIGN_SPACING: Duration = Duration::from_secs(15);

/// The case-boundary re-sign spacing.  `M3_ROTATION_RESIGN_SPACING_MS`
/// overrides it only to reproduce the back-to-back re-sign readiness defect
/// recorded in docs/tasks.md; a run with an override is not gate evidence.
fn resign_spacing() -> Duration {
    std::env::var("M3_ROTATION_RESIGN_SPACING_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(MEMBERSHIP_RESIGN_SPACING, Duration::from_millis)
}
const FROZEN_PHASES: [&str; 3] = ["quiescing", "draining", "committing"];
const SSE_EVENTS: [&[&[u8]]; 3] = [
    &[
        b"event: tick\r\ndata: synthetic-1 \xc3",
        b"\xa9\r",
        b"\n\r\n",
    ],
    &[b"data: synthetic-2\n", b"\n"],
    &[b"data: synthetic-", b"3 end\n\n"],
];

/// One rotation point.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RotationCaseEvidence {
    pub name: String,
    pub stream_id: u64,
    pub handler_invocations: usize,
    pub status: u16,
    pub bytes_exact: bool,
    pub body_ended_cleanly: bool,
    /// The owner observation(s) whose position matched this case.
    pub observations: Vec<HttpRotationObservation>,
    pub device_request_heads: u32,
    pub device_request_ends: u32,
    pub device_request_fin: bool,
    pub device_error: Option<String>,
    pub device_progress_expired: Option<String>,
    pub ingress_error: Option<String>,
    pub ingress_progress_expired: Option<String>,
    pub forgotten: bool,
}

/// The CANCEL/RESET race during a held freeze.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CancelRaceEvidence {
    pub stream_id: u64,
    pub freeze_observation_polls: usize,
    pub freeze_held: bool,
    pub handler_invocations: usize,
    pub handler_cancelled_while_frozen: bool,
    pub owner_still_frozen_after_cancel: bool,
    pub deferred_reset_while_frozen: bool,
    pub reset_unsequenced_while_frozen: bool,
    pub cancel_sent: bool,
    pub device_cancel_received: bool,
    pub observation: Option<HttpRotationObservation>,
    pub owner_record: Option<HttpOwnerStreamRecord>,
    pub device_error: Option<String>,
    pub ingress_error: Option<String>,
    pub forgotten: bool,
}

/// A synthetic side effect whose acknowledgement or owner was lost.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OutcomeUnknownEvidence {
    pub fault: String,
    pub side_effects_before_fault: usize,
    pub side_effects_after_outcome: usize,
    pub status: u16,
    pub body_code: String,
    pub body_execution: String,
    pub result_outcome: String,
    pub ingress_error: Option<String>,
    pub ingress_execution: Option<String>,
}

/// A head the codec rejects is refused before admission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdmissionProbeEvidence {
    pub status: u16,
    pub rejected_before_admission_delta: u64,
    pub ingress_exchange_delta: u64,
    pub owner_stream_delta: u64,
    pub owner_exchange_delta: u64,
    pub handler_invocations: usize,
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HttpForwardRotationEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    pub ingress_node: String,
    pub non_owner_ingress: bool,
    pub session_stable: bool,
    pub admission_probe: AdmissionProbeEvidence,
    pub cases: Vec<RotationCaseEvidence>,
    pub cancel_race: CancelRaceEvidence,
    pub lost_ack: OutcomeUnknownEvidence,
    pub owner_loss: OutcomeUnknownEvidence,
    pub rotations_completed: u64,
    /// Device TCP connections open at each settled steady state.
    pub steady_state_sockets: Vec<usize>,
    /// The most device TCP connections ever open at once before owner loss.
    pub device_socket_peak: u64,
    /// The effective case-boundary membership re-sign spacing, in
    /// milliseconds.  A run shortened by `M3_ROTATION_RESIGN_SPACING_MS` is a
    /// defect reproduction, not gate evidence.
    pub resign_spacing_ms: u128,
}

fn case<'a>(
    evidence: &'a HttpForwardRotationEvidence,
    name: &str,
) -> Option<&'a RotationCaseEvidence> {
    evidence.cases.iter().find(|case| case.name == name)
}

fn fence_accounted(observation: &HttpRotationObservation) -> bool {
    matches!(
        (
            observation.relay_fence,
            observation.relay_acknowledged,
            observation.connector_fence,
            observation.connector_acknowledged,
        ),
        (Some(relay), Some(relay_ack), Some(connector), Some(connector_ack))
            if relay == observation.frozen_last_emitted
                && relay_ack >= relay
                && connector_ack >= connector
    ) && observation.new_generation > observation.old_generation
}

/// Whether an observation shows this case's rotation point.
#[must_use]
pub fn position_matches(name: &str, observation: &HttpRotationObservation) -> bool {
    let request = &observation.request;
    let response = &observation.response;
    match name {
        "head" => {
            request.heads == 1
                && request.bodies == 0
                && request.ends == 0
                && request.position == "boundary"
                && response.total_bytes == 0
        }
        "partial-header" => {
            request.heads == 1
                && request.position == "partial_header"
                && request.partial_received == u32::from(HEADER_BYTES_AT_FENCE)
                && request.ends == 0
        }
        "partial-body" => {
            request.heads == 1
                && request.position == "partial_body"
                && request.partial_received > 0
                && request.partial_received < request.partial_total
                && request.ends == 0
        }
        "end-before-fin" => {
            request.ends == 1
                && request.position == "boundary"
                && !observation.request_fin_sequenced
                && response.total_bytes == 0
        }
        "early-response" => response.heads == 1 && request.ends == 0 && response.ends == 0,
        "credit-stall" => {
            response.heads == 1
                && response.ends == 0
                && observation.receive_buffered_bytes > STREAM_WINDOW_BYTES / 2
        }
        "sse" => {
            response.heads == 1
                && response.ends == 0
                && response.position == "boundary"
                && observation.request_fin_sequenced
        }
        // The consumer leaves after this freeze began, so the capture at
        // QUIESCE precedes the RESET: the race is proven by the fence, the
        // RESET's sequence and the live state while frozen instead.
        "cancel-race" => request.ends == 1 && observation.request_fin_sequenced,
        _ => false,
    }
}

/// Validate every rule; the first violated rule is named.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_http_forward_rotation_evidence(
    evidence: &HttpForwardRotationEvidence,
) -> Result<()> {
    let mut checks: Vec<(String, bool)> = vec![
        ("three relays".into(), evidence.relay_count == 3),
        (
            "membership re-sign spacing not shortened by an override".into(),
            evidence.resign_spacing_ms >= MEMBERSHIP_RESIGN_SPACING.as_millis(),
        ),
        ("non-owner ingress".into(), evidence.non_owner_ingress),
        (
            "one device session across every rotation case".into(),
            evidence.session_stable,
        ),
        (
            "forbidden head refused with 400".into(),
            evidence.admission_probe.status == 400,
        ),
        (
            "forbidden head refused before admission".into(),
            evidence.admission_probe.rejected_before_admission_delta == 1
                && evidence.admission_probe.ingress_exchange_delta == 0
                && evidence.admission_probe.owner_stream_delta == 0
                && evidence.admission_probe.owner_exchange_delta == 0
                && evidence.admission_probe.handler_invocations == 0,
        ),
        (
            "every rotation case ran".into(),
            ROTATION_CASES
                .iter()
                .all(|name| case(evidence, name).is_some()),
        ),
    ];
    for name in ROTATION_CASES {
        let Some(case) = case(evidence, name) else {
            continue;
        };
        let spanned = if name == "sse" { 2 } else { 1 };
        checks.extend([
            (
                format!("{name}: observed at its rotation point"),
                case.observations.len() >= spanned
                    && case
                        .observations
                        .iter()
                        .all(|observation| position_matches(name, observation)),
            ),
            (
                format!("{name}: distinct rotations"),
                case.observations
                    .iter()
                    .map(|observation| observation.rotation)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == case.observations.len(),
            ),
            (
                format!("{name}: fence accounting"),
                !case.observations.is_empty() && case.observations.iter().all(fence_accounted),
            ),
            (
                format!("{name}: single dispatch"),
                case.handler_invocations == 1,
            ),
            (
                format!("{name}: HEAD never repeated at the device"),
                case.device_request_heads == 1,
            ),
            (
                format!("{name}: END exactly once, FIN received"),
                case.device_request_ends == 1 && case.device_request_fin,
            ),
            (format!("{name}: status 200"), case.status == 200),
            (
                format!("{name}: bytes exact and in order"),
                case.bytes_exact,
            ),
            (
                format!("{name}: body ended by END and FIN"),
                case.body_ended_cleanly,
            ),
            (
                format!("{name}: no device or ingress failure"),
                case.device_error.is_none()
                    && case.ingress_error.is_none()
                    && case.device_progress_expired.is_none()
                    && case.ingress_progress_expired.is_none(),
            ),
            (format!("{name}: eventual STREAM_FORGET"), case.forgotten),
        ]);
    }
    let race = &evidence.cancel_race;
    let observation_ok = race.observation.as_ref().is_some_and(|observation| {
        position_matches("cancel-race", observation) && fence_accounted(observation)
    });
    let reset_in_order = match (race.observation.as_ref(), race.owner_record.as_ref()) {
        (Some(observation), Some(record)) => {
            observation.relay_fence.is_some_and(|fence| {
                record.reset_sequence == Some(fence + 1)
                    && record.reset_generation == Some(observation.new_generation)
            }) && record.reset_deferred_by_freeze
                && record.release == "reset"
                && record.reset_reason == Some(tunnel_protocol::reset_reason::CANCELLED)
        }
        _ => false,
    };
    checks.extend([
        ("cancel race: freeze held".into(), race.freeze_held),
        (
            "cancel race: single dispatch".into(),
            race.handler_invocations == 1,
        ),
        (
            "cancel race: handler cancelled while the owner stayed frozen".into(),
            race.handler_cancelled_while_frozen && race.owner_still_frozen_after_cancel,
        ),
        (
            "cancel race: RESET queued behind the freeze, unsequenced".into(),
            race.deferred_reset_while_frozen && race.reset_unsequenced_while_frozen,
        ),
        (
            "cancel race: control CANCEL sent and received".into(),
            race.cancel_sent && race.device_cancel_received,
        ),
        (
            "cancel race: rotation observation and fence accounting".into(),
            observation_ok,
        ),
        (
            "cancel race: RESET directly after the fence on the new carrier".into(),
            reset_in_order,
        ),
        (
            "cancel race: cancelled at device and ingress".into(),
            race.device_error.as_deref() == Some("HTTP_CANCELLED")
                && race.ingress_error.as_deref() == Some("HTTP_CANCELLED"),
        ),
        ("cancel race: eventual STREAM_FORGET".into(), race.forgotten),
    ]);
    for (label, outcome) in [
        ("lost acknowledgement", &evidence.lost_ack),
        ("owner loss", &evidence.owner_loss),
    ] {
        checks.extend([
            (
                format!("{label}: side effect happened once before the fault"),
                outcome.side_effects_before_fault == 1,
            ),
            (
                format!("{label}: no retry"),
                outcome.side_effects_after_outcome == 1,
            ),
            (
                format!("{label}: gateway failure with unknown execution"),
                (500..600).contains(&outcome.status)
                    && outcome.body_execution == "unknown"
                    && !outcome.body_code.is_empty(),
            ),
            (
                format!("{label}: outcome_unknown"),
                outcome.result_outcome == "outcome_unknown",
            ),
            (
                format!("{label}: ingress recorded unknown execution"),
                outcome.ingress_execution.as_deref() == Some("unknown")
                    && outcome.ingress_error.is_some(),
            ),
        ]);
    }
    checks.extend([
        (
            "rotations completed".into(),
            evidence.rotations_completed >= ROTATION_CASES.len() as u64 + 2,
        ),
        (
            "two device sockets at every steady state".into(),
            !evidence.steady_state_sockets.is_empty()
                && evidence.steady_state_sockets.iter().all(|open| *open == 2),
        ),
        (
            "at most one candidate data socket".into(),
            evidence.device_socket_peak <= 3,
        ),
    ]);
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "http-forward rotation gate failed: {rule}"
            )));
        }
    }
    Ok(())
}

fn profile() -> Result<Arc<Profile>> {
    let policy = |error| HarnessError::InvalidInput(format!("http-forward profile: {error:?}"));
    let mut request = RequestPolicy::new(64 * 1024 * 1024).map_err(policy)?;
    for (method, path) in [
        (Method::Post, "/upload-head"),
        (Method::Post, "/upload-partial-header"),
        (Method::Post, "/upload-partial-body"),
        (Method::Post, "/upload-end-before-fin"),
        (Method::Post, "/early-response"),
        (Method::Get, "/credit-stall"),
        (Method::Get, "/sse"),
        (Method::Get, "/cancel-race"),
        (Method::Post, "/effect-lost-ack"),
        (Method::Post, "/effect-owner-loss"),
        (Method::Get, "/ping"),
    ] {
        request.allow_route(method, path).map_err(policy)?;
    }
    request.allow_http_version(HttpVersion::Http11);
    request
        .headers
        .allow("content-type", Occurrence::Singleton)
        .map_err(policy)?;
    request
        .headers
        .allow("accept", Occurrence::Repeatable)
        .map_err(policy)?;
    let mut response = ResponsePolicy::new(64 * 1024 * 1024).map_err(policy)?;
    response
        .headers
        .allow("content-type", Occurrence::Singleton)
        .map_err(policy)?;
    response
        .headers
        .allow("cache-control", Occurrence::Repeatable)
        .map_err(policy)?;
    Ok(Arc::new(Profile { request, response }))
}

/// The gate holds a record open, a credit stall or a FIN until the next
/// observed rotation, and waits up to [`OBSERVATION_BOUND`] for it, so every
/// transport budget it can hit is raised above that bound (the budgets
/// themselves are proven by the bridge's progress tests).  A case can
/// therefore never fail on its own budget before its observation.
pub const GATE_PROGRESS_BUDGET: Duration = Duration::from_secs(60);
/// The longest `wait_observation` waits for one case's rotation.
pub const OBSERVATION_BOUND: Duration = Duration::from_secs(
    (GATE_ROTATION.interval_seconds + GATE_ROTATION.overlap_seconds) * MAX_ROTATIONS_PER_CASE,
);
const _: () = assert!(GATE_PROGRESS_BUDGET.as_secs() > OBSERVATION_BOUND.as_secs());

fn bridge_config() -> Result<BridgeConfig> {
    let progress = tunnel_http_bridge::ProgressBudgets::default()
        .with_record(GATE_PROGRESS_BUDGET)
        .and_then(|budgets| budgets.with_fin_after_end(GATE_PROGRESS_BUDGET))
        .and_then(|budgets| budgets.with_credit_stall(GATE_PROGRESS_BUDGET))
        .map_err(|error| HarnessError::InvalidInput(format!("progress budgets: {error}")))?;
    BridgeConfig::default()
        .with_deadline(Duration::from_secs(180))
        .map(|config| config.with_progress(progress))
        .map_err(|error| HarnessError::InvalidInput(format!("bridge config: {error}")))
}

fn upload_chunks() -> Vec<Bytes> {
    (0..UPLOAD_CHUNKS)
        .map(|index| synthetic_chunk(index * UPLOAD_CHUNK, UPLOAD_CHUNK))
        .collect()
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn upload_digest() -> String {
    let mut hasher = Sha256::new();
    for chunk in upload_chunks() {
        hasher.update(&chunk);
    }
    hex(&hasher.finalize())
}

fn download_digest() -> String {
    let mut hasher = Sha256::new();
    let mut offset = 0;
    while offset < DOWNLOAD_BYTES {
        let len = (DOWNLOAD_BYTES - offset).min(64 * 1024);
        hasher.update(synthetic_chunk(offset, len));
        offset += len;
    }
    hex(&hasher.finalize())
}

fn sse_bytes() -> Vec<u8> {
    SSE_EVENTS.iter().flat_map(|event| event.concat()).collect()
}

#[derive(Default)]
struct GateHandlerState {
    invocations: Mutex<BTreeMap<String, usize>>,
    invoked: Notify,
    sse_events: Mutex<Option<mpsc::Receiver<Bytes>>>,
    cancelled: Mutex<Option<Instant>>,
    cancelled_notify: Notify,
    effect_hit: Notify,
    effect_release: Notify,
    second_event: Notify,
}

impl GateHandlerState {
    fn count(&self, path: &str) -> usize {
        self.invocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(path)
            .copied()
            .unwrap_or(0)
    }

    fn total(&self) -> usize {
        self.invocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .sum()
    }

    async fn wait_invoked(&self, path: &str) -> Result<()> {
        timeout(WAIT, async {
            loop {
                let notified = self.invoked.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.count(path) > 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| HarnessError::Timeout(format!("handler for {path} was not invoked")))
    }
}

fn response_with(
    content_type: &'static str,
    body: tunnel_client::http_forward::HttpBody,
) -> std::result::Result<http::Response<tunnel_client::http_forward::HttpBody>, HttpHandlerError> {
    http::Response::builder()
        .status(200)
        .header("content-type", content_type)
        .header("cache-control", "no-store")
        .body(body)
        .map_err(|_| HttpHandlerError)
}

fn owned_body(bytes: Vec<u8>) -> tunnel_client::http_forward::HttpBody {
    http_body_util::Full::new(Bytes::from(bytes))
        .map_err(|never| match never {})
        .boxed()
}

async fn digest_body(mut body: ChannelBody) -> Option<String> {
    let mut hasher = Sha256::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        if let Ok(data) = frame.into_data() {
            hasher.update(&data);
        }
    }
    Some(hex(&hasher.finalize()))
}

#[allow(clippy::too_many_lines)]
fn gate_handler(state: Arc<GateHandlerState>) -> Arc<dyn HttpHandler> {
    Arc::new(
        move |request: http::Request<ChannelBody>| -> HttpHandlerFuture {
            let state = Arc::clone(&state);
            Box::pin(async move {
                let path = request.uri().path().to_owned();
                *state
                    .invocations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .entry(path.clone())
                    .or_default() += 1;
                state.invoked.notify_waiters();
                let cancellation = request.extensions().get::<HandlerCancellation>().cloned();
                match path.as_str() {
                    path if path.starts_with("/upload-") => {
                        let digest = digest_body(request.into_body())
                            .await
                            .ok_or(HttpHandlerError)?;
                        response_with("text/plain", owned_body(digest.into_bytes()))
                    }
                    "/early-response" => {
                        let (tx, rx) = mpsc::channel::<Bytes>(1);
                        let body = request.into_body();
                        tokio::spawn(async move {
                            if tx.send(Bytes::from_static(b"early-ack\n")).await.is_err() {
                                return;
                            }
                            if let Some(digest) = digest_body(body).await {
                                let _ = tx.send(Bytes::from(digest)).await;
                            }
                        });
                        response_with("text/plain", handler_body(rx))
                    }
                    "/credit-stall" => {
                        let (tx, rx) = mpsc::channel::<Bytes>(1);
                        tokio::spawn(async move {
                            let mut offset = 0;
                            while offset < DOWNLOAD_BYTES {
                                let len = (DOWNLOAD_BYTES - offset).min(64 * 1024);
                                if tx.send(synthetic_chunk(offset, len)).await.is_err() {
                                    return;
                                }
                                offset += len;
                            }
                        });
                        response_with("application/octet-stream", handler_body(rx))
                    }
                    "/sse" => {
                        let events = state
                            .sse_events
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                            .ok_or(HttpHandlerError)?;
                        response_with("text/event-stream", handler_body(events))
                    }
                    "/cancel-race" => {
                        let (tx, rx) = mpsc::channel::<Bytes>(1);
                        tokio::spawn(async move {
                            let _ = tx.send(Bytes::from_static(b"data: waiting\n\n")).await;
                            if let Some(HandlerCancellation(token)) = cancellation {
                                // A second chunk on request, sequenced into
                                // the fixture's paused data socket.
                                tokio::select! {
                                    () = token.cancelled() => {}
                                    () = state.second_event.notified() => {
                                        let _ = tx
                                            .send(Bytes::from_static(b"data: still-waiting\n\n"))
                                            .await;
                                        token.cancelled().await;
                                    }
                                }
                                *state
                                    .cancelled
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                    Some(Instant::now());
                                state.cancelled_notify.notify_waiters();
                            }
                            drop(tx);
                        });
                        response_with("text/event-stream", handler_body(rx))
                    }
                    "/effect-lost-ack" | "/effect-owner-loss" => {
                        let _ = request.into_body().collect().await;
                        let released = state.effect_release.notified();
                        tokio::pin!(released);
                        released.as_mut().enable();
                        state.effect_hit.notify_waiters();
                        let _ = timeout(OUTCOME_WAIT * 2, released).await;
                        response_with("text/plain", full_body(b"effect-done"))
                    }
                    "/ping" => response_with("text/plain", full_body(b"pong")),
                    _ => Err(HttpHandlerError),
                }
            })
        },
    )
}

fn controlled_body() -> (mpsc::Sender<Bytes>, StreamBody<ConsumerStream>) {
    let (tx, rx) = mpsc::channel::<Bytes>(1);
    let stream: ConsumerStream = Box::pin(futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|chunk| (Ok(Frame::data(chunk)), rx))
    }));
    (tx, StreamBody::new(stream))
}

/// Read the response body fully; `None` when it ended with an error.
async fn read_all(body: hyper::body::Incoming) -> Option<Vec<u8>> {
    body.collect()
        .await
        .ok()
        .map(|bytes| bytes.to_bytes().to_vec())
}

struct Gate<'a> {
    cluster: &'a mut ProductionCluster,
    state: Arc<GateHandlerState>,
    device_diagnostics: DeviceHttpDiagnostics,
    hold: HttpRelayHold,
    proxy: ProxyHandle,
    client: &'a tunnel_client::ConnectionHandle,
    device_id: uuid::Uuid,
    base: String,
    token: String,
    ca: Vec<u8>,
    ingress_addr: std::net::SocketAddr,
    last_stream_id: u64,
    /// When the membership records in force were signed (bootstrap or the
    /// last case-boundary re-sign).
    membership_signed_at: Instant,
    session_id: String,
}

impl Gate<'_> {
    async fn owner_snapshot(&self) -> Result<RelaySnapshot> {
        self.cluster.relay("relay-a")?.snapshot().await
    }

    async fn ingress_snapshot(&self) -> Result<RelaySnapshot> {
        self.cluster.relay("relay-c")?.snapshot().await
    }

    fn session<'s>(&self, snapshot: &'s RelaySnapshot) -> Result<&'s RelaySessionSnapshot> {
        snapshot
            .sessions
            .iter()
            .find(|session| session.device_id == self.device_id.to_string())
            .ok_or_else(|| HarnessError::Process("owner session is missing".into()))
    }

    async fn wait_new_stream(&mut self) -> Result<u64> {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = self.owner_snapshot().await?;
            if let Ok(session) = self.session(&snapshot)
                && let Some(stream) = session
                    .streams
                    .iter()
                    .filter(|stream| {
                        stream.http.is_some() && stream.stream_id > self.last_stream_id
                    })
                    .max_by_key(|stream| stream.stream_id)
            {
                self.last_stream_id = stream.stream_id;
                return Ok(stream.stream_id);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "new owner HTTP stream not observed".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    async fn wait_live(
        &self,
        stream_id: u64,
        label: &str,
        predicate: impl Fn(&RelayHttpStreamSnapshot) -> bool,
    ) -> Result<RelayHttpStreamSnapshot> {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = self.owner_snapshot().await?;
            if let Ok(session) = self.session(&snapshot)
                && let Some(http) = session
                    .streams
                    .iter()
                    .find(|stream| stream.stream_id == stream_id)
                    .and_then(|stream| stream.http.clone())
                && predicate(&http)
            {
                return Ok(http);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "owner stream {stream_id} never reached: {label}"
                )));
            }
            sleep(POLL).await;
        }
    }

    async fn rotations_completed(&self) -> Result<u64> {
        let snapshot = self.owner_snapshot().await?;
        Ok(self.session(&snapshot)?.rotations_completed)
    }

    /// Wait for the first observation of `stream_id` after `after` that
    /// matches `name`'s rotation point, within a bounded number of rotations.
    async fn wait_observation(
        &self,
        name: &str,
        stream_id: u64,
        after: u64,
    ) -> Result<HttpRotationObservation> {
        let deadline = Instant::now() + OBSERVATION_BOUND;
        loop {
            let snapshot = self.owner_snapshot().await?;
            let observations = snapshot
                .http_forward
                .rotations
                .iter()
                .filter(|observation| {
                    observation.stream_id == stream_id && observation.rotation > after
                })
                .collect::<Vec<_>>();
            if let Some(observation) = observations
                .iter()
                .find(|observation| position_matches(name, observation))
            {
                return Ok((*observation).clone());
            }
            if observations.len() as u64 >= MAX_ROTATIONS_PER_CASE || Instant::now() >= deadline {
                let session = self.session(&snapshot).ok();
                let terminal = snapshot
                    .session_terminal_events
                    .iter()
                    .map(|event| {
                        (
                            event.session_id.clone(),
                            event.reason,
                            event.rotation_id.is_some(),
                        )
                    })
                    .collect::<Vec<_>>();
                let device = self.client.status_snapshot();
                if let Ok(ingress) = self.ingress_snapshot().await {
                    eprintln!(
                        "http-forward rotation gate: recent ingress exchanges={:?} owner_all_exchanges={:?}",
                        ingress
                            .http_forward
                            .exchanges
                            .iter()
                            .rev()
                            .take(3)
                            .collect::<Vec<_>>(),
                        snapshot
                            .http_forward
                            .exchanges
                            .iter()
                            .rev()
                            .take(3)
                            .collect::<Vec<_>>()
                    );
                }
                eprintln!(
                    "http-forward rotation gate: stream records owner={:?} exchanges={:?} forgotten={:?} device={:?}",
                    snapshot
                        .http_forward
                        .owner_streams
                        .iter()
                        .filter(|r| r.stream_id == stream_id)
                        .collect::<Vec<_>>(),
                    snapshot
                        .http_forward
                        .exchanges
                        .iter()
                        .filter(|r| r.stream_id == Some(stream_id))
                        .collect::<Vec<_>>(),
                    snapshot
                        .http_forward
                        .forgotten
                        .iter()
                        .filter(|r| r.stream_id == stream_id)
                        .collect::<Vec<_>>(),
                    self.device_diagnostics
                        .snapshot()
                        .into_iter()
                        .filter(|r| r.stream_id == stream_id)
                        .collect::<Vec<_>>(),
                );
                eprintln!(
                    "http-forward rotation gate: owner session terminals={terminal:?} device_phase={} device_session={:?} device_rotations={} device_recovery_reason={:?} readiness={:?}",
                    device.phase,
                    device.session_id,
                    device.rotations_completed,
                    device.recovery_reset_reason,
                    *self.client.readiness().borrow()
                );
                return Err(HarnessError::Process(format!(
                    "{name}: no rotation observed stream {stream_id} at its point after rotation {after}: observations={observations:?} phase={:?} rotations_completed={:?} recovery={:?} forced={:?} replayed={:?} streams={:?}",
                    session.map(|session| session.phase.clone()),
                    session.map(|session| session.rotations_completed),
                    session.and_then(|session| session.rotation_recovery_reason),
                    session.map(|session| session.rotation_deadline_forced_retirement),
                    session.map(|session| session.total_replayed_frames),
                    session.map(|session| session
                        .streams
                        .iter()
                        .map(|stream| (
                            stream.stream_id,
                            stream.terminal,
                            stream.http.as_ref().map(|http| (
                                http.request.position,
                                http.response.position,
                                http.parked_bytes,
                                http.frozen
                            ))
                        ))
                        .collect::<Vec<_>>()),
                )));
            }
            sleep(POLL).await;
        }
    }

    async fn wait_device_record(&self, stream_id: u64) -> Result<DeviceHttpExchangeRecord> {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(record) = self
                .device_diagnostics
                .snapshot()
                .into_iter()
                .find(|record| record.stream_id == stream_id)
            {
                return Ok(record);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "device record for stream {stream_id} missing"
                )));
            }
            sleep(POLL).await;
        }
    }

    /// The owner_peer record for `stream_id`, then the ingress record with
    /// the same peer request identity.
    async fn wait_exchange_records(
        &self,
        stream_id: u64,
    ) -> Result<(HttpExchangeRecord, HttpExchangeRecord)> {
        let deadline = Instant::now() + WAIT;
        loop {
            let owner = self.owner_snapshot().await?;
            if let Some(owner_record) =
                owner.http_forward.exchanges.iter().find(|record| {
                    record.role == "owner_peer" && record.stream_id == Some(stream_id)
                })
            {
                let ingress = self.ingress_snapshot().await?;
                if let Some(ingress_record) = ingress.http_forward.exchanges.iter().find(|record| {
                    record.role == "ingress_remote" && record.request_id == owner_record.request_id
                }) {
                    return Ok((owner_record.clone(), ingress_record.clone()));
                }
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "exchange records for stream {stream_id} missing"
                )));
            }
            sleep(POLL).await;
        }
    }

    async fn wait_forgotten(&self, stream_id: u64) -> Result<bool> {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = self.owner_snapshot().await?;
            if snapshot
                .http_forward
                .forgotten
                .iter()
                .any(|record| record.stream_id == stream_id)
            {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            sleep(POLL).await;
        }
    }

    async fn wait_owner_record(&self, stream_id: u64) -> Result<HttpOwnerStreamRecord> {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = self.owner_snapshot().await?;
            if let Some(record) = snapshot
                .http_forward
                .owner_streams
                .iter()
                .find(|record| record.stream_id == stream_id)
            {
                return Ok(record.clone());
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "owner stream record {stream_id} missing"
                )));
            }
            sleep(POLL).await;
        }
    }

    /// Wait until the owner is between rotations with exactly the settled
    /// device sockets open, and return that count.
    async fn steady_sockets(&self) -> Result<usize> {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = self.owner_snapshot().await?;
            let session = self.session(&snapshot)?;
            let settled = session.phase == "active" && session.candidate_generation.is_none();
            let open = self.proxy.connections().len();
            if settled && open == 2 {
                return Ok(open);
            }
            if Instant::now() >= deadline {
                return Ok(open);
            }
            sleep(POLL).await;
        }
    }

    async fn send_request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: StreamBody<ConsumerStream>,
    ) -> Result<tokio::task::JoinHandle<Result<http::Response<hyper::body::Incoming>>>> {
        let (mut sender, connection) = connect_consumer(self.ingress_addr, &self.ca).await?;
        let request = request(
            method,
            &format!("{}{path}", self.base),
            Some(&self.token),
            headers,
            body,
        )?;
        Ok(tokio::spawn(async move {
            let response = sender
                .send_request(request)
                .await
                .map_err(|error| HarnessError::Http(format!("gate request: {error}")));
            // Keep the connection alive for the response body.
            tokio::spawn(async move {
                let _ = connection.await;
            });
            response
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_case(
        &mut self,
        name: &str,
        stream_id: u64,
        observations: Vec<HttpRotationObservation>,
        path: &str,
        status: u16,
        bytes_exact: bool,
        body_ended_cleanly: bool,
    ) -> Result<RotationCaseEvidence> {
        let device = self.wait_device_record(stream_id).await?;
        let (_, ingress) = self.wait_exchange_records(stream_id).await?;
        let forgotten = self.wait_forgotten(stream_id).await?;
        let report = device.report.unwrap_or(tunnel_http_bridge::ExchangeReport {
            request: tunnel_http_bridge::Outcome::Pending,
            response: tunnel_http_bridge::Outcome::Pending,
            execution: tunnel_http_bridge::Execution::Unknown,
            error: Some(tunnel_http_forward::HttpErrorCode::StreamInterrupted),
            progress_expired: None,
        });
        Ok(RotationCaseEvidence {
            name: name.to_owned(),
            stream_id,
            handler_invocations: self.state.count(path),
            status,
            bytes_exact,
            body_ended_cleanly,
            observations,
            device_request_heads: device.request_heads,
            device_request_ends: device.request_ends,
            device_request_fin: device.request_fin_received,
            device_error: report.error.map(|code| code.as_str().to_owned()),
            device_progress_expired: report.progress_expired.map(|kind| kind.as_str().to_owned()),
            ingress_error: ingress.error_code.map(str::to_owned),
            ingress_progress_expired: ingress.progress_expired.map(str::to_owned),
            forgotten,
        })
    }

    /// The four request-direction positions share one shape: an upload
    /// whose digest the handler returns.
    /// Explain a request that never reached the handler with identifiers,
    /// status codes and counters only.
    async fn dispatch_failure(
        &self,
        error: HarnessError,
        response: tokio::task::JoinHandle<Result<http::Response<hyper::body::Incoming>>>,
    ) -> HarnessError {
        let status = if response.is_finished() {
            match response.await {
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    let body = timeout(WAIT, read_all(response.into_body()))
                        .await
                        .ok()
                        .flatten()
                        .map(|body| {
                            String::from_utf8_lossy(&body)
                                .chars()
                                .take(200)
                                .collect::<String>()
                        });
                    format!("status {status} body {body:?}")
                }
                Ok(Err(error)) => format!("request failed: {error}"),
                Err(_) => "request task failed".to_owned(),
            }
        } else {
            response.abort();
            "no response".to_owned()
        };
        let ingress = self
            .ingress_snapshot()
            .await
            .map(|snapshot| {
                snapshot
                    .http_forward
                    .exchanges
                    .iter()
                    .rev()
                    .take(2)
                    .map(|record| (record.role, record.error_code, record.execution))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let owner_streams = self.owner_snapshot().await.ok().and_then(|snapshot| {
            self.session(&snapshot)
                .ok()
                .map(|session| (session.phase.clone(), session.streams.len()))
        });
        HarnessError::Process(format!(
            "{error}: {status}; ingress {ingress:?}; owner {owner_streams:?}"
        ))
    }

    async fn upload_case(
        &mut self,
        name: &str,
        hold: Option<HttpRelayHoldPoint>,
    ) -> Result<RotationCaseEvidence> {
        let path = format!("/upload-{name}");
        if let Some(point) = hold
            && !self.hold.arm(point)
        {
            return Err(HarnessError::Process(format!("{name}: hold was not idle")));
        }
        let (tx, body) = controlled_body();
        let response = self
            .send_request(
                "POST",
                &path,
                &[("content-type", "application/octet-stream")],
                body,
            )
            .await?;
        if let Err(error) = self.state.wait_invoked(&path).await {
            return Err(self.dispatch_failure(error, response).await);
        }
        let stream_id = self.wait_new_stream().await?;
        let chunks = upload_chunks();
        let observation = match hold {
            None => {
                // HEAD only: nothing else is sent until the rotation froze.
                self.wait_live(stream_id, "request HEAD only", |http| {
                    http.request.heads == 1
                        && http.request.total_bytes > 0
                        && http.request.bodies == 0
                })
                .await?;
                let after = self.rotations_completed().await?;
                let observation = self.wait_observation(name, stream_id, after).await?;
                for chunk in &chunks {
                    tx.send(chunk.clone())
                        .await
                        .map_err(|_| HarnessError::Http(format!("{name}: upload closed")))?;
                }
                drop(tx);
                observation
            }
            Some(HttpRelayHoldPoint::BeforeRequestFin) => {
                for chunk in &chunks {
                    tx.send(chunk.clone())
                        .await
                        .map_err(|_| HarnessError::Http(format!("{name}: upload closed")))?;
                }
                drop(tx);
                timeout(WAIT, self.hold.reached())
                    .await
                    .map_err(|_| HarnessError::Timeout(format!("{name}: hold not reached")))?;
                let after = self.rotations_completed().await?;
                let observation = self.wait_observation(name, stream_id, after).await;
                self.hold.release();
                observation?
            }
            Some(_) => {
                tx.send(chunks[0].clone())
                    .await
                    .map_err(|_| HarnessError::Http(format!("{name}: upload closed")))?;
                timeout(WAIT, self.hold.reached())
                    .await
                    .map_err(|_| HarnessError::Timeout(format!("{name}: hold not reached")))?;
                let after = self.rotations_completed().await?;
                let observation = self.wait_observation(name, stream_id, after).await;
                self.hold.release();
                let observation = observation?;
                for chunk in &chunks[1..] {
                    tx.send(chunk.clone())
                        .await
                        .map_err(|_| HarnessError::Http(format!("{name}: upload closed")))?;
                }
                drop(tx);
                observation
            }
        };
        let response = timeout(WAIT, response)
            .await
            .map_err(|_| HarnessError::Timeout(format!("{name}: response timed out")))?
            .map_err(|error| HarnessError::Process(format!("{name}: join: {error}")))??;
        let status = response.status().as_u16();
        let body = timeout(WAIT, read_all(response.into_body()))
            .await
            .map_err(|_| HarnessError::Timeout(format!("{name}: body timed out")))?;
        let bytes_exact = body.as_deref() == Some(upload_digest().as_bytes());
        self.finish_case(
            name,
            stream_id,
            vec![observation],
            &path,
            status,
            bytes_exact,
            body.is_some(),
        )
        .await
    }

    async fn early_response_case(&mut self) -> Result<RotationCaseEvidence> {
        let name = "early-response";
        let path = "/early-response";
        let (tx, body) = controlled_body();
        let response = self
            .send_request(
                "POST",
                path,
                &[("content-type", "application/octet-stream")],
                body,
            )
            .await?;
        let chunks = upload_chunks();
        tx.send(chunks[0].clone())
            .await
            .map_err(|_| HarnessError::Http("early-response: upload closed".into()))?;
        let response = timeout(WAIT, response)
            .await
            .map_err(|_| HarnessError::Timeout("early response head timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("early-response: join: {error}")))??;
        let stream_id = self.wait_new_stream().await?;
        self.wait_live(stream_id, "response head while uploading", |http| {
            http.response.heads == 1 && http.request.ends == 0
        })
        .await?;
        let after = self.rotations_completed().await?;
        let observation = self.wait_observation(name, stream_id, after).await?;
        let status = response.status().as_u16();
        let reader = tokio::spawn(read_all(response.into_body()));
        for chunk in &chunks[1..] {
            tx.send(chunk.clone())
                .await
                .map_err(|_| HarnessError::Http("early-response: upload closed".into()))?;
        }
        drop(tx);
        let body = timeout(WAIT, reader)
            .await
            .map_err(|_| HarnessError::Timeout("early-response body timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("early-response: join: {error}")))?;
        let mut expected = b"early-ack\n".to_vec();
        expected.extend_from_slice(upload_digest().as_bytes());
        let bytes_exact = body.as_deref() == Some(expected.as_slice());
        self.finish_case(
            name,
            stream_id,
            vec![observation],
            path,
            status,
            bytes_exact,
            body.is_some(),
        )
        .await
    }

    async fn credit_stall_case(&mut self) -> Result<RotationCaseEvidence> {
        let name = "credit-stall";
        let path = "/credit-stall";
        let response = self.send_request("GET", path, &[], empty_stream()).await?;
        let response = timeout(WAIT, response)
            .await
            .map_err(|_| HarnessError::Timeout("credit-stall head timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("credit-stall: join: {error}")))??;
        let stream_id = self.wait_new_stream().await?;
        // Do not read: the owner withholds credit once its buffer fills.
        self.wait_live(stream_id, "owner receive buffer filled", |http| {
            http.receive_buffered_bytes > STREAM_WINDOW_BYTES / 2
        })
        .await?;
        let after = self.rotations_completed().await?;
        let observation = self.wait_observation(name, stream_id, after).await?;
        let status = response.status().as_u16();
        let mut hasher = Sha256::new();
        let mut body = response.into_body();
        let mut clean = true;
        let read = timeout(WAIT * 2, async {
            while let Some(frame) = body.frame().await {
                match frame {
                    Ok(frame) => {
                        if let Ok(data) = frame.into_data() {
                            hasher.update(&data);
                        }
                    }
                    Err(_) => {
                        clean = false;
                        break;
                    }
                }
            }
        })
        .await;
        let bytes_exact = read.is_ok() && clean && hex(&hasher.finalize()) == download_digest();
        self.finish_case(
            name,
            stream_id,
            vec![observation],
            path,
            status,
            bytes_exact,
            read.is_ok() && clean,
        )
        .await
    }

    async fn sse_case(&mut self) -> Result<RotationCaseEvidence> {
        let name = "sse";
        let path = "/sse";
        let (events_tx, events_rx) = mpsc::channel::<Bytes>(4);
        *self
            .state
            .sse_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(events_rx);
        let response = self
            .send_request(
                "GET",
                path,
                &[("accept", "text/event-stream")],
                empty_stream(),
            )
            .await?;
        for fragment in SSE_EVENTS[0] {
            events_tx
                .send(Bytes::from_static(fragment))
                .await
                .map_err(|_| HarnessError::Http("sse: event channel closed".into()))?;
        }
        let response = timeout(WAIT, response)
            .await
            .map_err(|_| HarnessError::Timeout("sse head timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("sse: join: {error}")))??;
        let status = response.status().as_u16();
        let stream_id = self.wait_new_stream().await?;
        let mut body = response.into_body();
        let mut received = Vec::new();
        let mut clean = true;
        let mut observations = Vec::new();
        let expected = sse_bytes();
        let mut boundary = 0;
        for (index, event) in SSE_EVENTS.iter().enumerate() {
            if index > 0 {
                for fragment in *event {
                    events_tx
                        .send(Bytes::from_static(fragment))
                        .await
                        .map_err(|_| HarnessError::Http("sse: event channel closed".into()))?;
                }
            }
            boundary += event.concat().len();
            // Read exactly through this event: the next one is only emitted
            // after a rotation observed the stream between events.
            while received.len() < boundary {
                match timeout(WAIT, body.frame()).await {
                    Ok(Some(Ok(frame))) => {
                        if let Ok(data) = frame.into_data() {
                            received.extend_from_slice(&data);
                        }
                    }
                    _ => {
                        clean = false;
                        break;
                    }
                }
            }
            if index + 1 < SSE_EVENTS.len() {
                let after = observations.last().map_or(
                    self.rotations_completed().await?,
                    |last: &HttpRotationObservation| last.rotation,
                );
                let observation = self.wait_observation(name, stream_id, after).await?;
                observations.push(observation);
            }
        }
        drop(events_tx);
        let tail = timeout(WAIT, async {
            let mut tail = Vec::new();
            while let Some(frame) = body.frame().await {
                match frame {
                    Ok(frame) => {
                        if let Ok(data) = frame.into_data() {
                            tail.extend_from_slice(&data);
                        }
                    }
                    Err(_) => return None,
                }
            }
            Some(tail)
        })
        .await
        .ok()
        .flatten();
        let ended = tail.is_some();
        received.extend(tail.unwrap_or_default());
        let bytes_exact = clean && received == expected;
        self.finish_case(
            name,
            stream_id,
            observations,
            path,
            status,
            bytes_exact,
            clean && ended,
        )
        .await
    }

    async fn owner_frozen(&self) -> Result<bool> {
        let snapshot = self.owner_snapshot().await?;
        let session = self.session(&snapshot)?;
        Ok(
            session.session_id == self.session_id
                && FROZEN_PHASES.contains(&session.phase.as_str()),
        )
    }

    /// Hold the next rotation freeze deterministically.  The active data
    /// socket's connector→relay bytes are paused while the carrier is
    /// settled, and the handler then emits one more response chunk: the
    /// connector sequences it into the paused socket, so at the next
    /// rotation the connector's fence covers a frame the owner cannot
    /// receive, and the owner cannot prove its drain.  It stays frozen
    /// (draining) until the bytes are released, well inside the overlap
    /// deadline.  The control socket and the candidate stay untouched.
    async fn hold_freeze(&self) -> Result<(crate::ConnectionId, usize)> {
        // Settled: exactly the control and one data socket are open, so the
        // data socket is the one that is not the control socket.
        let deadline = Instant::now() + WAIT;
        let connection = loop {
            let device = self.client.status_snapshot();
            let open = self.proxy.connections();
            // Earlier streams must be fully reclaimed first: the owner can
            // only publish a STREAM_FORGET (and so QUIESCE) once the
            // connector's acknowledgement of that stream's terminal crossed
            // the data socket this fixture is about to pause.
            let owner_streams = {
                let snapshot = self.owner_snapshot().await?;
                self.session(&snapshot)?.streams.len()
            };
            if device.phase == "active"
                && device.candidate_generation.is_none()
                && device.streams == 1
                && owner_streams == 1
                && open.len() == 2
                && let Some(control) = device.control_local_addr
                && let Some(data) = open
                    .iter()
                    .find(|connection| connection.source_addr != control)
                && device.active_local_addr == Some(data.source_addr)
            {
                break data.id;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout("device carrier never settled".into()));
            }
            sleep(POLL).await;
        };
        self.proxy
            .pause(ProxyDirection::ClientToTarget, connection)
            .await?;
        self.state.second_event.notify_one();
        let deadline = Instant::now()
            + Duration::from_secs(
                (GATE_ROTATION.interval_seconds + GATE_ROTATION.overlap_seconds) * 2,
            );
        let mut polls = 0usize;
        // Phase labels seen while waiting, for a failure message only.
        let mut phases: Vec<String> = Vec::new();
        loop {
            polls += 1;
            let snapshot = self.owner_snapshot().await?;
            let session = self.session(&snapshot)?;
            if phases.last() != Some(&session.phase) {
                phases.push(session.phase.clone());
            }
            if session.session_id == self.session_id
                && FROZEN_PHASES.contains(&session.phase.as_str())
            {
                return Ok((connection, polls));
            }
            if Instant::now() >= deadline {
                self.proxy
                    .resume(ProxyDirection::ClientToTarget, connection)
                    .await?;
                return Err(HarnessError::Process(format!(
                    "the rotation freeze was not held: phases {phases:?}"
                )));
            }
            sleep(POLL).await;
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn cancel_race(&mut self) -> Result<CancelRaceEvidence> {
        let path = "/cancel-race";
        let mut evidence = CancelRaceEvidence::default();
        let (mut sender, connection) = connect_consumer(self.ingress_addr, &self.ca).await?;
        let response = timeout(
            WAIT,
            sender.send_request(request(
                "GET",
                &format!("{}{path}", self.base),
                Some(&self.token),
                &[("accept", "text/event-stream")],
                empty_stream(),
            )?),
        )
        .await
        .map_err(|_| HarnessError::Timeout("cancel-race head timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("cancel-race request: {error}")))?;
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut body = response.into_body();
        let _ = timeout(WAIT, body.frame()).await;
        let stream_id = self.wait_new_stream().await?;
        evidence.stream_id = stream_id;
        let (control, attempts) = self.hold_freeze().await?;
        // The held attempt completes as the next rotation.
        let held_rotation = self.rotations_completed().await.map(|count| count + 1);
        evidence.freeze_observation_polls = attempts;
        evidence.freeze_held = true;
        let outcome = async {
            // The consumer goes away while the owner is frozen.
            drop(body);
            drop(sender);
            connection.abort();
            let observed = timeout(Duration::from_secs(2), async {
                loop {
                    let cancelled = self.state.cancelled_notify.notified();
                    tokio::pin!(cancelled);
                    cancelled.as_mut().enable();
                    if self
                        .state
                        .cancelled
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .is_some()
                    {
                        return;
                    }
                    cancelled.await;
                }
            })
            .await
            .is_ok();
            let live = self
                .wait_live(stream_id, "deferred RESET and CANCEL", |http| {
                    http.cancel_sent && http.deferred_terminal == Some("reset")
                })
                .await;
            let frozen = self.owner_frozen().await?;
            Ok::<_, HarnessError>((observed, live, frozen))
        }
        .await;
        // Always release the control bytes, even on a failure above.
        self.proxy
            .resume(ProxyDirection::ClientToTarget, control)
            .await?;
        let (observed, live, frozen) = outcome?;
        evidence.handler_cancelled_while_frozen = observed;
        evidence.owner_still_frozen_after_cancel = frozen;
        if let Ok(live) = live {
            evidence.deferred_reset_while_frozen = live.deferred_terminal == Some("reset");
            evidence.reset_unsequenced_while_frozen = live.reset_sequence.is_none();
            evidence.cancel_sent = live.cancel_sent;
        }
        let held_rotation = held_rotation?;
        let deadline = Instant::now() + WAIT;
        evidence.observation = loop {
            let snapshot = self.owner_snapshot().await?;
            if let Some(observation) = snapshot.http_forward.rotations.iter().find(|observation| {
                observation.stream_id == stream_id && observation.rotation == held_rotation
            }) {
                break Some(observation.clone());
            }
            if Instant::now() >= deadline {
                break None;
            }
            sleep(POLL).await;
        };
        evidence.owner_record = Some(self.wait_owner_record(stream_id).await?);
        let device = self.wait_device_record(stream_id).await?;
        evidence.device_cancel_received = device.cancel_received;
        evidence.device_error = device
            .report
            .and_then(|report| report.error)
            .map(|code| code.as_str().to_owned());
        let (_, ingress) = self.wait_exchange_records(stream_id).await?;
        evidence.ingress_error = ingress.error_code.map(str::to_owned);
        evidence.forgotten = self.wait_forgotten(stream_id).await?;
        evidence.handler_invocations = self.state.count(path);
        Ok(evidence)
    }

    async fn effect_request(
        &self,
        path: &'static str,
        ingress_addr: std::net::SocketAddr,
    ) -> Result<tokio::task::JoinHandle<Result<(u16, Vec<u8>)>>> {
        let (mut sender, connection) = connect_consumer(ingress_addr, &self.ca).await?;
        let request = request(
            "POST",
            &format!("{}{path}", self.base),
            Some(&self.token),
            &[("content-type", "text/plain")],
            super::http_forward_real_path::once_stream(b"synthetic-effect"),
        )?;
        Ok(tokio::spawn(async move {
            let connection = tokio::spawn(async move {
                let _ = connection.await;
            });
            let response = sender
                .send_request(request)
                .await
                .map_err(|error| HarnessError::Http(format!("{path}: {error}")))?;
            let status = response.status().as_u16();
            let body = read_all(response.into_body()).await.unwrap_or_default();
            connection.abort();
            Ok((status, body))
        }))
    }

    fn outcome_from(
        fault: &str,
        before: usize,
        after: usize,
        status: u16,
        body: &[u8],
        ingress: Option<&HttpExchangeRecord>,
    ) -> OutcomeUnknownEvidence {
        let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        let code = parsed["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let execution = parsed["error"]["execution"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let result_outcome = match (
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
        };
        OutcomeUnknownEvidence {
            fault: fault.to_owned(),
            side_effects_before_fault: before,
            side_effects_after_outcome: after,
            status,
            body_code: code,
            body_execution: execution,
            result_outcome,
            ingress_error: ingress.and_then(|record| record.error_code.map(str::to_owned)),
            ingress_execution: ingress.map(|record| record.execution.to_owned()),
        }
    }

    async fn ingress_record_after(
        &self,
        node: &str,
        recorded_before: u64,
    ) -> Result<Option<HttpExchangeRecord>> {
        let deadline = Instant::now() + OUTCOME_WAIT;
        loop {
            let snapshot = self.cluster.relay(node)?.snapshot().await?;
            if snapshot.http_forward.exchanges_recorded > recorded_before
                && let Some(record) = snapshot
                    .http_forward
                    .exchanges
                    .iter()
                    .rev()
                    .find(|record| record.role == "ingress_remote")
            {
                return Ok(Some(record.clone()));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            sleep(POLL).await;
        }
    }

    /// The acknowledgement case enters through relay-b so its blackholed
    /// relay-b↔relay-a path leaves relay-c's route to the owner intact for
    /// the owner-loss case.
    async fn lost_ack(&mut self) -> Result<OutcomeUnknownEvidence> {
        let path = "/effect-lost-ack";
        let ingress_node = "relay-b";
        let ingress_addr = self.cluster.relay(ingress_node)?.consumer_addr()?;
        let recorded_before = self
            .cluster
            .relay(ingress_node)?
            .snapshot()
            .await?
            .http_forward
            .exchanges_recorded;
        let hit = self.state.effect_hit.notified();
        tokio::pin!(hit);
        hit.as_mut().enable();
        let response = self.effect_request(path, ingress_addr).await?;
        timeout(WAIT, hit)
            .await
            .map_err(|_| HarnessError::Timeout("lost-ack side effect not reached".into()))?;
        let before = self.state.count(path);
        // The owner→ingress path loses every packet: the response and the
        // transport acknowledgements of the forwarded request.
        self.cluster
            .set_peer_path_drop_from("relay-a", ingress_node, true)?;
        self.state.effect_release.notify_waiters();
        let outcome = timeout(OUTCOME_WAIT, response).await;
        let ingress = self
            .ingress_record_after(ingress_node, recorded_before)
            .await;
        self.cluster
            .set_peer_path_drop_from("relay-a", ingress_node, false)?;
        let (status, body) = outcome
            .map_err(|_| HarnessError::Timeout("lost-ack outcome timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("lost-ack join: {error}")))??;
        let ingress = ingress?;
        let after = self.state.count(path);
        Ok(Self::outcome_from(
            "owner_to_ingress_path_blackholed",
            before,
            after,
            status,
            &body,
            ingress.as_ref(),
        ))
    }

    /// Re-sign cluster membership at a case boundary.  A newer record
    /// version invalidates every peer admission, and with it every in-flight
    /// peer hop, so no case may straddle a refresh; the fixture's 60-second
    /// records outlive any single case.
    ///
    /// The refresh also drops the ingress relays' admissions to the owner, so
    /// both ingress routes the gate uses must answer a `/ping` again, and the
    /// owner must have reclaimed those pings, before the next case starts.
    async fn fresh_membership(&mut self) -> Result<()> {
        // Re-sign no more often than the chaos gate's background interval;
        // every case is shorter than the remaining record lifetime.
        if self.membership_signed_at.elapsed() < resign_spacing() {
            return Ok(());
        }
        self.cluster.resign_membership_now().await?;
        self.membership_signed_at = Instant::now();
        for node in ["relay-c", "relay-b"] {
            let address = self.cluster.relay(node)?.consumer_addr()?;
            if let Err(error) = self.wait_route_ready(address).await {
                let readiness = self
                    .cluster
                    .relays
                    .iter()
                    .map(|relay| {
                        (
                            relay.node_id.clone(),
                            relay.membership.readiness(),
                            relay.peer_runtime.is_ready(),
                            relay
                                .membership
                                .snapshot()
                                .memberships
                                .iter()
                                .map(|membership| membership.record_version)
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>();
                // Measure, for the defect record, how long peer readiness
                // stays down after the route check gave up.
                let gave_up = Instant::now();
                let recovered_after = loop {
                    if self
                        .cluster
                        .relays
                        .iter()
                        .filter(|relay| relay.running.is_some())
                        .all(|relay| relay.peer_runtime.is_ready())
                    {
                        break Some(gave_up.elapsed());
                    }
                    if gave_up.elapsed() >= Duration::from_secs(120) {
                        break None;
                    }
                    sleep(Duration::from_millis(250)).await;
                };
                return Err(HarnessError::Process(format!(
                    "{node}: {error}; readiness {readiness:?}; every relay peer-ready again {recovered_after:?} after the route check gave up"
                )));
            }
        }
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = self.owner_snapshot().await?;
            if self.session(&snapshot)?.streams.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "owner kept a stream after the route checks".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    /// Before owner loss, confirm relay-c's route to the owner answers.
    async fn wait_route_recovered(&self) -> Result<()> {
        self.wait_route_ready(self.ingress_addr).await
    }

    /// Wait until a `/ping` through `ingress_addr` is answered by the device.
    async fn wait_route_ready(&self, ingress_addr: std::net::SocketAddr) -> Result<()> {
        let deadline = Instant::now() + OUTCOME_WAIT;
        loop {
            let attempt = async {
                let (mut sender, connection) = connect_consumer(ingress_addr, &self.ca).await?;
                let connection = tokio::spawn(async move {
                    let _ = connection.await;
                });
                let response = sender
                    .send_request(request(
                        "GET",
                        &format!("{}/ping", self.base),
                        Some(&self.token),
                        &[],
                        empty_stream(),
                    )?)
                    .await
                    .map_err(|error| HarnessError::Http(format!("ping: {error}")))?;
                let status = response.status().as_u16();
                let body = read_all(response.into_body()).await;
                connection.abort();
                if status == 200 && body.as_deref() == Some(b"pong".as_slice()) {
                    Ok(None)
                } else {
                    // Relay error bodies carry only a code and a fixed message.
                    Ok::<_, HarnessError>(Some(format!(
                        "status {status} {:?}",
                        body.map(|body| String::from_utf8_lossy(&body)
                            .chars()
                            .take(160)
                            .collect::<String>())
                    )))
                }
            };
            let last = match timeout(Duration::from_secs(5), attempt).await {
                Ok(Ok(None)) => return Ok(()),
                Ok(Ok(Some(failure))) => failure,
                Ok(Err(error)) => error.to_string(),
                Err(_) => "ping timed out".to_owned(),
            };
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "the peer route from {ingress_addr} to the owner did not answer: {last}"
                )));
            }
            sleep(Duration::from_millis(250)).await;
        }
    }

    async fn owner_loss(&mut self) -> Result<OutcomeUnknownEvidence> {
        let path = "/effect-owner-loss";
        let recorded_before = self
            .ingress_snapshot()
            .await?
            .http_forward
            .exchanges_recorded;
        let hit = self.state.effect_hit.notified();
        tokio::pin!(hit);
        hit.as_mut().enable();
        let response = self.effect_request(path, self.ingress_addr).await?;
        timeout(WAIT, hit)
            .await
            .map_err(|_| HarnessError::Timeout("owner-loss side effect not reached".into()))?;
        let before = self.state.count(path);
        let mut readiness = self.client.readiness();
        self.cluster.shutdown_node("relay-a").await?;
        self.state.effect_release.notify_waiters();
        let outcome = timeout(OUTCOME_WAIT, response).await;
        let ingress = self
            .ingress_record_after("relay-c", recorded_before)
            .await?;
        // The device learns its session ended; nothing may be dispatched
        // again for this operation afterwards.
        let _ = timeout(WAIT, readiness.wait_for(|readiness| !readiness.is_ready())).await;
        let (status, body) = outcome
            .map_err(|_| HarnessError::Timeout("owner-loss outcome timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("owner-loss join: {error}")))??;
        let after = self.state.count(path);
        Ok(Self::outcome_from(
            "owner_process_loss",
            before,
            after,
            status,
            &body,
            ingress.as_ref(),
        ))
    }

    async fn admission_probe(&self) -> Result<AdmissionProbeEvidence> {
        let ingress_before = self.ingress_snapshot().await?.http_forward;
        let owner_before = self.owner_snapshot().await?.http_forward;
        let invocations_before = self.state.total();
        let (mut sender, connection) = connect_consumer(self.ingress_addr, &self.ca).await?;
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender
            .send_request(request(
                "POST",
                &format!("{}/upload-head", self.base),
                Some(&self.token),
                &[("x-agent-tunnel-owner", "relay-a")],
                super::http_forward_real_path::once_stream(b"probe"),
            )?)
            .await
            .map_err(|error| HarnessError::Http(format!("admission probe: {error}")))?;
        let status = response.status().as_u16();
        let _ = read_all(response.into_body()).await;
        connection.abort();
        let ingress_after = self.ingress_snapshot().await?.http_forward;
        let owner_after = self.owner_snapshot().await?.http_forward;
        Ok(AdmissionProbeEvidence {
            status,
            rejected_before_admission_delta: ingress_after
                .ingress_rejected_before_admission
                .saturating_sub(ingress_before.ingress_rejected_before_admission),
            ingress_exchange_delta: ingress_after
                .exchanges_recorded
                .saturating_sub(ingress_before.exchanges_recorded),
            owner_stream_delta: owner_after
                .owner_streams_recorded
                .saturating_sub(owner_before.owner_streams_recorded),
            owner_exchange_delta: owner_after
                .exchanges_recorded
                .saturating_sub(owner_before.exchanges_recorded),
            handler_invocations: self.state.total().saturating_sub(invocations_before),
        })
    }
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<HttpForwardRotationEvidence> {
    let options = HarnessOptions::from_env()?
        .http_forward_service(true)
        .rotation(GATE_ROTATION);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("rotation gate harness startup timed out".into()))??;
    let (profile, config) = match (profile(), bridge_config()) {
        (Ok(profile), Ok(config)) => (profile, config),
        (Err(error), _) | (_, Err(error)) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let hold = HttpRelayHold::default();
    let exports = match HttpForwardExports::new().with_profile(
        crate::FIXTURE_HTTP_FORWARD_PROFILE,
        HttpForwardExport::new(Arc::clone(&profile), config),
    ) {
        Ok(exports) => exports.with_fixture_interposer(Arc::new(hold.clone())),
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(HarnessError::InvalidInput(error.to_owned()));
        }
    };
    harness.http_forward = Some(exports);
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    // The fixture's signed membership records live 60 seconds and this gate
    // runs longer, so it re-signs them — but at case boundaries only (see
    // `Gate::fresh_membership`): a background re-sign invalidates the peer
    // admission under whichever peer hop happens to be in flight.
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        run(&mut cluster, &harness, profile, config, hold),
    )
    .await
    {
        Ok(result) => result.and_then(|evidence| {
            if let Err(error) = validate_http_forward_rotation_evidence(&evidence) {
                // Payload-free: identifiers, positions, counters and labels.
                eprintln!("http-forward rotation evidence: {evidence:?}");
                return Err(error);
            }
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "http-forward rotation scenario exceeded its bounded deadline".into(),
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
    profile: Arc<Profile>,
    config: BridgeConfig,
    hold: HttpRelayHold,
) -> Result<HttpForwardRotationEvidence> {
    let mut evidence = HttpForwardRotationEvidence {
        relay_count: cluster.relays.len(),
        resign_spacing_ms: resign_spacing().as_millis(),
        ..HttpForwardRotationEvidence::default()
    };
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("rotation gate device is missing".into()))?;
    let echo_service = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("rotation gate echo service missing".into()))?;
    let http_service = harness
        .http_forward_service
        .ok_or_else(|| HarnessError::InvalidInput("http-forward service was not seeded".into()))?;
    let owner_device_addr = cluster
        .relay("relay-a")?
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| HarnessError::Process("relay-a is not running".into()))?;
    // Every device socket passes this proxy, so the gate counts them and can
    // hold the control socket's connector→relay bytes.
    let proxy = TcpProxy::bind(owner_device_addr, ProxyConfig::default()).await?;
    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut device_profile = write_device_profile(
        directory.path(),
        device.id,
        echo_service,
        "m3-http-forward-rotation-canary",
        proxy.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    device_profile.config.rotation = GATE_ROTATION;
    device_profile.config.exports.insert(
        http_service.to_string(),
        LocalExport {
            kind: LocalExportKind::HttpForward,
            device_canary: None,
            mcp: None,
            acp: None,
            cua: None,
            fs: None,
        },
    );
    device_profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;
    let state = Arc::new(GateHandlerState::default());
    let handlers = HttpHandlers::new().with_export(
        http_service.to_string(),
        HttpExport {
            profile,
            config,
            handler: gate_handler(Arc::clone(&state)),
        },
    );
    let device_diagnostics = handlers.diagnostics();
    let client = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect_with_http_handlers(
            ConnectOptions::new(device_profile.config.clone()),
            handlers,
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("rotation gate device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("rotation gate device: {error}")))?;
    let mut client = client;
    let owner_lost = Arc::new(AtomicBool::new(false));
    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("rotation gate device readiness timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        let owner = {
            let deadline = Instant::now() + STARTUP_TIMEOUT;
            loop {
                let owner = cluster
                    .catalog
                    .current_owner(device.tenant_id, device.id, chrono::Utc::now())
                    .await
                    .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?;
                if let Some(owner) = owner
                    && owner.token.session_id == session.session_id
                {
                    break owner;
                }
                if Instant::now() >= deadline {
                    return Err(HarnessError::Timeout(
                        "device owner claim not observed".into(),
                    ));
                }
                sleep(Duration::from_millis(50)).await;
            }
        };
        evidence.owner_node = owner.token.node_id.clone();
        let ingress_addr = cluster.relay("relay-c")?.consumer_addr()?;
        evidence.ingress_node = "relay-c".to_owned();
        evidence.non_owner_ingress = owner.token.node_id == "relay-a";
        let token = harness.oidc.issue_with(
            &harness.topology.consumers_a[0].name,
            OidcTokenOptions {
                scope: Some("echo:invoke http:invoke".to_owned()),
                ..OidcTokenOptions::default()
            },
        )?;
        let mut gate = Gate {
            cluster,
            state: Arc::clone(&state),
            device_diagnostics: device_diagnostics.clone(),
            hold,
            proxy,
            client: &client,
            device_id: device.id,
            base: format!("/v1/devices/{}/services/{http_service}/http", device.id),
            token,
            ca: harness.pki.server_ca.certificate_der.clone(),
            ingress_addr,
            last_stream_id: 0,
            membership_signed_at: Instant::now(),
            session_id: session.session_id.clone(),
        };
        let only = std::env::var("M3_ROTATION_CASES").ok();
        let started = Instant::now();
        let selected = |name: &str| {
            let selected = only
                .as_deref()
                .is_none_or(|only| only.split(',').any(|selected| selected == name));
            if selected {
                // Progress labels only: case names and elapsed time.
                eprintln!(
                    "http-forward rotation gate: {name} at {} ms",
                    started.elapsed().as_millis()
                );
            }
            selected
        };
        let run_result = async {
            if selected("admission-probe") {
                gate.fresh_membership().await?;
                evidence.admission_probe = gate.admission_probe().await?;
            }
            if selected("cancel-race") {
                gate.fresh_membership().await?;
                evidence.cancel_race = gate.cancel_race().await?;
                evidence
                    .steady_state_sockets
                    .push(gate.steady_sockets().await?);
            }
            for (name, hold) in [
                ("head", None),
                (
                    "partial-header",
                    Some(HttpRelayHoldPoint::InsideBodyHeader {
                        bytes: HEADER_BYTES_AT_FENCE,
                    }),
                ),
                ("partial-body", Some(HttpRelayHoldPoint::InsideBodyPayload)),
                ("end-before-fin", Some(HttpRelayHoldPoint::BeforeRequestFin)),
            ] {
                if selected(name) {
                    gate.fresh_membership().await?;
                    let case = gate.upload_case(name, hold).await?;
                    evidence.cases.push(case);
                    evidence
                        .steady_state_sockets
                        .push(gate.steady_sockets().await?);
                }
            }
            if selected("early-response") {
                gate.fresh_membership().await?;
                let case = gate.early_response_case().await?;
                evidence.cases.push(case);
                evidence
                    .steady_state_sockets
                    .push(gate.steady_sockets().await?);
            }
            if selected("credit-stall") {
                gate.fresh_membership().await?;
                let case = gate.credit_stall_case().await?;
                evidence.cases.push(case);
                evidence
                    .steady_state_sockets
                    .push(gate.steady_sockets().await?);
            }
            if selected("sse") {
                gate.fresh_membership().await?;
                let case = gate.sse_case().await?;
                evidence.cases.push(case);
                evidence
                    .steady_state_sockets
                    .push(gate.steady_sockets().await?);
            }
            let final_snapshot = gate.owner_snapshot().await?;
            let final_session = gate.session(&final_snapshot)?;
            evidence.session_stable = final_session.session_id == gate.session_id;
            evidence.rotations_completed = final_session.rotations_completed;
            evidence.device_socket_peak = gate.proxy.diagnostics().peak_active;
            if selected("lost-ack") {
                gate.fresh_membership().await?;
                evidence.lost_ack = gate.lost_ack().await?;
            }
            if selected("owner-loss") {
                gate.fresh_membership().await?;
                gate.wait_route_recovered().await?;
                owner_lost.store(true, Ordering::SeqCst);
                evidence.owner_loss = gate.owner_loss().await?;
            }
            Ok::<_, HarnessError>(())
        }
        .await;
        if run_result.is_err() {
            eprintln!("http-forward rotation partial evidence: {evidence:?}");
            if let Ok(snapshot) = gate.owner_snapshot().await {
                eprintln!(
                    "http-forward rotation owner observations: {:?}",
                    snapshot.http_forward.rotations
                );
            }
        }
        let proxy = gate.proxy;
        run_result.map(|()| proxy)
    }
    .await;
    let stop = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    let proxy = scenario?;
    let _ = proxy.shutdown().await;
    match stop {
        Ok(Ok(())) => Ok(evidence),
        // The owner-loss case ends the device session on purpose.
        Ok(Err(_)) if owner_lost.load(Ordering::SeqCst) => Ok(evidence),
        Ok(Err(error)) => Err(HarnessError::Process(format!("device stop: {error}"))),
        Err(_) => Err(HarnessError::Timeout("device stop timed out".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_relay::http_forward_diagnostics::HttpRecordPosition;

    fn position(heads: u32, ends: u32, position: &'static str) -> HttpRecordPosition {
        HttpRecordPosition {
            heads,
            ends,
            position,
            total_bytes: 1,
            ..HttpRecordPosition::default()
        }
    }

    fn observation(name: &str, rotation: u64) -> HttpRotationObservation {
        let mut observation = HttpRotationObservation {
            stream_id: 1,
            rotation,
            old_generation: rotation,
            new_generation: rotation + 1,
            frozen_last_emitted: 3,
            relay_fence: Some(3),
            relay_acknowledged: Some(3),
            connector_fence: Some(2),
            connector_acknowledged: Some(2),
            request: position(1, 0, "boundary"),
            ..HttpRotationObservation::default()
        };
        match name {
            "partial-header" => {
                observation.request = position(1, 0, "partial_header");
                observation.request.partial_received = u32::from(HEADER_BYTES_AT_FENCE);
            }
            "partial-body" => {
                observation.request = position(1, 0, "partial_body");
                observation.request.partial_received = 1;
                observation.request.partial_total = 2;
            }
            "end-before-fin" => observation.request = position(1, 1, "boundary"),
            "early-response" => observation.response = position(1, 0, "boundary"),
            "credit-stall" => {
                observation.request = position(1, 1, "boundary");
                observation.request_fin_sequenced = true;
                observation.response = position(1, 0, "partial_body");
                observation.receive_buffered_bytes = STREAM_WINDOW_BYTES / 2 + 1;
            }
            "sse" => {
                observation.request = position(1, 1, "boundary");
                observation.request_fin_sequenced = true;
                observation.response = position(1, 0, "boundary");
            }
            "cancel-race" => {
                observation.request = position(1, 1, "boundary");
                observation.request_fin_sequenced = true;
            }
            _ => {}
        }
        observation
    }

    fn outcome(fault: &str) -> OutcomeUnknownEvidence {
        OutcomeUnknownEvidence {
            fault: fault.into(),
            side_effects_before_fault: 1,
            side_effects_after_outcome: 1,
            status: 502,
            body_code: "HTTP_OUTCOME_UNKNOWN".into(),
            body_execution: "unknown".into(),
            result_outcome: "outcome_unknown".into(),
            ingress_error: Some("HTTP_OUTCOME_UNKNOWN".into()),
            ingress_execution: Some("unknown".into()),
        }
    }

    fn passing() -> HttpForwardRotationEvidence {
        let cases = ROTATION_CASES
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let rotation = index as u64 + 2;
                let observations = if *name == "sse" {
                    vec![observation(name, rotation), observation(name, rotation + 1)]
                } else {
                    vec![observation(name, rotation)]
                };
                RotationCaseEvidence {
                    name: (*name).into(),
                    stream_id: index as u64 + 2,
                    handler_invocations: 1,
                    status: 200,
                    bytes_exact: true,
                    body_ended_cleanly: true,
                    observations,
                    device_request_heads: 1,
                    device_request_ends: 1,
                    device_request_fin: true,
                    forgotten: true,
                    ..RotationCaseEvidence::default()
                }
            })
            .collect();
        let race_observation = observation("cancel-race", 1);
        HttpForwardRotationEvidence {
            relay_count: 3,
            resign_spacing_ms: MEMBERSHIP_RESIGN_SPACING.as_millis(),
            owner_node: "relay-a".into(),
            ingress_node: "relay-c".into(),
            non_owner_ingress: true,
            session_stable: true,
            admission_probe: AdmissionProbeEvidence {
                status: 400,
                rejected_before_admission_delta: 1,
                ..AdmissionProbeEvidence::default()
            },
            cases,
            cancel_race: CancelRaceEvidence {
                stream_id: 1,
                freeze_observation_polls: 1,
                freeze_held: true,
                handler_invocations: 1,
                handler_cancelled_while_frozen: true,
                owner_still_frozen_after_cancel: true,
                deferred_reset_while_frozen: true,
                reset_unsequenced_while_frozen: true,
                cancel_sent: true,
                device_cancel_received: true,
                owner_record: Some(HttpOwnerStreamRecord {
                    stream_id: 1,
                    release: "reset",
                    reset_reason: Some(tunnel_protocol::reset_reason::CANCELLED),
                    reset_sequence: Some(4),
                    reset_generation: Some(race_observation.new_generation),
                    reset_deferred_by_freeze: true,
                    cancel_sent: true,
                    ..HttpOwnerStreamRecord::default()
                }),
                observation: Some(race_observation),
                device_error: Some("HTTP_CANCELLED".into()),
                ingress_error: Some("HTTP_CANCELLED".into()),
                forgotten: true,
            },
            lost_ack: outcome("lost-ack"),
            owner_loss: outcome("owner-loss"),
            rotations_completed: ROTATION_CASES.len() as u64 + 2,
            steady_state_sockets: vec![2, 2],
            device_socket_peak: 3,
        }
    }

    #[test]
    fn each_case_position_rule_accepts_its_own_point() {
        for name in ROTATION_CASES {
            assert!(
                position_matches(name, &observation(name, 1)),
                "{name} accepts its own point"
            );
        }
        // The upload points are mutually exclusive.
        let upload = ["head", "partial-header", "partial-body", "end-before-fin"];
        for name in upload {
            for other in upload.iter().filter(|other| **other != name) {
                assert!(
                    !position_matches(other, &observation(name, 1)),
                    "{other} must not accept the {name} point"
                );
            }
        }
        assert!(!position_matches("unknown", &observation("head", 1)));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn validator_accepts_passing_evidence_and_rejects_every_single_mutation() {
        validate_http_forward_rotation_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut HttpForwardRotationEvidence));
        let mutations: Vec<Mutation> = vec![
            ("relays", |e| e.relay_count = 2),
            ("resign spacing override", |e| e.resign_spacing_ms = 350),
            ("ingress", |e| e.non_owner_ingress = false),
            ("session", |e| e.session_stable = false),
            ("probe status", |e| e.admission_probe.status = 403),
            ("probe admitted", |e| {
                e.admission_probe.rejected_before_admission_delta = 0;
            }),
            ("probe exchange", |e| {
                e.admission_probe.ingress_exchange_delta = 1
            }),
            ("probe owner stream", |e| {
                e.admission_probe.owner_stream_delta = 1
            }),
            ("probe owner exchange", |e| {
                e.admission_probe.owner_exchange_delta = 1
            }),
            ("probe dispatched", |e| {
                e.admission_probe.handler_invocations = 1
            }),
            ("case missing", |e| {
                e.cases.pop();
            }),
            ("no observation", |e| e.cases[0].observations.clear()),
            ("sse one rotation", |e| {
                if let Some(sse) = e.cases.iter_mut().find(|case| case.name == "sse") {
                    sse.observations.pop();
                }
            }),
            ("sse same rotation twice", |e| {
                if let Some(sse) = e.cases.iter_mut().find(|case| case.name == "sse") {
                    sse.observations[1].rotation = sse.observations[0].rotation;
                }
            }),
            ("wrong position", |e| {
                e.cases[1].observations[0].request.position = "boundary";
            }),
            ("header bytes", |e| {
                e.cases[1].observations[0].request.partial_received += 1;
            }),
            ("fence", |e| {
                e.cases[0].observations[0].relay_fence = Some(2)
            }),
            ("relay ack below fence", |e| {
                e.cases[0].observations[0].relay_acknowledged = Some(2);
            }),
            ("connector ack below fence", |e| {
                e.cases[0].observations[0].connector_acknowledged = Some(1);
            }),
            ("missing fence", |e| {
                e.cases[0].observations[0].connector_fence = None
            }),
            ("generation", |e| {
                e.cases[0].observations[0].new_generation = 1
            }),
            ("duplicate dispatch", |e| e.cases[0].handler_invocations = 2),
            ("repeated HEAD", |e| e.cases[0].device_request_heads = 2),
            ("fabricated END", |e| e.cases[0].device_request_ends = 2),
            ("missing FIN", |e| e.cases[0].device_request_fin = false),
            ("status", |e| e.cases[0].status = 502),
            ("bytes", |e| e.cases[0].bytes_exact = false),
            ("body end", |e| e.cases[0].body_ended_cleanly = false),
            ("device error", |e| {
                e.cases[0].device_error = Some("HTTP_STREAM_INTERRUPTED".into());
            }),
            ("ingress error", |e| {
                e.cases[0].ingress_error = Some("HTTP_STREAM_INTERRUPTED".into());
            }),
            ("device budget", |e| {
                e.cases[0].device_progress_expired = Some("record".into());
            }),
            ("ingress budget", |e| {
                e.cases[0].ingress_progress_expired = Some("record".into());
            }),
            ("case forget", |e| e.cases[0].forgotten = false),
            ("freeze", |e| e.cancel_race.freeze_held = false),
            ("race dispatch", |e| e.cancel_race.handler_invocations = 2),
            ("race handler", |e| {
                e.cancel_race.handler_cancelled_while_frozen = false
            }),
            ("race thawed", |e| {
                e.cancel_race.owner_still_frozen_after_cancel = false
            }),
            ("race deferred", |e| {
                e.cancel_race.deferred_reset_while_frozen = false
            }),
            ("race sequenced", |e| {
                e.cancel_race.reset_unsequenced_while_frozen = false
            }),
            ("race cancel sent", |e| e.cancel_race.cancel_sent = false),
            ("race cancel received", |e| {
                e.cancel_race.device_cancel_received = false
            }),
            ("race observation", |e| e.cancel_race.observation = None),
            ("race record", |e| e.cancel_race.owner_record = None),
            ("race reset order", |e| {
                if let Some(record) = e.cancel_race.owner_record.as_mut() {
                    record.reset_sequence = Some(5);
                }
            }),
            ("race reset carrier", |e| {
                if let Some(record) = e.cancel_race.owner_record.as_mut() {
                    record.reset_generation = Some(1);
                }
            }),
            ("race reset not deferred", |e| {
                if let Some(record) = e.cancel_race.owner_record.as_mut() {
                    record.reset_deferred_by_freeze = false;
                }
            }),
            ("race release", |e| {
                if let Some(record) = e.cancel_race.owner_record.as_mut() {
                    record.release = "fin";
                }
            }),
            ("race reason", |e| {
                if let Some(record) = e.cancel_race.owner_record.as_mut() {
                    record.reset_reason = Some(tunnel_protocol::reset_reason::ADAPTER_FAILURE);
                }
            }),
            ("race device", |e| e.cancel_race.device_error = None),
            ("race ingress", |e| {
                e.cancel_race.ingress_error = Some("HTTP_STREAM_INTERRUPTED".into());
            }),
            ("race forget", |e| e.cancel_race.forgotten = false),
            ("effect before", |e| {
                e.lost_ack.side_effects_before_fault = 0
            }),
            ("retry", |e| e.lost_ack.side_effects_after_outcome = 2),
            ("owner-loss retry", |e| {
                e.owner_loss.side_effects_after_outcome = 2
            }),
            ("status success", |e| e.lost_ack.status = 200),
            ("body execution", |e| {
                e.owner_loss.body_execution = "not_dispatched".into();
            }),
            ("body code", |e| e.owner_loss.body_code.clear()),
            ("result outcome", |e| {
                e.lost_ack.result_outcome = "failed".into()
            }),
            ("ingress execution", |e| {
                e.owner_loss.ingress_execution = Some("dispatched".into());
            }),
            ("ingress error missing", |e| e.lost_ack.ingress_error = None),
            ("rotations", |e| {
                e.rotations_completed = ROTATION_CASES.len() as u64
            }),
            ("extra socket", |e| e.steady_state_sockets.push(3)),
            ("no steady state", |e| e.steady_state_sockets.clear()),
            ("socket peak", |e| e.device_socket_peak = 4),
        ];
        for (label, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_http_forward_rotation_evidence(&evidence).is_err(),
                "mutation {label} must be rejected"
            );
        }
    }
}
