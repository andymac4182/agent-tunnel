//! Implementation gate 3 of docs/http-forwarding.md over the real cluster:
//! consumer HTTP/1.1 → relay-c (non-owner Axum ingress) → HTTP/3 peer hop →
//! relay-a (owner actor) → device data WebSocket → `tunnel-client` → an
//! in-process `http-forward/1` handler.
//!
//! One exchange (`/echo`) is saturated in both directions: a 16 MiB
//! checksummed upload is echoed back by the handler while the consumer
//! deliberately stops reading the response, so every hop's queue fills to
//! its bound.  While it is saturated, a second exchange on the same device
//! (`/events`) is cancelled by a consumer disconnect and must end with RESET
//! (and a cancelled handler), and a third (`/permission`) must answer
//! within a latency bound.  Every hop's queue high-water mark is then read
//! from payload-free diagnostics and compared with its documented bound; the
//! upload and echo are compared by SHA-256 on both ends; and the headers the
//! handler received and the consumer's response headers are checked for
//! credentials, private addresses and internal metadata.
//!
//! All payloads, credentials and headers are synthetic.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, mpsc};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use tunnel_client::http_forward::{
    DeviceHttpExchangeRecord, HttpBody, HttpExport, HttpHandler, HttpHandlerError,
    HttpHandlerFuture, HttpHandlers,
};
use tunnel_client::{ConnectOptions, LocalExport, LocalExportKind};
use tunnel_http_bridge::{
    BridgeConfig, ChannelBody, HANDOFF_CAPACITY, HandlerCancellation, Outcome, Profile,
};
use tunnel_http_forward::{
    HttpErrorCode, HttpVersion, MAX_BODY_PAYLOAD_LEN, Method, Occurrence, RequestPolicy,
    ResponsePolicy,
};
use tunnel_relay::http_forward_diagnostics::{HttpExchangeRecord, HttpOwnerStreamRecord};
use tunnel_relay::{
    HttpForwardExport, HttpForwardExports, PEER_HOP_WINDOW_BYTES, PEER_HOP_WINDOW_RECORDS,
};

use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, SCENARIO_TIMEOUT, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::{Harness, HarnessError, HarnessOptions, Result};

/// The saturated upload, echoed back byte for byte.
/// It is larger than every socket and tunnel buffer on the path combined, so
/// the consumer's writer demonstrably stalls while the echo is unread.
pub const UPLOAD_BYTES: usize = 16 * 1024 * 1024;
/// The consumer does not read the echo for this long, so every hop fills.
const RESPONSE_PAUSE: Duration = Duration::from_millis(2_500);
/// The permission answer must arrive within this bound while `/echo` is
/// saturated.
pub const PERMISSION_LATENCY_BOUND: Duration = Duration::from_secs(2);
/// A consumer disconnect must cancel the handler within this bound.
pub const CANCELLATION_LATENCY_BOUND: Duration = Duration::from_secs(5);
/// The bridge body queue (chunks) at the ingress and the device.
pub const BODY_QUEUE_CHUNKS: usize = 4;
/// The owner's and connector's per-stream advertised window.
pub const STREAM_WINDOW_BYTES: usize = 128 * 1024;
/// docs/cluster.md: 256 KiB per peer stream.
pub const PEER_STREAM_BUDGET_BYTES: usize = 256 * 1024;
const CANCEL_REASON: u16 = tunnel_protocol::reset_reason::CANCELLED;
const COOKIE_SECRET: &str = "synthetic-session-cookie-0a1b2c";
const INTERNAL_HEADER: &str = "x-agent-tunnel-owner";
const DIAGNOSTIC_WAIT: Duration = Duration::from_secs(15);
/// M7-C82: one device session used to admit at most this many streams in its
/// whole lifetime, because its OPEN journal never released a tombstone.
pub const OPEN_JOURNAL_TRACKED_ENTRIES: usize =
    tunnel_protocol::control_journal::MAX_JOURNAL_ENTRIES;
/// Sequential small requests driven through one device session, comfortably
/// past that former ceiling.
pub const SEQUENTIAL_REQUESTS: usize = 160;
/// Consumer-cancelled `/events` exchanges driven through the same device
/// session after the sequential phase (task row M7-C85): more than the
/// connector's 128 tracked OPEN journal entries, so a cancelled exchange
/// whose entry was never reclaimed would wedge the session before the end.
pub const CANCELLED_EXCHANGES: usize = 140;
/// A fresh consumer connection every this many sequential requests, so the
/// loop does not depend on one HTTP/1.1 connection surviving all of them.
const SEQUENTIAL_CONNECTION_REQUESTS: usize = 32;
/// A typed `not_dispatched` refusal (an owner-not-ready condition) may be
/// retried this many times in total.  It never reached the device, so it
/// cannot account for a second dispatch.  Exceeding the cap fails the run
/// inside the loop; it is deliberately not also a validator rule, which
/// could only restate the cap the loop already enforces.
const SEQUENTIAL_RETRY_CAP: usize = 12;
const SEQUENTIAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// The most OPEN journal entries the sequential phase may retain at once:
/// one sixteenth of the journal cap, 8 (M3-31).
///
/// **Chosen, not derived, and chosen to catch one regression.**  No request
/// count bounds the peak by construction (see the reclamation rule below), so
/// this is a ceiling with margin: 4x the largest peak measured with forgets
/// published at close (1 locally; 2 on hosted Linux, from a settled baseline
/// of 0).  It is set to go red on a relay that publishes `STREAM_FORGET` only
/// on its 500 ms maintenance tick: with the close-time and
/// after-every-inbound-frame flushes both removed, two local runs peaked at
/// **23** and **25**, which a quarter of the cap (32) let through.  It cannot tell the
/// close-time flush alone from its absence, because the after-every-frame
/// flush bounds the lag at about one request either way; that rule is
/// witnessed by the relay actor test
/// `an_http_stream_is_forgotten_at_its_own_close_once_its_proof_is_complete`.
pub const SEQUENTIAL_JOURNAL_PEAK_BOUND: usize = OPEN_JOURNAL_TRACKED_ENTRIES / 16;
/// How long the earlier phases' OPEN journal entries may take to be
/// reclaimed before the sequential phase reads its baseline.
const JOURNAL_SETTLE_WAIT: Duration = Duration::from_secs(15);

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HttpForwardRealPathEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    pub ingress_node: String,
    pub non_owner_ingress: bool,
    // (c) checksums.
    pub upload_bytes: u64,
    pub handler_received_bytes: u64,
    pub echoed_bytes: u64,
    pub handler_digest_matches_upload: bool,
    pub echo_digest_matches_upload: bool,
    pub echo_status: u16,
    pub echo_body_ended_cleanly: bool,
    // (a) concurrency during saturation.
    pub saturated_when_probed: bool,
    pub permission_status: u16,
    pub permission_body_exact: bool,
    pub permission_latency_ms: u64,
    /// The same permission request through the owner's own public route
    /// (owner-local ingress, no peer hop) also answers exactly.
    pub owner_local_permission_exact: bool,
    pub cancel_owner_release: String,
    pub cancel_owner_reset_reason: Option<u16>,
    pub cancel_ingress_error: Option<String>,
    /// The ingress recorded the consumer's release of the `/events` body after
    /// its head as `released` (M3-32), not as an ordinary abort.
    pub cancel_ingress_response_released: bool,
    pub cancel_device_response_aborted: bool,
    pub cancel_device_response_completed: bool,
    // (e) consumer disconnect cancels the handler.
    pub handler_cancellation_observed: bool,
    pub handler_cancellation_latency_ms: u64,
    // (b) per-hop high-water marks for the saturated exchange and maxima
    // over every exchange.
    pub max_ingress_request_handoff: usize,
    pub max_ingress_response_handoff: usize,
    pub max_ingress_response_body: usize,
    pub max_ingress_peer_send_in_flight: usize,
    pub max_ingress_peer_receive_queue: usize,
    pub max_owner_request_handoff: usize,
    pub max_owner_response_handoff: usize,
    pub max_owner_peer_send_in_flight: usize,
    pub max_owner_peer_receive_queue: usize,
    pub max_owner_receive_buffer: usize,
    pub owner_receive_window: usize,
    pub max_owner_parked: usize,
    pub max_owner_replay: usize,
    pub owner_data_bytes_high_water: usize,
    pub owner_data_bytes_limit: usize,
    pub max_device_receive_buffer: usize,
    pub device_receive_window: u64,
    pub max_device_parked: usize,
    pub max_device_request_handoff: usize,
    pub max_device_response_handoff: usize,
    pub max_device_request_body: usize,
    pub echo_ingress_peer_send_in_flight: usize,
    pub echo_owner_peer_send_in_flight: usize,
    pub echo_owner_receive_buffer: usize,
    pub echo_device_receive_buffer: usize,
    // (d) header leakage.
    pub handler_header_names: Vec<String>,
    pub handler_saw_forbidden_header: bool,
    pub handler_header_value_leak: bool,
    pub consumer_response_header_leak: bool,
    pub internal_header_probe_status: u16,
    pub unauthenticated_status: u16,
    pub rejected_probes_dispatched: bool,
    // (f) M7-C82: one long-lived session past the former 128-stream ceiling.
    pub sequential_requests: usize,
    pub sequential_ok: usize,
    pub sequential_dispatches: u64,
    pub sequential_not_dispatched_retries: usize,
    pub sequential_highest_stream_id: u64,
    pub sequential_session_id_stable: bool,
    pub sequential_phase_after: String,
    pub sequential_ready_after: bool,
    /// The most OPEN journal entries seen after any sequential response.  No
    /// request-count bound on it can be derived (M3-31): an entry is released
    /// by the owner's `STREAM_FORGET` after its carrier barriers, which nothing
    /// orders before the next request's admission.  The gate still holds it to
    /// a *chosen* ceiling of a sixteenth of the journal cap, which catches
    /// forgets published only on the maintenance tick.  Measured 1 or 2.
    pub open_journal_entries_peak: usize,
    /// The connector's OPEN journal entries when the sequential phase began
    /// (after waiting for the earlier phases' entries to be reclaimed), and
    /// once every sequential stream had been retired.
    pub open_journal_entries_before_sequential: usize,
    pub open_journal_entries_after_sequential: usize,
    /// The stream IDs behind those two counts, lowest first (bounded).
    pub open_journal_stream_ids_before: Vec<u64>,
    pub open_journal_stream_ids_after: Vec<u64>,
    /// How long the earlier phases' entries took to be reclaimed, or the
    /// whole wait when they were not.
    pub open_journal_settle_ms: u64,
    /// The earlier phases' owner streams, `id:release[:reason][:role]`, so a
    /// retained entry can be named (M3-31).
    pub earlier_phase_streams: Vec<String>,
    pub open_streams_retired_before_sequential: u64,
    pub open_streams_retired: u64,
    pub open_retired_ranges_coalesced: u64,
    /// M7-C85: consumer-cancelled `/events` exchanges driven after the
    /// sequential phase, how many handlers observed their cancellation, the
    /// journal and retired counts around them, and whether the one device
    /// session survived all of them.
    pub cancelled_exchanges: usize,
    pub cancelled_handlers_observed: u64,
    pub open_journal_entries_after_cancelled: usize,
    pub open_journal_stream_ids_after_cancelled: Vec<u64>,
    pub open_streams_retired_after_cancelled: u64,
    pub cancelled_session_id_stable: bool,
    pub cancelled_ready_after: bool,
}

/// The documented bound every hop must respect.  Returns the first violated
/// rule, so a regression names the hop.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
pub fn validate_http_forward_real_path_evidence(
    evidence: &HttpForwardRealPathEvidence,
) -> Result<()> {
    let body_queue_bound = BODY_QUEUE_CHUNKS * MAX_BODY_PAYLOAD_LEN;
    let checks: [(&str, bool); 58] = [
        (
            "owner-local ingress answers the permission request",
            evidence.owner_local_permission_exact,
        ),
        ("three relays", evidence.relay_count == 3),
        ("non-owner ingress", evidence.non_owner_ingress),
        ("upload size", evidence.upload_bytes == UPLOAD_BYTES as u64),
        (
            "handler received every upload byte",
            evidence.handler_received_bytes == evidence.upload_bytes,
        ),
        (
            "echo returned every byte",
            evidence.echoed_bytes == evidence.upload_bytes,
        ),
        (
            "handler SHA-256 equals upload",
            evidence.handler_digest_matches_upload,
        ),
        (
            "echo SHA-256 equals upload",
            evidence.echo_digest_matches_upload,
        ),
        ("echo status 200", evidence.echo_status == 200),
        ("echo body ended cleanly", evidence.echo_body_ended_cleanly),
        (
            "probes ran while /echo was saturated",
            evidence.saturated_when_probed,
        ),
        ("permission status 200", evidence.permission_status == 200),
        ("permission body exact", evidence.permission_body_exact),
        (
            "permission latency bound",
            evidence.permission_latency_ms < PERMISSION_LATENCY_BOUND.as_millis() as u64,
        ),
        (
            "cancelled owner stream released by RESET",
            evidence.cancel_owner_release == "reset",
        ),
        (
            "cancelled owner stream RESET reason is CANCELLED",
            evidence.cancel_owner_reset_reason == Some(CANCEL_REASON),
        ),
        (
            "cancelled ingress exchange records HTTP_CANCELLED",
            evidence.cancel_ingress_error.as_deref() == Some(HttpErrorCode::Cancelled.as_str()),
        ),
        (
            // A release after the head is its own outcome (M3-32); the next
            // rule, the device's record, is what says the call was cut short.
            "cancelled ingress response released",
            evidence.cancel_ingress_response_released,
        ),
        (
            "cancelled device response aborted, not completed",
            evidence.cancel_device_response_aborted && !evidence.cancel_device_response_completed,
        ),
        (
            "handler cancellation observed",
            evidence.handler_cancellation_observed,
        ),
        (
            "handler cancellation latency bound",
            evidence.handler_cancellation_latency_ms
                < CANCELLATION_LATENCY_BOUND.as_millis() as u64,
        ),
        (
            "ingress request handoff bound",
            evidence.max_ingress_request_handoff <= HANDOFF_CAPACITY,
        ),
        (
            "ingress response handoff bound",
            evidence.max_ingress_response_handoff <= HANDOFF_CAPACITY,
        ),
        (
            "ingress response body queue bound",
            evidence.max_ingress_response_body <= body_queue_bound,
        ),
        (
            "ingress peer in-flight bound",
            evidence.max_ingress_peer_send_in_flight <= PEER_HOP_WINDOW_BYTES
                && PEER_HOP_WINDOW_BYTES <= PEER_STREAM_BUDGET_BYTES,
        ),
        (
            "ingress peer receive queue bound",
            evidence.max_ingress_peer_receive_queue <= PEER_HOP_WINDOW_BYTES,
        ),
        (
            "owner request handoff bound",
            evidence.max_owner_request_handoff <= HANDOFF_CAPACITY,
        ),
        (
            "owner response handoff bound",
            evidence.max_owner_response_handoff <= HANDOFF_CAPACITY,
        ),
        (
            "owner peer in-flight bound",
            evidence.max_owner_peer_send_in_flight <= PEER_HOP_WINDOW_BYTES,
        ),
        (
            "owner peer receive queue bound",
            evidence.max_owner_peer_receive_queue <= PEER_HOP_WINDOW_BYTES,
        ),
        (
            "owner receive buffer bound",
            evidence.owner_receive_window == STREAM_WINDOW_BYTES
                && evidence.max_owner_receive_buffer <= evidence.owner_receive_window,
        ),
        (
            "owner parked bound",
            evidence.max_owner_parked <= HANDOFF_CAPACITY,
        ),
        (
            "owner replay bound",
            evidence.max_owner_replay <= STREAM_WINDOW_BYTES,
        ),
        (
            "owner session data budget bound",
            evidence.owner_data_bytes_limit > 0
                && evidence.owner_data_bytes_high_water <= evidence.owner_data_bytes_limit,
        ),
        (
            "device receive buffer bound",
            evidence.device_receive_window == STREAM_WINDOW_BYTES as u64
                && evidence.max_device_receive_buffer <= STREAM_WINDOW_BYTES,
        ),
        (
            "device parked bound",
            evidence.max_device_parked <= HANDOFF_CAPACITY,
        ),
        (
            "device handoff bounds",
            evidence.max_device_request_handoff <= HANDOFF_CAPACITY
                && evidence.max_device_response_handoff <= HANDOFF_CAPACITY,
        ),
        (
            "device request body queue bound",
            evidence.max_device_request_body <= body_queue_bound,
        ),
        (
            "saturation reached the ingress peer window",
            evidence.echo_ingress_peer_send_in_flight > PEER_HOP_WINDOW_BYTES / 2,
        ),
        (
            "saturation reached the owner peer window",
            evidence.echo_owner_peer_send_in_flight > PEER_HOP_WINDOW_BYTES / 2,
        ),
        (
            "saturation reached the owner receive window",
            evidence.echo_owner_receive_buffer > STREAM_WINDOW_BYTES / 2,
        ),
        (
            "saturation reached the device receive window",
            evidence.echo_device_receive_buffer > STREAM_WINDOW_BYTES / 2,
        ),
        (
            "handler saw no credential, internal or forwarding header",
            !evidence.handler_saw_forbidden_header && !evidence.handler_header_names.is_empty(),
        ),
        (
            "no credential or private address in handler header values",
            !evidence.handler_header_value_leak,
        ),
        (
            "no credential, internal field or private address in consumer response headers",
            !evidence.consumer_response_header_leak,
        ),
        (
            "internal header and unauthenticated probes rejected before dispatch",
            evidence.internal_header_probe_status == 400
                && evidence.unauthenticated_status == 401
                && !evidence.rejected_probes_dispatched,
        ),
        (
            "one session served every sequential request",
            evidence.sequential_requests == SEQUENTIAL_REQUESTS
                && evidence.sequential_ok == SEQUENTIAL_REQUESTS,
        ),
        (
            "sequential streams passed the former 128-stream session ceiling",
            evidence.sequential_highest_stream_id > OPEN_JOURNAL_TRACKED_ENTRIES as u64,
        ),
        (
            "one dispatch per sequential request",
            evidence.sequential_dispatches == SEQUENTIAL_REQUESTS as u64,
        ),
        (
            "the device session survived every sequential stream",
            evidence.sequential_session_id_stable
                && evidence.sequential_ready_after
                && matches!(
                    evidence.sequential_phase_after.as_str(),
                    "active" | "preparing" | "quiescing" | "draining" | "committing" | "retiring"
                ),
        ),
        (
            // M3-31.  Every stream the earlier phases opened is reclaimed
            // before the sequential phase starts, so its baseline is not an
            // entry that happens to be in flight -- and an entry that is never
            // reclaimed is a retention leak (M7-C82's class), not a baseline.
            "the earlier phases' OPEN journal entries were all reclaimed",
            evidence.open_journal_entries_before_sequential == 0,
        ),
        (
            "the OPEN journal stayed within a sixteenth of its cap while serving them",
            evidence.open_journal_entries_peak <= SEQUENTIAL_JOURNAL_PEAK_BOUND
                && SEQUENTIAL_JOURNAL_PEAK_BOUND < OPEN_JOURNAL_TRACKED_ENTRIES,
        ),
        (
            // M3-31.  The rule this replaces bounded the *peak* at two, which
            // assumed request k's entry is reclaimed before request k+2 is
            // admitted.  Nothing orders that: the owner's STREAM_FORGET
            // follows the stream's close and the connector releases after the
            // FORGET's carrier barriers, while the consumer already has its
            // response and sends the next request (docs/protocol.md, "OPEN
            // retry horizon and journal reclamation").  So a peak is a
            // latency, and a bound on it could only be tuned to a host.  What
            // the phase must prove is that the journal does not accumulate:
            // read from the entry count itself, independently of the retired
            // counter below, it returns to where it started.  A leak of even
            // one entry fails this, which the peak rule never guaranteed.
            "the OPEN journal returned to its starting size once every sequential stream retired",
            evidence.open_journal_entries_after_sequential
                == evidence.open_journal_entries_before_sequential,
        ),
        (
            // Exactly, not at least: every stream this phase opened was
            // reclaimed at the horizon, and nothing else was.
            "every sequential stream was reclaimed at the OPEN retry horizon",
            evidence.open_streams_retired
                == evidence
                    .open_streams_retired_before_sequential
                    .saturating_add(SEQUENTIAL_REQUESTS as u64),
        ),
        (
            // M7-C85: more cancelled exchanges than the journal holds, each
            // one's handler cancelled, on the one session.
            "every consumer-cancelled exchange cancelled its handler",
            evidence.cancelled_exchanges == CANCELLED_EXCHANGES
                && CANCELLED_EXCHANGES > OPEN_JOURNAL_TRACKED_ENTRIES
                && evidence.cancelled_handlers_observed >= CANCELLED_EXCHANGES as u64,
        ),
        (
            "every consumer-cancelled exchange was reclaimed at the OPEN retry horizon",
            evidence.open_streams_retired_after_cancelled
                == evidence
                    .open_streams_retired
                    .saturating_add(CANCELLED_EXCHANGES as u64),
        ),
        (
            "the OPEN journal returned to its starting size after the cancelled exchanges",
            evidence.open_journal_entries_after_cancelled
                == evidence.open_journal_entries_before_sequential,
        ),
        (
            "the device session survived more cancelled exchanges than its journal holds",
            evidence.cancelled_session_id_stable && evidence.cancelled_ready_after,
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "http-forward real-path gate failed: {rule}"
            )));
        }
    }
    let _ = PEER_HOP_WINDOW_RECORDS;
    Ok(())
}

fn profile() -> Result<Arc<Profile>> {
    let policy = |error| HarnessError::InvalidInput(format!("http-forward profile: {error:?}"));
    let mut request = RequestPolicy::new(64 * 1024 * 1024).map_err(policy)?;
    for (method, path) in [
        (Method::Post, "/echo"),
        (Method::Get, "/events"),
        (Method::Post, "/permission"),
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

fn bridge_config() -> Result<BridgeConfig> {
    BridgeConfig::default()
        .with_deadline(Duration::from_secs(120))
        .and_then(|config| config.with_body_queue(BODY_QUEUE_CHUNKS))
        .map_err(|error| HarnessError::InvalidInput(format!("bridge config: {error}")))
}

/// Deterministic synthetic bytes for the upload.
pub(super) fn synthetic_chunk(offset: usize, len: usize) -> Bytes {
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ offset as u64;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.push((state >> 24) as u8);
    }
    Bytes::from(bytes)
}

#[derive(Default)]
struct HandlerState {
    invocations: AtomicUsize,
    headers: Mutex<Vec<(String, String)>>,
    received: AtomicU64,
    digest: Mutex<Option<[u8; 32]>>,
    events_started: Notify,
    events_started_flag: AtomicBool,
    cancellation: Mutex<Option<Instant>>,
    cancelled: Notify,
    /// Every `/events` handler cancellation observed, for M7-C85's loop.
    cancellations: AtomicU64,
}

pub(super) fn handler_body(receiver: mpsc::Receiver<Bytes>) -> HttpBody {
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|chunk| {
            (
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(Frame::data(chunk)),
                receiver,
            )
        })
    });
    StreamBody::new(stream).boxed()
}

pub(super) fn full_body(bytes: &'static [u8]) -> HttpBody {
    Full::new(Bytes::from_static(bytes))
        .map_err(|never| match never {})
        .boxed()
}

fn handler(state: Arc<HandlerState>) -> Arc<dyn HttpHandler> {
    Arc::new(
        move |request: http::Request<ChannelBody>| -> HttpHandlerFuture {
            let state = Arc::clone(&state);
            Box::pin(async move {
                state.invocations.fetch_add(1, Ordering::SeqCst);
                {
                    let mut headers = state
                        .headers
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    for (name, value) in request.headers() {
                        headers.push((
                            name.as_str().to_owned(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        ));
                    }
                }
                let cancellation = request.extensions().get::<HandlerCancellation>().cloned();
                match request.uri().path() {
                    "/echo" => {
                        let (tx, rx) = mpsc::channel::<Bytes>(1);
                        let mut body = request.into_body();
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            let mut hasher = Sha256::new();
                            while let Some(frame) = body.frame().await {
                                let Ok(frame) = frame else { return };
                                if let Ok(data) = frame.into_data() {
                                    hasher.update(&data);
                                    state
                                        .received
                                        .fetch_add(data.len() as u64, Ordering::SeqCst);
                                    if tx.send(data).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            *state
                                .digest
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(hasher.finalize().into());
                        });
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/octet-stream")
                            .body(handler_body(rx))
                            .map_err(|_| HttpHandlerError)
                    }
                    "/events" => {
                        let (tx, rx) = mpsc::channel::<Bytes>(1);
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            let _ = tx.send(Bytes::from_static(b"data: synthetic-1\n\n")).await;
                            state.events_started_flag.store(true, Ordering::SeqCst);
                            state.events_started.notify_waiters();
                            if let Some(HandlerCancellation(token)) = cancellation {
                                token.cancelled().await;
                                state
                                    .cancellation
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .get_or_insert_with(Instant::now);
                                state.cancellations.fetch_add(1, Ordering::SeqCst);
                                state.cancelled.notify_waiters();
                            }
                            drop(tx);
                        });
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "text/event-stream")
                            .header("cache-control", "no-store")
                            .body(handler_body(rx))
                            .map_err(|_| HttpHandlerError)
                    }
                    "/permission" => {
                        let _ = request.into_body().collect().await;
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(full_body(b"permission-granted"))
                            .map_err(|_| HttpHandlerError)
                    }
                    _ => Err(HttpHandlerError),
                }
            })
        },
    )
}

pub(super) type Sender = hyper::client::conn::http1::SendRequest<StreamBody<ConsumerStream>>;
pub(super) type ConsumerStream = std::pin::Pin<
    Box<
        dyn futures_util::Stream<
                Item = std::result::Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>,
            > + Send,
    >,
>;

pub(super) async fn connect_consumer(
    addr: SocketAddr,
    ca_der: &[u8],
) -> Result<(Sender, tokio::task::JoinHandle<()>)> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("consumer CA: {error}")))?;
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Http(format!("consumer TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(HarnessError::Io)?;
    let name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("server name: {error}")))?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|error| HarnessError::Http(format!("consumer TLS handshake: {error}")))?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|error| HarnessError::Http(format!("consumer HTTP handshake: {error}")))?;
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok((sender, task))
}

/// An error and every source beneath it, joined with `: `.  Hyper's top-level
/// message alone ("operation was canceled") does not say whether a request
/// was refused before it was written or lost on a closed connection; the
/// source does.  Hyper's sources are fixed strings and I/O kinds, never a
/// payload.
pub(super) fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        message.push_str(": ");
        message.push_str(&next.to_string());
        source = next.source();
    }
    message
}

pub(super) fn empty_stream() -> StreamBody<ConsumerStream> {
    StreamBody::new(Box::pin(futures_util::stream::empty()))
}

pub(super) fn once_stream(bytes: &'static [u8]) -> StreamBody<ConsumerStream> {
    StreamBody::new(Box::pin(futures_util::stream::once(async move {
        Ok(Frame::data(Bytes::from_static(bytes)))
    })))
}

pub(super) fn request(
    method: &str,
    uri: &str,
    token: Option<&str>,
    extra: &[(&str, &str)],
    body: StreamBody<ConsumerStream>,
) -> Result<http::Request<StreamBody<ConsumerStream>>> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost")
        .header("cookie", format!("session={COOKIE_SECRET}"));
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder
        .body(body)
        .map_err(|error| HarnessError::Http(format!("building request: {error}")))
}

fn header_leaks(
    headers: &[(String, String)],
    secrets: &[String],
    private_addresses: &BTreeSet<String>,
) -> (bool, bool) {
    let forbidden_name = headers.iter().any(|(name, _)| {
        let name = name.to_ascii_lowercase();
        matches!(
            name.as_str(),
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "set-cookie"
                | "host"
                | "forwarded"
                | "via"
                | "x-real-ip"
        ) || name.starts_with("x-agent-tunnel-")
            || name.starts_with("x-forwarded-")
    });
    let value_leak = headers.iter().any(|(_, value)| {
        secrets.iter().any(|secret| value.contains(secret.as_str()))
            || private_addresses
                .iter()
                .any(|address| value.contains(address.as_str()))
    });
    (forbidden_name, value_leak)
}

async fn wait_for_records<F, T>(label: &str, mut read: F) -> Result<T>
where
    F: AsyncFnMut() -> Result<Option<T>>,
{
    let deadline = Instant::now() + DIAGNOSTIC_WAIT;
    loop {
        if let Some(value) = read().await? {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "http-forward {label} diagnostics did not record every exchange"
            )));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<HttpForwardRealPathEvidence> {
    let options = HarnessOptions::from_env()?.http_forward_service(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("http-forward harness startup timed out".into()))??;
    let profile = match profile() {
        Ok(profile) => profile,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let config = match bridge_config() {
        Ok(config) => config,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let exports = match HttpForwardExports::new().with_profile(
        crate::FIXTURE_HTTP_FORWARD_PROFILE,
        HttpForwardExport::new(Arc::clone(&profile), config),
    ) {
        Ok(exports) => exports,
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
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        run(&mut cluster, &harness, profile, config),
    )
    .await
    {
        Ok(result) => result.and_then(|evidence| {
            if let Err(error) = validate_http_forward_real_path_evidence(&evidence) {
                // The rule name alone does not say by how much it failed
                // (M3-31: a hosted run broke the journal-peak bound with no
                // figure printed).  The evidence is counts, flags, node names
                // and digest matches only.
                eprintln!("http-forward real-path evidence (failed validation): {evidence:?}");
                return Err(error);
            }
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "http-forward real-path scenario exceeded its bounded deadline".into(),
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
) -> Result<HttpForwardRealPathEvidence> {
    let mut evidence = HttpForwardRealPathEvidence {
        relay_count: cluster.relays.len(),
        ..HttpForwardRealPathEvidence::default()
    };
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("http-forward device is missing".into()))?;
    let echo_service = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("http-forward echo service missing".into()))?;
    let http_service = harness
        .http_forward_service
        .ok_or_else(|| HarnessError::InvalidInput("http-forward service was not seeded".into()))?;

    // The device attaches directly to relay-a, which becomes the owner.
    let owner_relay = cluster.relay("relay-a")?;
    let owner_device_addr = owner_relay
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| HarnessError::Process("relay-a is not running".into()))?;
    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut device_profile = write_device_profile(
        directory.path(),
        device.id,
        echo_service,
        "m3-http-forward-canary",
        owner_device_addr,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    device_profile.config.exports.insert(
        http_service.to_string(),
        LocalExport {
            kind: LocalExportKind::HttpForward,
            device_canary: None,
            mcp: None,
            acp: None,
            fs: None,
        },
    );
    device_profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;
    let state = Arc::new(HandlerState::default());
    let handlers = HttpHandlers::new().with_export(
        http_service.to_string(),
        HttpExport {
            profile,
            config,
            handler: handler(Arc::clone(&state)),
        },
    );
    let device_diagnostics = handlers.diagnostics();
    let mut client = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect_with_http_handlers(
            ConnectOptions::new(device_profile.config.clone()),
            handlers,
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("http-forward device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("http-forward device: {error}")))?;
    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("http-forward device readiness timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        exercise(
            cluster,
            harness,
            &state,
            &device_diagnostics,
            &client,
            device.tenant_id,
            device.id,
            http_service,
            &session.session_id,
            &mut evidence,
        )
        .await
    }
    .await;
    if scenario.is_err() {
        eprintln!(
            "http-forward device status: {:?}",
            client.status_snapshot().phase
        );
        eprintln!(
            "http-forward device readiness: {:?}",
            *client.readiness().borrow()
        );
    }
    let stop = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    if scenario.is_err() {
        // Payload-free: identifiers, labels and byte counts only.
        eprintln!("http-forward partial evidence: {evidence:?}");
        for node in ["relay-a", "relay-c"] {
            if let Ok(relay) = cluster.relay(node)
                && let Ok(snapshot) = relay.snapshot().await
            {
                eprintln!(
                    "http-forward {node} peer faults: {:?}",
                    snapshot.peer_fault_diagnostics
                );
            }
        }
    }
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
    state: &Arc<HandlerState>,
    device_diagnostics: &tunnel_client::http_forward::DeviceHttpDiagnostics,
    client: &tunnel_client::ConnectionHandle,
    tenant_id: uuid::Uuid,
    device_id: uuid::Uuid,
    service_id: uuid::Uuid,
    session_id: &str,
    evidence: &mut HttpForwardRealPathEvidence,
) -> Result<()> {
    // Wait for the owner claim to land on relay-a.
    let owner = {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            let owner = cluster
                .catalog
                .current_owner(tenant_id, device_id, chrono::Utc::now())
                .await
                .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?;
            if let Some(owner) = owner
                && owner.token.session_id == session_id
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
    let ingress = cluster.relay("relay-c")?;
    evidence.ingress_node = ingress.node_id.clone();
    evidence.non_owner_ingress = owner.token.node_id == "relay-a" && ingress.node_id == "relay-c";
    let ingress_addr = ingress.consumer_addr()?;
    let ca = harness.pki.server_ca.certificate_der.clone();
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            scope: Some("echo:invoke http:invoke".to_owned()),
            ..OidcTokenOptions::default()
        },
    )?;
    let base = format!("/v1/devices/{device_id}/services/{service_id}/http");
    let mut private_addresses = BTreeSet::new();
    for relay in &cluster.relays {
        if let Some(running) = relay.running.as_ref() {
            for address in [running.consumer_addr, running.device_addr] {
                private_addresses.insert(address.to_string());
                private_addresses.insert(format!("localhost:{}", address.port()));
            }
        }
    }
    for proxy in cluster.peer_proxies.values() {
        private_addresses.insert(proxy.address().to_string());
    }
    let secrets = vec![token.clone(), COOKIE_SECRET.to_owned()];

    // (d) Rejected probes never reach the handler.
    {
        let (mut sender, task) = connect_consumer(ingress_addr, &ca).await?;
        let response = sender
            .send_request(request(
                "POST",
                &format!("{base}/permission"),
                Some(&token),
                &[(INTERNAL_HEADER, "relay-a")],
                once_stream(b"{}"),
            )?)
            .await
            .map_err(|error| HarnessError::Http(format!("internal header probe: {error}")))?;
        evidence.internal_header_probe_status = response.status().as_u16();
        drop(sender);
        task.abort();
    }
    {
        let (mut sender, task) = connect_consumer(ingress_addr, &ca).await?;
        let response = sender
            .send_request(request(
                "POST",
                &format!("{base}/permission"),
                None,
                &[],
                once_stream(b"{}"),
            )?)
            .await
            .map_err(|error| HarnessError::Http(format!("unauthenticated probe: {error}")))?;
        evidence.unauthenticated_status = response.status().as_u16();
        drop(sender);
        task.abort();
    }
    evidence.rejected_probes_dispatched = state.invocations.load(Ordering::SeqCst) != 0;

    // (a)+(c) Saturate /echo in both directions.
    let upload_digest: [u8; 32] = {
        let mut hasher = Sha256::new();
        let mut offset = 0;
        while offset < UPLOAD_BYTES {
            let len = (UPLOAD_BYTES - offset).min(64 * 1024);
            hasher.update(synthetic_chunk(offset, len));
            offset += len;
        }
        hasher.finalize().into()
    };
    let sent = Arc::new(AtomicU64::new(0));
    let upload_stream: ConsumerStream = {
        let sent = Arc::clone(&sent);
        Box::pin(futures_util::stream::unfold(0usize, move |offset| {
            let sent = Arc::clone(&sent);
            async move {
                if offset >= UPLOAD_BYTES {
                    return None;
                }
                let len = (UPLOAD_BYTES - offset).min(64 * 1024);
                sent.fetch_add(len as u64, Ordering::SeqCst);
                Some((Ok(Frame::data(synthetic_chunk(offset, len))), offset + len))
            }
        }))
    };
    let (mut echo_sender, echo_task) = connect_consumer(ingress_addr, &ca).await?;
    let echo_response = timeout(
        Duration::from_secs(10),
        echo_sender.send_request(request(
            "POST",
            &format!("{base}/echo"),
            Some(&token),
            &[("content-type", "application/octet-stream")],
            StreamBody::new(upload_stream),
        )?),
    )
    .await
    .map_err(|_| HarnessError::Timeout("/echo response head timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("/echo request: {error}")))?;
    evidence.echo_status = echo_response.status().as_u16();
    let response_headers = echo_response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect::<Vec<_>>();
    let mut echo_body = echo_response.into_body();
    // Do not read: let every hop fill, and confirm the upload stalled.
    sleep(RESPONSE_PAUSE).await;
    let stalled_at = sent.load(Ordering::SeqCst);
    sleep(Duration::from_millis(300)).await;
    evidence.saturated_when_probed =
        sent.load(Ordering::SeqCst) == stalled_at && stalled_at < UPLOAD_BYTES as u64;

    // (a)+(e) Cancel /events by disconnecting while /echo is saturated.
    {
        let (mut sender, task) = connect_consumer(ingress_addr, &ca).await?;
        let response = timeout(
            Duration::from_secs(10),
            sender.send_request(request(
                "GET",
                &format!("{base}/events"),
                Some(&token),
                &[("accept", "text/event-stream")],
                empty_stream(),
            )?),
        )
        .await
        .map_err(|_| HarnessError::Timeout("/events head timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("/events request: {error}")))?;
        let mut body = response.into_body();
        let _first = timeout(Duration::from_secs(10), body.frame())
            .await
            .map_err(|_| HarnessError::Timeout("/events first event timed out".into()))?;
        let disconnected = Instant::now();
        drop(body);
        drop(sender);
        task.abort();
        let _ = task.await;
        let observed = timeout(CANCELLATION_LATENCY_BOUND * 2, async {
            loop {
                let notified = state.cancelled.notified();
                if let Some(at) = *state
                    .cancellation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                {
                    return at;
                }
                notified.await;
            }
        })
        .await;
        if let Ok(at) = observed {
            evidence.handler_cancellation_observed = true;
            evidence.handler_cancellation_latency_ms =
                at.saturating_duration_since(disconnected).as_millis() as u64;
        }
    }

    // (a) The permission answer is prompt while /echo is still saturated.
    {
        let (mut sender, task) = connect_consumer(ingress_addr, &ca).await?;
        let started = Instant::now();
        let response = timeout(
            PERMISSION_LATENCY_BOUND * 5,
            sender.send_request(request(
                "POST",
                &format!("{base}/permission"),
                Some(&token),
                &[("content-type", "application/json")],
                once_stream(br#"{"permission":"allow_once"}"#),
            )?),
        )
        .await
        .map_err(|_| HarnessError::Timeout("/permission timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("/permission request: {error}")))?;
        evidence.permission_status = response.status().as_u16();
        let body = timeout(PERMISSION_LATENCY_BOUND * 5, response.into_body().collect())
            .await
            .map_err(|_| HarnessError::Timeout("/permission body timed out".into()))?
            .map_err(|error| HarnessError::Http(format!("/permission body: {error}")))?
            .to_bytes();
        evidence.permission_latency_ms = started.elapsed().as_millis() as u64;
        evidence.permission_body_exact = body.as_ref() == b"permission-granted";
        if !evidence.permission_body_exact && body.len() <= 512 {
            // A gateway error body is sanitized `{code, execution}` JSON.
            eprintln!(
                "http-forward /permission gateway body: {}",
                String::from_utf8_lossy(&body)
            );
        }
        drop(sender);
        task.abort();
        if evidence.saturated_when_probed {
            // Still saturated after both probes: the upload cannot complete
            // while its echo is unread (socket buffers may still absorb a
            // little more, so this is not an exact-equality check).
            evidence.saturated_when_probed = sent.load(Ordering::SeqCst) < UPLOAD_BYTES as u64;
        }
    }

    // The owner's own public route drives the actor stream directly.
    {
        let owner_addr = cluster.relay("relay-a")?.consumer_addr()?;
        let (mut sender, task) = connect_consumer(owner_addr, &ca).await?;
        let response = timeout(
            PERMISSION_LATENCY_BOUND * 5,
            sender.send_request(request(
                "POST",
                &format!("{base}/permission"),
                Some(&token),
                &[("content-type", "application/json")],
                once_stream(br#"{"permission":"allow_once"}"#),
            )?),
        )
        .await
        .map_err(|_| HarnessError::Timeout("owner-local /permission timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("owner-local /permission: {error}")))?;
        let status = response.status().as_u16();
        let body = timeout(PERMISSION_LATENCY_BOUND * 5, response.into_body().collect())
            .await
            .map_err(|_| HarnessError::Timeout("owner-local /permission body timed out".into()))?
            .map_err(|error| HarnessError::Http(format!("owner-local body: {error}")))?
            .to_bytes();
        evidence.owner_local_permission_exact =
            status == 200 && body.as_ref() == b"permission-granted";
        drop(sender);
        task.abort();
    }

    // (c) Drain the echo and compare digests.
    let mut hasher = Sha256::new();
    let mut echoed = 0u64;
    let drained = timeout(Duration::from_secs(60), async {
        while let Some(frame) = echo_body.frame().await {
            let frame =
                frame.map_err(|error| HarnessError::Http(format!("/echo body: {error}")))?;
            if let Ok(data) = frame.into_data() {
                hasher.update(&data);
                echoed += data.len() as u64;
            }
        }
        Ok::<_, HarnessError>(())
    })
    .await;
    evidence.echo_body_ended_cleanly = matches!(drained, Ok(Ok(())));
    evidence.upload_bytes = sent.load(Ordering::SeqCst);
    evidence.echoed_bytes = echoed;
    let echo_digest: [u8; 32] = hasher.finalize().into();
    evidence.echo_digest_matches_upload = echo_digest == upload_digest;
    evidence.handler_received_bytes = state.received.load(Ordering::SeqCst);
    evidence.handler_digest_matches_upload = *state
        .digest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        == Some(upload_digest);
    drop(echo_sender);
    echo_task.abort();

    // (d) Headers.
    let handler_headers = state
        .headers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let (forbidden, value_leak) = header_leaks(&handler_headers, &secrets, &private_addresses);
    evidence.handler_saw_forbidden_header = forbidden;
    evidence.handler_header_value_leak = value_leak;
    evidence.handler_header_names = handler_headers
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let (response_forbidden, response_value_leak) =
        header_leaks(&response_headers, &secrets, &private_addresses);
    evidence.consumer_response_header_leak = response_forbidden || response_value_leak;

    // (b) Per-hop high-water marks, correlated ingress → owner by request ID
    // and owner → device by stream ID.
    let owner_relay = cluster.relay("relay-a")?;
    let ingress_relay = cluster.relay("relay-c")?;
    let ingress_records: Vec<HttpExchangeRecord> = wait_for_records("ingress", async || {
        let snapshot = ingress_relay.snapshot().await?;
        let records = snapshot
            .http_forward
            .exchanges
            .into_iter()
            .filter(|record| record.role == "ingress_remote")
            .collect::<Vec<_>>();
        Ok((records.len() >= 3).then_some(records))
    })
    .await?;
    let echo_ingress = ingress_records
        .iter()
        .max_by_key(|record| record.request_handoff_high_water)
        .cloned()
        .ok_or_else(|| HarnessError::Process("no ingress record".into()))?;
    let cancel_ingress = ingress_records
        .iter()
        .find(|record| record.error_code == Some(HttpErrorCode::Cancelled.as_str()))
        .cloned();
    let (owner_records, owner_streams): (Vec<HttpExchangeRecord>, Vec<HttpOwnerStreamRecord>) =
        wait_for_records("owner", async || {
            let snapshot = owner_relay.snapshot().await?;
            let exchanges = snapshot
                .http_forward
                .exchanges
                .into_iter()
                .filter(|record| record.role == "owner_peer")
                .collect::<Vec<_>>();
            let streams = snapshot.http_forward.owner_streams;
            Ok((exchanges.len() >= 3 && streams.len() >= 3).then_some((exchanges, streams)))
        })
        .await?;
    let device_records: Vec<DeviceHttpExchangeRecord> = wait_for_records("device", async || {
        let records = device_diagnostics.snapshot();
        Ok((records.len() >= 3).then_some(records))
    })
    .await?;
    let owner_for = |request_id: &Option<String>| {
        owner_records
            .iter()
            .find(|record| record.request_id == *request_id)
            .cloned()
    };
    let stream_for = |stream_id: Option<u64>| {
        owner_streams
            .iter()
            .find(|record| Some(record.stream_id) == stream_id)
            .cloned()
    };
    let device_for = |stream_id: Option<u64>| {
        device_records
            .iter()
            .find(|record| Some(record.stream_id) == stream_id)
            .cloned()
    };
    if std::env::var_os("M3_HTTP_FORWARD_DIAGNOSTICS").is_some() {
        eprintln!("ingress records: {ingress_records:?}");
        eprintln!("owner records: {owner_records:?}");
        eprintln!("owner streams: {owner_streams:?}");
        eprintln!("device records: {device_records:?}");
    }
    let echo_owner = owner_for(&echo_ingress.request_id)
        .ok_or_else(|| HarnessError::Process("no owner record for /echo".into()))?;
    let cancel_stream_id = cancel_ingress
        .as_ref()
        .and_then(|record| owner_for(&record.request_id))
        .and_then(|record| record.stream_id);
    evidence.earlier_phase_streams = owner_streams
        .iter()
        .map(|stream| {
            let role = if Some(stream.stream_id) == echo_owner.stream_id {
                ":echo"
            } else if Some(stream.stream_id) == cancel_stream_id {
                ":cancelled"
            } else {
                ""
            };
            match stream.reset_reason {
                Some(reason) => format!("{}:{}:{reason}{role}", stream.stream_id, stream.release),
                None => format!("{}:{}{role}", stream.stream_id, stream.release),
            }
        })
        .collect();
    let echo_stream = stream_for(echo_owner.stream_id)
        .ok_or_else(|| HarnessError::Process("no owner stream for /echo".into()))?;
    let echo_device = device_for(echo_owner.stream_id)
        .ok_or_else(|| HarnessError::Process("no device record for /echo".into()))?;
    evidence.echo_ingress_peer_send_in_flight = echo_ingress.peer_send_in_flight_high_water;
    evidence.echo_owner_peer_send_in_flight = echo_owner.peer_send_in_flight_high_water;
    evidence.echo_owner_receive_buffer = echo_stream.receive_buffer_high_water;
    evidence.echo_device_receive_buffer = echo_device.receive_buffer_high_water;
    if let Some(cancel_ingress) = cancel_ingress {
        evidence.cancel_ingress_error = cancel_ingress.error_code.map(str::to_owned);
        evidence.cancel_ingress_response_released = cancel_ingress.response_outcome == "released";
        if let Some(cancel_owner) = owner_for(&cancel_ingress.request_id) {
            if let Some(stream) = stream_for(cancel_owner.stream_id) {
                evidence.cancel_owner_release = stream.release.to_owned();
                evidence.cancel_owner_reset_reason = stream.reset_reason;
            }
            if let Some(device) = device_for(cancel_owner.stream_id)
                && let Some(report) = device.report
            {
                evidence.cancel_device_response_aborted = report.response == Outcome::Aborted;
                evidence.cancel_device_response_completed = report.response == Outcome::Complete;
            }
        }
    }
    for record in &ingress_records {
        evidence.max_ingress_request_handoff = evidence
            .max_ingress_request_handoff
            .max(record.request_handoff_high_water);
        evidence.max_ingress_response_handoff = evidence
            .max_ingress_response_handoff
            .max(record.response_handoff_high_water);
        evidence.max_ingress_response_body = evidence
            .max_ingress_response_body
            .max(record.response_body_high_water);
        evidence.max_ingress_peer_send_in_flight = evidence
            .max_ingress_peer_send_in_flight
            .max(record.peer_send_in_flight_high_water);
        evidence.max_ingress_peer_receive_queue = evidence
            .max_ingress_peer_receive_queue
            .max(record.peer_receive_queue_high_water);
    }
    for record in &owner_records {
        evidence.max_owner_request_handoff = evidence
            .max_owner_request_handoff
            .max(record.request_handoff_high_water);
        evidence.max_owner_response_handoff = evidence
            .max_owner_response_handoff
            .max(record.response_handoff_high_water);
        evidence.max_owner_peer_send_in_flight = evidence
            .max_owner_peer_send_in_flight
            .max(record.peer_send_in_flight_high_water);
        evidence.max_owner_peer_receive_queue = evidence
            .max_owner_peer_receive_queue
            .max(record.peer_receive_queue_high_water);
    }
    evidence.owner_receive_window = echo_stream.receive_window;
    for stream in &owner_streams {
        evidence.max_owner_receive_buffer = evidence
            .max_owner_receive_buffer
            .max(stream.receive_buffer_high_water);
        evidence.max_owner_parked = evidence
            .max_owner_parked
            .max(stream.parked_bytes_high_water);
        evidence.max_owner_replay = evidence
            .max_owner_replay
            .max(stream.replay_bytes_high_water);
    }
    let owner_snapshot = owner_relay.snapshot().await?;
    if let Some(session) = owner_snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
    {
        evidence.owner_data_bytes_high_water = session.data_bytes_high_water;
        evidence.owner_data_bytes_limit = session.data_bytes_limit;
    }
    evidence.device_receive_window = echo_device.receive_window;
    for record in &device_records {
        evidence.max_device_receive_buffer = evidence
            .max_device_receive_buffer
            .max(record.receive_buffer_high_water);
        evidence.max_device_parked = evidence
            .max_device_parked
            .max(record.parked_bytes_high_water);
        evidence.max_device_request_handoff = evidence
            .max_device_request_handoff
            .max(record.request_handoff_high_water);
        evidence.max_device_response_handoff = evidence
            .max_device_response_handoff
            .max(record.response_handoff_high_water);
        evidence.max_device_request_body = evidence
            .max_device_request_body
            .max(record.request_body_high_water);
    }

    // (f) M7-C82: one long-lived session serves an unbounded number of
    // sequential streams.  Before the OPEN retry horizon this session died at
    // its 128th stream: the connector's journal refused admission and the
    // owner's next STREAM_FORGET for that unjournaled stream failed the
    // session.  Every request here is small, so the loop measures the
    // per-session stream ceiling rather than throughput.  It runs last,
    // because it evicts the bounded device exchange records read above.
    sequential_streams(
        ingress_addr,
        &ca,
        &token,
        &base,
        state,
        device_diagnostics,
        client,
        session_id,
        evidence,
    )
    .await?;
    cancelled_exchanges(
        ingress_addr,
        &ca,
        &token,
        &base,
        state,
        client,
        session_id,
        evidence,
    )
    .await
}

/// Task row M7-C85: cancel `CANCELLED_EXCHANGES` `/events` exchanges one at a
/// time by disconnecting the consumer after the first event, on the same
/// device session, and require every one to be reclaimed at the OPEN retry
/// horizon.  The owner forgets an exchange only once both terminals are
/// proved after its `RESET(CANCELLED)`; one it never forgot would permanently
/// spend a connector journal entry, and more cancellations than the journal
/// holds would then wedge the session at `RESOURCE_EXHAUSTED`.
#[allow(clippy::too_many_arguments)]
async fn cancelled_exchanges(
    ingress_addr: SocketAddr,
    ca: &[u8],
    token: &str,
    base: &str,
    state: &Arc<HandlerState>,
    client: &tunnel_client::ConnectionHandle,
    session_id: &str,
    evidence: &mut HttpForwardRealPathEvidence,
) -> Result<()> {
    let retired_before = evidence.open_streams_retired;
    for index in 0..CANCELLED_EXCHANGES {
        let observed_before = state.cancellations.load(Ordering::SeqCst);
        let (mut sender, task) = connect_consumer(ingress_addr, ca).await?;
        let response = timeout(
            SEQUENTIAL_REQUEST_TIMEOUT,
            sender.send_request(request(
                "GET",
                &format!("{base}/events"),
                Some(token),
                &[("accept", "text/event-stream")],
                empty_stream(),
            )?),
        )
        .await
        .map_err(|_| HarnessError::Timeout(format!("cancelled exchange {index} head timed out")))?
        .map_err(|error| {
            HarnessError::Http(format!(
                "cancelled exchange {index}: {}",
                error_chain(&error)
            ))
        })?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(HarnessError::Process(format!(
                "cancelled exchange {index} answered {status}"
            )));
        }
        let mut body = response.into_body();
        timeout(SEQUENTIAL_REQUEST_TIMEOUT, body.frame())
            .await
            .map_err(|_| {
                HarnessError::Timeout(format!("cancelled exchange {index} first event timed out"))
            })?;
        drop(body);
        drop(sender);
        task.abort();
        let _ = task.await;
        timeout(SEQUENTIAL_REQUEST_TIMEOUT, async {
            loop {
                let notified = state.cancelled.notified();
                if state.cancellations.load(Ordering::SeqCst) > observed_before {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "cancelled exchange {index}: the handler never observed its cancellation"
            ))
        })?;
        evidence.cancelled_exchanges += 1;
    }
    evidence.cancelled_handlers_observed = state.cancellations.load(Ordering::SeqCst);
    let target_retired = retired_before.saturating_add(CANCELLED_EXCHANGES as u64);
    let final_status = wait_for_records("cancelled exchanges' journal", async || {
        let snapshot = client.status_snapshot();
        Ok((snapshot.open_streams_retired >= target_retired
            && snapshot.open_journal_entries <= evidence.open_journal_entries_before_sequential)
            .then_some(snapshot))
    })
    .await;
    let final_status = match final_status {
        Ok(status) => status,
        Err(error) => {
            // Record what was retained so the failure names it.
            let snapshot = client.status_snapshot();
            evidence.open_journal_entries_after_cancelled = snapshot.open_journal_entries;
            evidence.open_journal_stream_ids_after_cancelled =
                snapshot.open_journal_stream_ids.clone();
            evidence.open_streams_retired_after_cancelled = snapshot.open_streams_retired;
            return Err(error);
        }
    };
    evidence.open_journal_entries_after_cancelled = final_status.open_journal_entries;
    evidence.open_journal_stream_ids_after_cancelled = final_status.open_journal_stream_ids.clone();
    evidence.open_streams_retired_after_cancelled = final_status.open_streams_retired;
    evidence.cancelled_session_id_stable = final_status.session_id.as_deref() == Some(session_id);
    evidence.cancelled_ready_after = matches!(
        &*client.readiness().borrow(),
        tunnel_client::Readiness::Ready(session) if session.session_id == session_id
    );
    Ok(())
}

/// Drive `SEQUENTIAL_REQUESTS` small requests through one device session, one
/// at a time, and record what the session and its OPEN journal did.
#[allow(clippy::too_many_arguments)]
async fn sequential_streams(
    ingress_addr: SocketAddr,
    ca: &[u8],
    token: &str,
    base: &str,
    state: &Arc<HandlerState>,
    device_diagnostics: &tunnel_client::http_forward::DeviceHttpDiagnostics,
    client: &tunnel_client::ConnectionHandle,
    session_id: &str,
    evidence: &mut HttpForwardRealPathEvidence,
) -> Result<()> {
    let dispatches_before = state.invocations.load(Ordering::SeqCst) as u64;
    evidence.sequential_requests = SEQUENTIAL_REQUESTS;
    // M3-31: let the earlier phases' reclamation settle before reading the
    // baseline, so the baseline is not an entry in flight.  An entry still
    // retained at the end of the wait is reported, not waited for forever.
    let settle_started = Instant::now();
    let mut before = client.status_snapshot();
    while before.open_journal_entries > 0 && settle_started.elapsed() < JOURNAL_SETTLE_WAIT {
        sleep(Duration::from_millis(20)).await;
        before = client.status_snapshot();
    }
    evidence.open_journal_settle_ms =
        u64::try_from(settle_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    evidence.open_streams_retired_before_sequential = before.open_streams_retired;
    evidence.open_journal_entries_before_sequential = before.open_journal_entries;
    evidence.open_journal_stream_ids_before = before.open_journal_stream_ids.clone();
    let mut connection: Option<(Sender, tokio::task::JoinHandle<()>)> = None;
    let mut on_connection = 0;
    let mut index = 0;
    while index < SEQUENTIAL_REQUESTS {
        if connection.is_none() || on_connection >= SEQUENTIAL_CONNECTION_REQUESTS {
            if let Some((sender, task)) = connection.take() {
                drop(sender);
                task.abort();
            }
            connection = Some(connect_consumer(ingress_addr, ca).await?);
            on_connection = 0;
        }
        let (sender, _task) = connection
            .as_mut()
            .ok_or_else(|| HarnessError::Process("sequential consumer connection".into()))?;
        // M3-21/M3-24: wait for the reused connection to ask for its next
        // request.  Hyper's HTTP/1 `SendRequest` buffers exactly one request
        // before the connection task first polls it; every later request is
        // refused -- as `Canceled`, "operation was canceled", source
        // "connection was not ready" -- unless the connection task has
        // already finished the previous exchange and re-armed its want.  The
        // loop sends the next request the moment the previous body is
        // collected, so on a loaded host it raced that task and failed at a
        // varying index that was never the first request on a connection.
        // Nothing was sent, so the relay saw nothing.  A connection that has
        // closed still fails here, with its own cause, rather than being
        // retried.
        timeout(SEQUENTIAL_REQUEST_TIMEOUT, sender.ready())
            .await
            .map_err(|_| {
                HarnessError::Timeout(format!("sequential request {index} connection not ready"))
            })?
            .map_err(|error| {
                HarnessError::Http(format!(
                    "sequential request {index}: connection closed before it was ready: {}",
                    error_chain(&error)
                ))
            })?;
        let response = timeout(
            SEQUENTIAL_REQUEST_TIMEOUT,
            sender.send_request(request(
                "POST",
                &format!("{base}/permission"),
                Some(token),
                &[("content-type", "application/json")],
                once_stream(br#"{"permission":"allow_once"}"#),
            )?),
        )
        .await
        .map_err(|_| HarnessError::Timeout(format!("sequential request {index} head timed out")))?
        .map_err(|error| {
            HarnessError::Http(format!(
                "sequential request {index}: {}",
                error_chain(&error)
            ))
        })?;
        let status = response.status().as_u16();
        let body = timeout(SEQUENTIAL_REQUEST_TIMEOUT, response.into_body().collect())
            .await
            .map_err(|_| HarnessError::Timeout(format!("sequential body {index} timed out")))?
            .map_err(|error| HarnessError::Http(format!("sequential body {index}: {error}")))?
            .to_bytes();
        on_connection += 1;
        if status == 200 && body.as_ref() == b"permission-granted" {
            evidence.sequential_ok += 1;
            index += 1;
        } else if body.windows(14).any(|window| window == b"not_dispatched")
            && evidence.sequential_not_dispatched_retries < SEQUENTIAL_RETRY_CAP
        {
            // A typed owner-not-ready refusal never reached the device, so it
            // cannot account for a second dispatch.  Retry the same request.
            evidence.sequential_not_dispatched_retries += 1;
            sleep(Duration::from_millis(100)).await;
        } else {
            return Err(HarnessError::Process(format!(
                "sequential request {index} failed with status {status} after {} typed retries",
                evidence.sequential_not_dispatched_retries
            )));
        }
        let status_snapshot = client.status_snapshot();
        evidence.open_journal_entries_peak = evidence
            .open_journal_entries_peak
            .max(status_snapshot.open_journal_entries);
    }
    if let Some((sender, task)) = connection.take() {
        drop(sender);
        task.abort();
    }
    evidence.sequential_dispatches =
        (state.invocations.load(Ordering::SeqCst) as u64).saturating_sub(dispatches_before);
    evidence.sequential_highest_stream_id = device_diagnostics
        .snapshot()
        .iter()
        .map(|record| record.stream_id)
        .max()
        .unwrap_or_default();
    // The journal releases an entry only after the owner's STREAM_FORGET has
    // completed its carrier barriers, which can trail the consumer response.
    let target_retired = evidence
        .open_streams_retired_before_sequential
        .saturating_add(SEQUENTIAL_REQUESTS as u64);
    let final_status = wait_for_records("open journal", async || {
        let snapshot = client.status_snapshot();
        Ok((snapshot.open_streams_retired >= target_retired).then_some(snapshot))
    })
    .await?;
    evidence.open_journal_entries_peak = evidence
        .open_journal_entries_peak
        .max(final_status.open_journal_entries);
    evidence.open_journal_entries_after_sequential = final_status.open_journal_entries;
    evidence.open_journal_stream_ids_after = final_status.open_journal_stream_ids.clone();
    evidence.open_streams_retired = final_status.open_streams_retired;
    evidence.open_retired_ranges_coalesced = final_status.open_retired_ranges_coalesced;
    evidence.sequential_session_id_stable = final_status.session_id.as_deref() == Some(session_id);
    evidence.sequential_phase_after = final_status.phase.clone();
    evidence.sequential_ready_after = matches!(
        &*client.readiness().borrow(),
        tunnel_client::Readiness::Ready(session) if session.session_id == session_id
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> HttpForwardRealPathEvidence {
        HttpForwardRealPathEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            ingress_node: "relay-c".into(),
            non_owner_ingress: true,
            upload_bytes: UPLOAD_BYTES as u64,
            handler_received_bytes: UPLOAD_BYTES as u64,
            echoed_bytes: UPLOAD_BYTES as u64,
            handler_digest_matches_upload: true,
            echo_digest_matches_upload: true,
            echo_status: 200,
            echo_body_ended_cleanly: true,
            saturated_when_probed: true,
            permission_status: 200,
            permission_body_exact: true,
            permission_latency_ms: 40,
            owner_local_permission_exact: true,
            cancel_owner_release: "reset".into(),
            cancel_owner_reset_reason: Some(CANCEL_REASON),
            cancel_ingress_error: Some("HTTP_CANCELLED".into()),
            cancel_ingress_response_released: true,
            cancel_device_response_aborted: true,
            cancel_device_response_completed: false,
            handler_cancellation_observed: true,
            handler_cancellation_latency_ms: 30,
            max_ingress_request_handoff: HANDOFF_CAPACITY,
            max_ingress_response_handoff: HANDOFF_CAPACITY,
            max_ingress_response_body: BODY_QUEUE_CHUNKS * MAX_BODY_PAYLOAD_LEN,
            max_ingress_peer_send_in_flight: PEER_HOP_WINDOW_BYTES,
            max_ingress_peer_receive_queue: PEER_HOP_WINDOW_BYTES,
            max_owner_request_handoff: HANDOFF_CAPACITY,
            max_owner_response_handoff: HANDOFF_CAPACITY,
            max_owner_peer_send_in_flight: PEER_HOP_WINDOW_BYTES,
            max_owner_peer_receive_queue: PEER_HOP_WINDOW_BYTES,
            max_owner_receive_buffer: STREAM_WINDOW_BYTES,
            owner_receive_window: STREAM_WINDOW_BYTES,
            max_owner_parked: HANDOFF_CAPACITY,
            max_owner_replay: STREAM_WINDOW_BYTES,
            owner_data_bytes_high_water: 1,
            owner_data_bytes_limit: 2,
            max_device_receive_buffer: STREAM_WINDOW_BYTES,
            device_receive_window: STREAM_WINDOW_BYTES as u64,
            max_device_parked: HANDOFF_CAPACITY,
            max_device_request_handoff: HANDOFF_CAPACITY,
            max_device_response_handoff: HANDOFF_CAPACITY,
            max_device_request_body: BODY_QUEUE_CHUNKS * MAX_BODY_PAYLOAD_LEN,
            echo_ingress_peer_send_in_flight: PEER_HOP_WINDOW_BYTES,
            echo_owner_peer_send_in_flight: PEER_HOP_WINDOW_BYTES,
            echo_owner_receive_buffer: STREAM_WINDOW_BYTES,
            echo_device_receive_buffer: STREAM_WINDOW_BYTES,
            handler_header_names: vec!["content-type".into()],
            handler_saw_forbidden_header: false,
            handler_header_value_leak: false,
            consumer_response_header_leak: false,
            internal_header_probe_status: 400,
            unauthenticated_status: 401,
            rejected_probes_dispatched: false,
            sequential_requests: SEQUENTIAL_REQUESTS,
            sequential_ok: SEQUENTIAL_REQUESTS,
            sequential_dispatches: SEQUENTIAL_REQUESTS as u64,
            sequential_not_dispatched_retries: 0,
            sequential_highest_stream_id: OPEN_JOURNAL_TRACKED_ENTRIES as u64 + 1,
            sequential_session_id_stable: true,
            sequential_phase_after: "active".into(),
            sequential_ready_after: true,
            open_journal_entries_peak: 3,
            open_journal_entries_before_sequential: 0,
            open_journal_entries_after_sequential: 0,
            open_journal_stream_ids_before: Vec::new(),
            open_journal_stream_ids_after: Vec::new(),
            open_journal_settle_ms: 40,
            earlier_phase_streams: vec!["1:fin:echo".into(), "3:reset:4005:cancelled".into()],
            open_streams_retired_before_sequential: 3,
            open_streams_retired: SEQUENTIAL_REQUESTS as u64 + 3,
            open_retired_ranges_coalesced: 0,
            cancelled_exchanges: CANCELLED_EXCHANGES,
            cancelled_handlers_observed: CANCELLED_EXCHANGES as u64 + 1,
            open_journal_entries_after_cancelled: 0,
            open_journal_stream_ids_after_cancelled: Vec::new(),
            open_streams_retired_after_cancelled: (SEQUENTIAL_REQUESTS + CANCELLED_EXCHANGES)
                as u64
                + 3,
            cancelled_session_id_stable: true,
            cancelled_ready_after: true,
        }
    }

    #[test]
    fn validator_accepts_exact_bounds_and_rejects_every_single_mutation() {
        validate_http_forward_real_path_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut HttpForwardRealPathEvidence));
        let mutations: Vec<Mutation> = vec![
            ("relays", |e| e.relay_count = 2),
            ("owner-local ingress", |e| {
                e.owner_local_permission_exact = false
            }),
            ("ingress", |e| e.non_owner_ingress = false),
            ("upload", |e| e.upload_bytes -= 1),
            ("handler bytes", |e| e.handler_received_bytes -= 1),
            ("echo bytes", |e| e.echoed_bytes -= 1),
            ("handler digest", |e| {
                e.handler_digest_matches_upload = false
            }),
            ("echo digest", |e| e.echo_digest_matches_upload = false),
            ("echo status", |e| e.echo_status = 502),
            ("echo end", |e| e.echo_body_ended_cleanly = false),
            ("saturated", |e| e.saturated_when_probed = false),
            ("permission status", |e| e.permission_status = 504),
            ("permission body", |e| e.permission_body_exact = false),
            ("permission latency", |e| {
                e.permission_latency_ms = PERMISSION_LATENCY_BOUND.as_millis() as u64;
            }),
            ("cancel fin", |e| e.cancel_owner_release = "fin".into()),
            ("cancel reason", |e| {
                e.cancel_owner_reset_reason = Some(tunnel_protocol::reset_reason::ADAPTER_FAILURE);
            }),
            ("cancel ingress code", |e| e.cancel_ingress_error = None),
            ("cancel ingress released", |e| {
                e.cancel_ingress_response_released = false;
            }),
            ("cancel device completed", |e| {
                e.cancel_device_response_completed = true;
            }),
            ("cancel observed", |e| {
                e.handler_cancellation_observed = false
            }),
            ("cancel latency", |e| {
                e.handler_cancellation_latency_ms = CANCELLATION_LATENCY_BOUND.as_millis() as u64;
            }),
            ("ingress request handoff", |e| {
                e.max_ingress_request_handoff = HANDOFF_CAPACITY + 1;
            }),
            ("ingress response handoff", |e| {
                e.max_ingress_response_handoff = HANDOFF_CAPACITY + 1;
            }),
            ("ingress body", |e| e.max_ingress_response_body += 1),
            ("ingress peer send", |e| {
                e.max_ingress_peer_send_in_flight = PEER_HOP_WINDOW_BYTES + 1;
            }),
            ("ingress peer receive", |e| {
                e.max_ingress_peer_receive_queue = PEER_HOP_WINDOW_BYTES + 1;
            }),
            ("owner request handoff", |e| {
                e.max_owner_request_handoff = HANDOFF_CAPACITY + 1;
            }),
            ("owner response handoff", |e| {
                e.max_owner_response_handoff = HANDOFF_CAPACITY + 1;
            }),
            ("owner peer send", |e| {
                e.max_owner_peer_send_in_flight = PEER_HOP_WINDOW_BYTES + 1;
            }),
            ("owner peer receive", |e| {
                e.max_owner_peer_receive_queue = PEER_HOP_WINDOW_BYTES + 1;
            }),
            ("owner receive buffer", |e| {
                e.max_owner_receive_buffer = STREAM_WINDOW_BYTES + 1;
            }),
            ("owner parked", |e| {
                e.max_owner_parked = HANDOFF_CAPACITY + 1
            }),
            ("owner replay", |e| {
                e.max_owner_replay = STREAM_WINDOW_BYTES + 1
            }),
            ("owner budget", |e| e.owner_data_bytes_high_water = 3),
            ("cancelled exchanges short", |e| {
                e.cancelled_exchanges = CANCELLED_EXCHANGES - 1;
            }),
            ("cancelled handler missed", |e| {
                e.cancelled_handlers_observed = CANCELLED_EXCHANGES as u64 - 1;
            }),
            ("cancelled exchange never reclaimed", |e| {
                e.open_streams_retired_after_cancelled -= 1;
            }),
            ("cancelled journal leak", |e| {
                e.open_journal_entries_after_cancelled = 1;
            }),
            ("cancelled session replaced", |e| {
                e.cancelled_session_id_stable = false;
            }),
            ("cancelled session not ready", |e| {
                e.cancelled_ready_after = false;
            }),
            ("device receive buffer", |e| {
                e.max_device_receive_buffer = STREAM_WINDOW_BYTES + 1;
            }),
            ("device parked", |e| {
                e.max_device_parked = HANDOFF_CAPACITY + 1
            }),
            ("device handoff", |e| {
                e.max_device_request_handoff = HANDOFF_CAPACITY + 1;
            }),
            ("device body", |e| e.max_device_request_body += 1),
            ("saturation ingress", |e| {
                e.echo_ingress_peer_send_in_flight = 0
            }),
            ("saturation owner", |e| e.echo_owner_peer_send_in_flight = 0),
            ("saturation owner buffer", |e| {
                e.echo_owner_receive_buffer = 0
            }),
            ("saturation device buffer", |e| {
                e.echo_device_receive_buffer = 0
            }),
            ("forbidden header", |e| {
                e.handler_saw_forbidden_header = true
            }),
            ("header value leak", |e| e.handler_header_value_leak = true),
            ("response leak", |e| e.consumer_response_header_leak = true),
            ("probe status", |e| e.internal_header_probe_status = 200),
            ("probe dispatched", |e| e.rejected_probes_dispatched = true),
            ("sequential count", |e| e.sequential_requests -= 1),
            ("sequential success", |e| e.sequential_ok -= 1),
            ("sequential ceiling", |e| {
                e.sequential_highest_stream_id = OPEN_JOURNAL_TRACKED_ENTRIES as u64;
            }),
            ("sequential double dispatch", |e| {
                e.sequential_dispatches += 1
            }),
            ("sequential session", |e| {
                e.sequential_session_id_stable = false
            }),
            ("sequential phase", |e| {
                e.sequential_phase_after = "failed".into()
            }),
            ("sequential readiness", |e| e.sequential_ready_after = false),
            ("journal leak", |e| {
                e.open_journal_entries_after_sequential =
                    e.open_journal_entries_before_sequential + 1;
            }),
            ("journal shrank below its baseline", |e| {
                e.open_journal_entries_before_sequential = 1;
                e.open_journal_entries_after_sequential = 0;
            }),
            ("earlier-phase entry never reclaimed", |e| {
                e.open_journal_entries_before_sequential = 1;
                e.open_journal_entries_after_sequential = 1;
            }),
            ("journal peak over a sixteenth of the cap", |e| {
                e.open_journal_entries_peak = SEQUENTIAL_JOURNAL_PEAK_BOUND + 1;
            }),
            ("journal reclamation short", |e| e.open_streams_retired -= 1),
            ("journal reclamation extra", |e| e.open_streams_retired += 1),
            ("reclamation baseline", |e| {
                e.open_streams_retired_before_sequential += 1
            }),
        ];
        for (name, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_http_forward_real_path_evidence(&evidence).is_err(),
                "mutation {name} passed"
            );
        }
    }

    #[test]
    fn header_leak_detector_finds_names_secrets_and_private_addresses() {
        let secrets = vec!["token-abc".to_owned()];
        let addresses = BTreeSet::from(["127.0.0.1:4433".to_owned()]);
        let clean = vec![("content-type".to_owned(), "text/plain".to_owned())];
        assert_eq!(header_leaks(&clean, &secrets, &addresses), (false, false));
        for name in [
            "authorization",
            "cookie",
            "x-agent-tunnel-owner",
            "x-forwarded-for",
            "via",
        ] {
            let headers = vec![(name.to_owned(), "x".to_owned())];
            assert!(header_leaks(&headers, &secrets, &addresses).0, "{name}");
        }
        let secret = vec![("accept".to_owned(), "a token-abc b".to_owned())];
        assert!(header_leaks(&secret, &secrets, &addresses).1);
        let address = vec![("accept".to_owned(), "http://127.0.0.1:4433/".to_owned())];
        assert!(header_leaks(&address, &secrets, &addresses).1);
    }

    /// M3-21/M3-24: the gate's `sequential request N: operation was canceled`
    /// is hyper refusing a request on a connection that has not asked for
    /// one.  `SendRequest` buffers one request before its connection task
    /// runs; a second, sent before that task re-arms its want, is refused
    /// synchronously and never written.  Here the connection task is never
    /// polled at all, which is the loaded-host case taken to its limit.
    #[tokio::test]
    async fn a_reused_connection_refuses_a_request_it_has_not_asked_for() {
        let (client_io, _server_io) = tokio::io::duplex(64 * 1024);
        let (mut sender, _connection) = hyper::client::conn::http1::handshake::<
            _,
            StreamBody<ConsumerStream>,
        >(TokioIo::new(client_io))
        .await
        .expect("handshake");
        let _first = sender.send_request(
            request("POST", "/first", None, &[], empty_stream()).expect("first request"),
        );
        let error = sender
            .send_request(request("POST", "/second", None, &[], empty_stream()).expect("second"))
            .await
            .expect_err("a request the connection did not ask for is refused");
        assert!(error.is_canceled());
        assert_eq!(error.to_string(), "operation was canceled");
        assert_eq!(
            error_chain(&error),
            "operation was canceled: connection was not ready"
        );
    }

    /// The fix: `ready()` waits for the connection to ask, so a reused
    /// connection serves request after request with no refusal.  The peer is
    /// a minimal HTTP/1.1 responder on an in-memory pipe.
    #[tokio::test]
    async fn a_reused_connection_serves_every_request_once_it_is_ready() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const REQUESTS: usize = 64;
        const BODY_END: &[u8] = b"0\r\n\r\n";
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut chunk = [0_u8; 4096];
            for _ in 0..REQUESTS {
                // Each request is a head plus an empty chunked body.
                let end = loop {
                    if let Some(position) = buffer
                        .windows(BODY_END.len())
                        .position(|window| window == BODY_END)
                    {
                        break position + BODY_END.len();
                    }
                    let read = server_io.read(&mut chunk).await.expect("read");
                    assert!(read > 0, "client closed early");
                    buffer.extend_from_slice(&chunk[..read]);
                };
                buffer.drain(..end);
                server_io
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await
                    .expect("write");
            }
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake::<
            _,
            StreamBody<ConsumerStream>,
        >(TokioIo::new(client_io))
        .await
        .expect("handshake");
        let connection = tokio::spawn(connection);
        for index in 0..REQUESTS {
            sender
                .ready()
                .await
                .expect("the connection asks for a request");
            let response = sender
                .send_request(request("POST", "/next", None, &[], empty_stream()).expect("request"))
                .await
                .unwrap_or_else(|error| panic!("request {index}: {}", error_chain(&error)));
            assert_eq!(response.status(), 200);
            let body = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            assert_eq!(body.as_ref(), b"ok");
        }
        server.await.expect("server");
        drop(sender);
        let _ = connection.await;
    }
}
