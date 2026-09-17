//! `verify-m8-acp-real-path`: ACP over the real three-relay production
//! cluster (task rows M8-03 and M8-04, M8 chunk 4).
//!
//! The device is owned by **relay-a** and the consumer enters at **relay-c**,
//! a non-owner ingress, so every exchange crosses the private mTLS HTTP/3 peer
//! hop to the owner actor and then the device's own data WebSocket. Chunks 1
//! to 3 had no tunnel, no relay and no principal; this gate is where those
//! arrive.
//!
//! # No claim terminates on an HTTP status
//!
//! `docs/acp.md`: "HTTP 202 means accepted by the bridge, not that an agent
//! finished or committed an action." Every claim here about a prompt, a
//! session or a permission anchors to a message **observed on an SSE stream**,
//! and `stopReason` is read off the wire. A status is asserted only where the
//! relay or the bridge *refused*, and each of those also shows that nothing
//! reached the agent.
//!
//! # The M7-C80 accommodation, and what it costs this gate's claims
//!
//! **A same-key membership re-sign at a higher record version invalidates
//! every peer admission and every in-flight stream riding it**
//! (`membership_runtime.rs`, the `current_version != Some(peer.record_version)`
//! invalidation). `docs/http-forwarding.md` gate 4 records the consequence: "A
//! long-lived SSE response through a non-owner ingress therefore does not
//! survive a membership re-sign."
//!
//! **ACP is nothing but a long-lived SSE response through a non-owner
//! ingress.** Every connection here holds a connection GET open for its whole
//! life, and a session GET beside it.
//!
//! So this gate does what `verify-m3-http-forward-rotation` does: it re-signs
//! the fixture's 60-second membership records **only at case boundaries, and
//! at most every [`MEMBERSHIP_RESIGN_SPACING`]**, never while a stream is in
//! flight, and waits for the relay-c route to answer again before the next
//! case starts. [`Gate::boundary`] is that code, and it is deliberately the
//! only place in this file that re-signs.
//!
//! **That is a harness accommodation, not a property of the product, and this
//! gate must not be read as one.** Nothing here shows that an ACP connection
//! survives normal cluster operation; a membership refresh in production would
//! break every ACP connection on a non-owner ingress, and M7-C80 is open for
//! exactly that reason. What the gate shows is ACP's own behaviour over the
//! real route *between* re-signs. [`NOT_COVERED`] says so in the evidence
//! itself rather than only in this comment.
//!
//! # Rotation-freeze refusals are never silently counted as passes
//!
//! M3-15 is open: a POST landing in a QUIESCE→COMMIT freeze is answered `503
//! PEER_UNAVAILABLE` with `not_dispatched`, which is the same body the relay
//! returns for every owner-not-ready condition. ACP is worse off than MCP here
//! because its subscription deadlines are ten seconds.
//!
//! This gate copies `verify-m3-mcp-cloud-client`'s discipline exactly: every
//! refusal is counted, correlated against an **observed** connector rotation
//! phase, resent only while it coincides with a freeze and only up to
//! [`NOT_DISPATCHED_RETRIES`], and the first refusal that does **not** coincide
//! is recorded in `unexplained_refusal` and fails the run by name. A case that
//! did not execute is reported as not executed; it is never folded into a pass
//! count.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use tunnel_client::http_forward::{AcpExportDiagnostics, HttpHandlers};
use tunnel_client::{ConnectOptions, ConnectionHandle};
use tunnel_core::RotationConfig;

use super::http_forward_real_path::{ConsumerStream, empty_stream};
use super::{
    CLEANUP_TIMEOUT, Harness, HarnessError, HarnessOptions, ProductionCluster, Result,
    RunningHarness, SCENARIO_TIMEOUT, STARTUP_TIMEOUT, finish_scenario_with_cleanup,
    push_cleanup_error,
};

/// The rotation policy this gate runs the device under.
///
/// **This does not make the gate a rotation test, and the earlier comment here
/// claimed it did.** `docs/acp.md` says ordinary data-socket rotation must
/// leave connections, sessions, callbacks and GET streams intact; proving that
/// needs a case that holds a connection open across a completed rotation and
/// asserts it survived, and there is no such case. Runs have been observed at
/// `rotations_completed` of both 0 and 4 — the count is incidental to how long
/// the cases happen to take, and nothing asserts it either way. The interval is
/// short so the device behaves like a real one rather than a static fixture.
/// The gate's `not_covered` carries the observed count.
pub const ACP_GATE_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 6,
    handshake_timeout_seconds: 2,
    overlap_seconds: 5,
};

/// How rarely membership may be re-signed: the M7-C80 accommodation.
///
/// `docs/http-forwarding.md` gate 4 uses the same 15 seconds against the same
/// defect. It is a harness accommodation; see the module comment.
pub const MEMBERSHIP_RESIGN_SPACING: Duration = Duration::from_secs(15);

/// The lifetime of the membership records the fixture signs.  Every case must
/// finish inside it, or the gate was relying on records that had expired.
pub const MEMBERSHIP_RECORD_LIFETIME: Duration = Duration::from_secs(60);

/// The relay's own retry hint for an owner-not-ready refusal.
const MIN_RETRY_HINT_MS: u64 = 250;
/// Margin above the handshake window, so a resend budget derived from the
/// rotation policy is not tight against it.
const RETRY_MARGIN: u64 = 4;
/// How many times a `not_dispatched` refusal that **coincides with an observed
/// freeze** may be resent.  Derived from this gate's own rotation policy
/// rather than tuned until the run passed.
pub const NOT_DISPATCHED_RETRIES: u64 = (ACP_GATE_ROTATION.handshake_timeout_seconds * 1_000)
    .div_ceil(MIN_RETRY_HINT_MS)
    + RETRY_MARGIN;

/// How close to an observed frozen sample a refusal must be to count as
/// coinciding with it.
const FREEZE_COINCIDENCE: Duration = Duration::from_millis(750);
/// The connector phases in which the owner refuses new stream admission.
const FROZEN_PHASES: [&str; 3] = ["quiescing", "draining", "committing"];

/// The cases this gate runs, in order.
pub const ACP_CASES: [&str; 7] = [
    "conversation",
    "permission-allow",
    "permission-reject",
    "cancel",
    "sse-loss-session",
    "sse-loss-connection",
    "outcome-unknown",
];

/// What this gate deliberately does not establish.
///
/// These are prose rather than fields because each is a limit on the claim,
/// not a measurement.  The validator requires the evidence to carry exactly as
/// many of them as are listed here, so a case that quietly stops recording one
/// fails the run.
pub const NOT_COVERED: [&str; 9] = [
    "an ACP connection surviving a membership re-sign: M7-C80 is open, and this gate re-signs only at case boundaries and at most every 15 s, which is a harness accommodation rather than a product property",
    "no retry beyond the moment of observation: the agent's ledger is read when the consumer's stream has failed and again after a settle window, and a replay issued after that would not be observed",
    "two users, cross-tenant isolation, grant revocation, owner loss and peer-key rotation: M8 chunk 5",
    "any host but macOS",
    "any ACP agent but this repository's own synthetic fixture, and any ACP server at all",
    "the connection-capacity table at its real bounds: 256 tracked and 32 per principal are proven as arithmetic in tunnel-acp-export, not by opening 257 connections with 257 child processes here",
    // The rotation sentence is NOT here: it carries a measurement, and a
    // measurement written into a constant is a claim about a run that has not
    // happened yet.  An earlier version of this list said "this run observed
    // rotations_completed = 0" unconditionally, and emitted that sentence
    // verbatim in a run that observed four.  It is formatted from the field in
    // [`not_covered`] instead.
    "the output-credit stall over the real route: the 30 s bound and its never-drop-and-continue half are measured against the export's own queue in tunnel-acp-export, and the carrier in front of it has flow control of its own that this gate does not drive to saturation",
    "the permission deadline over the real route: it is observed elapsing in tunnel-acp-export against a shortened bound, not here",
    "bounded per-hop queues at the ingress, owner and device hops: no case here saturates a hop, so no hop bound is asserted rather than asserted vacuously",
];

/// The limits of this gate's claim, with the ones that carry a measurement
/// formatted from what was actually observed.
///
/// **A disclosure that hard-codes a number is a claim, not a disclosure.**
#[must_use]
pub fn not_covered(rotations_observed: u64) -> Vec<String> {
    let mut all: Vec<String> = NOT_COVERED.iter().map(|text| (*text).to_owned()).collect();
    all.push(format!(
        "an ACP connection carried across a completed scheduled rotation: this run observed rotations_completed = {rotations_observed}, and no case asserts anything about a connection spanning one, so nothing here says what a rotation does to a live ACP connection"
    ));
    all
}

/// Everything this gate measured.  Primitives only: identifiers, counters,
/// statuses and typed labels, never a payload or a credential.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AcpRealPathEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    pub ingress_node: String,
    pub non_owner_ingress: bool,
    /// The cases that actually ran, in order.  A case that did not execute is
    /// absent here and the validator rejects the run; it is never folded into
    /// a pass count.
    pub cases_executed: Vec<String>,
    pub not_covered: Vec<String>,

    // --- the conversation, every claim read off an SSE stream ---
    /// `initialize` was answered 200 and returned a connection identifier.
    pub connection_opened: bool,
    /// The `session/new` result arrived **on the connection GET**.
    pub session_id_from_connection_stream: bool,
    /// The prompt's own result arrived on the session GET, with this
    /// `stopReason` read from the message itself.
    pub conversation_stop_reason: String,
    /// `session/prompt` was answered 202 and the result arrived separately.
    pub prompt_accepted_202: bool,

    // --- permissions ---
    /// The permission callback was observed on the session stream.
    pub permission_requested_on_wire: bool,
    /// The option identifiers the agent actually offered, read from the
    /// callback on the wire.
    pub offered_options: Vec<String>,
    /// The outcome the **agent itself** recorded receiving, read from its
    /// workspace marker rather than from anything the bridge believes.
    pub allow_outcome_at_agent: String,
    pub reject_outcome_at_agent: String,
    pub allow_stop_reason: String,
    pub reject_stop_reason: String,
    /// The **rule** each refused permission response named, read from the
    /// response body.
    ///
    /// A status alone would not do: a 404 from a mistyped route and a 503 from
    /// a rotation freeze are both "not 202", and neither is the rule firing.
    /// These carry the lifecycle rule's own code.
    pub unoffered_option_rule: String,
    pub unknown_request_id_rule: String,
    /// The wrong-connection case is a **404 with no rule**, deliberately: a
    /// foreign connection is indistinguishable from one that never existed, so
    /// there is no rule to name and the status is the whole answer.
    pub wrong_connection_status: u16,

    // --- cancellation ---
    /// `session/cancel` produced this `stopReason`, read off the wire.
    pub cancel_stop_reason: String,
    /// The outcome the agent recorded receiving for the permission that was
    /// outstanding when the cancellation arrived.
    pub cancel_outcome_at_agent: String,
    /// An update arrived **after** the cancellation and **before** the
    /// original prompt's result, which is `docs/acp.md`'s "Accept remaining
    /// updates until that response".
    pub update_after_cancel_before_result: bool,

    // --- subscriber loss, each required stream broken independently ---
    /// Per broken stream: the five consequences, each observed separately.
    pub session_loss: LossEvidence,
    pub connection_loss: LossEvidence,

    // --- an explicit unknown outcome after a crash ---
    /// How many times the agent's **own on-disk ledger** records the synthetic
    /// side effect, read after the fault.
    ///
    /// Read from the fixture's file rather than from a harness counter: a
    /// counter that increments where the harness believes it dispatched cannot
    /// tell "the effect happened once" from "it happened twice and one attempt
    /// was not recorded", which is the whole question.
    pub side_effects_in_ledger: u64,
    /// The same ledger re-read after a settle window, to show nothing replayed
    /// it.
    pub side_effects_after_settle: u64,
    /// The consumer's stream **errored** rather than ending cleanly or
    /// carrying a result: the turn has no terminal on the wire.
    pub unknown_stream_errored: bool,
    /// The stream **ended cleanly** instead.
    ///
    /// Recorded separately because "not errored" is three different outcomes
    /// wearing one name: a clean end, a stream still open, and a stream that
    /// errored after the gate stopped looking. A run that failed this case
    /// could previously say only "not errored", which is exactly the
    /// distinction the case exists to make.
    pub unknown_stream_ended_cleanly: bool,
    /// Milliseconds from the crashing prompt being accepted to the stream
    /// failing.  0 when it never failed.
    pub unknown_error_latency_ms: u128,
    /// How long the gate waited before giving up on the stream failing.
    pub unknown_error_wait_ms: u128,
    /// Whether the **export** ended the connection when its child died.
    ///
    /// This separates "the device never noticed the crash" from "the device
    /// noticed and the termination did not reach the consumer", which are
    /// different defects in different components, and the earlier evidence
    /// could not tell them apart.
    pub unknown_export_ended_connection: bool,
    /// Live ACP connections the export still held after the crash.
    pub unknown_export_live_connections: u64,
    /// No `stopReason` ever arrived for the crashed turn.
    pub unknown_no_stop_reason: bool,
    /// How many operations the **export** classified through
    /// `tunnel_acp::terminal` during each case, by the outcome that rule gave.
    ///
    /// **Read from the export's own diagnostics, never computed here.** An
    /// earlier version of this gate set a field to
    /// `AcpTerminal::LostAfterDispatch.result_status()` — the gate choosing the
    /// variant and evaluating a pure function, which observes nothing. These
    /// are deltas across the case, so what is asserted is that the export
    /// reached that classification for work that really ran.
    pub export_terminal_succeeded_delta: u64,
    pub export_terminal_cancelled_delta: u64,
    pub export_terminal_unknown_delta: u64,

    // --- the M7-C80 accommodation, made visible in the evidence ---
    pub resign_spacing_ms: u128,
    /// How old the membership records in force were when a case ended.  Every
    /// case must end inside their lifetime.
    pub max_membership_age_at_case_end_ms: u128,
    pub membership_resigns: u64,

    // --- rotation-freeze refusal discipline (M3-15) ---
    pub not_dispatched_refusals: u64,
    pub not_dispatched_retries: u64,
    /// The first refusal that did not coincide with an observed rotation
    /// freeze.  Any value here fails the run **by name**.
    pub unexplained_refusal: Option<String>,

    // --- the device and its child ---
    pub rotations_observed: u64,
    pub device_sessions: u64,
    /// Child processes still alive after the gate tore everything down, read
    /// from the process table.
    pub leftover_processes: usize,
}

/// `docs/acp.md`'s five consequences of an established required SSE stream
/// breaking, each recorded separately.
///
/// They are five fields rather than one boolean because the document names
/// five things and a single "the transport ended" flag would let four of them
/// regress silently.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LossEvidence {
    /// The transport ended, and by the subscriber-loss rule rather than by a
    /// child ending or a deadline.
    pub terminated_by_loss: bool,
    /// Pending permissions resolved `cancelled`.  Never approved.
    pub permissions_cancelled: u64,
    pub permissions_approved: u64,
    /// A prompt after the loss is refused.
    pub new_prompt_refused: bool,
    /// The *other* required stream was closed too, and **errored** rather than
    /// ending cleanly: a broken ACP stream must not look like an orderly one.
    pub other_stream_errored: bool,
    /// The old connection cannot be reattached to, and a fresh `initialize`
    /// works.
    pub reconnect_requires_initialize: bool,
    /// The child is gone from the **process table**, not from a counter.
    pub child_gone_from_process_table: bool,
}

/// A refusal the relay answered that this gate resent, and why it was allowed
/// to.
#[derive(Debug, Default)]
struct RefusalLedger {
    refusals: AtomicU64,
    retries: AtomicU64,
    unexplained: std::sync::Mutex<Option<String>>,
}

/// The connector's rotation phase, sampled from its own status watch.
///
/// A refusal is only resendable if it coincides with a phase **this observed**
/// — never because a refusal looked like one a rotation would produce.
#[derive(Debug, Default)]
struct FreezeWatch {
    frozen: std::sync::atomic::AtomicBool,
    seen_frozen: std::sync::atomic::AtomicBool,
    last_frozen_ms: AtomicU64,
    started: std::sync::Mutex<Option<Instant>>,
    phase: std::sync::Mutex<String>,
    rotations_completed: AtomicU64,
}

impl FreezeWatch {
    fn record(&self, phase: &str, rotations_completed: u64) {
        let mut started = self.started.lock().unwrap_or_else(|e| e.into_inner());
        if started.is_none() {
            *started = Some(Instant::now());
        }
        let origin = started.expect("set above");
        drop(started);
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = phase.to_owned();
        self.rotations_completed
            .store(rotations_completed, Ordering::SeqCst);
        let frozen = FROZEN_PHASES.contains(&phase);
        self.frozen.store(frozen, Ordering::SeqCst);
        if frozen {
            self.seen_frozen.store(true, Ordering::SeqCst);
            self.last_frozen_ms.store(
                u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
        }
    }

    fn coincides(&self) -> bool {
        if self.frozen.load(Ordering::SeqCst) {
            return true;
        }
        if !self.seen_frozen.load(Ordering::SeqCst) {
            return false;
        }
        let started = self.started.lock().unwrap_or_else(|e| e.into_inner());
        let Some(origin) = *started else {
            return false;
        };
        drop(started);
        let now = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        now.saturating_sub(self.last_frozen_ms.load(Ordering::SeqCst))
            <= u64::try_from(FREEZE_COINCIDENCE.as_millis()).unwrap_or(u64::MAX)
    }

    /// The sentence a refusal outside a freeze is reported with.  It names the
    /// connector state, so the failure is diagnosable without a rerun.
    fn unexplained(&self) -> String {
        let phase = self.phase.lock().unwrap_or_else(|e| e.into_inner()).clone();
        format!(
            "not_dispatched refusal outside a rotation freeze: connector phase={phase:?} rotations_completed={}",
            self.rotations_completed.load(Ordering::SeqCst)
        )
    }
}

/// The consumer's HTTP/2 connection to a relay's public listener.
///
/// **HTTP/2, because `acp-http-v1` is an HTTP/2-only profile** (M8-01): an
/// HTTP/1.1 consumer is refused `HTTP_UNSUPPORTED_FEATURE` by the codec before
/// anything is routed. The other `http-forward` gates share an HTTP/1.1
/// consumer helper, which is why this one is here rather than there.
///
/// One connection carries the long-lived GET streams and the POSTs beside
/// them, which is what h2 multiplexing is for and what the profile assumes.
struct AcpConsumer {
    sender: hyper::client::conn::http2::SendRequest<StreamBody<ConsumerStream>>,
    task: tokio::task::JoinHandle<()>,
}

impl AcpConsumer {
    async fn connect(addr: SocketAddr, ca_der: &[u8]) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_der.to_vec()))
            .map_err(|error| HarnessError::Http(format!("consumer CA: {error}")))?;
        let mut config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| HarnessError::Http(format!("consumer TLS: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        // ALPN `h2` only: the profile admits nothing else, so a silent
        // downgrade to HTTP/1.1 must fail the handshake here rather than
        // surface later as a puzzling codec refusal.
        config.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(HarnessError::Io)?;
        let name = ServerName::try_from("localhost".to_owned())
            .map_err(|error| HarnessError::Http(format!("server name: {error}")))?;
        let tls = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|error| HarnessError::Http(format!("consumer TLS handshake: {error}")))?;
        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(|error| HarnessError::Http(format!("consumer h2 handshake: {error}")))?;
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { sender, task })
    }

    fn shutdown(self) {
        self.task.abort();
    }
}

/// One ACP exchange's request, built for the public route.
fn acp_request(
    method: &str,
    uri: &str,
    token: &str,
    extra: &[(&str, &str)],
    body: StreamBody<ConsumerStream>,
) -> Result<http::Request<StreamBody<ConsumerStream>>> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .version(http::Version::HTTP_2)
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder
        .body(body)
        .map_err(|error| HarnessError::Http(format!("building an ACP request: {error}")))
}

fn json_stream(value: &Value) -> StreamBody<ConsumerStream> {
    let bytes = Bytes::from(serde_json::to_vec(value).unwrap_or_default());
    StreamBody::new(Box::pin(futures_util::stream::once(async move {
        Ok(Frame::data(bytes))
    })))
}

/// A subscribed SSE stream, drained in the background for the life of the
/// case.
///
/// **Holding it open is load-bearing**, and not only because the consumer
/// wants the messages: under `docs/acp.md`'s subscriber-loss policy an
/// established required stream whose body is dropped terminates the whole ACP
/// transport. A reader that took one message and let the response go would
/// destroy the connection it was reading.
struct HeldStream {
    payloads: Arc<std::sync::Mutex<Vec<Value>>>,
    errored: Arc<std::sync::atomic::AtomicBool>,
    ended: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl HeldStream {
    fn hold(response: http::Response<hyper::body::Incoming>) -> Self {
        let payloads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let errored = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = Arc::clone(&payloads);
        let failed = Arc::clone(&errored);
        let done = Arc::clone(&ended);
        let task = tokio::spawn(async move {
            let mut body = std::pin::pin!(response.into_body());
            let mut buffer: Vec<u8> = Vec::new();
            let mut taken = 0usize;
            while let Some(frame) = body.frame().await {
                match frame {
                    Ok(frame) => {
                        if let Ok(data) = frame.into_data() {
                            buffer.extend_from_slice(&data);
                        }
                    }
                    Err(_) => {
                        // A broken ACP stream errors its body; an orderly one
                        // ends.  The two must not be confused.
                        failed.store(true, Ordering::SeqCst);
                        return;
                    }
                }
                let all = sse_payloads(&buffer);
                if all.len() > taken {
                    let mut guard = sink.lock().unwrap_or_else(|e| e.into_inner());
                    for payload in &all[taken..] {
                        if let Ok(value) = serde_json::from_slice::<Value>(payload) {
                            guard.push(value);
                        }
                    }
                    taken = all.len();
                }
            }
            done.store(true, Ordering::SeqCst);
        });
        Self {
            payloads,
            errored,
            ended,
            task,
        }
    }

    fn seen(&self) -> Vec<Value> {
        self.payloads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Wait for a message this stream carried that `pick` accepts.
    ///
    /// Bounded: a stream that never carries it is a failure with a name, not a
    /// hang.
    async fn wait_for<T>(&self, what: &str, pick: impl Fn(&Value) -> Option<T>) -> Result<T> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            for value in self.seen() {
                if let Some(found) = pick(&value) {
                    return Ok(found);
                }
            }
            if self.errored.load(Ordering::SeqCst) {
                return Err(HarnessError::Process(format!(
                    "the stream errored before {what} arrived"
                )));
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "{what} never arrived on the stream"
                )));
            }
            sleep(Duration::from_millis(25)).await;
        }
    }

    /// Break this established stream the way a consumer going away breaks it.
    fn break_now(&self) {
        self.task.abort();
    }

    fn has_errored(&self) -> bool {
        self.errored.load(Ordering::SeqCst)
    }

    fn has_ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}

/// Split an SSE byte buffer into its `data:` payloads.
///
/// The encoding is this profile's own and is asserted byte for byte in
/// `tunnel-acp-export`; this is only the reader.
fn sse_payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let Some(stripped) = rest.strip_prefix(b"data: ") else {
            break;
        };
        let Some(end) = stripped
            .windows(2)
            .position(|window| window == b"\n\n")
            .or_else(|| stripped.iter().position(|byte| *byte == b'\n'))
        else {
            break;
        };
        payloads.push(stripped[..end].to_vec());
        rest = &stripped[(end + 2).min(stripped.len())..];
    }
    payloads
}

/// The lifecycle rule a refusal named, read from the response body.
///
/// `LifecycleRejection` displays as `<RULE_CODE>: <detail>`, and
/// `supervisor_refusal` puts that in `error.message`, so the rule really is on
/// the wire.  An answer that was accepted, or one carrying no rule, yields an
/// empty string rather than a guess — the validator then names it.
fn refusal_rule(status: http::StatusCode, body: &str) -> String {
    if status == http::StatusCode::ACCEPTED {
        return String::new();
    }
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .and_then(|message| message.split(':').next())
                .map(str::trim)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default()
}

fn stop_reason(value: &Value) -> Option<String> {
    value
        .pointer("/result/stopReason")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn session_id(value: &Value) -> Option<String> {
    value
        .pointer("/result/sessionId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// Whether a process is in the process table and not a reaped corpse.
///
/// `kill -0` alone succeeds on a zombie, so a cleanup claim resting on it
/// would stay green for the wrong reason.
fn process_alive(pid: u32) -> bool {
    let Ok(output) = std::process::Command::new("ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output()
    else {
        return false;
    };
    let state = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    !state.is_empty() && !state.starts_with('Z')
}

/// The device runtime configuration: the harness device profile plus one
/// `[exports.<service>.acp]` table, parsed and validated by `tunnel-client`
/// exactly as `tunnel-client connect` loads it.
fn device_config_text(base: &str, service: &str, fixture: &Path, workspace: &Path) -> String {
    let quote = |value: &str| serde_json::to_string(value).unwrap_or_default();
    format!(
        "{base}\n[exports.\"{service}\"]\ntype = \"http-forward\"\n\n[exports.\"{service}\".acp]\nprofile = \"acp-http-v1\"\n\n[exports.\"{service}\".acp.agent]\ncommand = {}\nargs = [\"agent\"]\nworkspace = {}\n",
        quote(&fixture.to_string_lossy()),
        quote(&workspace.to_string_lossy()),
    )
}

/// Where the ACP fixture binary is.
fn fixture_binary_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("TUNNEL_ACP_FIXTURE_BIN") {
        return Ok(PathBuf::from(path));
    }
    let exe = std::env::current_exe().map_err(HarnessError::Io)?;
    let directory = exe
        .parent()
        .ok_or_else(|| HarnessError::InvalidInput("the harness has no directory".into()))?;
    let candidate = directory.join("tunnel-acp-fixture");
    if candidate.exists() {
        return Ok(candidate);
    }
    let sibling = directory
        .parent()
        .map(|parent| parent.join("tunnel-acp-fixture"));
    match sibling {
        Some(path) if path.exists() => Ok(path),
        _ => Err(HarnessError::InvalidInput(
            "the tunnel-acp-fixture binary was not found; set TUNNEL_ACP_FIXTURE_BIN".into(),
        )),
    }
}

/// The gate's live state: the cluster, the device session, the consumer and
/// the accommodation's clock.
struct Gate<'h> {
    cluster: &'h mut ProductionCluster,
    tenant_id: uuid::Uuid,
    device_id: uuid::Uuid,
    service_id: uuid::Uuid,
    config: tunnel_client::ConnectConfig,
    client: Option<ConnectionHandle>,
    session_id: String,
    acp_diagnostics: AcpExportDiagnostics,
    freeze: Arc<FreezeWatch>,
    freeze_task: Option<tokio::task::JoinHandle<()>>,
    ledger: Arc<RefusalLedger>,
    /// When membership was last re-signed.  The M7-C80 accommodation's clock,
    /// and the only one.
    membership_signed_at: Instant,
    membership_resigns: u64,
    ingress_addr: SocketAddr,
    ca: Vec<u8>,
    token: String,
    base_uri: String,
    workspace: PathBuf,
}

impl Gate<'_> {
    fn export(&self) -> tunnel_acp_export::AcpDiagnostics {
        self.acp_diagnostics
            .get(&self.service_id.to_string())
            .unwrap_or_default()
    }

    /// Start a `tunnel-client` session with the ACP export registered exactly
    /// as `tunnel-client connect` registers it, and wait for its owner claim.
    async fn connect_device(&mut self) -> Result<String> {
        let handlers = HttpHandlers::new()
            .with_acp_exports(&self.config)
            .map_err(|error| HarnessError::InvalidInput(format!("ACP exports: {error}")))?;
        self.acp_diagnostics = handlers.acp_diagnostics_source();
        let client = timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect_with_http_handlers(
                ConnectOptions::new(self.config.clone()),
                handlers,
            ),
        )
        .await
        .map_err(|_| HarnessError::Timeout("ACP gate device startup timed out".into()))?
        .map_err(|error| HarnessError::Process(format!("ACP gate device: {error}")))?;
        let client = self.client.insert(client);
        // Watch this session's rotation phase.  A refusal may only be resent
        // if it coincides with a phase observed here.
        self.freeze = Arc::new(FreezeWatch::default());
        let freeze = Arc::clone(&self.freeze);
        let mut status = client.status();
        {
            let status = status.borrow_and_update();
            freeze.record(&status.phase, status.rotations_completed);
        }
        self.freeze_task = Some(tokio::spawn(async move {
            while status.changed().await.is_ok() {
                let (phase, rotations) = {
                    let status = status.borrow_and_update();
                    (status.phase.clone(), status.rotations_completed)
                };
                freeze.record(&phase, rotations);
            }
        }));
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("ACP gate device readiness timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        self.session_id = session.session_id.clone();
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            let owner = self
                .cluster
                .catalog
                .current_owner(self.tenant_id, self.device_id, chrono::Utc::now())
                .await
                .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?;
            if let Some(owner) = owner
                && owner.token.session_id == self.session_id
            {
                return Ok(owner.token.node_id);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the device owner claim was not observed".into(),
                ));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// POST one ACP message, resending **only** a `not_dispatched` refusal
    /// that coincides with an observed rotation freeze (M3-15).
    ///
    /// Every refusal is counted.  The first one that does not coincide is
    /// recorded and fails the run by name; it is never retried and never
    /// folded into a pass.
    async fn post(
        &self,
        consumer: &AcpConsumer,
        extra: &[(&str, &str)],
        message: &Value,
    ) -> Result<(http::StatusCode, http::HeaderMap, String)> {
        let mut retries = 0u64;
        loop {
            let request = acp_request(
                "POST",
                &self.base_uri,
                &self.token,
                &[
                    &[
                        ("content-type", "application/json"),
                        ("accept", "application/json"),
                    ][..],
                    extra,
                ]
                .concat(),
                json_stream(message),
            )?;
            let response = consumer
                .sender
                .clone()
                .send_request(request)
                .await
                .map_err(|error| HarnessError::Http(format!("ACP POST: {error}")))?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .into_body()
                .collect()
                .await
                .map(|collected| String::from_utf8_lossy(&collected.to_bytes()).into_owned())
                .unwrap_or_default();
            if status == http::StatusCode::SERVICE_UNAVAILABLE && body.contains("not_dispatched") {
                let coincides = self.freeze.coincides();
                self.ledger.refusals.fetch_add(1, Ordering::SeqCst);
                if coincides {
                    self.ledger.retries.fetch_add(1, Ordering::SeqCst);
                } else {
                    let mut slot = self
                        .ledger
                        .unexplained
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if slot.is_none() {
                        *slot = Some(self.freeze.unexplained());
                    }
                }
                if coincides && retries < NOT_DISPATCHED_RETRIES {
                    retries += 1;
                    sleep(Duration::from_millis(MIN_RETRY_HINT_MS)).await;
                    continue;
                }
            }
            return Ok((status, headers, body));
        }
    }

    /// Open an SSE stream and hold it.
    async fn open_stream(
        &self,
        consumer: &AcpConsumer,
        extra: &[(&str, &str)],
    ) -> Result<(http::StatusCode, http::HeaderMap, Option<HeldStream>)> {
        let request = acp_request(
            "GET",
            &self.base_uri,
            &self.token,
            &[&[("accept", "text/event-stream")][..], extra].concat(),
            empty_stream(),
        )?;
        let response = consumer
            .sender
            .clone()
            .send_request(request)
            .await
            .map_err(|error| HarnessError::Http(format!("ACP GET: {error}")))?;
        let status = response.status();
        let headers = response.headers().clone();
        if status != http::StatusCode::OK {
            return Ok((status, headers, None));
        }
        Ok((status, headers, Some(HeldStream::hold(response))))
    }

    /// The case boundary, and the **only** place membership is re-signed.
    ///
    /// The M7-C80 accommodation lives here and nowhere else: see the module
    /// comment for why it exists and what it costs this gate's claims.  It
    /// never runs while a stream is in flight, because the caller has closed
    /// its connection before reaching it.
    async fn boundary(&mut self) -> Result<()> {
        if self.membership_signed_at.elapsed() < MEMBERSHIP_RESIGN_SPACING {
            return Ok(());
        }
        self.cluster.resign_membership_now().await?;
        self.membership_signed_at = Instant::now();
        self.membership_resigns += 1;
        self.wait_peers_ready().await?;
        Ok(())
    }

    async fn wait_peers_ready(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(45);
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
                    "peer readiness did not return after a membership re-sign".into(),
                ));
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
}

/// One ACP connection over the real route: initialize, the connection GET, a
/// session, and its session GET.
struct Conversation {
    consumer: AcpConsumer,
    connection: String,
    connection_stream: HeldStream,
    session: String,
    session_stream: HeldStream,
}

impl Gate<'_> {
    /// Open a connection and a session over the real route.
    ///
    /// Every identifier is read from where the profile puts it: the connection
    /// id from the `initialize` **response header**, the session id from the
    /// `session/new` result **on the connection GET** — not from the 202 that
    /// accepted the POST, which `docs/acp.md` says means only that the bridge
    /// accepted it.
    async fn open_conversation(&self, evidence: &mut AcpRealPathEvidence) -> Result<Conversation> {
        let consumer = AcpConsumer::connect(self.ingress_addr, &self.ca).await?;
        let (status, headers, _body) = self
            .post(
                &consumer,
                &[],
                &json!({
                    "jsonrpc": "2.0",
                    "id": "init-1",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": 1,
                        "clientCapabilities": {},
                        "clientInfo": {"name": "tunnel-acp-gate", "version": "0.1.0"},
                    },
                }),
            )
            .await?;
        if status != http::StatusCode::OK {
            return Err(HarnessError::Http(format!(
                "initialize over the real route answered {status}"
            )));
        }
        let connection = headers
            .get(tunnel_acp::headers::ACP_CONNECTION_ID)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                HarnessError::Http("initialize returned no Acp-Connection-Id".to_owned())
            })?;
        evidence.connection_opened = true;

        let (status, _headers, stream) = self
            .open_stream(&consumer, &[("acp-connection-id", connection.as_str())])
            .await?;
        let connection_stream = stream
            .ok_or_else(|| HarnessError::Http(format!("the connection GET answered {status}")))?;

        let (status, _headers, _body) = self
            .post(
                &consumer,
                &[("acp-connection-id", connection.as_str())],
                &json!({
                    "jsonrpc": "2.0",
                    "id": "new-1",
                    "method": "session/new",
                    "params": {
                        "cwd": self.workspace.to_string_lossy(),
                        "mcpServers": [],
                    },
                }),
            )
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "session/new answered {status}, not 202"
            )));
        }
        // The session identifier comes off the **connection stream**, which is
        // where the RFD puts it, not from the status above.
        let session = connection_stream
            .wait_for("the session/new result", session_id)
            .await?;
        evidence.session_id_from_connection_stream = true;

        let (status, headers, stream) = self
            .open_stream(
                &consumer,
                &[
                    ("acp-connection-id", connection.as_str()),
                    ("acp-session-id", session.as_str()),
                ],
            )
            .await?;
        let session_stream = stream
            .ok_or_else(|| HarnessError::Http(format!("the session GET answered {status}")))?;
        // M8-C05: this profile puts no session header on a response, and the
        // decision is re-observed here over the real route rather than only in
        // the in-process bridge.
        if headers.contains_key(tunnel_acp::headers::ACP_SESSION_ID) {
            return Err(HarnessError::Http(
                "a session-scoped SSE response carried Acp-Session-Id (M8-C05)".to_owned(),
            ));
        }

        Ok(Conversation {
            consumer,
            connection,
            connection_stream,
            session,
            session_stream,
        })
    }

    fn connection_headers<'a>(&self, conversation: &'a Conversation) -> [(&'a str, &'a str); 1] {
        [("acp-connection-id", conversation.connection.as_str())]
    }

    fn session_headers<'a>(&self, conversation: &'a Conversation) -> [(&'a str, &'a str); 2] {
        [
            ("acp-connection-id", conversation.connection.as_str()),
            ("acp-session-id", conversation.session.as_str()),
        ]
    }

    /// POST a prompt and return the status; the result is read off the wire by
    /// the caller.
    async fn prompt(
        &self,
        conversation: &Conversation,
        id: &str,
        text: &str,
    ) -> Result<http::StatusCode> {
        let headers = self.session_headers(conversation);
        let (status, _headers, _body) = self
            .post(
                &conversation.consumer,
                &headers,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "session/prompt",
                    "params": {
                        "sessionId": conversation.session,
                        "prompt": [{"type": "text", "text": text}],
                    },
                }),
            )
            .await?;
        Ok(status)
    }

    /// Case `conversation`: a whole v1 turn over the real three-relay route.
    async fn case_conversation(&mut self, evidence: &mut AcpRealPathEvidence) -> Result<()> {
        let before = self.export();
        let conversation = self.open_conversation(evidence).await?;
        let status = self.prompt(&conversation, "prompt-1", "ok").await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "session/prompt answered {status}, not 202"
            )));
        }
        evidence.prompt_accepted_202 = true;
        // The turn's own result, read from the message the consumer received.
        evidence.conversation_stop_reason = conversation
            .session_stream
            .wait_for("the prompt result", stop_reason)
            .await?;
        // What the **export** made of that turn, through the terminal rule.
        evidence.export_terminal_succeeded_delta =
            self.export().terminals_succeeded - before.terminals_succeeded;
        self.close_conversation(conversation).await;
        Ok(())
    }

    /// Case `permission-allow` / `permission-reject`: a permission callback
    /// over the real route, answered with an offered option.
    ///
    /// The outcome is read from the marker the **agent itself** wrote, so what
    /// is proven is what the agent received rather than what the bridge
    /// believes it forwarded.
    async fn case_permission(
        &mut self,
        evidence: &mut AcpRealPathEvidence,
        allow: bool,
    ) -> Result<()> {
        let marker = self
            .workspace
            .join(tunnel_acp_fixture::PERMISSION_OUTCOME_FILE);
        let _ = std::fs::remove_file(&marker);

        let conversation = self.open_conversation(evidence).await?;
        let status = self
            .prompt(&conversation, "prompt-permission", "permission")
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "the permission prompt answered {status}, not 202"
            )));
        }
        // The callback is observed **on the wire**.
        let callback = conversation
            .session_stream
            .wait_for("the permission callback", |value| {
                (value.get("method").and_then(Value::as_str) == Some("session/request_permission"))
                    .then(|| value.clone())
            })
            .await?;
        evidence.permission_requested_on_wire = true;
        let request_id = callback
            .get("id")
            .cloned()
            .ok_or_else(|| HarnessError::Http("the permission callback carried no id".into()))?;
        let offered: Vec<String> = callback
            .pointer("/params/options")
            .and_then(Value::as_array)
            .map(|options| {
                options
                    .iter()
                    .filter_map(|option| {
                        option
                            .get("optionId")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    })
                    .collect()
            })
            .unwrap_or_default();
        evidence.offered_options = offered.clone();

        let chosen = if allow {
            tunnel_acp_fixture::PERMIT_OPTION
        } else {
            tunnel_acp_fixture::REJECT_OPTION
        };
        if !offered.iter().any(|option| option == chosen) {
            return Err(HarnessError::Process(format!(
                "the agent never offered {chosen}; it offered {offered:?}"
            )));
        }

        // Only on the allow pass, and only once: the three refusals below are
        // about *this* outstanding callback, so they must run while it is
        // still outstanding.
        if allow {
            self.check_permission_refusals(&conversation, &request_id, evidence)
                .await?;
        }

        let headers = self.session_headers(&conversation);
        let (status, _headers, _body) = self
            .post(
                &conversation.consumer,
                &headers,
                &json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"outcome": {"outcome": "selected", "optionId": chosen}},
                }),
            )
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "the permission response answered {status}, not 202"
            )));
        }

        let stop = conversation
            .session_stream
            .wait_for("the permission turn result", stop_reason)
            .await?;

        // What the **agent** recorded receiving, from its own marker file.
        let deadline = Instant::now() + Duration::from_secs(20);
        let recorded = loop {
            if let Ok(text) = std::fs::read_to_string(&marker) {
                let text = text.trim().to_owned();
                if !text.is_empty() {
                    break text;
                }
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the agent never recorded the permission outcome it received".into(),
                ));
            }
            sleep(Duration::from_millis(50)).await;
        };

        if allow {
            evidence.allow_stop_reason = stop;
            evidence.allow_outcome_at_agent = recorded;
        } else {
            evidence.reject_stop_reason = stop;
            evidence.reject_outcome_at_agent = recorded;
        }
        self.close_conversation(conversation).await;
        Ok(())
    }

    /// Three permission responses that must each be refused, while a real
    /// callback is outstanding.
    ///
    /// Each is checked while the genuine callback is still pending, and the
    /// genuine response succeeds afterwards — so a refusal cannot be passing
    /// because the callback had already gone.
    async fn check_permission_refusals(
        &self,
        conversation: &Conversation,
        request_id: &Value,
        evidence: &mut AcpRealPathEvidence,
    ) -> Result<()> {
        let headers = self.session_headers(conversation);

        // An option the agent never offered.
        let (status, _h, body) = self
            .post(
                &conversation.consumer,
                &headers,
                &json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"outcome": {"outcome": "selected", "optionId": "not-offered"}},
                }),
            )
            .await?;
        evidence.unoffered_option_rule = refusal_rule(status, &body);

        // An id that answers nothing outstanding.
        let (status, _h, body) = self
            .post(
                &conversation.consumer,
                &headers,
                &json!({
                    "jsonrpc": "2.0",
                    "id": "no-such-request",
                    "result": {"outcome": {"outcome": "selected", "optionId": tunnel_acp_fixture::PERMIT_OPTION}},
                }),
            )
            .await?;
        evidence.unknown_request_id_rule = refusal_rule(status, &body);

        // The right answer on the wrong connection: a second connection, whose
        // callback table has never heard of this id.
        let other = self
            .open_conversation(&mut AcpRealPathEvidence::default())
            .await?;
        let other_headers = self.session_headers(&other);
        let (status, _h, _b) = self
            .post(
                &other.consumer,
                &other_headers,
                &json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"outcome": {"outcome": "selected", "optionId": tunnel_acp_fixture::PERMIT_OPTION}},
                }),
            )
            .await?;
        evidence.wrong_connection_status = status.as_u16();
        self.close_conversation(other).await;
        Ok(())
    }

    /// End a conversation the way a well-behaved consumer does: DELETE, then
    /// let its streams go.
    async fn close_conversation(&self, conversation: Conversation) {
        let headers = self.connection_headers(&conversation);
        if let Ok(request) = acp_request(
            "DELETE",
            &self.base_uri,
            &self.token,
            &headers,
            empty_stream(),
        ) {
            let _ = conversation
                .consumer
                .sender
                .clone()
                .send_request(request)
                .await;
        }
        conversation.connection_stream.break_now();
        conversation.session_stream.break_now();
        conversation.consumer.shutdown();
    }
}

impl Gate<'_> {
    /// Case `cancel`: `session/cancel` over the real route.
    ///
    /// `docs/acp.md`: "The bridge resolves pending permission callbacks with
    /// `{"outcome":{"outcome":"cancelled"}}`, forwards cancellation, and waits
    /// for the original prompt response. Accept remaining updates until that
    /// response. A confirmed cancelled turn has `stopReason: "cancelled"`."
    ///
    /// All four halves are checked: the permission resolves cancelled at the
    /// **agent**, an update arrives after the cancellation and before the
    /// result, and the turn's own result says `cancelled`.
    async fn case_cancel(&mut self, evidence: &mut AcpRealPathEvidence) -> Result<()> {
        let marker = self
            .workspace
            .join(tunnel_acp_fixture::PERMISSION_OUTCOME_FILE);
        let _ = std::fs::remove_file(&marker);

        let before = self.export();
        let conversation = self.open_conversation(evidence).await?;
        let status = self
            .prompt(&conversation, "prompt-cancel", "permission")
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "the cancelled prompt answered {status}, not 202"
            )));
        }
        // Wait for the callback, so the cancellation really has something
        // outstanding to resolve.
        conversation
            .session_stream
            .wait_for("the permission callback", |value| {
                (value.get("method").and_then(Value::as_str) == Some("session/request_permission"))
                    .then_some(())
            })
            .await?;
        let seen_before_cancel = conversation.session_stream.seen().len();

        let headers = self.session_headers(&conversation);
        let (status, _h, _b) = self
            .post(
                &conversation.consumer,
                &headers,
                &json!({
                    "jsonrpc": "2.0",
                    "method": "session/cancel",
                    "params": {"sessionId": conversation.session},
                }),
            )
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "session/cancel answered {status}, not 202"
            )));
        }

        // The turn's own result, off the wire.
        evidence.cancel_stop_reason = conversation
            .session_stream
            .wait_for("the cancelled turn's result", stop_reason)
            .await?;

        // **Updates are accepted until that response.** The fixture reports
        // the outcome it received as an update before it finishes, so an
        // update landing after the cancellation and before the result is the
        // observation `docs/acp.md` asks for.  Position in the recorded stream
        // is what makes it "after": the messages are appended in arrival
        // order.
        let seen = conversation.session_stream.seen();
        let result_at = seen.iter().position(|value| stop_reason(value).is_some());
        evidence.update_after_cancel_before_result = result_at.is_some_and(|result_at| {
            seen.iter().enumerate().any(|(index, value)| {
                index >= seen_before_cancel
                    && index < result_at
                    && value.get("method").and_then(Value::as_str) == Some("session/update")
            })
        });

        let deadline = Instant::now() + Duration::from_secs(20);
        evidence.cancel_outcome_at_agent = loop {
            if let Ok(text) = std::fs::read_to_string(&marker) {
                let text = text.trim().to_owned();
                if !text.is_empty() {
                    break text;
                }
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the agent never recorded the cancelled permission".into(),
                ));
            }
            sleep(Duration::from_millis(50)).await;
        };
        // The export classified the cancelled turn through the same rule.
        evidence.export_terminal_cancelled_delta =
            self.export().terminals_cancelled - before.terminals_cancelled;
        self.close_conversation(conversation).await;
        Ok(())
    }

    /// Cases `sse-loss-session` and `sse-loss-connection`: break one
    /// **established required** SSE stream over the real route and observe the
    /// whole ACP connection terminate.
    ///
    /// Each required stream is broken independently, because
    /// `docs/acp.md` names "an established required SSE stream" without
    /// distinguishing them and this profile has two kinds.  `docs/acp.md`
    /// names five consequences and each is asserted separately in
    /// [`LossEvidence`].
    ///
    /// **An SDK reopening a GET would not be evidence that anything was
    /// recovered**, which is why the reconnect check requires the *old*
    /// connection to be gone rather than a new GET to succeed.
    async fn case_sse_loss(
        &mut self,
        evidence: &mut AcpRealPathEvidence,
        break_session_stream: bool,
    ) -> Result<()> {
        let conversation = self.open_conversation(evidence).await?;
        let before = self.export();

        // The child exists, read from the process table, **before** the break.
        let pids = self
            .acp_diagnostics
            .child_pids(&self.service_id.to_string());
        let child = pids
            .iter()
            .copied()
            .find(|pid| process_alive(*pid))
            .ok_or_else(|| HarnessError::Process("no live agent child to observe".into()))?;

        // Leave a permission outstanding, so the loss has one to cancel.
        let status = self
            .prompt(&conversation, "prompt-loss", "permission")
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "the prompt answered {status}, not 202"
            )));
        }
        conversation
            .session_stream
            .wait_for("the permission callback", |value| {
                (value.get("method").and_then(Value::as_str) == Some("session/request_permission"))
                    .then_some(())
            })
            .await?;

        let mut loss = LossEvidence::default();
        if break_session_stream {
            conversation.session_stream.break_now();
        } else {
            conversation.connection_stream.break_now();
        }

        // (1) the transport terminated, by the subscriber-loss rule.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let now = self.export();
            if now.connections_ended_by_subscriber_loss
                > before.connections_ended_by_subscriber_loss
            {
                loss.terminated_by_loss =
                    now.connections_ended_by_child == before.connections_ended_by_child;
                // (2) pending permissions cancelled, never approved.
                loss.permissions_cancelled =
                    now.permissions_cancelled_by_loss - before.permissions_cancelled_by_loss;
                loss.permissions_approved = now.permissions_answered - before.permissions_answered;
                break;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "breaking an established required stream did not terminate the transport"
                        .into(),
                ));
            }
            sleep(Duration::from_millis(50)).await;
        }

        // (3) new prompts are refused.
        let status = self
            .prompt(&conversation, "prompt-after-loss", "ok")
            .await?;
        loss.new_prompt_refused = status == http::StatusCode::NOT_FOUND;

        // (4) the other required stream closed, and errored rather than
        // ending cleanly.
        let other = if break_session_stream {
            &conversation.connection_stream
        } else {
            &conversation.session_stream
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if other.has_errored() {
                loss.other_stream_errored = true;
                break;
            }
            if other.has_ended() || Instant::now() >= deadline {
                // An orderly end is a failure here, and is recorded as such
                // rather than as a pass.
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }

        // (5) a reconnect must initialize anew: the old connection is gone,
        // and a fresh initialize opens a different one.
        let (status, _h, stream) = self
            .open_stream(
                &conversation.consumer,
                &self.connection_headers(&conversation),
            )
            .await?;
        let old_gone = status == http::StatusCode::NOT_FOUND;
        if let Some(stream) = stream {
            stream.break_now();
        }
        let fresh = self
            .open_conversation(&mut AcpRealPathEvidence::default())
            .await?;
        loss.reconnect_requires_initialize =
            old_gone && fresh.connection != conversation.connection;

        // (6) the child is gone from the process table.
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if !process_alive(child) {
                loss.child_gone_from_process_table = true;
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }

        if break_session_stream {
            evidence.session_loss = loss;
        } else {
            evidence.connection_loss = loss;
        }
        self.close_conversation(fresh).await;
        conversation.consumer.shutdown();
        Ok(())
    }
}

impl Gate<'_> {
    /// Case `outcome-unknown`: a child crash **after** an instrumented
    /// synthetic side effect.
    ///
    /// `docs/acp.md`: "a reset connection or lost process marks dispatched
    /// unresolved work `outcome_unknown`", and "never automatically replay its
    /// input into a replacement child".
    ///
    /// The side effect is counted from the **fixture's own append-only ledger
    /// on disk**, written and `fsync`ed by the agent process at the moment the
    /// effect happens and read back after the fault. A harness counter that
    /// incremented where the harness *thought* it dispatched would not be able
    /// to distinguish one effect from two with one unrecorded attempt.
    ///
    /// **The no-replay claim is bounded at the moment of observation**, the
    /// same way `docs/http-forwarding.md` gate 4 bounds its own: the ledger is
    /// read when the consumer's stream has failed and again after a settle
    /// window, and a replay issued after that would not be observed. That
    /// limit is in [`NOT_COVERED`].
    async fn case_outcome_unknown(&mut self, evidence: &mut AcpRealPathEvidence) -> Result<()> {
        let ledger = self.workspace.join(tunnel_acp_fixture::SIDE_EFFECT_LEDGER);
        let _ = std::fs::remove_file(&ledger);
        let effect = "acp-gate-effect";

        let before = self.export();
        let conversation = self.open_conversation(evidence).await?;
        let status = self
            .prompt(
                &conversation,
                "prompt-crash",
                &format!("effect-crash:{effect}"),
            )
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "the crashing prompt answered {status}, not 202"
            )));
        }

        // The child dies after recording the effect, so its transport ends and
        // the consumer's stream fails.  Nothing answers the prompt.
        let waited = Instant::now();
        // **70 s, and the number comes from the product rather than from what
        // made a run green.** The consumer-visible end of this exchange is
        // bimodal: normally ~52 ms, and otherwise ~58.7 s, which is the
        // forwarding layer's own 60 s record / FIN-after-END budget expiring
        // instead of the RESET arriving. An earlier version waited 30 s, which
        // is simply below that fallback, so it recorded "never terminated" for
        // an exchange that terminates at 58.7 s. The slow path is a defect
        // (M8-C14) and is recorded by `unknown_error_latency_ms` rather than
        // tolerated silently.
        let bound = Duration::from_secs(70);
        let deadline = waited + bound;
        loop {
            if conversation.session_stream.has_errored() {
                evidence.unknown_stream_errored = true;
                evidence.unknown_error_latency_ms = waited.elapsed().as_millis();
                break;
            }
            // A clean end is **not** the same failure as a stream that stayed
            // open, and the evidence has to be able to say which.
            if conversation.session_stream.has_ended() {
                evidence.unknown_stream_ended_cleanly = true;
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        evidence.unknown_error_wait_ms = bound.as_millis();
        let after = self.export();
        evidence.unknown_export_ended_connection =
            after.connections_ended_by_child > before.connections_ended_by_child;
        evidence.unknown_export_live_connections = after.live_connections;
        evidence.unknown_no_stop_reason = conversation
            .session_stream
            .seen()
            .iter()
            .all(|value| stop_reason(value).is_none());

        evidence.side_effects_in_ledger = count_effect(&ledger, effect);
        // A settle window, then read again: nothing re-ran it.
        sleep(Duration::from_secs(2)).await;
        evidence.side_effects_after_settle = count_effect(&ledger, effect);

        // **What the export decided**, not what this gate can compute. The
        // dispatched prompt never resolved, so the export classifies it
        // `outcome_unknown` through `tunnel_acp::terminal` and counts it there.
        evidence.export_terminal_unknown_delta =
            self.export().terminals_unknown - before.terminals_unknown;

        conversation.connection_stream.break_now();
        conversation.session_stream.break_now();
        conversation.consumer.shutdown();
        Ok(())
    }
}

/// How many times the ledger records exactly this effect name.
fn count_effect(ledger: &Path, effect: &str) -> u64 {
    std::fs::read_to_string(ledger)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.trim() == effect)
        .count() as u64
}

/// Run every case in order, with the M7-C80 accommodation between them.
async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    workspace: PathBuf,
) -> Result<AcpRealPathEvidence> {
    let mut evidence = AcpRealPathEvidence {
        relay_count: cluster.relays.len(),
        resign_spacing_ms: MEMBERSHIP_RESIGN_SPACING.as_millis(),
        ..AcpRealPathEvidence::default()
    };
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("the ACP gate device is missing".into()))?;
    let echo_service = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("the echo service is missing".into()))?;
    let acp_service = harness
        .acp_services
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("the ACP service was not seeded".into()))?
        .service_id;

    // The device attaches to relay-a, which becomes the owner.
    let owner_device_addr = cluster
        .relay("relay-a")?
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| HarnessError::Process("relay-a is not running".into()))?;
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let device_profile = crate::acceptance::helpers::write_device_profile(
        profile_directory.path(),
        device.id,
        echo_service,
        "m8-acp-canary",
        owner_device_addr,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let base = std::fs::read_to_string(&device_profile.config_path).map_err(HarnessError::Io)?;
    let fixture = fixture_binary_path()?;
    let text = device_config_text(&base, &acp_service.to_string(), &fixture, &workspace);
    let mut config = tunnel_client::ConnectConfig::parse(&text)
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;
    config.rotation = ACP_GATE_ROTATION;
    config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;

    let ingress = cluster.relay("relay-c")?;
    evidence.ingress_node = ingress.node_id.clone();
    let ingress_addr = ingress.consumer_addr()?;
    let ca = harness.pki.server_ca.certificate_der.clone();
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        crate::OidcTokenOptions {
            scope: Some("echo:invoke http:invoke".to_owned()),
            ..crate::OidcTokenOptions::default()
        },
    )?;
    let base_uri = format!(
        "https://localhost:{}/v1/devices/{}/services/{acp_service}/http/acp",
        ingress_addr.port(),
        device.id
    );

    let mut gate = Gate {
        cluster,
        tenant_id: device.tenant_id,
        device_id: device.id,
        service_id: acp_service,
        config,
        client: None,
        session_id: String::new(),
        acp_diagnostics: AcpExportDiagnostics::default(),
        freeze: Arc::new(FreezeWatch::default()),
        freeze_task: None,
        ledger: Arc::new(RefusalLedger::default()),
        // Pre-aged so the first case boundary re-signs: the bootstrap records
        // were signed when the cluster started.
        membership_signed_at: Instant::now()
            .checked_sub(MEMBERSHIP_RESIGN_SPACING)
            .unwrap_or_else(Instant::now),
        membership_resigns: 0,
        ingress_addr,
        ca,
        token,
        base_uri,
        workspace: workspace.clone(),
    };

    let owner_node = gate.connect_device().await?;
    evidence.owner_node = owner_node.clone();
    evidence.non_owner_ingress = owner_node == "relay-a" && evidence.ingress_node == "relay-c";

    let outcome = async {
        for case in ACP_CASES {
            gate.boundary().await?;
            let started = Instant::now();
            eprintln!("ACP real-path gate: {case}");
            match case {
                "conversation" => gate.case_conversation(&mut evidence).await?,
                "permission-allow" => gate.case_permission(&mut evidence, true).await?,
                "permission-reject" => gate.case_permission(&mut evidence, false).await?,
                "cancel" => gate.case_cancel(&mut evidence).await?,
                "sse-loss-session" => gate.case_sse_loss(&mut evidence, true).await?,
                "sse-loss-connection" => gate.case_sse_loss(&mut evidence, false).await?,
                "outcome-unknown" => gate.case_outcome_unknown(&mut evidence).await?,
                other => {
                    return Err(HarnessError::InvalidInput(format!(
                        "unknown ACP gate case {other}"
                    )));
                }
            }
            // A case is recorded as executed only after it returned, so a case
            // that failed is absent rather than counted.
            evidence.cases_executed.push(case.to_owned());
            evidence.max_membership_age_at_case_end_ms = evidence
                .max_membership_age_at_case_end_ms
                .max(gate.membership_signed_at.elapsed().as_millis());
            eprintln!(
                "ACP real-path case {case} at {} ms: {evidence:?}",
                started.elapsed().as_millis()
            );
        }
        Ok::<(), HarnessError>(())
    }
    .await;

    // The accommodation and the refusal ledger are recorded whether or not the
    // run succeeded, so a failure still reports them.
    evidence.membership_resigns = gate.membership_resigns;
    evidence.not_dispatched_refusals = gate.ledger.refusals.load(Ordering::SeqCst);
    evidence.not_dispatched_retries = gate.ledger.retries.load(Ordering::SeqCst);
    evidence.unexplained_refusal = gate
        .ledger
        .unexplained
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let export = gate.export();
    evidence.device_sessions = export.connections_opened;
    if let Some(client) = &gate.client {
        evidence.rotations_observed = client.status().borrow().rotations_completed;
    }
    // Built last, from what was observed rather than from a constant.
    evidence.not_covered = not_covered(evidence.rotations_observed);

    // Every child this export ever started must be gone.  Read from the
    // process table after teardown, not from a counter.
    let pids = gate
        .client
        .as_ref()
        .map(|_| {
            gate.acp_diagnostics
                .child_pids(&gate.service_id.to_string())
        })
        .unwrap_or_default();
    if let Some(task) = gate.freeze_task.take() {
        task.abort();
    }
    if let Some(client) = gate.client.take() {
        let _ = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    }
    evidence.leftover_processes = pids.into_iter().filter(|pid| process_alive(*pid)).count();

    outcome?;
    Ok(evidence)
}

/// Every rule this gate holds.  The first violated one names itself.
///
/// # Errors
/// The first rule that did not hold.
pub fn validate_acp_real_path_evidence(evidence: &AcpRealPathEvidence) -> Result<()> {
    let executed: Vec<&str> = evidence.cases_executed.iter().map(String::as_str).collect();
    let checks: [(&str, bool); 32] = [
        ("three relays", evidence.relay_count == 3),
        (
            "the device is owned by relay-a and the consumer entered at relay-c",
            evidence.non_owner_ingress
                && evidence.owner_node == "relay-a"
                && evidence.ingress_node == "relay-c",
        ),
        ("every case executed", executed == ACP_CASES.to_vec()),
        (
            // **Not `len() == NOT_COVERED.len()`**, which compared the evidence
            // against the constant it was built from and could not fail. This
            // checks the one entry that carries a measurement really carries
            // *this run's* measurement.
            "the limits of the claim are recorded, and the rotation disclosure states the observed count",
            evidence.not_covered.len() == NOT_COVERED.len() + 1
                && evidence.not_covered.iter().any(|text| {
                    text.contains(&format!(
                        "rotations_completed = {}",
                        evidence.rotations_observed
                    ))
                }),
        ),
        // --- the conversation, off the wire ---
        ("initialize opened a connection", evidence.connection_opened),
        (
            "the session identifier arrived on the connection stream",
            evidence.session_id_from_connection_stream,
        ),
        (
            "session/prompt was accepted 202 and answered separately",
            evidence.prompt_accepted_202,
        ),
        (
            "the turn completed with end_turn, read off the wire",
            evidence.conversation_stop_reason == "end_turn",
        ),
        // --- permissions ---
        (
            "the permission callback was observed on the session stream",
            evidence.permission_requested_on_wire,
        ),
        (
            "the agent offered exactly the two options this profile expects",
            evidence.offered_options
                == vec![
                    tunnel_acp_fixture::PERMIT_OPTION.to_owned(),
                    tunnel_acp_fixture::REJECT_OPTION.to_owned(),
                ],
        ),
        (
            "the agent itself recorded receiving the allowed option",
            evidence.allow_outcome_at_agent
                == format!("selected:{}", tunnel_acp_fixture::PERMIT_OPTION),
        ),
        (
            "the agent itself recorded receiving the rejected option",
            evidence.reject_outcome_at_agent
                == format!("selected:{}", tunnel_acp_fixture::REJECT_OPTION),
        ),
        (
            "an allowed permission ends the turn end_turn",
            evidence.allow_stop_reason == "end_turn",
        ),
        (
            "a rejected permission ends the turn refusal",
            evidence.reject_stop_reason == "refusal",
        ),
        (
            "an unoffered option is refused by its own rule, read off the wire",
            evidence.unoffered_option_rule == "ACP_OPTION_NOT_OFFERED",
        ),
        (
            "a response answering nothing outstanding is refused by its own rule",
            evidence.unknown_request_id_rule == "ACP_UNKNOWN_REQUEST_ID",
        ),
        (
            // No rule here on purpose: a foreign connection must be
            // indistinguishable from one that never existed.
            "a response on the wrong connection is answered 404, as a nonexistent one is",
            evidence.wrong_connection_status == 404,
        ),
        // --- cancellation ---
        (
            "a confirmed cancelled turn has stopReason cancelled, read off the wire",
            evidence.cancel_stop_reason == "cancelled",
        ),
        (
            "the agent itself recorded receiving a cancelled permission",
            evidence.cancel_outcome_at_agent == "cancelled:",
        ),
        (
            "an update was accepted after the cancellation and before the prompt result",
            evidence.update_after_cancel_before_result,
        ),
        // --- the explicit unknown outcome ---
        (
            "the crashed turn's stream errored rather than ending cleanly",
            evidence.unknown_stream_errored && !evidence.unknown_stream_ended_cleanly,
        ),
        (
            "the stream failed inside the forwarding layer's own terminal budget",
            evidence.unknown_error_latency_ms > 0
                && evidence.unknown_error_latency_ms < evidence.unknown_error_wait_ms,
        ),
        (
            // The device noticed; whether that reached the consumer promptly
            // is the separate, recorded question above.
            "the export ended the connection when its child died",
            evidence.unknown_export_ended_connection
                && evidence.unknown_export_live_connections == 0,
        ),
        (
            "no stopReason ever arrived for the crashed turn",
            evidence.unknown_no_stop_reason,
        ),
        (
            "the side effect is recorded exactly once in the agent's own ledger",
            evidence.side_effects_in_ledger == 1,
        ),
        (
            "nothing replayed the side effect within the observation window",
            evidence.side_effects_after_settle == 1,
        ),
        (
            "the export classified the crashed turn outcome_unknown through the terminal rule",
            evidence.export_terminal_unknown_delta == 1,
        ),
        (
            "the export classified the completed turn succeeded through the terminal rule",
            evidence.export_terminal_succeeded_delta == 1,
        ),
        (
            "the export classified the cancelled turn cancelled through the terminal rule",
            evidence.export_terminal_cancelled_delta == 1,
        ),
        // --- the M7-C80 accommodation ---
        (
            // **Not `resign_spacing_ms >= MEMBERSHIP_RESIGN_SPACING`**, which
            // compared a constant to the constant it was copied from. What
            // matters is that re-signing really was rare: the accommodation is
            // "at most every 15 s", so a run of this length admits very few.
            "membership was re-signed only at case boundaries, and rarely",
            evidence.membership_resigns >= 1
                && u128::from(evidence.membership_resigns)
                    <= (evidence.max_membership_age_at_case_end_ms
                        / MEMBERSHIP_RESIGN_SPACING.as_millis())
                        + 1,
        ),
        (
            "every case ended inside the membership records' lifetime",
            evidence.max_membership_age_at_case_end_ms < MEMBERSHIP_RECORD_LIFETIME.as_millis(),
        ),
        // --- refusals, and the process table ---
        (
            "every not_dispatched refusal coincided with an observed rotation freeze and was bounded",
            evidence.not_dispatched_refusals == evidence.not_dispatched_retries
                && evidence.not_dispatched_retries <= NOT_DISPATCHED_RETRIES
                && evidence.unexplained_refusal.is_none(),
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "ACP real-path gate failed: {rule}"
            )));
        }
    }
    // **The per-case rules come after "every case executed", deliberately.**
    // A case that did not run leaves its evidence at `Default`, and every one
    // of its rules then fails — which would report a case that never executed
    // as six substantive failures. The completeness rule above names the real
    // problem first.
    let loss_checks = |label: &str, loss: &LossEvidence| -> Vec<(String, bool)> {
        vec![
            (
                format!("{label}: the transport terminated by the subscriber-loss rule"),
                loss.terminated_by_loss,
            ),
            (
                format!("{label}: the pending permission resolved cancelled and none was approved"),
                loss.permissions_cancelled == 1 && loss.permissions_approved == 0,
            ),
            (
                format!("{label}: a new prompt is refused"),
                loss.new_prompt_refused,
            ),
            (
                format!("{label}: the other required stream errored rather than ending cleanly"),
                loss.other_stream_errored,
            ),
            (
                format!("{label}: a reconnect must initialize anew"),
                loss.reconnect_requires_initialize,
            ),
            (
                format!("{label}: the child is gone from the process table"),
                loss.child_gone_from_process_table,
            ),
        ]
    };
    for (rule, passed) in loss_checks("a broken session stream", &evidence.session_loss)
        .into_iter()
        .chain(loss_checks(
            "a broken connection stream",
            &evidence.connection_loss,
        ))
    {
        if !passed {
            return Err(HarnessError::Process(format!(
                "ACP real-path gate failed: {rule}"
            )));
        }
    }
    if evidence.leftover_processes != 0 {
        return Err(HarnessError::Process(format!(
            "ACP real-path gate failed: {} agent processes outlived the gate",
            evidence.leftover_processes
        )));
    }
    Ok(())
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<AcpRealPathEvidence> {
    let options = HarnessOptions::from_env()?
        .acp_services(true)
        .rotation(ACP_GATE_ROTATION);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("ACP gate harness startup timed out".into()))??;
    // The relays serve the pinned ACP profile exactly as `serve` builds it
    // from `[http_forward] profiles`.
    let serve = tunnel_relay::HttpForwardServeConfig {
        profiles: vec![tunnel_acp::PROFILE_ID.to_owned()],
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
    harness.http_forward = Some(exports);
    let workspace = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(HarnessError::Io(error));
        }
    };
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        run(&mut cluster, &harness, workspace.path().to_path_buf()),
    )
    .await
    {
        Ok(result) => result.and_then(|evidence| {
            if let Err(error) = validate_acp_real_path_evidence(&evidence) {
                // Payload-free: identifiers, counters and labels.
                eprintln!("ACP real-path evidence: {evidence:?}");
                return Err(error);
            }
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "the ACP real-path scenario exceeded its bounded deadline".into(),
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
