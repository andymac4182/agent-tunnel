//! M3-03 over the real cluster: the official rmcp 3.4.0 client, as a cloud
//! consumer with a bearer token, drives both pinned MCP profiles against
//! both device export kinds through non-owner ingress (relay-c), the peer
//! HTTP/3 hop, the owner actor (relay-a), the rotating device data
//! WebSocket and `tunnel-client`, which serves the exports from its own
//! `[exports.<id>.mcp]` configuration exactly as `tunnel-client connect`
//! does.  The relays serve the profiles from `[http_forward] profiles`, and
//! each catalog service selects its profile with `http_forward_profile`.
//!
//! The deterministic desktop fixture is `tunnel-mcp-fixture`: a stdio child
//! per export (one per request for 2026-07-28, one per session for
//! 2025-11-25) or a separate rmcp Streamable HTTP server process on a fixed
//! loopback port.
//!
//! For each (export kind, profile) combination the gate runs, each case
//! with a fresh client and a membership re-sign only between cases
//! (defect M7-C80):
//!
//! * `discovery`: `server/discover` (2026) or `initialize` (2025), then
//!   `tools/list` and an exact `echo` with arguments, `_meta` and an image;
//! * `notifications`: ordered progress during a call, and `notifications/
//!   message` on the request stream (2026) or the standalone GET stream
//!   (2025);
//! * `cancellation`: a running call cancelled by the client; the server
//!   observes the cancellation, no result is delivered, the stdio child's
//!   process group (with a synthetic descendant) is killed;
//! * `crash`: the backend exits after a first progress event; the client gets
//!   an error, the tool ran once, no result is fabricated, and a later call
//!   works on a fresh child or backend (2026) or after the session's 404
//!   (2025);
//! * `rotation-discovery` and `rotation-invocation`: a held `tools/list` and
//!   a held call are each observed dispatched and unanswered by the owner at
//!   a completed rotation, then answered exactly with one dispatch;
//! * `streaming`: 48 progress events of 4 KiB each, gated so the owner
//!   observes the open response at three distinct rotations, byte-exact and
//!   in order, with one dispatch.
//!
//! All payloads, credentials and processes are synthetic.

pub(super) mod wire;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientRequest, ProtocolVersion, Request,
    RequestMetaObject,
};
use rmcp::service::{PeerRequestOptions, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, UnixSocketHttpClient};
use rmcp::{ClientLifecycleMode, ClientServiceExt, RoleClient};
use tokio::time::{sleep, timeout};
use tunnel_client::ConnectOptions;
use tunnel_client::http_forward::{DeviceHttpDiagnostics, HttpHandlers, McpExportDiagnostics};
use tunnel_core::RotationConfig;
use tunnel_mcp_export::ExportDiagnostics;
use tunnel_relay::http_forward_diagnostics::HttpRotationObservation;
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot};

pub use self::wire::WireCounts;
use self::wire::{
    CountingHttpClient, FreezeWatch, GateClient, HttpBackend, NOT_DISPATCHED_RETRIES, Sidecar,
    WireLedger, count_lines, fixture_binary_path, process_exists, wait_file, wait_pid_file,
    wait_process_gone,
};
use super::http_forward_real_path::{connect_consumer, empty_stream, request};
use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::{Harness, HarnessError, HarnessOptions, McpServiceFixture, Result};

/// The short scheduled-rotation policy (as gate 4).
pub const MCP_GATE_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 6,
    handshake_timeout_seconds: 2,
    overlap_seconds: 5,
};
pub const PROFILE_2026: &str = "mcp-2026-07-28";
pub const PROFILE_2025: &str = "mcp-2025-11-25";
pub const KIND_STDIO: &str = "stdio";
pub const KIND_HTTP: &str = "streamable-http";
/// The cases every combination runs, in order.
pub const MCP_CASES: [&str; 7] = [
    "discovery",
    "notifications",
    "cancellation",
    "crash",
    "rotation-discovery",
    "rotation-invocation",
    "streaming",
];
/// Progress notifications in the `notifications` case.
pub const PROGRESS_STEPS: u64 = 6;
/// Log notifications in the `notifications` case.
pub const LOG_COUNT: u64 = 5;
/// Streamed events and their synthetic payload size.
pub const STREAM_EVENTS: u64 = 48;
pub const STREAM_EVENT_BYTES: usize = 4096;
/// The events after which the stream waits for a rotation observation.
pub const STREAM_GATES: [u64; 3] = [11, 23, 35];
/// The distinct rotations a stream must span (docs/mcp.md, M3 acceptance).
pub const STREAM_MIN_ROTATIONS: usize = 3;
const MAX_ROTATIONS_PER_WAIT: u64 = 4;
/// The longest one observation wait lasts.
pub const OBSERVATION_BOUND: Duration = Duration::from_secs(
    (MCP_GATE_ROTATION.interval_seconds + MCP_GATE_ROTATION.overlap_seconds)
        * MAX_ROTATIONS_PER_WAIT,
);
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(1_200);
const WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(20);
const CANCELLED: u16 = tunnel_protocol::reset_reason::CANCELLED;
const MEMBERSHIP_RESIGN_SPACING: Duration = Duration::from_secs(15);
/// The fixture's signed membership record lifetime (the product maximum).
const MEMBERSHIP_RECORD_LIFETIME: Duration = Duration::from_secs(60);
/// A process-group kill must land within this bound (the 2026 stdio bridge
/// allows its child 1 s after `notifications/cancelled`).
const PROCESS_EXIT_BOUND: Duration = Duration::from_secs(15);
/// What this gate does not exercise; recorded in the evidence and docs.
pub const NOT_COVERED: [&str; 6] = [
    "sampling/createMessage and elicitation/create server requests (M3-13)",
    "2026-07-28 MRTR input requests and subscriptions/listen (M3-13)",
    "resources and prompts (M3-13)",
    "Last-Event-ID resume of an interrupted stream (M3-10)",
    "process-group kill for a Streamable HTTP backend, which the device does not own",
    "session isolation, concurrent correlation, lost acknowledgements and revocation: covered by verify-m3-mcp-isolation (M3-04), not by this gate",
];

fn protocol_of(profile: &str) -> &'static str {
    if profile == PROFILE_2026 {
        "2026-07-28"
    } else {
        "2025-11-25"
    }
}

/// `discovery`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryEvidence {
    pub negotiated_version: String,
    /// `server/discover` (2026) or `initialize` (2025) dispatches.
    pub lifecycle_dispatches: u64,
    /// The other profile's lifecycle method dispatches (must be 0).
    pub foreign_lifecycle_dispatches: u64,
    pub tools_list_dispatches: u64,
    pub tools_complete: bool,
    pub echo_arguments_exact: bool,
    pub echo_meta_exact: bool,
    pub echo_protocol_meta_exact: bool,
    pub echo_image_exact: bool,
    pub echo_invocations: u64,
    pub wire: WireCounts,
}

/// `notifications`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NotificationEvidence {
    /// The progress value of every notification the client handler received,
    /// sorted: rmcp may run notification handlers concurrently, so only the
    /// wire order in `wire.progress_values` is ordering evidence (M3-29).
    pub progress_values: Vec<u64>,
    /// Whether the handler also saw the progress in order (reported only).
    pub progress_handler_order_exact: bool,
    pub progress_result_exact: bool,
    /// The `seq` of every log the client handler received, sorted: rmcp may
    /// run notification handlers concurrently, so only the wire order in
    /// `wire.log_seqs` is ordering evidence.
    pub log_seqs: Vec<u64>,
    pub log_data_exact: bool,
    /// Whether the handler also saw the logs in order (reported only).
    pub log_handler_order_exact: bool,
    pub log_result_exact: bool,
    pub wire: WireCounts,
}

/// `cancellation`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CancellationEvidence {
    pub stream_id: u64,
    pub operation_id: String,
    pub invocations: u64,
    pub server_observed_cancel: bool,
    /// Results or errors the client received for the cancelled call.
    pub cancelled_call_responses: u64,
    /// `notifications/cancelled` the stdio bridge wrote to the child.
    pub bridge_cancel_notifications: u64,
    /// Whether the synthetic descendant in the child's process group died
    /// (stdio only).
    pub descendant_killed: Option<bool>,
    pub owner_release: String,
    pub owner_reset_reason: Option<u16>,
    /// The ingress exchange record's error code (`none` without one), when
    /// relay-c recorded the exchange.
    pub ingress_record: Option<String>,
    pub follow_up_ok: bool,
    pub wire: WireCounts,
}

/// `crash`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CrashEvidence {
    pub progress_before_crash: bool,
    pub call_failed: bool,
    pub error_leaks_stderr: bool,
    pub crash_responses: u64,
    pub invocations: u64,
    pub follow_up_ok: bool,
    pub follow_up_attempts: u64,
    pub lifecycle_dispatches_after_crash: u64,
    pub children_spawned_after_crash: u64,
    pub export_interrupted: u64,
    pub sessions_ended: u64,
    pub descendant_killed: Option<bool>,
    pub backend_exited: Option<bool>,
    pub wire: WireCounts,
}

/// `rotation-discovery` and `rotation-invocation`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeldRotationEvidence {
    pub stream_id: u64,
    pub operation_id: String,
    pub observation: Option<HttpRotationObservation>,
    pub dispatches: u64,
    pub result_exact: bool,
    pub device_error: Option<String>,
    pub wire: WireCounts,
}

/// `streaming`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StreamingEvidence {
    pub stream_id: u64,
    pub operation_id: String,
    pub events_received: u64,
    /// Every event's message received once, the wire carried progress
    /// values 1..=48 in order, and the SHA-256 of the messages in wire
    /// order equals the source's.
    pub events_exact_in_order: bool,
    /// Whether the client handler also saw them in order (reported only:
    /// rmcp may dispatch notification handlers concurrently).
    pub handler_order_exact: bool,
    pub result_exact: bool,
    pub observations: Vec<HttpRotationObservation>,
    pub invocations: u64,
    pub children_spawned: u64,
    pub device_error: Option<String>,
    pub ingress_error: Option<String>,
    pub wire: WireCounts,
}

/// One (export kind, profile) combination.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpComboEvidence {
    pub kind: String,
    pub profile: String,
    /// The combination ran on one device session that stayed the owner's
    /// and the connector's session throughout.
    pub session_stable: bool,
    pub session_rotations: u64,
    /// The highest owner stream ID a call used (a session admits at most
    /// 128 streams in its lifetime, M7-C82).
    pub highest_call_stream_id: u64,
    /// MCP export children still running after this combination's device
    /// session stopped.
    pub children_running_after_stop: u64,
    pub discovery: DiscoveryEvidence,
    pub notifications: NotificationEvidence,
    pub cancellation: CancellationEvidence,
    pub crash: CrashEvidence,
    pub rotation_discovery: HeldRotationEvidence,
    pub rotation_invocation: HeldRotationEvidence,
    pub streaming: StreamingEvidence,
}

/// The bounded evidence one gate run produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpCloudClientEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    pub ingress_node: String,
    pub non_owner_ingress: bool,
    pub relay_profiles: Vec<String>,
    /// Device sessions used: one per combination.
    pub device_sessions: u64,
    pub device_session_stable: bool,
    pub rotations_completed: u64,
    pub sidecar_connections: u64,
    pub ingress_exchanges_recorded: u64,
    pub owner_exchanges_recorded: u64,
    pub combos: Vec<McpComboEvidence>,
    /// Fixture processes (backends and synthetic descendants) still alive
    /// after cleanup.
    pub leftover_processes: u64,
    pub resign_spacing_ms: u128,
    /// The oldest the membership records in force were when a case ended;
    /// every case must end inside the records' 60 s lifetime.
    pub max_membership_age_at_case_end_ms: u128,
    /// The owner relay's rotation-freeze admission hold counters at the end
    /// of the run (M3-15): how many new OPENs a freeze held, how they left
    /// the hold, and the longest wait.  Reported, not asserted: whether a
    /// request happens to land in a freeze is the schedule's choice.
    pub owner_freeze_hold: tunnel_relay::RotationFreezeHoldSnapshot,
    pub not_covered: Vec<String>,
}

impl McpComboEvidence {
    /// Every case's transport counts, in case order.
    #[must_use]
    pub fn case_wires(&self) -> Vec<(&'static str, &WireCounts)> {
        vec![
            ("discovery", &self.discovery.wire),
            ("notifications", &self.notifications.wire),
            ("cancellation", &self.cancellation.wire),
            ("crash", &self.crash.wire),
            ("rotation-discovery", &self.rotation_discovery.wire),
            ("rotation-invocation", &self.rotation_invocation.wire),
            ("streaming", &self.streaming.wire),
        ]
    }
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

/// The owner froze a dispatched request that had no complete response.
#[must_use]
pub fn held_position(observation: &HttpRotationObservation) -> bool {
    observation.request.heads == 1
        && observation.request.ends == 1
        && observation.request_fin_sequenced
        && observation.response.ends == 0
        && !observation.response_fin_received
}

/// The owner froze an open SSE response that had carried events.
#[must_use]
pub fn mid_stream_position(observation: &HttpRotationObservation) -> bool {
    held_position(observation)
        && observation.response.heads == 1
        && observation.response.body_bytes > 0
}

fn expected_stream_digest(label: &str) -> String {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    for message in expected_stream_messages(label) {
        digest.update(message.as_bytes());
        digest.update(b"\n");
    }
    wire::hex_digest(&digest.finalize())
}

fn expected_stream_messages(label: &str) -> Vec<String> {
    (0..STREAM_EVENTS)
        .map(|index| tunnel_mcp_fixture::stream_event_message(label, index, STREAM_EVENT_BYTES))
        .collect()
}

/// Validate every rule; the first violated rule is named.
///
/// # Errors
/// A `HarnessError::Process` naming the violated rule.
#[allow(clippy::too_many_lines)]
pub fn validate_mcp_cloud_client_evidence(evidence: &McpCloudClientEvidence) -> Result<()> {
    // Per-case rules come first, so a run restricted with M3_MCP_COMBOS or
    // M3_MCP_CASES names the case rule it broke before the global
    // completeness rules reject the partial run.
    let mut global: Vec<(String, bool)> = vec![
        ("three relays".into(), evidence.relay_count == 3),
        (
            "non-owner ingress".into(),
            evidence.non_owner_ingress
                && evidence.owner_node == "relay-a"
                && evidence.ingress_node == "relay-c",
        ),
        (
            "relays serve both MCP profiles from [http_forward]".into(),
            evidence.relay_profiles == [PROFILE_2025, PROFILE_2026],
        ),
        (
            "one stable device session per combination".into(),
            evidence.device_session_stable && evidence.device_sessions == 4,
        ),
        (
            "consumer traffic entered relay-c and reached the owner".into(),
            evidence.sidecar_connections > 0
                && evidence.ingress_exchanges_recorded > 0
                && evidence.owner_exchanges_recorded >= evidence.ingress_exchanges_recorded,
        ),
        (
            "no fixture process outlived the gate".into(),
            evidence.leftover_processes == 0,
        ),
        (
            "membership re-sign spacing".into(),
            evidence.resign_spacing_ms >= MEMBERSHIP_RESIGN_SPACING.as_millis(),
        ),
        (
            "every case ended inside its membership records' lifetime".into(),
            evidence.max_membership_age_at_case_end_ms > 0
                && evidence.max_membership_age_at_case_end_ms
                    < MEMBERSHIP_RECORD_LIFETIME.as_millis(),
        ),
        (
            "not-covered list recorded".into(),
            evidence.not_covered.len() == NOT_COVERED.len(),
        ),
    ];
    let mut checks: Vec<(String, bool)> = Vec::new();
    let mut combos = evidence
        .combos
        .iter()
        .map(|combo| (combo.kind.as_str(), combo.profile.as_str()))
        .collect::<Vec<_>>();
    combos.sort_unstable();
    global.push((
        "all four export kind x profile combinations".into(),
        combos
            == [
                (KIND_STDIO, PROFILE_2025),
                (KIND_STDIO, PROFILE_2026),
                (KIND_HTTP, PROFILE_2025),
                (KIND_HTTP, PROFILE_2026),
            ],
    ));
    for combo in &evidence.combos {
        // Rotation numbers restart with each device session.
        let mut observed_rotations = std::collections::BTreeSet::new();
        let name = format!("{}/{}", combo.kind, combo.profile);
        let current = combo.profile == PROFILE_2026;
        let stdio = combo.kind == KIND_STDIO;
        let lifecycle = if current {
            "server/discover"
        } else {
            "initialize"
        };
        let d = &combo.discovery;
        checks.extend([
            (
                format!("{name} discovery: negotiated version"),
                d.negotiated_version == protocol_of(&combo.profile),
            ),
            (
                format!("{name} discovery: one {lifecycle} dispatch, none of the other lifecycle"),
                d.lifecycle_dispatches == 1
                    && d.foreign_lifecycle_dispatches == 0
                    && d.wire.post(lifecycle) == 1,
            ),
            (
                format!("{name} discovery: one tools/list dispatch listing every tool"),
                d.tools_list_dispatches == 1 && d.tools_complete,
            ),
            (
                format!("{name} discovery: echo arguments, _meta and image exact"),
                d.echo_arguments_exact
                    && d.echo_meta_exact
                    && d.echo_image_exact
                    && (d.echo_protocol_meta_exact || !current),
            ),
            (
                format!("{name} discovery: echo invoked once"),
                d.echo_invocations == 1 && d.wire.result("tools/call:echo") == 1,
            ),
            (
                format!("{name} discovery: session header only for 2025"),
                if current {
                    d.wire.session_headers == 0
                } else {
                    d.wire.session_headers >= 1
                },
            ),
        ]);
        let n = &combo.notifications;
        let log_placement = if current {
            n.wire.logs_on_request_streams == LOG_COUNT
                && n.wire.logs_on_standalone_streams == 0
                && n.wire.standalone_opened == 0
        } else {
            n.wire.logs_on_standalone_streams == LOG_COUNT
                && n.wire.logs_on_request_streams == 0
                && n.wire.standalone_opened >= 1
        };
        checks.extend([
            (
                format!("{name} notifications: ordered progress"),
                n.progress_values == (1..=PROGRESS_STEPS).collect::<Vec<_>>()
                    && n.wire.progress_values == (1..=PROGRESS_STEPS).collect::<Vec<_>>()
                    && n.progress_result_exact,
            ),
            (
                format!("{name} notifications: every log message, in wire order"),
                n.log_seqs == (0..LOG_COUNT).collect::<Vec<_>>()
                    && n.wire.log_seqs == (0..LOG_COUNT).collect::<Vec<_>>()
                    && n.log_data_exact
                    && n.log_result_exact,
            ),
            (
                format!(
                    "{name} notifications: log messages on the {} stream",
                    if current { "request" } else { "standalone GET" }
                ),
                log_placement,
            ),
        ]);
        let c = &combo.cancellation;
        checks.extend([
            (
                format!("{name} cancellation: invoked once"),
                c.invocations == 1 && c.stream_id > 0,
            ),
            (
                format!("{name} cancellation: the server observed the cancellation"),
                c.server_observed_cancel,
            ),
            (
                format!("{name} cancellation: no result or error delivered"),
                c.cancelled_call_responses == 0,
            ),
            (
                format!("{name} cancellation: a later call works"),
                c.follow_up_ok,
            ),
            (
                format!("{name} cancellation: process group killed"),
                if stdio {
                    c.descendant_killed == Some(true)
                } else {
                    c.descendant_killed.is_none()
                },
            ),
            (
                // The cancelled call's stream carried no final response, so
                // the post-response drain (M3-23) never held it open.  For
                // 2026 that closing *is* the cancellation.
                format!("{name} cancellation: the cancelled call's stream was not drained"),
                c.wire.drained("tools/call:sleep") == 0,
            ),
            (
                // M3-14: a cancellation the owner recorded as RESET(CANCELLED)
                // is recorded by the ingress too, including when the consumer
                // left before any response head (the 2026 stdio case).
                format!("{name} cancellation: the ingress recorded the cancellation"),
                c.owner_release != "reset"
                    || c.owner_reset_reason != Some(CANCELLED)
                    || c.ingress_record.as_deref() == Some("HTTP_CANCELLED"),
            ),
            (
                format!("{name} cancellation: profile signal"),
                match (current, stdio) {
                    // Closing the response stream is the cancellation: the
                    // relays reset the stream and the bridge writes
                    // notifications/cancelled itself.
                    (true, true) => {
                        c.bridge_cancel_notifications == 1
                            && c.owner_release == "reset"
                            && c.owner_reset_reason == Some(CANCELLED)
                    }
                    // The export drops the backend response; whether the
                    // owner records the consumer's RESET or the device's
                    // FIN first is a race, so either terminal is accepted.
                    (true, false) => {
                        c.bridge_cancel_notifications == 0
                            && ((c.owner_release == "reset"
                                && c.owner_reset_reason == Some(CANCELLED))
                                || c.owner_release == "fin")
                    }
                    // The client POSTs notifications/cancelled.
                    (false, _) => {
                        c.bridge_cancel_notifications == 0
                            && c.wire.post("notifications/cancelled") == 1
                    }
                },
            ),
        ]);
        let k = &combo.crash;
        checks.extend([
            (
                format!("{name} crash: failed mid-stream with a scoped error"),
                k.progress_before_crash && k.call_failed && !k.error_leaks_stderr,
            ),
            (
                format!("{name} crash: no fabricated result and no replay"),
                k.crash_responses == 0
                    && k.invocations == 1
                    && k.wire.post("tools/call:crash") == 1,
            ),
            (
                format!("{name} crash: a later call works"),
                k.follow_up_ok && (1..=2).contains(&k.follow_up_attempts),
            ),
            (
                format!("{name} crash: process group killed"),
                if stdio {
                    k.descendant_killed == Some(true) && k.backend_exited.is_none()
                } else {
                    k.descendant_killed.is_none() && k.backend_exited == Some(true)
                },
            ),
            (
                format!("{name} crash: profile recovery"),
                match (current, stdio) {
                    (true, true) => {
                        k.wire.session_expired == 0
                            && k.export_interrupted >= 1
                            && k.children_spawned_after_crash >= 1
                            && k.lifecycle_dispatches_after_crash == 0
                    }
                    (true, false) => {
                        k.wire.session_expired == 0 && k.lifecycle_dispatches_after_crash == 0
                    }
                    (false, true) => {
                        k.wire.session_expired >= 1
                            && k.export_interrupted >= 1
                            && k.sessions_ended >= 1
                            && k.lifecycle_dispatches_after_crash == 1
                    }
                    (false, false) => {
                        k.wire.session_expired >= 1 && k.lifecycle_dispatches_after_crash == 1
                    }
                },
            ),
        ]);
        for (case, held, method) in [
            (
                "rotation-discovery",
                &combo.rotation_discovery,
                "tools/list",
            ),
            (
                "rotation-invocation",
                &combo.rotation_invocation,
                "tools/call:gate",
            ),
        ] {
            let observation_ok = held.observation.as_ref().is_some_and(|observation| {
                observation.stream_id == held.stream_id
                    && !held.operation_id.is_empty()
                    && observation.operation_id == held.operation_id
                    && held_position(observation)
                    && fence_accounted(observation)
            });
            if let Some(observation) = &held.observation {
                observed_rotations.insert(observation.rotation);
            }
            checks.extend([
                (
                    format!("{name} {case}: owner observed the dispatched request at a rotation"),
                    held.stream_id > 0 && observation_ok,
                ),
                (
                    format!("{name} {case}: one dispatch and one POST"),
                    held.dispatches == 1 && held.wire.post(method) == 1,
                ),
                (
                    format!("{name} {case}: exact answer, no device error"),
                    held.result_exact && held.device_error.is_none(),
                ),
            ]);
        }
        let s = &combo.streaming;
        let rotations = s
            .observations
            .iter()
            .map(|observation| observation.rotation)
            .collect::<std::collections::BTreeSet<_>>();
        observed_rotations.extend(rotations.iter().copied());
        checks.extend([
            (
                format!("{name} streaming: every event byte-exact and in order"),
                s.events_received == STREAM_EVENTS && s.events_exact_in_order && s.result_exact,
            ),
            (
                format!("{name} streaming: the open stream spanned three rotations"),
                rotations.len() >= STREAM_MIN_ROTATIONS
                    && !s.operation_id.is_empty()
                    && s.observations.iter().all(|observation| {
                        observation.stream_id == s.stream_id
                            && observation.operation_id == s.operation_id
                            && mid_stream_position(observation)
                            && fence_accounted(observation)
                    }),
            ),
            (
                format!("{name} streaming: one dispatch"),
                s.invocations == 1
                    && s.wire.post("tools/call:stream") == 1
                    && s.wire.result("tools/call:stream") == 1
                    && s.children_spawned == u64::from(stdio && current),
            ),
            (
                format!("{name} streaming: no device or ingress error"),
                s.device_error.is_none() && s.ingress_error.is_none(),
            ),
            (
                format!(
                    "{name}: every not_dispatched refusal was the relay's rotation-freeze answer (a standalone GET: inside an observed freeze) and its resends were bounded"
                ),
                combo.case_wires().iter().all(|(_, wire)| {
                    wire.not_dispatched_refusals == wire.not_dispatched_retries
                        && wire.standalone_not_dispatched_refusals == wire.standalone_retries
                        && wire.not_dispatched_retries <= NOT_DISPATCHED_RETRIES
                        && wire.standalone_retries <= NOT_DISPATCHED_RETRIES
                        && wire.unexplained_refusal.is_none()
                }),
            ),
            (
                format!("{name}: one device session stayed under the 128-stream limit (M7-C82)"),
                combo.highest_call_stream_id > 0 && combo.highest_call_stream_id < 128,
            ),
            (
                format!("{name}: no export child outlived its device session"),
                combo.children_running_after_stop == 0,
            ),
            (
                format!("{name}: five distinct rotations observed on one stable session"),
                combo.session_stable
                    && observed_rotations.len() >= 2 + STREAM_MIN_ROTATIONS
                    && combo.session_rotations >= observed_rotations.len() as u64,
            ),
        ]);
    }
    global.push((
        "rotations completed across the sessions".into(),
        evidence.rotations_completed
            == evidence
                .combos
                .iter()
                .map(|combo| combo.session_rotations)
                .sum::<u64>()
            && evidence.rotations_completed >= 4 * (2 + STREAM_MIN_ROTATIONS) as u64,
    ));
    checks.extend(global);
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "MCP cloud-client gate failed: {rule}"
            )));
        }
    }
    Ok(())
}

fn arguments(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn text_of(result: &CallToolResult) -> Option<String> {
    result
        .content
        .iter()
        .find_map(|block| block.as_text().map(|text| text.text.clone()))
}

fn call_request(tool: &'static str, value: serde_json::Value) -> ClientRequest {
    ClientRequest::CallToolRequest(Request::new(
        CallToolRequestParams::new(tool).with_arguments(arguments(value)),
    ))
}

fn call_result(response: rmcp::model::ServerResult) -> Option<CallToolResult> {
    match response {
        rmcp::model::ServerResult::CallToolResult(result) => Some(result),
        _ => None,
    }
}

/// The payload-free records of one exchange.
#[derive(Debug, Default)]
struct StreamRecords {
    device_seen: bool,
    device_error: Option<String>,
    owner_release: String,
    owner_reset_reason: Option<u16>,
    ingress_seen: bool,
    ingress_error: Option<String>,
}

impl StreamRecords {
    /// A device or ingress error, or a missing record, as one label.
    fn error(&self, ingress: bool) -> Option<String> {
        if !self.device_seen {
            return Some("device record missing".to_owned());
        }
        if ingress && !self.ingress_seen {
            return Some("ingress record missing".to_owned());
        }
        if ingress {
            self.ingress_error.clone()
        } else {
            self.device_error.clone()
        }
    }
}

struct Combo {
    service: McpServiceFixture,
    kind: &'static str,
    /// The stdio workspace or the HTTP backend's marker directory.
    marker_dir: PathBuf,
    ordinal: usize,
}

impl Combo {
    fn current(&self) -> bool {
        self.service.profile == PROFILE_2026
    }

    fn stdio(&self) -> bool {
        self.kind == KIND_STDIO
    }

    fn marker(&self, name: &str) -> PathBuf {
        self.marker_dir.join(name)
    }

    fn invocations(&self, tool: &str) -> u64 {
        count_lines(&self.marker("invocations.log"), tool)
    }

    fn discoveries(&self, method: &str) -> u64 {
        count_lines(&self.marker("discovery.log"), method)
    }

    fn label(&self, case: &str) -> String {
        format!("{case}{}", self.ordinal)
    }

    fn release(&self, name: &str) -> Result<()> {
        std::fs::write(
            self.marker(&tunnel_mcp_fixture::release_marker(name)),
            b"release",
        )
        .map_err(wire::io_during(
            "write a release marker in the combination's marker directory",
        ))
    }
}

type Client = RunningService<RoleClient, GateClient>;

struct Gate<'a> {
    cluster: &'a mut ProductionCluster,
    /// The device runtime configuration each device session connects with.
    config: tunnel_client::ConnectConfig,
    tenant_id: uuid::Uuid,
    client: Option<tunnel_client::ConnectionHandle>,
    device_diagnostics: DeviceHttpDiagnostics,
    mcp_diagnostics: McpExportDiagnostics,
    sidecar: Sidecar,
    backends: BTreeMap<&'static str, HttpBackend>,
    device_id: uuid::Uuid,
    /// Catalog service identifiers by combination label.
    service_ids: BTreeMap<&'static str, String>,
    token: String,
    ca: Vec<u8>,
    membership_signed_at: Instant,
    session_id: String,
    last_stream_id: u64,
    descendant_pids: Vec<u32>,
    /// Whether the connector is in a rotation freeze, watched for the
    /// current device session.
    freeze: Arc<FreezeWatch>,
    freeze_task: Option<tokio::task::JoinHandle<()>>,
}

impl Gate<'_> {
    async fn owner_snapshot(&self) -> Result<RelaySnapshot> {
        self.cluster.relay("relay-a")?.snapshot().await
    }

    fn session<'s>(&self, snapshot: &'s RelaySnapshot) -> Result<&'s RelaySessionSnapshot> {
        snapshot
            .sessions
            .iter()
            .find(|session| {
                session.device_id == self.device_id.to_string()
                    && session.session_id == self.session_id
            })
            .ok_or_else(|| HarnessError::Process("owner session is missing".into()))
    }

    /// Start a fresh `tunnel-client` session with the MCP exports registered
    /// exactly as `tunnel-client connect` registers them, wait for it to be
    /// ready and for its owner claim, and return the owner node.
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
        .map_err(|_| HarnessError::Timeout("MCP gate device startup timed out".into()))?
        .map_err(|error| HarnessError::Process(format!("MCP gate device: {error}")))?;
        let client = self.client.insert(client);
        // Watch this session's rotation phase: the relay refuses new stream
        // admission from QUIESCE to COMMIT with the same body it uses for
        // every other owner-not-ready condition, so only a refusal that
        // coincides with an observed freeze may be resent.
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
            .map_err(|_| HarnessError::Timeout("MCP gate device readiness timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        self.session_id = session.session_id.clone();
        self.last_stream_id = 0;
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
                let snapshot = self.owner_snapshot().await?;
                if self.session(&snapshot).is_ok() {
                    return Ok(owner.token.node_id);
                }
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "device owner claim not observed".into(),
                ));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Export children still running, summed over every MCP export.
    fn children_running(&self) -> u64 {
        crate::MCP_GATE_SERVICES
            .iter()
            .filter_map(|(label, _)| {
                self.service_ids
                    .get(label)
                    .and_then(|service_id| self.mcp_diagnostics.get(service_id))
            })
            .map(|diagnostics| diagnostics.children_running)
            .sum()
    }

    async fn stop_device(&mut self) -> Result<()> {
        if let Some(task) = self.freeze_task.take() {
            task.abort();
        }
        let Some(client) = self.client.take() else {
            return Ok(());
        };
        // Stop between rotations: a stop that lands inside an attempt can
        // fail its stream-forget barrier with "data writer stopped before
        // barrier completion" (defect M7-C84, seen once in fifteen runs).
        // The wait narrows that window; it is bounded and does not hide a
        // stop failure, and a failure names the phase it stopped in.
        let settled = Instant::now() + WAIT;
        loop {
            let status = client.status_snapshot();
            if (status.phase == "active" && status.candidate_generation.is_none())
                || Instant::now() >= settled
            {
                break;
            }
            sleep(POLL).await;
        }
        let stopping = client.status_snapshot();
        match timeout(CLEANUP_TIMEOUT, client.stop()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(HarnessError::Process(format!(
                "device stop in phase={} candidate_generation={:?} rotations={}: {error}",
                stopping.phase, stopping.candidate_generation, stopping.rotations_completed
            ))),
            Err(_) => Err(HarnessError::Timeout(format!(
                "device stop timed out in phase={} candidate_generation={:?}",
                stopping.phase, stopping.candidate_generation
            ))),
        }
    }

    /// Payload-free device and owner state after a failure.
    async fn print_failure_state(&self) {
        if let Some(client) = &self.client {
            let device = client.status_snapshot();
            eprintln!(
                "MCP cloud-client device at failure: phase={} same_session={} rotations={} recovery_attempt={:?} recovery_reason={:?} streams={} readiness={:?}",
                device.phase,
                device.session_id.as_deref() == Some(self.session_id.as_str()),
                device.rotations_completed,
                device.recovery_attempt,
                device.recovery_reset_reason,
                device.streams,
                *client.readiness().borrow(),
            );
        }
        if let Ok(snapshot) = self.owner_snapshot().await {
            eprintln!(
                "MCP cloud-client owner at failure: sessions={:?} terminals={:?}",
                snapshot
                    .sessions
                    .iter()
                    .map(|session| (
                        session.device_id == self.device_id.to_string(),
                        session.session_id == self.session_id,
                        session.phase.clone(),
                        session.rotations_completed
                    ))
                    .collect::<Vec<_>>(),
                snapshot
                    .session_terminal_events
                    .iter()
                    .map(|event| (
                        event.session_id == self.session_id,
                        event.reason,
                        event.rotation_id.is_some(),
                        event.active_generation,
                        event.candidate_generation
                    ))
                    .collect::<Vec<_>>()
            );
        }
    }

    fn export(&self, combo: &Combo) -> ExportDiagnostics {
        self.mcp_diagnostics
            .get(&combo.service.service_id.to_string())
            .unwrap_or_default()
    }

    fn uri(&self, combo: &Combo) -> String {
        format!(
            "http://localhost/v1/devices/{}/services/{}/http/mcp",
            self.device_id, combo.service.service_id
        )
    }

    async fn connect(&self, combo: &Combo) -> Result<(Client, GateClient, Arc<WireLedger>)> {
        let uri = self.uri(combo);
        let socket = self
            .sidecar
            .socket
            .to_str()
            .ok_or_else(|| HarnessError::InvalidInput("sidecar socket path".into()))?;
        let ledger = Arc::new(WireLedger::default());
        let http = CountingHttpClient::new(
            UnixSocketHttpClient::new(socket, &uri),
            Arc::clone(&ledger),
            Arc::clone(&self.freeze),
        );
        let mut config =
            StreamableHttpClientTransportConfig::with_uri(uri).auth_header(self.token.clone());
        // rmcp retries a broken event stream forever by default; a cloud
        // client bounds it, so an interrupted call surfaces as an error.
        config.retry_config = Arc::new(wire::BoundedRetry);
        let transport = StreamableHttpClientTransport::with_client(http, config);
        let (handler, lifecycle) = if combo.current() {
            (
                GateClient::default(),
                ClientLifecycleMode::Discover {
                    preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                },
            )
        } else {
            (GateClient::legacy(), ClientLifecycleMode::Initialize)
        };
        let running = timeout(
            WAIT,
            handler.clone().serve_with_lifecycle(transport, lifecycle),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!("{}: MCP lifecycle timed out", combo.service.label))
        })?
        .map_err(|error| {
            HarnessError::Process(format!(
                "{}: MCP lifecycle failed: {error}",
                combo.service.label
            ))
        })?;
        Ok((running, handler, ledger))
    }

    /// End a case's client, then join its post-response drains (M3-23)
    /// so none outlives the case.
    async fn close(client: Client, ledger: &WireLedger) {
        let _ = timeout(WAIT, client.cancel()).await;
        ledger.finish_drains(WAIT).await;
    }

    /// Case boundary: re-sign membership at most every
    /// [`MEMBERSHIP_RESIGN_SPACING`] (never under an in-flight stream), prove
    /// the relay-c route answers, and wait for the owner to hold no stream.
    async fn boundary(&mut self, route_probe: &Combo) -> Result<()> {
        self.wait_no_streams().await?;
        if self.membership_signed_at.elapsed() >= MEMBERSHIP_RESIGN_SPACING {
            self.cluster.resign_membership_now().await?;
            self.membership_signed_at = Instant::now();
            self.wait_peers_ready().await?;
            self.wait_route_ready(route_probe).await?;
            self.wait_no_streams().await?;
        }
        Ok(())
    }

    /// Every running relay's peer runtime is ready again after a re-sign.
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
                    "peer readiness did not recover after a membership re-sign".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    async fn wait_no_streams(&self) -> Result<()> {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = self.owner_snapshot().await?;
            if self.session(&snapshot)?.streams.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the owner kept a stream at a case boundary".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    /// A 2026 GET is answered 405 by the device export itself, before any
    /// backend: a cheap proof that relay-c reaches the device again.
    async fn wait_route_ready(&self, combo: &Combo) -> Result<()> {
        let ingress_addr = self.cluster.relay("relay-c")?.consumer_addr()?;
        let path = format!(
            "/v1/devices/{}/services/{}/http/mcp",
            self.device_id, combo.service.service_id
        );
        let deadline = Instant::now() + Duration::from_secs(45);
        // Two consecutive device answers: one can race a readiness flap.
        let mut answered = 0;
        loop {
            let attempt = async {
                let (mut sender, connection) = connect_consumer(ingress_addr, &self.ca).await?;
                let connection = tokio::spawn(async move {
                    let _ = connection.await;
                });
                let response = sender
                    .send_request(request(
                        "GET",
                        &path,
                        Some(&self.token),
                        &[
                            ("accept", "application/json, text/event-stream"),
                            ("mcp-protocol-version", "2026-07-28"),
                        ],
                        empty_stream(),
                    )?)
                    .await
                    .map_err(|error| HarnessError::Http(format!("route probe: {error}")))?;
                let status = response.status().as_u16();
                connection.abort();
                Ok::<_, HarnessError>(status)
            };
            let last = match timeout(Duration::from_secs(5), attempt).await {
                Ok(Ok(405)) => {
                    answered += 1;
                    if answered >= 2 {
                        return Ok(());
                    }
                    continue;
                }
                Ok(Ok(status)) => format!("status {status}"),
                Ok(Err(error)) => error.to_string(),
                Err(_) => "probe timed out".to_owned(),
            };
            answered = 0;
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "relay-c did not reach the device after a membership re-sign: {last}"
                )));
            }
            sleep(Duration::from_millis(250)).await;
        }
    }

    async fn rotations_completed(&self) -> Result<u64> {
        let snapshot = self.owner_snapshot().await?;
        Ok(self.session(&snapshot)?.rotations_completed)
    }

    /// The one live owner HTTP stream opened after the last identified one
    /// that carries a request body and has no complete response, with its
    /// logical operation ID.  Stream IDs restart with each device session
    /// and the owner's bounded diagnostics outlive a session, so records are
    /// always matched by operation ID as well.
    async fn call_stream(&mut self, label: &str) -> Result<(u64, String)> {
        let deadline = Instant::now() + WAIT;
        loop {
            let snapshot = self.owner_snapshot().await?;
            let session = self.session(&snapshot)?;
            let candidates = session
                .streams
                .iter()
                .filter(|stream| {
                    stream.stream_id > self.last_stream_id
                        && stream.http.as_ref().is_some_and(|http| {
                            http.request.body_bytes > 0
                                && http.request.ends == 1
                                && http.response.ends == 0
                        })
                })
                .map(|stream| (stream.stream_id, stream.operation_id.clone()))
                .collect::<Vec<_>>();
            if let [(stream_id, operation_id)] = candidates.as_slice() {
                self.last_stream_id = *stream_id;
                return Ok((*stream_id, operation_id.clone()));
            }
            // More than one open call stream is usually a transient overlap
            // (a previous case's stream is still settling), so wait for the
            // same bound rather than failing on the first sample.
            if Instant::now() >= deadline {
                return Err(HarnessError::Process(format!(
                    "{label}: expected one open call stream, found {candidates:?}"
                )));
            }
            sleep(POLL).await;
        }
    }

    async fn wait_observation(
        &self,
        label: &str,
        stream_id: u64,
        operation_id: &str,
        after: u64,
        position: fn(&HttpRotationObservation) -> bool,
    ) -> Result<HttpRotationObservation> {
        let deadline = Instant::now() + OBSERVATION_BOUND;
        let mut recorded_at_start = None;
        let mut polls = 0_u64;
        loop {
            let snapshot = self.owner_snapshot().await?;
            polls += 1;
            let recorded_now = snapshot.http_forward.rotations_recorded;
            let recorded_at_start = *recorded_at_start.get_or_insert(recorded_now);
            // M3-22: the relay-wide ring can evict a live stream's
            // observation within the rotation that recorded it, when that
            // rotation observed more than 64 streams; the stream's own
            // retained observations cannot be evicted by other streams.
            let own = self
                .session(&snapshot)
                .ok()
                .and_then(|session| {
                    session
                        .streams
                        .iter()
                        .find(|stream| {
                            stream.stream_id == stream_id && stream.operation_id == operation_id
                        })
                        .and_then(|stream| stream.http.as_ref())
                })
                .map(|http| http.rotation_observations.clone())
                .unwrap_or_default();
            let mut observations = snapshot
                .http_forward
                .rotations
                .iter()
                .chain(own.iter())
                .filter(|observation| {
                    observation.stream_id == stream_id
                        && observation.operation_id == operation_id
                        && observation.rotation > after
                })
                .collect::<Vec<_>>();
            observations.sort_by_key(|observation| observation.rotation);
            observations.dedup_by_key(|observation| observation.rotation);
            if let Some(observation) = observations
                .iter()
                .find(|observation| position(observation))
            {
                return Ok((*observation).clone());
            }
            if observations.len() as u64 >= MAX_ROTATIONS_PER_WAIT || Instant::now() >= deadline {
                let session = self.session(&snapshot).ok();
                // M3-22 forensics, payload-free: how much the owner's bounded
                // observation ring saw during this wait, what it still holds,
                // and which of the session's streams are open right now.
                let ring = &snapshot.http_forward.rotations;
                let after_any = ring
                    .iter()
                    .filter(|observation| observation.rotation > after)
                    .count();
                let ring_streams = ring
                    .iter()
                    .rev()
                    .take(8)
                    .map(|observation| (observation.stream_id, observation.rotation))
                    .collect::<Vec<_>>();
                let live = session
                    .map(|session| {
                        session
                            .streams
                            .iter()
                            .map(|stream| {
                                (
                                    stream.stream_id,
                                    stream.operation_id == operation_id,
                                    stream
                                        .http
                                        .as_ref()
                                        .map(|http| (http.request.ends, http.response.ends)),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                return Err(HarnessError::Process(format!(
                    "{label}: no rotation observed stream {stream_id} at its position after rotation {after}: observations={observations:?} phase={:?} rotations={:?} ring_len={} recorded_during_wait={} ring_after_rotation_any_stream={after_any} ring_newest={ring_streams:?} polls={polls} live_streams(id,same_operation,(request_ends,response_ends))={live:?}",
                    session.map(|session| session.phase.clone()),
                    session.map(|session| session.rotations_completed),
                    ring.len(),
                    recorded_now.saturating_sub(recorded_at_start),
                )));
            }
            sleep(POLL).await;
        }
    }

    /// The device, owner-stream and ingress records of one exchange.  The
    /// ingress record is looked for until `ingress_wait` after the owner
    /// record exists.
    async fn stream_records(
        &self,
        stream_id: u64,
        operation_id: &str,
        ingress_wait: Duration,
    ) -> StreamRecords {
        let mut records = StreamRecords::default();
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if let Some(record) = self
                .device_diagnostics
                .snapshot()
                .into_iter()
                .find(|record| record.stream_id == stream_id)
            {
                records.device_seen = true;
                records.device_error = record
                    .report
                    .and_then(|report| report.error)
                    .map(|code| code.as_str().to_owned());
                break;
            }
            sleep(POLL).await;
        }
        let deadline = Instant::now() + WAIT;
        let mut request_id = None;
        while Instant::now() < deadline {
            let Ok(owner) = self.owner_snapshot().await else {
                break;
            };
            if let Some(stream) =
                owner.http_forward.owner_streams.iter().find(|record| {
                    record.stream_id == stream_id && record.operation_id == operation_id
                })
            {
                request_id = Some(stream.request_id.clone());
                records.owner_release = stream.release.to_owned();
                records.owner_reset_reason = stream.reset_reason;
                break;
            }
            sleep(POLL).await;
        }
        let Some(request_id) = request_id else {
            return records;
        };
        let deadline = Instant::now() + ingress_wait;
        loop {
            if let Ok(relay) = self.cluster.relay("relay-c")
                && let Ok(ingress) = relay.snapshot().await
                && let Some(record) = ingress.http_forward.exchanges.iter().find(|record| {
                    record.role == "ingress_remote" && record.request_id == request_id
                })
            {
                records.ingress_seen = true;
                records.ingress_error = record.error_code.map(str::to_owned);
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            sleep(POLL).await;
        }
        records
    }

    // ---- cases ----------------------------------------------------------

    async fn discovery(&self, combo: &Combo) -> Result<DiscoveryEvidence> {
        let (lifecycle, foreign) = if combo.current() {
            ("server/discover", "initialize")
        } else {
            ("initialize", "server/discover")
        };
        let lifecycle_before = combo.discoveries(lifecycle);
        let foreign_before = combo.discoveries(foreign);
        let list_before = combo.discoveries("tools/list");
        let echo_before = combo.invocations("echo");
        let (client, _handler, ledger) = self.connect(combo).await?;
        let mut evidence = DiscoveryEvidence {
            negotiated_version: client
                .peer_info()
                .map(|info| info.protocol_version.to_string())
                .unwrap_or_default(),
            ..DiscoveryEvidence::default()
        };
        let outcome = async {
            let tools = timeout(WAIT, client.list_all_tools())
                .await
                .map_err(|_| HarnessError::Timeout("tools/list timed out".into()))?
                .map_err(|error| HarnessError::Process(format!("tools/list: {error}")))?;
            let names = tools
                .iter()
                .map(|tool| tool.name.to_string())
                .collect::<std::collections::BTreeSet<_>>();
            evidence.tools_complete = [
                "echo", "progress", "sleep", "crash", "log", "stream", "gate", "big",
            ]
            .iter()
            .all(|name| names.contains(*name));
            let marker = serde_json::json!({"nested": [1, "two", 3.5], "unicode": "caf\u{e9}"});
            let mut meta = RequestMetaObject::new();
            meta.insert("io.agent-tunnel.test/marker".to_owned(), marker.clone());
            let mut params = CallToolRequestParams::new("echo")
                .with_arguments(arguments(serde_json::json!({"a": 1, "b": "synthetic"})));
            params.meta = Some(meta);
            let echoed = timeout(WAIT, client.call_tool(params))
                .await
                .map_err(|_| HarnessError::Timeout("echo timed out".into()))?
                .map_err(|error| HarnessError::Process(format!("echo: {error}")))?;
            let seen: serde_json::Value = text_of(&echoed)
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or_default();
            evidence.echo_arguments_exact =
                seen["arguments"] == serde_json::json!({"a": 1, "b": "synthetic"});
            evidence.echo_meta_exact = seen["meta"]["io.agent-tunnel.test/marker"] == marker;
            evidence.echo_protocol_meta_exact =
                seen["meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28";
            evidence.echo_image_exact = echoed.content.iter().any(|block| {
                block
                    .as_image()
                    .is_some_and(|image| image.data == tunnel_mcp_fixture::IMAGE_PNG_BASE64)
            });
            Ok::<_, HarnessError>(())
        }
        .await;
        Self::close(client, &ledger).await;
        outcome?;
        evidence.lifecycle_dispatches = combo.discoveries(lifecycle) - lifecycle_before;
        evidence.foreign_lifecycle_dispatches = combo.discoveries(foreign) - foreign_before;
        evidence.tools_list_dispatches = combo.discoveries("tools/list") - list_before;
        evidence.echo_invocations = combo.invocations("echo") - echo_before;
        evidence.wire = ledger.counts();
        Ok(evidence)
    }

    async fn notifications(&self, combo: &Combo) -> Result<NotificationEvidence> {
        let label = combo.label("log");
        let (client, handler, ledger) = self.connect(combo).await?;
        let mut evidence = NotificationEvidence::default();
        let outcome = async {
            let handle = client
                .send_cancellable_request(
                    call_request("progress", serde_json::json!({"steps": PROGRESS_STEPS})),
                    PeerRequestOptions::no_options(),
                )
                .await
                .map_err(|error| HarnessError::Process(format!("progress request: {error}")))?;
            let response = timeout(WAIT, handle.await_response())
                .await
                .map_err(|_| HarnessError::Timeout("progress timed out".into()))?
                .map_err(|error| HarnessError::Process(format!("progress: {error}")))?;
            evidence.progress_result_exact = call_result(response)
                .and_then(|result| text_of(&result))
                .as_deref()
                == Some("done");
            handler
                .wait_for(WAIT, |handler| {
                    handler.progress().len() as u64 >= PROGRESS_STEPS
                })
                .await;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let received = handler
                .progress()
                .iter()
                .map(|(value, _)| *value as u64)
                .collect::<Vec<_>>();
            // The handler proves the multiset; the wire ledger proves the
            // order (M3-29: rmcp ran two handlers out of order on a hosted
            // runner while the wire order was exact).
            evidence.progress_handler_order_exact =
                received == (1..=PROGRESS_STEPS).collect::<Vec<_>>();
            evidence.progress_values = {
                let mut sorted = received;
                sorted.sort_unstable();
                sorted
            };
            let logged = timeout(
                WAIT,
                client.call_tool(CallToolRequestParams::new("log").with_arguments(arguments(
                    serde_json::json!({"label": label, "count": LOG_COUNT}),
                ))),
            )
            .await
            .map_err(|_| HarnessError::Timeout("log timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("log: {error}")))?;
            evidence.log_result_exact =
                text_of(&logged).as_deref() == Some(format!("logged-{LOG_COUNT}").as_str());
            handler
                .wait_for(WAIT, |handler| handler.logs().len() as u64 >= LOG_COUNT)
                .await;
            let logs = handler.logs();
            let received = logs
                .iter()
                .filter_map(|data| data["seq"].as_u64())
                .collect::<Vec<_>>();
            evidence.log_handler_order_exact = received == (0..LOG_COUNT).collect::<Vec<_>>();
            evidence.log_seqs = {
                let mut sorted = received;
                sorted.sort_unstable();
                sorted
            };
            let mut sorted_logs = logs.clone();
            sorted_logs.sort_by_key(|data| data["seq"].as_u64().unwrap_or(u64::MAX));
            evidence.log_data_exact = sorted_logs.len() as u64 == LOG_COUNT
                && sorted_logs.iter().enumerate().all(|(index, data)| {
                    *data == tunnel_mcp_fixture::log_data(&label, index as u64)
                });
            Ok::<_, HarnessError>(())
        }
        .await;
        Self::close(client, &ledger).await;
        outcome?;
        evidence.wire = ledger.counts();
        Ok(evidence)
    }

    async fn cancellation(&mut self, combo: &Combo) -> Result<CancellationEvidence> {
        let label = combo.label("cancel");
        let sleep_before = combo.invocations("sleep");
        let (client, _handler, ledger) = self.connect(combo).await?;
        let mut evidence = CancellationEvidence::default();
        let export_before = self.export(combo);
        let outcome = async {
            let handle = client
                .send_cancellable_request(
                    call_request(
                        "sleep",
                        serde_json::json!({"label": label, "descendant": combo.stdio()}),
                    ),
                    PeerRequestOptions::no_options(),
                )
                .await
                .map_err(|error| HarnessError::Process(format!("sleep request: {error}")))?;
            let deadline = Instant::now() + WAIT;
            while combo.invocations("sleep") == sleep_before && Instant::now() < deadline {
                sleep(POLL).await;
            }
            let descendant = if combo.stdio() {
                let pid = wait_pid_file(
                    &combo.marker(&tunnel_mcp_fixture::descendant_pid_file(&label)),
                    WAIT,
                )
                .await
                .ok_or_else(|| HarnessError::Timeout("descendant pid file missing".into()))?;
                self.descendant_pids.push(pid);
                Some(pid)
            } else {
                None
            };
            (evidence.stream_id, evidence.operation_id) = self.call_stream(&label).await?;
            timeout(
                WAIT,
                handle.cancel(Some("synthetic gate cancel".to_owned())),
            )
            .await
            .map_err(|_| HarnessError::Timeout("cancel timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("cancel: {error}")))?;
            evidence.server_observed_cancel =
                wait_file(&combo.marker(&format!("cancelled-{label}")), WAIT).await;
            if combo.current()
                && let Some(pid) = descendant
            {
                evidence.descendant_killed = Some(wait_process_gone(pid, PROCESS_EXIT_BOUND).await);
            }
            // A consumer that leaves before any response head used to be
            // recorded by the owner (RESET) but not by the ingress (M3-14).
            // The ingress now records it however the consumer leaves, so once
            // the owner has recorded the cancellation the ingress record is
            // waited for and required (see the validator).
            let mut records = self
                .stream_records(evidence.stream_id, &evidence.operation_id, Duration::ZERO)
                .await;
            if records.owner_release == "reset"
                && records.owner_reset_reason == Some(CANCELLED)
                && !records.ingress_seen
            {
                records = self
                    .stream_records(evidence.stream_id, &evidence.operation_id, WAIT)
                    .await;
            }
            evidence.owner_release = records.owner_release;
            evidence.owner_reset_reason = records.owner_reset_reason;
            evidence.ingress_record = records
                .ingress_seen
                .then(|| records.ingress_error.unwrap_or_else(|| "none".to_owned()));
            evidence.follow_up_ok =
                timeout(WAIT, client.call_tool(CallToolRequestParams::new("echo")))
                    .await
                    .is_ok_and(|result| result.is_ok());
            Ok::<_, HarnessError>(descendant)
        }
        .await;
        Self::close(client, &ledger).await;
        let descendant = outcome?;
        if !combo.current()
            && let Some(pid) = descendant
        {
            // 2025: the session ends with the client (DELETE).
            evidence.descendant_killed = Some(wait_process_gone(pid, PROCESS_EXIT_BOUND).await);
        }
        let export_after = self.export(combo);
        evidence.bridge_cancel_notifications =
            export_after.cancel_notifications_sent - export_before.cancel_notifications_sent;
        evidence.invocations = combo.invocations("sleep") - sleep_before;
        evidence.wire = ledger.counts();
        evidence.cancelled_call_responses =
            evidence.wire.result("tools/call:sleep") + evidence.wire.error("tools/call:sleep");
        Ok(evidence)
    }

    #[allow(clippy::too_many_lines)]
    async fn crash(&mut self, combo: &Combo) -> Result<CrashEvidence> {
        let label = combo.label("crash");
        let crash_before = combo.invocations("crash");
        let (client, handler, ledger) = self.connect(combo).await?;
        let mut evidence = CrashEvidence::default();
        let export_before = self.export(combo);
        let lifecycle = if combo.current() {
            "server/discover"
        } else {
            "initialize"
        };
        let outcome = async {
            let handle = client
                .send_cancellable_request(
                    call_request(
                        "crash",
                        serde_json::json!({"label": label, "descendant": combo.stdio()}),
                    ),
                    PeerRequestOptions::no_options(),
                )
                .await
                .map_err(|error| HarnessError::Process(format!("crash request: {error}")))?;
            let release = format!("crash{label}");
            if !wait_file(
                &combo.marker(&tunnel_mcp_fixture::waiting_marker(&release)),
                WAIT,
            )
            .await
            {
                return Err(HarnessError::Timeout("crash tool never waited".into()));
            }
            let descendant = if combo.stdio() {
                let pid = wait_pid_file(
                    &combo.marker(&tunnel_mcp_fixture::descendant_pid_file(&label)),
                    WAIT,
                )
                .await
                .ok_or_else(|| HarnessError::Timeout("descendant pid file missing".into()))?;
                self.descendant_pids.push(pid);
                Some(pid)
            } else {
                None
            };
            let expected = format!("before-crash:{label}");
            evidence.progress_before_crash = handler
                .wait_for(WAIT, |handler| {
                    handler
                        .progress()
                        .iter()
                        .any(|(_, message)| message.as_deref() == Some(expected.as_str()))
                })
                .await;
            let lifecycle_before = combo.discoveries(lifecycle);
            let spawned_before = self.export(combo).children_spawned;
            combo.release(&release)?;
            if !combo.stdio() {
                let backend = self
                    .backends
                    .get_mut(combo.service.label)
                    .ok_or_else(|| HarnessError::Process("backend missing".into()))?;
                evidence.backend_exited = Some(backend.wait_exit(PROCESS_EXIT_BOUND).await);
                // The operator's supervisor restarts the local server as soon
                // as it exits; the device export never does.  A resumption
                // the client attempts reaches a server without the session.
                backend.restart().await?;
            }
            match timeout(WAIT, handle.await_response()).await {
                Ok(Ok(_)) => evidence.call_failed = false,
                Ok(Err(error)) => {
                    evidence.call_failed = true;
                    let text = format!("{error} {error:?}");
                    evidence.error_leaks_stderr = text.contains(tunnel_mcp_fixture::STDERR_MARKER);
                }
                Err(_) => evidence.call_failed = false,
            }
            if let Some(pid) = descendant {
                evidence.descendant_killed = Some(wait_process_gone(pid, PROCESS_EXIT_BOUND).await);
            }
            for attempt in 1..=2 {
                evidence.follow_up_attempts = attempt;
                if timeout(WAIT, client.call_tool(CallToolRequestParams::new("echo")))
                    .await
                    .is_ok_and(|result| result.is_ok())
                {
                    evidence.follow_up_ok = true;
                    break;
                }
            }
            evidence.lifecycle_dispatches_after_crash =
                combo.discoveries(lifecycle) - lifecycle_before;
            evidence.children_spawned_after_crash =
                self.export(combo).children_spawned - spawned_before;
            Ok::<_, HarnessError>(())
        }
        .await;
        Self::close(client, &ledger).await;
        outcome?;
        let export_after = self.export(combo);
        evidence.export_interrupted = export_after.interrupted - export_before.interrupted;
        evidence.sessions_ended = export_after.sessions_ended - export_before.sessions_ended;
        evidence.invocations = combo.invocations("crash") - crash_before;
        evidence.wire = ledger.counts();
        evidence.crash_responses =
            evidence.wire.result("tools/call:crash") + evidence.wire.error("tools/call:crash");
        Ok(evidence)
    }

    async fn held(&mut self, combo: &Combo, discovery: bool) -> Result<HeldRotationEvidence> {
        let label = combo.label("held");
        let (release, dispatch_count): (String, Box<dyn Fn() -> u64 + Send>) = if discovery {
            let path = combo.marker("discovery.log");
            (
                tunnel_mcp_fixture::DISCOVERY_RELEASE.to_owned(),
                Box::new(move || count_lines(&path, "tools/list")),
            )
        } else {
            let path = combo.marker("invocations.log");
            (
                format!("gate{label}"),
                Box::new(move || count_lines(&path, "gate")),
            )
        };
        for stale in [
            tunnel_mcp_fixture::waiting_marker(&release),
            tunnel_mcp_fixture::release_marker(&release),
        ] {
            let _ = std::fs::remove_file(combo.marker(&stale));
        }
        let (client, _handler, ledger) = self.connect(combo).await?;
        let before = dispatch_count();
        let mut evidence = HeldRotationEvidence::default();
        let outcome = async {
            let peer = client.peer().clone();
            let call = if discovery {
                std::fs::write(combo.marker(tunnel_mcp_fixture::HOLD_DISCOVERY), b"hold")
                    .map_err(HarnessError::Io)?;
                tokio::spawn(async move {
                    peer.list_all_tools()
                        .await
                        .map(|tools| tools.iter().any(|tool| tool.name == "gate"))
                        .unwrap_or(false)
                })
            } else {
                let expected = format!("released-{label}");
                let label = label.clone();
                tokio::spawn(async move {
                    peer.call_tool(
                        CallToolRequestParams::new("gate")
                            .with_arguments(arguments(serde_json::json!({"label": label}))),
                    )
                    .await
                    .ok()
                    .and_then(|result| text_of(&result))
                        == Some(expected)
                })
            };
            if !wait_file(
                &combo.marker(&tunnel_mcp_fixture::waiting_marker(&release)),
                WAIT,
            )
            .await
            {
                call.abort();
                return Err(HarnessError::Timeout(format!("{label}: never held")));
            }
            (evidence.stream_id, evidence.operation_id) = self.call_stream(&label).await?;
            let after = self.rotations_completed().await?;
            let observation = self
                .wait_observation(
                    &label,
                    evidence.stream_id,
                    &evidence.operation_id,
                    after,
                    held_position,
                )
                .await;
            combo.release(&release)?;
            evidence.observation = Some(observation?);
            evidence.result_exact = timeout(WAIT, call)
                .await
                .map_err(|_| HarnessError::Timeout(format!("{label}: answer timed out")))?
                .unwrap_or(false);
            evidence.device_error = self
                .stream_records(evidence.stream_id, &evidence.operation_id, WAIT)
                .await
                .error(false);
            Ok::<_, HarnessError>(())
        }
        .await;
        Self::close(client, &ledger).await;
        for stale in [
            tunnel_mcp_fixture::waiting_marker(&release),
            tunnel_mcp_fixture::release_marker(&release),
        ] {
            let _ = std::fs::remove_file(combo.marker(&stale));
        }
        outcome?;
        evidence.dispatches = dispatch_count() - before;
        evidence.wire = ledger.counts();
        Ok(evidence)
    }

    async fn streaming(&mut self, combo: &Combo) -> Result<StreamingEvidence> {
        let label = combo.label("stream");
        let stream_before = combo.invocations("stream");
        let (client, handler, ledger) = self.connect(combo).await?;
        let mut evidence = StreamingEvidence::default();
        let spawned_before = self.export(combo).children_spawned;
        let outcome = async {
            let handle = client
                .send_cancellable_request(
                    call_request(
                        "stream",
                        serde_json::json!({
                            "label": label,
                            "events": STREAM_EVENTS,
                            "bytes": STREAM_EVENT_BYTES,
                            "gates": STREAM_GATES,
                        }),
                    ),
                    PeerRequestOptions::no_options(),
                )
                .await
                .map_err(|error| HarnessError::Process(format!("stream request: {error}")))?;
            let mut after = None;
            for gate in STREAM_GATES {
                let release = format!("stream{label}g{gate}");
                if !wait_file(
                    &combo.marker(&tunnel_mcp_fixture::waiting_marker(&release)),
                    WAIT,
                )
                .await
                {
                    return Err(HarnessError::Timeout(format!(
                        "{label}: gate {gate} never reached"
                    )));
                }
                if evidence.stream_id == 0 {
                    (evidence.stream_id, evidence.operation_id) = self.call_stream(&label).await?;
                }
                let since = match after {
                    Some(rotation) => rotation,
                    None => self.rotations_completed().await?,
                };
                let observation = self
                    .wait_observation(&label, evidence.stream_id, &evidence.operation_id, since, mid_stream_position)
                    .await?;
                after = Some(observation.rotation);
                evidence.observations.push(observation);
                combo.release(&release)?;
            }
            let response = timeout(WAIT, handle.await_response())
                .await
                .map_err(|_| HarnessError::Timeout(format!("{label}: result timed out")))?
                .map_err(|error| HarnessError::Process(format!("{label}: {error}")))?;
            evidence.result_exact = call_result(response).and_then(|result| text_of(&result))
                == Some(tunnel_mcp_fixture::stream_result(
                    &label,
                    STREAM_EVENTS,
                    STREAM_EVENT_BYTES,
                ));
            handler
                .wait_for(WAIT, |handler| {
                    handler.progress().len() as u64 >= STREAM_EVENTS
                })
                .await;
            let progress = handler.progress();
            evidence.events_received = progress.len() as u64;
            let expected = expected_stream_messages(&label);
            #[allow(clippy::cast_precision_loss)]
            let mismatch = progress.iter().zip(expected.iter()).enumerate().find(
                |(index, ((value, message), expected))| {
                    *value != (*index + 1) as f64 || message.as_deref() != Some(expected.as_str())
                },
            );
            // Wire order is authoritative: rmcp may run notification
            // handlers concurrently, so the handler proves the multiset.
            let wire_counts = ledger.counts();
            let mut received = progress
                .iter()
                .filter_map(|(_, message)| message.clone())
                .collect::<Vec<_>>();
            received.sort_unstable();
            let mut sorted_expected = expected.clone();
            sorted_expected.sort_unstable();
            evidence.handler_order_exact = progress.len() == expected.len() && mismatch.is_none();
            evidence.events_exact_in_order = received == sorted_expected
                && wire_counts.progress_values == (1..=STREAM_EVENTS).collect::<Vec<_>>()
                && wire_counts.progress_digest == expected_stream_digest(&label);
            if let Some((index, ((value, message), expected))) = mismatch {
                // Payload-free: the index and which field differed.
                #[allow(clippy::cast_precision_loss)]
                let value_ok = *value == (index + 1) as f64;
                eprintln!(
                    "MCP cloud-client {label}: first stream mismatch at event {index}: value_ok={value_ok} message_ok={} message_len={:?} expected_len={}",
                    message.as_deref() == Some(expected.as_str()),
                    message.as_ref().map(String::len),
                    expected.len()
                );
            }
            let records = self.stream_records(evidence.stream_id, &evidence.operation_id, WAIT).await;
            evidence.device_error = records.error(false);
            evidence.ingress_error = records.error(true);
            Ok::<_, HarnessError>(())
        }
        .await;
        Self::close(client, &ledger).await;
        outcome?;
        evidence.children_spawned = self.export(combo).children_spawned - spawned_before;
        evidence.invocations = combo.invocations("stream") - stream_before;
        evidence.wire = ledger.counts();
        Ok(evidence)
    }
}

/// The device runtime configuration: the harness device profile's file plus
/// one `[exports.<service>.mcp]` table per seeded MCP service, parsed and
/// validated by `tunnel-client` exactly as `tunnel-client connect` loads it.
fn device_config_text(
    base: &str,
    combos: &[Combo],
    fixture: &Path,
    backends: &BTreeMap<&'static str, HttpBackend>,
) -> Result<String> {
    let quote = |value: &str| serde_json::to_string(value).unwrap_or_default();
    let mut text = base.to_owned();
    for combo in combos {
        let service = combo.service.service_id;
        text.push_str(&format!(
            "\n[exports.\"{service}\"]\ntype = \"http-forward\"\n\n[exports.\"{service}\".mcp]\nprofile = {}\n\n[exports.\"{service}\".mcp.backend]\n",
            quote(combo.service.profile)
        ));
        if combo.stdio() {
            text.push_str(&format!(
                "kind = \"stdio\"\ncommand = {}\nargs = [\"stdio\"]\nworkspace = {}\nmax_children = 8\nsession_idle_seconds = 600\n",
                quote(&fixture.to_string_lossy()),
                quote(&combo.marker_dir.to_string_lossy()),
            ));
        } else {
            let backend = backends
                .get(combo.service.label)
                .ok_or_else(|| HarnessError::InvalidInput("HTTP backend missing".into()))?;
            text.push_str(&format!(
                "kind = \"streamable-http\"\nurl = {}\n",
                quote(&format!("http://{}/mcp", backend.address))
            ));
        }
    }
    Ok(text)
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<McpCloudClientEvidence> {
    let options = HarnessOptions::from_env()?
        .mcp_services(true)
        .rotation(MCP_GATE_ROTATION);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("MCP gate harness startup timed out".into()))??;
    // The relays serve the pinned profiles exactly as `serve` builds them
    // from `[http_forward] profiles`.
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
            if let Err(error) = validate_mcp_cloud_client_evidence(&evidence) {
                // Payload-free: identifiers, positions, counters and labels.
                eprintln!("MCP cloud-client evidence: {evidence:?}");
                return Err(error);
            }
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "MCP cloud-client scenario exceeded its bounded deadline".into(),
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
) -> Result<McpCloudClientEvidence> {
    let mut evidence = McpCloudClientEvidence {
        relay_count: cluster.relays.len(),
        relay_profiles,
        resign_spacing_ms: MEMBERSHIP_RESIGN_SPACING.as_millis(),
        not_covered: NOT_COVERED.iter().map(|item| (*item).to_owned()).collect(),
        ..McpCloudClientEvidence::default()
    };
    evidence.relay_profiles.sort();
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("MCP gate device is missing".into()))?;
    let echo_service = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("MCP gate echo service missing".into()))?;
    if harness.mcp_services.len() != crate::MCP_GATE_SERVICES.len() {
        return Err(HarnessError::InvalidInput(
            "MCP services were not seeded".into(),
        ));
    }
    let fixture = fixture_binary_path()?;
    let root = tempfile::tempdir().map_err(HarnessError::Io)?;
    let root_path = root.path().canonicalize().map_err(HarnessError::Io)?;
    let combos = harness
        .mcp_services
        .iter()
        .enumerate()
        .map(|(ordinal, service)| {
            let marker_dir = root_path.join(service.label);
            std::fs::create_dir_all(&marker_dir).map_err(HarnessError::Io)?;
            Ok(Combo {
                service: *service,
                kind: if service.label.starts_with("stdio") {
                    KIND_STDIO
                } else {
                    KIND_HTTP
                },
                marker_dir,
                ordinal,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut backends = BTreeMap::new();
    for combo in combos.iter().filter(|combo| !combo.stdio()) {
        match HttpBackend::start(&fixture, &combo.marker_dir, !combo.current()).await {
            Ok(backend) => {
                backends.insert(combo.service.label, backend);
            }
            Err(error) => {
                for backend in backends.values_mut() {
                    backend.stop().await;
                }
                return Err(error);
            }
        }
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
        "m3-mcp-cloud-client-canary",
        owner_device_addr,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let base = std::fs::read_to_string(&device_profile.config_path).map_err(HarnessError::Io)?;
    let text = device_config_text(&base, &combos, &fixture, &backends)?;
    let mut config = tunnel_client::ConnectConfig::parse(&text)
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;
    config.rotation = MCP_GATE_ROTATION;
    config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;
    evidence.ingress_node = "relay-c".to_owned();
    let ingress_addr = cluster.relay("relay-c")?.consumer_addr()?;
    let ingress_before = cluster.relay("relay-c")?.snapshot().await?.http_forward;
    let owner_before = cluster.relay("relay-a")?.snapshot().await?.http_forward;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            scope: Some("echo:invoke http:invoke".to_owned()),
            ..OidcTokenOptions::default()
        },
    )?;
    let ca = harness.pki.server_ca.certificate_der.clone();
    let sidecar = Sidecar::start(ingress_addr, &ca)?;
    let mut gate = Gate {
        cluster,
        config,
        tenant_id: device.tenant_id,
        client: None,
        device_diagnostics: DeviceHttpDiagnostics::default(),
        mcp_diagnostics: McpExportDiagnostics::default(),
        sidecar,
        backends,
        device_id: device.id,
        service_ids: combos
            .iter()
            .map(|combo| (combo.service.label, combo.service.service_id.to_string()))
            .collect(),
        token,
        ca,
        // The bootstrap records were signed when the cluster started, so
        // the first case boundary re-signs.
        membership_signed_at: Instant::now()
            .checked_sub(MEMBERSHIP_RESIGN_SPACING)
            .unwrap_or_else(Instant::now),
        session_id: String::new(),
        last_stream_id: 0,
        descendant_pids: Vec::new(),
        freeze: Arc::new(FreezeWatch::default()),
        freeze_task: None,
    };
    let only_cases = std::env::var("M3_MCP_CASES").ok();
    let only_combos = std::env::var("M3_MCP_COMBOS").ok();
    let selected = |filter: &Option<String>, name: &str| {
        filter
            .as_deref()
            .is_none_or(|only| only.split(',').any(|selected| selected == name))
    };
    let started = Instant::now();
    let run_result = async {
        let probe = combos
            .iter()
            .find(|combo| combo.stdio() && combo.current())
            .ok_or_else(|| HarnessError::InvalidInput("stdio 2026 service missing".into()))?;
        for combo in &combos {
            if !selected(&only_combos, combo.service.label) {
                continue;
            }
            // Each combination gets its own device session: a session admits
            // at most 128 streams in its lifetime (M7-C82).
            let owner_node = gate.connect_device().await?;
            // relay-c must route to the new session's owner token before the
            // first case: a request resolved against the previous session is
            // refused with an unknown outcome.
            gate.wait_route_ready(probe).await?;
            evidence.device_sessions += 1;
            evidence.owner_node = owner_node;
            evidence.non_owner_ingress = evidence.owner_node == "relay-a";
            evidence.combos.push(McpComboEvidence {
                kind: combo.kind.to_owned(),
                profile: combo.service.profile.to_owned(),
                ..McpComboEvidence::default()
            });
            for case in MCP_CASES {
                if !selected(&only_cases, case) {
                    continue;
                }
                // Progress labels only: combination, case and elapsed time.
                eprintln!(
                    "MCP cloud-client gate: {} {case} at {} ms",
                    combo.service.label,
                    started.elapsed().as_millis()
                );
                gate.boundary(probe).await?;
                // Each case's evidence is stored and printed as soon as it
                // exists (payload-free), so a later failure keeps it.
                let recorded = match case {
                    "discovery" => format!("{:?}", {
                        let case = gate.discovery(combo).await?;
                        last_combo(&mut evidence)?.discovery = case.clone();
                        case
                    }),
                    "notifications" => format!("{:?}", {
                        let case = gate.notifications(combo).await?;
                        last_combo(&mut evidence)?.notifications = case.clone();
                        case
                    }),
                    "cancellation" => format!("{:?}", {
                        let case = gate.cancellation(combo).await?;
                        last_combo(&mut evidence)?.cancellation = case.clone();
                        case
                    }),
                    "crash" => format!("{:?}", {
                        let case = gate.crash(combo).await?;
                        last_combo(&mut evidence)?.crash = case.clone();
                        case
                    }),
                    "rotation-discovery" => format!("{:?}", {
                        let case = gate.held(combo, true).await?;
                        last_combo(&mut evidence)?.rotation_discovery = case.clone();
                        case
                    }),
                    "rotation-invocation" => format!("{:?}", {
                        let case = gate.held(combo, false).await?;
                        last_combo(&mut evidence)?.rotation_invocation = case.clone();
                        case
                    }),
                    "streaming" => format!("{:?}", {
                        let case = gate.streaming(combo).await?;
                        last_combo(&mut evidence)?.streaming = case.clone();
                        case
                    }),
                    _ => String::new(),
                };
                evidence.max_membership_age_at_case_end_ms = evidence
                    .max_membership_age_at_case_end_ms
                    .max(gate.membership_signed_at.elapsed().as_millis());
                eprintln!(
                    "MCP cloud-client case {} {case} at {} ms: {recorded}",
                    combo.service.label,
                    started.elapsed().as_millis()
                );
            }
            gate.wait_no_streams().await?;
            let snapshot = gate.owner_snapshot().await?;
            let owner_session = gate.session(&snapshot)?;
            let rotations = owner_session.rotations_completed;
            let stable = owner_session.session_id == gate.session_id
                && gate.client.as_ref().is_some_and(|client| {
                    client.status_snapshot().session_id.as_deref() == Some(gate.session_id.as_str())
                });
            let highest_stream = gate.last_stream_id;
            let combo_evidence = last_combo(&mut evidence)?;
            combo_evidence.session_stable = stable;
            combo_evidence.session_rotations = rotations;
            combo_evidence.highest_call_stream_id = highest_stream;
            evidence.rotations_completed += rotations;
            gate.stop_device().await?;
            last_combo(&mut evidence)?.children_running_after_stop = gate.children_running();
        }
        evidence.device_session_stable =
            !evidence.combos.is_empty() && evidence.combos.iter().all(|combo| combo.session_stable);
        evidence.sidecar_connections = gate.sidecar.connections();
        evidence.ingress_exchanges_recorded = gate
            .cluster
            .relay("relay-c")?
            .snapshot()
            .await?
            .http_forward
            .exchanges_recorded
            - ingress_before.exchanges_recorded;
        let owner_after = gate.cluster.relay("relay-a")?.snapshot().await?;
        evidence.owner_exchanges_recorded =
            owner_after.http_forward.exchanges_recorded - owner_before.exchanges_recorded;
        evidence.owner_freeze_hold = owner_after.rotation_freeze_hold;
        Ok::<_, HarnessError>(())
    }
    .await;
    if run_result.is_err() {
        eprintln!("MCP cloud-client partial evidence: {evidence:?}");
        gate.print_failure_state().await;
    }
    let stop = gate.stop_device().await;
    let mut pids = std::mem::take(&mut gate.descendant_pids);
    let mut backends = std::mem::take(&mut gate.backends);
    drop(gate);
    for backend in backends.values_mut() {
        pids.extend(backend.pids.iter().copied());
        backend.stop().await;
    }
    // Stopping the device ends every legacy session and so every child.
    for pid in &pids {
        let _ = wait_process_gone(*pid, PROCESS_EXIT_BOUND).await;
    }
    evidence.leftover_processes = pids.iter().filter(|pid| process_exists(**pid)).count() as u64;
    drop(root);
    run_result?;
    stop?;
    Ok(evidence)
}

fn last_combo(evidence: &mut McpCloudClientEvidence) -> Result<&mut McpComboEvidence> {
    evidence
        .combos
        .last_mut()
        .ok_or_else(|| HarnessError::Process("no combination is running".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_relay::http_forward_diagnostics::HttpRecordPosition;

    fn observation(stream_id: u64, rotation: u64) -> HttpRotationObservation {
        HttpRotationObservation {
            stream_id,
            operation_id: format!("operation-{stream_id}"),
            rotation,
            old_generation: rotation,
            new_generation: rotation + 1,
            frozen_last_emitted: 7,
            relay_fence: Some(7),
            relay_acknowledged: Some(7),
            connector_fence: Some(4),
            connector_acknowledged: Some(4),
            request: HttpRecordPosition {
                heads: 1,
                ends: 1,
                body_bytes: 64,
                total_bytes: 96,
                position: "boundary",
                ..HttpRecordPosition::default()
            },
            request_fin_sequenced: true,
            response: HttpRecordPosition {
                heads: 1,
                body_bytes: 4096,
                total_bytes: 4200,
                position: "boundary",
                ..HttpRecordPosition::default()
            },
            ..HttpRotationObservation::default()
        }
    }

    fn counts(pairs: &[(&str, u64)], results: &[(&str, u64)]) -> WireCounts {
        WireCounts {
            posts: pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect(),
            results: results
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect(),
            ..WireCounts::default()
        }
    }

    #[allow(clippy::too_many_lines)]
    fn combo(kind: &str, profile: &str, rotation_base: u64) -> McpComboEvidence {
        let current = profile == PROFILE_2026;
        let stdio = kind == KIND_STDIO;
        let lifecycle = if current {
            "server/discover"
        } else {
            "initialize"
        };
        McpComboEvidence {
            kind: kind.to_owned(),
            profile: profile.to_owned(),
            session_stable: true,
            session_rotations: 5,
            highest_call_stream_id: 40,
            children_running_after_stop: 0,
            discovery: DiscoveryEvidence {
                negotiated_version: protocol_of(profile).to_owned(),
                lifecycle_dispatches: 1,
                foreign_lifecycle_dispatches: 0,
                tools_list_dispatches: 1,
                tools_complete: true,
                echo_arguments_exact: true,
                echo_meta_exact: true,
                echo_protocol_meta_exact: current,
                echo_image_exact: true,
                echo_invocations: 1,
                wire: WireCounts {
                    session_headers: u64::from(!current),
                    ..counts(&[(lifecycle, 1)], &[("tools/call:echo", 1)])
                },
            },
            notifications: NotificationEvidence {
                progress_values: (1..=PROGRESS_STEPS).collect(),
                progress_handler_order_exact: true,
                progress_result_exact: true,
                log_seqs: (0..LOG_COUNT).collect(),
                log_data_exact: true,
                log_handler_order_exact: true,
                log_result_exact: true,
                wire: WireCounts {
                    progress_values: (1..=PROGRESS_STEPS).collect(),
                    log_seqs: (0..LOG_COUNT).collect(),
                    logs_on_request_streams: if current { LOG_COUNT } else { 0 },
                    logs_on_standalone_streams: if current { 0 } else { LOG_COUNT },
                    standalone_opened: u64::from(!current),
                    ..WireCounts::default()
                },
            },
            cancellation: CancellationEvidence {
                stream_id: 3,
                operation_id: "operation-3".to_owned(),
                invocations: 1,
                server_observed_cancel: true,
                cancelled_call_responses: 0,
                bridge_cancel_notifications: u64::from(current && stdio),
                descendant_killed: stdio.then_some(true),
                owner_release: "reset".to_owned(),
                owner_reset_reason: Some(CANCELLED),
                ingress_record: Some("HTTP_CANCELLED".to_owned()),
                follow_up_ok: true,
                wire: counts(&[("notifications/cancelled", u64::from(!current))], &[]),
            },
            crash: CrashEvidence {
                progress_before_crash: true,
                call_failed: true,
                error_leaks_stderr: false,
                crash_responses: 0,
                invocations: 1,
                follow_up_ok: true,
                follow_up_attempts: 1,
                lifecycle_dispatches_after_crash: u64::from(!current),
                children_spawned_after_crash: u64::from(stdio),
                export_interrupted: u64::from(stdio),
                sessions_ended: u64::from(stdio && !current),
                descendant_killed: stdio.then_some(true),
                backend_exited: (!stdio).then_some(true),
                wire: WireCounts {
                    session_expired: u64::from(!current),
                    ..counts(&[("tools/call:crash", 1)], &[])
                },
            },
            rotation_discovery: HeldRotationEvidence {
                stream_id: 5,
                operation_id: "operation-5".to_owned(),
                observation: Some(observation(5, rotation_base)),
                dispatches: 1,
                result_exact: true,
                device_error: None,
                wire: counts(&[("tools/list", 1)], &[]),
            },
            rotation_invocation: HeldRotationEvidence {
                stream_id: 6,
                operation_id: "operation-6".to_owned(),
                observation: Some(observation(6, rotation_base + 1)),
                dispatches: 1,
                result_exact: true,
                device_error: None,
                wire: counts(&[("tools/call:gate", 1)], &[]),
            },
            streaming: StreamingEvidence {
                stream_id: 7,
                operation_id: "operation-7".to_owned(),
                events_received: STREAM_EVENTS,
                events_exact_in_order: true,
                handler_order_exact: true,
                result_exact: true,
                observations: vec![
                    observation(7, rotation_base + 2),
                    observation(7, rotation_base + 3),
                    observation(7, rotation_base + 4),
                ],
                invocations: 1,
                children_spawned: u64::from(stdio && current),
                device_error: None,
                ingress_error: None,
                wire: counts(&[("tools/call:stream", 1)], &[("tools/call:stream", 1)]),
            },
        }
    }

    fn passing() -> McpCloudClientEvidence {
        McpCloudClientEvidence {
            relay_count: 3,
            owner_node: "relay-a".into(),
            ingress_node: "relay-c".into(),
            non_owner_ingress: true,
            relay_profiles: vec![PROFILE_2025.into(), PROFILE_2026.into()],
            device_sessions: 4,
            device_session_stable: true,
            rotations_completed: 20,
            sidecar_connections: 100,
            ingress_exchanges_recorded: 90,
            owner_exchanges_recorded: 90,
            combos: vec![
                combo(KIND_STDIO, PROFILE_2026, 1),
                combo(KIND_STDIO, PROFILE_2025, 6),
                combo(KIND_HTTP, PROFILE_2026, 11),
                combo(KIND_HTTP, PROFILE_2025, 16),
            ],
            leftover_processes: 0,
            resign_spacing_ms: MEMBERSHIP_RESIGN_SPACING.as_millis(),
            max_membership_age_at_case_end_ms: 30_000,
            owner_freeze_hold: tunnel_relay::RotationFreezeHoldSnapshot::default(),
            not_covered: NOT_COVERED.iter().map(|item| (*item).to_owned()).collect(),
        }
    }

    #[test]
    fn positions_distinguish_held_and_mid_stream() {
        let open = observation(1, 1);
        assert!(held_position(&open) && mid_stream_position(&open));
        let mut unanswered = open.clone();
        unanswered.response = HttpRecordPosition::default();
        assert!(held_position(&unanswered) && !mid_stream_position(&unanswered));
        let mut answered = open.clone();
        answered.response.ends = 1;
        assert!(!held_position(&answered));
        let mut unsent = open;
        unsent.request_fin_sequenced = false;
        assert!(!held_position(&unsent));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn validator_accepts_passing_evidence_and_rejects_every_single_mutation() {
        validate_mcp_cloud_client_evidence(&passing()).expect("passing evidence");
        type Mutation = (&'static str, fn(&mut McpCloudClientEvidence));
        let mutations: Vec<Mutation> = vec![
            ("relays", |e| e.relay_count = 2),
            ("owner ingress", |e| e.non_owner_ingress = false),
            ("ingress node", |e| e.ingress_node = "relay-a".into()),
            ("profiles", |e| {
                e.relay_profiles.pop();
            }),
            ("session", |e| e.device_session_stable = false),
            ("sessions", |e| e.device_sessions = 1),
            ("sidecar", |e| e.sidecar_connections = 0),
            ("ingress exchanges", |e| e.ingress_exchanges_recorded = 0),
            ("owner exchanges", |e| e.owner_exchanges_recorded = 1),
            ("leftover", |e| e.leftover_processes = 1),
            ("resign spacing", |e| e.resign_spacing_ms = 1),
            ("membership age", |e| {
                e.max_membership_age_at_case_end_ms = 60_000
            }),
            ("refusal outside a freeze", |e| {
                e.combos[0].discovery.wire.not_dispatched_refusals = 1;
            }),
            ("unbounded freeze retries", |e| {
                e.combos[1].streaming.wire.not_dispatched_refusals = NOT_DISPATCHED_RETRIES + 1;
                e.combos[1].streaming.wire.not_dispatched_retries = NOT_DISPATCHED_RETRIES + 1;
            }),
            ("standalone refusal outside a freeze", |e| {
                e.combos[1]
                    .notifications
                    .wire
                    .standalone_not_dispatched_refusals = 1;
            }),
            ("unbounded standalone retries", |e| {
                e.combos[3]
                    .notifications
                    .wire
                    .standalone_not_dispatched_refusals = NOT_DISPATCHED_RETRIES + 1;
                e.combos[3].notifications.wire.standalone_retries = NOT_DISPATCHED_RETRIES + 1;
            }),
            ("unexplained refusal recorded", |e| {
                e.combos[0].crash.wire.unexplained_refusal =
                    Some("not_dispatched refusal outside a rotation freeze".to_owned());
            }),
            ("session stream limit", |e| {
                e.combos[2].highest_call_stream_id = 128;
            }),
            ("no call stream", |e| e.combos[2].highest_call_stream_id = 0),
            ("child outlived its session", |e| {
                e.combos[3].children_running_after_stop = 1;
            }),
            ("2026 standalone stream", |e| {
                e.combos[0].notifications.wire.standalone_opened = 1;
            }),
            ("cancel stream missing", |e| {
                e.combos[1].cancellation.stream_id = 0
            }),
            ("http cancel descendant", |e| {
                e.combos[2].cancellation.descendant_killed = Some(true);
            }),
            ("http crash descendant", |e| {
                e.combos[3].crash.descendant_killed = Some(true);
            }),
            ("2025 bridge cancel notification", |e| {
                e.combos[1].cancellation.bridge_cancel_notifications = 1;
            }),
            ("2026 session expired", |e| {
                e.combos[2].crash.wire.session_expired = 1;
            }),
            ("2026 stdio re-initialized", |e| {
                e.combos[0].crash.lifecycle_dispatches_after_crash = 1;
            }),
            ("2026 http re-initialized", |e| {
                e.combos[2].crash.lifecycle_dispatches_after_crash = 1;
            }),
            ("2025 stdio interrupted", |e| {
                e.combos[1].crash.export_interrupted = 0;
            }),
            ("stdio backend exit", |e| {
                e.combos[0].crash.backend_exited = Some(true);
            }),
            ("stream post missing", |e| {
                e.combos[2].streaming.wire.posts.clear();
            }),
            ("stream result missing", |e| {
                e.combos[2].streaming.wire.results.clear();
            }),
            ("cancel operation missing", |e| {
                e.combos[0].rotation_invocation.operation_id = String::new();
            }),
            ("stream operation missing", |e| {
                e.combos[3].streaming.operation_id = String::new();
            }),
            ("not covered", |e| {
                e.not_covered.pop();
            }),
            ("combo missing", |e| {
                e.combos.pop();
            }),
            ("combo duplicated", |e| {
                e.combos[3] = e.combos[2].clone();
            }),
            ("rotations", |e| e.rotations_completed = 3),
            ("combo session unstable", |e| {
                e.combos[1].session_stable = false
            }),
            ("combo rotations", |e| {
                e.combos[1].session_rotations = 4;
                e.rotations_completed = 19;
            }),
            ("version", |e| {
                e.combos[0].discovery.negotiated_version = "2025-11-25".into();
            }),
            ("lifecycle", |e| {
                e.combos[1].discovery.lifecycle_dispatches = 2
            }),
            ("foreign lifecycle", |e| {
                e.combos[0].discovery.foreign_lifecycle_dispatches = 1;
            }),
            ("lifecycle post", |e| {
                e.combos[0].discovery.wire.posts.clear();
            }),
            ("tools list", |e| {
                e.combos[2].discovery.tools_list_dispatches = 0
            }),
            ("tools", |e| e.combos[2].discovery.tools_complete = false),
            ("echo args", |e| {
                e.combos[3].discovery.echo_arguments_exact = false
            }),
            ("echo meta", |e| {
                e.combos[3].discovery.echo_meta_exact = false
            }),
            ("protocol meta", |e| {
                e.combos[0].discovery.echo_protocol_meta_exact = false;
            }),
            ("image", |e| e.combos[1].discovery.echo_image_exact = false),
            ("echo twice", |e| e.combos[1].discovery.echo_invocations = 2),
            ("echo result", |e| {
                e.combos[1].discovery.wire.results.clear();
            }),
            ("2026 session header", |e| {
                e.combos[0].discovery.wire.session_headers = 1;
            }),
            ("2025 no session header", |e| {
                e.combos[1].discovery.wire.session_headers = 0;
            }),
            ("cancelled stream drained", |e| {
                e.combos[0]
                    .cancellation
                    .wire
                    .drained_by_call
                    .insert("tools/call:sleep".to_owned(), 1);
            }),
            ("progress multiset", |e| {
                e.combos[0].notifications.progress_values.pop();
            }),
            ("progress wire order", |e| {
                e.combos[0].notifications.wire.progress_values.swap(0, 1);
            }),
            ("progress result", |e| {
                e.combos[0].notifications.progress_result_exact = false;
            }),
            ("log seq missing", |e| {
                e.combos[1].notifications.log_seqs.pop();
            }),
            ("log wire order", |e| {
                e.combos[1].notifications.wire.log_seqs.swap(0, 1);
            }),
            ("log data", |e| {
                e.combos[1].notifications.log_data_exact = false
            }),
            ("log result", |e| {
                e.combos[1].notifications.log_result_exact = false
            }),
            ("2026 log on standalone", |e| {
                e.combos[2].notifications.wire.logs_on_request_streams = 0;
                e.combos[2].notifications.wire.logs_on_standalone_streams = LOG_COUNT;
            }),
            ("2025 log on request", |e| {
                e.combos[3].notifications.wire.logs_on_standalone_streams = 0;
                e.combos[3].notifications.wire.logs_on_request_streams = LOG_COUNT;
            }),
            ("2025 no standalone", |e| {
                e.combos[3].notifications.wire.standalone_opened = 0;
            }),
            ("cancel invocations", |e| {
                e.combos[0].cancellation.invocations = 2
            }),
            ("cancel observed", |e| {
                e.combos[1].cancellation.server_observed_cancel = false;
            }),
            ("cancel result delivered", |e| {
                e.combos[2].cancellation.cancelled_call_responses = 1;
            }),
            ("cancel follow-up", |e| {
                e.combos[3].cancellation.follow_up_ok = false
            }),
            ("cancel descendant", |e| {
                e.combos[0].cancellation.descendant_killed = Some(false);
            }),
            ("cancel bridge notification", |e| {
                e.combos[0].cancellation.bridge_cancel_notifications = 0;
            }),
            ("cancel reset reason", |e| {
                e.combos[0].cancellation.owner_reset_reason = None;
            }),
            ("cancel http release", |e| {
                e.combos[2].cancellation.owner_release = String::new();
            }),
            ("cancel owner release", |e| {
                e.combos[0].cancellation.owner_release = "fin".into();
            }),
            ("cancel ingress record missing", |e| {
                e.combos[0].cancellation.ingress_record = None;
            }),
            ("2025 cancel post", |e| {
                e.combos[1].cancellation.wire.posts.clear();
            }),
            ("crash progress", |e| {
                e.combos[0].crash.progress_before_crash = false
            }),
            ("crash succeeded", |e| e.combos[1].crash.call_failed = false),
            ("crash leak", |e| {
                e.combos[2].crash.error_leaks_stderr = true
            }),
            ("crash fabricated", |e| {
                e.combos[3].crash.crash_responses = 1
            }),
            ("crash replay", |e| e.combos[0].crash.invocations = 2),
            ("crash reposted", |e| {
                e.combos[0]
                    .crash
                    .wire
                    .posts
                    .insert("tools/call:crash".into(), 2);
            }),
            ("crash follow-up", |e| {
                e.combos[1].crash.follow_up_ok = false
            }),
            ("crash attempts", |e| {
                e.combos[1].crash.follow_up_attempts = 3
            }),
            ("crash descendant", |e| {
                e.combos[1].crash.descendant_killed = Some(false)
            }),
            ("crash backend", |e| {
                e.combos[2].crash.backend_exited = Some(false)
            }),
            ("2026 stdio interrupted", |e| {
                e.combos[0].crash.export_interrupted = 0
            }),
            ("2026 stdio fresh child", |e| {
                e.combos[0].crash.children_spawned_after_crash = 0;
            }),
            ("2025 session expired", |e| {
                e.combos[3].crash.wire.session_expired = 0;
            }),
            ("2025 reinitialized", |e| {
                e.combos[1].crash.lifecycle_dispatches_after_crash = 0;
            }),
            ("2025 session ended", |e| {
                e.combos[1].crash.sessions_ended = 0
            }),
            ("held discovery observation", |e| {
                e.combos[0].rotation_discovery.observation = None;
            }),
            ("held discovery answered", |e| {
                if let Some(observation) = e.combos[0].rotation_discovery.observation.as_mut() {
                    observation.response.ends = 1;
                }
            }),
            ("held fence", |e| {
                if let Some(observation) = e.combos[1].rotation_invocation.observation.as_mut() {
                    observation.relay_acknowledged = Some(1);
                }
            }),
            ("held stream", |e| {
                e.combos[2].rotation_invocation.stream_id = 99
            }),
            ("held other session's operation", |e| {
                e.combos[2].rotation_discovery.operation_id = "operation-previous".into();
            }),
            ("stream other session's operation", |e| {
                e.combos[1].streaming.observations[1].operation_id = "operation-previous".into();
            }),
            ("held dispatches", |e| {
                e.combos[3].rotation_invocation.dispatches = 2
            }),
            ("held post", |e| {
                e.combos[3].rotation_discovery.wire.posts.clear();
            }),
            ("held result", |e| {
                e.combos[0].rotation_invocation.result_exact = false
            }),
            ("held device error", |e| {
                e.combos[0].rotation_invocation.device_error =
                    Some("HTTP_STREAM_INTERRUPTED".into());
            }),
            ("stream events", |e| {
                e.combos[0].streaming.events_received -= 1
            }),
            ("stream order", |e| {
                e.combos[1].streaming.events_exact_in_order = false
            }),
            ("stream result", |e| {
                e.combos[2].streaming.result_exact = false
            }),
            ("stream one rotation", |e| {
                e.combos[3].streaming.observations.pop();
            }),
            ("stream same rotation", |e| {
                let first = e.combos[3].streaming.observations[0].clone();
                e.combos[3].streaming.observations[1] = first;
            }),
            ("stream ended at observation", |e| {
                e.combos[0].streaming.observations[0].response.ends = 1;
            }),
            ("stream invocations", |e| {
                e.combos[0].streaming.invocations = 2
            }),
            ("stream children", |e| {
                e.combos[0].streaming.children_spawned = 2
            }),
            ("stream legacy children", |e| {
                e.combos[1].streaming.children_spawned = 1
            }),
            ("stream device error", |e| {
                e.combos[2].streaming.device_error = Some("HTTP_STREAM_INTERRUPTED".into());
            }),
            ("stream ingress error", |e| {
                e.combos[3].streaming.ingress_error = Some("HTTP_STREAM_INTERRUPTED".into());
            }),
        ];
        for (name, mutate) in mutations {
            let mut evidence = passing();
            mutate(&mut evidence);
            assert!(
                validate_mcp_cloud_client_evidence(&evidence).is_err(),
                "mutation {name} passed"
            );
        }
    }
}
