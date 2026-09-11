//! M7-I04 fail-closed admission, body-consumption, routing and fallback gate.
//!
//! This module extends the production three-relay admission family with the
//! negative membership, pin, body-consumption and fallback scopes that the
//! existing `verify-m7-admission` matrix leaves open.  Every scenario runs
//! against the real relay serving boundary, the real Redis authority, the built
//! `tunnel-client` process and the public consumer HTTPS/WSS listeners.
//!
//! The central instrument is a *request-body sentinel*: a consumer request body
//! that declares a length and then delivers a controlled number of bytes.  A
//! sentinel that declares bytes, delivers none, and still receives an exact
//! typed rejection well inside the relay's own body deadline is positive
//! evidence that the rejection preceded any body read.  The same sentinel in
//! `Withheld` mode against an *admitted* target reaches the relay's body
//! deadline instead, which proves the body read really is on this route and
//! keeps every zero-delivery rejection non-vacuous.
//!
//! Evidence is payload-free: statuses, allowlisted bounded codes, byte counts,
//! relay application-dispatch counters, owner-side authenticated
//! `ConsumerChunk` read counters, honeypot socket counters, and elapsed
//! milliseconds.  No request body, response payload, token, or credential is
//! retained.

use super::{
    ProductionCluster, RunningHarness, assert_public_health_ready, open_consumer_stream_target,
    public_health_request, start_cli_smoke, validate_public_health_response,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, Result};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Limited};
use hyper::Request;
use hyper::body::{Body, Frame, SizeHint};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Instant as TokioInstant, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// The whole matrix must finish inside this bound.  It deliberately exceeds
/// the relay's own ten-second request-body deadline, which two scenarios
/// reach on purpose.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(240);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
/// One public request's bound.  A withheld-body control case intentionally
/// consumes the relay's body deadline, so this is larger than that deadline.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(25);
/// A rejection that lands inside this bound cannot have waited for a body that
/// was never delivered; the relay's own body deadline is ten seconds.
const PREFLIGHT_BOUND_MS: u64 = 4_000;
/// The withheld-body control case must actually reach the relay's body
/// deadline rather than returning some earlier unrelated rejection.
const BODY_DEADLINE_FLOOR_MS: u64 = 8_000;
const MAX_ERROR_BODY_BYTES: usize = 1024;
const MAX_ECHO_RESPONSE_BYTES: usize = 64 * 1024 + 256;
/// Declared-but-withheld body length.  Small enough to stay far inside every
/// relay body bound, large enough that a completed read is unmistakable.
const WITHHELD_BODY_BYTES: usize = 512;
const HONEYPOT_OBSERVATION: Duration = Duration::from_millis(750);
/// The relay every remote scenario enters through.  It owns neither device, so
/// a peer connection from it to an owner is the legitimate remote hop whose
/// presented server name EC-017 constrains.
const INGRESS_NODE_ID: &str = "relay-c";
const SIBLING_CANARY_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound for the owner-readiness precondition before a must-succeed probe.
const OWNER_READY_TIMEOUT: Duration = Duration::from_secs(20);
const OWNER_READY_POLL: Duration = Duration::from_millis(250);
const OWNER_CLEAR_TIMEOUT: Duration = Duration::from_secs(20);

/// Consumer-controlled inputs that must never be able to name a peer address.
const FORGED_PEER_ENDPOINT_HEADER: &str = "x-agent-tunnel-peer-endpoint";
const FORGED_OWNER_ENDPOINT_HEADER: &str = "x-agent-tunnel-owner-endpoint";
const FORGED_OWNER_NODE_HEADER: &str = "x-agent-tunnel-owner-id";
const FORGED_FORWARDED_HOST_HEADER: &str = "x-forwarded-host";
const FORGED_FORWARDED_HEADER: &str = "forwarded";
const FORGED_DEVICE_HEADER: &str = "x-agent-tunnel-device-id";
const FORGED_SERVICE_HEADER: &str = "x-agent-tunnel-service-id";
const FORGED_TENANT_HEADER: &str = "x-agent-tunnel-tenant-id";

/// The complete advertised public consumer route set.  EC-009 is a browser
/// concern with no Rust surface; this list plus the typed rejection of every
/// other path is the recorded route boundary for it.
const ADVERTISED_PUBLIC_ROUTES: [&str; 5] = [
    "/livez",
    "/readyz",
    "/v1/devices",
    "/v1/devices/{device}/services",
    "/v1/devices/{device}/services/{service}/echo",
];
/// Safe method shapes probed at the POST-only echo route during owner loss.
/// The relay serves none of them there and reselects for none of them.
const SAFE_METHOD_SHAPES: [&str; 3] = ["GET", "HEAD", "OPTIONS"];
/// Paths that must stay outside the public consumer surface.
const EXCLUDED_PUBLIC_ROUTES: [&str; 6] = [
    "/v1/tunnel/control",
    "/v1/tunnel/data",
    "/v1/membership",
    "/v1/peers",
    "/diagnostics",
    "/metrics",
];

/// One payload-free public request outcome observed through a body sentinel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelOutcome {
    /// Bounded scenario label, used only for diagnostics.
    pub label: &'static str,
    /// HTTP status, or zero when the exchange failed below HTTP.
    pub status: u16,
    /// Allowlisted bounded failure code from the public error envelope.
    pub code: Option<&'static str>,
    /// Allowlisted bounded execution certainty from the same envelope.
    pub execution: Option<&'static str>,
    /// Bytes the sentinel declared in `content-length`.
    pub declared_body_bytes: u64,
    /// Bytes the sentinel actually handed to the transport.
    pub delivered_body_bytes: u64,
    /// Times the sentinel body was polled by the client transport.
    pub body_polls: u64,
    /// Whether the sentinel deliberately failed its body stream.
    pub body_stream_failed: bool,
    /// Whether the exchange ended below HTTP instead of with a response.
    pub transport_failed: bool,
    pub elapsed_ms: u64,
}

impl SentinelOutcome {
    /// A rejection proved to precede any body read: the sentinel declared a
    /// body, delivered none of it, and the bounded typed response arrived well
    /// inside the relay's own body deadline.
    #[must_use]
    pub fn preceded_body_read(&self) -> bool {
        self.declared_body_bytes > 0
            && self.delivered_body_bytes == 0
            && !self.transport_failed
            && self.elapsed_ms < PREFLIGHT_BOUND_MS
    }
}

/// Payload-free evidence from one fail-closed admission matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailClosedEvidence {
    pub relay_count: usize,
    /// Ingress relay used for every remote scenario; never the owner relay.
    pub remote_ingress_is_not_owner: bool,
    pub baseline_target_dispatches: u64,
    pub baseline_sibling_dispatches: u64,

    // ---- Control: the body read really is on this route (EC-031, FP-04) ----
    /// An admitted target whose sentinel withholds its declared body reaches
    /// the relay's typed body deadline.  Without this the zero-delivery
    /// rejections below would be vacuous.
    pub body_read_control: SentinelOutcome,
    pub body_read_control_dispatch_delta: u64,
    pub body_read_control_owner_chunk_read_delta: u64,

    // ---- EC-003: absent, ambiguous, duplicate and inactive targets ----
    pub absent_device: SentinelOutcome,
    pub unknown_service: SentinelOutcome,
    pub inactive_device: SentinelOutcome,
    /// A service-type label matching two active services must fail closed.
    pub ambiguous_service: SentinelOutcome,
    /// The same label against a device with one active service still resolves,
    /// so the ambiguous rejection above is a real ambiguity outcome.
    pub unambiguous_label_status: u16,
    pub unambiguous_label_response_exact: bool,
    /// A service identifier belonging to a different device is a
    /// caller-supplied destination and must never be used.
    pub caller_destination: SentinelOutcome,
    /// The same duplicate label through the public stream upgrade: the same
    /// typed ambiguous outcome, no 101, no owner selection (M7-C47).
    pub ambiguous_stream: SentinelOutcome,
    /// The service listing for the device with the duplicate label stays
    /// live and exposes both active echo services, so the ambiguity is
    /// visible to a consumer rather than hidden by the listing route.
    pub ambiguous_listing_status: u16,
    pub ambiguous_listing_active_echo_services: usize,
    pub ec003_dispatch_delta: u64,
    pub ec003_owner_chunk_read_delta: u64,

    // ---- EC-017 / EC-049: peer endpoint and preflight ----
    /// A real remote owner hop happened through the non-owner ingress, so the
    /// peer-endpoint and preflight zeros below are not vacuous.
    pub remote_route_proved: bool,
    /// A valid remote echo carrying forged peer/owner endpoint inputs still
    /// returned the membership-selected owner's canary.
    pub forged_endpoint_response_exact: bool,
    pub forged_endpoint_udp_datagrams: u64,
    pub forged_endpoint_tcp_connections: u64,
    /// The other half of EC-017: the TLS server name observed on the
    /// legitimate peer connection matched the owner's verified membership
    /// record and none of the names the caller supplied in headers.
    ///
    /// Zero contact with a caller-named address proves only that the peer
    /// *address* came from membership.  Without this flag a relay could still
    /// dial the membership address while presenting a caller-chosen server
    /// name, which is what the signed record is supposed to fix.
    pub peer_connection_server_name_from_membership: bool,
    /// A cross-scope target is rejected before any body read or peer forward.
    pub preflight_cross_scope: SentinelOutcome,
    pub preflight_dispatch_delta: u64,
    pub preflight_owner_chunk_read_delta: u64,

    // ---- EC-031: empty body versus failed body ----
    pub empty_body_status: u16,
    pub empty_body_response_exact: bool,
    pub empty_body_dispatch_delta: u64,
    pub empty_body_owner_chunk_read_delta: u64,
    pub failed_body: SentinelOutcome,
    pub failed_body_dispatch_delta: u64,
    pub failed_body_owner_chunk_read_delta: u64,
    pub empty_and_failed_body_distinct: bool,
    /// A safe GET with no request body at all stays live.
    pub safe_no_body_status: u16,

    // ---- FP-04 / IN-03: owner loss with consumed and unconsumed bodies ----
    /// A consumed mutation body under selected-owner loss.
    pub owner_loss_consumed_mutation: SentinelOutcome,
    /// The same consumed mutation repeated: still no dispatch anywhere.
    pub owner_loss_consumed_mutation_repeat: SentinelOutcome,
    /// A safe request with no body under the same fault.
    pub owner_loss_safe_unpolled: SentinelOutcome,
    /// A failed body under the same fault.
    pub owner_loss_failed_body: SentinelOutcome,
    /// GET, HEAD and OPTIONS shaped requests at the POST-only echo route of
    /// the lost owner's device, in that order.  Each is a typed
    /// `not_dispatched` rejection: the relay performs no automatic
    /// reselection on any method (M7-C46).
    pub owner_loss_safe_methods: Vec<SentinelOutcome>,
    /// The HEAD rejection mirrored the GET's typed envelope: same status and
    /// the same declared content length with no body bytes on the wire.
    pub owner_loss_head_mirrors_typed_get: bool,
    /// Dispatches attributable to the three safe-method probes alone.
    pub owner_loss_safe_method_dispatch_delta: u64,
    pub owner_loss_safe_method_owner_chunk_read_delta: u64,
    /// Cluster-wide application dispatches during the whole fault window.
    pub owner_loss_dispatch_delta: u64,
    pub owner_loss_owner_chunk_read_delta: u64,
    /// No mutation was reselected onto another owner or an unrelated backend.
    pub mutation_reselected: bool,
    /// Exactly one bounded safe retry bridged restored owner readiness.
    pub safe_retry_attempts: u64,
    pub safe_retry_succeeded: bool,
    pub safe_retry_dispatch_delta: u64,

    // ---- EC-023 / EC-048: owner disappearance ----
    /// The owner CLI was killed while one valid mutation was in flight.
    pub owner_process_killed: bool,
    /// Application dispatches attributable to that in-flight mutation.  One
    /// committed effect or none; never two.
    pub inflight_kill_dispatch_delta: u64,
    pub inflight_kill_outcome_classified: bool,
    /// A probe issued after the owner process is gone.
    pub post_kill_probe: SentinelOutcome,
    pub post_kill_dispatch_delta: u64,
    /// The pre-kill owner token is no longer the authoritative owner, so a
    /// fresh session is required rather than silently reused.
    pub owner_identity_required_fresh: bool,
    pub sibling_dispatch_delta_after_owner_kill: u64,
    pub sibling_canary_survived: bool,

    // ---- EC-009: excluded browser route boundary ----
    pub advertised_public_routes: usize,
    pub excluded_public_routes_typed: usize,
    pub route_boundary_dispatch_delta: u64,
    pub excluded_browser_boundary_recorded: bool,

    pub elapsed_ms: u64,
    /// Set by [`verify`] only after every child process, socket, relay, Redis
    /// namespace and honeypot completed bounded cleanup.
    pub cleanup_joined: bool,
}

/// Validate the mandatory fail-closed evidence.  Every check is strict: a
/// missing proof, a wrong bounded code, a body read that should not have
/// happened, or any dispatch on a negative path fails the gate.
pub fn validate_fail_closed_evidence(evidence: &FailClosedEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "fail-closed admission requires exactly three relays, observed {}",
            evidence.relay_count
        )));
    }
    let flags = [
        (
            "remote_ingress_is_not_owner",
            evidence.remote_ingress_is_not_owner,
        ),
        ("remote_route_proved", evidence.remote_route_proved),
        (
            "forged_endpoint_response_exact",
            evidence.forged_endpoint_response_exact,
        ),
        (
            "peer_connection_server_name_from_membership",
            evidence.peer_connection_server_name_from_membership,
        ),
        (
            "unambiguous_label_response_exact",
            evidence.unambiguous_label_response_exact,
        ),
        (
            "empty_body_response_exact",
            evidence.empty_body_response_exact,
        ),
        (
            "empty_and_failed_body_distinct",
            evidence.empty_and_failed_body_distinct,
        ),
        ("safe_retry_succeeded", evidence.safe_retry_succeeded),
        ("owner_process_killed", evidence.owner_process_killed),
        (
            "inflight_kill_outcome_classified",
            evidence.inflight_kill_outcome_classified,
        ),
        (
            "owner_identity_required_fresh",
            evidence.owner_identity_required_fresh,
        ),
        ("sibling_canary_survived", evidence.sibling_canary_survived),
        (
            "excluded_browser_boundary_recorded",
            evidence.excluded_browser_boundary_recorded,
        ),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = flags.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "fail-closed admission required gate {name} was false"
        )));
    }
    if evidence.mutation_reselected {
        return Err(HarnessError::Process(
            "fail-closed admission observed mutation_reselected; a consumed mutation body was reselected".into(),
        ));
    }
    if evidence.baseline_target_dispatches == 0 {
        return Err(HarnessError::Process(
            "fail-closed admission baseline_target_dispatches must be positive".into(),
        ));
    }
    if evidence.baseline_sibling_dispatches == 0 {
        return Err(HarnessError::Process(
            "fail-closed admission baseline_sibling_dispatches must be positive".into(),
        ));
    }

    // The body read must be proved to be on this route before any
    // zero-delivery rejection counts as preflight evidence.
    let control = &evidence.body_read_control;
    require_typed(control, 408, "BODY_TIMEOUT", "not_dispatched")?;
    if control.delivered_body_bytes != 0 || control.declared_body_bytes == 0 {
        return Err(HarnessError::Process(format!(
            "fail-closed body_read_control must declare a body and deliver none, observed declared={} delivered={}",
            control.declared_body_bytes, control.delivered_body_bytes
        )));
    }
    if control.elapsed_ms < BODY_DEADLINE_FLOOR_MS {
        return Err(HarnessError::Process(format!(
            "fail-closed body_read_control returned after {}ms; the relay body deadline was not reached, so no preflight claim is supported",
            control.elapsed_ms
        )));
    }
    zero_delta(
        "body_read_control_dispatch_delta",
        evidence.body_read_control_dispatch_delta,
    )?;
    zero_delta(
        "body_read_control_owner_chunk_read_delta",
        evidence.body_read_control_owner_chunk_read_delta,
    )?;

    // EC-003: every absent, ambiguous, duplicate, inactive and
    // caller-destination target fails before owner selection.
    let ec003 = [
        (&evidence.absent_device, 404_u16, "DEVICE_NOT_FOUND"),
        (&evidence.unknown_service, 404, "SERVICE_NOT_FOUND"),
        (&evidence.inactive_device, 404, "DEVICE_NOT_FOUND"),
        (&evidence.ambiguous_service, 409, "SERVICE_AMBIGUOUS"),
        (&evidence.caller_destination, 404, "SERVICE_NOT_FOUND"),
    ];
    for (outcome, status, code) in ec003 {
        require_typed(outcome, status, code, "not_dispatched")?;
        require_preflight(outcome)?;
    }
    if evidence.unambiguous_label_status != 200 {
        return Err(HarnessError::Process(format!(
            "fail-closed unambiguous_label_status was {}; a single active service must still resolve by label, otherwise the ambiguous rejection proves nothing",
            evidence.unambiguous_label_status
        )));
    }
    // M7-C47: the stream upgrade resolves the same duplicate label through
    // the same resolver, so it must report the identical typed outcome, carry
    // no body and never reach 101.
    require_typed(
        &evidence.ambiguous_stream,
        409,
        "SERVICE_AMBIGUOUS",
        "not_dispatched",
    )?;
    if evidence.ambiguous_stream.declared_body_bytes != 0
        || evidence.ambiguous_stream.delivered_body_bytes != 0
    {
        return Err(HarnessError::Process(format!(
            "fail-closed ambiguous_stream must carry no request body, observed declared={} delivered={}",
            evidence.ambiguous_stream.declared_body_bytes,
            evidence.ambiguous_stream.delivered_body_bytes
        )));
    }
    if evidence.ambiguous_listing_status != 200 {
        return Err(HarnessError::Process(format!(
            "fail-closed ambiguous_listing_status was {}; the service listing must stay live for a device with a duplicate label",
            evidence.ambiguous_listing_status
        )));
    }
    if evidence.ambiguous_listing_active_echo_services != 2 {
        return Err(HarnessError::Process(format!(
            "fail-closed ambiguous_listing_active_echo_services was {}, expected both active echo services to be listed",
            evidence.ambiguous_listing_active_echo_services
        )));
    }
    zero_delta("ec003_dispatch_delta", evidence.ec003_dispatch_delta)?;
    zero_delta(
        "ec003_owner_chunk_read_delta",
        evidence.ec003_owner_chunk_read_delta,
    )?;

    // EC-017 and EC-049: the peer endpoint comes only from verified
    // membership, and the preflight completes before a body is read.
    if evidence.forged_endpoint_udp_datagrams != 0 {
        return Err(HarnessError::Process(format!(
            "fail-closed forged_endpoint_udp_datagrams was {}; consumer input reached a caller-named peer address",
            evidence.forged_endpoint_udp_datagrams
        )));
    }
    if evidence.forged_endpoint_tcp_connections != 0 {
        return Err(HarnessError::Process(format!(
            "fail-closed forged_endpoint_tcp_connections was {}; consumer input reached a caller-named peer address",
            evidence.forged_endpoint_tcp_connections
        )));
    }
    require_typed(
        &evidence.preflight_cross_scope,
        404,
        "DEVICE_NOT_FOUND",
        "not_dispatched",
    )?;
    require_preflight(&evidence.preflight_cross_scope)?;
    zero_delta(
        "preflight_dispatch_delta",
        evidence.preflight_dispatch_delta,
    )?;
    zero_delta(
        "preflight_owner_chunk_read_delta",
        evidence.preflight_owner_chunk_read_delta,
    )?;

    // EC-031: a zero-byte safe request stays live and is distinct from a
    // failed body.
    if evidence.empty_body_status != 200 {
        return Err(HarnessError::Process(format!(
            "fail-closed empty_body_status was {}, expected an exact 200 zero-byte echo",
            evidence.empty_body_status
        )));
    }
    if evidence.empty_body_dispatch_delta != 1 {
        return Err(HarnessError::Process(format!(
            "fail-closed empty_body_dispatch_delta was {}, expected exactly one",
            evidence.empty_body_dispatch_delta
        )));
    }
    if evidence.empty_body_owner_chunk_read_delta == 0 {
        return Err(HarnessError::Process(
            "fail-closed empty_body_owner_chunk_read_delta must be positive; the zero-byte body must still be read and forwarded".into(),
        ));
    }
    if !evidence.failed_body.body_stream_failed {
        return Err(HarnessError::Process(
            "fail-closed failed_body did not actually fail its request-body stream".into(),
        ));
    }
    if evidence.failed_body.status == 200 {
        return Err(HarnessError::Process(
            "fail-closed failed_body returned 200; a failed body must never read as a live empty body".into(),
        ));
    }
    zero_delta(
        "failed_body_dispatch_delta",
        evidence.failed_body_dispatch_delta,
    )?;
    zero_delta(
        "failed_body_owner_chunk_read_delta",
        evidence.failed_body_owner_chunk_read_delta,
    )?;
    if evidence.safe_no_body_status != 200 {
        return Err(HarnessError::Process(format!(
            "fail-closed safe_no_body_status was {}; a safe request with no body must remain live",
            evidence.safe_no_body_status
        )));
    }

    // FP-04 and IN-03: only a proven not-dispatched safe request may bridge
    // readiness, and a consumed body is never replayed.
    let consumed = &evidence.owner_loss_consumed_mutation;
    require_selected_owner_failure(consumed)?;
    if consumed.delivered_body_bytes == 0
        || consumed.delivered_body_bytes != consumed.declared_body_bytes
    {
        return Err(HarnessError::Process(format!(
            "fail-closed owner_loss_consumed_mutation must have consumed its whole body, observed declared={} delivered={}",
            consumed.declared_body_bytes, consumed.delivered_body_bytes
        )));
    }
    require_selected_owner_failure(&evidence.owner_loss_consumed_mutation_repeat)?;
    require_selected_owner_failure(&evidence.owner_loss_safe_unpolled)?;
    if evidence.owner_loss_safe_unpolled.delivered_body_bytes != 0
        || evidence.owner_loss_safe_unpolled.declared_body_bytes != 0
    {
        return Err(HarnessError::Process(format!(
            "fail-closed owner_loss_safe_unpolled must carry no request body, observed declared={} delivered={}",
            evidence.owner_loss_safe_unpolled.declared_body_bytes,
            evidence.owner_loss_safe_unpolled.delivered_body_bytes
        )));
    }
    // M7-C46: the relay never reselects an owner for any method.  Each safe
    // method shape at the lost owner's echo route ends as one typed
    // `not_dispatched` rejection with no body and no dispatch anywhere.
    if evidence.owner_loss_safe_methods.len() != SAFE_METHOD_SHAPES.len() {
        return Err(HarnessError::Process(format!(
            "fail-closed owner_loss_safe_methods recorded {} outcomes, expected {}",
            evidence.owner_loss_safe_methods.len(),
            SAFE_METHOD_SHAPES.len()
        )));
    }
    for (outcome, method) in evidence
        .owner_loss_safe_methods
        .iter()
        .zip(SAFE_METHOD_SHAPES)
    {
        if outcome.label != method {
            return Err(HarnessError::Process(format!(
                "fail-closed owner_loss_safe_methods outcome {} is out of order, expected {method}",
                outcome.label
            )));
        }
        if outcome.declared_body_bytes != 0 || outcome.delivered_body_bytes != 0 {
            return Err(HarnessError::Process(format!(
                "fail-closed owner_loss_safe_methods {method} must carry no request body, observed declared={} delivered={}",
                outcome.declared_body_bytes, outcome.delivered_body_bytes
            )));
        }
        if method == "HEAD" {
            // A HEAD response carries no body, so its envelope is proved by
            // mirroring the GET's typed envelope instead of by parsing one.
            if outcome.status != 405 || outcome.transport_failed {
                return Err(HarnessError::Process(format!(
                    "fail-closed owner_loss_safe_methods HEAD returned status={} transport_failed={}, expected 405",
                    outcome.status, outcome.transport_failed
                )));
            }
            continue;
        }
        require_typed(outcome, 405, "METHOD_NOT_ALLOWED", "not_dispatched")?;
    }
    if !evidence.owner_loss_head_mirrors_typed_get {
        return Err(HarnessError::Process(
            "fail-closed owner_loss_head_mirrors_typed_get was false; the HEAD rejection did not mirror the GET's typed envelope".into(),
        ));
    }
    zero_delta(
        "owner_loss_safe_method_dispatch_delta",
        evidence.owner_loss_safe_method_dispatch_delta,
    )?;
    zero_delta(
        "owner_loss_safe_method_owner_chunk_read_delta",
        evidence.owner_loss_safe_method_owner_chunk_read_delta,
    )?;
    if !evidence.owner_loss_failed_body.body_stream_failed {
        return Err(HarnessError::Process(
            "fail-closed owner_loss_failed_body did not actually fail its request-body stream"
                .into(),
        ));
    }
    if evidence.owner_loss_failed_body.status == 200 {
        return Err(HarnessError::Process(
            "fail-closed owner_loss_failed_body returned 200 during selected-owner loss".into(),
        ));
    }
    zero_delta(
        "owner_loss_dispatch_delta",
        evidence.owner_loss_dispatch_delta,
    )?;
    zero_delta(
        "owner_loss_owner_chunk_read_delta",
        evidence.owner_loss_owner_chunk_read_delta,
    )?;
    if evidence.safe_retry_attempts != 1 {
        return Err(HarnessError::Process(format!(
            "fail-closed safe_retry_attempts was {}, expected exactly one bounded retry",
            evidence.safe_retry_attempts
        )));
    }
    if evidence.safe_retry_dispatch_delta != 1 {
        return Err(HarnessError::Process(format!(
            "fail-closed safe_retry_dispatch_delta was {}, expected exactly one",
            evidence.safe_retry_dispatch_delta
        )));
    }

    // EC-023 and EC-048: a real owner process loss never duplicates an effect
    // and always demands fresh ownership.
    if evidence.inflight_kill_dispatch_delta > 1 {
        return Err(HarnessError::Process(format!(
            "fail-closed inflight_kill_dispatch_delta was {}; an in-flight mutation was dispatched more than once",
            evidence.inflight_kill_dispatch_delta
        )));
    }
    // The post-kill probe must deliver its body: owner selection happens after
    // the relay's body read, so a withheld body would reach the body deadline
    // instead of the owner-loss outcome this row needs.
    require_selected_owner_failure(&evidence.post_kill_probe)?;
    if evidence.post_kill_probe.delivered_body_bytes != evidence.post_kill_probe.declared_body_bytes
        || evidence.post_kill_probe.declared_body_bytes == 0
    {
        return Err(HarnessError::Process(format!(
            "fail-closed post_kill_probe must reach owner selection with a fully delivered body, observed declared={} delivered={}",
            evidence.post_kill_probe.declared_body_bytes,
            evidence.post_kill_probe.delivered_body_bytes
        )));
    }
    zero_delta(
        "post_kill_dispatch_delta",
        evidence.post_kill_dispatch_delta,
    )?;
    if evidence.sibling_dispatch_delta_after_owner_kill != 1 {
        return Err(HarnessError::Process(format!(
            "fail-closed sibling_dispatch_delta_after_owner_kill was {}, expected exactly one",
            evidence.sibling_dispatch_delta_after_owner_kill
        )));
    }

    // EC-009: the advertised endpoint set is explicit and every excluded path
    // is typed, which is the recorded route boundary for the excluded browser
    // surface.
    if evidence.advertised_public_routes != ADVERTISED_PUBLIC_ROUTES.len() {
        return Err(HarnessError::Process(format!(
            "fail-closed advertised_public_routes was {}, expected {}",
            evidence.advertised_public_routes,
            ADVERTISED_PUBLIC_ROUTES.len()
        )));
    }
    if evidence.excluded_public_routes_typed != EXCLUDED_PUBLIC_ROUTES.len() {
        return Err(HarnessError::Process(format!(
            "fail-closed excluded_public_routes_typed was {}, expected {}",
            evidence.excluded_public_routes_typed,
            EXCLUDED_PUBLIC_ROUTES.len()
        )));
    }
    zero_delta(
        "route_boundary_dispatch_delta",
        evidence.route_boundary_dispatch_delta,
    )?;
    if evidence.elapsed_ms == 0 {
        return Err(HarnessError::Process(
            "fail-closed elapsed_ms must record a real scenario duration".into(),
        ));
    }
    Ok(())
}

fn zero_delta(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        return Ok(());
    }
    Err(HarnessError::Process(format!(
        "fail-closed admission counter {name} advanced by {value}, expected zero"
    )))
}

fn require_typed(
    outcome: &SentinelOutcome,
    status: u16,
    code: &'static str,
    execution: &'static str,
) -> Result<()> {
    if outcome.status == status
        && outcome.code == Some(code)
        && outcome.execution == Some(execution)
        && !outcome.transport_failed
    {
        return Ok(());
    }
    Err(HarnessError::Process(format!(
        "fail-closed scenario {} returned status={} code={:?} execution={:?} transport_failed={}, expected status={status} code={code} execution={execution}",
        outcome.label, outcome.status, outcome.code, outcome.execution, outcome.transport_failed
    )))
}

fn require_preflight(outcome: &SentinelOutcome) -> Result<()> {
    if outcome.preceded_body_read() {
        return Ok(());
    }
    Err(HarnessError::Process(format!(
        "fail-closed scenario {} did not prove its rejection preceded the body read: declared={} delivered={} elapsed_ms={} transport_failed={}",
        outcome.label,
        outcome.declared_body_bytes,
        outcome.delivered_body_bytes,
        outcome.elapsed_ms,
        outcome.transport_failed
    )))
}

fn require_selected_owner_failure(outcome: &SentinelOutcome) -> Result<()> {
    let typed = outcome.status == 503
        && matches!(
            outcome.code,
            Some("PEER_UNAVAILABLE") | Some("PEER_UNTRUSTED")
        )
        && matches!(outcome.execution, Some("not_dispatched"))
        && !outcome.transport_failed;
    if typed {
        return Ok(());
    }
    Err(HarnessError::Process(format!(
        "fail-closed scenario {} was not a typed not-dispatched selected-owner failure: status={} code={:?} execution={:?} transport_failed={}",
        outcome.label, outcome.status, outcome.code, outcome.execution, outcome.transport_failed
    )))
}

/// Allowlisted bounded public failure codes.  An unknown code is reported as
/// `None` so a renamed or unexpected envelope cannot silently satisfy a check.
fn known_failure_code(value: &str) -> Option<&'static str> {
    match value {
        "UNAUTHORIZED" => Some("UNAUTHORIZED"),
        "FORBIDDEN" => Some("FORBIDDEN"),
        "NOT_FOUND" => Some("NOT_FOUND"),
        "DEVICE_NOT_FOUND" => Some("DEVICE_NOT_FOUND"),
        "SERVICE_NOT_FOUND" => Some("SERVICE_NOT_FOUND"),
        "SERVICE_AMBIGUOUS" => Some("SERVICE_AMBIGUOUS"),
        "METHOD_NOT_ALLOWED" => Some("METHOD_NOT_ALLOWED"),
        "BODY_LIMIT" => Some("BODY_LIMIT"),
        "BODY_TIMEOUT" => Some("BODY_TIMEOUT"),
        "ADMISSION_LIMIT" => Some("ADMISSION_LIMIT"),
        "AUTHORIZATION_UNAVAILABLE" => Some("AUTHORIZATION_UNAVAILABLE"),
        "CLUSTER_UNREADY" => Some("CLUSTER_UNREADY"),
        "PEER_UNAVAILABLE" => Some("PEER_UNAVAILABLE"),
        "PEER_UNTRUSTED" => Some("PEER_UNTRUSTED"),
        "STREAM_LIMIT" => Some("STREAM_LIMIT"),
        "REVERSE_CHANNEL_UNAVAILABLE" => Some("REVERSE_CHANNEL_UNAVAILABLE"),
        "REVERSE_CHANNEL_INTERRUPTED" => Some("REVERSE_CHANNEL_INTERRUPTED"),
        "SUBPROTOCOL_REQUIRED" => Some("SUBPROTOCOL_REQUIRED"),
        _ => None,
    }
}

fn known_execution(value: &str) -> Option<&'static str> {
    match value {
        "not_dispatched" => Some("not_dispatched"),
        "unknown" => Some("unknown"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Request-body sentinel
// ---------------------------------------------------------------------------

/// What the sentinel does with the body it declares.
#[derive(Clone, Debug, Eq, PartialEq)]
enum BodyPlan {
    /// Declare and deliver exactly these bytes.
    Delivered(Vec<u8>),
    /// Declare this many bytes and deliver none of them, so a completed read
    /// is impossible and a fast typed rejection proves the read was skipped.
    Withheld(usize),
    /// Declare this many bytes, deliver none, and fail the body stream.
    Failed(usize),
    /// Carry no request body at all.
    None,
}

impl BodyPlan {
    fn declared_len(&self) -> usize {
        match self {
            Self::Delivered(bytes) => bytes.len(),
            Self::Withheld(len) | Self::Failed(len) => *len,
            Self::None => 0,
        }
    }
}

#[derive(Debug)]
struct SentinelBodyError;

impl std::fmt::Display for SentinelBodyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("fail-closed body sentinel failed its request-body stream")
    }
}

impl std::error::Error for SentinelBodyError {}

/// Shared, payload-free counters for one sentinel body.
#[derive(Clone, Debug, Default)]
struct SentinelCounters {
    polls: Arc<AtomicU64>,
    delivered: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

/// A request body with observable delivery.  `Withheld` returns `Pending`
/// without registering a waker on purpose: nothing will ever complete it, so
/// the relay either rejects before reading it or reaches its own body
/// deadline.  The owning request is always bounded by a caller deadline.
struct SentinelBody {
    plan: BodyPlan,
    declared: usize,
    finished: bool,
    counters: SentinelCounters,
}

impl SentinelBody {
    fn new(plan: BodyPlan, counters: SentinelCounters) -> Self {
        let declared = plan.declared_len();
        Self {
            plan,
            declared,
            finished: false,
            counters,
        }
    }
}

impl Body for SentinelBody {
    type Data = Bytes;
    type Error = SentinelBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        self.counters.polls.fetch_add(1, Ordering::Relaxed);
        if self.finished {
            return Poll::Ready(None);
        }
        match std::mem::replace(&mut self.plan, BodyPlan::None) {
            BodyPlan::Delivered(bytes) => {
                self.finished = true;
                let len = bytes.len() as u64;
                if len == 0 {
                    return Poll::Ready(None);
                }
                self.counters.delivered.fetch_add(len, Ordering::Relaxed);
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(bytes)))))
            }
            BodyPlan::Failed(_) => {
                self.finished = true;
                self.counters.failed.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Some(Err(SentinelBodyError)))
            }
            BodyPlan::Withheld(len) => {
                // Restore the plan so a second poll behaves identically.
                self.plan = BodyPlan::Withheld(len);
                Poll::Pending
            }
            BodyPlan::None => {
                self.finished = true;
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished && matches!(self.plan, BodyPlan::None)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.declared as u64)
    }
}

struct SentinelRequest<'a> {
    label: &'static str,
    consumer_addr: SocketAddr,
    server_ca_der: &'a [u8],
    token: &'a str,
    device_id: Uuid,
    service: &'a str,
    headers: &'a [(&'static str, String)],
    plan: BodyPlan,
}

/// One completed public echo exchange plus its bounded response body.
struct SentinelResult {
    outcome: SentinelOutcome,
    body: Vec<u8>,
}

/// Run one public HTTPS echo with an observable request body.
async fn sentinel_echo(request: SentinelRequest<'_>) -> Result<SentinelResult> {
    let SentinelRequest {
        label,
        consumer_addr,
        server_ca_der,
        token,
        device_id,
        service,
        headers,
        plan,
    } = request;
    if service.is_empty() || service.len() > 128 {
        return Err(HarnessError::InvalidInput(
            "fail-closed sentinel service label is outside its bound".into(),
        ));
    }
    let declared = plan.declared_len() as u64;
    let counters = SentinelCounters::default();
    let started = TokioInstant::now();
    let deadline = started + REQUEST_TIMEOUT;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("fail-closed sentinel CA: {error}")))?;
    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Http(format!("fail-closed sentinel TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = timeout_at(deadline, tokio::net::TcpStream::connect(consumer_addr))
        .await
        .map_err(|_| HarnessError::Timeout("fail-closed sentinel TCP connect timed out".into()))?
        .map_err(HarnessError::Io)?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("fail-closed sentinel name: {error}")))?;
    let tls_stream = timeout_at(deadline, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout("fail-closed sentinel TLS timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("fail-closed sentinel TLS: {error}")))?;
    let (mut sender, connection) = timeout_at(
        deadline,
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)),
    )
    .await
    .map_err(|_| HarnessError::Timeout("fail-closed sentinel handshake timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("fail-closed sentinel handshake: {error}")))?;
    let mut connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let exchange: std::result::Result<(u16, Vec<u8>), HarnessError> = async {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!(
                "https://localhost:{}/v1/devices/{device_id}/services/{service}/echo",
                consumer_addr.port()
            ))
            .header("host", "localhost")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/octet-stream");
        for (name, value) in headers {
            builder = builder.header(*name, value.as_str());
        }
        let outgoing = builder
            .body(SentinelBody::new(plan, counters.clone()))
            .map_err(|error| {
                HarnessError::Http(format!("building fail-closed sentinel request: {error}"))
            })?;
        let response = timeout_at(deadline, sender.send_request(outgoing))
            .await
            .map_err(|_| {
                HarnessError::Timeout("fail-closed sentinel request exceeded its bound".into())
            })?
            .map_err(|error| {
                HarnessError::Http(format!("fail-closed sentinel request failed: {error}"))
            })?;
        let status = response.status().as_u16();
        let limit = if status == 200 {
            MAX_ECHO_RESPONSE_BYTES
        } else {
            MAX_ERROR_BODY_BYTES
        };
        let body = timeout_at(
            deadline,
            Limited::new(response.into_body(), limit).collect(),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout("reading fail-closed sentinel response timed out".into())
        })?
        .map_err(|_| HarnessError::Http("fail-closed sentinel response exceeded its bound".into()))?
        .to_bytes()
        .to_vec();
        Ok((status, body))
    }
    .await;
    drop(sender);
    if timeout_at(deadline, &mut connection_task).await.is_err() {
        connection_task.abort();
        let _ = connection_task.await;
    }
    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let polls = counters.polls.load(Ordering::Acquire);
    let delivered = counters.delivered.load(Ordering::Acquire);
    let failed = counters.failed.load(Ordering::Acquire) > 0;
    match exchange {
        Ok((status, body)) => {
            let (code, execution) = if status == 200 {
                (None, None)
            } else {
                let value = serde_json::from_slice::<serde_json::Value>(&body).map_err(|_| {
                    HarnessError::Http(format!(
                        "fail-closed scenario {label} error response was not bounded JSON: status={status}"
                    ))
                })?;
                (
                    value
                        .get("code")
                        .and_then(serde_json::Value::as_str)
                        .and_then(known_failure_code),
                    value
                        .get("execution")
                        .and_then(serde_json::Value::as_str)
                        .and_then(known_execution),
                )
            };
            Ok(SentinelResult {
                outcome: SentinelOutcome {
                    label,
                    status,
                    code,
                    execution,
                    declared_body_bytes: declared,
                    delivered_body_bytes: delivered,
                    body_polls: polls,
                    body_stream_failed: failed,
                    transport_failed: false,
                    elapsed_ms,
                },
                body,
            })
        }
        Err(error) => {
            // A deliberately failed body stream may end below HTTP.  Record
            // that as a classified transport outcome rather than a harness
            // error, but never for a scenario that did not fail its body.
            if failed {
                return Ok(SentinelResult {
                    outcome: SentinelOutcome {
                        label,
                        status: 0,
                        code: None,
                        execution: None,
                        declared_body_bytes: declared,
                        delivered_body_bytes: delivered,
                        body_polls: polls,
                        body_stream_failed: true,
                        transport_failed: true,
                        elapsed_ms,
                    },
                    body: Vec::new(),
                });
            }
            Err(HarnessError::Http(format!(
                "fail-closed scenario {label} exchange failed: {error}"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Caller-named peer address honeypot
// ---------------------------------------------------------------------------

/// A UDP socket and a TCP listener that no relay may ever reach.  Consumer
/// input naming these addresses must not produce a single datagram or accepted
/// connection; the peer endpoint comes only from verified membership.
struct EndpointHoneypot {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    datagrams: Arc<AtomicU64>,
    connections: Arc<AtomicU64>,
    cancel: CancellationToken,
    udp_task: tokio::task::JoinHandle<()>,
    tcp_task: tokio::task::JoinHandle<()>,
}

impl EndpointHoneypot {
    async fn bind() -> Result<Self> {
        let udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(HarnessError::Io)?;
        let udp_addr = udp.local_addr().map_err(HarnessError::Io)?;
        let tcp = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(HarnessError::Io)?;
        let tcp_addr = tcp.local_addr().map_err(HarnessError::Io)?;
        let datagrams = Arc::new(AtomicU64::new(0));
        let connections = Arc::new(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let udp_counter = datagrams.clone();
        let udp_cancel = cancel.clone();
        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 2048];
            loop {
                tokio::select! {
                    _ = udp_cancel.cancelled() => break,
                    received = udp.recv_from(&mut buffer) => match received {
                        Ok(_) => {
                            udp_counter.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => break,
                    },
                }
            }
        });
        let tcp_counter = connections.clone();
        let tcp_cancel = cancel.clone();
        let tcp_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tcp_cancel.cancelled() => break,
                    accepted = tcp.accept() => match accepted {
                        Ok(_) => {
                            tcp_counter.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => break,
                    },
                }
            }
        });
        Ok(Self {
            udp_addr,
            tcp_addr,
            datagrams,
            connections,
            cancel,
            udp_task,
            tcp_task,
        })
    }

    fn datagrams(&self) -> u64 {
        self.datagrams.load(Ordering::Acquire)
    }

    fn connections(&self) -> u64 {
        self.connections.load(Ordering::Acquire)
    }

    async fn shutdown(self) -> Result<()> {
        self.cancel.cancel();
        let udp = timeout(CLEANUP_TIMEOUT, self.udp_task).await;
        let tcp = timeout(CLEANUP_TIMEOUT, self.tcp_task).await;
        match (udp, tcp) {
            (Ok(Ok(())), Ok(Ok(()))) => Ok(()),
            _ => Err(HarnessError::Process(
                "fail-closed endpoint honeypot did not join".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Relay counters
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct ClusterCounters {
    dispatches: BTreeMap<String, u64>,
    chunk_reads: BTreeMap<String, u64>,
}

impl ClusterCounters {
    fn dispatch_delta(&self, after: &Self) -> u64 {
        delta(&self.dispatches, &after.dispatches)
    }

    fn chunk_read_delta(&self, after: &Self) -> u64 {
        delta(&self.chunk_reads, &after.chunk_reads)
    }

    fn node_dispatch_delta(&self, after: &Self, node: &str) -> u64 {
        after
            .dispatches
            .get(node)
            .copied()
            .unwrap_or_default()
            .saturating_sub(self.dispatches.get(node).copied().unwrap_or_default())
    }
}

fn delta(before: &BTreeMap<String, u64>, after: &BTreeMap<String, u64>) -> u64 {
    before
        .iter()
        .filter_map(|(node, value)| after.get(node).map(|seen| seen.saturating_sub(*value)))
        .fold(0_u64, u64::saturating_add)
}

async fn counters(cluster: &ProductionCluster) -> Result<ClusterCounters> {
    let mut snapshot = ClusterCounters::default();
    for relay in &cluster.relays {
        let relay_snapshot = relay.snapshot().await?;
        snapshot.dispatches.insert(
            relay.node_id.clone(),
            relay_snapshot.lifetime_application_dispatches,
        );
        snapshot.chunk_reads.insert(
            relay.node_id.clone(),
            relay_snapshot.lifetime_consumer_chunk_reads,
        );
    }
    Ok(snapshot)
}

fn forged_endpoint_headers(
    honeypot: &EndpointHoneypot,
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    owner_node: &str,
) -> Vec<(&'static str, String)> {
    vec![
        (FORGED_PEER_ENDPOINT_HEADER, honeypot.udp_addr.to_string()),
        (FORGED_OWNER_ENDPOINT_HEADER, honeypot.tcp_addr.to_string()),
        (FORGED_OWNER_NODE_HEADER, owner_node.to_owned()),
        (FORGED_FORWARDED_HOST_HEADER, honeypot.tcp_addr.to_string()),
        (
            FORGED_FORWARDED_HEADER,
            format!("host={};proto=https", honeypot.tcp_addr),
        ),
        (FORGED_TENANT_HEADER, tenant_id.to_string()),
        (FORGED_DEVICE_HEADER, device_id.to_string()),
        (FORGED_SERVICE_HEADER, service_id.to_string()),
    ]
}

fn echo_body_matches(response: &[u8], canary: &[u8], payload: &[u8]) -> bool {
    response.len() == canary.len().saturating_add(payload.len())
        && response.starts_with(canary)
        && response.get(canary.len()..) == Some(payload)
}

/// Wait, within a bound, until the selected owner answers one small echo.
///
/// This is a *precondition* helper, never an assertion: the relay's retryable
/// `PEER_UNAVAILABLE`/`not_dispatched` hint is the documented signal that the
/// owner carrier is still being committed.  Warm-up dispatches deliberately
/// land before the caller takes its counter snapshot, so every measured delta
/// stays exact.
async fn wait_for_echo_ready(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service: &str,
    canary: &[u8],
) -> Result<()> {
    let deadline = TokioInstant::now() + OWNER_READY_TIMEOUT;
    let payload = b"m7-i04-owner-ready";
    loop {
        let result = sentinel_echo(SentinelRequest {
            label: "owner_ready_precondition",
            consumer_addr,
            server_ca_der,
            token,
            device_id,
            service,
            headers: &[],
            plan: BodyPlan::Delivered(payload.to_vec()),
        })
        .await?;
        if result.outcome.status == 200 && echo_body_matches(&result.body, canary, payload) {
            return Ok(());
        }
        if TokioInstant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "fail-closed owner readiness precondition did not complete: status={} code={:?} execution={:?} response_len={}",
                result.outcome.status,
                result.outcome.code,
                result.outcome.execution,
                result.body.len()
            )));
        }
        tokio::time::sleep(OWNER_READY_POLL).await;
    }
}

/// A bounded authenticated GET that carries no request body at all.  Only the
/// status is returned; response bytes never enter evidence.
async fn authenticated_get_status(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: Option<&str>,
    path: &str,
) -> Result<u16> {
    authenticated_request(consumer_addr, server_ca_der, token, "GET", path)
        .await
        .map(|response| response.status)
}

/// One bounded body-free response.  The body is retained only up to the echo
/// response bound so a typed envelope or a listing can be inspected; it is
/// never reported as evidence itself.
struct ProbeResponse {
    status: u16,
    content_length: Option<u64>,
    body: Vec<u8>,
}

impl ProbeResponse {
    /// The allowlisted `(code, execution)` pair of a typed envelope, or
    /// `(None, None)` when the body is absent or not a bounded envelope.
    fn typed_envelope(&self) -> (Option<&'static str>, Option<&'static str>) {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&self.body) else {
            return (None, None);
        };
        (
            value
                .get("code")
                .and_then(serde_json::Value::as_str)
                .and_then(known_failure_code),
            value
                .get("execution")
                .and_then(serde_json::Value::as_str)
                .and_then(known_execution),
        )
    }
}

/// A bounded authenticated request with the given method and no request body
/// at all.  The sentinel body plan is `None`, so any body poll is impossible
/// by construction.
async fn authenticated_request(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: Option<&str>,
    method: &str,
    path: &str,
) -> Result<ProbeResponse> {
    let deadline = TokioInstant::now() + REQUEST_TIMEOUT;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("fail-closed GET CA: {error}")))?;
    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Http(format!("fail-closed GET TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = timeout_at(deadline, tokio::net::TcpStream::connect(consumer_addr))
        .await
        .map_err(|_| HarnessError::Timeout("fail-closed GET connect timed out".into()))?
        .map_err(HarnessError::Io)?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("fail-closed GET name: {error}")))?;
    let tls_stream = timeout_at(deadline, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout("fail-closed GET TLS timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("fail-closed GET TLS: {error}")))?;
    let (mut sender, connection) = timeout_at(
        deadline,
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)),
    )
    .await
    .map_err(|_| HarnessError::Timeout("fail-closed GET handshake timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("fail-closed GET handshake: {error}")))?;
    let mut connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let result: Result<ProbeResponse> = async {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("https://localhost{path}"))
            .header("host", "localhost");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = builder
            .body(SentinelBody::new(
                BodyPlan::None,
                SentinelCounters::default(),
            ))
            .map_err(|error| {
                HarnessError::Http(format!("building fail-closed GET request: {error}"))
            })?;
        let response = timeout_at(deadline, sender.send_request(request))
            .await
            .map_err(|_| HarnessError::Timeout("fail-closed GET timed out".into()))?
            .map_err(|error| HarnessError::Http(format!("fail-closed GET failed: {error}")))?;
        let status = response.status().as_u16();
        let content_length = response
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let body = timeout_at(
            deadline,
            Limited::new(response.into_body(), MAX_ECHO_RESPONSE_BYTES).collect(),
        )
        .await
        .map_err(|_| HarnessError::Timeout("reading fail-closed GET timed out".into()))?
        .map_err(|_| HarnessError::Http("fail-closed GET body exceeded its bound".into()))?
        .to_bytes()
        .to_vec();
        Ok(ProbeResponse {
            status,
            content_length,
            body,
        })
    }
    .await;
    drop(sender);
    if timeout_at(deadline, &mut connection_task).await.is_err() {
        connection_task.abort();
        let _ = connection_task.await;
    }
    result
}

/// Probe the advertised WSS stream route once.  A typed rejection is returned
/// as a [`SentinelOutcome`] carrying no request body; an accepted upgrade is
/// closed immediately and reported as status 101.
async fn safe_stream_probe(
    label: &'static str,
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service: &str,
) -> Result<SentinelOutcome> {
    let started = TokioInstant::now();
    let probe =
        open_consumer_stream_target(consumer_addr, server_ca_der, token, device_id, service).await;
    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    match probe {
        Ok(mut stream) => {
            let _ = stream.close().await;
            Ok(SentinelOutcome {
                label,
                status: 101,
                code: None,
                execution: None,
                declared_body_bytes: 0,
                delivered_body_bytes: 0,
                body_polls: 0,
                body_stream_failed: false,
                transport_failed: false,
                elapsed_ms,
            })
        }
        Err(super::StreamConnectFailure::Status { status, body }) => {
            let (code, execution) = match body {
                Some(bytes) => {
                    let value = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_| {
                        HarnessError::Http(format!(
                            "fail-closed scenario {label} stream rejection was not bounded JSON: status={status}"
                        ))
                    })?;
                    (
                        value
                            .get("code")
                            .and_then(serde_json::Value::as_str)
                            .and_then(known_failure_code),
                        value
                            .get("execution")
                            .and_then(serde_json::Value::as_str)
                            .and_then(known_execution),
                    )
                }
                None => (None, None),
            };
            Ok(SentinelOutcome {
                label,
                status,
                code,
                execution,
                declared_body_bytes: 0,
                delivered_body_bytes: 0,
                body_polls: 0,
                body_stream_failed: false,
                transport_failed: false,
                elapsed_ms,
            })
        }
        Err(super::StreamConnectFailure::Harness(error)) => Err(HarnessError::Http(format!(
            "fail-closed scenario {label} stream probe failed below HTTP: {error}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Gate entry point
// ---------------------------------------------------------------------------

pub async fn verify() -> Result<FailClosedEvidence> {
    let options = HarnessOptions::from_env()?
        .namespace_prefix("m7-i04-fail-closed")
        // The policy rotation interval, deliberately not the accelerated M2
        // one: this matrix asserts admission outcomes, and a three-second
        // replacement carrier would inject unrelated owner-readiness windows.
        .rotation(tunnel_core::RotationConfig::default())
        .shared_device_uuid(true)
        .ambiguous_echo_service(true);
    if options.redis_url.is_none() {
        return Err(HarnessError::MissingRedisUrl {
            env_var: "TEST_REDIS_URL",
            guidance:
                "The fail-closed admission gate requires TEST_REDIS_URL for its real owner authority."
                    .to_owned(),
        });
    }
    let mut harness = timeout(super::STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("fail-closed harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let cleanup = harness.shutdown().await;
            return Err(join_failures(
                error,
                [("fail-closed Redis cleanup", cleanup)],
            ));
        }
    };
    let honeypot = match EndpointHoneypot::bind().await {
        Ok(honeypot) => honeypot,
        Err(error) => {
            let relay_cleanup = cluster.shutdown().await;
            let redis_cleanup = harness.shutdown().await;
            return Err(join_failures(
                error,
                [
                    ("fail-closed relay cleanup", relay_cleanup),
                    ("fail-closed Redis cleanup", redis_cleanup),
                ],
            ));
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness, &honeypot)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "fail-closed admission scenario exceeded its bounded deadline".into(),
        )),
    };
    let cleanup_deadline = TokioInstant::now() + super::CLEANUP_TIMEOUT;
    let relay_cleanup = cluster.shutdown_until(cleanup_deadline).await;
    let redis_cleanup = harness.shutdown_until(cleanup_deadline).await;
    let honeypot_cleanup = honeypot.shutdown().await;
    let cleanup = [
        ("fail-closed relay cleanup", relay_cleanup),
        ("fail-closed Redis cleanup", redis_cleanup),
        ("fail-closed honeypot cleanup", honeypot_cleanup),
    ];
    match scenario {
        Err(error) => Err(join_failures(error, cleanup)),
        Ok(mut evidence) => {
            if cleanup.iter().any(|(_, result)| result.is_err()) {
                return Err(join_failures(
                    HarnessError::Process(
                        "fail-closed admission scenario completed but cleanup failed".into(),
                    ),
                    cleanup,
                ));
            }
            evidence.cleanup_joined = true;
            validate_fail_closed_evidence(&evidence)?;
            Ok(evidence)
        }
    }
}

fn join_failures<const N: usize>(
    primary: HarnessError,
    failures: [(&str, Result<()>); N],
) -> HarnessError {
    let failures = failures
        .into_iter()
        .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error}")))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        return primary;
    }
    HarnessError::Process(format!(
        "{primary}; cleanup failures: {}",
        failures.join("; ")
    ))
}

struct LiveCli {
    process: ManagedProcess,
    stream: Option<super::ConsumerStream>,
}

impl LiveCli {
    async fn close_stream(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.close().await?;
        }
        Ok(())
    }

    async fn shutdown(mut self) -> Result<()> {
        let stream_result = self.close_stream().await;
        let process_result = self.process.shutdown(Duration::from_secs(5)).await;
        stream_result?;
        process_result.map(|_| ()).map_err(|error| {
            HarnessError::Process(format!("joining fail-closed admission CLI: {error}"))
        })
    }
}

#[allow(clippy::too_many_lines)]
async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    honeypot: &EndpointHoneypot,
) -> Result<FailClosedEvidence> {
    let started = TokioInstant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "fail-closed admission started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    cluster
        .wait_for_peer_readiness(super::STARTUP_TIMEOUT)
        .await?;
    assert_public_health_ready(
        cluster.relay("relay-a")?.consumer_addr()?,
        &harness.pki.server_ca.certificate_der,
    )
    .await?;

    let target =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("fail-closed target device is missing".into())
        })?;
    let inactive = harness.topology.devices_a.get(1).ok_or_else(|| {
        HarnessError::InvalidInput("fail-closed inactive device is missing".into())
    })?;
    let sibling = harness.topology.devices_a.get(2).ok_or_else(|| {
        HarnessError::InvalidInput("fail-closed sibling device is missing".into())
    })?;
    let target_service = *harness
        .topology
        .service_ids
        .get(&target.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("fail-closed target service is missing".into())
        })?;
    let sibling_service = *harness
        .topology
        .service_ids
        .get(&sibling.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("fail-closed sibling service is missing".into())
        })?;
    // The duplicate is seeded on the last tenant-A device, which is the
    // sibling.  It must never be addressed by identifier: only the ambiguous
    // service-type label may reach it.
    let duplicate_service = harness.ambiguous_echo_service.ok_or_else(|| {
        HarnessError::InvalidInput(
            "fail-closed admission requires the seeded duplicate echo service".into(),
        )
    })?;
    if duplicate_service == sibling_service || duplicate_service == target_service {
        return Err(HarnessError::Process(
            "fail-closed duplicate echo service collided with a primary service".into(),
        ));
    }
    let target_service_path = target_service.to_string();
    let sibling_service_path = sibling_service.to_string();
    let target_canary = format!("m7-i04-target:{}", target.id);
    let sibling_canary = format!("m7-i04-sibling:{}", sibling.id);

    let target_profile_dir = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut target_profile = write_device_profile(
        target_profile_dir.path(),
        target.id,
        target_service,
        &target_canary,
        cluster.device_fanout.local_addr(),
        &target.certificate.certificate_pem,
        &target.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    target_profile.config.rotation = tunnel_core::RotationConfig::default();
    target_profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("fail-closed target config: {error}"))
    })?;
    let sibling_profile_dir = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut sibling_profile = write_device_profile(
        sibling_profile_dir.path(),
        sibling.id,
        sibling_service,
        &sibling_canary,
        cluster.tenant_b_fanout.local_addr(),
        &sibling.certificate.certificate_pem,
        &sibling.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    sibling_profile.config.rotation = tunnel_core::RotationConfig::default();
    sibling_profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("fail-closed sibling config: {error}"))
    })?;

    let token_a = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(240),
            ..OidcTokenOptions::default()
        },
    )?;
    let token_b = harness.oidc.issue_with(
        &harness.topology.consumers_b[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(240),
            ..OidcTokenOptions::default()
        },
    )?;

    let (target_process, target_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        cluster.relay("relay-c")?.consumer_addr()?,
        &target_profile,
        &token_a,
        target.id,
        target_service,
    )
    .await?;
    let mut target_cli = Some(LiveCli {
        process: target_process,
        stream: Some(target_stream),
    });
    let (sibling_process, sibling_stream) = match start_cli_smoke(
        harness,
        cluster.tenant_b_fanout.local_addr(),
        cluster.relay("relay-b")?.consumer_addr()?,
        &sibling_profile,
        &token_a,
        sibling.id,
        sibling_service,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            if let Some(cli) = target_cli.take() {
                let _ = cli.shutdown().await;
            }
            return Err(error);
        }
    };
    let mut sibling_cli = Some(LiveCli {
        process: sibling_process,
        stream: Some(sibling_stream),
    });

    let matrix = matrix(MatrixContext {
        cluster,
        harness,
        honeypot,
        target_cli: &mut target_cli,
        sibling_cli: &mut sibling_cli,
        target_id: target.id,
        target_tenant: target.tenant_id,
        target_service,
        target_service_path: &target_service_path,
        target_canary: target_canary.as_bytes(),
        sibling_id: sibling.id,
        sibling_tenant: sibling.tenant_id,
        sibling_service,
        sibling_service_path: &sibling_service_path,
        duplicate_service,
        sibling_canary: sibling_canary.as_bytes(),
        inactive_id: inactive.id,
        inactive_tenant: inactive.tenant_id,
        token_a: &token_a,
        token_b: &token_b,
        target_profile: &target_profile,
        started,
    })
    .await;
    let sibling_cleanup = match sibling_cli.take() {
        Some(cli) => cli.shutdown().await,
        None => Ok(()),
    };
    let target_cleanup = match target_cli.take() {
        Some(cli) => cli.shutdown().await,
        None => Ok(()),
    };
    match (matrix, sibling_cleanup, target_cleanup) {
        (Err(error), _, _) => Err(error),
        (Ok(_), Err(error), _) | (Ok(_), Ok(()), Err(error)) => Err(error),
        (Ok(evidence), Ok(()), Ok(())) => Ok(evidence),
    }
}

struct MatrixContext<'a> {
    cluster: &'a mut ProductionCluster,
    harness: &'a RunningHarness,
    honeypot: &'a EndpointHoneypot,
    target_cli: &'a mut Option<LiveCli>,
    sibling_cli: &'a mut Option<LiveCli>,
    target_id: Uuid,
    target_tenant: Uuid,
    target_service: Uuid,
    target_service_path: &'a str,
    target_canary: &'a [u8],
    sibling_id: Uuid,
    sibling_tenant: Uuid,
    sibling_service: Uuid,
    sibling_service_path: &'a str,
    /// The seeded second active echo service on the sibling device.  Never
    /// addressed by identifier; it exists so the bare label is ambiguous.
    duplicate_service: Uuid,
    sibling_canary: &'a [u8],
    inactive_id: Uuid,
    inactive_tenant: Uuid,
    token_a: &'a str,
    token_b: &'a str,
    target_profile: &'a crate::acceptance::helpers::DeviceProfile,
    started: TokioInstant,
}

#[allow(clippy::too_many_lines)]
async fn matrix(context: MatrixContext<'_>) -> Result<FailClosedEvidence> {
    let MatrixContext {
        cluster,
        harness,
        honeypot,
        target_cli,
        sibling_cli,
        target_id,
        target_tenant,
        target_service,
        target_service_path,
        target_canary,
        sibling_id,
        sibling_tenant,
        sibling_service,
        sibling_service_path,
        duplicate_service,
        sibling_canary,
        inactive_id,
        inactive_tenant,
        token_a,
        token_b,
        target_profile,
        started,
    } = context;
    let server_ca = &harness.pki.server_ca.certificate_der;

    // ---- Baseline canaries and deterministic owner placement ----
    target_cli
        .as_mut()
        .ok_or_else(|| HarnessError::Process("fail-closed target CLI was not retained".into()))?
        .stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("fail-closed target stream was not retained".into()))?
        .round_trip(b"m7-i04-target-baseline", target_canary)
        .await?;
    sibling_cli
        .as_mut()
        .ok_or_else(|| HarnessError::Process("fail-closed sibling CLI was not retained".into()))?
        .stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("fail-closed sibling stream was not retained".into()))?
        .round_trip(b"m7-i04-sibling-baseline", sibling_canary)
        .await?;
    let target_owner = cluster
        .catalog
        .current_owner(target_tenant, target_id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading fail-closed target owner: {error}")))?
        .ok_or_else(|| {
            HarnessError::Process("fail-closed target CLI did not retain an owner".into())
        })?;
    let sibling_owner = cluster
        .catalog
        .current_owner(sibling_tenant, sibling_id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading fail-closed sibling owner: {error}"))
        })?
        .ok_or_else(|| {
            HarnessError::Process("fail-closed sibling CLI did not retain an owner".into())
        })?;
    let owner_node = target_owner.token.node_id.clone();
    let sibling_owner_node = sibling_owner.token.node_id.clone();
    if owner_node != "relay-a" || sibling_owner_node != "relay-b" {
        return Err(HarnessError::Process(format!(
            "fail-closed owner assignment was not deterministic: target={owner_node}, sibling={sibling_owner_node}, expected relay-a and relay-b"
        )));
    }
    // Every remote scenario uses relay-C, which owns neither device, so a
    // real private peer hop is required to reach either owner.
    let remote_ingress = cluster.relay("relay-c")?.consumer_addr()?;
    let remote_ingress_is_not_owner = true;
    let baseline = counters(cluster).await?;
    let baseline_target_dispatches = baseline
        .dispatches
        .get(&owner_node)
        .copied()
        .unwrap_or_default();
    let baseline_sibling_dispatches = baseline
        .dispatches
        .get(&sibling_owner_node)
        .copied()
        .unwrap_or_default();
    if baseline_target_dispatches == 0 || baseline_sibling_dispatches == 0 {
        return Err(HarnessError::Process(
            "fail-closed baseline canaries did not dispatch".into(),
        ));
    }

    // ---- Control: prove the request-body read is on this route ----
    // An admitted target whose sentinel withholds its declared body must reach
    // the relay's own body deadline.  Without this every zero-delivery
    // rejection below would be unfalsifiable.
    let before = counters(cluster).await?;
    let body_read_control = sentinel_echo(SentinelRequest {
        label: "body_read_control",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Withheld(WITHHELD_BODY_BYTES),
    })
    .await?
    .outcome;
    let after = counters(cluster).await?;
    let body_read_control_dispatch_delta = before.dispatch_delta(&after);
    let body_read_control_owner_chunk_read_delta = before.chunk_read_delta(&after);

    // ---- EC-003: absent, ambiguous, duplicate and inactive targets ----
    cluster
        .catalog
        .revoke_device(inactive_tenant, inactive_id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("revoking fail-closed inactive device: {error}"))
        })?;
    let before = counters(cluster).await?;
    let absent_device = sentinel_echo(SentinelRequest {
        label: "absent_device",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: Uuid::new_v4(),
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Withheld(WITHHELD_BODY_BYTES),
    })
    .await?
    .outcome;
    let unknown_service_path = Uuid::new_v4().to_string();
    let unknown_service = sentinel_echo(SentinelRequest {
        label: "unknown_service",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: unknown_service_path.as_str(),
        headers: &[],
        plan: BodyPlan::Withheld(WITHHELD_BODY_BYTES),
    })
    .await?
    .outcome;
    let inactive_device = sentinel_echo(SentinelRequest {
        label: "inactive_device",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: inactive_id,
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Withheld(WITHHELD_BODY_BYTES),
    })
    .await?
    .outcome;
    // The sibling device carries two active echo services, so the bare type
    // label names more than one live target and must resolve to none.
    let ambiguous_service = sentinel_echo(SentinelRequest {
        label: "ambiguous_service",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: sibling_id,
        service: "echo",
        headers: &[],
        plan: BodyPlan::Withheld(WITHHELD_BODY_BYTES),
    })
    .await?
    .outcome;
    // A service identifier that belongs to a different device is a
    // caller-supplied destination.  It must never select that other device's
    // owner.
    let caller_destination_path = sibling_service.to_string();
    let caller_destination_headers = vec![
        (FORGED_DEVICE_HEADER, sibling_id.to_string()),
        (FORGED_SERVICE_HEADER, sibling_service.to_string()),
        (FORGED_OWNER_NODE_HEADER, sibling_owner_node.clone()),
    ];
    let caller_destination = sentinel_echo(SentinelRequest {
        label: "caller_destination",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: caller_destination_path.as_str(),
        headers: &caller_destination_headers,
        plan: BodyPlan::Withheld(WITHHELD_BODY_BYTES),
    })
    .await?
    .outcome;
    // M7-C47: the same duplicate label through the stream upgrade must reach
    // the same typed ambiguous outcome through the shared resolver, with no
    // 101 and no owner selection.
    let ambiguous_stream = safe_stream_probe(
        "ambiguous_stream",
        remote_ingress,
        server_ca,
        token_a,
        sibling_id,
        "echo",
    )
    .await?;
    if ambiguous_stream.status == 101 {
        return Err(HarnessError::Process(
            "fail-closed ambiguous stream upgrade reached 101; the duplicate label selected a service".into(),
        ));
    }
    // The listing route resolves nothing: it stays live and shows both
    // active echo services, so the consumer can see why the label is
    // ambiguous and address one by identifier instead.
    let listing = authenticated_request(
        remote_ingress,
        server_ca,
        Some(token_a),
        "GET",
        &format!("/v1/devices/{sibling_id}/services"),
    )
    .await?;
    let ambiguous_listing_status = listing.status;
    let ambiguous_listing_active_echo_services =
        serde_json::from_slice::<serde_json::Value>(&listing.body)
            .ok()
            .and_then(|value| value.as_array().cloned())
            .map(|services| {
                services
                    .iter()
                    .filter(|service| {
                        service
                            .get("service_type")
                            .and_then(serde_json::Value::as_str)
                            == Some("echo")
                            && service.get("active").and_then(serde_json::Value::as_bool)
                                == Some(true)
                            && service
                                .get("service_id")
                                .and_then(serde_json::Value::as_str)
                                .and_then(|id| id.parse::<Uuid>().ok())
                                .is_some_and(|id| id == sibling_service || id == duplicate_service)
                    })
                    .count()
            })
            .unwrap_or_default();
    let after = counters(cluster).await?;
    let ec003_dispatch_delta = before.dispatch_delta(&after);
    let ec003_owner_chunk_read_delta = before.chunk_read_delta(&after);

    // The same label against a device with exactly one active service still
    // resolves, which is what makes the ambiguous rejection above an
    // ambiguity outcome rather than a broken label path.
    wait_for_echo_ready(
        remote_ingress,
        server_ca,
        token_a,
        target_id,
        target_service_path,
        target_canary,
    )
    .await?;
    let label_payload = b"m7-i04-unambiguous-label";
    let unambiguous = sentinel_echo(SentinelRequest {
        label: "unambiguous_label",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: "echo",
        headers: &[],
        plan: BodyPlan::Delivered(label_payload.to_vec()),
    })
    .await?;
    let unambiguous_label_status = unambiguous.outcome.status;
    let unambiguous_label_response_exact =
        echo_body_matches(&unambiguous.body, target_canary, label_payload);

    // ---- EC-017: the peer endpoint comes only from verified membership ----
    let forged_headers = forged_endpoint_headers(
        honeypot,
        harness.topology.tenant_b.id,
        sibling_id,
        sibling_service,
        &sibling_owner_node,
    );
    wait_for_echo_ready(
        remote_ingress,
        server_ca,
        token_a,
        target_id,
        target_service_path,
        target_canary,
    )
    .await?;
    let endpoint_payload = b"m7-i04-forged-endpoint";
    let forged = sentinel_echo(SentinelRequest {
        label: "forged_peer_endpoint",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: target_service_path,
        headers: &forged_headers,
        plan: BodyPlan::Delivered(endpoint_payload.to_vec()),
    })
    .await?;
    let forged_endpoint_response_exact =
        echo_body_matches(&forged.body, target_canary, endpoint_payload);
    // A real remote owner hop happened: relay-C is not the owner and the
    // owner's canary came back, so the membership-selected peer address was
    // used and the honeypot zeros below are meaningful.
    let remote_route_proved = forged.outcome.status == 200 && forged_endpoint_response_exact;
    tokio::time::sleep(HONEYPOT_OBSERVATION).await;
    let forged_endpoint_udp_datagrams = honeypot.datagrams();
    let forged_endpoint_tcp_connections = honeypot.connections();
    // The honeypot zeros above close the address half of EC-017.  This closes
    // the server-name half on the connection that did happen: the owner's own
    // peer listener reports the server name the ingress relay presented, and
    // it must be the one in the owner's verified membership record rather than
    // any name the consumer supplied.
    let membership_server_name = cluster
        .fixture
        .membership(&owner_node)
        .map(|membership| membership.payload.server_name.clone())
        .ok_or_else(|| {
            HarnessError::Process(
                "fail-closed fixture held no signed membership for the owner relay".into(),
            )
        })?;
    let caller_named_server_names = [
        honeypot.tcp_addr.to_string(),
        honeypot.tcp_addr.ip().to_string(),
        honeypot.udp_addr.to_string(),
        honeypot.udp_addr.ip().to_string(),
    ];
    let owner_peer_listener = cluster
        .relay(&owner_node)?
        .peer_server_stats()
        .ok_or_else(|| {
            HarnessError::Process(
                "the owner relay exposed no peer listener diagnostics for the server-name assertion"
                    .into(),
            )
        })?;
    let ingress_peer_connections = owner_peer_listener
        .connections
        .iter()
        .filter(|connection| connection.peer_node_id == INGRESS_NODE_ID)
        .count();
    if ingress_peer_connections == 0 {
        return Err(HarnessError::Process(
            "the remote hop left no peer connection from the ingress relay, so no server name could be observed".into(),
        ));
    }
    let peer_connection_server_name_from_membership = owner_peer_listener
        .connections
        .iter()
        .filter(|connection| connection.peer_node_id == INGRESS_NODE_ID)
        .all(|connection| {
            connection.observed_server_name.as_deref() == Some(membership_server_name.as_str())
                && !caller_named_server_names
                    .iter()
                    .any(|named| connection.observed_server_name.as_deref() == Some(named.as_str()))
        });

    // ---- EC-049: preflight completes before any body read or forward ----
    let before = counters(cluster).await?;
    let preflight_cross_scope = sentinel_echo(SentinelRequest {
        label: "preflight_cross_scope",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_b,
        device_id: sibling_id,
        service: sibling_service_path,
        headers: &forged_headers,
        plan: BodyPlan::Withheld(WITHHELD_BODY_BYTES),
    })
    .await?
    .outcome;
    let after = counters(cluster).await?;
    let preflight_dispatch_delta = before.dispatch_delta(&after);
    let preflight_owner_chunk_read_delta = before.chunk_read_delta(&after);

    // ---- EC-031: empty body versus failed body ----
    wait_for_echo_ready(
        remote_ingress,
        server_ca,
        token_a,
        target_id,
        target_service_path,
        target_canary,
    )
    .await?;
    let before = counters(cluster).await?;
    let empty = sentinel_echo(SentinelRequest {
        label: "empty_body",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Delivered(Vec::new()),
    })
    .await?;
    let after = counters(cluster).await?;
    let empty_body_status = empty.outcome.status;
    let empty_body_response_exact = echo_body_matches(&empty.body, target_canary, &[]);
    let empty_body_dispatch_delta = before.dispatch_delta(&after);
    let empty_body_owner_chunk_read_delta = before.chunk_read_delta(&after);
    if !empty_body_response_exact {
        return Err(HarnessError::Process(format!(
            "fail-closed empty_body_response_exact failed: status={empty_body_status} code={:?} execution={:?} response_len={} canary_len={} dispatch_delta={empty_body_dispatch_delta} owner_chunk_read_delta={empty_body_owner_chunk_read_delta}",
            empty.outcome.code,
            empty.outcome.execution,
            empty.body.len(),
            target_canary.len(),
        )));
    }

    let before = counters(cluster).await?;
    let failed_body = sentinel_echo(SentinelRequest {
        label: "failed_body",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Failed(WITHHELD_BODY_BYTES),
    })
    .await?
    .outcome;
    let after = counters(cluster).await?;
    let failed_body_dispatch_delta = before.dispatch_delta(&after);
    let failed_body_owner_chunk_read_delta = before.chunk_read_delta(&after);
    let empty_and_failed_body_distinct = empty_body_status == 200
        && empty_body_response_exact
        && failed_body.status != 200
        && failed_body.body_stream_failed;
    let safe_no_body_status = authenticated_get_status(
        remote_ingress,
        server_ca,
        Some(token_a),
        &format!("/v1/devices/{target_id}/services"),
    )
    .await?;

    // ---- EC-009: advertised routes and the excluded browser boundary ----
    let before = counters(cluster).await?;
    let mut advertised_public_routes = 0_usize;
    for path in ["/livez", "/readyz"] {
        let response = public_health_request(remote_ingress, server_ca, path).await?;
        validate_public_health_response(
            &response,
            path,
            200,
            if path == "/livez" {
                super::LIVEZ_BODY
            } else {
                super::READYZ_BODY
            },
        )?;
        advertised_public_routes += 1;
    }
    // The three authenticated consumer routes are exercised elsewhere in this
    // same matrix; count them from their observed live results.
    if safe_no_body_status == 200 {
        advertised_public_routes += 1;
    }
    if unambiguous_label_status == 200 {
        advertised_public_routes += 1;
    }
    let devices_index_status =
        authenticated_get_status(remote_ingress, server_ca, Some(token_a), "/v1/devices").await?;
    if devices_index_status == 200 {
        advertised_public_routes += 1;
    }
    let mut excluded_public_routes_typed = 0_usize;
    for path in EXCLUDED_PUBLIC_ROUTES {
        let status =
            authenticated_get_status(remote_ingress, server_ca, Some(token_a), path).await?;
        if status == 404 {
            excluded_public_routes_typed += 1;
        } else {
            return Err(HarnessError::Process(format!(
                "fail-closed excluded public route {path} returned status {status}, expected a typed 404"
            )));
        }
    }
    let after = counters(cluster).await?;
    let route_boundary_dispatch_delta = before.dispatch_delta(&after);
    // EC-009 is a browser CSP concern with no Rust surface.  The recorded
    // boundary is this explicit advertised route set plus the typed rejection
    // of every other path, with no silent retry elsewhere.
    let excluded_browser_boundary_recorded = advertised_public_routes
        == ADVERTISED_PUBLIC_ROUTES.len()
        && excluded_public_routes_typed == EXCLUDED_PUBLIC_ROUTES.len()
        && route_boundary_dispatch_delta == 0;

    // ---- EC-023 and EC-048: a real owner process dies mid-flight ----
    let before = counters(cluster).await?;
    let mut cli = target_cli
        .take()
        .ok_or_else(|| HarnessError::Process("fail-closed target CLI was not retained".into()))?;
    cli.close_stream().await?;
    let inflight_payload = vec![0x5a_u8; 4096];
    let inflight_request = sentinel_echo(SentinelRequest {
        label: "inflight_owner_kill",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Delivered(inflight_payload),
    });
    let kill = async {
        // SIGKILL: a zero grace period escalates immediately, so the owner
        // connector never runs its normal shutdown path.
        cli.process.shutdown(Duration::ZERO).await
    };
    let (inflight_result, kill_status) = tokio::join!(inflight_request, kill);
    let kill_status = kill_status.map_err(|error| {
        HarnessError::Process(format!("fail-closed owner kill did not reap: {error}"))
    })?;
    let owner_process_killed = !kill_status.success();
    let inflight = inflight_result?;
    let after = counters(cluster).await?;
    let inflight_kill_dispatch_delta = before.dispatch_delta(&after);
    // Either the mutation committed exactly once before the owner died, or it
    // ended as a typed non-success.  Anything else is unclassified.
    let inflight_kill_outcome_classified = if inflight.outcome.status == 200 {
        echo_body_matches(&inflight.body, target_canary, &vec![0x5a_u8; 4096])
            && inflight_kill_dispatch_delta == 1
    } else {
        inflight.outcome.code.is_some() && inflight.outcome.execution.is_some()
    };
    if !inflight_kill_outcome_classified {
        return Err(HarnessError::Process(format!(
            "fail-closed in-flight owner kill was unclassified: status={} code={:?} execution={:?} dispatch_delta={inflight_kill_dispatch_delta}",
            inflight.outcome.status, inflight.outcome.code, inflight.outcome.execution
        )));
    }
    cluster
        .wait_for_owner_clear(target_tenant, target_id, OWNER_CLEAR_TIMEOUT)
        .await?;
    let owner_after_kill = cluster
        .catalog
        .current_owner(target_tenant, target_id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading fail-closed owner after kill: {error}"))
        })?;
    // A fresh session is required: the pre-kill owner token is no longer
    // authoritative, so nothing can silently reuse it.
    let owner_identity_required_fresh = owner_after_kill
        .as_ref()
        .map(|owner| owner.token != target_owner.token)
        .unwrap_or(true);

    // ---- FP-04: consumed, unpolled and failed bodies under owner loss ----
    let before = counters(cluster).await?;
    let consumed_payload = vec![0x42_u8; 256];
    let owner_loss_consumed_mutation = sentinel_echo(SentinelRequest {
        label: "owner_loss_consumed_mutation",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Delivered(consumed_payload.clone()),
    })
    .await?
    .outcome;
    // The same consumed mutation again.  A relay that reselected or replayed
    // would show a dispatch on some relay; none may appear.
    let owner_loss_consumed_mutation_repeat = sentinel_echo(SentinelRequest {
        label: "owner_loss_consumed_mutation_repeat",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Delivered(consumed_payload),
    })
    .await?
    .outcome;
    // A safe request with no request body at all, through the advertised
    // stream endpoint: proven not dispatched, and no upgrade.
    let owner_loss_safe_unpolled = safe_stream_probe(
        "owner_loss_safe_unpolled",
        remote_ingress,
        server_ca,
        token_a,
        target_id,
        target_service_path,
    )
    .await?;
    if owner_loss_safe_unpolled.status == 101 {
        return Err(HarnessError::Process(
            "fail-closed safe stream upgrade reached 101 during owner loss; the owner token was not revalidated before attachment".into(),
        ));
    }
    // M7-C46: GET, HEAD and OPTIONS shaped requests at the lost owner's
    // POST-only echo route.  The relay serves none of them and reselects for
    // none of them: each is one typed not-dispatched rejection with no body,
    // and the counters prove no relay dispatched anything for any of them.
    let safe_method_before = counters(cluster).await?;
    let mut owner_loss_safe_methods = Vec::with_capacity(SAFE_METHOD_SHAPES.len());
    let mut get_envelope: Option<(u16, Option<u64>)> = None;
    let mut owner_loss_head_mirrors_typed_get = false;
    for method in SAFE_METHOD_SHAPES {
        let probe_started = TokioInstant::now();
        let response = authenticated_request(
            remote_ingress,
            server_ca,
            Some(token_a),
            method,
            &format!("/v1/devices/{target_id}/services/{target_service_path}/echo"),
        )
        .await?;
        let elapsed_ms = probe_started
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let (code, execution) = response.typed_envelope();
        match method {
            "GET" => get_envelope = Some((response.status, response.content_length)),
            "HEAD" => {
                owner_loss_head_mirrors_typed_get = response.body.is_empty()
                    && get_envelope.is_some_and(|(status, content_length)| {
                        status == response.status
                            && content_length.is_some()
                            && content_length == response.content_length
                    });
            }
            _ => {}
        }
        owner_loss_safe_methods.push(SentinelOutcome {
            label: method,
            status: response.status,
            code,
            execution,
            declared_body_bytes: 0,
            delivered_body_bytes: 0,
            body_polls: 0,
            body_stream_failed: false,
            transport_failed: false,
            elapsed_ms,
        });
    }
    let safe_method_after = counters(cluster).await?;
    let owner_loss_safe_method_dispatch_delta =
        safe_method_before.dispatch_delta(&safe_method_after);
    let owner_loss_safe_method_owner_chunk_read_delta =
        safe_method_before.chunk_read_delta(&safe_method_after);
    let owner_loss_failed_body = sentinel_echo(SentinelRequest {
        label: "owner_loss_failed_body",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Failed(WITHHELD_BODY_BYTES),
    })
    .await?
    .outcome;
    let post_kill_before = counters(cluster).await?;
    let post_kill_probe = sentinel_echo(SentinelRequest {
        label: "post_kill_probe",
        consumer_addr: remote_ingress,
        server_ca_der: server_ca,
        token: token_a,
        device_id: target_id,
        service: target_service_path,
        headers: &[],
        plan: BodyPlan::Delivered(vec![0x24_u8; 64]),
    })
    .await?
    .outcome;
    let post_kill_after = counters(cluster).await?;
    let post_kill_dispatch_delta = post_kill_before.dispatch_delta(&post_kill_after);
    // The surviving sibling owner keeps serving, which proves the fault was
    // scoped to the lost owner and that no unrelated backend absorbed the
    // rejected requests.
    let sibling_before = counters(cluster).await?;
    timeout(
        SIBLING_CANARY_TIMEOUT,
        sibling_cli
            .as_mut()
            .ok_or_else(|| HarnessError::Process("fail-closed sibling CLI was lost".into()))?
            .stream
            .as_mut()
            .ok_or_else(|| HarnessError::Process("fail-closed sibling stream was lost".into()))?
            .round_trip(b"m7-i04-sibling-after-owner-loss", sibling_canary),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("fail-closed sibling canary after owner loss timed out".into())
    })??;
    let sibling_after = counters(cluster).await?;
    let sibling_dispatch_delta_after_owner_kill =
        sibling_before.node_dispatch_delta(&sibling_after, &sibling_owner_node);
    let sibling_canary_survived = sibling_dispatch_delta_after_owner_kill == 1;
    let owner_loss_dispatch_delta = before.dispatch_delta(&sibling_before);
    let owner_loss_owner_chunk_read_delta = before.chunk_read_delta(&sibling_before);
    // Nothing was reselected: no relay dispatched anything for either
    // consumed mutation, and the only dispatch in the window belongs to the
    // sibling's own canary.
    let mutation_reselected = owner_loss_dispatch_delta != 0;

    // ---- IN-03: one bounded safe retry bridges committed successor readiness
    let (restarted_process, restarted_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        cluster.relay("relay-c")?.consumer_addr()?,
        target_profile,
        token_a,
        target_id,
        target_service,
    )
    .await?;
    *target_cli = Some(LiveCli {
        process: restarted_process,
        stream: Some(restarted_stream),
    });
    let retry_before = counters(cluster).await?;
    let safe_retry_attempts = 1_u64;
    let retry = target_cli
        .as_mut()
        .ok_or_else(|| HarnessError::Process("fail-closed retry CLI was lost".into()))?
        .stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("fail-closed retry stream was lost".into()))?
        .round_trip(b"m7-i04-safe-retry", target_canary)
        .await;
    let safe_retry_succeeded = retry.is_ok();
    retry?;
    let retry_after = counters(cluster).await?;
    let safe_retry_dispatch_delta = retry_before.dispatch_delta(&retry_after);

    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    Ok(FailClosedEvidence {
        relay_count: 3,
        remote_ingress_is_not_owner,
        baseline_target_dispatches,
        baseline_sibling_dispatches,
        body_read_control,
        body_read_control_dispatch_delta,
        body_read_control_owner_chunk_read_delta,
        absent_device,
        unknown_service,
        inactive_device,
        ambiguous_service,
        unambiguous_label_status,
        unambiguous_label_response_exact,
        caller_destination,
        ambiguous_stream,
        ambiguous_listing_status,
        ambiguous_listing_active_echo_services,
        ec003_dispatch_delta,
        ec003_owner_chunk_read_delta,
        remote_route_proved,
        forged_endpoint_response_exact,
        forged_endpoint_udp_datagrams,
        forged_endpoint_tcp_connections,
        peer_connection_server_name_from_membership,
        preflight_cross_scope,
        preflight_dispatch_delta,
        preflight_owner_chunk_read_delta,
        empty_body_status,
        empty_body_response_exact,
        empty_body_dispatch_delta,
        empty_body_owner_chunk_read_delta,
        failed_body,
        failed_body_dispatch_delta,
        failed_body_owner_chunk_read_delta,
        empty_and_failed_body_distinct,
        safe_no_body_status,
        owner_loss_consumed_mutation,
        owner_loss_consumed_mutation_repeat,
        owner_loss_safe_unpolled,
        owner_loss_failed_body,
        owner_loss_safe_methods,
        owner_loss_head_mirrors_typed_get,
        owner_loss_safe_method_dispatch_delta,
        owner_loss_safe_method_owner_chunk_read_delta,
        owner_loss_dispatch_delta,
        owner_loss_owner_chunk_read_delta,
        mutation_reselected,
        safe_retry_attempts,
        safe_retry_succeeded,
        safe_retry_dispatch_delta,
        owner_process_killed,
        inflight_kill_dispatch_delta,
        inflight_kill_outcome_classified,
        post_kill_probe,
        post_kill_dispatch_delta,
        owner_identity_required_fresh,
        sibling_dispatch_delta_after_owner_kill,
        sibling_canary_survived,
        advertised_public_routes,
        excluded_public_routes_typed,
        route_boundary_dispatch_delta,
        excluded_browser_boundary_recorded,
        elapsed_ms,
        cleanup_joined: false,
    })
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{
        ADVERTISED_PUBLIC_ROUTES, EXCLUDED_PUBLIC_ROUTES, FailClosedEvidence, SAFE_METHOD_SHAPES,
        SentinelOutcome, validate_fail_closed_evidence,
    };
    use crate::acceptance_test_support::{assert_failed, assert_rejected};

    fn rejection(
        label: &'static str,
        status: u16,
        code: &'static str,
        declared: u64,
    ) -> SentinelOutcome {
        SentinelOutcome {
            label,
            status,
            code: Some(code),
            execution: Some("not_dispatched"),
            declared_body_bytes: declared,
            delivered_body_bytes: 0,
            body_polls: 1,
            body_stream_failed: false,
            transport_failed: false,
            elapsed_ms: 25,
        }
    }

    fn consumed(label: &'static str, declared: u64) -> SentinelOutcome {
        SentinelOutcome {
            label,
            status: 503,
            code: Some("PEER_UNTRUSTED"),
            execution: Some("not_dispatched"),
            declared_body_bytes: declared,
            delivered_body_bytes: declared,
            body_polls: 2,
            body_stream_failed: false,
            transport_failed: false,
            elapsed_ms: 40,
        }
    }

    fn failed(label: &'static str) -> SentinelOutcome {
        SentinelOutcome {
            label,
            status: 0,
            code: None,
            execution: None,
            declared_body_bytes: 512,
            delivered_body_bytes: 0,
            body_polls: 1,
            body_stream_failed: true,
            transport_failed: true,
            elapsed_ms: 30,
        }
    }

    fn evidence() -> FailClosedEvidence {
        FailClosedEvidence {
            relay_count: 3,
            remote_ingress_is_not_owner: true,
            baseline_target_dispatches: 1,
            baseline_sibling_dispatches: 1,
            body_read_control: SentinelOutcome {
                label: "body_read_control",
                status: 408,
                code: Some("BODY_TIMEOUT"),
                execution: Some("not_dispatched"),
                declared_body_bytes: 512,
                delivered_body_bytes: 0,
                body_polls: 1,
                body_stream_failed: false,
                transport_failed: false,
                elapsed_ms: 10_050,
            },
            body_read_control_dispatch_delta: 0,
            body_read_control_owner_chunk_read_delta: 0,
            absent_device: rejection("absent_device", 404, "DEVICE_NOT_FOUND", 512),
            unknown_service: rejection("unknown_service", 404, "SERVICE_NOT_FOUND", 512),
            inactive_device: rejection("inactive_device", 404, "DEVICE_NOT_FOUND", 512),
            ambiguous_service: rejection("ambiguous_service", 409, "SERVICE_AMBIGUOUS", 512),
            unambiguous_label_status: 200,
            unambiguous_label_response_exact: true,
            ambiguous_stream: SentinelOutcome {
                label: "ambiguous_stream",
                status: 409,
                code: Some("SERVICE_AMBIGUOUS"),
                execution: Some("not_dispatched"),
                declared_body_bytes: 0,
                delivered_body_bytes: 0,
                body_polls: 0,
                body_stream_failed: false,
                transport_failed: false,
                elapsed_ms: 20,
            },
            ambiguous_listing_status: 200,
            ambiguous_listing_active_echo_services: 2,
            caller_destination: rejection("caller_destination", 404, "SERVICE_NOT_FOUND", 512),
            ec003_dispatch_delta: 0,
            ec003_owner_chunk_read_delta: 0,
            remote_route_proved: true,
            forged_endpoint_response_exact: true,
            forged_endpoint_udp_datagrams: 0,
            forged_endpoint_tcp_connections: 0,
            peer_connection_server_name_from_membership: true,
            preflight_cross_scope: rejection("preflight_cross_scope", 404, "DEVICE_NOT_FOUND", 512),
            preflight_dispatch_delta: 0,
            preflight_owner_chunk_read_delta: 0,
            empty_body_status: 200,
            empty_body_response_exact: true,
            empty_body_dispatch_delta: 1,
            empty_body_owner_chunk_read_delta: 1,
            failed_body: failed("failed_body"),
            failed_body_dispatch_delta: 0,
            failed_body_owner_chunk_read_delta: 0,
            empty_and_failed_body_distinct: true,
            safe_no_body_status: 200,
            owner_loss_consumed_mutation: consumed("owner_loss_consumed_mutation", 256),
            owner_loss_consumed_mutation_repeat: consumed(
                "owner_loss_consumed_mutation_repeat",
                256,
            ),
            owner_loss_safe_unpolled: SentinelOutcome {
                label: "owner_loss_safe_unpolled",
                status: 503,
                code: Some("PEER_UNTRUSTED"),
                execution: Some("not_dispatched"),
                declared_body_bytes: 0,
                delivered_body_bytes: 0,
                body_polls: 0,
                body_stream_failed: false,
                transport_failed: false,
                elapsed_ms: 18,
            },
            owner_loss_failed_body: failed("owner_loss_failed_body"),
            owner_loss_safe_methods: SAFE_METHOD_SHAPES
                .into_iter()
                .map(|method| SentinelOutcome {
                    label: method,
                    status: 405,
                    code: (method != "HEAD").then_some("METHOD_NOT_ALLOWED"),
                    execution: (method != "HEAD").then_some("not_dispatched"),
                    declared_body_bytes: 0,
                    delivered_body_bytes: 0,
                    body_polls: 0,
                    body_stream_failed: false,
                    transport_failed: false,
                    elapsed_ms: 5,
                })
                .collect(),
            owner_loss_head_mirrors_typed_get: true,
            owner_loss_safe_method_dispatch_delta: 0,
            owner_loss_safe_method_owner_chunk_read_delta: 0,
            owner_loss_dispatch_delta: 0,
            owner_loss_owner_chunk_read_delta: 0,
            mutation_reselected: false,
            safe_retry_attempts: 1,
            safe_retry_succeeded: true,
            safe_retry_dispatch_delta: 1,
            owner_process_killed: true,
            inflight_kill_dispatch_delta: 1,
            inflight_kill_outcome_classified: true,
            post_kill_probe: consumed("post_kill_probe", 64),
            post_kill_dispatch_delta: 0,
            owner_identity_required_fresh: true,
            sibling_dispatch_delta_after_owner_kill: 1,
            sibling_canary_survived: true,
            advertised_public_routes: ADVERTISED_PUBLIC_ROUTES.len(),
            excluded_public_routes_typed: EXCLUDED_PUBLIC_ROUTES.len(),
            route_boundary_dispatch_delta: 0,
            excluded_browser_boundary_recorded: true,
            elapsed_ms: 42_000,
            cleanup_joined: true,
        }
    }

    #[test]
    fn fail_closed_validator_accepts_complete_evidence() {
        validate_fail_closed_evidence(&evidence()).expect("complete fail-closed evidence is valid");
    }

    #[test]
    fn every_required_flag_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut FailClosedEvidence));
        let flags: [Disable; 14] = [
            ("remote_ingress_is_not_owner", |e| {
                e.remote_ingress_is_not_owner = false
            }),
            ("remote_route_proved", |e| e.remote_route_proved = false),
            ("forged_endpoint_response_exact", |e| {
                e.forged_endpoint_response_exact = false
            }),
            ("peer_connection_server_name_from_membership", |e| {
                e.peer_connection_server_name_from_membership = false
            }),
            ("unambiguous_label_response_exact", |e| {
                e.unambiguous_label_response_exact = false
            }),
            ("empty_body_response_exact", |e| {
                e.empty_body_response_exact = false
            }),
            ("empty_and_failed_body_distinct", |e| {
                e.empty_and_failed_body_distinct = false
            }),
            ("safe_retry_succeeded", |e| e.safe_retry_succeeded = false),
            ("owner_process_killed", |e| e.owner_process_killed = false),
            ("inflight_kill_outcome_classified", |e| {
                e.inflight_kill_outcome_classified = false
            }),
            ("owner_identity_required_fresh", |e| {
                e.owner_identity_required_fresh = false
            }),
            ("sibling_canary_survived", |e| {
                e.sibling_canary_survived = false
            }),
            ("excluded_browser_boundary_recorded", |e| {
                e.excluded_browser_boundary_recorded = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (name, disable) in flags {
            let mut value = evidence();
            disable(&mut value);
            assert_rejected(validate_fail_closed_evidence(&value), name);
        }
    }

    #[test]
    fn every_zero_dispatch_and_chunk_bound_is_enforced() {
        type Mutate = (&'static str, fn(&mut FailClosedEvidence));
        let counters: [Mutate; 12] = [
            ("body_read_control_dispatch_delta", |e| {
                e.body_read_control_dispatch_delta = 1
            }),
            ("body_read_control_owner_chunk_read_delta", |e| {
                e.body_read_control_owner_chunk_read_delta = 1
            }),
            ("ec003_dispatch_delta", |e| e.ec003_dispatch_delta = 1),
            ("ec003_owner_chunk_read_delta", |e| {
                e.ec003_owner_chunk_read_delta = 1
            }),
            ("preflight_dispatch_delta", |e| {
                e.preflight_dispatch_delta = 1
            }),
            ("preflight_owner_chunk_read_delta", |e| {
                e.preflight_owner_chunk_read_delta = 1
            }),
            ("failed_body_dispatch_delta", |e| {
                e.failed_body_dispatch_delta = 1
            }),
            ("failed_body_owner_chunk_read_delta", |e| {
                e.failed_body_owner_chunk_read_delta = 1
            }),
            ("owner_loss_dispatch_delta", |e| {
                e.owner_loss_dispatch_delta = 1
            }),
            ("owner_loss_owner_chunk_read_delta", |e| {
                e.owner_loss_owner_chunk_read_delta = 1
            }),
            ("post_kill_dispatch_delta", |e| {
                e.post_kill_dispatch_delta = 1
            }),
            ("route_boundary_dispatch_delta", |e| {
                e.route_boundary_dispatch_delta = 1
            }),
        ];
        for (name, mutate) in counters {
            let mut value = evidence();
            mutate(&mut value);
            assert_rejected(validate_fail_closed_evidence(&value), name);
        }
    }

    #[test]
    fn every_ec003_target_requires_its_exact_code_and_preflight_proof() {
        type Mutate = (&'static str, fn(&mut FailClosedEvidence));
        let wrong_code: [Mutate; 5] = [
            ("absent_device", |e| {
                e.absent_device.code = Some("SERVICE_NOT_FOUND")
            }),
            ("unknown_service", |e| e.unknown_service.status = 403),
            ("inactive_device", |e| e.inactive_device.execution = None),
            ("ambiguous_service", |e| {
                // The silent first-match selection this gate closed would
                // surface as a success, never as the ambiguous outcome.
                e.ambiguous_service.status = 200;
                e.ambiguous_service.code = None;
            }),
            ("caller_destination", |e| {
                e.caller_destination.code = Some("DEVICE_NOT_FOUND")
            }),
        ];
        for (label, mutate) in wrong_code {
            let mut value = evidence();
            mutate(&mut value);
            assert_rejected(validate_fail_closed_evidence(&value), label);
        }

        let preflight: [Mutate; 5] = [
            ("absent_device", |e| {
                e.absent_device.delivered_body_bytes = 512
            }),
            ("unknown_service", |e| {
                e.unknown_service.declared_body_bytes = 0
            }),
            ("inactive_device", |e| e.inactive_device.elapsed_ms = 9_900),
            ("ambiguous_service", |e| {
                e.ambiguous_service.delivered_body_bytes = 1
            }),
            ("caller_destination", |e| {
                e.caller_destination.elapsed_ms = 11_000
            }),
        ];
        for (label, mutate) in preflight {
            let mut value = evidence();
            mutate(&mut value);
            assert_rejected(validate_fail_closed_evidence(&value), label);
        }
    }

    #[test]
    fn the_body_read_control_must_actually_reach_the_relay_body_deadline() {
        // Without this control, every zero-delivery rejection above would be
        // unfalsifiable, so a fast control must fail the gate.
        let mut fast = evidence();
        fast.body_read_control.elapsed_ms = 40;
        assert_rejected(validate_fail_closed_evidence(&fast), "body_read_control");
        let mut wrong_code = evidence();
        wrong_code.body_read_control.code = Some("BODY_LIMIT");
        assert_rejected(
            validate_fail_closed_evidence(&wrong_code),
            "body_read_control",
        );
        let mut delivered = evidence();
        delivered.body_read_control.delivered_body_bytes = 512;
        assert_rejected(
            validate_fail_closed_evidence(&delivered),
            "body_read_control",
        );
    }

    #[test]
    fn a_caller_named_peer_address_must_never_be_reached() {
        let mut udp = evidence();
        udp.forged_endpoint_udp_datagrams = 1;
        assert_rejected(
            validate_fail_closed_evidence(&udp),
            "forged_endpoint_udp_datagrams",
        );
        let mut tcp = evidence();
        tcp.forged_endpoint_tcp_connections = 1;
        assert_rejected(
            validate_fail_closed_evidence(&tcp),
            "forged_endpoint_tcp_connections",
        );
    }

    /// C17: the address half alone is not EC-017.  Evidence that reaches no
    /// caller-named address is still rejected when the server name presented
    /// on the legitimate peer connection did not come from the verified
    /// membership record.
    #[test]
    fn a_membership_address_with_a_caller_chosen_server_name_must_be_rejected() {
        let mut named = evidence();
        assert_eq!(named.forged_endpoint_udp_datagrams, 0);
        assert_eq!(named.forged_endpoint_tcp_connections, 0);
        named.peer_connection_server_name_from_membership = false;
        assert_rejected(
            validate_fail_closed_evidence(&named),
            "peer_connection_server_name_from_membership",
        );
    }

    #[test]
    fn an_empty_body_must_stay_live_and_differ_from_a_failed_body() {
        let mut status = evidence();
        status.empty_body_status = 503;
        assert_rejected(validate_fail_closed_evidence(&status), "empty_body_status");
        let mut dispatch = evidence();
        dispatch.empty_body_dispatch_delta = 0;
        assert_rejected(
            validate_fail_closed_evidence(&dispatch),
            "empty_body_dispatch_delta",
        );
        let mut two = evidence();
        two.empty_body_dispatch_delta = 2;
        assert_rejected(
            validate_fail_closed_evidence(&two),
            "empty_body_dispatch_delta",
        );
        let mut unread = evidence();
        unread.empty_body_owner_chunk_read_delta = 0;
        assert_rejected(
            validate_fail_closed_evidence(&unread),
            "empty_body_owner_chunk_read_delta",
        );
        let mut not_failed = evidence();
        not_failed.failed_body.body_stream_failed = false;
        assert_rejected(validate_fail_closed_evidence(&not_failed), "failed_body");
        let mut succeeded = evidence();
        succeeded.failed_body.status = 200;
        assert_rejected(validate_fail_closed_evidence(&succeeded), "failed_body");
        let mut safe = evidence();
        safe.safe_no_body_status = 404;
        assert_rejected(validate_fail_closed_evidence(&safe), "safe_no_body_status");
    }

    #[test]
    fn owner_loss_requires_proven_not_dispatched_outcomes_and_no_replay() {
        type Mutate = (&'static str, fn(&mut FailClosedEvidence));
        let cases: [Mutate; 6] = [
            ("owner_loss_consumed_mutation", |e| {
                // An "unknown" execution is not a proven not-dispatched state.
                e.owner_loss_consumed_mutation.execution = Some("unknown")
            }),
            ("owner_loss_consumed_mutation", |e| {
                // A consumed body must be fully consumed, otherwise the
                // scenario never exercised the consumed case at all.
                e.owner_loss_consumed_mutation.delivered_body_bytes = 0
            }),
            ("owner_loss_consumed_mutation_repeat", |e| {
                e.owner_loss_consumed_mutation_repeat.status = 200
            }),
            ("owner_loss_safe_unpolled", |e| {
                e.owner_loss_safe_unpolled.execution = Some("unknown")
            }),
            ("owner_loss_safe_unpolled", |e| {
                e.owner_loss_safe_unpolled.declared_body_bytes = 256
            }),
            ("owner_loss_failed_body", |e| {
                e.owner_loss_failed_body.body_stream_failed = false
            }),
        ];
        for (label, mutate) in cases {
            let mut value = evidence();
            mutate(&mut value);
            assert_rejected(validate_fail_closed_evidence(&value), label);
        }
        let mut reselected = evidence();
        reselected.mutation_reselected = true;
        assert_rejected(
            validate_fail_closed_evidence(&reselected),
            "mutation_reselected",
        );
    }

    #[test]
    fn every_safe_method_shape_is_a_typed_not_dispatched_rejection() {
        // M7-C46: the relay never reselects on any method, so each safe
        // method shape must be exactly one typed rejection with no dispatch.
        type Mutate = (&'static str, fn(&mut FailClosedEvidence));
        let cases: [Mutate; 9] = [
            ("owner_loss_safe_methods", |e| {
                e.owner_loss_safe_methods.pop();
            }),
            ("owner_loss_safe_methods", |e| {
                e.owner_loss_safe_methods.swap(0, 2)
            }),
            ("GET", |e| e.owner_loss_safe_methods[0].status = 200),
            ("GET", |e| e.owner_loss_safe_methods[0].code = None),
            ("GET", |e| {
                e.owner_loss_safe_methods[0].execution = Some("unknown")
            }),
            ("HEAD", |e| e.owner_loss_safe_methods[1].status = 404),
            ("OPTIONS", |e| {
                e.owner_loss_safe_methods[2].code = Some("NOT_FOUND")
            }),
            ("OPTIONS", |e| {
                e.owner_loss_safe_methods[2].declared_body_bytes = 1
            }),
            ("owner_loss_head_mirrors_typed_get", |e| {
                e.owner_loss_head_mirrors_typed_get = false
            }),
        ];
        for (label, mutate) in cases {
            let mut value = evidence();
            mutate(&mut value);
            assert_rejected(validate_fail_closed_evidence(&value), label);
        }
        for (name, mutate) in [
            (
                "owner_loss_safe_method_dispatch_delta",
                (|e| e.owner_loss_safe_method_dispatch_delta = 1) as fn(&mut FailClosedEvidence),
            ),
            ("owner_loss_safe_method_owner_chunk_read_delta", |e| {
                e.owner_loss_safe_method_owner_chunk_read_delta = 1
            }),
        ] {
            let mut value = evidence();
            mutate(&mut value);
            assert_rejected(validate_fail_closed_evidence(&value), name);
        }
    }

    #[test]
    fn a_duplicate_label_is_ambiguous_through_the_stream_upgrade_too() {
        // M7-C47: a 101, a different code, a body, or a listing that hides
        // one of the duplicates each fail the gate.
        type Mutate = (&'static str, fn(&mut FailClosedEvidence));
        let cases: [Mutate; 6] = [
            ("ambiguous_stream", |e| {
                e.ambiguous_stream.status = 101;
                e.ambiguous_stream.code = None;
                e.ambiguous_stream.execution = None;
            }),
            ("ambiguous_stream", |e| {
                e.ambiguous_stream.code = Some("SERVICE_NOT_FOUND")
            }),
            ("ambiguous_stream", |e| {
                e.ambiguous_stream.execution = Some("unknown")
            }),
            ("ambiguous_stream", |e| {
                e.ambiguous_stream.delivered_body_bytes = 1
            }),
            ("ambiguous_listing_status", |e| {
                e.ambiguous_listing_status = 409
            }),
            ("ambiguous_listing_active_echo_services", |e| {
                e.ambiguous_listing_active_echo_services = 1
            }),
        ];
        for (label, mutate) in cases {
            let mut value = evidence();
            mutate(&mut value);
            assert_rejected(validate_fail_closed_evidence(&value), label);
        }
    }

    #[test]
    fn exactly_one_bounded_safe_retry_may_bridge_readiness() {
        for attempts in [0_u64, 2, 7] {
            let mut value = evidence();
            value.safe_retry_attempts = attempts;
            assert_rejected(validate_fail_closed_evidence(&value), "safe_retry_attempts");
        }
        for delta in [0_u64, 2] {
            let mut value = evidence();
            value.safe_retry_dispatch_delta = delta;
            assert_rejected(
                validate_fail_closed_evidence(&value),
                "safe_retry_dispatch_delta",
            );
        }
    }

    #[test]
    fn a_real_owner_loss_never_duplicates_an_effect_or_reuses_its_identity() {
        let mut duplicated = evidence();
        duplicated.inflight_kill_dispatch_delta = 2;
        assert_rejected(
            validate_fail_closed_evidence(&duplicated),
            "inflight_kill_dispatch_delta",
        );
        // Zero or one committed effect are both acceptable outcomes for an
        // in-flight mutation interrupted by a real process kill.
        let mut none = evidence();
        none.inflight_kill_dispatch_delta = 0;
        validate_fail_closed_evidence(&none)
            .expect("an interrupted in-flight mutation may commit no effect");
        let mut probe = evidence();
        probe.post_kill_probe.code = Some("REVERSE_CHANNEL_INTERRUPTED");
        assert_rejected(validate_fail_closed_evidence(&probe), "post_kill_probe");
        for delta in [0_u64, 2] {
            let mut value = evidence();
            value.sibling_dispatch_delta_after_owner_kill = delta;
            assert_rejected(
                validate_fail_closed_evidence(&value),
                "sibling_dispatch_delta_after_owner_kill",
            );
        }
    }

    #[test]
    fn the_excluded_browser_route_boundary_is_an_exact_set() {
        let mut fewer = evidence();
        fewer.advertised_public_routes = ADVERTISED_PUBLIC_ROUTES.len() - 1;
        assert_rejected(
            validate_fail_closed_evidence(&fewer),
            "advertised_public_routes",
        );
        let mut more = evidence();
        more.advertised_public_routes = ADVERTISED_PUBLIC_ROUTES.len() + 1;
        assert_rejected(
            validate_fail_closed_evidence(&more),
            "advertised_public_routes",
        );
        let mut excluded = evidence();
        excluded.excluded_public_routes_typed = EXCLUDED_PUBLIC_ROUTES.len() - 1;
        assert_rejected(
            validate_fail_closed_evidence(&excluded),
            "excluded_public_routes_typed",
        );
    }

    #[test]
    fn fixture_shape_and_baselines_reach_the_shared_exit_path() {
        let mut relays = evidence();
        relays.relay_count = 2;
        assert_rejected(validate_fail_closed_evidence(&relays), "three relays");
        let mut target = evidence();
        target.baseline_target_dispatches = 0;
        assert_rejected(
            validate_fail_closed_evidence(&target),
            "baseline_target_dispatches",
        );
        let mut sibling = evidence();
        sibling.baseline_sibling_dispatches = 0;
        assert_rejected(
            validate_fail_closed_evidence(&sibling),
            "baseline_sibling_dispatches",
        );
        let mut elapsed = evidence();
        elapsed.elapsed_ms = 0;
        assert_failed(validate_fail_closed_evidence(&elapsed));
    }
}
