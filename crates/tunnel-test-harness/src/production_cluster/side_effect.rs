//! Synthetic ordered-stream application-effect fixture for the production cluster.
//!
//! This module deliberately implements only the public device control/data
//! protocol.  It is a test device with a bounded synthetic backend boundary;
//! it is not a replacement for a future MCP, CUA, filesystem, or desktop
//! adapter.  The consumer still enters through a non-owner relay and the
//! device sockets terminate at the selected owner relay, so the test covers
//! the real three-relay/H3 route.

use super::{EXCHANGE_TIMEOUT, ProductionCluster, SCENARIO_TIMEOUT, open_consumer_stream};
use crate::{HarnessError, OidcTokenOptions, Result, RunningHarness};
use futures_util::{FutureExt, SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    task::JoinHandle,
    time::{Instant, sleep_until, timeout, timeout_at},
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::OwnerToken;
use tunnel_protocol::{
    AuthorizationChallenge, ControlMessage, Frame, FrameKind, Hello, Opened, OwnerFenced, Pong,
    ServiceAdvertisement, decode_control, encode_control,
};
use tunnel_transport::load_client_config_from_pem;
use uuid::Uuid;

const CONTROL_SUBPROTOCOL: &str = "agent-tunnel.control.v1";
const DATA_SUBPROTOCOL: &str = "agent-tunnel.data.v1";
const PROTOCOL_MAJOR: u16 = 1;
const PROTOCOL_MINOR: u16 = 0;
const DEVICE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const DEVICE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
// The forwarded consumer envelope carries a maximum 20-second admission
// budget.  The production fixture's peer transport idle timeout is 10
// seconds, so the envelope budget is the controlling bound here.  Keep this
// as one bounded observation window; an observer deadline is evidence of an
// unresolved outcome, not an interruption result.
const FAILURE_OBSERVATION_TIMEOUT: Duration =
    Duration::from_millis(tunnel_cluster::envelope::MAX_ADMISSION_REMAINING_MS as u64);
const POST_FAILURE_OBSERVATION: Duration = Duration::from_millis(500);
const LATE_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const LATE_RESPONSE_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);
const LATE_RESPONSE_POLL: Duration = Duration::from_millis(25);
const MAX_RAW_OBSERVATIONS: usize = 64;
const SYNTHETIC_REQUEST: &[u8] = b"m7-synthetic-effect";

#[repr(u8)]
#[derive(Clone, Copy)]
enum DevicePhase {
    Starting = 0,
    ControlConnected = 1,
    HelloSent = 2,
    WelcomeReceived = 3,
    OwnerFenced = 4,
    DataReady = 5,
    OperationOpened = 6,
    AuthorizationConfirmed = 7,
    HoldingResponse = 8,
    ResponseAttempted = 9,
    Draining = 10,
    Closed = 11,
}

impl DevicePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::ControlConnected => "control-connected",
            Self::HelloSent => "hello-sent",
            Self::WelcomeReceived => "welcome-received",
            Self::OwnerFenced => "owner-fenced",
            Self::DataReady => "data-ready",
            Self::OperationOpened => "operation-opened",
            Self::AuthorizationConfirmed => "authorization-confirmed",
            Self::HoldingResponse => "holding-response",
            Self::ResponseAttempted => "response-attempted",
            Self::Draining => "draining",
            Self::Closed => "closed",
        }
    }
}

type DeviceSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsumerTerminal {
    Success,
    Close,
    Eof,
    TransportError,
    ExplicitUnknown,
    ObserverDeadline,
}

impl ConsumerTerminal {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Close => "close",
            Self::Eof => "eof",
            Self::TransportError => "transport-error",
            Self::ExplicitUnknown => "explicit-unknown",
            Self::ObserverDeadline => "observer-deadline",
        }
    }

    fn is_interruption_or_unknown(self) -> bool {
        matches!(
            self,
            Self::Close | Self::Eof | Self::TransportError | Self::ExplicitUnknown
        )
    }
}

/// Compact, non-secret evidence for the synthetic application boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SideEffectEvidence {
    pub relay_count: usize,
    pub owner_relay: String,
    pub ingress_relay: String,
    pub control_admitted: bool,
    pub owner_fenced: bool,
    pub data_admitted: bool,
    pub operation_opened: bool,
    pub authorization_confirmed: bool,
    pub raw_request_observations: usize,
    pub unique_request_sequences: usize,
    pub duplicate_request_observations: usize,
    pub conflicting_request_observations: usize,
    pub invalid_request_observations: usize,
    pub incoming_fin_frames: usize,
    pub transport_ack_frames_sent: u64,
    pub transport_window_updates_sent: u64,
    pub backend_effect_invocations: u64,
    /// Application response DATA/FIN frames accepted by the local device
    /// socket after the selected peer fault. This is not consumer delivery.
    pub response_frames_sent: u64,
    /// The fixture reached its bounded response-send step after the fault,
    /// even if the socket rejected every response write.
    pub response_send_attempted: bool,
    /// Exact consumer-side terminal observation. `observer-deadline` is
    /// deliberately rejected by the validator as unresolved evidence.
    pub consumer_terminal: String,
    pub consumer_observation_elapsed_ms: u64,
    pub consumer_observation_deadline_ms: u64,
    pub consumer_success: bool,
    pub consumer_interrupted_or_unknown: bool,
    pub owner_remained_selected_during_fault: bool,
    pub owner_token_retained_at_release: bool,
    pub owner_token_retained_after_interruption: bool,
    pub owner_token_retained_after_failure: bool,
    pub alternate_owner_observed: bool,
    pub post_failure_effect_invocations: u64,
    pub raw_observations: Vec<RawFrameObservation>,
}

/// Raw connector-to-relay application observations.  These are intentionally
/// retained separately from the effect counter so a duplicate sequence cannot
/// be hidden by the fixture's idempotency guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawFrameObservation {
    pub epoch: u64,
    pub generation: u64,
    pub stream_id: u64,
    pub sequence: u64,
    pub kind: String,
    pub payload_len: usize,
}

/// Evidence for the standalone cross-peer late DATA/FIN boundary.
///
/// The local device writes are retained as trigger diagnostics only.  A local
/// WebSocket write does not prove that the owner relay received a frame; the
/// validator therefore also requires a post-trigger, identity-matched owner
/// diagnostic and either a live terminal stream snapshot or the owner's exact
/// connector FIN/RESET receipt latch before cleanup.  Stream absence alone is
/// never accepted as receipt evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LateResponseEvidence {
    pub relay_count: usize,
    pub owner_relay: String,
    pub ingress_relay: String,
    pub tenant_id: String,
    pub device_id: String,
    pub service_id: String,
    pub owner_token_digest: String,
    pub owner_token_digest_after_trigger: String,
    pub session_id: String,
    pub epoch: u64,
    pub generation: u64,
    pub connection_id: String,
    pub stream_id: u64,
    pub operation_id: String,
    pub consumer_terminal: String,
    pub consumer_interrupted_or_unknown: bool,
    pub data_attempts: u64,
    pub data_write_accepted: u64,
    pub data_write_rejected: u64,
    pub fin_attempts: u64,
    pub fin_write_accepted: u64,
    pub fin_write_rejected: u64,
    pub data_before_fin: bool,
    pub write_completed: bool,
    pub carrier_closed: bool,
    /// The authenticated forwarded peer request identity carried by the owner's
    /// FIN/RESET receipt. A non-empty value proves the terminal frame was
    /// correlated to the exact forwarded consumer request, owner-side.
    pub owner_receipt_request_id: String,
    pub owner_recv_contiguous_before: u64,
    pub owner_recv_contiguous_after: u64,
    pub owner_delivered_contiguous_before: u64,
    pub owner_delivered_contiguous_after: u64,
    /// The connector-to-relay terminal sequence observed by the owner. It must
    /// equal the final contiguous receive cursor for a complete DATA+FIN.
    pub owner_receive_terminal_sequence: u64,
    /// `live_stream` means the exact logical stream was still present and
    /// terminal; `stream_terminal_receipt` means the owner's bounded FIN/RESET
    /// receipt latch supplied the terminal evidence after the stream was
    /// reclaimed. No other value is accepted.
    pub terminal_evidence_source: String,
    pub stream_present_after_trigger: bool,
    pub stream_terminal_after_trigger: bool,
    pub terminal_stream_latched: bool,
    pub terminal_observed_before_teardown: bool,
    pub queue_bytes: usize,
    pub replay_frames: usize,
    pub replay_bytes: usize,
    pub no_replay_before_teardown: bool,
    pub cleanup_joined: bool,
}

/// Validate the standalone cross-peer late DATA/FIN contract.
///
/// The accepted local writes are deliberately not sufficient evidence.  The
/// owner must publish a bounded connector FIN/RESET receipt for the exact late
/// stream, with the final receive/delivery cursors advanced by the DATA+FIN
/// pair, the terminal sequence at that cursor, the forwarded request identity,
/// and no retained replay or queue bytes; its exact logical stream is either
/// still present and terminal or represented by that receipt after
/// reclamation.  The owner's best-effort forward to the severed ingress is not
/// a required observation: a small response buffers into the not-yet-timed-out
/// QUIC stream and produces no synchronous owner-send error, so requiring one
/// would be waiting on a connection idle timeout, not a correctness property.
/// The interrupted consumer proves the response never reached the consumer.
pub fn validate_late_response_evidence(evidence: &LateResponseEvidence) -> Result<()> {
    if evidence.relay_count != 3
        || evidence.owner_relay != "relay-a"
        || evidence.ingress_relay != "relay-c"
        || evidence.tenant_id.is_empty()
        || evidence.device_id.is_empty()
        || evidence.service_id.is_empty()
        || evidence.owner_token_digest.is_empty()
        || evidence.owner_token_digest_after_trigger.is_empty()
        || evidence.session_id.is_empty()
        || evidence.epoch == 0
        || evidence.generation == 0
        || evidence.connection_id.is_empty()
        || evidence.stream_id == 0
        || evidence.operation_id.is_empty()
    {
        return Err(HarnessError::Process(
            "late-frame evidence omitted the exact three-relay owner/session/carrier/stream identity"
                .into(),
        ));
    }
    if !matches!(
        evidence.consumer_terminal.as_str(),
        "close" | "eof" | "transport-error" | "explicit-unknown"
    ) || !evidence.consumer_interrupted_or_unknown
    {
        return Err(HarnessError::Process(
            "late-frame evidence did not observe an explicit consumer interruption".into(),
        ));
    }
    if evidence.data_attempts != 1
        || evidence.fin_attempts != 1
        || !evidence.data_before_fin
        || !evidence.write_completed
    {
        return Err(HarnessError::Process(format!(
            "late-frame DATA/FIN completion was data_attempts={}, fin_attempts={}, data_before_fin={}, write_completed={}; expected one ordered joined pair",
            evidence.data_attempts,
            evidence.fin_attempts,
            evidence.data_before_fin,
            evidence.write_completed
        )));
    }
    if evidence.data_write_accepted > evidence.data_attempts
        || evidence.data_write_rejected > evidence.data_attempts
        || evidence.fin_write_accepted > evidence.fin_attempts
        || evidence.fin_write_rejected > evidence.fin_attempts
        || evidence.data_write_accepted + evidence.data_write_rejected != evidence.data_attempts
        || evidence.fin_write_accepted + evidence.fin_write_rejected != evidence.fin_attempts
    {
        return Err(HarnessError::Process(
            "late-frame local write accounting did not reconcile DATA and FIN attempts".into(),
        ));
    }
    if evidence.owner_token_digest_after_trigger != evidence.owner_token_digest {
        return Err(HarnessError::Process(
            "late-frame catalog owner token changed after the trigger".into(),
        ));
    }
    let Some(expected_owner_receive) = evidence.owner_recv_contiguous_before.checked_add(2) else {
        return Err(HarnessError::Process(
            "late-frame owner receive cursor overflowed before the trigger".into(),
        ));
    };
    if evidence.owner_recv_contiguous_after != expected_owner_receive
        || evidence.owner_delivered_contiguous_before != evidence.owner_recv_contiguous_before
        || evidence.owner_delivered_contiguous_after != evidence.owner_recv_contiguous_after
        || evidence.owner_receive_terminal_sequence != evidence.owner_recv_contiguous_after
        || evidence.owner_receipt_request_id.is_empty()
    {
        return Err(HarnessError::Process(
            "late-frame owner did not prove the exact DATA/FIN receive and delivery cursors with a forwarded request identity".into(),
        ));
    }
    // Exactly one terminal evidence source is accepted, and its kind must
    // agree with the observed stream-presence/latch bits.  Absence of the
    // stream without a matching receipt latch is never accepted.
    let live_evidence = evidence.terminal_evidence_source == "live_stream";
    let receipt_evidence = evidence.terminal_evidence_source == "stream_terminal_receipt";
    if !(live_evidence || receipt_evidence)
        || live_evidence != evidence.stream_present_after_trigger
        || receipt_evidence != evidence.terminal_stream_latched
        || !evidence.stream_terminal_after_trigger
        || !evidence.terminal_observed_before_teardown
        || evidence.queue_bytes != 0
        || evidence.replay_frames != 0
        || evidence.replay_bytes != 0
        || !evidence.no_replay_before_teardown
        || !evidence.cleanup_joined
    {
        return Err(HarnessError::Process(
            "late-frame evidence lacked a live or latched exact terminal zero-queue/no-replay observation or joined cleanup"
                .into(),
        ));
    }
    Ok(())
}

/// Validate the narrow EC-054/FP-05 evidence contract.
pub fn validate_side_effect_evidence(evidence: &SideEffectEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect gate requires three relays, observed {}",
            evidence.relay_count
        )));
    }
    let terminal = evidence.consumer_terminal.as_str();
    if terminal == ConsumerTerminal::ObserverDeadline.as_str() {
        return Err(HarnessError::Timeout(format!(
            "synthetic side-effect consumer observation expired after {}ms (bound {}ms); no terminal or explicit unknown outcome",
            evidence.consumer_observation_elapsed_ms, evidence.consumer_observation_deadline_ms
        )));
    }
    if !matches!(
        terminal,
        "success" | "close" | "eof" | "transport-error" | "explicit-unknown"
    ) {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect consumer terminal classification was unsupported: {terminal}"
        )));
    }
    let expected_interrupted_or_unknown = matches!(
        terminal,
        "close" | "eof" | "transport-error" | "explicit-unknown"
    );
    if evidence.consumer_interrupted_or_unknown != expected_interrupted_or_unknown {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect consumer terminal {terminal} disagreed with interrupted_or_unknown={}",
            evidence.consumer_interrupted_or_unknown
        )));
    }
    if evidence.consumer_success != (terminal == "success") {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect consumer terminal {terminal} disagreed with success={}",
            evidence.consumer_success
        )));
    }
    if evidence.consumer_observation_deadline_ms != duration_millis(FAILURE_OBSERVATION_TIMEOUT) {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect consumer observation bound was {}ms, expected {}ms",
            evidence.consumer_observation_deadline_ms,
            duration_millis(FAILURE_OBSERVATION_TIMEOUT)
        )));
    }
    for (label, value) in [
        ("control_admitted", evidence.control_admitted),
        ("owner_fenced", evidence.owner_fenced),
        ("data_admitted", evidence.data_admitted),
        ("operation_opened", evidence.operation_opened),
        ("authorization_confirmed", evidence.authorization_confirmed),
        (
            "owner_remained_selected_during_fault",
            evidence.owner_remained_selected_during_fault,
        ),
        (
            "consumer_interrupted_or_unknown",
            evidence.consumer_interrupted_or_unknown,
        ),
        (
            "owner_token_retained_at_release",
            evidence.owner_token_retained_at_release,
        ),
        (
            "owner_token_retained_after_interruption",
            evidence.owner_token_retained_after_interruption,
        ),
        (
            "owner_token_retained_after_failure",
            evidence.owner_token_retained_after_failure,
        ),
    ] {
        if !value {
            return Err(HarnessError::Process(format!(
                "synthetic side-effect required evidence {label} was false"
            )));
        }
    }
    if evidence.owner_relay != "relay-a" || evidence.ingress_relay != "relay-c" {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect route was {} -> {} rather than relay-c -> relay-a",
            evidence.ingress_relay, evidence.owner_relay
        )));
    }
    if evidence.consumer_success {
        return Err(HarnessError::Process(
            "synthetic side-effect consumer unexpectedly received a success".into(),
        ));
    }
    if evidence.alternate_owner_observed {
        return Err(HarnessError::Process(
            "synthetic side-effect gate observed an alternate owner during the fault".into(),
        ));
    }
    if evidence.raw_request_observations != 1
        || evidence.unique_request_sequences != 1
        || evidence.duplicate_request_observations != 0
    {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect raw dispatch count was raw={}, unique={}, duplicates={}; expected exactly one raw request and no duplicate",
            evidence.raw_request_observations,
            evidence.unique_request_sequences,
            evidence.duplicate_request_observations
        )));
    }
    if evidence.conflicting_request_observations != 0 || evidence.invalid_request_observations != 0
    {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect request validation observed conflicting={} invalid={}",
            evidence.conflicting_request_observations, evidence.invalid_request_observations
        )));
    }
    if evidence.incoming_fin_frames > 1
        || evidence.transport_ack_frames_sent
            != (evidence.raw_request_observations + evidence.incoming_fin_frames) as u64
    {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect receipt ACK count was {} for {} DATA + {} FIN frames",
            evidence.transport_ack_frames_sent,
            evidence.raw_request_observations,
            evidence.incoming_fin_frames
        )));
    }
    if evidence.transport_window_updates_sent != evidence.raw_request_observations as u64 {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect receive-credit updates were {}, expected {}",
            evidence.transport_window_updates_sent, evidence.raw_request_observations
        )));
    }
    if evidence.backend_effect_invocations != 1 {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect counter was {}, expected exactly one invocation",
            evidence.backend_effect_invocations
        )));
    }
    if !evidence.response_send_attempted {
        return Err(HarnessError::Process(
            "synthetic side-effect fixture did not attempt its bounded response after the fault"
                .into(),
        ));
    }
    if evidence.response_frames_sent > 2 {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect fixture accepted {} response frames after the held request",
            evidence.response_frames_sent
        )));
    }
    if evidence.post_failure_effect_invocations != 0 {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect counter advanced by {} after the selected peer fault",
            evidence.post_failure_effect_invocations
        )));
    }
    if evidence.raw_observations.len()
        != evidence.raw_request_observations + evidence.incoming_fin_frames
    {
        return Err(HarnessError::Process(
            "synthetic side-effect raw observation vector did not match its count".into(),
        ));
    }
    let data_observations: Vec<_> = evidence
        .raw_observations
        .iter()
        .filter(|observation| observation.kind == "Data")
        .collect();
    if data_observations.len() != 1 {
        return Err(HarnessError::Process(format!(
            "synthetic side-effect evidence carried {} DATA observations",
            data_observations.len()
        )));
    }
    let first_data = data_observations[0];
    if first_data.sequence != 1
        || first_data.payload_len != SYNTHETIC_REQUEST.len().saturating_add(4)
        || first_data.epoch == 0
        || first_data.generation != 1
        || first_data.stream_id == 0
    {
        return Err(HarnessError::Process(
            "synthetic side-effect DATA context or 4-byte record boundary was invalid".into(),
        ));
    }
    for observation in &evidence.raw_observations {
        if observation.epoch != first_data.epoch
            || observation.generation != first_data.generation
            || observation.stream_id != first_data.stream_id
        {
            return Err(HarnessError::Process(
                "synthetic side-effect raw frames changed epoch/generation/stream context".into(),
            ));
        }
        if observation.kind == "Fin" && (observation.sequence != 2 || observation.payload_len != 0)
        {
            return Err(HarnessError::Process(
                "synthetic side-effect FIN was not the contiguous terminal frame".into(),
            ));
        }
        if observation.kind != "Data" && observation.kind != "Fin" {
            return Err(HarnessError::Process(
                "synthetic side-effect raw observation carried an unexpected frame kind".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{
        FAILURE_OBSERVATION_TIMEOUT, RawFrameObservation, SYNTHETIC_REQUEST, SideEffectEvidence,
        duration_millis, validate_side_effect_evidence,
    };
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> SideEffectEvidence {
        SideEffectEvidence {
            relay_count: 3,
            owner_relay: "relay-a".into(),
            ingress_relay: "relay-c".into(),
            control_admitted: true,
            owner_fenced: true,
            data_admitted: true,
            operation_opened: true,
            authorization_confirmed: true,
            raw_request_observations: 1,
            unique_request_sequences: 1,
            duplicate_request_observations: 0,
            conflicting_request_observations: 0,
            invalid_request_observations: 0,
            incoming_fin_frames: 1,
            transport_ack_frames_sent: 2,
            transport_window_updates_sent: 1,
            backend_effect_invocations: 1,
            response_frames_sent: 0,
            response_send_attempted: true,
            consumer_terminal: "explicit-unknown".into(),
            consumer_observation_elapsed_ms: 1,
            consumer_observation_deadline_ms: duration_millis(FAILURE_OBSERVATION_TIMEOUT),
            consumer_success: false,
            consumer_interrupted_or_unknown: true,
            owner_remained_selected_during_fault: true,
            owner_token_retained_at_release: true,
            owner_token_retained_after_interruption: true,
            owner_token_retained_after_failure: true,
            alternate_owner_observed: false,
            post_failure_effect_invocations: 0,
            raw_observations: vec![
                RawFrameObservation {
                    epoch: 1,
                    generation: 1,
                    stream_id: 1,
                    sequence: 1,
                    kind: "Data".into(),
                    payload_len: SYNTHETIC_REQUEST.len() + 4,
                },
                RawFrameObservation {
                    epoch: 1,
                    generation: 1,
                    stream_id: 1,
                    sequence: 2,
                    kind: "Fin".into(),
                    payload_len: 0,
                },
            ],
        }
    }

    #[test]
    fn every_side_effect_flag_and_count_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut SideEffectEvidence));
        let flags: [Disable; 10] = [
            ("control_admitted", |e| e.control_admitted = false),
            ("owner_fenced", |e| e.owner_fenced = false),
            ("data_admitted", |e| e.data_admitted = false),
            ("operation_opened", |e| e.operation_opened = false),
            ("authorization_confirmed", |e| {
                e.authorization_confirmed = false
            }),
            ("owner_remained_selected_during_fault", |e| {
                e.owner_remained_selected_during_fault = false
            }),
            ("interrupted_or_unknown", |e| {
                e.consumer_interrupted_or_unknown = false
            }),
            ("owner_token_retained_at_release", |e| {
                e.owner_token_retained_at_release = false
            }),
            ("owner_token_retained_after_interruption", |e| {
                e.owner_token_retained_after_interruption = false
            }),
            ("owner_token_retained_after_failure", |e| {
                e.owner_token_retained_after_failure = false
            }),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_side_effect_evidence(&evidence), name);
        }

        type Mutate = (&'static str, fn(&mut SideEffectEvidence));
        let counts: [Mutate; 17] = [
            ("relay_count", |e| e.relay_count = 2),
            ("raw_request_observations", |e| {
                e.raw_request_observations = 0
            }),
            ("unique_request_sequences", |e| {
                e.unique_request_sequences = 0
            }),
            ("duplicate_request_observations", |e| {
                e.duplicate_request_observations = 1
            }),
            ("conflicting_request_observations", |e| {
                e.conflicting_request_observations = 1
            }),
            ("invalid_request_observations", |e| {
                e.invalid_request_observations = 1
            }),
            ("incoming_fin_frames", |e| e.incoming_fin_frames = 2),
            ("backend_effect_invocations", |e| {
                e.backend_effect_invocations = 0
            }),
            ("response_send_attempted", |e| {
                e.response_send_attempted = false
            }),
            ("post_failure_effect_invocations", |e| {
                e.post_failure_effect_invocations = 1
            }),
            ("consumer_success", |e| e.consumer_success = true),
            ("alternate_owner_observed", |e| {
                e.alternate_owner_observed = true
            }),
            ("consumer_terminal", |e| {
                e.consumer_terminal = "observer-deadline".into()
            }),
            ("consumer_observation_deadline_ms", |e| {
                e.consumer_observation_deadline_ms = 0
            }),
            ("response_frames_sent", |e| e.response_frames_sent = 3),
            ("transport_ack_frames_sent", |e| {
                e.transport_ack_frames_sent = 1
            }),
            ("transport_window_updates_sent", |e| {
                e.transport_window_updates_sent = 0
            }),
        ];
        for (_, mutate) in counts {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(
                validate_side_effect_evidence(&evidence),
                "synthetic side-effect",
            );
        }

        let mut raw_count = valid_evidence();
        raw_count.raw_observations.pop();
        assert_rejected(
            validate_side_effect_evidence(&raw_count),
            "synthetic side-effect",
        );
        let mut raw_sequence = valid_evidence();
        raw_sequence.raw_observations[0].sequence = 2;
        assert_rejected(
            validate_side_effect_evidence(&raw_sequence),
            "synthetic side-effect",
        );
        let mut raw_kind = valid_evidence();
        raw_kind.raw_observations[1].kind = "Reset".into();
        assert_rejected(
            validate_side_effect_evidence(&raw_kind),
            "synthetic side-effect",
        );
    }

    #[test]
    fn side_effect_validator_accepts_complete_evidence() {
        validate_side_effect_evidence(&valid_evidence())
            .expect("complete synthetic side-effect evidence is valid");
    }

    #[test]
    fn every_side_effect_route_terminal_and_raw_frame_condition_names_its_rejection() {
        use crate::acceptance_test_support::assert_failed;

        const ROUTE: &str = "rather than relay-c -> relay-a";
        const DATA_CONTEXT: &str = "DATA context or 4-byte record boundary was invalid";
        const FIN: &str = "FIN was not the contiguous terminal frame";
        type Case = (&'static str, &'static str, fn(&mut SideEffectEvidence));
        let cases: &[Case] = &[
            (
                "unsupported_terminal",
                "terminal classification was unsupported",
                |e| e.consumer_terminal = "weird".into(),
            ),
            (
                "success_terminal_disagrees_with_interruption",
                "disagreed with interrupted_or_unknown",
                |e| e.consumer_terminal = "success".into(),
            ),
            (
                "success_flag_disagrees_with_terminal",
                "disagreed with success",
                |e| e.consumer_success = true,
            ),
            ("owner_relay", ROUTE, |e| e.owner_relay = "relay-b".into()),
            ("ingress_relay", ROUTE, |e| {
                e.ingress_relay = "relay-a".into()
            }),
            (
                "backend_effect_invocations_duplicate",
                "expected exactly one invocation",
                |e| e.backend_effect_invocations = 2,
            ),
            ("data_payload_boundary", DATA_CONTEXT, |e| {
                e.raw_observations[0].payload_len = SYNTHETIC_REQUEST.len()
            }),
            ("data_epoch_zero", DATA_CONTEXT, |e| {
                e.raw_observations[0].epoch = 0
            }),
            ("data_generation_not_one", DATA_CONTEXT, |e| {
                e.raw_observations[0].generation = 2
            }),
            ("data_stream_id_zero", DATA_CONTEXT, |e| {
                e.raw_observations[0].stream_id = 0
            }),
            (
                "fin_context_drift",
                "changed epoch/generation/stream context",
                |e| e.raw_observations[1].epoch = 2,
            ),
            ("fin_sequence", FIN, |e| e.raw_observations[1].sequence = 3),
            ("fin_payload", FIN, |e| {
                e.raw_observations[1].payload_len = 1
            }),
            ("no_data_observation", "carried 0 DATA observations", |e| {
                e.raw_observations[0].kind = "Fin".into()
            }),
        ];
        for &(name, fragment, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_side_effect_evidence(&evidence));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }
}

#[cfg(test)]
mod late_response_validator_tests {
    use super::{LateResponseEvidence, validate_late_response_evidence};
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> LateResponseEvidence {
        LateResponseEvidence {
            relay_count: 3,
            owner_relay: "relay-a".into(),
            ingress_relay: "relay-c".into(),
            tenant_id: "tenant-a".into(),
            device_id: "device-a".into(),
            service_id: "service-a".into(),
            owner_token_digest: "owner-digest-a".into(),
            owner_token_digest_after_trigger: "owner-digest-a".into(),
            session_id: "session-a".into(),
            epoch: 7,
            generation: 1,
            connection_id: "connection-a".into(),
            stream_id: 9,
            operation_id: "operation-a".into(),
            consumer_terminal: "explicit-unknown".into(),
            consumer_interrupted_or_unknown: true,
            data_attempts: 1,
            data_write_accepted: 1,
            data_write_rejected: 0,
            fin_attempts: 1,
            fin_write_accepted: 0,
            fin_write_rejected: 1,
            data_before_fin: true,
            write_completed: true,
            carrier_closed: true,
            owner_receipt_request_id: "request-a".into(),
            owner_recv_contiguous_before: 0,
            owner_recv_contiguous_after: 2,
            owner_delivered_contiguous_before: 0,
            owner_delivered_contiguous_after: 2,
            owner_receive_terminal_sequence: 2,
            terminal_evidence_source: "live_stream".into(),
            stream_present_after_trigger: true,
            stream_terminal_after_trigger: true,
            terminal_stream_latched: false,
            terminal_observed_before_teardown: true,
            queue_bytes: 0,
            replay_frames: 0,
            replay_bytes: 0,
            no_replay_before_teardown: true,
            cleanup_joined: true,
        }
    }

    #[test]
    fn late_response_validator_accepts_exact_fin_receipt_latch() {
        // The reclaimed-stream path: the live stream is gone, but the owner's
        // exact FIN/RESET receipt latch supplies the terminal evidence.
        let mut evidence = valid_evidence();
        evidence.terminal_evidence_source = "stream_terminal_receipt".into();
        evidence.stream_present_after_trigger = false;
        evidence.terminal_stream_latched = true;
        assert!(validate_late_response_evidence(&evidence).is_ok());

        // A latch claim without the matching bit, or with the live-stream bit
        // still set, must not reconcile.
        evidence.terminal_stream_latched = false;
        assert_rejected(validate_late_response_evidence(&evidence), "late-frame");
        let mut evidence = valid_evidence();
        evidence.terminal_evidence_source = "stream_terminal_receipt".into();
        evidence.terminal_stream_latched = true;
        assert_rejected(validate_late_response_evidence(&evidence), "late-frame");
    }

    #[test]
    fn late_response_validator_rejects_unproven_or_unreconciled_evidence() {
        type Mutate = (&'static str, fn(&mut LateResponseEvidence));
        let mutations: [Mutate; 30] = [
            ("relay_count", |e| e.relay_count = 2),
            ("connection_id", |e| e.connection_id.clear()),
            ("owner_token_digest", |e| e.owner_token_digest.clear()),
            ("owner_token_digest_after_trigger", |e| {
                e.owner_token_digest_after_trigger = "changed-owner".into()
            }),
            ("service_id", |e| e.service_id.clear()),
            ("consumer_terminal", |e| {
                e.consumer_terminal = "success".into()
            }),
            ("data_attempts", |e| e.data_attempts = 0),
            ("fin_attempts", |e| e.fin_attempts = 2),
            ("data_before_fin", |e| e.data_before_fin = false),
            ("write_completed", |e| e.write_completed = false),
            ("consumer_interrupted_or_unknown", |e| {
                e.consumer_interrupted_or_unknown = false
            }),
            ("data_write_accounting", |e| e.data_write_rejected = 1),
            ("data_write_accepted_overflow", |e| {
                e.data_write_accepted = 2
            }),
            ("fin_write_accounting", |e| e.fin_write_accepted = 1),
            ("fin_write_rejected_overflow", |e| e.fin_write_rejected = 2),
            ("owner_receipt_request_id", |e| {
                e.owner_receipt_request_id.clear()
            }),
            ("owner_receive_cursor", |e| {
                e.owner_recv_contiguous_after = 1
            }),
            ("owner_delivery_cursor", |e| {
                e.owner_delivered_contiguous_after = 1
            }),
            ("owner_terminal_cursor", |e| {
                e.owner_receive_terminal_sequence = 1
            }),
            ("terminal_source_unknown", |e| {
                e.terminal_evidence_source = "unknown".into()
            }),
            ("latched_bit_without_receipt_source", |e| {
                e.terminal_stream_latched = true
            }),
            ("live_source_without_stream", |e| {
                e.stream_present_after_trigger = false
            }),
            ("stream_absent", |e| {
                e.terminal_evidence_source = "stream_terminal_receipt".into();
                e.stream_present_after_trigger = false
            }),
            ("stream_not_terminal", |e| {
                e.stream_terminal_after_trigger = false
            }),
            ("terminal_not_observed_before_teardown", |e| {
                e.terminal_observed_before_teardown = false
            }),
            ("queued_bytes_visible", |e| e.queue_bytes = 1),
            ("replay_visible", |e| e.replay_frames = 1),
            ("replay_bytes_visible", |e| e.replay_bytes = 1),
            ("replay_not_proven_absent", |e| {
                e.no_replay_before_teardown = false
            }),
            ("cleanup_unjoined", |e| e.cleanup_joined = false),
        ];
        for (name, mutate) in mutations {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let result = validate_late_response_evidence(&evidence);
            assert!(
                result.is_err(),
                "late-frame mutation {name} must be rejected"
            );
            assert_rejected(result, "late-frame");
        }
    }

    #[test]
    fn late_response_validator_accepts_complete_evidence() {
        validate_late_response_evidence(&valid_evidence())
            .expect("complete late-frame evidence is valid");
    }

    #[test]
    fn every_late_response_identity_and_cursor_condition_names_its_rejection() {
        use crate::acceptance_test_support::assert_failed;

        const IDENTITY: &str = "owner/session/carrier/stream identity";
        type Case = (&'static str, &'static str, fn(&mut LateResponseEvidence));
        let cases: &[Case] = &[
            ("owner_relay", IDENTITY, |e| {
                e.owner_relay = "relay-b".into()
            }),
            ("ingress_relay", IDENTITY, |e| {
                e.ingress_relay = "relay-a".into()
            }),
            ("tenant_id_empty", IDENTITY, |e| e.tenant_id.clear()),
            ("device_id_empty", IDENTITY, |e| e.device_id.clear()),
            ("session_id_empty", IDENTITY, |e| e.session_id.clear()),
            ("epoch_zero", IDENTITY, |e| e.epoch = 0),
            ("generation_zero", IDENTITY, |e| e.generation = 0),
            ("stream_id_zero", IDENTITY, |e| e.stream_id = 0),
            ("operation_id_empty", IDENTITY, |e| e.operation_id.clear()),
            (
                "owner_delivered_before_mismatch",
                "exact DATA/FIN receive and delivery cursors",
                |e| e.owner_delivered_contiguous_before = 1,
            ),
            (
                "owner_receive_cursor_overflow",
                "receive cursor overflowed",
                |e| {
                    e.owner_recv_contiguous_before = u64::MAX - 1;
                    e.owner_delivered_contiguous_before = u64::MAX - 1;
                },
            ),
        ];
        for &(name, fragment, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_late_response_evidence(&evidence));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }
}

/// Run the bounded admitted ordered-stream effect scenario.
///
/// The caller owns the production cluster and harness lifecycle.  This
/// function owns only the device fixture, consumer stream, selected peer
/// fault, and all of their bounded cleanup.  The parent module should wire it
/// into a separate acceptance command so it remains distinct from I08
/// rotation evidence.
pub(crate) async fn verify(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<SideEffectEvidence> {
    let (result, _) = match AssertUnwindSafe(verify_inner_with_late(cluster, harness, false))
        .catch_unwind()
        .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err(HarnessError::Process(
                "synthetic side-effect scenario panicked".into(),
            ));
        }
    };
    validate_side_effect_evidence(&result)?;
    Ok(result)
}

/// Run the standalone late DATA/FIN boundary.  The original side-effect
/// command above keeps its existing owner-loss semantics; this entry point
/// adds a separate causal post-trigger owner rejection requirement.
pub(crate) async fn verify_late_response(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<LateResponseEvidence> {
    let (base, late) = match AssertUnwindSafe(verify_inner_with_late(cluster, harness, true))
        .catch_unwind()
        .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err(HarnessError::Process(
                "synthetic late-frame scenario panicked".into(),
            ));
        }
    };
    validate_side_effect_evidence(&base)?;
    let evidence = late.ok_or_else(|| {
        HarnessError::Process("synthetic late-frame scenario omitted its evidence".into())
    })?;
    validate_late_response_evidence(&evidence)?;
    Ok(evidence)
}

async fn verify_inner_with_late(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    run_late_response: bool,
) -> Result<(SideEffectEvidence, Option<LateResponseEvidence>)> {
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no device".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("synthetic device has no service".into()))?;
    let owner_relay = "relay-a";
    let ingress_relay = "relay-c";
    let owner_addr = relay_device_addr(cluster, owner_relay)?;
    let ingress_addr = cluster.relay(ingress_relay)?.consumer_addr()?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;

    let request = {
        let request_len = u32::try_from(SYNTHETIC_REQUEST.len()).map_err(|_| {
            HarnessError::InvalidInput("synthetic side-effect request length overflow".into())
        })?;
        let mut encoded = Vec::with_capacity(SYNTHETIC_REQUEST.len() + 4);
        encoded.extend_from_slice(&request_len.to_be_bytes());
        encoded.extend_from_slice(SYNTHETIC_REQUEST);
        encoded
    };
    let state = Arc::new(EffectState::new(request.clone()));
    let device_config = DeviceConfig {
        address: owner_addr,
        device_id: device.id,
        service_id,
        operation: "echo_stream".to_owned(),
        owner_id: None,
        allow_expected_owner_loss: false,
        certificate_pem: device.certificate.certificate_pem.clone(),
        private_key_pem: device.certificate.private_key_pem.clone(),
        server_ca_pem: harness.pki.server_ca.certificate_pem.clone(),
    };
    let mut fixture = Some(DeviceFixture::start(device_config, state.clone()).await?);
    let mut consumer = None;
    let mut fault_guard = None;
    let mut owner_remained_selected_during_fault = false;
    let mut owner_token_retained_at_release = false;
    let mut owner_token_retained_after_interruption = false;
    let mut owner_token_retained_after_failure = false;
    let mut alternate_owner_observed = false;
    let mut late_evidence = None;
    let scenario = match AssertUnwindSafe(async {
        let owner_token = sample_owner_token(
            cluster,
            device.tenant_id,
            device.id,
            fixture.as_ref(),
            "post-device-readiness",
        )
        .await?;
        if owner_token.node_id != owner_relay {
            return Err(HarnessError::Process(format!(
                "synthetic device owner landed on {}, expected {owner_relay}",
                owner_token.node_id
            )));
        }
        let observed_owner_id = state.fence_owner_id()?;
        let expected_owner_id = owner_digest(&owner_token);
        if observed_owner_id.as_deref() != Some(expected_owner_id.as_str()) {
            return Err(HarnessError::Process(
                "synthetic OWNER_FENCE owner digest did not match the complete catalog owner token"
                    .into(),
            ));
        }
        let stream = open_consumer_stream(
            ingress_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        )
        .await
        .map_err(super::connect_failure_to_harness)?;
        consumer = Some(stream);

        let owner_after_consumer_admission = sample_owner_token(
            cluster,
            device.tenant_id,
            device.id,
            fixture.as_ref(),
            "post-consumer-admission",
        )
        .await?;
        if owner_after_consumer_admission != owner_token {
            return Err(HarnessError::Process(
                "synthetic device owner token changed during consumer admission".into(),
            ));
        }

        let Some(consumer) = consumer.as_mut() else {
            return Err(HarnessError::Process(
                "synthetic consumer stream was lost before dispatch".into(),
            ));
        };
        consumer
            .socket
            .send(Message::Binary(request.clone().into()))
            .await
            .map_err(|error| HarnessError::Http(format!("sending synthetic request: {error}")))?;

        wait_for_effect(&state).await?;
        let owner_during_fault = sample_owner_token(
            cluster,
            device.tenant_id,
            device.id,
            fixture.as_ref(),
            "pre-peer-fault",
        )
        .await?;
        if owner_during_fault != owner_token {
            return Err(HarnessError::Process(format!(
                "synthetic device owner token changed before peer fault: node {}",
                owner_during_fault.node_id
            )));
        }
        let mut guard = PeerFaultGuard::new(cluster, owner_relay, ingress_relay);
        // The relay-C <-> relay-A peer QUIC flow is dropped in both packet
        // directions by the shared UDP fault proxy. Device-A remains live;
        // only the selected cross-relay route is cut.
        guard.enable()?;
        fault_guard = Some(guard);
        let owner_during_fault = sample_owner_token(
            cluster,
            device.tenant_id,
            device.id,
            fixture.as_ref(),
            "post-peer-fault-enable",
        )
        .await?;
        owner_remained_selected_during_fault = owner_during_fault == owner_token;
        alternate_owner_observed = !owner_remained_selected_during_fault;
        if !owner_remained_selected_during_fault {
            return Err(HarnessError::Process(format!(
                "synthetic device owner token changed during selected peer fault: node {}",
                owner_during_fault.node_id
            )));
        }
        let effects_at_fault = state.effect_invocations.load(Ordering::Acquire);
        let owner_before_release = sample_owner_token(
            cluster,
            device.tenant_id,
            device.id,
            fixture.as_ref(),
            "pre-held-response-release",
        )
        .await?;
        owner_token_retained_at_release = owner_before_release == owner_token;
        if !owner_token_retained_at_release {
            alternate_owner_observed = true;
            return Err(HarnessError::Process(
                "synthetic device owner token changed before releasing the held response".into(),
            ));
        }
        let late_identity = if run_late_response {
            let stream_id = state.operation_stream_id().ok_or_else(|| {
                HarnessError::Process(
                    "synthetic late-frame trigger lost the admitted stream ID".into(),
                )
            })?;
            Some(
                capture_late_response_identity(
                    cluster,
                    device.tenant_id,
                    device.id,
                    service_id,
                    &owner_token,
                    stream_id,
                    Instant::now() + LATE_RESPONSE_OBSERVATION_TIMEOUT,
                )
                .await?,
            )
        } else {
            None
        };
        if run_late_response {
            // Skip the ordinary response pair in this standalone branch so
            // the owner rejection observed after the trigger cannot be
            // attributed to an earlier response write.
            state.enable_late_mode();
        }
        let observation_started = Instant::now();
        let observation_deadline = observation_started + FAILURE_OBSERVATION_TIMEOUT;
        state.release_response.notify_one();
        let (consumer_outcome, late_send_result, late_owner_observation) = if run_late_response {
            let identity = late_identity.as_ref().ok_or_else(|| {
                HarnessError::Process("synthetic late-frame identity was not captured".into())
            })?;
            state.request_late_response();
            let late_deadline = Instant::now() + LATE_RESPONSE_OBSERVATION_TIMEOUT;
            let consumer_wait =
                wait_for_consumer_interruption(consumer, observation_started, observation_deadline);
            let late_wait = state.wait_for_late_response(late_deadline);
            // Observe the owner-side terminal state concurrently with the
            // consumer and local send waits.  The route fault can otherwise
            // leave the consumer reader waiting while the owner stream is
            // removed, making a later snapshot incapable of proving the
            // post-trigger terminal transition.
            let owner_wait = wait_for_late_response_terminal(
                cluster,
                identity,
                Instant::now() + LATE_RESPONSE_OBSERVATION_TIMEOUT,
            );
            let (consumer_result, late_result, owner_result) =
                tokio::join!(consumer_wait, late_wait, owner_wait);
            (consumer_result?, Some(late_result?), Some(owner_result?))
        } else {
            (
                wait_for_consumer_interruption(consumer, observation_started, observation_deadline)
                    .await?,
                None,
                None,
            )
        };
        if consumer_outcome.success {
            return Err(HarnessError::Process(
                "synthetic request returned a response after the selected peer fault".into(),
            ));
        }
        if let (Some(identity), Some(send_result), Some(owner_observation)) = (
            late_identity.as_ref(),
            late_send_result,
            late_owner_observation,
        ) {
            let owner_after_late = sample_owner_token(
                cluster,
                device.tenant_id,
                device.id,
                fixture.as_ref(),
                "post-late-frame-owner-observation",
            )
            .await?;
            if owner_after_late != owner_token {
                alternate_owner_observed = true;
                return Err(HarnessError::Process(
                    "synthetic late-frame catalog owner token changed after the trigger".into(),
                ));
            }
            late_evidence = Some(LateResponseEvidence {
                relay_count: cluster.relays.len(),
                owner_relay: owner_relay.to_owned(),
                ingress_relay: ingress_relay.to_owned(),
                tenant_id: identity.tenant_id.clone(),
                device_id: identity.device_id.clone(),
                service_id: identity.service_id.clone(),
                owner_token_digest: identity.owner_token_digest.clone(),
                owner_token_digest_after_trigger: owner_digest(&owner_after_late),
                session_id: identity.session_id.clone(),
                epoch: identity.epoch,
                generation: identity.generation,
                connection_id: identity.connection_id.clone(),
                stream_id: identity.stream_id,
                operation_id: identity.operation_id.clone(),
                consumer_terminal: consumer_outcome.terminal.as_str().to_owned(),
                consumer_interrupted_or_unknown: consumer_outcome.interrupted_or_unknown,
                data_attempts: send_result.data_attempts,
                data_write_accepted: send_result.data_write_accepted,
                data_write_rejected: send_result.data_write_rejected,
                fin_attempts: send_result.fin_attempts,
                fin_write_accepted: send_result.fin_write_accepted,
                fin_write_rejected: send_result.fin_write_rejected,
                data_before_fin: send_result.data_before_fin,
                write_completed: send_result.write_completed,
                carrier_closed: send_result.carrier_closed,
                owner_receipt_request_id: owner_observation.owner_receipt_request_id,
                owner_recv_contiguous_before: identity.owner_recv_contiguous_before,
                owner_recv_contiguous_after: owner_observation.owner_recv_contiguous_after,
                owner_delivered_contiguous_before: identity.owner_delivered_contiguous_before,
                owner_delivered_contiguous_after: owner_observation
                    .owner_delivered_contiguous_after,
                owner_receive_terminal_sequence: owner_observation.owner_receive_terminal_sequence,
                terminal_evidence_source: if owner_observation.terminal_stream_latched {
                    "stream_terminal_receipt".to_owned()
                } else {
                    "live_stream".to_owned()
                },
                stream_present_after_trigger: owner_observation.stream_present,
                stream_terminal_after_trigger: owner_observation.stream_terminal,
                terminal_stream_latched: owner_observation.terminal_stream_latched,
                terminal_observed_before_teardown: true,
                queue_bytes: owner_observation.queue_bytes,
                replay_frames: owner_observation.replay_frames,
                replay_bytes: owner_observation.replay_bytes,
                no_replay_before_teardown: owner_observation.no_replay,
                cleanup_joined: false,
            });
        }
        let owner_after_interruption = sample_owner_token(
            cluster,
            device.tenant_id,
            device.id,
            fixture.as_ref(),
            "post-consumer-interruption",
        )
        .await?;
        owner_token_retained_after_interruption = owner_after_interruption == owner_token;
        if !owner_token_retained_after_interruption {
            alternate_owner_observed = true;
        }
        let post_failure_effects = state
            .effect_invocations
            .load(Ordering::Acquire)
            .saturating_sub(effects_at_fault);
        let post_failure_deadline =
            (Instant::now() + POST_FAILURE_OBSERVATION).min(observation_deadline);
        sleep_until(post_failure_deadline).await;
        let post_failure_effects = post_failure_effects.max(
            state
                .effect_invocations
                .load(Ordering::Acquire)
                .saturating_sub(effects_at_fault),
        );
        let owner_after_failure = sample_owner_token(
            cluster,
            device.tenant_id,
            device.id,
            fixture.as_ref(),
            "post-failure-observation",
        )
        .await?;
        owner_token_retained_after_failure = owner_after_failure == owner_token;
        if !owner_token_retained_after_failure {
            alternate_owner_observed = true;
        }

        Ok((consumer_outcome, post_failure_effects))
    })
    .catch_unwind()
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Process(
            "synthetic side-effect scenario panicked".into(),
        )),
    };

    let consumer_cleanup = if let Some(mut stream) = consumer.take() {
        match timeout(DEVICE_CLEANUP_TIMEOUT, stream.close()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(HarnessError::Http(format!(
                "synthetic consumer cleanup: {error}"
            ))),
            Err(_) => Err(HarnessError::Timeout(
                "synthetic consumer cleanup timed out".into(),
            )),
        }
    } else {
        Ok(())
    };
    let fault_cleanup = if let Some(mut guard) = fault_guard.take() {
        guard.clear()
    } else {
        Ok(())
    };
    let fixture_cleanup = if let Some(fixture) = fixture.take() {
        fixture.shutdown().await
    } else {
        Ok(())
    };

    let cleanup_error = [consumer_cleanup, fault_cleanup, fixture_cleanup]
        .into_iter()
        .filter_map(Result::err)
        .reduce(|first, next| {
            HarnessError::Process(format!(
                "{first}; additional synthetic cleanup error: {next}"
            ))
        });
    if let Some(evidence) = late_evidence.as_mut() {
        evidence.cleanup_joined = cleanup_error.is_none();
    }
    match (scenario, cleanup_error) {
        (Err(primary), Some(cleanup)) => Err(HarnessError::Process(format!(
            "{primary}; synthetic cleanup also failed: {cleanup}"
        ))),
        (Err(primary), None) => Err(primary),
        (Ok(_), Some(cleanup)) => Err(cleanup),
        (Ok((outcome, post_failure_effects)), None) => {
            let raw_snapshot = state.raw_snapshot()?;
            let unique_request_sequences = state.unique_sequences()?;
            let duplicate_request_observations = usize::try_from(
                state.duplicate_observations.load(Ordering::Acquire),
            )
            .map_err(|_| HarnessError::Process("synthetic duplicate count overflow".into()))?;
            let conflicting_request_observations = usize::try_from(
                state.conflicting_observations.load(Ordering::Acquire),
            )
            .map_err(|_| HarnessError::Process("synthetic conflict count overflow".into()))?;
            let invalid_request_observations = usize::try_from(
                state.invalid_observations.load(Ordering::Acquire),
            )
            .map_err(|_| HarnessError::Process("synthetic invalid count overflow".into()))?;
            Ok((
                SideEffectEvidence {
                    relay_count: cluster.relays.len(),
                    owner_relay: owner_relay.to_owned(),
                    ingress_relay: ingress_relay.to_owned(),
                    control_admitted: state.control_admitted.load(Ordering::Acquire),
                    owner_fenced: state.owner_fenced.load(Ordering::Acquire),
                    data_admitted: state.data_admitted.load(Ordering::Acquire),
                    operation_opened: state.operation_opened.load(Ordering::Acquire),
                    authorization_confirmed: state.authorization_confirmed.load(Ordering::Acquire),
                    raw_request_observations: state.data_observations()?,
                    unique_request_sequences,
                    duplicate_request_observations,
                    conflicting_request_observations,
                    invalid_request_observations,
                    incoming_fin_frames: state.fin_observations.load(Ordering::Acquire) as usize,
                    transport_ack_frames_sent: state
                        .transport_ack_frames_sent
                        .load(Ordering::Acquire),
                    transport_window_updates_sent: state
                        .transport_window_updates_sent
                        .load(Ordering::Acquire),
                    backend_effect_invocations: state.effect_invocations.load(Ordering::Acquire),
                    response_frames_sent: state.response_frames_sent.load(Ordering::Acquire),
                    response_send_attempted: state.response_send_attempted.load(Ordering::Acquire),
                    consumer_terminal: outcome.terminal.as_str().to_owned(),
                    consumer_observation_elapsed_ms: outcome.observation_elapsed_ms,
                    consumer_observation_deadline_ms: outcome.observation_deadline_ms,
                    consumer_success: outcome.success,
                    consumer_interrupted_or_unknown: outcome.interrupted_or_unknown,
                    owner_remained_selected_during_fault,
                    owner_token_retained_at_release,
                    owner_token_retained_after_interruption,
                    owner_token_retained_after_failure,
                    alternate_owner_observed,
                    post_failure_effect_invocations: post_failure_effects,
                    raw_observations: raw_snapshot,
                },
                late_evidence,
            ))
        }
    }
}

fn relay_device_addr(cluster: &ProductionCluster, node_id: &str) -> Result<SocketAddr> {
    cluster
        .relays
        .iter()
        .find(|relay| relay.node_id == node_id)
        .and_then(|relay| relay.running.as_ref().map(|running| running.device_addr))
        .ok_or_else(|| HarnessError::Process(format!("relay {node_id} has no device listener")))
}

async fn current_owner_token(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<OwnerToken> {
    cluster
        .catalog
        .current_owner(tenant_id, device_id, chrono::Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading synthetic device owner: {error}")))?
        .map(|claim| claim.token)
        .ok_or_else(|| HarnessError::Process("synthetic device has no catalog owner".into()))
}

async fn sample_owner_token(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    fixture: Option<&DeviceFixture>,
    stage: &str,
) -> Result<OwnerToken> {
    let result = current_owner_token(cluster, tenant_id, device_id).await;
    result.map_err(|error| {
        let diagnostic = fixture
            .map(DeviceFixture::diagnostic)
            .unwrap_or_else(|| "device fixture unavailable".to_owned());
        HarnessError::Process(format!(
            "synthetic side-effect owner sample {stage} failed: {error}; {diagnostic}"
        ))
    })
}

async fn owner_snapshot_before(
    cluster: &ProductionCluster,
    deadline: Instant,
) -> Result<tunnel_relay::RelaySnapshot> {
    timeout_at(deadline, cluster.relay("relay-a")?.snapshot())
        .await
        .map_err(|_| {
            HarnessError::Timeout("synthetic late-frame owner snapshot timed out".into())
        })?
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LateResponseIdentity {
    tenant_id: String,
    device_id: String,
    service_id: String,
    owner_token_digest: String,
    session_id: String,
    epoch: u64,
    generation: u64,
    connection_id: String,
    stream_id: u64,
    operation_id: String,
    owner_recv_contiguous_before: u64,
    owner_delivered_contiguous_before: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LateResponseSendResult {
    data_attempts: u64,
    data_write_accepted: u64,
    data_write_rejected: u64,
    fin_attempts: u64,
    fin_write_accepted: u64,
    fin_write_rejected: u64,
    data_before_fin: bool,
    write_completed: bool,
    carrier_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LateResponseOwnerObservation {
    owner_receipt_request_id: String,
    owner_recv_contiguous_after: u64,
    owner_delivered_contiguous_after: u64,
    owner_receive_terminal_sequence: u64,
    stream_present: bool,
    stream_terminal: bool,
    terminal_stream_latched: bool,
    queue_bytes: usize,
    replay_frames: usize,
    replay_bytes: usize,
    no_replay: bool,
}

async fn capture_late_response_identity(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    owner: &OwnerToken,
    stream_id: u64,
    deadline: Instant,
) -> Result<LateResponseIdentity> {
    let snapshot = owner_snapshot_before(cluster, deadline).await?;
    let session = snapshot
        .sessions
        .iter()
        .find(|session| {
            session.tenant_id == tenant_id.to_string()
                && session.device_id == device_id.to_string()
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
        })
        .ok_or_else(|| {
            HarnessError::Process(
                "synthetic late-frame owner snapshot lacked the selected session".into(),
            )
        })?;
    if session.active_generation == 0 || session.active_connection_id.is_empty() {
        return Err(HarnessError::Process(
            "synthetic late-frame owner session lacked an active carrier identity".into(),
        ));
    }
    if session.streams.len() != 1 {
        return Err(HarnessError::Process(format!(
            "synthetic late-frame owner session exposed {} logical streams; exact owner-send correlation requires one",
            session.streams.len()
        )));
    }
    let stream = session
        .streams
        .iter()
        .find(|stream| stream.stream_id == stream_id)
        .ok_or_else(|| {
            HarnessError::Process(
                "synthetic late-frame owner snapshot lacked the admitted stream".into(),
            )
        })?;
    if stream.operation_id.is_empty() || stream.terminal {
        return Err(HarnessError::Process(
            "synthetic late-frame trigger did not capture a live operation".into(),
        ));
    }
    if stream.recv_contiguous_connector_to_relay != stream.delivered_contiguous_connector_to_relay {
        return Err(HarnessError::Process(
            "synthetic late-frame trigger started with an incomplete owner receive cursor".into(),
        ));
    }
    Ok(LateResponseIdentity {
        tenant_id: session.tenant_id.clone(),
        device_id: session.device_id.clone(),
        service_id: service_id.to_string(),
        owner_token_digest: owner_digest(owner),
        session_id: session.session_id.clone(),
        epoch: session.epoch,
        generation: session.active_generation,
        connection_id: session.active_connection_id.clone(),
        stream_id,
        operation_id: stream.operation_id.clone(),
        owner_recv_contiguous_before: stream.recv_contiguous_connector_to_relay,
        owner_delivered_contiguous_before: stream.delivered_contiguous_connector_to_relay,
    })
}

/// Find the owner's bounded connector FIN/RESET receipt for the exact late
/// stream identity.  The receipt carries the final connector-to-relay cursor,
/// terminal sequence and physical carrier, so absence of the live stream can
/// never be read as a receipt.  When `require_empty_budget` is set (the stream
/// has already been reclaimed) the relay-to-connector direction must be fully
/// acked with no retained replay or queue bytes.
fn matching_terminal_receipt<'a>(
    snapshot: &'a tunnel_relay::RelaySnapshot,
    identity: &LateResponseIdentity,
    expected_receive: u64,
    require_empty_budget: bool,
) -> Option<&'a tunnel_relay::StreamTerminalReceiptEvent> {
    snapshot
        .stream_terminal_receipt_events
        .iter()
        .find(|receipt| {
            receipt.tenant_id == identity.tenant_id
                && receipt.device_id == identity.device_id
                && receipt.session_id == identity.session_id
                && receipt.epoch == identity.epoch
                && receipt.owner_id == identity.owner_token_digest
                && receipt.active_generation == identity.generation
                && receipt.active_connection_id == identity.connection_id
                && receipt.stream_id == identity.stream_id
                && receipt.operation_id == identity.operation_id
                && receipt.recv_contiguous_connector_to_relay == expected_receive
                && receipt.delivered_contiguous_connector_to_relay == expected_receive
                && receipt.receive_terminal_sequence == expected_receive
                && (!require_empty_budget
                    || (receipt.last_emitted_relay_to_connector
                        == receipt.peer_acked_relay_to_connector
                        && receipt.replay_bytes_relay_to_connector == 0
                        && receipt.queue_bytes == 0))
        })
}

/// Require the receipt to carry a forwarded peer request identity, then build
/// the observation from the reclaimed-stream receipt latch.
fn latched_owner_observation(
    receipt: &tunnel_relay::StreamTerminalReceiptEvent,
) -> Option<LateResponseOwnerObservation> {
    let request_id = receipt.request_id.clone().filter(|id| !id.is_empty())?;
    Some(LateResponseOwnerObservation {
        owner_receipt_request_id: request_id,
        owner_recv_contiguous_after: receipt.recv_contiguous_connector_to_relay,
        owner_delivered_contiguous_after: receipt.delivered_contiguous_connector_to_relay,
        owner_receive_terminal_sequence: receipt.receive_terminal_sequence,
        stream_present: false,
        stream_terminal: true,
        terminal_stream_latched: true,
        queue_bytes: receipt.queue_bytes,
        replay_frames: receipt
            .last_emitted_relay_to_connector
            .saturating_sub(receipt.peer_acked_relay_to_connector)
            .try_into()
            .unwrap_or(usize::MAX),
        replay_bytes: receipt.replay_bytes_relay_to_connector,
        no_replay: true,
    })
}

/// Await the owner's bounded connector FIN/RESET receipt for the exact late
/// stream.  The receipt is the authoritative, positive owner-side proof of the
/// late DATA/FIN: it is published before the owner STREAM_FORGET can reclaim
/// the stream and survives that reclamation, so a fast reclamation cannot be
/// read as an absence.  When the stream is still live the live cursors are
/// additionally checked; once reclaimed, the receipt's own cursors/budget are.
/// The owner's best-effort forward to the severed ingress is deliberately not
/// required here; see [`validate_late_response_evidence`].
async fn wait_for_late_response_terminal(
    cluster: &ProductionCluster,
    identity: &LateResponseIdentity,
    deadline: Instant,
) -> Result<LateResponseOwnerObservation> {
    let expected_owner_receive = identity
        .owner_recv_contiguous_before
        .checked_add(2)
        .ok_or_else(|| {
            HarnessError::Process("synthetic late-frame owner receive cursor overflowed".into())
        })?;
    loop {
        let snapshot = owner_snapshot_before(cluster, deadline).await?;
        let session = snapshot.sessions.iter().find(|session| {
            session.tenant_id == identity.tenant_id
                && session.device_id == identity.device_id
                && session.session_id == identity.session_id
                && session.epoch == identity.epoch
        });
        if let Some(session) = session {
            // The catalog owner is unchanged throughout; a carrier change here
            // would mean the selected route moved and is a hard failure.
            if session.active_generation != identity.generation
                || session.active_connection_id != identity.connection_id
            {
                return Err(HarnessError::Process(
                    "synthetic late-frame owner carrier changed before terminal evidence".into(),
                ));
            }
            if let Some(stream) = session.streams.iter().find(|stream| {
                stream.stream_id == identity.stream_id
                    && stream.operation_id == identity.operation_id
            }) {
                // The exact stream is still present: require the live terminal
                // cursors together with the matching FIN/RESET receipt.
                if let Some(receipt) =
                    matching_terminal_receipt(&snapshot, identity, expected_owner_receive, false)
                    && let Some(request_id) = receipt.request_id.clone().filter(|id| !id.is_empty())
                    && stream.terminal
                    && stream.recv_contiguous_connector_to_relay == expected_owner_receive
                    && stream.delivered_contiguous_connector_to_relay == expected_owner_receive
                    && stream.queue_bytes == 0
                    && stream.replay_frames_relay_to_connector == 0
                    && stream.replay_bytes_relay_to_connector == 0
                {
                    return Ok(LateResponseOwnerObservation {
                        owner_receipt_request_id: request_id,
                        owner_recv_contiguous_after: stream.recv_contiguous_connector_to_relay,
                        owner_delivered_contiguous_after: stream
                            .delivered_contiguous_connector_to_relay,
                        owner_receive_terminal_sequence: receipt.receive_terminal_sequence,
                        stream_present: true,
                        stream_terminal: true,
                        terminal_stream_latched: false,
                        queue_bytes: stream.queue_bytes,
                        replay_frames: stream.replay_frames_relay_to_connector,
                        replay_bytes: stream.replay_bytes_relay_to_connector,
                        no_replay: true,
                    });
                }
            } else if let Some(receipt) =
                matching_terminal_receipt(&snapshot, identity, expected_owner_receive, true)
                && let Some(observation) = latched_owner_observation(receipt)
            {
                // The stream was reclaimed after the FIN, but the owner's
                // bounded receipt proves the exact terminal cursor was reached
                // on this carrier with no retained replay or queue.
                return Ok(observation);
            }
        } else if let Some(receipt) =
            matching_terminal_receipt(&snapshot, identity, expected_owner_receive, true)
            && let Some(observation) = latched_owner_observation(receipt)
        {
            // Even the session has been cleaned up, but the bounded receipt
            // latch still proves the exact connector FIN/RESET receipt.
            return Ok(observation);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "synthetic late-frame owner did not publish the exact connector FIN/RESET receipt"
                    .into(),
            ));
        }
        tokio::time::sleep(LATE_RESPONSE_POLL).await;
    }
}

fn owner_digest(owner: &OwnerToken) -> String {
    let canonical = serde_json::to_vec(owner).expect("OwnerToken is serializable");
    Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn wait_for_effect(state: &EffectState) -> Result<()> {
    let deadline = Instant::now() + SCENARIO_TIMEOUT;
    loop {
        if state.effect_invocations.load(Ordering::Acquire) > 0 {
            return Ok(());
        }
        timeout_at(deadline, state.effect_observed.notified())
            .await
            .map_err(|_| {
                HarnessError::Timeout("synthetic backend effect was not observed".into())
            })?;
    }
}

struct ConsumerOutcome {
    terminal: ConsumerTerminal,
    success: bool,
    interrupted_or_unknown: bool,
    observation_elapsed_ms: u64,
    observation_deadline_ms: u64,
}

impl ConsumerOutcome {
    fn new(terminal: ConsumerTerminal, started: Instant) -> Self {
        Self {
            terminal,
            success: matches!(terminal, ConsumerTerminal::Success),
            interrupted_or_unknown: terminal.is_interruption_or_unknown(),
            observation_elapsed_ms: duration_millis(started.elapsed()),
            observation_deadline_ms: duration_millis(FAILURE_OBSERVATION_TIMEOUT),
        }
    }
}

struct PeerFaultGuard<'a> {
    cluster: &'a ProductionCluster,
    owner_relay: &'static str,
    ingress_relay: &'static str,
    armed: bool,
}

impl<'a> PeerFaultGuard<'a> {
    fn new(
        cluster: &'a ProductionCluster,
        owner_relay: &'static str,
        ingress_relay: &'static str,
    ) -> Self {
        Self {
            cluster,
            owner_relay,
            ingress_relay,
            armed: false,
        }
    }

    fn enable(&mut self) -> Result<()> {
        self.cluster
            .set_peer_path_drop_from(self.owner_relay, self.ingress_relay, true)?;
        self.armed = true;
        Ok(())
    }

    fn clear(&mut self) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        let result =
            self.cluster
                .set_peer_path_drop_from(self.owner_relay, self.ingress_relay, false);
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl Drop for PeerFaultGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ =
                self.cluster
                    .set_peer_path_drop_from(self.owner_relay, self.ingress_relay, false);
        }
    }
}

async fn wait_for_consumer_interruption(
    stream: &mut super::ConsumerStream,
    started: Instant,
    deadline: Instant,
) -> Result<ConsumerOutcome> {
    loop {
        match timeout_at(deadline, stream.socket.next()).await {
            Err(_) => {
                return Ok(ConsumerOutcome::new(
                    ConsumerTerminal::ObserverDeadline,
                    started,
                ));
            }
            Ok(Some(Ok(Message::Binary(_)))) => {
                return Ok(ConsumerOutcome::new(ConsumerTerminal::Success, started));
            }
            Ok(Some(Ok(Message::Ping(payload)))) => {
                if stream.socket.send(Message::Pong(payload)).await.is_err() {
                    return Ok(ConsumerOutcome::new(
                        ConsumerTerminal::TransportError,
                        started,
                    ));
                }
            }
            Ok(Some(Ok(Message::Pong(_) | Message::Frame(_)))) => {}
            Ok(Some(Ok(Message::Close(_)))) => {
                return Ok(ConsumerOutcome::new(ConsumerTerminal::Close, started));
            }
            Ok(None) => return Ok(ConsumerOutcome::new(ConsumerTerminal::Eof, started)),
            Ok(Some(Err(_))) => {
                return Ok(ConsumerOutcome::new(
                    ConsumerTerminal::TransportError,
                    started,
                ));
            }
            Ok(Some(Ok(Message::Text(text)))) => {
                let text: &str = text.as_ref();
                if explicit_unknown(text) {
                    return Ok(ConsumerOutcome::new(
                        ConsumerTerminal::ExplicitUnknown,
                        started,
                    ));
                }
                return Err(HarnessError::Http(
                    "synthetic consumer returned unexpected text after peer fault".into(),
                ));
            }
        }
    }
}

fn explicit_unknown(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .is_some_and(|value| {
            value.get("execution").and_then(serde_json::Value::as_str) == Some("unknown")
        })
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone)]
pub(crate) struct DeviceConfig {
    address: SocketAddr,
    device_id: Uuid,
    service_id: Uuid,
    operation: String,
    owner_id: Option<String>,
    allow_expected_owner_loss: bool,
    certificate_pem: String,
    private_key_pem: String,
    server_ca_pem: String,
}

impl DeviceConfig {
    pub(crate) fn new(
        address: SocketAddr,
        device_id: Uuid,
        service_id: Uuid,
        operation: impl Into<String>,
        certificate_pem: String,
        private_key_pem: String,
        server_ca_pem: String,
    ) -> Self {
        Self {
            address,
            device_id,
            service_id,
            operation: operation.into(),
            owner_id: None,
            allow_expected_owner_loss: false,
            certificate_pem,
            private_key_pem,
            server_ca_pem,
        }
    }

    /// Allow the selected-owner-loss fixture to observe the relay closing its
    /// held stream after the effect has committed.  The default remains
    /// strict so an unexpected close still fails EC-054 and other fixtures.
    pub(crate) fn allow_expected_owner_loss(mut self) -> Self {
        self.allow_expected_owner_loss = true;
        self
    }
}

pub(crate) struct DeviceFixture {
    cancel: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
    state: Arc<EffectState>,
}

impl DeviceFixture {
    pub(crate) async fn start(config: DeviceConfig, state: Arc<EffectState>) -> Result<Self> {
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            let result = AssertUnwindSafe(run_device(
                config,
                task_state.clone(),
                task_cancel,
                ready_tx,
            ))
            .catch_unwind()
            .await;
            match result {
                Ok(result) => {
                    let outcome = match &result {
                        Ok(()) => "ok".to_owned(),
                        Err(error) => format!("error: {error}"),
                    };
                    task_state.record_device_task_outcome(outcome);
                    result
                }
                Err(_) => {
                    let error =
                        HarnessError::Process("synthetic device fixture task panicked".into());
                    task_state.record_device_task_outcome(format!("panic: {error}"));
                    Err(error)
                }
            }
        });
        let fixture = Self {
            cancel,
            task: Some(task),
            state,
        };
        match timeout(DEVICE_HANDSHAKE_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(fixture),
            Ok(Ok(Err(detail))) => {
                let primary = HarnessError::Http(format!("{detail}; {}", fixture.diagnostic()));
                let cleanup = fixture.shutdown().await;
                Err(with_cleanup(primary, cleanup))
            }
            Ok(Err(_)) => {
                let primary = HarnessError::Process(format!(
                    "synthetic device fixture exited before admission readiness; {}",
                    fixture.diagnostic()
                ));
                let cleanup = fixture.shutdown().await;
                Err(with_cleanup(primary, cleanup))
            }
            Err(_) => {
                let primary = HarnessError::Timeout(format!(
                    "synthetic device fixture admission exceeded its deadline; {}",
                    fixture.diagnostic()
                ));
                let cleanup = fixture.shutdown().await;
                Err(with_cleanup(primary, cleanup))
            }
        }
    }

    fn diagnostic(&self) -> String {
        let task_state = self.task.as_ref().map_or("joined", |task| {
            if task.is_finished() {
                "finished"
            } else {
                "running"
            }
        });
        self.state.device_diagnostic(task_state)
    }

    pub(crate) async fn shutdown(mut self) -> Result<()> {
        self.cancel.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match timeout(DEVICE_CLEANUP_TIMEOUT, &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(error)) => Err(HarnessError::Process(format!(
                "synthetic device fixture task failed: {error}"
            ))),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(HarnessError::Timeout(
                    "synthetic device fixture cleanup timed out".into(),
                ))
            }
        }
    }
}

impl Drop for DeviceFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn with_cleanup(primary: HarnessError, cleanup: Result<()>) -> HarnessError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => HarnessError::Process(format!(
            "{primary}; synthetic device cleanup also failed: {cleanup}"
        )),
    }
}

async fn run_device(
    config: DeviceConfig,
    state: Arc<EffectState>,
    cancel: CancellationToken,
    ready_tx: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    let mut ready_tx = Some(ready_tx);
    let mut ready_sent = false;
    let result = async {
        let tls = load_client_config_from_pem(
            config.certificate_pem.as_bytes(),
            config.private_key_pem.as_bytes(),
            config.server_ca_pem.as_bytes(),
        )
        .map_err(|error| HarnessError::Pki(format!("synthetic device TLS: {error}")))?;
        let mut control = connect_device(
            config.address,
            "/v1/tunnel/control",
            tls.clone(),
            CONTROL_SUBPROTOCOL,
            None,
        )
        .await?;
        state.set_device_phase(DevicePhase::ControlConnected);
        state.control_admitted.store(true, Ordering::Release);

        let hello_message_id = Uuid::new_v4().to_string();
        let mut hello = Hello::new(
            hello_message_id.clone(),
            config.device_id.to_string(),
            PROTOCOL_MAJOR,
            PROTOCOL_MINOR,
        );
        hello.features = vec![
            "m1-control-data".to_owned(),
            "authorization-challenge".to_owned(),
            "echo".to_owned(),
            "ordered-rotation-v1".to_owned(),
            "owner-fencing-v1".to_owned(),
        ];
        hello.rotation_policy = Some(tunnel_protocol::RotationPolicy::new(
            300_000,
            5_000,
            10_000,
        ));
        hello.services = vec![ServiceAdvertisement::new(
            config.service_id.to_string(),
            "echo",
            "1",
            ["echo", "data", "fin", "ack"],
        )];
        send_control(&mut control, &ControlMessage::Hello(hello)).await?;
        state.set_device_phase(DevicePhase::HelloSent);

        let welcome = match next_control(&mut control, Instant::now() + DEVICE_HANDSHAKE_TIMEOUT).await? {
            ControlMessage::Welcome(welcome) => welcome,
            other => {
                return Err(HarnessError::Http(format!(
                    "synthetic device expected WELCOME, received {}",
                    other.kind_name()
                )));
            }
        };
        state.set_device_phase(DevicePhase::WelcomeReceived);
        let required_features = [
            "m1-control-data",
            "authorization-challenge",
            "echo",
            "ordered-rotation-v1",
            "owner-fencing-v1",
        ];
        if welcome.session_id.is_empty()
            || welcome.message_id.is_empty()
            || welcome.reply_to != hello_message_id
            || welcome.epoch == 0
            || welcome.connection_id.is_empty()
            || welcome.attachment_ticket.is_empty()
            || welcome.generation != 1
            || welcome.protocol_major != PROTOCOL_MAJOR
            || welcome.protocol_minor != PROTOCOL_MINOR
            || welcome.owner_id.is_none()
            || welcome.reconnect_credential.is_some()
            || welcome.rotation_interval_ms.is_none()
            || welcome.rotation_handshake_timeout_ms.is_none()
            || welcome.rotation_overlap_timeout_ms.is_none()
            || welcome.rotation_recovery_timeout_ms.is_none()
            || required_features.iter().any(|feature| {
                !welcome
                    .supported_features
                    .iter()
                    .any(|candidate| candidate == feature)
            })
        {
            return Err(HarnessError::Http(
                "synthetic device received an invalid WELCOME".into(),
            ));
        }
        let fence = match next_control(&mut control, Instant::now() + DEVICE_HANDSHAKE_TIMEOUT).await? {
            ControlMessage::OwnerFence(fence) => fence,
            other => {
                return Err(HarnessError::Http(format!(
                    "synthetic device expected OWNER_FENCE, received {}",
                    other.kind_name()
                )));
            }
        };
        fence
            .validate()
            .map_err(|error| HarnessError::Http(format!("synthetic OWNER_FENCE validation: {error}")))?;
        if fence.session_id != welcome.session_id
            || fence.epoch != welcome.epoch
            || Some(&fence.owner_id) != welcome.owner_id.as_ref()
            || config
                .owner_id
                .as_deref()
                .is_some_and(|expected| expected != fence.owner_id)
        {
            return Err(HarnessError::Http(
                "synthetic device OWNER_FENCE did not match the WELCOME/session owner".into(),
            ));
        }
        state.record_fence_owner_id(&fence.owner_id)?;
        let owner_fenced = OwnerFenced::from_fence(Uuid::new_v4().to_string(), &fence);
        owner_fenced
            .validate_context(&fence)
            .map_err(|error| HarnessError::Http(format!("synthetic OWNER_FENCED validation: {error}")))?;
        send_control(
            &mut control,
            &ControlMessage::OwnerFenced(owner_fenced),
        )
        .await?;
        state.set_device_phase(DevicePhase::OwnerFenced);

        let mut data = connect_device(
            config.address,
            "/v1/tunnel/data",
            tls,
            DATA_SUBPROTOCOL,
            Some(&welcome.attachment_ticket),
        )
        .await?;
        let ready = loop {
            match next_control(&mut control, Instant::now() + DEVICE_HANDSHAKE_TIMEOUT).await? {
                ControlMessage::DataReady(ready) => break ready,
                ControlMessage::OwnerFence(_) => continue,
                other => {
                    return Err(HarnessError::Http(format!(
                        "synthetic device expected DATA_READY, received {}",
                        other.kind_name()
                    )));
                }
            }
        };
        if ready.session_id != welcome.session_id
            || ready.epoch != welcome.epoch
            || ready.generation != welcome.generation
            || ready.connection_id != welcome.connection_id
            || ready.reply_to != welcome.message_id
        {
            return Err(HarnessError::Http(
                "synthetic device DATA_READY did not match WELCOME".into(),
            ));
        }
        state.owner_fenced.store(true, Ordering::Release);
        state.data_admitted.store(true, Ordering::Release);
        state.set_device_phase(DevicePhase::DataReady);
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(Ok(()));
        }
        ready_sent = true;

        let mut stream_context: Option<StreamContext> = None;
        let mut authorized = false;
        let mut pending_data = None;
        let mut inbound = InboundSequence::default();
        loop {
            if authorized
                && let Some(frame) = pending_data.take()
            {
                let Some(context) = stream_context.as_ref() else {
                    return Err(HarnessError::Http(
                        "synthetic buffered data lost its OPEN context".into(),
                    ));
                };
                state.dispatch_buffered_application_frame(&frame)?;
                let frame_context = StreamFrameContext {
                    epoch: welcome.epoch,
                    generation: welcome.generation,
                    stream_id: context.stream_id,
                };
                let acknowledged = inbound.last_received_sequence();
                let mut runtime = DeviceStreamRuntime {
                    control: &mut control,
                    data: &mut data,
                    state: &state,
                    cancel: &cancel,
                    context: frame_context,
                    inbound: &mut inbound,
                    allow_expected_owner_loss: config.allow_expected_owner_loss,
                };
                state.set_device_phase(DevicePhase::HoldingResponse);
                hold_and_respond(&mut runtime, acknowledged).await?;
                break;
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                control_item = control.next() => {
                    match control_item {
                        Some(Ok(Message::Text(text))) => {
                            let message = decode_control(text.as_bytes()).map_err(|error| HarnessError::Http(format!("decoding synthetic control: {error}")))?;
                            match message {
                                ControlMessage::Open(open) => {
                                    if open.session_id != welcome.session_id
                                        || open.epoch != welcome.epoch
                                        || open.service_id != config.service_id.to_string()
                                        || open.operation != config.operation
                                        || stream_context.is_some()
                                    {
                                        return Err(HarnessError::Http("synthetic device received invalid OPEN".into()));
                                    }
                                    let opened = ControlMessage::Opened(Opened::new(
                                        Uuid::new_v4().to_string(),
                                        open.message_id.clone(),
                                        welcome.session_id.clone(),
                                        welcome.epoch,
                                        open.stream_id,
                                        open.operation_id.clone(),
                                        open.initial_receive_window,
                                        open.initial_send_window,
                                    ));
                                    send_control(&mut control, &opened).await?;
                                    state.set_device_phase(DevicePhase::OperationOpened);
                                    let challenge_id = Uuid::new_v4().to_string();
                                    let nonce = Uuid::new_v4().to_string();
                                    let permission_digest = open
                                        .metadata
                                        .get("permission_digest")
                                        .cloned()
                                        .unwrap_or_else(|| "m1-echo".to_owned());
                                    let grant_revision = open
                                        .metadata
                                        .get("grant_revision")
                                        .and_then(|value| value.parse::<u64>().ok())
                                        .unwrap_or(0);
                                    let challenge_message_id = Uuid::new_v4().to_string();
                                    let challenge = ControlMessage::AuthorizationChallenge(
                                        AuthorizationChallenge::new(
                                            challenge_message_id.clone(),
                                            welcome.session_id.clone(),
                                            welcome.epoch,
                                            open.stream_id,
                                            challenge_id.clone(),
                                            nonce.clone(),
                                            open.service_id.clone(),
                                            permission_digest.clone(),
                                            grant_revision,
                                        ),
                                    );
                                    send_control(&mut control, &challenge).await?;
                                    if open.initial_receive_window == 0 {
                                        return Err(HarnessError::Http(
                                            "synthetic OPEN carried zero receive credit".into(),
                                        ));
                                    }
                                    state.record_operation_stream_id(open.stream_id)?;
                                    inbound.set_receive_window(open.initial_receive_window);
                                    stream_context = Some(StreamContext {
                                        stream_id: open.stream_id,
                                        challenge_message_id,
                                        challenge_id,
                                        nonce,
                                        permission_digest,
                                        grant_revision,
                                    });
                                }
                                ControlMessage::AuthorizationConfirmed(confirmed) => {
                                    let Some(context) = stream_context.as_ref() else {
                                        return Err(HarnessError::Http("synthetic device received AUTHORIZATION_CONFIRMED before OPEN".into()));
                                    };
                                    if confirmed.session_id != welcome.session_id
                                        || confirmed.epoch != welcome.epoch
                                        || confirmed.stream_id != context.stream_id
                                        || confirmed.reply_to != context.challenge_message_id
                                        || confirmed.challenge_id != context.challenge_id
                                        || confirmed.nonce != context.nonce
                                        || confirmed.permission_digest != context.permission_digest
                                        || confirmed.grant_revision != context.grant_revision
                                        || !(1..=5_000).contains(&confirmed.remaining_ms)
                                    {
                                        return Err(HarnessError::Http("synthetic device received mismatched AUTHORIZATION_CONFIRMED".into()));
                                    }
                                    authorized = true;
                                    state.set_device_phase(DevicePhase::AuthorizationConfirmed);
                                    state.operation_opened.store(true, Ordering::Release);
                                    state.authorization_confirmed.store(true, Ordering::Release);
                                }
                                ControlMessage::AuthorizationChallenge(_) => {
                                    return Err(HarnessError::Http(
                                        "synthetic device received an unexpected AUTHORIZATION_CHALLENGE"
                                            .into(),
                                    ));
                                }
                                ControlMessage::Ping(ping) => {
                                    send_control_pong(&mut control, &ping).await?;
                                }
                                ControlMessage::Rejected(_) => return Ok(()),
                                ControlMessage::GoAway(_) => return Ok(()),
                                _ => {}
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            send_ws_pong(&mut control, payload).await?;
                        }
                        Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                        Some(Ok(Message::Close(_))) | None => return Ok(()),
                        Some(Ok(Message::Binary(_))) => return Err(HarnessError::Http("binary frame arrived on synthetic control socket".into())),
                        Some(Err(error)) => return Err(HarnessError::Http(format!("synthetic control socket: {error}"))),
                    }
                }
                data_item = data.next() => {
                    match data_item {
                        Some(Ok(Message::Binary(bytes))) => {
                            let frame = Frame::decode(&bytes).map_err(|error| HarnessError::Http(format!("decoding synthetic data frame: {error}")))?;
                            let Some(context) = stream_context.as_ref() else {
                                return Err(HarnessError::Http("synthetic data arrived before OPEN".into()));
                            };
                            if frame.epoch != welcome.epoch
                                || frame.generation != welcome.generation
                                || frame.stream_id != context.stream_id
                            {
                                return Err(HarnessError::Http("synthetic data frame was outside the admitted operation".into()));
                            }
                            match frame.kind {
                                FrameKind::Data => {
                                    state.validate_request_payload(&frame.payload)?;
                                    if !authorized {
                                        state.buffer_application_frame(&frame)?;
                                    } else {
                                        state.observe_application_frame(&frame)?;
                                    }
                                    if inbound.accept_data(frame.sequence)? {
                                        send_transport_ack(&mut data, &frame, &state).await?;
                                        let limit = inbound.release_payload(frame.payload.len())?;
                                        send_transport_window_update(
                                            &mut data, &frame, &state, limit,
                                        )
                                        .await?;
                                    }
                                    if !authorized {
                                        pending_data = Some(frame);
                                        continue;
                                    }
                                    let frame_context = StreamFrameContext {
                                        epoch: welcome.epoch,
                                        generation: welcome.generation,
                                        stream_id: context.stream_id,
                                    };
                                    let acknowledged = inbound.last_received_sequence();
                                    let mut runtime = DeviceStreamRuntime {
                                        control: &mut control,
                                        data: &mut data,
                                        state: &state,
                                        cancel: &cancel,
                                        context: frame_context,
                                        inbound: &mut inbound,
                                        allow_expected_owner_loss: config.allow_expected_owner_loss,
                                    };
                                    state.set_device_phase(DevicePhase::HoldingResponse);
                                    hold_and_respond(&mut runtime, acknowledged).await?;
                                    break;
                                }
                                FrameKind::Fin => {
                                    validate_empty_terminal(&frame.payload)?;
                                    let fresh_fin = inbound.accept_fin(frame.sequence)?;
                                    state.observe_terminal_frame(&frame)?;
                                    if fresh_fin {
                                        send_transport_ack(&mut data, &frame, &state).await?;
                                    }
                                }
                                FrameKind::Ack | FrameKind::WindowUpdate | FrameKind::Reset => {}
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            send_ws_pong(&mut data, payload).await?;
                        }
                        Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                        Some(Ok(Message::Close(_))) | None => return Ok(()),
                        Some(Ok(Message::Text(_))) => return Err(HarnessError::Http("text frame arrived on synthetic data socket".into())),
                        Some(Err(error)) => return Err(HarnessError::Http(format!("synthetic data socket: {error}"))),
                    }
                }
            }
        }
        state.set_device_phase(DevicePhase::Closed);
        close_device_socket(control).await;
        close_device_socket(data).await;
        Ok(())
    }
    .await;
    // If the carrier closes before the requested late branch can run, wake
    // the scenario with an explicit incomplete outcome rather than allowing
    // cleanup to race an unobserved send.
    state.complete_late_response_if_missing();
    if !ready_sent {
        let detail = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_else(|| "synthetic device exited before admission readiness".into());
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(Err(detail));
        }
    }
    result
}

#[derive(Clone)]
struct StreamContext {
    stream_id: u64,
    challenge_message_id: String,
    challenge_id: String,
    nonce: String,
    permission_digest: String,
    grant_revision: u64,
}

#[derive(Default)]
struct InboundSequence {
    next_sequence: u64,
    fin_seen: bool,
    receive_window: u64,
    released_payload_bytes: u64,
}

impl InboundSequence {
    fn set_receive_window(&mut self, receive_window: u64) {
        self.receive_window = receive_window;
    }

    fn release_payload(&mut self, payload_len: usize) -> Result<u64> {
        let payload_len = u64::try_from(payload_len)
            .map_err(|_| HarnessError::Http("synthetic payload length overflow".into()))?;
        self.released_payload_bytes = self
            .released_payload_bytes
            .checked_add(payload_len)
            .ok_or_else(|| HarnessError::Http("synthetic receive credit overflow".into()))?;
        self.receive_window
            .checked_add(self.released_payload_bytes)
            .ok_or_else(|| HarnessError::Http("synthetic receive window overflow".into()))
    }

    fn accept_data(&mut self, sequence: u64) -> Result<bool> {
        let expected = if self.next_sequence == 0 {
            1
        } else {
            self.next_sequence
        };
        if self.fin_seen || sequence > expected {
            return Err(HarnessError::Http(format!(
                "synthetic inbound DATA sequence was {sequence}, expected {expected}"
            )));
        }
        if sequence < expected {
            return Ok(false);
        }
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| HarnessError::Http("synthetic inbound sequence overflow".into()))?;
        Ok(true)
    }

    fn accept_fin(&mut self, sequence: u64) -> Result<bool> {
        let expected = if self.next_sequence == 0 {
            1
        } else {
            self.next_sequence
        };
        if sequence > expected {
            return Err(HarnessError::Http(format!(
                "synthetic inbound FIN sequence was {sequence}, expected {expected}"
            )));
        }
        if self.fin_seen || sequence < expected {
            return Ok(false);
        }
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| HarnessError::Http("synthetic inbound sequence overflow".into()))?;
        self.fin_seen = true;
        Ok(true)
    }

    fn last_received_sequence(&self) -> u64 {
        self.next_sequence.saturating_sub(1)
    }
}

#[derive(Clone, Copy)]
struct StreamFrameContext {
    epoch: u64,
    generation: u64,
    stream_id: u64,
}

struct DeviceStreamRuntime<'a> {
    control: &'a mut DeviceSocket,
    data: &'a mut DeviceSocket,
    state: &'a EffectState,
    cancel: &'a CancellationToken,
    context: StreamFrameContext,
    inbound: &'a mut InboundSequence,
    allow_expected_owner_loss: bool,
}

async fn hold_and_respond(runtime: &mut DeviceStreamRuntime<'_>, acknowledged: u64) -> Result<()> {
    hold_until_release(runtime).await?;
    // An armed owner-loss observation finishes this fixture operation. Do not
    // manufacture response writes and a second read loop on the dead carrier.
    // Cancellation likewise owns cleanup, rather than releasing a response.
    if runtime.state.owner_loss_close_observed() || runtime.cancel.is_cancelled() {
        return Ok(());
    }
    if runtime.state.late_mode() {
        return keep_alive_until_cancel(runtime).await;
    }
    let context = runtime.context;
    send_backend_response(
        runtime.data,
        runtime.state,
        context.epoch,
        context.generation,
        context.stream_id,
        acknowledged,
    )
    .await?;
    keep_alive_until_cancel(runtime).await
}

async fn hold_until_release(runtime: &mut DeviceStreamRuntime<'_>) -> Result<()> {
    let context = runtime.context;
    let control = &mut *runtime.control;
    let data = &mut *runtime.data;
    let state = runtime.state;
    let cancel = runtime.cancel;
    let inbound = &mut *runtime.inbound;
    let allow_expected_owner_loss = runtime.allow_expected_owner_loss;
    loop {
        tokio::select! {
            _ = state.release_response.notified() => return Ok(()),
            _ = cancel.cancelled() => return Ok(()),
            control_item = control.next() => match control_item {
                Some(Ok(Message::Ping(payload))) => send_ws_pong(control, payload).await?,
                Some(Ok(Message::Text(text))) => {
                    let message = decode_control(text.as_bytes()).map_err(|error| HarnessError::Http(format!("decoding held synthetic control: {error}")))?;
                    if let ControlMessage::Ping(ping) = message {
                        send_control_pong(control, &ping).await?;
                    }
                }
                Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    return record_expected_owner_loss_close(
                        state,
                        allow_expected_owner_loss,
                        "control",
                    );
                }
                Some(Ok(Message::Binary(_))) => return Err(HarnessError::Http("binary frame arrived on held synthetic control".into())),
                Some(Err(error)) if allow_expected_owner_loss && is_owner_loss_transport_close(&error) => {
                    return record_expected_owner_loss_close(state, allow_expected_owner_loss, "control");
                }
                Some(Err(error)) => return Err(HarnessError::Http(format!("held synthetic control socket: {error}"))),
            },
            data_item = data.next() => match data_item {
                Some(Ok(Message::Binary(bytes))) => {
                    let frame = Frame::decode(&bytes).map_err(|error| HarnessError::Http(format!("decoding held synthetic data frame: {error}")))?;
                    if frame.epoch != context.epoch
                        || frame.generation != context.generation
                        || frame.stream_id != context.stream_id
                    {
                        return Err(HarnessError::Http("held synthetic data frame changed operation".into()));
                    }
                    match frame.kind {
                        FrameKind::Data => {
                            state.validate_request_payload(&frame.payload)?;
                            state.observe_application_frame(&frame)?;
                            if inbound.accept_data(frame.sequence)? {
                                send_transport_ack(data, &frame, state).await?;
                                let limit = inbound.release_payload(frame.payload.len())?;
                                send_transport_window_update(data, &frame, state, limit).await?;
                            }
                        }
                        FrameKind::Fin => {
                            validate_empty_terminal(&frame.payload)?;
                            state.observe_terminal_frame(&frame)?;
                            if inbound.accept_fin(frame.sequence)? {
                                send_transport_ack(data, &frame, state).await?;
                            }
                        }
                        FrameKind::Ack | FrameKind::WindowUpdate | FrameKind::Reset => {}
                    }
                }
                Some(Ok(Message::Ping(payload))) => send_ws_pong(data, payload).await?,
                Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    return record_expected_owner_loss_close(
                        state,
                        allow_expected_owner_loss,
                        "data",
                    );
                }
                Some(Ok(Message::Text(_))) => return Err(HarnessError::Http("text frame arrived on held synthetic data".into())),
                Some(Err(error)) if allow_expected_owner_loss && is_owner_loss_transport_close(&error) => {
                    return record_expected_owner_loss_close(state, allow_expected_owner_loss, "data");
                }
                Some(Err(error)) => return Err(HarnessError::Http(format!("held synthetic data socket: {error}"))),
            },
        }
    }
}

/// Abrupt transport termination is expected only inside the explicitly armed
/// owner-loss fixture. Protocol/decoding errors are never treated as closure.
fn is_owner_loss_transport_close(error: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::Error;
    match error {
        Error::ConnectionClosed | Error::AlreadyClosed => true,
        Error::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
        ),
        _ => false,
    }
}

fn record_expected_owner_loss_close(
    state: &EffectState,
    allow_expected_owner_loss: bool,
    socket: &str,
) -> Result<()> {
    if !allow_expected_owner_loss || !state.expected_owner_loss_armed() {
        return Err(HarnessError::Http(format!(
            "synthetic {socket} closed while holding response"
        )));
    }
    if state.effect_count() != 1 || state.response_send_attempted() {
        return Err(HarnessError::Process(format!(
            "synthetic expected owner-loss {socket} close arrived outside the held one-effect boundary"
        )));
    }
    state.record_owner_loss_close();
    Ok(())
}

async fn keep_alive_until_cancel(runtime: &mut DeviceStreamRuntime<'_>) -> Result<()> {
    runtime.state.set_device_phase(DevicePhase::Draining);
    let context = runtime.context;
    let control = &mut *runtime.control;
    let data = &mut *runtime.data;
    let state = runtime.state;
    let cancel = runtime.cancel;
    let inbound = &mut *runtime.inbound;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = state.late_response_requested.notified() => {
                let result = send_late_backend_response(
                    data,
                    state,
                    context.epoch,
                    context.generation,
                    context.stream_id,
                    inbound.last_received_sequence(),
                )
                .await;
                state.complete_late_response(result);
            }
            control_item = control.next() => match control_item {
                Some(Ok(Message::Ping(payload))) => send_ws_pong(control, payload).await?,
                Some(Ok(Message::Text(text))) => {
                    let message = decode_control(text.as_bytes()).map_err(|error| HarnessError::Http(format!("decoding drained synthetic control: {error}")))?;
                    if let ControlMessage::Ping(ping) = message {
                        send_control_pong(control, &ping).await?;
                    }
                }
                Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Ok(Message::Binary(_))) => return Err(HarnessError::Http("binary frame arrived on drained synthetic control".into())),
                Some(Err(error)) => return Err(HarnessError::Http(format!("drained synthetic control socket: {error}"))),
            },
            data_item = data.next() => match data_item {
                Some(Ok(Message::Binary(bytes))) => {
                    let frame = Frame::decode(&bytes).map_err(|error| HarnessError::Http(format!("decoding drained synthetic data frame: {error}")))?;
                    if frame.epoch != context.epoch
                        || frame.generation != context.generation
                        || frame.stream_id != context.stream_id
                    {
                        return Err(HarnessError::Http("drained synthetic data frame changed operation".into()));
                    }
                    match frame.kind {
                        FrameKind::Data => {
                            state.validate_request_payload(&frame.payload)?;
                            state.observe_application_frame(&frame)?;
                            if inbound.accept_data(frame.sequence)? {
                                send_transport_ack(data, &frame, state).await?;
                                let limit = inbound.release_payload(frame.payload.len())?;
                                send_transport_window_update(data, &frame, state, limit).await?;
                            }
                        }
                        FrameKind::Fin => {
                            validate_empty_terminal(&frame.payload)?;
                            state.observe_terminal_frame(&frame)?;
                            if inbound.accept_fin(frame.sequence)? {
                                send_transport_ack(data, &frame, state).await?;
                            }
                        }
                        FrameKind::Ack | FrameKind::WindowUpdate | FrameKind::Reset => {}
                    }
                }
                Some(Ok(Message::Ping(payload))) => send_ws_pong(data, payload).await?,
                Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Ok(Message::Text(_))) => return Err(HarnessError::Http("text frame arrived on drained synthetic data".into())),
                Some(Err(error)) => return Err(HarnessError::Http(format!("drained synthetic data socket: {error}"))),
            },
        }
    }
}

fn validate_request_record(payload: &[u8]) -> Result<()> {
    if payload.len() < 4 {
        return Err(HarnessError::Http(
            "synthetic request record was truncated".into(),
        ));
    }
    let declared = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if declared != payload.len().saturating_sub(4) {
        return Err(HarnessError::Http(format!(
            "synthetic request record declared {declared} bytes but carried {}",
            payload.len().saturating_sub(4)
        )));
    }
    Ok(())
}

fn validate_empty_terminal(payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Http(
            "synthetic FIN carried an unexpected payload".into(),
        ))
    }
}

async fn send_transport_ack(
    data: &mut DeviceSocket,
    received: &Frame,
    state: &EffectState,
) -> Result<()> {
    let ack = Frame::ack(
        received.epoch,
        received.generation,
        received.stream_id,
        received.sequence,
    );
    let encoded = ack
        .encode()
        .map_err(|error| HarnessError::Http(format!("encoding synthetic receipt ACK: {error}")))?;
    timeout(EXCHANGE_TIMEOUT, data.send(Message::Binary(encoded.into())))
        .await
        .map_err(|_| HarnessError::Timeout("synthetic receipt ACK write timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("synthetic receipt ACK write: {error}")))?;
    state
        .transport_ack_frames_sent
        .fetch_add(1, Ordering::AcqRel);
    Ok(())
}

async fn send_transport_window_update(
    data: &mut DeviceSocket,
    received: &Frame,
    state: &EffectState,
    limit: u64,
) -> Result<()> {
    let update = Frame::window_update(
        received.epoch,
        received.generation,
        received.stream_id,
        limit,
    );
    let encoded = update.encode().map_err(|error| {
        HarnessError::Http(format!("encoding synthetic receive window update: {error}"))
    })?;
    timeout(EXCHANGE_TIMEOUT, data.send(Message::Binary(encoded.into())))
        .await
        .map_err(|_| HarnessError::Timeout("synthetic receive window write timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("synthetic receive window write: {error}")))?;
    state
        .transport_window_updates_sent
        .fetch_add(1, Ordering::AcqRel);
    Ok(())
}

async fn send_backend_response(
    data: &mut DeviceSocket,
    state: &EffectState,
    epoch: u64,
    generation: u64,
    stream_id: u64,
    acknowledged: u64,
) -> Result<()> {
    state.set_device_phase(DevicePhase::ResponseAttempted);
    state.response_send_attempted.store(true, Ordering::Release);
    let response = state.response_payload()?;
    let frames = [
        Frame::data(epoch, generation, stream_id, 1, acknowledged, response),
        Frame::fin(epoch, generation, stream_id, 2, acknowledged),
    ];
    for frame in frames {
        let encoded = frame.encode().map_err(|error| {
            HarnessError::Http(format!("encoding synthetic backend response: {error}"))
        })?;
        let accepted = matches!(
            timeout(
                FAILURE_OBSERVATION_TIMEOUT,
                data.send(Message::Binary(encoded.into()))
            )
            .await,
            Ok(Ok(()))
        );
        if accepted {
            state.response_frames_sent.fetch_add(1, Ordering::AcqRel);
        }
    }
    Ok(())
}

/// Attempt both late response frames and report their joined outcome.  Each
/// frame gets its own bounded write attempt even when the DATA write observes
/// a legitimate carrier close; local acceptance is retained only as trigger
/// accounting and is never treated as peer receipt.
async fn send_late_backend_response(
    data: &mut DeviceSocket,
    state: &EffectState,
    epoch: u64,
    generation: u64,
    stream_id: u64,
    acknowledged: u64,
) -> LateResponseSendResult {
    state.set_device_phase(DevicePhase::ResponseAttempted);
    state.response_send_attempted.store(true, Ordering::Release);
    let response = state.expected_payload.clone();
    let frames = [
        Frame::data(epoch, generation, stream_id, 1, acknowledged, response),
        Frame::fin(epoch, generation, stream_id, 2, acknowledged),
    ];
    let mut result = LateResponseSendResult {
        data_attempts: 0,
        data_write_accepted: 0,
        data_write_rejected: 0,
        fin_attempts: 0,
        fin_write_accepted: 0,
        fin_write_rejected: 0,
        data_before_fin: true,
        write_completed: false,
        carrier_closed: false,
    };
    for (index, frame) in frames.into_iter().enumerate() {
        if index == 0 {
            result.data_attempts = result.data_attempts.saturating_add(1);
        } else {
            result.fin_attempts = result.fin_attempts.saturating_add(1);
        }
        let encoded = match frame.encode() {
            Ok(encoded) => encoded,
            Err(_) => {
                result.carrier_closed = true;
                if index == 0 {
                    result.data_write_rejected = result.data_write_rejected.saturating_add(1);
                } else {
                    result.fin_write_rejected = result.fin_write_rejected.saturating_add(1);
                }
                continue;
            }
        };
        let accepted = matches!(
            timeout(
                LATE_RESPONSE_WRITE_TIMEOUT,
                data.send(Message::Binary(encoded.into()))
            )
            .await,
            Ok(Ok(()))
        );
        if index == 0 {
            if accepted {
                result.data_write_accepted = result.data_write_accepted.saturating_add(1);
                state.response_frames_sent.fetch_add(1, Ordering::AcqRel);
            } else {
                result.data_write_rejected = result.data_write_rejected.saturating_add(1);
                result.carrier_closed = true;
            }
        } else if accepted {
            result.fin_write_accepted = result.fin_write_accepted.saturating_add(1);
            state.response_frames_sent.fetch_add(1, Ordering::AcqRel);
        } else {
            result.fin_write_rejected = result.fin_write_rejected.saturating_add(1);
            result.carrier_closed = true;
        }
    }
    result.write_completed = true;
    result
}

fn encoded_record(payload: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(payload.len())
        .map_err(|_| HarnessError::InvalidInput("synthetic response length overflow".into()))?;
    let mut encoded = Vec::with_capacity(payload.len() + 4);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

async fn connect_device(
    address: SocketAddr,
    path: &str,
    tls: std::sync::Arc<rustls::ClientConfig>,
    subprotocol: &str,
    ticket: Option<&str>,
) -> Result<DeviceSocket> {
    let mut request = format!("wss://localhost:{}{path}", address.port())
        .into_client_request()
        .map_err(|error| {
            HarnessError::Http(format!("building synthetic device request: {error}"))
        })?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_str(subprotocol).map_err(|error| {
            HarnessError::Http(format!("building synthetic subprotocol header: {error}"))
        })?,
    );
    if let Some(ticket) = ticket {
        let value = HeaderValue::from_str(&format!("Bearer {ticket}"))
            .map_err(|error| HarnessError::Http(format!("building synthetic ticket: {error}")))?;
        request.headers_mut().insert("authorization", value);
    }
    let connected = timeout(
        DEVICE_HANDSHAKE_TIMEOUT,
        connect_async_tls_with_config(request, None, true, Some(Connector::Rustls(tls))),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("synthetic device {path} handshake timed out")))?
    .map_err(|error| HarnessError::Http(format!("synthetic device {path} handshake: {error}")))?;
    let selected = connected
        .1
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok());
    if selected != Some(subprotocol) {
        return Err(HarnessError::Http(format!(
            "synthetic device {path} did not negotiate {subprotocol}"
        )));
    }
    Ok(connected.0)
}

async fn next_control(socket: &mut DeviceSocket, deadline: Instant) -> Result<ControlMessage> {
    loop {
        let item = timeout_at(deadline, socket.next())
            .await
            .map_err(|_| HarnessError::Timeout("synthetic control deadline elapsed".into()))?;
        match item {
            Some(Ok(Message::Text(text))) => {
                let message = decode_control(text.as_bytes()).map_err(|error| {
                    HarnessError::Http(format!("synthetic control decode: {error}"))
                })?;
                if let ControlMessage::Ping(ping) = message {
                    send_control_pong(socket, &ping).await?;
                    continue;
                }
                return Ok(message);
            }
            Some(Ok(Message::Ping(payload))) => send_ws_pong(socket, payload).await?,
            Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
            Some(Ok(Message::Close(_))) | None => {
                return Err(HarnessError::Http(
                    "synthetic control closed during handshake".into(),
                ));
            }
            Some(Ok(Message::Binary(_))) => {
                return Err(HarnessError::Http(
                    "binary message arrived during synthetic control handshake".into(),
                ));
            }
            Some(Err(error)) => {
                return Err(HarnessError::Http(format!(
                    "synthetic control read: {error}"
                )));
            }
        }
    }
}

async fn send_control(socket: &mut DeviceSocket, message: &ControlMessage) -> Result<()> {
    let bytes = encode_control(message)
        .map_err(|error| HarnessError::Http(format!("synthetic control encode: {error}")))?;
    let text = String::from_utf8(bytes)
        .map_err(|error| HarnessError::Http(format!("synthetic control UTF-8: {error}")))?;
    timeout(
        DEVICE_HANDSHAKE_TIMEOUT,
        socket.send(Message::Text(text.into())),
    )
    .await
    .map_err(|_| HarnessError::Timeout("synthetic control write timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("synthetic control write: {error}")))
}

async fn send_control_pong(socket: &mut DeviceSocket, ping: &tunnel_protocol::Ping) -> Result<()> {
    send_control(
        socket,
        &ControlMessage::Pong(Pong::new(
            Uuid::new_v4().to_string(),
            ping.message_id.clone(),
            ping.session_id.clone(),
            ping.epoch,
            ping.nonce,
        )),
    )
    .await
}

async fn send_ws_pong(socket: &mut DeviceSocket, payload: bytes::Bytes) -> Result<()> {
    timeout(
        DEVICE_HANDSHAKE_TIMEOUT,
        socket.send(Message::Pong(payload)),
    )
    .await
    .map_err(|_| HarnessError::Timeout("synthetic WebSocket pong timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("synthetic WebSocket pong: {error}")))
}

async fn close_device_socket(mut socket: DeviceSocket) {
    let _ = timeout(DEVICE_CLEANUP_TIMEOUT, socket.close(None)).await;
}

pub(crate) struct EffectState {
    expected_payload: Vec<u8>,
    append_backend: bool,
    record_framed: bool,
    fence_owner_id: Mutex<Option<String>>,
    device_phase: AtomicU8,
    device_task_outcome: Mutex<Option<String>>,
    control_admitted: AtomicBool,
    owner_fenced: AtomicBool,
    data_admitted: AtomicBool,
    operation_opened: AtomicBool,
    authorization_confirmed: AtomicBool,
    expected_owner_loss_armed: AtomicBool,
    owner_loss_close_observed: AtomicBool,
    effect_invocations: AtomicU64,
    operation_stream_id: AtomicU64,
    late_mode: AtomicBool,
    response_frames_sent: AtomicU64,
    response_send_attempted: AtomicBool,
    transport_ack_frames_sent: AtomicU64,
    transport_window_updates_sent: AtomicU64,
    duplicate_observations: AtomicU64,
    conflicting_observations: AtomicU64,
    invalid_observations: AtomicU64,
    fin_observations: AtomicU64,
    raw: Mutex<Vec<RawFrameObservation>>,
    append_entries: Mutex<Vec<Vec<u8>>>,
    seen: Mutex<BTreeMap<IngressKey, (Vec<u8>, bool)>>,
    effect_observed: tokio::sync::Notify,
    release_response: tokio::sync::Notify,
    late_response_requested: tokio::sync::Notify,
    late_response_requested_flag: AtomicBool,
    late_response_completed: tokio::sync::Notify,
    late_response_result: Mutex<Option<LateResponseSendResult>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct IngressKey {
    epoch: u64,
    generation: u64,
    stream_id: u64,
    sequence: u64,
    kind: String,
}

impl EffectState {
    fn new(expected_payload: Vec<u8>) -> Self {
        Self::with_backend(expected_payload, false, true)
    }

    pub(crate) fn new_append_framed(body: Vec<u8>) -> Result<Self> {
        Ok(Self::with_backend(encoded_record(&body)?, true, true))
    }

    fn with_backend(expected_payload: Vec<u8>, append_backend: bool, record_framed: bool) -> Self {
        Self {
            expected_payload,
            append_backend,
            record_framed,
            fence_owner_id: Mutex::new(None),
            device_phase: AtomicU8::new(DevicePhase::Starting as u8),
            device_task_outcome: Mutex::new(None),
            control_admitted: AtomicBool::new(false),
            owner_fenced: AtomicBool::new(false),
            data_admitted: AtomicBool::new(false),
            operation_opened: AtomicBool::new(false),
            authorization_confirmed: AtomicBool::new(false),
            expected_owner_loss_armed: AtomicBool::new(false),
            owner_loss_close_observed: AtomicBool::new(false),
            effect_invocations: AtomicU64::new(0),
            operation_stream_id: AtomicU64::new(0),
            late_mode: AtomicBool::new(false),
            response_frames_sent: AtomicU64::new(0),
            response_send_attempted: AtomicBool::new(false),
            transport_ack_frames_sent: AtomicU64::new(0),
            transport_window_updates_sent: AtomicU64::new(0),
            duplicate_observations: AtomicU64::new(0),
            conflicting_observations: AtomicU64::new(0),
            invalid_observations: AtomicU64::new(0),
            fin_observations: AtomicU64::new(0),
            raw: Mutex::new(Vec::new()),
            append_entries: Mutex::new(Vec::new()),
            seen: Mutex::new(BTreeMap::new()),
            effect_observed: tokio::sync::Notify::new(),
            release_response: tokio::sync::Notify::new(),
            late_response_requested: tokio::sync::Notify::new(),
            late_response_requested_flag: AtomicBool::new(false),
            late_response_completed: tokio::sync::Notify::new(),
            late_response_result: Mutex::new(None),
        }
    }

    fn set_device_phase(&self, phase: DevicePhase) {
        self.device_phase.store(phase as u8, Ordering::Release);
    }

    fn record_operation_stream_id(&self, stream_id: u64) -> Result<()> {
        if stream_id == 0 {
            return Err(HarnessError::Process(
                "synthetic side-effect OPEN carried a zero stream ID".into(),
            ));
        }
        self.operation_stream_id.store(stream_id, Ordering::Release);
        Ok(())
    }

    fn operation_stream_id(&self) -> Option<u64> {
        match self.operation_stream_id.load(Ordering::Acquire) {
            0 => None,
            stream_id => Some(stream_id),
        }
    }

    fn enable_late_mode(&self) {
        self.late_mode.store(true, Ordering::Release);
    }

    fn late_mode(&self) -> bool {
        self.late_mode.load(Ordering::Acquire)
    }

    fn record_device_task_outcome(&self, outcome: String) {
        if let Ok(mut observed) = self.device_task_outcome.lock() {
            *observed = Some(outcome);
        }
    }

    fn device_diagnostic(&self, task_state: &str) -> String {
        let phase = match self.device_phase.load(Ordering::Acquire) {
            value if value == DevicePhase::Starting as u8 => DevicePhase::Starting,
            value if value == DevicePhase::ControlConnected as u8 => DevicePhase::ControlConnected,
            value if value == DevicePhase::HelloSent as u8 => DevicePhase::HelloSent,
            value if value == DevicePhase::WelcomeReceived as u8 => DevicePhase::WelcomeReceived,
            value if value == DevicePhase::OwnerFenced as u8 => DevicePhase::OwnerFenced,
            value if value == DevicePhase::DataReady as u8 => DevicePhase::DataReady,
            value if value == DevicePhase::OperationOpened as u8 => DevicePhase::OperationOpened,
            value if value == DevicePhase::AuthorizationConfirmed as u8 => {
                DevicePhase::AuthorizationConfirmed
            }
            value if value == DevicePhase::HoldingResponse as u8 => DevicePhase::HoldingResponse,
            value if value == DevicePhase::ResponseAttempted as u8 => {
                DevicePhase::ResponseAttempted
            }
            value if value == DevicePhase::Draining as u8 => DevicePhase::Draining,
            value if value == DevicePhase::Closed as u8 => DevicePhase::Closed,
            _ => return format!("device task={task_state}, phase=unknown, outcome=unknown"),
        };
        let outcome = self
            .device_task_outcome
            .lock()
            .ok()
            .and_then(|observed| observed.clone())
            .unwrap_or_else(|| "pending".to_owned());
        format!(
            "device task={task_state}, phase={}, outcome={outcome}",
            phase.as_str()
        )
    }

    fn record_fence_owner_id(&self, owner_id: &str) -> Result<()> {
        self.fence_owner_id
            .lock()
            .map_err(|_| {
                HarnessError::Process("synthetic side-effect owner ID lock poisoned".into())
            })
            .map(|mut observed| {
                *observed = Some(owner_id.to_owned());
            })
    }

    fn fence_owner_id(&self) -> Result<Option<String>> {
        self.fence_owner_id
            .lock()
            .map(|observed| observed.clone())
            .map_err(|_| {
                HarnessError::Process("synthetic side-effect owner ID lock poisoned".into())
            })
    }

    fn observe_application_frame(&self, frame: &Frame) -> Result<()> {
        self.record_application_frame(frame, true)
    }

    fn validate_request_payload(&self, payload: &[u8]) -> Result<()> {
        if self.record_framed {
            validate_request_record(payload)
        } else {
            Ok(())
        }
    }

    fn buffer_application_frame(&self, frame: &Frame) -> Result<()> {
        self.record_application_frame(frame, false)
    }

    fn record_application_frame(&self, frame: &Frame, dispatch: bool) -> Result<()> {
        let key = IngressKey {
            epoch: frame.epoch,
            generation: frame.generation,
            stream_id: frame.stream_id,
            sequence: frame.sequence,
            kind: format!("{:?}", frame.kind),
        };
        let observation = RawFrameObservation {
            epoch: frame.epoch,
            generation: frame.generation,
            stream_id: frame.stream_id,
            sequence: frame.sequence,
            kind: key.kind.clone(),
            payload_len: frame.payload.len(),
        };
        let mut raw = self.raw.lock().map_err(|_| {
            HarnessError::Process("synthetic side-effect raw observation lock poisoned".into())
        })?;
        if raw.len() >= MAX_RAW_OBSERVATIONS {
            return Err(HarnessError::Process(
                "synthetic side-effect raw observation bound exceeded".into(),
            ));
        }
        raw.push(observation);
        drop(raw);

        if frame.payload != self.expected_payload {
            self.invalid_observations.fetch_add(1, Ordering::AcqRel);
        }

        let mut seen = self.seen.lock().map_err(|_| {
            HarnessError::Process("synthetic side-effect sequence lock poisoned".into())
        })?;
        if let Some((previous, dispatched)) = seen.get_mut(&key) {
            self.duplicate_observations.fetch_add(1, Ordering::AcqRel);
            if previous.as_slice() != frame.payload.as_slice() {
                self.conflicting_observations.fetch_add(1, Ordering::AcqRel);
            }
            if dispatch && !*dispatched && previous.as_slice() == self.expected_payload.as_slice() {
                *dispatched = true;
                self.commit_effect(&frame.payload)?;
            }
            return Ok(());
        }
        seen.insert(key, (frame.payload.clone(), dispatch));
        drop(seen);
        if dispatch && frame.payload == self.expected_payload {
            self.commit_effect(&frame.payload)?;
        }
        Ok(())
    }

    fn dispatch_buffered_application_frame(&self, frame: &Frame) -> Result<()> {
        let key = IngressKey {
            epoch: frame.epoch,
            generation: frame.generation,
            stream_id: frame.stream_id,
            sequence: frame.sequence,
            kind: format!("{:?}", frame.kind),
        };
        let mut seen = self.seen.lock().map_err(|_| {
            HarnessError::Process("synthetic side-effect sequence lock poisoned".into())
        })?;
        let Some((payload, dispatched)) = seen.get_mut(&key) else {
            return Err(HarnessError::Process(
                "synthetic buffered DATA was absent from raw observations".into(),
            ));
        };
        if !*dispatched {
            *dispatched = true;
            if payload.as_slice() == self.expected_payload.as_slice() {
                self.commit_effect(payload)?;
            }
        }
        Ok(())
    }

    fn observe_terminal_frame(&self, frame: &Frame) -> Result<()> {
        let key = IngressKey {
            epoch: frame.epoch,
            generation: frame.generation,
            stream_id: frame.stream_id,
            sequence: frame.sequence,
            kind: format!("{:?}", frame.kind),
        };
        let observation = RawFrameObservation {
            epoch: frame.epoch,
            generation: frame.generation,
            stream_id: frame.stream_id,
            sequence: frame.sequence,
            kind: key.kind.clone(),
            payload_len: frame.payload.len(),
        };
        let mut raw = self.raw.lock().map_err(|_| {
            HarnessError::Process("synthetic side-effect raw observation lock poisoned".into())
        })?;
        if raw.len() >= MAX_RAW_OBSERVATIONS {
            return Err(HarnessError::Process(
                "synthetic side-effect raw observation bound exceeded".into(),
            ));
        }
        raw.push(observation);
        drop(raw);
        self.fin_observations.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn raw_snapshot(&self) -> Result<Vec<RawFrameObservation>> {
        self.raw.lock().map(|raw| raw.clone()).map_err(|_| {
            HarnessError::Process("synthetic side-effect raw observation lock poisoned".into())
        })
    }

    fn data_observations(&self) -> Result<usize> {
        self.raw
            .lock()
            .map(|raw| raw.iter().filter(|item| item.kind == "Data").count())
            .map_err(|_| {
                HarnessError::Process("synthetic side-effect raw observation lock poisoned".into())
            })
    }

    fn unique_sequences(&self) -> Result<usize> {
        self.seen
            .lock()
            .map(|seen| {
                seen.keys()
                    .filter(|key| key.kind == format!("{:?}", FrameKind::Data))
                    .count()
            })
            .map_err(|_| {
                HarnessError::Process("synthetic side-effect sequence lock poisoned".into())
            })
    }

    fn commit_effect(&self, payload: &[u8]) -> Result<()> {
        if self.append_backend {
            let body = if self.record_framed {
                payload.get(4..).ok_or_else(|| {
                    HarnessError::Http(
                        "synthetic append payload was shorter than its record header".into(),
                    )
                })?
            } else {
                payload
            };
            let mut entries = self.append_entries.lock().map_err(|_| {
                HarnessError::Process("synthetic append backend lock poisoned".into())
            })?;
            if entries.len() >= 64 {
                return Err(HarnessError::Process(
                    "synthetic append backend bound exceeded".into(),
                ));
            }
            entries.push(body.to_vec());
        }
        self.effect_invocations.fetch_add(1, Ordering::AcqRel);
        self.effect_observed.notify_waiters();
        Ok(())
    }

    pub(crate) fn append_entries(&self) -> Result<Vec<Vec<u8>>> {
        self.append_entries
            .lock()
            .map(|entries| entries.clone())
            .map_err(|_| HarnessError::Process("synthetic append backend lock poisoned".into()))
    }

    pub(crate) fn effect_count(&self) -> u64 {
        self.effect_invocations.load(Ordering::Acquire)
    }

    pub(crate) fn control_admitted(&self) -> bool {
        self.control_admitted.load(Ordering::Acquire)
    }

    pub(crate) fn owner_fenced(&self) -> bool {
        self.owner_fenced.load(Ordering::Acquire)
    }

    pub(crate) fn data_admitted(&self) -> bool {
        self.data_admitted.load(Ordering::Acquire)
    }

    pub(crate) fn operation_opened(&self) -> bool {
        self.operation_opened.load(Ordering::Acquire)
    }

    pub(crate) fn authorization_confirmed(&self) -> bool {
        self.authorization_confirmed.load(Ordering::Acquire)
    }

    pub(crate) fn record_owner_loss_close(&self) {
        self.owner_loss_close_observed
            .store(true, Ordering::Release);
    }

    pub(crate) fn owner_loss_close_observed(&self) -> bool {
        self.owner_loss_close_observed.load(Ordering::Acquire)
    }

    pub(crate) fn arm_expected_owner_loss(&self) {
        self.expected_owner_loss_armed
            .store(true, Ordering::Release);
    }

    fn expected_owner_loss_armed(&self) -> bool {
        self.expected_owner_loss_armed.load(Ordering::Acquire)
    }

    pub(crate) fn response_send_attempted(&self) -> bool {
        self.response_send_attempted.load(Ordering::Acquire)
    }

    pub(crate) fn duplicate_count(&self) -> u64 {
        self.duplicate_observations.load(Ordering::Acquire)
    }

    pub(crate) fn raw_count(&self) -> Result<usize> {
        self.raw.lock().map(|raw| raw.len()).map_err(|_| {
            HarnessError::Process("synthetic side-effect raw observation lock poisoned".into())
        })
    }

    pub(crate) fn data_count(&self) -> Result<usize> {
        self.raw
            .lock()
            .map(|raw| {
                raw.iter()
                    .filter(|observation| observation.kind == "Data")
                    .count()
            })
            .map_err(|_| {
                HarnessError::Process("synthetic side-effect raw observation lock poisoned".into())
            })
    }

    pub(crate) fn fin_count(&self) -> Result<usize> {
        self.raw
            .lock()
            .map(|raw| {
                raw.iter()
                    .filter(|observation| observation.kind == "Fin")
                    .count()
            })
            .map_err(|_| {
                HarnessError::Process("synthetic side-effect raw observation lock poisoned".into())
            })
    }

    pub(crate) fn notify_response(&self) {
        self.release_response.notify_one();
    }

    fn request_late_response(&self) {
        self.late_response_requested_flag
            .store(true, Ordering::Release);
        self.late_response_requested.notify_one();
    }

    fn complete_late_response(&self, result: LateResponseSendResult) {
        if let Ok(mut observed) = self.late_response_result.lock() {
            *observed = Some(result);
        }
        self.late_response_completed.notify_waiters();
    }

    fn complete_late_response_if_missing(&self) {
        if !self.late_response_requested_flag.load(Ordering::Acquire) {
            return;
        }
        let should_notify = self
            .late_response_result
            .lock()
            .map(|mut observed| {
                if observed.is_none() {
                    *observed = Some(LateResponseSendResult {
                        data_attempts: 0,
                        data_write_accepted: 0,
                        data_write_rejected: 0,
                        fin_attempts: 0,
                        fin_write_accepted: 0,
                        fin_write_rejected: 0,
                        data_before_fin: false,
                        write_completed: false,
                        carrier_closed: true,
                    });
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false);
        if should_notify {
            self.late_response_completed.notify_waiters();
        }
    }

    async fn wait_for_late_response(&self, deadline: Instant) -> Result<LateResponseSendResult> {
        loop {
            if let Some(result) = self
                .late_response_result
                .lock()
                .map_err(|_| {
                    HarnessError::Process("synthetic late-frame result lock poisoned".into())
                })?
                .as_ref()
                .copied()
            {
                return Ok(result);
            }
            timeout_at(deadline, self.late_response_completed.notified())
                .await
                .map_err(|_| {
                    HarnessError::Timeout(
                        "synthetic late-frame send did not reach its joined completion boundary"
                            .into(),
                    )
                })?;
        }
    }

    fn response_payload(&self) -> Result<Vec<u8>> {
        Ok(self.expected_payload.clone())
    }
}

#[cfg(test)]
mod owner_loss_causal_tests {
    use super::{
        DeviceSocket, DeviceStreamRuntime, EffectState, HarnessError, InboundSequence, Result,
        SYNTHETIC_REQUEST, StreamFrameContext, hold_and_respond,
    };
    use futures_util::StreamExt;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::protocol::Role};
    use tokio_util::sync::CancellationToken;

    async fn raw_socket_pair() -> Result<(DeviceSocket, DeviceSocket)> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| HarnessError::Process(format!("owner-loss test listener: {error}")))?;
        let address = listener.local_addr().map_err(|error| {
            HarnessError::Process(format!("owner-loss test listener address: {error}"))
        })?;
        let client = TcpStream::connect(address)
            .await
            .map_err(|error| HarnessError::Process(format!("owner-loss test client: {error}")))?;
        let (server, _) = listener
            .accept()
            .await
            .map_err(|error| HarnessError::Process(format!("owner-loss test accept: {error}")))?;
        Ok((
            WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(client), Role::Client, None)
                .await,
            WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(server), Role::Server, None)
                .await,
        ))
    }

    #[tokio::test]
    async fn armed_owner_loss_returns_after_release_without_response_write_or_data() -> Result<()> {
        let (mut control, _control_peer) = raw_socket_pair().await?;
        let (mut data, mut data_peer) = raw_socket_pair().await?;
        let state = EffectState::new(SYNTHETIC_REQUEST.to_vec());
        state.commit_effect(SYNTHETIC_REQUEST)?;
        state.arm_expected_owner_loss();
        state.record_owner_loss_close();
        state.notify_response();

        let cancel = CancellationToken::new();
        let mut inbound = InboundSequence::default();
        let mut runtime = DeviceStreamRuntime {
            control: &mut control,
            data: &mut data,
            state: &state,
            cancel: &cancel,
            context: StreamFrameContext {
                epoch: 1,
                generation: 1,
                stream_id: 1,
            },
            inbound: &mut inbound,
            allow_expected_owner_loss: true,
        };
        let result = timeout(Duration::from_secs(1), hold_and_respond(&mut runtime, 1))
            .await
            .map_err(|_| HarnessError::Timeout("owner-loss response hold did not return".into()))?;
        result?;

        assert!(state.owner_loss_close_observed());
        assert!(!state.response_send_attempted());
        assert_eq!(state.response_frames_sent.load(Ordering::Acquire), 0);
        assert!(
            timeout(Duration::from_millis(100), data_peer.next())
                .await
                .is_err(),
            "owner-loss hold emitted a WebSocket frame after the exact one-effect boundary"
        );
        Ok(())
    }
}
