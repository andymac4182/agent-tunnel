//! Bounded peer stage and cause tuples published through relay dispatch.
//!
//! Every peer fault the relay observes while dispatching a consumer request
//! to a remote owner, or while serving one as the owner, is reduced to a
//! closed `(role, stage, cause)` tuple plus the bounded identifiers needed to
//! correlate it with the owner's session: tenant, device, session, owner
//! epoch, owner node, service and request identifiers.  Transport error text,
//! peer payloads, bearer tokens, endpoints and filesystem paths never cross
//! this boundary.  The state keeps saturating counters, the latest event per
//! stage and a short ring of recent events so a fault survives the owner's
//! own state removal.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use serde::Serialize;
use tunnel_catalog::OwnerToken;
use tunnel_transport::PeerTransportError;
use uuid::Uuid;

use crate::peer_runtime::{PeerOpenDiagnostic, PeerOpenDiagnosticStage, PeerRuntimeError};

/// Maximum number of recent tuples retained in the ring.
pub const MAX_RECENT_PEER_FAULTS: usize = 32;

/// Maximum number of task closure records retained in the ring.
pub const MAX_TASK_CLOSURES: usize = 32;

/// Which relay task body reached its ordinary lifecycle end.
///
/// This is a lifecycle position, not a fault: the peer fault vocabulary above
/// names peer ingress and owner-side *failures*, and an ordinary socket close
/// is neither.  Keeping the two vocabularies apart is what stops a routine
/// close from inflating `fault_count` or a per-stage fault latch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClosureStage {
    /// The owner-local device control socket task.
    Control,
    /// The owner-local device data carrier task.
    Data,
    /// The public consumer stream adapter task.
    ConsumerStream,
}

impl TaskClosureStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
            Self::ConsumerStream => "consumer_stream",
        }
    }
}

/// Closed, payload-free causes for one task closure.
///
/// Every variant is a structural property of the socket loop's exit.  None is
/// derived from a request body, header, ticket, endpoint or error text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClosureCause {
    /// The remote endpoint closed, ended or errored its half of the socket.
    PeerClosed,
    /// A relay-to-peer write did not complete.
    WriteFailed,
    /// A bounded codec rejected an inbound frame.
    ProtocolError,
    /// An inbound frame exceeded this socket's bounded input window.
    RecordTooLarge,
    /// A message kind this socket does not serve arrived.
    UnexpectedMessage,
    /// The relay actor closed the socket, or its outbound channel ended.
    ServerClose,
    /// The owner closed the consumer stream under the adapter.
    StreamClosed,
    /// The absolute consumer authorization deadline elapsed.
    Expired,
    /// A stream write returned a typed failure or an unusable response frame.
    StreamFailed,
    /// Task row M6-C68: the device sent no frame of any kind -- not even the
    /// Pong owed to the relay's Ping -- for the device control idle timeout,
    /// so its path is presumed gone and the session is released.
    LivenessTimeout,
}

impl TaskClosureCause {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerClosed => "peer_closed",
            Self::WriteFailed => "write_failed",
            Self::ProtocolError => "protocol_error",
            Self::RecordTooLarge => "record_too_large",
            Self::UnexpectedMessage => "unexpected_message",
            Self::ServerClose => "server_close",
            Self::StreamClosed => "stream_closed",
            Self::Expired => "expired",
            Self::StreamFailed => "stream_failed",
            Self::LivenessTimeout => "liveness_timeout",
        }
    }
}

/// Bounded correlation identifiers for one task closure.
///
/// The fields are the same owner-registration identifiers
/// [`crate::runtime::OwnerUnregisterEvent`] carries, so a closure record and
/// the tombstone for the state it refers to can be matched without any
/// request-derived content passing through.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskClosureScope {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: String,
    pub epoch: u64,
    /// Present only for the consumer adapter, whose unregistered owner state
    /// is one stream inside the session rather than the session itself.
    pub stream_id: Option<u64>,
}

/// One bounded task closure tuple with its correlation identifiers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskClosureEventSnapshot {
    /// Position on the shared diagnostic clock, drawn from the same counter
    /// as peer fault tuples and owner unregister stamps.
    pub sequence: u64,
    /// Milliseconds from this relay process's monotonic diagnostic origin.
    pub observed_at_ms: u64,
    pub stage: TaskClosureStage,
    pub cause: TaskClosureCause,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: String,
    pub epoch: u64,
    pub stream_id: Option<u64>,
}

/// The relay-local side that observed the peer fault.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerFaultRole {
    /// The public ingress relay dispatching to a remote owner.
    Ingress,
    /// The owner relay serving a forwarded peer request.
    Owner,
}

impl PeerFaultRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Owner => "owner",
        }
    }
}

/// Closed, payload-free causes for one peer fault.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerFaultCause {
    /// No live owner claim exists for the scope.
    NoLiveOwner,
    /// The owner catalog could not be read.
    Catalog,
    /// Membership, checkpoint, lease or scope evidence did not authorize the
    /// request.
    Membership,
    /// The signed peer endpoint is not usable.
    InvalidEndpoint,
    /// The peer certificate or envelope identity did not match.
    IdentityMismatch,
    /// The peer transport deadline elapsed.
    TransportTimeout,
    /// The owner announced a planned drain.
    #[serde(rename = "transport_goaway")]
    TransportGoAway,
    /// The transport attempt was cancelled.
    TransportCancelled,
    /// An HTTP/3 error terminated the attempt.
    TransportH3,
    /// A QUIC error terminated the attempt.
    TransportQuic,
    /// The transport pool or permit budget was exhausted.
    TransportCapacity,
    /// This relay publishes no approved peer trust evidence, so no peer could
    /// be dialled.  Nothing was written to any owner.
    TransportPinsUnavailable,
    /// A bounded body or chunk limit was exceeded.
    TransportBodyLimit,
    /// Any other typed transport failure.
    TransportOther,
    /// The bounded envelope codec rejected the request.
    Envelope,
    /// The bounded record codec rejected a message.
    Frame,
    /// The owner rejected the request as unauthorized.
    RemoteUnauthorized,
    /// The owner rejected the request as forbidden.
    RemoteForbidden,
    /// The owner rejected the request with another bounded status.
    RemoteStatus,
    /// The internal route has no private endpoint.
    InvalidRoute,
    /// The first record was not the expected control record.
    UnexpectedRecord,
    /// The owner is committed but not ready.
    OwnerNotReady,
    /// The owner's bounded stream limit is full.
    Capacity,
    /// The peer membership admission expired.
    MembershipExpired,
    /// The peer stream was already closed.
    Closed,
    /// The relay's own operation deadline elapsed around the attempt.
    Deadline,
}

impl PeerFaultCause {
    /// Every cause, for tables that must enumerate the closed vocabulary.
    ///
    /// The C11 capture scanner keeps its own copy of these labels and refuses
    /// any snapshot carrying one outside it, so the two lists must not drift:
    /// `harness_peer_fault_causes_match_the_relay_vocabulary` in
    /// `tunnel-test-harness` compares them, and the exhaustive match in
    /// `every_cause_is_enumerated` below fails to compile if a variant is
    /// added without being listed here.
    pub const ALL: [Self; 26] = [
        Self::NoLiveOwner,
        Self::Catalog,
        Self::Membership,
        Self::InvalidEndpoint,
        Self::IdentityMismatch,
        Self::TransportTimeout,
        Self::TransportGoAway,
        Self::TransportCancelled,
        Self::TransportH3,
        Self::TransportQuic,
        Self::TransportCapacity,
        Self::TransportPinsUnavailable,
        Self::TransportBodyLimit,
        Self::TransportOther,
        Self::Envelope,
        Self::Frame,
        Self::RemoteUnauthorized,
        Self::RemoteForbidden,
        Self::RemoteStatus,
        Self::InvalidRoute,
        Self::UnexpectedRecord,
        Self::OwnerNotReady,
        Self::Capacity,
        Self::MembershipExpired,
        Self::Closed,
        Self::Deadline,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoLiveOwner => "no_live_owner",
            Self::Catalog => "catalog",
            Self::Membership => "membership",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::IdentityMismatch => "identity_mismatch",
            Self::TransportTimeout => "transport_timeout",
            Self::TransportGoAway => "transport_goaway",
            Self::TransportCancelled => "transport_cancelled",
            Self::TransportH3 => "transport_h3",
            Self::TransportQuic => "transport_quic",
            Self::TransportCapacity => "transport_capacity",
            Self::TransportPinsUnavailable => "transport_pins_unavailable",
            Self::TransportBodyLimit => "transport_body_limit",
            Self::TransportOther => "transport_other",
            Self::Envelope => "envelope",
            Self::Frame => "frame",
            Self::RemoteUnauthorized => "remote_unauthorized",
            Self::RemoteForbidden => "remote_forbidden",
            Self::RemoteStatus => "remote_status",
            Self::InvalidRoute => "invalid_route",
            Self::UnexpectedRecord => "unexpected_record",
            Self::OwnerNotReady => "owner_not_ready",
            Self::Capacity => "capacity",
            Self::MembershipExpired => "membership_expired",
            Self::Closed => "closed",
            Self::Deadline => "deadline",
        }
    }

    /// Classify a typed runtime error without retaining any of its text.
    #[must_use]
    pub fn from_error(error: &PeerRuntimeError) -> Self {
        match error {
            PeerRuntimeError::Routing(crate::routing::OwnerRoutingError::NoLiveOwner(_)) => {
                Self::NoLiveOwner
            }
            PeerRuntimeError::Routing(_) => Self::Catalog,
            PeerRuntimeError::Membership(_) => Self::Membership,
            PeerRuntimeError::InvalidEndpoint(_) => Self::InvalidEndpoint,
            PeerRuntimeError::PeerIdentityMismatch => Self::IdentityMismatch,
            PeerRuntimeError::Transport(error) => match error {
                PeerTransportError::Timeout => Self::TransportTimeout,
                PeerTransportError::GoAway => Self::TransportGoAway,
                PeerTransportError::Cancelled => Self::TransportCancelled,
                PeerTransportError::H3(_) => Self::TransportH3,
                PeerTransportError::Quic(_) => Self::TransportQuic,
                PeerTransportError::Capacity => Self::TransportCapacity,
                PeerTransportError::PinsUnavailable => Self::TransportPinsUnavailable,
                PeerTransportError::ChunkTooLarge { .. }
                | PeerTransportError::BodyTooLarge { .. } => Self::TransportBodyLimit,
                _ => Self::TransportOther,
            },
            PeerRuntimeError::Envelope(_) => Self::Envelope,
            PeerRuntimeError::Frame(_) => Self::Frame,
            PeerRuntimeError::RemoteStatus(status)
                if *status == axum::http::StatusCode::UNAUTHORIZED =>
            {
                Self::RemoteUnauthorized
            }
            PeerRuntimeError::RemoteStatus(status)
                if *status == axum::http::StatusCode::FORBIDDEN =>
            {
                Self::RemoteForbidden
            }
            PeerRuntimeError::RemoteStatus(_) => Self::RemoteStatus,
            PeerRuntimeError::InvalidRoute(_) => Self::InvalidRoute,
            PeerRuntimeError::UnexpectedRecord(_) => Self::UnexpectedRecord,
            PeerRuntimeError::OwnerNotReady { .. } => Self::OwnerNotReady,
            PeerRuntimeError::Capacity { .. } => Self::Capacity,
            PeerRuntimeError::MembershipExpired => Self::MembershipExpired,
            PeerRuntimeError::Closed => Self::Closed,
        }
    }

    /// Whether this cause is the owner's own admission decision rather than a
    /// transport or ingress-local failure.
    #[must_use]
    pub const fn is_owner_decision(self) -> bool {
        matches!(
            self,
            Self::RemoteUnauthorized
                | Self::RemoteForbidden
                | Self::RemoteStatus
                | Self::OwnerNotReady
                | Self::Capacity
        )
    }
}

/// Bounded correlation identifiers for one peer fault.
///
/// Every field is an identifier or counter; none is derived from a request
/// body, bearer token, endpoint or path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerFaultContext {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: Option<String>,
    pub owner_epoch: Option<u64>,
    pub owner_node_id: Option<String>,
    pub service_id: Option<Uuid>,
    pub request_id: Option<String>,
}

impl PeerFaultContext {
    /// Context for a fault observed before any owner was selected.
    #[must_use]
    pub fn unrouted(tenant_id: Uuid, device_id: Uuid, service_id: Option<Uuid>) -> Self {
        Self {
            tenant_id,
            device_id,
            session_id: None,
            owner_epoch: None,
            owner_node_id: None,
            service_id,
            request_id: None,
        }
    }

    /// Context for a fault against a selected owner token.
    #[must_use]
    pub fn for_owner(
        owner: &OwnerToken,
        service_id: Option<Uuid>,
        request_id: Option<String>,
    ) -> Self {
        Self {
            tenant_id: owner.tenant_id,
            device_id: owner.device_id,
            session_id: Some(owner.session_id.clone()),
            owner_epoch: Some(owner.epoch),
            owner_node_id: Some(owner.node_id.clone()),
            service_id,
            request_id,
        }
    }
}

/// One bounded peer fault tuple with its correlation identifiers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PeerFaultEventSnapshot {
    /// Saturating process-local sequence number.
    pub sequence: u64,
    /// Milliseconds from this relay process's monotonic diagnostic origin.
    pub observed_at_ms: u64,
    pub role: PeerFaultRole,
    pub stage: PeerOpenDiagnosticStage,
    pub cause: PeerFaultCause,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: Option<String>,
    pub owner_epoch: Option<u64>,
    pub owner_node_id: Option<String>,
    pub service_id: Option<Uuid>,
    pub request_id: Option<String>,
}

/// One payload-free position on the peer fault diagnostic clock.
///
/// A stamp carries a sequence number and a monotonic millisecond reading and
/// nothing else: no request, route, body, status or peer identity.  It is
/// drawn from the *same* counter and the same process origin that
/// [`PeerFaultDiagnostics::record`] uses for a fault tuple, so a stamp and a
/// tuple can be totally ordered against each other.  This is what makes the
/// EC-061 ordering clause observable from outside: the relay stamps the
/// unregister of the owner state a fault tuple refers to, and
/// `fault.sequence < unregister.sequence` proves the tuple was recorded
/// first rather than merely coexisting with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticStamp {
    /// Saturating process-local sequence number, shared with fault tuples.
    pub sequence: u64,
    /// Milliseconds from this relay process's monotonic diagnostic origin.
    pub at_ms: u64,
}

/// Redacted peer fault tuples retained by the typed relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PeerFaultDiagnosticSnapshot {
    /// Total faults observed by this relay in either role.
    pub fault_count: u64,
    /// Faults observed while this relay was the public ingress.
    pub ingress_count: u64,
    /// Faults observed while this relay was the selected owner.
    pub owner_count: u64,
    /// Saturating count per stage label.
    pub stage_counts: BTreeMap<&'static str, u64>,
    /// Saturating count per cause label.
    pub cause_counts: BTreeMap<&'static str, u64>,
    /// Latest tuple per stage label.
    pub last_by_stage: BTreeMap<&'static str, PeerFaultEventSnapshot>,
    /// The most recent tuples, oldest first, bounded by
    /// [`MAX_RECENT_PEER_FAULTS`].
    pub recent: Vec<PeerFaultEventSnapshot>,
    /// Saturating count per task closure stage label.
    pub closure_stage_counts: BTreeMap<&'static str, u64>,
    /// Saturating count per task closure cause label.
    pub closure_cause_counts: BTreeMap<&'static str, u64>,
    /// The most recent task closure tuples, oldest first, bounded by
    /// [`MAX_TASK_CLOSURES`].  These are lifecycle ends, not faults: they are
    /// kept in their own ring so a routine close never appears in
    /// `fault_count`, `cause_counts`, `last_by_stage` or `recent`.
    pub closures: Vec<TaskClosureEventSnapshot>,
}

#[derive(Default)]
struct PeerFaultDiagnosticState {
    sequence: u64,
    fault_count: u64,
    ingress_count: u64,
    owner_count: u64,
    stage_counts: BTreeMap<&'static str, u64>,
    cause_counts: BTreeMap<&'static str, u64>,
    last_by_stage: BTreeMap<&'static str, PeerFaultEventSnapshot>,
    recent: VecDeque<PeerFaultEventSnapshot>,
    closure_stage_counts: BTreeMap<&'static str, u64>,
    closure_cause_counts: BTreeMap<&'static str, u64>,
    closures: VecDeque<TaskClosureEventSnapshot>,
}

/// Cloneable bounded state for peer fault tuples.
#[derive(Clone, Default)]
pub(crate) struct PeerFaultDiagnostics {
    state: Arc<Mutex<PeerFaultDiagnosticState>>,
}

impl PeerFaultDiagnostics {
    /// Record one tuple without retaining any error text.
    pub(crate) fn record(
        &self,
        context: &PeerFaultContext,
        role: PeerFaultRole,
        stage: PeerOpenDiagnosticStage,
        cause: PeerFaultCause,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sequence = state.sequence.saturating_add(1);
        let event = PeerFaultEventSnapshot {
            sequence: state.sequence,
            observed_at_ms: diagnostic_now_ms(),
            role,
            stage,
            cause,
            tenant_id: context.tenant_id,
            device_id: context.device_id,
            session_id: context.session_id.clone(),
            owner_epoch: context.owner_epoch,
            owner_node_id: context.owner_node_id.clone(),
            service_id: context.service_id,
            request_id: context.request_id.clone(),
        };
        state.fault_count = state.fault_count.saturating_add(1);
        match role {
            PeerFaultRole::Ingress => state.ingress_count = state.ingress_count.saturating_add(1),
            PeerFaultRole::Owner => state.owner_count = state.owner_count.saturating_add(1),
        }
        let stage_count = state.stage_counts.entry(stage.as_str()).or_default();
        *stage_count = stage_count.saturating_add(1);
        let cause_count = state.cause_counts.entry(cause.as_str()).or_default();
        *cause_count = cause_count.saturating_add(1);
        state.last_by_stage.insert(stage.as_str(), event.clone());
        if state.recent.len() >= MAX_RECENT_PEER_FAULTS {
            state.recent.pop_front();
        }
        state.recent.push_back(event);
    }

    /// Record one bounded task closure tuple and return its position on the
    /// shared diagnostic clock.
    ///
    /// EC-061 requires every closure to report a bounded lifecycle stage and
    /// cause *before* the owner state it refers to is unregistered.  The
    /// sequence here is drawn from the same mutex-protected counter that
    /// [`Self::record`] and [`Self::stamp`] use, so a closure tuple and an
    /// owner unregister tombstone are totally ordered against each other by
    /// the identical predicate: `closure.sequence < unregister.sequence`
    /// proves this call released the shared mutex before the unregister's
    /// stamp acquired it, and therefore before the removal that follows that
    /// stamp in program order.
    ///
    /// A closure is not a fault.  It touches only the closure ring and the
    /// closure counters; `fault_count`, `cause_counts`, `last_by_stage` and
    /// `recent` keep their existing shape and meaning, so an ordinary
    /// lifecycle end can never be misread as a peer fault.  The call takes no
    /// session lock and performs no I/O, so it cannot change when the close
    /// it attributes actually lands.
    pub(crate) fn record_closure(
        &self,
        scope: &TaskClosureScope,
        stage: TaskClosureStage,
        cause: TaskClosureCause,
    ) -> DiagnosticStamp {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sequence = state.sequence.saturating_add(1);
        let stamp = DiagnosticStamp {
            sequence: state.sequence,
            at_ms: diagnostic_now_ms(),
        };
        let event = TaskClosureEventSnapshot {
            sequence: stamp.sequence,
            observed_at_ms: stamp.at_ms,
            stage,
            cause,
            tenant_id: scope.tenant_id,
            device_id: scope.device_id,
            session_id: scope.session_id.clone(),
            epoch: scope.epoch,
            stream_id: scope.stream_id,
        };
        let stage_count = state
            .closure_stage_counts
            .entry(stage.as_str())
            .or_default();
        *stage_count = stage_count.saturating_add(1);
        let cause_count = state
            .closure_cause_counts
            .entry(cause.as_str())
            .or_default();
        *cause_count = cause_count.saturating_add(1);
        if state.closures.len() >= MAX_TASK_CLOSURES {
            state.closures.pop_front();
        }
        state.closures.push_back(event);
        stamp
    }

    /// Draw the next position on this relay's diagnostic clock without
    /// recording a fault.
    ///
    /// The sequence comes from the same mutex-protected counter as
    /// [`Self::record`], so acquiring a stamp establishes a real happens-after
    /// relationship with every tuple that already holds a lower sequence.  The
    /// caller stamps the moment *before* it unregisters owner state, so a
    /// tuple with a lower sequence is provably recorded first.  It retains
    /// nothing and is not itself a fault: no counter, ring or per-stage latch
    /// is touched.
    #[must_use]
    pub(crate) fn stamp(&self) -> DiagnosticStamp {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sequence = state.sequence.saturating_add(1);
        DiagnosticStamp {
            sequence: state.sequence,
            at_ms: diagnostic_now_ms(),
        }
    }

    /// Return the bounded typed view used by the relay snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> PeerFaultDiagnosticSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        PeerFaultDiagnosticSnapshot {
            fault_count: state.fault_count,
            ingress_count: state.ingress_count,
            owner_count: state.owner_count,
            stage_counts: state.stage_counts.clone(),
            cause_counts: state.cause_counts.clone(),
            last_by_stage: state.last_by_stage.clone(),
            recent: state.recent.iter().cloned().collect(),
            closure_stage_counts: state.closure_stage_counts.clone(),
            closure_cause_counts: state.closure_cause_counts.clone(),
            closures: state.closures.iter().cloned().collect(),
        }
    }
}

/// A per-request observer that tracks the current peer stage and records at
/// most one fault tuple for that request.
///
/// It wraps the transport-aware [`PeerOpenDiagnostic`] so the stage reached
/// inside pooled HTTP/3 admission is reported exactly, and extends it with
/// the head, body, lease and owner stages the dispatch and owner paths mark
/// themselves.  Recording is idempotent: a fault classified deep inside a
/// handler is not overwritten by the outer error mapping.
pub struct PeerFaultObserver {
    diagnostic: PeerOpenDiagnostic,
    context: PeerFaultContext,
    role: PeerFaultRole,
    recorded: AtomicBool,
}

impl PeerFaultObserver {
    #[must_use]
    pub fn new(role: PeerFaultRole, context: PeerFaultContext) -> Self {
        Self {
            diagnostic: PeerOpenDiagnostic::new(),
            context,
            role,
            recorded: AtomicBool::new(false),
        }
    }

    /// The transport-aware open observer for this request.
    #[must_use]
    pub fn diagnostic(&self) -> &PeerOpenDiagnostic {
        &self.diagnostic
    }

    /// Replace the correlation context once an owner has been selected.
    pub fn set_context(&mut self, context: PeerFaultContext) {
        self.context = context;
    }

    #[must_use]
    pub fn context(&self) -> &PeerFaultContext {
        &self.context
    }

    /// Mark the stage this request has reached.
    pub fn mark(&self, stage: PeerOpenDiagnosticStage) {
        self.diagnostic.mark(stage);
    }

    /// The last stage reached by this request.
    #[must_use]
    pub fn stage(&self) -> PeerOpenDiagnosticStage {
        self.diagnostic.stage()
    }

    /// Whether a tuple has already been recorded for this request.
    #[must_use]
    pub fn recorded(&self) -> bool {
        self.recorded.load(Ordering::Acquire)
    }

    /// Record the tuple for a typed error at the current stage, once.
    ///
    /// An owner admission decision observed while the ingress was waiting for
    /// the response head is attributed to the `owner` stage: the transport
    /// completed and the owner itself refused the request.
    pub(crate) fn record_error(
        &self,
        diagnostics: &PeerFaultDiagnostics,
        error: &PeerRuntimeError,
    ) {
        let cause = PeerFaultCause::from_error(error);
        let stage = match self.stage() {
            PeerOpenDiagnosticStage::Head if cause.is_owner_decision() => {
                PeerOpenDiagnosticStage::Owner
            }
            stage => stage,
        };
        self.record_tuple(diagnostics, stage, cause);
    }

    /// Record an explicit tuple at a caller-selected stage, once.
    pub(crate) fn record_tuple(
        &self,
        diagnostics: &PeerFaultDiagnostics,
        stage: PeerOpenDiagnosticStage,
        cause: PeerFaultCause,
    ) {
        if self
            .recorded
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        diagnostics.record(&self.context, self.role, stage, cause);
    }
}

static DIAGNOSTIC_ORIGIN: OnceLock<Instant> = OnceLock::new();

fn diagnostic_now_ms() -> u64 {
    DIAGNOSTIC_ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    /// Adding a `PeerFaultCause` variant must also add it to
    /// [`PeerFaultCause::ALL`] and to the C11 scanner's copy of the
    /// vocabulary in `tunnel-test-harness`; otherwise a relay snapshot
    /// carrying the new cause is rejected as outside the closed vocabulary
    /// and `verify-m7-c11-diagnostics` fails at capture time rather than at
    /// compile time.  The exhaustive match below is the compile-time half.
    #[test]
    fn every_cause_is_enumerated() {
        use super::PeerFaultCause;
        for cause in PeerFaultCause::ALL {
            match cause {
                PeerFaultCause::NoLiveOwner
                | PeerFaultCause::Catalog
                | PeerFaultCause::Membership
                | PeerFaultCause::InvalidEndpoint
                | PeerFaultCause::IdentityMismatch
                | PeerFaultCause::TransportTimeout
                | PeerFaultCause::TransportGoAway
                | PeerFaultCause::TransportCancelled
                | PeerFaultCause::TransportH3
                | PeerFaultCause::TransportQuic
                | PeerFaultCause::TransportCapacity
                | PeerFaultCause::TransportPinsUnavailable
                | PeerFaultCause::TransportBodyLimit
                | PeerFaultCause::TransportOther
                | PeerFaultCause::Envelope
                | PeerFaultCause::Frame
                | PeerFaultCause::RemoteUnauthorized
                | PeerFaultCause::RemoteForbidden
                | PeerFaultCause::RemoteStatus
                | PeerFaultCause::InvalidRoute
                | PeerFaultCause::UnexpectedRecord
                | PeerFaultCause::OwnerNotReady
                | PeerFaultCause::Capacity
                | PeerFaultCause::MembershipExpired
                | PeerFaultCause::Closed
                | PeerFaultCause::Deadline => {}
            }
        }
        let mut labels: Vec<&str> = PeerFaultCause::ALL.iter().map(|c| c.as_str()).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total, "cause labels must be distinct");
    }

    use super::*;
    use crate::routing::OwnerRoutingError;
    use crate::routing::OwnerScope;

    fn owner() -> OwnerToken {
        OwnerToken {
            deployment_incarnation: "incarnation-1".to_owned(),
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            session_id: "session-7".to_owned(),
            epoch: 9,
            node_id: "relay-b".to_owned(),
            boot_id: "boot-1".to_owned(),
        }
    }

    #[test]
    fn every_runtime_error_maps_to_a_closed_cause_without_text() {
        let secret = "secret-endpoint-text";
        let cases: Vec<(PeerRuntimeError, PeerFaultCause)> = vec![
            (
                PeerRuntimeError::Routing(OwnerRoutingError::NoLiveOwner(OwnerScope::new(
                    Uuid::nil(),
                    Uuid::nil(),
                ))),
                PeerFaultCause::NoLiveOwner,
            ),
            (
                PeerRuntimeError::Membership(secret.to_owned()),
                PeerFaultCause::Membership,
            ),
            (
                PeerRuntimeError::InvalidEndpoint(secret.to_owned()),
                PeerFaultCause::InvalidEndpoint,
            ),
            (
                PeerRuntimeError::PeerIdentityMismatch,
                PeerFaultCause::IdentityMismatch,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::Timeout),
                PeerFaultCause::TransportTimeout,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::GoAway),
                PeerFaultCause::TransportGoAway,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::Cancelled),
                PeerFaultCause::TransportCancelled,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::H3(secret.to_owned())),
                PeerFaultCause::TransportH3,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::Quic(secret.to_owned())),
                PeerFaultCause::TransportQuic,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::Capacity),
                PeerFaultCause::TransportCapacity,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::BodyTooLarge {
                    observed: 2,
                    maximum: 1,
                }),
                PeerFaultCause::TransportBodyLimit,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::PolicyRejected),
                PeerFaultCause::TransportOther,
            ),
            (
                PeerRuntimeError::RemoteStatus(axum::http::StatusCode::UNAUTHORIZED),
                PeerFaultCause::RemoteUnauthorized,
            ),
            (
                PeerRuntimeError::RemoteStatus(axum::http::StatusCode::FORBIDDEN),
                PeerFaultCause::RemoteForbidden,
            ),
            (
                PeerRuntimeError::RemoteStatus(axum::http::StatusCode::BAD_GATEWAY),
                PeerFaultCause::RemoteStatus,
            ),
            (
                PeerRuntimeError::OwnerNotReady { retry_after_ms: 1 },
                PeerFaultCause::OwnerNotReady,
            ),
            (
                PeerRuntimeError::Capacity { retry_after_ms: 1 },
                PeerFaultCause::Capacity,
            ),
            (
                PeerRuntimeError::MembershipExpired,
                PeerFaultCause::MembershipExpired,
            ),
            (PeerRuntimeError::Closed, PeerFaultCause::Closed),
        ];
        for (error, expected) in cases {
            let cause = PeerFaultCause::from_error(&error);
            assert_eq!(cause, expected, "{error}");
            let label = serde_json::to_string(&cause).expect("cause serializes");
            assert_eq!(label, format!("\"{}\"", cause.as_str()));
            assert!(!label.contains(secret));
        }
    }

    #[test]
    fn stage_and_cause_json_labels_match_their_closed_vocabulary() {
        for stage in PeerOpenDiagnosticStage::ALL {
            let label = serde_json::to_string(&stage).expect("stage serializes");
            assert_eq!(label, format!("\"{}\"", stage.as_str()));
        }
        let stages: Vec<&str> = PeerOpenDiagnosticStage::ALL
            .iter()
            .map(|stage| stage.as_str())
            .collect();
        assert_eq!(
            stages,
            [
                "validation",
                "pool_connect",
                "stream_permit_checkout",
                "sender_lock",
                "h3_dispatch",
                "envelope_send",
                "complete",
                "head",
                "body",
                "lease",
                "owner",
            ]
        );
    }

    #[test]
    fn observer_records_once_at_the_reached_stage_with_bounded_identity() {
        let diagnostics = PeerFaultDiagnostics::default();
        let observer = PeerFaultObserver::new(
            PeerFaultRole::Ingress,
            PeerFaultContext::for_owner(
                &owner(),
                Some(Uuid::from_u128(3)),
                Some("request-11".to_owned()),
            ),
        );
        observer.mark(PeerOpenDiagnosticStage::Lease);
        observer.record_error(
            &diagnostics,
            &PeerRuntimeError::OwnerNotReady { retry_after_ms: 5 },
        );
        // A second classification for the same request is ignored.
        observer.record_error(&diagnostics, &PeerRuntimeError::Closed);
        assert!(observer.recorded());

        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.fault_count, 1);
        assert_eq!(snapshot.ingress_count, 1);
        assert_eq!(snapshot.owner_count, 0);
        assert_eq!(snapshot.stage_counts.get("lease"), Some(&1));
        assert_eq!(snapshot.cause_counts.get("owner_not_ready"), Some(&1));
        let event = snapshot
            .last_by_stage
            .get("lease")
            .expect("lease tuple retained");
        assert_eq!(event.sequence, 1);
        assert_eq!(event.role, PeerFaultRole::Ingress);
        assert_eq!(event.stage, PeerOpenDiagnosticStage::Lease);
        assert_eq!(event.cause, PeerFaultCause::OwnerNotReady);
        assert_eq!(event.tenant_id, Uuid::from_u128(1));
        assert_eq!(event.device_id, Uuid::from_u128(2));
        assert_eq!(event.session_id.as_deref(), Some("session-7"));
        assert_eq!(event.owner_epoch, Some(9));
        assert_eq!(event.owner_node_id.as_deref(), Some("relay-b"));
        assert_eq!(event.service_id, Some(Uuid::from_u128(3)));
        assert_eq!(event.request_id.as_deref(), Some("request-11"));
        assert_eq!(snapshot.recent, vec![event.clone()]);
    }

    #[test]
    fn head_stage_owner_decisions_are_attributed_to_the_owner_stage() {
        let diagnostics = PeerFaultDiagnostics::default();
        let observer = PeerFaultObserver::new(
            PeerFaultRole::Ingress,
            PeerFaultContext::unrouted(Uuid::from_u128(1), Uuid::from_u128(2), None),
        );
        observer.mark(PeerOpenDiagnosticStage::Head);
        observer.record_error(
            &diagnostics,
            &PeerRuntimeError::RemoteStatus(axum::http::StatusCode::UNAUTHORIZED),
        );
        let snapshot = diagnostics.snapshot();
        let event = snapshot
            .last_by_stage
            .get("owner")
            .expect("owner tuple retained");
        assert_eq!(event.cause, PeerFaultCause::RemoteUnauthorized);
        assert_eq!(event.session_id, None);
        assert_eq!(event.owner_epoch, None);

        let transport = PeerFaultObserver::new(
            PeerFaultRole::Ingress,
            PeerFaultContext::unrouted(Uuid::from_u128(1), Uuid::from_u128(2), None),
        );
        transport.mark(PeerOpenDiagnosticStage::Head);
        transport.record_error(
            &diagnostics,
            &PeerRuntimeError::Transport(PeerTransportError::GoAway),
        );
        let snapshot = diagnostics.snapshot();
        assert_eq!(
            snapshot.last_by_stage.get("head").map(|event| event.cause),
            Some(PeerFaultCause::TransportGoAway)
        );
    }

    #[test]
    fn stamps_and_fault_tuples_share_one_sequence_and_one_clock() {
        let diagnostics = PeerFaultDiagnostics::default();
        let context = PeerFaultContext::unrouted(Uuid::from_u128(1), Uuid::from_u128(2), None);
        diagnostics.record(
            &context,
            PeerFaultRole::Owner,
            PeerOpenDiagnosticStage::Body,
            PeerFaultCause::Closed,
        );
        let first = diagnostics.stamp();
        diagnostics.record(
            &context,
            PeerFaultRole::Owner,
            PeerOpenDiagnosticStage::Head,
            PeerFaultCause::Closed,
        );
        let second = diagnostics.stamp();

        let snapshot = diagnostics.snapshot();
        let before = snapshot
            .last_by_stage
            .get("body")
            .expect("first tuple retained");
        let after = snapshot
            .last_by_stage
            .get("head")
            .expect("second tuple retained");
        // One counter, interleaved: a stamp is comparable with a tuple.
        assert_eq!(
            (
                before.sequence,
                first.sequence,
                after.sequence,
                second.sequence
            ),
            (1, 2, 3, 4)
        );
        assert!(before.observed_at_ms <= first.at_ms);
        assert!(first.at_ms <= after.observed_at_ms);
        assert!(after.observed_at_ms <= second.at_ms);
        // A stamp is not a fault: only the two records are counted.
        assert_eq!(snapshot.fault_count, 2);
        assert_eq!(snapshot.recent.len(), 2);
    }

    #[test]
    fn recent_ring_and_counters_stay_bounded() {
        let diagnostics = PeerFaultDiagnostics::default();
        let context = PeerFaultContext::unrouted(Uuid::from_u128(1), Uuid::from_u128(2), None);
        for _ in 0..(MAX_RECENT_PEER_FAULTS + 5) {
            diagnostics.record(
                &context,
                PeerFaultRole::Owner,
                PeerOpenDiagnosticStage::Body,
                PeerFaultCause::Closed,
            );
        }
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.recent.len(), MAX_RECENT_PEER_FAULTS);
        assert_eq!(snapshot.fault_count, (MAX_RECENT_PEER_FAULTS + 5) as u64);
        assert_eq!(snapshot.owner_count, (MAX_RECENT_PEER_FAULTS + 5) as u64);
        assert_eq!(snapshot.recent.first().map(|event| event.sequence), Some(6));
        assert_eq!(snapshot.last_by_stage.len(), 1);
        let json = serde_json::to_string(&snapshot).expect("snapshot serializes");
        assert!(json.contains("\"stage\":\"body\""));
        assert!(json.contains("\"cause\":\"closed\""));
        assert!(json.contains("\"role\":\"owner\""));
    }
}
