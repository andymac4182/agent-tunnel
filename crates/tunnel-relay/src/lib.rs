//! The M1 relay runtime.
//!
//! The relay owns one bounded actor for all live device sessions.  Axum
//! handlers authenticate and validate requests, then send typed commands to
//! that actor; handlers never mutate socket or epoch state themselves.  The
//! device listener is intended to be run through `tunnel-transport`, which
//! performs mandatory mTLS and injects the verified [`tunnel_transport::TlsIdentity`]
//! extension before the WebSocket upgrade.

#![deny(unsafe_code)]

mod actor;
mod authority_readiness;
pub mod catalog_changes;
mod config;
mod consumer_framing;
mod consumer_write_diagnostics;
mod file_identity;
mod health;
mod http;
pub mod http_forward_diagnostics;
pub mod membership_runtime;
pub mod membership_version_state;
mod metrics;
mod peer_consumer_transport_diagnostics;
pub mod peer_fault_diagnostics;
pub mod peer_runtime;
mod peer_transport_diagnostics;
pub mod provisioning;
pub mod recovery;
pub mod redis_connection;
pub mod routing;
mod runtime;
mod wire;

pub use actor::{
    ListenerSocketOptions, PeerListenerConfig, Relay, RelayError, RelayHandle, RunningRelay,
};
pub use config::{
    ClusterConfig, DEFAULT_MAX_PENDING_OPERATIONS_PER_OWNER, HttpForwardServeConfig,
    MAX_PENDING_OPERATIONS_PER_OWNER_CEILING, PrivateEndpointPolicyConfig, RecoveryConfig,
    RelayLimits, RelayOptions, ServeConfig,
};
pub use consumer_write_diagnostics::{
    ConsumerIngressKind, ConsumerWriteDiagnosticSnapshot, ConsumerWriteScope,
    ConsumerWriteTimeoutSnapshot,
};
pub use http::forward::{
    HOP_AGGREGATE_BYTES, HTTP_FORWARD_PROFILE_CAPABILITY, HttpForwardExport, HttpForwardExports,
    HttpRelayHoldPoint, HttpRelayInterposer, MAX_PROFILE_ID_LEN, PEER_HOP_WINDOW_BYTES,
    PEER_HOP_WINDOW_RECORDS,
};
pub use http::{
    ConsumerUpgradeBarrier, ControlAttachBarrier, PeerAdmissionBarrier, PeerAdmissionScope,
    consumer_router, device_router, device_router_with_peer_and_barrier, peer_ingress_handler,
    peer_ingress_handler_with_http_forward, router, router_with_peer,
};
pub use membership_runtime::{
    AdmissionDeadline, CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest,
    CheckpointResponse, HttpsCheckpointAuthority, MAX_MEMBERSHIP_PERSISTENCE_TIMEOUT,
    MembershipReadiness, MembershipRecordSource, MembershipRuntime, MembershipRuntimeConfig,
    MembershipRuntimeError, MembershipRuntimeHandle, MembershipSnapshot, MembershipUnreadyReason,
    PeerAdmission, PeerIdentity as MembershipPeerIdentity, PeerInvalidationReason,
};
pub use membership_version_state::{
    MembershipVersionStateIdentity, MembershipVersionStateStore, MembershipVersionStateStoreError,
};
pub use peer_consumer_transport_diagnostics::{
    PeerConsumerDiagnosticEventSnapshot, PeerConsumerDiagnosticH3Code, PeerConsumerDiagnosticRole,
    PeerConsumerDiagnosticSnapshot,
};
pub use peer_fault_diagnostics::{
    DiagnosticStamp, MAX_RECENT_PEER_FAULTS, MAX_TASK_CLOSURES, PeerFaultCause, PeerFaultContext,
    PeerFaultDiagnosticSnapshot, PeerFaultEventSnapshot, PeerFaultObserver, PeerFaultRole,
    TaskClosureCause, TaskClosureEventSnapshot, TaskClosureScope, TaskClosureStage,
};
pub use peer_runtime::peer_readiness::{
    PeerListenerState, PeerProbeState, PeerReadiness, PeerReadinessError, PeerReadinessSnapshot,
    PeerRouteReadiness, PeerRouteTarget,
};
pub use peer_runtime::{
    InboundPeerRequest, PeerBindingProvider, PeerIngressHandler, PeerOpenDiagnosticStage,
    PeerRuntime, PeerRuntimeError,
};
pub use peer_transport_diagnostics::{
    PeerTransportDiagnosticEventSnapshot, PeerTransportDiagnosticOutcome,
    PeerTransportDiagnosticRole, PeerTransportDiagnosticSnapshot,
};
pub use recovery::{
    QuiescenceAcknowledgement, QuiescenceStatus, RecoverRequest, RecoveryObservation,
    RecoveryOutcome, RecoveryWorkflowConfig, RecoveryWorkflowError,
};
pub use runtime::{
    OwnerUnregisterEvent, OwnerUnregisterKind, RelayCarrierSnapshot, RelayRotationSnapshot,
    RelaySessionSnapshot, RelaySnapshot, RelayStreamSnapshot, RotationDeadlineEvent,
    StreamTerminalCause, StreamTerminalEvent, StreamTerminalReceiptEvent, recovery_reason_name,
};
pub use wire::{MAX_BODY_BYTES, MAX_CONTROL_BYTES};

/// Protocol major supported by this relay.
pub const PROTOCOL_MAJOR: u8 = 1;
/// The one M1 application export.  Later adapters add their own negotiated
/// feature names; the relay never accepts an executable or URL from a peer.
pub const ECHO_SERVICE_TYPE: &str = "echo";
/// The fixed operation name used by the echo grant.
pub const ECHO_OPERATION: &str = "echo:invoke";
/// The catalog service type of an `http-forward/1` export.
pub const HTTP_FORWARD_SERVICE_TYPE: &str = "http-forward";
/// The grant operation (and consumer token scope) for an `http-forward/1`
/// export.
pub const HTTP_FORWARD_OPERATION: &str = "http:invoke";
/// The catalog service type of a filesystem export.
pub const FS_SERVICE_TYPE: &str = "fs";
/// The grant operation and consumer token scope that admit a filesystem
/// session at all.
///
/// Deliberately **not** one of the four capabilities. A scope is one name, and
/// the contract's model is that every capability a session holds was named
/// individually: a session-admitting scope that also meant `read` would make a
/// `list`-without-`read` grant unable to open a session, which is one of the
/// grant shapes the contract requires to work.
pub const FS_SESSION_OPERATION: &str = "fs:connect";
/// The grant operation naming the `read` capability.
pub const FS_READ_OPERATION: &str = "fs:read";
/// The grant operation naming the `write` capability. Gate 5 is where it
/// becomes usable; the name is pinned here so a grant seeded for it cannot mean
/// something else later.
pub const FS_WRITE_OPERATION: &str = "fs:write";
/// The grant operation naming the `list` capability.
pub const FS_LIST_OPERATION: &str = "fs:list";
/// The grant operation naming the `delete` capability. Gate 5's.
pub const FS_DELETE_OPERATION: &str = "fs:delete";
/// The service capability naming the export's observed case behaviour.
///
/// Required on a filesystem service record. The contract says the provider
/// **reports** the host's case behaviour and never assumes it, so a relay that
/// had to guess would be inventing it; an export without this capability is one
/// this relay does not serve, and discovery answers 404 for it exactly as it
/// does for an `http-forward` service naming no profile.
pub const FS_CASE_SENSITIVITY_CAPABILITY: &str = "fs_case_sensitivity";
/// The service capability by which a device declares that its host cannot serve
/// filesystem exports at all.
///
/// `false` answers `403 ACCESS_DENIED`. Gate 2 declares filesystem exports
/// unsupported on Windows, in one function, so that discovery can answer 403
/// for such a host; this is how that declaration reaches the relay, which does
/// not know the device's operating system.
pub const FS_HOST_SUPPORTED_CAPABILITY: &str = "fs_host_supported";
