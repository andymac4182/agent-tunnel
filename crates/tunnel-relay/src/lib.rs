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
mod config;
mod consumer_write_diagnostics;
mod health;
mod http;
pub mod membership_runtime;
pub mod membership_version_state;
mod peer_consumer_transport_diagnostics;
pub mod peer_runtime;
mod peer_transport_diagnostics;
pub mod recovery;
pub mod redis_connection;
pub mod routing;
mod runtime;
mod wire;

pub use actor::{
    ListenerSocketOptions, PeerListenerConfig, Relay, RelayError, RelayHandle, RunningRelay,
};
pub use config::{
    ClusterConfig, PrivateEndpointPolicyConfig, RecoveryConfig, RelayLimits, RelayOptions,
    ServeConfig,
};
pub use consumer_write_diagnostics::{
    ConsumerIngressKind, ConsumerWriteDiagnosticSnapshot, ConsumerWriteScope,
    ConsumerWriteTimeoutSnapshot,
};
pub use http::{
    ConsumerUpgradeBarrier, PeerAdmissionBarrier, PeerAdmissionScope, consumer_router,
    device_router, peer_ingress_handler, router, router_with_peer,
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
pub use peer_runtime::peer_readiness::{
    PeerListenerState, PeerProbeState, PeerReadiness, PeerReadinessError, PeerReadinessSnapshot,
    PeerRouteReadiness, PeerRouteTarget,
};
pub use peer_runtime::{
    InboundPeerRequest, PeerBindingProvider, PeerIngressHandler, PeerRuntime, PeerRuntimeError,
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
    RelayCarrierSnapshot, RelayRotationSnapshot, RelaySessionSnapshot, RelaySnapshot,
    RelayStreamSnapshot, RotationDeadlineEvent, StreamTerminalCause, StreamTerminalEvent,
    StreamTerminalReceiptEvent,
};
pub use wire::{MAX_BODY_BYTES, MAX_CONTROL_BYTES};

/// Protocol major supported by this relay.
pub const PROTOCOL_MAJOR: u8 = 1;
/// The one M1 application export.  Later adapters add their own negotiated
/// feature names; the relay never accepts an executable or URL from a peer.
pub const ECHO_SERVICE_TYPE: &str = "echo";
/// The fixed operation name used by the echo grant.
pub const ECHO_OPERATION: &str = "echo:invoke";
