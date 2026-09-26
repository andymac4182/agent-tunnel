//! Shared transport primitives for the Agent Tunnel relay and connector.
//!
//! The crate deliberately stops at transport boundaries.  It does not assign
//! tenants, consume attachment tickets, or make routing decisions.  TLS
//! verification produces a typed [`TlsIdentity`]; the caller still has to
//! look that identity up in its durable credential catalogue before admitting
//! a control/data connection.

#![deny(missing_docs)]

pub mod log_limit;
mod peer;
mod peer_identity;
mod peer_probe;
mod server;
mod tls;

pub use peer::{
    DEFAULT_PEER_BODY_CHUNK_BYTES, DEFAULT_PEER_CONNECTION_BODY_BYTES, DEFAULT_PEER_CONNECTIONS,
    DEFAULT_PEER_DESTINATIONS, DEFAULT_PEER_HANDSHAKE_TIMEOUT, DEFAULT_PEER_HEADER_BYTES,
    DEFAULT_PEER_STREAM_BODY_BYTES, DEFAULT_PEER_STREAM_TIMEOUT,
    DEFAULT_PEER_STREAMS_PER_CONNECTION, LOCAL_IDENTITY_RETIRED_CODE,
    LOCAL_IDENTITY_RETIRED_REASON, MAX_DYNAMIC_PEER_PINS, MAX_ROTATION_DRAINING_CONNECTIONS,
    PeerBodyChunk, PeerClient, PeerClientRecv, PeerClientSend, PeerClientStream,
    PeerConnectionHandle, PeerDestination, PeerHandlerFuture, PeerOpenProgress, PeerPinSnapshot,
    PeerPolicyRejected, PeerPoolConnectionStats, PeerPoolStats, PeerRequestHandler,
    PeerRequestPolicy, PeerServer, PeerServerConnectionStats, PeerServerDiagnostics,
    PeerServerRecv, PeerServerSend, PeerServerStats, PeerServerStream, PeerTransportError,
    PeerTransportLimits, PeerTransportOpenStage, SharedPeerPins, serve_peer,
};
pub use peer_identity::{PeerIdentityError, RotatingPeerIdentity, StagedPeerIdentity};
pub use peer_probe::{
    ApprovedPeerPins, PeerProbeError, PeerProbeLimits, PeerProbeResponse, peer_probe,
    serve_peer_probe,
};
pub use server::{
    ACCEPT_ERROR_BACKOFF, AcceptedSocketDiagnostics, AcceptedSocketOptions, CONNECTION_LIMIT_BODY,
    CONNECTION_LIMIT_RETRY_AFTER_MS, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_HTTP1_HEADER_READ_TIMEOUT,
    DEFAULT_MAX_CONCURRENT_HANDSHAKES, DEFAULT_MAX_HTTP1_HEADERS,
    DEFAULT_MAX_HTTP2_HEADER_LIST_BYTES, DEFAULT_MAX_HTTP2_STREAMS, DEFAULT_PRE_REQUEST_TIMEOUT,
    DEFAULT_REFUSAL_MARGIN, DEFAULT_REFUSAL_TIMEOUT, ListenerCapacity, ListenerTimeouts,
    MAX_LISTENER_CONNECTIONS, MAX_REFUSAL_BODY_BYTES, MAX_REFUSAL_MARGIN, TransportError,
    log_tls_refusal, serve, serve_with_listener_options, serve_with_socket_options,
    transient_accept_error,
};
pub use tls::{
    CertificateRole, ClientTlsConfigError, ProviderAlreadyInstalled, SanName, SpkiSha256,
    TlsConfigError, TlsIdentity, TlsIdentityError, install_process_crypto_provider,
    leaf_identity_from_der, load_client_config_from_pem, load_client_config_from_pem_with_alpn,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, load_quinn_client_config,
    load_quinn_server_config, load_server_config_from_pem, load_server_config_from_pem_with_alpn,
    process_provider_is_ring, require_client_ca, require_root_certificates, spki_sha256_from_der,
};
