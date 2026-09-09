//! Shared transport primitives for the Agent Tunnel relay and connector.
//!
//! The crate deliberately stops at transport boundaries.  It does not assign
//! tenants, consume attachment tickets, or make routing decisions.  TLS
//! verification produces a typed [`TlsIdentity`]; the caller still has to
//! look that identity up in its durable credential catalogue before admitting
//! a control/data connection.

#![deny(missing_docs)]

mod peer_probe;
mod server;
mod tls;

pub use peer_probe::{
    ApprovedPeerPins, PeerProbeError, PeerProbeLimits, PeerProbeResponse, peer_probe,
    serve_peer_probe,
};
pub use server::{
    DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_CONCURRENT_HANDSHAKES, DEFAULT_MAX_HTTP1_HEADERS,
    DEFAULT_MAX_HTTP2_HEADER_LIST_BYTES, DEFAULT_MAX_HTTP2_STREAMS, TransportError, serve,
};
pub use tls::{
    CertificateRole, ClientTlsConfigError, SanName, SpkiSha256, TlsConfigError, TlsIdentity,
    TlsIdentityError, load_client_config_from_pem, load_client_config_from_pem_with_alpn,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, load_quinn_client_config,
    load_quinn_server_config, load_server_config_from_pem, load_server_config_from_pem_with_alpn,
    require_client_ca, require_root_certificates, spki_sha256_from_der,
};
