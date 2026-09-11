//! Bounded cluster policy and transport contracts.
//!
//! Redis remains the catalog and coordination authority. Membership trust is
//! verified against operator-provisioned keys, never bootstrapped from Redis.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod error;
pub mod membership;
pub mod peer_frame;
/// Recovery approval verification is owned by the authoritative catalog
/// crate so the catalog can gate Redis activation without a dependency cycle.
pub mod recovery {
    pub use tunnel_catalog::recovery::*;
}
