//! Pure, bounded M7 coordination helpers.
//!
//! This module deliberately has no dependency on the future `tunnel-cluster`
//! crate.  It owns the catalog-side wire/schema limits and the opaque ticket
//! digest helper; signature verification of membership bytes belongs to that
//! higher-level cluster crate.

use crate::{
    CatalogError,
    memory::valid_fingerprint,
    types::{AttachmentTicketBinding, AttachmentTicketIssueRequest, MAX_SIGNED_MEMBERSHIP_BYTES},
};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const MAX_TICKET_LIFETIME: Duration = Duration::seconds(30);
pub(crate) const MAX_TICKET_FIELD_BYTES: usize = 128;
pub(crate) const MAX_TICKET_PURPOSE_BYTES: usize = 64;
pub(crate) const MAX_TICKET_TOKEN_BYTES: usize = 256;
pub(crate) const MEMBERSHIP_TTL_SECONDS: usize = 60;

pub(crate) fn validate_ticket_issue(
    request: &AttachmentTicketIssueRequest,
    configured_incarnation: &str,
    now: DateTime<Utc>,
) -> Result<(), CatalogError> {
    validate_binding(
        &request.binding(),
        configured_incarnation,
        request.tenant_id,
        request.device_id,
    )?;
    if request.expires_at <= now || request.expires_at - now > MAX_TICKET_LIFETIME {
        return Err(CatalogError::InvalidInput("attachment ticket expiry"));
    }
    Ok(())
}

pub(crate) fn validate_ticket_consume(
    binding: &AttachmentTicketBinding,
    configured_incarnation: &str,
    ticket: &str,
) -> Result<(), CatalogError> {
    validate_binding(
        binding,
        configured_incarnation,
        binding.tenant_id,
        binding.device_id,
    )?;
    if ticket.len() > MAX_TICKET_TOKEN_BYTES
        || ticket.len() < 64
        || !ticket.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CatalogError::InvalidInput("attachment ticket"));
    }
    Ok(())
}

pub(crate) fn validate_binding(
    binding: &AttachmentTicketBinding,
    configured_incarnation: &str,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<(), CatalogError> {
    if binding.tenant_id != tenant_id
        || binding.device_id != device_id
        || binding.owner.tenant_id != tenant_id
        || binding.owner.device_id != device_id
        || binding.owner.deployment_incarnation != configured_incarnation
    {
        return Err(CatalogError::InvalidOwner);
    }
    if !valid_fingerprint(&binding.spki_fingerprint) {
        return Err(CatalogError::InvalidInput("attachment SPKI fingerprint"));
    }
    validate_identifier(&binding.owner.node_id, MAX_TICKET_FIELD_BYTES)?;
    validate_identifier(&binding.owner.boot_id, MAX_TICKET_FIELD_BYTES)?;
    validate_identifier(&binding.owner.session_id, MAX_TICKET_FIELD_BYTES)?;
    validate_identifier(
        &binding.owner.deployment_incarnation,
        MAX_TICKET_FIELD_BYTES,
    )?;
    validate_identifier(&binding.connection_id, MAX_TICKET_FIELD_BYTES)?;
    validate_identifier(&binding.purpose, MAX_TICKET_PURPOSE_BYTES)?;
    validate_identifier(&binding.binding_digest, MAX_TICKET_FIELD_BYTES)?;
    if binding.owner.epoch == 0 {
        return Err(CatalogError::InvalidOwner);
    }
    Ok(())
}

pub(crate) fn validate_membership_bytes(bytes: &[u8]) -> Result<(), CatalogError> {
    if bytes.is_empty() || bytes.len() > MAX_SIGNED_MEMBERSHIP_BYTES {
        return Err(CatalogError::InvalidInput("signed membership size"));
    }
    Ok(())
}

pub(crate) fn validate_identifier(value: &str, max_bytes: usize) -> Result<(), CatalogError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(CatalogError::InvalidInput("cluster identifier"));
    }
    Ok(())
}

/// Generate a 32-byte opaque ticket from two UUID v4 values (244 random bits).
/// UUID v4 uses the operating system random
/// source through the already pinned `uuid` dependency; no ticket bytes are
/// sent to Redis.
pub(crate) fn generate_ticket() -> String {
    let mut bytes = [0_u8; 32];
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    bytes[..16].copy_from_slice(first.as_bytes());
    bytes[16..].copy_from_slice(second.as_bytes());
    hex_encode(&bytes)
}

pub(crate) fn ticket_digest(ticket: &str) -> String {
    let digest = Sha256::digest(ticket.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::ticket_digest;

    #[test]
    fn sha256_matches_standard_empty_vector() {
        assert_eq!(
            ticket_digest(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_matches_standard_abc_vector() {
        assert_eq!(
            ticket_digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
