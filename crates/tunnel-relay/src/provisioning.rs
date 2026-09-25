//! Operator bootstrap of one relay's Redis authority (task row M6-C21).
//!
//! Before this module, nothing shipped could create the records a relay
//! authorizes against -- tenant, user and issuer identity, membership, device,
//! device credential, service and grant -- or activate the first deployment
//! incarnation `serve` requires.  Only the test harness could, through
//! `Catalog::seed_fixture` (refused outside `test-`/`fixture-` namespaces) and
//! `RedisCatalog::activate_deployment_incarnation` (which will also *replace*
//! an incarnation, a recovery transition).
//!
//! Two `tunnel-relay` subcommands sit on this module:
//!
//! * `activate-first-incarnation --config RELAY.toml` binds the relay's
//!   configured `deployment_incarnation` to an **empty** namespace, using
//!   `RedisCatalog::activate_first_deployment_incarnation`, which refuses any
//!   namespace that already holds a key.
//! * `provision-catalog --config RELAY.toml --records RECORDS.toml
//!   [--dry-run]` writes exactly one tenant, one user, one device with one
//!   credential, one service and one grant, using
//!   `RedisCatalog::provision_initial_catalog`, which applies the fixture
//!   seed's own validation, reservation and writer.  The service is an
//!   `echo`, an `http-forward` (MCP or ACP, by `http_forward_profile`) or an
//!   `fs` export, written with the capability the relay serves its type by;
//!   the dry run refuses any other type and any record of these types the
//!   relay could not serve (task row M6-C57).
//!
//! **What this module decides, and what it deliberately does not.**  It reads
//! the relay's own `ServeConfig` for the Redis authority, namespace,
//! incarnation and OIDC issuer, so the records land exactly where `serve` will
//! look and the identity binds to the issuer `serve` will verify.  It derives
//! the credential's SPKI pin, serial and validity from the device certificate
//! with `tunnel_transport::leaf_identity_from_der`, the parser the device
//! listener applies after the handshake, and it requires that certificate's
//! `urn:agent-tunnel:device:<id>` SAN to name the provisioned device -- the
//! comparison registration makes.  Every relationship, uniqueness and bound
//! rule belongs to `tunnel_catalog` and is not restated here.
//!
//! No record body, certificate body, key or token is printed or logged:
//! output carries identifiers, the SPKI pin (a public-key digest) and
//! timestamps only.

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsString,
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
};

use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;
use tunnel_catalog::{
    CatalogError, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord,
    MembershipRole, PermissionSet, PrincipalIdentity, RedisCatalog, ServiceSpec, TenantRecord,
    UserRecord,
};
use tunnel_transport::{CertificateRole, leaf_identity_from_der};
use uuid::Uuid;

use crate::{
    ServeConfig,
    redis_connection::{self, RedisConnectionError, RedisTlsMaterialPaths},
};

/// Largest records document or device certificate file accepted.
pub const MAX_PROVISIONING_FILE_BYTES: u64 = 256 * 1024;

/// Failures of the operator bootstrap commands.  Messages carry field names,
/// identifiers and the catalog's own static refusal text, never file bodies,
/// Redis URLs or backend error text.
#[derive(Debug)]
pub enum ProvisioningError {
    Usage(&'static str),
    Records(String),
    Certificate(String),
    Redis(RedisConnectionError),
    Catalog(CatalogError),
}

impl fmt::Display for ProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => formatter.write_str(message),
            Self::Records(message) => write!(formatter, "invalid provisioning records: {message}"),
            Self::Certificate(message) => {
                write!(formatter, "invalid device certificate: {message}")
            }
            Self::Redis(error) => write!(formatter, "{error}"),
            Self::Catalog(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for ProvisioningError {}

impl From<RedisConnectionError> for ProvisioningError {
    fn from(error: RedisConnectionError) -> Self {
        Self::Redis(error)
    }
}

impl From<CatalogError> for ProvisioningError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

/// The operator's records document: one of each record, nothing optional that
/// the relay would need later.  Unknown fields are refused so a misspelt key
/// cannot silently fall back to a default.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningRecords {
    pub tenant: TenantSection,
    pub user: UserSection,
    pub device: DeviceSection,
    pub service: ServiceSection,
    pub grant: GrantSection,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantSection {
    pub id: Uuid,
    pub display_name: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    #[default]
    Member,
    Admin,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSection {
    pub id: Uuid,
    pub display_name: String,
    /// The `sub` claim the relay's `oidc_issuer` puts in this user's tokens.
    pub oidc_subject: String,
    #[serde(default)]
    pub role: UserRole,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSection {
    pub id: Uuid,
    pub display_name: String,
    /// The device's issued certificate (PEM, leaf first), relative to the
    /// records document.
    pub certificate: PathBuf,
    /// Optional; a fresh identifier is generated and printed when absent.
    pub credential_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSection {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub service_type: String,
    pub display_name: String,
    pub operations: Vec<String>,
    /// Required on an `http-forward` service, refused on any other: the
    /// pinned application profile (`mcp-2025-11-25`, `mcp-2026-07-28` or
    /// `acp-http-v1`) the relay selects for it.  The relay's own
    /// `[http_forward] profiles` must list it (task row M6-C57).
    #[serde(default)]
    pub http_forward_profile: Option<String>,
    /// Required on an `fs` service, refused on any other: the export host's
    /// case behaviour, `sensitive` or `insensitive-preserving`.  The relay
    /// reports it and never guesses it (M6-C57).
    #[serde(default)]
    pub fs_case_sensitivity: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSection {
    pub operations: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// The catalog seed built from a records document, with the facts an operator
/// needs to see printed.
#[derive(Clone, Debug)]
pub struct ProvisioningPlan {
    pub records: CatalogFixture,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub credential_id: Uuid,
    pub service_id: Uuid,
    pub spki_fingerprint: String,
    pub credential_not_before: DateTime<Utc>,
    pub credential_expires_at: DateTime<Utc>,
    pub operations: BTreeSet<String>,
}

impl ProvisioningPlan {
    /// The provisioned service's type and the capability the relay selects
    /// it by, as `service_type=... [http_forward_profile=...|fs_case_sensitivity=...]`.
    fn service_summary(&self) -> String {
        let Some(service) = self.records.services.first() else {
            return String::new();
        };
        let mut summary = format!("service_type={}", service.service_type);
        for capability in [
            crate::http::forward::HTTP_FORWARD_PROFILE_CAPABILITY,
            crate::FS_CASE_SENSITIVITY_CAPABILITY,
        ] {
            if let Some(value) = service
                .capabilities
                .get(capability)
                .and_then(serde_json::Value::as_str)
            {
                summary.push_str(&format!(" {capability}={value}"));
            }
        }
        summary
    }

    fn summary(&self) -> String {
        format!(
            "tenant={} user={} device={} credential={} service={} {} spki_sha256={} \
             credential_valid={}..{} grant_operations={}",
            self.tenant_id,
            self.user_id,
            self.device_id,
            self.credential_id,
            self.service_id,
            self.service_summary(),
            self.spki_fingerprint,
            self.credential_not_before.to_rfc3339(),
            self.credential_expires_at.to_rfc3339(),
            self.operations
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

pub(crate) fn read_bounded(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|error| format!("could not read {what}: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_PROVISIONING_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read {what}: {error}"))?;
    if bytes.len() as u64 > MAX_PROVISIONING_FILE_BYTES {
        return Err(format!(
            "{what} exceeds the {MAX_PROVISIONING_FILE_BYTES}-byte bound"
        ));
    }
    Ok(bytes)
}

pub(crate) fn operation_set(
    field: &str,
    operations: &[String],
) -> Result<BTreeSet<String>, ProvisioningError> {
    let mut set = BTreeSet::new();
    for operation in operations {
        let trimmed = operation.trim();
        if trimmed.is_empty() || trimmed != operation || operation.chars().any(char::is_control) {
            return Err(ProvisioningError::Records(format!(
                "{field} entries must be non-empty names without surrounding whitespace"
            )));
        }
        // M6-C36: a grant is checked by exact name (`PermissionSet::allows`)
        // and the catalog stores names opaquely, so `*` would be kept as a
        // literal operation that nothing ever asks for: a grant that looks
        // like "everything" and authorizes nothing.  No adapter defines a
        // name containing `*`, so refusing it rejects no real operation.
        if operation.contains('*') {
            return Err(ProvisioningError::Records(format!(
                "{field} entry {operation:?} contains '*': wildcards are not supported; \
                 list each operation by its exact name, such as echo:invoke"
            )));
        }
        if !set.insert(operation.clone()) {
            return Err(ProvisioningError::Records(format!(
                "{field} lists an operation twice"
            )));
        }
    }
    if set.is_empty() {
        return Err(ProvisioningError::Records(format!(
            "{field} must name at least one operation"
        )));
    }
    Ok(set)
}

/// The service types `provision-catalog` can create, as the dry run names
/// them in a refusal.
pub const PROVISIONABLE_SERVICE_TYPES: &str =
    "echo, http-forward (MCP and ACP, selected by http_forward_profile) and fs";

/// The operations each provisionable service type defines.  A name outside
/// its type's list is refused: the relay checks grants by exact name, so such
/// an operation could never be asked for.
const ECHO_OPERATIONS: &[&str] = &[crate::ECHO_OPERATION];
const HTTP_FORWARD_OPERATIONS: &[&str] = &[crate::HTTP_FORWARD_OPERATION];
const FS_OPERATIONS: &[&str] = &[
    crate::FS_SESSION_OPERATION,
    crate::FS_READ_OPERATION,
    crate::FS_WRITE_OPERATION,
    crate::FS_LIST_OPERATION,
    crate::FS_DELETE_OPERATION,
];
/// The filesystem case behaviours the relay's descriptor can report.
const FS_CASE_SENSITIVITIES: &[&str] = &["sensitive", "insensitive-preserving"];

fn refuse_field(service_type: &str, field: &str) -> ProvisioningError {
    ProvisioningError::Records(format!(
        "service.{field} does not apply to a service of type {service_type:?}"
    ))
}

fn require_known_operations(
    service_type: &str,
    known: &[&str],
    operations: &BTreeSet<String>,
) -> Result<(), ProvisioningError> {
    if let Some(unknown) = operations
        .iter()
        .find(|operation| !known.contains(&operation.as_str()))
    {
        return Err(ProvisioningError::Records(format!(
            "service.operations entry {unknown:?} is not an operation of a {service_type:?} \
             service, which defines {}",
            known.join(", ")
        )));
    }
    Ok(())
}

/// The catalog capabilities of the one provisioned service: everything the
/// relay reads from the service record to serve its type (task row M6-C57).
///
/// Before M6-C57 every service was written as `{"operations": [...]}`, which
/// is all an echo service needs, so an `http-forward` service had no
/// `http_forward_profile` and was answered 404 `NOT_FOUND`, and an `fs`
/// service had no `fs_case_sensitivity` and was answered 404
/// `EXPORT_NOT_FOUND` -- after a dry run and a write that both succeeded.
/// Now the rules the relay applies when it serves each type are applied here,
/// so the dry run refuses what the write could not serve.
///
/// `served_profiles` is the relay configuration's `[http_forward] profiles`,
/// which `ServeConfig::parse` has already restricted to pinned profiles.
pub(crate) fn service_capabilities(
    service: &ServiceSection,
    service_operations: &BTreeSet<String>,
    served_profiles: &[String],
) -> Result<serde_json::Value, ProvisioningError> {
    let service_type = service.service_type.as_str();
    let mut capabilities = serde_json::json!({ "operations": service_operations });
    match service_type {
        crate::ECHO_SERVICE_TYPE => {
            if service.http_forward_profile.is_some() {
                return Err(refuse_field(service_type, "http_forward_profile"));
            }
            if service.fs_case_sensitivity.is_some() {
                return Err(refuse_field(service_type, "fs_case_sensitivity"));
            }
            require_known_operations(service_type, ECHO_OPERATIONS, service_operations)?;
        }
        crate::HTTP_FORWARD_SERVICE_TYPE => {
            if service.fs_case_sensitivity.is_some() {
                return Err(refuse_field(service_type, "fs_case_sensitivity"));
            }
            require_known_operations(service_type, HTTP_FORWARD_OPERATIONS, service_operations)?;
            let Some(profile) = service.http_forward_profile.as_deref() else {
                return Err(ProvisioningError::Records(
                    "an http-forward service requires service.http_forward_profile: \
                     mcp-2025-11-25 or mcp-2026-07-28 for an MCP server, acp-http-v1 for \
                     an ACP agent, computer-v1 for a CUA backend; without it the relay answers every request 404"
                        .into(),
                ));
            };
            let pinned = tunnel_mcp::McpProfile::parse_id(profile).is_some()
                || tunnel_acp::AcpProfile::parse_id(profile).is_some()
                || tunnel_cua::CuaProfile::parse_id(profile).is_some();
            if !pinned {
                return Err(ProvisioningError::Records(format!(
                    "service.http_forward_profile {profile:?} is not a pinned profile; \
                     the relay serves mcp-2025-11-25, mcp-2026-07-28, acp-http-v1 and computer-v1"
                )));
            }
            if !served_profiles.iter().any(|served| served == profile) {
                return Err(ProvisioningError::Records(format!(
                    "service.http_forward_profile {profile:?} is not served by this relay: \
                     add it to the [http_forward] profiles of the relay configuration \
                     given with --config"
                )));
            }
            capabilities[crate::http::forward::HTTP_FORWARD_PROFILE_CAPABILITY] =
                serde_json::Value::String(profile.to_owned());
        }
        crate::FS_SERVICE_TYPE => {
            if service.http_forward_profile.is_some() {
                return Err(refuse_field(service_type, "http_forward_profile"));
            }
            require_known_operations(service_type, FS_OPERATIONS, service_operations)?;
            let Some(case) = service.fs_case_sensitivity.as_deref() else {
                return Err(ProvisioningError::Records(
                    "an fs service requires service.fs_case_sensitivity: sensitive or \
                     insensitive-preserving, as the export's host behaves; without it \
                     the relay answers every request 404"
                        .into(),
                ));
            };
            if !FS_CASE_SENSITIVITIES.contains(&case) {
                return Err(ProvisioningError::Records(format!(
                    "service.fs_case_sensitivity {case:?} must be sensitive or \
                     insensitive-preserving"
                )));
            }
            capabilities[crate::FS_CASE_SENSITIVITY_CAPABILITY] =
                serde_json::Value::String(case.to_owned());
        }
        other => {
            return Err(ProvisioningError::Records(format!(
                "service.type {other:?} is not a type provision-catalog can create; \
                 it creates {PROVISIONABLE_SERVICE_TYPES}"
            )));
        }
    }
    Ok(capabilities)
}

/// The rules a grant must meet to authorize anything on its service: its
/// operations are a subset of the service's, and a filesystem grant names the
/// session operation and at least one capability.  Shared by
/// `provision-catalog` and `set-grant` (task row M6-C31); `set-grant` applies
/// it to the service record it reads from the catalog.
pub(crate) fn check_grant(
    service_type: &str,
    service_operations: &BTreeSet<String>,
    grant_operations: &BTreeSet<String>,
) -> Result<(), ProvisioningError> {
    if !grant_operations.is_subset(service_operations) {
        return Err(ProvisioningError::Records(
            "grant.operations must be a subset of service.operations".into(),
        ));
    }
    if service_type == crate::FS_SERVICE_TYPE {
        // The relay admits a filesystem session only for a grant naming the
        // session operation and at least one capability; a grant without
        // both is refused 403 on every request.
        if !grant_operations.contains(crate::FS_SESSION_OPERATION) {
            return Err(ProvisioningError::Records(format!(
                "an fs grant must include {}, which admits a filesystem session",
                crate::FS_SESSION_OPERATION
            )));
        }
        if grant_operations.len() < 2 {
            return Err(ProvisioningError::Records(format!(
                "an fs grant must also name at least one of {}, {}, {} or {}; a grant \
                 naming no capability admits no session",
                crate::FS_READ_OPERATION,
                crate::FS_WRITE_OPERATION,
                crate::FS_LIST_OPERATION,
                crate::FS_DELETE_OPERATION
            )));
        }
    }
    Ok(())
}

/// Refuse a grant expiry that has already passed.
pub(crate) fn check_grant_expiry(
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), ProvisioningError> {
    if expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Err(ProvisioningError::Records(
            "grant.expires_at is already in the past".into(),
        ));
    }
    Ok(())
}

/// A device credential as the device listener will see it, derived from the
/// device's issued certificate.
#[derive(Clone, Debug)]
pub(crate) struct DeviceCredential {
    pub spki_fingerprint: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Read a device certificate (PEM, leaf first) and derive its credential,
/// refusing one the relay would not register for `device_id`.  Shared by
/// `provision-catalog` and `add-device` (M6-C31).
pub(crate) fn device_credential(
    certificate_path: &Path,
    device_id: Uuid,
    now: DateTime<Utc>,
) -> Result<DeviceCredential, ProvisioningError> {
    let pem = read_bounded(certificate_path, "device.certificate")
        .map_err(ProvisioningError::Certificate)?;
    let leaf = rustls_pemfile::certs(&mut pem.as_slice())
        .next()
        .ok_or_else(|| ProvisioningError::Certificate("no PEM certificate found".into()))?
        .map_err(|_| ProvisioningError::Certificate("malformed PEM certificate".into()))?;
    let identity = leaf_identity_from_der(leaf.as_ref())
        .map_err(|error| ProvisioningError::Certificate(error.to_string()))?;
    // The device listener parses this SAN into the device identifier and
    // registration refuses a credential whose catalog device differs, so a
    // mismatch here is a device that could never connect.
    let named = match identity.role() {
        CertificateRole::Device { id } => id.parse::<Uuid>().ok(),
        CertificateRole::Peer { .. } => {
            return Err(ProvisioningError::Certificate(
                "certificate carries a relay peer role, not a device role".into(),
            ));
        }
    };
    if named != Some(device_id) {
        return Err(ProvisioningError::Certificate(format!(
            "its urn:agent-tunnel:device: SAN must name device.id {device_id}"
        )));
    }
    let not_before = timestamp(identity.certificate_not_before(), "notBefore")?;
    let expires_at = timestamp(identity.certificate_expires_at(), "notAfter")?;
    if expires_at <= now {
        return Err(ProvisioningError::Certificate(
            "certificate has already expired".into(),
        ));
    }
    Ok(DeviceCredential {
        spki_fingerprint: identity.spki_sha256().to_hex(),
        serial: identity.certificate_serial().to_owned(),
        not_before,
        expires_at,
    })
}

fn timestamp(seconds: i64, field: &str) -> Result<DateTime<Utc>, ProvisioningError> {
    Utc.timestamp_opt(seconds, 0).single().ok_or_else(|| {
        ProvisioningError::Certificate(format!("{field} is outside the supported range"))
    })
}

/// Build the catalog seed for one records document without contacting Redis.
///
/// `records_path` anchors the relative certificate path.  `issuer` is the
/// relay's configured `oidc_issuer`; `served_profiles` is its
/// `[http_forward] profiles` (empty when the table is absent); `now` is the
/// instant the credential must still be valid at.
pub fn plan_provisioning(
    records_path: &Path,
    issuer: &str,
    served_profiles: &[String],
    now: DateTime<Utc>,
) -> Result<ProvisioningPlan, ProvisioningError> {
    let text =
        read_bounded(records_path, "the records document").map_err(ProvisioningError::Records)?;
    let text = String::from_utf8(text)
        .map_err(|_| ProvisioningError::Records("the records document is not UTF-8".into()))?;
    let document: ProvisioningRecords =
        toml::from_str(&text).map_err(|error| ProvisioningError::Records(error.to_string()))?;

    let service_operations = operation_set("service.operations", &document.service.operations)?;
    let grant_operations = operation_set("grant.operations", &document.grant.operations)?;
    if !grant_operations.is_subset(&service_operations) {
        return Err(ProvisioningError::Records(
            "grant.operations must be a subset of service.operations".into(),
        ));
    }
    let capabilities =
        service_capabilities(&document.service, &service_operations, served_profiles)?;
    check_grant(
        &document.service.service_type,
        &service_operations,
        &grant_operations,
    )?;
    check_grant_expiry(document.grant.expires_at, now)?;

    let certificate_path = records_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&document.device.certificate);
    let DeviceCredential {
        spki_fingerprint,
        serial,
        not_before,
        expires_at,
    } = device_credential(&certificate_path, document.device.id, now)?;

    let tenant_id = document.tenant.id;
    let user_id = document.user.id;
    let device_id = document.device.id;
    let service_id = document.service.id;
    let credential_id = document.device.credential_id.unwrap_or_else(Uuid::new_v4);
    let records = CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id,
            display_name: document.tenant.display_name,
            active: true,
        }],
        users: vec![UserRecord {
            user_id,
            display_name: document.user.display_name,
        }],
        identities: vec![PrincipalIdentity {
            issuer: issuer.to_owned(),
            subject: document.user.oidc_subject,
            user_id,
        }],
        memberships: vec![MembershipRecord {
            tenant_id,
            user_id,
            role: match document.user.role {
                UserRole::Member => MembershipRole::Member,
                UserRole::Admin => MembershipRole::Admin,
            },
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id,
            device_id,
            owner_user_id: user_id,
            display_name: document.device.display_name,
            active: true,
            last_seen_at: None,
        }],
        credentials: vec![CredentialRecord {
            tenant_id,
            device_id,
            credential_id,
            spki_fingerprint: spki_fingerprint.clone(),
            serial: Some(serial),
            not_before,
            expires_at,
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id,
            device_id,
            service_id,
            service_type: document.service.service_type,
            display_name: document.service.display_name,
            capabilities,
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id,
            principal_id: user_id,
            device_id,
            service_id,
            permissions: PermissionSet {
                operations: grant_operations.clone(),
            },
            constraints: serde_json::json!({}),
            expires_at: document.grant.expires_at,
            active: true,
        }],
    };
    records.validate()?;
    Ok(ProvisioningPlan {
        records,
        tenant_id,
        user_id,
        device_id,
        credential_id,
        service_id,
        spki_fingerprint,
        credential_not_before: not_before,
        credential_expires_at: expires_at,
        operations: grant_operations,
    })
}

pub(crate) fn load_config(path: &Path) -> Result<ServeConfig, Box<dyn Error>> {
    Ok(ServeConfig::parse(&fs::read_to_string(path)?)?)
}

pub(crate) fn tls_material(config: &ServeConfig) -> RedisTlsMaterialPaths {
    RedisTlsMaterialPaths {
        root_ca_path: config.redis_tls_root_ca_path.clone(),
        client_cert_path: config.redis_tls_client_cert_path.clone(),
        client_key_path: config.redis_tls_client_key_path.clone(),
    }
}

/// `tunnel-relay activate-first-incarnation --config PATH`.  Returns the line
/// to print.
pub async fn activate_first_incarnation(config_path: &Path) -> Result<String, Box<dyn Error>> {
    let config = load_config(config_path)?;
    let catalog: RedisCatalog = redis_connection::connect_for_first_activation(
        &config.redis_url,
        &config.redis_namespace,
        &config.deployment_incarnation,
        &tls_material(&config),
    )
    .await
    .map_err(ProvisioningError::from)?;
    catalog
        .activate_first_deployment_incarnation()
        .await
        .map_err(ProvisioningError::from)?;
    Ok(format!(
        "Activated deployment incarnation {} as the first incarnation of namespace {}.",
        config.deployment_incarnation, config.redis_namespace
    ))
}

/// The declaration `rebind-redis-run` requires (M6-C65).
pub const REDIS_RESTARTED_IN_PLACE_FLAG: &str = "--redis-restarted-in-place";

/// `tunnel-relay rebind-redis-run --config RELAY.toml
/// --redis-restarted-in-place` (task row M6-C65): after an orderly Redis
/// restart that kept its data, move the namespace's run binding to the new
/// Redis run so `serve` accepts the same namespace again, with nothing
/// reprovisioned.
///
/// The catalog refuses a namespace without its incarnation or run binding
/// (Redis came back empty) and one whose incarnation is not this relay's.  It
/// cannot distinguish a restart that kept every acknowledged write from a
/// restore of an older consistent backup, so the operator must declare, with
/// the flag, that Redis restarted from its own persistence and was not
/// restored or replaced.  A single relay only: a `[cluster]` deployment's
/// Redis recovery is the approved `recover` workflow (M6-C22).
pub async fn rebind_redis_run(args: &[OsString]) -> Result<String, Box<dyn Error>> {
    const USAGE: &str = "rebind-redis-run requires --config PATH --redis-restarted-in-place";
    let mut config_path = None;
    let mut declared = false;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index]
            .to_str()
            .ok_or(ProvisioningError::Usage(USAGE))?;
        match argument {
            "--config" if config_path.is_none() => {
                index += 1;
                let value = args
                    .get(index)
                    .filter(|value| !value.is_empty())
                    .ok_or(ProvisioningError::Usage(USAGE))?;
                config_path = Some(PathBuf::from(value));
            }
            REDIS_RESTARTED_IN_PLACE_FLAG if !declared => declared = true,
            _ => return Err(ProvisioningError::Usage(USAGE).into()),
        }
        index += 1;
    }
    let config_path = config_path.ok_or(ProvisioningError::Usage(USAGE))?;
    if !declared {
        return Err(ProvisioningError::Usage(
            "rebind-redis-run requires --redis-restarted-in-place: declare that Redis restarted from its own persistence and was not restored from a backup, replaced or emptied",
        )
        .into());
    }
    let config = load_config(&config_path)?;
    if config.cluster.is_some() {
        return Err(ProvisioningError::Usage(
            "rebind-redis-run is for a single relay; a [cluster] deployment recovers Redis with the recovery workflow",
        )
        .into());
    }
    let catalog: RedisCatalog = redis_connection::connect_for_first_activation(
        &config.redis_url,
        &config.redis_namespace,
        &config.deployment_incarnation,
        &tls_material(&config),
    )
    .await
    .map_err(ProvisioningError::from)?;
    let outcome = catalog
        .rebind_restarted_redis_run()
        .await
        .map_err(|error| {
            let class = tunnel_catalog::CatalogConnectionFailure::classify(&error).as_str();
            format!("Redis run re-binding refused: {error}; stage=authority_identity class={class}")
        })?;
    Ok(match outcome {
        tunnel_catalog::RedisRunRebind::AlreadyCurrent { run_id } => format!(
            "Namespace {} is already bound to Redis run {run_id}; nothing changed.",
            config.redis_namespace
        ),
        tunnel_catalog::RedisRunRebind::Rebound {
            previous_run_id,
            run_id,
        } => format!(
            "Re-bound namespace {} (deployment incarnation {}) from Redis run {previous_run_id} to {run_id}, on the operator's declaration that Redis restarted in place; not verified.",
            config.redis_namespace, config.deployment_incarnation
        ),
    })
}

struct ProvisionArguments {
    config: PathBuf,
    records: PathBuf,
    dry_run: bool,
}

fn parse_provision_arguments(args: &[OsString]) -> Result<ProvisionArguments, ProvisioningError> {
    const USAGE: &str = "provision-catalog requires --config PATH --records PATH [--dry-run]";
    let mut config = None;
    let mut records = None;
    let mut dry_run = false;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index]
            .to_str()
            .ok_or(ProvisioningError::Usage(USAGE))?;
        match argument {
            "--config" | "--records" => {
                index += 1;
                let value = args
                    .get(index)
                    .filter(|value| !value.is_empty())
                    .ok_or(ProvisioningError::Usage(USAGE))?;
                let slot = if argument == "--config" {
                    &mut config
                } else {
                    &mut records
                };
                if slot.replace(PathBuf::from(value)).is_some() {
                    return Err(ProvisioningError::Usage(
                        "provision-catalog: duplicate argument",
                    ));
                }
            }
            "--dry-run" if !dry_run => dry_run = true,
            _ => return Err(ProvisioningError::Usage(USAGE)),
        }
        index += 1;
    }
    Ok(ProvisionArguments {
        config: config.ok_or(ProvisioningError::Usage(USAGE))?,
        records: records.ok_or(ProvisioningError::Usage(USAGE))?,
        dry_run,
    })
}

/// `tunnel-relay provision-catalog --config PATH --records PATH [--dry-run]`.
/// Returns the line to print.
pub async fn provision_catalog(args: &[OsString]) -> Result<String, Box<dyn Error>> {
    let arguments = parse_provision_arguments(args)?;
    let config = load_config(&arguments.config)?;
    let served_profiles = config
        .http_forward
        .as_ref()
        .map_or(&[][..], |http_forward| http_forward.profiles.as_slice());
    let plan = plan_provisioning(
        &arguments.records,
        &config.oidc_issuer,
        served_profiles,
        Utc::now(),
    )?;
    if arguments.dry_run {
        return Ok(format!(
            "Provisioning records are valid for namespace {}: {}. \
             This dry run contacted no Redis authority and wrote nothing.",
            config.redis_namespace,
            plan.summary()
        ));
    }
    // The same connection `serve` makes, including its active-incarnation
    // and Redis-run fence: records are only written where a relay can start.
    let catalog = redis_connection::connect(
        &config.redis_url,
        &config.redis_namespace,
        &config.deployment_incarnation,
        &tls_material(&config),
    )
    .await
    .map_err(ProvisioningError::from)?;
    catalog
        .provision_initial_catalog(&plan.records)
        .await
        .map_err(ProvisioningError::from)?;
    Ok(format!(
        "Provisioned namespace {} for deployment incarnation {}: {}.",
        config.redis_namespace,
        config.deployment_incarnation,
        plan.summary()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn provision_arguments_require_both_paths_and_refuse_repeats() {
        let parsed = parse_provision_arguments(&args(&[
            "--config",
            "relay.toml",
            "--records",
            "r.toml",
            "--dry-run",
        ]))
        .expect("complete arguments parse");
        assert!(parsed.dry_run);
        assert_eq!(parsed.config, PathBuf::from("relay.toml"));
        assert_eq!(parsed.records, PathBuf::from("r.toml"));
        for bad in [
            &["--config", "relay.toml"][..],
            &["--records", "r.toml"][..],
            &["--config", "a", "--config", "b", "--records", "r"][..],
            &["--config", "a", "--records", "r", "--dry-run", "--dry-run"][..],
            &["--config", "a", "--records", "r", "--force"][..],
            &["--config", "", "--records", "r"][..],
            &["--config"][..],
        ] {
            assert!(
                parse_provision_arguments(&args(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    const ISSUER: &str = "https://issuer.provisioning.invalid/";
    const TENANT: &str = "6f1d7a3e-0b0c-4c1e-9f55-1a2b3c4d5e01";
    const USER: &str = "6f1d7a3e-0b0c-4c1e-9f55-1a2b3c4d5e02";
    const DEVICE: &str = "6f1d7a3e-0b0c-4c1e-9f55-1a2b3c4d5e03";
    const SERVICE: &str = "6f1d7a3e-0b0c-4c1e-9f55-1a2b3c4d5e04";

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scratch() -> Scratch {
        let dir = std::env::temp_dir().join(format!("m6c21-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create scratch directory");
        Scratch(dir)
    }

    /// A synthetic device certificate; `san` is the whole URI, or none.
    fn certificate(san: Option<&str>) -> (String, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("generate key");
        let mut params = rcgen::CertificateParams::default();
        if let Some(uri) = san {
            params.subject_alt_names.push(rcgen::SanType::URI(
                uri.to_owned().try_into().expect("URI SAN"),
            ));
        }
        let certificate = params.self_signed(&key).expect("self-sign");
        (certificate.pem(), certificate.der().to_vec())
    }

    fn records(grant_operations: &str) -> String {
        records_for(
            "type = \"echo\"\noperations = [\"echo:invoke\"]",
            grant_operations,
        )
    }

    /// A records document whose `[service]` table carries `service_fields`
    /// after its id and display name.
    fn records_for(service_fields: &str, grant_operations: &str) -> String {
        format!(
            "[tenant]\nid = \"{TENANT}\"\ndisplay_name = \"t\"\n\n\
             [user]\nid = \"{USER}\"\ndisplay_name = \"u\"\noidc_subject = \"subject-1\"\n\n\
             [device]\nid = \"{DEVICE}\"\ndisplay_name = \"d\"\ncertificate = \"device.pem\"\n\n\
             [service]\nid = \"{SERVICE}\"\ndisplay_name = \"s\"\n{service_fields}\n\n\
             [grant]\noperations = {grant_operations}\n"
        )
    }

    /// Every pinned `http-forward` profile, as a relay configured to serve
    /// all of them lists it.
    fn served() -> Vec<String> {
        ["mcp-2025-11-25", "mcp-2026-07-28", "acp-http-v1", "computer-v1"]
            .map(str::to_owned)
            .to_vec()
    }

    fn plan_with(
        dir: &Path,
        san: Option<&str>,
        document: &str,
    ) -> (Result<ProvisioningPlan, ProvisioningError>, Vec<u8>) {
        plan_serving(dir, san, document, &served())
    }

    fn plan_serving(
        dir: &Path,
        san: Option<&str>,
        document: &str,
        served_profiles: &[String],
    ) -> (Result<ProvisioningPlan, ProvisioningError>, Vec<u8>) {
        let (pem, der) = certificate(san);
        fs::write(dir.join("device.pem"), pem).expect("write certificate");
        let path = dir.join("records.toml");
        fs::write(&path, document).expect("write records");
        (
            plan_provisioning(&path, ISSUER, served_profiles, Utc::now()),
            der,
        )
    }

    /// M6-C57: each service type the alpha serves is written with the
    /// capability the relay selects it by.  Before M6-C57 the records schema
    /// had no field for either capability (`deny_unknown_fields` refused the
    /// document) and the writer stored `{"operations": [...]}` alone, so the
    /// relay answered 404 for every MCP, ACP and filesystem request.
    #[test]
    fn plan_writes_the_capability_each_service_type_is_served_by() {
        let dir = scratch();
        let san = format!("urn:agent-tunnel:device:{DEVICE}");
        for (fields, grant, key, value) in [
            (
                "type = \"http-forward\"\noperations = [\"http:invoke\"]\n\
                 http_forward_profile = \"mcp-2025-11-25\"",
                "[\"http:invoke\"]",
                "http_forward_profile",
                "mcp-2025-11-25",
            ),
            (
                "type = \"http-forward\"\noperations = [\"http:invoke\"]\n\
                 http_forward_profile = \"mcp-2026-07-28\"",
                "[\"http:invoke\"]",
                "http_forward_profile",
                "mcp-2026-07-28",
            ),
            (
                "type = \"http-forward\"\noperations = [\"http:invoke\"]\n\
                 http_forward_profile = \"acp-http-v1\"",
                "[\"http:invoke\"]",
                "http_forward_profile",
                "acp-http-v1",
            ),
            (
                "type = \"http-forward\"\noperations = [\"http:invoke\"]\n\
                 http_forward_profile = \"computer-v1\"",
                "[\"http:invoke\"]",
                "http_forward_profile",
                "computer-v1",
            ),
            (
                "type = \"fs\"\noperations = [\"fs:connect\", \"fs:read\", \"fs:list\"]\n\
                 fs_case_sensitivity = \"insensitive-preserving\"",
                "[\"fs:connect\", \"fs:read\"]",
                "fs_case_sensitivity",
                "insensitive-preserving",
            ),
        ] {
            let (plan, _) = plan_with(&dir.0, Some(&san), &records_for(fields, grant));
            let plan = plan.unwrap_or_else(|error| panic!("{value}: {error}"));
            let capabilities = &plan.records.services[0].capabilities;
            assert_eq!(
                capabilities[key].as_str(),
                Some(value),
                "{value}: the service record must carry {key}: {capabilities}"
            );
            assert!(
                plan.summary().contains(&format!("{key}={value}")),
                "{value}: the printed summary must name what was provisioned"
            );
        }
        // The echo record is unchanged: operations only.
        let (plan, _) = plan_with(&dir.0, Some(&san), &records("[\"echo:invoke\"]"));
        let capabilities = plan.expect("echo plans").records.services[0]
            .capabilities
            .clone();
        assert_eq!(
            capabilities,
            serde_json::json!({"operations": ["echo:invoke"]})
        );
    }

    /// M6-C57: the dry run refuses every service the relay could not serve,
    /// naming the field, instead of accepting a record that is answered 404
    /// forever.  Before M6-C57 the three cases naming neither new field
    /// planned clean, and the rest were refused only because the old schema
    /// did not know the field -- a refusal for the wrong reason.
    #[test]
    fn plan_refuses_a_service_the_relay_could_not_serve() {
        let dir = scratch();
        let san = format!("urn:agent-tunnel:device:{DEVICE}");
        let http = "type = \"http-forward\"\noperations = [\"http:invoke\"]";
        let fs_service = "type = \"fs\"\noperations = [\"fs:connect\", \"fs:read\"]";
        let cases = [
            (
                "unknown type",
                "type = \"files\"\noperations = [\"files:read\"]".to_owned(),
                "[\"files:read\"]",
                served(),
                "is not a type provision-catalog can create",
            ),
            (
                "http-forward without a profile",
                http.to_owned(),
                "[\"http:invoke\"]",
                served(),
                "requires service.http_forward_profile",
            ),
            (
                "unpinned profile",
                format!("{http}\nhttp_forward_profile = \"mcp-2024-11-05\""),
                "[\"http:invoke\"]",
                served(),
                "is not a pinned profile",
            ),
            (
                "profile the relay does not serve",
                format!("{http}\nhttp_forward_profile = \"acp-http-v1\""),
                "[\"http:invoke\"]",
                vec!["mcp-2025-11-25".to_owned()],
                "is not served by this relay",
            ),
            (
                "relay without [http_forward]",
                format!("{http}\nhttp_forward_profile = \"mcp-2025-11-25\""),
                "[\"http:invoke\"]",
                Vec::new(),
                "is not served by this relay",
            ),
            (
                "http-forward with an echo operation",
                "type = \"http-forward\"\noperations = [\"echo:invoke\"]\n\
                 http_forward_profile = \"mcp-2025-11-25\""
                    .to_owned(),
                "[\"echo:invoke\"]",
                served(),
                "is not an operation of a \"http-forward\" service",
            ),
            (
                "fs without a case behaviour",
                fs_service.to_owned(),
                "[\"fs:connect\", \"fs:read\"]",
                served(),
                "requires service.fs_case_sensitivity",
            ),
            (
                "fs with an unknown case behaviour",
                format!("{fs_service}\nfs_case_sensitivity = \"insensitive\""),
                "[\"fs:connect\", \"fs:read\"]",
                served(),
                "must be sensitive or insensitive-preserving",
            ),
            (
                "fs grant without the session operation",
                format!("{fs_service}\nfs_case_sensitivity = \"sensitive\""),
                "[\"fs:read\"]",
                served(),
                "must include fs:connect",
            ),
            (
                "fs grant naming no capability",
                format!("{fs_service}\nfs_case_sensitivity = \"sensitive\""),
                "[\"fs:connect\"]",
                served(),
                "admits no session",
            ),
            (
                "fs with an http operation",
                "type = \"fs\"\noperations = [\"fs:connect\", \"http:invoke\"]\n\
                 fs_case_sensitivity = \"sensitive\""
                    .to_owned(),
                "[\"fs:connect\"]",
                served(),
                "is not an operation of a \"fs\" service",
            ),
            (
                "echo with a profile",
                "type = \"echo\"\noperations = [\"echo:invoke\"]\n\
                 http_forward_profile = \"mcp-2025-11-25\""
                    .to_owned(),
                "[\"echo:invoke\"]",
                served(),
                "does not apply to a service of type \"echo\"",
            ),
            (
                "echo with a case behaviour",
                "type = \"echo\"\noperations = [\"echo:invoke\"]\n\
                 fs_case_sensitivity = \"sensitive\""
                    .to_owned(),
                "[\"echo:invoke\"]",
                served(),
                "does not apply to a service of type \"echo\"",
            ),
        ];
        let total = cases.len();
        // Every case is tried, and every miss is reported with its reason,
        // so a regression names each rule it broke rather than the first.
        let mut misses = Vec::new();
        for (case, fields, grant, served_profiles, expected) in cases {
            let (plan, _) = plan_serving(
                &dir.0,
                Some(&san),
                &records_for(&fields, grant),
                &served_profiles,
            );
            match plan {
                Ok(plan) => misses.push(format!(
                    "{case}: planned a service the relay cannot serve: {}",
                    plan.summary()
                )),
                Err(error) if !error.to_string().contains(expected) => {
                    misses.push(format!("{case}: refused for another reason: {error}"));
                }
                Err(_) => {}
            }
        }
        assert!(
            misses.is_empty(),
            "{} of {total} unservable services were not refused for their own reason:\n{}",
            misses.len(),
            misses.join("\n")
        );
    }

    #[test]
    fn plan_derives_the_credential_the_device_listener_will_see() {
        let dir = scratch();
        let san = format!("urn:agent-tunnel:device:{DEVICE}");
        let (plan, der) = plan_with(&dir.0, Some(&san), &records("[\"echo:invoke\"]"));
        let plan = plan.expect("a matching certificate plans");
        let expected = tunnel_transport::spki_sha256_from_der(&der)
            .expect("pin")
            .to_hex();
        assert_eq!(plan.spki_fingerprint, expected);
        assert_eq!(plan.records.credentials[0].spki_fingerprint, expected);
        assert_eq!(plan.records.identities[0].issuer, ISSUER);
        assert_eq!(plan.records.identities[0].subject, "subject-1");
        assert_eq!(plan.device_id.to_string(), DEVICE);
        assert_eq!(plan.records.grants.len(), 1);
        assert!(plan.records.grants[0].permissions.allows("echo:invoke"));
        assert!(plan.records.validate().is_ok());
    }

    #[test]
    fn plan_refuses_a_certificate_the_relay_would_not_register() {
        let dir = scratch();
        let document = records("[\"echo:invoke\"]");
        // No role SAN at all: the listener's parser refuses it.
        let (plan, _) = plan_with(&dir.0, None, &document);
        let error = plan.expect_err("no device SAN").to_string();
        assert!(error.contains("urn:agent-tunnel:device:"), "{error}");
        // A device SAN for another device: registration's comparison.
        let other = format!("urn:agent-tunnel:device:{}", Uuid::new_v4());
        let (plan, _) = plan_with(&dir.0, Some(&other), &document);
        let error = plan.expect_err("another device").to_string();
        assert!(error.contains("must name device.id"), "{error}");
        // A relay peer identity is not a device credential.
        let (plan, _) = plan_with(&dir.0, Some("urn:agent-tunnel:peer:relay-a"), &document);
        let error = plan.expect_err("peer role").to_string();
        assert!(error.contains("peer role"), "{error}");
    }

    #[test]
    fn plan_refuses_records_the_relay_cannot_honour() {
        let dir = scratch();
        let san = format!("urn:agent-tunnel:device:{DEVICE}");
        let (plan, _) = plan_with(
            &dir.0,
            Some(&san),
            &records("[\"echo:invoke\", \"fs:read\"]"),
        );
        let error = plan.expect_err("grant wider than service").to_string();
        assert!(error.contains("subset"), "{error}");
        let (plan, _) = plan_with(
            &dir.0,
            Some(&san),
            &format!("{}\n[extra]\nx = 1\n", records("[\"echo:invoke\"]")),
        );
        assert!(
            plan.expect_err("unknown table")
                .to_string()
                .contains("extra"),
            "an unknown table must be named"
        );
    }

    #[test]
    fn operation_sets_refuse_empty_duplicate_and_padded_names() {
        assert!(operation_set("f", &[]).is_err());
        assert!(operation_set("f", &["".into()]).is_err());
        assert!(operation_set("f", &[" echo:invoke".into()]).is_err());
        assert!(operation_set("f", &["a".into(), "a".into()]).is_err());
        // M6-C36: wildcards, whole or partial, are refused by name.
        for wildcard in ["*", "echo:*", "*:invoke"] {
            let error = operation_set("f", &[wildcard.into()]).expect_err(wildcard);
            assert!(
                error.to_string().contains("wildcards are not supported"),
                "{wildcard}: {error}"
            );
        }
        assert_eq!(
            operation_set("f", &["echo:invoke".into()])
                .expect("one name")
                .len(),
            1
        );
    }
}
