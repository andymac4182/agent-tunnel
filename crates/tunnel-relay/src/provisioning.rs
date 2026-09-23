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
//!   seed's own validation, reservation and writer.
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
    fn summary(&self) -> String {
        format!(
            "tenant={} user={} device={} credential={} service={} spki_sha256={} \
             credential_valid={}..{} grant_operations={}",
            self.tenant_id,
            self.user_id,
            self.device_id,
            self.credential_id,
            self.service_id,
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

fn read_bounded(path: &Path, what: &str) -> Result<Vec<u8>, String> {
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

fn operation_set(
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

fn timestamp(seconds: i64, field: &str) -> Result<DateTime<Utc>, ProvisioningError> {
    Utc.timestamp_opt(seconds, 0).single().ok_or_else(|| {
        ProvisioningError::Certificate(format!("{field} is outside the supported range"))
    })
}

/// Build the catalog seed for one records document without contacting Redis.
///
/// `records_path` anchors the relative certificate path.  `issuer` is the
/// relay's configured `oidc_issuer`; `now` is the instant the credential must
/// still be valid at.
pub fn plan_provisioning(
    records_path: &Path,
    issuer: &str,
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
    if document
        .grant
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(ProvisioningError::Records(
            "grant.expires_at is already in the past".into(),
        ));
    }

    let certificate_path = records_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&document.device.certificate);
    let pem = read_bounded(&certificate_path, "device.certificate")
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
    if named != Some(document.device.id) {
        return Err(ProvisioningError::Certificate(format!(
            "its urn:agent-tunnel:device: SAN must name device.id {}",
            document.device.id
        )));
    }
    let not_before = timestamp(identity.certificate_not_before(), "notBefore")?;
    let expires_at = timestamp(identity.certificate_expires_at(), "notAfter")?;
    if expires_at <= now {
        return Err(ProvisioningError::Certificate(
            "certificate has already expired".into(),
        ));
    }

    let tenant_id = document.tenant.id;
    let user_id = document.user.id;
    let device_id = document.device.id;
    let service_id = document.service.id;
    let credential_id = document.device.credential_id.unwrap_or_else(Uuid::new_v4);
    let spki_fingerprint = identity.spki_sha256().to_hex();
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
            serial: Some(identity.certificate_serial().to_owned()),
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
            capabilities: serde_json::json!({ "operations": service_operations }),
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

fn load_config(path: &Path) -> Result<ServeConfig, Box<dyn Error>> {
    Ok(ServeConfig::parse(&fs::read_to_string(path)?)?)
}

fn tls_material(config: &ServeConfig) -> RedisTlsMaterialPaths {
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
    let plan = plan_provisioning(&arguments.records, &config.oidc_issuer, Utc::now())?;
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
        format!(
            "[tenant]\nid = \"{TENANT}\"\ndisplay_name = \"t\"\n\n\
             [user]\nid = \"{USER}\"\ndisplay_name = \"u\"\noidc_subject = \"subject-1\"\n\n\
             [device]\nid = \"{DEVICE}\"\ndisplay_name = \"d\"\ncertificate = \"device.pem\"\n\n\
             [service]\nid = \"{SERVICE}\"\ntype = \"echo\"\ndisplay_name = \"s\"\n\
             operations = [\"echo:invoke\"]\n\n\
             [grant]\noperations = {grant_operations}\n"
        )
    }

    fn plan_with(
        dir: &Path,
        san: Option<&str>,
        document: &str,
    ) -> (Result<ProvisioningPlan, ProvisioningError>, Vec<u8>) {
        let (pem, der) = certificate(san);
        fs::write(dir.join("device.pem"), pem).expect("write certificate");
        let path = dir.join("records.toml");
        fs::write(&path, document).expect("write records");
        (plan_provisioning(&path, ISSUER, Utc::now()), der)
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
        assert_eq!(
            operation_set("f", &["echo:invoke".into()])
                .expect("one name")
                .len(),
            1
        );
    }
}
