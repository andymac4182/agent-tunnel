//! Day-2 catalog changes on a provisioned, serving relay (task row M6-C31).
//!
//! `provision-catalog` runs once per namespace (M6-C21).  Before this module,
//! nothing shipped could change the catalog afterwards: no second user,
//! device, service or grant, no grant change, and no revocation, so every
//! outside tester needed a namespace of their own.  Seven `tunnel-relay`
//! subcommands sit on this module, each reading the relay's own serving
//! configuration exactly as `provision-catalog` does:
//!
//! * `add-user --config RELAY.toml --records USER.toml [--dry-run]`
//! * `add-device --config RELAY.toml --records DEVICE.toml [--dry-run]`
//! * `add-service --config RELAY.toml --records SERVICE.toml [--dry-run]`
//! * `set-grant --config RELAY.toml --records GRANT.toml [--dry-run]` (add or
//!   replace)
//! * `revoke-grant --config RELAY.toml --tenant T --user U --device D
//!   --service S [--dry-run]`
//! * `revoke-device --config RELAY.toml --tenant T --device D [--dry-run]`
//! * `revoke-credential --config RELAY.toml --tenant T --device D
//!   --credential C [--dry-run]`
//!
//! **Writers.**  Each command is one atomic Redis script.  The three additions
//! use the new `RedisCatalog::add_user`, `add_device` and `add_service`
//! scripts, which require a provisioned namespace and the active incarnation
//! and Redis run, refuse any duplicate and overwrite nothing.  `set-grant` and
//! the revocations call the catalog's existing `upsert_grant`, `revoke_grant`,
//! `revoke_device` and `revoke_credential` unchanged -- the methods the row
//! found with no caller.  No command writes the incarnation, run or
//! reservation keys.
//!
//! **Dry runs.**  Every `--dry-run` applies the same record rules as the real
//! run -- the functions below, `provisioning`'s service-type, operation and
//! certificate rules, and the catalog's own `validate_*_addition` -- and
//! contacts no Redis.  Rules that depend on what the namespace already holds
//! (the tenant exists, the owner is a member, an identifier is new, the
//! service a grant names has these operations) can only be checked by the
//! write, inside its script, and the dry run says so by printing that it
//! contacted no Redis.
//!
//! **Pickup and revocation.**  The relay does not cache catalog records: every
//! device registration resolves the certificate's SPKI pin, and every consumer
//! request resolves the identity and authorizes the grant, against Redis.  A
//! record written here is therefore used by the next registration or request
//! with no restart.  A revoked grant refuses the next request; a revoked
//! device or credential also closes its live session at the owner actor's
//! next maintenance re-check (a 500 ms tick, at most 64 sessions a tick).
//!
//! Output carries identifiers, the SPKI pin and timestamps only; no record
//! body, certificate, key or token is printed or logged.

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsString,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use tunnel_catalog::{
    Catalog, CatalogError, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord,
    MembershipRole, PermissionSet, PrincipalIdentity, RedisCatalog, ServiceSpec, UserRecord,
    validate_device_addition, validate_service_addition, validate_user_addition,
};
use uuid::Uuid;

use crate::{
    ServeConfig,
    provisioning::{
        DeviceCredential, ProvisioningError, ServiceSection, UserRole, check_grant,
        check_grant_expiry, device_credential, load_config, operation_set, read_bounded,
        service_capabilities, tls_material,
    },
    redis_connection,
};

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// Parsed command line of one day-2 command.
#[derive(Debug)]
struct Arguments {
    config: PathBuf,
    records: Option<PathBuf>,
    ids: Vec<(&'static str, Uuid)>,
    dry_run: bool,
}

impl Arguments {
    fn id(&self, flag: &str) -> Uuid {
        self.ids
            .iter()
            .find(|(name, _)| *name == flag)
            .map(|(_, id)| *id)
            .expect("parse_arguments requires every declared identifier flag")
    }
}

/// `--config PATH`, then either `--records PATH` or the given identifier
/// flags, each exactly once, and an optional `--dry-run`.
fn parse_arguments(
    args: &[OsString],
    usage: &'static str,
    records: bool,
    id_flags: &[&'static str],
) -> Result<Arguments, ProvisioningError> {
    let mut config = None;
    let mut records_path = None;
    let mut ids: Vec<(&'static str, Uuid)> = Vec::new();
    let mut dry_run = false;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index]
            .to_str()
            .ok_or(ProvisioningError::Usage(usage))?;
        if argument == "--dry-run" {
            if dry_run {
                return Err(ProvisioningError::Usage(usage));
            }
            dry_run = true;
            index += 1;
            continue;
        }
        let value = args
            .get(index + 1)
            .filter(|value| !value.is_empty())
            .ok_or(ProvisioningError::Usage(usage))?;
        match argument {
            "--config" | "--records" if argument == "--config" || records => {
                let slot = if argument == "--config" {
                    &mut config
                } else {
                    &mut records_path
                };
                if slot.replace(PathBuf::from(value)).is_some() {
                    return Err(ProvisioningError::Usage(usage));
                }
            }
            flag => {
                let Some(name) = id_flags.iter().find(|name| **name == flag) else {
                    return Err(ProvisioningError::Usage(usage));
                };
                if ids.iter().any(|(seen, _)| seen == name) {
                    return Err(ProvisioningError::Usage(usage));
                }
                let id = value
                    .to_str()
                    .and_then(|text| text.parse::<Uuid>().ok())
                    .ok_or(ProvisioningError::Usage(usage))?;
                ids.push((name, id));
            }
        }
        index += 2;
    }
    if ids.len() != id_flags.len() || (records && records_path.is_none()) {
        return Err(ProvisioningError::Usage(usage));
    }
    Ok(Arguments {
        config: config.ok_or(ProvisioningError::Usage(usage))?,
        records: records_path,
        ids,
        dry_run,
    })
}

// ---------------------------------------------------------------------------
// Records documents
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserDocument {
    user: NewUser,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewUser {
    /// The existing tenant the user joins.
    tenant: Uuid,
    id: Uuid,
    display_name: String,
    /// The `sub` claim the relay's `oidc_issuer` puts in this user's tokens.
    oidc_subject: String,
    #[serde(default)]
    role: UserRole,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceDocument {
    device: NewDevice,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewDevice {
    tenant: Uuid,
    /// The user who owns the device: an existing member of `tenant`.
    owner: Uuid,
    id: Uuid,
    display_name: String,
    /// The device's issued certificate, relative to the records document.
    certificate: PathBuf,
    credential_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceDocument {
    service: NewService,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewService {
    tenant: Uuid,
    device: Uuid,
    id: Uuid,
    #[serde(rename = "type")]
    service_type: String,
    display_name: String,
    operations: Vec<String>,
    #[serde(default)]
    http_forward_profile: Option<String>,
    #[serde(default)]
    fs_case_sensitivity: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantDocument {
    grant: NewGrant,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NewGrant {
    tenant: Uuid,
    user: Uuid,
    device: Uuid,
    service: Uuid,
    operations: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
}

fn read_document<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ProvisioningError> {
    let bytes = read_bounded(path, "the records document").map_err(ProvisioningError::Records)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| ProvisioningError::Records("the records document is not UTF-8".into()))?;
    toml::from_str(&text).map_err(|error| ProvisioningError::Records(error.to_string()))
}

// ---------------------------------------------------------------------------
// Plans: every rule a dry run can apply, shared with the write
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct UserPlan {
    pub user: UserRecord,
    pub identity: PrincipalIdentity,
    pub membership: MembershipRecord,
}

impl UserPlan {
    fn summary(&self) -> String {
        format!(
            "tenant={} user={} role={}",
            self.membership.tenant_id,
            self.user.user_id,
            self.membership.role.as_str()
        )
    }
}

/// Build the records of `add-user` without contacting Redis.
pub fn plan_add_user(records_path: &Path, issuer: &str) -> Result<UserPlan, ProvisioningError> {
    let UserDocument { user } = read_document(records_path)?;
    let plan = UserPlan {
        user: UserRecord {
            user_id: user.id,
            display_name: user.display_name,
        },
        identity: PrincipalIdentity {
            issuer: issuer.to_owned(),
            subject: user.oidc_subject,
            user_id: user.id,
        },
        membership: MembershipRecord {
            tenant_id: user.tenant,
            user_id: user.id,
            role: match user.role {
                UserRole::Member => MembershipRole::Member,
                UserRole::Admin => MembershipRole::Admin,
            },
            active: true,
        },
    };
    validate_user_addition(&plan.user, &plan.identity, &plan.membership)?;
    Ok(plan)
}

#[derive(Clone, Debug)]
pub struct DevicePlan {
    pub device: FixtureDevice,
    pub credential: CredentialRecord,
}

impl DevicePlan {
    fn summary(&self) -> String {
        format!(
            "tenant={} device={} owner={} credential={} spki_sha256={} credential_valid={}..{}",
            self.device.tenant_id,
            self.device.device_id,
            self.device.owner_user_id,
            self.credential.credential_id,
            self.credential.spki_fingerprint,
            self.credential.not_before.to_rfc3339(),
            self.credential.expires_at.to_rfc3339(),
        )
    }
}

/// Build the records of `add-device` without contacting Redis: the
/// certificate is parsed and checked as `provision-catalog` checks it.
pub fn plan_add_device(
    records_path: &Path,
    now: DateTime<Utc>,
) -> Result<DevicePlan, ProvisioningError> {
    let DeviceDocument { device } = read_document(records_path)?;
    let certificate_path = records_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&device.certificate);
    let DeviceCredential {
        spki_fingerprint,
        serial,
        not_before,
        expires_at,
    } = device_credential(&certificate_path, device.id, now)?;
    let plan = DevicePlan {
        device: FixtureDevice {
            tenant_id: device.tenant,
            device_id: device.id,
            owner_user_id: device.owner,
            display_name: device.display_name,
            active: true,
            last_seen_at: None,
        },
        credential: CredentialRecord {
            tenant_id: device.tenant,
            device_id: device.id,
            credential_id: device.credential_id.unwrap_or_else(Uuid::new_v4),
            spki_fingerprint,
            serial: Some(serial),
            not_before,
            expires_at,
            revoked_at: None,
            active: true,
        },
    };
    validate_device_addition(&plan.device, &plan.credential)?;
    Ok(plan)
}

#[derive(Clone, Debug)]
pub struct ServicePlan {
    pub service: ServiceSpec,
    pub operations: BTreeSet<String>,
}

impl ServicePlan {
    fn summary(&self) -> String {
        let mut summary = format!(
            "tenant={} device={} service={} service_type={}",
            self.service.tenant_id,
            self.service.device_id,
            self.service.service_id,
            self.service.service_type
        );
        for capability in [
            crate::http::forward::HTTP_FORWARD_PROFILE_CAPABILITY,
            crate::FS_CASE_SENSITIVITY_CAPABILITY,
        ] {
            if let Some(value) = self
                .service
                .capabilities
                .get(capability)
                .and_then(serde_json::Value::as_str)
            {
                summary.push_str(&format!(" {capability}={value}"));
            }
        }
        summary.push_str(&format!(
            " operations={}",
            self.operations
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        ));
        summary
    }
}

/// Build the record of `add-service` without contacting Redis, with the
/// service-type rules `provision-catalog` applies (M6-C57).
pub fn plan_add_service(
    records_path: &Path,
    served_profiles: &[String],
) -> Result<ServicePlan, ProvisioningError> {
    let ServiceDocument { service } = read_document(records_path)?;
    let operations = operation_set("service.operations", &service.operations)?;
    let section = ServiceSection {
        id: service.id,
        service_type: service.service_type.clone(),
        display_name: service.display_name.clone(),
        operations: service.operations.clone(),
        http_forward_profile: service.http_forward_profile,
        fs_case_sensitivity: service.fs_case_sensitivity,
    };
    let capabilities = service_capabilities(&section, &operations, served_profiles)?;
    let plan = ServicePlan {
        service: ServiceSpec {
            tenant_id: service.tenant,
            device_id: service.device,
            service_id: service.id,
            service_type: service.service_type,
            display_name: service.display_name,
            capabilities,
            version: 1,
            active: true,
        },
        operations,
    };
    validate_service_addition(&plan.service)?;
    Ok(plan)
}

#[derive(Clone, Debug)]
pub struct GrantPlan {
    pub grant: GrantSpec,
}

impl GrantPlan {
    fn summary(&self) -> String {
        format!(
            "tenant={} user={} device={} service={} grant_operations={}{}",
            self.grant.tenant_id,
            self.grant.principal_id,
            self.grant.device_id,
            self.grant.service_id,
            self.grant
                .permissions
                .operations
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
            self.grant
                .expires_at
                .map(|expiry| format!(" expires_at={}", expiry.to_rfc3339()))
                .unwrap_or_default(),
        )
    }
}

/// Build the grant of `set-grant` without contacting Redis.  The write also
/// checks it against the service record (`check_grant`).
pub fn plan_set_grant(
    records_path: &Path,
    now: DateTime<Utc>,
) -> Result<GrantPlan, ProvisioningError> {
    let GrantDocument { grant } = read_document(records_path)?;
    let operations = operation_set("grant.operations", &grant.operations)?;
    check_grant_expiry(grant.expires_at, now)?;
    Ok(GrantPlan {
        grant: GrantSpec {
            tenant_id: grant.tenant,
            principal_id: grant.user,
            device_id: grant.device,
            service_id: grant.service,
            permissions: PermissionSet { operations },
            constraints: serde_json::json!({}),
            expires_at: grant.expires_at,
            active: true,
        },
    })
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn dry_run_line(config: &ServeConfig, command: &str, summary: &str) -> String {
    format!(
        "Catalog change is valid for namespace {}: {command} {summary}. \
         This dry run contacted no Redis authority and wrote nothing.",
        config.redis_namespace
    )
}

fn served_profiles(config: &ServeConfig) -> &[String] {
    config
        .http_forward
        .as_ref()
        .map_or(&[][..], |http_forward| http_forward.profiles.as_slice())
}

/// The connection `serve` makes, including its active-incarnation and
/// Redis-run fence: a change is only written where a relay is serving.
async fn connect(config: &ServeConfig) -> Result<RedisCatalog, ProvisioningError> {
    Ok(redis_connection::connect(
        &config.redis_url,
        &config.redis_namespace,
        &config.deployment_incarnation,
        &tls_material(config),
    )
    .await?)
}

/// Prefix a catalog refusal with the command and the record it concerns.
fn refused(command: &str, what: &str, error: CatalogError) -> ProvisioningError {
    ProvisioningError::Records(format!("{command} refused for {what}: {error}"))
}

const ADD_USER_USAGE: &str = "add-user requires --config PATH --records PATH [--dry-run]";
const ADD_DEVICE_USAGE: &str = "add-device requires --config PATH --records PATH [--dry-run]";
const ADD_SERVICE_USAGE: &str = "add-service requires --config PATH --records PATH [--dry-run]";
const SET_GRANT_USAGE: &str = "set-grant requires --config PATH --records PATH [--dry-run]";
const REVOKE_GRANT_USAGE: &str = "revoke-grant requires --config PATH --tenant UUID --user UUID \
     --device UUID --service UUID [--dry-run]";
const REVOKE_DEVICE_USAGE: &str =
    "revoke-device requires --config PATH --tenant UUID --device UUID [--dry-run]";
const REVOKE_CREDENTIAL_USAGE: &str = "revoke-credential requires --config PATH --tenant UUID \
     --device UUID --credential UUID [--dry-run]";

/// `tunnel-relay add-user`.  Returns the line to print.
pub async fn add_user(args: &[OsString]) -> Result<String, Box<dyn Error>> {
    let arguments = parse_arguments(args, ADD_USER_USAGE, true, &[])?;
    let config = load_config(&arguments.config)?;
    let records = arguments.records.as_deref().expect("records required");
    let plan = plan_add_user(records, &config.oidc_issuer)?;
    if arguments.dry_run {
        return Ok(dry_run_line(&config, "add-user", &plan.summary()));
    }
    let catalog = connect(&config).await?;
    catalog
        .add_user(&plan.user, &plan.identity, &plan.membership)
        .await
        .map_err(|error| refused("add-user", &format!("user {}", plan.user.user_id), error))?;
    Ok(format!(
        "Added to namespace {}: {}.",
        config.redis_namespace,
        plan.summary()
    ))
}

/// `tunnel-relay add-device`.  Returns the line to print.
pub async fn add_device(args: &[OsString]) -> Result<String, Box<dyn Error>> {
    let arguments = parse_arguments(args, ADD_DEVICE_USAGE, true, &[])?;
    let config = load_config(&arguments.config)?;
    let records = arguments.records.as_deref().expect("records required");
    let plan = plan_add_device(records, Utc::now())?;
    if arguments.dry_run {
        return Ok(dry_run_line(&config, "add-device", &plan.summary()));
    }
    let catalog = connect(&config).await?;
    catalog
        .add_device(&plan.device, &plan.credential)
        .await
        .map_err(|error| {
            refused(
                "add-device",
                &format!("device {}", plan.device.device_id),
                error,
            )
        })?;
    Ok(format!(
        "Added to namespace {}: {}.",
        config.redis_namespace,
        plan.summary()
    ))
}

/// `tunnel-relay add-service`.  Returns the line to print.
pub async fn add_service(args: &[OsString]) -> Result<String, Box<dyn Error>> {
    let arguments = parse_arguments(args, ADD_SERVICE_USAGE, true, &[])?;
    let config = load_config(&arguments.config)?;
    let records = arguments.records.as_deref().expect("records required");
    let plan = plan_add_service(records, served_profiles(&config))?;
    if arguments.dry_run {
        return Ok(dry_run_line(&config, "add-service", &plan.summary()));
    }
    let catalog = connect(&config).await?;
    catalog.add_service(&plan.service).await.map_err(|error| {
        refused(
            "add-service",
            &format!("service {}", plan.service.service_id),
            error,
        )
    })?;
    Ok(format!(
        "Added to namespace {}: {}.",
        config.redis_namespace,
        plan.summary()
    ))
}

/// `tunnel-relay set-grant`: add a grant, or replace the grant for the same
/// user, device and service.  Returns the line to print.
pub async fn set_grant(args: &[OsString]) -> Result<String, Box<dyn Error>> {
    let arguments = parse_arguments(args, SET_GRANT_USAGE, true, &[])?;
    let config = load_config(&arguments.config)?;
    let records = arguments.records.as_deref().expect("records required");
    let plan = plan_set_grant(records, Utc::now())?;
    if arguments.dry_run {
        return Ok(dry_run_line(&config, "set-grant", &plan.summary()));
    }
    let catalog = connect(&config).await?;
    let grant = &plan.grant;
    let what = format!("service {} on device {}", grant.service_id, grant.device_id);
    // The service's type and operations decide which grants authorize
    // anything; the catalog's grant script checks only that it exists.
    let service = catalog
        .read_service(grant.tenant_id, grant.device_id, grant.service_id)
        .await
        .map_err(|error| refused("set-grant", &what, error))?
        .filter(|service| service.active)
        .ok_or_else(|| {
            ProvisioningError::Records(format!(
                "set-grant refused for {what}: no active service with that identifier in \
                 tenant {}",
                grant.tenant_id
            ))
        })?;
    let service_operations: BTreeSet<String> = service
        .capabilities
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .map(|operations| {
            operations
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    check_grant(
        &service.service_type,
        &service_operations,
        &grant.permissions.operations,
    )?;
    let snapshot = catalog
        .upsert_grant(grant)
        .await
        .map_err(|error| match error {
            CatalogError::InvalidInput("grant tenant relationship") => {
                ProvisioningError::Records(format!(
                    "set-grant refused for {what}: user {} must be an active member of tenant {}, \
                 and the tenant, device and service must exist",
                    grant.principal_id, grant.tenant_id
                ))
            }
            other => refused("set-grant", &what, other),
        })?;
    Ok(format!(
        "{} grant in namespace {}: {} revision={}.",
        if snapshot.revision == 1 {
            "Added"
        } else {
            "Replaced"
        },
        config.redis_namespace,
        plan.summary(),
        snapshot.revision
    ))
}

fn not_found(command: &str, what: String, error: CatalogError) -> ProvisioningError {
    match error {
        CatalogError::NotFound => {
            ProvisioningError::Records(format!("{command} refused: no {what} in this namespace"))
        }
        other => refused(command, &what, other),
    }
}

/// `tunnel-relay revoke-grant`.  Returns the line to print.
pub async fn revoke_grant(args: &[OsString]) -> Result<String, Box<dyn Error>> {
    let arguments = parse_arguments(
        args,
        REVOKE_GRANT_USAGE,
        false,
        &["--tenant", "--user", "--device", "--service"],
    )?;
    let config = load_config(&arguments.config)?;
    let (tenant, user, device, service) = (
        arguments.id("--tenant"),
        arguments.id("--user"),
        arguments.id("--device"),
        arguments.id("--service"),
    );
    let summary = format!("tenant={tenant} user={user} device={device} service={service}");
    if arguments.dry_run {
        return Ok(dry_run_line(&config, "revoke-grant", &summary));
    }
    let catalog = connect(&config).await?;
    let revision = catalog
        .revoke_grant(tenant, user, device, service, Utc::now())
        .await
        .map_err(|error| not_found("revoke-grant", format!("grant ({summary})"), error))?;
    Ok(format!(
        "Revoked grant in namespace {}: {summary} revision={revision}. New requests are \
         refused now; a stream already admitted ends within its 5 s authorization snapshot.",
        config.redis_namespace
    ))
}

/// `tunnel-relay revoke-device`: deactivate a device, every credential and
/// grant it has, and its owner lease.  Returns the line to print.
pub async fn revoke_device(args: &[OsString]) -> Result<String, Box<dyn Error>> {
    let arguments = parse_arguments(args, REVOKE_DEVICE_USAGE, false, &["--tenant", "--device"])?;
    let config = load_config(&arguments.config)?;
    let (tenant, device) = (arguments.id("--tenant"), arguments.id("--device"));
    let summary = format!("tenant={tenant} device={device}");
    if arguments.dry_run {
        return Ok(dry_run_line(&config, "revoke-device", &summary));
    }
    let catalog = connect(&config).await?;
    let version = catalog
        .revoke_device(tenant, device, Utc::now())
        .await
        .map_err(|error| not_found("revoke-device", format!("device ({summary})"), error))?;
    Ok(format!(
        "Revoked device in namespace {}: {summary} device_version={version}. Its credentials \
         and grants are revoked and its live session is closed at the relay's next \
         maintenance check.",
        config.redis_namespace
    ))
}

/// `tunnel-relay revoke-credential`: revoke one credential of a device, as
/// for a lost key.  Returns the line to print.
pub async fn revoke_credential(args: &[OsString]) -> Result<String, Box<dyn Error>> {
    let arguments = parse_arguments(
        args,
        REVOKE_CREDENTIAL_USAGE,
        false,
        &["--tenant", "--device", "--credential"],
    )?;
    let config = load_config(&arguments.config)?;
    let (tenant, device, credential) = (
        arguments.id("--tenant"),
        arguments.id("--device"),
        arguments.id("--credential"),
    );
    let summary = format!("tenant={tenant} device={device} credential={credential}");
    if arguments.dry_run {
        return Ok(dry_run_line(&config, "revoke-credential", &summary));
    }
    let catalog = connect(&config).await?;
    let version = catalog
        .revoke_credential(tenant, device, credential, Utc::now())
        .await
        .map_err(|error| {
            not_found(
                "revoke-credential",
                format!("active credential ({summary})"),
                error,
            )
        })?;
    Ok(format!(
        "Revoked credential in namespace {}: {summary} device_version={version}. A session \
         using it is closed at the relay's next maintenance check.",
        config.redis_namespace
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    const TENANT: &str = "6f1d7a3e-0b0c-4c1e-9f55-1a2b3c4d5e01";
    const USER: &str = "6f1d7a3e-0b0c-4c1e-9f55-1a2b3c4d5e02";
    const DEVICE: &str = "6f1d7a3e-0b0c-4c1e-9f55-1a2b3c4d5e03";
    const SERVICE: &str = "6f1d7a3e-0b0c-4c1e-9f55-1a2b3c4d5e04";

    #[test]
    fn arguments_require_each_flag_once_and_refuse_anything_else() {
        let parsed = parse_arguments(
            &args(&["--config", "r.toml", "--records", "u.toml", "--dry-run"]),
            ADD_USER_USAGE,
            true,
            &[],
        )
        .expect("complete records arguments");
        assert!(parsed.dry_run);
        assert_eq!(parsed.records, Some(PathBuf::from("u.toml")));
        let parsed = parse_arguments(
            &args(&["--tenant", TENANT, "--config", "r.toml", "--device", DEVICE]),
            REVOKE_DEVICE_USAGE,
            false,
            &["--tenant", "--device"],
        )
        .expect("complete identifier arguments");
        assert_eq!(parsed.id("--device").to_string(), DEVICE);
        assert!(!parsed.dry_run);
        for (bad, records, flags) in [
            (&["--config", "r"][..], true, &[][..]),
            (&["--records", "u"][..], true, &[][..]),
            (
                &["--config", "r", "--records", "u", "--force"][..],
                true,
                &[][..],
            ),
            (
                &["--config", "r", "--records", "u", "--dry-run", "--dry-run"][..],
                true,
                &[][..],
            ),
            (
                &["--config", "r", "--config", "s", "--records", "u"][..],
                true,
                &[][..],
            ),
            (&["--config", "", "--records", "u"][..], true, &[][..]),
            // Revocations take identifiers, never a records document.
            (
                &[
                    "--config",
                    "r",
                    "--records",
                    "u",
                    "--tenant",
                    TENANT,
                    "--device",
                    DEVICE,
                ][..],
                false,
                &["--tenant", "--device"][..],
            ),
            (
                &["--config", "r", "--tenant", TENANT][..],
                false,
                &["--tenant", "--device"][..],
            ),
            (
                &[
                    "--config",
                    "r",
                    "--tenant",
                    "not-a-uuid",
                    "--device",
                    DEVICE,
                ][..],
                false,
                &["--tenant", "--device"][..],
            ),
            (
                &[
                    "--config", "r", "--tenant", TENANT, "--tenant", TENANT, "--device", DEVICE,
                ][..],
                false,
                &["--tenant", "--device"][..],
            ),
            (
                &[
                    "--config", "r", "--tenant", TENANT, "--device", DEVICE, "--user", USER,
                ][..],
                false,
                &["--tenant", "--device"][..],
            ),
            (&["--config"][..], false, &[][..]),
        ] {
            assert!(
                parse_arguments(&args(bad), REVOKE_DEVICE_USAGE, records, flags).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scratch() -> Scratch {
        let dir = std::env::temp_dir().join(format!("m6c31-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create scratch directory");
        Scratch(dir)
    }

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, text).expect("write document");
        path
    }

    #[test]
    fn add_user_plan_binds_the_relay_issuer_and_refuses_bad_documents() {
        let dir = scratch();
        let path = write(
            &dir.0,
            "user.toml",
            &format!(
                "[user]\ntenant = \"{TENANT}\"\nid = \"{USER}\"\ndisplay_name = \"u\"\n\
                 oidc_subject = \"second-user\"\nrole = \"admin\"\n"
            ),
        );
        let plan = plan_add_user(&path, "https://issuer.invalid/").expect("valid user");
        assert_eq!(plan.identity.issuer, "https://issuer.invalid/");
        assert_eq!(plan.identity.subject, "second-user");
        assert_eq!(plan.membership.role, MembershipRole::Admin);
        assert_eq!(plan.membership.tenant_id.to_string(), TENANT);
        // The catalog's own identity rule, applied offline.
        let blank = write(
            &dir.0,
            "blank.toml",
            &format!(
                "[user]\ntenant = \"{TENANT}\"\nid = \"{USER}\"\ndisplay_name = \"u\"\n\
                 oidc_subject = \"  \"\n"
            ),
        );
        let error = plan_add_user(&blank, "https://issuer.invalid/").expect_err("blank subject");
        assert!(error.to_string().contains("user addition"), "{error}");
        // No tenant, an unknown field: refused by the document schema.
        let missing = write(
            &dir.0,
            "missing.toml",
            &format!("[user]\nid = \"{USER}\"\ndisplay_name = \"u\"\noidc_subject = \"s\"\n"),
        );
        assert!(plan_add_user(&missing, "https://issuer.invalid/").is_err());
        let extra = write(
            &dir.0,
            "extra.toml",
            &format!(
                "[user]\ntenant = \"{TENANT}\"\nid = \"{USER}\"\ndisplay_name = \"u\"\n\
                 oidc_subject = \"s\"\ndevice = \"{DEVICE}\"\n"
            ),
        );
        assert!(plan_add_user(&extra, "https://issuer.invalid/").is_err());
    }

    fn certificate(san: &str) -> String {
        let key = rcgen::KeyPair::generate().expect("generate key");
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names.push(rcgen::SanType::URI(
            san.to_owned().try_into().expect("URI SAN"),
        ));
        params.self_signed(&key).expect("self-sign").pem()
    }

    #[test]
    fn add_device_plan_derives_the_credential_and_refuses_another_device_certificate() {
        let dir = scratch();
        let document = format!(
            "[device]\ntenant = \"{TENANT}\"\nowner = \"{USER}\"\nid = \"{DEVICE}\"\n\
             display_name = \"d\"\ncertificate = \"device.pem\"\n"
        );
        let path = write(&dir.0, "device.toml", &document);
        write(
            &dir.0,
            "device.pem",
            &certificate(&format!("urn:agent-tunnel:device:{DEVICE}")),
        );
        let plan = plan_add_device(&path, Utc::now()).expect("valid device");
        assert_eq!(plan.device.owner_user_id.to_string(), USER);
        assert_eq!(plan.credential.spki_fingerprint.len(), 64);
        assert!(plan.summary().contains("spki_sha256="));
        write(
            &dir.0,
            "device.pem",
            &certificate(&format!("urn:agent-tunnel:device:{}", Uuid::new_v4())),
        );
        let error = plan_add_device(&path, Utc::now()).expect_err("another device's SAN");
        assert!(error.to_string().contains("must name device.id"), "{error}");
    }

    #[test]
    fn add_service_plan_applies_the_provisioning_service_rules() {
        let dir = scratch();
        let base = format!(
            "[service]\ntenant = \"{TENANT}\"\ndevice = \"{DEVICE}\"\nid = \"{SERVICE}\"\n\
             display_name = \"s\"\n"
        );
        let echo = write(
            &dir.0,
            "echo.toml",
            &format!("{base}type = \"echo\"\noperations = [\"echo:invoke\"]\n"),
        );
        let plan = plan_add_service(&echo, &[]).expect("echo service");
        assert_eq!(
            plan.service.capabilities,
            serde_json::json!({"operations": ["echo:invoke"]})
        );
        let mcp = write(
            &dir.0,
            "mcp.toml",
            &format!(
                "{base}type = \"http-forward\"\noperations = [\"http:invoke\"]\n\
                 http_forward_profile = \"mcp-2025-11-25\"\n"
            ),
        );
        let error = plan_add_service(&mcp, &[]).expect_err("profile not served");
        assert!(
            error.to_string().contains("is not served by this relay"),
            "{error}"
        );
        let plan = plan_add_service(&mcp, &["mcp-2025-11-25".to_owned()]).expect("served");
        assert!(
            plan.summary()
                .contains("http_forward_profile=mcp-2025-11-25")
        );
        let files = write(
            &dir.0,
            "files.toml",
            &format!("{base}type = \"files\"\noperations = [\"files:read\"]\n"),
        );
        assert!(plan_add_service(&files, &[]).is_err());
    }

    #[test]
    fn set_grant_plan_refuses_wildcards_and_past_expiry_and_check_grant_applies_service_rules() {
        let dir = scratch();
        let grant = |operations: &str, expiry: &str| {
            format!(
                "[grant]\ntenant = \"{TENANT}\"\nuser = \"{USER}\"\ndevice = \"{DEVICE}\"\n\
                 service = \"{SERVICE}\"\noperations = {operations}\n{expiry}"
            )
        };
        let ok = write(&dir.0, "ok.toml", &grant("[\"echo:invoke\"]", ""));
        let plan = plan_set_grant(&ok, Utc::now()).expect("valid grant");
        assert!(plan.grant.permissions.allows("echo:invoke"));
        let wildcard = write(&dir.0, "wild.toml", &grant("[\"*\"]", ""));
        assert!(
            plan_set_grant(&wildcard, Utc::now())
                .expect_err("wildcard")
                .to_string()
                .contains("wildcards are not supported")
        );
        let past = write(
            &dir.0,
            "past.toml",
            &grant(
                "[\"echo:invoke\"]",
                "expires_at = \"2020-01-01T00:00:00Z\"\n",
            ),
        );
        assert!(
            plan_set_grant(&past, Utc::now())
                .expect_err("past expiry")
                .to_string()
                .contains("already in the past")
        );
        // What the write checks against the service record it reads.
        let set = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
        assert!(check_grant("echo", &set(&["echo:invoke"]), &set(&["echo:invoke"])).is_ok());
        assert!(check_grant("echo", &set(&["echo:invoke"]), &set(&["fs:read"])).is_err());
        assert!(check_grant("fs", &set(&["fs:connect", "fs:read"]), &set(&["fs:read"])).is_err());
    }
}
