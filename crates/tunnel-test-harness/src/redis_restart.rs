//! Redis AOF restart acceptance fixture for the M1 catalog.
//!
//! The fixture deliberately goes through the production [`Catalog`] contract:
//! it seeds an active authorization and device credential, claims an owner,
//! records grant and credential revocations, and then releases that owner
//! before the restart boundary.  The companion check reconnects to the same
//! Redis namespace after the caller restarts the container, verifies that the
//! durable revocations survived, and explicitly activates a new owner-fencing
//! incarnation before admitting a fresh owner.
//!
//! This module does not start or stop Redis.  `scripts/m1-redis-restart-verify.sh`
//! owns one pinned, loopback-only container and calls [`redis_restart_seed`],
//! restarts that same container, and then calls [`redis_restart_check`].  The
//! acceptance boundary therefore proves AOF restart recovery for one process
//! and namespace.  It does not prove replication, disk failure recovery, or a
//! multi-node failover.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use tunnel_catalog::{
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, CredentialRecord, FixtureDevice,
    GrantSpec, MembershipRecord, MembershipRole, OwnerClaimRequest, OwnerToken, PermissionSet,
    PrincipalIdentity, RedisCatalog, ServiceSpec, TenantRecord, UserRecord,
};
use uuid::Uuid;

const RECEIPT_VERSION: u8 = 1;
const FIXTURE_ISSUER: &str = "https://issuer.m1.fixture.invalid";
const OLD_DEPLOYMENT_INCARNATION: &str = "m1-redis-restart-old-incarnation";
// Redis owner APIs cap a lease at thirty seconds.  Keep five seconds of
// margin for the container restart and the second harness invocation.
const OWNER_LEASE: Duration = Duration::seconds(25);

/// Errors returned by the seed/check entry points.
#[derive(Debug)]
pub enum RedisRestartError {
    Catalog(CatalogError),
    Io(io::Error),
    Json(serde_json::Error),
    Assertion(String),
}

impl fmt::Display for RedisRestartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(error) => write!(formatter, "catalog operation failed: {error:?}"),
            Self::Io(error) => write!(formatter, "receipt I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "receipt encoding failed: {error}"),
            Self::Assertion(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for RedisRestartError {}

impl From<CatalogError> for RedisRestartError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

impl From<io::Error> for RedisRestartError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for RedisRestartError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// Identifiers needed by the second process.  This file contains only
/// synthetic fixture identifiers and owner fencing tokens; it never contains
/// a private key, certificate body, access token, or payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisRestartReceipt {
    pub version: u8,
    pub namespace: String,
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub device_id: Uuid,
    pub service_id: Uuid,
    pub credential_id: Uuid,
    pub spki_fingerprint: String,
    pub old_owner: OwnerToken,
    pub new_deployment_incarnation: String,
}

impl RedisRestartReceipt {
    fn write_to(&self, path: &Path) -> Result<(), RedisRestartError> {
        let bytes = serde_json::to_vec_pretty(self)?;
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    fn read_from(path: &Path) -> Result<Self, RedisRestartError> {
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn validate_for_namespace(&self, namespace: &str) -> Result<(), RedisRestartError> {
        if self.version != RECEIPT_VERSION {
            return Err(RedisRestartError::Assertion(format!(
                "unsupported Redis restart receipt version {}",
                self.version
            )));
        }
        if self.namespace != namespace {
            return Err(RedisRestartError::Assertion(
                "Redis restart receipt namespace does not match the requested namespace".into(),
            ));
        }
        if self.old_owner.tenant_id != self.tenant_id
            || self.old_owner.device_id != self.device_id
            || self.new_deployment_incarnation.is_empty()
        {
            return Err(RedisRestartError::Assertion(
                "Redis restart receipt owner token is for a different fixture".into(),
            ));
        }
        if self.old_owner.deployment_incarnation == self.new_deployment_incarnation {
            return Err(RedisRestartError::Assertion(
                "Redis restart receipt does not contain a new owner incarnation".into(),
            ));
        }
        Ok(())
    }
}

/// Seed the production Redis catalog and write the receipt used after restart.
pub async fn redis_restart_seed(
    redis_url: &str,
    namespace: &str,
    receipt_file: impl AsRef<Path>,
) -> Result<(), RedisRestartError> {
    let derived_incarnation = format!("m1-redis-restart-new-{namespace}");
    redis_restart_seed_with_incarnation(redis_url, namespace, receipt_file, &derived_incarnation)
        .await
}

/// Seed variant for callers that obtain the replacement deployment
/// incarnation from an operator or an external harness run ID.  Keeping this
/// value outside the catalog crate prevents a restart check from silently
/// inventing authority after an ambiguous Redis restore.
pub async fn redis_restart_seed_with_incarnation(
    redis_url: &str,
    namespace: &str,
    receipt_file: impl AsRef<Path>,
    new_deployment_incarnation: &str,
) -> Result<(), RedisRestartError> {
    if new_deployment_incarnation.trim().is_empty()
        || new_deployment_incarnation == OLD_DEPLOYMENT_INCARNATION
    {
        return Err(RedisRestartError::Assertion(
            "replacement deployment incarnation must differ from the seeded incarnation".into(),
        ));
    }
    let catalog = RedisCatalog::connect(redis_url, namespace).await?;
    let now = Utc::now();
    let fixture = restart_fixture(now);
    let tenant_id = fixture.tenants[0].tenant_id;
    let principal_id = fixture.users[0].user_id;
    let device_id = fixture.devices[0].device_id;
    let service_id = fixture.services[0].service_id;
    let credential = &fixture.credentials[0];

    catalog.seed_fixture(&fixture).await?;

    let principal = AuthenticatedConsumer {
        tenant_id,
        principal_id,
    };
    let active_grant = catalog
        .authorize(&principal, device_id, service_id, now, Utc::now())
        .await?
        .ok_or_else(|| {
            RedisRestartError::Assertion(
                "seeded Redis catalog did not return its active authorization".into(),
            )
        })?;
    if !active_grant.permissions.allows("echo:invoke") {
        return Err(RedisRestartError::Assertion(
            "seeded Redis grant is missing echo:invoke".into(),
        ));
    }
    if catalog
        .resolve_device(&credential.spki_fingerprint, Utc::now())
        .await?
        .is_none()
    {
        return Err(RedisRestartError::Assertion(
            "seeded Redis catalog did not return its active device credential".into(),
        ));
    }

    let mut owner_catalog = RedisCatalog::connect(redis_url, namespace).await?;
    owner_catalog.configure_deployment_incarnation(OLD_DEPLOYMENT_INCARNATION)?;
    owner_catalog.activate_deployment_incarnation().await?;
    let old_owner = owner_catalog
        .claim_owner(&owner_request(
            tenant_id,
            device_id,
            OLD_DEPLOYMENT_INCARNATION,
            "m1-restart-node-a",
            "m1-restart-boot-a",
            "m1-restart-session-a",
            now,
        ))
        .await?
        .token;

    // Owner leases are ephemeral and must not be treated as durable catalog
    // state.  Release the seeded owner before the restart; the receipt keeps
    // its complete token so recovery can prove that it cannot be reused.
    if !owner_catalog.release_owner(&old_owner).await? {
        return Err(RedisRestartError::Assertion(
            "seeded Redis catalog did not release the first owner incarnation".into(),
        ));
    }

    // Keep the device active so authorization revocation remains independent
    // from the owner-fencing transition.
    let revoked_at = Utc::now();
    catalog
        .revoke_grant(tenant_id, principal_id, device_id, service_id, revoked_at)
        .await?;
    catalog
        .revoke_credential(tenant_id, device_id, credential.credential_id, revoked_at)
        .await?;

    if owner_catalog
        .authorize(&principal, device_id, service_id, revoked_at, Utc::now())
        .await?
        .is_some()
    {
        return Err(RedisRestartError::Assertion(
            "Redis catalog returned a grant after revocation".into(),
        ));
    }
    if owner_catalog
        .resolve_device(&credential.spki_fingerprint, Utc::now())
        .await?
        .is_some()
    {
        return Err(RedisRestartError::Assertion(
            "Redis catalog returned a credential after revocation".into(),
        ));
    }

    let receipt = RedisRestartReceipt {
        version: RECEIPT_VERSION,
        namespace: namespace.to_owned(),
        tenant_id,
        principal_id,
        device_id,
        service_id,
        credential_id: credential.credential_id,
        spki_fingerprint: credential.spki_fingerprint.clone(),
        old_owner,
        new_deployment_incarnation: new_deployment_incarnation.to_owned(),
    };
    receipt.write_to(receipt_file.as_ref())
}

/// Reconnect to the same Redis namespace and verify the post-restart fence.
pub async fn redis_restart_check(
    redis_url: &str,
    namespace: &str,
    receipt_file: impl AsRef<Path>,
) -> Result<(), RedisRestartError> {
    let receipt = RedisRestartReceipt::read_from(receipt_file.as_ref())?;
    receipt.validate_for_namespace(namespace)?;
    // Read durable catalog records through an unconfigured connection first.
    // Owner operations remain unavailable until the explicit recovery step
    // below has fenced the pre-restart Redis run.
    let catalog = RedisCatalog::connect(redis_url, namespace).await?;
    let principal = AuthenticatedConsumer {
        tenant_id: receipt.tenant_id,
        principal_id: receipt.principal_id,
    };
    let now = Utc::now();

    if catalog
        .resolve_consumer(
            FIXTURE_ISSUER,
            &format!("subject-{}", receipt.principal_id),
            Some(receipt.tenant_id),
        )
        .await?
        .is_none()
    {
        return Err(RedisRestartError::Assertion(
            "seeded Redis identity or membership did not survive AOF restart".into(),
        ));
    }

    if catalog
        .authorize(&principal, receipt.device_id, receipt.service_id, now, now)
        .await?
        .is_some()
    {
        return Err(RedisRestartError::Assertion(
            "revoked Redis grant resurrected after AOF restart".into(),
        ));
    }
    if catalog
        .resolve_device(&receipt.spki_fingerprint, now)
        .await?
        .is_some()
    {
        return Err(RedisRestartError::Assertion(
            "revoked Redis credential resurrected after AOF restart".into(),
        ));
    }

    // A normal owner-enabled connection carrying the old incarnation must
    // reject the changed Redis server run ID.  This check prevents a stale
    // owner from using the durable catalog connection as a recovery shortcut.
    match RedisCatalog::connect_with_deployment_incarnation(
        redis_url,
        namespace,
        &receipt.old_owner.deployment_incarnation,
    )
    .await
    {
        Err(CatalogError::Conflict("active deployment incarnation or Redis authority run")) => {}
        Err(error) => return Err(error.into()),
        Ok(_) => {
            return Err(RedisRestartError::Assertion(
                "stale owner-enabled Redis connection accepted the old server run".into(),
            ));
        }
    }

    let stale_recovery = RedisCatalog::connect_for_recovery(
        redis_url,
        namespace,
        &receipt.old_owner.deployment_incarnation,
    )
    .await?;
    match stale_recovery.activate_deployment_incarnation().await {
        Err(CatalogError::Conflict("active deployment incarnation")) => {}
        Err(error) => return Err(error.into()),
        Ok(()) => {
            return Err(RedisRestartError::Assertion(
                "recovery reused the pre-restart deployment incarnation".into(),
            ));
        }
    }

    // Recovery is an explicit operator boundary.  It records the new Redis
    // run ID and deployment incarnation before any owner mutation is allowed.
    let recovery = RedisCatalog::connect_for_recovery(
        redis_url,
        namespace,
        &receipt.new_deployment_incarnation,
    )
    .await?;
    recovery.activate_deployment_incarnation().await?;

    if recovery
        .current_owner(receipt.tenant_id, receipt.device_id, now)
        .await?
        .is_some()
    {
        return Err(RedisRestartError::Assertion(
            "Redis owner state was restored across recovery instead of being fenced".into(),
        ));
    }

    if recovery
        .renew_owner(&receipt.old_owner, now + OWNER_LEASE)
        .await?
    {
        return Err(RedisRestartError::Assertion(
            "stale Redis owner renewed after an explicit new incarnation".into(),
        ));
    }
    if recovery.release_owner(&receipt.old_owner).await? {
        return Err(RedisRestartError::Assertion(
            "stale Redis owner released the post-restart incarnation".into(),
        ));
    }

    let new_owner = recovery
        .claim_owner(&owner_request(
            receipt.tenant_id,
            receipt.device_id,
            &receipt.new_deployment_incarnation,
            "m1-restart-node-recovered",
            "m1-restart-boot-recovered",
            "m1-restart-session-recovered",
            now,
        ))
        .await?
        .token;
    if new_owner.epoch <= receipt.old_owner.epoch {
        return Err(RedisRestartError::Assertion(
            "post-restart owner epoch did not advance past the stale token".into(),
        ));
    }
    let current = recovery
        .current_owner(receipt.tenant_id, receipt.device_id, Utc::now())
        .await?
        .ok_or_else(|| {
            RedisRestartError::Assertion(
                "fresh owner was not visible after explicit recovery".into(),
            )
        })?;
    if current.token != new_owner {
        return Err(RedisRestartError::Assertion(
            "post-restart owner readback did not match the fresh token".into(),
        ));
    }
    Ok(())
}

/// Short aliases for harness command dispatchers.
pub async fn seed(
    redis_url: &str,
    namespace: &str,
    receipt_file: impl AsRef<Path>,
) -> Result<(), RedisRestartError> {
    redis_restart_seed(redis_url, namespace, receipt_file).await
}

/// Short alias for dispatchers that pass an externally approved incarnation.
pub async fn seed_with_incarnation(
    redis_url: &str,
    namespace: &str,
    receipt_file: impl AsRef<Path>,
    new_deployment_incarnation: &str,
) -> Result<(), RedisRestartError> {
    redis_restart_seed_with_incarnation(
        redis_url,
        namespace,
        receipt_file,
        new_deployment_incarnation,
    )
    .await
}

/// Short aliases for harness command dispatchers.
pub async fn check(
    redis_url: &str,
    namespace: &str,
    receipt_file: impl AsRef<Path>,
) -> Result<(), RedisRestartError> {
    redis_restart_check(redis_url, namespace, receipt_file).await
}

/// Shared with the live-catalog restart command in
/// [`crate::redis_lane_restart`], which seeds the same synthetic records
/// through the same production `Catalog` contract.
pub(crate) fn restart_fixture(now: chrono::DateTime<Utc>) -> CatalogFixture {
    let tenant_id = Uuid::new_v4();
    let principal_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let service_id = Uuid::new_v4();
    let credential_id = Uuid::new_v4();
    let spki_fingerprint = format!("{:064x}", credential_id.as_u128());

    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id,
            display_name: "M1 Redis restart fixture".into(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: principal_id,
            display_name: "synthetic M1 fixture user".into(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: FIXTURE_ISSUER.into(),
            subject: format!("subject-{principal_id}"),
            user_id: principal_id,
        }],
        memberships: vec![MembershipRecord {
            tenant_id,
            user_id: principal_id,
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            display_name: "synthetic Redis restart device".into(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id,
            device_id,
            credential_id,
            spki_fingerprint,
            serial: Some(format!("serial-{credential_id}")),
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::hours(1),
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id,
            device_id,
            service_id,
            service_type: "echo".into(),
            display_name: "synthetic restart echo".into(),
            capabilities: serde_json::json!({"operations":["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            permissions: PermissionSet {
                operations: std::collections::BTreeSet::from(["echo:invoke".into()]),
            },
            constraints: serde_json::json!({"max_bytes":4096}),
            expires_at: Some(now + Duration::hours(1)),
            active: true,
        }],
    }
}

fn owner_request(
    tenant_id: Uuid,
    device_id: Uuid,
    deployment_incarnation: &str,
    node_id: &str,
    boot_id: &str,
    session_id: &str,
    now: chrono::DateTime<Utc>,
) -> OwnerClaimRequest {
    OwnerClaimRequest {
        deployment_incarnation: deployment_incarnation.into(),
        tenant_id,
        device_id,
        node_id: node_id.into(),
        boot_id: boot_id.into(),
        session_id: session_id.into(),
        lease_expires_at: now + OWNER_LEASE,
    }
}
