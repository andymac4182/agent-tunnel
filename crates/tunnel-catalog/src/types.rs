use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub type TenantId = Uuid;
pub type UserId = Uuid;
pub type DeviceId = Uuid;
pub type ServiceId = Uuid;
pub type CredentialId = Uuid;
pub type GrantRevision = u64;

/// Identity produced only after a consumer credential has passed issuer,
/// subject, audience, lifetime, and scope validation and has been mapped to a
/// durable membership.  There is intentionally no tenant claim here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedConsumer {
    pub tenant_id: TenantId,
    pub principal_id: UserId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalIdentity {
    pub issuer: String,
    pub subject: String,
    pub user_id: UserId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRecord {
    pub tenant_id: TenantId,
    pub display_name: String,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    pub user_id: UserId,
    pub display_name: String,
}

/// Roles are catalog facts.  Authorization for a service still requires an
/// explicit grant; a membership role never becomes a service permission by
/// itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    #[default]
    Member,
    Admin,
}

impl MembershipRole {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRecord {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub role: MembershipRole,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
    pub credential_id: CredentialId,
    /// Lower-case SHA-256 hex of the certificate public-key SPKI.  Private
    /// keys and certificate bodies are never part of this record.
    pub spki_fingerprint: String,
    pub serial: Option<String>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
    pub owner_user_id: UserId,
    pub credential_id: CredentialId,
    pub spki_fingerprint: String,
    pub credential_not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub credential_revoked_at: Option<DateTime<Utc>>,
    pub device_active: bool,
    pub credential_active: bool,
    pub device_version: GrantRevision,
    pub owner_epoch: u64,
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
    pub service_id: ServiceId,
    pub service_type: String,
    pub display_name: String,
    pub capabilities: serde_json::Value,
    pub version: GrantRevision,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceSpec {
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
    pub service_id: ServiceId,
    pub service_type: String,
    pub display_name: String,
    #[serde(default)]
    pub capabilities: serde_json::Value,
    #[serde(default = "default_revision")]
    pub version: GrantRevision,
    #[serde(default = "default_active")]
    pub active: bool,
}

/// Grant operations are opaque capability names at this layer.  Concrete
/// adapters define names such as `echo:invoke`, `fs:read`, or `fs:write`,
/// while the catalog preserves the set without granting anything implicitly.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    #[serde(default)]
    pub operations: BTreeSet<String>,
}

impl PermissionSet {
    pub fn allows(&self, operation: &str) -> bool {
        self.operations.contains(operation)
    }
}

pub type GrantConstraints = serde_json::Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantSpec {
    pub tenant_id: TenantId,
    pub principal_id: UserId,
    pub device_id: DeviceId,
    pub service_id: ServiceId,
    pub permissions: PermissionSet,
    #[serde(default = "default_constraints")]
    pub constraints: GrantConstraints,
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default = "default_active")]
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantSnapshot {
    pub tenant_id: TenantId,
    pub principal_id: UserId,
    pub device_id: DeviceId,
    pub service_id: ServiceId,
    pub revision: GrantRevision,
    pub permissions: PermissionSet,
    pub constraints: GrantConstraints,
    /// The authoritative wall-clock expiry.  Relay actors convert this to a
    /// monotonic deadline anchored at `read_started_at`.
    pub valid_until: DateTime<Utc>,
    pub read_started_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceListFilter {
    pub service_id: Option<ServiceId>,
    pub owner_user_id: Option<UserId>,
    /// Inactive devices remain hidden by default.  Offline is a presence state
    /// and is still listed when the durable device is active.
    pub include_inactive: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
    pub owner_user_id: UserId,
    pub display_name: String,
    pub active: bool,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub services: Vec<ServiceRecord>,
    pub grant_revision: GrantRevision,
}

/// The full fencing identity of a live device owner.  A partial token cannot
/// renew or release a lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerToken {
    pub deployment_incarnation: String,
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
    pub node_id: String,
    pub boot_id: String,
    pub session_id: String,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerClaimRequest {
    pub deployment_incarnation: String,
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
    pub node_id: String,
    pub boot_id: String,
    pub session_id: String,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerClaim {
    pub token: OwnerToken,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CatalogFixture {
    #[serde(default)]
    pub tenants: Vec<TenantRecord>,
    #[serde(default)]
    pub users: Vec<UserRecord>,
    #[serde(default)]
    pub identities: Vec<PrincipalIdentity>,
    #[serde(default)]
    pub memberships: Vec<MembershipRecord>,
    #[serde(default)]
    pub devices: Vec<FixtureDevice>,
    #[serde(default)]
    pub credentials: Vec<CredentialRecord>,
    #[serde(default)]
    pub services: Vec<ServiceSpec>,
    #[serde(default)]
    pub grants: Vec<GrantSpec>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FixtureDevice {
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
    pub owner_user_id: UserId,
    pub display_name: String,
    #[serde(default = "default_active")]
    pub active: bool,
    pub last_seen_at: Option<DateTime<Utc>>,
}

fn default_revision() -> GrantRevision {
    1
}

fn default_active() -> bool {
    true
}

fn default_constraints() -> GrantConstraints {
    serde_json::Value::Object(serde_json::Map::new())
}
