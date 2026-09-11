//! Durable tenant-scoped identity and authorization records for the relay.
//!
//! The catalog is deliberately narrower than the relay runtime.  It answers
//! identity, grant, and ownership questions and does not own sockets, stream
//! buffers, or adapter state. Every record is tenant-qualified in the
//! authoritative Redis namespace.

mod cluster;
mod error;
mod memory;
mod oidc;
pub mod recovery;
mod redis;
mod types;

pub use error::{CatalogConnectionError, CatalogConnectionStage, CatalogError};
pub use memory::MemoryCatalog;
pub use oidc::{
    ApprovedJwk, OidcConfig, OidcError, OidcVerifier, ValidatedAccessToken, ValidatedClaims,
};
pub use recovery::{
    RecoveryApproval, RecoveryApprovalIssuer, RecoveryApprovalVerifier, RecoveryError,
    RecoveryPolicy, SignedRecoveryApproval, TrustedRecoveryKey, VerifiedRecoveryApproval,
};
pub use redis::{
    DurableCatalogObservation, RedisCatalog, RedisMembershipPublisher, RedisTlsOptions,
};
pub use types::{
    AttachmentPurpose, AttachmentTicket, AttachmentTicketBinding, AttachmentTicketConsumeRequest,
    AttachmentTicketIssueRequest, AttachmentTicketLocator, AuthenticatedConsumer, CatalogFixture,
    ConsumedAttachmentTicket, CredentialId, CredentialRecord, DeviceId, DeviceIdentity,
    DeviceListFilter, DeviceSummary, FixtureDevice, GrantConstraints, GrantRevision, GrantSnapshot,
    GrantSpec, MAX_ATTACHMENT_TICKETS_PER_DEVICE, MAX_SIGNED_MEMBERSHIP_BYTES,
    MAX_SIGNED_MEMBERSHIP_RECORDS, MembershipRecord, MembershipRole, OwnerClaim, OwnerClaimRequest,
    OwnerToken, PermissionSet, PrincipalIdentity, ServiceId, ServiceRecord, ServiceSpec,
    SignedMembershipRecord, TenantId, TenantRecord, UserId, UserRecord,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A shared, object-safe catalog used by Axum handlers and owner actors.
///
/// Methods intentionally return typed, bounded records rather than backend
/// rows. Implementations must perform authorization and tenant checks in the
/// same authoritative operation where possible.
#[async_trait]
pub trait Catalog: Send + Sync {
    /// Resolve a certificate's SPKI fingerprint to its currently usable
    /// device credential.  Expired, revoked, disabled, and unknown credentials
    /// resolve to `Ok(None)` so callers cannot accidentally treat them as live.
    async fn resolve_device(
        &self,
        spki_fingerprint: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<DeviceIdentity>, CatalogError>;

    /// Compatibility spelling for TLS/device-listener call sites.  It is a
    /// default alias so the catalog has one authoritative implementation.
    async fn resolve_credential(
        &self,
        spki_fingerprint: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<DeviceIdentity>, CatalogError> {
        self.resolve_device(spki_fingerprint, at).await
    }

    /// Resolve an issuer/subject identity into one tenant membership.  A
    /// caller supplying `tenant_id` must be checked against the durable
    /// membership; the token's optional tenant claim is never consulted.
    async fn resolve_consumer(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: Option<Uuid>,
    ) -> Result<Option<AuthenticatedConsumer>, CatalogError>;

    /// Compatibility spelling for the consumer-authentication boundary.
    async fn authenticate_consumer(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: Option<Uuid>,
    ) -> Result<Option<AuthenticatedConsumer>, CatalogError> {
        self.resolve_consumer(issuer, subject, tenant_id).await
    }

    /// Take an authorization snapshot whose validity is bounded from the
    /// authoritative read start.  `read_started_at` is supplied by the caller
    /// so a relay can anchor its monotonic deadline before queueing work.
    async fn authorize(
        &self,
        principal: &AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        read_started_at: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> Result<Option<GrantSnapshot>, CatalogError>;

    /// List only devices visible to the authenticated principal.  The
    /// implementation must not use a caller-supplied tenant field; tenant is
    /// derived from `principal` and repeated in every join predicate.
    async fn list_devices_filtered(
        &self,
        principal: &AuthenticatedConsumer,
        filter: &DeviceListFilter,
        at: DateTime<Utc>,
    ) -> Result<Vec<DeviceSummary>, CatalogError>;

    /// Compatibility spelling for route handlers that already apply a
    /// principal-derived filter.
    async fn list_devices(
        &self,
        principal: &AuthenticatedConsumer,
        filter: &DeviceListFilter,
        at: DateTime<Utc>,
    ) -> Result<Vec<DeviceSummary>, CatalogError> {
        self.list_devices_filtered(principal, filter, at).await
    }

    /// Apply a grant replacement and atomically advance its revision.
    async fn upsert_grant(&self, spec: &GrantSpec) -> Result<GrantSnapshot, CatalogError>;

    /// Revoke a grant while preserving its monotonic revision row.
    async fn revoke_grant(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        device_id: Uuid,
        service_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError>;

    /// Disable a device and all credentials bound to it.  This is an
    /// administrative mutation and is intentionally tenant-qualified.
    async fn revoke_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError>;

    /// Revoke one certificate credential without changing another credential
    /// on the same device.
    async fn revoke_credential(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        credential_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError>;

    /// Seed synthetic records for a local fixture or an administrator-owned
    /// harness.  Production enrollment should use a separately authorized
    /// workflow rather than expose this method as a public route.
    async fn seed_fixture(&self, fixture: &CatalogFixture) -> Result<(), CatalogError>;

    /// Atomically claim a device owner. Redis implementations use a single Lua
    /// operation and the complete owner token contract for fencing.
    async fn claim_owner(&self, request: &OwnerClaimRequest) -> Result<OwnerClaim, CatalogError>;

    /// Renew only the exact current owner token.  A stale owner receives
    /// `Ok(false)` and must stop dispatch.
    async fn renew_owner(
        &self,
        token: &OwnerToken,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<bool, CatalogError>;

    /// Release only an exact owner token.  Cleanup from a stale process cannot
    /// delete a successor's lease.
    async fn release_owner(&self, token: &OwnerToken) -> Result<bool, CatalogError>;

    /// Compatibility spelling for owner-epoch cleanup paths.
    async fn release_epoch(&self, token: &OwnerToken) -> Result<bool, CatalogError> {
        self.release_owner(token).await
    }

    /// Read the current owner token for diagnostics and direct routing.
    async fn current_owner(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<Option<OwnerClaim>, CatalogError>;

    /// Issue a short-lived, one-use data attachment ticket bound to the
    /// complete owner token and authenticated device key.
    async fn issue_attachment_ticket(
        &self,
        request: &AttachmentTicketIssueRequest,
    ) -> Result<AttachmentTicket, CatalogError>;

    /// Atomically consume one attachment ticket.  Any uncertain Redis result
    /// is surfaced as a database error and callers must fail closed.
    async fn consume_attachment_ticket(
        &self,
        request: &AttachmentTicketConsumeRequest,
    ) -> Result<ConsumedAttachmentTicket, CatalogError>;

    /// Read the latest opaque signed membership bytes.  Verification is owned
    /// by the cluster trust layer and is intentionally absent from this trait.
    async fn read_signed_membership(&self) -> Result<Option<SignedMembershipRecord>, CatalogError>;

    /// Read the bounded opaque signed membership directory.  Each returned
    /// value is one independently signed relay record; the catalog never
    /// verifies or promotes these bytes to trust anchors.
    async fn read_signed_memberships(&self) -> Result<Vec<SignedMembershipRecord>, CatalogError> {
        Ok(self.read_signed_membership().await?.into_iter().collect())
    }
}

/// The object type used by relay state owners.
pub type SharedCatalog = std::sync::Arc<dyn Catalog>;

/// The bounded authorization lifetime required by the cluster contract.
pub const MAX_AUTHORIZATION_SNAPSHOT: chrono::Duration = chrono::Duration::seconds(5);

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::collections::BTreeSet;

    fn fixture() -> CatalogFixture {
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let user_a = Uuid::from_u128(11);
        let user_b = Uuid::from_u128(12);
        let device = Uuid::from_u128(21);
        let service = Uuid::from_u128(31);
        let now = Utc::now();
        CatalogFixture {
            tenants: vec![
                TenantRecord {
                    tenant_id: tenant_a,
                    display_name: "tenant-a".into(),
                    active: true,
                },
                TenantRecord {
                    tenant_id: tenant_b,
                    display_name: "tenant-b".into(),
                    active: true,
                },
            ],
            users: vec![
                UserRecord {
                    user_id: user_a,
                    display_name: "Alice".into(),
                },
                UserRecord {
                    user_id: user_b,
                    display_name: "Bob".into(),
                },
            ],
            identities: vec![
                PrincipalIdentity {
                    issuer: "https://issuer.example".into(),
                    subject: "alice".into(),
                    user_id: user_a,
                },
                PrincipalIdentity {
                    issuer: "https://issuer.example".into(),
                    subject: "bob".into(),
                    user_id: user_b,
                },
            ],
            memberships: vec![
                MembershipRecord {
                    tenant_id: tenant_a,
                    user_id: user_a,
                    role: MembershipRole::Member,
                    active: true,
                },
                MembershipRecord {
                    tenant_id: tenant_b,
                    user_id: user_b,
                    role: MembershipRole::Member,
                    active: true,
                },
            ],
            devices: vec![
                FixtureDevice {
                    tenant_id: tenant_a,
                    device_id: device,
                    owner_user_id: user_a,
                    display_name: "Alice Mac".into(),
                    active: true,
                    last_seen_at: Some(now),
                },
                FixtureDevice {
                    tenant_id: tenant_b,
                    device_id: device,
                    owner_user_id: user_b,
                    display_name: "Bob Mac".into(),
                    active: true,
                    last_seen_at: Some(now),
                },
            ],
            credentials: vec![
                CredentialRecord {
                    tenant_id: tenant_a,
                    device_id: device,
                    credential_id: Uuid::from_u128(41),
                    spki_fingerprint:
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    serial: Some("a".into()),
                    not_before: now - Duration::seconds(1),
                    expires_at: now + Duration::hours(1),
                    revoked_at: None,
                    active: true,
                },
                CredentialRecord {
                    tenant_id: tenant_b,
                    device_id: device,
                    credential_id: Uuid::from_u128(42),
                    spki_fingerprint:
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                    serial: Some("b".into()),
                    not_before: now - Duration::seconds(1),
                    expires_at: now + Duration::hours(1),
                    revoked_at: None,
                    active: true,
                },
            ],
            services: vec![
                ServiceSpec {
                    tenant_id: tenant_a,
                    device_id: device,
                    service_id: service,
                    service_type: "echo".into(),
                    display_name: "Echo".into(),
                    capabilities: serde_json::json!({"operations":["echo:invoke"]}),
                    version: 1,
                    active: true,
                },
                ServiceSpec {
                    tenant_id: tenant_b,
                    device_id: device,
                    service_id: service,
                    service_type: "echo".into(),
                    display_name: "Echo".into(),
                    capabilities: serde_json::json!({"operations":["echo:invoke"]}),
                    version: 1,
                    active: true,
                },
            ],
            grants: vec![
                GrantSpec {
                    tenant_id: tenant_a,
                    principal_id: user_a,
                    device_id: device,
                    service_id: service,
                    permissions: PermissionSet {
                        operations: BTreeSet::from(["echo:invoke".into()]),
                    },
                    constraints: serde_json::json!({}),
                    expires_at: Some(now + Duration::hours(1)),
                    active: true,
                },
                GrantSpec {
                    tenant_id: tenant_b,
                    principal_id: user_b,
                    device_id: device,
                    service_id: service,
                    permissions: PermissionSet {
                        operations: BTreeSet::from(["echo:invoke".into()]),
                    },
                    constraints: serde_json::json!({}),
                    expires_at: Some(now + Duration::hours(1)),
                    active: true,
                },
            ],
        }
    }

    #[tokio::test]
    async fn memory_catalog_keeps_same_ids_isolated_by_tenant() {
        let catalog = MemoryCatalog::new();
        catalog.seed_fixture(&fixture()).await.unwrap();
        let now = Utc::now();
        let alice = catalog
            .resolve_consumer("https://issuer.example", "alice", None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alice.tenant_id, Uuid::from_u128(1));
        assert!(
            catalog
                .authorize(&alice, Uuid::from_u128(21), Uuid::from_u128(31), now, now)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            catalog
                .authorize(&alice, Uuid::from_u128(21), Uuid::from_u128(31), now, now)
                .await
                .unwrap()
                .unwrap()
                .permissions
                .allows("echo:invoke")
        );
        let bob = AuthenticatedConsumer {
            tenant_id: Uuid::from_u128(2),
            principal_id: Uuid::from_u128(12),
        };
        assert_eq!(
            catalog
                .list_devices_filtered(&bob, &DeviceListFilter::default(), now)
                .await
                .unwrap()
                .len(),
            1
        );
        let wrong_tenant = AuthenticatedConsumer {
            tenant_id: Uuid::from_u128(1),
            principal_id: Uuid::from_u128(12),
        };
        assert!(
            catalog
                .authorize(
                    &wrong_tenant,
                    Uuid::from_u128(21),
                    Uuid::from_u128(31),
                    now,
                    now
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn memory_grant_revisions_and_owner_fencing_are_monotonic() {
        let catalog = MemoryCatalog::new();
        catalog.seed_fixture(&fixture()).await.unwrap();
        let now = Utc::now();
        let spec = fixture().grants.into_iter().next().unwrap();
        let first = catalog.upsert_grant(&spec).await.unwrap();
        let second = catalog.upsert_grant(&spec).await.unwrap();
        assert!(second.revision > first.revision);
        assert_eq!(
            catalog
                .revoke_grant(
                    spec.tenant_id,
                    spec.principal_id,
                    spec.device_id,
                    spec.service_id,
                    now
                )
                .await
                .unwrap(),
            second.revision + 1
        );

        let request = OwnerClaimRequest {
            deployment_incarnation: "inc-1".into(),
            tenant_id: spec.tenant_id,
            device_id: spec.device_id,
            node_id: "node-a".into(),
            boot_id: "boot-a".into(),
            session_id: "session-a".into(),
            lease_expires_at: now + Duration::seconds(1),
        };
        let claim = catalog.claim_owner(&request).await.unwrap();
        let competing = OwnerClaimRequest {
            node_id: "node-b".into(),
            boot_id: "boot-b".into(),
            session_id: "session-b".into(),
            ..request.clone()
        };
        assert!(matches!(
            catalog.claim_owner(&competing).await,
            Err(CatalogError::OwnerBusy)
        ));
        assert!(
            !catalog
                .release_owner(&OwnerToken {
                    node_id: "stale".into(),
                    ..claim.token.clone()
                })
                .await
                .unwrap()
        );
        assert!(catalog.release_owner(&claim.token).await.unwrap());
        let replacement = catalog.claim_owner(&competing).await.unwrap();
        assert!(replacement.token.epoch > claim.token.epoch);
    }

    #[tokio::test]
    async fn memory_device_revocation_fences_owner_and_advances_epoch() {
        let catalog = MemoryCatalog::new();
        let fixture = fixture();
        catalog.seed_fixture(&fixture).await.unwrap();
        let now = Utc::now();
        let device = fixture.devices[0].device_id;
        let tenant = fixture.devices[0].tenant_id;
        let credential = &fixture.credentials[0];
        let claim = catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: "revocation-test".into(),
                tenant_id: tenant,
                device_id: device,
                node_id: "node-a".into(),
                boot_id: "boot-a".into(),
                session_id: "session-a".into(),
                lease_expires_at: now + Duration::seconds(10),
            })
            .await
            .unwrap();
        let version_before = catalog
            .resolve_device(&credential.spki_fingerprint, now)
            .await
            .unwrap()
            .unwrap()
            .device_version;

        let version_after = catalog.revoke_device(tenant, device, now).await.unwrap();
        assert!(version_after > version_before);
        assert!(
            catalog
                .current_owner(tenant, device, now)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !catalog
                .renew_owner(&claim.token, now + Duration::seconds(10))
                .await
                .unwrap()
        );
        assert!(matches!(
            catalog
                .claim_owner(&OwnerClaimRequest {
                    deployment_incarnation: "replacement-while-revoked".into(),
                    tenant_id: tenant,
                    device_id: device,
                    node_id: "node-b".into(),
                    boot_id: "boot-b".into(),
                    session_id: "session-b".into(),
                    lease_expires_at: now + Duration::seconds(10),
                })
                .await,
            Err(CatalogError::NotFound)
        ));

        // MemoryCatalog is a resettable unit-test double. Redis fixture
        // namespaces use a one-shot reservation and require a new namespace
        // after a partial or completed seed; this replacement models an
        // explicit in-process test fixture reset only.
        let mut restored = fixture.clone();
        restored.devices[0].active = true;
        restored.credentials[0].active = true;
        restored.credentials[0].revoked_at = None;
        catalog.seed_fixture(&restored).await.unwrap();
        let replacement = catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: "replacement-after-restore".into(),
                tenant_id: tenant,
                device_id: device,
                node_id: "node-b".into(),
                boot_id: "boot-b".into(),
                session_id: "session-b".into(),
                lease_expires_at: now + Duration::seconds(10),
            })
            .await
            .unwrap();
        assert!(replacement.token.epoch > claim.token.epoch);
    }

    #[tokio::test]
    async fn memory_catalog_reads_all_signed_membership_records() {
        let catalog = MemoryCatalog::new();
        let records = (0..3)
            .map(|index| SignedMembershipRecord {
                version: index + 1,
                bytes: format!(r#"{{"node_id":"relay-{index}"}}"#).into_bytes(),
            })
            .collect::<Vec<_>>();
        catalog
            .set_signed_memberships(records.clone())
            .await
            .expect("bounded membership directory");
        assert_eq!(catalog.read_signed_memberships().await.unwrap(), records);
        assert_eq!(
            catalog.read_signed_membership().await.unwrap(),
            records.first().cloned()
        );
        assert!(matches!(
            catalog
                .set_signed_memberships(
                    (0..=MAX_SIGNED_MEMBERSHIP_RECORDS)
                        .map(|index| SignedMembershipRecord {
                            version: index as u64 + 1,
                            bytes: vec![1],
                        })
                        .collect(),
                )
                .await,
            Err(CatalogError::InvalidInput("signed membership count"))
        ));
    }
}
