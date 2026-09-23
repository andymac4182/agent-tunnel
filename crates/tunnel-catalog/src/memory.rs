use crate::types::valid_principal_identity;
use crate::{
    AttachmentTicket, AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest,
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, ConsumedAttachmentTicket,
    CredentialRecord, DeviceIdentity, DeviceListFilter, DeviceSummary, FixtureDevice,
    GrantSnapshot, GrantSpec, MAX_SIGNED_MEMBERSHIP_RECORDS, MembershipRecord, OwnerClaim,
    OwnerClaimRequest, OwnerToken, PrincipalIdentity, ServiceRecord, ServiceSpec,
    SignedMembershipRecord, cluster,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct MemoryCatalog {
    state: Arc<Mutex<State>>,
}

#[derive(Clone, Default)]
struct State {
    tenants: HashMap<Uuid, crate::TenantRecord>,
    users: HashMap<Uuid, crate::UserRecord>,
    identities: HashMap<(String, String), PrincipalIdentity>,
    memberships: HashMap<(Uuid, Uuid), MembershipRecord>,
    devices: HashMap<(Uuid, Uuid), FixtureDevice>,
    device_versions: HashMap<(Uuid, Uuid), u64>,
    credentials: HashMap<(Uuid, Uuid, Uuid), CredentialRecord>,
    services: HashMap<(Uuid, Uuid, Uuid), ServiceRecord>,
    grants: HashMap<(Uuid, Uuid, Uuid, Uuid), MemoryGrant>,
    owners: HashMap<(Uuid, Uuid), OwnerClaim>,
    owner_epochs: HashMap<(Uuid, Uuid), u64>,
    attachment_tickets: HashMap<String, MemoryAttachmentTicket>,
    signed_memberships: Vec<SignedMembershipRecord>,
}

#[derive(Clone)]
struct MemoryGrant {
    spec: GrantSpec,
    revision: u64,
}

#[derive(Clone)]
struct MemoryAttachmentTicket {
    binding: crate::AttachmentTicketBinding,
    expires_at: DateTime<Utc>,
}

impl MemoryCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the in-process membership directory used by runtime tests and
    /// embedding callers.  Signature verification remains outside the catalog
    /// boundary, just as it is for Redis.
    pub async fn set_signed_memberships(
        &self,
        records: Vec<SignedMembershipRecord>,
    ) -> Result<(), CatalogError> {
        if records.len() > MAX_SIGNED_MEMBERSHIP_RECORDS {
            return Err(CatalogError::InvalidInput("signed membership count"));
        }
        self.state.lock().await.signed_memberships = records;
        Ok(())
    }

    pub async fn snapshot_fixture(&self) -> CatalogFixture {
        let state = self.state.lock().await;
        CatalogFixture {
            tenants: state.tenants.values().cloned().collect(),
            users: state.users.values().cloned().collect(),
            identities: state.identities.values().cloned().collect(),
            memberships: state.memberships.values().cloned().collect(),
            devices: state.devices.values().cloned().collect(),
            credentials: state.credentials.values().cloned().collect(),
            services: state
                .services
                .values()
                .cloned()
                .map(ServiceRecord::into_spec)
                .collect(),
            grants: state
                .grants
                .values()
                .map(|grant| grant.spec.clone())
                .collect(),
        }
    }

    async fn validate_and_apply(
        state: &mut State,
        fixture: &CatalogFixture,
    ) -> Result<(), CatalogError> {
        for tenant in &fixture.tenants {
            state.tenants.insert(tenant.tenant_id, tenant.clone());
        }
        for user in &fixture.users {
            state.users.insert(user.user_id, user.clone());
        }
        for identity in &fixture.identities {
            if !state.users.contains_key(&identity.user_id)
                || !valid_principal_identity(&identity.issuer, &identity.subject)
            {
                return Err(CatalogError::InvalidInput(
                    "identity user, issuer, or subject",
                ));
            }
            state.identities.insert(
                (identity.issuer.clone(), identity.subject.clone()),
                identity.clone(),
            );
        }
        for membership in &fixture.memberships {
            if !state.tenants.contains_key(&membership.tenant_id)
                || !state.users.contains_key(&membership.user_id)
            {
                return Err(CatalogError::InvalidInput("membership tenant or user"));
            }
            state.memberships.insert(
                (membership.tenant_id, membership.user_id),
                membership.clone(),
            );
        }
        for device in &fixture.devices {
            if !state.tenants.contains_key(&device.tenant_id)
                || !state
                    .memberships
                    .contains_key(&(device.tenant_id, device.owner_user_id))
            {
                return Err(CatalogError::InvalidInput(
                    "device tenant or owner membership",
                ));
            }
            let key = (device.tenant_id, device.device_id);
            let existed = state.devices.insert(key, device.clone()).is_some();
            let version = state.device_versions.entry(key).or_insert(1);
            if existed {
                *version = version
                    .checked_add(1)
                    .ok_or(CatalogError::RevisionOverflow)?;
            }
        }
        for credential in &fixture.credentials {
            if state.credentials.iter().any(|(key, existing)| {
                key != &(
                    credential.tenant_id,
                    credential.device_id,
                    credential.credential_id,
                ) && existing.spki_fingerprint == credential.spki_fingerprint
            }) {
                return Err(CatalogError::Conflict("duplicate SPKI fingerprint"));
            }
            if !state
                .devices
                .contains_key(&(credential.tenant_id, credential.device_id))
                || !valid_fingerprint(&credential.spki_fingerprint)
                || credential.expires_at <= credential.not_before
            {
                return Err(CatalogError::InvalidInput(
                    "credential binding or fingerprint",
                ));
            }
            state.credentials.insert(
                (
                    credential.tenant_id,
                    credential.device_id,
                    credential.credential_id,
                ),
                credential.clone(),
            );
        }
        for service in &fixture.services {
            if !state
                .devices
                .contains_key(&(service.tenant_id, service.device_id))
                || service.service_type.trim().is_empty()
            {
                return Err(CatalogError::InvalidInput("service device or type"));
            }
            state.services.insert(
                (service.tenant_id, service.device_id, service.service_id),
                service.clone().into_record(),
            );
        }
        for grant in &fixture.grants {
            let service_key = (grant.tenant_id, grant.device_id, grant.service_id);
            if !state
                .memberships
                .contains_key(&(grant.tenant_id, grant.principal_id))
                || !state
                    .devices
                    .contains_key(&(grant.tenant_id, grant.device_id))
                || !state.services.contains_key(&service_key)
            {
                return Err(CatalogError::InvalidInput("grant tenant relationship"));
            }
            let key = (
                grant.tenant_id,
                grant.principal_id,
                grant.device_id,
                grant.service_id,
            );
            let revision = state.grants.get(&key).map_or(0, |old| old.revision);
            let revision = revision
                .checked_add(1)
                .ok_or(CatalogError::RevisionOverflow)?;
            state.grants.insert(
                key,
                MemoryGrant {
                    spec: grant.clone(),
                    revision,
                },
            );
        }
        Ok(())
    }

    async fn with_state<F, T>(&self, operation: F) -> Result<T, CatalogError>
    where
        F: FnOnce(&mut State) -> Result<T, CatalogError>,
    {
        let mut state = self.state.lock().await;
        operation(&mut state)
    }
}

#[async_trait]
impl Catalog for MemoryCatalog {
    async fn resolve_device(
        &self,
        spki_fingerprint: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<DeviceIdentity>, CatalogError> {
        if !valid_fingerprint(spki_fingerprint) {
            return Ok(None);
        }
        let state = self.state.lock().await;
        for credential in state.credentials.values() {
            if credential.spki_fingerprint != spki_fingerprint
                || !credential.active
                || credential.revoked_at.is_some()
                || credential.expires_at <= at
            {
                continue;
            }
            let Some(device) = state
                .devices
                .get(&(credential.tenant_id, credential.device_id))
            else {
                continue;
            };
            if !device.active {
                continue;
            }
            // The same order as the Redis script: refused states first, and a
            // not-yet-valid credential is a retryable conflict, not `None`.
            if credential.not_before > at {
                return Err(CatalogError::Conflict(crate::RESOLVE_NOT_YET_VALID));
            }
            let owner_epoch = state
                .owner_epochs
                .get(&(credential.tenant_id, credential.device_id))
                .copied()
                .unwrap_or(0);
            return Ok(Some(DeviceIdentity {
                tenant_id: credential.tenant_id,
                device_id: credential.device_id,
                owner_user_id: device.owner_user_id,
                credential_id: credential.credential_id,
                spki_fingerprint: credential.spki_fingerprint.clone(),
                credential_not_before: credential.not_before,
                expires_at: credential.expires_at,
                credential_revoked_at: credential.revoked_at,
                device_active: device.active,
                credential_active: credential.active,
                device_version: state
                    .device_versions
                    .get(&(credential.tenant_id, credential.device_id))
                    .copied()
                    .unwrap_or(1),
                owner_epoch,
                last_seen_at: device.last_seen_at,
            }));
        }
        Ok(None)
    }

    async fn resolve_consumer(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: Option<Uuid>,
    ) -> Result<Option<AuthenticatedConsumer>, CatalogError> {
        if !valid_principal_identity(issuer, subject) {
            return Ok(None);
        }
        let state = self.state.lock().await;
        let Some(identity) = state
            .identities
            .get(&(issuer.to_owned(), subject.to_owned()))
        else {
            return Ok(None);
        };
        let memberships = state
            .memberships
            .values()
            .filter(|membership| {
                membership.user_id == identity.user_id
                    && membership.active
                    && state
                        .tenants
                        .get(&membership.tenant_id)
                        .is_some_and(|tenant| tenant.active)
                    && tenant_id.is_none_or(|requested| requested == membership.tenant_id)
            })
            .collect::<Vec<_>>();
        match memberships.as_slice() {
            [] => Ok(None),
            [membership] => Ok(Some(AuthenticatedConsumer {
                tenant_id: membership.tenant_id,
                principal_id: identity.user_id,
            })),
            _ => Err(CatalogError::Conflict(
                "consumer requires an explicit tenant selection",
            )),
        }
    }

    async fn authorize(
        &self,
        principal: &AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        read_started_at: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> Result<Option<GrantSnapshot>, CatalogError> {
        if read_started_at > at {
            return Err(CatalogError::InvalidInput("authorization read start"));
        }
        let state = self.state.lock().await;
        if !active_membership(&state, principal.tenant_id, principal.principal_id) {
            return Ok(None);
        }
        let Some(device) = state.devices.get(&(principal.tenant_id, device_id)) else {
            return Ok(None);
        };
        if !device.active {
            return Ok(None);
        }
        let Some(service) = state
            .services
            .get(&(principal.tenant_id, device_id, service_id))
        else {
            return Ok(None);
        };
        if !service.active {
            return Ok(None);
        }
        let Some(grant) = state.grants.get(&(
            principal.tenant_id,
            principal.principal_id,
            device_id,
            service_id,
        )) else {
            return Ok(None);
        };
        if !grant.spec.active || grant.spec.expires_at.is_some_and(|expiry| expiry <= at) {
            return Ok(None);
        }
        let mut valid_until = read_started_at + Duration::seconds(5);
        if let Some(expiry) = grant.spec.expires_at {
            valid_until = valid_until.min(expiry);
        }
        if valid_until <= at {
            return Ok(None);
        }
        Ok(Some(GrantSnapshot {
            tenant_id: principal.tenant_id,
            principal_id: principal.principal_id,
            device_id,
            service_id,
            revision: grant.revision,
            permissions: grant.spec.permissions.clone(),
            constraints: grant.spec.constraints.clone(),
            valid_until,
            read_started_at,
        }))
    }

    async fn list_devices_filtered(
        &self,
        principal: &AuthenticatedConsumer,
        filter: &DeviceListFilter,
        at: DateTime<Utc>,
    ) -> Result<Vec<DeviceSummary>, CatalogError> {
        let state = self.state.lock().await;
        if !active_membership(&state, principal.tenant_id, principal.principal_id) {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        for device in state.devices.values() {
            if device.tenant_id != principal.tenant_id
                || (!filter.include_inactive && !device.active)
                || filter
                    .owner_user_id
                    .is_some_and(|owner| owner != device.owner_user_id)
            {
                continue;
            }
            let mut services = Vec::new();
            let mut max_revision = 0;
            for service in state.services.values().filter(|service| {
                service.tenant_id == principal.tenant_id
                    && service.device_id == device.device_id
                    && filter.service_id.is_none_or(|id| id == service.service_id)
                    && (filter.include_inactive || service.active)
            }) {
                let Some(grant) = state.grants.get(&(
                    principal.tenant_id,
                    principal.principal_id,
                    device.device_id,
                    service.service_id,
                )) else {
                    continue;
                };
                if !grant.spec.active || grant.spec.expires_at.is_some_and(|expiry| expiry <= at) {
                    continue;
                }
                max_revision = max_revision.max(grant.revision);
                services.push(service.clone());
            }
            if !services.is_empty() {
                result.push(DeviceSummary {
                    tenant_id: device.tenant_id,
                    device_id: device.device_id,
                    owner_user_id: device.owner_user_id,
                    display_name: device.display_name.clone(),
                    active: device.active,
                    last_seen_at: device.last_seen_at,
                    services,
                    grant_revision: max_revision,
                });
            }
        }
        result.sort_by_key(|device| device.device_id);
        Ok(result)
    }

    async fn upsert_grant(&self, spec: &GrantSpec) -> Result<GrantSnapshot, CatalogError> {
        let now = Utc::now();
        if spec.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(CatalogError::InvalidInput("grant expiry"));
        }
        let key = (
            spec.tenant_id,
            spec.principal_id,
            spec.device_id,
            spec.service_id,
        );
        self.with_state(|state| {
            if !active_membership(state, spec.tenant_id, spec.principal_id)
                || !state
                    .devices
                    .contains_key(&(spec.tenant_id, spec.device_id))
                || !state
                    .services
                    .get(&(spec.tenant_id, spec.device_id, spec.service_id))
                    .is_some_and(|service| service.active)
            {
                return Err(CatalogError::InvalidInput("grant tenant relationship"));
            }
            let revision = state.grants.get(&key).map_or(0, |grant| grant.revision);
            let revision = revision
                .checked_add(1)
                .ok_or(CatalogError::RevisionOverflow)?;
            state.grants.insert(
                key,
                MemoryGrant {
                    spec: spec.clone(),
                    revision,
                },
            );
            let valid_until = spec
                .expires_at
                .map_or(now + Duration::seconds(5), |expiry| {
                    (now + Duration::seconds(5)).min(expiry)
                });
            Ok(GrantSnapshot {
                tenant_id: spec.tenant_id,
                principal_id: spec.principal_id,
                device_id: spec.device_id,
                service_id: spec.service_id,
                revision,
                permissions: spec.permissions.clone(),
                constraints: spec.constraints.clone(),
                valid_until,
                read_started_at: now,
            })
        })
        .await
    }

    async fn revoke_grant(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        device_id: Uuid,
        service_id: Uuid,
        _at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        self.with_state(|state| {
            let key = (tenant_id, principal_id, device_id, service_id);
            let Some(grant) = state.grants.get_mut(&key) else {
                return Err(CatalogError::NotFound);
            };
            grant.revision = grant
                .revision
                .checked_add(1)
                .ok_or(CatalogError::RevisionOverflow)?;
            grant.spec.active = false;
            Ok(grant.revision)
        })
        .await
    }

    async fn revoke_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        self.with_state(|state| {
            let key = (tenant_id, device_id);
            if !state.devices.contains_key(&key) {
                return Err(CatalogError::NotFound);
            }
            let next_version = state
                .device_versions
                .get(&key)
                .copied()
                .unwrap_or(1)
                .checked_add(1)
                .ok_or(CatalogError::RevisionOverflow)?;
            let next_epoch = state
                .owner_epochs
                .get(&key)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(CatalogError::RevisionOverflow)?;
            for grant in state.grants.values().filter(|grant| {
                grant.spec.tenant_id == tenant_id && grant.spec.device_id == device_id
            }) {
                if grant.revision == u64::MAX {
                    return Err(CatalogError::RevisionOverflow);
                }
            }
            state
                .devices
                .get_mut(&key)
                .expect("device checked above")
                .active = false;
            state.device_versions.insert(key, next_version);
            state.owner_epochs.insert(key, next_epoch);
            state.owners.remove(&key);
            state.attachment_tickets.retain(|_, ticket| {
                ticket.binding.tenant_id != tenant_id || ticket.binding.device_id != device_id
            });
            for credential in state.credentials.values_mut().filter(|credential| {
                credential.tenant_id == tenant_id && credential.device_id == device_id
            }) {
                credential.active = false;
                credential.revoked_at.get_or_insert(at);
            }
            for grant in state.grants.values_mut().filter(|grant| {
                grant.spec.tenant_id == tenant_id && grant.spec.device_id == device_id
            }) {
                grant.spec.active = false;
                grant.revision = grant
                    .revision
                    .checked_add(1)
                    .ok_or(CatalogError::RevisionOverflow)?;
            }
            Ok(next_version)
        })
        .await
    }

    async fn revoke_credential(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        credential_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        self.with_state(|state| {
            let key = (tenant_id, device_id, credential_id);
            if !state
                .credentials
                .get(&key)
                .is_some_and(|credential| credential.active)
            {
                return Err(CatalogError::NotFound);
            }
            let device_key = (tenant_id, device_id);
            let next_version = state
                .device_versions
                .get(&device_key)
                .copied()
                .unwrap_or(1)
                .checked_add(1)
                .ok_or(CatalogError::RevisionOverflow)?;
            let credential = state
                .credentials
                .get_mut(&key)
                .expect("credential checked above");
            credential.active = false;
            credential.revoked_at.get_or_insert(at);
            state.device_versions.insert(device_key, next_version);
            Ok(next_version)
        })
        .await
    }

    async fn seed_fixture(&self, fixture: &CatalogFixture) -> Result<(), CatalogError> {
        let mut state = self.state.lock().await.clone();
        Self::validate_and_apply(&mut state, fixture).await?;
        *self.state.lock().await = state;
        Ok(())
    }

    async fn claim_owner(&self, request: &OwnerClaimRequest) -> Result<OwnerClaim, CatalogError> {
        let now = Utc::now();
        if request.lease_expires_at <= now
            || request.deployment_incarnation.trim().is_empty()
            || request.node_id.trim().is_empty()
            || request.boot_id.trim().is_empty()
            || request.session_id.trim().is_empty()
        {
            return Err(CatalogError::InvalidOwner);
        }
        self.with_state(|state| {
            if !state
                .devices
                .get(&(request.tenant_id, request.device_id))
                .is_some_and(|device| device.active)
            {
                return Err(CatalogError::NotFound);
            }
            let key = (request.tenant_id, request.device_id);
            if let Some(current) = state.owners.get(&key)
                && current.lease_expires_at > now
            {
                if current.token.deployment_incarnation == request.deployment_incarnation
                    && current.token.node_id == request.node_id
                    && current.token.boot_id == request.boot_id
                    && current.token.session_id == request.session_id
                {
                    return Ok(current.clone());
                }
                return Err(CatalogError::OwnerBusy);
            }
            let previous_epoch = state.owner_epochs.get(&key).copied().unwrap_or(0);
            let epoch = previous_epoch
                .checked_add(1)
                .ok_or(CatalogError::RevisionOverflow)?;
            let claim = OwnerClaim {
                token: OwnerToken {
                    deployment_incarnation: request.deployment_incarnation.clone(),
                    tenant_id: request.tenant_id,
                    device_id: request.device_id,
                    node_id: request.node_id.clone(),
                    boot_id: request.boot_id.clone(),
                    session_id: request.session_id.clone(),
                    epoch,
                },
                lease_expires_at: request.lease_expires_at,
            };
            state.owner_epochs.insert(key, epoch);
            state.owners.insert(key, claim.clone());
            Ok(claim)
        })
        .await
    }

    async fn renew_owner(
        &self,
        token: &OwnerToken,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<bool, CatalogError> {
        let now = Utc::now();
        if lease_expires_at <= now {
            return Err(CatalogError::InvalidOwner);
        }
        self.with_state(|state| {
            if !state
                .devices
                .get(&(token.tenant_id, token.device_id))
                .is_some_and(|device| device.active)
            {
                return Ok(false);
            }
            let Some(claim) = state.owners.get_mut(&(token.tenant_id, token.device_id)) else {
                return Ok(false);
            };
            if claim.token != *token || claim.lease_expires_at <= now {
                return Ok(false);
            }
            claim.lease_expires_at = lease_expires_at;
            Ok(true)
        })
        .await
    }

    async fn release_owner(&self, token: &OwnerToken) -> Result<bool, CatalogError> {
        self.with_state(|state| {
            let key = (token.tenant_id, token.device_id);
            if state
                .owners
                .get(&key)
                .is_some_and(|claim| claim.token == *token)
            {
                state.owners.remove(&key);
                return Ok(true);
            }
            Ok(false)
        })
        .await
    }

    async fn current_owner(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<Option<OwnerClaim>, CatalogError> {
        self.with_state(|state| {
            let key = (tenant_id, device_id);
            if !state.devices.get(&key).is_some_and(|device| device.active) {
                return Ok(None);
            }
            if state
                .owners
                .get(&key)
                .is_some_and(|claim| claim.lease_expires_at <= at)
            {
                state.owners.remove(&key);
            }
            Ok(state.owners.get(&key).cloned())
        })
        .await
    }

    async fn issue_attachment_ticket(
        &self,
        request: &AttachmentTicketIssueRequest,
    ) -> Result<AttachmentTicket, CatalogError> {
        let now = Utc::now();
        cluster::validate_ticket_issue(request, &request.owner.deployment_incarnation, now)?;
        let key = (request.tenant_id, request.device_id);
        self.with_state(|state| {
            let Some(current) = state.owners.get(&key) else {
                return Err(CatalogError::InvalidOwner);
            };
            if current.token != request.owner || current.lease_expires_at <= now {
                return Err(CatalogError::InvalidOwner);
            }
            state
                .attachment_tickets
                .retain(|_, ticket| ticket.expires_at > now);
            let outstanding = state
                .attachment_tickets
                .values()
                .filter(|ticket| {
                    ticket.binding.tenant_id == request.tenant_id
                        && ticket.binding.device_id == request.device_id
                })
                .count();
            if outstanding >= crate::MAX_ATTACHMENT_TICKETS_PER_DEVICE {
                return Err(CatalogError::Conflict("attachment ticket bound"));
            }
            let ticket = cluster::generate_ticket();
            let digest = cluster::ticket_digest(&ticket);
            state.attachment_tickets.insert(
                digest.clone(),
                MemoryAttachmentTicket {
                    binding: request.binding(),
                    expires_at: request.expires_at,
                },
            );
            Ok(AttachmentTicket {
                ticket,
                locator: crate::AttachmentTicketLocator {
                    tenant_id: request.tenant_id,
                    device_id: request.device_id,
                    digest,
                },
                expires_at: request.expires_at,
            })
        })
        .await
    }

    async fn consume_attachment_ticket(
        &self,
        request: &AttachmentTicketConsumeRequest,
    ) -> Result<ConsumedAttachmentTicket, CatalogError> {
        let binding = request.binding();
        cluster::validate_ticket_consume(
            &binding,
            &request.owner.deployment_incarnation,
            &request.ticket,
        )?;
        let digest = cluster::ticket_digest(&request.ticket);
        self.with_state(|state| {
            let Some(ticket) = state.attachment_tickets.get(&digest) else {
                return Err(CatalogError::Unauthorized);
            };
            if ticket.expires_at <= Utc::now() || ticket.binding != binding {
                return Err(CatalogError::Unauthorized);
            }
            let ticket = state
                .attachment_tickets
                .remove(&digest)
                .expect("ticket checked above");
            Ok(ConsumedAttachmentTicket {
                binding: ticket.binding,
                expires_at: ticket.expires_at,
            })
        })
        .await
    }

    async fn read_signed_membership(&self) -> Result<Option<SignedMembershipRecord>, CatalogError> {
        Ok(self.state.lock().await.signed_memberships.first().cloned())
    }

    async fn read_signed_memberships(&self) -> Result<Vec<SignedMembershipRecord>, CatalogError> {
        Ok(self.state.lock().await.signed_memberships.clone())
    }
}

impl ServiceSpec {
    fn into_record(self) -> ServiceRecord {
        ServiceRecord {
            tenant_id: self.tenant_id,
            device_id: self.device_id,
            service_id: self.service_id,
            service_type: self.service_type,
            display_name: self.display_name,
            capabilities: self.capabilities,
            version: self.version,
            active: self.active,
        }
    }
}

impl ServiceRecord {
    fn into_spec(self) -> ServiceSpec {
        ServiceSpec {
            tenant_id: self.tenant_id,
            device_id: self.device_id,
            service_id: self.service_id,
            service_type: self.service_type,
            display_name: self.display_name,
            capabilities: self.capabilities,
            version: self.version,
            active: self.active,
        }
    }
}

fn active_membership(state: &State, tenant_id: Uuid, user_id: Uuid) -> bool {
    state
        .memberships
        .get(&(tenant_id, user_id))
        .is_some_and(|membership| {
            membership.active
                && state
                    .tenants
                    .get(&tenant_id)
                    .is_some_and(|tenant| tenant.active)
        })
}

pub(crate) fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
