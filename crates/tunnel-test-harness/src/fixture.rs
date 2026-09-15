use crate::error::{HarnessError, Result};
use crate::oidc::OidcFixture;
use crate::pki::{CertificateMaterial, FixturePki};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use tunnel_catalog::{
    CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord, MembershipRole,
    PermissionSet, PrincipalIdentity, ServiceSpec, TenantRecord, UserRecord,
};
use uuid::Uuid;

/// A tenant identity for a real catalog seed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantFixture {
    pub id: Uuid,
    pub name: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrincipalRole {
    Owner,
    Member,
    Consumer,
}

/// A catalog principal.  Authorization remains production-catalog behavior;
/// this type only describes the fixture identities to insert.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalFixture {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub role: PrincipalRole,
}

/// An enrolled device and its role-separated client certificate.
#[derive(Clone, Debug)]
pub struct DeviceFixture {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub label: String,
    pub certificate: CertificateMaterial,
    /// Binary canary includes zero bytes and values above ASCII so tests catch
    /// accidental UTF-8/string conversion or truncation.
    pub binary_canary: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsumerFixture {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantFixture {
    pub principal_id: Uuid,
    pub device_id: Uuid,
    pub service: String,
    pub allowed: bool,
}

/// The deliberately colliding identity used by tenant-isolation fixtures.
///
/// Device and service identifiers are normally unique in the default M1
/// topology. M7 also needs to prove that both identifiers are scoped by the
/// tenant, so this value is opt-in and is applied before the one-shot catalog
/// seed. The two certificates remain distinct because each tenant receives a
/// separately generated device key pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedFixtureIdentity {
    pub device_id: Uuid,
    pub service_id: Uuid,
}

impl SharedFixtureIdentity {
    pub const fn new(device_id: Uuid, service_id: Uuid) -> Self {
        Self {
            device_id,
            service_id,
        }
    }
}

/// M1's minimum two-tenant/five-device topology.
#[derive(Clone, Debug)]
pub struct FixtureTopology {
    pub tenant_a: TenantFixture,
    pub tenant_b: TenantFixture,
    pub owner_a: PrincipalFixture,
    pub limited_member_a: PrincipalFixture,
    pub owner_b: PrincipalFixture,
    pub consumers_a: Vec<ConsumerFixture>,
    pub consumers_b: Vec<ConsumerFixture>,
    pub devices_a: Vec<DeviceFixture>,
    pub devices_b: Vec<DeviceFixture>,
    pub service_ids: BTreeMap<Uuid, Uuid>,
    pub grants: Vec<GrantFixture>,
}

impl FixtureTopology {
    pub fn new(pki: &FixturePki) -> Result<Self> {
        let tenant_a = TenantFixture {
            id: Uuid::new_v4(),
            name: "m1-tenant-a".to_owned(),
        };
        let tenant_b = TenantFixture {
            id: Uuid::new_v4(),
            name: "m1-tenant-b".to_owned(),
        };
        let owner_a = principal(tenant_a.id, "owner-a", PrincipalRole::Owner);
        let limited_member_a = principal(tenant_a.id, "limited-member-a", PrincipalRole::Member);
        let owner_b = principal(tenant_b.id, "owner-b", PrincipalRole::Owner);
        let consumers_a = (1..=2)
            .map(|index| ConsumerFixture {
                id: Uuid::new_v4(),
                tenant_id: tenant_a.id,
                name: format!("consumer-a-{index}"),
            })
            .collect::<Vec<_>>();
        let consumers_b = (1..=2)
            .map(|index| ConsumerFixture {
                id: Uuid::new_v4(),
                tenant_id: tenant_b.id,
                name: format!("consumer-b-{index}"),
            })
            .collect::<Vec<_>>();

        let devices_a = (1..=3)
            .map(|index| make_device(pki, tenant_a.id, format!("shared-label-{index}")))
            .collect::<Result<Vec<_>>>()?;
        let devices_b = (1..=2)
            .map(|index| make_device(pki, tenant_b.id, format!("shared-label-{index}")))
            .collect::<Result<Vec<_>>>()?;
        let service_ids = self_service_ids(devices_a.iter().chain(devices_b.iter()));

        let mut grants = Vec::new();
        for consumer in &consumers_a {
            for device in &devices_a {
                grants.push(GrantFixture {
                    principal_id: consumer.id,
                    device_id: device.id,
                    service: "echo".to_owned(),
                    allowed: true,
                });
            }
        }
        for consumer in &consumers_b {
            for device in &devices_b {
                grants.push(GrantFixture {
                    principal_id: consumer.id,
                    device_id: device.id,
                    service: "echo".to_owned(),
                    allowed: true,
                });
            }
        }
        for device in &devices_a {
            grants.push(GrantFixture {
                principal_id: owner_a.id,
                device_id: device.id,
                service: "echo".to_owned(),
                allowed: true,
            });
        }
        grants.push(GrantFixture {
            principal_id: limited_member_a.id,
            device_id: devices_a[0].id,
            service: "echo".to_owned(),
            allowed: true,
        });

        Ok(Self {
            tenant_a,
            tenant_b,
            owner_a,
            limited_member_a,
            owner_b,
            consumers_a,
            consumers_b,
            devices_a,
            devices_b,
            service_ids,
            grants,
        })
    }

    /// Build the normal two-tenant topology while deliberately reusing one
    /// device UUID in both tenant scopes.  Redis keys are tenant-qualified,
    /// so this is a useful production authorization edge case: a tenant-B
    /// credential must never reach tenant A's device merely because the
    /// device UUID and service UUID are identical.
    pub fn new_with_shared_device_uuid(pki: &FixturePki, shared_device_id: Uuid) -> Result<Self> {
        let mut topology = Self::new(pki)?;
        let source_device_id = topology
            .devices_a
            .first()
            .ok_or_else(|| HarnessError::InvalidInput("tenant A has no fixture device".into()))?
            .id;
        let shared_service_id = topology
            .service_ids
            .get(&source_device_id)
            .copied()
            .ok_or_else(|| {
                HarnessError::InvalidInput(format!(
                    "device {source_device_id} has no fixture service id"
                ))
            })?;
        replace_shared_identity(
            pki,
            &mut topology,
            SharedFixtureIdentity {
                device_id: shared_device_id,
                service_id: shared_service_id,
            },
        )?;
        Ok(topology)
    }

    /// Build the normal topology with the first device in each tenant sharing
    /// an explicitly chosen device UUID and service UUID.
    ///
    /// This constructor is intended for M7 tenant-isolation scenarios. It
    /// keeps the default five-device/four-consumer topology and performs all
    /// records through [`Self::catalog_fixture`] before the caller performs
    /// the production catalog's one-shot seed.
    pub fn new_with_shared_device_and_service_uuid(
        pki: &FixturePki,
        shared: SharedFixtureIdentity,
    ) -> Result<Self> {
        let mut topology = Self::new(pki)?;
        replace_shared_identity(pki, &mut topology, shared)?;
        Ok(topology)
    }

    pub fn all_devices(&self) -> impl Iterator<Item = &DeviceFixture> {
        self.devices_a.iter().chain(self.devices_b.iter())
    }

    pub fn all_consumers(&self) -> impl Iterator<Item = &ConsumerFixture> {
        self.consumers_a.iter().chain(self.consumers_b.iter())
    }

    pub fn grant(&self, principal_id: Uuid, device_id: Uuid, service: &str) -> bool {
        self.grants.iter().any(|grant| {
            grant.principal_id == principal_id
                && grant.device_id == device_id
                && grant.service == service
                && grant.allowed
        })
    }

    pub fn canaries_by_device(&self) -> BTreeMap<Uuid, Vec<u8>> {
        self.all_devices()
            .map(|device| (device.id, device.binary_canary.clone()))
            .collect()
    }

    pub fn cross_tenant_device(&self) -> &DeviceFixture {
        &self.devices_b[0]
    }

    /// Append an active `http-forward` service to `device_id`.  Every
    /// principal granted the device's primary echo service receives exactly
    /// the `http:invoke` operation on it, so the HTTP routes are authorized by
    /// their own grant operation and never by an echo grant.  Apply before the
    /// harness's single catalog seed.
    pub fn push_http_forward_service(
        &self,
        fixture: &mut CatalogFixture,
        device_id: Uuid,
    ) -> Result<Uuid> {
        let device = self
            .all_devices()
            .find(|device| device.id == device_id)
            .ok_or_else(|| {
                HarnessError::InvalidInput(format!(
                    "http-forward service references unknown device {device_id}"
                ))
            })?;
        let primary = self.service_ids.get(&device_id).copied().ok_or_else(|| {
            HarnessError::InvalidInput(format!("device {device_id} has no service id"))
        })?;
        let service_id = Uuid::new_v4();
        fixture.services.push(ServiceSpec {
            tenant_id: device.tenant_id,
            device_id,
            service_id,
            service_type: "http-forward".to_owned(),
            display_name: "Synthetic in-process HTTP export".to_owned(),
            capabilities: serde_json::json!({"operations": ["http:invoke"]}),
            version: 1,
            active: true,
        });
        let mirrored = fixture
            .grants
            .iter()
            .filter(|grant| grant.device_id == device_id && grant.service_id == primary)
            .map(|grant| GrantSpec {
                service_id,
                permissions: PermissionSet {
                    operations: ["http:invoke".to_owned()].into_iter().collect(),
                },
                ..grant.clone()
            })
            .collect::<Vec<_>>();
        if mirrored.is_empty() {
            return Err(HarnessError::InvalidInput(format!(
                "device {device_id} has no primary grant to mirror"
            )));
        }
        fixture.grants.extend(mirrored);
        Ok(service_id)
    }

    /// Append a second active `echo` service to `device_id` so the public
    /// service-type label resolves to more than one live target.
    ///
    /// The duplicate receives the same grants as the device's primary service,
    /// so neither candidate is less authorized than the other and the only
    /// correct outcome for a label request is an explicit ambiguous rejection
    /// rather than an arbitrary selection.  The caller must apply this before
    /// the harness performs its single authoritative catalog seed; the
    /// returned identifier is the duplicate, never the primary.
    pub fn push_ambiguous_echo_service(
        &self,
        fixture: &mut CatalogFixture,
        device_id: Uuid,
    ) -> Result<Uuid> {
        let device = self
            .all_devices()
            .find(|device| device.id == device_id)
            .ok_or_else(|| {
                HarnessError::InvalidInput(format!(
                    "ambiguous echo service references unknown device {device_id}"
                ))
            })?;
        let primary = self.service_ids.get(&device_id).copied().ok_or_else(|| {
            HarnessError::InvalidInput(format!("device {device_id} has no service id"))
        })?;
        let duplicate = Uuid::new_v4();
        if duplicate == primary {
            return Err(HarnessError::InvalidInput(
                "ambiguous echo service collided with the primary service id".to_owned(),
            ));
        }
        fixture.services.push(ServiceSpec {
            tenant_id: device.tenant_id,
            device_id,
            service_id: duplicate,
            service_type: "echo".to_owned(),
            display_name: "Synthetic duplicate binary echo".to_owned(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        });
        let mirrored = fixture
            .grants
            .iter()
            .filter(|grant| grant.device_id == device_id && grant.service_id == primary)
            .map(|grant| GrantSpec {
                service_id: duplicate,
                ..grant.clone()
            })
            .collect::<Vec<_>>();
        if mirrored.is_empty() {
            return Err(HarnessError::InvalidInput(format!(
                "device {device_id} has no primary echo grant to mirror"
            )));
        }
        fixture.grants.extend(mirrored);
        Ok(duplicate)
    }

    /// Convert the topology into the production catalog's seed contract.
    /// This does not write anything itself; callers must use the real
    /// `Catalog::seed_fixture` on the production Redis backend or another
    /// production `Catalog`
    /// implementation.
    pub fn catalog_fixture(&self, oidc: &OidcFixture) -> Result<CatalogFixture> {
        let mut fixture = CatalogFixture {
            tenants: vec![
                TenantRecord {
                    tenant_id: self.tenant_a.id,
                    display_name: self.tenant_a.name.clone(),
                    active: true,
                },
                TenantRecord {
                    tenant_id: self.tenant_b.id,
                    display_name: self.tenant_b.name.clone(),
                    active: true,
                },
            ],
            ..CatalogFixture::default()
        };
        let mut principals = vec![
            self.owner_a.clone(),
            self.limited_member_a.clone(),
            self.owner_b.clone(),
        ];
        principals.extend(self.consumers_a.iter().map(|consumer| PrincipalFixture {
            id: consumer.id,
            tenant_id: consumer.tenant_id,
            name: consumer.name.clone(),
            role: PrincipalRole::Consumer,
        }));
        principals.extend(self.consumers_b.iter().map(|consumer| PrincipalFixture {
            id: consumer.id,
            tenant_id: consumer.tenant_id,
            name: consumer.name.clone(),
            role: PrincipalRole::Consumer,
        }));
        for principal in &principals {
            fixture.users.push(UserRecord {
                user_id: principal.id,
                display_name: principal.name.clone(),
            });
            fixture.identities.push(PrincipalIdentity {
                issuer: oidc.issuer.clone(),
                subject: principal.name.clone(),
                user_id: principal.id,
            });
            fixture.memberships.push(MembershipRecord {
                tenant_id: principal.tenant_id,
                user_id: principal.id,
                role: if principal.role == PrincipalRole::Owner {
                    MembershipRole::Admin
                } else {
                    MembershipRole::Member
                },
                active: true,
            });
        }

        for device in self.all_devices() {
            let service_id = self.service_ids.get(&device.id).copied().ok_or_else(|| {
                HarnessError::InvalidInput(format!("device {} has no service id", device.id))
            })?;
            let owner_user_id = if device.tenant_id == self.tenant_a.id {
                self.owner_a.id
            } else {
                self.owner_b.id
            };
            fixture.devices.push(FixtureDevice {
                tenant_id: device.tenant_id,
                device_id: device.id,
                owner_user_id,
                display_name: device.label.clone(),
                active: true,
                last_seen_at: None,
            });
            let fingerprint = device.certificate.spki_fingerprint_sha256()?;
            fixture.credentials.push(CredentialRecord {
                tenant_id: device.tenant_id,
                device_id: device.id,
                credential_id: Uuid::new_v4(),
                spki_fingerprint: fingerprint,
                serial: None,
                not_before: to_chrono(device.certificate.not_before)?,
                expires_at: to_chrono(device.certificate.not_after)?,
                revoked_at: None,
                active: true,
            });
            fixture.services.push(ServiceSpec {
                tenant_id: device.tenant_id,
                device_id: device.id,
                service_id,
                service_type: "echo".to_owned(),
                display_name: "Synthetic binary echo".to_owned(),
                capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
                version: 1,
                active: true,
            });
        }
        for grant in &self.grants {
            if !grant.allowed {
                continue;
            }
            let service_id = self
                .service_ids
                .get(&grant.device_id)
                .copied()
                .ok_or_else(|| {
                    HarnessError::InvalidInput(format!(
                        "grant references unknown device {}",
                        grant.device_id
                    ))
                })?;
            let tenant_id = if grant.principal_id == self.owner_a.id
                || grant.principal_id == self.limited_member_a.id
                || self
                    .consumers_a
                    .iter()
                    .any(|consumer| consumer.id == grant.principal_id)
            {
                self.tenant_a.id
            } else if grant.principal_id == self.owner_b.id
                || self
                    .consumers_b
                    .iter()
                    .any(|consumer| consumer.id == grant.principal_id)
            {
                self.tenant_b.id
            } else {
                return Err(HarnessError::InvalidInput(format!(
                    "grant references unknown principal {}",
                    grant.principal_id
                )));
            };
            fixture.grants.push(GrantSpec {
                tenant_id,
                principal_id: grant.principal_id,
                device_id: grant.device_id,
                service_id,
                permissions: PermissionSet {
                    operations: BTreeSet::from([grant.service.clone() + ":invoke"]),
                },
                constraints: serde_json::json!({}),
                expires_at: None,
                active: true,
            });
        }
        Ok(fixture)
    }
}

fn principal(tenant_id: Uuid, name: &str, role: PrincipalRole) -> PrincipalFixture {
    PrincipalFixture {
        id: Uuid::new_v4(),
        tenant_id,
        name: name.to_owned(),
        role,
    }
}

fn make_device(pki: &FixturePki, tenant_id: Uuid, label: String) -> Result<DeviceFixture> {
    make_device_with_id(pki, tenant_id, Uuid::new_v4(), label)
}

fn make_device_with_id(
    pki: &FixturePki,
    tenant_id: Uuid,
    id: Uuid,
    label: String,
) -> Result<DeviceFixture> {
    let certificate = pki.issue_device(tenant_id, id)?;
    let mut binary_canary = Vec::with_capacity(256);
    for byte in 0_u16..=255 {
        binary_canary.push(byte as u8);
    }
    binary_canary.extend_from_slice(label.as_bytes());
    binary_canary.extend_from_slice(&id.as_bytes()[..]);
    Ok(DeviceFixture {
        id,
        tenant_id,
        label,
        certificate,
        binary_canary,
    })
}

fn replace_shared_identity(
    pki: &FixturePki,
    topology: &mut FixtureTopology,
    shared: SharedFixtureIdentity,
) -> Result<()> {
    if shared.device_id.is_nil() {
        return Err(HarnessError::InvalidInput(
            "shared fixture device UUID must be non-nil".to_owned(),
        ));
    }
    if shared.service_id.is_nil() {
        return Err(HarnessError::InvalidInput(
            "shared fixture service UUID must be non-nil".to_owned(),
        ));
    }

    let tenant_a_device = topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no fixture device".into()))?;
    let tenant_b_device = topology
        .devices_b
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant B has no fixture device".into()))?;
    let previous_device_ids = [tenant_a_device.id, tenant_b_device.id];
    if topology
        .all_devices()
        .any(|device| device.id == shared.device_id && !previous_device_ids.contains(&device.id))
    {
        return Err(HarnessError::InvalidInput(format!(
            "shared fixture device UUID {} is already used by another device",
            shared.device_id
        )));
    }
    let replacement_a = make_device_with_id(
        pki,
        topology.tenant_a.id,
        shared.device_id,
        tenant_a_device.label.clone(),
    )?;
    let replacement_b = make_device_with_id(
        pki,
        topology.tenant_b.id,
        shared.device_id,
        tenant_b_device.label.clone(),
    )?;
    topology.devices_a[0] = replacement_a;
    topology.devices_b[0] = replacement_b;

    for previous_device_id in previous_device_ids {
        topology.service_ids.remove(&previous_device_id);
    }
    topology
        .service_ids
        .insert(shared.device_id, shared.service_id);
    for grant in &mut topology.grants {
        if previous_device_ids.contains(&grant.device_id) {
            grant.device_id = shared.device_id;
        }
    }
    Ok(())
}

fn self_service_ids<'a>(devices: impl Iterator<Item = &'a DeviceFixture>) -> BTreeMap<Uuid, Uuid> {
    devices.map(|device| (device.id, Uuid::new_v4())).collect()
}

fn to_chrono(value: time::OffsetDateTime) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp(value.unix_timestamp(), value.nanosecond()).ok_or_else(|| {
        HarnessError::InvalidInput("certificate validity is outside chrono range".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::FixtureTopology;
    use crate::pki::FixturePki;

    #[test]
    fn topology_has_required_devices_consumers_and_limited_member() {
        let topology = FixtureTopology::new(&FixturePki::default()).expect("topology");
        assert_eq!(topology.devices_a.len(), 3);
        assert_eq!(topology.devices_b.len(), 2);
        assert_eq!(topology.consumers_a.len(), 2);
        assert_eq!(topology.consumers_b.len(), 2);
        assert!(topology.grant(
            topology.limited_member_a.id,
            topology.devices_a[0].id,
            "echo"
        ));
        assert!(!topology.grant(
            topology.limited_member_a.id,
            topology.devices_a[1].id,
            "echo"
        ));
        assert!(!topology.grant(topology.consumers_a[0].id, topology.devices_b[0].id, "echo"));
        assert_eq!(
            topology.devices_a[0].binary_canary.len(),
            256 + topology.devices_a[0].label.len() + 16
        );
    }

    #[test]
    fn shared_device_uuid_remains_tenant_scoped_in_catalog_fixture() {
        let pki = FixturePki::default();
        let shared_device_id = uuid::Uuid::from_u128(0xfeed);
        let shared_service_id = uuid::Uuid::from_u128(0xbeef);
        let topology = FixtureTopology::new_with_shared_device_and_service_uuid(
            &pki,
            super::SharedFixtureIdentity {
                device_id: shared_device_id,
                service_id: shared_service_id,
            },
        )
        .expect("shared topology");
        assert_eq!(topology.devices_a[0].id, shared_device_id);
        assert_eq!(topology.devices_b[0].id, shared_device_id);
        assert_ne!(
            topology.devices_a[0]
                .certificate
                .spki_fingerprint_sha256()
                .expect("tenant A SPKI"),
            topology.devices_b[0]
                .certificate
                .spki_fingerprint_sha256()
                .expect("tenant B SPKI")
        );
        let oidc = crate::oidc::OidcFixture::new("https://fixture.test", "audience").expect("oidc");
        let catalog = topology.catalog_fixture(&oidc).expect("catalog fixture");
        assert_eq!(
            catalog
                .devices
                .iter()
                .filter(|device| device.device_id == shared_device_id)
                .count(),
            2
        );
        let shared_services = catalog
            .services
            .iter()
            .filter(|service| service.device_id == shared_device_id)
            .collect::<Vec<_>>();
        assert_eq!(shared_services.len(), 2);
        assert!(
            shared_services
                .iter()
                .all(|service| service.service_id == shared_service_id)
        );
        assert_eq!(
            catalog
                .credentials
                .iter()
                .filter(|credential| credential.device_id == shared_device_id)
                .count(),
            2
        );
        let shared_credentials = catalog
            .credentials
            .iter()
            .filter(|credential| credential.device_id == shared_device_id)
            .collect::<Vec<_>>();
        assert!(
            shared_credentials
                .iter()
                .any(|credential| credential.tenant_id == topology.tenant_a.id)
        );
        assert!(
            shared_credentials
                .iter()
                .any(|credential| credential.tenant_id == topology.tenant_b.id)
        );
        let tenant_a_spki = topology.devices_a[0]
            .certificate
            .spki_fingerprint_sha256()
            .expect("tenant A SPKI");
        let tenant_b_spki = topology.devices_b[0]
            .certificate
            .spki_fingerprint_sha256()
            .expect("tenant B SPKI");
        assert_eq!(
            shared_credentials
                .iter()
                .find(|credential| credential.tenant_id == topology.tenant_a.id)
                .expect("tenant A credential")
                .spki_fingerprint
                .as_str(),
            tenant_a_spki.as_str()
        );
        assert_eq!(
            shared_credentials
                .iter()
                .find(|credential| credential.tenant_id == topology.tenant_b.id)
                .expect("tenant B credential")
                .spki_fingerprint
                .as_str(),
            tenant_b_spki.as_str()
        );
        assert_ne!(
            shared_credentials[0].spki_fingerprint,
            shared_credentials[1].spki_fingerprint
        );
        let tenant_a_grants = catalog
            .grants
            .iter()
            .filter(|grant| {
                grant.tenant_id == topology.tenant_a.id && grant.device_id == shared_device_id
            })
            .count();
        let tenant_b_grants = catalog
            .grants
            .iter()
            .filter(|grant| {
                grant.tenant_id == topology.tenant_b.id && grant.device_id == shared_device_id
            })
            .count();
        assert!(tenant_a_grants > 0);
        assert!(tenant_b_grants > 0);
        assert!(catalog.grants.iter().any(|grant| {
            grant.tenant_id == topology.tenant_a.id
                && grant.principal_id == topology.consumers_a[0].id
                && grant.device_id == shared_device_id
                && grant.service_id == shared_service_id
        }));
        assert!(catalog.grants.iter().any(|grant| {
            grant.tenant_id == topology.tenant_b.id
                && grant.principal_id == topology.consumers_b[0].id
                && grant.device_id == shared_device_id
                && grant.service_id == shared_service_id
        }));
        assert!(!catalog.grants.iter().any(|grant| {
            grant.tenant_id == topology.tenant_a.id
                && grant.principal_id == topology.consumers_b[0].id
                && grant.device_id == shared_device_id
        }));
        assert!(!catalog.grants.iter().any(|grant| {
            grant.tenant_id == topology.tenant_b.id
                && grant.principal_id == topology.consumers_a[0].id
                && grant.device_id == shared_device_id
        }));
        assert_eq!(
            catalog
                .grants
                .iter()
                .filter(|grant| grant.device_id == shared_device_id)
                .count(),
            tenant_a_grants + tenant_b_grants
        );
    }

    #[test]
    fn generated_shared_device_constructor_reuses_a_service_uuid() {
        let topology = FixtureTopology::new_with_shared_device_uuid(
            &FixturePki::default(),
            uuid::Uuid::from_u128(0xfeed),
        )
        .expect("shared topology");
        assert_eq!(topology.devices_a[0].id, topology.devices_b[0].id);
        assert_eq!(
            topology.service_ids[&topology.devices_a[0].id],
            topology.service_ids[&topology.devices_b[0].id]
        );
    }
}
