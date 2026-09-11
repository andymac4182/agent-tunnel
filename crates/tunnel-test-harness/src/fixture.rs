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
            let tenant_id = if self
                .devices_a
                .iter()
                .any(|device| device.id == grant.device_id)
            {
                self.tenant_a.id
            } else {
                self.tenant_b.id
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
    let id = Uuid::new_v4();
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
}
