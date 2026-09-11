//! EC-003 duplicate-service publication boundary.
//!
//! A public route carries one opaque service UUID.  The catalog fixture
//! authority must reject two records with the same tenant/device/service key
//! before reserving or mutating a Redis namespace.  This is the supported
//! duplicate-target analogue; the production catalog does not expose a
//! caller-controlled alias or a service-registration route.

use chrono::{Duration, Utc};
use std::collections::BTreeSet;
use tunnel_catalog::{
    Catalog, CatalogError, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec,
    MembershipRecord, MembershipRole, PermissionSet, PrincipalIdentity, RedisCatalog, ServiceSpec,
    TenantRecord, UserRecord,
};
use uuid::Uuid;

fn fixture() -> CatalogFixture {
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let service_id = Uuid::new_v4();
    let now = Utc::now();
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id,
            display_name: "EC-003 duplicate tenant".into(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id,
            display_name: "EC-003 duplicate user".into(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: "https://issuer.ec003.invalid".into(),
            subject: format!("subject-{user_id}"),
            user_id,
        }],
        memberships: vec![MembershipRecord {
            tenant_id,
            user_id,
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id,
            device_id,
            owner_user_id: user_id,
            display_name: "EC-003 duplicate device".into(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id,
            device_id,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: format!("{:064x}", user_id.as_u128()),
            serial: Some("ec003-duplicate".into()),
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
            display_name: "EC-003 echo".into(),
            capabilities: serde_json::json!({"operations":["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id,
            principal_id: user_id,
            device_id,
            service_id,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".into()]),
            },
            constraints: serde_json::json!({}),
            expires_at: Some(now + Duration::hours(1)),
            active: true,
        }],
    }
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn duplicate_service_identity_is_rejected_before_namespace_mutation() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("EC-003 duplicate-service test requires TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-ec003-duplicate-service-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, "ec003-duplicate")
        .await
        .expect("connect Redis catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate EC-003 fixture incarnation");

    let valid = fixture();
    let mut duplicate = valid.clone();
    duplicate.services.push(valid.services[0].clone());
    let scenario = async {
        let error = match catalog.seed_fixture(&duplicate).await {
            Ok(()) => return Err("duplicate service seed unexpectedly succeeded".into()),
            Err(error) => error,
        };
        if !matches!(error, CatalogError::InvalidInput("service fixture")) {
            return Err("duplicate service seed returned an unexpected error".into());
        }

        // Validation precedes namespace reservation.  A valid seed succeeding
        // in this same namespace proves the rejected duplicate did not leave
        // partial device/service/grant records behind.
        catalog
            .seed_fixture(&valid)
            .await
            .map_err(|error| format!("valid fixture seed after duplicate rejection: {error}"))?;
        let principal = tunnel_catalog::AuthenticatedConsumer {
            tenant_id: valid.tenants[0].tenant_id,
            principal_id: valid.users[0].user_id,
        };
        let devices = catalog
            .list_devices_filtered(&principal, &Default::default(), Utc::now())
            .await
            .map_err(|error| format!("list after duplicate rejection: {error}"))?;
        if devices.len() != 1
            || devices[0].services.len() != 1
            || devices[0].services[0].service_id != valid.services[0].service_id
        {
            return Err(
                "valid seed after duplicate rejection was not the one-service fixture".into(),
            );
        }
        Ok::<(), String>(())
    }
    .await;

    let cleanup = catalog.cleanup_fixture_namespace().await;
    if let Err(error) = cleanup {
        panic!("cleanup EC-003 duplicate-service namespace: {error}");
    }
    scenario.expect("EC-003 duplicate-service scenario");
}
