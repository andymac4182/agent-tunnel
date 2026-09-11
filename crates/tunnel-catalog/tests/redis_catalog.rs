//! Redis authority integration coverage.
//!
//! The default workspace suite leaves this test ignored because Redis is an
//! external authority. The M1 harness runs it explicitly with a disposable
//! primary and a unique namespace; a missing URL is an error, never a pass.

use chrono::{Duration, Utc};
use std::collections::BTreeSet;
use tunnel_catalog::{
    AuthenticatedConsumer, Catalog, CatalogFixture, CredentialRecord, DeviceListFilter,
    FixtureDevice, GrantSpec, MembershipRecord, MembershipRole, OwnerClaimRequest, PermissionSet,
    PrincipalIdentity, RedisCatalog, ServiceSpec, TenantRecord, UserRecord,
};
use uuid::Uuid;

fn fixture() -> CatalogFixture {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let service = Uuid::new_v4();
    let now = Utc::now();
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant,
            display_name: "M1 Redis fixture".into(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user,
            display_name: "fixture user".into(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: "https://issuer.fixture.invalid".into(),
            subject: format!("subject-{user}"),
            user_id: user,
        }],
        memberships: vec![MembershipRecord {
            tenant_id: tenant,
            user_id: user,
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id: tenant,
            device_id: device,
            owner_user_id: user,
            display_name: "fixture device".into(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant,
            device_id: device,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: format!("{:064x}", user.as_u128()),
            serial: Some(format!("serial-{device}")),
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::hours(1),
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id: tenant,
            device_id: device,
            service_id: service,
            service_type: "echo".into(),
            display_name: "fixture echo".into(),
            capabilities: serde_json::json!({"operations":["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: tenant,
            principal_id: user,
            device_id: device,
            service_id: service,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".into()]),
            },
            constraints: serde_json::json!({"max_bytes":4096}),
            expires_at: Some(now + Duration::hours(1)),
            active: true,
        }],
    }
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn redis_catalog_enforces_authorization_and_owner_fencing() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M1 Redis harness must set TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-fixture-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, "fixture-incarnation")
        .await
        .expect("connect Redis catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate explicit fixture incarnation");
    let fixture = fixture();
    catalog.seed_fixture(&fixture).await.expect("seed fixture");

    let principal = AuthenticatedConsumer {
        tenant_id: fixture.tenants[0].tenant_id,
        principal_id: fixture.users[0].user_id,
    };
    let now = Utc::now();
    let device = fixture.devices[0].device_id;
    let service = fixture.services[0].service_id;
    let snapshot = catalog
        .authorize(&principal, device, service, now, now)
        .await
        .expect("authorize fixture")
        .expect("fixture grant visible");
    assert!(snapshot.permissions.allows("echo:invoke"));
    assert_eq!(
        catalog
            .list_devices_filtered(&principal, &DeviceListFilter::default(), now)
            .await
            .expect("list fixture devices")
            .len(),
        1
    );
    let resolved = catalog
        .resolve_device(&fixture.credentials[0].spki_fingerprint, now)
        .await
        .expect("resolve device")
        .expect("credential is live");
    assert_eq!(resolved.device_id, device);

    let first = catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: "fixture-incarnation".into(),
            tenant_id: principal.tenant_id,
            device_id: device,
            node_id: "node-a".into(),
            boot_id: "boot-a".into(),
            session_id: "session-a".into(),
            lease_expires_at: Utc::now() + Duration::seconds(10),
        })
        .await
        .expect("claim owner");
    assert!(matches!(
        catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: "fixture-incarnation".into(),
                tenant_id: principal.tenant_id,
                device_id: device,
                node_id: "node-b".into(),
                boot_id: "boot-b".into(),
                session_id: "session-b".into(),
                lease_expires_at: Utc::now() + Duration::seconds(10),
            })
            .await,
        Err(tunnel_catalog::CatalogError::OwnerBusy)
    ));
    assert!(
        catalog
            .release_owner(&first.token)
            .await
            .expect("release owner")
    );

    catalog
        .revoke_credential(
            principal.tenant_id,
            device,
            fixture.credentials[0].credential_id,
            Utc::now(),
        )
        .await
        .expect("revoke credential");
    assert!(
        catalog
            .resolve_device(&fixture.credentials[0].spki_fingerprint, Utc::now())
            .await
            .expect("recheck revoked credential")
            .is_none()
    );

    let owner = catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: "fixture-incarnation".into(),
            tenant_id: principal.tenant_id,
            device_id: device,
            node_id: "node-a".into(),
            boot_id: "boot-b".into(),
            session_id: "session-b".into(),
            lease_expires_at: Utc::now() + Duration::seconds(10),
        })
        .await
        .expect("claim before device revoke");
    let next_version = catalog
        .revoke_device(principal.tenant_id, device, Utc::now())
        .await
        .expect("revoke device");
    assert!(next_version > resolved.device_version);
    assert!(
        catalog
            .current_owner(principal.tenant_id, device, Utc::now())
            .await
            .expect("current owner")
            .is_none()
    );
    assert!(
        !catalog
            .renew_owner(&owner.token, Utc::now() + Duration::seconds(10))
            .await
            .expect("renew revoked owner")
    );
    assert!(
        catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: "fixture-incarnation".into(),
                tenant_id: principal.tenant_id,
                device_id: device,
                node_id: "node-c".into(),
                boot_id: "boot-c".into(),
                session_id: "session-c".into(),
                lease_expires_at: Utc::now() + Duration::seconds(10),
            })
            .await
            .is_err()
    );

    catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup fixture namespace");
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn redis_normal_startup_rejects_missing_or_partial_incarnation_metadata() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M1 Redis harness must set TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-bootstrap-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect(&url, &namespace)
        .await
        .expect("connect Redis catalog");
    let error =
        RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, "fresh-incarnation")
            .await
            .expect_err("normal startup must not bootstrap metadata");
    assert!(matches!(
        error,
        tunnel_catalog::CatalogError::Conflict(
            "active deployment incarnation or Redis authority run"
        )
    ));

    // A partial restore can leave durable authorization records while losing
    // both authority markers. Existing records must never trigger bootstrap.
    catalog
        .seed_fixture(&fixture())
        .await
        .expect("seed isolated catalog");
    assert!(matches!(
        RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, "fresh-incarnation")
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "active deployment incarnation or Redis authority run"
        ))
    ));

    let client = redis::Client::open(url.as_str()).expect("open Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect Redis client");
    redis::cmd("SET")
        .arg(format!(
            "tunnel-catalog:{namespace}:meta:active_incarnation"
        ))
        .arg("partial-incarnation")
        .query_async::<()>(&mut connection)
        .await
        .expect("write partial metadata");
    let error =
        RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, "partial-incarnation")
            .await
            .expect_err("normal startup must reject one absent metadata key");
    assert!(matches!(
        error,
        tunnel_catalog::CatalogError::Conflict(
            "active deployment incarnation or Redis authority run"
        )
    ));
    redis::cmd("SET")
        .arg(format!("tunnel-catalog:{namespace}:meta:redis_run_id"))
        .arg(format!("old-run-{}", Uuid::new_v4()))
        .query_async::<()>(&mut connection)
        .await
        .expect("write stale Redis run metadata");
    let recovery = RedisCatalog::connect_for_recovery(&url, &namespace, "partial-incarnation")
        .await
        .expect("connect recovery catalog");
    let error = recovery
        .activate_deployment_incarnation()
        .await
        .expect_err("same incarnation cannot cross a Redis run change");
    assert!(matches!(
        error,
        tunnel_catalog::CatalogError::Conflict("active deployment incarnation")
    ));
    catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup bootstrap fixture namespace");
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn redis_fixture_seed_is_one_shot_and_cannot_resurrect_revocation() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M1 Redis harness must set TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-reseed-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, "fixture-incarnation")
        .await
        .expect("connect Redis catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate explicit fixture incarnation");
    let fixture = fixture();
    catalog.seed_fixture(&fixture).await.expect("seed fixture");
    let now = Utc::now();
    catalog
        .revoke_credential(
            fixture.tenants[0].tenant_id,
            fixture.devices[0].device_id,
            fixture.credentials[0].credential_id,
            now,
        )
        .await
        .expect("revoke fixture credential");
    assert!(
        catalog
            .resolve_device(&fixture.credentials[0].spki_fingerprint, Utc::now())
            .await
            .expect("resolve revoked credential")
            .is_none()
    );
    let principal = AuthenticatedConsumer {
        tenant_id: fixture.tenants[0].tenant_id,
        principal_id: fixture.users[0].user_id,
    };
    catalog
        .revoke_grant(
            principal.tenant_id,
            principal.principal_id,
            fixture.devices[0].device_id,
            fixture.services[0].service_id,
            now,
        )
        .await
        .expect("revoke fixture grant");
    let error = catalog
        .seed_fixture(&fixture)
        .await
        .expect_err("reseed must be rejected");
    assert!(matches!(
        error,
        tunnel_catalog::CatalogError::Conflict("fixture namespace already seeded")
    ));
    assert!(
        catalog
            .resolve_device(&fixture.credentials[0].spki_fingerprint, Utc::now())
            .await
            .expect("resolve after rejected reseed")
            .is_none()
    );
    assert!(
        catalog
            .authorize(
                &principal,
                fixture.devices[0].device_id,
                fixture.services[0].service_id,
                Utc::now(),
                Utc::now(),
            )
            .await
            .expect("authorize after rejected reseed")
            .is_none()
    );
    catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup reseed fixture namespace");
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn redis_fixture_seed_rejects_non_fixture_namespace() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M1 Redis harness must set TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("production-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect(&url, &namespace)
        .await
        .expect("connect Redis catalog");
    let error = catalog
        .seed_fixture(&fixture())
        .await
        .expect_err("production namespace fixture seed must be rejected");
    assert!(matches!(
        error,
        tunnel_catalog::CatalogError::InvalidInput("fixture namespace")
    ));
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn redis_authority_clock_bounds_expiry_checks() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M1 Redis harness must set TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-clock-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, "fixture-incarnation")
        .await
        .expect("connect Redis catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate explicit fixture incarnation");
    let fixture = fixture();
    catalog.seed_fixture(&fixture).await.expect("seed fixture");
    let principal = AuthenticatedConsumer {
        tenant_id: fixture.tenants[0].tenant_id,
        principal_id: fixture.users[0].user_id,
    };
    let device = fixture.devices[0].device_id;
    let service = fixture.services[0].service_id;
    let too_old = Utc::now() - Duration::seconds(2);
    assert!(matches!(
        catalog
            .resolve_device(&fixture.credentials[0].spki_fingerprint, too_old)
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "authority clock skew"
        ))
    ));
    assert!(matches!(
        catalog
            .authorize(&principal, device, service, too_old, too_old)
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "authority clock skew"
        ))
    ));
    assert!(matches!(
        catalog
            .list_devices_filtered(&principal, &DeviceListFilter::default(), too_old)
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "authority clock skew"
        ))
    ));

    let base_now = Utc::now();
    let stale_but_bounded = base_now - Duration::milliseconds(500);
    let client = redis::Client::open(url.as_str()).expect("open Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect Redis client");
    let soon_expired = (base_now + Duration::milliseconds(1200))
        .timestamp_micros()
        .to_string();
    redis::cmd("HSET")
        .arg(format!(
            "tunnel-catalog:{namespace}:grant:{}:{}:{}:{}",
            principal.tenant_id, principal.principal_id, device, service
        ))
        .arg("expires_at_us")
        .arg(&soon_expired)
        .query_async::<()>(&mut connection)
        .await
        .expect("set near-expiry grant in Redis");
    let snapshot = catalog
        .authorize(
            &principal,
            device,
            service,
            stale_but_bounded,
            stale_but_bounded,
        )
        .await
        .expect("authorize near-expiry grant")
        .expect("near-expiry grant remains live");
    let translated_deadline = snapshot.valid_until;
    assert!(translated_deadline > stale_but_bounded);
    assert!(translated_deadline <= stale_but_bounded + Duration::milliseconds(1500));

    let already_expired = (base_now - Duration::milliseconds(100))
        .timestamp_micros()
        .to_string();
    redis::cmd("HSET")
        .arg(format!(
            "tunnel-catalog:{namespace}:credential:{}:{}:{}",
            fixture.tenants[0].tenant_id, device, fixture.credentials[0].credential_id
        ))
        .arg("expires_at_us")
        .arg(&already_expired)
        .query_async::<()>(&mut connection)
        .await
        .expect("expire credential in Redis");
    redis::cmd("HSET")
        .arg(format!(
            "tunnel-catalog:{namespace}:grant:{}:{}:{}:{}",
            principal.tenant_id, principal.principal_id, device, service
        ))
        .arg("expires_at_us")
        .arg(&already_expired)
        .query_async::<()>(&mut connection)
        .await
        .expect("expire grant in Redis");
    assert!(
        catalog
            .resolve_device(&fixture.credentials[0].spki_fingerprint, stale_but_bounded)
            .await
            .expect("resolve expired credential")
            .is_none()
    );
    assert!(
        catalog
            .authorize(
                &principal,
                device,
                service,
                stale_but_bounded,
                stale_but_bounded,
            )
            .await
            .expect("authorize expired grant")
            .is_none()
    );
    assert!(
        catalog
            .list_devices_filtered(&principal, &DeviceListFilter::default(), stale_but_bounded)
            .await
            .expect("list expired grant")
            .is_empty()
    );
    catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup clock fixture namespace");
}

/// A caller timestamp that lags the authority by more than the clock-skew
/// budget but still arrives inside the 2 second authority deadline must be
/// honoured, not rejected as clock skew.
///
/// The script cannot separate "the caller's clock is wrong" from "this command
/// spent time in flight": it only ever sees the timestamp the caller sampled
/// before dispatching. docs/cluster.md records the 2 second authority deadline
/// as the single boundary for a maintenance read, with a later reply reported
/// as the `timeout` category. A symmetric skew bound tighter than that deadline
/// creates a second, undocumented boundary in which a reply the transport
/// accepted is deterministically refused, and refused as a `conflict` rather
/// than a timeout. Lagging callers are already fail-closed without the
/// rejection: every script evaluates validity at `math.max(caller_at, now)` and
/// translates the returned windows back into the caller's frame, so a stale
/// caller timestamp can only shorten a validity window, never extend one.
#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn redis_authority_accepts_caller_lag_inside_the_authority_deadline() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M1 Redis harness must set TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-lag-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, "fixture-incarnation")
        .await
        .expect("connect Redis catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate explicit fixture incarnation");
    let fixture = fixture();
    catalog.seed_fixture(&fixture).await.expect("seed fixture");
    let principal = AuthenticatedConsumer {
        tenant_id: fixture.tenants[0].tenant_id,
        principal_id: fixture.users[0].user_id,
    };
    let device = fixture.devices[0].device_id;
    let service = fixture.services[0].service_id;

    // 1.5s is the band the relay's maintenance tick actually observed: past the
    // 1 second skew budget, inside the 2 second authority deadline.
    let lagging = Utc::now() - Duration::milliseconds(1_500);

    let identity = catalog
        .resolve_device(&fixture.credentials[0].spki_fingerprint, lagging)
        .await
        .expect("a reply inside the authority deadline must not be a clock-skew conflict")
        .expect("the seeded credential remains live");
    assert_eq!(identity.device_id, device);
    assert!(identity.device_active);
    assert!(identity.credential_active);
    // The window is translated into the lagging caller's frame, so it may only
    // shorten. It must never be reported as still valid past the real expiry.
    assert!(identity.expires_at <= fixture.credentials[0].expires_at);

    let grant = catalog
        .authorize(&principal, device, service, lagging, lagging)
        .await
        .expect("a reply inside the authority deadline must not be a clock-skew conflict")
        .expect("the seeded grant remains live");
    assert_eq!(grant.device_id, device);
    assert!(grant.valid_until > lagging);

    let devices = catalog
        .list_devices_filtered(&principal, &DeviceListFilter::default(), lagging)
        .await
        .expect("a reply inside the authority deadline must not be a clock-skew conflict");
    assert!(devices.iter().any(|summary| summary.device_id == device));

    // A caller whose clock runs ahead of the authority is genuine skew and
    // stays refused: `math.max` would otherwise extend a validity window.
    let ahead = Utc::now() + Duration::milliseconds(1_500);
    assert!(matches!(
        catalog
            .resolve_device(&fixture.credentials[0].spki_fingerprint, ahead)
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "authority clock skew"
        ))
    ));

    catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup lag fixture namespace");
}
