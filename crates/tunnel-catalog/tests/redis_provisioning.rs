//! Operator bootstrap of a production namespace (task row M6-C21).
//!
//! Every test needs an operator-supplied Redis primary in
//! `TUNNEL_CATALOG_REDIS_URL` and uses a unique namespace that is **not** a
//! `test-`/`fixture-` namespace, because the point is that the operator path
//! works where the fixture seed is refused.  Each test deletes its own keys.

use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use redis::AsyncCommands;
use tunnel_catalog::{
    Catalog, CatalogError, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec,
    MembershipRecord, MembershipRole, PermissionSet, PrincipalIdentity, RedisCatalog, ServiceSpec,
    TenantRecord, UserRecord,
};
use uuid::Uuid;

const INCARNATION: &str = "m6c21-first-incarnation";
const ISSUER: &str = "https://issuer.provisioning.invalid/";
const SUBJECT: &str = "m6c21-operator";

fn url() -> String {
    std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("provisioning tests require TUNNEL_CATALOG_REDIS_URL")
}

fn fresh_namespace() -> String {
    format!("m6c21-prov-{}", Uuid::new_v4().simple())
}

struct Ids {
    tenant: Uuid,
    user: Uuid,
    device: Uuid,
    service: Uuid,
    fingerprint: String,
}

fn records() -> (CatalogFixture, Ids) {
    let ids = Ids {
        tenant: Uuid::new_v4(),
        user: Uuid::new_v4(),
        device: Uuid::new_v4(),
        service: Uuid::new_v4(),
        fingerprint: format!("{:064x}", Uuid::new_v4().as_u128()),
    };
    let now = Utc::now();
    let fixture = CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: ids.tenant,
            display_name: "tenant".into(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: ids.user,
            display_name: "user".into(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: ISSUER.into(),
            subject: SUBJECT.into(),
            user_id: ids.user,
        }],
        memberships: vec![MembershipRecord {
            tenant_id: ids.tenant,
            user_id: ids.user,
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id: ids.tenant,
            device_id: ids.device,
            owner_user_id: ids.user,
            display_name: "device".into(),
            active: true,
            last_seen_at: None,
        }],
        credentials: vec![CredentialRecord {
            tenant_id: ids.tenant,
            device_id: ids.device,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: ids.fingerprint.clone(),
            serial: None,
            not_before: now - Duration::minutes(1),
            expires_at: now + Duration::hours(1),
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id: ids.tenant,
            device_id: ids.device,
            service_id: ids.service,
            service_type: "echo".into(),
            display_name: "echo".into(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: ids.tenant,
            principal_id: ids.user,
            device_id: ids.device,
            service_id: ids.service,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            expires_at: None,
            active: true,
        }],
    };
    (fixture, ids)
}

async fn keys(namespace: &str) -> Vec<String> {
    let client = redis::Client::open(url()).expect("open Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect Redis");
    let mut found: Vec<String> = connection
        .keys(format!("tunnel-catalog:{namespace}:*"))
        .await
        .expect("list namespace keys");
    found.sort();
    found
}

async fn delete_namespace(namespace: &str) {
    let found = keys(namespace).await;
    if found.is_empty() {
        return;
    }
    let client = redis::Client::open(url()).expect("open Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect Redis");
    let _: () = connection.del(found).await.expect("delete namespace keys");
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn first_activation_then_provisioning_yields_records_serve_resolves() {
    let namespace = fresh_namespace();
    let bootstrap = RedisCatalog::connect_for_recovery(&url(), &namespace, INCARNATION)
        .await
        .expect("connect for bootstrap");
    // `serve`'s own fence refuses the empty namespace before activation...
    assert!(
        RedisCatalog::connect_with_deployment_incarnation(&url(), &namespace, INCARNATION)
            .await
            .is_err(),
        "serve's fence must refuse a namespace with no incarnation"
    );
    bootstrap
        .activate_first_deployment_incarnation()
        .await
        .expect("first activation of an empty namespace");
    // ...and accepts it after.
    let serving =
        RedisCatalog::connect_with_deployment_incarnation(&url(), &namespace, INCARNATION)
            .await
            .expect("serve's fence accepts the activated namespace");

    let (records, ids) = records();
    bootstrap
        .provision_initial_catalog(&records)
        .await
        .expect("provision a production namespace");

    let now = Utc::now();
    let device = serving
        .resolve_device(&ids.fingerprint, now)
        .await
        .expect("resolve device")
        .expect("the credential resolves");
    assert_eq!(device.tenant_id, ids.tenant);
    assert_eq!(device.device_id, ids.device);
    assert!(device.device_active && device.credential_active);
    let consumer = serving
        .resolve_consumer(ISSUER, SUBJECT, None)
        .await
        .expect("resolve consumer")
        .expect("the issuer identity resolves");
    assert_eq!(consumer.tenant_id, ids.tenant);
    assert_eq!(consumer.principal_id, ids.user);
    let grant = serving
        .authorize(&consumer, ids.device, ids.service, now, now)
        .await
        .expect("authorize")
        .expect("the grant authorizes");
    assert!(grant.permissions.allows("echo:invoke"));
    // The namespace stays observable by the recovery workflow.
    let observation = serving
        .observe_durable_catalog()
        .await
        .expect("recovery can observe a provisioned namespace");
    assert!(observation.key_count() > 0);

    delete_namespace(&namespace).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn first_activation_refuses_any_namespace_that_is_not_empty() {
    let namespace = fresh_namespace();
    let first = RedisCatalog::connect_for_recovery(&url(), &namespace, INCARNATION)
        .await
        .expect("connect");
    first
        .activate_first_deployment_incarnation()
        .await
        .expect("first activation");
    // Repeating it, or naming another incarnation, is a recovery transition.
    for incarnation in [INCARNATION, "m6c21-second-incarnation"] {
        let again = RedisCatalog::connect_for_recovery(&url(), &namespace, incarnation)
            .await
            .expect("connect");
        match again.activate_first_deployment_incarnation().await {
            Err(CatalogError::Conflict(message)) => {
                assert!(message.contains("requires recovery"), "{message}");
            }
            other => panic!("{incarnation}: expected an active refusal, got {other:?}"),
        }
    }
    delete_namespace(&namespace).await;

    // Any stray key -- here a lone tenant record -- also refuses it.
    let occupied = fresh_namespace();
    let client = redis::Client::open(url()).expect("open Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect Redis");
    let _: () = connection
        .set(format!("tunnel-catalog:{occupied}:idx:tenants"), "x")
        .await
        .expect("plant a key");
    let catalog = RedisCatalog::connect_for_recovery(&url(), &occupied, INCARNATION)
        .await
        .expect("connect");
    match catalog.activate_first_deployment_incarnation().await {
        Err(CatalogError::Conflict(message)) => {
            assert!(message.contains("not empty"), "{message}");
        }
        other => panic!("expected an occupied refusal, got {other:?}"),
    }
    assert_eq!(keys(&occupied).await.len(), 1, "nothing was written");
    delete_namespace(&occupied).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn provisioning_requires_an_active_incarnation_valid_records_and_runs_once() {
    let namespace = fresh_namespace();
    let catalog = RedisCatalog::connect_for_recovery(&url(), &namespace, INCARNATION)
        .await
        .expect("connect");
    let (records, _) = records();

    // Before activation: the same fence `serve` applies refuses the write.
    assert!(catalog.provision_initial_catalog(&records).await.is_err());
    assert!(keys(&namespace).await.is_empty(), "nothing was written");

    catalog
        .activate_first_deployment_incarnation()
        .await
        .expect("first activation");

    // Invalid records are refused by the fixture seed's own validation,
    // before the reservation is taken.
    let mut invalid = records.clone();
    invalid.grants[0].service_id = Uuid::new_v4();
    match catalog.provision_initial_catalog(&invalid).await {
        Err(CatalogError::InvalidInput(message)) => assert_eq!(message, "grant fixture"),
        other => panic!("expected the grant relationship refusal, got {other:?}"),
    }
    assert_eq!(keys(&namespace).await.len(), 2, "only the activation keys");

    catalog
        .provision_initial_catalog(&records)
        .await
        .expect("first provisioning");
    match catalog.provision_initial_catalog(&records).await {
        Err(CatalogError::Conflict(message)) => {
            assert!(message.contains("already provisioned"), "{message}");
        }
        other => panic!("expected a one-shot refusal, got {other:?}"),
    }
    delete_namespace(&namespace).await;
}

async fn get(namespace: &str, key: &str) -> Option<String> {
    let client = redis::Client::open(url()).expect("open Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect Redis");
    connection
        .get(format!("tunnel-catalog:{namespace}:{key}"))
        .await
        .expect("GET")
}

/// Task row M6-C31: day-2 additions on a provisioned namespace.  Each is one
/// script: it refuses a namespace `provision-catalog` has not run on and a
/// stale incarnation, refuses every duplicate without writing, never touches
/// the incarnation, run or reservation keys, advances the catalog generation,
/// and writes records `serve`'s own reads resolve.
#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m6c31_day2_additions_are_atomic_refuse_duplicates_and_keep_the_authority_records() {
    let namespace = fresh_namespace();
    let catalog = RedisCatalog::connect_for_recovery(&url(), &namespace, INCARNATION)
        .await
        .expect("connect");
    catalog
        .activate_first_deployment_incarnation()
        .await
        .expect("first activation");
    let (records, ids) = records();

    let second_user = Uuid::new_v4();
    let user = UserRecord {
        user_id: second_user,
        display_name: "second user".into(),
    };
    let identity = PrincipalIdentity {
        issuer: ISSUER.into(),
        subject: "m6c31-second-user".into(),
        user_id: second_user,
    };
    let membership = MembershipRecord {
        tenant_id: ids.tenant,
        user_id: second_user,
        role: MembershipRole::Member,
        active: true,
    };

    // Before provisioning: refused, and nothing is written, so
    // `provision-catalog` can still run on this namespace.
    let before = keys(&namespace).await;
    match catalog.add_user(&user, &identity, &membership).await {
        Err(CatalogError::Conflict(message)) => {
            assert!(message.contains("not been provisioned"), "{message}");
        }
        other => panic!("expected an unprovisioned refusal, got {other:?}"),
    }
    assert_eq!(keys(&namespace).await, before, "nothing was written");

    catalog
        .provision_initial_catalog(&records)
        .await
        .expect("first provisioning");
    let incarnation = get(&namespace, "meta:active_incarnation").await;
    let run_id = get(&namespace, "meta:redis_run_id").await;
    let generation =
        |value: Option<String>| -> u64 { value.expect("generation").parse().expect("decimal") };
    let provisioned_generation = generation(get(&namespace, "meta:catalog_generation").await);

    // A catalog configured with another incarnation is refused by the script.
    let stale = RedisCatalog::connect_for_recovery(&url(), &namespace, "m6c31-other")
        .await
        .expect("connect with another incarnation");
    match stale.add_user(&user, &identity, &membership).await {
        Err(CatalogError::Conflict(message)) => {
            assert!(message.contains("incarnation"), "{message}");
        }
        other => panic!("expected an incarnation refusal, got {other:?}"),
    }

    catalog
        .add_user(&user, &identity, &membership)
        .await
        .expect("add the second user");
    // Repeating it, or binding the same subject to another user, is refused.
    match catalog.add_user(&user, &identity, &membership).await {
        Err(CatalogError::Conflict(message)) => assert_eq!(message, "user already exists"),
        other => panic!("expected a duplicate refusal, got {other:?}"),
    }
    let third = Uuid::new_v4();
    match catalog
        .add_user(
            &UserRecord {
                user_id: third,
                display_name: "third".into(),
            },
            &PrincipalIdentity {
                user_id: third,
                ..identity.clone()
            },
            &MembershipRecord {
                user_id: third,
                ..membership.clone()
            },
        )
        .await
    {
        Err(CatalogError::Conflict(message)) => {
            assert!(message.contains("already bound"), "{message}");
        }
        other => panic!("expected an identity refusal, got {other:?}"),
    }
    assert!(
        keys(&namespace)
            .await
            .iter()
            .all(|key| !key.contains(&third.to_string())),
        "a refused user writes nothing"
    );

    // A second device, owned by the second user.
    let second_device = Uuid::new_v4();
    let now = Utc::now();
    let device = FixtureDevice {
        tenant_id: ids.tenant,
        device_id: second_device,
        owner_user_id: second_user,
        display_name: "second device".into(),
        active: true,
        last_seen_at: None,
    };
    let fingerprint = format!("{:064x}", Uuid::new_v4().as_u128());
    let credential = CredentialRecord {
        tenant_id: ids.tenant,
        device_id: second_device,
        credential_id: Uuid::new_v4(),
        spki_fingerprint: fingerprint.clone(),
        serial: Some("01".into()),
        not_before: now - Duration::minutes(1),
        expires_at: now + Duration::hours(1),
        revoked_at: None,
        active: true,
    };
    // An owner outside the tenant is refused.
    let stranger_owner = FixtureDevice {
        owner_user_id: Uuid::new_v4(),
        ..device.clone()
    };
    match catalog.add_device(&stranger_owner, &credential).await {
        Err(CatalogError::Conflict(message)) => assert!(message.contains("owner"), "{message}"),
        other => panic!("expected an owner refusal, got {other:?}"),
    }
    // The first device's pin is refused for a new device.
    let reused_pin = CredentialRecord {
        spki_fingerprint: ids.fingerprint.clone(),
        ..credential.clone()
    };
    match catalog.add_device(&device, &reused_pin).await {
        Err(CatalogError::Conflict(message)) => {
            assert_eq!(message, "duplicate SPKI fingerprint");
        }
        other => panic!("expected a pin refusal, got {other:?}"),
    }
    assert!(
        keys(&namespace)
            .await
            .iter()
            .all(|key| !key.contains(&second_device.to_string())),
        "a refused device writes nothing"
    );
    catalog
        .add_device(&device, &credential)
        .await
        .expect("add the second device");
    match catalog.add_device(&device, &credential).await {
        Err(CatalogError::Conflict(message)) => {
            assert!(message.contains("already exists"), "{message}");
        }
        other => panic!("expected a duplicate device refusal, got {other:?}"),
    }

    let second_service = Uuid::new_v4();
    let service = ServiceSpec {
        tenant_id: ids.tenant,
        device_id: second_device,
        service_id: second_service,
        service_type: "echo".into(),
        display_name: "second echo".into(),
        capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
        version: 1,
        active: true,
    };
    catalog.add_service(&service).await.expect("add a service");
    match catalog.add_service(&service).await {
        Err(CatalogError::Conflict(message)) => assert_eq!(message, "service already exists"),
        other => panic!("expected a duplicate service refusal, got {other:?}"),
    }
    let read = catalog
        .read_service(ids.tenant, second_device, second_service)
        .await
        .expect("read service")
        .expect("the service exists");
    assert_eq!(read, service);
    assert!(
        catalog
            .read_service(ids.tenant, second_device, Uuid::new_v4())
            .await
            .expect("read")
            .is_none()
    );

    // Everything `serve` reads resolves the additions.
    let serving =
        RedisCatalog::connect_with_deployment_incarnation(&url(), &namespace, INCARNATION)
            .await
            .expect("serve's fence still accepts the namespace");
    let resolved = serving
        .resolve_device(&fingerprint, Utc::now())
        .await
        .expect("resolve")
        .expect("the added credential resolves");
    assert_eq!(resolved.device_id, second_device);
    assert_eq!(resolved.owner_user_id, second_user);
    let consumer = serving
        .resolve_consumer(ISSUER, "m6c31-second-user", None)
        .await
        .expect("resolve consumer")
        .expect("the added identity resolves");
    assert_eq!(consumer.principal_id, second_user);
    let now = Utc::now();
    assert!(
        serving
            .authorize(&consumer, second_device, second_service, now, now)
            .await
            .expect("authorize")
            .is_none(),
        "no grant yet"
    );
    serving
        .upsert_grant(&GrantSpec {
            tenant_id: ids.tenant,
            principal_id: second_user,
            device_id: second_device,
            service_id: second_service,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            expires_at: None,
            active: true,
        })
        .await
        .expect("grant");
    let now = Utc::now();
    assert!(
        serving
            .authorize(&consumer, second_device, second_service, now, now)
            .await
            .expect("authorize")
            .is_some()
    );

    // The authority records are untouched; the generation advanced once per
    // accepted addition (user, device, service) and once for the grant.
    assert_eq!(
        get(&namespace, "meta:active_incarnation").await,
        incarnation
    );
    assert_eq!(get(&namespace, "meta:redis_run_id").await, run_id);
    assert_eq!(
        get(&namespace, "meta:fixture_seeded").await.as_deref(),
        Some("1")
    );
    assert_eq!(
        generation(get(&namespace, "meta:catalog_generation").await),
        provisioned_generation + 4
    );
    let epoch = get(
        &namespace,
        &format!("coord:epoch:{}:{second_device}", ids.tenant),
    )
    .await;
    assert_eq!(epoch.as_deref(), Some("0"));
    // Recovery still observes the namespace.
    serving
        .observe_durable_catalog()
        .await
        .expect("recovery can observe a namespace with day-2 additions");
    delete_namespace(&namespace).await;
}
