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
