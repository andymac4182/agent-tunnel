//! M7 durable-catalog recovery integration coverage.
//!
//! Every test requires an operator-supplied Redis primary and uses a unique
//! `test-recovery-*` namespace.

use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use redis::AsyncCommands;
use tunnel_catalog::{
    Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord,
    MembershipRole, RecoveryApproval, RecoveryApprovalIssuer, RecoveryApprovalVerifier,
    RecoveryError, RecoveryPolicy, RedisCatalog, TenantRecord, TrustedRecoveryKey, UserRecord,
};
use uuid::Uuid;

const DEPLOYMENT_ID: &str = "recovery-test-deployment";
const INITIAL_INCARC: &str = "recovery-initial-incarnation";

struct Fixture {
    catalog: RedisCatalog,
    url: String,
    namespace: String,
    tenant: Uuid,
    user: Uuid,
    device: Uuid,
    service: Uuid,
}

fn fixture_values() -> (CatalogFixture, Uuid, Uuid, Uuid, Uuid, GrantSpec) {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let service = Uuid::new_v4();
    let now = Utc::now();
    let grant = GrantSpec {
        tenant_id: tenant,
        principal_id: user,
        device_id: device,
        service_id: service,
        permissions: tunnel_catalog::PermissionSet {
            operations: BTreeSet::from(["echo:invoke".to_owned()]),
        },
        constraints: serde_json::json!({"max_bytes": 4096}),
        expires_at: Some(now + Duration::hours(1)),
        active: true,
    };
    let fixture = CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant,
            display_name: "recovery tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user,
            display_name: "recovery user".to_owned(),
        }],
        identities: vec![tunnel_catalog::PrincipalIdentity {
            issuer: "https://issuer.recovery.invalid".to_owned(),
            subject: format!("recovery-subject-{user}"),
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
            display_name: "recovery device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant,
            device_id: device,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            serial: Some("recovery-credential".to_owned()),
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::hours(1),
            revoked_at: None,
            active: true,
        }],
        services: vec![tunnel_catalog::ServiceSpec {
            tenant_id: tenant,
            device_id: device,
            service_id: service,
            service_type: "echo".to_owned(),
            display_name: "recovery echo".to_owned(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![grant.clone()],
    };
    (fixture, tenant, user, device, service, grant)
}

async fn fixture() -> Fixture {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M7 recovery tests require TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-recovery-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, INITIAL_INCARC)
        .await
        .expect("connect recovery catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate initial incarnation");
    let (records, tenant, user, device, service, _grant) = fixture_values();
    catalog
        .seed_fixture(&records)
        .await
        .expect("seed recovery fixture");
    Fixture {
        catalog,
        url,
        namespace,
        tenant,
        user,
        device,
        service,
    }
}

async fn cleanup(fixture: &Fixture) {
    fixture
        .catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup recovery namespace");
}

async fn active_incarnation(url: &str, namespace: &str) -> String {
    let client = redis::Client::open(url).expect("open raw Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect raw Redis client");
    connection
        .get(format!(
            "tunnel-catalog:{namespace}:meta:active_incarnation"
        ))
        .await
        .expect("read active incarnation")
}

async fn raw_unit(url: &str, command: &mut redis::Cmd) {
    let client = redis::Client::open(url).expect("open raw Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect raw Redis client");
    command
        .query_async::<()>(&mut connection)
        .await
        .expect("raw Redis command");
}

fn signed_approval(
    fixture: &Fixture,
    digest: &str,
    run_id: &str,
    incarnation: &str,
    now: chrono::DateTime<Utc>,
    approval_version: u64,
) -> tunnel_catalog::VerifiedRecoveryApproval {
    let (issuer, _) = RecoveryApprovalIssuer::generate("recovery-publisher")
        .expect("generate recovery publisher");
    let trusted = TrustedRecoveryKey::new(
        "recovery-publisher",
        issuer.public_key().expect("publisher public key"),
    )
    .expect("trusted recovery key");
    let policy = RecoveryPolicy::new(DEPLOYMENT_ID, &fixture.namespace, run_id, incarnation)
        .expect("recovery policy");
    let verifier = RecoveryApprovalVerifier::new(policy, [trusted]).expect("recovery verifier");
    let nonce = format!("nonce-{approval_version:016x}-recovery");
    let approval = RecoveryApproval {
        schema_version: 1,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        redis_namespace: fixture.namespace.clone(),
        redis_run_id: run_id.to_owned(),
        deployment_incarnation: incarnation.to_owned(),
        approval_version,
        nonce: nonce.clone(),
        catalog_digest: digest.to_owned(),
        issued_at: now - Duration::seconds(1),
        not_before: now - Duration::milliseconds(500),
        expires_at: now + Duration::seconds(20),
    };
    let bytes = issuer
        .sign_approval_bytes(approval)
        .expect("sign recovery approval");
    verifier
        .verify(&bytes, &nonce, now, None)
        .expect("verify recovery approval")
}

fn assert_catalog_schema_error(error: tunnel_catalog::CatalogError, expected: &str) {
    // Preserve the exact bounded schema cause so a generic `is_err()` cannot
    // pass accidentally.
    match error {
        tunnel_catalog::CatalogError::Serialization(message) => assert_eq!(message, expected),
        other => panic!("expected recovery schema cause {expected:?}, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_activates_fresh_incarnation_from_complete_catalog_and_preserves_digest() {
    let fixture = fixture().await;
    let before = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect("observe complete durable catalog");
    assert!(before.key_count() > 0);
    assert!(before.byte_count() > 0);
    let approval = signed_approval(
        &fixture,
        before.catalog_digest(),
        before.redis_run_id(),
        "recovery-approved-incarnation",
        Utc::now(),
        1,
    );
    let recovered = RedisCatalog::connect_for_recovery(
        &fixture.url,
        &fixture.namespace,
        "recovery-approved-incarnation",
    )
    .await
    .expect("connect recovery incarnation");
    recovered
        .activate_deployment_incarnation_with_approval(&approval)
        .await
        .expect("activate signed recovery incarnation");
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        "recovery-approved-incarnation"
    );
    let after = recovered
        .observe_durable_catalog()
        .await
        .expect("observe catalog after activation");
    assert_eq!(after.catalog_digest(), before.catalog_digest());
    assert_eq!(after.redis_run_id(), before.redis_run_id());
    cleanup(&fixture).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_rejects_revocation_rollback_digest_and_keeps_active_incarnation() {
    let fixture = fixture().await;
    let before = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect("observe complete catalog");
    fixture
        .catalog
        .revoke_grant(
            fixture.tenant,
            fixture.user,
            fixture.device,
            fixture.service,
            Utc::now(),
        )
        .await
        .expect("revoke durable grant");
    let approval = signed_approval(
        &fixture,
        before.catalog_digest(),
        before.redis_run_id(),
        "rollback-incarnation",
        Utc::now(),
        2,
    );
    let recovered = RedisCatalog::connect_for_recovery(
        &fixture.url,
        &fixture.namespace,
        "rollback-incarnation",
    )
    .await
    .expect("connect rollback recovery");
    let error = recovered
        .activate_deployment_incarnation_with_approval(&approval)
        .await
        .expect_err("stale pre-revocation approval must fail");
    assert!(matches!(
        error,
        tunnel_catalog::CatalogError::Conflict("recovery approval catalog digest")
    ));
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );
    cleanup(&fixture).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_rejects_live_owner_for_same_and_new_incarnation() {
    let fixture = fixture().await;
    let owner = fixture
        .catalog
        .claim_owner(&tunnel_catalog::OwnerClaimRequest {
            deployment_incarnation: INITIAL_INCARC.to_owned(),
            tenant_id: fixture.tenant,
            device_id: fixture.device,
            node_id: "live-recovery-owner".to_owned(),
            boot_id: "live-recovery-boot".to_owned(),
            session_id: "live-recovery-session".to_owned(),
            lease_expires_at: Utc::now() + Duration::seconds(10),
        })
        .await
        .expect("claim live owner");
    let observation = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect("observe catalog with live owner");
    let same_approval = signed_approval(
        &fixture,
        observation.catalog_digest(),
        observation.redis_run_id(),
        INITIAL_INCARC,
        Utc::now(),
        3,
    );
    let same = RedisCatalog::connect_for_recovery(&fixture.url, &fixture.namespace, INITIAL_INCARC)
        .await
        .expect("connect same recovery incarnation");
    assert!(matches!(
        same.activate_deployment_incarnation_with_approval(&same_approval)
            .await,
        Err(tunnel_catalog::CatalogError::OwnerBusy)
    ));

    let new_approval = signed_approval(
        &fixture,
        observation.catalog_digest(),
        observation.redis_run_id(),
        "new-owner-blocked-incarnation",
        Utc::now(),
        4,
    );
    let new = RedisCatalog::connect_for_recovery(
        &fixture.url,
        &fixture.namespace,
        "new-owner-blocked-incarnation",
    )
    .await
    .expect("connect new recovery incarnation");
    assert!(matches!(
        new.activate_deployment_incarnation_with_approval(&new_approval)
            .await,
        Err(tunnel_catalog::CatalogError::OwnerBusy)
    ));
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );
    assert!(
        fixture
            .catalog
            .release_owner(&owner.token)
            .await
            .expect("release owner")
    );
    cleanup(&fixture).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_rejects_orphan_fingerprint_and_preserves_active_incarnation() {
    let fixture = fixture().await;
    let orphan_fingerprint = "a".repeat(64);
    let orphan_credential = Uuid::new_v4();
    raw_unit(
        &fixture.url,
        redis::cmd("SET")
            .arg(format!(
                "tunnel-catalog:{}:idx:fingerprint:{orphan_fingerprint}",
                fixture.namespace
            ))
            .arg(format!(
                "tunnel-catalog:{}:credential:{}:{}:{orphan_credential}",
                fixture.namespace, fixture.tenant, fixture.device
            )),
    )
    .await;
    let error = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect_err("orphan fingerprint lookup must fail closed");
    assert_catalog_schema_error(error, "orphan Redis index or direct lookup");
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );
    cleanup(&fixture).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_rejects_orphan_epoch_and_unknown_durable_key() {
    for (suffix, value, expected) in [
        (
            format!("coord:epoch:{}:{}", Uuid::new_v4(), Uuid::new_v4()),
            "1",
            "orphan Redis index or direct lookup",
        ),
        (
            "unknown:durable-record".to_owned(),
            "x",
            "unknown Redis key class",
        ),
    ] {
        let fixture = fixture().await;
        raw_unit(
            &fixture.url,
            redis::cmd("SET")
                .arg(format!("tunnel-catalog:{}:{suffix}", fixture.namespace))
                .arg(value),
        )
        .await;
        let error = fixture
            .catalog
            .observe_durable_catalog()
            .await
            .expect_err("malformed durable namespace must fail closed");
        assert_catalog_schema_error(error, expected);
        assert_eq!(
            active_incarnation(&fixture.url, &fixture.namespace).await,
            INITIAL_INCARC
        );
        cleanup(&fixture).await;
    }
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_rejects_missing_epoch_for_seeded_device_and_preserves_incarnation() {
    let fixture = fixture().await;
    let observation = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect("observe complete catalog before epoch deletion");
    let approval = signed_approval(
        &fixture,
        observation.catalog_digest(),
        observation.redis_run_id(),
        "missing-epoch-incarnation",
        Utc::now(),
        8,
    );
    raw_unit(
        &fixture.url,
        redis::cmd("DEL").arg(format!(
            "tunnel-catalog:{}:coord:epoch:{}:{}",
            fixture.namespace, fixture.tenant, fixture.device
        )),
    )
    .await;

    let observed_error = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect_err("seeded device without retained epoch must fail closed");
    assert_catalog_schema_error(observed_error, "missing durable device epoch");

    let recovered = RedisCatalog::connect_for_recovery(
        &fixture.url,
        &fixture.namespace,
        "missing-epoch-incarnation",
    )
    .await
    .expect("connect missing-epoch recovery");
    let activation_error = recovered
        .activate_deployment_incarnation_with_approval(&approval)
        .await
        .expect_err("activation must reject a missing retained epoch");
    assert_catalog_schema_error(activation_error, "missing durable device epoch");
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );
    cleanup(&fixture).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_rejects_oversized_namespace_key_before_materialization() {
    let fixture = fixture().await;
    let oversized_key = format!(
        "tunnel-catalog:{}:oversized:{}",
        fixture.namespace,
        "k".repeat(256 * 1024 + 1)
    );
    raw_unit(&fixture.url, redis::cmd("SET").arg(oversized_key).arg("x")).await;

    let error = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect_err("oversized namespace key must fail before materialization");
    assert!(matches!(
        error,
        tunnel_catalog::CatalogError::Conflict("recovery namespace scan batch bound")
    ));
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );
    cleanup(&fixture).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_rejects_cumulative_namespace_key_bytes() {
    let fixture = fixture().await;
    let suffix = "b".repeat(8_000);
    let mut command = redis::cmd("MSET");
    for index in 0..530 {
        command
            .arg(format!(
                "tunnel-catalog:{}:key-budget:{index:04}:{suffix}",
                fixture.namespace
            ))
            .arg("x");
    }
    raw_unit(&fixture.url, &mut command).await;

    let error = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect_err("cumulative namespace key bytes must fail closed");
    match error {
        tunnel_catalog::CatalogError::Conflict(message) => assert!(
            message == "recovery namespace key bound"
                || message == "recovery namespace scan batch bound",
            "unexpected bounded scan error: {message}"
        ),
        other => panic!("expected bounded scan conflict, got {other:?}"),
    }
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );
    cleanup(&fixture).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_rejects_ttl_on_durable_key_and_preserves_active_incarnation() {
    let fixture = fixture().await;
    let device_key = format!(
        "tunnel-catalog:{}:device:{}:{}",
        fixture.namespace, fixture.tenant, fixture.device
    );
    raw_unit(
        &fixture.url,
        redis::cmd("PEXPIRE").arg(device_key).arg(60_000_i64),
    )
    .await;
    let error = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect_err("durable catalog TTL must fail closed");
    assert_catalog_schema_error(error, "Redis TTL does not match key class");
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );
    cleanup(&fixture).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn recovery_rejects_expired_untrusted_and_wrong_run_approvals_without_activation() {
    let fixture = fixture().await;
    let observation = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect("observe catalog");
    let now = Utc::now();
    let (trusted_issuer, _) =
        RecoveryApprovalIssuer::generate("trusted-recovery").expect("trusted issuer");
    let verifier = RecoveryApprovalVerifier::new(
        RecoveryPolicy::new(
            DEPLOYMENT_ID,
            &fixture.namespace,
            observation.redis_run_id(),
            "approval-negative-incarnation",
        )
        .expect("approval policy"),
        [TrustedRecoveryKey::new(
            "trusted-recovery",
            trusted_issuer.public_key().expect("trusted public key"),
        )
        .expect("trusted key")],
    )
    .expect("approval verifier");
    let expired = RecoveryApproval {
        schema_version: 1,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        redis_namespace: fixture.namespace.clone(),
        redis_run_id: observation.redis_run_id().to_owned(),
        deployment_incarnation: "approval-negative-incarnation".to_owned(),
        approval_version: 5,
        nonce: "expired-recovery-nonce".to_owned(),
        catalog_digest: observation.catalog_digest().to_owned(),
        issued_at: now - Duration::seconds(120),
        not_before: now - Duration::seconds(120),
        expires_at: now - Duration::seconds(60),
    };
    let expired_bytes = trusted_issuer
        .sign_approval_bytes(expired)
        .expect("sign expired approval");
    assert_eq!(
        verifier.verify(&expired_bytes, "expired-recovery-nonce", now, None),
        Err(RecoveryError::Expired)
    );
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );

    let (untrusted_issuer, _) =
        RecoveryApprovalIssuer::generate("untrusted-recovery").expect("untrusted issuer");
    let untrusted = RecoveryApproval {
        schema_version: 1,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        redis_namespace: fixture.namespace.clone(),
        redis_run_id: observation.redis_run_id().to_owned(),
        deployment_incarnation: "approval-negative-incarnation".to_owned(),
        approval_version: 6,
        nonce: "untrusted-recovery-nonce".to_owned(),
        catalog_digest: observation.catalog_digest().to_owned(),
        issued_at: now - Duration::seconds(1),
        not_before: now - Duration::milliseconds(500),
        expires_at: now + Duration::seconds(20),
    };
    let untrusted_bytes = untrusted_issuer
        .sign_approval_bytes(untrusted)
        .expect("sign untrusted approval");
    assert_eq!(
        verifier.verify(&untrusted_bytes, "untrusted-recovery-nonce", now, None),
        Err(RecoveryError::UnknownTrustedKey(
            "untrusted-recovery".to_owned()
        ))
    );
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );

    let (wrong_run_issuer, _) =
        RecoveryApprovalIssuer::generate("wrong-run-recovery").expect("wrong-run issuer");
    let wrong_run_trusted = TrustedRecoveryKey::new(
        "wrong-run-recovery",
        wrong_run_issuer.public_key().expect("wrong-run public key"),
    )
    .expect("wrong-run trusted key");
    let wrong_run_verifier = RecoveryApprovalVerifier::new(
        RecoveryPolicy::new(
            DEPLOYMENT_ID,
            &fixture.namespace,
            "wrong-live-run-id",
            "approval-negative-incarnation",
        )
        .expect("wrong-run policy"),
        [wrong_run_trusted],
    )
    .expect("wrong-run verifier");
    let wrong_run_nonce = "wrong-run-recovery-nonce";
    let wrong_run = RecoveryApproval {
        schema_version: 1,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        redis_namespace: fixture.namespace.clone(),
        redis_run_id: "wrong-live-run-id".to_owned(),
        deployment_incarnation: "approval-negative-incarnation".to_owned(),
        approval_version: 7,
        nonce: wrong_run_nonce.to_owned(),
        catalog_digest: observation.catalog_digest().to_owned(),
        issued_at: now - Duration::seconds(1),
        not_before: now - Duration::milliseconds(500),
        expires_at: now + Duration::seconds(20),
    };
    let wrong_run_bytes = wrong_run_issuer
        .sign_approval_bytes(wrong_run)
        .expect("sign wrong-run approval");
    let wrong_run_approval = wrong_run_verifier
        .verify(&wrong_run_bytes, wrong_run_nonce, now, None)
        .expect("wrong-run approval signature is otherwise valid");
    let recovered = RedisCatalog::connect_for_recovery(
        &fixture.url,
        &fixture.namespace,
        "approval-negative-incarnation",
    )
    .await
    .expect("connect wrong-run recovery");
    assert!(matches!(
        recovered
            .activate_deployment_incarnation_with_approval(&wrong_run_approval)
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "recovery approval Redis run id"
        ))
    ));
    assert_eq!(
        active_incarnation(&fixture.url, &fixture.namespace).await,
        INITIAL_INCARC
    );
    cleanup(&fixture).await;
}
