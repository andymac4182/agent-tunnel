//! M7 coordination integration coverage.
//!
//! These tests are ignored in the ordinary workspace suite because they need
//! an operator-provided Redis primary.  The harness supplies
//! `TUNNEL_CATALOG_REDIS_URL`; every test uses a disposable namespace.

use chrono::{Duration, Utc};
use redis::AsyncCommands;
use std::collections::BTreeSet;
use tunnel_catalog::{
    AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest, Catalog, CatalogFixture,
    CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord, MembershipRole, OwnerClaim,
    OwnerClaimRequest, PermissionSet, PrincipalIdentity, RedisCatalog, RedisMembershipPublisher,
    ServiceSpec, SignedMembershipRecord, TenantRecord, UserRecord,
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
            display_name: "M7 tenant".into(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id,
            display_name: "M7 user".into(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: "https://issuer.m7.invalid".into(),
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
            display_name: "M7 device".into(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id,
            device_id,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .into(),
            serial: Some("m7".into()),
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
            display_name: "M7 echo".into(),
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

async fn catalog() -> (RedisCatalog, CatalogFixture, String) {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M7 Redis tests require TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-cluster-{}", Uuid::new_v4());
    let incarnation = "m7-incarnation".to_owned();
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, &incarnation)
        .await
        .expect("connect Redis catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate M7 incarnation");
    let fixture = fixture();
    catalog.seed_fixture(&fixture).await.expect("seed fixture");
    (catalog, fixture, namespace)
}

fn claim_request(fixture: &CatalogFixture, incarnation: &str, node: &str) -> OwnerClaimRequest {
    OwnerClaimRequest {
        deployment_incarnation: incarnation.into(),
        tenant_id: fixture.devices[0].tenant_id,
        device_id: fixture.devices[0].device_id,
        node_id: node.into(),
        boot_id: format!("boot-{node}"),
        session_id: format!("session-{node}"),
        lease_expires_at: Utc::now() + Duration::seconds(10),
    }
}

async fn cleanup(catalog: &RedisCatalog) {
    catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup M7 namespace");
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_owner_claims_are_atomic_and_stale_tokens_cannot_renew_or_release() {
    let (catalog, fixture, _namespace) = catalog().await;
    let first_request = claim_request(&fixture, "m7-incarnation", "node-a");
    let second_request = claim_request(&fixture, "m7-incarnation", "node-b");
    let (first, second) = tokio::join!(
        catalog.claim_owner(&first_request),
        catalog.claim_owner(&second_request)
    );
    let owner = match (first, second) {
        (Ok(owner), Err(tunnel_catalog::CatalogError::OwnerBusy))
        | (Err(tunnel_catalog::CatalogError::OwnerBusy), Ok(owner)) => owner,
        result => panic!("expected one owner and one conflict: {result:?}"),
    };
    let stale = OwnerClaim {
        token: tunnel_catalog::OwnerToken {
            node_id: "stale-node".into(),
            ..owner.token.clone()
        },
        ..owner.clone()
    };
    assert!(
        !catalog
            .renew_owner(&stale.token, Utc::now() + Duration::seconds(10))
            .await
            .expect("stale renew result")
    );
    assert!(
        !catalog
            .release_owner(&stale.token)
            .await
            .expect("stale release result")
    );
    assert!(
        catalog
            .release_owner(&owner.token)
            .await
            .expect("release owner")
    );
    cleanup(&catalog).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_owner_lease_has_ttl_while_device_and_epoch_are_durable() {
    let (catalog, fixture, namespace) = catalog().await;
    let owner = catalog
        .claim_owner(&claim_request(&fixture, "m7-incarnation", "node-a"))
        .await
        .expect("claim owner");
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL").expect("Redis URL");
    let client = redis::Client::open(url).expect("Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let prefix = format!("tunnel-catalog:{namespace}:");
    let owner_key = format!(
        "{prefix}coord:owner:m7-incarnation:{}:{}",
        fixture.devices[0].tenant_id, fixture.devices[0].device_id
    );
    let device_key = format!(
        "{prefix}device:{}:{}",
        fixture.devices[0].tenant_id, fixture.devices[0].device_id
    );
    let epoch_key = format!(
        "{prefix}coord:epoch:{}:{}",
        fixture.devices[0].tenant_id, fixture.devices[0].device_id
    );
    let owner_ttl: i64 = connection.ttl(&owner_key).await.expect("owner TTL");
    let device_ttl: i64 = connection.ttl(&device_key).await.expect("device TTL");
    let epoch_ttl: i64 = connection.ttl(&epoch_key).await.expect("epoch TTL");
    assert!(owner_ttl > 0, "owner lease must be TTL-bound");
    assert_eq!(device_ttl, -1, "durable device must have no TTL");
    assert_eq!(epoch_ttl, -1, "epoch fence must have no TTL");
    assert!(
        catalog
            .release_owner(&owner.token)
            .await
            .expect("release owner")
    );
    cleanup(&catalog).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_recovery_new_incarnation_fences_old_owner_and_preserves_durable_revocation() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M7 Redis tests require TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-cluster-recovery-{}", Uuid::new_v4());
    let old_incarnation = "m7-recovery-old";
    let new_incarnation = "m7-recovery-new";
    let old = RedisCatalog::connect_for_recovery(&url, &namespace, old_incarnation)
        .await
        .expect("connect old recovery catalog");
    old.activate_deployment_incarnation()
        .await
        .expect("activate old incarnation");
    let fixture = fixture();
    old.seed_fixture(&fixture)
        .await
        .expect("seed recovery fixture");

    let owner = old
        .claim_owner(&claim_request(&fixture, old_incarnation, "old-relay"))
        .await
        .expect("claim old owner");
    let principal = old
        .resolve_consumer(
            &fixture.identities[0].issuer,
            &fixture.identities[0].subject,
            Some(fixture.tenants[0].tenant_id),
        )
        .await
        .expect("resolve durable consumer")
        .expect("durable membership remains active");
    let now = Utc::now();
    assert!(
        old.authorize(
            &principal,
            fixture.devices[0].device_id,
            fixture.services[0].service_id,
            now,
            now,
        )
        .await
        .expect("authorize before revocation")
        .is_some()
    );
    let revoked_revision = old
        .revoke_grant(
            fixture.tenants[0].tenant_id,
            fixture.users[0].user_id,
            fixture.devices[0].device_id,
            fixture.services[0].service_id,
            Utc::now(),
        )
        .await
        .expect("revoke durable grant");
    assert!(
        revoked_revision > 1,
        "revocation must advance the grant revision"
    );
    assert!(
        old.authorize(
            &principal,
            fixture.devices[0].device_id,
            fixture.services[0].service_id,
            Utc::now(),
            Utc::now(),
        )
        .await
        .expect("authorize after revocation")
        .is_none()
    );

    let new = RedisCatalog::connect_for_recovery(&url, &namespace, new_incarnation)
        .await
        .expect("connect new recovery catalog");
    assert!(matches!(
        new.activate_deployment_incarnation().await,
        Err(tunnel_catalog::CatalogError::OwnerBusy)
    ));
    assert!(
        old.release_owner(&owner.token)
            .await
            .expect("release old owner before handoff")
    );
    new.activate_deployment_incarnation()
        .await
        .expect("activate approved new incarnation");

    assert!(
        !old.renew_owner(&owner.token, Utc::now() + Duration::seconds(10))
            .await
            .expect("old owner renew result")
    );
    assert!(matches!(
        old.claim_owner(&claim_request(&fixture, old_incarnation, "old-relay-2"))
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "active deployment incarnation"
        ))
    ));
    assert!(matches!(
        RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, old_incarnation).await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "active deployment incarnation or Redis authority run"
        ))
    ));

    let new_principal = new
        .resolve_consumer(
            &fixture.identities[0].issuer,
            &fixture.identities[0].subject,
            Some(fixture.tenants[0].tenant_id),
        )
        .await
        .expect("read durable consumer after recovery")
        .expect("tenant membership survives incarnation change");
    assert_eq!(new_principal, principal);
    assert!(
        new.authorize(
            &new_principal,
            fixture.devices[0].device_id,
            fixture.services[0].service_id,
            Utc::now(),
            Utc::now(),
        )
        .await
        .expect("read durable revoked grant after recovery")
        .is_none()
    );
    let new_owner = new
        .claim_owner(&claim_request(&fixture, new_incarnation, "new-relay"))
        .await
        .expect("new incarnation claims owner");
    assert!(
        new.release_owner(&new_owner.token)
            .await
            .expect("release new owner")
    );

    // External checkpoint approval and backup/rollback verification are relay
    // recovery gates, not Redis catalog operations; this test intentionally
    // covers only the Redis-side owner/run fencing and durable record boundary.
    cleanup(&new).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_normal_startup_rejects_arbitrary_redis_run_identity_change() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M7 Redis tests require TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-cluster-run-identity-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, "m7-run-incarnation")
        .await
        .expect("connect recovery catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate run identity fixture");

    let client = redis::Client::open(url.as_str()).expect("open Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect Redis client");
    redis::cmd("SET")
        .arg(format!("tunnel-catalog:{namespace}:meta:redis_run_id"))
        .arg(format!("arbitrary-run-{}", Uuid::new_v4()))
        .query_async::<()>(&mut connection)
        .await
        .expect("write arbitrary run identity");

    assert!(matches!(
        RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, "m7-run-incarnation")
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "active deployment incarnation or Redis authority run"
        ))
    ));
    cleanup(&catalog).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_attachment_tickets_are_one_use_owner_and_binding_bound() {
    let (catalog, fixture, _namespace) = catalog().await;
    let owner = catalog
        .claim_owner(&claim_request(&fixture, "m7-incarnation", "node-a"))
        .await
        .expect("claim owner");
    let credential = &fixture.credentials[0];
    let request = AttachmentTicketIssueRequest {
        tenant_id: fixture.devices[0].tenant_id,
        device_id: fixture.devices[0].device_id,
        spki_fingerprint: credential.spki_fingerprint.clone(),
        owner: owner.token.clone(),
        generation: 1,
        connection_id: "connection-a".into(),
        purpose: "initial".into(),
        binding_digest: "binding-a".into(),
        expires_at: Utc::now() + Duration::seconds(5),
    };
    let ticket = catalog
        .issue_attachment_ticket(&request)
        .await
        .expect("issue ticket");
    assert!(!ticket.locator.digest.contains(&ticket.ticket));
    let consume = AttachmentTicketConsumeRequest {
        ticket: ticket.ticket.clone(),
        tenant_id: request.tenant_id,
        device_id: request.device_id,
        spki_fingerprint: request.spki_fingerprint.clone(),
        owner: request.owner.clone(),
        generation: request.generation,
        connection_id: request.connection_id.clone(),
        purpose: request.purpose.clone(),
        binding_digest: request.binding_digest.clone(),
    };
    catalog
        .consume_attachment_ticket(&consume)
        .await
        .expect("consume ticket");
    assert!(catalog.consume_attachment_ticket(&consume).await.is_err());
    cleanup(&catalog).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_ticket_is_fenced_when_the_bound_credential_is_revoked() {
    let (catalog, fixture, _namespace) = catalog().await;
    let owner = catalog
        .claim_owner(&claim_request(&fixture, "m7-incarnation", "node-a"))
        .await
        .expect("claim owner");
    let credential = &fixture.credentials[0];
    let issue = AttachmentTicketIssueRequest {
        tenant_id: fixture.devices[0].tenant_id,
        device_id: fixture.devices[0].device_id,
        spki_fingerprint: credential.spki_fingerprint.clone(),
        owner: owner.token.clone(),
        generation: 2,
        connection_id: "connection-revocation".into(),
        purpose: "rotation_candidate".into(),
        binding_digest: "binding-revocation".into(),
        expires_at: Utc::now() + Duration::seconds(5),
    };
    let ticket = catalog
        .issue_attachment_ticket(&issue)
        .await
        .expect("issue ticket");
    catalog
        .revoke_credential(
            issue.tenant_id,
            issue.device_id,
            credential.credential_id,
            Utc::now(),
        )
        .await
        .expect("revoke credential");
    let consume = AttachmentTicketConsumeRequest {
        ticket: ticket.ticket,
        tenant_id: issue.tenant_id,
        device_id: issue.device_id,
        spki_fingerprint: issue.spki_fingerprint.clone(),
        owner: issue.owner.clone(),
        generation: issue.generation,
        connection_id: issue.connection_id.clone(),
        purpose: issue.purpose.clone(),
        binding_digest: issue.binding_digest.clone(),
    };
    assert!(catalog.consume_attachment_ticket(&consume).await.is_err());
    cleanup(&catalog).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_concurrent_ticket_consumers_have_one_winner_and_expired_owner_rejects() {
    let (catalog, fixture, _namespace) = catalog().await;
    let mut owner_request = claim_request(&fixture, "m7-incarnation", "node-a");
    owner_request.lease_expires_at = Utc::now() + Duration::milliseconds(250);
    let owner = catalog
        .claim_owner(&owner_request)
        .await
        .expect("claim short owner lease");
    let credential = &fixture.credentials[0];
    let issue = AttachmentTicketIssueRequest {
        tenant_id: fixture.devices[0].tenant_id,
        device_id: fixture.devices[0].device_id,
        spki_fingerprint: credential.spki_fingerprint.clone(),
        owner: owner.token.clone(),
        generation: 3,
        connection_id: "connection-race".into(),
        purpose: "recovery".into(),
        binding_digest: "binding-race".into(),
        expires_at: Utc::now() + Duration::seconds(5),
    };
    let ticket = catalog
        .issue_attachment_ticket(&issue)
        .await
        .expect("issue ticket");
    let consume = AttachmentTicketConsumeRequest {
        ticket: ticket.ticket,
        tenant_id: issue.tenant_id,
        device_id: issue.device_id,
        spki_fingerprint: issue.spki_fingerprint.clone(),
        owner: issue.owner.clone(),
        generation: issue.generation,
        connection_id: issue.connection_id.clone(),
        purpose: issue.purpose.clone(),
        binding_digest: issue.binding_digest.clone(),
    };
    let (first, second) = tokio::join!(
        catalog.consume_attachment_ticket(&consume),
        catalog.consume_attachment_ticket(&consume),
    );
    assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);

    // The spent marker is independent from the lease.  A fresh ticket issued
    // before the lease deadline must still fail after Redis expires the owner.
    let mut long_ticket_owner = claim_request(&fixture, "m7-incarnation", "node-a");
    long_ticket_owner.lease_expires_at = Utc::now() + Duration::milliseconds(200);
    let owner = catalog
        .claim_owner(&long_ticket_owner)
        .await
        .expect("reclaim after short lease");
    let issue = AttachmentTicketIssueRequest {
        owner: owner.token.clone(),
        generation: 4,
        connection_id: "connection-expired".into(),
        binding_digest: "binding-expired".into(),
        expires_at: Utc::now() + Duration::seconds(5),
        ..issue
    };
    let ticket = catalog
        .issue_attachment_ticket(&issue)
        .await
        .expect("issue expiry ticket");
    tokio::time::sleep(std::time::Duration::from_millis(450)).await;
    let consume = AttachmentTicketConsumeRequest {
        ticket: ticket.ticket,
        tenant_id: issue.tenant_id,
        device_id: issue.device_id,
        spki_fingerprint: issue.spki_fingerprint,
        owner: issue.owner,
        generation: issue.generation,
        connection_id: issue.connection_id,
        purpose: issue.purpose,
        binding_digest: issue.binding_digest,
    };
    assert!(catalog.consume_attachment_ticket(&consume).await.is_err());
    cleanup(&catalog).await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_membership_publisher_is_separate_and_reads_opaque_bytes() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M7 Redis tests require TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-cluster-membership-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect(&url, &namespace)
        .await
        .expect("connect catalog");
    let publisher = RedisMembershipPublisher::connect(&url, &namespace)
        .await
        .expect("connect publisher");
    let bytes = vec![0, 1, 2, 0xff, 4];
    publisher
        .publish_signed_membership(&SignedMembershipRecord {
            version: 1,
            bytes: bytes.clone(),
        })
        .await
        .expect("publish membership");
    assert_eq!(
        catalog
            .read_signed_membership()
            .await
            .unwrap()
            .unwrap()
            .bytes,
        bytes
    );
    assert!(
        publisher
            .publish_signed_membership(&SignedMembershipRecord {
                version: 1,
                bytes: vec![9],
            })
            .await
            .is_err()
    );
    catalog.cleanup_fixture_namespace().await.ok();
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_membership_directory_reads_all_nodes_with_per_node_versions() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M7 Redis tests require TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-cluster-membership-directory-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect(&url, &namespace)
        .await
        .expect("connect catalog");
    let publisher = RedisMembershipPublisher::connect(&url, &namespace)
        .await
        .expect("connect publisher");
    for (node_id, version) in [("relay-a", 4_u64), ("relay-b", 2_u64), ("relay-c", 9_u64)] {
        publisher
            .publish_signed_membership(&SignedMembershipRecord {
                version,
                bytes: format!(r#"{{"node_id":"{node_id}"}}"#).into_bytes(),
            })
            .await
            .expect("publish directory record");
    }
    let records = catalog
        .read_signed_memberships()
        .await
        .expect("read directory");
    assert_eq!(records.len(), 3);
    let versions = records
        .into_iter()
        .map(|record| {
            let value: serde_json::Value = serde_json::from_slice(&record.bytes).unwrap();
            (
                value["node_id"].as_str().unwrap().to_owned(),
                record.version,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        versions,
        std::collections::BTreeMap::from([
            ("relay-a".to_owned(), 4),
            ("relay-b".to_owned(), 2),
            ("relay-c".to_owned(), 9),
        ])
    );
    assert!(matches!(
        publisher
            .publish_signed_membership(&SignedMembershipRecord {
                version: 3,
                bytes: br#"{"node_id":"relay-a"}"#.to_vec(),
            })
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "signed membership version"
        ))
    ));
    assert!(matches!(
        publisher
            .publish_signed_membership(&SignedMembershipRecord {
                version: 4,
                bytes: br#"{"node_id":"relay-a","changed":true}"#.to_vec(),
            })
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "signed membership contents"
        ))
    ));
    assert!(matches!(
        publisher
            .publish_signed_membership_for_node(
                "relay-other",
                &SignedMembershipRecord {
                    version: 1,
                    bytes: br#"{"node_id":"relay-a"}"#.to_vec(),
                },
            )
            .await,
        Err(tunnel_catalog::CatalogError::InvalidInput(
            "signed membership node id"
        ))
    ));
    for index in 3..32 {
        publisher
            .publish_signed_membership(&SignedMembershipRecord {
                version: 1,
                bytes: format!(r#"{{"node_id":"relay-{index}"}}"#).into_bytes(),
            })
            .await
            .expect("publish bounded directory record");
    }
    assert!(matches!(
        publisher
            .publish_signed_membership(&SignedMembershipRecord {
                version: 1,
                bytes: br#"{"node_id":"relay-overflow"}"#.to_vec(),
            })
            .await,
        Err(tunnel_catalog::CatalogError::Conflict(
            "signed membership directory bound"
        ))
    ));
    catalog.cleanup_fixture_namespace().await.ok();
}
