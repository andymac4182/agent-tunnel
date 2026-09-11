//! EC-014's narrow same-authority concurrency gate.
//!
//! The test deliberately uses only the public `Catalog` API through one
//! `RedisCatalog` and one isolated fixture namespace.  It proves atomic
//! ownership, exact-token lease fencing, authorization reads, and one-use
//! attachment consumption on the same Redis authority profile.  It does not
//! inject a lost Redis reply and therefore makes no ambiguous-write claim.

use chrono::{Duration, Utc};
use std::collections::BTreeSet;
use std::time::Duration as StdDuration;
use tunnel_catalog::{
    AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest, AuthenticatedConsumer, Catalog,
    CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord, MembershipRole,
    OwnerClaimRequest, OwnerToken, PermissionSet, PrincipalIdentity, RedisCatalog, ServiceSpec,
    TenantRecord, UserRecord,
};
use uuid::Uuid;

const INCARNATION: &str = "m7-ec014-authority";

fn fixture() -> CatalogFixture {
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let service_id = Uuid::new_v4();
    let now = Utc::now();
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id,
            display_name: "EC-014 tenant".into(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id,
            display_name: "EC-014 user".into(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: "https://issuer.ec014.fixture.invalid".into(),
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
            display_name: "EC-014 device".into(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id,
            device_id,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: format!("{:064x}", user_id.as_u128()),
            serial: Some(format!("serial-{device_id}")),
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
            display_name: "EC-014 echo".into(),
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
            constraints: serde_json::json!({"max_bytes":4096}),
            expires_at: Some(now + Duration::hours(1)),
            active: true,
        }],
    }
}

fn owner_request(fixture: &CatalogFixture, node_id: &str) -> OwnerClaimRequest {
    OwnerClaimRequest {
        deployment_incarnation: INCARNATION.into(),
        tenant_id: fixture.devices[0].tenant_id,
        device_id: fixture.devices[0].device_id,
        node_id: node_id.into(),
        boot_id: format!("boot-{node_id}"),
        session_id: format!("session-{node_id}"),
        lease_expires_at: Utc::now() + Duration::seconds(10),
    }
}

fn consume_request(
    ticket: String,
    issue: &AttachmentTicketIssueRequest,
) -> AttachmentTicketConsumeRequest {
    AttachmentTicketConsumeRequest {
        ticket,
        tenant_id: issue.tenant_id,
        device_id: issue.device_id,
        spki_fingerprint: issue.spki_fingerprint.clone(),
        owner: issue.owner.clone(),
        generation: issue.generation,
        connection_id: issue.connection_id.clone(),
        purpose: issue.purpose.clone(),
        binding_digest: issue.binding_digest.clone(),
    }
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_ec014_same_authority_concurrent_catalog_lease_and_ticket_operations() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("EC-014 Redis test requires TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-ec014-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, INCARNATION)
        .await
        .expect("connect Redis catalog");

    // Keep the scenario in a task so assertion panics are observed as a
    // primary failure and the outer test can still clean the namespace.
    let scenario_catalog = catalog.clone();
    let mut scenario = tokio::spawn(async move {
        let catalog = scenario_catalog;
        catalog
            .activate_deployment_incarnation()
            .await
            .expect("activate EC-014 incarnation");
        let fixture = fixture();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed EC-014 fixture");

        let principal = AuthenticatedConsumer {
            tenant_id: fixture.tenants[0].tenant_id,
            principal_id: fixture.users[0].user_id,
        };
        let device_id = fixture.devices[0].device_id;
        let service_id = fixture.services[0].service_id;
        let credential = &fixture.credentials[0];

        // Authorization and competing owner claims all use this one catalog and
        // namespace.  Exactly one complete owner token may win the CAS.
        let first_request = owner_request(&fixture, "node-a");
        let second_request = owner_request(&fixture, "node-b");
        let initial_authorization_at = Utc::now();
        let (authorization, first, second) = tokio::join!(
            catalog.authorize(
                &principal,
                device_id,
                service_id,
                initial_authorization_at,
                initial_authorization_at,
            ),
            catalog.claim_owner(&first_request),
            catalog.claim_owner(&second_request),
        );
        let snapshot = authorization
            .expect("authorize on the same authority")
            .expect("fixture grant visible");
        assert!(snapshot.permissions.allows("echo:invoke"));
        let owner = match (first, second) {
            (Ok(owner), Err(tunnel_catalog::CatalogError::OwnerBusy))
            | (Err(tunnel_catalog::CatalogError::OwnerBusy), Ok(owner)) => owner,
            result => panic!("expected one owner winner and one conflict: {result:?}"),
        };

        // A token with one changed identity field cannot renew or release the
        // winner's lease, and the exact winner remains observable afterwards.
        let stale = OwnerToken {
            node_id: "stale-node".into(),
            ..owner.token.clone()
        };
        let (stale_renew, stale_release) = tokio::join!(
            catalog.renew_owner(&stale, Utc::now() + Duration::seconds(10)),
            catalog.release_owner(&stale),
        );
        assert!(!stale_renew.expect("stale renew result"));
        assert!(!stale_release.expect("stale release result"));
        assert_eq!(
            catalog
                .current_owner(principal.tenant_id, device_id, Utc::now())
                .await
                .expect("read exact current owner")
                .expect("winner still owns the device")
                .token,
            owner.token
        );

        let issue = AttachmentTicketIssueRequest {
            tenant_id: principal.tenant_id,
            device_id,
            spki_fingerprint: credential.spki_fingerprint.clone(),
            owner: owner.token.clone(),
            generation: 1,
            connection_id: "connection-authority".into(),
            purpose: "initial".into(),
            binding_digest: "binding-authority".into(),
            expires_at: Utc::now() + Duration::seconds(5),
        };
        let ticket = catalog
            .issue_attachment_ticket(&issue)
            .await
            .expect("issue attachment ticket from same authority");
        let consume = consume_request(ticket.ticket, &issue);

        // These operations share the one authoritative profile.  The ticket
        // consumers race deliberately; the atomic spend transition allows one
        // success and rejects the duplicate, while auth and lease reads continue.
        let owner_token = owner.token.clone();
        let auth_a_at = Utc::now();
        let auth_b_at = Utc::now();
        let (auth_a, auth_b, renewed, observed_owner, consumed_a, consumed_b) = tokio::join!(
            catalog.authorize(&principal, device_id, service_id, auth_a_at, auth_a_at),
            catalog.authorize(&principal, device_id, service_id, auth_b_at, auth_b_at),
            catalog.renew_owner(&owner_token, Utc::now() + Duration::seconds(10)),
            catalog.current_owner(principal.tenant_id, device_id, Utc::now()),
            catalog.consume_attachment_ticket(&consume),
            catalog.consume_attachment_ticket(&consume),
        );
        assert!(auth_a.expect("first concurrent authorization").is_some());
        assert!(auth_b.expect("second concurrent authorization").is_some());
        assert!(renewed.expect("renew exact owner token"));
        assert_eq!(
            observed_owner
                .expect("read owner while concurrent operations run")
                .expect("owner remains live")
                .token,
            owner_token
        );
        match (consumed_a, consumed_b) {
            (Ok(_), Err(tunnel_catalog::CatalogError::Unauthorized))
            | (Err(tunnel_catalog::CatalogError::Unauthorized), Ok(_)) => {}
            result => panic!(
                "expected one successful ticket consume and one unauthorized duplicate: {result:?}"
            ),
        }

        // A ticket issued before credential revocation remains present but cannot
        // cross the credential fence.  This is a revocation boundary, not a
        // network lost-reply or replay test.
        let revocation_issue = AttachmentTicketIssueRequest {
            generation: 2,
            connection_id: "connection-revocation".into(),
            purpose: "revocation-boundary".into(),
            binding_digest: "binding-revocation".into(),
            ..issue.clone()
        };
        let revocation_ticket = catalog
            .issue_attachment_ticket(&revocation_issue)
            .await
            .expect("issue revocation-bound ticket");
        let revocation_consume = consume_request(revocation_ticket.ticket, &revocation_issue);
        catalog
            .revoke_credential(
                principal.tenant_id,
                device_id,
                credential.credential_id,
                Utc::now(),
            )
            .await
            .expect("revoke bound credential");
        assert!(matches!(
            catalog.consume_attachment_ticket(&revocation_consume).await,
            Err(tunnel_catalog::CatalogError::Unauthorized)
        ));

        // Device revocation fences the live owner too; the old exact token cannot
        // renew after this authoritative mutation.
        catalog
            .revoke_device(principal.tenant_id, device_id, Utc::now())
            .await
            .expect("revoke device and owner");
        assert!(
            !catalog
                .renew_owner(&owner_token, Utc::now() + Duration::seconds(10))
                .await
                .expect("renew revoked owner")
        );
        assert!(
            catalog
                .current_owner(principal.tenant_id, device_id, Utc::now())
                .await
                .expect("read owner after revocation")
                .is_none()
        );
    });

    let primary = match tokio::time::timeout(StdDuration::from_secs(30), &mut scenario).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(join_error)) if join_error.is_panic() => {
            Err(format!("scenario panicked: {join_error}"))
        }
        Ok(Err(join_error)) => Err(format!("scenario did not complete: {join_error}")),
        Err(_) => {
            scenario.abort();
            let _ = scenario.await;
            Err("scenario deadline exceeded after 30 seconds".into())
        }
    };
    let cleanup = match tokio::time::timeout(
        StdDuration::from_secs(5),
        catalog.cleanup_fixture_namespace(),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("cleanup failed: {error}")),
        Err(_) => Err("cleanup deadline exceeded after 5 seconds".into()),
    };
    match (primary, cleanup) {
        (Ok(()), Ok(())) => {}
        (primary, cleanup) => {
            panic!("EC-014 authority scenario failed: primary={primary:?}; cleanup={cleanup:?}")
        }
    }
}
