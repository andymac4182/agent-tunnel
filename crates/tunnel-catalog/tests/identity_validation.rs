//! Pure EC-002 identity-boundary and control-corpus coverage.

use tunnel_catalog::{
    Catalog, CatalogError, CatalogFixture, MembershipRecord, MembershipRole, MemoryCatalog,
    PrincipalIdentity, TenantRecord, UserRecord,
};
use uuid::Uuid;

struct Case {
    issuer: String,
    subject: String,
    user_id: Uuid,
}

fn exact_unicode_bytes(target: usize) -> String {
    let mut value = String::new();
    while value.len() + "界".len() <= target {
        value.push('界');
    }
    if target - value.len() == 2 {
        value.push('é');
    } else {
        for _ in 0..(target - value.len()) {
            value.push('a');
        }
    }
    assert_eq!(value.len(), target);
    value
}

fn valid_cases() -> Vec<Case> {
    let mut cases = vec![
        Case {
            issuer: exact_unicode_bytes(2048),
            subject: "issuer-boundary".into(),
            user_id: Uuid::from_u128(0x3000),
        },
        Case {
            issuer: "subject-boundary".into(),
            subject: exact_unicode_bytes(1024),
            user_id: Uuid::from_u128(0x3001),
        },
    ];
    for index in 0_u128..6 {
        let marker = match index % 3 {
            0 => "é",
            1 => "界",
            _ => "e\u{301}",
        };
        cases.push(Case {
            issuer: format!("generated-{index}:{marker}/issuer_{index}"),
            subject: format!("subject:{index}/{marker}:value_{index}"),
            user_id: Uuid::from_u128(0x3100 + index),
        });
    }
    cases
}

fn fixture_for(cases: &[Case]) -> CatalogFixture {
    let tenant_id = Uuid::from_u128(0x3200);
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id,
            display_name: "EC-002 pure tenant".into(),
            active: true,
        }],
        users: cases
            .iter()
            .map(|case| UserRecord {
                user_id: case.user_id,
                display_name: format!("EC-002 pure user {}", case.user_id),
            })
            .collect(),
        identities: cases
            .iter()
            .map(|case| PrincipalIdentity {
                issuer: case.issuer.clone(),
                subject: case.subject.clone(),
                user_id: case.user_id,
            })
            .collect(),
        memberships: cases
            .iter()
            .map(|case| MembershipRecord {
                tenant_id,
                user_id: case.user_id,
                role: MembershipRole::Member,
                active: true,
            })
            .collect(),
        ..CatalogFixture::default()
    }
}

fn invalid_fixture(issuer: String, subject: String) -> CatalogFixture {
    let tenant_id = Uuid::from_u128(0x3300);
    let user_id = Uuid::from_u128(0x3301);
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id,
            display_name: "EC-002 invalid pure tenant".into(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id,
            display_name: "EC-002 invalid pure user".into(),
        }],
        identities: vec![PrincipalIdentity {
            issuer,
            subject,
            user_id,
        }],
        memberships: vec![MembershipRecord {
            tenant_id,
            user_id,
            role: MembershipRole::Member,
            active: true,
        }],
        ..CatalogFixture::default()
    }
}

#[tokio::test]
async fn identity_validation_has_byte_bounds_and_exact_opaque_resolution() {
    let catalog = MemoryCatalog::new();
    let cases = valid_cases();
    let fixture = fixture_for(&cases);
    catalog
        .seed_fixture(&fixture)
        .await
        .expect("seed valid identity boundaries");
    let tenant_id = fixture.tenants[0].tenant_id;
    for case in &cases {
        let resolved = catalog
            .resolve_consumer(&case.issuer, &case.subject, Some(tenant_id))
            .await
            .expect("resolve exact identity")
            .expect("valid identity is present");
        assert_eq!(resolved.tenant_id, tenant_id);
        assert_eq!(resolved.principal_id, case.user_id);
    }

    let mut invalid = vec![
        (exact_unicode_bytes(2049), "subject".to_owned()),
        ("issuer".to_owned(), exact_unicode_bytes(1025)),
        (String::new(), "subject".to_owned()),
        ("issuer".to_owned(), String::new()),
        (" \t".to_owned(), "subject".to_owned()),
        ("issuer".to_owned(), "\u{2003}".to_owned()),
    ];
    for codepoint in 0_u32..=0x1f_u32 {
        add_control(&mut invalid, codepoint);
    }
    for codepoint in 0x7f_u32..=0x9f_u32 {
        add_control(&mut invalid, codepoint);
    }
    for (issuer, subject) in invalid {
        let error = catalog
            .seed_fixture(&invalid_fixture(issuer.clone(), subject.clone()))
            .await
            .expect_err("invalid identity accepted");
        assert!(matches!(
            error,
            CatalogError::InvalidInput("identity user, issuer, or subject")
        ));
        assert!(
            catalog
                .resolve_consumer(&issuer, &subject, Some(tenant_id))
                .await
                .expect("resolve rejected identity")
                .is_none()
        );
    }
}

fn add_control(cases: &mut Vec<(String, String)>, codepoint: u32) {
    let control = char::from_u32(codepoint).expect("control codepoint is scalar");
    cases.push((format!("issuer-{control}"), "subject".to_owned()));
    cases.push(("issuer".to_owned(), format!("subject-{control}")));
}
