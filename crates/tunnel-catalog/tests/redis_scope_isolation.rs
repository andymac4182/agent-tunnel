//! EC-002 Redis scope and opaque-identity integration coverage.
//!
//! These checks use one disposable fixture namespace and are ignored in the
//! ordinary workspace suite because Redis is an external authority.  The
//! fixture intentionally exercises byte-sensitive principal identity inputs:
//! the catalog has no Unicode normalization contract, so canonically similar
//! strings must remain separate identities rather than silently aliasing.

use std::{collections::BTreeSet, time::Duration};

use tunnel_catalog::{
    Catalog, CatalogError, CatalogFixture, MembershipRecord, MembershipRole, MemoryCatalog,
    PrincipalIdentity, RedisCatalog, TenantRecord, UserRecord,
};
use uuid::Uuid;

const MAX_IDENTITY_KEYS: usize = 32;
const MAX_SCAN_ROUNDS: usize = 64;
const RAW_REDIS_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_IDENTITY_KEY_BYTES: usize = 16 * 1024;

struct IdentityCase {
    issuer: String,
    subject: String,
    user_id: Uuid,
}

fn identity_corpus() -> Vec<IdentityCase> {
    let mut cases = vec![
        // A delimiter-only key builder would make these two pairs identical.
        IdentityCase {
            issuer: "issuer:a".into(),
            subject: "subject".into(),
            user_id: Uuid::from_u128(0x1000),
        },
        IdentityCase {
            issuer: "issuer".into(),
            subject: "a:subject".into(),
            user_id: Uuid::from_u128(0x1001),
        },
        // A key escape that does not encode '_' would make these identical.
        IdentityCase {
            issuer: "escaped_3a".into(),
            subject: "same-subject".into(),
            user_id: Uuid::from_u128(0x1002),
        },
        IdentityCase {
            issuer: "escaped:".into(),
            subject: "same-subject".into(),
            user_id: Uuid::from_u128(0x1003),
        },
        // NFC and NFD are distinct opaque inputs.  No normalization is
        // supported by the catalog, so they must not alias one another.
        IdentityCase {
            issuer: "issuer-é".into(),
            subject: "normalized".into(),
            user_id: Uuid::from_u128(0x1004),
        },
        IdentityCase {
            issuer: "issuer-e\u{301}".into(),
            subject: "normalized".into(),
            user_id: Uuid::from_u128(0x1005),
        },
        // Case is also opaque: exact comparison must not select the sibling.
        IdentityCase {
            issuer: "case".into(),
            subject: "Exact".into(),
            user_id: Uuid::from_u128(0x1006),
        },
        IdentityCase {
            issuer: "CASE".into(),
            subject: "Exact".into(),
            user_id: Uuid::from_u128(0x1007),
        },
    ];
    cases.extend([
        IdentityCase {
            issuer: exact_mixed_bytes(2048),
            subject: "issuer-boundary".into(),
            user_id: Uuid::from_u128(0x1008),
        },
        IdentityCase {
            issuer: "subject-boundary".into(),
            subject: exact_mixed_bytes(1024),
            user_id: Uuid::from_u128(0x1009),
        },
    ]);
    for index in 0_u128..8 {
        let marker = match index % 4 {
            0 => "é",
            1 => "界",
            2 => "e\u{301}",
            _ => "ß",
        };
        cases.push(IdentityCase {
            issuer: format!("generated-{index}:{marker}/opaque_{index}"),
            subject: format!("subject:{index}/{marker}:segment_{index}"),
            user_id: Uuid::from_u128(0x2000 + index),
        });
    }
    cases
}

fn exact_mixed_bytes(target: usize) -> String {
    let mut value = String::new();
    while value.len() + "界".len() <= target {
        value.push('界');
    }
    match target - value.len() {
        0 => {}
        1 => value.push('a'),
        2 => value.push('é'),
        remainder => panic!("unexpected UTF-8 remainder {remainder}"),
    }
    assert_eq!(value.len(), target);
    value
}

fn invalid_identity_cases() -> Vec<(String, String)> {
    let mut cases = vec![
        (String::new(), "subject".to_owned()),
        ("issuer".to_owned(), String::new()),
        (" \t".to_owned(), "subject".to_owned()),
        ("issuer".to_owned(), "\u{2003}".to_owned()),
        (exact_mixed_bytes(2049), "subject".to_owned()),
        ("issuer".to_owned(), exact_mixed_bytes(1025)),
    ];
    for codepoint in 0_u32..=0x1f_u32 {
        add_control_cases(&mut cases, codepoint);
    }
    for codepoint in 0x7f_u32..=0x9f_u32 {
        add_control_cases(&mut cases, codepoint);
    }
    cases
}

fn add_control_cases(cases: &mut Vec<(String, String)>, codepoint: u32) {
    let control = char::from_u32(codepoint).expect("control codepoint is scalar");
    cases.push((format!("issuer-{control}"), "subject".to_owned()));
    cases.push(("issuer".to_owned(), format!("subject-{control}")));
}

fn fixture_for(cases: &[IdentityCase]) -> CatalogFixture {
    let tenant_id = Uuid::from_u128(0xec00_2000);
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id,
            display_name: "EC-002 tenant".into(),
            active: true,
        }],
        users: cases
            .iter()
            .map(|case| UserRecord {
                user_id: case.user_id,
                display_name: format!("EC-002 user {}", case.user_id),
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

fn invalid_identity_fixture(issuer: &str, subject: &str) -> CatalogFixture {
    let tenant_id = Uuid::from_u128(0xec00_2001);
    let user_id = Uuid::from_u128(0xec00_2002);
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id,
            display_name: "EC-002 invalid tenant".into(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id,
            display_name: "EC-002 invalid user".into(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
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

async fn assert_exact_resolution<C: Catalog>(
    catalog: &C,
    cases: &[IdentityCase],
    tenant_id: Uuid,
    backend: &str,
) -> Result<(), String> {
    for case in cases {
        let resolved = catalog
            .resolve_consumer(&case.issuer, &case.subject, Some(tenant_id))
            .await
            .map_err(|error| format!("{backend} exact lookup: {error:?}"))?
            .ok_or_else(|| format!("{backend} exact opaque identity is missing"))?;
        if resolved.tenant_id != tenant_id || resolved.principal_id != case.user_id {
            return Err(format!(
                "{backend} exact opaque identity resolved to the wrong scope"
            ));
        }
    }
    Ok(())
}

async fn assert_identity_rejected<C: Catalog>(
    catalog: &C,
    issuer: &str,
    subject: &str,
    expected_message: &'static str,
    backend: &str,
) -> Result<(), String> {
    match catalog
        .seed_fixture(&invalid_identity_fixture(issuer, subject))
        .await
    {
        Err(CatalogError::InvalidInput(message)) if message == expected_message => {}
        Err(error) => {
            return Err(format!(
                "{backend} unexpected identity rejection: {error:?}"
            ));
        }
        Ok(()) => return Err(format!("{backend} accepted invalid identity")),
    }
    if catalog
        .resolve_consumer(issuer, subject, None)
        .await
        .map_err(|error| format!("{backend} invalid lookup: {error:?}"))?
        .is_some()
    {
        return Err(format!("{backend} resolved invalid identity"));
    }
    Ok(())
}

async fn scan_identity_keys(url: &str, namespace: &str) -> Result<Vec<String>, String> {
    let client =
        redis::Client::open(url).map_err(|error| format!("open raw Redis client: {error}"))?;
    let mut connection =
        tokio::time::timeout(RAW_REDIS_TIMEOUT, client.get_multiplexed_async_connection())
            .await
            .map_err(|_| "connect raw Redis client timed out".to_owned())?
            .map_err(|error| format!("connect raw Redis client: {error}"))?;
    let pattern = format!("tunnel-catalog:{namespace}:identity:*");
    let mut cursor = 0_u64;
    let mut keys = BTreeSet::new();
    let mut rounds = 0;
    loop {
        rounds += 1;
        if rounds > MAX_SCAN_ROUNDS {
            return Err("identity-key scan exceeded its cursor bound".into());
        }
        let (next, batch): (u64, Vec<String>) = tokio::time::timeout(
            RAW_REDIS_TIMEOUT,
            redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(64_i64)
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| "scan identity keys timed out".to_owned())?
        .map_err(|error| format!("scan identity keys: {error}"))?;
        if batch.len() > MAX_IDENTITY_KEYS {
            return Err("identity-key scan returned an oversized batch".into());
        }
        for key in batch {
            if key.len() > MAX_IDENTITY_KEY_BYTES {
                return Err("identity-key scan returned an oversized key".into());
            }
            keys.insert(key);
            if keys.len() > MAX_IDENTITY_KEYS {
                return Err("identity-key scan exceeded the bounded corpus".into());
            }
        }
        if next == 0 {
            break;
        }
        cursor = next;
    }
    Ok(keys.into_iter().collect())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn assert_canonical_component(component: &str) -> Result<(), String> {
    if component.is_empty() {
        return Err("empty Redis identity key component".into());
    }
    let bytes = component.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'_' {
            if !(index + 2 < bytes.len()
                && is_lower_hex(bytes[index + 1])
                && is_lower_hex(bytes[index + 2]))
            {
                return Err("non-canonical Redis identity escape".into());
            }
            index += 3;
        } else {
            if !(bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'.' | b'-')) {
                return Err("raw Redis identity key fragment was accepted".into());
            }
            index += 1;
        }
    }
    Ok(())
}

fn assert_identity_key_shape(key: &str, namespace: &str) -> Result<(), String> {
    let prefix = format!("tunnel-catalog:{namespace}:identity:");
    let tail = key
        .strip_prefix(&prefix)
        .ok_or_else(|| "identity key escaped the fixture namespace".to_owned())?;
    let components: Vec<_> = tail.split(':').collect();
    if components.len() != 2 {
        return Err("identity key contains an unescaped namespace delimiter".into());
    }
    for component in components {
        assert_canonical_component(component)?;
    }
    Ok(())
}

async fn raw_set(url: &str, key: &str, value: &str) -> Result<(), String> {
    if key.len() > 256 || value.len() > 64 {
        return Err("raw Redis fixture command exceeded its bound".into());
    }
    let client =
        redis::Client::open(url).map_err(|error| format!("open raw Redis client: {error}"))?;
    let mut connection =
        tokio::time::timeout(RAW_REDIS_TIMEOUT, client.get_multiplexed_async_connection())
            .await
            .map_err(|_| "connect raw Redis client timed out".to_owned())?
            .map_err(|error| format!("connect raw Redis client: {error}"))?;
    tokio::time::timeout(
        RAW_REDIS_TIMEOUT,
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .query_async::<()>(&mut connection),
    )
    .await
    .map_err(|_| "write raw Redis fixture key timed out".to_owned())?
    .map_err(|error| format!("write raw Redis fixture key: {error}"))
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn ec002_rejects_control_inputs_and_isolates_opaque_identity_keys() {
    let url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("EC-002 requires TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-ec002-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(&url, &namespace, "ec002-incarnation")
        .await
        .expect("connect EC-002 Redis catalog");
    if let Err(error) = catalog.activate_deployment_incarnation().await {
        let cleanup = catalog.cleanup_fixture_namespace().await;
        panic!("activate EC-002 fixture incarnation: {error}; cleanup: {cleanup:?}");
    }

    let scenario_catalog = catalog.clone();
    let scenario_url = url.clone();
    let scenario_namespace = namespace.clone();
    let scenario = tokio::spawn(async move {
        ec002_body(scenario_catalog, scenario_url, scenario_namespace).await
    })
    .await;

    let cleanup = catalog.cleanup_fixture_namespace().await;
    if let Err(error) = cleanup {
        panic!("cleanup EC-002 fixture namespace: {error}");
    }
    match scenario {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("EC-002 scenario failed: {error}"),
        Err(error) => panic!("EC-002 scenario task failed: {error}"),
    }
}

async fn ec002_body(catalog: RedisCatalog, url: String, namespace: String) -> Result<(), String> {
    // The namespace is an opaque Redis-key scope; controls cannot enter it.
    match RedisCatalog::connect(&url, "test-ec002-invalid\n").await {
        Err(CatalogError::InvalidInput("Redis namespace")) => {}
        Err(error) => return Err(format!("unexpected namespace validation error: {error:?}")),
        Ok(_) => return Err("control namespace was accepted".into()),
    }

    let cases = identity_corpus();
    let fixture = fixture_for(&cases);
    let memory = MemoryCatalog::new();
    memory
        .seed_fixture(&fixture)
        .await
        .map_err(|error| format!("seed valid memory identity corpus: {error:?}"))?;
    let tenant_id = fixture.tenants[0].tenant_id;
    assert_exact_resolution(&memory, &cases, tenant_id, "memory").await?;

    // A principal identity is required to reject empty, oversized, and every
    // C0/C1 control-bearing issuer/subject value. These calls validate before
    // namespace reserve, so no invalid fixture can occupy the Redis scope.
    for (issuer, subject) in invalid_identity_cases() {
        assert_identity_rejected(
            &memory,
            &issuer,
            &subject,
            "identity user, issuer, or subject",
            "memory",
        )
        .await?;
        assert_identity_rejected(&catalog, &issuer, &subject, "identity fixture", "Redis").await?;
    }

    catalog
        .seed_fixture(&fixture)
        .await
        .map_err(|error| format!("seed valid EC-002 identity corpus: {error:?}"))?;
    assert_exact_resolution(&catalog, &cases, tenant_id, "Redis").await?;

    // A caller-supplied escaped fragment cannot address the colon-bearing
    // identity, and a different tenant UUID cannot broaden its scope.
    for (label, issuer, subject, requested_tenant) in [
        ("raw key fragment", "issuer_3aa", "subject", tenant_id),
        ("whitespace alias", " issuer:a", "subject", tenant_id),
        (
            "cross-tenant lookup",
            "issuer:a",
            "subject",
            Uuid::from_u128(0xec00_2003),
        ),
        ("mismatched Unicode pair", "issuer-é", "Exact", tenant_id),
    ] {
        if catalog
            .resolve_consumer(issuer, subject, Some(requested_tenant))
            .await
            .map_err(|error| format!("{label} lookup: {error:?}"))?
            .is_some()
        {
            return Err(format!("{label} unexpectedly resolved"));
        }
    }

    let keys = scan_identity_keys(&url, &namespace).await?;
    if keys.len() != cases.len() {
        return Err(format!(
            "expected {} identity keys, found {}",
            cases.len(),
            keys.len()
        ));
    }
    for key in &keys {
        assert_identity_key_shape(key, &namespace)?;
    }

    // The recovery scanner also rejects a raw namespace delimiter instead of
    // treating it as a caller-controlled issuer/subject alias.
    let malformed_key = format!("tunnel-catalog:{namespace}:identity:issuer:a:subject");
    raw_set(&url, &malformed_key, "raw-alias").await?;
    match catalog.observe_durable_catalog().await {
        Err(CatalogError::Serialization(message)) if message == "malformed Redis key" => {}
        Err(error) => return Err(format!("unexpected raw-key rejection: {error:?}")),
        Ok(_) => return Err("raw identity key fragment was accepted".into()),
    }
    Ok(())
}
