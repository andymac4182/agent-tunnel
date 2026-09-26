//! Task row M3-11: a standard MCP client that has no token yet can discover
//! how to authenticate to an `http-forward` route.
//!
//! Every request crosses the real consumer router on a loopback socket.  The
//! refusals themselves (status, code, message) are `consumer_refusal_tests`'
//! subject and are unchanged; this module asserts what M3-11 adds: the RFC
//! 6750 / RFC 9728 `WWW-Authenticate` challenge on each refused credential,
//! and the protected-resource metadata document it points to.  Tokens are
//! synthetic, signed by a key made for the test.

use std::{sync::Arc, time::Duration};

use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rcgen::KeyPair;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tunnel_catalog::{
    ApprovedJwk, Catalog, CatalogFixture, MembershipRecord, MembershipRole, MemoryCatalog,
    OidcConfig, OidcVerifier, PrincipalIdentity, TenantRecord, UserRecord,
};
use uuid::Uuid;

use super::consumer_router_with_peer_and_barriers;
use crate::{
    actor::RelayHandle,
    config::{RelayLimits, RelayOptions},
};

const ISSUER: &str = "https://m3-11-issuer.example";
const AUDIENCE: &str = "m3-11-audience";
const KID: &str = "m3-11";
const SUBJECT: &str = "m3-11-member";
const BUDGET: Duration = Duration::from_secs(5);
const HOST: &str = "relay.m3-11.test:8443";

#[derive(serde::Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    scope: &'a str,
}

fn token(key: &KeyPair, scope: &str) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(KID.to_owned());
    encode(
        &header,
        &Claims {
            iss: ISSUER,
            sub: SUBJECT,
            aud: AUDIENCE,
            exp: Utc::now().timestamp() + 300,
            scope,
        },
        &EncodingKey::from_ed_der(&key.serialize_der()),
    )
    .expect("sign token")
}

async fn start(
    exports: Option<crate::http::forward::HttpForwardExports>,
) -> (std::net::SocketAddr, KeyPair) {
    start_requiring(exports, &[]).await
}

async fn start_requiring(
    exports: Option<crate::http::forward::HttpForwardExports>,
    required_scopes: &[&str],
) -> (std::net::SocketAddr, KeyPair) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("OIDC signing key");
    let approved = ApprovedJwk::from_ed25519_der(KID, key.public_key_raw()).expect("approved key");
    let config = OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved])
        .expect("config")
        .with_required_scopes(required_scopes.iter().map(|scope| (*scope).to_owned()))
        .expect("required scopes");
    let oidc = Arc::new(OidcVerifier::new(config).expect("verifier"));
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let catalog = Arc::new(MemoryCatalog::new());
    catalog
        .seed_fixture(&CatalogFixture {
            tenants: vec![TenantRecord {
                tenant_id,
                display_name: "m3-11 tenant".to_owned(),
                active: true,
            }],
            users: vec![UserRecord {
                user_id,
                display_name: "m3-11 member".to_owned(),
            }],
            identities: vec![PrincipalIdentity {
                issuer: ISSUER.to_owned(),
                subject: SUBJECT.to_owned(),
                user_id,
            }],
            memberships: vec![MembershipRecord {
                tenant_id,
                user_id,
                role: MembershipRole::Member,
                active: true,
            }],
            ..CatalogFixture::default()
        })
        .await
        .expect("seed catalog");
    let handle = RelayHandle::spawn(RelayOptions::new(oidc.clone()), catalog.clone());
    let router = consumer_router_with_peer_and_barriers(
        handle,
        catalog,
        oidc,
        RelayLimits::default(),
        None,
        None,
        None,
        exports,
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .await
            .expect("consumer router");
    });
    (address, key)
}

struct Answer {
    status: u16,
    challenge: Option<String>,
    body: serde_json::Value,
}

async fn send(
    address: std::net::SocketAddr,
    request_line: &str,
    authorization: Option<&str>,
) -> Answer {
    let mut socket = TcpStream::connect(address).await.expect("connect");
    let mut request = format!("{request_line}\r\nHost: {HOST}\r\nConnection: close\r\n");
    if request_line.starts_with("POST") {
        request.push_str("Content-Type: application/json\r\nContent-Length: 2\r\n");
    }
    if let Some(value) = authorization {
        request.push_str(&format!("Authorization: {value}\r\n"));
    }
    request.push_str("\r\n");
    if request_line.starts_with("POST") {
        request.push_str("{}");
    }
    socket.write_all(request.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    timeout(BUDGET, socket.read_to_end(&mut raw))
        .await
        .expect("answered in time")
        .expect("read");
    let text = String::from_utf8(raw).expect("UTF-8 answer");
    let (head, body) = text.split_once("\r\n\r\n").expect("head and body");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status");
    let challenge = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("www-authenticate")
            .then(|| value.trim().to_owned())
    });
    let body = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    Answer {
        status,
        challenge,
        body,
    }
}

#[tokio::test]
async fn refused_credentials_carry_a_bearer_challenge_naming_the_resource_metadata() {
    let (address, key) = start(Some(crate::http::forward::HttpForwardExports::new())).await;
    let (device, service) = (Uuid::new_v4(), Uuid::new_v4());
    let path = format!("/v1/devices/{device}/services/{service}/http/mcp");
    let metadata =
        format!("resource_metadata=\"https://{HOST}/.well-known/oauth-protected-resource{path}\"");
    let line = format!("POST {path} HTTP/1.1");

    let missing = send(address, &line, None).await;
    assert_eq!(missing.status, 401);
    assert_eq!(
        missing.challenge.as_deref(),
        Some(format!("Bearer {metadata}, scope=\"http:invoke\"").as_str()),
        "a request with no token is told where the metadata is and which scope it needs"
    );

    let invalid = send(address, &line, Some("Bearer not-a-jwt")).await;
    assert_eq!(invalid.status, 401);
    assert_eq!(
        invalid.challenge.as_deref(),
        Some(format!("Bearer error=\"invalid_token\", {metadata}, scope=\"http:invoke\"").as_str())
    );

    let wrong_scope = token(&key, "echo:invoke");
    let insufficient = send(address, &line, Some(&format!("Bearer {wrong_scope}"))).await;
    assert_eq!(insufficient.status, 403);
    assert_eq!(
        insufficient.challenge.as_deref(),
        Some(
            format!("Bearer error=\"insufficient_scope\", {metadata}, scope=\"http:invoke\"")
                .as_str()
        )
    );

    // A token that passes is refused later for want of a grant, which is not
    // a credential challenge: no `WWW-Authenticate` is invented for it.
    let good = token(&key, "http:invoke");
    let no_grant = send(address, &line, Some(&format!("Bearer {good}"))).await;
    assert_ne!(no_grant.status, 401);
    assert_eq!(no_grant.challenge, None);
}

#[tokio::test]
async fn the_protected_resource_metadata_names_the_issuer_the_scope_and_the_exact_resource() {
    let (address, _key) = start(Some(crate::http::forward::HttpForwardExports::new())).await;
    let (device, service) = (Uuid::new_v4(), Uuid::new_v4());
    let path = format!("/v1/devices/{device}/services/{service}/http/mcp");
    let answer = send(
        address,
        &format!("GET /.well-known/oauth-protected-resource{path} HTTP/1.1"),
        None,
    )
    .await;
    assert_eq!(answer.status, 200, "{:?}", answer.body);
    assert_eq!(answer.body["resource"], format!("https://{HOST}{path}"));
    assert_eq!(
        answer.body["authorization_servers"],
        serde_json::json!([ISSUER])
    );
    assert_eq!(
        answer.body["scopes_supported"],
        serde_json::json!(["http:invoke"])
    );
    assert_eq!(
        answer.body["bearer_methods_supported"],
        serde_json::json!(["header"])
    );

    // A configured public origin replaces the request's authority.
    let (configured, _key) = start(Some(
        crate::http::forward::HttpForwardExports::new()
            .with_public_url("https://relay.public.test")
            .expect("valid origin"),
    ))
    .await;
    let answer = send(
        configured,
        &format!("GET /.well-known/oauth-protected-resource{path} HTTP/1.1"),
        None,
    )
    .await;
    assert_eq!(
        answer.body["resource"],
        format!("https://relay.public.test{path}")
    );
    let missing = send(configured, &format!("POST {path} HTTP/1.1"), None).await;
    assert!(
        missing
            .challenge
            .as_deref()
            .is_some_and(|value| value.contains(&format!(
                "resource_metadata=\"https://relay.public.test/.well-known/oauth-protected-resource{path}\""
            ))),
        "{:?}",
        missing.challenge
    );

    // Malformed identifiers are not resources.
    for refused in [
        format!(
            "GET /.well-known/oauth-protected-resource/v1/devices/not-a-uuid/services/{service}/http/mcp HTTP/1.1"
        ),
        format!(
            "GET /.well-known/oauth-protected-resource/v1/devices/{device}/services/{service}/http/mc%20p HTTP/1.1"
        ),
    ] {
        assert_eq!(send(address, &refused, None).await.status, 404, "{refused}");
    }

    // A relay that serves no http-forward profile publishes no metadata.
    let (bare, _key) = start(None).await;
    assert_eq!(
        send(
            bare,
            &format!("GET /.well-known/oauth-protected-resource{path} HTTP/1.1"),
            None
        )
        .await
        .status,
        404
    );
}

/// Review of #173: the challenge's `scope` and the metadata's
/// `scopes_supported` are the same set, including any scope the relay
/// requires of every token, so a client that asks for exactly what the
/// challenge names gets a token this route accepts.
#[tokio::test]
async fn the_challenge_scope_and_scopes_supported_are_the_same_set() {
    let (address, _key) = start_requiring(
        Some(crate::http::forward::HttpForwardExports::new()),
        &["agent:use"],
    )
    .await;
    let (device, service) = (Uuid::new_v4(), Uuid::new_v4());
    let path = format!("/v1/devices/{device}/services/{service}/http/mcp");
    let metadata = send(
        address,
        &format!("GET /.well-known/oauth-protected-resource{path} HTTP/1.1"),
        None,
    )
    .await;
    let supported: Vec<String> = metadata.body["scopes_supported"]
        .as_array()
        .expect("scopes_supported")
        .iter()
        .map(|scope| scope.as_str().expect("string").to_owned())
        .collect();
    assert_eq!(supported, ["agent:use", "http:invoke"]);
    let challenge = send(address, &format!("POST {path} HTTP/1.1"), None)
        .await
        .challenge
        .expect("challenge");
    let scope = challenge
        .split("scope=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("scope parameter");
    assert_eq!(scope.split(' ').collect::<Vec<_>>(), supported);
}
