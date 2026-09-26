//! Task row M6-C144 (the M6-C123 soak defect): while an authorized device is
//! offline, the http-forward route (MCP, ACP, computer) must answer the way
//! the echo route does -- `503 DEVICE_OFFLINE`, `execution = not_dispatched`
//! -- and not `404 NOT_FOUND`, which a client reads as "no such service" and
//! does not retry.
//!
//! The offline answer is only reachable after authentication, the catalog
//! lookup and the grant check have all passed, so it tells nothing to a
//! caller who could not already see the service: a caller without a grant
//! gets the same answer for a real service on an offline device as for a
//! service that does not exist.
//!
//! Every request crosses the real consumer router on a loopback socket, with
//! no device session registered at the relay.  The tokens, identifiers and
//! bodies are synthetic.

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
    ApprovedJwk, Catalog, CatalogFixture, FixtureDevice, GrantSpec, MembershipRecord,
    MembershipRole, MemoryCatalog, OidcConfig, OidcVerifier, PermissionSet, PrincipalIdentity,
    ServiceSpec, TenantRecord, UserRecord,
};
use uuid::Uuid;

use super::consumer_router_with_peer_and_barriers;
use crate::{
    actor::RelayHandle,
    config::{RelayLimits, RelayOptions},
    http::forward::{HttpForwardExport, HttpForwardExports},
};

const ISSUER: &str = "https://offline-refusal-issuer.example";
const AUDIENCE: &str = "offline-refusal-audience";
const KID: &str = "offline-refusal";
const GRANTED: &str = "offline-refusal-granted";
const STRANGER: &str = "offline-refusal-stranger";
const PROFILE: &str = "mcp-2025-11-25";
const BUDGET: Duration = Duration::from_secs(10);

#[derive(serde::Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    scope: &'a str,
}

struct Fixture {
    address: std::net::SocketAddr,
    key: KeyPair,
    device_id: Uuid,
    echo_id: Uuid,
    mcp_id: Uuid,
}

impl Fixture {
    fn bearer(&self, subject: &str) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(KID.to_owned());
        let token = encode(
            &header,
            &Claims {
                iss: ISSUER,
                sub: subject,
                aud: AUDIENCE,
                exp: Utc::now().timestamp() + 300,
                scope: "echo:invoke http:invoke",
            },
            &EncodingKey::from_ed_der(self.key.serialized_der()),
        )
        .expect("synthetic token");
        format!("Bearer {token}")
    }
}

async fn start() -> Fixture {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("OIDC signing key");
    let approved = ApprovedJwk::from_ed25519_der(KID, key.public_key_raw()).expect("approved key");
    let config = OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved]).expect("config");
    let oidc = Arc::new(OidcVerifier::new(config).expect("verifier"));

    let tenant_id = Uuid::new_v4();
    let granted = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let echo_id = Uuid::new_v4();
    let mcp_id = Uuid::new_v4();
    let member = |user_id| MembershipRecord {
        tenant_id,
        user_id,
        role: MembershipRole::Member,
        active: true,
    };
    let grant = |service_id, operation: &str| GrantSpec {
        tenant_id,
        principal_id: granted,
        device_id,
        service_id,
        permissions: PermissionSet {
            operations: [operation.to_owned()].into_iter().collect(),
        },
        constraints: serde_json::json!({}),
        expires_at: None,
        active: true,
    };
    let catalog = Arc::new(MemoryCatalog::new());
    catalog
        .seed_fixture(&CatalogFixture {
            tenants: vec![TenantRecord {
                tenant_id,
                display_name: "offline-refusal tenant".to_owned(),
                active: true,
            }],
            users: vec![
                UserRecord {
                    user_id: granted,
                    display_name: "offline-refusal granted".to_owned(),
                },
                UserRecord {
                    user_id: stranger,
                    display_name: "offline-refusal stranger".to_owned(),
                },
            ],
            identities: vec![
                PrincipalIdentity {
                    issuer: ISSUER.to_owned(),
                    subject: GRANTED.to_owned(),
                    user_id: granted,
                },
                PrincipalIdentity {
                    issuer: ISSUER.to_owned(),
                    subject: STRANGER.to_owned(),
                    user_id: stranger,
                },
            ],
            memberships: vec![member(granted), member(stranger)],
            devices: vec![FixtureDevice {
                tenant_id,
                device_id,
                owner_user_id: granted,
                display_name: "offline-refusal device".to_owned(),
                active: true,
                last_seen_at: None,
            }],
            services: vec![
                ServiceSpec {
                    tenant_id,
                    device_id,
                    service_id: echo_id,
                    service_type: crate::ECHO_SERVICE_TYPE.to_owned(),
                    display_name: "offline-refusal echo".to_owned(),
                    capabilities: serde_json::json!({}),
                    version: 1,
                    active: true,
                },
                ServiceSpec {
                    tenant_id,
                    device_id,
                    service_id: mcp_id,
                    service_type: crate::HTTP_FORWARD_SERVICE_TYPE.to_owned(),
                    display_name: "offline-refusal mcp".to_owned(),
                    capabilities: serde_json::json!({
                        "operations": [crate::HTTP_FORWARD_OPERATION],
                        "http_forward_profile": PROFILE,
                    }),
                    version: 1,
                    active: true,
                },
            ],
            grants: vec![
                grant(echo_id, crate::ECHO_OPERATION),
                grant(mcp_id, crate::HTTP_FORWARD_OPERATION),
            ],
            ..CatalogFixture::default()
        })
        .await
        .expect("seed catalog");
    let profile = tunnel_mcp::McpProfile::V2025_11_25
        .policies(tunnel_mcp::McpLimits::default())
        .expect("MCP profile");
    let exports = HttpForwardExports::new()
        .with_profile(
            PROFILE,
            HttpForwardExport::new(
                Arc::new(profile),
                tunnel_http_bridge::BridgeConfig::default(),
            ),
        )
        .expect("export");
    let handle = RelayHandle::spawn(RelayOptions::new(oidc.clone()), catalog.clone());
    let router = consumer_router_with_peer_and_barriers(
        handle,
        catalog,
        oidc,
        RelayLimits::default(),
        None,
        None,
        None,
        Some(exports),
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .await
            .expect("consumer router");
    });
    Fixture {
        address,
        key,
        device_id,
        echo_id,
        mcp_id,
    }
}

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"offline-refusal","version":"1"}}}"#;

/// Send one request and read its status and JSON body.
async fn send(
    address: std::net::SocketAddr,
    method_and_path: &str,
    headers: &str,
    body: &str,
    authorization: &str,
) -> (u16, serde_json::Value) {
    let mut socket = TcpStream::connect(address).await.expect("connect");
    let request = format!(
        "{method_and_path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Authorization: {authorization}\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(request.as_bytes()).await.expect("write");
    timeout(BUDGET, async {
        let mut raw = Vec::new();
        socket.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8(raw).expect("UTF-8 response");
        let (head, body) = text.split_once("\r\n\r\n").expect("response head");
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status");
        let body = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(body).unwrap_or_else(|_| serde_json::json!({"raw": body}))
        };
        (status, body)
    })
    .await
    .expect("answered in time")
}

async fn mcp(fixture: &Fixture, service: Uuid, subject: &str) -> (u16, serde_json::Value) {
    send(
        fixture.address,
        &format!(
            "POST /v1/devices/{}/services/{service}/http/mcp",
            fixture.device_id
        ),
        "Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n",
        INITIALIZE,
        &fixture.bearer(subject),
    )
    .await
}

fn outcome(body: &serde_json::Value) -> (String, String) {
    let detail = body.get("error").unwrap_or(body);
    (
        detail["code"].as_str().unwrap_or_default().to_owned(),
        detail["execution"].as_str().unwrap_or_default().to_owned(),
    )
}

#[tokio::test]
async fn an_offline_device_is_device_offline_on_the_http_forward_route_as_on_echo() {
    let fixture = start().await;

    // Echo is the reference answer for an authorized request to an offline
    // device.
    let (echo_status, echo_body) = send(
        fixture.address,
        &format!(
            "POST /v1/devices/{}/services/{}/echo",
            fixture.device_id, fixture.echo_id
        ),
        "Content-Type: application/octet-stream\r\n",
        "offline-refusal",
        &fixture.bearer(GRANTED),
    )
    .await;
    assert_eq!(echo_status, 503, "echo reference: {echo_body}");
    assert_eq!(
        outcome(&echo_body),
        ("DEVICE_OFFLINE".to_owned(), "not_dispatched".to_owned()),
        "echo reference: {echo_body}"
    );

    // The MCP route, for the same consumer and device, gives the same class.
    let (status, body) = mcp(&fixture, fixture.mcp_id, GRANTED).await;
    assert_eq!(
        (status, outcome(&body)),
        (echo_status, outcome(&echo_body)),
        "an authorized MCP request to an offline device must be DEVICE_OFFLINE/not_dispatched \
         like echo, not a 404 that reads as 'no such service': {body}"
    );
}

#[tokio::test]
async fn the_offline_answer_says_nothing_to_a_caller_without_a_grant() {
    let fixture = start().await;

    // No such service, even for the granted consumer: still the 404 class.
    let (missing_status, missing_body) = mcp(&fixture, Uuid::new_v4(), GRANTED).await;
    assert_eq!(missing_status, 404, "{missing_body}");
    assert_eq!(outcome(&missing_body).1, "not_dispatched", "{missing_body}");

    // A member without a grant: a real service on an offline device and an
    // invented one are answered identically, and neither is DEVICE_OFFLINE.
    let real = mcp(&fixture, fixture.mcp_id, STRANGER).await;
    let invented = mcp(&fixture, Uuid::new_v4(), STRANGER).await;
    assert_eq!(
        (real.0, outcome(&real.1)),
        (invented.0, outcome(&invented.1)),
        "an unauthorized caller must not learn that the service exists: {} / {}",
        real.1,
        invented.1
    );
    assert_ne!(outcome(&real.1).0, "DEVICE_OFFLINE", "{}", real.1);
    assert!(matches!(real.0, 403 | 404), "{}", real.1);
}
