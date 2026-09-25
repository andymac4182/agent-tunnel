//! Task rows M6-C53 and M6-C52: a consumer credential refusal gets one
//! status and one truthful message per cause on every consumer route, and
//! the relay logs one payload-free line naming the stage.
//!
//! The dogfood run measured the opposite: the filesystem route answered a
//! validly signed token for an unknown `sub`, and an expired token, with "a
//! consumer access token is required" -- false, a token was sent -- while the
//! echo route said "consumer authentication failed" for the same faults, a
//! token lacking the route's scope got `401` where `403` says the token
//! itself is fine, and the relay logged nothing at all.
//!
//! Every request here crosses the real consumer router on a loopback socket:
//! `devices`, `echo`, `stream`, `http-forward` and `fs`.  Each route keeps its
//! documented code vocabulary -- the flat body's `UNAUTHORIZED`/`FORBIDDEN`,
//! the filesystem contract's `UNAUTHENTICATED`/`ACCESS_DENIED`
//! (`docs/filesystem-api.md`) -- and the status and message are asserted
//! equal across all of them.  The tokens are synthetic, signed by a key made
//! for the test.

use std::{
    io::Write as _,
    sync::{Arc, Mutex},
    time::Duration,
};

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

use super::{CONSUMER_TOKEN_REFUSED, consumer_router_with_peer_and_barriers};
use crate::{
    actor::RelayHandle,
    config::{RelayLimits, RelayOptions},
};

const ISSUER: &str = "https://consumer-refusal-issuer.example";
const AUDIENCE: &str = "consumer-refusal-audience";
const KID: &str = "consumer-refusal";
const KNOWN_SUBJECT: &str = "consumer-refusal-member";
const BUDGET: Duration = Duration::from_secs(5);

const MISSING_MESSAGE: &str = "a consumer access token is required";
const SCOPE_MESSAGE: &str = "the consumer access token does not grant this route's scope";

#[derive(serde::Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    scope: &'a str,
}

struct Signer {
    key: KeyPair,
}

impl Signer {
    fn token(&self, subject: &str, expires_in: i64, scope: &str) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(KID.to_owned());
        encode(
            &header,
            &Claims {
                iss: ISSUER,
                sub: subject,
                aud: AUDIENCE,
                exp: Utc::now().timestamp() + expires_in,
                scope,
            },
            &EncodingKey::from_ed_der(self.key.serialized_der()),
        )
        .expect("synthetic token")
    }
}

/// A `MakeWriter` collecting the relay's log lines for the assertions below.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut *self.0.lock().expect("log buffer"), bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log buffer")).into_owned()
    }
}

async fn start() -> (std::net::SocketAddr, Signer) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("OIDC signing key");
    let approved = ApprovedJwk::from_ed25519_der(KID, key.public_key_raw()).expect("approved key");
    let config = OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved]).expect("config");
    let oidc = Arc::new(OidcVerifier::new(config).expect("verifier"));

    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let catalog = Arc::new(MemoryCatalog::new());
    catalog
        .seed_fixture(&CatalogFixture {
            tenants: vec![TenantRecord {
                tenant_id,
                display_name: "consumer-refusal tenant".to_owned(),
                active: true,
            }],
            users: vec![UserRecord {
                user_id,
                display_name: "consumer-refusal member".to_owned(),
            }],
            identities: vec![PrincipalIdentity {
                issuer: ISSUER.to_owned(),
                subject: KNOWN_SUBJECT.to_owned(),
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
    let options = RelayOptions::new(oidc.clone());
    let limits = RelayLimits::default();
    let handle = RelayHandle::spawn(options, catalog.clone());
    let router = consumer_router_with_peer_and_barriers(
        handle,
        catalog,
        oidc,
        limits,
        None,
        None,
        None,
        Some(crate::http::forward::HttpForwardExports::new()),
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .await
            .expect("consumer router");
    });
    (address, Signer { key })
}

/// The five consumer routes, each as `(label, request line and headers)`.
fn routes() -> Vec<(&'static str, String)> {
    let device = Uuid::new_v4();
    let service = Uuid::new_v4();
    let base = format!("/v1/devices/{device}/services/{service}");
    vec![
        ("devices", "GET /v1/devices HTTP/1.1\r\n".to_owned()),
        (
            "echo",
            format!("POST {base}/echo HTTP/1.1\r\nContent-Length: 0\r\n"),
        ),
        (
            "stream",
            format!(
                "GET {base}/stream HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
                 Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Sec-WebSocket-Protocol: {}\r\n",
                super::ECHO_STREAM_SUBPROTOCOL
            ),
        ),
        (
            "http-forward",
            format!(
                "POST {base}/http/mcp HTTP/1.1\r\nContent-Type: application/json\r\n\
                 Content-Length: 2\r\n"
            ),
        ),
        ("fs", format!("GET {base}/fs HTTP/1.1\r\n")),
    ]
}

/// Send one request and read its status and JSON body.
async fn send(
    address: std::net::SocketAddr,
    head: &str,
    authorization: Option<&str>,
) -> (u16, serde_json::Value) {
    let mut socket = TcpStream::connect(address).await.expect("connect");
    let mut request = format!("{head}Host: 127.0.0.1\r\nConnection: close\r\n");
    if head.contains("Upgrade: websocket") {
        request = format!("{head}Host: 127.0.0.1\r\n");
    }
    if let Some(value) = authorization {
        request.push_str(&format!("Authorization: {value}\r\n"));
    }
    request.push_str("\r\n");
    if head.contains("Content-Length: 2") {
        request.push_str("{}");
    }
    socket.write_all(request.as_bytes()).await.expect("write");
    timeout(BUDGET, async {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let read = socket.read(&mut byte).await.expect("read head");
            assert_eq!(read, 1, "closed before answering");
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).expect("UTF-8 head");
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status");
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        socket.read_exact(&mut body).await.expect("read body");
        let body = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).expect("JSON body")
        };
        (status, body)
    })
    .await
    .expect("answered in time")
}

/// The code and message of either body shape.
fn code_and_message(body: &serde_json::Value) -> (String, String) {
    let detail = body.get("error").unwrap_or(body);
    (
        detail["code"].as_str().unwrap_or_default().to_owned(),
        detail["message"].as_str().unwrap_or_default().to_owned(),
    )
}

#[tokio::test]
async fn every_route_gives_each_refusal_cause_one_status_and_one_truthful_message() {
    // The subscriber is process-global, not thread-scoped: a scoped one lost
    // events to callsite-interest caching when other tests in this binary had
    // already hit the same callsites on threads with no subscriber.  No other
    // test in the crate installs one.  Lines from concurrent tests may land in
    // the buffer too, so each check below looks for the exact route, stage
    // and status triple among the lines its own request produced, and the
    // unit tests that call the same functions use a route label no request
    // here uses.
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("no other test in this crate installs a global subscriber");
    let (address, signer) = start().await;

    let garbage = "Bearer not-a-jwt";
    let unknown = format!(
        "Bearer {}",
        signer.token(
            "consumer-refusal-stranger",
            300,
            "echo:invoke http:invoke fs:connect"
        )
    );
    let expired = format!(
        "Bearer {}",
        signer.token(KNOWN_SUBJECT, -600, "echo:invoke http:invoke fs:connect")
    );
    let unscoped = format!(
        "Bearer {}",
        signer.token(KNOWN_SUBJECT, 300, "devices:read")
    );
    // An unknown consumer whose token also lacks the scope is refused as an
    // unknown consumer (`401`), never told its token is fine (`403`): the
    // verifier checks scope only after the identity lookup.
    let unknown_unscoped = format!(
        "Bearer {}",
        signer.token("consumer-refusal-stranger", 300, "devices:read")
    );
    // (label, Authorization, expected status, expected message, stage)
    let causes: [(&str, Option<&str>, u16, &str, &str); 6] = [
        ("no token", None, 401, MISSING_MESSAGE, "bearer"),
        (
            "unknown sub without the scope",
            Some(&unknown_unscoped),
            401,
            CONSUMER_TOKEN_REFUSED,
            "identity",
        ),
        (
            "garbage token",
            Some(garbage),
            401,
            CONSUMER_TOKEN_REFUSED,
            "token",
        ),
        (
            "unknown sub",
            Some(&unknown),
            401,
            CONSUMER_TOKEN_REFUSED,
            "identity",
        ),
        (
            "expired",
            Some(&expired),
            401,
            CONSUMER_TOKEN_REFUSED,
            "claims",
        ),
        ("wrong scope", Some(&unscoped), 403, SCOPE_MESSAGE, "scope"),
    ];
    let mut all_logs = String::new();
    for (cause, authorization, status, message, stage) in causes {
        for (route, head) in routes() {
            // `/v1/devices` asks for no scope: a token lacking one is fine.
            if route == "devices" && cause == "wrong scope" {
                continue;
            }
            captured.0.lock().expect("log buffer").clear();
            let (got, body) = send(address, &head, authorization).await;
            let (code, got_message) = code_and_message(&body);
            assert_eq!(got, status, "{route}/{cause}: {body}");
            assert_eq!(got_message, message, "{route}/{cause}: {body}");
            let expected_code = match (route, status) {
                ("fs", 401) => "UNAUTHENTICATED",
                ("fs", _) => "ACCESS_DENIED",
                (_, 401) => "UNAUTHORIZED",
                _ => "FORBIDDEN",
            };
            assert_eq!(code, expected_code, "{route}/{cause}: {body}");
            let logs = captured.text();
            assert!(
                logs.lines()
                    .any(|line| line.contains("consumer request refused")
                        && line.contains(&format!("route=\"{route}\""))
                        && line.contains(&format!("stage=\"{stage}\""))
                        && line.contains(&format!("status={status}"))),
                "{route}/{cause}: no refusal line naming route, stage and status in {logs}"
            );
            all_logs.push_str(&logs);
        }
    }
    // M6-C52: payload-free and credential-free -- no token, and no part of
    // one, in anything the relay logged for any of the requests above.
    let logs = all_logs;
    for token in [&unknown, &expired, &unscoped, &unknown_unscoped] {
        let token = token.trim_start_matches("Bearer ");
        for part in token.split('.') {
            assert!(!logs.contains(part), "a token segment reached the log");
        }
    }
    assert!(!logs.contains("not-a-jwt"));

    // Review of M6-C52: the credential stages are reachable with no
    // credential at all, so a flood of them is rate limited per stage.  Sixty
    // requests with no token are each refused, and at most the limiter's
    // burst of lines is written for the `bearer` stage in its window (some of
    // which the loop above already used).
    captured.0.lock().expect("log buffer").clear();
    for _ in 0..60 {
        let (status, _) = send(address, "GET /v1/devices HTTP/1.1\r\n", None).await;
        assert_eq!(status, 401);
    }
    let flood = captured.text();
    let bearer_lines = flood
        .lines()
        .filter(|line| {
            line.contains("consumer request refused") && line.contains("stage=\"bearer\"")
        })
        .count();
    assert!(
        bearer_lines <= tunnel_transport::log_limit::DEFAULT_REFUSAL_LOG_BURST as usize,
        "{bearer_lines} bearer-stage lines for 60 unauthenticated requests"
    );
    assert!(
        !logs.contains("consumer-refusal-stranger"),
        "claims are not logged"
    );
    let _ = std::io::stderr().flush();
}

/// Review of M6-C53: a verifier configuration fault is the relay's, not the
/// consumer's, so it is `503`, never a `401` that blames the token.
#[test]
fn a_verifier_configuration_fault_is_unavailable_not_a_refused_token() {
    let refusal =
        super::classify_consumer_refusal(&tunnel_catalog::OidcError::InvalidConfiguration);
    assert_eq!(refusal.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(refusal.message, CONSUMER_TOKEN_REFUSED);
}

/// Review of M6-C52: the limiter the relay's credential-stage lines go
/// through admits its burst per stage and no more, and stages are separate.
#[test]
fn credential_stage_refusal_lines_are_rate_limited_per_stage() {
    let limiter = tunnel_transport::log_limit::RefusalLogLimiter::new(4, Duration::from_secs(60));
    let bearer = super::classify_consumer_refusal(&tunnel_catalog::OidcError::MissingBearer);
    let token = super::classify_consumer_refusal(&tunnel_catalog::OidcError::InvalidToken);
    let written = (0..200)
        .filter(|_| super::log_consumer_refusal_with(&limiter, "unit", &bearer))
        .count();
    assert_eq!(written, 4);
    assert!(super::log_consumer_refusal_with(&limiter, "unit", &token));
}
