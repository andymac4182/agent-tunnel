#![cfg(unix)]
//! M3-04: `mcp-2025-11-25` protocol sessions are bound to the authenticated
//! principal the relay ingress named, for both export kinds.
//!
//! The relay derives an opaque per-principal value and sets it as
//! `tunnel-principal-binding`; these tests drive the device export directly
//! through the in-process `http-forward/1` bridge with chosen binding values,
//! which is exactly what the export sees on the wire.  A request whose
//! binding differs from the one the session was opened with is answered as an
//! unknown session — the same status, code and message — so a session ID that
//! leaks to another authorized consumer proves nothing and grants nothing.

mod common;

use bytes::Bytes;
use common::{body_bytes, exchange, http_export, rmcp_http_backend, stdio_export, within};
use http::{Request, StatusCode};
use http_body_util::Full;
use tunnel_mcp_export::McpExport;

const LEGACY: &str = "mcp-2025-11-25";
const CURRENT: &str = "mcp-2026-07-28";
const BINDING: &str = "tunnel-principal-binding";
/// Two distinct opaque bindings, as the ingress would derive them for two
/// authenticated consumers of the same device and service.
const CONSUMER_A: &str = "7f2c9a1b4d6e8f0a1b2c3d4e5f60718a";
const CONSUMER_B: &str = "0a1b2c3d4e5f60718a7f2c9a1b4d6e8f";

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}"#;
const LIST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

fn request(method: &str, headers: &[(&str, &str)], body: impl Into<Bytes>) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method(method)
        .uri("/mcp")
        .header("host", "gateway.test");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Full::new(body.into())).expect("request")
}

fn post(headers: &[(&str, &str)], body: impl Into<Bytes>) -> Request<Full<Bytes>> {
    request("POST", headers, body)
}

/// The headers of a POST on an established session for one binding.
fn session_post(session: &str, binding: Option<&str>) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
        ("mcp-protocol-version", "2025-11-25".to_owned()),
        ("mcp-session-id", session.to_owned()),
    ];
    if let Some(binding) = binding {
        headers.push((BINDING, binding.to_owned()));
    }
    headers
}

fn refs<'a>(headers: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

/// Open a legacy session as `binding` and return its ID.
async fn open_session(export: &McpExport, binding: &str) -> String {
    let headers = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        (BINDING, binding),
    ];
    let response = within(exchange(export, post(&headers, INITIALIZE))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()[tunnel_mcp::headers::MCP_SESSION_ID]
        .to_str()
        .expect("session id")
        .to_owned();
    let _ = body_bytes(response).await;
    let initialized = session_post(&session, Some(binding));
    let response = within(exchange(
        export,
        post(
            &refs(&initialized),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        ),
    ))
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let _ = body_bytes(response).await;
    session
}

/// A response reduced to what a consumer can distinguish.
#[derive(Debug, Eq, PartialEq)]
struct Seen {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn seen(response: http::Response<tunnel_http_bridge::ChannelBody>) -> Seen {
    let status = response.status();
    let mut headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    headers.sort();
    let body = body_bytes(response).await.unwrap_or_default().to_vec();
    Seen {
        status,
        headers,
        body,
    }
}

/// Every legacy route refuses another principal's binding, and the absence of
/// a binding is itself a distinct principal rather than a wildcard.  Each
/// refusal is compared field for field with the same route's answer for a
/// session that never existed, so nothing at all distinguishes them.
async fn refuses_every_other_binding(export: &McpExport, session: &str) {
    const ABSENT: &str = "ffffffffffffffffffffffffffffffff";
    for foreign in [Some(CONSUMER_B), None] {
        let foreign_post = seen(
            within(exchange(
                export,
                post(&refs(&session_post(session, foreign)), LIST),
            ))
            .await,
        )
        .await;
        let absent_post = seen(
            within(exchange(
                export,
                post(&refs(&session_post(ABSENT, foreign)), LIST),
            ))
            .await,
        )
        .await;
        assert_eq!(
            foreign_post.status,
            StatusCode::NOT_FOUND,
            "POST with binding {foreign:?}"
        );
        assert_eq!(foreign_post, absent_post, "POST with binding {foreign:?}");

        let get_headers = |id: &str| {
            let mut headers = session_post(id, foreign);
            headers.retain(|(name, _)| *name != "content-type" && *name != "accept");
            headers.push(("accept", "text/event-stream".to_owned()));
            headers
        };
        let foreign_get = seen(
            within(exchange(
                export,
                request("GET", &refs(&get_headers(session)), Bytes::new()),
            ))
            .await,
        )
        .await;
        let absent_get = seen(
            within(exchange(
                export,
                request("GET", &refs(&get_headers(ABSENT)), Bytes::new()),
            ))
            .await,
        )
        .await;
        assert_eq!(
            foreign_get.status,
            StatusCode::NOT_FOUND,
            "GET with binding {foreign:?}"
        );
        assert_eq!(foreign_get, absent_get, "GET with binding {foreign:?}");

        let delete_headers = |id: &str| {
            let mut headers = session_post(id, foreign);
            headers.retain(|(name, _)| *name != "content-type" && *name != "accept");
            headers
        };
        let foreign_delete = seen(
            within(exchange(
                export,
                request("DELETE", &refs(&delete_headers(session)), Bytes::new()),
            ))
            .await,
        )
        .await;
        let absent_delete = seen(
            within(exchange(
                export,
                request("DELETE", &refs(&delete_headers(ABSENT)), Bytes::new()),
            ))
            .await,
        )
        .await;
        assert_eq!(
            foreign_delete.status,
            StatusCode::NOT_FOUND,
            "DELETE with binding {foreign:?}"
        );
        assert_eq!(
            foreign_delete, absent_delete,
            "DELETE with binding {foreign:?}"
        );
    }
}

/// The owning principal still holds a working session after every refusal.
async fn still_serves_its_own_principal(export: &McpExport, session: &str, binding: &str) {
    let headers = session_post(session, Some(binding));
    let response = within(exchange(export, post(&refs(&headers), LIST))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await.expect("body");
    let text = std::str::from_utf8(&body).expect("utf-8");
    assert!(text.contains("\"id\":1"), "own principal still served");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stdio_legacy_session_serves_only_the_principal_it_was_opened_for() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(LEGACY, workspace.path(), 4);
    let session = open_session(&export, CONSUMER_A).await;

    refuses_every_other_binding(&export, &session).await;
    still_serves_its_own_principal(&export, &session, CONSUMER_A).await;

    // A second principal opens its own session on the same export; the two
    // are distinct and neither ID works for the other.
    let other = open_session(&export, CONSUMER_B).await;
    assert_ne!(session, other);
    let crossed = session_post(&other, Some(CONSUMER_A));
    let response = within(exchange(&export, post(&refs(&crossed), LIST))).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let _ = body_bytes(response).await;
    still_serves_its_own_principal(&export, &other, CONSUMER_B).await;

    // Only the owning principal can end the session.
    let mut delete_headers = session_post(&session, Some(CONSUMER_A));
    delete_headers.retain(|(name, _)| *name != "content-type" && *name != "accept");
    let response = within(exchange(
        &export,
        request("DELETE", &refs(&delete_headers), Bytes::new()),
    ))
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let _ = body_bytes(response).await;
    let after = session_post(&session, Some(CONSUMER_A));
    let response = within(exchange(&export, post(&refs(&after), LIST))).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let _ = body_bytes(response).await;
    // The other principal's session is untouched by that DELETE.
    still_serves_its_own_principal(&export, &other, CONSUMER_B).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_streamable_http_legacy_session_serves_only_the_principal_it_was_opened_for() {
    let markers = tempfile::tempdir().expect("markers");
    let (url, shutdown) = rmcp_http_backend(true, markers.path()).await;
    let export = http_export(LEGACY, &url, None);
    let session = open_session(&export, CONSUMER_A).await;

    refuses_every_other_binding(&export, &session).await;
    still_serves_its_own_principal(&export, &session, CONSUMER_A).await;

    let other = open_session(&export, CONSUMER_B).await;
    assert_ne!(session, other);
    let crossed = session_post(&other, Some(CONSUMER_A));
    let response = within(exchange(&export, post(&refs(&crossed), LIST))).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let _ = body_bytes(response).await;
    still_serves_its_own_principal(&export, &other, CONSUMER_B).await;
    shutdown.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_binding_header_is_not_part_of_the_2026_profile() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export(CURRENT, workspace.path(), 2);
    let profile = export.profile_policies().expect("profile");
    assert!(!profile.request.headers.allows(BINDING));
    // The bridge refuses it before the device is invoked, so no child runs.
    let headers = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/list"),
        (BINDING, CONSUMER_A),
    ];
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    let response = within(exchange(&export, post(&headers, body))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let _ = body_bytes(response).await;
    assert_eq!(export.diagnostics().children_spawned, 0);
}
