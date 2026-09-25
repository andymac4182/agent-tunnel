//! Task row M3-11: the MCP HTTP authorization profile at the relay.
//!
//! The MCP 2025-11-25 authorization specification (pinned in
//! docs/sources.md) requires a protected MCP server to publish OAuth 2.0
//! Protected Resource Metadata (RFC 9728) and to name it in the
//! `WWW-Authenticate` challenge of every `401`, so that a standard client that
//! has no token yet can discover which authorization server to ask.  A
//! token that lacks the route's scope gets `403` with
//! `error="insufficient_scope"` and the scope it needs.
//!
//! **The relay's own OIDC/JWT validation stays the authority.**  Nothing
//! here accepts, derives or widens a credential: the metadata names the
//! configured issuer as the only authorization server and `http:invoke`
//! (plus any scope every token must carry) as the scopes, and the challenge
//! only describes a refusal the verifier already made.  Token validation --
//! issuer, audience, signature, expiry, scope, catalog identity and grant --
//! is unchanged and happens before any of this is consulted.
//!
//! **What the metadata does not reveal.**  It is served without
//! authentication for any well-formed device and service identifier, and it
//! is the same document whether or not that device, service or grant exists,
//! so it is not an existence oracle.  The resource identifier is built from
//! the configured `public_url` or, absent that, from the request's own
//! authority -- the URL the caller used, which is what RFC 9728 section 3.3
//! requires the `resource` value to equal.

use axum::http::HeaderValue;
use tunnel_catalog::OidcError;

use super::*;

/// RFC 9728's well-known path segment, inserted before the resource's path.
pub(crate) const PROTECTED_RESOURCE_WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";
/// The longest resource path the metadata route answers for.
const MAX_RESOURCE_PATH: usize = 512;
/// The longest authority taken from a request.
const MAX_AUTHORITY: usize = 255;

/// Validate a configured public origin: `https://host[:port]`, no path,
/// query, fragment or userinfo.  Returns it without a trailing slash.
///
/// # Errors
/// Anything else.
pub fn validate_public_url(url: &str) -> Result<String, &'static str> {
    const INVALID: &str =
        "http_forward.public_url must be https://host[:port] with no path, query or userinfo";
    let authority = url
        .strip_prefix("https://")
        .ok_or(INVALID)?
        .trim_end_matches('/');
    if !authority_is_plain(authority) {
        return Err(INVALID);
    }
    Ok(format!("https://{authority}"))
}

/// A host and optional port made only of the characters an authority may
/// carry here: no userinfo, path, query, fragment, whitespace or percent.
fn authority_is_plain(authority: &str) -> bool {
    !authority.is_empty()
        && authority.len() <= MAX_AUTHORITY
        && authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
}

/// The origin resource identifiers are built from: the configured public
/// URL, or the request's own authority over HTTPS.  `None` when neither is
/// usable, in which case no metadata URL is advertised.
pub(crate) fn resource_origin(
    exports: &HttpForwardExports,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> Option<String> {
    if let Some(public) = exports.public_url() {
        return Some(public.to_owned());
    }
    let authority = uri
        .authority()
        .map(|authority| authority.as_str().to_owned())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })?;
    authority_is_plain(&authority).then(|| format!("https://{authority}"))
}

/// The `WWW-Authenticate` value for a refused consumer credential on an
/// `http-forward` route, or `None` when the refusal is the relay's own fault
/// (`503`), which is not a credential challenge.
pub(crate) fn bearer_challenge(
    origin: Option<&str>,
    resource_path: &str,
    error: &OidcError,
) -> Option<HeaderValue> {
    let error_code = match error {
        OidcError::MissingBearer => None,
        OidcError::InvalidToken
        | OidcError::DisallowedAlgorithm
        | OidcError::MissingKeyId
        | OidcError::UnknownKey
        | OidcError::ClaimsRejected
        | OidcError::UnknownConsumer => Some("invalid_token"),
        OidcError::InsufficientScope => Some("insufficient_scope"),
        OidcError::Catalog(_) | OidcError::InvalidConfiguration => return None,
    };
    let mut parameters = Vec::new();
    if let Some(code) = error_code {
        parameters.push(format!("error=\"{code}\""));
    }
    if let Some(origin) = origin {
        parameters.push(format!(
            "resource_metadata=\"{origin}{PROTECTED_RESOURCE_WELL_KNOWN}{resource_path}\""
        ));
    }
    parameters.push(format!("scope=\"{}\"", crate::HTTP_FORWARD_OPERATION));
    HeaderValue::from_str(&format!("Bearer {}", parameters.join(", "))).ok()
}

/// The scopes a token needs on an `http-forward` route: `http:invoke` and
/// every scope the relay requires of all tokens.
fn scopes_supported(oidc: &tunnel_catalog::OidcVerifier) -> Vec<String> {
    let mut scopes: std::collections::BTreeSet<String> =
        oidc.config().required_scopes.iter().cloned().collect();
    scopes.insert(crate::HTTP_FORWARD_OPERATION.to_owned());
    scopes.into_iter().collect()
}

/// `GET /.well-known/oauth-protected-resource/v1/devices/{device}/services/{service}/http/{*path}`:
/// RFC 9728 metadata for that `http-forward` route.
pub(crate) async fn protected_resource_metadata_route(
    State(state): State<HttpState>,
    Path((device, service, path)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let not_found = || {
        error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "not found",
            "not_dispatched",
        )
    };
    let (Some(exports), Some(oidc)) = (state.http_forward.as_ref(), state.oidc.as_ref()) else {
        return not_found();
    };
    if Uuid::parse_str(&device).is_err()
        || Uuid::parse_str(&service).is_err()
        || path.is_empty()
        || path.len() > MAX_RESOURCE_PATH
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
    {
        return not_found();
    }
    let Some(origin) = resource_origin(exports, request.headers(), request.uri()) else {
        return not_found();
    };
    let body = serde_json::json!({
        "resource": format!("{origin}/v1/devices/{device}/services/{service}/http/{path}"),
        "authorization_servers": [oidc.config().issuer.clone()],
        "scopes_supported": scopes_supported(oidc),
        "bearer_methods_supported": ["header"],
        "resource_name": "Agent Uplink http-forward export",
    });
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_urls_are_bare_https_origins() {
        assert_eq!(
            validate_public_url("https://relay.example.test/").as_deref(),
            Ok("https://relay.example.test")
        );
        assert_eq!(
            validate_public_url("https://relay.example.test:8443").as_deref(),
            Ok("https://relay.example.test:8443")
        );
        for refused in [
            "http://relay.example.test",
            "https://",
            "https://relay.example.test/v1",
            "https://user@relay.example.test",
            "https://relay.example.test?x=1",
            "https://relay.example.test#f",
            "https://relay example",
        ] {
            assert!(validate_public_url(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn challenges_name_the_metadata_the_scope_and_the_token_error() {
        let path = "/v1/devices/d/services/s/http/mcp";
        let origin = Some("https://relay.test");
        let value = |error| {
            bearer_challenge(origin, path, &error)
                .map(|value| value.to_str().expect("ASCII").to_owned())
        };
        let metadata = "resource_metadata=\"https://relay.test/.well-known/oauth-protected-resource/v1/devices/d/services/s/http/mcp\"";
        assert_eq!(
            value(OidcError::MissingBearer).as_deref(),
            Some(format!("Bearer {metadata}, scope=\"http:invoke\"").as_str())
        );
        assert_eq!(
            value(OidcError::ClaimsRejected).as_deref(),
            Some(
                format!("Bearer error=\"invalid_token\", {metadata}, scope=\"http:invoke\"")
                    .as_str()
            )
        );
        assert_eq!(
            value(OidcError::InsufficientScope).as_deref(),
            Some(
                format!("Bearer error=\"insufficient_scope\", {metadata}, scope=\"http:invoke\"")
                    .as_str()
            )
        );
        assert_eq!(value(OidcError::InvalidConfiguration), None);
        assert_eq!(
            bearer_challenge(None, path, &OidcError::MissingBearer)
                .map(|value| value.to_str().expect("ASCII").to_owned())
                .as_deref(),
            Some("Bearer scope=\"http:invoke\"")
        );
    }

    #[test]
    fn a_request_authority_is_used_only_when_it_is_plain() {
        let exports = HttpForwardExports::new();
        let mut headers = HeaderMap::new();
        let uri: axum::http::Uri = "/v1/x".parse().expect("uri");
        headers.insert(header::HOST, HeaderValue::from_static("localhost:8443"));
        assert_eq!(
            resource_origin(&exports, &headers, &uri).as_deref(),
            Some("https://localhost:8443")
        );
        headers.insert(header::HOST, HeaderValue::from_static("evil.test/path?x"));
        assert_eq!(resource_origin(&exports, &headers, &uri), None);
        let configured = HttpForwardExports::new()
            .with_public_url("https://relay.example.test")
            .expect("valid");
        assert_eq!(
            resource_origin(&configured, &headers, &uri).as_deref(),
            Some("https://relay.example.test")
        );
    }
}
