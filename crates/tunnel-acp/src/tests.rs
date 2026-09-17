//! Profile allowlist tests.
//!
//! Every assertion here drives the **real** `http-forward/1` validator
//! (`encode_request_head` / `encode_response_head`) against the policies
//! `AcpProfile::policies` built.  None of them compares the pinned tables with
//! themselves: a test that read `request_headers()` and asserted the same list
//! back would pass for any table at all.

use super::*;
use tunnel_http_forward::{
    CodecError, HeaderField, HeaderRule, HttpErrorCode, RequestHead, ResponseHead,
    encode_request_head, encode_response_head,
};

fn profile() -> Profile {
    AcpProfile::HttpV1.policies(AcpLimits::default()).unwrap()
}

fn request(method: Method, path: &str, headers: &[(&str, &str)]) -> RequestHead {
    RequestHead {
        method,
        path: path.to_owned(),
        query: String::new(),
        http_version: HttpVersion::Http2,
        headers: headers
            .iter()
            .map(|(name, value)| HeaderField::new(*name, *value))
            .collect(),
        body_length: Some(0),
    }
}

fn check_request(profile: &Profile, head: &RequestHead) -> Result<(), CodecError> {
    encode_request_head(head, &profile.request, &mut Vec::new())
}

fn check_response(profile: &Profile, headers: &[(&str, &str)]) -> Result<(), CodecError> {
    let head = ResponseHead {
        status: 200,
        headers: headers
            .iter()
            .map(|(name, value)| HeaderField::new(*name, *value))
            .collect(),
        body_length: None,
    };
    encode_response_head(&head, &profile.response, Method::Post, &mut Vec::new())
}

/// Names one keystroke away from an allowed one, or from a neighbouring
/// protocol.  Each must be refused as "not allowed" rather than reaching the
/// device.
const NEIGHBOUR_REQUEST_HEADERS: &[&str] = &[
    "acp-connection",
    "acp-connectionid",
    "acp-connection-ids",
    "acp-session",
    "acp-sessionid",
    "acp-session-ids",
    "acp-protocol-version",
    "acp-connection-id-2",
    "x-acp-connection-id",
    "tunnel-principal",
    "tunnel-principal-bindings",
    "mcp-session-id",
    "last-event-id",
    "origin",
    "user-agent",
    "accept-encoding",
    "accept-language",
    "content-encoding",
    "cache-control",
    "if-none-match",
    "www-authenticate",
    "sec-fetch-mode",
];

const NEIGHBOUR_RESPONSE_HEADERS: &[&str] = &[
    // The RFD returns a new session's identifier in the `session/new`
    // response **body**; no response carries it as a header, so allowing one
    // would create a second, unvalidated source of session identity.
    "acp-session-id",
    "acp-connection",
    "www-authenticate",
    "location",
    "content-encoding",
    "etag",
    "server",
    "date",
    "access-control-allow-origin",
    "retry-after",
    "vary",
    "tunnel-principal-binding",
];

#[test]
fn the_profile_id_and_version_are_pinned() {
    assert_eq!(AcpProfile::HttpV1.id(), "acp-http-v1");
    assert_eq!(AcpProfile::HttpV1.protocol_version(), 1);
    assert_eq!(
        AcpProfile::parse_id("acp-http-v1"),
        Some(AcpProfile::HttpV1)
    );
    for bad in [
        "acp",
        "acp-http",
        "acp-http-v2",
        "ACP-HTTP-V1",
        "acp-http-v1 ",
        "http-v1",
    ] {
        assert_eq!(AcpProfile::parse_id(bad), None, "{bad}");
    }
}

#[test]
fn every_allowed_request_header_is_accepted_on_its_own() {
    let profile = profile();
    let all = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("acp-connection-id", "connection-demo"),
        ("acp-session-id", "session-demo"),
        (
            "tunnel-principal-binding",
            "7f2c9a1b4d6e8f0a1b2c3d4e5f60718a",
        ),
    ];
    assert_eq!(
        check_request(&profile, &request(Method::Post, "/acp", &all)),
        Ok(())
    );
    // Each one alone, so a pass cannot come from a neighbour in the same head.
    for (name, value) in all {
        assert_eq!(
            check_request(&profile, &request(Method::Post, "/acp", &[(name, value)])),
            Ok(()),
            "{name}"
        );
    }
    // The pinned list and the validator agree about membership.
    for (name, _) in AcpProfile::HttpV1.request_headers() {
        assert!(profile.request.headers.allows(name), "{name}");
    }
}

#[test]
fn every_allowed_response_header_is_accepted_on_its_own() {
    let profile = profile();
    for name in [
        "content-type",
        "cache-control",
        "x-accel-buffering",
        "acp-connection-id",
    ] {
        assert_eq!(check_response(&profile, &[(name, "x")]), Ok(()), "{name}");
    }
    assert_eq!(
        check_response(
            &profile,
            &[
                ("content-type", "text/event-stream"),
                ("cache-control", "no-store"),
                ("x-accel-buffering", "no"),
                ("acp-connection-id", "connection-demo"),
            ]
        ),
        Ok(())
    );
}

#[test]
fn the_principal_binding_is_request_only_and_a_singleton() {
    let profile = profile();
    let name = headers::TUNNEL_PRINCIPAL_BINDING;
    assert!(profile.request.headers.allows(name));
    // A device can never answer with one: it is derived by the ingress.
    assert!(!profile.response.headers.allows(name));
    assert_eq!(
        check_request(
            &profile,
            &request(Method::Post, "/acp", &[(name, "a"), (name, "b")])
        ),
        Err(CodecError::InvalidHeader(HeaderRule::RepeatedSingleton))
    );
}

#[test]
fn every_pinned_request_header_rejects_a_repeat() {
    let profile = profile();
    for (name, _) in AcpProfile::HttpV1.request_headers() {
        assert_eq!(
            check_request(
                &profile,
                &request(Method::Post, "/acp", &[(name, "a"), (name, "b")])
            ),
            Err(CodecError::InvalidHeader(HeaderRule::RepeatedSingleton)),
            "{name}"
        );
    }
}

#[test]
fn neighbouring_header_spellings_are_refused_in_both_directions() {
    let profile = profile();
    for name in NEIGHBOUR_REQUEST_HEADERS {
        assert_eq!(
            check_request(&profile, &request(Method::Post, "/acp", &[(name, "x")])),
            Err(CodecError::InvalidHeader(HeaderRule::NotAllowed)),
            "{name}"
        );
    }
    for name in NEIGHBOUR_RESPONSE_HEADERS {
        assert_eq!(
            check_response(&profile, &[(name, "x")]),
            Err(CodecError::InvalidHeader(HeaderRule::NotAllowed)),
            "{name}"
        );
    }
}

#[test]
fn credentials_and_routing_authority_are_forbidden_not_merely_unlisted() {
    let profile = profile();
    for name in [
        "authorization",
        "cookie",
        "set-cookie",
        "host",
        "content-length",
        "x-forwarded-for",
        "forwarded",
        "x-agent-tunnel-tenant",
    ] {
        assert_eq!(
            check_request(&profile, &request(Method::Post, "/acp", &[(name, "x")])),
            Err(CodecError::InvalidHeader(HeaderRule::Forbidden)),
            "{name}"
        );
    }
}

#[test]
fn exactly_post_get_and_delete_are_routed_at_the_single_endpoint() {
    let profile = profile();
    for method in [Method::Post, Method::Get, Method::Delete] {
        assert_eq!(
            check_request(&profile, &request(method, "/acp", &[])),
            Ok(()),
            "{method:?}"
        );
    }
    for method in [Method::Put, Method::Patch, Method::Head, Method::Options] {
        assert_eq!(
            check_request(&profile, &request(method, "/acp", &[])),
            Err(CodecError::RouteNotAllowed),
            "{method:?}"
        );
    }
}

#[test]
fn neighbouring_paths_and_any_query_are_refused() {
    let profile = profile();
    for path in [
        "/",
        "/acp/",
        "/acpx",
        "/ACP",
        "/acp/session",
        "/v1/acp",
        "/ac",
        "/mcp",
    ] {
        assert!(
            check_request(&profile, &request(Method::Post, path, &[])).is_err(),
            "{path}"
        );
    }
    for query in ["session=1", "access_token=abc", "connectionId=x"] {
        let mut head = request(Method::Post, "/acp", &[]);
        head.query = query.to_owned();
        assert!(check_request(&profile, &head).is_err(), "{query}");
    }
}

/// One of the three refusals this chunk must keep distinct.  An unsupported
/// consumer HTTP version is `HttpVersionNotAllowed`, which carries
/// `HTTP_UNSUPPORTED_FEATURE` — not the code a route or a header earns, and
/// not the 501 a batch earns.
#[test]
fn only_http_2_is_accepted_and_http_1_1_is_an_unsupported_feature() {
    let profile = profile();
    // HTTP/2 is the accepted version: the identical head passes.
    assert_eq!(
        check_request(&profile, &request(Method::Post, "/acp", &[])),
        Ok(())
    );

    let mut head = request(Method::Post, "/acp", &[]);
    head.http_version = HttpVersion::Http11;
    let error = check_request(&profile, &head).unwrap_err();
    assert_eq!(error, CodecError::HttpVersionNotAllowed);
    assert_eq!(error.code(), HttpErrorCode::UnsupportedFeature);

    // A different rule, and a different code, from a route that is not
    // advertised.
    let route = check_request(&profile, &request(Method::Put, "/acp", &[])).unwrap_err();
    assert_eq!(route, CodecError::RouteNotAllowed);
    assert_ne!(route.code(), HttpErrorCode::UnsupportedFeature);
}

#[test]
fn the_rfd_shorthand_resolves_but_is_not_itself_an_accepted_method() {
    // `docs/acp.md` calls this out by name: the RFD's sequence diagram writes
    // `request_permission`, which is prose, not a method.
    assert_eq!(
        resolve_rfd_shorthand(RFD_PERMISSION_SHORTHAND),
        Some("session/request_permission")
    );
    // The normative name comes from the pinned schema, so a rename upstream
    // fails here rather than passing against a string in this repository.
    assert_eq!(
        resolve_rfd_shorthand(RFD_PERMISSION_SHORTHAND),
        Some(agent_client_protocol::schema::v1::CLIENT_METHOD_NAMES.session_request_permission)
    );

    assert!(is_accepted_method("session/request_permission"));
    assert!(!is_accepted_method(RFD_PERMISSION_SHORTHAND));
    assert!(!is_accepted_method("request_permission"));
    assert_eq!(resolve_rfd_shorthand("session/request_permission"), None);
    for near in [
        "session/requestPermission",
        "session/request-permission",
        "Session/request_permission",
        "session/request_permission ",
        "/session/request_permission",
    ] {
        assert!(!is_accepted_method(near), "{near}");
        assert_eq!(resolve_rfd_shorthand(near), None, "{near}");
    }
}

#[test]
fn the_method_set_is_exact_and_comes_from_the_pinned_schema() {
    let agent = agent_client_protocol::schema::v1::AGENT_METHOD_NAMES;
    let client = agent_client_protocol::schema::v1::CLIENT_METHOD_NAMES;
    let expected = [
        agent.initialize,
        agent.session_new,
        agent.session_load,
        agent.session_prompt,
        agent.session_cancel,
        client.session_update,
        client.session_request_permission,
    ];
    let mut all = methods::all();
    all.sort_unstable();
    let mut wanted: Vec<&str> = expected.to_vec();
    wanted.sort_unstable();
    assert_eq!(all, wanted);
    for method in expected {
        assert!(is_accepted_method(method), "{method}");
    }
    // Methods the pinned schema defines that this export deliberately does not
    // carry.  Each needs a policy decision of its own.
    for method in [
        agent.session_list,
        agent.session_delete,
        agent.session_close,
        agent.session_resume,
        agent.session_set_mode,
        agent.session_set_config_option,
        agent.authenticate,
        agent.logout,
        client.fs_read_text_file,
        client.fs_write_text_file,
        client.terminal_create,
        client.elicitation_create,
    ] {
        assert!(!is_accepted_method(method), "{method}");
    }
    // No prefix or wildcard rule exists.
    for method in [
        "session/",
        "session/new/extra",
        "$/cancel_request",
        "",
        "initialize ",
    ] {
        assert!(!is_accepted_method(method), "{method:?}");
    }
}

#[test]
fn limits_are_finite_ordered_and_bounded() {
    assert!(AcpLimits::new(1, 1, 1).is_ok());
    assert!(
        AcpLimits::new(
            MAX_REQUEST_BODY_LIMIT,
            MAX_JSON_RESPONSE_LIMIT,
            MAX_SSE_RESPONSE_LIMIT
        )
        .is_ok()
    );
    for (request, json, sse) in [
        (0, 1, 1),
        (1, 0, 1),
        (1, 1, 0),
        (MAX_REQUEST_BODY_LIMIT + 1, 1, 1),
        (1, MAX_JSON_RESPONSE_LIMIT + 1, MAX_SSE_RESPONSE_LIMIT),
        (1, 1, MAX_SSE_RESPONSE_LIMIT + 1),
        (1, 2, 1),
    ] {
        assert_eq!(AcpLimits::new(request, json, sse), Err(AcpLimitsError));
    }
    let profile = profile();
    assert_eq!(profile.request.body_limit(), DEFAULT_REQUEST_BODY_LIMIT);
    assert_eq!(profile.response.body_limit(), DEFAULT_SSE_RESPONSE_LIMIT);
    let narrow = AcpProfile::HttpV1
        .policies(AcpLimits::new(1024, 2048, 4096).unwrap())
        .unwrap();
    assert_eq!(narrow.request.body_limit(), 1024);
    assert_eq!(narrow.response.body_limit(), 4096);
}
