//! Per-profile allowlist tests: every pinned route and header is accepted by
//! the real codec validator, and neighbouring names, methods and paths are
//! rejected.

use super::*;
use tunnel_http_forward::{
    CodecError, HeaderField, HeaderRule, RequestHead, ResponseHead, encode_request_head,
    encode_response_head,
};

fn request(method: Method, path: &str, headers: &[(&str, &str)]) -> RequestHead {
    RequestHead {
        method,
        path: path.to_owned(),
        query: String::new(),
        http_version: HttpVersion::Http11,
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

const NEIGHBOUR_REQUEST_HEADERS: &[&str] = &[
    "origin",
    "user-agent",
    "accept-encoding",
    "accept-language",
    "content-encoding",
    "cache-control",
    "if-none-match",
    "mcp-protocol-versions",
    "mcp-session",
    "mcp-sessionid",
    "x-mcp-header",
    "mcp-params-x",
    "mcp-param",
    "www-authenticate",
    "sec-fetch-mode",
];

const NEIGHBOUR_RESPONSE_HEADERS: &[&str] = &[
    "www-authenticate",
    "location",
    "content-encoding",
    "etag",
    "server",
    "date",
    "access-control-allow-origin",
    "mcp-protocol-version",
    "mcp-method",
    "retry-after",
    "vary",
];

#[test]
fn profile_ids_and_versions_are_pinned_and_distinct() {
    assert_eq!(McpProfile::V2026_07_28.id(), "mcp-2026-07-28");
    assert_eq!(McpProfile::V2025_11_25.id(), "mcp-2025-11-25");
    assert_eq!(McpProfile::V2026_07_28.protocol_version(), "2026-07-28");
    assert_eq!(McpProfile::V2025_11_25.protocol_version(), "2025-11-25");
    for profile in McpProfile::ALL {
        assert_eq!(McpProfile::parse_id(profile.id()), Some(profile));
    }
    for bad in [
        "mcp",
        "mcp-2025-06-18",
        "MCP-2026-07-28",
        "mcp-2026-07-28 ",
        "2026-07-28",
    ] {
        assert_eq!(McpProfile::parse_id(bad), None, "{bad}");
    }
    let current = McpProfile::V2026_07_28
        .policies(McpLimits::default())
        .unwrap();
    let legacy = McpProfile::V2025_11_25
        .policies(McpLimits::default())
        .unwrap();
    assert_ne!(current.request, legacy.request);
    assert_ne!(current.response, legacy.response);
}

#[test]
fn the_2026_profile_accepts_exactly_post_mcp_and_its_metadata_headers() {
    let profile = McpProfile::V2026_07_28
        .policies(McpLimits::default())
        .unwrap();
    let all = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "echo"),
        ("mcp-param-region", "us-west1"),
        ("mcp-param-text", "=?base64?IHBhZGRlZCA=?="),
    ];
    assert_eq!(
        check_request(&profile, &request(Method::Post, "/mcp", &all)),
        Ok(())
    );
    for (name, value) in all {
        assert_eq!(
            check_request(&profile, &request(Method::Post, "/mcp", &[(name, value)])),
            Ok(()),
            "{name}"
        );
    }
    // Legacy-only mechanisms are not part of this revision.
    for name in ["mcp-session-id", "last-event-id"] {
        assert_eq!(
            check_request(&profile, &request(Method::Post, "/mcp", &[(name, "x")])),
            Err(CodecError::InvalidHeader(HeaderRule::NotAllowed)),
            "{name}"
        );
    }
    for method in [
        Method::Get,
        Method::Delete,
        Method::Put,
        Method::Head,
        Method::Options,
        Method::Patch,
    ] {
        assert_eq!(
            check_request(&profile, &request(method, "/mcp", &[])),
            Err(CodecError::RouteNotAllowed),
            "{method:?}"
        );
    }
    for response in ["content-type", "cache-control", "x-accel-buffering"] {
        assert_eq!(
            check_response(&profile, &[(response, "x")]),
            Ok(()),
            "{response}"
        );
    }
    assert_eq!(
        check_response(&profile, &[("mcp-session-id", "x")]),
        Err(CodecError::InvalidHeader(HeaderRule::NotAllowed))
    );
}

#[test]
fn the_2025_profile_accepts_post_get_delete_and_session_headers() {
    let profile = McpProfile::V2025_11_25
        .policies(McpLimits::default())
        .unwrap();
    let all = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", "2025-11-25"),
        ("mcp-session-id", "0123abcd"),
        ("last-event-id", "7"),
    ];
    for method in [Method::Post, Method::Get, Method::Delete] {
        assert_eq!(
            check_request(&profile, &request(method, "/mcp", &all)),
            Ok(()),
            "{method:?}"
        );
    }
    for method in [Method::Put, Method::Head, Method::Options, Method::Patch] {
        assert_eq!(
            check_request(&profile, &request(method, "/mcp", &[])),
            Err(CodecError::RouteNotAllowed),
            "{method:?}"
        );
    }
    // 2026 per-request metadata headers are not part of this revision.
    for name in ["mcp-method", "mcp-name", "mcp-param-region"] {
        assert_eq!(
            check_request(&profile, &request(Method::Post, "/mcp", &[(name, "x")])),
            Err(CodecError::InvalidHeader(HeaderRule::NotAllowed)),
            "{name}"
        );
    }
    for response in [
        "content-type",
        "cache-control",
        "x-accel-buffering",
        "mcp-session-id",
    ] {
        assert_eq!(
            check_response(&profile, &[(response, "x")]),
            Ok(()),
            "{response}"
        );
    }
}

#[test]
fn neighbouring_paths_queries_headers_and_credentials_are_rejected_for_both_profiles() {
    for profile_id in McpProfile::ALL {
        let profile = profile_id.policies(McpLimits::default()).unwrap();
        for path in [
            "/",
            "/mcp/",
            "/mcpx",
            "/MCP",
            "/mcp/tools",
            "/v1/mcp",
            "/mc",
        ] {
            let head = request(Method::Post, path, &[]);
            assert!(
                check_request(&profile, &head).is_err(),
                "{profile_id:?} {path}"
            );
        }
        let mut with_query = request(Method::Post, "/mcp", &[]);
        with_query.query = "session=1".to_owned();
        assert!(check_request(&profile, &with_query).is_err());
        for name in NEIGHBOUR_REQUEST_HEADERS {
            assert_eq!(
                check_request(&profile, &request(Method::Post, "/mcp", &[(name, "x")])),
                Err(CodecError::InvalidHeader(HeaderRule::NotAllowed)),
                "{profile_id:?} {name}"
            );
        }
        for name in [
            "authorization",
            "cookie",
            "host",
            "x-forwarded-for",
            "x-agent-tunnel-tenant",
        ] {
            assert_eq!(
                check_request(&profile, &request(Method::Post, "/mcp", &[(name, "x")])),
                Err(CodecError::InvalidHeader(HeaderRule::Forbidden)),
                "{profile_id:?} {name}"
            );
        }
        for name in NEIGHBOUR_RESPONSE_HEADERS {
            if profile_id
                .response_headers()
                .iter()
                .any(|(allowed, _)| allowed == name)
            {
                continue;
            }
            assert_eq!(
                check_response(&profile, &[(name, "x")]),
                Err(CodecError::InvalidHeader(HeaderRule::NotAllowed)),
                "{profile_id:?} {name}"
            );
        }
        // Every pinned singleton rejects a repeat.
        for (name, _) in profile_id.request_headers() {
            assert_eq!(
                check_request(
                    &profile,
                    &request(Method::Post, "/mcp", &[(name, "a"), (name, "b")])
                ),
                Err(CodecError::InvalidHeader(HeaderRule::RepeatedSingleton)),
                "{profile_id:?} {name}"
            );
        }
        assert_eq!(profile.request.body_limit(), DEFAULT_REQUEST_BODY_LIMIT);
        assert_eq!(profile.response.body_limit(), DEFAULT_SSE_RESPONSE_LIMIT);
    }
}

#[test]
fn limits_are_finite_ordered_and_bounded() {
    assert!(McpLimits::new(1, 1, 1).is_ok());
    assert!(
        McpLimits::new(
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
        assert_eq!(McpLimits::new(request, json, sse), Err(McpLimitsError));
    }
    let limits = McpLimits::new(1024, 2048, 4096).unwrap();
    let profile = McpProfile::V2026_07_28.policies(limits).unwrap();
    assert_eq!(profile.request.body_limit(), 1024);
    assert_eq!(profile.response.body_limit(), 4096);
}
