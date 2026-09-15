//! Path, query, and header ambiguity cases, plus policy construction.

mod common;

use common::*;
use tunnel_http_forward::{
    CodecError, FORBIDDEN_HEADERS, HeaderField, HeaderPolicy, HeaderRule, HttpErrorCode, Method,
    Occurrence, PathRule, PolicyError, QueryPolicy, QueryRule, RequestPolicy, UNSUPPORTED_HEADERS,
    parse_request_head, parse_response_head, validate_headers, validate_path, validate_query,
};

#[test]
fn canonical_paths_accepted() {
    for path in [
        "/",
        "/acp",
        "/v1/events.stream",
        "/a-b_c~d.e/F9",
        "/.well-known",
        "/a..b",
        "/...",
        &format!("/{}", "a".repeat(1023)),
    ] {
        assert_eq!(validate_path(path), Ok(()), "{path}");
    }
}

#[test]
fn ambiguous_paths_rejected() {
    let cases: &[(&str, PathRule)] = &[
        ("", PathRule::Empty),
        ("acp", PathRule::MissingLeadingSlash),
        ("//acp", PathRule::EmptySegment),
        ("/acp/", PathRule::EmptySegment),
        ("/a//b", PathRule::EmptySegment),
        ("/.", PathRule::DotSegment),
        ("/..", PathRule::DotSegment),
        ("/a/./b", PathRule::DotSegment),
        ("/a/../b", PathRule::DotSegment),
        ("/a/..", PathRule::DotSegment),
        ("/a%2fb", PathRule::PercentEscape),
        ("/%2e%2e", PathRule::PercentEscape),
        ("/acp%00", PathRule::PercentEscape),
        ("/a\\b", PathRule::Backslash),
        ("/acp?x=1", PathRule::QueryOrFragmentDelimiter),
        ("/acp#frag", PathRule::QueryOrFragmentDelimiter),
        ("/acp\0", PathRule::Nul),
        ("http://evil/acp", PathRule::DisallowedCharacter),
        ("//evil.example/acp", PathRule::EmptySegment),
        ("/a;b", PathRule::DisallowedCharacter),
        ("/a b", PathRule::DisallowedCharacter),
        ("/a:b", PathRule::DisallowedCharacter),
        ("/a@b", PathRule::DisallowedCharacter),
        ("/a+b", PathRule::DisallowedCharacter),
        ("/caf\u{e9}", PathRule::DisallowedCharacter),
        ("/acp\t", PathRule::DisallowedCharacter),
        ("*", PathRule::DisallowedCharacter),
    ];
    for (path, rule) in cases {
        assert_eq!(validate_path(path), Err(*rule), "{path:?}");
    }
    assert_eq!(
        validate_path(&format!("/{}", "a".repeat(1024))),
        Err(PathRule::TooLong)
    );
}

#[test]
fn path_must_match_an_advertised_route() {
    let json = request_json_with("path", "\"/\"");
    assert_eq!(
        parse_request_head(json.as_bytes(), &request_policy()),
        Err(CodecError::RouteNotAllowed)
    );
    let mut with_root = request_policy();
    with_root.allow_route(Method::Post, "/").unwrap();
    assert!(parse_request_head(json.as_bytes(), &with_root).is_ok());
    // Case differs from the route: no normalization.
    let upper = request_json_with("path", "\"/ACP\"");
    assert_eq!(
        parse_request_head(upper.as_bytes(), &request_policy()),
        Err(CodecError::RouteNotAllowed)
    );
    // Method mismatch for an existing path.
    let put = request_json_with("method", "\"PUT\"");
    assert_eq!(
        parse_request_head(put.as_bytes(), &request_policy()),
        Err(CodecError::RouteNotAllowed)
    );
    let bad = request_json_with("path", "\"/acp/../acp\"");
    let error = parse_request_head(bad.as_bytes(), &request_policy()).unwrap_err();
    assert_eq!(error, CodecError::InvalidPath(PathRule::DotSegment));
    assert_eq!(error.code(), HttpErrorCode::InvalidHead);
}

fn query_policy() -> QueryPolicy {
    request_policy().query
}

#[test]
fn valid_queries_decode_once() {
    let policy = query_policy();
    assert_eq!(validate_query("", &policy), Ok(vec![]));
    assert_eq!(
        validate_query("cursor=abc", &policy),
        Ok(vec![("cursor".into(), "abc".into())])
    );
    assert_eq!(
        validate_query("tag=a&tag=b&cursor=", &policy),
        Ok(vec![
            ("tag".into(), "a".into()),
            ("tag".into(), "b".into()),
            ("cursor".into(), String::new()),
        ])
    );
    // Only the first '=' separates key and value; later '=' is value data
    // (RFC 3986 permits it), so base64 padding is accepted verbatim.
    assert_eq!(
        validate_query("cursor=a=b", &policy),
        Ok(vec![("cursor".into(), "a=b".into())])
    );
    assert_eq!(
        validate_query("cursor=YWJjZA==&tag=YQ%3D%3D", &policy),
        Ok(vec![
            ("cursor".into(), "YWJjZA==".into()),
            ("tag".into(), "YQ==".into()),
        ])
    );
    assert_eq!(
        validate_query("cursor=", &policy),
        Ok(vec![("cursor".into(), String::new())])
    );
    assert_eq!(
        validate_query("cursor", &policy),
        Ok(vec![("cursor".into(), String::new())])
    );
    // Decoded exactly once: %2541 stays "%41", not "A".
    assert_eq!(
        validate_query("cursor=%2541", &policy),
        Ok(vec![("cursor".into(), "%41".into())])
    );
    // Encoded delimiters inside a value are data.
    assert_eq!(
        validate_query("cursor=a%26tag%3Dx", &policy),
        Ok(vec![("cursor".into(), "a&tag=x".into())])
    );
    assert_eq!(
        validate_query("cursor=caf%C3%A9", &policy),
        Ok(vec![("cursor".into(), "caf\u{e9}".into())])
    );
}

#[test]
fn ambiguous_queries_rejected() {
    let policy = query_policy();
    let cases: &[(&str, QueryRule)] = &[
        ("x=1", QueryRule::UnrecognizedKey),
        ("cursor=1&cursor=2", QueryRule::DuplicateKey),
        ("cursor=1&", QueryRule::EmptyPair),
        ("&cursor=1", QueryRule::EmptyPair),
        ("cursor=1&&tag=2", QueryRule::EmptyPair),
        ("=1", QueryRule::EmptyKey),
        ("cursor=a+b", QueryRule::DisallowedCharacter),
        ("cursor=a;tag=b", QueryRule::DisallowedCharacter),
        ("cursor=a b", QueryRule::DisallowedCharacter),
        ("cursor=a#b", QueryRule::DisallowedCharacter),
        ("cursor=\"", QueryRule::DisallowedCharacter),
        ("cursor=caf\u{e9}", QueryRule::DisallowedCharacter),
        ("cursor=%", QueryRule::InvalidPercentEscape),
        ("cursor=%4", QueryRule::InvalidPercentEscape),
        ("cursor=%GG", QueryRule::InvalidPercentEscape),
        ("cursor=%%41", QueryRule::InvalidPercentEscape),
        ("cursor=%FF", QueryRule::InvalidUtf8),
        ("cursor=%C3", QueryRule::InvalidUtf8),
        ("cursor=%ED%A0%80", QueryRule::InvalidUtf8),
        ("cursor=%00", QueryRule::DecodedControl),
        ("cursor=%0D%0A", QueryRule::DecodedControl),
        ("cursor=%7F", QueryRule::DecodedControl),
        ("cursor=%C2%85", QueryRule::DecodedControl),
        ("%63ursor=1", QueryRule::EncodedKey),
        ("cursor%3D1", QueryRule::EncodedKey),
        ("access_token=abc", QueryRule::CredentialParameter),
        ("Access_Token=abc", QueryRule::CredentialParameter),
        ("api_key=abc", QueryRule::CredentialParameter),
        ("%74oken=abc", QueryRule::CredentialParameter),
        ("Cursor=1", QueryRule::UnrecognizedKey),
    ];
    for (query, rule) in cases {
        assert_eq!(validate_query(query, &policy), Err(*rule), "{query:?}");
    }
}

#[test]
fn query_limits() {
    let policy = query_policy();
    assert_eq!(
        validate_query("cursor=1", &QueryPolicy::new()),
        Err(QueryRule::NotPermitted)
    );
    let pairs32 = vec!["tag=a"; 32].join("&");
    assert_eq!(validate_query(&pairs32, &policy).unwrap().len(), 32);
    let pairs33 = vec!["tag=a"; 33].join("&");
    assert_eq!(
        validate_query(&pairs33, &policy),
        Err(QueryRule::TooManyPairs)
    );
    let at_limit = format!("cursor={}", "a".repeat(2048 - 7));
    assert_eq!(at_limit.len(), 2048);
    assert!(validate_query(&at_limit, &policy).is_ok());
    let over = format!("{at_limit}a");
    assert_eq!(validate_query(&over, &policy), Err(QueryRule::TooLong));

    let json = request_json_with("query", "\"cursor=1&cursor=2\"");
    assert_eq!(
        parse_request_head(json.as_bytes(), &request_policy()),
        Err(CodecError::InvalidQuery(QueryRule::DuplicateKey))
    );
    // A query is never re-encoded: the accepted original bytes are preserved.
    let json = request_json_with("query", "\"cursor=%2541&tag=x\"");
    let head = parse_request_head(json.as_bytes(), &request_policy()).unwrap();
    assert_eq!(head.query, "cursor=%2541&tag=x");
    // Leading `?` is not part of the component.
    let json = request_json_with("query", "\"?cursor=1\"");
    assert_eq!(
        parse_request_head(json.as_bytes(), &request_policy()),
        Err(CodecError::InvalidQuery(QueryRule::UnrecognizedKey))
    );
}

#[test]
fn query_policy_construction_rejects_credentials() {
    let mut policy = QueryPolicy::new();
    assert_eq!(
        policy.allow("token", Occurrence::Singleton),
        Err(PolicyError::CredentialQueryParameter)
    );
    assert_eq!(
        policy.allow("PASSWORD", Occurrence::Singleton),
        Err(PolicyError::CredentialQueryParameter)
    );
    assert_eq!(
        policy.allow("a=b", Occurrence::Singleton),
        Err(PolicyError::InvalidQueryKey)
    );
    assert_eq!(
        policy.allow("", Occurrence::Singleton),
        Err(PolicyError::InvalidQueryKey)
    );
    policy.allow("page", Occurrence::Singleton).unwrap();
    assert_eq!(
        policy.allow("page", Occurrence::Repeatable),
        Err(PolicyError::DuplicateEntry)
    );
}

fn fields(pairs: &[(&str, &str)]) -> Vec<HeaderField> {
    pairs
        .iter()
        .map(|(name, value)| HeaderField::new(*name, *value))
        .collect()
}

fn headers_policy() -> HeaderPolicy {
    request_policy().headers
}

#[test]
fn header_names_and_values() {
    let policy = headers_policy();
    let ok = |pairs: &[(&str, &str)]| validate_headers(&fields(pairs), &policy);
    assert_eq!(ok(&[("content-type", "application/json")]), Ok(()));
    assert_eq!(ok(&[("accept", "")]), Ok(()));
    assert_eq!(ok(&[("accept", "a\tb")]), Ok(()));
    assert_eq!(ok(&[("accept", "~!@#$%^&*()")]), Ok(()));
    let cases: &[(&str, &str, HeaderRule)] = &[
        ("", "x", HeaderRule::NameLength),
        ("Content-Type", "x", HeaderRule::NameCharacter),
        ("content type", "x", HeaderRule::NameCharacter),
        ("content-type:", "x", HeaderRule::NameCharacter),
        ("content\u{e9}", "x", HeaderRule::NameCharacter),
        ("(accept)", "x", HeaderRule::NameCharacter),
        ("accept", "a\rb", HeaderRule::ValueCharacter),
        ("accept", "a\nb", HeaderRule::ValueCharacter),
        ("accept", "a\r\n b", HeaderRule::ValueCharacter),
        ("accept", "a\0b", HeaderRule::ValueCharacter),
        ("accept", "a\u{1}b", HeaderRule::ValueCharacter),
        ("accept", "a\u{7f}b", HeaderRule::ValueCharacter),
        ("accept", "caf\u{e9}", HeaderRule::ValueCharacter),
        ("accept", " a", HeaderRule::ValueBoundaryWhitespace),
        ("accept", "a ", HeaderRule::ValueBoundaryWhitespace),
        ("accept", "\ta", HeaderRule::ValueBoundaryWhitespace),
        ("accept", " ", HeaderRule::ValueBoundaryWhitespace),
        ("x-unknown", "a", HeaderRule::NotAllowed),
    ];
    for (name, value, rule) in cases {
        assert_eq!(ok(&[(name, value)]), Err(*rule), "{name:?}: {value:?}");
    }
    let name128 = "a".repeat(128);
    let name129 = "a".repeat(129);
    assert_eq!(ok(&[(&name128, "x")]), Err(HeaderRule::NotAllowed));
    assert_eq!(ok(&[(&name129, "x")]), Err(HeaderRule::NameLength));
    let value4096 = "v".repeat(4096);
    let value4097 = "v".repeat(4097);
    assert_eq!(ok(&[("accept", &value4096)]), Ok(()));
    assert_eq!(ok(&[("accept", &value4097)]), Err(HeaderRule::ValueTooLong));
}

#[test]
fn header_counts_and_totals() {
    let policy = headers_policy();
    let repeated = |count: usize, value: &str| {
        let list: Vec<HeaderField> = (0..count)
            .map(|_| HeaderField::new("cache-control", value))
            .collect();
        validate_headers(&list, &policy)
    };
    assert_eq!(repeated(32, "x"), Ok(()));
    assert_eq!(repeated(33, "x"), Err(HeaderRule::TooManyFields));
    // "cache-control" is 13 bytes.  2 × (13 + 4083) = 8192 exactly.
    assert_eq!(repeated(2, &"v".repeat(4083)), Ok(()));
    assert_eq!(repeated(2, &"v".repeat(4084)), Err(HeaderRule::TotalBytes));
    let mut many = vec![HeaderField::new("cache-control", "v".repeat(4000)); 2];
    many.push(HeaderField::new("accept", "v".repeat(200)));
    assert_eq!(
        validate_headers(&many, &policy),
        Err(HeaderRule::TotalBytes)
    );
}

#[test]
fn singleton_and_repeatable_fields() {
    let policy = headers_policy();
    assert_eq!(
        validate_headers(
            &fields(&[
                ("content-type", "a"),
                ("accept", "b"),
                ("content-type", "a")
            ]),
            &policy
        ),
        Err(HeaderRule::RepeatedSingleton)
    );
    assert_eq!(
        validate_headers(
            &fields(&[("cache-control", "no-store"), ("cache-control", "no-cache")]),
            &policy
        ),
        Ok(())
    );
}

#[test]
fn forbidden_headers_are_classified_before_the_allowlist_and_refused_by_policy() {
    // The runtime guard with an allowlist that names these headers is covered
    // by the unit test in src/validate.rs, which can bypass `allow`.
    let everything = headers_policy();
    let mut names: Vec<String> = FORBIDDEN_HEADERS.iter().map(|s| (*s).to_owned()).collect();
    names.extend(
        [
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-agent-tunnel-tenant",
            "x-agent-tunnel-",
        ]
        .map(str::to_owned),
    );
    for required in [
        "host",
        "connection",
        "keep-alive",
        "proxy-connection",
        "content-length",
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "forwarded",
    ] {
        assert!(FORBIDDEN_HEADERS.contains(&required), "{required}");
    }
    for name in &names {
        let result = validate_headers(&fields(&[(name, "x")]), &everything);
        assert_eq!(result, Err(HeaderRule::Forbidden), "{name}");
        let mut policy = HeaderPolicy::new();
        assert_eq!(
            policy.allow(name, Occurrence::Singleton),
            Err(PolicyError::ForbiddenHeader),
            "{name}"
        );
    }
    assert_eq!(UNSUPPORTED_HEADERS.len(), 5);
    for name in UNSUPPORTED_HEADERS.iter().copied() {
        assert!(["transfer-encoding", "te", "trailer", "upgrade", "expect"].contains(&name));
        assert!(UNSUPPORTED_HEADERS.contains(&name));
        assert_eq!(
            validate_headers(&fields(&[(name, "x")]), &everything),
            Err(HeaderRule::Unsupported),
            "{name}"
        );
        assert_eq!(
            CodecError::InvalidHeader(HeaderRule::Unsupported).code(),
            HttpErrorCode::UnsupportedFeature
        );
        let mut policy = HeaderPolicy::new();
        assert_eq!(
            policy.allow(name, Occurrence::Repeatable),
            Err(PolicyError::UnsupportedHeader),
            "{name}"
        );
    }
    // A connection-nominated field cannot ride along: connection itself fails.
    assert_eq!(
        validate_headers(
            &fields(&[("connection", "accept"), ("accept", "x")]),
            &everything
        ),
        Err(HeaderRule::Forbidden)
    );
    // Uppercase spellings of forbidden names fail the lowercase rule first.
    assert_eq!(
        validate_headers(&fields(&[("Authorization", "x")]), &everything),
        Err(HeaderRule::NameCharacter)
    );
}

#[test]
fn response_direction_uses_its_own_allowlist() {
    let json = r#"{"status":200,"headers":[["acp-session-id","s"]],"body_length":null}"#;
    assert_eq!(
        parse_response_head(json.as_bytes(), &response_policy(), Method::Post),
        Err(CodecError::InvalidHeader(HeaderRule::NotAllowed))
    );
    let json = r#"{"status":200,"headers":[["set-cookie","a=b"]],"body_length":null}"#;
    assert_eq!(
        parse_response_head(json.as_bytes(), &response_policy(), Method::Post),
        Err(CodecError::InvalidHeader(HeaderRule::Forbidden))
    );
    let json = r#"{"status":200,"headers":[["cache-control","no-store"],["cache-control","private"]],"body_length":null}"#;
    assert!(parse_response_head(json.as_bytes(), &response_policy(), Method::Post).is_ok());
}

#[test]
fn route_policy_construction() {
    let mut policy = RequestPolicy::new(10).unwrap();
    assert_eq!(
        policy.allow_route(Method::Get, "/a/../b"),
        Err(PolicyError::InvalidRoutePath(PathRule::DotSegment))
    );
    policy.allow_route(Method::Get, "/a").unwrap();
    assert_eq!(
        policy.allow_route(Method::Get, "/a"),
        Err(PolicyError::DuplicateEntry)
    );
    let mut headers = HeaderPolicy::new();
    assert_eq!(
        headers.allow("Content-Type", Occurrence::Singleton),
        Err(PolicyError::InvalidHeaderName)
    );
}
