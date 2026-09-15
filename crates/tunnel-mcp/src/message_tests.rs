use super::*;
use http::{HeaderName, HeaderValue};

fn map(headers: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

const BASE: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("accept", "application/json, text/event-stream"),
];

fn headers_2026(method: &str, name: Option<&str>) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> =
        BASE.iter().map(|(n, v)| (*n, (*v).to_owned())).collect();
    out.push(("mcp-protocol-version", "2026-07-28".to_owned()));
    out.push(("mcp-method", method.to_owned()));
    if let Some(name) = name {
        out.push(("mcp-name", name.to_owned()));
    }
    out
}

fn to_map(headers: &[(&'static str, String)]) -> HeaderMap {
    let pairs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    map(&pairs)
}

fn call_body(id: &str, name: &str, version: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{{}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"{version}","progressToken":"p1","x-custom":{{"n":1}}}}}}}}"#
    )
    .into_bytes()
}

#[test]
fn a_valid_2026_tools_call_preserves_id_meta_and_bytes() {
    let body = call_body("\"req-1\"", "echo", "2026-07-28");
    let message = validate_post(
        McpProfile::V2026_07_28,
        &to_map(&headers_2026("tools/call", Some("echo"))),
        &body,
    )
    .unwrap();
    assert_eq!(message.kind, MessageKind::Request);
    assert_eq!(message.id, Some(Value::from("req-1")));
    assert_eq!(message.compact, body, "already compact bytes are unchanged");
    assert_eq!(message.progress_token(), Some(&Value::from("p1")));
    // A large integer ID survives exactly in the compact bytes.
    let body = call_body("9007199254740993", "echo", "2026-07-28");
    let message = validate_post(
        McpProfile::V2026_07_28,
        &to_map(&headers_2026("tools/call", Some("echo"))),
        &body,
    )
    .unwrap();
    assert!(
        String::from_utf8(message.compact)
            .unwrap()
            .contains("\"id\":9007199254740993")
    );
    // Base64 sentinel Mcp-Name is decoded before comparison.
    let body = call_body("1", "héllo", "2026-07-28");
    let encoded = format!(
        "=?base64?{}?=",
        base64::engine::general_purpose::STANDARD.encode("héllo")
    );
    assert!(
        validate_post(
            McpProfile::V2026_07_28,
            &to_map(&headers_2026("tools/call", Some(&encoded))),
            &body,
        )
        .is_ok()
    );
}

#[test]
fn the_2026_header_body_rules_reject_mismatches_with_header_mismatch() {
    let profile = McpProfile::V2026_07_28;
    let good = call_body("1", "echo", "2026-07-28");
    let cases: Vec<(Vec<(&'static str, String)>, Vec<u8>, i64)> = vec![
        // Wrong Mcp-Name.
        (
            headers_2026("tools/call", Some("other")),
            good.clone(),
            codes::HEADER_MISMATCH,
        ),
        // Missing Mcp-Name.
        (
            headers_2026("tools/call", None),
            good.clone(),
            codes::HEADER_MISMATCH,
        ),
        // Wrong Mcp-Method.
        (
            headers_2026("tools/list", Some("echo")),
            good.clone(),
            codes::HEADER_MISMATCH,
        ),
        // Body _meta version differs from the header.
        (
            headers_2026("tools/call", Some("echo")),
            call_body("1", "echo", "2025-11-25"),
            codes::HEADER_MISMATCH,
        ),
        // Invalid Base64 in Mcp-Name.
        (
            headers_2026("tools/call", Some("=?base64?!!!?=")),
            good.clone(),
            codes::HEADER_MISMATCH,
        ),
    ];
    for (headers, body, code) in cases {
        let rejection = validate_post(profile, &to_map(&headers), &body).unwrap_err();
        assert_eq!((rejection.status, rejection.code), (400, code));
        assert_eq!(rejection.id, Some(Value::from(1)));
        let text = String::from_utf8(rejection.body()).unwrap();
        assert!(!text.contains("echo") && !text.contains("other"), "{text}");
    }
    // Missing MCP-Protocol-Version on a request.
    let mut headers = headers_2026("tools/call", Some("echo"));
    headers.retain(|(name, _)| *name != "mcp-protocol-version");
    let rejection = validate_post(profile, &to_map(&headers), &good).unwrap_err();
    assert_eq!(rejection.code, codes::HEADER_MISMATCH);
    // Unsupported MCP-Protocol-Version lists the supported revision only.
    let mut headers = headers_2026("tools/call", Some("echo"));
    headers.retain(|(name, _)| *name != "mcp-protocol-version");
    headers.push(("mcp-protocol-version", "2025-11-25".to_owned()));
    let rejection = validate_post(profile, &to_map(&headers), &good).unwrap_err();
    assert_eq!(rejection.code, codes::UNSUPPORTED_PROTOCOL_VERSION);
    assert!(
        String::from_utf8(rejection.body())
            .unwrap()
            .contains(r#""supported":["2026-07-28"]"#)
    );
    // Unrepresentable Mcp-Param value.
    let mut headers = headers_2026("tools/call", Some("echo"));
    headers.push(("mcp-param-x", "=?base64?%%?=".to_owned()));
    assert_eq!(
        validate_post(profile, &to_map(&headers), &good)
            .unwrap_err()
            .code,
        codes::HEADER_MISMATCH
    );
    // A JSON-RPC response from the client is not allowed in this revision.
    let response = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    assert_eq!(
        validate_post(profile, &to_map(&headers_2026("x", None)), response)
            .unwrap_err()
            .code,
        codes::INVALID_REQUEST
    );
    // resources/read compares params.uri; other methods need no Mcp-Name.
    let read = br#"{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///a","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    assert!(
        validate_post(
            profile,
            &to_map(&headers_2026("resources/read", Some("file:///a"))),
            read
        )
        .is_ok()
    );
    let list = br#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    assert!(validate_post(profile, &to_map(&headers_2026("tools/list", None)), list).is_ok());
}

#[test]
fn content_negotiation_and_strict_json_are_enforced_for_both_profiles() {
    for profile in McpProfile::ALL {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let wrong_type = map(&[
            ("content-type", "text/plain"),
            ("accept", "application/json, text/event-stream"),
        ]);
        assert_eq!(
            validate_post(profile, &wrong_type, body)
                .unwrap_err()
                .status,
            415
        );
        let json_only = map(&[
            ("content-type", "application/json"),
            ("accept", "application/json"),
        ]);
        assert_eq!(
            validate_post(profile, &json_only, body).unwrap_err().status,
            406
        );
        let wildcard = map(&[
            ("content-type", "application/json; charset=utf-8"),
            ("accept", "*/*"),
        ]);
        assert!(check_post_headers(&wildcard).is_ok());
        for bad in [
            &br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#[..],
            br#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
            br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            br#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":3}"#,
            br#"{"jsonrpc":"2.0","id":1}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"x"} trailing"#,
            b"not json",
        ] {
            let headers = map(BASE);
            let rejection = validate_post(profile, &headers, bad).unwrap_err();
            assert_eq!(rejection.status, 400, "{profile:?} {bad:?}");
        }
    }
}

#[test]
fn the_2025_profile_requires_its_version_except_on_initialize() {
    let profile = McpProfile::V2025_11_25;
    let init = br#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#;
    assert!(validate_post(profile, &map(BASE), init).is_ok());
    let list = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    assert_eq!(
        validate_post(profile, &map(BASE), list).unwrap_err().code,
        codes::INVALID_REQUEST
    );
    let mut with_version = BASE.to_vec();
    with_version.push(("mcp-protocol-version", "2025-11-25"));
    assert!(validate_post(profile, &map(&with_version), list).is_ok());
    let notification =
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#;
    assert_eq!(
        validate_post(profile, &map(&with_version), notification)
            .unwrap()
            .kind,
        MessageKind::Notification
    );
    let response = br#"{"jsonrpc":"2.0","id":"s-1","result":{}}"#;
    assert_eq!(
        validate_post(profile, &map(&with_version), response)
            .unwrap()
            .kind,
        MessageKind::Response
    );
    let mut wrong = BASE.to_vec();
    wrong.push(("mcp-protocol-version", "2026-07-28"));
    let rejection = validate_post(profile, &map(&wrong), list).unwrap_err();
    assert_eq!(rejection.code, codes::UNSUPPORTED_PROTOCOL_VERSION);
    assert_eq!(rejection.supported, Some("2025-11-25"));
    // GET needs text/event-stream; GET and DELETE are 405 for 2026.
    assert!(validate_get(profile, &map(&[("accept", "text/event-stream")])).is_ok());
    assert_eq!(
        validate_get(profile, &map(&[("accept", "application/json")]))
            .unwrap_err()
            .status,
        406
    );
    assert!(validate_delete(profile, &map(&[])).is_ok());
    assert_eq!(
        validate_get(
            McpProfile::V2026_07_28,
            &map(&[("accept", "text/event-stream")])
        )
        .unwrap_err()
        .status,
        405
    );
    assert_eq!(
        validate_delete(McpProfile::V2026_07_28, &map(&[]))
            .unwrap_err()
            .status,
        405
    );
}
