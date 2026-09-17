//! Message-validation tests.
//!
//! Every case drives `parse_message` / `validate_*` and asserts **the rule and
//! its code**, never merely that something errored.  "Refused" without a
//! reason would pass for a batch that was rejected for being malformed, which
//! is exactly the evidence this chunk is not allowed to produce.
//!
//! The JSON bodies are synthetic, built from the field shapes in
//! `docs/acp.md`.  No agent, client or server is involved.

use super::*;
use http::{HeaderMap, HeaderValue};

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn json_post() -> HeaderMap {
    headers(&[("content-type", "application/json")])
}

fn json_post_on(connection: &str) -> HeaderMap {
    headers(&[
        ("content-type", "application/json"),
        ("acp-connection-id", connection),
    ])
}

fn rule(error: &AcpRejection) -> (AcpRule, u16, i64) {
    (error.rule, error.status, error.code)
}

// --------------------------------------------------------------- the batch

/// The first of the three refusals this chunk must keep distinct.
#[test]
fn a_batch_is_refused_as_a_batch_with_501_and_its_own_code() {
    let batch =
        br#"[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}]"#;
    let error = parse_message(batch).unwrap_err();
    assert_eq!(
        rule(&error),
        (AcpRule::BatchNotSupported, 501, codes::BATCH_NOT_SUPPORTED)
    );
}

/// A batch whose contents are *also* wrong is still refused for being a
/// batch.  Without this the 501 could be an accident of parse order.
#[test]
fn a_malformed_batch_is_still_refused_for_being_a_batch() {
    for body in [
        &b"[]"[..],
        b"[",
        b"[{]",
        b"[1,2,3]",
        b"  \n\t [ {\"jsonrpc\":\"1.0\"} ]",
        br#"[{"jsonrpc":"2.0","id":1,"id":2,"method":"initialize"}]"#,
    ] {
        let error = parse_message(body).unwrap_err();
        assert_eq!(
            error.rule,
            AcpRule::BatchNotSupported,
            "{}",
            String::from_utf8_lossy(body)
        );
        assert_eq!(error.status, 501);
    }
}

/// And a non-batch malformed body is **not** given the batch's answer.
#[test]
fn a_malformed_object_is_not_refused_as_a_batch() {
    for (body, expected) in [
        (&b"{"[..], AcpRule::NotStrictJson),
        (
            b"{\"jsonrpc\":\"2.0\",\"jsonrpc\":\"2.0\"}",
            AcpRule::NotStrictJson,
        ),
        (b"\"a string\"", AcpRule::NotJsonRpcMessage),
        (b"7", AcpRule::NotJsonRpcMessage),
        (b"null", AcpRule::NotJsonRpcMessage),
        (b"", AcpRule::NotJsonRpcMessage),
        (b"{} {}", AcpRule::NotStrictJson),
    ] {
        let error = parse_message(body).unwrap_err();
        assert_eq!(error.rule, expected, "{}", String::from_utf8_lossy(body));
        assert_ne!(error.status, 501);
        assert_ne!(error.code, codes::BATCH_NOT_SUPPORTED);
    }
}

// ----------------------------------------------------- the strict envelope

#[test]
fn a_strict_v1_request_notification_and_response_are_accepted() {
    let request = br#"{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{}}}"#;
    let parsed = parse_message(request).unwrap();
    assert_eq!(parsed.kind, MessageKind::Request);
    assert!(parsed.is_initialize());
    assert_eq!(parsed.method.as_deref(), Some("initialize"));

    let notification =
        br#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"session-demo"}}"#;
    let parsed = parse_message(notification).unwrap();
    assert_eq!(parsed.kind, MessageKind::Notification);
    assert_eq!(parsed.id, None);
    assert_eq!(parsed.session_id(), Some("session-demo"));

    let response =
        br#"{"jsonrpc":"2.0","id":"permission-1","result":{"outcome":{"outcome":"selected","optionId":"permit-one"}}}"#;
    let parsed = parse_message(response).unwrap();
    assert_eq!(parsed.kind, MessageKind::Response);
    assert_eq!(parsed.method, None);
}

#[test]
fn the_jsonrpc_member_must_be_exactly_2_0() {
    for body in [
        &br#"{"id":1,"method":"initialize"}"#[..],
        br#"{"jsonrpc":"1.0","id":1,"method":"initialize"}"#,
        br#"{"jsonrpc":2.0,"id":1,"method":"initialize"}"#,
        br#"{"jsonrpc":"2.0 ","id":1,"method":"initialize"}"#,
        br#"{"jsonrpc":null,"id":1,"method":"initialize"}"#,
    ] {
        let error = parse_message(body).unwrap_err();
        assert_eq!(
            rule(&error),
            (AcpRule::JsonRpcVersion, 400, codes::INVALID_REQUEST),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn an_id_must_be_a_string_or_an_integer() {
    for good in [
        &br#"{"jsonrpc":"2.0","id":"init-1","method":"initialize"}"#[..],
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        br#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#,
        br#"{"jsonrpc":"2.0","id":-1,"method":"initialize"}"#,
    ] {
        assert!(
            parse_message(good).is_ok(),
            "{}",
            String::from_utf8_lossy(good)
        );
    }
    for bad in [
        &br#"{"jsonrpc":"2.0","id":1.5,"method":"initialize"}"#[..],
        br#"{"jsonrpc":"2.0","id":1e3,"method":"initialize"}"#,
        br#"{"jsonrpc":"2.0","id":true,"method":"initialize"}"#,
        br#"{"jsonrpc":"2.0","id":["a"],"method":"initialize"}"#,
        br#"{"jsonrpc":"2.0","id":{"a":1},"method":"initialize"}"#,
    ] {
        let error = parse_message(bad).unwrap_err();
        assert_eq!(
            rule(&error),
            (AcpRule::RequestId, 400, codes::INVALID_REQUEST),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    // A JSON `null` id is the "unknown id" of a JSON-RPC error reply.  It is
    // not a correlation value a client may send, and it is refused by the
    // id rule rather than being read as an absent id — which would have
    // silently turned a request into a notification.
    let error = parse_message(br#"{"jsonrpc":"2.0","id":null,"method":"initialize"}"#).unwrap_err();
    assert_eq!(error.rule, AcpRule::RequestId);
}

/// ACP v1 has no positional parameters: every method takes an object, and an
/// `Acp-Session-Id` header can only be reconciled with an object body.
#[test]
fn params_must_be_an_object() {
    assert!(
        parse_message(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#).is_ok()
    );
    for bad in [
        &br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":[1,2]}"#[..],
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":[]}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":"x"}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":null}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":7}"#,
    ] {
        let error = parse_message(bad).unwrap_err();
        assert_eq!(
            rule(&error),
            (AcpRule::NotJsonRpcMessage, 400, codes::INVALID_REQUEST),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// A body with `escape` spliced in where a JSON `\` escape belongs.  Built
/// byte by byte so that no Rust-level escape processing can quietly change
/// what the scanner is handed.
fn body_with_escape(escape: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":\"");
    body.extend_from_slice(escape.as_bytes());
    body.extend_from_slice(b"\",\"method\":\"initialize\"}");
    body
}

const BACKSLASH: u8 = 0x5c;

#[test]
fn strictness_beyond_serde_is_enforced() {
    // Duplicate member names, written plainly.
    let error =
        parse_message(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","id":2}"#).unwrap_err();
    assert_eq!(error.rule, AcpRule::NotStrictJson);

    // Duplicate member names where one spelling is escaped: the first key
    // is written with a unicode escape for its `i` and so unescapes to `id`
    // as well.  serde_json's map would keep the last one silently.
    let mut escaped_key = Vec::new();
    escaped_key.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"");
    escaped_key.push(BACKSLASH);
    escaped_key.extend_from_slice(b"u0069d\":1,\"id\":2,\"method\":\"initialize\"}");
    assert_eq!(
        parse_message(&escaped_key).unwrap_err().rule,
        AcpRule::NotStrictJson
    );

    // Invalid UTF-8.
    assert_eq!(
        parse_message(&[b'{', 0xff, b'}']).unwrap_err().rule,
        AcpRule::NotStrictJson
    );

    // A lone surrogate escape is refused, never repaired.
    let mut lone = String::from(char::from(BACKSLASH));
    lone.push_str("ud800");
    assert_eq!(
        parse_message(&body_with_escape(&lone)).unwrap_err().rule,
        AcpRule::NotStrictJson
    );

    // A raw control character inside a string.
    assert_eq!(
        parse_message(b"{\"jsonrpc\":\"2.0\",\"id\":\"a\nb\",\"method\":\"initialize\"}")
            .unwrap_err()
            .rule,
        AcpRule::NotStrictJson
    );

    // A well-formed surrogate pair is accepted, and the compact copy keeps the
    // original escapes rather than folding them to the scalar.
    let mut pair = String::from(char::from(BACKSLASH));
    pair.push_str("ud83d");
    pair.push(char::from(BACKSLASH));
    pair.push_str("ude00");
    let parsed = parse_message(&body_with_escape(&pair)).unwrap();
    assert!(String::from_utf8(parsed.compact).unwrap().contains(&pair));
}

#[test]
fn the_compact_copy_drops_only_insignificant_whitespace() {
    let body = b"{ \"jsonrpc\" : \"2.0\" ,\n  \"id\" : 1 ,\n  \"method\" : \"initialize\" }";
    let parsed = parse_message(body).unwrap();
    assert_eq!(
        parsed.compact,
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#
    );
}

#[test]
fn nesting_deeper_than_the_bound_is_refused() {
    let mut body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":"#.to_vec();
    let depth = crate::json::MAX_DEPTH + 4;
    body.extend(std::iter::repeat_n(b'[', depth));
    body.extend(std::iter::repeat_n(b']', depth));
    body.push(b'}');
    // `params` must be an object, so use a deep object instead.
    let mut deep = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":"#.to_vec();
    for _ in 0..depth {
        deep.extend_from_slice(br#"{"a":"#);
    }
    deep.extend_from_slice(b"1");
    deep.extend(std::iter::repeat_n(b'}', depth));
    deep.push(b'}');
    assert_eq!(
        parse_message(&deep).unwrap_err().rule,
        AcpRule::NotStrictJson
    );
}

// ----------------------------------------------- content negotiation rules

#[test]
fn a_post_must_be_application_json() {
    assert_eq!(check_post_content_type(&json_post()), Ok(()));
    assert_eq!(
        check_post_content_type(&headers(&[(
            "content-type",
            "application/json; charset=utf-8"
        )])),
        Ok(())
    );
    for value in [
        "text/plain",
        "application/jsonl",
        "text/event-stream",
        "application/json-rpc",
    ] {
        let error = check_post_content_type(&headers(&[("content-type", value)])).unwrap_err();
        assert_eq!(
            rule(&error),
            (AcpRule::ContentType, 415, codes::INVALID_REQUEST),
            "{value}"
        );
    }
    let error = check_post_content_type(&HeaderMap::new()).unwrap_err();
    assert_eq!(error.rule, AcpRule::ContentType);
}

#[test]
fn a_get_must_accept_the_event_stream_and_name_its_connection() {
    assert_eq!(
        validate_get(&headers(&[
            ("accept", "text/event-stream"),
            ("acp-connection-id", "connection-demo"),
        ])),
        Ok(())
    );
    let error = validate_get(&headers(&[
        ("accept", "application/json"),
        ("acp-connection-id", "connection-demo"),
    ]))
    .unwrap_err();
    assert_eq!(rule(&error), (AcpRule::Accept, 406, codes::INVALID_REQUEST));

    let error = validate_get(&headers(&[("accept", "text/event-stream")])).unwrap_err();
    assert_eq!(
        rule(&error),
        (
            AcpRule::ConnectionHeaderRequired,
            400,
            codes::HEADER_MISMATCH
        )
    );
}

#[test]
fn a_delete_must_name_its_connection() {
    assert_eq!(
        validate_delete(&headers(&[("acp-connection-id", "connection-demo")])),
        Ok(())
    );
    assert_eq!(
        validate_delete(&HeaderMap::new()).unwrap_err().rule,
        AcpRule::ConnectionHeaderRequired
    );
}

// ------------------------------------------------------ version negotiation

/// The second of the three refusals this chunk must keep distinct.
#[test]
fn protocol_version_2_is_refused_by_its_own_rule_with_its_own_code() {
    assert_eq!(negotiate_protocol_version(&serde_json::json!(1)), Ok(1));

    let error = negotiate_protocol_version(&serde_json::json!(2)).unwrap_err();
    assert_eq!(
        rule(&error),
        (
            AcpRule::UnsupportedProtocolVersion,
            400,
            codes::UNSUPPORTED_PROTOCOL_VERSION
        )
    );
    assert_eq!(error.supported, Some(1));
    // It is neither the batch's answer nor an unsupported-feature answer.
    assert_ne!(error.status, 501);
    assert_ne!(error.code, codes::BATCH_NOT_SUPPORTED);
    let body = String::from_utf8(error.body()).unwrap();
    assert!(body.contains("\"supported\":[1]"), "{body}");

    for version in [0u64, 3, 65535] {
        let error = negotiate_protocol_version(&serde_json::json!(version)).unwrap_err();
        assert_eq!(error.rule, AcpRule::UnsupportedProtocolVersion, "{version}");
    }
    // A shape failure is a different rule again: it is not a version this
    // export could ever support, and it is not the v2 draft either.
    for value in [
        serde_json::json!("1"),
        serde_json::json!(1.0),
        serde_json::json!(-1),
        serde_json::json!(70000),
        serde_json::json!(null),
        serde_json::json!({"major": 1}),
    ] {
        let error = negotiate_protocol_version(&value).unwrap_err();
        assert_eq!(error.rule, AcpRule::ProtocolVersionShape, "{value}");
    }
}

#[test]
fn an_initialize_negotiates_its_version_in_both_directions() {
    let request = parse_message(
        br#"{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{}}}"#,
    )
    .unwrap();
    assert_eq!(check_initialize_version(&request), Ok(1));

    let v2 = parse_message(
        br#"{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":2,"clientCapabilities":{}}}"#,
    )
    .unwrap();
    let error = check_initialize_version(&v2).unwrap_err();
    assert_eq!(error.rule, AcpRule::UnsupportedProtocolVersion);
    assert_eq!(error.id, Some(serde_json::json!("init-1")));

    // A result that claims a version this bridge does not speak is refused
    // the same way: the agent does not get to raise the version either.
    let result = parse_message(
        br#"{"jsonrpc":"2.0","id":"init-1","result":{"protocolVersion":2,"agentCapabilities":{}}}"#,
    )
    .unwrap();
    assert_eq!(
        check_initialize_version(&result).unwrap_err().rule,
        AcpRule::UnsupportedProtocolVersion
    );

    let missing =
        parse_message(br#"{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{}}"#)
            .unwrap();
    assert_eq!(
        check_initialize_version(&missing).unwrap_err().rule,
        AcpRule::ProtocolVersionShape
    );
}

// -------------------------------------- a v2 acknowledgement is not a turn

#[test]
fn a_v2_prompt_acknowledgement_is_never_read_as_a_v1_turn_completion() {
    use agent_client_protocol::schema::v1::StopReason;

    // v1: the prompt response carries the stop reason.
    assert_eq!(
        read_turn_completion(&serde_json::json!({"stopReason": "end_turn"})),
        Ok(StopReason::EndTurn)
    );
    assert_eq!(
        read_turn_completion(&serde_json::json!({"stopReason": "cancelled"})),
        Ok(StopReason::Cancelled)
    );

    // v2: the prompt response is a bare acknowledgement of acceptance, with
    // completion arriving later as a notification.  Its shape is exactly an
    // empty object plus an optional `_meta`.
    for acknowledgement in [
        serde_json::json!({}),
        serde_json::json!({"_meta": {}}),
        serde_json::json!({"_meta": {"vendor": "x"}}),
    ] {
        let error = read_turn_completion(&acknowledgement).unwrap_err();
        assert_eq!(
            rule(&error),
            (
                AcpRule::V2PromptAcknowledgement,
                400,
                codes::V2_PROMPT_ACKNOWLEDGEMENT
            ),
            "{acknowledgement}"
        );
    }

    // A stop reason outside the pinned vocabulary is a third, separate rule:
    // it is not an acknowledgement, and it is not a completion either.
    for unknown in ["accepted", "EndTurn", "end-turn", "", "done"] {
        let error =
            read_turn_completion(&serde_json::json!({ "stopReason": unknown })).unwrap_err();
        assert_eq!(error.rule, AcpRule::UnknownStopReason, "{unknown}");
    }
    assert_eq!(
        read_turn_completion(&serde_json::json!(null))
            .unwrap_err()
            .rule,
        AcpRule::TurnCompletionShape
    );
}

/// The accepted vocabulary is the pinned crate's, not a list here: every
/// variant of its `StopReason` round-trips through the real reader.
#[test]
fn the_stop_reason_vocabulary_is_the_pinned_crates() {
    use agent_client_protocol::schema::v1::StopReason;
    for reason in [
        StopReason::EndTurn,
        StopReason::MaxTokens,
        StopReason::MaxTurnRequests,
        StopReason::Refusal,
        StopReason::Cancelled,
    ] {
        let encoded = serde_json::to_value(reason).unwrap();
        let result = serde_json::json!({ "stopReason": encoded });
        assert_eq!(read_turn_completion(&result), Ok(reason));
    }
}

// ------------------------------------------------------- identity headers

#[test]
fn initialize_opens_a_connection_and_every_other_post_names_one() {
    let initialize =
        br#"{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":1}}"#;
    assert!(validate_post(&json_post(), initialize).is_ok());
    let error = validate_post(&json_post_on("connection-demo"), initialize).unwrap_err();
    assert_eq!(error.rule, AcpRule::ConnectionHeaderForbidden);

    let session_new =
        br#"{"jsonrpc":"2.0","id":"new-1","method":"session/new","params":{"cwd":"/workspace/demo","mcpServers":[]}}"#;
    assert!(validate_post(&json_post_on("connection-demo"), session_new).is_ok());
    let error = validate_post(&json_post(), session_new).unwrap_err();
    assert_eq!(
        rule(&error),
        (
            AcpRule::ConnectionHeaderRequired,
            400,
            codes::HEADER_MISMATCH
        )
    );
    assert_eq!(error.id, Some(serde_json::json!("new-1")));
}

#[test]
fn a_session_scoped_post_needs_both_headers_and_a_body_that_agrees() {
    let prompt = br#"{"jsonrpc":"2.0","id":"prompt-1","method":"session/prompt","params":{"sessionId":"session-demo","prompt":[]}}"#;
    let both = headers(&[
        ("content-type", "application/json"),
        ("acp-connection-id", "connection-demo"),
        ("acp-session-id", "session-demo"),
    ]);
    assert!(validate_post(&both, prompt).is_ok());

    let error = validate_post(&json_post_on("connection-demo"), prompt).unwrap_err();
    assert_eq!(error.rule, AcpRule::SessionHeaderRequired);

    let disagreeing = headers(&[
        ("content-type", "application/json"),
        ("acp-connection-id", "connection-demo"),
        ("acp-session-id", "session-other"),
    ]);
    let error = validate_post(&disagreeing, prompt).unwrap_err();
    assert_eq!(
        rule(&error),
        (AcpRule::SessionHeaderMismatch, 400, codes::HEADER_MISMATCH)
    );

    // `session/new` is connection-scoped: it has no session to name yet.
    let session_new =
        br#"{"jsonrpc":"2.0","id":"new-1","method":"session/new","params":{"cwd":"/workspace/demo","mcpServers":[]}}"#;
    assert!(validate_post(&json_post_on("connection-demo"), session_new).is_ok());
}

#[test]
fn an_unaccepted_method_is_refused_before_anything_is_dispatched() {
    for method in [
        "session/fork",
        "session/list",
        "authenticate",
        "fs/read_text_file",
        "terminal/create",
        "request_permission",
        "mcp/connect",
    ] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":"x","method":"{method}","params":{{"sessionId":"session-demo"}}}}"#
        );
        let error = validate_post(&json_post_on("connection-demo"), body.as_bytes()).unwrap_err();
        assert_eq!(
            rule(&error),
            (AcpRule::MethodNotAccepted, 400, codes::METHOD_NOT_FOUND),
            "{method}"
        );
    }
}

// ------------------------------------------------------ rules stay distinct

/// Each rule has its own status/code pair where the chunk requires one, and no
/// two of the three headline refusals collapse into one answer.
#[test]
fn the_three_headline_refusals_have_three_distinct_answers() {
    let batch = parse_message(br#"[{"jsonrpc":"2.0"}]"#).unwrap_err();
    let version = negotiate_protocol_version(&serde_json::json!(2)).unwrap_err();
    assert_ne!(batch.rule, version.rule);
    assert_ne!(batch.status, version.status);
    assert_ne!(batch.code, version.code);
    // The third, the unsupported consumer HTTP version, is not answered here
    // at all: it is the codec's, and `tests.rs` asserts its distinct code.
    assert_eq!(batch.status, 501);
    assert_eq!(version.status, 400);
}

#[test]
fn a_rejection_body_carries_no_consumer_data() {
    let error = validate_post(
        &headers(&[("content-type", "text/plain")]),
        br#"{"jsonrpc":"2.0","id":"secret-id","method":"initialize","params":{"token":"s3cret"}}"#,
    )
    .unwrap_err();
    let body = String::from_utf8(error.body()).unwrap();
    assert!(!body.contains("s3cret"), "{body}");
    assert!(!body.contains("text/plain"), "{body}");
    // The content-type failure happens before the body is parsed, so not even
    // the id is echoed.
    assert!(!body.contains("secret-id"), "{body}");
    // Debug of a parsed message prints no payload either.
    let parsed = parse_message(
        br#"{"jsonrpc":"2.0","id":"prompt-1","method":"session/prompt","params":{"prompt":[{"type":"text","text":"s3cret"}],"sessionId":"s"}}"#,
    )
    .unwrap();
    let rendered = format!("{parsed:?}");
    assert!(!rendered.contains("s3cret"), "{rendered}");
    assert!(!rendered.contains("prompt-1"), "{rendered}");
}
