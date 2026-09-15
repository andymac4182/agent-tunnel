//! Strict head JSON: schema, duplicates, types, UTF-8, escapes, lengths.

mod common;

use common::*;
use tunnel_http_forward::{
    CodecError, HttpErrorCode, HttpVersion, Method, parse_request_head, parse_response_head,
    request_head_json,
};

fn request_json_without(key: &str) -> String {
    let fields = [
        ("method", "\"POST\""),
        ("path", "\"/acp\""),
        ("query", "\"\""),
        ("http_version", "\"2\""),
        ("headers", "[]"),
        ("body_length", "null"),
    ];
    let kept: Vec<String> = fields
        .iter()
        .filter(|(name, _)| *name != key)
        .map(|(name, value)| format!("\"{name}\":{value}"))
        .collect();
    format!("{{{}}}", kept.join(","))
}

fn req(json: &str) -> Result<tunnel_http_forward::RequestHead, CodecError> {
    parse_request_head(json.as_bytes(), &request_policy())
}

fn resp(json: &str) -> Result<tunnel_http_forward::ResponseHead, CodecError> {
    parse_response_head(json.as_bytes(), &response_policy(), Method::Post)
}

#[test]
fn baseline_heads_parse() {
    let head = req(&request_json_with("", "")).unwrap();
    assert_eq!(head.method, Method::Post);
    assert_eq!(head.http_version, HttpVersion::Http2);
    assert_eq!(head.body_length, None);
    let head = resp(&response_json_with("", "")).unwrap();
    assert_eq!(head.status, 200);
}

#[test]
fn whitespace_and_key_order_are_insignificant() {
    let json = " \t\r\n{ \"body_length\" : \"12\" ,\n\"headers\":[ [ \"accept\" , \"*/*\" ] ],\
                \"http_version\":\"1.1\",\"query\":\"\",\"path\":\"/acp\",\"method\":\"GET\" }\n ";
    let head = req(json).unwrap();
    assert_eq!(head.method, Method::Get);
    assert_eq!(head.body_length, Some(12));
    assert_eq!(head.http_version, HttpVersion::Http11);
}

#[test]
fn duplicate_keys_rejected_including_escaped_spellings() {
    let base = request_json_with("", "");
    let dup_method = base.replacen('{', "{\"method\":\"POST\",", 1);
    assert_eq!(req(&dup_method), Err(CodecError::DuplicateKey));
    let dup_null = base.replacen('{', "{\"body_length\":null,", 1);
    assert_eq!(req(&dup_null), Err(CodecError::DuplicateKey));
    // The same key spelled with an escape is still the same key.
    let escaped = base.replacen('{', &format!("{{\"{}ethod\":\"GET\",", uesc("006d")), 1);
    assert_eq!(req(&escaped), Err(CodecError::DuplicateKey));
    let dup_resp = response_json_with("", "").replacen('{', "{\"status\":201,", 1);
    assert_eq!(resp(&dup_resp), Err(CodecError::DuplicateKey));
    // A duplicate unknown key is still a duplicate, detected before schema.
    let dup_unknown = base.replacen('{', "{\"x\":1,\"x\":2,", 1);
    assert_eq!(req(&dup_unknown), Err(CodecError::DuplicateKey));
}

#[test]
fn unknown_and_missing_keys_rejected() {
    let base = request_json_with("", "");
    assert_eq!(
        req(&base.replacen('{', "{\"extra\":null,", 1)),
        Err(CodecError::UnknownKey)
    );
    assert_eq!(
        req(&base.replacen("\"method\"", "\"Method\"", 1)),
        Err(CodecError::UnknownKey)
    );
    for key in [
        "method",
        "path",
        "query",
        "http_version",
        "headers",
        "body_length",
    ] {
        let removed = request_json_without(key);
        assert_eq!(req(&removed), Err(CodecError::MissingKey), "{key}");
    }
    let response = response_json_with("", "");
    assert_eq!(
        resp(&response.replacen('{', "{\"reason\":\"OK\",", 1)),
        Err(CodecError::UnknownKey)
    );
    assert_eq!(
        resp(r#"{"status":200,"headers":[]}"#),
        Err(CodecError::MissingKey)
    );
    assert_eq!(
        resp(r#"{"headers":[],"body_length":null}"#),
        Err(CodecError::MissingKey)
    );
    // Request fields are unknown in a response and vice versa.
    assert_eq!(
        resp(&request_json_with("", "")),
        Err(CodecError::UnknownKey)
    );
    assert_eq!(
        req(&response_json_with("", "")),
        Err(CodecError::UnknownKey)
    );
}

#[test]
fn top_level_must_be_one_object() {
    for text in ["[]", "null", "\"x\"", "1", "true"] {
        assert_eq!(req(text), Err(CodecError::NotAnObject), "{text}");
    }
    assert_eq!(req(""), Err(CodecError::JsonSyntax));
    assert_eq!(req("   "), Err(CodecError::JsonSyntax));
}

#[test]
fn wrong_types_rejected() {
    let cases = [
        ("method", "1"),
        ("method", "null"),
        ("method", "[\"POST\"]"),
        ("path", "null"),
        ("query", "null"),
        ("query", "{}"),
        ("http_version", "2"),
        ("http_version", "2.0"),
        ("headers", "{}"),
        ("headers", "null"),
        ("headers", "[\"content-type\"]"),
        ("headers", "[[\"content-type\"]]"),
        ("headers", "[[\"content-type\",\"a\",\"b\"]]"),
        ("headers", "[[\"content-type\",1]]"),
        ("headers", "[[1,\"a\"]]"),
        ("headers", "[[\"content-type\",null]]"),
        ("body_length", "0"),
        ("body_length", "12"),
        ("body_length", "true"),
        ("body_length", "[]"),
    ];
    for (field, raw) in cases {
        assert_eq!(
            req(&request_json_with(field, raw)),
            Err(CodecError::WrongType),
            "{field}={raw}"
        );
    }
    for (field, raw) in [
        ("status", "\"200\""),
        ("status", "null"),
        ("headers", "{}"),
        ("body_length", "0"),
    ] {
        assert_eq!(
            resp(&response_json_with(field, raw)),
            Err(CodecError::WrongType),
            "{field}={raw}"
        );
    }
}

#[test]
fn trailing_data_rejected() {
    let base = request_json_with("", "");
    for suffix in ["x", "{}", ",", "null", "}", "\u{0}"] {
        assert_eq!(
            req(&format!("{base}{suffix}")),
            Err(CodecError::TrailingData),
            "{suffix:?}"
        );
    }
    assert!(req(&format!("{base} \n\t\r")).is_ok());
    // Non-JSON whitespace is not whitespace.
    assert_eq!(req(&format!("{base}\u{a0}")), Err(CodecError::TrailingData));
}

#[test]
fn invalid_utf8_rejected() {
    let base = request_json_with("", "");
    for bad in [
        &[0xff][..],
        &[0xc3],
        &[0xed, 0xa0, 0x80],
        &[0xc0, 0xaf],
        &[0x80],
    ] {
        let mut bytes = base.as_bytes().to_vec();
        // Inside a string value.
        let pos = base.find("application").unwrap();
        bytes.splice(pos..pos, bad.iter().copied());
        assert_eq!(
            parse_request_head(&bytes, &request_policy()),
            Err(CodecError::InvalidUtf8)
        );
        // After the object, where a lax parser might stop reading.
        let mut trailing = base.as_bytes().to_vec();
        trailing.extend_from_slice(bad);
        assert_eq!(
            parse_request_head(&trailing, &request_policy()),
            Err(CodecError::InvalidUtf8)
        );
    }
}

#[test]
fn invalid_escapes_and_lone_surrogates_rejected() {
    let invalid_escapes = [
        "\\x41".to_owned(),
        "\\a".to_owned(),
        "\\'".to_owned(),
        uesc("12"),
        uesc("12G4"),
        uesc(""),
        "\\".to_owned(),
    ];
    for escape in &invalid_escapes {
        let json = request_json_with("path", &format!("\"/acp{escape}\""));
        let result = req(&json);
        assert!(
            matches!(
                result,
                Err(CodecError::InvalidEscape | CodecError::JsonSyntax)
            ),
            "{escape}: {result:?}"
        );
    }
    let surrogates = [
        uesc("d800"),
        uesc("DBFF"),
        uesc("dc00"),
        format!("{}x", uesc("d83d")),
        format!("{}{}", uesc("d83d"), uesc("0041")),
        format!("{}{}", uesc("d83d"), uesc("d83d")),
        format!("{}{}", uesc("de00"), uesc("d83d")),
    ];
    for escape in &surrogates {
        let json = request_json_with("path", &format!("\"/acp{escape}\""));
        assert_eq!(req(&json), Err(CodecError::LoneSurrogate), "{escape}");
        // Keys are decoded with the same rules.
        let key = response_json_with("", "").replacen('{', &format!("{{\"k{escape}\":1,"), 1);
        assert_eq!(resp(&key), Err(CodecError::LoneSurrogate), "key {escape}");
    }
}

#[test]
fn valid_escapes_decode_before_validation() {
    // "/acp" spelled entirely with escapes is the same canonical path.
    let path = format!("\"\\/{}{}{}\"", uesc("0061"), uesc("0063"), uesc("0070"));
    assert_eq!(req(&request_json_with("path", &path)).unwrap().path, "/acp");
    // An escaped NUL or CR becomes a real control and is rejected by field rules.
    let nul = request_json_with("path", &format!("\"/acp{}\"", uesc("0000")));
    assert_eq!(
        req(&nul),
        Err(CodecError::InvalidPath(tunnel_http_forward::PathRule::Nul))
    );
    let header = request_json_with("headers", "[[\"content-type\",\"text/plain\\r\\nx: y\"]]");
    assert_eq!(
        req(&header),
        Err(CodecError::InvalidHeader(
            tunnel_http_forward::HeaderRule::ValueCharacter
        ))
    );
    // A valid surrogate pair decodes to a scalar, then fails the ASCII value rule.
    let emoji = request_json_with(
        "headers",
        &format!("[[\"content-type\",\"{}{}\"]]", uesc("d83d"), uesc("de00")),
    );
    assert_eq!(
        req(&emoji),
        Err(CodecError::InvalidHeader(
            tunnel_http_forward::HeaderRule::ValueCharacter
        ))
    );
}

#[test]
fn unescaped_control_characters_in_strings_rejected() {
    for control in ['\u{0}', '\u{1}', '\n', '\t', '\u{1f}'] {
        let json = request_json_with("query", &format!("\"{control}\""));
        assert_eq!(req(&json), Err(CodecError::JsonSyntax), "{control:?}");
    }
}

#[test]
fn body_length_canonical_decimal_strings() {
    for (raw, expected) in [
        ("\"0\"", Some(0)),
        ("\"1\"", Some(1)),
        ("\"10\"", Some(10)),
        ("\"18446744073709551615\"", Some(u64::MAX)),
        ("null", None),
    ] {
        let head = req(&request_json_with("body_length", raw)).unwrap();
        assert_eq!(head.body_length, expected, "{raw}");
    }
    for raw in [
        "\"\"",
        "\"00\"",
        "\"01\"",
        "\"007\"",
        "\"-1\"",
        "\"+1\"",
        "\"-0\"",
        "\" 1\"",
        "\"1 \"",
        "\"1.0\"",
        "\"1e3\"",
        "\"0x10\"",
        "\"18446744073709551616\"",
        "\"99999999999999999999\"",
        "\"１\"",
    ] {
        assert_eq!(
            req(&request_json_with("body_length", raw)),
            Err(CodecError::InvalidBodyLength),
            "{raw}"
        );
        assert_eq!(
            resp(&response_json_with("body_length", raw)),
            Err(CodecError::InvalidBodyLength),
            "{raw}"
        );
    }
    for raw in ["0", "1", "1.0", "-1", "1e3", "18446744073709551615"] {
        assert_eq!(
            req(&request_json_with("body_length", raw)),
            Err(CodecError::WrongType),
            "JSON number {raw}"
        );
    }
}

#[test]
fn status_is_an_integer_from_200_to_599() {
    for status in [200, 201, 204, 299, 301, 404, 500, 599] {
        let body_length = if status == 204 { "\"0\"" } else { "null" };
        let json = format!("{{\"status\":{status},\"headers\":[],\"body_length\":{body_length}}}");
        assert_eq!(resp(&json).unwrap().status, status);
    }
    for raw in [
        "0", "100", "101", "103", "199", "600", "999", "1000", "-200", "200.0", "2e2", "2.5e2",
        "200e0", "20",
    ] {
        assert_eq!(
            resp(&response_json_with("status", raw)),
            Err(CodecError::InvalidStatus),
            "{raw}"
        );
    }
    assert_eq!(
        resp(&response_json_with("status", "0200")),
        Err(CodecError::JsonSyntax)
    );
}

#[test]
fn method_and_version_sets_are_exact() {
    for method in Method::ALL {
        let json = request_json_with("method", &format!("\"{}\"", method.as_str()));
        let result = req(&json);
        match method {
            Method::Post | Method::Get | Method::Head | Method::Delete => {
                assert_eq!(result.unwrap().method, method);
            }
            _ => assert_eq!(result, Err(CodecError::RouteNotAllowed)),
        }
    }
    for raw in [
        "\"post\"",
        "\"CONNECT\"",
        "\"TRACE\"",
        "\"POST \"",
        "\"\"",
        "\"PRI\"",
    ] {
        assert_eq!(
            req(&request_json_with("method", raw)),
            Err(CodecError::InvalidMethod),
            "{raw}"
        );
    }
    for raw in [
        "\"1.0\"",
        "\"2.0\"",
        "\"3\"",
        "\"HTTP/1.1\"",
        "\"\"",
        "\"1\"",
    ] {
        assert_eq!(
            req(&request_json_with("http_version", raw)),
            Err(CodecError::InvalidHttpVersion),
            "{raw}"
        );
    }
    let mut only_h2 = tunnel_http_forward::RequestPolicy::new(1024).unwrap();
    only_h2.allow_route(Method::Post, "/acp").unwrap();
    only_h2.allow_http_version(HttpVersion::Http2);
    only_h2
        .headers
        .allow("content-type", tunnel_http_forward::Occurrence::Singleton)
        .unwrap();
    let h11 = request_json_with("http_version", "\"1.1\"");
    let error = parse_request_head(h11.as_bytes(), &only_h2).unwrap_err();
    assert_eq!(error, CodecError::HttpVersionNotAllowed);
    assert_eq!(error.code(), HttpErrorCode::UnsupportedFeature);
}

#[test]
fn nesting_is_bounded() {
    let json = request_json_with("headers", "[[[\"a\",\"b\"]]]");
    assert_eq!(req(&json), Err(CodecError::NestingTooDeep));
    let deep = "[".repeat(10_000);
    assert_eq!(req(&deep), Err(CodecError::NestingTooDeep));
}

#[test]
fn head_json_errors_map_to_invalid_head_and_do_not_leak_values() {
    let secret = "super-secret-header-value";
    let json = request_json_with("headers", &format!("[[\"x-unknown\",\"{secret}\"]]"));
    let error = req(&json).unwrap_err();
    assert_eq!(error.code(), HttpErrorCode::InvalidHead);
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{error:?}").contains("x-unknown"));
    let head = req(&request_json_with("", "")).unwrap();
    let debug = format!("{head:?}");
    assert!(!debug.contains("application/json"));
    assert!(!debug.contains("/acp"));
}

#[test]
fn serializer_escapes_and_round_trips() {
    let mut head = doc_request_head();
    head.headers[1].value = "a\"b\\c".into();
    let text = request_head_json(&head);
    assert!(text.contains("a\\\"b\\\\c"));
    assert_eq!(
        parse_request_head(text.as_bytes(), &request_policy()),
        Ok(head)
    );
}
