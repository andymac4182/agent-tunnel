//! Tests of the scanner's own contract.
//!
//! `message.rs` re-parses the compact copy with `serde_json`, which has
//! opinions of its own, so some of the scanner's refusals are invisible from
//! there: a raw control character inside a string, for instance, is refused by
//! both, and a test that only went through `parse_message` would stay green
//! with the scanner's rule removed.  The compact copy is what a later chunk
//! will hand to a child process, so the scanner's contract has to be measured
//! where it lives.

use super::*;

const BACKSLASH: u8 = 0x5c;

fn body(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"{\"a\":\"");
    out.extend_from_slice(inner);
    out.extend_from_slice(b"\"}");
    out
}

#[test]
fn the_top_level_is_classified_from_the_first_non_whitespace_byte() {
    assert_eq!(top_level(b"{}"), TopLevel::Object);
    assert_eq!(top_level(b"  \r\n\t {"), TopLevel::Object);
    assert_eq!(top_level(b"[]"), TopLevel::Array);
    assert_eq!(top_level(b"  \n [ this is not json"), TopLevel::Array);
    for other in [&b""[..], b"   ", b"null", b"7", b"\"x\"", b"}", b"]"] {
        assert_eq!(
            top_level(other),
            TopLevel::Other,
            "{}",
            String::from_utf8_lossy(other)
        );
    }
}

#[test]
fn the_scanner_refuses_a_raw_control_character_in_a_string() {
    for control in 0x00u8..=0x1f {
        assert_eq!(
            compact_object(&body(&[control])),
            Err(JsonError::Syntax),
            "control byte {control:#04x} was accepted"
        );
    }
    // The escaped spellings of the same characters are fine.
    let mut escaped = vec![BACKSLASH];
    escaped.extend_from_slice(b"n");
    assert!(compact_object(&body(&escaped)).is_ok());
}

#[test]
fn the_scanner_refuses_a_lone_surrogate_and_accepts_a_pair() {
    let mut lone = vec![BACKSLASH];
    lone.extend_from_slice(b"ud800");
    assert_eq!(compact_object(&body(&lone)), Err(JsonError::Syntax));

    let mut trailing = vec![BACKSLASH];
    trailing.extend_from_slice(b"udc00");
    assert_eq!(compact_object(&body(&trailing)), Err(JsonError::Syntax));

    let mut pair = vec![BACKSLASH];
    pair.extend_from_slice(b"ud83d");
    pair.push(BACKSLASH);
    pair.extend_from_slice(b"ude00");
    let compact = compact_object(&body(&pair)).unwrap();
    // The escapes are preserved rather than folded to the scalar.
    assert_eq!(compact, body(&pair));
}

#[test]
fn the_scanner_refuses_duplicate_names_trailing_data_and_deep_nesting() {
    assert_eq!(
        compact_object(br#"{"a":1,"a":2}"#),
        Err(JsonError::DuplicateKey)
    );
    assert_eq!(
        compact_object(br#"{"a":1} x"#),
        Err(JsonError::TrailingData)
    );
    assert_eq!(
        compact_object(br#"{"a":1}{}"#),
        Err(JsonError::TrailingData)
    );

    let depth = MAX_DEPTH + 2;
    let mut deep = Vec::new();
    for _ in 0..depth {
        deep.extend_from_slice(br#"{"a":"#);
    }
    deep.push(b'1');
    deep.extend(std::iter::repeat_n(b'}', depth));
    assert_eq!(compact_object(&deep), Err(JsonError::TooDeep));
}

#[test]
fn the_scanner_refuses_a_non_object_top_level_without_naming_the_batch() {
    for body in [&b"[1]"[..], b"7", b"\"x\"", b"", b"   "] {
        assert_eq!(
            compact_object(body),
            Err(JsonError::Syntax),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn invalid_utf8_is_refused_before_the_scan() {
    assert_eq!(
        compact_object(&[b'{', b'"', b'a', b'"', b':', b'"', 0xff, b'"', b'}']),
        Err(JsonError::InvalidUtf8)
    );
}

#[test]
fn whitespace_is_the_only_thing_the_compact_copy_drops() {
    let compact = compact_object(b" { \"a\" : [ 1 , 2.50 , 1e3 , true , null ] } ").unwrap();
    assert_eq!(compact, br#"{"a":[1,2.50,1e3,true,null]}"#);
}
