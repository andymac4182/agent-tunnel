//! A strict, bounded JSON parser for head payloads.
//!
//! This parser exists because derived `serde_json` deserialization silently
//! accepts duplicate object keys.  It rejects invalid UTF-8, duplicate keys
//! (compared after escape decoding), invalid escapes, lone surrogates,
//! unescaped control characters, trailing non-whitespace, and nesting deeper
//! than any v1 head needs.  Numbers keep their validated lexeme so callers can
//! reject fractions and exponents rather than coercing them.

use std::collections::BTreeSet;

use crate::error::CodecError;

/// Heads need object → headers array → pair array.
pub(crate) const MAX_DEPTH: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    /// A grammar-valid number lexeme.
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Json, CodecError> {
    let text = core::str::from_utf8(bytes).map_err(|_| CodecError::InvalidUtf8)?;
    let mut parser = Parser {
        bytes: text.as_bytes(),
        text,
        pos: 0,
    };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.pos != parser.bytes.len() {
        return Err(CodecError::TrailingData);
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.pos) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect_literal(&mut self, literal: &[u8]) -> Result<(), CodecError> {
        if self.bytes[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            Ok(())
        } else {
            Err(CodecError::JsonSyntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, CodecError> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Json::String),
            Some(b't') => self.expect_literal(b"true").map(|()| Json::Bool(true)),
            Some(b'f') => self.expect_literal(b"false").map(|()| Json::Bool(false)),
            Some(b'n') => self.expect_literal(b"null").map(|()| Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(CodecError::JsonSyntax),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, CodecError> {
        if depth > MAX_DEPTH {
            return Err(CodecError::NestingTooDeep);
        }
        self.pos += 1;
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(entries));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(CodecError::JsonSyntax);
            }
            let key = self.string()?;
            if !seen.insert(key.clone()) {
                return Err(CodecError::DuplicateKey);
            }
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return Err(CodecError::JsonSyntax);
            }
            self.pos += 1;
            self.skip_whitespace();
            let value = self.value(depth)?;
            entries.push((key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(entries));
                }
                _ => return Err(CodecError::JsonSyntax),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, CodecError> {
        if depth > MAX_DEPTH {
            return Err(CodecError::NestingTooDeep);
        }
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(CodecError::JsonSyntax),
            }
        }
    }

    fn number(&mut self) -> Result<Json, CodecError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(CodecError::JsonSyntax),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(CodecError::JsonSyntax);
            }
            self.digits();
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.pos += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(CodecError::JsonSyntax);
            }
            self.digits();
        }
        Ok(Json::Number(self.text[start..self.pos].to_owned()))
    }

    fn digits(&mut self) {
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
    }

    fn string(&mut self) -> Result<String, CodecError> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(byte) = self.peek() {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            // Boundaries are ASCII bytes, so this slice is valid UTF-8.
            out.push_str(&self.text[start..self.pos]);
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    self.escape(&mut out)?;
                }
                // Unescaped control character or unterminated string.
                _ => return Err(CodecError::JsonSyntax),
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), CodecError> {
        let Some(byte) = self.peek() else {
            return Err(CodecError::InvalidEscape);
        };
        self.pos += 1;
        let decoded = match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{0008}',
            b'f' => '\u{000C}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let first = self.hex4()?;
                match first {
                    0xD800..=0xDBFF => {
                        if !self.bytes[self.pos..].starts_with(b"\\u") {
                            return Err(CodecError::LoneSurrogate);
                        }
                        self.pos += 2;
                        let second = self.hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&second) {
                            return Err(CodecError::LoneSurrogate);
                        }
                        let scalar = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
                        char::from_u32(scalar).ok_or(CodecError::LoneSurrogate)?
                    }
                    0xDC00..=0xDFFF => return Err(CodecError::LoneSurrogate),
                    other => char::from_u32(other).ok_or(CodecError::InvalidEscape)?,
                }
            }
            _ => return Err(CodecError::InvalidEscape),
        };
        out.push(decoded);
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, CodecError> {
        let Some(digits) = self.bytes.get(self.pos..self.pos + 4) else {
            return Err(CodecError::InvalidEscape);
        };
        let mut value = 0u32;
        for digit in digits {
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(CodecError::InvalidEscape),
            };
            value = (value << 4) | u32::from(nibble);
        }
        self.pos += 4;
        Ok(value)
    }
}

/// Append `value` as a JSON string literal.
pub(crate) fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JSON backslash-u escape prefix, spelled so no tooling rewrites it.
    const UESC: &str = concat!("\\", "u");

    #[test]
    fn depth_limit_is_exactly_three() {
        assert!(parse(br#"{"a":[["x","y"]]}"#).is_ok());
        assert_eq!(
            parse(br#"{"a":[[["x"]]]}"#),
            Err(CodecError::NestingTooDeep)
        );
        assert_eq!(
            parse(br#"{"a":[{"b":{}}]}"#),
            Err(CodecError::NestingTooDeep)
        );
        // A deeply nested hostile payload fails without recursing past the cap.
        let hostile = "[".repeat(16 * 1024);
        assert_eq!(parse(hostile.as_bytes()), Err(CodecError::NestingTooDeep));
    }

    #[test]
    fn grammar_edges() {
        for bad in [
            &b""[..],
            b"{",
            b"{\"a\" 1}",
            b"{\"a\":1,}",
            b"[1,]",
            b"01",
            b"1.",
            b"1e",
            b"-",
            b"tru",
            b"{'a':1}",
            b"\"\x01\"",
            b"\"abc",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse(b" -0.5e+10 "), Ok(Json::Number("-0.5e+10".into())));
        assert_eq!(
            parse(format!("\"{e}d83d{e}de00{e}00e9\\/\"", e = UESC).as_bytes()),
            Ok(Json::String("\u{1F600}\u{e9}/".into()))
        );
    }

    #[test]
    fn string_writer_round_trips_controls() {
        let mut out = String::new();
        write_string("a\"\\\n\u{1}\u{7f}é", &mut out);
        assert_eq!(
            parse(out.as_bytes()),
            Ok(Json::String("a\"\\\n\u{1}\u{7f}é".into()))
        );
    }
}
