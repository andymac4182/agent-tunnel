//! A strict JSON scanner for one `computer.v1` request body.
//!
//! It rejects what a permissive parser silently accepts and a backend could
//! then interpret differently from the device's policy check: duplicate member
//! names, invalid UTF-8, lone surrogate escapes, raw control characters in
//! strings, nesting deeper than [`MAX_DEPTH`], and trailing data after the
//! value.
//!
//! **Why duplicate keys matter here specifically.** `serde_json` takes the
//! last of a duplicated member. A body carrying `{"operation":"capture",
//! "operation":"click"}` would validate as `capture` under one parser and act
//! as `click` under another; the whole point of validating before dispatch is
//! that the thing validated and the thing dispatched are the same thing.
//!
//! This is deliberately a sibling of `tunnel_acp::json` rather than a use of
//! it. Depending on `tunnel-acp` would pull the pinned ACP SDK crates into the
//! graph of everything that touches CUA, which weakens this crate's own
//! dependency assertion for no gain. The two differ in what they classify:
//! that one must tell a JSON-RPC batch from a non-object, because the ACP
//! transport answers a batch `501`. `computer.v1` has no batch, so this one
//! refuses everything that is not an object with a single answer.
//!
//! Nothing here reads a network or a file, and no error carries input bytes.

/// The deepest accepted nesting of arrays and objects.
///
/// A `computer.v1` request nests two levels (`params` and, at most, one object
/// inside it). 32 is already far past anything the schema admits; it exists so
/// a hostile body cannot drive the scanner's own recursion.
pub const MAX_DEPTH: usize = 32;

/// Why a body is not one strict JSON object. Carries no input bytes — the
/// diagnostics rule in `AGENTS.md` applies to a rejected request exactly as it
/// does to an accepted one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JsonError {
    /// Not an object at the top level (an array, a scalar, or empty).
    NotAnObject,
    /// Malformed JSON, a raw control character in a string, or a lone
    /// surrogate escape.
    Syntax,
    /// The body is not UTF-8.
    InvalidUtf8,
    /// Two members of one object share a name, compared after unescaping.
    DuplicateKey,
    /// Nesting beyond [`MAX_DEPTH`].
    TooDeep,
    /// Bytes after the top-level value.
    TrailingData,
}

impl core::fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::NotAnObject => "the request body is not a JSON object",
            Self::Syntax => "the request body is not well-formed JSON",
            Self::InvalidUtf8 => "the request body is not UTF-8",
            Self::DuplicateKey => "an object member name is repeated",
            Self::TooDeep => "the request body nests too deeply",
            Self::TrailingData => "the request body carries data after the JSON value",
        })
    }
}

impl std::error::Error for JsonError {}

/// Parse `input` as exactly one strict JSON object.
///
/// # Errors
/// Any of [`JsonError`].
pub fn strict_object(
    input: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>, JsonError> {
    let text = core::str::from_utf8(input).map_err(|_| JsonError::InvalidUtf8)?;
    if text.trim_start().as_bytes().first() != Some(&b'{') {
        return Err(JsonError::NotAnObject);
    }
    // The scan runs first and is the authority on duplicates, depth and
    // trailing data.  `serde_json` then produces the value from the same bytes;
    // it cannot disagree about the shape, because the scan already refused
    // every shape the two parsers could read differently.
    Scanner::new(text).scan()?;
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        Ok(_) => Err(JsonError::NotAnObject),
        Err(_) => Err(JsonError::Syntax),
    }
}

struct Scanner<'a> {
    bytes: &'a [u8],
    index: usize,
    depth: usize,
}

impl<'a> Scanner<'a> {
    const fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            index: 0,
            depth: 0,
        }
    }

    fn scan(mut self) -> Result<(), JsonError> {
        self.skip_whitespace();
        self.value()?;
        self.skip_whitespace();
        if self.index == self.bytes.len() {
            Ok(())
        } else {
            Err(JsonError::TrailingData)
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.index),
            Some(b' ' | b'\t' | b'\n' | b'\r')
        ) {
            self.index += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn eat(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.peek() == Some(byte) {
            self.index += 1;
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn value(&mut self) -> Result<(), JsonError> {
        match self.peek().ok_or(JsonError::Syntax)? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(JsonError::Syntax),
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), JsonError> {
        if self.bytes[self.index..].starts_with(word) {
            self.index += word.len();
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn number(&mut self) -> Result<(), JsonError> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.index += 1;
        }
        while matches!(
            self.peek(),
            Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        ) {
            self.index += 1;
        }
        if self.index == start {
            return Err(JsonError::Syntax);
        }
        Ok(())
    }

    fn enter(&mut self) -> Result<(), JsonError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        Ok(())
    }

    fn array(&mut self) -> Result<(), JsonError> {
        self.enter()?;
        self.eat(b'[')?;
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.index += 1;
            self.depth -= 1;
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            self.value()?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.index += 1,
                Some(b']') => {
                    self.index += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn object(&mut self) -> Result<(), JsonError> {
        self.enter()?;
        self.eat(b'{')?;
        let mut seen: Vec<String> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.index += 1;
            self.depth -= 1;
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            let name = self.string()?;
            // Compared after unescaping, so `"a"` and `"a"` are the same
            // member -- which is exactly the pair a byte comparison misses.
            if seen.contains(&name) {
                return Err(JsonError::DuplicateKey);
            }
            seen.push(name);
            self.skip_whitespace();
            self.eat(b':')?;
            self.skip_whitespace();
            self.value()?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    /// Scan one string and return its unescaped value.
    fn string(&mut self) -> Result<String, JsonError> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self.peek().ok_or(JsonError::Syntax)?;
            self.index += 1;
            match byte {
                b'"' => return Ok(out),
                // Raw control characters are never legal inside a JSON string,
                // and a permissive parser that accepts them lets a member name
                // carry a byte no log line can render.
                0x00..=0x1f => return Err(JsonError::Syntax),
                b'\\' => {
                    let escape = self.peek().ok_or(JsonError::Syntax)?;
                    self.index += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(JsonError::Syntax),
                    }
                }
                _ => {
                    // The input is already known to be UTF-8, so stepping back
                    // and taking one whole character is safe and cheap.
                    self.index -= 1;
                    let rest = core::str::from_utf8(&self.bytes[self.index..])
                        .map_err(|_| JsonError::InvalidUtf8)?;
                    let character = rest.chars().next().ok_or(JsonError::Syntax)?;
                    self.index += character.len_utf8();
                    out.push(character);
                }
            }
        }
    }

    /// A `\uXXXX` escape, including the surrogate-pair rule.
    ///
    /// A lone surrogate is refused rather than replaced. `serde_json` refuses
    /// it too, but this scanner is the authority on the shape and must not
    /// depend on that agreement.
    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.hex4()?;
        if (0xd800..0xdc00).contains(&first) {
            self.eat(b'\\')?;
            self.eat(b'u')?;
            let second = self.hex4()?;
            if !(0xdc00..0xe000).contains(&second) {
                return Err(JsonError::Syntax);
            }
            let combined =
                0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00);
            return char::from_u32(combined).ok_or(JsonError::Syntax);
        }
        if (0xdc00..0xe000).contains(&first) {
            // A trailing surrogate with no leader.
            return Err(JsonError::Syntax);
        }
        char::from_u32(u32::from(first)).ok_or(JsonError::Syntax)
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        let slice = self
            .bytes
            .get(self.index..self.index + 4)
            .ok_or(JsonError::Syntax)?;
        let text = core::str::from_utf8(slice).map_err(|_| JsonError::Syntax)?;
        let value = u16::from_str_radix(text, 16).map_err(|_| JsonError::Syntax)?;
        self.index += 4;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_object_is_accepted_and_its_members_survive() {
        let map = strict_object(br#"{"version":"computer.v1","params":{"display":1}}"#).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map["version"], "computer.v1");
        assert_eq!(map["params"]["display"], 1);
    }

    #[test]
    fn a_duplicate_member_is_refused_at_the_top_level_and_nested() {
        assert_eq!(
            strict_object(br#"{"operation":"capture","operation":"click"}"#),
            Err(JsonError::DuplicateKey)
        );
        assert_eq!(
            strict_object(br#"{"params":{"x":1,"x":2}}"#),
            Err(JsonError::DuplicateKey)
        );
        // Unescaped comparison: these are the same member name.
        assert_eq!(
            strict_object(br#"{"a":1,"a":2}"#),
            Err(JsonError::DuplicateKey)
        );
        // Non-vacuity: two genuinely different names are fine, so the rule is
        // comparing names rather than counting members.
        assert!(strict_object(br#"{"a":1,"b":2}"#).is_ok());
    }

    #[test]
    fn everything_that_is_not_one_object_is_refused() {
        assert_eq!(strict_object(b""), Err(JsonError::NotAnObject));
        assert_eq!(strict_object(b"   "), Err(JsonError::NotAnObject));
        assert_eq!(strict_object(b"[{}]"), Err(JsonError::NotAnObject));
        assert_eq!(strict_object(b"\"capture\""), Err(JsonError::NotAnObject));
        assert_eq!(strict_object(b"null"), Err(JsonError::NotAnObject));
        assert_eq!(strict_object(b"{} {}"), Err(JsonError::TrailingData));
        assert_eq!(strict_object(b"{}trailing"), Err(JsonError::TrailingData));
        assert_eq!(strict_object(b"{"), Err(JsonError::Syntax));
        assert_eq!(
            strict_object(&[b'{', 0xff, b'}']),
            Err(JsonError::InvalidUtf8)
        );
    }

    #[test]
    fn control_characters_and_lone_surrogates_are_refused() {
        assert_eq!(strict_object(b"{\"a\":\"x\ty\"}"), Err(JsonError::Syntax));
        assert_eq!(strict_object(br#"{"a":"\ud800"}"#), Err(JsonError::Syntax));
        assert_eq!(strict_object(br#"{"a":"\udc00"}"#), Err(JsonError::Syntax));
        // Non-vacuity: a complete surrogate pair is a legal character.
        assert!(strict_object(b"{\"a\":\"\\ud83d\\ude00\"}").is_ok());
        // Escaped, it is legal.
        assert!(strict_object(br#"{"a":"x\ty"}"#).is_ok());
    }

    #[test]
    fn nesting_past_the_bound_is_refused_and_nesting_within_it_is_not() {
        let deep = format!("{}{}", "{\"a\":".repeat(MAX_DEPTH + 1), "1".to_owned())
            + &"}".repeat(MAX_DEPTH + 1);
        assert_eq!(strict_object(deep.as_bytes()), Err(JsonError::TooDeep));

        let shallow =
            format!("{}{}", "{\"a\":".repeat(MAX_DEPTH), "1".to_owned()) + &"}".repeat(MAX_DEPTH);
        assert!(strict_object(shallow.as_bytes()).is_ok());
    }
}
