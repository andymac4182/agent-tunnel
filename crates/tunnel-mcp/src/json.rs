//! A strict JSON scanner for one JSON-RPC message.
//!
//! It checks the complete body once and produces an exact compact copy:
//! insignificant whitespace is removed and every other byte (numbers,
//! strings, escapes and member order) is preserved verbatim.  The compact
//! copy is what a stdio export writes to the child as one newline-delimited
//! line, so request IDs and `_meta` reach the child exactly as the consumer
//! sent them.
//!
//! It rejects what a permissive parser would silently accept and a child
//! could interpret differently from the device's policy check: duplicate
//! object member names (compared after unescaping), invalid UTF-8, lone
//! surrogate escapes, raw control characters in strings, nesting deeper than
//! [`MAX_DEPTH`], a non-object top level, and trailing data.

/// The deepest accepted nesting of arrays and objects.
pub const MAX_DEPTH: usize = 64;

/// Why a body is not one strict JSON object.  Carries no input bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JsonError {
    Syntax,
    InvalidUtf8,
    DuplicateKey,
    TooDeep,
    NotAnObject,
    TrailingData,
}

/// Scan `input` as exactly one JSON object and return its compact form.
///
/// # Errors
/// The first [`JsonError`] found.
pub fn compact_object(input: &[u8]) -> Result<Vec<u8>, JsonError> {
    if std::str::from_utf8(input).is_err() {
        return Err(JsonError::InvalidUtf8);
    }
    let mut scanner = Scanner {
        input,
        position: 0,
        out: Vec::with_capacity(input.len()),
    };
    scanner.skip_whitespace();
    if scanner.peek() != Some(b'{') {
        return Err(if scanner.peek().is_none() {
            JsonError::Syntax
        } else {
            JsonError::NotAnObject
        });
    }
    scanner.value(0)?;
    scanner.skip_whitespace();
    if scanner.position != input.len() {
        return Err(JsonError::TrailingData);
    }
    Ok(scanner.out)
}

struct Scanner<'a> {
    input: &'a [u8],
    position: usize,
    out: Vec<u8>,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn bump(&mut self) -> Result<u8, JsonError> {
        let byte = self.peek().ok_or(JsonError::Syntax)?;
        self.position += 1;
        Ok(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.bump()? == byte {
            self.out.push(byte);
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<(), JsonError> {
        self.skip_whitespace();
        match self.peek().ok_or(JsonError::Syntax)? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(JsonError::Syntax),
        }
    }

    fn literal(&mut self, text: &[u8]) -> Result<(), JsonError> {
        if self.input[self.position..].starts_with(text) {
            self.position += text.len();
            self.out.extend_from_slice(text);
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        self.expect(b'{')?;
        let mut keys: Vec<String> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            return self.expect(b'}');
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Syntax);
            }
            let key = self.string()?;
            if keys.contains(&key) {
                return Err(JsonError::DuplicateKey);
            }
            keys.push(key);
            self.skip_whitespace();
            self.expect(b':')?;
            self.value(depth)?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.expect(b',')?,
                Some(b'}') => return self.expect(b'}'),
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        self.expect(b'[')?;
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            return self.expect(b']');
        }
        loop {
            self.value(depth)?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.expect(b',')?,
                Some(b']') => return self.expect(b']'),
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn number(&mut self) -> Result<(), JsonError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return Err(JsonError::Syntax),
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::Syntax);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::Syntax);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        self.out
            .extend_from_slice(&self.input[start..self.position]);
        Ok(())
    }

    /// Copy one string verbatim and return its unescaped value.
    fn string(&mut self) -> Result<String, JsonError> {
        let start = self.position;
        if self.bump()? != b'"' {
            return Err(JsonError::Syntax);
        }
        let mut decoded = String::new();
        loop {
            let byte = self.bump()?;
            match byte {
                b'"' => break,
                b'\\' => match self.bump()? {
                    b'"' => decoded.push('"'),
                    b'\\' => decoded.push('\\'),
                    b'/' => decoded.push('/'),
                    b'b' => decoded.push('\u{8}'),
                    b'f' => decoded.push('\u{c}'),
                    b'n' => decoded.push('\n'),
                    b'r' => decoded.push('\r'),
                    b't' => decoded.push('\t'),
                    b'u' => {
                        let first = self.hex4()?;
                        let scalar = if (0xd800..0xdc00).contains(&first) {
                            if self.bump()? != b'\\' || self.bump()? != b'u' {
                                return Err(JsonError::InvalidUtf8);
                            }
                            let second = self.hex4()?;
                            if !(0xdc00..0xe000).contains(&second) {
                                return Err(JsonError::InvalidUtf8);
                            }
                            0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                        } else if (0xdc00..0xe000).contains(&first) {
                            return Err(JsonError::InvalidUtf8);
                        } else {
                            first
                        };
                        decoded.push(char::from_u32(scalar).ok_or(JsonError::InvalidUtf8)?);
                    }
                    _ => return Err(JsonError::Syntax),
                },
                0x00..=0x1f => return Err(JsonError::Syntax),
                _ => {
                    // The whole input is valid UTF-8, so a multi-byte
                    // sequence starting here is complete.
                    let width = utf8_width(byte);
                    let begin = self.position - 1;
                    let end = begin + width;
                    let text = std::str::from_utf8(&self.input[begin..end])
                        .map_err(|_| JsonError::InvalidUtf8)?;
                    decoded.push_str(text);
                    self.position = end;
                }
            }
        }
        self.out
            .extend_from_slice(&self.input[start..self.position]);
        Ok(decoded)
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = char::from(self.bump()?)
                .to_digit(16)
                .ok_or(JsonError::Syntax)?;
            value = value * 16 + digit;
        }
        Ok(value)
    }
}

const fn utf8_width(first: u8) -> usize {
    match first {
        0xf0..=0xf7 => 4,
        0xe0..=0xef => 3,
        0xc0..=0xdf => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compacts_whitespace_and_preserves_every_significant_byte() {
        // Escapes are built at run time so the source stays ASCII and the
        // backslashes are unambiguous.
        let bs = '\\';
        let text = format!("{{\"a b{bs}n{bs}u00e9{bs}ud83d{bs}ude00\": \"\u{e9}\"}}");
        let input = format!(
            " {{ \"jsonrpc\" : \"2.0\", \"id\" : 12345678901234567890 ,\n  \"method\":\"tools/call\", \"params\" : {{ \"_meta\" : {{\"k\" : [1.50e+3, -0, {text}]}} }} }} "
        );
        let compact = compact_object(input.as_bytes()).unwrap();
        let expected = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":12345678901234567890,\"method\":\"tools/call\",\"params\":{{\"_meta\":{{\"k\":[1.50e+3,-0,{{\"a b{bs}n{bs}u00e9{bs}ud83d{bs}ude00\":\"\u{e9}\"}}]}}}}}}"
        );
        assert_eq!(String::from_utf8(compact.clone()).unwrap(), expected);
        assert!(!compact.contains(&b'\n'));
        // An escaped member name equal to an earlier literal one is a
        // duplicate.
        let escaped = format!("{{\"a\":1,\"{bs}u0061\":2}}");
        assert_eq!(
            compact_object(escaped.as_bytes()),
            Err(JsonError::DuplicateKey)
        );
    }

    #[test]
    fn rejects_ambiguous_or_malformed_input() {
        let cases: &[(&[u8], JsonError)] = &[
            (br#"{"a":1,"a":2}"#, JsonError::DuplicateKey),
            (br#"[{"a":1}]"#, JsonError::NotAnObject),
            (b"1", JsonError::NotAnObject),
            (b"", JsonError::Syntax),
            (br#"{"a":1} x"#, JsonError::TrailingData),
            (br#"{"a":1}{"b":2}"#, JsonError::TrailingData),
            (br#"{"a":"\ud800"}"#, JsonError::InvalidUtf8),
            (br#"{"a":"\udc00"}"#, JsonError::InvalidUtf8),
            (b"{\"a\":\"\xff\"}", JsonError::InvalidUtf8),
            (b"{\"a\":\"\x01\"}", JsonError::Syntax),
            (br#"{"a":01}"#, JsonError::Syntax),
            (br#"{"a":1.}"#, JsonError::Syntax),
            (br#"{"a":tru}"#, JsonError::Syntax),
            (br#"{"a":1,}"#, JsonError::Syntax),
        ];
        for (input, error) in cases {
            assert_eq!(compact_object(input), Err(*error), "{input:?}");
        }
        let deep = format!(
            "{}{}",
            "{\"a\":".repeat(MAX_DEPTH + 1),
            "}".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(compact_object(deep.as_bytes()), Err(JsonError::TooDeep));
        let ok = format!("{}1{}", "{\"a\":".repeat(MAX_DEPTH), "}".repeat(MAX_DEPTH));
        assert!(compact_object(ok.as_bytes()).is_ok());
    }
}
