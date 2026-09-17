//! A strict JSON scanner for one ACP JSON-RPC message body.
//!
//! It answers two questions in one pass, and keeps them separate:
//!
//! 1. **What is the top level?** A JSON array is a JSON-RPC *batch*, which the
//!    upstream transport RFD answers with HTTP 501, so it has to be
//!    distinguishable from "not an object" before any other check runs.  A
//!    batch that is also malformed is still refused as a batch: the top-level
//!    classification is taken from the first non-whitespace byte, so the
//!    refusal cannot be attributed to the payload's contents.
//! 2. **Is the object strict?** It rejects what a permissive parser would
//!    silently accept and a child process could then interpret differently
//!    from the device's policy check: duplicate member names (compared after
//!    unescaping), invalid UTF-8, lone surrogate escapes, raw control
//!    characters in strings, nesting deeper than [`MAX_DEPTH`], and trailing
//!    data after the value.
//!
//! The scan produces an exact compact copy: insignificant whitespace is
//! removed and every other byte — numbers, string bytes, escapes and member
//! order — is preserved verbatim, so a later chunk can hand the child exactly
//! what the consumer sent.
//!
//! Nothing here reads a network or a file, and no error carries input bytes.

/// The deepest accepted nesting of arrays and objects.
pub const MAX_DEPTH: usize = 64;

/// What the first non-whitespace byte of the body says the top level is.
///
/// Decided from that byte alone, so a rejection names the shape the caller
/// sent rather than the first parse error inside it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TopLevel {
    /// `{` — a single JSON-RPC message.
    Object,
    /// `[` — a JSON-RPC batch.
    Array,
    /// Anything else, including an empty body.
    Other,
}

/// Why a body is not one strict JSON object.  Carries no input bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JsonError {
    Syntax,
    InvalidUtf8,
    DuplicateKey,
    TooDeep,
    TrailingData,
}

/// Classify the top level without parsing the value.
#[must_use]
pub fn top_level(input: &[u8]) -> TopLevel {
    let mut index = 0;
    while let Some(byte) = input.get(index) {
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
            index += 1;
            continue;
        }
        return match byte {
            b'{' => TopLevel::Object,
            b'[' => TopLevel::Array,
            _ => TopLevel::Other,
        };
    }
    TopLevel::Other
}

/// Scan `input` as exactly one strict JSON object and return its compact form.
///
/// The caller is expected to have classified the top level already with
/// [`top_level`]; a non-object top level is reported here as
/// [`JsonError::Syntax`] rather than being given a shape-specific error, so
/// that the batch decision cannot be reached through this function by
/// accident.
///
/// # Errors
/// The first [`JsonError`] found.
pub fn compact_object(input: &[u8]) -> Result<Vec<u8>, JsonError> {
    if core::str::from_utf8(input).is_err() {
        return Err(JsonError::InvalidUtf8);
    }
    if top_level(input) != TopLevel::Object {
        return Err(JsonError::Syntax);
    }
    let mut scanner = Scanner {
        input,
        position: 0,
        out: Vec::with_capacity(input.len()),
    };
    scanner.skip_whitespace();
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

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        self.out.push(byte);
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.peek() == Some(byte) {
            self.position += 1;
            self.out.push(byte);
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<(), JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        match self.peek().ok_or(JsonError::Syntax)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(JsonError::Syntax),
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), JsonError> {
        for expected in word {
            if self.bump() != Some(*expected) {
                return Err(JsonError::Syntax);
            }
        }
        Ok(())
    }

    fn number(&mut self) -> Result<(), JsonError> {
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => {
                self.bump();
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.bump();
                }
            }
            _ => return Err(JsonError::Syntax),
        }
        if self.peek() == Some(b'.') {
            self.bump();
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::Syntax);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.bump();
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::Syntax);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.bump();
            }
        }
        Ok(())
    }

    /// Scan one string and return its unescaped text, used to compare member
    /// names.  The compact copy keeps the original escapes.
    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut text = String::new();
        loop {
            let byte = self.bump().ok_or(JsonError::Syntax)?;
            match byte {
                b'"' => return Ok(text),
                // Raw control characters are not permitted in a JSON string.
                0x00..=0x1f => return Err(JsonError::Syntax),
                b'\\' => {
                    let escape = self.bump().ok_or(JsonError::Syntax)?;
                    match escape {
                        b'"' => text.push('"'),
                        b'\\' => text.push('\\'),
                        b'/' => text.push('/'),
                        b'b' => text.push('\u{8}'),
                        b'f' => text.push('\u{c}'),
                        b'n' => text.push('\n'),
                        b'r' => text.push('\r'),
                        b't' => text.push('\t'),
                        b'u' => text.push(self.unicode_escape()?),
                        _ => return Err(JsonError::Syntax),
                    }
                }
                _ => {
                    // The whole input was checked as UTF-8 before the scan, so
                    // a continuation byte here is part of a valid scalar.
                    if byte < 0x80 {
                        text.push(char::from(byte));
                    } else {
                        let start = self.position - 1;
                        while self.peek().is_some_and(|next| next & 0xc0 == 0x80) {
                            self.bump();
                        }
                        let slice = &self.input[start..self.position];
                        text.push_str(core::str::from_utf8(slice).map_err(|_| JsonError::Syntax)?);
                    }
                }
            }
        }
    }

    /// Read the four hex digits of a `\u` escape, joining a surrogate pair.
    /// A lone surrogate is a syntax error rather than a replacement
    /// character: a child that repaired it would see different text from the
    /// one this device validated.
    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.hex4()?;
        if (0xdc00..=0xdfff).contains(&first) {
            return Err(JsonError::Syntax);
        }
        if !(0xd800..=0xdbff).contains(&first) {
            return char::from_u32(u32::from(first)).ok_or(JsonError::Syntax);
        }
        if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
            return Err(JsonError::Syntax);
        }
        let second = self.hex4()?;
        if !(0xdc00..=0xdfff).contains(&second) {
            return Err(JsonError::Syntax);
        }
        let scalar = 0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00);
        char::from_u32(scalar).ok_or(JsonError::Syntax)
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let byte = self.bump().ok_or(JsonError::Syntax)?;
            let digit = char::from(byte).to_digit(16).ok_or(JsonError::Syntax)?;
            value = value * 16 + u16::try_from(digit).map_err(|_| JsonError::Syntax)?;
        }
        Ok(value)
    }

    fn array(&mut self, depth: usize) -> Result<(), JsonError> {
        self.expect(b'[')?;
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            self.value(depth + 1)?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                }
                Some(b']') => {
                    self.bump();
                    return Ok(());
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), JsonError> {
        self.expect(b'{')?;
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(());
        }
        let mut names: Vec<String> = Vec::new();
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Syntax);
            }
            let name = self.string()?;
            if names.contains(&name) {
                return Err(JsonError::DuplicateKey);
            }
            names.push(name);
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            self.value(depth + 1)?;
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                }
                Some(b'}') => {
                    self.bump();
                    return Ok(());
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
