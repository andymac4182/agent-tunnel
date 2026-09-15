//! Path, query, and header validation plus caller-supplied policies.
//!
//! Policies are trusted configuration built by the selected service profile.
//! The codec enforces them: unknown headers and query keys are rejected, not
//! dropped.

use crate::error::{CodecError, HeaderRule, PathRule, PolicyError, QueryRule};
use crate::head::{HeaderField, HttpVersion, Method};

pub const MAX_PATH_LEN: usize = 1024;
pub const MAX_QUERY_LEN: usize = 2 * 1024;
pub const MAX_QUERY_PAIRS: usize = 32;
pub const MAX_HEADER_NAME_LEN: usize = 128;
pub const MAX_HEADER_VALUE_LEN: usize = 4 * 1024;
pub const MAX_HEADER_FIELDS: usize = 32;
pub const MAX_HEADER_TOTAL_BYTES: usize = 8 * 1024;

/// Header names that never cross this array, in either direction, regardless
/// of policy: routing, framing, credentials, forwarded identity, and internal
/// metadata.  `connection` is itself forbidden, so any field it nominates can
/// never be accompanied by a valid `connection` field.
pub const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "content-length",
    "authorization",
    "proxy-authorization",
    "proxy-authenticate",
    "cookie",
    "set-cookie",
    "forwarded",
    "via",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
];

/// Forbidden name prefixes.
pub const FORBIDDEN_HEADER_PREFIXES: &[&str] = &["x-forwarded-", "x-agent-tunnel-"];

/// Hop-by-hop features this profile does not support.  They are forbidden
/// like the list above but map to `HTTP_UNSUPPORTED_FEATURE`.
pub const UNSUPPORTED_HEADERS: &[&str] =
    &["transfer-encoding", "te", "trailer", "upgrade", "expect"];

/// Query parameter names treated as credential-bearing, compared
/// ASCII-case-insensitively after decoding.  They cannot be allowlisted.
pub const CREDENTIAL_QUERY_PARAMETERS: &[&str] = &[
    "access_token",
    "id_token",
    "refresh_token",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "key",
    "password",
    "passwd",
    "secret",
    "client_secret",
    "auth",
    "authorization",
    "session_token",
    "x-amz-security-token",
    "x-amz-signature",
    "sig",
    "signature",
];

/// Whether a header or query key may occur more than once.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Occurrence {
    Singleton,
    Repeatable,
}

/// One route advertised by the export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub method: Method,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NameRule {
    name: String,
    occurrence: Occurrence,
}

/// A direction-specific header allowlist.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeaderPolicy {
    rules: Vec<NameRule>,
}

impl HeaderPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Allow a header name.
    ///
    /// # Errors
    /// Rejects invalid, forbidden, unsupported, or duplicate names.
    pub fn allow(&mut self, name: &str, occurrence: Occurrence) -> Result<(), PolicyError> {
        if validate_header_name(name).is_err() {
            return Err(PolicyError::InvalidHeaderName);
        }
        if header_forbidden(name).is_some() {
            return Err(PolicyError::ForbiddenHeader);
        }
        if self.rules.iter().any(|rule| rule.name == name) {
            return Err(PolicyError::DuplicateEntry);
        }
        self.rules.push(NameRule {
            name: name.to_owned(),
            occurrence,
        });
        Ok(())
    }

    fn occurrence(&self, name: &str) -> Option<Occurrence> {
        self.rules
            .iter()
            .find(|rule| rule.name == name)
            .map(|rule| rule.occurrence)
    }
}

/// The query parameter allowlist.  Empty means the query must be empty.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QueryPolicy {
    rules: Vec<NameRule>,
}

impl QueryPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Allow a literal query key.
    ///
    /// # Errors
    /// Rejects keys outside the literal key alphabet, credential-bearing
    /// names, and duplicates.
    pub fn allow(&mut self, key: &str, occurrence: Occurrence) -> Result<(), PolicyError> {
        if key.is_empty() || !key.bytes().all(is_literal_query_key_byte) {
            return Err(PolicyError::InvalidQueryKey);
        }
        if is_credential_parameter(key) {
            return Err(PolicyError::CredentialQueryParameter);
        }
        if self.rules.iter().any(|rule| rule.name == key) {
            return Err(PolicyError::DuplicateEntry);
        }
        self.rules.push(NameRule {
            name: key.to_owned(),
            occurrence,
        });
        Ok(())
    }

    fn occurrence(&self, key: &str) -> Option<Occurrence> {
        self.rules
            .iter()
            .find(|rule| rule.name == key)
            .map(|rule| rule.occurrence)
    }
}

/// The owner→device request policy for one selected export profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestPolicy {
    routes: Vec<Route>,
    http_versions: Vec<HttpVersion>,
    pub query: QueryPolicy,
    pub headers: HeaderPolicy,
    body_limit: u64,
}

impl RequestPolicy {
    /// A policy with no routes, no versions, no query keys, no headers, and
    /// the given finite cumulative request body limit.
    #[must_use]
    pub const fn new(body_limit: u64) -> Self {
        Self {
            routes: Vec::new(),
            http_versions: Vec::new(),
            query: QueryPolicy::new(),
            headers: HeaderPolicy::new(),
            body_limit,
        }
    }

    /// Advertise a method/path pair.
    ///
    /// # Errors
    /// Rejects a non-canonical path or a duplicate route.
    pub fn allow_route(&mut self, method: Method, path: &str) -> Result<(), PolicyError> {
        validate_path(path).map_err(PolicyError::InvalidRoutePath)?;
        if self
            .routes
            .iter()
            .any(|route| route.method == method && route.path == path)
        {
            return Err(PolicyError::DuplicateEntry);
        }
        self.routes.push(Route {
            method,
            path: path.to_owned(),
        });
        Ok(())
    }

    /// Accept a consumer HTTP version.
    pub fn allow_http_version(&mut self, version: HttpVersion) {
        if !self.http_versions.contains(&version) {
            self.http_versions.push(version);
        }
    }

    #[must_use]
    pub const fn body_limit(&self) -> u64 {
        self.body_limit
    }

    pub(crate) fn route_allowed(&self, method: Method, path: &str) -> bool {
        self.routes
            .iter()
            .any(|route| route.method == method && route.path == path)
    }

    pub(crate) fn version_allowed(&self, version: HttpVersion) -> bool {
        self.http_versions.contains(&version)
    }
}

/// The device→owner response policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponsePolicy {
    pub headers: HeaderPolicy,
    body_limit: u64,
}

impl ResponsePolicy {
    #[must_use]
    pub const fn new(body_limit: u64) -> Self {
        Self {
            headers: HeaderPolicy::new(),
            body_limit,
        }
    }

    #[must_use]
    pub const fn body_limit(&self) -> u64 {
        self.body_limit
    }
}

/// Validate a canonical export path.
///
/// # Errors
/// Returns the first violated [`PathRule`].
pub fn validate_path(path: &str) -> Result<(), PathRule> {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return Err(PathRule::Empty);
    }
    if bytes.len() > MAX_PATH_LEN {
        return Err(PathRule::TooLong);
    }
    for &byte in bytes {
        match byte {
            b'/' | b'-' | b'.' | b'_' | b'~' => {}
            byte if byte.is_ascii_alphanumeric() => {}
            0 => return Err(PathRule::Nul),
            b'%' => return Err(PathRule::PercentEscape),
            b'\\' => return Err(PathRule::Backslash),
            b'?' | b'#' => return Err(PathRule::QueryOrFragmentDelimiter),
            _ => return Err(PathRule::DisallowedCharacter),
        }
    }
    if bytes[0] != b'/' {
        return Err(PathRule::MissingLeadingSlash);
    }
    if path == "/" {
        return Ok(());
    }
    for segment in path[1..].split('/') {
        match segment {
            "" => return Err(PathRule::EmptySegment),
            "." | ".." => return Err(PathRule::DotSegment),
            _ => {}
        }
    }
    Ok(())
}

/// Validate a query against its policy, decoding percent escapes exactly once
/// for the policy decision.  Returns the decoded pairs; forwarding must use
/// the original query bytes, never these values.
///
/// # Errors
/// Returns the first violated [`QueryRule`].
pub fn validate_query(
    query: &str,
    policy: &QueryPolicy,
) -> Result<Vec<(String, String)>, QueryRule> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    if policy.rules.is_empty() {
        return Err(QueryRule::NotPermitted);
    }
    if query.len() > MAX_QUERY_LEN {
        return Err(QueryRule::TooLong);
    }
    if !query.bytes().all(is_raw_query_byte) {
        return Err(QueryRule::DisallowedCharacter);
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (index, pair) in query.split('&').enumerate() {
        if index >= MAX_QUERY_PAIRS {
            return Err(QueryRule::TooManyPairs);
        }
        if pair.is_empty() {
            return Err(QueryRule::EmptyPair);
        }
        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        if raw_value.contains('=') {
            return Err(QueryRule::AmbiguousSeparator);
        }
        if raw_key.is_empty() {
            return Err(QueryRule::EmptyKey);
        }
        let key = percent_decode_once(raw_key)?;
        if key != raw_key {
            // Keys are literal so no downstream decode can disagree on them.
            if is_credential_parameter(&key) {
                return Err(QueryRule::CredentialParameter);
            }
            return Err(QueryRule::EncodedKey);
        }
        let value = percent_decode_once(raw_value)?;
        if is_credential_parameter(&key) {
            return Err(QueryRule::CredentialParameter);
        }
        let Some(occurrence) = policy.occurrence(&key) else {
            return Err(QueryRule::UnrecognizedKey);
        };
        if occurrence == Occurrence::Singleton && pairs.iter().any(|(seen, _)| *seen == key) {
            return Err(QueryRule::DuplicateKey);
        }
        pairs.push((key, value));
    }
    Ok(pairs)
}

fn percent_decode_once(raw: &str) -> Result<String, QueryRule> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let (Some(high), Some(low)) = (
                bytes.get(index + 1).and_then(|b| hex_value(*b)),
                bytes.get(index + 2).and_then(|b| hex_value(*b)),
            ) else {
                return Err(QueryRule::InvalidPercentEscape);
            };
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let text = String::from_utf8(decoded).map_err(|_| QueryRule::InvalidUtf8)?;
    if text.chars().any(char::is_control) {
        return Err(QueryRule::DecodedControl);
    }
    Ok(text)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// RFC 3986 query characters, excluding `+` (form-decoding ambiguity) and
/// `;` (legacy pair separator ambiguity).
const fn is_raw_query_byte(byte: u8) -> bool {
    matches!(byte,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
        | b'-' | b'.' | b'_' | b'~'
        | b'%' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b','
        | b'=' | b':' | b'@' | b'/' | b'?')
}

const fn is_literal_query_key_byte(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

fn is_credential_parameter(key: &str) -> bool {
    CREDENTIAL_QUERY_PARAMETERS
        .iter()
        .any(|name| name.eq_ignore_ascii_case(key))
}

const fn is_tchar_lower(byte: u8) -> bool {
    matches!(byte,
        b'a'..=b'z' | b'0'..=b'9'
        | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~')
}

fn validate_header_name(name: &str) -> Result<(), HeaderRule> {
    if name.is_empty() || name.len() > MAX_HEADER_NAME_LEN {
        return Err(HeaderRule::NameLength);
    }
    if !name.bytes().all(is_tchar_lower) {
        return Err(HeaderRule::NameCharacter);
    }
    Ok(())
}

fn header_forbidden(name: &str) -> Option<HeaderRule> {
    if UNSUPPORTED_HEADERS.contains(&name) {
        return Some(HeaderRule::Unsupported);
    }
    if FORBIDDEN_HEADERS.contains(&name)
        || FORBIDDEN_HEADER_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    {
        return Some(HeaderRule::Forbidden);
    }
    None
}

fn validate_header_value(value: &str) -> Result<(), HeaderRule> {
    if value.len() > MAX_HEADER_VALUE_LEN {
        return Err(HeaderRule::ValueTooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    {
        return Err(HeaderRule::ValueCharacter);
    }
    let bytes = value.as_bytes();
    let boundary = |byte: Option<&u8>| matches!(byte, Some(b' ' | b'\t'));
    if boundary(bytes.first()) || boundary(bytes.last()) {
        return Err(HeaderRule::ValueBoundaryWhitespace);
    }
    Ok(())
}

/// Validate a header array against the direction's policy.
///
/// # Errors
/// Returns the first violated [`HeaderRule`].
pub fn validate_headers(headers: &[HeaderField], policy: &HeaderPolicy) -> Result<(), HeaderRule> {
    if headers.len() > MAX_HEADER_FIELDS {
        return Err(HeaderRule::TooManyFields);
    }
    let mut total = 0usize;
    for (index, field) in headers.iter().enumerate() {
        validate_header_name(&field.name)?;
        validate_header_value(&field.value)?;
        total = total
            .checked_add(field.name.len())
            .and_then(|sum| sum.checked_add(field.value.len()))
            .ok_or(HeaderRule::TotalBytes)?;
        if total > MAX_HEADER_TOTAL_BYTES {
            return Err(HeaderRule::TotalBytes);
        }
        if let Some(rule) = header_forbidden(&field.name) {
            return Err(rule);
        }
        let Some(occurrence) = policy.occurrence(&field.name) else {
            return Err(HeaderRule::NotAllowed);
        };
        if occurrence == Occurrence::Singleton
            && headers[..index].iter().any(|seen| seen.name == field.name)
        {
            return Err(HeaderRule::RepeatedSingleton);
        }
    }
    Ok(())
}

pub(crate) fn header_error(rule: HeaderRule) -> CodecError {
    CodecError::InvalidHeader(rule)
}
