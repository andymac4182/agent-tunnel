#![forbid(unsafe_code)]
//! Pinned MCP Streamable HTTP profiles for `http-forward/1` (M3-01, and the
//! gate-5 per-profile allowlists of docs/http-forwarding.md).
//!
//! Two profiles exist and are distinct types of configuration, never mixed:
//!
//! * [`McpProfile::V2026_07_28`] — the current target.  One `POST /mcp`
//!   endpoint, per-request metadata mirrored into `MCP-Protocol-Version`,
//!   `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*`, no protocol sessions, no GET
//!   stream and no `Last-Event-ID` resume.
//! * [`McpProfile::V2025_11_25`] — deliberate legacy compatibility.
//!   `POST`/`GET`/`DELETE /mcp`, `initialize` lifecycle, `Mcp-Session-Id`
//!   sessions and `Last-Event-ID`.
//!
//! [`McpProfile::policies`] builds the exact `http-forward/1` request and
//! response allowlists both relay endpoints and the device validate against.
//! [`message`] holds the buffer-before-dispatch validation the device runs on
//! a complete bounded request before any backend is invoked.

pub mod json;
pub mod message;

use tunnel_http_bridge::Profile;
use tunnel_http_forward::{
    HttpVersion, Method, Occurrence, PolicyError, RequestPolicy, ResponsePolicy,
};

/// The protocol revision string of the current target.
pub const PROTOCOL_2026_07_28: &str = "2026-07-28";
/// The protocol revision string of the legacy compatibility target.
pub const PROTOCOL_2025_11_25: &str = "2025-11-25";

/// The fixed export-local path of the single MCP endpoint.
pub const MCP_ENDPOINT_PATH: &str = "/mcp";

/// Header names (lowercase), as pinned from the specification snapshot.
pub mod headers {
    pub const CONTENT_TYPE: &str = "content-type";
    pub const ACCEPT: &str = "accept";
    pub const CACHE_CONTROL: &str = "cache-control";
    pub const X_ACCEL_BUFFERING: &str = "x-accel-buffering";
    pub const MCP_PROTOCOL_VERSION: &str = "mcp-protocol-version";
    pub const MCP_METHOD: &str = "mcp-method";
    pub const MCP_NAME: &str = "mcp-name";
    pub const MCP_PARAM_PREFIX: &str = "mcp-param-";
    pub const MCP_SESSION_ID: &str = "mcp-session-id";
    pub const LAST_EVENT_ID: &str = "last-event-id";
}

/// The two selectable MCP profiles.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum McpProfile {
    /// The 2026-07-28 current target.
    V2026_07_28,
    /// The 2025-11-25 deliberate compatibility target.
    V2025_11_25,
}

type HeaderRules = &'static [(&'static str, Occurrence)];

const REQUEST_2026: HeaderRules = &[
    (headers::CONTENT_TYPE, Occurrence::Singleton),
    (headers::ACCEPT, Occurrence::Singleton),
    (headers::MCP_PROTOCOL_VERSION, Occurrence::Singleton),
    (headers::MCP_METHOD, Occurrence::Singleton),
    (headers::MCP_NAME, Occurrence::Singleton),
];
const REQUEST_PREFIXES_2026: HeaderRules = &[(headers::MCP_PARAM_PREFIX, Occurrence::Singleton)];
const RESPONSE_2026: HeaderRules = &[
    (headers::CONTENT_TYPE, Occurrence::Singleton),
    (headers::CACHE_CONTROL, Occurrence::Singleton),
    (headers::X_ACCEL_BUFFERING, Occurrence::Singleton),
];
const REQUEST_2025: HeaderRules = &[
    (headers::CONTENT_TYPE, Occurrence::Singleton),
    (headers::ACCEPT, Occurrence::Singleton),
    (headers::MCP_PROTOCOL_VERSION, Occurrence::Singleton),
    (headers::MCP_SESSION_ID, Occurrence::Singleton),
    (headers::LAST_EVENT_ID, Occurrence::Singleton),
];
const RESPONSE_2025: HeaderRules = &[
    (headers::CONTENT_TYPE, Occurrence::Singleton),
    (headers::CACHE_CONTROL, Occurrence::Singleton),
    (headers::X_ACCEL_BUFFERING, Occurrence::Singleton),
    (headers::MCP_SESSION_ID, Occurrence::Singleton),
];

impl McpProfile {
    pub const ALL: [Self; 2] = [Self::V2026_07_28, Self::V2025_11_25];

    /// The stable profile identifier used in relay configuration, the
    /// catalog service capability and the device export configuration.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::V2026_07_28 => "mcp-2026-07-28",
            Self::V2025_11_25 => "mcp-2025-11-25",
        }
    }

    #[must_use]
    pub fn parse_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|profile| profile.id() == id)
    }

    /// The exact `MCP-Protocol-Version` value this profile carries.
    #[must_use]
    pub const fn protocol_version(self) -> &'static str {
        match self {
            Self::V2026_07_28 => PROTOCOL_2026_07_28,
            Self::V2025_11_25 => PROTOCOL_2025_11_25,
        }
    }

    /// Whether the revision has protocol sessions, the GET stream, DELETE
    /// and `Last-Event-ID`.
    #[must_use]
    pub const fn is_legacy(self) -> bool {
        matches!(self, Self::V2025_11_25)
    }

    /// The advertised method/path pairs.  Everything else is refused by the
    /// codec before admission.
    #[must_use]
    pub const fn routes(self) -> &'static [Method] {
        match self {
            Self::V2026_07_28 => &[Method::Post],
            Self::V2025_11_25 => &[Method::Post, Method::Get, Method::Delete],
        }
    }

    /// Exact request (owner→device) header names.
    #[must_use]
    pub const fn request_headers(self) -> HeaderRules {
        match self {
            Self::V2026_07_28 => REQUEST_2026,
            Self::V2025_11_25 => REQUEST_2025,
        }
    }

    /// Request header name prefixes.
    #[must_use]
    pub const fn request_header_prefixes(self) -> HeaderRules {
        match self {
            Self::V2026_07_28 => REQUEST_PREFIXES_2026,
            Self::V2025_11_25 => &[],
        }
    }

    /// Exact response (device→owner) header names.
    #[must_use]
    pub const fn response_headers(self) -> HeaderRules {
        match self {
            Self::V2026_07_28 => RESPONSE_2026,
            Self::V2025_11_25 => RESPONSE_2025,
        }
    }

    /// Build this profile's `http-forward/1` policies.
    ///
    /// The query must be empty.  Consumer HTTP/1.1 and HTTP/2 are accepted.
    /// The request limit is the finite JSON-RPC message limit; the response
    /// codec limit is the SSE cumulative limit, and the device additionally
    /// enforces the smaller finite JSON response limit.
    ///
    /// # Errors
    /// Only if the pinned tables are inconsistent (covered by tests).
    pub fn policies(self, limits: McpLimits) -> Result<Profile, PolicyError> {
        let mut request = RequestPolicy::new(limits.request_body())?;
        for method in self.routes() {
            request.allow_route(*method, MCP_ENDPOINT_PATH)?;
        }
        request.allow_http_version(HttpVersion::Http11);
        request.allow_http_version(HttpVersion::Http2);
        for (name, occurrence) in self.request_headers() {
            request.headers.allow(name, *occurrence)?;
        }
        for (prefix, occurrence) in self.request_header_prefixes() {
            request.headers.allow_prefix(prefix, *occurrence)?;
        }
        let mut response = ResponsePolicy::new(limits.sse_response_body())?;
        for (name, occurrence) in self.response_headers() {
            response.headers.allow(name, *occurrence)?;
        }
        Ok(Profile { request, response })
    }
}

/// Default finite JSON-RPC request body limit (1 MiB).
pub const DEFAULT_REQUEST_BODY_LIMIT: u64 = 1 << 20;
/// Default finite `application/json` response body limit (8 MiB).
pub const DEFAULT_JSON_RESPONSE_LIMIT: u64 = 8 << 20;
/// Default cumulative `text/event-stream` response limit (64 MiB).
pub const DEFAULT_SSE_RESPONSE_LIMIT: u64 = 64 << 20;
/// Ceiling on the request limit (16 MiB).
pub const MAX_REQUEST_BODY_LIMIT: u64 = 16 << 20;
/// Ceiling on the JSON response limit (64 MiB).
pub const MAX_JSON_RESPONSE_LIMIT: u64 = 64 << 20;
/// Ceiling on the SSE cumulative limit (1 GiB).
pub const MAX_SSE_RESPONSE_LIMIT: u64 = 1 << 30;

/// Finite per-exchange body limits for an MCP export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpLimits {
    request_body: u64,
    json_response_body: u64,
    sse_response_body: u64,
}

impl Default for McpLimits {
    fn default() -> Self {
        Self {
            request_body: DEFAULT_REQUEST_BODY_LIMIT,
            json_response_body: DEFAULT_JSON_RESPONSE_LIMIT,
            sse_response_body: DEFAULT_SSE_RESPONSE_LIMIT,
        }
    }
}

/// A rejected limit configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpLimitsError;

impl core::fmt::Display for McpLimitsError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(
            "MCP limits must be non-zero, within their ceilings, and the JSON response limit must not exceed the SSE limit",
        )
    }
}

impl std::error::Error for McpLimitsError {}

impl McpLimits {
    /// # Errors
    /// Zero, above a ceiling, or a JSON limit above the SSE limit.
    pub const fn new(
        request_body: u64,
        json_response_body: u64,
        sse_response_body: u64,
    ) -> Result<Self, McpLimitsError> {
        if request_body == 0
            || request_body > MAX_REQUEST_BODY_LIMIT
            || json_response_body == 0
            || json_response_body > MAX_JSON_RESPONSE_LIMIT
            || sse_response_body == 0
            || sse_response_body > MAX_SSE_RESPONSE_LIMIT
            || json_response_body > sse_response_body
        {
            return Err(McpLimitsError);
        }
        Ok(Self {
            request_body,
            json_response_body,
            sse_response_body,
        })
    }

    #[must_use]
    pub const fn request_body(&self) -> u64 {
        self.request_body
    }

    #[must_use]
    pub const fn json_response_body(&self) -> u64 {
        self.json_response_body
    }

    #[must_use]
    pub const fn sse_response_body(&self) -> u64 {
        self.sse_response_body
    }
}

#[cfg(test)]
mod tests;
