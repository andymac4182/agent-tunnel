#![forbid(unsafe_code)]
//! The pinned ACP v1 HTTP profile for `http-forward/1` (task row M8-01, and
//! the gate-5 per-profile allowlists of `docs/http-forwarding.md`).
//!
//! **What this crate is.** One `http-forward/1` [`Profile`] — routes, method
//! set and per-direction header allowlists — plus the buffer-before-dispatch
//! validation of a single ACP JSON-RPC message, plus the pinned-artifact
//! assertions in [`pin`].  It is pure: no sockets, no child process, no Axum,
//! no clock.
//!
//! **What this crate is not.** It is not evidence of interoperability with any
//! ACP client.  A profile table that passes its own tests says only that the
//! table is the one that was pinned.  Nothing here has spoken to an agent, a
//! relay or a device, and compiling against the official SDK is not the same
//! as running against it.  The HTTP handler, SSE streams, connection and
//! session state, the child process and the tunnel are chunks 2 to 5.
//!
//! **The codec is not here either.** `http-forward/1` is implemented in
//! `tunnel-http-forward` and is already verified; this crate only instantiates
//! its [`Profile`] parameter.
//!
//! # The pin
//!
//! See [`pin`] for the exact crate versions, their `Cargo.lock` checksums, the
//! upstream commits, and the assertions that the two draft features are off.
//! `docs/sources.md` records the immutable references.
//!
//! # Where the profile's contents come from
//!
//! The transport shape — one endpoint, `POST`/`GET`/`DELETE`, the
//! `Acp-Connection-Id` and `Acp-Session-Id` header pair, HTTP/2, 415 on a
//! non-JSON POST, 406 on a GET that does not accept `text/event-stream`, and
//! **501 on a batch** — is the upstream Streamable HTTP & WebSocket Transport
//! RFD.  The method names are the *normative v1 schema*, taken from the
//! pinned crate rather than retyped: the RFD's own examples use an
//! abbreviated `request_permission`, which is not a method name.  See
//! [`resolve_rfd_shorthand`].
//!
//! The revision the RFD and the SDK disagree on, and what this crate pinned,
//! are recorded in `docs/sources.md` and `docs/acp.md`.

pub mod json;
pub mod message;
pub mod pin;

use tunnel_http_bridge::Profile;
use tunnel_http_forward::{
    HttpVersion, Method, Occurrence, PolicyError, RequestPolicy, ResponsePolicy,
};

/// The stable profile identifier used in relay configuration, the catalog
/// service capability and the device export configuration.
pub const PROFILE_ID: &str = "acp-http-v1";

/// The fixed export-local path of the single ACP endpoint.
pub const ACP_ENDPOINT_PATH: &str = "/acp";

/// The only ACP protocol version this profile speaks.
///
/// ACP v2 is a draft with different prompt-completion semantics.  It is not a
/// value this profile can negotiate, and the pinned SDK is built without the
/// feature that would even define it ([`pin`]).
pub const PROTOCOL_VERSION_V1: u16 = 1;

/// Header names (lowercase), as pinned from the upstream transport RFD.
pub mod headers {
    /// `POST` bodies are `application/json`; responses are `application/json`
    /// or `text/event-stream`.
    pub const CONTENT_TYPE: &str = "content-type";
    /// A `GET` must accept `text/event-stream`.
    pub const ACCEPT: &str = "accept";
    pub const CACHE_CONTROL: &str = "cache-control";
    pub const X_ACCEL_BUFFERING: &str = "x-accel-buffering";
    /// Returned by the server in the `initialize` response and required on
    /// every later request.  An opaque routing identifier, never a credential.
    pub const ACP_CONNECTION_ID: &str = "acp-connection-id";
    /// Required on session-scoped requests and on a session-scoped `GET`.
    pub const ACP_SESSION_ID: &str = "acp-session-id";
    /// Not an ACP header.  The relay ingress, which is the only endpoint that
    /// authenticates the consumer, derives this opaque per-principal value and
    /// sets it on every request so the device can bind an ACP connection to
    /// the principal it was opened for.  It carries no identity: it is a
    /// one-way digest over the tenant, principal, device and service
    /// identifiers.  A consumer that sends it itself is refused by the ingress
    /// before anything is forwarded.  Request direction only.
    pub const TUNNEL_PRINCIPAL_BINDING: &str = "tunnel-principal-binding";
}

type HeaderRules = &'static [(&'static str, Occurrence)];

const REQUEST_HEADERS: HeaderRules = &[
    (headers::CONTENT_TYPE, Occurrence::Singleton),
    (headers::ACCEPT, Occurrence::Singleton),
    (headers::ACP_CONNECTION_ID, Occurrence::Singleton),
    (headers::ACP_SESSION_ID, Occurrence::Singleton),
    (headers::TUNNEL_PRINCIPAL_BINDING, Occurrence::Singleton),
];

/// The response direction carries no `acp-session-id`, and this is a
/// **deliberate divergence from the pinned SDK**, not a reading of it.
///
/// The RFD returns a new session's identifier in the `session/new`
/// **response body**, and names only `Acp-Connection-Id` on responses, so
/// this allowlist follows the RFD. The pinned server does **not** agree:
/// `agent-client-protocol-http` 2.1.0 `http_server.rs:410-413` (`handle_get`)
/// inserts `HEADER_SESSION_ID` on every session-scoped SSE response it
/// serves. An earlier draft of this comment asserted the opposite as fact,
/// and review caught it against the published source.
///
/// The consequence is real and is **deferred, not resolved**: a later chunk
/// that fronts or mirrors that server would have every session-scoped stream
/// refused by this allowlist. Whether to widen it or to strip the header at
/// the bridge is a decision for the chunk that has a live stream to decide
/// it against; it is recorded as a task row rather than settled here by a
/// constant nobody revisits.
const RESPONSE_HEADERS: HeaderRules = &[
    (headers::CONTENT_TYPE, Occurrence::Singleton),
    (headers::CACHE_CONTROL, Occurrence::Singleton),
    (headers::X_ACCEL_BUFFERING, Occurrence::Singleton),
    (headers::ACP_CONNECTION_ID, Occurrence::Singleton),
];

/// The advertised method/path pairs.  Everything else is refused by the codec
/// before admission.
///
/// `PUT`, `PATCH`, `HEAD` and `OPTIONS` are not routed at all: the endpoint
/// has no representation to replace, patch or describe, and a browser profile
/// with its preflight is a separate gate.
const ROUTES: &[Method] = &[Method::Post, Method::Get, Method::Delete];

/// The single selectable ACP profile.
///
/// It is an enum with one variant rather than a unit type because a second
/// profile — a v2 version profile with its own fixtures — is the shape any
/// future draft support would take, and because the relay selects a profile by
/// [`PROFILE_ID`] exactly as it does for MCP.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AcpProfile {
    /// Stable ACP v1 over the upstream Streamable HTTP binding.
    HttpV1,
}

impl AcpProfile {
    pub const ALL: [Self; 1] = [Self::HttpV1];

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::HttpV1 => PROFILE_ID,
        }
    }

    #[must_use]
    pub fn parse_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|profile| profile.id() == id)
    }

    /// The only protocol version this profile negotiates.
    #[must_use]
    pub const fn protocol_version(self) -> u16 {
        PROTOCOL_VERSION_V1
    }

    #[must_use]
    pub const fn routes(self) -> &'static [Method] {
        ROUTES
    }

    /// Exact request (owner→device) header names.
    #[must_use]
    pub const fn request_headers(self) -> HeaderRules {
        REQUEST_HEADERS
    }

    /// Exact response (device→owner) header names.
    #[must_use]
    pub const fn response_headers(self) -> HeaderRules {
        RESPONSE_HEADERS
    }

    /// Build this profile's `http-forward/1` policies.
    ///
    /// The query must be empty: the endpoint takes no parameters, and a
    /// native `EventSource`'s header limitation must never be answered with a
    /// query-string credential.
    ///
    /// **HTTP/2 only.** The RFD requires it for the Streamable HTTP profile,
    /// and the codec answers an HTTP/1.1 consumer with
    /// `HTTP_UNSUPPORTED_FEATURE` — a different rule and a different code from
    /// a route that is not advertised.
    ///
    /// # Errors
    /// Only if the pinned tables are inconsistent (covered by tests).
    pub fn policies(self, limits: AcpLimits) -> Result<Profile, PolicyError> {
        let mut request = RequestPolicy::new(limits.request_body())?;
        for method in self.routes() {
            request.allow_route(*method, ACP_ENDPOINT_PATH)?;
        }
        request.allow_http_version(HttpVersion::Http2);
        for (name, occurrence) in self.request_headers() {
            request.headers.allow(name, *occurrence)?;
        }
        let mut response = ResponsePolicy::new(limits.sse_response_body())?;
        for (name, occurrence) in self.response_headers() {
            response.headers.allow(name, *occurrence)?;
        }
        Ok(Profile { request, response })
    }
}

/// Default finite JSON-RPC request body limit (1 MiB), the value
/// `docs/acp.md` gives for one ACP message including its stdio line.
pub const DEFAULT_REQUEST_BODY_LIMIT: u64 = 1 << 20;
/// Default finite `application/json` response limit (1 MiB): an `initialize`
/// result is the only JSON response this binding produces.
pub const DEFAULT_JSON_RESPONSE_LIMIT: u64 = 1 << 20;
/// Default cumulative `text/event-stream` response limit (64 MiB) for a
/// long-lived connection- or session-scoped stream.
pub const DEFAULT_SSE_RESPONSE_LIMIT: u64 = 64 << 20;
/// Ceiling on the request limit (16 MiB).
pub const MAX_REQUEST_BODY_LIMIT: u64 = 16 << 20;
/// Ceiling on the JSON response limit (64 MiB).
pub const MAX_JSON_RESPONSE_LIMIT: u64 = 64 << 20;
/// Ceiling on the SSE cumulative limit (1 GiB).
pub const MAX_SSE_RESPONSE_LIMIT: u64 = 1 << 30;

/// Finite per-exchange body limits for an ACP export.  No unlimited sentinel
/// exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcpLimits {
    request_body: u64,
    json_response_body: u64,
    sse_response_body: u64,
}

impl Default for AcpLimits {
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
pub struct AcpLimitsError;

impl core::fmt::Display for AcpLimitsError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(
            "ACP limits must be non-zero, within their ceilings, and the JSON response limit must not exceed the SSE limit",
        )
    }
}

impl std::error::Error for AcpLimitsError {}

impl AcpLimits {
    /// # Errors
    /// Zero, above a ceiling, or a JSON limit above the SSE limit.
    pub const fn new(
        request_body: u64,
        json_response_body: u64,
        sse_response_body: u64,
    ) -> Result<Self, AcpLimitsError> {
        if request_body == 0
            || request_body > MAX_REQUEST_BODY_LIMIT
            || json_response_body == 0
            || json_response_body > MAX_JSON_RESPONSE_LIMIT
            || sse_response_body == 0
            || sse_response_body > MAX_SSE_RESPONSE_LIMIT
            || json_response_body > sse_response_body
        {
            return Err(AcpLimitsError);
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

/// The abbreviated name the transport RFD's sequence diagram uses for a
/// server-to-client permission request, and the normative v1 method it stands
/// for.
///
/// The RFD writes `{ method: "request_permission", id: 99 }` in its example.
/// That is prose shorthand, not a method name, and copying it would put a
/// method on the wire that no v1 agent implements.
pub const RFD_PERMISSION_SHORTHAND: &str = "request_permission";

/// Resolve an RFD shorthand against the normative v1 method name.
///
/// The returned name comes from the pinned schema crate's own
/// `CLIENT_METHOD_NAMES`, not from a string in this file, so a rename
/// upstream turns these tests red instead of silently disagreeing.
///
/// This resolution exists for reading the RFD.  The shorthand itself is
/// **not** an accepted method: see [`is_accepted_method`].
#[must_use]
pub fn resolve_rfd_shorthand(name: &str) -> Option<&'static str> {
    if name == RFD_PERMISSION_SHORTHAND {
        return Some(
            agent_client_protocol::schema::v1::CLIENT_METHOD_NAMES.session_request_permission,
        );
    }
    None
}

/// The v1 methods this profile carries, in the direction each travels.
///
/// Every name is read from the pinned schema crate's method tables.  A
/// name that is not in this set is refused; there is no prefix rule and no
/// `$/`-style wildcard, so an unrecognised extension method fails validation
/// rather than being forwarded to a child as if it were supported.
pub mod methods {
    use agent_client_protocol::schema::v1::{AGENT_METHOD_NAMES, CLIENT_METHOD_NAMES};

    /// Client→agent methods and notifications the host may POST.
    ///
    /// The set is deliberately narrower than the pinned schema's full table:
    /// `session/fork`, `session/resume`, `session/list`, `session/delete`,
    /// `session/close`, `session/set_mode`, `session/set_config_option`,
    /// `authenticate` and `logout` each need a policy decision of their own
    /// and are not part of the first ACP milestone.
    #[must_use]
    pub fn client_to_agent() -> Vec<&'static str> {
        vec![
            AGENT_METHOD_NAMES.initialize,
            AGENT_METHOD_NAMES.session_new,
            AGENT_METHOD_NAMES.session_load,
            AGENT_METHOD_NAMES.session_prompt,
            AGENT_METHOD_NAMES.session_cancel,
        ]
    }

    /// Agent→client methods and notifications that arrive on an SSE stream.
    #[must_use]
    pub fn agent_to_client() -> Vec<&'static str> {
        vec![
            CLIENT_METHOD_NAMES.session_update,
            CLIENT_METHOD_NAMES.session_request_permission,
        ]
    }

    /// Every accepted method name, in both directions.
    #[must_use]
    pub fn all() -> Vec<&'static str> {
        let mut names = client_to_agent();
        names.extend(agent_to_client());
        names
    }
}

/// Whether `name` is a method this profile accepts, in either direction.
///
/// The comparison is exact: no case folding, no trimming and no prefix match.
#[must_use]
pub fn is_accepted_method(name: &str) -> bool {
    methods::all().contains(&name)
}

#[cfg(test)]
mod tests;
