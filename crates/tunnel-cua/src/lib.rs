#![forbid(unsafe_code)]
//! The `computer.v1` profile for `http-forward/1` (task row M5-02, chunk 2).
//!
//! **What this crate is.** One `http-forward/1` [`Profile`] — route, method set
//! and per-direction header allowlists — plus the `computer.v1` request and
//! response schema, plus the **pre-dispatch** validation that
//! `docs/http-forwarding.md` requires of the initial JSON-command profiles
//! ("the initial JSON-command profiles for ACP, MCP, and typed CUA
//! additionally wait for their complete bounded request body and schema/policy
//! validation before invocation"), plus the read-only operation allowlist, the
//! loopback endpoint policy, the three-way capability intersection and the
//! classification of a backend response into *dispatched* or *not dispatched*.
//!
//! It is pure: no sockets, no child process, no Axum, **no clock**. The
//! fixture backend, the Lane A dispatch client and the end-to-end evidence are
//! `tunnel-cua-fixture`.
//!
//! **What this crate is not.** It is not evidence of interoperability with any
//! CUA backend. `cua-computer-server` 0.3.46 — the artifact
//! [`tunnel_http_forward::cua_pin`] names — has still never been installed,
//! imported or executed in this repository, and nothing here has spoken to
//! one. The schema below was written *against* that pin's recorded wire shape;
//! it has not been observed on a socket.
//!
//! **Nothing in this crate can touch a host's screen or input devices**, and
//! that is checkable rather than assertable: see `tests/host_untouched.rs`,
//! which reads this crate's manifest and the workspace lockfile.
//!
//! # Scope after chunk 3 — the read-only surface plus the input half
//!
//! [`Operation`] carries twelve of `docs/integrations.md`'s thirteen names:
//! the four read-only ones from chunk 2 (`describe`, `capture`, `screen_info`,
//! `cursor_position`) and the eight that synthesise input (`click`,
//! `double_click`, `move`, `drag`, `scroll`, `type_text`, `press_key`,
//! `hotkey`). `accessibility_tree` remains in
//! [`operation::DEFERRED_OPERATIONS`] and is refused **as a deferral**, which
//! is a different answer from the one a typo gets.
//!
//! The input half brings three obligations the read-only half does not have,
//! all of them state that spans exchanges and therefore — per D3 — device-side
//! rather than codec state:
//!
//! * [`lease`] — **the exclusive input lease, one per target OS session.** Two
//!   authorized agents cannot interleave keyboard or pointer actions. Reads
//!   are deliberately *not* gated, so two agents may watch one screen.
//! * [`capture`] — **capture identity, dimensions, display scale and target
//!   identity carried into actions.** A coordinate is meaningless without the
//!   image it was picked from, so a stale, mismatched or out-of-bounds
//!   reference is refused rather than best-guessed, and the display scale is
//!   *applied* rather than merely carried.
//! * [`outcome::Dispatch::retry_is_safe_for`] — **an input operation that
//!   reached the backend is never retryable**, whatever came back. That is the
//!   difference between one click and two.
//!
//! # The two layers, and why the order matters
//!
//! ```text
//!   consumer JSON  --schema::validate_request-->  Request      (no dispatch yet)
//!                  --operation allowlist      ->  Operation    (no dispatch yet)
//!                  --capability::negotiate    ->  permitted    (no dispatch yet)
//!                  --lease::InputLeases::check->  input held   (no dispatch yet)
//!                  --capture::Captures        ->  coordinates  (no dispatch yet)
//!                  --endpoint::BackendEndpoint->  loopback     (no dispatch yet)
//!   ================================== dispatch boundary ======================
//!                  --outcome::classify_backend_response-> Dispatch
//! ```
//!
//! Everything above the boundary produces [`outcome::NotDispatched`], which a
//! caller may retry. Everything below it may only produce
//! [`outcome::Completion`], one arm of which is `Unknown` — and `Unknown` is
//! **not** retryable. Conflating the two is the trap `docs/tasks.md` M5-04
//! exists for.

pub mod capability;
pub mod capture;
pub mod endpoint;
pub mod json;
pub mod lease;
pub mod marker;
pub mod operation;
pub mod outcome;
pub mod plan;
pub mod schema;

pub use operation::Operation;

use tunnel_http_bridge::Profile;
use tunnel_http_forward::{
    HttpVersion, Method, Occurrence, PolicyError, RequestPolicy, ResponsePolicy,
};

/// The stable profile identifier used in relay configuration, the catalog
/// service capability and the device export configuration.
pub const PROFILE_ID: &str = "computer-v1";

/// The fixed export-local path of the single `computer.v1` endpoint.
pub const COMPUTER_ENDPOINT_PATH: &str = "/computer";

/// The value the `version` member of every request and response must carry.
///
/// A version *string* rather than an integer, and checked exactly: a profile
/// whose operations can move a mouse must not negotiate by comparing numbers.
pub const SCHEMA_VERSION: &str = "computer.v1";

/// Header names (lowercase) this profile carries.
pub mod headers {
    /// Requests are `application/json`; so are responses. The device-side
    /// facade normalizes the backend's `text/plain` `data: <JSON>\n\n` quirk
    /// away, so the consumer-facing profile never sees it.
    pub const CONTENT_TYPE: &str = "content-type";
    /// Not a CUA header. The relay ingress — the only endpoint that
    /// authenticates the consumer — sets this opaque per-principal value so the
    /// device can bind an operation to the principal it was authorized for.
    /// It carries no identity and is request-direction only. The same header
    /// `tunnel-acp` uses, for the same reason.
    pub const TUNNEL_PRINCIPAL_BINDING: &str = "tunnel-principal-binding";
}

type HeaderRules = &'static [(&'static str, Occurrence)];

const REQUEST_HEADERS: HeaderRules = &[
    (headers::CONTENT_TYPE, Occurrence::Singleton),
    (headers::TUNNEL_PRINCIPAL_BINDING, Occurrence::Singleton),
];

/// The response direction carries no correlation header.
///
/// `computer.v1` is strictly one request, one response, one exchange: the
/// `http-forward/1` outer sequence already correlates them, and a second
/// correlation channel would be a second thing to keep consistent. The state
/// that genuinely spans exchanges — the input lease and the capture identity
/// carry-forward — lives in the device-side facade keyed by tunnel session,
/// never in a header and never in the codec.
const RESPONSE_HEADERS: HeaderRules = &[(headers::CONTENT_TYPE, Occurrence::Singleton)];

/// `POST` only. There is no representation to `GET`, replace, patch, delete or
/// describe: every operation is a command with its own schema, and a screen
/// capture is emphatically not a cacheable `GET`.
const ROUTES: &[Method] = &[Method::Post];

/// The single selectable `computer.v1` profile.
///
/// An enum with one variant rather than a unit type, for the same reason
/// `tunnel_acp::AcpProfile` is: the relay selects a profile by [`PROFILE_ID`],
/// and a second profile — the deferred `/ws` surface, should it ever be taken
/// up — is the shape a second variant would take.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CuaProfile {
    /// `computer.v1` over the shared `http-forward/1` codec.
    ComputerV1,
}

impl CuaProfile {
    pub const ALL: [Self; 1] = [Self::ComputerV1];

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ComputerV1 => PROFILE_ID,
        }
    }

    #[must_use]
    pub fn parse_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|profile| profile.id() == id)
    }

    #[must_use]
    pub const fn schema_version(self) -> &'static str {
        SCHEMA_VERSION
    }

    #[must_use]
    pub const fn routes(self) -> &'static [Method] {
        ROUTES
    }

    #[must_use]
    pub const fn request_headers(self) -> HeaderRules {
        REQUEST_HEADERS
    }

    #[must_use]
    pub const fn response_headers(self) -> HeaderRules {
        RESPONSE_HEADERS
    }

    /// Build this profile's `http-forward/1` policies.
    ///
    /// The query must be empty: the endpoint takes no parameters, and nothing
    /// about a capture or a coordinate may ever be expressible in a URL that
    /// gets logged.
    ///
    /// **HTTP/2 only**, matching the ACP profile and the bridge gate it rides.
    ///
    /// # Errors
    /// Only if the pinned tables are inconsistent (covered by tests).
    pub fn policies(self, limits: CuaLimits) -> Result<Profile, PolicyError> {
        let mut request = RequestPolicy::new(limits.request_body())?;
        for method in self.routes() {
            request.allow_route(*method, COMPUTER_ENDPOINT_PATH)?;
        }
        request.allow_http_version(HttpVersion::Http2);
        for (name, occurrence) in self.request_headers() {
            request.headers.allow(name, *occurrence)?;
        }
        let mut response = ResponsePolicy::new(limits.response_body())?;
        for (name, occurrence) in self.response_headers() {
            response.headers.allow(name, *occurrence)?;
        }
        Ok(Profile { request, response })
    }
}

/// Default request body limit (64 KiB).
///
/// A `computer.v1` request is an operation name and a handful of integers. It
/// is three orders of magnitude smaller than the ACP profile's message limit
/// **on purpose**: nothing a consumer sends this profile is large, so a large
/// request is a fault, and the cheapest place to refuse it is before the body
/// is buffered for validation.
pub const DEFAULT_REQUEST_BODY_LIMIT: u64 = 64 << 10;
/// Default response body limit (32 MiB): one bounded synthetic or real capture
/// plus its metadata. There is no unlimited sentinel.
pub const DEFAULT_RESPONSE_BODY_LIMIT: u64 = 32 << 20;
/// Ceiling on the request limit (1 MiB).
pub const MAX_REQUEST_BODY_LIMIT: u64 = 1 << 20;
/// Ceiling on the response limit (256 MiB).
pub const MAX_RESPONSE_BODY_LIMIT: u64 = 256 << 20;

/// Finite per-exchange body limits for a `computer.v1` export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CuaLimits {
    request_body: u64,
    response_body: u64,
}

impl Default for CuaLimits {
    fn default() -> Self {
        Self {
            request_body: DEFAULT_REQUEST_BODY_LIMIT,
            response_body: DEFAULT_RESPONSE_BODY_LIMIT,
        }
    }
}

/// A rejected limit configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CuaLimitsError;

impl core::fmt::Display for CuaLimitsError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(
            "computer.v1 limits must be non-zero, within their ceilings, and the request limit must not exceed the response limit",
        )
    }
}

impl std::error::Error for CuaLimitsError {}

impl CuaLimits {
    /// # Errors
    /// Zero, above a ceiling, or a request limit above the response limit.
    pub const fn new(request_body: u64, response_body: u64) -> Result<Self, CuaLimitsError> {
        if request_body == 0
            || request_body > MAX_REQUEST_BODY_LIMIT
            || response_body == 0
            || response_body > MAX_RESPONSE_BODY_LIMIT
            || request_body > response_body
        {
            return Err(CuaLimitsError);
        }
        Ok(Self {
            request_body,
            response_body,
        })
    }

    #[must_use]
    pub const fn request_body(&self) -> u64 {
        self.request_body
    }

    #[must_use]
    pub const fn response_body(&self) -> u64 {
        self.response_body
    }
}

#[cfg(test)]
mod tests;
