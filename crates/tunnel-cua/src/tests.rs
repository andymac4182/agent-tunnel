//! Profile allowlist tests.
//!
//! Every assertion here drives the **real** `http-forward/1` validator
//! (`encode_request_head` / `encode_response_head`) against the policies
//! `CuaProfile::policies` built, the way `tunnel_acp::tests` does. None of
//! them reads `request_headers()` and asserts the same list back: that would
//! pass for any table at all.

use super::*;
use tunnel_http_forward::{
    CodecError, HeaderField, RequestHead, ResponseHead, encode_request_head, encode_response_head,
};

fn profile() -> Profile {
    CuaProfile::ComputerV1
        .policies(CuaLimits::default())
        .unwrap()
}

fn request(method: Method, path: &str, headers: &[(&str, &str)]) -> RequestHead {
    RequestHead {
        method,
        path: path.to_owned(),
        query: String::new(),
        http_version: HttpVersion::Http2,
        headers: headers
            .iter()
            .map(|(name, value)| HeaderField::new(*name, *value))
            .collect(),
        body_length: Some(0),
    }
}

fn check_request(profile: &Profile, head: &RequestHead) -> Result<(), CodecError> {
    encode_request_head(head, &profile.request, &mut Vec::new())
}

fn check_response(profile: &Profile, headers: &[(&str, &str)]) -> Result<(), CodecError> {
    let head = ResponseHead {
        status: 200,
        headers: headers
            .iter()
            .map(|(name, value)| HeaderField::new(*name, *value))
            .collect(),
        body_length: Some(0),
    };
    encode_response_head(&head, &profile.response, Method::Post, &mut Vec::new())
}

#[test]
fn the_profile_id_round_trips_and_nothing_else_parses() {
    assert_eq!(
        CuaProfile::parse_id(PROFILE_ID),
        Some(CuaProfile::ComputerV1)
    );
    for rejected in [
        "computer-v2",
        "computer.v1",
        "acp-http-v1",
        "",
        "COMPUTER-V1",
    ] {
        assert_eq!(CuaProfile::parse_id(rejected), None, "{rejected:?}");
    }
    // The profile id and the schema version are different strings and must
    // stay so: one selects a relay profile, the other gates a request body.
    assert_ne!(PROFILE_ID, SCHEMA_VERSION);
}

/// `POST /computer` is the whole route table. Everything else is refused by
/// the real validator, not by a comparison against our own list.
#[test]
fn only_post_on_the_computer_path_is_routed() {
    let profile = profile();
    assert!(
        check_request(
            &profile,
            &request(
                Method::Post,
                COMPUTER_ENDPOINT_PATH,
                &[("content-type", "application/json")]
            )
        )
        .is_ok()
    );
    for method in [
        Method::Get,
        Method::Head,
        Method::Put,
        Method::Patch,
        Method::Delete,
        Method::Options,
    ] {
        assert!(
            check_request(&profile, &request(method, COMPUTER_ENDPOINT_PATH, &[])).is_err(),
            "{method:?} must not be routed on the computer endpoint"
        );
    }
    // Neighbouring and adjacent paths, including the backend's own `/cmd`
    // spelling, which must never be reachable through the consumer profile.
    for path in [
        "/computer/",
        "/computer/capture",
        "/Computer",
        "/computers",
        "/acp",
        "/cmd",
        "/",
    ] {
        assert!(
            check_request(&profile, &request(Method::Post, path, &[])).is_err(),
            "{path} must not be routed"
        );
    }
}

/// HTTP/2 only, and an HTTP/1.1 consumer is refused by the codec rather than
/// silently upgraded.
#[test]
fn http11_is_refused_and_http2_is_accepted() {
    let profile = profile();
    let mut head = request(
        Method::Post,
        COMPUTER_ENDPOINT_PATH,
        &[("content-type", "application/json")],
    );
    assert!(check_request(&profile, &head).is_ok());
    head.http_version = HttpVersion::Http11;
    assert!(check_request(&profile, &head).is_err());
}

/// The endpoint takes no query parameters at all. A capture's display index
/// must never be expressible in a URL that could be logged.
#[test]
fn no_query_parameter_is_accepted() {
    let profile = profile();
    for query in ["display=0", "token=abc", "a=1", ""] {
        let mut head = request(
            Method::Post,
            COMPUTER_ENDPOINT_PATH,
            &[("content-type", "application/json")],
        );
        head.query = query.to_owned();
        let outcome = check_request(&profile, &head);
        if query.is_empty() {
            assert!(outcome.is_ok(), "an empty query must be accepted");
        } else {
            assert!(outcome.is_err(), "{query} must be refused");
        }
    }
}

/// Header names one keystroke from an allowed one, and the upstream CUA cloud
/// credentials, which must never be carried in either direction.
#[test]
fn only_the_two_request_headers_are_allowed_and_cua_credentials_never_are() {
    let profile = profile();
    for allowed in [headers::CONTENT_TYPE, headers::TUNNEL_PRINCIPAL_BINDING] {
        assert!(
            check_request(
                &profile,
                &request(Method::Post, COMPUTER_ENDPOINT_PATH, &[(allowed, "v")])
            )
            .is_ok(),
            "{allowed} must be allowed on a request"
        );
    }
    for refused in [
        // Near misses.
        "tunnel-principal",
        "tunnel-principal-bindings",
        "tunnel_principal_binding",
        "content-types",
        // The upstream cloud credentials. `docs/integrations.md`: do not
        // forward relay tokens into CUA, and do not advertise upstream cloud
        // auth as local protection. Neither may cross this profile.
        "x-api-key",
        "x-container-name",
        // An ACP header, so a misconfigured relay cannot cross profiles.
        "acp-session-id",
    ] {
        assert!(
            check_request(
                &profile,
                &request(Method::Post, COMPUTER_ENDPOINT_PATH, &[(refused, "v")])
            )
            .is_err(),
            "{refused} must be refused on a request"
        );
    }
}

/// The response direction is narrower still, and in particular never echoes
/// the principal binding back to the consumer.
#[test]
fn the_response_carries_content_type_and_nothing_else() {
    let profile = profile();
    assert!(check_response(&profile, &[("content-type", "application/json")]).is_ok());
    for refused in [
        headers::TUNNEL_PRINCIPAL_BINDING,
        "x-api-key",
        "x-container-name",
        "acp-connection-id",
        "set-cookie",
    ] {
        assert!(
            check_response(&profile, &[(refused, "v")]).is_err(),
            "{refused} must be refused on a response"
        );
    }
}

#[test]
fn the_configured_limits_reach_the_policies() {
    let profile = profile();
    assert_eq!(profile.request.body_limit(), DEFAULT_REQUEST_BODY_LIMIT);
    assert_eq!(profile.response.body_limit(), DEFAULT_RESPONSE_BODY_LIMIT);

    let narrow = CuaProfile::ComputerV1
        .policies(CuaLimits::new(1024, 4096).unwrap())
        .unwrap();
    assert_eq!(narrow.request.body_limit(), 1024);
    assert_eq!(narrow.response.body_limit(), 4096);
}

/// The request limit is deliberately small. A regression that raised it to the
/// ACP profile's megabyte would be invisible without this.
///
/// **Read through the built profile and the real constructor, not compared as
/// literals.** An `assert!` over two constants cannot fail at run time — it is
/// an assertion that only a recompile can break, which is precisely the
/// "evidence that proves less than it claims" defect this repository tracks,
/// and it is what clippy's `assertions_on_constants` is warning about. The
/// values below come out of `policies()` and `CuaLimits::new`, so the test
/// exercises the code that a consumer's limits actually travel through.
#[test]
fn the_default_request_limit_is_far_below_the_response_limit_and_both_are_accepted() {
    let profile = profile();
    let request = profile.request.body_limit();
    let response = profile.response.body_limit();
    assert!(
        request.saturating_mul(256) < response,
        "the request limit ({request}) is not far below the response limit ({response})"
    );

    // Both defaults are within their ceilings -- established by the
    // constructor accepting them, and by it refusing one byte more.
    assert!(CuaLimits::new(request, response).is_ok());
    assert_eq!(
        CuaLimits::new(MAX_REQUEST_BODY_LIMIT + 1, response),
        Err(CuaLimitsError)
    );
    assert_eq!(
        CuaLimits::new(request, MAX_RESPONSE_BODY_LIMIT + 1),
        Err(CuaLimitsError)
    );

    // The two ceilings are themselves a usable pair, so "within the ceilings"
    // is not satisfied by a ceiling that nothing could reach.
    assert!(CuaLimits::new(MAX_REQUEST_BODY_LIMIT, MAX_RESPONSE_BODY_LIMIT).is_ok());
}

#[test]
fn limits_must_be_non_zero_within_their_ceilings_and_correctly_ordered() {
    assert!(CuaLimits::new(1, 1).is_ok());
    assert_eq!(CuaLimits::new(0, 1), Err(CuaLimitsError));
    assert_eq!(CuaLimits::new(1, 0), Err(CuaLimitsError));
    assert_eq!(
        CuaLimits::new(MAX_REQUEST_BODY_LIMIT + 1, MAX_RESPONSE_BODY_LIMIT),
        Err(CuaLimitsError)
    );
    assert_eq!(
        CuaLimits::new(1, MAX_RESPONSE_BODY_LIMIT + 1),
        Err(CuaLimitsError)
    );
    // A request limit above the response limit: a shape that cannot be
    // satisfied, refused rather than clamped.
    assert_eq!(CuaLimits::new(1024, 512), Err(CuaLimitsError));
}
