//! Pre-dispatch validation.
//!
//! Every rejection in this file happens **before** any dispatch could occur.
//! `crates/tunnel-cua-fixture/tests/dispatch.rs` is what proves that claim on
//! a socket: it sends each of these bodies at the fixture and reads the
//! fixture's own ledger back, which is empty.

use super::*;
use crate::operation::{Button, Deferral};

const LIMIT: u64 = crate::DEFAULT_REQUEST_BODY_LIMIT;

fn body(text: &str) -> Result<Request, SchemaError> {
    validate_request(text.as_bytes(), LIMIT)
}

/// The minimal accepted request for each of the twelve operations, and the
/// table is exhaustive by construction: it is indexed by
/// [`Operation::ALL`], so a new operation with no row here fails the test
/// rather than being skipped.
fn minimal_params(operation: Operation) -> &'static str {
    match operation {
        Operation::Describe
        | Operation::Capture
        | Operation::ScreenInfo
        | Operation::CursorPosition => "{}",
        Operation::Click | Operation::DoubleClick | Operation::Move => {
            r#"{"capture":1,"x":0,"y":0}"#
        }
        Operation::Drag => r#"{"capture":1,"x":0,"y":0,"to_x":1,"to_y":1}"#,
        Operation::Scroll => r#"{"dx":0,"dy":1}"#,
        Operation::TypeText => r#"{"text":"a"}"#,
        Operation::PressKey => r#"{"key":"a"}"#,
        Operation::Hotkey => r#"{"keys":["a"]}"#,
    }
}

#[test]
fn a_minimal_request_for_each_operation_validates() {
    for operation in Operation::ALL {
        let text = format!(
            r#"{{"version":"computer.v1","operation":"{}","params":{}}}"#,
            operation.name(),
            minimal_params(operation)
        );
        let request = body(&text).unwrap_or_else(|error| panic!("{}: {error}", operation.name()));
        assert_eq!(request.operation(), operation);
    }
}

/// **Every required parameter of every input operation is required**, and an
/// empty `params` is refused rather than defaulted.
///
/// The one deliberate default is `click`'s button; everything else must be
/// named. A defaulted capture would be the worst of them: it would silently
/// act on an image the consumer never saw.
#[test]
fn an_input_operation_refuses_an_empty_params_object() {
    for operation in Operation::INPUT {
        let text = format!(
            r#"{{"version":"computer.v1","operation":"{}","params":{{}}}}"#,
            operation.name()
        );
        assert!(
            matches!(body(&text), Err(SchemaError::MissingMember { .. })),
            "{} accepted an empty params object",
            operation.name()
        );
    }
}

/// Keystroke and coordinate bounds, each at its edge.
#[test]
fn keystroke_and_coordinate_parameters_are_bounded_and_fail_closed() {
    let request = |operation: &str, params: String| {
        body(&format!(
            r#"{{"version":"computer.v1","operation":"{operation}","params":{params}}}"#
        ))
    };
    // Text: empty and oversized are both refused; the boundary length is not.
    assert!(request("type_text", r#"{"text":""}"#.to_owned()).is_err());
    let at_limit = "a".repeat(MAX_TEXT_BYTES);
    assert!(request("type_text", format!(r#"{{"text":"{at_limit}"}}"#)).is_ok());
    let over = "a".repeat(MAX_TEXT_BYTES + 1);
    assert_eq!(
        request("type_text", format!(r#"{{"text":"{over}"}}"#)),
        Err(SchemaError::OutOfRange { name: "text" })
    );

    // Key names: a conservative charset, so a separator or a space cannot
    // reach a backend that would map it onto a keyboard layout.
    for refused in ["", "a b", "a,b", "a+b", "a\tb", "ctrl shift", "é"] {
        assert!(
            request("press_key", format!(r#"{{"key":"{refused}"}}"#)).is_err(),
            "press_key accepted {refused:?}"
        );
    }
    for accepted in ["a", "Return", "F13", "page_up", "alt-left"] {
        assert!(
            request("press_key", format!(r#"{{"key":"{accepted}"}}"#)).is_ok(),
            "press_key refused {accepted:?}"
        );
    }

    // Chords: bounded in length, and every member goes through the same rule.
    let too_many = (0..=MAX_HOTKEY_KEYS)
        .map(|_| "\"a\"")
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        request("hotkey", format!(r#"{{"keys":[{too_many}]}}"#)),
        Err(SchemaError::OutOfRange { name: "keys" })
    );
    assert!(request("hotkey", r#"{"keys":["cmd","shift","a"]}"#.to_owned()).is_ok());
    assert!(request("hotkey", r#"{"keys":["cmd","a b"]}"#.to_owned()).is_err());

    // Scroll deltas: signed, bounded both ways.
    assert!(request("scroll", format!(r#"{{"dx":0,"dy":{MAX_SCROLL_DELTA}}}"#)).is_ok());
    assert_eq!(
        request(
            "scroll",
            format!(r#"{{"dx":0,"dy":{}}}"#, MAX_SCROLL_DELTA + 1)
        ),
        Err(SchemaError::OutOfRange { name: "dy" })
    );
    assert_eq!(
        request(
            "scroll",
            format!(r#"{{"dx":{},"dy":0}}"#, -MAX_SCROLL_DELTA - 1)
        ),
        Err(SchemaError::OutOfRange { name: "dx" })
    );

    // Coordinates: bounded at the schema before any capture is consulted.
    assert_eq!(
        request(
            "click",
            format!(
                r#"{{"capture":1,"x":{},"y":0}}"#,
                u64::from(MAX_COORDINATE) + 1
            )
        ),
        Err(SchemaError::OutOfRange { name: "x" })
    );
    // And a negative coordinate is a type error, not a wrap-around.
    assert_eq!(
        request("click", r#"{"capture":1,"x":-1,"y":0}"#.to_owned()),
        Err(SchemaError::WrongType { name: "x" })
    );
}

/// The button is the one input parameter with a default, and an unknown
/// spelling is refused rather than folded into it.
#[test]
fn the_click_button_defaults_to_left_and_an_unknown_button_is_refused() {
    let request = |params: &str| {
        body(&format!(
            r#"{{"version":"computer.v1","operation":"click","params":{params}}}"#
        ))
    };
    assert_eq!(
        request(r#"{"capture":7,"x":1,"y":2}"#).unwrap().params(),
        &Params::Click {
            capture: crate::capture::CaptureId::new(7),
            point: crate::capture::Point::new(1, 2),
            button: Button::Left,
        }
    );
    assert_eq!(
        request(r#"{"capture":7,"x":1,"y":2,"button":"right"}"#)
            .unwrap()
            .params(),
        &Params::Click {
            capture: crate::capture::CaptureId::new(7),
            point: crate::capture::Point::new(1, 2),
            button: Button::Right,
        }
    );
    for refused in ["middle", "Left", "", "LEFT"] {
        assert_eq!(
            request(&format!(
                r#"{{"capture":7,"x":1,"y":2,"button":"{refused}"}}"#
            )),
            Err(SchemaError::OutOfRange { name: "button" }),
            "button={refused:?}"
        );
    }
}

#[test]
fn the_display_parameter_defaults_and_is_bounded() {
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"capture","params":{}}"#)
            .unwrap()
            .params(),
        &Params::Capture {
            display: DEFAULT_DISPLAY
        }
    );
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"capture","params":{"display":3}}"#)
            .unwrap()
            .params(),
        &Params::Capture { display: 3 }
    );
    assert_eq!(
        body(&format!(
            r#"{{"version":"computer.v1","operation":"capture","params":{{"display":{MAX_DISPLAY}}}}}"#
        ))
        .unwrap()
        .params(),
        &Params::Capture {
            display: MAX_DISPLAY
        }
    );
    for rejected in [
        format!("{}", u64::from(MAX_DISPLAY) + 1),
        format!("{}", u64::MAX),
    ] {
        assert_eq!(
            body(&format!(
                r#"{{"version":"computer.v1","operation":"capture","params":{{"display":{rejected}}}}}"#
            )),
            Err(SchemaError::OutOfRange { name: "display" })
        );
    }
    for wrong in ["-1", "\"0\"", "null", "1.5", "true", "[]"] {
        assert_eq!(
            body(&format!(
                r#"{{"version":"computer.v1","operation":"capture","params":{{"display":{wrong}}}}}"#
            )),
            Err(SchemaError::WrongType { name: "display" }),
            "display={wrong}"
        );
    }
}

/// An unknown member is a refusal, not an ignored extra. A parameter this
/// profile has not reasoned about must never reach a backend that might act
/// on it.
#[test]
fn unknown_members_are_refused_at_the_top_level_and_inside_params() {
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"capture","params":{},"extra":1}"#),
        Err(SchemaError::UnknownMember)
    );
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"capture","params":{"quality":90}}"#),
        Err(SchemaError::UnknownMember)
    );
    // A parameter belonging to a different operation. The per-operation
    // `Params` variant makes this structural rather than remembered.
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"cursor_position","params":{"display":0}}"#),
        Err(SchemaError::UnknownMember)
    );
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"describe","params":{"display":0}}"#),
        Err(SchemaError::UnknownMember)
    );
    // Non-vacuity: the same member on the operation that does define it passes.
    assert!(
        body(r#"{"version":"computer.v1","operation":"screen_info","params":{"display":0}}"#)
            .is_ok()
    );
}

#[test]
fn every_top_level_member_is_required_and_typed() {
    assert_eq!(
        body(r#"{"operation":"capture","params":{}}"#),
        Err(SchemaError::MissingMember { name: "version" })
    );
    assert_eq!(
        body(r#"{"version":"computer.v1","params":{}}"#),
        Err(SchemaError::MissingMember { name: "operation" })
    );
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"capture"}"#),
        Err(SchemaError::MissingMember { name: "params" })
    );
    assert_eq!(
        body(r#"{"version":1,"operation":"capture","params":{}}"#),
        Err(SchemaError::WrongType { name: "version" })
    );
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":7,"params":{}}"#),
        Err(SchemaError::WrongType { name: "operation" })
    );
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"capture","params":[]}"#),
        Err(SchemaError::WrongType { name: "params" })
    );
}

#[test]
fn the_version_is_compared_exactly() {
    for wrong in ["computer.v2", "computer.V1", "computer.v1 ", "v1", "1", ""] {
        assert_eq!(
            body(&format!(
                r#"{{"version":"{wrong}","operation":"capture","params":{{}}}}"#
            )),
            Err(SchemaError::UnsupportedVersion),
            "version={wrong:?}"
        );
    }
}

/// **The allowlist's fail-closed behaviour, at the schema boundary.**
///
/// A deferred operation and a typo both end in a refusal and neither is
/// dispatched; they are distinguishable only in the diagnostic. The input
/// operations chunk 3 carries are no longer on this list — they are on the
/// *accepted* one, which `an_input_operation_is_accepted_with_its_own_parameters`
/// covers.
#[test]
fn a_deferred_operation_is_deferred_and_a_typo_is_unknown_and_neither_dispatches() {
    for (name, expected) in [
        (
            "accessibility_tree",
            SchemaError::Operation(Refusal::Deferred(Deferral::NeedsBackendProbe)),
        ),
        ("clcik", SchemaError::Operation(Refusal::Unknown)),
        ("screenshot", SchemaError::Operation(Refusal::Unknown)),
        ("left_click", SchemaError::Operation(Refusal::Unknown)),
        ("run_command", SchemaError::Operation(Refusal::Unknown)),
        ("", SchemaError::Operation(Refusal::Unknown)),
    ] {
        assert_eq!(
            body(&format!(
                r#"{{"version":"computer.v1","operation":"{name}","params":{{}}}}"#
            )),
            Err(expected),
            "operation={name:?}"
        );
    }
}

/// The limit is checked before the body is scanned, so an oversized body is
/// never parsed.
#[test]
fn an_oversized_body_is_refused_by_length_before_it_is_parsed() {
    let filler = "A".repeat(2048);
    let oversized = format!(r#"{{"version":"computer.v1","operation":"{filler}","params":{{}}}}"#);
    assert_eq!(
        validate_request(oversized.as_bytes(), 512),
        Err(SchemaError::TooLarge { limit: 512 })
    );
    // Non-vacuity: the same body under a limit that admits it is refused for
    // its *contents* instead, which shows the length check ran first above.
    assert_eq!(
        validate_request(oversized.as_bytes(), LIMIT),
        Err(SchemaError::Operation(Refusal::Unknown))
    );
}

/// The duplicate-key rule, at the boundary it actually protects: a body whose
/// two `operation` members disagree must not validate as one and act as the
/// other.
#[test]
fn a_duplicated_operation_member_is_refused_rather_than_resolved() {
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"capture","operation":"click","params":{}}"#),
        Err(SchemaError::Json(JsonError::DuplicateKey))
    );
    assert_eq!(
        body(r#"{"version":"computer.v1","operation":"click","operation":"capture","params":{}}"#),
        Err(SchemaError::Json(JsonError::DuplicateKey))
    );
}

#[test]
fn a_response_serializes_with_its_outcome_and_never_omits_it() {
    let ok = Response::ok(Operation::ScreenInfo, serde_json::json!({"width": 1280}));
    let text = serde_json::to_string(&ok).unwrap();
    assert!(text.contains(r#""outcome":"ok""#), "{text}");
    assert!(text.contains(r#""operation":"screen_info""#), "{text}");
    assert!(!text.contains("error"), "{text}");

    let failed = Response::failed(
        Operation::Capture,
        "backend_reported",
        "the backend refused",
    );
    assert_eq!(failed.outcome, ResponseOutcome::Failed);
    assert!(failed.error.as_ref().unwrap().retryable);

    let unknown = Response::unknown(
        Operation::Capture,
        "transport_lost",
        "the response was lost",
    );
    assert_eq!(unknown.outcome, ResponseOutcome::Unknown);
    assert!(
        !unknown.error.as_ref().unwrap().retryable,
        "an unknown outcome is never retryable"
    );
}

/// **`Response::not_dispatched` renders as its own outcome, not as `failed`.**
///
/// The first review of this chunk found it rendering as `failed` — whose
/// contract is "the operation was dispatched and failed" — which collapsed, on
/// the wire, the exact distinction this crate exists for. It was also the one
/// constructor with no test at all.
#[test]
fn a_pre_dispatch_refusal_is_distinguishable_from_a_dispatched_failure_on_the_wire() {
    let refused = Response::not_dispatched("click", "operation_deferred", "not carried yet");
    assert_eq!(refused.outcome, ResponseOutcome::NotDispatched);
    assert_eq!(refused.operation, "click");
    assert!(refused.result.is_none());
    let error = refused.error.as_ref().expect("a refusal carries an error");
    assert!(error.retryable, "nothing happened, so a retry is safe");

    let text = serde_json::to_string(&refused).unwrap();
    assert!(text.contains(r#""outcome":"not_dispatched""#), "{text}");

    // The distinction is on the wire, not merely in the retryable flag: a
    // dispatched failure is also retryable, so a consumer keying on
    // retryability alone could not tell the two apart.
    let failed = Response::failed(
        Operation::Capture,
        "backend_reported",
        "the backend said no",
    );
    assert!(failed.error.as_ref().unwrap().retryable);
    assert_ne!(refused.outcome, failed.outcome);
    assert_eq!(
        refused.error.as_ref().unwrap().retryable,
        failed.error.as_ref().unwrap().retryable,
        "both are retryable, which is why the outcome has to carry the difference"
    );

    // And it round-trips, so a consumer can actually read it back.
    let parsed: Response = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed.outcome, ResponseOutcome::NotDispatched);
}

/// A locally-answered operation is its own outcome too: it carries a result
/// like a success, and says the backend was not involved.
#[test]
fn a_locally_answered_operation_renders_as_its_own_outcome() {
    let local = Response::answered_locally(
        Operation::Describe,
        serde_json::json!({"operations": ["describe"]}),
    );
    assert_eq!(local.outcome, ResponseOutcome::AnsweredLocally);
    assert!(local.result.is_some(), "a local answer is still an answer");
    assert!(local.error.is_none());
    let text = serde_json::to_string(&local).unwrap();
    assert!(text.contains(r#""outcome":"answered_locally""#), "{text}");
    assert_ne!(
        local.outcome,
        Response::ok(Operation::Describe, Value::Null).outcome
    );
}

/// Every arm of the wire outcome is distinct, so none of them can be conflated
/// by a consumer branching on the string.
#[test]
fn the_five_wire_outcomes_serialize_to_five_distinct_strings() {
    let spellings: Vec<String> = [
        ResponseOutcome::Ok,
        ResponseOutcome::Failed,
        ResponseOutcome::Unknown,
        ResponseOutcome::NotDispatched,
        ResponseOutcome::AnsweredLocally,
    ]
    .iter()
    .map(|outcome| serde_json::to_string(outcome).unwrap())
    .collect();
    let mut sorted = spellings.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        5,
        "two outcomes share a spelling: {spellings:?}"
    );
    assert_eq!(
        spellings,
        vec![
            "\"ok\"",
            "\"failed\"",
            "\"unknown\"",
            "\"not_dispatched\"",
            "\"answered_locally\""
        ]
    );
}

/// A response with no `outcome` must not deserialize. There is no default, and
/// this is the test that keeps one from being added.
#[test]
fn a_response_without_an_outcome_does_not_deserialize() {
    let text = r#"{"version":"computer.v1","operation":"capture"}"#;
    assert!(serde_json::from_str::<Response>(text).is_err());
    // Nor does an outcome spelling outside the closed set.
    let text = r#"{"version":"computer.v1","operation":"capture","outcome":"success"}"#;
    assert!(serde_json::from_str::<Response>(text).is_err());
    // Non-vacuity: the three real spellings do.
    for outcome in [
        "ok",
        "failed",
        "unknown",
        "not_dispatched",
        "answered_locally",
    ] {
        let text =
            format!(r#"{{"version":"computer.v1","operation":"capture","outcome":"{outcome}"}}"#);
        assert!(serde_json::from_str::<Response>(&text).is_ok(), "{outcome}");
    }
}
