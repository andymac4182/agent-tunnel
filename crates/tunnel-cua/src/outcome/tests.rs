//! The dispatched / not-dispatched classification.
//!
//! These are unit tests over bytes. The claim that the classification matches
//! what the backend actually did is made on a socket, against the fixture's
//! own ledger, in `crates/tunnel-cua-fixture/tests/dispatch.rs`.

use super::*;
use serde_json::json;

fn framed(payload: serde_json::Value) -> Vec<u8> {
    format!("data: {payload}\n\n").into_bytes()
}

/// Shape 1: the ordinary success.
#[test]
fn a_framed_success_is_dispatched_and_ok_with_the_envelope_key_removed() {
    let body = framed(json!({"success": true, "width": 1280, "height": 800}));
    let dispatch = classify_backend_response(200, &body);
    let Dispatch::Dispatched(Completion::Ok(result)) = &dispatch else {
        panic!("expected a dispatched success, got {dispatch:?}");
    };
    assert_eq!(result["width"], 1280);
    assert_eq!(result["height"], 800);
    assert!(
        result.get("success").is_none(),
        "the envelope key is transport, not result"
    );
    assert!(dispatch.reached_the_backend());
    assert!(
        !dispatch.retry_is_safe(),
        "a success is not a thing to retry"
    );
}

/// **Shape 2, the trap.** HTTP 200 with `success: false`. A classifier that
/// read the status would call this a success.
#[test]
fn a_two_hundred_carrying_success_false_is_a_dispatched_failure() {
    let body = framed(json!({"success": false, "error": "the backend said no"}));
    let dispatch = classify_backend_response(200, &body);
    assert_eq!(
        dispatch,
        Dispatch::Dispatched(Completion::Failed {
            code: FailureCode::BackendReported
        })
    );
    assert!(dispatch.reached_the_backend());
    // A failure did not happen, so a retry is safe -- unlike an unknown.
    assert!(dispatch.retry_is_safe());
}

/// The override the released envelope allows: `{"success": True, **result}`
/// means a handler result carrying its own `success` wins. What arrives on the
/// wire is the merged value, and the merged value is the only thing read.
#[test]
fn a_handler_result_that_overrides_the_envelopes_success_key_is_believed() {
    // On the wire there is exactly one `success` member, and it is the
    // handler's. It must be read as a failure even though the envelope
    // "intended" true.
    let body = framed(json!({"success": false, "screenshot": "..."}));
    assert!(matches!(
        classify_backend_response(200, &body),
        Dispatch::Dispatched(Completion::Failed { .. })
    ));
}

/// **The absent-is-not-true rule.**
#[test]
fn a_payload_with_no_success_member_is_unknown_rather_than_a_success() {
    let body = framed(json!({"width": 1280}));
    assert_eq!(
        classify_backend_response(200, &body),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::SuccessAbsent))
    );
    // A non-boolean `success` is not truthiness either.
    for value in [json!("true"), json!(1), json!(null), json!({})] {
        let body = framed(json!({"success": value}));
        assert_eq!(
            classify_backend_response(200, &body),
            Dispatch::Dispatched(Completion::Unknown(UnknownReason::Unparseable)),
            "success={value}"
        );
    }
}

/// **Shape 3.** Pre-dispatch `HTTPException`s: real 400/401 with **no** `data:`
/// framing at all. A parser that assumed the framing would fault here, on the
/// error path, which is the path least likely to be exercised.
#[test]
fn a_pre_dispatch_four_hundred_or_four_oh_one_is_not_dispatched_and_carries_no_framing() {
    for status in [400u16, 401] {
        // The real shape: FastAPI's `HTTPException` body, unframed JSON.
        let body = br#"{"detail":"Unknown command"}"#;
        let dispatch = classify_backend_response(status, body);
        assert_eq!(
            dispatch,
            Dispatch::NotDispatched(NotDispatched::BackendRejected { status })
        );
        assert!(!dispatch.reached_the_backend());
        assert!(dispatch.retry_is_safe());
        // The framing really is absent, which is what breaks a naive parser.
        assert_eq!(parse_framed_event(body), Err(UnknownReason::FramingAbsent));
    }
    // And the pinned set is the one being read, not a literal retyped here.
    assert_eq!(cua_pin::PRE_DISPATCH_ERROR_STATUSES, &[400, 401]);
}

/// **Shape 4.** `UNAVAILABLE_WITHOUT_CONTAINER_NAME`: deliberately
/// unavailable, not a transient fault a supervisor should retry through.
#[test]
fn a_five_oh_three_is_deliberate_unavailability_and_not_a_dispatch() {
    let dispatch = classify_backend_response(UNAVAILABLE_STATUS, b"");
    assert_eq!(
        dispatch,
        Dispatch::NotDispatched(NotDispatched::BackendUnavailable)
    );
    assert!(!dispatch.reached_the_backend());
    assert_eq!(
        cua_pin::UNAVAILABLE_FLAG,
        "UNAVAILABLE_WITHOUT_CONTAINER_NAME"
    );
}

/// The direction the classifier fails in. Every unrecognised status becomes
/// `Unknown`, never `NotDispatched`, because the cost of guessing wrong is a
/// duplicated effect rather than a lost round trip.
#[test]
fn an_unreasoned_status_fails_towards_unknown_and_is_not_retryable() {
    for status in [500u16, 502, 404, 403, 429, 201, 204] {
        let dispatch = classify_backend_response(status, b"");
        assert_eq!(
            dispatch,
            Dispatch::Dispatched(Completion::Unknown(UnknownReason::UnexpectedStatus {
                status
            })),
            "status={status}"
        );
        assert!(
            !dispatch.retry_is_safe(),
            "status {status} must not invite a retry"
        );
    }
}

/// A body that began and stopped is **truncated**, which is dispatched — the
/// backend got far enough to start answering. A body with no framing at all
/// under a 200 is `FramingAbsent`, also dispatched. Neither is retryable.
#[test]
fn a_truncated_or_unframed_two_hundred_is_dispatched_and_unknown() {
    let truncated = b"data: {\"success\": tr";
    assert_eq!(
        classify_backend_response(200, truncated),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::Truncated))
    );
    // Prefix and terminator, but the middle is not JSON.
    assert_eq!(
        classify_backend_response(200, b"data: not json\n\n"),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::Unparseable))
    );
    // Framed, terminated, and a JSON *array* rather than an object.
    assert_eq!(
        classify_backend_response(200, b"data: [1,2]\n\n"),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::Unparseable))
    );
    // No framing at all under a 200.
    assert_eq!(
        classify_backend_response(200, br#"{"success":true}"#),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::FramingAbsent))
    );
    assert_eq!(
        classify_backend_response(200, b""),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::FramingAbsent))
    );
    for unknown in [
        UnknownReason::Truncated,
        UnknownReason::FramingAbsent,
        UnknownReason::Unparseable,
        UnknownReason::SuccessAbsent,
    ] {
        assert!(
            !Dispatch::Dispatched(Completion::Unknown(unknown)).retry_is_safe(),
            "{unknown:?} must not invite a retry"
        );
    }
}

/// The framing constants come from the pin, not from literals retyped here.
#[test]
fn the_framing_this_parser_expects_is_the_pinned_framing() {
    assert_eq!(cua_pin::CMD_EVENT_PREFIX, "data: ");
    assert_eq!(cua_pin::CMD_EVENT_TERMINATOR, "\n\n");
    // A near-miss framing is refused rather than tolerated: the terminator is
    // two newlines, and one is not enough.
    assert_eq!(
        parse_framed_event(b"data: {}\n"),
        Err(UnknownReason::Truncated)
    );
    assert_eq!(
        parse_framed_event(b"data:{}\n\n"),
        Err(UnknownReason::FramingAbsent)
    );
}

/// The backend's own error text is reduced to a code this repository owns, and
/// the default is the non-committal one. A permission denial is preserved as a
/// permission denial rather than escalated or retried under another backend.
#[test]
fn a_permission_denial_and_an_unsupported_command_are_distinguished_from_a_plain_failure() {
    for (error, expected) in [
        (
            "Screen Recording permission is not granted",
            FailureCode::PermissionDenied,
        ),
        (
            "accessibility access required",
            FailureCode::PermissionDenied,
        ),
        ("not authorized", FailureCode::PermissionDenied),
        (
            "command not supported on this backend",
            FailureCode::Unsupported,
        ),
        ("unknown command", FailureCode::Unsupported),
        ("something else entirely", FailureCode::BackendReported),
        ("", FailureCode::BackendReported),
    ] {
        let body = framed(json!({"success": false, "error": error}));
        assert_eq!(
            classify_backend_response(200, &body),
            Dispatch::Dispatched(Completion::Failed { code: expected }),
            "error={error:?}"
        );
    }
    // An error member that is not a string does not crash the reduction; it
    // falls to the non-committal code.
    let body = framed(json!({"success": false, "error": {"code": 7}}));
    assert_eq!(
        classify_backend_response(200, &body),
        Dispatch::Dispatched(Completion::Failed {
            code: FailureCode::BackendReported
        })
    );
}

/// The whole point of the module, stated as one table.
#[test]
fn retry_is_safe_exactly_for_not_dispatched_and_for_a_reported_failure() {
    let safe = [
        Dispatch::NotDispatched(NotDispatched::NotReached),
        Dispatch::NotDispatched(NotDispatched::EndpointRefused),
        Dispatch::NotDispatched(NotDispatched::NotPermitted),
        Dispatch::NotDispatched(NotDispatched::BackendRejected { status: 400 }),
        Dispatch::NotDispatched(NotDispatched::BackendUnavailable),
        Dispatch::Dispatched(Completion::Failed {
            code: FailureCode::BackendReported,
        }),
    ];
    let unsafe_to_retry = [
        Dispatch::Dispatched(Completion::Ok(serde_json::Value::Null)),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost)),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::DeadlineExpired)),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::Truncated)),
    ];
    for dispatch in &safe {
        assert!(dispatch.retry_is_safe(), "{dispatch:?}");
    }
    for dispatch in &unsafe_to_retry {
        assert!(!dispatch.retry_is_safe(), "{dispatch:?}");
    }
    // `NotDispatched` and `Dispatched(Unknown)` are the pair the whole module
    // exists to keep apart, and they answer both questions differently.
    let not_dispatched = Dispatch::NotDispatched(NotDispatched::NotReached);
    let unknown = Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost));
    assert_ne!(not_dispatched.retry_is_safe(), unknown.retry_is_safe());
    assert_ne!(
        not_dispatched.reached_the_backend(),
        unknown.reached_the_backend()
    );
}
