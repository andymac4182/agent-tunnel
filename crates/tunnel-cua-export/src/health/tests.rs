use super::*;

use serde_json::json;
use tunnel_cua::outcome::UnknownReason;
use tunnel_cua::schema::validate_request;

const LIMIT: u64 = 64 << 10;

fn request(operation: &str, params: serde_json::Value) -> Request {
    let body = json!({
        "version": tunnel_cua::SCHEMA_VERSION,
        "operation": operation,
        "params": params,
    })
    .to_string();
    validate_request(body.as_bytes(), LIMIT).expect("a valid request")
}

fn ok() -> Dispatch {
    Dispatch::Dispatched(Completion::Ok(json!({"width": 128, "height": 96})))
}

#[test]
fn a_dispatched_read_only_probe_that_succeeded_is_the_only_route_to_working() {
    for operation in ["screen_info", "cursor_position"] {
        let request = request(operation, json!({}));
        let health = assess(&request, &ok());
        assert!(
            health.permits_dispatch(),
            "{operation} should be a usable probe"
        );
        assert!(health.evidence().is_some(), "the evidence is carried");
    }
}

#[test]
fn describe_can_never_report_a_working_backend() {
    // **The anti-echo rule.** `describe` is answered from the negotiated
    // capability set without touching the backend, so it cannot report that
    // the backend can act. It is refused as `NotAProbe` -- a caller's bug --
    // rather than as a probe that ran and failed.
    let request = request("describe", json!({}));
    assert_eq!(
        assess(&request, &Dispatch::AnsweredLocally(json!({}))),
        Health::Unhealthy(Unhealthy::NotAProbe)
    );
    // And it stays refused even when handed a dispatched success, which is
    // the shape an echo-based health check would be built out of.
    assert_eq!(
        assess(&request, &ok()),
        Health::Unhealthy(Unhealthy::NotAProbe)
    );
}

#[test]
fn a_non_probe_that_was_never_dispatched_is_still_reported_as_not_a_probe() {
    // **Added because the deletion harness found the allowlist check
    // non-load-bearing, and the finding was right.** For a *dispatched*
    // `describe`, `ProbeEvidence::from_probe` refuses on its own and the
    // verdict is `NotAProbe` either way, so deleting the check changed
    // nothing any test could see.
    //
    // The input it uniquely decides is this one: a non-probe operation that
    // never reached the backend. Without the check that reads as
    // `ProbeNotDispatched` -- a fact about the host -- when it is really a
    // caller offering the wrong operation. The two have entirely different
    // remedies, which is why they are different arms, and this is the case
    // that keeps the distinction real.
    let echo = request("describe", json!({}));
    assert_eq!(
        assess(&echo, &Dispatch::NotDispatched(NotDispatched::NotReached)),
        Health::Unhealthy(Unhealthy::NotAProbe),
        "offering describe as a probe is a caller's bug, not a backend that \
         could not be reached"
    );
    // And the control: the same dispatch with a real probe *is* a fact about
    // the host, so the check discriminates rather than answering NotAProbe to
    // everything.
    assert_eq!(
        assess(
            &request("screen_info", json!({})),
            &Dispatch::NotDispatched(NotDispatched::NotReached)
        ),
        Health::Unhealthy(Unhealthy::ProbeNotDispatched(NotDispatched::NotReached))
    );
}

#[test]
fn a_capture_is_not_a_probe_and_neither_is_any_operation_that_mutates() {
    // `capture` is read-only but is refused as a probe: a probe runs on every
    // supervision cycle and must be cheap. Everything that synthesises input
    // is refused for the far more serious reason.
    assert_eq!(
        PROBE_OPERATIONS.len(),
        2,
        "the probe pair, and only the pair"
    );
    assert!(!PROBE_OPERATIONS.contains(&Operation::Capture));
    assert!(!PROBE_OPERATIONS.contains(&Operation::Describe));
    for operation in Operation::ALL {
        if operation.mutates_target() {
            assert!(
                !PROBE_OPERATIONS.contains(&operation),
                "{operation:?} synthesises input and must never be a health probe"
            );
        }
    }
    // **No probe may mutate the target.** Stated over the pair itself, so a
    // future edit that added a click to `PROBE_OPERATIONS` turns this red.
    for operation in PROBE_OPERATIONS {
        assert!(
            !operation.mutates_target(),
            "{operation:?} is a health probe and must change nothing"
        );
        assert!(
            !operation.needs_capture_identity(),
            "{operation:?} is a health probe and must not depend on a capture"
        );
    }
}

#[test]
fn the_probe_allowlist_agrees_with_the_evidence_type() {
    // `PROBE_OPERATIONS` is written here and `ProbeEvidence::from_probe` has
    // its own rule in `tunnel-cua`. Two lists that must agree are two lists
    // that eventually do not, so the agreement is measured over the whole
    // operation set rather than kept in step by hand.
    for operation in Operation::ALL {
        let name = operation.name();
        let params = if operation == Operation::Capture {
            json!({"display": 0})
        } else if operation.mutates_target() {
            // A mutating operation's params would not validate without a
            // capture reference; the allowlist check below does not need one.
            continue;
        } else {
            json!({})
        };
        let Ok(request) = validate_request(
            json!({
                "version": tunnel_cua::SCHEMA_VERSION,
                "operation": name,
                "params": params,
            })
            .to_string()
            .as_bytes(),
            LIMIT,
        ) else {
            continue;
        };
        let evidence_says = ProbeEvidence::from_probe(&request, &ok()).is_some();
        let allowlist_says = PROBE_OPERATIONS.contains(&operation);
        assert_eq!(
            evidence_says, allowlist_says,
            "{name}: the allowlist and ProbeEvidence disagree about whether it is a probe"
        );
    }
}

#[test]
fn a_backend_that_is_present_but_unpermitted_is_unhealthy_and_says_why() {
    // The case this module exists for: the process is up, the socket answers,
    // and the OS has not granted accessibility or screen recording.
    let request = request("screen_info", json!({}));
    let denied = Dispatch::Dispatched(Completion::Failed {
        code: FailureCode::PermissionDenied,
    });
    assert_eq!(
        assess(&request, &denied),
        Health::Unhealthy(Unhealthy::ProbeFailed(FailureCode::PermissionDenied))
    );
    // Preserved as a permission denial rather than flattened into a generic
    // failure: the remedy is an operator granting something, not a retry.
    assert!(!assess(&request, &denied).permits_dispatch());
}

#[test]
fn a_probe_that_never_reached_the_backend_is_distinct_from_one_that_failed() {
    let request = request("screen_info", json!({}));
    assert_eq!(
        assess(
            &request,
            &Dispatch::NotDispatched(NotDispatched::NotReached)
        ),
        Health::Unhealthy(Unhealthy::ProbeNotDispatched(NotDispatched::NotReached))
    );
    assert_eq!(
        assess(
            &request,
            &Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost))
        ),
        Health::Unhealthy(Unhealthy::ProbeUnknown)
    );
}

#[test]
fn a_probe_lost_across_a_restart_is_unknown_rather_than_not_dispatched() {
    // The restart reason reaching the health verdict, so a supervisor that
    // restarts under its own probe does not read the lost probe as evidence
    // that nothing was sent.
    let request = request("cursor_position", json!({}));
    let lost =
        tunnel_cua::supervision::restart_outcome(tunnel_cua::supervision::InFlight::ReachedBackend);
    assert_eq!(
        assess(&request, &lost),
        Health::Unhealthy(Unhealthy::ProbeUnknown)
    );
}

#[test]
fn nothing_but_working_permits_a_dispatch() {
    assert!(!Health::NotStarted.permits_dispatch());
    assert!(!Health::Started.permits_dispatch());
    assert!(!Health::Exited.permits_dispatch());
    assert!(!Health::Unhealthy(Unhealthy::NotAProbe).permits_dispatch());
    assert!(assess(&request("screen_info", json!({})), &ok()).permits_dispatch());
}

#[test]
fn running_and_working_are_different_questions() {
    // The separation, asserted rather than only described: `Started` is a
    // running process that has proven nothing, and it must never be read as
    // permission to dispatch.
    assert!(Health::Started.process_is_running());
    assert!(!Health::Started.permits_dispatch());
    assert!(Health::Unhealthy(Unhealthy::ProbeUnknown).process_is_running());
    assert!(!Health::NotStarted.process_is_running());
    assert!(!Health::Exited.process_is_running());
}

#[test]
fn an_absent_capture_authority_is_unknown_and_permits_the_attempt() {
    // Chunk 1's measured finding, carried rather than re-derived: the
    // released server omits `desktop_capture_authorized` on the supported
    // 0.22.x SDK, so absent is the normal answer on a working host.
    let version_without_the_key =
        Dispatch::Dispatched(Completion::Ok(json!({"version": "0.3.46"})));
    let authority = capture_authority(&version_without_the_key);
    assert_eq!(authority, CaptureAuthority::Unknown);
    assert!(authority.permits_attempt());

    // And a backend that said `false` is taken at its word.
    let denied = Dispatch::Dispatched(Completion::Ok(json!({
        "desktop_capture_authorized": false
    })));
    assert_eq!(capture_authority(&denied), CaptureAuthority::Denied);
    assert!(!capture_authority(&denied).permits_attempt());
}

#[test]
fn a_version_reading_cannot_produce_a_health_verdict_at_all() {
    // The structural half of the anti-echo rule: `version` is not a
    // `computer.v1` operation, so there is no `Request` a caller could hand
    // `assess` that would let a `version` reading stand as health. What it
    // *can* produce is a capture authority, which is a capability input.
    assert!(tunnel_cua::Operation::parse("version").is_none());
    let version = Dispatch::Dispatched(Completion::Ok(json!({"version": "0.3.46"})));
    assert_eq!(capture_authority(&version), CaptureAuthority::Unknown);
}
