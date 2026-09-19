//! Capability negotiation, and the config-echo trap it is shaped around.

use super::*;
use crate::outcome::{Completion, Dispatch, FailureCode, NotDispatched, UnknownReason};
use serde_json::json;

fn probe_ok(status: serde_json::Value) -> Dispatch {
    Dispatch::Dispatched(Completion::Ok(status))
}

fn evidence() -> ProbeEvidence {
    ProbeEvidence::from_probe(
        Operation::ScreenInfo,
        &probe_ok(json!({"width": 1280, "height": 800})),
    )
    .expect("a dispatched, succeeded screen_info probe is evidence")
}

fn commands() -> Vec<String> {
    [
        "version",
        "screenshot",
        "get_screen_size",
        "get_cursor_position",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect()
}

fn everything() -> LocalConfiguration {
    Operation::ALL
        .into_iter()
        .fold(LocalConfiguration::none(), LocalConfiguration::with)
}

fn granted_everything() -> CallerGrant {
    Operation::ALL
        .into_iter()
        .fold(CallerGrant::none(), CallerGrant::with)
}

/// **The config-echo trap, tested as a type-level impossibility.**
///
/// Probe evidence exists only for a dispatched, succeeded probe. Everything
/// else — a refusal, a reported failure, an unknown outcome, a command that
/// never left the device — produces none, so no `UpstreamSupport` can be built
/// from it and nothing can be advertised.
#[test]
fn only_a_dispatched_succeeded_probe_is_evidence() {
    assert!(ProbeEvidence::from_probe(Operation::ScreenInfo, &probe_ok(json!({}))).is_some());
    assert!(ProbeEvidence::from_probe(Operation::CursorPosition, &probe_ok(json!({}))).is_some());

    for not_evidence in [
        Dispatch::NotDispatched(NotDispatched::NotReached),
        Dispatch::NotDispatched(NotDispatched::BackendUnavailable),
        Dispatch::NotDispatched(NotDispatched::BackendRejected { status: 401 }),
        Dispatch::Dispatched(Completion::Failed {
            code: FailureCode::PermissionDenied,
        }),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::SuccessAbsent)),
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost)),
    ] {
        assert!(
            ProbeEvidence::from_probe(Operation::ScreenInfo, &not_evidence).is_none(),
            "{not_evidence:?} must not be probe evidence"
        );
    }
}

/// `describe` is the config echo itself, and `capture` is too expensive to run
/// on a supervision cycle. Neither may stand in for the probe.
#[test]
fn describe_and_capture_are_refused_as_probes() {
    assert!(ProbeEvidence::from_probe(Operation::Describe, &probe_ok(json!({}))).is_none());
    assert!(ProbeEvidence::from_probe(Operation::Capture, &probe_ok(json!({}))).is_none());
    // Non-vacuity: the two that are accepted are accepted from the same value.
    assert!(ProbeEvidence::from_probe(Operation::ScreenInfo, &probe_ok(json!({}))).is_some());
}

/// **`desktop_capture_authorized` is absent-by-default, not false.**
///
/// Chunk 1 measured this on the released 0.3.46 artifact: the key became
/// conditional on `hasattr`, so the supported 0.22.x SDK omits it. Reading
/// absence as denial would refuse capture on every correctly-permissioned
/// host.
#[test]
fn an_absent_capture_authority_is_unknown_and_unknown_permits_an_attempt() {
    assert_eq!(
        CaptureAuthority::from_status(&json!({"desktop_unlocked": true})),
        CaptureAuthority::Unknown,
        "an absent key must never read as Denied"
    );
    assert_eq!(
        CaptureAuthority::from_status(&json!({})),
        CaptureAuthority::Unknown
    );
    // Not inferred from a neighbouring key either.
    assert_eq!(
        CaptureAuthority::from_status(&json!({"desktop_unlocked": false})),
        CaptureAuthority::Unknown
    );
    // A non-boolean is reported as not known rather than as denied.
    for value in [json!("true"), json!(1), json!(null)] {
        assert_eq!(
            CaptureAuthority::from_status(&json!({ "desktop_capture_authorized": value })),
            CaptureAuthority::Unknown,
            "value={value}"
        );
    }
    // The two states the backend can actually assert.
    assert_eq!(
        CaptureAuthority::from_status(&json!({"desktop_capture_authorized": true})),
        CaptureAuthority::Granted
    );
    assert_eq!(
        CaptureAuthority::from_status(&json!({"desktop_capture_authorized": false})),
        CaptureAuthority::Denied
    );

    assert!(CaptureAuthority::Unknown.permits_attempt());
    assert!(CaptureAuthority::Granted.permits_attempt());
    assert!(!CaptureAuthority::Denied.permits_attempt());
}

#[test]
fn the_negotiated_set_is_the_intersection_of_all_three_inputs() {
    let upstream = UpstreamSupport::new(&commands(), evidence());

    // All three agree on everything.
    let all = negotiate(&everything(), &upstream, &granted_everything());
    assert_eq!(all.len(), Operation::ALL.len());

    // Local configuration alone narrows it.
    let local_narrow = negotiate(
        &LocalConfiguration::none().with(Operation::ScreenInfo),
        &upstream,
        &granted_everything(),
    );
    assert_eq!(
        local_narrow.into_iter().collect::<Vec<_>>(),
        vec![Operation::ScreenInfo]
    );

    // The grant alone narrows it.
    let grant_narrow = negotiate(
        &everything(),
        &upstream,
        &CallerGrant::none().with(Operation::CursorPosition),
    );
    assert_eq!(
        grant_narrow.into_iter().collect::<Vec<_>>(),
        vec![Operation::CursorPosition]
    );

    // Upstream support alone narrows it: a backend that does not advertise
    // `screenshot` (the VNC-narrowed registry is the real case) cannot be
    // asked for a capture however it was configured or granted.
    let without_screenshot: Vec<String> = commands()
        .into_iter()
        .filter(|name| name != "screenshot")
        .collect();
    let narrowed = UpstreamSupport::new(&without_screenshot, evidence());
    let upstream_narrow = negotiate(&everything(), &narrowed, &granted_everything());
    assert!(!upstream_narrow.contains(&Operation::Capture));
    assert!(upstream_narrow.contains(&Operation::ScreenInfo));

    // And the safe answer is reachable: nothing enabled, nothing advertised.
    assert!(
        negotiate(
            &LocalConfiguration::none(),
            &upstream,
            &granted_everything()
        )
        .is_empty()
    );
    assert!(negotiate(&everything(), &upstream, &CallerGrant::none()).is_empty());
}

/// An explicit `false` from the backend removes capture even when all three
/// sets contain it — and an absent key does not.
#[test]
fn a_denied_capture_authority_removes_capture_and_an_absent_one_does_not() {
    let denied = UpstreamSupport::new(
        &commands(),
        ProbeEvidence::from_probe(
            Operation::ScreenInfo,
            &probe_ok(json!({"desktop_capture_authorized": false})),
        )
        .unwrap(),
    );
    let set = negotiate(&everything(), &denied, &granted_everything());
    assert!(!set.contains(&Operation::Capture));
    // The other three are untouched: the gate is capture-specific.
    assert!(set.contains(&Operation::ScreenInfo));
    assert!(set.contains(&Operation::CursorPosition));
    assert!(set.contains(&Operation::Describe));

    // Absent: capture stays in, which is the whole absent-is-not-false point.
    let absent = UpstreamSupport::new(&commands(), evidence());
    assert!(negotiate(&everything(), &absent, &granted_everything()).contains(&Operation::Capture));
}

/// `describe` maps to no single command, so it must not be excluded merely
/// because a backend's registry is narrow.
#[test]
fn describe_survives_a_narrowed_registry_because_it_is_not_a_command() {
    let bare = UpstreamSupport::new(&[], evidence());
    assert!(bare.supports(Operation::Describe));
    assert!(!bare.supports(Operation::Capture));
    assert!(!bare.supports(Operation::ScreenInfo));
    assert_eq!(
        negotiate(&everything(), &bare, &granted_everything())
            .into_iter()
            .collect::<Vec<_>>(),
        vec![Operation::Describe]
    );
}

/// An empty local configuration is the default, so a CUA export configured by
/// forgetting to configure it exports nothing.
#[test]
fn the_default_local_configuration_and_grant_are_empty() {
    let upstream = UpstreamSupport::new(&commands(), evidence());
    assert!(
        negotiate(
            &LocalConfiguration::default(),
            &upstream,
            &CallerGrant::default()
        )
        .is_empty()
    );
    for operation in Operation::ALL {
        assert!(!LocalConfiguration::none().contains(operation));
        assert!(!CallerGrant::none().contains(operation));
    }
}
