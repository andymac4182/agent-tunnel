//! **The input half, judged against the fixture's own ledger.**
//!
//! Four claims are made here, and each is written so that the obvious cheap
//! version of it would fail:
//!
//! 1. **A click happens once.** Not "we sent one click" — the fixture counts
//!    the clicks it performed, and `double_click` contributes **2**, so a
//!    counter of dispatches would read 1 where this reads 2. That control is
//!    `a_click_happens_once_and_the_double_click_control_reads_two`.
//! 2. **A second agent is refused because the first holds the lease.** The
//!    first agent's holding is established by it *successfully clicking*, and
//!    the second agent's competence is established by it clicking once the
//!    lease is released. A refusal with neither leg proves nothing.
//! 3. **A rotation never repeats a click.** The carrier rotates across a lost
//!    answer; the ledger still shows one click afterwards, and the profile
//!    reports the retry as unsafe.
//! 4. **Capture identity, dimensions, display scale and target identity flow
//!    into the action.** The fixture serves a 2× capture, and the coordinate
//!    that arrives at the backend is the converted one.
//!
//! Nothing here installs, executes or contacts a real `computer-server`, and
//! nothing touches a screen or an input device. The fixture's "clicks" are
//! integers in a `Vec`.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Value, json};

use tunnel_cua::Operation;
use tunnel_cua::capture::CaptureRefusal;
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::lease::{GrantRevision, LeaseRefusal, SessionId, TargetSession};
use tunnel_cua::outcome::{Completion, Dispatch, InputRefusal, NotDispatched};
use tunnel_cua::schema::{Response, ResponseOutcome};

use tunnel_cua_fixture::client::{DeviceState, Dispatcher, SessionFacade, request_body};
use tunnel_cua_fixture::{Fault, FixtureBackend, SCREEN_HEIGHT, SCREEN_WIDTH};

const LIMIT: u64 = tunnel_cua::DEFAULT_REQUEST_BODY_LIMIT;

fn target() -> TargetSession {
    TargetSession::new("console:1")
}

/// A device with two sessions on it, both fully granted, both pointed at the
/// same target OS session. This is the two-agent situation the lease exists
/// for.
fn two_agents(backend: &FixtureBackend) -> (Arc<DeviceState>, SessionFacade, SessionFacade) {
    let state = DeviceState::new();
    let endpoint = BackendEndpoint::new(backend.address()).expect("the fixture binds loopback");
    let facade = |session| {
        SessionFacade::new(
            Arc::clone(&state),
            Dispatcher::new(endpoint, BTreeSet::from(Operation::ALL)),
            SessionId::new(session),
            target(),
        )
    };
    let first = facade(1);
    let second = facade(2);
    (state, first, second)
}

/// Capture through `agent`, and return the identity the device issued.
async fn capture(agent: &SessionFacade) -> u64 {
    let dispatch = agent
        .handle(&request_body("capture", json!({})), LIMIT)
        .await;
    let Dispatch::Dispatched(Completion::Ok(result)) = dispatch else {
        panic!("a capture should succeed: {dispatch:?}");
    };
    result
        .get("capture")
        .and_then(Value::as_u64)
        .expect("a successful capture issues an identity the consumer can carry")
}

fn click(capture: u64, x: u32, y: u32) -> Vec<u8> {
    request_body("click", json!({"capture": capture, "x": x, "y": y}))
}

/// **The click counter, and the control that shows it counts effects.**
///
/// One `click` exchange leaves one ledger entry and **one** click. One
/// `double_click` exchange leaves one ledger entry and **two** clicks. The
/// second number is the whole point: a counter that incremented per dispatch —
/// in the harness, or in the client — would report 1 for the double click and
/// would be indistinguishable from this one on every other row.
#[tokio::test]
async fn a_click_happens_once_and_the_double_click_control_reads_two() {
    let backend = FixtureBackend::start().await.unwrap();
    let (_state, agent, _idle) = two_agents(&backend);
    agent.acquire_input_lease().expect("the target is free");
    let identity = capture(&agent).await;

    assert_eq!(backend.ledger().pointer_clicks(), 0, "nothing has clicked");

    let dispatch = agent.handle(&click(identity, 10, 20), LIMIT).await;
    assert!(
        matches!(dispatch, Dispatch::Dispatched(Completion::Ok(_))),
        "{dispatch:?}"
    );
    assert_eq!(backend.ledger().count("left_click"), 1);
    assert_eq!(
        backend.ledger().pointer_clicks(),
        1,
        "one click command, one click"
    );

    // **The control.** One more command; two more clicks.
    let entries_before = backend.ledger().len();
    let dispatch = agent
        .handle(
            &request_body(
                "double_click",
                json!({"capture": identity, "x": 10, "y": 20}),
            ),
            LIMIT,
        )
        .await;
    assert!(matches!(dispatch, Dispatch::Dispatched(Completion::Ok(_))));
    assert_eq!(
        backend.ledger().len() - entries_before,
        1,
        "a double click is one command"
    );
    assert_eq!(
        backend.ledger().pointer_clicks(),
        3,
        "and two clicks, so the counter is counting effects rather than dispatches"
    );
    // Stated as the discriminator rather than left implicit: **two** clicking
    // commands were dispatched and **three** clicks happened. A counter of
    // dispatches would have reported two, and no arrangement of this run makes
    // those two numbers coincide.
    let clicking_commands =
        backend.ledger().count("left_click") + backend.ledger().count("double_click");
    assert_eq!(clicking_commands, 2);
    assert_eq!(backend.ledger().pointer_clicks(), 3);
    assert_ne!(
        u32::try_from(clicking_commands).unwrap(),
        backend.ledger().pointer_clicks(),
        "the effect count and the dispatch count must differ, or the counter proves nothing"
    );
    backend.stop();
}

/// **The refusal, with a holder that genuinely holds — end to end.**
///
/// Four legs, and the outer two are what stop this proving nothing: the first
/// agent's lease is demonstrated by a click that lands, and the second agent's
/// ability to click is demonstrated after the release.
#[tokio::test]
async fn a_second_agent_is_refused_only_while_the_first_genuinely_holds_the_lease() {
    let backend = FixtureBackend::start().await.unwrap();
    let (state, first, second) = two_agents(&backend);

    // Leg 1: the first agent holds the lease, and proves it by clicking.
    let grant = first.acquire_input_lease().expect("the target is free");
    assert_eq!(state.holder(&target()), Some(first.session()));
    let identity = capture(&first).await;
    assert!(matches!(
        first.handle(&click(identity, 1, 1), LIMIT).await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    assert_eq!(backend.ledger().pointer_clicks(), 1);

    // Leg 2: the second agent may still *read* — shared within the permitted
    // scope — and its capture supersedes the first agent's.
    let second_identity = capture(&second).await;
    assert_ne!(
        second_identity, identity,
        "a second capture, a new identity"
    );

    // Leg 3: the second agent is refused for input, at acquisition and at use,
    // and **nothing reaches the backend**.
    assert_eq!(
        second.acquire_input_lease().map(|_| ()),
        Err(LeaseRefusal::HeldByAnotherSession)
    );
    let clicks_before = backend.ledger().pointer_clicks();
    let entries_before = backend.ledger().len();
    let refused = second.handle(&click(second_identity, 1, 1), LIMIT).await;
    assert_eq!(
        refused,
        Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Lease(
            LeaseRefusal::HeldByAnotherSession
        )))
    );
    assert!(!refused.reached_the_backend());
    assert_eq!(backend.ledger().len(), entries_before, "nothing was sent");
    assert_eq!(backend.ledger().pointer_clicks(), clicks_before);

    // Leg 4 — the non-vacuity control. Release, and the same second agent
    // clicks successfully with the same request shape. So leg 3 refused the
    // lease, not the agent.
    first
        .release_input_lease(&grant)
        .expect("the first holds it");
    second
        .acquire_input_lease()
        .expect("the target is free now");
    assert_eq!(state.holder(&target()), Some(second.session()));
    assert!(matches!(
        second.handle(&click(second_identity, 1, 1), LIMIT).await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    assert_eq!(backend.ledger().pointer_clicks(), clicks_before + 1);
    backend.stop();
}

/// **A rotation leaves the lease held, and never repeats a click.**
///
/// The fixture records the click and then drops the connection, so the answer
/// is lost and the outcome is genuinely unknown — the ledger proves the click
/// arrived. The carrier then rotates. Afterwards: the lease is still the same
/// holding, the profile reports the operation as not safe to retry, and the
/// click count is still one.
#[tokio::test]
async fn a_rotation_leaves_the_lease_held_and_never_repeats_a_click() {
    let backend = FixtureBackend::start().await.unwrap();
    let (state, mut agent, _idle) = two_agents(&backend);
    let grant = agent.acquire_input_lease().unwrap();
    let identity = capture(&agent).await;

    backend.faults().set("left_click", Fault::DropAfterLedger);
    let dispatch = agent.handle(&click(identity, 5, 5), LIMIT).await;

    // Dispatched, outcome unknown — and the ledger is what says the click
    // really did arrive, so this is not a not-dispatched in disguise.
    assert_eq!(
        dispatch,
        Dispatch::Dispatched(Completion::Unknown(
            tunnel_cua::outcome::UnknownReason::TransportLost
        ))
    );
    assert_eq!(backend.ledger().pointer_clicks(), 1);
    assert!(
        !dispatch.retry_is_safe_for(Operation::Click),
        "a click whose outcome is unknown must never be retried"
    );

    // The carrier rotates underneath the session.
    let before = agent.carrier_generation();
    agent.rotate_carrier();
    assert_eq!(agent.carrier_generation(), before + 1);

    // The lease survives: same holder, same holding.
    assert_eq!(state.holder(&target()), Some(agent.session()));
    assert!(
        agent.release_input_lease(&grant).is_ok(),
        "the holding the agent took before the rotation is still the current one"
    );

    // And nothing re-sent the click. The count is unchanged, which is the only
    // form this claim can take: the rotation is not a retry mechanism, so
    // there is no code that could have resent it — and the assertion is what
    // stops that from becoming untrue silently.
    assert_eq!(
        backend.ledger().pointer_clicks(),
        1,
        "the rotation must not have repeated the click"
    );
    backend.stop();
}

/// **Where input operations sit relative to `retry_is_safe`.**
///
/// The narrow rule and its control, on one fixture: for a *read*, a
/// backend-reported failure is retryable; for a *click* with the identical
/// classification, it is not. Without the read leg this would be
/// indistinguishable from a rule that refused every retry.
#[tokio::test]
async fn an_input_operation_that_reached_the_backend_is_never_retryable() {
    let backend = FixtureBackend::start().await.unwrap();
    let (_state, agent, _idle) = two_agents(&backend);
    agent.acquire_input_lease().unwrap();
    let identity = capture(&agent).await;

    // The read: dispatched and failed, and a retry is permitted.
    backend.faults().set("get_screen_size", Fault::SuccessFalse);
    let read = agent
        .handle(&request_body("screen_info", json!({})), LIMIT)
        .await;
    assert!(matches!(
        read,
        Dispatch::Dispatched(Completion::Failed { .. })
    ));
    assert!(read.retry_is_safe(), "the transport permits it");
    assert!(
        read.retry_is_safe_for(Operation::ScreenInfo),
        "and so does the operation"
    );

    // The click: the same classification, and a retry is refused.
    backend.faults().set("left_click", Fault::SuccessFalse);
    let input = agent.handle(&click(identity, 1, 1), LIMIT).await;
    assert!(matches!(
        input,
        Dispatch::Dispatched(Completion::Failed { .. })
    ));
    assert!(
        input.retry_is_safe(),
        "the transport-level fact is unchanged, which is what makes the narrow rule load-bearing"
    );
    assert!(
        !input.retry_is_safe_for(Operation::Click),
        "an input operation that reached the backend is never retryable"
    );
    assert_eq!(backend.ledger().pointer_clicks(), 1);

    // And the wire says so too, so a consumer learns it without re-deriving
    // the rule.
    let rendered = Response::failed(Operation::Click, "backend_reported", "the backend refused");
    assert_eq!(rendered.outcome, ResponseOutcome::Failed);
    assert!(!rendered.error.as_ref().unwrap().retryable);
    let read_rendered = Response::failed(
        Operation::ScreenInfo,
        "backend_reported",
        "the backend refused",
    );
    assert!(read_rendered.error.as_ref().unwrap().retryable);
    backend.stop();
}

/// **The capture carry-forward, end to end, at a scale where it is not the
/// identity.**
///
/// The fixture serves a 2× capture: a 256×192 image of its 128×96 screen. A
/// click at image pixel (100, 80) must arrive at the backend as (50, 40), and
/// the fixture's ledger is what records the coordinate that arrived.
#[tokio::test]
async fn a_capture_identity_and_its_display_scale_flow_into_the_click() {
    let backend = FixtureBackend::start().await.unwrap();
    backend.capture_scale().set(200);
    let (_state, agent, _idle) = two_agents(&backend);
    agent.acquire_input_lease().unwrap();

    let dispatch = agent
        .handle(&request_body("capture", json!({})), LIMIT)
        .await;
    let Dispatch::Dispatched(Completion::Ok(result)) = dispatch else {
        panic!("a capture should succeed");
    };
    assert_eq!(result["width"], json!(u32::from(SCREEN_WIDTH) * 2));
    assert_eq!(result["height"], json!(u32::from(SCREEN_HEIGHT) * 2));
    assert_eq!(result["scale_percent"], json!(200));
    let identity = result["capture"].as_u64().expect("an identity was issued");

    agent.handle(&click(identity, 100, 80), LIMIT).await;
    assert_eq!(
        backend.ledger().points(),
        vec![(50, 40)],
        "the pixel must be converted through the capture's display scale"
    );

    // The control: the same pixel through a 1x capture arrives unchanged, so
    // the assertion above is reading the scale and not a constant.
    backend.capture_scale().set(100);
    let unscaled = capture(&agent).await;
    agent.handle(&click(unscaled, 100, 80), LIMIT).await;
    assert_eq!(backend.ledger().points(), vec![(50, 40), (100, 80)]);
    backend.stop();
}

/// **A stale or mismatched capture coordinate never reaches the backend.**
///
/// Four refusals, each with the ledger unchanged, and a fifth leg showing the
/// current capture is accepted — so the refusals are the capture check and not
/// a device that refuses every click.
#[tokio::test]
async fn a_stale_or_mismatched_capture_coordinate_never_reaches_the_backend() {
    let backend = FixtureBackend::start().await.unwrap();
    let (_state, agent, _idle) = two_agents(&backend);
    agent.acquire_input_lease().unwrap();

    let stale = capture(&agent).await;
    let fresh = capture(&agent).await;
    let before = backend.ledger().len();

    for (body, expected) in [
        (click(stale, 1, 1), CaptureRefusal::Superseded),
        (click(9_999, 1, 1), CaptureRefusal::Unknown),
        (
            click(fresh, u32::from(SCREEN_WIDTH), 1),
            CaptureRefusal::OutsideCapture,
        ),
        (
            click(fresh, 1, u32::from(SCREEN_HEIGHT)),
            CaptureRefusal::OutsideCapture,
        ),
    ] {
        let dispatch = agent.handle(&body, LIMIT).await;
        assert_eq!(
            dispatch,
            Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Capture(
                expected
            ))),
            "expected {expected:?}"
        );
        assert!(
            dispatch.retry_is_safe_for(Operation::Click),
            "nothing happened"
        );
    }
    assert_eq!(
        backend.ledger().len(),
        before,
        "every capture refusal is above the dispatch boundary"
    );
    assert_eq!(backend.ledger().pointer_clicks(), 0);

    // The control: the current capture, inside its bounds, does reach it.
    assert!(matches!(
        agent
            .handle(
                &click(
                    fresh,
                    u32::from(SCREEN_WIDTH) - 1,
                    u32::from(SCREEN_HEIGHT) - 1
                ),
                LIMIT
            )
            .await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    assert_eq!(backend.ledger().pointer_clicks(), 1);
    backend.stop();
}

/// A capture taken against another target does not authorize a click here.
///
/// The second facade drives a different target OS session, so its capture is a
/// coordinate on another machine's screen.
#[tokio::test]
async fn a_capture_from_another_target_does_not_authorize_a_click() {
    let backend = FixtureBackend::start().await.unwrap();
    let state = DeviceState::new();
    let endpoint = BackendEndpoint::new(backend.address()).unwrap();
    let here = SessionFacade::new(
        Arc::clone(&state),
        Dispatcher::new(endpoint, BTreeSet::from(Operation::ALL)),
        SessionId::new(1),
        TargetSession::new("console:1"),
    );
    let there = SessionFacade::new(
        Arc::clone(&state),
        Dispatcher::new(endpoint, BTreeSet::from(Operation::ALL)),
        SessionId::new(2),
        TargetSession::new("console:2"),
    );
    here.acquire_input_lease().unwrap();
    there.acquire_input_lease().expect("a different target");

    let theirs = capture(&there).await;
    let mine = capture(&here).await;
    let before = backend.ledger().len();

    assert_eq!(
        here.handle(&click(theirs, 1, 1), LIMIT).await,
        Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Capture(
            CaptureRefusal::TargetMismatch
        )))
    );
    assert_eq!(backend.ledger().len(), before);
    // Control: my own capture works, so the refusal is the target and not the
    // lease or the identity.
    assert!(matches!(
        here.handle(&click(mine, 1, 1), LIMIT).await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    backend.stop();
}

/// **M3-16 end to end: what a revoked grant does to a held lease.**
///
/// Both halves, because only one of them is closed. The holder is refused at
/// the point of use as soon as the device believes the revision advanced; the
/// target stays blocked until the lease is reconciled away; and nothing in
/// this repository drives either, because nothing tells a device that a grant
/// was revoked. See `docs/tasks.md` M5-C05.
#[tokio::test]
async fn a_revoked_grant_refuses_the_holder_but_only_a_reconcile_frees_the_target() {
    let backend = FixtureBackend::start().await.unwrap();
    let (state, mut first, second) = two_agents(&backend);
    first.acquire_input_lease().unwrap();
    let identity = capture(&first).await;
    assert!(matches!(
        first.handle(&click(identity, 1, 1), LIMIT).await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    let clicks = backend.ledger().pointer_clicks();

    // The device learns that the grant behind the lease has moved on.
    first.note_grant_revision(GrantRevision::new(1));

    // Half one, closed: the holder is refused, and nothing is dispatched.
    let refused = first.handle(&click(identity, 1, 1), LIMIT).await;
    assert_eq!(
        refused,
        Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Lease(
            LeaseRefusal::GrantRevoked
        )))
    );
    assert_eq!(backend.ledger().pointer_clicks(), clicks);

    // **And the holder cannot lift its own refusal by taking the lease
    // again**, which is the obvious client response to one and is what review
    // found this test stopping short of. If it could, the refusal above would
    // be advisory and the reconcile below would free nothing.
    assert_eq!(
        first.acquire_input_lease().map(|_| ()),
        Err(LeaseRefusal::GrantRevoked)
    );
    let still_refused = first.handle(&click(identity, 1, 1), LIMIT).await;
    assert_eq!(
        still_refused,
        Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Lease(
            LeaseRefusal::GrantRevoked
        )))
    );
    assert_eq!(backend.ledger().pointer_clicks(), clicks);

    // Half two, open: the target is still blocked, by a lease nobody may use.
    assert_eq!(
        second.acquire_input_lease().map(|_| ()),
        Err(LeaseRefusal::HeldByAnotherSession)
    );
    assert_eq!(state.holder(&target()), Some(first.session()));

    // Only an explicit reconcile frees it — and nothing calls this in
    // production, which is exactly what M5-C05 records.
    let freed = state.reconcile_grant(first.session(), GrantRevision::new(1));
    assert_eq!(freed, vec![target()]);
    second
        .acquire_input_lease()
        .expect("the target is free now");
    let theirs = capture(&second).await;
    assert!(matches!(
        second.handle(&click(theirs, 1, 1), LIMIT).await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    backend.stop();
}

/// **Never log typed text.**
///
/// The two places a keystroke could escape into a diagnostic are the validated
/// request — covered by a unit test in `plan.rs` — and the fixture's ledger,
/// which a failing assertion prints. This checks the second, and checks that
/// the text nevertheless reached the backend, so the redaction is not hiding a
/// dropped payload.
#[tokio::test]
async fn the_typed_text_reaches_the_backend_and_appears_in_no_diagnostic() {
    let backend = FixtureBackend::start().await.unwrap();
    let (_state, agent, _idle) = two_agents(&backend);
    agent.acquire_input_lease().unwrap();

    let secret = "correct horse battery staple";
    let dispatch = agent
        .handle(&request_body("type_text", json!({"text": secret})), LIMIT)
        .await;
    assert!(matches!(dispatch, Dispatch::Dispatched(Completion::Ok(_))));

    // It arrived: the fixture counted the characters it was asked to type.
    assert_eq!(backend.ledger().count("type_text"), 1);
    assert_eq!(
        backend.ledger().typed_characters(),
        secret.chars().count(),
        "the text really was delivered, so the redaction below is not hiding a drop"
    );

    // And it is nowhere in anything printable.
    let rendered = format!("{:?}", backend.ledger().entries());
    assert!(
        !rendered.contains("horse"),
        "the ledger rendered the typed text: {rendered}"
    );
    assert!(!format!("{dispatch:?}").contains("horse"));
    backend.stop();
}

/// **The central invariant, on the input half.**
///
/// `reached_the_backend() == (ledger entries added == 1)` for every input
/// operation, refusals included.
#[tokio::test]
async fn the_ledger_agrees_with_the_client_for_every_input_operation() {
    let backend = FixtureBackend::start().await.unwrap();
    let (_state, agent, unleased) = two_agents(&backend);
    agent.acquire_input_lease().unwrap();
    let identity = capture(&agent).await;
    let c = identity;

    let bodies = [
        request_body("click", json!({"capture": c, "x": 1, "y": 1})),
        request_body(
            "click",
            json!({"capture": c, "x": 1, "y": 1, "button": "right"}),
        ),
        request_body("double_click", json!({"capture": c, "x": 1, "y": 1})),
        request_body("move", json!({"capture": c, "x": 2, "y": 2})),
        request_body(
            "drag",
            json!({"capture": c, "x": 1, "y": 1, "to_x": 3, "to_y": 3}),
        ),
        request_body(
            "scroll",
            json!({"capture": c, "x": 1, "y": 1, "dx": 0, "dy": -2}),
        ),
        request_body("type_text", json!({"text": "hi"})),
        request_body("press_key", json!({"key": "Return"})),
        request_body("hotkey", json!({"keys": ["cmd", "c"]})),
    ];

    let mut commands = Vec::new();
    for body in &bodies {
        let before = backend.ledger().len();
        let dispatch = agent.handle(body, LIMIT).await;
        let added = backend.ledger().len() - before;
        assert_eq!(
            dispatch.reached_the_backend(),
            added == 1,
            "the client and the ledger disagree for {}",
            String::from_utf8_lossy(body)
        );
        commands.extend(
            backend.ledger().entries()[before..]
                .iter()
                .map(|e| e.command.clone()),
        );
    }
    assert_eq!(
        commands,
        vec![
            "left_click",
            "right_click",
            "double_click",
            "move_cursor",
            "drag",
            "scroll",
            "type_text",
            "press_key",
            "hotkey",
        ],
        "each operation dispatched exactly the canonical command the table names"
    );

    // And the same nine, from a session without the lease, add nothing.
    let before = backend.ledger().len();
    for body in &bodies {
        let dispatch = unleased.handle(body, LIMIT).await;
        assert!(!dispatch.reached_the_backend());
        assert_eq!(
            dispatch.reached_the_backend(),
            backend.ledger().len() > before
        );
    }
    assert_eq!(backend.ledger().len(), before);
    backend.stop();
}

/// **M3-15 at the boundary a consumer sees.** A peer-unavailable refusal is
/// retryable for a read and not for a click, and the wire carries the
/// difference.
#[test]
fn a_peer_unavailable_refusal_is_not_auto_retried_for_an_input_operation() {
    let refusal = Dispatch::NotDispatched(NotDispatched::PeerUnavailable);
    assert!(
        refusal.retry_is_safe(),
        "nothing was dispatched on this attempt"
    );
    assert!(refusal.retry_is_safe_for(Operation::Capture));
    assert!(
        !refusal.retry_is_safe_for(Operation::Click),
        "a rotation freeze is indistinguishable from a fault state, so a click is never retried"
    );

    for operation in Operation::INPUT {
        assert!(
            !refusal.retry_is_safe_for(operation),
            "{}",
            operation.name()
        );
        let rendered = Response::not_dispatched_retryable(
            operation.name(),
            "peer_unavailable",
            "the device-side peer was not ready",
            refusal.retry_is_safe_for(operation),
        );
        assert_eq!(rendered.outcome, ResponseOutcome::NotDispatched);
        assert!(!rendered.error.as_ref().unwrap().retryable);
    }
    // The control: every other not-dispatched refusal *is* retryable for an
    // input operation, so the rule is about this one refusal and not about
    // input operations being un-retryable everywhere.
    let schema_refusal = Dispatch::NotDispatched(NotDispatched::NotPermitted);
    assert!(schema_refusal.retry_is_safe_for(Operation::Click));
}

/// **The wire constructor that derives retryability rather than assuming it.**
///
/// Review's point was that the M3-15 rule reached the wire only if a caller
/// remembered to compute it, and `Response::not_dispatched`'s hardcoded `true`
/// was the easy path. `not_dispatched_for` reads the rule from
/// `retry_is_safe_for`, so the two cannot drift.
#[test]
fn the_wire_derives_retryability_from_the_refusal_and_the_operation() {
    let rendered = Response::not_dispatched_for(
        Operation::Click,
        NotDispatched::PeerUnavailable,
        "peer_unavailable",
        "the device-side peer was not ready",
    );
    assert_eq!(rendered.outcome, ResponseOutcome::NotDispatched);
    assert!(
        !rendered.error.as_ref().unwrap().retryable,
        "a click is never auto-retried through a peer-unavailable refusal"
    );

    // Three controls, so this is reading the rule rather than refusing
    // everything: the same refusal for a read is retryable; a different
    // refusal for the same click is retryable; and the operation name is
    // echoed from the operation rather than from a caller's string.
    let read = Response::not_dispatched_for(
        Operation::Capture,
        NotDispatched::PeerUnavailable,
        "peer_unavailable",
        "the device-side peer was not ready",
    );
    assert!(read.error.as_ref().unwrap().retryable);

    let other = Response::not_dispatched_for(
        Operation::Click,
        NotDispatched::NotPermitted,
        "not_permitted",
        "the operation is not in the negotiated set",
    );
    assert!(other.error.as_ref().unwrap().retryable);
    assert_eq!(rendered.operation, "click");
}

/// `retry_is_safe_for` is **never wider** than `retry_is_safe`, over the whole
/// cross-product. Two methods where one could be called by mistake need this,
/// or the narrow one is only narrow where somebody remembered.
#[test]
fn retry_is_safe_for_is_never_wider_than_retry_is_safe() {
    let dispatches = [
        Dispatch::NotDispatched(NotDispatched::NotPermitted),
        Dispatch::NotDispatched(NotDispatched::NotReached),
        Dispatch::NotDispatched(NotDispatched::BackendUnavailable),
        Dispatch::NotDispatched(NotDispatched::PeerUnavailable),
        Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Lease(
            LeaseRefusal::NotHeld,
        ))),
        Dispatch::AnsweredLocally(json!({})),
        Dispatch::Dispatched(Completion::Ok(json!({}))),
        Dispatch::Dispatched(Completion::Failed {
            code: tunnel_cua::outcome::FailureCode::BackendReported,
        }),
        Dispatch::Dispatched(Completion::Unknown(
            tunnel_cua::outcome::UnknownReason::TransportLost,
        )),
    ];
    let mut narrower_somewhere = false;
    for dispatch in &dispatches {
        for operation in Operation::ALL {
            let wide = dispatch.retry_is_safe();
            let narrow = dispatch.retry_is_safe_for(operation);
            assert!(
                !narrow || wide,
                "{dispatch:?} / {} is retryable for the operation but not for the transport",
                operation.name()
            );
            if wide && !narrow {
                narrower_somewhere = true;
            }
        }
    }
    assert!(
        narrower_somewhere,
        "the narrow method never differs, so it is decorative"
    );
}
