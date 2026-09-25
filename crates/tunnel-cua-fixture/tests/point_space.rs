//! **M5-C19 option (b), judged against the fixture's ledger**: a device told
//! its display's size in input point space derives each capture's scale from
//! that capture's own PNG, and a declaration the capture contradicts refuses
//! every coordinate instead of clicking somewhere else.
//!
//! Applied by default pending owner confirmation (2026-09-25); see
//! `docs/tasks.md` M5-C19. Nothing here touches a screen or an input device:
//! the fixture's clicks are integers in a `Vec`.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Value, json};

use tunnel_cua::Operation;
use tunnel_cua::capture::{CaptureRefusal, PointSpace};
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::lease::{SessionId, TargetSession};
use tunnel_cua::outcome::{Completion, Dispatch, InputRefusal, NotDispatched};

use tunnel_cua_fixture::client::{DeviceState, Dispatcher, SessionFacade, request_body};
use tunnel_cua_fixture::{FixtureBackend, SCREEN_HEIGHT, SCREEN_WIDTH};

const LIMIT: u64 = tunnel_cua::DEFAULT_REQUEST_BODY_LIMIT;

fn agent(backend: &FixtureBackend) -> (Arc<DeviceState>, SessionFacade) {
    let state = DeviceState::new();
    let endpoint = BackendEndpoint::new(backend.address()).expect("the fixture binds loopback");
    let facade = SessionFacade::new(
        Arc::clone(&state),
        Dispatcher::new(endpoint, BTreeSet::from(Operation::ALL)),
        SessionId::new(1),
        TargetSession::new("console:1"),
    );
    facade.acquire_input_lease().expect("an idle target");
    (state, facade)
}

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
        .expect("a successful capture issues an identity")
}

fn click(capture: u64, x: u32, y: u32) -> Vec<u8> {
    request_body("click", json!({"capture": capture, "x": x, "y": y}))
}

fn screen() -> PointSpace {
    PointSpace::new(u32::from(SCREEN_WIDTH), u32::from(SCREEN_HEIGHT)).expect("fixture screen")
}

/// **No percentage is declared anywhere in this test.** The fixture serves a
/// 2x capture (256x192 of its 128x96 screen); the device knows only the point
/// size, and pixel (100, 80) must arrive as point (50, 40). The same
/// declaration then serves a 1x capture, and the same pixel arrives unchanged
/// -- one declaration, two correct ratios, which a declared factor cannot do.
#[tokio::test]
async fn a_declared_point_space_derives_the_scale_of_every_capture() {
    let backend = FixtureBackend::start().await.unwrap();
    let (state, agent) = agent(&backend);
    state.declare_point_space(Some(screen()));

    backend.capture_scale().set(200);
    let doubled = capture(&agent).await;
    assert!(matches!(
        agent.handle(&click(doubled, 100, 80), LIMIT).await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));

    backend.capture_scale().set(100);
    let identity = capture(&agent).await;
    assert!(matches!(
        agent.handle(&click(identity, 100, 80), LIMIT).await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));

    assert_eq!(backend.ledger().points(), vec![(50, 40), (100, 80)]);
    assert_eq!(backend.ledger().pointer_clicks(), 2);
    backend.stop();
}

/// **A wrong declaration refuses; it does not click elsewhere.** A point
/// space with the screen's axes swapped contradicts every capture's aspect
/// ratio, so the capture is recorded with no scale and every coordinate on it
/// is refused by name, with nothing dispatched. Clearing the declaration is
/// the M5-C14 behaviour, also a refusal. The control declares the right size
/// and the same pixel lands, so the refusals were the declaration.
#[tokio::test]
async fn a_contradicted_or_missing_point_space_refuses_every_coordinate() {
    let backend = FixtureBackend::start().await.unwrap();
    backend.capture_scale().set(200);
    let (state, agent) = agent(&backend);
    let refused = Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Capture(
        CaptureRefusal::ScaleUndeclared,
    )));

    let swapped = PointSpace::new(u32::from(SCREEN_HEIGHT), u32::from(SCREEN_WIDTH)).unwrap();
    state.declare_point_space(Some(swapped));
    let identity = capture(&agent).await;
    assert_eq!(agent.handle(&click(identity, 100, 80), LIMIT).await, refused);
    assert_eq!(
        agent
            .handle(
                &request_body("move", json!({"capture": identity, "x": 1, "y": 1})),
                LIMIT
            )
            .await,
        refused
    );

    state.declare_point_space(None);
    let undeclared = capture(&agent).await;
    assert_eq!(agent.handle(&click(undeclared, 100, 80), LIMIT).await, refused);

    assert!(
        backend.ledger().points().is_empty(),
        "no coordinate may reach the backend on a contradicted or missing declaration"
    );
    assert_eq!(backend.ledger().pointer_clicks(), 0);

    state.declare_point_space(Some(screen()));
    let declared = capture(&agent).await;
    assert!(matches!(
        agent.handle(&click(declared, 100, 80), LIMIT).await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    assert_eq!(backend.ledger().points(), vec![(50, 40)]);
    backend.stop();
}

/// A declared point space outranks a declared percentage: an operator who
/// set both gets the ratio derived from the image, never a stale factor.
#[tokio::test]
async fn a_point_space_outranks_a_declared_percentage() {
    let backend = FixtureBackend::start().await.unwrap();
    backend.capture_scale().set(200);
    let (state, agent) = agent(&backend);
    state.declare_scale_percent(Some(100));
    state.declare_point_space(Some(screen()));
    let identity = capture(&agent).await;
    agent.handle(&click(identity, 100, 80), LIMIT).await;
    assert_eq!(backend.ledger().points(), vec![(50, 40)]);
    backend.stop();
}
