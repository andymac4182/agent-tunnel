//! End-to-end dispatch against the fixture backend, judged against the
//! fixture's **own ledger**.
//!
//! **Proof 1 of the four host-untouched proofs: dispatched commands equal
//! fixture-ledger entries.** Every test here asserts the ledger, not a
//! harness-side counter, because a harness counter increments where the
//! harness *believes* it dispatched and therefore proves only what the harness
//! believed.
//!
//! **Proof 4 is here too**: every capture is verified by decoding markers, and
//! `a_byte_count_would_not_have_caught_the_wrong_display` is the control
//! showing that a length comparison could not have.
//!
//! Nothing in this file installs, executes or contacts a real
//! `computer-server`, and nothing touches a screen or an input device.

use std::collections::BTreeSet;

use serde_json::json;

use tunnel_cua::Operation;
use tunnel_cua::capability::{
    CallerGrant, CaptureAuthority, LocalConfiguration, ProbeEvidence, UpstreamSupport,
};
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::lease::{SessionId, TargetSession};
use tunnel_cua::marker;
use tunnel_cua::operation::{Deferral, Refusal};
use tunnel_cua::outcome::{Completion, Dispatch, NotDispatched};
use tunnel_cua::schema::{SchemaError, validate_request};

use tunnel_cua_fixture::client::{
    DeviceState, Dispatcher, SessionFacade, read_commands, request_body,
};
use tunnel_cua_fixture::{
    CURSOR, FixtureBackend, IMAGE_SEED, LedgerEntry, SCREEN_HEIGHT, SCREEN_WIDTH, from_hex,
};

const LIMIT: u64 = tunnel_cua::DEFAULT_REQUEST_BODY_LIMIT;

/// Build a dispatcher permitting everything the backend and a full grant
/// allow, having actually probed the backend.
/// The one session every read-only test drives. It holds **no input lease**,
/// which is the point: reads are shared, so none of these tests needs one.
fn facade(dispatcher: Dispatcher) -> SessionFacade {
    SessionFacade::new(
        DeviceState::new(),
        dispatcher,
        SessionId::new(1),
        TargetSession::new("console:1"),
    )
}

async fn negotiated(backend: &FixtureBackend) -> SessionFacade {
    let endpoint = BackendEndpoint::new(backend.address()).expect("the fixture binds loopback");
    let commands = read_commands(endpoint)
        .await
        .expect("the fixture lists commands");

    // The probe is a real dispatch. It is the only thing that can produce
    // `ProbeEvidence`, and it leaves its own ledger entry -- which every test
    // below accounts for.
    let bare = facade(Dispatcher::new(
        endpoint,
        BTreeSet::from([Operation::ScreenInfo]),
    ));
    let probe_body = request_body("screen_info", json!({}));
    let probe = bare.handle(&probe_body, LIMIT).await;
    let probe_request = validate_request(&probe_body, LIMIT).expect("a valid probe request");
    let evidence = ProbeEvidence::from_probe(&probe_request, &probe)
        .expect("a succeeded screen_info probe is evidence");

    // The capture authority comes from a **`version`** reading, which is the
    // response that carries `desktop_capture_authorized`. It is a second real
    // dispatch and leaves its own ledger entry too.
    let capture_authority =
        CaptureAuthority::from_version_reading(&bare.dispatcher().read_version().await);

    let local = Operation::ALL
        .into_iter()
        .fold(LocalConfiguration::none(), LocalConfiguration::with);
    let grant = Operation::ALL
        .into_iter()
        .fold(CallerGrant::none(), CallerGrant::with);
    facade(Dispatcher::negotiated(
        endpoint,
        &local,
        &UpstreamSupport::new(&commands, evidence, capture_authority),
        &grant,
    ))
}

/// The two discovery dispatches `negotiated` performs, so every ledger
/// assertion accounts for them explicitly rather than by an off-by-one nobody
/// notices.
///
/// There are two because capability discovery genuinely needs two different
/// responses: a probe the OS permission layer gates (`get_screen_size`), and
/// the `version` reading that carries `desktop_capture_authorized`.
fn discovery_entries() -> Vec<LedgerEntry> {
    vec![
        LedgerEntry::new("get_screen_size", Some(0)),
        LedgerEntry::new("version", None),
    ]
}

#[tokio::test]
async fn each_read_only_operation_dispatches_exactly_the_command_the_table_names() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = negotiated(&backend).await;

    for (operation, expected) in [
        ("screen_info", Some("get_screen_size")),
        ("cursor_position", Some("get_cursor_position")),
        ("capture", Some("screenshot")),
        // `describe` dispatches nothing at all.
        ("describe", None),
    ] {
        let before = backend.ledger().len();
        let dispatch = dispatcher
            .handle(&request_body(operation, json!({})), LIMIT)
            .await;
        let added = &backend.ledger().entries()[before..];
        match expected {
            // `describe` is answered from device-side state. It must report
            // itself as such -- **not** as a dispatch, which would make
            // `reached_the_backend()` true for an operation that sent nothing.
            None => {
                assert!(
                    matches!(dispatch, Dispatch::AnsweredLocally(_)),
                    "{operation} should have been answered locally, got {dispatch:?}"
                );
                assert!(
                    added.is_empty(),
                    "describe must dispatch no command, it added {added:?}"
                );
            }
            Some(command) => {
                assert!(
                    matches!(dispatch, Dispatch::Dispatched(Completion::Ok(_))),
                    "{operation} should have succeeded, got {dispatch:?}"
                );
                assert_eq!(added.len(), 1, "{operation} dispatched {added:?}");
                assert_eq!(added[0].command, command);
            }
        }
        // The invariant, on every operation rather than only on the ones the
        // fault table covers.
        assert_eq!(
            dispatch.reached_the_backend(),
            added.len() == 1,
            "{operation}: the client and the ledger disagree"
        );
    }
    backend.stop();
}

/// **Proof 1, stated as one equality.** The commands the dispatcher believes
/// it sent are exactly the entries the fixture recorded, in order — including
/// the probe, and including the operations that dispatch nothing.
#[tokio::test]
async fn the_ledger_equals_the_commands_that_were_dispatched_and_nothing_more() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = negotiated(&backend).await;

    for (operation, params) in [
        ("describe", json!({})),
        ("cursor_position", json!({})),
        ("capture", json!({"display": 2})),
        ("screen_info", json!({"display": 1})),
        ("describe", json!({})),
    ] {
        dispatcher
            .handle(&request_body(operation, params), LIMIT)
            .await;
    }

    let mut expected = discovery_entries();
    expected.extend([
        LedgerEntry::new("get_cursor_position", None),
        LedgerEntry::new("screenshot", Some(2)),
        LedgerEntry::new("get_screen_size", Some(1)),
    ]);
    assert_eq!(
        backend.ledger().entries(),
        expected,
        "the ledger is the authority on what the backend was asked to do"
    );
    backend.stop();
}

/// **The allowlist fails closed, measured on the ledger.**
///
/// The fixture registers every input command, so a dispatcher that forwarded
/// one would leave an entry. None appears, and the ledger is unchanged from
/// before the attempt — which is what makes this a measurement rather than an
/// assumption about a backend that could not have answered anyway.
#[tokio::test]
async fn no_refused_operation_reaches_the_backend() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = negotiated(&backend).await;
    let before = backend.ledger().entries();

    for (operation, expected) in [
        (
            "accessibility_tree",
            SchemaError::Operation(Refusal::Deferred(Deferral::NeedsBackendProbe)),
        ),
        ("screenshot", SchemaError::Operation(Refusal::Unknown)),
        ("left_click", SchemaError::Operation(Refusal::Unknown)),
        ("run_command", SchemaError::Operation(Refusal::Unknown)),
        ("clcik", SchemaError::Operation(Refusal::Unknown)),
    ] {
        let dispatch = dispatcher
            .handle(&request_body(operation, json!({})), LIMIT)
            .await;
        assert_eq!(
            dispatch,
            Dispatch::NotDispatched(NotDispatched::Schema(expected)),
            "operation={operation}"
        );
        assert!(dispatch.retry_is_safe());
        assert!(!dispatch.reached_the_backend());
    }

    assert_eq!(
        backend.ledger().entries(),
        before,
        "a refused operation must leave the ledger untouched"
    );
    // Non-vacuity: the fixture really would have recorded an input command if
    // one had reached it. `left_click` is registered; the profile is what
    // refuses it, not the backend.
    assert!(tunnel_cua_fixture::REGISTERED_COMMANDS.contains(&"left_click"));
    assert!(tunnel_cua_fixture::REGISTERED_COMMANDS.contains(&"type_text"));
    backend.stop();
}

/// Every pre-dispatch refusal leaves the ledger empty, and the schema
/// rejections are the same set the unit tests cover — this is the claim that
/// they really do sit above the dispatch boundary.
#[tokio::test]
async fn every_schema_rejection_leaves_the_ledger_empty() {
    let backend = FixtureBackend::start().await.unwrap();
    let endpoint = BackendEndpoint::new(backend.address()).unwrap();
    let dispatcher = facade(Dispatcher::new(endpoint, BTreeSet::from(Operation::ALL)));

    for body in [
        b"".to_vec(),
        b"not json".to_vec(),
        b"[]".to_vec(),
        br#"{"version":"computer.v2","operation":"capture","params":{}}"#.to_vec(),
        br#"{"version":"computer.v1","operation":"capture"}"#.to_vec(),
        br#"{"version":"computer.v1","operation":"capture","params":{},"extra":1}"#.to_vec(),
        br#"{"version":"computer.v1","operation":"capture","params":{"display":999}}"#.to_vec(),
        br#"{"version":"computer.v1","operation":"capture","operation":"click","params":{}}"#
            .to_vec(),
    ] {
        let dispatch = dispatcher.handle(&body, LIMIT).await;
        assert!(
            matches!(dispatch, Dispatch::NotDispatched(NotDispatched::Schema(_))),
            "body={:?} gave {dispatch:?}",
            String::from_utf8_lossy(&body)
        );
    }
    assert!(
        backend.ledger().is_empty(),
        "validation runs before dispatch, so nothing reached the backend: {:?}",
        backend.ledger().entries()
    );
    backend.stop();
}

/// An operation outside the negotiated set is refused before dispatch, even
/// though the backend advertises it and would answer.
#[tokio::test]
async fn an_ungranted_operation_is_refused_before_dispatch() {
    let backend = FixtureBackend::start().await.unwrap();
    let endpoint = BackendEndpoint::new(backend.address()).unwrap();
    let dispatcher = facade(Dispatcher::new(
        endpoint,
        BTreeSet::from([Operation::ScreenInfo]),
    ));

    let dispatch = dispatcher
        .handle(&request_body("capture", json!({})), LIMIT)
        .await;
    assert_eq!(
        dispatch,
        Dispatch::NotDispatched(NotDispatched::NotPermitted)
    );
    assert!(backend.ledger().is_empty());

    // Non-vacuity: the backend does advertise `screenshot` and does answer it
    // when the operation is permitted, so the refusal above came from the
    // negotiated set and not from the backend.
    let commands = read_commands(endpoint).await.unwrap();
    assert!(commands.iter().any(|name| name == "screenshot"));
    let permitted = facade(Dispatcher::new(
        endpoint,
        BTreeSet::from([Operation::Capture]),
    ));
    assert!(matches!(
        permitted
            .handle(&request_body("capture", json!({})), LIMIT)
            .await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    assert_eq!(backend.ledger().count("screenshot"), 1);
    backend.stop();
}

/// **Proof 4: a capture is verified by decoding markers.**
#[tokio::test]
async fn a_capture_is_verified_by_decoding_its_markers() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = negotiated(&backend).await;

    let dispatch = dispatcher
        .handle(&request_body("capture", json!({"display": 0})), LIMIT)
        .await;
    let Dispatch::Dispatched(Completion::Ok(result)) = dispatch else {
        panic!("capture should have succeeded: {dispatch:?}");
    };
    let image = from_hex(result["image_hex"].as_str().unwrap()).expect("the image decodes as hex");

    // The check that matters: every marker recomputed from the seed.
    let decoded = marker::verify(&image, SCREEN_WIDTH, SCREEN_HEIGHT, IMAGE_SEED)
        .expect("the fixture's synthetic image verifies");
    assert_eq!(decoded.width, SCREEN_WIDTH);
    assert_eq!(decoded.height, SCREEN_HEIGHT);
    assert_eq!(
        result["width"].as_u64(),
        Some(u64::from(SCREEN_WIDTH)),
        "the reported dimensions must agree with the decoded ones"
    );
    backend.stop();
}

/// **The control for proof 4.** Two displays produce images of *identical
/// length* and different markers, so a byte-count comparison cannot tell them
/// apart and the marker check can.
#[tokio::test]
async fn a_byte_count_would_not_have_caught_the_wrong_display() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = negotiated(&backend).await;

    let mut images = Vec::new();
    for display in [0u32, 1] {
        let dispatch = dispatcher
            .handle(
                &request_body("capture", json!({ "display": display })),
                LIMIT,
            )
            .await;
        let Dispatch::Dispatched(Completion::Ok(result)) = dispatch else {
            panic!("capture should have succeeded: {dispatch:?}");
        };
        images.push(from_hex(result["image_hex"].as_str().unwrap()).unwrap());
    }

    // The bad evidence: identical lengths.
    assert_eq!(images[0].len(), images[1].len());

    // The good evidence: each verifies against its own display's seed and
    // fails against the other's.
    assert!(marker::verify(&images[0], SCREEN_WIDTH, SCREEN_HEIGHT, IMAGE_SEED).is_ok());
    assert!(marker::verify(&images[1], SCREEN_WIDTH, SCREEN_HEIGHT, IMAGE_SEED + 1).is_ok());
    assert!(matches!(
        marker::verify(&images[1], SCREEN_WIDTH, SCREEN_HEIGHT, IMAGE_SEED),
        Err(marker::MarkerError::MarkerMismatch { .. })
    ));

    // And the ledger recorded which display each capture asked for, so "the
    // right image came back" and "the right image was requested" are separate
    // facts, both checked.
    assert_eq!(
        backend.ledger().entries()[discovery_entries().len()..],
        [
            LedgerEntry::new("screenshot", Some(0)),
            LedgerEntry::new("screenshot", Some(1)),
        ]
    );
    backend.stop();
}

#[tokio::test]
async fn screen_info_and_cursor_position_return_the_synthetic_values() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = negotiated(&backend).await;

    let Dispatch::Dispatched(Completion::Ok(screen)) = dispatcher
        .handle(&request_body("screen_info", json!({})), LIMIT)
        .await
    else {
        panic!("screen_info should have succeeded");
    };
    assert_eq!(screen["width"].as_u64(), Some(u64::from(SCREEN_WIDTH)));
    assert_eq!(screen["height"].as_u64(), Some(u64::from(SCREEN_HEIGHT)));

    let Dispatch::Dispatched(Completion::Ok(cursor)) = dispatcher
        .handle(&request_body("cursor_position", json!({})), LIMIT)
        .await
    else {
        panic!("cursor_position should have succeeded");
    };
    assert_eq!(cursor["x"].as_u64(), Some(u64::from(CURSOR.0)));
    assert_eq!(cursor["y"].as_u64(), Some(u64::from(CURSOR.1)));
    backend.stop();
}

/// `describe` is answered from the negotiated set, and it is **not** a config
/// echo: narrow the set and the answer narrows with it, without any
/// configuration changing.
#[tokio::test]
async fn describe_reports_the_negotiated_set_rather_than_the_configuration() {
    let backend = FixtureBackend::start().await.unwrap();
    let endpoint = BackendEndpoint::new(backend.address()).unwrap();

    let wide = facade(Dispatcher::new(endpoint, BTreeSet::from(Operation::ALL)));
    let Dispatch::AnsweredLocally(all) = wide
        .handle(&request_body("describe", json!({})), LIMIT)
        .await
    else {
        panic!("describe should have been answered locally");
    };
    assert_eq!(
        all["operations"].as_array().unwrap().len(),
        Operation::ALL.len()
    );

    let narrow = facade(Dispatcher::new(
        endpoint,
        BTreeSet::from([Operation::Describe, Operation::CursorPosition]),
    ));
    let Dispatch::AnsweredLocally(some) = narrow
        .handle(&request_body("describe", json!({})), LIMIT)
        .await
    else {
        panic!("describe should have been answered locally");
    };
    assert_eq!(
        some["operations"],
        json!(["describe", "cursor_position"]),
        "describe must report what was negotiated"
    );
    assert!(backend.ledger().is_empty(), "describe dispatches nothing");
    backend.stop();
}

/// The endpoint check is on the dispatch path, not only in a unit test: a
/// non-loopback address cannot be turned into a `BackendEndpoint` at all, so
/// there is no `Dispatcher` that could reach one.
#[tokio::test]
async fn a_non_loopback_backend_cannot_be_dispatched_to_at_all() {
    use std::net::{Ipv4Addr, SocketAddr};

    assert!(
        BackendEndpoint::new(SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 8080))).is_err()
    );
    // The fixture's own address is loopback, so the type is constructible for
    // the address this chunk actually uses -- the refusal above is about the
    // address, not about the type being unusable.
    let backend = FixtureBackend::start().await.unwrap();
    assert!(backend.address().ip().is_loopback());
    assert!(BackendEndpoint::new(backend.address()).is_ok());
    backend.stop();
}

/// **Capture authority is read from the `version` response, end to end.**
///
/// The first review found this being derived from the probe result — a
/// response that does not carry `desktop_capture_authorized` — so against the
/// pinned backend the `Denied` arm was unreachable and the capture gate could
/// never refuse. This runs the real discovery path against the fixture and
/// checks all three states.
///
/// **What this does not show.** No real backend has been observed emitting
/// `false`; the fixture is what produces it here, and task row M5-C03 records
/// the `Denied` arm as modelled rather than measured. The *default* case is
/// the faithful one: the fixture omits the key, exactly as the released server
/// does on the supported 0.22.x SDK.
#[tokio::test]
async fn capture_authority_comes_from_the_version_reading_and_gates_capture() {
    let backend = FixtureBackend::start().await.unwrap();
    let endpoint = BackendEndpoint::new(backend.address()).unwrap();
    let bare = facade(Dispatcher::new(
        endpoint,
        BTreeSet::from([Operation::ScreenInfo]),
    ));

    // The default: the key is absent, which is what the pinned server does.
    // Absent is not denied, so capture stays available.
    assert_eq!(
        CaptureAuthority::from_version_reading(&bare.dispatcher().read_version().await),
        CaptureAuthority::Unknown,
        "the fixture must omit the key by default, as the released server does"
    );

    // Explicitly granted.
    backend.capture_authority().set(Some(true));
    assert_eq!(
        CaptureAuthority::from_version_reading(&bare.dispatcher().read_version().await),
        CaptureAuthority::Granted
    );

    // Explicitly denied: the one state that removes capture from the
    // negotiated set.
    backend.capture_authority().set(Some(false));
    let denied = CaptureAuthority::from_version_reading(&bare.dispatcher().read_version().await);
    assert_eq!(denied, CaptureAuthority::Denied);

    // And the gate actually bites, through the real negotiation.
    let commands = read_commands(endpoint).await.unwrap();
    let probe_body = request_body("screen_info", json!({}));
    let probe = bare.handle(&probe_body, LIMIT).await;
    let evidence =
        ProbeEvidence::from_probe(&validate_request(&probe_body, LIMIT).unwrap(), &probe).unwrap();
    let local = Operation::ALL
        .into_iter()
        .fold(LocalConfiguration::none(), LocalConfiguration::with);
    let grant = Operation::ALL
        .into_iter()
        .fold(CallerGrant::none(), CallerGrant::with);

    let refusing = facade(Dispatcher::negotiated(
        endpoint,
        &local,
        &UpstreamSupport::new(&commands, evidence.clone(), denied),
        &grant,
    ));
    assert!(!refusing.dispatcher().permits(Operation::Capture));
    let before = backend.ledger().count("screenshot");
    let dispatch = refusing
        .handle(&request_body("capture", json!({})), LIMIT)
        .await;
    assert_eq!(
        dispatch,
        Dispatch::NotDispatched(NotDispatched::NotPermitted)
    );
    assert_eq!(
        backend.ledger().count("screenshot"),
        before,
        "a refused capture must not reach the backend"
    );

    // Non-vacuity: the identical setup with an absent authority does permit
    // capture and does dispatch it, so the refusal above came from the
    // authority rather than from anything else in the negotiation.
    let permitting = facade(Dispatcher::negotiated(
        endpoint,
        &local,
        &UpstreamSupport::new(&commands, evidence, CaptureAuthority::Unknown),
        &grant,
    ));
    assert!(permitting.dispatcher().permits(Operation::Capture));
    assert!(matches!(
        permitting
            .handle(&request_body("capture", json!({})), LIMIT)
            .await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    assert_eq!(backend.ledger().count("screenshot"), before + 1);
    backend.stop();
}
