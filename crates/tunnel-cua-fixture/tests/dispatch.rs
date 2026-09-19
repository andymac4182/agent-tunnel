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
use tunnel_cua::capability::{CallerGrant, LocalConfiguration, ProbeEvidence, UpstreamSupport};
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::marker;
use tunnel_cua::operation::{Deferral, Refusal};
use tunnel_cua::outcome::{Completion, Dispatch, NotDispatched};
use tunnel_cua::schema::SchemaError;

use tunnel_cua_fixture::client::{Dispatcher, read_commands, request_body};
use tunnel_cua_fixture::{
    CURSOR, FixtureBackend, IMAGE_SEED, LedgerEntry, SCREEN_HEIGHT, SCREEN_WIDTH, from_hex,
};

const LIMIT: u64 = tunnel_cua::DEFAULT_REQUEST_BODY_LIMIT;

/// Build a dispatcher permitting everything the backend and a full grant
/// allow, having actually probed the backend.
async fn negotiated(backend: &FixtureBackend) -> Dispatcher {
    let endpoint = BackendEndpoint::new(backend.address()).expect("the fixture binds loopback");
    let commands = read_commands(endpoint)
        .await
        .expect("the fixture lists commands");

    // The probe is a real dispatch. It is the only thing that can produce
    // `ProbeEvidence`, and it leaves its own ledger entry -- which every test
    // below accounts for.
    let bare = Dispatcher::new(endpoint, BTreeSet::from([Operation::ScreenInfo]));
    let probe = bare
        .handle(&request_body("screen_info", json!({})), LIMIT)
        .await;
    let evidence = ProbeEvidence::from_probe(Operation::ScreenInfo, &probe)
        .expect("a succeeded screen_info probe is evidence");

    let local = Operation::ALL
        .into_iter()
        .fold(LocalConfiguration::none(), LocalConfiguration::with);
    let grant = Operation::ALL
        .into_iter()
        .fold(CallerGrant::none(), CallerGrant::with);
    Dispatcher::negotiated(
        endpoint,
        &local,
        &UpstreamSupport::new(&commands, evidence),
        &grant,
    )
}

/// The probe that `negotiated` performs, so every ledger assertion can account
/// for it explicitly rather than by an off-by-one nobody notices.
fn probe_entry() -> LedgerEntry {
    LedgerEntry::new("get_screen_size", Some(0))
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
        assert!(
            matches!(dispatch, Dispatch::Dispatched(Completion::Ok(_))),
            "{operation} should have succeeded, got {dispatch:?}"
        );
        let added = &backend.ledger().entries()[before..];
        match expected {
            None => assert!(
                added.is_empty(),
                "describe must dispatch no command, it added {added:?}"
            ),
            Some(command) => {
                assert_eq!(added.len(), 1, "{operation} dispatched {added:?}");
                assert_eq!(added[0].command, command);
            }
        }
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

    assert_eq!(
        backend.ledger().entries(),
        vec![
            probe_entry(),
            LedgerEntry::new("get_cursor_position", None),
            LedgerEntry::new("screenshot", Some(2)),
            LedgerEntry::new("get_screen_size", Some(1)),
        ],
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
            "click",
            SchemaError::Operation(Refusal::Deferred(Deferral::SynthesisesInput)),
        ),
        (
            "type_text",
            SchemaError::Operation(Refusal::Deferred(Deferral::SynthesisesInput)),
        ),
        (
            "press_key",
            SchemaError::Operation(Refusal::Deferred(Deferral::SynthesisesInput)),
        ),
        (
            "drag",
            SchemaError::Operation(Refusal::Deferred(Deferral::SynthesisesInput)),
        ),
        (
            "scroll",
            SchemaError::Operation(Refusal::Deferred(Deferral::SynthesisesInput)),
        ),
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
    let dispatcher = Dispatcher::new(endpoint, BTreeSet::from(Operation::ALL));

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
    let dispatcher = Dispatcher::new(endpoint, BTreeSet::from([Operation::ScreenInfo]));

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
    let permitted = Dispatcher::new(endpoint, BTreeSet::from([Operation::Capture]));
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
        backend.ledger().entries()[1..],
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

    let wide = Dispatcher::new(endpoint, BTreeSet::from(Operation::ALL));
    let Dispatch::Dispatched(Completion::Ok(all)) = wide
        .handle(&request_body("describe", json!({})), LIMIT)
        .await
    else {
        panic!("describe should have succeeded");
    };
    assert_eq!(all["operations"].as_array().unwrap().len(), 4);

    let narrow = Dispatcher::new(
        endpoint,
        BTreeSet::from([Operation::Describe, Operation::CursorPosition]),
    );
    let Dispatch::Dispatched(Completion::Ok(some)) = narrow
        .handle(&request_body("describe", json!({})), LIMIT)
        .await
    else {
        panic!("describe should have succeeded");
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
