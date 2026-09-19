//! **"Unknown outcome" versus "not dispatched", decided against the ledger.**
//!
//! This is the file the whole chunk turns on. The trap
//! `<scratchpad>/m5-scoping-and-decisions.md` names is *"unknown outcome" that
//! is really "not dispatched"*, and its remedy is *inject faults after the
//! ledger entry exists, so the two are distinguishable*.
//!
//! So every test below pairs a classification with a ledger reading:
//!
//! * a fault injected **before** the ledger entry must classify as
//!   `NotDispatched` **and** leave the ledger empty;
//! * a fault injected **after** it must classify as `Dispatched(Unknown)`
//!   **and** leave exactly one entry.
//!
//! Either half alone would be the defect this repository tracks. A
//! classification with no ledger reading proves only what the client believed;
//! a ledger reading with no classification proves only what the server saw.
//!
//! For this chunk's read-only operations nothing is actually lost when the
//! classification is wrong. That is why the machinery is built here: the
//! stakes are zero, and in chunk 3 the same misclassification is a second
//! click on somebody's desktop.

use std::collections::BTreeSet;

use serde_json::json;

use tunnel_cua::Operation;
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::outcome::{Completion, Dispatch, FailureCode, NotDispatched, UnknownReason};

use tunnel_cua_fixture::client::{Dispatcher, request_body};
use tunnel_cua_fixture::{Fault, FixtureBackend};

const LIMIT: u64 = tunnel_cua::DEFAULT_REQUEST_BODY_LIMIT;

async fn dispatcher(backend: &FixtureBackend) -> Dispatcher {
    Dispatcher::new(
        BackendEndpoint::new(backend.address()).expect("the fixture binds loopback"),
        BTreeSet::from(Operation::ALL),
    )
}

/// The whole distinction, as one table, run against one fixture.
///
/// Reading it top to bottom is the argument: the two `NotDispatched` rows add
/// nothing to the ledger and the three `Unknown`/`Failed` rows each add
/// exactly one entry, so the classification is tracking what the backend saw
/// rather than what the client guessed.
#[tokio::test]
async fn the_fault_table_agrees_with_the_ledger_row_by_row() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = dispatcher(&backend).await;

    struct Row {
        fault: Fault,
        expected: Dispatch,
        ledger_entries_added: usize,
    }

    let rows = [
        Row {
            fault: Fault::None,
            expected: Dispatch::Dispatched(Completion::Ok(json!({
                "width": tunnel_cua_fixture::SCREEN_WIDTH,
                "height": tunnel_cua_fixture::SCREEN_HEIGHT,
            }))),
            ledger_entries_added: 1,
        },
        Row {
            fault: Fault::SuccessFalse,
            expected: Dispatch::Dispatched(Completion::Failed {
                code: FailureCode::BackendReported,
            }),
            ledger_entries_added: 1,
        },
        Row {
            fault: Fault::TruncateAfterLedger,
            expected: Dispatch::Dispatched(Completion::Unknown(UnknownReason::Truncated)),
            ledger_entries_added: 1,
        },
        Row {
            fault: Fault::DropAfterLedger,
            expected: Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost)),
            ledger_entries_added: 1,
        },
        Row {
            fault: Fault::SuccessAbsent,
            expected: Dispatch::Dispatched(Completion::Unknown(UnknownReason::SuccessAbsent)),
            ledger_entries_added: 1,
        },
        Row {
            fault: Fault::PreDispatchRejection { status: 400 },
            expected: Dispatch::NotDispatched(NotDispatched::BackendRejected { status: 400 }),
            ledger_entries_added: 0,
        },
        Row {
            fault: Fault::PreDispatchRejection { status: 401 },
            expected: Dispatch::NotDispatched(NotDispatched::BackendRejected { status: 401 }),
            ledger_entries_added: 0,
        },
        Row {
            fault: Fault::Unavailable,
            expected: Dispatch::NotDispatched(NotDispatched::BackendUnavailable),
            ledger_entries_added: 0,
        },
    ];

    for row in rows {
        backend.faults().set("get_screen_size", row.fault);
        let before = backend.ledger().len();
        let dispatch = dispatcher
            .handle(&request_body("screen_info", json!({})), LIMIT)
            .await;
        assert_eq!(dispatch, row.expected, "fault={:?}", row.fault);

        let added = backend.ledger().len() - before;
        assert_eq!(
            added, row.ledger_entries_added,
            "fault={:?} classified as {dispatch:?} but added {added} ledger entries",
            row.fault
        );

        // The two facts must agree. This is the assertion the chunk exists
        // for: "the backend saw it" as the client reports it, against "the
        // backend saw it" as the backend recorded it.
        assert_eq!(
            dispatch.reached_the_backend(),
            added == 1,
            "fault={:?}: the client and the ledger disagree about whether the command was dispatched",
            row.fault
        );
    }
    backend.stop();
}

/// **The half that costs something if it is wrong.** An unknown outcome must
/// never invite a retry; a not-dispatched one must.
#[tokio::test]
async fn an_unknown_outcome_refuses_a_retry_and_a_not_dispatched_one_permits_it() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = dispatcher(&backend).await;

    backend
        .faults()
        .set("get_cursor_position", Fault::DropAfterLedger);
    let unknown = dispatcher
        .handle(&request_body("cursor_position", json!({})), LIMIT)
        .await;
    assert!(
        !unknown.retry_is_safe(),
        "a dispatched command with a lost answer must not be retried: {unknown:?}"
    );
    assert_eq!(backend.ledger().count("get_cursor_position"), 1);

    backend.faults().set(
        "get_cursor_position",
        Fault::PreDispatchRejection { status: 400 },
    );
    let refused = dispatcher
        .handle(&request_body("cursor_position", json!({})), LIMIT)
        .await;
    assert!(refused.retry_is_safe());
    assert_eq!(
        backend.ledger().count("get_cursor_position"),
        1,
        "the pre-dispatch refusal added nothing"
    );

    // And the retry that the classification permits really does reach the
    // backend, so `retry_is_safe` is describing something that happens.
    backend.faults().set("get_cursor_position", Fault::None);
    assert!(matches!(
        dispatcher
            .handle(&request_body("cursor_position", json!({})), LIMIT)
            .await,
        Dispatch::Dispatched(Completion::Ok(_))
    ));
    assert_eq!(backend.ledger().count("get_cursor_position"), 2);
    backend.stop();
}

/// **The trap in its own right: HTTP 200 with `success: false`.**
///
/// The backend answered 200. The command really was dispatched — one ledger
/// entry — and it really did fail. A classifier that read the status would
/// have returned a success here with an entirely plausible-looking payload.
#[tokio::test]
async fn a_two_hundred_carrying_a_failure_is_a_dispatched_failure_not_a_success() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = dispatcher(&backend).await;

    backend.faults().set("screenshot", Fault::SuccessFalse);
    let dispatch = dispatcher
        .handle(&request_body("capture", json!({})), LIMIT)
        .await;
    assert_eq!(
        dispatch,
        Dispatch::Dispatched(Completion::Failed {
            code: FailureCode::BackendReported
        })
    );
    assert_eq!(backend.ledger().count("screenshot"), 1);
    backend.stop();
}

/// The `{"success": True, **result}` override: a handler result carrying its
/// own `success` key wins, and what is on the wire is the merged value.
#[tokio::test]
async fn a_handler_result_overriding_the_envelope_is_read_from_the_wire() {
    let backend = FixtureBackend::start().await.unwrap();
    let dispatcher = dispatcher(&backend).await;

    backend
        .faults()
        .set("screenshot", Fault::ResultOverridesEnvelope);
    let dispatch = dispatcher
        .handle(&request_body("capture", json!({})), LIMIT)
        .await;
    assert!(
        matches!(dispatch, Dispatch::Dispatched(Completion::Failed { .. })),
        "the handler's success key wins over the envelope's: {dispatch:?}"
    );
    assert_eq!(backend.ledger().count("screenshot"), 1);
    backend.stop();
}

/// A backend that is not listening at all is **not dispatched** — the one case
/// where `NotDispatched` is the right answer for a transport failure, because
/// nothing was ever written.
#[tokio::test]
async fn a_backend_that_is_not_listening_is_not_dispatched() {
    // Bind and immediately stop, so the port is one nothing answers on. Still
    // loopback, so the endpoint check is not what is being measured.
    let backend = FixtureBackend::start().await.unwrap();
    let address = backend.address();
    let endpoint = BackendEndpoint::new(address).unwrap();
    backend.stop();
    // Give the listener a moment to actually go away.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let dispatcher = Dispatcher::new(endpoint, BTreeSet::from(Operation::ALL));
    let dispatch = dispatcher
        .handle(&request_body("screen_info", json!({})), LIMIT)
        .await;
    match dispatch {
        Dispatch::NotDispatched(NotDispatched::NotReached) => {}
        // A connection that is accepted by a lingering socket and then
        // answers nothing is `TransportLost`, which is also correct and is
        // what a listener closing underneath us can produce. Both are
        // acceptable; anything else is not.
        Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost)) => {}
        other => panic!("a dead backend must be NotReached or TransportLost, got {other:?}"),
    }
}

/// A deadline that expires after the request was written is **unknown**, not
/// not-dispatched: the backend has the command.
#[tokio::test]
async fn a_deadline_that_expires_after_the_write_is_unknown_and_the_ledger_shows_why() {
    let backend = FixtureBackend::start().await.unwrap();
    // The fixture records the entry and then never answers, so the deadline is
    // the only thing that ends the exchange -- and the ledger proves the
    // command arrived.
    backend
        .faults()
        .set("get_screen_size", Fault::DropAfterLedger);
    let dispatcher = dispatcher(&backend)
        .await
        .with_deadline(std::time::Duration::from_secs(5));

    let dispatch = dispatcher
        .handle(&request_body("screen_info", json!({})), LIMIT)
        .await;
    assert!(
        dispatch.reached_the_backend(),
        "the ledger says it arrived, so the classification must too: {dispatch:?}"
    );
    assert!(!dispatch.retry_is_safe());
    assert_eq!(backend.ledger().count("get_screen_size"), 1);
    backend.stop();
}
