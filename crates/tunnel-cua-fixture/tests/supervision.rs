//! Task row M5-C08, end to end: a real supervisor over a real backend
//! process, with the effect count read from a **journal that survives the
//! restart**.
//!
//! # Why the journal, and why the count would otherwise be meaningless
//!
//! The claim under test is *the supervisor restarted a hung backend and the
//! click did not land twice*. That is a statement about a count spanning two
//! backend processes. An in-memory ledger dies with the first one, so after a
//! restart it reads zero and "the count did not increase" is true of nothing
//! at all — the trap this file exists to avoid, in its most literal form.
//!
//! So the supervised backend writes an append-only journal, at the moment the
//! command is accepted and **before** any fault is applied, and the tests read
//! it back across generations.
//!
//! # The two layers a restart puts between a caller and a second click
//!
//! Both are measured here, because a consumer that ignores the first still
//! meets the second:
//!
//! 1. **The in-flight operation is `Unknown`, never retryable.**
//!    `Dispatch::retry_is_safe_for` says `false` for the click, which is the
//!    answer a well-behaved consumer acts on.
//! 2. **The lease and the capture identity are gone.** A consumer that
//!    retries anyway is refused *above the dispatch boundary*, so the retry
//!    never reaches the backend — and the journal proves it, because the
//!    count does not move.
//!
//! # What this file does not touch
//!
//! No screen, no input device, no real backend. The supervised process is
//! `tunnel-cua-fixture backend`, which binds `127.0.0.1:0` and serves
//! synthetic answers. Chunks 2 and 3's four host-untouched proofs are
//! unaffected and still hold.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use tunnel_cua::Operation;
use tunnel_cua::capability::{CallerGrant, LocalConfiguration, UpstreamSupport};
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::lease::{SessionId, TargetSession};
use tunnel_cua::outcome::{Completion, Dispatch, InputRefusal, NotDispatched};
use tunnel_cua::schema::validate_request;
use tunnel_cua_export::health::{Health, Unhealthy};
use tunnel_cua_export::{BackendProcess, Supervisor};
use tunnel_cua_fixture::client::{DeviceState, Dispatcher, SessionFacade, read_commands};
use tunnel_cua_fixture::process::{ADDRESS_FILE, BACKEND_MODE, HELPER_PID_FILE, JOURNAL_FILE};
use tunnel_cua_fixture::{Fault, Ledger};

const LIMIT: u64 = 64 << 10;

// ------------------------------------------------------------------ helpers

fn fixture_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    let binary = path.join("tunnel-cua-fixture");
    assert!(
        binary.is_file(),
        "the fixture binary must be built; run the workspace test command, not a bare -p run"
    );
    binary
}

fn supervised(workspace: &Path) -> BackendProcess {
    supervised_hanging(workspace, None)
}

/// The same backend, optionally with one command that records its effect and
/// then never answers.
fn supervised_hanging(workspace: &Path, hang: Option<&str>) -> BackendProcess {
    let mut args = vec![
        BACKEND_MODE.to_owned(),
        workspace.join(ADDRESS_FILE).display().to_string(),
        workspace.join(JOURNAL_FILE).display().to_string(),
        workspace.join(HELPER_PID_FILE).display().to_string(),
    ];
    if let Some(command) = hang {
        args.push(command.to_owned());
    }
    BackendProcess::new(
        fixture_binary(),
        args,
        workspace.to_path_buf(),
        workspace.join(ADDRESS_FILE),
    )
    .expect("a valid supervised backend")
}

/// Kills every pid it is given when it goes out of scope, however the test
/// left — including through a panic above the cleanup. This file starts
/// processes, so nothing may be cleaned up only on the happy path.
struct PidGuard(Vec<u32>);

impl PidGuard {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn watch(&mut self, pid: u32) {
        self.0.push(pid);
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        for pid in &self.0 {
            let _ = std::process::Command::new("/bin/kill")
                .args(["-9", &pid.to_string()])
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

fn body(operation: &str, params: serde_json::Value) -> Vec<u8> {
    json!({
        "version": tunnel_cua::SCHEMA_VERSION,
        "operation": operation,
        "params": params,
    })
    .to_string()
    .into_bytes()
}

/// Every operation, so a test is exercising the profile rather than a
/// narrowed configuration.
fn everything() -> (LocalConfiguration, CallerGrant) {
    let mut local = LocalConfiguration::none();
    let mut grant = CallerGrant::none();
    for operation in Operation::ALL {
        local = local.with(operation);
        grant = grant.with(operation);
    }
    (local, grant)
}

/// Negotiate against a live backend, taking the probe evidence from a real
/// `screen_info` exchange.
async fn dispatcher_for(endpoint: BackendEndpoint) -> Dispatcher {
    let commands = read_commands(endpoint).await.expect("the backend listed");
    let probe_only = Dispatcher::new(endpoint, [Operation::ScreenInfo].into_iter().collect());
    let request = validate_request(&body("screen_info", json!({})), LIMIT).expect("valid");
    let dispatch =
        dispatch_stateless(&probe_only, &TargetSession::new("desktop-0"), "screen_info").await;
    let evidence = tunnel_cua::capability::ProbeEvidence::from_probe(&request, &dispatch)
        .expect("the probe was dispatched and succeeded");
    let authority = tunnel_cua_export::health::capture_authority(&probe_only.read_version().await);
    let upstream = UpstreamSupport::new(&commands, evidence, authority);
    let (local, grant) = everything();
    Dispatcher::negotiated(endpoint, &local, &upstream, &grant)
}

/// Dispatch one read-only operation with no session state behind it.
///
/// Discovery reads -- the probe and `describe` -- are issued on nobody's
/// behalf, so they carry empty registries. The registries are local to this
/// call rather than shared: a probe that could see a lease would be a probe
/// whose answer depended on consumer state.
async fn dispatch_stateless(
    dispatcher: &Dispatcher,
    target: &TargetSession,
    operation: &str,
) -> Dispatch {
    let leases = tunnel_cua::lease::InputLeases::new();
    let captures = tunnel_cua::capture::Captures::new();
    let context = tunnel_cua::plan::SessionContext {
        session: SessionId::new(0),
        target,
        grant_revision: tunnel_cua::lease::GrantRevision::new(0),
        leases: &leases,
        captures: &captures,
    };
    dispatcher
        .handle(&body(operation, json!({})), LIMIT, &context)
        .await
}

fn facade(
    state: &Arc<DeviceState>,
    dispatcher: Dispatcher,
    target: &TargetSession,
) -> SessionFacade {
    SessionFacade::new(
        Arc::clone(state),
        dispatcher,
        SessionId::new(1),
        target.clone(),
    )
}

/// Take the lease and one capture, and hand back the grant and the capture
/// identity a later click must refer to.
async fn capture_then_lease(facade: &SessionFacade) -> (tunnel_cua::lease::LeaseGrant, u64) {
    let grant = facade.acquire_input_lease().expect("the lease was free");
    let dispatch = facade
        .handle(&body("capture", json!({"display": 0})), LIMIT)
        .await;
    let Dispatch::Dispatched(Completion::Ok(result)) = &dispatch else {
        panic!("the capture should have succeeded: {dispatch:?}");
    };
    let capture = result
        .get("capture")
        .and_then(serde_json::Value::as_u64)
        .expect("a capture identity was issued");
    (grant, capture)
}

// ------------------------------------------------------- lifecycle and health

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_supervised_backend_starts_on_loopback_and_is_not_working_until_probed() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut guard = PidGuard::new();
    let mut supervisor = Supervisor::new(supervised(workspace.path()));

    assert_eq!(supervisor.health(), Health::NotStarted);
    let endpoint = supervisor.start().await.expect("it started");
    guard.watch(supervisor.pid().expect("a pid"));

    assert!(
        endpoint.address().ip().is_loopback(),
        "the endpoint came from the process that is actually listening"
    );
    // **The separation.** A listening process is `Started`, never `Working`.
    assert_eq!(supervisor.health(), Health::Started);
    assert!(!supervisor.health().permits_dispatch());

    // A probe, and only a probe, moves it on.
    let dispatcher = Dispatcher::new(endpoint, [Operation::ScreenInfo].into_iter().collect());
    let request = validate_request(&body("screen_info", json!({})), LIMIT).expect("valid");
    let dispatch =
        dispatch_stateless(&dispatcher, &TargetSession::new("desktop-0"), "screen_info").await;
    let verdict = supervisor.assess(&request, &dispatch);
    assert!(
        verdict.permits_dispatch(),
        "a dispatched, succeeded, OS-gated read is what makes a backend working: {verdict:?}"
    );
    assert_eq!(
        verdict
            .evidence()
            .map(tunnel_cua::capability::ProbeEvidence::probe),
        Some(Operation::ScreenInfo)
    );

    supervisor.stop(DeviceState::new().as_ref()).await;
    assert_eq!(supervisor.health(), Health::Exited);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_describe_can_never_report_a_running_backend_as_working() {
    // **The anti-echo control, end to end.** `describe` is answered entirely
    // from the negotiated set: it sends no bytes, so it can say nothing about
    // whether the backend can act. Against a genuinely working backend it is
    // still refused as a probe.
    let workspace = tempfile::tempdir().expect("workspace");
    let mut guard = PidGuard::new();
    let mut supervisor = Supervisor::new(supervised(workspace.path()));
    let endpoint = supervisor.start().await.expect("it started");
    guard.watch(supervisor.pid().expect("a pid"));

    let dispatcher = dispatcher_for(endpoint).await;
    let request = validate_request(&body("describe", json!({})), LIMIT).expect("valid");
    let dispatch =
        dispatch_stateless(&dispatcher, &TargetSession::new("desktop-0"), "describe").await;
    assert!(
        dispatch.answered_locally(),
        "describe is answered from device state, not from the backend"
    );
    assert!(!dispatch.reached_the_backend());
    assert_eq!(
        supervisor.assess(&request, &dispatch),
        Health::Unhealthy(Unhealthy::NotAProbe),
        "a config echo must not be able to report a working backend"
    );

    // And the control that makes this mean something: the very same backend
    // answers a real probe as working.
    let probe = validate_request(&body("cursor_position", json!({})), LIMIT).expect("valid");
    let probe_dispatch = dispatch_stateless(
        &dispatcher,
        &TargetSession::new("desktop-0"),
        "cursor_position",
    )
    .await;
    assert!(
        supervisor
            .assess(&probe, &probe_dispatch)
            .permits_dispatch(),
        "the same backend, probed properly, is working -- so the refusal above \
         is about the operation and not about a broken backend"
    );

    supervisor.stop(DeviceState::new().as_ref()).await;
}

// --------------------------------------------------------- restart semantics

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_mid_operation_is_unknown_and_the_click_does_not_land_twice() {
    // **The measurement this chunk exists for.**
    let workspace = tempfile::tempdir().expect("workspace");
    let journal = workspace.path().join(JOURNAL_FILE);
    let mut guard = PidGuard::new();
    let state = DeviceState::new();
    let desktop = TargetSession::new("desktop-0");

    // The backend hangs on `left_click`: it records the effect and then never
    // answers, which is the hung backend a supervisor exists to restart.
    let mut supervisor = Supervisor::new(supervised_hanging(workspace.path(), Some("left_click")));
    let endpoint = supervisor.start().await.expect("it started");
    guard.watch(supervisor.pid().expect("a pid"));
    let first_generation = supervisor.generation();

    let session = facade(&state, dispatcher_for(endpoint).await, &desktop);
    let (lease, capture) = capture_then_lease(&session).await;
    assert_eq!(state.holder(&desktop), Some(SessionId::new(1)));

    // A click, dispatched for real, against a backend that is about to be
    // taken away underneath it. The deadline is long, so nothing here can
    // expire on its own and be mistaken for the restart.
    let session = Arc::new(session);
    let click_session = Arc::clone(&session);
    let click_body = body(
        "click",
        json!({"capture": capture, "x": 10, "y": 12, "button": "left"}),
    );
    let click = tokio::spawn(async move { click_session.handle(&click_body, LIMIT).await });

    // Wait until the backend has actually recorded the click, so the restart
    // lands *after* the effect rather than racing it. Without this the test
    // could restart before the command arrived and would then be measuring a
    // `NotDispatched`, which is a different and much weaker claim.
    let clicked = wait_for_clicks(&journal, 1).await;
    assert_eq!(
        clicked, 1,
        "the backend recorded the click before the restart; without that this \
         test measures a retryable failure rather than an unknown one"
    );

    let (invalidation, restarted) = supervisor.restart(state.as_ref()).await;
    let new_endpoint = restarted.expect("the replacement backend started");
    guard.watch(supervisor.pid().expect("a pid"));

    let outcome = click.await.expect("the click task finished");

    // ---- layer 1: the in-flight operation is unknown and not retryable ----
    assert!(
        outcome.reached_the_backend(),
        "the click reached the backend -- the journal says so -- so it must not \
         be reported as not dispatched: {outcome:?}"
    );
    assert!(!outcome.retry_is_safe(), "{outcome:?}");
    assert!(
        !outcome.retry_is_safe_for(Operation::Click),
        "an input operation that reached the backend is never retryable: {outcome:?}"
    );
    assert!(
        matches!(outcome, Dispatch::Dispatched(Completion::Unknown(_))),
        "got {outcome:?}"
    );

    // ---- layer 2: the lease and the capture identity are gone -------------
    assert_eq!(invalidation.leases_released, vec![desktop.clone()]);
    assert_eq!(invalidation.captures_forgotten, 1);
    assert_eq!(
        state.holder(&desktop),
        None,
        "the restart dropped the lease from the registry, not merely reported it"
    );
    assert_eq!(state.capture_count(), 0);
    assert!(supervisor.generation() > first_generation);

    // ---- the control: a caller that retries anyway does not double-click --
    let retry = facade(&state, dispatcher_for(new_endpoint).await, &desktop);
    let retried = retry
        .handle(
            &body(
                "click",
                json!({"capture": capture, "x": 10, "y": 12, "button": "left"}),
            ),
            LIMIT,
        )
        .await;
    assert!(
        matches!(
            retried,
            Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Lease(_)))
        ),
        "the retry is refused above the dispatch boundary: {retried:?}"
    );

    // **The effect count, read from the journal, across both generations.**
    let clicks = Ledger::journal_pointer_clicks(&journal);
    let entries = Ledger::journal_entries(&journal);
    eprintln!(
        "MEASURED restart mid-click: generations {} -> {}, journal entries {:?}, \
         pointer clicks {clicks}, outcome {outcome:?}",
        first_generation.value(),
        supervisor.generation().value(),
        entries
            .iter()
            .map(|entry| entry.command.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        clicks, 1,
        "MEASUREMENT (M5-C08): exactly one click was performed across the \
         restart. Two would be the 'unknown outcome read as not dispatched' \
         trap arriving through the supervisor."
    );
    assert_eq!(
        Ledger::journal_entries(&journal)
            .iter()
            .filter(|entry| entry.command == "left_click")
            .count(),
        1
    );

    // The old lease grant is not merely unusable, it is unknown to the
    // registry: releasing it fails rather than silently succeeding.
    assert!(session.release_input_lease(&lease).is_err());

    supervisor.stop(state.as_ref()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capture_identity_from_before_a_restart_is_unknown_afterwards() {
    // The other half of the invalidation, measured against a live backend: a
    // coordinate picked from an image a dead backend produced must not be
    // dispatched at a screen nobody has looked at.
    let workspace = tempfile::tempdir().expect("workspace");
    let journal = workspace.path().join(JOURNAL_FILE);
    let mut guard = PidGuard::new();
    let state = DeviceState::new();
    let desktop = TargetSession::new("desktop-0");

    let mut supervisor = Supervisor::new(supervised(workspace.path()));
    let endpoint = supervisor.start().await.expect("it started");
    guard.watch(supervisor.pid().expect("a pid"));

    let session = facade(&state, dispatcher_for(endpoint).await, &desktop);
    let (_lease, stale_capture) = capture_then_lease(&session).await;

    let (_, restarted) = supervisor.restart(state.as_ref()).await;
    let new_endpoint = restarted.expect("the replacement started");
    guard.watch(supervisor.pid().expect("a pid"));

    // Re-acquire the lease, so the refusal below is about the capture and not
    // about the lease: one refusal at a time, or the test proves the wrong one.
    let session = facade(&state, dispatcher_for(new_endpoint).await, &desktop);
    session
        .acquire_input_lease()
        .expect("free after the restart");

    let refused = session
        .handle(
            &body(
                "click",
                json!({"capture": stale_capture, "x": 10, "y": 12, "button": "left"}),
            ),
            LIMIT,
        )
        .await;
    assert!(
        matches!(
            refused,
            Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Capture(
                tunnel_cua::capture::CaptureRefusal::Unknown
            )))
        ),
        "a pre-restart capture identity is unknown, not merely superseded: {refused:?}"
    );
    assert_eq!(
        Ledger::journal_pointer_clicks(&journal),
        0,
        "nothing was clicked at coordinates from a dead backend's image"
    );

    supervisor.stop(state.as_ref()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capture_taken_after_a_restart_never_reuses_a_pre_restart_identity() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut guard = PidGuard::new();
    let state = DeviceState::new();
    let desktop = TargetSession::new("desktop-0");

    let mut supervisor = Supervisor::new(supervised(workspace.path()));
    let endpoint = supervisor.start().await.expect("it started");
    guard.watch(supervisor.pid().expect("a pid"));
    let session = facade(&state, dispatcher_for(endpoint).await, &desktop);
    let (_lease, before) = capture_then_lease(&session).await;

    let (_, restarted) = supervisor.restart(state.as_ref()).await;
    let new_endpoint = restarted.expect("the replacement started");
    guard.watch(supervisor.pid().expect("a pid"));

    let session = facade(&state, dispatcher_for(new_endpoint).await, &desktop);
    let (_lease, after) = capture_then_lease(&session).await;
    assert_ne!(
        before, after,
        "a reissued identity would let a stale click resolve against a \
         different image and pass the bounds check"
    );

    supervisor.stop(state.as_ref()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_in_process_backend_that_hangs_is_dispatched_and_unknown() {
    // The fault-shape control for the restart test above, taken in process
    // where the fault knob exists. It shows that a command which records its
    // effect and then never answers is classified as **dispatched, unknown** —
    // which is what makes the restart test's outcome attributable to the
    // restart rather than to a misclassification.
    let backend = tunnel_cua_fixture::FixtureBackend::start()
        .await
        .expect("the in-process fixture started");
    let endpoint = BackendEndpoint::new(backend.address()).expect("loopback");
    backend.faults().set("left_click", Fault::DropAfterLedger);

    let state = DeviceState::new();
    let desktop = TargetSession::new("desktop-0");
    let session = facade(&state, dispatcher_for(endpoint).await, &desktop);
    let (_lease, capture) = capture_then_lease(&session).await;

    let outcome = session
        .handle(
            &body(
                "click",
                json!({"capture": capture, "x": 10, "y": 12, "button": "left"}),
            ),
            LIMIT,
        )
        .await;
    assert!(outcome.reached_the_backend(), "{outcome:?}");
    assert!(!outcome.retry_is_safe_for(Operation::Click));
    assert_eq!(
        backend.ledger().pointer_clicks(),
        1,
        "the effect happened once, and the client was told it does not know"
    );
    backend.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_journal_records_the_same_effects_the_in_memory_ledger_does() {
    // **Non-vacuity for every journal assertion in this file.** A journal that
    // silently recorded nothing would make every "the count did not increase"
    // claim above trivially true. This runs the in-process fixture with a
    // journal and requires the two to agree, including on the `double_click`
    // case where an entry count and an effect count differ.
    let workspace = tempfile::tempdir().expect("workspace");
    let journal = workspace.path().join("journal");
    let backend =
        tunnel_cua_fixture::FixtureBackend::start_with(Ledger::with_journal(journal.clone()))
            .await
            .expect("started");
    let endpoint = BackendEndpoint::new(backend.address()).expect("loopback");

    let state = DeviceState::new();
    let desktop = TargetSession::new("desktop-0");
    let session = facade(&state, dispatcher_for(endpoint).await, &desktop);
    let (_lease, capture) = capture_then_lease(&session).await;

    let clicked = session
        .handle(
            &body(
                "double_click",
                json!({"capture": capture, "x": 10, "y": 12}),
            ),
            LIMIT,
        )
        .await;
    assert!(
        matches!(clicked, Dispatch::Dispatched(Completion::Ok(_))),
        "{clicked:?}"
    );

    assert_eq!(
        Ledger::journal_pointer_clicks(&journal),
        backend.ledger().pointer_clicks(),
        "the journal and the in-memory ledger agree on effects"
    );
    assert_eq!(
        Ledger::journal_pointer_clicks(&journal),
        2,
        "one double_click command, two clicks -- the count is of effects, not \
         of dispatches, and a journal that lost that would be worthless here"
    );
    assert_eq!(
        Ledger::journal_entries(&journal).len(),
        backend.ledger().len()
    );
    // And no typed text anywhere: the journal stores a count, like the ledger.
    let typed = session
        .handle(&body("type_text", json!({"text": "synthetic"})), LIMIT)
        .await;
    assert!(typed.reached_the_backend(), "{typed:?}");
    let text = std::fs::read_to_string(&journal).expect("readable");
    assert!(
        !text.contains("synthetic"),
        "the journal must never carry typed text"
    );
    assert_eq!(
        Ledger::journal_entries(&journal)
            .iter()
            .map(|entry| entry.typed_characters)
            .sum::<usize>(),
        "synthetic".len()
    );
    backend.stop();
}

/// Wait, bounded, for the journal to record `wanted` clicks. Returns the count
/// it last saw, so a failure reports what it found rather than only that it
/// waited.
async fn wait_for_clicks(journal: &Path, wanted: u32) -> u32 {
    for _ in 0..1000 {
        let clicks = Ledger::journal_pointer_clicks(journal);
        if clicks >= wanted {
            return clicks;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ledger::journal_pointer_clicks(journal)
}
