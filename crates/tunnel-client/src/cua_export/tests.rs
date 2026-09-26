//! The Lane B export, judged against the Lane A fixture's ledger.
//!
//! The supervised "backend" is `/bin/sh` publishing the address of an
//! in-process [`FixtureBackend`] and then holding its stdin open, so the
//! whole export path -- supervision, the read-only health probe, the
//! `/commands` and `version` readings, the negotiation, the per-principal
//! session, the lease and the capture carry-forward -- runs for real against a
//! backend that cannot touch a screen. Nothing here starts a real CUA server.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use http::Request;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tunnel_cua_fixture::{FixtureBackend, SCREEN_HEIGHT, SCREEN_WIDTH};
use tunnel_http_bridge::ChannelBody;

use super::*;
use crate::config::{CuaBackendSettings, CuaExportSettings};

const ALL: [&str; 12] = [
    "describe",
    "capture",
    "screen_info",
    "cursor_position",
    "click",
    "double_click",
    "move",
    "drag",
    "scroll",
    "type_text",
    "press_key",
    "hotkey",
];

fn settings(
    workspace: &Path,
    backend: &FixtureBackend,
    point: Option<(u32, u32)>,
) -> CuaExportSettings {
    let address_file = workspace.join("backend.address");
    CuaExportSettings {
        profile: CUA_PROFILE_ID.to_owned(),
        target: None,
        point_width: point.map(|(width, _)| width),
        point_height: point.map(|(_, height)| height),
        operations: ALL.map(str::to_owned).to_vec(),
        backend: CuaBackendSettings {
            command: PathBuf::from("/bin/sh"),
            args: vec![
                "-c".to_owned(),
                "printf %s \"$0\" > \"$1.tmp\" && mv \"$1.tmp\" \"$1\" && exec cat >/dev/null"
                    .to_owned(),
                backend.address().to_string(),
                address_file.display().to_string(),
            ],
            workspace: workspace.to_path_buf(),
            address_file,
            inherit_env: Vec::new(),
            env: [("PATH".to_owned(), "/usr/bin:/bin".to_owned())].into(),
            startup_seconds: Some(10),
        },
    }
}

async fn call(export: &CuaExport, binding: &str, operation: &str, params: Value) -> Value {
    call_with(export, Some(binding), operation, params).await
}

async fn call_with(
    export: &CuaExport,
    binding: Option<&str>,
    operation: &str,
    params: Value,
) -> Value {
    let body = json!({"version": "computer.v1", "operation": operation, "params": params});
    let mut request = Request::post("/computer").header("content-type", "application/json");
    if let Some(binding) = binding {
        request = request.header(tunnel_cua::headers::TUNNEL_PRINCIPAL_BINDING, binding);
    }
    let request = request
        .body(ChannelBody::full(Bytes::from(body.to_string())))
        .expect("request");
    let response = export.handle(request).await;
    assert_eq!(response.status(), 200);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("a computer.v1 JSON answer")
}

fn outcome(answer: &Value) -> &str {
    answer["outcome"].as_str().unwrap_or_default()
}

/// **The demo path, against the ledger.** Capture, take the lease, click on
/// the capture through a 2x scale derived from the declared point space, and
/// type -- and the fixture records exactly one click, at the converted point,
/// and the typed character count. A second principal is refused the lease
/// while the first holds it, and nothing it sends reaches the backend.
#[tokio::test]
async fn a_consumer_captures_clicks_and_types_through_the_export() {
    let backend = FixtureBackend::start().await.expect("fixture");
    backend.capture_scale().set(200);
    let workspace = tempfile::tempdir().expect("workspace");
    let export = CuaExport::from_settings(&settings(
        workspace.path(),
        &backend,
        Some((u32::from(SCREEN_WIDTH), u32::from(SCREEN_HEIGHT))),
    ))
    .expect("export");

    let described = call(&export, "agent-a", "describe", json!({})).await;
    assert_eq!(outcome(&described), "answered_locally", "{described}");
    assert_eq!(export.diagnostics().backend_starts, 1);
    assert!(!export.diagnostics().point_space_refused);

    let capture = call(&export, "agent-a", "capture", json!({})).await;
    assert_eq!(outcome(&capture), "ok");
    let identity = capture["result"]["capture"].as_u64().expect("an identity");

    // An input operation never takes the lease as a side effect.
    let unleased = call(
        &export,
        "agent-a",
        "click",
        json!({"capture": identity, "x": 100, "y": 80}),
    )
    .await;
    assert_eq!(outcome(&unleased), "not_dispatched");
    assert_eq!(unleased["error"]["code"], "lease_not_held");
    assert_eq!(backend.ledger().pointer_clicks(), 0);

    let lease = call(&export, "agent-a", LEASE_ACQUIRE, json!({})).await;
    assert_eq!(outcome(&lease), "answered_locally", "{lease}");
    assert_eq!(lease["result"]["held"], true);

    let clicked = call(
        &export,
        "agent-a",
        "click",
        json!({"capture": identity, "x": 100, "y": 80}),
    )
    .await;
    assert_eq!(outcome(&clicked), "ok", "{clicked}");
    let typed = call(
        &export,
        "agent-a",
        "type_text",
        json!({"text": "synthetic"}),
    )
    .await;
    assert_eq!(outcome(&typed), "ok");

    // The second principal: reads are shared, input is refused, and nothing
    // it sends reaches the backend.
    let other = call(&export, "agent-b", LEASE_ACQUIRE, json!({})).await;
    assert_eq!(outcome(&other), "not_dispatched");
    assert_eq!(other["error"]["code"], "lease_held_by_another_session");
    let refused = call(&export, "agent-b", "press_key", json!({"key": "a"})).await;
    assert_eq!(outcome(&refused), "not_dispatched");

    assert_eq!(backend.ledger().points(), vec![(50, 40)]);
    assert_eq!(backend.ledger().pointer_clicks(), 1);
    assert_eq!(backend.ledger().typed_characters(), "synthetic".len());
    assert_eq!(backend.ledger().count("press_key"), 0);

    // Released, the second principal may act.
    let released = call(&export, "agent-a", LEASE_RELEASE, json!({})).await;
    assert_eq!(outcome(&released), "answered_locally", "{released}");
    let taken = call(&export, "agent-b", LEASE_ACQUIRE, json!({})).await;
    assert_eq!(outcome(&taken), "answered_locally");
    assert_eq!(export.diagnostics().sessions, 2);
    export.shutdown().await;
    backend.stop();
}

/// **M5-C19's guard at the export: a point space the backend contradicts is
/// not declared, and every coordinate is refused rather than placed.** The
/// fixture reports a 128x96 screen; declaring half of it would, if believed,
/// click at twice the intended position. On Linux the reading must equal the
/// declaration exactly; elsewhere a whole multiple is allowed, so the case
/// that is refused on every platform is a size the reading does not divide.
#[tokio::test]
async fn a_point_space_the_backend_contradicts_refuses_every_coordinate() {
    let backend = FixtureBackend::start().await.expect("fixture");
    let workspace = tempfile::tempdir().expect("workspace");
    let export = CuaExport::from_settings(&settings(
        workspace.path(),
        &backend,
        Some((u32::from(SCREEN_WIDTH) + 1, u32::from(SCREEN_HEIGHT))),
    ))
    .expect("export");
    call(&export, "agent-a", LEASE_ACQUIRE, json!({})).await;
    assert!(export.diagnostics().point_space_refused);
    let capture = call(&export, "agent-a", "capture", json!({})).await;
    let identity = capture["result"]["capture"].as_u64().expect("an identity");
    let clicked = call(
        &export,
        "agent-a",
        "click",
        json!({"capture": identity, "x": 10, "y": 10}),
    )
    .await;
    assert_eq!(outcome(&clicked), "not_dispatched");
    assert_eq!(clicked["error"]["code"], "capture_scale_undeclared");
    assert!(backend.ledger().points().is_empty());
    export.shutdown().await;
    backend.stop();
}

/// The control for the test above: the exact screen size is declared.
#[tokio::test]
async fn a_point_space_the_backend_confirms_is_declared() {
    let backend = FixtureBackend::start().await.expect("fixture");
    let workspace = tempfile::tempdir().expect("workspace");
    let export = CuaExport::from_settings(&settings(
        workspace.path(),
        &backend,
        Some((u32::from(SCREEN_WIDTH), u32::from(SCREEN_HEIGHT))),
    ))
    .expect("export");
    call(&export, "agent-a", LEASE_ACQUIRE, json!({})).await;
    assert!(!export.diagnostics().point_space_refused);
    let capture = call(&export, "agent-a", "capture", json!({})).await;
    let identity = capture["result"]["capture"].as_u64().expect("an identity");
    let clicked = call(
        &export,
        "agent-a",
        "click",
        json!({"capture": identity, "x": 10, "y": 10}),
    )
    .await;
    assert_eq!(outcome(&clicked), "ok", "{clicked}");
    assert_eq!(backend.ledger().points(), vec![(10, 10)]);
    export.shutdown().await;
    backend.stop();
}

/// The local configuration narrows: an operation the operator did not list
/// is refused before dispatch, however the backend and the grant read.
#[tokio::test]
async fn an_operation_the_operator_did_not_list_is_not_dispatched() {
    let backend = FixtureBackend::start().await.expect("fixture");
    let workspace = tempfile::tempdir().expect("workspace");
    let mut configured = settings(workspace.path(), &backend, None);
    configured.operations = vec!["describe".to_owned(), "capture".to_owned()];
    let export = CuaExport::from_settings(&configured).expect("export");
    call(&export, "agent-a", LEASE_ACQUIRE, json!({})).await;
    let typed = call(&export, "agent-a", "type_text", json!({"text": "x"})).await;
    assert_eq!(outcome(&typed), "not_dispatched");
    assert_eq!(typed["error"]["code"], "not_permitted");
    assert_eq!(backend.ledger().typed_characters(), 0);
    export.shutdown().await;
    backend.stop();
}

/// A backend that never publishes an address is reported as unavailable,
/// retryably, and nothing is dispatched.
#[tokio::test]
async fn a_backend_that_never_comes_up_is_unavailable_not_dispatched() {
    let backend = FixtureBackend::start().await.expect("fixture");
    let workspace = tempfile::tempdir().expect("workspace");
    let mut configured = settings(workspace.path(), &backend, None);
    configured.backend.args = vec!["-c".to_owned(), "exec cat >/dev/null".to_owned()];
    configured.backend.startup_seconds = Some(1);
    let export = CuaExport::from_settings(&configured).expect("export");
    let answer = call(&export, "agent-a", "screen_info", json!({})).await;
    assert_eq!(outcome(&answer), "not_dispatched");
    assert_eq!(answer["error"]["code"], "backend_unavailable");
    assert_eq!(answer["error"]["retryable"], true);
    assert_eq!(export.diagnostics().backend_start_failures, 1);
    assert!(backend.ledger().is_empty());
    backend.stop();
}

#[test]
fn a_lease_request_is_the_bare_envelope_and_nothing_else() {
    let ok = br#"{"version":"computer.v1","operation":"acquire_input_lease","params":{}}"#;
    assert!(is_lease_envelope(ok, LEASE_ACQUIRE));
    let no_params = br#"{"version":"computer.v1","operation":"acquire_input_lease"}"#;
    assert!(is_lease_envelope(no_params, LEASE_ACQUIRE));
    for refused in [
        &br#"{"version":"computer.v2","operation":"acquire_input_lease","params":{}}"#[..],
        br#"{"version":"computer.v1","operation":"acquire_input_lease","params":{"target":"x"}}"#,
        br#"{"version":"computer.v1","operation":"acquire_input_lease","params":{},"extra":1}"#,
        br#"{"version":"computer.v1","operation":"release_input_lease","params":{}}"#,
        b"not json",
    ] {
        assert!(!is_lease_envelope(refused, LEASE_ACQUIRE));
    }
}

#[test]
fn codes_are_identifiers_and_carry_no_payload() {
    assert_eq!(snake("ScaleUndeclared"), "scale_undeclared");
    assert_eq!(
        snake("UnexpectedStatus { status: 418 }"),
        "unexpected_status"
    );
    assert_eq!(snake("BackendRejected { status: 400 }"), "backend_rejected");
    let unknown = render(
        "click",
        Some(Operation::Click),
        &Dispatch::Dispatched(Completion::Unknown(
            tunnel_cua::outcome::UnknownReason::TransportLost,
        )),
    );
    let unknown = serde_json::to_value(unknown).unwrap();
    assert_eq!(unknown["outcome"], "unknown");
    assert_eq!(unknown["error"]["code"], "unknown_transport_lost");
    assert_eq!(unknown["error"]["retryable"], false);
    let failed = serde_json::to_value(render(
        "click",
        Some(Operation::Click),
        &Dispatch::Dispatched(Completion::Failed {
            code: FailureCode::PermissionDenied,
        }),
    ))
    .unwrap();
    assert_eq!(failed["error"]["code"], "permission_denied");
    assert_eq!(
        failed["error"]["retryable"], false,
        "a dispatched click is never retryable"
    );
    let typo = serde_json::to_value(render(
        "clik",
        None,
        &Dispatch::NotDispatched(NotDispatched::Operation(
            tunnel_cua::operation::Refusal::Unknown,
        )),
    ))
    .unwrap();
    assert_eq!(typo["outcome"], "not_dispatched");
    assert_eq!(typo["operation"], "clik");
}

/// **A request without a principal binding is refused, not given a shared
/// session.** Before the fix every such request fell into one `"none"`
/// session, so a second binding-less caller could use a lease the first had
/// taken. Nothing reaches the backend, and the backend is not even started.
#[tokio::test]
async fn a_request_without_a_principal_binding_is_refused() {
    let backend = FixtureBackend::start().await.expect("fixture");
    let workspace = tempfile::tempdir().expect("workspace");
    let export = CuaExport::from_settings(&settings(
        workspace.path(),
        &backend,
        Some((u32::from(SCREEN_WIDTH), u32::from(SCREEN_HEIGHT))),
    ))
    .expect("export");
    for (operation, params) in [
        (LEASE_ACQUIRE, json!({})),
        ("capture", json!({})),
        ("press_key", json!({"key": "a"})),
    ] {
        let answer = call_with(&export, None, operation, params.clone()).await;
        assert_eq!(outcome(&answer), "not_dispatched", "{answer}");
        assert_eq!(answer["error"]["code"], "principal_binding_missing");
        let empty = call_with(&export, Some(""), operation, params).await;
        assert_eq!(empty["error"]["code"], "principal_binding_missing");
    }
    assert_eq!(export.diagnostics().sessions, 0);
    assert_eq!(export.diagnostics().backend_starts, 0);
    assert!(backend.ledger().is_empty());
    backend.stop();
}

/// **A stale capture is refused at the export, as the demo relies on.** A
/// second capture supersedes the first, and a click on the first is
/// `capture_superseded`, not dispatched, with nothing on the ledger; the same
/// point on the fresh capture lands.
#[tokio::test]
async fn a_click_on_a_superseded_capture_is_refused_at_the_export() {
    let backend = FixtureBackend::start().await.expect("fixture");
    let workspace = tempfile::tempdir().expect("workspace");
    let export = CuaExport::from_settings(&settings(
        workspace.path(),
        &backend,
        Some((u32::from(SCREEN_WIDTH), u32::from(SCREEN_HEIGHT))),
    ))
    .expect("export");
    call(&export, "agent-a", LEASE_ACQUIRE, json!({})).await;
    let first = call(&export, "agent-a", "capture", json!({})).await["result"]["capture"]
        .as_u64()
        .expect("first identity");
    let second = call(&export, "agent-a", "capture", json!({})).await["result"]["capture"]
        .as_u64()
        .expect("second identity");
    let stale = call(
        &export,
        "agent-a",
        "click",
        json!({"capture": first, "x": 10, "y": 10}),
    )
    .await;
    assert_eq!(outcome(&stale), "not_dispatched", "{stale}");
    assert_eq!(stale["error"]["code"], "capture_superseded");
    assert_eq!(backend.ledger().pointer_clicks(), 0);
    let fresh = call(
        &export,
        "agent-a",
        "click",
        json!({"capture": second, "x": 10, "y": 10}),
    )
    .await;
    assert_eq!(outcome(&fresh), "ok", "{fresh}");
    assert_eq!(backend.ledger().points(), vec![(10, 10)]);
    export.shutdown().await;
    backend.stop();
}
