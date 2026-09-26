//! The device half of a `computer.v1` (CUA) export — M5 **Lane B**.
//!
//! **What this is.** An in-process `http-forward/1` handler for
//! `POST /computer` that supervises one real CUA backend (the pinned
//! `cua-computer-server` 0.3.46, started through an operator-named wrapper),
//! negotiates the operations it will serve, and answers each consumer request
//! through [`tunnel_cua_fixture::client::SessionFacade`] — the device-side
//! facade the Lane A tests judge against the fixture's ledger. The ordering
//! (schema, capability, lease, capture, dispatch) is `tunnel_cua::plan`'s and
//! is not re-derived here.
//!
//! **Three gates, all required.** This module exists only in a build with
//! the non-default `cua` feature; a configuration naming a CUA export is
//! refused by a build without it; and a build with it still refuses unless
//! [`crate::CUA_OPT_IN_ENV`] is `1`. **Run it only on a dedicated,
//! disposable machine**: the backend moves a real pointer and types on a
//! real keyboard, and `AGENTS.md` forbids that against anyone's desktop. None
//! of this module's dependencies can synthesise input or capture a screen
//! (`tunnel-cua/tests/host_untouched.rs`); the capability is the backend
//! process's.
//!
//! **Sessions are keyed by the relay's principal binding.** The relay derives
//! an opaque per-principal `tunnel-principal-binding` for every request and
//! refuses a consumer that sends its own, so one authenticated principal is
//! one device-side session: its input lease and its capture identities are
//! its own, and a second principal on the same export is refused the lease
//! while the first holds it.
//!
//! **The lease has a wire form here, and it is this export's choice** (task
//! row M5-C20, pending owner confirmation): `acquire_input_lease` and
//! `release_input_lease` are answered locally from device state, in the same
//! `computer.v1` envelope, before `tunnel_cua::schema` sees the body. The
//! pure schema carries no lease operation, and an input operation never takes
//! the lease as a side effect.
//!
//! **The display scale comes from a declared point space** (M5-C19 option
//! (b), applied by default pending owner confirmation, 2026-09-25): each
//! capture's ratio is derived from its own PNG, and the export refuses to
//! declare a point space that the backend's `get_screen_size` contradicts —
//! exact equality on Linux, where X11 has no scale; a whole multiple
//! elsewhere. A refused or missing declaration refuses every coordinate.
//!
//! **Not done here, and not claimed:** no restart on a failed health probe
//! (the supervisor can restart; nothing drives it on a timer yet), no grant
//! revision delivery (M5-C05), and no per-operation grant from the relay
//! (the catalog grants `http:invoke`, so the caller-grant term is every
//! operation and the local configuration is what narrows).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tunnel_http_bridge::{ChannelBody, Profile};

use tunnel_cua::capability::{
    CallerGrant, CaptureAuthority, LocalConfiguration, UpstreamSupport, negotiate,
};
use tunnel_cua::capture::PointSpace;
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::lease::{LeaseGrant, SessionId, TargetSession};
use tunnel_cua::outcome::{Completion, Dispatch, FailureCode, InputRefusal, NotDispatched};
use tunnel_cua::schema::{Response as CuaResponse, validate_request};
use tunnel_cua::{CuaLimits, CuaProfile, Operation};
use tunnel_cua_export::{BackendProcess, Health, Supervisor};
use tunnel_cua_fixture::client::{DeviceState, Dispatcher, SessionFacade, read_commands};

use crate::config::{CUA_PROFILE_ID, CuaExportSettings};
use crate::http_forward::HttpBody;

/// The locally answered operation that takes the exclusive input lease.
pub const LEASE_ACQUIRE: &str = "acquire_input_lease";
/// The locally answered operation that releases it.
pub const LEASE_RELEASE: &str = "release_input_lease";
/// Distinct principals one export tracks. A new principal beyond this is
/// refused, never admitted by evicting another's session and lease.
pub const MAX_SESSIONS: usize = 64;
/// The default target name when the configuration names none.
pub const DEFAULT_TARGET: &str = "primary";
/// How often the startup probe is retried while the backend comes up.
const PROBE_RETRY: Duration = Duration::from_millis(500);

/// Why a CUA export could not be registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CuaConfigError(pub &'static str);

impl std::fmt::Display for CuaConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for CuaConfigError {}

/// Payload-free counters of one CUA export.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CuaDiagnostics {
    pub requests: u64,
    pub backend_starts: u64,
    pub backend_start_failures: u64,
    pub dispatched: u64,
    pub not_dispatched: u64,
    pub answered_locally: u64,
    pub unknown_outcomes: u64,
    /// Whether the declared point space was refused because the backend's
    /// `get_screen_size` contradicted it (every coordinate is then refused).
    pub point_space_refused: bool,
    pub sessions: u64,
}

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    backend_starts: AtomicU64,
    backend_start_failures: AtomicU64,
    dispatched: AtomicU64,
    not_dispatched: AtomicU64,
    answered_locally: AtomicU64,
    unknown_outcomes: AtomicU64,
    point_space_refused: std::sync::atomic::AtomicBool,
}

/// One registered CUA export. Cheap to clone; clones share one backend.
#[derive(Clone)]
pub struct CuaExport {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for CuaExport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CuaExport")
            .field("target", &self.inner.target.as_str())
            .field("diagnostics", &self.diagnostics())
            .finish_non_exhaustive()
    }
}

struct Inner {
    process: BackendProcess,
    local: LocalConfiguration,
    point_space: Option<PointSpace>,
    target: TargetSession,
    limits: CuaLimits,
    state: Arc<DeviceState>,
    /// The supervised backend once it has been started, probed and
    /// negotiated; `None` before the first request and after a shutdown.
    backend: tokio::sync::Mutex<Option<Ready>>,
    sessions: Mutex<Sessions>,
    counters: Counters,
}

struct Ready {
    supervisor: Supervisor,
    endpoint: BackendEndpoint,
    permitted: BTreeSet<Operation>,
}

#[derive(Default)]
struct Sessions {
    next: u64,
    by_binding: BTreeMap<String, SessionEntry>,
}

struct SessionEntry {
    facade: Arc<SessionFacade>,
    grant: Option<LeaseGrant>,
}

/// What the backend-startup step hands a request.
#[derive(Clone)]
struct Negotiated {
    endpoint: BackendEndpoint,
    permitted: BTreeSet<Operation>,
    epoch: tunnel_cua_export::supervisor::LifecycleEpochHandle,
}

impl CuaExport {
    /// Build an export from a validated configuration table. Starts nothing:
    /// the backend is started, probed and negotiated on the first request.
    ///
    /// # Errors
    /// [`CuaConfigError`] for a configuration the typed crates refuse.
    pub fn from_settings(settings: &CuaExportSettings) -> Result<Self, CuaConfigError> {
        settings
            .validate()
            .map_err(|_| CuaConfigError("the cua export configuration is invalid"))?;
        if CuaProfile::parse_id(&settings.profile).is_none() || settings.profile != CUA_PROFILE_ID {
            return Err(CuaConfigError("a cua export's profile must be computer-v1"));
        }
        let mut local = LocalConfiguration::none();
        for name in &settings.operations {
            let operation = Operation::parse(name).ok_or(CuaConfigError(
                "a cua export names an operation computer.v1 does not carry",
            ))?;
            local = local.with(operation);
        }
        let backend = &settings.backend;
        let mut process = BackendProcess::new(
            backend.command.clone(),
            backend.args.clone(),
            backend.workspace.clone(),
            backend.address_file.clone(),
        )
        .map_err(|_| CuaConfigError("the cua backend process configuration is invalid"))?;
        if let Some(seconds) = backend.startup_seconds {
            process = process
                .with_startup(Duration::from_secs(seconds))
                .map_err(|_| CuaConfigError("a cua backend's startup_seconds is out of range"))?;
        }
        for name in &backend.inherit_env {
            process = process.inheriting(name);
        }
        for (name, value) in &backend.env {
            process = process.with_env(name, value);
        }
        let point_space = match (settings.point_width, settings.point_height) {
            (Some(width), Some(height)) => Some(
                PointSpace::new(width, height)
                    .map_err(|_| CuaConfigError("a cua export's point size is out of range"))?,
            ),
            _ => None,
        };
        let target = TargetSession::new(settings.target.as_deref().unwrap_or(DEFAULT_TARGET));
        Ok(Self {
            inner: Arc::new(Inner {
                process,
                local,
                point_space,
                target,
                limits: CuaLimits::default(),
                state: DeviceState::new(),
                backend: tokio::sync::Mutex::new(None),
                sessions: Mutex::new(Sessions::default()),
                counters: Counters::default(),
            }),
        })
    }

    /// This export's `http-forward/1` policies: `tunnel-cua`'s own table, the
    /// same one the relay selects for `computer-v1`.
    ///
    /// # Errors
    /// Only if the pinned tables are inconsistent.
    pub fn profile_policies(&self) -> Result<Profile, CuaConfigError> {
        CuaProfile::ComputerV1
            .policies(self.inner.limits)
            .map_err(|_| CuaConfigError("the pinned computer.v1 profile tables are inconsistent"))
    }

    /// Payload-free counters.
    #[must_use]
    pub fn diagnostics(&self) -> CuaDiagnostics {
        let counters = &self.inner.counters;
        let sessions = self
            .inner
            .sessions
            .lock()
            .map(|sessions| sessions.by_binding.len() as u64)
            .unwrap_or_default();
        CuaDiagnostics {
            requests: counters.requests.load(Ordering::Relaxed),
            backend_starts: counters.backend_starts.load(Ordering::Relaxed),
            backend_start_failures: counters.backend_start_failures.load(Ordering::Relaxed),
            dispatched: counters.dispatched.load(Ordering::Relaxed),
            not_dispatched: counters.not_dispatched.load(Ordering::Relaxed),
            answered_locally: counters.answered_locally.load(Ordering::Relaxed),
            unknown_outcomes: counters.unknown_outcomes.load(Ordering::Relaxed),
            point_space_refused: counters.point_space_refused.load(Ordering::Relaxed),
            sessions,
        }
    }

    /// Stop the supervised backend now, invalidating every lease and capture
    /// identity held against it. The backend's process group is also killed
    /// when the last clone of this export is dropped.
    pub async fn shutdown(&self) {
        let mut backend = self.inner.backend.lock().await;
        if let Some(mut ready) = backend.take() {
            let _ = ready.supervisor.stop(self.inner.state.as_ref()).await;
        }
    }

    /// Serve one `POST /computer` exchange.
    ///
    /// Every outcome is a `200` whose `computer.v1` body carries the outcome:
    /// the consumer reads the payload, never the status, exactly as this
    /// profile reads the pinned backend's.
    pub async fn handle(&self, request: Request<ChannelBody>) -> Response<HttpBody> {
        self.inner.counters.requests.fetch_add(1, Ordering::Relaxed);
        let (parts, body) = request.into_parts();
        // **No binding, no session.** The relay ingress always derives one
        // for a `computer-v1` request, so a request without it did not come
        // through an authenticating ingress. Folding every such request into
        // one shared session would let any of them use a lease another took.
        // Refused before the body is read or the backend started.
        let Some(binding) = parts
            .headers
            .get(tunnel_cua::headers::TUNNEL_PRINCIPAL_BINDING)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
        else {
            self.inner
                .counters
                .not_dispatched
                .fetch_add(1, Ordering::Relaxed);
            return self.reply(&CuaResponse::not_dispatched_retryable(
                "",
                "principal_binding_missing",
                "the request carries no relay principal binding",
                false,
            ));
        };
        let Ok(bytes) = collect_limited(body, self.inner.limits.request_body()).await else {
            return self.reply(&CuaResponse::not_dispatched(
                "",
                "request_too_large",
                "the request body exceeds the computer.v1 limit",
            ));
        };
        let name = operation_name(&bytes);
        let negotiated = match self.ensure_ready().await {
            Ok(negotiated) => negotiated,
            Err(reason) => {
                return self.reply(&CuaResponse::not_dispatched_retryable(
                    &name,
                    "backend_unavailable",
                    reason,
                    true,
                ));
            }
        };
        let (facade, lease) = match self.session(&binding, &negotiated) {
            Ok(session) => session,
            Err(response) => return self.reply(&response),
        };
        if name == LEASE_ACQUIRE || name == LEASE_RELEASE {
            return self.reply(&self.lease(&binding, &name, &bytes, &facade, lease));
        }
        let dispatch = facade
            .handle(&bytes, self.inner.limits.request_body())
            .await;
        let operation = Operation::parse(&name);
        self.count(&dispatch);
        self.reply(&render(&name, operation, &dispatch))
    }

    fn count(&self, dispatch: &Dispatch) {
        let counters = &self.inner.counters;
        match dispatch {
            Dispatch::NotDispatched(_) => counters.not_dispatched.fetch_add(1, Ordering::Relaxed),
            Dispatch::AnsweredLocally(_) => {
                counters.answered_locally.fetch_add(1, Ordering::Relaxed)
            }
            Dispatch::Dispatched(Completion::Unknown(_)) => {
                counters.dispatched.fetch_add(1, Ordering::Relaxed);
                counters.unknown_outcomes.fetch_add(1, Ordering::Relaxed)
            }
            Dispatch::Dispatched(_) => counters.dispatched.fetch_add(1, Ordering::Relaxed),
        };
    }

    fn reply(&self, response: &CuaResponse) -> Response<HttpBody> {
        let body = serde_json::to_vec(response).unwrap_or_else(|_| b"{}".to_vec());
        let mut out = Response::new(full(Bytes::from(body)));
        out.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        out
    }

    /// Start, probe and negotiate the backend once; later requests reuse it.
    async fn ensure_ready(&self) -> Result<Negotiated, &'static str> {
        let mut backend = self.inner.backend.lock().await;
        if let Some(ready) = &*backend {
            return Ok(Negotiated {
                endpoint: ready.endpoint,
                permitted: ready.permitted.clone(),
                epoch: ready.supervisor.lifecycle_epoch(),
            });
        }
        self.inner
            .counters
            .backend_starts
            .fetch_add(1, Ordering::Relaxed);
        match self.start().await {
            Ok(ready) => {
                let negotiated = Negotiated {
                    endpoint: ready.endpoint,
                    permitted: ready.permitted.clone(),
                    epoch: ready.supervisor.lifecycle_epoch(),
                };
                *backend = Some(ready);
                Ok(negotiated)
            }
            Err(reason) => {
                self.inner
                    .counters
                    .backend_start_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(reason)
            }
        }
    }

    async fn start(&self) -> Result<Ready, &'static str> {
        let mut supervisor = Supervisor::new(self.inner.process.clone());
        let endpoint = supervisor
            .start()
            .await
            .map_err(|_| "the cua backend did not start or published no loopback address")?;

        // Health: a dispatched, succeeded, read-only, OS-gated probe --
        // `screen_info`, never a click. Retried while the backend comes up.
        let probe_body = tunnel_cua_fixture::client::request_body("screen_info", json!({}));
        let probe_request = validate_request(&probe_body, self.inner.limits.request_body())
            .map_err(|_| "the startup probe is not a valid computer.v1 request")?;
        let prober = SessionFacade::new(
            Arc::clone(&self.inner.state),
            Dispatcher::new(endpoint, BTreeSet::from([Operation::ScreenInfo])),
            SessionId::new(0),
            self.inner.target.clone(),
        );
        let deadline = tokio::time::Instant::now() + self.inner.process.startup;
        let (probe, evidence) = loop {
            let dispatch = prober
                .handle(&probe_body, self.inner.limits.request_body())
                .await;
            if let Health::Working(evidence) = supervisor.assess(&probe_request, &dispatch) {
                break (dispatch, evidence);
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = supervisor.stop(self.inner.state.as_ref()).await;
                return Err("the cua backend never answered its read-only health probe");
            }
            tokio::time::sleep(PROBE_RETRY).await;
        };

        let commands = match read_commands(endpoint).await {
            Ok(commands) => commands,
            Err(_) => {
                let _ = supervisor.stop(self.inner.state.as_ref()).await;
                return Err("the cua backend's command listing could not be read");
            }
        };
        let authority = CaptureAuthority::from_version_reading(
            &Dispatcher::new(endpoint, BTreeSet::new())
                .read_version()
                .await,
        );
        let upstream = UpstreamSupport::new(&commands, evidence, authority);
        let grant = Operation::ALL
            .into_iter()
            .fold(CallerGrant::none(), CallerGrant::with);
        let permitted = negotiate(&self.inner.local, &upstream, &grant);

        // M5-C19 option (b): declare the point space only if the backend's
        // own screen-size reading agrees with it.
        let declared = self
            .inner
            .point_space
            .filter(|space| point_space_agrees(space, &probe));
        self.inner.counters.point_space_refused.store(
            self.inner.point_space.is_some() && declared.is_none(),
            Ordering::Relaxed,
        );
        self.inner.state.declare_point_space(declared);

        Ok(Ready {
            supervisor,
            endpoint,
            permitted,
        })
    }

    /// The session for one principal binding, created on first use.
    fn session(
        &self,
        binding: &str,
        negotiated: &Negotiated,
    ) -> Result<(Arc<SessionFacade>, Option<LeaseGrant>), Box<CuaResponse>> {
        let mut sessions = self
            .inner
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = sessions.by_binding.get(binding) {
            return Ok((Arc::clone(&entry.facade), entry.grant.clone()));
        }
        if sessions.by_binding.len() >= MAX_SESSIONS {
            return Err(Box::new(CuaResponse::not_dispatched(
                "",
                "session_capacity",
                "this export tracks no more principals",
            )));
        }
        sessions.next += 1;
        let facade = Arc::new(SessionFacade::new(
            Arc::clone(&self.inner.state),
            Dispatcher::new(negotiated.endpoint, negotiated.permitted.clone())
                .watching(negotiated.epoch.clone()),
            SessionId::new(sessions.next),
            self.inner.target.clone(),
        ));
        sessions.by_binding.insert(
            binding.to_owned(),
            SessionEntry {
                facade: Arc::clone(&facade),
                grant: None,
            },
        );
        Ok((facade, None))
    }

    /// `acquire_input_lease` / `release_input_lease`, answered from device
    /// state. The envelope is `computer.v1`'s, with empty `params`.
    fn lease(
        &self,
        binding: &str,
        name: &str,
        bytes: &[u8],
        facade: &SessionFacade,
        held: Option<LeaseGrant>,
    ) -> CuaResponse {
        if !is_lease_envelope(bytes, name) {
            return CuaResponse::not_dispatched(
                name,
                "schema",
                "a lease request is {version, operation, params: {}} and nothing else",
            );
        }
        let counters = &self.inner.counters;
        let outcome = if name == LEASE_ACQUIRE {
            facade.acquire_input_lease().map(Some)
        } else {
            match &held {
                Some(grant) => facade.release_input_lease(grant).map(|()| None),
                None => Err(tunnel_cua::lease::LeaseRefusal::NotHeld),
            }
        };
        match outcome {
            Ok(grant) => {
                let result = json!({
                    "target": self.inner.target.as_str(),
                    "held": grant.is_some(),
                    "lease": grant.as_ref().map(|grant| grant.lease().value()),
                });
                if let Some(entry) = self
                    .inner
                    .sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .by_binding
                    .get_mut(binding)
                {
                    entry.grant = grant;
                }
                counters.answered_locally.fetch_add(1, Ordering::Relaxed);
                lease_response(name, "answered_locally", Some(result), None)
            }
            Err(refusal) => {
                counters.not_dispatched.fetch_add(1, Ordering::Relaxed);
                lease_response(
                    name,
                    "not_dispatched",
                    None,
                    Some((
                        format!("lease_{}", snake(&format!("{refusal:?}"))),
                        refusal.to_string(),
                    )),
                )
            }
        }
    }
}

/// A lease answer in the `computer.v1` envelope. Built by hand because the
/// lease operations are this export's, not `tunnel_cua::Operation`s.
fn lease_response(
    name: &str,
    outcome: &str,
    result: Option<Value>,
    error: Option<(String, String)>,
) -> CuaResponse {
    let mut value = json!({
        "version": tunnel_cua::SCHEMA_VERSION,
        "operation": name,
        "outcome": outcome,
    });
    if let Some(result) = result {
        value["result"] = result;
    }
    if let Some((code, message)) = error {
        // A refused lease request changed nothing, so it is always safe to
        // send again.
        value["error"] = json!({"code": code, "message": message, "retryable": true});
    }
    serde_json::from_value(value).unwrap_or_else(|_| {
        CuaResponse::not_dispatched(name, "internal", "the lease answer could not be rendered")
    })
}

/// Whether a `screen_info` probe's reading agrees with a declared point space.
fn point_space_agrees(space: &PointSpace, probe: &Dispatch) -> bool {
    let Dispatch::Dispatched(Completion::Ok(result)) = probe else {
        return false;
    };
    let size = result.get("size").unwrap_or(result);
    let read = |key: &str| {
        size.get(key)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
    };
    let (Some(width), Some(height)) = (read("width"), read("height")) else {
        return false;
    };
    space.agrees_with_screen_size(width, height, pixel_multiples())
}

/// The whole factors by which the backend's `get_screen_size` may exceed the
/// point space on this platform. X11 has no scale, so Linux requires equality.
const fn pixel_multiples() -> &'static [u32] {
    if cfg!(target_os = "linux") {
        &[1]
    } else {
        &[1, 2, 3]
    }
}

/// The body is exactly `{"version": "computer.v1", "operation": <name>,
/// "params": {}}` (params may be omitted).
fn is_lease_envelope(bytes: &[u8], name: &str) -> bool {
    let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    object
        .keys()
        .all(|key| matches!(key.as_str(), "version" | "operation" | "params"))
        && object.get("version").and_then(Value::as_str) == Some(tunnel_cua::SCHEMA_VERSION)
        && object.get("operation").and_then(Value::as_str) == Some(name)
        && object
            .get("params")
            .is_none_or(|params| params.as_object().is_some_and(serde_json::Map::is_empty))
}

/// The operation name a request body names, for echoing only; never trusted.
fn operation_name(bytes: &[u8]) -> String {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| {
            value
                .get("operation")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|name| name.len() <= 64 && name.bytes().all(|byte| byte.is_ascii_graphic()))
        .unwrap_or_default()
}

/// Render one [`Dispatch`] in the `computer.v1` wire envelope.
///
/// Retryability is never decided here: it comes from
/// `Response::not_dispatched_for` (which reads `retry_is_safe_for`),
/// `Response::failed` (which reads `mutates_target`) and `Response::unknown`
/// (never). Codes are identifiers derived from the typed reasons; messages
/// are this repository's own words, never a backend's.
#[must_use]
pub fn render(name: &str, operation: Option<Operation>, dispatch: &Dispatch) -> CuaResponse {
    let Some(operation) = operation else {
        // An operation this build cannot parse was refused before dispatch;
        // anything else without an operation is a defect, reported as not
        // retryable rather than guessed at.
        return match dispatch {
            Dispatch::NotDispatched(refusal) => {
                let (code, message) = refusal_code(refusal);
                CuaResponse::not_dispatched(name, &code, &message)
            }
            _ => CuaResponse::not_dispatched_retryable(
                name,
                "internal",
                "an unparsed operation produced a dispatch",
                false,
            ),
        };
    };
    match dispatch {
        Dispatch::AnsweredLocally(result) => {
            CuaResponse::answered_locally(operation, result.clone())
        }
        Dispatch::Dispatched(Completion::Ok(result)) => CuaResponse::ok(operation, result.clone()),
        Dispatch::Dispatched(Completion::Failed { code }) => {
            let (code, message) = match code {
                FailureCode::BackendReported => {
                    ("backend_reported", "the backend reported a failure")
                }
                FailureCode::Unsupported => {
                    ("unsupported", "the backend does not support this operation")
                }
                FailureCode::PermissionDenied => (
                    "permission_denied",
                    "the backend reported an OS permission refusal",
                ),
            };
            CuaResponse::failed(operation, code, message)
        }
        Dispatch::Dispatched(Completion::Unknown(reason)) => CuaResponse::unknown(
            operation,
            &format!("unknown_{}", snake(&format!("{reason:?}"))),
            "the operation reached the backend and its effect is not known; do not retry it",
        ),
        Dispatch::NotDispatched(refusal) => {
            let (code, message) = refusal_code(refusal);
            CuaResponse::not_dispatched_for(operation, *refusal, &code, &message)
        }
    }
}

fn refusal_code(refusal: &NotDispatched) -> (String, String) {
    match refusal {
        NotDispatched::Schema(error) => ("schema".to_owned(), error.to_string()),
        NotDispatched::InputAuthority(InputRefusal::Lease(lease)) => (
            format!("lease_{}", snake(&format!("{lease:?}"))),
            lease.to_string(),
        ),
        NotDispatched::InputAuthority(InputRefusal::Capture(capture)) => (
            format!("capture_{}", snake(&format!("{capture:?}"))),
            capture.to_string(),
        ),
        other => (
            snake(&format!("{other:?}")),
            "the operation was not dispatched".to_owned(),
        ),
    }
}

/// `ScaleUndeclared` -> `scale_undeclared`; stops at the first character
/// that is not alphanumeric, so a variant's payload never reaches a code.
fn snake(debug: &str) -> String {
    let mut out = String::new();
    for character in debug.chars() {
        if !character.is_ascii_alphanumeric() {
            break;
        }
        if character.is_ascii_uppercase() {
            if !out.is_empty() {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
        } else {
            out.push(character);
        }
    }
    out
}

fn full(bytes: Bytes) -> HttpBody {
    http_body_util::Full::new(bytes)
        .map_err(|never| match never {})
        .boxed()
}

async fn collect_limited(body: ChannelBody, limit: u64) -> Result<Bytes, ()> {
    let mut body = std::pin::pin!(body);
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if (out.len() as u64).saturating_add(data.len() as u64) > limit {
                return Err(());
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests;
