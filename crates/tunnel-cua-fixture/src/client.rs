//! The Lane A dispatch path: validate, negotiate, check the endpoint, then —
//! and only then — send one `/cmd` exchange and classify the answer.
//!
//! **Where this lives, and why.** The *policy* — the ordering of the checks,
//! the lease, the capture carry-forward — lives in `tunnel-cua`, which is pure.
//! What lives here is the part that is genuinely transport, plus [`SessionFacade`]:
//! the device-side state one tunnel session's operations are planned against,
//! and the one place a lease is taken and a capture identity is issued. It
//! lives beside the fixture because the fixture is the only backend it is
//! allowed to talk to.
//!
//! **Supervision arrived in chunk 4 and is still not *here*.** The lifecycle,
//! the health probe and the deadman are `tunnel-cua-export`; what this file
//! gained is the one place they meet this state: [`DeviceState`] implements
//! [`tunnel_cua_export::supervisor::InputAuthority`], so a supervised restart
//! drops every lease and forgets every capture identity through
//! [`tunnel_cua::supervision::invalidate`].
//!
//! A restarted backend is a **new endpoint**, so a session driving it needs a
//! new [`SessionFacade`] built on the same [`DeviceState`]. There is
//! deliberately no `retarget`: a facade that could be pointed at a different
//! backend in place would be a facade whose outstanding operations changed
//! meaning underneath them, and "which backend was this dispatched to" is
//! exactly the question a restart makes load-bearing.
//!
//! **The ordering is the contract.** Every check below the comment marked
//! `dispatch boundary` may produce a [`Completion`]; every check above it may
//! only produce a [`NotDispatched`]. A test reads the fixture's ledger to
//! check that claim rather than taking this module's word for it.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use tunnel_cua::capability::{CallerGrant, LocalConfiguration, UpstreamSupport};
use tunnel_cua::capture::Captures;
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::lease::{
    GrantRevision, InputLeases, LeaseGrant, LeaseRefusal, SessionId, TargetSession,
};
use tunnel_cua::operation::Operation;
use tunnel_cua::outcome::{
    Completion, Dispatch, NotDispatched, UnknownReason, classify_backend_response,
};
use tunnel_cua::plan::{Planned, SessionContext, discovery_payload, plan};
use tunnel_cua::schema::Request;

use crate::CMD_PATH;

/// Everything the dispatcher needs that is not the request.
pub struct Dispatcher {
    endpoint: BackendEndpoint,
    permitted: BTreeSet<Operation>,
    deadline: Duration,
    /// The supervisor's lifecycle epoch, if this dispatcher was given one.
    ///
    /// Detached by default, so a dispatcher talking to a backend nobody
    /// supervises attributes nothing and the transport's own reason survives.
    epoch: tunnel_cua_export::supervisor::LifecycleEpochHandle,
}

/// The default per-exchange deadline. Finite; there is no unlimited value.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(10);

impl Dispatcher {
    /// Build a dispatcher for a negotiated capability set.
    ///
    /// The capability set is computed by the caller through
    /// [`tunnel_cua::capability::negotiate`], so the dispatcher cannot widen
    /// it: it has no access to the three inputs, only to their intersection.
    #[must_use]
    pub fn new(endpoint: BackendEndpoint, permitted: BTreeSet<Operation>) -> Self {
        Self {
            endpoint,
            permitted,
            deadline: DEFAULT_DEADLINE,
            epoch: tunnel_cua_export::supervisor::LifecycleEpochHandle::detached(),
        }
    }

    /// Watch a supervisor's lifecycle epoch, so an exchange that fails across
    /// a supervised restart is reported as a restart rather than as a lost
    /// connection.
    ///
    /// **This is the production caller `docs/tasks.md` M5-C10 says
    /// [`tunnel_cua::supervision::restart_outcome`] lacked.** Without it the
    /// contract still held -- `TransportLost` is equally `Dispatched`, equally
    /// `Unknown` and equally non-retryable -- but the named reason never
    /// reached a consumer, so a diagnostic could not tell "the backend was
    /// replaced under you" from "the network went away".
    #[must_use]
    pub fn watching(mut self, epoch: tunnel_cua_export::supervisor::LifecycleEpochHandle) -> Self {
        self.epoch = epoch;
        self
    }

    /// Build one from the three negotiation inputs.
    #[must_use]
    pub fn negotiated(
        endpoint: BackendEndpoint,
        local: &LocalConfiguration,
        upstream: &UpstreamSupport,
        grant: &CallerGrant,
    ) -> Self {
        Self::new(
            endpoint,
            tunnel_cua::capability::negotiate(local, upstream, grant),
        )
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    #[must_use]
    pub fn permits(&self, operation: Operation) -> bool {
        self.permitted.contains(&operation)
    }

    /// The negotiated set this dispatcher was built with.
    #[must_use]
    pub const fn permitted(&self) -> &BTreeSet<Operation> {
        &self.permitted
    }

    /// Validate a consumer request body and dispatch it if everything allows.
    ///
    /// **The ordering is not written here.** It lives in
    /// [`tunnel_cua::plan::plan`], in the production crate, so a future
    /// device-side facade inherits it rather than re-deriving it. This
    /// function is the part that is genuinely transport: take the plan, and
    /// either send it or answer it locally.
    pub async fn handle(&self, body: &[u8], limit: u64, context: &SessionContext<'_>) -> Dispatch {
        self.dispatch_planned(plan(body, limit, &self.permitted, context))
            .await
            .1
    }

    /// Plan, then dispatch, returning the plan alongside the outcome.
    ///
    /// [`SessionFacade`] needs both: the outcome to return, and the plan to
    /// know whether a capture identity should be issued and for which display.
    /// Splitting them out here keeps the facade from re-deriving either.
    async fn dispatch_planned(
        &self,
        planned: Result<Planned, Dispatch>,
    ) -> (Option<Planned>, Dispatch) {
        // ---- above the dispatch boundary: nothing has been sent -------------
        let planned = match planned {
            Ok(planned) => planned,
            Err(refused) => return (None, refused),
        };
        let payload = match &planned {
            // `describe` is answered from the negotiated set -- the only
            // honest thing it could be answered from, since a config echo
            // would be the trap. It is **not** a dispatch, and reporting it as
            // one made `reached_the_backend()` true for an operation that sent
            // no bytes.
            Planned::AnswerLocally { .. } => {
                return (Some(planned), Dispatch::AnsweredLocally(self.describe()));
            }
            Planned::Dispatch { payload, .. } => payload.clone(),
        };

        // ---- the dispatch boundary -----------------------------------------
        // Past this line the backend may have seen the command, so no failure
        // may be reported as `NotDispatched` unless we know the request was
        // never fully written.
        let dispatch = self.send(&payload).await;
        (Some(planned), dispatch)
    }

    /// Read the backend's `version` response, which is where
    /// `desktop_capture_authorized` lives.
    ///
    /// Separate from [`Dispatcher::handle`] because `version` is not a
    /// `computer.v1` operation: it is issued during capability discovery, on
    /// nobody's behalf, and it goes through
    /// [`tunnel_cua::plan::discovery_payload`] which admits only the commands
    /// `describe` reads.
    pub async fn read_version(&self) -> Dispatch {
        match discovery_payload(tunnel_cua::capability::CAPTURE_AUTHORITY_COMMAND) {
            Err(refusal) => Dispatch::NotDispatched(refusal),
            Ok(payload) => self.send(&payload).await,
        }
    }

    /// The `describe` answer: the negotiated set, and facts this dispatcher
    /// can actually observe.
    ///
    /// `endpoint_is_loopback` is **derived from the endpoint**, not written as
    /// a literal. It is tautologically true given that
    /// [`BackendEndpoint`] cannot hold anything else -- but a hardcoded `true`
    /// asserting a safety property is the config-echo shape this chunk spends
    /// its length policing, and a derived one costs nothing.
    fn describe(&self) -> Value {
        json!({
            "operations": self
                .permitted
                .iter()
                .map(|operation| operation.name())
                .collect::<Vec<_>>(),
            "endpoint_is_loopback": self.endpoint.address().ip().is_loopback(),
        })
    }

    async fn send(&self, payload: &Value) -> Dispatch {
        // **Read before a single byte is written**, so the comparison below
        // spans the whole exchange. Reading it after the write would leave the
        // request-writing window unwatched, which is exactly the window a
        // restart-killed click occupies.
        let before = self.epoch.read();
        let transport = match tokio::time::timeout(self.deadline, self.exchange(payload)).await {
            // The deadline expired. We had already begun writing, so the
            // outcome is unknown rather than not dispatched.
            Err(_) => Dispatch::Dispatched(Completion::Unknown(UnknownReason::DeadlineExpired)),
            Ok(Err(stage)) => stage.into_dispatch(),
            Ok(Ok((status, body))) => classify_backend_response(status, &body),
        };
        // The attribution is a pure function of the two readings and the
        // transport's own answer; this line owns none of the policy. It cannot
        // widen retryability -- `attribution_never_changes_what_a_retry_is_
        // allowed_to_do` measures that over the full cross-product.
        tunnel_cua::supervision::attribute_restart(before, self.epoch.read(), transport)
    }

    /// One HTTP/1.1 exchange against the fixture.
    ///
    /// The error type is the **stage** the failure happened at, because that
    /// is precisely what decides `NotDispatched` versus `Unknown`. An error
    /// that merely said "I/O error" would have thrown the distinction away at
    /// the only point where it is recoverable.
    async fn exchange(&self, payload: &Value) -> Result<(u16, Vec<u8>), FailureStage> {
        let mut stream = TcpStream::connect(self.endpoint.address())
            .await
            .map_err(|_| FailureStage::Connecting)?;
        let body = payload.to_string();
        let request = format!(
            "POST {CMD_PATH} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.endpoint.address(),
            body.len()
        );
        // Written and flushed as one unit. Until this returns Ok, nothing was
        // fully delivered and the request is safely `NotReached`.
        //
        // **The assumption this rests on, stated rather than left implicit.**
        // Treating a partial write as `NotDispatched` is only sound because
        // the backend will not act on a truncated request: the pinned server
        // reads a `Content-Length`-framed body and dispatches to the command
        // registry **after** the body is complete, so bytes that never arrived
        // cannot have been parsed into a command. A backend that dispatched
        // incrementally -- a chunked or streaming command surface -- would
        // break this, and `/ws` is exactly such a surface. It is deferred
        // (`cua_pin::WEBSOCKET_DEFERRAL_RECORDED_AS`), and a chunk that takes
        // it up must revisit this mapping rather than inherit it.
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| FailureStage::Writing)?;
        stream.flush().await.map_err(|_| FailureStage::Writing)?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|_| FailureStage::Reading)?;
        if response.is_empty() {
            // The connection closed with no answer at all, after we had
            // written the whole request. Dispatched; outcome unknown.
            return Err(FailureStage::Reading);
        }
        parse_response(&response).ok_or(FailureStage::Reading)
    }
}

/// Where in the exchange a failure happened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureStage {
    /// The connection was never established. Nothing was sent.
    Connecting,
    /// The request was not fully written. Partial HTTP is not a command: the
    /// backend cannot have parsed a body it did not receive.
    Writing,
    /// The request was fully written and the answer was lost.
    Reading,
}

impl FailureStage {
    const fn into_dispatch(self) -> Dispatch {
        match self {
            Self::Connecting | Self::Writing => Dispatch::NotDispatched(NotDispatched::NotReached),
            Self::Reading => {
                Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost))
            }
        }
    }
}

/// Split an HTTP/1.1 response into its status and body.
fn parse_response(bytes: &[u8]) -> Option<(u16, Vec<u8>)> {
    let separator = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = core::str::from_utf8(&bytes[..separator]).ok()?;
    let status = head
        .split("\r\n")
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, bytes[separator + 4..].to_vec()))
}

/// Read the backend's `/commands` listing.
///
/// Separate from [`Dispatcher`] because it is part of building an
/// [`UpstreamSupport`], not part of dispatching an operation — and because a
/// `/commands` reading is **not** on its own evidence that a backend can act.
///
/// # Errors
/// Any I/O failure, or a response this function cannot parse.
pub async fn read_commands(endpoint: BackendEndpoint) -> std::io::Result<Vec<String>> {
    let mut stream = TcpStream::connect(endpoint.address()).await?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        crate::COMMANDS_PATH,
        endpoint.address()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let (_, body) = parse_response(&response).ok_or(std::io::ErrorKind::InvalidData)?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| std::io::ErrorKind::InvalidData)?;
    Ok(value
        .get("commands")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default())
}

/// Build a `computer.v1` request body, the way a consumer would.
#[must_use]
pub fn request_body(operation: &str, params: Value) -> Vec<u8> {
    json!({
        "version": tunnel_cua::SCHEMA_VERSION,
        "operation": operation,
        "params": params,
    })
    .to_string()
    .into_bytes()
}

/// A convenience for a validated request's operation, for tests that need to
/// name what they sent.
#[must_use]
pub fn operation_of(request: &Request) -> Operation {
    request.operation()
}

/// The device-side state shared by every tunnel session on one device.
///
/// One lease registry and one capture registry, because both are properties of
/// the **device**, not of a session: a lease that was per-session could not
/// exclude anybody, and a capture registry that was per-session could not
/// notice that another session's capture superseded yours.
#[derive(Debug, Default)]
pub struct DeviceState {
    leases: Mutex<InputLeases>,
    captures: Mutex<Captures>,
}

impl DeviceState {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Which session holds the input lease for a target, if any. For tests
    /// that need to read the registry rather than infer it from a refusal.
    #[must_use]
    pub fn holder(&self, target: &TargetSession) -> Option<SessionId> {
        self.leases
            .lock()
            .expect("the lease mutex is never poisoned by fixture code")
            .holder(target)
    }

    /// Drop the leases of a session whose grant revision has advanced.
    ///
    /// **The M3-16 mechanism, with no production caller.** See
    /// `tunnel_cua::lease` and `docs/tasks.md` M5-C05.
    pub fn reconcile_grant(
        &self,
        session: SessionId,
        revision: GrantRevision,
    ) -> Vec<TargetSession> {
        self.leases
            .lock()
            .expect("the lease mutex is never poisoned by fixture code")
            .reconcile_grant(session, revision)
    }

    /// How many capture identities this device is holding.
    ///
    /// For a test that must read the registry rather than infer its size from
    /// a refusal.
    #[must_use]
    pub fn capture_count(&self) -> usize {
        self.captures
            .lock()
            .expect("the capture mutex is never poisoned by fixture code")
            .len()
    }
}

/// **The restart contract, wired to the device's own registries.**
///
/// This is the whole production shape of the M5-C08 decision: a supervised
/// restart hands the device state to
/// [`tunnel_cua::supervision::invalidate`], which drops every input lease and
/// forgets every capture identity in one call. There is no implementation of
/// this trait that keeps a lease, and
/// [`tunnel_cua_export::Supervisor::restart`] takes it as a required argument,
/// so a restart cannot happen without one.
impl tunnel_cua_export::supervisor::InputAuthority for DeviceState {
    fn invalidate(
        &self,
        generation: tunnel_cua::supervision::BackendGeneration,
    ) -> tunnel_cua::supervision::Invalidation {
        // Both locks, in the same order everything else in this file takes
        // them, and released before the call returns. Nothing is dispatched
        // while they are held.
        let mut leases = self
            .leases
            .lock()
            .expect("the lease mutex is never poisoned by fixture code");
        let mut captures = self
            .captures
            .lock()
            .expect("the capture mutex is never poisoned by fixture code");
        tunnel_cua::supervision::invalidate(&mut leases, &mut captures, generation)
    }
}

/// One tunnel session's view of a device: its lease, its captures, its
/// dispatcher.
///
/// This is the shape D3 describes — cross-exchange state keyed by tunnel
/// session, device-side, never in the codec — reduced to what Lane A needs.
pub struct SessionFacade {
    state: Arc<DeviceState>,
    dispatcher: Dispatcher,
    session: SessionId,
    target: TargetSession,
    grant_revision: GrantRevision,
    carrier_generation: u64,
}

impl SessionFacade {
    #[must_use]
    pub fn new(
        state: Arc<DeviceState>,
        dispatcher: Dispatcher,
        session: SessionId,
        target: TargetSession,
    ) -> Self {
        Self {
            state,
            dispatcher,
            session,
            target,
            grant_revision: GrantRevision::new(0),
            carrier_generation: 0,
        }
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub fn target(&self) -> &TargetSession {
        &self.target
    }

    /// Take the exclusive input lease for this session's target.
    ///
    /// **Explicit, never implicit.** An input operation does not take the
    /// lease as a side effect: a lease taken by a click is a lease nobody
    /// releases, and the second agent would then be excluded by an accident.
    ///
    /// # Errors
    /// [`LeaseRefusal::HeldByAnotherSession`].
    pub fn acquire_input_lease(&self) -> Result<LeaseGrant, LeaseRefusal> {
        self.state
            .leases
            .lock()
            .expect("the lease mutex is never poisoned by fixture code")
            .acquire(&self.target, self.session, self.grant_revision)
    }

    /// Release a lease this session holds.
    ///
    /// # Errors
    /// Any [`LeaseRefusal`].
    pub fn release_input_lease(&self, grant: &LeaseGrant) -> Result<(), LeaseRefusal> {
        self.state
            .leases
            .lock()
            .expect("the lease mutex is never poisoned by fixture code")
            .release(grant)
    }

    /// The carrier rotated underneath this session.
    ///
    /// **It does nothing to the lease, and that is the contract.** The holder
    /// is the tunnel session, not the carrier, so there is no code path by
    /// which a rotation could drop a lease — and
    /// `tests/input_lease.rs::a_rotation_leaves_the_lease_held_and_never_repeats_a_click`
    /// drives one across a held lease and a lost click to check it. The
    /// generation is tracked only so a test can show the rotation happened.
    pub const fn rotate_carrier(&mut self) {
        self.carrier_generation += 1;
    }

    #[must_use]
    pub const fn carrier_generation(&self) -> u64 {
        self.carrier_generation
    }

    /// Tell this session what revision the device believes its grant carries.
    ///
    /// Nothing calls this in production, because nothing tells a device that a
    /// grant was revoked. M3-16; see `docs/tasks.md` M5-C05.
    pub const fn note_grant_revision(&mut self, revision: GrantRevision) {
        self.grant_revision = revision;
    }

    #[must_use]
    pub const fn grant_revision(&self) -> GrantRevision {
        self.grant_revision
    }

    /// The dispatcher underneath, for the discovery reads that are not
    /// `computer.v1` operations and therefore have no session context.
    #[must_use]
    pub const fn dispatcher(&self) -> &Dispatcher {
        &self.dispatcher
    }

    /// Validate and dispatch one `computer.v1` request for this session.
    ///
    /// The locks are held **only** across [`plan`], which is pure and cannot
    /// block, and are dropped before anything is sent. A lock held across the
    /// exchange would make the lease a mutex over the network rather than over
    /// input.
    pub async fn handle(&self, body: &[u8], limit: u64) -> Dispatch {
        let planned = {
            let leases = self
                .state
                .leases
                .lock()
                .expect("the lease mutex is never poisoned by fixture code");
            let captures = self
                .state
                .captures
                .lock()
                .expect("the capture mutex is never poisoned by fixture code");
            let context = SessionContext {
                session: self.session,
                target: &self.target,
                grant_revision: self.grant_revision,
                leases: &leases,
                captures: &captures,
            };
            plan(body, limit, self.dispatcher.permitted(), &context)
        };

        let (planned, dispatch) = self.dispatcher.dispatch_planned(planned).await;
        self.issue_capture_identity(planned.as_ref(), dispatch)
    }

    /// Record a successful capture and hand its identity back to the consumer.
    ///
    /// **Only on [`Completion::Ok`].** A capture that failed, or whose outcome
    /// is unknown, issues no identity: there is no image the consumer could
    /// have looked at, so there is nothing for a later click to refer to.
    fn issue_capture_identity(&self, planned: Option<&Planned>, dispatch: Dispatch) -> Dispatch {
        let Some(Planned::Dispatch {
            operation: Operation::Capture,
            payload,
            ..
        }) = planned
        else {
            return dispatch;
        };
        let Dispatch::Dispatched(Completion::Ok(result)) = &dispatch else {
            return dispatch;
        };
        let display = payload
            .pointer("/params/display")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let number = |name: &str| {
            result
                .get(name)
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
        };
        let (Some(width), Some(height)) = (number("width"), number("height")) else {
            // A capture whose dimensions we cannot read is not one a later
            // coordinate may refer to. The capture itself still succeeded, so
            // the outcome is unchanged; what is withheld is the identity.
            return dispatch;
        };
        // **An absent scale is read as 1x, and the released source has now
        // been read: 0.3.46 never sends the member.** M5-C06 left this line
        // saying no source had been read; one has. `scale_percent` appears
        // nowhere in the pinned sdist, and no backend's `screenshot` returns
        // it -- macOS, Linux, Windows and Android return
        // `{success, image_data, format}`, VNC omits `format` too.
        //
        // That would make this default wrong by a factor of two on a real 2x
        // display -- except that it is **unreachable against a released
        // backend**, because `width` and `height` are not returned either and
        // the `let else` above takes the early return first. No identity is
        // issued, so every later coordinate is refused rather than landing in
        // the wrong place: the safe direction, reached by accident. The 1x
        // default is therefore exercised only against this fixture, which
        // emits all three members.
        //
        // Deriving a real scale needs two commands (decoded image width over
        // `get_screen_size` width) and must not be built before a real
        // backend is probed. Recorded as `docs/tasks.md` M5-C14, which
        // carries the measurement; M5-C06 is closed.
        let scale = number("scale_percent").unwrap_or(tunnel_cua::capture::IDENTITY_SCALE_PERCENT);
        let Ok(identity) = self
            .state
            .captures
            .lock()
            .expect("the capture mutex is never poisoned by fixture code")
            .record(&self.target, display, width, height, scale)
        else {
            return dispatch;
        };

        let mut annotated = result.clone();
        if let Some(object) = annotated.as_object_mut() {
            object.insert("capture".to_owned(), json!(identity.id().value()));
            object.insert("display".to_owned(), json!(display));
        }
        Dispatch::Dispatched(Completion::Ok(annotated))
    }
}
