//! The filesystem capability descriptor, the WSS upgrade, and the byte pump —
//! implementation gate 4 of `docs/filesystem-api.md`, relay side.
//!
//! One URL, three answers, exactly as the contract's table says:
//!
//! | Request | Answer |
//! | --- | --- |
//! | Authenticated `GET`, no `Upgrade` | the JSON descriptor, `no-store` |
//! | Authenticated WSS upgrade, subprotocol `agent-tunnel.9p.v1` | a binary 9P connection |
//! | Anything else | `405`; there is no JSON per-operation RPC here |
//!
//! # The error body is the contract's, not the relay's
//!
//! Every other relay route answers the flat `{code, execution, message}` body.
//! The filesystem endpoint answers `{"error": {"code", "message", "requestId"}}`
//! with the contract's own code vocabulary — `UNAUTHENTICATED`,
//! `EXPORT_NOT_FOUND`, `ACCESS_DENIED`, `CAPABILITIES_CHANGED`,
//! `RESOURCE_EXHAUSTED`, `DEVICE_OFFLINE`, `BACKEND_UNAVAILABLE` — because
//! `docs/filesystem-api.md` specifies that shape for this URL and says it takes
//! precedence over earlier sketches. **This is a decision, not an oversight:**
//! the alternative was to amend the contract to the relay's existing shape, and
//! a published client contract that already names its codes is the worse of the
//! two things to change. The two vocabularies do not mix: a filesystem response
//! never carries `execution`, and no other route carries `error`.
//!
//! # What crosses the tunnel
//!
//! The consumer WebSocket's rule is **one complete 9P message per binary
//! message**, and this relay enforces it with gate 3's own `decode_exact`
//! before a byte is forwarded. The device's rule is an ordered byte stream, and
//! it reassembles with gate 3's `FrameDecoder`. Both of gate 3's two decode
//! entry points are therefore exercised on the real path, which is what they
//! were made two functions for.
//!
//! The device→consumer direction carries `tunnel_fs_provider::record` framing
//! rather than raw 9P, for one reason: a session ends with a **close code**
//! decided on the device, and no 9P message means "close with 1008". See that
//! module for why the alternative — inventing an opcode — is worse.
//!
//! # Owner-local only, and said so
//!
//! Gate 4 admits a filesystem session **only at the relay that owns the
//! device**. A consumer reaching a non-owner relay is answered `503
//! BACKEND_UNAVAILABLE` with `DEVICE_NOT_OWNED_HERE` in the message, rather
//! than being forwarded over the peer hop the way `http-forward/1` is. The hop
//! itself is not the difficulty — the peer envelope already carries a
//! `required_scope` and would take this one unchanged — but proving a bounded,
//! credited 9P stream across it is its own piece of evidence, and claiming it
//! from an untested path would be worse than naming it. It is recorded as
//! gate-4 residue.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use futures_util::{SinkExt as _, StreamExt as _};
use serde::Serialize;
use tokio::time::timeout;
use uuid::Uuid;

use tunnel_fs_core::{
    Availability, Capability, CapabilitySet, CaseSensitivity, Descriptor, ExportIdentity,
    FeatureSet, Identifier, SessionErrorCode, TRANSPORT_SUBPROTOCOL, admits_session,
};
use tunnel_fs_ninep::{MAX_MESSAGE_BYTES, decode_exact};
use tunnel_fs_provider::{Record, RecordDecoder, default_limits};

use tokio_util::sync::CancellationToken;

use crate::actor::StreamTeardownCause;
use crate::http::forward::actor_carriers;
use crate::routing::{OwnerRoute, OwnerScope};
use tunnel_http_bridge::{CarrierEvent, CarrierReader as _, CarrierWriter as _};

use super::{
    HttpState, bearer, cluster_is_ready, parse_uuid, service_and_grant_of_type, subprotocol_offered,
};

/// The header a Node client sends the descriptor's `grantRevision` in.
pub const GRANT_REVISION_HEADER: &str = "x-agent-tunnel-grant-revision";

/// How long the descriptor read and the stream admission may take.
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);

/// The contract's JSON error body. No host detail, no `execution`.
#[derive(Serialize)]
struct FsErrorBody<'a> {
    error: FsErrorDetail<'a>,
}

#[derive(Serialize)]
struct FsErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(rename = "requestId")]
    request_id: String,
}

/// Build one filesystem error response.
///
/// `message` is diagnostic and callers branch on `code`, which is why both are
/// `&'static str`: a message assembled from a request could carry a path.
fn fs_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    let body = FsErrorBody {
        error: FsErrorDetail {
            code,
            message,
            // Correlates a consumer's report with this relay's own logs and
            // carries nothing about the request.
            request_id: Uuid::new_v4().to_string(),
        },
    };
    let mut response = (status, axum::Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
    }
    response
}

/// The single route for `/v1/devices/{device}/services/{service}/fs`.
pub(crate) async fn fs_route(
    State(state): State<HttpState>,
    method: Method,
    headers: HeaderMap,
    Path((device, service)): Path<(String, String)>,
    request: axum::extract::Request,
) -> Response {
    if method != Method::GET {
        // "Other methods: 405; no JSON per-operation filesystem RPC at this
        // URL."  Taken before authentication, so an unserved method cannot be
        // used to probe whether an export exists.
        return fs_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "METHOD_NOT_ALLOWED",
            "this endpoint serves a descriptor and a WebSocket upgrade only",
        );
    }
    if !cluster_is_ready(&state) {
        return fs_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "BACKEND_UNAVAILABLE",
            "cluster readiness unavailable",
        );
    }
    if !is_upgrade(&headers) {
        return serve_descriptor(state, headers, device, service).await;
    }
    // Built only for a request that actually asked to upgrade, because
    // `WebSocketUpgrade` has no optional extractor in this Axum version and a
    // plain `GET` must not be answered with its rejection.
    let (mut parts, body) = request.into_parts();
    let _ = body;
    let upgrade =
        match <WebSocketUpgrade as axum::extract::FromRequestParts<HttpState>>::from_request_parts(
            &mut parts, &state,
        )
        .await
        {
            Ok(upgrade) => upgrade,
            Err(_) => {
                return fs_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_UPGRADE",
                    "the upgrade request is not a valid WebSocket handshake",
                );
            }
        };
    upgrade_session(state, headers, device, service, upgrade).await
}

/// Whether this request asked to upgrade to WebSocket.
///
/// Read from the headers rather than from a failed extraction, so an ordinary
/// `GET` is answered with the descriptor and never with an upgrade rejection.
fn is_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

/// Everything the two answers share: authenticate, resolve, authorize, and
/// derive the grant.
struct Admitted {
    device_id: Uuid,
    service_id: Uuid,
    grant: tunnel_catalog::GrantSnapshot,
    consumer: tunnel_catalog::AuthenticatedConsumer,
    consumer_expires_at: chrono::DateTime<Utc>,
    capabilities: CapabilitySet,
    case_sensitivity: CaseSensitivity,
}

async fn admit(
    state: &HttpState,
    headers: &HeaderMap,
    device: &str,
    service: &str,
) -> Result<Admitted, Response> {
    let (Some(catalog), Some(oidc)) = (state.catalog.as_ref(), state.oidc.as_ref()) else {
        return Err(fs_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "BACKEND_UNAVAILABLE",
            "catalog unavailable",
        ));
    };
    let validated = oidc
        .authenticate_for_scope(
            &**catalog,
            bearer(headers),
            None,
            crate::FS_SESSION_OPERATION,
        )
        .await
        .map_err(|error| match error {
            tunnel_catalog::OidcError::Catalog(_) => fs_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BACKEND_UNAVAILABLE",
                "authorization unavailable",
            ),
            _ => fs_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHENTICATED",
                "a consumer access token is required",
            ),
        })?;
    let device_id = parse_uuid(device).map_err(|()| {
        // A nonexistent and an undiscoverable export get the same external
        // answer, so a 404 discloses nothing about which it was.
        fs_error(
            StatusCode::NOT_FOUND,
            "EXPORT_NOT_FOUND",
            "no such filesystem export",
        )
    })?;
    let (service_id, grant, capabilities) = service_and_grant_of_type(
        state,
        &validated.consumer,
        device_id,
        service,
        crate::FS_SERVICE_TYPE,
    )
    .await
    .map_err(translate_resolution)?;

    // The host declaration.  Gate 2 declares filesystem exports unsupported on
    // Windows in one function so discovery can answer 403; this is how that
    // reaches a relay, which does not know the device's operating system.
    if capabilities
        .get(crate::FS_HOST_SUPPORTED_CAPABILITY)
        .and_then(serde_json::Value::as_bool)
        == Some(false)
    {
        return Err(fs_error(
            StatusCode::FORBIDDEN,
            "ACCESS_DENIED",
            "filesystem exports are unsupported on this device's host",
        ));
    }
    // The case behaviour is **reported, never assumed**, so an export that did
    // not declare it is one this relay cannot describe — the same answer an
    // `http-forward` service naming no profile gets.
    let Some(case_sensitivity) = capabilities
        .get(crate::FS_CASE_SENSITIVITY_CAPABILITY)
        .and_then(serde_json::Value::as_str)
        .and_then(parse_case_sensitivity)
    else {
        return Err(fs_error(
            StatusCode::NOT_FOUND,
            "EXPORT_NOT_FOUND",
            "no such filesystem export",
        ));
    };

    let now = Utc::now();
    if !grant.permissions.allows(crate::FS_SESSION_OPERATION)
        || grant.valid_until <= now
        || validated.expires_at <= now
    {
        return Err(fs_error(
            StatusCode::FORBIDDEN,
            "ACCESS_DENIED",
            "the grant does not admit a filesystem session",
        ));
    }
    let derived = derive_capabilities(&grant);
    // "An export granting nothing admits no session at all, rather than
    // admitting a session that can do nothing." Discovery answers 403 rather
    // than serving a descriptor that advertises an empty operation list.
    if !admits_session(derived) {
        return Err(fs_error(
            StatusCode::FORBIDDEN,
            "ACCESS_DENIED",
            "the grant names no filesystem capability",
        ));
    }
    let mut grant = grant;
    grant.valid_until = grant.valid_until.min(validated.expires_at);
    Ok(Admitted {
        device_id,
        service_id,
        consumer_expires_at: validated.expires_at,
        consumer: validated.consumer,
        grant,
        capabilities: derived,
        case_sensitivity,
    })
}

/// Re-render the shared resolver's refusal in this endpoint's vocabulary.
///
/// The resolver answers in the relay's own shape and codes, and this URL
/// answers in the contract's. Mapping by **status** rather than by code keeps
/// the two vocabularies from leaking into one another while preserving the
/// distinction that matters to a caller: a catalog this relay could not read is
/// not the same answer as an export that does not exist, and collapsing both to
/// 404 would tell a consumer its export was gone when the relay simply could not
/// look.
///
/// `409 SERVICE_AMBIGUOUS` becomes `404 EXPORT_NOT_FOUND`, deliberately: the
/// contract reserves 409 at this URL for `CAPABILITIES_CHANGED`, and a label
/// matching several live services names no single export, which is what
/// undiscoverable means here.
fn translate_resolution(response: Response) -> Response {
    match response.status() {
        StatusCode::SERVICE_UNAVAILABLE => fs_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "BACKEND_UNAVAILABLE",
            "authorization unavailable",
        ),
        StatusCode::FORBIDDEN => fs_error(
            StatusCode::FORBIDDEN,
            "ACCESS_DENIED",
            "the grant does not admit a filesystem session",
        ),
        StatusCode::TOO_MANY_REQUESTS => fs_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RESOURCE_EXHAUSTED",
            "admission capacity exhausted",
        ),
        // A nonexistent and an undiscoverable export get the same external
        // answer, so a 404 discloses nothing about which it was.
        _ => fs_error(
            StatusCode::NOT_FOUND,
            "EXPORT_NOT_FOUND",
            "no such filesystem export",
        ),
    }
}

fn parse_case_sensitivity(text: &str) -> Option<CaseSensitivity> {
    match text {
        "sensitive" => Some(CaseSensitivity::Sensitive),
        "insensitive-preserving" => Some(CaseSensitivity::InsensitivePreserving),
        _ => None,
    }
}

/// The four capabilities a grant's operation set names.
///
/// Every capability a session holds was named individually: there is no
/// wildcard, and a scope that admits the session is not itself a capability.
fn derive_capabilities(grant: &tunnel_catalog::GrantSnapshot) -> CapabilitySet {
    let mut set = CapabilitySet::DENY;
    for (operation, capability) in [
        (crate::FS_READ_OPERATION, Capability::Read),
        (crate::FS_WRITE_OPERATION, Capability::Write),
        (crate::FS_LIST_OPERATION, Capability::List),
        (crate::FS_DELETE_OPERATION, Capability::Delete),
    ] {
        if grant.permissions.allows(operation) {
            set = set.with(capability);
        }
    }
    set
}

/// The comma-separated capability names the OPEN hands the connector.
fn capability_metadata(set: CapabilitySet) -> String {
    set.iter()
        .map(Capability::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

/// Whether a supplied grant revision still matches.
fn revision_matches(headers: &HeaderMap, revision: u64) -> bool {
    headers
        .get(GRANT_REVISION_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value.trim() == revision.to_string())
}

/// Whether this relay owns the device, and whether the device is connected.
async fn availability(state: &HttpState, tenant: Uuid, device_id: Uuid) -> (Availability, bool) {
    let Some(peer) = state.peer.as_ref() else {
        // A single-relay deployment: this relay is the owner if it holds the
        // session at all, which the stream admission decides.
        return (Availability::Online, true);
    };
    match peer
        .resolve(OwnerScope::new(tenant, device_id), Utc::now())
        .await
    {
        Ok(OwnerRoute::Local { .. }) => (Availability::Online, true),
        // Discovery "can show `offline` for a previously enrolled device
        // without claiming its backend is ready": a device owned elsewhere is
        // reachable, so it is online, but gate 4 does not admit its session
        // here.
        Ok(OwnerRoute::Remote { .. }) => (Availability::Online, false),
        Err(_) => (Availability::Offline, false),
    }
}

async fn serve_descriptor(
    state: HttpState,
    headers: HeaderMap,
    device: String,
    service: String,
) -> Response {
    let Ok(_permit) = state.admission.clone().try_acquire_owned() else {
        return fs_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RESOURCE_EXHAUSTED",
            "admission capacity exhausted",
        );
    };
    let admitted = match timeout(
        ADMISSION_TIMEOUT,
        admit(&state, &headers, &device, &service),
    )
    .await
    {
        Ok(Ok(admitted)) => admitted,
        Ok(Err(response)) => return response,
        Err(_) => {
            return fs_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BACKEND_UNAVAILABLE",
                "authorization read did not complete",
            );
        }
    };
    if !revision_matches(&headers, admitted.grant.revision) {
        return fs_error(
            StatusCode::CONFLICT,
            "CAPABILITIES_CHANGED",
            "the supplied grant revision is no longer current",
        );
    }
    let (availability, _owned_here) =
        availability(&state, admitted.grant.tenant_id, admitted.device_id).await;

    let Some(identity) = export_identity(&admitted) else {
        return fs_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "BACKEND_UNAVAILABLE",
            "the export identifiers are not representable in the descriptor",
        );
    };
    let descriptor = Descriptor::new(
        identity,
        availability,
        admitted.case_sensitivity,
        admitted.capabilities,
        // Gate 4 advertises no optional feature: no symlinks, no hard links, no
        // atomic rename, no native append, no exclusive create, no birth time
        // and no fsync.  Each would need its own tested implementation, and the
        // descriptor may not advertise what the provider does not enforce.
        FeatureSet::NONE,
        default_limits(),
    );
    let mut response = (StatusCode::OK, descriptor.to_json()).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn export_identity(admitted: &Admitted) -> Option<ExportIdentity> {
    Some(ExportIdentity {
        device_id: Identifier::parse(&admitted.device_id.to_string()).ok()?,
        service_id: Identifier::parse(&admitted.service_id.to_string()).ok()?,
        grant_revision: Identifier::parse(&admitted.grant.revision.to_string()).ok()?,
    })
}

async fn upgrade_session(
    state: HttpState,
    headers: HeaderMap,
    device: String,
    service: String,
    upgrade: WebSocketUpgrade,
) -> Response {
    // The subprotocol is checked before anything else, so an unsupported
    // profile is reported without a credential having been evaluated.
    if !subprotocol_offered(&headers, TRANSPORT_SUBPROTOCOL) {
        return fs_error(
            StatusCode::UPGRADE_REQUIRED,
            "SUBPROTOCOL_REQUIRED",
            "the agent-tunnel.9p.v1 subprotocol is required",
        );
    }
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return fs_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RESOURCE_EXHAUSTED",
            "admission capacity exhausted",
        );
    };
    let admitted = match timeout(
        ADMISSION_TIMEOUT,
        admit(&state, &headers, &device, &service),
    )
    .await
    {
        Ok(Ok(admitted)) => admitted,
        Ok(Err(response)) => return response,
        Err(_) => {
            return fs_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BACKEND_UNAVAILABLE",
                "authorization read did not complete",
            );
        }
    };
    // The upgrade rechecks authorization rather than trusting the descriptor: a
    // cached descriptor is informative and never an authorization credential.
    if !revision_matches(&headers, admitted.grant.revision) {
        return fs_error(
            StatusCode::CONFLICT,
            "CAPABILITIES_CHANGED",
            "the supplied grant revision is no longer current",
        );
    }
    let (availability, owned_here) =
        availability(&state, admitted.grant.tenant_id, admitted.device_id).await;
    if availability == Availability::Offline {
        return fs_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "DEVICE_OFFLINE",
            "the device is not connected",
        );
    }
    if !owned_here {
        return fs_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "BACKEND_UNAVAILABLE",
            "DEVICE_NOT_OWNED_HERE: gate 4 admits a filesystem session only at the owning relay",
        );
    }
    let Some(scope_permit) = state.scoped_admission.try_acquire(OwnerScope::new(
        admitted.grant.tenant_id,
        admitted.device_id,
    )) else {
        return fs_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RESOURCE_EXHAUSTED",
            "admission capacity exhausted for this device",
        );
    };

    let handle = state.handle.clone();
    let capabilities = capability_metadata(admitted.capabilities);
    let registration = match timeout(
        state.limits.operation_timeout,
        handle.open_fs_stream(
            admitted.consumer,
            admitted.device_id,
            admitted.service_id,
            admitted.grant,
            admitted.consumer_expires_at,
            None,
            capabilities,
        ),
    )
    .await
    {
        Ok(Ok(registration)) => registration,
        Ok(Err(_)) => {
            return fs_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BACKEND_UNAVAILABLE",
                "the device did not admit a filesystem session",
            );
        }
        Err(_) => {
            return fs_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BACKEND_UNAVAILABLE",
                "filesystem session admission timed out",
            );
        }
    };

    let consumer_expires_at = admitted.consumer_expires_at;
    upgrade
        .protocols([TRANSPORT_SUBPROTOCOL])
        // `msize` bounds the complete 9P message; the WebSocket frame bound is
        // the same number plus nothing, because one binary message is exactly
        // one 9P message.
        .max_message_size(MAX_MESSAGE_BYTES as usize)
        .max_frame_size(MAX_MESSAGE_BYTES as usize)
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_MESSAGE_BYTES as usize * 2)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let _scope_permit = scope_permit;
            pump(socket, handle, registration, consumer_expires_at).await;
        })
        .into_response()
}

/// The session close a reset reason names.
///
/// **`AUTHORIZATION_EXPIRED` is 1008 and everything else is 1011.** The
/// contract requires an authorization invalidation to close the session with
/// 1008, and that decision is taken on the **device** — by the connector, which
/// holds the authorization context and the clock — or by the owner when a grant
/// moves under a live stream. Neither can reach the consumer's socket except
/// through this reset code, because the connector aborts the exchange task
/// before it invalidates, so the provider never runs again and never emits its
/// own close record.
///
/// The wire has **one** code for the whole class: `AUTHORIZATION_EXPIRED`
/// covers an expired snapshot, a revoked grant and a moved revision alike. So
/// this maps to `AuthExpired` rather than `CapabilitiesChanged` — both close
/// 1008, which is what a consumer branches on, and claiming to distinguish them
/// here would be inventing a distinction the reason code does not carry.
fn session_close_for_reset(reason: Option<u16>) -> SessionErrorCode {
    match reason {
        Some(tunnel_protocol::reset_reason::AUTHORIZATION_EXPIRED) => SessionErrorCode::AuthExpired,
        _ => SessionErrorCode::SessionLost,
    }
}

/// No verdict published yet.
///
/// `u8::MAX` rather than a sentinel of its own, because a published verdict is
/// an index into gate 1's `SessionErrorCode::ALL` and that array is far shorter
/// than 255.
const NO_VERDICT: u8 = u8::MAX;

/// Publish the inbound task's verdict. The first one wins.
fn publish(slot: &AtomicU8, code: SessionErrorCode) {
    let _ = slot.compare_exchange(
        NO_VERDICT,
        tunnel_fs_provider::record::close_byte(code),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

/// The verdict the inbound task published, if it published one.
fn collect(slot: &AtomicU8) -> Option<SessionErrorCode> {
    let byte = slot.load(Ordering::Acquire);
    (byte != NO_VERDICT).then(|| tunnel_fs_provider::record::close_code(byte))?
}

/// Why the consumer socket was closed, as a bounded sanitized identifier.
fn close_frame(code: SessionErrorCode) -> Option<axum::extract::ws::CloseFrame> {
    code.close_code()
        .map(|number| axum::extract::ws::CloseFrame {
            code: number,
            reason: tunnel_fs_provider::close_reason(code).into(),
        })
}

/// Move bytes between the consumer WebSocket and the owner's logical stream.
async fn pump(
    socket: WebSocket,
    handle: crate::RelayHandle,
    registration: crate::actor::HttpStreamRegistration,
    consumer_expires_at: chrono::DateTime<Utc>,
) {
    let key = registration.base.key.clone();
    let stream_id = registration.base.stream_id;
    let operation_id = registration.base.operation_id.clone();
    let closed = registration.base.closed.clone();
    registration.base.claim_admission();
    let mut cleanup = handle.echo_cleanup_guard(key.clone(), stream_id, operation_id.clone(), None);
    // The invariant this depends on: `accept_reset` publishes the watch before
    // anything cancels `closed` in the same actor turn, so either exit reads the
    // reason.  Reordering that in the actor would silently downgrade a 1008 to a
    // codeless close.
    // Cloned before the carriers consume the registration: the connector's
    // RESET is observed here out of band, ahead of its ordered delivery, and a
    // stream the actor closes for a revocation ends this loop through
    // `closed.cancelled()` without ever delivering that RESET in order. Without
    // this the consumer would see a close with no code where the contract
    // requires 1008.
    let mut peer_reset = registration.peer_reset.clone();
    // Why the actor tore this stream down, on the same out-of-band footing
    // as `peer_reset` above and for the same reason: a stream the actor
    // closes ends this loop through `closed.cancelled()`, so a cause
    // published in that same turn has to be readable here rather than
    // delivered in order.
    let mut terminal_cause = registration.terminal.clone();
    let (mut writer, mut reader, signal_task, _freeze) = actor_carriers(&handle, registration);

    let (mut sink, mut stream) = socket.split();
    let inbound_closed = closed.clone();
    // The inbound task's verdict, published rather than returned.
    //
    // It cannot be a `JoinHandle`'s value: the outbound loop below has to stop
    // as soon as the consumer's side ends, and aborting the task to make that
    // happen discards whatever it was about to return — including a framing
    // violation, which is the one thing that must not be lost. So the task
    // publishes its verdict before it ends and cancels the token; the outbound
    // loop reads the verdict after it stops.
    let verdict: Arc<AtomicU8> = Arc::new(AtomicU8::new(NO_VERDICT));
    let inbound_verdict = Arc::clone(&verdict);
    let inbound_done = CancellationToken::new();
    let inbound_ended = inbound_done.clone();

    // Consumer → device.  A separate task, because the device direction must
    // keep being serviced while a write is parked for send credit: the two
    // directions of a 9P session are independent, and a client that pipelines
    // sixty-four tags would otherwise deadlock against its own replies.
    let inbound = tokio::spawn(async move {
        let _guard = inbound_ended.drop_guard();
        loop {
            let message = tokio::select! {
                biased;
                () = inbound_closed.cancelled() => break,
                message = stream.next() => message,
            };
            let Some(Ok(message)) = message else { break };
            match message {
                Message::Binary(bytes) => {
                    // The consumer WebSocket rule, enforced with gate 3's own
                    // function: exactly one complete 9P message per binary
                    // message.  Two packed into one and half of one are both
                    // framing violations, and a framing violation is a 1002
                    // close and never an `Rlerror`.
                    if decode_exact(&bytes, MAX_MESSAGE_BYTES).is_err() {
                        publish(&inbound_verdict, SessionErrorCode::ProtocolViolation);
                        break;
                    }
                    if writer.data(bytes).await.is_err() {
                        break;
                    }
                }
                // "Reject text" — the profile is binary, and a text frame is a
                // peer that did not read the contract.
                Message::Text(_) => {
                    publish(&inbound_verdict, SessionErrorCode::ProtocolViolation);
                    break;
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
            }
        }
        let _ = writer.finish().await;
    });

    // Device → consumer.
    let mut decoder = RecordDecoder::new();
    let mut close_with: Option<SessionErrorCode> = None;
    let expires_in = (consumer_expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    let expires = tokio::time::sleep(expires_in);
    tokio::pin!(expires);
    loop {
        let event = tokio::select! {
            biased;
            () = closed.cancelled() => break,
            // The consumer's side ended — cleanly, or on a framing violation
            // this loop must report. Either way there is nothing left to
            // forward, so the session ends here rather than waiting for the
            // device to notice.
            () = inbound_done.cancelled() => break,
            () = &mut expires => {
                close_with = Some(SessionErrorCode::AuthExpired);
                break;
            }
            event = reader.next() => event,
        };
        match event {
            CarrierEvent::Data(bytes) => {
                if decoder.push(&bytes).is_err() {
                    close_with = Some(SessionErrorCode::ProtocolViolation);
                    break;
                }
                let mut ended = false;
                loop {
                    match decoder.next_record() {
                        Ok(Some(Record::Message(message))) => {
                            if sink.send(Message::Binary(message.into())).await.is_err() {
                                ended = true;
                                break;
                            }
                        }
                        Ok(Some(Record::Close(code))) => {
                            close_with = Some(code);
                            ended = true;
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            close_with = Some(SessionErrorCode::ProtocolViolation);
                            ended = true;
                            break;
                        }
                    }
                }
                if ended {
                    break;
                }
            }
            CarrierEvent::Fin | CarrierEvent::Closed => break,
            CarrierEvent::Reset(_) => {
                close_with = Some(session_close_for_reset(reader.last_reset_reason()));
                break;
            }
        }
    }

    inbound.abort();
    // A RESET the connector raised out of band but never delivered in order —
    // the shape an authorization invalidation takes, because the connector
    // aborts its exchange before it resets — still decides the close code.
    if close_with.is_none()
        && let Some(observed) = peer_reset.borrow_and_update().as_ref()
    {
        close_with = Some(session_close_for_reset(Some(observed.reason)));
    }
    // The actor tore this stream down and said **why**.
    //
    // `docs/protocol.md` requires that across a control-session reconnect the
    // profile "terminate that filesystem session, **fail pending calls
    // explicitly** and create a fresh 9P session". A close with no code is a
    // termination that is not explicit: the caller cannot tell a device that
    // went away from a relay that broke, and an outstanding tag's outcome is
    // left unnamed. That was M4-28.
    //
    // The code is derived from the **cause**, never from the bare fact that
    // the stream was cancelled. `close_session` is reached from roughly thirty
    // distinct reasons — relay shutdown, an authority outage, an owner fence,
    // a rotation or recovery failure, a device framing fault — and almost none
    // of them mean the device went away. Keying off cancellation alone would
    // tell a consumer "the device is not connected" when the relay was what
    // stopped, which is the error class M4-25 was filed for. So the actor
    // publishes a cause only where it can name one accurately, and every other
    // reason arrives here as `None` and keeps exactly the close it had before.
    //
    // `DeviceOffline` is the code for a device that went away on its own
    // documented grounds: it is "the code the contract reserves for shutdown,
    // because the export's backend is the thing that went away", while 1011
    // "would report it as an unexpected relay failure" when the relay is
    // healthy and the device is not.
    //
    // This runs **after** the peer-reset resolution above, so a revocation
    // still closes 1008 (M4-25) rather than being downgraded, and before the
    // framing verdict below, which outranks everything.
    if close_with.is_none()
        && let Some(cause) = *terminal_cause.borrow_and_update()
    {
        close_with = Some(match cause {
            StreamTeardownCause::DeviceGone => SessionErrorCode::DeviceOffline,
        });
    }
    // A framing violation the consumer committed wins over every other reason
    // this loop stopped: the close code is what tells the peer its own frame was
    // refused, and reporting 1011 for it would name the relay as the failure.
    if let Some(violation) = collect(&verdict) {
        close_with = Some(violation);
    }
    signal_task.abort();
    let frame = close_with.and_then(close_frame);
    let _ = sink.send(Message::Close(frame)).await;
    let _ = sink.close().await;
    if matches!(
        timeout(
            Duration::from_secs(5),
            handle.close_echo_stream_with_cause(key, stream_id, operation_id, None),
        )
        .await,
        Ok(true)
    ) {
        cleanup.disarm();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        capability_metadata, derive_capabilities, parse_case_sensitivity, revision_matches,
    };
    use axum::http::{HeaderMap, StatusCode};
    use tunnel_fs_core::{Capability, CapabilitySet, CaseSensitivity};

    fn grant_with(operations: &[&str]) -> tunnel_catalog::GrantSnapshot {
        tunnel_catalog::GrantSnapshot {
            tenant_id: uuid::Uuid::nil(),
            principal_id: uuid::Uuid::nil(),
            device_id: uuid::Uuid::nil(),
            service_id: uuid::Uuid::nil(),
            revision: 3,
            permissions: tunnel_catalog::PermissionSet {
                operations: operations.iter().map(|value| (*value).to_owned()).collect(),
            },
            constraints: serde_json::Value::Null,
            valid_until: chrono::Utc::now(),
            read_started_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn every_capability_is_named_individually_and_none_is_implied() {
        assert_eq!(derive_capabilities(&grant_with(&[])), CapabilitySet::DENY);
        // The scope that admits the session is not itself a capability beyond
        // the one it names: `fs:read` gives `read` and nothing else.
        let read = derive_capabilities(&grant_with(&["fs:read"]));
        assert!(read.allows(Capability::Read));
        assert!(!read.allows(Capability::List));
        assert!(!read.allows(Capability::Write));
        assert!(!read.allows(Capability::Delete));
        let all = derive_capabilities(&grant_with(&[
            "fs:read",
            "fs:write",
            "fs:list",
            "fs:delete",
        ]));
        for capability in Capability::ALL {
            assert!(all.allows(capability), "{capability}");
        }
        // An unrelated operation grants nothing.
        assert_eq!(
            derive_capabilities(&grant_with(&["http:invoke", "echo:invoke"])),
            CapabilitySet::DENY
        );
    }

    #[test]
    fn capability_metadata_names_each_capability_once() {
        let set = CapabilitySet::from_slice(&[Capability::Read, Capability::List]);
        let rendered = capability_metadata(set);
        assert_eq!(rendered, "read,list");
        assert_eq!(capability_metadata(CapabilitySet::DENY), "");
    }

    #[test]
    fn the_case_behaviour_is_parsed_and_never_guessed() {
        assert_eq!(
            parse_case_sensitivity("sensitive"),
            Some(CaseSensitivity::Sensitive)
        );
        assert_eq!(
            parse_case_sensitivity("insensitive-preserving"),
            Some(CaseSensitivity::InsensitivePreserving)
        );
        for unknown in ["", "SENSITIVE", "insensitive", "true", "case-folding"] {
            assert_eq!(parse_case_sensitivity(unknown), None, "{unknown}");
        }
    }

    #[test]
    fn a_resolver_refusal_keeps_its_distinction_in_the_contracts_vocabulary() {
        use axum::body::Body;
        use axum::http::Response as HttpResponse;

        let cases = [
            (
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (StatusCode::FORBIDDEN, StatusCode::FORBIDDEN),
            (StatusCode::TOO_MANY_REQUESTS, StatusCode::TOO_MANY_REQUESTS),
            (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND),
            // The contract reserves 409 at this URL for CAPABILITIES_CHANGED, so
            // an ambiguous service label is undiscoverable rather than a
            // conflict.
            (StatusCode::CONFLICT, StatusCode::NOT_FOUND),
        ];
        for (from, expected) in cases {
            let refusal = HttpResponse::builder()
                .status(from)
                .body(Body::empty())
                .expect("response");
            assert_eq!(
                super::translate_resolution(refusal).status(),
                expected,
                "{from}"
            );
        }
    }

    #[test]
    fn only_a_websocket_upgrade_request_is_read_as_one() {
        let mut headers = HeaderMap::new();
        assert!(
            !super::is_upgrade(&headers),
            "a plain GET is the descriptor"
        );
        headers.insert(axum::http::header::UPGRADE, "h2c".parse().expect("value"));
        assert!(!super::is_upgrade(&headers));
        headers.insert(
            axum::http::header::UPGRADE,
            "WebSocket".parse().expect("value"),
        );
        assert!(super::is_upgrade(&headers), "the token is case-insensitive");
    }

    #[test]
    fn a_missing_revision_header_matches_and_a_stale_one_does_not() {
        let mut headers = HeaderMap::new();
        assert!(revision_matches(&headers, 7));
        headers.insert(super::GRANT_REVISION_HEADER, "7".parse().expect("value"));
        assert!(revision_matches(&headers, 7));
        assert!(!revision_matches(&headers, 8));
        headers.insert(super::GRANT_REVISION_HEADER, " 7 ".parse().expect("value"));
        assert!(revision_matches(&headers, 7));
        headers.insert(super::GRANT_REVISION_HEADER, "".parse().expect("value"));
        assert!(!revision_matches(&headers, 7));
    }
}
