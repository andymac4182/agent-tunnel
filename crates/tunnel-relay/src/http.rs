use std::{sync::Arc, time::Duration};

use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{
        Path, Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::{sync::Semaphore, time::timeout};
use tunnel_catalog::{DeviceListFilter, OidcVerifier, SharedCatalog};
use tunnel_transport::TlsIdentity;
use uuid::Uuid;

const CONTROL_SUBPROTOCOL: &str = "agent-tunnel.control.v1";
const DATA_SUBPROTOCOL: &str = "agent-tunnel.data.v1";
const ECHO_STREAM_SUBPROTOCOL: &str = "agent-tunnel.echo.v1";
const MAX_ECHO_CANARY_BYTES: usize = 256;
// Includes the record prefix and the largest unmasked WebSocket frame header.
const MAX_ECHO_WRITE_BYTES: usize = MAX_BODY_BYTES + MAX_ECHO_CANARY_BYTES + 4 + 10;

use crate::{
    actor::{EchoOutcome, RelayHandle},
    config::RelayLimits,
    wire::{self, MAX_BODY_BYTES, MAX_CONTROL_BYTES},
};

#[derive(Clone)]
pub(crate) struct HttpState {
    pub(crate) handle: RelayHandle,
    pub(crate) catalog: Option<SharedCatalog>,
    pub(crate) oidc: Option<Arc<OidcVerifier>>,
    pub(crate) limits: RelayLimits,
    /// Reserved before reading a request body; bounds aggregate materialization.
    pub(crate) admission: Arc<Semaphore>,
}

/// Build both public consumer and device WebSocket routes. Run this router
/// through `tunnel_transport::serve` so identities come from verified TLS.
pub fn router(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    limits: RelayLimits,
) -> Router {
    Router::new()
        .merge(consumer_router(
            handle.clone(),
            catalog.clone(),
            oidc,
            limits.clone(),
        ))
        .merge(device_router(handle, limits))
}

pub fn consumer_router(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    limits: RelayLimits,
) -> Router {
    let state = HttpState {
        handle,
        catalog: Some(catalog),
        oidc: Some(oidc),
        admission: Arc::new(Semaphore::new(limits.max_pending_operations)),
        limits: limits.clone(),
    };
    Router::new()
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/{device}/services", get(list_services))
        .route("/v1/devices/{device}/services/{service}/echo", post(echo))
        .route(
            "/v1/devices/{device}/services/{service}/stream",
            get(echo_stream),
        )
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
}

pub fn device_router(handle: RelayHandle, limits: RelayLimits) -> Router {
    let state = HttpState {
        handle,
        catalog: None,
        oidc: None,
        admission: Arc::new(Semaphore::new(limits.max_devices.saturating_mul(2))),
        limits,
    };
    Router::new()
        .route("/v1/tunnel/control", get(control))
        .route("/v1/tunnel/data", get(data))
        .with_state(state)
}

async fn list_devices(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    let Ok(_permit) = state.admission.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "ADMISSION_LIMIT",
            "request capacity exhausted",
            "not_dispatched",
        );
    };
    let principal = match authenticate(&state, &headers, None).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let Some(catalog) = state.catalog.as_ref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        );
    };
    match catalog
        .list_devices_filtered(&principal, &DeviceListFilter::default(), Utc::now())
        .await
    {
        Ok(devices) => Json(devices).into_response(),
        Err(error) => catalog_error(error),
    }
}

async fn list_services(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(device): Path<String>,
) -> Response {
    let Ok(_permit) = state.admission.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "ADMISSION_LIMIT",
            "request capacity exhausted",
            "not_dispatched",
        );
    };
    let principal = match authenticate(&state, &headers, None).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let device_id = match parse_uuid(&device) {
        Ok(value) => value,
        Err(()) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "not found",
                "not_dispatched",
            );
        }
    };
    let filter = DeviceListFilter {
        service_id: None,
        owner_user_id: None,
        include_inactive: false,
    };
    let Some(catalog) = state.catalog.as_ref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        );
    };
    match catalog
        .list_devices_filtered(&principal, &filter, Utc::now())
        .await
    {
        Ok(devices) => devices
            .into_iter()
            .find(|summary| summary.device_id == device_id)
            .map(|summary| Json(summary.services).into_response())
            .unwrap_or_else(|| {
                error_response(
                    StatusCode::NOT_FOUND,
                    "DEVICE_NOT_FOUND",
                    "not found",
                    "not_dispatched",
                )
            }),
        Err(error) => catalog_error(error),
    }
}

async fn echo(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((device, service)): Path<(String, String)>,
    request: Request,
) -> Response {
    let Ok(_permit) = state.admission.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "ADMISSION_LIMIT",
            "request capacity exhausted",
            "not_dispatched",
        );
    };
    let (Some(catalog), Some(oidc)) = (state.catalog.as_ref(), state.oidc.as_ref()) else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        );
    };
    let validated = match oidc
        .authenticate_for_scope(&**catalog, bearer(&headers), None, crate::ECHO_OPERATION)
        .await
    {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "consumer authentication failed",
                "not_dispatched",
            );
        }
    };
    let device_id = match parse_uuid(&device) {
        Ok(value) => value,
        Err(()) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "not found",
                "not_dispatched",
            );
        }
    };
    let (service_id, mut grant) =
        match service_and_grant(&state, &validated.consumer, device_id, &service).await {
            Ok(value) => value,
            Err(response) => return response,
        };
    if grant.valid_until <= Utc::now() || !grant.permissions.allows(crate::ECHO_OPERATION) {
        return error_response(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "echo is not authorized",
            "not_dispatched",
        );
    }
    let body = match timeout(
        Duration::from_secs(10),
        to_bytes(
            request.into_body(),
            state.limits.max_body_bytes.min(MAX_BODY_BYTES),
        ),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "BODY_LIMIT",
                "request body exceeds the echo limit or is incomplete",
                "not_dispatched",
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::REQUEST_TIMEOUT,
                "BODY_TIMEOUT",
                "request body deadline exceeded",
                "not_dispatched",
            );
        }
    };
    if validated.expires_at <= Utc::now() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "consumer token expired before dispatch",
            "not_dispatched",
        );
    }
    grant.valid_until = grant.valid_until.min(validated.expires_at);
    let result = timeout(
        state.limits.operation_timeout,
        state.handle.dispatch_echo(
            validated.consumer,
            device_id,
            service_id,
            grant,
            body.to_vec(),
            validated.expires_at,
        ),
    )
    .await;
    match result {
        Ok(Ok(EchoOutcome::Success(bytes))) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Ok(Ok(EchoOutcome::Failure { code, execution })) => failure_outcome(code, execution),
        Ok(Err(_)) => failure_outcome("REVERSE_CHANNEL_UNAVAILABLE", "not_dispatched"),
        Err(_) => failure_outcome("REVERSE_CHANNEL_INTERRUPTED", "unknown"),
    }
}

async fn echo_stream(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((device, service)): Path<(String, String)>,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !subprotocol_offered(&headers, ECHO_STREAM_SUBPROTOCOL) {
        return error_response(
            StatusCode::UPGRADE_REQUIRED,
            "SUBPROTOCOL_REQUIRED",
            "consumer stream subprotocol is required",
            "not_dispatched",
        );
    }
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "ADMISSION_LIMIT",
            "request capacity exhausted",
            "not_dispatched",
        );
    };
    let (Some(catalog), Some(oidc)) = (state.catalog.as_ref(), state.oidc.as_ref()) else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        );
    };
    let validated = match oidc
        .authenticate_for_scope(&**catalog, bearer(&headers), None, crate::ECHO_OPERATION)
        .await
    {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "consumer authentication failed",
                "not_dispatched",
            );
        }
    };
    let device_id = match parse_uuid(&device) {
        Ok(value) => value,
        Err(()) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "not found",
                "not_dispatched",
            );
        }
    };
    let (service_id, mut grant) =
        match service_and_grant(&state, &validated.consumer, device_id, &service).await {
            Ok(value) => value,
            Err(response) => return response,
        };
    if !grant.permissions.allows(crate::ECHO_OPERATION)
        || grant.valid_until <= Utc::now()
        || validated.expires_at <= Utc::now()
    {
        return error_response(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "echo stream is not authorized",
            "not_dispatched",
        );
    }
    grant.valid_until = grant.valid_until.min(validated.expires_at);
    let handle = state.handle.clone();
    let consumer = validated.consumer;
    let consumer_expires_at = validated.expires_at;
    upgrade
        .protocols([ECHO_STREAM_SUBPROTOCOL])
        .max_message_size(MAX_BODY_BYTES.saturating_add(4))
        .max_frame_size(MAX_BODY_BYTES.saturating_add(4))
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_ECHO_WRITE_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            handle_consumer_stream(
                socket,
                handle,
                consumer,
                device_id,
                service_id,
                grant,
                consumer_expires_at,
            )
            .await;
        })
        .into_response()
}

async fn handle_consumer_stream(
    mut socket: WebSocket,
    handle: RelayHandle,
    consumer: tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Uuid,
    grant: tunnel_catalog::GrantSnapshot,
    consumer_expires_at: chrono::DateTime<Utc>,
) {
    let registration = match handle
        .open_echo_stream(consumer, device_id, service_id, grant, consumer_expires_at)
        .await
    {
        Ok(registration) => registration,
        Err(_) => {
            let _ = send_socket(&mut socket, Message::Close(None)).await;
            return;
        }
    };
    let key = registration.key.clone();
    let stream_id = registration.stream_id;
    let operation_id = registration.operation_id.clone();
    let mut input = Vec::new();
    let expires_in = (consumer_expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    let expires = tokio::time::sleep(expires_in);
    tokio::pin!(expires);
    'connection: loop {
        let message = tokio::select! {
            biased;
            _ = registration.closed.cancelled() => break,
            _ = &mut expires => break,
            message = socket.next() => message,
        };
        let Some(message) = message else {
            break;
        };
        let message = match message {
            Ok(message) => message,
            Err(_) => break,
        };
        match message {
            Message::Binary(bytes) => {
                if input.len().saturating_add(bytes.len()) > MAX_BODY_BYTES.saturating_add(4) {
                    break;
                }
                input.extend_from_slice(&bytes);
                loop {
                    if input.len() < 4 {
                        break;
                    }
                    let declared =
                        u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
                    if declared > MAX_BODY_BYTES {
                        break 'connection;
                    }
                    let Some(total) = declared.checked_add(4) else {
                        break 'connection;
                    };
                    if input.len() < total {
                        break;
                    }
                    let record: Vec<u8> = input.drain(..total).collect();
                    let body = record[4..].to_vec();
                    let result = handle
                        .write_echo_stream(key.clone(), stream_id, operation_id.clone(), body)
                        .await;
                    let Ok(response) = result else {
                        break 'connection;
                    };
                    if response.len() < 4 {
                        break 'connection;
                    }
                    let response_len =
                        u32::from_be_bytes([response[0], response[1], response[2], response[3]])
                            as usize;
                    if response_len > MAX_BODY_BYTES.saturating_add(MAX_ECHO_CANARY_BYTES)
                        || response_len.saturating_add(4) != response.len()
                    {
                        break 'connection;
                    }
                    if !send_socket(&mut socket, Message::Binary(response.into())).await {
                        break 'connection;
                    }
                }
            }
            Message::Ping(payload) => {
                if !send_socket(&mut socket, Message::Pong(payload)).await {
                    break;
                }
            }
            Message::Close(_) => {
                // Tungstenite queues the peer's close reply while reading.
                // Flush it before dropping the upgraded TLS connection.
                let _ = timeout(Duration::from_secs(5), socket.flush()).await;
                break;
            }
            Message::Pong(_) => {}
            Message::Text(_) => break,
        }
    }
    let _ = send_socket(&mut socket, Message::Close(None)).await;
    handle.close_echo_stream(key, stream_id, operation_id).await;
}

async fn service_and_grant(
    state: &HttpState,
    consumer: &tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service: &str,
) -> Result<(Uuid, tunnel_catalog::GrantSnapshot), Response> {
    let filter = DeviceListFilter::default();
    let Some(catalog) = state.catalog.as_ref() else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        ));
    };
    let devices = catalog
        .list_devices_filtered(consumer, &filter, Utc::now())
        .await
        .map_err(catalog_error)?;
    let device = devices
        .into_iter()
        .find(|summary| summary.device_id == device_id)
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "DEVICE_NOT_FOUND",
                "not found",
                "not_dispatched",
            )
        })?;
    let service_id = service
        .parse::<Uuid>()
        .ok()
        .or_else(|| {
            device
                .services
                .iter()
                .find(|candidate| {
                    candidate.service_type == crate::ECHO_SERVICE_TYPE
                        && candidate.service_id.to_string() == service
                })
                .map(|candidate| candidate.service_id)
        })
        .or_else(|| {
            device
                .services
                .iter()
                .find(|candidate| candidate.service_type == service)
                .map(|candidate| candidate.service_id)
        })
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "SERVICE_NOT_FOUND",
                "not found",
                "not_dispatched",
            )
        })?;
    if !device.services.iter().any(|candidate| {
        candidate.service_id == service_id
            && candidate.service_type == crate::ECHO_SERVICE_TYPE
            && candidate.active
    }) {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "SERVICE_NOT_FOUND",
            "not found",
            "not_dispatched",
        ));
    }
    let read_started = Utc::now();
    let grant = catalog
        .authorize(consumer, device_id, service_id, read_started, Utc::now())
        .await
        .map_err(catalog_error)?
        .ok_or_else(|| {
            error_response(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "service is not authorized",
                "not_dispatched",
            )
        })?;
    Ok((service_id, grant))
}

async fn authenticate(
    state: &HttpState,
    headers: &HeaderMap,
    scope: Option<&str>,
) -> Result<tunnel_catalog::AuthenticatedConsumer, Response> {
    let authorization = bearer(headers);
    let (Some(catalog), Some(oidc)) = (state.catalog.as_ref(), state.oidc.as_ref()) else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        ));
    };
    match scope {
        Some(scope) => oidc
            .authenticate_for_scope(&**catalog, authorization, None, scope)
            .await
            .map(|value| value.consumer),
        None => oidc.authenticate(&**catalog, authorization, None).await,
    }
    .map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "consumer authentication failed",
            "not_dispatched",
        )
    })
}

fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

fn parse_uuid(value: &str) -> Result<Uuid, ()> {
    Uuid::parse_str(value).map_err(|_| ())
}

async fn control(
    State(state): State<HttpState>,
    identity: Option<Extension<TlsIdentity>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !subprotocol_offered(&headers, CONTROL_SUBPROTOCOL) {
        return error_response(
            StatusCode::UPGRADE_REQUIRED,
            "SUBPROTOCOL_REQUIRED",
            "control WebSocket subprotocol required",
            "not_dispatched",
        );
    }
    let Some(Extension(identity)) = identity else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "DEVICE_MTLS_REQUIRED",
            "device certificate required",
            "not_dispatched",
        );
    };
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "SOCKET_LIMIT",
            "device socket capacity exhausted",
            "not_dispatched",
        );
    };
    upgrade
        .protocols([CONTROL_SUBPROTOCOL])
        .max_message_size(state.limits.max_control_bytes)
        .max_frame_size(state.limits.max_control_bytes)
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_CONTROL_BYTES * 2)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            handle_control(socket, identity, state.handle).await;
        })
        .into_response()
}

async fn data(
    State(state): State<HttpState>,
    identity: Option<Extension<TlsIdentity>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !subprotocol_offered(&headers, DATA_SUBPROTOCOL) {
        return error_response(
            StatusCode::UPGRADE_REQUIRED,
            "SUBPROTOCOL_REQUIRED",
            "data WebSocket subprotocol required",
            "not_dispatched",
        );
    }
    let Some(Extension(identity)) = identity else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "DEVICE_MTLS_REQUIRED",
            "device certificate required",
            "not_dispatched",
        );
    };
    let ticket = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .unwrap_or("")
        .to_owned();
    if ticket.is_empty() || ticket.len() > MAX_CONTROL_BYTES {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "DATA_TICKET_REQUIRED",
            "attachment ticket required",
            "not_dispatched",
        );
    }
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "SOCKET_LIMIT",
            "device socket capacity exhausted",
            "not_dispatched",
        );
    };
    upgrade
        .protocols([DATA_SUBPROTOCOL])
        .max_message_size(tunnel_protocol::MAX_FRAME_LEN)
        .max_frame_size(tunnel_protocol::MAX_FRAME_LEN)
        .write_buffer_size(0)
        .max_write_buffer_size(tunnel_protocol::MAX_FRAME_LEN * 2)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            handle_data(socket, identity, ticket, state.handle).await;
        })
        .into_response()
}

fn subprotocol_offered(headers: &HeaderMap, required: &str) -> bool {
    headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == required)
        })
}

async fn handle_control(mut socket: WebSocket, identity: TlsIdentity, handle: RelayHandle) {
    let first = match timeout(Duration::from_secs(10), socket.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        _ => return,
    };
    let hello = match wire::parse_control(first.as_bytes()) {
        Ok(value) => value,
        Err(_) => return,
    };
    let registration = match handle.register_control(identity, hello).await {
        Ok(value) => value,
        Err(_) => return,
    };
    let key = registration.key.clone();
    if !send_socket(&mut socket, Message::Text(registration.welcome.into())).await {
        handle.disconnect_control(key).await;
        return;
    }
    let mut rx = registration.rx;
    let queue_budget = registration.queue_budget;
    loop {
        tokio::select! {
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(Message::Text(text))) if text.len() <= MAX_CONTROL_BYTES => {
                        if let Ok(message) = wire::parse_control(text.as_bytes()) {
                            let _ = handle.inbound_control(key.clone(), message).await;
                        } else { break; }
                    }
                    Some(Ok(Message::Ping(payload))) => { if !send_socket(&mut socket, Message::Pong(payload)).await { break; } }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => break,
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(crate::actor::ControlOutbound::Text(text)) => {
                        let bytes = text.len();
                        let sent = send_socket(&mut socket, Message::Text(text.into())).await;
                        queue_budget.release(bytes);
                        if !sent { break; }
                    }
                    Some(crate::actor::ControlOutbound::Close) | None => { let _ = send_socket(&mut socket, Message::Close(None)).await; break; }
                }
            }
        }
    }
    // Close admission to this writer before releasing every queued charge.
    // The actor may still hold a sender until it processes the disconnect.
    rx.close();
    while let Ok(message) = rx.try_recv() {
        if let crate::actor::ControlOutbound::Text(text) = message {
            queue_budget.release(text.len());
        }
    }
    handle.disconnect_control(key).await;
}

async fn handle_data(
    mut socket: WebSocket,
    identity: TlsIdentity,
    ticket: String,
    handle: RelayHandle,
) {
    let registration = match handle.attach_data(identity, ticket).await {
        Ok(value) => value,
        Err(_) => return,
    };
    let carrier = registration.carrier.clone();
    let mut rx = registration.rx;
    let queue_budget = registration.queue_budget;
    loop {
        tokio::select! {
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(Message::Binary(bytes))) if bytes.len() <= tunnel_protocol::frame::MAX_FRAME_LEN => {
                        let _ = handle.inbound_data(carrier.clone(), bytes.to_vec()).await;
                    }
                    Some(Ok(Message::Ping(payload))) => { if !send_socket(&mut socket, Message::Pong(payload)).await { break; } }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => break,
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(crate::actor::DataOutbound::Binary(bytes)) => {
                        let len = bytes.len();
                        let sent = send_socket(&mut socket, Message::Binary(bytes.into())).await;
                        queue_budget.release(len);
                        if !sent { break; }
                    }
                    Some(crate::actor::DataOutbound::Barrier(done)) => {
                        let _ = done.send(());
                    }
                    Some(crate::actor::DataOutbound::Close) | None => { let _ = send_socket(&mut socket, Message::Close(None)).await; break; }
                }
            }
        }
    }
    rx.close();
    while let Ok(message) = rx.try_recv() {
        if let crate::actor::DataOutbound::Binary(bytes) = message {
            queue_budget.release(bytes.len());
        }
    }
    handle.disconnect_data(carrier).await;
}

async fn send_socket(socket: &mut WebSocket, message: Message) -> bool {
    matches!(
        timeout(Duration::from_secs(5), socket.send(message)).await,
        Ok(Ok(()))
    )
}

fn catalog_error(error: tunnel_catalog::CatalogError) -> Response {
    let _ = error;
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "AUTHORIZATION_UNAVAILABLE",
        "authorization catalog unavailable",
        "not_dispatched",
    )
}

fn failure_outcome(code: &'static str, execution: &'static str) -> Response {
    let status = if execution == "not_dispatched" && code == "FORBIDDEN" {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    error_response(
        status,
        code,
        "reverse channel operation did not complete",
        execution,
    )
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    execution: &'a str,
    message: &'a str,
}

fn error_response(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    execution: &'static str,
) -> Response {
    (
        status,
        Json(ErrorBody {
            code,
            execution,
            message,
        }),
    )
        .into_response()
}
