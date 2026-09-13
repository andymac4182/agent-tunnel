//! Bounded, redacted relay health endpoints.
//!
//! Liveness answers whether the HTTP process can answer a request. Readiness
//! is owned by the cluster membership provider and is allowed to fail closed
//! while liveness remains available. Neither endpoint exposes membership
//! records, endpoints, pins, tenant identifiers, or backend error details.

use std::sync::Arc;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

use crate::peer_runtime::PeerRuntime;

const LIVE_STATUS: &str = "live";
const READY_STATUS: &str = "ready";
const UNREADY_STATUS: &str = "unready";

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
}

/// Build the public, bounded liveness/readiness endpoints.
///
/// The optional peer runtime is the existing cluster startup seam. A relay
/// without a private peer runtime is the local M1/M2 profile and is ready once
/// its HTTP actor is serving.
pub(crate) fn router<S>(peer: Option<Arc<PeerRuntime>>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let readiness_peer = peer;
    Router::<S>::new()
        .route("/livez", get(|| async { livez() }))
        .route(
            "/readyz",
            get(move || {
                let peer = readiness_peer.clone();
                async move {
                    let ready = peer.as_ref().is_none_or(|runtime| runtime.is_ready());
                    ready_response(ready)
                }
            }),
        )
}

/// Return a process-only liveness response. This must not consult Redis,
/// membership, owner routing, or any other external authority.
pub(crate) fn livez() -> Response {
    (
        StatusCode::OK,
        Json(HealthBody {
            status: LIVE_STATUS,
        }),
    )
        .into_response()
}

/// Return a redacted readiness response from the caller-provided state.
pub(crate) fn ready_response(ready: bool) -> Response {
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = if ready { READY_STATUS } else { UNREADY_STATUS };
    (status, Json(HealthBody { status: body })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_is_always_ok() {
        assert_eq!(livez().status(), StatusCode::OK);
    }

    #[test]
    fn readiness_fails_closed_without_leaking_a_reason() {
        assert_eq!(
            ready_response(false).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(ready_response(true).status(), StatusCode::OK);
    }
}
