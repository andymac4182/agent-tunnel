//! A private, payload-free metrics listener (task row M6-C24).
//!
//! `serve` opens it only when `metrics_bind` is configured, and only on a
//! loopback or private address: it is plain HTTP with no authentication, so
//! its protection is where it listens.  It serves one route, `GET /metrics`,
//! in the Prometheus text format (version 0.0.4); everything else is `404`.
//! It is never merged into the public consumer or device routers, so
//! `/metrics` stays off the public surface (M7-I04 asserts that).
//!
//! **What a scrape can contain.** Every series is an aggregate: a count, a
//! gauge or a byte total.  Every label value is a fixed word from a closed
//! set in this crate (a route, a refusal stage, a peer-fault stage or cause,
//! an authority failure class) or the crate version.  No tenant, device,
//! session, connection, stream or operation identifier, subject, issuer,
//! token, URL, path, endpoint, error text or payload byte is ever rendered;
//! [`render`] reads identifiers from the snapshot only to count them, and
//! `metrics_tests.rs` seeds canaries into every identifier field to prove it.
//!
//! **Bounds.** One scrape at a time (a concurrent one gets `503`); the actor
//! snapshot is bounded by [`SNAPSHOT_DEADLINE`]; the body's size is bounded by
//! the closed label sets.  The listener itself ([`serve_bounded`]) holds at
//! most [`MAX_CONNECTIONS`] connections, closing any beyond that at accept;
//! each must send its request head within [`HEADER_TIMEOUT`], serves one
//! request (no keep-alive) and is closed after [`CONNECTION_TIMEOUT`] however
//! far it got, so an idle or slow client cannot hold a connection open
//! (PR #158 review).

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{Arc, LazyLock, Mutex, PoisonError},
    time::Duration,
};

use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use tokio::sync::Semaphore;

use crate::{
    RelayHandle, RelaySnapshot, authority_readiness::AuthorityReadiness, peer_runtime::PeerRuntime,
};

/// The longest a scrape waits for the relay actor's snapshot.
pub(crate) const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(2);

/// Connections the metrics listener holds at once; one beyond this is
/// closed as soon as it is accepted.
pub(crate) const MAX_CONNECTIONS: usize = 4;

/// The longest a connection may take to send its request head.
pub(crate) const HEADER_TIMEOUT: Duration = Duration::from_secs(2);

/// The longest any metrics connection stays open, request and response
/// included.  Longer than one scrape's snapshot deadline plus the head.
pub(crate) const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve `router` on `listener` until `cancel`, with the bounds above.
///
/// Plain HTTP/1.1 through hyper, one request per connection.  A connection
/// over [`MAX_CONNECTIONS`] is dropped at accept, which closes it; the
/// request-head deadline is hyper's `header_read_timeout`; the whole
/// connection runs under [`CONNECTION_TIMEOUT`] and stops at `cancel`.
/// Accept errors (for example a descriptor limit) are retried after a short
/// pause rather than ending the listener.
pub(crate) async fn serve_bounded(
    listener: tokio::net::TcpListener,
    router: Router,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<(), std::io::Error> {
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let router = router.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = hyper::service::service_fn(
                move |request: axum::http::Request<hyper::body::Incoming>| {
                    let router = router.clone();
                    async move {
                        tower::ServiceExt::oneshot(router, request.map(axum::body::Body::new)).await
                    }
                },
            );
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .keep_alive(false);
            let connection =
                builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
            tokio::select! {
                () = cancel.cancelled() => {}
                _ = tokio::time::timeout(CONNECTION_TIMEOUT, connection) => {}
            }
        });
    }
}

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Consumer refusals by `(route, stage)`, both fixed labels (M6-C52's
/// vocabulary).  Counted before the log rate limit, so suppressed lines are
/// still counted.  Process-wide, like the log limiter it sits beside.
static CONSUMER_REFUSALS: LazyLock<Mutex<BTreeMap<(&'static str, &'static str), u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Count one refused consumer request.
pub(crate) fn count_consumer_refusal(route: &'static str, stage: &'static str) {
    let mut counts = CONSUMER_REFUSALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let count = counts.entry((route, stage)).or_insert(0);
    *count = count.saturating_add(1);
}

/// Count one consumer request this relay, as the device's owner, refused
/// `ROTATION_FREEZE` itself (stage `rotation_freeze`).  These refusals reach
/// the consumer through the local admission answers, not through
/// `log_consumer_refusal`, and are counted without a log line: the hold's own
/// counters say why.  A freeze refusal for a request that arrived through a
/// peer hop is not counted here; it is a peer fault with cause
/// `rotation_freeze`.
pub(crate) fn count_local_rotation_freeze(route: &'static str) {
    count_consumer_refusal(route, "rotation_freeze");
}

/// The route label for a grant refusal, from the closed set of public
/// routes.  A service type the relay does not name is `other`.
pub(crate) fn route_label(route: &str) -> &'static str {
    match route {
        "devices" => "devices",
        "services" => "services",
        "echo" => "echo",
        "stream" => "stream",
        "http-forward" => "http-forward",
        "fs" => "fs",
        _ => "other",
    }
}

pub(crate) fn consumer_refusals() -> BTreeMap<(&'static str, &'static str), u64> {
    CONSUMER_REFUSALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Everything one scrape renders.
pub(crate) struct MetricsInput<'a> {
    pub(crate) ready: bool,
    /// `None` on a relay without a Redis authority check (a cluster relay).
    pub(crate) authority: Option<AuthorityMetrics>,
    pub(crate) snapshot: &'a RelaySnapshot,
    pub(crate) consumer_refusals: BTreeMap<(&'static str, &'static str), u64>,
}

/// The authority check's state and counters (M6-C67).
pub(crate) struct AuthorityMetrics {
    pub(crate) ready: bool,
    pub(crate) checks: u64,
    pub(crate) failures: BTreeMap<&'static str, u64>,
}

struct Writer(String);

impl Writer {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &'static str)], value: u64) {
        self.0.push_str(name);
        if !labels.is_empty() {
            self.0.push('{');
            for (index, (key, label)) in labels.iter().enumerate() {
                if index > 0 {
                    self.0.push(',');
                }
                let _ = write!(self.0, "{key}=\"{label}\"");
            }
            self.0.push('}');
        }
        let _ = writeln!(self.0, " {value}");
    }
}

fn gauge(out: &mut Writer, name: &str, help: &str, value: u64) {
    out.family(name, "gauge", help);
    out.sample(name, &[], value);
}

fn counter(out: &mut Writer, name: &str, help: &str, value: u64) {
    out.family(name, "counter", help);
    out.sample(name, &[], value);
}

/// Every label `runtime::phase_name` can produce, in protocol order.
const ROTATION_PHASES: [&str; 9] = [
    "active",
    "preparing",
    "quiescing",
    "draining",
    "committing",
    "retiring",
    "aborting",
    "recovering",
    "closed",
];

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// The owner's admission hold across a data-rotation freeze (task row M3-15),
/// from [`crate::RotationFreezeHoldSnapshot`].  Every held OPEN leaves the
/// hold through exactly one `released_total{outcome}`, `refused_total{reason=
/// "after_bound"}` or `cancelled_total` sample, so an operator can check
/// `held_total == current + released + refused(after_bound) + cancelled`.
/// Every label value is a fixed word; the snapshot carries no identifier.
fn render_rotation_freeze_hold(out: &mut Writer, hold: &crate::RotationFreezeHoldSnapshot) {
    counter(
        out,
        "tunnel_relay_rotation_freeze_hold_held_total",
        "New consumer OPENs held at the owner across a data-rotation freeze.",
        hold.held,
    );
    gauge(
        out,
        "tunnel_relay_rotation_freeze_hold_current",
        "OPENs in the rotation-freeze hold now.",
        hold.currently_held,
    );
    counter(
        out,
        "tunnel_relay_rotation_freeze_hold_admitted_total",
        "Held OPENs admitted once the hold ended.",
        hold.admitted_after_hold,
    );
    out.family(
        "tunnel_relay_rotation_freeze_hold_released_total",
        "counter",
        "Held OPENs released, by what ended the hold.",
    );
    for (outcome, count) in [
        ("commit", hold.released_on_commit),
        ("abort", hold.released_on_abort),
        ("recovery", hold.released_on_recovery),
        ("session_loss", hold.released_on_session_loss),
    ] {
        out.sample(
            "tunnel_relay_rotation_freeze_hold_released_total",
            &[("outcome", outcome)],
            count,
        );
    }
    counter(
        out,
        "tunnel_relay_rotation_freeze_hold_released_with_deferred_writes_total",
        "Hold releases that found deferred writes still queued on the session.",
        hold.released_with_deferred_writes,
    );
    out.family(
        "tunnel_relay_rotation_freeze_hold_refused_total",
        "counter",
        "OPENs refused ROTATION_FREEZE by the hold: held past its bound, or never held because the hold was full.",
    );
    for (reason, count) in [
        ("after_bound", hold.refused_after_bound),
        ("hold_full", hold.refused_hold_full),
    ] {
        out.sample(
            "tunnel_relay_rotation_freeze_hold_refused_total",
            &[("reason", reason)],
            count,
        );
    }
    counter(
        out,
        "tunnel_relay_rotation_freeze_hold_cancelled_total",
        "Held OPENs whose consumer went away during the hold.",
        hold.cancelled,
    );
    gauge(
        out,
        "tunnel_relay_rotation_freeze_hold_max_wait_ms",
        "The longest any OPEN spent in the rotation-freeze hold, in milliseconds.",
        hold.max_hold_wait_ms,
    );
}

/// Render one scrape.  Pure: identifiers in `input` are only counted.
pub(crate) fn render(input: &MetricsInput<'_>) -> String {
    let mut out = Writer(String::with_capacity(4096));
    let snapshot = input.snapshot;

    out.family(
        "tunnel_relay_build_info",
        "gauge",
        "The relay build; always 1.",
    );
    out.sample(
        "tunnel_relay_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );
    gauge(
        &mut out,
        "tunnel_relay_ready",
        "1 while /readyz answers ready, else 0.",
        u64::from(input.ready),
    );
    if let Some(authority) = &input.authority {
        gauge(
            &mut out,
            "tunnel_relay_authority_ready",
            "1 while the last bounded Redis authority check succeeded recently (single relay).",
            u64::from(authority.ready),
        );
        counter(
            &mut out,
            "tunnel_relay_authority_checks_total",
            "Redis authority checks run (single relay).",
            authority.checks,
        );
        out.family(
            "tunnel_relay_authority_check_failures_total",
            "counter",
            "Failed Redis authority checks by fixed failure class (single relay).",
        );
        for (class, count) in &authority.failures {
            out.sample(
                "tunnel_relay_authority_check_failures_total",
                &[("class", class)],
                *count,
            );
        }
    }

    let sessions = &snapshot.sessions;
    gauge(
        &mut out,
        "tunnel_relay_device_sessions",
        "Live device sessions this relay owns.",
        usize_u64(sessions.len()),
    );
    gauge(
        &mut out,
        "tunnel_relay_device_sockets",
        "Device sockets attached to live sessions.",
        sessions.iter().map(|s| u64::from(s.sockets)).sum(),
    );
    gauge(
        &mut out,
        "tunnel_relay_streams",
        "Logical streams on live sessions.",
        sessions.iter().map(|s| usize_u64(s.streams.len())).sum(),
    );
    gauge(
        &mut out,
        "tunnel_relay_sessions_rotating",
        "Live sessions whose data socket is in a rotation phase other than active.",
        usize_u64(sessions.iter().filter(|s| s.phase != "active").count()),
    );
    // M6-06: which phase, not only "not active". Nine fixed labels, every
    // one always present, so a scrape can watch a session enter and leave a
    // phase and the series set never depends on state.
    out.family(
        "tunnel_relay_sessions_by_rotation_phase",
        "gauge",
        "Live sessions by data-socket rotation phase.",
    );
    for phase in ROTATION_PHASES {
        out.sample(
            "tunnel_relay_sessions_by_rotation_phase",
            &[("phase", phase)],
            usize_u64(sessions.iter().filter(|s| s.phase == phase).count()),
        );
    }
    gauge(
        &mut out,
        "tunnel_relay_sessions_owner_write_unknown",
        "Live sessions whose last owner-lease renewal has an unknown outcome.",
        usize_u64(
            sessions
                .iter()
                .filter(|s| s.owner_write_unknown.is_some())
                .count(),
        ),
    );
    gauge(
        &mut out,
        "tunnel_relay_queue_bytes",
        "Bytes queued on live sessions.",
        sessions.iter().map(|s| usize_u64(s.queue_bytes)).sum(),
    );
    gauge(
        &mut out,
        "tunnel_relay_replay_bytes",
        "Bytes retained for replay on live sessions.",
        sessions.iter().map(|s| usize_u64(s.replay_bytes)).sum(),
    );
    counter(
        &mut out,
        "tunnel_relay_application_dispatches_total",
        "Application records accepted for dispatch to a device.",
        snapshot.lifetime_application_dispatches,
    );
    counter(
        &mut out,
        "tunnel_relay_control_registration_conflicts_total",
        "Device control sessions refused because the device already had an owner (owner_busy).",
        snapshot.control_registration_conflicts,
    );
    counter(
        &mut out,
        "tunnel_relay_consumer_write_timeouts_total",
        "Public response writes that timed out.",
        snapshot.consumer_write_diagnostics.timeout_count,
    );

    render_rotation_freeze_hold(&mut out, &snapshot.rotation_freeze_hold);

    out.family(
        "tunnel_relay_consumer_refusals_total",
        "counter",
        "Refused consumer requests by fixed route and stage (process-wide).",
    );
    for ((route, stage), count) in &input.consumer_refusals {
        out.sample(
            "tunnel_relay_consumer_refusals_total",
            &[("route", route), ("stage", stage)],
            *count,
        );
    }

    let faults = &snapshot.peer_fault_diagnostics;
    out.family(
        "tunnel_relay_peer_faults_total",
        "counter",
        "Peer faults this relay observed, by fixed dispatch stage.",
    );
    for (stage, count) in &faults.stage_counts {
        out.sample(
            "tunnel_relay_peer_faults_total",
            &[("stage", stage)],
            *count,
        );
    }
    out.family(
        "tunnel_relay_peer_fault_causes_total",
        "counter",
        "Peer faults this relay observed, by fixed cause.",
    );
    for (cause, count) in &faults.cause_counts {
        out.sample(
            "tunnel_relay_peer_fault_causes_total",
            &[("cause", cause)],
            *count,
        );
    }
    out.0
}

#[derive(Clone)]
struct MetricsState {
    handle: RelayHandle,
    peer: Option<Arc<PeerRuntime>>,
    authority: Option<Arc<AuthorityReadiness>>,
    scrape: Arc<Semaphore>,
}

/// The private metrics router: `GET /metrics` only.
pub(crate) fn router(
    handle: RelayHandle,
    peer: Option<Arc<PeerRuntime>>,
    authority: Option<Arc<AuthorityReadiness>>,
) -> Router {
    Router::new()
        .route("/metrics", get(scrape))
        .with_state(MetricsState {
            handle,
            peer,
            authority,
            scrape: Arc::new(Semaphore::new(1)),
        })
}

async fn scrape(State(state): State<MetricsState>) -> Response {
    let Ok(_permit) = state.scrape.try_acquire() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "scrape in progress\n").into_response();
    };
    let Ok(Ok(snapshot)) = tokio::time::timeout(SNAPSHOT_DEADLINE, state.handle.snapshot()).await
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "relay snapshot unavailable\n",
        )
            .into_response();
    };
    let ready = crate::health::relay_ready(state.peer.as_ref(), state.authority.as_ref());
    let authority = state.authority.as_ref().map(|authority| AuthorityMetrics {
        ready: authority.is_ready(),
        checks: authority.checks(),
        failures: authority.failures(),
    });
    let body = render(&MetricsInput {
        ready,
        authority,
        snapshot: &snapshot,
        consumer_refusals: consumer_refusals(),
    });
    ([(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response()
}

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
