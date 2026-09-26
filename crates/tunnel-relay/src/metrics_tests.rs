//! Task row M6-C24: the metrics text carries aggregates and fixed labels only.

use std::collections::BTreeMap;

use uuid::Uuid;

use super::*;
use crate::{
    ConsumerIngressKind, ConsumerWriteScope, ConsumerWriteTimeoutSnapshot, PeerFaultCause,
    PeerFaultEventSnapshot, PeerFaultRole, PeerOpenDiagnosticStage, RelaySessionSnapshot,
    RelayStreamSnapshot,
};

/// Synthetic canary identifiers, one per identifier field the snapshot
/// carries.  None of them may appear in a scrape.
const TENANT: &str = "c24c24c2-0000-4000-8000-00000000a001";
const DEVICE: &str = "c24c24c2-0000-4000-8000-00000000a002";
const SERVICE: &str = "c24c24c2-0000-4000-8000-00000000a003";
const SESSION: &str = "m6c24-canary-session";
const CONNECTION: &str = "m6c24-canary-connection";
const CANDIDATE: &str = "m6c24-canary-candidate";
const OPERATION: &str = "m6c24-canary-operation";
const OWNER_NODE: &str = "m6c24-canary-owner-node";
const REQUEST: &str = "m6c24-canary-request";

fn canary_snapshot() -> RelaySnapshot {
    let stream = RelayStreamSnapshot {
        stream_id: 7,
        operation_id: OPERATION.to_owned(),
        queue_bytes: 11,
        ..RelayStreamSnapshot::default()
    };
    let session = |phase: &str, unknown: Option<&'static str>| RelaySessionSnapshot {
        tenant_id: TENANT.to_owned(),
        device_id: DEVICE.to_owned(),
        session_id: SESSION.to_owned(),
        phase: phase.to_owned(),
        owner_write_unknown: unknown,
        active_connection_id: CONNECTION.to_owned(),
        candidate_connection_id: Some(CANDIDATE.to_owned()),
        sockets: 2,
        queue_bytes: 100,
        replay_bytes: 40,
        streams: vec![stream.clone()],
        ..RelaySessionSnapshot::default()
    };
    let mut snapshot = RelaySnapshot {
        lifetime_application_dispatches: 5,
        control_registration_conflicts: 3,
        http_writer_parks: 11,
        sessions: vec![
            session("active", None),
            session("draining", Some("reply_timeout")),
        ],
        ..RelaySnapshot::default()
    };
    snapshot.consumer_write_diagnostics.timeout_count = 2;
    // Distinct values so a field rendered under the wrong series is caught.
    snapshot.rotation_freeze_hold = crate::RotationFreezeHoldSnapshot {
        held: 35,
        currently_held: 2,
        admitted_after_hold: 17,
        released_on_commit: 13,
        released_on_abort: 3,
        released_on_recovery: 1,
        released_with_deferred_writes: 4,
        refused_after_bound: 5,
        refused_hold_full: 7,
        cancelled: 3,
        released_on_session_loss: 2,
        refused_on_revocation: 6,
        max_hold_wait_ms: 1_234,
    };
    snapshot
        .consumer_write_diagnostics
        .recent_timeouts
        .push(ConsumerWriteTimeoutSnapshot {
            sequence: 1,
            scope: ConsumerWriteScope {
                device_id: Uuid::parse_str(DEVICE).expect("uuid"),
                service_id: Uuid::parse_str(SERVICE).expect("uuid"),
                ingress: ConsumerIngressKind::Forwarded,
            },
        });
    let faults = &mut snapshot.peer_fault_diagnostics;
    faults.fault_count = 4;
    faults.stage_counts.insert("head", 4);
    faults.cause_counts.insert("transport_timeout", 4);
    faults.recent.push(PeerFaultEventSnapshot {
        sequence: 1,
        observed_at_ms: 1,
        role: PeerFaultRole::Ingress,
        stage: PeerOpenDiagnosticStage::Validation,
        cause: PeerFaultCause::NoLiveOwner,
        tenant_id: Uuid::parse_str(TENANT).expect("uuid"),
        device_id: Uuid::parse_str(DEVICE).expect("uuid"),
        session_id: Some(SESSION.to_owned()),
        owner_epoch: Some(9),
        owner_node_id: Some(OWNER_NODE.to_owned()),
        service_id: Some(Uuid::parse_str(SERVICE).expect("uuid")),
        request_id: Some(REQUEST.to_owned()),
    });
    snapshot
}

fn rendered() -> String {
    let snapshot = canary_snapshot();
    render(&MetricsInput {
        ready: true,
        authority: Some(AuthorityMetrics {
            ready: false,
            checks: 12,
            failures: BTreeMap::from([("run_changed", 2), ("timeout", 1)]),
        }),
        snapshot: &snapshot,
        consumer_refusals: BTreeMap::from([
            (("echo", "identity"), 6),
            (("echo", "grant"), 1),
            (("stream", "rotation_freeze"), 8),
        ]),
    })
}

#[test]
fn m6c24_a_scrape_never_carries_an_identifier_from_the_snapshot() {
    let text = rendered();
    for canary in [
        TENANT, DEVICE, SERVICE, SESSION, CONNECTION, CANDIDATE, OPERATION, OWNER_NODE, REQUEST,
    ] {
        assert!(
            !text.contains(canary),
            "the scrape leaked the canary {canary}:\n{text}"
        );
    }
    // Any UUID-shaped or canary-shaped token at all.
    assert!(!text.contains("c24c24c2"), "{text}");
    assert!(!text.contains("m6c24-canary"), "{text}");
}

#[test]
fn m6c24_a_scrape_reports_the_aggregates() {
    let text = rendered();
    for line in [
        "tunnel_relay_ready 1",
        "tunnel_relay_authority_ready 0",
        "tunnel_relay_authority_checks_total 12",
        "tunnel_relay_authority_check_failures_total{class=\"run_changed\"} 2",
        "tunnel_relay_authority_check_failures_total{class=\"timeout\"} 1",
        "tunnel_relay_device_sessions 2",
        "tunnel_relay_device_sockets 4",
        "tunnel_relay_streams 2",
        "tunnel_relay_sessions_rotating 1",
        "tunnel_relay_sessions_by_rotation_phase{phase=\"active\"} 1",
        "tunnel_relay_sessions_by_rotation_phase{phase=\"draining\"} 1",
        "tunnel_relay_sessions_by_rotation_phase{phase=\"closed\"} 0",
        "tunnel_relay_sessions_owner_write_unknown 1",
        "tunnel_relay_queue_bytes 200",
        "tunnel_relay_replay_bytes 80",
        "tunnel_relay_application_dispatches_total 5",
        "tunnel_relay_control_registration_conflicts_total 3",
        "tunnel_relay_consumer_write_timeouts_total 2",
        "tunnel_relay_http_writer_parks_total 11",
        "tunnel_relay_consumer_refusals_total{route=\"echo\",stage=\"identity\"} 6",
        "tunnel_relay_consumer_refusals_total{route=\"echo\",stage=\"grant\"} 1",
        "tunnel_relay_consumer_refusals_total{route=\"stream\",stage=\"rotation_freeze\"} 8",
        "tunnel_relay_rotation_freeze_hold_held_total 35",
        "tunnel_relay_rotation_freeze_hold_current 2",
        "tunnel_relay_rotation_freeze_hold_admitted_total 17",
        "tunnel_relay_rotation_freeze_hold_released_total{outcome=\"commit\"} 13",
        "tunnel_relay_rotation_freeze_hold_released_total{outcome=\"abort\"} 3",
        "tunnel_relay_rotation_freeze_hold_released_total{outcome=\"recovery\"} 1",
        "tunnel_relay_rotation_freeze_hold_released_total{outcome=\"session_loss\"} 2",
        "tunnel_relay_rotation_freeze_hold_released_with_deferred_writes_total 4",
        "tunnel_relay_rotation_freeze_hold_refused_total{reason=\"after_bound\"} 5",
        "tunnel_relay_rotation_freeze_hold_refused_total{reason=\"hold_full\"} 7",
        "tunnel_relay_rotation_freeze_hold_refused_total{reason=\"revocation\"} 6",
        "tunnel_relay_rotation_freeze_hold_cancelled_total 3",
        "tunnel_relay_rotation_freeze_hold_max_wait_ms 1234",
        "tunnel_relay_peer_faults_total{stage=\"head\"} 4",
        "tunnel_relay_peer_fault_causes_total{cause=\"transport_timeout\"} 4",
    ] {
        assert!(
            text.lines().any(|candidate| candidate == line),
            "missing `{line}`:\n{text}"
        );
    }
}

/// The hold's partition (every held OPEN leaves exactly once) can be checked
/// from the scrape alone: `held_total == current + released_total (all
/// outcomes) + refused_total{after_bound} + cancelled_total`.
#[test]
fn m3_15_the_freeze_hold_partition_is_checkable_from_a_scrape() {
    let text = rendered();
    let value = |series: &str| -> u64 {
        text.lines()
            .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
            .unwrap_or_else(|| panic!("missing {series}:\n{text}"))
            .parse()
            .expect("u64 sample")
    };
    let released: u64 = ["commit", "abort", "recovery", "session_loss"]
        .into_iter()
        .map(|outcome| {
            value(&format!(
                "tunnel_relay_rotation_freeze_hold_released_total{{outcome=\"{outcome}\"}}"
            ))
        })
        .sum();
    assert_eq!(
        value("tunnel_relay_rotation_freeze_hold_held_total"),
        value("tunnel_relay_rotation_freeze_hold_current")
            + released
            + value("tunnel_relay_rotation_freeze_hold_refused_total{reason=\"after_bound\"}")
            + value("tunnel_relay_rotation_freeze_hold_refused_total{reason=\"revocation\"}")
            + value("tunnel_relay_rotation_freeze_hold_cancelled_total"),
    );
}

#[test]
fn m6c24_every_line_is_a_comment_or_a_well_formed_sample() {
    for line in rendered().lines() {
        if line.starts_with("# HELP tunnel_relay_") || line.starts_with("# TYPE tunnel_relay_") {
            continue;
        }
        let (series, value) = line.rsplit_once(' ').expect("sample");
        assert!(series.starts_with("tunnel_relay_"), "{line}");
        assert!(value.parse::<u64>().is_ok(), "{line}");
        // Label values are fixed words: lowercase, digits, `_`, `-`, `.`.
        if let Some((_, labels)) = series.split_once('{') {
            for value in labels.trim_end_matches('}').split(',').filter_map(|pair| {
                pair.split_once('=')
                    .map(|(_, value)| value.trim_matches('"'))
            }) {
                assert!(
                    value.chars().all(|c| c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || matches!(c, '_' | '-' | '.')),
                    "{line}"
                );
            }
        }
    }
}

#[test]
fn m6c24_an_unknown_grant_route_is_other() {
    assert_eq!(route_label("echo"), "echo");
    assert_eq!(route_label("m6c24-canary-service-type"), "other");
}

/// A router that answers `GET /metrics` with a fixed body, for the listener
/// bound tests below (no relay actor needed).
fn fixed_router() -> Router {
    Router::new().route("/metrics", get(|| async { "ok\n" }))
}

async fn bounded_listener() -> (
    std::net::SocketAddr,
    tokio_util::sync::CancellationToken,
    tokio::task::JoinHandle<Result<(), std::io::Error>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(serve_bounded(listener, fixed_router(), cancel.clone()));
    (address, cancel, task)
}

/// Read until the peer closes; `true` when it closed within `within`.
async fn closed_within(stream: &mut tokio::net::TcpStream, within: Duration) -> bool {
    use tokio::io::AsyncReadExt as _;
    let mut buffer = [0_u8; 1024];
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => {}
            Err(_) => return false,
        }
    }
}

async fn scrape_status(address: std::net::SocketAddr) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: metrics\r\n\r\n")
        .await
        .expect("write");
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut reply)).await;
    String::from_utf8_lossy(&reply)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// PR #158 review: a client that connects and sends nothing is closed after
/// the request-head deadline, not held open indefinitely.
#[tokio::test]
async fn m6c24_an_idle_metrics_connection_is_closed_after_the_head_deadline() {
    let (address, cancel, task) = bounded_listener().await;
    let mut idle = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let started = std::time::Instant::now();
    assert!(
        closed_within(&mut idle, HEADER_TIMEOUT + Duration::from_secs(2)).await,
        "an idle metrics connection was still open after {:?}",
        started.elapsed()
    );
    assert!(scrape_status(address).await.contains("200"));
    cancel.cancel();
    task.await.expect("join").expect("serve");
}

/// PR #158 review: the listener holds at most `MAX_CONNECTIONS`; one more is
/// closed at once, and a scrape works again as soon as a slot frees.
#[tokio::test]
async fn m6c24_metrics_connections_beyond_the_cap_are_closed_at_accept() {
    let (address, cancel, task) = bounded_listener().await;
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        held.push(
            tokio::net::TcpStream::connect(address)
                .await
                .expect("connect"),
        );
    }
    // Let the listener accept and hold the first `MAX_CONNECTIONS`.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut extra = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    assert!(
        closed_within(&mut extra, Duration::from_millis(500)).await,
        "a connection beyond the cap of {MAX_CONNECTIONS} was held open"
    );
    drop(held);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(scrape_status(address).await.contains("200"));
    cancel.cancel();
    task.await.expect("join").expect("serve");
}
