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
        sessions: vec![
            session("active", None),
            session("draining", Some("reply_timeout")),
        ],
        ..RelaySnapshot::default()
    };
    snapshot.consumer_write_diagnostics.timeout_count = 2;
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
        consumer_refusals: BTreeMap::from([(("echo", "identity"), 6), (("echo", "grant"), 1)]),
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
        "tunnel_relay_sessions_owner_write_unknown 1",
        "tunnel_relay_queue_bytes 200",
        "tunnel_relay_replay_bytes 80",
        "tunnel_relay_application_dispatches_total 5",
        "tunnel_relay_control_registration_conflicts_total 3",
        "tunnel_relay_consumer_write_timeouts_total 2",
        "tunnel_relay_consumer_refusals_total{route=\"echo\",stage=\"identity\"} 6",
        "tunnel_relay_consumer_refusals_total{route=\"echo\",stage=\"grant\"} 1",
        "tunnel_relay_peer_faults_total{stage=\"head\"} 4",
        "tunnel_relay_peer_fault_causes_total{cause=\"transport_timeout\"} 4",
    ] {
        assert!(
            text.lines().any(|candidate| candidate == line),
            "missing `{line}`:\n{text}"
        );
    }
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
