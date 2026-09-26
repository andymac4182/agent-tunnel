//! Task row M7-C160: one payload-free, rate-bounded diagnostic for every
//! connector `REJECTED` the relay accepts for a live session.
//!
//! The relay answers the consumer with its own mapping (M6-C120:
//! `RESOURCE_EXHAUSTED` stays `RESOURCE_EXHAUSTED`, everything else becomes
//! `DEVICE_REJECTED`), which hides the connector's code.  This line keeps that
//! code attributable at the default `info` filter.
//!
//! `code` and `reason` arrive from the device and are untrusted.  Neither is
//! ever written verbatim.  Each is matched against the fixed set the shipped
//! connector sends; a known value is logged as a fixed label, and anything
//! else is logged only as `other` plus its byte length.  A device therefore
//! cannot put payload data, credentials, control characters or unbounded text
//! into the relay's log through a refusal.

use tunnel_protocol::rotation::RotationPhase;
use tunnel_transport::log_limit::RefusalLogLimiter;

/// The process-wide limit on `connector rejected` lines, keyed by the code
/// label: a device answering every OPEN with REJECTED cannot set the growth
/// rate of the relay's log.
#[cfg(not(test))]
static CONNECTOR_REJECTED_LOG: std::sync::LazyLock<RefusalLogLimiter> =
    std::sync::LazyLock::new(RefusalLogLimiter::with_defaults);

// Unit tests share one process, so each test thread gets its own limiter with
// the same defaults; another test's refusals cannot spend this test's budget.
#[cfg(test)]
thread_local! {
    static CONNECTOR_REJECTED_LOG: RefusalLogLimiter = RefusalLogLimiter::with_defaults();
}

/// Label for a code or reason outside the known set.
pub(super) const OTHER: &str = "other";

/// The connector refusal codes the shipped connector sends
/// (`crates/tunnel-client/src/lib.rs` and `m2_runtime.rs`).
const KNOWN_CODES: &[&str] = &[
    "AUTHORIZATION_EXPIRED",
    "CANCELLED",
    "EXPORT_DENIED",
    "GOAWAY",
    "OPERATION_DENIED",
    "RESOURCE_EXHAUSTED",
    "STALE_REQUEST",
    "STREAM_EXISTS",
];

/// The connector's fixed reason texts, each mapped to a stable category.
const KNOWN_REASONS: &[(&str, &str)] = &[
    ("connector is draining", "connector_draining"),
    ("stream limit reached", "stream_limit"),
    ("bounded OPEN admission is full", "open_admission_full"),
    (
        "parsed OPEN retention is full; start a fresh session",
        "open_retention_full",
    ),
    (
        "OPEN idempotency retention is full; start a fresh session",
        "open_idempotency_full",
    ),
    (
        "service is not locally allowlisted",
        "export_not_allowlisted",
    ),
    (
        "only the local echo operation is enabled",
        "operation_not_enabled",
    ),
    (
        "only the local echo operations are enabled",
        "operation_not_enabled",
    ),
    ("stream ID is already active", "stream_active"),
    (
        "stream ID is already active or was already forgotten",
        "stream_active_or_forgotten",
    ),
    (
        "stream ID was already forgotten; start a fresh session",
        "stream_forgotten",
    ),
    (
        "OPEN was already forgotten; start a fresh session",
        "open_forgotten",
    ),
    (
        "OPEN authorization window expired before admission",
        "authorization_window_expired",
    ),
    ("local echo cancelled", "cancelled"),
];

/// The logged form of a connector code: a fixed label, never device text.
pub(super) fn code_label(code: &str) -> &'static str {
    KNOWN_CODES
        .iter()
        .copied()
        .find(|known| *known == code)
        .unwrap_or(OTHER)
}

/// The logged form of a connector reason: a fixed category, never device text.
pub(super) fn reason_category(reason: &str) -> &'static str {
    KNOWN_REASONS
        .iter()
        .find(|(text, _)| *text == reason)
        .map_or(OTHER, |(_, category)| category)
}

pub(super) fn rotation_phase_label(phase: Option<RotationPhase>) -> &'static str {
    match phase {
        None => "none",
        Some(RotationPhase::Active) => "active",
        Some(RotationPhase::Preparing) => "preparing",
        Some(RotationPhase::Quiescing) => "quiescing",
        Some(RotationPhase::Draining) => "draining",
        Some(RotationPhase::Committing) => "committing",
        Some(RotationPhase::Retiring) => "retiring",
        Some(RotationPhase::Aborting) => "aborting",
        Some(RotationPhase::Recovering) => "recovering",
        Some(RotationPhase::Closed) => "closed",
    }
}

/// Identifiers the relay resolved itself, plus the relay's own answer.
pub(super) struct ConnectorRejectedContext<'a> {
    pub tenant_id: &'a uuid::Uuid,
    pub device_id: &'a uuid::Uuid,
    pub session_id: &'a str,
    pub epoch: u64,
    pub stream_id: u64,
    pub operation_id: &'a str,
    pub rotation_phase: Option<RotationPhase>,
    /// Which relay record the REJECTED matched: `unary`, `stream` or `none`.
    pub matched: &'static str,
    /// The code the consumer receives, or `none` when no unary waiter was
    /// answered.
    pub relay_code: &'static str,
}

pub(super) fn log_connector_rejected(
    context: &ConnectorRejectedContext<'_>,
    code: &str,
    reason: &str,
) -> bool {
    #[cfg(not(test))]
    {
        log_connector_rejected_with(&CONNECTOR_REJECTED_LOG, context, code, reason)
    }
    #[cfg(test)]
    {
        CONNECTOR_REJECTED_LOG
            .with(|limiter| log_connector_rejected_with(limiter, context, code, reason))
    }
}

/// [`log_connector_rejected`] against an explicit limiter; returns whether
/// the line was written.  An admitted line carries `suppressed`, the number
/// of lines for its code label dropped since the previous one.
pub(super) fn log_connector_rejected_with(
    limiter: &RefusalLogLimiter,
    context: &ConnectorRejectedContext<'_>,
    code: &str,
    reason: &str,
) -> bool {
    let code_label = code_label(code);
    let Some(suppressed) = limiter.admit(code_label) else {
        return false;
    };
    tracing::info!(
        phase = "connector_rejected",
        tenant_id = %context.tenant_id,
        device_id = %context.device_id,
        session_id = context.session_id,
        epoch = context.epoch,
        stream_id = context.stream_id,
        operation_id = context.operation_id,
        rotation_phase = rotation_phase_label(context.rotation_phase),
        matched = context.matched,
        connector_code = code_label,
        connector_code_len = code.len(),
        reason_category = reason_category(reason),
        reason_len = reason.len(),
        relay_code = context.relay_code,
        suppressed,
        "connector rejected an OPEN"
    );
    true
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tunnel_transport::log_limit::RefusalLogLimiter;

    use super::{
        ConnectorRejectedContext, OTHER, code_label, log_connector_rejected_with, reason_category,
    };

    /// Every code and reason the shipped connector sends must have a label,
    /// or the diagnostic degrades to `other` for a real refusal.
    #[test]
    fn every_shipped_connector_refusal_has_a_label() {
        for source in [
            include_str!("../../tunnel-client/src/lib.rs"),
            include_str!("../../tunnel-client/src/m2_runtime.rs"),
        ] {
            // Production code only: the test modules build synthetic refusals.
            let production = source
                .split("\n#[cfg(test)]\nmod ")
                .next()
                .unwrap_or(source);
            let lines: Vec<&str> = production.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                let call = line.contains("send_rejected(")
                    || line.contains("send_open_rejected_journaled(")
                    || line.contains("Rejected::new(");
                if !call || line.trim_start().starts_with("fn ") || line.contains("fn send_") {
                    continue;
                }
                // The call's arguments run to the end of its statement.
                let mut literals = Vec::new();
                for next in lines.iter().skip(index).take(12) {
                    literals.extend(next.split('"').skip(1).step_by(2));
                    let trimmed = next.trim();
                    if trimmed.ends_with(';') || trimmed == "}" {
                        break;
                    }
                }
                for literal in literals {
                    if literal.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                        && literal.len() > 3
                    {
                        assert_ne!(code_label(literal), OTHER, "unlabelled code {literal}");
                    } else if literal.contains(' ') {
                        assert_ne!(
                            reason_category(literal),
                            OTHER,
                            "unlabelled reason {literal:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn lines_are_rate_bounded_per_code_label() {
        let limiter = RefusalLogLimiter::new(2, Duration::from_secs(3600));
        let tenant_id = uuid::Uuid::nil();
        let context = ConnectorRejectedContext {
            tenant_id: &tenant_id,
            device_id: &tenant_id,
            session_id: "m7c160-rate",
            epoch: 1,
            stream_id: 1,
            operation_id: "unmatched",
            rotation_phase: None,
            matched: "none",
            relay_code: "none",
        };
        let written: Vec<bool> = (0..4)
            .map(|_| log_connector_rejected_with(&limiter, &context, "GOAWAY", "x"))
            .collect();
        assert_eq!(written, [true, true, false, false]);
        // Hostile codes share one label, so they share one budget.
        assert!(log_connector_rejected_with(&limiter, &context, "A", "x"));
        assert!(log_connector_rejected_with(&limiter, &context, "B", "x"));
        assert!(!log_connector_rejected_with(&limiter, &context, "C", "x"));
    }

    #[test]
    fn unknown_or_hostile_text_is_never_echoed() {
        assert_eq!(code_label("GOAWAY"), "GOAWAY");
        assert_eq!(code_label("goaway"), OTHER);
        assert_eq!(code_label("SECRET_TOKEN_abc"), OTHER);
        assert_eq!(
            reason_category("connector is draining"),
            "connector_draining"
        );
        assert_eq!(reason_category("connector is draining\n"), OTHER);
        assert_eq!(reason_category("\u{1b}[31mpayload"), OTHER);
    }

    /// A `MakeWriter` collecting log lines.
    #[derive(Clone, Default)]
    pub(crate) struct Captured(pub(crate) Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            std::io::Write::write(&mut *self.0.lock().expect("log buffer"), bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl Captured {
        pub(crate) fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("log buffer")).into_owned()
        }
    }
}

#[cfg(test)]
pub(super) use tests::Captured;

/// The real actor path: a connector REJECTED for a pending M2 OPEN is logged
/// at `info` with the connector's code, a reason category and the rotation
/// phase, and never with the device's reason text.
#[cfg(test)]
mod actor_tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, Utc};
    use tokio::sync::{mpsc, oneshot};
    use tunnel_catalog::{AuthenticatedConsumer, DeviceIdentity, GrantSnapshot, PermissionSet};
    use tunnel_protocol::ControlMessage;
    use uuid::Uuid;

    use super::Captured;
    use crate::actor::{
        DataCarrier, RuntimeProfile, SessionKey, runtime::CarrierContext,
        stream_identity_tests::admitted_control_actor,
    };

    /// Synthetic marker standing in for payload bytes or a credential that a
    /// hostile or buggy device might put in a refusal reason.
    const SYNTHETIC_SECRET: &str = "m7c160-synthetic-secret-7f3a";

    #[tokio::test(flavor = "current_thread")]
    async fn m7c160_connector_rejected_is_logged_with_code_category_and_phase_only() {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_env_filter("info")
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let now = Utc::now();
        let tenant_id = Uuid::from_u128(0xc160_01);
        let device_id = Uuid::from_u128(0xc160_02);
        let principal_id = Uuid::from_u128(0xc160_03);
        let service_id = Uuid::from_u128(0xc160_04);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(0xc160_05),
            spki_fingerprint: "m7c160-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "m7c160-session".to_owned(),
            epoch: 1,
        };
        let (mut actor, _control) = admitted_control_actor(identity, key.clone());
        let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = RuntimeProfile::M2;
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    "m7c160-data".to_owned(),
                ),
                tx: data_tx,
            });
        }
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };

        let mut streams = Vec::new();
        for _ in 0..2 {
            let (tx, rx) = oneshot::channel();
            actor.open_echo_stream(
                consumer.clone(),
                device_id,
                service_id,
                grant.clone(),
                now + Duration::minutes(1),
                tx,
            );
            streams.push(rx.await.expect("registration").expect("M2 admission"));
        }
        let open_message_id = |actor: &crate::actor::RelayActor, stream_id: u64| {
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.streams.get(&stream_id))
                .map(|stream| stream.open_message_id.clone())
                .expect("OPEN correlation")
        };

        // A known refusal: the shipped connector's draining GOAWAY.
        let first = &streams[0];
        let reply_to = open_message_id(&actor, first.stream_id);
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                    "m7c160-rejected-known",
                    reply_to,
                    key.session_id.clone(),
                    key.epoch,
                    first.stream_id,
                    first.operation_id.clone(),
                    "GOAWAY",
                    "connector is draining",
                )),
            )
            .await;

        // A hostile refusal: free-form code and reason carrying a synthetic
        // secret and terminal control characters.
        let second = &streams[1];
        let reply_to = open_message_id(&actor, second.stream_id);
        let hostile_reason = format!("\u{1b}[2J\r\nfake log line {SYNTHETIC_SECRET}");
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                    "m7c160-rejected-hostile",
                    reply_to,
                    key.session_id.clone(),
                    key.epoch,
                    second.stream_id,
                    second.operation_id.clone(),
                    format!("X_{SYNTHETIC_SECRET}"),
                    hostile_reason.clone(),
                )),
            )
            .await;

        let text = captured.text();
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("connector_rejected"))
            .collect();
        assert_eq!(lines.len(), 2, "one line per connector REJECTED: {text}");
        let known = lines[0];
        for field in [
            " INFO ",
            &format!("stream_id={}", first.stream_id),
            &format!("operation_id=\"{}\"", first.operation_id),
            &format!("device_id={device_id}"),
            "session_id=\"m7c160-session\"",
            "rotation_phase=\"none\"",
            "matched=\"stream\"",
            "connector_code=\"GOAWAY\"",
            "reason_category=\"connector_draining\"",
            "reason_len=21",
            "relay_code=\"stream_closed\"",
        ] {
            assert!(known.contains(field), "missing {field:?} in {known}");
        }
        let hostile = lines[1];
        for field in [
            &format!("stream_id={}", second.stream_id),
            "connector_code=\"other\"",
            &format!("connector_code_len={}", SYNTHETIC_SECRET.len() + 2),
            "reason_category=\"other\"",
            &format!("reason_len={}", hostile_reason.len()),
        ] {
            assert!(hostile.contains(field), "missing {field:?} in {hostile}");
        }
        assert!(
            !text.contains(SYNTHETIC_SECRET)
                && !text.contains("fake log line")
                && !text.contains('\u{1b}')
                && !text.contains("connector is draining"),
            "device text reached the log: {text}"
        );
    }
}
