//! Task row M7-C160: one payload-free, rate-bounded diagnostic for every
//! connector `REJECTED` the relay receives for a live session.
//!
//! The relay answers the consumer with its own mapping (M6-C120:
//! `RESOURCE_EXHAUSTED` stays `RESOURCE_EXHAUSTED`, everything else becomes
//! `DEVICE_REJECTED`), which hides the connector's code.  This line keeps that
//! code attributable at the default `info` filter.
//!
//! `code` and `reason` arrive from the device and are untrusted.  Neither is
//! ever written verbatim.  Each is looked up in the refusal table the shipped
//! connector sends from (`tunnel_protocol::open_refusal`); a table entry is
//! logged as its fixed code and category, and anything else only as `other`
//! plus its byte length.  A device therefore cannot put payload data,
//! credentials, control characters or unbounded text into the relay's log
//! through a refusal.
//!
//! **Rate bounds.**  Each session has its own small budget
//! ([`SESSION_REJECTED_LOG_BURST`] lines per [`SESSION_REJECTED_LOG_WINDOW`]),
//! so one device cannot crowd out another.  A process-wide limiter is the
//! overall cap: matched refusals share a budget per code label, and REJECTEDs
//! that match no relay record (which a device can forge freely) share a
//! separate `unmatched` budget, so forged ones cannot spend the budget of real
//! ones.

use std::time::{Duration, Instant};

use tunnel_protocol::{open_refusal, rotation::RotationPhase};
use tunnel_transport::log_limit::RefusalLogLimiter;

/// The process-wide cap on `connector rejected` lines, keyed by the code label
/// for matched refusals and by [`UNMATCHED_KEY`] for unmatched ones.
#[cfg(not(test))]
static CONNECTOR_REJECTED_LOG: std::sync::LazyLock<RefusalLogLimiter> =
    std::sync::LazyLock::new(RefusalLogLimiter::with_defaults);

// Unit tests share one process, so each test thread gets its own global
// limiter with the same defaults; another test's refusals cannot spend this
// test's budget.
#[cfg(test)]
thread_local! {
    static CONNECTOR_REJECTED_LOG: RefusalLogLimiter = RefusalLogLimiter::with_defaults();
}

/// Lines one session may write per window, below the global cap.
pub(super) const SESSION_REJECTED_LOG_BURST: u32 = 5;
/// The per-session window.
pub(super) const SESSION_REJECTED_LOG_WINDOW: Duration = Duration::from_secs(10);

/// Global limiter key for a REJECTED matching no relay record.
const UNMATCHED_KEY: &str = "unmatched";

/// Label for a code or reason outside the connector's refusal table.
pub(super) const OTHER: &str = "other";

/// A session's own fixed-window line budget: two counters and a start time,
/// held in the (bounded) session state.
#[derive(Debug, Default)]
pub(super) struct SessionRejectedLog {
    window_started: Option<Instant>,
    admitted: u32,
    suppressed: u64,
}

impl SessionRejectedLog {
    /// `Some(n)` admits a line and carries the number this session had
    /// suppressed since its previous admitted line; `None` suppresses it.
    pub(super) fn admit_at(&mut self, now: Instant) -> Option<u64> {
        let expired = self.window_started.is_none_or(|started| {
            now.saturating_duration_since(started) >= SESSION_REJECTED_LOG_WINDOW
        });
        if expired {
            self.window_started = Some(now);
            self.admitted = 0;
        }
        if self.admitted >= SESSION_REJECTED_LOG_BURST {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.admitted += 1;
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// The logged form of a connector code: a fixed label, never device text.
pub(super) fn code_label(code: &str) -> &'static str {
    open_refusal::known_code(code).unwrap_or(OTHER)
}

/// The logged form of a connector reason: a fixed category, never device text.
pub(super) fn reason_category(reason: &str) -> &'static str {
    open_refusal::reason_category(reason).unwrap_or(OTHER)
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
    /// The code the consumer receives, `stream_closed` for a pending M2 OPEN,
    /// or `none`.
    pub relay_code: &'static str,
}

pub(super) fn log_connector_rejected(
    session_log: Option<&mut SessionRejectedLog>,
    context: &ConnectorRejectedContext<'_>,
    code: &str,
    reason: &str,
) -> bool {
    #[cfg(not(test))]
    {
        log_connector_rejected_with(
            &CONNECTOR_REJECTED_LOG,
            session_log,
            Instant::now(),
            context,
            code,
            reason,
        )
    }
    #[cfg(test)]
    {
        CONNECTOR_REJECTED_LOG.with(|limiter| {
            log_connector_rejected_with(limiter, session_log, Instant::now(), context, code, reason)
        })
    }
}

/// [`log_connector_rejected`] against an explicit global limiter and clock;
/// returns whether the line was written.  The session budget is checked
/// first, then the global cap.  An admitted line carries `suppressed` (global,
/// for its key) and `session_suppressed` (this session's own).
pub(super) fn log_connector_rejected_with(
    limiter: &RefusalLogLimiter,
    session_log: Option<&mut SessionRejectedLog>,
    now: Instant,
    context: &ConnectorRejectedContext<'_>,
    code: &str,
    reason: &str,
) -> bool {
    let session_suppressed = match session_log {
        Some(session_log) => match session_log.admit_at(now) {
            Some(suppressed) => suppressed,
            None => return false,
        },
        None => 0,
    };
    let code_label = code_label(code);
    let key = if context.matched == "none" {
        UNMATCHED_KEY
    } else {
        code_label
    };
    let Some(suppressed) = limiter.admit_at(key, now) else {
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
        session_suppressed,
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

    use std::time::Instant;

    use tunnel_transport::log_limit::RefusalLogLimiter;

    use super::{
        ConnectorRejectedContext, OTHER, SESSION_REJECTED_LOG_BURST, SESSION_REJECTED_LOG_WINDOW,
        SessionRejectedLog, code_label, log_connector_rejected_with, reason_category,
    };

    fn context(matched: &'static str) -> ConnectorRejectedContext<'static> {
        static NIL: uuid::Uuid = uuid::Uuid::nil();
        ConnectorRejectedContext {
            tenant_id: &NIL,
            device_id: &NIL,
            session_id: "m7c160-rate",
            epoch: 1,
            stream_id: 1,
            operation_id: "unmatched",
            rotation_phase: None,
            matched,
            relay_code: "none",
        }
    }

    #[test]
    fn the_global_cap_is_per_code_label_and_unmatched_has_its_own_key() {
        let limiter = RefusalLogLimiter::new(2, Duration::from_secs(3600));
        let now = Instant::now();
        let matched = context("stream");
        let log = |context: &ConnectorRejectedContext<'_>, code: &str| {
            log_connector_rejected_with(&limiter, None, now, context, code, "x")
        };
        let written: Vec<bool> = (0..3).map(|_| log(&matched, "GOAWAY")).collect();
        assert_eq!(written, [true, true, false]);
        // Hostile codes share one label, so they share one budget.
        assert!(log(&matched, "A"));
        assert!(log(&matched, "B"));
        assert!(!log(&matched, "C"));
        // Unmatched REJECTEDs spend only their own key, whatever their code.
        let unmatched = context("none");
        assert!(log(&unmatched, "RESOURCE_EXHAUSTED"));
        assert!(log(&unmatched, "RESOURCE_EXHAUSTED"));
        assert!(!log(&unmatched, "RESOURCE_EXHAUSTED"));
        assert!(log(&matched, "RESOURCE_EXHAUSTED"));
    }

    #[test]
    fn each_session_has_its_own_budget_below_the_global_cap() {
        let limiter = RefusalLogLimiter::with_defaults();
        let start = Instant::now();
        let matched = context("stream");
        let mut noisy = SessionRejectedLog::default();
        let mut quiet = SessionRejectedLog::default();
        let burst = SESSION_REJECTED_LOG_BURST as usize;
        let written = (0..burst * 2)
            .filter(|_| {
                log_connector_rejected_with(
                    &limiter,
                    Some(&mut noisy),
                    start,
                    &matched,
                    "GOAWAY",
                    "x",
                )
            })
            .count();
        assert_eq!(written, burst);
        assert!(log_connector_rejected_with(
            &limiter,
            Some(&mut quiet),
            start,
            &matched,
            "GOAWAY",
            "x"
        ));
        // A new window admits the noisy session again and reports what it
        // suppressed.
        let later = start + SESSION_REJECTED_LOG_WINDOW;
        assert_eq!(noisy.admit_at(later), Some(burst as u64));
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

/// The real actor path: a connector REJECTED is logged at `info` with the
/// connector's code, a reason category and the rotation phase, and never with
/// the device's reason text.
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
        ConsumerStreamRegistration, DataCarrier, RelayActor, RuntimeProfile, SessionKey,
        runtime::CarrierContext, stream_identity_tests::admitted_control_actor,
    };

    /// Synthetic marker standing in for payload bytes or a credential that a
    /// hostile or buggy device might put in a refusal reason.
    const SYNTHETIC_SECRET: &str = "m7c160-synthetic-secret-7f3a";

    fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_env_filter("info")
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (captured, guard)
    }

    struct Device {
        actor: RelayActor,
        key: SessionKey,
        streams: Vec<ConsumerStreamRegistration>,
        _data_rx: mpsc::Receiver<crate::actor::DataOutbound>,
        _control: crate::actor::ControlRegistration,
    }

    impl Device {
        /// One admitted M2 session for its own tenant and device, with `opens`
        /// pending OPENs the relay issued.
        async fn open(seed: u128, opens: usize) -> Self {
            let now = Utc::now();
            let tenant_id = Uuid::from_u128(0xc160_0000 + seed * 16 + 1);
            let device_id = Uuid::from_u128(0xc160_0000 + seed * 16 + 2);
            let principal_id = Uuid::from_u128(0xc160_0000 + seed * 16 + 3);
            let service_id = Uuid::from_u128(0xc160_0000 + seed * 16 + 4);
            let identity = DeviceIdentity {
                tenant_id,
                device_id,
                owner_user_id: principal_id,
                credential_id: Uuid::from_u128(0xc160_0000 + seed * 16 + 5),
                spki_fingerprint: format!("m7c160-spki-{seed}"),
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
                session_id: format!("m7c160-session-{seed}"),
                epoch: 1,
            };
            let (mut actor, control) = admitted_control_actor(identity, key.clone());
            let (data_tx, data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
            if let Some(session) = actor.sessions.get_mut(&key.scope()) {
                session.profile = RuntimeProfile::M2;
                session.active_carrier = Some(DataCarrier {
                    context: CarrierContext::new(
                        key.session_id.clone(),
                        key.epoch,
                        1,
                        format!("m7c160-data-{seed}"),
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
            for _ in 0..opens {
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
            Self {
                actor,
                key,
                streams,
                _data_rx: data_rx,
                _control: control,
            }
        }

        fn open_message_id(&self, stream_id: u64) -> String {
            self.actor
                .sessions
                .get(&self.key.scope())
                .and_then(|session| session.streams.get(&stream_id))
                .map(|stream| stream.open_message_id.clone())
                .expect("OPEN correlation")
        }

        /// Send a REJECTED answering this device's `index`th OPEN.
        async fn reject(&mut self, index: usize, code: &str, reason: &str) {
            let stream_id = self.streams[index].stream_id;
            let operation_id = self.streams[index].operation_id.clone();
            let reply_to = self.open_message_id(stream_id);
            self.actor
                .inbound_control(
                    self.key.clone(),
                    ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                        format!("m7c160-rejected-{index}"),
                        reply_to,
                        self.key.session_id.clone(),
                        self.key.epoch,
                        stream_id,
                        operation_id,
                        code,
                        reason,
                    )),
                )
                .await;
        }

        /// Send a REJECTED for a stream the relay never opened.
        async fn reject_invented(&mut self, stream_id: u64) {
            self.actor
                .inbound_control(
                    self.key.clone(),
                    ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                        format!("m7c160-forged-{stream_id}"),
                        "forged-open",
                        self.key.session_id.clone(),
                        self.key.epoch,
                        stream_id,
                        "forged-operation",
                        "GOAWAY",
                        "connector is draining",
                    )),
                )
                .await;
        }
    }

    fn rejected_lines(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|line| line.contains("connector_rejected"))
            .collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn m7c160_connector_rejected_is_logged_with_code_category_and_phase_only() {
        let (captured, _guard) = capture();
        let mut device = Device::open(0, 2).await;
        let device_id = device.key.device_id;
        let (first, second) = (
            (
                device.streams[0].stream_id,
                device.streams[0].operation_id.clone(),
            ),
            device.streams[1].stream_id,
        );

        // A known refusal: the shipped connector's draining GOAWAY.
        device.reject(0, "GOAWAY", "connector is draining").await;
        // A hostile refusal: free-form code and reason carrying a synthetic
        // secret and terminal control characters.
        let hostile_code = format!("X_{SYNTHETIC_SECRET}");
        let hostile_reason = format!("\u{1b}[2J\r\nfake log line {SYNTHETIC_SECRET}");
        device.reject(1, &hostile_code, &hostile_reason).await;

        let text = captured.text();
        let lines = rejected_lines(&text);
        assert_eq!(lines.len(), 2, "one line per connector REJECTED: {text}");
        let known = lines[0];
        for field in [
            " INFO ",
            &format!("stream_id={}", first.0),
            &format!("operation_id=\"{}\"", first.1),
            &format!("device_id={device_id}"),
            "session_id=\"m7c160-session-0\"",
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
            &format!("stream_id={second}"),
            "connector_code=\"other\"",
            &format!("connector_code_len={}", hostile_code.len()),
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

    /// Review of PR #207: a device flooding REJECTEDs for stream IDs the relay
    /// never opened must not spend the budget another tenant's genuine
    /// refusal needs.
    #[tokio::test(flavor = "current_thread")]
    async fn m7c160_a_forged_rejected_flood_cannot_silence_another_tenants_refusal() {
        let (captured, _guard) = capture();
        let mut flooder = Device::open(1, 0).await;
        let mut victim = Device::open(2, 1).await;
        let flood = u64::from(tunnel_transport::log_limit::DEFAULT_REFUSAL_LOG_BURST) * 3;
        for stream_id in 0..flood {
            flooder.reject_invented(1_000_000 + stream_id).await;
        }
        victim.reject(0, "GOAWAY", "connector is draining").await;

        let text = captured.text();
        let victim_session = format!("session_id=\"{}\"", victim.key.session_id);
        let victim_lines: Vec<&str> = rejected_lines(&text)
            .into_iter()
            .filter(|line| line.contains(&victim_session))
            .collect();
        assert_eq!(
            victim_lines.len(),
            1,
            "the victim's matched GOAWAY must be logged despite the flood: {text}"
        );
        assert!(victim_lines[0].contains("matched=\"stream\""));
        let flooder_session = format!("session_id=\"{}\"", flooder.key.session_id);
        let flooder_lines = rejected_lines(&text)
            .into_iter()
            .filter(|line| line.contains(&flooder_session))
            .count();
        assert!(
            flooder_lines <= super::SESSION_REJECTED_LOG_BURST as usize,
            "one session is bounded by its own budget: {flooder_lines} lines"
        );
        assert!(flooder_lines > 0, "the flood must have been logged at all");
    }
}
