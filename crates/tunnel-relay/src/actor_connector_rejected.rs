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
//! **Rate bounds, in order.**
//! 1. Each session: [`SESSION_REJECTED_LOG_BURST`] lines per window, held in
//!    the session state, so one device cannot spend its tenant's whole
//!    budget.
//! 2. Each tenant: [`TENANT_REJECTED_LOG_BURST`] lines per window across all
//!    of its sessions, held in the actor.  Another tenant's lines are not
//!    counted here, so no number of devices or forged REJECTEDs in one
//!    tenant can silence another tenant's refusals.  The budget is kept while
//!    any of the tenant's sessions is live, so reconnecting some devices does
//!    not reset it.
//! 3. The process: [`GLOBAL_REJECTED_LOG_BURST`] lines per window, an I/O
//!    backstop well above one tenant's burst.  It can only be reached by many
//!    tenants flooding at once, and then drops lines for everyone.
//!
//! Each window is [`REJECTED_LOG_WINDOW`] long.  Matched and forged
//! (unmatched) REJECTEDs spend the same session and tenant budgets.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use tunnel_protocol::{open_refusal, rotation::RotationPhase};
use tunnel_transport::log_limit::RefusalLogLimiter;
use uuid::Uuid;

/// Lines one session may write per window.
pub(super) const SESSION_REJECTED_LOG_BURST: u32 = 5;
/// Lines one tenant may write per window, across all of its sessions.
pub(super) const TENANT_REJECTED_LOG_BURST: u32 = 10;
/// Lines the whole process may write per window: an I/O backstop.
pub(super) const GLOBAL_REJECTED_LOG_BURST: u32 = 200;
// The backstop must sit well above one tenant's burst.
const _: () = assert!(GLOBAL_REJECTED_LOG_BURST >= TENANT_REJECTED_LOG_BURST * 10);
/// The window for all three budgets.
pub(super) const REJECTED_LOG_WINDOW: Duration = Duration::from_secs(10);

/// The single key of the process-wide backstop.
const GLOBAL_KEY: &str = "connector_rejected";

#[cfg(not(test))]
static CONNECTOR_REJECTED_LOG: std::sync::LazyLock<RefusalLogLimiter> =
    std::sync::LazyLock::new(|| {
        RefusalLogLimiter::new(GLOBAL_REJECTED_LOG_BURST, REJECTED_LOG_WINDOW)
    });

// Unit tests share one process, so each test thread gets its own backstop
// with the same size; another test's refusals cannot spend this test's.
#[cfg(test)]
thread_local! {
    static CONNECTOR_REJECTED_LOG: RefusalLogLimiter =
        RefusalLogLimiter::new(GLOBAL_REJECTED_LOG_BURST, REJECTED_LOG_WINDOW);
}

/// Label for a code or reason outside the connector's refusal table.
pub(super) const OTHER: &str = "other";

/// A fixed-window line budget: a start time and two counters.
#[derive(Debug, Default)]
pub(super) struct RejectedLogWindow {
    window_started: Option<Instant>,
    admitted: u32,
    suppressed: u64,
}

impl RejectedLogWindow {
    /// `Some(n)` admits a line and carries the number this budget suppressed
    /// since its previous admitted line; `None` suppresses it.
    pub(super) fn admit_at(&mut self, now: Instant, burst: u32) -> Option<u64> {
        let expired = self
            .window_started
            .is_none_or(|started| now.saturating_duration_since(started) >= REJECTED_LOG_WINDOW);
        if expired {
            self.window_started = Some(now);
            self.admitted = 0;
        }
        if self.admitted >= burst {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.admitted += 1;
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// Per-tenant budgets, held by the actor.  An entry is created with a
/// tenant's first line, and entries for tenants with no live session are
/// dropped whenever a new tenant's entry is created, so the map never holds
/// more than the live tenants plus one.
#[derive(Debug, Default)]
pub(super) struct TenantRejectedLogs {
    tenants: HashMap<Uuid, RejectedLogWindow>,
}

impl TenantRejectedLogs {
    /// The budget for `tenant_id`, creating it (and first dropping every
    /// tenant for which `live` is false) if it does not exist.
    pub(super) fn budget(
        &mut self,
        tenant_id: Uuid,
        live: impl Fn(&Uuid) -> bool,
    ) -> &mut RejectedLogWindow {
        if !self.tenants.contains_key(&tenant_id) {
            self.tenants.retain(|tenant, _| live(tenant));
        }
        self.tenants.entry(tenant_id).or_default()
    }

    /// Whether `tenant_id` already has a budget.
    pub(super) fn contains(&self, tenant_id: &Uuid) -> bool {
        self.tenants.contains_key(tenant_id)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.tenants.len()
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
    pub tenant_id: &'a Uuid,
    pub device_id: &'a Uuid,
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

/// The session and tenant budgets a line is charged to.
pub(super) struct RejectedLogBudgets<'a> {
    pub session: &'a mut RejectedLogWindow,
    pub tenant: &'a mut RejectedLogWindow,
}

pub(super) fn log_connector_rejected(
    budgets: RejectedLogBudgets<'_>,
    context: &ConnectorRejectedContext<'_>,
    code: &str,
    reason: &str,
) -> bool {
    #[cfg(not(test))]
    {
        log_connector_rejected_with(
            &CONNECTOR_REJECTED_LOG,
            budgets,
            Instant::now(),
            context,
            code,
            reason,
        )
    }
    #[cfg(test)]
    {
        CONNECTOR_REJECTED_LOG.with(|limiter| {
            log_connector_rejected_with(limiter, budgets, Instant::now(), context, code, reason)
        })
    }
}

/// [`log_connector_rejected`] against an explicit backstop and clock; returns
/// whether the line was written.  The session budget is charged first, then
/// the tenant's, then the backstop.  An admitted line carries each budget's
/// suppressed count since its previous admitted line.
pub(super) fn log_connector_rejected_with(
    backstop: &RefusalLogLimiter,
    budgets: RejectedLogBudgets<'_>,
    now: Instant,
    context: &ConnectorRejectedContext<'_>,
    code: &str,
    reason: &str,
) -> bool {
    let Some(session_suppressed) = budgets.session.admit_at(now, SESSION_REJECTED_LOG_BURST) else {
        return false;
    };
    let Some(tenant_suppressed) = budgets.tenant.admit_at(now, TENANT_REJECTED_LOG_BURST) else {
        return false;
    };
    let Some(suppressed) = backstop.admit_at(GLOBAL_KEY, now) else {
        return false;
    };
    let code_label = code_label(code);
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
        session_suppressed,
        tenant_suppressed,
        suppressed,
        "connector rejected an OPEN"
    );
    true
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Instant,
    };

    use tunnel_transport::log_limit::RefusalLogLimiter;

    use super::{
        ConnectorRejectedContext, GLOBAL_REJECTED_LOG_BURST, OTHER, REJECTED_LOG_WINDOW,
        RejectedLogBudgets, RejectedLogWindow, SESSION_REJECTED_LOG_BURST,
        TENANT_REJECTED_LOG_BURST, TenantRejectedLogs, code_label, log_connector_rejected_with,
        reason_category,
    };
    use uuid::Uuid;

    fn context(tenant_id: &Uuid) -> ConnectorRejectedContext<'_> {
        ConnectorRejectedContext {
            tenant_id,
            device_id: tenant_id,
            session_id: "m7c160-budget",
            epoch: 1,
            stream_id: 1,
            operation_id: "unmatched",
            rotation_phase: None,
            matched: "stream",
            relay_code: "none",
        }
    }

    #[test]
    fn session_then_tenant_then_backstop_budgets_apply_in_order() {
        let backstop = RefusalLogLimiter::new(GLOBAL_REJECTED_LOG_BURST, REJECTED_LOG_WINDOW);
        let start = Instant::now();
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let mut tenant_a_budget = RejectedLogWindow::default();
        let mut tenant_b_budget = RejectedLogWindow::default();
        let log =
            |session: &mut RejectedLogWindow, tenant: &mut RejectedLogWindow, tenant_id: &Uuid| {
                log_connector_rejected_with(
                    &backstop,
                    RejectedLogBudgets { session, tenant },
                    start,
                    &context(tenant_id),
                    "GOAWAY",
                    "x",
                )
            };
        // One session stops at its own burst.
        let mut noisy = RejectedLogWindow::default();
        let written = (0..SESSION_REJECTED_LOG_BURST * 2)
            .filter(|_| log(&mut noisy, &mut tenant_a_budget, &tenant_a))
            .count();
        assert_eq!(written, SESSION_REJECTED_LOG_BURST as usize);
        // Further sessions of the same tenant stop at the tenant's burst.
        let mut more = 0;
        for _ in 0..8 {
            let mut session = RejectedLogWindow::default();
            more += (0..SESSION_REJECTED_LOG_BURST)
                .filter(|_| log(&mut session, &mut tenant_a_budget, &tenant_a))
                .count();
        }
        assert_eq!(
            written + more,
            TENANT_REJECTED_LOG_BURST as usize,
            "one tenant is capped at its own burst"
        );
        // Another tenant is untouched.
        let mut other = RejectedLogWindow::default();
        assert!(log(&mut other, &mut tenant_b_budget, &tenant_b));
        // A new window admits again and reports what was suppressed.
        let later = start + REJECTED_LOG_WINDOW;
        assert_eq!(
            noisy.admit_at(later, SESSION_REJECTED_LOG_BURST),
            Some(u64::from(SESSION_REJECTED_LOG_BURST))
        );
    }

    #[test]
    fn the_backstop_is_one_process_wide_cap() {
        let backstop = RefusalLogLimiter::new(3, REJECTED_LOG_WINDOW);
        let now = Instant::now();
        let written = (0..5u128)
            .filter(|tenant| {
                let tenant_id = Uuid::from_u128(*tenant);
                log_connector_rejected_with(
                    &backstop,
                    RejectedLogBudgets {
                        session: &mut RejectedLogWindow::default(),
                        tenant: &mut RejectedLogWindow::default(),
                    },
                    now,
                    &context(&tenant_id),
                    "GOAWAY",
                    "x",
                )
            })
            .count();
        assert_eq!(written, 3);
    }

    #[test]
    fn tenant_budgets_are_bounded_by_live_tenants() {
        let mut logs = TenantRejectedLogs::default();
        for tenant in 0..100u128 {
            // Only the tenant being created is live.
            let tenant_id = Uuid::from_u128(tenant);
            logs.budget(tenant_id, |candidate| *candidate == tenant_id);
            assert!(logs.len() <= 2, "{} entries", logs.len());
        }
        // Live tenants keep their entries (and their spent budgets).
        let live = [Uuid::from_u128(500), Uuid::from_u128(501)];
        for tenant_id in live {
            logs.budget(tenant_id, |candidate| live.contains(candidate));
        }
        assert_eq!(logs.len(), 2);
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
        ConsumerStreamRegistration, ControlRegistration, DataCarrier, DataOutbound, RelayActor,
        RuntimeProfile, SessionKey, runtime::CarrierContext,
        stream_identity_tests::admitted_control_actor,
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

    fn uuid(tenant: u128, device: u128, role: u128) -> Uuid {
        Uuid::from_u128(0xc160_0000_0000 + (tenant << 16) + (device << 4) + role)
    }

    /// One admitted M2 session with the OPENs the relay issued to it.
    struct Device {
        key: SessionKey,
        streams: Vec<ConsumerStreamRegistration>,
    }

    /// One relay actor holding every session, as a real relay does.
    struct Relay {
        actor: Option<RelayActor>,
        _keep: Vec<(ControlRegistration, mpsc::Receiver<DataOutbound>)>,
    }

    impl Relay {
        fn new() -> Self {
            Self {
                actor: None,
                _keep: Vec::new(),
            }
        }

        fn actor(&mut self) -> &mut RelayActor {
            self.actor.as_mut().expect("a device was added")
        }

        /// Admit one M2 session for (`tenant`, `device`) with `opens`
        /// pending OPENs.  Every device of a tenant shares its principal.
        async fn device(&mut self, tenant: u128, device: u128, opens: usize) -> Device {
            let now = Utc::now();
            let tenant_id = uuid(tenant, 0, 1);
            let principal_id = uuid(tenant, 0, 3);
            let device_id = uuid(tenant, device, 2);
            let service_id = uuid(tenant, device, 4);
            let identity = DeviceIdentity {
                tenant_id,
                device_id,
                owner_user_id: principal_id,
                credential_id: uuid(tenant, device, 5),
                spki_fingerprint: format!("m7c160-spki-{tenant}-{device}"),
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
                session_id: format!("m7c160-session-{tenant}-{device}"),
                epoch: 1,
            };
            let (mut single, control) = admitted_control_actor(identity, key.clone());
            let (data_tx, data_rx) = mpsc::channel(single.options.limits.max_queue_messages);
            let mut session = single
                .sessions
                .remove(&key.scope())
                .expect("admitted session");
            session.profile = RuntimeProfile::M2;
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    format!("m7c160-data-{tenant}-{device}"),
                ),
                tx: data_tx,
            });
            self._keep.push((control, data_rx));
            let actor = self.actor.get_or_insert(single);
            actor.sessions.insert(key.scope(), session);

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
            Device { key, streams }
        }

        /// Send a REJECTED answering `device`'s `index`th OPEN.
        async fn reject(&mut self, device: &Device, index: usize, code: &str, reason: &str) {
            let stream = &device.streams[index];
            let reply_to = self
                .actor()
                .sessions
                .get(&device.key.scope())
                .and_then(|session| session.streams.get(&stream.stream_id))
                .map(|pending| pending.open_message_id.clone())
                .expect("OPEN correlation");
            self.actor()
                .inbound_control(
                    device.key.clone(),
                    ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                        format!("m7c160-rejected-{index}"),
                        reply_to,
                        device.key.session_id.clone(),
                        device.key.epoch,
                        stream.stream_id,
                        stream.operation_id.clone(),
                        code,
                        reason,
                    )),
                )
                .await;
        }

        /// Send a REJECTED for a stream the relay never opened.
        async fn reject_invented(&mut self, device: &Device, stream_id: u64) {
            self.actor()
                .inbound_control(
                    device.key.clone(),
                    ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                        format!("m7c160-forged-{stream_id}"),
                        "forged-open",
                        device.key.session_id.clone(),
                        device.key.epoch,
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

    fn lines_for<'a>(text: &'a str, device: &Device) -> Vec<&'a str> {
        let session = format!("session_id=\"{}\"", device.key.session_id);
        rejected_lines(text)
            .into_iter()
            .filter(|line| line.contains(&session))
            .collect()
    }

    fn lines_for_tenant(text: &str, tenant_id: Uuid) -> usize {
        let tenant = format!("tenant_id={tenant_id}");
        rejected_lines(text)
            .into_iter()
            .filter(|line| line.contains(&tenant))
            .count()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn m7c160_connector_rejected_is_logged_with_code_category_and_phase_only() {
        let (captured, _guard) = capture();
        let mut relay = Relay::new();
        let device = relay.device(0, 0, 2).await;
        let first = &device.streams[0];

        // A known refusal: the shipped connector's draining GOAWAY.
        relay
            .reject(&device, 0, "GOAWAY", "connector is draining")
            .await;
        // A hostile refusal: free-form code and reason carrying a synthetic
        // secret and terminal control characters.
        let hostile_code = format!("X_{SYNTHETIC_SECRET}");
        let hostile_reason = format!("\u{1b}[2J\r\nfake log line {SYNTHETIC_SECRET}");
        relay
            .reject(&device, 1, &hostile_code, &hostile_reason)
            .await;

        let text = captured.text();
        let lines = rejected_lines(&text);
        assert_eq!(lines.len(), 2, "one line per connector REJECTED: {text}");
        let known = lines[0];
        for field in [
            " INFO ",
            &format!("stream_id={}", first.stream_id),
            &format!("operation_id=\"{}\"", first.operation_id),
            &format!("device_id={}", device.key.device_id),
            &format!("session_id=\"{}\"", device.key.session_id),
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
            &format!("stream_id={}", device.streams[1].stream_id),
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

    /// Review of PR #207: one session flooding REJECTEDs for stream IDs the
    /// relay never opened stays within its own budget, and another tenant's
    /// refusal is still logged.
    #[tokio::test(flavor = "current_thread")]
    async fn m7c160_one_session_forging_rejecteds_is_bounded_by_its_session_budget() {
        let (captured, _guard) = capture();
        let mut relay = Relay::new();
        let flooder = relay.device(1, 0, 0).await;
        let victim = relay.device(2, 0, 1).await;
        let flood = u64::from(tunnel_transport::log_limit::DEFAULT_REFUSAL_LOG_BURST) * 3;
        for stream_id in 0..flood {
            relay.reject_invented(&flooder, 1_000_000 + stream_id).await;
        }
        relay
            .reject(&victim, 0, "GOAWAY", "connector is draining")
            .await;

        let text = captured.text();
        let victim_lines = lines_for(&text, &victim);
        assert_eq!(victim_lines.len(), 1, "victim line missing: {text}");
        assert!(victim_lines[0].contains("matched=\"stream\""));
        let flooder_lines = lines_for(&text, &flooder).len();
        assert!(flooder_lines > 0, "the flood must have been logged at all");
        assert!(
            flooder_lines <= super::SESSION_REJECTED_LOG_BURST as usize,
            "one session is bounded by its own budget: {flooder_lines} lines"
        );
    }

    /// Re-review of PR #207: one tenant holding `max_devices_per_user`
    /// sessions, each flooding matched and forged GOAWAYs, cannot silence
    /// another tenant's GOAWAY.
    #[tokio::test(flavor = "current_thread")]
    async fn m7c160_a_tenant_flooding_from_every_device_cannot_silence_another_tenant() {
        let (captured, _guard) = capture();
        let mut relay = Relay::new();
        let devices = crate::config::RelayLimits::default().max_devices_per_user;
        let per_session = super::SESSION_REJECTED_LOG_BURST as usize + 1;
        let mut flooders = Vec::new();
        for device in 0..devices {
            flooders.push(relay.device(3, device as u128, per_session).await);
        }
        let victim = relay.device(4, 0, 1).await;
        let flooder_tenant = flooders[0].key.tenant_id;
        for flooder in &flooders {
            for index in 0..per_session {
                relay
                    .reject(flooder, index, "GOAWAY", "connector is draining")
                    .await;
                relay
                    .reject_invented(flooder, 1_000_000 + index as u64)
                    .await;
            }
        }
        relay
            .reject(&victim, 0, "GOAWAY", "connector is draining")
            .await;

        let text = captured.text();
        assert_eq!(
            lines_for(&text, &victim).len(),
            1,
            "another tenant's GOAWAY must be logged despite the flood"
        );
        let flooder_lines = lines_for_tenant(&text, flooder_tenant);
        assert!(flooder_lines > 0, "the flood must have been logged at all");
        assert!(
            flooder_lines <= super::TENANT_REJECTED_LOG_BURST as usize,
            "one tenant is bounded by its own budget: {flooder_lines} lines"
        );
    }
}
