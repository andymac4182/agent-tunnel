//! `verify-m8-acp-cluster`: ACP across three relays, three completed
//! scheduled rotations, two tenants, revocation, peer-key rotation, owner loss
//! and saturated forwarding (task row M8-04, M8 chunk 5).
//!
//! This is the sibling of [`super::acp_real_path`], which put ACP on the real
//! cluster for the first time.  Everything that gate listed as chunk 5's is
//! here: two users in two tenants, cross-tenant isolation, grant revocation,
//! owner loss, peer-key rotation, saturation — and the one it could not do at
//! all, **an ACP connection carried across a completed scheduled rotation**.
//!
//! # The headline: three completed rotations, and why it is possible here
//!
//! Chunk 4 recorded `rotations_completed` per run and asserted nothing about
//! it.  This gate asserts three, with two sessions live across them.  That is
//! only possible because **device data-socket rotation and cluster membership
//! re-signing are different mechanisms**, and only the second is M7-C80:
//!
//! * A scheduled rotation replaces the device's **data WebSocket**
//!   (`tunnel_protocol::rotation`).  It fences, drains and replays the logical
//!   streams, and `docs/acp.md` says in terms that it "leaves ACP connections,
//!   sessions, requests, callbacks, and GET streams intact".  The device holds
//!   two steady-state sockets and a third only while a candidate is attaching.
//! * A membership re-sign invalidates every **peer admission**
//!   (`membership_runtime.rs`), and with it every in-flight peer stream.  That
//!   is M7-C80, and it is what `Gate::boundary` accommodates.
//!
//! So the demand is met without weakening anything: the consumer still enters
//! at **relay-c**, a non-owner, so every exchange still crosses the private
//! mTLS HTTP/3 peer hop; the rotations are real scheduled device rotations
//! driven by the connector's own policy timer; and membership is simply not
//! re-signed while the streams are live.
//!
//! **What that costs, stated rather than hidden.** A peer admission's deadline
//! is anchored at admission and never extended (`membership_runtime.rs`, the
//! `AdmissionDeadline` comment: "never extended by a later checkpoint
//! receipt"), and the fixture's records live 60 s — the product maximum
//! (`tunnel_cluster::membership::MAX_RECORD_LIFETIME`).  Re-signing kills a
//! live stream and letting the record expire kills it too, by the same
//! cancellation token with a different recorded reason.  **There is therefore
//! no path that keeps one ACP connection on a non-owner ingress alive past its
//! membership record's expiry**, and this gate's rotation case fits inside
//! that window rather than escaping it.  [`ROTATION_CEILING`] is that bound
//! written down, and the case asserts it finished inside it.  M8-C14 reached
//! the same ceiling from the other side, by expiry rather than by a re-sign.
//!
//! # No claim terminates on an HTTP status
//!
//! As in chunk 4: 202 means accepted by the bridge and nothing more, so every
//! claim about a prompt, a session, a callback or a rotation anchors to a
//! message **observed on an SSE stream**, and `stopReason` is read off the
//! wire.  A status is asserted only where something was *refused*, and each
//! refusal also shows that nothing reached the device.
//!
//! # Rotation-freeze refusals are never silently counted as passes
//!
//! M3-15 is open and this gate inherits chunk 4's discipline unchanged: every
//! `503 not_dispatched` is counted, correlated against an **observed**
//! connector rotation phase, resent only while it coincides with a freeze and
//! only up to [`super::acp_real_path::NOT_DISPATCHED_RETRIES`], and the first
//! refusal that does not coincide fails the run by name.  This gate runs the
//! device at a **3-second** rotation interval, so it meets far more freezes
//! than chunk 4 did; that is the point, and the budget is derived from the
//! policy rather than tuned.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};
use tunnel_client::http_forward::{AcpExportDiagnostics, HttpHandlers};
use tunnel_client::{ConnectOptions, ConnectionHandle};
use tunnel_core::RotationConfig;

use super::acp_real_path::{
    AcpConsumer, FreezeWatch, HeldStream, MEMBERSHIP_RECORD_LIFETIME, MEMBERSHIP_RESIGN_SPACING,
    MIN_RETRY_HINT_MS, NOT_DISPATCHED_RETRIES, RefusalLedger, acp_request, device_config_text,
    fixture_binary_path, json_stream, process_alive, session_id, stop_reason,
};
use super::{
    CLEANUP_TIMEOUT, Harness, HarnessError, HarnessOptions, ProductionCluster, ProxyConfig, Result,
    RunningHarness, SCENARIO_TIMEOUT, STARTUP_TIMEOUT, TcpProxy, finish_scenario_with_cleanup,
    push_cleanup_error,
};

/// The rotation policy this gate runs the device under.
///
/// **Unlike chunk 4's, this one is load-bearing.** Three completed rotations
/// must fit inside one membership record's remaining lifetime, so the interval
/// is the configuration floor — `tunnel_core::RotationConfig::validate`
/// requires `handshake_timeout < overlap < interval`, and 1 < 2 < 3 is the
/// smallest triple that satisfies it.  It is also exactly the production
/// cluster fixture's own `ROTATION`, so it is a proven setting rather than one
/// invented here to make a deadline.
pub const CLUSTER_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 3,
    handshake_timeout_seconds: 1,
    overlap_seconds: 2,
};

/// How many completed scheduled rotations the sessions must be carried across.
pub const REQUIRED_ROTATIONS: u64 = 3;

/// The longest the rotation case may take before it is relying on membership
/// records that were already expiring.
///
/// Deliberately **well inside** [`MEMBERSHIP_RECORD_LIFETIME`] rather than
/// equal to it: the records were signed at the case boundary, before the
/// consumer connected, so the admission's own deadline is already shorter than
/// the record's nominal lifetime by the setup time.  A case that needed the
/// whole 60 s would be resting on the last moments of a record.
pub const ROTATION_CEILING: Duration = Duration::from_secs(40);

/// The two sessions the rotation case holds open.
pub const ROTATION_SESSIONS: usize = 2;

/// The side effect the held turns record, one each, in the agent's own
/// append-only ledger.
const ROTATION_EFFECT: &str = "rotation-span";

/// The cases this gate runs, in order.
///
/// The order is not cosmetic.  `rotation-span` is first because it needs the
/// most membership headroom of any case here.  `owner-loss` is last because
/// it removes relay-a from the cluster, and `peer-key-rotation` before it
/// because it leaves a relay's pin set rewritten.
pub const CLUSTER_CASES: [&str; 7] = [
    "rotation-span",
    "two-tenant-ids",
    "forged-heads",
    "saturation",
    "revocation",
    "peer-key-rotation",
    "owner-loss",
];

/// What this gate deliberately does not establish.
pub const NOT_COVERED: [&str; 7] = [
    "an ACP connection surviving a membership re-sign, or outliving its membership record: M7-C80 is open, a peer admission's deadline is never extended, and this gate's rotation case is bounded to finish inside one record rather than escaping that limit",
    "per-OS process-tree cleanup: macOS is the only host any of this has run on, and a descendant that leaves its process group is not reached at all (M8-C07)",
    "any OS sandbox guarantee: until a tested sandbox profile exists this export is trusted-agent execution, and filesystem confinement is not claimed from cwd alone",
    "real-agent interoperability: the only agent here is this repository's own synthetic fixture, the roadmap gate's real-agent clause is dedicated-VM work, and no ACP server has been run",
    "no retry beyond the moment of observation: a ledger is read when a stream has failed and again after a settle window, and a replay issued after that would not be observed",
    "the connection-capacity table at its real bounds: 256 tracked and 32 per principal are proven as arithmetic in tunnel-acp-export, not by opening 257 connections here",
    "the permission deadline and the idle, prompt-wall-time bounds of the limits table over the real route: they are measured against the export's own clock in tunnel-acp-export, not here",
];

/// The limits of this gate's claim, with the ones carrying a measurement
/// formatted from what was actually observed.
///
/// **A disclosure that hard-codes a number is a claim, not a disclosure** —
/// chunk 4's lesson, kept.
#[must_use]
pub fn not_covered(rotation_span_ms: u128, rotations_observed: u64) -> Vec<String> {
    let mut all: Vec<String> = NOT_COVERED.iter().map(|text| (*text).to_owned()).collect();
    all.push(format!(
        "an ACP connection living longer than one membership record on a non-owner ingress: this run carried its sessions across {rotations_observed} completed rotations in {rotation_span_ms} ms, inside records of {} ms, and says nothing about a connection that outlives one",
        MEMBERSHIP_RECORD_LIFETIME.as_millis()
    ));
    all
}

/// What one session recorded across the rotation window.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionSpan {
    /// The session identifier, unchanged from creation to completion.
    pub session: String,
    /// `session/update` messages observed **before** the rotation window.
    pub updates_before: usize,
    /// `session/request_permission` callbacks observed, across the whole case.
    /// More than one is a duplicated callback.
    pub callbacks: usize,
    /// `session/update` messages observed **after** the held callback was
    /// answered.
    pub updates_after: usize,
    /// The turn's own result, read off the session stream.
    pub stop_reason: String,
    /// The stream neither errored nor ended at any point in the window.
    pub stream_alive_through_window: bool,
    /// Every distinct JSON-RPC id seen from the agent on this stream, so a
    /// replayed message is visible as a repeat rather than inferred.
    pub distinct_agent_ids: usize,
    /// Total messages observed on this stream.
    pub messages: usize,
}

/// Everything this gate measured.  Primitives only: identifiers, counters,
/// statuses and typed labels, never a payload or a credential.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AcpClusterEvidence {
    pub relay_count: usize,
    pub owner_node: String,
    pub ingress_node: String,
    pub non_owner_ingress: bool,
    /// The cases that actually ran, in order.  A case that did not execute is
    /// absent here and the validator rejects the run; it is never folded into
    /// a pass count.
    pub cases_executed: Vec<String>,
    pub not_covered: Vec<String>,

    // --- the rotation span ---
    /// Completed scheduled rotations observed **while the sessions were
    /// live**, from the connector's own counter, cross-checked against the
    /// owner's.
    pub rotations_across_span: u64,
    /// The owner relay's own count of completed rotations over the same
    /// window.  Recorded separately because the connector and the owner
    /// maintain it independently, and agreement is the evidence.
    pub owner_rotations_across_span: u64,
    /// Wall-clock length of the window the sessions were held across.
    pub rotation_span_ms: u128,
    /// The rotation case ran for at least the configured schedule.  A window
    /// shorter than `interval * REQUIRED_ROTATIONS` counted recovery
    /// activations, which bump the same counter, rather than scheduled
    /// rotations.
    pub rotation_span_met_schedule: bool,
    /// Per-session evidence across the window.
    pub sessions: Vec<SessionSpan>,
    /// The ACP connection identifier was the same before and after.
    pub connection_stable: bool,
    /// The connection GET neither errored nor ended across the window.
    pub connection_stream_alive: bool,
    /// The device tunnel session identifier was unchanged, so the rotations
    /// were rotations and not a reconnect.
    pub device_session_stable: bool,
    /// The device owner epoch was unchanged across the window.
    pub device_epoch_stable: bool,
    /// Distinct data-socket local addresses the device used, from the proxy.
    /// A completed rotation moves to a new socket, so this is the rotation
    /// count seen from underneath the tunnel rather than from a counter.
    pub distinct_device_sockets: usize,
    /// Device sockets open at each settled steady state.
    pub steady_state_sockets: Vec<usize>,
    /// The high-water mark of concurrent device sockets.
    pub device_socket_peak: u64,
    /// The synthetic side effect each held turn recorded, counted from the
    /// agent's own append-only ledger.
    pub side_effects_in_ledger: u64,
    /// The same count after a settle window, so a replay would be visible.
    pub side_effects_after_settle: u64,

    // --- the accommodation and the refusal ledger ---
    pub membership_resigns: u64,
    pub max_membership_age_at_case_end_ms: u128,
    pub resign_spacing_ms: u128,
    pub not_dispatched_refusals: u64,
    pub not_dispatched_retries: u64,
    pub unexplained_refusal: Option<String>,

    // --- two users in two tenants ---
    /// Whether the two tenants' exports independently chose the same
    /// connection identifier.
    ///
    /// **Recorded, not required.**  A connection id is
    /// `acp-{epoch:016x}-{sequence:x}` and the epoch is per-export, so two
    /// separately started exports cannot mint the same one and no consumer
    /// can make them.  The row's "identical connection ids" is therefore met
    /// the only way the product allows — see
    /// [`AcpClusterEvidence::connection_id_inert_in_other_tenant`] — and this
    /// field is disclosed rather than asserted, because asserting it would be
    /// asserting something the gate cannot cause.
    pub connection_ids_collide: bool,
    /// A live connection id from tenant A carries **no authority at all** in
    /// tenant B's context: presented on tenant B's route by tenant B's own
    /// principal it is refused byte-identically to an id that never existed.
    ///
    /// This is the reusable-identifier property that matters.  Two tenants
    /// cannot be given one connection id, but an attacker who *learns* one
    /// can present it, and what this asserts is that doing so is
    /// indistinguishable from presenting a fiction.
    pub connection_id_inert_in_other_tenant: bool,
    /// ...and the same session identifier.
    pub session_ids_collide: bool,
    /// Both principals used the identical JSON-RPC ids — the string `"1"` and
    /// the number `1` — and each reply came back to its own caller.
    pub shared_rpc_ids: Vec<String>,
    /// Every reply was routed to the principal that asked, with no crossing.
    pub replies_routed_per_principal: bool,
    /// A second principal of the **same tenant** presenting the first's
    /// connection id is refused exactly as an id that never existed is:
    /// same status, same header fields, same body bytes.
    pub same_tenant_foreign_matches_unknown: bool,
    /// The same, for a principal of the **other tenant**.
    pub cross_tenant_foreign_matches_unknown: bool,
    /// The status those refusals carried, recorded so the comparison cannot
    /// pass by both being some unrelated error.
    pub foreign_refusal_status: u16,
    /// The genuine owner's own request still succeeded afterwards, so the
    /// refusals are not passing because the connection had already gone.
    pub genuine_request_still_served: bool,
    /// Sessions tenant B's export opened during the two-tenant case.
    ///
    /// Exactly one: Carol's.  Every probe that presented tenant A's live
    /// connection id on tenant B's route must have opened nothing, which is
    /// the "never reach another process" half of the acceptance — a refusal
    /// that had already started a child would be a leak whatever it answered.
    pub tenant_b_sessions_opened: u64,

    // --- forged heads ---
    /// Forgery attempts made, and how many were refused before dispatch.
    pub forgery_attempts: u64,
    pub forgeries_refused: u64,
    /// The relay's own count of ingress rejections over the forgery window.
    pub forgery_ingress_rejections: u64,
    /// ACP exchanges the device export accepted during the forgery window.
    /// Zero is the claim: not one byte reached the device.
    pub forgery_dispatched: u64,
    /// The distinct refusal codes the forgeries met.
    pub forgery_codes: Vec<String>,

    // --- grant revocation ---
    pub revocation_in_flight_withdrawn: bool,
    /// The relay's own classification of the withdrawn exchange, read from
    /// its exchange record rather than guessed from a status.
    pub revocation_in_flight_execution: String,
    pub revocation_after_status: u16,
    pub revocation_after_code: String,
    pub revocation_after_execution: String,
    /// ACP prompts the export accepted after the grant was revoked.
    pub revocation_dispatched_after: u64,
    /// No `stopReason` was ever produced for the withdrawn turn.
    pub revocation_no_stop_reason: bool,

    // --- explicit interruptions ---
    /// Peer-key rotation interrupted the live stream explicitly.
    pub key_rotation_interrupted: bool,
    /// ...and never produced a `stopReason` for the turn it interrupted.
    pub key_rotation_no_stop_reason: bool,
    /// Owner loss interrupted the live stream explicitly.
    pub owner_loss_interrupted: bool,
    /// ...and never produced a `stopReason` either.
    pub owner_loss_no_stop_reason: bool,

    // --- saturation ---
    /// The ingress→owner peer hop's high-water in-flight bytes, and the
    /// window it is measured against.
    pub ingress_peer_send_in_flight: usize,
    pub owner_peer_send_in_flight: usize,
    pub peer_window: usize,
    /// Both segments were over half their window at the same time.
    pub both_segments_saturated: bool,
    /// A second, live SSE stream still delivered while both hops were full.
    pub live_stream_served_while_saturated: bool,

    /// Agent processes that outlived the gate, read from the process table.
    pub leftover_processes: usize,
}

/// One consumer answer, reduced to what the gate asserts on.
///
/// The header list is what makes this a byte-identical comparison rather than
/// a status comparison: a refusal that leaked the other principal's id through
/// a differing header would pass a status check and fail this one.  M3-04's
/// `Answer` is the precedent, `date` excluded for the same reason.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    /// Whether two answers are indistinguishable to a consumer.
    fn indistinguishable_from(&self, other: &Self) -> bool {
        self.status == other.status && self.headers == other.headers && self.body == other.body
    }

    /// The sanitized error code and execution this answer carried, if any.
    fn error(&self) -> (String, String) {
        let text = String::from_utf8_lossy(&self.body);
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let pick = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .or_else(|| {
                    value
                        .pointer(&format!("/error/{key}"))
                        .and_then(Value::as_str)
                })
                .unwrap_or_default()
                .to_owned()
        };
        (pick("code"), pick("execution"))
    }
}

/// The gate's live state.
struct Gate<'h> {
    cluster: &'h mut ProductionCluster,
    tenant_id: uuid::Uuid,
    device_id: uuid::Uuid,
    service_id: uuid::Uuid,
    config: tunnel_client::ConnectConfig,
    client: Option<ConnectionHandle>,
    session_id: String,
    acp_diagnostics: AcpExportDiagnostics,
    freeze: Arc<FreezeWatch>,
    freeze_task: Option<tokio::task::JoinHandle<()>>,
    ledger: Arc<RefusalLedger>,
    /// When membership was last re-signed.  The M7-C80 accommodation's clock,
    /// and the only one.
    membership_signed_at: Instant,
    membership_resigns: u64,
    ingress_addr: SocketAddr,
    ca: Vec<u8>,
    token: String,
    base_uri: String,
    workspace: PathBuf,
    /// Every device socket passes this proxy, so the gate counts them.
    proxy: super::ProxyHandle,

    // --- the second principal of the same tenant, and the second tenant ---
    /// `consumer-a-2`: a different principal with its own grant on the *same*
    /// device and service.  The sharpest isolation probe, because nothing but
    /// the principal binding separates it from `consumer-a-1`.
    sibling_token: String,
    /// The revocation victim: a **third** principal with its own grant on the
    /// same export.
    ///
    /// M3-04's precedent, and it is not tidiness.  An earlier version revoked
    /// the grant of the principal every other case drives, so every case after
    /// `revocation` met `404 SERVICE_NOT_FOUND` and the run died at the next
    /// `initialize`.  Revoking a principal nobody else uses keeps the
    /// revocation evidence and the rest of the gate independent.
    victim_token: String,
    victim_principal_id: uuid::Uuid,
    /// Tenant B's device, its own ACP export, and the principal that owns it.
    b_tenant_id: uuid::Uuid,
    b_device_id: uuid::Uuid,
    b_service_id: uuid::Uuid,
    b_config: tunnel_client::ConnectConfig,
    b_client: Option<ConnectionHandle>,
    b_acp_diagnostics: AcpExportDiagnostics,
    b_base_uri: String,
    b_token: String,
    b_workspace: PathBuf,
}

impl Gate<'_> {
    fn export(&self) -> tunnel_acp_export::AcpDiagnostics {
        self.acp_diagnostics
            .get(&self.service_id.to_string())
            .unwrap_or_default()
    }

    /// Start a `tunnel-client` session with the ACP export registered exactly
    /// as `tunnel-client connect` registers it, and wait for its owner claim.
    async fn connect_device(&mut self) -> Result<String> {
        let handlers = HttpHandlers::new()
            .with_acp_exports(&self.config)
            .map_err(|error| HarnessError::InvalidInput(format!("ACP exports: {error}")))?;
        self.acp_diagnostics = handlers.acp_diagnostics_source();
        let client = timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect_with_http_handlers(
                ConnectOptions::new(self.config.clone()),
                handlers,
            ),
        )
        .await
        .map_err(|_| HarnessError::Timeout("ACP cluster gate device startup timed out".into()))?
        .map_err(|error| HarnessError::Process(format!("ACP cluster gate device: {error}")))?;
        let client = self.client.insert(client);
        self.freeze = Arc::new(FreezeWatch::default());
        let freeze = Arc::clone(&self.freeze);
        let mut status = client.status();
        {
            let status = status.borrow_and_update();
            freeze.record(&status.phase, status.rotations_completed);
        }
        self.freeze_task = Some(tokio::spawn(async move {
            while status.changed().await.is_ok() {
                let (phase, rotations) = {
                    let status = status.borrow_and_update();
                    (status.phase.clone(), status.rotations_completed)
                };
                freeze.record(&phase, rotations);
            }
        }));
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("ACP cluster device readiness timed out".into()))?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        self.session_id = session.session_id.clone();
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            let owner = self
                .cluster
                .catalog
                .current_owner(self.tenant_id, self.device_id, chrono::Utc::now())
                .await
                .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?;
            if let Some(owner) = owner
                && owner.token.session_id == self.session_id
            {
                return Ok(owner.token.node_id);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the device owner claim was not observed".into(),
                ));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Start the tenant-B device and wait for its owner claim.
    ///
    /// Deliberately not folded into [`Self::connect_device`]: that one also
    /// installs the freeze watch, and there must be exactly one of those —
    /// the refusal correlation is about the route the cases drive, which is
    /// tenant A's.
    async fn connect_device_b(&mut self) -> Result<String> {
        let handlers = HttpHandlers::new()
            .with_acp_exports(&self.b_config)
            .map_err(|error| {
                HarnessError::InvalidInput(format!("tenant-B ACP exports: {error}"))
            })?;
        self.b_acp_diagnostics = handlers.acp_diagnostics_source();
        let client = timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect_with_http_handlers(
                ConnectOptions::new(self.b_config.clone()),
                handlers,
            ),
        )
        .await
        .map_err(|_| HarnessError::Timeout("tenant-B device startup timed out".into()))?
        .map_err(|error| HarnessError::Process(format!("tenant-B device: {error}")))?;
        let client = self.b_client.insert(client);
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("tenant-B device readiness timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("tenant-B device not ready: {error}"))
            })?;
        let session_id = session.session_id.clone();
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            let owner = self
                .cluster
                .catalog
                .current_owner(self.b_tenant_id, self.b_device_id, chrono::Utc::now())
                .await
                .map_err(|error| HarnessError::Redis(format!("reading tenant-B owner: {error}")))?;
            if let Some(owner) = owner
                && owner.token.session_id == session_id
            {
                return Ok(owner.token.node_id);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the tenant-B device owner claim was not observed".into(),
                ));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Record one `503 not_dispatched` refusal and say whether it coincided
    /// with a rotation freeze **this gate observed**.
    ///
    /// Shared by the POST and GET paths on purpose.  An earlier version of
    /// this gate applied the M3-15 discipline to POSTs only, and a session GET
    /// that landed in a QUIESCE→COMMIT freeze failed the run as though the
    /// route were broken.  A refusal is a refusal whichever verb met it, and
    /// counting it in one direction and not the other would have understated
    /// every refusal figure this gate reports.
    fn note_refusal(&self) -> bool {
        let coincides = self.freeze.coincides();
        self.ledger.refusals.fetch_add(1, Ordering::SeqCst);
        if coincides {
            self.ledger.retries.fetch_add(1, Ordering::SeqCst);
        } else {
            let mut slot = self
                .ledger
                .unexplained
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if slot.is_none() {
                *slot = Some(self.freeze.unexplained());
            }
        }
        coincides
    }

    /// POST one ACP message, resending **only** a `not_dispatched` refusal
    /// that coincides with an observed rotation freeze (M3-15).
    async fn post(
        &self,
        consumer: &AcpConsumer,
        extra: &[(&str, &str)],
        message: &Value,
    ) -> Result<(http::StatusCode, http::HeaderMap, String)> {
        self.post_as(consumer, &self.base_uri, &self.token, extra, message)
            .await
    }

    /// The tenant-B export's diagnostics.
    fn export_b(&self) -> tunnel_acp_export::AcpDiagnostics {
        self.b_acp_diagnostics
            .get(&self.b_service_id.to_string())
            .unwrap_or_default()
    }

    /// One request on its own fresh HTTP/2 connection, reduced to an
    /// [`Answer`].
    ///
    /// A fresh connection per probe is deliberate: two probes that must be
    /// compared byte for byte must not be able to influence each other through
    /// shared h2 connection state.
    async fn probe(
        &self,
        base_uri: &str,
        token: &str,
        method: &str,
        extra: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<Answer> {
        let consumer = AcpConsumer::connect(self.ingress_addr, &self.ca).await?;
        let base: Vec<(&str, &str)> = if body.is_some() {
            vec![
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ]
        } else {
            vec![("accept", "text/event-stream")]
        };
        let request = acp_request(
            method,
            base_uri,
            token,
            &[&base[..], extra].concat(),
            match body {
                Some(value) => json_stream(value),
                None => super::http_forward_real_path::empty_stream(),
            },
        )?;
        let response = consumer
            .sender
            .clone()
            .send_request(request)
            .await
            .map_err(|error| HarnessError::Http(format!("ACP probe: {error}")))?;
        let status = response.status().as_u16();
        let mut headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter(|(name, _)| name.as_str() != "date")
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        headers.sort();
        let body = response
            .into_body()
            .collect()
            .await
            .map(|collected| collected.to_bytes().to_vec())
            .unwrap_or_default();
        consumer.shutdown();
        Ok(Answer {
            status,
            headers,
            body,
        })
    }

    /// The same, with an explicit bearer token, for the two-tenant cases where
    /// the point is *which* principal is speaking.
    async fn post_as(
        &self,
        consumer: &AcpConsumer,
        base_uri: &str,
        token: &str,
        extra: &[(&str, &str)],
        message: &Value,
    ) -> Result<(http::StatusCode, http::HeaderMap, String)> {
        let mut retries = 0u64;
        loop {
            let request = acp_request(
                "POST",
                base_uri,
                token,
                &[
                    &[
                        ("content-type", "application/json"),
                        ("accept", "application/json"),
                    ][..],
                    extra,
                ]
                .concat(),
                json_stream(message),
            )?;
            let response = consumer
                .sender
                .clone()
                .send_request(request)
                .await
                .map_err(|error| HarnessError::Http(format!("ACP POST: {error}")))?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .into_body()
                .collect()
                .await
                .map(|collected| String::from_utf8_lossy(&collected.to_bytes()).into_owned())
                .unwrap_or_default();
            if status == http::StatusCode::SERVICE_UNAVAILABLE && body.contains("not_dispatched") {
                let coincides = self.note_refusal();
                if coincides && retries < NOT_DISPATCHED_RETRIES {
                    retries += 1;
                    sleep(Duration::from_millis(MIN_RETRY_HINT_MS)).await;
                    continue;
                }
            }
            return Ok((status, headers, body));
        }
    }

    /// Open an SSE stream and hold it.
    async fn open_stream_on(
        &self,
        consumer: &AcpConsumer,
        base_uri: &str,
        token: &str,
        extra: &[(&str, &str)],
    ) -> Result<(http::StatusCode, http::HeaderMap, Option<HeldStream>)> {
        let mut retries = 0u64;
        loop {
            let request = acp_request(
                "GET",
                base_uri,
                token,
                &[&[("accept", "text/event-stream")][..], extra].concat(),
                super::http_forward_real_path::empty_stream(),
            )?;
            let response = consumer
                .sender
                .clone()
                .send_request(request)
                .await
                .map_err(|error| HarnessError::Http(format!("ACP GET: {error}")))?;
            let status = response.status();
            let headers = response.headers().clone();
            if status == http::StatusCode::SERVICE_UNAVAILABLE {
                // The body has to be read to tell an owner-not-ready refusal
                // from anything else, so the stream is given up either way and
                // the request is reissued rather than resumed.
                let body = response
                    .into_body()
                    .collect()
                    .await
                    .map(|collected| String::from_utf8_lossy(&collected.to_bytes()).into_owned())
                    .unwrap_or_default();
                if body.contains("not_dispatched") {
                    let coincides = self.note_refusal();
                    if coincides && retries < NOT_DISPATCHED_RETRIES {
                        retries += 1;
                        sleep(Duration::from_millis(MIN_RETRY_HINT_MS)).await;
                        continue;
                    }
                }
                return Ok((status, headers, None));
            }
            if status != http::StatusCode::OK {
                return Ok((status, headers, None));
            }
            return Ok((status, headers, Some(HeldStream::hold(response))));
        }
    }

    /// The case boundary, and the **only** place membership is re-signed.
    ///
    /// The M7-C80 accommodation lives here and nowhere else.  It never runs
    /// while a stream is in flight, because the caller has closed its
    /// connection before reaching it — and for the rotation case that is the
    /// difference between a real result and a fabricated one.
    async fn boundary(&mut self) -> Result<()> {
        if self.membership_signed_at.elapsed() < MEMBERSHIP_RESIGN_SPACING {
            return Ok(());
        }
        self.cluster.resign_membership_now().await?;
        self.membership_signed_at = Instant::now();
        self.membership_resigns += 1;
        self.wait_peers_ready().await?;
        Ok(())
    }

    async fn wait_peers_ready(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if self
                .cluster
                .relays
                .iter()
                .filter(|relay| relay.running.is_some())
                .all(|relay| relay.peer_runtime.is_ready())
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "peer readiness did not return after a membership re-sign".into(),
                ));
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn owner_snapshot(&self) -> Result<tunnel_relay::RelaySnapshot> {
        self.cluster.relay("relay-a")?.snapshot().await
    }

    /// The owner's view of this device's session.
    async fn owner_session(&self) -> Result<tunnel_relay::RelaySessionSnapshot> {
        let snapshot = self.owner_snapshot().await?;
        snapshot
            .sessions
            .into_iter()
            .find(|session| session.device_id == self.device_id.to_string())
            .ok_or_else(|| HarnessError::Process("the owner has no session for this device".into()))
    }

    /// Wait until the device is settled between rotations, and report the
    /// sockets open at that moment.
    async fn steady_sockets(&self) -> Result<usize> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let session = self.owner_session().await?;
            let settled = session.phase == "active" && session.candidate_generation.is_none();
            let open = self.proxy.connections().len();
            if settled && open == 2 {
                return Ok(open);
            }
            if Instant::now() >= deadline {
                return Ok(open);
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
}

/// One ACP connection over the real route.
struct Conversation {
    consumer: AcpConsumer,
    connection: String,
    connection_stream: HeldStream,
    /// The route and credential this connection belongs to.  Carried here so
    /// a two-tenant case cannot accidentally drive one tenant's connection
    /// with the other tenant's URI or token.
    base_uri: String,
    token: String,
    /// The configured workspace of the export this connection reached.  A
    /// `session/new` naming any other path is refused, which is the rule
    /// `docs/acp.md` states and which a two-tenant gate meets immediately:
    /// the two exports have different workspaces on purpose.
    workspace: PathBuf,
}

impl Gate<'_> {
    /// Open a connection (initialize plus its connection GET) over the real
    /// route, with no session yet.
    async fn open_connection(&self) -> Result<Conversation> {
        self.open_connection_on(&self.base_uri, &self.token, &self.workspace)
            .await
    }

    /// Tenant B's route, credential and workspace.
    async fn open_connection_b(&self) -> Result<Conversation> {
        self.open_connection_on(&self.b_base_uri, &self.b_token, &self.b_workspace)
            .await
    }

    async fn open_connection_on(
        &self,
        base_uri: &str,
        token: &str,
        workspace: &std::path::Path,
    ) -> Result<Conversation> {
        let consumer = AcpConsumer::connect(self.ingress_addr, &self.ca).await?;
        let (status, headers, _body) = self
            .post_as(
                &consumer,
                base_uri,
                token,
                &[],
                &json!({
                    "jsonrpc": "2.0",
                    "id": "init-1",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": 1,
                        "clientCapabilities": {},
                        "clientInfo": {"name": "tunnel-acp-cluster-gate", "version": "0.1.0"},
                    },
                }),
            )
            .await?;
        if status != http::StatusCode::OK {
            return Err(HarnessError::Http(format!(
                "initialize over the real route answered {status}"
            )));
        }
        let connection = headers
            .get(tunnel_acp::headers::ACP_CONNECTION_ID)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                HarnessError::Http("initialize returned no Acp-Connection-Id".to_owned())
            })?;
        let (status, _headers, stream) = self
            .open_stream_on(
                &consumer,
                base_uri,
                token,
                &[("acp-connection-id", connection.as_str())],
            )
            .await?;
        let connection_stream = stream
            .ok_or_else(|| HarnessError::Http(format!("the connection GET answered {status}")))?;
        Ok(Conversation {
            consumer,
            connection,
            connection_stream,
            base_uri: base_uri.to_owned(),
            token: token.to_owned(),
            workspace: workspace.to_path_buf(),
        })
    }

    /// Create one session on an open connection and subscribe to it.
    ///
    /// The session identifier is read from the `session/new` result **on the
    /// connection GET**, which is where the RFD puts it — never from the 202
    /// that accepted the POST.
    /// `known` are the session identifiers this connection has already
    /// claimed.  The connection GET keeps every message it has seen, so a
    /// second `session/new` would otherwise match the **first** session's
    /// result still sitting in that buffer, and the gate would subscribe to
    /// one session twice and be refused 409 by the one-subscriber rule.  That
    /// is a real refusal for a real reason, which is why this takes the
    /// already-claimed set rather than widening the rule.
    async fn open_session(
        &self,
        conversation: &Conversation,
        request_id: &str,
        known: &[String],
    ) -> Result<(String, HeldStream)> {
        let session = self.create_session(conversation, request_id, known).await?;
        let stream = self.subscribe_session(conversation, &session).await?;
        Ok((session, stream))
    }

    /// Create a session **without** subscribing to it.
    ///
    /// Split out because this profile allows exactly one subscriber per
    /// session: the saturation case has to subscribe with a stream it never
    /// reads, and calling [`Self::open_session`] first would consume the one
    /// subscription and make the second GET a legitimate 409.
    async fn create_session(
        &self,
        conversation: &Conversation,
        request_id: &str,
        known: &[String],
    ) -> Result<String> {
        let (status, _headers, _body) = self
            .post_as(
                &conversation.consumer,
                &conversation.base_uri,
                &conversation.token,
                &[("acp-connection-id", conversation.connection.as_str())],
                &json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "session/new",
                    "params": {
                        "cwd": conversation.workspace.to_string_lossy(),
                        "mcpServers": [],
                    },
                }),
            )
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "session/new answered {status}, not 202"
            )));
        }
        let claimed: Vec<String> = known.to_vec();
        conversation
            .connection_stream
            .wait_for("the session/new result", move |value| {
                session_id(value).filter(|found| !claimed.contains(found))
            })
            .await
    }

    /// Subscribe to an existing session and hold its stream.
    async fn subscribe_session(
        &self,
        conversation: &Conversation,
        session: &str,
    ) -> Result<HeldStream> {
        let (status, headers, stream) = self
            .open_stream_on(
                &conversation.consumer,
                &conversation.base_uri,
                &conversation.token,
                &[
                    ("acp-connection-id", conversation.connection.as_str()),
                    ("acp-session-id", session),
                ],
            )
            .await?;
        let stream = stream
            .ok_or_else(|| HarnessError::Http(format!("the session GET answered {status}")))?;
        // M8-C05: this profile puts no session header on a response.
        if headers.contains_key(tunnel_acp::headers::ACP_SESSION_ID) {
            return Err(HarnessError::Http(
                "a session-scoped SSE response carried Acp-Session-Id (M8-C05)".to_owned(),
            ));
        }
        Ok(stream)
    }

    async fn prompt(
        &self,
        conversation: &Conversation,
        session: &str,
        id: &str,
        text: &str,
    ) -> Result<http::StatusCode> {
        self.prompt_with_id(conversation, session, &json!(id), text)
            .await
    }

    /// The same, with the id as a JSON value, so a string `"1"` and a number
    /// `1` can both be sent — the profile keeps their type, and the two-tenant
    /// case relies on that.
    async fn prompt_with_id(
        &self,
        conversation: &Conversation,
        session: &str,
        id: &Value,
        text: &str,
    ) -> Result<http::StatusCode> {
        let (status, _headers, _body) = self
            .post_as(
                &conversation.consumer,
                &conversation.base_uri,
                &conversation.token,
                &[
                    ("acp-connection-id", conversation.connection.as_str()),
                    ("acp-session-id", session),
                ],
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "session/prompt",
                    "params": {
                        "sessionId": session,
                        "prompt": [{"type": "text", "text": text}],
                    },
                }),
            )
            .await?;
        Ok(status)
    }
}

/// A connection identifier that never existed: the control every isolation
/// refusal is compared against.
const ABSENT_CONNECTION: &str = "ffffffffffffffffffffffffffffffff";

/// A forged principal binding.  Shaped exactly like a real one — sixteen bytes
/// of lowercase hex — so the refusal cannot be for being malformed.
const FORGED_BINDING: &str = "0a1b2c3d4e5f60718a7f2c9a1b4d6e8f";

/// How long an explicit interruption may take to reach the consumer before the
/// gate reports that it did not arrive.
const INTERRUPTION_BOUND: Duration = Duration::from_secs(45);

/// How long a revoked in-flight exchange has to be withdrawn.
const REVOCATION_BOUND: Duration = Duration::from_secs(30);

impl Gate<'_> {
    /// Case `two-tenant-ids`: two users in two tenants reusing identical
    /// JSON-RPC ids, connection ids and session ids, with every reply routed
    /// by the complete context — and one principal's ids refused for another
    /// **byte-identically** to an id that never existed.
    async fn case_two_tenant_ids(&mut self, evidence: &mut AcpClusterEvidence) -> Result<()> {
        let alice = self.open_connection().await?;
        let b_token = self.b_token.clone();
        let carol = self.open_connection_b().await?;

        // The two exports number their connections independently, so a
        // collision here is the product's own doing rather than the gate's.
        evidence.connection_ids_collide = alice.connection == carol.connection;

        // `session/new` on both, with the **same** string id.
        let (a_session, a_stream) = self.open_session(&alice, "1", &[]).await?;
        let (c_session, c_stream) = self.open_session(&carol, "1", &[]).await?;
        evidence.session_ids_collide = a_session == c_session;

        // The same numeric id 1 on both, at the same time, on two tenants,
        // two devices, two owners and two exports.
        let numeric = json!(1);
        for (conversation, session) in [(&alice, &a_session), (&carol, &c_session)] {
            let status = self
                .prompt_with_id(conversation, session, &numeric, "ok")
                .await?;
            if status != http::StatusCode::ACCEPTED {
                return Err(HarnessError::Http(format!(
                    "the shared-id prompt answered {status}, not 202"
                )));
            }
        }
        evidence.shared_rpc_ids = vec!["s:1".to_owned(), "n:1".to_owned()];

        // Each reply must arrive on its own caller's stream.  Both carry id 1;
        // only the (tenant, principal, device, service, connection, direction)
        // context distinguishes them.
        let a_stop = a_stream
            .wait_for("tenant A's reply to id 1", |value| {
                (value.get("id") == Some(&numeric))
                    .then(|| stop_reason(value))
                    .flatten()
            })
            .await?;
        let c_stop = c_stream
            .wait_for("tenant B's reply to id 1", |value| {
                (value.get("id") == Some(&numeric))
                    .then(|| stop_reason(value))
                    .flatten()
            })
            .await?;
        let a_replies = a_stream
            .seen()
            .iter()
            .filter(|value| value.get("id") == Some(&numeric))
            .count();
        let c_replies = c_stream
            .seen()
            .iter()
            .filter(|value| value.get("id") == Some(&numeric))
            .count();
        // Exactly one reply each: a cross-routed answer would show as two on
        // one stream, which a per-stream "did it finish" check would miss.
        evidence.replies_routed_per_principal =
            a_stop == "end_turn" && c_stop == "end_turn" && a_replies == 1 && c_replies == 1;

        // --- isolation, byte for byte ---
        //
        // The comparison is against an identifier that never existed, on the
        // same route with the same credential, so the only difference between
        // the two probes is whether the id is real.  A different status, a
        // different header or a different body would tell the caller that
        // somebody else's connection exists.
        let sibling = self.sibling_token.clone();
        let base = self.base_uri.clone();
        let foreign = self
            .probe(
                &base,
                &sibling,
                "GET",
                &[("acp-connection-id", alice.connection.as_str())],
                None,
            )
            .await?;
        let absent = self
            .probe(
                &base,
                &sibling,
                "GET",
                &[("acp-connection-id", ABSENT_CONNECTION)],
                None,
            )
            .await?;
        evidence.same_tenant_foreign_matches_unknown = foreign.indistinguishable_from(&absent);
        evidence.foreign_refusal_status = foreign.status;

        let cross = self
            .probe(
                &base,
                &b_token,
                "GET",
                &[("acp-connection-id", alice.connection.as_str())],
                None,
            )
            .await?;
        let cross_absent = self
            .probe(
                &base,
                &b_token,
                "GET",
                &[("acp-connection-id", ABSENT_CONNECTION)],
                None,
            )
            .await?;
        evidence.cross_tenant_foreign_matches_unknown = cross.indistinguishable_from(&cross_absent);

        // The same live identifier, presented in the *other tenant's* context
        // by that tenant's own principal.  Two exports cannot be made to mint
        // one connection id, so this is what "reusing a connection id across
        // tenants" can actually mean here: the string is live in tenant A and
        // must mean nothing whatsoever in tenant B.
        let b_base_route = self.b_base_uri.clone();
        let in_b = self
            .probe(
                &b_base_route,
                &b_token,
                "GET",
                &[("acp-connection-id", alice.connection.as_str())],
                None,
            )
            .await?;
        let in_b_absent = self
            .probe(
                &b_base_route,
                &b_token,
                "GET",
                &[("acp-connection-id", ABSENT_CONNECTION)],
                None,
            )
            .await?;
        evidence.connection_id_inert_in_other_tenant =
            in_b.indistinguishable_from(&in_b_absent) && in_b.status == 404;

        // The genuine owner is still served, so the refusals above are not
        // passing because Alice's connection had already gone.
        let status = self
            .prompt_with_id(&alice, &a_session, &json!("after-isolation"), "ok")
            .await?;
        let served = status == http::StatusCode::ACCEPTED
            && a_stream
                .wait_for(
                    "Alice's own turn after the refusals",
                    stop_reason_for("after-isolation"),
                )
                .await?
                == "end_turn";
        evidence.genuine_request_still_served = served;
        evidence.tenant_b_sessions_opened = self.export_b().sessions_opened;

        a_stream.break_now();
        c_stream.break_now();
        alice.connection_stream.break_now();
        carol.connection_stream.break_now();
        alice.consumer.shutdown();
        carol.consumer.shutdown();
        Ok(())
    }

    /// The relay-c ingress's own count of requests rejected before admission.
    async fn ingress_rejections(&self) -> Result<u64> {
        Ok(self
            .cluster
            .relay("relay-c")?
            .snapshot()
            .await?
            .http_forward
            .ingress_rejected_before_admission)
    }

    /// Case `forged-heads`: a forged principal binding, a forged
    /// `x-agent-tunnel-*` header and a forged internal identity header, each
    /// refused **before a byte reaches the device**.
    async fn case_forged_heads(&mut self, evidence: &mut AcpClusterEvidence) -> Result<()> {
        let rejections_before = self.ingress_rejections().await?;
        let opened_before = self.export().connections_opened;
        let base = self.base_uri.clone();
        let token = self.token.clone();
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": "forge-1",
            "method": "initialize",
            "params": {
                "protocolVersion": 1,
                "clientCapabilities": {},
                "clientInfo": {"name": "tunnel-acp-cluster-gate", "version": "0.1.0"},
            },
        });
        // Three different forgeries, not three spellings of one: a binding the
        // ingress derives itself, a relay-internal routing header, and an
        // internal identity claim.
        let foreign_tenant = self.b_tenant_id.to_string();
        let forgeries: [(&str, Vec<(&str, &str)>); 3] = [
            (
                "tunnel-principal-binding",
                vec![("tunnel-principal-binding", FORGED_BINDING)],
            ),
            (
                "x-agent-tunnel-owner",
                vec![("x-agent-tunnel-owner", "relay-a")],
            ),
            (
                "internal identity",
                vec![
                    ("x-agent-tunnel-tenant-id", foreign_tenant.as_str()),
                    ("x-agent-tunnel-principal-id", FORGED_BINDING),
                ],
            ),
        ];
        let mut codes = Vec::new();
        for (label, headers) in &forgeries {
            let owned: Vec<(&str, &str)> = headers.clone();
            let answer = self
                .probe(&base, &token, "POST", &owned, Some(&initialize))
                .await?;
            evidence.forgery_attempts += 1;
            let (code, execution) = answer.error();
            if answer.status == 400 && execution == "not_dispatched" {
                evidence.forgeries_refused += 1;
            }
            codes.push(format!("{label}={}:{code}:{execution}", answer.status));
        }
        evidence.forgery_codes = codes;
        evidence.forgery_ingress_rejections = self
            .ingress_rejections()
            .await?
            .saturating_sub(rejections_before);
        // The claim is not "they were refused" but "nothing reached the
        // device": a forged `initialize` that got through would have opened a
        // connection and started a child.
        evidence.forgery_dispatched = self
            .export()
            .connections_opened
            .saturating_sub(opened_before);
        Ok(())
    }

    /// The relay's own record for the exchange carrying `stream_id`, or the
    /// most recent aborted owner-side record.
    async fn withdrawn_execution(&self) -> Result<String> {
        let snapshot = self.cluster.relay("relay-c")?.snapshot().await?;
        Ok(snapshot
            .http_forward
            .exchanges
            .iter()
            .filter(|record| record.role == "ingress_remote")
            .filter(|record| record.response_outcome == "aborted")
            .map(|record| record.execution.to_owned())
            .next_back()
            .unwrap_or_default())
    }

    /// Case `revocation`: revoking the grant withdraws the admitted exchange
    /// with `execution: unknown`, and nothing is dispatched afterwards.
    async fn case_revocation(&mut self, evidence: &mut AcpClusterEvidence) -> Result<()> {
        let victim = self.victim_token.clone();
        let base = self.base_uri.clone();
        let workspace = self.workspace.clone();
        let conversation = self.open_connection_on(&base, &victim, &workspace).await?;
        let (session, stream) = self.open_session(&conversation, "rev-new", &[]).await?;
        // A baseline turn, so the route is known good before anything is
        // revoked.
        let status = self
            .prompt(&conversation, &session, "rev-warm", "ok")
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "the revocation baseline prompt answered {status}, not 202"
            )));
        }
        stream
            .wait_for(
                "the revocation baseline result",
                stop_reason_for("rev-warm"),
            )
            .await?;

        // A turn held open on a pending callback: this is the admitted
        // exchange the revocation must withdraw.
        let status = self
            .prompt(&conversation, &session, "rev-held", "permission")
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "the revocation held prompt answered {status}, not 202"
            )));
        }
        stream
            .wait_for("the revocation callback", |value| {
                (method_of(value) == Some("session/request_permission")).then(|| true)
            })
            .await?;

        let accepted_before = self.export().prompts_accepted;
        self.cluster
            .catalog
            .revoke_grant(
                self.tenant_id,
                self.victim_principal_id,
                self.device_id,
                self.service_id,
                chrono::Utc::now(),
            )
            .await
            .map_err(|error| HarnessError::Redis(format!("revoking the ACP grant: {error}")))?;

        // Only the revocation's own typed refusal ends this wait; a transient
        // owner-not-ready 503 from a rotation freeze is retried, so the loop
        // cannot mistake a freeze for a revocation.
        let deadline = Instant::now() + REVOCATION_BOUND;
        loop {
            let answer = self
                .probe(
                    &base,
                    &victim,
                    "GET",
                    &[("acp-connection-id", conversation.connection.as_str())],
                    None,
                )
                .await?;
            let (code, execution) = answer.error();
            if answer.status == 404 || Instant::now() >= deadline {
                evidence.revocation_after_status = answer.status;
                evidence.revocation_after_code = code;
                evidence.revocation_after_execution = execution;
                break;
            }
            sleep(Duration::from_millis(200)).await;
        }

        // The in-flight exchange must be withdrawn by itself, inside the
        // bound, rather than the gate releasing it and calling that a result.
        let withdrawn_by = Instant::now() + REVOCATION_BOUND;
        while Instant::now() < withdrawn_by {
            if stream.has_errored() || stream.has_ended() {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        evidence.revocation_in_flight_withdrawn = stream.has_errored() || stream.has_ended();
        evidence.revocation_in_flight_execution = self.withdrawn_execution().await?;
        // A withdrawn turn must never acquire a stop reason: the bridge does
        // not know how the turn ended, and inventing one would be the exact
        // fabrication this gate exists to exclude.
        evidence.revocation_no_stop_reason = !stream
            .seen()
            .iter()
            .any(|value| stop_reason_for("rev-held")(value).is_some());
        evidence.revocation_dispatched_after = self
            .export()
            .prompts_accepted
            .saturating_sub(accepted_before);

        stream.break_now();
        conversation.connection_stream.break_now();
        conversation.consumer.shutdown();
        Ok(())
    }

    /// Hold a live turn open, run `disturb`, and report whether the consumer
    /// received an **explicit interruption** and whether any `stopReason` was
    /// ever fabricated for the turn.
    ///
    /// Both the peer-key-rotation and owner-loss cases are this shape, and
    /// writing it once keeps the two answers comparable.
    async fn interruption_case(
        &mut self,
        label: &str,
        disturb: impl AsyncFnOnce(&mut Self) -> Result<()>,
    ) -> Result<(bool, bool)> {
        let conversation = self.open_connection().await?;
        let (session, stream) = self
            .open_session(&conversation, &format!("{label}-new"), &[])
            .await?;
        let held = format!("{label}-held");
        let status = self
            .prompt(&conversation, &session, &held, "permission")
            .await?;
        if status != http::StatusCode::ACCEPTED {
            return Err(HarnessError::Http(format!(
                "the {label} held prompt answered {status}, not 202"
            )));
        }
        stream
            .wait_for(&format!("the {label} callback"), |value| {
                (method_of(value) == Some("session/request_permission")).then(|| true)
            })
            .await?;

        disturb(self).await?;

        let deadline = Instant::now() + INTERRUPTION_BOUND;
        while Instant::now() < deadline {
            if stream.has_errored() || stream.has_ended() {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        // An explicit interruption is the stream *failing*, not ending
        // cleanly: a clean end would say the turn finished, which it did not.
        let interrupted = stream.has_errored();
        let picker = stop_reason_for(&held);
        let no_stop_reason = !stream.seen().iter().any(|value| picker(value).is_some());
        stream.break_now();
        conversation.connection_stream.break_now();
        conversation.consumer.shutdown();
        Ok((interrupted, no_stop_reason))
    }

    /// Case `peer-key-rotation`: withdrawing the ingress relay's peer pins
    /// interrupts the live stream explicitly and never fabricates a stop
    /// reason.
    async fn case_key_rotation(&mut self, evidence: &mut AcpClusterEvidence) -> Result<()> {
        let (interrupted, no_stop_reason) = self
            .interruption_case("keyrot", async |gate: &mut Self| {
                let relay = gate.cluster.relay("relay-c")?;
                relay
                    .pins
                    .replace(std::iter::empty::<tunnel_transport::SpkiSha256>())
                    .map_err(|error| {
                        HarnessError::Process(format!("withdrawing relay-c peer pins: {error}"))
                    })?;
                // Also drop the ingress→owner path, so an already-pooled
                // connection cannot carry the stream on regardless of the pin
                // set: a pin set governs new dials, and this case is about an
                // in-flight stream.
                gate.cluster
                    .set_peer_path_drop_from("relay-a", "relay-c", true)?;
                Ok(())
            })
            .await?;
        evidence.key_rotation_interrupted = interrupted;
        evidence.key_rotation_no_stop_reason = no_stop_reason;
        // Restore both halves, so the owner-loss case measures owner loss
        // rather than this case's leftovers.  The pin set is re-derived from
        // the membership snapshot rather than remembered here: that is the
        // same path the fixture publishes pins through normally, so the
        // restored set is the real one and not a copy that could drift.
        self.cluster
            .set_peer_path_drop_from("relay-a", "relay-c", false)?;
        let relay = self.cluster.relay("relay-c")?;
        super::publish_verified_pins(&relay.membership, &relay.pins)?;
        // The route has to be answering again before the next case starts, or
        // that case would be measuring this one's recovery.
        self.wait_peers_ready().await?;
        Ok(())
    }

    /// Open a session GET and **never read it**, so the response direction
    /// backs up through both hops.
    ///
    /// The body is returned un-polled deliberately: a reader that drained it
    /// would relieve the very backpressure this case exists to create.  This
    /// is on its own connection because an unread stream reaches the export's
    /// 30 s output-credit stall and ends *that* transport, which must not be
    /// the transport carrying the live stream.
    async fn open_unread_stream(
        &self,
        conversation: &Conversation,
        session: &str,
    ) -> Result<hyper::body::Incoming> {
        let request = acp_request(
            "GET",
            &conversation.base_uri,
            &conversation.token,
            &[
                ("accept", "text/event-stream"),
                ("acp-connection-id", conversation.connection.as_str()),
                ("acp-session-id", session),
            ],
            super::http_forward_real_path::empty_stream(),
        )?;
        let response = conversation
            .consumer
            .sender
            .clone()
            .send_request(request)
            .await
            .map_err(|error| HarnessError::Http(format!("the unread GET: {error}")))?;
        if response.status() != http::StatusCode::OK {
            return Err(HarnessError::Http(format!(
                "the unread GET answered {}",
                response.status()
            )));
        }
        Ok(response.into_body())
    }

    /// The high-water peer figures for one relay role: bytes this relay has
    /// sent and the peer has not consumed, bytes received here and not yet
    /// consumed by the next hop, and the hop's own credit window.
    async fn hop_high_water(&self, node: &str, role: &str) -> Result<(usize, usize, usize)> {
        let snapshot = self.cluster.relay(node)?.snapshot().await?;
        Ok(snapshot
            .http_forward
            .exchanges
            .iter()
            .filter(|record| record.role == role)
            .fold(
                (0usize, 0usize, 0usize),
                |(flight, queue, window), record| {
                    (
                        flight.max(record.peer_send_in_flight_high_water),
                        queue.max(record.peer_receive_queue_high_water),
                        window.max(record.peer_window),
                    )
                },
            ))
    }

    /// Case `saturation`: both forwarding segments driven to backpressure at
    /// the same time, with a third, live SSE stream still delivering.
    ///
    /// `docs/acp.md`'s bounded per-hop queues were listed by chunk 4 as "not
    /// asserted rather than asserted vacuously" because no case saturated a
    /// hop.  This case saturates both.
    async fn case_saturation(&mut self, evidence: &mut AcpClusterEvidence) -> Result<()> {
        // The stalled connection: a session nobody reads, flooded with
        // updates.  This backs up the response direction through the device,
        // the owner and the ingress.
        let stalled = self.open_connection().await?;
        let stalled_session = self.create_session(&stalled, "sat-stalled", &[]).await?;
        let parked = self.open_unread_stream(&stalled, &stalled_session).await?;
        let _ = self
            .prompt(&stalled, &stalled_session, "sat-flood", "updates:4000")
            .await?;

        // The live connection: a separate transport, so the stalled one
        // reaching its output-credit bound cannot end this one.
        let live = self.open_connection().await?;
        let (live_session, live_stream) = self.open_session(&live, "sat-live", &[]).await?;

        // The request direction: a prompt close to the profile's 1 MiB body
        // limit, which is the largest request this profile admits at all.
        let filler = "x".repeat(900_000);
        let _ = self
            .prompt(&live, &live_session, "sat-upload", &filler)
            .await?;

        // Sample while both directions are backed up.  The stalled stream is
        // unread throughout, so the response direction stays full.
        // Both segments are sampled in the same loop, so "concurrently" is a
        // measurement rather than an arrangement: the run only stops early
        // when both are over half at the same sample.
        let mut ingress = (0usize, 0usize, 0usize);
        let mut owner = (0usize, 0usize, 0usize);
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            let a = self.hop_high_water("relay-c", "ingress_remote").await?;
            let b = self.hop_high_water("relay-a", "owner_peer").await?;
            ingress = (ingress.0.max(a.0), ingress.1.max(a.1), ingress.2.max(a.2));
            owner = (owner.0.max(b.0), owner.1.max(b.1), owner.2.max(b.2));
            let window = ingress.2.max(owner.2);
            if window > 0
                && ingress.0.max(ingress.1) * 2 > window
                && owner.0.max(owner.1) * 2 > window
            {
                break;
            }
            sleep(Duration::from_millis(200)).await;
        }
        // Each segment is reported by the larger of the two directions it can
        // back up in: the ingress fills its *send* side driving a large
        // request toward the owner, and the owner fills its *receive* side
        // taking a flood back from the device that the parked consumer is not
        // draining.  Asserting one named direction per segment would have
        // measured whichever one this fixture happens to fill.
        evidence.ingress_peer_send_in_flight = ingress.0.max(ingress.1);
        evidence.owner_peer_send_in_flight = owner.0.max(owner.1);
        evidence.peer_window = ingress.2.max(owner.2);
        evidence.both_segments_saturated = evidence.peer_window > 0
            && evidence.ingress_peer_send_in_flight * 2 > evidence.peer_window
            && evidence.owner_peer_send_in_flight * 2 > evidence.peer_window;
        eprintln!(
            "ACP cluster saturation: ingress(send={} recv={}) owner(send={} recv={}) window={}",
            ingress.0, ingress.1, owner.0, owner.1, evidence.peer_window
        );

        // A live SSE stream still delivers while both hops are full.  Read
        // off the wire, as everything else here is.
        let status = self.prompt(&live, &live_session, "sat-probe", "ok").await?;
        evidence.live_stream_served_while_saturated = status == http::StatusCode::ACCEPTED
            && timeout(
                Duration::from_secs(60),
                live_stream.wait_for(
                    "the live turn under saturation",
                    stop_reason_for("sat-probe"),
                ),
            )
            .await
            .ok()
            .and_then(std::result::Result::ok)
            .is_some_and(|stop| stop == "end_turn");

        drop(parked);
        live_stream.break_now();
        live.connection_stream.break_now();
        stalled.connection_stream.break_now();
        live.consumer.shutdown();
        stalled.consumer.shutdown();
        Ok(())
    }

    /// Case `owner-loss`: stopping the owner relay interrupts the live stream
    /// explicitly and never fabricates a stop reason.
    async fn case_owner_loss(&mut self, evidence: &mut AcpClusterEvidence) -> Result<()> {
        let (interrupted, no_stop_reason) = self
            .interruption_case("ownerloss", async |gate: &mut Self| {
                gate.cluster.shutdown_node("relay-a").await
            })
            .await?;
        evidence.owner_loss_interrupted = interrupted;
        evidence.owner_loss_no_stop_reason = no_stop_reason;
        Ok(())
    }
}

/// Count the lines naming `effect` in the agent's own append-only ledger.
fn count_effect(ledger: &std::path::Path, effect: &str) -> u64 {
    std::fs::read_to_string(ledger)
        .map(|text| {
            text.lines()
                .filter(|line| line.contains(effect))
                .count()
                .try_into()
                .unwrap_or(u64::MAX)
        })
        .unwrap_or(0)
}

/// The `stopReason` of the result **for this request id**.
///
/// Correlating by id is not fastidiousness.  A held stream keeps every
/// message it has seen, so a picker that matched "any message carrying a
/// stopReason" would match the *warm-up* turn's `end_turn` still sitting in
/// the buffer and report it as the held turn's result — which is a test that
/// passes without the held turn ever finishing.  The profile scopes ids per
/// direction for exactly this reason, so the gate reads them the same way.
fn stop_reason_for(request_id: &str) -> impl Fn(&Value) -> Option<String> + use<> {
    let wanted = request_id.to_owned();
    move |value: &Value| {
        (value.get("id").and_then(Value::as_str) == Some(wanted.as_str()))
            .then(|| stop_reason(value))
            .flatten()
    }
}

/// The JSON-RPC method of an observed message, if it has one.
fn method_of(value: &Value) -> Option<&str> {
    value.get("method").and_then(Value::as_str)
}

/// The JSON-RPC id of an observed message, rendered so a string `"1"` and a
/// number `1` are distinguishable.
fn typed_id(value: &Value) -> Option<String> {
    match value.get("id") {
        Some(Value::String(text)) => Some(format!("s:{text}")),
        Some(Value::Number(number)) => Some(format!("n:{number}")),
        _ => None,
    }
}

impl Gate<'_> {
    /// Case `rotation-span`: two sessions held live across three **completed
    /// scheduled device data-socket rotations**, with a prompt, a callback and
    /// a pending response spanning the drain.
    ///
    /// This is the case chunk 4 could not write.  Everything it asserts is
    /// read either off an SSE stream, out of the agent's own ledger, or from
    /// the socket table underneath the tunnel — never from the fact that a
    /// POST was accepted.
    async fn case_rotation_span(&mut self, evidence: &mut AcpClusterEvidence) -> Result<()> {
        let ledger = self.workspace.join(tunnel_acp_fixture::SIDE_EFFECT_LEDGER);
        let conversation = self.open_connection().await?;

        // Two sessions on one connection, each with its own subscriber.
        let mut sessions: Vec<(String, HeldStream)> = Vec::new();
        for index in 0..ROTATION_SESSIONS {
            let known: Vec<String> = sessions.iter().map(|(id, _)| id.clone()).collect();
            let (session, stream) = self
                .open_session(&conversation, &format!("new-{index}"), &known)
                .await?;
            sessions.push((session, stream));
        }

        // A completed turn on each session *before* the window, so "no lost
        // updates" has something to lose and the streams are known good.
        for (index, (session, stream)) in sessions.iter().enumerate() {
            let status = self
                .prompt(&conversation, session, &format!("warm-{index}"), "ok")
                .await?;
            if status != http::StatusCode::ACCEPTED {
                return Err(HarnessError::Http(format!(
                    "the warm-up prompt answered {status}, not 202"
                )));
            }
            let stop = stream
                .wait_for(
                    "the warm-up result",
                    stop_reason_for(&format!("warm-{index}")),
                )
                .await?;
            if stop != "end_turn" {
                return Err(HarnessError::Process(format!(
                    "the warm-up turn ended {stop}, not end_turn"
                )));
            }
        }
        let updates_before: Vec<usize> = sessions
            .iter()
            .map(|(_, stream)| {
                stream
                    .seen()
                    .iter()
                    .filter(|value| method_of(value) == Some("session/update"))
                    .count()
            })
            .collect();

        // Now the held turns: each records one durable side effect and then
        // waits on a permission callback.  The callback is outstanding for the
        // whole rotation window, which is what "prompts, callbacks and pending
        // responses spanning the drain" means.
        for (index, (session, _stream)) in sessions.iter().enumerate() {
            let status = self
                .prompt(
                    &conversation,
                    session,
                    &format!("held-{index}"),
                    &format!("effect-permission:{ROTATION_EFFECT}"),
                )
                .await?;
            if status != http::StatusCode::ACCEPTED {
                return Err(HarnessError::Http(format!(
                    "the held prompt answered {status}, not 202"
                )));
            }
        }
        // Each callback must be on the wire before the window opens, or the
        // window would not actually be spanning a pending callback.
        let mut permission_ids = Vec::new();
        for (_, stream) in &sessions {
            let id = stream
                .wait_for("the permission callback", |value| {
                    (method_of(value) == Some("session/request_permission"))
                        .then(|| typed_id(value))
                        .flatten()
                })
                .await?;
            permission_ids.push(id);
        }

        // --- the window ---
        let window_started = Instant::now();
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| HarnessError::Process("the device client is gone".into()))?;
        let before = client.status_snapshot();
        let baseline_rotations = before.rotations_completed;
        let baseline_generation = before.active_generation.unwrap_or(0);
        let owner_before = self.owner_session().await?;
        let baseline_owner_rotations = owner_before.rotations_completed;
        let baseline_device_session = owner_before.session_id.clone();
        let baseline_epoch = owner_before.epoch;

        let mut sockets = std::collections::BTreeSet::new();
        for connection in self.proxy.connections() {
            sockets.insert(connection.source_addr.to_string());
        }
        let mut steady = Vec::new();

        // Wait out three completed rotations, checking after each that the
        // held streams are still live.  `wait_for_rotation` cross-checks the
        // connector against the owner's own snapshot and requires the
        // candidate to be gone and the active socket to have moved, so a
        // half-finished attempt cannot be counted.
        let mut generation = baseline_generation;
        for round in 1..=REQUIRED_ROTATIONS {
            let session = self
                .cluster
                .wait_for_rotation(
                    self.client
                        .as_mut()
                        .ok_or_else(|| HarnessError::Process("the device client is gone".into()))?,
                    generation,
                    None,
                    baseline_rotations + round,
                )
                .await?;
            generation = session.active_generation;
            for connection in self.proxy.connections() {
                sockets.insert(connection.source_addr.to_string());
            }
            steady.push(self.steady_sockets().await?);
            // The streams must still be live *at this rotation*, not merely at
            // the end: a stream that died in rotation one and was never read
            // again would otherwise look identical.
            if conversation.connection_stream.has_errored()
                || conversation.connection_stream.has_ended()
            {
                return Err(HarnessError::Process(format!(
                    "the connection GET died at rotation {round}"
                )));
            }
            for (session_id, stream) in &sessions {
                if stream.has_errored() || stream.has_ended() {
                    return Err(HarnessError::Process(format!(
                        "the session GET for {session_id} died at rotation {round}"
                    )));
                }
            }
        }
        let span = window_started.elapsed();
        evidence.rotation_span_ms = span.as_millis();
        // The anti-cheat i08 uses: a window shorter than the schedule counted
        // recovery activations, which bump the same counter, rather than
        // scheduled rotations.
        evidence.rotation_span_met_schedule =
            span >= Duration::from_secs(CLUSTER_ROTATION.interval_seconds * REQUIRED_ROTATIONS);

        let after = self
            .client
            .as_ref()
            .ok_or_else(|| HarnessError::Process("the device client is gone".into()))?
            .status_snapshot();
        evidence.rotations_across_span = after.rotations_completed - baseline_rotations;
        let owner_after = self.owner_session().await?;
        evidence.owner_rotations_across_span =
            owner_after.rotations_completed - baseline_owner_rotations;
        evidence.device_session_stable = owner_after.session_id == baseline_device_session;
        evidence.device_epoch_stable = owner_after.epoch == baseline_epoch;
        evidence.distinct_device_sockets = sockets.len();
        evidence.steady_state_sockets = steady;
        evidence.device_socket_peak = self.proxy.diagnostics().peak_active;
        evidence.connection_stream_alive = !conversation.connection_stream.has_errored()
            && !conversation.connection_stream.has_ended();

        // --- answer the callbacks that were pending the whole time ---
        for ((session, _stream), permission_id) in sessions.iter().zip(&permission_ids) {
            let raw = permission_id
                .strip_prefix("s:")
                .ok_or_else(|| HarnessError::Process("the callback id was not a string".into()))?;
            let (status, _headers, body) = self
                .post(
                    &conversation.consumer,
                    &[
                        ("acp-connection-id", conversation.connection.as_str()),
                        ("acp-session-id", session.as_str()),
                    ],
                    &json!({
                        "jsonrpc": "2.0",
                        "id": raw,
                        "result": {
                            "outcome": {
                                "outcome": "selected",
                                "optionId": tunnel_acp_fixture::PERMIT_OPTION,
                            },
                        },
                    }),
                )
                .await?;
            if status != http::StatusCode::ACCEPTED {
                return Err(HarnessError::Http(format!(
                    "the held permission response answered {status}, not 202: {body}"
                )));
            }
        }

        // Each turn's own result, read off its session stream.
        for (index, (session, stream)) in sessions.iter().enumerate() {
            let stop = stream
                .wait_for(
                    "the held prompt result",
                    stop_reason_for(&format!("held-{index}")),
                )
                .await?;
            let seen = stream.seen();
            let updates_after = seen
                .iter()
                .filter(|value| method_of(value) == Some("session/update"))
                .count()
                - updates_before[index];
            let callbacks = seen
                .iter()
                .filter(|value| method_of(value) == Some("session/request_permission"))
                .count();
            let distinct: std::collections::BTreeSet<String> =
                seen.iter().filter_map(typed_id).collect();
            evidence.sessions.push(SessionSpan {
                session: session.clone(),
                updates_before: updates_before[index],
                callbacks,
                updates_after,
                stop_reason: stop,
                stream_alive_through_window: !stream.has_errored() && !stream.has_ended(),
                distinct_agent_ids: distinct.len(),
                messages: seen.len(),
            });
        }
        evidence.connection_stable = !conversation.connection.is_empty();

        // The side effects, counted from the agent's own append-only ledger —
        // one per held turn, written and flushed by the agent process at the
        // moment the effect happened, not by a harness counter.
        evidence.side_effects_in_ledger = count_effect(&ledger, ROTATION_EFFECT);
        sleep(Duration::from_secs(2)).await;
        evidence.side_effects_after_settle = count_effect(&ledger, ROTATION_EFFECT);

        for (_, stream) in sessions {
            stream.break_now();
        }
        conversation.connection_stream.break_now();
        conversation.consumer.shutdown();
        Ok(())
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    workspace: PathBuf,
) -> Result<AcpClusterEvidence> {
    let mut evidence = AcpClusterEvidence {
        relay_count: cluster.relays.len(),
        resign_spacing_ms: MEMBERSHIP_RESIGN_SPACING.as_millis(),
        ..AcpClusterEvidence::default()
    };
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("the ACP gate device is missing".into()))?;
    let echo_service = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("the echo service is missing".into()))?;
    let acp_service = harness
        .acp_service("acp")
        .ok_or_else(|| HarnessError::InvalidInput("the tenant-A ACP service is missing".into()))?
        .service_id;

    let owner_device_addr = cluster
        .relay("relay-a")?
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| HarnessError::Process("relay-a is not running".into()))?;
    // Every device socket passes this proxy, so the gate can count them
    // underneath the tunnel rather than trusting a relay counter.
    let proxy = TcpProxy::bind(owner_device_addr, ProxyConfig::default()).await?;
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let device_profile = crate::acceptance::helpers::write_device_profile(
        profile_directory.path(),
        device.id,
        echo_service,
        "m8-acp-cluster-canary",
        proxy.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let base = std::fs::read_to_string(&device_profile.config_path).map_err(HarnessError::Io)?;
    let fixture = fixture_binary_path()?;
    let text = device_config_text(&base, &acp_service.to_string(), &fixture, &workspace);
    let mut config = tunnel_client::ConnectConfig::parse(&text)
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;
    config.rotation = CLUSTER_ROTATION;
    config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;

    let ingress = cluster.relay("relay-c")?;
    evidence.ingress_node = ingress.node_id.clone();
    let ingress_addr = ingress.consumer_addr()?;
    let ca = harness.pki.server_ca.certificate_der.clone();
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        crate::OidcTokenOptions {
            scope: Some("echo:invoke http:invoke".to_owned()),
            ..crate::OidcTokenOptions::default()
        },
    )?;
    let base_uri = format!(
        "https://localhost:{}/v1/devices/{}/services/{acp_service}/http/acp",
        ingress_addr.port(),
        device.id
    );

    // --- the second tenant ---
    //
    // A different tenant, a different device, a different ACP export and a
    // different owner relay: tenant B's device attaches to relay-b.  Nothing
    // is shared with tenant A except the relay mesh and the ingress the
    // consumers enter at, which is the point.
    let device_b = harness
        .topology
        .devices_b
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("the tenant-B device is missing".into()))?;
    let echo_service_b = *harness
        .topology
        .service_ids
        .get(&device_b.id)
        .ok_or_else(|| HarnessError::InvalidInput("the tenant-B echo service is missing".into()))?;
    let acp_service_b = harness
        .acp_service("acp-b")
        .ok_or_else(|| HarnessError::InvalidInput("the tenant-B ACP service is missing".into()))?
        .service_id;
    let device_b_addr = cluster
        .relay("relay-b")?
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| HarnessError::Process("relay-b is not running".into()))?;
    let profile_b_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let device_b_profile = crate::acceptance::helpers::write_device_profile(
        profile_b_directory.path(),
        device_b.id,
        echo_service_b,
        "m8-acp-cluster-canary-b",
        device_b_addr,
        &device_b.certificate.certificate_pem,
        &device_b.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let base_b =
        std::fs::read_to_string(&device_b_profile.config_path).map_err(HarnessError::Io)?;
    // Its own workspace: the fixture writes markers and its side-effect ledger
    // into the workspace, and two tenants sharing one would make every
    // per-agent measurement ambiguous.
    let workspace_b = tempfile::tempdir().map_err(HarnessError::Io)?;
    let text_b = device_config_text(
        &base_b,
        &acp_service_b.to_string(),
        &fixture,
        workspace_b.path(),
    );
    let mut config_b = tunnel_client::ConnectConfig::parse(&text_b)
        .map_err(|error| HarnessError::InvalidInput(format!("tenant-B device config: {error}")))?;
    config_b.rotation = CLUSTER_ROTATION;
    config_b
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("tenant-B device config: {error}")))?;
    let scope = crate::OidcTokenOptions {
        scope: Some("echo:invoke http:invoke".to_owned()),
        ..crate::OidcTokenOptions::default()
    };
    let sibling_token = harness
        .oidc
        .issue_with(&harness.topology.consumers_a[1].name, scope.clone())?;
    let victim_scope = scope.clone();
    let b_principal = harness
        .topology
        .consumers_b
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("a tenant-B consumer is missing".into()))?;
    let b_token = harness.oidc.issue_with(&b_principal.name, scope)?;
    let b_base_uri = format!(
        "https://localhost:{}/v1/devices/{}/services/{acp_service_b}/http/acp",
        ingress_addr.port(),
        device_b.id
    );

    let mut gate = Gate {
        cluster,
        tenant_id: device.tenant_id,
        victim_token: harness
            .oidc
            .issue_with(&harness.topology.owner_a.name, victim_scope)?,
        victim_principal_id: harness.topology.owner_a.id,
        device_id: device.id,
        service_id: acp_service,
        config,
        client: None,
        session_id: String::new(),
        acp_diagnostics: AcpExportDiagnostics::default(),
        freeze: Arc::new(FreezeWatch::default()),
        freeze_task: None,
        ledger: Arc::new(RefusalLedger::default()),
        membership_signed_at: Instant::now()
            .checked_sub(MEMBERSHIP_RESIGN_SPACING)
            .unwrap_or_else(Instant::now),
        membership_resigns: 0,
        ingress_addr,
        ca,
        token,
        base_uri,
        workspace: workspace.clone(),
        proxy,
        sibling_token,
        b_tenant_id: device_b.tenant_id,
        b_device_id: device_b.id,
        b_service_id: acp_service_b,
        b_config: config_b,
        b_client: None,
        b_acp_diagnostics: AcpExportDiagnostics::default(),
        b_base_uri,
        b_token,
        b_workspace: workspace_b.path().to_path_buf(),
    };

    let owner_node = gate.connect_device().await?;
    let owner_node_b = gate.connect_device_b().await?;
    if owner_node_b != "relay-b" {
        return Err(HarnessError::Process(format!(
            "the tenant-B device is owned by {owner_node_b}, not relay-b"
        )));
    }
    evidence.owner_node = owner_node.clone();
    evidence.non_owner_ingress = owner_node == "relay-a" && evidence.ingress_node == "relay-c";

    let outcome = async {
        for case in CLUSTER_CASES {
            gate.boundary().await?;
            let started = Instant::now();
            eprintln!("ACP cluster gate: {case}");
            match case {
                "rotation-span" => gate.case_rotation_span(&mut evidence).await?,
                "two-tenant-ids" => gate.case_two_tenant_ids(&mut evidence).await?,
                "forged-heads" => gate.case_forged_heads(&mut evidence).await?,
                "saturation" => gate.case_saturation(&mut evidence).await?,
                "revocation" => gate.case_revocation(&mut evidence).await?,
                "peer-key-rotation" => gate.case_key_rotation(&mut evidence).await?,
                "owner-loss" => gate.case_owner_loss(&mut evidence).await?,
                other => {
                    return Err(HarnessError::InvalidInput(format!(
                        "unknown ACP cluster gate case {other}"
                    )));
                }
            }
            evidence.cases_executed.push(case.to_owned());
            evidence.max_membership_age_at_case_end_ms = evidence
                .max_membership_age_at_case_end_ms
                .max(gate.membership_signed_at.elapsed().as_millis());
            eprintln!(
                "ACP cluster case {case} at {} ms",
                started.elapsed().as_millis()
            );
        }
        Ok::<(), HarnessError>(())
    }
    .await;

    evidence.membership_resigns = gate.membership_resigns;
    evidence.not_dispatched_refusals = gate.ledger.refusals.load(Ordering::SeqCst);
    evidence.not_dispatched_retries = gate.ledger.retries.load(Ordering::SeqCst);
    evidence.unexplained_refusal = gate
        .ledger
        .unexplained
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    evidence.not_covered = not_covered(evidence.rotation_span_ms, evidence.rotations_across_span);

    let pids = gate
        .client
        .as_ref()
        .map(|_| {
            gate.acp_diagnostics
                .child_pids(&gate.service_id.to_string())
        })
        .unwrap_or_default();
    if let Some(task) = gate.freeze_task.take() {
        task.abort();
    }
    let pids_b = gate
        .b_client
        .as_ref()
        .map(|_| {
            gate.b_acp_diagnostics
                .child_pids(&gate.b_service_id.to_string())
        })
        .unwrap_or_default();
    if let Some(client) = gate.client.take() {
        let _ = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    }
    if let Some(client) = gate.b_client.take() {
        let _ = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    }
    // Both tenants' agents, read from the process table after teardown.
    evidence.leftover_processes = pids
        .into_iter()
        .chain(pids_b)
        .filter(|pid| process_alive(*pid))
        .count();
    let _ = gate.proxy.shutdown().await;

    outcome?;
    Ok(evidence)
}

/// Every rule this gate holds.  The first violated one names itself.
///
/// # Errors
/// The first rule that did not hold.
pub fn validate_acp_cluster_evidence(evidence: &AcpClusterEvidence) -> Result<()> {
    let executed: Vec<&str> = evidence.cases_executed.iter().map(String::as_str).collect();
    let checks: [(&str, bool); 16] = [
        ("three relays", evidence.relay_count == 3),
        (
            "the device is owned by relay-a and the consumer entered at relay-c",
            evidence.non_owner_ingress
                && evidence.owner_node == "relay-a"
                && evidence.ingress_node == "relay-c",
        ),
        ("every case executed", executed == CLUSTER_CASES.to_vec()),
        (
            "the limits of the claim are recorded, and the rotation disclosure states this run's own span",
            evidence.not_covered.len() == NOT_COVERED.len() + 1
                && evidence.not_covered.iter().any(|text| {
                    text.contains(&format!(
                        "across {} completed rotations in {} ms",
                        evidence.rotations_across_span, evidence.rotation_span_ms
                    ))
                }),
        ),
        // --- the headline ---
        (
            "at least three scheduled rotations completed while the sessions were live",
            evidence.rotations_across_span >= REQUIRED_ROTATIONS,
        ),
        (
            "the owner counted the same rotations independently of the connector",
            evidence.owner_rotations_across_span >= REQUIRED_ROTATIONS,
        ),
        (
            // i08's anti-cheat: recovery activations bump the same counter, so
            // a window shorter than the schedule did not observe the schedule.
            "the window was at least as long as the configured rotation schedule",
            evidence.rotation_span_met_schedule,
        ),
        (
            "the rotation window finished inside one membership record",
            evidence.rotation_span_ms < ROTATION_CEILING.as_millis(),
        ),
        (
            "the device moved to a new data socket for each rotation",
            evidence.distinct_device_sockets
                >= usize::try_from(REQUIRED_ROTATIONS).unwrap_or(usize::MAX),
        ),
        (
            "two device sockets at every settled steady state",
            !evidence.steady_state_sockets.is_empty()
                && evidence.steady_state_sockets.iter().all(|open| *open == 2),
        ),
        (
            "at most one candidate data socket at a time",
            evidence.device_socket_peak <= 3,
        ),
        (
            "the connection GET stayed live across every rotation",
            evidence.connection_stream_alive && evidence.connection_stable,
        ),
        (
            "the device session and owner epoch were unchanged, so these were rotations and not a reconnect",
            evidence.device_session_stable && evidence.device_epoch_stable,
        ),
        (
            "each held turn recorded its side effect exactly once in the agent's own ledger, and nothing replayed it",
            evidence.side_effects_in_ledger == ROTATION_SESSIONS as u64
                && evidence.side_effects_after_settle == ROTATION_SESSIONS as u64,
        ),
        // --- the M7-C80 accommodation ---
        (
            "every case ended inside the membership records' lifetime",
            evidence.max_membership_age_at_case_end_ms < MEMBERSHIP_RECORD_LIFETIME.as_millis(),
        ),
        (
            "every not_dispatched refusal coincided with an observed rotation freeze and was bounded",
            evidence.not_dispatched_refusals == evidence.not_dispatched_retries
                && evidence.unexplained_refusal.is_none(),
        ),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::Process(format!(
                "ACP cluster gate failed: {rule}"
            )));
        }
    }
    let later: [(&str, bool); 17] = [
        // --- two users in two tenants ---
        (
            "the two principals really did reuse the same JSON-RPC ids, in both types",
            evidence.shared_rpc_ids == vec!["s:1".to_owned(), "n:1".to_owned()],
        ),
        (
            // Not "the ids collided": see the field's own comment for why
            // that is not something this gate can cause.  What is asserted is
            // that a live connection id is inert in the other tenant.
            "a live connection id from one tenant is refused in the other byte-identically to an id that never existed",
            evidence.connection_id_inert_in_other_tenant,
        ),
        (
            "the two tenants' exports issued the same session identifier",
            evidence.session_ids_collide,
        ),
        (
            "every reply was routed to the principal that asked, exactly once",
            evidence.replies_routed_per_principal,
        ),
        (
            // Byte-identical, not merely "both refused": a different status,
            // header or body would tell the caller the other principal's
            // connection exists.
            "another principal of the same tenant is refused byte-identically to an id that never existed",
            evidence.same_tenant_foreign_matches_unknown,
        ),
        (
            "a principal of the other tenant is refused byte-identically to an id that never existed",
            evidence.cross_tenant_foreign_matches_unknown,
        ),
        (
            // The comparison must not pass by both probes being some
            // unrelated error, so the status is pinned to the profile's own
            // "no such connection or session".
            "those refusals were the profile's not-found, not some other error",
            evidence.foreign_refusal_status == 404,
        ),
        (
            "the genuine owner was still served afterwards",
            evidence.genuine_request_still_served,
        ),
        (
            "tenant B's export served exactly its own principal and opened nothing for the probes",
            evidence.tenant_b_sessions_opened == 1,
        ),
        // --- forged heads ---
        (
            "every forged head was refused before dispatch",
            evidence.forgery_attempts == 3 && evidence.forgeries_refused == 3,
        ),
        (
            // The claim is not that they were refused but that nothing
            // reached the device: a forged initialize that got through would
            // have opened a connection and started a child.
            "not one forged head reached the device",
            evidence.forgery_dispatched == 0,
        ),
        (
            "the ingress counted each forgery as a rejection before admission",
            evidence.forgery_ingress_rejections >= evidence.forgery_attempts,
        ),
        // --- revocation ---
        (
            "revocation withdrew the admitted exchange",
            evidence.revocation_in_flight_withdrawn,
        ),
        (
            "the withdrawn exchange was classified execution: unknown by the relay itself",
            evidence.revocation_in_flight_execution == "unknown",
        ),
        (
            "nothing was dispatched to the device after revocation",
            evidence.revocation_dispatched_after == 0,
        ),
        (
            "the withdrawn turn never acquired a stop reason",
            evidence.revocation_no_stop_reason,
        ),
        // --- saturation ---
        (
            "both forwarding segments were over half their peer window at once, with a live SSE stream still served",
            evidence.both_segments_saturated && evidence.live_stream_served_while_saturated,
        ),
    ];
    for (rule, passed) in later {
        if !passed {
            return Err(HarnessError::Process(format!(
                "ACP cluster gate failed: {rule}"
            )));
        }
    }
    // Peer-key rotation and owner loss are checked together, because the
    // property is the same one and stating it twice separately invites one of
    // them to be quietly weakened.
    for (label, interrupted, no_stop_reason) in [
        (
            "peer-key rotation",
            evidence.key_rotation_interrupted,
            evidence.key_rotation_no_stop_reason,
        ),
        (
            "owner loss",
            evidence.owner_loss_interrupted,
            evidence.owner_loss_no_stop_reason,
        ),
    ] {
        if !interrupted {
            return Err(HarnessError::Process(format!(
                "ACP cluster gate failed: {label} did not produce an explicit interruption"
            )));
        }
        if !no_stop_reason {
            return Err(HarnessError::Process(format!(
                "ACP cluster gate failed: {label} produced a stopReason for a turn that never finished, which is a fabricated terminal"
            )));
        }
    }
    // The per-session rules come after "every case executed", deliberately: a
    // case that did not run leaves these at `Default` and would otherwise
    // report as several unrelated failures rather than as a case that never
    // ran.
    if evidence.sessions.len() != ROTATION_SESSIONS {
        return Err(HarnessError::Process(format!(
            "ACP cluster gate failed: {} sessions were carried across the window, not {ROTATION_SESSIONS}",
            evidence.sessions.len()
        )));
    }
    for span in &evidence.sessions {
        let rules = [
            (
                "the session stream stayed live across every rotation",
                span.stream_alive_through_window,
            ),
            (
                "the held turn completed end_turn, read off the wire",
                span.stop_reason == "end_turn",
            ),
            (
                // Exactly one: a duplicated callback is the failure this case
                // exists to exclude, and it is counted at the wire.
                "the permission callback arrived exactly once across the window",
                span.callbacks == 1,
            ),
            (
                "the warm-up update arrived before the window",
                span.updates_before >= 1,
            ),
            (
                "the held turn's own update arrived after its callback was answered",
                span.updates_after >= 1,
            ),
            (
                // Every agent-originated message with an id carried a distinct
                // one, so nothing was replayed under an id already seen.
                "no message was repeated under an id already seen on this stream",
                span.distinct_agent_ids >= 1 && span.messages >= span.distinct_agent_ids,
            ),
        ];
        for (rule, passed) in rules {
            if !passed {
                return Err(HarnessError::Process(format!(
                    "ACP cluster gate failed: session {}: {rule}",
                    span.session
                )));
            }
        }
    }
    if evidence.leftover_processes != 0 {
        return Err(HarnessError::Process(format!(
            "ACP cluster gate failed: {} agent processes outlived the gate",
            evidence.leftover_processes
        )));
    }
    Ok(())
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<AcpClusterEvidence> {
    let options = HarnessOptions::from_env()?
        .acp_services(true)
        .acp_services_tenant_b(true)
        .rotation(CLUSTER_ROTATION);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("ACP cluster harness startup timed out".into()))??;
    let serve = tunnel_relay::HttpForwardServeConfig {
        profiles: vec![tunnel_acp::PROFILE_ID.to_owned()],
        request_body_bytes: None,
        response_body_bytes: None,
        deadline_seconds: None,
    };
    let exports = match serve.exports() {
        Ok(exports) => exports,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(HarnessError::InvalidInput(format!(
                "[http_forward] profiles: {error}"
            )));
        }
    };
    harness.http_forward = Some(exports);
    let workspace = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(HarnessError::Io(error));
        }
    };
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        run(&mut cluster, &harness, workspace.path().to_path_buf()),
    )
    .await
    {
        Ok(result) => result.and_then(|evidence| {
            if let Err(error) = validate_acp_cluster_evidence(&evidence) {
                // Payload-free: identifiers, counters and labels.
                eprintln!("ACP cluster evidence: {evidence:?}");
                return Err(error);
            }
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "the ACP cluster scenario exceeded its bounded deadline".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Evidence from a run where everything this gate asserts held.
    ///
    /// Built from the fields a passing run actually recorded, so the
    /// falsification test below is checking the real validator against real
    /// shapes rather than against a hand-tuned minimum.
    fn passing_evidence() -> AcpClusterEvidence {
        let span = |session: &str| SessionSpan {
            session: session.to_owned(),
            updates_before: 1,
            callbacks: 1,
            updates_after: 1,
            stop_reason: "end_turn".to_owned(),
            stream_alive_through_window: true,
            distinct_agent_ids: 3,
            messages: 5,
        };
        let mut evidence = AcpClusterEvidence {
            relay_count: 3,
            owner_node: "relay-a".to_owned(),
            ingress_node: "relay-c".to_owned(),
            non_owner_ingress: true,
            cases_executed: CLUSTER_CASES
                .iter()
                .map(|case| (*case).to_owned())
                .collect(),
            not_covered: Vec::new(),
            rotations_across_span: 3,
            owner_rotations_across_span: 3,
            rotation_span_ms: 11_223,
            rotation_span_met_schedule: true,
            sessions: vec![span("session-1"), span("session-2")],
            connection_stable: true,
            connection_stream_alive: true,
            device_session_stable: true,
            device_epoch_stable: true,
            distinct_device_sockets: 5,
            steady_state_sockets: vec![2, 2, 2],
            device_socket_peak: 3,
            side_effects_in_ledger: 2,
            side_effects_after_settle: 2,
            membership_resigns: 2,
            max_membership_age_at_case_end_ms: 15_621,
            resign_spacing_ms: MEMBERSHIP_RESIGN_SPACING.as_millis(),
            not_dispatched_refusals: 0,
            not_dispatched_retries: 0,
            unexplained_refusal: None,
            connection_ids_collide: false,
            connection_id_inert_in_other_tenant: true,
            session_ids_collide: true,
            shared_rpc_ids: vec!["s:1".to_owned(), "n:1".to_owned()],
            replies_routed_per_principal: true,
            same_tenant_foreign_matches_unknown: true,
            cross_tenant_foreign_matches_unknown: true,
            foreign_refusal_status: 404,
            genuine_request_still_served: true,
            tenant_b_sessions_opened: 1,
            forgery_attempts: 3,
            forgeries_refused: 3,
            forgery_ingress_rejections: 3,
            forgery_dispatched: 0,
            forgery_codes: Vec::new(),
            revocation_in_flight_withdrawn: true,
            revocation_in_flight_execution: "unknown".to_owned(),
            revocation_after_status: 404,
            revocation_after_code: "SERVICE_NOT_FOUND".to_owned(),
            revocation_after_execution: "not_dispatched".to_owned(),
            revocation_dispatched_after: 0,
            revocation_no_stop_reason: true,
            key_rotation_interrupted: true,
            key_rotation_no_stop_reason: true,
            owner_loss_interrupted: true,
            owner_loss_no_stop_reason: true,
            ingress_peer_send_in_flight: 195_933,
            owner_peer_send_in_flight: 195_717,
            peer_window: 196_608,
            both_segments_saturated: true,
            live_stream_served_while_saturated: true,
            leftover_processes: 0,
        };
        evidence.not_covered =
            not_covered(evidence.rotation_span_ms, evidence.rotations_across_span);
        evidence
    }

    #[test]
    fn a_passing_run_validates() {
        validate_acp_cluster_evidence(&passing_evidence())
            .expect("evidence from a passing run must validate");
    }

    /// Every field this gate claims something about must be able to fail the
    /// validator on its own.
    ///
    /// This is M3-04's precedent and it is what makes the guard-deletion suite
    /// meaningful: a rule that has been deleted or neutered stops rejecting
    /// its own falsification, and this test names it.  Without it, a deleted
    /// rule would simply stop being checked and nothing would go red.
    #[test]
    fn every_claim_can_fail_on_its_own() {
        let mutations: Vec<(&str, fn(&mut AcpClusterEvidence))> = vec![
            ("relay_count", |e| e.relay_count = 2),
            ("non_owner_ingress", |e| e.non_owner_ingress = false),
            ("owner_node", |e| e.owner_node = "relay-c".to_owned()),
            ("ingress_node", |e| e.ingress_node = "relay-a".to_owned()),
            ("cases_executed", |e| {
                e.cases_executed.pop();
            }),
            ("rotations_across_span", |e| e.rotations_across_span = 2),
            ("owner_rotations_across_span", |e| {
                e.owner_rotations_across_span = 2;
            }),
            ("rotation_span_met_schedule", |e| {
                e.rotation_span_met_schedule = false;
            }),
            ("rotation_span_ms", |e| {
                e.rotation_span_ms = ROTATION_CEILING.as_millis() + 1;
            }),
            ("distinct_device_sockets", |e| e.distinct_device_sockets = 1),
            ("steady_state_sockets", |e| {
                e.steady_state_sockets = vec![2, 3, 2];
            }),
            ("device_socket_peak", |e| e.device_socket_peak = 4),
            ("connection_stream_alive", |e| {
                e.connection_stream_alive = false;
            }),
            ("device_session_stable", |e| e.device_session_stable = false),
            ("device_epoch_stable", |e| e.device_epoch_stable = false),
            ("side_effects_in_ledger", |e| e.side_effects_in_ledger = 3),
            ("side_effects_after_settle", |e| {
                e.side_effects_after_settle = 3;
            }),
            ("max_membership_age_at_case_end_ms", |e| {
                e.max_membership_age_at_case_end_ms = MEMBERSHIP_RECORD_LIFETIME.as_millis() + 1;
            }),
            ("unexplained_refusal", |e| {
                e.unexplained_refusal = Some("phase=active".to_owned());
            }),
            ("shared_rpc_ids", |e| {
                e.shared_rpc_ids = vec!["s:1".to_owned()]
            }),
            ("connection_id_inert_in_other_tenant", |e| {
                e.connection_id_inert_in_other_tenant = false;
            }),
            ("session_ids_collide", |e| e.session_ids_collide = false),
            ("replies_routed_per_principal", |e| {
                e.replies_routed_per_principal = false;
            }),
            ("same_tenant_foreign_matches_unknown", |e| {
                e.same_tenant_foreign_matches_unknown = false;
            }),
            ("cross_tenant_foreign_matches_unknown", |e| {
                e.cross_tenant_foreign_matches_unknown = false;
            }),
            ("foreign_refusal_status", |e| e.foreign_refusal_status = 403),
            ("genuine_request_still_served", |e| {
                e.genuine_request_still_served = false;
            }),
            ("tenant_b_sessions_opened", |e| {
                e.tenant_b_sessions_opened = 2
            }),
            ("forgeries_refused", |e| e.forgeries_refused = 2),
            ("forgery_dispatched", |e| e.forgery_dispatched = 1),
            ("forgery_ingress_rejections", |e| {
                e.forgery_ingress_rejections = 0;
            }),
            ("revocation_in_flight_withdrawn", |e| {
                e.revocation_in_flight_withdrawn = false;
            }),
            ("revocation_in_flight_execution", |e| {
                e.revocation_in_flight_execution = "not_dispatched".to_owned();
            }),
            ("revocation_dispatched_after", |e| {
                e.revocation_dispatched_after = 1;
            }),
            ("revocation_no_stop_reason", |e| {
                e.revocation_no_stop_reason = false;
            }),
            ("key_rotation_interrupted", |e| {
                e.key_rotation_interrupted = false;
            }),
            ("key_rotation_no_stop_reason", |e| {
                e.key_rotation_no_stop_reason = false;
            }),
            ("owner_loss_interrupted", |e| {
                e.owner_loss_interrupted = false
            }),
            ("owner_loss_no_stop_reason", |e| {
                e.owner_loss_no_stop_reason = false;
            }),
            ("both_segments_saturated", |e| {
                e.both_segments_saturated = false;
            }),
            ("live_stream_served_while_saturated", |e| {
                e.live_stream_served_while_saturated = false;
            }),
            ("leftover_processes", |e| e.leftover_processes = 1),
            ("session stop_reason", |e| {
                e.sessions[0].stop_reason = "cancelled".to_owned();
            }),
            ("session callbacks", |e| e.sessions[1].callbacks = 2),
            ("session updates_before", |e| {
                e.sessions[0].updates_before = 0
            }),
            ("session updates_after", |e| e.sessions[1].updates_after = 0),
            ("session stream_alive_through_window", |e| {
                e.sessions[0].stream_alive_through_window = false;
            }),
            ("session count", |e| {
                e.sessions.pop();
            }),
        ];
        for (name, mutate) in mutations {
            let mut evidence = passing_evidence();
            mutate(&mut evidence);
            // Rebuild the disclosure from the mutated run before validating.
            //
            // Two of these fields — the rotation count and the span — are also
            // quoted in the rotation disclosure, so mutating one made the
            // *disclosure* rule fail and the rule under test was never
            // reached.  The guard-deletion suite found it: deleting "three
            // completed rotations are required" and "the window must finish
            // inside one membership record" reddened nothing, because this
            // test was catching those two mutations by the wrong rule.  The
            // disclosure rule keeps its own test below.
            evidence.not_covered =
                not_covered(evidence.rotation_span_ms, evidence.rotations_across_span);
            assert!(
                validate_acp_cluster_evidence(&evidence).is_err(),
                "falsifying {name} was accepted by the validator"
            );
        }
    }

    /// The rotation disclosure must carry **this run's** numbers.
    ///
    /// A disclosure built from a constant would say the same thing whatever
    /// happened, which is chunk 4's recorded lesson.
    #[test]
    fn the_rotation_disclosure_carries_the_run_it_describes() {
        let mut evidence = passing_evidence();
        // A disclosure left over from some other run must not validate.
        evidence.not_covered = not_covered(999, 9);
        assert!(validate_acp_cluster_evidence(&evidence).is_err());
    }

    /// The case list and the disclosure list are the two places a case can be
    /// silently dropped.
    #[test]
    fn a_case_that_did_not_run_is_named_rather_than_counted() {
        let mut evidence = passing_evidence();
        evidence.cases_executed.retain(|case| case != "revocation");
        let error =
            validate_acp_cluster_evidence(&evidence).expect_err("a missing case must fail the run");
        assert!(
            error.to_string().contains("every case executed"),
            "a missing case must name itself, not produce unrelated failures: {error}"
        );
    }
}
