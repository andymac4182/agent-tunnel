//! M7-I06/I08 credential expiry during an active scheduled rotation.
//!
//! This acceptance command uses the production three-relay fixture and the
//! built `tunnel-client` process;
//! the application service remains the existing synthetic echo service.  It
//! does not implement or claim a deployed adapter.
//!
//! A fixture-only catalog gate pauses one refresh authorization after the real
//! Redis read, while device-revocation covers a device credential without an
//! active rotation.  This fixture fills the narrow intersection: a short-lived
//! consumer credential is admitted before a scheduled carrier rotation, expires
//! while that rotation and one refresh challenge are active, and cannot be
//! extended by the rotation.  A same-UUID tenant sibling remains a positive
//! control throughout the phase.

use super::{
    CLEANUP_TIMEOUT, ConsumerStream, ProductionCluster, RunningHarness, connect_failure_to_harness,
    start_cli_smoke, wait_for_fanout_drained,
};
use crate::acceptance::helpers::{DeviceProfile, write_device_profile};
use crate::{HarnessError, ManagedProcess, OidcClaims, OidcTokenOptions, ProxyHandle, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};
use tokio::{
    sync::Notify,
    time::{sleep, timeout},
};
use tokio_tungstenite::tungstenite::Message;
use tunnel_catalog::{
    AttachmentTicket, AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest,
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, ConsumedAttachmentTicket,
    DeviceIdentity, DeviceListFilter, DeviceSummary, GrantSnapshot, GrantSpec, OwnerClaim,
    OwnerClaimRequest, OwnerToken, SharedCatalog, SignedMembershipRecord,
};
use tunnel_core::RotationConfig;
use tunnel_protocol::rotation_control::RotationAttemptIdentity;
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot, RelayStreamSnapshot};

mod rotation_barrier;
use rotation_barrier::{
    RotationBarrierEvidence, RotationBarrierHold, bind_device_proxy, install_rotation_barrier,
    wait_for_committed_cli_route,
};
use uuid::Uuid;

const EXPIRY_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
const EXPIRY_PHASE_TIMEOUT: Duration = Duration::from_secs(20);
const EXPIRY_POLL: Duration = Duration::from_millis(50);
const EXPIRY_TOKEN_LIFETIME: Duration = Duration::from_secs(16);
const MIN_TOKEN_REMAINING_MS: u64 = 2_500;
const ROTATION_EXPIRY_MARGIN_MS: u64 = 1_000;
const AUTHORIZATION_CHALLENGE_INTERVAL: Duration = Duration::from_secs(2);
// Arm close to the client's 1.5-second refresh margin.  An earlier gate can
// hold a refresh whose fixed two-second relay challenge expires before the
// consumer token, which is a different deadline winner.
const GATE_ARM_REMAINING_MS: u64 = 1_500;
const CHALLENGE_EXPIRY_SAFETY_MARGIN_MS: u64 = 250;
const EXPIRY_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const OWNER_LEASE_SAFETY_MARGIN: ChronoDuration = ChronoDuration::seconds(5);
const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;
const MAX_DISPATCH_DELTA: u64 = 0;

/// Fixture-only lead time before the first configured carrier rotation.  The
/// long-lived stream stays live and emits bounded positive echoes until this
/// two-second window; the barrier is then installed once while the original
/// carrier is still active.  This avoids accumulating the normal idle/FIN
/// budget before the selected attempt and does not alter any production
/// timeout.
const ROTATION_ARM_LEAD_MS: u64 = 2_000;

#[derive(Clone, Copy, Debug)]
struct PreRotationTiming {
    /// `start_cli_smoke` observes public admission after the M2 timer starts;
    /// the helper therefore treats this as a conservative fixture estimate.
    ready_at: Instant,
    deadline: Instant,
}

/// The expiry phase uses a deliberately generous synthetic rotation policy so
/// the fixture can admit a short-lived token and establish one exact
/// candidate/old-carrier attempt before holding one refresh authorization
/// challenge through expiry.  This policy is scoped to this fixture; it does
/// not change the production default or prove a deployed adapter contract.
pub(super) const EXPIRY_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 12,
    handshake_timeout_seconds: 1,
    overlap_seconds: 8,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorizationScope {
    tenant_id: Uuid,
    principal_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
}

struct AuthorizationDelayState {
    scope: Mutex<Option<AuthorizationScope>>,
    device_spki: Mutex<Option<String>>,
    token_expires_at: Mutex<Option<DateTime<Utc>>>,
    armed: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
    held_result: AtomicBool,
    completed: AtomicBool,
    matching_calls: AtomicU64,
    held_calls: AtomicU64,
    owner_followup_calls: AtomicU64,
    device_followup_calls: AtomicU64,
    entered_notify: Notify,
    release_notify: Notify,
    completion_notify: Notify,
    followup_notify: Notify,
}

/// A test-only catalog wrapper that holds one successful refresh authorization
/// after the real Redis read.  The gate is armed only after the short token's
/// initial admission and authoritative grant read, so it cannot block setup or
/// turn a stale grant read into evidence.  The call-time token window is also
/// checked, so an earlier refresh is returned normally and cannot consume the
/// one-use hold before the challenge can cover token expiry.
#[derive(Clone)]
pub(super) struct AuthorizationDelayGate {
    state: Arc<AuthorizationDelayState>,
}

impl Default for AuthorizationDelayGate {
    fn default() -> Self {
        Self {
            state: Arc::new(AuthorizationDelayState {
                scope: Mutex::new(None),
                device_spki: Mutex::new(None),
                token_expires_at: Mutex::new(None),
                armed: AtomicBool::new(false),
                entered: AtomicBool::new(false),
                released: AtomicBool::new(false),
                held_result: AtomicBool::new(false),
                completed: AtomicBool::new(false),
                matching_calls: AtomicU64::new(0),
                held_calls: AtomicU64::new(0),
                owner_followup_calls: AtomicU64::new(0),
                device_followup_calls: AtomicU64::new(0),
                entered_notify: Notify::new(),
                release_notify: Notify::new(),
                completion_notify: Notify::new(),
                followup_notify: Notify::new(),
            }),
        }
    }
}

impl AuthorizationDelayGate {
    fn arm(&self, scope: AuthorizationScope, token_expires_at: DateTime<Utc>) -> Result<()> {
        let mut current = self.state.scope.lock().map_err(|_| {
            HarnessError::Process("credential-expiry authorization gate lock poisoned".into())
        })?;
        *current = Some(scope);
        *self.state.device_spki.lock().map_err(|_| {
            HarnessError::Process("credential-expiry authorization gate lock poisoned".into())
        })? = None;
        *self.state.token_expires_at.lock().map_err(|_| {
            HarnessError::Process("credential-expiry authorization gate lock poisoned".into())
        })? = Some(token_expires_at);
        self.state.armed.store(true, Ordering::Release);
        self.state.entered.store(false, Ordering::Release);
        self.state.released.store(false, Ordering::Release);
        self.state.held_result.store(false, Ordering::Release);
        self.state.completed.store(false, Ordering::Release);
        self.state.matching_calls.store(0, Ordering::Release);
        self.state.held_calls.store(0, Ordering::Release);
        self.state.owner_followup_calls.store(0, Ordering::Release);
        self.state.device_followup_calls.store(0, Ordering::Release);
        Ok(())
    }

    fn set_device_spki(&self, spki: &str) -> Result<()> {
        *self.state.device_spki.lock().map_err(|_| {
            HarnessError::Process("credential-expiry authorization gate lock poisoned".into())
        })? = Some(spki.to_owned());
        Ok(())
    }

    fn matches(&self, scope: AuthorizationScope, at: DateTime<Utc>) -> bool {
        let scope_matches = self
            .state
            .scope
            .lock()
            .map(|current| current.as_ref() == Some(&scope))
            .unwrap_or(false);
        let token_window_matches = self
            .state
            .token_expires_at
            .lock()
            .ok()
            .and_then(|expires_at| expires_at.as_ref().copied())
            .is_some_and(|expires_at| {
                expires_at > at && remaining_ms(expires_at, at) <= GATE_ARM_REMAINING_MS
            });
        !self.state.released.load(Ordering::Acquire) && scope_matches && token_window_matches
    }

    fn record_matching_call(&self) -> u64 {
        self.state.matching_calls.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn claim_hold(&self) -> bool {
        self.state.armed.swap(false, Ordering::AcqRel)
    }

    fn mark_held(&self) {
        self.state.held_calls.fetch_add(1, Ordering::AcqRel);
        self.state.entered.store(true, Ordering::Release);
        // `mark_held` is reached only after the real inner Redis authorize
        // returned `Some(GrantSnapshot)`. The gate retains that result; it
        // never performs a second Redis authorize after release.
        self.state.held_result.store(true, Ordering::Release);
        self.state.entered_notify.notify_waiters();
    }

    pub(super) fn release(&self) {
        self.state.released.store(true, Ordering::Release);
        self.state.release_notify.notify_waiters();
    }

    fn mark_completed(&self) {
        self.state.completed.store(true, Ordering::Release);
        self.state.completion_notify.notify_waiters();
    }

    fn record_owner_followup(&self, tenant_id: Uuid, device_id: Uuid) {
        let matches_scope = self.state.released.load(Ordering::Acquire)
            && self.state.completed.load(Ordering::Acquire)
            && self
                .state
                .scope
                .lock()
                .map(|scope| {
                    scope.as_ref().is_some_and(|scope| {
                        scope.tenant_id == tenant_id && scope.device_id == device_id
                    })
                })
                .unwrap_or(false);
        if matches_scope {
            self.state
                .owner_followup_calls
                .fetch_add(1, Ordering::AcqRel);
            self.state.followup_notify.notify_waiters();
        }
    }

    fn record_device_followup(&self, spki: &str) {
        let matches_scope = self.state.released.load(Ordering::Acquire)
            && self.state.completed.load(Ordering::Acquire)
            && self
                .state
                .device_spki
                .lock()
                .map(|expected| expected.as_deref() == Some(spki))
                .unwrap_or(false);
        if matches_scope {
            self.state
                .device_followup_calls
                .fetch_add(1, Ordering::AcqRel);
            self.state.followup_notify.notify_waiters();
        }
    }

    /// The actor enqueues `ChallengeAuthorized` only after the gated
    /// `authorize` result and both of its follow-up catalog reads complete.
    /// This bounded marker distinguishes that causal point from mere gate
    /// release. It is diagnostic-only; terminal acceptance remains strict.
    async fn wait_for_followups(&self, deadline: Instant) -> Result<()> {
        if !self.state.held_result.load(Ordering::Acquire) {
            return Err(HarnessError::Process(
                "credential-expiry follow-up observation requested without a held successful authorization result"
                    .into(),
            ));
        }
        loop {
            if self.state.owner_followup_calls.load(Ordering::Acquire) > 0
                && self.state.device_followup_calls.load(Ordering::Acquire) > 0
            {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HarnessError::Timeout(
                    "credential-expiry authorization follow-up catalog reads were not observed after gate release"
                        .into(),
                ));
            }
            let notified = self.state.followup_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.owner_followup_calls.load(Ordering::Acquire) > 0
                && self.state.device_followup_calls.load(Ordering::Acquire) > 0
            {
                return Ok(());
            }
            timeout(remaining, notified).await.map_err(|_| {
                HarnessError::Timeout(
                    "credential-expiry authorization follow-up catalog reads were not observed after gate release"
                        .into(),
                )
            })?;
        }
    }

    /// Wait until the gated `authorize` call has returned to the relay's
    /// background task.  Releasing the gate alone does not prove this: the
    /// actor performs the subsequent owner and device catalog reads before it
    /// can enqueue `ChallengeAuthorized`.  This bounded marker makes that
    /// causal gap explicit without changing the production actor.
    async fn wait_for_completion(&self, deadline: Instant) -> Result<()> {
        loop {
            if self.state.completed.load(Ordering::Acquire) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HarnessError::Timeout(
                    "credential-expiry authorization catalog call did not return after gate release"
                        .into(),
                ));
            }
            let notified = self.state.completion_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.completed.load(Ordering::Acquire) {
                return Ok(());
            }
            timeout(remaining, notified).await.map_err(|_| {
                HarnessError::Timeout(
                    "credential-expiry authorization catalog call did not return after gate release"
                        .into(),
                )
            })?;
        }
    }

    async fn wait_for_hit(&self, deadline: Instant) -> Result<()> {
        loop {
            if self.state.entered.load(Ordering::Acquire) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HarnessError::Timeout(
                    "credential-expiry authorization challenge gate was not reached".into(),
                ));
            }
            let notified = self.state.entered_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.entered.load(Ordering::Acquire) {
                return Ok(());
            }
            timeout(remaining, notified).await.map_err(|_| {
                HarnessError::Timeout(
                    "credential-expiry authorization challenge gate was not reached".into(),
                )
            })?;
        }
    }

    async fn wait_for_release(&self) -> std::result::Result<(), CatalogError> {
        let deadline = Instant::now() + EXPIRY_PHASE_TIMEOUT;
        loop {
            if self.state.released.load(Ordering::Acquire) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CatalogError::Conflict(
                    "credential-expiry authorization gate release timed out",
                ));
            }
            let notified = self.state.release_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.released.load(Ordering::Acquire) {
                return Ok(());
            }
            timeout(remaining, notified).await.map_err(|_| {
                CatalogError::Conflict("credential-expiry authorization gate release timed out")
            })?;
        }
    }

    fn exactly_one_hold(&self) -> bool {
        self.state.matching_calls.load(Ordering::Acquire) == 1
            && self.state.held_calls.load(Ordering::Acquire) == 1
            && self.state.released.load(Ordering::Acquire)
    }

    /// Snapshot only the bounded state needed to explain a failed fixture
    /// phase.  This is diagnostic metadata; it is not acceptance evidence and
    /// deliberately excludes credentials and payloads.
    fn diagnostic_summary(&self) -> String {
        format!(
            "armed={} entered={} released={} held_result={} completed={} matching_calls={} held_calls={} owner_followup_calls={} device_followup_calls={}",
            self.state.armed.load(Ordering::Acquire),
            self.state.entered.load(Ordering::Acquire),
            self.state.released.load(Ordering::Acquire),
            self.state.held_result.load(Ordering::Acquire),
            self.state.completed.load(Ordering::Acquire),
            self.state.matching_calls.load(Ordering::Acquire),
            self.state.held_calls.load(Ordering::Acquire),
            self.state.owner_followup_calls.load(Ordering::Acquire),
            self.state.device_followup_calls.load(Ordering::Acquire),
        )
    }
}

struct AuthorizationDelayCatalog {
    inner: SharedCatalog,
    gate: AuthorizationDelayGate,
}

impl AuthorizationDelayCatalog {
    fn new(inner: SharedCatalog, gate: AuthorizationDelayGate) -> Self {
        Self { inner, gate }
    }
}

#[async_trait]
impl Catalog for AuthorizationDelayCatalog {
    async fn resolve_device(
        &self,
        spki_fingerprint: &str,
        at: DateTime<Utc>,
    ) -> std::result::Result<Option<DeviceIdentity>, CatalogError> {
        let result = self.inner.resolve_device(spki_fingerprint, at).await;
        self.gate.record_device_followup(spki_fingerprint);
        result
    }

    async fn resolve_consumer(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: Option<Uuid>,
    ) -> std::result::Result<Option<AuthenticatedConsumer>, CatalogError> {
        self.inner
            .resolve_consumer(issuer, subject, tenant_id)
            .await
    }

    async fn authorize(
        &self,
        principal: &AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        read_started_at: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> std::result::Result<Option<GrantSnapshot>, CatalogError> {
        let result = self
            .inner
            .authorize(principal, device_id, service_id, read_started_at, at)
            .await?;
        // Redis `None` is a real no-grant result.  The actor returns before
        // current_owner/resolve_device for that result, so it must neither
        // enter this gate nor be made to satisfy the follow-up observation.
        if result.is_some()
            && self.gate.matches(
                AuthorizationScope {
                    tenant_id: principal.tenant_id,
                    principal_id: principal.principal_id,
                    device_id,
                    service_id,
                },
                at,
            )
        {
            let matching_calls = self.gate.record_matching_call();
            if matching_calls != 1 || !self.gate.claim_hold() {
                return Err(CatalogError::Conflict(
                    "credential-expiry authorization gate saw an ambiguous matching call",
                ));
            }
            self.gate.mark_held();
            self.gate.wait_for_release().await?;
            self.gate.mark_completed();
        }
        Ok(result)
    }

    async fn list_devices_filtered(
        &self,
        principal: &AuthenticatedConsumer,
        filter: &DeviceListFilter,
        at: DateTime<Utc>,
    ) -> std::result::Result<Vec<DeviceSummary>, CatalogError> {
        self.inner
            .list_devices_filtered(principal, filter, at)
            .await
    }

    async fn upsert_grant(
        &self,
        spec: &GrantSpec,
    ) -> std::result::Result<GrantSnapshot, CatalogError> {
        self.inner.upsert_grant(spec).await
    }

    async fn revoke_grant(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        device_id: Uuid,
        service_id: Uuid,
        at: DateTime<Utc>,
    ) -> std::result::Result<u64, CatalogError> {
        self.inner
            .revoke_grant(tenant_id, principal_id, device_id, service_id, at)
            .await
    }

    async fn revoke_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> std::result::Result<u64, CatalogError> {
        self.inner.revoke_device(tenant_id, device_id, at).await
    }

    async fn revoke_credential(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        credential_id: Uuid,
        at: DateTime<Utc>,
    ) -> std::result::Result<u64, CatalogError> {
        self.inner
            .revoke_credential(tenant_id, device_id, credential_id, at)
            .await
    }

    async fn seed_fixture(
        &self,
        fixture: &CatalogFixture,
    ) -> std::result::Result<(), CatalogError> {
        self.inner.seed_fixture(fixture).await
    }

    async fn claim_owner(
        &self,
        request: &OwnerClaimRequest,
    ) -> std::result::Result<OwnerClaim, CatalogError> {
        self.inner.claim_owner(request).await
    }

    async fn renew_owner(
        &self,
        token: &OwnerToken,
        lease_expires_at: DateTime<Utc>,
    ) -> std::result::Result<bool, CatalogError> {
        self.inner.renew_owner(token, lease_expires_at).await
    }

    async fn release_owner(&self, token: &OwnerToken) -> std::result::Result<bool, CatalogError> {
        self.inner.release_owner(token).await
    }

    async fn current_owner(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> std::result::Result<Option<OwnerClaim>, CatalogError> {
        let result = self.inner.current_owner(tenant_id, device_id, at).await;
        self.gate.record_owner_followup(tenant_id, device_id);
        result
    }

    async fn issue_attachment_ticket(
        &self,
        request: &AttachmentTicketIssueRequest,
    ) -> std::result::Result<AttachmentTicket, CatalogError> {
        self.inner.issue_attachment_ticket(request).await
    }

    async fn consume_attachment_ticket(
        &self,
        request: &AttachmentTicketConsumeRequest,
    ) -> std::result::Result<ConsumedAttachmentTicket, CatalogError> {
        self.inner.consume_attachment_ticket(request).await
    }

    async fn read_signed_membership(
        &self,
    ) -> std::result::Result<Option<SignedMembershipRecord>, CatalogError> {
        self.inner.read_signed_membership().await
    }

    async fn read_signed_memberships(
        &self,
    ) -> std::result::Result<Vec<SignedMembershipRecord>, CatalogError> {
        self.inner.read_signed_memberships().await
    }
}

/// Build the real Redis authority plus the fixture-only delay gate.  The
/// parent wrapper starts all three relays with this shared catalog instance.
pub(super) fn gated_catalog(
    harness: &RunningHarness,
) -> Result<(SharedCatalog, AuthorizationDelayGate)> {
    let catalog = Arc::new(harness.production_catalog()?.clone()) as SharedCatalog;
    let gate = AuthorizationDelayGate::default();
    let gated = Arc::new(AuthorizationDelayCatalog::new(catalog, gate.clone())) as SharedCatalog;
    Ok((gated, gate))
}

/// Payload-free evidence for the credential-expiry/rotation intersection.
///
/// The `*_remaining_ms` values are sampled at the same monotonic observation
/// as `expiry_observed_at_ms`; zero means the deadline has passed.  They are
/// deliberately retained so a future caller cannot turn a generic terminal
/// stream observation into an earliest-deadline claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialExpiryRotationEvidence {
    pub scope: &'static str,
    pub relay_count: usize,
    pub actual_cli_processes: usize,
    pub public_ingress: bool,
    pub baseline_echo: bool,
    pub same_uuid_tenant_sibling: bool,
    pub rotation_attempt_observed: bool,
    pub rotation_active_at_expiry: bool,
    pub rotation_candidate_ready_at_expiry: bool,
    pub rotation_old_sockets_open_at_expiry: bool,
    pub rotation_id: String,
    pub rotation_session_id: String,
    pub rotation_epoch: u64,
    pub rotation_owner_id: String,
    pub rotation_old_generation: u64,
    pub rotation_new_generation: u64,
    pub rotation_old_connection_id: String,
    pub rotation_new_connection_id: String,
    pub rotation_started_at_ms: u64,
    pub rotation_deadline_ms: u64,
    pub expiry_observed_at_ms: u64,
    pub consumer_token_expires_at_unix_ms: u64,
    pub consumer_token_expired: bool,
    pub token_identity_exact: bool,
    pub token_issuer: String,
    pub token_audience: String,
    pub token_subject: String,
    pub authorization_delay_injected: bool,
    pub challenge_active_at_expiry: bool,
    pub challenge_started_at_ms: u64,
    pub challenge_deadline_ms: u64,
    pub challenge_admission_deadline_ms: u64,
    /// Exactly one probe is attempted after token expiry while the
    /// authorization gate is still held.  The outcome is writer-side only and
    /// does not claim that a peer received or processed the frame.
    pub post_expiry_probe_attempted: bool,
    pub post_expiry_probe_after_expiry: bool,
    /// Unix epoch milliseconds sampled immediately before the one send call.
    pub post_expiry_probe_at_unix_ms: u64,
    pub post_expiry_probe_outcome: &'static str,
    pub authorization_grant_still_valid: bool,
    pub device_credential_still_valid: bool,
    pub owner_safe_deadline_still_valid: bool,
    pub earliest_deadline: &'static str,
    pub consumer_remaining_ms: u64,
    pub grant_remaining_ms: u64,
    pub device_credential_remaining_ms: u64,
    pub owner_safe_remaining_ms: u64,
    pub rotation_remaining_ms: u64,
    pub expired_stream_terminal: bool,
    pub expired_stream_cause: &'static str,
    pub expired_transport_terminal: bool,
    pub expired_terminal_kind: &'static str,
    pub expired_ingress_rejected: bool,
    pub expired_ingress_status: u16,
    pub expired_ingress_code: &'static str,
    pub expired_ingress_execution: &'static str,
    pub owner_token_retained: bool,
    pub owner_fence_exact: bool,
    pub owner_dispatch_before: u64,
    pub owner_dispatch_after: u64,
    pub rotation_completed_after_expiry: bool,
    pub rotation_completion_latch_observed: bool,
    pub rotation_completion_id: String,
    pub rotation_completion_session_id: String,
    pub rotation_completion_epoch: u64,
    pub rotation_completion_owner_id: String,
    pub rotation_completion_old_generation: u64,
    pub rotation_completion_new_generation: u64,
    pub rotation_completion_old_connection_id: String,
    pub rotation_completion_new_connection_id: String,
    pub sibling_owner_retained: bool,
    pub sibling_stream_survived: bool,
    pub sibling_echo: bool,
    pub cleanup_joined: bool,
    pub elapsed_ms: u64,
}

/// Reject incomplete, impossible, or accidentally widened evidence.  In
/// particular, an observer timeout is never accepted as the stream terminal
/// outcome and a rotation snapshot cannot stand in for a credential expiry.
pub fn validate_credential_expiry_rotation_evidence(
    evidence: &CredentialExpiryRotationEvidence,
) -> Result<()> {
    if evidence.scope != "consumer_credential_expiry_during_scheduled_rotation" {
        return Err(HarnessError::Process(
            "credential-expiry evidence scope was not the bounded consumer/rotation case".into(),
        ));
    }
    if evidence.relay_count != 3 || evidence.actual_cli_processes != 2 {
        return Err(HarnessError::Process(format!(
            "credential-expiry gate expected three relays and two actual CLI processes, observed relays={} processes={}",
            evidence.relay_count, evidence.actual_cli_processes
        )));
    }
    let required = [
        ("public_ingress", evidence.public_ingress),
        ("baseline_echo", evidence.baseline_echo),
        (
            "same_uuid_tenant_sibling",
            evidence.same_uuid_tenant_sibling,
        ),
        (
            "rotation_attempt_observed",
            evidence.rotation_attempt_observed,
        ),
        (
            "rotation_active_at_expiry",
            evidence.rotation_active_at_expiry,
        ),
        (
            "rotation_candidate_ready_at_expiry",
            evidence.rotation_candidate_ready_at_expiry,
        ),
        (
            "rotation_old_sockets_open_at_expiry",
            evidence.rotation_old_sockets_open_at_expiry,
        ),
        ("consumer_token_expired", evidence.consumer_token_expired),
        ("token_identity_exact", evidence.token_identity_exact),
        (
            "authorization_delay_injected",
            evidence.authorization_delay_injected,
        ),
        (
            "challenge_active_at_expiry",
            evidence.challenge_active_at_expiry,
        ),
        (
            "post_expiry_probe_attempted",
            evidence.post_expiry_probe_attempted,
        ),
        (
            "post_expiry_probe_after_expiry",
            evidence.post_expiry_probe_after_expiry,
        ),
        (
            "authorization_grant_still_valid",
            evidence.authorization_grant_still_valid,
        ),
        (
            "device_credential_still_valid",
            evidence.device_credential_still_valid,
        ),
        (
            "owner_safe_deadline_still_valid",
            evidence.owner_safe_deadline_still_valid,
        ),
        ("expired_stream_terminal", evidence.expired_stream_terminal),
        (
            "expired_ingress_rejected",
            evidence.expired_ingress_rejected,
        ),
        ("owner_token_retained", evidence.owner_token_retained),
        ("owner_fence_exact", evidence.owner_fence_exact),
        (
            "rotation_completed_after_expiry",
            evidence.rotation_completed_after_expiry,
        ),
        (
            "rotation_completion_latch_observed",
            evidence.rotation_completion_latch_observed,
        ),
        ("sibling_owner_retained", evidence.sibling_owner_retained),
        ("sibling_stream_survived", evidence.sibling_stream_survived),
        ("sibling_echo", evidence.sibling_echo),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, value)| !value) {
        return Err(HarnessError::Process(format!(
            "M7-I06 credential-expiry/rotation evidence omitted {name}"
        )));
    }
    if evidence.rotation_id.is_empty()
        || evidence.rotation_session_id.is_empty()
        || evidence.rotation_owner_id.is_empty()
        || evidence.rotation_epoch == 0
        || evidence.rotation_old_generation == 0
        || evidence.rotation_new_generation <= evidence.rotation_old_generation
        || evidence.rotation_old_connection_id.is_empty()
        || evidence.rotation_new_connection_id.is_empty()
        || evidence.rotation_old_connection_id == evidence.rotation_new_connection_id
        || evidence.rotation_started_at_ms >= evidence.expiry_observed_at_ms
        || evidence.expiry_observed_at_ms >= evidence.rotation_deadline_ms
        || evidence.rotation_completion_id != evidence.rotation_id
        || evidence.rotation_completion_session_id != evidence.rotation_session_id
        || evidence.rotation_completion_epoch != evidence.rotation_epoch
        || evidence.rotation_completion_owner_id != evidence.rotation_owner_id
        || evidence.rotation_completion_old_generation != evidence.rotation_old_generation
        || evidence.rotation_completion_new_generation != evidence.rotation_new_generation
        || evidence.rotation_completion_old_connection_id != evidence.rotation_old_connection_id
        || evidence.rotation_completion_new_connection_id != evidence.rotation_new_connection_id
        || evidence.rotation_completion_old_connection_id
            == evidence.rotation_completion_new_connection_id
        || evidence.token_issuer.is_empty()
        || evidence.token_audience.is_empty()
        || evidence.token_subject.is_empty()
        || evidence.challenge_started_at_ms == 0
        || evidence.challenge_deadline_ms <= evidence.challenge_started_at_ms
        || evidence.challenge_deadline_ms - evidence.challenge_started_at_ms
            != u64::try_from(AUTHORIZATION_CHALLENGE_INTERVAL.as_millis()).unwrap_or(u64::MAX)
        || evidence.challenge_admission_deadline_ms == 0
    {
        return Err(HarnessError::Process(
            "credential-expiry evidence did not place expiry strictly inside one rotation attempt"
                .into(),
        ));
    }
    if evidence.consumer_remaining_ms != 0
        || evidence.grant_remaining_ms == 0
        || evidence.device_credential_remaining_ms == 0
        || evidence.owner_safe_remaining_ms == 0
        || evidence.rotation_remaining_ms == 0
        || evidence.earliest_deadline != "consumer_credential"
    {
        return Err(HarnessError::Process(
            "credential-expiry evidence did not prove the consumer credential was the earliest deadline"
            .into(),
        ));
    }
    if evidence.expiry_observed_at_ms < evidence.challenge_started_at_ms
        || evidence.expiry_observed_at_ms >= evidence.challenge_deadline_ms
        || evidence.challenge_admission_deadline_ms <= evidence.expiry_observed_at_ms
        || evidence.consumer_token_expires_at_unix_ms == 0
        || evidence.post_expiry_probe_at_unix_ms == 0
        || evidence.post_expiry_probe_at_unix_ms < evidence.consumer_token_expires_at_unix_ms
        || !matches!(
            evidence.post_expiry_probe_outcome,
            "local_write_accepted" | "local_write_rejected"
        )
    {
        return Err(HarnessError::Process(format!(
            "credential-expiry evidence did not retain the exact post-expiry probe observation (expiry_observed_at_ms={}, challenge_started_at_ms={}, challenge_deadline_ms={}, challenge_admission_deadline_ms={}, token_expires_at_unix_ms={}, probe_at_unix_ms={}, probe_attempted={}, probe_after_expiry={}, probe_outcome={})",
            evidence.expiry_observed_at_ms,
            evidence.challenge_started_at_ms,
            evidence.challenge_deadline_ms,
            evidence.challenge_admission_deadline_ms,
            evidence.consumer_token_expires_at_unix_ms,
            evidence.post_expiry_probe_at_unix_ms,
            evidence.post_expiry_probe_attempted,
            evidence.post_expiry_probe_after_expiry,
            evidence.post_expiry_probe_outcome,
        )));
    }
    let socket_terminal = matches!(
        evidence.expired_terminal_kind,
        "close_or_eof" | "transport_error"
    );
    let explicit_socket_unknown =
        evidence.expired_terminal_kind == "explicit_unknown_after_authoritative_terminal";
    if evidence.expired_stream_cause != "AUTHORIZATION_EXPIRED"
        || (!socket_terminal && !explicit_socket_unknown)
        || evidence.expired_transport_terminal != socket_terminal
        || evidence.expired_ingress_status != 401
        || evidence.expired_ingress_code != "UNAUTHORIZED"
        || evidence.expired_ingress_execution != "not_dispatched"
    {
        return Err(HarnessError::Process(
            "credential-expiry evidence did not retain the exact typed authorization outcome"
                .into(),
        ));
    }
    if evidence.owner_dispatch_after != evidence.owner_dispatch_before
        || evidence
            .owner_dispatch_after
            .saturating_sub(evidence.owner_dispatch_before)
            > MAX_DISPATCH_DELTA
    {
        return Err(HarnessError::Process(
            "expired credential probe advanced owner application dispatch".into(),
        ));
    }
    if evidence.elapsed_ms == 0 {
        return Err(HarnessError::Process(
            "credential-expiry evidence reported zero elapsed time".into(),
        ));
    }
    Ok(())
}

/// Handles owned by this isolated phase.  The production cluster and Redis
/// namespace are owned by the parent wrapper; CLI processes, public streams,
/// profiles, and the owner identities observed here are joined before this
/// function returns on both success and failure.
struct ExpiryResources {
    profile_roots: Vec<TempDir>,
    profiles: Vec<DeviceProfile>,
    process_a: Option<ManagedProcess>,
    process_b: Option<ManagedProcess>,
    stream_a: Option<ConsumerStream>,
    barrier_stream: Option<ConsumerStream>,
    stream_b: Option<ConsumerStream>,
    rotation_proxy: Option<ProxyHandle>,
    owner_a: Option<(Uuid, Uuid)>,
    owner_b: Option<(Uuid, Uuid)>,
}

impl ExpiryResources {
    fn new() -> Self {
        Self {
            profile_roots: Vec::new(),
            profiles: Vec::new(),
            process_a: None,
            process_b: None,
            stream_a: None,
            barrier_stream: None,
            stream_b: None,
            rotation_proxy: None,
            owner_a: None,
            owner_b: None,
        }
    }

    async fn cleanup(mut self, cluster: &ProductionCluster) -> Result<()> {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut errors = Vec::new();
        for (label, stream) in [
            ("tenant-A expired stream", self.stream_a.take()),
            (
                "tenant-A rotation barrier stream",
                self.barrier_stream.take(),
            ),
            ("tenant-B sibling stream", self.stream_b.take()),
        ] {
            if let Some(mut stream) = stream {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    errors.push(format!("{label} cleanup exceeded the shared deadline"));
                } else {
                    match timeout(remaining, stream.close()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            errors.push(format!("{label} cleanup failed: {error}"));
                        }
                        Err(_) => errors.push(format!("{label} cleanup timed out")),
                    }
                }
            }
        }
        for (label, process) in [
            ("tenant-A CLI", self.process_a.take()),
            ("tenant-B CLI", self.process_b.take()),
        ] {
            if let Some(mut process) = process {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    errors.push(format!("{label} cleanup exceeded the shared deadline"));
                }
                // Always retain ownership through the explicit stop/reap path,
                // even when the shared scenario deadline has already elapsed.
                // Dropping ManagedProcess here would only request kill-on-drop
                // and would lose the child/output join evidence.
                let stop_request = process.request_stop().await;
                // Capture the bounded, redacted terminal record before
                // consuming the child in shutdown. A nonzero exit is never
                // treated as success; this evidence distinguishes the
                // connector's actual transport/protocol cause from a reaper
                // failure without retaining raw CLI text. With no shared time
                // left this samples already-buffered output only.
                let diagnostics = cli_terminal_diagnostics_with_budget(
                    &mut process,
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await;
                // ManagedProcess owns the child and output drains. Do not
                // place its bounded shutdown/reap behind another cancellable
                // timeout. A zero grace deliberately enters its forced-reap
                // path while retaining the owned join result.
                let shutdown_remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(5));
                let shutdown = process.shutdown(shutdown_remaining).await;
                match (stop_request, shutdown) {
                    (Ok(()), Ok(status)) if status.success() => {}
                    (Ok(()), Ok(status)) => {
                        errors.push(format!("{label} exited with {status}; {diagnostics}"));
                    }
                    (Ok(()), Err(error)) | (Err(error), Ok(_)) => {
                        errors.push(format!("{label} cleanup failed: {error}; {diagnostics}"));
                    }
                    (Err(stop), Err(shutdown)) => errors.push(format!(
                        "{label} cleanup failed: {stop}; {shutdown}; {diagnostics}"
                    )),
                }
            }
        }
        // Stop connectors before closing the device proxy. Closing the proxy
        // first turns an intentional SIGINT shutdown into a transport-error
        // exit and can hide the actual terminal cause in cleanup diagnostics.
        if let Some(mut proxy) = self.rotation_proxy.take() {
            match proxy
                .shutdown_until(tokio::time::Instant::from_std(deadline))
                .await
            {
                Ok(()) => {}
                Err(error) => {
                    errors.push(format!("tenant-A rotation proxy cleanup failed: {error}"))
                }
            }
        }
        for (label, owner) in [
            ("tenant-A owner", self.owner_a.take()),
            ("tenant-B owner", self.owner_b.take()),
        ] {
            if let Some((tenant_id, device_id)) = owner {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    errors.push(format!("{label} release exceeded the shared deadline"));
                } else {
                    match timeout(remaining, cluster.wait_for_no_owner(tenant_id, device_id)).await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            errors.push(format!("{label} release failed: {error}"));
                        }
                        Err(_) => errors.push(format!("{label} was not released before cleanup")),
                    }
                }
            }
        }
        for (label, fanout) in [
            ("tenant-A device fanout", &cluster.device_fanout),
            ("tenant-B device fanout", &cluster.tenant_b_fanout),
        ] {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                errors.push(format!("{label} did not drain before cleanup"));
            } else {
                match timeout(remaining, wait_for_fanout_drained(fanout, label)).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => errors.push(format!("{label} drain failed: {error}")),
                    Err(_) => errors.push(format!("{label} did not drain before cleanup")),
                }
            }
        }
        // Profiles are dropped last, after their CLI children and output
        // drains have joined, so no process can outlive its certificate files.
        self.profiles.clear();
        self.profile_roots.clear();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(errors.join("; ")))
        }
    }
}

#[derive(Clone, Debug)]
struct TokenDeadline {
    claims: OidcClaims,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedRotation {
    attempt: RotationAttemptIdentity,
    started_at_ms: u64,
    deadline_ms: u64,
    old_generation: u64,
    old_connection_id: String,
    candidate_generation: u64,
    candidate_connection_id: String,
}

fn selected_rotation_from_barrier(evidence: &RotationBarrierEvidence) -> SelectedRotation {
    SelectedRotation {
        attempt: evidence.attempt.clone(),
        started_at_ms: evidence.started_at_ms,
        deadline_ms: evidence.deadline_ms,
        old_generation: evidence.old_generation,
        old_connection_id: evidence.old_connection_id.clone(),
        candidate_generation: evidence.candidate_generation,
        candidate_connection_id: evidence.candidate_connection_id.clone(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorizationChallengeBarrier {
    started_at_ms: u64,
    challenge_deadline_ms: u64,
    admission_deadline_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct PostExpiryProbeObservation {
    attempted: bool,
    attempted_after_expiry: bool,
    attempted_at_unix_ms: u64,
    outcome: &'static str,
}

#[derive(Clone, Debug)]
struct ExpiryObservation {
    attempt: RotationAttemptIdentity,
    started_at_ms: u64,
    deadline_ms: u64,
    expiry_observed_at_ms: u64,
    consumer_remaining_ms: u64,
    grant_remaining_ms: u64,
    device_remaining_ms: u64,
    owner_safe_remaining_ms: u64,
    rotation_remaining_ms: u64,
    transport_terminal: bool,
    terminal_kind: &'static str,
    candidate_ready_at_expiry: bool,
    old_sockets_open_at_expiry: bool,
    challenge: AuthorizationChallengeBarrier,
    challenge_active_at_expiry: bool,
    post_expiry_probe: PostExpiryProbeObservation,
}

#[derive(Clone, Debug)]
struct RotationCompletionObservation {
    attempt: RotationAttemptIdentity,
    latch_observed: bool,
}

fn parse_token_deadline(
    harness: &RunningHarness,
    token: &str,
    expected_subject: &str,
) -> Result<TokenDeadline> {
    let key = DecodingKey::from_rsa_pem(harness.oidc.public_key_pem().as_bytes())
        .map_err(|error| HarnessError::InvalidInput(format!("reading OIDC public key: {error}")))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&harness.oidc.audience]);
    validation.set_issuer(&[&harness.oidc.issuer]);
    validation.sub = Some(expected_subject.to_owned());
    validation.leeway = 0;
    let claims: OidcClaims = decode(token, &key, &validation)
        .map_err(|error| HarnessError::InvalidInput(format!("decoding OIDC claims: {error}")))?
        .claims;
    if claims.iss != harness.oidc.issuer
        || claims.aud != harness.oidc.audience
        || claims.sub != expected_subject
    {
        return Err(HarnessError::InvalidInput(
            "short-lived OIDC token issuer/audience/subject did not match the authoritative fixture identity"
                .into(),
        ));
    }
    let expires_at = DateTime::from_timestamp(claims.exp, 0).ok_or_else(|| {
        HarnessError::InvalidInput("OIDC consumer expiry was outside chrono's range".into())
    })?;
    Ok(TokenDeadline { claims, expires_at })
}

fn remaining_ms(deadline: DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    (deadline - now).num_milliseconds().max(0) as u64
}

fn owner_id_for_token(token: &OwnerToken) -> Result<String> {
    let canonical = serde_json::to_vec(token)
        .map_err(|error| HarnessError::Process(format!("encoding owner identity: {error}")))?;
    Ok(Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn session_for<'a>(
    snapshot: &'a RelaySnapshot,
    owner: &OwnerToken,
    device_id: Uuid,
) -> Result<&'a RelaySessionSnapshot> {
    let tenant = owner.tenant_id.to_string();
    let device = device_id.to_string();
    snapshot
        .sessions
        .iter()
        .find(|session| {
            session.tenant_id == tenant
                && session.device_id == device
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
        })
        .ok_or_else(|| HarnessError::Process("owner session was absent from relay snapshot".into()))
}

fn stream_for(session: &RelaySessionSnapshot, stream_id: u64) -> Result<&RelayStreamSnapshot> {
    session
        .streams
        .iter()
        .find(|stream| stream.stream_id == stream_id)
        .ok_or_else(|| {
            HarnessError::Process("tested consumer stream was absent from snapshot".into())
        })
}

async fn wait_for_exact_new_admitted_stream(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    device_id: Uuid,
    excluded_stream_id: u64,
    deadline: Instant,
) -> Result<(RelaySnapshot, u64)> {
    let relay = cluster.relay(&owner.node_id)?;
    loop {
        let snapshot = relay.snapshot().await?;
        let session = session_for(&snapshot, owner, device_id)?;
        let candidates = session
            .streams
            .iter()
            .filter(|stream| {
                stream.stream_id != excluded_stream_id
                    && !stream.terminal
                    && !stream.authorization_in_flight
            })
            .collect::<Vec<_>>();
        if candidates.len() > 1 {
            return Err(HarnessError::Process(
                "owner session exposed more than one nonterminal stream besides the selected barrier stream"
                    .into(),
            ));
        }
        if let Some(stream) = candidates.into_iter().next() {
            let stream_id = stream.stream_id;
            return Ok((snapshot, stream_id));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "short-lived consumer stream did not reach an admitted snapshot distinct from the barrier stream"
                    .into(),
            ));
        }
        sleep(EXPIRY_POLL).await;
    }
}

/// Already-admitted consumer streams that must remain live while setup
/// waits for the first rotation window.  Each is an independent public
/// stream, but the barrier stream is the only one paused after this helper
/// returns.
struct PreRotationKeepalives<'a> {
    barrier: &'a mut ConsumerStream,
    barrier_canary: &'a [u8],
    short: &'a mut ConsumerStream,
    short_canary: &'a [u8],
    sibling: &'a mut ConsumerStream,
    sibling_canary: &'a [u8],
}

impl PreRotationKeepalives<'_> {
    async fn round_trip_all(&mut self) -> Result<()> {
        self.barrier
            .round_trip(
                b"m7-i06-expiry-pre-rotation-barrier-keepalive",
                self.barrier_canary,
            )
            .await
            .map_err(|error| {
                HarnessError::Process(format!(
                    "tenant-A barrier stream stopped making progress before rotation hold: {error}"
                ))
            })?;
        self.short
            .round_trip(
                b"m7-i06-expiry-pre-rotation-short-keepalive",
                self.short_canary,
            )
            .await
            .map_err(|error| {
                HarnessError::Process(format!(
                    "tenant-A short stream stopped making progress before rotation hold: {error}"
                ))
            })?;
        self.sibling
            .round_trip(
                b"m7-i06-expiry-pre-rotation-sibling-keepalive",
                self.sibling_canary,
            )
            .await
            .map_err(|error| {
                HarnessError::Process(format!(
                    "tenant-B sibling stream stopped making progress before rotation hold: {error}"
                ))
            })?;
        Ok(())
    }
}

/// Keep every already-admitted required stream active until just before the
/// first scheduled rotation.  The positive echoes are a bounded fixture gate:
/// they keep the existing connections from entering the normal idle/FIN path
/// while setup finishes, and the final authoritative snapshot rejects any
/// attempt that started before the barrier was installed.  A missed window is
/// an error; the caller never retries by selecting a later rotation.
async fn wait_for_pre_rotation_barrier_window(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    device_id: Uuid,
    expected_rotations: u64,
    streams: &mut PreRotationKeepalives<'_>,
    timing: PreRotationTiming,
) -> Result<()> {
    let arm_at = timing.ready_at
        + Duration::from_secs(EXPIRY_ROTATION.interval_seconds)
            .saturating_sub(Duration::from_millis(ROTATION_ARM_LEAD_MS));
    let relay = cluster.relay(&owner.node_id)?;
    loop {
        let snapshot = relay.snapshot().await?;
        let session = session_for(&snapshot, owner, device_id)?;
        let attempt_started = session
            .rotation_diagnostics
            .as_ref()
            .is_some_and(|diagnostics| diagnostics.attempt_active || diagnostics.attempt.is_some());
        if session.phase != "active"
            || session.rotations_completed != expected_rotations
            || attempt_started
        {
            return Err(HarnessError::Process(
                "credential-expiry fixture missed the first pre-rotation barrier window; refusing to pause a later attempt"
                    .into(),
            ));
        }

        let now = Instant::now();
        if now >= arm_at {
            return Ok(());
        }
        let remaining = timing.deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "credential-expiry fixture reached its phase deadline before the pre-rotation barrier window"
                    .into(),
            ));
        }
        let keepalive_window = remaining
            .min(arm_at.saturating_duration_since(now))
            .min(Duration::from_secs(2));
        timeout(keepalive_window, streams.round_trip_all())
            .await
            .map_err(|_| {
                HarnessError::Timeout(
                    "credential-expiry pre-rotation keepalives exceeded their bounded window"
                        .into(),
                )
            })??;
        let remaining = timing.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "credential-expiry fixture phase deadline elapsed during pre-rotation keepalive"
                    .into(),
            ));
        }
        let until_arm = arm_at.saturating_duration_since(Instant::now());
        if !until_arm.is_zero() {
            sleep(EXPIRY_POLL.min(until_arm).min(remaining)).await;
        }
    }
}

fn selected_rotation(
    session: &RelaySessionSnapshot,
    owner: &OwnerToken,
    expected_owner_id: &str,
) -> Result<Option<SelectedRotation>> {
    let Some(diagnostics) = session.rotation_diagnostics.as_ref() else {
        return Ok(None);
    };
    let Some(attempt) = diagnostics.attempt.as_ref() else {
        return Ok(None);
    };
    if !diagnostics.attempt_active {
        return Ok(None);
    }
    if attempt.session_id != owner.session_id
        || attempt.epoch != owner.epoch
        || attempt.owner_id != expected_owner_id
    {
        return Err(HarnessError::Process(
            "credential-expiry rotation attempt did not match the full owner fence".into(),
        ));
    }
    let Some(started_at_ms) = session.rotation_started_at_ms else {
        return Ok(None);
    };
    let Some(deadline_ms) = session.rotation_deadline_ms else {
        return Ok(None);
    };
    let Some(candidate_generation) = session.candidate_generation else {
        return Ok(None);
    };
    let Some(candidate_connection_id) = session.candidate_connection_id.as_ref() else {
        return Ok(None);
    };
    if !diagnostics.candidate_ready
        || diagnostics
            .old_socket_closed
            .into_iter()
            .any(|closed| closed)
        || !matches!(
            session.phase.as_str(),
            "preparing" | "quiescing" | "draining"
        )
        || session.active_generation != attempt.old_generation
        || session.active_connection_id != attempt.old_connection_id
        || candidate_generation != attempt.new_generation
        || candidate_connection_id != &attempt.new_connection_id
        || attempt.old_connection_id == attempt.new_connection_id
        || started_at_ms >= deadline_ms
    {
        return Ok(None);
    }
    Ok(Some(SelectedRotation {
        attempt: attempt.clone(),
        started_at_ms,
        deadline_ms,
        old_generation: attempt.old_generation,
        old_connection_id: attempt.old_connection_id.clone(),
        candidate_generation,
        candidate_connection_id: candidate_connection_id.clone(),
    }))
}

fn same_rotation_records(left: &SelectedRotation, right: &SelectedRotation) -> bool {
    left.attempt == right.attempt
        && left.started_at_ms == right.started_at_ms
        && left.deadline_ms == right.deadline_ms
        && left.old_generation == right.old_generation
        && left.old_connection_id == right.old_connection_id
        && left.candidate_generation == right.candidate_generation
        && left.candidate_connection_id == right.candidate_connection_id
}

fn exact_unauthorized(status: u16, body: Option<&[u8]>) -> bool {
    if status != 401 {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    if body.len() > MAX_ERROR_BODY_BYTES {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    value.get("code").and_then(serde_json::Value::as_str) == Some("UNAUTHORIZED")
        && value.get("execution").and_then(serde_json::Value::as_str) == Some("not_dispatched")
}

async fn wait_for_stable_owner(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    device_id: Uuid,
    deadline: Instant,
) -> Result<RelaySnapshot> {
    let relay = cluster.relay(&owner.node_id)?;
    loop {
        let snapshot = relay.snapshot().await?;
        let session = session_for(&snapshot, owner, device_id)?;
        if session.phase == "active"
            && session.candidate_generation.is_none()
            && session.rotation_started_at_ms.is_none()
            && session.rotation_deadline_ms.is_none()
        {
            return Ok(snapshot);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "owner did not return to an unambiguous active phase".into(),
            ));
        }
        sleep(EXPIRY_POLL).await;
    }
}

async fn wait_for_authorization_challenge(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    stream_id: u64,
    selected: &SelectedRotation,
    gate: &AuthorizationDelayGate,
    token_expires_at: DateTime<Utc>,
    deadline: Instant,
) -> Result<AuthorizationChallengeBarrier> {
    gate.wait_for_hit(deadline).await?;
    let relay = cluster.relay(&owner.node_id)?;
    let expected_owner_id = owner_id_for_token(owner)?;
    loop {
        let snapshot = relay.snapshot().await?;
        let session = session_for(&snapshot, owner, owner.device_id)?;
        let Some(current) = selected_rotation(session, owner, &expected_owner_id)? else {
            return Err(HarnessError::Process(
                "selected candidate/old rotation barrier disappeared while the authorization gate was held"
                    .into(),
            ));
        };
        if !same_rotation_records(&current, selected) {
            return Err(HarnessError::Process(
                "authorization challenge was observed under a different rotation attempt".into(),
            ));
        }
        let stream = stream_for(session, stream_id)?;
        if stream.terminal {
            return Err(HarnessError::Process(
                "authorization challenge became terminal before consumer expiry".into(),
            ));
        }
        if stream.authorization_in_flight {
            let started_at_ms = stream.authorization_started_at_ms.ok_or_else(|| {
                HarnessError::Process(
                    "authorization challenge omitted its monotonic start sample".into(),
                )
            })?;
            let challenge_deadline_ms = stream.authorization_deadline_ms.ok_or_else(|| {
                HarnessError::Process(
                    "authorization challenge omitted its monotonic deadline sample".into(),
                )
            })?;
            let admission_deadline_ms =
                stream.authorization_admission_deadline_ms.ok_or_else(|| {
                    HarnessError::Process(
                        "authorization challenge omitted its prior admission deadline".into(),
                    )
                })?;
            let expected =
                u64::try_from(AUTHORIZATION_CHALLENGE_INTERVAL.as_millis()).unwrap_or(u64::MAX);
            let token_remaining_ms = remaining_ms(token_expires_at, Utc::now());
            let projected_token_expiry_ms =
                snapshot.monotonic_now_ms.saturating_add(token_remaining_ms);
            let challenge_margin_ms = CHALLENGE_EXPIRY_SAFETY_MARGIN_MS;
            if challenge_deadline_ms.saturating_sub(started_at_ms) != expected
                || admission_deadline_ms <= started_at_ms
                || snapshot.monotonic_now_ms >= challenge_deadline_ms
                || challenge_deadline_ms
                    <= projected_token_expiry_ms.saturating_add(challenge_margin_ms)
            {
                return Err(HarnessError::Process(format!(
                    "authorization challenge did not extend past projected consumer expiry with margin (challenge_deadline_ms={challenge_deadline_ms} projected_token_expiry_ms={projected_token_expiry_ms} margin_ms={challenge_margin_ms})"
                )));
            }
            return Ok(AuthorizationChallengeBarrier {
                started_at_ms,
                challenge_deadline_ms,
                admission_deadline_ms,
            });
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "authorization refresh challenge was not held before the fixed phase deadline"
                    .into(),
            ));
        }
        sleep(EXPIRY_POLL.min(deadline.saturating_duration_since(Instant::now()))).await;
    }
}

async fn attempt_post_expiry_probe(
    stream: &mut ConsumerStream,
    deadline: Instant,
    token_expires_at: DateTime<Utc>,
) -> Result<PostExpiryProbeObservation> {
    let payload = b"m7-i06-expired-consumer-probe";
    if payload.len() > super::MAX_RECORD_BYTES {
        return Err(HarnessError::InvalidInput(
            "credential-expiry probe exceeded its bound".into(),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        HarnessError::InvalidInput("credential-expiry probe length overflow".into())
    })?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    let attempted_at = Utc::now();
    if attempted_at < token_expires_at {
        return Err(HarnessError::Timeout(
            "credential-expiry probe was scheduled before token expiry".into(),
        ));
    }
    let attempted_at_unix_ms = u64::try_from(attempted_at.timestamp_millis()).map_err(|_| {
        HarnessError::Process("credential-expiry probe timestamp was before Unix epoch".into())
    })?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(
            "credential-expiry probe had no bounded post-expiry send window".into(),
        ));
    }
    let outcome = match timeout(remaining, stream.socket.send(Message::Binary(frame.into()))).await
    {
        Err(_) => {
            return Err(HarnessError::Timeout(
                "post-expiry consumer probe write timed out; no expiry evidence was accepted"
                    .into(),
            ));
        }
        Ok(Err(_)) => "local_write_rejected",
        Ok(Ok(())) => "local_write_accepted",
    };
    Ok(PostExpiryProbeObservation {
        attempted: true,
        attempted_after_expiry: attempted_at >= token_expires_at,
        attempted_at_unix_ms,
        outcome,
    })
}

/// Inputs for the bounded expiry failure snapshot.  Keeping these in one
/// context also prevents diagnostic-only arguments from drifting between the
/// gate-window, challenge, and expiry stages.
struct ExpiryPhaseDiagnostic<'a> {
    cluster: &'a ProductionCluster,
    owner: &'a OwnerToken,
    device_id: Uuid,
    stream_id: u64,
    selected: &'a SelectedRotation,
    gate: &'a AuthorizationDelayGate,
    token_expires_at: DateTime<Utc>,
    phase_deadline: Instant,
}

/// Preserve the exact phase and selected stream state when a bounded expiry
/// wait fails.  The live gate can fail because the old carrier reaches its
/// overlap deadline first; a plain `owner session was absent` error cannot
/// distinguish that from a gate that never armed or a refresh challenge that
/// never entered flight.  This helper is observation-only and has its own
/// one-second cap so error reporting cannot turn into an unbounded wait.
async fn expiry_phase_diagnostics(context: &ExpiryPhaseDiagnostic<'_>, stage: &str) -> String {
    let cluster = context.cluster;
    let owner = context.owner;
    let device_id = context.device_id;
    let stream_id = context.stream_id;
    let selected = context.selected;
    let gate = context.gate;
    let token_expires_at = context.token_expires_at;
    let phase_deadline = context.phase_deadline;
    let now = Utc::now();
    let mut detail = format!(
        "stage={stage} now={now} token_expires_at={token_expires_at} token_remaining_ms={} phase_remaining_ms={} selected_attempt={} selected_session={} selected_epoch={} selected_started_ms={} selected_deadline_ms={} stream_id={} gate=[{}]",
        remaining_ms(token_expires_at, now),
        phase_deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
        selected.attempt.rotation_id,
        selected.attempt.session_id,
        selected.attempt.epoch,
        selected.started_at_ms,
        selected.deadline_ms,
        stream_id,
        gate.diagnostic_summary(),
    );
    let relay = match cluster.relay(&owner.node_id) {
        Ok(relay) => relay,
        Err(error) => {
            detail.push_str(&format!(" snapshot_relay_error={error}"));
            return detail;
        }
    };
    let snapshot_budget = phase_deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(1));
    if snapshot_budget.is_zero() {
        detail.push_str(" snapshot=skipped_deadline");
        return detail;
    }
    let snapshot = match timeout(snapshot_budget, relay.snapshot()).await {
        Ok(Ok(snapshot)) => snapshot,
        Ok(Err(error)) => {
            detail.push_str(&format!(" snapshot_error={error}"));
            return detail;
        }
        Err(_) => {
            detail.push_str(" snapshot_error=timeout");
            return detail;
        }
    };
    let expected_owner_id =
        owner_id_for_token(owner).unwrap_or_else(|error| format!("owner-id-error:{error}"));
    let Some(session) = snapshot.sessions.iter().find(|session| {
        session.tenant_id == owner.tenant_id.to_string()
            && session.device_id == device_id.to_string()
            && session.session_id == owner.session_id
            && session.epoch == owner.epoch
    }) else {
        detail.push_str(&format!(
            " snapshot_monotonic_ms={} session=absent owner_node={} owner_session={} owner_epoch={}",
            snapshot.monotonic_now_ms, owner.node_id, owner.session_id, owner.epoch
        ));
        return detail;
    };
    let rotation = match selected_rotation(session, owner, &expected_owner_id) {
        Ok(Some(current)) => format!(
            "present id={} session={} epoch={} owner_id={} active={} started_ms={} deadline_ms={} old_gen={} new_gen={} old_conn={} new_conn={}",
            current.attempt.rotation_id,
            current.attempt.session_id,
            current.attempt.epoch,
            current.attempt.owner_id,
            session
                .rotation_diagnostics
                .as_ref()
                .is_some_and(|diagnostics| diagnostics.attempt_active),
            current.started_at_ms,
            current.deadline_ms,
            current.old_generation,
            current.candidate_generation,
            current.old_connection_id,
            current.candidate_connection_id,
        ),
        Ok(None) => "absent".to_owned(),
        Err(error) => format!("error={error}"),
    };
    let stream = match stream_for(session, stream_id) {
        Ok(stream) => format!(
            "present terminal={} auth_in_flight={} auth_started_ms={:?} auth_deadline_ms={:?} admission_deadline_ms={:?} failure_code={:?} recv_contiguous={} delivered_contiguous={} last_emitted={} peer_acked={}",
            stream.terminal,
            stream.authorization_in_flight,
            stream.authorization_started_at_ms,
            stream.authorization_deadline_ms,
            stream.authorization_admission_deadline_ms,
            stream.authorization_failure_code,
            stream.recv_contiguous_connector_to_relay,
            stream.delivered_contiguous_connector_to_relay,
            stream.last_emitted_relay_to_connector,
            stream.peer_acked_relay_to_connector,
        ),
        Err(error) => format!("error={error}"),
    };
    detail.push_str(&format!(
        " snapshot_monotonic_ms={} phase={} active_generation={} active_connection_id={} candidate_generation={:?} candidate_connection_id={:?} rotation={rotation} stream={stream}",
        snapshot.monotonic_now_ms,
        session.phase,
        session.active_generation,
        session.active_connection_id,
        session.candidate_generation,
        session.candidate_connection_id,
    ));
    detail
}

async fn read_expiry_probe_terminal(
    stream: &mut ConsumerStream,
    deadline: Instant,
) -> Result<&'static str> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok("explicit_unknown_after_authoritative_terminal");
        }
        match timeout(remaining, stream.socket.next()).await {
            Err(_) => return Ok("explicit_unknown_after_authoritative_terminal"),
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => return Ok("close_or_eof"),
            Ok(Some(Err(_))) => return Ok("transport_error"),
            Ok(Some(Ok(Message::Ping(bytes)))) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok("explicit_unknown_after_authoritative_terminal");
                }
                match timeout(remaining, stream.socket.send(Message::Pong(bytes))).await {
                    Err(_) => return Ok("explicit_unknown_after_authoritative_terminal"),
                    Ok(Err(_)) => return Ok("transport_error"),
                    Ok(Ok(())) => {}
                }
            }
            Ok(Some(Ok(Message::Binary(_)))) => {
                return Err(HarnessError::Process(
                    "credential-expiry probe received an application response after the authoritative authorization expiry terminal"
                        .into(),
                ));
            }
            Ok(Some(Ok(Message::Text(_)))) => {
                return Err(HarnessError::Process(
                    "credential-expiry probe received an unexpected text response after the authoritative authorization expiry terminal".into(),
                ));
            }
            Ok(Some(Ok(Message::Pong(_)))) | Ok(Some(Ok(Message::Frame(_)))) => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_gate_window(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    device_id: Uuid,
    expected_owner_id: &str,
    barrier_hold: &RotationBarrierHold<'_>,
    token_expires_at: DateTime<Utc>,
    sibling_stream: &mut ConsumerStream,
    sibling_canary: &[u8],
    deadline: Instant,
) -> Result<()> {
    let mut sibling_progress_observed = false;
    loop {
        barrier_hold
            .assert_held(cluster, owner, device_id, expected_owner_id)
            .await?;
        let remaining_ms = remaining_ms(token_expires_at, Utc::now());
        if remaining_ms == 0 {
            return Err(HarnessError::Timeout(
                "short-lived consumer expired before the authorization gate arm window".into(),
            ));
        }
        if sibling_progress_observed && remaining_ms <= GATE_ARM_REMAINING_MS {
            return Ok(());
        }
        sibling_stream
            .round_trip(b"m7-i06-expiry-sibling-hold", sibling_canary)
            .await
            .map_err(|error| {
                HarnessError::Process(format!(
                    "tenant-B sibling stopped making progress while expiry barrier was held: {error}"
                ))
            })?;
        sibling_progress_observed = true;
        barrier_hold
            .assert_held(cluster, owner, device_id, expected_owner_id)
            .await?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "credential-expiry gate did not reach its near-expiry arm window".into(),
            ));
        }
        sleep(EXPIRY_POLL.min(remaining)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_expiry(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    device_id: Uuid,
    stream_id: u64,
    token: &TokenDeadline,
    selected: &SelectedRotation,
    challenge: AuthorizationChallengeBarrier,
    grant_expires_at: DateTime<Utc>,
    device_expires_at: DateTime<Utc>,
    owner_claim: &OwnerClaim,
    gate: &AuthorizationDelayGate,
    barrier_hold: &RotationBarrierHold<'_>,
    stream: &mut ConsumerStream,
    deadline: Instant,
) -> Result<ExpiryObservation> {
    let relay = cluster.relay(&owner.node_id)?;
    let expected_owner_id = owner_id_for_token(owner)?;
    let mut released = false;
    let mut post_expiry_probe = None;
    let mut challenge_active_at_expiry = false;
    let mut candidate_ready_at_expiry = false;
    let mut old_sockets_open_at_expiry = false;
    let mut last_stream_state = String::from("none");
    loop {
        let snapshot = relay.snapshot().await?;
        let session = match session_for(&snapshot, owner, device_id) {
            Ok(session) => session,
            Err(_) => {
                return Err(HarnessError::Process(format!(
                    "owner session was absent from relay snapshot; last_stream_state={last_stream_state}"
                )));
            }
        };
        let Some(current) = selected_rotation(session, owner, &expected_owner_id)? else {
            return Err(HarnessError::Process(
                "selected candidate/old rotation barrier disappeared before credential expiry"
                    .into(),
            ));
        };
        if !same_rotation_records(&current, selected) {
            return Err(HarnessError::Process(
                "credential expiry crossed into a different rotation attempt".into(),
            ));
        }
        let tested_stream = stream_for(session, stream_id)?;
        last_stream_state = format!(
            "snapshot_monotonic_ms={} authorization_in_flight={} terminal={} failure_code={:?} authorization_started_ms={:?} authorization_deadline_ms={:?}",
            snapshot.monotonic_now_ms,
            tested_stream.authorization_in_flight,
            tested_stream.terminal,
            tested_stream.authorization_failure_code,
            tested_stream.authorization_started_at_ms,
            tested_stream.authorization_deadline_ms,
        );
        let now = Utc::now();
        if now >= token.expires_at && !released {
            let diagnostics = session.rotation_diagnostics.as_ref().ok_or_else(|| {
                HarnessError::Process(
                    "selected rotation omitted diagnostics at the credential expiry boundary"
                        .into(),
                )
            })?;
            candidate_ready_at_expiry = diagnostics.candidate_ready;
            old_sockets_open_at_expiry = diagnostics
                .old_socket_closed
                .into_iter()
                .all(|closed| !closed);
            // The ingress independently enforces this same verified token
            // deadline. Its close may reach the owner while the selected
            // catalog refresh is still held. Accept that ordering only when
            // the owner has already recorded the exact expiry reason; a
            // generic or unrelated terminal cannot satisfy the barrier.
            if (tested_stream.terminal
                && tested_stream.authorization_failure_code != Some("AUTHORIZATION_EXPIRED"))
                || !tested_stream.authorization_in_flight
                || tested_stream.authorization_started_at_ms != Some(challenge.started_at_ms)
                || tested_stream.authorization_deadline_ms != Some(challenge.challenge_deadline_ms)
                || tested_stream.authorization_admission_deadline_ms
                    != Some(challenge.admission_deadline_ms)
                || snapshot.monotonic_now_ms >= challenge.challenge_deadline_ms
                || !candidate_ready_at_expiry
                || !old_sockets_open_at_expiry
                || snapshot.monotonic_now_ms < selected.started_at_ms
                || snapshot.monotonic_now_ms >= selected.deadline_ms
            {
                return Err(HarnessError::Process(
                    "consumer expiry was not observed while the selected rotation and held authorization challenge were both active (untyped terminal, expired challenge or state mismatch)"
                        .into(),
                ));
            }
            let consumer_remaining_ms = remaining_ms(token.expires_at, now);
            let grant_remaining_ms = remaining_ms(grant_expires_at, now);
            let device_remaining_ms = remaining_ms(device_expires_at, now);
            let owner_safe_deadline = owner_claim.lease_expires_at - OWNER_LEASE_SAFETY_MARGIN;
            let owner_safe_remaining_ms = remaining_ms(owner_safe_deadline, now);
            if consumer_remaining_ms != 0
                || grant_remaining_ms == 0
                || device_remaining_ms == 0
                || owner_safe_remaining_ms == 0
            {
                return Err(HarnessError::Process(
                    "consumer expiry did not win against the authoritative grant/device/owner deadlines"
                        .into(),
                ));
            }
            challenge_active_at_expiry = true;
            barrier_hold
                .assert_held(cluster, owner, device_id, &expected_owner_id)
                .await?;
            // Keep the authorization refresh held while making exactly one
            // post-expiry application send attempt.  Its result is a local
            // WebSocket writer observation only; the authoritative relay
            // terminal below is the acceptance proof.
            post_expiry_probe =
                Some(attempt_post_expiry_probe(stream, deadline, token.expires_at).await?);
            gate.release();
            gate.wait_for_completion(deadline).await?;
            gate.wait_for_followups(deadline).await?;
            released = true;
        }
        if released
            && tested_stream.terminal
            && tested_stream.authorization_failure_code == Some("AUTHORIZATION_EXPIRED")
        {
            let expiry_observed_at_ms = snapshot.monotonic_now_ms;
            if expiry_observed_at_ms < selected.started_at_ms
                || expiry_observed_at_ms >= selected.deadline_ms
            {
                return Err(HarnessError::Process(
                    "authorization expiry terminal was outside the selected rotation window".into(),
                ));
            }
            let now = Utc::now();
            let consumer_remaining_ms = remaining_ms(token.expires_at, now);
            let grant_remaining_ms = remaining_ms(grant_expires_at, now);
            let device_remaining_ms = remaining_ms(device_expires_at, now);
            let owner_safe_deadline = owner_claim.lease_expires_at - OWNER_LEASE_SAFETY_MARGIN;
            let owner_safe_remaining_ms = remaining_ms(owner_safe_deadline, now);
            // The typed relay terminal is the acceptance proof.  A socket
            // close/error after that snapshot is useful supplementary
            // transport evidence, but a handler need not remain readable for
            // this fixture to prove post-expiry invalidation.
            let probe_deadline = deadline.min(Instant::now() + EXPIRY_PROBE_TIMEOUT);
            let terminal_kind = read_expiry_probe_terminal(stream, probe_deadline).await?;
            let transport_terminal = matches!(terminal_kind, "close_or_eof" | "transport_error");
            let post_expiry_probe = post_expiry_probe.ok_or_else(|| {
                HarnessError::Process(
                    "authorization expiry terminal was observed without the one post-expiry probe attempt"
                        .into(),
                )
            })?;
            return Ok(ExpiryObservation {
                attempt: selected.attempt.clone(),
                started_at_ms: selected.started_at_ms,
                deadline_ms: selected.deadline_ms,
                expiry_observed_at_ms,
                consumer_remaining_ms,
                grant_remaining_ms,
                device_remaining_ms,
                owner_safe_remaining_ms,
                rotation_remaining_ms: selected.deadline_ms.saturating_sub(expiry_observed_at_ms),
                transport_terminal,
                terminal_kind,
                candidate_ready_at_expiry,
                old_sockets_open_at_expiry,
                challenge,
                challenge_active_at_expiry,
                post_expiry_probe,
            });
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "consumer credential expiry was not observed before the bounded phase deadline"
                    .into(),
            ));
        }
        sleep(EXPIRY_POLL.min(deadline.saturating_duration_since(Instant::now()))).await;
    }
}

struct RotationExpiryWaitContext<'a> {
    cluster: &'a ProductionCluster,
    owner: &'a OwnerToken,
    device_id: Uuid,
    stream_id: u64,
    expected_attempt: &'a RotationAttemptIdentity,
    prior_rotations: u64,
    expiry_observed_at_ms: u64,
    process: &'a mut ManagedProcess,
    deadline: Instant,
}

async fn wait_for_rotation_after_expiry(
    context: RotationExpiryWaitContext<'_>,
) -> Result<RotationCompletionObservation> {
    let RotationExpiryWaitContext {
        cluster,
        owner,
        device_id,
        stream_id,
        expected_attempt,
        prior_rotations,
        expiry_observed_at_ms,
        process,
        deadline,
    } = context;
    let relay = cluster.relay(&owner.node_id)?;
    loop {
        let snapshot = relay.snapshot().await?;
        let Some(session) = snapshot.sessions.iter().find(|session| {
            session.tenant_id == owner.tenant_id.to_string()
                && session.device_id == device_id.to_string()
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
        }) else {
            let diagnostics = post_release_diagnostics(
                &snapshot,
                owner,
                device_id,
                stream_id,
                expected_attempt,
                expiry_observed_at_ms,
                process,
            )
            .await;
            return Err(HarnessError::Process(format!(
                "owner session was absent from relay snapshot; {diagnostics}"
            )));
        };
        if session.rotations_completed > prior_rotations
            && session.phase == "active"
            && session.candidate_generation.is_none()
            && session.rotation_started_at_ms.is_none()
            && session.rotation_deadline_ms.is_none()
            && snapshot.monotonic_now_ms > expiry_observed_at_ms
        {
            let Some(diagnostics) = session.rotation_diagnostics.as_ref() else {
                return Err(HarnessError::Process(
                    "rotation completed without a retained completion latch".into(),
                ));
            };
            let Some(completed_attempt) = diagnostics.attempt.as_ref() else {
                return Err(HarnessError::Process(
                    "rotation completion latch omitted the exact attempt identity".into(),
                ));
            };
            if diagnostics.attempt_active
                || !diagnostics
                    .old_socket_closed
                    .into_iter()
                    .all(|closed| closed)
                || completed_attempt != expected_attempt
                || session.active_generation != expected_attempt.new_generation
                || session.active_connection_id != expected_attempt.new_connection_id
            {
                let diagnostics = post_release_diagnostics(
                    &snapshot,
                    owner,
                    device_id,
                    stream_id,
                    expected_attempt,
                    expiry_observed_at_ms,
                    process,
                )
                .await;
                return Err(HarnessError::Process(format!(
                    "rotation completion latch did not match the expired stream's attempt; {diagnostics}"
                )));
            }
            return Ok(RotationCompletionObservation {
                attempt: completed_attempt.clone(),
                latch_observed: true,
            });
        }
        if Instant::now() >= deadline {
            let diagnostics = post_release_diagnostics(
                &snapshot,
                owner,
                device_id,
                stream_id,
                expected_attempt,
                expiry_observed_at_ms,
                process,
            )
            .await;
            return Err(HarnessError::Timeout(format!(
                "scheduled rotation did not complete after credential expiry; {diagnostics}"
            )));
        }
        sleep(EXPIRY_POLL).await;
    }
}

const POST_RELEASE_CLI_DIAGNOSTIC_WAIT: Duration = Duration::from_millis(250);
const POST_RELEASE_CLI_DIAGNOSTIC_POLL: Duration = Duration::from_millis(10);

/// Capture the real connector's terminal status and JSON protocol code after
/// the relay has removed its owner session.  This is deliberately bounded and
/// payload-free: diagnostic output never includes the CLI error message,
/// paths, credentials, addresses, or application data.
async fn cli_terminal_diagnostics(process: &mut ManagedProcess) -> String {
    cli_terminal_diagnostics_with_budget(process, POST_RELEASE_CLI_DIAGNOSTIC_WAIT).await
}

async fn cli_terminal_diagnostics_with_budget(
    process: &mut ManagedProcess,
    budget: Duration,
) -> String {
    let wait_deadline = Instant::now() + budget.min(POST_RELEASE_CLI_DIAGNOSTIC_WAIT);
    while Instant::now() < wait_deadline {
        match process.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => sleep(POST_RELEASE_CLI_DIAGNOSTIC_POLL).await,
            Err(_) => break,
        }
    }
    tokio::task::yield_now().await;
    let terminal = match process.try_wait() {
        Ok(Some(status)) => format!(
            "state=exited,success={},exit_code={}",
            status.success(),
            status
                .code()
                .map_or_else(|| "none".to_owned(), |code| code.to_string())
        ),
        Ok(None) => "state=running".to_owned(),
        Err(_) => "state=unknown".to_owned(),
    };
    let mut status = None;
    let mut error = None;
    let mut json_records = 0usize;
    let mut protocol_causes = Vec::new();
    collect_cli_json_diagnostics(
        &process.stdout(),
        &mut status,
        &mut error,
        &mut json_records,
        &mut protocol_causes,
    );
    collect_cli_json_diagnostics(
        &process.stderr(),
        &mut status,
        &mut error,
        &mut json_records,
        &mut protocol_causes,
    );
    format!(
        "cli=[{terminal},json_records={json_records},last_status={},error={},protocol_causes={protocol_causes:?}]",
        status.as_deref().unwrap_or("missing"),
        error.as_deref().unwrap_or("missing"),
    )
}

/// Preserve bounded, redacted connector diagnostics for every scenario error
/// after an actual CLI process has been admitted.  Held-phase diagnostics have
/// the relay snapshot already, while this outer sample also covers setup and
/// pre-rotation failures before that context exists.
async fn early_cli_diagnostics(resources: &mut ExpiryResources) -> String {
    let mut diagnostics = Vec::with_capacity(2);
    if let Some(process) = resources.process_a.as_mut() {
        diagnostics.push(format!(
            "tenant-A {}",
            cli_terminal_diagnostics(process).await
        ));
    }
    if let Some(process) = resources.process_b.as_mut() {
        diagnostics.push(format!(
            "tenant-B {}",
            cli_terminal_diagnostics(process).await
        ));
    }
    if diagnostics.is_empty() {
        "cli_diagnostics=unavailable".to_owned()
    } else {
        format!("cli_diagnostics=[{}]", diagnostics.join("; "))
    }
}

const CLI_PROTOCOL_CAUSE_LIMIT: usize = 8;

fn collect_cli_json_diagnostics(
    bytes: &[u8],
    status: &mut Option<String>,
    error: &mut Option<String>,
    json_records: &mut usize,
    protocol_causes: &mut Vec<&'static str>,
) {
    for line in String::from_utf8_lossy(bytes).lines().rev().take(64) {
        if line.len() > 8 * 1024 {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        *json_records = json_records.saturating_add(1);
        let command = value.get("command").and_then(serde_json::Value::as_str);
        match (
            command,
            value.get("ok").and_then(serde_json::Value::as_bool),
        ) {
            (Some("connect-status"), Some(true)) if status.is_none() => {
                let result = value.get("result");
                *status = Some(format!(
                    "phase={} epoch={} generation={} rotations_completed={} drain_fences={} drain_acks={} session_present={} active_connection_present={}",
                    bounded_diagnostic_token(
                        result.and_then(|value| value.get("phase")),
                        "unknown"
                    ),
                    result
                        .and_then(|value| value.get("epoch"))
                        .and_then(serde_json::Value::as_u64)
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    result
                        .and_then(|value| value.get("generation"))
                        .and_then(serde_json::Value::as_u64)
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    result
                        .and_then(|value| value.get("rotations_completed"))
                        .and_then(serde_json::Value::as_u64)
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    result
                        .and_then(|value| value.get("drain_fences"))
                        .and_then(serde_json::Value::as_u64)
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    result
                        .and_then(|value| value.get("drain_acks"))
                        .and_then(serde_json::Value::as_u64)
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    result
                        .and_then(|value| value.get("session_id"))
                        .is_some_and(|value| !value.is_null()),
                    result
                        .and_then(|value| value.get("active_connection_id"))
                        .is_some_and(|value| !value.is_null()),
                ));
            }
            (Some("connect"), Some(false)) => {
                let diagnostic_error = value.get("error");
                if diagnostic_error
                    .and_then(|value| value.get("code"))
                    .and_then(serde_json::Value::as_str)
                    == Some("PROTOCOL_ERROR")
                    && let Some(message) = diagnostic_error
                        .and_then(|value| value.get("message"))
                        .and_then(serde_json::Value::as_str)
                {
                    let cause = super::lifecycle::classify_protocol_cause(message);
                    if protocol_causes.len() < CLI_PROTOCOL_CAUSE_LIMIT
                        && !protocol_causes.contains(&cause)
                    {
                        protocol_causes.push(cause);
                    }
                }
                if error.is_none() {
                    *error = Some(format!(
                        "code={} retryable={}",
                        bounded_diagnostic_token(
                            diagnostic_error.and_then(|value| value.get("code")),
                            "missing"
                        ),
                        diagnostic_error
                            .and_then(|value| value.get("retryable"))
                            .and_then(serde_json::Value::as_bool)
                            .map_or("missing", |value| if value { "true" } else { "false" }),
                    ));
                }
            }
            _ => {}
        }
    }
}

fn bounded_diagnostic_token(value: Option<&serde_json::Value>, fallback: &str) -> String {
    let Some(value) = value.and_then(serde_json::Value::as_str) else {
        return fallback.to_owned();
    };
    if value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        value.to_owned()
    } else {
        fallback.to_owned()
    }
}

async fn post_release_diagnostics(
    snapshot: &RelaySnapshot,
    owner: &OwnerToken,
    device_id: Uuid,
    stream_id: u64,
    expected_attempt: &RotationAttemptIdentity,
    expiry_observed_at_ms: u64,
    process: &mut ManagedProcess,
) -> String {
    let tenant_id = owner.tenant_id.to_string();
    let device_id_text = device_id.to_string();
    let session = snapshot.sessions.iter().find(|session| {
        session.tenant_id == tenant_id
            && session.device_id == device_id_text
            && session.session_id == owner.session_id
            && session.epoch == owner.epoch
    });
    let session_detail = session.map_or_else(
        || "session=absent".to_owned(),
        |session| {
            let stream = session
                .streams
                .iter()
                .find(|stream| stream.stream_id == stream_id)
                .map_or_else(
                    || "stream=absent".to_owned(),
                    |stream| {
                        format!(
                            "stream=present,terminal={},auth_in_flight={},auth_failure_code={:?},recv_contiguous={},delivered_contiguous={},last_emitted={},peer_acked={}",
                            stream.terminal,
                            stream.authorization_in_flight,
                            stream.authorization_failure_code,
                            stream.recv_contiguous_connector_to_relay,
                            stream.delivered_contiguous_connector_to_relay,
                            stream.last_emitted_relay_to_connector,
                            stream.peer_acked_relay_to_connector,
                        )
                    },
                );
            let rotation = session.rotation_diagnostics.as_ref().map_or_else(
                || "rotation=absent".to_owned(),
                |rotation| {
                    format!(
                        "rotation=present,active={},candidate_ready={},commit_sent={},commit_accepted={},old_socket_closed={:?},relay_fence_sequences={:?},connector_fence_sequences={:?},relay_ack_sequences={:?},connector_ack_sequences={:?},relay_fence_digest_present={},connector_fence_digest_present={}",
                        rotation.attempt_active,
                        rotation.candidate_ready,
                        rotation.commit_sent,
                        rotation.commit_accepted,
                        rotation.old_socket_closed,
                        rotation.relay_fence_sequences,
                        rotation.connector_fence_sequences,
                        rotation.relay_ack_sequences,
                        rotation.connector_ack_sequences,
                        rotation.relay_fence_digest.is_some(),
                        rotation.connector_fence_digest.is_some(),
                    )
                },
            );
            format!(
                "session=present,phase={},active_generation={},active_connection_id={},candidate_generation={:?},candidate_connection_id={:?},rotations_completed={},rotation_started_ms={:?},rotation_deadline_ms={:?},{rotation},{stream}",
                session.phase,
                session.active_generation,
                session.active_connection_id,
                session.candidate_generation,
                session.candidate_connection_id,
                session.rotations_completed,
                session.rotation_started_at_ms,
                session.rotation_deadline_ms,
            )
        },
    );
    let terminal_event = snapshot
        .session_terminal_events
        .iter()
        .rev()
        .find(|event| {
            event.tenant_id == tenant_id
                && event.device_id == device_id_text
                && event.session_id == owner.session_id
                && event.epoch == owner.epoch
                && event.rotation_id.as_deref() == Some(expected_attempt.rotation_id.as_str())
        })
        .or_else(|| {
            snapshot.session_terminal_events.iter().rev().find(|event| {
                event.tenant_id == tenant_id
                    && event.device_id == device_id_text
                    && event.session_id == owner.session_id
                    && event.epoch == owner.epoch
            })
        });
    let terminal_detail = terminal_event.map_or_else(
        || "terminal_event=absent".to_owned(),
        |event| {
            format!(
                "terminal_event=present,reason={},closed_at_ms={},active_generation={},active_connection_id={},candidate_generation={:?},candidate_connection_id={:?},rotation_id={}",
                event.reason,
                event.closed_at_ms,
                event.active_generation,
                event.active_connection_id,
                event.candidate_generation,
                event.candidate_connection_id,
                event.rotation_id.as_deref().unwrap_or("none"),
            )
        },
    );
    let deadline_event = snapshot
        .rotation_deadline_events
        .iter()
        .rev()
        .find(|event| {
            event.tenant_id == tenant_id
                && event.device_id == device_id_text
                && event.session_id == owner.session_id
                && event.epoch == owner.epoch
                && event.old_generation == expected_attempt.old_generation
                && event.old_connection_id == expected_attempt.old_connection_id
                && event.candidate_generation == expected_attempt.new_generation
                && event.candidate_connection_id == expected_attempt.new_connection_id
        });
    let deadline_detail = deadline_event.map_or_else(
        || "deadline_event=absent".to_owned(),
        |event| {
            format!(
                "deadline_event=present,started_at_ms={},deadline_ms={},fired_at_ms={},reason={}",
                event.started_at_ms, event.deadline_ms, event.fired_at_ms, event.reason,
            )
        },
    );
    let cli = cli_terminal_diagnostics(process).await;
    format!(
        "snapshot_monotonic_ms={} snapshot_sessions={} owner_node={} owner_tenant={} owner_device={} owner_session={} owner_epoch={} expected_attempt={{rotation_id={},session_id={},epoch={},owner_id={},old_generation={},new_generation={},old_connection_id={},new_connection_id={}}} expiry_observed_at_ms={} {} {} {} {}",
        snapshot.monotonic_now_ms,
        snapshot.sessions.len(),
        owner.node_id,
        owner.tenant_id,
        device_id,
        owner.session_id,
        owner.epoch,
        expected_attempt.rotation_id,
        expected_attempt.session_id,
        expected_attempt.epoch,
        expected_attempt.owner_id,
        expected_attempt.old_generation,
        expected_attempt.new_generation,
        expected_attempt.old_connection_id,
        expected_attempt.new_connection_id,
        expiry_observed_at_ms,
        session_detail,
        terminal_detail,
        deadline_detail,
        cli,
    )
}

fn owner_claim_matches(expected: &OwnerToken, observed: &OwnerClaim) -> bool {
    observed.token == *expected
}

async fn run_inner(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    authorization_gate: &AuthorizationDelayGate,
    resources: &mut ExpiryResources,
) -> Result<CredentialExpiryRotationEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "credential-expiry fixture expected three relays, observed {}",
            cluster.relays.len()
        )));
    }
    cluster
        .wait_for_peer_readiness(EXPIRY_STARTUP_TIMEOUT)
        .await?;

    let relay_c_consumer_addr = cluster.relay("relay-c")?.consumer_addr()?;
    let device_a = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no fixture device".into()))?;
    let device_b = harness
        .topology
        .devices_b
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant B has no fixture device".into()))?;
    let service_a = *harness
        .topology
        .service_ids
        .get(&device_a.id)
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no echo service".into()))?;
    let service_b = *harness
        .topology
        .service_ids
        .get(&device_b.id)
        .ok_or_else(|| HarnessError::InvalidInput("tenant B has no echo service".into()))?;
    if device_a.tenant_id == device_b.tenant_id
        || device_a.id != device_b.id
        || service_a != service_b
    {
        return Err(HarnessError::InvalidInput(
            "credential-expiry fixture did not establish distinct tenants with shared device/service UUIDs"
                .into(),
        ));
    }
    let spki_a = device_a.certificate.spki_fingerprint_sha256()?;
    let spki_b = device_b.certificate.spki_fingerprint_sha256()?;
    if spki_a == spki_b {
        return Err(HarnessError::Process(
            "same-UUID sibling fixture reused the device credential instead of a tenant-scoped certificate"
                .into(),
        ));
    }

    let canary_a = format!("m7-i06-expiry:a:{}", device_a.id);
    let canary_b = format!("m7-i06-expiry:b:{}", device_b.id);
    let profile_root_a = tempdir().map_err(HarnessError::Io)?;
    let profile_root_b = tempdir().map_err(HarnessError::Io)?;
    // Bind the actual device-side proxy before writing tenant A's profile.  The
    // proxy is an owned phase resource; the deterministic child barrier borrows
    // it only while its connection-scoped pause is held.
    resources.rotation_proxy = Some(bind_device_proxy(cluster).await?);
    let device_proxy_addr = resources
        .rotation_proxy
        .as_ref()
        .ok_or_else(|| HarnessError::Process("device rotation proxy disappeared".into()))?
        .local_addr();
    let mut profile_a = write_device_profile(
        profile_root_a.path(),
        device_a.id,
        service_a,
        &canary_a,
        device_proxy_addr,
        &device_a.certificate.certificate_pem,
        &device_a.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let mut profile_b = write_device_profile(
        profile_root_b.path(),
        device_b.id,
        service_b,
        &canary_b,
        cluster.tenant_b_fanout.local_addr(),
        &device_b.certificate.certificate_pem,
        &device_b.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile_a.config.rotation = EXPIRY_ROTATION.clone();
    profile_b.config.rotation = EXPIRY_ROTATION.clone();
    profile_a
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("tenant-A profile: {error}")))?;
    profile_b
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("tenant-B profile: {error}")))?;

    // Keep the long-lived barrier stream on a distinct principal.  The
    // expiry gate matches the full tenant/principal/device/service scope, so
    // this makes its single held catalog call causally attributable to the
    // short-lived consumer below rather than a concurrent barrier refresh.
    let barrier_consumer_a = harness.topology.consumers_a.get(1).ok_or_else(|| {
        HarnessError::InvalidInput(
            "tenant A has no second consumer for the rotation barrier stream".into(),
        )
    })?;
    let long_token_a = harness.oidc.issue_with(
        &barrier_consumer_a.name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;
    let token_b = harness.oidc.issue_with(
        &harness.topology.consumers_b[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;
    let (process_a, initial_stream_a) = start_cli_smoke(
        harness,
        device_proxy_addr,
        relay_c_consumer_addr,
        &profile_a,
        &long_token_a,
        device_a.id,
        service_a,
    )
    .await?;
    // `start_cli_smoke` returns only after the public device stream is
    // admitted, after the M2 actor's rotation timer has started.  Treat this
    // as a conservative fixture estimate; the pre-rotation guard below fails
    // if the first attempt has already begun rather than selecting a later one.
    let client_a_ready_at = Instant::now();
    resources.process_a = Some(process_a);
    resources.stream_a = Some(initial_stream_a);
    resources.profiles.push(profile_a);
    resources.profile_roots.push(profile_root_a);
    resources
        .stream_a
        .as_mut()
        .ok_or_else(|| HarnessError::Process("tenant-A startup stream was missing".into()))?
        .round_trip(b"m7-i06-expiry-baseline-a", canary_a.as_bytes())
        .await?;

    let (process_b, stream_b) = start_cli_smoke(
        harness,
        cluster.tenant_b_fanout.local_addr(),
        relay_c_consumer_addr,
        &profile_b,
        &token_b,
        device_b.id,
        service_b,
    )
    .await?;
    resources.process_b = Some(process_b);
    resources.stream_b = Some(stream_b);
    resources.profiles.push(profile_b);
    resources.profile_roots.push(profile_root_b);
    resources
        .stream_b
        .as_mut()
        .ok_or_else(|| HarnessError::Process("tenant-B sibling stream was missing".into()))?
        .round_trip(b"m7-i06-expiry-baseline-b", canary_b.as_bytes())
        .await?;

    let owner_a = cluster
        .catalog
        .current_owner(device_a.tenant_id, device_a.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading tenant-A owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("tenant-A owner was not admitted".into()))?;
    resources.owner_a = Some((device_a.tenant_id, device_a.id));
    let owner_b = cluster
        .catalog
        .current_owner(device_b.tenant_id, device_b.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading tenant-B owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("tenant-B owner was not admitted".into()))?;
    resources.owner_b = Some((device_b.tenant_id, device_b.id));
    if owner_a.token.node_id == owner_b.token.node_id {
        return Err(HarnessError::Process(
            "credential-expiry sibling owners were not independently placed".into(),
        ));
    }
    let owner_relay_a = cluster.relay(&owner_a.token.node_id)?;
    let stable_a = wait_for_stable_owner(
        cluster,
        &owner_a.token,
        device_a.id,
        Instant::now() + EXPIRY_PHASE_TIMEOUT,
    )
    .await?;
    let barrier_snapshot = owner_relay_a.snapshot().await?;
    let barrier_session = session_for(&barrier_snapshot, &owner_a.token, device_a.id)?;
    let admitted_barrier_streams = barrier_session
        .streams
        .iter()
        .filter(|stream| !stream.terminal && !stream.authorization_in_flight)
        .collect::<Vec<_>>();
    if admitted_barrier_streams.len() != 1 {
        return Err(HarnessError::Process(format!(
            "tenant-A expected exactly one initial admitted barrier stream, observed {}",
            admitted_barrier_streams.len()
        )));
    }
    let barrier_stream_id = admitted_barrier_streams[0].stream_id;
    let barrier_stream = resources
        .stream_a
        .take()
        .ok_or_else(|| HarnessError::Process("tenant-A barrier stream disappeared".into()))?;
    resources.barrier_stream = Some(barrier_stream);
    let baseline_dispatch = barrier_snapshot.lifetime_application_dispatches;
    if baseline_dispatch == 0 {
        return Err(HarnessError::Process(
            "credential-expiry owner had no positive dispatch baseline".into(),
        ));
    }
    let prior_rotations = session_for(&stable_a, &owner_a.token, device_a.id)?.rotations_completed;

    // Choose the token before the scheduled rotation attempt, then admit and
    // baseline it while the old carrier is still active.  With the fixed
    // sixteen-second lifetime and the 12/1/8 fixture policy, the token expires
    // inside the first naturally scheduled eight-second overlap.
    let phase_deadline = Instant::now() + EXPIRY_PHASE_TIMEOUT;
    let short_token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: EXPIRY_TOKEN_LIFETIME,
            ..OidcTokenOptions::default()
        },
    )?;
    let token_deadline =
        parse_token_deadline(harness, &short_token, &harness.topology.consumers_a[0].name)?;
    let token_remaining_at_issue = remaining_ms(token_deadline.expires_at, Utc::now());
    if token_remaining_at_issue < MIN_TOKEN_REMAINING_MS {
        return Err(HarnessError::Timeout(
            "short-lived consumer token had insufficient bounded lifetime at issue".into(),
        ));
    }
    let principal = cluster
        .catalog
        .resolve_consumer(
            &harness.oidc.issuer,
            &harness.topology.consumers_a[0].name,
            None,
        )
        .await
        .map_err(|error| HarnessError::Redis(format!("resolving short consumer: {error}")))?
        .ok_or_else(|| HarnessError::Process("short consumer was not a catalog member".into()))?;
    if principal.tenant_id != device_a.tenant_id {
        return Err(HarnessError::Process(
            "short-lived consumer resolved to the wrong tenant".into(),
        ));
    }
    let device_identity = cluster
        .catalog
        .resolve_device(&spki_a, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading device credential: {error}")))?
        .ok_or_else(|| HarnessError::Process("device credential was not active".into()))?;
    if device_identity.tenant_id != device_a.tenant_id || device_identity.device_id != device_a.id {
        return Err(HarnessError::Process(
            "device credential scope did not match tenant-A owner".into(),
        ));
    }
    if Utc::now() >= token_deadline.expires_at {
        return Err(HarnessError::Timeout(
            "short-lived consumer expired before public admission began".into(),
        ));
    }
    let admission_deadline = phase_deadline
        .min(Instant::now() + Duration::from_millis(token_remaining_at_issue.saturating_sub(100)));
    if admission_deadline <= Instant::now() {
        return Err(HarnessError::Timeout(
            "short-lived consumer had no bounded time remaining for public admission".into(),
        ));
    }
    let short_stream = timeout(
        admission_deadline.saturating_duration_since(Instant::now()),
        super::open_consumer_stream(
            relay_c_consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &short_token,
            device_a.id,
            service_a,
        ),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("short consumer stream was not admitted before expiry".into())
    })?
    .map_err(connect_failure_to_harness)?;
    resources.stream_a = Some(short_stream);
    if Utc::now() >= token_deadline.expires_at {
        return Err(HarnessError::Timeout(
            "short-lived consumer expired before the admitted stream was ready".into(),
        ));
    }
    let baseline_echo = resources
        .stream_a
        .as_mut()
        .ok_or_else(|| HarnessError::Process("short consumer stream was missing".into()))?
        .round_trip(b"m7-i06-expiry-baseline-short", canary_a.as_bytes())
        .await
        .map(|_| true)?;
    let (_, stream_id) = wait_for_exact_new_admitted_stream(
        cluster,
        &owner_a.token,
        device_a.id,
        barrier_stream_id,
        phase_deadline,
    )
    .await?;
    // Keep the original admitted carrier making positive progress until just
    // before the first configured rotation.  This gate is intentionally before
    // `install_rotation_barrier`: it never pauses a carrier and then queues a
    // late barrier after the client has entered Preparing/Quiescing.
    {
        let barrier_stream = resources
            .barrier_stream
            .as_mut()
            .ok_or_else(|| HarnessError::Process("tenant-A barrier stream was missing".into()))?;
        let short_stream = resources
            .stream_a
            .as_mut()
            .ok_or_else(|| HarnessError::Process("tenant-A short stream was missing".into()))?;
        let sibling_stream = resources
            .stream_b
            .as_mut()
            .ok_or_else(|| HarnessError::Process("tenant-B sibling stream was missing".into()))?;
        let mut streams = PreRotationKeepalives {
            barrier: barrier_stream,
            barrier_canary: canary_a.as_bytes(),
            short: short_stream,
            short_canary: canary_a.as_bytes(),
            sibling: sibling_stream,
            sibling_canary: canary_b.as_bytes(),
        };
        wait_for_pre_rotation_barrier_window(
            cluster,
            &owner_a.token,
            device_a.id,
            prior_rotations,
            &mut streams,
            PreRotationTiming {
                ready_at: client_a_ready_at,
                deadline: phase_deadline,
            },
        )
        .await?;
    }
    // Install the deterministic immutable old-carrier hold only after the
    // short stream has a successful public baseline echo.  The held stream is
    // the original long-lived stream; the expiry stream remains independently
    // identified by its exact stream ID.
    let mut barrier_stream = resources
        .barrier_stream
        .take()
        .ok_or_else(|| HarnessError::Process("tenant-A barrier stream was missing".into()))?;
    let Some(proxy) = resources.rotation_proxy.as_ref() else {
        resources.barrier_stream = Some(barrier_stream);
        return Err(HarnessError::Process(
            "tenant-A rotation proxy was missing".into(),
        ));
    };
    let Some(process_a) = resources.process_a.as_ref() else {
        resources.barrier_stream = Some(barrier_stream);
        return Err(HarnessError::Process(
            "tenant-A CLI process disappeared before rotation barrier".into(),
        ));
    };
    let mut barrier_hold = match install_rotation_barrier(
        cluster,
        &owner_a.token,
        device_a.id,
        &owner_id_for_token(&owner_a.token)?,
        proxy,
        process_a,
        &mut barrier_stream,
        barrier_stream_id,
        EXPIRY_ROTATION.overlap_seconds.saturating_mul(1_000),
        MIN_TOKEN_REMAINING_MS.saturating_add(ROTATION_EXPIRY_MARGIN_MS),
        phase_deadline,
    )
    .await
    {
        Ok(hold) => hold,
        Err(error) => {
            resources.barrier_stream = Some(barrier_stream);
            return Err(error);
        }
    };
    let barrier_evidence = barrier_hold.evidence().clone();
    let selected_rotation = selected_rotation_from_barrier(&barrier_evidence);
    // The helper has already revalidated the exact pre-commit attempt and
    // required bounded remaining margin.  The same hold is asserted again by
    // wait_for_expiry immediately before the post-expiry probe.

    // Read the authoritative grant only after token choice, public admission,
    // and the immutable candidate/old barrier.  All fallible work after the
    // hold is installed lives inside this result so the explicit release below
    // runs on every path.
    let diagnostic_context = ExpiryPhaseDiagnostic {
        cluster,
        owner: &owner_a.token,
        device_id: device_a.id,
        stream_id,
        selected: &selected_rotation,
        gate: authorization_gate,
        token_expires_at: token_deadline.expires_at,
        phase_deadline,
    };
    let held_phase: Result<(u64, ExpiryObservation, u64)> = async {
        let grant_read_started = Utc::now();
        let grant = cluster
            .catalog
            .authorize(
                &principal,
                device_a.id,
                service_a,
                grant_read_started,
                grant_read_started,
            )
            .await
            .map_err(|error| HarnessError::Redis(format!("reading admitted short grant: {error}")))?
            .ok_or_else(|| {
                HarnessError::Process("admitted short consumer lost its echo grant".into())
            })?;
        let barrier_snapshot = owner_relay_a.snapshot().await?;
        let token_remaining_at_barrier = remaining_ms(token_deadline.expires_at, Utc::now());
        let rotation_remaining_at_barrier = selected_rotation
            .deadline_ms
            .saturating_sub(barrier_snapshot.monotonic_now_ms);
        if token_remaining_at_barrier < MIN_TOKEN_REMAINING_MS
            || token_remaining_at_barrier.saturating_add(ROTATION_EXPIRY_MARGIN_MS)
                >= rotation_remaining_at_barrier
        {
            return Err(HarnessError::Process(
                "short-lived token expiry was not contained by the exact candidate/old rotation barrier"
                    .into(),
            ));
        }
        let dispatch_before_expiry = barrier_snapshot.lifetime_application_dispatches;
        let gate_window = wait_for_gate_window(
            cluster,
            &owner_a.token,
            device_a.id,
            &owner_id_for_token(&owner_a.token)?,
            &barrier_hold,
            token_deadline.expires_at,
            resources
                .stream_b
                .as_mut()
                .ok_or_else(|| HarnessError::Process("tenant-B sibling stream disappeared".into()))?,
            canary_b.as_bytes(),
            phase_deadline,
        )
        .await;
        if let Err(primary) = gate_window {
            let diagnostics =
                expiry_phase_diagnostics(&diagnostic_context, "wait_for_gate_window").await;
            return Err(HarnessError::Process(format!(
                "credential-expiry gate window failed: {primary}; {diagnostics}"
            )));
        }
        authorization_gate.arm(
            AuthorizationScope {
                tenant_id: principal.tenant_id,
                principal_id: principal.principal_id,
                device_id: device_a.id,
                service_id: service_a,
            },
            token_deadline.expires_at,
        )?;
        authorization_gate.set_device_spki(&spki_a)?;
        let challenge_result = wait_for_authorization_challenge(
            cluster,
            &owner_a.token,
            stream_id,
            &selected_rotation,
            authorization_gate,
            token_deadline.expires_at,
            phase_deadline,
        )
        .await;
        let challenge = match challenge_result {
            Ok(challenge) => challenge,
            Err(primary) => {
                let diagnostics = expiry_phase_diagnostics(
                    &diagnostic_context,
                    "wait_for_authorization_challenge",
                )
                .await;
                return Err(HarnessError::Process(format!(
                    "credential-expiry authorization challenge failed: {primary}; {diagnostics}"
                )));
            }
        };
        let observed_result = wait_for_expiry(
            cluster,
            &owner_a.token,
            device_a.id,
            stream_id,
            &token_deadline,
            &selected_rotation,
            challenge,
            grant.valid_until,
            device_identity.expires_at,
            &owner_a,
            authorization_gate,
            &barrier_hold,
            resources
                .stream_a
                .as_mut()
                .ok_or_else(|| HarnessError::Process("short consumer stream disappeared".into()))?,
            phase_deadline,
        )
        .await;
        let observed = match observed_result {
            Ok(observed) => observed,
            Err(primary) => {
                let diagnostics = expiry_phase_diagnostics(&diagnostic_context, "wait_for_expiry").await;
                return Err(HarnessError::Process(format!(
                    "credential-expiry expiry wait failed: {primary}; {diagnostics}"
                )));
            }
        };
        let dispatch_after_terminal = owner_relay_a
            .snapshot()
            .await?
            .lifetime_application_dispatches;
        Ok((dispatch_before_expiry, observed, dispatch_after_terminal))
    }
    .await;
    let release_result = barrier_hold
        .release_until(Instant::now() + CLEANUP_TIMEOUT)
        .await;
    drop(barrier_hold);
    resources.barrier_stream = Some(barrier_stream);
    let (dispatch_before_expiry, observed, dispatch_after_terminal) = match (
        held_phase,
        release_result,
    ) {
        (Ok(value), Ok(())) => value,
        (Err(primary), Ok(())) => return Err(primary),
        (Ok(_), Err(cleanup)) => {
            return Err(HarnessError::Process(format!(
                "credential expiry was observed but releasing its deterministic rotation barrier failed: {cleanup}"
            )));
        }
        (Err(primary), Err(cleanup)) => {
            return Err(HarnessError::Process(format!(
                "credential expiry failed: {primary}; releasing its deterministic rotation barrier also failed: {cleanup}"
            )));
        }
    };
    if dispatch_after_terminal != dispatch_before_expiry {
        return Err(HarnessError::Process(
            "credential expiry allowed dispatch before releasing the held carrier".into(),
        ));
    }
    let process_a = resources.process_a.as_mut().ok_or_else(|| {
        HarnessError::Process("tenant-A CLI process disappeared after barrier release".into())
    })?;
    let rotation_completion = wait_for_rotation_after_expiry(RotationExpiryWaitContext {
        cluster,
        owner: &owner_a.token,
        device_id: device_a.id,
        stream_id,
        expected_attempt: &observed.attempt,
        prior_rotations,
        expiry_observed_at_ms: observed.expiry_observed_at_ms,
        process: process_a,
        deadline: Instant::now() + EXPIRY_PHASE_TIMEOUT,
    })
    .await?;
    let process_a = resources.process_a.as_ref().ok_or_else(|| {
        HarnessError::Process("tenant-A CLI process disappeared after rotation".into())
    })?;
    let rotation_proxy = resources.rotation_proxy.as_ref().ok_or_else(|| {
        HarnessError::Process("tenant-A rotation proxy disappeared after rotation".into())
    })?;
    let _committed_cli_local_addr = wait_for_committed_cli_route(
        cluster,
        process_a,
        rotation_proxy,
        &rotation_completion.attempt,
        Instant::now() + EXPIRY_PHASE_TIMEOUT,
    )
    .await?;

    let expired_ingress = match super::open_consumer_stream(
        relay_c_consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &short_token,
        device_a.id,
        service_a,
    )
    .await
    {
        Err(super::StreamConnectFailure::Status { status, body }) => {
            if !exact_unauthorized(status, body.as_deref()) {
                return Err(HarnessError::Process(
                    "expired consumer ingress returned an unexpected typed response".into(),
                ));
            }
            (true, status)
        }
        Ok(mut stream) => {
            let _ = stream.close().await;
            return Err(HarnessError::Process(
                "expired consumer credential opened a new public stream".into(),
            ));
        }
        Err(super::StreamConnectFailure::Harness(error)) => return Err(error),
    };

    let snapshot_after_expiry = owner_relay_a.snapshot().await?;
    let owner_dispatch_after = snapshot_after_expiry.lifetime_application_dispatches;
    let owner_after = cluster
        .catalog
        .current_owner(device_a.tenant_id, device_a.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading post-expiry owner: {error}")))?
        .ok_or_else(|| {
            HarnessError::Process("tenant-A owner disappeared after credential expiry".into())
        })?;
    let sibling_owner_after = cluster
        .catalog
        .current_owner(device_b.tenant_id, device_b.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading sibling owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("tenant-B sibling owner disappeared".into()))?;
    if !owner_claim_matches(&owner_a.token, &owner_after) {
        return Err(HarnessError::Process(
            "tenant-A owner token changed during credential expiry".into(),
        ));
    }
    if !owner_claim_matches(&owner_b.token, &sibling_owner_after) {
        return Err(HarnessError::Process(
            "tenant-B sibling owner token changed during credential expiry".into(),
        ));
    }
    let sibling_echo = resources
        .stream_b
        .as_mut()
        .ok_or_else(|| HarnessError::Process("tenant-B sibling stream disappeared".into()))?
        .round_trip(b"m7-i06-expiry-sibling-after", canary_b.as_bytes())
        .await
        .map(|_| true)?;
    let owner_fence_exact = observed.attempt.owner_id == owner_id_for_token(&owner_a.token)?
        && observed.attempt.session_id == owner_a.token.session_id
        && observed.attempt.epoch == owner_a.token.epoch;
    let process_a_alive = resources
        .process_a
        .as_mut()
        .ok_or_else(|| HarnessError::Process("tenant-A CLI process disappeared".into()))?
        .try_wait()?
        .is_none();
    let process_b_alive = resources
        .process_b
        .as_mut()
        .ok_or_else(|| HarnessError::Process("tenant-B CLI process disappeared".into()))?
        .try_wait()?
        .is_none();
    if !process_a_alive || !process_b_alive {
        return Err(HarnessError::Process(
            "credential-expiry phase lost one of its actual CLI processes".into(),
        ));
    }

    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(CredentialExpiryRotationEvidence {
        scope: "consumer_credential_expiry_during_scheduled_rotation",
        relay_count: cluster.relays.len(),
        actual_cli_processes: 2,
        public_ingress: true,
        baseline_echo,
        same_uuid_tenant_sibling: device_a.id == device_b.id && service_a == service_b,
        rotation_attempt_observed: true,
        rotation_active_at_expiry: true,
        rotation_candidate_ready_at_expiry: observed.candidate_ready_at_expiry,
        rotation_old_sockets_open_at_expiry: observed.old_sockets_open_at_expiry,
        rotation_id: observed.attempt.rotation_id,
        rotation_session_id: observed.attempt.session_id,
        rotation_epoch: observed.attempt.epoch,
        rotation_owner_id: observed.attempt.owner_id,
        rotation_old_generation: observed.attempt.old_generation,
        rotation_new_generation: observed.attempt.new_generation,
        rotation_old_connection_id: observed.attempt.old_connection_id,
        rotation_new_connection_id: observed.attempt.new_connection_id,
        rotation_started_at_ms: observed.started_at_ms,
        rotation_deadline_ms: observed.deadline_ms,
        expiry_observed_at_ms: observed.expiry_observed_at_ms,
        consumer_token_expires_at_unix_ms: u64::try_from(
            token_deadline.expires_at.timestamp_millis(),
        )
        .map_err(|_| HarnessError::Process("consumer token expiry was before Unix epoch".into()))?,
        consumer_token_expired: observed.consumer_remaining_ms == 0,
        token_identity_exact: token_deadline.claims.iss == harness.oidc.issuer
            && token_deadline.claims.aud == harness.oidc.audience
            && token_deadline.claims.sub == harness.topology.consumers_a[0].name,
        token_issuer: token_deadline.claims.iss.clone(),
        token_audience: token_deadline.claims.aud.clone(),
        token_subject: token_deadline.claims.sub.clone(),
        authorization_delay_injected: authorization_gate.exactly_one_hold(),
        challenge_active_at_expiry: observed.challenge_active_at_expiry,
        challenge_started_at_ms: observed.challenge.started_at_ms,
        challenge_deadline_ms: observed.challenge.challenge_deadline_ms,
        challenge_admission_deadline_ms: observed.challenge.admission_deadline_ms,
        post_expiry_probe_attempted: observed.post_expiry_probe.attempted,
        post_expiry_probe_after_expiry: observed.post_expiry_probe.attempted_after_expiry,
        post_expiry_probe_at_unix_ms: observed.post_expiry_probe.attempted_at_unix_ms,
        post_expiry_probe_outcome: observed.post_expiry_probe.outcome,
        authorization_grant_still_valid: observed.grant_remaining_ms > 0,
        device_credential_still_valid: observed.device_remaining_ms > 0,
        owner_safe_deadline_still_valid: observed.owner_safe_remaining_ms > 0,
        earliest_deadline: "consumer_credential",
        consumer_remaining_ms: observed.consumer_remaining_ms,
        grant_remaining_ms: observed.grant_remaining_ms,
        device_credential_remaining_ms: observed.device_remaining_ms,
        owner_safe_remaining_ms: observed.owner_safe_remaining_ms,
        rotation_remaining_ms: observed.rotation_remaining_ms,
        expired_stream_terminal: true,
        expired_stream_cause: "AUTHORIZATION_EXPIRED",
        expired_transport_terminal: observed.transport_terminal,
        expired_terminal_kind: observed.terminal_kind,
        expired_ingress_rejected: expired_ingress.0,
        expired_ingress_status: expired_ingress.1,
        expired_ingress_code: "UNAUTHORIZED",
        expired_ingress_execution: "not_dispatched",
        owner_token_retained: owner_claim_matches(&owner_a.token, &owner_after),
        owner_fence_exact,
        owner_dispatch_before: dispatch_before_expiry,
        owner_dispatch_after,
        rotation_completed_after_expiry: rotation_completion.latch_observed,
        rotation_completion_latch_observed: rotation_completion.latch_observed,
        rotation_completion_id: rotation_completion.attempt.rotation_id,
        rotation_completion_session_id: rotation_completion.attempt.session_id,
        rotation_completion_epoch: rotation_completion.attempt.epoch,
        rotation_completion_owner_id: rotation_completion.attempt.owner_id,
        rotation_completion_old_generation: rotation_completion.attempt.old_generation,
        rotation_completion_new_generation: rotation_completion.attempt.new_generation,
        rotation_completion_old_connection_id: rotation_completion.attempt.old_connection_id,
        rotation_completion_new_connection_id: rotation_completion.attempt.new_connection_id,
        sibling_owner_retained: owner_claim_matches(&owner_b.token, &sibling_owner_after),
        sibling_stream_survived: sibling_echo,
        sibling_echo,
        cleanup_joined: false,
        elapsed_ms,
    })
}

/// Run the isolated phase with caller-owned production cluster/Redis setup.
/// CLI, stream, profile, and owner cleanup remains inside this function so a
/// scenario error cannot detach an actual client process before the parent
/// starts relay/catalog shutdown.
pub async fn verify(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    authorization_gate: &AuthorizationDelayGate,
) -> Result<CredentialExpiryRotationEvidence> {
    let mut resources = ExpiryResources::new();
    // `run_inner` owns the connection-scoped rotation hold until it has
    // explicitly released it.  Do not wrap it in a consuming timeout: that
    // would cancel the future while the hold is borrowed and drop the
    // release/cleanup path before the proxy can be resumed.
    let scenario = match run_inner(cluster, harness, authorization_gate, &mut resources).await {
        Ok(evidence) => Ok(evidence),
        Err(primary) => {
            let diagnostics = early_cli_diagnostics(&mut resources).await;
            Err(HarnessError::Process(format!("{primary}; {diagnostics}")))
        }
    };
    authorization_gate.release();
    let cleanup = resources.cleanup(cluster).await;
    match (scenario, cleanup) {
        (Err(primary), Err(cleanup)) => Err(HarnessError::Process(format!(
            "credential-expiry rotation failed: {primary}; owned cleanup failed: {cleanup}"
        ))),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Ok(mut evidence), Ok(())) => {
            evidence.cleanup_joined = true;
            validate_credential_expiry_rotation_evidence(&evidence)?;
            Ok(evidence)
        }
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;
    use crate::acceptance_test_support::{assert_failed, assert_rejected};

    fn valid_evidence() -> CredentialExpiryRotationEvidence {
        CredentialExpiryRotationEvidence {
            scope: "consumer_credential_expiry_during_scheduled_rotation",
            relay_count: 3,
            actual_cli_processes: 2,
            public_ingress: true,
            baseline_echo: true,
            same_uuid_tenant_sibling: true,
            rotation_attempt_observed: true,
            rotation_active_at_expiry: true,
            rotation_candidate_ready_at_expiry: true,
            rotation_old_sockets_open_at_expiry: true,
            rotation_id: "rotation-1".to_owned(),
            rotation_session_id: "session-1".to_owned(),
            rotation_epoch: 4,
            rotation_owner_id: "owner-1".to_owned(),
            rotation_old_generation: 7,
            rotation_new_generation: 8,
            rotation_old_connection_id: "connection-old".to_owned(),
            rotation_new_connection_id: "connection-new".to_owned(),
            rotation_started_at_ms: 100,
            rotation_deadline_ms: 300,
            expiry_observed_at_ms: 200,
            consumer_token_expires_at_unix_ms: 1_725_000_000_000,
            consumer_token_expired: true,
            token_identity_exact: true,
            token_issuer: "https://fixture.test".to_owned(),
            token_audience: "audience".to_owned(),
            token_subject: "consumer-a".to_owned(),
            authorization_delay_injected: true,
            challenge_active_at_expiry: true,
            challenge_started_at_ms: 100,
            challenge_deadline_ms: 2_100,
            challenge_admission_deadline_ms: 3_000,
            post_expiry_probe_attempted: true,
            post_expiry_probe_after_expiry: true,
            post_expiry_probe_at_unix_ms: 1_725_000_000_000,
            post_expiry_probe_outcome: "local_write_accepted",
            authorization_grant_still_valid: true,
            device_credential_still_valid: true,
            owner_safe_deadline_still_valid: true,
            earliest_deadline: "consumer_credential",
            consumer_remaining_ms: 0,
            grant_remaining_ms: 4_000,
            device_credential_remaining_ms: 5_000,
            owner_safe_remaining_ms: 6_000,
            rotation_remaining_ms: 100,
            expired_stream_terminal: true,
            expired_stream_cause: "AUTHORIZATION_EXPIRED",
            expired_transport_terminal: true,
            expired_terminal_kind: "close_or_eof",
            expired_ingress_rejected: true,
            expired_ingress_status: 401,
            expired_ingress_code: "UNAUTHORIZED",
            expired_ingress_execution: "not_dispatched",
            owner_token_retained: true,
            owner_fence_exact: true,
            owner_dispatch_before: 9,
            owner_dispatch_after: 9,
            rotation_completed_after_expiry: true,
            rotation_completion_latch_observed: true,
            rotation_completion_id: "rotation-1".to_owned(),
            rotation_completion_session_id: "session-1".to_owned(),
            rotation_completion_epoch: 4,
            rotation_completion_owner_id: "owner-1".to_owned(),
            rotation_completion_old_generation: 7,
            rotation_completion_new_generation: 8,
            rotation_completion_old_connection_id: "connection-old".to_owned(),
            rotation_completion_new_connection_id: "connection-new".to_owned(),
            sibling_owner_retained: true,
            sibling_stream_survived: true,
            sibling_echo: true,
            cleanup_joined: true,
            elapsed_ms: 1_000,
        }
    }

    #[test]
    fn accepts_exact_expiry_and_completion_latch() {
        validate_credential_expiry_rotation_evidence(&valid_evidence()).unwrap();
    }

    #[test]
    fn cli_protocol_diagnostic_classifies_and_redacts_protocol_message() {
        let line = br#"{"command":"connect","ok":false,"error":{"code":"PROTOCOL_ERROR","message":"cannot process Fin after terminal state Fin; token=secret-value","retryable":false}}"#;
        let unknown = br#"{"command":"connect","ok":false,"error":{"code":"PROTOCOL_ERROR","message":"unrecognized private protocol detail","retryable":false}}"#;
        let mut status = None;
        let mut error = None;
        let mut json_records = 0;
        let mut protocol_causes = Vec::new();
        collect_cli_json_diagnostics(
            line,
            &mut status,
            &mut error,
            &mut json_records,
            &mut protocol_causes,
        );
        collect_cli_json_diagnostics(
            unknown,
            &mut status,
            &mut error,
            &mut json_records,
            &mut protocol_causes,
        );
        assert_eq!(
            error.as_deref(),
            Some("code=PROTOCOL_ERROR retryable=false")
        );
        assert_eq!(protocol_causes, vec!["sequence_after_terminal", "unknown"]);
        assert!(
            !error
                .as_deref()
                .is_some_and(|value| value.contains("secret-value"))
        );
    }

    #[test]
    fn accepts_authoritative_terminal_without_readable_handler() {
        let mut evidence = valid_evidence();
        evidence.expired_transport_terminal = false;
        evidence.expired_terminal_kind = "explicit_unknown_after_authoritative_terminal";
        validate_credential_expiry_rotation_evidence(&evidence).unwrap();
    }

    #[test]
    fn rejects_observer_deadline_as_expiry_evidence() {
        let mut evidence = valid_evidence();
        evidence.expired_transport_terminal = false;
        evidence.expired_terminal_kind = "observer_deadline";
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn rejects_probe_not_attempted_after_expiry() {
        let mut evidence = valid_evidence();
        evidence.post_expiry_probe_after_expiry = false;
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn rejects_local_probe_timeout_as_evidence() {
        let mut evidence = valid_evidence();
        evidence.post_expiry_probe_outcome = "local_write_timeout";
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn local_probe_rejection_requires_authoritative_expiry_terminal() {
        let mut evidence = valid_evidence();
        evidence.post_expiry_probe_outcome = "local_write_rejected";
        validate_credential_expiry_rotation_evidence(&evidence).unwrap();
        evidence.expired_stream_terminal = false;
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn rejects_terminal_observation_after_rotation_was_cleared() {
        let mut evidence = valid_evidence();
        evidence.rotation_active_at_expiry = false;
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn rejects_completion_latch_for_another_attempt() {
        let mut evidence = valid_evidence();
        evidence.rotation_completion_id = "rotation-2".to_owned();
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn rejects_owner_dispatch_change() {
        let mut evidence = valid_evidence();
        evidence.owner_dispatch_after += 1;
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn rejects_expiry_at_or_after_rotation_deadline() {
        let mut evidence = valid_evidence();
        evidence.expiry_observed_at_ms = evidence.rotation_deadline_ms;
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn rejects_expiry_without_an_active_authorization_challenge() {
        let mut evidence = valid_evidence();
        evidence.challenge_active_at_expiry = false;
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn rejects_unverified_token_identity() {
        let mut evidence = valid_evidence();
        evidence.token_identity_exact = false;
        assert!(validate_credential_expiry_rotation_evidence(&evidence).is_err());
    }

    #[test]
    fn every_expiry_flag_and_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut CredentialExpiryRotationEvidence));
        let flags: [Disable; 26] = [
            ("public_ingress", |e| e.public_ingress = false),
            ("baseline_echo", |e| e.baseline_echo = false),
            ("same_uuid_tenant_sibling", |e| {
                e.same_uuid_tenant_sibling = false
            }),
            ("rotation_attempt_observed", |e| {
                e.rotation_attempt_observed = false
            }),
            ("rotation_active_at_expiry", |e| {
                e.rotation_active_at_expiry = false
            }),
            ("rotation_candidate_ready_at_expiry", |e| {
                e.rotation_candidate_ready_at_expiry = false
            }),
            ("rotation_old_sockets_open_at_expiry", |e| {
                e.rotation_old_sockets_open_at_expiry = false
            }),
            ("consumer_token_expired", |e| {
                e.consumer_token_expired = false
            }),
            ("token_identity_exact", |e| e.token_identity_exact = false),
            ("authorization_delay_injected", |e| {
                e.authorization_delay_injected = false
            }),
            ("challenge_active_at_expiry", |e| {
                e.challenge_active_at_expiry = false
            }),
            ("post_expiry_probe_attempted", |e| {
                e.post_expiry_probe_attempted = false
            }),
            ("post_expiry_probe_after_expiry", |e| {
                e.post_expiry_probe_after_expiry = false
            }),
            ("authorization_grant_still_valid", |e| {
                e.authorization_grant_still_valid = false
            }),
            ("device_credential_still_valid", |e| {
                e.device_credential_still_valid = false
            }),
            ("owner_safe_deadline_still_valid", |e| {
                e.owner_safe_deadline_still_valid = false
            }),
            ("expired_stream_terminal", |e| {
                e.expired_stream_terminal = false
            }),
            ("expired_ingress_rejected", |e| {
                e.expired_ingress_rejected = false
            }),
            ("owner_token_retained", |e| e.owner_token_retained = false),
            ("owner_fence_exact", |e| e.owner_fence_exact = false),
            ("rotation_completed_after_expiry", |e| {
                e.rotation_completed_after_expiry = false
            }),
            ("rotation_completion_latch_observed", |e| {
                e.rotation_completion_latch_observed = false
            }),
            ("sibling_owner_retained", |e| {
                e.sibling_owner_retained = false
            }),
            ("sibling_stream_survived", |e| {
                e.sibling_stream_survived = false
            }),
            ("sibling_echo", |e| e.sibling_echo = false),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(
                validate_credential_expiry_rotation_evidence(&evidence),
                name,
            );
        }

        type Mutate = (&'static str, fn(&mut CredentialExpiryRotationEvidence));
        let bounds: [Mutate; 25] = [
            ("relay_count", |e| e.relay_count = 2),
            ("actual_cli_processes", |e| e.actual_cli_processes = 1),
            ("rotation_epoch", |e| e.rotation_epoch = 0),
            ("rotation_old_generation", |e| e.rotation_old_generation = 0),
            ("rotation_new_generation", |e| {
                e.rotation_new_generation = e.rotation_old_generation
            }),
            ("rotation_started_at_ms", |e| {
                e.rotation_started_at_ms = e.expiry_observed_at_ms
            }),
            ("rotation_deadline", |e| {
                e.expiry_observed_at_ms = e.rotation_deadline_ms
            }),
            ("expiry_observed_at_ms", |e| {
                e.expiry_observed_at_ms = e.rotation_started_at_ms
            }),
            ("consumer_token_expires_at_unix_ms", |e| {
                e.consumer_token_expires_at_unix_ms = 0
            }),
            ("challenge_started_at_ms", |e| e.challenge_started_at_ms = 0),
            ("challenge_deadline_ms", |e| {
                e.challenge_deadline_ms = e.challenge_started_at_ms
            }),
            ("challenge_admission_deadline_ms", |e| {
                e.challenge_admission_deadline_ms = e.expiry_observed_at_ms
            }),
            ("consumer_remaining_ms", |e| e.consumer_remaining_ms = 1),
            ("grant_remaining_ms", |e| e.grant_remaining_ms = 0),
            ("device_credential_remaining_ms", |e| {
                e.device_credential_remaining_ms = 0
            }),
            ("owner_safe_remaining_ms", |e| e.owner_safe_remaining_ms = 0),
            ("rotation_remaining_ms", |e| e.rotation_remaining_ms = 0),
            ("earliest_deadline", |e| e.earliest_deadline = "grant"),
            ("post_expiry_probe_at_unix_ms", |e| {
                e.post_expiry_probe_at_unix_ms = 0
            }),
            ("owner_dispatch_before", |e| e.owner_dispatch_before = 8),
            ("owner_dispatch", |e| e.owner_dispatch_after += 1),
            ("rotation_completion_epoch", |e| {
                e.rotation_completion_epoch = 0
            }),
            ("rotation_completion_old_generation", |e| {
                e.rotation_completion_old_generation = 0
            }),
            ("rotation_completion_new_generation", |e| {
                e.rotation_completion_new_generation = 0
            }),
            ("elapsed_ms", |e| e.elapsed_ms = 0),
        ];
        for (_, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_failed(validate_credential_expiry_rotation_evidence(&evidence));
        }

        let mut terminal = valid_evidence();
        terminal.expired_transport_terminal = false;
        assert_failed(validate_credential_expiry_rotation_evidence(&terminal));
    }
}
