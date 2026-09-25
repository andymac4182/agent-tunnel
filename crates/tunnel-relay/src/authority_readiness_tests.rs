//! Task row M6-C67: a single relay's `/readyz` follows its authority.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::body::Body;
use chrono::{DateTime, Utc};
use http_body_util::BodyExt;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tunnel_catalog::{
    AttachmentTicket, AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest,
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, ConsumedAttachmentTicket,
    DeviceIdentity, DeviceListFilter, DeviceSummary, GrantSnapshot, GrantSpec, MemoryCatalog,
    OwnerClaim, OwnerClaimRequest, OwnerToken, SharedCatalog, SignedMembershipRecord,
};
use uuid::Uuid;

use super::*;

#[test]
fn a_failed_check_withdraws_readiness_and_a_success_restores_it() {
    let readiness = AuthorityReadiness::new();
    assert!(readiness.is_ready(), "a relay starts ready");
    readiness.mark_unready();
    assert!(!readiness.is_ready());
    readiness.mark_ready();
    assert!(readiness.is_ready());
}

#[test]
fn readiness_lapses_without_a_fresh_check() {
    let readiness = AuthorityReadiness::new();
    // A success whose window already closed: a probe task that stopped.
    readiness.ready_until_ms.store(1, Ordering::Release);
    std::thread::sleep(Duration::from_millis(5));
    assert!(!readiness.is_ready());
}

/// A memory catalog whose authority check can be made to fail (a lost
/// connection) or to hang (a stalled authority).
struct SwitchableAuthority {
    inner: MemoryCatalog,
    down: AtomicBool,
    hang: AtomicBool,
    checks: AtomicUsize,
}

#[async_trait]
impl Catalog for SwitchableAuthority {
    async fn check_authority(&self) -> Result<(), CatalogError> {
        self.checks.fetch_add(1, Ordering::AcqRel);
        if self.hang.load(Ordering::Acquire) {
            std::future::pending::<()>().await;
        }
        if self.down.load(Ordering::Acquire) {
            return Err(CatalogError::Database(
                std::io::Error::from(std::io::ErrorKind::ConnectionReset).into(),
            ));
        }
        Ok(())
    }

    async fn resolve_device(
        &self,
        spki_fingerprint: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<DeviceIdentity>, CatalogError> {
        self.inner.resolve_device(spki_fingerprint, at).await
    }

    async fn resolve_consumer(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: Option<Uuid>,
    ) -> Result<Option<AuthenticatedConsumer>, CatalogError> {
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
    ) -> Result<Option<GrantSnapshot>, CatalogError> {
        self.inner
            .authorize(principal, device_id, service_id, read_started_at, at)
            .await
    }

    async fn list_devices_filtered(
        &self,
        principal: &AuthenticatedConsumer,
        filter: &DeviceListFilter,
        at: DateTime<Utc>,
    ) -> Result<Vec<DeviceSummary>, CatalogError> {
        self.inner
            .list_devices_filtered(principal, filter, at)
            .await
    }

    async fn upsert_grant(&self, spec: &GrantSpec) -> Result<GrantSnapshot, CatalogError> {
        self.inner.upsert_grant(spec).await
    }

    async fn revoke_grant(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        device_id: Uuid,
        service_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        self.inner
            .revoke_grant(tenant_id, principal_id, device_id, service_id, at)
            .await
    }

    async fn revoke_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        self.inner.revoke_device(tenant_id, device_id, at).await
    }

    async fn revoke_credential(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        credential_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        self.inner
            .revoke_credential(tenant_id, device_id, credential_id, at)
            .await
    }

    async fn seed_fixture(&self, fixture: &CatalogFixture) -> Result<(), CatalogError> {
        self.inner.seed_fixture(fixture).await
    }

    async fn claim_owner(&self, request: &OwnerClaimRequest) -> Result<OwnerClaim, CatalogError> {
        self.inner.claim_owner(request).await
    }

    async fn renew_owner(
        &self,
        token: &OwnerToken,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<bool, CatalogError> {
        self.inner.renew_owner(token, lease_expires_at).await
    }

    async fn release_owner(&self, token: &OwnerToken) -> Result<bool, CatalogError> {
        self.inner.release_owner(token).await
    }

    async fn current_owner(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<Option<OwnerClaim>, CatalogError> {
        self.inner.current_owner(tenant_id, device_id, at).await
    }

    async fn issue_attachment_ticket(
        &self,
        request: &AttachmentTicketIssueRequest,
    ) -> Result<AttachmentTicket, CatalogError> {
        self.inner.issue_attachment_ticket(request).await
    }

    async fn consume_attachment_ticket(
        &self,
        request: &AttachmentTicketConsumeRequest,
    ) -> Result<ConsumedAttachmentTicket, CatalogError> {
        self.inner.consume_attachment_ticket(request).await
    }

    async fn read_signed_membership(&self) -> Result<Option<SignedMembershipRecord>, CatalogError> {
        self.inner.read_signed_membership().await
    }
}

async fn readyz(app: &axum::Router) -> (u16, String) {
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::get("/readyz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("readyz");
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Poll `/readyz` until it answers `status`, within `bound`.
async fn until_readyz(app: &axum::Router, status: u16, bound: Duration) -> (Duration, String) {
    let started = Instant::now();
    loop {
        let (got, body) = readyz(app).await;
        if got == status {
            return (started.elapsed(), body);
        }
        assert!(
            started.elapsed() < bound,
            "/readyz still answered {got} {body} after {bound:?}, expected {status}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn m6c67_readyz_follows_a_lost_and_a_stalled_authority_and_recovers() {
    let catalog = Arc::new(SwitchableAuthority {
        inner: MemoryCatalog::new(),
        down: AtomicBool::new(false),
        hang: AtomicBool::new(false),
        checks: AtomicUsize::new(0),
    });
    let shared: SharedCatalog = catalog.clone();
    let cancel = CancellationToken::new();
    let authority = AuthorityReadiness::spawn(shared, cancel.clone());
    let app: axum::Router = crate::health::router(None, Some(authority));
    let bound = PROBE_INTERVAL + PROBE_DEADLINE + Duration::from_secs(2);

    let (_, body) = until_readyz(&app, 200, bound).await;
    assert_eq!(body, r#"{"status":"ready"}"#);

    // The authority is lost: not ready within one interval.
    catalog.down.store(true, Ordering::Release);
    let (after, body) = until_readyz(&app, 503, bound).await;
    assert_eq!(body, r#"{"status":"unready"}"#, "fixed words only");
    assert!(
        after <= PROBE_INTERVAL + Duration::from_secs(1),
        "{after:?}"
    );

    // `/readyz` never reaches the authority itself: a burst of probes adds
    // no check.
    let before = catalog.checks.load(Ordering::Acquire);
    for _ in 0..50 {
        assert_eq!(readyz(&app).await.0, 503);
    }
    assert!(catalog.checks.load(Ordering::Acquire) <= before + 1);

    // It recovers.
    catalog.down.store(false, Ordering::Release);
    until_readyz(&app, 200, bound).await;

    // A stalled authority (no reply at all) is not ready within the check
    // deadline, never unboundedly later.
    catalog.hang.store(true, Ordering::Release);
    let (after, _) = until_readyz(&app, 503, bound + PROBE_DEADLINE).await;
    assert!(
        after <= READY_FOR + Duration::from_secs(1),
        "stalled authority withdrew readiness only after {after:?}"
    );
    catalog.hang.store(false, Ordering::Release);
    until_readyz(&app, 200, bound).await;

    // A stopped check task fails closed: the last success lapses.
    cancel.cancel();
    let (after, _) = until_readyz(&app, 503, READY_FOR + Duration::from_secs(2)).await;
    assert!(after <= READY_FOR + Duration::from_secs(1), "{after:?}");
}
