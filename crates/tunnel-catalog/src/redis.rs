use crate::cluster;
use crate::error::{
    CatalogConnectionError, CatalogConnectionFailure, CatalogConnectionLane, CatalogConnectionStage,
};
use crate::memory::valid_fingerprint;
use crate::types::valid_principal_identity;
use crate::{
    AttachmentTicket, AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest,
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, ConsumedAttachmentTicket,
    CredentialRecord, DeviceIdentity, DeviceListFilter, DeviceSummary, FixtureDevice,
    GrantSnapshot, GrantSpec, MAX_SIGNED_MEMBERSHIP_RECORDS, MembershipRecord, OwnerClaim,
    OwnerClaimRequest, OwnerToken, PrincipalIdentity, ServiceRecord, ServiceSpec,
    SignedMembershipRecord, UserRecord,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use redis::{FromRedisValue, IntoConnectionInfo, aio::MultiplexedConnection};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

mod lane;
mod recovery;
mod recovery_scanner;
mod recovery_schema;
use lane::{AuthorityLane, LaneGroup, RebindScope};
pub(crate) use lane::{
    CONTINUITY_MISMATCH, NAMESPACE_UNBOUND, PERSISTENCE_UNSOUND, RUN_BINDING_CHANGED,
};
pub use recovery::DurableCatalogObservation;

const MAX_SAFE_REDIS_TIME: i64 = 9_000_000_000_000_000;
const MAX_FIXTURE_RECORDS: usize = 4_096;
const MAX_CLEANUP_KEYS: usize = 100_000;
const MAX_SEED_SCAN_KEYS: usize = 100_000;
const DEFAULT_MAX_LIST_ITEMS: usize = 1_024;
const MAX_IDENTIFIER_BYTES: usize = 128;
/// Maximum accepted length of the authoritative Redis key namespace.
pub const MAX_REDIS_NAMESPACE_BYTES: usize = 96;
const REDIS_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
/// Placeholder for the Redis run id in a script's arguments.  The lane that
/// runs the script replaces it with the run its connection was verified
/// against (see `AuthorityLane::query_eval`), so a script's run fence never
/// carries a run the catalog has since moved away from (M6-C65).  It starts
/// with a control character and carries a per-process random suffix, and
/// `query_eval` refuses any other argument that starts with that character,
/// so no caller-supplied value can be taken for it.
fn bound_run_id() -> &'static str {
    static PLACEHOLDER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PLACEHOLDER
        .get_or_init(|| format!("{BOUND_RUN_MARKER}bound-run-id-{}", Uuid::new_v4().simple()))
}

/// The first character of [`bound_run_id`].
const BOUND_RUN_MARKER: char = '\u{1}';
/// The budget for opening one authority connection: DNS resolution, TCP
/// connect, the TLS handshake and redis-rs's setup exchange (`AUTH`,
/// `CLIENT SETINFO`).  It is separate from the two-second per-command
/// [`REDIS_OPERATION_TIMEOUT`], and it is set explicitly both inside
/// redis-rs and around it (M6-C73): redis-rs's own default is one second and
/// covers DNS, and the first lookup on a fresh Fly machine was measured at
/// 2,038 ms, so the old budget expired before TCP connect began.  Ten seconds
/// is that cold lookup with about 4x headroom, and still bounded.
///
/// It governs the connections a catalog opens (the primary and its lanes)
/// and recovery connections.  **It does not reach a lane reconnect inside a
/// running relay**: `AuthorityLane::admit` caps the whole verification,
/// reconnect included, at [`REDIS_OPERATION_TIMEOUT`] while holding the lane
/// lock, deliberately, so sibling callers never queue behind a ten-second
/// connect (M6-C74).
pub(crate) const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// The budget covers the measured 2,038 ms cold lookup with headroom and is
// separate from, and longer than, the per-command deadline (M6-C73).
const _: () = assert!(REDIS_CONNECT_TIMEOUT.as_millis() >= 4 * 2_038);
const _: () = assert!(REDIS_CONNECT_TIMEOUT.as_millis() > REDIS_OPERATION_TIMEOUT.as_millis());
const AUTHORIZATION_CONNECTIONS: usize = 4;
/// Physical lanes reserved for the relay's per-session maintenance reads
/// (`resolve_device`) and owner renewals (`renew_owner`).  Two lanes keep
/// that steady per-tick traffic off the catalog lane's atomic pipelines and
/// off the authorization lanes; the relay bounds how many sessions it
/// maintains per tick, so the lane count is a transport choice, not a
/// concurrency limit.
const MAINTENANCE_CONNECTIONS: usize = 2;
/// Every lane opened after the primary connection, for diagnostics.
const LANE_CONNECTIONS: usize = AUTHORIZATION_CONNECTIONS + MAINTENANCE_CONNECTIONS;
/// How far a caller's clock may run *ahead* of the authority before a
/// timestamped read is refused. This is the genuine clock-skew direction: the
/// scripts evaluate validity at `math.max(caller_at, now)`, so a caller ahead of
/// the authority would otherwise extend a validity window past its real expiry.
const MAX_AUTHORITY_CLOCK_SKEW_US: i64 = 1_000_000;
/// How far a caller's timestamp may lag the authority's clock before a
/// timestamped read is refused.
///
/// A script only ever sees the timestamp the caller sampled before dispatching
/// its command, so it cannot separate a slow caller clock from time the command
/// spent in flight. Bounding this direction below the authority deadline
/// therefore creates a latency band in which a reply the transport accepted is
/// deterministically refused, and refused as a `Conflict` rather than a timeout
/// -- the relay's maintenance tick escalates that into `AUTHORITY_UNAVAILABLE`
/// and closes a healthy session whose lease is still being renewed. The budget
/// is the authority deadline so that the deadline stays the single boundary
/// docs/cluster.md documents; a command in flight longer than that fails as a
/// `timeout` before any script runs. Lag needs no tighter bound to stay fail
/// closed: validity is evaluated at `math.max(caller_at, now)` and the returned
/// windows are translated back into the caller's frame, so a lagging caller
/// timestamp can only shorten a window, never extend one.
const MAX_AUTHORITY_CALLER_LAG_US: i64 = REDIS_OPERATION_TIMEOUT.as_micros() as i64;
const MAX_TICKET_INDEX_ITEMS: usize = crate::MAX_ATTACHMENT_TICKETS_PER_DEVICE;
const MAX_REDIS_TLS_PEM_BYTES: usize = 1024 * 1024;

/// Outcome of the one-shot seed reservation script, mapped to a caller's own
/// refusal wording by the fixture seed and the operator bootstrap.
enum NamespaceReservation {
    Reserved,
    AlreadyReserved,
    Occupied,
    ScanBound,
}

/// Outcome of [`RedisCatalog::rebind_restarted_redis_run`] (M6-C65).  Run
/// ids are Redis's own random server identifiers, not secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedisRunRebind {
    /// The namespace was already bound to this Redis run; nothing changed.
    AlreadyCurrent { run_id: String },
    /// The binding moved from `previous_run_id` to `run_id`.
    Rebound {
        previous_run_id: String,
        run_id: String,
    },
}

/// The authoritative M1 catalog. Redis is the only durable state authority;
/// this type deliberately uses plain multiplexed connections and does not
/// enable redis-rs' reconnecting `ConnectionManager`. A connection error is
/// surfaced to the caller that observed it and authorization/ownership fail
/// closed; no command is ever replayed. Each lane re-establishes a lost
/// connection only for a later command, and only to a primary whose `run_id`
/// is the one the catalog is bound to, or a new run the namespace itself
/// allows (see `lane.rs`, task row M6-C65); a Redis that came back empty or
/// from an older snapshot remains a fail-closed recovery event.
#[derive(Clone)]
pub struct RedisCatalog {
    client: redis::Client,
    connection: Arc<AuthorityLane>,
    /// Authorization snapshots use a bounded set of separate physical
    /// connections so a delayed atomic authorization EVAL cannot
    /// head-of-line block owner, recovery, or fixture transactions on the
    /// catalog connection (or every other authorization read). The Lua
    /// operation itself remains atomic on Redis; only its transport lanes are
    /// isolated.
    authorization_connections: Arc<Vec<AuthorityLane>>,
    authorization_next: Arc<AtomicUsize>,
    /// Maintenance identity reads and owner renewals use their own bounded
    /// lanes for the same reason: the relay's tick must never wait behind a
    /// seed, cleanup, membership publish, or authorization pipeline, and an
    /// authority deadline observed there must mean the authority stalled.
    maintenance_connections: Arc<Vec<AuthorityLane>>,
    maintenance_next: Arc<AtomicUsize>,
    namespace: String,
    prefix: String,
    /// The loss generation and Redis run binding every lane shares.
    lane_group: Arc<LaneGroup>,
    deployment_incarnation: Option<String>,
    max_list_items: usize,
}

/// Explicit TLS material for a Redis authority connection.
///
/// The relay's low-level catalog API normally uses the system/webpki trust
/// roots for `rediss://`.  Tests and deployments with a private Redis CA can
/// pass a bounded PEM trust bundle here.  Client certificate and key material
/// must be supplied together; private bytes are never included in `Debug`.
#[derive(Clone, Default)]
pub struct RedisTlsOptions {
    pub root_cert_pem: Option<Vec<u8>>,
    pub client_cert_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
}

impl std::fmt::Debug for RedisTlsOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisTlsOptions")
            .field("has_root_cert", &self.root_cert_pem.is_some())
            .field("has_client_identity", &self.client_cert_pem.is_some())
            .finish()
    }
}

impl RedisTlsOptions {
    pub fn with_root_cert_pem(root_cert_pem: impl Into<Vec<u8>>) -> Self {
        Self {
            root_cert_pem: Some(root_cert_pem.into()),
            ..Self::default()
        }
    }

    pub fn with_client_identity_pem(
        mut self,
        client_cert_pem: impl Into<Vec<u8>>,
        client_key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.client_cert_pem = Some(client_cert_pem.into());
        self.client_key_pem = Some(client_key_pem.into());
        self
    }

    fn into_redis_certificates(self) -> Result<redis::TlsCertificates, CatalogError> {
        if self
            .root_cert_pem
            .as_ref()
            .is_some_and(|pem| pem.is_empty() || pem.len() > MAX_REDIS_TLS_PEM_BYTES)
        {
            return Err(CatalogError::InvalidInput(
                "Redis TLS root certificate PEM must be 1..=1048576 bytes",
            ));
        }
        if self
            .client_cert_pem
            .as_ref()
            .is_some_and(|pem| pem.is_empty() || pem.len() > MAX_REDIS_TLS_PEM_BYTES)
        {
            return Err(CatalogError::InvalidInput(
                "Redis TLS client certificate PEM must be 1..=1048576 bytes",
            ));
        }
        if self
            .client_key_pem
            .as_ref()
            .is_some_and(|pem| pem.is_empty() || pem.len() > MAX_REDIS_TLS_PEM_BYTES)
        {
            return Err(CatalogError::InvalidInput(
                "Redis TLS client key PEM must be 1..=1048576 bytes",
            ));
        }
        let client_tls = match (self.client_cert_pem, self.client_key_pem) {
            (Some(client_cert), Some(client_key)) => Some(redis::ClientTlsConfig {
                client_cert,
                client_key,
            }),
            (None, None) => None,
            _ => {
                return Err(CatalogError::InvalidInput(
                    "Redis TLS client certificate and key must be supplied together",
                ));
            }
        };
        Ok(redis::TlsCertificates {
            client_tls,
            root_cert: self.root_cert_pem,
        })
    }
}

/// Redis stores one envelope per node in the directory hash.  The version is
/// encoded as a decimal string so Lua comparisons remain exact for the full
/// `u64` range; signed membership bytes remain opaque and are base64-encoded
/// by serde inside this envelope.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct DirectoryMembershipValue {
    version: String,
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct MembershipNodeId {
    node_id: String,
}

/// A separately constructed publisher handle for the operator-only signed
/// membership namespace.  Relay/catalog handles expose reads only; deployments
/// should give this connection a Redis ACL limited to `membership:operator:*`.
#[derive(Clone)]
pub struct RedisMembershipPublisher {
    catalog: RedisCatalog,
}

impl std::fmt::Debug for RedisMembershipPublisher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisMembershipPublisher")
            .field("namespace", &self.catalog.namespace)
            .finish_non_exhaustive()
    }
}

impl RedisMembershipPublisher {
    /// Connect with the operator's separately authenticated Redis URL.  ACL
    /// enforcement is intentionally delegated to Redis deployment policy; the
    /// catalog code never treats signed bytes as trust anchors.
    pub async fn connect(redis_url: &str, namespace: &str) -> Result<Self, CatalogError> {
        Ok(Self {
            catalog: RedisCatalog::connect(redis_url, namespace).await?,
        })
    }

    pub async fn publish_signed_membership(
        &self,
        record: &SignedMembershipRecord,
    ) -> Result<(), CatalogError> {
        cluster::validate_membership_bytes(&record.bytes)?;
        if record.version == 0 {
            return Err(CatalogError::InvalidInput("signed membership version"));
        }
        // SignedMembershipRecord is intentionally opaque at the catalog
        // boundary.  We inspect only the bounded node_id field to select a
        // directory slot; the cluster verifier still authenticates every
        // signed field before admission.  Keep the legacy path for old
        // publisher fixtures that contain arbitrary opaque bytes.
        if let Ok(node_id) = membership_node_id(&record.bytes) {
            return self
                .publish_signed_membership_for_node(&node_id, record)
                .await;
        }
        let version = record.version.to_string();
        let reply: Vec<String> = self
            .catalog
            .eval_membership_publish(&version, &record.bytes)
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(()),
            Some("stale") => Err(CatalogError::Conflict("signed membership version")),
            Some("conflict") => Err(CatalogError::Conflict("signed membership contents")),
            _ => Err(CatalogError::Serialization(
                "invalid Redis membership publish reply".into(),
            )),
        }
    }

    /// Publish one independently signed relay record into the bounded
    /// operator directory.  The node id is an index only; it does not grant
    /// trust and is checked again against the signed bytes by the reader and
    /// cluster verifier.
    pub async fn publish_signed_membership_for_node(
        &self,
        node_id: &str,
        record: &SignedMembershipRecord,
    ) -> Result<(), CatalogError> {
        cluster::validate_membership_bytes(&record.bytes)?;
        cluster::validate_identifier(node_id, 128)?;
        if record.version == 0 {
            return Err(CatalogError::InvalidInput("signed membership version"));
        }
        let encoded_node_id = membership_node_id(&record.bytes)?;
        if encoded_node_id != node_id {
            return Err(CatalogError::InvalidInput("signed membership node id"));
        }
        let envelope = DirectoryMembershipValue {
            version: record.version.to_string(),
            bytes: record.bytes.clone(),
        };
        let envelope = serde_json::to_vec(&envelope)?;
        let reply = self
            .catalog
            .eval_membership_publish_directory(node_id, &record.version.to_string(), &envelope)
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(()),
            Some("stale") => Err(CatalogError::Conflict("signed membership version")),
            Some("conflict") => Err(CatalogError::Conflict("signed membership contents")),
            Some("bound") => Err(CatalogError::Conflict("signed membership directory bound")),
            _ => Err(CatalogError::Serialization(
                "invalid Redis membership publish reply".into(),
            )),
        }
    }
}

impl std::fmt::Debug for RedisCatalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisCatalog")
            .field("namespace", &self.namespace)
            .field(
                "deployment_incarnation_configured",
                &self.deployment_incarnation.is_some(),
            )
            .field("max_list_items", &self.max_list_items)
            .finish_non_exhaustive()
    }
}

impl RedisCatalog {
    /// Connect to one explicitly selected Redis primary and namespace.
    /// `namespace` is durable identity state and must not be changed when a
    /// deployment incarnation changes after an uncertain Redis restore.
    pub async fn connect(redis_url: &str, namespace: &str) -> Result<Self, CatalogError> {
        Self::connect_staged(redis_url, namespace)
            .await
            .map_err(CatalogConnectionError::into_catalog_error)
    }

    /// [`Self::connect`] keeping the bounded stage, lane and failure class
    /// for operator diagnostics.
    pub async fn connect_staged(
        redis_url: &str,
        namespace: &str,
    ) -> Result<Self, CatalogConnectionError> {
        Self::connect_inner(redis_url, namespace, None).await
    }

    /// Connect to Redis over verified TLS with an explicit trust bundle and,
    /// optionally, a client certificate/key pair. The URL must use the
    /// `rediss://` scheme; the TLS handshake and the first PING/INFO exchange
    /// complete before this returns.
    pub async fn connect_with_tls(
        redis_url: &str,
        namespace: &str,
        tls: RedisTlsOptions,
    ) -> Result<Self, CatalogError> {
        Self::connect_with_tls_staged(redis_url, namespace, tls)
            .await
            .map_err(CatalogConnectionError::into_catalog_error)
    }

    /// [`Self::connect_with_tls`] keeping the bounded stage, lane and failure
    /// class for operator diagnostics.
    pub async fn connect_with_tls_staged(
        redis_url: &str,
        namespace: &str,
        tls: RedisTlsOptions,
    ) -> Result<Self, CatalogConnectionError> {
        Self::connect_inner(redis_url, namespace, Some(tls)).await
    }

    async fn connect_inner(
        redis_url: &str,
        namespace: &str,
        tls: Option<RedisTlsOptions>,
    ) -> Result<Self, CatalogConnectionError> {
        validate_redis_namespace(namespace).map_err(|error| {
            catalog_connection_error(CatalogConnectionStage::AuthorityProfile, error)
        })?;
        if redis_url.trim().is_empty() {
            return Err(catalog_connection_error(
                CatalogConnectionStage::ConnectionEstablishment,
                CatalogError::InvalidInput("redis URL"),
            ));
        }
        let client = match tls {
            Some(tls) => {
                let connection_info = redis_url.into_connection_info().map_err(|error| {
                    catalog_connection_error(CatalogConnectionStage::ConnectionEstablishment, error)
                })?;
                if !matches!(
                    connection_info.addr(),
                    redis::ConnectionAddr::TcpTls {
                        insecure: false,
                        ..
                    }
                ) {
                    return Err(catalog_connection_error(
                        CatalogConnectionStage::TlsSetup,
                        CatalogError::InvalidInput(
                            "Redis TLS connection requires a verified rediss:// URL",
                        ),
                    ));
                }
                let certificates = tls.into_redis_certificates().map_err(|error| {
                    catalog_connection_error(CatalogConnectionStage::TlsSetup, error)
                })?;
                redis::Client::build_with_tls(connection_info, certificates).map_err(|error| {
                    catalog_connection_error(CatalogConnectionStage::ConnectionEstablishment, error)
                })?
            }
            None => redis::Client::open(redis_url).map_err(|error| {
                catalog_connection_error(CatalogConnectionStage::ConnectionEstablishment, error)
            })?,
        };
        let (connection, redis_run_id) = open_verified_connection(&client).await?;
        let lane_group = Arc::new(LaneGroup::default());
        // Lanes are numbered 1..=LANE_CONNECTIONS in opening order so a
        // failure after the primary connection names the lane that failed.
        let open_lanes = async |first: usize,
                                count: usize|
               -> Result<Vec<AuthorityLane>, CatalogConnectionError> {
            let mut lanes = Vec::with_capacity(count);
            for offset in 0..count {
                let lane_number = CatalogConnectionLane {
                    index: u8::try_from(first + offset).unwrap_or(u8::MAX),
                    total: u8::try_from(LANE_CONNECTIONS).unwrap_or(u8::MAX),
                };
                let (lane_connection, lane_run_id) = open_verified_connection(&client)
                    .await
                    .map_err(|error| error.with_lane(lane_number))?;
                if lane_run_id != redis_run_id {
                    return Err(catalog_connection_error(
                        CatalogConnectionStage::PrimaryIdentity,
                        CatalogError::Conflict(lane::RUN_ID_CONFLICT),
                    )
                    .with_failure(CatalogConnectionFailure::RunIdConflict)
                    .with_lane(lane_number));
                }
                lanes.push(AuthorityLane::new(
                    client.clone(),
                    lane_connection,
                    redis_run_id.clone(),
                    Arc::clone(&lane_group),
                ));
            }
            Ok(lanes)
        };
        let authorization_connections = open_lanes(1, AUTHORIZATION_CONNECTIONS).await?;
        let maintenance_connections =
            open_lanes(1 + AUTHORIZATION_CONNECTIONS, MAINTENANCE_CONNECTIONS).await?;
        let connection_group = Arc::clone(&lane_group);
        let connection = Arc::new(AuthorityLane::new(
            client.clone(),
            connection,
            redis_run_id,
            lane_group,
        ));
        Ok(Self {
            client,
            connection,
            authorization_connections: Arc::new(authorization_connections),
            authorization_next: Arc::new(AtomicUsize::new(0)),
            maintenance_connections: Arc::new(maintenance_connections),
            maintenance_next: Arc::new(AtomicUsize::new(0)),
            namespace: namespace.to_owned(),
            prefix: format!("tunnel-catalog:{namespace}:"),
            lane_group: connection_group,
            deployment_incarnation: None,
            max_list_items: DEFAULT_MAX_LIST_ITEMS,
        })
    }

    /// Connect with the operator-provisioned incarnation used for owner
    /// fencing. A different persisted incarnation or Redis server run is
    /// rejected; recovery uses `connect_for_recovery` instead.
    pub async fn connect_with_deployment_incarnation(
        redis_url: &str,
        namespace: &str,
        deployment_incarnation: &str,
    ) -> Result<Self, CatalogError> {
        Self::connect_with_deployment_incarnation_staged(
            redis_url,
            namespace,
            deployment_incarnation,
        )
        .await
        .map_err(CatalogConnectionError::into_catalog_error)
    }

    /// Staged startup connection used by the relay's bounded diagnostics.
    /// Existing callers should use [`Self::connect_with_deployment_incarnation`]
    /// when they only need the catalog error classification.
    pub async fn connect_with_deployment_incarnation_staged(
        redis_url: &str,
        namespace: &str,
        deployment_incarnation: &str,
    ) -> Result<Self, CatalogConnectionError> {
        let mut catalog = Self::connect_inner(redis_url, namespace, None).await?;
        catalog
            .configure_deployment_incarnation(deployment_incarnation)
            .map_err(|error| {
                catalog_connection_error(CatalogConnectionStage::AuthorityProfile, error)
            })?;
        catalog
            .ensure_active_incarnation_classified()
            .await
            .map_err(|(error, failure)| {
                let error =
                    catalog_connection_error(CatalogConnectionStage::AuthorityIdentity, error);
                match failure {
                    Some(failure) => error.with_failure(failure),
                    None => error,
                }
            })?;
        Ok(catalog)
    }

    /// TLS-configured variant of [`Self::connect_with_deployment_incarnation`].
    pub async fn connect_with_tls_and_deployment_incarnation(
        redis_url: &str,
        namespace: &str,
        deployment_incarnation: &str,
        tls: RedisTlsOptions,
    ) -> Result<Self, CatalogError> {
        Self::connect_with_tls_and_deployment_incarnation_staged(
            redis_url,
            namespace,
            deployment_incarnation,
            tls,
        )
        .await
        .map_err(CatalogConnectionError::into_catalog_error)
    }

    /// TLS-configured staged startup connection used by the relay's bounded
    /// diagnostics. Existing callers should use
    /// [`Self::connect_with_tls_and_deployment_incarnation`] when they only
    /// need the catalog error classification.
    pub async fn connect_with_tls_and_deployment_incarnation_staged(
        redis_url: &str,
        namespace: &str,
        deployment_incarnation: &str,
        tls: RedisTlsOptions,
    ) -> Result<Self, CatalogConnectionError> {
        let mut catalog = Self::connect_inner(redis_url, namespace, Some(tls)).await?;
        catalog
            .configure_deployment_incarnation(deployment_incarnation)
            .map_err(|error| {
                catalog_connection_error(CatalogConnectionStage::AuthorityProfile, error)
            })?;
        catalog
            .ensure_active_incarnation_classified()
            .await
            .map_err(|(error, failure)| {
                let error =
                    catalog_connection_error(CatalogConnectionStage::AuthorityIdentity, error);
                match failure {
                    Some(failure) => error.with_failure(failure),
                    None => error,
                }
            })?;
        Ok(catalog)
    }

    /// Connect for an operator-controlled recovery transition. This leaves
    /// the configured incarnation inactive until the caller has reviewed
    /// quiescence and invokes `activate_deployment_incarnation` explicitly.
    pub async fn connect_for_recovery(
        redis_url: &str,
        namespace: &str,
        deployment_incarnation: &str,
    ) -> Result<Self, CatalogError> {
        Self::connect_for_recovery_staged(redis_url, namespace, deployment_incarnation)
            .await
            .map_err(CatalogConnectionError::into_catalog_error)
    }

    /// [`Self::connect_for_recovery`] keeping the bounded stage, lane and
    /// failure class for operator diagnostics.
    pub async fn connect_for_recovery_staged(
        redis_url: &str,
        namespace: &str,
        deployment_incarnation: &str,
    ) -> Result<Self, CatalogConnectionError> {
        let mut catalog = Self::connect_inner(redis_url, namespace, None).await?;
        catalog
            .configure_deployment_incarnation(deployment_incarnation)
            .map_err(|error| {
                catalog_connection_error(CatalogConnectionStage::AuthorityProfile, error)
            })?;
        Ok(catalog)
    }

    /// TLS-configured variant of [`Self::connect_for_recovery`].
    pub async fn connect_for_recovery_with_tls(
        redis_url: &str,
        namespace: &str,
        deployment_incarnation: &str,
        tls: RedisTlsOptions,
    ) -> Result<Self, CatalogError> {
        Self::connect_for_recovery_with_tls_staged(
            redis_url,
            namespace,
            deployment_incarnation,
            tls,
        )
        .await
        .map_err(CatalogConnectionError::into_catalog_error)
    }

    /// [`Self::connect_for_recovery_with_tls`] keeping the bounded stage,
    /// lane and failure class for operator diagnostics.
    pub async fn connect_for_recovery_with_tls_staged(
        redis_url: &str,
        namespace: &str,
        deployment_incarnation: &str,
        tls: RedisTlsOptions,
    ) -> Result<Self, CatalogConnectionError> {
        let mut catalog = Self::connect_inner(redis_url, namespace, Some(tls)).await?;
        catalog
            .configure_deployment_incarnation(deployment_incarnation)
            .map_err(|error| {
                catalog_connection_error(CatalogConnectionStage::AuthorityProfile, error)
            })?;
        Ok(catalog)
    }

    /// Configure the operator-provisioned owner-fencing incarnation. This
    /// only changes local configuration; `activate_deployment_incarnation`
    /// performs the separate Redis authority transition.
    pub fn configure_deployment_incarnation(
        &mut self,
        deployment_incarnation: &str,
    ) -> Result<(), CatalogError> {
        validate_identifier(deployment_incarnation, MAX_IDENTIFIER_BYTES)?;
        if self
            .deployment_incarnation
            .as_deref()
            .is_some_and(|current| current != deployment_incarnation)
        {
            return Err(CatalogError::Conflict(
                "deployment incarnation configuration",
            ));
        }
        self.deployment_incarnation = Some(deployment_incarnation.to_owned());
        Ok(())
    }

    /// Single relay only (M6-C65): let this catalog's lanes adopt a new Redis
    /// run the namespace allows -- one an operator re-attested with
    /// `rebind-redis-run`, or, with a continuity witness, one holding this
    /// process's last acknowledged token.  A catalog that never calls this,
    /// including every `[cluster]` relay's, refuses any run but the one it
    /// connected to, as before M6-C65.
    pub fn enable_run_rebinding(&self) -> Result<(), CatalogError> {
        let incarnation = self.configured_incarnation()?;
        self.lane_group.binding().set_scope(RebindScope {
            incarnation: incarnation.to_owned(),
            incarnation_key: self.active_incarnation_key(),
            run_key: self.redis_run_id_key(),
            continuity_key: self.continuity_key(),
        });
        Ok(())
    }

    /// Compatibility bootstrap/fixture path for setting the configured
    /// incarnation as active. Production recovery must use
    /// `activate_deployment_incarnation_with_approval`, which verifies an
    /// external approval and a fresh durable-catalog observation first. This
    /// method is idempotent for the same incarnation and Redis run, or
    /// installs a different incarnation when no live owner exists. A Redis
    /// run change requires a different incarnation and never promotes
    /// automatically.
    pub async fn activate_deployment_incarnation(&self) -> Result<(), CatalogError> {
        let incarnation = self.configured_incarnation()?;
        let reply: Vec<String> = self
            .eval(
                SCRIPT_ACTIVATE_INCARNATION,
                &[
                    self.active_incarnation_key(),
                    self.tenants_index(),
                    self.redis_run_id_key(),
                ],
                &[
                    self.prefix.clone(),
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(()),
            Some("busy") => Err(CatalogError::OwnerBusy),
            Some("bound") => Err(CatalogError::Conflict("owner lease scan bound")),
            Some("mismatch") => Err(CatalogError::Conflict("active deployment incarnation")),
            _ => Err(CatalogError::Serialization(
                "invalid Redis incarnation reply".into(),
            )),
        }
    }

    /// Operator bootstrap: make the configured incarnation the first active
    /// incarnation of a namespace that holds **no key at all** (task row
    /// M6-C21).
    ///
    /// This is deliberately narrower than
    /// [`Self::activate_deployment_incarnation`], which also *replaces* an
    /// incarnation when no live owner exists -- a transition that, outside a
    /// disposable fixture, belongs to the approved recovery workflow.  Here any
    /// existing active incarnation, Redis run binding or other namespace key is
    /// a refusal, so a shipped command built on this can never become a way to
    /// move a live deployment to a new incarnation without recovery approval.
    /// The incarnation and the Redis run id are written in the same script that
    /// proves the namespace empty.
    pub async fn activate_first_deployment_incarnation(&self) -> Result<(), CatalogError> {
        let incarnation = self.configured_incarnation()?;
        let reply: Vec<String> = self
            .eval(
                SCRIPT_ACTIVATE_FIRST_INCARNATION,
                &[self.active_incarnation_key(), self.redis_run_id_key()],
                &[
                    self.prefix.clone(),
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                    MAX_SEED_SCAN_KEYS.to_string(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(()),
            Some("active") => Err(CatalogError::Conflict(
                "namespace already has a deployment incarnation; changing it requires recovery",
            )),
            Some("occupied") => Err(CatalogError::Conflict(
                "namespace is not empty; first activation requires an empty namespace",
            )),
            Some("bound") => Err(CatalogError::Conflict("namespace scan bound")),
            _ => Err(CatalogError::Serialization(
                "invalid Redis incarnation reply".into(),
            )),
        }
    }

    /// The Redis server run this catalog is bound to now (M6-C65).  It
    /// changes only when a lane adopts a restarted run the namespace allows.
    pub fn bound_redis_run_id(&self) -> String {
        self.lane_group.binding().run_id()
    }

    /// How many times this catalog has moved its binding to a restarted
    /// Redis run (M6-C65).
    pub fn redis_run_rebinds(&self) -> u64 {
        self.lane_group.binding().rebinds()
    }

    /// Operator re-attestation after an orderly Redis restart (M6-C65,
    /// `tunnel-relay rebind-redis-run`): move the namespace's run binding to
    /// the run this connection verified, so `serve` accepts the namespace
    /// again without reprovisioning.
    ///
    /// One script refuses a namespace without its incarnation or run binding
    /// (never activated, or Redis came back empty) and a namespace whose
    /// incarnation is not the configured one, and otherwise writes only the
    /// run binding.  It cannot tell a restart that kept every acknowledged
    /// write from a restore of an older consistent snapshot: the caller's
    /// declaration that Redis restarted from its own persistence is what
    /// covers that, and a relay that stayed up across the restart proves it
    /// instead with its continuity witness
    /// ([`Self::enable_restart_continuity`]).
    pub async fn rebind_restarted_redis_run(&self) -> Result<RedisRunRebind, CatalogError> {
        let incarnation = self.configured_incarnation()?;
        let reply: Vec<String> = self
            .eval(
                SCRIPT_OPERATOR_REBIND_RUN,
                &[self.active_incarnation_key(), self.redis_run_id_key()],
                &[incarnation.to_owned(), bound_run_id().to_owned()],
            )
            .await?;
        match reply.as_slice() {
            [status, current] if status == "current" => Ok(RedisRunRebind::AlreadyCurrent {
                run_id: current.clone(),
            }),
            [status, previous, current] if status == "rebound" => Ok(RedisRunRebind::Rebound {
                previous_run_id: previous.clone(),
                run_id: current.clone(),
            }),
            [status] if status == "unbound" => Err(CatalogError::Conflict(NAMESPACE_UNBOUND)),
            [status] if status == "incarnation" => {
                Err(CatalogError::Conflict("active deployment incarnation"))
            }
            _ => Err(CatalogError::Serialization(
                "invalid Redis run binding reply".into(),
            )),
        }
    }

    /// Single relay only (M6-C65): keep a continuity witness in this process
    /// and write its first token, so that after an in-place Redis restart the
    /// lanes can re-bind to the new run when, and only when, Redis still holds
    /// this process's last acknowledged token.  The caller then calls
    /// [`Self::advance_restart_continuity`] every `interval`, and
    /// [`Self::disable_restart_continuity`] if it stops doing so.
    ///
    /// Refused unless run re-binding is enabled
    /// ([`Self::enable_run_rebinding`]) and `CONFIG GET` shows `appendonly
    /// yes`, `appendfsync always` and `no-appendfsync-on-rewrite no`: with a
    /// looser policy a crash can lose acknowledged writes made after the last
    /// token, which the witness cannot see.  A refused `CONFIG GET` is refused
    /// the same way.  The lanes check the same settings again on the new run
    /// before every token re-binding.  Sound for one Redis restarting from its
    /// own AOF only, not across failover or replica promotion (see
    /// `lane.rs`).
    pub async fn enable_restart_continuity(&self, interval: Duration) -> Result<(), CatalogError> {
        self.configured_incarnation()?;
        if !self.lane_group.binding().has_scope() {
            return Err(CatalogError::InvalidInput(
                "restart continuity requires run re-binding",
            ));
        }
        let mut command = redis::cmd("CONFIG");
        command
            .arg("GET")
            .arg("appendonly")
            .arg("appendfsync")
            .arg("no-appendfsync-on-rewrite");
        let sound = match self.connection.query::<Vec<String>>(&command).await {
            Ok(pairs) => lane::persistence_is_sound(&pairs),
            // Redis answered with a refusal (`NOPERM`, an unknown or renamed
            // command): nothing proves the writes durable.
            Err(CatalogError::Database(error)) if error.code().is_some() => false,
            Err(error) => return Err(error),
        };
        if !sound {
            return Err(CatalogError::Conflict(PERSISTENCE_UNSOUND));
        }
        self.lane_group.binding().enable_witness(interval);
        self.advance_restart_continuity().await
    }

    /// Stop re-binding on continuity tokens (M6-C65): the relay's token loop
    /// ended, so the last token no longer bounds what Redis acknowledged.  A
    /// restarted Redis is then refused as `run_changed` until an operator
    /// re-attests it.
    pub fn disable_restart_continuity(&self) {
        self.lane_group.binding().disable_witness();
    }

    /// Write a new continuity token (M6-C65).  The token is recorded as a
    /// candidate before dispatch, becomes the only candidate once Redis
    /// acknowledges it, is dropped when the write definitely did not happen,
    /// and stays a candidate when its outcome is unknown.  The script writes
    /// only while the namespace is bound to this configured incarnation and
    /// to the run the lane verified.
    pub async fn advance_restart_continuity(&self) -> Result<(), CatalogError> {
        let incarnation = self.configured_incarnation()?.to_owned();
        let binding = self.lane_group.binding();
        if !binding.witness_enabled() {
            return Err(CatalogError::InvalidInput(
                "restart continuity is not enabled",
            ));
        }
        let token = Uuid::new_v4().simple().to_string();
        binding.continuity_dispatching(&token);
        let result: Result<Vec<String>, CatalogError> = self
            .connection
            .query_eval(
                SCRIPT_ADVANCE_CONTINUITY,
                &[
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                    self.continuity_key(),
                ],
                &[incarnation, bound_run_id().to_owned(), token.clone()],
                true,
            )
            .await;
        let refused = match result {
            Ok(reply) => match reply.first().map(String::as_str) {
                Some("ok") => {
                    binding.continuity_acknowledged(&token);
                    return Ok(());
                }
                Some("unbound") => CatalogError::Conflict(NAMESPACE_UNBOUND),
                Some("incarnation") => CatalogError::Conflict("active deployment incarnation"),
                Some("run") => CatalogError::Conflict(RUN_BINDING_CHANGED),
                _ => CatalogError::Serialization("invalid Redis continuity reply".into()),
            },
            Err(error @ CatalogError::WriteOutcomeUnknown(_)) => return Err(error),
            Err(error) => error,
        };
        binding.continuity_not_written(&token);
        Err(refused)
    }

    /// Operator bootstrap: write the first tenant-scoped authority records into
    /// a namespace whose configured incarnation is active and which holds
    /// nothing else (task row M6-C21).
    ///
    /// It shares every rule with the fixture seed rather than restating any:
    /// the same `validate_fixture` relationship and bound checks, the same
    /// one-shot reservation script and key, and the same record writer,
    /// credential-fingerprint uniqueness script and grant upsert.  What differs
    /// is the precondition: the fixture seed accepts only disposable
    /// `test-`/`fixture-` namespaces, while this accepts any valid namespace but
    /// first requires the same active-incarnation and Redis-run check `serve`
    /// applies at startup, so records are never written where a relay could
    /// not start.  The reservation key is the existing `meta:fixture_seeded`
    /// marker because the recovery snapshot schema already classifies it; a
    /// new marker would make every provisioned namespace unobservable by
    /// `recovery-observe`.
    ///
    /// The reservation is taken before any record is written, so a second run
    /// is refused even after a partial failure; a namespace left partial is
    /// discarded, not repaired, exactly as the fixture seed's is.
    pub async fn provision_initial_catalog(
        &self,
        records: &CatalogFixture,
    ) -> Result<(), CatalogError> {
        validate_fixture(records)?;
        self.ensure_active_incarnation().await?;
        match self.reserve_empty_namespace().await? {
            NamespaceReservation::Reserved => {}
            NamespaceReservation::AlreadyReserved => {
                return Err(CatalogError::Conflict("namespace was already provisioned"));
            }
            NamespaceReservation::Occupied => {
                return Err(CatalogError::Conflict(
                    "namespace holds records other than its active incarnation",
                ));
            }
            NamespaceReservation::ScanBound => {
                return Err(CatalogError::Conflict("namespace scan bound"));
            }
        }
        self.write_seed_records(records).await
    }

    /// Day-2 catalog change (task row M6-C31): add one user, bound to one
    /// issuer identity, as a member of one existing tenant.
    ///
    /// One Lua script checks and writes everything, so the change is atomic:
    /// the namespace must already be provisioned (`meta:fixture_seeded`, so a
    /// day-2 write can never make `provision-catalog` refuse a namespace it
    /// has not run on yet), the configured incarnation and Redis run must be
    /// the active ones (the fence `serve` applies), the tenant must be active,
    /// and the user, the identity and the membership must all be new.  A
    /// duplicate of any of them is refused and nothing is written; nothing
    /// existing is ever overwritten.  The key layout and fields are exactly
    /// those `write_seed_records` writes, and the catalog generation advances
    /// as for every other catalog mutation.  The incarnation and run keys
    /// are read, never written.
    pub async fn add_user(
        &self,
        user: &UserRecord,
        identity: &PrincipalIdentity,
        membership: &MembershipRecord,
    ) -> Result<(), CatalogError> {
        validate_user_addition(user, identity, membership)?;
        let incarnation = self.configured_incarnation()?;
        let identity_key = self.identity_key(&identity.issuer, &identity.subject);
        let reply: Vec<String> = self
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{LUA_DAY2_PRECONDITIONS}{SCRIPT_ADD_USER_BODY}"),
                &[
                    self.fixture_seed_guard_key(),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                    self.catalog_generation_key(),
                    self.tenant_key(membership.tenant_id),
                    self.user_key(user.user_id),
                    identity_key.clone(),
                    self.membership_key(membership.tenant_id, user.user_id),
                    self.users_index(),
                    self.identities_index(),
                    self.memberships_index(membership.tenant_id),
                    self.user_tenants_index(user.user_id),
                ],
                &[
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                    membership.tenant_id.to_string(),
                    user.user_id.to_string(),
                    user.display_name.clone(),
                    identity.issuer.clone(),
                    identity.subject.clone(),
                    membership.role.as_str().to_owned(),
                    identity_key,
                ],
            )
            .await?;
        day2_reply(&reply)
    }

    /// Day-2 catalog change (M6-C31): add one device, owned by an existing
    /// active member of an existing active tenant, with its one credential.
    ///
    /// Device and credential are written by one script, with the same
    /// preconditions as [`Self::add_user`].  The device must be new in its
    /// tenant (a revoked device is not reused: its owner epoch and version
    /// must never go backwards), and the SPKI pin must not be bound to any
    /// credential, as `SCRIPT_SEED_CREDENTIAL` requires.  The owner epoch is
    /// created with `SETNX`, exactly as the seed does.
    pub async fn add_device(
        &self,
        device: &FixtureDevice,
        credential: &CredentialRecord,
    ) -> Result<(), CatalogError> {
        validate_device_addition(device, credential)?;
        let incarnation = self.configured_incarnation()?;
        let credential_key = self.credential_key(
            credential.tenant_id,
            credential.device_id,
            credential.credential_id,
        );
        let reply: Vec<String> = self
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{LUA_DAY2_PRECONDITIONS}{SCRIPT_ADD_DEVICE_BODY}"),
                &[
                    self.fixture_seed_guard_key(),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                    self.catalog_generation_key(),
                    self.tenant_key(device.tenant_id),
                    self.membership_key(device.tenant_id, device.owner_user_id),
                    self.device_key(device.tenant_id, device.device_id),
                    self.devices_index(device.tenant_id),
                    self.owner_epoch_key(device.tenant_id, device.device_id),
                    credential_key.clone(),
                    self.fingerprint_index(&credential.spki_fingerprint),
                    self.credentials_index(device.tenant_id, device.device_id),
                ],
                &[
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                    device.tenant_id.to_string(),
                    device.device_id.to_string(),
                    device.owner_user_id.to_string(),
                    device.display_name.clone(),
                    credential.credential_id.to_string(),
                    credential.spki_fingerprint.clone(),
                    credential.serial.clone().unwrap_or_default(),
                    datetime_micros(credential.not_before)?.to_string(),
                    datetime_micros(credential.expires_at)?.to_string(),
                    credential_key,
                ],
            )
            .await?;
        day2_reply(&reply)
    }

    /// Day-2 catalog change (M6-C31): add one service to an existing active
    /// device, with the preconditions of [`Self::add_user`].  The service
    /// must be new; its record is the seed's layout at version 1.
    pub async fn add_service(&self, service: &ServiceSpec) -> Result<(), CatalogError> {
        validate_service_addition(service)?;
        let incarnation = self.configured_incarnation()?;
        let reply: Vec<String> = self
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{LUA_DAY2_PRECONDITIONS}{SCRIPT_ADD_SERVICE_BODY}"),
                &[
                    self.fixture_seed_guard_key(),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                    self.catalog_generation_key(),
                    self.tenant_key(service.tenant_id),
                    self.device_key(service.tenant_id, service.device_id),
                    self.service_key(service.tenant_id, service.device_id, service.service_id),
                    self.services_index(service.tenant_id, service.device_id),
                ],
                &[
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                    service.tenant_id.to_string(),
                    service.device_id.to_string(),
                    service.service_id.to_string(),
                    service.service_type.clone(),
                    service.display_name.clone(),
                    serde_json::to_string(&service.capabilities)?,
                ],
            )
            .await?;
        day2_reply(&reply)
    }

    /// Whether a device record exists and is active (M6-C31): `None` when it
    /// does not exist.  `set-grant` refuses a device that is not active,
    /// because `upsert_grant` requires only that the device exists and a
    /// grant on a revoked device authorizes nothing.
    pub async fn device_active(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<bool>, CatalogError> {
        let mut command = redis::cmd("HGET");
        command
            .arg(self.device_key(tenant_id, device_id))
            .arg("active");
        let active: Option<String> = self.connection.query(&command).await?;
        Ok(active.map(|value| value == "1"))
    }

    /// Read one service record (M6-C31), so a grant can be checked against
    /// the service type and operations it will authorize.  `None` when the
    /// record does not exist.
    pub async fn read_service(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        service_id: Uuid,
    ) -> Result<Option<ServiceSpec>, CatalogError> {
        let mut command = redis::cmd("HMGET");
        command
            .arg(self.service_key(tenant_id, device_id, service_id))
            .arg("service_type")
            .arg("display_name")
            .arg("capabilities")
            .arg("version")
            .arg("active");
        let fields: Vec<Option<String>> = self.connection.query(&command).await?;
        let [service_type, display_name, capabilities, version, active] = fields.as_slice() else {
            return Err(CatalogError::Serialization(
                "invalid Redis service reply".into(),
            ));
        };
        let Some(service_type) = service_type else {
            return Ok(None);
        };
        Ok(Some(ServiceSpec {
            tenant_id,
            device_id,
            service_id,
            service_type: service_type.clone(),
            display_name: display_name.clone().unwrap_or_default(),
            capabilities: serde_json::from_str(capabilities.as_deref().unwrap_or("{}"))?,
            version: parse_u64_decimal(version.as_deref().unwrap_or("0"))?,
            active: active.as_deref() == Some("1"),
        }))
    }

    /// Take the one-shot seed reservation of a namespace holding nothing but
    /// its active incarnation, Redis run binding and, when a relay already
    /// served it, that relay's continuity token (M6-C65).
    async fn reserve_empty_namespace(&self) -> Result<NamespaceReservation, CatalogError> {
        let reply: Vec<String> = self
            .eval(
                SCRIPT_RESERVE_FIXTURE_NAMESPACE,
                &[
                    self.fixture_seed_guard_key(),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                    self.continuity_key(),
                ],
                &[self.prefix.clone(), MAX_SEED_SCAN_KEYS.to_string()],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(NamespaceReservation::Reserved),
            Some("used") => Ok(NamespaceReservation::AlreadyReserved),
            Some("occupied") => Ok(NamespaceReservation::Occupied),
            Some("bound") => Ok(NamespaceReservation::ScanBound),
            _ => Err(CatalogError::Serialization(
                "invalid Redis fixture reservation reply".into(),
            )),
        }
    }

    async fn ensure_active_incarnation(&self) -> Result<(), CatalogError> {
        self.ensure_active_incarnation_classified()
            .await
            .map_err(|(error, _)| error)
    }

    /// [`Self::ensure_active_incarnation`] with the bounded class of a
    /// refusal (M6-C65): `unbound` when the namespace has no incarnation or
    /// run binding (never activated, or Redis came back without its data),
    /// `run_changed` when it is bound to an earlier Redis run (Redis
    /// restarted and nothing re-attested it), and the error's own class for
    /// a different incarnation.  The error itself keeps the one conflict
    /// label callers already match.
    async fn ensure_active_incarnation_classified(
        &self,
    ) -> Result<(), (CatalogError, Option<CatalogConnectionFailure>)> {
        let incarnation = self
            .configured_incarnation()
            .map_err(|error| (error, None))?;
        let reply: Vec<String> = self
            .eval(
                SCRIPT_ENSURE_INCARNATION,
                &[
                    self.active_incarnation_key(),
                    self.tenants_index(),
                    self.redis_run_id_key(),
                ],
                &[incarnation.to_owned(), bound_run_id().to_owned()],
            )
            .await
            .map_err(|error| (error, None))?;
        let refused = |failure| {
            Err((
                CatalogError::Conflict("active deployment incarnation or Redis authority run"),
                failure,
            ))
        };
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(()),
            Some("unbound") => refused(Some(CatalogConnectionFailure::Unbound)),
            Some("run") => refused(Some(CatalogConnectionFailure::RunChanged)),
            Some("mismatch") => refused(None),
            _ => Err((
                CatalogError::Serialization("invalid Redis incarnation reply".into()),
                None,
            )),
        }
    }

    /// Remove all records from a bounded fixture namespace, deleting the
    /// one-shot seed reservation last. This explicit teardown is the only
    /// operation that makes a fixture namespace reusable. It is intentionally
    /// guarded so production namespaces cannot be erased accidentally.
    pub async fn cleanup_fixture_namespace(&self) -> Result<(), CatalogError> {
        if !is_fixture_namespace(&self.namespace) {
            return Err(CatalogError::InvalidInput("fixture namespace"));
        }
        let guard_key = self.fixture_seed_guard_key();
        let mut cursor = 0_u64;
        let mut keys = Vec::new();
        loop {
            let (next, mut batch): (u64, Vec<String>) = {
                let mut command = redis::cmd("SCAN");
                command
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(format!("{}*", self.prefix))
                    .arg("COUNT")
                    .arg(256_i64);
                self.connection.query(&command).await?
            };
            batch.retain(|key| key != &guard_key);
            keys.append(&mut batch);
            if keys.len() > MAX_CLEANUP_KEYS {
                return Err(CatalogError::Conflict("fixture cleanup bound"));
            }
            if next == 0 {
                break;
            }
            cursor = next;
        }
        if !keys.is_empty() {
            let mut pipeline = redis::pipe();
            pipeline.atomic();
            for key in keys {
                pipeline.cmd("DEL").arg(key).ignore();
            }
            self.connection.query_pipeline::<()>(&pipeline).await?;
        }
        let mut delete_guard = redis::cmd("DEL");
        delete_guard.arg(&guard_key);
        self.connection.query::<()>(&delete_guard).await?;
        Ok(())
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn deployment_incarnation(&self) -> Option<&str> {
        self.deployment_incarnation.as_deref()
    }

    pub fn with_max_list_items(mut self, max_items: usize) -> Result<Self, CatalogError> {
        if !(1..=MAX_CLEANUP_KEYS).contains(&max_items) {
            return Err(CatalogError::InvalidInput("Redis list bound"));
        }
        self.max_list_items = max_items;
        Ok(self)
    }

    fn configured_incarnation(&self) -> Result<&str, CatalogError> {
        self.deployment_incarnation
            .as_deref()
            .ok_or(CatalogError::InvalidOwner)
    }

    async fn eval<T: FromRedisValue>(
        &self,
        script: &str,
        keys: &[String],
        args: &[String],
    ) -> Result<T, CatalogError> {
        self.eval_on(&self.connection, script, keys, args).await
    }

    /// Run one maintenance script (`resolve_device`, `renew_owner`) on the
    /// next maintenance lane, round-robin.
    async fn eval_maintenance<T: FromRedisValue>(
        &self,
        script: &str,
        keys: &[String],
        args: &[String],
    ) -> Result<T, CatalogError> {
        let lane = self.maintenance_next.fetch_add(1, Ordering::Relaxed)
            % self.maintenance_connections.len();
        self.eval_on(&self.maintenance_connections[lane], script, keys, args)
            .await
    }

    async fn eval_on<T: FromRedisValue>(
        &self,
        lane: &AuthorityLane,
        script: &str,
        keys: &[String],
        args: &[String],
    ) -> Result<T, CatalogError> {
        lane.query_eval(script, keys, args, false).await
    }

    /// Run one owner-affecting write script (`claim_owner`, `release_owner`)
    /// on the catalog lane.  A reply lost after dispatch is the typed
    /// [`CatalogError::WriteOutcomeUnknown`], never a replay.
    async fn eval_owner_write<T: FromRedisValue>(
        &self,
        script: &str,
        keys: &[String],
        args: &[String],
    ) -> Result<T, CatalogError> {
        self.connection.query_eval(script, keys, args, true).await
    }

    /// Run the owner renewal script on the next maintenance lane with the
    /// same lost-reply contract as [`Self::eval_owner_write`].
    async fn eval_maintenance_owner_write<T: FromRedisValue>(
        &self,
        script: &str,
        keys: &[String],
        args: &[String],
    ) -> Result<T, CatalogError> {
        let lane = self.maintenance_next.fetch_add(1, Ordering::Relaxed)
            % self.maintenance_connections.len();
        self.maintenance_connections[lane]
            .query_eval(script, keys, args, true)
            .await
    }

    async fn eval_membership_publish(
        &self,
        version: &str,
        bytes: &[u8],
    ) -> Result<Vec<String>, CatalogError> {
        let mut command = redis::cmd("EVAL");
        command
            .arg(format!("{LUA_DECIMAL_HELPERS}{SCRIPT_PUBLISH_MEMBERSHIP}"))
            .arg(1_i64)
            .arg(self.signed_membership_key())
            .arg(version)
            .arg(bytes)
            .arg(cluster::MEMBERSHIP_TTL_SECONDS.to_string());
        self.connection.query(&command).await
    }

    async fn eval_membership_publish_directory(
        &self,
        node_id: &str,
        version: &str,
        envelope: &[u8],
    ) -> Result<Vec<String>, CatalogError> {
        let mut command = redis::cmd("EVAL");
        command
            .arg(format!(
                "{LUA_DECIMAL_HELPERS}{SCRIPT_PUBLISH_MEMBERSHIP_DIRECTORY}"
            ))
            .arg(1_i64)
            .arg(self.signed_membership_directory_key())
            .arg(node_id)
            .arg(version)
            .arg(envelope)
            .arg(MAX_SIGNED_MEMBERSHIP_RECORDS.to_string())
            .arg(cluster::MEMBERSHIP_TTL_SECONDS.to_string());
        self.connection.query(&command).await
    }

    async fn read_signed_membership_directory(
        &self,
    ) -> Result<Vec<SignedMembershipRecord>, CatalogError> {
        // The Lua side checks HLEN before HGETALL.  This keeps a malformed or
        // unauthorized directory from turning a catalog read into an
        // unbounded client allocation.
        let reply: Vec<String> = self
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{SCRIPT_READ_MEMBERSHIP_DIRECTORY}"),
                &[self.signed_membership_directory_key()],
                &[MAX_SIGNED_MEMBERSHIP_RECORDS.to_string()],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => {}
            Some("too_many") => {
                return Err(CatalogError::InvalidInput("signed membership count"));
            }
            _ => {
                return Err(CatalogError::Serialization(
                    "invalid Redis membership directory reply".into(),
                ));
            }
        }
        let payload = &reply[1..];
        if !payload.len().is_multiple_of(2) || payload.len() / 2 > MAX_SIGNED_MEMBERSHIP_RECORDS {
            return Err(CatalogError::Serialization(
                "invalid Redis membership directory shape".into(),
            ));
        }
        let mut records = Vec::with_capacity(payload.len() / 2);
        for pair in payload.chunks_exact(2) {
            let node_id = &pair[0];
            cluster::validate_identifier(node_id, 128)?;
            let envelope: DirectoryMembershipValue = serde_json::from_str(&pair[1])?;
            let version = parse_u64_decimal(&envelope.version)?;
            if version == 0 {
                return Err(CatalogError::Serialization(
                    "invalid Redis membership version".into(),
                ));
            }
            cluster::validate_membership_bytes(&envelope.bytes)?;
            if membership_node_id(&envelope.bytes)? != node_id.as_str() {
                return Err(CatalogError::Serialization(
                    "Redis membership node index mismatch".into(),
                ));
            }
            records.push(SignedMembershipRecord {
                version,
                bytes: envelope.bytes,
            });
        }
        Ok(records)
    }

    async fn read_legacy_signed_membership(
        &self,
    ) -> Result<Option<SignedMembershipRecord>, CatalogError> {
        let key = self.signed_membership_key();
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        pipeline.cmd("HGET").arg(&key).arg("version");
        pipeline.cmd("HGET").arg(&key).arg("bytes");
        let reply: (Option<String>, Option<Vec<u8>>) =
            self.connection.query_pipeline(&pipeline).await?;
        match reply {
            (None, None) => Ok(None),
            (Some(version), Some(bytes)) => {
                cluster::validate_membership_bytes(&bytes)?;
                let version = parse_u64_decimal(&version)?;
                if version == 0 {
                    return Err(CatalogError::Serialization(
                        "invalid Redis membership version".into(),
                    ));
                }
                Ok(Some(SignedMembershipRecord { version, bytes }))
            }
            _ => Err(CatalogError::Serialization(
                "partial Redis membership record".into(),
            )),
        }
    }

    /// Write every record of an already-validated seed into a namespace whose
    /// one-shot reservation the caller has just taken.  Shared by the fixture
    /// seed and the operator bootstrap so both write exactly one key layout.
    async fn write_seed_records(&self, fixture: &CatalogFixture) -> Result<(), CatalogError> {
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        for tenant in &fixture.tenants {
            pipeline
                .cmd("HSET")
                .arg(self.tenant_key(tenant.tenant_id))
                .arg("tenant_id")
                .arg(tenant.tenant_id.to_string())
                .arg("display_name")
                .arg(&tenant.display_name)
                .arg("active")
                .arg(bool_string(tenant.active));
            pipeline
                .cmd("SADD")
                .arg(self.tenants_index())
                .arg(tenant.tenant_id.to_string());
        }
        for user in &fixture.users {
            pipeline
                .cmd("HSET")
                .arg(self.user_key(user.user_id))
                .arg("user_id")
                .arg(user.user_id.to_string())
                .arg("display_name")
                .arg(&user.display_name);
            pipeline
                .cmd("SADD")
                .arg(self.users_index())
                .arg(user.user_id.to_string());
        }
        for identity in &fixture.identities {
            pipeline
                .cmd("HSET")
                .arg(self.identity_key(&identity.issuer, &identity.subject))
                .arg("issuer")
                .arg(&identity.issuer)
                .arg("subject")
                .arg(&identity.subject)
                .arg("user_id")
                .arg(identity.user_id.to_string());
            pipeline
                .cmd("SADD")
                .arg(self.identities_index())
                .arg(self.identity_key(&identity.issuer, &identity.subject));
        }
        for membership in &fixture.memberships {
            pipeline
                .cmd("HSET")
                .arg(self.membership_key(membership.tenant_id, membership.user_id))
                .arg("tenant_id")
                .arg(membership.tenant_id.to_string())
                .arg("user_id")
                .arg(membership.user_id.to_string())
                .arg("role")
                .arg(membership.role.as_str())
                .arg("active")
                .arg(bool_string(membership.active));
            pipeline
                .cmd("SADD")
                .arg(self.memberships_index(membership.tenant_id))
                .arg(membership.user_id.to_string());
            pipeline
                .cmd("SADD")
                .arg(self.user_tenants_index(membership.user_id))
                .arg(membership.tenant_id.to_string());
        }
        for device in &fixture.devices {
            pipeline
                .cmd("HSET")
                .arg(self.device_key(device.tenant_id, device.device_id))
                .arg("tenant_id")
                .arg(device.tenant_id.to_string())
                .arg("device_id")
                .arg(device.device_id.to_string())
                .arg("owner_user_id")
                .arg(device.owner_user_id.to_string())
                .arg("display_name")
                .arg(&device.display_name)
                .arg("active")
                .arg(bool_string(device.active))
                .arg("last_seen_at_us")
                .arg(
                    device
                        .last_seen_at
                        .map(datetime_micros)
                        .transpose()?
                        .map_or_else(String::new, |value| value.to_string()),
                );
            pipeline
                .cmd("HSETNX")
                .arg(self.device_key(device.tenant_id, device.device_id))
                .arg("device_version")
                .arg("1");
            pipeline
                .cmd("SETNX")
                .arg(self.owner_epoch_key(device.tenant_id, device.device_id))
                .arg("0")
                .ignore();
            pipeline
                .cmd("SADD")
                .arg(self.devices_index(device.tenant_id))
                .arg(device.device_id.to_string());
        }
        for service in &fixture.services {
            pipeline
                .cmd("HSET")
                .arg(self.service_key(service.tenant_id, service.device_id, service.service_id))
                .arg("tenant_id")
                .arg(service.tenant_id.to_string())
                .arg("device_id")
                .arg(service.device_id.to_string())
                .arg("service_id")
                .arg(service.service_id.to_string())
                .arg("service_type")
                .arg(&service.service_type)
                .arg("display_name")
                .arg(&service.display_name)
                .arg("capabilities")
                .arg(serde_json::to_string(&service.capabilities)?)
                .arg("version")
                .arg(service.version.to_string())
                .arg("active")
                .arg(bool_string(service.active));
            pipeline
                .cmd("SADD")
                .arg(self.services_index(service.tenant_id, service.device_id))
                .arg(service.service_id.to_string());
        }
        pipeline
            .cmd("EVAL")
            .arg(format!(
                "{LUA_DECIMAL_HELPERS}{SCRIPT_INCREMENT_CATALOG_GENERATION}"
            ))
            .arg(1_i64)
            .arg(self.catalog_generation_key())
            .ignore();
        self.execute_seed_pipeline(pipeline).await?;
        for credential in &fixture.credentials {
            self.seed_credential(credential).await?;
        }
        for grant in &fixture.grants {
            self.upsert_grant(grant).await?;
        }
        Ok(())
    }

    async fn execute_seed_pipeline(&self, pipeline: redis::Pipeline) -> Result<(), CatalogError> {
        self.connection.query_pipeline::<()>(&pipeline).await
    }

    fn tenant_key(&self, tenant: Uuid) -> String {
        format!("{}tenant:{tenant}", self.prefix)
    }

    fn user_key(&self, user: Uuid) -> String {
        format!("{}user:{user}", self.prefix)
    }

    fn identity_key(&self, issuer: &str, subject: &str) -> String {
        format!(
            "{}identity:{}:{}",
            self.prefix,
            key_component(issuer),
            key_component(subject)
        )
    }

    fn membership_key(&self, tenant: Uuid, user: Uuid) -> String {
        format!("{}membership:{tenant}:{user}", self.prefix)
    }

    fn device_key(&self, tenant: Uuid, device: Uuid) -> String {
        format!("{}device:{tenant}:{device}", self.prefix)
    }

    /// Ephemeral owner leases are incarnation-scoped and carry a Redis TTL.
    /// The key is deliberately separate from the durable device hash.
    fn owner_key(&self, incarnation: &str, tenant: Uuid, device: Uuid) -> String {
        format!(
            "{}coord:owner:{}:{}:{}",
            self.prefix,
            key_component(incarnation),
            tenant,
            device
        )
    }

    /// Epoch counters are durable coordination fences.  They have no TTL and
    /// are intentionally independent of deployment incarnation.
    fn owner_epoch_key(&self, tenant: Uuid, device: Uuid) -> String {
        format!("{}coord:epoch:{tenant}:{device}", self.prefix)
    }

    fn attachment_ticket_key(
        &self,
        incarnation: &str,
        tenant: Uuid,
        device: Uuid,
        digest: &str,
    ) -> String {
        format!(
            "{}coord:ticket:{}:{}:{}:{}",
            self.prefix,
            key_component(incarnation),
            tenant,
            device,
            digest
        )
    }

    fn attachment_ticket_index_key(&self, incarnation: &str, tenant: Uuid, device: Uuid) -> String {
        format!(
            "{}coord:tickets:{}:{}:{}",
            self.prefix,
            key_component(incarnation),
            tenant,
            device
        )
    }

    fn credential_key(&self, tenant: Uuid, device: Uuid, credential: Uuid) -> String {
        format!("{}credential:{tenant}:{device}:{credential}", self.prefix)
    }

    fn service_key(&self, tenant: Uuid, device: Uuid, service: Uuid) -> String {
        format!("{}service:{tenant}:{device}:{service}", self.prefix)
    }

    fn grant_key(&self, tenant: Uuid, principal: Uuid, device: Uuid, service: Uuid) -> String {
        format!(
            "{}grant:{tenant}:{principal}:{device}:{service}",
            self.prefix
        )
    }

    fn tenants_index(&self) -> String {
        format!("{}idx:tenants", self.prefix)
    }

    fn users_index(&self) -> String {
        format!("{}idx:users", self.prefix)
    }

    fn identities_index(&self) -> String {
        format!("{}idx:identities", self.prefix)
    }

    fn memberships_index(&self, tenant: Uuid) -> String {
        format!("{}idx:memberships:{tenant}", self.prefix)
    }

    fn user_tenants_index(&self, user: Uuid) -> String {
        format!("{}idx:user_tenants:{user}", self.prefix)
    }

    fn devices_index(&self, tenant: Uuid) -> String {
        format!("{}idx:devices:{tenant}", self.prefix)
    }

    fn credentials_index(&self, tenant: Uuid, device: Uuid) -> String {
        format!("{}idx:credentials:{tenant}:{device}", self.prefix)
    }

    fn services_index(&self, tenant: Uuid, device: Uuid) -> String {
        format!("{}idx:services:{tenant}:{device}", self.prefix)
    }

    fn grants_device_index(&self, tenant: Uuid, device: Uuid) -> String {
        format!("{}idx:grants_device:{tenant}:{device}", self.prefix)
    }

    fn active_incarnation_key(&self) -> String {
        format!("{}meta:active_incarnation", self.prefix)
    }

    fn redis_run_id_key(&self) -> String {
        format!("{}meta:redis_run_id", self.prefix)
    }

    /// The single relay's continuity token (M6-C65): a random value the
    /// serving relay rewrites periodically and remembers, so that after a
    /// Redis restart it can tell whether Redis still holds its last
    /// acknowledged write.
    fn continuity_key(&self) -> String {
        format!("{}meta:continuity", self.prefix)
    }

    /// Durable catalog mutation generation used only as a live concurrency
    /// fence while recovery observes the namespace.  It is deliberately not
    /// an external checkpoint or rollback authority.
    fn catalog_generation_key(&self) -> String {
        format!("{}meta:catalog_generation", self.prefix)
    }

    fn fixture_seed_guard_key(&self) -> String {
        format!("{}meta:fixture_seeded", self.prefix)
    }

    fn signed_membership_key(&self) -> String {
        format!("{}membership:operator:current", self.prefix)
    }

    fn signed_membership_directory_key(&self) -> String {
        format!("{}membership:operator:directory", self.prefix)
    }

    fn fingerprint_index(&self, fingerprint: &str) -> String {
        format!("{}idx:fingerprint:{fingerprint}", self.prefix)
    }

    async fn seed_credential(&self, credential: &CredentialRecord) -> Result<(), CatalogError> {
        let not_before = datetime_micros(credential.not_before)?;
        let expires = datetime_micros(credential.expires_at)?;
        let revoked = credential
            .revoked_at
            .map(datetime_micros)
            .transpose()?
            .map_or_else(String::new, |value| value.to_string());
        let reply: Vec<String> = self
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{SCRIPT_SEED_CREDENTIAL}"),
                &[
                    self.credential_key(
                        credential.tenant_id,
                        credential.device_id,
                        credential.credential_id,
                    ),
                    self.fingerprint_index(&credential.spki_fingerprint),
                    self.credentials_index(credential.tenant_id, credential.device_id),
                    self.catalog_generation_key(),
                ],
                &[
                    credential.tenant_id.to_string(),
                    credential.device_id.to_string(),
                    credential.credential_id.to_string(),
                    credential.spki_fingerprint.clone(),
                    credential.serial.clone().unwrap_or_default(),
                    not_before.to_string(),
                    expires.to_string(),
                    revoked,
                    bool_string(credential.active).into(),
                    self.prefix.clone(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(()),
            Some("conflict") => Err(CatalogError::Conflict("duplicate SPKI fingerprint")),
            _ => Err(CatalogError::Serialization(
                "invalid Redis credential reply".into(),
            )),
        }
    }
}

#[async_trait]
impl Catalog for RedisCatalog {
    async fn resolve_device(
        &self,
        spki_fingerprint: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<DeviceIdentity>, CatalogError> {
        if !valid_fingerprint(spki_fingerprint) {
            return Ok(None);
        }
        let at = datetime_micros(at)?;
        let reply: Vec<String> = self
            .eval_maintenance(
                SCRIPT_RESOLVE_DEVICE,
                &[self.fingerprint_index(spki_fingerprint)],
                &[
                    spki_fingerprint.to_owned(),
                    at.to_string(),
                    self.prefix.clone(),
                    MAX_AUTHORITY_CLOCK_SKEW_US.to_string(),
                    MAX_AUTHORITY_CALLER_LAG_US.to_string(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Ok(None),
            Some("clock_skew") => Err(CatalogError::Conflict("authority clock skew")),
            Some("not_yet_valid") => Err(CatalogError::Conflict(crate::RESOLVE_NOT_YET_VALID)),
            Some("ok") => parse_device_reply(&reply),
            _ => Err(CatalogError::Serialization(
                "invalid Redis device reply".into(),
            )),
        }
    }

    async fn resolve_consumer(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: Option<Uuid>,
    ) -> Result<Option<AuthenticatedConsumer>, CatalogError> {
        if !valid_principal_identity(issuer, subject) {
            return Ok(None);
        }
        let reply: Vec<String> = self
            .eval(
                SCRIPT_RESOLVE_CONSUMER,
                &[self.identity_key(issuer, subject)],
                &[
                    self.prefix.clone(),
                    tenant_id.map_or_else(String::new, |tenant| tenant.to_string()),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Ok(None),
            Some("conflict") => Err(CatalogError::Conflict(
                "consumer requires an explicit tenant selection",
            )),
            Some("ok") if reply.len() == 3 => Ok(Some(AuthenticatedConsumer {
                tenant_id: parse_uuid(&reply[1])?,
                principal_id: parse_uuid(&reply[2])?,
            })),
            _ => Err(CatalogError::Serialization(
                "invalid Redis consumer reply".into(),
            )),
        }
    }

    async fn authorize(
        &self,
        principal: &AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        read_started_at: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> Result<Option<GrantSnapshot>, CatalogError> {
        if read_started_at > at {
            return Err(CatalogError::InvalidInput("authorization read start"));
        }
        let read_started_us = datetime_micros(read_started_at)?;
        let at_us = datetime_micros(at)?;
        let lane = self.authorization_next.fetch_add(1, Ordering::Relaxed)
            % self.authorization_connections.len();
        let reply: Vec<String> = self
            .eval_on(
                &self.authorization_connections[lane],
                SCRIPT_AUTHORIZE,
                &[
                    self.grant_key(
                        principal.tenant_id,
                        principal.principal_id,
                        device_id,
                        service_id,
                    ),
                    self.membership_key(principal.tenant_id, principal.principal_id),
                    self.tenant_key(principal.tenant_id),
                    self.device_key(principal.tenant_id, device_id),
                    self.service_key(principal.tenant_id, device_id, service_id),
                ],
                &[
                    at_us.to_string(),
                    read_started_us.to_string(),
                    MAX_AUTHORITY_CLOCK_SKEW_US.to_string(),
                    MAX_AUTHORITY_CALLER_LAG_US.to_string(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Ok(None),
            Some("clock_skew") => Err(CatalogError::Conflict("authority clock skew")),
            Some("ok") if reply.len() == 5 => Ok(Some(GrantSnapshot {
                tenant_id: principal.tenant_id,
                principal_id: principal.principal_id,
                device_id,
                service_id,
                revision: parse_u64_decimal(&reply[1])?,
                permissions: serde_json::from_str(&reply[2])?,
                constraints: serde_json::from_str(&reply[3])?,
                valid_until: parse_datetime_micros(&reply[4])?,
                read_started_at,
            })),
            _ => Err(CatalogError::Serialization(
                "invalid Redis authorization reply".into(),
            )),
        }
    }

    async fn list_devices_filtered(
        &self,
        principal: &AuthenticatedConsumer,
        filter: &DeviceListFilter,
        at: DateTime<Utc>,
    ) -> Result<Vec<DeviceSummary>, CatalogError> {
        let at_us = datetime_micros(at)?;
        let reply: Vec<String> = self
            .eval(
                SCRIPT_LIST_DEVICES,
                &[
                    self.tenant_key(principal.tenant_id),
                    self.membership_key(principal.tenant_id, principal.principal_id),
                ],
                &[
                    self.prefix.clone(),
                    principal.tenant_id.to_string(),
                    principal.principal_id.to_string(),
                    filter
                        .service_id
                        .map_or_else(String::new, |id| id.to_string()),
                    filter
                        .owner_user_id
                        .map_or_else(String::new, |id| id.to_string()),
                    bool_string(filter.include_inactive).into(),
                    at_us.to_string(),
                    self.max_list_items.to_string(),
                    (self.max_list_items.saturating_mul(32)).to_string(),
                    MAX_AUTHORITY_CLOCK_SKEW_US.to_string(),
                    MAX_AUTHORITY_CALLER_LAG_US.to_string(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Ok(Vec::new()),
            Some("clock_skew") => Err(CatalogError::Conflict("authority clock skew")),
            Some("bound") => Err(CatalogError::Conflict("Redis catalog list bound")),
            Some("ok") => parse_device_summaries(&reply),
            _ => Err(CatalogError::Serialization(
                "invalid Redis device list reply".into(),
            )),
        }
    }

    async fn upsert_grant(&self, spec: &GrantSpec) -> Result<GrantSnapshot, CatalogError> {
        let now = Utc::now();
        let at_us = datetime_micros(now)?;
        let permissions = serde_json::to_string(&spec.permissions)?;
        let constraints = serde_json::to_string(&spec.constraints)?;
        let expires = spec
            .expires_at
            .map(datetime_micros)
            .transpose()?
            .map_or_else(String::new, |value| value.to_string());
        let reply: Vec<String> = self
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{SCRIPT_UPSERT_GRANT_BODY}"),
                &[
                    self.grant_key(
                        spec.tenant_id,
                        spec.principal_id,
                        spec.device_id,
                        spec.service_id,
                    ),
                    self.membership_key(spec.tenant_id, spec.principal_id),
                    self.tenant_key(spec.tenant_id),
                    self.device_key(spec.tenant_id, spec.device_id),
                    self.service_key(spec.tenant_id, spec.device_id, spec.service_id),
                    self.grants_device_index(spec.tenant_id, spec.device_id),
                    self.catalog_generation_key(),
                ],
                &[
                    at_us.to_string(),
                    permissions,
                    constraints,
                    expires,
                    bool_string(spec.active).into(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Err(CatalogError::InvalidInput("grant tenant relationship")),
            Some("expired") => Err(CatalogError::InvalidInput("grant expiry")),
            Some("overflow") => Err(CatalogError::RevisionOverflow),
            Some("ok") if reply.len() == 2 => {
                let valid_until = spec
                    .expires_at
                    .map_or(now + ChronoDuration::seconds(5), |expiry| {
                        (now + ChronoDuration::seconds(5)).min(expiry)
                    });
                Ok(GrantSnapshot {
                    tenant_id: spec.tenant_id,
                    principal_id: spec.principal_id,
                    device_id: spec.device_id,
                    service_id: spec.service_id,
                    revision: parse_u64_decimal(&reply[1])?,
                    permissions: spec.permissions.clone(),
                    constraints: spec.constraints.clone(),
                    valid_until,
                    read_started_at: now,
                })
            }
            _ => Err(CatalogError::Serialization(
                "invalid Redis grant reply".into(),
            )),
        }
    }

    async fn revoke_grant(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        device_id: Uuid,
        service_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        let at_us = datetime_micros(at)?;
        let reply: Vec<String> = self
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{SCRIPT_REVOKE_GRANT_BODY}"),
                &[
                    self.grant_key(tenant_id, principal_id, device_id, service_id),
                    self.catalog_generation_key(),
                ],
                &[at_us.to_string()],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Err(CatalogError::NotFound),
            Some("overflow") => Err(CatalogError::RevisionOverflow),
            Some("ok") if reply.len() == 2 => parse_u64_decimal(&reply[1]),
            _ => Err(CatalogError::Serialization(
                "invalid Redis grant revoke reply".into(),
            )),
        }
    }

    async fn revoke_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        let at_us = datetime_micros(at)?;
        let reply: Vec<String> = self
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{SCRIPT_REVOKE_DEVICE_BODY}"),
                &[
                    self.device_key(tenant_id, device_id),
                    self.credentials_index(tenant_id, device_id),
                    self.grants_device_index(tenant_id, device_id),
                    self.owner_key(self.configured_incarnation()?, tenant_id, device_id),
                    self.owner_epoch_key(tenant_id, device_id),
                    self.catalog_generation_key(),
                ],
                &[
                    self.prefix.clone(),
                    tenant_id.to_string(),
                    device_id.to_string(),
                    at_us.to_string(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Err(CatalogError::NotFound),
            Some("overflow") => Err(CatalogError::RevisionOverflow),
            Some("ok") if reply.len() == 2 => parse_u64_decimal(&reply[1]),
            _ => Err(CatalogError::Serialization(
                "invalid Redis device revoke reply".into(),
            )),
        }
    }

    async fn revoke_credential(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        credential_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        let at_us = datetime_micros(at)?;
        let reply: Vec<String> = self
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{SCRIPT_REVOKE_CREDENTIAL_BODY}"),
                &[
                    self.device_key(tenant_id, device_id),
                    self.credential_key(tenant_id, device_id, credential_id),
                    self.catalog_generation_key(),
                ],
                &[at_us.to_string()],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Err(CatalogError::NotFound),
            Some("overflow") => Err(CatalogError::RevisionOverflow),
            Some("ok") if reply.len() == 2 => parse_u64_decimal(&reply[1]),
            _ => Err(CatalogError::Serialization(
                "invalid Redis credential revoke reply".into(),
            )),
        }
    }

    async fn seed_fixture(&self, fixture: &CatalogFixture) -> Result<(), CatalogError> {
        if !is_fixture_namespace(&self.namespace) {
            return Err(CatalogError::InvalidInput("fixture namespace"));
        }
        validate_fixture(fixture)?;
        match self.reserve_empty_namespace().await? {
            NamespaceReservation::Reserved => {}
            NamespaceReservation::AlreadyReserved => {
                return Err(CatalogError::Conflict("fixture namespace already seeded"));
            }
            NamespaceReservation::Occupied => {
                return Err(CatalogError::Conflict("fixture namespace is not empty"));
            }
            NamespaceReservation::ScanBound => {
                return Err(CatalogError::Conflict("fixture namespace scan bound"));
            }
        }
        self.write_seed_records(fixture).await
    }

    async fn claim_owner(&self, request: &OwnerClaimRequest) -> Result<OwnerClaim, CatalogError> {
        let incarnation = self.configured_incarnation()?;
        if incarnation != request.deployment_incarnation {
            return Err(CatalogError::InvalidOwner);
        }
        validate_identifier(&request.deployment_incarnation, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&request.node_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&request.boot_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&request.session_id, MAX_IDENTIFIER_BYTES)?;
        let now = Utc::now();
        let max_lease = ChronoDuration::seconds(30);
        if request.lease_expires_at <= now || request.lease_expires_at - now > max_lease {
            return Err(CatalogError::InvalidOwner);
        }
        let lease_us = datetime_micros(request.lease_expires_at)?;
        let reply: Vec<String> = self
            .eval_owner_write(
                &format!("{LUA_DECIMAL_HELPERS}{SCRIPT_CLAIM_OWNER_BODY}"),
                &[
                    self.owner_key(incarnation, request.tenant_id, request.device_id),
                    self.owner_epoch_key(request.tenant_id, request.device_id),
                    self.device_key(request.tenant_id, request.device_id),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                    self.catalog_generation_key(),
                ],
                &[
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                    request.node_id.clone(),
                    request.boot_id.clone(),
                    request.session_id.clone(),
                    lease_us.to_string(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Err(CatalogError::NotFound),
            Some("busy") => Err(CatalogError::OwnerBusy),
            Some("incarnation") => Err(CatalogError::Conflict("active deployment incarnation")),
            Some("authority") => Err(CatalogError::Conflict("Redis authority run")),
            Some("missing_epoch") => Err(CatalogError::Conflict("missing owner epoch")),
            Some("overflow") => Err(CatalogError::RevisionOverflow),
            Some("ok") if reply.len() == 3 => Ok(OwnerClaim {
                token: OwnerToken {
                    deployment_incarnation: request.deployment_incarnation.clone(),
                    tenant_id: request.tenant_id,
                    device_id: request.device_id,
                    node_id: request.node_id.clone(),
                    boot_id: request.boot_id.clone(),
                    session_id: request.session_id.clone(),
                    epoch: parse_u64_decimal(&reply[1])?,
                },
                lease_expires_at: parse_datetime_micros(&reply[2])?,
            }),
            _ => Err(CatalogError::Serialization(
                "invalid Redis owner claim reply".into(),
            )),
        }
    }

    async fn renew_owner(
        &self,
        token: &OwnerToken,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<bool, CatalogError> {
        let incarnation = self.configured_incarnation()?;
        if incarnation != token.deployment_incarnation {
            return Ok(false);
        }
        validate_identifier(&token.deployment_incarnation, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&token.node_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&token.boot_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&token.session_id, MAX_IDENTIFIER_BYTES)?;
        let now = Utc::now();
        if lease_expires_at <= now || lease_expires_at - now > ChronoDuration::seconds(30) {
            return Err(CatalogError::InvalidOwner);
        }
        let reply: Vec<String> = self
            .eval_maintenance_owner_write(
                SCRIPT_RENEW_OWNER,
                &[
                    self.owner_key(incarnation, token.tenant_id, token.device_id),
                    self.device_key(token.tenant_id, token.device_id),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                    token.epoch.to_string(),
                    token.node_id.clone(),
                    token.boot_id.clone(),
                    token.session_id.clone(),
                    datetime_micros(lease_expires_at)?.to_string(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(true),
            Some("stale") => Ok(false),
            Some("incarnation") => Ok(false),
            Some("authority") => Ok(false),
            _ => Err(CatalogError::Serialization(
                "invalid Redis owner renew reply".into(),
            )),
        }
    }

    async fn release_owner(&self, token: &OwnerToken) -> Result<bool, CatalogError> {
        let incarnation = self.configured_incarnation()?;
        if incarnation != token.deployment_incarnation {
            return Ok(false);
        }
        validate_identifier(&token.deployment_incarnation, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&token.node_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&token.boot_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&token.session_id, MAX_IDENTIFIER_BYTES)?;
        let reply: Vec<String> = self
            .eval_owner_write(
                SCRIPT_RELEASE_OWNER,
                &[
                    self.owner_key(incarnation, token.tenant_id, token.device_id),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                    token.epoch.to_string(),
                    token.node_id.clone(),
                    token.boot_id.clone(),
                    token.session_id.clone(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(true),
            Some("stale") | Some("incarnation") => Ok(false),
            Some("authority") => Ok(false),
            _ => Err(CatalogError::Serialization(
                "invalid Redis owner release reply".into(),
            )),
        }
    }

    async fn current_owner(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        _at: DateTime<Utc>,
    ) -> Result<Option<OwnerClaim>, CatalogError> {
        let incarnation = self.configured_incarnation()?;
        let reply: Vec<String> = self
            .eval(
                SCRIPT_CURRENT_OWNER,
                &[
                    self.owner_key(incarnation, tenant_id, device_id),
                    self.device_key(tenant_id, device_id),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[incarnation.to_owned(), bound_run_id().to_owned()],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") | Some("incarnation") => Ok(None),
            Some("authority") => Err(CatalogError::Conflict("Redis authority run")),
            Some("ok") if reply.len() == 6 => Ok(Some(OwnerClaim {
                token: OwnerToken {
                    deployment_incarnation: incarnation.to_owned(),
                    tenant_id,
                    device_id,
                    node_id: reply[1].clone(),
                    boot_id: reply[2].clone(),
                    session_id: reply[3].clone(),
                    epoch: parse_u64_decimal(&reply[4])?,
                },
                lease_expires_at: parse_datetime_micros(&reply[5])?,
            })),
            _ => Err(CatalogError::Serialization(
                "invalid Redis current owner reply".into(),
            )),
        }
    }

    async fn issue_attachment_ticket(
        &self,
        request: &AttachmentTicketIssueRequest,
    ) -> Result<AttachmentTicket, CatalogError> {
        let incarnation = self.configured_incarnation()?;
        if incarnation != request.owner.deployment_incarnation {
            return Err(CatalogError::InvalidOwner);
        }
        let now = Utc::now();
        cluster::validate_ticket_issue(request, incarnation, now)?;
        let ticket = cluster::generate_ticket();
        let digest = cluster::ticket_digest(&ticket);
        let expiry_us = datetime_micros(request.expires_at)?;
        let reply: Vec<String> = self
            .eval(
                SCRIPT_ISSUE_ATTACHMENT_TICKET,
                &[
                    self.owner_key(incarnation, request.tenant_id, request.device_id),
                    self.attachment_ticket_key(
                        incarnation,
                        request.tenant_id,
                        request.device_id,
                        &digest,
                    ),
                    self.attachment_ticket_index_key(
                        incarnation,
                        request.tenant_id,
                        request.device_id,
                    ),
                    self.device_key(request.tenant_id, request.device_id),
                    self.fingerprint_index(&request.spki_fingerprint),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                    request.owner.epoch.to_string(),
                    request.owner.node_id.clone(),
                    request.owner.boot_id.clone(),
                    request.owner.session_id.clone(),
                    request.spki_fingerprint.clone(),
                    request.generation.to_string(),
                    request.connection_id.clone(),
                    request.purpose.clone(),
                    request.binding_digest.clone(),
                    request.tenant_id.to_string(),
                    request.device_id.to_string(),
                    expiry_us.to_string(),
                    digest.clone(),
                    MAX_TICKET_INDEX_ITEMS.to_string(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(AttachmentTicket {
                ticket,
                locator: crate::AttachmentTicketLocator {
                    tenant_id: request.tenant_id,
                    device_id: request.device_id,
                    digest,
                },
                expires_at: request.expires_at,
            }),
            Some("busy") => Err(CatalogError::InvalidOwner),
            Some("bound") => Err(CatalogError::Conflict("attachment ticket bound")),
            Some("collision") => Err(CatalogError::Conflict("attachment ticket collision")),
            Some("incarnation") => Err(CatalogError::Conflict("active deployment incarnation")),
            Some("authority") => Err(CatalogError::Conflict("Redis authority run")),
            Some("stale") => Err(CatalogError::StaleOwner),
            _ => Err(CatalogError::Serialization(
                "invalid Redis attachment ticket issue reply".into(),
            )),
        }
    }

    async fn consume_attachment_ticket(
        &self,
        request: &AttachmentTicketConsumeRequest,
    ) -> Result<ConsumedAttachmentTicket, CatalogError> {
        let incarnation = self.configured_incarnation()?;
        if incarnation != request.owner.deployment_incarnation {
            return Err(CatalogError::InvalidOwner);
        }
        let binding = request.binding();
        cluster::validate_ticket_consume(&binding, incarnation, &request.ticket)?;
        let digest = cluster::ticket_digest(&request.ticket);
        let reply: Vec<String> = self
            .eval(
                SCRIPT_CONSUME_ATTACHMENT_TICKET,
                &[
                    self.attachment_ticket_key(
                        incarnation,
                        request.tenant_id,
                        request.device_id,
                        &digest,
                    ),
                    self.attachment_ticket_index_key(
                        incarnation,
                        request.tenant_id,
                        request.device_id,
                    ),
                    self.owner_key(incarnation, request.tenant_id, request.device_id),
                    self.device_key(request.tenant_id, request.device_id),
                    self.fingerprint_index(&request.spki_fingerprint),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[
                    incarnation.to_owned(),
                    bound_run_id().to_owned(),
                    request.owner.epoch.to_string(),
                    request.owner.node_id.clone(),
                    request.owner.boot_id.clone(),
                    request.owner.session_id.clone(),
                    request.spki_fingerprint.clone(),
                    request.generation.to_string(),
                    request.connection_id.clone(),
                    request.purpose.clone(),
                    request.binding_digest.clone(),
                    request.tenant_id.to_string(),
                    request.device_id.to_string(),
                    digest,
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") if reply.len() == 14 => Ok(ConsumedAttachmentTicket {
                binding: crate::AttachmentTicketBinding {
                    tenant_id: parse_uuid(&reply[1])?,
                    device_id: parse_uuid(&reply[2])?,
                    spki_fingerprint: reply[3].clone(),
                    owner: OwnerToken {
                        deployment_incarnation: reply[4].clone(),
                        tenant_id: parse_uuid(&reply[1])?,
                        device_id: parse_uuid(&reply[2])?,
                        node_id: reply[5].clone(),
                        boot_id: reply[6].clone(),
                        session_id: reply[7].clone(),
                        epoch: parse_u64_decimal(&reply[8])?,
                    },
                    generation: parse_u64_decimal(&reply[9])?,
                    connection_id: reply[10].clone(),
                    purpose: reply[11].clone(),
                    binding_digest: reply[12].clone(),
                },
                expires_at: parse_datetime_micros(&reply[13])?,
            }),
            Some("missing") | Some("spent") | Some("expired") | Some("mismatch")
            | Some("stale") | Some("incarnation") | Some("authority") => {
                Err(CatalogError::Unauthorized)
            }
            _ => Err(CatalogError::Serialization(
                "invalid Redis attachment ticket consume reply".into(),
            )),
        }
    }

    async fn read_signed_membership(&self) -> Result<Option<SignedMembershipRecord>, CatalogError> {
        if let Some(record) = self
            .read_signed_membership_directory()
            .await?
            .into_iter()
            .next()
        {
            return Ok(Some(record));
        }
        self.read_legacy_signed_membership().await
    }

    async fn read_signed_memberships(&self) -> Result<Vec<SignedMembershipRecord>, CatalogError> {
        let records = self.read_signed_membership_directory().await?;
        if !records.is_empty() {
            return Ok(records);
        }
        Ok(self
            .read_legacy_signed_membership()
            .await?
            .into_iter()
            .collect())
    }
}

/// The authoritative Redis namespace rule, applied without opening a
/// connection.
///
/// `connect_inner` enforces exactly this before any socket is created, so a
/// configuration validator can refuse an unusable namespace at parse time
/// instead of discovering it after listeners are bound. Every key the catalog
/// writes is prefixed with this value, so the charset stays restricted to
/// characters that cannot introduce a second key separator or a glob
/// metacharacter into a scan pattern.
pub fn validate_redis_namespace(namespace: &str) -> Result<(), CatalogError> {
    if namespace.is_empty() || namespace.len() > MAX_REDIS_NAMESPACE_BYTES {
        return Err(CatalogError::InvalidInput("Redis namespace"));
    }
    if !namespace
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(CatalogError::InvalidInput("Redis namespace"));
    }
    Ok(())
}

/// The redis-rs connection configuration every authority connection uses.
///
/// redis-rs applies its own per-command response deadline inside the
/// multiplexed connection, measured from the moment the command is written
/// until its reply arrives.  It is set to the documented two-second
/// authority bound here (the library default is 500 ms) so that deadline,
/// like the catalog's outer one, bounds the authority's reply and nothing
/// else; a reply slower than that is reported as a timeout distinct from a
/// severed connection.  The connection timeout is set to `connect_budget`
/// (the library default is one second, M6-C73), and callers apply the same
/// budget around the call, so neither deadline undercuts the other.  (A lane
/// reconnect inside a running relay is additionally capped by
/// `AuthorityLane::admit`; see [`REDIS_CONNECT_TIMEOUT`].)  Host names are
/// resolved by [`CatalogResolver`], so a lookup failure is classified `dns`.
pub(crate) fn connection_config(connect_budget: Duration) -> redis::AsyncConnectionConfig {
    redis::AsyncConnectionConfig::new()
        .set_response_timeout(Some(REDIS_OPERATION_TIMEOUT))
        .set_connection_timeout(Some(connect_budget))
        .set_dns_resolver(CatalogResolver)
}

/// The system resolver, with a failed or empty lookup reported as the typed
/// [`crate::error::DnsLookupFailed`] instead of redis-rs's generic
/// "invalid client config" or an untyped I/O error.
struct CatalogResolver;

impl redis::io::AsyncDNSResolver for CatalogResolver {
    fn resolve<'a, 'b: 'a>(
        &'a self,
        host: &'b str,
        port: u16,
    ) -> redis::RedisFuture<'a, Box<dyn Iterator<Item = std::net::SocketAddr> + Send + 'a>> {
        Box::pin(async move {
            let lookup_failed =
                || redis::RedisError::from(std::io::Error::other(crate::error::DnsLookupFailed));
            let addresses: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| lookup_failed())?
                .collect();
            if addresses.is_empty() {
                return Err(lookup_failed());
            }
            Ok(Box::new(addresses.into_iter())
                as Box<dyn Iterator<Item = std::net::SocketAddr> + Send>)
        })
    }
}

/// Open one multiplexed connection within `connect_budget`, applied both
/// inside redis-rs (through `config`) and around it.
async fn connect_within(
    client: &redis::Client,
    config: &redis::AsyncConnectionConfig,
    connect_budget: Duration,
) -> Result<MultiplexedConnection, CatalogConnectionError> {
    tokio::time::timeout(
        connect_budget,
        client.get_multiplexed_async_connection_with_config(config),
    )
    .await
    .map_err(|_| {
        catalog_connection_error(
            CatalogConnectionStage::ConnectionEstablishment,
            redis_timeout(),
        )
    })?
    .map_err(|error| {
        catalog_connection_error(CatalogConnectionStage::ConnectionEstablishment, error)
    })
}

/// Open one lane connection and verify the primary's identity.
async fn open_verified_connection(
    client: &redis::Client,
) -> Result<(MultiplexedConnection, String), CatalogConnectionError> {
    let connection = connect_within(
        client,
        &connection_config(REDIS_CONNECT_TIMEOUT),
        REDIS_CONNECT_TIMEOUT,
    )
    .await?;
    verify_connection_identity(connection).await
}

/// Complete the same bounded PING/INFO exchange used by configured catalog
/// startup.  Keeping this separate gives the in-process transport regression a
/// real redis-rs `MultiplexedConnection` seam, so it can distinguish an
/// injected AsyncWrite error from a peer/read-side close without inferring direction from
/// the remote socket's last observed command.
async fn verify_connection_identity(
    mut connection: MultiplexedConnection,
) -> Result<(MultiplexedConnection, String), CatalogConnectionError> {
    tokio::time::timeout(
        REDIS_OPERATION_TIMEOUT,
        redis::cmd("PING").query_async::<String>(&mut connection),
    )
    .await
    .map_err(|_| catalog_connection_error(CatalogConnectionStage::Ping, redis_timeout()))?
    .map_err(|error| catalog_connection_error(CatalogConnectionStage::Ping, error))?;
    let info: String = tokio::time::timeout(
        REDIS_OPERATION_TIMEOUT,
        redis::cmd("INFO")
            .arg("server")
            .query_async(&mut connection),
    )
    .await
    .map_err(|_| {
        catalog_connection_error(CatalogConnectionStage::PrimaryIdentity, redis_timeout())
    })?
    .map_err(|error| catalog_connection_error(CatalogConnectionStage::PrimaryIdentity, error))?;
    let redis_run_id = parse_redis_run_id(&info).map_err(|error| {
        catalog_connection_error(CatalogConnectionStage::PrimaryIdentity, error)
            .with_failure(CatalogConnectionFailure::InvalidReply)
    })?;
    Ok((connection, redis_run_id))
}

fn is_fixture_namespace(namespace: &str) -> bool {
    namespace.starts_with("test-")
        || namespace.starts_with("fixture-")
        || namespace.contains("-fixture-")
}

fn eval_command(script: &str, keys: &[String], args: &[String]) -> redis::Cmd {
    let mut command = redis::cmd("EVAL");
    command.arg(script).arg(keys.len() as i64);
    for key in keys {
        command.arg(key);
    }
    for arg in args {
        command.arg(arg);
    }
    command
}

fn redis_timeout() -> redis::RedisError {
    redis::RedisError::from(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "Redis catalog operation timed out",
    ))
}

fn catalog_connection_error(
    stage: CatalogConnectionStage,
    error: impl Into<CatalogError>,
) -> CatalogConnectionError {
    CatalogConnectionError::new(stage, error.into())
}

fn parse_redis_run_id(info: &str) -> Result<String, CatalogError> {
    let run_id = info
        .lines()
        .find_map(|line| line.strip_prefix("run_id:"))
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(CatalogError::InvalidInput("Redis server run id"))?;
    Ok(run_id.to_owned())
}

fn validate_identifier(value: &str, max_bytes: usize) -> Result<(), CatalogError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(CatalogError::InvalidOwner);
    }
    Ok(())
}

fn key_component(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for byte in value.bytes() {
        // `_` introduces an encoded byte. Encoding it too prevents a literal
        // sequence such as `a_3a` from colliding with the encoded `a:`.
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-') {
            result.push(byte as char);
        } else {
            result.push('_');
            result.push_str(&format!("{byte:02x}"));
        }
    }
    result
}

fn bool_string(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

fn datetime_micros(value: DateTime<Utc>) -> Result<i64, CatalogError> {
    let micros = value.timestamp_micros();
    if !(-MAX_SAFE_REDIS_TIME..=MAX_SAFE_REDIS_TIME).contains(&micros) {
        return Err(CatalogError::InvalidInput("Redis timestamp range"));
    }
    Ok(micros)
}

fn parse_datetime_micros(value: &str) -> Result<DateTime<Utc>, CatalogError> {
    let micros = value
        .parse::<i64>()
        .map_err(|_| CatalogError::Serialization("invalid Redis timestamp".into()))?;
    DateTime::from_timestamp_micros(micros)
        .ok_or_else(|| CatalogError::Serialization("invalid Redis timestamp".into()))
}

fn parse_uuid(value: &str) -> Result<Uuid, CatalogError> {
    Uuid::parse_str(value).map_err(|_| CatalogError::Serialization("invalid Redis UUID".into()))
}

fn parse_u64_decimal(value: &str) -> Result<u64, CatalogError> {
    value
        .parse::<u64>()
        .map_err(|_| CatalogError::Serialization("invalid Redis revision".into()))
}

/// Extract only the bounded index field needed to select a directory slot.
/// This does not validate a signature or any other membership field; that
/// remains the cluster trust layer's responsibility.
fn membership_node_id(bytes: &[u8]) -> Result<String, CatalogError> {
    let envelope: MembershipNodeId = serde_json::from_slice(bytes)?;
    cluster::validate_identifier(&envelope.node_id, 128)?;
    Ok(envelope.node_id)
}

fn optional_datetime(value: &str) -> Result<Option<DateTime<Utc>>, CatalogError> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_datetime_micros(value).map(Some)
    }
}

fn parse_device_reply(reply: &[String]) -> Result<Option<DeviceIdentity>, CatalogError> {
    if reply.len() != 14 {
        return Err(CatalogError::Serialization(
            "invalid Redis device reply".into(),
        ));
    }
    Ok(Some(DeviceIdentity {
        tenant_id: parse_uuid(&reply[1])?,
        device_id: parse_uuid(&reply[2])?,
        owner_user_id: parse_uuid(&reply[3])?,
        credential_id: parse_uuid(&reply[4])?,
        spki_fingerprint: reply[5].clone(),
        credential_not_before: parse_datetime_micros(&reply[6])?,
        expires_at: parse_datetime_micros(&reply[7])?,
        credential_revoked_at: optional_datetime(&reply[8])?,
        device_active: reply[9] == "1",
        credential_active: reply[10] == "1",
        device_version: parse_u64_decimal(&reply[11])?,
        owner_epoch: parse_u64_decimal(&reply[12])?,
        last_seen_at: optional_datetime(&reply[13])?,
    }))
}

fn parse_device_summaries(reply: &[String]) -> Result<Vec<DeviceSummary>, CatalogError> {
    if reply.len() < 2 {
        return Err(CatalogError::Serialization(
            "invalid Redis device list reply".into(),
        ));
    }
    let count = reply[1]
        .parse::<usize>()
        .map_err(|_| CatalogError::Serialization("invalid Redis device list count".into()))?;
    if count > MAX_CLEANUP_KEYS || count > reply.len().saturating_sub(2) / 8 {
        return Err(CatalogError::Serialization(
            "invalid Redis device list count".into(),
        ));
    }
    let mut index = 2;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        if index + 8 > reply.len() {
            return Err(CatalogError::Serialization(
                "truncated Redis device list".into(),
            ));
        }
        let tenant_id = parse_uuid(&reply[index])?;
        let device_id = parse_uuid(&reply[index + 1])?;
        let owner_user_id = parse_uuid(&reply[index + 2])?;
        let display_name = reply[index + 3].clone();
        let active = reply[index + 4] == "1";
        let last_seen_at = optional_datetime(&reply[index + 5])?;
        let grant_revision = parse_u64_decimal(&reply[index + 6])?;
        let service_count = reply[index + 7]
            .parse::<usize>()
            .map_err(|_| CatalogError::Serialization("invalid Redis service count".into()))?;
        index += 8;
        if service_count > MAX_CLEANUP_KEYS || service_count > reply.len().saturating_sub(index) / 6
        {
            return Err(CatalogError::Serialization(
                "invalid Redis service count".into(),
            ));
        }
        let mut services = Vec::with_capacity(service_count);
        for _ in 0..service_count {
            if index + 6 > reply.len() {
                return Err(CatalogError::Serialization(
                    "truncated Redis service list".into(),
                ));
            }
            services.push(ServiceRecord {
                tenant_id,
                device_id,
                service_id: parse_uuid(&reply[index])?,
                service_type: reply[index + 1].clone(),
                display_name: reply[index + 2].clone(),
                capabilities: serde_json::from_str(&reply[index + 3])?,
                version: parse_u64_decimal(&reply[index + 4])?,
                active: reply[index + 5] == "1",
            });
            index += 6;
        }
        result.push(DeviceSummary {
            tenant_id,
            device_id,
            owner_user_id,
            display_name,
            active,
            last_seen_at,
            services,
            grant_revision,
        });
    }
    if index != reply.len() {
        return Err(CatalogError::Serialization(
            "extra Redis device list fields".into(),
        ));
    }
    Ok(result)
}

pub(crate) fn validate_fixture(fixture: &CatalogFixture) -> Result<(), CatalogError> {
    let total = fixture.tenants.len()
        + fixture.users.len()
        + fixture.identities.len()
        + fixture.memberships.len()
        + fixture.devices.len()
        + fixture.credentials.len()
        + fixture.services.len()
        + fixture.grants.len();
    if total > MAX_FIXTURE_RECORDS {
        return Err(CatalogError::InvalidInput("fixture size"));
    }
    let tenants: HashSet<_> = fixture
        .tenants
        .iter()
        .map(|record| record.tenant_id)
        .collect();
    let users: HashSet<_> = fixture.users.iter().map(|record| record.user_id).collect();
    if tenants.len() != fixture.tenants.len() || users.len() != fixture.users.len() {
        return Err(CatalogError::Conflict("duplicate fixture identity"));
    }
    let memberships: HashSet<_> = fixture
        .memberships
        .iter()
        .map(|record| (record.tenant_id, record.user_id))
        .collect();
    if memberships.len() != fixture.memberships.len() {
        return Err(CatalogError::Conflict("duplicate fixture membership"));
    }
    for identity in &fixture.identities {
        if !users.contains(&identity.user_id)
            || !valid_principal_identity(&identity.issuer, &identity.subject)
        {
            return Err(CatalogError::InvalidInput("identity fixture"));
        }
    }
    for membership in &fixture.memberships {
        if !tenants.contains(&membership.tenant_id) || !users.contains(&membership.user_id) {
            return Err(CatalogError::InvalidInput("membership fixture"));
        }
    }
    let devices: HashSet<_> = fixture
        .devices
        .iter()
        .map(|record| (record.tenant_id, record.device_id))
        .collect();
    if devices.len() != fixture.devices.len() {
        return Err(CatalogError::Conflict("duplicate fixture device"));
    }
    for device in &fixture.devices {
        if !tenants.contains(&device.tenant_id)
            || !memberships.contains(&(device.tenant_id, device.owner_user_id))
        {
            return Err(CatalogError::InvalidInput("device fixture"));
        }
    }
    let mut fingerprints = HashSet::new();
    let mut credentials = HashSet::new();
    for credential in &fixture.credentials {
        if !devices.contains(&(credential.tenant_id, credential.device_id))
            || !valid_fingerprint(&credential.spki_fingerprint)
            || credential.expires_at <= credential.not_before
            || !fingerprints.insert(credential.spki_fingerprint.clone())
            || !credentials.insert((
                credential.tenant_id,
                credential.device_id,
                credential.credential_id,
            ))
        {
            return Err(CatalogError::InvalidInput("credential fixture"));
        }
    }
    let mut services = HashSet::new();
    for service in &fixture.services {
        if !devices.contains(&(service.tenant_id, service.device_id))
            || service.service_type.trim().is_empty()
            || !services.insert((service.tenant_id, service.device_id, service.service_id))
        {
            return Err(CatalogError::InvalidInput("service fixture"));
        }
    }
    let mut grants = HashSet::new();
    for grant in &fixture.grants {
        if !memberships.contains(&(grant.tenant_id, grant.principal_id))
            || !devices.contains(&(grant.tenant_id, grant.device_id))
            || !services.contains(&(grant.tenant_id, grant.device_id, grant.service_id))
            || !grants.insert((
                grant.tenant_id,
                grant.principal_id,
                grant.device_id,
                grant.service_id,
            ))
        {
            return Err(CatalogError::InvalidInput("grant fixture"));
        }
    }
    Ok(())
}

const SCRIPT_RESERVE_FIXTURE_NAMESPACE: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then return {'used'} end
local cursor = '0'
local examined = 0
local limit = tonumber(ARGV[2])
repeat
  local result = redis.call('SCAN', cursor, 'MATCH', ARGV[1] .. '*', 'COUNT', 256)
  cursor = result[1]
  for _, key in ipairs(result[2]) do
    examined = examined + 1
    if examined > limit then return {'bound'} end
    if key ~= KEYS[1] and key ~= KEYS[2] and key ~= KEYS[3] and key ~= KEYS[4] then
      return {'occupied'}
    end
  end
until cursor == '0'
redis.call('SET', KEYS[1], '1')
return {'ok'}
"#;

const SCRIPT_ENSURE_INCARNATION: &str = r#"
local current = redis.call('GET', KEYS[1])
local current_run = redis.call('GET', KEYS[3])
if not current or not current_run then return {'unbound'} end
if current ~= ARGV[1] then return {'mismatch'} end
if current_run ~= ARGV[2] then return {'run'} end
return {'ok'}
"#;

/// First activation only: refuse an existing incarnation or run binding, then
/// refuse any other key under the prefix, and only then bind both.
const SCRIPT_ACTIVATE_FIRST_INCARNATION: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 or redis.call('EXISTS', KEYS[2]) == 1 then
  return {'active'}
end
local cursor = '0'
local examined = 0
local limit = tonumber(ARGV[4])
repeat
  local result = redis.call('SCAN', cursor, 'MATCH', ARGV[1] .. '*', 'COUNT', 256)
  cursor = result[1]
  for _, key in ipairs(result[2]) do
    examined = examined + 1
    if examined > limit then return {'bound'} end
    return {'occupied'}
  end
until cursor == '0'
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[3])
return {'ok'}
"#;

const SCRIPT_ACTIVATE_INCARNATION: &str = r#"
local current = redis.call('GET', KEYS[1])
local current_run = redis.call('GET', KEYS[3])
if current and current == ARGV[2] and current_run == ARGV[3] then return {'ok'} end
if current and current == ARGV[2] and current_run ~= ARGV[3] then return {'mismatch'} end
-- Owner leases are ephemeral keys.  Do not consult durable device hashes:
-- doing so would make old M1 owner fields a second authority.
local cursor = '0'
local examined = 0
repeat
  local result = redis.call('SCAN', cursor, 'MATCH', ARGV[1] .. 'coord:owner:*', 'COUNT', 256)
  cursor = result[1]
  for _, key in ipairs(result[2]) do
    examined = examined + 1
    if examined > 100000 then return {'bound'} end
    if redis.call('EXISTS', key) == 1 then return {'busy'} end
  end
until cursor == '0'
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[3], ARGV[3])
return {'ok'}
"#;

/// Operator re-attestation after a Redis restart (M6-C65).  KEYS[1] active
/// incarnation, [2] run binding; ARGV[1] configured incarnation, [2] the run
/// the connection verified.  Writes only the run binding.
const SCRIPT_OPERATOR_REBIND_RUN: &str = r#"
local incarnation = redis.call('GET', KEYS[1])
local run = redis.call('GET', KEYS[2])
if not incarnation or not run then return {'unbound'} end
if incarnation ~= ARGV[1] then return {'incarnation'} end
if run == ARGV[2] then return {'current', run} end
redis.call('SET', KEYS[2], ARGV[2])
return {'rebound', run, ARGV[2]}
"#;

/// A single relay's continuity token (M6-C65).  KEYS[1] active incarnation,
/// [2] run binding, [3] continuity token; ARGV[1] configured incarnation,
/// [2] the run the connection verified, [3] the new token.
const SCRIPT_ADVANCE_CONTINUITY: &str = r#"
local incarnation = redis.call('GET', KEYS[1])
local run = redis.call('GET', KEYS[2])
if not incarnation or not run then return {'unbound'} end
if incarnation ~= ARGV[1] then return {'incarnation'} end
if run ~= ARGV[2] then return {'run'} end
redis.call('SET', KEYS[3], ARGV[3])
return {'ok'}
"#;

const SCRIPT_RESOLVE_DEVICE: &str = r#"
local credential_key = redis.call('GET', KEYS[1])
if not credential_key then return {'none'} end
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
local credential_id = h(credential_key, 'credential_id')
local device_id = h(credential_key, 'device_id')
local tenant_id = h(credential_key, 'tenant_id')
if credential_id == '' or device_id == '' or tenant_id == '' then return {'none'} end
local device_key = ARGV[3] .. 'device:' .. tenant_id .. ':' .. device_id
local caller_at = tonumber(ARGV[2])
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
if not caller_at or caller_at - now > tonumber(ARGV[4])
   or now - caller_at > tonumber(ARGV[5]) then return {'clock_skew'} end
local at = math.max(caller_at, now)
local translation = math.max(0, now - caller_at)
local active = h(credential_key, 'active')
local device_active = h(device_key, 'active')
local not_before = tonumber(h(credential_key, 'not_before_us'))
local expires = tonumber(h(credential_key, 'expires_at_us'))
if active ~= '1' or device_active ~= '1' or h(credential_key, 'revoked_at_us') ~= '' then return {'none'} end
if not not_before or not expires or expires <= at then return {'none'} end
-- M6-C32 review: a credential that is not valid *yet* is not an unknown or
-- refused identity.  A relay clock a few seconds behind the issuer's reaches
-- it, and it heals by itself, so it must not share 'none' with a revoked,
-- expired or unknown credential, which a device is told never to retry.
if not_before > at then return {'not_yet_valid'} end
return {
  'ok', tenant_id, device_id, h(device_key, 'owner_user_id'), credential_id,
  h(credential_key, 'spki_fingerprint'), string.format('%.0f', not_before - translation),
  string.format('%.0f', expires - translation), h(credential_key, 'revoked_at_us'),
  device_active, active, h(device_key, 'device_version'),
  redis.call('GET', ARGV[3] .. 'coord:epoch:' .. tenant_id .. ':' .. device_id) or h(device_key, 'owner_epoch'),
  h(device_key, 'last_seen_at_us')
}
"#;

const SCRIPT_RESOLVE_CONSUMER: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
local user = h(KEYS[1], 'user_id')
if user == '' then return {'none'} end
local requested = ARGV[2]
local function valid(tenant)
  local membership = ARGV[1] .. 'membership:' .. tenant .. ':' .. user
  local tenant_key = ARGV[1] .. 'tenant:' .. tenant
  if h(membership, 'active') == '1' and h(tenant_key, 'active') == '1' then return true end
  return false
end
if requested ~= '' then
  if valid(requested) then return {'ok', requested, user} end
  return {'none'}
end
local matches = {}
for _, tenant in ipairs(redis.call('SMEMBERS', ARGV[1] .. 'idx:user_tenants:' .. user)) do
  if valid(tenant) then table.insert(matches, tenant) end
end
if #matches == 0 then return {'none'} end
if #matches > 1 then return {'conflict'} end
return {'ok', matches[1], user}
"#;

const SCRIPT_AUTHORIZE: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if h(KEYS[2], 'active') ~= '1' or h(KEYS[3], 'active') ~= '1'
   or h(KEYS[4], 'active') ~= '1' or h(KEYS[5], 'active') ~= '1'
   or h(KEYS[1], 'active') ~= '1' then return {'none'} end
local at = tonumber(ARGV[1])
local start = tonumber(ARGV[2])
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
if not at or at - now > tonumber(ARGV[3])
   or now - at > tonumber(ARGV[4]) then return {'clock_skew'} end
local effective_at = math.max(at, now)
local expiry_string = h(KEYS[1], 'expires_at_us')
local expiry
if expiry_string ~= '' then
  expiry = tonumber(expiry_string)
  if not expiry or expiry <= effective_at then return {'none'} end
end
local valid = start + 5000000
if expiry then
  -- Convert an authority-clock expiry to the caller's wall-clock frame. A
  -- Redis clock ahead of the caller must never extend the returned deadline.
  local translation = math.max(0, now - at)
  valid = math.min(valid, expiry - translation)
end
if valid <= at then return {'none'} end
return {'ok', h(KEYS[1], 'revision'), h(KEYS[1], 'permissions'), h(KEYS[1], 'constraints'), string.format('%.0f', valid)}
"#;

const SCRIPT_LIST_DEVICES: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if h(KEYS[1], 'active') ~= '1' or h(KEYS[2], 'active') ~= '1' then return {'none'} end
local prefix = ARGV[1]
local tenant = ARGV[2]
local principal = ARGV[3]
local requested_service = ARGV[4]
local requested_owner = ARGV[5]
local include_inactive = ARGV[6] == '1'
local caller_at = tonumber(ARGV[7])
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
if not caller_at or caller_at - now > tonumber(ARGV[10])
   or now - caller_at > tonumber(ARGV[11]) then return {'clock_skew'} end
local at = math.max(caller_at, now)
local max_devices = tonumber(ARGV[8])
local max_services = tonumber(ARGV[9])
local output = {'ok', '0'}
local device_count = 0
local service_total = 0
for _, device_id in ipairs(redis.call('SMEMBERS', prefix .. 'idx:devices:' .. tenant)) do
  local device_key = prefix .. 'device:' .. tenant .. ':' .. device_id
  local device_active = h(device_key, 'active')
  local owner = h(device_key, 'owner_user_id')
  if (include_inactive or device_active == '1') and (requested_owner == '' or requested_owner == owner) then
    local services = {}
    local max_revision = '0'
    for _, service_id in ipairs(redis.call('SMEMBERS', prefix .. 'idx:services:' .. tenant .. ':' .. device_id)) do
      if requested_service == '' or requested_service == service_id then
        local service_key = prefix .. 'service:' .. tenant .. ':' .. device_id .. ':' .. service_id
        local grant_key = prefix .. 'grant:' .. tenant .. ':' .. principal .. ':' .. device_id .. ':' .. service_id
        local grant_active = h(grant_key, 'active')
        local expiry = h(grant_key, 'expires_at_us')
        local grant_live = grant_active == '1' and (expiry == '' or (tonumber(expiry) and tonumber(expiry) > at))
        if grant_live and (include_inactive or h(service_key, 'active') == '1') then
          service_total = service_total + 1
          if service_total > max_services then return {'bound'} end
          local revision = h(grant_key, 'revision')
          if #revision > #max_revision or (#revision == #max_revision and revision > max_revision) then max_revision = revision end
          table.insert(services, {service_id, h(service_key, 'service_type'), h(service_key, 'display_name'), h(service_key, 'capabilities'), h(service_key, 'version'), h(service_key, 'active')})
        end
      end
    end
    if #services > 0 then
      device_count = device_count + 1
      if device_count > max_devices then return {'bound'} end
      output[#output + 1] = tenant
      output[#output + 1] = device_id
      output[#output + 1] = owner
      output[#output + 1] = h(device_key, 'display_name')
      output[#output + 1] = device_active
      output[#output + 1] = h(device_key, 'last_seen_at_us')
      output[#output + 1] = max_revision
      output[#output + 1] = tostring(#services)
      for _, service in ipairs(services) do
        for _, value in ipairs(service) do output[#output + 1] = value end
      end
    end
  end
end
output[2] = tostring(device_count)
return output
"#;

const LUA_DECIMAL_HELPERS: &str = r#"
local MAX_U64 = '18446744073709551615'
local function normalize_decimal(value)
  if not value or value == '' then return '0' end
  if string.find(value, '[^0-9]') then return nil end
  value = string.gsub(value, '^0+', '')
  if value == '' then return '0' end
  return value
end
local function decimal_compare(a, b)
  a = normalize_decimal(a)
  b = normalize_decimal(b)
  if not a or not b then return nil end
  if #a < #b then return -1 end
  if #a > #b then return 1 end
  if a < b then return -1 end
  if a > b then return 1 end
  return 0
end
local function decimal_increment(value)
  value = normalize_decimal(value)
  if not value or decimal_compare(value, MAX_U64) >= 0 then return nil end
  local chars = {}
  local carry = 1
  for index = #value, 1, -1 do
    local digit = string.byte(value, index) - 48 + carry
    if digit >= 10 then digit = digit - 10; carry = 1 else carry = 0 end
    chars[index] = string.char(48 + digit)
  end
  if carry == 1 then table.insert(chars, 1, '1') end
  return table.concat(chars)
end
"#;

const SCRIPT_INCREMENT_CATALOG_GENERATION: &str = r#"
local next_generation = decimal_increment(redis.call('GET', KEYS[1]))
if not next_generation then return redis.error_reply('catalog generation overflow') end
redis.call('SET', KEYS[1], next_generation)
return next_generation
"#;

const SCRIPT_UPSERT_GRANT_BODY: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
local at = tonumber(ARGV[1])
if h(KEYS[2], 'active') ~= '1' or h(KEYS[3], 'active') ~= '1'
   or h(KEYS[4], 'active') == '' or h(KEYS[5], 'active') ~= '1' then return {'none'} end
if ARGV[4] ~= '' and (not tonumber(ARGV[4]) or tonumber(ARGV[4]) <= at) then return {'expired'} end
local old = h(KEYS[1], 'revision')
local revision = '1'
if old ~= '' then
  revision = decimal_increment(old)
  if not revision then return {'overflow'} end
end
local next_generation = decimal_increment(redis.call('GET', KEYS[7]))
if not next_generation then return {'overflow'} end
redis.call('HSET', KEYS[1], 'tenant_id', h(KEYS[3], 'tenant_id'), 'principal_id', h(KEYS[2], 'user_id'), 'device_id', h(KEYS[4], 'device_id'), 'service_id', h(KEYS[5], 'service_id'), 'revision', revision, 'permissions', ARGV[2], 'constraints', ARGV[3], 'expires_at_us', ARGV[4], 'active', ARGV[5], 'revoked_at_us', '')
redis.call('SADD', KEYS[6], KEYS[1])
redis.call('SET', KEYS[7], next_generation)
return {'ok', revision}
"#;

const SCRIPT_REVOKE_GRANT_BODY: &str = r#"
local revision = redis.call('HGET', KEYS[1], 'revision')
if not revision then return {'none'} end
local next_revision = decimal_increment(revision)
if not next_revision then return {'overflow'} end
local next_generation = decimal_increment(redis.call('GET', KEYS[2]))
if not next_generation then return {'overflow'} end
redis.call('HSET', KEYS[1], 'revision', next_revision, 'active', '0', 'revoked_at_us', ARGV[1])
redis.call('SET', KEYS[2], next_generation)
return {'ok', next_revision}
"#;

const SCRIPT_REVOKE_DEVICE_BODY: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if h(KEYS[1], 'device_id') == '' then return {'none'} end
local device_version = decimal_increment(h(KEYS[1], 'device_version'))
local owner_epoch = decimal_increment(redis.call('GET', KEYS[5]) or h(KEYS[1], 'owner_epoch'))
local next_generation = decimal_increment(redis.call('GET', KEYS[6]))
if not device_version or not owner_epoch or not next_generation then return {'overflow'} end
local grants = redis.call('SMEMBERS', KEYS[3])
local next_revisions = {}
for _, grant_key in ipairs(grants) do
  local next_revision = decimal_increment(h(grant_key, 'revision'))
  if not next_revision then return {'overflow'} end
  next_revisions[grant_key] = next_revision
end
redis.call('HSET', KEYS[1], 'active', '0', 'device_version', device_version)
redis.call('SET', KEYS[5], owner_epoch)
redis.call('SET', KEYS[6], next_generation)
redis.call('DEL', KEYS[4])
for _, credential_id in ipairs(redis.call('SMEMBERS', KEYS[2])) do
  local credential_key = ARGV[1] .. 'credential:' .. ARGV[2] .. ':' .. ARGV[3] .. ':' .. credential_id
  redis.call('HSET', credential_key, 'active', '0', 'revoked_at_us', ARGV[4])
end
for _, grant_key in ipairs(grants) do
  redis.call('HSET', grant_key, 'revision', next_revisions[grant_key], 'active', '0', 'revoked_at_us', ARGV[4])
end
return {'ok', device_version}
"#;

const SCRIPT_REVOKE_CREDENTIAL_BODY: &str = r#"
local active = redis.call('HGET', KEYS[2], 'active')
if active ~= '1' then return {'none'} end
local revision = redis.call('HGET', KEYS[1], 'device_version') or '0'
local next_revision = decimal_increment(revision)
if not next_revision then return {'overflow'} end
local next_generation = decimal_increment(redis.call('GET', KEYS[3]))
if not next_generation then return {'overflow'} end
redis.call('HSET', KEYS[2], 'active', '0', 'revoked_at_us', ARGV[1])
redis.call('HSET', KEYS[1], 'device_version', next_revision)
redis.call('SET', KEYS[3], next_generation)
return {'ok', next_revision}
"#;

const SCRIPT_CLAIM_OWNER_BODY: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[4]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[5]) ~= ARGV[2] then return {'authority'} end
if h(KEYS[3], 'device_id') == '' or h(KEYS[3], 'active') ~= '1' then return {'none'} end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local lease = tonumber(ARGV[6])
if not lease or lease <= now then return {'stale'} end
local expiry = tonumber(h(KEYS[1], 'lease_expires_at_us'))
if expiry and expiry > now then
  if h(KEYS[1], 'deployment_incarnation') == ARGV[1]
     and h(KEYS[1], 'node_id') == ARGV[3]
     and h(KEYS[1], 'boot_id') == ARGV[4]
     and h(KEYS[1], 'session_id') == ARGV[5] then
    local selected = math.max(expiry, lease)
    redis.call('HSET', KEYS[1], 'lease_expires_at_us', string.format('%.0f', selected))
    redis.call('PEXPIREAT', KEYS[1], math.floor(selected / 1000))
    return {'ok', h(KEYS[1], 'owner_epoch'), string.format('%.0f', selected)}
  end
  return {'busy'}
end
local epoch = redis.call('GET', KEYS[2])
if not epoch then epoch = h(KEYS[3], 'owner_epoch') end
if not epoch or epoch == '' then return {'missing_epoch'} end
epoch = decimal_increment(epoch)
local next_generation = decimal_increment(redis.call('GET', KEYS[6]))
if not epoch or not next_generation then return {'overflow'} end
redis.call('SET', KEYS[2], epoch)
redis.call('HSET', KEYS[1],
  'tenant_id', h(KEYS[3], 'tenant_id'), 'device_id', h(KEYS[3], 'device_id'),
  'deployment_incarnation', ARGV[1], 'node_id', ARGV[3], 'boot_id', ARGV[4],
  'session_id', ARGV[5], 'owner_epoch', epoch, 'lease_expires_at_us', ARGV[6])
redis.call('PEXPIREAT', KEYS[1], math.floor(lease / 1000))
redis.call('SET', KEYS[6], next_generation)
return {'ok', epoch, ARGV[6]}
"#;

const SCRIPT_RENEW_OWNER: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[3]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[4]) ~= ARGV[2] then return {'authority'} end
if h(KEYS[2], 'active') ~= '1' then return {'stale'} end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local lease = tonumber(ARGV[7])
local current_expiry = tonumber(h(KEYS[1], 'lease_expires_at_us'))
if not lease or not current_expiry or lease <= now or current_expiry <= now then return {'stale'} end
if h(KEYS[1], 'owner_epoch') ~= ARGV[3]
   or h(KEYS[1], 'deployment_incarnation') ~= ARGV[1]
   or h(KEYS[1], 'node_id') ~= ARGV[4]
   or h(KEYS[1], 'boot_id') ~= ARGV[5]
   or h(KEYS[1], 'session_id') ~= ARGV[6] then return {'stale'} end
redis.call('HSET', KEYS[1], 'lease_expires_at_us', ARGV[7])
redis.call('PEXPIREAT', KEYS[1], math.floor(tonumber(ARGV[7]) / 1000))
return {'ok'}
"#;

const SCRIPT_RELEASE_OWNER: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[2]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[3]) ~= ARGV[2] then return {'authority'} end
if h(KEYS[1], 'owner_epoch') ~= ARGV[3]
   or h(KEYS[1], 'deployment_incarnation') ~= ARGV[1]
   or h(KEYS[1], 'node_id') ~= ARGV[4]
   or h(KEYS[1], 'boot_id') ~= ARGV[5]
   or h(KEYS[1], 'session_id') ~= ARGV[6] then return {'stale'} end
redis.call('DEL', KEYS[1])
return {'ok'}
"#;

const SCRIPT_CURRENT_OWNER: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[3]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[4]) ~= ARGV[2] then return {'authority'} end
if h(KEYS[2], 'active') ~= '1' then return {'none'} end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local expiry = tonumber(h(KEYS[1], 'lease_expires_at_us'))
if not expiry or expiry <= now then return {'none'} end
return {'ok', h(KEYS[1], 'node_id'), h(KEYS[1], 'boot_id'), h(KEYS[1], 'session_id'), h(KEYS[1], 'owner_epoch'), h(KEYS[1], 'lease_expires_at_us')}
"#;

const SCRIPT_ISSUE_ATTACHMENT_TICKET: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[6]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[7]) ~= ARGV[2] then return {'authority'} end
if h(KEYS[4], 'active') ~= '1' then return {'stale'} end
local clock = redis.call('TIME')
local now_us = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local expiry = tonumber(ARGV[14])
local lease = tonumber(h(KEYS[1], 'lease_expires_at_us'))
if not expiry or expiry <= now_us or not lease or lease <= now_us then return {'stale'} end
local credential_key = redis.call('GET', KEYS[5])
if not credential_key or h(credential_key, 'active') ~= '1'
   or h(credential_key, 'tenant_id') ~= ARGV[12]
   or h(credential_key, 'device_id') ~= ARGV[13]
   or h(credential_key, 'revoked_at_us') ~= '' then return {'stale'} end
local not_before = tonumber(h(credential_key, 'not_before_us'))
local credential_expiry = tonumber(h(credential_key, 'expires_at_us'))
if not not_before or not credential_expiry or not_before > now_us or credential_expiry <= now_us then return {'stale'} end
if h(KEYS[1], 'owner_epoch') ~= ARGV[3]
   or h(KEYS[1], 'deployment_incarnation') ~= ARGV[1]
   or h(KEYS[1], 'node_id') ~= ARGV[4]
   or h(KEYS[1], 'boot_id') ~= ARGV[5]
   or h(KEYS[1], 'session_id') ~= ARGV[6] then return {'stale'} end
if redis.call('EXISTS', KEYS[2]) == 1 then return {'collision'} end
local now_ms = math.floor(now_us / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now_ms)
if redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[16]) then return {'bound'} end
redis.call('HSET', KEYS[2],
  'tenant_id', ARGV[12], 'device_id', ARGV[13], 'spki_fingerprint', ARGV[7],
  'deployment_incarnation', ARGV[1], 'node_id', ARGV[4], 'boot_id', ARGV[5],
  'session_id', ARGV[6], 'owner_epoch', ARGV[3], 'generation', ARGV[8],
  'connection_id', ARGV[9], 'purpose', ARGV[10], 'binding_digest', ARGV[11],
  'expires_at_us', ARGV[14], 'spent', '0')
redis.call('PEXPIREAT', KEYS[2], math.floor(expiry / 1000))
redis.call('ZADD', KEYS[3], math.floor(expiry / 1000), ARGV[15])
redis.call('PEXPIREAT', KEYS[3], math.floor(expiry / 1000))
return {'ok'}
"#;

const SCRIPT_CONSUME_ATTACHMENT_TICKET: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[6]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[7]) ~= ARGV[2] then return {'authority'} end
if redis.call('EXISTS', KEYS[1]) == 0 then return {'missing'} end
if h(KEYS[1], 'spent') == '1' then return {'spent'} end
local clock = redis.call('TIME')
local now_us = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local expiry = tonumber(h(KEYS[1], 'expires_at_us'))
if not expiry or expiry <= now_us then return {'expired'} end
if h(KEYS[4], 'active') ~= '1' then return {'stale'} end
local lease = tonumber(h(KEYS[3], 'lease_expires_at_us'))
if not lease or lease <= now_us then return {'stale'} end
local credential_key = redis.call('GET', KEYS[5])
if not credential_key or h(credential_key, 'active') ~= '1'
   or h(credential_key, 'tenant_id') ~= ARGV[12]
   or h(credential_key, 'device_id') ~= ARGV[13]
   or h(credential_key, 'revoked_at_us') ~= '' then return {'stale'} end
local not_before = tonumber(h(credential_key, 'not_before_us'))
local credential_expiry = tonumber(h(credential_key, 'expires_at_us'))
if not not_before or not credential_expiry or not_before > now_us or credential_expiry <= now_us then return {'stale'} end
if h(KEYS[3], 'owner_epoch') ~= ARGV[3]
   or h(KEYS[3], 'deployment_incarnation') ~= ARGV[1]
   or h(KEYS[3], 'node_id') ~= ARGV[4]
   or h(KEYS[3], 'boot_id') ~= ARGV[5]
   or h(KEYS[3], 'session_id') ~= ARGV[6] then return {'stale'} end
if h(KEYS[1], 'tenant_id') ~= ARGV[12]
   or h(KEYS[1], 'device_id') ~= ARGV[13]
   or h(KEYS[1], 'spki_fingerprint') ~= ARGV[7]
   or h(KEYS[1], 'deployment_incarnation') ~= ARGV[1]
   or h(KEYS[1], 'node_id') ~= ARGV[4]
   or h(KEYS[1], 'boot_id') ~= ARGV[5]
   or h(KEYS[1], 'session_id') ~= ARGV[6]
   or h(KEYS[1], 'owner_epoch') ~= ARGV[3]
   or h(KEYS[1], 'generation') ~= ARGV[8]
   or h(KEYS[1], 'connection_id') ~= ARGV[9]
   or h(KEYS[1], 'purpose') ~= ARGV[10]
   or h(KEYS[1], 'binding_digest') ~= ARGV[11] then return {'mismatch'} end
redis.call('HSET', KEYS[1], 'spent', '1')
redis.call('PEXPIREAT', KEYS[1], math.floor(expiry / 1000))
redis.call('ZREM', KEYS[2], ARGV[14])
return {
  'ok', h(KEYS[1], 'tenant_id'), h(KEYS[1], 'device_id'), h(KEYS[1], 'spki_fingerprint'),
  h(KEYS[1], 'deployment_incarnation'), h(KEYS[1], 'node_id'), h(KEYS[1], 'boot_id'),
  h(KEYS[1], 'session_id'), h(KEYS[1], 'owner_epoch'), h(KEYS[1], 'generation'),
  h(KEYS[1], 'connection_id'), h(KEYS[1], 'purpose'), h(KEYS[1], 'binding_digest'),
  h(KEYS[1], 'expires_at_us')
}
"#;

const SCRIPT_PUBLISH_MEMBERSHIP: &str = r#"
local current = redis.call('HGET', KEYS[1], 'version')
if current then
  local ordering = decimal_compare(current, ARGV[1])
  if not ordering then return {'invalid'} end
  if ordering > 0 then return {'stale'} end
  if ordering == 0 then
    local existing = redis.call('HGET', KEYS[1], 'bytes')
    if existing == ARGV[2] then
      redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
      return {'ok'}
    end
    return {'conflict'}
  end
end
redis.call('HSET', KEYS[1], 'version', ARGV[1], 'bytes', ARGV[2])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
return {'ok'}
"#;

const SCRIPT_PUBLISH_MEMBERSHIP_DIRECTORY: &str = r#"
local current = redis.call('HGET', KEYS[1], ARGV[1])
if current then
  local ok, decoded = pcall(cjson.decode, current)
  if not ok or type(decoded) ~= 'table' or not decoded.version then return {'invalid'} end
  local ordering = decimal_compare(tostring(decoded.version), ARGV[2])
  if not ordering then return {'invalid'} end
  if ordering > 0 then return {'stale'} end
  if ordering == 0 then
    if current == ARGV[3] then
      redis.call('EXPIRE', KEYS[1], tonumber(ARGV[5]))
      return {'ok'}
    end
    return {'conflict'}
  end
else
  local max_records = tonumber(ARGV[4])
  if not max_records or redis.call('HLEN', KEYS[1]) >= max_records then return {'bound'} end
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[5]))
return {'ok'}
"#;

const SCRIPT_READ_MEMBERSHIP_DIRECTORY: &str = r#"
local max_records = tonumber(ARGV[1])
local count = redis.call('HLEN', KEYS[1])
if not max_records or count > max_records then return {'too_many'} end
local entries = redis.call('HGETALL', KEYS[1])
local result = {'ok'}
for _, value in ipairs(entries) do result[#result + 1] = value end
return result
"#;

/// Shared head of every day-2 addition script (M6-C31).  KEYS[1] is the
/// provisioning reservation, KEYS[2] and KEYS[3] the incarnation and Redis run
/// bindings, KEYS[4] the catalog generation; ARGV[1] and ARGV[2] the
/// configured incarnation and the connection's Redis run id.  Nothing here
/// writes; `next_generation` is the value the body sets last.
const LUA_DAY2_PRECONDITIONS: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('EXISTS', KEYS[1]) ~= 1 then return {'unprovisioned'} end
if redis.call('GET', KEYS[2]) ~= ARGV[1] or redis.call('GET', KEYS[3]) ~= ARGV[2] then
  return {'incarnation'}
end
local next_generation = decimal_increment(redis.call('GET', KEYS[4]))
if not next_generation then return {'overflow'} end
"#;

/// KEYS[5] tenant, [6] user, [7] identity, [8] membership, [9] users index,
/// [10] identities index, [11] tenant memberships index, [12] user tenants
/// index.  ARGV[3] tenant, [4] user, [5] display name, [6] issuer,
/// [7] subject, [8] role, [9] identity key.
const SCRIPT_ADD_USER_BODY: &str = r#"
if h(KEYS[5], 'active') ~= '1' then return {'tenant'} end
if redis.call('EXISTS', KEYS[6]) == 1 then return {'user_exists'} end
if redis.call('EXISTS', KEYS[7]) == 1 then return {'identity_exists'} end
if redis.call('EXISTS', KEYS[8]) == 1 then return {'membership_exists'} end
redis.call('HSET', KEYS[6], 'user_id', ARGV[4], 'display_name', ARGV[5])
redis.call('SADD', KEYS[9], ARGV[4])
redis.call('HSET', KEYS[7], 'issuer', ARGV[6], 'subject', ARGV[7], 'user_id', ARGV[4])
redis.call('SADD', KEYS[10], ARGV[9])
redis.call('HSET', KEYS[8], 'tenant_id', ARGV[3], 'user_id', ARGV[4], 'role', ARGV[8], 'active', '1')
redis.call('SADD', KEYS[11], ARGV[4])
redis.call('SADD', KEYS[12], ARGV[3])
redis.call('SET', KEYS[4], next_generation)
return {'ok'}
"#;

/// KEYS[5] tenant, [6] owner membership, [7] device, [8] tenant devices
/// index, [9] owner epoch, [10] credential, [11] fingerprint index,
/// [12] device credentials index.  ARGV[3] tenant, [4] device, [5] owner,
/// [6] display name, [7] credential id, [8] SPKI pin, [9] serial,
/// [10] not_before_us, [11] expires_at_us, [12] credential key.
const SCRIPT_ADD_DEVICE_BODY: &str = r#"
if h(KEYS[5], 'active') ~= '1' then return {'tenant'} end
if h(KEYS[6], 'active') ~= '1' then return {'owner'} end
if redis.call('EXISTS', KEYS[7]) == 1 then return {'device_exists'} end
if redis.call('EXISTS', KEYS[11]) == 1 then return {'fingerprint_exists'} end
if redis.call('EXISTS', KEYS[10]) == 1 then return {'credential_exists'} end
redis.call('HSET', KEYS[7], 'tenant_id', ARGV[3], 'device_id', ARGV[4], 'owner_user_id', ARGV[5], 'display_name', ARGV[6], 'active', '1', 'last_seen_at_us', '', 'device_version', '1')
redis.call('SETNX', KEYS[9], '0')
redis.call('SADD', KEYS[8], ARGV[4])
redis.call('HSET', KEYS[10], 'tenant_id', ARGV[3], 'device_id', ARGV[4], 'credential_id', ARGV[7], 'spki_fingerprint', ARGV[8], 'serial', ARGV[9], 'not_before_us', ARGV[10], 'expires_at_us', ARGV[11], 'revoked_at_us', '', 'active', '1')
redis.call('SET', KEYS[11], ARGV[12])
redis.call('SADD', KEYS[12], ARGV[7])
redis.call('SET', KEYS[4], next_generation)
return {'ok'}
"#;

/// KEYS[5] tenant, [6] device, [7] service, [8] device services index.
/// ARGV[3] tenant, [4] device, [5] service, [6] type, [7] display name,
/// [8] capabilities JSON.
const SCRIPT_ADD_SERVICE_BODY: &str = r#"
if h(KEYS[5], 'active') ~= '1' then return {'tenant'} end
if h(KEYS[6], 'active') ~= '1' then return {'device'} end
if redis.call('EXISTS', KEYS[7]) == 1 then return {'service_exists'} end
redis.call('HSET', KEYS[7], 'tenant_id', ARGV[3], 'device_id', ARGV[4], 'service_id', ARGV[5], 'service_type', ARGV[6], 'display_name', ARGV[7], 'capabilities', ARGV[8], 'version', '1', 'active', '1')
redis.call('SADD', KEYS[8], ARGV[5])
redis.call('SET', KEYS[4], next_generation)
return {'ok'}
"#;

/// The record rules of [`RedisCatalog::add_user`], applied before any Redis
/// call.  Public so an operator command's dry run applies exactly these rules
/// without contacting Redis (task row M6-C31).
pub fn validate_user_addition(
    user: &UserRecord,
    identity: &PrincipalIdentity,
    membership: &MembershipRecord,
) -> Result<(), CatalogError> {
    if identity.user_id != user.user_id
        || membership.user_id != user.user_id
        || !membership.active
        || !valid_principal_identity(&identity.issuer, &identity.subject)
    {
        return Err(CatalogError::InvalidInput("user addition"));
    }
    Ok(())
}

/// The record rules of [`RedisCatalog::add_device`], applied before any
/// Redis call (M6-C31).
pub fn validate_device_addition(
    device: &FixtureDevice,
    credential: &CredentialRecord,
) -> Result<(), CatalogError> {
    if credential.tenant_id != device.tenant_id
        || credential.device_id != device.device_id
        || !device.active
        || !credential.active
        || credential.revoked_at.is_some()
        || !valid_fingerprint(&credential.spki_fingerprint)
        || credential.expires_at <= credential.not_before
    {
        return Err(CatalogError::InvalidInput("device addition"));
    }
    Ok(())
}

/// The record rules of [`RedisCatalog::add_service`], applied before any
/// Redis call (M6-C31).
pub fn validate_service_addition(service: &ServiceSpec) -> Result<(), CatalogError> {
    if service.service_type.trim().is_empty() || !service.active {
        return Err(CatalogError::InvalidInput("service addition"));
    }
    Ok(())
}

/// Map a day-2 addition script's reply to its outcome.  Every refusal is
/// static text naming the record, never a Redis error string.
fn day2_reply(reply: &[String]) -> Result<(), CatalogError> {
    match reply.first().map(String::as_str) {
        Some("ok") => Ok(()),
        Some("unprovisioned") => Err(CatalogError::Conflict(
            "namespace has not been provisioned; run provision-catalog first",
        )),
        Some("incarnation") => Err(CatalogError::Conflict(
            "active deployment incarnation or Redis authority run",
        )),
        Some("overflow") => Err(CatalogError::RevisionOverflow),
        Some("tenant") => Err(CatalogError::Conflict(
            "tenant does not exist or is inactive",
        )),
        Some("owner") => Err(CatalogError::Conflict(
            "owner is not an active member of the tenant",
        )),
        Some("device") => Err(CatalogError::Conflict(
            "device does not exist or is inactive",
        )),
        Some("user_exists") => Err(CatalogError::Conflict("user already exists")),
        Some("identity_exists") => Err(CatalogError::Conflict(
            "the issuer subject is already bound to a user",
        )),
        Some("membership_exists") => Err(CatalogError::Conflict("membership already exists")),
        Some("device_exists") => Err(CatalogError::Conflict(
            "device already exists in the tenant (a revoked device id is not reused)",
        )),
        Some("fingerprint_exists") => Err(CatalogError::Conflict("duplicate SPKI fingerprint")),
        Some("credential_exists") => Err(CatalogError::Conflict("credential already exists")),
        Some("service_exists") => Err(CatalogError::Conflict("service already exists")),
        _ => Err(CatalogError::Serialization(
            "invalid Redis catalog change reply".into(),
        )),
    }
}

const SCRIPT_SEED_CREDENTIAL: &str = r#"
local existing = redis.call('GET', KEYS[2])
if existing and existing ~= KEYS[1] then return {'conflict'} end
local next_generation = decimal_increment(redis.call('GET', KEYS[4]))
if not next_generation then return {'overflow'} end
redis.call('HSET', KEYS[1], 'tenant_id', ARGV[1], 'device_id', ARGV[2], 'credential_id', ARGV[3], 'spki_fingerprint', ARGV[4], 'serial', ARGV[5], 'not_before_us', ARGV[6], 'expires_at_us', ARGV[7], 'revoked_at_us', ARGV[8], 'active', ARGV[9])
redis.call('SET', KEYS[2], KEYS[1])
redis.call('SADD', KEYS[3], ARGV[3])
redis.call('SET', KEYS[4], next_generation)
return {'ok'}
"#;

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    /// `examples/m1-relay.toml` shipped `agent-tunnel/m1`, which this rule
    /// refuses: the documented `serve --config` therefore failed at startup.
    /// The rule is the authority for every relay key prefix, so pin both the
    /// accepted charset and the exact characters that broke the example.
    #[test]
    fn redis_namespace_rule_accepts_only_bounded_unambiguous_key_prefixes() {
        for accepted in [
            "agent-tunnel-m1",
            "agent_tunnel.m1",
            "AgentTunnel0",
            "a",
            "-",
            ".",
            "_",
            &"n".repeat(super::MAX_REDIS_NAMESPACE_BYTES),
        ] {
            super::validate_redis_namespace(accepted)
                .unwrap_or_else(|error| panic!("{accepted:?} must be accepted: {error}"));
        }

        for rejected in [
            // The exact namespace the checked-in example shipped.
            "agent-tunnel/m1",
            "",
            &"n".repeat(super::MAX_REDIS_NAMESPACE_BYTES + 1),
            // A second key separator would let a namespace address another
            // namespace's keys.
            "agent:tunnel",
            // Glob metacharacters would change which keys a scan pattern
            // matches.
            "agent*tunnel",
            "agent?tunnel",
            "agent[tunnel]",
            // Whitespace, control bytes and non-ASCII are never key-safe.
            " agent-tunnel",
            "agent-tunnel ",
            "agent\ttunnel",
            "agent\ntunnel",
            "agent\0tunnel",
            "agent-tünnel",
            "agent+tunnel",
            "agent{tunnel}",
        ] {
            assert!(
                super::validate_redis_namespace(rejected).is_err(),
                "{rejected:?} must be rejected"
            );
        }
    }

    /// The namespace is refused before the catalog opens a socket, so a
    /// configuration validator mirroring the rule loses no fidelity.
    #[tokio::test]
    async fn redis_namespace_is_rejected_before_any_connection_attempt() {
        // Port 1 on loopback: a connection attempt fails with a distinct
        // database error, so the namespace error cannot come from the network.
        let namespace_error =
            super::RedisCatalog::connect("redis://127.0.0.1:1/0", "bad/namespace")
                .await
                .expect_err("an invalid namespace must be refused");
        assert!(
            matches!(
                namespace_error,
                crate::CatalogError::InvalidInput("Redis namespace")
            ),
            "expected the namespace rule, observed {namespace_error:?}"
        );
        let connection_error =
            super::RedisCatalog::connect("redis://127.0.0.1:1/0", "good-namespace")
                .await
                .expect_err("an unreachable authority must fail");
        assert!(
            !matches!(
                connection_error,
                crate::CatalogError::InvalidInput("Redis namespace")
            ),
            "a valid namespace must reach the connection attempt"
        );
    }

    #[test]
    fn malformed_list_counts_are_rejected_before_allocation() {
        let huge = usize::MAX.to_string();
        assert!(super::parse_device_summaries(&["ok".into(), huge.clone()]).is_err());
        let id = uuid::Uuid::nil().to_string();
        let reply = vec![
            "ok".into(),
            "1".into(),
            id.clone(),
            id.clone(),
            id,
            "fixture".into(),
            "1".into(),
            "".into(),
            "1".into(),
            huge,
        ];
        assert!(super::parse_device_summaries(&reply).is_err());
    }

    use super::{
        CatalogConnectionStage, RedisCatalog, RedisTlsOptions, is_fixture_namespace, key_component,
    };
    use uuid::Uuid;

    #[test]
    fn encoded_key_components_cannot_collide_with_escape_sequences() {
        assert_ne!(key_component("a:b"), key_component("a_3ab"));
        assert_ne!(key_component("_"), key_component("_5f"));
    }

    #[test]
    fn tenant_and_principal_components_remain_independent() {
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let principal_a = Uuid::from_u128(3);
        let principal_b = Uuid::from_u128(4);
        let prefix = "tunnel-catalog:test:";
        let grant_a = format!("{prefix}grant:{tenant_a}:{principal_a}");
        let grant_b = format!("{prefix}grant:{tenant_b}:{principal_a}");
        let grant_c = format!("{prefix}grant:{tenant_a}:{principal_b}");
        assert_ne!(grant_a, grant_b);
        assert_ne!(grant_a, grant_c);
    }

    #[test]
    fn fixture_namespace_guard_is_explicit() {
        assert!(is_fixture_namespace("test-fixture-123"));
        assert!(is_fixture_namespace("m1-fixture-123"));
        assert!(is_fixture_namespace("fixture-123"));
        assert!(!is_fixture_namespace("production-123"));
        assert!(!is_fixture_namespace("test123"));
    }

    #[tokio::test]
    async fn tls_connection_rejects_insecure_profile_and_unbounded_material() {
        let insecure = RedisCatalog::connect_with_tls(
            "rediss://localhost:1/#insecure",
            "test-tls-validation",
            RedisTlsOptions::default(),
        )
        .await
        .expect_err("insecure Redis TLS profile must be rejected before dialing");
        assert!(matches!(
            insecure,
            super::CatalogError::InvalidInput(
                "Redis TLS connection requires a verified rediss:// URL"
            )
        ));

        let empty = RedisCatalog::connect_with_tls(
            "rediss://localhost:1/0",
            "test-tls-validation",
            RedisTlsOptions::with_root_cert_pem(Vec::new()),
        )
        .await
        .expect_err("empty Redis TLS material must be rejected before dialing");
        assert!(matches!(
            empty,
            super::CatalogError::InvalidInput(
                "Redis TLS root certificate PEM must be 1..=1048576 bytes"
            )
        ));

        let oversized = RedisCatalog::connect_with_tls(
            "rediss://localhost:1/0",
            "test-tls-validation",
            RedisTlsOptions::with_root_cert_pem(vec![b'x'; super::MAX_REDIS_TLS_PEM_BYTES + 1]),
        )
        .await
        .expect_err("oversized Redis TLS material must be rejected before dialing");
        assert!(matches!(
            oversized,
            super::CatalogError::InvalidInput(
                "Redis TLS root certificate PEM must be 1..=1048576 bytes"
            )
        ));
    }

    #[tokio::test]
    async fn staged_tls_connection_reports_tls_setup_without_changing_error() {
        let error = RedisCatalog::connect_with_tls_and_deployment_incarnation_staged(
            "rediss://localhost:1/0",
            "test-tls-validation",
            "test-incarnation",
            RedisTlsOptions::with_root_cert_pem(Vec::new()),
        )
        .await
        .expect_err("empty Redis TLS material must be rejected before dialing");
        assert_eq!(error.stage(), CatalogConnectionStage::TlsSetup);
        assert!(matches!(
            error.into_catalog_error(),
            super::CatalogError::InvalidInput(
                "Redis TLS root certificate PEM must be 1..=1048576 bytes"
            )
        ));
    }

    #[tokio::test]
    async fn staged_connection_reports_authority_profile_before_dialing() {
        let error = RedisCatalog::connect_with_deployment_incarnation_staged(
            "redis://localhost:1/0",
            "invalid namespace",
            "test-incarnation",
        )
        .await
        .expect_err("invalid Redis namespace must be rejected before dialing");
        assert_eq!(error.stage(), CatalogConnectionStage::AuthorityProfile);
        assert!(matches!(
            error.into_catalog_error(),
            super::CatalogError::InvalidInput("Redis namespace")
        ));
    }

    #[derive(Clone, Copy, Debug)]
    enum TransportFault {
        InfoWrite,
        InfoRead,
    }

    #[derive(Default)]
    struct TransportObservation {
        writes_completed: AtomicUsize,
        write_bytes: AtomicUsize,
        write_errors: AtomicUsize,
        read_bytes: AtomicUsize,
        read_eof: AtomicUsize,
        read_errors: AtomicUsize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ObservationSnapshot {
        writes_completed: usize,
        write_bytes: usize,
        write_errors: usize,
        read_bytes: usize,
        read_eof: usize,
        read_errors: usize,
    }

    impl TransportObservation {
        fn snapshot(&self) -> ObservationSnapshot {
            ObservationSnapshot {
                writes_completed: self.writes_completed.load(Ordering::Acquire),
                write_bytes: self.write_bytes.load(Ordering::Acquire),
                write_errors: self.write_errors.load(Ordering::Acquire),
                read_bytes: self.read_bytes.load(Ordering::Acquire),
                read_eof: self.read_eof.load(Ordering::Acquire),
                read_errors: self.read_errors.load(Ordering::Acquire),
            }
        }
    }

    struct ObservedStream {
        inner: tokio::io::DuplexStream,
        observation: Arc<TransportObservation>,
        fault: TransportFault,
    }

    impl AsyncRead for ObservedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buffer.filled().len();
            match Pin::new(&mut self.inner).poll_read(cx, buffer) {
                Poll::Ready(Ok(())) => {
                    let bytes = buffer.filled().len().saturating_sub(before);
                    if bytes == 0 {
                        self.observation.read_eof.fetch_add(1, Ordering::Release);
                    } else {
                        self.observation
                            .read_bytes
                            .fetch_add(bytes, Ordering::Release);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => {
                    self.observation.read_errors.fetch_add(1, Ordering::Release);
                    Poll::Ready(Err(error))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for ObservedStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if matches!(self.fault, TransportFault::InfoWrite)
                && bytes
                    .windows(b"$4\r\nINFO\r\n".len())
                    .any(|window| window == b"$4\r\nINFO\r\n")
            {
                self.observation
                    .write_errors
                    .fetch_add(1, Ordering::Release);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected INFO write failure",
                )));
            }
            match Pin::new(&mut self.inner).poll_write(cx, bytes) {
                Poll::Ready(Ok(written)) => {
                    self.observation
                        .writes_completed
                        .fetch_add(1, Ordering::Release);
                    self.observation
                        .write_bytes
                        .fetch_add(written, Ordering::Release);
                    Poll::Ready(Ok(written))
                }
                Poll::Ready(Err(error)) => {
                    self.observation
                        .write_errors
                        .fetch_add(1, Ordering::Release);
                    Poll::Ready(Err(error))
                }
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => {
                    self.observation
                        .write_errors
                        .fetch_add(1, Ordering::Release);
                    Poll::Ready(Err(error))
                }
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    async fn serve_observed_redis(
        mut stream: tokio::io::DuplexStream,
        fault: TransportFault,
    ) -> io::Result<()> {
        let mut pending = Vec::new();
        let mut setup_responses = 0;
        let mut ping_replied = false;
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Ok(());
            }
            pending.extend_from_slice(&buffer[..read]);
            if pending.len() > 16 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bounded Redis observer request buffer exceeded",
                ));
            }
            while setup_responses < 2
                && pending
                    .windows(b"CLIENT".len())
                    .any(|window| window == b"CLIENT")
            {
                stream.write_all(b"+OK\r\n").await?;
                setup_responses += 1;
            }
            if !ping_replied
                && pending
                    .windows(b"$4\r\nPING\r\n".len())
                    .any(|window| window == b"$4\r\nPING\r\n")
            {
                stream.write_all(b"+PONG\r\n").await?;
                ping_replied = true;
            }
            if ping_replied
                && pending
                    .windows(b"$4\r\nINFO\r\n".len())
                    .any(|window| window == b"$4\r\nINFO\r\n")
            {
                if matches!(fault, TransportFault::InfoRead) {
                    return Ok(());
                }
                let body = b"# Server\r\nrun_id: transport-observer\r\n\r\n";
                let header = format!("${}\r\n", body.len());
                stream.write_all(header.as_bytes()).await?;
                stream.write_all(body).await?;
                stream.write_all(b"\r\n").await?;
                return Ok(());
            }
        }
    }

    async fn run_observed_transport(
        fault: TransportFault,
    ) -> (super::CatalogConnectionError, ObservationSnapshot) {
        const OBSERVER_DEADLINE: Duration = Duration::from_secs(3);
        const HANDLE_CLEANUP_DEADLINE: Duration = Duration::from_secs(1);

        let (client_stream, server_stream) = tokio::io::duplex(16 * 1024);
        let observation = Arc::new(TransportObservation::default());
        let server = tokio::spawn(serve_observed_redis(server_stream, fault));
        let observed_stream = ObservedStream {
            inner: client_stream,
            observation: Arc::clone(&observation),
            fault,
        };
        let connection_info = redis::RedisConnectionInfo::default().set_skip_set_lib_name();
        let constructed = tokio::time::timeout(
            OBSERVER_DEADLINE,
            redis::aio::MultiplexedConnection::new(&connection_info, observed_stream),
        )
        .await;
        let (connection, driver) = match constructed {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                let server_result = join_observed_server(server, HANDLE_CLEANUP_DEADLINE).await;
                assert!(server_result.is_ok());
                panic!("construct observed Redis connection: {error}");
            }
            Err(_) => {
                let server_result = join_observed_server(server, HANDLE_CLEANUP_DEADLINE).await;
                assert!(server_result.is_ok());
                panic!("construct observed Redis connection timed out");
            }
        };
        // Drive the borrowed Redis future in this scope. redis-rs 1.7 captures
        // connection_info in its returned future, so spawning it would require
        // leaking that configuration. The bounded join owns both futures and
        // drops them together on timeout.
        let probe = tokio::time::timeout(OBSERVER_DEADLINE, async {
            let (result, ()) = tokio::join!(super::verify_connection_identity(connection), driver);
            result
        })
        .await;
        let server_result = join_observed_server(server, HANDLE_CLEANUP_DEADLINE).await;
        assert!(server_result.is_ok());
        let error = match probe {
            Ok(Err(error)) => error,
            Ok(Ok((_connection, _redis_run_id))) => {
                panic!("injected transport fault unexpectedly passed PING/INFO verification")
            }
            Err(_) => panic!("observed Redis transport probe timed out"),
        };
        (error, observation.snapshot())
    }

    async fn join_observed_server(
        mut handle: tokio::task::JoinHandle<io::Result<()>>,
        cleanup_deadline: Duration,
    ) -> io::Result<()> {
        match tokio::time::timeout(cleanup_deadline, &mut handle).await {
            Ok(joined) => joined.expect("observed Redis server task must join"),
            Err(_) => {
                handle.abort();
                match handle.await {
                    Ok(result) => result,
                    Err(error) => {
                        assert!(
                            error.is_cancelled(),
                            "observed Redis server task failed while joining: {error}"
                        );
                        Ok(())
                    }
                }
            }
        }
    }

    /// A resolver that answers after `delay`, standing in for the cold first
    /// DNS lookup measured on a fresh Fly machine (M6-C73).
    struct SlowResolver {
        delay: Duration,
        address: std::net::SocketAddr,
    }

    impl redis::io::AsyncDNSResolver for SlowResolver {
        fn resolve<'a, 'b: 'a>(
            &'a self,
            _host: &'b str,
            _port: u16,
        ) -> redis::RedisFuture<'a, Box<dyn Iterator<Item = std::net::SocketAddr> + Send + 'a>>
        {
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                Ok(Box::new(std::iter::once(self.address))
                    as Box<dyn Iterator<Item = std::net::SocketAddr> + Send>)
            })
        }
    }

    /// A minimal RESP peer: answers every command with `+OK`, which is all
    /// redis-rs's connection setup needs.
    async fn answering_peer() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind answering peer");
        let address = listener.local_addr().expect("peer address");
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (read, mut write) = socket.into_split();
                    let mut reader = tokio::io::BufReader::new(read);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                        let Some(count) = line
                            .strip_prefix('*')
                            .and_then(|rest| rest.trim_end().parse::<usize>().ok())
                        else {
                            continue;
                        };
                        // Each argument is a length line and a data line.
                        for _ in 0..count * 2 {
                            line.clear();
                            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                                return;
                            }
                        }
                        if write.write_all(b"+OK\r\n").await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        address
    }

    /// A peer that accepts TCP and never answers.
    async fn silent_peer() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent peer");
        let address = listener.local_addr().expect("peer address");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        address
    }

    const COLD_DNS: Duration = Duration::from_millis(2_000);

    fn slow_dns_client() -> redis::Client {
        redis::Client::open("redis://cold-dns.invalid:6379/").expect("client")
    }

    /// M6-C73: a cold two-second DNS lookup fits the catalog's connect budget.
    #[tokio::test]
    async fn m6c73_cold_dns_lookup_connects_within_the_catalog_budget() {
        let address = answering_peer().await;
        let config =
            super::connection_config(super::REDIS_CONNECT_TIMEOUT).set_dns_resolver(SlowResolver {
                delay: COLD_DNS,
                address,
            });
        let started = std::time::Instant::now();
        let connected =
            super::connect_within(&slow_dns_client(), &config, super::REDIS_CONNECT_TIMEOUT).await;
        let elapsed = started.elapsed();
        assert!(
            connected.is_ok(),
            "connect with a cold DNS lookup: {:?}",
            connected
                .err()
                .map(|error| (error.stage(), error.failure()))
        );
        assert!(
            elapsed >= COLD_DNS,
            "the resolver delay applied: {elapsed:?}"
        );
    }

    /// The pre-M6-C73 configuration: redis-rs's default connection timeout
    /// (one second, covering DNS) inside the two-second outer deadline.  The
    /// same cold lookup fails as a connection-establishment timeout before
    /// TCP connect starts, which is what the Fly deployment printed.
    #[tokio::test]
    async fn m6c73_library_default_connect_budget_fails_the_cold_lookup_as_a_timeout() {
        let address = answering_peer().await;
        let config = redis::AsyncConnectionConfig::new()
            .set_response_timeout(Some(super::REDIS_OPERATION_TIMEOUT))
            .set_dns_resolver(SlowResolver {
                delay: COLD_DNS,
                address,
            });
        let started = std::time::Instant::now();
        let error =
            super::connect_within(&slow_dns_client(), &config, super::REDIS_OPERATION_TIMEOUT)
                .await
                .expect_err("the library default must not fit a two-second lookup");
        let elapsed = started.elapsed();
        assert_eq!(
            error.stage(),
            CatalogConnectionStage::ConnectionEstablishment
        );
        assert_eq!(error.failure(), crate::CatalogConnectionFailure::Timeout);
        // The library's one-second default decided, not the two-second
        // outer deadline around it.
        assert!(
            elapsed < Duration::from_millis(1_500),
            "redis-rs's one-second default expired first: {elapsed:?}"
        );
    }

    /// M6-C74 review: a host name that does not resolve is classified `dns`,
    /// not `config` (redis-rs's own resolver reports an empty lookup as an
    /// invalid client configuration).
    #[tokio::test]
    async fn unresolvable_host_is_classified_dns() {
        let client =
            redis::Client::open("redis://m6c74-no-such-host.invalid:6379/").expect("client");
        let error = super::connect_within(
            &client,
            &super::connection_config(super::REDIS_CONNECT_TIMEOUT),
            super::REDIS_CONNECT_TIMEOUT,
        )
        .await
        .expect_err("an .invalid host never resolves");
        assert_eq!(
            error.stage(),
            CatalogConnectionStage::ConnectionEstablishment
        );
        assert_eq!(error.failure(), crate::CatalogConnectionFailure::Dns);
    }

    /// The effective connect budget is the configured one, inside redis-rs
    /// and around it, so a library default cannot silently shrink it again.
    #[tokio::test]
    async fn m6c73_effective_connect_budget_is_the_configured_one() {
        const BUDGET: Duration = Duration::from_secs(3);
        let address = silent_peer().await;
        let client = redis::Client::open(format!("redis://{address}/")).expect("client");
        let started = std::time::Instant::now();
        let error = super::connect_within(&client, &super::connection_config(BUDGET), BUDGET)
            .await
            .expect_err("a silent peer never completes setup");
        let elapsed = started.elapsed();
        assert_eq!(error.failure(), crate::CatalogConnectionFailure::Timeout);
        assert!(
            elapsed >= BUDGET - Duration::from_millis(100)
                && elapsed < BUDGET + Duration::from_millis(1_500),
            "the configured {BUDGET:?} decided, not a library default: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn transport_observer_distinguishes_info_write_error_from_peer_read_close() {
        let (write_error, write_observation) =
            run_observed_transport(TransportFault::InfoWrite).await;
        assert_eq!(write_error.stage(), CatalogConnectionStage::PrimaryIdentity);
        assert!(write_observation.writes_completed >= 1);
        assert!(write_observation.write_bytes > 0);
        assert!(write_observation.read_bytes > 0);
        assert!(write_observation.write_errors >= 1);
        assert_eq!(write_observation.read_errors, 0);

        let (read_error, read_observation) = run_observed_transport(TransportFault::InfoRead).await;
        assert_eq!(read_error.stage(), CatalogConnectionStage::PrimaryIdentity);
        assert!(read_observation.writes_completed >= 2);
        assert!(read_observation.write_bytes > 0);
        assert!(read_observation.read_bytes > 0);
        assert_eq!(read_observation.write_errors, 0);
        assert!(read_observation.read_eof >= 1 || read_observation.read_errors >= 1);
    }
}
