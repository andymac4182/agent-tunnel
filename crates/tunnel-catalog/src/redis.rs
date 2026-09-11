use crate::memory::valid_fingerprint;
use crate::{
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, CredentialRecord, DeviceIdentity,
    DeviceListFilter, DeviceSummary, GrantSnapshot, GrantSpec, OwnerClaim, OwnerClaimRequest,
    OwnerToken, ServiceRecord,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use redis::{FromRedisValue, aio::MultiplexedConnection};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use uuid::Uuid;

const MAX_SAFE_REDIS_TIME: i64 = 9_000_000_000_000_000;
const MAX_FIXTURE_RECORDS: usize = 4_096;
const MAX_CLEANUP_KEYS: usize = 100_000;
const MAX_SEED_SCAN_KEYS: usize = 100_000;
const DEFAULT_MAX_LIST_ITEMS: usize = 1_024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const REDIS_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_AUTHORITY_CLOCK_SKEW_US: i64 = 1_000_000;

/// The authoritative M1 catalog. Redis is the only durable state authority;
/// this type deliberately uses a plain multiplexed connection and does not
/// enable redis-rs' reconnecting `ConnectionManager`. A connection error is
/// therefore surfaced to callers and authorization/ownership fail closed.
#[derive(Clone)]
pub struct RedisCatalog {
    connection: Arc<Mutex<MultiplexedConnection>>,
    namespace: String,
    prefix: String,
    redis_run_id: String,
    deployment_incarnation: Option<String>,
    max_list_items: usize,
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
        validate_namespace(namespace)?;
        if redis_url.trim().is_empty() {
            return Err(CatalogError::InvalidInput("redis URL"));
        }
        let client = redis::Client::open(redis_url)?;
        let mut connection = tokio::time::timeout(
            REDIS_OPERATION_TIMEOUT,
            client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_| redis_timeout())??;
        tokio::time::timeout(
            REDIS_OPERATION_TIMEOUT,
            redis::cmd("PING").query_async::<String>(&mut connection),
        )
        .await
        .map_err(|_| redis_timeout())??;
        let info: String = tokio::time::timeout(
            REDIS_OPERATION_TIMEOUT,
            redis::cmd("INFO")
                .arg("server")
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| redis_timeout())??;
        let redis_run_id = parse_redis_run_id(&info)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            namespace: namespace.to_owned(),
            prefix: format!("tunnel-catalog:{namespace}:"),
            redis_run_id,
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
        let mut catalog = Self::connect(redis_url, namespace).await?;
        catalog.configure_deployment_incarnation(deployment_incarnation)?;
        catalog.ensure_active_incarnation().await?;
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
        let mut catalog = Self::connect(redis_url, namespace).await?;
        catalog.configure_deployment_incarnation(deployment_incarnation)?;
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

    /// Set the configured incarnation as the active owner-fencing
    /// incarnation. This is an explicit recovery operation. It is idempotent
    /// for the same incarnation and Redis run, or installs a different
    /// incarnation when no live owner exists. A Redis run change requires a
    /// different incarnation and never promotes automatically.
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
                    self.redis_run_id.clone(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(()),
            Some("busy") => Err(CatalogError::OwnerBusy),
            Some("mismatch") => Err(CatalogError::Conflict("active deployment incarnation")),
            _ => Err(CatalogError::Serialization(
                "invalid Redis incarnation reply".into(),
            )),
        }
    }

    async fn ensure_active_incarnation(&self) -> Result<(), CatalogError> {
        let incarnation = self.configured_incarnation()?;
        let reply: Vec<String> = self
            .eval(
                SCRIPT_ENSURE_INCARNATION,
                &[
                    self.active_incarnation_key(),
                    self.tenants_index(),
                    self.redis_run_id_key(),
                ],
                &[incarnation.to_owned(), self.redis_run_id.clone()],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(()),
            Some("mismatch") => Err(CatalogError::Conflict(
                "active deployment incarnation or Redis authority run",
            )),
            Some("busy") => Err(CatalogError::OwnerBusy),
            _ => Err(CatalogError::Serialization(
                "invalid Redis incarnation reply".into(),
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
                tokio::time::timeout(REDIS_OPERATION_TIMEOUT, async {
                    let mut connection = self.connection.lock().await;
                    command.query_async(&mut *connection).await
                })
                .await
                .map_err(|_| redis_timeout())??
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
            tokio::time::timeout(REDIS_OPERATION_TIMEOUT, async {
                let mut connection = self.connection.lock().await;
                pipeline.query_async::<()>(&mut *connection).await
            })
            .await
            .map_err(|_| redis_timeout())??;
        }
        let mut delete_guard = redis::cmd("DEL");
        delete_guard.arg(&guard_key);
        tokio::time::timeout(REDIS_OPERATION_TIMEOUT, async {
            let mut connection = self.connection.lock().await;
            delete_guard.query_async::<()>(&mut *connection).await
        })
        .await
        .map_err(|_| redis_timeout())??;
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
        let mut command = redis::cmd("EVAL");
        command.arg(script).arg(keys.len() as i64);
        for key in keys {
            command.arg(key);
        }
        for arg in args {
            command.arg(arg);
        }
        let result = tokio::time::timeout(REDIS_OPERATION_TIMEOUT, async {
            let mut connection = self.connection.lock().await;
            command.query_async(&mut *connection).await
        })
        .await
        .map_err(|_| redis_timeout())??;
        Ok(result)
    }

    async fn execute_seed_pipeline(&self, pipeline: redis::Pipeline) -> Result<(), CatalogError> {
        tokio::time::timeout(REDIS_OPERATION_TIMEOUT, async {
            let mut connection = self.connection.lock().await;
            pipeline.query_async::<()>(&mut *connection).await
        })
        .await
        .map_err(|_| redis_timeout())??;
        Ok(())
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

    fn fixture_seed_guard_key(&self) -> String {
        format!("{}meta:fixture_seeded", self.prefix)
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
                SCRIPT_SEED_CREDENTIAL,
                &[
                    self.credential_key(
                        credential.tenant_id,
                        credential.device_id,
                        credential.credential_id,
                    ),
                    self.fingerprint_index(&credential.spki_fingerprint),
                    self.credentials_index(credential.tenant_id, credential.device_id),
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
            .eval(
                SCRIPT_RESOLVE_DEVICE,
                &[self.fingerprint_index(spki_fingerprint)],
                &[
                    spki_fingerprint.to_owned(),
                    at.to_string(),
                    self.prefix.clone(),
                    MAX_AUTHORITY_CLOCK_SKEW_US.to_string(),
                ],
            )
            .await?;
        match reply.first().map(String::as_str) {
            Some("none") => Ok(None),
            Some("clock_skew") => Err(CatalogError::Conflict("authority clock skew")),
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
        if issuer.trim().is_empty() || subject.trim().is_empty() {
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
        let reply: Vec<String> = self
            .eval(
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
                &[self.grant_key(tenant_id, principal_id, device_id, service_id)],
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
        let guard_reply: Vec<String> = self
            .eval(
                SCRIPT_RESERVE_FIXTURE_NAMESPACE,
                &[
                    self.fixture_seed_guard_key(),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[self.prefix.clone(), MAX_SEED_SCAN_KEYS.to_string()],
            )
            .await?;
        match guard_reply.first().map(String::as_str) {
            Some("ok") => {}
            Some("used") => {
                return Err(CatalogError::Conflict("fixture namespace already seeded"));
            }
            Some("occupied") => {
                return Err(CatalogError::Conflict("fixture namespace is not empty"));
            }
            Some("bound") => {
                return Err(CatalogError::Conflict("fixture namespace scan bound"));
            }
            _ => {
                return Err(CatalogError::Serialization(
                    "invalid Redis fixture reservation reply".into(),
                ));
            }
        }
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
                .cmd("HSETNX")
                .arg(self.device_key(device.tenant_id, device.device_id))
                .arg("owner_epoch")
                .arg("0");
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
        self.execute_seed_pipeline(pipeline).await?;
        for credential in &fixture.credentials {
            self.seed_credential(credential).await?;
        }
        for grant in &fixture.grants {
            self.upsert_grant(grant).await?;
        }
        Ok(())
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
            .eval(
                &format!("{LUA_DECIMAL_HELPERS}{SCRIPT_CLAIM_OWNER_BODY}"),
                &[
                    self.device_key(request.tenant_id, request.device_id),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[
                    incarnation.to_owned(),
                    self.redis_run_id.clone(),
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
            .eval(
                SCRIPT_RENEW_OWNER,
                &[
                    self.device_key(token.tenant_id, token.device_id),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[
                    incarnation.to_owned(),
                    self.redis_run_id.clone(),
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
            .eval(
                SCRIPT_RELEASE_OWNER,
                &[
                    self.device_key(token.tenant_id, token.device_id),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[
                    incarnation.to_owned(),
                    self.redis_run_id.clone(),
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
                    self.device_key(tenant_id, device_id),
                    self.active_incarnation_key(),
                    self.redis_run_id_key(),
                ],
                &[incarnation.to_owned(), self.redis_run_id.clone()],
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
}

fn validate_namespace(namespace: &str) -> Result<(), CatalogError> {
    if namespace.is_empty() || namespace.len() > 96 {
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

fn is_fixture_namespace(namespace: &str) -> bool {
    namespace.starts_with("test-")
        || namespace.starts_with("fixture-")
        || namespace.contains("-fixture-")
}

fn redis_timeout() -> redis::RedisError {
    redis::RedisError::from(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "Redis catalog operation timed out",
    ))
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

fn validate_fixture(fixture: &CatalogFixture) -> Result<(), CatalogError> {
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
            || identity.issuer.trim().is_empty()
            || identity.subject.trim().is_empty()
            || identity.issuer.len() > 2048
            || identity.subject.len() > 1024
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
    if key ~= KEYS[1] and key ~= KEYS[2] and key ~= KEYS[3] then
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
if not current or not current_run then return {'mismatch'} end
if current == ARGV[1] and current_run == ARGV[2] then return {'ok'} end
return {'mismatch'}
"#;

const SCRIPT_ACTIVATE_INCARNATION: &str = r#"
local current = redis.call('GET', KEYS[1])
local current_run = redis.call('GET', KEYS[3])
if current and current == ARGV[2] and current_run == ARGV[3] then return {'ok'} end
if current and current == ARGV[2] and current_run ~= ARGV[3] then return {'mismatch'} end
local tenants = redis.call('SMEMBERS', KEYS[2])
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
for _, tenant in ipairs(tenants) do
  local devices = redis.call('SMEMBERS', ARGV[1] .. 'idx:devices:' .. tenant)
  for _, device in ipairs(devices) do
    local key = ARGV[1] .. 'device:' .. tenant .. ':' .. device
    local expiry = redis.call('HGET', key, 'owner_expires_at_us')
    if expiry and expiry ~= '' and tonumber(expiry) > now then
      return {'busy'}
    end
  end
end
redis.call('SET', KEYS[1], ARGV[2])
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
if not caller_at or math.abs(now - caller_at) > tonumber(ARGV[4]) then return {'clock_skew'} end
local at = math.max(caller_at, now)
local translation = math.max(0, now - caller_at)
local active = h(credential_key, 'active')
local device_active = h(device_key, 'active')
local not_before = tonumber(h(credential_key, 'not_before_us'))
local expires = tonumber(h(credential_key, 'expires_at_us'))
if active ~= '1' or device_active ~= '1' or h(credential_key, 'revoked_at_us') ~= '' then return {'none'} end
if not not_before or not expires or not_before > at or expires <= at then return {'none'} end
return {
  'ok', tenant_id, device_id, h(device_key, 'owner_user_id'), credential_id,
  h(credential_key, 'spki_fingerprint'), string.format('%.0f', not_before - translation),
  string.format('%.0f', expires - translation), h(credential_key, 'revoked_at_us'),
  device_active, active, h(device_key, 'device_version'), h(device_key, 'owner_epoch'),
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
if not at or math.abs(now - at) > tonumber(ARGV[3]) then return {'clock_skew'} end
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
if not caller_at or math.abs(now - caller_at) > tonumber(ARGV[10]) then return {'clock_skew'} end
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
redis.call('HSET', KEYS[1], 'tenant_id', h(KEYS[3], 'tenant_id'), 'principal_id', h(KEYS[2], 'user_id'), 'device_id', h(KEYS[4], 'device_id'), 'service_id', h(KEYS[5], 'service_id'), 'revision', revision, 'permissions', ARGV[2], 'constraints', ARGV[3], 'expires_at_us', ARGV[4], 'active', ARGV[5], 'revoked_at_us', '')
redis.call('SADD', KEYS[6], KEYS[1])
return {'ok', revision}
"#;

const SCRIPT_REVOKE_GRANT_BODY: &str = r#"
local revision = redis.call('HGET', KEYS[1], 'revision')
if not revision then return {'none'} end
local next_revision = decimal_increment(revision)
if not next_revision then return {'overflow'} end
redis.call('HSET', KEYS[1], 'revision', next_revision, 'active', '0', 'revoked_at_us', ARGV[1])
return {'ok', next_revision}
"#;

const SCRIPT_REVOKE_DEVICE_BODY: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if h(KEYS[1], 'device_id') == '' then return {'none'} end
local device_version = decimal_increment(h(KEYS[1], 'device_version'))
local owner_epoch = decimal_increment(h(KEYS[1], 'owner_epoch'))
if not device_version or not owner_epoch then return {'overflow'} end
local grants = redis.call('SMEMBERS', KEYS[3])
local next_revisions = {}
for _, grant_key in ipairs(grants) do
  local next_revision = decimal_increment(h(grant_key, 'revision'))
  if not next_revision then return {'overflow'} end
  next_revisions[grant_key] = next_revision
end
redis.call('HSET', KEYS[1], 'active', '0', 'device_version', device_version, 'owner_epoch', owner_epoch, 'owner_deployment_incarnation', '', 'owner_node_id', '', 'owner_boot_id', '', 'owner_session_id', '', 'owner_expires_at_us', '')
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
redis.call('HSET', KEYS[2], 'active', '0', 'revoked_at_us', ARGV[1])
redis.call('HSET', KEYS[1], 'device_version', next_revision)
return {'ok', next_revision}
"#;

const SCRIPT_CLAIM_OWNER_BODY: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[2]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[3]) ~= ARGV[2] then return {'authority'} end
if h(KEYS[1], 'device_id') == '' or h(KEYS[1], 'active') ~= '1' then return {'none'} end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local lease = tonumber(ARGV[6])
if not lease or lease <= now then return {'stale'} end
local expiry = tonumber(h(KEYS[1], 'owner_expires_at_us'))
if expiry and expiry > now then
  if h(KEYS[1], 'owner_deployment_incarnation') == ARGV[1]
     and h(KEYS[1], 'owner_node_id') == ARGV[3]
     and h(KEYS[1], 'owner_boot_id') == ARGV[4]
     and h(KEYS[1], 'owner_session_id') == ARGV[5] then
    local selected = math.max(expiry, lease)
    redis.call('HSET', KEYS[1], 'owner_expires_at_us', string.format('%.0f', selected))
    return {'ok', h(KEYS[1], 'owner_epoch'), string.format('%.0f', selected)}
  end
  return {'busy'}
end
local epoch = decimal_increment(h(KEYS[1], 'owner_epoch'))
if not epoch then return {'overflow'} end
redis.call('HSET', KEYS[1], 'owner_epoch', epoch, 'owner_deployment_incarnation', ARGV[1], 'owner_node_id', ARGV[3], 'owner_boot_id', ARGV[4], 'owner_session_id', ARGV[5], 'owner_expires_at_us', ARGV[6])
return {'ok', epoch, ARGV[6]}
"#;

const SCRIPT_RENEW_OWNER: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[2]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[3]) ~= ARGV[2] then return {'authority'} end
if h(KEYS[1], 'active') ~= '1' then return {'stale'} end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local lease = tonumber(ARGV[7])
local current_expiry = tonumber(h(KEYS[1], 'owner_expires_at_us'))
if not lease or not current_expiry or lease <= now or current_expiry <= now then return {'stale'} end
if h(KEYS[1], 'owner_epoch') ~= ARGV[3]
   or h(KEYS[1], 'owner_deployment_incarnation') ~= ARGV[1]
   or h(KEYS[1], 'owner_node_id') ~= ARGV[4]
   or h(KEYS[1], 'owner_boot_id') ~= ARGV[5]
   or h(KEYS[1], 'owner_session_id') ~= ARGV[6] then return {'stale'} end
redis.call('HSET', KEYS[1], 'owner_expires_at_us', ARGV[7])
return {'ok'}
"#;

const SCRIPT_RELEASE_OWNER: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[2]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[3]) ~= ARGV[2] then return {'authority'} end
if h(KEYS[1], 'owner_epoch') ~= ARGV[3]
   or h(KEYS[1], 'owner_deployment_incarnation') ~= ARGV[1]
   or h(KEYS[1], 'owner_node_id') ~= ARGV[4]
   or h(KEYS[1], 'owner_boot_id') ~= ARGV[5]
   or h(KEYS[1], 'owner_session_id') ~= ARGV[6] then return {'stale'} end
redis.call('HSET', KEYS[1], 'owner_deployment_incarnation', '', 'owner_node_id', '', 'owner_boot_id', '', 'owner_session_id', '', 'owner_expires_at_us', '')
return {'ok'}
"#;

const SCRIPT_CURRENT_OWNER: &str = r#"
local function h(key, field)
  return redis.call('HGET', key, field) or ''
end
if redis.call('GET', KEYS[2]) ~= ARGV[1] then return {'incarnation'} end
if redis.call('GET', KEYS[3]) ~= ARGV[2] then return {'authority'} end
if h(KEYS[1], 'active') ~= '1' then return {'none'} end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local expiry = tonumber(h(KEYS[1], 'owner_expires_at_us'))
if not expiry or expiry <= now then return {'none'} end
return {'ok', h(KEYS[1], 'owner_node_id'), h(KEYS[1], 'owner_boot_id'), h(KEYS[1], 'owner_session_id'), h(KEYS[1], 'owner_epoch'), h(KEYS[1], 'owner_expires_at_us')}
"#;

const SCRIPT_SEED_CREDENTIAL: &str = r#"
local existing = redis.call('GET', KEYS[2])
if existing and existing ~= KEYS[1] then return {'conflict'} end
redis.call('HSET', KEYS[1], 'tenant_id', ARGV[1], 'device_id', ARGV[2], 'credential_id', ARGV[3], 'spki_fingerprint', ARGV[4], 'serial', ARGV[5], 'not_before_us', ARGV[6], 'expires_at_us', ARGV[7], 'revoked_at_us', ARGV[8], 'active', ARGV[9])
redis.call('SET', KEYS[2], KEYS[1])
redis.call('SADD', KEYS[3], ARGV[3])
return {'ok'}
"#;

#[cfg(test)]
mod tests {
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

    use super::{is_fixture_namespace, key_component};
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
}
