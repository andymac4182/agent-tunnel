//! Bounded durable-catalog observation and approval-gated activation.
//!
//! Each recovery operation owns one physical Redis connection and uses
//! optimistic transactions.
//! The fixed root indexes are watched before any nested index is enumerated;
//! every discovered index and record key is then watched before its value is
//! read.  The final `EXEC` either atomically changes the active incarnation or
//! aborts when a watched catalog key changed.  Redis errors are returned
//! directly: the bounded retry loop only retries a watch conflict and never
//! reconnects or retries after a connection failure.

use std::time::Duration;

use chrono::Utc;
use redis::{FromRedisValue, aio::MultiplexedConnection};

use crate::{
    CatalogError,
    recovery::{VerifiedRecoveryApproval, durable_catalog_digest},
};

use super::recovery_scanner;
use super::{
    REDIS_OPERATION_TIMEOUT, RedisCatalog, datetime_micros, parse_redis_run_id, redis_timeout,
};

const MAX_RECOVERY_ATTEMPTS: usize = 3;
const MAX_RECOVERY_OPERATION_DURATION: Duration = Duration::from_secs(10);
pub(super) const MAX_RECOVERY_KEYS: usize = 16_384;
pub(super) const MAX_RECOVERY_INDEX_MEMBERS: usize = 8_192;
pub(super) const MAX_RECOVERY_VALUE_BYTES: usize = 256 * 1024;

const SCRIPT_ACTIVATE_RECOVERY: &str = r#"
local current = redis.call('GET', KEYS[1])
local current_run = redis.call('GET', KEYS[3])
local current_generation = redis.call('GET', KEYS[4]) or '0'
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local not_before = tonumber(ARGV[4])
local expires_at = tonumber(ARGV[5])
if not not_before or not expires_at then return {'approval_time_invalid'} end
if now < not_before then return {'approval_not_yet_valid'} end
if now > expires_at then return {'approval_expired'} end
if current and current == ARGV[2] and current_run ~= ARGV[3] then return {'mismatch'} end
if current_generation ~= ARGV[6] then return {'generation_mismatch'} end
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
if current and current == ARGV[2] and current_run == ARGV[3] then return {'ok'} end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[3], ARGV[3])
return {'ok'}
"#;

/// A bounded, stable observation of the durable catalog.
///
/// The observation exposes only the digest and bounded counters.  The
/// canonical bytes are retained inside the recovery operation and are never
/// treated as a catalog cache or authorization snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableCatalogObservation {
    catalog_digest: String,
    redis_run_id: String,
    catalog_generation: String,
    key_count: usize,
    byte_count: usize,
}

impl DurableCatalogObservation {
    /// Lower-case SHA-256 of the canonical durable catalog observation.
    pub fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }

    /// The live Redis `INFO server` run identity observed with this digest.
    pub fn redis_run_id(&self) -> &str {
        &self.redis_run_id
    }

    /// The live Redis durable-mutation generation observed with this digest.
    /// This is a concurrency fence only; it is not part of the signed digest
    /// or an external rollback/checkpoint authority.
    pub fn catalog_generation(&self) -> &str {
        &self.catalog_generation
    }

    /// Number of durable keys represented by the observation.
    pub fn key_count(&self) -> usize {
        self.key_count
    }

    /// Number of canonical observation bytes hashed.
    pub fn byte_count(&self) -> usize {
        self.byte_count
    }
}

impl RedisCatalog {
    /// Read a bounded, live durable-catalog digest without activating an
    /// incarnation.  A concurrent mutation causes a bounded retry; a stable
    /// observation is returned only after the same connection's `EXEC` probe
    /// confirms that watched keys did not change.
    pub async fn observe_durable_catalog(&self) -> Result<DurableCatalogObservation, CatalogError> {
        let mut connection = open_recovery_connection(self).await?;
        let result = tokio::time::timeout(MAX_RECOVERY_OPERATION_DURATION, async {
            for _attempt in 0..MAX_RECOVERY_ATTEMPTS {
                let result = collect_observation(self, &mut connection).await;
                match result {
                    Ok(Some(observation)) => return Ok(observation),
                    Ok(None) => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(CatalogError::Conflict(
                "recovery catalog changed during bounded observation",
            ))
        })
        .await;
        match result {
            Ok(result) => {
                if result.is_err() {
                    unwatch_best_effort(&mut connection).await;
                }
                result
            }
            Err(_) => {
                unwatch_best_effort(&mut connection).await;
                Err(CatalogError::Conflict("recovery observation deadline"))
            }
        }
    }

    /// Activate the configured incarnation only after an externally verified
    /// recovery approval matches a fresh durable-catalog digest and live Redis
    /// run identity.  Only watch conflicts are retried, at most three times;
    /// this method never reconnects or retries a Redis connection failure.
    pub async fn activate_deployment_incarnation_with_approval(
        &self,
        approval: &VerifiedRecoveryApproval,
    ) -> Result<(), CatalogError> {
        let incarnation = self.configured_incarnation()?.to_owned();
        if approval.redis_namespace() != self.namespace {
            return Err(CatalogError::Conflict("recovery approval Redis namespace"));
        }
        if approval.deployment_incarnation() != incarnation {
            return Err(CatalogError::Conflict("recovery approval incarnation"));
        }

        let mut connection = open_recovery_connection(self).await?;
        let mut exec_in_flight = false;
        let result = tokio::time::timeout(MAX_RECOVERY_OPERATION_DURATION, async {
            for _attempt in 0..MAX_RECOVERY_ATTEMPTS {
                match activate_once(
                    self,
                    &mut connection,
                    approval,
                    &incarnation,
                    &mut exec_in_flight,
                )
                .await
                {
                    Ok(ActivationResult::Committed) => return Ok(()),
                    Ok(ActivationResult::WatchConflict) => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(CatalogError::Conflict(
                "recovery catalog changed during bounded activation",
            ))
        })
        .await;
        match result {
            Ok(result) => {
                if result.is_err() {
                    unwatch_best_effort(&mut connection).await;
                }
                result
            }
            Err(_) => {
                unwatch_best_effort(&mut connection).await;
                if exec_in_flight {
                    Err(CatalogError::Conflict(
                        "recovery activation outcome unknown",
                    ))
                } else {
                    Err(CatalogError::Conflict("recovery activation deadline"))
                }
            }
        }
    }

    /// Compatibility spelling for callers that name the approval explicitly.
    pub async fn activate_deployment_incarnation_with_recovery_approval(
        &self,
        approval: &VerifiedRecoveryApproval,
    ) -> Result<(), CatalogError> {
        self.activate_deployment_incarnation_with_approval(approval)
            .await
    }
}

enum ActivationResult {
    Committed,
    WatchConflict,
}

async fn open_recovery_connection(
    catalog: &RedisCatalog,
) -> Result<MultiplexedConnection, CatalogError> {
    tokio::time::timeout(
        REDIS_OPERATION_TIMEOUT,
        catalog.client.get_multiplexed_async_connection(),
    )
    .await
    .map_err(|_| redis_timeout())?
    .map_err(CatalogError::Database)
}

async fn collect_observation(
    catalog: &RedisCatalog,
    connection: &mut MultiplexedConnection,
) -> Result<Option<DurableCatalogObservation>, CatalogError> {
    let Some(observation) =
        recovery_scanner::collect_full_observation(catalog, connection, true).await?
    else {
        return Ok(None);
    };
    Ok(Some(observation_from_snapshot(observation)))
}

async fn activate_once(
    catalog: &RedisCatalog,
    connection: &mut MultiplexedConnection,
    approval: &VerifiedRecoveryApproval,
    incarnation: &str,
    exec_in_flight: &mut bool,
) -> Result<ActivationResult, CatalogError> {
    let run_id = live_redis_run_id(connection).await?;
    if run_id != approval.redis_run_id() {
        return Err(CatalogError::Conflict("recovery approval Redis run id"));
    }
    check_approval_window(approval)?;

    let Some(observation) =
        recovery_scanner::collect_full_observation(catalog, connection, false).await?
    else {
        return Ok(ActivationResult::WatchConflict);
    };
    let observed = durable_catalog_digest(observation.snapshot.canonical_bytes());
    if observed != approval.catalog_digest() {
        unwatch_best_effort(connection).await;
        return Err(CatalogError::Conflict("recovery approval catalog digest"));
    }

    if observation.redis_run_id != run_id || observation.redis_run_id != approval.redis_run_id() {
        unwatch_best_effort(connection).await;
        return Err(CatalogError::Conflict("recovery approval Redis run id"));
    }
    check_approval_window(approval)?;

    let not_before = datetime_micros(approval.not_before())?;
    let expires_at = datetime_micros(approval.expires_at())?;
    let mut pipeline = redis::pipe();
    pipeline
        .atomic()
        .cmd("EVAL")
        .arg(SCRIPT_ACTIVATE_RECOVERY)
        .arg(4_i64)
        .arg(catalog.active_incarnation_key())
        .arg(catalog.tenants_index())
        .arg(catalog.redis_run_id_key())
        .arg(catalog.catalog_generation_key())
        .arg(catalog.prefix.clone())
        .arg(incarnation)
        .arg(observation.redis_run_id.clone())
        .arg(not_before.to_string())
        .arg(expires_at.to_string())
        .arg(observation.catalog_generation.clone());
    *exec_in_flight = true;
    let pipeline_result = query_pipeline(connection, pipeline).await;
    *exec_in_flight = false;
    let response: Option<Vec<Vec<String>>> = match pipeline_result {
        Ok(response) => response,
        Err(_error) => {
            unwatch_best_effort(connection).await;
            return Err(CatalogError::Conflict(
                "recovery activation outcome unknown",
            ));
        }
    };
    let Some(mut replies) = response else {
        return Ok(ActivationResult::WatchConflict);
    };
    if replies.len() != 1 {
        return Err(CatalogError::Serialization(
            "invalid recovery activation transaction reply".into(),
        ));
    }
    let reply = replies.pop().unwrap_or_default();
    match reply.first().map(String::as_str) {
        Some("ok") => Ok(ActivationResult::Committed),
        Some("busy") => Err(CatalogError::OwnerBusy),
        Some("bound") => Err(CatalogError::Conflict("owner lease scan bound")),
        Some("mismatch") => Err(CatalogError::Conflict("active deployment incarnation")),
        Some("generation_mismatch") => Ok(ActivationResult::WatchConflict),
        Some("approval_not_yet_valid") => {
            Err(CatalogError::Conflict("recovery approval not yet valid"))
        }
        Some("approval_expired") => Err(CatalogError::Conflict("recovery approval expired")),
        Some("approval_time_invalid") => {
            Err(CatalogError::Conflict("recovery approval time invalid"))
        }
        _ => Err(CatalogError::Conflict(
            "recovery activation outcome unknown",
        )),
    }
}

fn check_approval_window(approval: &VerifiedRecoveryApproval) -> Result<(), CatalogError> {
    let now = Utc::now();
    if now < approval.not_before() {
        return Err(CatalogError::Conflict("recovery approval not yet valid"));
    }
    if now > approval.expires_at() {
        return Err(CatalogError::Conflict("recovery approval expired"));
    }
    Ok(())
}

pub(super) fn recovery_root_keys(catalog: &RedisCatalog) -> Vec<String> {
    let mut keys = vec![
        catalog.active_incarnation_key(),
        catalog.redis_run_id_key(),
        catalog.catalog_generation_key(),
        catalog.tenants_index(),
        catalog.users_index(),
        catalog.identities_index(),
    ];
    keys.sort();
    keys.dedup();
    keys
}

fn observation_from_snapshot(
    observation: recovery_scanner::FullObservation,
) -> DurableCatalogObservation {
    let snapshot = observation.snapshot;
    DurableCatalogObservation {
        catalog_digest: durable_catalog_digest(snapshot.canonical_bytes()),
        redis_run_id: observation.redis_run_id,
        catalog_generation: observation.catalog_generation,
        key_count: snapshot.durable_key_count(),
        byte_count: snapshot.canonical_byte_count(),
    }
}

pub(super) async fn watch_keys(
    connection: &mut MultiplexedConnection,
    keys: &[String],
) -> Result<(), CatalogError> {
    if keys.is_empty() {
        return Err(CatalogError::Conflict("recovery catalog watch roots"));
    }
    let mut command = redis::cmd("WATCH");
    command.arg(keys);
    query_command(connection, command).await
}

pub(super) async fn live_redis_run_id(
    connection: &mut MultiplexedConnection,
) -> Result<String, CatalogError> {
    let mut command = redis::cmd("INFO");
    command.arg("server");
    let info: String = query_command(connection, command).await?;
    parse_redis_run_id(&info)
}

pub(super) async fn exec_probe(
    connection: &mut MultiplexedConnection,
) -> Result<bool, CatalogError> {
    let mut pipeline = redis::pipe();
    pipeline.atomic().cmd("PING");
    let response: Option<Vec<String>> = query_pipeline(connection, pipeline).await?;
    Ok(response
        .as_ref()
        .is_some_and(|reply| reply.len() == 1 && reply[0] == "PONG"))
}

pub(super) async fn unwatch_best_effort(connection: &mut MultiplexedConnection) {
    let _ = tokio::time::timeout(
        REDIS_OPERATION_TIMEOUT,
        redis::cmd("UNWATCH").query_async::<()>(&mut *connection),
    )
    .await;
}

pub(super) async fn query_command<T: FromRedisValue>(
    connection: &mut MultiplexedConnection,
    command: redis::Cmd,
) -> Result<T, CatalogError> {
    tokio::time::timeout(REDIS_OPERATION_TIMEOUT, command.query_async(connection))
        .await
        .map_err(|_| redis_timeout())?
        .map_err(CatalogError::Database)
}

pub(super) async fn query_pipeline<T: FromRedisValue>(
    connection: &mut MultiplexedConnection,
    pipeline: redis::Pipeline,
) -> Result<T, CatalogError> {
    tokio::time::timeout(REDIS_OPERATION_TIMEOUT, pipeline.query_async(connection))
        .await
        .map_err(|_| redis_timeout())?
        .map_err(CatalogError::Database)
}
