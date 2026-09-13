//! Staged full-namespace reader for recovery.
//!
//! The Redis I/O is separate from the schema owner: Redis applies bounded
//! reads, while `validate_observed_catalog` decides which keys are durable,
//! ephemeral, orphaned, or unknown and owns canonical encoding.

use std::collections::BTreeSet;

use redis::aio::MultiplexedConnection;

use crate::{
    CatalogError,
    redis::recovery_schema::{
        ObservedRedisKey, ObservedRedisType, ObservedRedisValue, ValidatedCatalogSnapshot,
        validate_observed_catalog,
    },
};

use super::RedisCatalog;
use super::recovery::{
    MAX_RECOVERY_INDEX_MEMBERS, MAX_RECOVERY_KEYS, MAX_RECOVERY_VALUE_BYTES, exec_probe,
    live_redis_run_id, query_command, query_pipeline, recovery_root_keys, unwatch_best_effort,
    watch_keys,
};

const MAX_SCAN_BATCH_KEYS: usize = 512;
const MAX_RECOVERY_VALUE_BYTES_TOTAL: usize = 4 * 1024 * 1024;

const SCRIPT_SCAN_BOUNDED: &str = r#"
local cursor = ARGV[1]
local pattern = ARGV[2]
local max_keys = tonumber(ARGV[3])
local max_key_bytes = tonumber(ARGV[4])
local max_batch_bytes = tonumber(ARGV[5])
local count = ARGV[6]
local result = redis.call('SCAN', cursor, 'MATCH', pattern, 'COUNT', count)
local keys = result[2]
if #keys > max_keys then return {'bound'} end
local bytes = 0
local response = {'ok', result[1]}
for _, key in ipairs(keys) do
  if #key == 0 or #key > max_key_bytes then return {'bound'} end
  bytes = bytes + #key
  if bytes > max_batch_bytes then return {'bound'} end
  response[#response + 1] = key
end
return response
"#;

const SCRIPT_READ_HASH_BOUNDED: &str = r#"
local max_fields = tonumber(ARGV[1])
local max_bytes = tonumber(ARGV[2])
local max_value = tonumber(ARGV[3])
if redis.call('EXISTS', KEYS[1]) == 0 then return {'missing'} end
local count = redis.call('HLEN', KEYS[1])
if count > max_fields then return {'bound'} end
local values = redis.call('HGETALL', KEYS[1])
if #values % 2 ~= 0 then return {'invalid'} end
local total = 0
for index = 1, #values do
  if #values[index] > max_value then return {'bound'} end
  total = total + #values[index]
  if total > max_bytes then return {'bound'} end
end
local result = {'ok'}
for index = 1, #values do result[#result + 1] = values[index] end
return result
"#;

const SCRIPT_READ_SET_BOUNDED: &str = r#"
local max_members = tonumber(ARGV[1])
local max_bytes = tonumber(ARGV[2])
local max_value = tonumber(ARGV[3])
if redis.call('EXISTS', KEYS[1]) == 0 then return {'missing'} end
local count = redis.call('SCARD', KEYS[1])
if count > max_members then return {'bound'} end
local values = redis.call('SMEMBERS', KEYS[1])
local total = 0
for index = 1, #values do
  if #values[index] > max_value then return {'bound'} end
  total = total + #values[index]
  if total > max_bytes then return {'bound'} end
end
local result = {'ok'}
for index = 1, #values do result[#result + 1] = values[index] end
return result
"#;

const SCRIPT_READ_STRING_BOUNDED: &str = r#"
local max_bytes = tonumber(ARGV[1])
local max_value = tonumber(ARGV[2])
if redis.call('EXISTS', KEYS[1]) == 0 then return {'missing'} end
local length = redis.call('STRLEN', KEYS[1])
if length > max_value or length > max_bytes then return {'bound'} end
local value = redis.call('GET', KEYS[1])
if not value then return {'missing'} end
if #value > max_value or #value > max_bytes then return {'bound'} end
return {'ok', value}
"#;

const SCRIPT_READ_ZSET_BOUNDED: &str = r#"
local max_members = tonumber(ARGV[1])
local max_bytes = tonumber(ARGV[2])
local max_value = tonumber(ARGV[3])
if redis.call('EXISTS', KEYS[1]) == 0 then return {'missing'} end
local count = redis.call('ZCARD', KEYS[1])
if count > max_members then return {'bound'} end
local values = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
if #values % 2 ~= 0 then return {'invalid'} end
local total = 0
for index = 1, #values do
  if #values[index] > max_value then return {'bound'} end
  total = total + #values[index]
  if total > max_bytes then return {'bound'} end
end
local result = {'ok'}
for index = 1, #values do result[#result + 1] = values[index] end
return result
"#;

/// A stable full-namespace read, plus the live concurrency fence values that
/// are deliberately kept outside the signed catalog digest.
pub(super) struct FullObservation {
    pub snapshot: ValidatedCatalogSnapshot,
    pub redis_run_id: String,
    pub catalog_generation: String,
}

/// Read every namespace key through one physical Redis connection. The first
/// WATCH covers the generation fence before SCAN starts; all keys discovered
/// by SCAN are then watched before any value is materialized. A second SCAN
/// catches key creation/deletion races that occurred between WATCH and read.
pub(super) async fn collect_full_observation(
    catalog: &RedisCatalog,
    connection: &mut MultiplexedConnection,
    finish_watch: bool,
) -> Result<Option<FullObservation>, CatalogError> {
    let run_id = live_redis_run_id(connection).await?;
    let generation = read_catalog_generation(catalog, connection).await?;
    let roots = recovery_root_keys(catalog);
    watch_keys(connection, &roots).await?;

    let keys = scan_namespace(connection, &catalog.prefix).await?;
    let mut watched = roots.clone();
    watched.extend(keys.iter().cloned());
    watched.sort();
    watched.dedup();
    watch_keys(connection, &watched).await?;

    let metadata = read_key_metadata(connection, &keys).await?;
    let Some(observed) = read_observed_values(connection, &metadata).await? else {
        unwatch_best_effort(connection).await;
        return Ok(None);
    };

    let ending_keys = scan_namespace(connection, &catalog.prefix).await?;
    if ending_keys != keys {
        unwatch_best_effort(connection).await;
        return Ok(None);
    }
    let ending_run_id = live_redis_run_id(connection).await?;
    let ending_generation = read_catalog_generation(catalog, connection).await?;
    if ending_run_id != run_id || ending_generation != generation {
        unwatch_best_effort(connection).await;
        return Ok(None);
    }

    let snapshot = validate_observed_catalog(&catalog.prefix, &observed)
        .map_err(|error| CatalogError::Serialization(error.to_string()))?;
    let snapshot_generation = snapshot
        .catalog_generation()
        .unwrap_or_default()
        .to_string();
    if snapshot_generation != generation {
        unwatch_best_effort(connection).await;
        return Ok(None);
    }
    if finish_watch && !exec_probe(connection).await? {
        unwatch_best_effort(connection).await;
        return Ok(None);
    }
    Ok(Some(FullObservation {
        snapshot,
        redis_run_id: run_id,
        catalog_generation: generation,
    }))
}

/// Bounded scan of the selected namespace. Redis `COUNT` is a hint, so every
/// returned batch is checked before it is appended to the bounded key set.
async fn scan_namespace(
    connection: &mut MultiplexedConnection,
    prefix: &str,
) -> Result<Vec<String>, CatalogError> {
    let mut cursor = 0_u64;
    let mut keys = BTreeSet::new();
    let mut key_bytes = 0_usize;
    let pattern = format!("{prefix}*");
    loop {
        let mut command = redis::cmd("EVAL");
        command
            .arg(SCRIPT_SCAN_BOUNDED)
            .arg(0_i64)
            .arg(cursor)
            .arg(&pattern)
            .arg(MAX_SCAN_BATCH_KEYS as i64)
            .arg(MAX_RECOVERY_VALUE_BYTES as i64)
            .arg(MAX_RECOVERY_VALUE_BYTES_TOTAL as i64)
            .arg(MAX_SCAN_BATCH_KEYS as i64);
        let reply: Vec<String> = query_command(connection, command).await?;
        if reply.first().map(String::as_str) == Some("bound") {
            return Err(CatalogError::Conflict(
                "recovery namespace scan batch bound",
            ));
        }
        if reply.first().map(String::as_str) != Some("ok") || reply.len() < 2 {
            return Err(CatalogError::Serialization(
                "recovery namespace scan reply shape".into(),
            ));
        }
        let next = reply[1]
            .parse::<u64>()
            .map_err(|_| CatalogError::Serialization("recovery namespace scan cursor".into()))?;
        let batch = &reply[2..];
        if batch.len() > MAX_SCAN_BATCH_KEYS {
            return Err(CatalogError::Conflict(
                "recovery namespace scan batch bound",
            ));
        }
        for key in batch {
            if key.len() > MAX_RECOVERY_VALUE_BYTES || key.is_empty() || !key.starts_with(prefix) {
                return Err(CatalogError::Serialization(
                    "recovery namespace key shape".into(),
                ));
            }
            key_bytes = key_bytes
                .checked_add(key.len())
                .ok_or(CatalogError::Conflict("recovery namespace key bound"))?;
            if key_bytes > MAX_RECOVERY_VALUE_BYTES_TOTAL {
                return Err(CatalogError::Conflict("recovery namespace key bound"));
            }
            keys.insert(key.clone());
            if keys.len() > MAX_RECOVERY_KEYS {
                return Err(CatalogError::Conflict("recovery namespace key bound"));
            }
        }
        if next == 0 {
            break;
        }
        cursor = next;
    }
    Ok(keys.into_iter().collect())
}

/// Fetch TYPE and PTTL only. The value commands are deliberately separate so
/// HGETALL/SMEMBERS/ZRANGE never run before their cardinality bound is known.
async fn read_key_metadata(
    connection: &mut MultiplexedConnection,
    keys: &[String],
) -> Result<Vec<(String, String, i64)>, CatalogError> {
    let mut pipeline = redis::pipe();
    for key in keys {
        pipeline.cmd("TYPE").arg(key);
        pipeline.cmd("PTTL").arg(key);
    }
    let replies: Vec<redis::Value> = query_pipeline(connection, pipeline).await?;
    if replies.len() != keys.len().saturating_mul(2) {
        return Err(CatalogError::Serialization(
            "recovery namespace metadata shape".into(),
        ));
    }
    let mut metadata = Vec::with_capacity(keys.len());
    let mut replies = replies.into_iter();
    for key in keys {
        let redis_type_value = replies.next().ok_or_else(|| {
            CatalogError::Serialization("recovery namespace metadata shape".into())
        })?;
        let ttl_value = replies.next().ok_or_else(|| {
            CatalogError::Serialization("recovery namespace metadata shape".into())
        })?;
        let redis_type = redis::from_redis_value::<String>(redis_type_value)
            .map_err(|_| CatalogError::Serialization("recovery namespace type".into()))?;
        let ttl_ms = redis::from_redis_value::<i64>(ttl_value)
            .map_err(|_| CatalogError::Serialization("recovery namespace ttl".into()))?;
        if ttl_ms == -2 || redis_type == "none" {
            return Err(CatalogError::Conflict("recovery namespace key disappeared"));
        }
        metadata.push((key.clone(), redis_type, ttl_ms));
    }
    Ok(metadata)
}

async fn read_observed_values(
    connection: &mut MultiplexedConnection,
    metadata: &[(String, String, i64)],
) -> Result<Option<Vec<ObservedRedisKey>>, CatalogError> {
    let mut observed = Vec::with_capacity(metadata.len());
    let mut total_bytes = 0_usize;
    for (key, redis_type, ttl_ms) in metadata {
        add_total_bytes(&mut total_bytes, key.len())?;
        let value = match redis_type.as_str() {
            "hash" => {
                let Some((fields, bytes)) = read_hash(connection, key, total_bytes).await? else {
                    return Ok(None);
                };
                add_total_bytes(&mut total_bytes, bytes)?;
                ObservedRedisValue::Hash(fields)
            }
            "set" => {
                let Some((members, bytes)) = read_set(connection, key, total_bytes).await? else {
                    return Ok(None);
                };
                add_total_bytes(&mut total_bytes, bytes)?;
                ObservedRedisValue::Set(members)
            }
            "string" => {
                let Some((value, bytes)) = read_string(connection, key, total_bytes).await? else {
                    return Ok(None);
                };
                add_total_bytes(&mut total_bytes, bytes)?;
                ObservedRedisValue::String(value)
            }
            "zset" => {
                let Some((members, bytes)) = read_zset(connection, key, total_bytes).await? else {
                    return Ok(None);
                };
                add_total_bytes(&mut total_bytes, bytes)?;
                ObservedRedisValue::Zset(members)
            }
            _ => {
                return Err(CatalogError::Serialization(
                    "recovery namespace Redis type".into(),
                ));
            }
        };
        observed.push(ObservedRedisKey {
            key: key.clone(),
            redis_type: match redis_type.as_str() {
                "hash" => ObservedRedisType::Hash,
                "set" => ObservedRedisType::Set,
                "string" => ObservedRedisType::String,
                "zset" => ObservedRedisType::Zset,
                _ => unreachable!(),
            },
            ttl_ms: *ttl_ms,
            value,
        });
    }
    Ok(Some(observed))
}

async fn read_hash(
    connection: &mut MultiplexedConnection,
    key: &str,
    total_bytes: usize,
) -> Result<Option<(Vec<(String, String)>, usize)>, CatalogError> {
    let Some(values) = read_bounded_reply(
        connection,
        SCRIPT_READ_HASH_BOUNDED,
        key,
        &[
            MAX_RECOVERY_INDEX_MEMBERS as i64,
            remaining_value_bytes(total_bytes) as i64,
            MAX_RECOVERY_VALUE_BYTES as i64,
        ],
    )
    .await?
    else {
        return Ok(None);
    };
    if !values.len().is_multiple_of(2) {
        return Err(CatalogError::Serialization(
            "recovery hash reply shape".into(),
        ));
    }
    let bytes = reply_bytes(&values)?;
    let mut fields = values
        .chunks_exact(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect::<Vec<_>>();
    fields.sort();
    Ok(Some((fields, bytes)))
}

async fn read_set(
    connection: &mut MultiplexedConnection,
    key: &str,
    total_bytes: usize,
) -> Result<Option<(Vec<String>, usize)>, CatalogError> {
    let Some(values) = read_bounded_reply(
        connection,
        SCRIPT_READ_SET_BOUNDED,
        key,
        &[
            MAX_RECOVERY_INDEX_MEMBERS as i64,
            remaining_value_bytes(total_bytes) as i64,
            MAX_RECOVERY_VALUE_BYTES as i64,
        ],
    )
    .await?
    else {
        return Ok(None);
    };
    let bytes = reply_bytes(&values)?;
    let mut members = values;
    members.sort();
    members.dedup();
    Ok(Some((members, bytes)))
}

async fn read_string(
    connection: &mut MultiplexedConnection,
    key: &str,
    total_bytes: usize,
) -> Result<Option<(String, usize)>, CatalogError> {
    let Some(values) = read_bounded_reply(
        connection,
        SCRIPT_READ_STRING_BOUNDED,
        key,
        &[
            remaining_value_bytes(total_bytes) as i64,
            MAX_RECOVERY_VALUE_BYTES as i64,
        ],
    )
    .await?
    else {
        return Ok(None);
    };
    if values.len() != 1 {
        return Err(CatalogError::Serialization(
            "recovery string reply shape".into(),
        ));
    }
    let value = values
        .into_iter()
        .next()
        .ok_or(CatalogError::Serialization(
            "recovery string reply shape".into(),
        ))?;
    let bytes = value.len();
    Ok(Some((value, bytes)))
}

async fn read_zset(
    connection: &mut MultiplexedConnection,
    key: &str,
    total_bytes: usize,
) -> Result<Option<(Vec<(String, String)>, usize)>, CatalogError> {
    let Some(values) = read_bounded_reply(
        connection,
        SCRIPT_READ_ZSET_BOUNDED,
        key,
        &[
            MAX_RECOVERY_INDEX_MEMBERS as i64,
            remaining_value_bytes(total_bytes) as i64,
            MAX_RECOVERY_VALUE_BYTES as i64,
        ],
    )
    .await?
    else {
        return Ok(None);
    };
    if !values.len().is_multiple_of(2) {
        return Err(CatalogError::Serialization(
            "recovery zset reply shape".into(),
        ));
    }
    let bytes = reply_bytes(&values)?;
    let mut members = values
        .chunks_exact(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect::<Vec<_>>();
    members.sort();
    Ok(Some((members, bytes)))
}

async fn read_bounded_reply(
    connection: &mut MultiplexedConnection,
    script: &str,
    key: &str,
    arguments: &[i64],
) -> Result<Option<Vec<String>>, CatalogError> {
    let mut command = redis::cmd("EVAL");
    command.arg(script).arg(1_i64).arg(key);
    for argument in arguments {
        command.arg(*argument);
    }
    let reply: Vec<String> = query_command(connection, command).await?;
    let Some(marker) = reply.first().map(String::as_str) else {
        return Err(CatalogError::Serialization(
            "recovery bounded reply shape".into(),
        ));
    };
    match marker {
        "missing" => Ok(None),
        "bound" => Err(CatalogError::Conflict("recovery value bound")),
        "invalid" => Err(CatalogError::Serialization(
            "recovery bounded reply shape".into(),
        )),
        "ok" => Ok(Some(reply.into_iter().skip(1).collect())),
        _ => Err(CatalogError::Serialization(
            "recovery bounded reply marker".into(),
        )),
    }
}

fn reply_bytes(values: &[String]) -> Result<usize, CatalogError> {
    values.iter().try_fold(0_usize, |total, value| {
        total
            .checked_add(value.len())
            .ok_or(CatalogError::Conflict("recovery namespace value bound"))
    })
}

fn add_total_bytes(total: &mut usize, amount: usize) -> Result<(), CatalogError> {
    *total = total
        .checked_add(amount)
        .ok_or(CatalogError::Conflict("recovery namespace value bound"))?;
    if *total > MAX_RECOVERY_VALUE_BYTES_TOTAL {
        return Err(CatalogError::Conflict("recovery namespace value bound"));
    }
    Ok(())
}

fn remaining_value_bytes(total: usize) -> usize {
    MAX_RECOVERY_VALUE_BYTES_TOTAL.saturating_sub(total)
}

async fn read_catalog_generation(
    catalog: &RedisCatalog,
    connection: &mut MultiplexedConnection,
) -> Result<String, CatalogError> {
    let mut command = redis::cmd("GET");
    command.arg(catalog.catalog_generation_key());
    let value: Option<String> = query_command(connection, command).await?;
    let Some(value) = value else {
        return Ok("0".into());
    };
    if value.len() > MAX_RECOVERY_VALUE_BYTES {
        return Err(CatalogError::Conflict("recovery generation bound"));
    }
    let generation = value
        .parse::<u64>()
        .map_err(|_| CatalogError::Serialization("recovery generation encoding".into()))?;
    Ok(generation.to_string())
}
