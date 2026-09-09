use crate::error::{HarnessError, Result};
use redis::Client;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

const REDIS_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const MARKER_TTL_SECONDS: u64 = 60 * 60;
const SCAN_COUNT: u64 = 128;
// RedisCatalog accepts namespaces up to 96 bytes and its guarded fixture
// cleanup recognizes `-fixture-` namespaces. Keep room for that marker and
// the complete UUID suffix.
const MAX_NAMESPACE_PREFIX_BYTES: usize = 55;

/// Options for one isolated Redis namespace.
#[derive(Debug, Clone)]
pub struct RedisLeaseOptions {
    /// Redis URL. If omitted, `TEST_REDIS_URL` is read.
    pub redis_url: Option<String>,
    /// Human-readable prefix for the generated namespace. The suffix is
    /// always random, so concurrent harness runs cannot share keys.
    pub namespace_prefix: Option<String>,
}

impl Default for RedisLeaseOptions {
    fn default() -> Self {
        Self {
            redis_url: None,
            namespace_prefix: Some("m1-fixture".to_owned()),
        }
    }
}

/// A per-run Redis namespace lease.
///
/// The lease never calls `FLUSHDB`. Cleanup scans only keys below the
/// generated namespace prefix and removes them in bounded `UNLINK` batches.
/// Call [`RedisLease::close`] for deterministic cleanup; `Drop` schedules the
/// same bounded cleanup when a Tokio runtime is still alive.
pub struct RedisLease {
    client: Option<Client>,
    redis_url: String,
    namespace: String,
    run_id: Uuid,
}

impl std::fmt::Debug for RedisLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisLease")
            .field("namespace", &self.namespace)
            .field("run_id", &self.run_id)
            .finish_non_exhaustive()
    }
}

impl RedisLease {
    /// Connect to Redis, verify the service, and reserve a unique marker key.
    pub async fn open(options: RedisLeaseOptions) -> Result<Self> {
        let redis_url = options
            .redis_url
            .or_else(|| std::env::var("TEST_REDIS_URL").ok())
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| HarnessError::MissingRedisUrl {
                env_var: "TEST_REDIS_URL",
                guidance: "Start the CI Redis service and export TEST_REDIS_URL, for example `redis://127.0.0.1:6379/`. The M1 suite fails closed when this is absent.".to_owned(),
            })?;
        let client =
            Client::open(redis_url.clone()).map_err(|error| HarnessError::InvalidRedisUrl {
                message: error.to_string(),
            })?;
        let namespace = make_namespace_name(
            options.namespace_prefix.as_deref().unwrap_or("m1-fixture"),
            Uuid::new_v4(),
        );
        let run_id = Uuid::new_v4();

        let mut connection = timeout(
            REDIS_OPERATION_TIMEOUT,
            client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_| HarnessError::Timeout("connecting to TEST_REDIS_URL timed out".to_owned()))?
        .map_err(|error| redis_error("connecting to TEST_REDIS_URL", error))?;
        let _: String = timeout(
            REDIS_OPERATION_TIMEOUT,
            redis::cmd("PING").query_async(&mut connection),
        )
        .await
        .map_err(|_| HarnessError::Timeout("Redis PING timed out".to_owned()))?
        .map_err(|error| redis_error("Redis PING", error))?;

        let marker = marker_key(&namespace);
        let created: Option<String> = timeout(
            REDIS_OPERATION_TIMEOUT,
            redis::cmd("SET")
                .arg(&marker)
                .arg(run_id.to_string())
                .arg("NX")
                .arg("EX")
                .arg(MARKER_TTL_SECONDS)
                .query_async(&mut connection),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout("reserving Redis fixture namespace timed out".to_owned())
        })?
        .map_err(|error| redis_error("reserving Redis fixture namespace", error))?;
        if created.is_none() {
            return Err(HarnessError::Redis(
                "random Redis fixture namespace unexpectedly already exists".to_owned(),
            ));
        }

        Ok(Self {
            client: Some(client),
            redis_url,
            namespace,
            run_id,
        })
    }

    /// The configured Redis URL. Credentials are never included in Debug
    /// output, but callers may pass this directly to the production catalog.
    pub fn redis_url(&self) -> &str {
        &self.redis_url
    }

    /// The random namespace passed to `RedisCatalog::connect`.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn run_id(&self) -> Uuid {
        self.run_id
    }

    /// Return a key below this lease's namespace after validating its suffix.
    pub fn qualified_key(&self, suffix: &str) -> Result<String> {
        if !is_safe_key_suffix(suffix) {
            return Err(HarnessError::InvalidInput(format!(
                "Redis key suffix must contain only letters, digits, '.', '-', or '_': {suffix:?}"
            )));
        }
        Ok(format!("{}:{suffix}", self.namespace))
    }

    /// Drop every key owned by this namespace using bounded SCAN + UNLINK.
    pub async fn close(mut self) -> Result<()> {
        let Some(client) = self.client.take() else {
            return Ok(());
        };
        timeout(
            REDIS_OPERATION_TIMEOUT,
            cleanup_namespace(client, self.namespace.clone()),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "cleaning Redis fixture namespace {} timed out",
                self.namespace
            ))
        })??;
        Ok(())
    }
}

impl Drop for RedisLease {
    fn drop(&mut self) {
        let Some(client) = self.client.take() else {
            return;
        };
        let namespace = self.namespace.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            eprintln!(
                "tunnel-test-harness Redis cleanup not scheduled for namespace {namespace}: no Tokio runtime; call RedisLease::close before dropping"
            );
            return;
        };
        handle.spawn(async move {
            let result = timeout(
                REDIS_OPERATION_TIMEOUT,
                cleanup_namespace(client, namespace.clone()),
            )
            .await
            .map_err(|_| {
                HarnessError::Timeout(format!(
                    "cleaning Redis fixture namespace {namespace} timed out"
                ))
            })
            .and_then(|result| result);
            if let Err(error) = result {
                eprintln!("tunnel-test-harness Redis cleanup failed: {error}");
            }
        });
    }
}

async fn cleanup_namespace(client: Client, namespace: String) -> Result<()> {
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|error| redis_error("connecting for Redis fixture cleanup", error))?;
    // RedisCatalog namespaces keys below `tunnel-catalog:<namespace>:` while
    // the lease marker and any future harness-owned keys use
    // `<namespace>:`.  Both patterns are derived solely from this random
    // namespace; no database-wide flush is ever used.
    for pattern in [
        format!("{namespace}:*"),
        format!("tunnel-catalog:{namespace}:*"),
    ] {
        let mut cursor = 0_u64;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(SCAN_COUNT)
                .query_async(&mut connection)
                .await
                .map_err(|error| redis_error("scanning Redis fixture namespace", error))?;
            for batch in keys.chunks(64) {
                if batch.is_empty() {
                    continue;
                }
                let mut command = redis::cmd("UNLINK");
                for key in batch {
                    command.arg(key);
                }
                let _: u64 = command
                    .query_async(&mut connection)
                    .await
                    .map_err(|error| redis_error("unlinking Redis fixture keys", error))?;
            }
            if next_cursor == 0 {
                break;
            }
            cursor = next_cursor;
        }
    }
    Ok(())
}

fn marker_key(namespace: &str) -> String {
    format!("{namespace}:__harness_run")
}

fn make_namespace_name(prefix: &str, run_id: Uuid) -> String {
    let mut normalized = prefix
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    if normalized.is_empty() || !normalized.as_bytes()[0].is_ascii_alphabetic() {
        normalized.insert_str(0, "at_");
    }
    normalized.truncate(MAX_NAMESPACE_PREFIX_BYTES);
    if !normalized.contains("-fixture") {
        normalized.push_str("-fixture");
    }
    format!("{normalized}-{}", run_id.simple())
}

fn is_safe_key_suffix(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn redis_error(context: &str, error: redis::RedisError) -> HarnessError {
    HarnessError::Redis(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{is_safe_key_suffix, make_namespace_name};
    use uuid::Uuid;

    #[test]
    fn namespace_is_unique_and_safe() {
        let name = make_namespace_name("M1 run", Uuid::nil());
        assert!(name.starts_with("m1_run-"));
        assert!(name.contains("-fixture-"));
        assert!(name.ends_with("-00000000000000000000000000000000"));
        assert!(name.bytes().all(|byte| byte.is_ascii() && byte != b' '));
    }

    #[test]
    fn key_suffix_rejects_patterns_and_commands() {
        assert!(is_safe_key_suffix("device-1.echo"));
        assert!(!is_safe_key_suffix(""));
        assert!(!is_safe_key_suffix("foo:*"));
        assert!(!is_safe_key_suffix("foo DEL"));
    }

    #[test]
    fn namespace_keeps_full_uuid_within_catalog_limit() {
        let name = make_namespace_name(&"prefix".repeat(200), Uuid::nil());
        assert!(name.len() <= 96);
        assert!(name.ends_with("-00000000000000000000000000000000"));
    }
}
