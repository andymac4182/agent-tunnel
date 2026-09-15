//! Live-catalog Redis process restart acceptance (M7-C06).
//!
//! `scripts/m7-redis-lane-restart-verify.sh` owns one pinned, loopback-only
//! Redis container on a fixed host port and restarts *that* process while this
//! command keeps a single [`RedisCatalog`] alive across the boundary.  The
//! catalog's authority lanes therefore meet a genuinely new Redis `run_id` on
//! a real socket rather than a fake authority: the command that observes the
//! severed connection fails closed without replay, and every later command
//! repeats the bounded PING/INFO identity check, sees the new `run_id` and is
//! refused with the typed [`CatalogError::Conflict`] rather than silently
//! resuming against a primary the catalog never verified.
//!
//! The harness never starts, stops or restarts Redis.  It signals the script
//! through a small synthetic handshake file, which carries only the two
//! literal words below; no identifier, credential or payload is written to it.
//! Every assertion is on a live catalog against a live Redis process, and all
//! reported evidence is payload-free.

use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use chrono::Utc;
use tunnel_catalog::{AuthenticatedConsumer, Catalog, CatalogError, OwnerClaim, RedisCatalog};

use crate::redis_restart::restart_fixture;

/// Written by this command once its live catalog is verified.
const HANDSHAKE_CONNECTED: &str = "connected";
/// Written by the owning script once the Redis process has restarted.
const HANDSHAKE_RESTARTED: &str = "restarted";
/// Bound on the script's container restart, measured from the connected
/// signal.
const RESTART_WAIT: Duration = Duration::from_secs(180);
const HANDSHAKE_POLL: Duration = Duration::from_millis(100);
/// Commands issued on the live catalog after the restart.  The first one may
/// be the discovering failure; the lane must refuse every remaining one with
/// the typed conflict and never return a value.
const POST_RESTART_ATTEMPTS: usize = 12;
const POST_RESTART_SPACING: Duration = Duration::from_millis(250);
/// Bounded attempts for the freshly connected catalog's control read while a
/// just-restarted primary finishes loading its append-only file.
const FRESH_READ_ATTEMPTS: usize = 20;
/// The typed conflict label the catalog returns for a changed primary.
const RUN_ID_CONFLICT: &str = "Redis server run id";

#[derive(Debug)]
pub enum RedisLaneRestartError {
    Catalog(CatalogError),
    Io(io::Error),
    Assertion(String),
    Timeout(String),
}

impl fmt::Display for RedisLaneRestartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(error) => write!(formatter, "catalog operation failed: {error:?}"),
            Self::Io(error) => write!(formatter, "handshake I/O failed: {error}"),
            Self::Assertion(message) => formatter.write_str(message),
            Self::Timeout(message) => write!(formatter, "bounded wait expired: {message}"),
        }
    }
}

impl std::error::Error for RedisLaneRestartError {}

impl From<CatalogError> for RedisLaneRestartError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

impl From<io::Error> for RedisLaneRestartError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

type Result<T> = std::result::Result<T, RedisLaneRestartError>;

/// How one post-restart command on the live catalog ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaneOutcome {
    /// The catalog answered.  After a restart to a different `run_id` this is
    /// a silent resume and is never allowed.
    Served,
    /// The command that observed the severed connection failed closed
    /// without replay.
    FailedClosed,
    /// The lane reconnected, repeated its identity check and refused the
    /// changed primary with the typed conflict.
    RunIdConflict,
    /// Any other typed catalog outcome, kept distinct so it cannot be counted
    /// as the conflict.
    Other,
}

impl LaneOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::FailedClosed => "failed_closed",
            Self::RunIdConflict => "run_id_conflict",
            Self::Other => "other",
        }
    }
}

fn classify(outcome: &std::result::Result<Option<OwnerClaim>, CatalogError>) -> LaneOutcome {
    match outcome {
        Ok(_) => LaneOutcome::Served,
        Err(CatalogError::Conflict(label)) if label.contains(RUN_ID_CONFLICT) => {
            LaneOutcome::RunIdConflict
        }
        Err(CatalogError::Database(_)) => LaneOutcome::FailedClosed,
        Err(_) => LaneOutcome::Other,
    }
}

/// Payload-free evidence for one live-catalog restart boundary.
#[derive(Debug)]
pub struct RedisLaneRestartEvidence {
    pub run_id_before: String,
    pub run_id_after: String,
    pub served_before_restart: bool,
    pub outcomes: Vec<LaneOutcomeRecord>,
    pub first_conflict_attempt: usize,
    pub fresh_catalog_served_after_restart: bool,
}

#[derive(Debug)]
pub struct LaneOutcomeRecord {
    attempt: usize,
    outcome: LaneOutcome,
}

impl RedisLaneRestartEvidence {
    fn validate(&self) -> Result<()> {
        if self.run_id_before.is_empty() || self.run_id_after.is_empty() {
            return Err(RedisLaneRestartError::Assertion(
                "the Redis primary did not report a run identifier on both sides of the restart"
                    .into(),
            ));
        }
        if self.run_id_before == self.run_id_after {
            return Err(RedisLaneRestartError::Assertion(
                "the Redis process did not restart: the primary kept its run identifier".into(),
            ));
        }
        if !self.served_before_restart {
            return Err(RedisLaneRestartError::Assertion(
                "the live catalog did not serve a read before the restart boundary".into(),
            ));
        }
        if self
            .outcomes
            .iter()
            .any(|record| record.outcome == LaneOutcome::Served)
        {
            return Err(RedisLaneRestartError::Assertion(
                "the live catalog served a read from a primary whose run identifier it never verified"
                    .into(),
            ));
        }
        if self
            .outcomes
            .iter()
            .any(|record| record.outcome == LaneOutcome::Other)
        {
            return Err(RedisLaneRestartError::Assertion(
                "a post-restart command returned an outcome that is not the typed run-identifier conflict"
                    .into(),
            ));
        }
        if self.first_conflict_attempt == 0 {
            return Err(RedisLaneRestartError::Assertion(
                "the live catalog never refused the restarted primary with its typed run-identifier conflict"
                    .into(),
            ));
        }
        if self.first_conflict_attempt > 2 {
            return Err(RedisLaneRestartError::Assertion(format!(
                "the typed run-identifier conflict did not arrive on the command after the discovering failure (first conflict at attempt {})",
                self.first_conflict_attempt
            )));
        }
        if self
            .outcomes
            .iter()
            .skip(self.first_conflict_attempt - 1)
            .any(|record| record.outcome != LaneOutcome::RunIdConflict)
        {
            return Err(RedisLaneRestartError::Assertion(
                "the live catalog stopped refusing the changed primary after its first typed conflict"
                    .into(),
            ));
        }
        if !self.fresh_catalog_served_after_restart {
            return Err(RedisLaneRestartError::Assertion(
                "a freshly connected catalog could not read the seeded authorization back from the restarted primary, so the refusal was not identity-specific"
                    .into(),
            ));
        }
        Ok(())
    }

    /// One bounded, payload-free line naming the two run identifiers and the
    /// exact per-command outcome sequence.
    pub fn evidence_line(&self) -> String {
        let sequence = self
            .outcomes
            .iter()
            .map(|record| format!("{}:{}", record.attempt, record.outcome.as_str()))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "m7-redis-lane-restart run_id_before={} run_id_after={} served_before_restart={} attempts={} first_conflict_attempt={} outcomes={} fresh_catalog_served_after_restart={}",
            self.run_id_before,
            self.run_id_after,
            self.served_before_restart,
            self.outcomes.len(),
            self.first_conflict_attempt,
            sequence,
            self.fresh_catalog_served_after_restart,
        )
    }
}

/// Read the primary's `run_id` on a throwaway connection.  This is evidence
/// only: the assertions below are made by the live catalog's own lanes.
async fn read_run_id(redis_url: &str) -> Result<String> {
    let client = redis::Client::open(redis_url).map_err(|error| {
        RedisLaneRestartError::Assertion(format!("Redis URL is not usable: {error}"))
    })?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|error| {
            RedisLaneRestartError::Assertion(format!("reading the primary identity: {error}"))
        })?;
    let info: String = redis::cmd("INFO")
        .arg("server")
        .query_async(&mut connection)
        .await
        .map_err(|error| {
            RedisLaneRestartError::Assertion(format!("reading the primary identity: {error}"))
        })?;
    info.lines()
        .find_map(|line| line.trim().strip_prefix("run_id:"))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            RedisLaneRestartError::Assertion("the Redis primary reported no run identifier".into())
        })
}

fn write_handshake(path: &Path, value: &str) -> Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, value.as_bytes())?;
    fs::rename(temporary, path)?;
    Ok(())
}

async fn wait_for_handshake(path: &Path, expected: &str, bound: Duration) -> Result<()> {
    let deadline = Instant::now() + bound;
    loop {
        if let Ok(contents) = fs::read_to_string(path)
            && contents.trim() == expected
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(RedisLaneRestartError::Timeout(format!(
                "the owning script did not signal `{expected}` within {} seconds",
                bound.as_secs()
            )));
        }
        tokio::time::sleep(HANDSHAKE_POLL).await;
    }
}

/// Drive one live-catalog Redis process restart and return its evidence.
pub async fn run(
    redis_url: &str,
    namespace: &str,
    handshake_file: impl AsRef<Path>,
) -> Result<RedisLaneRestartEvidence> {
    let handshake: PathBuf = handshake_file.as_ref().to_path_buf();
    let run_id_before = read_run_id(redis_url).await?;

    // One live catalog is built here and is never rebuilt: every post-restart
    // assertion below is made through these same authority lanes.
    let mut catalog = RedisCatalog::connect(redis_url, namespace).await?;
    // Owner reads are fenced by an activated deployment incarnation, exactly
    // as a relay process activates its own at startup.
    let incarnation = format!("m7-lane-restart-{namespace}");
    catalog.configure_deployment_incarnation(&incarnation)?;
    catalog.activate_deployment_incarnation().await?;
    let now = Utc::now();
    let fixture = restart_fixture(now);
    let tenant_id = fixture.tenants[0].tenant_id;
    let principal_id = fixture.users[0].user_id;
    let device_id = fixture.devices[0].device_id;
    let service_id = fixture.services[0].service_id;
    catalog.seed_fixture(&fixture).await?;
    let principal = AuthenticatedConsumer {
        tenant_id,
        principal_id,
    };
    if catalog
        .authorize(&principal, device_id, service_id, now, Utc::now())
        .await?
        .is_none()
    {
        return Err(RedisLaneRestartError::Assertion(
            "the live catalog did not return its seeded authorization before the restart".into(),
        ));
    }
    let served_before_restart = catalog
        .current_owner(tenant_id, device_id, Utc::now())
        .await
        .map(|owner| owner.is_none())
        .map_err(RedisLaneRestartError::Catalog)?;

    write_handshake(&handshake, HANDSHAKE_CONNECTED)?;
    wait_for_handshake(&handshake, HANDSHAKE_RESTARTED, RESTART_WAIT).await?;

    let run_id_after = read_run_id(redis_url).await?;

    let mut outcomes = Vec::with_capacity(POST_RESTART_ATTEMPTS);
    let mut first_conflict_attempt = 0usize;
    for attempt in 1..=POST_RESTART_ATTEMPTS {
        let outcome = classify(
            &catalog
                .current_owner(tenant_id, device_id, Utc::now())
                .await,
        );
        if outcome == LaneOutcome::RunIdConflict && first_conflict_attempt == 0 {
            first_conflict_attempt = attempt;
        }
        outcomes.push(LaneOutcomeRecord { attempt, outcome });
        tokio::time::sleep(POST_RESTART_SPACING).await;
    }

    // A catalog connected *after* the restart verifies the new primary at
    // startup and serves it normally, so the refusal above is specific to the
    // identity the first catalog verified, not a client that stopped working.
    // The seeded authorization it reads back also crossed the restart on the
    // container's append-only file.
    let fresh = RedisCatalog::connect(redis_url, namespace).await?;
    let mut fresh_catalog_served_after_restart = false;
    for _ in 0..FRESH_READ_ATTEMPTS {
        let at = Utc::now();
        if matches!(
            fresh
                .authorize(&principal, device_id, service_id, at, Utc::now())
                .await,
            Ok(Some(_))
        ) {
            fresh_catalog_served_after_restart = true;
            break;
        }
        tokio::time::sleep(POST_RESTART_SPACING).await;
    }

    let evidence = RedisLaneRestartEvidence {
        run_id_before,
        run_id_after,
        served_before_restart,
        outcomes,
        first_conflict_attempt,
        fresh_catalog_served_after_restart,
    };
    evidence.validate()?;
    Ok(evidence)
}
