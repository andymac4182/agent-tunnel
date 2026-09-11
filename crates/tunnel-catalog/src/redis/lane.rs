//! Verified physical lanes to the Redis authority.
//!
//! The catalog keeps a plain redis-rs `MultiplexedConnection` per lane and
//! never hides a transport failure behind a generic reconnecting pool.  The
//! command that observes the failure returns it, so authorization, ownership
//! and recovery callers keep their fail-closed and unknown-outcome semantics;
//! nothing is replayed and nothing reconnects in the background.  A lane
//! re-establishes its connection only for a *later* command, and only after
//! repeating the bounded PING/INFO identity check used at startup.  A primary
//! whose `run_id` differs from the one the catalog verified when it connected
//! is refused, so a Redis restart, restore or promotion stays an operator
//! recovery event rather than a silent resume.
//!
//! Lanes of one catalog share a loss generation.  When one lane observes a
//! transport loss, every sibling lane probes its own connection with the same
//! startup `PING` before its next caller command: a connection severed by the
//! same event reconnects there instead of failing one more caller closed,
//! while a live connection keeps its place.  The probe is never the caller's
//! command.
//!
//! A lane does not serialize its callers.  The lane lock is held only across
//! the bounded probe or reconnect that verifies the physical connection;
//! every caller then runs its own command on a handle to that multiplexed
//! connection, so concurrent commands pipeline on one socket and the
//! per-command deadline measures the authority's reply, never the time spent
//! waiting behind other callers.  A queueing delay therefore cannot be
//! reported as an authority timeout, while a stalled or severed authority
//! still fails exactly the commands that observed it.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use redis::{FromRedisValue, RedisError, aio::MultiplexedConnection};
use tokio::sync::Mutex;

use super::{REDIS_OPERATION_TIMEOUT, open_verified_connection, redis_timeout};
use crate::{CatalogConnectionError, CatalogError, UnknownWriteCause};

/// The closed conflict label returned when a reconnect reaches a primary
/// whose `run_id` differs from the verified startup identity.
pub(super) const RUN_ID_CONFLICT: &str = "Redis server run id";

/// Transport-loss signal shared by every lane of one catalog.
#[derive(Default)]
pub(super) struct LaneGroup {
    loss_generation: AtomicU64,
}

struct LaneState {
    connection: Option<MultiplexedConnection>,
    /// The group loss generation this connection was last verified against.
    verified_generation: u64,
    /// Advanced whenever the connection slot is cleared or replaced, so a
    /// caller that observed a loss on an older connection cannot release one
    /// that a sibling caller has since re-established.
    connection_generation: u64,
}

pub(super) struct AuthorityLane {
    client: redis::Client,
    expected_run_id: String,
    group: Arc<LaneGroup>,
    state: Mutex<LaneState>,
}

impl AuthorityLane {
    pub(super) fn new(
        client: redis::Client,
        connection: MultiplexedConnection,
        expected_run_id: String,
        group: Arc<LaneGroup>,
    ) -> Self {
        let verified_generation = group.loss_generation.load(Ordering::Acquire);
        Self {
            client,
            expected_run_id,
            group,
            state: Mutex::new(LaneState {
                connection: Some(connection),
                verified_generation,
                connection_generation: 0,
            }),
        }
    }

    /// Run one bounded command on this lane.
    ///
    /// A transport failure releases the lane's connection so the *next*
    /// command reconnects; the failed command itself is never retried and its
    /// error is returned unchanged.
    pub(super) async fn query<T: FromRedisValue>(
        &self,
        command: &redis::Cmd,
    ) -> Result<T, CatalogError> {
        self.execute(
            async |connection| command.query_async::<T>(connection).await,
            DispatchedFailure::Definite,
        )
        .await
    }

    /// Run one owner-affecting write on this lane.
    ///
    /// Once the command has been dispatched, a lost reply no longer proves
    /// the write failed: the script may have committed on the authority
    /// before the reply deadline passed or the connection was severed.  Those
    /// two failures are reported as the typed
    /// [`CatalogError::WriteOutcomeUnknown`] so the caller can stay unready
    /// until it re-reads the authority; a failure before dispatch (lane
    /// admission) and an actual authority reply keep their definite shapes.
    /// The write itself is never replayed.
    pub(super) async fn query_owner_write<T: FromRedisValue>(
        &self,
        command: &redis::Cmd,
    ) -> Result<T, CatalogError> {
        self.execute(
            async |connection| command.query_async::<T>(connection).await,
            DispatchedFailure::Unknown,
        )
        .await
    }

    /// Run one bounded pipeline on this lane with the same failure contract
    /// as [`Self::query`].
    pub(super) async fn query_pipeline<T: FromRedisValue>(
        &self,
        pipeline: &redis::Pipeline,
    ) -> Result<T, CatalogError> {
        self.execute(
            async |connection| pipeline.query_async::<T>(connection).await,
            DispatchedFailure::Definite,
        )
        .await
    }

    async fn execute<T>(
        &self,
        operation: impl AsyncFnOnce(&mut MultiplexedConnection) -> Result<T, RedisError>,
        dispatched: DispatchedFailure,
    ) -> Result<T, CatalogError> {
        let (mut connection, connection_generation) = self.admit().await?;
        // The lane lock is no longer held: this deadline covers only the
        // authority's handling of the caller's own command.  From here on the
        // command may have reached the authority, so `dispatched` decides
        // how a lost reply is reported.
        match tokio::time::timeout(REDIS_OPERATION_TIMEOUT, operation(&mut connection)).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                let lost = lane_lost(&error);
                if lost {
                    // Release the dead connection and tell sibling lanes to
                    // probe theirs.  This command stays failed and is never
                    // replayed.
                    self.release_lost(connection_generation).await;
                }
                Err(dispatched.classify(error, lost))
            }
            Err(_) => Err(dispatched.timeout()),
        }
    }

    /// Hand out a handle to this lane's verified physical connection.
    ///
    /// Waiting for the lane lock is not part of any authority deadline: the
    /// lock is only ever held across the bounded probe or reconnect in
    /// [`Self::verify`], so a caller queued behind a sibling waits at most one
    /// such verification and then shares the same multiplexed connection.
    /// A verification that exceeds its deadline keeps the connection exactly
    /// as a timed-out command does.
    async fn admit(&self) -> Result<(MultiplexedConnection, u64), CatalogError> {
        let mut state = self.state.lock().await;
        tokio::time::timeout(REDIS_OPERATION_TIMEOUT, self.verify(&mut state))
            .await
            .map_err(|_| CatalogError::Database(redis_timeout()))?
    }

    async fn verify(
        &self,
        state: &mut LaneState,
    ) -> Result<(MultiplexedConnection, u64), CatalogError> {
        let loss_generation = self.group.loss_generation.load(Ordering::Acquire);
        if state.verified_generation != loss_generation
            && let Some(connection) = state.connection.as_mut()
        {
            // A sibling lane observed a transport loss since this
            // connection was last verified.  Probe before the caller's
            // command so a connection severed by the same event
            // reconnects here instead of failing this caller closed.
            match redis::cmd("PING").query_async::<String>(connection).await {
                Ok(_) => {}
                Err(error) if lane_lost(&error) => {
                    state.connection = None;
                    state.connection_generation += 1;
                }
                Err(error) => return Err(CatalogError::Database(error)),
            }
        }
        if state.connection.is_none() {
            state.connection = Some(self.reconnect().await?);
            state.connection_generation += 1;
        }
        state.verified_generation = loss_generation;
        let connection = state
            .connection
            .clone()
            .ok_or(CatalogError::Conflict("Redis authority lane"))?;
        Ok((connection, state.connection_generation))
    }

    /// Release the connection a caller observed a transport loss on, unless a
    /// sibling caller already released or replaced it.  Only the first
    /// observer of one loss advances the group loss generation.
    async fn release_lost(&self, connection_generation: u64) {
        let mut state = self.state.lock().await;
        if state.connection_generation == connection_generation && state.connection.is_some() {
            state.connection = None;
            state.connection_generation += 1;
            self.group.loss_generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    async fn reconnect(&self) -> Result<MultiplexedConnection, CatalogError> {
        let (connection, run_id) = open_verified_connection(&self.client)
            .await
            .map_err(CatalogConnectionError::into_catalog_error)?;
        if run_id != self.expected_run_id {
            return Err(CatalogError::Conflict(RUN_ID_CONFLICT));
        }
        Ok(connection)
    }
}

/// How a failure observed after the command was handed to the connection is
/// reported.  Reads and non-owner writes keep the definite `Database` shape;
/// owner-affecting writes report a lost reply as the typed unknown outcome.
#[derive(Clone, Copy)]
enum DispatchedFailure {
    Definite,
    Unknown,
}

impl DispatchedFailure {
    fn classify(self, error: RedisError, lost: bool) -> CatalogError {
        match self {
            Self::Definite => CatalogError::Database(error),
            Self::Unknown if lost => {
                CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ConnectionLost)
            }
            Self::Unknown if error.is_timeout() => {
                CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ReplyTimeout)
            }
            // An actual authority reply (server error, parse failure) is a
            // definite outcome even for an owner write.
            Self::Unknown => CatalogError::Database(error),
        }
    }

    fn timeout(self) -> CatalogError {
        match self {
            Self::Definite => CatalogError::Database(redis_timeout()),
            Self::Unknown => CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ReplyTimeout),
        }
    }
}

/// Whether a command failure means the physical connection is gone.  Server
/// replies, parse failures and caller-side deadlines keep the connection.
fn lane_lost(error: &RedisError) -> bool {
    error.is_io_error() || error.is_connection_dropped()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Mutex as AsyncMutex, oneshot},
        task::JoinSet,
    };

    const TEST_DEADLINE: Duration = Duration::from_secs(5);
    const MAX_REQUEST_BYTES: usize = 16 * 1024;
    const MAX_PENDING_REPLIES: usize = 1_024;
    /// Concurrent callers on one lane in the queueing regression.  With the
    /// per-reply delay below, serializing them takes three seconds while any
    /// single reply arrives well inside the two-second operation deadline.
    const QUEUED_CALLERS: usize = 20;
    const QUEUED_REPLY_DELAY: Duration = Duration::from_millis(150);
    /// A stalled authority: one reply takes longer than the operation
    /// deadline even with no other caller queued.
    const STALLED_REPLY_DELAY: Duration = Duration::from_millis(2_600);

    /// A bounded RESP2 authority double: answers the redis-rs handshake,
    /// `PING`, and `INFO` with a configurable `run_id`, and can sever any
    /// accepted connection while keeping its listener.
    struct FakeAuthority {
        port: u16,
        run_id: Arc<AsyncMutex<String>>,
        /// Delay applied to every reply, measured from the command's arrival.
        /// Replies stay in command order but are delayed concurrently, like a
        /// network path that adds latency to each reply rather than a server
        /// that spends that long on each command.
        reply_delay_ms: Arc<AtomicU64>,
        severs: Arc<StdMutex<Vec<Option<oneshot::Sender<()>>>>>,
        active: Arc<AtomicUsize>,
        shutdown: Option<oneshot::Sender<()>>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    impl FakeAuthority {
        async fn start(run_id: &str) -> Self {
            Self::start_with_reply_delay(run_id, Duration::ZERO).await
        }

        async fn start_with_reply_delay(run_id: &str, reply_delay: Duration) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake authority");
            let port = listener
                .local_addr()
                .expect("fake authority address")
                .port();
            let run_id = Arc::new(AsyncMutex::new(run_id.to_owned()));
            let reply_delay_ms = Arc::new(AtomicU64::new(
                u64::try_from(reply_delay.as_millis()).expect("bounded reply delay"),
            ));
            let severs = Arc::new(StdMutex::new(Vec::new()));
            let active = Arc::new(AtomicUsize::new(0));
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let task = tokio::spawn(run_fake_authority(
                listener,
                Arc::clone(&run_id),
                Arc::clone(&reply_delay_ms),
                Arc::clone(&severs),
                Arc::clone(&active),
                shutdown_rx,
            ));
            Self {
                port,
                run_id,
                reply_delay_ms,
                severs,
                active,
                shutdown: Some(shutdown_tx),
                task: Some(task),
            }
        }

        fn set_reply_delay(&self, reply_delay: Duration) {
            self.reply_delay_ms.store(
                u64::try_from(reply_delay.as_millis()).expect("bounded reply delay"),
                Ordering::Release,
            );
        }

        fn url(&self) -> String {
            format!("redis://127.0.0.1:{}/", self.port)
        }

        /// Connections accepted so far, in accept order.
        fn accepted(&self) -> usize {
            self.severs.lock().expect("sever registry").len()
        }

        async fn set_run_id(&self, run_id: &str) {
            *self.run_id.lock().await = run_id.to_owned();
        }

        /// Sever the connection with this accept index and wait until the
        /// server has dropped it.  The listener keeps accepting.
        async fn sever(&self, index: usize) {
            let before = self.active.load(Ordering::Acquire);
            let sender = self
                .severs
                .lock()
                .expect("sever registry")
                .get_mut(index)
                .and_then(Option::take)
                .expect("connection index was accepted and not yet severed");
            sender.send(()).expect("connection task is live");
            self.wait_active(before - 1).await;
        }

        /// Sever every live connection and wait until all are dropped.
        async fn sever_all(&self) {
            let senders: Vec<_> = self
                .severs
                .lock()
                .expect("sever registry")
                .iter_mut()
                .filter_map(Option::take)
                .collect();
            for sender in senders {
                let _ = sender.send(());
            }
            self.wait_active(0).await;
        }

        async fn wait_active(&self, expected: usize) {
            let deadline = tokio::time::Instant::now() + TEST_DEADLINE;
            while self.active.load(Ordering::Acquire) != expected {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "fake authority did not sever its connections"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        async fn shutdown(mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(task) = self.task.take() {
                tokio::time::timeout(TEST_DEADLINE, task)
                    .await
                    .expect("fake authority shutdown deadline")
                    .expect("fake authority task");
            }
        }
    }

    async fn run_fake_authority(
        listener: TcpListener,
        run_id: Arc<AsyncMutex<String>>,
        reply_delay_ms: Arc<AtomicU64>,
        severs: Arc<StdMutex<Vec<Option<oneshot::Sender<()>>>>>,
        active: Arc<AtomicUsize>,
        mut shutdown: oneshot::Receiver<()>,
    ) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                    return;
                }
                accepted_stream = listener.accept() => {
                    let Ok((stream, _)) = accepted_stream else { return; };
                    let (sever_tx, sever_rx) = oneshot::channel();
                    active.fetch_add(1, Ordering::AcqRel);
                    severs.lock().expect("sever registry").push(Some(sever_tx));
                    connections.spawn(serve_fake_connection(
                        stream,
                        Arc::clone(&run_id),
                        Arc::clone(&reply_delay_ms),
                        sever_rx,
                        Arc::clone(&active),
                    ));
                }
                Some(_) = connections.join_next() => {}
            }
        }
    }

    async fn serve_fake_connection(
        mut stream: TcpStream,
        run_id: Arc<AsyncMutex<String>>,
        reply_delay_ms: Arc<AtomicU64>,
        mut sever: oneshot::Receiver<()>,
        active: Arc<AtomicUsize>,
    ) {
        let mut pending = Vec::new();
        let mut buffer = [0_u8; 1024];
        // Replies due in command order; each is written once its own delay,
        // counted from the command's arrival, has elapsed.
        let mut due: VecDeque<(tokio::time::Instant, Vec<u8>)> = VecDeque::new();
        loop {
            let next_due = due.front().map(|(at, _)| *at);
            tokio::select! {
                // Dropping the stream is the injected transport loss.
                _ = &mut sever => break,
                read = stream.read(&mut buffer) => {
                    let read = match read {
                        Ok(0) | Err(_) => break,
                        Ok(read) => read,
                    };
                    pending.extend_from_slice(&buffer[..read]);
                    if pending.len() > MAX_REQUEST_BYTES {
                        break;
                    }
                    let delay = Duration::from_millis(reply_delay_ms.load(Ordering::Acquire));
                    let arrived = tokio::time::Instant::now();
                    while let Some((command, consumed)) = parse_command(&pending) {
                        pending.drain(..consumed);
                        let reply = match command.as_str() {
                            "CLIENT" => b"+OK\r\n".to_vec(),
                            "PING" => b"+PONG\r\n".to_vec(),
                            "INFO" => {
                                let body =
                                    format!("# Server\r\nrun_id:{}\r\n", run_id.lock().await);
                                format!("${}\r\n{body}\r\n", body.len()).into_bytes()
                            }
                            _ => b"-ERR unsupported fake authority command\r\n".to_vec(),
                        };
                        due.push_back((arrived + delay, reply));
                    }
                    if due.len() > MAX_PENDING_REPLIES {
                        break;
                    }
                }
                _ = async {
                    match next_due {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let Some((_, reply)) = due.pop_front() else { continue };
                    if stream.write_all(&reply).await.is_err() {
                        break;
                    }
                }
            }
        }
        active.fetch_sub(1, Ordering::AcqRel);
    }

    /// Parse one complete RESP2 command array, returning its upper-cased
    /// name and the consumed byte count, or `None` while incomplete.
    fn parse_command(bytes: &[u8]) -> Option<(String, usize)> {
        let (count_line, mut offset) = resp_line(bytes, 0)?;
        let count: usize = std::str::from_utf8(count_line.strip_prefix(b"*")?)
            .ok()?
            .parse()
            .ok()?;
        let mut name = None;
        for index in 0..count {
            let (length_line, next) = resp_line(bytes, offset)?;
            let length: usize = std::str::from_utf8(length_line.strip_prefix(b"$")?)
                .ok()?
                .parse()
                .ok()?;
            let end = next.checked_add(length)?;
            if bytes.len() < end.checked_add(2)? {
                return None;
            }
            if index == 0 {
                name = Some(String::from_utf8_lossy(&bytes[next..end]).to_ascii_uppercase());
            }
            offset = end + 2;
        }
        Some((name?, offset))
    }

    fn resp_line(bytes: &[u8], start: usize) -> Option<(&[u8], usize)> {
        let rest = bytes.get(start..)?;
        let end = rest.windows(2).position(|window| window == b"\r\n")?;
        Some((&rest[..end], start + end + 2))
    }

    async fn verified_lane(
        client: &redis::Client,
        expected_run_id: &str,
        group: &Arc<LaneGroup>,
    ) -> AuthorityLane {
        let (connection, run_id) =
            tokio::time::timeout(TEST_DEADLINE, open_verified_connection(client))
                .await
                .expect("bounded startup connection")
                .expect("verified startup connection");
        assert_eq!(run_id, expected_run_id);
        AuthorityLane::new(client.clone(), connection, run_id, Arc::clone(group))
    }

    async fn ping(lane: &AuthorityLane) -> Result<String, CatalogError> {
        tokio::time::timeout(TEST_DEADLINE, lane.query::<String>(&redis::cmd("PING")))
            .await
            .expect("bounded lane command")
    }

    fn assert_lost(result: Result<String, CatalogError>, context: &str) {
        match result {
            Err(CatalogError::Database(error)) if lane_lost(&error) => {}
            Err(other) => panic!("{context}: reported {other} instead of a transport loss"),
            Ok(reply) => panic!("{context}: succeeded with {reply} on a severed connection"),
        }
    }

    #[tokio::test]
    async fn severed_lane_fails_once_then_reconnects_only_to_the_same_primary() {
        let server = FakeAuthority::start("lane-run-a").await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = verified_lane(&client, "lane-run-a", &group).await;
        assert_eq!(ping(&lane).await.expect("healthy lane"), "PONG");
        assert_eq!(server.accepted(), 1);

        server.sever_all().await;
        assert_lost(ping(&lane).await, "severed lane");
        assert_eq!(
            server.accepted(),
            1,
            "the failed command must neither retry nor reconnect"
        );

        server.set_run_id("lane-run-b").await;
        for _ in 0..2 {
            let refused = ping(&lane)
                .await
                .expect_err("a changed primary identity must be refused");
            assert!(
                matches!(refused, CatalogError::Conflict(RUN_ID_CONFLICT)),
                "changed primary reported {refused}"
            );
        }
        assert_eq!(
            server.accepted(),
            3,
            "each refused reconnect verifies identity on a fresh connection"
        );

        server.set_run_id("lane-run-a").await;
        assert_eq!(ping(&lane).await.expect("same primary reconnects"), "PONG");
        assert_eq!(
            ping(&lane).await.expect("reconnected lane is reused"),
            "PONG"
        );
        assert_eq!(server.accepted(), 4);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn sibling_lanes_probe_after_a_loss_without_failing_their_callers() {
        let server = FakeAuthority::start("lane-run-a").await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let discovering = verified_lane(&client, "lane-run-a", &group).await;
        let severed_sibling = verified_lane(&client, "lane-run-a", &group).await;
        let live_sibling = verified_lane(&client, "lane-run-a", &group).await;
        assert_eq!(server.accepted(), 3);

        // Connections 0 and 1 are lost by the same event; connection 2 stays.
        server.sever(0).await;
        server.sever(1).await;
        assert_lost(ping(&discovering).await, "discovering lane");
        assert_eq!(server.accepted(), 3, "discovery never reconnects in place");

        assert_eq!(
            ping(&severed_sibling)
                .await
                .expect("a severed sibling reconnects before its caller's command"),
            "PONG"
        );
        assert_eq!(
            server.accepted(),
            4,
            "the severed sibling opened one connection"
        );
        assert_eq!(
            ping(&live_sibling)
                .await
                .expect("a live sibling passes its probe and keeps its connection"),
            "PONG"
        );
        assert_eq!(
            server.accepted(),
            4,
            "the live sibling opened no connection"
        );

        assert_eq!(
            ping(&discovering)
                .await
                .expect("the discovering lane reconnects on its next command"),
            "PONG"
        );
        assert_eq!(server.accepted(), 5);
        for lane in [&discovering, &severed_sibling, &live_sibling] {
            assert_eq!(ping(lane).await.expect("verified lanes are reused"), "PONG");
        }
        assert_eq!(server.accepted(), 5, "no further probe reconnects");
        server.shutdown().await;
    }

    fn timed_out(error: &RedisError) -> bool {
        error.is_timeout()
    }

    /// M7-C32 regression: callers queued on one lane must be measured
    /// against the authority's reply, not against each other.  Twenty
    /// callers whose replies each take 150 ms would take three seconds if the
    /// lane served them one at a time, so the last of them would report a
    /// two-second "authority timeout" that Redis never caused.  A genuinely
    /// stalled reply and a severed connection must still fail closed, with
    /// distinguishable transport classes and no reconnect in place.
    #[tokio::test]
    async fn queued_callers_are_measured_against_the_authority_not_the_queue() {
        let server = FakeAuthority::start_with_reply_delay("lane-run-a", QUEUED_REPLY_DELAY).await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = Arc::new(verified_lane(&client, "lane-run-a", &group).await);
        assert_eq!(server.accepted(), 1);

        let started = tokio::time::Instant::now();
        let mut callers = JoinSet::new();
        for _ in 0..QUEUED_CALLERS {
            let lane = Arc::clone(&lane);
            callers.spawn(async move { ping(&lane).await });
        }
        let mut replies = Vec::with_capacity(QUEUED_CALLERS);
        while let Some(joined) = callers.join_next().await {
            replies.push(joined.expect("queued caller task"));
        }
        let elapsed = started.elapsed();
        let failures: Vec<String> = replies
            .iter()
            .filter_map(|reply| reply.as_ref().err().map(ToString::to_string))
            .collect();
        assert!(
            failures.is_empty(),
            "{} of {QUEUED_CALLERS} queued callers failed after {elapsed:?} although every \
             reply took {QUEUED_REPLY_DELAY:?}: {failures:?}",
            failures.len()
        );
        assert!(
            elapsed < REDIS_OPERATION_TIMEOUT,
            "queued callers took {elapsed:?}; the lane serialized them behind each other"
        );
        assert_eq!(server.accepted(), 1, "queueing must not open connections");

        // A reply that genuinely exceeds the deadline is a timeout, reported
        // as such rather than as a severed connection.  The stalled command
        // is never retried; the lane releases the connection so the next
        // command re-verifies the primary before it is trusted again.
        server.set_reply_delay(STALLED_REPLY_DELAY);
        let stalled_started = tokio::time::Instant::now();
        match ping(&lane).await {
            Err(CatalogError::Database(error)) => assert!(
                timed_out(&error) && !error.is_connection_dropped(),
                "stalled authority reported {error} instead of a timeout"
            ),
            other => panic!("stalled authority reported {other:?} instead of a timeout"),
        }
        assert!(
            stalled_started.elapsed() >= REDIS_OPERATION_TIMEOUT,
            "the authority deadline fired before the documented bound"
        );
        assert_eq!(server.accepted(), 1, "a timeout never reconnects in place");
        server.set_reply_delay(Duration::ZERO);
        assert_eq!(
            ping(&lane)
                .await
                .expect("the command after a timeout re-verifies the same primary"),
            "PONG"
        );
        assert_eq!(server.accepted(), 2);

        // A severed connection is a transport loss, never a timeout, and the
        // discovering command fails closed exactly once.
        server.sever_all().await;
        match ping(&lane).await {
            Err(CatalogError::Database(error)) => assert!(
                lane_lost(&error) && !timed_out(&error),
                "severed lane reported {error} instead of a transport loss"
            ),
            other => panic!("severed lane reported {other:?} instead of a transport loss"),
        }
        assert_eq!(
            server.accepted(),
            2,
            "the discovering command never reconnects"
        );
        assert_eq!(
            ping(&lane).await.expect("the next command reconnects"),
            "PONG"
        );
        assert_eq!(server.accepted(), 3);
        server.shutdown().await;
    }

    /// Callers that observe the same loss concurrently release the lane once
    /// and advance the group loss generation once; a sibling that has already
    /// reconnected is never released by a late observer.
    #[tokio::test]
    async fn concurrent_loss_observers_release_the_lane_once() {
        let server = FakeAuthority::start_with_reply_delay("lane-run-a", QUEUED_REPLY_DELAY).await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = Arc::new(verified_lane(&client, "lane-run-a", &group).await);

        let mut callers = JoinSet::new();
        for _ in 0..QUEUED_CALLERS {
            let lane = Arc::clone(&lane);
            callers.spawn(async move { ping(&lane).await });
        }
        // Every caller is in flight behind the delayed replies when the
        // connection is severed, so all of them observe the same loss.
        tokio::time::sleep(QUEUED_REPLY_DELAY / 3).await;
        server.sever_all().await;
        while let Some(joined) = callers.join_next().await {
            assert_lost(joined.expect("queued caller task"), "concurrent observer");
        }
        assert_eq!(
            group.loss_generation.load(Ordering::Acquire),
            1,
            "one loss event advances the group generation once"
        );
        assert_eq!(server.accepted(), 1, "no observer reconnects in place");
        assert_eq!(
            ping(&lane).await.expect("the next command reconnects once"),
            "PONG"
        );
        assert_eq!(server.accepted(), 2);
        server.shutdown().await;
    }

    #[test]
    fn lane_loss_classification_is_transport_only() {
        assert!(lane_lost(&RedisError::from(std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        ))));
        assert!(lane_lost(&RedisError::from(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))));
        assert!(!lane_lost(&RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "wrong value type"
        ))));
        assert!(!lane_lost(&RedisError::from((
            redis::ErrorKind::Parse,
            "malformed reply"
        ))));
    }
}
