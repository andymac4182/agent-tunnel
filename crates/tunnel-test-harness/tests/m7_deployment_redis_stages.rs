//! Process-bound Redis authority failure-stage acceptance.
//!
//! Each case drives the configured executable through one real authority
//! boundary: DNS/connection checkout, TLS handshake, a read-side response
//! failure, or a post-PONG peer close before the next relay command. The sink
//! records only bounded counters so the test can prove which stage was reached
//! without retaining protocol bytes. The relay reports the explicit catalog
//! operation stage: TCP/TLS checkout shares the connection-establishment
//! boundary, while observed PING/PONG traffic proves the later command
//! boundary. The fixture checks both the bounded stage and independent sink
//! counters, without guessing from backend error text.

// The harness library is Unix-only (see `src/entry.rs`).
#![cfg(unix)]

use std::{
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::RedisCatalog;
use tunnel_test_harness::{
    FixturePki, HarnessError, ManagedProcess, OidcFixture, ProcessSpec, Result,
};
use tunnel_transport::load_server_config_from_pem;
use uuid::Uuid;

#[path = "common/m7_deployment.rs"]
mod common;
use common::{
    FixtureFiles, free_tcp_addr, jwks_json, parse_plaintext_upstream, process_diagnostic,
    relay_binary_path, toml_path, toml_string, wait_for_exit,
};

const TEST_DEADLINE: Duration = Duration::from_secs(90);
const PROCESS_DEADLINE: Duration = Duration::from_secs(8);
const SINK_PHASE_DEADLINE: Duration = Duration::from_secs(3);
const SINK_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(100);
const DIAGNOSTIC_MAX: usize = 16 * 1024;
const RESP_BUFFER_LIMIT: usize = 16 * 1024;
const RESP_ARRAY_LIMIT: usize = 16;
const REDIS_FAILURE_CATEGORY: &str = "redis catalog connection failed";

#[derive(Clone, Copy, Debug)]
enum RedisFaultStage {
    DnsResolution,
    TcpCheckout,
    TlsHandshake,
    RedisHead,
    PostPongPeerClose,
    RedisResponse,
}

impl RedisFaultStage {
    const ALL: [Self; 6] = [
        Self::DnsResolution,
        Self::TcpCheckout,
        Self::TlsHandshake,
        Self::RedisHead,
        Self::PostPongPeerClose,
        Self::RedisResponse,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::DnsResolution => "dns-resolution",
            Self::TcpCheckout => "tcp-checkout",
            Self::TlsHandshake => "tls-handshake",
            Self::RedisHead => "redis-head",
            Self::PostPongPeerClose => "post-pong-peer-close",
            Self::RedisResponse => "redis-response",
        }
    }

    fn diagnostic_stage(self) -> &'static str {
        match self {
            Self::DnsResolution | Self::TcpCheckout | Self::TlsHandshake => {
                "stage=connection_establishment"
            }
            Self::RedisHead => "stage=ping",
            Self::PostPongPeerClose => "stage=primary_identity",
            Self::RedisResponse => "stage=primary_identity",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum SinkBehavior {
    DropBeforeRedisResponse,
    CloseAfterPong,
    ReplyPongThenDrop,
}

#[derive(Clone, Copy, Debug, Default)]
struct SinkStats {
    accepted: usize,
    tls_handshakes: usize,
    application_reads: usize,
    initialization_responses: usize,
    responses_written: usize,
}

#[derive(Clone)]
struct SinkCounters {
    accepted: Arc<AtomicUsize>,
    tls_handshakes: Arc<AtomicUsize>,
    application_reads: Arc<AtomicUsize>,
    initialization_responses: Arc<AtomicUsize>,
    responses_written: Arc<AtomicUsize>,
}

impl Default for SinkCounters {
    fn default() -> Self {
        Self {
            accepted: Arc::new(AtomicUsize::new(0)),
            tls_handshakes: Arc::new(AtomicUsize::new(0)),
            application_reads: Arc::new(AtomicUsize::new(0)),
            initialization_responses: Arc::new(AtomicUsize::new(0)),
            responses_written: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct FaultSink {
    address: SocketAddr,
    counters: SinkCounters,
    cancellation: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
}

impl FaultSink {
    async fn bind(
        server_config: Arc<rustls::ServerConfig>,
        behavior: SinkBehavior,
    ) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let counters = SinkCounters::default();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_fault_sink(
            listener,
            TlsAcceptor::from(server_config),
            behavior,
            counters.clone(),
            cancellation.clone(),
        ));
        sleep(Duration::from_millis(1)).await;
        Ok(Self {
            address,
            counters,
            cancellation,
            task: Some(task),
        })
    }

    fn redis_url(&self) -> String {
        format!("rediss://localhost:{}/0", self.address.port())
    }

    fn stats(&self) -> SinkStats {
        SinkStats {
            accepted: self.counters.accepted.load(Ordering::Acquire),
            tls_handshakes: self.counters.tls_handshakes.load(Ordering::Acquire),
            application_reads: self.counters.application_reads.load(Ordering::Acquire),
            initialization_responses: self
                .counters
                .initialization_responses
                .load(Ordering::Acquire),
            responses_written: self.counters.responses_written.load(Ordering::Acquire),
        }
    }

    async fn shutdown(mut self) -> Result<SinkStats> {
        self.cancellation.cancel();
        if let Some(mut task) = self.task.take() {
            match timeout(SINK_SHUTDOWN_DEADLINE, &mut task).await {
                Ok(Ok(result)) => result?,
                Ok(Err(error)) => {
                    return Err(HarnessError::Proxy(format!(
                        "Redis staged fault sink join failed: {error}"
                    )));
                }
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    return Err(HarnessError::Timeout(
                        "Redis staged fault sink shutdown".into(),
                    ));
                }
            }
        }
        Ok(self.stats())
    }
}

impl Drop for FaultSink {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_fault_sink(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    behavior: SinkBehavior,
    counters: SinkCounters,
    cancellation: CancellationToken,
) -> Result<()> {
    let (stream, _) = tokio::select! {
        _ = cancellation.cancelled() => return Ok(()),
        accepted = listener.accept() => accepted?,
    };
    counters.accepted.fetch_add(1, Ordering::Release);
    let mut tls = match timeout(SINK_PHASE_DEADLINE, acceptor.accept(stream)).await {
        Ok(Ok(stream)) => {
            counters.tls_handshakes.fetch_add(1, Ordering::Release);
            stream
        }
        Ok(Err(_)) | Err(_) => return Ok(()),
    };
    let mut pending = Vec::new();
    loop {
        let Some(command) = read_redis_command(
            &mut tls,
            &mut pending,
            &counters.application_reads,
            &cancellation,
        )
        .await
        else {
            return Ok(());
        };
        match command {
            // redis-rs 1.7 sends two CLIENT SETINFO commands before the
            // catalog's explicit PING. Reply to those bounded setup calls so
            // the injected fault starts at the command stage under test.
            RedisCommand::ClientSetInfo | RedisCommand::Other => {
                write_sink_response(&mut tls, b"+OK\r\n", &counters.initialization_responses).await;
            }
            RedisCommand::Ping => match behavior {
                SinkBehavior::DropBeforeRedisResponse => return Ok(()),
                SinkBehavior::CloseAfterPong => {
                    write_sink_response(&mut tls, b"+PONG\r\n", &counters.responses_written).await;
                    // PING completed a full request/response exchange. Close
                    // before the relay can write its sequential INFO request.
                    return Ok(());
                }
                SinkBehavior::ReplyPongThenDrop => {
                    write_sink_response(&mut tls, b"+PONG\r\n", &counters.responses_written).await;
                    loop {
                        let Some(next) = read_redis_command(
                            &mut tls,
                            &mut pending,
                            &counters.application_reads,
                            &cancellation,
                        )
                        .await
                        else {
                            return Ok(());
                        };
                        match next {
                            RedisCommand::Info => return Ok(()),
                            RedisCommand::ClientSetInfo | RedisCommand::Other => {
                                write_sink_response(
                                    &mut tls,
                                    b"+OK\r\n",
                                    &counters.initialization_responses,
                                )
                                .await;
                            }
                            RedisCommand::Ping => return Ok(()),
                        }
                    }
                }
            },
            RedisCommand::Info => return Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RedisCommand {
    ClientSetInfo,
    Ping,
    Info,
    Other,
}

async fn read_redis_command(
    tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    pending: &mut Vec<u8>,
    application_reads: &AtomicUsize,
    cancellation: &CancellationToken,
) -> Option<RedisCommand> {
    loop {
        if let Some((command, consumed)) = parse_redis_command(pending) {
            pending.drain(..consumed);
            application_reads.fetch_add(1, Ordering::Release);
            return Some(command);
        }
        if pending.len() >= RESP_BUFFER_LIMIT {
            return None;
        }
        let mut chunk = [0_u8; 4096];
        let result = tokio::select! {
            _ = cancellation.cancelled() => return None,
            result = timeout(SINK_PHASE_DEADLINE, tls.read(&mut chunk)) => result,
        };
        match result {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
            Ok(Ok(read)) => {
                if pending.len().saturating_add(read) > RESP_BUFFER_LIMIT {
                    return None;
                }
                pending.extend_from_slice(&chunk[..read]);
            }
        }
    }
}

async fn write_sink_response(
    tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    response: &[u8],
    responses_written: &AtomicUsize,
) {
    if matches!(
        timeout(SINK_PHASE_DEADLINE, tls.write_all(response)).await,
        Ok(Ok(()))
    ) {
        responses_written.fetch_add(1, Ordering::Release);
    }
}

fn parse_redis_command(bytes: &[u8]) -> Option<(RedisCommand, usize)> {
    if bytes.first() != Some(&b'*') {
        return (!bytes.is_empty()).then_some((RedisCommand::Other, 1));
    }
    let (count, mut cursor) = parse_resp_integer(bytes, 1)?;
    if !(1..=RESP_ARRAY_LIMIT).contains(&count) {
        return Some((RedisCommand::Other, cursor.min(bytes.len())));
    }
    let mut first = None;
    let mut second = None;
    for index in 0..count {
        if bytes.get(cursor) != Some(&b'$') {
            return Some((RedisCommand::Other, cursor.min(bytes.len()).max(1)));
        }
        let (length, payload_start) = parse_resp_integer(bytes, cursor + 1)?;
        let payload_end = payload_start.checked_add(length)?;
        let frame_end = payload_end.checked_add(2)?;
        if bytes.len() < frame_end {
            return None;
        }
        if &bytes[payload_end..frame_end] != b"\r\n" {
            return Some((RedisCommand::Other, frame_end.min(bytes.len()).max(1)));
        }
        if index == 0 {
            first = Some(&bytes[payload_start..payload_end]);
        } else if index == 1 {
            second = Some(&bytes[payload_start..payload_end]);
        }
        cursor = frame_end;
    }
    let command = if first.is_some_and(|value| ascii_case_eq(value, b"CLIENT"))
        && second.is_some_and(|value| ascii_case_eq(value, b"SETINFO"))
    {
        RedisCommand::ClientSetInfo
    } else if first.is_some_and(|value| ascii_case_eq(value, b"PING")) {
        RedisCommand::Ping
    } else if first.is_some_and(|value| ascii_case_eq(value, b"INFO")) {
        RedisCommand::Info
    } else {
        RedisCommand::Other
    };
    Some((command, cursor))
}

fn parse_resp_integer(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut end = start;
    while end + 1 < bytes.len() {
        if &bytes[end..end + 2] == b"\r\n" {
            let value = std::str::from_utf8(&bytes[start..end])
                .ok()?
                .parse::<usize>()
                .ok()?;
            return Some((value, end + 2));
        }
        end += 1;
    }
    None
}

fn ascii_case_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

struct PartialFixture {
    catalog: Option<RedisCatalog>,
    sink: Option<FaultSink>,
}

impl PartialFixture {
    fn new() -> Self {
        Self {
            catalog: None,
            sink: None,
        }
    }

    async fn cleanup(self) -> Result<()> {
        let Self { catalog, sink } = self;
        let catalog_result = match catalog {
            Some(catalog) => catalog.cleanup_fixture_namespace().await.map_err(|error| {
                HarnessError::Redis(format!("cleaning Redis stage fixture: {error}"))
            }),
            None => Ok(()),
        };
        let sink_result = match sink {
            Some(sink) => sink.shutdown().await.map(|_| ()),
            None => Ok(()),
        };
        combine_results("partial Redis stage cleanup", catalog_result, sink_result)
    }
}

struct ProcessFixture {
    _files: FixtureFiles,
    catalog: RedisCatalog,
    sink: Option<FaultSink>,
    relay_binary: PathBuf,
    config_path: PathBuf,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    namespace: String,
    stage: RedisFaultStage,
}

impl ProcessFixture {
    fn sink_stats(&self) -> Option<SinkStats> {
        self.sink.as_ref().map(FaultSink::stats)
    }

    async fn cleanup(self) -> Result<()> {
        let Self {
            _files: _,
            catalog,
            sink,
            ..
        } = self;
        let catalog_result = catalog
            .cleanup_fixture_namespace()
            .await
            .map_err(|error| HarnessError::Redis(format!("cleaning Redis stage fixture: {error}")));
        let sink_result = match sink {
            Some(sink) => sink.shutdown().await.map(|_| ()),
            None => Ok(()),
        };
        combine_results("Redis stage cleanup", catalog_result, sink_result)
    }
}

#[tokio::test]
#[ignore = "requires TEST_REDIS_URL and the root-built relay binary"]
async fn m7_configured_relay_redis_fault_stages_fail_closed_without_leaks() {
    run_all_stages().await.expect("Redis staged fault gate");
}

async fn run_all_stages() -> Result<()> {
    // Keep one shared budget for the matrix, but do not cancel an in-flight
    // stage: run_stage owns Redis namespace, sink, process, and listener
    // cleanup, so cancellation here would detach those resources.
    let deadline = Instant::now() + TEST_DEADLINE;
    let mut failures = Vec::new();
    for stage in RedisFaultStage::ALL {
        if Instant::now() >= deadline {
            failures.push(HarnessError::Timeout(format!(
                "Redis staged fault matrix exhausted its shared {} second budget before {}",
                TEST_DEADLINE.as_secs(),
                stage.name()
            )));
            break;
        }
        if let Err(error) = run_stage(stage).await {
            failures.push(HarnessError::Process(format!(
                "{} stage failed: {error}",
                stage.name()
            )));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(combine_error_list("Redis staged fault cases", failures))
    }
}

async fn run_stage(stage: RedisFaultStage) -> Result<()> {
    let mut fixture = create_fixture(stage).await?;
    let process_result = run_process(&mut fixture).await;
    let stats = fixture.sink_stats();
    let evidence_result = assert_stage_evidence(stage, stats);
    let cleanup_result = fixture.cleanup().await;
    combine_results(
        stage.name(),
        combine_two(process_result, evidence_result),
        cleanup_result,
    )
}

async fn run_process(fixture: &mut ProcessFixture) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        format!("m7-redis-stage-{}", fixture.stage.name()),
        ProcessSpec::new(&fixture.relay_binary)
            .arg("serve")
            .arg("--config")
            .arg(fixture.config_path.display().to_string()),
    )
    .await?;
    let status = match wait_for_exit(&mut process, PROCESS_DEADLINE).await {
        Ok(status) => status,
        Err(error) => {
            let diagnostic = process_diagnostic(&process);
            let _ = process.shutdown(SHUTDOWN_GRACE).await;
            return Err(HarnessError::Process(format!(
                "Redis {} failure did not terminate within the bound: {error}; diagnostic_bytes={}",
                fixture.stage.name(),
                diagnostic.len()
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    let joined_status = process.shutdown(SHUTDOWN_GRACE).await?;
    if status.success() || joined_status.success() {
        return Err(HarnessError::Process(format!(
            "Redis {} failure unexpectedly returned success",
            fixture.stage.name()
        )));
    }
    let diagnostic_result =
        assert_safe_redacted_failure(fixture, &diagnostic, fixture.sink_stats());
    let ports_result =
        wait_for_tcp_ports_released(fixture.consumer_bind, fixture.device_bind).await;
    combine_two(diagnostic_result, ports_result)
}

async fn wait_for_tcp_ports_released(
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let consumer = std::net::TcpListener::bind(consumer_bind);
        let device = std::net::TcpListener::bind(device_bind);
        if consumer.is_ok() && device.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "Redis staged fault left a public listener bound".into(),
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn assert_safe_redacted_failure(
    fixture: &ProcessFixture,
    diagnostic: &str,
    stats: Option<SinkStats>,
) -> Result<()> {
    if diagnostic.len() > DIAGNOSTIC_MAX {
        return Err(HarnessError::Process(format!(
            "Redis {} diagnostic exceeded its bound: {} bytes",
            fixture.stage.name(),
            diagnostic.len()
        )));
    }
    let lower = diagnostic.to_ascii_lowercase();
    if lower.contains("-----begin")
        || lower.contains("private_key")
        || lower.contains("private key")
        || lower.contains("rediss://")
        || lower.contains(&fixture.namespace.to_ascii_lowercase())
    {
        return Err(HarnessError::Process(format!(
            "Redis {} diagnostic leaked authority material",
            fixture.stage.name()
        )));
    }
    if !lower.contains(REDIS_FAILURE_CATEGORY) {
        return Err(HarnessError::Process(format!(
            "Redis {} diagnostic did not expose the bounded typed authority category",
            fixture.stage.name()
        )));
    }
    if !lower.contains(fixture.stage.diagnostic_stage()) {
        return Err(HarnessError::Process(format!(
            "Redis {} diagnostic did not expose the expected catalog stage {}; observed_stage={} counters={:?}",
            fixture.stage.name(),
            fixture.stage.diagnostic_stage(),
            observed_sink_stage(stats),
            stats
        )));
    }
    Ok(())
}

fn observed_sink_stage(stats: Option<SinkStats>) -> &'static str {
    let Some(stats) = stats else {
        return "no_sink";
    };
    if stats.tls_handshakes == 0 {
        "tls_handshake"
    } else if stats.initialization_responses < 2 {
        "redis_connection_setup"
    } else if stats.responses_written == 0 {
        "ping"
    } else {
        "primary_identity"
    }
}

fn assert_stage_evidence(stage: RedisFaultStage, stats: Option<SinkStats>) -> Result<()> {
    match stage {
        RedisFaultStage::DnsResolution => {
            if stats.is_some() {
                return Err(HarnessError::Process(
                    "DNS resolution fixture unexpectedly created a sink".into(),
                ));
            }
        }
        RedisFaultStage::TcpCheckout => {
            if stats.is_some() {
                return Err(HarnessError::Process(
                    "TCP checkout fixture unexpectedly created a sink".into(),
                ));
            }
        }
        RedisFaultStage::TlsHandshake => {
            let Some(stats) = stats else {
                return Err(HarnessError::Process(
                    "TLS handshake fixture did not retain its sink".into(),
                ));
            };
            if stats.accepted == 0 || stats.tls_handshakes != 0 {
                return Err(HarnessError::Process(format!(
                    "TLS handshake stage counters were not exact: accepted={} tls_handshakes={}",
                    stats.accepted, stats.tls_handshakes
                )));
            }
        }
        RedisFaultStage::RedisHead => {
            let Some(stats) = stats else {
                return Err(HarnessError::Process(
                    "Redis head fixture did not retain its sink".into(),
                ));
            };
            if stats.tls_handshakes != 1
                || stats.initialization_responses != 2
                || stats.application_reads < 3
                || stats.responses_written != 0
            {
                return Err(HarnessError::Process(format!(
                    "Redis head stage counters were not exact: tls_handshakes={} setup_responses={} reads={} responses={}",
                    stats.tls_handshakes,
                    stats.initialization_responses,
                    stats.application_reads,
                    stats.responses_written
                )));
            }
        }
        RedisFaultStage::PostPongPeerClose => {
            let Some(stats) = stats else {
                return Err(HarnessError::Process(
                    "Redis post-PONG close fixture did not retain its sink".into(),
                ));
            };
            if stats.tls_handshakes != 1
                || stats.initialization_responses != 2
                || stats.application_reads != 3
                || stats.responses_written != 1
            {
                return Err(HarnessError::Process(format!(
                    "Redis post-PONG close counters were not exact: tls_handshakes={} setup_responses={} reads={} responses={}",
                    stats.tls_handshakes,
                    stats.initialization_responses,
                    stats.application_reads,
                    stats.responses_written
                )));
            }
        }
        RedisFaultStage::RedisResponse => {
            let Some(stats) = stats else {
                return Err(HarnessError::Process(
                    "Redis response fixture did not retain its sink".into(),
                ));
            };
            if stats.tls_handshakes != 1
                || stats.initialization_responses != 2
                || stats.application_reads < 4
                || stats.responses_written != 1
            {
                return Err(HarnessError::Process(format!(
                    "Redis response stage counters were not exact: tls_handshakes={} setup_responses={} reads={} responses={}",
                    stats.tls_handshakes,
                    stats.initialization_responses,
                    stats.application_reads,
                    stats.responses_written
                )));
            }
        }
    }
    Ok(())
}

async fn create_fixture(stage: RedisFaultStage) -> Result<ProcessFixture> {
    let files = FixtureFiles::new()?;
    let mut partial = PartialFixture::new();
    let result = create_fixture_inner(files, stage, &mut partial).await;
    match result {
        Ok(fixture) => Ok(fixture),
        Err(primary) => match partial.cleanup().await {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(HarnessError::Process(format!(
                "Redis {} fixture setup failed: {primary}; cleanup failed: {cleanup}",
                stage.name()
            ))),
        },
    }
}

async fn create_fixture_inner(
    files: FixtureFiles,
    stage: RedisFaultStage,
    partial: &mut PartialFixture,
) -> Result<ProcessFixture> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance: "the Redis staged fault gate requires a disposable plaintext Redis upstream for fixture cleanup".into(),
    })?;
    parse_plaintext_upstream(&upstream_url)?;
    let run_id = Uuid::new_v4().simple().to_string();
    let namespace = format!("m7-redis-stage-fixture-{run_id}");
    let deployment_incarnation = format!("m7-redis-stage-incarnation-{run_id}");
    let pki = FixturePki::new()?;
    let server_leaf = pki.issue_server("m7-redis-stage-relay")?;
    let server_chain = format!(
        "{}{}",
        server_leaf.certificate_pem, pki.server_ca.certificate_pem
    );
    let sink = match stage {
        RedisFaultStage::DnsResolution => None,
        RedisFaultStage::TcpCheckout => None,
        RedisFaultStage::TlsHandshake => {
            let wrong_pki = FixturePki::new()?;
            let wrong_leaf = wrong_pki.issue_server("m7-redis-stage-wrong-authority")?;
            let wrong_chain = format!(
                "{}{}",
                wrong_leaf.certificate_pem, wrong_pki.server_ca.certificate_pem
            );
            let config = load_server_config_from_pem(
                wrong_chain.as_bytes(),
                wrong_leaf.private_key_pem.as_bytes(),
                None,
            )
            .map_err(|error| HarnessError::Pki(format!("building staged TLS sink: {error}")))?;
            Some(FaultSink::bind(config, SinkBehavior::DropBeforeRedisResponse).await?)
        }
        RedisFaultStage::RedisHead
        | RedisFaultStage::PostPongPeerClose
        | RedisFaultStage::RedisResponse => {
            let config = load_server_config_from_pem(
                server_chain.as_bytes(),
                server_leaf.private_key_pem.as_bytes(),
                None,
            )
            .map_err(|error| HarnessError::Pki(format!("building staged Redis sink: {error}")))?;
            let behavior = match stage {
                RedisFaultStage::RedisHead => SinkBehavior::DropBeforeRedisResponse,
                RedisFaultStage::PostPongPeerClose => SinkBehavior::CloseAfterPong,
                RedisFaultStage::RedisResponse => SinkBehavior::ReplyPongThenDrop,
                _ => unreachable!("sink created only for Redis command stages"),
            };
            Some(FaultSink::bind(config, behavior).await?)
        }
    };
    partial.sink = sink;
    let redis_url = match stage {
        RedisFaultStage::DnsResolution => {
            // RFC 2606 reserves .invalid for names that must never resolve.
            // No local listener or TLS sink participates in this case.
            "rediss://m7-redis-stage-dns.invalid:6380/0".to_owned()
        }
        RedisFaultStage::TcpCheckout => {
            let unused = free_tcp_addr();
            format!("rediss://localhost:{}/0", unused.port())
        }
        RedisFaultStage::TlsHandshake
        | RedisFaultStage::RedisHead
        | RedisFaultStage::PostPongPeerClose
        | RedisFaultStage::RedisResponse => partial
            .sink
            .as_ref()
            .expect("staged Redis sink retained")
            .redis_url(),
    };
    let catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, &deployment_incarnation)
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("opening Redis stage catalog: {error}"))
            })?;
    partial.catalog = Some(catalog);
    partial
        .catalog
        .as_ref()
        .expect("Redis stage catalog retained")
        .activate_deployment_incarnation()
        .await
        .map_err(|error| HarnessError::Redis(format!("activating Redis stage catalog: {error}")))?;
    common::mark_catalog_provisioned(
        partial
            .catalog
            .as_ref()
            .expect("Redis stage catalog retained"),
    )
    .await?;

    let oidc = OidcFixture::new(
        format!("https://m7-redis-stage-oidc-{run_id}.invalid"),
        "agent-tunnel",
    )?;
    let oidc_jwks = jwks_json(&oidc)?;
    let server_chain_path = files.write("relay-cert-chain.pem", server_chain.as_bytes())?;
    let server_key_path = files.write("relay-key.pem", server_leaf.private_key_pem.as_bytes())?;
    let server_ca_path = files.write("server-ca.pem", pki.server_ca.certificate_pem.as_bytes())?;
    let device_ca_path = files.write("device-ca.pem", pki.device_ca.certificate_pem.as_bytes())?;
    let oidc_jwks_path = files.write("oidc-jwks.json", oidc_jwks.as_bytes())?;
    let consumer_bind = free_tcp_addr();
    let device_bind = loop {
        let candidate = free_tcp_addr();
        if candidate != consumer_bind {
            break candidate;
        }
    };
    let config = format!(
        "consumer_bind = {}\ndevice_bind = {}\noidc_issuer = {}\noidc_audience = [\"agent-tunnel\"]\noidc_jwks_path = {}\nredis_url = {}\nredis_namespace = {}\nredis_tls_root_ca_path = {}\ndeployment_incarnation = {}\ndevice_tls_cert_chain = {}\ndevice_tls_private_key = {}\ndevice_tls_client_ca = {}\nconsumer_tls_cert_chain = {}\nconsumer_tls_private_key = {}\n",
        toml_string(&consumer_bind.to_string()),
        toml_string(&device_bind.to_string()),
        toml_string(&oidc.issuer),
        toml_path(&oidc_jwks_path),
        toml_string(&redis_url),
        toml_string(&namespace),
        toml_path(&server_ca_path),
        toml_string(&deployment_incarnation),
        toml_path(&server_chain_path),
        toml_path(&server_key_path),
        toml_path(&device_ca_path),
        toml_path(&server_chain_path),
        toml_path(&server_key_path),
    );
    let config_path = files.write("relay.toml", config.as_bytes())?;
    let catalog = partial
        .catalog
        .take()
        .expect("Redis stage catalog retained");
    Ok(ProcessFixture {
        _files: files,
        catalog,
        sink: partial.sink.take(),
        relay_binary,
        config_path,
        consumer_bind,
        device_bind,
        namespace,
        stage,
    })
}

fn combine_two(first: Result<()>, second: Result<()>) -> Result<()> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(HarnessError::Process(format!("{first}; {second}"))),
    }
}

fn combine_results(label: &str, first: Result<()>, second: Result<()>) -> Result<()> {
    combine_two(first, second).map_err(|error| HarnessError::Process(format!("{label}: {error}")))
}

fn combine_error_list(label: &str, errors: Vec<HarnessError>) -> HarnessError {
    debug_assert!(!errors.is_empty());
    HarnessError::Process(format!(
        "{label}: {}",
        errors
            .into_iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ")
    ))
}

#[cfg(test)]
mod protocol_tests {
    use super::{RedisCommand, ascii_case_eq, parse_redis_command};

    #[test]
    fn redis_setup_pipeline_frames_are_classified_before_fault_command() {
        let mut bytes = b"*4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$8\r\nLIB-NAME\r\n$8\r\nredis-rs\r\n*4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$7\r\nLIB-VER\r\n$5\r\n1.7.0\r\n*1\r\n$4\r\nPING\r\n"
            .to_vec();
        let (first, consumed) = parse_redis_command(&bytes).expect("first setup frame");
        assert_eq!(first, RedisCommand::ClientSetInfo);
        bytes.drain(..consumed);
        let (second, consumed) = parse_redis_command(&bytes).expect("second setup frame");
        assert_eq!(second, RedisCommand::ClientSetInfo);
        bytes.drain(..consumed);
        let (ping, consumed) = parse_redis_command(&bytes).expect("PING frame");
        assert_eq!(ping, RedisCommand::Ping);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn redis_command_parser_keeps_incomplete_frames_bounded() {
        assert!(parse_redis_command(b"*1\r\n$4\r\nPI").is_none());
        assert!(ascii_case_eq(b"pInG", b"PING"));
    }
}
