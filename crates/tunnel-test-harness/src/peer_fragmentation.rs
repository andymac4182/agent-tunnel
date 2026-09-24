//! Real HTTP/3 peer-record fragmentation and rejection evidence.
//!
//! This fixture deliberately sits below the normal relay forwarding helper.
//! It sends the initial envelope and subsequent peer records with a raw
//! [`tunnel_transport::PeerClientStream`] so an HTTP/3 body boundary can fall
//! anywhere in an eight-byte peer prefix, a four-byte consumer prefix, or a
//! record body.  The server side is still the production
//! [`tunnel_relay::peer_runtime::PeerRuntime`] admission handler and owner
//! callback.  Consequently malformed records are rejected by the live relay
//! decoder before an owner record is dispatched.
//!
//! The module is intentionally unreferenced until the acceptance command wires
//! it into its own command.  It owns no Redis state and makes no claim about a
//! public HTTP adapter or a desktop/device process.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{Request, StatusCode};
use sha2::{Digest, Sha256};
use tokio::{
    sync::Mutex,
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{MemoryCatalog, OwnerToken, SharedCatalog};
use tunnel_cluster::{
    envelope::{
        ConsumerStreamsRequest, Destination, ForwardedConsumerBearer, InternalRequest,
        InternalRoute, PeerIdentity, RequestEnvelope,
    },
    membership::{
        MembershipPolicy, MembershipVerifier, PrivateEndpointPolicy, VerifiedPeerBinding,
    },
    peer_frame::{
        ConnectionBudget, MAX_CONSUMER_CHUNK_BODY, PREFIX_LEN, PeerFrameError, PeerRecordDecoder,
        PeerRecordKind,
    },
};
use tunnel_relay::{
    peer_runtime::{
        InboundPeerRequest, PeerBindingFuture, PeerBindingProvider, PeerRuntime, PeerRuntimeError,
    },
    routing::{OwnerRouter, RelayIdentity},
};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerDestination, PeerServer, PeerTransportError,
    PeerTransportLimits, SharedPeerPins, load_peer_client_config_from_pem,
    load_peer_server_config_from_pem, spki_sha256_from_der,
};

use crate::{ClusterFixture, FixturePki, HarnessError, Result};

const OWNER_NODE_ID: &str = "relay-a";
const SOURCE_NODE_ID: &str = "relay-b";
const SERVER_NAME: &str = "localhost";
const CASE_TIMEOUT: Duration = Duration::from_secs(8);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const ABORT_JOIN_TIMEOUT: Duration = Duration::from_millis(250);
const REJECTION_TIMEOUT: Duration = Duration::from_secs(4);
const INNER_BODY_LEN: usize = 1_024;

/// Evidence returned by one real authenticated peer-fragmentation run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerFragmentationEvidence {
    /// Number of synthetic relay identities in the fixture.  The focused
    /// case runs one owner listener and one source HTTP/3 client; it does not
    /// claim three production relay processes.
    pub relay_count: usize,
    /// Whether the successful cases crossed mTLS, HTTP/3, and PeerRuntime
    /// admission before reaching the owner callback.
    pub authenticated_http3: bool,
    /// Number of cases that split the envelope's eight-byte prefix.
    pub fragmented_prefix_cases: usize,
    /// Number of cases that split a peer body, including a four-byte consumer
    /// length prefix and the maximum legal consumer body.
    pub fragmented_body_cases: usize,
    /// Number of valid peer records sent in one coalesced HTTP/3 body chunk.
    pub coalesced_records: usize,
    /// Whether an empty legal ConsumerChunk survived the round trip.
    pub empty_record_preserved: bool,
    /// Whether the maximum legal ConsumerChunk survived the round trip.
    pub maximum_record_preserved: bool,
    /// Whether echoed bodies and their peer-record kinds were byte exact.
    pub exact_bytes: bool,
    /// Whether echoed record order was unchanged.
    pub order_preserved: bool,
    /// Number of malformed peer-frame cases attempted.
    pub malformed_cases: usize,
    /// Number of malformed cases that failed closed within the bounded wait.
    pub malformed_rejections: usize,
    /// Number of records dispatched by the owner callback during malformed
    /// cases.  This must remain zero.
    pub malformed_dispatches: usize,
    /// Whether a valid sibling stream progressed after malformed inputs.
    pub sibling_progress: bool,
    /// Whether local response decoding and the post-rejection sibling both
    /// demonstrated released bounded resources.
    pub budget_reclaimed: bool,
    /// Whether the server and both client supervisors were cancelled and
    /// joined within their cleanup bound.
    pub cleanup_joined: bool,
}

impl PeerFragmentationEvidence {
    /// Validate the exact EC-034 evidence shape before a caller publishes it.
    pub fn validate(&self) -> Result<()> {
        if self.relay_count != 3 {
            return Err(HarnessError::Http(format!(
                "peer-fragmentation fixture requires 3 relays, observed {}",
                self.relay_count
            )));
        }
        if !self.authenticated_http3
            || self.fragmented_prefix_cases != 7
            || self.fragmented_body_cases != 2
            || self.coalesced_records != 3
            || !self.empty_record_preserved
            || !self.maximum_record_preserved
            || !self.exact_bytes
            || !self.order_preserved
            || self.malformed_cases != 7
            || self.malformed_rejections != self.malformed_cases
            || self.malformed_dispatches != 0
            || !self.sibling_progress
            || !self.budget_reclaimed
            || !self.cleanup_joined
        {
            return Err(HarnessError::Http(
                "peer-fragmentation EC-034 evidence was incomplete".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct DispatchState {
    accepted_requests: usize,
    records: Vec<RecordDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecordDigest {
    kind: PeerRecordKind,
    length: usize,
    sha256: [u8; 32],
}

impl RecordDigest {
    fn of(kind: PeerRecordKind, body: &[u8]) -> Self {
        Self {
            kind,
            length: body.len(),
            sha256: Sha256::digest(body).into(),
        }
    }
}

#[derive(Clone)]
struct FixtureBindings {
    binding: VerifiedPeerBinding,
}

impl PeerBindingProvider for FixtureBindings {
    fn binding<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        _now: DateTime<Utc>,
    ) -> PeerBindingFuture<'a> {
        let result = if self.binding.node_id() == node_id && self.binding.boot_id() == boot_id {
            Ok(self.binding.clone())
        } else {
            Err(PeerRuntimeError::Membership(
                "peer-fragmentation binding unavailable".to_owned(),
            ))
        };
        Box::pin(async move { result })
    }
}

struct RunningFixture {
    client: PeerClient,
    destination: PeerDestination,
    runtime: Arc<PeerRuntime>,
    owner_boot_id: String,
    source_boot_id: String,
    deployment_incarnation: String,
    cancel: CancellationToken,
    server_task: JoinHandle<std::result::Result<(), PeerTransportError>>,
    state: Arc<Mutex<DispatchState>>,
}

impl RunningFixture {
    async fn shutdown(mut self) -> Result<()> {
        self.cancel.cancel();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut errors = Vec::new();

        if let Err(error) = join_server(&mut self.server_task, deadline).await {
            errors.push(format!("server: {error}"));
        }
        match timeout_at(deadline, self.client.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("client: {error}")),
            Err(_) => errors.push("client: shutdown deadline exceeded".to_owned()),
        }
        match timeout_at(deadline, self.runtime.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("runtime: {error}")),
            Err(_) => errors.push("runtime: shutdown deadline exceeded".to_owned()),
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(format!(
                "peer-fragmentation cleanup failed: {}",
                errors.join("; ")
            )))
        }
    }
}

async fn join_server(
    task: &mut JoinHandle<std::result::Result<(), PeerTransportError>>,
    deadline: Instant,
) -> Result<()> {
    let joined = match timeout_at(deadline, &mut *task).await {
        Ok(joined) => joined,
        Err(_) => {
            task.abort();
            match timeout(ABORT_JOIN_TIMEOUT, &mut *task).await {
                Ok(joined) => joined,
                Err(_) => {
                    return Err(HarnessError::Timeout(
                        "joining peer-fragmentation server after abort".to_owned(),
                    ));
                }
            }
        }
    };
    let result =
        joined.map_err(|error| HarnessError::Process(format!("joining server task: {error}")))?;
    result.map_err(|error| HarnessError::Http(format!("server shutdown: {error}")))
}

#[derive(Default)]
struct RunCounters {
    fragmented_prefix_cases: usize,
    fragmented_body_cases: usize,
    coalesced_records: usize,
    empty_record_preserved: bool,
    maximum_record_preserved: bool,
    exact_bytes: bool,
    order_preserved: bool,
    malformed_cases: usize,
    malformed_rejections: usize,
    malformed_dispatches: usize,
    sibling_progress: bool,
    budget_reclaimed: bool,
    authenticated_http3: bool,
}

struct ValidCaseResult {
    exact_bytes: bool,
    order_preserved: bool,
    accepted_request: bool,
    budget_reclaimed: bool,
}

/// Run the real mTLS HTTP/3 peer-record fragmentation fixture.
pub async fn verify() -> Result<PeerFragmentationEvidence> {
    verify_inner().await
}

async fn verify_inner() -> Result<PeerFragmentationEvidence> {
    let pki = FixturePki::new()?;
    let mut cluster = ClusterFixture::new(&pki)?;
    if cluster.nodes.len() != 3 {
        return Err(HarnessError::InvalidInput(
            "peer-fragmentation fixture did not create three relays".to_owned(),
        ));
    }
    // The owner's listener takes its reserved UDP socket (M7-C118).
    let owner_socket = cluster
        .node_mut(OWNER_NODE_ID)
        .ok_or_else(|| HarnessError::InvalidInput("peer-fragmentation owner missing".to_owned()))?
        .take_quic_socket()?;
    cluster
        .node_mut(SOURCE_NODE_ID)
        .ok_or_else(|| HarnessError::InvalidInput("peer-fragmentation source missing".to_owned()))?
        .release_ports();

    let source_binding = verified_binding(&cluster, SOURCE_NODE_ID)?;
    let running = start_fixture(&cluster, source_binding, owner_socket)?;
    let run_result = match timeout(CASE_TIMEOUT.saturating_mul(16), run_cases(&running)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "peer-fragmentation fixture exceeded its bounded run".to_owned(),
        )),
    };
    let cleanup_result = running.shutdown().await;

    let counters = match (run_result, cleanup_result) {
        (Ok(counters), Ok(())) => counters,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(cleanup)) => {
            return Err(HarnessError::Process(format!(
                "{error}; peer-fragmentation cleanup also failed: {cleanup}"
            )));
        }
    };

    let evidence = PeerFragmentationEvidence {
        relay_count: cluster.nodes.len(),
        authenticated_http3: counters.authenticated_http3,
        fragmented_prefix_cases: counters.fragmented_prefix_cases,
        fragmented_body_cases: counters.fragmented_body_cases,
        coalesced_records: counters.coalesced_records,
        empty_record_preserved: counters.empty_record_preserved,
        maximum_record_preserved: counters.maximum_record_preserved,
        exact_bytes: counters.exact_bytes,
        order_preserved: counters.order_preserved,
        malformed_cases: counters.malformed_cases,
        malformed_rejections: counters.malformed_rejections,
        malformed_dispatches: counters.malformed_dispatches,
        sibling_progress: counters.sibling_progress,
        budget_reclaimed: counters.budget_reclaimed,
        cleanup_joined: true,
    };
    evidence.validate()?;
    Ok(evidence)
}

async fn run_cases(running: &RunningFixture) -> Result<RunCounters> {
    let mut counters = RunCounters {
        exact_bytes: true,
        order_preserved: true,
        budget_reclaimed: true,
        ..RunCounters::default()
    };

    for split in 1..=7 {
        let envelope = envelope_for_case(running, format!("prefix-{split}"))?;
        let envelope_record = wire_record(PeerRecordKind::CompleteControlText, &envelope)?;
        let empty_record = wire_record(PeerRecordKind::ConsumerChunk, &[])?;
        let fragments = vec![
            envelope_record[..split].to_vec(),
            envelope_record[split..].to_vec(),
            empty_record,
        ];
        let result = run_valid_case(
            running,
            fragments,
            vec![(PeerRecordKind::ConsumerChunk, Vec::new())],
        )
        .await?;
        counters.fragmented_prefix_cases += 1;
        counters.empty_record_preserved |= result.exact_bytes;
        counters.authenticated_http3 |= result.accepted_request;
        counters.exact_bytes &= result.exact_bytes;
        counters.order_preserved &= result.order_preserved;
        counters.budget_reclaimed &= result.budget_reclaimed;
    }

    let envelope = envelope_for_case(running, "coalesced".to_owned())?;
    let envelope_record = wire_record(PeerRecordKind::CompleteControlText, &envelope)?;
    let coalesced = [
        wire_record(PeerRecordKind::ConsumerChunk, &[])?,
        wire_record(PeerRecordKind::ConsumerChunk, b"coalesced-a")?,
        wire_record(PeerRecordKind::ConsumerChunk, b"coalesced-b")?,
    ]
    .concat();
    let result = run_valid_case(
        running,
        vec![envelope_record, coalesced],
        vec![
            (PeerRecordKind::ConsumerChunk, Vec::new()),
            (PeerRecordKind::ConsumerChunk, b"coalesced-a".to_vec()),
            (PeerRecordKind::ConsumerChunk, b"coalesced-b".to_vec()),
        ],
    )
    .await?;
    counters.coalesced_records = 3;
    counters.empty_record_preserved |= result.exact_bytes;
    counters.authenticated_http3 |= result.accepted_request;
    counters.exact_bytes &= result.exact_bytes;
    counters.order_preserved &= result.order_preserved;
    counters.budget_reclaimed &= result.budget_reclaimed;

    let framed_body = framed_inner_body();
    let envelope = envelope_for_case(running, "four-byte-prefix".to_owned())?;
    let envelope_record = wire_record(PeerRecordKind::CompleteControlText, &envelope)?;
    let record = wire_record(PeerRecordKind::ConsumerChunk, &framed_body)?;
    let cuts = [1, 4, 7, 8, 9, 11, 12, 8 + 4 + 1, 8 + 4 + INNER_BODY_LEN / 2];
    let fragments = record_fragments(&envelope_record, &record, &cuts);
    let result = run_valid_case(
        running,
        fragments,
        vec![(PeerRecordKind::ConsumerChunk, framed_body)],
    )
    .await?;
    counters.fragmented_body_cases += 1;
    counters.authenticated_http3 |= result.accepted_request;
    counters.exact_bytes &= result.exact_bytes;
    counters.order_preserved &= result.order_preserved;
    counters.budget_reclaimed &= result.budget_reclaimed;

    // A malformed peer record may terminate the HTTP/3 connection.  Retire
    // the pooled connection before the first case and after every case so a
    // later case proves its own fresh authenticated stream rather than
    // inheriting a terminal connection state.
    close_malformed_connection(running, "preflight", "before malformed cases").await?;
    for malformed in malformed_cases(running)? {
        let before = dispatch_snapshot(&running.state).await;
        let rejected = run_malformed_case(running, malformed.name, malformed.fragments).await?;
        let after = dispatch_snapshot(&running.state).await;
        let dispatched = after.saturating_sub(before);
        counters.malformed_cases += 1;
        counters.malformed_rejections += usize::from(rejected);
        counters.malformed_dispatches += dispatched;
    }

    let maximum_body = vec![0xa5; MAX_CONSUMER_CHUNK_BODY];
    let envelope = envelope_for_case(running, "maximum-sibling".to_owned())?;
    let envelope_record = wire_record(PeerRecordKind::CompleteControlText, &envelope)?;
    let maximum_record = wire_record(PeerRecordKind::ConsumerChunk, &maximum_body)?;
    let mut fragments = vec![envelope_record];
    fragments.extend(
        maximum_record
            .chunks(tunnel_transport::DEFAULT_PEER_BODY_CHUNK_BYTES)
            .map(|chunk| chunk.to_vec()),
    );
    let result = run_valid_case(
        running,
        fragments,
        vec![(PeerRecordKind::ConsumerChunk, maximum_body)],
    )
    .await?;
    counters.fragmented_body_cases += 1;
    counters.maximum_record_preserved = result.exact_bytes;
    counters.sibling_progress = result.accepted_request && result.exact_bytes;
    counters.authenticated_http3 |= result.accepted_request;
    counters.exact_bytes &= result.exact_bytes;
    counters.order_preserved &= result.order_preserved;
    counters.budget_reclaimed &= result.budget_reclaimed;

    Ok(counters)
}

struct MalformedCase {
    name: &'static str,
    fragments: Vec<Vec<u8>>,
}

fn malformed_cases(running: &RunningFixture) -> Result<Vec<MalformedCase>> {
    let cases = [
        "malformed-unknown-kind",
        "malformed-flags",
        "malformed-reserved",
        "malformed-oversized",
        "malformed-truncated-prefix",
        "malformed-truncated-body",
        "malformed-utf8",
    ];
    let mut output = Vec::with_capacity(cases.len());
    for (index, name) in cases.into_iter().enumerate() {
        let envelope = envelope_for_case(running, name.to_owned())?;
        let envelope_record = wire_record(PeerRecordKind::CompleteControlText, &envelope)?;
        let malformed = match index {
            0 => {
                let invalid = raw_prefix(0, 0x7f, 0, 0);
                let valid_after = wire_record(PeerRecordKind::ConsumerChunk, b"must-not-dispatch")?;
                vec![envelope_record, [invalid, valid_after].concat()]
            }
            1 => vec![
                envelope_record,
                raw_prefix(1, PeerRecordKind::ConsumerChunk.code(), 1, 0),
            ],
            2 => vec![
                envelope_record,
                raw_prefix(1, PeerRecordKind::ConsumerChunk.code(), 0, 1),
            ],
            3 => vec![
                envelope_record,
                raw_prefix(
                    MAX_CONSUMER_CHUNK_BODY + 1,
                    PeerRecordKind::ConsumerChunk.code(),
                    0,
                    0,
                ),
            ],
            4 => {
                let prefix = raw_prefix(0, PeerRecordKind::ConsumerChunk.code(), 0, 0);
                vec![envelope_record, prefix[..3].to_vec()]
            }
            5 => {
                let prefix = raw_prefix(4, PeerRecordKind::ConsumerChunk.code(), 0, 0);
                vec![envelope_record, [prefix, vec![0x01, 0x02]].concat()]
            }
            6 => {
                let invalid = raw_prefix(1, PeerRecordKind::CompleteControlText.code(), 0, 0);
                vec![envelope_record, [invalid, vec![0xff]].concat()]
            }
            _ => unreachable!(),
        };
        output.push(MalformedCase {
            name,
            fragments: malformed,
        });
    }
    Ok(output)
}

async fn run_valid_case(
    running: &RunningFixture,
    fragments: Vec<Vec<u8>>,
    expected: Vec<(PeerRecordKind, Vec<u8>)>,
) -> Result<ValidCaseResult> {
    timeout(
        CASE_TIMEOUT,
        run_valid_case_inner(running, fragments, expected),
    )
    .await
    .map_err(|_| HarnessError::Timeout("peer-fragmentation valid case timed out".to_owned()))?
}

async fn run_valid_case_inner(
    running: &RunningFixture,
    fragments: Vec<Vec<u8>>,
    expected: Vec<(PeerRecordKind, Vec<u8>)>,
) -> Result<ValidCaseResult> {
    let before = state_snapshot(&running.state).await;
    let connection = running
        .client
        .connect(running.destination.clone())
        .await
        .map_err(|error| peer_http_error("connecting valid fragmentation case", error))?;
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "https://{SERVER_NAME}{}",
            PeerRuntime::path(InternalRoute::ConsumerStreams)
        ))
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(|error| {
            HarnessError::Http(format!("building peer-fragmentation request: {error}"))
        })?;
    let stream = connection
        .open(request)
        .await
        .map_err(|error| peer_http_error("opening valid fragmentation stream", error))?;
    let (mut send, mut recv) = stream.split();
    for fragment in fragments {
        send.send_chunk(Bytes::from(fragment))
            .await
            .map_err(|error| peer_http_error("sending valid fragmented body", error))?;
    }
    send.finish()
        .await
        .map_err(|error| peer_http_error("finishing valid fragmented body", error))?;

    let response = recv
        .recv_response()
        .await
        .map_err(|error| peer_http_error("receiving valid fragmentation response", error))?;
    if response.status() != StatusCode::OK {
        return Err(HarnessError::Http(format!(
            "valid peer-fragmentation case returned {}",
            response.status()
        )));
    }

    let connection_budget = ConnectionBudget::new();
    let stream_budget = connection_budget
        .open_stream()
        .map_err(|error| HarnessError::Http(format!("opening response decode budget: {error}")))?;
    let mut decoder = PeerRecordDecoder::new(stream_budget.clone());
    let mut records = Vec::new();
    while let Some(chunk) = recv
        .recv_chunk()
        .await
        .map_err(|error| peer_http_error("receiving valid response body", error))?
    {
        records.extend(
            decoder
                .push(chunk.as_bytes())
                .map_err(|error| peer_frame_error("decoding valid response records", error))?,
        );
    }
    decoder
        .finish()
        .map_err(|error| peer_frame_error("finishing valid response records", error))?;

    let exact_bytes = records.len() == expected.len()
        && records
            .iter()
            .zip(expected.iter())
            .all(|(actual, (kind, body))| actual.kind() == *kind && actual.body() == body);
    let order_preserved = records
        .iter()
        .map(|record| record.kind())
        .eq(expected.iter().map(|(kind, _)| *kind));
    drop(records);
    drop(decoder);
    drop(stream_budget);
    let budget_reclaimed =
        connection_budget.reserved_bytes() == 0 && connection_budget.active_streams() == 0;

    let after = state_snapshot(&running.state).await;
    let accepted_request = after.0 == before.0 + 1
        && after.1.len() == before.1.len() + expected.len()
        && expected.iter().enumerate().all(|(offset, (kind, body))| {
            after.1[before.1.len() + offset] == RecordDigest::of(*kind, body)
        });
    if !accepted_request {
        return Err(HarnessError::Http(
            "valid peer-fragmentation record was not dispatched exactly once".to_owned(),
        ));
    }

    Ok(ValidCaseResult {
        exact_bytes,
        order_preserved,
        accepted_request,
        budget_reclaimed,
    })
}

async fn run_malformed_case(
    running: &RunningFixture,
    case_name: &'static str,
    fragments: Vec<Vec<u8>>,
) -> Result<bool> {
    let result = match timeout(
        REJECTION_TIMEOUT,
        run_malformed_case_inner(running, fragments),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(format!(
            "malformed peer case `{case_name}` was not bounded"
        ))),
    };
    let cleanup = close_malformed_connection(running, case_name, "after case").await;
    match (result, cleanup) {
        (Ok(rejected), Ok(())) => Ok(rejected),
        (Err(error), Ok(())) => Err(HarnessError::Http(format!(
            "malformed peer case `{case_name}` failed before explicit rejection: {error}"
        ))),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(HarnessError::Process(format!(
            "malformed peer case `{case_name}` failed before explicit rejection: {error}; connection cleanup also failed: {cleanup}"
        ))),
    }
}

async fn close_malformed_connection(
    running: &RunningFixture,
    case_name: &str,
    phase: &str,
) -> Result<()> {
    timeout(
        CASE_TIMEOUT,
        running.client.close_peer(&running.destination),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout(format!(
            "malformed peer case `{case_name}` {phase} connection cleanup timed out"
        ))
    })?
    .map_err(|error| {
        peer_http_error(
            &format!("malformed peer case `{case_name}` {phase} connection cleanup"),
            error,
        )
    })
}

async fn run_malformed_case_inner(
    running: &RunningFixture,
    fragments: Vec<Vec<u8>>,
) -> Result<bool> {
    let connection = running
        .client
        .connect(running.destination.clone())
        .await
        .map_err(|error| peer_http_error("connecting malformed fragmentation case", error))?;
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "https://{SERVER_NAME}{}",
            PeerRuntime::path(InternalRoute::ConsumerStreams)
        ))
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(|error| HarnessError::Http(format!("building malformed peer request: {error}")))?;
    let stream = connection
        .open(request)
        .await
        .map_err(|error| peer_http_error("opening malformed fragmentation stream", error))?;
    let (mut send, mut recv) = stream.split();
    let mut rejected = false;
    for fragment in fragments {
        if send.send_chunk(Bytes::from(fragment)).await.is_err() {
            rejected = true;
            send.cancel();
            break;
        }
    }
    if !rejected && send.finish().await.is_err() {
        rejected = true;
        send.cancel();
    }

    match recv.recv_response().await {
        Ok(response) => {
            let mut body_error = false;
            loop {
                match recv.recv_chunk().await {
                    Ok(Some(_chunk)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        body_error = true;
                        break;
                    }
                }
            }
            // A clean 200 response followed by EOF is not a protocol
            // rejection.  Only an explicit non-OK response or a body-read
            // error proves that the malformed request failed closed.
            rejected = rejected || response.status() != StatusCode::OK || body_error;
        }
        Err(_) => rejected = true,
    }
    Ok(rejected)
}

fn start_fixture(
    cluster: &ClusterFixture,
    source_binding: VerifiedPeerBinding,
    owner_socket: std::net::UdpSocket,
) -> Result<RunningFixture> {
    let owner = cluster
        .node(OWNER_NODE_ID)
        .ok_or_else(|| HarnessError::InvalidInput("peer-fragmentation owner missing".to_owned()))?;
    let source = cluster.node(SOURCE_NODE_ID).ok_or_else(|| {
        HarnessError::InvalidInput("peer-fragmentation source missing".to_owned())
    })?;
    let owner_pin = spki_sha256_from_der(&owner.peer_certificate.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("owner peer SPKI: {error}")))?;
    let source_pin = spki_sha256_from_der(&source.peer_certificate.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("source peer SPKI: {error}")))?;
    let limits = PeerTransportLimits::default();

    let server_config = load_peer_server_config_from_pem(
        owner.peer_certificate_chain_pem().as_bytes(),
        owner.peer_certificate.private_key_pem.as_bytes(),
        owner.peer_ca_pem().as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("peer-fragmentation server TLS: {error}")))?;
    let server_endpoint = crate::cluster_fixture::quic_server_on(server_config, owner_socket)
        .map_err(|error| {
            HarnessError::Http(format!("binding peer-fragmentation server: {error}"))
        })?;

    let server_pins = SharedPeerPins::new(
        ApprovedPeerPins::new([source_pin])
            .map_err(|error| HarnessError::Http(format!("source peer pin set: {error}")))?,
    )
    .map_err(|error| HarnessError::Http(format!("source peer pin provider: {error}")))?;
    let owner_client = make_client(owner, &source_pin, limits.clone())?;
    let identity = RelayIdentity::new(
        cluster.deployment_incarnation.clone(),
        owner.node_id.clone(),
        owner.boot_id.clone(),
    )
    .map_err(|error| HarnessError::InvalidInput(format!("owner identity: {error}")))?;
    let catalog: SharedCatalog = Arc::new(MemoryCatalog::new());
    let router = OwnerRouter::new(catalog, identity)
        .map_err(|error| HarnessError::InvalidInput(format!("owner router: {error}")))?;
    let bindings: Arc<dyn PeerBindingProvider> = Arc::new(FixtureBindings {
        binding: source_binding,
    });
    let runtime = Arc::new(PeerRuntime::new(
        owner_client,
        Arc::new(router),
        bindings,
        owner.node_id.clone(),
        owner.boot_id.clone(),
    ));
    let state = Arc::new(Mutex::new(DispatchState::default()));
    let callback_state = state.clone();
    let callback = move |request: InboundPeerRequest| {
        let state = callback_state.clone();
        async move { owner_echo(request, state).await }
    };
    let (policy, handler) = runtime.server_components(callback);
    let server = PeerServer::new_with_pin_provider(
        server_endpoint,
        server_pins,
        limits.clone(),
        policy,
        handler,
    )
    .map_err(|error| HarnessError::Http(format!("peer-fragmentation server: {error}")))?;
    let client = make_client(source, &owner_pin, limits)?;
    let destination = PeerDestination::new(owner.addresses.udp, SERVER_NAME);
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    Ok(RunningFixture {
        client,
        destination,
        runtime,
        owner_boot_id: owner.boot_id.clone(),
        source_boot_id: source.boot_id.clone(),
        deployment_incarnation: cluster.deployment_incarnation.clone(),
        cancel,
        server_task,
        state,
    })
}

async fn owner_echo(
    request: InboundPeerRequest,
    state: Arc<Mutex<DispatchState>>,
) -> std::result::Result<(), PeerRuntimeError> {
    if request.envelope().route != InternalRoute::ConsumerStreams
        || request.envelope().request.route() != InternalRoute::ConsumerStreams
    {
        return Err(PeerRuntimeError::InvalidRoute(request.envelope().route));
    }
    let (mut send, mut recv) = request.split();
    let Some(first) = recv.recv_message().await? else {
        return Err(PeerRuntimeError::Closed);
    };
    if first.kind() != PeerRecordKind::ConsumerChunk {
        return Err(PeerRuntimeError::UnexpectedRecord(first.kind()));
    }
    accepted_dispatch(&state, &first).await;
    send.respond(StatusCode::OK).await?;
    send.send_message(first.kind(), first.body()).await?;
    while let Some(record) = recv.recv_message().await? {
        if record.kind() != PeerRecordKind::ConsumerChunk {
            return Err(PeerRuntimeError::UnexpectedRecord(record.kind()));
        }
        record_dispatch(&state, &record).await;
        send.send_message(record.kind(), record.body()).await?;
    }
    send.finish().await
}

async fn record_dispatch(
    state: &Arc<Mutex<DispatchState>>,
    record: &tunnel_cluster::peer_frame::PeerRecord,
) {
    let mut state = state.lock().await;
    state
        .records
        .push(RecordDigest::of(record.kind(), record.body()));
}

async fn accepted_dispatch(
    state: &Arc<Mutex<DispatchState>>,
    record: &tunnel_cluster::peer_frame::PeerRecord,
) {
    let mut state = state.lock().await;
    state.accepted_requests += 1;
    state
        .records
        .push(RecordDigest::of(record.kind(), record.body()));
}

fn make_client(
    node: &crate::cluster_fixture::RelayNodeFixture,
    approved_pin: &tunnel_transport::SpkiSha256,
    limits: PeerTransportLimits,
) -> Result<PeerClient> {
    let mut endpoint =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).map_err(|error| {
            HarnessError::Http(format!("binding peer-fragmentation client: {error}"))
        })?;
    let config = load_peer_client_config_from_pem(
        node.peer_certificate_chain_pem().as_bytes(),
        node.peer_certificate.private_key_pem.as_bytes(),
        node.peer_ca_pem().as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("peer-fragmentation client TLS: {error}")))?;
    endpoint.set_default_client_config(config);
    let pins = ApprovedPeerPins::new([*approved_pin])
        .map_err(|error| HarnessError::Http(format!("peer-fragmentation client pins: {error}")))?;
    let pin_provider = SharedPeerPins::new(pins).map_err(|error| {
        HarnessError::Http(format!("peer-fragmentation client pin provider: {error}"))
    })?;
    PeerClient::new_with_pin_provider(endpoint, pin_provider, limits)
        .map_err(|error| HarnessError::Http(format!("peer-fragmentation client: {error}")))
}

fn verified_binding(cluster: &ClusterFixture, node_id: &str) -> Result<VerifiedPeerBinding> {
    let ports = cluster.nodes.iter().map(|node| node.addresses.udp.port());
    let endpoint_policy = PrivateEndpointPolicy::allowlisted(["127.0.0.1"], [SERVER_NAME], ports)
        .map_err(|error| {
        HarnessError::InvalidInput(format!("fragmentation endpoint policy: {error}"))
    })?;
    let policy = MembershipPolicy::new(
        &cluster.deployment_id,
        &cluster.deployment_incarnation,
        endpoint_policy,
    )
    .map_err(|error| {
        HarnessError::InvalidInput(format!("fragmentation membership policy: {error}"))
    })?;
    let trusted = cluster.membership_authority.trusted_key()?;
    let mut verifier = MembershipVerifier::new(policy, [trusted])
        .map_err(|error| HarnessError::InvalidInput(format!("fragmentation verifier: {error}")))?;
    let now = Utc::now();
    verifier
        .verify_checkpoint(
            cluster.checkpoint.encoded_bytes(),
            &cluster.checkpoint.payload.nonce,
            now,
        )
        .map_err(|error| {
            HarnessError::InvalidInput(format!("fragmentation checkpoint: {error}"))
        })?;
    for membership in cluster.memberships.values() {
        verifier
            .verify_membership(membership.encoded_bytes(), now)
            .map_err(|error| {
                HarnessError::InvalidInput(format!("fragmentation membership: {error}"))
            })?;
    }
    let node = cluster.node(node_id).ok_or_else(|| {
        HarnessError::InvalidInput(format!("missing fragmentation node {node_id}"))
    })?;
    let spki = node.peer_spki_fingerprint()?;
    verifier
        .bind_peer(&node.node_id, &node.boot_id, &spki, now)
        .map_err(|error| HarnessError::InvalidInput(format!("fragmentation peer binding: {error}")))
}

fn envelope_for_case(running: &RunningFixture, request_id: String) -> Result<Vec<u8>> {
    let token = OwnerToken {
        deployment_incarnation: running.deployment_incarnation.clone(),
        tenant_id: uuid::Uuid::from_u128(0x11111111111111111111111111111111),
        device_id: uuid::Uuid::from_u128(0x22222222222222222222222222222222),
        node_id: OWNER_NODE_ID.to_owned(),
        boot_id: running.owner_boot_id.clone(),
        session_id: "fragmentation-owner-session".to_owned(),
        epoch: 1,
    };
    let service_id = uuid::Uuid::from_u128(0x33333333333333333333333333333333);
    let destination = Destination::new(token.clone(), service_id);
    let bearer = ForwardedConsumerBearer::new("fragmentation-bearer", token)
        .map_err(|error| HarnessError::InvalidInput(format!("fragmentation bearer: {error}")))?;
    let request = InternalRequest::ConsumerStreams(ConsumerStreamsRequest {
        stream_id: format!("stream-{request_id}"),
        required_scope: "echo:invoke".to_owned(),
        bearer,
        bytes: Vec::new(),
    });
    let envelope = RequestEnvelope::new(
        InternalRoute::ConsumerStreams,
        request_id,
        PeerIdentity::new(SOURCE_NODE_ID, running.source_boot_id.clone()),
        destination,
        5_000,
        Some(5_000),
        request,
    );
    envelope.encode().map_err(|error| {
        HarnessError::InvalidInput(format!("encoding fragmentation envelope: {error}"))
    })
}

fn wire_record(kind: PeerRecordKind, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > kind.max_body() {
        return Err(HarnessError::InvalidInput(format!(
            "fragmentation test body {} exceeds {:?} limit {}",
            body.len(),
            kind,
            kind.max_body()
        )));
    }
    let length = u32::try_from(body.len())
        .map_err(|_| HarnessError::InvalidInput("fragmentation body length overflow".to_owned()))?;
    let mut record = Vec::with_capacity(PREFIX_LEN + body.len());
    record.extend_from_slice(&length.to_be_bytes());
    record.push(kind.code());
    record.push(0);
    record.extend_from_slice(&0_u16.to_be_bytes());
    record.extend_from_slice(body);
    Ok(record)
}

fn raw_prefix(body_len: usize, kind: u8, flags: u8, reserved: u16) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(PREFIX_LEN);
    prefix.extend_from_slice(&(body_len as u32).to_be_bytes());
    prefix.push(kind);
    prefix.push(flags);
    prefix.extend_from_slice(&reserved.to_be_bytes());
    prefix
}

fn record_fragments(envelope: &[u8], record: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
    let mut fragments = vec![envelope.to_vec()];
    let mut start = 0;
    for &cut in cuts {
        if cut > start && cut < record.len() {
            fragments.push(record[start..cut].to_vec());
            start = cut;
        }
    }
    if start < record.len() {
        fragments.push(record[start..].to_vec());
    }
    fragments
}

fn framed_inner_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + INNER_BODY_LEN);
    body.extend_from_slice(&(INNER_BODY_LEN as u32).to_be_bytes());
    body.extend(vec![0x5a; INNER_BODY_LEN]);
    body
}

async fn state_snapshot(state: &Arc<Mutex<DispatchState>>) -> (usize, Vec<RecordDigest>) {
    let state = state.lock().await;
    (state.accepted_requests, state.records.clone())
}

async fn dispatch_snapshot(state: &Arc<Mutex<DispatchState>>) -> usize {
    state.lock().await.records.len()
}

fn peer_http_error(context: &str, error: impl std::fmt::Display) -> HarnessError {
    HarnessError::Http(format!("{context}: {error}"))
}

fn peer_frame_error(context: &str, error: PeerFrameError) -> HarnessError {
    HarnessError::Http(format!("{context}: {error}"))
}

#[cfg(test)]
mod c17_validator_tests {
    use super::PeerFragmentationEvidence;
    use crate::acceptance_test_support::assert_failed;

    fn valid_evidence() -> PeerFragmentationEvidence {
        PeerFragmentationEvidence {
            relay_count: 3,
            authenticated_http3: true,
            fragmented_prefix_cases: 7,
            fragmented_body_cases: 2,
            coalesced_records: 3,
            empty_record_preserved: true,
            maximum_record_preserved: true,
            exact_bytes: true,
            order_preserved: true,
            malformed_cases: 7,
            malformed_rejections: 7,
            malformed_dispatches: 0,
            sibling_progress: true,
            budget_reclaimed: true,
            cleanup_joined: true,
        }
    }

    #[test]
    fn every_fragmentation_flag_and_count_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut PeerFragmentationEvidence));
        let cases: [Mutate; 15] = [
            ("relay_count", |e| e.relay_count = 2),
            ("authenticated_http3", |e| e.authenticated_http3 = false),
            ("fragmented_prefix_cases", |e| e.fragmented_prefix_cases = 6),
            ("fragmented_body_cases", |e| e.fragmented_body_cases = 1),
            ("coalesced_records", |e| e.coalesced_records = 2),
            ("empty_record_preserved", |e| {
                e.empty_record_preserved = false
            }),
            ("maximum_record_preserved", |e| {
                e.maximum_record_preserved = false
            }),
            ("exact_bytes", |e| e.exact_bytes = false),
            ("order_preserved", |e| e.order_preserved = false),
            ("malformed_cases", |e| e.malformed_cases = 6),
            ("malformed_rejections", |e| e.malformed_rejections = 6),
            ("malformed_dispatches", |e| e.malformed_dispatches = 1),
            ("sibling_progress", |e| e.sibling_progress = false),
            ("budget_reclaimed", |e| e.budget_reclaimed = false),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (_, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(evidence.validate());
            assert!(diagnostic.contains("peer-fragmentation"));
        }
    }

    #[test]
    fn fragmentation_validator_accepts_complete_evidence() {
        valid_evidence()
            .validate()
            .expect("complete peer-fragmentation evidence is valid");
    }
}
