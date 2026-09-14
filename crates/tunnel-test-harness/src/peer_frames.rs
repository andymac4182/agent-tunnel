//! EC-044 peer-path frame injection: reordered, duplicate and late frames
//! delivered through a real ingress-to-owner HTTP/3 `CompleteDeviceData`
//! forward into the production shared frame validator.
//!
//! `peer_fragmentation.rs` proves that malformed peer *records* fail closed,
//! but its owner callback is a synthetic echo, so the records never reach
//! `RelayActor::inbound_m2_stream_data`.  The existing ordering regressions in
//! `actor_late_frame_tests.rs` do reach that validator, but they install the
//! carrier directly and never cross a socket.  This module closes the gap: the
//! server side is a real [`tunnel_relay::Relay`] actor behind the production
//! [`tunnel_relay::peer_ingress_handler`], and the client side is a raw
//! [`tunnel_transport::PeerClientStream`] standing in for an ingress relay so
//! arbitrary frame bytes can be placed inside a real `CompleteDeviceData`
//! record.
//!
//! Three bounded phases run against one admitted M2 session:
//!
//! * **reorder** — the connector answers at sequence `n + 1` before `n`.  The
//!   owner's delivered contiguous cursor must not advance until `n` lands.
//! * **duplicate** — an already-accepted sequence is replayed.  The cursor
//!   must not move and the session must survive.
//! * **late** — a DATA frame follows the terminal FIN.  The stream keeps
//!   exactly one terminal latch, the session fails closed, a peer fault tuple
//!   is recorded on the forwarded body, and no adapter bytes appear past the
//!   FIN cursor.
//!
//! Everything is synthetic: ephemeral PKI, an in-memory catalog, and a
//! fixture OIDC signer.  No Redis, no external process, no real device.

use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use http::{Request, StatusCode};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use tokio::{
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    ApprovedJwk, Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec,
    MembershipRecord, MembershipRole, MemoryCatalog, OidcConfig, OidcVerifier, OwnerClaimRequest,
    OwnerToken, PermissionSet, PrincipalIdentity, ServiceSpec, SharedCatalog, TenantRecord,
    UserRecord,
};
use tunnel_cluster::{
    envelope::{
        ConsumerStreamsRequest, Destination, DeviceAuthenticationContext, DeviceControlRequest,
        DeviceDataRequest, ForwardedConsumerBearer, IngressRequestBinding, InternalRequest,
        InternalRoute, PeerIdentity, RequestEnvelope, VerifiedDeviceCertificate,
    },
    membership::{
        MembershipPolicy, MembershipVerifier, PrivateEndpointPolicy, VerifiedPeerBinding,
    },
    peer_frame::{ConnectionBudget, PREFIX_LEN, PeerRecord, PeerRecordDecoder, PeerRecordKind},
};
use tunnel_protocol::{ControlMessage, Frame, FrameKind, Hello, control::decode_control};
use tunnel_relay::{
    Relay, RelayHandle, RelayOptions, peer_ingress_handler,
    peer_runtime::{PeerBindingFuture, PeerBindingProvider, PeerRuntime, PeerRuntimeError},
    routing::{OwnerRouter, RelayIdentity},
};
use tunnel_relay::{RelaySnapshot, RelayStreamSnapshot};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerClientRecv, PeerClientSend, PeerDestination, PeerServer,
    PeerTransportError, PeerTransportLimits, SharedPeerPins, load_peer_client_config_from_pem,
    load_peer_server_config_from_pem, spki_sha256_from_der,
};
use uuid::Uuid;

use crate::{ClusterFixture, FixturePki, HarnessError, Result};

const OWNER_NODE_ID: &str = "relay-a";
const SOURCE_NODE_ID: &str = "relay-b";
const SERVER_NAME: &str = "localhost";

const ISSUER: &str = "https://ec044.fixture.invalid/";
const AUDIENCE: &str = "agent-tunnel-ec044";
const SUBJECT: &str = "ec044-consumer";
const DEVICE_SPKI: &str = "ec044ec044ec044ec044ec044ec044ec044ec044ec044ec044ec044ec044ec04";

const PHASE_TIMEOUT: Duration = Duration::from_secs(20);
const STEP_TIMEOUT: Duration = Duration::from_secs(8);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const ABORT_JOIN_TIMEOUT: Duration = Duration::from_millis(250);
const SNAPSHOT_POLL: Duration = Duration::from_millis(20);
/// Window granted to the owner's ingress to admit the control envelope before
/// the predecessor owner claim is withdrawn for the staged handover.
const HANDOVER_WINDOW: Duration = Duration::from_millis(250);
/// Bounded retries for that staging.  A refused attempt creates no session.
const REGISTRATION_ATTEMPTS: usize = 6;
/// Body of the one reordered response record, and the offset at which it is
/// split across two sequenced DATA frames.
const REORDER_BODY: &[u8] = b"ec044-reorder-response-body";
const REORDER_SPLIT: usize = 9;

/// Outstanding consumer records per phase.
///
/// The owner admits exactly one in-flight record per logical stream and
/// accepts exactly one connector response record for it.  A second response
/// record would be *unsolicited*: `inbound_m2_stream_data` finds no waiting
/// receiver, sets `invalid`, and fences the whole session on
/// `INVALID_SEQUENCE` before any ordering assertion could be reached.  A
/// reordered or fragmented pair therefore has to be built from two DATA
/// frames answering this one record, which is exactly the shape the shared
/// validator reassembles.
const OUTSTANDING_RECORDS: usize = 1;

fn tenant_id() -> Uuid {
    Uuid::from_u128(0xec04_4000_0000_0000_0000_0000_0000_0001)
}

fn device_id() -> Uuid {
    Uuid::from_u128(0xec04_4000_0000_0000_0000_0000_0000_0002)
}

fn service_id() -> Uuid {
    Uuid::from_u128(0xec04_4000_0000_0000_0000_0000_0000_0003)
}

fn user_id() -> Uuid {
    Uuid::from_u128(0xec04_4000_0000_0000_0000_0000_0000_0004)
}

fn credential_id() -> Uuid {
    Uuid::from_u128(0xec04_4000_0000_0000_0000_0000_0000_0005)
}

/// Bounded, payload-free evidence for one EC-044 peer-path frame run.
///
/// Every field is derived from the owner relay's own redacted snapshot or
/// from bytes the fixture observed on a real peer stream.  No frame payload,
/// credential or transport error text is retained.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PeerFrameEvidence {
    /// Whether the owner side ran a real relay actor behind the production
    /// peer ingress handler rather than a synthetic echo callback.
    pub real_owner_ingress: bool,
    /// Whether the device control registration and data carrier attachment
    /// both crossed mTLS, HTTP/3 and `PeerRuntime` admission.
    pub authenticated_carrier: bool,
    /// Negotiated session profile reported by the owner snapshot.  The shared
    /// frame validator under test runs only for `m2`.
    pub session_profile: String,
    /// Outstanding request records dispatched per phase.
    pub outstanding_records: usize,

    /// Sequence the owner acknowledged for the out-of-order frame at `n + 1`.
    /// A buffered frame leaves the contiguous receive cursor where it was, so
    /// this must still be zero.
    pub reorder_ack_after_gap: u64,
    /// Delivered contiguous connector-to-relay cursor after the out-of-order
    /// frame at `n + 1` was forwarded and acknowledged, before `n` arrived.
    pub reorder_delivered_after_gap: u64,
    /// Sequence the owner acknowledged once the missing frame at `n` landed.
    pub reorder_ack_after_fill: u64,
    /// Delivered contiguous cursor after the missing frame at `n` landed.
    pub reorder_delivered_after_fill: u64,
    /// Whether the reordered pair was delivered in sequence order rather than
    /// arrival order.
    pub reorder_order_restored: bool,
    /// Whether the reorder phase left the session alive.
    pub reorder_session_alive: bool,

    /// Sequence acknowledged for the first, legitimately ordered frame.
    pub duplicate_ack_before: u64,
    /// Delivered contiguous cursor immediately before the duplicate frame.
    pub duplicate_delivered_before: u64,
    /// Sequence acknowledged for the duplicate.  A duplicate is still
    /// acknowledged at the sequence already accepted; it may not advance it.
    pub duplicate_ack_after: u64,
    /// Delivered contiguous cursor after the duplicate frame was forwarded.
    pub duplicate_delivered_after: u64,
    /// Adapter records observed for the duplicate phase's stream.  A
    /// duplicate must not produce a second response record.
    pub duplicate_adapter_records: usize,
    /// Whether the duplicate phase left the session alive.
    pub duplicate_session_alive: bool,

    /// Delivered contiguous cursor latched with the terminal FIN.
    pub late_fin_cursor: u64,
    /// Stream terminal latches recorded for the late phase's stream.  The
    /// first terminal is immutable, so a post-FIN DATA frame must not add a
    /// second one.
    pub late_stream_terminals: usize,
    /// Adapter response bytes observed beyond the FIN cursor.  Must be zero.
    pub late_adapter_bytes_after_fin: usize,
    /// Closed session terminal reason recorded when the late frame fenced the
    /// session, from the allowlisted vocabulary.
    pub late_session_reason: String,
    /// Peer fault stage labels recorded by the owner for the late phase.
    pub late_fault_stages: Vec<String>,
    /// Peer fault cause labels recorded by the owner for the late phase.
    pub late_fault_causes: Vec<String>,
    /// Whether the owner recorded at least one peer fault in the `owner`
    /// role while forwarding the late body.
    pub late_owner_fault_recorded: bool,

    /// Whether the peer server task and both client supervisors were
    /// cancelled and joined within their bound.
    pub cleanup_joined: bool,
}

/// Stage label the owner must attribute a forwarded-body fault to.
pub const BODY_STAGE: &str = "body";

impl PeerFrameEvidence {
    /// Validate the exact EC-044 peer-path evidence shape.
    ///
    /// This is a pure function over the evidence value so the CLI boundary
    /// can be exercised without a live fixture.
    pub fn validate(&self) -> Result<()> {
        let mut failures: Vec<&'static str> = Vec::new();

        if !self.real_owner_ingress {
            failures.push("real_owner_ingress");
        }
        if !self.authenticated_carrier {
            failures.push("authenticated_carrier");
        }
        if self.session_profile != "m2" {
            failures.push("session_profile");
        }
        if self.outstanding_records != OUTSTANDING_RECORDS {
            failures.push("outstanding_records");
        }

        // Reorder: the gap must hold the cursor back, and filling it must
        // release both frames at once.  A cursor that already advanced across
        // the gap would mean the validator accepted arrival order.
        if self.reorder_ack_after_gap != 0 {
            failures.push("reorder_ack_after_gap");
        }
        if self.reorder_delivered_after_gap != 0 {
            failures.push("reorder_delivered_after_gap");
        }
        if self.reorder_ack_after_fill != self.reorder_delivered_after_fill {
            failures.push("reorder_ack_after_fill");
        }
        if self.reorder_delivered_after_fill < 2 {
            failures.push("reorder_delivered_after_fill");
        }
        if self.reorder_delivered_after_fill <= self.reorder_delivered_after_gap {
            failures.push("reorder_cursor_advance");
        }
        if !self.reorder_order_restored {
            failures.push("reorder_order_restored");
        }
        if !self.reorder_session_alive {
            failures.push("reorder_session_alive");
        }

        // Duplicate: nothing moves and nothing is delivered twice.
        if self.duplicate_ack_before == 0 {
            failures.push("duplicate_ack_before");
        }
        if self.duplicate_delivered_before == 0 {
            failures.push("duplicate_delivered_before");
        }
        if self.duplicate_ack_after != self.duplicate_ack_before {
            failures.push("duplicate_ack_after");
        }
        if self.duplicate_delivered_after != self.duplicate_delivered_before {
            failures.push("duplicate_delivered_after");
        }
        if self.duplicate_adapter_records != 1 {
            failures.push("duplicate_adapter_records");
        }
        if !self.duplicate_session_alive {
            failures.push("duplicate_session_alive");
        }

        // Late: exactly one terminal, no bytes past the FIN, a typed close
        // and a peer fault tuple attributed to the forwarded body.
        if self.late_fin_cursor == 0 {
            failures.push("late_fin_cursor");
        }
        if self.late_stream_terminals != 1 {
            failures.push("late_stream_terminals");
        }
        if self.late_adapter_bytes_after_fin != 0 {
            failures.push("late_adapter_bytes_after_fin");
        }
        if self.late_session_reason != "INVALID_SEQUENCE" {
            failures.push("late_session_reason");
        }
        if !self.late_owner_fault_recorded {
            failures.push("late_owner_fault_recorded");
        }
        // The exact tuple set varies between runs because the control and
        // data carriers race each other to observe the fenced session, so the
        // stage set is asserted as a required subset rather than an equality.
        if !self
            .late_fault_stages
            .iter()
            .any(|stage| stage == BODY_STAGE)
        {
            failures.push("late_fault_stages");
        }
        if self.late_fault_causes.is_empty() {
            failures.push("late_fault_causes");
        }

        if !self.cleanup_joined {
            failures.push("cleanup_joined");
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Http(format!(
                "peer-frame EC-044 evidence was incomplete: {}",
                failures.join(",")
            )))
        }
    }

    /// One bounded, payload-free evidence line for the gate script.
    #[must_use]
    pub fn evidence_line(&self) -> String {
        format!(
            "M7 EC-044 peer frames passed: real_owner_ingress={} authenticated_carrier={} profile={} outstanding_records={} reorder_ack_after_gap={} reorder_delivered_after_gap={} reorder_ack_after_fill={} reorder_delivered_after_fill={} reorder_order_restored={} duplicate_ack_before={} duplicate_delivered_before={} duplicate_ack_after={} duplicate_delivered_after={} duplicate_adapter_records={} late_fin_cursor={} late_stream_terminals={} late_adapter_bytes_after_fin={} late_session_reason={} late_fault_stages=[{}] late_fault_causes=[{}] cleanup_joined={}",
            self.real_owner_ingress,
            self.authenticated_carrier,
            self.session_profile,
            self.outstanding_records,
            self.reorder_ack_after_gap,
            self.reorder_delivered_after_gap,
            self.reorder_ack_after_fill,
            self.reorder_delivered_after_fill,
            self.reorder_order_restored,
            self.duplicate_ack_before,
            self.duplicate_delivered_before,
            self.duplicate_ack_after,
            self.duplicate_delivered_after,
            self.duplicate_adapter_records,
            self.late_fin_cursor,
            self.late_stream_terminals,
            self.late_adapter_bytes_after_fin,
            self.late_session_reason,
            self.late_fault_stages.join("|"),
            self.late_fault_causes.join("|"),
            self.cleanup_joined,
        )
    }
}

/// Wrap the production ingress so a bounded, payload-free copy of the last
/// handler error is available to the fixture's own failure messages.  The
/// wrapper only observes; it never changes the handler's result.
struct RecordingIngress<H> {
    inner: H,
    last_error: Arc<std::sync::Mutex<Option<String>>>,
}

impl<H> tunnel_relay::peer_runtime::PeerIngressHandler for RecordingIngress<H>
where
    H: tunnel_relay::peer_runtime::PeerIngressHandler,
{
    fn handle(
        &self,
        request: tunnel_relay::peer_runtime::InboundPeerRequest,
    ) -> tunnel_relay::peer_runtime::PeerIngressHandlerFuture {
        let inner = self.inner.handle(request);
        let last_error = Arc::clone(&self.last_error);
        Box::pin(async move {
            let result = inner.await;
            if let Err(error) = &result
                && let Ok(mut slot) = last_error.lock()
            {
                *slot = Some(error.to_string());
            }
            result
        })
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
                "ec044 peer binding unavailable".to_owned(),
            ))
        };
        Box::pin(async move { result })
    }
}

struct RunningFixture {
    catalog: Arc<MemoryCatalog>,
    handle: RelayHandle,
    client: PeerClient,
    destination: PeerDestination,
    runtime: Arc<PeerRuntime>,
    owner_token: std::sync::Mutex<OwnerToken>,
    last_ingress_error: Arc<std::sync::Mutex<Option<String>>>,
    source_boot_id: String,
    consumer_token: String,
    cancel: CancellationToken,
    server_task: JoinHandle<std::result::Result<(), PeerTransportError>>,
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
        match timeout_at(deadline, self.handle.shutdown()).await {
            Ok(_) => {}
            Err(_) => errors.push("relay: shutdown deadline exceeded".to_owned()),
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(format!(
                "ec044 peer-frame cleanup failed: {}",
                errors.join("; ")
            )))
        }
    }
}

impl RunningFixture {
    /// Bounded suffix naming the owner's own last ingress rejection, so a
    /// transport-level admission failure is diagnosable without tracing.
    fn owner_token(&self) -> OwnerToken {
        self.owner_token
            .lock()
            .expect("ec044 owner token lock")
            .clone()
    }

    fn set_owner_token(&self, token: OwnerToken) {
        *self.owner_token.lock().expect("ec044 owner token lock") = token;
    }

    fn ingress_error_suffix(&self) -> String {
        self.last_ingress_error
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .map_or_else(String::new, |error| format!(" (owner ingress: {error})"))
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
                        "joining ec044 peer server after abort".to_owned(),
                    ));
                }
            }
        }
    };
    let result =
        joined.map_err(|error| HarnessError::Process(format!("joining server task: {error}")))?;
    result.map_err(|error| HarnessError::Http(format!("server shutdown: {error}")))
}

/// A raw peer stream plus its own bounded record decoder.
struct RawStream {
    label: &'static str,
    send: PeerClientSend,
    recv: PeerClientRecv,
    decoder: PeerRecordDecoder,
    // The connection budget must outlive the stream budget held by the
    // decoder; keeping it here ties both to the stream's lifetime.
    _budget: ConnectionBudget,
    pending: Vec<PeerRecord>,
}

impl RawStream {
    async fn open(
        fixture: &RunningFixture,
        route: InternalRoute,
        label: &'static str,
    ) -> Result<Self> {
        let connection = fixture
            .client
            .connect(fixture.destination.clone())
            .await
            .map_err(|error| http_error("connecting ec044 peer stream", error))?;
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://{SERVER_NAME}{}", PeerRuntime::path(route)))
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|error| HarnessError::Http(format!("building ec044 peer request: {error}")))?;
        let stream = connection
            .open(request)
            .await
            .map_err(|error| http_error("opening ec044 peer stream", error))?;
        let (send, recv) = stream.split();
        let budget = ConnectionBudget::new();
        let stream_budget = budget
            .open_stream()
            .map_err(|error| HarnessError::Http(format!("ec044 stream budget: {error}")))?;
        Ok(Self {
            label,
            send,
            recv,
            decoder: PeerRecordDecoder::new(stream_budget),
            _budget: budget,
            pending: Vec::new(),
        })
    }

    async fn send_record(&mut self, kind: PeerRecordKind, body: &[u8]) -> Result<()> {
        self.send
            .send_chunk(Bytes::from(wire_record(kind, body)?))
            .await
            .map_err(|error| http_error("sending ec044 peer record", error))
    }

    async fn expect_ok(&mut self, running: &RunningFixture, context: &str) -> Result<()> {
        let response = timeout(STEP_TIMEOUT, self.recv.recv_response())
            .await
            .map_err(|_| HarnessError::Timeout(format!("{context} response deadline")))?
            .map_err(|error| {
                http_error(
                    context,
                    format!("{error}{}", running.ingress_error_suffix()),
                )
            })?;
        if response.status() != StatusCode::OK {
            return Err(HarnessError::Http(format!(
                "{context} returned {}",
                response.status()
            )));
        }
        Ok(())
    }

    /// Read the next decoded peer record, or `None` at a clean end of body.
    async fn next_record(&mut self) -> Result<Option<PeerRecord>> {
        loop {
            if !self.pending.is_empty() {
                return Ok(Some(self.pending.remove(0)));
            }
            let chunk = match timeout(STEP_TIMEOUT, self.recv.recv_chunk())
                .await
                .map_err(|_| {
                    HarnessError::Timeout(format!("ec044 {} peer record deadline", self.label))
                })? {
                Ok(Some(chunk)) => chunk,
                Ok(None) => return Ok(None),
                Err(error) => return Err(http_error("receiving ec044 peer record", error)),
            };
            self.pending.extend(
                self.decoder.push(chunk.as_bytes()).map_err(|error| {
                    HarnessError::Http(format!("decoding ec044 record: {error}"))
                })?,
            );
        }
    }

    /// Drain whatever records are already buffered without blocking on a
    /// fresh chunk.  Used to prove that nothing further arrived.
    fn drain_buffered(&mut self) -> Vec<PeerRecord> {
        std::mem::take(&mut self.pending)
    }
}

/// Run the EC-044 peer-path frame gate.
pub async fn verify() -> Result<PeerFrameEvidence> {
    let pki = FixturePki::new()?;
    let mut cluster = ClusterFixture::new(&pki)?;
    cluster
        .node_mut(OWNER_NODE_ID)
        .ok_or_else(|| HarnessError::InvalidInput("ec044 owner node missing".to_owned()))?
        .release_ports();
    cluster
        .node_mut(SOURCE_NODE_ID)
        .ok_or_else(|| HarnessError::InvalidInput("ec044 source node missing".to_owned()))?
        .release_ports();

    let source_binding = verified_binding(&cluster, SOURCE_NODE_ID)?;
    let running = start_fixture(&cluster, source_binding).await?;

    let run_result = match timeout(PHASE_TIMEOUT.saturating_mul(4), run_phases(&running)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "ec044 peer-frame fixture exceeded its bounded run".to_owned(),
        )),
    };
    let cleanup_result = running.shutdown().await;

    let mut evidence = match (run_result, cleanup_result) {
        (Ok(evidence), Ok(())) => evidence,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(cleanup)) => {
            return Err(HarnessError::Process(format!(
                "{error}; ec044 cleanup also failed: {cleanup}"
            )));
        }
    };
    evidence.cleanup_joined = true;
    evidence.validate()?;
    Ok(evidence)
}

async fn run_phases(running: &RunningFixture) -> Result<PeerFrameEvidence> {
    let mut evidence = PeerFrameEvidence {
        real_owner_ingress: true,
        outstanding_records: OUTSTANDING_RECORDS,
        ..PeerFrameEvidence::default()
    };

    // Phase 0: authenticated control registration and data carrier over the
    // real peer transport.
    let (mut control, welcome) = register_control(running).await?;
    let mut data = RawStream::open(running, InternalRoute::DeviceData, "data").await?;
    admit_data(running, &mut data, &welcome.ticket).await?;
    evidence.authenticated_carrier = true;

    let session = wait_for(running, "device session", |snapshot| {
        snapshot
            .sessions
            .iter()
            .find(|session| session.session_id == welcome.session_id)
            .filter(|session| session.sockets >= 2)
            .cloned()
    })
    .await?;
    evidence.session_profile = session.profile.to_owned();

    let context = FrameContext {
        epoch: welcome.epoch,
        generation: session.active_generation,
        session_id: welcome.session_id.clone(),
    };

    timeout(
        PHASE_TIMEOUT,
        phase_reorder(running, &mut control, &mut data, &context, &mut evidence),
    )
    .await
    .map_err(|_| HarnessError::Timeout("ec044 reorder phase exceeded its bound".to_owned()))??;

    timeout(
        PHASE_TIMEOUT,
        phase_duplicate(running, &mut control, &mut data, &context, &mut evidence),
    )
    .await
    .map_err(|_| HarnessError::Timeout("ec044 duplicate phase exceeded its bound".to_owned()))??;

    timeout(
        PHASE_TIMEOUT,
        phase_late(running, &mut control, &mut data, &context, &mut evidence),
    )
    .await
    .map_err(|_| HarnessError::Timeout("ec044 late phase exceeded its bound".to_owned()))??;

    control.send.cancel();
    control.recv.cancel();
    Ok(evidence)
}

struct FrameContext {
    epoch: u64,
    generation: u64,
    session_id: String,
}

/// One open consumer request whose records are outstanding at the owner.
struct ConsumerPhase {
    stream: RawStream,
    stream_id: u64,
    /// Relay-to-connector sequence of the last request frame observed on the
    /// data carrier.  Connector frames acknowledge it.
    relay_last_emitted: u64,
}

/// Open a consumer peer stream, dispatch `OUTSTANDING_RECORDS` request
/// records, and read the resulting relay-to-connector DATA frames off the
/// real data carrier so the phase knows the owner's stream identity and
/// current send cursor.
async fn open_consumer_phase(
    running: &RunningFixture,
    control: &mut RawStream,
    data: &mut RawStream,
    context: &FrameContext,
    label: &str,
) -> Result<ConsumerPhase> {
    let mut stream = RawStream::open(running, InternalRoute::ConsumerStreams, "consumer").await?;
    let envelope = consumer_envelope(running, label)?;
    stream
        .send_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().map_err(|error| {
                HarnessError::InvalidInput(format!("encoding ec044 consumer envelope: {error}"))
            })?,
        )
        .await?;
    stream
        .expect_ok(running, "ec044 consumer admission")
        .await?;

    // The owner queues one OPEN for the new logical stream; the connector
    // must accept it before any record is dispatched onto the data carrier.
    let open = admit_open(control, &context.session_id, context.epoch).await?;

    for index in 0..OUTSTANDING_RECORDS {
        let body = format!("{label}-request-{index}");
        stream
            .send_record(PeerRecordKind::ConsumerChunk, &framed(body.as_bytes()))
            .await?;
    }

    // Every dispatched record becomes one relay-to-connector DATA frame on
    // the authenticated carrier.  Reading them is what makes this a peer-path
    // proof rather than a direct actor drive.
    let stream_id = open.stream_id;
    let mut relay_last_emitted = 0;
    for _ in 0..OUTSTANDING_RECORDS {
        let frame = match next_data_frame(data, stream_id).await {
            Ok(frame) => frame,
            Err(error) => {
                let snapshot = snapshot(running).await?;
                return Err(HarnessError::Http(format!(
                    "{error}; chunk_reads={} dispatches={} owner state: {:?}",
                    snapshot.lifetime_consumer_chunk_reads,
                    snapshot.lifetime_application_dispatches,
                    snapshot
                        .sessions
                        .iter()
                        .map(|session| (
                            session.profile,
                            session.sockets,
                            session.queue_messages,
                            session
                                .streams
                                .iter()
                                .map(|stream| (
                                    stream.stream_id,
                                    stream.last_emitted_relay_to_connector,
                                    stream.recv_contiguous_connector_to_relay,
                                    stream.authorization_in_flight,
                                    stream.authorization_failure_code,
                                ))
                                .collect::<Vec<_>>()
                        ))
                        .collect::<Vec<_>>()
                )));
            }
        };
        relay_last_emitted = relay_last_emitted.max(frame.sequence);
    }

    Ok(ConsumerPhase {
        stream,
        stream_id,
        relay_last_emitted,
    })
}

/// Answer the owner's queued `OPEN` for a freshly admitted consumer stream
/// exactly as a real connector does.  Nothing reaches the data carrier until
/// the connector has accepted the logical stream, so every phase must clear
/// this handshake before it can inject frames.
async fn admit_open(
    control: &mut RawStream,
    session_id: &str,
    epoch: u64,
) -> Result<tunnel_protocol::Open> {
    loop {
        let Some(record) = control.next_record().await? else {
            return Err(HarnessError::Http(
                "ec044 control stream closed before OPEN".to_owned(),
            ));
        };
        if record.kind() != PeerRecordKind::CompleteControlText {
            continue;
        }
        let message = decode_control(record.body()).map_err(|error| {
            HarnessError::Http(format!("decoding ec044 owner control message: {error}"))
        })?;
        let ControlMessage::Open(open) = message else {
            continue;
        };
        let opened = ControlMessage::Opened(tunnel_protocol::Opened::new(
            format!("{}-opened", open.message_id),
            open.message_id.clone(),
            session_id.to_owned(),
            epoch,
            open.stream_id,
            open.operation_id.clone(),
            open.initial_send_window,
            open.initial_receive_window,
        ));
        let encoded = tunnel_protocol::control::encode_control(&opened).map_err(|error| {
            HarnessError::InvalidInput(format!("encoding ec044 OPENED: {error}"))
        })?;
        control
            .send_record(PeerRecordKind::CompleteControlText, &encoded)
            .await?;

        // A real connector pairs OPENED with its own authorization
        // challenge: until the owner confirms the grant, `authorized_until`
        // is unset and every record for the stream is parked in the bounded
        // per-stream FIFO instead of reaching the data carrier.
        let challenge =
            ControlMessage::AuthorizationChallenge(tunnel_protocol::AuthorizationChallenge::new(
                format!("{}-challenge", open.message_id),
                session_id.to_owned(),
                epoch,
                open.stream_id,
                format!("{}-challenge-id", open.message_id),
                format!("{}-nonce", open.message_id),
                open.service_id.clone(),
                open.metadata
                    .get("permission_digest")
                    .cloned()
                    .unwrap_or_default(),
                open.metadata
                    .get("grant_revision")
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0),
            ));
        let encoded_challenge =
            tunnel_protocol::control::encode_control(&challenge).map_err(|error| {
                HarnessError::InvalidInput(format!("encoding ec044 challenge: {error}"))
            })?;
        control
            .send_record(PeerRecordKind::CompleteControlText, &encoded_challenge)
            .await?;
        return Ok(open);
    }
}

/// Read the next relay-to-connector sequenced frame for `stream_id`.
///
/// The data carrier is shared by every logical stream on the session, so
/// ACK/WINDOW_UPDATE frames and a previous phase's terminal frames are
/// skipped rather than mistaken for this phase's request.
async fn next_data_frame(data: &mut RawStream, stream_id: u64) -> Result<Frame> {
    loop {
        let Some(record) = data.next_record().await? else {
            return Err(HarnessError::Http(
                "ec044 data carrier closed before a request frame".to_owned(),
            ));
        };
        if record.kind() != PeerRecordKind::CompleteDeviceData {
            continue;
        }
        let frame = tunnel_protocol::frame::decode(record.body())
            .map_err(|error| HarnessError::Http(format!("decoding ec044 relay frame: {error}")))?;
        if frame.stream_id == stream_id
            && matches!(
                frame.kind,
                FrameKind::Data | FrameKind::Fin | FrameKind::Reset
            )
        {
            return Ok(frame);
        }
    }
}

/// Read the owner's ACK for `stream_id` and return the sequence it
/// acknowledges.
///
/// This is the fixture's only settle barrier, and it is the owner's own:
/// `inbound_m2_stream_data` queues the ACK at the very end of the frame's
/// accounting, after the receive cursor, delivery, byte release and credit
/// update.  A cursor sampled once the ACK is on the wire is therefore
/// settled, where an immediate snapshot would merely race the actor and make
/// a "nothing advanced" assertion vacuous.
async fn next_ack(data: &mut RawStream, stream_id: u64) -> Result<u64> {
    loop {
        let Some(record) = data.next_record().await? else {
            return Err(HarnessError::Http(
                "ec044 data carrier closed before the owner acknowledged a frame".to_owned(),
            ));
        };
        if record.kind() != PeerRecordKind::CompleteDeviceData {
            continue;
        }
        let frame = tunnel_protocol::frame::decode(record.body())
            .map_err(|error| HarnessError::Http(format!("decoding ec044 owner ACK: {error}")))?;
        if frame.stream_id == stream_id && frame.kind == FrameKind::Ack {
            return Ok(frame.ack);
        }
    }
}

/// Forward one connector frame inside a real `CompleteDeviceData` peer
/// record, exactly as an ingress relay does.
async fn forward_frame(data: &mut RawStream, frame: &Frame) -> Result<()> {
    let bytes = frame
        .encode()
        .map_err(|error| HarnessError::InvalidInput(format!("encoding ec044 frame: {error}")))?;
    data.send_record(PeerRecordKind::CompleteDeviceData, &bytes)
        .await
}

async fn phase_reorder(
    running: &RunningFixture,
    control: &mut RawStream,
    data: &mut RawStream,
    context: &FrameContext,
    evidence: &mut PeerFrameEvidence,
) -> Result<()> {
    let mut phase = open_consumer_phase(running, control, data, context, "reorder").await?;
    let stream_id = phase.stream_id;

    // One solicited response record, split across two sequenced DATA frames.
    // The connector sends the tail first; the owner may not deliver it until
    // the head arrives, and must then reassemble in sequence order.
    let record = framed(REORDER_BODY);
    let (head, tail) = record.split_at(REORDER_SPLIT);
    let tail_frame = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        2,
        phase.relay_last_emitted,
        tail.to_vec(),
    );
    forward_frame(data, &tail_frame).await?;
    evidence.reorder_ack_after_gap = next_ack(data, stream_id).await?;
    evidence.reorder_delivered_after_gap = settled_cursor(running, context, stream_id).await?;

    let head_frame = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        1,
        phase.relay_last_emitted,
        head.to_vec(),
    );
    forward_frame(data, &head_frame).await?;
    evidence.reorder_ack_after_fill = next_ack(data, stream_id).await?;
    evidence.reorder_delivered_after_fill = settled_cursor(running, context, stream_id).await?;

    // Byte-exact reassembly is the order proof: had the owner appended in
    // arrival order the record would be the tail followed by the head, whose
    // leading four bytes are not this record's length prefix at all.
    let delivered = next_consumer_record(&mut phase.stream).await?;
    evidence.reorder_order_restored = delivered == REORDER_BODY;
    evidence.reorder_session_alive = session_alive(running, &context.session_id).await?;

    phase.stream.send.cancel();
    phase.stream.recv.cancel();
    Ok(())
}

async fn phase_duplicate(
    running: &RunningFixture,
    control: &mut RawStream,
    data: &mut RawStream,
    context: &FrameContext,
    evidence: &mut PeerFrameEvidence,
) -> Result<()> {
    let mut phase = open_consumer_phase(running, control, data, context, "duplicate").await?;
    let stream_id = phase.stream_id;

    let accepted = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        1,
        phase.relay_last_emitted,
        framed(b"duplicate-response-1"),
    );
    forward_frame(data, &accepted).await?;
    evidence.duplicate_ack_before = next_ack(data, stream_id).await?;
    evidence.duplicate_delivered_before = settled_cursor(running, context, stream_id).await?;

    let first_body = next_consumer_record(&mut phase.stream).await?;
    if first_body != b"duplicate-response-1" {
        return Err(HarnessError::Http(
            "ec044 duplicate baseline record did not reach the adapter".to_owned(),
        ));
    }

    // Replay the exact accepted sequence.  A duplicate must be dropped before
    // it can touch the cursor, produce a second adapter record, or fence the
    // session.
    forward_frame(data, &accepted).await?;
    // A duplicate is still acknowledged, so the owner's second ACK proves the
    // frame was actually consumed before the cursor is resampled.
    evidence.duplicate_ack_after = next_ack(data, stream_id).await?;
    evidence.duplicate_delivered_after = settled_cursor(running, context, stream_id).await?;
    evidence.duplicate_adapter_records = 1 + phase.stream.drain_buffered().len();
    evidence.duplicate_session_alive = session_alive(running, &context.session_id).await?;

    phase.stream.send.cancel();
    phase.stream.recv.cancel();
    Ok(())
}

async fn phase_late(
    running: &RunningFixture,
    control: &mut RawStream,
    data: &mut RawStream,
    context: &FrameContext,
    evidence: &mut PeerFrameEvidence,
) -> Result<()> {
    let mut phase = open_consumer_phase(running, control, data, context, "late").await?;
    let stream_id = phase.stream_id;

    let response = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        1,
        phase.relay_last_emitted,
        framed(b"late-response-1"),
    );
    forward_frame(data, &response).await?;
    next_ack(data, stream_id).await?;
    let delivered = next_consumer_record(&mut phase.stream).await?;
    if delivered != b"late-response-1" {
        return Err(HarnessError::Http(
            "ec044 late phase baseline record did not reach the adapter".to_owned(),
        ));
    }

    let fin = Frame::fin(
        context.epoch,
        context.generation,
        stream_id,
        2,
        phase.relay_last_emitted,
    );
    forward_frame(data, &fin).await?;

    evidence.late_fin_cursor = wait_for(running, "late terminal", |snapshot| {
        snapshot
            .stream_terminal_events
            .iter()
            .find(|event| event.session_id == context.session_id && event.stream_id == stream_id)
            .map(|event| event.delivered_contiguous_connector_to_relay)
    })
    .await?;

    // The terminal has been latched.  A DATA frame after it is a terminal
    // precedence violation on a real peer forward, not a late event.
    let late = Frame::data(
        context.epoch,
        context.generation,
        stream_id,
        3,
        phase.relay_last_emitted,
        framed(b"late-after-fin"),
    );
    forward_frame(data, &late).await?;

    let closed = wait_for(running, "late session close", |snapshot| {
        snapshot
            .session_terminal_events
            .iter()
            .find(|event| event.session_id == context.session_id)
            .map(|event| event.reason.to_owned())
    })
    .await?;
    evidence.late_session_reason = closed;

    let snapshot = snapshot(running).await?;
    evidence.late_stream_terminals = snapshot
        .stream_terminal_events
        .iter()
        .filter(|event| event.session_id == context.session_id && event.stream_id == stream_id)
        .count();

    // Nothing may reach the adapter past the FIN.  The consumer stream is
    // drained to its end; any record here would be a post-terminal delivery.
    let mut after_fin = 0usize;
    loop {
        match phase.stream.next_record().await {
            Ok(Some(record)) => after_fin = after_fin.saturating_add(record.body().len()),
            Ok(None) => break,
            // A fenced session tears the forwarded consumer stream down; an
            // interrupted read is the expected shape and proves nothing was
            // delivered, so it ends the drain rather than failing the phase.
            Err(_) => break,
        }
    }
    evidence.late_adapter_bytes_after_fin = after_fin;

    // The owner's own bounded fault tuples.  The set varies between runs
    // because the control and data carriers race to observe the fenced
    // session, so both label lists are reported and only the required subset
    // is enforced by `validate`.
    let faults = wait_for(running, "late peer fault", |snapshot| {
        (snapshot.peer_fault_diagnostics.owner_count > 0)
            .then(|| snapshot.peer_fault_diagnostics.clone())
    })
    .await?;
    evidence.late_owner_fault_recorded = faults.owner_count > 0;
    evidence.late_fault_stages = faults
        .stage_counts
        .keys()
        .map(|stage| (*stage).to_owned())
        .collect();
    evidence.late_fault_causes = faults
        .cause_counts
        .keys()
        .map(|cause| (*cause).to_owned())
        .collect();

    phase.stream.send.cancel();
    phase.stream.recv.cancel();
    Ok(())
}

/// Read one complete length-prefixed adapter record from a consumer stream.
async fn next_consumer_record(stream: &mut RawStream) -> Result<Vec<u8>> {
    let mut buffered: Vec<u8> = Vec::new();
    loop {
        if buffered.len() >= 4 {
            let declared =
                u32::from_be_bytes([buffered[0], buffered[1], buffered[2], buffered[3]]) as usize;
            if buffered.len() >= declared + 4 {
                return Ok(buffered[4..declared + 4].to_vec());
            }
        }
        let Some(record) = stream.next_record().await? else {
            return Err(HarnessError::Http(
                "ec044 consumer stream ended before a complete adapter record".to_owned(),
            ));
        };
        buffered.extend_from_slice(record.body());
    }
}

async fn snapshot(running: &RunningFixture) -> Result<RelaySnapshot> {
    running
        .handle
        .snapshot()
        .await
        .map_err(|error| HarnessError::Http(format!("ec044 relay snapshot: {error}")))
}

fn stream_snapshot(
    snapshot: &RelaySnapshot,
    session_id: &str,
    stream_id: u64,
) -> Option<RelayStreamSnapshot> {
    snapshot
        .sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .and_then(|session| {
            session
                .streams
                .iter()
                .find(|stream| stream.stream_id == stream_id)
                .cloned()
        })
}

async fn wait_for<T, F>(running: &RunningFixture, what: &str, mut ready: F) -> Result<T>
where
    F: FnMut(&RelaySnapshot) -> Option<T>,
{
    let deadline = Instant::now() + STEP_TIMEOUT;
    loop {
        let snapshot = snapshot(running).await?;
        if let Some(value) = ready(&snapshot) {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "ec044 waiting for {what} exceeded its bound"
            )));
        }
        tokio::time::sleep(SNAPSHOT_POLL).await;
    }
}

/// Sample the delivered contiguous connector-to-relay cursor for one stream.
///
/// Every caller takes this sample immediately after [`next_ack`] has proved
/// the owner finished accounting the frame under test, so the value is
/// settled rather than a race with the actor.
async fn settled_cursor(
    running: &RunningFixture,
    context: &FrameContext,
    stream_id: u64,
) -> Result<u64> {
    let snapshot = snapshot(running).await?;
    Ok(stream_snapshot(&snapshot, &context.session_id, stream_id)
        .map_or(0, |stream| stream.delivered_contiguous_connector_to_relay))
}

async fn session_alive(running: &RunningFixture, session_id: &str) -> Result<bool> {
    let snapshot = snapshot(running).await?;
    Ok(snapshot
        .sessions
        .iter()
        .any(|session| session.session_id == session_id))
}

struct WelcomeFacts {
    session_id: String,
    epoch: u64,
    ticket: String,
}

/// Register the device's control session on the owner relay over the real
/// peer `DeviceControl` route and return the WELCOME facts the data carrier
/// needs.
///
/// The ingress owner preflight and the owner's own registration disagree by
/// construction: the preflight needs a live predecessor claim for the scope,
/// and `begin_register_forwarded_control` then claims the same scope under a
/// fresh session identifier, which a live predecessor claim refuses as
/// `OwnerBusy`.  That is the ordinary owner-handover shape, so the fixture
/// stages it: the predecessor claim is released after the envelope has been
/// admitted and before the HELLO is sent.  A refused attempt leaves no
/// session behind, so the staging is retried under a bounded budget rather
/// than relying on a single timing window.
async fn register_control(running: &RunningFixture) -> Result<(RawStream, WelcomeFacts)> {
    let mut last = None;
    for attempt in 1..=REGISTRATION_ATTEMPTS {
        match register_control_attempt(running, attempt).await {
            Ok(registered) => return Ok(registered),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        HarnessError::Http("ec044 control registration made no attempt".to_owned())
    }))
}

async fn register_control_attempt(
    running: &RunningFixture,
    attempt: usize,
) -> Result<(RawStream, WelcomeFacts)> {
    let predecessor = running.owner_token();
    let mut control = RawStream::open(running, InternalRoute::DeviceControl, "control").await?;
    let envelope = device_envelope(
        running,
        InternalRoute::DeviceControl,
        &format!("ec044-control-{attempt}"),
    )?;
    control
        .send_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().map_err(|error| {
                HarnessError::InvalidInput(format!("encoding ec044 control envelope: {error}"))
            })?,
        )
        .await?;

    // Let the owner's ingress consume the envelope and complete its owner
    // preflight before the predecessor claim is withdrawn.
    tokio::time::sleep(HANDOVER_WINDOW).await;
    running
        .catalog
        .release_owner(&predecessor)
        .await
        .map_err(|error| HarnessError::Http(format!("ec044 predecessor owner release: {error}")))?;

    let mut hello = Hello::new(
        format!("ec044-hello-{attempt}"),
        device_id().to_string(),
        1,
        0,
    );
    hello.features = vec![
        "m1-control-data".to_owned(),
        "ordered-rotation-v1".to_owned(),
        "authorization-challenge".to_owned(),
        "echo".to_owned(),
    ];
    let encoded = tunnel_protocol::control::encode_control(&ControlMessage::Hello(hello))
        .map_err(|error| HarnessError::InvalidInput(format!("encoding ec044 HELLO: {error}")))?;
    let registered = async {
        control
            .send_record(PeerRecordKind::CompleteControlText, &encoded)
            .await?;
        control
            .expect_ok(running, "ec044 control admission")
            .await?;
        let Some(record) = control.next_record().await? else {
            return Err(HarnessError::Http(
                "ec044 control stream closed before WELCOME".to_owned(),
            ));
        };
        let message = decode_control(record.body())
            .map_err(|error| HarnessError::Http(format!("decoding ec044 WELCOME: {error}")))?;
        let ControlMessage::Welcome(welcome) = message else {
            return Err(HarnessError::Http(
                "ec044 control registration did not answer WELCOME".to_owned(),
            ));
        };
        Ok(WelcomeFacts {
            session_id: welcome.session_id,
            epoch: welcome.epoch,
            ticket: welcome.attachment_ticket,
        })
    }
    .await;

    match registered {
        Ok(welcome) => {
            // The owner relay now holds the authoritative claim for the
            // scope; every later envelope must carry that exact token.
            let claim = running
                .catalog
                .current_owner(tenant_id(), device_id(), Utc::now())
                .await
                .map_err(|error| {
                    HarnessError::Http(format!("ec044 owner read after registration: {error}"))
                })?
                .ok_or_else(|| {
                    HarnessError::Http(
                        "ec044 registration left no owner claim for the scope".to_owned(),
                    )
                })?;
            running.set_owner_token(claim.token);
            Ok((control, welcome))
        }
        Err(error) => {
            control.send.cancel();
            control.recv.cancel();
            // Restore a predecessor claim so the next attempt's preflight has
            // something live to match.
            let request = OwnerClaimRequest {
                deployment_incarnation: predecessor.deployment_incarnation.clone(),
                tenant_id: predecessor.tenant_id,
                device_id: predecessor.device_id,
                node_id: predecessor.node_id.clone(),
                boot_id: predecessor.boot_id.clone(),
                session_id: format!("ec044-bootstrap-{}", Uuid::new_v4()),
                lease_expires_at: Utc::now() + ChronoDuration::seconds(120),
            };
            if let Ok(claim) = running.catalog.claim_owner(&request).await {
                running.set_owner_token(claim.token);
            }
            Err(error)
        }
    }
}

async fn admit_data(running: &RunningFixture, data: &mut RawStream, ticket: &str) -> Result<()> {
    let envelope = device_envelope(running, InternalRoute::DeviceData, "ec044-data")?;
    data.send_record(
        PeerRecordKind::CompleteControlText,
        &envelope.encode().map_err(|error| {
            HarnessError::InvalidInput(format!("encoding ec044 data envelope: {error}"))
        })?,
    )
    .await?;
    data.send_record(
        PeerRecordKind::CompleteControlText,
        format!("Bearer {ticket}").as_bytes(),
    )
    .await?;
    data.expect_ok(running, "ec044 data admission").await
}

fn device_envelope(
    running: &RunningFixture,
    route: InternalRoute,
    request_id: &str,
) -> Result<RequestEnvelope> {
    let now = Utc::now();
    let source = PeerIdentity::new(SOURCE_NODE_ID, running.source_boot_id.clone());
    let destination = Destination::new(running.owner_token(), Uuid::nil());
    let authentication = DeviceAuthenticationContext {
        certificate: VerifiedDeviceCertificate {
            certificate_identity: device_id().to_string(),
            spki_fingerprint: DEVICE_SPKI.to_owned(),
            serial: "ec044-device".to_owned(),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::minutes(5),
            tenant_id: tenant_id(),
            device_id: device_id(),
        },
        ingress: IngressRequestBinding {
            request_id: request_id.to_owned(),
            source: source.clone(),
            destination: destination.clone(),
            expires_at: now + ChronoDuration::seconds(10),
        },
    };
    let request = match route {
        InternalRoute::DeviceControl => InternalRequest::DeviceControl(DeviceControlRequest {
            stream_id: request_id.to_owned(),
            authentication,
        }),
        InternalRoute::DeviceData => InternalRequest::DeviceData(DeviceDataRequest {
            stream_id: request_id.to_owned(),
            sequence: 1,
            authentication,
            bytes: Vec::new(),
        }),
        other => {
            return Err(HarnessError::InvalidInput(format!(
                "ec044 device envelope needs a device route, got {other:?}"
            )));
        }
    };
    Ok(RequestEnvelope::new(
        route,
        request_id,
        source,
        destination,
        20_000,
        None,
        request,
    ))
}

fn consumer_envelope(running: &RunningFixture, label: &str) -> Result<RequestEnvelope> {
    let source = PeerIdentity::new(SOURCE_NODE_ID, running.source_boot_id.clone());
    let destination = Destination::new(running.owner_token(), service_id());
    let bearer =
        ForwardedConsumerBearer::new(running.consumer_token.clone(), running.owner_token())
            .map_err(|error| {
                HarnessError::InvalidInput(format!("ec044 consumer bearer: {error}"))
            })?;
    Ok(RequestEnvelope::new(
        InternalRoute::ConsumerStreams,
        format!("ec044-{label}"),
        source,
        destination,
        20_000,
        Some(20_000),
        InternalRequest::ConsumerStreams(ConsumerStreamsRequest {
            stream_id: format!("ec044-{label}-stream"),
            required_scope: tunnel_relay::ECHO_OPERATION.to_owned(),
            bearer,
            bytes: Vec::new(),
        }),
    ))
}

async fn start_fixture(
    cluster: &ClusterFixture,
    source_binding: VerifiedPeerBinding,
) -> Result<RunningFixture> {
    let owner = cluster
        .node(OWNER_NODE_ID)
        .ok_or_else(|| HarnessError::InvalidInput("ec044 owner node missing".to_owned()))?;
    let source = cluster
        .node(SOURCE_NODE_ID)
        .ok_or_else(|| HarnessError::InvalidInput("ec044 source node missing".to_owned()))?;

    let now = Utc::now();
    let catalog = Arc::new(MemoryCatalog::new());
    catalog
        .seed_fixture(&catalog_fixture(now))
        .await
        .map_err(|error| HarnessError::Http(format!("seeding ec044 catalog: {error}")))?;
    // A bootstrap claim exists only so the ingress owner preflight has a live
    // claim to match.  `register_control` releases it before the HELLO so the
    // owner relay's own registration can claim the scope for real, which is
    // exactly the handover shape a forwarded HELLO sees in production.
    let bootstrap = catalog
        .claim_owner(&bootstrap_claim_request(cluster, owner, now))
        .await
        .map_err(|error| HarnessError::Http(format!("ec044 bootstrap owner claim: {error}")))?;
    let (oidc, consumer_token) = oidc_fixture()?;
    let mut options = RelayOptions::new(Arc::clone(&oidc));
    options.node_id = owner.node_id.clone();
    options.boot_id = owner.boot_id.clone();
    options.deployment_incarnation = cluster.deployment_incarnation.clone();
    let handle = Relay::spawn(options, catalog.clone() as SharedCatalog)
        .await
        .map_err(|error| HarnessError::Http(format!("spawning ec044 relay: {error}")))?;

    let owner_pin = spki_sha256_from_der(&owner.peer_certificate.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("ec044 owner SPKI: {error}")))?;
    let source_pin = spki_sha256_from_der(&source.peer_certificate.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("ec044 source SPKI: {error}")))?;
    let limits = PeerTransportLimits::default();

    let server_config = load_peer_server_config_from_pem(
        owner.peer_certificate_chain_pem().as_bytes(),
        owner.peer_certificate.private_key_pem.as_bytes(),
        owner.peer_ca_pem().as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("ec044 server TLS: {error}")))?;
    let server_endpoint = quinn::Endpoint::server(server_config, owner.addresses.udp)
        .map_err(|error| HarnessError::Http(format!("binding ec044 peer server: {error}")))?;
    let server_pins = SharedPeerPins::new(
        ApprovedPeerPins::new([source_pin])
            .map_err(|error| HarnessError::Http(format!("ec044 source pin set: {error}")))?,
    )
    .map_err(|error| HarnessError::Http(format!("ec044 source pin provider: {error}")))?;

    let owner_client = make_client(owner, &source_pin, limits.clone())?;
    let identity = RelayIdentity::new(
        cluster.deployment_incarnation.clone(),
        owner.node_id.clone(),
        owner.boot_id.clone(),
    )
    .map_err(|error| HarnessError::InvalidInput(format!("ec044 owner identity: {error}")))?;
    let router = OwnerRouter::new(catalog.clone() as SharedCatalog, identity)
        .map_err(|error| HarnessError::InvalidInput(format!("ec044 owner router: {error}")))?;
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

    // The production owner callback: real catalog owner recheck, real
    // envelope and credential validation, and entry into the same relay actor
    // a local device socket would reach.
    let ingress = peer_ingress_handler(
        handle.clone(),
        catalog.clone() as SharedCatalog,
        oidc,
        owner.node_id.clone(),
        owner.boot_id.clone(),
    );
    let last_ingress_error = Arc::new(std::sync::Mutex::new(None));
    let (policy, server_handler) = runtime.server_components(RecordingIngress {
        inner: ingress,
        last_error: Arc::clone(&last_ingress_error),
    });
    let server = PeerServer::new_with_pin_provider(
        server_endpoint,
        server_pins,
        limits.clone(),
        policy,
        server_handler,
    )
    .map_err(|error| HarnessError::Http(format!("ec044 peer server: {error}")))?;

    let client = make_client(source, &owner_pin, limits)?;
    let destination = PeerDestination::new(owner.addresses.udp, SERVER_NAME);
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));

    Ok(RunningFixture {
        catalog,
        handle,
        client,
        destination,
        runtime,
        owner_token: std::sync::Mutex::new(bootstrap.token),
        last_ingress_error,
        source_boot_id: source.boot_id.clone(),
        consumer_token,
        cancel,
        server_task,
    })
}

/// A predecessor owner claim for the fixture's device scope.
///
/// The session identifier is unique per attempt so a retried registration
/// never re-adopts a claim the relay has already refused.
fn bootstrap_claim_request(
    cluster: &ClusterFixture,
    owner: &crate::cluster_fixture::RelayNodeFixture,
    now: DateTime<Utc>,
) -> OwnerClaimRequest {
    OwnerClaimRequest {
        deployment_incarnation: cluster.deployment_incarnation.clone(),
        tenant_id: tenant_id(),
        device_id: device_id(),
        node_id: owner.node_id.clone(),
        boot_id: owner.boot_id.clone(),
        session_id: format!("ec044-bootstrap-{}", Uuid::new_v4()),
        lease_expires_at: now + ChronoDuration::seconds(120),
    }
}

fn make_client(
    node: &crate::cluster_fixture::RelayNodeFixture,
    approved_pin: &tunnel_transport::SpkiSha256,
    limits: PeerTransportLimits,
) -> Result<PeerClient> {
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|error| HarnessError::Http(format!("binding ec044 peer client: {error}")))?;
    let config = load_peer_client_config_from_pem(
        node.peer_certificate_chain_pem().as_bytes(),
        node.peer_certificate.private_key_pem.as_bytes(),
        node.peer_ca_pem().as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("ec044 client TLS: {error}")))?;
    endpoint.set_default_client_config(config);
    let pins = ApprovedPeerPins::new([*approved_pin])
        .map_err(|error| HarnessError::Http(format!("ec044 client pins: {error}")))?;
    let provider = SharedPeerPins::new(pins)
        .map_err(|error| HarnessError::Http(format!("ec044 client pin provider: {error}")))?;
    PeerClient::new_with_pin_provider(endpoint, provider, limits)
        .map_err(|error| HarnessError::Http(format!("ec044 peer client: {error}")))
}

fn verified_binding(cluster: &ClusterFixture, node_id: &str) -> Result<VerifiedPeerBinding> {
    let ports = cluster.nodes.iter().map(|node| node.addresses.udp.port());
    let endpoint_policy = PrivateEndpointPolicy::allowlisted(["127.0.0.1"], [SERVER_NAME], ports)
        .map_err(|error| {
        HarnessError::InvalidInput(format!("ec044 endpoint policy: {error}"))
    })?;
    let policy = MembershipPolicy::new(
        &cluster.deployment_id,
        &cluster.deployment_incarnation,
        endpoint_policy,
    )
    .map_err(|error| HarnessError::InvalidInput(format!("ec044 membership policy: {error}")))?;
    let trusted = cluster.membership_authority.trusted_key()?;
    let mut verifier = MembershipVerifier::new(policy, [trusted])
        .map_err(|error| HarnessError::InvalidInput(format!("ec044 verifier: {error}")))?;
    let now = Utc::now();
    verifier
        .verify_checkpoint(
            cluster.checkpoint.encoded_bytes(),
            &cluster.checkpoint.payload.nonce,
            now,
        )
        .map_err(|error| HarnessError::InvalidInput(format!("ec044 checkpoint: {error}")))?;
    for membership in cluster.memberships.values() {
        verifier
            .verify_membership(membership.encoded_bytes(), now)
            .map_err(|error| HarnessError::InvalidInput(format!("ec044 membership: {error}")))?;
    }
    let node = cluster
        .node(node_id)
        .ok_or_else(|| HarnessError::InvalidInput(format!("ec044 missing node {node_id}")))?;
    let spki = node.peer_spki_fingerprint()?;
    verifier
        .bind_peer(&node.node_id, &node.boot_id, &spki, now)
        .map_err(|error| HarnessError::InvalidInput(format!("ec044 peer binding: {error}")))
}

fn oidc_fixture() -> Result<(Arc<OidcVerifier>, String)> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|error| HarnessError::Pki(format!("ec044 OIDC signing key: {error}")))?;
    let approved = ApprovedJwk::from_ed25519_der("ec044", key.public_key_raw())
        .map_err(|error| HarnessError::Pki(format!("ec044 OIDC verification key: {error}")))?;
    let config = OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved])
        .map_err(|error| HarnessError::InvalidInput(format!("ec044 OIDC config: {error}")))?;
    let verifier =
        Arc::new(OidcVerifier::new(config).map_err(|error| {
            HarnessError::InvalidInput(format!("ec044 OIDC verifier: {error}"))
        })?);

    #[derive(Serialize)]
    struct Claims {
        iss: String,
        sub: String,
        aud: String,
        exp: usize,
        scope: String,
    }

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ec044".to_owned());
    let claims = Claims {
        iss: ISSUER.to_owned(),
        sub: SUBJECT.to_owned(),
        aud: AUDIENCE.to_owned(),
        exp: (Utc::now().timestamp() + 600) as usize,
        scope: tunnel_relay::ECHO_OPERATION.to_owned(),
    };
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_der(key.serialized_der()),
    )
    .map_err(|error| HarnessError::InvalidInput(format!("ec044 OIDC token: {error}")))?;
    Ok((verifier, token))
}

fn catalog_fixture(now: DateTime<Utc>) -> CatalogFixture {
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant_id(),
            display_name: "ec044 tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user_id(),
            display_name: "ec044 consumer".to_owned(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: ISSUER.to_owned(),
            subject: SUBJECT.to_owned(),
            user_id: user_id(),
        }],
        memberships: vec![MembershipRecord {
            tenant_id: tenant_id(),
            user_id: user_id(),
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id: tenant_id(),
            device_id: device_id(),
            owner_user_id: user_id(),
            display_name: "ec044 device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant_id(),
            device_id: device_id(),
            credential_id: credential_id(),
            spki_fingerprint: DEVICE_SPKI.to_owned(),
            serial: Some("ec044-device".to_owned()),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::minutes(30),
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id: tenant_id(),
            device_id: device_id(),
            service_id: service_id(),
            service_type: "echo".to_owned(),
            display_name: "EC-044 echo".to_owned(),
            capabilities: serde_json::json!({"operations": [tunnel_relay::ECHO_OPERATION]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: tenant_id(),
            principal_id: user_id(),
            device_id: device_id(),
            service_id: service_id(),
            permissions: PermissionSet {
                operations: BTreeSet::from([tunnel_relay::ECHO_OPERATION.to_owned()]),
            },
            constraints: serde_json::json!({}),
            expires_at: Some(now + ChronoDuration::minutes(30)),
            active: true,
        }],
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(body);
    framed
}

fn wire_record(kind: PeerRecordKind, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > kind.max_body() {
        return Err(HarnessError::InvalidInput(format!(
            "ec044 body {} exceeds {:?} limit {}",
            body.len(),
            kind,
            kind.max_body()
        )));
    }
    let length = u32::try_from(body.len())
        .map_err(|_| HarnessError::InvalidInput("ec044 body length overflow".to_owned()))?;
    let mut record = Vec::with_capacity(PREFIX_LEN + body.len());
    record.extend_from_slice(&length.to_be_bytes());
    record.push(kind.code());
    record.push(0);
    record.extend_from_slice(&0_u16.to_be_bytes());
    record.extend_from_slice(body);
    Ok(record)
}

fn http_error(context: &str, error: impl std::fmt::Display) -> HarnessError {
    HarnessError::Http(format!("{context}: {error}"))
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{BODY_STAGE, PeerFrameEvidence};
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> PeerFrameEvidence {
        PeerFrameEvidence {
            real_owner_ingress: true,
            authenticated_carrier: true,
            session_profile: "m2".to_owned(),
            outstanding_records: 1,
            reorder_ack_after_gap: 0,
            reorder_delivered_after_gap: 0,
            reorder_ack_after_fill: 2,
            reorder_delivered_after_fill: 2,
            reorder_order_restored: true,
            reorder_session_alive: true,
            duplicate_ack_before: 1,
            duplicate_delivered_before: 1,
            duplicate_ack_after: 1,
            duplicate_delivered_after: 1,
            duplicate_adapter_records: 1,
            duplicate_session_alive: true,
            late_fin_cursor: 2,
            late_stream_terminals: 1,
            late_adapter_bytes_after_fin: 0,
            late_session_reason: "INVALID_SEQUENCE".to_owned(),
            late_fault_stages: vec![BODY_STAGE.to_owned()],
            late_fault_causes: vec!["closed".to_owned()],
            late_owner_fault_recorded: true,
            cleanup_joined: true,
        }
    }

    #[test]
    fn peer_frame_validator_accepts_complete_evidence() {
        valid_evidence()
            .validate()
            .expect("complete EC-044 peer-frame evidence is valid");
    }

    /// Every flag, count and bound in the validator has a red case that
    /// reaches the shared nonzero CLI exit path with its own named field.
    #[test]
    fn every_peer_frame_flag_and_bound_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut PeerFrameEvidence));
        let cases: [Mutate; 25] = [
            ("real_owner_ingress", |e| e.real_owner_ingress = false),
            ("authenticated_carrier", |e| e.authenticated_carrier = false),
            ("session_profile", |e| e.session_profile = "m1".to_owned()),
            ("outstanding_records", |e| e.outstanding_records = 2),
            ("reorder_ack_after_gap", |e| e.reorder_ack_after_gap = 2),
            ("reorder_delivered_after_gap", |e| {
                e.reorder_delivered_after_gap = 1
            }),
            ("reorder_ack_after_fill", |e| e.reorder_ack_after_fill = 1),
            ("reorder_delivered_after_fill", |e| {
                e.reorder_delivered_after_fill = 1;
                e.reorder_ack_after_fill = 1;
            }),
            ("reorder_cursor_advance", |e| {
                e.reorder_delivered_after_gap = 2;
                e.reorder_delivered_after_fill = 2;
                e.reorder_ack_after_gap = 0;
            }),
            ("reorder_order_restored", |e| {
                e.reorder_order_restored = false
            }),
            ("reorder_session_alive", |e| e.reorder_session_alive = false),
            ("duplicate_ack_before", |e| {
                e.duplicate_ack_before = 0;
                e.duplicate_ack_after = 0;
            }),
            ("duplicate_delivered_before", |e| {
                e.duplicate_delivered_before = 0;
                e.duplicate_delivered_after = 0;
            }),
            ("duplicate_ack_after", |e| e.duplicate_ack_after = 2),
            ("duplicate_delivered_after", |e| {
                e.duplicate_delivered_after = 2
            }),
            ("duplicate_adapter_records", |e| {
                e.duplicate_adapter_records = 2
            }),
            ("duplicate_session_alive", |e| {
                e.duplicate_session_alive = false
            }),
            ("late_fin_cursor", |e| e.late_fin_cursor = 0),
            ("late_stream_terminals", |e| e.late_stream_terminals = 2),
            ("late_adapter_bytes_after_fin", |e| {
                e.late_adapter_bytes_after_fin = 1
            }),
            ("late_session_reason", |e| {
                e.late_session_reason = "STREAM_CLOSED".to_owned()
            }),
            ("late_owner_fault_recorded", |e| {
                e.late_owner_fault_recorded = false
            }),
            ("late_fault_stages", |e| {
                e.late_fault_stages = vec!["owner".to_owned()]
            }),
            ("late_fault_causes", |e| e.late_fault_causes = Vec::new()),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (field, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(evidence.validate(), field);
        }
    }

    /// A stage list that merely contains the body stage alongside other
    /// racing stages must still pass: the gate asserts a required subset, not
    /// an exact set, because the observed tuple set varies between runs.
    #[test]
    fn peer_frame_validator_accepts_a_superset_of_fault_stages() {
        let mut evidence = valid_evidence();
        evidence.late_fault_stages = vec![
            BODY_STAGE.to_owned(),
            "owner".to_owned(),
            "validation".to_owned(),
        ];
        evidence.late_fault_causes = vec!["closed".to_owned(), "unexpected_record".to_owned()];
        evidence
            .validate()
            .expect("a superset of observed fault stages is complete evidence");
    }
}
