use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::Router;
use chrono::{Duration as ChronoDuration, Utc};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    AuthenticatedConsumer, DeviceIdentity, GrantSnapshot, OwnerClaimRequest, OwnerToken,
    SharedCatalog,
};
use tunnel_protocol::{AuthorizationChallenge, ControlMessage, FrameKind, Hello};
use tunnel_transport::{CertificateRole, TlsIdentity};
use uuid::Uuid;

use crate::{
    config::{RelayLimits, RelayOptions},
    http,
    wire::{self, WireError},
};

const AUTHORIZATION_LIFETIME: Duration = Duration::from_secs(5);
const OWNER_LEASE_SAFETY_MARGIN: Duration = Duration::from_secs(5);
const MAX_ECHO_RESPONSE_EXTRA_BYTES: usize = 256;

/// Errors returned by the relay API.  HTTP handlers map these to bounded,
/// sanitized responses; certificate details, tokens, and backend payloads are
/// never included in this type's public message.
#[derive(Debug)]
pub enum RelayError {
    Config(String),
    Catalog(String),
    Unauthorized,
    Forbidden,
    Conflict(&'static str),
    NotFound,
    Overloaded(&'static str),
    Protocol(String),
    Transport(String),
    Shutdown,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message)
            | Self::Catalog(message)
            | Self::Protocol(message)
            | Self::Transport(message) => formatter.write_str(message),
            Self::Unauthorized => formatter.write_str("authentication failed"),
            Self::Forbidden => formatter.write_str("operation is not authorized"),
            Self::Conflict(message) => formatter.write_str(message),
            Self::NotFound => formatter.write_str("device or service was not found"),
            Self::Overloaded(message) => formatter.write_str(message),
            Self::Shutdown => formatter.write_str("relay is shutting down"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<WireError> for RelayError {
    fn from(error: WireError) -> Self {
        Self::Protocol(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SessionKey {
    pub(crate) device_id: Uuid,
    pub(crate) session_id: String,
    pub(crate) epoch: u64,
}

#[derive(Debug)]
pub(crate) enum ControlOutbound {
    Text(String),
    Close,
}

#[derive(Debug)]
pub(crate) enum DataOutbound {
    Binary(Vec<u8>),
    Close,
}

pub(crate) struct ControlRegistration {
    pub(crate) key: SessionKey,
    pub(crate) welcome: String,
    pub(crate) rx: mpsc::Receiver<ControlOutbound>,
    pub(crate) queue_budget: QueueBudget,
}

pub(crate) struct DataRegistration {
    pub(crate) key: SessionKey,
    pub(crate) rx: mpsc::Receiver<DataOutbound>,
    pub(crate) queue_budget: QueueBudget,
}

/// Shared per-device byte accounting for pending request bodies and encoded
/// outbound control/data queue items.  Socket tasks release an item when they
/// take ownership of it from a bounded channel.
#[derive(Clone, Debug)]
pub(crate) struct QueueBudget {
    used: Arc<AtomicUsize>,
    limit: usize,
}

impl QueueBudget {
    fn new(limit: usize) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    fn reserve(&self, bytes: usize) -> bool {
        if bytes > self.limit {
            return false;
        }
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .is_ok()
    }

    pub(crate) fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }
}

struct DispatchRequest {
    consumer: AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Uuid,
    grant: GrantSnapshot,
    body: Vec<u8>,
    consumer_expires_at: chrono::DateTime<Utc>,
    response: oneshot::Sender<EchoOutcome>,
}

#[derive(Debug)]
pub(crate) enum EchoOutcome {
    Success(Vec<u8>),
    Failure {
        code: &'static str,
        execution: &'static str,
    },
}

struct PendingEcho {
    operation_id: String,
    send_sequence: u64,
    response: oneshot::Sender<EchoOutcome>,
    response_sequence: u64,
    response_body: Vec<u8>,
    challenge_id: Option<String>,
    consumer: AuthenticatedConsumer,
    service_id: Uuid,
    grant: GrantSnapshot,
    consumer_expires_at: chrono::DateTime<Utc>,
    body: Vec<u8>,
    created_at: Instant,
    dispatched: bool,
    authorization_in_flight: bool,
}

struct DeviceChallenge {
    message_id: String,
    stream_id: u64,
    service_id: String,
    challenge_id: String,
    nonce: String,
    permission_digest: String,
    grant_revision: u64,
    received_at: Instant,
    lifetime: Duration,
}

enum ResponseFrameUpdate {
    Accepted,
    Complete(Vec<u8>, oneshot::Sender<EchoOutcome>),
    Invalid,
}

type ChallengeAuthorizationResult = Result<
    (
        Option<GrantSnapshot>,
        Option<tunnel_catalog::OwnerClaim>,
        Option<DeviceIdentity>,
        Option<Instant>,
    ),
    String,
>;

#[derive(Clone)]
struct Ticket {
    value: String,
    device_id: Uuid,
    spki: String,
    session_id: String,
    epoch: u64,
    generation: u64,
    welcome_message_id: String,
    connection_id: String,
    issued_at_wall: chrono::DateTime<Utc>,
    expires_at_wall: chrono::DateTime<Utc>,
    expires_at: Instant,
    consuming: bool,
}

struct DeviceSession {
    identity: DeviceIdentity,
    owner: OwnerToken,
    key: SessionKey,
    control_tx: mpsc::Sender<ControlOutbound>,
    data_tx: Option<mpsc::Sender<DataOutbound>>,
    generation: u64,
    next_stream_id: u64,
    pending: HashMap<u64, PendingEcho>,
    queued_bytes: usize,
    queue_budget: QueueBudget,
    last_lease_renewal: Instant,
    maintenance_in_flight: bool,
    closed: bool,
}

enum Command {
    RegisterControl {
        identity: TlsIdentity,
        hello: ControlMessage,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
    },
    AttachData {
        identity: TlsIdentity,
        ticket: String,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
    },
    InboundControl {
        key: SessionKey,
        message: ControlMessage,
    },
    InboundData {
        key: SessionKey,
        bytes: Vec<u8>,
    },
    DisconnectControl(SessionKey),
    DisconnectData(SessionKey),
    DispatchEcho {
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        body: Vec<u8>,
        consumer_expires_at: chrono::DateTime<Utc>,
        response: oneshot::Sender<EchoOutcome>,
    },
    Tick,
    Shutdown(oneshot::Sender<()>),
    RegisterResolved {
        device_id: Uuid,
        identity: TlsIdentity,
        hello: Hello,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
        result: Result<(DeviceIdentity, tunnel_catalog::OwnerClaim), RelayError>,
    },
    AttachResolved {
        identity: TlsIdentity,
        ticket: Ticket,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
        result: Result<(Option<DeviceIdentity>, Option<tunnel_catalog::OwnerClaim>), String>,
    },
    ChallengeAuthorized {
        key: SessionKey,
        challenge: DeviceChallenge,
        result: ChallengeAuthorizationResult,
    },
    MaintenanceResult {
        key: SessionKey,
        renewed: Option<Result<bool, String>>,
        identity: Result<Option<DeviceIdentity>, String>,
    },
}

/// A cloneable, bounded command handle used by HTTP and WebSocket tasks.
#[derive(Clone)]
pub struct RelayHandle {
    tx: mpsc::Sender<Command>,
}

impl RelayHandle {
    pub(crate) fn spawn(options: RelayOptions, catalog: SharedCatalog) -> Self {
        let capacity = options.limits.max_queue_messages.max(32);
        let (tx, rx) = mpsc::channel(capacity);
        let handle = Self { tx: tx.clone() };
        let actor = RelayActor {
            options,
            catalog,
            command_tx: tx.clone(),
            rx,
            sessions: HashMap::new(),
            registering: HashSet::new(),
            tickets: HashMap::new(),
            cleanup_tasks: Vec::new(),
            shutting_down: false,
        };
        tokio::spawn(actor.run());
        let ticker = handle.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                if ticker.tx.send(Command::Tick).await.is_err() {
                    break;
                }
            }
        });
        handle
    }

    pub(crate) async fn register_control(
        &self,
        identity: TlsIdentity,
        hello: ControlMessage,
    ) -> Result<ControlRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::RegisterControl {
                identity,
                hello,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    pub(crate) async fn attach_data(
        &self,
        identity: TlsIdentity,
        ticket: String,
    ) -> Result<DataRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::AttachData {
                identity,
                ticket,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    pub(crate) async fn inbound_control(
        &self,
        key: SessionKey,
        message: ControlMessage,
    ) -> Result<(), RelayError> {
        self.tx
            .send(Command::InboundControl { key, message })
            .await
            .map_err(|_| RelayError::Shutdown)
    }

    pub(crate) async fn inbound_data(
        &self,
        key: SessionKey,
        bytes: Vec<u8>,
    ) -> Result<(), RelayError> {
        self.tx
            .send(Command::InboundData { key, bytes })
            .await
            .map_err(|_| RelayError::Shutdown)
    }

    pub(crate) async fn disconnect_control(&self, key: SessionKey) {
        let _ = self.tx.send(Command::DisconnectControl(key)).await;
    }

    pub(crate) async fn disconnect_data(&self, key: SessionKey) {
        let _ = self.tx.send(Command::DisconnectData(key)).await;
    }

    pub(crate) async fn dispatch_echo(
        &self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        body: Vec<u8>,
        consumer_expires_at: chrono::DateTime<Utc>,
    ) -> Result<EchoOutcome, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::DispatchEcho {
                consumer,
                device_id,
                service_id,
                grant,
                body,
                consumer_expires_at,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)
    }

    pub async fn shutdown(&self) -> Result<(), RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::Shutdown(response))
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)
    }
}

struct RelayActor {
    options: RelayOptions,
    catalog: SharedCatalog,
    command_tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Command>,
    sessions: HashMap<Uuid, DeviceSession>,
    registering: HashSet<Uuid>,
    tickets: HashMap<String, Ticket>,
    cleanup_tasks: Vec<JoinHandle<()>>,
    shutting_down: bool,
}

impl RelayActor {
    async fn run(mut self) {
        while let Some(command) = self.rx.recv().await {
            let shutdown = matches!(command, Command::Shutdown(_));
            self.handle(command).await;
            if shutdown || self.shutting_down {
                break;
            }
        }
        self.close_all().await;
    }

    async fn handle(&mut self, command: Command) {
        match command {
            Command::RegisterControl {
                identity,
                hello,
                response,
            } => {
                self.begin_register_control(identity, hello, response);
            }
            Command::RegisterResolved {
                device_id,
                identity,
                hello,
                response,
                result,
            } => {
                self.finish_register_control(device_id, identity, hello, response, result);
            }
            Command::AttachData {
                identity,
                ticket,
                response,
            } => {
                self.begin_attach_data(identity, ticket, response);
            }
            Command::AttachResolved {
                identity,
                ticket,
                response,
                result,
            } => {
                self.finish_attach_data(identity, ticket, response, result);
            }
            Command::InboundControl { key, message } => self.inbound_control(key, message).await,
            Command::InboundData { key, bytes } => self.inbound_data(key, bytes).await,
            Command::DisconnectControl(key) => self.disconnect_control(key).await,
            Command::DisconnectData(key) => self.disconnect_data(key).await,
            Command::DispatchEcho {
                consumer,
                device_id,
                service_id,
                grant,
                consumer_expires_at,
                body,
                response,
            } => {
                self.dispatch_echo(DispatchRequest {
                    consumer,
                    device_id,
                    service_id,
                    grant,
                    body,
                    consumer_expires_at,
                    response,
                })
                .await;
            }
            Command::Tick => self.tick().await,
            Command::ChallengeAuthorized {
                key,
                challenge,
                result,
            } => {
                self.finish_device_challenge(key, challenge, result);
            }
            Command::MaintenanceResult {
                key,
                renewed,
                identity,
            } => {
                self.finish_maintenance(key, renewed, identity).await;
            }
            Command::Shutdown(response) => {
                self.shutting_down = true;
                let _ = response.send(());
            }
        }
    }

    fn begin_register_control(
        &mut self,
        identity: TlsIdentity,
        hello: ControlMessage,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
    ) {
        if !matches!(identity.role(), CertificateRole::Device { .. }) {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let device_id = match identity.role_id().parse::<Uuid>() {
            Ok(device_id) => device_id,
            Err(_) => {
                let _ = response.send(Err(RelayError::Unauthorized));
                return;
            }
        };
        let hello = match hello {
            ControlMessage::Hello(hello) => hello,
            _ => {
                let _ = response.send(Err(RelayError::Protocol(
                    "first control message must be HELLO".into(),
                )));
                return;
            }
        };
        if let Err(error) = validate_hello(&hello, device_id) {
            let _ = response.send(Err(error));
            return;
        }
        if self.sessions.contains_key(&device_id) || !self.registering.insert(device_id) {
            let _ = response.send(Err(RelayError::Conflict(
                "device already has an active control connection",
            )));
            return;
        }
        if self.sessions.len().saturating_add(self.registering.len())
            > self.options.limits.max_devices
        {
            self.registering.remove(&device_id);
            let _ = response.send(Err(RelayError::Overloaded(
                "relay device capacity is exhausted",
            )));
            return;
        }

        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        let options = self.options.clone();
        let spki = identity.spki_sha256().to_hex();
        tokio::spawn(async move {
            let result = async {
                let at = Utc::now();
                let device_identity = catalog
                    .resolve_device(&spki, at)
                    .await
                    .map_err(|error| RelayError::Catalog(error.to_string()))?
                    .filter(|record| {
                        record.device_id == device_id
                            && record.spki_fingerprint == spki
                            && record.device_active
                            && record.credential_active
                            && record.credential_revoked_at.is_none()
                            && record.expires_at > at
                    })
                    .ok_or(RelayError::Unauthorized)?;
                let session_id = wire::random_token();
                let lease_expires_at = at
                    + ChronoDuration::from_std(options.owner_lease)
                        .map_err(|_| RelayError::Config("owner lease is invalid".into()))?;
                let claim = catalog
                    .claim_owner(&OwnerClaimRequest {
                        deployment_incarnation: options.deployment_incarnation.clone(),
                        tenant_id: device_identity.tenant_id,
                        device_id,
                        node_id: options.node_id.clone(),
                        boot_id: options.boot_id.clone(),
                        session_id,
                        lease_expires_at,
                    })
                    .await
                    .map_err(|error| RelayError::Catalog(error.to_string()))?;
                Ok((device_identity, claim))
            }
            .await;
            let _ = command_tx
                .send(Command::RegisterResolved {
                    device_id,
                    identity,
                    hello,
                    response,
                    result,
                })
                .await;
        });
    }

    fn finish_register_control(
        &mut self,
        device_id: Uuid,
        identity: TlsIdentity,
        hello: Hello,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
        result: Result<(DeviceIdentity, tunnel_catalog::OwnerClaim), RelayError>,
    ) {
        self.registering.remove(&device_id);
        let (device_identity, claim) = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = response.send(Err(error));
                return;
            }
        };
        if response.is_closed() {
            let token = claim.token;
            let catalog = self.catalog.clone();
            self.cleanup_tasks.push(tokio::spawn(async move {
                let _ = catalog.release_owner(&token).await;
            }));
            return;
        }
        if self.sessions.contains_key(&device_id) {
            let token = claim.token;
            let catalog = self.catalog.clone();
            self.cleanup_tasks.push(tokio::spawn(async move {
                let _ = catalog.release_owner(&token).await;
            }));
            let _ = response.send(Err(RelayError::Conflict(
                "device already has an active control connection",
            )));
            return;
        }
        let user_sessions = self
            .sessions
            .values()
            .filter(|session| {
                session.identity.tenant_id == device_identity.tenant_id
                    && session.identity.owner_user_id == device_identity.owner_user_id
            })
            .count();
        if user_sessions >= self.options.limits.max_devices_per_user {
            let token = claim.token;
            let catalog = self.catalog.clone();
            self.cleanup_tasks.push(tokio::spawn(async move {
                let _ = catalog.release_owner(&token).await;
            }));
            let _ = response.send(Err(RelayError::Overloaded(
                "per-user device capacity is exhausted",
            )));
            return;
        }
        let session_id = claim.token.session_id.clone();
        let key = SessionKey {
            device_id,
            session_id: session_id.clone(),
            epoch: claim.token.epoch,
        };
        let (control_tx, rx) = mpsc::channel(self.options.limits.max_queue_messages);
        let queue_budget = QueueBudget::new(self.options.limits.max_queue_bytes);
        let ticket = wire::random_token();
        let welcome_message_id = wire::random_token();
        let data_connection_id = wire::random_token();
        let ticket_issued_at_wall = Utc::now();
        let ticket_expires_at_wall = ticket_issued_at_wall
            + ChronoDuration::from_std(wire::TICKET_TTL)
                .unwrap_or_else(|_| ChronoDuration::seconds(10));
        self.tickets.insert(
            ticket.clone(),
            Ticket {
                value: ticket.clone(),
                device_id,
                spki: identity.spki_sha256().to_hex(),
                session_id: session_id.clone(),
                epoch: claim.token.epoch,
                generation: 1,
                welcome_message_id: welcome_message_id.clone(),
                connection_id: data_connection_id.clone(),
                issued_at_wall: ticket_issued_at_wall,
                expires_at_wall: ticket_expires_at_wall,
                expires_at: Instant::now() + wire::TICKET_TTL,
                consuming: false,
            },
        );
        let welcome = wire::welcome(
            &welcome_message_id,
            &hello.message_id,
            &session_id,
            claim.token.epoch,
            1,
            &data_connection_id,
            &ticket,
        );
        let welcome = match wire::encode_control_message(&welcome) {
            Ok(value) => value,
            Err(error) => {
                let token = claim.token;
                let catalog = self.catalog.clone();
                self.cleanup_tasks.push(tokio::spawn(async move {
                    let _ = catalog.release_owner(&token).await;
                }));
                let _ = response.send(Err(RelayError::Protocol(error.to_string())));
                return;
            }
        };
        let trace_tenant_id = device_identity.tenant_id;
        let trace_epoch = claim.token.epoch;
        self.sessions.insert(
            device_id,
            DeviceSession {
                identity: device_identity,
                owner: claim.token,
                key: key.clone(),
                control_tx,
                data_tx: None,
                generation: 1,
                next_stream_id: 1,
                pending: HashMap::new(),
                queued_bytes: 0,
                queue_budget: queue_budget.clone(),
                last_lease_renewal: Instant::now(),
                maintenance_in_flight: false,
                closed: false,
            },
        );
        tracing::info!(
            tenant_id = %trace_tenant_id,
            device_id = %device_id,
            session_id = %session_id,
            epoch = trace_epoch,
            phase = "session_admitted",
        );
        let _ = response.send(Ok(ControlRegistration {
            key,
            welcome,
            rx,
            queue_budget,
        }));
    }

    fn begin_attach_data(
        &mut self,
        identity: TlsIdentity,
        ticket_value: String,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
    ) {
        if !matches!(identity.role(), CertificateRole::Device { .. }) {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let spki = identity.spki_sha256().to_hex();
        let now_wall = Utc::now();
        let Some(ticket) = self.tickets.get_mut(&ticket_value) else {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        };
        if ticket.value != ticket_value
            || ticket.expires_at <= Instant::now()
            || now_wall < ticket.issued_at_wall
            || now_wall >= ticket.expires_at_wall
            || ticket.spki != spki
            || ticket.consuming
        {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        ticket.consuming = true;
        let ticket = ticket.clone();
        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let device = catalog
                    .resolve_device(&spki, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                let Some(device) = device else {
                    return Ok((None, None));
                };
                let owner = catalog
                    .current_owner(device.tenant_id, ticket.device_id, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                Ok((Some(device), owner))
            }
            .await;
            let _ = command_tx
                .send(Command::AttachResolved {
                    identity,
                    ticket,
                    response,
                    result,
                })
                .await;
        });
    }

    fn finish_attach_data(
        &mut self,
        identity: TlsIdentity,
        ticket: Ticket,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
        result: Result<(Option<DeviceIdentity>, Option<tunnel_catalog::OwnerClaim>), String>,
    ) {
        let now_wall = Utc::now();
        if !self.ticket_matches(&ticket) {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        if ticket.expires_at <= Instant::now()
            || now_wall < ticket.issued_at_wall
            || now_wall >= ticket.expires_at_wall
        {
            self.remove_ticket_if_matches(&ticket);
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        if response.is_closed() {
            self.remove_ticket_if_matches(&ticket);
            return;
        }
        let (identity_result, owner_result) = match result {
            Ok(value) => value,
            Err(_) => {
                self.remove_ticket_if_matches(&ticket);
                let _ = response.send(Err(RelayError::Unauthorized));
                return;
            }
        };
        let valid_identity = identity_result.filter(|record| {
            record.device_id == ticket.device_id
                && record.spki_fingerprint == ticket.spki
                && record.device_active
                && record.credential_active
                && record.credential_revoked_at.is_none()
                && record.expires_at > Utc::now()
        });
        let Some(device_identity) = valid_identity else {
            self.remove_ticket_if_matches(&ticket);
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        };
        let result =
            self.attach_data_verified(identity, ticket.clone(), device_identity, owner_result);
        if result.is_ok() {
            self.remove_ticket_if_matches(&ticket);
        } else if let Some(pending) = self.tickets.get_mut(&ticket.value) {
            pending.consuming = false;
        }
        let _ = response.send(result);
    }

    fn attach_data_verified(
        &mut self,
        identity: TlsIdentity,
        ticket: Ticket,
        current_identity: DeviceIdentity,
        current_owner: Option<tunnel_catalog::OwnerClaim>,
    ) -> Result<DataRegistration, RelayError> {
        let spki = identity.spki_sha256().to_hex();
        if current_identity.spki_fingerprint != spki {
            return Err(RelayError::Unauthorized);
        }
        let session = self
            .sessions
            .get_mut(&ticket.device_id)
            .ok_or(RelayError::Conflict("control connection is not active"))?;
        if session.key.session_id != ticket.session_id
            || session.key.epoch != ticket.epoch
            || session.generation != ticket.generation
        {
            return Err(RelayError::Unauthorized);
        }
        if session.data_tx.is_some() {
            return Err(RelayError::Conflict("data connection is already active"));
        }
        if session.identity.spki_fingerprint != spki {
            return Err(RelayError::Unauthorized);
        }
        if session.identity.device_version != current_identity.device_version {
            return Err(RelayError::Unauthorized);
        }
        if session.owner.epoch != current_identity.owner_epoch {
            return Err(RelayError::Unauthorized);
        }
        let now_wall = Utc::now();
        let Some(current_owner) = current_owner else {
            return Err(RelayError::Unauthorized);
        };
        if current_owner.token != session.owner
            || current_owner.lease_expires_at
                <= now_wall
                    + ChronoDuration::from_std(OWNER_LEASE_SAFETY_MARGIN)
                        .unwrap_or_else(|_| ChronoDuration::seconds(5))
        {
            return Err(RelayError::Unauthorized);
        }
        let (data_tx, rx) = mpsc::channel(self.options.limits.max_queue_messages);
        let ready = wire::encode_control_message(&wire::data_ready(
            &ticket.welcome_message_id,
            &session.key.session_id,
            session.key.epoch,
            session.generation,
            &ticket.connection_id,
        ))
        .map_err(|error| RelayError::Protocol(error.to_string()))?;
        queue_control(&session.control_tx, &session.queue_budget, ready)
            .map_err(|_| RelayError::Overloaded("control queue is full"))?;
        session.data_tx = Some(data_tx);
        tracing::info!(
            tenant_id = %session.identity.tenant_id,
            device_id = %ticket.device_id,
            session_id = %session.key.session_id,
            epoch = session.key.epoch,
            phase = "data_attached",
        );
        Ok(DataRegistration {
            key: session.key.clone(),
            rx,
            queue_budget: session.queue_budget.clone(),
        })
    }

    async fn dispatch_echo(&mut self, request: DispatchRequest) {
        let DispatchRequest {
            consumer,
            device_id,
            service_id,
            grant,
            body,
            consumer_expires_at,
            response,
        } = request;
        if response.is_closed() {
            return;
        }
        if body.len() > self.options.limits.max_body_bytes {
            let _ = response.send(EchoOutcome::Failure {
                code: "BODY_LIMIT",
                execution: "not_dispatched",
            });
            return;
        }
        if grant.tenant_id != consumer.tenant_id
            || grant.principal_id != consumer.principal_id
            || grant.device_id != device_id
            || grant.service_id != service_id
            || !grant.permissions.allows(crate::ECHO_OPERATION)
        {
            let _ = response.send(EchoOutcome::Failure {
                code: "FORBIDDEN",
                execution: "not_dispatched",
            });
            return;
        }
        let Some(session) = self.sessions.get_mut(&device_id) else {
            let _ = response.send(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            });
            return;
        };
        if session.identity.tenant_id != consumer.tenant_id || session.data_tx.is_none() {
            let _ = response.send(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            });
            return;
        }
        if session.pending.len() >= self.options.limits.max_pending_operations
            || session.pending.len() >= self.options.limits.max_streams_per_device
        {
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        if session.queued_bytes.saturating_add(body.len()) > self.options.limits.max_queue_bytes {
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        let stream_id = session.next_stream_id;
        session.next_stream_id = session.next_stream_id.checked_add(1).unwrap_or(1);
        let sequence = 1;
        let Some(next_stream_id) = session.next_stream_id.checked_add(1) else {
            let _ = response.send(EchoOutcome::Failure {
                code: "STREAM_LIMIT",
                execution: "not_dispatched",
            });
            return;
        };
        session.next_stream_id = next_stream_id;
        let operation_id = Uuid::new_v4().to_string();
        let queued_len = body.len();
        let digest = wire::permission_digest(&grant, &service_id.to_string());
        let service_name = service_id.to_string();
        let open = match wire::encode_control_message(&wire::open(wire::OpenRequest {
            session_id: &session.key.session_id,
            epoch: session.key.epoch,
            stream_id,
            operation_id: &operation_id,
            service_id: &service_name,
            body_len: body.len(),
            grant_revision: grant.revision,
            digest: &digest,
        })) {
            Ok(value) => value,
            Err(_) => {
                let _ = response.send(EchoOutcome::Failure {
                    code: "CONTROL_LIMIT",
                    execution: "not_dispatched",
                });
                return;
            }
        };
        let open_bytes = open.len();
        if !session.queue_budget.reserve(queued_len) {
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        if !session.queue_budget.reserve(open_bytes) {
            session.queue_budget.release(queued_len);
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        session.pending.insert(
            stream_id,
            PendingEcho {
                operation_id: operation_id.clone(),
                send_sequence: sequence,
                response,
                response_sequence: 0,
                response_body: Vec::new(),
                challenge_id: None,
                consumer,
                service_id,
                grant,
                consumer_expires_at,
                body,
                created_at: Instant::now(),
                dispatched: false,
                authorization_in_flight: false,
            },
        );
        session.queued_bytes = session.queued_bytes.saturating_add(queued_len);
        if session
            .control_tx
            .try_send(ControlOutbound::Text(open))
            .is_err()
        {
            if let Some(pending) = session.pending.remove(&stream_id) {
                session.queue_budget.release(open_bytes);
                release_pending_budget(session, &pending);
                let _ = pending.response.send(EchoOutcome::Failure {
                    code: "CONTROL_UNAVAILABLE",
                    execution: "not_dispatched",
                });
            }
            return;
        }
        tracing::debug!(
            tenant_id = %session.identity.tenant_id,
            device_id = %device_id,
            session_id = %session.key.session_id,
            epoch = session.key.epoch,
            stream_id,
            operation_id = %operation_id,
            service_id = %service_id,
            bytes = queued_len,
            phase = "stream_admitted",
        );
    }

    async fn inbound_control(&mut self, key: SessionKey, message: ControlMessage) {
        if self.session_for(&key).is_none() {
            return;
        }
        match message {
            ControlMessage::AuthorizationChallenge(challenge) => {
                self.begin_device_challenge(key, challenge);
            }
            ControlMessage::Opened(opened) => {
                if opened.session_id != key.session_id || opened.epoch != key.epoch {
                    self.protocol_failure(&key, "STALE_CONTROL").await;
                }
            }
            ControlMessage::Pong(pong) => {
                if pong.session_id != key.session_id || pong.epoch != key.epoch {
                    self.protocol_failure(&key, "STALE_CONTROL").await;
                }
            }
            ControlMessage::Rejected(rejected) => {
                if rejected.session_id != key.session_id || rejected.epoch != key.epoch {
                    return;
                }
                if let Some(session) = self.session_mut(&key)
                    && session
                        .pending
                        .get(&rejected.stream_id)
                        .is_some_and(|pending| pending.operation_id == rejected.operation_id)
                    && let Some(pending) = session.pending.remove(&rejected.stream_id)
                {
                    tracing::debug!(
                        tenant_id = %session.identity.tenant_id,
                        device_id = %key.device_id,
                        session_id = %key.session_id,
                        epoch = key.epoch,
                        stream_id = rejected.stream_id,
                        operation_id = %rejected.operation_id,
                        phase = "stream_rejected",
                    );
                    release_pending_budget(session, &pending);
                    let _ = pending.response.send(EchoOutcome::Failure {
                        code: "DEVICE_REJECTED",
                        execution: "not_dispatched",
                    });
                }
            }
            ControlMessage::AuthorizationInvalidated(invalidated) => {
                if invalidated.session_id != key.session_id || invalidated.epoch != key.epoch {
                    return;
                }
                if let Some(session) = self.session_mut(&key)
                    && session
                        .pending
                        .get(&invalidated.stream_id)
                        .is_some_and(|pending| {
                            pending.challenge_id.as_deref()
                                == Some(invalidated.challenge_id.as_str())
                                && pending.grant.revision == invalidated.grant_revision
                        })
                    && let Some(pending) = session.pending.remove(&invalidated.stream_id)
                {
                    release_pending_budget(session, &pending);
                    let _ = pending.response.send(EchoOutcome::Failure {
                        code: "AUTHORIZATION_REVOKED",
                        execution: "not_dispatched",
                    });
                }
            }
            ControlMessage::Cancel(cancel) => {
                if cancel.session_id != key.session_id || cancel.epoch != key.epoch {
                    return;
                }
                self.cancel(&key, cancel.stream_id, cancel.operation_id);
            }
            _ => {
                let _ = self.send_control(
                    &key,
                    wire::rejected(
                        &wire::random_token(),
                        &key.session_id,
                        key.epoch,
                        1,
                        "control",
                        "UNKNOWN_CONTROL",
                        "unsupported control message",
                    ),
                );
            }
        }
    }

    fn begin_device_challenge(&mut self, key: SessionKey, message: AuthorizationChallenge) {
        if message.session_id != key.session_id || message.epoch != key.epoch {
            return;
        }
        let service_id = message.service_id.clone();
        let challenge = DeviceChallenge {
            message_id: message.message_id,
            stream_id: message.stream_id,
            service_id,
            challenge_id: message.challenge_id,
            nonce: message.nonce,
            permission_digest: message.permission_digest,
            grant_revision: message.grant_revision,
            received_at: Instant::now(),
            lifetime: self.options.challenge_interval.min(AUTHORIZATION_LIFETIME),
        };
        let Some(session) = self.session_mut(&key) else {
            return;
        };
        let Some(pending) = session.pending.get_mut(&message.stream_id) else {
            return;
        };
        if pending.dispatched || pending.authorization_in_flight {
            return;
        }
        let expected_digest =
            wire::permission_digest(&pending.grant, &pending.service_id.to_string());
        if challenge.permission_digest != expected_digest
            || challenge.grant_revision != pending.grant.revision
            || challenge.service_id != pending.service_id.to_string()
        {
            return;
        }
        pending.authorization_in_flight = true;
        pending.challenge_id = Some(challenge.challenge_id.clone());
        let consumer = pending.consumer.clone();
        let service_id = pending.service_id;
        let read_started_at = pending.grant.read_started_at;
        let spki = session.identity.spki_fingerprint.clone();
        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let current = catalog
                    .authorize(
                        &consumer,
                        key.device_id,
                        service_id,
                        read_started_at,
                        Utc::now(),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let Some(current) = current else {
                    return Ok((None, None, None, None));
                };
                let owner = catalog
                    .current_owner(current.tenant_id, key.device_id, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                let owner_deadline = owner.as_ref().and_then(|claim| {
                    (claim.lease_expires_at - Utc::now())
                        .to_std()
                        .ok()
                        .and_then(|remaining| remaining.checked_sub(OWNER_LEASE_SAFETY_MARGIN))
                        .map(|remaining| Instant::now() + remaining)
                });
                let identity = catalog
                    .resolve_device(&spki, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                Ok((Some(current), owner, identity, owner_deadline))
            }
            .await;
            let _ = command_tx
                .send(Command::ChallengeAuthorized {
                    key,
                    challenge,
                    result,
                })
                .await;
        });
    }

    fn finish_device_challenge(
        &mut self,
        key: SessionKey,
        challenge: DeviceChallenge,
        result: ChallengeAuthorizationResult,
    ) {
        let Some(session) = self.session_for(&key) else {
            return;
        };
        let Some(pending) = session.pending.get(&challenge.stream_id) else {
            return;
        };
        if !pending.authorization_in_flight
            || pending.dispatched
            || pending.grant.revision != challenge.grant_revision
            || pending.service_id.to_string() != challenge.service_id
        {
            return;
        }
        let consumer_expires_at = pending.consumer_expires_at;
        let (current, owner, identity, owner_deadline) = match result {
            Ok(value) => value,
            Err(_) => {
                self.invalidate_pending(
                    &key,
                    challenge.stream_id,
                    &challenge,
                    "authorization unavailable",
                );
                return;
            }
        };
        let Some(current) = current else {
            self.invalidate_pending(&key, challenge.stream_id, &challenge, "grant unavailable");
            return;
        };
        let Some(owner) = owner else {
            self.invalidate_pending(&key, challenge.stream_id, &challenge, "owner unavailable");
            return;
        };
        let Some(identity) = identity else {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "device authorization unavailable",
            );
            return;
        };
        let now_wall = Utc::now();
        let Some(session) = self.session_for(&key) else {
            return;
        };
        if owner.token != session.owner
            || identity.device_id != key.device_id
            || identity.spki_fingerprint != session.identity.spki_fingerprint
            || identity.device_version != session.identity.device_version
            || identity.owner_epoch != session.owner.epoch
            || !identity.device_active
            || !identity.credential_active
            || identity.credential_revoked_at.is_some()
            || identity.expires_at <= now_wall
            || current.revision != challenge.grant_revision
            || wire::permission_digest(&current, &challenge.service_id)
                != challenge.permission_digest
            || current.valid_until <= now_wall
        {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization changed",
            );
            return;
        }
        let challenge_remaining = challenge
            .lifetime
            .checked_sub(challenge.received_at.elapsed())
            .unwrap_or_default();
        let snapshot_remaining = (current.valid_until - now_wall)
            .to_std()
            .unwrap_or_default();
        let token_remaining = (consumer_expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let owner_remaining = owner_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_default();
        let credential_remaining = (identity.expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let remaining = challenge_remaining
            .min(snapshot_remaining)
            .min(token_remaining)
            .min(owner_remaining)
            .min(credential_remaining);
        let remaining_ms = remaining.as_millis().min(5_000) as u64;
        if remaining_ms == 0 {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization expired",
            );
            return;
        }
        let dispatch_deadline = Instant::now() + Duration::from_millis(remaining_ms);
        let owner_safe_until = owner.lease_expires_at
            - ChronoDuration::from_std(OWNER_LEASE_SAFETY_MARGIN)
                .unwrap_or_else(|_| ChronoDuration::seconds(5));
        let grant_read_started_at = current.read_started_at;
        let authorization_is_live = || {
            let now = Utc::now();
            Instant::now() < dispatch_deadline
                && now >= grant_read_started_at
                && now < current.valid_until
                && now < consumer_expires_at
                && now < identity.expires_at
                && now < owner_safe_until
        };

        if self
            .session_for(&key)
            .and_then(|session| session.data_tx.as_ref())
            .is_none()
        {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "DEVICE_OFFLINE",
                "not_dispatched",
            );
            return;
        }
        let (control_tx, data_tx, queue_budget, generation, send_sequence, body) = {
            let Some(session) = self.session_for(&key) else {
                return;
            };
            let Some(pending) = session.pending.get(&challenge.stream_id) else {
                return;
            };
            let data_tx = session.data_tx.clone().expect("data socket checked above");
            (
                session.control_tx.clone(),
                data_tx,
                session.queue_budget.clone(),
                session.generation,
                pending.send_sequence,
                pending.body.clone(),
            )
        };
        if data_tx.is_closed() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "DEVICE_OFFLINE",
                "not_dispatched",
            );
            return;
        }
        let confirmed = wire::authorization_confirmed(wire::AuthorizationConfirmation {
            reply_to: &challenge.message_id,
            session_id: &key.session_id,
            epoch: key.epoch,
            stream_id: challenge.stream_id,
            challenge_id: &challenge.challenge_id,
            nonce: &challenge.nonce,
            permission_digest: &challenge.permission_digest,
            grant_revision: challenge.grant_revision,
            remaining_ms,
        });
        let Ok(confirmed) = wire::encode_control_message(&confirmed) else {
            self.fail_pending(&key, challenge.stream_id, "CONTROL_LIMIT", "not_dispatched");
            return;
        };
        let frame = match wire::data_frame(
            key.epoch,
            generation,
            challenge.stream_id,
            send_sequence,
            body,
        ) {
            Ok(frame) => frame,
            Err(_) => {
                self.fail_pending(&key, challenge.stream_id, "FRAME_LIMIT", "not_dispatched");
                return;
            }
        };
        let fin_sequence = match send_sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                self.fail_pending(&key, challenge.stream_id, "STREAM_LIMIT", "not_dispatched");
                return;
            }
        };
        let fin = match wire::fin_frame(key.epoch, generation, challenge.stream_id, fin_sequence) {
            Ok(frame) => frame,
            Err(_) => {
                self.fail_pending(&key, challenge.stream_id, "FRAME_LIMIT", "not_dispatched");
                return;
            }
        };
        if !authorization_is_live() {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization expired",
            );
            return;
        }
        if queue_control(&control_tx, &queue_budget, confirmed).is_err() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "CONTROL_UNAVAILABLE",
                "not_dispatched",
            );
            return;
        }
        if !authorization_is_live() {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization expired",
            );
            return;
        }
        if queue_data(&data_tx, &queue_budget, frame).is_err() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "REVERSE_CHANNEL_UNAVAILABLE",
                "unknown",
            );
            let _ = data_tx.try_send(DataOutbound::Close);
            let _ = control_tx.try_send(ControlOutbound::Close);
            let _ = self
                .command_tx
                .try_send(Command::DisconnectControl(key.clone()));
            return;
        }
        if queue_data(&data_tx, &queue_budget, fin).is_err() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "REVERSE_CHANNEL_UNAVAILABLE",
                "unknown",
            );
            let _ = data_tx.try_send(DataOutbound::Close);
            let _ = control_tx.try_send(ControlOutbound::Close);
            let _ = self
                .command_tx
                .try_send(Command::DisconnectControl(key.clone()));
            return;
        }
        if let Some(session) = self.session_mut(&key)
            && let Some(pending) = session.pending.get_mut(&challenge.stream_id)
        {
            let body_len = pending.body.len();
            pending.body.clear();
            pending.authorization_in_flight = false;
            pending.dispatched = true;
            session.queued_bytes = session.queued_bytes.saturating_sub(body_len);
            session.queue_budget.release(body_len);
        }
    }

    async fn inbound_data(&mut self, key: SessionKey, bytes: Vec<u8>) {
        if bytes.len() > tunnel_protocol::frame::MAX_FRAME_LEN {
            return self.protocol_failure(&key, "FRAME_LIMIT").await;
        }
        let frame = match wire::decode_frame(&bytes) {
            Ok(frame) => frame,
            Err(_) => return self.protocol_failure(&key, "INVALID_FRAME").await,
        };
        let Some(session) = self.session_for(&key) else {
            return;
        };
        if frame.epoch != key.epoch || frame.generation != session.generation {
            return self.protocol_failure(&key, "STALE_DATA").await;
        }
        let stream_id = frame.stream_id;
        let max_response_bytes = self
            .options
            .limits
            .max_body_bytes
            .saturating_add(MAX_ECHO_RESPONSE_EXTRA_BYTES);
        match frame.kind {
            FrameKind::Data | FrameKind::Fin => {
                if !self
                    .session_for(&key)
                    .is_some_and(|session| session.pending.contains_key(&stream_id))
                {
                    return self.protocol_failure(&key, "UNKNOWN_STREAM").await;
                }
                let (update, data_tx, queue_budget, tenant_id, operation_id) = {
                    let Some(session) = self.session_mut(&key) else {
                        return;
                    };
                    let Some(pending) = session.pending.get_mut(&stream_id) else {
                        return;
                    };
                    let data_tx = session.data_tx.clone();
                    let queue_budget = session.queue_budget.clone();
                    let tenant_id = session.identity.tenant_id;
                    let operation_id = pending.operation_id.clone();
                    let invalid_frame = !pending.dispatched
                        || frame.ack > pending.send_sequence.saturating_add(1)
                        || frame.sequence <= pending.response_sequence
                        || frame.sequence != pending.response_sequence.saturating_add(1)
                        || (frame.kind == FrameKind::Data
                            && (pending
                                .response_body
                                .len()
                                .saturating_add(frame.payload.len())
                                > max_response_bytes
                                || !queue_budget.reserve(frame.payload.len())));
                    if invalid_frame {
                        (
                            ResponseFrameUpdate::Invalid,
                            data_tx,
                            queue_budget,
                            tenant_id,
                            operation_id,
                        )
                    } else {
                        pending.response_sequence = frame.sequence;
                        if frame.kind == FrameKind::Data {
                            pending.response_body.extend_from_slice(&frame.payload);
                            (
                                ResponseFrameUpdate::Accepted,
                                data_tx,
                                queue_budget,
                                tenant_id,
                                operation_id,
                            )
                        } else {
                            let body = std::mem::take(&mut pending.response_body);
                            let pending = session
                                .pending
                                .remove(&stream_id)
                                .expect("pending entry exists");
                            let released = pending.body.len().saturating_add(body.len());
                            session.queued_bytes = session.queued_bytes.saturating_sub(released);
                            session.queue_budget.release(released);
                            (
                                ResponseFrameUpdate::Complete(body, pending.response),
                                data_tx,
                                queue_budget,
                                tenant_id,
                                operation_id,
                            )
                        }
                    }
                };
                if matches!(&update, ResponseFrameUpdate::Accepted)
                    && let Some(session) = self.session_mut(&key)
                {
                    session.queued_bytes = session.queued_bytes.saturating_add(frame.payload.len());
                }
                let ack_sequence = match &update {
                    ResponseFrameUpdate::Accepted | ResponseFrameUpdate::Complete(_, _) => {
                        frame.sequence
                    }
                    ResponseFrameUpdate::Invalid => {
                        self.protocol_failure(&key, "INVALID_SEQUENCE").await;
                        return;
                    }
                };
                let Some(data_tx) = data_tx else {
                    if let ResponseFrameUpdate::Complete(_, response) = update {
                        let _ = response.send(EchoOutcome::Failure {
                            code: "DEVICE_OFFLINE",
                            execution: "unknown",
                        });
                    }
                    self.protocol_failure(&key, "DEVICE_OFFLINE").await;
                    return;
                };
                let Ok(ack) = tunnel_protocol::Frame::ack(
                    key.epoch,
                    self.sessions[&key.device_id].generation,
                    stream_id,
                    ack_sequence,
                )
                .encode() else {
                    self.protocol_failure(&key, "FRAME_LIMIT").await;
                    return;
                };
                if queue_data(&data_tx, &queue_budget, ack).is_err() {
                    if let ResponseFrameUpdate::Complete(_, response) = update {
                        let _ = response.send(EchoOutcome::Failure {
                            code: "REVERSE_CHANNEL_UNAVAILABLE",
                            execution: "unknown",
                        });
                    }
                    self.protocol_failure(&key, "REVERSE_CHANNEL_UNAVAILABLE")
                        .await;
                    return;
                }
                if let ResponseFrameUpdate::Complete(body, response) = update {
                    let response_bytes = body.len();
                    let _ = response.send(EchoOutcome::Success(body));
                    tracing::debug!(
                        tenant_id = %tenant_id,
                        device_id = %key.device_id,
                        session_id = %key.session_id,
                        epoch = key.epoch,
                        stream_id,
                        operation_id = %operation_id,
                        bytes = response_bytes,
                        phase = "stream_completed",
                    );
                }
            }
            FrameKind::Ack => {
                let stale_ack = self
                    .session_for(&key)
                    .and_then(|session| session.pending.get(&stream_id))
                    .is_some_and(|pending| {
                        !pending.dispatched || frame.ack > pending.send_sequence.saturating_add(1)
                    });
                if stale_ack {
                    self.protocol_failure(&key, "STALE_ACK").await;
                }
            }
            FrameKind::WindowUpdate => {
                // M1 has no receive-window state to update; the bounded queue is
                // governed by the per-session budget and the frame size limit.
            }
            FrameKind::Reset => {
                let valid_reset = self
                    .session_for(&key)
                    .and_then(|session| session.pending.get(&stream_id))
                    .is_some_and(|pending| {
                        pending.dispatched
                            && frame.ack <= pending.send_sequence.saturating_add(1)
                            && pending.response_sequence.checked_add(1) == Some(frame.sequence)
                    });
                if valid_reset {
                    self.fail_pending(&key, stream_id, "DEVICE_RESET", "unknown");
                } else {
                    self.protocol_failure(&key, "INVALID_RESET").await;
                }
            }
        }
    }

    fn cancel(&mut self, key: &SessionKey, stream_id: u64, operation_id: String) {
        if let Some(session) = self.session_mut(key)
            && session
                .pending
                .get(&stream_id)
                .is_some_and(|pending| pending.operation_id == operation_id)
            && let Some(pending) = session.pending.remove(&stream_id)
        {
            release_pending_budget(session, &pending);
            let _ = pending.response.send(EchoOutcome::Failure {
                code: "CANCELLED",
                execution: "unknown",
            });
            if let Ok(message) = wire::encode_control_message(&wire::cancel(
                &key.session_id,
                key.epoch,
                stream_id,
                &operation_id,
            )) {
                let _ = queue_control(&session.control_tx, &session.queue_budget, message);
            }
        }
    }

    async fn tick(&mut self) {
        let now = Instant::now();
        let keys: Vec<_> = self
            .sessions
            .values()
            .map(|session| session.key.clone())
            .collect();
        for key in keys {
            let expired: Vec<_> = self
                .session_for(&key)
                .map(|session| {
                    session
                        .pending
                        .iter()
                        .filter(|(_, pending)| {
                            pending.response.is_closed()
                                || pending.created_at.elapsed()
                                    > self.options.limits.operation_timeout
                        })
                        .map(|(stream_id, _)| *stream_id)
                        .collect()
                })
                .unwrap_or_default();
            for stream_id in expired {
                self.fail_pending(&key, stream_id, "REVERSE_CHANNEL_INTERRUPTED", "unknown");
            }
            let Some(snapshot) = self.session_for(&key).map(|session| {
                (
                    session.identity.spki_fingerprint.clone(),
                    session.identity.device_version,
                    session.owner.clone(),
                    session.last_lease_renewal,
                    session.maintenance_in_flight,
                )
            }) else {
                continue;
            };
            if snapshot.4 {
                continue;
            }
            if let Some(session) = self.session_mut(&key) {
                session.maintenance_in_flight = true;
            }
            let catalog = self.catalog.clone();
            let command_tx = self.command_tx.clone();
            let owner_lease = self.options.owner_lease;
            let renew = snapshot.3.elapsed() >= owner_lease / 3;
            tokio::spawn(async move {
                let renewed = if renew {
                    let lease_expires_at = Utc::now()
                        + ChronoDuration::from_std(owner_lease)
                            .unwrap_or_else(|_| ChronoDuration::seconds(30));
                    Some(
                        catalog
                            .renew_owner(&snapshot.2, lease_expires_at)
                            .await
                            .map_err(|error| error.to_string()),
                    )
                } else {
                    None
                };
                let identity = catalog
                    .resolve_device(&snapshot.0, Utc::now())
                    .await
                    .map_err(|error| error.to_string());
                let _ = command_tx
                    .send(Command::MaintenanceResult {
                        key,
                        renewed,
                        identity,
                    })
                    .await;
            });
        }
        let wall_now = Utc::now();
        self.tickets.retain(|_, ticket| {
            ticket.expires_at > now
                && wall_now >= ticket.issued_at_wall
                && wall_now < ticket.expires_at_wall
        });
    }

    async fn finish_maintenance(
        &mut self,
        key: SessionKey,
        renewed: Option<Result<bool, String>>,
        identity: Result<Option<DeviceIdentity>, String>,
    ) {
        let mut close_reason = None;
        if let Some(session) = self.sessions.get_mut(&key.device_id) {
            if session.key != key {
                return;
            }
            session.maintenance_in_flight = false;
            if let Some(renewed) = renewed {
                match renewed {
                    Ok(true) => session.last_lease_renewal = Instant::now(),
                    _ => close_reason = Some("OWNER_FENCED"),
                }
            }
            match identity {
                Ok(Some(current))
                    if current.device_id == key.device_id
                        && current.device_version == session.identity.device_version
                        && current.spki_fingerprint == session.identity.spki_fingerprint
                        && current.device_active
                        && current.credential_active
                        && current.credential_revoked_at.is_none() => {}
                _ => {
                    if close_reason.is_none() {
                        close_reason = Some("AUTHORIZATION_REVOKED");
                    }
                }
            };
        }
        if let Some(reason) = close_reason {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                reason = %reason,
                phase = "owner_check_failed",
            );
            self.close_session(&key, reason).await;
        }
    }

    async fn disconnect_control(&mut self, key: SessionKey) {
        let matches = self
            .sessions
            .get(&key.device_id)
            .is_some_and(|session| session.key == key);
        if !matches {
            return;
        }
        self.close_session(&key, "CONTROL_CLOSED").await;
    }

    async fn disconnect_data(&mut self, key: SessionKey) {
        if let Some(session) = self.sessions.get_mut(&key.device_id) {
            if session.key != key {
                return;
            }
            session.data_tx = None;
            let pending = std::mem::take(&mut session.pending);
            session.queued_bytes = 0;
            for (_, pending) in pending {
                release_pending_budget(session, &pending);
                let _ = pending.response.send(EchoOutcome::Failure {
                    code: "REVERSE_CHANNEL_INTERRUPTED",
                    execution: "unknown",
                });
            }
        }
    }

    async fn close_session(&mut self, key: &SessionKey, reason: &str) {
        if !self
            .sessions
            .get(&key.device_id)
            .is_some_and(|session| session.key == *key)
        {
            return;
        }
        let Some(mut session) = self.sessions.remove(&key.device_id) else {
            return;
        };
        if session.closed {
            return;
        }
        session.closed = true;
        tracing::info!(
            tenant_id = %session.identity.tenant_id,
            device_id = %key.device_id,
            session_id = %key.session_id,
            epoch = key.epoch,
            reason = %reason,
            phase = "session_closed",
        );
        let rejected = wire::rejected(
            &wire::random_token(),
            &session.key.session_id,
            session.key.epoch,
            1,
            "session",
            reason,
            "device session closed",
        );
        if let Ok(text) = wire::encode_control_message(&rejected) {
            let _ = queue_control(&session.control_tx, &session.queue_budget, text);
        }
        let _ = session.control_tx.try_send(ControlOutbound::Close);
        if let Some(data) = session.data_tx.take() {
            let _ = data.try_send(DataOutbound::Close);
        }
        let queue_budget = session.queue_budget.clone();
        for (_, pending) in session.pending.drain() {
            let bytes = pending
                .body
                .len()
                .saturating_add(pending.response_body.len());
            queue_budget.release(bytes);
            let _ = pending.response.send(EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_INTERRUPTED",
                execution: "unknown",
            });
        }
        self.tickets
            .retain(|_, ticket| ticket.session_id != key.session_id || ticket.epoch != key.epoch);
        let catalog = self.catalog.clone();
        let owner = session.owner.clone();
        self.cleanup_tasks.push(tokio::spawn(async move {
            let _ = catalog.release_owner(&owner).await;
        }));
    }

    async fn close_all(&mut self) {
        let keys: Vec<_> = self
            .sessions
            .values()
            .map(|session| session.key.clone())
            .collect();
        for key in keys {
            self.close_session(&key, "SHUTDOWN").await;
        }
        self.tickets.clear();
        while let Some(task) = self.cleanup_tasks.pop() {
            let _ = task.await;
        }
    }

    async fn protocol_failure(&mut self, key: &SessionKey, code: &str) {
        self.close_session(key, code).await;
    }

    fn session_for(&self, key: &SessionKey) -> Option<&DeviceSession> {
        self.sessions
            .get(&key.device_id)
            .filter(|session| session.key == *key)
    }

    fn ticket_matches(&self, ticket: &Ticket) -> bool {
        self.tickets.get(&ticket.value).is_some_and(|pending| {
            pending.value == ticket.value
                && pending.session_id == ticket.session_id
                && pending.epoch == ticket.epoch
                && pending.generation == ticket.generation
                && pending.consuming
                && pending.expires_at == ticket.expires_at
                && pending.expires_at_wall == ticket.expires_at_wall
        })
    }

    fn remove_ticket_if_matches(&mut self, ticket: &Ticket) {
        if self.ticket_matches(ticket) {
            self.tickets.remove(&ticket.value);
        }
    }

    fn session_mut(&mut self, key: &SessionKey) -> Option<&mut DeviceSession> {
        self.sessions
            .get_mut(&key.device_id)
            .filter(|session| session.key == *key)
    }

    fn fail_pending(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        code: &'static str,
        execution: &'static str,
    ) {
        if let Some(session) = self.session_mut(key)
            && let Some(pending) = session.pending.remove(&stream_id)
        {
            release_pending_budget(session, &pending);
            let _ = pending
                .response
                .send(EchoOutcome::Failure { code, execution });
        }
    }

    fn invalidate_pending(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        challenge: &DeviceChallenge,
        reason: &str,
    ) {
        let _ = self.send_control(
            key,
            wire::authorization_invalidated(
                &key.session_id,
                key.epoch,
                stream_id,
                &challenge.challenge_id,
                challenge.grant_revision,
                reason,
            ),
        );
        self.fail_pending(key, stream_id, "AUTHORIZATION_REVOKED", "not_dispatched");
    }

    fn send_control(&self, key: &SessionKey, message: ControlMessage) -> Result<(), RelayError> {
        let text = wire::encode_control_message(&message)
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
        let session = self.session_for(key).ok_or(RelayError::NotFound)?;
        queue_control(&session.control_tx, &session.queue_budget, text)
            .map_err(|_| RelayError::Overloaded("control queue is full"))
    }
}

fn release_pending_budget(session: &mut DeviceSession, pending: &PendingEcho) {
    let bytes = pending
        .body
        .len()
        .saturating_add(pending.response_body.len());
    session.queued_bytes = session.queued_bytes.saturating_sub(bytes);
    session.queue_budget.release(bytes);
}

fn queue_control(
    sender: &mpsc::Sender<ControlOutbound>,
    budget: &QueueBudget,
    text: String,
) -> Result<(), ()> {
    let bytes = text.len();
    if !budget.reserve(bytes) {
        return Err(());
    }
    if sender.try_send(ControlOutbound::Text(text)).is_err() {
        budget.release(bytes);
        return Err(());
    }
    Ok(())
}

fn queue_data(
    sender: &mpsc::Sender<DataOutbound>,
    budget: &QueueBudget,
    bytes: Vec<u8>,
) -> Result<(), ()> {
    let length = bytes.len();
    if !budget.reserve(length) {
        return Err(());
    }
    if sender.try_send(DataOutbound::Binary(bytes)).is_err() {
        budget.release(length);
        return Err(());
    }
    Ok(())
}

fn validate_hello(message: &Hello, device_id: Uuid) -> Result<(), RelayError> {
    if message.protocol_major != u16::from(crate::PROTOCOL_MAJOR) {
        return Err(RelayError::Protocol("unsupported protocol major".into()));
    }
    if message.connector_id.parse::<Uuid>().ok() != Some(device_id) {
        return Err(RelayError::Unauthorized);
    }
    let supports_echo = message.features.iter().any(|value| value == "echo")
        || message
            .services
            .iter()
            .any(|service| service.service_type == crate::ECHO_SERVICE_TYPE);
    if !supports_echo {
        return Err(RelayError::Protocol(
            "device did not advertise fixed echo export".into(),
        ));
    }
    Ok(())
}

/// A running relay owns its two transport listener tasks and actor.  Dropping
/// a running value requests cancellation; callers should prefer `shutdown`
/// to observe all joins and catalog lease cleanup.
pub struct RunningRelay {
    pub(crate) handle: RelayHandle,
    cancel: CancellationToken,
    consumer_task: JoinHandle<Result<(), tunnel_transport::TransportError>>,
    device_task: JoinHandle<Result<(), tunnel_transport::TransportError>>,
    pub consumer_addr: std::net::SocketAddr,
    pub device_addr: std::net::SocketAddr,
}

impl RunningRelay {
    pub async fn shutdown(self) -> Result<(), RelayError> {
        self.cancel.cancel();
        let _ = self.handle.shutdown().await;
        self.consumer_task
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        self.device_task
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        Ok(())
    }
}

/// Relay construction and listener startup.
pub struct Relay;

impl Relay {
    pub async fn start(
        options: RelayOptions,
        catalog: SharedCatalog,
        consumer_listener: TcpListener,
        device_listener: TcpListener,
        consumer_tls: Arc<rustls::ServerConfig>,
        device_tls: Arc<rustls::ServerConfig>,
    ) -> Result<RunningRelay, RelayError> {
        options
            .validate()
            .map_err(|error| RelayError::Config(error.to_string()))?;
        let handle = RelayHandle::spawn(options.clone(), catalog.clone());
        let cancel = options.shutdown.clone();
        let consumer_addr = consumer_listener
            .local_addr()
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        let device_addr = device_listener
            .local_addr()
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        let consumer_router = http::consumer_router(
            handle.clone(),
            catalog.clone(),
            options.oidc.clone(),
            options.limits.clone(),
        );
        let device_router = http::device_router(handle.clone(), options.limits.clone());
        let consumer_cancel = cancel.child_token();
        let device_cancel = cancel.child_token();
        let consumer_task = tokio::spawn(async move {
            tunnel_transport::serve(
                consumer_listener,
                consumer_router,
                consumer_tls,
                consumer_cancel,
            )
            .await
        });
        let device_task = tokio::spawn(async move {
            tunnel_transport::serve(device_listener, device_router, device_tls, device_cancel).await
        });
        Ok(RunningRelay {
            handle,
            cancel,
            consumer_task,
            device_task,
            consumer_addr,
            device_addr,
        })
    }

    pub async fn spawn(
        options: RelayOptions,
        catalog: SharedCatalog,
    ) -> Result<RelayHandle, RelayError> {
        options
            .validate()
            .map_err(|error| RelayError::Config(error.to_string()))?;
        Ok(RelayHandle::spawn(options, catalog))
    }

    pub fn router(
        handle: RelayHandle,
        catalog: SharedCatalog,
        oidc: Arc<tunnel_catalog::OidcVerifier>,
        limits: RelayLimits,
    ) -> Router {
        http::router(handle, catalog, oidc, limits)
    }
}
