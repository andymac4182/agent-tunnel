use crate::database::{RedisLease, RedisLeaseOptions};
use crate::error::{HarnessError, Result};
use crate::fixture::{FixtureTopology, SharedFixtureIdentity};
use crate::oidc::OidcFixture;
use crate::pki::FixturePki;
use crate::proxy::{ProxyConfig, ProxyHandle, TcpProxy};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use std::sync::Arc;
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;
use tunnel_catalog::{ApprovedJwk, Catalog, OidcConfig, OidcVerifier, RedisCatalog};
use tunnel_core::RotationConfig;
use tunnel_relay::{Relay, RelayLimits, RelayOptions, RelaySnapshot, RunningRelay};

const FIXTURE_DEPLOYMENT_INCARNATION: &str = "m1-local";

/// Inputs for one isolated real-socket harness run.
#[derive(Clone, Debug)]
pub struct HarnessOptions {
    pub redis_url: Option<String>,
    pub namespace_prefix: Option<String>,
    pub proxy_target: Option<SocketAddr>,
    pub proxy_config: ProxyConfig,
    /// Effective data-carrier rotation policy used by the production relay.
    /// M1 callers can keep the defaults; M2 acceptance overrides this with an
    /// accelerated policy while preserving the same real runtime path.
    pub rotation: RotationConfig,
    /// Build the production fixture with one device UUID reused by both
    /// tenant scopes.  This is reserved for tenant-isolation acceptance and
    /// remains disabled for the ordinary M1/M2 topology.
    pub shared_device_uuid: bool,
    /// Explicit colliding device/service identity for an M7 tenant-isolation
    /// run. This takes precedence over `shared_device_uuid` when set.
    pub shared_fixture_identity: Option<SharedFixtureIdentity>,
    /// Seed a second active `echo` service on the first tenant-A device so a
    /// service-type label has more than one live target.  This is reserved for
    /// the fail-closed admission matrix and stays disabled everywhere else, so
    /// no existing gate's service or grant counts change.
    pub ambiguous_echo_service: bool,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            redis_url: None,
            namespace_prefix: Some("m1-fixture".to_owned()),
            proxy_target: None,
            proxy_config: ProxyConfig::default(),
            rotation: RotationConfig::default(),
            shared_device_uuid: false,
            shared_fixture_identity: None,
            ambiguous_echo_service: false,
        }
    }
}

impl HarnessOptions {
    pub fn from_env() -> Result<Self> {
        let proxy_target = std::env::var("TUNNEL_TEST_PROXY_TARGET")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value.parse::<SocketAddr>().map_err(|error| {
                    HarnessError::InvalidInput(format!(
                        "TUNNEL_TEST_PROXY_TARGET {value:?}: {error}"
                    ))
                })
            })
            .transpose()?;
        Ok(Self {
            redis_url: std::env::var("TEST_REDIS_URL").ok(),
            namespace_prefix: std::env::var("TUNNEL_TEST_REDIS_NAMESPACE_PREFIX").ok(),
            proxy_target,
            ..Self::default()
        })
    }

    pub fn redis_url(mut self, value: impl Into<String>) -> Self {
        self.redis_url = Some(value.into());
        self
    }

    pub fn namespace_prefix(mut self, value: impl Into<String>) -> Self {
        self.namespace_prefix = Some(value.into());
        self
    }

    pub fn proxy_target(mut self, value: SocketAddr) -> Self {
        self.proxy_target = Some(value);
        self
    }

    pub fn proxy_config(mut self, value: ProxyConfig) -> Self {
        self.proxy_config = value;
        self
    }

    pub fn rotation(mut self, value: RotationConfig) -> Self {
        self.rotation = value;
        self
    }

    pub fn shared_device_uuid(mut self, value: bool) -> Self {
        self.shared_device_uuid = value;
        self
    }

    /// Opt into the duplicate active `echo` service used by the fail-closed
    /// admission matrix's ambiguous-target scenario.
    pub fn ambiguous_echo_service(mut self, value: bool) -> Self {
        self.ambiguous_echo_service = value;
        self
    }

    /// Opt into a fixture where both tenant records use the supplied device
    /// and service UUIDs. The topology is seeded once through the production
    /// catalog, preserving tenant-qualified authority keys.
    pub fn shared_fixture_identity(mut self, value: SharedFixtureIdentity) -> Self {
        self.shared_fixture_identity = Some(value);
        self.shared_device_uuid = false;
        self
    }
}

/// Entry point kept deliberately tiny so integration tests can share setup.
pub struct Harness;

impl Harness {
    pub async fn start(options: HarnessOptions) -> Result<RunningHarness> {
        // Open Redis first so a missing or unavailable dependency fails
        // before any test can accidentally report fixture-only success.
        let redis = RedisLease::open(RedisLeaseOptions {
            redis_url: options.redis_url,
            namespace_prefix: options.namespace_prefix,
        })
        .await?;
        let pki = match FixturePki::new() {
            Ok(pki) => pki,
            Err(error) => {
                return Err(with_redis_cleanup(error, redis.close().await));
            }
        };
        let oidc = match OidcFixture::new("https://m1-oidc.fixture.test", "agent-tunnel") {
            Ok(oidc) => oidc,
            Err(error) => {
                return Err(with_redis_cleanup(error, redis.close().await));
            }
        };
        let topology = match match options.shared_fixture_identity {
            Some(shared) => FixtureTopology::new_with_shared_device_and_service_uuid(&pki, shared),
            None if options.shared_device_uuid => {
                FixtureTopology::new_with_shared_device_uuid(&pki, uuid::Uuid::new_v4())
            }
            None => FixtureTopology::new(&pki),
        } {
            Ok(topology) => topology,
            Err(error) => {
                return Err(with_redis_cleanup(error, redis.close().await));
            }
        };
        let proxy = match options.proxy_target {
            Some(target) => match TcpProxy::bind(target, options.proxy_config).await {
                Ok(proxy) => Some(proxy),
                Err(error) => {
                    return Err(with_redis_cleanup(error, redis.close().await));
                }
            },
            None => None,
        };

        // Connect and seed the same production RedisCatalog instance that the
        // relay will receive.  This is intentionally a one-time seed; callers
        // obtain clones through RunningHarness::production_catalog.
        let redis_url = redis.redis_url().to_owned();
        if let Err(error) =
            crate::c11_capture::record_sentinel("private_endpoint", redis_url.as_bytes())
        {
            return Err(with_redis_cleanup(error, redis.close().await));
        }
        let namespace = redis.namespace().to_owned();
        let catalog = match RedisCatalog::connect_for_recovery(
            &redis_url,
            &namespace,
            FIXTURE_DEPLOYMENT_INCARNATION,
        )
        .await
        {
            Ok(catalog) => catalog,
            Err(error) => {
                let error =
                    HarnessError::Redis(format!("connecting production Redis catalog: {error}"));
                return Err(with_redis_cleanup(error, redis.close().await));
            }
        };
        // A fresh, isolated fixture is an explicit bootstrap operation. Normal
        // relay startup may only verify existing authority metadata.
        if let Err(error) = catalog.activate_deployment_incarnation().await {
            let error = HarnessError::Redis(format!("bootstrapping fixture authority: {error}"));
            return Err(with_redis_cleanup(error, redis.close().await));
        }
        let mut fixture = match topology.catalog_fixture(&oidc) {
            Ok(fixture) => fixture,
            Err(error) => return Err(with_redis_cleanup(error, redis.close().await)),
        };
        let admission_devices =
            match crate::admission::prepare_admission_devices(&pki, &topology, &mut fixture) {
                Ok(devices) => devices,
                Err(error) => return Err(with_redis_cleanup(error, redis.close().await)),
            };
        let ambiguous_echo_service = if options.ambiguous_echo_service {
            // Deliberately the last tenant-A device: the first one can share
            // its device and service UUID with tenant B, and an ambiguous
            // label must be scoped to exactly one tenant's service list.
            let device_id = match topology.devices_a.last() {
                Some(device) => device.id,
                None => {
                    let error = HarnessError::InvalidInput(
                        "ambiguous echo service requires a tenant-A device".to_owned(),
                    );
                    return Err(with_redis_cleanup(error, redis.close().await));
                }
            };
            match topology.push_ambiguous_echo_service(&mut fixture, device_id) {
                Ok(service_id) => Some(service_id),
                Err(error) => return Err(with_redis_cleanup(error, redis.close().await)),
            }
        } else {
            None
        };
        if let Err(error) = catalog.seed_fixture(&fixture).await {
            let error = HarnessError::Redis(format!("seeding production Redis catalog: {error}"));
            // A seed is one-shot. Discard a failed fixture, including partial
            // writes and its guard, instead of attempting to reseed it.
            let cleanup = catalog.cleanup_fixture_namespace().await.map_err(|error| {
                HarnessError::Redis(format!("discarding failed catalog fixture: {error}"))
            });
            let error = with_redis_cleanup(error, cleanup);
            return Err(with_redis_cleanup(error, redis.close().await));
        }
        Ok(RunningHarness {
            redis,
            pki,
            oidc,
            topology,
            admission_devices,
            ambiguous_echo_service,
            proxy,
            production_catalog: Some(catalog),
            production_relay: None,
            rotation: options.rotation,
        })
    }
}

/// Resources owned by one test run.  The relay and catalog are production
/// implementations started from this resource manager; callers drive them
/// through real sockets, so this object cannot pass a test through an
/// in-process routing shortcut.
pub struct RunningHarness {
    pub redis: RedisLease,
    pub pki: FixturePki,
    pub oidc: OidcFixture,
    pub topology: FixtureTopology,
    pub(crate) admission_devices: Vec<crate::admission::AdmissionDevice>,
    /// The duplicate active `echo` service seeded for the fail-closed
    /// admission matrix, present only when that option was requested.
    pub ambiguous_echo_service: Option<uuid::Uuid>,
    pub proxy: Option<ProxyHandle>,
    production_catalog: Option<RedisCatalog>,
    production_relay: Option<RunningRelay>,
    rotation: RotationConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicConsumerEvidence {
    pub invalid_token_status: StatusCode,
    pub valid_token_status: StatusCode,
    pub valid_body: Vec<u8>,
}

impl std::fmt::Debug for RunningHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningHarness")
            .field("redis", &self.redis)
            .field("topology", &self.topology)
            .field("proxy", &self.proxy)
            .field("production_relay_running", &self.production_relay.is_some())
            .finish_non_exhaustive()
    }
}

impl RunningHarness {
    pub(crate) fn rotation_config(&self) -> RotationConfig {
        self.rotation.clone()
    }

    /// Return the already seeded production Redis catalog.  The relay and
    /// acceptance callers share this cloneable connection-backed instance;
    /// this accessor never reconnects, reseeds, or substitutes a memory
    /// catalog.
    pub fn production_catalog(&self) -> Result<RedisCatalog> {
        self.production_catalog.clone().ok_or_else(|| {
            HarnessError::InvalidInput("production Redis catalog is unavailable".to_owned())
        })
    }

    /// Start the real Axum relay with ephemeral public consumer and mandatory
    /// device-mTLS listeners.  The caller still drives those listeners through
    /// a real HTTP/WebSocket client or process; no handler is called directly.
    pub async fn start_production_relay(&mut self) -> Result<(SocketAddr, SocketAddr)> {
        self.start_production_relay_with_limits(RelayLimits::default())
            .await
    }

    /// Start the production relay with explicit bounded runtime limits.  M1
    /// admission tests use this to make queue saturation deterministic while
    /// retaining the exact production relay and transport stack.
    pub async fn start_production_relay_with_limits(
        &mut self,
        limits: RelayLimits,
    ) -> Result<(SocketAddr, SocketAddr)> {
        if self.production_relay.is_some() {
            return Err(HarnessError::InvalidInput(
                "production relay already started".to_owned(),
            ));
        }
        let catalog = self.production_catalog()?;
        let consumer_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let device_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let server = self
            .pki
            .issue_server("relay-m1")
            .map_err(|error| HarnessError::Pki(error.to_string()))?;
        let server_chain = format!(
            "{}{}",
            server.certificate_pem, self.pki.server_ca.certificate_pem
        );
        let device_tls = tunnel_transport::load_server_config_from_pem(
            server_chain.as_bytes(),
            server.private_key_pem.as_bytes(),
            Some(self.pki.device_ca.certificate_pem.as_bytes()),
        )
        .map_err(|error| HarnessError::Pki(format!("building device TLS config: {error}")))?;
        let consumer_tls = tunnel_transport::load_server_config_from_pem(
            server_chain.as_bytes(),
            server.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| HarnessError::Pki(format!("building consumer TLS config: {error}")))?;
        let oidc = self.production_oidc_verifier()?;
        let mut options = RelayOptions::new(oidc);
        options.limits = limits;
        options.deployment_incarnation = FIXTURE_DEPLOYMENT_INCARNATION.to_owned();
        options.rotation = self.rotation.clone();
        let shared_catalog: tunnel_catalog::SharedCatalog = Arc::new(catalog.clone());
        let relay = Relay::start(
            options,
            shared_catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
        )
        .await
        .map_err(|error| HarnessError::Process(format!("starting production relay: {error}")))?;
        let addresses = (relay.consumer_addr, relay.device_addr);
        self.production_catalog = Some(catalog);
        self.production_relay = Some(relay);
        Ok(addresses)
    }

    pub fn production_addresses(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.production_relay
            .as_ref()
            .map(|relay| (relay.consumer_addr, relay.device_addr))
    }

    /// Return the relay's bounded, payload-free runtime snapshot for
    /// acceptance evidence.  This remains an in-process diagnostic call; all
    /// exercised service traffic still crosses the public TLS/WebSocket
    /// listeners.
    pub async fn production_snapshot(&self) -> Result<RelaySnapshot> {
        let relay = self.production_relay.as_ref().ok_or_else(|| {
            HarnessError::InvalidInput("production relay is not running".to_owned())
        })?;
        relay
            .snapshot()
            .await
            .map_err(|error| HarnessError::Process(format!("reading relay snapshot: {error}")))
    }

    /// Exercise the public HTTPS listener through a real TLS connection and
    /// HTTP/1.1 client.  This intentionally uses the public router and bearer
    /// verifier; it never calls relay handlers or actor methods directly.
    pub async fn verify_public_consumer(&self) -> Result<PublicConsumerEvidence> {
        let (consumer_addr, _) = self.production_addresses().ok_or_else(|| {
            HarnessError::InvalidInput("production relay is not running".to_owned())
        })?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                self.pki.server_ca.certificate_der.clone(),
            ))
            .map_err(|error| {
                HarnessError::Http(format!("adding server CA to HTTPS probe: {error}"))
            })?;
        let client_config =
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|error| HarnessError::Http(format!("configuring HTTPS TLS 1.3: {error}")))?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = tokio::net::TcpStream::connect(consumer_addr).await?;
        let server_name = ServerName::try_from("localhost".to_owned()).map_err(|error| {
            HarnessError::Http(format!("building localhost server name: {error}"))
        })?;
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| HarnessError::Http(format!("consumer TLS handshake: {error}")))?;
        let io = TokioIo::new(tls_stream);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|error| HarnessError::Http(format!("HTTP/1.1 handshake: {error}")))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let invalid_request = Request::builder()
            .method("GET")
            .uri("/v1/devices")
            .header("host", "localhost")
            .header("authorization", "Bearer invalid")
            .body(Empty::<Bytes>::new())
            .map_err(|error| {
                HarnessError::Http(format!("building invalid-token request: {error}"))
            })?;
        let invalid_response = sender
            .send_request(invalid_request)
            .await
            .map_err(|error| HarnessError::Http(format!("invalid-token request: {error}")))?;
        let invalid_token_status = invalid_response.status();
        let _ = invalid_response.into_body().collect().await;

        // A fresh connection is used for the valid request because HTTP/1.1
        // sender ownership is consumed by the in-flight response body.
        let stream = tokio::net::TcpStream::connect(consumer_addr).await?;
        let server_name = ServerName::try_from("localhost".to_owned()).map_err(|error| {
            HarnessError::Http(format!("building localhost server name: {error}"))
        })?;
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| HarnessError::Http(format!("consumer TLS handshake: {error}")))?;
        let io = TokioIo::new(tls_stream);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|error| HarnessError::Http(format!("HTTP/1.1 handshake: {error}")))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let subject = self
            .topology
            .consumers_a
            .first()
            .ok_or_else(|| HarnessError::InvalidInput("fixture has no consumer".to_owned()))?;
        let token = self.oidc.issue(&subject.name)?;
        let valid_request = Request::builder()
            .method("GET")
            .uri("/v1/devices")
            .header("host", "localhost")
            .header("authorization", format!("Bearer {token}"))
            .body(Empty::<Bytes>::new())
            .map_err(|error| {
                HarnessError::Http(format!("building valid-token request: {error}"))
            })?;
        let valid_response = sender
            .send_request(valid_request)
            .await
            .map_err(|error| HarnessError::Http(format!("valid-token request: {error}")))?;
        let valid_token_status = valid_response.status();
        let valid_body = valid_response
            .into_body()
            .collect()
            .await
            .map_err(|error| HarnessError::Http(format!("reading valid-token response: {error}")))?
            .to_bytes()
            .to_vec();
        Ok(PublicConsumerEvidence {
            invalid_token_status,
            valid_token_status,
            valid_body,
        })
    }

    /// Construct the production OIDC verifier from the per-run RSA public key.
    pub fn production_oidc_verifier(&self) -> Result<Arc<OidcVerifier>> {
        let key =
            ApprovedJwk::from_rsa_pem(&self.oidc.key_id, self.oidc.public_key_pem().as_bytes())
                .map_err(|error| {
                    HarnessError::InvalidInput(format!("building OIDC approved key: {error}"))
                })?;
        let config = OidcConfig::new(
            self.oidc.issuer.clone(),
            [self.oidc.audience.clone()],
            vec![key],
        )
        .map_err(|error| {
            HarnessError::InvalidInput(format!("building OIDC verifier config: {error}"))
        })?
        .with_required_scopes(["echo:invoke".to_owned()])
        .map_err(|error| HarnessError::InvalidInput(format!("setting OIDC scope: {error}")))?;
        Ok(Arc::new(OidcVerifier::new(config).map_err(|error| {
            HarnessError::InvalidInput(format!("building OIDC verifier: {error}"))
        })?))
    }

    /// Stop the relay/proxy, close their tasks, and remove this run's Redis
    /// namespace.  Call this from the inner acceptance future before an outer
    /// timeout drops the run so cleanup failures remain observable.
    /// The public Redis lease is intentionally movable so shutdown can report
    /// cleanup failures instead of relying on `Drop`.
    pub async fn shutdown(mut self) -> Result<()> {
        let mut first_error = None;
        if let Some(relay) = self.production_relay.take()
            && let Err(error) = relay.shutdown().await
        {
            first_error = Some(HarnessError::Process(format!(
                "stopping production relay: {error}"
            )));
        }
        if let Some(catalog) = self.production_catalog.take()
            && let Err(error) = catalog.cleanup_fixture_namespace().await
        {
            first_error.get_or_insert_with(|| {
                HarnessError::Redis(format!("cleaning production Redis catalog: {error}"))
            });
        }
        if let Some(proxy) = self.proxy.take()
            && let Err(error) = proxy.shutdown().await
        {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.redis.close().await {
            first_error.get_or_insert(error);
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    /// Shut down with a caller-owned absolute deadline while retaining every
    /// task-bearing handle until its cancellation-safe join path completes.
    /// Relay and Redis lease shutdowns already own their internal bounds; the
    /// proxy uses an abort-and-join fallback when the shared deadline expires.
    pub async fn shutdown_until(mut self, deadline: tokio::time::Instant) -> Result<()> {
        let mut errors = Vec::new();
        if let Some(relay) = self.production_relay.take()
            && let Err(error) = relay.shutdown().await
        {
            errors.push(format!("stopping production relay: {error}"));
        }
        if let Some(catalog) = self.production_catalog.take() {
            match tokio::time::timeout_at(deadline, catalog.cleanup_fixture_namespace()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    errors.push(format!("cleaning production Redis catalog: {error}"));
                }
                Err(_) => {
                    errors.push(
                        "cleaning production Redis catalog exceeded its shared deadline".to_owned(),
                    );
                }
            }
        }
        if let Some(mut proxy) = self.proxy.take()
            && let Err(error) = shutdown_proxy_until(&mut proxy, deadline).await
        {
            errors.push(format!("proxy cleanup: {error}"));
        }
        if let Err(error) = self.redis.close().await {
            errors.push(format!("Redis lease cleanup: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(errors.join("; ")))
        }
    }
}

const PROXY_FORCED_JOIN_GRACE: Duration = Duration::from_secs(2);

async fn shutdown_proxy_until(
    proxy: &mut ProxyHandle,
    graceful_deadline: tokio::time::Instant,
) -> Result<()> {
    let graceful = proxy.shutdown_until(graceful_deadline).await;
    let Err(graceful_error) = graceful else {
        return Ok(());
    };
    // Keep ownership after the helper's bounded abort/join path and perform
    // bounded retries on that same handle. Never call the unbounded
    // consuming `ProxyHandle::shutdown` from this deadline-aware path.
    let forced_deadline = tokio::time::Instant::now() + PROXY_FORCED_JOIN_GRACE;
    match proxy.shutdown_until(forced_deadline).await {
        Ok(()) => Err(HarnessError::Process(format!(
            "harness proxy exceeded its graceful shutdown deadline: {graceful_error}; bounded forced join completed"
        ))),
        Err(forced_error) => {
            let final_deadline = tokio::time::Instant::now() + PROXY_FORCED_JOIN_GRACE;
            match proxy.shutdown_until(final_deadline).await {
                Ok(()) => Err(HarnessError::Process(format!(
                    "harness proxy graceful shutdown failed: {graceful_error}; bounded forced join failed: {forced_error}; final bounded join completed"
                ))),
                Err(final_error) => Err(HarnessError::Process(format!(
                    "harness proxy graceful shutdown failed: {graceful_error}; bounded forced join failed: {forced_error}; final bounded join failed: {final_error}"
                ))),
            }
        }
    }
}

fn with_redis_cleanup(error: HarnessError, cleanup: Result<()>) -> HarnessError {
    match cleanup {
        Ok(()) => error,
        Err(cleanup_error) => HarnessError::Redis(format!(
            "{error}; Redis fixture cleanup also failed: {cleanup_error}"
        )),
    }
}
