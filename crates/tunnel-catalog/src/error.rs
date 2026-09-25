use std::{error::Error, fmt};

/// The bounded operation boundary where a Redis authority connection failed.
/// These stages describe catalog call sites, not inferred backend causes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogConnectionStage {
    ConnectionEstablishment,
    TlsSetup,
    Ping,
    PrimaryIdentity,
    AuthorityProfile,
    AuthorityIdentity,
}

impl CatalogConnectionStage {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ConnectionEstablishment => "connection_establishment",
            Self::TlsSetup => "tls_setup",
            Self::Ping => "ping",
            Self::PrimaryIdentity => "primary_identity",
            Self::AuthorityProfile => "authority_profile",
            Self::AuthorityIdentity => "authority_identity",
        }
    }
}

/// A typed startup context around a [`CatalogError`].  Existing catalog
/// methods continue to return [`CatalogError`]; the relay's startup path uses
/// this wrapper so its bounded diagnostic can identify the explicit operation
/// boundary without retaining a URL, credential, or backend error string.
///
/// Its `Debug` and `Display` print only the stage, lane and failure class,
/// and it exposes no `source()`: the wrapped [`CatalogError`] can hold a raw
/// `RedisError` whose text includes server replies or I/O messages, so it is
/// reachable only by consuming the wrapper with [`Self::into_catalog_error`].
pub struct CatalogConnectionError {
    stage: CatalogConnectionStage,
    lane: Option<CatalogConnectionLane>,
    failure: CatalogConnectionFailure,
    source: CatalogError,
}

/// Which authority connection failed while a catalog was being opened.  The
/// primary connection is opened first (and has no lane); the bounded
/// authorization and maintenance lanes follow it, numbered `1..=total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogConnectionLane {
    pub index: u8,
    pub total: u8,
}

/// A bounded class for the failure behind a [`CatalogConnectionError`].
///
/// The class is derived from typed error kinds only (the redis-rs error kind,
/// the I/O error kind, the rustls error variant, or the catalog's own fixed
/// error shape), never from backend or peer-supplied text, so it can be
/// printed without disclosing a URL, a credential, or a server message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogConnectionFailure {
    /// The bounded operation deadline elapsed.
    Timeout,
    /// The Redis host name did not resolve: the lookup failed or returned no
    /// address.
    Dns,
    /// The TCP connection was refused.
    Refused,
    /// The connection closed or failed at the transport layer.
    Io,
    /// The server's certificate was rejected (for example an unrelated CA
    /// or a name mismatch).
    TlsCertificate,
    /// The TLS peer sent an alert, for example refusing a missing or
    /// untrusted client certificate.
    TlsAlert,
    /// Any other TLS failure.
    Tls,
    /// Redis rejected the credentials (`AUTH` failure, `WRONGPASS`,
    /// `NOAUTH`).
    Auth,
    /// Redis refused the command for this ACL user (`NOPERM`).
    NoPerm,
    /// Redis answered with an error reply.
    Reply,
    /// Redis answered with a reply the catalog could not use (for example
    /// `INFO server` without a `run_id`).
    InvalidReply,
    /// A lane connected to a different Redis server run than the primary
    /// connection.
    RunIdConflict,
    /// The namespace has no deployment incarnation or no Redis run binding:
    /// it was never activated, or Redis came back without its data (M6-C65).
    Unbound,
    /// The namespace is bound to an earlier Redis server run: Redis
    /// restarted and nothing re-attested the namespace (M6-C65).
    RunChanged,
    /// The namespace is activated but `provision-catalog` has not run on it
    /// (M6-C34): `serve` refuses it so that a relay started between the two
    /// bootstrap commands cannot write anything that would make provisioning
    /// refuse the namespace.
    Unprovisioned,
    /// Redis restarted without the serving relay's last acknowledged
    /// continuity token: it came back from a copy older than that token (an
    /// earlier snapshot or backup, or a replica that had not received it), or
    /// a run already refused for this (M6-C65).  A copy that does hold the
    /// token is not caught: the token is no proof across failover or replica
    /// promotion.
    Continuity,
    /// A token re-binding was not attempted because the restarted Redis does
    /// not show `appendonly yes`, `appendfsync always` and
    /// `no-appendfsync-on-rewrite no` to `CONFIG GET`, or refused it (M6-C65).
    Persistence,
    /// The connection configuration was rejected before any exchange.
    Config,
    /// A catalog-level refusal (for example a missing or mismatched
    /// deployment incarnation).
    Catalog,
}

impl CatalogConnectionFailure {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Dns => "dns",
            Self::Refused => "refused",
            Self::Io => "io",
            Self::TlsCertificate => "tls_certificate",
            Self::TlsAlert => "tls_alert",
            Self::Tls => "tls",
            Self::Auth => "auth",
            Self::NoPerm => "noperm",
            Self::Reply => "reply",
            Self::InvalidReply => "invalid_reply",
            Self::RunIdConflict => "run_id_conflict",
            Self::Unbound => "unbound",
            Self::RunChanged => "run_changed",
            Self::Unprovisioned => "unprovisioned",
            Self::Continuity => "continuity",
            Self::Persistence => "persistence",
            Self::Config => "config",
            Self::Catalog => "catalog",
        }
    }

    /// Classify a catalog error by its typed shape only.
    pub fn classify(error: &CatalogError) -> Self {
        match error {
            CatalogError::Database(error) => classify_redis_error(error),
            CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ReplyTimeout) => Self::Timeout,
            CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ConnectionLost) => Self::Io,
            CatalogError::InvalidInput(_) => Self::Config,
            CatalogError::Serialization(_) => Self::InvalidReply,
            CatalogError::Unauthorized => Self::Auth,
            CatalogError::Conflict(label) if *label == crate::redis::NAMESPACE_UNBOUND => {
                Self::Unbound
            }
            CatalogError::Conflict(label) if *label == crate::redis::RUN_BINDING_CHANGED => {
                Self::RunChanged
            }
            CatalogError::Conflict(label) if *label == crate::redis::NAMESPACE_UNPROVISIONED => {
                Self::Unprovisioned
            }
            CatalogError::Conflict(label) if *label == crate::redis::CONTINUITY_MISMATCH => {
                Self::Continuity
            }
            CatalogError::Conflict(label) if *label == crate::redis::PERSISTENCE_UNSOUND => {
                Self::Persistence
            }
            CatalogError::NotFound
            | CatalogError::Conflict(_)
            | CatalogError::OwnerBusy
            | CatalogError::StaleOwner
            | CatalogError::InvalidOwner
            | CatalogError::RevisionOverflow => Self::Catalog,
        }
    }
}

/// The typed marker the catalog's own DNS resolver wraps in the I/O error it
/// returns when a Redis host name does not resolve, so the failure is
/// classified by type rather than by redis-rs's or the resolver's text.
#[derive(Debug)]
pub(crate) struct DnsLookupFailed;

impl fmt::Display for DnsLookupFailed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Redis host name lookup failed")
    }
}

impl Error for DnsLookupFailed {}

fn classify_redis_error(error: &redis::RedisError) -> CatalogConnectionFailure {
    use redis::{ErrorKind, ServerErrorKind};
    match error.kind() {
        ErrorKind::AuthenticationFailed => return CatalogConnectionFailure::Auth,
        ErrorKind::Server(ServerErrorKind::NoPerm) => return CatalogConnectionFailure::NoPerm,
        ErrorKind::InvalidClientConfig | ErrorKind::Client => {
            return CatalogConnectionFailure::Config;
        }
        ErrorKind::Parse | ErrorKind::UnexpectedReturnType | ErrorKind::RESP3NotSupported => {
            return CatalogConnectionFailure::InvalidReply;
        }
        ErrorKind::Io => {}
        _ => {
            // Redis error replies carry a fixed code word; only a small
            // allow-list of codes is interpreted, and the code itself is
            // never printed.
            return match error.code() {
                Some("WRONGPASS" | "NOAUTH") => CatalogConnectionFailure::Auth,
                Some("NOPERM") => CatalogConnectionFailure::NoPerm,
                _ => CatalogConnectionFailure::Reply,
            };
        }
    }
    // redis-rs keeps the I/O error behind an `Arc<dyn Error>`, which is what
    // `source()` returns; unwrap that one layer to reach the typed error.
    let Some(io_error) = std::error::Error::source(error).and_then(|source| {
        source
            .downcast_ref::<std::sync::Arc<dyn Error + Send + Sync>>()
            .and_then(|shared| shared.downcast_ref::<std::io::Error>())
            .or_else(|| source.downcast_ref::<std::io::Error>())
    }) else {
        return CatalogConnectionFailure::Io;
    };
    if io_error
        .get_ref()
        .is_some_and(|inner| inner.is::<DnsLookupFailed>())
    {
        return CatalogConnectionFailure::Dns;
    }
    if let Some(tls) = io_error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return match tls {
            rustls::Error::InvalidCertificate(_) => CatalogConnectionFailure::TlsCertificate,
            rustls::Error::AlertReceived(_) => CatalogConnectionFailure::TlsAlert,
            _ => CatalogConnectionFailure::Tls,
        };
    }
    match io_error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            CatalogConnectionFailure::Timeout
        }
        std::io::ErrorKind::ConnectionRefused => CatalogConnectionFailure::Refused,
        _ => CatalogConnectionFailure::Io,
    }
}

impl CatalogConnectionError {
    pub(crate) fn new(stage: CatalogConnectionStage, source: CatalogError) -> Self {
        Self {
            stage,
            lane: None,
            failure: CatalogConnectionFailure::classify(&source),
            source,
        }
    }

    /// Record a class the call site knows better than the error's shape,
    /// for example a lane on a different Redis server run.
    pub(crate) fn with_failure(mut self, failure: CatalogConnectionFailure) -> Self {
        self.failure = failure;
        self
    }

    pub(crate) fn with_lane(mut self, lane: CatalogConnectionLane) -> Self {
        self.lane = Some(lane);
        self
    }

    pub const fn stage(&self) -> CatalogConnectionStage {
        self.stage
    }

    /// The lane whose connection failed, or `None` for the primary
    /// connection and for failures outside connection setup.
    pub const fn lane(&self) -> Option<CatalogConnectionLane> {
        self.lane
    }

    /// The bounded failure class; see [`CatalogConnectionFailure`].
    pub const fn failure(&self) -> CatalogConnectionFailure {
        self.failure
    }

    pub fn into_catalog_error(self) -> CatalogError {
        self.source
    }
}

impl fmt::Debug for CatalogConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogConnectionError")
            .field("stage", &self.stage)
            .field("lane", &self.lane)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for CatalogConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Redis catalog connection failed; stage={}",
            self.stage.as_str()
        )?;
        if let Some(lane) = self.lane {
            write!(formatter, " lane={}/{}", lane.index, lane.total)?;
        }
        write!(formatter, " class={}", self.failure.as_str())
    }
}

/// No `source()`: see the type's documentation.
impl Error for CatalogConnectionError {}

impl From<CatalogConnectionError> for CatalogError {
    fn from(error: CatalogConnectionError) -> Self {
        error.into_catalog_error()
    }
}

/// Why an owner-affecting write has no known outcome.  Both causes occur
/// only after the command was dispatched to the authority: the script may
/// have committed before its reply was lost, so the caller must neither
/// assume failure nor replay the write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownWriteCause {
    /// The authority did not answer within the bounded operation deadline.
    ReplyTimeout,
    /// The connection was severed after dispatch, before a reply arrived.
    ConnectionLost,
}

impl UnknownWriteCause {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ReplyTimeout => "reply_timeout",
            Self::ConnectionLost => "connection_lost",
        }
    }
}

/// Errors returned by the durable catalog. User-facing handlers should map
/// these to bounded public codes; backend details are never included in a
/// response containing a bearer credential.
#[derive(Debug)]
pub enum CatalogError {
    Database(redis::RedisError),
    /// An owner-affecting write (`claim_owner`, `renew_owner`,
    /// `release_owner`) was dispatched but its reply was lost.  The write may
    /// have committed.  Callers keep the affected session unready until a
    /// fresh authoritative read confirms the owner state and never retry the
    /// write automatically.  A failure *before* dispatch keeps its definite
    /// shape (`Database`, `Conflict`, ...).
    WriteOutcomeUnknown(UnknownWriteCause),
    InvalidInput(&'static str),
    NotFound,
    Unauthorized,
    Conflict(&'static str),
    OwnerBusy,
    StaleOwner,
    InvalidOwner,
    RevisionOverflow,
    Serialization(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => formatter.write_str("catalog database failure"),
            Self::WriteOutcomeUnknown(cause) => write!(
                formatter,
                "catalog write outcome unknown after dispatch ({})",
                cause.as_str()
            ),
            Self::InvalidInput(message) => write!(formatter, "invalid catalog input: {message}"),
            Self::NotFound => formatter.write_str("catalog record not found"),
            Self::Unauthorized => formatter.write_str("catalog authorization denied"),
            Self::Conflict(message) => write!(formatter, "catalog conflict: {message}"),
            Self::OwnerBusy => formatter.write_str("device owner is still live"),
            Self::StaleOwner => formatter.write_str("device owner token is stale"),
            Self::InvalidOwner => formatter.write_str("device owner token is invalid"),
            Self::RevisionOverflow => formatter.write_str("catalog revision exhausted"),
            Self::Serialization(message) => {
                write!(formatter, "catalog serialization failure: {message}")
            }
        }
    }
}

impl Error for CatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<redis::RedisError> for CatalogError {
    fn from(error: redis::RedisError) -> Self {
        Self::Database(error)
    }
}

impl From<serde_json::Error> for CatalogError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{CatalogConnectionFailure as Failure, CatalogError, UnknownWriteCause};
    use redis::{ErrorKind, RedisError, ServerErrorKind};
    use std::io;

    fn classify(error: RedisError) -> Failure {
        Failure::classify(&CatalogError::Database(error))
    }

    fn io_error(kind: io::ErrorKind) -> RedisError {
        io::Error::new(kind, "peer-supplied text that is never printed").into()
    }

    fn tls_error(error: rustls::Error) -> RedisError {
        io::Error::new(io::ErrorKind::InvalidData, error).into()
    }

    fn server_reply(line: &str) -> RedisError {
        redis::parse_redis_value(format!("-{line}\r\n").as_bytes())
            .expect("server error reply")
            .extract_error()
            .expect_err("a server error reply is an error")
    }

    /// M6-C72: every class comes from a typed kind, and distinct failures
    /// get distinct classes.
    #[test]
    fn connection_failures_classify_by_typed_kind_only() {
        let cases = [
            (io_error(io::ErrorKind::TimedOut), Failure::Timeout),
            (io_error(io::ErrorKind::ConnectionRefused), Failure::Refused),
            (io_error(io::ErrorKind::ConnectionReset), Failure::Io),
            (io_error(io::ErrorKind::UnexpectedEof), Failure::Io),
            (
                tls_error(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                )),
                Failure::TlsCertificate,
            ),
            (
                tls_error(rustls::Error::AlertReceived(
                    rustls::AlertDescription::CertificateRequired,
                )),
                Failure::TlsAlert,
            ),
            (
                tls_error(rustls::Error::General("peer text".into())),
                Failure::Tls,
            ),
            (
                RedisError::from((
                    ErrorKind::AuthenticationFailed,
                    "Password authentication failed",
                )),
                Failure::Auth,
            ),
            (
                server_reply("WRONGPASS invalid username-password pair"),
                Failure::Auth,
            ),
            (
                server_reply("NOAUTH Authentication required."),
                Failure::Auth,
            ),
            (
                server_reply("NOPERM User x has no permissions to run the 'info' command"),
                Failure::NoPerm,
            ),
            (
                RedisError::from((ErrorKind::Server(ServerErrorKind::NoPerm), "denied")),
                Failure::NoPerm,
            ),
            (server_reply("ERR unknown command"), Failure::Reply),
            (server_reply("LOADING Redis is loading"), Failure::Reply),
            (
                RedisError::from((ErrorKind::InvalidClientConfig, "bad URL")),
                Failure::Config,
            ),
            (
                RedisError::from((ErrorKind::Parse, "bad reply")),
                Failure::InvalidReply,
            ),
        ];
        let dns: RedisError = io::Error::other(super::DnsLookupFailed).into();
        let mut cases = cases.to_vec();
        cases.push((dns, Failure::Dns));
        for (error, expected) in cases {
            let shown = error.to_string();
            assert_eq!(classify(error), expected, "{shown}");
        }
        assert_eq!(
            Failure::classify(&CatalogError::WriteOutcomeUnknown(
                UnknownWriteCause::ReplyTimeout
            )),
            Failure::Timeout
        );
        assert_eq!(
            Failure::classify(&CatalogError::InvalidInput("redis URL")),
            Failure::Config
        );
        assert_eq!(
            Failure::classify(&CatalogError::Conflict("active deployment incarnation")),
            Failure::Catalog
        );
    }

    /// `Debug`, `Display` and the error chain of a connection error print
    /// only the bounded stage, lane and class, whatever the wrapped error
    /// carries.
    #[test]
    fn connection_error_formatting_never_includes_the_wrapped_text() {
        use super::{CatalogConnectionError, CatalogConnectionLane, CatalogConnectionStage};
        let leaky = concat!(
            "peer text ",
            "rediss",
            "://m6c74-user:",
            "m6c74-synthetic-pass",
            "@redis.example.test/0"
        );
        for source in [
            RedisError::from(io::Error::new(io::ErrorKind::ConnectionReset, leaky)),
            server_reply(&format!("ERR {leaky}")),
        ] {
            let error = CatalogConnectionError::new(
                CatalogConnectionStage::Ping,
                CatalogError::Database(source),
            )
            .with_lane(CatalogConnectionLane { index: 2, total: 6 });
            for shown in [
                format!("{error:?}"),
                format!("{error:#?}"),
                error.to_string(),
            ] {
                assert!(!shown.contains("m6c74-synthetic-pass"), "{shown}");
                assert!(!shown.contains("rediss"), "{shown}");
                assert!(!shown.contains("peer text"), "{shown}");
            }
            assert!(std::error::Error::source(&error).is_none());
            assert_eq!(
                error.to_string(),
                format!(
                    "Redis catalog connection failed; stage=ping lane=2/6 class={}",
                    error.failure().as_str()
                )
            );
        }
    }

    /// M6-C65: the run-binding refusals carry their own classes; any other
    /// conflict stays `catalog`.
    #[test]
    fn run_binding_refusals_are_classified_by_their_label() {
        for (label, class) in [
            (crate::redis::NAMESPACE_UNBOUND, Failure::Unbound),
            (crate::redis::RUN_BINDING_CHANGED, Failure::RunChanged),
            (crate::redis::CONTINUITY_MISMATCH, Failure::Continuity),
            (crate::redis::PERSISTENCE_UNSOUND, Failure::Persistence),
            ("active deployment incarnation", Failure::Catalog),
            ("Redis server run id", Failure::Catalog),
        ] {
            assert_eq!(
                Failure::classify(&CatalogError::Conflict(label)),
                class,
                "{label}"
            );
        }
    }

    #[test]
    fn failure_class_names_are_distinct_fixed_words() {
        let all = [
            Failure::Timeout,
            Failure::Dns,
            Failure::Refused,
            Failure::Io,
            Failure::TlsCertificate,
            Failure::TlsAlert,
            Failure::Tls,
            Failure::Auth,
            Failure::NoPerm,
            Failure::Reply,
            Failure::InvalidReply,
            Failure::RunIdConflict,
            Failure::Unbound,
            Failure::RunChanged,
            Failure::Continuity,
            Failure::Persistence,
            Failure::Config,
            Failure::Catalog,
        ];
        let names: std::collections::BTreeSet<_> = all.iter().map(Failure::as_str).collect();
        assert_eq!(names.len(), all.len());
        assert!(names.iter().all(|name| {
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        }));
    }
}
