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
#[derive(Debug)]
pub struct CatalogConnectionError {
    stage: CatalogConnectionStage,
    source: CatalogError,
}

impl CatalogConnectionError {
    pub(crate) fn new(stage: CatalogConnectionStage, source: CatalogError) -> Self {
        Self { stage, source }
    }

    pub const fn stage(&self) -> CatalogConnectionStage {
        self.stage
    }

    pub fn into_catalog_error(self) -> CatalogError {
        self.source
    }
}

impl fmt::Display for CatalogConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl Error for CatalogConnectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl From<CatalogConnectionError> for CatalogError {
    fn from(error: CatalogConnectionError) -> Self {
        error.into_catalog_error()
    }
}

/// Errors returned by the durable catalog. User-facing handlers should map
/// these to bounded public codes; backend details are never included in a
/// response containing a bearer credential.
#[derive(Debug)]
pub enum CatalogError {
    Database(redis::RedisError),
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
