use std::{error::Error, fmt};

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
