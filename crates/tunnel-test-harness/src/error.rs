use std::fmt;

/// Result type shared by all harness resources.
pub type Result<T> = std::result::Result<T, HarnessError>;

/// Errors are intentionally actionable: a missing external dependency is a
/// failed acceptance precondition, never a skipped test.
#[derive(Debug)]
pub enum HarnessError {
    MissingRedisUrl {
        env_var: &'static str,
        guidance: String,
    },
    InvalidRedisUrl {
        message: String,
    },
    Redis(String),
    Io(std::io::Error),
    Json(serde_json::Error),
    Jwt(jsonwebtoken::errors::Error),
    Pki(String),
    Proxy(String),
    Http(String),
    Process(String),
    InvalidInput(String),
    Timeout(String),
    Unsupported(String),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRedisUrl { env_var, guidance } => write!(
                f,
                "missing {env_var}; the M1 acceptance suite requires a real Redis service. {guidance}"
            ),
            Self::InvalidRedisUrl { message } => {
                write!(f, "invalid Redis connection URL: {message}")
            }
            Self::Redis(message) => write!(f, "Redis harness error: {message}"),
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Json(error) => write!(f, "JSON error: {error}"),
            Self::Jwt(error) => write!(f, "OIDC/JWT error: {error}"),
            Self::Pki(message) => write!(f, "fixture PKI error: {message}"),
            Self::Proxy(message) => write!(f, "TCP proxy error: {message}"),
            Self::Http(message) => write!(f, "HTTP/TLS probe error: {message}"),
            Self::Process(message) => write!(f, "managed process error: {message}"),
            Self::InvalidInput(message) => write!(f, "invalid harness input: {message}"),
            Self::Timeout(message) => write!(f, "harness timeout: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported harness operation: {message}"),
        }
    }
}

impl std::error::Error for HarnessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Jwt(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for HarnessError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for HarnessError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<jsonwebtoken::errors::Error> for HarnessError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        Self::Jwt(error)
    }
}

impl From<redis::RedisError> for HarnessError {
    fn from(error: redis::RedisError) -> Self {
        Self::Redis(error.to_string())
    }
}
