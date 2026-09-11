use crate::{AuthenticatedConsumer, Catalog, CatalogError};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};
use uuid::Uuid;

/// A public verification key approved by operator configuration.  Keys are
/// indexed by `kid` and algorithm; a JWT cannot select an unconfigured key or
/// downgrade from RS256/EdDSA to another algorithm.
#[derive(Clone)]
pub struct ApprovedJwk {
    pub kid: String,
    pub algorithm: Algorithm,
    key: DecodingKey,
}

impl fmt::Debug for ApprovedJwk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedJwk")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl ApprovedJwk {
    pub fn from_rsa_pem(kid: impl Into<String>, pem: &[u8]) -> Result<Self, OidcError> {
        let kid = non_empty(kid.into(), "OIDC key id")?;
        let key = DecodingKey::from_rsa_pem(pem).map_err(|_| OidcError::InvalidConfiguration)?;
        Ok(Self {
            kid,
            algorithm: Algorithm::RS256,
            key,
        })
    }

    pub fn from_ed25519_der(kid: impl Into<String>, der: &[u8]) -> Result<Self, OidcError> {
        let kid = non_empty(kid.into(), "OIDC key id")?;
        let key = DecodingKey::from_ed_der(der);
        Ok(Self {
            kid,
            algorithm: Algorithm::EdDSA,
            key,
        })
    }

    /// Build a key from a caller that already parsed a trusted static key.
    /// Only RS256 and EdDSA are accepted, even if a caller passes another
    /// `jsonwebtoken` algorithm value.
    pub fn from_decoding_key(
        kid: impl Into<String>,
        algorithm: Algorithm,
        key: DecodingKey,
    ) -> Result<Self, OidcError> {
        if !matches!(algorithm, Algorithm::RS256 | Algorithm::EdDSA) {
            return Err(OidcError::DisallowedAlgorithm);
        }
        Ok(Self {
            kid: non_empty(kid.into(), "OIDC key id")?,
            algorithm,
            key,
        })
    }
}

#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub approved_keys: Vec<ApprovedJwk>,
    /// Scopes that every accepted token must carry.  A route can require an
    /// additional scope with `authenticate_for_scope`.
    pub required_scopes: BTreeSet<String>,
    pub leeway_seconds: u64,
    pub max_token_bytes: usize,
}

impl OidcConfig {
    pub fn new(
        issuer: impl Into<String>,
        audiences: impl IntoIterator<Item = String>,
        approved_keys: Vec<ApprovedJwk>,
    ) -> Result<Self, OidcError> {
        let issuer = non_empty(issuer.into(), "OIDC issuer")?;
        let audiences: Vec<String> = audiences
            .into_iter()
            .map(|value| value.trim().to_owned())
            .collect();
        if audiences.iter().any(String::is_empty) || approved_keys.is_empty() {
            return Err(OidcError::InvalidConfiguration);
        }
        let mut kids = BTreeSet::new();
        for key in &approved_keys {
            if key.kid.trim().is_empty() || !kids.insert(key.kid.clone()) {
                return Err(OidcError::InvalidConfiguration);
            }
            if !matches!(key.algorithm, Algorithm::RS256 | Algorithm::EdDSA) {
                return Err(OidcError::DisallowedAlgorithm);
            }
        }
        Ok(Self {
            issuer,
            audiences,
            approved_keys,
            required_scopes: BTreeSet::new(),
            leeway_seconds: 0,
            max_token_bytes: 32 * 1024,
        })
    }

    pub fn with_required_scopes(
        mut self,
        required_scopes: impl IntoIterator<Item = String>,
    ) -> Result<Self, OidcError> {
        let scopes: BTreeSet<_> = required_scopes
            .into_iter()
            .map(|scope| scope.trim().to_owned())
            .collect();
        if scopes.iter().any(String::is_empty) {
            return Err(OidcError::InvalidConfiguration);
        }
        self.required_scopes = scopes;
        Ok(self)
    }

    pub fn with_leeway_seconds(mut self, seconds: u64) -> Self {
        self.leeway_seconds = seconds;
        self
    }

    pub fn with_max_token_bytes(mut self, bytes: usize) -> Result<Self, OidcError> {
        if !(256..=128 * 1024).contains(&bytes) {
            return Err(OidcError::InvalidConfiguration);
        }
        self.max_token_bytes = bytes;
        Ok(self)
    }
}

#[derive(Clone)]
pub struct OidcVerifier {
    config: Arc<OidcConfig>,
}

impl fmt::Debug for OidcVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcVerifier")
            .field("issuer", &self.config.issuer)
            .field("audiences", &self.config.audiences)
            .field("approved_key_count", &self.config.approved_keys.len())
            .field("required_scopes", &self.config.required_scopes)
            .finish()
    }
}

impl OidcVerifier {
    pub fn new(config: OidcConfig) -> Result<Self, OidcError> {
        if config.issuer.trim().is_empty()
            || config.audiences.is_empty()
            || config
                .audiences
                .iter()
                .any(|audience| audience.trim().is_empty())
            || config.approved_keys.is_empty()
            || config.approved_keys.len() > 32
            || config.leeway_seconds > 30
            || !(256..=128 * 1024).contains(&config.max_token_bytes)
        {
            return Err(OidcError::InvalidConfiguration);
        }
        let mut keys = BTreeSet::new();
        for key in &config.approved_keys {
            if key.kid.trim().is_empty()
                || !matches!(key.algorithm, Algorithm::RS256 | Algorithm::EdDSA)
                || !keys.insert(key.kid.clone())
            {
                return Err(OidcError::InvalidConfiguration);
            }
        }
        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// Validate the `Authorization: Bearer` value and return its durable
    /// claims.  This method never logs or includes the bearer in an error.
    pub fn validate_bearer(&self, authorization: &str) -> Result<ValidatedClaims, OidcError> {
        let token = authorization
            .strip_prefix("Bearer ")
            .or_else(|| authorization.strip_prefix("bearer "))
            .ok_or(OidcError::InvalidToken)?;
        if token.is_empty() || token.len() > self.config.max_token_bytes {
            return Err(OidcError::InvalidToken);
        }
        self.validate_token(token)
    }

    /// Validate a raw token.  Callers should normally use
    /// `validate_bearer` so the route cannot accidentally accept another
    /// credential scheme.
    pub fn validate_token(&self, token: &str) -> Result<ValidatedClaims, OidcError> {
        if token.is_empty() || token.len() > self.config.max_token_bytes {
            return Err(OidcError::InvalidToken);
        }
        let header = decode_header(token).map_err(|_| OidcError::InvalidToken)?;
        if !matches!(header.alg, Algorithm::RS256 | Algorithm::EdDSA) {
            return Err(OidcError::DisallowedAlgorithm);
        }
        let kid = header.kid.ok_or(OidcError::MissingKeyId)?;
        let approved = self
            .config
            .approved_keys
            .iter()
            .find(|key| key.kid == kid && key.algorithm == header.alg)
            .ok_or(OidcError::UnknownKey)?;

        let mut validation = Validation::new(approved.algorithm);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        let audiences = self
            .config
            .audiences
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        validation.set_audience(&audiences);
        validation.leeway = self.config.leeway_seconds;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.required_spec_claims.clear();
        validation.required_spec_claims.insert("exp".to_owned());
        validation.required_spec_claims.insert("iss".to_owned());
        validation.required_spec_claims.insert("sub".to_owned());
        validation.required_spec_claims.insert("aud".to_owned());

        let decoded = decode::<Claims>(token, &approved.key, &validation)
            .map_err(|_| OidcError::InvalidToken)?;
        if decoded.claims.sub.trim().is_empty() || decoded.claims.iss != self.config.issuer {
            return Err(OidcError::InvalidToken);
        }
        let exp = i64::try_from(decoded.claims.exp).map_err(|_| OidcError::InvalidToken)?;
        let expires_at = DateTime::<Utc>::from_timestamp(exp, 0).ok_or(OidcError::InvalidToken)?;
        let scopes = decoded
            .claims
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if !self
            .config
            .required_scopes
            .iter()
            .all(|scope| scopes.contains(scope))
        {
            return Err(OidcError::InsufficientScope);
        }
        Ok(ValidatedClaims {
            issuer: decoded.claims.iss,
            subject: decoded.claims.sub,
            scopes,
            expires_at,
        })
    }

    /// Validate and resolve a consumer identity for a tenant.  The tenant
    /// hint is checked against the catalog; no JWT tenant claim is trusted.
    pub async fn authenticate(
        &self,
        catalog: &dyn Catalog,
        authorization: &str,
        tenant_id: Option<Uuid>,
    ) -> Result<AuthenticatedConsumer, OidcError> {
        Ok(self
            .authenticate_access(catalog, authorization, tenant_id, None)
            .await?
            .consumer)
    }

    /// Route helper for explicit capability scopes, such as `echo:invoke`.
    /// The catalog grant remains a separate required check.
    pub async fn authenticate_for_scope(
        &self,
        catalog: &dyn Catalog,
        authorization: &str,
        tenant_id: Option<Uuid>,
        required_scope: &str,
    ) -> Result<ValidatedAccessToken, OidcError> {
        let required_scope = non_empty(required_scope.to_owned(), "OIDC scope")?;
        self.authenticate_access(catalog, authorization, tenant_id, Some(&required_scope))
            .await
    }

    async fn authenticate_access(
        &self,
        catalog: &dyn Catalog,
        authorization: &str,
        tenant_id: Option<Uuid>,
        required_scope: Option<&str>,
    ) -> Result<ValidatedAccessToken, OidcError> {
        let claims = self.validate_bearer(authorization)?;
        if let Some(scope) = required_scope
            && !claims.scopes.contains(scope)
        {
            return Err(OidcError::InsufficientScope);
        }
        let consumer = catalog
            .resolve_consumer(&claims.issuer, &claims.subject, tenant_id)
            .await
            .map_err(OidcError::Catalog)?
            .ok_or(OidcError::UnknownConsumer)?;
        // The catalog lookup is an await boundary.  Do not let a token that
        // expired while it was in flight create a usable relay identity.
        if Utc::now() >= claims.expires_at {
            return Err(OidcError::InvalidToken);
        }
        Ok(ValidatedAccessToken {
            consumer,
            issuer: claims.issuer,
            subject: claims.subject,
            scopes: claims.scopes,
            expires_at: claims.expires_at,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedClaims {
    pub issuer: String,
    pub subject: String,
    pub scopes: BTreeSet<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedAccessToken {
    pub consumer: AuthenticatedConsumer,
    pub issuer: String,
    pub subject: String,
    pub scopes: BTreeSet<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub enum OidcError {
    InvalidConfiguration,
    InvalidToken,
    DisallowedAlgorithm,
    MissingKeyId,
    UnknownKey,
    InsufficientScope,
    UnknownConsumer,
    Catalog(CatalogError),
}

impl fmt::Display for OidcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("invalid OIDC verifier configuration")
            }
            Self::InvalidToken => formatter.write_str("invalid consumer credential"),
            Self::DisallowedAlgorithm => {
                formatter.write_str("consumer credential algorithm is not allowed")
            }
            Self::MissingKeyId => formatter.write_str("consumer credential has no key id"),
            Self::UnknownKey => formatter.write_str("consumer credential key is not approved"),
            Self::InsufficientScope => {
                formatter.write_str("consumer credential lacks required scope")
            }
            Self::UnknownConsumer => {
                formatter.write_str("consumer identity is not an active tenant member")
            }
            Self::Catalog(_) => formatter.write_str("consumer identity lookup failed"),
        }
    }
}

impl Error for OidcError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Catalog(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    #[allow(dead_code)]
    aud: serde_json::Value,
    exp: usize,
    #[allow(dead_code)]
    #[serde(default)]
    nbf: Option<usize>,
    #[serde(default)]
    scope: Option<String>,
}

fn non_empty(value: String, _field: &'static str) -> Result<String, OidcError> {
    if value.trim().is_empty() {
        Err(OidcError::InvalidConfiguration)
    } else {
        Ok(value)
    }
}
