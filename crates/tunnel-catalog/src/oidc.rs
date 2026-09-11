use crate::{AuthenticatedConsumer, Catalog, CatalogError};
use chrono::{DateTime, Utc};
use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, Validation, decode, decode_header,
};
use serde::Deserialize;
use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};
use uuid::Uuid;

/// Smallest RSA modulus accepted for RS256, in bits.  This is the floor that
/// `ring` enforced for jsonwebtoken 9 (`RSA_PKCS1_2048_8192_SHA256`); the
/// RustCrypto backend used by jsonwebtoken 10 has no minimum, so the verifier
/// keeps the bound itself.
const RSA_MIN_MODULUS_BITS: usize = 2048;
/// Largest RSA modulus accepted for RS256, in bits.  This is
/// `RsaPublicKey::MAX_SIZE` in the RustCrypto backend, which would otherwise
/// reject a larger key on every token instead of once at configuration time.
const RSA_MAX_MODULUS_BITS: usize = 4096;
/// The RustCrypto verifier accepts public exponents up to 2^33 - 1.
const RSA_MAX_PUBLIC_EXPONENT_BITS: usize = 33;
/// A raw Ed25519 public key is exactly 32 bytes (RFC 8032, section 5.1.5).
const ED25519_PUBLIC_KEY_LEN: usize = 32;

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
    /// Approve an RSA public key for RS256 from PEM (`PUBLIC KEY` or
    /// `RSA PUBLIC KEY`).  The modulus must be 2048..=4096 bits with an odd
    /// public exponent of at least 3; private keys and other key types are
    /// rejected.
    pub fn from_rsa_pem(kid: impl Into<String>, pem: &[u8]) -> Result<Self, OidcError> {
        let kid = non_empty(kid.into(), "OIDC key id")?;
        let key = DecodingKey::from_rsa_pem(pem).map_err(|_| OidcError::InvalidConfiguration)?;
        check_key_for_algorithm(&key, Algorithm::RS256)?;
        Ok(Self {
            kid,
            algorithm: Algorithm::RS256,
            key,
        })
    }

    /// Approve a raw 32-byte Ed25519 public key (RFC 8032), such as
    /// `rcgen::KeyPair::public_key_raw`, for EdDSA.  Any other length is
    /// rejected here because the verifier would otherwise truncate a longer
    /// encoding or panic on a shorter one at request time.
    pub fn from_ed25519_der(kid: impl Into<String>, der: &[u8]) -> Result<Self, OidcError> {
        let kid = non_empty(kid.into(), "OIDC key id")?;
        let key = DecodingKey::from_ed_der(der);
        check_key_for_algorithm(&key, Algorithm::EdDSA)?;
        Ok(Self {
            kid,
            algorithm: Algorithm::EdDSA,
            key,
        })
    }

    /// Build a key from a caller that already parsed a trusted static key.
    /// Only RS256 and EdDSA are accepted, even if a caller passes another
    /// `jsonwebtoken` algorithm value, and the key material must belong to
    /// that algorithm's family: an HMAC secret or Ed25519 key can never be
    /// approved as an RS256 key, nor an RSA key as an EdDSA key.
    pub fn from_decoding_key(
        kid: impl Into<String>,
        algorithm: Algorithm,
        key: DecodingKey,
    ) -> Result<Self, OidcError> {
        if !matches!(algorithm, Algorithm::RS256 | Algorithm::EdDSA) {
            return Err(OidcError::DisallowedAlgorithm);
        }
        let kid = non_empty(kid.into(), "OIDC key id")?;
        check_key_for_algorithm(&key, algorithm)?;
        Ok(Self {
            kid,
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

/// Reject key material that does not belong to `algorithm`, so an approved
/// key can never be exercised by another algorithm family, and reject RSA
/// keys the verifier could not use.  jsonwebtoken checks the family again
/// when decoding; failing here turns a misconfigured key into a
/// configuration error instead of a silent per-request signature failure.
fn check_key_for_algorithm(key: &DecodingKey, algorithm: Algorithm) -> Result<(), OidcError> {
    match (algorithm, key.family(), key.kind()) {
        (Algorithm::RS256, AlgorithmFamily::Rsa, DecodingKeyKind::RsaModulusExponent { n, e }) => {
            check_rsa_public_key(n, e)
        }
        (Algorithm::RS256, AlgorithmFamily::Rsa, DecodingKeyKind::SecretOrDer(der)) => {
            let (modulus, exponent) = parse_pkcs1_rsa_public_key(der)?;
            check_rsa_public_key(modulus, exponent)
        }
        (Algorithm::EdDSA, AlgorithmFamily::Ed, DecodingKeyKind::SecretOrDer(raw))
            if raw.len() == ED25519_PUBLIC_KEY_LEN =>
        {
            Ok(())
        }
        _ => Err(OidcError::InvalidConfiguration),
    }
}

/// Accept only RSA public keys in the verifiable size range with an odd
/// public exponent of at least 3 (RFC 8017, section 3.1).
fn check_rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Result<(), OidcError> {
    let is_odd = |value: &[u8]| value.last().is_some_and(|byte| byte & 1 == 1);
    let modulus_bits = unsigned_bit_length(modulus);
    let exponent_bits = unsigned_bit_length(exponent);
    if !(RSA_MIN_MODULUS_BITS..=RSA_MAX_MODULUS_BITS).contains(&modulus_bits)
        || !is_odd(modulus)
        || !(2..=RSA_MAX_PUBLIC_EXPONENT_BITS).contains(&exponent_bits)
        || !is_odd(exponent)
    {
        return Err(OidcError::InvalidConfiguration);
    }
    Ok(())
}

/// Bit length of a big-endian unsigned integer, ignoring leading zero bytes.
fn unsigned_bit_length(value: &[u8]) -> usize {
    let mut bytes = value;
    while let [0, rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
        .first()
        .map_or(0, |first| bytes.len() * 8 - first.leading_zeros() as usize)
}

/// Extract `(modulus, exponent)` from a PKCS#1 `RSAPublicKey`
/// (`SEQUENCE { INTEGER n, INTEGER e }`), which is what jsonwebtoken yields
/// for both `RSA PUBLIC KEY` and SubjectPublicKeyInfo PEM inputs.  Anything
/// else, including an RSA private key, is rejected.
fn parse_pkcs1_rsa_public_key(der: &[u8]) -> Result<(&[u8], &[u8]), OidcError> {
    let (body, trailing) = read_der_element(der, 0x30)?;
    let (modulus, rest) = read_der_element(body, 0x02)?;
    let (exponent, rest) = read_der_element(rest, 0x02)?;
    if !trailing.is_empty() || !rest.is_empty() {
        return Err(OidcError::InvalidConfiguration);
    }
    Ok((
        der_positive_integer(modulus)?,
        der_positive_integer(exponent)?,
    ))
}

/// Split one DER element with the expected tag into `(contents, remainder)`,
/// accepting only minimal definite-length encodings.
fn read_der_element(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), OidcError> {
    let [actual, first, rest @ ..] = input else {
        return Err(OidcError::InvalidConfiguration);
    };
    if *actual != tag {
        return Err(OidcError::InvalidConfiguration);
    }
    let (length, rest) = if *first < 0x80 {
        (usize::from(*first), rest)
    } else {
        let count = usize::from(*first & 0x7f);
        if !(1..=4).contains(&count) || rest.len() < count {
            return Err(OidcError::InvalidConfiguration);
        }
        let (length_bytes, rest) = rest.split_at(count);
        let length = length_bytes
            .iter()
            .fold(0_usize, |acc, byte| (acc << 8) | usize::from(*byte));
        if length_bytes[0] == 0 || length < 0x80 {
            return Err(OidcError::InvalidConfiguration);
        }
        (length, rest)
    };
    if rest.len() < length {
        return Err(OidcError::InvalidConfiguration);
    }
    Ok(rest.split_at(length))
}

/// Contents of a DER INTEGER as an unsigned big-endian value.  Negative,
/// zero and non-minimal encodings are rejected.
fn der_positive_integer(contents: &[u8]) -> Result<&[u8], OidcError> {
    match contents {
        [first, ..] if *first & 0x80 != 0 => Err(OidcError::InvalidConfiguration),
        [0, rest @ ..] if rest.first().is_some_and(|byte| byte & 0x80 != 0) => Ok(rest),
        [] | [0, ..] => Err(OidcError::InvalidConfiguration),
        _ => Ok(contents),
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovedJwk, OidcConfig, OidcError, OidcVerifier};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use serde_json::{Value, json};
    use std::time::{SystemTime, UNIX_EPOCH};

    const ISSUER: &str = "https://issuer.test";
    const AUDIENCE: &str = "agent-tunnel";
    const ED_KID: &str = "fixture-ed25519";
    const RSA_KID: &str = "fixture-rsa-2048";
    const RSA_EXPONENT: &str = "AQAB";

    /// Public half of a throwaway 2048-bit RSA key generated with OpenSSL for
    /// these tests.  The private half was discarded, so no token can be
    /// minted for it; it exercises RSA import rules and kid/algorithm binding.
    const RSA_2048_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwpzxK4YhVbeIGQkBFuC8
Lwc5iX4NpKHeWN6c1zg6xBCJ2oDK+KD/Q19VR+/OeOcQvzeWHPnHM1c6Mg2vrBm+
6obc5R4gNQd+CZz9H4QS6SUQ+S2rjWVzCWpx0SWIzS4Uw7/yu/qHsoUWQVBVZIBQ
49AUBNLg6pCr+r6dwkxcr67+m5Jjw1+E9+Vq54tgGMzRocZWU79N75jXzLRzDOLb
OJex+CrCcek2owQ+Cv5f61+5gacszQjnu8kjt2Zsmnr0PVzNcaBwvbt66qJLAnXL
Zghu6JmWEGoeGYpG7XjX9S/A8n/9pA58xDnrsxSNnlRTy3LQMUtlDcDCd0jLvBLw
3wIDAQAB
-----END PUBLIC KEY-----
";
    /// JWK `n` of `RSA_2048_PUBLIC_PEM`.
    const RSA_2048_MODULUS: &str = "wpzxK4YhVbeIGQkBFuC8Lwc5iX4NpKHeWN6c1zg6xBCJ2oDK-KD_Q19VR-_OeOcQvzeWHPnHM1c6Mg2vrBm-6obc5R4gNQd-CZz9H4QS6SUQ-S2rjWVzCWpx0SWIzS4Uw7_yu_qHsoUWQVBVZIBQ49AUBNLg6pCr-r6dwkxcr67-m5Jjw1-E9-Vq54tgGMzRocZWU79N75jXzLRzDOLbOJex-CrCcek2owQ-Cv5f61-5gacszQjnu8kjt2Zsmnr0PVzNcaBwvbt66qJLAnXLZghu6JmWEGoeGYpG7XjX9S_A8n_9pA58xDnrsxSNnlRTy3LQMUtlDcDCd0jLvBLw3w";
    /// Public half of a throwaway 1024-bit RSA key: too small to approve.
    const RSA_1024_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu53cgtApldqwowkHXRD5AlnU
71G7rc0hODdm3aimn3Arkj3zmhzrktgpMKYgo+QUY1JrsJnJNtRurIqhrPwTScZj
RmhmPwbfTUulxJsJXfAT1sT91WOq91SpqlIMjHOyIIUqiOwOcNqLVhCfEacwZ5Dz
JomFp0oAL1CkwVFrEQIDAQAB
-----END PUBLIC KEY-----
";
    /// JWK `n` of `RSA_1024_PUBLIC_PEM`.
    const RSA_1024_MODULUS: &str = "0bud3ILQKZXasKMJB10Q-QJZ1O9Ru63NITg3Zt2opp9wK5I985oc65LYKTCmIKPkFGNSa7CZyTbUbqyKoaz8E0nGY0ZoZj8G301LpcSbCV3wE9bE_dVjqvdUqapSDIxzsiCFKojsDnDai1YQnxGnMGeQ8yaJhadKAC9QpMFRaxE";
    /// An Ed25519 SubjectPublicKeyInfo PEM, which is not an RSA key.
    const ED25519_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+0dizco+FMBvifqw1ZUJzKYN5gspRlxsvm+MudOfijQ=
-----END PUBLIC KEY-----
";
    /// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410).
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    /// A fresh Ed25519 signing key; nothing is persisted.
    struct EdKey {
        pkcs8: Vec<u8>,
        public: Vec<u8>,
    }

    impl EdKey {
        fn generate() -> Self {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519 key");
            let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse Ed25519 key");
            Self {
                pkcs8: pkcs8.as_ref().to_vec(),
                public: pair.public_key().as_ref().to_vec(),
            }
        }

        fn approved(&self, kid: &str) -> ApprovedJwk {
            ApprovedJwk::from_ed25519_der(kid, &self.public).expect("approved Ed25519 key")
        }

        fn sign(&self, header: &Header, claims: &Value) -> String {
            encode(header, claims, &EncodingKey::from_ed_der(&self.pkcs8)).expect("sign token")
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs()
    }

    fn claims() -> Value {
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "consumer-a",
            "exp": now() + 300,
            "iat": now(),
            "scope": "echo:invoke devices:read",
        })
    }

    fn header(algorithm: Algorithm, kid: &str) -> Header {
        let mut header = Header::new(algorithm);
        header.kid = Some(kid.to_owned());
        header
    }

    fn config(keys: Vec<ApprovedJwk>) -> OidcConfig {
        OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], keys).expect("OIDC config")
    }

    fn verifier(keys: Vec<ApprovedJwk>) -> OidcVerifier {
        OidcVerifier::new(config(keys)).expect("OIDC verifier")
    }

    fn rsa_key() -> ApprovedJwk {
        ApprovedJwk::from_rsa_pem(RSA_KID, RSA_2048_PUBLIC_PEM.as_bytes())
            .expect("approved RSA key")
    }

    fn encode_part(value: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("JSON part"))
    }

    /// Replace a signed token's header, keeping its payload and signature.
    fn relabel(token: &str, header: &Value) -> String {
        let mut parts = token.split('.');
        let _ = parts.next();
        let payload = parts.next().expect("payload");
        let signature = parts.next().expect("signature");
        format!("{}.{payload}.{signature}", encode_part(header))
    }

    /// Replace a signed token's payload, keeping its header and signature.
    fn replace_payload(token: &str, claims: &Value) -> String {
        let mut parts = token.split('.');
        let header = parts.next().expect("header");
        let _ = parts.next();
        let signature = parts.next().expect("signature");
        format!("{header}.{}.{signature}", encode_part(claims))
    }

    fn rejects(result: Result<impl std::fmt::Debug, OidcError>, check: fn(&OidcError) -> bool) {
        match result {
            Err(error) if check(&error) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    fn invalid_token(error: &OidcError) -> bool {
        matches!(error, OidcError::InvalidToken)
    }

    fn invalid_configuration(error: &OidcError) -> bool {
        matches!(error, OidcError::InvalidConfiguration)
    }

    fn disallowed_algorithm(error: &OidcError) -> bool {
        matches!(error, OidcError::DisallowedAlgorithm)
    }

    fn unknown_key(error: &OidcError) -> bool {
        matches!(error, OidcError::UnknownKey)
    }

    #[test]
    fn accepts_eddsa_token_with_approved_kid_and_required_claims() {
        let key = EdKey::generate();
        let verifier = verifier(vec![key.approved(ED_KID)]);
        let token = key.sign(&header(Algorithm::EdDSA, ED_KID), &claims());
        let validated = verifier
            .validate_bearer(&format!("Bearer {token}"))
            .expect("approved token validates");
        assert_eq!(validated.issuer, ISSUER);
        assert_eq!(validated.subject, "consumer-a");
        assert!(validated.scopes.contains("echo:invoke"));
        assert!(validated.scopes.contains("devices:read"));
        assert!(validated.expires_at > Utc::now());
        let lower_case_scheme = verifier
            .validate_bearer(&format!("bearer {token}"))
            .expect("lower-case scheme validates");
        assert_eq!(lower_case_scheme, validated);
    }

    #[test]
    fn rejects_header_algorithms_outside_rs256_and_eddsa() {
        let key = EdKey::generate();
        let verifier = verifier(vec![key.approved(ED_KID), rsa_key()]);
        let signed = key.sign(&header(Algorithm::EdDSA, ED_KID), &claims());
        for algorithm in [
            "HS256", "HS384", "HS512", "RS384", "RS512", "PS256", "ES256",
        ] {
            for kid in [ED_KID, RSA_KID] {
                let token = relabel(&signed, &json!({ "alg": algorithm, "kid": kid }));
                rejects(verifier.validate_token(&token), disallowed_algorithm);
            }
        }
        // `none` and a missing `alg` are not even parseable headers.
        let token = relabel(&signed, &json!({ "alg": "none", "kid": ED_KID }));
        rejects(verifier.validate_token(&token), invalid_token);
        let token = relabel(&signed, &json!({ "kid": ED_KID }));
        rejects(verifier.validate_token(&token), invalid_token);
        // jsonwebtoken 10 parses unknown header members as strings, so a
        // non-string member fails closed as well.
        let token = relabel(
            &signed,
            &json!({ "alg": "EdDSA", "kid": ED_KID, "b64": false }),
        );
        rejects(verifier.validate_token(&token), invalid_token);
    }

    #[test]
    fn rejects_missing_and_unknown_key_ids() {
        let key = EdKey::generate();
        let verifier = verifier(vec![key.approved(ED_KID)]);
        let no_kid = key.sign(&Header::new(Algorithm::EdDSA), &claims());
        rejects(verifier.validate_token(&no_kid), |error| {
            matches!(error, OidcError::MissingKeyId)
        });
        let unknown = key.sign(&header(Algorithm::EdDSA, "rotated-away"), &claims());
        rejects(verifier.validate_token(&unknown), unknown_key);
    }

    #[test]
    fn binds_each_kid_to_its_key_type_and_algorithm() {
        let key = EdKey::generate();
        let verifier = verifier(vec![key.approved(ED_KID), rsa_key()]);
        let signed = key.sign(&header(Algorithm::EdDSA, ED_KID), &claims());
        // An EdDSA signature cannot be presented under the RSA key's kid ...
        let cross_kid = relabel(&signed, &json!({ "alg": "EdDSA", "kid": RSA_KID }));
        rejects(verifier.validate_token(&cross_kid), unknown_key);
        // ... nor re-labelled as RS256 to reach the Ed25519 key ...
        let cross_alg = relabel(&signed, &json!({ "alg": "RS256", "kid": ED_KID }));
        rejects(verifier.validate_token(&cross_alg), unknown_key);
        // ... and re-labelled as RS256 for the RSA kid it fails signature
        // verification against the RSA key without panicking.
        let confused = relabel(&signed, &json!({ "alg": "RS256", "kid": RSA_KID }));
        rejects(verifier.validate_token(&confused), invalid_token);
    }

    #[test]
    fn rejects_unapproved_signers_and_tampered_payloads() {
        let approved = EdKey::generate();
        let rogue = EdKey::generate();
        let verifier = verifier(vec![approved.approved(ED_KID)]);
        let rogue_token = rogue.sign(&header(Algorithm::EdDSA, ED_KID), &claims());
        rejects(verifier.validate_token(&rogue_token), invalid_token);
        let genuine = approved.sign(&header(Algorithm::EdDSA, ED_KID), &claims());
        let mut tampered = claims();
        tampered["sub"] = json!("consumer-b");
        rejects(
            verifier.validate_token(&replace_payload(&genuine, &tampered)),
            invalid_token,
        );
        let unsigned = format!(
            "{}.{}.",
            encode_part(&json!({ "alg": "EdDSA", "kid": ED_KID })),
            encode_part(&claims())
        );
        rejects(verifier.validate_token(&unsigned), invalid_token);
        rejects(verifier.validate_token("not.a-jwt"), invalid_token);
        rejects(verifier.validate_token(""), invalid_token);
    }

    #[test]
    fn requires_exp_iss_sub_and_aud_claims() {
        let key = EdKey::generate();
        let verifier = verifier(vec![key.approved(ED_KID)]);
        for claim in ["exp", "iss", "sub", "aud"] {
            let mut claims = claims();
            claims.as_object_mut().expect("claims object").remove(claim);
            let token = key.sign(&header(Algorithm::EdDSA, ED_KID), &claims);
            rejects(verifier.validate_token(&token), invalid_token);
        }
    }

    #[test]
    fn rejects_wrong_issuer_wrong_audience_and_blank_subject() {
        let key = EdKey::generate();
        let verifier = verifier(vec![key.approved(ED_KID)]);
        let sign = |claims: &Value| key.sign(&header(Algorithm::EdDSA, ED_KID), claims);
        let mut wrong_issuer = claims();
        wrong_issuer["iss"] = json!("https://other-issuer.test");
        rejects(verifier.validate_token(&sign(&wrong_issuer)), invalid_token);
        let mut wrong_audience = claims();
        wrong_audience["aud"] = json!("agent-tunnel-staging");
        rejects(
            verifier.validate_token(&sign(&wrong_audience)),
            invalid_token,
        );
        let mut foreign_audiences = claims();
        foreign_audiences["aud"] = json!(["someone-else", "another-service"]);
        rejects(
            verifier.validate_token(&sign(&foreign_audiences)),
            invalid_token,
        );
        let mut empty_audiences = claims();
        empty_audiences["aud"] = json!([]);
        rejects(
            verifier.validate_token(&sign(&empty_audiences)),
            invalid_token,
        );
        // RFC 7519 allows several audiences as long as this relay is one.
        let mut shared_audience = claims();
        shared_audience["aud"] = json!(["someone-else", AUDIENCE]);
        verifier
            .validate_token(&sign(&shared_audience))
            .expect("audience list containing this relay validates");
        let mut blank_subject = claims();
        blank_subject["sub"] = json!("   ");
        rejects(
            verifier.validate_token(&sign(&blank_subject)),
            invalid_token,
        );
        let mut numeric_subject = claims();
        numeric_subject["sub"] = json!(42);
        rejects(
            verifier.validate_token(&sign(&numeric_subject)),
            invalid_token,
        );
    }

    #[test]
    fn enforces_exp_and_nbf_with_only_the_configured_leeway() {
        let key = EdKey::generate();
        let strict = verifier(vec![key.approved(ED_KID)]);
        let sign = |claims: &Value| key.sign(&header(Algorithm::EdDSA, ED_KID), claims);
        // jsonwebtoken's own default leeway of 60 seconds would accept this;
        // the verifier's default of zero must not.
        let mut expired = claims();
        expired["exp"] = json!(now() - 30);
        rejects(strict.validate_token(&sign(&expired)), invalid_token);
        let mut not_yet_valid = claims();
        not_yet_valid["nbf"] = json!(now() + 120);
        rejects(strict.validate_token(&sign(&not_yet_valid)), invalid_token);
        let mut already_valid = claims();
        already_valid["nbf"] = json!(now() - 5);
        strict
            .validate_token(&sign(&already_valid))
            .expect("past nbf validates");
        // Configured leeway is honoured and capped at 30 seconds.
        let lenient = OidcVerifier::new(config(vec![key.approved(ED_KID)]).with_leeway_seconds(30))
            .expect("30 second leeway is allowed");
        let mut slightly_expired = claims();
        slightly_expired["exp"] = json!(now() - 10);
        lenient
            .validate_token(&sign(&slightly_expired))
            .expect("within configured leeway");
        rejects(
            strict.validate_token(&sign(&slightly_expired)),
            invalid_token,
        );
        rejects(
            OidcVerifier::new(config(vec![key.approved(ED_KID)]).with_leeway_seconds(31)),
            invalid_configuration,
        );
    }

    #[test]
    fn rejects_malformed_exp_and_nbf_types() {
        // CVE-2026-25537 / GHSA-h395-gr6q-cpjc: jsonwebtoken < 10.3.0 treated
        // a claim that failed to parse like an absent one when it was
        // validated but not required.  `nbf` is validated-but-optional here,
        // which is the exact shape of the advisory; every malformed value
        // must still fail closed.
        let key = EdKey::generate();
        let verifier = verifier(vec![key.approved(ED_KID)]);
        // An explicit JSON null is malformed too: jsonwebtoken 10.3.0 reports
        // it as an invalid claim format rather than skipping the check.
        let cases = [
            ("nbf", json!("99999999999")),
            ("nbf", json!(-1)),
            ("nbf", json!(1.5)),
            ("nbf", json!([1])),
            ("nbf", json!({ "at": 1 })),
            ("nbf", json!(null)),
            ("exp", json!("never")),
            ("exp", json!(-1)),
            ("exp", json!(1e30)),
            ("exp", json!(null)),
        ];
        for (claim, value) in cases {
            let mut claims = claims();
            claims[claim] = value.clone();
            let token = key.sign(&header(Algorithm::EdDSA, ED_KID), &claims);
            match verifier.validate_token(&token) {
                Err(OidcError::InvalidToken) => {}
                other => panic!("{claim}={value} was not rejected: {other:?}"),
            }
        }
        // An absent `nbf` remains optional.
        let claims = claims();
        assert!(claims.get("nbf").is_none());
        verifier
            .validate_token(&key.sign(&header(Algorithm::EdDSA, ED_KID), &claims))
            .expect("token without nbf validates");
    }

    #[test]
    fn enforces_required_scopes_and_bearer_framing() {
        let key = EdKey::generate();
        let config = config(vec![key.approved(ED_KID)])
            .with_required_scopes(["echo:invoke".to_owned()])
            .expect("required scope");
        let verifier = OidcVerifier::new(config).expect("OIDC verifier");
        let token = key.sign(&header(Algorithm::EdDSA, ED_KID), &claims());
        verifier
            .validate_bearer(&format!("Bearer {token}"))
            .expect("scoped token validates");
        rejects(verifier.validate_bearer(&token), invalid_token);
        rejects(
            verifier.validate_bearer(&format!("Basic {token}")),
            invalid_token,
        );
        rejects(verifier.validate_bearer("Bearer "), invalid_token);
        let oversized = format!("Bearer {token}{}", "A".repeat(32 * 1024));
        rejects(verifier.validate_bearer(&oversized), invalid_token);
        let mut other_scope = claims();
        other_scope["scope"] = json!("devices:read");
        rejects(
            verifier.validate_token(&key.sign(&header(Algorithm::EdDSA, ED_KID), &other_scope)),
            |error| matches!(error, OidcError::InsufficientScope),
        );
        let mut no_scope = claims();
        no_scope
            .as_object_mut()
            .expect("claims object")
            .remove("scope");
        rejects(
            verifier.validate_token(&key.sign(&header(Algorithm::EdDSA, ED_KID), &no_scope)),
            |error| matches!(error, OidcError::InsufficientScope),
        );
    }

    #[test]
    fn ed25519_keys_must_be_exactly_32_raw_bytes() {
        let key = EdKey::generate();
        assert!(ApprovedJwk::from_ed25519_der(ED_KID, &key.public).is_ok());
        // Relay tests use an all-zero placeholder when no token is validated.
        assert!(ApprovedJwk::from_ed25519_der(ED_KID, &[0_u8; 32]).is_ok());
        rejects(
            ApprovedJwk::from_ed25519_der(ED_KID, &[]),
            invalid_configuration,
        );
        rejects(
            ApprovedJwk::from_ed25519_der(ED_KID, &key.public[..31]),
            invalid_configuration,
        );
        let mut too_long = key.public.clone();
        too_long.push(0);
        rejects(
            ApprovedJwk::from_ed25519_der(ED_KID, &too_long),
            invalid_configuration,
        );
        // A SubjectPublicKeyInfo encoding is refused rather than truncated.
        let spki: Vec<u8> = ED25519_SPKI_PREFIX
            .iter()
            .chain(key.public.iter())
            .copied()
            .collect();
        rejects(
            ApprovedJwk::from_ed25519_der(ED_KID, &spki),
            invalid_configuration,
        );
        rejects(
            ApprovedJwk::from_ed25519_der(" ", &key.public),
            invalid_configuration,
        );
    }

    #[test]
    fn rsa_keys_must_be_2048_to_4096_bit_public_keys() {
        assert!(ApprovedJwk::from_rsa_pem(RSA_KID, RSA_2048_PUBLIC_PEM.as_bytes()).is_ok());
        rejects(
            ApprovedJwk::from_rsa_pem(RSA_KID, RSA_1024_PUBLIC_PEM.as_bytes()),
            invalid_configuration,
        );
        rejects(
            ApprovedJwk::from_rsa_pem(RSA_KID, ED25519_SPKI_PEM.as_bytes()),
            invalid_configuration,
        );
        rejects(
            ApprovedJwk::from_rsa_pem(RSA_KID, b"not a pem"),
            invalid_configuration,
        );
        rejects(
            ApprovedJwk::from_rsa_pem("", RSA_2048_PUBLIC_PEM.as_bytes()),
            invalid_configuration,
        );
        // JWK components follow the same rules.
        let components = |n: &str, e: &str| {
            DecodingKey::from_rsa_components(n, e).expect("base64url components")
        };
        assert!(
            ApprovedJwk::from_decoding_key(
                RSA_KID,
                Algorithm::RS256,
                components(RSA_2048_MODULUS, RSA_EXPONENT)
            )
            .is_ok()
        );
        assert!(
            ApprovedJwk::from_decoding_key(
                RSA_KID,
                Algorithm::RS256,
                components(RSA_2048_MODULUS, "Aw")
            )
            .is_ok(),
            "e = 3 is the smallest legal exponent"
        );
        for (name, n, e) in [
            ("1024-bit modulus", RSA_1024_MODULUS, RSA_EXPONENT),
            ("even exponent", RSA_2048_MODULUS, "AQAC"),
            ("exponent of one", RSA_2048_MODULUS, "AQ"),
            ("exponent of zero", RSA_2048_MODULUS, "AA"),
            ("exponent above 2^33", RSA_2048_MODULUS, "AgAAAAE"),
            ("empty exponent", RSA_2048_MODULUS, ""),
        ] {
            match ApprovedJwk::from_decoding_key(RSA_KID, Algorithm::RS256, components(n, e)) {
                Err(OidcError::InvalidConfiguration) => {}
                other => panic!("{name} was not rejected: {other:?}"),
            }
        }
        // Size boundaries, using raw components.
        let modulus = |bytes: usize| {
            let mut modulus = vec![0xff_u8; bytes];
            modulus[0] = 0x80;
            modulus
        };
        let exponent = [0x01, 0x00, 0x01];
        for (name, bytes, accepted) in [
            ("2040-bit", 255, false),
            ("2048-bit", 256, true),
            ("4096-bit", 512, true),
            ("4104-bit", 513, false),
        ] {
            let key = DecodingKey::from_rsa_raw_components(&modulus(bytes), &exponent);
            let result = ApprovedJwk::from_decoding_key(RSA_KID, Algorithm::RS256, key);
            assert_eq!(result.is_ok(), accepted, "{name}: {result:?}");
        }
        let mut even_modulus = modulus(256);
        even_modulus[255] = 0xfe;
        rejects(
            ApprovedJwk::from_decoding_key(
                RSA_KID,
                Algorithm::RS256,
                DecodingKey::from_rsa_raw_components(&even_modulus, &exponent),
            ),
            invalid_configuration,
        );
    }

    #[test]
    fn decoding_keys_must_match_the_approved_algorithm_family() {
        let key = EdKey::generate();
        let ed25519 = DecodingKey::from_ed_der(&key.public);
        assert!(ApprovedJwk::from_decoding_key(ED_KID, Algorithm::EdDSA, ed25519.clone()).is_ok());
        rejects(
            ApprovedJwk::from_decoding_key(ED_KID, Algorithm::RS256, ed25519),
            invalid_configuration,
        );
        let rsa = DecodingKey::from_rsa_components(RSA_2048_MODULUS, RSA_EXPONENT)
            .expect("RSA components");
        rejects(
            ApprovedJwk::from_decoding_key(RSA_KID, Algorithm::EdDSA, rsa.clone()),
            invalid_configuration,
        );
        // An HMAC secret is never a verification key, whatever it is labelled.
        let secret = DecodingKey::from_secret(b"shared-secret");
        rejects(
            ApprovedJwk::from_decoding_key("hmac", Algorithm::RS256, secret.clone()),
            invalid_configuration,
        );
        rejects(
            ApprovedJwk::from_decoding_key("hmac", Algorithm::EdDSA, secret.clone()),
            invalid_configuration,
        );
        rejects(
            ApprovedJwk::from_decoding_key("hmac", Algorithm::HS256, secret),
            disallowed_algorithm,
        );
        for algorithm in [
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::ES256,
        ] {
            rejects(
                ApprovedJwk::from_decoding_key(RSA_KID, algorithm, rsa.clone()),
                disallowed_algorithm,
            );
        }
    }

    #[test]
    fn verifier_configuration_rejects_empty_sets_and_duplicate_kids() {
        let key = EdKey::generate();
        rejects(
            OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], Vec::new()),
            invalid_configuration,
        );
        rejects(
            OidcConfig::new(
                ISSUER,
                [AUDIENCE.to_owned()],
                vec![key.approved(ED_KID), key.approved(ED_KID)],
            ),
            invalid_configuration,
        );
        rejects(
            OidcConfig::new(" ", [AUDIENCE.to_owned()], vec![key.approved(ED_KID)]),
            invalid_configuration,
        );
        rejects(
            OidcConfig::new(ISSUER, [" ".to_owned()], vec![key.approved(ED_KID)]),
            invalid_configuration,
        );
        rejects(
            OidcConfig::new(ISSUER, Vec::new(), vec![key.approved(ED_KID)])
                .and_then(OidcVerifier::new),
            invalid_configuration,
        );
    }
}
