use crate::error::{HarnessError, Result};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Claims issued by the fixture OIDC provider.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OidcClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
}

/// Overrides used to generate deliberately invalid issuer/audience/expiry
/// cases without hand-writing JWTs in an integration test.
#[derive(Clone, Debug)]
pub struct OidcTokenOptions {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub expires_in: Duration,
    pub not_before: Option<SystemTime>,
    pub scope: Option<String>,
    pub tenant_id: Option<Uuid>,
}

impl Default for OidcTokenOptions {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            expires_in: Duration::from_secs(300),
            not_before: None,
            scope: Some("echo:invoke".to_owned()),
            tenant_id: None,
        }
    }
}

/// Minimal issuer plus the real RSA signature verifier used by relay tests.
pub struct OidcFixture {
    pub issuer: String,
    pub audience: String,
    pub key_id: String,
    encoding_key: EncodingKey,
    public_key_pem: String,
}

impl std::fmt::Debug for OidcFixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcFixture")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl OidcFixture {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|error| HarnessError::Pki(format!("generating OIDC RSA key: {error}")))?;
        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|error| HarnessError::Pki(format!("encoding OIDC RSA private key: {error}")))?
            .to_string();
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|error| HarnessError::Pki(format!("encoding OIDC RSA public key: {error}")))?;
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
        Ok(Self {
            issuer: issuer.into(),
            audience: audience.into(),
            key_id: "m1-fixture-rsa-1".to_owned(),
            encoding_key,
            public_key_pem,
        })
    }

    pub fn issue(&self, subject: impl Into<String>) -> Result<String> {
        self.issue_with(subject, OidcTokenOptions::default())
    }

    pub fn issue_for_tenant(&self, subject: impl Into<String>, tenant_id: Uuid) -> Result<String> {
        self.issue_with(
            subject,
            OidcTokenOptions {
                tenant_id: Some(tenant_id),
                ..OidcTokenOptions::default()
            },
        )
    }

    pub fn issue_with(
        &self,
        subject: impl Into<String>,
        options: OidcTokenOptions,
    ) -> Result<String> {
        let now = unix_seconds(SystemTime::now())?;
        let exp = if options.expires_in.is_zero() {
            now.saturating_sub(60)
        } else {
            now.saturating_add(options.expires_in.as_secs() as i64)
        };
        let nbf = options.not_before.map(unix_seconds).transpose()?;
        let claims = OidcClaims {
            iss: options.issuer.unwrap_or_else(|| self.issuer.clone()),
            aud: options.audience.unwrap_or_else(|| self.audience.clone()),
            sub: subject.into(),
            exp,
            iat: now,
            nbf,
            scope: options.scope,
            tenant_id: options.tenant_id,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());
        let token = encode(&header, &claims, &self.encoding_key)?;
        crate::c11_capture::record_sentinel("credential", token.as_bytes())?;
        Ok(token)
    }

    pub fn issue_expired(&self, subject: impl Into<String>) -> Result<String> {
        self.issue_with(
            subject,
            OidcTokenOptions {
                expires_in: Duration::from_secs(0),
                ..OidcTokenOptions::default()
            },
        )
    }

    pub fn issue_with_wrong_issuer(&self, subject: impl Into<String>) -> Result<String> {
        self.issue_with(
            subject,
            OidcTokenOptions {
                issuer: Some("https://invalid.example.test".to_owned()),
                ..OidcTokenOptions::default()
            },
        )
    }

    pub fn issue_with_wrong_audience(&self, subject: impl Into<String>) -> Result<String> {
        self.issue_with(
            subject,
            OidcTokenOptions {
                audience: Some("agent-tunnel-wrong-audience".to_owned()),
                ..OidcTokenOptions::default()
            },
        )
    }

    /// Return the per-run public key in PEM form for the production OIDC
    /// verifier.  The harness deliberately does not implement a second
    /// verifier, so acceptance tests exercise the relay's verifier itself.
    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }
}

fn unix_seconds(time: SystemTime) -> Result<i64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|error| {
            HarnessError::InvalidInput(format!("system clock before Unix epoch: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::{OidcFixture, OidcTokenOptions};
    use std::time::{Duration, SystemTime};
    use tunnel_catalog::{ApprovedJwk, OidcConfig, OidcError, OidcVerifier};

    /// The relay's real verifier, approving the fixture's RSA key under `kid`.
    fn production_verifier(fixture: &OidcFixture, kid: &str) -> OidcVerifier {
        let key = ApprovedJwk::from_rsa_pem(kid, fixture.public_key_pem().as_bytes())
            .expect("approved fixture RSA key");
        let config = OidcConfig::new(
            fixture.issuer.clone(),
            [fixture.audience.clone()],
            vec![key],
        )
        .expect("OIDC config")
        .with_required_scopes(["echo:invoke".to_owned()])
        .expect("required scope");
        OidcVerifier::new(config).expect("OIDC verifier")
    }

    fn rejected(result: Result<tunnel_catalog::ValidatedClaims, OidcError>) -> OidcError {
        match result {
            Ok(claims) => panic!("token was accepted: {claims:?}"),
            Err(error) => error,
        }
    }

    #[test]
    fn production_verifier_accepts_fixture_rs256_tokens_and_rejects_claim_variants() {
        let fixture = OidcFixture::new("https://issuer.test", "agent-tunnel").expect("fixture");
        let verifier = production_verifier(&fixture, &fixture.key_id);
        let token = fixture.issue("consumer-a").expect("token");
        let validated = verifier
            .validate_bearer(&format!("Bearer {token}"))
            .expect("fixture RS256 token validates");
        assert_eq!(validated.issuer, fixture.issuer);
        assert_eq!(validated.subject, "consumer-a");
        assert!(validated.scopes.contains("echo:invoke"));

        // M6-C52/M6-C53: a correctly signed token whose registered claims
        // are refused is `ClaimsRejected`, a stage of its own.
        let expired = fixture.issue_expired("consumer-a").expect("expired token");
        assert!(matches!(
            rejected(verifier.validate_token(&expired)),
            OidcError::ClaimsRejected
        ));
        let wrong_issuer = fixture
            .issue_with_wrong_issuer("consumer-a")
            .expect("wrong issuer token");
        assert!(matches!(
            rejected(verifier.validate_token(&wrong_issuer)),
            OidcError::ClaimsRejected
        ));
        let wrong_audience = fixture
            .issue_with_wrong_audience("consumer-a")
            .expect("wrong audience token");
        assert!(matches!(
            rejected(verifier.validate_token(&wrong_audience)),
            OidcError::ClaimsRejected
        ));
        let not_yet_valid = fixture
            .issue_with(
                "consumer-a",
                OidcTokenOptions {
                    not_before: Some(SystemTime::now() + Duration::from_secs(120)),
                    ..Default::default()
                },
            )
            .expect("future nbf token");
        assert!(matches!(
            rejected(verifier.validate_token(&not_yet_valid)),
            OidcError::ClaimsRejected
        ));
        let already_valid = fixture
            .issue_with(
                "consumer-a",
                OidcTokenOptions {
                    not_before: Some(SystemTime::now() - Duration::from_secs(60)),
                    ..Default::default()
                },
            )
            .expect("past nbf token");
        verifier
            .validate_token(&already_valid)
            .expect("past nbf validates");
        let other_scope = fixture
            .issue_with(
                "consumer-a",
                OidcTokenOptions {
                    scope: Some("devices:read".to_owned()),
                    ..Default::default()
                },
            )
            .expect("other scope token");
        assert!(matches!(
            rejected(verifier.validate_token(&other_scope)),
            OidcError::InsufficientScope
        ));

        // The same RSA key approved under another kid does not serve the
        // fixture's kid, and another fixture's key cannot sign for it.
        let rotated = production_verifier(&fixture, "rotated-fixture-key");
        assert!(matches!(
            rejected(rotated.validate_token(&token)),
            OidcError::UnknownKey
        ));
        let impostor = OidcFixture::new("https://issuer.test", "agent-tunnel").expect("impostor");
        let forged = impostor.issue("consumer-a").expect("impostor token");
        assert!(matches!(
            rejected(verifier.validate_token(&forged)),
            OidcError::InvalidToken
        ));
    }

    #[test]
    fn rsa_fixture_issues_claim_variants_for_production_verifier() {
        let fixture = OidcFixture::new("https://issuer.test", "agent-tunnel").expect("fixture");
        let token = fixture.issue("consumer-a").expect("token");
        assert!(token.split('.').count() == 3);
        assert!(!fixture.public_key_pem().is_empty());
        assert_ne!(
            token,
            fixture
                .issue_with_wrong_issuer("consumer-a")
                .expect("token")
        );
        assert_ne!(
            token,
            fixture
                .issue_with_wrong_audience("consumer-a")
                .expect("token")
        );
        assert_ne!(token, fixture.issue_expired("consumer-a").expect("token"));
        let future = std::time::SystemTime::now() + Duration::from_secs(60);
        assert_ne!(
            token,
            fixture
                .issue_with(
                    "consumer-a",
                    OidcTokenOptions {
                        not_before: Some(future),
                        ..Default::default()
                    }
                )
                .expect("token")
        );
    }
}
