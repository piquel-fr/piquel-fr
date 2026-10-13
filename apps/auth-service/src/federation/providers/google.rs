//! Google sign-in: `OpenID` Connect, so the identity comes only from a signed ID token.

use super::{
    FederationApplication, IdentityStrategy, MAX_TOKEN_BYTES, ProviderEndpoints, ProviderError,
    VerifiedIdentity,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use piquel_auth_protocol::oauth::{Prompt, Scope};
use piquel_crypto::jwt::{Algorithm as JwtAlgorithm, Claim, KeyType, KeyUse};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// Google scopes: a signed ID token carrying email and profile claims.
const SCOPES: &[&str] = &[
    Scope::OpenId.as_str(),
    Scope::Email.as_str(),
    Scope::Profile.as_str(),
];
/// Claims an ID token must carry, on top of a valid signature.
const REQUIRED_CLAIMS: [&str; 4] = [
    Claim::Issuer.as_str(),
    Claim::Audience.as_str(),
    Claim::ExpiresAt.as_str(),
    Claim::Subject.as_str(),
];
/// Allowed clock skew when checking ID-token issuance.
const CLOCK_SKEW_SECONDS: i64 = 30;
/// Display name proposed when the token carries no usable name.
const FALLBACK_NAME: &str = "Google user";

/// Reasons a Google ID token is not accepted.
#[derive(Debug, Error)]
pub(in crate::federation) enum GoogleError {
    /// The ID token is longer than we accept.
    #[error("Google ID token is {0} bytes; at most {MAX_TOKEN_BYTES} are accepted")]
    TokenTooLong(usize),
    /// The ID token is signed with another algorithm.
    #[error("Google ID token is signed with {0:?}, not RS256")]
    Algorithm(Algorithm),
    /// The ID token header names no signing key.
    #[error("Google ID token header has no key ID")]
    MissingKeyId,
    /// Google publishes no RSA signing key with the ID token's `kid`.
    #[error("Google publishes no RSA signing key with ID {0:?}")]
    UnknownSigningKey(String),
    /// The ID token or its signing key could not be decoded, or the signature, issuer,
    /// audience or a required claim is wrong.
    #[error("Google ID token failed verification")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    /// The ID token also names clients other than this one.
    #[error("Google ID token audience includes other clients")]
    SharedAudience,
    /// The ID token was issued for another sign-in attempt.
    #[error("Google ID token nonce does not match this sign-in attempt")]
    NonceMismatch,
    /// The ID token has expired.
    #[error("Google ID token has expired")]
    Expired,
    /// The ID token's issuance time is in the future.
    #[error("Google ID token is issued in the future")]
    IssuedInFuture,
    /// The ID token was authorized for another client.
    #[error("Google ID token authorized party is another client")]
    AuthorizedPartyMismatch,
}

/// Facts needed to request and verify Google ID tokens.
#[derive(Clone)]
pub(in crate::federation) struct GoogleProtocol {
    /// Public signing-key (JWKS) endpoint, a `String` so tests can use a local fixture.
    pub(in crate::federation) keys: String,
    /// Accepted `iss` values: Google uses both the HTTPS and the legacy scheme-less form.
    pub(in crate::federation) issuers: &'static [&'static str],
}

impl ProviderEndpoints {
    /// Google's protocol facts.
    pub(super) fn google() -> Self {
        Self {
            issuer: "https://accounts.google.com",
            authorization: "https://accounts.google.com/o/oauth2/v2/auth",
            token: "https://oauth2.googleapis.com/token".into(),
            scopes: SCOPES,
            identity: IdentityStrategy::Google(GoogleProtocol {
                keys: "https://www.googleapis.com/oauth2/v3/certs".into(),
                issuers: &["https://accounts.google.com", "accounts.google.com"],
            }),
        }
    }
}

impl GoogleProtocol {
    /// Binds the ID token to this flow's nonce, and makes the user pick an account
    /// instead of silently reusing one.
    pub(super) fn extend_authorization(url: &mut Url, nonce: &str) {
        url.query_pairs_mut()
            .append_pair("nonce", nonce)
            .append_pair("prompt", Prompt::SelectAccount.as_str());
    }
}

impl FederationApplication {
    /// Takes Google's identity only from an `RS256` ID token signed by a published key.
    pub(in crate::federation) async fn google_identity(
        &self,
        response: reqwest::Response,
        client_id: &str,
        nonce: &str,
        protocol: &GoogleProtocol,
    ) -> Result<VerifiedIdentity, ProviderError> {
        let token: GoogleToken = Self::json(response).await?;
        if token.id_token.len() > MAX_TOKEN_BYTES {
            return Err(GoogleError::TokenTooLong(token.id_token.len()).into());
        }
        let header = decode_header(&token.id_token).map_err(GoogleError::from)?;
        if header.alg != Algorithm::RS256 {
            return Err(GoogleError::Algorithm(header.alg).into());
        }
        let kid = header.kid.ok_or(GoogleError::MissingKeyId)?;
        let jwks: GoogleJwks = Self::json(self.client.get(&protocol.keys).send().await?).await?;
        let jwk = jwks
            .keys
            .into_iter()
            .find(|key| key.signs(&kid))
            .ok_or(GoogleError::UnknownSigningKey(kid))?;
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(GoogleError::from)?;
        let claims =
            GoogleClaims::verify(&token.id_token, &key, client_id, nonce, protocol.issuers)?;
        VerifiedIdentity::new(
            claims.sub,
            claims.email.filter(|_| claims.email_verified),
            claims.name,
            FALLBACK_NAME.into(),
        )
    }
}

/// Google's code-exchange response.
#[derive(Deserialize)]
struct GoogleToken {
    /// Signed ID token, never trusted before `GoogleClaims::verify`.
    id_token: String,
}

/// Claims read from a Google ID token.
#[derive(Deserialize)]
pub(in crate::federation) struct GoogleClaims {
    /// Intended client or clients.
    aud: GoogleAudience,
    /// Stable Google account ID.
    sub: String,
    /// Expiry, as a Unix timestamp.
    exp: i64,
    /// Issuance time, as a Unix timestamp.
    iat: i64,
    /// Nonce stored with the federation flow when it started.
    nonce: String,
    /// Authorized party; must be this client when present.
    azp: Option<String>,
    /// Contact address, if the `email` scope returned one.
    email: Option<String>,
    /// Whether Google verified `email`.
    #[serde(default)]
    email_verified: bool,
    /// Profile name proposed for onboarding.
    name: Option<String>,
}

impl GoogleClaims {
    /// Verifies the signature, issuer, exclusive audience, nonce and expiry.
    pub(in crate::federation) fn verify(
        token: &str,
        key: &DecodingKey,
        client_id: &str,
        nonce: &str,
        issuers: &[&str],
    ) -> Result<Self, GoogleError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&REQUIRED_CLAIMS);
        validation.set_audience(&[client_id]);
        validation.set_issuer(issuers);
        validation.leeway = CLOCK_SKEW_SECONDS.unsigned_abs();
        // `decode` checks the signature, required claims, issuer and that the audience
        // includes this client. The checks below are stricter than the library's.
        let claims = decode::<Self>(token, key, &validation)?.claims;
        let now = Utc::now().timestamp();
        if !claims.aud.only_contains(client_id) {
            return Err(GoogleError::SharedAudience);
        }
        if claims.nonce != nonce {
            return Err(GoogleError::NonceMismatch);
        }
        // The library allows `leeway` past expiry; we do not.
        if claims.exp <= now {
            return Err(GoogleError::Expired);
        }
        if claims.iat > now + CLOCK_SKEW_SECONDS {
            return Err(GoogleError::IssuedInFuture);
        }
        if claims.azp.as_deref().is_some_and(|azp| azp != client_id) {
            return Err(GoogleError::AuthorizedPartyMismatch);
        }
        Ok(claims)
    }
}

/// The two legal `OpenID` Connect `aud` encodings.
#[derive(Deserialize)]
#[serde(untagged)]
enum GoogleAudience {
    /// A token for one client.
    Single(String),
    /// A token naming a list of clients.
    Multiple(Vec<String>),
}

impl GoogleAudience {
    /// True when the audience is nonempty and names only this client, never another one.
    fn only_contains(&self, client_id: &str) -> bool {
        match self {
            Self::Single(value) => value == client_id,
            Self::Multiple(values) => {
                !values.is_empty() && values.iter().all(|value| value == client_id)
            }
        }
    }
}

/// Google's published signing keys.
#[derive(Deserialize)]
struct GoogleJwks {
    /// Candidate keys, matched against the ID token's `kid`.
    keys: Vec<GoogleJwk>,
}

/// One published RSA key and its optional metadata.
#[derive(Deserialize)]
struct GoogleJwk {
    /// Key ID matched against the ID token header.
    kid: String,
    /// Key type; must be RSA.
    kty: String,
    /// Signature algorithm; must be RS256 when present.
    alg: Option<String>,
    /// Key usage; must be signing when present.
    #[serde(rename = "use")]
    key_use: Option<String>,
    /// Base64url RSA modulus.
    n: String,
    /// Base64url RSA public exponent.
    e: String,
}

impl GoogleJwk {
    /// True for the RS256 signing key named `kid`; absent metadata does not exclude a key.
    fn signs(&self, kid: &str) -> bool {
        self.kid == kid
            && self.kty == KeyType::Rsa.as_str()
            && self
                .alg
                .as_deref()
                .is_none_or(|alg| alg == JwtAlgorithm::Rs256.as_str())
            && self
                .key_use
                .as_deref()
                .is_none_or(|usage| usage == KeyUse::Signature.as_str())
    }
}
