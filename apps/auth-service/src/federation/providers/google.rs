//! Google sign-in: `OpenID` Connect, so the identity comes only from a signed ID token.

use super::{
    FederationApplication, IdentityStrategy, MAX_TOKEN_BYTES, ProviderEndpoints, ProviderError,
    VerifiedIdentity,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use piquel_auth_protocol::jwt::{Algorithm as JwtAlgorithm, Claim, KeyType, KeyUse};
use piquel_auth_protocol::oauth::{Prompt, Scope};
use piquel_common::ErrorChain;
use reqwest::header::{CACHE_CONTROL, HeaderMap};
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::Mutex;
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
/// Shortest time between two signing-key fetches, and the shortest time fetched keys
/// stay fresh. Bounds how often unknown key IDs or an outage can make us call Google.
const MIN_KEYS_FETCH_INTERVAL: Duration = Duration::from_mins(1);
/// How long fetched keys stay fresh when Google's response sets no `max-age`.
const DEFAULT_KEYS_LIFETIME: Duration = Duration::from_hours(1);
/// Longest time fetched keys stay fresh, whatever `max-age` says.
const MAX_KEYS_LIFETIME: Duration = Duration::from_hours(24);

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
    /// Keys last fetched from `keys`, shared by every clone of this protocol.
    cache: Arc<Mutex<GoogleKeyCache>>,
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
                cache: Arc::default(),
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

    /// Returns the RS256 key named `kid`, as of `now`. Google's keys are fetched only
    /// when the cache is stale or lacks `kid` (key rotation), and at most once per
    /// `MIN_KEYS_FETCH_INTERVAL`. The lock is held across the fetch, so concurrent
    /// sign-ins share one request instead of each calling Google. If a fetch fails but
    /// the stale keys still hold `kid`, they are used: the ID token itself came straight
    /// from Google's token endpoint over TLS, so a key endpoint outage should not stop
    /// sign-in.
    pub(in crate::federation) async fn signing_key(
        &self,
        client: &reqwest::Client,
        kid: String,
        now: Instant,
    ) -> Result<DecodingKey, ProviderError> {
        let mut cache = self.cache.lock().await;
        if cache.needs_fetch(&kid, now)
            && let Err(error) = cache.fetch(client, &self.keys, now).await
        {
            if cache.find(&kid).is_none() {
                return Err(error);
            }
            tracing::warn!(error = %ErrorChain(&error), "using stale Google signing keys");
        }
        let jwk = cache
            .find(&kid)
            .ok_or(GoogleError::UnknownSigningKey(kid))?;
        Ok(DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(GoogleError::from)?)
    }
}

/// Google's signing keys as last fetched, with when to fetch them again.
#[derive(Default)]
struct GoogleKeyCache {
    /// Keys from the last successful fetch; empty before the first one.
    keys: Vec<GoogleJwk>,
    /// When `keys` stop being fresh; `None` before the first successful fetch.
    fresh_until: Option<Instant>,
    /// Start of the last fetch, successful or not.
    fetched_at: Option<Instant>,
}

impl GoogleKeyCache {
    /// True when the keys are stale or lack `kid`, and the last fetch is at least
    /// `MIN_KEYS_FETCH_INTERVAL` old.
    fn needs_fetch(&self, kid: &str, now: Instant) -> bool {
        let unusable =
            self.fresh_until.is_none_or(|until| now >= until) || self.find(kid).is_none();
        unusable
            && self
                .fetched_at
                .is_none_or(|at| now.saturating_duration_since(at) >= MIN_KEYS_FETCH_INTERVAL)
    }

    /// Replaces the keys with Google's current ones. A failure keeps the old keys but
    /// still counts as a fetch, so a failing endpoint is not retried on every sign-in.
    async fn fetch(
        &mut self,
        client: &reqwest::Client,
        url: &str,
        now: Instant,
    ) -> Result<(), ProviderError> {
        self.fetched_at = Some(now);
        let response = client.get(url).send().await?;
        let lifetime = Self::lifetime(response.headers());
        let jwks: GoogleJwks = FederationApplication::json(response).await?;
        self.keys = jwks.keys;
        self.fresh_until = Some(now + lifetime);
        Ok(())
    }

    /// Reads how long keys stay fresh from `Cache-Control: max-age`, falling back to
    /// `DEFAULT_KEYS_LIFETIME` and bounded to
    /// `MIN_KEYS_FETCH_INTERVAL..=MAX_KEYS_LIFETIME`.
    fn lifetime(headers: &HeaderMap) -> Duration {
        headers
            .get_all(CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .find_map(|directive| directive.trim().strip_prefix("max-age=")?.parse().ok())
            .map_or(DEFAULT_KEYS_LIFETIME, Duration::from_secs)
            .clamp(MIN_KEYS_FETCH_INTERVAL, MAX_KEYS_LIFETIME)
    }

    /// Finds the RS256 signing key named `kid`.
    fn find(&self, kid: &str) -> Option<&GoogleJwk> {
        self.keys.iter().find(|key| key.signs(kid))
    }
}

impl FederationApplication {
    /// Takes Google's identity only from an `RS256` ID token signed by a published key,
    /// looked up in the protocol's key cache.
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
        let key = protocol
            .signing_key(&self.client, kid, Instant::now())
            .await?;
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
