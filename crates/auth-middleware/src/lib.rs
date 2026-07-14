//! Fail-closed local validation for Piquel ES256 access tokens.
#![allow(missing_docs)]

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use p256::{
    EncodedPoint,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
};
use piquel_auth_protocol::{Audience, ClientId, SessionId, TokenId, UserId};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;

const MAX_TOKEN_BYTES: usize = 8192;
const MAX_JWKS_BYTES: usize = 256 * 1024;
const CACHE_TTL: Duration = Duration::from_mins(5);
const RETIRED_KEY_OVERLAP: Duration = Duration::from_mins(10);
const UNKNOWN_KID_BACKOFF: Duration = Duration::from_secs(30);

/// A verified user identity, never a raw JWT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedUser {
    user_id: UserId,
    session_id: SessionId,
    token_id: TokenId,
    client_id: ClientId,
    audience: Audience,
    scopes: BTreeSet<String>,
    profile_version: u64,
}
impl AuthenticatedUser {
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
    #[must_use]
    pub const fn token_id(&self) -> TokenId {
        self.token_id
    }
    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }
    #[must_use]
    pub fn audience(&self) -> &Audience {
        &self.audience
    }
    #[must_use]
    pub fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }
    #[must_use]
    pub const fn profile_version(&self) -> u64 {
        self.profile_version
    }
}

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("issuer and JWKS URL must be exact HTTPS URLs")]
    InvalidIssuer,
    #[error("only ES256 is supported")]
    InvalidAlgorithm,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthenticationError {
    #[error("authentication failed")]
    MalformedBearer,
    #[error("authentication failed")]
    InvalidToken,
    #[error("authentication temporarily unavailable")]
    KeySetUnavailable,
    #[error("required scope is absent")]
    MissingScope,
}

/// Fetch boundary used by the bounded JWKS cache.
#[async_trait]
pub trait JwksFetcher: Send + Sync {
    async fn fetch(&self, url: &Url) -> Result<Vec<u8>, AuthenticationError>;
}

struct HttpJwksFetcher(reqwest::Client);
#[async_trait]
impl JwksFetcher for HttpJwksFetcher {
    async fn fetch(&self, url: &Url) -> Result<Vec<u8>, AuthenticationError> {
        let response = self
            .0
            .get(url.clone())
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|_| AuthenticationError::KeySetUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err(AuthenticationError::KeySetUnavailable);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| AuthenticationError::KeySetUnavailable)?;
        if bytes.len() > MAX_JWKS_BYTES {
            return Err(AuthenticationError::KeySetUnavailable);
        }
        Ok(bytes.to_vec())
    }
}

#[derive(Clone)]
pub struct AuthMiddleware {
    inner: Arc<Validator>,
}
struct Validator {
    issuer: String,
    audience: Audience,
    jwks_url: Url,
    fetcher: Arc<dyn JwksFetcher>,
    cache: Mutex<KeyCache>,
}
struct KeyCache {
    keys: HashMap<String, CachedKey>,
    fetched_at: Option<Instant>,
    last_unknown_refresh: Option<Instant>,
}
struct CachedKey {
    key: VerifyingKey,
    last_present: Instant,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    kid: String,
    x: String,
    y: String,
}
#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

impl AuthMiddleware {
    /// Builds a validator with a bounded HTTPS JWKS fetcher.
    ///
    /// # Errors
    ///
    /// Returns an error unless issuer and JWKS are HTTPS and ES256 is explicitly selected.
    pub fn new(
        issuer: &Url,
        audience: Audience,
        jwks_url: &Url,
        algorithm: &str,
    ) -> Result<Self, ConfigurationError> {
        Self::with_fetcher(
            issuer,
            audience,
            jwks_url,
            algorithm,
            Arc::new(HttpJwksFetcher(reqwest::Client::new())),
        )
    }

    /// Builds a validator with a caller-supplied fetch boundary, primarily for controlled infrastructure and tests.
    ///
    /// # Errors
    ///
    /// Returns an error unless issuer and JWKS are HTTPS and ES256 is explicitly selected.
    pub fn with_fetcher(
        issuer: &Url,
        audience: Audience,
        jwks_url: &Url,
        algorithm: &str,
        fetcher: Arc<dyn JwksFetcher>,
    ) -> Result<Self, ConfigurationError> {
        if issuer.scheme() != "https"
            || jwks_url.scheme() != "https"
            || issuer.fragment().is_some()
            || issuer.query().is_some()
            || jwks_url.fragment().is_some()
        {
            return Err(ConfigurationError::InvalidIssuer);
        }
        if algorithm != "ES256" {
            return Err(ConfigurationError::InvalidAlgorithm);
        }
        Ok(Self {
            inner: Arc::new(Validator {
                issuer: issuer.as_str().trim_end_matches('/').to_owned(),
                audience,
                jwks_url: jwks_url.clone(),
                fetcher,
                cache: Mutex::new(KeyCache {
                    keys: HashMap::new(),
                    fetched_at: None,
                    last_unknown_refresh: None,
                }),
            }),
        })
    }

    #[must_use]
    pub fn expected_audience(&self) -> &Audience {
        &self.inner.audience
    }
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }
    #[must_use]
    pub fn jwks_url(&self) -> &Url {
        &self.inner.jwks_url
    }
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        "ES256"
    }

    /// Parses exactly one well-formed Bearer credential.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error unless the value contains one Bearer token.
    pub fn bearer_header(value: &str) -> Result<&str, AuthenticationError> {
        let token = value
            .strip_prefix("Bearer ")
            .ok_or(AuthenticationError::MalformedBearer)?;
        if token.is_empty() || token.contains(char::is_whitespace) {
            return Err(AuthenticationError::MalformedBearer);
        }
        Ok(token)
    }

    /// Rejects zero or multiple Authorization header values before validating the token.
    ///
    /// # Errors
    ///
    /// Returns a sanitized authentication or key-availability error.
    pub async fn authenticate_headers<'a>(
        &self,
        values: impl IntoIterator<Item = &'a str>,
    ) -> Result<AuthenticatedUser, AuthenticationError> {
        let mut values = values.into_iter();
        let value = values.next().ok_or(AuthenticationError::MalformedBearer)?;
        if values.next().is_some() {
            return Err(AuthenticationError::MalformedBearer);
        }
        self.authenticate(Self::bearer_header(value)?).await
    }

    /// Validates signature, token type, fixed algorithm, key identifier, issuer, audience, time, and typed claims.
    ///
    /// # Errors
    ///
    /// Returns a sanitized authentication or key-availability error.
    pub async fn authenticate(
        &self,
        token: &str,
    ) -> Result<AuthenticatedUser, AuthenticationError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(AuthenticationError::InvalidToken);
        }
        let mut parts = token.split('.');
        let header_part = parts.next().ok_or(AuthenticationError::InvalidToken)?;
        let claims_part = parts.next().ok_or(AuthenticationError::InvalidToken)?;
        let signature_part = parts.next().ok_or(AuthenticationError::InvalidToken)?;
        if parts.next().is_some() {
            return Err(AuthenticationError::InvalidToken);
        }
        let header: Header = decode_json(header_part)?;
        if header.alg != "ES256"
            || header.typ != "at+jwt"
            || header.kid.is_empty()
            || header.kid.len() > 128
        {
            return Err(AuthenticationError::InvalidToken);
        }
        let key = self.key(&header.kid).await?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_part)
            .map_err(|_| AuthenticationError::InvalidToken)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| AuthenticationError::InvalidToken)?;
        key.verify(
            format!("{header_part}.{claims_part}").as_bytes(),
            &signature,
        )
        .map_err(|_| AuthenticationError::InvalidToken)?;
        let claims: Value = decode_json(claims_part)?;
        self.validate_claims(&claims)
    }

    /// Applies an optional coarse scope gate after authentication.
    ///
    /// # Errors
    ///
    /// Returns `MissingScope` when the verified token lacks the requested scope.
    pub fn require_scope(user: &AuthenticatedUser, scope: &str) -> Result<(), AuthenticationError> {
        if user.scopes().contains(scope) {
            Ok(())
        } else {
            Err(AuthenticationError::MissingScope)
        }
    }

    async fn key(&self, kid: &str) -> Result<VerifyingKey, AuthenticationError> {
        let now = Instant::now();
        let mut cache = self.inner.cache.lock().await;
        if cache
            .fetched_at
            .is_none_or(|at| now.duration_since(at) >= CACHE_TTL)
        {
            self.refresh_locked(&mut cache, now).await?;
        }
        if let Some(key) = cache.keys.get(kid) {
            return Ok(key.key);
        }
        if cache
            .last_unknown_refresh
            .is_none_or(|at| now.duration_since(at) >= UNKNOWN_KID_BACKOFF)
        {
            cache.last_unknown_refresh = Some(now);
            self.refresh_locked(&mut cache, now).await?;
        }
        cache
            .keys
            .get(kid)
            .map(|key| key.key)
            .ok_or(AuthenticationError::InvalidToken)
    }
    async fn refresh_locked(
        &self,
        cache: &mut KeyCache,
        now: Instant,
    ) -> Result<(), AuthenticationError> {
        let bytes = self.inner.fetcher.fetch(&self.inner.jwks_url).await?;
        let jwks: Jwks =
            serde_json::from_slice(&bytes).map_err(|_| AuthenticationError::KeySetUnavailable)?;
        if jwks.keys.is_empty() || jwks.keys.len() > 32 {
            return Err(AuthenticationError::KeySetUnavailable);
        }
        let mut present = BTreeSet::new();
        for jwk in jwks.keys {
            if jwk.kty != "EC"
                || jwk.crv != "P-256"
                || jwk.alg.as_deref() != Some("ES256")
                || jwk.use_.as_deref().is_some_and(|use_| use_ != "sig")
                || jwk.kid.is_empty()
            {
                continue;
            }
            let x = URL_SAFE_NO_PAD
                .decode(jwk.x)
                .map_err(|_| AuthenticationError::KeySetUnavailable)?;
            let y = URL_SAFE_NO_PAD
                .decode(jwk.y)
                .map_err(|_| AuthenticationError::KeySetUnavailable)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AuthenticationError::KeySetUnavailable);
            }
            let point = EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            let key = VerifyingKey::from_encoded_point(&point)
                .map_err(|_| AuthenticationError::KeySetUnavailable)?;
            present.insert(jwk.kid.clone());
            cache.keys.insert(
                jwk.kid,
                CachedKey {
                    key,
                    last_present: now,
                },
            );
        }
        if present.is_empty() {
            return Err(AuthenticationError::KeySetUnavailable);
        }
        cache.keys.retain(|kid, key| {
            present.contains(kid) || now.duration_since(key.last_present) < RETIRED_KEY_OVERLAP
        });
        cache.fetched_at = Some(now);
        Ok(())
    }
    fn validate_claims(&self, claims: &Value) -> Result<AuthenticatedUser, AuthenticationError> {
        let string = |name| {
            claims
                .get(name)
                .and_then(Value::as_str)
                .ok_or(AuthenticationError::InvalidToken)
        };
        let integer = |name| {
            claims
                .get(name)
                .and_then(Value::as_i64)
                .ok_or(AuthenticationError::InvalidToken)
        };
        let now = Utc::now().timestamp();
        let exp = integer("exp")?;
        let iat = integer("iat")?;
        if exp <= now
            || exp > iat + 300
            || iat > now + 30
            || claims
                .get("nbf")
                .and_then(Value::as_i64)
                .is_some_and(|nbf| nbf > now + 30)
            || string("iss")? != self.inner.issuer
            || string("aud")? != self.inner.audience.as_str()
        {
            return Err(AuthenticationError::InvalidToken);
        }
        let scopes = string("scope")?
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect();
        let profile_version = claims
            .get("profile_version")
            .and_then(Value::as_u64)
            .ok_or(AuthenticationError::InvalidToken)?;
        Ok(AuthenticatedUser {
            user_id: UserId::from_str(string("sub")?)
                .map_err(|_| AuthenticationError::InvalidToken)?,
            session_id: SessionId::from_str(string("sid")?)
                .map_err(|_| AuthenticationError::InvalidToken)?,
            token_id: TokenId::from_str(string("jti")?)
                .map_err(|_| AuthenticationError::InvalidToken)?,
            client_id: ClientId::from_str(string("client_id")?)
                .map_err(|_| AuthenticationError::InvalidToken)?,
            audience: self.inner.audience.clone(),
            scopes,
            profile_version,
        })
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(part: &str) -> Result<T, AuthenticationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| AuthenticationError::InvalidToken)?;
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(AuthenticationError::InvalidToken);
    }
    serde_json::from_slice(&bytes).map_err(|_| AuthenticationError::InvalidToken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use serde_json::json;
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct MockFetcher {
        body: StdMutex<Vec<u8>>,
        calls: AtomicUsize,
        fail: bool,
    }
    #[async_trait]
    impl JwksFetcher for MockFetcher {
        async fn fetch(&self, _: &Url) -> Result<Vec<u8>, AuthenticationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(AuthenticationError::KeySetUnavailable)
            } else {
                Ok(self.body.lock().expect("body").clone())
            }
        }
    }
    fn jwks(kid: &str, key: &SigningKey) -> Vec<u8> {
        let point = key.verifying_key().to_encoded_point(false);
        serde_json::to_vec(&json!({"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":kid,"x":URL_SAFE_NO_PAD.encode(point.x().expect("x")),"y":URL_SAFE_NO_PAD.encode(point.y().expect("y"))}]})).expect("JWKS")
    }
    fn token(kid: &str, typ: &str, key: &SigningKey, aud: &str) -> String {
        let now = Utc::now().timestamp();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"alg":"ES256","typ":typ,"kid":kid})).expect("header"),
        );
        let claims=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":"https://issuer.example","sub":UserId::new(),"aud":aud,"sid":SessionId::new(),"jti":TokenId::new(),"client_id":"web-client","scope":"openid profile","profile_version":1,"iat":now,"exp":now+300})).expect("claims"));
        let input = format!("{header}.{claims}");
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
    fn validator(fetcher: Arc<dyn JwksFetcher>) -> AuthMiddleware {
        AuthMiddleware::with_fetcher(
            &Url::parse("https://issuer.example").expect("issuer"),
            Audience::from_str("product-api").expect("audience"),
            &Url::parse("https://issuer.example/.well-known/jwks.json").expect("JWKS URL"),
            "ES256",
            fetcher,
        )
        .expect("validator")
    }
    #[test]
    fn bearer_requires_one_value() {
        assert_eq!(
            AuthMiddleware::bearer_header("Bearer token").expect("token"),
            "token"
        );
        assert!(AuthMiddleware::bearer_header("Bearer one two").is_err());
    }
    #[test]
    fn no_insecure_constructor() {
        assert!(
            AuthMiddleware::new(
                &Url::parse("http://issuer").expect("url"),
                Audience::from_str("api").expect("audience"),
                &Url::parse("https://issuer/jwks").expect("url"),
                "none"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn verifies_real_es256_and_rejects_wrong_token_contract() {
        let key = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("key");
        let fetcher = Arc::new(MockFetcher {
            body: StdMutex::new(jwks("active", &key)),
            calls: AtomicUsize::new(0),
            fail: false,
        });
        let middleware = validator(fetcher);
        assert!(
            middleware
                .authenticate(&token("active", "at+jwt", &key, "product-api"))
                .await
                .is_ok()
        );
        assert_eq!(
            middleware
                .authenticate(&token("active", "JWT", &key, "product-api"))
                .await,
            Err(AuthenticationError::InvalidToken)
        );
        assert_eq!(
            middleware
                .authenticate(&token("active", "at+jwt", &key, "other-api"))
                .await,
            Err(AuthenticationError::InvalidToken)
        );
    }

    #[tokio::test]
    async fn refreshes_once_for_unknown_kid_and_keeps_rotation_overlap() {
        let old = SigningKey::from_bytes((&[3_u8; 32]).into()).expect("old");
        let new = SigningKey::from_bytes((&[4_u8; 32]).into()).expect("new");
        let fetcher = Arc::new(MockFetcher {
            body: StdMutex::new(jwks("old", &old)),
            calls: AtomicUsize::new(0),
            fail: false,
        });
        let middleware = validator(fetcher.clone());
        let old_token = token("old", "at+jwt", &old, "product-api");
        middleware
            .authenticate(&old_token)
            .await
            .expect("old accepted");
        *fetcher.body.lock().expect("body") = jwks("new", &new);
        middleware
            .authenticate(&token("new", "at+jwt", &new, "product-api"))
            .await
            .expect("new accepted after refresh");
        middleware
            .authenticate(&old_token)
            .await
            .expect("old retained during overlap");
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
        assert!(
            middleware
                .authenticate(&token("unknown", "at+jwt", &new, "product-api"))
                .await
                .is_err()
        );
        assert!(
            middleware
                .authenticate(&token("another", "at+jwt", &new, "product-api"))
                .await
                .is_err()
        );
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fails_closed_when_jwks_is_unavailable() {
        let fetcher = Arc::new(MockFetcher {
            body: StdMutex::new(vec![]),
            calls: AtomicUsize::new(0),
            fail: true,
        });
        let key = SigningKey::from_bytes((&[9_u8; 32]).into()).expect("key");
        assert_eq!(
            validator(fetcher)
                .authenticate(&token("kid", "at+jwt", &key, "product-api"))
                .await,
            Err(AuthenticationError::KeySetUnavailable)
        );
    }
}
