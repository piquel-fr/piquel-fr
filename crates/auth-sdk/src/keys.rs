//! Compact JWS parsing and the signing key cache.

use crate::{
    Clock, SystemClock, TokenError,
    http::{Authorization, Http, NetworkError},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::{DecodingKey, crypto::aws_lc::DEFAULT_PROVIDER};
use piquel_auth_protocol::{
    jwt::{Algorithm, Jwk, JwkSet, TokenType},
    sdk::{ErrorCategory, ErrorReason, SdkError},
};
use serde::Deserialize;
use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};
use thiserror::Error;
use url::Url;

/// Most bytes accepted for a compact token, checked before decoding it.
const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Shortest time between two key fetches, whatever triggers them. Bounds how often
/// unknown key IDs or an outage can make the cache call the issuer.
const MIN_FETCH_INTERVAL: TimeDelta = TimeDelta::seconds(30);
/// How long fetched keys stay fresh when the response sets no `max-age`.
const DEFAULT_LIFETIME: TimeDelta = TimeDelta::hours(1);
/// Longest time fetched keys stay fresh, whatever `max-age` says.
const MAX_LIFETIME: TimeDelta = TimeDelta::hours(24);
/// `typ` media types may carry this prefix (RFC 7515 §4.1.9).
const MEDIA_TYPE_PREFIX: &str = "application/";

/// The protected header of a compact JWS.
#[derive(Clone, Debug, Deserialize)]
pub struct JwsHeader {
    /// Signing algorithm, as sent.
    pub alg: String,
    /// Key that signed the token.
    pub kid: Option<String>,
    /// Token type.
    pub typ: Option<String>,
    /// Extensions the signer requires the verifier to understand (RFC 7515 §4.1.11).
    /// This SDK understands none, so the member is rejected whenever it is present,
    /// even as `null`.
    #[serde(default, deserialize_with = "JwsHeader::present")]
    crit: Option<serde_json::Value>,
}

impl JwsHeader {
    /// Reads a member that matters by its presence, so `null` counts as present.
    fn present<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<serde_json::Value>, D::Error> {
        serde_json::Value::deserialize(deserializer).map(Some)
    }
}

/// A compact JWS, decoded but not yet verified. Parse a token, check its header, then
/// verify it with a [`KeyCache`] before reading the payload.
///
/// ```
/// use piquel_auth::{
///     Jws, TokenError,
///     protocol::jwt::{Algorithm, TokenType},
/// };
///
/// let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0yMDI2IiwidHlwIjoiYXQrand0In0.e30.c2lnbmF0dXJl";
/// let jws = Jws::parse(token)?;
/// assert_eq!(jws.header().kid.as_deref(), Some("key-2026"));
/// jws.require_type(TokenType::Access)?;
/// assert_eq!(jws.require_algorithm(&[Algorithm::Rs256])?, Algorithm::Rs256);
/// assert!(matches!(
///     jws.require_type(TokenType::Id),
///     Err(TokenError::WrongType { .. })
/// ));
/// assert!(matches!(Jws::parse("two.segments"), Err(TokenError::Malformed(_))));
/// # Ok::<(), TokenError>(())
/// ```
#[derive(Clone)]
pub struct Jws<'a> {
    /// Decoded protected header.
    header: JwsHeader,
    /// `header.payload`, the bytes the signature covers.
    signing_input: &'a str,
    /// Decoded payload.
    payload: Vec<u8>,
    /// Decoded signature.
    signature: Vec<u8>,
}

impl fmt::Debug for Jws<'_> {
    /// Shows the header only: the rest would let a reader replay the token.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Jws")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl<'a> Jws<'a> {
    /// Splits and decodes a compact JWS.
    ///
    /// # Errors
    /// [`TokenError::Malformed`] unless the token is three base64url segments, at most
    /// 16 KiB, with a JSON header; [`TokenError::UnsupportedCriticalHeader`] if that
    /// header sets `crit`.
    pub fn parse(token: &'a str) -> Result<Self, TokenError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::Malformed("the token exceeds 16 KiB"));
        }
        let mut segments = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(TokenError::Malformed("the token is not three segments"));
        };
        let decode = |segment: &str| {
            URL_SAFE_NO_PAD
                .decode(segment)
                .map_err(|_| TokenError::Malformed("a segment is not base64url"))
        };
        let parsed: JwsHeader = serde_json::from_slice(&decode(header)?)
            .map_err(|_| TokenError::Malformed("the header is not a JWS header"))?;
        if parsed.crit.is_some() {
            return Err(TokenError::UnsupportedCriticalHeader);
        }
        Ok(Self {
            header: parsed,
            signing_input: &token[..header.len() + 1 + payload.len()],
            payload: decode(payload)?,
            signature: decode(signature)?,
        })
    }

    /// The protected header.
    #[must_use]
    pub const fn header(&self) -> &JwsHeader {
        &self.header
    }

    /// The payload. Read it only once the signature has been verified.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Requires `typ` to be `expected`, compared case-insensitively with or without
    /// the `application/` prefix (RFC 7515 §4.1.9).
    ///
    /// # Errors
    /// [`TokenError::WrongType`] otherwise.
    pub fn require_type(&self, expected: TokenType) -> Result<(), TokenError> {
        let found = self.header.typ.as_deref();
        let matches = found.is_some_and(|typ| {
            let typ = typ
                .get(..MEDIA_TYPE_PREFIX.len())
                .filter(|prefix| prefix.eq_ignore_ascii_case(MEDIA_TYPE_PREFIX))
                .map_or(typ, |_| &typ[MEDIA_TYPE_PREFIX.len()..]);
            typ.eq_ignore_ascii_case(expected.as_str())
        });
        if matches {
            Ok(())
        } else {
            Err(TokenError::WrongType {
                expected,
                found: found.map(str::to_owned),
            })
        }
    }

    /// Requires `alg` to be one of `allowed`.
    ///
    /// # Errors
    /// [`TokenError::UnsupportedAlgorithm`] otherwise, including for `none` and HMAC.
    pub fn require_algorithm(&self, allowed: &[Algorithm]) -> Result<Algorithm, TokenError> {
        self.header
            .alg
            .parse()
            .ok()
            .filter(|algorithm| allowed.contains(algorithm))
            .ok_or_else(|| TokenError::UnsupportedAlgorithm(self.header.alg.clone()))
    }
}

/// Signing keys could not be fetched or used.
#[derive(Debug, Error)]
pub enum KeyError {
    /// The key endpoint could not be reached.
    #[error(transparent)]
    Network(#[from] NetworkError),
    /// The response is not a JSON Web Key Set.
    #[error("signing keys are not a JSON Web Key Set")]
    InvalidDocument(#[source] serde_json::Error),
    /// Two usable keys share a `kid`, so a token's key would be ambiguous.
    #[error("two signing keys share the key ID {0:?}")]
    DuplicateKeyId(String),
    /// The last fetch failed and the next is not due yet, so whether the key exists
    /// is unknown.
    #[error("signing keys could not be fetched recently")]
    Unavailable,
}

impl KeyError {
    /// The shared SDK error code.
    #[must_use]
    pub const fn code(&self) -> SdkError {
        match self {
            Self::Network(_) | Self::Unavailable => SdkError::category(ErrorCategory::Network),
            Self::InvalidDocument(_) => {
                SdkError::new(ErrorCategory::Keys, ErrorReason::InvalidDocument)
            }
            Self::DuplicateKeyId(_) => {
                SdkError::new(ErrorCategory::Keys, ErrorReason::DuplicateKeyId)
            }
        }
    }
}

/// One usable signing key.
#[derive(Clone)]
struct Key {
    /// Key ID matched against token headers.
    kid: String,
    /// The only algorithm the key may verify, when the set names one.
    alg: Option<Algorithm>,
    /// Public key material.
    decoding: DecodingKey,
}

/// The usable keys of a JSON Web Key Set.
///
/// ```
/// use piquel_auth::{KeyError, KeySet};
///
/// let keys = KeySet::parse(br#"{"keys": [
///     {"kty": "RSA", "kid": "key-2026", "use": "sig", "alg": "RS256", "n": "AQAB", "e": "AQAB"},
///     {"kty": "RSA", "kid": "encryption", "use": "enc", "n": "AQAB", "e": "AQAB"},
///     {"kty": "OKP", "kid": "future", "crv": "Ed25519", "x": "AQAB"}
/// ]}"#)?;
/// // Keys for encryption, or of a type the SDK does not know, are skipped.
/// assert_eq!(keys.kids().collect::<Vec<_>>(), ["key-2026"]);
///
/// let duplicated = br#"{"keys": [
///     {"kty": "RSA", "kid": "a", "n": "AQAB", "e": "AQAB"},
///     {"kty": "RSA", "kid": "a", "n": "AQAB", "e": "AQAB"}
/// ]}"#;
/// assert!(matches!(KeySet::parse(duplicated), Err(KeyError::DuplicateKeyId(_))));
/// # Ok::<(), KeyError>(())
/// ```
#[derive(Clone, Default)]
pub struct KeySet {
    /// Keys in document order.
    keys: Vec<Key>,
}

impl fmt::Debug for KeySet {
    /// Lists key IDs; key material is public but long.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.kids()).finish()
    }
}

impl KeySet {
    /// Parses a key set. Keys this SDK cannot use are skipped, as RFC 7517 §5 asks: an
    /// unknown `kty` or `alg`, a `use` other than `sig`, no `kid`, or invalid material.
    ///
    /// # Errors
    /// Fails when the document is not a key set, or two usable keys share a `kid`.
    pub fn parse(document: &[u8]) -> Result<Self, KeyError> {
        let set: JwkSet<serde_json::Value> =
            serde_json::from_slice(document).map_err(KeyError::InvalidDocument)?;
        let mut keys: Vec<Key> = Vec::with_capacity(set.keys.len());
        for value in set.keys {
            let Ok(jwk) = serde_json::from_value::<Jwk>(value) else {
                continue;
            };
            let Ok(decoding) = DecodingKey::from_rsa_components(&jwk.n, &jwk.e) else {
                continue;
            };
            if keys.iter().any(|key| key.kid == jwk.kid) {
                return Err(KeyError::DuplicateKeyId(jwk.kid));
            }
            keys.push(Key {
                kid: jwk.kid,
                alg: jwk.alg,
                decoding,
            });
        }
        Ok(Self { keys })
    }

    /// Key IDs of the usable keys, in document order.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|key| key.kid.as_str())
    }

    /// The key named `kid`.
    fn find(&self, kid: &str) -> Option<&Key> {
        self.keys.iter().find(|key| key.kid == kid)
    }
}

/// Where a cache's keys come from.
struct Source {
    /// The JWKS URL.
    url: Url,
    /// Client fetching it.
    http: Http,
}

/// The cached keys and fetch bookkeeping.
#[derive(Default)]
struct CachedKeys {
    /// Keys from the last successful fetch.
    keys: Arc<KeySet>,
    /// When `keys` stop being fresh; `None` before the first successful fetch.
    fresh_until: Option<DateTime<Utc>>,
    /// Start of the last fetch, successful or not.
    fetched_at: Option<DateTime<Utc>>,
    /// Whether the last fetch failed.
    failed: bool,
}

/// The shared state behind a [`KeyCache`].
struct KeyCacheInner {
    /// Where keys are fetched from; `None` for a fixed set.
    source: Option<Source>,
    /// Time source for freshness and fetch spacing.
    clock: Arc<dyn Clock>,
    /// Keys and bookkeeping, locked only briefly and never across a fetch, so
    /// verifications with fresh keys never wait on the network.
    cached: Mutex<CachedKeys>,
    /// Held during a fetch, so concurrent verifications needing keys share one
    /// request instead of each calling the issuer.
    fetching: tokio::sync::Mutex<()>,
}

/// A cache of an issuer's signing keys, usable with any JWKS URL. Cheap to clone;
/// clones share keys.
///
/// - An unknown `kid` triggers one refetch; it then fails with
///   [`TokenError::UnknownKey`].
/// - Keys are fetched at most once every 30 seconds, whatever the reason.
/// - Keys stay fresh for the response's `max-age`, bounded to 30 seconds through 24
///   hours, or one hour without one.
/// - A failed fetch keeps the last good keys.
///
/// ```no_run
/// # async fn run(token: &str) -> Result<(), Box<dyn std::error::Error>> {
/// use piquel_auth::{Jws, KeyCache, protocol::jwt::Algorithm};
///
/// // One cache per issuer, shared by every request: clones share keys and fetch spacing.
/// let keys = KeyCache::new(
///     "https://www.googleapis.com/oauth2/v3/certs".parse()?,
///     reqwest::Client::new(),
/// );
/// let jws = Jws::parse(token)?;
/// let algorithm = jws.require_algorithm(&[Algorithm::Rs256])?;
/// keys.verify(&jws, algorithm).await?;
/// // Only now can the payload be trusted.
/// let claims: serde_json::Value = serde_json::from_slice(jws.payload())?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct KeyCache(Arc<KeyCacheInner>);

impl fmt::Debug for KeyCache {
    /// Names the source; the keys are behind a lock.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyCache")
            .field("url", &self.0.source.as_ref().map(|source| &source.url))
            .finish_non_exhaustive()
    }
}

impl KeyCache {
    /// Keys fetched from `jwks_uri` with `http`, on first use.
    #[must_use]
    pub fn new(jwks_uri: Url, http: reqwest::Client) -> Self {
        Self::fetched(jwks_uri, Http::new(http), Arc::new(SystemClock))
    }

    /// Like [`Self::new`], with an injected clock.
    #[must_use]
    pub fn with_clock(jwks_uri: Url, http: reqwest::Client, clock: impl Clock) -> Self {
        Self::fetched(jwks_uri, Http::new(http), Arc::new(clock))
    }

    /// Keys that never change and are never fetched, for tests and pinned keys.
    ///
    /// ```
    /// use piquel_auth::{KeyCache, KeySet};
    ///
    /// let pinned = KeySet::parse(
    ///     br#"{"keys": [{"kty": "RSA", "kid": "key-2026", "n": "AQAB", "e": "AQAB"}]}"#,
    /// )?;
    /// let keys = KeyCache::fixed(pinned);
    /// # Ok::<(), piquel_auth::KeyError>(())
    /// ```
    #[must_use]
    pub fn fixed(keys: KeySet) -> Self {
        Self(Arc::new(KeyCacheInner {
            source: None,
            clock: Arc::new(SystemClock),
            cached: Mutex::new(CachedKeys {
                keys: Arc::new(keys),
                ..CachedKeys::default()
            }),
            fetching: tokio::sync::Mutex::default(),
        }))
    }

    /// The cache an [`Issuer`](crate::Issuer) builds for its `jwks_uri`.
    pub(crate) fn fetched(url: Url, http: Http, clock: Arc<dyn Clock>) -> Self {
        Self(Arc::new(KeyCacheInner {
            source: Some(Source { url, http }),
            clock,
            cached: Mutex::default(),
            fetching: tokio::sync::Mutex::default(),
        }))
    }

    /// Verifies `jws`'s signature under `algorithm`, which the caller has already
    /// checked with [`Jws::require_algorithm`], with the key its `kid` names.
    ///
    /// # Errors
    /// [`TokenError::UnknownKey`] when no usable key matches, [`TokenError::Keys`]
    /// when keys were needed but could not be fetched, and
    /// [`TokenError::BadSignature`] when the signature does not verify.
    pub async fn verify(&self, jws: &Jws<'_>, algorithm: Algorithm) -> Result<(), TokenError> {
        let kid = jws
            .header
            .kid
            .as_deref()
            .ok_or(TokenError::UnknownKey(None))?;
        let key = self.key(kid).await?;
        if key.alg.is_some_and(|alg| alg != algorithm) {
            return Err(TokenError::UnknownKey(Some(kid.to_owned())));
        }
        let name = match algorithm {
            Algorithm::Rs256 => jsonwebtoken::Algorithm::RS256,
        };
        // The aws-lc-rs provider is named explicitly instead of through
        // jsonwebtoken's process default, which an application enabling another
        // backend would make ambiguous.
        let verifier = (DEFAULT_PROVIDER.verifier_factory)(&name, &key.decoding)
            .map_err(|_| TokenError::BadSignature)?;
        verifier
            .verify(jws.signing_input.as_bytes(), &jws.signature)
            .map_err(|_| TokenError::BadSignature)
    }

    /// The cached keys. Nothing panics while holding the lock, so poisoning is
    /// ignored.
    fn cached(&self) -> MutexGuard<'_, CachedKeys> {
        self.0.cached.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The key named `kid`, if the cached keys hold it and are fresh.
    fn fresh(&self, kid: &str) -> Option<Key> {
        let now = self.0.clock.now();
        let cached = self.cached();
        let fresh = cached.fresh_until.is_some_and(|until| now < until);
        cached.keys.find(kid).filter(|_| fresh).cloned()
    }

    /// The key named `kid`, fetching keys when they are stale or lack it and the last
    /// fetch is old enough.
    async fn key(&self, kid: &str) -> Result<Key, TokenError> {
        if let Some(key) = self.fresh(kid) {
            return Ok(key);
        }
        let _fetching = match &self.0.source {
            Some(_) => Some(self.0.fetching.lock().await),
            None => None,
        };
        // Another request may have fetched the key while this one waited.
        if let Some(key) = self.fresh(kid) {
            return Ok(key);
        }
        let now = self.0.clock.now();
        let due = {
            let mut cached = self.cached();
            let due = self.0.source.is_some()
                && cached
                    .fetched_at
                    .is_none_or(|at| now.signed_duration_since(at) >= MIN_FETCH_INTERVAL);
            if due {
                // Counted as failed until it succeeds, so a fetch whose caller is
                // cancelled mid-request still reports keys as unavailable.
                cached.fetched_at = Some(now);
                cached.failed = true;
            }
            due
        };
        if let Some(source) = self.0.source.as_ref().filter(|_| due) {
            let fetched = Self::fetch(source).await;
            let mut cached = self.cached();
            match fetched {
                Ok((keys, lifetime)) => {
                    cached.keys = Arc::new(keys);
                    cached.fresh_until = Some(now + lifetime);
                    cached.failed = false;
                }
                // Stale keys that hold `kid` are better than failing every request
                // while the key endpoint is down.
                Err(error) => {
                    if cached.keys.find(kid).is_none() {
                        return Err(TokenError::Keys(error));
                    }
                }
            }
        }
        let cached = self.cached();
        match cached.keys.find(kid) {
            Some(key) => Ok(key.clone()),
            None if cached.failed => Err(TokenError::Keys(KeyError::Unavailable)),
            None => Err(TokenError::UnknownKey(Some(kid.to_owned()))),
        }
    }

    /// Fetches the key set and how long it stays fresh.
    async fn fetch(source: &Source) -> Result<(KeySet, TimeDelta), KeyError> {
        let reply = source
            .http
            .get(&source.url, Authorization::None)
            .await?
            .ok(&source.url)?;
        // A `max-age` too large to represent is longer than the cap anyway.
        let lifetime = reply
            .max_age
            .map_or(DEFAULT_LIFETIME, |seconds| {
                i64::try_from(seconds)
                    .ok()
                    .and_then(TimeDelta::try_seconds)
                    .unwrap_or(MAX_LIFETIME)
            })
            .clamp(MIN_FETCH_INTERVAL, MAX_LIFETIME);
        Ok((KeySet::parse(&reply.body)?, lifetime))
    }
}
