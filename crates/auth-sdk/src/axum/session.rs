//! Session storage. Applications implement [`SessionBackend`], four plain operations
//! on opaque records, wherever they want to keep sessions. The SDK keeps everything
//! else: the record format and its validation, expiry, pending logins, and the
//! refresh lease that stops two requests from redeeming one refresh token.

use super::ReturnTo;
use crate::{BearerToken, IdToken, PendingLogin, RefreshToken, Scopes, SessionId, Tokens};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt,
    future::{Future, ready},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

/// Random bytes in a session key: 256 bits.
const KEY_BYTES: usize = 32;
/// Random bytes in a lease ID.
const LEASE_BYTES: usize = 16;

/// A record a [`SessionBackend`] stores. The SDK writes `data` and reads it back
/// through its own validated types, so a backend stores it as an opaque string.
/// `Debug` never prints `data`, which holds the user's tokens.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Increases with every write, for [`SessionBackend::replace`].
    pub version: u64,
    /// The SDK's serialized record. Store it unchanged.
    pub data: String,
    /// When the record stops being valid. The SDK ignores expired records, so a
    /// backend may delete them whenever it likes, or never.
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for SessionRecord {
    /// Shows the version and expiry, never the tokens in `data`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRecord")
            .field("version", &self.version)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Where the login routes keep sessions: four operations on [`SessionRecord`]s under
/// string keys, in any database.
///
/// [`MemoryBackend`] is for development and tests only: it loses every session on
/// restart and is not shared between replicas. **Applications implement their own
/// backend for real persistence**, and check it with `check_backend` (the
/// `test-util` feature) against a real database.
///
/// The SDK keeps all the logic, so a backend needs no knowledge of sessions. It
/// only has to make [`Self::replace`] and [`Self::remove`] atomic: two replicas
/// refreshing one session at once would otherwise both redeem its refresh token, and
/// auth answers a reused refresh token by revoking the whole family, signing the user
/// out.
///
/// Refresh leases expire by the issuer clock, the system clock by default, which
/// replicas compare with each other: keep their clocks synchronized, for example with
/// NTP. A lease lasts a minute, so a few seconds of skew are harmless.
///
/// # Example: PostgreSQL
///
/// One table holds every record:
///
/// ```sql
/// CREATE TABLE auth_sessions (
///     key TEXT PRIMARY KEY,
///     version BIGINT NOT NULL,
///     data TEXT NOT NULL,
///     expires_at TIMESTAMPTZ NOT NULL
/// );
/// ```
///
/// Each operation is one statement, which an application writes with its own
/// database layer, for example `SQLx`'s checked `query!` macros. `BIGINT` is signed,
/// so convert versions with `i64::try_from` rather than `as`:
///
/// | Operation | Statement |
/// | --- | --- |
/// | `load` | `SELECT version, data, expires_at FROM auth_sessions WHERE key = $1` |
/// | `insert` | `INSERT INTO auth_sessions (key, version, data, expires_at) VALUES ($1, $2, $3, $4)` |
/// | `replace` | `UPDATE auth_sessions SET version = $3, data = $4, expires_at = $5 WHERE key = $1 AND version = $2`, `true` if one row changed |
/// | `remove` | `DELETE FROM auth_sessions WHERE key = $1`, `true` if one row went |
///
/// Expired rows can be swept with `DELETE FROM auth_sessions WHERE expires_at < now()`.
///
/// # Example: a backend over a map
///
/// ```
/// use piquel_auth::axum::{SessionBackend, SessionRecord};
/// use std::{
///     collections::HashMap,
///     convert::Infallible,
///     sync::{Arc, Mutex},
/// };
///
/// /// Records in a shared map.
/// #[derive(Clone, Default)]
/// struct MapBackend(Arc<Mutex<HashMap<String, SessionRecord>>>);
///
/// impl SessionBackend for MapBackend {
///     type Error = Infallible;
///
///     async fn load(&self, key: &str) -> Result<Option<SessionRecord>, Infallible> {
///         Ok(self.0.lock().unwrap().get(key).cloned())
///     }
///
///     async fn insert(&self, key: &str, record: &SessionRecord) -> Result<(), Infallible> {
///         self.0.lock().unwrap().insert(key.to_owned(), record.clone());
///         Ok(())
///     }
///
///     async fn replace(
///         &self,
///         key: &str,
///         expected: u64,
///         record: &SessionRecord,
///     ) -> Result<bool, Infallible> {
///         let mut records = self.0.lock().unwrap();
///         match records.get_mut(key) {
///             Some(stored) if stored.version == expected => {
///                 *stored = record.clone();
///                 Ok(true)
///             }
///             _ => Ok(false),
///         }
///     }
///
///     async fn remove(&self, key: &str) -> Result<bool, Infallible> {
///         Ok(self.0.lock().unwrap().remove(key).is_some())
///     }
/// }
/// ```
pub trait SessionBackend: Clone + Send + Sync + 'static {
    /// The backend's failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The record under `key`, if any.
    fn load(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<SessionRecord>, Self::Error>> + Send;

    /// Stores a record under a new `key`. Keys are random, so they never collide.
    fn insert(
        &self,
        key: &str,
        record: &SessionRecord,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Replaces the record under `key` with `record`, but only if the stored record
    /// is still at version `expected`, in one atomic step. Returns whether it wrote.
    fn replace(
        &self,
        key: &str,
        expected: u64,
        record: &SessionRecord,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Removes the record under `key`. Returns whether there was one: of two
    /// concurrent calls, only one may return `true`.
    fn remove(&self, key: &str) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}

/// Sessions in process memory, for development and tests only. **Every session is
/// lost on restart, and replicas do not share them**; implement a
/// [`SessionBackend`] for real persistence.
///
/// ```
/// use piquel_auth::axum::{LoginRoutes, MemoryBackend};
/// # fn run(client: piquel_auth::Client) {
/// let auth = LoginRoutes::new(client, MemoryBackend::default());
/// # }
/// ```
#[derive(Clone, Default)]
pub struct MemoryBackend(Arc<Mutex<HashMap<String, SessionRecord>>>);

impl fmt::Debug for MemoryBackend {
    /// Names the backend.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemoryBackend")
    }
}

impl MemoryBackend {
    /// Runs `operation` on the records, after dropping expired ones. A panic while
    /// holding the lock cannot leave a record half-written, so poisoning is ignored.
    fn with<T>(&self, operation: impl FnOnce(&mut HashMap<String, SessionRecord>) -> T) -> T {
        let mut records = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Utc::now();
        records.retain(|_, record| record.expires_at > now);
        operation(&mut records)
    }
}

/// The memory backend answers at once, so each operation is a ready future.
impl SessionBackend for MemoryBackend {
    type Error = Infallible;

    fn load(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<SessionRecord>, Infallible>> + Send {
        ready(Ok(self.with(|records| records.get(key).cloned())))
    }

    fn insert(
        &self,
        key: &str,
        record: &SessionRecord,
    ) -> impl Future<Output = Result<(), Infallible>> + Send {
        self.with(|records| records.insert(key.to_owned(), record.clone()));
        ready(Ok(()))
    }

    fn replace(
        &self,
        key: &str,
        expected: u64,
        record: &SessionRecord,
    ) -> impl Future<Output = Result<bool, Infallible>> + Send {
        ready(Ok(self.with(|records| match records.get_mut(key) {
            Some(stored) if stored.version == expected => {
                *stored = record.clone();
                true
            }
            _ => false,
        })))
    }

    fn remove(&self, key: &str) -> impl Future<Output = Result<bool, Infallible>> + Send {
        ready(Ok(self.with(|records| records.remove(key).is_some())))
    }
}

/// A signed-in user's tokens, kept server-side.
///
/// ```no_run
/// # async fn run(user: piquel_auth::axum::SignedIn) -> Result<(), reqwest::Error> {
/// // Call an API for the user with their access token, refreshed by the login layer.
/// let notes = reqwest::Client::new()
///     .get("https://notes.piquel.fr/api/notes")
///     .bearer_auth(user.login().access_token.expose())
///     .send()
///     .await?;
/// # Ok(()) }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredLogin {
    /// The issuer the user signed in with.
    pub issuer: String,
    /// The validated ID token of the sign-in, or of the latest refresh that sent one.
    pub id_token: IdToken,
    /// The latest access token.
    pub access_token: BearerToken,
    /// When the access token expires.
    pub expires_at: DateTime<Utc>,
    /// Scopes granted to the access token.
    pub scopes: Scopes,
    /// The refresh token, with `offline_access`. Auth rotates it on every refresh.
    pub refresh_token: Option<RefreshToken>,
}

impl StoredLogin {
    /// The login `tokens` describe, if they hold the ID token every sign-in returns.
    pub(super) fn new(issuer: String, tokens: Tokens) -> Option<Self> {
        Some(Self {
            issuer,
            id_token: tokens.id_token?,
            access_token: tokens.access_token,
            expires_at: tokens.expires_at,
            scopes: tokens.scopes,
            refresh_token: tokens.refresh_token,
        })
    }

    /// This login after a refresh returned `tokens`. An absent ID token or refresh
    /// token keeps the current one. `None` if a new ID token names another user or
    /// issuer (OIDC Core §12.2).
    pub(super) fn refreshed(&self, tokens: Tokens) -> Option<Self> {
        let same = |id_token: &IdToken| {
            let (new, old) = (id_token.claims(), self.id_token.claims());
            new.sub == old.sub && new.iss == old.iss
        };
        if tokens
            .id_token
            .as_ref()
            .is_some_and(|id_token| !same(id_token))
        {
            return None;
        }
        Some(Self {
            issuer: self.issuer.clone(),
            id_token: tokens.id_token.unwrap_or_else(|| self.id_token.clone()),
            access_token: tokens.access_token,
            expires_at: tokens.expires_at,
            scopes: tokens.scopes,
            refresh_token: tokens.refresh_token.or_else(|| self.refresh_token.clone()),
        })
    }

    /// The user's `sub`.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.id_token.claims().sub
    }

    /// Auth's session ID, if the ID token carries one.
    #[must_use]
    pub fn sid(&self) -> Option<SessionId> {
        self.id_token.claims().authentication.sid
    }
}

/// A session's random key, held by the browser in a cookie. Backends see only its
/// SHA-256, so reading the backend does not give access to sessions.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct SessionKey(String);

impl fmt::Debug for SessionKey {
    /// Never prints the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionKey(REDACTED)")
    }
}

impl SessionKey {
    /// A fresh random key.
    pub(super) fn generate() -> Result<Self, rand::Error> {
        Ok(Self(random(KEY_BYTES)?))
    }

    /// A key read from a cookie, if it has the shape of one.
    pub(super) fn parse(value: &str) -> Option<Self> {
        URL_SAFE_NO_PAD
            .decode(value)
            .ok()
            .filter(|bytes| bytes.len() == KEY_BYTES)
            .map(|_| Self(value.to_owned()))
    }

    /// The key as sent in the cookie.
    pub(super) fn as_cookie(&self) -> &str {
        &self.0
    }

    /// The backend key of this session's record of `kind`: the SHA-256 of the key,
    /// namespaced so sessions and pending logins never collide.
    fn record(&self, kind: &str) -> String {
        format!(
            "{kind}:{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(self.0.as_bytes()))
        )
    }
}

/// `bytes` random bytes, base64url-encoded.
fn random(bytes: usize) -> Result<String, rand::Error> {
    let mut buffer = vec![0; bytes];
    OsRng.try_fill_bytes(&mut buffer)?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

/// A login waiting for its callback, with where to send the user afterwards.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PendingAuthorization {
    /// The PKCE verifier, `state` and `nonce` of the login.
    pub(super) login: PendingLogin,
    /// Where the user goes once signed in.
    pub(super) return_to: ReturnTo,
}

/// A refresh lease: which attempt holds it, and until when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseState {
    /// The holding attempt.
    id: String,
    /// When the lease expires if it is never given back.
    until: DateTime<Utc>,
}

/// What a session record's `data` holds.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionData {
    /// The signed-in user's tokens.
    login: StoredLogin,
    /// The refresh lease, while an attempt holds it.
    lease: Option<LeaseState>,
}

/// A session as read: its login, record version, and whether a refresh holds it.
#[derive(Clone, Debug)]
pub(super) struct Session {
    /// The signed-in user's tokens.
    pub(super) login: StoredLogin,
    /// The record version read.
    pub(super) version: u64,
    /// Whether a refresh attempt holds the lease.
    pub(super) leased: bool,
}

/// The outcome of [`Sessions::lease`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lease {
    /// This attempt holds the lease until the given time, and must refresh, save and
    /// give it back before then.
    Acquired(DateTime<Utc>),
    /// Another attempt, possibly on another replica, is refreshing.
    Busy,
    /// The session was saved since it was read: reload it.
    Changed,
    /// A lease expired without being given back. Auth may have rotated the refresh
    /// token anyway, so the stored one cannot be trusted: the session must end.
    Abandoned,
    /// The session no longer exists.
    Missing,
}

/// The ID of one refresh attempt's lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LeaseId(String);

impl LeaseId {
    /// A fresh random ID.
    pub(super) fn generate() -> Result<Self, rand::Error> {
        Ok(Self(random(LEASE_BYTES)?))
    }
}

/// Any backend's failure, once erased.
pub(super) type BackendError = Box<dyn std::error::Error + Send + Sync>;
/// A backend operation, once erased.
type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BackendError>> + Send + 'a>>;

/// Declares [`ErasedBackend`], an object-safe copy of [`SessionBackend`], and
/// implements it for every backend, so the routes and extractors need no backend
/// type parameter.
macro_rules! erased_backend {
    ($($method:ident($($argument:ident: $type:ty),*) -> $output:ty;)+) => {
        /// [`SessionBackend`] with boxed futures and errors.
        trait ErasedBackend: Send + Sync {
            $(
                #[doc = concat!("Erased [`SessionBackend::", stringify!($method), "`].")]
                fn $method<'a>(&'a self, $($argument: $type),*) -> BackendFuture<'a, $output>;
            )+
        }

        impl<B: SessionBackend> ErasedBackend for B {
            $(
                fn $method<'a>(&'a self, $($argument: $type),*) -> BackendFuture<'a, $output> {
                    Box::pin(async move {
                        SessionBackend::$method(self, $($argument),*).await.map_err(Into::into)
                    })
                }
            )+
        }
    };
}

erased_backend! {
    load(key: &'a str) -> Option<SessionRecord>;
    insert(key: &'a str, record: &'a SessionRecord) -> ();
    replace(key: &'a str, expected: u64, record: &'a SessionRecord) -> bool;
    remove(key: &'a str) -> bool;
}

/// The SDK's session logic over an application's backend: record format, expiry,
/// pending logins and the refresh lease.
#[derive(Clone)]
pub(super) struct Sessions(Arc<dyn ErasedBackend>);

/// Record kind of a signed-in session.
const SESSION: &str = "session";
/// Record kind of a pending login.
const PENDING: &str = "pending";

impl Sessions {
    /// Sessions in `backend`.
    pub(super) fn new(backend: impl SessionBackend) -> Self {
        Self(Arc::new(backend))
    }

    /// The record under `key` and its decoded data, unless it is missing, expired or
    /// unreadable. An unreadable record, written by another version or corrupted, is
    /// treated as missing rather than trusted.
    async fn read<T: DeserializeOwned>(
        &self,
        key: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(SessionRecord, T)>, BackendError> {
        let Some(record) = self.0.load(key).await? else {
            return Ok(None);
        };
        if record.expires_at <= now {
            return Ok(None);
        }
        match serde_json::from_str(&record.data) {
            Ok(data) => Ok(Some((record, data))),
            Err(error) => {
                tracing::warn!(%error, "ignoring an unreadable session record");
                Ok(None)
            }
        }
    }

    /// A record holding `data` at `version`, expiring at `expires_at`.
    fn record(
        data: &impl Serialize,
        version: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<SessionRecord, BackendError> {
        Ok(SessionRecord {
            version,
            data: serde_json::to_string(data)?,
            expires_at,
        })
    }

    /// The session under `key`.
    pub(super) async fn load(
        &self,
        key: &SessionKey,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, BackendError> {
        let session = self.read::<SessionData>(&key.record(SESSION), now).await?;
        Ok(session.map(|(record, data)| Session {
            login: data.login,
            version: record.version,
            leased: data.lease.is_some(),
        }))
    }

    /// Starts a session under `key`, until `expires_at`.
    pub(super) async fn insert(
        &self,
        key: &SessionKey,
        login: &StoredLogin,
        expires_at: DateTime<Utc>,
    ) -> Result<(), BackendError> {
        let data = SessionData {
            login: login.clone(),
            lease: None,
        };
        let record = Self::record(&data, 1, expires_at)?;
        self.0.insert(&key.record(SESSION), &record).await
    }

    /// Ends the session under `key`.
    pub(super) async fn delete(&self, key: &SessionKey) -> Result<(), BackendError> {
        self.0.remove(&key.record(SESSION)).await.map(drop)
    }

    /// Takes the refresh lease as `lease` until `now + ttl`, but only while the
    /// session is still at `version` and no attempt holds it.
    pub(super) async fn lease(
        &self,
        key: &SessionKey,
        version: u64,
        lease: &LeaseId,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<Lease, BackendError> {
        let name = key.record(SESSION);
        let Some((record, mut data)) = self.read::<SessionData>(&name, now).await? else {
            return Ok(Lease::Missing);
        };
        match &data.lease {
            Some(held) if held.until > now => return Ok(Lease::Busy),
            Some(_) => return Ok(Lease::Abandoned),
            None => {}
        }
        if record.version != version {
            return Ok(Lease::Changed);
        }
        let ttl = TimeDelta::from_std(ttl).unwrap_or(TimeDelta::MAX);
        let until = now.checked_add_signed(ttl).unwrap_or(now);
        data.lease = Some(LeaseState {
            id: lease.0.clone(),
            until,
        });
        let leased = Self::record(&data, version + 1, record.expires_at)?;
        Ok(if self.0.replace(&name, version, &leased).await? {
            Lease::Acquired(until)
        } else {
            // Another request wrote between the read and the write, most likely
            // taking the lease: wait for its result.
            Lease::Busy
        })
    }

    /// Writes `login` and gives the lease back, but only if `lease` still holds it and
    /// has not expired: past its expiry, another request may already have found it
    /// abandoned. Returns the saved session, or `None` if the lease was lost, as when
    /// the session was logged out meanwhile.
    ///
    /// `now` is read again after the backend read, so a slow read cannot make an
    /// expired lease look current. The caller bounds the whole save by the lease.
    pub(super) async fn save(
        &self,
        key: &SessionKey,
        lease: &LeaseId,
        login: StoredLogin,
        now: impl Fn() -> DateTime<Utc> + Send + Sync,
    ) -> Result<Option<Session>, BackendError> {
        let name = key.record(SESSION);
        let Some((record, data)) = self.read::<SessionData>(&name, now()).await? else {
            return Ok(None);
        };
        let now = now();
        if data
            .lease
            .as_ref()
            .is_none_or(|held| held.id != lease.0 || held.until <= now)
        {
            return Ok(None);
        }
        let version = record.version + 1;
        let data = SessionData { login, lease: None };
        let saved = Self::record(&data, version, record.expires_at)?;
        Ok(self
            .0
            .replace(&name, record.version, &saved)
            .await?
            .then_some(Session {
                login: data.login,
                version,
                leased: false,
            }))
    }

    /// Keeps a pending login under `key`, until `expires_at`.
    pub(super) async fn insert_pending(
        &self,
        key: &SessionKey,
        pending: &PendingAuthorization,
        expires_at: DateTime<Utc>,
    ) -> Result<(), BackendError> {
        let record = Self::record(pending, 1, expires_at)?;
        self.0.insert(&key.record(PENDING), &record).await
    }

    /// Takes the pending login under `key`, at most once: only the request whose
    /// removal succeeds gets it.
    pub(super) async fn take_pending(
        &self,
        key: &SessionKey,
        now: DateTime<Utc>,
    ) -> Result<Option<PendingAuthorization>, BackendError> {
        let name = key.record(PENDING);
        let Some((_, pending)) = self.read(&name, now).await? else {
            return Ok(None);
        };
        Ok(self.0.remove(&name).await?.then_some(pending))
    }
}

/// How a backend failed [`check_backend`].
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, thiserror::Error)]
pub enum BackendCheckError {
    /// An operation failed.
    #[error("the backend failed")]
    Backend(#[source] BackendError),
    /// An operation succeeded but broke the [`SessionBackend`] contract.
    #[error("the backend breaks its contract: {0}")]
    Contract(&'static str),
}

/// Rounds of contention [`check_backend`] runs.
#[cfg(any(test, feature = "test-util"))]
const CHECK_ROUNDS: usize = 25;
/// Concurrent callers in each round of contention.
#[cfg(any(test, feature = "test-util"))]
const CHECK_COMPETITORS: usize = 4;

/// Checks that `backend` keeps the [`SessionBackend`] contract the login routes rely
/// on. Run it in a test against the real database, on a multi-threaded runtime with
/// at least two workers:
///
/// ```
/// use piquel_auth::axum::{MemoryBackend, check_backend};
///
/// # let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
/// # runtime.block_on(async {
/// // In a `#[tokio::test(flavor = "multi_thread")]`:
/// check_backend(&MemoryBackend::default()).await.expect("a sound backend");
/// # });
/// ```
///
/// It checks that records round-trip, that `replace` and `remove` refuse missing
/// records and never create one, and that of several callers racing `replace` at
/// one version, or `remove`, exactly one wins, and the stored record is the winner's.
/// The races run on separate tasks over 25 rounds, which catches a
/// read-then-write backend in practice but cannot prove atomicity: keep each
/// operation a single atomic statement. It writes and removes records under random
/// keys.
///
/// # Errors
/// [`BackendCheckError`] naming the first failed check, or saying the runtime has
/// fewer than two workers, since racing calls could not overlap.
#[cfg(any(test, feature = "test-util"))]
pub async fn check_backend<B: SessionBackend>(backend: &B) -> Result<(), BackendCheckError> {
    use BackendCheckError::Contract;
    use tokio::runtime::{Handle, RuntimeFlavor};
    let runtime = Handle::current();
    if runtime.runtime_flavor() != RuntimeFlavor::MultiThread || runtime.metrics().num_workers() < 2
    {
        return Err(Contract(
            "run check_backend on a multi-threaded runtime with at least two workers, \
             so racing calls overlap",
        ));
    }
    let failed = |error: B::Error| BackendCheckError::Backend(Box::new(error));
    let record = |version, data: String| SessionRecord {
        version,
        data,
        expires_at: Utc::now() + TimeDelta::minutes(5),
    };
    let key = check_key()?;
    if backend.load(&key).await.map_err(failed)?.is_some() {
        return Err(Contract("load found a record that was never inserted"));
    }
    let missing = record(2, "missing".into());
    if backend.replace(&key, 1, &missing).await.map_err(failed)?
        || backend.load(&key).await.map_err(failed)?.is_some()
    {
        return Err(Contract("replace wrote a record that does not exist"));
    }
    if backend.remove(&key).await.map_err(failed)? {
        return Err(Contract("remove reported a record that does not exist"));
    }
    let first = record(1, "first".into());
    backend.insert(&key, &first).await.map_err(failed)?;
    if backend.load(&key).await.map_err(failed)?.as_ref() != Some(&first) {
        return Err(Contract(
            "load did not return the inserted record unchanged",
        ));
    }
    let second = record(2, "second".into());
    if backend.replace(&key, 7, &second).await.map_err(failed)? {
        return Err(Contract("replace wrote although the version did not match"));
    }
    if !backend.replace(&key, 1, &second).await.map_err(failed)?
        || backend.load(&key).await.map_err(failed)?.as_ref() != Some(&second)
    {
        return Err(Contract("replace did not write at the matching version"));
    }
    if !backend.remove(&key).await.map_err(failed)?
        || backend.load(&key).await.map_err(failed)?.is_some()
        || backend.replace(&key, 2, &second).await.map_err(failed)?
        || backend.load(&key).await.map_err(failed)?.is_some()
    {
        return Err(Contract("a removed record came back"));
    }
    for _ in 0..CHECK_ROUNDS {
        race(backend).await?;
    }
    Ok(())
}

/// A fresh random key for [`check_backend`].
#[cfg(any(test, feature = "test-util"))]
fn check_key() -> Result<String, BackendCheckError> {
    random(KEY_BYTES)
        .map(|key| format!("check:{key}"))
        .map_err(|error| BackendCheckError::Backend(Box::new(error)))
}

/// One round of contention: racing `replace` calls at one version, then racing
/// `remove` calls, each on its own task, released together.
#[cfg(any(test, feature = "test-util"))]
async fn race<B: SessionBackend>(backend: &B) -> Result<(), BackendCheckError> {
    use BackendCheckError::{Backend, Contract};
    use tokio::sync::Barrier;
    let key = Arc::new(check_key()?);
    let expires_at = Utc::now() + TimeDelta::minutes(5);
    let initial = SessionRecord {
        version: 1,
        data: "initial".into(),
        expires_at,
    };
    backend
        .insert(&key, &initial)
        .await
        .map_err(|error| Backend(Box::new(error)))?;
    // Every competitor starts its call at once, on its own task.
    let spawn = |call: fn(B, Arc<String>, usize) -> _| {
        let barrier = Arc::new(Barrier::new(CHECK_COMPETITORS));
        (0..CHECK_COMPETITORS)
            .map(|competitor| {
                let (backend, key, barrier) = (backend.clone(), key.clone(), barrier.clone());
                tokio::spawn(async move {
                    barrier.wait().await;
                    call(backend, key, competitor).await
                })
            })
            .collect::<Vec<_>>()
    };
    let winners = |tasks: Vec<tokio::task::JoinHandle<Result<bool, B::Error>>>| async move {
        let mut winners = Vec::new();
        for (competitor, task) in tasks.into_iter().enumerate() {
            if task
                .await
                .map_err(|error| Backend(Box::new(error)))?
                .map_err(|error| Backend(Box::new(error)))?
            {
                winners.push(competitor);
            }
        }
        Ok::<_, BackendCheckError>(winners)
    };
    let replaces = spawn(|backend, key, competitor| {
        Box::pin(async move {
            let record = SessionRecord {
                version: 2,
                data: format!("competitor {competitor}"),
                expires_at: Utc::now() + TimeDelta::minutes(5),
            };
            backend.replace(&key, 1, &record).await
        }) as Pin<Box<dyn Future<Output = Result<bool, B::Error>> + Send>>
    });
    let won = winners(replaces).await?;
    let [winner] = won[..] else {
        return Err(Contract(
            "of racing replaces at one version, exactly one must write",
        ));
    };
    let stored = backend
        .load(&key)
        .await
        .map_err(|error| Backend(Box::new(error)))?;
    if stored.map(|record| record.data) != Some(format!("competitor {winner}")) {
        return Err(Contract("the stored record is not the winning replace's"));
    }
    let removes = spawn(|backend, key, _| {
        Box::pin(async move { backend.remove(&key).await })
            as Pin<Box<dyn Future<Output = Result<bool, B::Error>> + Send>>
    });
    if winners(removes).await?.len() != 1 {
        return Err(Contract(
            "of racing removes, exactly one must report the record",
        ));
    }
    if backend
        .load(&key)
        .await
        .map_err(|error| Backend(Box::new(error)))?
        .is_some()
    {
        return Err(Contract("a record survived the racing removes"));
    }
    Ok(())
}
