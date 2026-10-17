//! Server-side session storage: the store trait, its records, and an in-memory store.

use super::ReturnTo;
use crate::{BearerToken, IdToken, PendingLogin, RefreshToken, Scopes, SessionId, Tokens};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt,
    future::{Future, ready},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

/// Random bytes in a session key: 256 bits.
const KEY_BYTES: usize = 32;

/// A session's random key, held by the browser in a cookie. Stores receive it but
/// should persist only [`Self::storage_key`], so reading the store does not give
/// access to sessions.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionKey(String);

impl fmt::Debug for SessionKey {
    /// Never prints the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionKey(REDACTED)")
    }
}

impl SessionKey {
    /// A fresh random key.
    pub(super) fn generate() -> Result<Self, rand::Error> {
        let mut bytes = [0; KEY_BYTES];
        OsRng.try_fill_bytes(&mut bytes)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
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

    /// The SHA-256 of the key, base64url-encoded: what a store should persist.
    #[must_use]
    pub fn storage_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.0.as_bytes()))
    }
}

/// A stored value and its version, which every save increments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Versioned<T> {
    /// The value.
    pub value: T,
    /// The version it was saved at.
    pub version: u64,
}

/// A signed-in user's tokens, kept server-side.
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

    /// The user's `sub`, for [`SessionStore::delete_by_subject`].
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.id_token.claims().sub
    }

    /// Auth's session ID, for [`SessionStore::delete_by_sid`].
    #[must_use]
    pub fn sid(&self) -> Option<SessionId> {
        self.id_token.claims().authentication.sid
    }
}

/// A login waiting for its callback, with where to send the user afterwards.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingAuthorization {
    /// The PKCE verifier, `state` and `nonce` of the login.
    pub login: PendingLogin,
    /// Where the user goes once signed in.
    pub return_to: ReturnTo,
}

/// The ID of one refresh attempt's lease. Stores keep it with the session, so only
/// that attempt can save its result or give the lease back.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LeaseId(String);

impl LeaseId {
    /// A fresh random ID.
    pub(super) fn generate() -> Result<Self, rand::Error> {
        let mut bytes = [0; 16];
        OsRng.try_fill_bytes(&mut bytes)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// The ID, to persist.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The outcome of [`SessionStore::lease_refresh`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lease {
    /// This request holds the lease and must refresh.
    Acquired,
    /// Another request, possibly on another replica, is refreshing.
    Busy,
    /// The session was saved since it was read: someone already refreshed it. Reload
    /// it instead of redeeming the old refresh token.
    Changed,
    /// A lease expired without its holder saving or giving it back. Auth may have
    /// rotated the refresh token anyway, so the stored one cannot be trusted: the
    /// session must end.
    Abandoned,
    /// The session no longer exists.
    Missing,
}

/// Which sessions a back-channel logout ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogoutTarget {
    /// One of auth's sessions, named by `sid`.
    Session(SessionId),
    /// Every session of the user `sub`, as when the user removes the app's access.
    Subject(String),
}

/// A validated back-channel logout, applied once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackchannelLogout {
    /// The issuer that sent it.
    pub issuer: String,
    /// The logout token's ID; a second logout with it changes nothing.
    pub jti: String,
    /// Which sessions end.
    pub target: LogoutTarget,
    /// How long to remember `jti`: as long as the token could still validate.
    pub remember_until: DateTime<Utc>,
}

/// Where sessions are kept: the only extension point of the login routes. Use
/// [`MemorySessions`] for development and tests, `PostgresSessions` (the `postgres`
/// feature) in production, or implement it for another database.
///
/// Auth rotates refresh tokens and revokes the whole family when one is reused, so
/// two requests refreshing one session at once would sign the user out. Refreshes
/// are therefore serialized through [`Self::lease_refresh`], shared by every replica.
/// Only the attempt holding the lease may write its result with [`Self::save_if`],
/// so a slow attempt cannot overwrite a later one or resurrect a logged-out session.
pub trait SessionStore: Clone + Send + Sync + 'static {
    /// The store's failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The session `id` names, unless it expired or was deleted.
    fn load(
        &self,
        id: &SessionKey,
    ) -> impl Future<Output = Result<Option<Versioned<StoredLogin>>, Self::Error>> + Send;

    /// Stores a new session at version 1, until `expires`.
    fn insert(
        &self,
        id: &SessionKey,
        login: &StoredLogin,
        expires: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Takes the session's refresh lease as `lease` for `ttl`, but only while the
    /// session is still at `version` and holds no lease. Otherwise reports why: a
    /// lease still running is [`Lease::Busy`], one that expired without being given
    /// back is [`Lease::Abandoned`], and a newer version is [`Lease::Changed`].
    fn lease_refresh(
        &self,
        id: &SessionKey,
        version: u64,
        lease: &LeaseId,
        ttl: Duration,
    ) -> impl Future<Output = Result<Lease, Self::Error>> + Send;

    /// Writes `login`, increments the version and gives the lease back, but only if
    /// the session still holds `lease`, even past its expiry. Returns whether it wrote.
    fn save_if(
        &self,
        id: &SessionKey,
        lease: &LeaseId,
        login: &StoredLogin,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Deletes a session.
    fn delete(&self, id: &SessionKey) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Applies a back-channel logout atomically: remembers its `jti` and deletes the
    /// sessions it names, or does neither. Returns `false`, deleting nothing, if the
    /// `jti` was already applied by any replica.
    fn logout(
        &self,
        logout: &BackchannelLogout,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Stores a login waiting for its callback, until `expires`.
    fn insert_pending(
        &self,
        id: &SessionKey,
        pending: &PendingAuthorization,
        expires: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Removes and returns a pending login, unless it expired, so a callback completes
    /// at most once.
    fn take_pending(
        &self,
        id: &SessionKey,
    ) -> impl Future<Output = Result<Option<PendingAuthorization>, Self::Error>> + Send;
}

/// One session in [`MemorySessions`].
struct MemorySession {
    /// The login and its version.
    login: Versioned<StoredLogin>,
    /// When the session ends.
    expires: DateTime<Utc>,
    /// The refresh lease held, and when it expires.
    lease: Option<(LeaseId, DateTime<Utc>)>,
}

/// Everything [`MemorySessions`] holds.
#[derive(Default)]
struct MemoryState {
    /// Sessions by storage key.
    sessions: HashMap<String, MemorySession>,
    /// Pending logins by storage key, with their expiry.
    pending: HashMap<String, (PendingAuthorization, DateTime<Utc>)>,
    /// Applied logout token IDs by issuer and `jti`, with how long to remember them.
    logouts: HashMap<(String, String), DateTime<Utc>>,
}

/// Sessions in process memory, for development and tests. Lost on restart, and not
/// shared between replicas.
#[derive(Clone, Default)]
pub struct MemorySessions(Arc<Mutex<MemoryState>>);

impl fmt::Debug for MemorySessions {
    /// Names the store.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemorySessions")
    }
}

impl MemorySessions {
    /// Runs `operation` on the state, after dropping expired records. A panic while
    /// holding the lock cannot leave a record half-written, so poisoning is ignored.
    fn with<T>(&self, operation: impl FnOnce(&mut MemoryState) -> T) -> T {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Utc::now();
        state.sessions.retain(|_, session| session.expires > now);
        state.pending.retain(|_, (_, expires)| *expires > now);
        state.logouts.retain(|_, until| *until > now);
        operation(&mut state)
    }
}

/// The memory store answers at once, so each operation is a ready future.
impl SessionStore for MemorySessions {
    type Error = Infallible;

    fn load(
        &self,
        id: &SessionKey,
    ) -> impl Future<Output = Result<Option<Versioned<StoredLogin>>, Infallible>> + Send {
        let key = id.storage_key();
        ready(Ok(self.with(|state| {
            state
                .sessions
                .get(&key)
                .map(|session| session.login.clone())
        })))
    }

    fn insert(
        &self,
        id: &SessionKey,
        login: &StoredLogin,
        expires: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Infallible>> + Send {
        let session = MemorySession {
            login: Versioned {
                value: login.clone(),
                version: 1,
            },
            expires,
            lease: None,
        };
        self.with(|state| state.sessions.insert(id.storage_key(), session));
        ready(Ok(()))
    }

    fn lease_refresh(
        &self,
        id: &SessionKey,
        version: u64,
        lease: &LeaseId,
        ttl: Duration,
    ) -> impl Future<Output = Result<Lease, Infallible>> + Send {
        ready(Ok(self.with(|state| {
            let Some(session) = state.sessions.get_mut(&id.storage_key()) else {
                return Lease::Missing;
            };
            let now = Utc::now();
            match &session.lease {
                Some((_, until)) if *until > now => return Lease::Busy,
                Some(_) => return Lease::Abandoned,
                None => {}
            }
            if session.login.version != version {
                return Lease::Changed;
            }
            let until = chrono::TimeDelta::from_std(ttl)
                .ok()
                .and_then(|ttl| now.checked_add_signed(ttl))
                .unwrap_or(now);
            session.lease = Some((lease.clone(), until));
            Lease::Acquired
        })))
    }

    fn save_if(
        &self,
        id: &SessionKey,
        lease: &LeaseId,
        login: &StoredLogin,
    ) -> impl Future<Output = Result<bool, Infallible>> + Send {
        ready(Ok(self.with(|state| {
            let Some(session) = state.sessions.get_mut(&id.storage_key()).filter(|session| {
                session
                    .lease
                    .as_ref()
                    .is_some_and(|(held, _)| held == lease)
            }) else {
                return false;
            };
            session.login = Versioned {
                value: login.clone(),
                version: session.login.version + 1,
            };
            session.lease = None;
            true
        })))
    }

    fn delete(&self, id: &SessionKey) -> impl Future<Output = Result<(), Infallible>> + Send {
        self.with(|state| state.sessions.remove(&id.storage_key()));
        ready(Ok(()))
    }

    fn logout(
        &self,
        logout: &BackchannelLogout,
    ) -> impl Future<Output = Result<bool, Infallible>> + Send {
        ready(Ok(self.with(|state| {
            let key = (logout.issuer.clone(), logout.jti.clone());
            if state.logouts.contains_key(&key) {
                return false;
            }
            state.logouts.insert(key, logout.remember_until);
            state.sessions.retain(|_, session| {
                let login = &session.login.value;
                login.issuer != logout.issuer
                    || match &logout.target {
                        LogoutTarget::Session(sid) => login.sid() != Some(*sid),
                        LogoutTarget::Subject(sub) => login.subject() != sub,
                    }
            });
            true
        })))
    }

    fn insert_pending(
        &self,
        id: &SessionKey,
        pending: &PendingAuthorization,
        expires: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Infallible>> + Send {
        let record = (pending.clone(), expires);
        self.with(|state| state.pending.insert(id.storage_key(), record));
        ready(Ok(()))
    }

    fn take_pending(
        &self,
        id: &SessionKey,
    ) -> impl Future<Output = Result<Option<PendingAuthorization>, Infallible>> + Send {
        ready(Ok(self.with(|state| {
            state
                .pending
                .remove(&id.storage_key())
                .map(|(pending, _)| pending)
        })))
    }
}
