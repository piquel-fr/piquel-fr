//! The SDK's session logic over an application's backend: the record format, its
//! sealing and validation, expiry, the refresh lease, and the indexes back-channel
//! logout finds sessions with.

use super::{
    LoginData, SessionKey, SessionRecord, StoredLogin,
    backend::{BackendError, ErasedBackend},
    hashed, random,
};
use crate::{
    ClientId, LEEWAY, LogoutScope, LogoutToken,
    axum::{
        SessionBackend,
        bearer::ErrorChain,
        seal::{Purpose, SealingKey},
    },
};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

/// Random bytes in a lease ID.
const LEASE_BYTES: usize = 16;
/// Tries at writing an index or logout record before giving up on contention.
const UPDATE_ATTEMPTS: usize = 8;

/// A refresh lease: which attempt holds it, and until when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseState {
    /// The holding attempt.
    id: String,
    /// When the lease expires if it is never given back.
    until: DateTime<Utc>,
}

/// What a session record's `data` holds, sealed.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionData {
    /// The signed-in user's tokens.
    login: LoginData,
    /// The refresh lease, while an attempt holds it.
    lease: Option<LeaseState>,
}

/// What an index record's `data` holds: the sessions started under one auth session
/// (`sid`) or for one user (`sub`), which a back-channel logout ends.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct IndexData {
    /// Backend keys of the sessions, each with when it expires.
    sessions: BTreeMap<String, DateTime<Utc>>,
    /// Whether auth ended this `sid`, so no session may join it. Only `sid` indexes
    /// are ended.
    #[serde(default)]
    ended: bool,
}

impl IndexData {
    /// This index with `session` added until `expires_at` and the sessions expired at
    /// `now` dropped, and when its record expires: with its last session.
    fn join(
        mut self,
        session: &str,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> (Self, DateTime<Utc>) {
        self.sessions.retain(|_, until| *until > now);
        self.sessions.insert(session.to_owned(), expires_at);
        let last = self.sessions.values().max().copied().unwrap_or(expires_at);
        (self, last)
    }
}

/// A write the SDK gave up on for reasons of its own, not the backend's.
#[derive(Debug, thiserror::Error)]
enum WriteError {
    /// A fresh random key already holds a record.
    #[error("a fresh random key is already in use")]
    KeyTaken,
    /// Other writers changed a record between every read and write.
    #[error("a record kept changing over {UPDATE_ATTEMPTS} attempts to write it")]
    Contended,
}

/// A session as read: its login, record version, and whether a refresh holds it.
#[derive(Clone, Debug)]
pub(crate) struct Session {
    /// The signed-in user's tokens.
    pub(crate) login: StoredLogin,
    /// The record version read.
    pub(crate) version: u64,
    /// Whether a refresh attempt holds the lease.
    pub(crate) leased: bool,
}

/// The outcome of [`Sessions::lease`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lease {
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
pub(crate) struct LeaseId(String);

impl LeaseId {
    /// A fresh random ID.
    pub(crate) fn generate() -> Result<Self, rand::Error> {
        Ok(Self(random(LEASE_BYTES)?))
    }
}

/// The SDK's session logic over an application's backend, for one client: record
/// format, sealing, expiry and the refresh lease.
#[derive(Clone)]
pub(crate) struct Sessions {
    /// Where records live.
    backend: Arc<dyn ErasedBackend>,
    /// The client whose sessions these are, part of every session record's name.
    client: ClientId,
}

/// Record kind of a signed-in session. `v3` sessions are sealed and named for their
/// client; earlier ones held tokens in plain text and are no longer read: their users
/// sign in again.
const SESSION: &str = "session-v3";
/// Record kind of the sessions of one auth session, by issuer and `sid`.
const SID_INDEX: &str = "logout-sid";
/// Record kind of the sessions of one user, by issuer and `sub`.
const SUB_INDEX: &str = "logout-sub";
/// Record kind of an applied logout token, by issuer and `jti`.
const LOGOUT_JTI: &str = "logout-jti";

/// Where one session lives: its record's name and the key sealing the record, both
/// derived from the session key, which the backend never sees.
struct SessionSlot {
    /// The record's name: the SHA-256 of the client and the session key.
    name: String,
    /// The record's sealing key, derived from the session key.
    seal: SealingKey,
}

impl SessionSlot {
    /// `record`'s session data, unless it is expired, or does not open: written by
    /// another version, for another record or client, or corrupted. Such a record is
    /// treated as missing rather than trusted.
    fn open(&self, record: &SessionRecord, now: DateTime<Utc>) -> Option<SessionData> {
        if record.expires_at <= now {
            return None;
        }
        let data = self.seal.open(&record.data, &self.name);
        if data.is_none() {
            tracing::warn!("ignoring a session record that does not open");
        }
        data
    }

    /// A record holding `data` sealed, at `version`, expiring at `expires_at`.
    fn record(
        &self,
        data: &SessionData,
        version: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<SessionRecord, BackendError> {
        Ok(SessionRecord {
            version,
            data: self.seal.seal(data, &self.name)?,
            expires_at,
        })
    }
}

impl Sessions {
    /// The sessions of `client` in `backend`.
    pub(crate) fn new(backend: impl SessionBackend, client: ClientId) -> Self {
        Self {
            backend: Arc::new(backend),
            client,
        }
    }

    /// Where the session under `key` lives. The record is named for the client too,
    /// so an app sharing the backend never finds another app's sessions.
    fn slot(&self, key: &SessionKey) -> Result<SessionSlot, BackendError> {
        Ok(SessionSlot {
            name: hashed(SESSION, &[self.client.as_str(), key.secret()]),
            seal: SealingKey::derive(key.secret().as_bytes(), Purpose::Session)?,
        })
    }

    /// The session record under `slot` and its data, unless it is missing, expired or
    /// does not open.
    async fn read_session(
        &self,
        slot: &SessionSlot,
        now: DateTime<Utc>,
    ) -> Result<Option<(SessionRecord, SessionData)>, BackendError> {
        let Some(record) = self.backend.load(&slot.name).await? else {
            return Ok(None);
        };
        Ok(slot.open(&record, now).map(|data| (record, data)))
    }

    /// The decoded data of `record`, unless it is expired or unreadable. An unreadable
    /// record, written by another version or corrupted, is treated as missing rather
    /// than trusted.
    fn decode<T: DeserializeOwned>(record: &SessionRecord, now: DateTime<Utc>) -> Option<T> {
        if record.expires_at <= now {
            return None;
        }
        serde_json::from_str(&record.data)
            .inspect_err(|error| tracing::warn!(%error, "ignoring an unreadable session record"))
            .ok()
    }

    /// The record under `key` and its decoded data, unless it is missing, expired or
    /// unreadable.
    async fn read<T: DeserializeOwned>(
        &self,
        key: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(SessionRecord, T)>, BackendError> {
        let Some(record) = self.backend.load(key).await? else {
            return Ok(None);
        };
        Ok(Self::decode(&record, now).map(|data| (record, data)))
    }

    /// Rewrites the record under `key`. `change` gets its data, `None` when it is
    /// missing, expired or unreadable, and returns the data to write with its expiry,
    /// or `None` to leave the record alone. A write that loses to another writer is
    /// retried from a fresh read. Returns whether `change` wrote, and the data it last
    /// got.
    async fn update<T: Serialize + DeserializeOwned>(
        &self,
        key: &str,
        now: DateTime<Utc>,
        change: impl Fn(Option<&T>) -> Option<(T, DateTime<Utc>)> + Send,
    ) -> Result<(bool, Option<T>), BackendError> {
        for _ in 0..UPDATE_ATTEMPTS {
            let stored = self.backend.load(key).await?;
            let current = stored.as_ref().and_then(|record| Self::decode(record, now));
            let Some((data, expires_at)) = change(current.as_ref()) else {
                return Ok((false, current));
            };
            // An expired or unreadable record is still stored, so it is replaced.
            // A new record starts at the current time in microseconds, a version a
            // deleted record under the key has not reached, so a writer that read
            // the deleted one cannot overwrite its successor.
            let written = if let Some(record) = &stored {
                let next = Self::record(&data, record.version + 1, expires_at)?;
                self.backend.replace(key, record.version, &next).await?
            } else {
                let version = u64::try_from(now.timestamp_micros()).unwrap_or(1);
                self.backend
                    .insert(key, &Self::record(&data, version, expires_at)?)
                    .await?
            };
            if written {
                return Ok((true, current));
            }
        }
        Err(WriteError::Contended.into())
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
    pub(crate) async fn load(
        &self,
        key: &SessionKey,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, BackendError> {
        let session = self.read_session(&self.slot(key)?, now).await?;
        Ok(session.map(|(record, data)| Session {
            login: StoredLogin(data.login),
            version: record.version,
            leased: data.lease.is_some(),
        }))
    }

    /// Starts a session under `key`, until `expires_at`, and lists it under its `sid`
    /// and `sub` for back-channel logout. Returns `false`, keeping no session, when
    /// auth already ended its `sid`: a logout overtook the sign-in.
    pub(crate) async fn insert(
        &self,
        key: &SessionKey,
        login: &StoredLogin,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, BackendError> {
        let slot = self.slot(key)?;
        let data = SessionData {
            login: login.0.clone(),
            lease: None,
        };
        if !self
            .backend
            .insert(&slot.name, &slot.record(&data, 1, expires_at)?)
            .await?
        {
            return Err(WriteError::KeyTaken.into());
        }
        let name = slot.name;
        let listed = self.list(&name, login, expires_at, now).await;
        if !matches!(listed, Ok(true))
            && let Err(error) = self.backend.remove(&name).await
        {
            // The browser never gets this session's key, so the record is unreachable.
            tracing::warn!(error = %ErrorChain(error.as_ref()), "could not delete a session that failed to start");
        }
        listed
    }

    /// Lists the session `name` under its `sid`, unless auth ended it, then under its
    /// `sub`. Returns whether it was listed: a session missing from either index would
    /// survive a back-channel logout.
    async fn list(
        &self,
        name: &str,
        login: &StoredLogin,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, BackendError> {
        if let Some(sid) = login.sid() {
            let index = hashed(SID_INDEX, &[login.issuer(), &sid.to_string()]);
            let (joined, _) = self
                .update(&index, now, |index: Option<&IndexData>| {
                    let index = index.cloned().unwrap_or_default();
                    (!index.ended).then(|| index.join(name, expires_at, now))
                })
                .await?;
            if !joined {
                return Ok(false);
            }
        }
        let index = hashed(SUB_INDEX, &[login.issuer(), login.subject()]);
        self.update(&index, now, |index: Option<&IndexData>| {
            Some(
                index
                    .cloned()
                    .unwrap_or_default()
                    .join(name, expires_at, now),
            )
        })
        .await?;
        Ok(true)
    }

    /// Applies a validated back-channel logout: deletes every session listed for its
    /// scope, then remembers its `jti` until its expiry and the leeway. A session
    /// logout also ends the `sid` until `ended_until`, so a sign-in that completes
    /// later cannot join it. Returns `false`, changing nothing, if the token was
    /// applied before, as when auth sends it again after losing the answer.
    ///
    /// The `jti` is remembered only once the deletion is done, so a request cut short
    /// by a failure, a crash or auth hanging up is applied again on auth's retry
    /// rather than skipped as applied. Two copies racing may both apply, which ends
    /// the same sessions twice.
    pub(crate) async fn log_out(
        &self,
        token: &LogoutToken,
        ended_until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, BackendError> {
        let claims = token.claims();
        let jti = hashed(LOGOUT_JTI, &[&claims.iss, &claims.jti.to_string()]);
        if self.read::<()>(&jti, now).await?.is_some() {
            return Ok(false);
        }
        self.end(&claims.iss, token.scope(), ended_until, now)
            .await?;
        let until = claims.exp.checked_add_signed(LEEWAY).unwrap_or(claims.exp);
        self.update(&jti, now, |used: Option<&()>| {
            used.is_none().then_some(((), until))
        })
        .await?;
        Ok(true)
    }

    /// Deletes every session listed for `scope` at `issuer`, ending a `sid` until
    /// `ended_until`. Sessions stay listed, so a retry after a failed deletion finds
    /// them again.
    async fn end(
        &self,
        issuer: &str,
        scope: &LogoutScope,
        ended_until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), BackendError> {
        let index = match scope {
            LogoutScope::Session(sid) => {
                let key = hashed(SID_INDEX, &[issuer, &sid.to_string()]);
                let mark_ended = |index: Option<&IndexData>| {
                    let sessions = index.map(|index| index.sessions.clone());
                    let ended = IndexData {
                        sessions: sessions.unwrap_or_default(),
                        ended: true,
                    };
                    Some((ended, ended_until))
                };
                self.update(&key, now, mark_ended).await?.1
            }
            LogoutScope::Subject(sub) => self
                .read(&hashed(SUB_INDEX, &[issuer, sub]), now)
                .await?
                .map(|(_, index)| index),
        };
        for session in index
            .into_iter()
            .flat_map(|index| index.sessions.into_keys())
        {
            self.backend.remove(&session).await?;
        }
        Ok(())
    }

    /// Ends the session under `key`.
    pub(crate) async fn delete(&self, key: &SessionKey) -> Result<(), BackendError> {
        self.backend.remove(&self.slot(key)?.name).await.map(drop)
    }

    /// Takes the refresh lease as `lease` until `now + ttl`, but only while the
    /// session is still at `version` and no attempt holds it.
    pub(crate) async fn lease(
        &self,
        key: &SessionKey,
        version: u64,
        lease: &LeaseId,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<Lease, BackendError> {
        let slot = self.slot(key)?;
        let Some((record, mut data)) = self.read_session(&slot, now).await? else {
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
        let leased = slot.record(&data, version + 1, record.expires_at)?;
        Ok(
            if self.backend.replace(&slot.name, version, &leased).await? {
                Lease::Acquired(until)
            } else {
                // Another request wrote between the read and the write, most likely
                // taking the lease: wait for its result.
                Lease::Busy
            },
        )
    }

    /// Writes `login` and gives the lease back, but only if `lease` still holds it and
    /// has not expired: past its expiry, another request may already have found it
    /// abandoned. Returns the saved session, or `None` if the lease was lost, as when
    /// the session was logged out meanwhile.
    ///
    /// `now` is read again after the backend read, so a slow read cannot make an
    /// expired lease look current. The caller bounds the whole save by the lease.
    pub(crate) async fn save(
        &self,
        key: &SessionKey,
        lease: &LeaseId,
        login: StoredLogin,
        now: impl Fn() -> DateTime<Utc> + Send + Sync,
    ) -> Result<Option<Session>, BackendError> {
        let slot = self.slot(key)?;
        let Some((record, data)) = self.read_session(&slot, now()).await? else {
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
        let data = SessionData {
            login: login.0,
            lease: None,
        };
        let saved = slot.record(&data, version, record.expires_at)?;
        Ok(self
            .backend
            .replace(&slot.name, record.version, &saved)
            .await?
            .then_some(Session {
                login: StoredLogin(data.login),
                version,
                leased: false,
            }))
    }
}
