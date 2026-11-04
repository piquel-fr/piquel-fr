//! The storage interface applications implement, four plain operations on opaque
//! records, the in-memory backend for development, and the object-safe copy the
//! SDK holds backends through.

use chrono::{DateTime, Utc};
use std::{
    collections::{HashMap, hash_map::Entry},
    convert::Infallible,
    fmt,
    future::{Future, ready},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
};

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
/// only has to make [`Self::insert`], [`Self::replace`] and [`Self::remove`] atomic:
/// two replicas refreshing one session at once would otherwise both redeem its
/// refresh token, and auth answers a reused refresh token by revoking the whole
/// family, signing the user out. Back-channel logout uses the same operations: the
/// SDK keeps records of its own listing the sessions of each auth session and user,
/// and of the logout tokens already applied.
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
/// | `insert` | `INSERT INTO auth_sessions (key, version, data, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT (key) DO NOTHING`, `true` if one row was inserted |
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
///     async fn insert(&self, key: &str, record: &SessionRecord) -> Result<bool, Infallible> {
///         let mut records = self.0.lock().unwrap();
///         if records.contains_key(key) {
///             return Ok(false);
///         }
///         records.insert(key.to_owned(), record.clone());
///         Ok(true)
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

    /// Stores `record` under `key` only if no record is there, in one atomic step.
    /// Returns whether it stored: of two concurrent calls for one key, only one may
    /// return `true`. A record still stored counts as there even once expired; the SDK
    /// replaces expired records itself.
    fn insert(
        &self,
        key: &str,
        record: &SessionRecord,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

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
    ) -> impl Future<Output = Result<bool, Infallible>> + Send {
        ready(Ok(self.with(|records| {
            match records.entry(key.to_owned()) {
                Entry::Occupied(_) => false,
                Entry::Vacant(vacant) => {
                    vacant.insert(record.clone());
                    true
                }
            }
        })))
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

/// Any backend's failure, once erased.
pub(crate) type BackendError = Box<dyn std::error::Error + Send + Sync>;
/// A backend operation, once erased.
pub(super) type BackendFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, BackendError>> + Send + 'a>>;

/// Declares [`ErasedBackend`], an object-safe copy of [`SessionBackend`], and
/// implements it for every backend, so the routes and extractors need no backend
/// type parameter.
macro_rules! erased_backend {
    ($($method:ident($($argument:ident: $type:ty),*) -> $output:ty;)+) => {
        /// [`SessionBackend`] with boxed futures and errors.
        pub(super) trait ErasedBackend: Send + Sync {
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
    insert(key: &'a str, record: &'a SessionRecord) -> bool;
    replace(key: &'a str, expected: u64, record: &'a SessionRecord) -> bool;
    remove(key: &'a str) -> bool;
}
