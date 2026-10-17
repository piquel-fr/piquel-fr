//! Domain repository handles backed by a private pool or transaction connection.
//!
//! This module holds only what every repository shares: the executor, the
//! declaration macro, the `run!` query macro and the column types that checked
//! queries decode into. Each submodule owns one repository together with the
//! records it accepts and returns.

use crate::{Database, DatabaseTransaction, ExclusiveConnection};
use serde::de::DeserializeOwned;
use sqlx::{
    Decode, PgConnection, PgPool, Postgres, Type,
    error::BoxDynError,
    postgres::{PgTypeInfo, PgValueRef},
    types::Json,
};

/// Where a repository runs its queries: directly on the pool, or on the
/// connection of an open transaction.
pub(crate) enum RepositoryExecutor<'a> {
    /// Each operation borrows a connection from the shared pool.
    Pool(&'a PgPool),
    /// Every operation participates in one caller-owned transaction.
    Connection(&'a mut PgConnection),
}

/// Declares each repository handle and its accessor on [`Database`],
/// [`DatabaseTransaction`] and [`ExclusiveConnection`], so all three always expose
/// the same families. Each entry reads `/// Doc comment` then `accessor: HandleName;`.
macro_rules! repositories {
    ($($(#[doc = $doc:literal])* $accessor:ident: $name:ident;)*) => {
        $(
            $(#[doc = $doc])*
            ///
            /// A focused persistence handle: it has no policy and no public SQL escape hatch.
            #[must_use]
            pub struct $name<'a> {
                /// Shared pool or caller-owned transaction used by query macros.
                executor: RepositoryExecutor<'a>,
            }

            impl<'a> $name<'a> {
                /// Binds this handle to the private shared pool.
                pub(crate) const fn from_pool(pool: &'a PgPool) -> Self {
                    Self { executor: RepositoryExecutor::Pool(pool) }
                }

                /// Binds this handle to a transaction connection for atomic operations.
                pub(crate) fn from_connection(connection: &'a mut PgConnection) -> Self {
                    Self { executor: RepositoryExecutor::Connection(connection) }
                }
            }
        )*

        impl Database {
            $(
                #[doc = concat!(
                    "Returns a [`", stringify!($name), "`] that runs each query on the pool."
                )]
                pub fn $accessor(&self) -> $name<'_> {
                    $name::from_pool(&self.pool)
                }
            )*
        }

        impl DatabaseTransaction<'_> {
            $(
                #[doc = concat!("Returns a [`", stringify!($name), "`] bound to this transaction.")]
                pub fn $accessor(&mut self) -> $name<'_> {
                    $name::from_connection(&mut self.inner)
                }
            )*
        }

        impl ExclusiveConnection {
            $(
                #[doc = concat!(
                    "Returns a [`", stringify!($name), "`] bound to the locked connection."
                )]
                pub fn $accessor(&mut self) -> $name<'_> {
                    $name::from_connection(&mut self.connection)
                }
            )*
        }
    };
}

repositories! {
    /// User accounts.
    users: UserRepository;
    /// Verified email addresses and their cross-account ownership.
    emails: EmailRepository;
    /// Browser sessions, their cookie digests and passkey confirmations.
    sessions: SessionRepository;
    /// Typed domain events, their personal data and consumer cursors.
    events: EventRepository;
    /// Passkey credentials and `WebAuthn` ceremony state.
    passkeys: PasskeyRepository;
    /// OIDC clients, authorization requests, codes and consent.
    oidc: OidcRepository;
    /// Refresh token families and their rotation.
    tokens: TokenRepository;
    /// Social login transactions, pending signups and linked identities.
    federation: FederationRepository;
    /// Invitations and shared request rate limits.
    security: SecurityRepository;
    /// Deletion of expired ephemeral state.
    maintenance: MaintenanceRepository;
}

/// Runs a checked query on the repository's pool or transaction connection and
/// converts the driver error into a [`DatabaseError`](crate::DatabaseError), e.g.
/// `run!(self, fetch_optional, sqlx::query_as!(StoredUser, "...", id.as_uuid()))`.
///
/// `$method` is the `sqlx` executor method: `execute`, `fetch_one` (a missing row
/// becomes [`DatabaseError::NotFound`](crate::DatabaseError::NotFound)), `fetch_optional` or `fetch_all`. A macro
/// rather than a method because `&PgPool` and `&mut PgConnection` are different
/// executor types.
macro_rules! run {
    ($self:expr, $method:ident, $query:expr) => {{
        let query = $query;
        match &mut $self.executor {
            RepositoryExecutor::Pool(pool) => query.$method(*pool).await,
            RepositoryExecutor::Connection(connection) => query.$method(&mut **connection).await,
        }
        .map_err(Into::<DatabaseError>::into)
    }};
}

/// A JSONB array column decoded straight into a record's `Vec` field, e.g.
/// `scopes AS "scopes: JsonArray<String>"` in `query_as!`, which converts each
/// overridden column with `Into`. Invalid JSON fails decoding.
#[derive(Debug)]
struct JsonArray<T>(Vec<T>);

impl<T> Type<Postgres> for JsonArray<T> {
    /// Stored as `JSONB`.
    fn type_info() -> PgTypeInfo {
        Json::<Vec<T>>::type_info()
    }
}

impl<'r, T: DeserializeOwned + 'r> Decode<'r, Postgres> for JsonArray<T> {
    /// Deserializes the stored array.
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        Json::<Vec<T>>::decode(value).map(|Json(values)| Self(values))
    }
}

impl<T> From<JsonArray<T>> for Vec<T> {
    /// Unwraps the decoded array.
    fn from(JsonArray(values): JsonArray<T>) -> Self {
        values
    }
}

/// A `BIGINT` column that must not be negative, decoded into a `u64` field, e.g.
/// `profile_version AS "profile_version: Unsigned"`.
struct Unsigned(u64);

impl Type<Postgres> for Unsigned {
    /// Stored as `BIGINT`.
    fn type_info() -> PgTypeInfo {
        i64::type_info()
    }
}

impl Decode<'_, Postgres> for Unsigned {
    /// Rejects negative values.
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        Ok(Self(u64::try_from(i64::decode(value)?)?))
    }
}

impl From<Unsigned> for u64 {
    /// Unwraps the decoded value.
    fn from(Unsigned(value): Unsigned) -> Self {
        value
    }
}

/// Verified email ownership and primary-address persistence.
pub(crate) mod emails;
/// Typed domain events, personal data and the consumer cursor.
pub(crate) mod events;
/// Provider transactions, pending signups and external identity links.
pub(crate) mod federation;
/// Expired-state cleanup.
pub(crate) mod maintenance;
/// Client provisioning, authorization requests, codes and consent.
pub(crate) mod oidc;
/// Passkey credentials and single-use ceremony records.
pub(crate) mod passkeys;
/// Signup invitations and shared request budgets.
pub(crate) mod security;
/// Browser sessions, cookie digests and passkey confirmations.
pub(crate) mod sessions;
/// Focused tests for the column types shared by every repository.
#[cfg(test)]
mod tests;
/// Refresh-token grants, rotation and replay revocation.
pub(crate) mod tokens;
/// Account records and serialization locks.
pub(crate) mod users;
