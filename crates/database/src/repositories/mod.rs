//! Domain repository handles backed by a private pool or transaction connection.
//!
//! This module holds only what every repository shares: the executor, the
//! declaration macro, query macros and typed row decoding. Each submodule owns
//! one repository together with the records it accepts and returns.

use crate::{Database, DatabaseError, DatabaseTransaction};
use piquel_auth_protocol::{InvalidValue, SessionId, TokenId, UserId};
use sqlx::{Decode, PgConnection, PgPool, Postgres, Row, Type, postgres::PgRow, types::Json};
use uuid::Uuid;

/// Where a repository runs its queries: directly on the pool, or on the
/// connection of an open transaction.
pub(crate) enum RepositoryExecutor<'a> {
    Pool(&'a PgPool),
    Connection(&'a mut PgConnection),
}

/// Declares each repository handle and its accessor on both [`Database`] and
/// [`DatabaseTransaction`], so the two always expose the same families.
macro_rules! repositories {
    ($($(#[doc = $doc:literal])* $accessor:ident: $name:ident;)*) => {
        $(
            $(#[doc = $doc])*
            ///
            /// A focused persistence handle: it has no policy and no public SQL escape hatch.
            #[must_use]
            pub struct $name<'a> {
                executor: RepositoryExecutor<'a>,
            }

            impl<'a> $name<'a> {
                pub(crate) const fn from_pool(pool: &'a PgPool) -> Self {
                    Self { executor: RepositoryExecutor::Pool(pool) }
                }

                pub(crate) fn from_connection(connection: &'a mut PgConnection) -> Self {
                    Self { executor: RepositoryExecutor::Connection(connection) }
                }
            }
        )*

        impl Database {
            $(
                #[doc = concat!("Returns a [`", stringify!($name), "`] that runs each query on the pool.")]
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
    };
}

repositories! {
    /// User accounts.
    users: UserRepository;
    /// Verified email addresses and their cross-account ownership.
    emails: EmailRepository;
    /// Browser sessions, their cookie digests and management windows.
    sessions: SessionRepository;
    /// The append-only security audit log.
    audit_events: AuditEventRepository;
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
}

/// Runs `$query.$method(executor)` on the repository's executor and converts the
/// driver error into a [`DatabaseError`].
macro_rules! run {
    ($self:expr, $method:ident, $query:expr) => {{
        match &mut $self.executor {
            RepositoryExecutor::Pool(pool) => $query.$method(*pool).await,
            RepositoryExecutor::Connection(connection) => $query.$method(&mut **connection).await,
        }
        .map_err(Into::<DatabaseError>::into)
    }};
}
macro_rules! fetch_optional {
    ($self:expr, $query:expr) => {
        run!($self, fetch_optional, $query)
    };
}
macro_rules! fetch_one {
    ($self:expr, $query:expr) => {
        run!($self, fetch_one, $query)
    };
}
macro_rules! fetch_all {
    ($self:expr, $query:expr) => {
        run!($self, fetch_all, $query)
    };
}
macro_rules! execute {
    ($self:expr, $query:expr) => {
        run!($self, execute, $query)
    };
}

/// A protocol identifier stored in a `UUID` column. `Option<Id>` decodes a
/// nullable column.
trait StoredId: Sized {
    /// The column's SQL representation.
    type Raw: for<'r> Decode<'r, Postgres> + Type<Postgres>;

    /// Validates the stored value.
    fn from_raw(raw: Self::Raw) -> Result<Self, InvalidValue>;
}

macro_rules! stored_ids {
    ($($id:ty),*) => {$(
        impl StoredId for $id {
            type Raw = Uuid;

            fn from_raw(raw: Uuid) -> Result<Self, InvalidValue> {
                Self::from_uuid(raw)
            }
        }
    )*};
}
stored_ids!(UserId, SessionId, TokenId);

impl<I: StoredId<Raw = Uuid>> StoredId for Option<I> {
    type Raw = Option<Uuid>;

    fn from_raw(raw: Option<Uuid>) -> Result<Self, InvalidValue> {
        raw.map(I::from_raw).transpose()
    }
}

/// Typed column access that reports malformed rows as
/// [`DatabaseError::InvalidStoredData`] naming the column.
trait StoredRow {
    /// Decodes a column into its SQL-compatible Rust type.
    fn column<'r, T>(&'r self, column: &'static str) -> Result<T, DatabaseError>
    where
        T: Decode<'r, Postgres> + Type<Postgres>;

    /// Decodes a JSONB column.
    fn json<'r, T>(&'r self, column: &'static str) -> Result<T, DatabaseError>
    where
        Json<T>: Decode<'r, Postgres>,
    {
        self.column::<Json<T>>(column).map(|Json(value)| value)
    }

    /// Decodes and validates an identifier column.
    fn id<I: StoredId>(&self, column: &'static str) -> Result<I, DatabaseError> {
        I::from_raw(self.column(column)?)
            .map_err(|error| DatabaseError::invalid_stored(column, error))
    }
}

impl StoredRow for PgRow {
    fn column<'r, T>(&'r self, column: &'static str) -> Result<T, DatabaseError>
    where
        T: Decode<'r, Postgres> + Type<Postgres>,
    {
        self.try_get(column)
            .map_err(|error| DatabaseError::invalid_stored(column, error))
    }
}

pub(crate) mod audit;
pub(crate) mod emails;
pub(crate) mod federation;
pub(crate) mod oidc;
pub(crate) mod passkeys;
pub(crate) mod security;
pub(crate) mod sessions;
pub(crate) mod tokens;
pub(crate) mod users;

/// Connects to `TEST_DATABASE_URL` and applies the schema for database tests.
#[cfg(test)]
async fn test_pool() -> PgPool {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL"))
        .await
        .expect("connect");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrate");
    pool
}
