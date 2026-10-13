//! Domain repository handles backed by a private pool or transaction connection.
//!
//! This module holds only what every repository shares: the executor, the
//! declaration macro, the `run!` query macro and typed row decoding. Each submodule owns
//! one repository together with the records it accepts and returns.

use crate::{Database, DatabaseError, DatabaseTransaction};
use piquel_auth_protocol::{InvalidValue, SessionId, TokenId, UserId};
use sqlx::{Decode, PgConnection, PgPool, Postgres, Row, Type, postgres::PgRow, types::Json};
use uuid::Uuid;

/// Where a repository runs its queries: directly on the pool, or on the
/// connection of an open transaction.
pub(crate) enum RepositoryExecutor<'a> {
    /// Each operation borrows a connection from the shared pool.
    Pool(&'a PgPool),
    /// Every operation participates in one caller-owned transaction.
    Connection(&'a mut PgConnection),
}

/// Declares each repository handle and its accessor on both [`Database`] and
/// [`DatabaseTransaction`], so the two always expose the same families. Each entry
/// reads `/// Doc comment` then `accessor: HandleName;`.
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

/// Runs a query on the repository's pool or transaction connection and converts
/// the driver error into a [`DatabaseError`], e.g.
/// `run!(self, fetch_optional, sqlx::query("...").bind(id))`.
///
/// `$method` is the `sqlx` executor method: `execute`, `fetch_one` (a missing row
/// becomes [`DatabaseError::NotFound`]), `fetch_optional` or `fetch_all`. A macro
/// rather than a method because `&PgPool` and `&mut PgConnection` are different
/// executor types.
macro_rules! run {
    ($self:expr, $method:ident, $query:expr) => {{
        match &mut $self.executor {
            RepositoryExecutor::Pool(pool) => $query.$method(*pool).await,
            RepositoryExecutor::Connection(connection) => $query.$method(&mut **connection).await,
        }
        .map_err(Into::<DatabaseError>::into)
    }};
}

/// A protocol identifier stored in a `UUID` column. `Option<Id>` decodes a
/// nullable column.
trait StoredId: Sized {
    /// The column's SQL representation.
    type Raw: for<'r> Decode<'r, Postgres> + Type<Postgres>;

    /// Validates the stored value.
    fn from_raw(raw: Self::Raw) -> Result<Self, InvalidValue>;
}

/// Implements UUID decoding for every protocol ID without repeating validation.
macro_rules! stored_ids {
    ($($id:ty),*) => {$(
        impl StoredId for $id {
            type Raw = Uuid;
            /// Validates the decoded storage representation before constructing a protocol
            /// identifier.
            fn from_raw(raw: Uuid) -> Result<Self, InvalidValue> {
                Self::from_uuid(raw)
            }
        }
    )*};
}
stored_ids!(UserId, SessionId, TokenId);

impl<I: StoredId<Raw = Uuid>> StoredId for Option<I> {
    type Raw = Option<Uuid>;
    /// Validates the decoded storage representation before constructing a protocol
    /// identifier.
    fn from_raw(raw: Option<Uuid>) -> Result<Self, InvalidValue> {
        raw.map(I::from_raw).transpose()
    }
}

/// Typed column access that reports malformed rows as
/// [`DatabaseError::InvalidStoredData`] naming the column.
trait StoredRow {
    /// Parses a closed vocabulary stored in a text column.
    fn vocabulary<T: std::str::FromStr<Err = piquel_common::VocabularyError>>(
        &self,
        column: &'static str,
    ) -> Result<T, DatabaseError> {
        self.column::<String>(column)?
            .parse()
            .map_err(|source| DatabaseError::invalid_stored(column, source))
    }

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
    /// Decodes a column and retains both its name and the original driver diagnostic.
    fn column<'r, T>(&'r self, column: &'static str) -> Result<T, DatabaseError>
    where
        T: Decode<'r, Postgres> + Type<Postgres>,
    {
        self.try_get(column)
            .map_err(|error| DatabaseError::invalid_stored(column, error))
    }
}

/// Append-only security history with typed actions and outcomes.
pub(crate) mod audit;
/// Verified email ownership and primary-address persistence.
pub(crate) mod emails;
/// Provider transactions, pending signups and external identity links.
pub(crate) mod federation;
/// Client provisioning, authorization requests, codes and consent.
pub(crate) mod oidc;
/// Passkey credentials and single-use ceremony records.
pub(crate) mod passkeys;
/// Signup invitations and shared request budgets.
pub(crate) mod security;
/// Browser sessions, cookie digests and management windows.
pub(crate) mod sessions;
/// Refresh-token grants, rotation and replay revocation.
pub(crate) mod tokens;
/// Account records and serialization locks.
pub(crate) mod users;
