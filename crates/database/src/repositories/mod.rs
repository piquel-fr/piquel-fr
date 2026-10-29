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
    /// Current, released and retired handles.
    handles: HandleRepository;
    /// Verified email addresses and their cross-account ownership.
    emails: EmailRepository;
    /// Browser sessions, their cookie digests and passkey confirmations.
    sessions: SessionRepository;
    /// Typed domain events, their personal data and consumer cursors.
    events: EventRepository;
    /// The audit chain over sealed events, its checkpoints and anchor.
    audit: AuditRepository;
    /// Outbound deliveries, their leases and ordering.
    deliveries: DeliveryRepository;
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
    /// Deletion of expired ephemeral state, and counts of what is left of it.
    maintenance: MaintenanceRepository;
    /// Administrator rights.
    administrators: AdministratorRepository;
    /// Account recoveries and their links.
    recoveries: RecoveryRepository;
    /// Sign-ins to the admin dashboard: handoff codes and dashboard sessions.
    dashboard: DashboardRepository;
    /// Signing keys and their lifecycle.
    signing_keys: SigningKeyRepository;
    /// Accounts scheduled for deletion, and their purge.
    deletions: AccountDeletionRepository;
}

/// Runs a checked query on the repository's pool or transaction connection, in a
/// [`RepositoryExecutor::span`], and converts the driver error into a
/// [`DatabaseError`](crate::DatabaseError), e.g.
/// `run!(self, fetch_optional, sqlx::query_as!(StoredUser, "...", id.as_uuid()))`.
///
/// `$method` is the `sqlx` executor method: `execute`, `fetch_one` (a missing row
/// becomes [`DatabaseError::NotFound`](crate::DatabaseError::NotFound)), `fetch_optional` or `fetch_all`. A macro
/// rather than a method because `&PgPool` and `&mut PgConnection` are different
/// executor types.
macro_rules! run {
    ($self:expr, $method:ident, $query:expr) => {{
        let query = $query;
        let span = RepositoryExecutor::span(sqlx::Execute::sql(&query));
        let result = tracing::Instrument::instrument(
            async {
                match &mut $self.executor {
                    RepositoryExecutor::Pool(pool) => query.$method(*pool).await,
                    RepositoryExecutor::Connection(connection) => {
                        query.$method(&mut **connection).await
                    }
                }
            },
            span.clone(),
        )
        .await
        .map_err(Into::<DatabaseError>::into);
        RepositoryExecutor::finish(&span, result)
    }};
}

impl RepositoryExecutor<'_> {
    /// A client span for one query, recording its parameterized `sql` as
    /// `db.query.text`, never its bind values. A query outside any trace, such as an
    /// idle delivery worker's poll, gets none: each would be a trace of its own.
    fn span(sql: &str) -> tracing::Span {
        if tracing::Span::current().is_none() {
            return tracing::Span::none();
        }
        let operation = sql.split_whitespace().next().unwrap_or("query");
        tracing::info_span!(
            "db.query",
            otel.name = operation,
            otel.kind = "client",
            otel.status_code = tracing::field::Empty,
            db.system.name = "postgresql",
            db.query.text = sql,
        )
    }

    /// Marks `span` failed when the query failed for a reason other than a
    /// missing row or a conflict, which callers expect.
    fn finish<T>(
        span: &tracing::Span,
        result: Result<T, crate::DatabaseError>,
    ) -> Result<T, crate::DatabaseError> {
        if let Err(
            crate::DatabaseError::Timeout(_)
            | crate::DatabaseError::InvalidStoredData { .. }
            | crate::DatabaseError::Operation(_),
        ) = &result
        {
            span.record("otel.status_code", "ERROR");
        }
        result
    }
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
#[derive(Debug)]
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

impl Unsigned {
    /// Converts a value for a `BIGINT` bind.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Operation`](crate::DatabaseError::Operation) for a
    /// value above `i64::MAX`, which no stored value reaches.
    fn bind(value: u64) -> Result<i64, crate::DatabaseError> {
        i64::try_from(value).map_err(|error| crate::DatabaseError::Operation(Box::new(error)))
    }
}

impl From<Unsigned> for u64 {
    /// Unwraps the decoded value.
    fn from(Unsigned(value): Unsigned) -> Self {
        value
    }
}

/// A `BYTEA` column holding exactly 32 bytes, such as a SHA-256 hash, decoded
/// into a `[u8; 32]` field, e.g. `head AS "head: Bytes32"`.
#[derive(Debug)]
struct Bytes32([u8; 32]);

impl Type<Postgres> for Bytes32 {
    /// Stored as `BYTEA`.
    fn type_info() -> PgTypeInfo {
        Vec::<u8>::type_info()
    }
}

impl Decode<'_, Postgres> for Bytes32 {
    /// Rejects any other length.
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        let bytes = <&[u8]>::decode(value)?;
        Ok(Self(bytes.try_into()?))
    }
}

impl From<Bytes32> for [u8; 32] {
    /// Unwraps the decoded bytes.
    fn from(Bytes32(value): Bytes32) -> Self {
        value
    }
}

/// Administrator rights and the lock that serializes their changes.
pub(crate) mod administrators;
/// The audit chain, its checkpoints and its anchor.
pub(crate) mod audit;
/// Handoff codes and dashboard sessions.
pub(crate) mod dashboard;
/// Accounts scheduled for deletion, restore tokens and the purge.
pub(crate) mod deletions;
/// The outbound delivery queue.
pub(crate) mod deliveries;
/// Verified email ownership and primary-address persistence.
pub(crate) mod emails;
/// Typed domain events, personal data and the consumer cursor.
pub(crate) mod events;
/// Provider transactions, pending signups and external identity links.
pub(crate) mod federation;
/// Every handle, current or released, and the rename that moves between them.
pub(crate) mod handles;
/// Expired-state cleanup.
pub(crate) mod maintenance;
/// Client registrations, authorization requests, codes and consent.
pub(crate) mod oidc;
/// Passkey credentials and single-use ceremony records.
pub(crate) mod passkeys;
/// Account recoveries and their links.
pub(crate) mod recoveries;
/// Signup invitations and shared request budgets.
pub(crate) mod security;
/// Browser sessions, cookie digests and passkey confirmations.
pub(crate) mod sessions;
/// Signing keys, their lifecycle and its lock.
pub(crate) mod signing_keys;
/// Focused tests for the column types shared by every repository.
#[cfg(test)]
mod tests;
/// Refresh-token grants, rotation and replay revocation.
pub(crate) mod tokens;
/// Account records and serialization locks.
pub(crate) mod users;
