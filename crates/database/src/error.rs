//! Typed persistence and startup failures, retaining driver causes.

use std::error::Error as StdError;
use thiserror::Error;

/// A boxed underlying error kept as the source for diagnostics.
type Source = Box<dyn StdError + Send + Sync>;

/// Stable, non-SQL database failure categories.
#[derive(Debug, Error)]
pub enum DatabaseError {
    /// No row matched, or a single-use record is missing, expired or consumed.
    #[error("the requested record was not found")]
    NotFound,
    /// A uniqueness constraint rejected the write; its driver diagnostic is retained.
    #[error("the operation conflicts with existing data")]
    Conflict(#[source] Source),
    /// The database did not answer within the bounded wait.
    #[error("the database operation timed out")]
    Timeout(#[source] tokio::time::error::Elapsed),
    /// A stored column could not be decoded into its typed value, e.g. an ID
    /// that is not `UUIDv7` or JSON that does not match its record.
    #[error("stored column {column} is invalid")]
    InvalidStoredData {
        /// The column that failed to decode, as `SQLx` reports it: its index in
        /// the query's result row.
        column: String,
        /// Why decoding failed.
        #[source]
        source: Source,
    },
    /// Any other driver, query or migration failure.
    #[error("database operation failed")]
    Operation(#[source] Source),
}

/// Errors that can occur while constructing the database boundary.
#[derive(Debug, Error)]
pub enum DatabaseConnectionError {
    /// The supplied URL could not be parsed.
    #[error("database URL must be an absolute postgres:// or postgresql:// URL")]
    Url(#[from] url::ParseError),
    /// The URL uses a non-`PostgreSQL` scheme.
    #[error("database URL must use postgres:// or postgresql://")]
    Scheme,
    /// A zero-size pool or zero acquire timeout could never serve a request.
    #[error("database maximum connections and connection timeout must be greater than zero")]
    ZeroPoolBound,
    /// A TCP hostname or localhost for a Unix socket is required.
    #[error(
        "database URL must include a host; use localhost with \
         host=/absolute/socket/path for Unix sockets"
    )]
    MissingHost,
    /// Repeated TLS or socket settings, or a `hostaddr` override, would make the
    /// effective transport depend on parser order instead of the validated URL.
    #[error(
        "database URL must contain at most one sslmode (or ssl-mode) and one host parameter, \
         and no hostaddr"
    )]
    AmbiguousTransport,
    /// The socket is not an absolute local path or overrides a remote host.
    #[error(
        "database host parameter must be an absolute Unix socket path without NUL bytes, \
         with localhost as the URL host"
    )]
    InvalidSocket,
    /// TCP requires authenticated TLS or an explicit plaintext choice.
    #[error("database TCP transport requires sslmode=verify-full or explicit sslmode=disable")]
    InsecureTransport,
    /// `SQLx` rejected otherwise validated connection options.
    #[error("database connection options could not be parsed")]
    Options(#[source] Source),
    /// The pool could not connect.
    #[error("database connection failed")]
    Connection(#[source] Source),
}

impl From<sqlx::Error> for DatabaseError {
    /// Converts the domain failure at its boundary while retaining internal error sources.
    fn from(value: sqlx::Error) -> Self {
        match value {
            // RowNotFound has no diagnostic fields beyond the semantic category.
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::ColumnDecode { index, source } => Self::InvalidStoredData {
                column: index,
                source,
            },
            sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
                Self::Conflict(Box::new(sqlx::Error::Database(database_error)))
            }
            error => Self::Operation(Box::new(error)),
        }
    }
}
