//! Typed persistence and startup failures, retaining driver causes.

use sourceorigin_common::ErrorChain;
use std::{error::Error as StdError, fmt};
use thiserror::Error;

/// A boxed underlying error kept as the source for diagnostics.
type Source = Box<dyn StdError + Send + Sync>;

/// SQLSTATE of a cancelled statement: past its statement timeout, or cancelled by
/// an operator.
const QUERY_CANCELED: &str = "57014";
/// SQLSTATE of a lock not granted within the lock timeout.
const LOCK_NOT_AVAILABLE: &str = "55P03";

/// Stable, non-SQL database failure categories. Its `Debug` is its error chain,
/// so it is safe to log either way (see the `Debug` impl).
#[derive(Error)]
pub enum DatabaseError {
    /// No row matched, or a single-use record is missing, expired or consumed.
    #[error("the requested record was not found")]
    NotFound,
    /// A uniqueness constraint rejected the write; its driver diagnostic is retained.
    #[error("the operation conflicts with existing data")]
    Conflict(#[source] Source),
    /// A check constraint or trigger refused the write, such as the one keeping
    /// an account at 100 active passkeys; its driver diagnostic is retained.
    #[error("a database check refused the write")]
    Refused(#[source] Source),
    /// The database did not answer within the bounded wait.
    #[error("the database operation timed out")]
    Timeout(#[source] tokio::time::error::Elapsed),
    /// `PostgreSQL` cancelled the statement, which ran past its statement timeout
    /// (see `docs/dev/architecture/database.md`) or was cancelled by an operator.
    #[error("the database cancelled a statement that ran too long")]
    Cancelled(#[source] Source),
    /// A statement waited for a lock past its lock timeout.
    #[error("a database lock was not granted in time")]
    LockUnavailable(#[source] Source),
    /// A stored column could not be decoded into its typed value, e.g. an ID
    /// that is not `UUIDv7` or JSON that does not match its record.
    #[error("stored column {column} is invalid")]
    InvalidStoredData {
        /// The column that failed to decode, as `SQLx` reports it: its index in
        /// the query's result row.
        column: String,
        /// Why decoding failed, without the value.
        #[source]
        source: DecodeFailure,
    },
    /// Any other driver, query, migration or event serialization failure.
    #[error("database operation failed")]
    Operation(#[source] Source),
}

/// Why a stored value did not decode, without the value: a decoder's message can
/// quote it, as `serde_json`'s `invalid type: string "alice@example.com"` does.
/// Only `serde_json`'s category and position are kept; query the column to see
/// the value itself. Boxed, so [`DatabaseError`] stays small.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct DecodeFailure(Box<Decode>);

/// What [`DecodeFailure`] keeps.
#[derive(Debug, Error)]
enum Decode {
    /// A JSON column that does not parse, or does not match its type.
    #[error("{category} at line {line} column {column}")]
    Json {
        /// What went wrong, such as a missing field or a wrong type.
        category: &'static str,
        /// Where, in the column's JSON.
        line: usize,
        /// Where, on that line.
        column: usize,
    },
    /// A value that decodes but breaks a rule, such as an alert update whose
    /// author is neither an administrator nor an operator. The rule is a
    /// `&'static str`, so it cannot quote the value.
    #[error("{0}")]
    Rule(&'static str),
    /// Any other decoder's failure.
    #[error("the stored value does not decode")]
    Other,
}

impl From<&'static str> for DecodeFailure {
    /// The rule the value breaks.
    fn from(rule: &'static str) -> Self {
        Self(Box::new(Decode::Rule(rule)))
    }
}

impl From<serde_json::Error> for DecodeFailure {
    /// Keeps the category and position, dropping the message.
    fn from(error: serde_json::Error) -> Self {
        let category = match error.classify() {
            serde_json::error::Category::Io => "JSON I/O error",
            serde_json::error::Category::Syntax => "JSON syntax error",
            serde_json::error::Category::Data => "JSON that does not match its type",
            serde_json::error::Category::Eof => "JSON that ends early",
        };
        Self(Box::new(Decode::Json {
            category,
            line: error.line(),
            column: error.column(),
        }))
    }
}

impl From<Source> for DecodeFailure {
    /// Keeps what a `serde_json` error would, and nothing of any other error.
    fn from(error: Source) -> Self {
        error.downcast::<serde_json::Error>().map_or_else(
            |_| Self(Box::new(Decode::Other)),
            |error| Self::from(*error),
        )
    }
}

impl fmt::Debug for DatabaseError {
    /// Writes the error chain, as `Display` through [`ErrorChain`] would. The
    /// driver's own `Debug` would add `PostgreSQL`'s diagnostic fields, whose
    /// `detail` quotes the rejected values, e.g. `Key (address)=(…) already
    /// exists`: an address in a log line. Only the messages remain, which name a
    /// constraint but no value. Every error wrapping this one, and every `?error`
    /// log field holding it, is then safe too.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", ErrorChain(self))
    }
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
    /// A role the database provisions must have a name no SQL needs to quote.
    #[error(
        "database runtime user must be at most 63 lowercase letters, digits and underscores, \
         not starting with a digit"
    )]
    RoleName,
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
                source: source.into(),
            },
            sqlx::Error::Database(error) if error.is_unique_violation() => {
                Self::Conflict(Box::new(sqlx::Error::Database(error)))
            }
            sqlx::Error::Database(error) if error.is_check_violation() => {
                Self::Refused(Box::new(sqlx::Error::Database(error)))
            }
            sqlx::Error::Database(error) if error.code().as_deref() == Some(QUERY_CANCELED) => {
                Self::Cancelled(Box::new(sqlx::Error::Database(error)))
            }
            sqlx::Error::Database(error) if error.code().as_deref() == Some(LOCK_NOT_AVAILABLE) => {
                Self::LockUnavailable(Box::new(sqlx::Error::Database(error)))
            }
            error => Self::Operation(Box::new(error)),
        }
    }
}

#[cfg(test)]
mod tests;
