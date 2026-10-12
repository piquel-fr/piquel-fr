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
    /// A uniqueness constraint or input validation rejected the write.
    #[error("the operation conflicts with existing data")]
    Conflict,
    /// The database did not answer within the bounded wait.
    #[error("the database operation timed out")]
    Timeout,
    /// A stored column could not be decoded into its typed value.
    #[error("stored column `{column}` is invalid")]
    InvalidStoredData {
        /// The column that failed to decode.
        column: &'static str,
        /// Why decoding failed.
        #[source]
        source: Source,
    },
    /// Any other driver, query or migration failure.
    #[error("database operation failed")]
    Operation(#[source] Source),
}

impl DatabaseError {
    /// Reports that `column` holds a value its Rust type rejects.
    pub(crate) fn invalid_stored(column: &'static str, source: impl Into<Source>) -> Self {
        Self::InvalidStoredData {
            column,
            source: source.into(),
        }
    }
}

/// Errors that can occur while constructing the database boundary.
#[derive(Debug, Error)]
pub enum DatabaseConnectionError {
    /// The URL or pool settings are invalid or insecure.
    #[error("database configuration is invalid")]
    InvalidConfiguration,
    /// The pool could not connect.
    #[error("database connection failed")]
    Connection(#[source] Source),
}

impl From<sqlx::Error> for DatabaseError {
    fn from(value: sqlx::Error) -> Self {
        match value {
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
                Self::Conflict
            }
            error => Self::Operation(Box::new(error)),
        }
    }
}
