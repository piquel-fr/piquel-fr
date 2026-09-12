use thiserror::Error;

/// Stable, non-SQL database failure categories.
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("the requested record was not found")]
    NotFound,
    #[error("the operation conflicts with existing data")]
    Conflict,
    #[error("the database operation timed out")]
    Timeout,
    #[error("the database is unavailable")]
    Unavailable,
    #[error("stored database data is invalid")]
    InvalidStoredData,
    #[error("the transaction could not be completed")]
    TransactionFailed,
    #[error("an unexpected database error occurred")]
    Internal,
    #[error("database operation failed")]
    Operation(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors that can occur while constructing the database boundary.
#[derive(Debug, Error)]
pub enum DatabaseConnectionError {
    #[error("database configuration is invalid")]
    InvalidConfiguration,
    #[error("database connection is unavailable")]
    Unavailable,
    #[error("database connection failed")]
    Connection(#[source] Box<dyn std::error::Error + Send + Sync>),
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
