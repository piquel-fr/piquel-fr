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
}

/// Errors that can occur while constructing the database boundary.
#[derive(Debug, Error)]
pub enum DatabaseConnectionError {
    #[error("database configuration is invalid")]
    InvalidConfiguration,
    #[error("database connection is unavailable")]
    Unavailable,
}

<<<<<<< HEAD
pub(crate) fn map_error(error: sqlx::Error) -> DatabaseError {
    match error {
        sqlx::Error::RowNotFound => DatabaseError::NotFound,
        sqlx::Error::PoolTimedOut => DatabaseError::Timeout,
        sqlx::Error::PoolClosed | sqlx::Error::Io(_) | sqlx::Error::Tls(_) => {
            DatabaseError::Unavailable
        }
        sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
            DatabaseError::Conflict
        }
        _ => DatabaseError::Internal,
=======
impl From<sqlx::Error> for DatabaseError {
    fn from(value: sqlx::Error) -> Self {
        match value {
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::PoolTimedOut => Self::Timeout,
            sqlx::Error::PoolClosed | sqlx::Error::Io(_) | sqlx::Error::Tls(_) => Self::Unavailable,
            sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
                Self::Conflict
            }
            _ => Self::Internal,
        }
>>>>>>> main
    }
}
