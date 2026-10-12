use crate::DatabaseError;
use sqlx::{Postgres, Transaction};

/// A private-SQLx transaction with the same typed repository families as
/// [`Database`](crate::Database). Dropping it without committing rolls back.
#[must_use = "dropping a transaction rolls it back"]
pub struct DatabaseTransaction<'a> {
    pub(crate) inner: Transaction<'a, Postgres>,
}

impl<'a> DatabaseTransaction<'a> {
    pub(crate) const fn new(inner: Transaction<'a, Postgres>) -> Self {
        Self { inner }
    }

    /// Commits every change made through this transaction.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the commit fails, e.g. when a deferred
    /// constraint is violated.
    pub async fn commit(self) -> Result<(), DatabaseError> {
        self.inner.commit().await.map_err(Into::into)
    }

    /// Discards every change made through this transaction.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the rollback fails.
    pub async fn rollback(self) -> Result<(), DatabaseError> {
        self.inner.rollback().await.map_err(Into::into)
    }
}
