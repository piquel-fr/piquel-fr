//! Advisory locks that let one replica at a time run a job.

use crate::{Database, DatabaseError, DatabaseTransaction};
use sqlx::{Connection, PgConnection};

/// Session-level advisory lock keys, one per exclusive job. The values are stable
/// and never reused, so replicas running different releases agree on them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum LockKey {
    /// Expired-state cleanup.
    Cleanup = 1,
    /// Sealing the audit chain and signing its checkpoints.
    AuditChain = 2,
    /// Job runner tests in other crates; no release takes it.
    #[cfg(feature = "test-support")]
    Test = -1,
}

impl LockKey {
    /// The `bigint` key passed to `PostgreSQL`'s advisory lock functions.
    const fn id(self) -> i64 {
        self as i64
    }
}

/// A dedicated connection, outside the pool, holding one advisory lock. The lock
/// lasts as long as the connection: [`Self::release`] ends both, and so does
/// dropping it, e.g. when a job is cancelled or panics, or the process dies.
/// A lock holder therefore never returns to the pool.
#[must_use = "dropping the connection releases the lock"]
pub struct ExclusiveConnection {
    /// The `PostgreSQL` session holding the lock.
    pub(crate) connection: PgConnection,
    /// The lock it holds.
    key: LockKey,
}

impl Database {
    /// Opens a connection with the pool's settings and takes `key`'s lock. Returns
    /// `None`, closing the connection, when another session already holds it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Timeout`] if connecting takes longer than the
    /// pool's acquire timeout, or another [`DatabaseError`] if a query fails.
    pub async fn try_exclusive(
        &self,
        key: LockKey,
    ) -> Result<Option<ExclusiveConnection>, DatabaseError> {
        let mut connection = tokio::time::timeout(
            self.pool.options().get_acquire_timeout(),
            PgConnection::connect_with(&self.pool.connect_options()),
        )
        .await
        .map_err(DatabaseError::Timeout)??;
        let locked =
            sqlx::query_scalar!(r#"SELECT pg_try_advisory_lock($1) AS "locked!""#, key.id())
                .fetch_one(&mut connection)
                .await?;
        if locked {
            Ok(Some(ExclusiveConnection { connection, key }))
        } else {
            connection.close().await?;
            Ok(None)
        }
    }
}

impl ExclusiveConnection {
    /// Opens a transaction on the locked connection.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if `BEGIN` fails.
    pub async fn begin(&mut self) -> Result<DatabaseTransaction<'_>, DatabaseError> {
        self.connection
            .begin()
            .await
            .map(DatabaseTransaction::new)
            .map_err(Into::into)
    }

    /// Releases the lock, so another replica can take it as soon as this returns,
    /// then closes the connection.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if unlocking or closing fails. The connection is
    /// gone either way, which releases the lock.
    pub async fn release(mut self) -> Result<(), DatabaseError> {
        let unlocked = sqlx::query_scalar!("SELECT pg_advisory_unlock($1)", self.key.id())
            .fetch_one(&mut self.connection)
            .await;
        let closed = self.connection.close().await;
        unlocked?;
        Ok(closed?)
    }
}

/// Focused tests for lock exclusion and release.
#[cfg(test)]
mod tests;
