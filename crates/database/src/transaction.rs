//! Explicit commit/rollback over repository operations; drop rolls back unfinished work.

use crate::{
    DatabaseError,
    repositories::deliveries::{Channels, Registered},
};
use piquel_common::{
    UserId,
    events::{DomainEvent, EventContext},
};
use sqlx::{Postgres, Transaction};

/// A private-`SQLx` transaction with the same typed repository families as
/// [`Database`](crate::Database). Dropping it without committing rolls back.
#[must_use = "dropping a transaction rolls it back"]
pub struct DatabaseTransaction<'a> {
    /// Private `SQLx` transaction borrowed by generated repository accessors.
    pub(crate) inner: Transaction<'a, Postgres>,
}

impl<'a> DatabaseTransaction<'a> {
    /// Wraps a begun `SQLx` transaction without exposing its connection.
    pub(crate) const fn new(inner: Transaction<'a, Postgres>) -> Self {
        Self { inner }
    }

    /// Records `event`, caused as `context` says and concerning the `subject`
    /// account, in this transaction, with the outbound deliveries it causes: they
    /// all commit or roll back with the change they describe. An operation that
    /// changes nothing, such as a failed sign-in, records its event in a
    /// transaction of its own.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the event or a delivery cannot be serialized or
    /// written.
    pub async fn record(
        &mut self,
        context: &EventContext,
        subject: Option<UserId>,
        event: DomainEvent,
    ) -> Result<(), DatabaseError> {
        self.record_to::<Registered>(context, subject, event).await
    }

    /// [`Self::record`], fanning out to the channels `C`, which tests replace.
    pub(crate) async fn record_to<C: Channels>(
        &mut self,
        context: &EventContext,
        subject: Option<UserId>,
        event: DomainEvent,
    ) -> Result<(), DatabaseError> {
        let event_id = self.events().insert(context, subject, &event).await?;
        C::fan_out(self, event_id, subject, &event).await
    }

    /// Counts the other transactions waiting for a lock this one holds, so tests
    /// can order concurrent work on what the database is doing rather than on
    /// sleeps.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    #[cfg(feature = "test-support")]
    pub async fn blocked_transactions(&mut self) -> Result<i64, DatabaseError> {
        sqlx::query_scalar!(
            // `pg_locks` is read afresh by every query; `pg_stat_activity` would
            // keep the backends this transaction saw first.
            r#"SELECT count(DISTINCT pid) AS "count!"
            FROM pg_locks
            WHERE NOT granted
            AND pg_backend_pid() = ANY(pg_blocking_pids(pid))"#
        )
        .fetch_one(&mut *self.inner)
        .await
        .map_err(Into::into)
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
