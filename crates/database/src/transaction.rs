//! Explicit commit/rollback over repository operations; drop rolls back unfinished work.

use crate::{
    DatabaseError,
    repositories::deliveries::{Channels, Registered},
    telemetry::Committed,
};
use piquel_common::{
    UserId,
    events::{Actor, DomainEvent, EventContext, HistoryActor},
};
use sqlx::{Postgres, Transaction};

/// A private-`SQLx` transaction with the same typed repository families as
/// [`Database`](crate::Database). Dropping it without committing rolls back.
#[must_use = "dropping a transaction rolls it back"]
pub struct DatabaseTransaction<'a> {
    /// Private `SQLx` transaction borrowed by generated repository accessors.
    pub(crate) inner: Transaction<'a, Postgres>,
    /// Events recorded so far, published to telemetry once the transaction commits.
    recorded: Vec<Committed>,
}

impl<'a> DatabaseTransaction<'a> {
    /// Wraps a begun `SQLx` transaction without exposing its connection.
    pub(crate) const fn new(inner: Transaction<'a, Postgres>) -> Self {
        Self {
            inner,
            recorded: Vec::new(),
        }
    }

    /// Records `event`, caused as `context` says and concerning the `subject`
    /// account, in this transaction, with the outbound deliveries it causes: they
    /// all commit or roll back with the change they describe. An operation that
    /// changes nothing, such as a failed sign-in, records its event in a
    /// transaction of its own. Once the transaction commits, each event is logged
    /// and counted in telemetry, with the current trace ID it is also stored with.
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
        let id = self.events().insert(context, subject, &event).await?;
        C::fan_out(self, id, subject, &event).await?;
        self.recorded.push(Committed {
            id,
            actor: HistoryActor::from(&context.actor),
            administrator: match context.actor {
                Actor::Admin { user_id, .. } => Some(user_id),
                _ => None,
            },
            subject,
            event,
        });
        Ok(())
    }

    /// Counts the other transactions waiting for a lock this one holds, directly
    /// or queued behind another such waiter, so tests can order concurrent work
    /// on what the database is doing rather than on sleeps.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    #[cfg(feature = "test-support")]
    pub async fn blocked_transactions(&mut self) -> Result<i64, DatabaseError> {
        sqlx::query_scalar!(
            // `pg_locks` is read afresh by every query; `pg_stat_activity` would
            // keep the backends this transaction saw first.
            // A waiter queued behind another waiter for the same row reports that
            // waiter as its blocker, so waiters are followed transitively.
            r#"WITH RECURSIVE waiting (pid) AS (
                SELECT pid FROM pg_locks
                WHERE NOT granted AND pg_backend_pid() = ANY(pg_blocking_pids(pid))
                UNION
                SELECT l.pid FROM pg_locks l, waiting w
                WHERE NOT l.granted AND w.pid = ANY(pg_blocking_pids(l.pid))
            )
            SELECT count(*) AS "count!" FROM waiting"#
        )
        .fetch_one(&mut *self.inner)
        .await
        .map_err(Into::into)
    }

    /// Commits every change made through this transaction, then publishes the
    /// events it recorded.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the commit fails, e.g. when a deferred
    /// constraint is violated.
    pub async fn commit(self) -> Result<(), DatabaseError> {
        self.inner.commit().await?;
        for committed in &self.recorded {
            committed.publish();
        }
        Ok(())
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
