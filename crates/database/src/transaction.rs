//! Explicit commit/rollback over repository operations; drop rolls back unfinished work.

use crate::{
    DatabaseError, Limit, Scope,
    repositories::{
        deliveries::{Channels, Registered},
        notifications::Notified,
    },
    telemetry::Committed,
};
use sourceorigin_common::{
    EventId, UserId,
    events::{Actor, DomainEvent, EventContext, HistoryActor},
    notifications::{Audience, Notification},
};
use sqlx::{Postgres, Transaction};
use std::time::Duration;

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

    /// Lets this transaction sit idle for up to `limit` between statements, until
    /// it ends, rather than the default 30 seconds: for a reader that waits on
    /// something else between reads, as a data export waits on its download.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if setting the limit fails.
    pub async fn allow_idle(&mut self, limit: Duration) -> Result<(), DatabaseError> {
        Limit::IDLE_IN_TRANSACTION
            .at(limit)
            .set(Scope::Transaction)
            .fetch_one(&mut *self.inner)
            .await?;
        Ok(())
    }

    /// Records `event`, caused as `context` says and concerning the `subject`
    /// account, in this transaction, with the notification it gives the subject
    /// ([`DomainEvent::notification`]) and the outbound deliveries it causes: they
    /// all commit or roll back with the change they describe. An operation that
    /// changes nothing, such as a failed sign-in, records its event in a
    /// transaction of its own. Once the transaction commits, each event is logged
    /// and counted in telemetry, with the current trace ID it is also stored with.
    /// Returns the event's ID, for a row that refers to it.
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
    ) -> Result<EventId, DatabaseError> {
        self.record_to::<Registered>(context, subject, event).await
    }

    /// Records that `context`'s administrator or operator sent the account
    /// `user_id` a message, [`DomainEvent::MessageSent`], as [`Self::record`]
    /// does, and gives the account the message, `title` and `text`, as a
    /// notification, emailed as every other. The event, which the audit chain
    /// keeps, holds no text: the notification and its queued email hold the
    /// message's only copies, which purging the account deletes.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the event, the notification or a delivery
    /// cannot be written.
    pub async fn record_message(
        &mut self,
        context: &EventContext,
        user_id: UserId,
        title: String,
        text: String,
    ) -> Result<EventId, DatabaseError> {
        let message = Notification::Message { title, text };
        self.write::<Registered>(
            context,
            Some(user_id),
            DomainEvent::MessageSent {},
            Some(message),
        )
        .await
    }

    /// [`Self::record`], fanning out to the channels `C`, which tests replace.
    pub(crate) async fn record_to<C: Channels>(
        &mut self,
        context: &EventContext,
        subject: Option<UserId>,
        event: DomainEvent,
    ) -> Result<EventId, DatabaseError> {
        let notification = event.notification(&context.actor);
        self.write::<C>(context, subject, event, notification).await
    }

    /// Records `event`, giving its audience `notification`, and fans both out to
    /// the channels `C`.
    async fn write<C: Channels>(
        &mut self,
        context: &EventContext,
        subject: Option<UserId>,
        event: DomainEvent,
        notification: Option<Notification>,
    ) -> Result<EventId, DatabaseError> {
        let id = self.events().insert(context, subject, &event).await?;
        let notified = match notification {
            Some(notification) => self.notify(id, subject, notification).await?,
            None => Vec::new(),
        };
        C::fan_out(self, id, subject, &event, &notified).await?;
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
        Ok(id)
    }

    /// Writes `notification`, from the event `event_id` about `subject`, to the
    /// inbox of each account of its audience, and returns what it wrote.
    async fn notify(
        &mut self,
        event_id: EventId,
        subject: Option<UserId>,
        notification: Notification,
    ) -> Result<Vec<Notified>, DatabaseError> {
        let accounts = match notification.audience() {
            Audience::Subject => subject.into_iter().collect(),
            Audience::Administrators => self.administrators().active().await?,
        };
        let mut notified = Vec::new();
        for user_id in accounts {
            let written = self
                .notifications()
                .insert(user_id, Some(event_id), &notification)
                .await?;
            if let Some(id) = written {
                notified.push(Notified {
                    user_id,
                    id,
                    notification: notification.clone(),
                });
            }
        }
        Ok(notified)
    }

    /// Counts the other transactions waiting for a lock this one holds, directly
    /// or queued behind another such waiter, so tests can order concurrent work
    /// on what the database is doing rather than on sleeps.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    #[cfg(any(test, feature = "test-util"))]
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
