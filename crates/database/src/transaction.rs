//! Explicit commit/rollback over repository operations; drop rolls back unfinished work.

use crate::{DatabaseError, DomainEvent, EventContext};
use piquel_auth_protocol::UserId;
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
    /// account, in this transaction: it commits or rolls back with the change it
    /// describes. An operation that changes nothing, such as a failed sign-in,
    /// records its event in a transaction of its own.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the event cannot be serialized or written.
    pub async fn record(
        &mut self,
        context: &EventContext,
        subject: Option<UserId>,
        event: DomainEvent,
    ) -> Result<(), DatabaseError> {
        self.events().insert(context, subject, &event).await
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
