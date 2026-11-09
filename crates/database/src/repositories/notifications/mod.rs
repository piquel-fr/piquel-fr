//! Each account's inbox: its notifications, newest first, and whether its owner
//! read them. [`DatabaseTransaction::record`](crate::DatabaseTransaction::record)
//! writes the notification an event gives its subject in the event's transaction.

use super::{KindProbe, NotificationRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use sourceorigin_common::{
    EventId, NotificationId, UserId,
    notifications::{EmailCategory, Notification, NotificationPreference},
};
use serde::Serialize;
use serde_json::Value;

/// A notification of an account's inbox, as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoredNotification {
    /// Notification identifier.
    pub id: NotificationId,
    /// The event it comes from, which audit pruning may have deleted since.
    pub event_id: Option<EventId>,
    /// What it says; `None` for a kind a newer release wrote, which this one
    /// cannot show.
    pub notification: Option<Notification>,
    /// When it was written.
    pub created_at: DateTime<Utc>,
    /// When its owner last read it, unless they marked it unread since.
    pub read_at: Option<DateTime<Utc>>,
}

/// A notification `record` just wrote, which the channels its event fans out to
/// see: the `email` channel sends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notified {
    /// The account whose inbox it is in.
    pub user_id: UserId,
    /// The notification's ID, which its page's path names.
    pub id: NotificationId,
    /// What it says.
    pub notification: Notification,
}

/// A notification as the queries return it, before its payload decodes.
struct NotificationRow {
    /// Notification identifier.
    id: NotificationId,
    /// The event it comes from.
    event_id: Option<EventId>,
    /// The serialized [`Notification`].
    payload: Value,
    /// When it was written.
    created_at: DateTime<Utc>,
    /// When it was read.
    read_at: Option<DateTime<Utc>>,
}

impl TryFrom<NotificationRow> for StoredNotification {
    type Error = DatabaseError;

    /// Decodes the payload. A kind this release does not know reads as `None`;
    /// a known one that does not decode fails.
    fn try_from(row: NotificationRow) -> Result<Self, DatabaseError> {
        let known = row
            .payload
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(KindProbe::knows::<Notification>);
        let notification = known
            .then(|| serde_json::from_value(row.payload))
            .transpose()
            .map_err(|source| DatabaseError::InvalidStoredData {
                column: "payload".into(),
                source: source.into(),
            })?;
        Ok(Self {
            id: row.id,
            event_id: row.event_id,
            notification,
            created_at: row.created_at,
            read_at: row.read_at,
        })
    }
}

impl NotificationRepository<'_> {
    /// Writes `notification` to `user_id`'s inbox, unread, from the event
    /// `event_id`, if it comes from one. An account purged meanwhile, as one a
    /// request still in flight records an event about, gets none, and `None`
    /// says so: nobody reads its inbox.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if it cannot be serialized or written.
    pub async fn insert(
        &mut self,
        user_id: UserId,
        event_id: Option<EventId>,
        notification: &Notification,
    ) -> Result<Option<NotificationId>, DatabaseError> {
        let payload = serde_json::to_value(notification)
            .map_err(|error| DatabaseError::Operation(Box::new(error)))?;
        let id = NotificationId::new();
        let inserted = run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO notifications (id, user_id, event_id, payload)
                SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM users WHERE id = $2)",
                id.as_uuid(),
                user_id.as_uuid(),
                event_id.map(EventId::as_uuid),
                payload,
            )
        )?
        .rows_affected();
        Ok((inserted == 1).then_some(id))
    }

    /// Up to `limit` of `user_id`'s notifications, newest first, older than
    /// `before`, one of theirs. Notifications written together share a time, so
    /// the order breaks ties by ID and a page never skips or repeats one. A
    /// `before` that is not theirs reads nothing.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a payload does not decode.
    pub async fn list(
        &mut self,
        user_id: UserId,
        before: Option<NotificationId>,
        limit: u32,
    ) -> Result<Vec<StoredNotification>, DatabaseError> {
        let rows = run!(
            self,
            fetch_all,
            sqlx::query_as!(
                NotificationRow,
                r#"SELECT id AS "id: NotificationId", event_id AS "event_id: EventId",
                    payload, created_at, read_at
                FROM notifications
                WHERE user_id = $1
                    AND ($2::uuid IS NULL OR (created_at, id) < (
                        SELECT created_at, id FROM notifications WHERE id = $2 AND user_id = $1
                    ))
                ORDER BY created_at DESC, id DESC
                LIMIT $3"#,
                user_id.as_uuid(),
                before.map(NotificationId::as_uuid),
                i64::from(limit),
            )
        )?;
        rows.into_iter().map(StoredNotification::try_from).collect()
    }

    /// `user_id`'s notification `id`, if it is theirs.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or its payload does not decode.
    pub async fn find(
        &mut self,
        user_id: UserId,
        id: NotificationId,
    ) -> Result<Option<StoredNotification>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                NotificationRow,
                r#"SELECT id AS "id: NotificationId", event_id AS "event_id: EventId",
                    payload, created_at, read_at
                FROM notifications
                WHERE user_id = $1 AND id = $2"#,
                user_id.as_uuid(),
                id.as_uuid(),
            )
        )?
        .map(StoredNotification::try_from)
        .transpose()
    }

    /// How many of `user_id`'s notifications are unread.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn unread(&mut self, user_id: UserId) -> Result<u64, DatabaseError> {
        let count = run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "count!"
                FROM notifications
                WHERE user_id = $1 AND read_at IS NULL"#,
                user_id.as_uuid(),
            )
        )?;
        Ok(count.try_into().unwrap_or_default())
    }

    /// Marks `user_id`'s notification `id` read, keeping when it was first read,
    /// or unread. Returns whether they have it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn mark(
        &mut self,
        user_id: UserId,
        id: NotificationId,
        read: bool,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE notifications
                SET read_at = CASE WHEN $3 THEN coalesce(read_at, now()) END
                WHERE user_id = $1 AND id = $2",
                user_id.as_uuid(),
                id.as_uuid(),
                read,
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Whether `user_id` receives each category's email, its default, on, where
    /// they never chose.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn preferences(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<NotificationPreference>, DatabaseError> {
        let chosen = run!(
            self,
            fetch_all,
            sqlx::query_as!(
                NotificationPreference,
                r#"SELECT category AS "category: EmailCategory", email
                FROM notification_preferences WHERE user_id = $1"#,
                user_id.as_uuid(),
            )
        )?;
        Ok(EmailCategory::ALL
            .into_iter()
            .map(|category| NotificationPreference {
                category,
                email: chosen
                    .iter()
                    .find(|chosen| chosen.category == category)
                    .is_none_or(|chosen| chosen.email),
            })
            .collect())
    }

    /// Sets `user_id`'s `preference`. Returns whether it changed what they
    /// receive. Run it in a transaction holding the account's lock, so a
    /// concurrent change waits and finds it already made.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a query fails or a row is invalid.
    pub async fn set_preference(
        &mut self,
        user_id: UserId,
        preference: NotificationPreference,
    ) -> Result<bool, DatabaseError> {
        let current = self.preferences(user_id).await?;
        if current.contains(&preference) {
            return Ok(false);
        }
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO notification_preferences (user_id, category, email)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id, category)
                DO UPDATE SET email = EXCLUDED.email, updated_at = now()",
                user_id.as_uuid(),
                preference.category.as_str(),
                preference.email,
            )
        )?;
        Ok(true)
    }

    /// Marks every unread notification of `user_id`'s read.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn mark_all_read(&mut self, user_id: UserId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE notifications SET read_at = now()
                WHERE user_id = $1 AND read_at IS NULL",
                user_id.as_uuid(),
            )
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
