//! Announcements administrators send to accounts, and the accounts each goes to.
//!
//! An announcement is a draft until [`AnnouncementRepository::send`] marks it
//! sent, and only a draft changes. A draft to chosen accounts lists them from the
//! start; one to everyone gets every account as its recipients when it is sent.

use super::{AnnouncementRepository, RepositoryExecutor, Unsigned};
use crate::DatabaseError;
use piquel_common::{
    AccountStatus, AnnouncementId, Handle, PictureId, UserId,
    admin::{Announcement, AnnouncementEmails, User},
    notifications::Notification,
};
use uuid::Uuid;

/// Whom an announcement goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipients<'a> {
    /// Every account, as of its sending.
    Everyone,
    /// These accounts.
    Accounts(&'a [UserId]),
}

/// An announcement's draft, as an administrator wrote it.
#[derive(Clone, Copy, Debug)]
pub struct DraftedAnnouncement<'a> {
    /// The announcement.
    pub id: AnnouncementId,
    /// Its subject.
    pub subject: &'a str,
    /// Its text.
    pub body: &'a str,
    /// Whom it goes to.
    pub recipients: Recipients<'a>,
}

impl Recipients<'_> {
    /// Whether it is every account, and the chosen ones' IDs otherwise.
    fn columns(self) -> (bool, Vec<Uuid>) {
        match self {
            Self::Everyone => (true, Vec::new()),
            Self::Accounts(accounts) => (false, accounts.iter().map(|id| id.as_uuid()).collect()),
        }
    }
}

impl AnnouncementRepository<'_> {
    /// Stores a new draft and its chosen recipients. Run it in a transaction, so
    /// the draft never lacks them.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a statement fails, e.g. for an unknown account.
    pub async fn insert_draft(
        &mut self,
        draft: &DraftedAnnouncement<'_>,
    ) -> Result<(), DatabaseError> {
        let (everyone, accounts) = draft.recipients.columns();
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO announcements (id, subject, body, everyone) VALUES ($1, $2, $3, $4)",
                draft.id.as_uuid(),
                draft.subject,
                draft.body,
                everyone,
            )
        )?;
        self.choose(draft.id, &accounts).await
    }

    /// Replaces a draft's text and recipients, and returns its new revision, or
    /// `None` if no draft has this ID: it was sent or discarded. Waits for a concurrent send, then finds
    /// it sent. Run it in a transaction, so the draft never lacks its recipients.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a statement fails, e.g. for an unknown account.
    pub async fn update_draft(
        &mut self,
        draft: &DraftedAnnouncement<'_>,
    ) -> Result<Option<u64>, DatabaseError> {
        let (everyone, accounts) = draft.recipients.columns();
        let revision = run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                r#"UPDATE announcements
                SET subject = $2, body = $3, everyone = $4, revision = revision + 1,
                    updated_at = now()
                WHERE id = $1 AND sent_at IS NULL
                RETURNING revision AS "revision: Unsigned""#,
                draft.id.as_uuid(),
                draft.subject,
                draft.body,
                everyone,
            )
        )?;
        let Some(revision) = revision else {
            return Ok(None);
        };
        run!(
            self,
            execute,
            sqlx::query!(
                "DELETE FROM announcement_recipients WHERE announcement_id = $1",
                draft.id.as_uuid(),
            )
        )?;
        self.choose(draft.id, &accounts).await?;
        Ok(Some(revision.into()))
    }

    /// Adds `accounts` to the recipients of `id`.
    async fn choose(&mut self, id: AnnouncementId, accounts: &[Uuid]) -> Result<(), DatabaseError> {
        if accounts.is_empty() {
            return Ok(());
        }
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO announcement_recipients (announcement_id, user_id)
                SELECT $1, account FROM unnest($2::uuid[]) account
                ON CONFLICT DO NOTHING",
                id.as_uuid(),
                accounts,
            )
        )?;
        Ok(())
    }

    /// Deletes a draft. Returns `false` if no draft has this ID.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn discard(&mut self, id: AnnouncementId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "DELETE FROM announcements WHERE id = $1 AND sent_at IS NULL",
                id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Marks the draft `id` sent, if it is still at `revision`, the one its
    /// sender checked; makes every account a recipient of one to everyone; and
    /// returns how many accounts it goes to, or `None` if no draft has this ID
    /// and revision. Its row stays locked until the transaction ends, so an edit,
    /// a discard or another send waits, then finds it sent. Run it in the
    /// transaction that records the sending, whose event queues the emails.
    ///
    /// Its recipients stay key-share locked until then, so an account's purge
    /// waits for the sending, then deletes the account's rows and emails with
    /// it; an account a purge already deleted is left out once that commits.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a statement fails.
    pub async fn send(
        &mut self,
        id: AnnouncementId,
        revision: u64,
    ) -> Result<Option<u64>, DatabaseError> {
        let sent = run!(
            self,
            fetch_optional,
            sqlx::query!(
                "UPDATE announcements SET sent_at = now()
                WHERE id = $1 AND sent_at IS NULL AND revision = $2
                RETURNING everyone, subject, body",
                id.as_uuid(),
                Unsigned::bind(revision)?,
            )
        )?;
        let Some(sent) = sent else {
            return Ok(None);
        };
        if sent.everyone {
            run!(
                self,
                execute,
                sqlx::query!(
                    "INSERT INTO announcement_recipients (announcement_id, user_id)
                    SELECT $1, id FROM users FOR KEY SHARE",
                    id.as_uuid(),
                )
            )?;
        }
        let recipients = run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                // The accounts too, before the notifications' foreign keys would,
                // so a purge of one waits for the whole sending.
                r#"SELECT count(*) AS "count!: Unsigned" FROM (
                    SELECT FROM announcement_recipients r
                    JOIN users u ON u.id = r.user_id
                    WHERE r.announcement_id = $1
                    FOR KEY SHARE
                ) locked"#,
                id.as_uuid(),
            )
        )?;
        // Each recipient's inbox gets it, from the recipients just locked.
        let notification = Notification::Announcement {
            announcement_id: id,
            title: sent.subject,
            text: sent.body,
        };
        let payload = serde_json::to_value(&notification)
            .map_err(|error| DatabaseError::Operation(Box::new(error)))?;
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO notifications (id, user_id, payload)
                SELECT uuidv7(), user_id, $2 FROM announcement_recipients
                WHERE announcement_id = $1",
                id.as_uuid(),
                payload,
            )
        )?;
        Ok(Some(recipients.into()))
    }

    /// The latest `limit` announcements, drafts and sent ones, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list(&mut self, limit: u32) -> Result<Vec<Announcement>, DatabaseError> {
        // A draft to everyone counts every account now; any other, its rows.
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                Announcement,
                r#"SELECT a.id AS "id: AnnouncementId", a.subject, a.body, a.everyone,
                    a.revision AS "revision: Unsigned",
                    CASE WHEN a.everyone AND a.sent_at IS NULL
                        THEN (SELECT count(*) FROM users)
                        ELSE (SELECT count(*) FROM announcement_recipients r
                            WHERE r.announcement_id = a.id)
                    END AS "recipients!: Unsigned",
                    -- Cleanup's cutoff for recipients (`purge_expired_auth_state`).
                    (a.sent_at IS NULL OR a.sent_at >= now() - interval '1 year')
                        AS "recipients_kept!",
                    a.created_at, a.updated_at, a.sent_at
                FROM announcements a
                ORDER BY a.created_at DESC, a.id DESC
                LIMIT $1"#,
                i64::from(limit),
            )
        )
    }

    /// The announcement `id`, draft or sent.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find(
        &mut self,
        id: AnnouncementId,
    ) -> Result<Option<Announcement>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                Announcement,
                r#"SELECT a.id AS "id: AnnouncementId", a.subject, a.body, a.everyone,
                    a.revision AS "revision: Unsigned",
                    CASE WHEN a.everyone AND a.sent_at IS NULL
                        THEN (SELECT count(*) FROM users)
                        ELSE (SELECT count(*) FROM announcement_recipients r
                            WHERE r.announcement_id = a.id)
                    END AS "recipients!: Unsigned",
                    -- Cleanup's cutoff for recipients (`purge_expired_auth_state`).
                    (a.sent_at IS NULL OR a.sent_at >= now() - interval '1 year')
                        AS "recipients_kept!",
                    a.created_at, a.updated_at, a.sent_at
                FROM announcements a
                WHERE a.id = $1"#,
                id.as_uuid(),
            )
        )
    }

    /// The accounts the announcement `id` was chosen for, by handle; none for one
    /// to everyone.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn chosen(&mut self, id: AnnouncementId) -> Result<Vec<User>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                User,
                r#"SELECT
                    u.id AS "id: UserId", h.handle AS "handle: Handle", u.display_name,
                    u.status AS "status: AccountStatus", u.created_at,
                    p.id AS "picture?: PictureId"
                FROM announcements a
                JOIN announcement_recipients r ON r.announcement_id = a.id
                JOIN users u ON u.id = r.user_id
                JOIN handles h ON h.user_id = u.id AND h.released_at IS NULL
                LEFT JOIN profile_pictures p ON p.user_id = u.id AND u.status = 'active'
                WHERE a.id = $1 AND NOT a.everyone
                ORDER BY h.handle"#,
                id.as_uuid(),
            )
        )
    }

    /// How many of the recipients of `id` have a primary verified address now:
    /// for a draft to everyone, how many accounts do.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn mailed(&mut self, id: AnnouncementId) -> Result<u64, DatabaseError> {
        Ok(run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "count!: Unsigned"
                FROM announcements a
                JOIN user_emails e ON e.is_primary AND (
                    (a.everyone AND a.sent_at IS NULL)
                    OR EXISTS (SELECT FROM announcement_recipients r
                        WHERE r.announcement_id = a.id AND r.user_id = e.user_id)
                )
                WHERE a.id = $1"#,
                id.as_uuid(),
            )
        )?
        .into())
    }

    /// How many recipients of `id` have read it in their inbox.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn read(&mut self, id: AnnouncementId) -> Result<u64, DatabaseError> {
        Ok(run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "count!: Unsigned" FROM notifications
                WHERE payload ->> 'kind' = 'announcement'
                AND payload ->> 'announcement_id' = $1::uuid::text AND read_at IS NOT NULL"#,
                id.as_uuid(),
            )
        )?
        .into())
    }

    /// The recipients of `id` with a primary verified address, whom its email
    /// goes to. Their rows stay key-share locked until the transaction ends, so a
    /// purge of one waits for the emails to be queued, and then deletes its own.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn mail_recipients(
        &mut self,
        id: AnnouncementId,
    ) -> Result<Vec<UserId>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_scalar!(
                r#"SELECT r.user_id AS "user_id: UserId"
                FROM announcement_recipients r
                JOIN user_emails e ON e.user_id = r.user_id AND e.is_primary
                WHERE r.announcement_id = $1
                ORDER BY r.user_id
                FOR KEY SHARE OF r"#,
                id.as_uuid(),
            )
        )
    }

    /// The emails of `id` in the delivery queue, by status.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn emails(
        &mut self,
        id: AnnouncementId,
    ) -> Result<AnnouncementEmails, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                AnnouncementEmails,
                r#"SELECT
                    count(*) FILTER (WHERE status = 'pending') AS "pending!: Unsigned",
                    count(*) FILTER (WHERE status = 'succeeded') AS "succeeded!: Unsigned",
                    count(*) FILTER (WHERE status = 'failed') AS "failed!: Unsigned",
                    count(*) FILTER (WHERE status = 'cancelled') AS "cancelled!: Unsigned"
                FROM deliveries
                WHERE channel = 'announcement' AND payload = to_jsonb($1::uuid::text)"#,
                id.as_uuid(),
            )
        )
    }
}

/// Drafts, sending, recipients and what each account received.
#[cfg(test)]
mod tests;
