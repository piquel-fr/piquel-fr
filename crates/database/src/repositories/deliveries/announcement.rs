//! The `announcement` channel: the email of an announcement administrators sent,
//! one per recipient with a primary verified address.
//!
//! It is a channel of its own, with workers of its own, so an announcement to
//! every account never holds back a verification or recovery link behind it on
//! the `email` channel. A delivery stores only the account and the
//! announcement's ID: the sender reads the account's primary verified address
//! and the text when it sends, through [`EmailRepository::announcement`].

use super::{Channel, NewDelivery};
use crate::{
    DatabaseError, DatabaseTransaction, Notified,
    repositories::{EmailRepository, RepositoryExecutor},
};
use piquel_common::{AnnouncementId, UserId, events::DomainEvent};

/// Announcements' emails, sent over SMTP by auth-service.
pub struct Announcement;

/// An announcement's email as it goes out: where, and what it says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnouncementEmail {
    /// The account's primary verified address.
    pub address: String,
    /// The announcement's subject.
    pub subject: String,
    /// Its text.
    pub body: String,
    /// Whether it went to every account, rather than to chosen ones.
    pub everyone: bool,
}

impl Channel for Announcement {
    const NAME: &'static str = "announcement";
    type Recipient = UserId;
    type Payload = AnnouncementId;

    /// One unordered delivery per recipient of the sent announcement with a
    /// primary verified address. Its `destination` names the account and the
    /// announcement, never the address.
    async fn deliveries(
        event: &DomainEvent,
        _: Option<UserId>,
        _: Option<&Notified>,
        tx: &mut DatabaseTransaction<'_>,
    ) -> Result<Vec<NewDelivery<Self>>, DatabaseError> {
        let DomainEvent::AnnouncementSent {
            announcement_id, ..
        } = event
        else {
            return Ok(Vec::new());
        };
        Ok(tx
            .announcements()
            .mail_recipients(*announcement_id)
            .await?
            .into_iter()
            .map(|user_id| NewDelivery {
                destination: format!("account {user_id}, announcement {announcement_id}"),
                recipient: user_id,
                payload: *announcement_id,
                ordering_key: None,
            })
            .collect())
    }
}

impl EmailRepository<'_> {
    /// The email of the sent announcement `id` to `user_id`, at the account's
    /// primary verified address now, if it still has one and is still a
    /// recipient: a purge removes it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn announcement(
        &mut self,
        user_id: UserId,
        id: AnnouncementId,
    ) -> Result<Option<AnnouncementEmail>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                AnnouncementEmail,
                "SELECT e.normalized_email AS address, a.subject, a.body, a.everyone
                FROM announcement_recipients r
                JOIN announcements a ON a.id = r.announcement_id
                JOIN user_emails e ON e.user_id = r.user_id AND e.is_primary
                WHERE r.user_id = $1 AND r.announcement_id = $2 AND a.sent_at IS NOT NULL",
                user_id.as_uuid(),
                id.as_uuid(),
            )
        )
    }
}
