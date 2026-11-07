//! Announcements to accounts, such as a security incident or a change to the
//! privacy policy: drafting, changing and sending them.

use super::AdminService;
use crate::admin::{AdminError, AnnouncementDraft, AnnouncementRecipients, Operator};
use piquel_common::{
    AnnouncementId, UserId,
    admin::{Announcement, AnnouncementDetail},
    events::DomainEvent,
};
use piquel_repository::{DraftedAnnouncement, Recipients};

/// Announcements listed, the latest first.
const ANNOUNCEMENT_LIST_SIZE: u32 = 100;

impl AdminService {
    /// The latest announcements, drafts and sent ones, newest first.
    pub(crate) async fn list_announcements(
        &self,
        operator: &Operator,
    ) -> Result<Vec<Announcement>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self
            .database
            .announcements()
            .list(ANNOUNCEMENT_LIST_SIZE)
            .await?)
    }

    /// Announcement `id`, with how many of its recipients its email reaches, and
    /// once sent, how its emails fared.
    pub(crate) async fn view_announcement(
        &self,
        operator: &Operator,
        id: AnnouncementId,
    ) -> Result<AnnouncementDetail, AdminError> {
        operator.authorize_read(&self.database).await?;
        let mut announcements = self.database.announcements();
        let announcement = announcements
            .find(id)
            .await?
            .ok_or(AdminError::AnnouncementNotFound)?;
        Ok(AnnouncementDetail {
            accounts: announcements.chosen(id).await?,
            mailed: announcements.mailed(id).await?,
            read: announcements.read(id).await?,
            emails: announcements.emails(id).await?,
            announcement,
        })
    }

    /// Stores `draft` as a new announcement, sent to nobody yet, and returns its
    /// ID. A draft is the administrators' own working copy, which nobody else
    /// sees, so writing, changing or discarding one needs only what a read needs:
    /// a long text never outlasts a passkey confirmation. Sending it needs a
    /// recent one.
    pub(crate) async fn draft_announcement(
        &self,
        operator: &Operator,
        draft: &AnnouncementDraft,
    ) -> Result<AnnouncementId, AdminError> {
        let accounts = self.chosen(operator, &draft.recipients).await?;
        let id = AnnouncementId::new();
        let mut tx = self.database.begin().await?;
        tx.announcements()
            .insert_draft(&Self::drafted(id, draft, accounts.as_deref()))
            .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Replaces the draft `id` with `draft`, and returns its new revision, which
    /// sending it as saved names. Refused once it is sent.
    pub(crate) async fn edit_announcement(
        &self,
        operator: &Operator,
        id: AnnouncementId,
        draft: &AnnouncementDraft,
    ) -> Result<u64, AdminError> {
        let accounts = self.chosen(operator, &draft.recipients).await?;
        let mut tx = self.database.begin().await?;
        let Some(revision) = tx
            .announcements()
            .update_draft(&Self::drafted(id, draft, accounts.as_deref()))
            .await?
        else {
            return Err(self.unchangeable(id).await);
        };
        tx.commit().await?;
        Ok(revision)
    }

    /// Deletes the draft `id`. Refused once it is sent.
    pub(crate) async fn discard_announcement(
        &self,
        operator: &Operator,
        id: AnnouncementId,
    ) -> Result<(), AdminError> {
        operator.authorize_read(&self.database).await?;
        if self.database.announcements().discard(id).await? {
            Ok(())
        } else {
            Err(self.unchangeable(id).await)
        }
    }

    /// Sends the draft `id` at `revision`, the one its sender checked, and
    /// returns how many accounts it went to: every account if it is to everyone,
    /// or the chosen ones still there. Each with a primary verified address is
    /// emailed it, from the `announcement` delivery channel, and every one gets
    /// it as a notification in their inbox. Recorded, without the text, which never changes once
    /// sent. A draft changed since its sender checked it is refused, to be
    /// checked again.
    pub(crate) async fn send_announcement(
        &self,
        operator: &Operator,
        id: AnnouncementId,
        revision: u64,
    ) -> Result<u64, AdminError> {
        let mut tx = self.database.begin().await?;
        let Some(recipients) = tx.announcements().send(id, revision).await? else {
            return Err(self.unchangeable(id).await);
        };
        let sent = DomainEvent::AnnouncementSent {
            announcement_id: id,
            recipients,
        };
        Self::finish(tx, operator, None, vec![sent]).await?;
        Ok(recipients)
    }

    /// The accounts `recipients` names, each once, or `None` for everyone. An
    /// account that does not exist is named in the refusal.
    async fn chosen(
        &self,
        operator: &Operator,
        recipients: &AnnouncementRecipients,
    ) -> Result<Option<Vec<UserId>>, AdminError> {
        operator.authorize_read(&self.database).await?;
        let AnnouncementRecipients::Accounts(users) = recipients else {
            return Ok(None);
        };
        let mut accounts = Vec::with_capacity(users.len());
        for user in users {
            let account = self
                .lookup(user)
                .await?
                .ok_or_else(|| AdminError::UnknownRecipient(user.clone()))?;
            if !accounts.contains(&account) {
                accounts.push(account);
            }
        }
        Ok(Some(accounts))
    }

    /// `draft` as the repository stores it as `id`, to `accounts`, or everyone.
    fn drafted<'a>(
        id: AnnouncementId,
        draft: &'a AnnouncementDraft,
        accounts: Option<&'a [UserId]>,
    ) -> DraftedAnnouncement<'a> {
        DraftedAnnouncement {
            id,
            subject: &draft.subject,
            body: &draft.body,
            recipients: accounts.map_or(Recipients::Everyone, Recipients::Accounts),
        }
    }

    /// Why the announcement `id` could not change or be sent: it was sent, it
    /// does not exist, or, still a draft, it changed since its sender checked it.
    async fn unchangeable(&self, id: AnnouncementId) -> AdminError {
        match self.database.announcements().find(id).await {
            Ok(Some(found)) if found.sent_at.is_some() => AdminError::AnnouncementSent,
            Ok(Some(_)) => AdminError::AnnouncementChanged,
            Ok(None) => AdminError::AnnouncementNotFound,
            Err(error) => error.into(),
        }
    }
}
