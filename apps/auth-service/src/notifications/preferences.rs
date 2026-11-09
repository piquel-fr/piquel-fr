//! Which categories of notifications the owner receives by email. The emails
//! they may turn off carry a one-click unsubscribe link (RFC 8058,
//! [`UnsubscribeLinks`](super::UnsubscribeLinks)).
//!
//! Everything about the account itself is always emailed: only
//! [`EmailCategory`]s have a preference. Any administrator may read them, as
//! the rest of the inbox, but only the owner changes them, since turning email
//! off could hide a notice from them.

use crate::{
    account::{AccountError, AccountService, Owner, Viewer},
    security::RequestContext,
};
use sourceorigin_common::{
    UserId,
    events::{Actor, DomainEvent},
    notifications::{EmailCategory, NotificationPreference},
};
use sourceorigin_repository::DatabaseTransaction;

/// The owner's email preferences, which any administrator may also read.
impl AccountService {
    /// Whether the account receives each category's email.
    pub(crate) async fn notification_preferences(
        &self,
        viewer: &Viewer,
    ) -> Result<Vec<NotificationPreference>, AccountError> {
        viewer.authorize(&self.database).await?;
        Ok(self
            .database
            .notifications()
            .preferences(viewer.user())
            .await?)
    }

    /// Sets the owner's `preference`, under the account lock. Their session is
    /// enough: it changes only what they are emailed.
    pub(crate) async fn set_notification_preference(
        &self,
        owner: &Owner,
        preference: NotificationPreference,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        owner.lock(&mut tx).await?;
        Self::prefer(&mut tx, owner.context(), owner.user(), preference).await?;
        Ok(tx.commit().await?)
    }

    /// Turns `user`'s announcements' email off, from an unsubscribe link their
    /// email carried, opened from `request`: as the owner, without a session.
    /// An account that no longer exists changes nothing.
    pub(crate) async fn unsubscribe(
        &self,
        user: UserId,
        request: RequestContext,
    ) -> Result<(), AccountError> {
        let mut tx = self.database.begin().await?;
        if tx.users().find_by_id_for_update(user).await?.is_none() {
            return Ok(());
        }
        let context = request.actor(Actor::User {
            user_id: user,
            session_id: None,
        });
        let preference = NotificationPreference {
            category: EmailCategory::Announcements,
            email: false,
        };
        Self::prefer(&mut tx, context, user, preference).await?;
        Ok(tx.commit().await?)
    }

    /// Sets `user`'s `preference` in `tx`, which holds the account lock, and
    /// records it as `context`'s if it changed anything.
    async fn prefer(
        tx: &mut DatabaseTransaction<'_>,
        context: sourceorigin_common::events::EventContext,
        user: UserId,
        preference: NotificationPreference,
    ) -> Result<(), AccountError> {
        if tx.notifications().set_preference(user, preference).await? {
            let event = DomainEvent::NotificationPreferenceChanged(preference);
            tx.record(&context, Some(user), event).await?;
        }
        Ok(())
    }
}
