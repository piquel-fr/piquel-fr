//! Which categories of notifications the owner receives by email, and the
//! one-click unsubscribe links (RFC 8058) of the emails they may turn off.
//!
//! Everything about the account itself is always emailed: only
//! [`EmailCategory`]s have a preference. Any administrator may read them, as
//! the rest of the inbox, but only the owner changes them, since turning email
//! off could hide a notice from them.

use crate::{
    account::{AccountError, AccountService, Owner, Viewer},
    config::LinkKeys,
    routes::page,
    security::RequestContext,
};
use piquel_common::{
    UserId,
    config::Origin,
    events::{Actor, DomainEvent},
    notifications::{EmailCategory, NotificationPreference},
};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::DatabaseTransaction;
use serde::{Deserialize, Serialize};

/// The links that turn an account's announcements' email off, which every
/// email that is not essential carries. A link names the account and a token
/// derived from its ID under the token digest key, so nothing is stored, and it
/// never expires: whoever holds it can only turn that email off, which the
/// owner sees in their history and turns back on in their settings. A change
/// of key keeps the links of the accepted key working until it is dropped.
#[derive(Clone)]
pub(crate) struct UnsubscribeLinks {
    /// Auth's origin, where the unsubscribe page is.
    origin: Origin,
    /// Derives and checks the tokens.
    keys: LinkKeys,
}

/// What an unsubscribe link's query names: the account, and its token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Unsubscribe {
    /// The account.
    pub(crate) account: UserId,
    /// Its token, encoded.
    pub(crate) token: String,
}

impl UnsubscribeLinks {
    /// Links to `origin`'s unsubscribe page, with tokens `keys` derive.
    pub(crate) const fn new(origin: Origin, keys: LinkKeys) -> Self {
        Self { origin, keys }
    }

    /// The link turning `user`'s announcements' email off.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn link(&self, user: UserId) -> Result<String, CryptoError> {
        // An ID and an unpadded base64url token need no escaping.
        let token = self.keys.token(user.as_uuid().as_bytes())?.encoded();
        Ok(format!(
            "{}?account={user}&token={token}",
            self.origin.join(page::UNSUBSCRIBE)
        ))
    }

    /// The account `link` names, if a configured key derives its token.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn check(&self, link: &Unsubscribe) -> Result<Option<UserId>, CryptoError> {
        let Ok(token) = Secret::parse(&link.token) else {
            return Ok(None);
        };
        Ok(self
            .keys
            .derives(link.account.as_uuid().as_bytes(), &token)?
            .then_some(link.account))
    }
}

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
        context: piquel_common::events::EventContext,
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
