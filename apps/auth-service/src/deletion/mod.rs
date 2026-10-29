//! Deleting an account, restoring it, and downloading its data, as GDPR Art. 17
//! and 20 require.
//!
//! Deleting an account first schedules it: the account can no longer sign in, and
//! its sessions and grants end. For [`GRACE_PERIOD_DAYS`], a passkey sign-in
//! offers to restore it instead of signing in. The purge job then deletes it with
//! everything that identifies its person and the clients it manages. Its handles
//! stay without an owner, so nobody claims them until an operator releases them.
//!
//! The owner exports, deletes and restores through [`AccountService`]. Exporting
//! and deleting take an [`Owner`] whose session a passkey confirmed recently,
//! checked under the account lock: no administrator can run them, and neither can
//! a session that never confirms, such as a recovery's probation sign-in.
//! `AdminService`, the CLI and the purge job share the steps of [`Deletions`].

/// Deletion failures and their response mapping.
mod error;
/// The account's data, as its owner downloads it.
mod export;
#[cfg(test)]
mod tests;

pub use error::DeletionError;
pub(crate) use export::AccountExport;

use crate::{
    ClientRegistry,
    account::{AccountError, AccountService, Owner},
    passkey::PasskeyApplication,
    security::{BrowserCookie, RequestContext, Session},
};
use axum::http::{HeaderMap, header::InvalidHeaderValue};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    AccountStatus, ClientId, PasskeyId, UserId,
    events::{Actor, DomainEvent, EventContext, RevocationReason},
};
use piquel_crypto::Secret;
use piquel_repository::{DatabaseTransaction, StoredUser};

/// How long an account scheduled for deletion can still be restored.
pub(crate) const GRACE_PERIOD_DAYS: i64 = 30;
/// How long a restore offer, made by a passkey sign-in, stays valid.
const RESTORE_OFFER_MINUTES: i64 = 5;

/// The steps of deleting an account, in the caller's transaction, each recorded
/// as made in one context: the one place that changes a deletion. Callers lock the
/// account with [`Self::lock`] first.
pub(crate) struct Deletions<'a, 't> {
    /// The caller's transaction.
    tx: &'a mut DatabaseTransaction<'t>,
    /// Who acts, and from where.
    context: EventContext,
}

/// A deletion just scheduled from the owner's browser, which signed every browser
/// out, this one included: its response must delete the session cookie. Only
/// [`AccountService::delete_account`] makes one.
#[must_use = "the browser keeps its session cookie until `clear_on` deletes it"]
pub(crate) struct AccountDeleted {
    /// When the account is purged, unless it is restored first.
    pub(crate) purge_after: DateTime<Utc>,
    /// The cookie of the session it ended.
    cookie: BrowserCookie,
}

/// A passkey sign-in to an account scheduled for deletion, which signs nothing in:
/// its response stores the single-use restore offer in the browser instead. Only
/// [`Deletions::offer_restore`] makes one.
#[must_use = "the browser cannot restore the account until `set_on` stores the offer"]
pub(crate) struct RestoreOffered(Secret);

/// The browser's restore offer, as the sign-in page shows it.
pub(crate) struct RestoreOffer {
    /// The account's handle.
    pub(crate) handle: String,
    /// When the account is purged, unless it is restored first.
    pub(crate) purge_after: DateTime<Utc>,
}

/// What restoring an account, or declining to, does to the browser: it signs in
/// with the restored account, and drops the offer either way. Only
/// [`AccountService::restore`] and [`RestoreSettled::declined`] make one.
#[must_use = "the browser keeps its restore offer until `set_on` drops it"]
pub(crate) struct RestoreSettled(Option<Secret>);

impl<'a, 't> Deletions<'a, 't> {
    /// Locks the administrator list, then the account, in any status, to delete or
    /// purge it: the order grants take them in. Refuses the last active
    /// administrator's account, so someone is always left to administer.
    ///
    /// # Errors
    /// Fails when the account does not exist or is the last active administrator's.
    pub(crate) async fn lock(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
    ) -> Result<StoredUser, DeletionError> {
        tx.administrators().lock().await?;
        let user = tx
            .users()
            .find_by_id_for_update(user_id)
            .await?
            .ok_or(DeletionError::NotFound)?;
        if user.status == AccountStatus::Active
            && tx.administrators().contains(user_id).await?
            && !tx.administrators().others_active(user_id).await?
        {
            return Err(DeletionError::LastAdministrator);
        }
        Ok(user)
    }

    /// Makes the steps in `tx`, recording each as made in `context`.
    pub(crate) const fn new(tx: &'a mut DatabaseTransaction<'t>, context: EventContext) -> Self {
        Self { tx, context }
    }

    /// Schedules the deletion of the active account `user`, which [`Self::lock`]
    /// locked: it stops signing in, and every session and refresh grant ends, which
    /// tells their clients. Returns when it will be purged.
    ///
    /// # Errors
    /// Fails when the account is not active.
    pub(crate) async fn schedule(
        &mut self,
        user: &StoredUser,
    ) -> Result<DateTime<Utc>, DeletionError> {
        if user.status != AccountStatus::Active {
            return Err(DeletionError::NotActive);
        }
        self.tx
            .users()
            .set_status(user.id, AccountStatus::Deleting)
            .await?;
        let purge_after = Utc::now() + Duration::days(GRACE_PERIOD_DAYS);
        self.tx.deletions().schedule(user.id, purge_after).await?;
        // As disabling does: a recovery link not used yet does not outlive it.
        self.tx.recoveries().cancel_open(user.id).await?;
        let scheduled = DomainEvent::AccountDeletionScheduled { purge_after };
        self.tx
            .record(&self.context, Some(user.id), scheduled)
            .await?;
        Session::end_all(
            self.tx,
            &self.context,
            user.id,
            RevocationReason::AccountDeletion,
        )
        .await?;
        Ok(purge_after)
    }

    /// Reactivates `user`, which is locked and scheduled for deletion. It keeps its
    /// verified emails throughout, so nobody can have claimed them meanwhile.
    ///
    /// # Errors
    /// Fails when the account is not scheduled for deletion.
    pub(crate) async fn restore(&mut self, user: &StoredUser) -> Result<(), DeletionError> {
        if user.status != AccountStatus::Deleting || !self.tx.deletions().cancel(user.id).await? {
            return Err(DeletionError::NotScheduled);
        }
        self.tx
            .users()
            .set_status(user.id, AccountStatus::Active)
            .await?;
        self.tx
            .record(
                &self.context,
                Some(user.id),
                DomainEvent::AccountRestored {},
            )
            .await?;
        Ok(())
    }

    /// Deletes `user`, which [`Self::lock`] locked, in any status: ends its
    /// sessions and grants, which tells their clients, deletes the clients it
    /// manages, then purges it.
    ///
    /// # Errors
    /// Fails when a client cannot be deleted or persistence fails.
    pub(crate) async fn purge(&mut self, user: &StoredUser) -> Result<(), DeletionError> {
        Session::end_all(
            self.tx,
            &self.context,
            user.id,
            RevocationReason::AccountDeletion,
        )
        .await?;
        // Each becomes a tombstone without an owner, so its ID is never reused.
        // Their families are locked together first, in the one order every
        // statement locks families in.
        let owned: Vec<ClientId> = (self.tx.oidc().list_owned_clients(user.id).await?)
            .into_iter()
            .map(|client| client.id)
            .collect();
        self.tx.tokens().lock_client_families(&owned).await?;
        let mut clients = ClientRegistry::new(self.tx, self.context.clone());
        for client in &owned {
            clients.delete(client).await?;
        }
        if !self.tx.deletions().purge(user.id).await? {
            return Err(DeletionError::NotFound);
        }
        // Recorded once the account is gone, so the personal data of the request
        // that purged it is not stored.
        self.tx
            .record(&self.context, Some(user.id), DomainEvent::AccountPurged {})
            .await?;
        Ok(())
    }

    /// Answers `passkey`'s verified sign-in to `user_id`, an account scheduled for
    /// deletion that `tx` locked, with an offer to restore it instead of a
    /// session: a single-use token, valid for [`RESTORE_OFFER_MINUTES`], whose
    /// digest alone is stored. Commits `tx`.
    ///
    /// # Errors
    /// Fails when the account is not scheduled for deletion.
    pub(crate) async fn offer_restore(
        mut tx: DatabaseTransaction<'_>,
        user_id: UserId,
        passkey: PasskeyId,
    ) -> Result<RestoreOffered, DeletionError> {
        let token = Secret::generate()?;
        tx.deletions()
            .issue_restore_token(
                user_id,
                token.digest().as_bytes(),
                passkey,
                Utc::now() + Duration::minutes(RESTORE_OFFER_MINUTES),
            )
            .await?
            .ok_or(DeletionError::NotScheduled)?;
        tx.commit().await?;
        Ok(RestoreOffered(token))
    }
}

/// Exporting, deleting and restoring, which only the owner may do.
/// Administrators schedule, restore and purge through `AdminService`.
impl AccountService {
    /// Every record of the owner's account, read from one snapshot, and recorded.
    /// It holds IP and email addresses, so it needs a recent passkey confirmation,
    /// checked in the snapshot under the account lock.
    pub(crate) async fn export(&self, owner: &Owner) -> Result<AccountExport, AccountError> {
        let mut tx = self.database.begin_snapshot().await?;
        owner.lock_confirmed(&mut tx).await?;
        let export = AccountExport::read(&mut tx, owner.user(), owner.session().id).await?;
        tx.record(
            &owner.context(),
            Some(owner.user()),
            DomainEvent::AccountExported {},
        )
        .await?;
        tx.commit().await?;
        Ok(export)
    }

    /// Schedules the deletion of the owner's account, once they typed its
    /// `handle`, after a recent passkey confirmation. Signs every browser out, this
    /// one included.
    pub(crate) async fn delete_account(
        &self,
        owner: &Owner,
        handle: &str,
    ) -> Result<AccountDeleted, AccountError> {
        let mut tx = self.database.begin().await?;
        let user = Deletions::lock(&mut tx, owner.user()).await?;
        owner.lock_confirmed(&mut tx).await?;
        if handle != user.handle.as_str() {
            return Err(DeletionError::HandleMismatch.into());
        }
        let purge_after = Deletions::new(&mut tx, owner.context())
            .schedule(&user)
            .await?;
        tx.commit().await?;
        Ok(AccountDeleted {
            purge_after,
            cookie: BrowserCookie::Session,
        })
    }

    /// The restore offer the browser behind `headers` holds, if it is still valid.
    pub(crate) async fn restore_offer(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<RestoreOffer>, AccountError> {
        let Some(token) = BrowserCookie::Restore.read(headers) else {
            return Ok(None);
        };
        let Some(offer) = self
            .database
            .deletions()
            .find_by_restore_token(token.digest().as_bytes())
            .await?
        else {
            return Ok(None);
        };
        let (Some(user), Some(deletion)) = (
            self.database.users().find_by_id(offer.user_id).await?,
            self.database.deletions().find(offer.user_id).await?,
        ) else {
            return Ok(None);
        };
        Ok(Some(RestoreOffer {
            handle: user.handle.to_string(),
            purge_after: deletion.purge_after,
        }))
    }

    /// Restores the account the browser's restore offer names, and signs the
    /// browser in to it with the passkey that made the offer. The offer proves
    /// that passkey's sign-in at most [`RESTORE_OFFER_MINUTES`] ago, so a stolen
    /// session cannot restore anything. The new session counts as confirmed from
    /// now, as that sign-in would have, up to those minutes later.
    pub(crate) async fn restore(
        &self,
        context: RequestContext,
        headers: &HeaderMap,
    ) -> Result<RestoreSettled, AccountError> {
        let digest = BrowserCookie::Restore
            .read(headers)
            .ok_or(DeletionError::RestoreExpired)?
            .digest();
        let offer = self
            .database
            .deletions()
            .find_by_restore_token(digest.as_bytes())
            .await?
            .ok_or(DeletionError::RestoreExpired)?;
        let mut tx = self.database.begin().await?;
        let user = tx
            .users()
            .find_by_id_for_update(offer.user_id)
            .await?
            .ok_or(DeletionError::RestoreExpired)?;
        // Checked again under the account lock, which restoring takes too, so the
        // offer restores at most once.
        if tx
            .deletions()
            .find_by_restore_token(digest.as_bytes())
            .await?
            != Some(offer)
        {
            return Err(DeletionError::RestoreExpired.into());
        }
        let actor = context.actor(Actor::User {
            user_id: user.id,
            session_id: None,
        });
        Deletions::new(&mut tx, actor).restore(&user).await?;
        // As the passkey's sign-in would have: a recovery's passkey in probation
        // confirms nothing.
        let credential = PasskeyApplication::credential(&mut tx, offer.passkey_id).await?;
        let session = Session::sign_in(&mut tx, context, headers, user.id, credential).await?;
        tx.commit().await?;
        Ok(RestoreSettled(Some(session)))
    }
}

impl AccountDeleted {
    /// Deletes the session cookie on `response`, an axum response or a page's,
    /// keeping any other cookies being set.
    pub(crate) fn clear_on<B>(
        &self,
        response: &mut axum::http::Response<B>,
    ) -> Result<(), InvalidHeaderValue> {
        self.cookie.clear_on(response)
    }
}

impl RestoreOffered {
    /// Stores the offer on `response`, an axum response or a page's, keeping any
    /// other cookies being set.
    pub(crate) fn set_on<B>(
        self,
        response: &mut axum::http::Response<B>,
    ) -> Result<(), InvalidHeaderValue> {
        BrowserCookie::Restore.set_on(response, &self.0)
    }
}

impl RestoreSettled {
    /// Declines the browser's restore offer, leaving the account scheduled for
    /// deletion: the browser forgets it. Its token stays stored until it expires,
    /// unused, or a newer sign-in replaces it.
    pub(crate) const fn declined() -> Self {
        Self(None)
    }

    /// Drops the offer on `response`, an axum response or a page's, and stores the
    /// restored account's session, if it was restored, keeping any other cookies
    /// being set.
    pub(crate) fn set_on<B>(
        self,
        response: &mut axum::http::Response<B>,
    ) -> Result<(), InvalidHeaderValue> {
        BrowserCookie::Restore.clear_on(response)?;
        match self.0 {
            Some(session) => BrowserCookie::Session.set_on(response, &session),
            None => Ok(()),
        }
    }
}
