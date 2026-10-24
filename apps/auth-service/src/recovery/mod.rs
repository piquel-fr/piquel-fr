//! Account recovery for an owner who lost every passkey.
//!
//! An administrator or operator starts one (`AdminService::recover_account`). It
//! ends the account's sessions and refresh grants, and emails its owner a link
//! that enrolls one new passkey, once, within a day. The link's token is derived
//! from the recovery's ID with [`RecoveryLinks`], so it is stored nowhere, not even
//! in the email's delivery. The token alone authorizes the link: the recovery page
//! enrolls the passkey, and signs its browser in with it.
//!
//! The owner can undo a recovery from a session signed in, or confirmed, by a
//! passkey enrolled before it started. The recovery's own passkey and a social
//! sign-in do not count. The recovery's passkey sign-in counts as a fresh
//! confirmation, so whoever used the link could add more ways in at once. Undoing
//! it therefore takes back everything the account gained since it started (a
//! [`Rollback`]): it stops a link not used yet, removes the passkeys enrolled, the
//! identities linked and the addresses added or verified since, restores the
//! primary address, and signs out every other session, each of which was signed
//! in since. The owner loses what they added themselves meanwhile too; the undo
//! page lists all of it first. Until then, only a session an older passkey
//! signed in may remove an older passkey, so the link's holder cannot make the
//! recovery impossible to undo.

/// Recovery failures and their browser response mapping.
mod error;
pub(crate) use error::RecoveryError;

use crate::{
    account::{AccountError, AccountService, Owner},
    emails::EmailApplication,
    routes,
};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    AccountStatus, PasskeyId, RecoveryId, SessionId, UserId,
    config::Origin,
    events::{DomainEvent, EventContext, RevocationReason},
};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::{
    DatabaseError, DatabaseTransaction, Rollback, SessionScope, StoredRecovery,
};
use serde::Serialize;
use std::sync::Arc;
use url::Url;

/// How long a recovery link works.
pub(crate) const LINK_LIFETIME: Duration = Duration::hours(24);

/// Derives recovery links' tokens from recoveries' IDs, with a key derived from
/// the current token digest key, so every replica, the email sender and the CLI
/// derive the same token, and builds the links on auth's origin. A link is
/// checked against its token's stored digest, never re-derived, so changing the
/// token digest key never breaks a link already sent. During a change, the
/// sender rebuilds a link under whichever key started its recovery.
#[derive(Clone)]
pub(crate) struct RecoveryLinks {
    /// Auth's origin, where the recovery page is.
    origin: Origin,
    /// HMAC keys reserved for recovery tokens: the current one, which derives
    /// every new token, then the one accepted during a change of key, if any.
    keys: Arc<[Secret]>,
}

/// A recovery whose link still works, found by the link's token: the token
/// authorizes enrolling a passkey on its account. Only
/// [`AccountService::open_recovery`] builds one.
pub(crate) struct OpenRecovery {
    /// The recovery.
    id: RecoveryId,
    /// Its account.
    user_id: UserId,
    /// What the recovery page shows of it.
    account: RecoveryAccount,
}

/// The account a recovery link recovers, as its page shows it.
#[derive(Serialize)]
pub(crate) struct RecoveryAccount {
    /// The account's login name.
    pub(crate) username: String,
    /// Its display name.
    pub(crate) display_name: String,
    /// When the link stops working.
    pub(crate) expires_at: DateTime<Utc>,
}

/// The account's newest recovery its owner could undo, as the undo page shows
/// it.
#[derive(Serialize)]
pub(crate) struct RecoveryView {
    /// The recovery, which undoing it names.
    id: RecoveryId,
    /// When it started.
    started_at: DateTime<Utc>,
    /// When its link enrolled a passkey; `None` while the link still works.
    completed_at: Option<DateTime<Utc>>,
    /// Exactly what undoing it would take back now.
    rollback: Rollback,
    /// Whether this session may undo it: a passkey enrolled before the recovery
    /// signed it in, or confirmed it since.
    can_undo: bool,
}

impl RecoveryLinks {
    /// Links on `origin`, with new tokens derived with `current`, and those of
    /// recoveries started under `accepted` still rebuilt with it.
    pub(crate) fn new(origin: Origin, current: Secret, accepted: Option<Secret>) -> Self {
        let keys: Vec<_> = std::iter::once(current).chain(accepted).collect();
        Self {
            origin,
            keys: keys.into(),
        }
    }

    /// The token of a new recovery `id`'s link, under the current key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn token(&self, id: RecoveryId) -> Result<Secret, CryptoError> {
        Self::derive(&self.keys[0], id)
    }

    /// Recovery `id`'s link, as [`Self::url`] builds it, under the key whose
    /// token has the stored SHA-256 `digest`. `None` once no configured key
    /// derives it.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn link(&self, id: RecoveryId, digest: &[u8]) -> Result<Option<Url>, CryptoError> {
        for key in self.keys.iter() {
            let token = Self::derive(key, id)?;
            if token.digest().as_bytes() == digest {
                return Ok(Some(self.url(&token)));
            }
        }
        Ok(None)
    }

    /// The token `key` derives for recovery `id`.
    fn derive(key: &Secret, id: RecoveryId) -> Result<Secret, CryptoError> {
        Secret::derive(key.as_bytes(), id.as_uuid().as_bytes())
    }

    /// The link holding `token`: the recovery page, with the token in its
    /// fragment so it never reaches a server log.
    pub(crate) fn url(&self, token: &Secret) -> Url {
        let mut link = self.origin.url(routes::page::RECOVER);
        link.set_fragment(Some(&format!("token={}", token.encoded())));
        link
    }
}

impl OpenRecovery {
    /// The recovery.
    pub(crate) const fn id(&self) -> RecoveryId {
        self.id
    }

    /// Its account.
    pub(crate) const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// What the recovery page shows of it.
    pub(crate) const fn account(&self) -> &RecoveryAccount {
        &self.account
    }

    /// What the recovery page shows of it, without the recovery.
    pub(crate) fn into_account(self) -> RecoveryAccount {
        self.account
    }
}

/// Recoveries as their link and their owner use them.
impl AccountService {
    /// The recovery whose link holds `token`, if the link still works and its
    /// account is active. A token that does not parse cannot match, so it answers
    /// as an unknown one.
    pub(crate) async fn open_recovery(&self, token: &str) -> Result<OpenRecovery, AccountError> {
        let digest = Secret::parse(token)
            .map_err(|_| RecoveryError::InvalidLink)?
            .digest();
        let recovery = self
            .database
            .recoveries()
            .find_open_by_digest(digest.as_bytes())
            .await?
            .ok_or(RecoveryError::InvalidLink)?;
        let user = self
            .database
            .users()
            .find_by_id(recovery.user_id)
            .await?
            .filter(|user| user.status == AccountStatus::Active)
            .ok_or(RecoveryError::InvalidLink)?;
        Ok(OpenRecovery {
            id: recovery.id,
            user_id: recovery.user_id,
            account: RecoveryAccount {
                username: user.username,
                display_name: user.display_name,
                expires_at: recovery.expires_at,
            },
        })
    }

    /// The account's newest recovery its owner could undo, what undoing it would
    /// take back, and whether the owner's session may undo it.
    pub(crate) async fn recovery(
        &self,
        owner: &Owner,
    ) -> Result<Option<RecoveryView>, AccountError> {
        let mut tx = self.database.begin().await?;
        let Some(recovery) = tx.recoveries().latest_undoable(owner.user()).await? else {
            return Ok(None);
        };
        let rollback = tx.recoveries().rollback(&recovery).await?;
        let can_undo = Self::predates(&mut tx, owner.user(), owner.session().id, &recovery).await?;
        tx.commit().await?;
        Ok(Some(RecoveryView {
            id: recovery.id,
            started_at: recovery.started_at,
            completed_at: recovery.completed_at,
            rollback,
            can_undo,
        }))
    }

    /// Undoes recovery `id`, the account's newest one, for an owner whose session
    /// a passkey enrolled before it signed in or confirmed. Takes back its
    /// [`Rollback`], records each change as the owner's, and signs out every other
    /// session; the owner's own session stays.
    pub(crate) async fn undo_recovery(
        &self,
        owner: &Owner,
        id: RecoveryId,
    ) -> Result<(), AccountError> {
        let user = owner.user();
        let mut tx = self.database.begin().await?;
        owner.lock(&mut tx).await?;
        let recovery = tx
            .recoveries()
            .latest_undoable(user)
            .await?
            .ok_or(RecoveryError::NothingToUndo)?;
        if recovery.id != id {
            return Err(RecoveryError::Changed.into());
        }
        if !Self::predates(&mut tx, user, owner.session().id, &recovery).await? {
            return Err(RecoveryError::OlderPasskeyRequired.into());
        }
        let context = owner.context();
        let rollback = tx.recoveries().rollback(&recovery).await?;
        Self::take_back(&mut tx, &context, user, rollback).await?;
        tx.recoveries().undo(recovery.id).await?;
        tx.record(
            &context,
            Some(user),
            DomainEvent::RecoveryUndone {
                recovery_id: recovery.id,
            },
        )
        .await?;
        tx.revoke_sessions(
            &context,
            user,
            SessionScope::AllExcept(owner.session().id),
            &RevocationReason::CredentialRemoved,
        )
        .await?;
        Ok(tx.commit().await?)
    }

    /// Applies `rollback` to `user`'s account in `tx`, recording each change in
    /// `context`. The primary address moves back before the added ones go, since
    /// one of them may be primary. The undoing session's passkey predates the
    /// recovery, so a passkey always remains.
    async fn take_back(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user: UserId,
        rollback: Rollback,
    ) -> Result<(), DatabaseError> {
        for passkey in rollback.passkeys {
            if tx.passkeys().revoke_if_not_last(passkey.id, user).await? {
                let removed = DomainEvent::PasskeyRemoved {
                    passkey_id: passkey.id,
                };
                tx.record(context, Some(user), removed).await?;
            }
        }
        for identity in rollback.identities {
            let provider = identity.provider;
            if tx.federation().unlink(user, provider).await? {
                let unlinked = DomainEvent::IdentityUnlinked { provider };
                tx.record(context, Some(user), unlinked).await?;
            }
        }
        if let Some(primary) = rollback.primary {
            let previous_email_id = tx.emails().set_primary(user, primary.id).await?;
            let changed = DomainEvent::PrimaryEmailChanged {
                email_id: primary.id,
                previous_email_id,
            };
            tx.record(context, Some(user), changed).await?;
        }
        for email in rollback.emails {
            EmailApplication::delete(tx, context, user, email.id).await?;
        }
        Ok(())
    }

    /// Refuses removing `user`'s passkey `id` from the owner's `session` while
    /// the account has a recovery to undo that the passkey predates and the
    /// session does not. Whoever used the link could otherwise remove every
    /// older passkey, and nothing could undo the recovery. Administrators, who
    /// have no such session, still can. In the removal's transaction, under the
    /// account lock.
    pub(crate) async fn keep_older_passkey(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
        session: SessionId,
        id: PasskeyId,
    ) -> Result<(), AccountError> {
        let Some(recovery) = tx.recoveries().latest_undoable(user).await? else {
            return Ok(());
        };
        if Self::older(tx, user, id, &recovery).await?
            && !Self::predates(tx, user, session, &recovery).await?
        {
            return Err(RecoveryError::OlderPasskeyKept.into());
        }
        Ok(())
    }

    /// Whether a passkey enrolled before `recovery` started, still active,
    /// signed `session` in or confirmed it since.
    async fn predates(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
        session: SessionId,
        recovery: &StoredRecovery,
    ) -> Result<bool, AccountError> {
        let Some(passkey) = tx.sessions().passkey(session).await? else {
            return Ok(false);
        };
        Self::older(tx, user, passkey, recovery).await
    }

    /// Whether `user`'s passkey `id` is active and was enrolled before
    /// `recovery` started.
    async fn older(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
        id: PasskeyId,
        recovery: &StoredRecovery,
    ) -> Result<bool, AccountError> {
        let enrolled = tx.passkeys().enrolled_at(user, id).await?;
        Ok(enrolled.is_some_and(|enrolled| enrolled < recovery.started_at))
    }
}

/// Database-backed recovery scenarios.
#[cfg(test)]
mod tests;
