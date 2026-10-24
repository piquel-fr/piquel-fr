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
//! sign-in do not count. Undoing it stops a link not used yet, or removes the
//! passkey it enrolled and signs out every other session: the recovery signed out
//! all of them, so each was signed in since, perhaps with a social sign-in that
//! passkey linked.

/// Recovery failures and their browser response mapping.
mod error;
pub(crate) use error::RecoveryError;

use crate::{
    account::{AccountError, AccountService, Owner},
    routes,
};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    AccountStatus, RecoveryId, UserId,
    config::Origin,
    events::{DomainEvent, RevocationReason},
    protocol::api::Passkey,
};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::{DatabaseTransaction, SessionScope, StoredRecovery};
use serde::Serialize;
use std::sync::Arc;
use url::Url;

/// How long a recovery link works.
pub(crate) const LINK_LIFETIME: Duration = Duration::hours(24);

/// Derives recovery links' tokens from recoveries' IDs, with a key derived from
/// the current token digest key, so every replica, the email sender and the CLI
/// derive the same token, and builds the links on auth's origin.
#[derive(Clone)]
pub(crate) struct RecoveryLinks {
    /// Auth's origin, where the recovery page is.
    origin: Origin,
    /// HMAC key reserved for recovery tokens.
    key: Arc<Secret>,
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

/// The account's newest recovery its owner could undo, as settings show it.
#[derive(Serialize)]
pub(crate) struct RecoveryView {
    /// The recovery.
    id: RecoveryId,
    /// When it started.
    started_at: DateTime<Utc>,
    /// When its link enrolled a passkey; `None` while the link still works.
    completed_at: Option<DateTime<Utc>>,
    /// The passkey it enrolled, while it is active.
    passkey: Option<Passkey>,
    /// Whether this session may undo it: a passkey enrolled before the recovery
    /// signed it in, or confirmed it since.
    can_undo: bool,
}

impl RecoveryLinks {
    /// Links on `origin`, with tokens derived with `key`.
    pub(crate) fn new(origin: Origin, key: Secret) -> Self {
        Self {
            origin,
            key: Arc::new(key),
        }
    }

    /// The token of recovery `id`'s link.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn token(&self, id: RecoveryId) -> Result<Secret, CryptoError> {
        Secret::derive(self.key.as_bytes(), id.as_uuid().as_bytes())
    }

    /// Recovery `id`'s link: the recovery page, with the token in its fragment so
    /// it never reaches a server log.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the HMAC provider fails.
    pub(crate) fn link(&self, id: RecoveryId) -> Result<Url, CryptoError> {
        let mut link = self.origin.url(routes::page::RECOVER);
        link.set_fragment(Some(&format!("token={}", self.token(id)?.encoded())));
        Ok(link)
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

    /// The account's newest recovery its owner could undo, and whether the
    /// owner's session may undo it.
    pub(crate) async fn recovery(
        &self,
        owner: &Owner,
    ) -> Result<Option<RecoveryView>, AccountError> {
        let mut tx = self.database.begin().await?;
        let Some(recovery) = tx.recoveries().latest_undoable(owner.user()).await? else {
            return Ok(None);
        };
        let passkey = match recovery.passkey_id {
            Some(id) => tx
                .passkeys()
                .list_active(owner.user())
                .await?
                .into_iter()
                .find(|passkey| passkey.id == id)
                .map(Passkey::from),
            None => None,
        };
        let can_undo = Self::predates(&mut tx, owner, &recovery).await?;
        tx.commit().await?;
        Ok(Some(RecoveryView {
            id: recovery.id,
            started_at: recovery.started_at,
            completed_at: recovery.completed_at,
            passkey,
            can_undo,
        }))
    }

    /// Undoes the account's newest recovery, for an owner whose session a passkey
    /// enrolled before it signed in or confirmed. A link not used yet stops
    /// working. Once it enrolled a passkey, that passkey is removed and every other
    /// session ends; the owner's own session stays.
    pub(crate) async fn undo_recovery(&self, owner: &Owner) -> Result<(), AccountError> {
        let user = owner.user();
        let mut tx = self.database.begin().await?;
        owner.lock(&mut tx).await?;
        let recovery = tx
            .recoveries()
            .latest_undoable(user)
            .await?
            .ok_or(RecoveryError::NothingToUndo)?;
        if !Self::predates(&mut tx, owner, &recovery).await? {
            return Err(RecoveryError::OlderPasskeyRequired.into());
        }
        let context = owner.context();
        tx.recoveries().undo(recovery.id).await?;
        tx.record(
            &context,
            Some(user),
            DomainEvent::RecoveryUndone {
                recovery_id: recovery.id,
            },
        )
        .await?;
        if let Some(passkey_id) = recovery.passkey_id {
            // The owner may have removed it already.
            if tx.passkeys().revoke_if_not_last(passkey_id, user).await? {
                let removed = DomainEvent::PasskeyRemoved { passkey_id };
                tx.record(&context, Some(user), removed).await?;
            }
            tx.revoke_sessions(
                &context,
                user,
                SessionScope::AllExcept(owner.session().id),
                &RevocationReason::CredentialRemoved,
            )
            .await?;
        }
        Ok(tx.commit().await?)
    }

    /// Whether a passkey enrolled before `recovery` started, still active,
    /// signed the owner's session in or confirmed it since.
    async fn predates(
        tx: &mut DatabaseTransaction<'_>,
        owner: &Owner,
        recovery: &StoredRecovery,
    ) -> Result<bool, AccountError> {
        let Some(passkey) = tx.sessions().passkey(owner.session().id).await? else {
            return Ok(false);
        };
        Ok(tx
            .passkeys()
            .enrolled_at(owner.user(), passkey)
            .await?
            .is_some_and(|enrolled| enrolled < recovery.started_at))
    }
}

/// Database-backed recovery scenarios.
#[cfg(test)]
mod tests;
