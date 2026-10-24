//! Account recovery for an owner who lost every passkey.
//!
//! An administrator or operator starts one (`AdminService::recover_account`). It
//! ends the account's sessions and refresh grants, and emails its owner a link
//! that enrolls one new passkey, once, within a day. The link's token is derived
//! from the recovery's ID with [`RecoveryLinks`], so it is stored nowhere, not even
//! in the email's delivery. The token alone authorizes the link: the recovery page
//! enrolls the passkey, and signs its browser in with it.
//!
//! A recovery can be undone until its link expires unused, or for
//! [`SETTLE_WINDOW`] after it was used; then it settles. Undoing it is a passkey
//! ceremony of its own, by a passkey enrolled before every recovery that can
//! still be undone: not the recovery's own, nor a social sign-in. It needs no
//! session, so signing the owner out cannot stop it. The recovery's passkey
//! sign-in counts as a fresh confirmation, so whoever used the link could add
//! more ways in at once. Undoing therefore takes back everything the account
//! gained since it started (a [`Rollback`]): it stops a link not used yet,
//! removes the passkeys enrolled, the identities linked, the consents given and
//! the addresses added or verified since, restores the primary address, ends
//! every session, each of which was signed in since, and signs the undoing
//! browser in. The owner loses what they added themselves meanwhile too; the undo
//! page lists all of it first.
//!
//! Until a recovery settles, a session that does not predate it cannot remove
//! the passkeys, identities or addresses the account had before it, nor move the
//! primary address away from one ([`AccountService::keep_older`]), so the link's
//! holder can neither make it impossible to undo nor redirect the next link;
//! administrators and operators still can. An owner left with no passkey from
//! before it is helped by support, which undoes it for them
//! (`AdminService::undo_recovery`) with the same [`AccountService::revert`].

/// Recovery failures and their browser response mapping.
mod error;
pub(crate) use error::RecoveryError;

use crate::{
    account::{AccountError, AccountService, Owner},
    emails::EmailApplication,
    routes,
    security::RequestContext,
};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    AccountStatus, PasskeyId, RecoveryId, SessionId, UserId,
    config::Origin,
    events::{Actor, DomainEvent, EventContext, RevocationReason},
    protocol::api::Passkey,
};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::{
    DatabaseError, DatabaseTransaction, RecentRecovery, Rollback, SessionScope, StoredPasskey,
    StoredRecovery,
};
use serde::Serialize;
use std::sync::Arc;
use url::Url;

/// How long a recovery link works.
pub(crate) const LINK_LIFETIME: Duration = Duration::hours(24);

/// How long after its link was used a recovery can be undone. Until then, what
/// the account had before it is protected from sessions that do not predate it,
/// and its passkey does not count as an older one; after, it settles: it can no
/// longer be undone, and its passkey is an ordinary one.
pub(crate) const SETTLE_WINDOW: Duration = Duration::days(30);

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
    /// When it can no longer be undone, once its link was used.
    settles_at: Option<DateTime<Utc>>,
    /// Exactly what undoing it would take back now.
    rollback: Rollback,
    /// The passkeys that may undo it: those enrolled before every recovery that
    /// can still be undone. None, and it cannot be undone.
    undo_with: Vec<Passkey>,
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
    /// derives it, which fails its delivery.
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

/// Whether undoing a recovery may remove the account's last passkey. The
/// owner's undo never needs to: the passkey that undoes it predates it. Support's
/// takes back every passkey added since, even when support removed the older
/// ones meanwhile, and starts a new recovery after.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LastPasskey {
    /// Keep the last one.
    Keep,
    /// Remove it too.
    Remove,
}

/// What starting a recovery does while another can still be undone. Support
/// reviews and undoes the other first; starting anyway is a deliberate choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WhileUndoable {
    /// Refuse to start.
    Refuse,
    /// Start anyway, replacing an unused link.
    Proceed,
}

/// A recent recovery, with what undoing it would take back while it can still
/// be undone, as support reviews it.
#[derive(Debug, Serialize)]
pub(crate) struct ReviewedRecovery {
    /// The recovery and the passkey its link enrolled.
    #[serde(flatten)]
    pub(crate) recovery: RecentRecovery,
    /// What undoing it would take back now; `None` once it cannot be undone.
    pub(crate) rollback: Option<Rollback>,
}

/// The account's recoveries that can still be undone, newest first: those whose
/// link still works, and those used less than [`SETTLE_WINDOW`] ago. Whoever
/// used any of them may not be the owner, so only what predates all of them is
/// trusted.
pub(crate) struct Undoable(Vec<StoredRecovery>);

impl Undoable {
    /// `user`'s undoable recoveries, read in `tx`.
    pub(crate) async fn load(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
    ) -> Result<Self, DatabaseError> {
        let settled_before = Utc::now() - SETTLE_WINDOW;
        Ok(Self(tx.recoveries().undoable(user, settled_before).await?))
    }

    /// The newest.
    pub(crate) fn newest(&self) -> Option<&StoredRecovery> {
        self.0.first()
    }

    /// The oldest, whose recorded primary address predates them all.
    pub(crate) fn oldest(&self) -> Option<&StoredRecovery> {
        self.0.last()
    }

    /// Whether one of them was used: an unused link has let nobody in, and a
    /// new recovery replaces it.
    pub(crate) fn any_used(&self) -> bool {
        self.0
            .iter()
            .any(|recovery| recovery.completed_at.is_some())
    }

    /// `recent`, each with what undoing it would take back while it can be.
    pub(crate) async fn review(
        &self,
        tx: &mut DatabaseTransaction<'_>,
        recent: Vec<RecentRecovery>,
    ) -> Result<Vec<ReviewedRecovery>, DatabaseError> {
        let mut reviewed = Vec::with_capacity(recent.len());
        for recovery in recent {
            let rollback = match self.0.iter().find(|undoable| undoable.id == recovery.id) {
                Some(undoable) => Some(tx.recoveries().rollback(undoable).await?),
                None => None,
            };
            reviewed.push(ReviewedRecovery { recovery, rollback });
        }
        Ok(reviewed)
    }

    /// The newest, if it is recovery `id`, which an undo names.
    pub(crate) fn newest_is(&self, id: RecoveryId) -> Result<&StoredRecovery, RecoveryError> {
        let newest = self.newest().ok_or(RecoveryError::NothingToUndo)?;
        if newest.id == id {
            Ok(newest)
        } else {
            Err(RecoveryError::Changed)
        }
    }

    /// When the oldest started: only a passkey enrolled before it may undo.
    fn trusted_before(&self) -> Option<DateTime<Utc>> {
        self.0.iter().map(|recovery| recovery.started_at).min()
    }

    /// When the first of them that started after `added_at` did, which a session
    /// must predate to remove what was added then.
    fn protecting(&self, added_at: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let started = self.0.iter().map(|recovery| recovery.started_at);
        started.filter(|started| *started > added_at).min()
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
    /// take back, and the passkeys that may undo it.
    pub(crate) async fn recovery(
        &self,
        owner: &Owner,
    ) -> Result<Option<RecoveryView>, AccountError> {
        let mut tx = self.database.begin().await?;
        let undoable = Undoable::load(&mut tx, owner.user()).await?;
        let Some(recovery) = undoable.newest() else {
            return Ok(None);
        };
        let rollback = tx.recoveries().rollback(recovery).await?;
        let undo_with = Self::trusted(&mut tx, owner.user(), &undoable).await?;
        tx.commit().await?;
        Ok(Some(RecoveryView {
            id: recovery.id,
            started_at: recovery.started_at,
            completed_at: recovery.completed_at,
            settles_at: recovery.completed_at.map(|at| at + SETTLE_WINDOW),
            rollback,
            undo_with: undo_with.into_iter().map(Passkey::from).collect(),
        }))
    }

    /// The account recovery `id` belongs to, and the passkeys that may undo it,
    /// which its undo ceremony challenges. The recovery must be the account's
    /// newest undoable one. Needs no session, so ending the owner's sessions
    /// cannot stop an undo.
    pub(crate) async fn undo_passkeys(
        &self,
        id: RecoveryId,
    ) -> Result<(UserId, Vec<StoredPasskey>), AccountError> {
        let mut tx = self.database.begin().await?;
        let recovery = tx
            .recoveries()
            .find(id)
            .await?
            .ok_or(RecoveryError::NothingToUndo)?;
        // A disabled account has nothing to undo until it is enabled again.
        tx.users()
            .find_by_id(recovery.user_id)
            .await?
            .filter(|user| user.status == AccountStatus::Active)
            .ok_or(RecoveryError::NothingToUndo)?;
        let undoable = Undoable::load(&mut tx, recovery.user_id).await?;
        undoable.newest_is(id)?;
        let passkeys = Self::trusted(&mut tx, recovery.user_id, &undoable).await?;
        tx.commit().await?;
        if passkeys.is_empty() {
            return Err(RecoveryError::OlderPasskeyRequired.into());
        }
        Ok((recovery.user_id, passkeys))
    }

    /// Undoes `user`'s recovery `id`, its newest undoable one, in the caller's
    /// transaction, in which `passkey` just asserted. The passkey must predate
    /// every undoable recovery. Takes back its [`Rollback`], records each change
    /// as the owner's, and ends every session; the caller then signs the
    /// undoing browser in with `passkey`.
    pub(crate) async fn undo_recovery(
        tx: &mut DatabaseTransaction<'_>,
        request: RequestContext,
        user: UserId,
        id: RecoveryId,
        passkey: PasskeyId,
    ) -> Result<(), AccountError> {
        tx.users()
            .find_active_by_id_for_update(user)
            .await?
            .ok_or(RecoveryError::NothingToUndo)?;
        let undoable = Undoable::load(tx, user).await?;
        let recovery = undoable.newest_is(id)?;
        let enrolled = tx.passkeys().enrolled_at(user, passkey).await?;
        let trusted = matches!(
            (enrolled, undoable.trusted_before()),
            (Some(enrolled), Some(before)) if enrolled < before
        );
        if !trusted {
            return Err(RecoveryError::OlderPasskeyRequired.into());
        }
        let context = request.actor(Actor::User {
            user_id: user,
            session_id: None,
        });
        Self::revert(tx, &context, recovery, LastPasskey::Keep).await?;
        tx.revoke_sessions(
            &context,
            user,
            SessionScope::All,
            &RevocationReason::CredentialRemoved,
        )
        .await?;
        Ok(())
    }

    /// Undoes `recovery` in `tx`: takes back its [`Rollback`] and records each
    /// change, and the undo, in `context`. The owner's undo and support's both
    /// use it, then end the account's sessions.
    pub(crate) async fn revert(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        recovery: &StoredRecovery,
        last: LastPasskey,
    ) -> Result<(), DatabaseError> {
        let user = recovery.user_id;
        let rollback = tx.recoveries().rollback(recovery).await?;
        Self::take_back(tx, context, user, rollback, last).await?;
        tx.recoveries().undo(recovery.id).await?;
        let undone = DomainEvent::RecoveryUndone {
            recovery_id: recovery.id,
        };
        tx.record(context, Some(user), undone).await
    }

    /// Applies `rollback` to `user`'s account in `tx`, recording each change in
    /// `context`. The primary address moves back before the added ones go, since
    /// one of them may be primary. Whether the last passkey may go is `last`'s
    /// to say.
    async fn take_back(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user: UserId,
        rollback: Rollback,
        last: LastPasskey,
    ) -> Result<(), DatabaseError> {
        for passkey in rollback.passkeys {
            let mut passkeys = tx.passkeys();
            let revoked = match last {
                LastPasskey::Keep => passkeys.revoke_if_not_last(passkey.id, user).await?,
                LastPasskey::Remove => passkeys.revoke(passkey.id, user).await?,
            };
            if revoked {
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
        for consent in rollback.consents {
            let client_id = consent.client_id;
            if tx
                .oidc()
                .revoke_consent(user, &client_id, &consent.audience)
                .await?
            {
                let revoked = DomainEvent::ConsentRevoked { client_id };
                tx.record(context, Some(user), revoked).await?;
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

    /// Refuses the owner's removal of a passkey, identity or address of `user`
    /// that joined the account at `added_at`, while a recovery that started after
    /// it can be undone and the owner's `session` does not predate that recovery:
    /// a passkey enrolled before it must have signed the session in or confirmed
    /// it. Whoever used the link could otherwise remove what undoing needs, or
    /// what it would leave the owner. Administrators and operators act without
    /// such a session, `None`, and still can. In the removal's transaction,
    /// under the account lock; nothing to check when the setting is gone.
    pub(crate) async fn keep_older(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
        session: Option<SessionId>,
        added_at: Option<DateTime<Utc>>,
    ) -> Result<(), AccountError> {
        let (Some(session), Some(added_at)) = (session, added_at) else {
            return Ok(());
        };
        let undoable = Undoable::load(tx, user).await?;
        let Some(protecting) = undoable.protecting(added_at) else {
            return Ok(());
        };
        let enrolled = match tx.sessions().passkey(session).await? {
            Some(passkey) => tx.passkeys().enrolled_at(user, passkey).await?,
            None => None,
        };
        if enrolled.is_some_and(|enrolled| enrolled < protecting) {
            Ok(())
        } else {
            Err(RecoveryError::Protected.into())
        }
    }

    /// The account's active passkeys that predate every undoable recovery, which
    /// may undo the newest.
    async fn trusted(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
        undoable: &Undoable,
    ) -> Result<Vec<StoredPasskey>, DatabaseError> {
        match undoable.trusted_before() {
            Some(before) => tx.passkeys().enrolled_before(user, before).await,
            None => Ok(Vec::new()),
        }
    }
}

/// Database-backed recovery scenarios.
#[cfg(test)]
mod tests;
