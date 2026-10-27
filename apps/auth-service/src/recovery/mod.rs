//! Account recovery for an owner who lost every passkey.
//!
//! An operator starts one (`AdminService::recover_account`). It ends the
//! account's sessions and refresh grants, removes its unverified addresses, and
//! emails its owner a link that enrolls one new passkey, once, within a day. The
//! link's token is derived from the recovery's ID with [`RecoveryLinks`], so it
//! is stored nowhere, not even in the email's delivery. The token alone
//! authorizes the link.
//!
//! For [`PROBATION`] after its link is used, the recovery is in probation: its
//! passkey signs in like a social login, a [`ProbationPasskey`], and never
//! confirms a session. Every step-up gate refuses it (account changes, the admin
//! API, relying parties that ask for `phr`), so whoever used the link can use the
//! account but add no way into it. Undoing a recovery in probation therefore
//! takes back a short, fixed list: its passkey, every session and refresh grant,
//! and every consent ([`AccountService::revert`]). Undoing one whose link was
//! not used only cancels the link.
//!
//! The owner undoes with any passkey but the recovery's own, in a passkey
//! ceremony that needs no session, so signing them out cannot stop it, and that
//! works on a disabled account too. While the recovery can be undone, its link
//! unused or its probation running, no passkey but its own is removed, by anyone, so nothing takes that ability away
//! ([`AccountService::refuse_mid_recovery`]). Support undoes for an owner with
//! none (`AdminService::undo_recovery`). The database backs the probation and
//! that rule for every writer, an older release included: see migration
//! `0019_account_recoveries`.

/// Recovery failures and their browser response mapping.
mod error;
pub(crate) use error::RecoveryError;

use crate::{
    account::{AccountError, AccountService, Owner},
    passkey::VerifiedRecoveryUndo,
    routes,
    security::RequestContext,
};
use chrono::{DateTime, Duration, Utc};
use piquel_common::{
    AccountStatus, PasskeyId, RecoveryId, UserId,
    config::Origin,
    events::{Actor, DomainEvent, EventContext, RevocationReason},
    protocol::api::Passkey,
};
use piquel_crypto::{CryptoError, Secret};
use piquel_repository::{
    DatabaseError, DatabaseTransaction, RecoveryState, SessionScope, StoredPasskey, StoredRecovery,
};
use serde::Serialize;
use std::sync::Arc;
use url::Url;

/// How long a recovery link works.
pub(crate) const LINK_LIFETIME: Duration = Duration::hours(24);

/// How long after its link was used a recovery is in probation: its passkey
/// never confirms a session, and a passkey from before it can undo it. Then it
/// settles, and its passkey is an ordinary one. A session outlives it, but a
/// session the link signed in stays unconfirmed until that passkey confirms it
/// again, once the recovery settled.
pub(crate) const PROBATION: Duration = Duration::days(15);

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
pub(crate) struct RecoveryAccount {
    /// The account's login name.
    pub(crate) username: String,
    /// Its display name.
    pub(crate) display_name: String,
}

/// A recovery's passkey during its probation, as a sign-in credential: it signs
/// in, but never confirms a session. Only [`Self::of`] builds one, from a
/// recovery in probation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProbationPasskey {
    /// The passkey.
    passkey: PasskeyId,
    /// When the probation ends.
    settles_at: DateTime<Utc>,
}

impl ProbationPasskey {
    /// `recovery`'s passkey, if the recovery is in probation.
    pub(crate) fn of(recovery: &StoredRecovery) -> Option<Self> {
        match (recovery.state(), recovery.passkey_id) {
            (RecoveryState::Probation { settles_at }, Some(passkey)) => Some(Self {
                passkey,
                settles_at,
            }),
            _ => None,
        }
    }

    /// The passkey.
    pub(crate) const fn passkey(self) -> PasskeyId {
        self.passkey
    }

    /// When the probation ends.
    pub(crate) const fn settles_at(self) -> DateTime<Utc> {
        self.settles_at
    }
}

/// The passkeys a recovery started with `--revoke` keeps: those the owner
/// vouched for. Every other passkey is revoked, every identity unlinked and
/// every consent withdrawn, in the start's transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Revoke {
    /// The passkeys kept.
    pub(crate) keep: Vec<PasskeyId>,
}

/// A recovery that can still be undone, as undoing it sees it. Only
/// [`AccountService::undoable`] builds one, and its state is private, so no
/// caller can claim a recovery is undoable, or in which stage.
pub(crate) struct UndoableRecovery {
    /// The recovery.
    recovery: StoredRecovery,
    /// Its passkey, once its link was used and while its probation lasts; `None`
    /// while its link works.
    probation: Option<ProbationPasskey>,
}

impl UndoableRecovery {
    /// `recovery`, if it can still be undone.
    fn of(recovery: StoredRecovery) -> Option<Self> {
        let probation = match recovery.state() {
            RecoveryState::Open => None,
            RecoveryState::Probation { .. } => Some(ProbationPasskey::of(&recovery)?),
            RecoveryState::Settled | RecoveryState::Ended => return None,
        };
        Some(Self {
            recovery,
            probation,
        })
    }

    /// Whether its link was used, so it is in probation: starting another
    /// recovery waits until it is undone or settles.
    pub(crate) const fn is_probation(&self) -> bool {
        self.probation.is_some()
    }

    /// The passkey its link enrolled, once used.
    fn passkey(&self) -> Option<PasskeyId> {
        self.probation.map(ProbationPasskey::passkey)
    }
}

/// Where an undoable recovery stands, as its page shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum UndoableState {
    /// Its link works.
    Open,
    /// Its link was used, and it has not settled.
    Probation,
}

/// The account's recovery that can still be undone, as `GET /account/recovery`
/// answers it.
#[derive(Serialize)]
pub(crate) struct RecoveryView {
    /// The recovery, which undoing it names.
    id: RecoveryId,
    /// Whether its link works or was used.
    state: UndoableState,
    /// When it started.
    started_at: DateTime<Utc>,
    /// When its link stops working; `None` once used.
    expires_at: Option<DateTime<Utc>>,
    /// When its link enrolled a passkey; `None` while it works.
    completed_at: Option<DateTime<Utc>>,
    /// When its probation ends; `None` while its link works.
    settles_at: Option<DateTime<Utc>>,
    /// The passkey its link enrolled, while active. Pages name it by ID and
    /// enrollment time, since a probation session can rename it.
    passkey: Option<Passkey>,
    /// The passkeys that may undo it: every active one but its own. None, and
    /// only support can.
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

    /// The undo page of recovery `id`, which the notices link to, so an owner
    /// signed out can still undo it.
    pub(crate) fn undo_url(&self, id: RecoveryId) -> Url {
        let mut link = self.origin.url(routes::page::RECOVER_UNDO);
        link.set_fragment(Some(&format!("recovery={id}")));
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
            },
        })
    }

    /// The account's recovery that can still be undone, if any, and the passkeys
    /// that may undo it.
    pub(crate) async fn recovery(
        &self,
        owner: &Owner,
    ) -> Result<Option<RecoveryView>, AccountError> {
        let mut tx = self.database.begin().await?;
        let view = match Self::undoable(&mut tx, owner.user()).await? {
            Some(undoable) => Some(Self::view(&mut tx, &undoable).await?),
            None => None,
        };
        tx.commit().await?;
        Ok(view)
    }

    /// How `undoable`'s page shows it, with the passkeys that may undo it.
    async fn view(
        tx: &mut DatabaseTransaction<'_>,
        undoable: &UndoableRecovery,
    ) -> Result<RecoveryView, DatabaseError> {
        let (own, undo_with) = Self::split(tx, undoable).await?;
        let recovery = &undoable.recovery;
        let (state, expires_at, settles_at) = match undoable.probation {
            None => (UndoableState::Open, Some(recovery.expires_at), None),
            Some(probation) => (UndoableState::Probation, None, Some(probation.settles_at())),
        };
        Ok(RecoveryView {
            id: recovery.id,
            state,
            started_at: recovery.started_at,
            expires_at,
            completed_at: recovery.completed_at,
            settles_at,
            passkey: own.map(Passkey::from),
            undo_with: undo_with.into_iter().map(Passkey::from).collect(),
        })
    }

    /// The account recovery `id` belongs to, and the passkeys that may undo it,
    /// which its undo ceremony challenges. The recovery must be the account's
    /// undoable one. Needs no session, so ending the owner's sessions cannot
    /// stop an undo, and works on a disabled account, so disabling it cannot
    /// either.
    pub(crate) async fn undo_passkeys(
        &self,
        id: RecoveryId,
    ) -> Result<(UserId, Vec<StoredPasskey>), AccountError> {
        let mut tx = self.database.begin().await?;
        let user = tx
            .recoveries()
            .find(id)
            .await?
            .ok_or(RecoveryError::NothingToUndo)?
            .user_id;
        let undoable = Self::undoable_named(&mut tx, user, id).await?;
        let (_, passkeys) = Self::split(&mut tx, &undoable).await?;
        tx.commit().await?;
        if passkeys.is_empty() {
            return Err(RecoveryError::OlderPasskeyRequired.into());
        }
        Ok((user, passkeys))
    }

    /// Undoes the recovery `verified` names, its account's undoable one, in the
    /// transaction its assertion was verified in, under the account lock. The
    /// asserting passkey must not be the recovery's own. Records each change as
    /// the owner's; the caller then signs the undoing browser in, unless the
    /// account is disabled.
    pub(crate) async fn undo_recovery(
        tx: &mut DatabaseTransaction<'_>,
        request: RequestContext,
        verified: &VerifiedRecoveryUndo,
    ) -> Result<(), AccountError> {
        let user = verified.user_id();
        let undoable = Self::undoable_named(tx, user, verified.recovery_id()).await?;
        if undoable.passkey() == Some(verified.passkey()) {
            return Err(RecoveryError::OlderPasskeyRequired.into());
        }
        let context = request.actor(Actor::User {
            user_id: user,
            session_id: None,
        });
        let reason = RevocationReason::CredentialRemoved;
        Ok(Self::revert(tx, &context, &undoable, reason).await?)
    }

    /// Undoes `undoable` in `tx`, recording each change in `context`. In
    /// probation, it takes back everything whoever used its link could have kept:
    /// its passkey, every refresh grant and consent, and every session, which end
    /// for `reason`. Its link unused, it only cancels the link. The owner's
    /// undo and support's both use it.
    pub(crate) async fn revert(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        undoable: &UndoableRecovery,
        reason: RevocationReason,
    ) -> Result<(), DatabaseError> {
        let recovery = &undoable.recovery;
        let user = recovery.user_id;
        let undone = DomainEvent::RecoveryUndone {
            recovery_id: recovery.id,
        };
        match undoable.probation {
            None => {
                tx.recoveries().cancel_open(user).await?;
                tx.record(context, Some(user), undone).await
            }
            Some(probation) => {
                Self::take_back_passkey(tx, context, user, probation.passkey()).await?;
                Self::withdraw_consents(tx, context, user).await?;
                tx.recoveries().undo(recovery.id).await?;
                tx.record(context, Some(user), undone).await?;
                tx.revoke_sessions(context, user, SessionScope::All, &reason)
                    .await?;
                Ok(())
            }
        }
    }

    /// Revokes `user`'s passkey `passkey_id`, the last one included, recording
    /// its removal in `context`, and returns whether it was active. Undoing a
    /// recovery and starting one with `--revoke` take passkeys back with it.
    pub(crate) async fn take_back_passkey(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user: UserId,
        passkey_id: PasskeyId,
    ) -> Result<bool, DatabaseError> {
        let revoked = tx.passkeys().revoke(passkey_id, user).await?;
        if revoked {
            let removed = DomainEvent::PasskeyRemoved { passkey_id };
            tx.record(context, Some(user), removed).await?;
        }
        Ok(revoked)
    }

    /// Withdraws every consent of `user`, recording each in `context`, so an app
    /// asks again at its next sign-in, and revokes every refresh grant. Undoing a
    /// recovery and starting one with `--revoke` do. The grants go first: a
    /// client's deletion locks its families before its consents, so taking them in
    /// the other order could deadlock with it.
    pub(crate) async fn withdraw_consents(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user: UserId,
    ) -> Result<(), DatabaseError> {
        tx.tokens().revoke_all_for_user(user).await?;
        for client_id in tx.oidc().revoke_consents(user).await? {
            let revoked = DomainEvent::ConsentRevoked { client_id };
            tx.record(context, Some(user), revoked).await?;
        }
        Ok(())
    }

    /// Refuses removing `user`'s passkey `passkey` while a recovery of the
    /// account can be undone, unless it is that recovery's own: nothing may take
    /// away the passkeys that can undo it, not even support, whoever asks. In the
    /// removal's transaction, under the account lock. The migration's
    /// `passkeys_kept_mid_recovery` backs it for every writer.
    pub(crate) async fn refuse_mid_recovery(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
        passkey: PasskeyId,
    ) -> Result<(), AccountError> {
        match Self::undoable(tx, user).await? {
            Some(undoable) if undoable.passkey() != Some(passkey) => {
                Err(RecoveryError::InProgress.into())
            }
            _ => Ok(()),
        }
    }

    /// `user`'s recovery that can still be undone, if any. A start cancels an
    /// unused link and is refused during a probation, so it is the latest.
    pub(crate) async fn undoable(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
    ) -> Result<Option<UndoableRecovery>, DatabaseError> {
        let latest = tx.recoveries().latest(user).await?;
        Ok(latest.and_then(UndoableRecovery::of))
    }

    /// `user`'s recovery `id`, if it is the one that can still be undone.
    async fn undoable_named(
        tx: &mut DatabaseTransaction<'_>,
        user: UserId,
        id: RecoveryId,
    ) -> Result<UndoableRecovery, AccountError> {
        Ok(Self::undoable(tx, user)
            .await?
            .filter(|undoable| undoable.recovery.id == id)
            .ok_or(RecoveryError::NothingToUndo)?)
    }

    /// The account's active passkeys, split into `undoable`'s own, if still
    /// active, and every other, which may undo it.
    async fn split(
        tx: &mut DatabaseTransaction<'_>,
        undoable: &UndoableRecovery,
    ) -> Result<(Option<StoredPasskey>, Vec<StoredPasskey>), DatabaseError> {
        let own = undoable.passkey();
        let (own, others) = tx
            .passkeys()
            .list_active(undoable.recovery.user_id)
            .await?
            .into_iter()
            .partition::<Vec<_>, _>(|passkey| Some(passkey.id) == own);
        Ok((own.into_iter().next(), others))
    }
}

/// Database-backed recovery scenarios.
#[cfg(test)]
mod tests;
