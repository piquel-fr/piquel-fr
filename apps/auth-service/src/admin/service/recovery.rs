//! Recovering an account whose owner lost every passkey, seeing its recent
//! recoveries, and undoing one.

use super::AdminService;
use crate::{
    account::AccountService,
    admin::{AdminError, Operator, Reason},
    emails::EmailApplication,
    recovery::{LINK_LIFETIME, PROBATION, RecoveryLinks, Revoke},
    security::Session,
};
use chrono::Utc;
use sourceorigin_common::{
    AccountStatus, RecoveryId, UserId,
    events::{DomainEvent, EventContext, RecoveryRevocation, RevocationReason},
};
use sourceorigin_repository::{DatabaseTransaction, InsertRecovery, RecentRecovery};
use url::Url;

impl AdminService {
    /// Starts recovering the active account `user_id`, whose owner lost every
    /// passkey, for `reason`, in one transaction. It ends the account's sessions
    /// and refresh grants, removes its unverified addresses, so no verification
    /// link sent before can change it, and cancels an unused older link. Its
    /// current primary verified address is sent a link that enrolls one passkey,
    /// once, within a day. An operator at the terminal is also given the link,
    /// which also reaches an owner without an address. An administrator never
    /// sees it, so they may only start a recovery that mails it, which needs email
    /// enabled.
    ///
    /// With `revoke`, for an account that was in someone else's hands, it first
    /// takes back every way in but the passkeys the owner vouched for: every
    /// other passkey, the last included, every identity and every consent. Its
    /// link is then only printed, and every verified address is told at once.
    ///
    /// Refused for an administrator, whose rights must be revoked first, and while
    /// a recovery of the account is in probation, which support undoes first
    /// ([`Self::undo_recovery`]) once it knows who used it.
    pub(crate) async fn recover_account(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
        links: &RecoveryLinks,
        revoke: Option<Revoke>,
    ) -> Result<Option<Url>, AdminError> {
        let mut tx = self.database.begin().await?;
        let user = operator.lock(&mut tx, user_id).await?;
        if user.status != AccountStatus::Active {
            return Err(AdminError::RecoveryOfDisabledAccount);
        }
        if tx.administrators().contains(user_id).await? {
            return Err(AdminError::RecoveryOfAdministrator);
        }
        if AccountService::undoable(&mut tx, user_id)
            .await?
            .is_some_and(|undoable| undoable.is_probation())
        {
            return Err(AdminError::RecoveryInProbation);
        }
        let shown = matches!(operator, Operator::Cli { .. });
        let emails = tx.emails().list(user_id).await?;
        let mailed = self.mails
            && revoke.is_none()
            && emails
                .iter()
                .any(|email| email.is_primary && email.verified_at.is_some());
        if !mailed && !shown {
            return Err(AdminError::RecoveryNeedsEmail);
        }
        let context = Self::context(operator, reason);
        // Cancelled before any revocation, which the database refuses while a
        // recovery's link works.
        tx.recoveries().cancel_open(user_id).await?;
        let revoke = match revoke {
            Some(revoke) => Some(Self::take_back(&mut tx, &context, user_id, revoke).await?),
            None => None,
        };
        for email in emails.iter().filter(|email| email.verified_at.is_none()) {
            EmailApplication::delete(&mut tx, &context, user_id, email.id).await?;
        }
        let id = RecoveryId::new();
        let token = links.token(id)?;
        let expires_at = Utc::now() + LINK_LIFETIME;
        tx.recoveries()
            .insert(&InsertRecovery {
                id,
                user_id,
                secret_digest: token.digest().as_bytes(),
                expires_at,
            })
            .await?;
        let started = DomainEvent::RecoveryStarted {
            recovery_id: id,
            expires_at,
            revoke,
        };
        tx.record(&context, Some(user_id), started).await?;
        Session::end_all(&mut tx, &context, user_id, RevocationReason::Admin).await?;
        let link = shown.then(|| links.url(&token));
        Self::finish(tx, operator, Some(user_id), vec![]).await?;
        Ok(link)
    }

    /// Takes back every way into `user_id`'s account but the passkeys `revoke`
    /// keeps, recording each change in `context`: every other passkey, the last
    /// included, every identity, and every refresh grant and consent. Fails if a
    /// kept passkey is not an active one of the account, so a typo cannot leave a
    /// stolen one active.
    async fn take_back(
        tx: &mut DatabaseTransaction<'_>,
        context: &EventContext,
        user_id: UserId,
        revoke: Revoke,
    ) -> Result<RecoveryRevocation, AdminError> {
        let passkeys = tx.passkeys().list_active(user_id).await?;
        if let Some(unknown) = revoke
            .keep
            .iter()
            .find(|kept| !passkeys.iter().any(|passkey| passkey.id == **kept))
        {
            return Err(AdminError::UnknownPasskey(*unknown));
        }
        let mut revoked = Vec::new();
        for passkey in passkeys
            .iter()
            .filter(|passkey| !revoke.keep.contains(&passkey.id))
        {
            if AccountService::take_back_passkey(tx, context, user_id, passkey.id).await? {
                revoked.push(passkey.id);
            }
        }
        for identity in tx.federation().list_active(user_id).await? {
            let provider = identity.provider;
            if tx.federation().unlink(user_id, provider).await? {
                tx.record(
                    context,
                    Some(user_id),
                    DomainEvent::IdentityUnlinked { provider },
                )
                .await?;
            }
        }
        AccountService::withdraw_consents(tx, context, user_id).await?;
        Ok(RecoveryRevocation {
            revoked,
            kept: revoke.keep,
        })
    }

    /// The account's recoveries started or used within the last [`PROBATION`],
    /// newest first, with where each stands and the passkey each enrolled, those
    /// undone included, so support sees a repeated attempt before starting
    /// another. Recorded, as a view of the account.
    pub(crate) async fn recent_recoveries(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<Vec<RecentRecovery>, AdminError> {
        operator.authorize_read(&self.database).await?;
        let mut tx = self.database.begin().await?;
        let since = Utc::now() - PROBATION;
        let recent = tx.recoveries().recent(user_id, since).await?;
        operator.record_view(&mut tx, user_id).await?;
        tx.commit().await?;
        Ok(recent)
    }

    /// Undoes the account's recovery that can still be undone, for `reason`, as
    /// support does once it has confirmed the owner, who may have no passkey left
    /// from before it, or whose account is disabled. In probation, it takes back
    /// the recovery's passkey, even the account's last, every consent, every
    /// session and every refresh grant, each change recording `reason`; support
    /// then starts a new recovery if the owner needs one. Its link unused, it
    /// only cancels the link.
    pub(crate) async fn undo_recovery(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        operator.lock(&mut tx, user_id).await?;
        let recovery = AccountService::undoable(&mut tx, user_id)
            .await?
            .ok_or(AdminError::NoRecoveryToUndo)?;
        let context = Self::context(operator, reason);
        AccountService::revert(&mut tx, &context, &recovery, RevocationReason::Admin).await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }
}
