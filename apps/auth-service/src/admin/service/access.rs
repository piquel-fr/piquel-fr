//! Who may join and who administers: signup invitations and administrator
//! rights.

use super::AdminService;
use crate::{
    account::AccountService,
    admin::{AdminError, InviteExpiry, Operator},
    routes,
};
use chrono::Utc;
use sourceorigin_common::{
    AccountStatus, TokenId, UserId,
    admin::{Administrator, CreatedInvitation, Invitation},
    config::Origin,
    events::DomainEvent,
};
use sourceorigin_crypto::Secret;
use sourceorigin_ui::{LoginQuery, Query};

impl AdminService {
    /// Lists invitations that have not been purged yet, newest first.
    pub(crate) async fn list_invitations(
        &self,
        operator: &Operator,
    ) -> Result<Vec<Invitation>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self.database.security().list_invitations().await?)
    }

    /// Creates a single-use signup link to the registration page on `origin`, auth's
    /// own. Only the secret's digest is stored, so the link cannot be shown again.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, or secret generation or
    /// persistence fails.
    pub async fn create_invitation(
        &self,
        operator: &Operator,
        origin: &Origin,
        expires_in: InviteExpiry,
    ) -> Result<CreatedInvitation, AdminError> {
        let secret = Secret::generate()?;
        let id = TokenId::new();
        let expires_at = Utc::now() + expires_in.duration();
        let mut tx = self.database.begin().await?;
        tx.security()
            .create_invitation(id, secret.digest().as_bytes(), expires_at)
            .await?;
        let created = DomainEvent::InvitationCreated { expires_at };
        Self::finish(tx, operator, None, vec![created]).await?;
        let url = LoginQuery {
            invitation: Some(secret.encoded()),
            ..LoginQuery::default()
        }
        .url(origin.as_url(), routes::page::REGISTER)?;
        Ok(CreatedInvitation {
            id,
            url,
            expires_at,
        })
    }

    /// Revokes an unredeemed invitation.
    pub(crate) async fn revoke_invitation(
        &self,
        operator: &Operator,
        invitation_id: TokenId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        if !tx.security().revoke_invitation(invitation_id).await? {
            return Err(AdminError::InvitationNotFound);
        }
        let revoked = DomainEvent::InvitationRevoked { invitation_id };
        Self::finish(tx, operator, None, vec![revoked]).await
    }

    /// Lists every administrator, oldest grant first.
    ///
    /// # Errors
    /// Fails when the operator may not read, or the query fails.
    pub async fn list_administrators(
        &self,
        operator: &Operator,
    ) -> Result<Vec<Administrator>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self.database.administrators().list().await?)
    }

    /// Makes the active account `user_id` an administrator. Administrators cannot
    /// grant themselves rights: one whose rights were revoked while the request
    /// waited would otherwise restore them. While a recovery of the account can
    /// still be undone, it is refused, by the CLI too: granted during a probation,
    /// the rights would go live for whoever used its link once it settles. The
    /// migration's `administrators_no_grant_mid_recovery` backs it for every
    /// writer.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, or the account is unknown,
    /// disabled, already an administrator, the caller's own, or has a recovery
    /// that can still be undone.
    pub(crate) async fn grant_administrator(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        operator.refuse_own_rights(user_id)?;
        let mut tx = self.database.begin().await?;
        tx.administrators().lock().await?;
        let user = tx
            .users()
            .find_by_id_for_update(user_id)
            .await?
            .ok_or(AdminError::UserNotFound)?;
        if user.status != AccountStatus::Active {
            return Err(AdminError::AccountDisabled);
        }
        if AccountService::undoable(&mut tx, user_id).await?.is_some() {
            return Err(AdminError::GrantDuringRecovery);
        }
        if !tx.administrators().grant(user_id).await? {
            return Err(AdminError::AlreadyAdministrator);
        }
        let granted = DomainEvent::AdministratorGranted {};
        Self::finish(tx, operator, Some(user_id), vec![granted]).await
    }

    /// Removes the administrator rights of `user_id`. Administrators cannot remove
    /// their own, and nobody can remove the last active administrator's: someone
    /// must be left to administer.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, the account is not an
    /// administrator, or either rule forbids it.
    pub async fn revoke_administrator(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        operator.refuse_own_rights(user_id)?;
        let mut tx = self.database.begin().await?;
        let locked = tx.administrators().lock().await?;
        if tx.administrators().is_last_active(&locked, user_id).await? {
            return Err(AdminError::LastAdministrator);
        }
        if !tx.administrators().revoke(user_id).await? {
            return Err(AdminError::NotAnAdministrator);
        }
        let revoked = DomainEvent::AdministratorRevoked {};
        Self::finish(tx, operator, Some(user_id), vec![revoked]).await
    }
}
