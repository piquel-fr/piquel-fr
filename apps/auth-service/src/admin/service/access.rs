//! Who may join and who administers: signup invitations and administrator
//! rights.

use super::AdminService;
use crate::{
    account::AccountService,
    admin::{AdminError, DashboardSignIn, InviteExpiry, Operator, Reason},
    invitations::InvitationLinks,
};
use chrono::Utc;
use sourceorigin_common::{
    AccountStatus, Personal, TokenId, UserId,
    admin::{Administrator, CreatedInvitation, Invitation, InvitationSent},
    email::NormalizedEmail,
    events::DomainEvent,
};
use sourceorigin_repository::{InsertInvitation, InvitationKey};

impl AdminService {
    /// Lists invitations that have not been purged yet, newest first.
    pub(crate) async fn list_invitations(
        &self,
        operator: &Operator,
    ) -> Result<Vec<Invitation>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(self.database.security().list_invitations().await?)
    }

    /// Creates a single-use signup invitation, valid for `expires_in`, for
    /// `reason`, whatever the signup setting: while signup is open, it is a
    /// tracked signup link. With an `email`, its link is mailed there, and the
    /// account created with it starts with that address, verified; it is refused
    /// before anything is created while email is disabled, or when an active
    /// account already holds the address verified. Without one, its link is
    /// returned for the operator to pass on: only its token's digest is stored, so
    /// it is never shown again.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, the invitation cannot be
    /// mailed, or token derivation or persistence fails.
    pub(crate) async fn create_invitation(
        &self,
        operator: &Operator,
        links: &InvitationLinks,
        expires_in: InviteExpiry,
        email: Option<NormalizedEmail>,
        reason: Reason,
    ) -> Result<CreatedInvitation, AdminError> {
        if email.is_some() && !self.mails {
            return Err(AdminError::InvitationNeedsEmail);
        }
        let id = TokenId::new();
        let token = links.token(id)?;
        let expires_at = Utc::now() + expires_in.duration();
        let mut tx = self.database.begin().await?;
        if let Some(email) = &email
            && tx
                .emails()
                .find_active_verified(email.as_str())
                .await?
                .is_some()
        {
            return Err(AdminError::InvitationAddressTaken);
        }
        tx.security()
            .create_invitation(&InsertInvitation {
                id,
                secret_digest: token.digest().as_bytes(),
                expires_at,
                email: email.as_ref().map(NormalizedEmail::as_str),
            })
            .await?;
        let mut events = vec![DomainEvent::InvitationCreated {
            invitation_id: id,
            expires_at,
        }];
        let sent = match email {
            Some(email) => {
                events.push(Self::mailed(id, email.clone()));
                InvitationSent::Mailed(email.into())
            }
            None => InvitationSent::Link(links.url(&token)),
        };
        Self::finish(tx, operator, &reason, None, events).await?;
        Ok(CreatedInvitation {
            id,
            sent,
            expires_at,
        })
    }

    /// Mails an open invitation's link again, to the address it was mailed to,
    /// for `reason`. The link and its expiry stay the same: to give more time,
    /// revoke it and invite again.
    pub(crate) async fn resend_invitation(
        &self,
        operator: &Operator,
        invitation_id: TokenId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        if !self.mails {
            return Err(AdminError::InvitationNeedsEmail);
        }
        let mut tx = self.database.begin().await?;
        let invitation = tx
            .security()
            .open_invitation(InvitationKey::Id(invitation_id))
            .await?
            .ok_or(AdminError::InvitationNotFound)?;
        let email = invitation.email.ok_or(AdminError::InvitationNotMailed)?;
        let mailed = Self::mailed(invitation_id, NormalizedEmail::parse(&email)?);
        Self::finish(tx, operator, &reason, None, vec![mailed]).await
    }

    /// The event mailing invitation `invitation_id` to `email`, which queues its
    /// email.
    fn mailed(invitation_id: TokenId, email: NormalizedEmail) -> DomainEvent {
        DomainEvent::InvitationMailed {
            invitation_id,
            recipient: Personal::Value(email),
        }
    }

    /// Revokes an unredeemed invitation, for `reason`.
    pub(crate) async fn revoke_invitation(
        &self,
        operator: &Operator,
        invitation_id: TokenId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        if !tx.security().revoke_invitation(invitation_id).await? {
            return Err(AdminError::InvitationNotFound);
        }
        let revoked = DomainEvent::InvitationRevoked { invitation_id };
        Self::finish(tx, operator, &reason, None, vec![revoked]).await
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

    /// Makes the active account `user_id` an administrator, for `reason`, which
    /// its owner sees in their history. Administrators cannot
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
        reason: Reason,
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
        Self::finish(tx, operator, &reason, Some(user_id), vec![granted]).await
    }

    /// Removes the administrator rights of `user_id`, for `reason`, which its owner
    /// sees in their history, and ends its dashboard sessions with them, and the
    /// handoffs that would start one: rights granted again later revive none.
    /// Administrators cannot remove their own, and nobody can remove the last
    /// active administrator's: someone must be left to administer.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, the account is not an
    /// administrator, or either rule forbids it.
    pub async fn revoke_administrator(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
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
        let ended = tx
            .dashboard()
            .end_of_user(user_id, DashboardSignIn::idle_since())
            .await?;
        let signed_out = ended
            .into_iter()
            .map(|session_id| DomainEvent::DashboardSignedOut { session_id });
        let events = std::iter::once(DomainEvent::AdministratorRevoked {})
            .chain(signed_out)
            .collect();
        Self::finish(tx, operator, &reason, Some(user_id), events).await
    }
}
