//! Every administrative operation, shared by the admin API and the CLI.

use super::{
    AdminError,
    types::{AuditPage, ClientView, CreatedInvitation, InviteExpiry, Reason, UserDetail, UserPage},
};
use crate::passkey::PasskeyView;
use chrono::Utc;
use piquel_auth_protocol::{AccountStatus, SessionId, TokenId, UserId};
use piquel_common::Origin;
use piquel_crypto::Secret;
use piquel_repository::{
    Actor, AuditAction, AuditFilter, Database, DatabaseError, DatabaseTransaction,
    StoredAdministrator, StoredInvitation, StoredUser,
};

/// Accounts per search page.
const USER_PAGE_SIZE: u16 = 50;
/// Entries per audit page.
const AUDIT_PAGE_SIZE: u16 = 100;
/// Registration page used by generated signup links.
const REGISTRATION_PATH: &str = "/register";
/// Invitation proof sent to the registration page.
const INVITATION_PARAMETER: &str = "invitation";

/// Owns each administrative operation. HTTP handlers and CLI commands are thin
/// adapters that pass their [`Actor`]; every mutation, and viewing an account's
/// details, records an audit entry attributed to it in the same transaction.
///
/// Operations on accounts refuse administrator accounts unless the actor is the
/// CLI, so a stolen admin session cannot lock out other administrators.
#[derive(Clone)]
pub struct AdminOperations {
    /// Accounts, sessions, invitations, clients and the audit log.
    database: Database,
    /// Auth origin that serves the registration page invitations link to.
    origin: Origin,
}

impl AdminOperations {
    /// Operates on `database`, linking invitations to registration on `origin`.
    #[must_use]
    pub const fn new(database: Database, origin: Origin) -> Self {
        Self { database, origin }
    }

    /// Locks the account and refuses administrator accounts unless the CLI acts.
    async fn lock_target(
        tx: &mut DatabaseTransaction<'_>,
        actor: &Actor,
        user_id: UserId,
    ) -> Result<StoredUser, AdminError> {
        let user = tx
            .users()
            .find_by_id_for_update(user_id)
            .await?
            .ok_or(AdminError::UserNotFound)?;
        match actor {
            Actor::Admin { .. } if tx.administrators().contains(user_id).await? => {
                Err(AdminError::AdministratorTarget)
            }
            Actor::Admin { .. } | Actor::Cli { .. } => Ok(user),
        }
    }

    /// Finds the account named `username`, in any status.
    async fn named(
        tx: &mut DatabaseTransaction<'_>,
        username: &str,
    ) -> Result<StoredUser, AdminError> {
        tx.users()
            .find_by_username(username)
            .await?
            .ok_or(AdminError::UserNotFound)
    }

    /// Lists accounts matching `query`, by ID, after the `cursor` of a previous page.
    pub(crate) async fn search_users(
        &self,
        query: &str,
        cursor: Option<UserId>,
    ) -> Result<UserPage, AdminError> {
        let users = self
            .database
            .users()
            .search(query.trim(), cursor, USER_PAGE_SIZE)
            .await?;
        let next = (users.len() == usize::from(USER_PAGE_SIZE))
            .then(|| users.last().map(|user| user.id))
            .flatten();
        Ok(UserPage { users, next })
    }

    /// Returns an account's profile, emails, status, passkey labels, identities,
    /// sessions and consents. Recorded, since it exposes personal data.
    pub(crate) async fn view_user(
        &self,
        actor: &Actor,
        user_id: UserId,
    ) -> Result<UserDetail, AdminError> {
        let mut tx = self.database.begin().await?;
        let user = tx
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(AdminError::UserNotFound)?;
        let detail = UserDetail {
            administrator: tx.administrators().contains(user_id).await?,
            emails: tx.emails().list_for_user(user_id).await?,
            passkeys: tx
                .passkeys()
                .list_active(user_id)
                .await?
                .into_iter()
                .map(PasskeyView::from)
                .collect(),
            identities: tx.federation().list_active(user_id).await?,
            sessions: tx.sessions().list_active_for_user(user_id).await?,
            consents: tx.oidc().list_consents(user_id).await?,
            user,
        };
        tx.audit_events()
            .record_by(actor, Some(user_id), AuditAction::AdminUserView, None)
            .await?;
        tx.commit().await?;
        Ok(detail)
    }

    /// Disables an account and revokes all its sessions and refresh grants in one
    /// transaction, so its next request and token refresh fail.
    pub(crate) async fn disable_user(
        &self,
        actor: &Actor,
        user_id: UserId,
        reason: &Reason,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        Self::lock_target(&mut tx, actor, user_id).await?;
        if !tx
            .users()
            .set_status(user_id, AccountStatus::Disabled)
            .await?
        {
            return Err(AdminError::AlreadyDisabled);
        }
        Self::end_sessions(&mut tx, user_id).await?;
        tx.audit_events()
            .record_by(
                actor,
                Some(user_id),
                AuditAction::AdminUserDisable,
                Some(reason.as_str()),
            )
            .await?;
        Ok(tx.commit().await?)
    }

    /// Reactivates a disabled account. Fails if another active account claimed one
    /// of its verified emails meanwhile.
    pub(crate) async fn enable_user(
        &self,
        actor: &Actor,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        Self::lock_target(&mut tx, actor, user_id).await?;
        let changed = tx
            .users()
            .set_status(user_id, AccountStatus::Active)
            .await
            .map_err(|error| match error {
                DatabaseError::Conflict(_) => AdminError::EmailClaimed(error),
                DatabaseError::NotFound
                | DatabaseError::Timeout(_)
                | DatabaseError::InvalidStoredData { .. }
                | DatabaseError::Operation(_) => error.into(),
            })?;
        if !changed {
            return Err(AdminError::AlreadyActive);
        }
        tx.audit_events()
            .record_by(actor, Some(user_id), AuditAction::AdminUserEnable, None)
            .await?;
        Ok(tx.commit().await?)
    }

    /// Revokes every session and refresh grant of an account.
    pub(crate) async fn revoke_user_sessions(
        &self,
        actor: &Actor,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        Self::lock_target(&mut tx, actor, user_id).await?;
        Self::end_sessions(&mut tx, user_id).await?;
        tx.audit_events()
            .record_by(actor, Some(user_id), AuditAction::AdminSessionsRevoke, None)
            .await?;
        Ok(tx.commit().await?)
    }

    /// Revokes the account's sessions, then its refresh grants, in lock order.
    async fn end_sessions(
        tx: &mut DatabaseTransaction<'_>,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        tx.sessions().revoke_all_for_user(user_id).await?;
        tx.tokens().revoke_all_for_user(user_id).await?;
        Ok(())
    }

    /// Revokes one active session and the refresh grants issued from it.
    pub(crate) async fn revoke_session(
        &self,
        actor: &Actor,
        session_id: SessionId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        // The owner never changes, so it can be read before taking the account lock.
        let session = tx
            .sessions()
            .find_by_id(session_id)
            .await?
            .filter(|session| session.revoked_at.is_none() && session.expires_at > Utc::now())
            .ok_or(AdminError::SessionNotFound)?;
        Self::lock_target(&mut tx, actor, session.user_id).await?;
        tx.oidc().revoke_session(session_id).await?;
        tx.audit_events()
            .record_by(
                actor,
                Some(session.user_id),
                AuditAction::AdminSessionRevoke,
                None,
            )
            .await?;
        Ok(tx.commit().await?)
    }

    /// Lists invitations that have not been purged yet, newest first.
    pub(crate) async fn list_invitations(&self) -> Result<Vec<StoredInvitation>, AdminError> {
        Ok(self.database.security().list_invitations().await?)
    }

    /// Creates a single-use signup link. Only the secret's digest is stored, so the
    /// link cannot be shown again.
    ///
    /// # Errors
    /// Fails when secret generation or persistence fails.
    pub async fn create_invitation(
        &self,
        actor: &Actor,
        expires_in: InviteExpiry,
    ) -> Result<CreatedInvitation, AdminError> {
        let secret = Secret::generate()?;
        let id = TokenId::new();
        let expires_at = Utc::now() + expires_in.duration();
        let mut tx = self.database.begin().await?;
        tx.security()
            .create_invitation(id, secret.digest().as_bytes(), expires_at, actor)
            .await?;
        tx.audit_events()
            .record_by(actor, None, AuditAction::AdminInvitationCreate, None)
            .await?;
        tx.commit().await?;
        let mut url = self.origin.url(REGISTRATION_PATH);
        url.query_pairs_mut()
            .append_pair(INVITATION_PARAMETER, &secret.encoded());
        Ok(CreatedInvitation {
            id,
            url,
            expires_at,
        })
    }

    /// Revokes an unredeemed invitation.
    pub(crate) async fn revoke_invitation(
        &self,
        actor: &Actor,
        id: TokenId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        if !tx.security().revoke_invitation(id).await? {
            return Err(AdminError::InvitationNotFound);
        }
        tx.audit_events()
            .record_by(actor, None, AuditAction::AdminInvitationRevoke, None)
            .await?;
        Ok(tx.commit().await?)
    }

    /// Lists every OIDC client, enabled or not.
    pub(crate) async fn list_clients(&self) -> Result<Vec<ClientView>, AdminError> {
        Ok(self
            .database
            .oidc()
            .list_clients()
            .await?
            .into_iter()
            .map(ClientView::from)
            .collect())
    }

    /// Describes one OIDC client.
    pub(crate) async fn client(&self, id: &str) -> Result<ClientView, AdminError> {
        self.database
            .oidc()
            .find_client(id)
            .await?
            .map(ClientView::from)
            .ok_or(AdminError::ClientNotFound)
    }

    /// Returns a page of audit entries matching `filter`, newest first.
    pub(crate) async fn audit(&self, filter: AuditFilter) -> Result<AuditPage, AdminError> {
        let entries = self
            .database
            .audit_events()
            .list(filter, AUDIT_PAGE_SIZE)
            .await?;
        let next = (entries.len() == usize::from(AUDIT_PAGE_SIZE))
            .then(|| entries.last().map(|entry| entry.id))
            .flatten();
        Ok(AuditPage { entries, next })
    }

    /// Makes the active account `username` an administrator. Only the CLI calls this;
    /// no HTTP route grants administrator rights.
    ///
    /// # Errors
    /// Fails when the account is unknown, disabled or already an administrator.
    pub async fn grant_administrator(
        &self,
        actor: &Actor,
        username: &str,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        let user = Self::named(&mut tx, username).await?;
        match user.status {
            AccountStatus::Active => {}
            AccountStatus::Disabled => return Err(AdminError::AccountDisabled),
        }
        if !tx.administrators().grant(user.id, actor).await? {
            return Err(AdminError::AlreadyAdministrator);
        }
        tx.audit_events()
            .record_by(actor, Some(user.id), AuditAction::AdminGrant, None)
            .await?;
        Ok(tx.commit().await?)
    }

    /// Removes the administrator rights of the account `username`. Only the CLI
    /// calls this; no HTTP route revokes administrator rights.
    ///
    /// # Errors
    /// Fails when the account is unknown or not an administrator.
    pub async fn revoke_administrator(
        &self,
        actor: &Actor,
        username: &str,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        let user = Self::named(&mut tx, username).await?;
        if !tx.administrators().revoke(user.id).await? {
            return Err(AdminError::NotAdministrator);
        }
        tx.audit_events()
            .record_by(actor, Some(user.id), AuditAction::AdminRevoke, None)
            .await?;
        Ok(tx.commit().await?)
    }

    /// Lists every administrator, oldest grant first.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_administrators(&self) -> Result<Vec<StoredAdministrator>, AdminError> {
        Ok(self.database.administrators().list().await?)
    }
}
