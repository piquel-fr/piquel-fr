//! Every administrative operation, shared by the admin API and the CLI.

use super::{AdminError, HandleIssue, HandleProblem, InviteExpiry, Operator, Reason};
use chrono::Utc;
use piquel_admin_api::{
    Administrator, Client, CreatedInvitation, Event, EventPage, EventSearch, Invitation,
    UserDetail, UserPage,
};
use piquel_common::{
    AccountStatus, Handle, Personal, SessionId, TokenId, UserId,
    config::Origin,
    events::{DomainEvent, RevocationReason},
};
use piquel_crypto::Secret;
use piquel_repository::{
    Database, DatabaseError, DatabaseTransaction, EventFilter, SessionScope, StoredUser,
};
use std::collections::BTreeMap;

/// Accounts per search page.
const USER_PAGE_SIZE: u16 = 50;
/// Events per page.
const EVENT_PAGE_SIZE: u16 = 100;
/// Registration page used by generated signup links.
const REGISTRATION_PATH: &str = "/register";
/// Invitation proof sent to the registration page.
const INVITATION_PARAMETER: &str = "invitation";

/// Owns each administrative operation. HTTP handlers and CLI commands are thin
/// adapters that say which [`Operator`] acts. Every mutation, and viewing an
/// account's details, records a domain event attributed to it in the same
/// transaction.
///
/// Mutations recheck that an administrator still holds their rights, session and
/// confirmation after their last write, just before committing. Those on accounts refuse
/// administrator accounts unless the CLI acts, so a stolen admin token cannot lock
/// other administrators out; revoking their rights comes first, and is itself
/// guarded.
#[derive(Clone)]
pub struct AdminOperations {
    /// Accounts, sessions, invitations, clients, events and administrators.
    database: Database,
}

impl AdminOperations {
    /// Operates on `database`.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Locks the account `user_id` and refuses an administrator's unless the CLI
    /// acts. Granting rights takes the same account lock, so the account cannot
    /// become an administrator before `tx` commits. A known administrator is
    /// refused before waiting for the lock, too.
    async fn lock_target(
        tx: &mut DatabaseTransaction<'_>,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<StoredUser, AdminError> {
        let checked = operator.administrator().is_some();
        if checked && tx.administrators().contains(user_id).await? {
            return Err(AdminError::AdministratorTarget);
        }
        let user = tx
            .users()
            .find_by_id_for_update(user_id)
            .await?
            .ok_or(AdminError::UserNotFound)?;
        if checked && tx.administrators().contains(user_id).await? {
            return Err(AdminError::AdministratorTarget);
        }
        Ok(user)
    }

    /// Ends every mutation: rechecks `operator`, records `events` about `subject`,
    /// then commits. The check runs after the mutation's last write, so it waits
    /// for nothing afterwards, and a failure rolls the writes back.
    async fn finish(
        mut tx: DatabaseTransaction<'_>,
        operator: &Operator,
        subject: Option<UserId>,
        events: Vec<DomainEvent>,
    ) -> Result<(), AdminError> {
        operator.authorize(&mut tx).await?;
        let context = operator.context();
        for event in events {
            tx.record(&context, subject, event).await?;
        }
        Ok(tx.commit().await?)
    }

    /// The ID of the account named `username`, in any status.
    ///
    /// # Errors
    /// Fails when no account has this username.
    pub async fn user_named(&self, username: &str) -> Result<UserId, AdminError> {
        Ok(self
            .database
            .users()
            .find_by_username(username)
            .await?
            .ok_or(AdminError::UserNotFound)?
            .id)
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
    /// sessions and consents. Recorded, since it shows personal data.
    pub(crate) async fn view_user(
        &self,
        operator: &Operator,
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
            passkeys: Self::views(tx.passkeys().list_active(user_id).await?),
            identities: Self::views(tx.federation().list_active(user_id).await?),
            sessions: tx
                .sessions()
                .list_active_for_user(user_id)
                .await?
                .into_iter()
                .map(Into::into)
                .collect(),
            consents: tx.oidc().list_consents(user_id).await?,
            user: user.into(),
        };
        tx.record(
            &operator.context(),
            Some(user_id),
            DomainEvent::AccountViewed {},
        )
        .await?;
        tx.commit().await?;
        Ok(detail)
    }

    /// Shows each stored record without what the API never returns.
    fn views<S: Into<T>, T>(records: Vec<S>) -> Vec<T> {
        records.into_iter().map(Into::into).collect()
    }

    /// Disables an account and ends all its sessions and refresh grants in one
    /// transaction, so its next request and token refresh fail.
    pub(crate) async fn disable_user(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        Self::lock_target(&mut tx, operator, user_id).await?;
        if !tx
            .users()
            .set_status(user_id, AccountStatus::Disabled)
            .await?
        {
            return Err(AdminError::AlreadyDisabled);
        }
        let disabled = DomainEvent::AccountDisabled {
            reason: Personal::Value(reason.into_inner()),
        };
        tx.record(&operator.context(), Some(user_id), disabled)
            .await?;
        Self::end_sessions(
            &mut tx,
            operator,
            user_id,
            RevocationReason::AccountDisabled,
        )
        .await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Reactivates a disabled account. Fails if another active account claimed one
    /// of its verified emails meanwhile.
    pub(crate) async fn enable_user(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        Self::lock_target(&mut tx, operator, user_id).await?;
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
        Self::finish(
            tx,
            operator,
            Some(user_id),
            vec![DomainEvent::AccountEnabled {}],
        )
        .await
    }

    /// Ends every session and refresh grant of an account.
    pub(crate) async fn revoke_user_sessions(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        Self::lock_target(&mut tx, operator, user_id).await?;
        Self::end_sessions(&mut tx, operator, user_id, RevocationReason::Admin).await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Revokes the account's sessions, recording each as `operator`'s, then its
    /// refresh grants. Callers hold the account lock.
    async fn end_sessions(
        tx: &mut DatabaseTransaction<'_>,
        operator: &Operator,
        user_id: UserId,
        reason: RevocationReason,
    ) -> Result<(), AdminError> {
        tx.revoke_sessions(&operator.context(), user_id, SessionScope::All, &reason)
            .await?;
        tx.tokens().revoke_all_for_user(user_id).await?;
        Ok(())
    }

    /// Ends one active session and the refresh grants issued from it.
    pub(crate) async fn revoke_session(
        &self,
        operator: &Operator,
        session_id: SessionId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        // The owner never changes, so it can be read before taking the account lock.
        let session = tx
            .sessions()
            .find_by_id(session_id)
            .await?
            .ok_or(AdminError::SessionNotFound)?;
        Self::lock_target(&mut tx, operator, session.user_id).await?;
        if tx
            .revoke_sessions(
                &operator.context(),
                session.user_id,
                SessionScope::One(session_id),
                &RevocationReason::Admin,
            )
            .await?
            .is_empty()
        {
            return Err(AdminError::SessionNotFound);
        }
        Self::finish(tx, operator, Some(session.user_id), vec![]).await
    }

    /// Lists invitations that have not been purged yet, newest first.
    pub(crate) async fn list_invitations(&self) -> Result<Vec<Invitation>, AdminError> {
        Ok(self.database.security().list_invitations().await?)
    }

    /// Creates a single-use signup link to the registration page on `origin`, auth's
    /// own. Only the secret's digest is stored, so the link cannot be shown again.
    ///
    /// # Errors
    /// Fails when secret generation or persistence fails.
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
        let mut url = origin.url(REGISTRATION_PATH);
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

    /// Lists every OIDC client, enabled or not.
    pub(crate) async fn list_clients(&self) -> Result<Vec<Client>, AdminError> {
        Ok(Self::views(self.database.oidc().list_clients().await?))
    }

    /// Describes one OIDC client.
    pub(crate) async fn client(&self, id: &str) -> Result<Client, AdminError> {
        self.database
            .oidc()
            .find_client(id)
            .await?
            .map(Into::into)
            .ok_or(AdminError::ClientNotFound)
    }

    /// Returns a page of the events matching `search`, newest first.
    pub(crate) async fn events(&self, search: EventSearch) -> Result<EventPage, AdminError> {
        let filter = EventFilter {
            subject: search.user,
            kind: search.kind,
            before: search.before,
            id: None,
        };
        let stored = self
            .database
            .events()
            .list(&filter, u32::from(EVENT_PAGE_SIZE))
            .await?;
        let next = (stored.len() == usize::from(EVENT_PAGE_SIZE))
            .then(|| stored.last().map(|event| event.id))
            .flatten();
        let events = stored
            .into_iter()
            .map(|stored| {
                Ok(Event {
                    id: stored.id,
                    occurred_at: stored.occurred_at,
                    actor: serde_json::to_value(stored.actor)?,
                    subject: stored.subject,
                    trace_id: stored.trace_id,
                    event: serde_json::to_value(stored.event)?,
                })
            })
            .collect::<Result<_, serde_json::Error>>()?;
        Ok(EventPage { events, next })
    }

    /// Lists the accounts whose login name the handle rules refuse, by name: it
    /// breaks the syntax, is reserved, or shares its skeleton with another account's.
    /// Reserved names an operator assigned on purpose are listed too.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn check_handles(&self) -> Result<Vec<HandleProblem>, AdminError> {
        let names: Vec<_> = self
            .database
            .users()
            .list_names()
            .await?
            .into_iter()
            .map(|name| {
                let handle = name.username.parse::<Handle>();
                (name, handle)
            })
            .collect();
        let mut skeletons = BTreeMap::<String, Vec<&str>>::new();
        for (name, handle) in &names {
            if let Ok(handle) = handle {
                skeletons
                    .entry(handle.skeleton())
                    .or_default()
                    .push(&name.username);
            }
        }
        Ok(names
            .iter()
            .filter_map(|(name, handle)| {
                let issue = match handle.clone().and_then(|handle| {
                    handle.ensure_unreserved()?;
                    Ok(handle)
                }) {
                    Err(error) => HandleIssue::Refused(error),
                    Ok(handle) => {
                        let others: Vec<String> = skeletons[&handle.skeleton()]
                            .iter()
                            .filter(|other| **other != name.username)
                            .map(|other| (*other).to_owned())
                            .collect();
                        if others.is_empty() {
                            return None;
                        }
                        HandleIssue::LooksLike(others)
                    }
                };
                Some(HandleProblem {
                    user_id: name.id,
                    username: name.username.clone(),
                    issue,
                })
            })
            .collect())
    }

    /// Gives the account `user_id` the handle `handle`, unless another account has
    /// it. Reserved names are refused unless `allow_reserved`. The account's profile
    /// version is bumped, so relying parties refresh `preferred_username`.
    ///
    /// Look-alikes are not checked here: only the next release's `handles` table can
    /// enforce them atomically, and with an index. [`Self::check_handles`] lists
    /// them, and that release's migration refuses to run while any remain.
    ///
    /// # Errors
    /// Fails when the account is unknown or already has the handle, or the handle is
    /// reserved or taken.
    pub async fn rename_handle(
        &self,
        operator: &Operator,
        user_id: UserId,
        handle: Handle,
        allow_reserved: bool,
    ) -> Result<(), AdminError> {
        if !allow_reserved {
            handle.ensure_unreserved()?;
        }
        let mut tx = self.database.begin().await?;
        let user = Self::lock_target(&mut tx, operator, user_id).await?;
        if user.username == handle.as_str() {
            return Err(AdminError::SameHandle);
        }
        tx.users()
            .rename(user_id, &handle)
            .await
            .map_err(|error| match error {
                DatabaseError::Conflict(_) => AdminError::HandleTaken(error),
                DatabaseError::NotFound
                | DatabaseError::Timeout(_)
                | DatabaseError::InvalidStoredData { .. }
                | DatabaseError::Operation(_) => error.into(),
            })?;
        let changed = DomainEvent::HandleChanged {
            old: Personal::Value(user.username),
            new: Personal::Value(handle),
        };
        Self::finish(tx, operator, Some(user_id), vec![changed]).await
    }

    /// Lists every administrator, oldest grant first.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_administrators(&self) -> Result<Vec<Administrator>, AdminError> {
        Ok(self.database.administrators().list().await?)
    }

    /// Makes the active account `user_id` an administrator. Administrators cannot
    /// grant themselves rights: one whose rights were revoked while the request
    /// waited would otherwise restore them.
    ///
    /// # Errors
    /// Fails when the account is unknown, disabled, already an administrator or the
    /// caller's own.
    pub async fn grant_administrator(
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
        if user.status == AccountStatus::Disabled {
            return Err(AdminError::AccountDisabled);
        }
        if !tx.administrators().grant(user_id).await? {
            return Err(AdminError::AlreadyAdministrator);
        }
        let granted = DomainEvent::AdministratorGranted {};
        Self::finish(tx, operator, Some(user_id), vec![granted]).await
    }

    /// Removes the administrator rights of `user_id`. Administrators cannot remove
    /// their own, and nobody can remove the last administrator's: someone must be
    /// left to administer.
    ///
    /// # Errors
    /// Fails when the account is not an administrator, or either rule forbids it.
    pub async fn revoke_administrator(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        operator.refuse_own_rights(user_id)?;
        let mut tx = self.database.begin().await?;
        tx.administrators().lock().await?;
        let administrators = tx.administrators().list().await?;
        if !administrators.iter().any(|admin| admin.user_id == user_id) {
            return Err(AdminError::NotAnAdministrator);
        }
        if administrators.len() == 1 {
            return Err(AdminError::LastAdministrator);
        }
        tx.administrators().revoke(user_id).await?;
        let revoked = DomainEvent::AdministratorRevoked {};
        Self::finish(tx, operator, Some(user_id), vec![revoked]).await
    }
}
