//! Accounts: finding, searching and viewing them, disabling, enabling and
//! deleting them, ending their sessions, and their handles.

use super::AdminService;
use crate::{
    admin::{AdminError, HandleProblem, Operator, Reason, UserRef},
    deletion::Deletions,
    handles::Handles,
    security::Session,
};
use piquel_common::{
    AccountStatus, Handle, HandleError, Personal, SessionId, UserId,
    admin::{
        Email, Paging, ReleasedHandle, ReservedHandle, ScheduledDeletion, UserDetail, UserPage,
    },
    email::NormalizedEmail,
    events::{DomainEvent, EventContext, RevocationReason},
};
use piquel_repository::{DatabaseError, DatabaseTransaction, SessionScope, StoredUser};

/// Accounts per search page.
const USER_PAGE_SIZE: u16 = 50;

impl AdminService {
    /// The ID of the account `user` names, in any status; an email names only the
    /// active account that verified it.
    pub(crate) async fn find_user(
        &self,
        operator: &Operator,
        user: &UserRef,
    ) -> Result<UserId, AdminError> {
        operator.authorize_read(&self.database).await?;
        let found = match user {
            UserRef::Id(id) => self
                .database
                .users()
                .find_by_id(*id)
                .await?
                .map(|user| user.id),
            // A name that is not a handle was never stored.
            UserRef::Handle(handle) => match Handle::parse(handle) {
                Ok(handle) => self
                    .database
                    .users()
                    .find_by_handle(&handle)
                    .await?
                    .map(|user| user.id),
                Err(_) => None,
            },
            // An address that cannot be normalized was never stored.
            UserRef::Email(address) => match NormalizedEmail::parse(address) {
                Ok(address) => self
                    .database
                    .emails()
                    .find_active_verified(address.as_str())
                    .await?
                    .map(|email| email.user_id),
                Err(_) => None,
            },
        };
        found.ok_or(AdminError::UserNotFound)
    }

    /// Lists `page` of the accounts matching `query`, by handle: the first page
    /// when `None`.
    pub(crate) async fn search_users(
        &self,
        operator: &Operator,
        query: &str,
        page: Option<u32>,
    ) -> Result<UserPage, AdminError> {
        operator.authorize_read(&self.database).await?;
        let query = query.trim();
        let mut users = self.database.users();
        let total = users.count_matching(query).await?;
        let paging = Paging::new(page, total, u32::from(USER_PAGE_SIZE));
        let users = users.search(query, paging.offset(), USER_PAGE_SIZE).await?;
        Ok(UserPage { users, paging })
    }

    /// Returns an account's profile, emails, status, passkey labels, identities,
    /// sessions, consents and scheduled deletion, with why its purge keeps
    /// failing. Recorded, since it shows personal data.
    pub(crate) async fn view_user(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<UserDetail, AdminError> {
        operator.authorize_read(&self.database).await?;
        let mut tx = self.database.begin().await?;
        let user = tx
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(AdminError::UserNotFound)?;
        let detail = UserDetail {
            administrator: tx.administrators().contains(user_id).await?,
            emails: tx
                .emails()
                .list(user_id)
                .await?
                .into_iter()
                .map(Email::from)
                .collect(),
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
            deletion: match tx.deletions().find(user_id).await? {
                Some(deletion) => Some(ScheduledDeletion {
                    requested_at: deletion.requested_at,
                    purge_after: deletion.purge_after,
                    failure: tx.deletions().failure(user_id).await?,
                }),
                None => None,
            },
            user: user.into(),
        };
        operator.record_view(&mut tx, user_id).await?;
        tx.commit().await?;
        Ok(detail)
    }

    /// Disables an account and ends all its sessions and refresh grants in one
    /// transaction, so its next request and token refresh fail. A recovery link
    /// not used yet stops working, so re-enabling the account does not revive it.
    /// Nobody can disable the last active administrator.
    pub(crate) async fn disable_user(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        let locked = tx.administrators().lock().await?;
        match operator.lock(&mut tx, user_id).await?.status {
            AccountStatus::Active => {}
            AccountStatus::Disabled => return Err(AdminError::AlreadyDisabled),
            AccountStatus::Deleting => return Err(AdminError::DeletionScheduled),
        }
        if tx.administrators().is_last_active(&locked, user_id).await? {
            return Err(AdminError::LastAdministrator);
        }
        tx.users()
            .set_status(user_id, AccountStatus::Disabled)
            .await?;
        let disabled = DomainEvent::AccountDisabled {
            reason: Personal::Value(reason.into_inner()),
        };
        tx.record(&operator.context(), Some(user_id), disabled)
            .await?;
        tx.recoveries().cancel_open(user_id).await?;
        Session::end_all(
            &mut tx,
            &operator.context(),
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
        match operator.lock(&mut tx, user_id).await?.status {
            AccountStatus::Disabled => {}
            AccountStatus::Active => return Err(AdminError::AlreadyActive),
            AccountStatus::Deleting => return Err(AdminError::DeletionScheduled),
        }
        tx.users()
            .set_status(user_id, AccountStatus::Active)
            .await
            .map_err(|error| match error {
                DatabaseError::Conflict(_) => AdminError::EmailClaimed(error),
                DatabaseError::NotFound
                | DatabaseError::Timeout(_)
                | DatabaseError::Cancelled(_)
                | DatabaseError::LockUnavailable(_)
                | DatabaseError::InvalidStoredData { .. }
                | DatabaseError::Operation(_) => error.into(),
            })?;
        Self::finish(
            tx,
            operator,
            Some(user_id),
            vec![DomainEvent::AccountEnabled {}],
        )
        .await
    }

    /// Schedules the deletion of an active account, for `reason`: it can no longer
    /// sign in, its sessions and refresh grants end, and it is purged once its
    /// grace period ends, unless it is restored first. Nobody can delete the last
    /// active administrator's account.
    pub(crate) async fn schedule_deletion(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let (mut tx, user) = self.lock_deletable(operator, user_id).await?;
        Deletions::new(&mut tx, Self::context(operator, reason))
            .schedule(&user)
            .await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Purges an account now, in any status, without a grace period, for
    /// `reason`. It cannot be undone, so only the CLI offers it.
    pub(crate) async fn purge_user(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let (mut tx, user) = self.lock_deletable(operator, user_id).await?;
        Deletions::new(&mut tx, Self::context(operator, reason))
            .purge(&user)
            .await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Restores an account scheduled for deletion, for `reason`. It can sign in
    /// again.
    pub(crate) async fn restore_user(
        &self,
        operator: &Operator,
        user_id: UserId,
        reason: Reason,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        let user = operator.lock(&mut tx, user_id).await?;
        Deletions::new(&mut tx, Self::context(operator, reason))
            .restore(&user)
            .await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Opens the transaction of a deletion and locks its account as
    /// [`Deletions::lock`] does, refusing an administrator's unless the CLI acts.
    async fn lock_deletable(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(DatabaseTransaction<'_>, StoredUser), AdminError> {
        let mut tx = self.database.begin().await?;
        let user = Deletions::lock(&mut tx, user_id).await?;
        // The administrator list is locked, so the answer holds until commit.
        if operator.administrator().is_some() && tx.administrators().contains(user_id).await? {
            return Err(AdminError::AdministratorTarget);
        }
        Ok((tx, user))
    }

    /// Ends every session and refresh grant of an account.
    pub(crate) async fn revoke_user_sessions(
        &self,
        operator: &Operator,
        user_id: UserId,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        operator.lock(&mut tx, user_id).await?;
        Session::end_all(
            &mut tx,
            &operator.context(),
            user_id,
            RevocationReason::Admin,
        )
        .await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
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
        operator.lock(&mut tx, session.user_id).await?;
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

    /// Lists the accounts whose current handle is reserved, by the handle rules or
    /// an administrator, by handle: ones an operator assigned on purpose, or that a
    /// later release or reservation reserved.
    ///
    /// # Errors
    /// Fails when the operator may not read, or the query fails.
    pub async fn check_handles(
        &self,
        operator: &Operator,
    ) -> Result<Vec<HandleProblem>, AdminError> {
        operator.authorize_read(&self.database).await?;
        let mut handles = self.database.handles();
        let reserved = handles.list_reserved().await?;
        Ok(handles
            .list_current()
            .await?
            .into_iter()
            .filter_map(|current| {
                let skeleton = current.handle.skeleton();
                let error = current.handle.ensure_unreserved().err().or_else(|| {
                    reserved
                        .iter()
                        .find(|reservation| reservation.handle.skeleton() == skeleton)
                        .map(|reservation| HandleError::Reserved(reservation.handle.to_string()))
                })?;
                Some(HandleProblem {
                    user_id: current.user_id?,
                    handle: current.handle,
                    error,
                })
            })
            .collect())
    }

    /// Gives the account `user_id` the handle `handle`, for `reason`, as a settings
    /// rename does but without its cooldown. Reserved names, built in or reserved by
    /// an administrator, are refused unless `allow_reserved`. The reason is recorded
    /// with the change, as personal data the owner sees in their history.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, the account is unknown, or
    /// the handle is reserved, taken, retired, a look-alike or already the
    /// account's.
    pub async fn rename_handle(
        &self,
        operator: &Operator,
        user_id: UserId,
        handle: Handle,
        reason: Reason,
        allow_reserved: bool,
    ) -> Result<(), AdminError> {
        if !allow_reserved {
            Handles::new(&self.database)
                .ensure_unreserved(&handle)
                .await?;
        }
        let mut tx = self.database.begin().await?;
        let user = operator.lock(&mut tx, user_id).await?;
        let (mut tx, changed) = Handles::new(&self.database)
            .rename(tx, &user, handle)
            .await?;
        let context = EventContext {
            reason: Some(reason.into_inner()),
            ..operator.context()
        };
        tx.record(&context, Some(user_id), changed).await?;
        Self::finish(tx, operator, Some(user_id), vec![]).await
    }

    /// Deletes the released handle `handle`, or a purged account's last one, so
    /// anyone may claim it again: the only way a handle returns to the pool, for
    /// cases such as a trademark dispute.
    ///
    /// # Errors
    /// Fails when no released handle, or purged account's, is `handle`.
    pub async fn release_handle(
        &self,
        operator: &Operator,
        handle: Handle,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        let released = tx
            .handles()
            .delete_released(&handle)
            .await?
            .ok_or(AdminError::HandleNotReleased)?;
        let event = DomainEvent::HandleReleased {
            handle: Personal::Value(handle),
        };
        Self::finish(tx, operator, released.user_id, vec![event]).await
    }

    /// Lists the handles no account holds but that are kept from others, by
    /// handle: released ones, and purged accounts' last ones. Each may be released.
    ///
    /// # Errors
    /// Fails when the operator may not read, or the query fails.
    pub(crate) async fn list_released_handles(
        &self,
        operator: &Operator,
    ) -> Result<Vec<ReleasedHandle>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(Self::views(self.database.handles().list_released().await?))
    }

    /// Lists the handles administrators reserved, by handle. The handle rules
    /// reserve [`Handle`]'s built-in names too, which no operation changes.
    ///
    /// # Errors
    /// Fails when the operator may not read, or the query fails.
    pub(crate) async fn list_reserved_handles(
        &self,
        operator: &Operator,
    ) -> Result<Vec<ReservedHandle>, AdminError> {
        operator.authorize_read(&self.database).await?;
        Ok(Self::views(self.database.handles().list_reserved().await?))
    }

    /// Reserves `handle` for `reason`, which says who or what it is kept for:
    /// signup and the settings refuse it and its look-alikes until an administrator
    /// gives it to an account, or removes it from the list. An account already
    /// holding it keeps it.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, or the handle rules reserve
    /// it, or a look-alike, already.
    pub(crate) async fn reserve_handle(
        &self,
        operator: &Operator,
        handle: Handle,
        reason: Reason,
    ) -> Result<(), AdminError> {
        if handle.ensure_unreserved().is_err() {
            return Err(AdminError::HandleReserved);
        }
        let context = Self::context(operator, reason);
        let mut tx = self.database.begin().await?;
        let reason = context.reason.as_deref().unwrap_or_default();
        if !tx.handles().reserve(&handle, reason).await? {
            return Err(AdminError::HandleReserved);
        }
        tx.record(&context, None, DomainEvent::HandleReserved { handle })
            .await?;
        Self::finish(tx, operator, None, vec![]).await
    }

    /// Removes `handle` from the reserved list, so anyone may claim it again.
    ///
    /// # Errors
    /// Fails when the operator may not make changes, or no administrator reserved
    /// `handle`.
    pub(crate) async fn unreserve_handle(
        &self,
        operator: &Operator,
        handle: Handle,
    ) -> Result<(), AdminError> {
        let mut tx = self.database.begin().await?;
        if !tx.handles().unreserve(&handle).await? {
            return Err(AdminError::HandleNotReserved);
        }
        let event = DomainEvent::HandleUnreserved { handle };
        Self::finish(tx, operator, None, vec![event]).await
    }
}
