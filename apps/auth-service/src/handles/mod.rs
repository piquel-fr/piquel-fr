//! Handles: whether an account may take one, and the renames signup, settings and
//! the admin operations share.
use crate::account::{AccountError, AccountService, Owner};
use chrono::{Duration, Utc};
use piquel_common::{Handle, Personal, UserId, events::DomainEvent};
use piquel_repository::{Database, DatabaseError, DatabaseTransaction, StoredUser};

/// Refusals and their response mapping.
mod error;
pub use error::HandlesError;

/// How long a handle stays before its account may change it again. Settings
/// renames wait for it; operators do not.
pub(crate) const COOLDOWN: Duration = Duration::days(30);

/// The handle rules that need the database: whether a handle is free, and claiming
/// it. Signup, the owner's rename and the admin operations share them.
pub(crate) struct Handles<'a> {
    /// Accounts and their handles.
    database: &'a Database,
}

impl<'a> Handles<'a> {
    /// Checks handles against `database`.
    pub(crate) const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    /// Fails with the reason `user`, or a new account, cannot take `handle`, from the
    /// one row sharing its skeleton: taken, retired, a look-alike, or already theirs.
    /// An account may take back a handle it released.
    pub(crate) async fn claimable(
        &self,
        handle: &Handle,
        user: Option<UserId>,
    ) -> Result<(), HandlesError> {
        let Some(holder) = self.database.handles().holder(handle).await? else {
            return Ok(());
        };
        let own = user.is_some() && holder.user_id == user;
        if holder.handle != *handle {
            return Err(HandlesError::Confusable(holder.handle));
        }
        match (own, holder.released_at, holder.user_id) {
            (true, None, _) => Err(HandlesError::Current),
            (true, Some(_), _) => Ok(()),
            (false, None, Some(_)) => Err(HandlesError::Taken),
            // Released, or the current handle of a purged account.
            (false, _, _) => Err(HandlesError::Retired),
        }
    }

    /// Why a claim of `handle` by `user`, or a new account, failed. Callers roll
    /// back first. A concurrent claim that has since rolled back reads as taken.
    pub(crate) async fn refusal(&self, handle: &Handle, user: Option<UserId>) -> HandlesError {
        match self.claimable(handle, user).await {
            Ok(()) => HandlesError::Taken,
            Err(error) => error,
        }
    }

    /// Gives the account `user`, locked in `tx`, the handle `handle`, and returns
    /// `tx` with the event to record. On refusal, `tx` is rolled back first, so the
    /// reason is looked up without holding a second connection.
    pub(crate) async fn rename<'t>(
        &self,
        mut tx: DatabaseTransaction<'t>,
        user: &StoredUser,
        handle: Handle,
    ) -> Result<(DatabaseTransaction<'t>, DomainEvent), HandlesError> {
        if user.handle == handle {
            return Err(HandlesError::Current);
        }
        let renamed = match tx.rename_handle(user.id, &handle).await {
            Ok(renamed) => renamed,
            Err(DatabaseError::Conflict(_)) => false,
            Err(error) => return Err(error.into()),
        };
        if !renamed {
            tx.rollback().await?;
            return Err(self.refusal(&handle, Some(user.id)).await);
        }
        let changed = DomainEvent::HandleChanged {
            old: Personal::Value(user.handle.to_string()),
            new: Personal::Value(handle),
        };
        Ok((tx, changed))
    }
}

impl AccountService {
    /// Changes the owner's handle to `input`, at most once per [`COOLDOWN`], once
    /// they confirmed with a passkey: the handle is the login name. Only the owner
    /// renames here; operators rename through `AdminService`, without the cooldown.
    /// The profile version is bumped, so relying parties refresh
    /// `preferred_username`.
    pub(crate) async fn rename_handle(
        &self,
        owner: &Owner,
        input: &str,
    ) -> Result<Handle, AccountError> {
        let handle = Handle::parse(input).map_err(HandlesError::from)?;
        handle.ensure_unreserved().map_err(HandlesError::from)?;
        let mut tx = self.database.begin().await?;
        owner.lock_confirmed(&mut tx).await?;
        // Already locked, which the confirmation check does not return.
        let user = tx
            .users()
            .find_active_by_id_for_update(owner.user())
            .await?
            .ok_or(crate::security::SessionError::Missing)?;
        let retry_after = user.handle_changed_at + COOLDOWN;
        if retry_after > Utc::now() && user.handle != handle {
            return Err(HandlesError::Cooldown { retry_after }.into());
        }
        let (mut tx, changed) = Handles::new(&self.database)
            .rename(tx, &user, handle.clone())
            .await?;
        tx.record(&owner.context(), Some(user.id), changed).await?;
        tx.commit().await?;
        Ok(handle)
    }
}

/// Database-backed rename scenarios.
#[cfg(test)]
mod tests;
