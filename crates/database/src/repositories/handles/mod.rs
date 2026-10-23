//! Every handle an account holds or held, and the look-alikes they keep from others.
//!
//! A handle row is current while `released_at` is unset. Renaming releases it
//! rather than deleting it, so a handle never passes to another account: only its
//! former owner may claim it again. The table's keys keep handles and their
//! skeletons unique across current, released and purged accounts' rows.

use super::{HandleRepository, RepositoryExecutor};
use crate::{DatabaseError, DatabaseTransaction};
use chrono::{DateTime, Utc};
use piquel_common::{Handle, UserId};

/// A handle row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHandle {
    /// The handle.
    pub handle: Handle,
    /// Its account, or `None` once the account is purged.
    pub user_id: Option<UserId>,
    /// When it was claimed, or first claimed if its owner reclaimed it.
    pub claimed_at: DateTime<Utc>,
    /// When it stopped being its account's handle, or `None` while it is.
    pub released_at: Option<DateTime<Utc>>,
}

impl HandleRepository<'_> {
    /// Finds the row sharing `handle`'s skeleton: the handle itself, or the one it
    /// looks like. Skeletons are unique, so there is at most one.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn holder(&mut self, handle: &Handle) -> Result<Option<StoredHandle>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredHandle,
                r#"SELECT handle AS "handle: Handle", user_id AS "user_id: UserId", claimed_at,
                    released_at
                FROM handles
                WHERE skeleton = handle_skeleton($1)"#,
                handle.as_str(),
            )
        )
    }

    /// Lists every account's current handle, by handle.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_current(&mut self) -> Result<Vec<StoredHandle>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredHandle,
                r#"SELECT handle AS "handle: Handle", user_id AS "user_id: UserId", claimed_at,
                    released_at
                FROM handles
                WHERE released_at IS NULL
                ORDER BY handle"#,
            )
        )
    }

    /// Deletes a released handle, so anyone may claim it, and returns its row. The
    /// only way a handle returns to the pool; a current handle is never deleted.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn delete_released(
        &mut self,
        handle: &Handle,
    ) -> Result<Option<StoredHandle>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredHandle,
                r#"DELETE FROM handles
                WHERE handle = $1 AND released_at IS NOT NULL
                RETURNING handle AS "handle: Handle", user_id AS "user_id: UserId", claimed_at,
                    released_at"#,
                handle.as_str(),
            )
        )
    }

    /// Releases the account's current handle.
    async fn release_current(&mut self, user_id: UserId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE handles SET released_at = now()
                WHERE user_id = $1 AND released_at IS NULL",
                user_id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// Makes `handle` the account's current handle: a new row, or the account's own
    /// released one. Returns `false` if another account holds or held it.
    async fn claim(&mut self, user_id: UserId, handle: &Handle) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO handles (handle, user_id) VALUES ($1, $2)
                ON CONFLICT (handle) DO UPDATE SET released_at = NULL
                WHERE handles.user_id = $2 AND handles.released_at IS NOT NULL",
                handle.as_str(),
                user_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }
}

impl DatabaseTransaction<'_> {
    /// Gives the account `user_id` the handle `handle`: releases its current one,
    /// claims the new one or reclaims its own released row, and records the change
    /// on the account, bumping its profile version. Returns `false` if another
    /// account holds or held `handle`. Callers lock the account first; a concurrent
    /// claim of the same handle waits for this transaction, then fails.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if `handle` looks like another handle,
    /// the account's own released ones included, or another [`DatabaseError`] if a
    /// query fails. The transaction is then aborted.
    pub async fn rename_handle(
        &mut self,
        user_id: UserId,
        handle: &Handle,
    ) -> Result<bool, DatabaseError> {
        self.handles().release_current(user_id).await?;
        if !self.handles().claim(user_id, handle).await? {
            return Ok(false);
        }
        self.users().handle_changed(user_id).await?;
        Ok(true)
    }
}

/// Renames, reclaims and their races, against the schema's keys.
#[cfg(test)]
mod tests;
