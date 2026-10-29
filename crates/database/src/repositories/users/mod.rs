//! Account records and locks that serialize security-sensitive mutations.

use super::{RepositoryExecutor, Unsigned, UserRepository};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{AccountStatus, Handle, UserId, admin::User};

/// A user account row, with its current handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredUser {
    /// Immutable account identifier.
    pub id: UserId,
    /// Public identifier and login name.
    pub handle: Handle,
    /// When the handle last changed, or the account was created.
    pub handle_changed_at: DateTime<Utc>,
    /// Name shown to the user and to relying parties.
    pub display_name: String,
    /// Starts at 1; bumped when profile claims change.
    pub profile_version: u64,
    /// Whether the account can authenticate.
    pub status: AccountStatus,
    /// When the account was created.
    pub created_at: DateTime<Utc>,
    /// When the profile last changed.
    pub updated_at: DateTime<Utc>,
}

impl From<StoredUser> for User {
    fn from(user: StoredUser) -> Self {
        Self {
            id: user.id,
            handle: user.handle,
            display_name: user.display_name,
            status: user.status,
            created_at: user.created_at,
        }
    }
}

/// A new active account.
#[derive(Clone, Debug)]
pub struct InsertUser {
    /// Identifier for the new account.
    pub id: UserId,
    /// Handle, also the login name. Reserved names are the caller's concern.
    pub handle: Handle,
    /// Name shown to the user and to relying parties.
    pub display_name: String,
}

#[cfg(any(test, feature = "test-support"))]
impl InsertUser {
    /// An account whose handle is `prefix` and a random suffix, for tests.
    ///
    /// # Panics
    ///
    /// Panics if `prefix` cannot start a handle.
    #[must_use]
    pub fn named(prefix: &str) -> Self {
        let id = UserId::new();
        Self {
            id,
            handle: Handle::parse(&format!("{prefix}-{}", &id.to_string()[24..]))
                .expect("a handle prefix"),
            display_name: format!("{prefix} test"),
        }
    }
}

impl UserRepository<'_> {
    /// Creates an active account holding `input.handle`, in one statement.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the id is taken or another account
    /// holds the handle or one that looks like it, or another [`DatabaseError`] if
    /// the query fails.
    pub async fn insert(&mut self, input: &InsertUser) -> Result<StoredUser, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                StoredUser,
                // Foreign keys are checked at the end of the statement, after both
                // inserts.
                r#"WITH u AS (
                    INSERT INTO users (id, display_name) VALUES ($1, $3) RETURNING *
                ), h AS (
                    INSERT INTO handles (handle, user_id) VALUES ($2, $1) RETURNING handle
                )
                SELECT
                    u.id AS "id: UserId", h.handle AS "handle: Handle", u.handle_changed_at,
                    u.display_name, u.profile_version AS "profile_version: Unsigned",
                    u.status AS "status: AccountStatus", u.created_at, u.updated_at
                FROM u, h"#,
                input.id.as_uuid(),
                input.handle.as_str(),
                input.display_name,
            )
        )
    }

    /// Finds an account in any status.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_by_id(&mut self, id: UserId) -> Result<Option<StoredUser>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredUser,
                r#"SELECT
                    u.id AS "id: UserId", h.handle AS "handle: Handle", u.handle_changed_at,
                    u.display_name, u.profile_version AS "profile_version: Unsigned",
                    u.status AS "status: AccountStatus", u.created_at, u.updated_at
                FROM users u
                JOIN handles h ON h.user_id = u.id AND h.released_at IS NULL
                WHERE u.id = $1"#,
                id.as_uuid(),
            )
        )
    }

    /// Finds an active account and locks it until the transaction ends.
    ///
    /// Account mutations serialize on this lock. `FOR NO KEY UPDATE` still
    /// lets inserts that reference the account check their foreign keys
    /// concurrently. Only the account row is locked, not its handle.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_id_for_update(
        &mut self,
        id: UserId,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        self.lock(id, true).await
    }

    /// Locks the account `id`, only if active when `active`, then reads it. A lock
    /// that waited sees the account's latest row, but a join in the same statement
    /// would keep the handle its snapshot saw, perhaps from before a rename that
    /// committed meanwhile. The read is a separate statement, with a fresh snapshot.
    async fn lock(
        &mut self,
        id: UserId,
        active: bool,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        let locked = run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT id FROM users
                WHERE id = $1 AND (NOT $2 OR status = 'active')
                FOR NO KEY UPDATE",
                id.as_uuid(),
                active,
            )
        )?;
        match locked {
            Some(_) => self.find_by_id(id).await,
            None => Ok(None),
        }
    }

    /// Finds an active account by its current handle.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_handle(
        &mut self,
        handle: &Handle,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredUser,
                r#"SELECT
                    u.id AS "id: UserId", h.handle AS "handle: Handle", u.handle_changed_at,
                    u.display_name, u.profile_version AS "profile_version: Unsigned",
                    u.status AS "status: AccountStatus", u.created_at, u.updated_at
                FROM users u
                JOIN handles h ON h.user_id = u.id AND h.released_at IS NULL
                WHERE h.handle = $1
                AND u.status = 'active'"#,
                handle.as_str(),
            )
        )
    }

    /// Finds an account in any status and locks it until the transaction ends, like
    /// [`Self::find_active_by_id_for_update`].
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_by_id_for_update(
        &mut self,
        id: UserId,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        self.lock(id, false).await
    }

    /// Finds an account in any status by its current handle.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_by_handle(
        &mut self,
        handle: &Handle,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredUser,
                r#"SELECT
                    u.id AS "id: UserId", h.handle AS "handle: Handle", u.handle_changed_at,
                    u.display_name, u.profile_version AS "profile_version: Unsigned",
                    u.status AS "status: AccountStatus", u.created_at, u.updated_at
                FROM users u
                JOIN handles h ON h.user_id = u.id AND h.released_at IS NULL
                WHERE h.handle = $1"#,
                handle.as_str(),
            )
        )
    }

    /// Records that the account's handle changed now, and bumps its profile version
    /// so relying parties refresh `preferred_username`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub(crate) async fn handle_changed(&mut self, id: UserId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE users
                SET handle_changed_at = now(), profile_version = profile_version + 1,
                    updated_at = now()
                WHERE id = $1",
                id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// Moves the account's last handle change `days` into the past, so tests need
    /// not wait out the rename cooldown.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    #[cfg(feature = "test-support")]
    pub async fn age_handle_change(&mut self, id: UserId, days: i32) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE users SET handle_changed_at = handle_changed_at - make_interval(days => $2)
                WHERE id = $1",
                id.as_uuid(),
                days,
            )
        )?;
        Ok(())
    }

    /// Changes the account's status. Returns `false` if it already had it.
    ///
    /// Disabling releases the account's verified emails and reactivating reclaims
    /// them, through the schema's triggers.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if reactivation finds one of its verified
    /// emails owned by another active account, or another [`DatabaseError`] if the
    /// query fails.
    pub async fn set_status(
        &mut self,
        id: UserId,
        status: AccountStatus,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE users
                SET status = $2, updated_at = now()
                WHERE id = $1
                AND status <> $2",
                id.as_uuid(),
                status.as_str(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Lists up to `limit` accounts whose ID equals `query`, or whose handle,
    /// display name or any email contains it, ignoring case. An empty query matches
    /// every account. Results are ordered by ID and continue after `after`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn search(
        &mut self,
        query: &str,
        after: Option<UserId>,
        limit: u16,
    ) -> Result<Vec<User>, DatabaseError> {
        // Escape LIKE wildcards so the query matches literally.
        let pattern = format!(
            "%{}%",
            query
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                User,
                r#"SELECT
                    u.id AS "id: UserId", h.handle AS "handle: Handle", u.display_name,
                    u.status AS "status: AccountStatus", u.created_at
                FROM users u
                JOIN handles h ON h.user_id = u.id AND h.released_at IS NULL
                WHERE (
                    $1 = ''
                    OR u.id::text = $1
                    OR h.handle ILIKE $2
                    OR u.display_name ILIKE $2
                    OR EXISTS (
                        SELECT FROM user_emails e
                        WHERE e.user_id = u.id
                        AND e.normalized_email ILIKE $2
                    )
                )
                AND ($3::uuid IS NULL OR u.id > $3)
                ORDER BY u.id
                LIMIT $4"#,
                query,
                pattern,
                after.map(UserId::as_uuid),
                i64::from(limit),
            )
        )
    }
}
/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
