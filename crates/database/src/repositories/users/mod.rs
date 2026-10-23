//! Account records and locks that serialize security-sensitive mutations.

use super::{RepositoryExecutor, Unsigned, UserRepository};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_admin_api::User;
use piquel_common::{AccountStatus, Handle, UserId};

/// A user account row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredUser {
    /// Immutable account identifier.
    pub id: UserId,
    /// Unique login name.
    pub username: String,
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
            username: user.username,
            display_name: user.display_name,
            status: user.status,
            created_at: user.created_at,
        }
    }
}

/// An account's ID and login name, for checking every name against the handle rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountName {
    /// Account identifier.
    pub id: UserId,
    /// Login name, which may predate the handle rules.
    pub username: String,
}

/// A new active account.
#[derive(Clone, Debug)]
pub struct InsertUser {
    /// Identifier for the new account.
    pub id: UserId,
    /// Handle, also the login name; must be unique.
    pub handle: Handle,
    /// Name shown to the user and to relying parties.
    pub display_name: String,
}

impl UserRepository<'_> {
    /// Creates an active account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the id or username is taken, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn insert(&mut self, input: &InsertUser) -> Result<StoredUser, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                StoredUser,
                r#"INSERT INTO users (id, username, display_name)
                VALUES ($1, $2, $3)
                RETURNING
                    id AS "id: UserId", username, display_name,
                    profile_version AS "profile_version: Unsigned",
                    status AS "status: AccountStatus", created_at, updated_at"#,
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
                    id AS "id: UserId", username, display_name,
                    profile_version AS "profile_version: Unsigned",
                    status AS "status: AccountStatus", created_at, updated_at
                FROM users
                WHERE id = $1"#,
                id.as_uuid(),
            )
        )
    }

    /// Finds an active account and locks it until the transaction ends.
    ///
    /// Account mutations serialize on this lock. `FOR NO KEY UPDATE` still
    /// lets inserts that reference the account check their foreign keys concurrently.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_id_for_update(
        &mut self,
        id: UserId,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredUser,
                r#"SELECT
                    id AS "id: UserId", username, display_name,
                    profile_version AS "profile_version: Unsigned",
                    status AS "status: AccountStatus", created_at, updated_at
                FROM users
                WHERE id = $1
                AND status = 'active'
                FOR NO KEY UPDATE"#,
                id.as_uuid(),
            )
        )
    }

    /// Finds an active account by its login name.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredUser,
                r#"SELECT
                    id AS "id: UserId", username, display_name,
                    profile_version AS "profile_version: Unsigned",
                    status AS "status: AccountStatus", created_at, updated_at
                FROM users
                WHERE username = $1
                AND status = 'active'"#,
                username,
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
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredUser,
                r#"SELECT
                    id AS "id: UserId", username, display_name,
                    profile_version AS "profile_version: Unsigned",
                    status AS "status: AccountStatus", created_at, updated_at
                FROM users
                WHERE id = $1
                FOR NO KEY UPDATE"#,
                id.as_uuid(),
            )
        )
    }

    /// Finds an account in any status by its login name.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<StoredUser>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredUser,
                r#"SELECT
                    id AS "id: UserId", username, display_name,
                    profile_version AS "profile_version: Unsigned",
                    status AS "status: AccountStatus", created_at, updated_at
                FROM users
                WHERE username = $1"#,
                username,
            )
        )
    }

    /// Lists every account's login name, in any status, ordered by name.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_names(&mut self) -> Result<Vec<AccountName>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                AccountName,
                r#"SELECT id AS "id: UserId", username FROM users ORDER BY username"#,
            )
        )
    }

    /// Gives the account `handle` as its login name and bumps its profile version,
    /// so relying parties refresh `preferred_username`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if another account has the name, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn rename(&mut self, id: UserId, handle: &Handle) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE users
                SET username = $2, profile_version = profile_version + 1, updated_at = now()
                WHERE id = $1",
                id.as_uuid(),
                handle.as_str(),
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

    /// Lists up to `limit` accounts whose ID equals `query`, or whose username,
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
                    u.id AS "id: UserId", u.username, u.display_name,
                    u.status AS "status: AccountStatus", u.created_at
                FROM users u
                WHERE (
                    $1 = ''
                    OR u.id::text = $1
                    OR u.username ILIKE $2
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
