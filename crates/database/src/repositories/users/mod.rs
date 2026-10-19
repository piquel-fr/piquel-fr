//! Account records and locks that serialize security-sensitive mutations.

use super::{RepositoryExecutor, Unsigned, UserRepository};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{AccountStatus, UserId};

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

/// A new active account.
#[derive(Clone, Debug)]
pub struct InsertUser {
    /// Identifier for the new account.
    pub id: UserId,
    /// Login name; must be unique.
    pub username: String,
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
                input.username,
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
}
/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
