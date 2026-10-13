//! Account records and locks that serialize security-sensitive mutations.

use super::{RepositoryExecutor, StoredRow, UserRepository};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{AccountStatus, UserId};
use sqlx::postgres::PgRow;

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

impl StoredUser {
    /// Decodes a stored row, retaining the column name and cause for invalid data.
    fn from_row(row: &PgRow) -> Result<Self, DatabaseError> {
        Ok(Self {
            id: row.id("id")?,
            username: row.column("username")?,
            display_name: row.column("display_name")?,
            profile_version: u64::try_from(row.column::<i64>("profile_version")?)
                .map_err(|error| DatabaseError::invalid_stored("profile_version", error))?,
            status: row.vocabulary("status")?,
            created_at: row.column("created_at")?,
            updated_at: row.column("updated_at")?,
        })
    }
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
        let row = run!(
            self,
            fetch_one,
            sqlx::query(
                "INSERT INTO users (id, username, display_name)
                VALUES ($1, $2, $3)
                RETURNING
                    id, username, display_name, profile_version, status, created_at, updated_at"
            )
            .bind(input.id.as_uuid())
            .bind(&input.username)
            .bind(&input.display_name)
        )?;
        StoredUser::from_row(&row)
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
            sqlx::query(
                "SELECT id, username, display_name, profile_version, status, created_at, updated_at
                FROM users
                WHERE id = $1"
            )
            .bind(id.as_uuid())
        )?
        .as_ref()
        .map(StoredUser::from_row)
        .transpose()
    }

    /// Finds an active account and locks it until the transaction ends.
    ///
    /// Account mutations serialize on this lock. `FOR NO KEY UPDATE` still
    /// lets logout and audit inserts check their foreign keys concurrently.
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
            sqlx::query(
                "SELECT id, username, display_name, profile_version, status, created_at, updated_at
                FROM users
                WHERE id = $1
                AND status = 'active'
                FOR NO KEY UPDATE"
            )
            .bind(id.as_uuid())
        )?
        .as_ref()
        .map(StoredUser::from_row)
        .transpose()
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
            sqlx::query(
                "SELECT id, username, display_name, profile_version, status, created_at, updated_at
                FROM users
                WHERE username = $1
                AND status = 'active'"
            )
            .bind(username)
        )?
        .as_ref()
        .map(StoredUser::from_row)
        .transpose()
    }
}
/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
