//! Verified email ownership and primary-address persistence.

use super::{EmailRepository, RepositoryExecutor, StoredRow};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{TokenId, UserId};
use sqlx::postgres::PgRow;

/// An email address attached to an account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEmail {
    /// Row identifier.
    pub id: TokenId,
    /// Owning account.
    pub user_id: UserId,
    /// Address after normalization; the ownership key.
    pub normalized_email: String,
    /// When the address was verified; `None` while unverified.
    pub verified_at: Option<DateTime<Utc>>,
    /// Whether this is the account's primary address. Only a verified address
    /// can be primary, and an account with verified addresses has exactly one.
    pub is_primary: bool,
}

impl StoredEmail {
    /// Decodes a stored row, retaining the column name and cause for invalid data.
    fn from_row(row: &PgRow) -> Result<Self, DatabaseError> {
        Ok(Self {
            id: row.id("id")?,
            user_id: row.id("user_id")?,
            normalized_email: row.column("normalized_email")?,
            verified_at: row.column("verified_at")?,
            is_primary: row.column("is_primary")?,
        })
    }
}

/// A verified address to attach to an account.
#[derive(Clone, Debug)]
pub struct InsertVerifiedEmail {
    /// Row identifier.
    pub id: TokenId,
    /// Owning account.
    pub user_id: UserId,
    /// Address after normalization.
    pub normalized_email: String,
    /// Whether this becomes the account's primary address.
    pub is_primary: bool,
    /// When the address was verified.
    pub verified_at: DateTime<Utc>,
}

impl EmailRepository<'_> {
    /// Attaches a verified address and claims its ownership for the account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if another active account owns the
    /// address, or another [`DatabaseError`] if the query fails.
    pub async fn insert_verified(
        &mut self,
        input: &InsertVerifiedEmail,
    ) -> Result<StoredEmail, DatabaseError> {
        let row = run!(self, fetch_one, sqlx::query("INSERT INTO user_emails (id, user_id, normalized_email, verified_at, is_primary) VALUES ($1, $2, $3, $4, $5) RETURNING id, user_id, normalized_email, verified_at, is_primary").bind(input.id.as_uuid()).bind(input.user_id.as_uuid()).bind(&input.normalized_email).bind(input.verified_at).bind(input.is_primary))?;
        StoredEmail::from_row(&row)
    }

    /// Finds the verified address owned by an active account, preferring its
    /// primary row.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_verified(
        &mut self,
        normalized: &str,
    ) -> Result<Option<StoredEmail>, DatabaseError> {
        run!(self, fetch_optional, sqlx::query("SELECT e.id, e.user_id, e.normalized_email, e.verified_at, e.is_primary FROM active_verified_email_ownership o JOIN users u ON u.id = o.user_id AND u.status = 'active' JOIN user_emails e ON e.user_id = o.user_id AND e.normalized_email = o.normalized_email AND e.verified_at IS NOT NULL WHERE o.normalized_email = $1 ORDER BY e.is_primary DESC, e.created_at LIMIT 1").bind(normalized))?.as_ref().map(StoredEmail::from_row).transpose()
    }
}
/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
