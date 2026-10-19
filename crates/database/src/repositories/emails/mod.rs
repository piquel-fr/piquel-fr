//! Verified email ownership and primary-address persistence.

use super::{EmailRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_admin_api::Email;
use piquel_common::{TokenId, UserId};

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
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                StoredEmail,
                r#"INSERT INTO user_emails (id, user_id, normalized_email, verified_at, is_primary)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING
                    id AS "id: TokenId", user_id AS "user_id: UserId", normalized_email,
                    verified_at, is_primary"#,
                input.id.as_uuid(),
                input.user_id.as_uuid(),
                input.normalized_email,
                input.verified_at,
                input.is_primary,
            )
        )
    }

    /// Lists the account's addresses, primary first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_for_user(&mut self, user_id: UserId) -> Result<Vec<Email>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                Email,
                r#"SELECT normalized_email AS address, verified_at, is_primary AS "primary"
                FROM user_emails
                WHERE user_id = $1
                ORDER BY is_primary DESC, created_at"#,
                user_id.as_uuid(),
            )
        )
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
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredEmail,
                r#"SELECT
                    e.id AS "id: TokenId", e.user_id AS "user_id: UserId", e.normalized_email,
                    e.verified_at, e.is_primary
                FROM active_verified_email_ownership o
                JOIN users u ON u.id = o.user_id
                    AND u.status = 'active'
                JOIN user_emails e ON e.user_id = o.user_id
                    AND e.normalized_email = o.normalized_email
                    AND e.verified_at IS NOT NULL
                WHERE o.normalized_email = $1
                ORDER BY e.is_primary DESC, e.created_at
                LIMIT 1"#,
                normalized,
            )
        )
    }
}
/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
