//! Email addresses of accounts: verification, verified ownership and the primary
//! address.

use super::{EmailRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_admin_api::Email;
use piquel_common::{EmailId, UserId};

/// An email address attached to an account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEmail {
    /// Row identifier.
    pub id: EmailId,
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
    pub id: EmailId,
    /// Owning account.
    pub user_id: UserId,
    /// Address after normalization.
    pub normalized_email: String,
    /// Whether this becomes the account's primary address.
    pub is_primary: bool,
    /// When the address was verified.
    pub verified_at: DateTime<Utc>,
}

/// An unverified address to attach to an account, waiting for its verification link.
#[derive(Clone, Debug)]
pub struct InsertUnverifiedEmail<'a> {
    /// Row identifier, from which auth derives the verification token.
    pub id: EmailId,
    /// Owning account.
    pub user_id: UserId,
    /// Address after normalization.
    pub normalized_email: &'a str,
    /// SHA-256 digest of the verification token.
    pub secret_digest: &'a [u8],
    /// When the verification link stops working.
    pub expires_at: DateTime<Utc>,
}

/// An address whose verification token was presented, before it is verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingVerification {
    /// The unverified address.
    pub email_id: EmailId,
    /// Its account.
    pub user_id: UserId,
    /// The address itself.
    pub address: String,
}

impl From<StoredEmail> for Email {
    /// The address as the admin API shows it.
    fn from(email: StoredEmail) -> Self {
        Self {
            address: email.normalized_email,
            verified_at: email.verified_at,
            primary: email.is_primary,
        }
    }
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
                    id AS "id: EmailId", user_id AS "user_id: UserId", normalized_email,
                    verified_at, is_primary"#,
                input.id.as_uuid(),
                input.user_id.as_uuid(),
                input.normalized_email,
                input.verified_at,
                input.is_primary,
            )
        )
    }

    /// Attaches an unverified address and the digest of its verification token,
    /// in one statement. Ownership is claimed only once it is verified.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the ID or digest is already used, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn insert_unverified(
        &mut self,
        input: &InsertUnverifiedEmail<'_>,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "WITH email AS (
                    INSERT INTO user_emails (id, user_id, normalized_email)
                    VALUES ($1, $2, $3)
                    RETURNING id
                )
                INSERT INTO email_verification_secrets (email_id, secret_digest, expires_at)
                SELECT id, $4, $5 FROM email",
                input.id.as_uuid(),
                input.user_id.as_uuid(),
                input.normalized_email,
                input.secret_digest,
                input.expires_at,
            )
        )?;
        Ok(())
    }

    /// Lists the account's addresses with their IDs, primary first, then oldest
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list(&mut self, user_id: UserId) -> Result<Vec<StoredEmail>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                StoredEmail,
                r#"SELECT
                    id AS "id: EmailId", user_id AS "user_id: UserId", normalized_email,
                    verified_at, is_primary
                FROM user_emails
                WHERE user_id = $1
                ORDER BY is_primary DESC, created_at, id"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Finds one of the account's addresses.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find(
        &mut self,
        user_id: UserId,
        id: EmailId,
    ) -> Result<Option<StoredEmail>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredEmail,
                r#"SELECT
                    id AS "id: EmailId", user_id AS "user_id: UserId", normalized_email,
                    verified_at, is_primary
                FROM user_emails
                WHERE user_id = $1 AND id = $2"#,
                user_id.as_uuid(),
                id.as_uuid(),
            )
        )
    }

    /// Finds the unverified address whose unexpired verification token has this
    /// digest, if its account is active. Nothing is locked: lock the account, then
    /// [`Self::consume_verification`].
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_verification(
        &mut self,
        secret_digest: &[u8],
    ) -> Result<Option<PendingVerification>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                PendingVerification,
                r#"SELECT
                    e.id AS "email_id: EmailId", e.user_id AS "user_id: UserId",
                    e.normalized_email AS address
                FROM email_verification_secrets s
                JOIN user_emails e ON e.id = s.email_id AND e.verified_at IS NULL
                JOIN users u ON u.id = e.user_id AND u.status = 'active'
                WHERE s.secret_digest = $1 AND s.expires_at > now()"#,
                secret_digest,
            )
        )
    }

    /// Verifies `pending`, under its account's lock: deletes its verification
    /// secret, so the token works once, and marks the address verified. It becomes
    /// primary if the account has no primary address yet. Returns whether it did.
    /// The ownership trigger then claims the address for the account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the secret expired or was used
    /// since it was found, [`DatabaseError::Conflict`] if another active account
    /// owns the address, or another [`DatabaseError`] if a query fails.
    pub async fn consume_verification(
        &mut self,
        pending: &PendingVerification,
        secret_digest: &[u8],
    ) -> Result<bool, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "DELETE FROM email_verification_secrets
                WHERE email_id = $1 AND secret_digest = $2 AND expires_at > now()
                RETURNING email_id",
                pending.email_id.as_uuid(),
                secret_digest,
            )
        )?;
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "UPDATE user_emails
                SET verified_at = now(),
                    is_primary = NOT EXISTS (
                        SELECT 1 FROM user_emails WHERE user_id = $2 AND is_primary
                    )
                WHERE id = $1 AND user_id = $2 AND verified_at IS NULL
                RETURNING is_primary",
                pending.email_id.as_uuid(),
                pending.user_id.as_uuid(),
            )
        )
    }

    /// Makes the account's verified address `id` its primary one, under the
    /// account's lock, and returns the previous primary address. Two statements,
    /// since a unique index allows one primary per account at any time.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the account has no verified address
    /// `id`, or another [`DatabaseError`] if a query fails.
    pub async fn set_primary(
        &mut self,
        user_id: UserId,
        id: EmailId,
    ) -> Result<Option<EmailId>, DatabaseError> {
        let previous = run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                r#"UPDATE user_emails SET is_primary = false
                WHERE user_id = $1 AND is_primary AND id <> $2
                RETURNING id AS "id: EmailId""#,
                user_id.as_uuid(),
                id.as_uuid(),
            )
        )?;
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "UPDATE user_emails SET is_primary = true
                WHERE user_id = $1 AND id = $2 AND verified_at IS NOT NULL
                RETURNING id",
                user_id.as_uuid(),
                id.as_uuid(),
            )
        )?;
        Ok(previous)
    }

    /// Removes one of the account's addresses, with its verification secret.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the account has no address `id`, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn remove(&mut self, user_id: UserId, id: EmailId) -> Result<(), DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                "DELETE FROM user_emails WHERE user_id = $1 AND id = $2 RETURNING id",
                user_id.as_uuid(),
                id.as_uuid(),
            )
        )?;
        Ok(())
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
                    e.id AS "id: EmailId", e.user_id AS "user_id: UserId", e.normalized_email,
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
