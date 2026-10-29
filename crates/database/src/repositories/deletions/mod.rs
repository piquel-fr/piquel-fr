//! Accounts scheduled for deletion, their restore tokens, and the purge that
//! deletes them.

use super::{AccountDeletionRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{PasskeyId, UserId};

/// A restore token's account, and the passkey whose sign-in it continues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreToken {
    /// The account scheduled for deletion.
    pub user_id: UserId,
    /// The passkey that signed in, which restoring signs in with.
    pub passkey_id: PasskeyId,
}

/// An account scheduled for deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountDeletion {
    /// The account.
    pub user_id: UserId,
    /// When the deletion was scheduled.
    pub requested_at: DateTime<Utc>,
    /// When the purge job may delete the account.
    pub purge_after: DateTime<Utc>,
}

impl AccountDeletionRepository<'_> {
    /// Schedules the account's purge for `purge_after`. Callers lock the account
    /// and set its status to `deleting` in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the account is already scheduled, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn schedule(
        &mut self,
        user_id: UserId,
        purge_after: DateTime<Utc>,
    ) -> Result<AccountDeletion, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                AccountDeletion,
                r#"INSERT INTO account_deletions (user_id, purge_after)
                VALUES ($1, $2)
                RETURNING user_id AS "user_id: UserId", requested_at, purge_after"#,
                user_id.as_uuid(),
                purge_after,
            )
        )
    }

    /// Finds the account's scheduled deletion.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find(
        &mut self,
        user_id: UserId,
    ) -> Result<Option<AccountDeletion>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                AccountDeletion,
                r#"SELECT user_id AS "user_id: UserId", requested_at, purge_after
                FROM account_deletions
                WHERE user_id = $1"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Cancels the account's scheduled deletion and its restore token. Returns
    /// `false` if none was scheduled. Callers reactivate the account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn cancel(&mut self, user_id: UserId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "DELETE FROM account_deletions WHERE user_id = $1",
                user_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Lists up to `limit` accounts whose grace period has ended, longest-due first.
    /// The purge job locks and rechecks each one before purging it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn due(&mut self, limit: u32) -> Result<Vec<UserId>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_scalar!(
                r#"SELECT user_id AS "user_id: UserId"
                FROM account_deletions
                WHERE purge_after <= now()
                ORDER BY purge_after
                LIMIT $1"#,
                i64::from(limit),
            )
        )
    }

    /// Stores the digest of a restore token for the account, replacing any earlier
    /// one, valid until `expires_at`, continuing `passkey`'s sign-in. Returns the
    /// scheduled deletion, or `None` if the account is not scheduled.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn issue_restore_token(
        &mut self,
        user_id: UserId,
        digest: &[u8],
        passkey: PasskeyId,
        expires_at: DateTime<Utc>,
    ) -> Result<Option<AccountDeletion>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                AccountDeletion,
                r#"UPDATE account_deletions
                SET restore_token_digest = $2, restore_passkey_id = $3,
                    restore_token_expires_at = $4
                WHERE user_id = $1
                RETURNING user_id AS "user_id: UserId", requested_at, purge_after"#,
                user_id.as_uuid(),
                digest,
                passkey.as_uuid(),
                expires_at,
            )
        )
    }

    /// Finds the account whose unexpired restore token has this digest, and the
    /// passkey it continues, while that passkey is active: one revoked since, as an
    /// undone recovery's, restores nothing. Restoring cancels the deletion, so a
    /// token restores at most once.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_by_restore_token(
        &mut self,
        digest: &[u8],
    ) -> Result<Option<RestoreToken>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                RestoreToken,
                r#"SELECT
                    d.user_id AS "user_id: UserId", d.restore_passkey_id AS "passkey_id!: PasskeyId"
                FROM account_deletions d
                JOIN passkey_credentials p
                    ON p.id = d.restore_passkey_id AND p.user_id = d.user_id
                    AND p.revoked_at IS NULL
                WHERE d.restore_token_digest = $1
                AND d.restore_token_expires_at > now()"#,
                digest,
            )
        )
    }

    /// Deletes the account and everything that identifies its person. Returns
    /// `false` if the account does not exist. Callers lock
    /// the account first, and record its last events afterwards.
    ///
    /// Deletes, in order: the personal data of every event the account is the
    /// subject or actor of, so those events read it as erased; the grants,
    /// consents, sessions and administrator rights that reference the account
    /// without cascading, and its email deliveries; then the account, which
    /// cascades to its emails, passkeys, identities, ceremonies and scheduled
    /// deletion, and leaves its handles without an owner, so nobody claims them
    /// again. Callers end its sessions, which queues their clients' logout
    /// tokens, and delete the clients it manages first. The events themselves
    /// stay: they hold only pseudonymous IDs.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a statement fails.
    pub async fn purge(&mut self, user_id: UserId) -> Result<bool, DatabaseError> {
        let id = user_id.as_uuid();
        // Each statement is a checked query with its own type, so they cannot share a loop.
        macro_rules! delete {
            ($($statement:literal,)+) => {
                $(run!(self, execute, sqlx::query!($statement, id))?;)+
            };
        }
        delete!(
            // Users and administrators act as `{"type": …, "user_id": …}`. Events
            // recorded after this keep none, as migration 0022's trigger ensures.
            "DELETE FROM event_personal_data p
            USING domain_events e
            WHERE p.event_id = e.id
            AND (e.subject_user_id = $1 OR e.actor ->> 'user_id' = $1::text)",
            // Cascades to the families' refresh tokens.
            "DELETE FROM refresh_token_families WHERE user_id = $1",
            "DELETE FROM authorization_codes WHERE user_id = $1",
            "DELETE FROM authorization_requests WHERE hinted_user_id = $1",
            "DELETE FROM oidc_consents WHERE user_id = $1",
            // Cascades to cookie digests, ceremonies and provider redirects.
            "DELETE FROM sessions WHERE user_id = $1",
            "DELETE FROM administrators WHERE user_id = $1",
            // Notices to removed or replaced addresses copy them; the account's
            // other channels' deliveries hold no personal data.
            "DELETE FROM deliveries WHERE channel = 'email' AND recipient = to_jsonb($1::uuid::text)",
        );
        Ok(run!(
            self,
            execute,
            sqlx::query!("DELETE FROM users WHERE id = $1", id)
        )?
        .rows_affected()
            == 1)
    }
}

/// Database tests for scheduling, restore tokens and the purge.
#[cfg(test)]
mod tests;
