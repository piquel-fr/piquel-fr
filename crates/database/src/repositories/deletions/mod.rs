//! Accounts scheduled for deletion, their restore tokens, and the purge that
//! deletes them.

use super::{AccountDeletionRepository, RepositoryExecutor, Unsigned};
use crate::DatabaseError;
use chrono::{DateTime, Duration, Utc};
use piquel_common::{PasskeyId, UserId, admin::PurgeFailure};

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

    /// Lists up to `limit` accounts that are due: past their grace period, and
    /// past their next attempt if a purge failed, longest-due first, so accounts
    /// that keep failing wait their backoff behind the others. The purge job locks
    /// and rechecks each one before purging it.
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
                WHERE greatest(next_attempt_at, purge_after) <= now()
                ORDER BY greatest(next_attempt_at, purge_after)
                LIMIT $1"#,
                i64::from(limit),
            )
        )
    }

    /// Records a failed purge of the account with its error, and delays the next
    /// attempt by `backoff` doubled for each earlier failure, up to `max_backoff`.
    /// Does nothing if the account is no longer due, as when it was restored and
    /// scheduled again since the attempt, so a new schedule starts without failures.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn record_failure(
        &mut self,
        user_id: UserId,
        error: &str,
        backoff: Duration,
        max_backoff: Duration,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_deletions
                SET attempts = attempts + 1, last_error = $2,
                    -- The exponent stops at 30, so no backoff overflows an interval.
                    next_attempt_at = now() + least(
                        $3::bigint * power(2, least(attempts, 30)), $4::bigint
                    ) * interval '1 second'
                WHERE user_id = $1 AND purge_after <= now()",
                user_id.as_uuid(),
                error,
                backoff.num_seconds(),
                max_backoff.num_seconds(),
            )
        )?;
        Ok(())
    }

    /// Finds why the account's purge keeps failing, if it failed since its
    /// deletion was scheduled.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn failure(
        &mut self,
        user_id: UserId,
    ) -> Result<Option<PurgeFailure>, DatabaseError> {
        let row = run!(
            self,
            fetch_optional,
            sqlx::query!(
                r#"SELECT attempts::bigint AS "attempts!: Unsigned",
                    last_error AS "last_error!", next_attempt_at AS "next_attempt_at!"
                FROM account_deletions
                WHERE user_id = $1 AND attempts > 0"#,
                user_id.as_uuid(),
            )
        )?;
        Ok(row.map(|row| PurgeFailure {
            attempts: row.attempts.into(),
            last_error: row.last_error,
            next_attempt_at: row.next_attempt_at,
        }))
    }

    /// Counts the accounts whose purge failed at least `attempts` times in a row.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn count_failing(&mut self, attempts: u16) -> Result<u64, DatabaseError> {
        Ok(run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "count!: Unsigned"
                FROM account_deletions
                WHERE attempts >= $1"#,
                i32::from(attempts),
            )
        )?
        .into())
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
    /// Deletes, in order: the grants, consents, sessions and administrator rights
    /// that reference the account without cascading, and its email deliveries;
    /// the related origins of its clients, deleted ones included, wherever events
    /// recorded them, since its domain may be among them;
    /// the account, which cascades to its emails, passkeys, identities, ceremonies
    /// and scheduled deletion, and leaves its handles without an owner, so nobody
    /// claims them again; then the personal data of every event the account is
    /// the subject or actor of, so those events read it as erased. Callers end its
    /// sessions, which queues their clients' logout tokens, and delete the clients
    /// it manages first. The events themselves stay: they hold only pseudonymous
    /// IDs.
    ///
    /// The personal data goes last because of migration 0022's trigger, which
    /// key-share locks every account an event names as it stores the event's
    /// personal data. Only deleting the account conflicts with that lock; the
    /// callers' `FOR NO KEY UPDATE` does not. So the delete waits for every
    /// request that stored personal data while the account existed, and the next
    /// statement, with a fresh snapshot, erases it too; a request that stores
    /// some later waits for this transaction, finds the account gone, and stores
    /// none. Erasing first would miss what such a request committed in between.
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
        // An operator's approval and another person's inline sign-in name neither
        // the owner nor its account, so only the client finds them. They read
        // the removed keys as erased. Ownership goes with the account, so this
        // runs first; a sign-in it misses still ends with retention.
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE event_personal_data p
                SET details = p.details - '/origin' - '/inline/origin'
                FROM domain_events e
                JOIN oidc_clients c ON c.id = e.client_id
                WHERE p.event_id = e.id AND c.owner_id = $1
                AND p.details ?| ARRAY['/origin', '/inline/origin']",
                id,
            )
        )?;
        let purged = run!(
            self,
            execute,
            sqlx::query!("DELETE FROM users WHERE id = $1", id)
        )?
        .rows_affected()
            == 1;
        // Users and administrators act as `{"type": …, "user_id": …}`; both
        // branches are indexed, so the cost does not grow with others' history.
        delete!(
            "DELETE FROM event_personal_data p
            USING domain_events e
            WHERE p.event_id = e.id
            AND (e.subject_user_id = $1 OR e.actor ->> 'user_id' = $1::text)",
        );
        Ok(purged)
    }
}

/// Database tests for scheduling, restore tokens and the purge.
#[cfg(test)]
mod tests;
