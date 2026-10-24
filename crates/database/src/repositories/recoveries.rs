//! Account recoveries and their links. Every change to an account's recoveries
//! happens under that account's lock, so they serialize without row locks.

use super::{RecoveryRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{PasskeyId, RecoveryId, UserId};

/// A new recovery, whose link works until `expires_at`.
pub struct InsertRecovery<'a> {
    /// Recovery identifier, which the link's token is derived from.
    pub id: RecoveryId,
    /// The account recovered.
    pub user_id: UserId,
    /// SHA-256 of the link's token.
    pub secret_digest: &'a [u8],
    /// When the link stops working.
    pub expires_at: DateTime<Utc>,
}

/// A recovery as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecovery {
    /// Recovery identifier.
    pub id: RecoveryId,
    /// The account recovered.
    pub user_id: UserId,
    /// When it started.
    pub started_at: DateTime<Utc>,
    /// When its link stops working.
    pub expires_at: DateTime<Utc>,
    /// When its link enrolled a passkey, if it did.
    pub completed_at: Option<DateTime<Utc>>,
    /// The passkey its link enrolled, if it did.
    pub passkey_id: Option<PasskeyId>,
}

impl RecoveryRepository<'_> {
    /// Stores a new recovery.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails.
    pub async fn insert(&mut self, recovery: &InsertRecovery<'_>) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO account_recoveries (id, user_id, secret_digest, expires_at)
                VALUES ($1, $2, $3, $4)",
                recovery.id.as_uuid(),
                recovery.user_id.as_uuid(),
                recovery.secret_digest,
                recovery.expires_at,
            )
        )?;
        Ok(())
    }

    /// Cancels the account's recoveries whose link was not used yet, so only the
    /// newest one works. Returns how many there were.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn cancel_open(&mut self, user_id: UserId) -> Result<u64, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries SET cancelled_at = now()
                WHERE user_id = $1
                AND completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL",
                user_id.as_uuid(),
            )
        )?
        .rows_affected())
    }

    /// The recovery whose link's token has SHA-256 `digest`, if the link still
    /// works: not used, cancelled, undone or expired.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn find_open_by_digest(
        &mut self,
        digest: &[u8],
    ) -> Result<Option<StoredRecovery>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredRecovery,
                r#"SELECT
                    id AS "id: RecoveryId", user_id AS "user_id: UserId", started_at,
                    expires_at, completed_at, passkey_id AS "passkey_id: PasskeyId"
                FROM account_recoveries
                WHERE secret_digest = $1
                AND completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL
                AND expires_at > now()"#,
                digest,
            )
        )
    }

    /// Recovery `id`, if its link still works, as [`Self::find_open_by_digest`]
    /// says.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn find_open(
        &mut self,
        id: RecoveryId,
    ) -> Result<Option<StoredRecovery>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredRecovery,
                r#"SELECT
                    id AS "id: RecoveryId", user_id AS "user_id: UserId", started_at,
                    expires_at, completed_at, passkey_id AS "passkey_id: PasskeyId"
                FROM account_recoveries
                WHERE id = $1
                AND completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL
                AND expires_at > now()"#,
                id.as_uuid(),
            )
        )
    }

    /// Records that recovery `id`'s link enrolled `passkey_id`, once. Returns
    /// `false` if the link no longer works.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn complete(
        &mut self,
        id: RecoveryId,
        passkey_id: PasskeyId,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries SET completed_at = now(), passkey_id = $2
                WHERE id = $1
                AND completed_at IS NULL AND cancelled_at IS NULL AND undone_at IS NULL
                AND expires_at > now()",
                id.as_uuid(),
                passkey_id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// The account's newest recovery that can still be undone: its link still
    /// works, or it enrolled a passkey and was not undone.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn latest_undoable(
        &mut self,
        user_id: UserId,
    ) -> Result<Option<StoredRecovery>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredRecovery,
                r#"SELECT
                    id AS "id: RecoveryId", user_id AS "user_id: UserId", started_at,
                    expires_at, completed_at, passkey_id AS "passkey_id: PasskeyId"
                FROM account_recoveries
                WHERE user_id = $1
                AND cancelled_at IS NULL AND undone_at IS NULL
                AND (completed_at IS NOT NULL OR expires_at > now())
                ORDER BY started_at DESC
                LIMIT 1"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Records that the owner undid recovery `id`. Returns `false` if it was
    /// already undone or cancelled.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn undo(&mut self, id: RecoveryId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE account_recoveries SET undone_at = now()
                WHERE id = $1 AND cancelled_at IS NULL AND undone_at IS NULL",
                id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }
}
