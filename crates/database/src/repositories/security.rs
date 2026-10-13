//! Single-use signup invitations and shared per-client request budgets.

use super::{RepositoryExecutor, SecurityRepository, StoredRow};
use crate::DatabaseError;
use chrono::{DateTime, Utc};

impl SecurityRepository<'_> {
    /// Stores an invitation by the 32-byte digest of its secret.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for a digest of
    /// the wrong length or one that already exists.
    pub async fn create_invitation(
        &mut self,
        digest: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query("INSERT INTO invitations(secret_digest,expires_at) VALUES($1,$2)")
                .bind(digest)
                .bind(expires_at)
        )?;
        Ok(())
    }

    /// Reports whether an invitation exists, is unexpired and is unredeemed.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn invitation_active(&mut self, digest: &[u8]) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            fetch_optional,
            sqlx::query(
                "SELECT 1
                FROM invitations
                WHERE secret_digest = $1
                AND redeemed_at IS NULL
                AND expires_at > now()"
            )
            .bind(digest)
        )?
        .is_some())
    }

    /// Redeems an active invitation. Returns `false` if it is unknown,
    /// expired or already redeemed. Call it inside the account-creation
    /// transaction so a rollback keeps the invitation usable.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn redeem_invitation(&mut self, digest: &[u8]) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query(
                "UPDATE invitations
                SET redeemed_at = clock_timestamp()
                WHERE secret_digest = $1
                AND redeemed_at IS NULL
                AND expires_at > clock_timestamp()"
            )
            .bind(digest)
        )?
        .rows_affected()
            == 1)
    }

    /// Counts a request in `bucket`'s one-minute fixed window and reports
    /// whether the window is still within `limit` requests. The counter is
    /// shared by all service processes.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn allow_request(
        &mut self,
        bucket: &[u8],
        limit: i32,
    ) -> Result<bool, DatabaseError> {
        let row = run!(
            self,
            fetch_one,
            sqlx::query(
                "INSERT INTO request_limits (bucket, requests, expires_at)
                VALUES ($1, 1, now() + interval '1 minute')
                ON CONFLICT (bucket) DO UPDATE
                SET requests = CASE
                        WHEN request_limits.expires_at <= now() THEN 1
                        ELSE request_limits.requests + 1
                    END,
                    expires_at = CASE
                        WHEN request_limits.expires_at <= now() THEN now() + interval '1 minute'
                        ELSE request_limits.expires_at
                    END
                RETURNING requests"
            )
            .bind(bucket)
        )?;
        Ok(row.column::<i32>("requests")? <= limit)
    }
}
