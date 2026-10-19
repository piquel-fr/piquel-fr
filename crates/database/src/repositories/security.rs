//! Single-use signup invitations and shared per-client request budgets.

use super::{RepositoryExecutor, SecurityRepository};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_admin_api::Invitation;
use piquel_common::TokenId;

impl SecurityRepository<'_> {
    /// Stores an invitation by the 32-byte digest of its secret.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for a digest of
    /// the wrong length or one that already exists.
    pub async fn create_invitation(
        &mut self,
        id: TokenId,
        digest: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO invitations(id,secret_digest,expires_at) VALUES($1,$2,$3)",
                id.as_uuid(),
                digest,
                expires_at,
            )
        )?;
        Ok(())
    }

    /// Lists every invitation not yet purged, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn list_invitations(&mut self) -> Result<Vec<Invitation>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                Invitation,
                r#"SELECT id AS "id: TokenId", created_at, expires_at, redeemed_at, revoked_at
                FROM invitations
                ORDER BY created_at DESC, id DESC"#
            )
        )
    }

    /// Revokes an unredeemed invitation. Returns `false` if it is unknown,
    /// redeemed or already revoked. It also expires now: releases before
    /// `revoked_at` check only the expiry, and cleanup then purges it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_invitation(&mut self, id: TokenId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE invitations
                SET revoked_at = now(), expires_at = LEAST(expires_at, now())
                WHERE id = $1
                AND redeemed_at IS NULL
                AND revoked_at IS NULL",
                id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Reports whether an invitation exists, is unexpired, unrevoked and unredeemed.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn invitation_active(&mut self, digest: &[u8]) -> Result<bool, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
                r#"SELECT EXISTS (
                    SELECT
                    FROM invitations
                    WHERE secret_digest = $1
                    AND redeemed_at IS NULL
                    AND revoked_at IS NULL
                    AND expires_at > now()
                ) AS "active!""#,
                digest,
            )
        )
    }

    /// Redeems an active invitation. Returns `false` if it is unknown,
    /// expired, revoked or already redeemed. Call it inside the account-creation
    /// transaction so a rollback keeps the invitation usable.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn redeem_invitation(&mut self, digest: &[u8]) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE invitations
                SET redeemed_at = clock_timestamp()
                WHERE secret_digest = $1
                AND redeemed_at IS NULL
                AND revoked_at IS NULL
                AND expires_at > clock_timestamp()",
                digest,
            )
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
        let requests = run!(
            self,
            fetch_one,
            sqlx::query_scalar!(
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
                RETURNING requests",
                bucket,
            )
        )?;
        Ok(requests <= limit)
    }
}
