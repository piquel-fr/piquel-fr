use super::*;
use chrono::{DateTime, Utc};

impl SessionRepository<'_> {
    /// Locks the session during a transaction so logout cannot race a settings change.
    pub async fn management_active(&mut self, id: SessionId) -> Result<bool, DatabaseError> {
        Ok(fetch_optional!(self, sqlx::query("SELECT s.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.management_expires_at>clock_timestamp() AND u.status='active' FOR UPDATE OF s").bind(id.as_uuid()))?.is_some())
    }

    pub async fn management_expiry(
        &mut self,
        id: SessionId,
    ) -> Result<Option<DateTime<Utc>>, DatabaseError> {
        let row = fetch_optional!(self, sqlx::query("SELECT management_expires_at FROM sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>now() AND management_expires_at>now()").bind(id.as_uuid()))?;
        row.map(|row| row.try_get("management_expires_at").map_err(Into::into))
            .transpose()
            .map(Option::flatten)
    }

    pub async fn grant_management(
        &mut self,
        id: SessionId,
    ) -> Result<DateTime<Utc>, DatabaseError> {
        let row = fetch_one!(self, sqlx::query("UPDATE sessions SET management_expires_at=LEAST(expires_at,clock_timestamp()+interval '2 minutes') WHERE id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp() RETURNING management_expires_at").bind(id.as_uuid()))?;
        row.try_get("management_expires_at").map_err(Into::into)
    }

    pub async fn revoke_other(
        &mut self,
        user_id: UserId,
        except_session: SessionId,
    ) -> Result<u64, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE sessions SET revoked_at=now(),management_expires_at=NULL WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL").bind(user_id.as_uuid()).bind(except_session.as_uuid()))?.rows_affected())
    }
}

impl SecurityRepository<'_> {
    pub async fn create_invitation(
        &mut self,
        digest: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        execute!(
            self,
            sqlx::query("INSERT INTO invitations(secret_digest,expires_at) VALUES($1,$2)")
                .bind(digest)
                .bind(expires_at)
        )?;
        Ok(())
    }

    pub async fn invitation_active(&mut self, digest: &[u8]) -> Result<bool, DatabaseError> {
        Ok(fetch_optional!(self, sqlx::query("SELECT 1 FROM invitations WHERE secret_digest=$1 AND redeemed_at IS NULL AND expires_at>now()").bind(digest))?.is_some())
    }

    /// Redeems an invitation inside the account-creation transaction.
    pub async fn redeem_invitation(&mut self, digest: &[u8]) -> Result<bool, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE invitations SET redeemed_at=clock_timestamp() WHERE secret_digest=$1 AND redeemed_at IS NULL AND expires_at>clock_timestamp()").bind(digest))?.rows_affected()==1)
    }

    /// A database-backed fixed window shared by all service processes.
    pub async fn allow_request(
        &mut self,
        bucket: &[u8],
        limit: i32,
    ) -> Result<bool, DatabaseError> {
        let row = fetch_one!(self, sqlx::query("INSERT INTO request_limits(bucket,requests,expires_at) VALUES($1,1,now()+interval '1 minute') ON CONFLICT(bucket) DO UPDATE SET requests=CASE WHEN request_limits.expires_at<=now() THEN 1 ELSE request_limits.requests+1 END, expires_at=CASE WHEN request_limits.expires_at<=now() THEN now()+interval '1 minute' ELSE request_limits.expires_at END RETURNING requests").bind(bucket))?;
        Ok(row.try_get::<i32, _>("requests")? <= limit)
    }
}
