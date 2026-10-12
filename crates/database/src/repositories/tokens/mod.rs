use super::{RepositoryExecutor, StoredRow, TokenRepository};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{SessionId, TokenId, UserId};
use sqlx::types::Json;
use thiserror::Error;
use uuid::Uuid;

/// A new refresh token family: one grant whose tokens rotate on each use.
#[derive(Clone, Debug)]
pub struct InsertRefreshFamily {
    /// Family identifier.
    pub id: TokenId,
    /// Account the grant belongs to.
    pub user_id: UserId,
    /// Client the grant was issued to.
    pub client_id: String,
    /// Session the grant came from; revoking it revokes the family.
    pub session_id: SessionId,
    /// Granted token audience.
    pub audience: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
}

/// A new refresh token within a family.
#[derive(Clone, Debug)]
pub struct InsertRefreshToken {
    /// Token identifier.
    pub id: TokenId,
    /// Family the token belongs to.
    pub family_id: TokenId,
    /// Digest of the token secret.
    pub secret_digest: Vec<u8>,
    /// When the token stops being accepted.
    pub expires_at: DateTime<Utc>,
}

/// The grant behind a refresh token consumed by
/// [`TokenRepository::consume_for_rotation`].
#[derive(Clone, Debug)]
pub struct RotatedRefreshToken {
    /// Family to issue the replacement token in.
    pub family_id: TokenId,
    /// Account the grant belongs to.
    pub user_id: UserId,
    /// Client the grant was issued to.
    pub client_id: String,
    /// Session the grant came from.
    pub session_id: SessionId,
    /// Granted token audience.
    pub audience: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
}

/// Why a refresh token could not be rotated.
#[derive(Debug, Error)]
pub enum RefreshRotationError {
    /// The database failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// The token, its family, session, account or client is unknown, expired,
    /// revoked or disabled.
    #[error("the refresh token is invalid")]
    Invalid,
    /// The token was already used; its family is now revoked.
    #[error("the refresh token was replayed")]
    Replay {
        /// Account whose grant was revoked.
        user_id: UserId,
    },
    /// The client no longer allows the grant; its family is now revoked.
    #[error("the client policy no longer allows the refresh grant")]
    Policy {
        /// Account whose grant was revoked.
        user_id: UserId,
    },
}

impl TokenRepository<'_> {
    /// Creates a family together with its first token.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if an insert fails.
    pub async fn insert_family(
        &mut self,
        family: &InsertRefreshFamily,
        token: &InsertRefreshToken,
    ) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("INSERT INTO refresh_token_families(id,user_id,client_id,session_id,audience,scopes) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(family.id.as_uuid()).bind(family.user_id.as_uuid()).bind(&family.client_id)
            .bind(family.session_id.as_uuid()).bind(&family.audience).bind(Json(&family.scopes)))?;
        self.insert_token(token).await
    }

    /// Adds a token to an existing family, e.g. the replacement after rotation.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails.
    pub async fn insert_token(&mut self, token: &InsertRefreshToken) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("INSERT INTO refresh_tokens(id,family_id,secret_digest,expires_at) VALUES($1,$2,$3,$4)")
            .bind(token.id.as_uuid()).bind(token.family_id.as_uuid()).bind(&token.secret_digest).bind(token.expires_at))?;
        Ok(())
    }

    /// Locks the token's account, session, family and client in a fixed order.
    async fn lock_rotation(
        &mut self,
        id: TokenId,
        digest: &[u8],
        client: &str,
    ) -> Result<(), RefreshRotationError> {
        // All state locks must outlive rotation, replacement insertion and commit.
        if matches!(self.executor, RepositoryExecutor::Pool(_)) {
            return Err(
                DatabaseError::Operation("refresh rotation requires a transaction".into()).into(),
            );
        }
        // Look up immutable ownership without locks, then acquire locks explicitly.
        // Account mutations take user -> session -> family; logout takes session ->
        // family. A joined FOR UPDATE does not guarantee that ordering.
        let owner = fetch_optional!(
            self,
            sqlx::query(
                "SELECT f.user_id,f.session_id,f.id AS family_id FROM refresh_tokens t
             JOIN refresh_token_families f ON f.id=t.family_id
             WHERE t.id=$1 AND t.secret_digest=$2 AND f.client_id=$3"
            )
            .bind(id.as_uuid())
            .bind(digest)
            .bind(client)
        )?
        .ok_or(RefreshRotationError::Invalid)?;
        // The user key never changes: NO KEY UPDATE permits concurrent logout
        // audit/session foreign-key checks while we wait for its session lock.
        for (query, key) in [
            (
                "SELECT id FROM users WHERE id=$1 AND status='active' FOR NO KEY UPDATE",
                owner.column::<Uuid>("user_id")?,
            ),
            (
                "SELECT id FROM sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>now() FOR UPDATE",
                owner.column::<Uuid>("session_id")?,
            ),
            (
                "SELECT id FROM refresh_token_families WHERE id=$1 AND revoked_at IS NULL FOR UPDATE",
                owner.column::<Uuid>("family_id")?,
            ),
        ] {
            fetch_optional!(self, sqlx::query(query).bind(key))?
                .ok_or(RefreshRotationError::Invalid)?;
        }
        // Shared policy locks let independent accounts refresh concurrently while
        // still serializing client-policy updates until token issuance commits.
        fetch_optional!(
            self,
            sqlx::query("SELECT id FROM oidc_clients WHERE id=$1 AND enabled FOR SHARE")
                .bind(client)
        )?
        .ok_or(RefreshRotationError::Invalid)?;
        Ok(())
    }

    /// Revokes a family that was replayed or lost its client policy.
    async fn revoke_family(&mut self, family: TokenId) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("UPDATE refresh_token_families SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL").bind(family.as_uuid()))?;
        Ok(())
    }

    /// Consumes a refresh token for rotation and returns its grant.
    ///
    /// Must run in a transaction kept open through replacement-token insertion
    /// and commit: the rotation locks the token's account, session, family and
    /// client until then.
    ///
    /// # Errors
    ///
    /// Returns [`RefreshRotationError::Replay`] or
    /// [`RefreshRotationError::Policy`] after revoking the family,
    /// [`RefreshRotationError::Invalid`] if the token is not usable, or
    /// [`RefreshRotationError::Database`] if a query fails or this repository
    /// is not bound to a transaction.
    pub async fn consume_for_rotation(
        &mut self,
        id: TokenId,
        digest: &[u8],
        client: &str,
    ) -> Result<RotatedRefreshToken, RefreshRotationError> {
        self.lock_rotation(id, digest, client).await?;
        let row = fetch_optional!(
            self,
            sqlx::query(
                "SELECT t.family_id,t.consumed_at,f.user_id,f.client_id,f.session_id,
                    f.audience,f.scopes,c.allow_refresh,c.allowed_scopes,c.allowed_audiences
             FROM refresh_tokens t
             JOIN refresh_token_families f ON f.id=t.family_id
             JOIN oidc_clients c ON c.id=f.client_id
             JOIN sessions s ON s.id=f.session_id
             JOIN users u ON u.id=f.user_id
             WHERE t.id=$1 AND t.secret_digest=$2 AND f.client_id=$3
               AND t.expires_at>now() AND f.revoked_at IS NULL AND c.enabled
               AND s.user_id=f.user_id AND s.revoked_at IS NULL AND s.expires_at>now()
               AND u.status='active'
             FOR UPDATE OF t"
            )
            .bind(id.as_uuid())
            .bind(digest)
            .bind(client)
        )?
        .ok_or(RefreshRotationError::Invalid)?;
        let family_id = row.id("family_id")?;
        let user_id = row.id("user_id")?;
        if row
            .column::<Option<DateTime<Utc>>>("consumed_at")?
            .is_some()
        {
            self.revoke_family(family_id).await?;
            return Err(RefreshRotationError::Replay { user_id });
        }
        let scopes: Vec<String> = row.json("scopes")?;
        let allowed_scopes: Vec<String> = row.json("allowed_scopes")?;
        let allowed_audiences: Vec<String> = row.json("allowed_audiences")?;
        let audience: String = row.column("audience")?;
        let policy_valid = row.column::<bool>("allow_refresh")?
            && allowed_audiences.contains(&audience)
            && scopes.iter().all(|scope| allowed_scopes.contains(scope));
        if !policy_valid {
            self.revoke_family(family_id).await?;
            return Err(RefreshRotationError::Policy { user_id });
        }
        if execute!(
            self,
            sqlx::query(
                "UPDATE refresh_tokens SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL"
            )
            .bind(id.as_uuid())
        )?
        .rows_affected()
            != 1
        {
            return Err(RefreshRotationError::Invalid);
        }
        Ok(RotatedRefreshToken {
            family_id,
            user_id,
            client_id: row.column("client_id")?,
            session_id: row.id("session_id")?,
            audience,
            scopes,
        })
    }

    /// Revokes the family of the token matching `id` and `digest`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_family_for_token(
        &mut self,
        id: TokenId,
        digest: &[u8],
    ) -> Result<(), DatabaseError> {
        execute!(self, sqlx::query("UPDATE refresh_token_families f SET revoked_at=COALESCE(revoked_at,now()) FROM refresh_tokens t WHERE t.id=$1 AND t.secret_digest=$2 AND t.family_id=f.id").bind(id.as_uuid()).bind(digest))?;
        Ok(())
    }

    /// Like [`Self::revoke_family_for_token`], but only for a family issued to
    /// `client` (token revocation by that client).
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_family_for_client_token(
        &mut self,
        id: TokenId,
        digest: &[u8],
        client: &str,
    ) -> Result<(), DatabaseError> {
        execute!(self,sqlx::query("UPDATE refresh_token_families f SET revoked_at=COALESCE(revoked_at,now()) FROM refresh_tokens t WHERE t.id=$1 AND t.secret_digest=$2 AND t.family_id=f.id AND f.client_id=$3").bind(id.as_uuid()).bind(digest).bind(client))?;
        Ok(())
    }

    /// Revokes every active family of the account and returns how many were
    /// revoked.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_all_for_user(&mut self, user_id: UserId) -> Result<u64, DatabaseError> {
        Ok(execute!(self, sqlx::query("UPDATE refresh_token_families SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL").bind(user_id.as_uuid()))?.rows_affected())
    }
}

#[cfg(test)]
mod tests;
