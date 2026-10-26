//! Transactional refresh-token families, rotation and replay revocation.

use super::{RepositoryExecutor, TokenRepository};
use crate::{DatabaseError, SessionAuthentication};
use chrono::{DateTime, Utc};
use piquel_common::{ClientId, SessionId, TokenId, UserId};
use sqlx::types::Json;
use thiserror::Error;

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
    /// Authorization code the grant was redeemed from; replaying the code
    /// revokes the family.
    pub authorization_code_id: TokenId,
    /// Granted token audience.
    pub audience: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// How the session had authenticated when the code was issued. Every token
    /// of the family reports it (OIDC Core §12.2).
    pub authentication: SessionAuthentication,
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
    /// Fingerprint of the digest key that made `secret_digest`.
    pub digest_key: String,
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
    /// How the session had authenticated when the grant's code was issued.
    pub authentication: SessionAuthentication,
}

/// A refresh family that a revocation ended.
#[derive(Clone, Copy, Debug)]
pub struct RevokedFamily {
    /// The revoked family.
    pub id: TokenId,
    /// Account the grant belonged to.
    pub user_id: UserId,
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
        /// The revoked family.
        family_id: TokenId,
    },
    /// The client no longer allows the grant; its family is now revoked.
    #[error("the client policy no longer allows the refresh grant")]
    Policy {
        /// Account whose grant was revoked.
        user_id: UserId,
        /// The revoked family.
        family_id: TokenId,
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
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO refresh_token_families (
                    id, user_id, client_id, session_id, authorization_code_id, audience, scopes,
                    authentication
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                family.id.as_uuid(),
                family.user_id.as_uuid(),
                family.client_id,
                family.session_id.as_uuid(),
                family.authorization_code_id.as_uuid(),
                family.audience,
                Json(&family.scopes) as _,
                Json(&family.authentication) as _,
            )
        )?;
        self.insert_token(token).await
    }

    /// Adds a token to an existing family, e.g. the replacement after rotation.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails.
    pub async fn insert_token(&mut self, token: &InsertRefreshToken) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO refresh_tokens (id, family_id, secret_digest, expires_at, digest_key)
                VALUES ($1, $2, $3, $4, $5)",
                token.id.as_uuid(),
                token.family_id.as_uuid(),
                token.secret_digest,
                token.expires_at,
                token.digest_key,
            )
        )?;
        Ok(())
    }

    /// Locks the token's account, session, family and client in a fixed order.
    async fn lock_rotation(
        &mut self,
        id: TokenId,
        digests: &[Vec<u8>],
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
        let owner = run!(
            self,
            fetch_optional,
            sqlx::query!(
                "SELECT f.user_id, f.session_id, f.id AS family_id
                FROM refresh_tokens t
                JOIN refresh_token_families f ON f.id = t.family_id
                WHERE t.id = $1
                AND t.secret_digest = ANY($2)
                AND f.client_id = $3",
                id.as_uuid(),
                digests,
                client,
            )
        )?
        .ok_or(RefreshRotationError::Invalid)?;
        // The user key never changes: NO KEY UPDATE permits concurrent session
        // foreign-key checks while we wait for its session lock.
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT id
                FROM users
                WHERE id = $1
                AND status = 'active'
                FOR NO KEY UPDATE",
                owner.user_id,
            )
        )?
        .ok_or(RefreshRotationError::Invalid)?;
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT id
                FROM sessions
                WHERE id = $1
                AND revoked_at IS NULL
                AND expires_at > now()
                FOR UPDATE",
                owner.session_id,
            )
        )?
        .ok_or(RefreshRotationError::Invalid)?;
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT id
                FROM refresh_token_families
                WHERE id = $1
                AND revoked_at IS NULL
                FOR UPDATE",
                owner.family_id,
            )
        )?
        .ok_or(RefreshRotationError::Invalid)?;
        // Shared policy locks let independent accounts refresh concurrently while
        // still serializing client-policy updates until token issuance commits.
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT id FROM oidc_clients WHERE id=$1 AND enabled FOR SHARE",
                client,
            )
        )?
        .ok_or(RefreshRotationError::Invalid)?;
        Ok(())
    }

    /// Revokes a family that was replayed or lost its client policy.
    async fn revoke_family(&mut self, family: TokenId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE refresh_token_families
                SET revoked_at = now()
                WHERE id = $1
                AND revoked_at IS NULL",
                family.as_uuid(),
            )
        )?;
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
        digests: &[Vec<u8>],
        client: &str,
    ) -> Result<RotatedRefreshToken, RefreshRotationError> {
        /// Decodes a JSONB column of the grant, naming it if invalid.
        fn decode<T: serde::de::DeserializeOwned>(
            column: &str,
            value: serde_json::Value,
        ) -> Result<T, DatabaseError> {
            serde_json::from_value(value).map_err(|source| DatabaseError::InvalidStoredData {
                column: column.into(),
                source: source.into(),
            })
        }
        self.lock_rotation(id, digests, client).await?;
        let row = run!(
            self,
            fetch_optional,
            sqlx::query!(
                r#"SELECT
                    t.family_id AS "family_id: TokenId", t.consumed_at,
                    f.user_id AS "user_id: UserId", f.client_id,
                    f.session_id AS "session_id: SessionId", f.audience, f.scopes,
                    f.authentication, c.allow_refresh, c.allowed_scopes, c.allowed_audiences
                FROM refresh_tokens t
                JOIN refresh_token_families f ON f.id = t.family_id
                JOIN oidc_clients c ON c.id = f.client_id
                JOIN sessions s ON s.id = f.session_id
                JOIN users u ON u.id = f.user_id
                WHERE t.id = $1
                AND t.secret_digest = ANY($2)
                AND f.client_id = $3
                AND t.expires_at > now()
                AND f.revoked_at IS NULL
                AND c.enabled
                AND s.user_id = f.user_id
                AND s.revoked_at IS NULL
                AND s.expires_at > now()
                AND u.status = 'active'
                FOR UPDATE OF t"#,
                id.as_uuid(),
                digests,
                client,
            )
        )?
        .ok_or(RefreshRotationError::Invalid)?;
        let (family_id, user_id) = (row.family_id, row.user_id);
        if row.consumed_at.is_some() {
            self.revoke_family(family_id).await?;
            return Err(RefreshRotationError::Replay { user_id, family_id });
        }
        // The grant's JSON is decoded only after the replay check, so a replayed
        // token revokes its family even if that JSON is invalid.
        let strings = decode::<Vec<String>>;
        let scopes = strings("scopes", row.scopes)?;
        let allowed_scopes = strings("allowed_scopes", row.allowed_scopes)?;
        let policy_valid = row.allow_refresh
            && strings("allowed_audiences", row.allowed_audiences)?.contains(&row.audience)
            && scopes.iter().all(|scope| allowed_scopes.contains(scope));
        if !policy_valid {
            self.revoke_family(family_id).await?;
            return Err(RefreshRotationError::Policy { user_id, family_id });
        }
        if run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE refresh_tokens SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL",
                id.as_uuid(),
            )
        )?
        .rows_affected()
            != 1
        {
            return Err(RefreshRotationError::Invalid);
        }
        Ok(RotatedRefreshToken {
            family_id,
            user_id,
            client_id: row.client_id,
            session_id: row.session_id,
            audience: row.audience,
            scopes,
            authentication: decode("authentication", row.authentication)?,
        })
    }

    /// Revokes the family of the token matching `id` and any of `digests`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_family_for_token(
        &mut self,
        id: TokenId,
        digests: &[Vec<u8>],
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE refresh_token_families f
                SET revoked_at = COALESCE(revoked_at, now())
                FROM refresh_tokens t
                WHERE t.id = $1
                AND t.secret_digest = ANY($2)
                AND t.family_id = f.id",
                id.as_uuid(),
                digests,
            )
        )?;
        Ok(())
    }

    /// Like [`Self::revoke_family_for_token`], but only for a family issued to
    /// `client` (token revocation by that client). Returns the family if this
    /// call revoked it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_family_for_client_token(
        &mut self,
        id: TokenId,
        digests: &[Vec<u8>],
        client: &str,
    ) -> Result<Option<RevokedFamily>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                RevokedFamily,
                r#"UPDATE refresh_token_families f
                SET revoked_at = now()
                FROM refresh_tokens t
                WHERE t.id = $1
                AND t.secret_digest = ANY($2)
                AND t.family_id = f.id
                AND f.client_id = $3
                AND f.revoked_at IS NULL
                RETURNING f.id AS "id: TokenId", f.user_id AS "user_id: UserId""#,
                id.as_uuid(),
                digests,
                client,
            )
        )
    }

    /// Locks one family until the transaction ends, for tests that order
    /// concurrent revocations on what holds which lock.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    #[cfg(feature = "test-support")]
    pub async fn lock_family(&mut self, id: TokenId) -> Result<(), DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_scalar!(
                "SELECT id FROM refresh_token_families WHERE id = $1 FOR UPDATE",
                id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// Locks the client's live families until the transaction ends, in ID order.
    /// A rotation locks its family before its client, so a change that locks the
    /// client and then writes its families, such as a deletion, takes these
    /// first; otherwise each could hold the lock the other waits for.
    ///
    /// Every statement that locks several families locks them in ID order, as
    /// this one does, so two of them never wait for each other's families: a
    /// deletion's for a client and a logout's for a session can share some.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn lock_client_families(&mut self, client: &ClientId) -> Result<(), DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_scalar!(
                "SELECT id FROM refresh_token_families
                WHERE client_id = $1 AND revoked_at IS NULL
                ORDER BY id
                FOR UPDATE",
                client.as_str(),
            )
        )?;
        Ok(())
    }

    /// Revokes the account's active families of `client`, or of every client when
    /// `None`, and returns how many were revoked.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_for_user(
        &mut self,
        user_id: UserId,
        client: Option<&ClientId>,
    ) -> Result<u64, DatabaseError> {
        // Locked in ID order, as `lock_client_families` explains.
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "WITH locked AS (
                    SELECT id FROM refresh_token_families
                    WHERE user_id = $1
                    AND ($2::TEXT IS NULL OR client_id = $2)
                    AND revoked_at IS NULL
                    ORDER BY id
                    FOR UPDATE
                )
                UPDATE refresh_token_families f
                SET revoked_at = now()
                FROM locked
                WHERE f.id = locked.id AND f.revoked_at IS NULL",
                user_id.as_uuid(),
                client.map(ClientId::as_str),
            )
        )?
        .rows_affected())
    }
}
/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
