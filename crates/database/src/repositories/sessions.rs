//! Active browser sessions, cookie digests and passkey confirmations.

use super::{JsonArray, RepositoryExecutor, SessionRepository};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{AuthenticationMethod, SessionId, UserId};
use sqlx::types::Json;

/// A new browser session.
#[derive(Clone, Debug)]
pub struct InsertSession {
    /// Session identifier.
    pub id: SessionId,
    /// Authenticated account; it must be active.
    pub user_id: UserId,
    /// Methods that authenticated this session, reported as `amr`.
    pub authentication_methods: Vec<AuthenticationMethod>,
    /// When authentication happened; also the initial `last_seen_at`.
    pub authenticated_at: DateTime<Utc>,
    /// Absolute expiry; must be after `authenticated_at`.
    pub expires_at: DateTime<Utc>,
    /// Coarse user agent family, if recorded; never the raw header.
    pub user_agent_family: Option<String>,
    /// When the session last proved possession of a passkey, if it did.
    pub passkey_confirmed_at: Option<DateTime<Utc>>,
}

/// A browser session row.
#[derive(Clone, Debug)]
pub struct StoredSession {
    /// Session identifier.
    pub id: SessionId,
    /// Authenticated account.
    pub user_id: UserId,
    /// Methods that authenticated this session.
    pub authentication_methods: Vec<AuthenticationMethod>,
    /// When authentication happened.
    pub authenticated_at: DateTime<Utc>,
    /// Absolute expiry.
    pub expires_at: DateTime<Utc>,
    /// Last recorded activity.
    pub last_seen_at: DateTime<Utc>,
    /// When the session was revoked; `None` while it is usable.
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the session last proved possession of a passkey. Social sign-in never sets it.
    pub passkey_confirmed_at: Option<DateTime<Utc>>,
}

impl SessionRepository<'_> {
    /// Creates a session for an active account.
    ///
    /// The account row stays locked through insertion, so disablement and
    /// session creation share one serialization point: a session is never
    /// committed for an account that was disabled first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the account is not active, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn insert(&mut self, input: &InsertSession) -> Result<StoredSession, DatabaseError> {
        run!(
            self,
            fetch_one,
            sqlx::query_as!(
                StoredSession,
                r#"WITH active_user AS (
                    SELECT id
                    FROM users
                    WHERE id = $2
                    AND status = 'active'
                    FOR NO KEY UPDATE
                )
                INSERT INTO sessions (
                    id, user_id, authentication_methods, authenticated_at, expires_at,
                    last_seen_at, user_agent_family, passkey_confirmed_at
                )
                SELECT $1, id, $3, $4, $5, $4, $6, $7
                FROM active_user
                RETURNING
                    id AS "id: SessionId", user_id AS "user_id: UserId",
                    authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    authenticated_at, expires_at, last_seen_at, revoked_at, passkey_confirmed_at"#,
                input.id.as_uuid(),
                input.user_id.as_uuid(),
                Json(&input.authentication_methods) as _,
                input.authenticated_at,
                input.expires_at,
                input.user_agent_family,
                input.passkey_confirmed_at,
            )
        )
    }

    /// Finds a session in any state.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_by_id(
        &mut self,
        id: SessionId,
    ) -> Result<Option<StoredSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredSession,
                r#"SELECT
                    id AS "id: SessionId", user_id AS "user_id: UserId",
                    authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    authenticated_at, expires_at, last_seen_at, revoked_at, passkey_confirmed_at
                FROM sessions
                WHERE id = $1"#,
                id.as_uuid(),
            )
        )
    }

    /// Finds an unrevoked, unexpired session of an active account.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_id(
        &mut self,
        id: SessionId,
    ) -> Result<Option<StoredSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredSession,
                r#"SELECT
                    s.id AS "id: SessionId", s.user_id AS "user_id: UserId",
                    s.authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    s.authenticated_at, s.expires_at, s.last_seen_at, s.revoked_at,
                    s.passkey_confirmed_at
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.id = $1
                AND s.revoked_at IS NULL
                AND s.expires_at > now()
                AND u.status = 'active'"#,
                id.as_uuid(),
            )
        )
    }

    /// Finds and locks an unrevoked, unexpired session of an active account, so a
    /// concurrent logout either commits first or waits until this transaction ends.
    /// Callers lock the account first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_id_for_update(
        &mut self,
        id: SessionId,
    ) -> Result<Option<StoredSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredSession,
                r#"SELECT
                    s.id AS "id: SessionId", s.user_id AS "user_id: UserId",
                    s.authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    s.authenticated_at, s.expires_at, s.last_seen_at, s.revoked_at,
                    s.passkey_confirmed_at
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.id = $1
                AND s.revoked_at IS NULL
                AND s.expires_at > now()
                AND u.status = 'active'
                FOR NO KEY UPDATE OF s"#,
                id.as_uuid(),
            )
        )
    }

    /// Revokes a session. Returns `false` if it was already revoked or unknown.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke(&mut self, id: SessionId) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL",
                id.as_uuid(),
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Revokes every other unrevoked session of the account and returns how
    /// many were revoked.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn revoke_other(
        &mut self,
        user_id: UserId,
        except_session: SessionId,
    ) -> Result<u64, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE sessions
                SET revoked_at = now(), passkey_confirmed_at = NULL
                WHERE user_id = $1
                AND id <> $2
                AND revoked_at IS NULL",
                user_id.as_uuid(),
                except_session.as_uuid(),
            )
        )?
        .rows_affected())
    }

    /// Stores the digest of a session's browser cookie secret.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Conflict`] if the session already has a secret
    /// or the digest is reused, or another [`DatabaseError`] if the query fails.
    pub async fn insert_browser_secret(
        &mut self,
        session_id: SessionId,
        digest: &[u8],
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO browser_session_secrets(session_id,secret_digest) VALUES($1,$2)",
                session_id.as_uuid(),
                digest,
            )
        )?;
        Ok(())
    }

    /// Finds the active session whose browser secret has this digest.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or the row is invalid.
    pub async fn find_active_by_browser_secret(
        &mut self,
        digest: &[u8],
    ) -> Result<Option<StoredSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredSession,
                r#"SELECT
                    s.id AS "id: SessionId", s.user_id AS "user_id: UserId",
                    s.authentication_methods AS "authentication_methods: JsonArray<AuthenticationMethod>",
                    s.authenticated_at, s.expires_at, s.last_seen_at, s.revoked_at,
                    s.passkey_confirmed_at
                FROM browser_session_secrets b
                JOIN sessions s ON s.id = b.session_id
                JOIN users u ON u.id = s.user_id
                WHERE b.secret_digest = $1
                AND s.revoked_at IS NULL
                AND s.expires_at > now()
                AND u.status = 'active'"#,
                digest,
            )
        )
    }

    /// Records that the session proved possession of a passkey `at` this time.
    /// Protected actions accept the confirmation for a fixed time after it, so using
    /// it never extends it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::NotFound`] if the session is revoked or expired, or
    /// another [`DatabaseError`] if the query fails.
    pub async fn confirm_passkey(
        &mut self,
        id: SessionId,
        at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        let updated = run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE sessions
                SET passkey_confirmed_at = $2
                WHERE id = $1
                AND revoked_at IS NULL
                AND expires_at > now()",
                id.as_uuid(),
                at,
            )
        )?
        .rows_affected();
        if updated == 0 {
            return Err(DatabaseError::NotFound);
        }
        Ok(())
    }
}
