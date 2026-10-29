//! Sign-ins to the admin dashboard: the codes auth hands off with, and the
//! dashboard's own sessions. Both rest on an auth session, and go with it.

use super::{DashboardRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{Handle, SessionId, UserId};

/// A handoff code, which redeems once, before `expires_at`, in the browser
/// holding the state its digest names.
pub struct InsertHandoff<'a> {
    /// SHA-256 of the code.
    pub code_digest: &'a [u8],
    /// The auth session handing off.
    pub session_id: SessionId,
    /// SHA-256 of the dashboard's state cookie in the browser that asked.
    pub state_digest: &'a [u8],
    /// The dashboard path to go on to.
    pub return_to: &'a str,
    /// When a passkey confirmed the handoff, if one did.
    pub confirmed_at: Option<DateTime<Utc>>,
    /// When the code stops working.
    pub expires_at: DateTime<Utc>,
}

/// A handoff code, as its redemption consumed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedeemedHandoff {
    /// The auth session that handed off.
    pub session_id: SessionId,
    /// The dashboard path to go on to.
    pub return_to: String,
    /// When a passkey confirmed the handoff, if one did.
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// A dashboard session whose auth session is still active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredDashboardSession {
    /// Its auth session.
    pub session_id: SessionId,
    /// The account signed in.
    pub user_id: UserId,
    /// The account's handle, which the dashboard shows.
    pub handle: Handle,
    /// When a passkey last confirmed it, in a ceremony started for the dashboard.
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// One of an account's sign-ins to the dashboard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DashboardSignIn {
    /// The auth session it rests on.
    pub session_id: SessionId,
    /// When it started.
    pub created_at: DateTime<Utc>,
    /// When a passkey last confirmed it, if one did.
    pub confirmed_at: Option<DateTime<Utc>>,
}

impl DashboardRepository<'_> {
    /// Lists `user_id`'s dashboard sessions, newest first, while their auth
    /// sessions are kept.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn of_user(
        &mut self,
        user_id: UserId,
    ) -> Result<Vec<DashboardSignIn>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                DashboardSignIn,
                r#"SELECT d.session_id AS "session_id: SessionId", d.created_at, d.confirmed_at
                FROM dashboard_sessions d
                JOIN sessions s ON s.id = d.session_id
                WHERE s.user_id = $1
                ORDER BY d.created_at DESC"#,
                user_id.as_uuid(),
            )
        )
    }

    /// Stores a handoff code.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for an unknown session.
    pub async fn insert_handoff(
        &mut self,
        handoff: &InsertHandoff<'_>,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO dashboard_handoffs
                    (code_digest, session_id, state_digest, return_to, confirmed_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6)",
                handoff.code_digest,
                handoff.session_id.as_uuid(),
                handoff.state_digest,
                handoff.return_to,
                handoff.confirmed_at,
                handoff.expires_at,
            )
        )?;
        Ok(())
    }

    /// Consumes the unexpired code with this digest, if the browser's state has
    /// this digest. A code presented with another state stays, so a forged
    /// redemption cannot burn the browser's own.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn redeem_handoff(
        &mut self,
        code_digest: &[u8],
        state_digest: &[u8],
    ) -> Result<Option<RedeemedHandoff>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                RedeemedHandoff,
                r#"DELETE FROM dashboard_handoffs
                WHERE code_digest = $1 AND state_digest = $2 AND expires_at > now()
                RETURNING session_id AS "session_id: SessionId", return_to, confirmed_at"#,
                code_digest,
                state_digest,
            )
        )
    }

    /// Stores a dashboard session of the auth session `session_id`, confirmed at
    /// `confirmed_at` if a passkey confirmed it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for an unknown session.
    pub async fn insert_session(
        &mut self,
        secret_digest: &[u8],
        session_id: SessionId,
        confirmed_at: Option<DateTime<Utc>>,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO dashboard_sessions (secret_digest, session_id, confirmed_at)
                VALUES ($1, $2, $3)",
                secret_digest,
                session_id.as_uuid(),
                confirmed_at,
            )
        )?;
        Ok(())
    }

    /// The dashboard session with this cookie digest, if its auth session is still
    /// active: signing out, a revocation or an expiry of the auth session ends it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn find_session(
        &mut self,
        secret_digest: &[u8],
    ) -> Result<Option<StoredDashboardSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredDashboardSession,
                r#"SELECT d.session_id AS "session_id: SessionId",
                    s.user_id AS "user_id: UserId", h.handle AS "handle: Handle", d.confirmed_at
                FROM dashboard_sessions d
                JOIN sessions s ON s.id = d.session_id
                JOIN handles h ON h.user_id = s.user_id AND h.released_at IS NULL
                WHERE d.secret_digest = $1
                AND s.revoked_at IS NULL AND s.expires_at > now()"#,
                secret_digest,
            )
        )
    }

    /// Ends the dashboard session with this cookie digest. Returns `false` if there
    /// was none.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn delete_session(&mut self, secret_digest: &[u8]) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "DELETE FROM dashboard_sessions WHERE secret_digest = $1",
                secret_digest,
            )
        )?
        .rows_affected()
            == 1)
    }
}
