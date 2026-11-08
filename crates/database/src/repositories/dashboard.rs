//! Sign-ins to the admin dashboard: the codes auth hands off with, and the
//! dashboard's own sessions. Both rest on an auth session, and go with it.

use super::{DashboardRepository, RepositoryExecutor};
use crate::DatabaseError;
use chrono::{DateTime, Utc};
use piquel_common::{Handle, PictureId, SessionId, UserId, admin::DashboardSession};
use uuid::Uuid;

/// A handoff code, which redeems once, before `expires_at`, in the browser
/// holding the state its digest names. Every handoff needs a passkey's proof.
pub struct InsertHandoff<'a> {
    /// SHA-256 of the code.
    pub code_digest: &'a [u8],
    /// The auth session handing off.
    pub session_id: SessionId,
    /// SHA-256 of the dashboard's state cookie in the browser that asked.
    pub state_digest: &'a [u8],
    /// The dashboard path to go on to.
    pub return_to: &'a str,
    /// When a passkey proved the handoff, which confirms the dashboard session
    /// it starts.
    pub confirmed_at: DateTime<Utc>,
    /// When the code stops working.
    pub expires_at: DateTime<Utc>,
}

/// A handoff code, as its redemption consumed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedeemedHandoff {
    /// The auth session that handed off.
    pub session_id: SessionId,
    /// Its account.
    pub user_id: UserId,
    /// The dashboard path to go on to.
    pub return_to: String,
    /// When a passkey proved the handoff.
    pub confirmed_at: DateTime<Utc>,
}

/// A dashboard session in use: its auth session is still active, and it has
/// not timed out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredDashboardSession {
    /// Its auth session.
    pub session_id: SessionId,
    /// The account signed in.
    pub user_id: UserId,
    /// The account's handle, which the dashboard shows.
    pub handle: Handle,
    /// The account's profile picture, which the dashboard shows.
    pub picture: Option<PictureId>,
    /// When a passkey last confirmed it, in a ceremony started for the dashboard.
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// A dashboard session that signing out ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndedDashboardSession {
    /// Its auth session.
    pub session_id: SessionId,
    /// The account that was signed in.
    pub user_id: UserId,
}

/// A claim's own token, which only the request that took it holds: only
/// [`DashboardRepository::claim_submission`] makes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmissionToken(Uuid);

/// What claiming a change the dashboard posted found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    /// The change is claimed now, by this token, to be made.
    Claimed(SubmissionToken),
    /// The same change was made moments ago.
    Made,
    /// The same change is being made still.
    Pending,
}

impl DashboardRepository<'_> {
    /// Lists `user_id`'s dashboard sessions still in use, newest first: their
    /// auth sessions are active, they have not reached their `expires_at`, and
    /// their last request came after `idle_since`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn of_user(
        &mut self,
        user_id: UserId,
        idle_since: DateTime<Utc>,
    ) -> Result<Vec<DashboardSession>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_as!(
                DashboardSession,
                r#"SELECT d.session_id AS "session_id: SessionId", d.created_at AS signed_in_at,
                    d.last_used_at, d.expires_at
                FROM dashboard_sessions d
                JOIN sessions s ON s.id = d.session_id
                WHERE s.user_id = $1
                AND s.revoked_at IS NULL AND s.expires_at > now()
                AND d.expires_at > now() AND d.last_used_at > $2
                ORDER BY d.created_at DESC"#,
                user_id.as_uuid(),
                idle_since,
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

    /// The account whose session handed off the unexpired code with this digest,
    /// if there is one: what redeeming it locks first.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn handoff_user(
        &mut self,
        code_digest: &[u8],
    ) -> Result<Option<UserId>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                r#"SELECT s.user_id AS "user_id: UserId"
                FROM dashboard_handoffs h
                JOIN sessions s ON s.id = h.session_id
                WHERE h.code_digest = $1 AND h.expires_at > now()"#,
                code_digest,
            )
        )
    }

    /// Consumes the unexpired code with this digest, if the browser's state has
    /// this digest, and a passkey proved it: the previous release handed off
    /// without one. A code presented with another state stays, so a forged
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
                r#"DELETE FROM dashboard_handoffs h
                USING sessions s
                WHERE h.code_digest = $1 AND h.state_digest = $2 AND h.expires_at > now()
                AND h.confirmed_at IS NOT NULL AND s.id = h.session_id
                RETURNING h.session_id AS "session_id: SessionId",
                    s.user_id AS "user_id: UserId", h.return_to,
                    h.confirmed_at AS "confirmed_at!""#,
                code_digest,
                state_digest,
            )
        )
    }

    /// Stores a dashboard session of the auth session `session_id`, confirmed at
    /// `confirmed_at`, which ends at `expires_at` however busy.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for an unknown session.
    pub async fn insert_session(
        &mut self,
        secret_digest: &[u8],
        session_id: SessionId,
        confirmed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO dashboard_sessions
                    (secret_digest, session_id, confirmed_at, expires_at)
                VALUES ($1, $2, $3, $4)",
                secret_digest,
                session_id.as_uuid(),
                confirmed_at,
                expires_at,
            )
        )?;
        Ok(())
    }

    /// Records that a passkey confirmed the dashboard session with this cookie
    /// digest at `confirmed_at`, if it still rests on the auth session
    /// `session_id`. Returns `false` if it does not, or there is none.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn confirm_session(
        &mut self,
        secret_digest: &[u8],
        session_id: SessionId,
        confirmed_at: DateTime<Utc>,
    ) -> Result<bool, DatabaseError> {
        Ok(run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE dashboard_sessions SET confirmed_at = $3
                WHERE secret_digest = $1 AND session_id = $2",
                secret_digest,
                session_id.as_uuid(),
                confirmed_at,
            )
        )?
        .rows_affected()
            == 1)
    }

    /// Uses the dashboard session with this cookie digest, if it is still in use:
    /// its auth session is active, since signing out, a revocation or an expiry
    /// of the auth session ends it, it has not reached its `expires_at`, and its
    /// last request came after `idle_since`. Using it makes this request its
    /// last.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn use_session(
        &mut self,
        secret_digest: &[u8],
        idle_since: DateTime<Utc>,
    ) -> Result<Option<StoredDashboardSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                StoredDashboardSession,
                r#"WITH used AS (
                    UPDATE dashboard_sessions d SET last_used_at = now()
                    FROM sessions s
                    WHERE d.secret_digest = $1 AND s.id = d.session_id
                    AND s.revoked_at IS NULL AND s.expires_at > now()
                    AND d.expires_at > now() AND d.last_used_at > $2
                    RETURNING d.session_id, s.user_id, d.confirmed_at
                )
                SELECT u.session_id AS "session_id: SessionId",
                    u.user_id AS "user_id: UserId", h.handle AS "handle: Handle",
                    p.id AS "picture?: PictureId", u.confirmed_at
                FROM used u
                JOIN handles h ON h.user_id = u.user_id AND h.released_at IS NULL
                LEFT JOIN profile_pictures p ON p.user_id = u.user_id"#,
                secret_digest,
                idle_since,
            )
        )
    }

    /// Ends the dashboard session with this cookie digest: the one it was, if
    /// there was one.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn delete_session(
        &mut self,
        secret_digest: &[u8],
    ) -> Result<Option<EndedDashboardSession>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_as!(
                EndedDashboardSession,
                r#"DELETE FROM dashboard_sessions d
                USING sessions s
                WHERE d.secret_digest = $1 AND s.id = d.session_id
                RETURNING d.session_id AS "session_id: SessionId", s.user_id AS "user_id: UserId""#,
                secret_digest,
            )
        )
    }

    /// Ends every dashboard session of `user_id`, and the handoffs that would
    /// start one, as revoking its administrator rights does. Returns the auth
    /// sessions of those still in use, as [`Self::of_user`] finds them with
    /// `idle_since`, each once.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails or a row is invalid.
    pub async fn end_of_user(
        &mut self,
        user_id: UserId,
        idle_since: DateTime<Utc>,
    ) -> Result<Vec<SessionId>, DatabaseError> {
        run!(
            self,
            fetch_all,
            sqlx::query_scalar!(
                r#"WITH handoffs AS (
                    DELETE FROM dashboard_handoffs h
                    USING sessions s
                    WHERE s.id = h.session_id AND s.user_id = $1
                ),
                ended AS (
                    DELETE FROM dashboard_sessions d
                    USING sessions s
                    WHERE s.id = d.session_id AND s.user_id = $1
                    RETURNING d.session_id, d.created_at,
                        s.revoked_at IS NULL AND s.expires_at > now()
                        AND d.expires_at > now() AND d.last_used_at > $2 AS in_use
                )
                SELECT session_id AS "session_id!: SessionId"
                FROM ended
                WHERE in_use
                GROUP BY session_id
                ORDER BY min(created_at)"#,
                user_id.as_uuid(),
                idle_since,
            )
        )
    }

    /// Keeps `form`, as JSON, which `user_id` posted to the dashboard page `path`,
    /// until `expires_at`, as the draft of that page, replacing one already
    /// kept.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the insert fails, e.g. for an unknown account.
    pub async fn keep_draft(
        &mut self,
        user_id: UserId,
        path: &str,
        form: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "INSERT INTO dashboard_drafts (user_id, path, form, expires_at)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id, path)
                DO UPDATE SET form = EXCLUDED.form, expires_at = EXCLUDED.expires_at",
                user_id.as_uuid(),
                path,
                form,
                expires_at,
            )
        )?;
        Ok(())
    }

    /// Takes the unexpired draft `user_id` posted to the page `path`, if any: its
    /// form, as JSON, shown once.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the query fails.
    pub async fn take_draft(
        &mut self,
        user_id: UserId,
        path: &str,
    ) -> Result<Option<String>, DatabaseError> {
        run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "DELETE FROM dashboard_drafts
                WHERE user_id = $1 AND path = $2 AND expires_at > now()
                RETURNING form",
                user_id.as_uuid(),
                path,
            )
        )
    }

    /// Claims the change `user_id` posted, whose administrator, page and form
    /// have the digest `digest`, as being made, until `expires_at`: the claim's
    /// own token, or, if the change is claimed already and its claim has not
    /// expired, whether it was made, or is being made still.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a query fails.
    pub async fn claim_submission(
        &mut self,
        digest: &[u8],
        user_id: UserId,
        expires_at: DateTime<Utc>,
    ) -> Result<Submission, DatabaseError> {
        let claimed = run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "INSERT INTO dashboard_submissions (digest, user_id, token, expires_at)
                VALUES ($1, $2, gen_random_uuid(), $3)
                ON CONFLICT (digest) DO UPDATE
                SET token = EXCLUDED.token, made = FALSE, expires_at = EXCLUDED.expires_at
                WHERE dashboard_submissions.expires_at <= now()
                RETURNING token",
                digest,
                user_id.as_uuid(),
                expires_at,
            )
        )?;
        if let Some(token) = claimed {
            return Ok(Submission::Claimed(SubmissionToken(token)));
        }
        let made = run!(
            self,
            fetch_optional,
            sqlx::query_scalar!(
                "SELECT made FROM dashboard_submissions WHERE digest = $1",
                digest,
            )
        )?;
        // One released since, a refused change, is taken as still being made:
        // posting again, once told, tries again.
        Ok(if made == Some(true) {
            Submission::Made
        } else {
            Submission::Pending
        })
    }

    /// Records that the change claimed with `token` was made, and keeps its
    /// claim until `expires_at`, unless another request took it since.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    pub async fn made_submission(
        &mut self,
        token: SubmissionToken,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE dashboard_submissions SET made = TRUE, expires_at = $2 WHERE token = $1",
                token.0,
                expires_at,
            )
        )?;
        Ok(())
    }

    /// Releases the claim `token` of a change that made nothing, so posting it
    /// again tries again, unless another request took it since.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the delete fails.
    pub async fn release_submission(
        &mut self,
        token: SubmissionToken,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "DELETE FROM dashboard_submissions WHERE token = $1",
                token.0,
            )
        )?;
        Ok(())
    }

    /// Ends `user_id`'s claims on changes, as if their window had passed: a
    /// fixture for posting the same form again.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the delete fails.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn forget_submissions(&mut self, user_id: UserId) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "DELETE FROM dashboard_submissions WHERE user_id = $1",
                user_id.as_uuid(),
            )
        )?;
        Ok(())
    }

    /// Moves the last use of the dashboard sessions of the auth session
    /// `session_id` `by` into the past, as if they had been left that long: a
    /// fixture for their idle timeout.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if the update fails.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn backdate_use(
        &mut self,
        session_id: SessionId,
        by: chrono::Duration,
    ) -> Result<(), DatabaseError> {
        run!(
            self,
            execute,
            sqlx::query!(
                "UPDATE dashboard_sessions
                SET last_used_at = last_used_at - $2::bigint * interval '1 millisecond'
                WHERE session_id = $1",
                session_id.as_uuid(),
                by.num_milliseconds(),
            )
        )?;
        Ok(())
    }
}
