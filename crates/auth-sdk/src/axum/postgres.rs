//! A PostgreSQL session store, behind the `postgres` feature.
//!
//! Its queries are checked at runtime rather than with SQLx's compile-time macros,
//! since the tables live in the application's database, created by
//! [`PostgresSessions::migrate`].

use super::{
    BackchannelLogout, Lease, LeaseId, LogoutTarget, PendingAuthorization, SessionKey,
    SessionStore, StoredLogin, Versioned,
};
use crate::SessionId;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, types::Json};
use std::time::Duration;

/// Sessions in PostgreSQL, shared by every replica of the application.
///
/// The refresh lease is one conditional `UPDATE`, so only one replica refreshes a
/// session at a time, and writes are conditional on the version they read.
#[derive(Clone, Debug)]
pub struct PostgresSessions {
    /// The application's pool.
    pool: PgPool,
}

impl PostgresSessions {
    /// Stores sessions through `pool`. Run [`Self::migrate`] once first.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Creates the session tables if they do not exist.
    ///
    /// # Errors
    /// Fails if the statements fail.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        for statement in [
            "CREATE TABLE IF NOT EXISTS piquel_auth_sessions (
                id TEXT PRIMARY KEY,
                issuer TEXT NOT NULL,
                subject TEXT NOT NULL,
                sid UUID,
                login JSONB NOT NULL,
                version BIGINT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                refresh_lease_id TEXT,
                refresh_lease_until TIMESTAMPTZ
            )",
            "CREATE INDEX IF NOT EXISTS piquel_auth_sessions_sid
                ON piquel_auth_sessions (issuer, sid)",
            "CREATE INDEX IF NOT EXISTS piquel_auth_sessions_subject
                ON piquel_auth_sessions (issuer, subject)",
            "CREATE TABLE IF NOT EXISTS piquel_auth_logouts (
                issuer TEXT NOT NULL,
                jti TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (issuer, jti)
            )",
            "CREATE TABLE IF NOT EXISTS piquel_auth_pending (
                id TEXT PRIMARY KEY,
                pending JSONB NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
            )",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        Ok(())
    }

    /// Converts a stored version, which only this store writes, from `BIGINT`.
    fn version(version: i64) -> u64 {
        version.unsigned_abs()
    }
}

impl SessionStore for PostgresSessions {
    type Error = sqlx::Error;

    async fn load(&self, id: &SessionKey) -> Result<Option<Versioned<StoredLogin>>, sqlx::Error> {
        let row: Option<(Json<StoredLogin>, i64)> = sqlx::query_as(
            "SELECT login, version FROM piquel_auth_sessions
             WHERE id = $1 AND expires_at > now()",
        )
        .bind(id.storage_key())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(Json(value), version)| Versioned {
            value,
            version: Self::version(version),
        }))
    }

    async fn insert(
        &self,
        id: &SessionKey,
        login: &StoredLogin,
        expires: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        // Expired sessions are swept as new ones start.
        sqlx::query("DELETE FROM piquel_auth_sessions WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO piquel_auth_sessions (id, issuer, subject, sid, login, version, expires_at)
             VALUES ($1, $2, $3, $4, $5, 1, $6)",
        )
        .bind(id.storage_key())
        .bind(&login.issuer)
        .bind(login.subject())
        .bind(login.sid().map(SessionId::as_uuid))
        .bind(Json(login))
        .bind(expires)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn lease_refresh(
        &self,
        id: &SessionKey,
        version: u64,
        lease: &LeaseId,
        ttl: Duration,
    ) -> Result<Lease, sqlx::Error> {
        let Ok(version) = i64::try_from(version) else {
            return Ok(Lease::Changed);
        };
        let leased = sqlx::query(
            "UPDATE piquel_auth_sessions
             SET refresh_lease_id = $3, refresh_lease_until = now() + make_interval(secs => $4)
             WHERE id = $1 AND version = $2 AND expires_at > now() AND refresh_lease_id IS NULL",
        )
        .bind(id.storage_key())
        .bind(version)
        .bind(lease.as_str())
        .bind(ttl.as_secs_f64())
        .execute(&self.pool)
        .await?;
        if leased.rows_affected() == 1 {
            return Ok(Lease::Acquired);
        }
        let state: Option<(bool, bool)> = sqlx::query_as(
            "SELECT refresh_lease_id IS NOT NULL, COALESCE(refresh_lease_until >= now(), false)
             FROM piquel_auth_sessions WHERE id = $1 AND expires_at > now()",
        )
        .bind(id.storage_key())
        .fetch_optional(&self.pool)
        .await?;
        Ok(match state {
            None => Lease::Missing,
            Some((true, true)) => Lease::Busy,
            Some((true, false)) => Lease::Abandoned,
            Some((false, _)) => Lease::Changed,
        })
    }

    async fn save_if(
        &self,
        id: &SessionKey,
        lease: &LeaseId,
        login: &StoredLogin,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE piquel_auth_sessions
             SET login = $3, sid = $4, version = version + 1,
                 refresh_lease_id = NULL, refresh_lease_until = NULL
             WHERE id = $1 AND refresh_lease_id = $2",
        )
        .bind(id.storage_key())
        .bind(lease.as_str())
        .bind(Json(login))
        .bind(login.sid().map(SessionId::as_uuid))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete(&self, id: &SessionKey) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM piquel_auth_sessions WHERE id = $1")
            .bind(id.storage_key())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn logout(&self, logout: &BackchannelLogout) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM piquel_auth_logouts WHERE expires_at <= now()")
            .execute(&mut *tx)
            .await?;
        let applied = sqlx::query(
            "INSERT INTO piquel_auth_logouts (issuer, jti, expires_at) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
        )
        .bind(&logout.issuer)
        .bind(&logout.jti)
        .bind(logout.remember_until)
        .execute(&mut *tx)
        .await?;
        if applied.rows_affected() == 0 {
            return Ok(false);
        }
        match &logout.target {
            LogoutTarget::Session(sid) => {
                sqlx::query("DELETE FROM piquel_auth_sessions WHERE issuer = $1 AND sid = $2")
                    .bind(&logout.issuer)
                    .bind(sid.as_uuid())
                    .execute(&mut *tx)
                    .await?;
            }
            LogoutTarget::Subject(sub) => {
                sqlx::query("DELETE FROM piquel_auth_sessions WHERE issuer = $1 AND subject = $2")
                    .bind(&logout.issuer)
                    .bind(sub)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(true)
    }

    async fn insert_pending(
        &self,
        id: &SessionKey,
        pending: &PendingAuthorization,
        expires: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        // Abandoned logins are swept as new ones start.
        sqlx::query("DELETE FROM piquel_auth_pending WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO piquel_auth_pending (id, pending, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(id.storage_key())
        .bind(Json(pending))
        .bind(expires)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn take_pending(
        &self,
        id: &SessionKey,
    ) -> Result<Option<PendingAuthorization>, sqlx::Error> {
        let pending: Option<Json<PendingAuthorization>> = sqlx::query_scalar(
            "DELETE FROM piquel_auth_pending WHERE id = $1 AND expires_at > now()
             RETURNING pending",
        )
        .bind(id.storage_key())
        .fetch_optional(&self.pool)
        .await?;
        Ok(pending.map(|Json(pending)| pending))
    }
}
