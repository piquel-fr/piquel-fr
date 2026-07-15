use crate::{
    DatabaseConnectionError, DatabaseError, repositories::*, transaction::DatabaseTransaction,
};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{net::IpAddr, str::FromStr, time::Duration};
use url::Url;

/// Validated database connection configuration.
#[derive(Clone)]
pub struct DatabaseConfig {
    options: PgConnectOptions,
    max_connections: u32,
    connect_timeout: Duration,
}
impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("options", &"[REDACTED]")
            .field("max_connections", &self.max_connections)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}
impl DatabaseConfig {
    /// Creates production configuration requiring verified `PostgreSQL` TLS.
    pub fn new(
        url: &str,
        max_connections: u32,
        connect_timeout: Duration,
    ) -> Result<Self, DatabaseConnectionError> {
        let options = Self::validate(url, max_connections, connect_timeout, false)?;
        Ok(Self {
            options,
            max_connections,
            connect_timeout,
        })
    }

    /// Creates explicit local-development configuration for a loopback database.
    pub fn new_development(
        url: &str,
        max_connections: u32,
        connect_timeout: Duration,
    ) -> Result<Self, DatabaseConnectionError> {
        let options = Self::validate(url, max_connections, connect_timeout, true)?;
        Ok(Self {
            options,
            max_connections,
            connect_timeout,
        })
    }

    fn validate(
        url: &str,
        max_connections: u32,
        connect_timeout: Duration,
        development: bool,
    ) -> Result<PgConnectOptions, DatabaseConnectionError> {
        let parsed = Url::parse(url).map_err(|_| DatabaseConnectionError::InvalidConfiguration)?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql")
            || max_connections == 0
            || connect_timeout.is_zero()
        {
            return Err(DatabaseConnectionError::InvalidConfiguration);
        }
        let host = parsed
            .host_str()
            .ok_or(DatabaseConnectionError::InvalidConfiguration)?;

        let mut ssl_modes = parsed.query_pairs().filter_map(|(name, value)| {
            matches!(name.as_ref(), "sslmode" | "ssl-mode").then_some(value)
        });
        let ssl_mode = ssl_modes.next();
        if ssl_modes.next().is_some()
            || parsed
                .query_pairs()
                .any(|(name, _)| matches!(name.as_ref(), "host" | "hostaddr"))
        {
            return Err(DatabaseConnectionError::InvalidConfiguration);
        }
        if development {
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
            if !loopback {
                return Err(DatabaseConnectionError::InvalidConfiguration);
            }
        } else if ssl_mode.as_deref() != Some("verify-full") {
            return Err(DatabaseConnectionError::InvalidConfiguration);
        }

        let options = PgConnectOptions::from_str(url)
            .map_err(|_| DatabaseConnectionError::InvalidConfiguration)?;
        Ok(if development {
            options
        } else {
            // Keep the effective mode explicit even after validating the URL so
            // future parser changes cannot silently weaken production TLS.
            options.ssl_mode(PgSslMode::VerifyFull)
        })
    }
}

/// Typed database boundary. Its pool is intentionally private.
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}
impl Database {
    /// Connects without running migrations; releases must run them explicitly.
    pub async fn connect(config: DatabaseConfig) -> Result<Self, DatabaseConnectionError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.connect_timeout)
            .connect_with(config.options)
            .await
            .map_err(|_| DatabaseConnectionError::Unavailable)?;
        Ok(Self { pool })
    }
    /// Checks availability with a bounded, non-sensitive query.
    pub async fn health_check(&self) -> Result<(), DatabaseError> {
        tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query("SELECT 1").execute(&self.pool),
        )
        .await
        .map_err(|_| DatabaseError::Timeout)?
        .map(|_| ())
        .map_err(Into::into)
    }
    /// Opens an explicit short-lived transaction.
    pub async fn begin(&self) -> Result<DatabaseTransaction<'_>, DatabaseError> {
        self.pool
            .begin()
            .await
            .map(DatabaseTransaction::new)
            .map_err(Into::into)
    }
    /// Runs immutable migrations only when explicitly invoked by the migration binary.
    pub async fn run_migrations(&self) -> Result<(), DatabaseError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|_| DatabaseError::Internal)
    }
    /// Purges a bounded batch of expired ephemeral authentication state.
    pub async fn purge_expired_auth_state(&self, batch_size: u32) -> Result<u64, DatabaseError> {
        let limit = i64::from(batch_size.clamp(1, 1_000));
        let mut transaction = self.pool.begin().await.map_err(DatabaseError::from)?;
        let mut deleted = 0;
        for statement in [
            "DELETE FROM federation_transactions WHERE ctid IN (SELECT ctid FROM federation_transactions WHERE expires_at<now() OR consumed_at<now()-interval '1 day' LIMIT $1)",
            "DELETE FROM webauthn_ceremonies WHERE ctid IN (SELECT ctid FROM webauthn_ceremonies WHERE expires_at<now() OR consumed_at<now()-interval '1 day' LIMIT $1)",
            "DELETE FROM authorization_requests WHERE ctid IN (SELECT ctid FROM authorization_requests WHERE expires_at<now() OR consumed_at<now()-interval '1 day' LIMIT $1)",
            "DELETE FROM authorization_codes WHERE ctid IN (SELECT ctid FROM authorization_codes WHERE expires_at<now() OR consumed_at<now()-interval '1 day' LIMIT $1)",
            "DELETE FROM refresh_tokens t WHERE t.ctid IN (SELECT token.ctid FROM refresh_tokens token JOIN refresh_token_families family ON family.id=token.family_id WHERE token.expires_at<now() OR family.revoked_at<now()-interval '1 day' LIMIT $1)",
            "DELETE FROM refresh_token_families f WHERE f.ctid IN (SELECT family.ctid FROM refresh_token_families family WHERE (family.revoked_at<now()-interval '1 day' OR family.created_at<now()-interval '31 days') AND NOT EXISTS(SELECT 1 FROM refresh_tokens token WHERE token.family_id=family.id) LIMIT $1)",
            "DELETE FROM browser_session_secrets b WHERE b.ctid IN (SELECT secret.ctid FROM browser_session_secrets secret JOIN sessions session ON session.id=secret.session_id WHERE session.expires_at<now() OR session.revoked_at<now()-interval '1 day' LIMIT $1)",
            "DELETE FROM sessions s WHERE s.ctid IN (SELECT session.ctid FROM sessions session WHERE (session.expires_at<now() OR session.revoked_at<now()-interval '1 day') AND NOT EXISTS(SELECT 1 FROM refresh_token_families family WHERE family.session_id=session.id) AND NOT EXISTS(SELECT 1 FROM authorization_codes code WHERE code.session_id=session.id) LIMIT $1)",
        ] {
            deleted += sqlx::query(statement)
                .bind(limit)
                .execute(&mut *transaction)
                .await
                .map_err(DatabaseError::from)?
                .rows_affected();
        }
        transaction.commit().await.map_err(DatabaseError::from)?;
        Ok(deleted)
    }
    pub fn users(&self) -> UserRepository<'_> {
        UserRepository::from_pool(&self.pool)
    }
    pub fn emails(&self) -> EmailRepository<'_> {
        EmailRepository::from_pool(&self.pool)
    }
    pub fn sessions(&self) -> SessionRepository<'_> {
        SessionRepository::from_pool(&self.pool)
    }
    pub fn audit_events(&self) -> AuditEventRepository<'_> {
        AuditEventRepository::from_pool(&self.pool)
    }
    pub fn internal_events(&self) -> InternalEventRepository<'_> {
        InternalEventRepository::from_pool(&self.pool)
    }
    pub fn passkeys(&self) -> PasskeyRepository<'_> {
        PasskeyRepository::from_pool(&self.pool)
    }
    pub fn oidc(&self) -> OidcRepository<'_> {
        OidcRepository::from_pool(&self.pool)
    }
    pub fn tokens(&self) -> TokenRepository<'_> {
        TokenRepository::from_pool(&self.pool)
    }
    pub fn federation(&self) -> FederationRepository<'_> {
        FederationRepository::from_pool(&self.pool)
    }
    pub fn service_identities(&self) -> ServiceIdentityRepository<'_> {
        ServiceIdentityRepository::from_pool(&self.pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_requires_verified_tls() {
        assert!(
            DatabaseConfig::new("postgres://db.example/piquel", 1, Duration::from_secs(1)).is_err()
        );
        assert!(
            DatabaseConfig::new(
                "postgres://db.example/piquel?sslmode=verify-full",
                1,
                Duration::from_secs(1)
            )
            .is_ok()
        );
        assert!(
            DatabaseConfig::new(
                "postgres://db.example/piquel?ssl-mode=verify-full",
                1,
                Duration::from_secs(1)
            )
            .is_ok()
        );
    }

    #[test]
    fn production_rejects_ambiguous_tls_modes_and_host_overrides() {
        for url in [
            "postgres://db.example/piquel?sslmode=verify-full&sslmode=disable",
            "postgres://db.example/piquel?sslmode=disable&sslmode=verify-full",
            "postgres://db.example/piquel?sslmode=verify-full&ssl-mode=disable",
            "postgres://db.example/piquel?sslmode=verify-full&ssl-mode=verify-full",
            "postgres://db.example/piquel?sslmode=verify-full&host=elsewhere.example",
            "postgres://db.example/piquel?sslmode=verify-full&hostaddr=127.0.0.1",
        ] {
            assert!(
                DatabaseConfig::new(url, 1, Duration::from_secs(1)).is_err(),
                "accepted ambiguous database URL: {url}"
            );
        }
    }

    #[test]
    fn development_is_loopback_only() {
        assert!(
            DatabaseConfig::new_development(
                "postgres://localhost/piquel",
                1,
                Duration::from_secs(1)
            )
            .is_ok()
        );
        assert!(
            DatabaseConfig::new_development(
                "postgres://db.example/piquel",
                1,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            DatabaseConfig::new_development(
                "postgres://localhost/piquel?host=db.example",
                1,
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
}
