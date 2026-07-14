use crate::{
    DatabaseConnectionError, DatabaseError, repositories::*, transaction::DatabaseTransaction,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{net::IpAddr, time::Duration};
use url::Url;

/// Validated database connection configuration.
#[derive(Clone)]
pub struct DatabaseConfig {
    url: String,
    max_connections: u32,
    connect_timeout: Duration,
}
impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("url", &"[REDACTED]")
            .field("max_connections", &self.max_connections)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}
impl DatabaseConfig {
    /// Creates production configuration requiring verified `PostgreSQL` TLS.
    pub fn new(
        url: String,
        max_connections: u32,
        connect_timeout: Duration,
    ) -> Result<Self, DatabaseConnectionError> {
        Self::validate(&url, max_connections, connect_timeout, false)?;
        Ok(Self {
            url,
            max_connections,
            connect_timeout,
        })
    }

    /// Creates explicit local-development configuration for a loopback database.
    pub fn new_development(
        url: String,
        max_connections: u32,
        connect_timeout: Duration,
    ) -> Result<Self, DatabaseConnectionError> {
        Self::validate(&url, max_connections, connect_timeout, true)?;
        Ok(Self {
            url,
            max_connections,
            connect_timeout,
        })
    }

    fn validate(
        url: &str,
        max_connections: u32,
        connect_timeout: Duration,
        development: bool,
    ) -> Result<(), DatabaseConnectionError> {
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
        if development {
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
            if !loopback {
                return Err(DatabaseConnectionError::InvalidConfiguration);
            }
        } else if !parsed
            .query_pairs()
            .any(|(name, value)| name == "sslmode" && value == "verify-full")
        {
            return Err(DatabaseConnectionError::InvalidConfiguration);
        }
        Ok(())
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
            .connect(&config.url)
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
            DatabaseConfig::new(
                "postgres://db.example/piquel".into(),
                1,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            DatabaseConfig::new(
                "postgres://db.example/piquel?sslmode=verify-full".into(),
                1,
                Duration::from_secs(1)
            )
            .is_ok()
        );
    }

    #[test]
    fn development_is_loopback_only() {
        assert!(
            DatabaseConfig::new_development(
                "postgres://localhost/piquel".into(),
                1,
                Duration::from_secs(1)
            )
            .is_ok()
        );
        assert!(
            DatabaseConfig::new_development(
                "postgres://db.example/piquel".into(),
                1,
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
}
