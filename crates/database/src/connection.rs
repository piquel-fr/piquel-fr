use crate::{
    DatabaseConnectionError, DatabaseError, repositories::*, transaction::DatabaseTransaction,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

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
    /// Creates configuration without exposing the URL through `Debug`.
    pub fn new(
        url: String,
        max_connections: u32,
        connect_timeout: Duration,
    ) -> Result<Self, DatabaseConnectionError> {
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://")
            || max_connections == 0
            || connect_timeout.is_zero()
        {
            return Err(DatabaseConnectionError::InvalidConfiguration);
        }
        Ok(Self {
            url,
            max_connections,
            connect_timeout,
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
            .connect(&config.url)
            .await
            .map_err(|_| DatabaseConnectionError::Unavailable)?;
        Ok(Self { pool })
    }
    /// Checks availability with a bounded, non-sensitive query.
    pub async fn health_check(&self) -> Result<(), DatabaseError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(crate::error::map_error)
    }
    /// Opens an explicit short-lived transaction.
    pub async fn begin(&self) -> Result<DatabaseTransaction<'_>, DatabaseError> {
        self.pool
            .begin()
            .await
            .map(DatabaseTransaction::new)
            .map_err(crate::error::map_error)
    }
    /// Runs immutable migrations only when explicitly invoked by the migration binary.
    pub async fn run_migrations(&self) -> Result<(), DatabaseError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|_| DatabaseError::Internal)
    }
    pub fn users(&self) -> UserRepository<'_> {
        UserRepository::new()
    }
    pub fn emails(&self) -> EmailRepository<'_> {
        EmailRepository::new()
    }
    pub fn sessions(&self) -> SessionRepository<'_> {
        SessionRepository::new()
    }
    pub fn audit_events(&self) -> AuditEventRepository<'_> {
        AuditEventRepository::new()
    }
    pub fn internal_events(&self) -> InternalEventRepository<'_> {
        InternalEventRepository::new()
    }
    pub fn passkeys(&self) -> PasskeyRepository<'_> {
        PasskeyRepository::new()
    }
    pub fn oidc(&self) -> OidcRepository<'_> {
        OidcRepository::new()
    }
    pub fn tokens(&self) -> TokenRepository<'_> {
        TokenRepository::new()
    }
    pub fn federation(&self) -> FederationRepository<'_> {
        FederationRepository::new()
    }
    pub fn service_identities(&self) -> ServiceIdentityRepository<'_> {
        ServiceIdentityRepository::new()
    }
}
