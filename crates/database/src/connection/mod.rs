//! Validated `PostgreSQL` transport, bounded pools and explicit maintenance.

use crate::{DatabaseConnectionError, DatabaseError, DatabaseTransaction, LockKey};
use sqlx::{
    ConnectOptions, Connection, PgConnection, PgPool,
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{str::FromStr, time::Duration};
use url::Url;

/// TCP mode that verifies both the certificate chain and server hostname.
const VERIFIED_SSL_MODE: &str = "verify-full";
/// Explicit plaintext opt-in for trusted private networks.
const PLAINTEXT_SSL_MODE: &str = "disable";
/// Accepted spelling of the TLS mode query parameter.
const SSL_MODE_PARAMETER: &str = "sslmode";
/// `SQLx`'s alternate TLS mode query parameter spelling.
const SSL_MODE_PARAMETER_ALIAS: &str = "ssl-mode";
/// Unix socket path query parameter; cannot override remote TCP hosts.
const SOCKET_PARAMETER: &str = "host";
/// Address overrides bypass the validated authority and are forbidden.
const HOST_ADDRESS_PARAMETER: &str = "hostaddr";
/// Socket connections require this explicit local URL authority.
const SOCKET_HOST: &str = "localhost";

/// The schema migrations embedded at compile time, in version order.
pub(crate) static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Readiness must fail quickly when the database stops responding.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Longest role name `PostgreSQL` keeps; it truncates longer ones.
const MAX_ROLE_NAME_LENGTH: usize = 63;

/// Validated database connection configuration.
#[derive(Clone)]
pub struct DatabaseConfig {
    /// Transport and credentials; diagnostic formatting redacts them.
    options: PgConnectOptions,
    /// Upper bound on simultaneously pooled connections.
    max_connections: u32,
    /// Maximum wait for a pooled connection.
    connect_timeout: Duration,
}

impl std::fmt::Debug for DatabaseConfig {
    /// Renders a safe diagnostic representation without exposing secrets.
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
    /// Creates production configuration using verified TLS, an explicit local Unix socket,
    /// or plaintext TCP explicitly requested with `sslmode=disable`.
    ///
    /// `max_connections` bounds the pool; `connect_timeout` bounds each wait
    /// for a pooled connection.
    ///
    /// # Errors
    ///
    /// Names malformed URLs, zero bounds and insecure or ambiguous transport settings.
    /// Underlying parser errors remain available through their source.
    pub fn new(
        url: &str,
        max_connections: u32,
        connect_timeout: Duration,
    ) -> Result<Self, DatabaseConnectionError> {
        let options = Self::validate(url, max_connections, connect_timeout)?;
        Ok(Self {
            options,
            max_connections,
            connect_timeout,
        })
    }

    /// Sets the password separately from the URL, e.g. from a mounted secret file.
    #[must_use]
    pub fn with_password(mut self, password: &str) -> Self {
        self.options = self.options.password(password);
        self
    }

    /// Validates transport before `SQLx` parses options, preventing ambiguous overrides.
    fn validate(
        url: &str,
        max_connections: u32,
        connect_timeout: Duration,
    ) -> Result<PgConnectOptions, DatabaseConnectionError> {
        let parsed = Url::parse(url)?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql") {
            return Err(DatabaseConnectionError::Scheme);
        }
        if max_connections == 0 || connect_timeout.is_zero() {
            return Err(DatabaseConnectionError::ZeroPoolBound);
        }
        let host = parsed
            .host_str()
            .ok_or(DatabaseConnectionError::MissingHost)?;

        let mut ssl_modes = parsed.query_pairs().filter_map(|(name, value)| {
            matches!(name.as_ref(), SSL_MODE_PARAMETER | SSL_MODE_PARAMETER_ALIAS).then_some(value)
        });
        let ssl_mode = ssl_modes.next();
        let mut socket_paths = parsed
            .query_pairs()
            .filter_map(|(name, value)| (name == SOCKET_PARAMETER).then_some(value));
        let socket_path = socket_paths.next();
        if ssl_modes.next().is_some()
            || socket_paths.next().is_some()
            || parsed
                .query_pairs()
                .any(|(name, _)| name == HOST_ADDRESS_PARAMETER)
        {
            return Err(DatabaseConnectionError::AmbiguousTransport);
        }
        if socket_path.as_ref().is_some_and(|path| {
            host != SOCKET_HOST || !path.starts_with('/') || path.contains('\0')
        }) {
            return Err(DatabaseConnectionError::InvalidSocket);
        }
        // Plaintext TCP needs an explicit `sslmode=disable`, e.g. on a private container
        // network. Weaker TLS modes would look encrypted without verifying the server.
        let plaintext = ssl_mode.as_deref() == Some(PLAINTEXT_SSL_MODE);
        let require_verified_tls = socket_path.is_none() && !plaintext;
        if require_verified_tls && ssl_mode.as_deref() != Some(VERIFIED_SSL_MODE) {
            return Err(DatabaseConnectionError::InsecureTransport);
        }

        let options = PgConnectOptions::from_str(url)
            .map_err(|source| DatabaseConnectionError::Options(Box::new(source)))?;
        Ok(if require_verified_tls {
            // Keep the effective mode explicit even after validating the URL so
            // future parser changes cannot silently weaken production TLS.
            options.ssl_mode(PgSslMode::VerifyFull)
        } else {
            options
        })
    }
}

/// The login role `serve` connects as, which [`Database::provision`] creates or
/// resets with exactly the privileges the service needs.
pub struct RuntimeRole {
    /// A plain lowercase identifier, so SQL never needs to quote it.
    name: String,
    /// What the role logs in with.
    password: String,
}

impl RuntimeRole {
    /// The role `runtime` connects as, logging in with `password`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseConnectionError::RoleName`] unless the connection's user
    /// is a plain lowercase identifier, like `piquel_auth`.
    pub fn new(runtime: &DatabaseConfig, password: &str) -> Result<Self, DatabaseConnectionError> {
        let name = runtime.options.get_username();
        let mut chars = name.chars();
        let plain = chars
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first == '_')
            && chars.all(|next| next.is_ascii_lowercase() || next.is_ascii_digit() || next == '_');
        if !plain || name.len() > MAX_ROLE_NAME_LENGTH {
            return Err(DatabaseConnectionError::RoleName);
        }
        Ok(Self {
            name: name.to_owned(),
            password: password.to_owned(),
        })
    }
}

/// Typed database boundary. Its pool is intentionally private.
#[derive(Clone)]
pub struct Database {
    /// Only repository handles can issue SQL on this pool.
    pub(crate) pool: PgPool,
}

impl Database {
    /// Connects without running migrations; releases must run them explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseConnectionError::Connection`] if the first connection fails.
    pub async fn connect(config: DatabaseConfig) -> Result<Self, DatabaseConnectionError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.connect_timeout)
            .connect_with(config.options)
            .await
            .map_err(|error| DatabaseConnectionError::Connection(Box::new(error)))?;
        Ok(Self { pool })
    }

    /// Checks availability with a bounded, non-sensitive query.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Timeout`] after two seconds, or another
    /// [`DatabaseError`] if the query fails.
    pub async fn health_check(&self) -> Result<(), DatabaseError> {
        tokio::time::timeout(
            HEALTH_CHECK_TIMEOUT,
            sqlx::query_scalar!("SELECT 1 AS alive").fetch_one(&self.pool),
        )
        .await
        .map_err(DatabaseError::Timeout)??;
        Ok(())
    }

    /// Opens an explicit short-lived transaction.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if no connection is available or `BEGIN` fails.
    pub async fn begin(&self) -> Result<DatabaseTransaction<'_>, DatabaseError> {
        self.pool
            .begin()
            .await
            .map(DatabaseTransaction::new)
            .map_err(Into::into)
    }

    /// Opens a `REPEATABLE READ` transaction: every query reads one snapshot, so
    /// reads spread over several queries are consistent with each other.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if no connection is available or `BEGIN` fails.
    pub async fn begin_snapshot(&self) -> Result<DatabaseTransaction<'_>, DatabaseError> {
        self.pool
            .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .await
            .map(DatabaseTransaction::new)
            .map_err(Into::into)
    }

    /// Runs schema migrations when explicitly requested through the auth binary.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Operation`] if a migration fails or the applied
    /// history differs from the embedded migrations.
    pub async fn run_migrations(&self) -> Result<(), DatabaseError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|error| DatabaseError::Operation(Box::new(error)))
    }

    /// Creates `role`, or resets its attributes and password, then grants it row
    /// access to the app tables and nothing else; see `runtime_role.sql`. Run it as
    /// the schema owner after migrations, so the grants cover every table.
    ///
    /// The script holds the password, so it runs on a dedicated connection that
    /// never logs statements, as one implicit transaction: concurrent queries see
    /// the old grants or the new ones, never none. It takes an advisory lock, so
    /// overlapping runs wait for each other.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Operation`] if `role` is the schema owner or a
    /// superuser, or if a statement fails, e.g. when the owner is not a superuser.
    pub async fn provision(&self, role: &RuntimeRole) -> Result<(), DatabaseError> {
        let options = self.pool.connect_options().as_ref().clone();
        let mut connection =
            PgConnection::connect_with(&options.disable_statement_logging()).await?;
        let script = sqlx::query_file_scalar!(
            "src/connection/runtime_role.sql",
            role.name,
            role.password,
            LockKey::Provisioning.id()
        )
        .fetch_one(&mut connection)
        .await?;
        sqlx::raw_sql(&script).execute(&mut connection).await?;
        Ok(connection.close().await?)
    }
}

#[cfg(test)]
impl Database {
    /// Connects to `TEST_DATABASE_URL` and applies the schema. In-crate database
    /// tests get the raw pool so they can insert fixtures with plain SQL.
    pub(crate) async fn test_pool() -> PgPool {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let pool = PgPool::connect(&url).await.expect("connect");
        Self { pool: pool.clone() }
            .run_migrations()
            .await
            .expect("migrate");
        pool
    }
}

/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
