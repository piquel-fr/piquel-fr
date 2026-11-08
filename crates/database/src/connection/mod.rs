//! Validated `PostgreSQL` transport, bounded pools and explicit maintenance.

use crate::{DatabaseConnectionError, DatabaseError, DatabaseTransaction, LockKey};
use piquel_crypto::ScramVerifier;
use sqlx::{
    ConnectOptions, Connection, PgConnection, PgPool,
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{str::FromStr, time::Duration};
use url::Url;

/// Time limits on sessions.
mod limits;

pub(crate) use limits::{Limit, Scope};

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

/// Longest a migration's statement may run: one may rewrite a whole table. Its
/// lock waits keep the default limit, so DDL never queues requests for long.
const MIGRATION_STATEMENT_TIMEOUT: Duration = Duration::from_mins(30);

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
            .map_err(|source| DatabaseConnectionError::Options(Box::new(source)))?
            .options(Limit::DEFAULTS.map(Limit::option));
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

    /// Opens a connection outside the pool, with `options`, for work whose session
    /// state must never reach the pool. Connecting has the pool's acquire timeout,
    /// since no statement timeout bounds it.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Timeout`] if connecting takes longer, or another
    /// [`DatabaseError`] if it fails.
    pub(crate) async fn connect_dedicated(
        &self,
        options: &PgConnectOptions,
    ) -> Result<PgConnection, DatabaseError> {
        tokio::time::timeout(
            self.pool.options().get_acquire_timeout(),
            PgConnection::connect_with(options),
        )
        .await
        .map_err(DatabaseError::Timeout)?
        .map_err(Into::into)
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

    /// Opens a read-only `REPEATABLE READ` transaction: every query reads one
    /// snapshot, so reads spread over several queries agree with each other. It
    /// writes and locks nothing, so it never fails with a serialization error.
    /// It owns its connection, so it may outlive this handle, as a streamed data
    /// export's does.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if no connection is available or `BEGIN` fails.
    pub async fn begin_snapshot(&self) -> Result<DatabaseTransaction<'static>, DatabaseError> {
        self.pool
            .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await
            .map(DatabaseTransaction::new)
            .map_err(Into::into)
    }

    /// Runs schema migrations when explicitly requested through the auth binary.
    ///
    /// They run on a dedicated connection, whose statements may take up to
    /// 30 minutes (`MIGRATION_STATEMENT_TIMEOUT`). It first waits for
    /// [`LockKey::Migrations`], with no lock limit but within that statement
    /// limit, so overlapping runs take turns; `SQLx`'s own lock is then free. Lock
    /// waits get their default limit back before any DDL, so a migration blocked
    /// by a long transaction fails rather than queue every request behind it; run
    /// it again once that transaction ends.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Timeout`] if connecting takes too long,
    /// [`DatabaseError::Cancelled`] if another run holds the lock for 30 minutes,
    /// and [`DatabaseError::Operation`] if a migration fails, including on a lock
    /// wait past its limit, or the applied history differs from the embedded
    /// migrations.
    pub async fn run_migrations(&self) -> Result<(), DatabaseError> {
        let mut connection = self.connect_dedicated(&self.pool.connect_options()).await?;
        for limit in [
            Limit::STATEMENT.at(MIGRATION_STATEMENT_TIMEOUT),
            Limit::LOCK.at(Duration::ZERO),
        ] {
            limit.set(Scope::Session).fetch_one(&mut connection).await?;
        }
        sqlx::query!("SELECT pg_advisory_lock($1)", LockKey::Migrations.id())
            .fetch_one(&mut connection)
            .await?;
        Limit::LOCK
            .set(Scope::Session)
            .fetch_one(&mut connection)
            .await?;
        MIGRATOR
            .run(&mut connection)
            .await
            .map_err(|error| DatabaseError::Operation(Box::new(error)))?;
        // Closing the connection releases the lock.
        Ok(connection.close().await?)
    }

    /// Creates `role`, or resets its attributes and password, then grants it row
    /// access to the app tables and nothing else; see `runtime_role.sql`. Run it as
    /// the schema owner after migrations, so the grants cover every table.
    ///
    /// The script sets the password's SCRAM verifier, never the password, so the
    /// server and its logs never see it. It still runs on a dedicated connection
    /// that never logs statements, as one implicit transaction: concurrent queries
    /// see the old grants or the new ones, never none. It takes an advisory lock, so
    /// overlapping runs wait for each other.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Operation`] if `role` is the schema owner, a
    /// superuser, a member of another role or the owner of anything, if it or
    /// `PUBLIC` was granted a server parameter, if its verifier cannot be
    /// derived, or if a statement fails, e.g. when the owner is not a superuser.
    pub async fn provision(&self, role: &RuntimeRole) -> Result<(), DatabaseError> {
        let verifier = ScramVerifier::new(&role.password)
            .map_err(|error| DatabaseError::Operation(Box::new(error)))?;
        let options = self.pool.connect_options().as_ref().clone();
        let mut connection = self
            .connect_dedicated(&options.disable_statement_logging())
            .await?;
        let script = sqlx::query_file_scalar!(
            "src/connection/runtime_role.sql",
            role.name,
            verifier.to_string(),
            LockKey::Provisioning.id()
        )
        .fetch_one(&mut connection)
        .await?;
        sqlx::raw_sql(&script).execute(&mut connection).await?;
        Ok(connection.close().await?)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Database {
    /// Connects to `config`'s database in a schema of its own, created and migrated
    /// for this call, so a test can change history that the whole database shares,
    /// like the audit chain, without disturbing other tests. The schema is left
    /// behind; test databases are disposable.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if connecting, creating the schema or migrating fails.
    pub async fn isolated(config: DatabaseConfig) -> Result<Self, DatabaseError> {
        let schema = format!("test_{}", uuid::Uuid::now_v7().simple());
        let setup = Self::connect(config.clone())
            .await
            .map_err(|error| DatabaseError::Operation(Box::new(error)))?;
        // A schema name cannot be a bind parameter; this one is generated above.
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
            .execute(&setup.pool)
            .await?;
        setup.pool.close().await;
        let config = DatabaseConfig {
            options: config.options.options([("search_path", schema.as_str())]),
            ..config
        };
        let database = Self::connect(config)
            .await
            .map_err(|error| DatabaseError::Operation(Box::new(error)))?;
        database.run_migrations().await?;
        Ok(database)
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

    /// Connects to `TEST_DATABASE_URL` in a new schema of its own, with the
    /// migrations in `versions` applied, for tests of a migration: the test
    /// database is already migrated. The schema is left behind; test databases
    /// are disposable.
    pub(crate) async fn scratch_schema(versions: impl std::ops::RangeBounds<i64>) -> PgConnection {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let mut connection = PgConnection::connect(&url).await.expect("connect");
        let schema = format!("scratch_{}", uuid::Uuid::now_v7().simple());
        // A schema name cannot be a bind parameter; this one is generated above.
        sqlx::raw_sql(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .execute(&mut connection)
        .await
        .expect("schema");
        Self::apply_migrations(&mut connection, versions).await;
        connection
    }

    /// Applies the migrations in `versions` to `connection`'s schema, in order.
    pub(crate) async fn apply_migrations(
        connection: &mut PgConnection,
        versions: impl std::ops::RangeBounds<i64>,
    ) {
        for migration in MIGRATOR.iter().filter(|m| versions.contains(&m.version)) {
            sqlx::raw_sql(&migration.sql)
                .execute(&mut *connection)
                .await
                .unwrap_or_else(|error| panic!("migration {}: {error}", migration.version));
        }
    }

    /// The server process of `connection`, to watch its lock waits with
    /// [`Self::wait_for_lock`].
    pub(crate) async fn backend(connection: &mut PgConnection) -> i32 {
        sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(connection)
            .await
            .expect("backend pid")
    }

    /// Waits until the server process `backend` is blocked on a lock.
    pub(crate) async fn wait_for_lock(pool: &PgPool, backend: i32) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (
                    SELECT FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock'
                )",
            )
            .bind(backend)
            .fetch_one(pool)
            .await
            .expect("wait state")
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the transaction waits for a lock");
    }
}

/// Focused tests for this module and its security contracts.
#[cfg(test)]
mod tests;
